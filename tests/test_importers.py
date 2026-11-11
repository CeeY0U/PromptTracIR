"""Trace importers: Claude Code transcripts, OpenTelemetry GenAI spans, AgentDFIR packages."""
import gzip
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.adfir import PackageError, import_package, read_artifact, verify  # noqa: E402
from prompttracir.case import Case  # noqa: E402
from prompttracir.cli import main  # noqa: E402
from prompttracir.parsers import claude_code, otel  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402
from prompttracir.schema import Action  # noqa: E402

CC = ROOT / "tests" / "fixtures" / "claude_code_session.jsonl"
ENV = {"allowed_paths": ["C:\\Users\\lab\\project"], "allowed_domains": ["docs.example-lab.test"],
       "model_api_domains": ["127.0.0.1"]}


# ---------------- Claude Code ----------------
def test_claude_code_events():
    evs = list(claude_code.parse(CC, "e" * 64))
    acts = [e.action for e in evs]
    assert acts[0] == Action.SESSION_START and evs[0].attrs["model"] == "claude-sonnet-5"
    assert acts.count(Action.USER_PROMPT) == 1 and acts.count(Action.MODEL_CALL) == 4
    bash = next(e for e in evs if e.action == Action.TOOL_CALL and e.attrs["tool"] == "Bash")
    assert bash.command_line.startswith("curl.exe") and bash.model_call_id == "msg_02"
    frags = [e for e in evs if e.action == Action.CONTEXT_FRAGMENT and e.tool_call_id == "toolu_01"]
    assert len(frags) == 4 and frags[0].attrs["source"]["kind"] == "url"
    mc2 = next(e for e in evs if e.action == Action.MODEL_CALL and e.model_call_id == "msg_02")
    assert mc2.attrs["input_fragments"] == [f"toolu_01-{i}" for i in range(4)]
    write = next(e for e in evs if e.action == Action.TOOL_RESULT and e.tool_call_id == "toolu_03")
    assert write.attrs["files_written"] == ["C:\\Users\\lab\\project\\notes.md"]
    # event ids sort in file order, so equal timestamps never reorder call and result
    assert [e.event_id for e in evs] == sorted(e.event_id for e in evs)
    assert evs[1].raw.locator.startswith("line:2")


def test_claude_code_case_analysis(tmp_path):
    c = Case.create(tmp_path / "c", "cc", ENV)
    c.add_evidence(CC, "claude_code")
    ingest(c)
    s = analyze(c)
    assert s["first_deviation"] == "tool_call:toolu_02"
    assert s["entry_points"][0]["fragment"] == "fragment:toolu_01-2"


def test_claude_code_tolerates_torn_last_line(tmp_path):
    f = tmp_path / "live.jsonl"
    f.write_text(CC.read_text() + '{"type": "assistant", "sessionId": "x", "timest')
    assert len(list(claude_code.parse(f, "e" * 64))) == len(list(claude_code.parse(CC, "e" * 64)))


# ---------------- OpenTelemetry ----------------
T0 = datetime(2026, 10, 29, 7, 0, 0, tzinfo=timezone.utc)


def _ns(sec: float) -> str:
    return str(int((T0 + timedelta(seconds=sec)).timestamp() * 1e9))


def _kv(d: dict) -> list:
    out = []
    for k, v in d.items():
        if isinstance(v, bool):
            val = {"boolValue": v}
        elif isinstance(v, int):
            val = {"intValue": str(v)}
        else:
            val = {"stringValue": v if isinstance(v, str) else json.dumps(v)}
        out.append({"key": k, "value": val})
    return out


def otel_doc() -> dict:
    """The synthetic sample's run, as an OpenTelemetry-instrumented agent would export it."""
    from samples.make_sample import FRAGS, SECRET, UPLOAD
    tid = "0af7651916cd43dd8448eb211c80319c"
    page = "\n\n".join(FRAGS.values())

    def span(sid, name, start, end, attrs, parent="a0"):
        return {"traceId": tid, "spanId": sid, "parentSpanId": parent, "name": name,
                "startTimeUnixNano": _ns(start), "endTimeUnixNano": _ns(end), "attributes": _kv(attrs)}

    def tool(sid, call_id, name, args, start, end, result, **extra):
        return span(sid, f"execute_tool {name}", start, end, {
            "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": name, "gen_ai.tool.call.id": call_id,
            "gen_ai.tool.call.arguments": json.dumps(args), "gen_ai.tool.call.result": result, **extra})

    def chat(sid, start, end, **extra):
        return span(sid, "chat local-8b-instruct", start, end, {
            "gen_ai.operation.name": "chat", "gen_ai.request.model": "local-8b-instruct", **extra})

    prompt = [{"role": "user", "parts": [{"type": "text", "content":
               "Summarise the lab guide and save notes to C:\\Users\\lab\\project\\notes.md"}]}]
    spans = [
        span("a0", "invoke_agent lab-agent", 0, 7.2, {"gen_ai.operation.name": "invoke_agent",
             "gen_ai.agent.name": "lab-agent", "gen_ai.conversation.id": "conv-1"}, parent=""),
        chat("c1", 0.2, 0.9, **{"gen_ai.input.messages": json.dumps(prompt)}),
        tool("x1", "t1", "http_get", {"url": "https://docs.example-lab.test/guide"}, 1.0, 1.6, page),
        chat("c2", 2.0, 2.9),
        tool("x2", "t2", "read_file", {"path": SECRET}, 3.0, 3.1, "OPENAI_API_KEY=sk-lab-000"),
        chat("c3", 4.0, 4.9),
        tool("x3", "t3", "shell", {"command": UPLOAD}, 5.0, 5.9, "ok", **{"ptir.child_pid": 5200}),
        chat("c4", 6.5, 6.9),
        tool("x4", "t4", "write_file", {"path": "C:\\Users\\lab\\project\\notes.md", "content": "x"}, 7.0, 7.1,
             "wrote 1 chars"),
    ]
    resource = {"attributes": _kv({"service.name": "lab-agent", "process.pid": 4100, "host.name": "LAB-WIN11",
                                   "process.executable.path": "C:\\Python312\\python.exe"})}
    return {"resourceSpans": [{"resource": resource, "scopeSpans": [{"scope": {"name": "t"}, "spans": spans}]}]}


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    out = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(out)], check=True)
    return out


def test_otel_events(tmp_path):
    f = tmp_path / "otel.json"
    f.write_text(json.dumps(otel_doc()))
    evs = list(otel.parse(f, "f" * 64))
    start = evs[0]
    assert start.action == Action.SESSION_START and start.pid == 4100 and start.session_id == "conv-1"
    assert next(e for e in evs if e.action == Action.USER_PROMPT).attrs["text"].startswith("Summarise")
    calls = {e.tool_call_id: e for e in evs if e.action == Action.TOOL_CALL}
    assert calls["t3"].model_call_id == "c3" and calls["t3"].command_line.startswith("curl.exe")
    res = next(e for e in evs if e.action == Action.TOOL_RESULT and e.tool_call_id == "t3")
    assert res.pid == 5200
    mc2 = next(e for e in evs if e.action == Action.MODEL_CALL and e.model_call_id == "c2")
    assert mc2.attrs["input_fragments"] == ["t1-0", "t1-1", "t1-2"]


def test_otel_jsonl_and_sample_evidence(tmp_path, sample):
    """Same run as the harness sample: OTel trace + Sysmon + Zeek must reconstruct the same chain."""
    f = tmp_path / "otel.jsonl"          # collector file exporter: one document per line
    doc = otel_doc()
    rs = doc["resourceSpans"][0]
    spans = rs["scopeSpans"][0]["spans"]
    lines = [{"resourceSpans": [{**rs, "scopeSpans": [{"spans": spans[:4]}]}]},
             {"resourceSpans": [{**rs, "scopeSpans": [{"spans": spans[4:]}]}]}]
    f.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    c = Case.create(tmp_path / "c", "otel", json.loads((sample / "envelope.json").read_text()))
    c.add_evidence(f, "otel_trace")
    c.add_evidence(sample / "sysmon.jsonl", "sysmon")
    c.add_evidence(sample / "zeek_conn.json", "zeek_conn")
    ingest(c)
    s = analyze(c)
    assert s["first_deviation"] == "tool_call:t2"
    assert s["entry_points"][0]["fragment"] == "fragment:t1-1"
    link = next(l for l in c.read_output("tool_links.json") if l["tool_call_id"] == "t3")
    assert link["status"] == "corroborated" and link["signals"]["child_pid_match"]
    assert dict(s["impact"])["collect.attacker-lab.test"] in ("confirmed", "probable")


def test_otel_without_content_still_parses(tmp_path):
    doc = otel_doc()
    for sp in doc["resourceSpans"][0]["scopeSpans"][0]["spans"]:
        sp["attributes"] = [a for a in sp["attributes"] if a["key"] not in
                            ("gen_ai.tool.call.result", "gen_ai.tool.call.arguments", "gen_ai.input.messages")]
    f = tmp_path / "otel.json"
    f.write_text(json.dumps(doc))
    evs = list(otel.parse(f, "f" * 64))
    assert sum(e.action == Action.TOOL_CALL for e in evs) == 4
    assert not any(e.action == Action.CONTEXT_FRAGMENT for e in evs)


# ---------------- AgentDFIR packages ----------------
def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_package(root: Path, chunked: bool = False) -> Path:
    """Minimal .adfir 0.2 package holding the Claude Code fixture (and one unsupported artifact)."""
    pkg = root / "case.adfir"
    (pkg / "raw").mkdir(parents=True)
    data = CC.read_bytes()
    recs = []
    if chunked:
        a, b = data[:700], data[700:]
        chunks = []
        for i, part in enumerate((a, b), 1):
            gz = gzip.compress(part)
            (pkg / "raw" / f"{_sha(part)}.gz").write_bytes(gz)
            chunks.append({"id": _sha(part), "size": len(part), "codec": "gzip", "stored_sha256": _sha(gz),
                           "stored_size": len(gz), "round": i})
        recs.append({"artifact_id": _sha(data), "size": len(data), "chunks": chunks})
    else:
        gz = gzip.compress(data)
        (pkg / "raw" / f"{_sha(data)}.gz").write_bytes(gz)
        recs.append({"artifact_id": _sha(data), "size": len(data), "codec": "gzip", "stored_sha256": _sha(gz)})
    recs[0].update(logical_path=".claude/projects/C--Users-lab-project/5f0c2a9e.jsonl", product="claude-code",
                   artifact_type="agent_session", status="OK", round=1)
    other = b'{"mcpServers": {}}'
    (pkg / "raw" / _sha(other)).write_bytes(other)
    recs.append({"artifact_id": _sha(other), "size": len(other), "codec": "none", "logical_path": ".cursor/mcp.json",
                 "product": "cursor", "artifact_type": "config", "status": "OK"})
    recs.append({"artifact_id": "", "logical_path": ".codex/sessions/x.jsonl", "product": "codex",
                 "status": "NOT_PRESENT"})
    header = {"adfir_version": "0.2", "case_id": "TEST-1", "collector_name": "agentdfir",
              "collector_version": "3.2.0", "host": "LAB-WIN11"}
    (pkg / "manifest.jsonl").write_text("\n".join(json.dumps(r) for r in [header] + recs) + "\n")
    (pkg / "case.json").write_text(json.dumps({"case_id": "TEST-1"}))
    (pkg / "collection.jsonl").write_text('{"seq": 1, "event": "collected"}\n')
    (pkg / "chain-of-custody.jsonl").write_text('{"seq": 1, "event": "sealed"}\n')
    files = sorted(p for p in pkg.rglob("*") if p.is_file())
    (pkg / "SHA256SUMS").write_text("".join(f"{_sha(p.read_bytes())}  {p.relative_to(pkg).as_posix()}\n"
                                            for p in files))
    (pkg / "normalized").mkdir()                    # overlay: never sealed, never read
    (pkg / "normalized" / "events.jsonl").write_text("{}\n")
    return pkg


@pytest.mark.parametrize("chunked", [False, True], ids=["single", "chunked"])
def test_adfir_import(tmp_path, chunked):
    pkg = make_package(tmp_path, chunked)
    assert verify(pkg) == []
    c = Case.create(tmp_path / "c", "adfir", ENV)
    res = import_package(c, pkg)
    aid = _sha(CC.read_bytes())
    assert [i["artifact_id"] for i in res["imported"]] == [aid]          # same id in both tools
    assert c.meta["evidence"][aid]["kind"] == "claude_code"
    assert res["skipped_by_product"] == {"cursor/config": 1}
    assert sum(v["kind"] == "adfir_meta" for v in c.meta["evidence"].values()) == 5
    assert '"adfir_imported"' in (c.root / "custody.jsonl").read_text()
    ingest(c)
    assert analyze(c)["first_deviation"] == "tool_call:toolu_02"


@pytest.mark.parametrize("tamper", ["flip_raw", "plant_raw", "drop_case_line", "path_escape", "plant_top"])
def test_adfir_tampering_is_detected(tmp_path, tamper):
    pkg = make_package(tmp_path)
    blob = next((pkg / "raw").glob("*.gz"))
    sums = pkg / "SHA256SUMS"
    if tamper == "flip_raw":
        b = bytearray(blob.read_bytes()); b[-5] ^= 0xFF; blob.write_bytes(bytes(b))
    elif tamper == "plant_raw":
        (pkg / "raw" / ("0" * 64)).write_bytes(b"planted")
    elif tamper == "drop_case_line":
        sums.write_text("".join(l + "\n" for l in sums.read_text().splitlines() if not l.endswith("  case.json")))
    elif tamper == "path_escape":
        sums.write_text(sums.read_text() + f"{'0' * 64}  ../outside\n")
    elif tamper == "plant_top":
        (pkg / "manifest.json").write_text("{}")
    assert verify(pkg)
    c = Case.create(tmp_path / "c", "adfir")
    with pytest.raises(PackageError):
        import_package(c, pkg)
    assert c.meta["evidence"] == {}                                     # nothing imported


def test_adfir_read_artifact_checks_content_id(tmp_path):
    pkg = make_package(tmp_path)
    rec = next(r for r in (json.loads(l) for l in (pkg / "manifest.jsonl").read_text().splitlines())
               if r.get("product") == "claude-code")
    rec["artifact_id"] = "1" * 64
    (pkg / "raw" / ("1" * 64 + ".gz")).write_bytes(gzip.compress(CC.read_bytes()))
    with pytest.raises(PackageError, match="does not match"):
        read_artifact(pkg, rec)


def test_cli_import_adfir(tmp_path, capsys):
    pkg = make_package(tmp_path)
    main(["init", str(tmp_path / "c"), "--name", "t"])
    assert main(["import-adfir", str(tmp_path / "c"), str(pkg)]) == 0
    assert "1 transcript(s) imported from AgentDFIR case TEST-1" in capsys.readouterr().out
    b = bytearray(next((pkg / "raw").glob("*.gz")).read_bytes()); b[-5] ^= 0xFF
    next((pkg / "raw").glob("*.gz")).write_bytes(bytes(b))
    main(["init", str(tmp_path / "c2"), "--name", "t"])
    assert main(["import-adfir", str(tmp_path / "c2"), str(pkg)]) == 1
    assert main(["import-adfir", str(tmp_path / "c2"), str(pkg), "--force"]) == 0
    out = capsys.readouterr().out
    assert "UNREADABLE" in out and "0 transcript(s) imported" in out
