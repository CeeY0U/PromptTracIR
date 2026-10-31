import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.case import Case  # noqa: E402
from prompttracir.evaluate import evaluate_case  # noqa: E402
from prompttracir.llm import validate_narrative  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402

SAMPLE = ROOT / "samples" / "scenario_exfil"


@pytest.fixture(scope="module")
def sample_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(out)], check=True)
    return out


def make_case(tmp_path, sample_dir):
    c = Case.create(tmp_path / "case", "test", json.loads((sample_dir / "envelope.json").read_text()))
    for f, k in [("trace.jsonl", "agent_trace"), ("requests.jsonl", "agent_requests"), ("sysmon.jsonl", "sysmon"),
                 ("ConsoleHost_history.txt", "psreadline"), ("zeek_conn.json", "zeek_conn")]:
        c.add_evidence(sample_dir / f, k)
    ingest(c)
    return c


def test_evidence_is_hashed_and_verifiable(tmp_path, sample_dir):
    c = make_case(tmp_path, sample_dir)
    assert all(c.verify_evidence().values())
    custody = (c.root / "custody.jsonl").read_text().splitlines()
    assert any('"evidence_added"' in l for l in custody)


def test_end_to_end_heuristic(tmp_path, sample_dir):
    c = make_case(tmp_path, sample_dir)
    summary = analyze(c)
    assert summary["first_deviation"] == "tool_call:t2"
    assert summary["entry_points"][0]["fragment"] == "fragment:f2"
    gt = json.loads((sample_dir / "ground_truth.json").read_text())
    ev = evaluate_case(c, gt)
    assert ev["attribution"]["accuracy"] == 1.0
    assert ev["impact"]["collect.attacker-lab.test"]["pred"] == "confirmed"
    assert ev["malicious_tool_calls"]["f1"] == 1.0
    # the python temp file must not become a finding
    findings = c.read_output("findings.json")
    assert not any("tmp8x2k" in f["summary"] for f in findings)


def test_tool_call_link_is_corroborated(tmp_path, sample_dir):
    c = make_case(tmp_path, sample_dir)
    analyze(c)
    links = c.read_output("tool_links.json")
    assert links[0]["tool_call_id"] == "t3"
    assert links[0]["status"] == "corroborated"
    assert links[0]["signals"]["child_pid_match"]


class FakeReplayer:
    """Model stand-in: issues the upload call only while the injected text is present."""
    def replay(self, request):
        ctx = json.dumps(request["messages"])
        if "verify access by running" in ctx:
            from samples.make_sample import UPLOAD, SECRET
            return [{"tool": "read_file", "args": {"path": SECRET}}, {"tool": "shell", "args": {"command": UPLOAD}}]
        return [{"tool": "write_file", "args": {"path": "notes.md"}}]


def test_replay_traceback(tmp_path, sample_dir):
    c = make_case(tmp_path, sample_dir)
    summary = analyze(c, replayer=FakeReplayer(), samples=2)
    ep = summary["entry_points"][0]
    assert ep["fragment"] == "fragment:f2" and ep["method"] == "leave_one_out_replay"
    assert ep["confidence"] == 1.0
    tb = c.read_output("traceback.json")
    benign = [r for t in tb for r in t["results"] if r["fragment_id"] != "fragment:f2"]
    assert all(r["influence"] == 0 for r in benign)


class FakeLLM:
    def chat(self, messages, json_mode=False):
        if json_mode:
            return json.dumps({"directing_fragments": ["fragment:f2", "fragment:ghost"], "required_by_task": False,
                               "verdict": "injection_driven", "confidence": 0.9, "rationale": "x",
                               "evidence_ids": ["fragment:f2", "tool_call:zzz"]})
        return ("The page injected an instruction [fragment:f2]. The agent uploaded a file [tool_call:t3]. "
                "It also deleted the logs [process:doesnotexist]. Everything was fine.")


def test_llm_outputs_are_validated(tmp_path, sample_dir):
    c = make_case(tmp_path, sample_dir)
    analyze(c, llm=FakeLLM())
    out = c.read_output("llm.json")
    cls = out["classifications"][0]
    assert "fragment:ghost" in cls["unsupported_ids"] and "fragment:ghost" not in cls["directing_fragments"]
    s = out["summary"]
    assert "deleted the logs" not in s["summary"] and "Everything was fine" not in s["summary"]
    assert s["unsupported_rate_before_validation"] == 0.5


def test_validate_narrative():
    r = validate_narrative("A happened [a:1]. B happened [b:2].", {"a:1"})
    assert r["summary"] == "A happened [a:1]." and len(r["dropped"]) == 1


def test_harness_agent_records_trace(tmp_path):
    """Run the lab agent against a fake OpenAI-compatible server (no real model needed)."""
    state = {"n": 0}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            state["n"] += 1
            if state["n"] == 1:
                msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function",
                       "function": {"name": "shell", "arguments": json.dumps({"command": "echo hello"})}}]}
            else:
                msg = {"role": "assistant", "content": "done"}
            body = json.dumps({"choices": [{"message": msg}]}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    from harness.agent import run
    out = tmp_path / "run"
    assert run("say hello", f"http://127.0.0.1:{srv.server_port}", "fake", out) == "done"
    srv.shutdown()
    recs = [json.loads(l) for l in (out / "trace.jsonl").read_text().splitlines()]
    types = [r["type"] for r in recs]
    assert types[:4] == ["session_start", "user_prompt", "model_call", "tool_call"]
    res = next(r for r in recs if r["type"] == "tool_result")
    assert res["child_pid"] > 0 and res["exit_code"] == 0
    assert any(r["type"] == "context_fragment" and "hello" in r["text"] for r in recs)
    assert len((out / "requests.jsonl").read_text().splitlines()) == 2
