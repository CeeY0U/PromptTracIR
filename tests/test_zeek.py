"""v0.3.0: Zeek conn/dns/http logs in JSON and tab-separated form."""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.case import Case  # noqa: E402
from prompttracir.parsers import zeek  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402
from prompttracir.runs import plan  # noqa: E402
from prompttracir.schema import Action, EventSource  # noqa: E402

T0 = datetime(2026, 10, 29, 7, 0, 0, tzinfo=timezone.utc)


def _epoch(sec: float) -> float:
    return (T0 + timedelta(seconds=sec)).timestamp()


def _tsv(path: Path, log: str, fields: list[str], types: list[str], rows: list[list[str]]) -> Path:
    head = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
            f"#path\t{log}", "#open\t2026-10-29-07-00-00", "#fields\t" + "\t".join(fields),
            "#types\t" + "\t".join(types)]
    path.write_text("\n".join(head + ["\t".join(r) for r in rows] + ["#close\t2026-10-29-07-01-00"]) + "\n")
    return path


# ---------------- Zeek ----------------
CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
               "duration", "orig_bytes", "resp_bytes"]


def test_zeek_conn_tsv_matches_json(tmp_path):
    sample = tmp_path / "s"
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    js = list(zeek.parse_conn(sample / "zeek_conn.json", "a" * 64))
    rows = []
    for line in (sample / "zeek_conn.json").read_text().splitlines():
        r = json.loads(line)
        rows.append([f"{r['ts']:.6f}"] + [str(r[k]) for k in CONN_FIELDS[1:]])
    tsv = _tsv(tmp_path / "conn.log", "conn", CONN_FIELDS, ["time"] + ["string"] * 10, rows)
    ts = list(zeek.parse_conn(tsv, "a" * 64))
    assert [(e.object, e.attrs["orig_bytes"], e.attrs["resp_p"]) for e in ts] == \
           [(e.object, e.attrs["orig_bytes"], e.attrs["resp_p"]) for e in js]
    assert [e.timestamp for e in ts] == [e.timestamp for e in js]
    assert zeek.parse is zeek.parse_conn                     # old name still works


def test_zeek_conn_unset_bytes(tmp_path):
    tsv = _tsv(tmp_path / "conn.log", "conn", CONN_FIELDS, ["string"] * 11,
               [[f"{_epoch(1):.6f}", "C9", "10.0.0.2", "50000", "10.0.0.9", "443", "tcp", "-", "-", "-", "-"]])
    e = next(zeek.parse_conn(tsv, "a" * 64))
    assert e.attrs["orig_bytes"] == 0 and e.attrs["service"] is None and e.attrs["duration"] is None


def test_zeek_dns_json_and_tsv(tmp_path):
    j = tmp_path / "dns.json"
    j.write_text(json.dumps({"ts": _epoch(5.14), "uid": "D1", "id.orig_h": "10.10.10.20", "id.resp_h": "10.10.10.1",
                             "query": "collect.attacker-lab.test", "qtype_name": "A", "rcode_name": "NOERROR",
                             "answers": ["203.0.113.50"], "TTLs": [60.0]}) + "\n")
    tsv = _tsv(tmp_path / "dns.log", "dns",
               ["ts", "uid", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "answers"],
               ["time"] + ["string"] * 7,
               [[f"{_epoch(5.14):.6f}", "D1", "10.10.10.20", "10.10.10.1", "collect.attacker-lab.test", "A",
                 "NOERROR", "203.0.113.50,198.51.100.7"],
                [f"{_epoch(6):.6f}", "D2", "10.10.10.20", "10.10.10.1", "-", "-", "-", "-"]])   # no query: skipped
    a, = zeek.parse_dns(j, "b" * 64)
    b = list(zeek.parse_dns(tsv, "b" * 64))
    assert len(b) == 1
    for e in (a, b[0]):
        assert e.action == Action.DNS_QUERY and e.source == EventSource.ZEEK
        assert e.object == "collect.attacker-lab.test" and e.pid is None
    assert a.attrs["results"] == "203.0.113.50"
    assert b[0].attrs["answers"] == ["203.0.113.50", "198.51.100.7"]


def test_zeek_http(tmp_path):
    tsv = _tsv(tmp_path / "http.log", "http",
               ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "method", "host", "uri", "user_agent",
                "request_body_len", "response_body_len", "status_code"],
               ["time"] + ["string"] * 11,
               [[f"{_epoch(5.2):.6f}", "H1", "10.10.10.20", "203.0.113.50", "8443", "POST",
                 "collect.attacker-lab.test", "/u", "curl/8.9.1", "2210", "2", "200"]])
    e, = zeek.parse_http(tsv, "c" * 64)
    assert e.action == Action.HTTP_REQUEST and e.object == "collect.attacker-lab.test/u"
    assert e.attrs["method"] == "POST" and e.attrs["request_body_len"] == 2210 and e.attrs["status_code"] == 200


def test_zeek_rejects_headerless_tsv(tmp_path):
    f = tmp_path / "conn.log"
    f.write_text("1730185200.0\tC1\t10.0.0.1\n")
    with pytest.raises(ValueError, match="#fields"):
        list(zeek.parse_conn(f, "a" * 64))


def test_add_run_maps_zeek_logs(tmp_path):
    run = tmp_path / "run01"
    (run / "evidence" / "zeek").mkdir(parents=True)
    for name in ("conn.log", "dns.log", "http.log", "ssl.log"):
        (run / "evidence" / "zeek" / name).write_text("#fields\tts\n")
    kinds = {f.name: k for f, k in plan(run)}
    assert kinds == {"conn.log": "zeek_conn", "dns.log": "zeek_dns", "http.log": "zeek_http", "ssl.log": "other"}



@pytest.fixture()
def sample_case(tmp_path):
    sample = tmp_path / "s"
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    c = Case.create(tmp_path / "case", "t", json.loads((sample / "envelope.json").read_text()))
    for f, k in [("trace.jsonl", "agent_trace"), ("sysmon.jsonl", "sysmon"), ("zeek_conn.json", "zeek_conn")]:
        c.add_evidence(sample / f, k)
    return c, tmp_path


def test_zeek_dns_ingests_into_sample(sample_case):
    c, tmp = sample_case
    d = tmp / "dns.json"
    d.write_text(json.dumps({"ts": _epoch(5.14), "uid": "D1", "id.orig_h": "10.10.10.20", "id.resp_h": "10.10.10.1",
                             "query": "collect.attacker-lab.test", "answers": ["203.0.113.50"]}) + "\n")
    c.add_evidence(d, "zeek_dns")
    ingest(c)
    s = analyze(c)
    assert s["first_deviation"] == "tool_call:t2" and dict(s["impact"])["collect.attacker-lab.test"] == "confirmed"
    g = c.read_output("graph.json")
    assert any(e["src"] == "domain:collect.attacker-lab.test" and e["relation"] == "resolved_to"
               and "zeek_dns" in " ".join(e["evidence"]) for e in g["edges"])
