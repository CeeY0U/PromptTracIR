"""v0.3.0: Security 4663 file access on audited paths."""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.case import Case  # noqa: E402
from prompttracir.parsers import windows  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402
from prompttracir.schema import Action, EventSource  # noqa: E402

T0 = datetime(2026, 10, 29, 7, 0, 0, tzinfo=timezone.utc)


# ---------------- Security 4663 ----------------
SECRET = r"C:\Users\lab\secrets\api_keys.txt"


def _sec(rec: int, sec: float, pid: int, image: str, mask: str, obj: str = SECRET, otype: str = "File") -> dict:
    return {"EventID": 4663, "TimeCreated": (T0 + timedelta(seconds=sec)).isoformat().replace("+00:00", "Z"),
            "Computer": "LAB-WIN11", "RecordID": rec, "Channel": "Security",
            "EventData": {"SubjectUserName": "lab", "SubjectDomainName": "LAB-WIN11", "SubjectLogonId": "0x5a3f1",
                          "ObjectType": otype, "ObjectName": obj, "HandleId": "0x1f4", "AccessList": "%%4416",
                          "AccessMask": mask, "ProcessId": hex(pid), "ProcessName": image}}


def test_4663_parsing(tmp_path):
    f = tmp_path / "security.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in [
        _sec(1, 3.05, 4100, r"C:\Python312\python.exe", "0x1"),
        _sec(2, 3.06, 4100, r"C:\Python312\python.exe", "0x2"),
        _sec(3, 3.07, 4100, r"C:\Python312\python.exe", "0x1", obj=r"HKLM\SOFTWARE\x", otype="Key"),
    ]) + "\n")
    evs = list(windows.parse(f, "d" * 64))
    assert [e.action for e in evs] == [Action.FILE_READ, Action.FILE_MODIFY]      # registry object skipped
    r = evs[0]
    assert r.source == EventSource.SECURITY and r.pid == 4100 and r.process_guid is None
    assert r.object == SECRET and r.attrs["access_mask"] == "0x1" and r.attrs["via"] == "4663"


@pytest.fixture()
def sample_case(tmp_path):
    sample = tmp_path / "s"
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    c = Case.create(tmp_path / "case", "t", json.loads((sample / "envelope.json").read_text()))
    for f, k in [("trace.jsonl", "agent_trace"), ("sysmon.jsonl", "sysmon"), ("zeek_conn.json", "zeek_conn")]:
        c.add_evidence(sample / f, k)
    return c, tmp_path


def test_4663_corroborates_trace_read_and_joins_child_process(sample_case):
    c, tmp = sample_case
    sec = tmp / "security.jsonl"
    sec.write_text("\n".join(json.dumps(r) for r in [
        _sec(10, 3.05, 4100, r"C:\Python312\python.exe", "0x1"),      # read_file tool call t2, in-process
        _sec(11, 5.12, 5210, r"C:\Windows\System32\curl.exe", "0x1"),  # curl uploading the file
        _sec(12, 6.20, 9999, r"C:\Windows\notepad.exe", "0x1"),       # unknown PID: not joined
    ]) + "\n")
    c.add_evidence(sec, "security")
    ingest(c)
    s = analyze(c)
    assert s["first_deviation"] == "tool_call:t2"
    g = c.read_output("graph.json")
    fid = "file:" + SECRET.lower()
    t2 = next(e for e in g["edges"] if e["src"] == "tool_call:t2" and e["dst"] == fid and e["relation"] == "read")
    assert t2["status"] == "corroborated" and t2["signals"]["trace_claim_match"]
    curl = next(e for e in g["edges"] if e["dst"] == fid and e["src"].startswith("process:")
                and e["relation"] == "read")
    assert curl["status"] == "observed" and curl["signals"]["joined_by"] == "pid_and_time"
    assert "notepad" not in json.dumps([n for n in g["nodes"] if n["id"].startswith("process:")]).lower()
    reads = [f for f in c.read_output("findings.json")
             if f["kind"] == "out_of_scope_file" and f["attrs"]["relation"] == "read"]
    assert {f["attrs"]["tool_call"] for f in reads} >= {"tool_call:t2", "tool_call:t3"}
