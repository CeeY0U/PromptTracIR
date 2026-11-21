"""v0.7 analyst interface and export: STIX 2.1 bundle (valid, deterministic, ATLAS / ATT&CK
tags), the attack-flow, timeline and evidence views, the raw-record viewer, and the API and
static files the single-page UI uses."""
import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from prompttracir import stix, views
from prompttracir.api import create_app
from prompttracir.case import Case
from prompttracir.cli import main as cli_main
from prompttracir.pipeline import analyze, ingest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    sample = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    c = Case.create(tmp_path_factory.mktemp("c") / "case", "v07", json.loads((sample / "envelope.json").read_text()))
    for f, k in [("trace.jsonl", "agent_trace"), ("requests.jsonl", "agent_requests"), ("sysmon.jsonl", "sysmon"),
                 ("ConsoleHost_history.txt", "psreadline"), ("zeek_conn.json", "zeek_conn")]:
        c.add_evidence(sample / f, k)
    ingest(c)
    analyze(c)
    return c


# ---------- STIX ----------

def test_stix_bundle_is_deterministic_and_tagged(case):
    a, b = stix.export_case(case), stix.export_case(case)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    types = {o["type"] for o in a["objects"]}
    assert {"process", "file", "network-traffic", "observed-data", "attack-pattern", "sighting",
            "incident", "report", "extension-definition"} <= types
    tags = {o["external_references"][0]["external_id"] for o in a["objects"] if o["type"] == "attack-pattern"}
    # the sample is an indirect injection that uploads a secret
    assert {"AML.T0051.001", "AML.T0053", "AML.T0086", "T1700"} <= tags
    assert "T1053.005" not in tags and "T1547.001" not in tags                  # no persistence in it


def test_stix_carries_evidence_states_in_the_extension(case):
    bundle = stix.export_case(case)
    ext = next(o["id"] for o in bundle["objects"] if o["type"] == "extension-definition")
    ods = [o for o in bundle["objects"] if o["type"] == "observed-data" and "finding" in o["extensions"][ext]]
    assert ods
    for od in ods:
        props = od["extensions"][ext]
        assert props["extension_type"] == "property-extension"
        assert set(props["evidence_status"]) <= {"observed", "corroborated", "inferred", "contradicted"}
        assert props["records"]                                                   # back to raw records
    procs = [o for o in bundle["objects"] if o["type"] == "process"]
    assert any(p["extensions"][ext].get("attribution") == "agent" for p in procs)


def test_stix_bundle_validates(case):
    pytest.importorskip("stix2validator")
    ok, errors = stix.validate(stix.export_case(case))
    assert ok, errors


def test_export_stix_command(case, capsys):
    out = case.root / "output" / "stix_bundle.json"
    out.unlink(missing_ok=True)
    cli_main(["export-stix", str(case.root)])
    assert json.loads(out.read_text())["type"] == "bundle"


# ---------- views ----------

def test_attack_flow_runs_from_request_to_the_deviation(case):
    steps = views.attack_flow(case)["steps"]
    assert [s["stage"] for s in steps[:2]] == ["request", "entry_point"]
    calls = [s for s in steps if s["stage"] == "tool_call"]
    assert sum(1 for s in calls if s["deviation"]) == 1
    dev = next(s for s in calls if s["deviation"])
    assert dev["node"]["label"].startswith("read_file(") and dev["findings"]   # the sample reads the secret first
    upload = calls[-1]
    assert upload["processes"] and {"external_egress"} <= {f["kind"] for f in upload["findings"]}
    assert all(e["status"] in ("observed", "corroborated", "inferred", "contradicted") for e in dev["effects"])


def test_timeline_filters(case):
    every = views.timeline(case, None, None, False, 5000)
    assert every["matched"] == len(every["rows"]) == sum(every["sources"].values())
    chain = views.timeline(case, None, None, True, 5000)
    assert 0 < chain["matched"] < every["matched"] and all(r["in_chain"] for r in chain["rows"])
    sysmon = views.timeline(case, "sysmon", None, False, 5000)
    assert sysmon["rows"] and {r["source"] for r in sysmon["rows"]} == {"sysmon"}
    q = views.timeline(case, None, "curl", False, 5000)
    assert q["rows"] and all("curl" in json.dumps(r).lower() for r in q["rows"])
    assert len(views.timeline(case, None, None, False, 3)["rows"]) == 3


def test_raw_record_reads_the_preserved_copy(case):
    rows = views.timeline(case, None, None, False, 5000)["rows"]
    seen = set()
    for r in rows:
        if r["source"] in seen:
            continue
        seen.add(r["source"])
        raw = views.raw_record(case, r["event_id"])
        assert raw["content"] not in (None, "", {}), r["source"]
        assert (case.root / raw["file"]).exists()
    assert seen == {"sysmon", "agent_trace", "zeek", "psreadline"}
    trace = next(r for r in rows if r["source"] == "agent_trace" and r["action"] == "tool_call")
    assert views.raw_record(case, trace["event_id"])["content"]["type"] == "tool_call"


def test_evidence_view_lists_items_and_custody(case):
    ev = views.evidence(case)
    assert len(ev["items"]) == 5 and all(len(i["sha256"]) == 64 for i in ev["items"])
    assert {"evidence_added", "ingested", "analyzed"} <= {c["action"] for c in ev["custody"]}


# ---------- API and UI ----------

def test_api_and_static_files(case):
    cl = TestClient(create_app(case))
    page = cl.get("/").text
    assert "/static/cytoscape.min.js" in page and "unpkg" not in page          # works offline
    js = cl.get("/static/cytoscape.min.js")
    assert js.status_code == 200 and len(js.content) > 100_000
    assert cl.get("/api/flow").json()["steps"]
    assert cl.get("/api/timeline", params={"chain": "true", "limit": 5}).json()["shown"] <= 5
    assert cl.get("/api/evidence").json()["items"]
    assert cl.get("/api/raw/no-such-event").status_code == 404
    assert cl.get("/api/llm").json().get("summary") is None                    # explain not run
    assert cl.post("/api/verify").json()["ok"]
    r = cl.get("/api/export/stix")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert r.json()["type"] == "bundle"


def test_case_made_on_windows_opens_on_linux(case, tmp_path):
    # Before v0.7 a case made on Windows stored "evidence\<sha>\name"; mounted into the Docker
    # image (Linux) it must still verify and show raw records.
    import shutil
    copy = tmp_path / "wincase"
    shutil.copytree(case.root, copy)
    meta = json.loads((copy / "case.json").read_text())
    for info in meta["evidence"].values():
        info["file"] = info["file"].replace("/", "\\")
    (copy / "case.json").write_text(json.dumps(meta))
    c = Case(copy) if not hasattr(Case, "load") else Case.load(copy)
    assert all(c.verify_evidence().values())
    row = views.timeline(c, "sysmon", None, False, 1)["rows"][0]
    assert views.raw_record(c, row["event_id"])["content"]
    assert all("\\" not in i["file"] for i in json.loads((case.root / "case.json").read_text())["evidence"].values())
