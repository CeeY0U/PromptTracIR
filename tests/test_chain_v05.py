"""v0.5 chain reconstruction: transcript cross-check, tampered traces, chain metrics, inventory.

Built on the synthetic sample (samples/make_sample.py) laid out as a lab run folder. On the
real lab runs of 16 Nov (jt-01..05, cy-03, cy-05, run04) the same checks gave: chain edge F1 1.0,
path exact match 1.0, 3 of 3 tampered copies detected, 0 contradictions on untampered runs.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

from prompttracir.batch import evaluate_runs
from prompttracir.case import Case
from prompttracir.evaluate import chain_scores, gold_chain
from prompttracir.parsers import PARSERS
from prompttracir.pipeline import analyze, ingest
from prompttracir.runs import add_run

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.tamper_trace import tamper  # noqa: E402


def _run_folder(tmp_path: Path) -> Path:
    sample = ROOT / "samples" / "scenario_exfil"
    if not (sample / "trace.jsonl").exists():
        subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py")], check=True)
    run = tmp_path / "s01"
    (run / "evidence").mkdir(parents=True)
    shutil.copy(sample / "trace.jsonl", run / "trace.jsonl")
    shutil.copy(sample / "requests.jsonl", run / "requests.jsonl")
    shutil.copy(sample / "sysmon.jsonl", run / "evidence" / "sysmon.jsonl")
    shutil.copy(sample / "ConsoleHost_history.txt", run / "evidence" / "ConsoleHost_history.txt")
    gt = json.loads((sample / "ground_truth.json").read_text())
    gt.update(reviewed=True, family="data_transmission", injection_present=True, injection_followed=True,
              attack_succeeded=True,
              malicious_details=[{"tool_call": "tool_call:t3", "files": ["C:\\Users\\lab\\secrets\\api_keys.txt"],
                                  "destinations": ["collect.attacker-lab.test"]}])
    (run / "ground_truth.json").write_text(json.dumps(gt))
    env = json.loads((sample / "envelope.json").read_text())
    (run / "scenario.json").write_text(json.dumps({"id": "sample", "envelope": env}))
    return run


def _analyse(run: Path) -> dict:
    case, _ = add_run(run / "case", run)
    ingest(case)
    return analyze(case)


def test_untampered_run_has_no_contradiction(tmp_path):
    run = _run_folder(tmp_path)
    res = _analyse(run)
    assert res["contradicted"] == 0
    cc = Case(run / "case").read_output("crosscheck.json")
    assert any(c["verdict"] == "agree" for c in cc)


def test_edited_command_is_contradicted_by_sysmon(tmp_path):
    run = _run_folder(tmp_path)
    out = tmp_path / "s01-edit"
    t = tamper(run, out, "edit-command", "t3")
    assert t["original_command"].startswith("curl.exe")
    res = _analyse(out)
    assert res["contradicted"] >= 1
    f = [x for x in Case(out / "case").read_output("findings.json") if x["kind"] == "transcript_mismatch"]
    assert f and f[0]["attrs"]["tool_call"] == "tool_call:t3"


def test_dropped_call_leaves_an_untraced_process(tmp_path):
    run = _run_folder(tmp_path)
    out = tmp_path / "s01-drop"
    tamper(run, out, "drop-call", "t3")
    _analyse(out)
    kinds = [x["kind"] for x in Case(out / "case").read_output("findings.json")]
    assert "untraced_agent_process" in kinds


def test_tampered_copies_count_only_for_detection(tmp_path):
    run = _run_folder(tmp_path)
    _analyse(run)
    tamper(run, tmp_path / "s02-edit", "edit-command", "t3")
    _analyse(tmp_path / "s02-edit")
    rep = evaluate_runs([run, tmp_path / "s02-edit"])
    o = rep["overall"]
    assert o["runs"] == 1 and o["tampered_runs"] == 1 and o["tampering_detected"] == 1
    assert o["contradictions_on_untampered_runs"] == 0


def test_chain_scores_exact_match_and_misses():
    gt = {"injected_fragments": ["fragment:f2"], "malicious_tool_calls": ["tool_call:t3"],
          "tool_process_links": {"tool_call:t3": "g1"},
          "malicious_details": [{"tool_call": "tool_call:t3", "files": ["C:\\Users\\lab\\secrets\\api_keys.txt"],
                                 "destinations": ["Collect.Attacker-Lab.test"]}]}
    assert len(gold_chain(gt)) == 4
    graph = {"edges": [{"src": "fragment:f2", "dst": "tool_call:t3", "relation": "influenced", "confidence": 0.6}]}
    findings = [{"kind": "out_of_scope_file", "attrs": {"tool_call": "tool_call:t3",
                                                        "path": "C:\\\\Users\\\\lab\\\\secrets\\\\api_keys.txt"}},
                {"kind": "external_egress", "attrs": {"tool_call": "tool_call:t3",
                                                      "destination": "collect.attacker-lab.test"}}]
    links = [{"tool_call_id": "t3", "process_guid": "g1"}]
    s = chain_scores(gt, graph, findings, links, lambda g: g)
    assert s["path_exact_match"] and s["edges"]["f1"] == 1.0
    s = chain_scores(gt, graph, findings[:1], links, lambda g: g)
    assert not s["path_exact_match"] and s["edges"]["recall"] == 0.75
    assert chain_scores({}, graph, findings, links, lambda g: g)["scored"] is False


def test_file_inventory_parser(tmp_path):
    inv = tmp_path / "file_inventory.json"
    inv.write_text(json.dumps({"collected_utc": "2026-11-16T11:46:00Z", "files": [
        {"path": "C:\\Users\\lab\\secrets\\api_keys.txt", "size": 214, "sha256": "AB" * 32}]}))
    [e] = list(PARSERS["file_inventory"](inv, "f" * 64))
    assert e.object.endswith("api_keys.txt") and e.attrs["size"] == 214 and e.attrs["sha256"] == "ab" * 32
