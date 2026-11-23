"""v0.8 evaluation release: in-trace ablations, the timestamp baseline, the dataset freeze and the
experiments script that writes every results table."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from prompttracir import ablation
from prompttracir.case import Case
from prompttracir.cli import main as cli_main
from prompttracir.experiments import check_freeze, freeze, run_experiments
from prompttracir.pipeline import analyze, ingest
from prompttracir.schema import Action

ROOT = Path(__file__).resolve().parents[1]
FILES = [("trace.jsonl", "agent_trace"), ("requests.jsonl", "agent_requests"), ("sysmon.jsonl", "sysmon"),
         ("ConsoleHost_history.txt", "psreadline"), ("zeek_conn.json", "zeek_conn")]


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """A runs folder with one analysed run (the synthetic sample) and its ground truth."""
    sample = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    root = tmp_path_factory.mktemp("runs")
    run = root / "s1"
    run.mkdir()
    gt = json.loads((sample / "ground_truth.json").read_text())
    gt.update(reviewed=True, family=gt.get("family") or "data_transmission")
    (run / "ground_truth.json").write_text(json.dumps(gt))
    c = Case.create(run / "case", "s1", json.loads((sample / "envelope.json").read_text()))
    for f, k in FILES:
        c.add_evidence(sample / f, k)
    ingest(c)
    analyze(c)
    return root


def _case(runs):
    return Case(runs / "s1" / "case")


def test_pid_ablation_strips_trace_pids_only(runs):
    ev = _case(runs).load_events()
    after = ablation.apply(ev, ablation.check(["pids"]))
    trace = [e for e in after if ablation._is_trace(e)]
    assert trace and all(e.pid is None and e.process_guid is None for e in trace
                         if e.action in (Action.SESSION_START, Action.TOOL_RESULT))
    host = [(a.pid, b.pid) for a, b in zip(ev, after) if not ablation._is_trace(a)]
    assert host and all(x == y for x, y in host)          # Sysmon keeps its PIDs


def test_context_ids_are_rebuilt_from_time_order(runs):
    ev = _case(runs).load_events()
    # wipe the identifiers, then let the ablation rebuild them
    wiped = [e.model_copy(update={"attrs": {**e.attrs, "input_fragments": []}}) if e.action == Action.MODEL_CALL
             else e.model_copy(update={"tool_call_id": None}) if e.action == Action.CONTEXT_FRAGMENT
             else e.model_copy(update={"model_call_id": None}) if e.action == Action.TOOL_CALL else e for e in ev]
    rebuilt = ablation.apply(wiped, ablation.check(["context_ids"]))
    key = lambda e: (e.attrs.get("input_fragments"), e.tool_call_id, e.model_call_id)   # noqa: E731
    assert [key(e) for e in rebuilt] == [key(e) for e in ev]   # the sample's agent is sequential


def test_unknown_ablation_is_rejected(runs):
    with pytest.raises(ValueError, match="unknown ablation"):
        analyze(_case(runs), ablate=["nope"], tag="x")


def test_timestamp_baseline_uses_time_only(runs):
    c = _case(runs)
    analyze(c, ablate=["timestamp_links"], tag="ts")
    out = c.view("ts")
    links = out.read_output("tool_links.json")
    assert links and all(l["signals"] == {"time_window": True} and l["status"] == "inferred" for l in links)
    att = out.read_output("attribution.json")
    assert att and all(a["signals"][0].startswith("baseline:") for a in att)
    assert out.read_output("config.json")["ablate"] == ["pids", "timestamp_links"]
    assert c.read_output("config.json")["ablate"] == []                  # the full analysis is untouched


def test_freeze_detects_changes(runs, tmp_path):
    root = tmp_path / "runs"
    shutil.copytree(runs, root)
    manifest = freeze(root)
    assert [r["run"] for r in manifest["runs"]] == ["s1"] and manifest["runs"][0]["evidence"]
    assert manifest["settings"]["prompt_version"] and manifest["settings"]["config_fingerprint"]
    assert check_freeze(root, manifest) == []
    gt = json.loads((root / "s1" / "ground_truth.json").read_text())
    (root / "s1" / "ground_truth.json").write_text(json.dumps(gt, indent=4) + "\r\n")   # same content
    assert check_freeze(root, manifest) == []
    gt["first_deviation"] = "tool_call:other"
    (root / "s1" / "ground_truth.json").write_text(json.dumps(gt))
    assert check_freeze(root, manifest) == ["s1: ground truth changed since the freeze"]


def test_experiments_write_every_table_and_repeat_exactly(runs, tmp_path):
    only = ["full", "no-pids", "timestamp-only", "no-local-model"]
    run_experiments(runs, tmp_path / "a", only=only, progress=lambda m: None)
    run_experiments(runs, tmp_path / "b", only=only, progress=lambda m: None)
    a = (tmp_path / "a" / "RESULTS.md").read_text()
    assert a == (tmp_path / "b" / "RESULTS.md").read_text()
    for heading in ("## Dataset", "## Table III", "## Baselines", "## Ablations", "## Narrative grounding"):
        assert heading in a
    assert "Without PID capture" in a and "Timestamp only" in a and "Analyst utility" in a
    res = json.loads((tmp_path / "a" / "experiments.json").read_text())
    assert set(res["conditions"]) == set(only)
    assert (tmp_path / "a" / "no-pids" / "per_run.csv").exists()


def test_cli_freeze_then_experiments(runs, tmp_path, capsys):
    manifest = tmp_path / "frozen.json"
    assert cli_main(["freeze", str(runs), "--out", str(manifest)]) == 0
    assert cli_main(["experiments", str(runs), "--out", str(tmp_path / "x"), "--freeze", str(manifest),
                     "--only", "full"]) == 0
    assert "runs and settings match" in capsys.readouterr().out
    gt = json.loads((runs / "s1" / "ground_truth.json").read_text())
    try:
        (runs / "s1" / "ground_truth.json").write_text(json.dumps({**gt, "family": "download"}))
        assert cli_main(["experiments", str(runs), "--out", str(tmp_path / "y"), "--freeze", str(manifest),
                         "--only", "full"]) == 2
    finally:
        (runs / "s1" / "ground_truth.json").write_text(json.dumps(gt))


def test_v10_missing_freeze_stops_unless_forced(runs, tmp_path):
    missing = str(tmp_path / "no-such-manifest.json")
    assert cli_main(["experiments", str(runs), "--out", str(tmp_path / "a"), "--freeze", missing, "--only", "full"]) == 2
    assert not (tmp_path / "a").exists()
    assert cli_main(["experiments", str(runs), "--out", str(tmp_path / "b"), "--freeze", missing,
                     "--only", "full", "--force"]) == 0
    assert b"\r\n" not in (tmp_path / "b" / "RESULTS.md").read_bytes()          # LF on every platform


def test_v10_dataset_package_leaves_out_raw_evidence(runs, tmp_path):
    import zipfile
    manifest = tmp_path / "frozen.json"
    cli_main(["freeze", str(runs), "--out", str(manifest)])
    out = tmp_path / "ds.zip"
    assert cli_main(["package-dataset", str(runs), "--out", str(out), "--include", str(manifest)]) == 0
    names = zipfile.ZipFile(out).namelist()
    assert "runs/s1/ground_truth.json" in names and "runs/s1/case/case.json" in names
    assert "runs/s1/case/output/graph.json" in names and "frozen.json" in names
    assert {"README.txt", "MANIFEST.txt"} <= set(names)
    assert not any("/evidence/" in n or n.endswith(".duckdb") for n in names)
    assert not any(n.startswith("runs/s1/case/output/") and n.count("/") > 4 for n in names)   # no output/<tag>/
    listed = zipfile.ZipFile(out).read("MANIFEST.txt").decode().splitlines()
    assert len(listed) == len(names) - 2
