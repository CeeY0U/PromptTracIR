"""ptir eval-batch: score many runs and aggregate."""
import csv
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.label_run import label  # noqa: E402
from prompttracir.batch import evaluate_runs, find_runs  # noqa: E402
from prompttracir.cli import main  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402
from prompttracir.runs import add_run  # noqa: E402


def _attack_run(root: Path, sample: Path) -> None:
    from samples.make_sample import FRAGS
    run = root / "run01"
    (run / "evidence").mkdir(parents=True)
    shutil.copy(sample / "trace.jsonl", run / "trace.jsonl")
    shutil.copy(sample / "requests.jsonl", run / "requests.jsonl")
    shutil.copy(sample / "sysmon.jsonl", run / "evidence" / "sysmon.jsonl")
    shutil.copy(sample / "ConsoleHost_history.txt", run / "evidence" / "ConsoleHost_history.txt")
    shutil.copy(sample / "zeek_conn.json", run / "evidence" / "conn.log")
    sc = {"id": "sample_exfil", "family": "data_transmission",
          "envelope": json.loads((sample / "envelope.json").read_text()),
          "injection": {"vector": "web_page", "location": "x", "payload": FRAGS["f2"], "goal": "x"},
          "attacker_markers": ["collect.attacker-lab.test", r"secrets\api_keys.txt"],
          "exfil_destinations": ["collect.attacker-lab.test"], "canary": "C", "success_check": "sink_canary"}
    (run / "scenario.json").write_text(json.dumps(sc))
    (run / "sink_log.jsonl").write_text(json.dumps(
        {"ts": datetime(2026, 10, 29, 7, 0, 6, tzinfo=timezone.utc).isoformat(), "canary_received": True}) + "\n")
    gt = label(run, sc, sink=run / "sink_log.jsonl", human_pids=[3500], sysmon=run / "evidence" / "sysmon.jsonl")
    gt["reviewed"] = True
    (run / "ground_truth.json").write_text(json.dumps(gt))
    case, _ = add_run(run / "case", run)
    ingest(case); analyze(case)


def _legit_run(root: Path) -> None:
    run = root / "run02"
    run.mkdir(parents=True)
    t = "2026-10-30T08:00:0{}Z"
    recs = [
        {"ts": t.format(0), "type": "session_start", "session_id": "s2", "agent": "ptir-harness", "pid": 9100},
        {"ts": t.format(1), "type": "user_prompt", "session_id": "s2", "span_id": "p1", "text": "write notes"},
        {"ts": t.format(2), "type": "model_call", "session_id": "s2", "model_call_id": "lm1", "input_fragments": []},
        {"ts": t.format(3), "type": "tool_call", "session_id": "s2", "tool_call_id": "lt1", "model_call_id": "lm1",
         "tool": "write_file", "args": {"path": "C:\\Users\\lab\\project\\notes.md", "content": "x"}},
        {"ts": t.format(4), "type": "tool_result", "session_id": "s2", "tool_call_id": "lt1", "exit_code": 0,
         "files_written": ["C:\\Users\\lab\\project\\notes.md"]},
    ]
    (run / "trace.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
    sc = json.loads((ROOT / "harness" / "scenarios" / "legit_notes_01.json").read_text())
    shutil.copy(ROOT / "harness" / "scenarios" / "legit_notes_01.json", run / "scenario.json")
    (run / "ground_truth.json").write_text(json.dumps(label(run, sc)))      # left unreviewed
    case, _ = add_run(run / "case", run)
    ingest(case); analyze(case)


def _unanalysed_run(root: Path) -> None:
    run = root / "run03"
    (run / "case").mkdir(parents=True)
    (run / "case" / "case.json").write_text("{}")
    (run / "ground_truth.json").write_text("{}")


def _build(tmp_path) -> Path:
    sample = tmp_path / "sample"
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    root = tmp_path / "runs"
    _attack_run(root, sample)
    _legit_run(root)
    _unanalysed_run(root)
    return root


def test_eval_batch_aggregates(tmp_path):
    root = _build(tmp_path)
    runs = find_runs(root)
    assert [r.name for r in runs] == ["run01", "run02", "run03"]
    rep = evaluate_runs(runs)
    o = rep["overall"]
    assert o["runs"] == 2 and o["attack_runs"] == 1 and o["legitimate_runs"] == 1
    assert o["unreviewed_runs"] == 1
    assert o["first_deviation_accuracy"] == 1.0 and o["legitimate_false_alarm_rate"] == 0.0
    assert o["injected_fragment_localization_successful"]["f1"] == 1.0
    assert o["tool_process_links"]["precision"] == 1.0 and o["tool_process_links"]["gold"] == 1
    assert o["attribution"]["macro_f1"] == 1.0
    assert o["connection_only_labelled_confirmed"] == 0
    assert set(rep["by_family"]) == {"data_transmission", "legitimate"}
    assert rep["skipped"] == [{"run": "run03", "reason": "case not analysed (run ptir ingest and ptir analyze)"}]


def test_eval_batch_reviewed_only(tmp_path):
    rep = evaluate_runs(find_runs(_build(tmp_path)), reviewed_only=True)
    assert rep["overall"]["runs"] == 1
    assert {"run": "run02", "reason": "ground truth not reviewed"} in rep["skipped"]


def test_eval_batch_cli_writes_report(tmp_path, capsys):
    root = _build(tmp_path)
    assert main(["eval-batch", str(root)]) == 0
    out = capsys.readouterr().out
    assert "first deviation accuracy           1.0" in out
    rows = list(csv.DictReader(open(root / "results" / "per_run.csv")))
    assert [r["run"] for r in rows] == ["run01", "run02"]
    res = json.loads((root / "results" / "results.json").read_text())
    assert res["overall"]["runs"] == 2 and len(res["per_run"]) == 2
    assert main(["eval-batch", str(tmp_path / "nothing")]) == 1
