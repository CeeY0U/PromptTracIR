"""v0.4 evaluation: calibration of P(agent) and of tool-link scores."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.case import Case  # noqa: E402
from prompttracir.correlate import agent_probability  # noqa: E402
from prompttracir.evaluate import calibration, evaluate_case  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    out = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(out)], check=True)
    return out


def _case(tmp: Path, sample: Path, name: str, files) -> Case:
    c = Case.create(tmp / name, name, json.loads((sample / "envelope.json").read_text()))
    for f, k in files:
        c.add_evidence(f, k)
    ingest(c)
    return c


def test_calibration_math():
    assert calibration([]) == {"ece": None, "brier": None, "n": 0}
    perfect = calibration([(1.0, True), (0.0, False)])
    assert perfect["ece"] == 0.0 and perfect["brier"] == 0.0
    bad = calibration([(0.9, False), (0.9, False)])
    assert bad["ece"] == 0.9 and bad["brier"] == 0.81
    assert agent_probability(3.0, 0.0, 1.5) > 0.85 and agent_probability(0.0, 0.0, 1.5) == 0.5


def test_evaluate_reports_probabilities_and_link_scores(tmp_path, sample):
    c = _case(tmp_path, sample, "c", [(sample / "trace.jsonl", "agent_trace"), (sample / "sysmon.jsonl", "sysmon")])
    analyze(c)
    gt = json.loads((sample / "ground_truth.json").read_text())
    gt["tool_process_links"] = {"tool_call:t3": "a0000006-1111-6a00-0000-001000000006"}
    r = evaluate_case(c, gt)
    assert all(row["p_agent"] is not None for row in r["attribution"]["rows"])
    assert r["attribution"]["calibration"]["n"] == 3 and r["attribution"]["calibration"]["ece"] < 0.2
    assert r["tool_process_links"]["scored"] == [{"score": 1.0, "correct": True, "status": "corroborated"}]
