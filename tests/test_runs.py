"""ptir add-run: one lab run folder -> one case."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.cli import main  # noqa: E402
from prompttracir.pipeline import analyze, ingest  # noqa: E402
from prompttracir.runs import add_run, plan  # noqa: E402


@pytest.fixture()
def run_dir(tmp_path):
    """Lay the synthetic sample out the way the harness and collect-run.ps1 do."""
    sample = tmp_path / "sample"
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    run = tmp_path / "run01"
    (run / "evidence").mkdir(parents=True)
    (run / "sources").mkdir()
    shutil.copy(sample / "trace.jsonl", run / "trace.jsonl")
    shutil.copy(sample / "requests.jsonl", run / "requests.jsonl")
    shutil.copy(sample / "sysmon.jsonl", run / "evidence" / "sysmon.jsonl")
    shutil.copy(sample / "ConsoleHost_history.txt", run / "evidence" / "ConsoleHost_history.txt")
    shutil.copy(sample / "zeek_conn.json", run / "evidence" / "conn.log")
    shutil.copy(sample / "ground_truth.json", run / "ground_truth.json")
    (run / "sources" / ("ab" * 32)).write_bytes(b"<html>original page bytes</html>")
    (run / "evidence" / "Sysmon.evtx").write_bytes(b"ElfFile\x00 not a real log")
    (run / "evidence" / "memory").mkdir()
    (run / "evidence" / "memory" / "mem.raw").write_bytes(b"\x00" * 64)
    (run / "human_run01.json").write_text(json.dumps({"shell_pid": 3500}))
    (run / "scenario.json").write_text(json.dumps(
        {"id": "x", "envelope": json.loads((sample / "envelope.json").read_text())}))
    return run


def test_plan_maps_kinds_and_skips_labels(run_dir):
    kinds = {f.relative_to(run_dir).as_posix(): k for f, k in plan(run_dir)}
    assert kinds["trace.jsonl"] == "agent_trace"
    assert kinds["evidence/sysmon.jsonl"] == "sysmon"
    assert kinds["evidence/Sysmon.evtx"] == "evtx_raw"          # not parsed twice
    assert kinds["evidence/ConsoleHost_history.txt"] == "psreadline"
    assert kinds["evidence/conn.log"] == "zeek_conn"
    assert kinds["evidence/memory/mem.raw"] == "memory_image"
    assert kinds["sources/" + "ab" * 32] == "agent_sources"
    for label in ("ground_truth.json", "human_run01.json", "scenario.json"):
        assert label not in kinds


def test_collection_manifest_overrides_patterns(run_dir):
    (run_dir / "evidence" / "odd_name.bin").write_bytes(b"x")
    (run_dir / "evidence" / "collection.json").write_text(json.dumps(
        {"files": [{"path": "odd_name.bin", "kind": "pcap"}]}))
    kinds = {f.name: k for f, k in plan(run_dir)}
    assert kinds["odd_name.bin"] == "pcap"
    assert "collection.json" not in kinds


def test_unknown_kind_in_manifest_is_rejected(run_dir):
    (run_dir / "evidence" / "collection.json").write_text(json.dumps(
        {"files": [{"path": "sysmon.jsonl", "kind": "sysmonn"}]}))
    with pytest.raises(ValueError, match="unknown evidence kind"):
        plan(run_dir)


def test_add_run_end_to_end(run_dir):
    case, added = add_run(run_dir / "case", run_dir)
    assert case.meta["envelope"]["allowed_paths"]            # envelope came from scenario.json
    counts = ingest(case)
    assert not any("evtx_raw" in k or "memory_image" in k for k in counts)   # preserved only
    summary = analyze(case)
    assert summary["first_deviation"] == "tool_call:t2"
    assert all(case.verify_evidence().values())
    # running add-run again must not duplicate the case
    add_run(run_dir / "case", run_dir)
    assert len(case.meta["evidence"]) == len(added)


def test_cli_rejects_unknown_kind(tmp_path, capsys):
    main(["init", str(tmp_path / "c"), "--name", "t"])
    f = tmp_path / "f.txt"; f.write_text("x")
    assert main(["add", str(tmp_path / "c"), str(f), "--kind", "sysmonn"]) == 2


def test_cli_add_directory(tmp_path):
    main(["init", str(tmp_path / "c"), "--name", "t"])
    d = tmp_path / "d"; (d / "sub").mkdir(parents=True)
    (d / "a.pf").write_bytes(b"a"); (d / "sub" / "b.pf").write_bytes(b"b")
    assert main(["add", str(tmp_path / "c"), str(d), "--kind", "prefetch"]) == 0
    from prompttracir.case import Case
    assert len(Case(tmp_path / "c").meta["evidence"]) == 2


def test_readding_keeps_ingest_state(run_dir):
    case, _ = add_run(run_dir / "case", run_dir)
    ingest(case)
    add_run(run_dir / "case", run_dir)
    assert ingest(case) == {}      # nothing re-ingested
    custody = (case.root / "custody.jsonl").read_text()
    assert '"evidence_duplicate"' in custody
