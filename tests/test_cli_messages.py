"""CLI messages that confused the first lab runs (15 Nov 2026)."""
from prompttracir.cli import main


def test_missing_case_is_a_message_not_a_traceback(tmp_path, capsys):
    assert main(["ingest", str(tmp_path / "nocase")]) == 2
    assert "case.json not found" in capsys.readouterr().err


def test_missing_envelope_mentions_git_bash_paths(tmp_path, capsys):
    assert main(["init", str(tmp_path / "c"), "--name", "x", "--envelope", "C:/Program Files/Git/envelope.json"]) == 2
    err = capsys.readouterr().err
    assert "envelope file not found" in err and "./envelope.json" in err


def test_add_run_again_reports_only_new_files(tmp_path, capsys):
    run = tmp_path / "run01"
    (run / "evidence").mkdir(parents=True)
    (run / "trace.jsonl").write_text('{"type": "session_start"}\n')
    (run / "evidence" / "sysmon.jsonl").write_text("")
    assert main(["add-run", str(run)]) == 0
    assert "2 new files added" in capsys.readouterr().out
    (run / "evidence" / "zeek").mkdir()
    (run / "evidence" / "zeek" / "conn.log").write_text("#fields\tts\n")
    assert main(["add-run", str(run)]) == 0
    out = capsys.readouterr().out
    assert "1 new file added" in out and "(2 already in the case, skipped)" in out
    assert "sysmon.jsonl" not in out
