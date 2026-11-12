"""v0.3 Windows artifact parsers: EZ Tools CSV output and Volatility 3 JSON.

Fixtures in tests/fixtures/v03/ follow the column layouts of the tools' own CSV classes and the
Volatility TreeGrid columns, and tell the same story as samples/make_sample.py: the agent's curl
uploads C:\\Users\\lab\\secrets\\api_keys.txt and drops a startup script, while the human had
opened the secrets file and folder earlier from Explorer.
"""
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.case import Case  # noqa: E402
from prompttracir.parsers import KNOWN_KINDS, PARSERS, PRESERVE_ONLY, ez, volatility  # noqa: E402
from prompttracir.pipeline import ingest  # noqa: E402
from prompttracir.runs import plan  # noqa: E402
from prompttracir.schema import Action, EventSource  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "v03"
EID = "a" * 64
SECRET = r"C:\Users\lab\secrets\api_keys.txt"
STARTUP = r"C:\Users\lab\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.cmd"


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


def by_object(evs, obj):
    return [e for e in evs if e.object == obj]


# ---------------- NTFS ----------------
def test_mft_records():
    evs = list(ez.parse_mft(FX / "20261029070100_MFTECmd_$MFT_Output.csv", EID))
    assert all(e.source == EventSource.MFT for e in evs)
    assert not any(e.object == r"C:\Users\lab\secrets" for e in evs)          # directories skipped
    secret = by_object(evs, SECRET)
    assert [e.action for e in secret] == [Action.FILE_CREATE, Action.FILE_MODIFY]
    assert secret[0].timestamp == utc(2026, 10, 20, 9, 14, 3, 123456)         # 7-digit fraction truncated
    assert secret[0].attrs["size"] == 412 and secret[0].attrs["ts_meaning"] == "$SI created"
    # Startup script: $SI created back-dated to 2024 but $FN says the run -> timestomp flag kept
    stomped = by_object(evs, STARTUP)[0]
    assert stomped.attrs["timestomped"] and stomped.attrs["fn_created"].startswith("2026-10-29")
    # A deleted record is kept with in_use False and its zone identifier
    payload = by_object(evs, r"C:\Users\lab\Downloads\payload.ps1")
    assert len(payload) == 1 and payload[0].attrs["in_use"] is False      # created == modified
    assert "ZoneId=3" in payload[0].attrs["zone_id"]
    assert len({e.event_id for e in evs}) == len(evs)


def test_usn_close_records_only():
    evs = list(ez.parse_usn(FX / "20261029070100_MFTECmd_$J_Output.csv", EID))
    got = [(e.action, e.object.rsplit("\\", 1)[-1]) for e in evs]
    assert got == [(Action.FILE_CREATE, "updater.tmp"), (Action.FILE_RENAME, "updater.cmd"),
                   (Action.FILE_DELETE, "payload.ps1"), (Action.FILE_MODIFY, "notes.md")]
    rename = evs[1]
    assert rename.object == STARTUP and rename.attrs["old_name"].endswith("updater.tmp")
    # $J parsed without -m $MFT: no parent path, recorded as unresolved
    assert evs[2].object == "payload.ps1" and evs[2].attrs["path_resolved"] is False


# ---------------- execution ----------------
def test_prefetch_run_times_and_path():
    evs = list(ez.parse_prefetch(FX / "20261029070100_PECmd_Output.csv", EID))
    curl = [e for e in evs if e.attrs["executable"] == "CURL.EXE"]
    assert [e.timestamp for e in curl] == [utc(2026, 10, 29, 7, 0, 5), utc(2026, 10, 21, 8, 0, 0)]
    assert curl[0].image == r"C:\WINDOWS\SYSTEM32\CURL.EXE"                  # from FilesLoaded
    assert curl[0].attrs["authorship_weight"] == "weak" and curl[0].attrs["run_count"] == 2
    assert all(e.action == Action.PROGRAM_RUN and e.ts_precision == "s" for e in evs)


def test_amcache_is_not_execution_time():
    evs = list(ez.parse_amcache(FX / "20261029070100_Amcache_UnassociatedFileEntries.csv", EID))
    assert len(evs) == 1                                                     # row without a time dropped
    e = evs[0]
    assert e.action == Action.PROGRAM_PRESENT and e.image == r"c:\users\lab\downloads\payload.exe"
    assert e.attrs["sha1"] == "1234567890abcdef1234567890abcdef12345678"    # 0000 padding removed
    assert "not execution time" in e.attrs["ts_meaning"]


# ---------------- network usage ----------------
def test_srum_network_usage():
    evs = list(ez.parse_srum(FX / "20261029070100_SrumECmd_NetworkUsages_Output.csv", EID))
    curl = next(e for e in evs if e.image.endswith("curl.exe"))
    assert curl.action == Action.NET_USAGE and curl.ts_precision == "h"
    assert curl.attrs["bytes_sent"] == 48211 and curl.user == r"LAB-PC\lab"


# ---------------- registry ----------------
def test_registry_userassist_autorun_and_other():
    evs = list(ez.parse_registry(FX / "20261029070100_RECmd_Batch_Kroll_Batch_Output.csv", EID))
    acts = [e.action for e in evs]
    assert acts == [Action.GUI_LAUNCH, Action.GUI_LAUNCH, Action.AUTORUN, Action.REGISTRY_VALUE]
    ua = evs[0]
    assert ua.image.endswith("powershell.exe") and ua.attrs["run_count"] == 14
    assert ua.timestamp == utc(2026, 10, 29, 6, 59, 30)
    # No last-executed time: falls back to the key last-write and says so
    assert evs[1].attrs["run_count"] == 1203 and "key last-write" in evs[1].attrs["ts_meaning"]
    run = evs[2]
    assert run.object == r"Software\Microsoft\Windows\CurrentVersion\Run\Updater"
    assert run.attrs["data"].endswith("updater.cmd")


# ---------------- user activity ----------------
def test_lnk_jumplist_shellbags_are_user_activity():
    lnk = list(ez.parse_lnk(FX / "20261029070100_LECmd_Output.csv", EID))
    jl = list(ez.parse_jumplist(FX / "20261029070100_AutomaticDestinations.csv", EID))
    sb = list(ez.parse_shellbags(FX / "shellbags" / "lab_UsrClass.csv", EID))
    assert [(e.action, e.object) for e in lnk] == [(Action.FILE_OPEN, SECRET)]
    assert lnk[0].timestamp == utc(2026, 10, 29, 6, 58, 0)
    assert jl[0].object == SECRET and jl[0].attrs["app"] == "Notepad (64-bit)"
    assert jl[0].attrs["interaction_count"] == 3
    assert len(sb) == 1 and sb[0].action == Action.FOLDER_OPEN                # bag without times dropped
    assert sb[0].object == r"My Computer\C:\Users\lab\secrets" and sb[0].attrs["has_explored"]


def test_ez_blank_and_unset_times():
    assert ez._time("") is None and ez._time("0001-01-01 00:00:00") is None
    assert ez._time("1601-01-01 00:00:00.0000000") is None and ez._time("garbage") is None


# ---------------- Volatility ----------------
def test_volatility_pstree_flattens_children_and_skips_banner():
    evs = list(volatility.parse_pslist(FX / "vol" / "vol_pstree.json", EID))
    assert [e.pid for e in evs] == [4, 5200, 5210]
    curl = evs[2]
    assert curl.action == Action.MEM_PROCESS and curl.source == EventSource.MEMORY
    assert curl.parent_pid == 5200 and curl.timestamp == utc(2026, 10, 29, 7, 0, 5, 100000)
    assert evs[1].attrs["path"] == r"C:\Windows\System32\cmd.exe"


def test_volatility_cmdline_and_netscan():
    cl = list(volatility.parse_cmdline(FX / "vol" / "vol_cmdline.jsonl", EID))
    assert cl[0].command_line.startswith("curl.exe -s -F file=@") and cl[0].ts_precision == "none"
    assert cl[1].command_line is None and cl[1].attrs["readable"] is False
    ns = list(volatility.parse_netscan(FX / "vol" / "vol_netscan.json", EID))
    assert ns[0].object == "203.0.113.50:443" and ns[0].pid == 5210 and ns[0].ts_precision == "ms"
    assert ns[1].object is None and ns[1].ts_precision == "none"            # UDP listener, no peer


# ---------------- registry of kinds, ingest, run folders ----------------
NEW_KINDS = ["ez_mft", "ez_usn", "ez_prefetch", "ez_amcache", "ez_srum", "ez_registry", "ez_lnk",
             "ez_jumplist", "ez_shellbags", "vol_pslist", "vol_cmdline", "vol_netscan"]


def test_new_kinds_are_parsed_and_raw_kinds_still_preserved():
    assert set(NEW_KINDS) <= set(PARSERS) and set(NEW_KINDS) <= KNOWN_KINDS
    for raw in ("mft", "usn_journal", "prefetch", "amcache", "srum", "registry_hive", "memory_image"):
        assert raw in PRESERVE_ONLY


def test_run_folder_patterns_and_ingest(tmp_path):
    run = tmp_path / "run01"
    shutil.copytree(FX, run / "evidence" / "ez")
    shutil.move(str(run / "evidence" / "ez" / "vol"), str(run / "evidence" / "vol"))
    kinds = {f.name: k for f, k in plan(run)}
    assert kinds["20261029070100_MFTECmd_$MFT_Output.csv"] == "ez_mft"
    assert kinds["20261029070100_MFTECmd_$J_Output.csv"] == "ez_usn"
    assert kinds["20261029070100_RECmd_Batch_Kroll_Batch_Output.csv"] == "ez_registry"
    assert kinds["lab_UsrClass.csv"] == "ez_shellbags"
    assert kinds["vol_pstree.json"] == "vol_pslist" and kinds["vol_cmdline.jsonl"] == "vol_cmdline"
    assert set(kinds.values()) == set(NEW_KINDS)

    c = Case.create(tmp_path / "case", "v03")
    for f, k in plan(run):
        c.add_evidence(f, k)
    counts = ingest(c)
    assert len(counts) == len(NEW_KINDS) and all(n > 0 for n in counts.values())
    evs = c.load_events()
    assert all(e.raw.ingested_at for e in evs)
    assert all("ts_meaning" in e.attrs for e in evs if e.source not in (EventSource.AGENT_TRACE,))
    # second ingest is a no-op
    assert ingest(c) == {}


@pytest.mark.parametrize("kind", NEW_KINDS)
def test_parsers_tolerate_empty_and_header_only_files(tmp_path, kind):
    empty = tmp_path / "empty.csv"
    empty.write_text("" if kind.startswith("vol_") else "A,B,C\n")
    assert list(PARSERS[kind](empty, EID)) == []


def test_timeline_api_shows_new_events(tmp_path):
    from fastapi.testclient import TestClient
    from prompttracir.api import create_app

    c = Case.create(tmp_path / "case", "v03")
    c.add_evidence(FX / "20261029070100_PECmd_Output.csv", "ez_prefetch")
    c.add_evidence(FX / "vol" / "vol_netscan.json", "vol_netscan")
    ingest(c)
    rows = TestClient(create_app(c)).get("/api/timeline").json()
    pf = [r for r in rows if r["source"] == "prefetch"]
    assert pf and all(r["detail"] for r in pf)                               # program path, not blank
    assert any(r["detail"] == "203.0.113.50:443" for r in rows if r["action"] == "mem_conn")


def test_volatility_ignores_rows_that_are_not_objects(tmp_path):
    # Found by fuzzing: a hand-edited or foreign JSON file must not crash ingest.
    f = tmp_path / "odd.json"
    f.write_text('[null, 3, "x", {"PID": "abc"}, {"PID": 7, "__children": "bad", "ImageFileName": 5}]')
    assert [e.pid for e in volatility.parse_pslist(f, EID)] == [7]
    assert volatility.parse_pslist(f, EID).__next__().image is None
    assert [e.pid for e in volatility.parse_cmdline(f, EID)] == [7]
    assert list(volatility.parse_netscan(f, EID)) == []


def test_store_events_bulk_insert_round_trip_and_replace(tmp_path, monkeypatch):
    c = Case.create(tmp_path / "case", "store")
    monkeypatch.setattr(Case, "STORE_CHUNK", 3)                              # force several chunks
    evs = list(ez.parse_mft(FX / "20261029070100_MFTECmd_$MFT_Output.csv", EID))
    evs += list(volatility.parse_netscan(FX / "vol" / "vol_netscan.json", EID))
    changed = evs[0].model_copy(update={"object": "replaced"})               # same id, later chunk
    assert c.store_events(evs + [changed]) == len(evs) + 1
    back = {e.event_id: e for e in c.load_events()}
    assert len(back) == len(evs) and back[evs[0].event_id].object == "replaced"
    for e in evs[1:]:
        assert back[e.event_id].model_dump() == e.model_dump()               # exact round trip
    assert not list((tmp_path / "case").glob(".ingest-*"))                   # temp file removed
