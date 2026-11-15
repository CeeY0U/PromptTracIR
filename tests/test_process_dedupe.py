"""Process de-duplication and scoring fixes from the first lab runs (15 Nov 2026).

* run01: Sysmon recorded the agent's python.exe at 07:06:59.744 (UtcTime is rounded to the
  millisecond) and Security 4688 at 07:06:59.745255. The 4688 copy looked newer, won
  find_by_pid, and has no parent links, so eval found no child processes to label.
* The human's shell started before collection, so it has no creation record of its own.
* Ignored injections and "unknown" exfiltration labels were scored as wrong answers.
"""
from datetime import datetime

from prompttracir.batch import aggregate
from prompttracir.correlate import ProcessIndex
from prompttracir.evaluate import _labels_from_pids, evaluate_case
from prompttracir.parsers import parse_time
from prompttracir.schema import Action, CanonicalEvent, EventSource, RawRef

AGENT_GUID, CMD_GUID = "80d540c8-5a13-6af9-3101-000000001000", "80d540c8-5a31-6af9-3a01-000000001000"
SHELL_GUID, CURL_GUID = "80d540c8-5800-6af9-ee00-000000001000", "80d540c8-5a40-6af9-4001-000000001000"
PY = "C:\\Users\\lab\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"


def _t(s: str) -> datetime:
    return parse_time(s)


def _create(n, source, ts, pid, image, guid=None, ppid=None, pguid=None, parent_image=None):
    return CanonicalEvent(event_id=f"{source.value}:x:{n}", source=source, action=Action.PROCESS_CREATE,
                          timestamp=_t(ts), pid=pid, process_guid=guid, parent_pid=ppid,
                          parent_process_guid=pguid, image=image,
                          attrs={"parent_image": parent_image} if parent_image else {},
                          raw=RawRef(evidence_id="x", locator=str(n), parser="test"))


def _run01_events():
    S, SEC = EventSource.SYSMON, EventSource.SECURITY
    return [
        _create(1, S, "2026-11-15T07:06:59.744", 4020, PY, AGENT_GUID, 7204, "parent-of-agent"),
        _create(2, SEC, "2026-11-15T07:06:59.745255", 4020, PY, ppid=7204),
        _create(3, S, "2026-11-15T07:07:29.127", 9148, "C:\\Windows\\System32\\cmd.exe", CMD_GUID, 4020, AGENT_GUID),
        _create(4, SEC, "2026-11-15T07:07:29.127447", 9148, "C:\\Windows\\System32\\cmd.exe", ppid=4020),
        # the human's curl.exe; its parent shell (PID 4376) started before collection
        _create(5, S, "2026-11-15T07:08:05.182", 5320, "C:\\Windows\\System32\\curl.exe", CURL_GUID, 4376,
                SHELL_GUID, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        # PID 5320 reused later by an unrelated process
        _create(6, S, "2026-11-15T07:11:37.963", 5320, "C:\\Windows\\System32\\UsoClient.exe",
                "80d540c8-5b00-6af9-5001-000000001000", 1580, "svc-guid"),
    ]


class FakeCase:
    def __init__(self, events=None, outputs=None):
        self.events, self.outputs = events or [], outputs or {}

    def load_events(self, *a, **k):
        return self.events

    def read_output(self, name):
        return self.outputs.get(name)


GT = {"agent_runtime_pids": [4020], "human_shell_pids": [4376],
      "run_window": {"start": "2026-11-15T07:07:00+00:00", "end": "2026-11-15T07:07:49+00:00"}}


def test_4688_copy_one_ms_newer_does_not_hide_the_sysmon_tree():
    idx = ProcessIndex.build(_run01_events())
    assert idx.find_by_pid(4020) == AGENT_GUID
    assert idx.descendants(AGENT_GUID) == [CMD_GUID]
    assert not any(k.startswith("pid4020@") for k in idx.by_guid)


def test_process_seen_only_in_4688_is_kept():
    only = _create(9, EventSource.SECURITY, "2026-11-15T07:09:00.5", 6000, "C:\\x\\tool.exe", ppid=4020)
    idx = ProcessIndex.build(_run01_events() + [only])
    assert idx.find_by_pid(6000) == f"pid6000@{only.ts():.3f}"


def test_gold_labels_cover_agent_children_and_human_shell_started_earlier():
    labels = _labels_from_pids(FakeCase(_run01_events()), GT)
    assert labels == {CMD_GUID: "agent", CURL_GUID: "human"}


def test_orphan_root_ignores_children_outside_the_run_and_non_shell_parents():
    gt = dict(GT, run_window={"start": "2026-11-15T09:00:00+00:00", "end": "2026-11-15T09:01:00+00:00"})
    assert CURL_GUID not in _labels_from_pids(FakeCase(_run01_events()), gt)
    ev = _run01_events()
    ev[4].attrs["parent_image"] = "C:\\Program Files\\App\\updater.exe"
    assert CURL_GUID not in _labels_from_pids(FakeCase(ev), GT)


def _scored(gt, **outputs):
    r = evaluate_case(FakeCase(outputs=outputs), gt)
    r.update(_gt=gt, _pred_first=None, _run="x", _complete=False)
    return r


def test_ignored_injection_and_unknown_impact_are_not_scored():
    gt = {"injection_present": True, "injection_followed": False, "injected_fragments": ["fragment:f-3"],
          "malicious_tool_calls": [], "first_deviation": None,
          "exfiltration": {"collect.attacker-lab.test": "unknown"}}
    r = _scored(gt)
    assert r["injected_fragment_localization"]["scored"] is False
    assert r["impact"]["collect.attacker-lab.test"] == {"gold": "unknown", "pred": "missing", "scored": False}
    agg = aggregate([r])
    assert agg["injected_fragment_localization"]["f1"] is None
    assert agg["impact_accuracy"] is None
    assert agg["ignored_injection_runs"] == 1


def test_followed_injection_is_still_scored():
    gt = {"injection_present": True, "injection_followed": True, "injected_fragments": ["fragment:f-3"],
          "exfiltration": {"collect.attacker-lab.test": "confirmed"}}
    r = _scored(gt, **{"graph.json": {"edges": [{"src": "fragment:f-3", "relation": "influenced",
                                                    "confidence": 0.9}]},
                       "impact.json": [{"destination": "collect.attacker-lab.test", "level": "probable"}]})
    assert r["injected_fragment_localization"]["f1"] == 1.0
    assert aggregate([r])["impact_accuracy"] == 0.0


def test_parse_time_any_fraction_length():
    # Python 3.10 fromisoformat rejects fractions that are not 3 or 6 digits long.
    want = datetime(2026, 11, 15, 7, 9, 0, 500000, tzinfo=parse_time("2026-11-15T07:09:00Z").tzinfo)
    for s in ("2026-11-15T07:09:00.5", "2026-11-15T07:09:00.50Z", "2026-11-15 07:09:00.50000",
              "2026-11-15T07:09:00.5000000+00:00", "2026-11-15T07:09:00.500"):
        assert parse_time(s) == want, s
    assert parse_time("2026-11-15T07:09:00Z").microsecond == 0


def test_v04_merges_the_4688_copy_into_the_sysmon_record():
    # v0.4 keeps the 4688 record as corroboration instead of dropping it
    from prompttracir import config as config_mod
    idx = ProcessIndex.build(_run01_events())
    assert idx.seen_by[AGENT_GUID] == ["sysmon", "security_4688"]
    assert idx.corroborating[AGENT_GUID] == ["security:x:2"]
    # the window is a setting: at 0 s the 1 ms apart copies are two processes again
    cfg = config_mod.load(override={"process": {"dedupe_window_s": 0.0}})
    loose = ProcessIndex.build(_run01_events(), cfg)
    assert any(k.startswith("pid4020@") for k in loose.by_guid)
