"""Lab run jt-01 (v0.4.0): the scripted model answers within the same clock tick, so trace
records share timestamps and their order must come from the file, not from string sorting."""
import json
from pathlib import Path

from prompttracir.correlate import ProcessIndex
from prompttracir.graph import ProvGraph, build_graph
from prompttracir.parsers.agent_trace import parse
from prompttracir.schema import Edge, EdgeStatus, Node, NodeKind

TS = "2026-11-16T05:44:23.942539Z"


def _trace(tmp_path: Path) -> Path:
    s = "s-1"
    recs = [{"type": "session_start", "ts": TS, "session_id": s, "pid": 7064, "agent": "ptir-harness"},
            {"type": "user_prompt", "ts": TS, "session_id": s, "span_id": "p1", "text": "summarise"},
            {"type": "model_call", "ts": TS, "session_id": s, "model_call_id": "m1", "input_fragments": []},
            {"type": "tool_call", "ts": TS, "session_id": s, "tool_call_id": "t1", "model_call_id": "m1",
             "tool": "http_get", "args": {"url": "http://docs.example-lab.test/guide.html"}},
            {"type": "tool_result", "ts": TS, "session_id": s, "tool_call_id": "t1", "output_preview": "x"}]
    frags = [f"t1-{i}" for i in range(6)]
    recs += [{"type": "context_fragment", "ts": TS, "session_id": s, "fragment_id": f, "tool_call_id": "t1",
              "index": i, "text": f"part {i}", "source": {"kind": "web", "uri": "http://docs.example-lab.test/guide.html"}}
             for i, f in enumerate(frags)]
    recs.append({"type": "model_call", "ts": TS, "session_id": s, "model_call_id": "m2", "input_fragments": frags})
    p = tmp_path / "trace.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    return p


def test_equal_timestamps_keep_file_order(tmp_path):
    events = list(parse(_trace(tmp_path), "e" * 64))
    assert len(events) == 12
    # the case store orders by (timestamp, event_id): that must be file order
    assert sorted(events, key=lambda e: (e.timestamp, e.event_id)) == events


def test_graph_builds_with_equal_timestamps(tmp_path):
    events = list(parse(_trace(tmp_path), "e" * 64))
    # worst case: the model call that lists the fragments comes before them
    events = events[:5] + [events[-1]] + events[5:-1]
    pg = build_graph(events, ProcessIndex.build(events), {}, [], [])
    assert {n.id for n in pg.nodes(NodeKind.FRAGMENT)} == {f"fragment:t1-{i}" for i in range(6)}
    assert sum(1 for e in pg.edges() if e.relation == "in_context") == 6
    assert all("node" in d for _, d in pg.g.nodes(data=True))


def test_edge_before_node_then_node():
    pg = ProvGraph()
    pg.add_edge(Edge(src="fragment:a", dst="model_call:m", relation="in_context", status=EdgeStatus.OBSERVED))
    pg.add_node(Node(id="fragment:a", kind=NodeKind.FRAGMENT, label="a"))
    assert pg.node("fragment:a").label == "a"
    assert [n.id for n in pg.nodes()] == ["fragment:a"]   # model_call:m is still a bare placeholder

