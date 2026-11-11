"""End-to-end pipeline: ingest evidence -> correlate -> graph -> rules -> traceback -> impact."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .case import Case
from .correlate import ProcessIndex, attribute_processes, find_sessions, link_tool_calls
from .graph import ProvGraph, build_graph
from .impact import assess
from .parsers import PARSERS, PRESERVE_ONLY
from .schema import NodeKind
from .scope import first_deviation, run_rules
from .traceback import Replayer, run_traceback


def ingest(case: Case) -> dict[str, int]:
    counts = {}
    meta = case.meta
    for digest, info in meta["evidence"].items():
        kind = info["kind"]
        if info.get("ingested"):
            continue
        if kind not in PARSERS:
            if kind in PRESERVE_ONLY:
                continue   # preserved only; ingested automatically once a parser exists
            raise ValueError(f"no parser for evidence kind '{kind}' (known: {sorted(PARSERS)})")
        n = case.store_events(PARSERS[kind](case.evidence_path(digest), digest))
        counts[digest[:12] + f" ({kind})"] = n
        meta = case.meta
        meta["evidence"][digest]["ingested"] = True
        case._save_meta(meta)
    case._custody("ingested", counts)
    return counts


def load_requests(case: Case) -> dict[str, dict]:
    out = {}
    for digest, info in case.meta["evidence"].items():
        if info["kind"] == "agent_requests":
            with open(case.evidence_path(digest)) as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        out[r["model_call_id"]] = r["request"]
    return out


def analyze(case: Case, replayer: Replayer | None = None, llm=None, samples: int = 3) -> dict:
    events = case.load_events()
    pidx = ProcessIndex.build(events)
    sessions = find_sessions(events, pidx)
    links = link_tool_calls(events, pidx, sessions)
    attributions = attribute_processes(events, pidx, sessions, links)
    pg = build_graph(events, pidx, sessions, links, attributions)

    envelope = case.meta.get("envelope", {})
    findings = run_rules(pg, envelope)
    deviating = sorted({f.attrs["tool_call"] for f in findings if f.attrs.get("tool_call")})
    tb_log = run_traceback(pg, deviating, load_requests(case), replayer, samples)

    llm_out = []
    if llm is not None:
        from .llm import classify_tool_call
        llm_out = [classify_tool_call(pg, tc, llm) for tc in deviating]

    impact = assess(pg, findings)
    first = first_deviation(pg, findings)
    chain = attack_chain(pg, first, findings)

    summary = None
    if llm is not None and chain["nodes"]:
        from .llm import summarize
        summary = summarize(pg, set(chain["nodes"]), llm)

    case.write_output("graph.json", pg.to_json())
    case.write_output("attribution.json", [a.model_dump(mode="json") for a in attributions])
    case.write_output("tool_links.json", [l.__dict__ | {"status": l.status.value} for l in links])
    case.write_output("findings.json", [f.model_dump(mode="json") for f in findings])
    case.write_output("traceback.json", tb_log)
    case.write_output("impact.json", impact)
    case.write_output("llm.json", {"classifications": llm_out, "summary": summary})
    case.write_output("chain.json", chain)
    case._custody("analyzed", {"findings": len(findings), "first_deviation": first})
    return {"events": len(events), "processes": len(pidx.by_guid), "tool_links": len(links),
            "findings": len(findings), "first_deviation": first, "entry_points": chain["entry_points"],
            "impact": [(i["destination"], i["level"]) for i in impact]}


def attack_chain(pg: ProvGraph, first: str | None, findings) -> dict:
    """Entry point(s) -> first deviation -> everything the deviating tool calls caused."""
    if not first:
        return {"first_deviation": None, "entry_points": [], "nodes": []}
    nodes: set[str] = set()
    deviating = {f.attrs["tool_call"] for f in findings if f.attrs.get("tool_call")}
    for tc in deviating:
        nodes |= pg.forward(tc)
        nodes |= {p for p in pg.backward(tc) if pg.node(p).kind in
                  (NodeKind.PROMPT, NodeKind.MODEL_CALL, NodeKind.FRAGMENT, NodeKind.SOURCE,
                   NodeKind.TOOL_CALL, NodeKind.SESSION)}
    # entry points: fragments with an 'influenced' edge into the first deviating call
    entries = []
    for e in pg.edges():
        if e.relation == "influenced" and e.dst == first:
            src = pg.node(e.src)
            entries.append({"fragment": e.src, "source": (src.attrs.get("source") or {}).get("uri"),
                            "confidence": e.confidence, "method": e.signals.get("method")})
    entries.sort(key=lambda x: -x["confidence"])
    # keep fragments only if they influenced something, so the chain stays readable
    influenced_src = {e.src for e in pg.edges() if e.relation == "influenced"}
    nodes = {n for n in nodes if pg.node(n).kind != NodeKind.FRAGMENT or n in influenced_src}
    nodes |= {s for f in influenced_src for s in pg.g.predecessors(f) if pg.node(s).kind == NodeKind.SOURCE}
    return {"first_deviation": first, "entry_points": entries, "nodes": sorted(nodes),
            "generated": datetime.now(timezone.utc).isoformat()}
