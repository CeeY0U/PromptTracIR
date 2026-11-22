"""End-to-end pipeline: ingest evidence -> correlate -> graph -> rules -> traceback -> impact."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import config as config_mod
from .case import Case
from .correlate import ProcessIndex, attribute_processes, find_sessions, link_tool_calls
from .crosscheck import cross_check
from .graph import ProvGraph, build_graph
from .impact import assess
from .parsers import PARSERS, PRESERVE_ONLY
from .schema import NodeKind
from .scope import first_deviation, run_rules
from .traceback import Replayer, run_traceback


def _stamp(events):
    """Record ingestion time on every event's raw reference (schema v0.3)."""
    now = datetime.now(timezone.utc).isoformat()
    for e in events:
        e.raw.ingested_at = now
        yield e


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
        n = case.store_events(_stamp(PARSERS[kind](case.evidence_path(digest), digest)))
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


def excluded_evidence(case: Case, without: list[str] | None) -> set[str]:
    """Evidence ids of the kinds left out of an ablation run."""
    if not without:
        return set()
    from .parsers import KNOWN_KINDS
    unknown = sorted(set(without) - KNOWN_KINDS)
    if unknown:
        raise ValueError(f"unknown evidence kind(s) for --without: {', '.join(unknown)} (see `ptir kinds`)")
    return {d for d, info in case.meta["evidence"].items() if info["kind"] in set(without)}


def analyze(case: Case, replayer: Replayer | None = None, llm=None, samples: int = 3,
            config: dict | None = None, without: list[str] | None = None, tag: str | None = None,
            localizer: str = "auto") -> dict:
    """Correlate and analyse a case.

    config   settings from prompttracir.config (default: the built-in defaults)
    without  evidence kinds to leave out (ablation); their events are ignored, not deleted
    tag      write outputs to output/<tag>/ instead of output/ (keeps the full analysis intact)
    localizer traceback method: auto, segment, heuristic, replay or group (see traceback.py)
    """
    cfg = config if config is not None else config_mod.load()
    drop = excluded_evidence(case, without)
    out = case.view(tag) if tag else case
    events = [e for e in case.load_events() if e.raw.evidence_id not in drop]
    pidx = ProcessIndex.build(events, cfg)
    sessions = find_sessions(events, pidx, cfg)
    links = link_tool_calls(events, pidx, sessions, cfg)
    attributions = attribute_processes(events, pidx, sessions, links, cfg)
    envelope = case.meta.get("envelope", {})
    pg = build_graph(events, pidx, sessions, links, attributions, envelope)

    findings = run_rules(pg, envelope)
    cc_log, cc_findings = cross_check(pg, events, pidx, sessions, links)
    findings = findings + cc_findings
    for i, f in enumerate(findings, 1):
        f.finding_id = f"F{i:03d}"
    deviating = sorted({f.attrs["tool_call"] for f in findings if f.attrs.get("tool_call")})
    tb_log = run_traceback(pg, deviating, load_requests(case), replayer, samples, method=localizer)

    llm_out = []
    if llm is not None:
        from .llm import classify_tool_call
        llm_out = [classify_tool_call(pg, tc, llm) for tc in deviating]

    impact = assess(pg, findings, events)
    first = first_deviation(pg, findings)
    chain = attack_chain(pg, first, findings)

    summary = None
    if llm is not None and chain["nodes"]:
        from .llm import summarize
        summary = summarize(pg, set(chain["nodes"]), llm, chain)

    fp = config_mod.fingerprint(cfg)
    kinds = sorted({case.meta["evidence"][d]["kind"] for d in case.meta["evidence"]} -
                   {case.meta["evidence"][d]["kind"] for d in drop})
    out.write_output("config.json", {"fingerprint": fp, "without": sorted(without or []), "tag": tag,
                                     "evidence_kinds": kinds, "settings": cfg})
    out.write_output("correlation.json", {"sessions": [s.summary() for s in sessions.values()]})
    out.write_output("graph.json", pg.to_json())
    out.write_output("attribution.json", [a.model_dump(mode="json") for a in attributions])
    out.write_output("tool_links.json", [l.__dict__ | {"status": l.status.value} for l in links])
    out.write_output("findings.json", [f.model_dump(mode="json") for f in findings])
    out.write_output("traceback.json", tb_log)
    out.write_output("impact.json", impact)
    llm_rec = {"classifications": llm_out, "summary": summary}
    if llm is not None:
        from .llm import run_record
        llm_rec["run"] = run_record(llm)
    out.write_output("llm.json", llm_rec)
    out.write_output("chain.json", chain)
    out.write_output("crosscheck.json", cc_log)
    keep = set(chain["nodes"])
    for n in list(keep):
        keep |= set(pg.g.predecessors(n)) | set(pg.g.successors(n))
    out.write_output("graph_reduced.json", pg.subgraph_json(keep))
    case._custody("analyzed", {"findings": len(findings), "first_deviation": first, "config": fp,
                               "without": sorted(without or []), "tag": tag})
    labels = {}
    for a in attributions:
        labels[a.label.value] = labels.get(a.label.value, 0) + 1
    return {"events": len(events), "processes": len(pidx.by_guid), "tool_links": len(links),
            "findings": len(findings), "first_deviation": first, "entry_points": chain["entry_points"],
            "impact": [(i["destination"], i["level"]) for i in impact],
            "attribution": labels, "config": fp, "without": sorted(without or []), "tag": tag,
            "contradicted": sum(1 for e in pg.edges() if e.status.value == "contradicted")}


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


def explain(case: Case, llm, tag: str | None = None) -> dict:
    """Run only the local-model layer (v0.6) on an analysed case: classify each deviating tool
    call and write the grounded summary of the attack chain into llm.json. The graph, findings
    and chain on disk are read, not changed, so this can be repeated with another model or
    prompt without re-analysing the case."""
    from .llm import classify_tool_call, run_record, summarize
    out = case.view(tag) if tag else case
    graph = out.read_output("graph.json")
    if graph is None:
        raise ValueError(f"{case.root}: not analysed (run ptir analyze first)")
    pg = ProvGraph.from_json(graph)
    findings = out.read_output("findings.json") or []
    chain = out.read_output("chain.json") or {}
    deviating = sorted({f["attrs"]["tool_call"] for f in findings if (f.get("attrs") or {}).get("tool_call")})
    classifications = [classify_tool_call(pg, tc, llm) for tc in deviating if tc in pg.g]
    summary = summarize(pg, set(chain.get("nodes") or []), llm, chain) if chain.get("nodes") else None
    rec = {"classifications": classifications, "summary": summary, "run": run_record(llm)}
    out.write_output("llm.json", rec)
    case._custody("explained", {"tag": tag, "classified": len(classifications),
                                "summary_sentences": (summary or {}).get("sentences", 0)})
    return rec


def revalidate_case(case: Case, tag: str | None = None) -> dict | None:
    """v0.7: check a stored summary again with the current validation (relations included),
    without calling the model. The previous outcome is kept under summary_before_revalidation."""
    from .llm import revalidate
    out = case.view(tag) if tag else case
    rec = out.read_output("llm.json")
    if not rec or not rec.get("summary"):
        return None
    pg = ProvGraph.from_json(out.read_output("graph.json"))
    chain = out.read_output("chain.json") or {}
    before = {k: rec["summary"].get(k) for k in ("sentences", "kept", "unsupported_rate_before_validation",
                                                 "validation", "unsupported_by_reason")}
    rec["summary"] = revalidate(pg, rec["summary"], chain)
    rec["summary_before_revalidation"] = before
    out.write_output("llm.json", rec)
    case._custody("revalidated", {"tag": tag, "sentences": rec["summary"]["sentences"],
                                  "kept": rec["summary"]["kept"]})
    return rec
