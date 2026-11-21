"""Analyst views for the web UI (v0.7): attack flow, filtered timeline, evidence and raw records.

The UI stays one HTML page (prompttracir/web/index.html, no build step; decision recorded in
ROADMAP.md, v0.7). These functions do the work on the server so they can be tested:

  attack_flow   the chain as ordered steps: request -> entry point -> each deviating tool call with
                the model turn that issued it, the processes it started and what they did, each
                edge with its evidence state, and the findings on it
  timeline      events with filters (source, text, chain-only) and each event's evidence state:
                the strongest status of the graph edges it supports
  evidence      the preserved files and the chain-of-custody log
  raw_record    the record an event was parsed from, read back from the preserved file at the
                event's locator (line, Windows RecordID, Volatility row, inventory entry)
"""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from .case import Case
from .graph import ProvGraph
from .schema import NodeKind

STATUS_RANK = {"contradicted": 4, "corroborated": 3, "observed": 2, "inferred": 1}
EFFECT_KINDS = {NodeKind.FILE, NodeKind.REGISTRY, NodeKind.NETWORK, NodeKind.DOMAIN, NodeKind.DATA_OBJECT}
RAW_LIMIT = 20000


def _node(pg: ProvGraph, nid: str) -> dict:
    n = pg.node(nid)
    return {"id": nid, "kind": n.kind.value, "label": n.label,
            "attribution": n.attrs.get("attribution"), "ts": n.attrs.get("ts")}


def _edge(e) -> dict:
    return {"src": e.src, "dst": e.dst, "relation": e.relation, "status": e.status.value,
            "confidence": e.confidence}


def attack_flow(case: Case, tag: str | None = None) -> dict:
    out = case.view(tag) if tag else case
    graph, chain = out.read_output("graph.json"), out.read_output("chain.json") or {}
    if graph is None:
        return {"steps": [], "note": "run ptir analyze first"}
    pg = ProvGraph.from_json(graph)
    findings = out.read_output("findings.json") or []
    keep = set(chain.get("nodes") or [])
    by_call: dict[str, list[dict]] = {}
    for f in findings:
        tc = (f.get("attrs") or {}).get("tool_call") or (f.get("attrs") or {}).get("context_tool_call")
        if tc:
            by_call.setdefault(tc, []).append({k: f[k] for k in ("finding_id", "kind", "severity", "summary")})
    steps = []
    prompts = [n.id for n in pg.nodes(NodeKind.PROMPT)]
    if prompts:
        p = pg.node(prompts[0])
        steps.append({"stage": "request", "node": _node(pg, prompts[0]), "text": (p.attrs.get("text") or "")[:400]})
    for ep in chain.get("entry_points") or []:
        fid = ep.get("fragment")
        if fid in pg.g:
            steps.append({"stage": "entry_point", "node": _node(pg, fid), "source": ep.get("source"),
                          "method": ep.get("method"), "confidence": ep.get("confidence"),
                          "text": (pg.node(fid).attrs.get("text") or "")[:600]})
    calls = sorted((n for n in pg.nodes(NodeKind.TOOL_CALL) if n.id in keep or n.id in by_call),
                   key=lambda n: str(n.attrs.get("ts") or ""))
    for c in calls:
        issued = [e for e in pg.edges() if e.dst == c.id and e.relation == "issued"]
        influenced = [_edge(e) for e in pg.edges() if e.dst == c.id and e.relation == "influenced"]
        procs, effects, edges, todo, seen = [], [], [], [c.id], {c.id}
        while todo:
            n = todo.pop(0)
            for e in pg.edges():
                if e.src != n or e.relation in ("returned", "transcript_check"):
                    continue
                d = pg.node(e.dst)
                if d.kind == NodeKind.PROCESS and e.dst not in seen:
                    procs.append(_node(pg, e.dst) | {"command_line": d.attrs.get("command_line")})
                    seen.add(e.dst)
                    todo.append(e.dst)
                elif d.kind in EFFECT_KINDS and (e.dst in keep or n != c.id or e.status.value != "inferred"):
                    effects.append(_node(pg, e.dst) | {"relation": e.relation, "status": e.status.value})
                else:
                    continue
                edges.append(_edge(e))
        steps.append({"stage": "tool_call", "node": _node(pg, c.id), "tool": c.attrs.get("tool"),
                      "args": c.attrs.get("args"), "deviation": c.id == chain.get("first_deviation"),
                      "issued_by": [e.src for e in issued], "influenced_by": influenced,
                      "processes": procs, "effects": effects, "edges": edges,
                      "findings": by_call.get(c.id, [])})
    return {"first_deviation": chain.get("first_deviation"), "steps": steps}


def _event_states(case: Case, tag: str | None) -> tuple[dict[str, str], set[str]]:
    out = case.view(tag) if tag else case
    graph = out.read_output("graph.json") or {"nodes": [], "edges": []}
    chain = set((out.read_output("chain.json") or {}).get("nodes") or [])
    state: dict[str, str] = {}
    in_chain: set[str] = set()
    for e in graph["edges"]:
        for ev in e.get("evidence") or []:
            if STATUS_RANK.get(e["status"], 0) > STATUS_RANK.get(state.get(ev, ""), 0):
                state[ev] = e["status"]
            if e["src"] in chain and e["dst"] in chain:
                in_chain.add(ev)
    for n in graph["nodes"]:
        if n["id"] in chain:
            in_chain.update(n.get("evidence") or [])
    return state, in_chain


def timeline(case: Case, source: str | None = None, q: str | None = None, chain_only: bool = False,
             limit: int = 2000, tag: str | None = None) -> dict:
    state, in_chain = _event_states(case, tag)
    rows, sources, total = [], {}, 0
    rx = re.compile(re.escape(q), re.I) if q else None
    for e in case.load_events():
        sources[e.source.value] = sources.get(e.source.value, 0) + 1
        if source and e.source.value != source:
            continue
        if chain_only and e.event_id not in in_chain:
            continue
        detail = (e.command_line or e.object or (e.attrs or {}).get("text", "")[:160] or (e.attrs or {}).get("tool")
                  or e.image)
        if rx and not rx.search(" ".join(str(x) for x in (detail, e.image, e.action.value, e.event_id) if x)):
            continue
        total += 1
        if len(rows) < limit:
            rows.append({"event_id": e.event_id, "ts": e.timestamp.isoformat(), "source": e.source.value,
                         "action": e.action.value, "pid": e.pid, "image": e.image, "detail": detail,
                         "state": state.get(e.event_id), "in_chain": e.event_id in in_chain})
    return {"rows": rows, "matched": total, "shown": len(rows), "sources": sources}


def evidence(case: Case) -> dict:
    m = case.meta
    items = [{"sha256": d, "kind": i.get("kind"), "file": i.get("file"), "original_path": i.get("original_path"),
              "size": i.get("size"), "added": i.get("added"), "ingested": i.get("ingested")}
             for d, i in sorted(m["evidence"].items(), key=lambda kv: (kv[1].get("kind") or "", kv[1].get("file") or ""))]
    custody = []
    p = case.root / "custody.jsonl"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                custody.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return {"items": items, "custody": custody}


def _lines(path: Path, a: int, b: int) -> list[str]:
    out = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if i > b:
                break
            if i >= a:
                out.append(line.rstrip("\r\n"))
    return out


def _zeek_fields(path: Path) -> list[str] | None:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                return line.rstrip("\r\n").split("\t")[1:]
            if not line.startswith("#"):
                return None
    return None


def raw_record(case: Case, event_id: str) -> dict:
    """The record an event came from, read from the preserved (read-only) evidence copy."""
    ev = case.load_events("event_id = ?", [event_id])
    if not ev:
        raise KeyError(event_id)
    e = ev[0]
    info = case.meta["evidence"].get(e.raw.evidence_id) or {}
    path = case.evidence_path(e.raw.evidence_id) if info.get("file") else None
    out = {"event_id": event_id, "evidence_id": e.raw.evidence_id, "kind": info.get("kind"),
           "file": info.get("file"), "original_path": info.get("original_path"),
           "locator": e.raw.locator, "parser": e.raw.parser, "format": "text", "content": None}
    if path is None or not path.exists():
        out["note"] = "the preserved file is not in this case"
        return out
    loc = e.raw.locator or ""
    try:
        m = re.match(r"line:(\d+)(?:-(\d+))?", loc)
        if m:
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            lines = _lines(path, a, b)
            text = "\n".join(lines)
            if path.suffix.lower() == ".csv" or info.get("kind", "").startswith("ez_"):
                header = _lines(path, 1, 1)
                rows = list(csv.reader(io.StringIO(header[0] + "\n" + text))) if header else []
                if len(rows) >= 2:
                    out["format"], out["content"] = "json", dict(zip(rows[0], rows[1]))
                    return out
            try:
                out["format"], out["content"] = "json", json.loads(text)
            except (json.JSONDecodeError, ValueError):
                fields = _zeek_fields(path) if (info.get("kind") or "").startswith("zeek") else None
                if fields and len(lines) == 1:
                    out["format"], out["content"] = "json", dict(zip(fields, lines[0].split("\t")))
                else:
                    out["content"] = text[:RAW_LIMIT]
            return out
        m = re.match(r"record:(\d+)$", loc)
        if m and e.raw.parser == "windows_evtx":
            from .parsers import windows
            rid = int(m.group(1))
            recs = windows._records_from_evtx(path) if path.suffix.lower() == ".evtx" \
                else windows._records_from_jsonl(path)
            for r in recs:
                if int(r.get("RecordID") or -1) == rid:
                    out["format"], out["content"] = "json", r
                    return out
        elif m and (e.raw.parser or "").startswith("vol_"):
            from .parsers.volatility import _records
            for i, r in enumerate(_records(path)):
                if i == int(m.group(1)):
                    out["format"], out["content"] = "json", r
                    return out
        m = re.match(r"files\[(\d+)\]$", loc)
        if m:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            out["format"], out["content"] = "json", (data.get("files") or [])[int(m.group(1))]
            return out
    except Exception as exc:   # noqa: BLE001 - show the problem in the viewer instead of failing
        out["note"] = f"could not read the record: {exc!r}"
        return out
    out["note"] = f"locator {loc!r} is not one the viewer reads"
    return out
