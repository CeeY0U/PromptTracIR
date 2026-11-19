"""Provenance graph linking prompts, context fragments, model calls and tool calls
to processes, files, registry keys and network activity.

Rule enforced here: only parsed records create OBSERVED/CORROBORATED edges.
Traceback and the local LLM may only add INFERRED edges (see add_inferred).
"""
from __future__ import annotations

import re
from typing import Iterable

import networkx as nx

from .correlate import ProcessIndex, Session, ToolLink, basename
from .schema import (Action, Attribution, AttributionLabel, CanonicalEvent, Edge, EdgeStatus,
                     EventSource, Node, NodeKind)

STATUS_RANK = {EdgeStatus.CONTRADICTED: 4, EdgeStatus.CORROBORATED: 3, EdgeStatus.OBSERVED: 2,
               EdgeStatus.INFERRED: 1, EdgeStatus.UNKNOWN: 0}
HOST_EFFECTS = {Action.FILE_CREATE: ("file", "created"), Action.FILE_DELETE: ("file", "deleted"),
                Action.REGISTRY_SET: ("registry", "set"), Action.NET_CONNECT: ("network", "connected"),
                Action.DNS_QUERY: ("domain", "resolved"), Action.FILE_READ: ("file", "read"),
                Action.FILE_MODIFY: ("file", "wrote")}
# Host effects that carry a PID but no ProcessGuid (Security 4663). They are joined to a
# process by PID and time; artifact events without a PID (USN, MFT) never become effects.
PID_ONLY_SOURCES = {EventSource.SECURITY}
_IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def file_id(path: str) -> str:
    return "file:" + path.replace("/", "\\").lower()


class ProvGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()

    # ---------- primitives ----------
    def add_node(self, node: Node) -> str:
        data = self.g.nodes[node.id] if node.id in self.g else None
        if data is not None and "node" in data:
            cur: Node = data["node"]
            cur.evidence = sorted(set(cur.evidence) | set(node.evidence))
            cur.attrs.update({k: v for k, v in node.attrs.items() if v is not None})
        else:   # new, or so far only the end of an edge added before its node
            self.g.add_node(node.id, node=node)
        return node.id

    def add_edge(self, edge: Edge) -> None:
        key = edge.relation
        if self.g.has_edge(edge.src, edge.dst, key):
            cur: Edge = self.g.edges[edge.src, edge.dst, key]["edge"]
            cur.evidence = sorted(set(cur.evidence) | set(edge.evidence))
            cur.signals.update(edge.signals)
            if STATUS_RANK[edge.status] > STATUS_RANK[cur.status]:
                cur.status = edge.status
            cur.confidence = max(cur.confidence, edge.confidence)
        else:
            self.g.add_edge(edge.src, edge.dst, key=key, edge=edge)

    def add_inferred(self, src: str, dst: str, relation: str, confidence: float,
                     signals: dict, evidence: list[str]) -> None:
        """The only entry point for analysis modules (traceback, LLM)."""
        if src not in self.g or dst not in self.g:
            raise KeyError(f"inferred edge must connect existing nodes: {src} -> {dst}")
        self.add_edge(Edge(src=src, dst=dst, relation=relation, status=EdgeStatus.INFERRED,
                           confidence=confidence, signals=signals, evidence=evidence))

    def node(self, nid: str) -> Node:
        return self.g.nodes[nid]["node"]

    def nodes(self, kind: NodeKind | None = None) -> list[Node]:
        # an edge may name a node the evidence never defines (a fragment missing from the trace)
        return [d["node"] for _, d in self.g.nodes(data=True)
                if "node" in d and (kind is None or d["node"].kind == kind)]

    def edges(self) -> list[Edge]:
        return [d["edge"] for _, _, d in self.g.edges(data=True)]

    # ---------- traversal ----------
    def backward(self, nid: str) -> set[str]:
        """Everything that could have caused nid (source tracing)."""
        return nx.ancestors(self.g, nid) | {nid}

    def forward(self, nid: str) -> set[str]:
        """Everything nid could have affected (impact analysis)."""
        return nx.descendants(self.g, nid) | {nid}

    def subgraph_json(self, ids: Iterable[str]) -> dict:
        ids = set(ids)
        return {
            "nodes": [self.node(n).model_dump(mode="json") for n in ids if n in self.g],
            "edges": [e.model_dump(mode="json") for e in self.edges() if e.src in ids and e.dst in ids],
        }

    # ---------- serialization ----------
    def to_json(self) -> dict:
        return {"nodes": [n.model_dump(mode="json") for n in self.nodes()],
                "edges": [e.model_dump(mode="json") for e in self.edges()]}

    @classmethod
    def from_json(cls, data: dict) -> "ProvGraph":
        pg = cls()
        for n in data["nodes"]:
            pg.add_node(Node(**n))
        for e in data["edges"]:
            pg.add_edge(Edge(**e))
        return pg


def build_graph(events: list[CanonicalEvent], pidx: ProcessIndex, sessions: dict[str, Session],
                links: list[ToolLink], attributions: list[Attribution]) -> ProvGraph:
    pg = ProvGraph()
    attr_by_guid = {a.process_guid: a for a in attributions}
    O, C, I = EdgeStatus.OBSERVED, EdgeStatus.CORROBORATED, EdgeStatus.INFERRED

    # ---------------- agent trace layer ----------------
    tool_calls = {e.tool_call_id: e for e in events if e.action == Action.TOOL_CALL}
    tool_results = {e.tool_call_id: e for e in events if e.action == Action.TOOL_RESULT}
    last_prompt: dict[str, str] = {}
    for e in events:
        sid = e.session_id
        if e.action == Action.SESSION_START:
            pg.add_node(Node(id=f"session:{sid}", kind=NodeKind.SESSION, label=f"agent session {sid}",
                             attrs=dict(e.attrs, pid=e.pid), evidence=[e.event_id]))
        elif e.action == Action.USER_PROMPT:
            pid_ = f"prompt:{sid}:{e.attrs.get('span_id') or e.event_id}"
            pg.add_node(Node(id=pid_, kind=NodeKind.PROMPT, label="user prompt",
                             attrs={"text": e.attrs["text"], "ts": e.timestamp.isoformat()},
                             evidence=[e.event_id]))
            if f"session:{sid}" in pg.g:
                pg.add_edge(Edge(src=f"session:{sid}", dst=pid_, relation="received", status=O,
                                 evidence=[e.event_id]))
            last_prompt[sid] = pid_
        elif e.action == Action.CONTEXT_FRAGMENT:
            fid = f"fragment:{e.fragment_id}"
            src = e.attrs.get("source") or {}
            pg.add_node(Node(id=fid, kind=NodeKind.FRAGMENT, label=f"fragment {e.fragment_id}",
                             attrs={"text": e.attrs["text"], "source": src, "index": e.attrs.get("index"),
                                    "ts": e.timestamp.isoformat()}, evidence=[e.event_id]))
            if src.get("uri"):
                sid_ = f"source:{src['uri']}"
                pg.add_node(Node(id=sid_, kind=NodeKind.SOURCE, label=src["uri"],
                                 attrs={"kind": src.get("kind"), "sha256": src.get("sha256")},
                                 evidence=[e.event_id]))
                pg.add_edge(Edge(src=sid_, dst=fid, relation="contains", status=O, evidence=[e.event_id]))
            if e.tool_call_id:
                pg.add_edge(Edge(src=f"tool_call:{e.tool_call_id}", dst=fid, relation="returned",
                                 status=O, evidence=[e.event_id]))
        elif e.action == Action.MODEL_CALL:
            mid = f"model_call:{e.model_call_id}"
            pg.add_node(Node(id=mid, kind=NodeKind.MODEL_CALL, label=f"model call {e.model_call_id}",
                             attrs={"ts": e.timestamp.isoformat(),
                                    "request_ref": e.attrs.get("request_ref")}, evidence=[e.event_id]))
            if sid in last_prompt:
                pg.add_edge(Edge(src=last_prompt[sid], dst=mid, relation="instructs", status=O,
                                 evidence=[e.event_id]))
            for f in e.attrs.get("input_fragments", []):
                pg.add_edge(Edge(src=f"fragment:{f}", dst=mid, relation="in_context", status=O,
                                 evidence=[e.event_id]))
        elif e.action == Action.TOOL_CALL:
            tid = f"tool_call:{e.tool_call_id}"
            res = tool_results.get(e.tool_call_id)
            pg.add_node(Node(id=tid, kind=NodeKind.TOOL_CALL,
                             label=f"{e.attrs.get('tool')}({_short(e.attrs.get('args'))})",
                             attrs={"tool": e.attrs.get("tool"), "args": e.attrs.get("args"),
                                    "ts": e.timestamp.isoformat(),
                                    "dropped_parallel_calls": e.attrs.get("dropped_parallel_calls") or 0,
                                    "result": res.attrs if res else None},
                             evidence=[e.event_id] + ([res.event_id] if res else [])))
            if e.model_call_id:
                pg.add_edge(Edge(src=f"model_call:{e.model_call_id}", dst=tid, relation="issued",
                                 status=O, evidence=[e.event_id]))
            if res:   # effects the trace claims; host evidence may corroborate them below
                for item in res.attrs.get("files_read") or []:
                    path = item["path"] if isinstance(item, dict) else item
                    _file_node(pg, path, [res.event_id], item if isinstance(item, dict) else {})
                    pg.add_edge(Edge(src=tid, dst=file_id(path), relation="read", status=O,
                                     evidence=[res.event_id], signals={"sources": ["agent_trace"]}))
                for item in res.attrs.get("files_written") or []:
                    path = item["path"] if isinstance(item, dict) else item
                    _file_node(pg, path, [res.event_id], item if isinstance(item, dict) else {})
                    pg.add_edge(Edge(src=tid, dst=file_id(path), relation="wrote", status=O,
                                     evidence=[res.event_id], signals={"sources": ["agent_trace"]}))

    # ---------------- host layer ----------------
    in_graph: set[str] = set()
    for s in sessions.values():
        if s.runtime_guid and s.runtime_guid in pidx.by_guid:
            in_graph.add(s.runtime_guid)
            in_graph.update(pidx.descendants(s.runtime_guid))
    for l in links:
        in_graph.add(l.process_guid)
        in_graph.update(pidx.descendants(l.process_guid))
    span_lo = min((s.start.ts() for s in sessions.values()), default=0) - 120
    span_hi = max((s.end_ts for s in sessions.values()), default=0) + 120
    for a in attributions:   # include human/mixed activity near the session for contrast
        p = pidx.by_guid[a.process_guid]
        if a.label in (AttributionLabel.HUMAN, AttributionLabel.MIXED) and span_lo <= p.ts() <= span_hi:
            in_graph.add(a.process_guid)

    for guid in in_graph:
        p = pidx.by_guid[guid]
        a = attr_by_guid.get(guid)
        pg.add_node(Node(id=f"process:{guid}", kind=NodeKind.PROCESS,
                         label=f"{basename(p.image)} ({p.pid})",
                         attrs={"image": p.image, "pid": p.pid, "command_line": p.command_line,
                                "user": p.user, "ts": p.timestamp.isoformat(),
                                "attribution": a.label.value if a else "agent_runtime",
                                "attribution_signals": a.signals if a else [],
                                "agent_probability": a.agent_probability if a else None,
                                "seen_by": pidx.seen_by.get(guid, [])},
                         evidence=[p.event_id] + pidx.corroborating.get(guid, [])))
    for guid in in_graph:
        p = pidx.by_guid[guid]
        parent = pidx.parent_of.get(guid)
        if parent in in_graph:
            joined = p.parent_process_guid is None      # 4688: parent found by PID and time
            pg.add_edge(Edge(src=f"process:{parent}", dst=f"process:{guid}",
                             relation="spawned", status=O, evidence=[p.event_id],
                             signals={"joined_by": "parent_pid_and_time"} if joined else {}))
    for s in sessions.values():
        if f"session:{s.session_id}" in pg.g:
            pg.node(f"session:{s.session_id}").attrs.update(
                {"runtime_method": s.runtime_method, "clock_offset_s": round(s.clock_offset, 3)})
        if s.runtime_guid in in_graph:
            inferred = s.runtime_method == "inferred"
            pg.add_edge(Edge(src=f"session:{s.session_id}", dst=f"process:{s.runtime_guid}",
                             relation="runs_in", status=I if inferred else O,
                             confidence=0.7 if inferred else 1.0,
                             signals=s.runtime_signals if inferred else {}, evidence=[s.start.event_id]))
    for l in links:
        pg.add_edge(Edge(src=f"tool_call:{l.tool_call_id}", dst=f"process:{l.process_guid}",
                         relation="spawned", status=l.status, confidence=l.score,
                         signals=l.signals, evidence=l.evidence))

    # host effects of processes in the graph
    zeek = [e for e in events if e.action == Action.CONN]
    effect_guid = _effect_guids(events, pidx)
    for e in events:
        g = effect_guid.get(e.event_id)
        if e.action not in HOST_EFFECTS or not g or g not in in_graph or not e.object:
            continue
        kind, rel = HOST_EFFECTS[e.action]
        oid = _effect_node(pg, e, kind)
        status, sig, z = O, {}, None
        if e.action == Action.NET_CONNECT:
            z = _match_conn(e, zeek)
            if z:
                status = C
                sig = {"zeek_uid": z.attrs.get("uid"), "orig_bytes": z.attrs["orig_bytes"],
                       "resp_bytes": z.attrs["resp_bytes"]}
                pg.node(oid).attrs["orig_bytes"] = pg.node(oid).attrs.get("orig_bytes", 0) + z.attrs["orig_bytes"]
        if e.process_guid is None:
            sig = {**sig, "joined_by": "pid_and_time", "via": e.attrs.get("via")}
        pg.add_edge(Edge(src=f"process:{g}", dst=oid, relation=rel, status=status,
                         signals=sig, evidence=[e.event_id] + ([z.event_id] if z else [])))

    # in-process effects of non-exec tool calls (e.g. http_get/write_file inside python.exe).
    # Each effect goes to one call. A call's window runs from just before it starts to its
    # result, and never past the start of the session's next call, so calls a few ms apart
    # (the scripted model) do not share effects. Inside the windows, a call whose trace claims
    # the object wins.
    host_fx = [e for e in events if e.action in HOST_EFFECTS and effect_guid.get(e.event_id)]
    for s in sessions.values():
        if not s.runtime_guid:
            continue
        calls = sorted((c for c in tool_calls.values() if (c.session_id or "") == s.session_id),
                       key=lambda c: c.ts())
        windows = in_process_windows(calls, tool_results, s.clock_offset)
        claimed = {c.tool_call_id: _claimed_objects(tool_results.get(c.tool_call_id)) for c in calls}
        for e in host_fx:
            if effect_guid[e.event_id] != s.runtime_guid or not e.object:
                continue
            t = e.ts()
            cands = [tc for tc, (lo, hi) in windows.items() if lo <= t <= hi]
            if not cands:
                continue
            names = [x.lower() for x in (e.object, e.attrs.get("dst_host")) if x]
            claimants = [tc for tc in cands
                         if any(c in n or n in c for c in claimed[tc] for n in names)]
            kind, rel = HOST_EFFECTS[e.action]
            for tcid in claimants or cands[:1]:
                match = tcid in claimants
                oid = _effect_node(pg, e, kind)
                pg.add_edge(Edge(src=f"tool_call:{tcid}", dst=oid, relation=rel,
                                 status=C if match else I, confidence=0.9 if match else 0.5,
                                 signals={"in_process_effect": True, "trace_claim_match": match},
                                 evidence=[tool_calls[tcid].event_id, e.event_id]))

    # DNS answers -> network endpoints
    for e in events:
        if e.action == Action.DNS_QUERY and e.object and f"domain:{e.object.lower()}" in pg.g:
            for ip in _IP.findall(str(e.attrs.get("results") or "")):
                for n in pg.nodes(NodeKind.NETWORK):
                    if n.attrs.get("ip") == ip:
                        pg.add_edge(Edge(src=f"domain:{e.object.lower()}", dst=n.id, relation="resolved_to",
                                         status=O, evidence=[e.event_id]))
    # v0.5: logon sessions of the processes in the graph (Sysmon/4688 LogonId, 4624 logon type)
    logon_type = {e.logon_id.lower(): e for e in events
                  if e.action == Action.LOGON and e.logon_id}
    for guid in in_graph:
        lid = (pidx.by_guid[guid].logon_id or "").lower()
        if not lid:
            continue
        lo_ev = logon_type.get(lid)
        nid = pg.add_node(Node(id=f"logon:{lid}", kind=NodeKind.LOGON_SESSION, label=f"logon {lid}",
                               attrs={"logon_id": lid,
                                      "logon_type": lo_ev.attrs.get("logon_type") if lo_ev else None},
                               evidence=[lo_ev.event_id] if lo_ev else []))
        pg.add_edge(Edge(src=nid, dst=f"process:{guid}", relation="hosts", status=O,
                         evidence=[pidx.by_guid[guid].event_id]))

    # v0.5: file inventory (collect-run.ps1): size and content hash of files in the graph, and
    # the content itself as a data object, so the same secret can be followed across copies
    inventory = {file_id(e.object): e for e in events if e.action == Action.FILE_STAT and e.object}
    pg.g.graph["inventory"] = {k: {"path": e.object, "size": e.attrs.get("size"),
                                   "sha256": e.attrs.get("sha256"), "event": e.event_id}
                               for k, e in inventory.items()}
    for n in pg.nodes(NodeKind.FILE):
        inv = inventory.get(n.id)
        if not inv:
            continue
        n.attrs.setdefault("size", inv.attrs.get("size"))
        n.attrs["sha256"] = inv.attrs.get("sha256")
        n.evidence = sorted(set(n.evidence) | {inv.event_id})
        if inv.attrs.get("sha256"):
            did = pg.add_node(Node(id=f"data:{inv.attrs['sha256']}", kind=NodeKind.DATA_OBJECT,
                                   label=f"content {inv.attrs['sha256'][:12]}",
                                   attrs={"sha256": inv.attrs["sha256"], "size": inv.attrs.get("size")},
                                   evidence=[inv.event_id]))
            pg.add_edge(Edge(src=n.id, dst=did, relation="holds", status=O, evidence=[inv.event_id]))

    # an edge to a node the evidence never defines leaves a bare placeholder: drop it
    pg.g.remove_nodes_from([n for n, d in pg.g.nodes(data=True) if "node" not in d])
    return pg


# ---------------- helpers ----------------

def in_process_windows(calls: list[CanonicalEvent], results: dict[str, CanonicalEvent],
                       offset: float, margin: float = 0.5) -> dict[str, tuple[float, float]]:
    """Host-clock time window per tool call, for effects inside the agent's own process.

    calls must be one session's calls in time order. A window starts ``margin`` before the
    call (but not before the previous window ends) and ends ``margin`` after its result (or
    30 s after the call without one), cut at the start of the next call."""
    out: dict[str, tuple[float, float]] = {}
    prev_hi = None
    for i, call in enumerate(calls):
        res = results.get(call.tool_call_id)
        lo = call.ts() + offset - margin
        if prev_hi is not None:
            lo = max(lo, prev_hi)
        hi = (res.ts() if res else call.ts() + 30) + offset + margin
        if i + 1 < len(calls):
            hi = min(hi, calls[i + 1].ts() + offset)
        hi = max(hi, lo)
        out[call.tool_call_id] = (lo, hi)
        prev_hi = hi
    return out


def _effect_guids(events: list[CanonicalEvent], pidx: ProcessIndex) -> dict[str, str]:
    """event_id -> ProcessGuid of the acting process, for every host-effect event."""
    out = {}
    for e in events:
        if e.action not in HOST_EFFECTS:
            continue
        if e.process_guid:
            out[e.event_id] = e.process_guid
        elif e.pid is not None and e.source in PID_ONLY_SOURCES:
            g = pidx.find_by_pid(e.pid, before_ts=e.ts())
            if g:
                out[e.event_id] = g
    return out


def _short(args, n: int = 48) -> str:
    if isinstance(args, dict):
        v = args.get("command") or args.get("path") or args.get("url") or next(iter(args.values()), "")
    else:
        v = args
    s = str(v or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _file_node(pg: ProvGraph, path: str, ev: list[str], extra: dict | None = None) -> str:
    return pg.add_node(Node(id=file_id(path), kind=NodeKind.FILE, label=basename(path),
                            attrs={"path": path, **{k: v for k, v in (extra or {}).items() if k != "path"}},
                            evidence=ev))


def _effect_node(pg: ProvGraph, e: CanonicalEvent, kind: str) -> str:
    if kind == "file":
        return _file_node(pg, e.object, [e.event_id])
    if kind == "registry":
        return pg.add_node(Node(id=f"registry:{e.object.lower()}", kind=NodeKind.REGISTRY,
                                label=e.object.split("\\")[-1], attrs={"key": e.object,
                                                                       "details": e.attrs.get("details")},
                                evidence=[e.event_id]))
    if kind == "network":
        nid = pg.add_node(Node(id=f"net:{e.object}", kind=NodeKind.NETWORK, label=e.object,
                               attrs={"ip": e.attrs.get("dst_ip"), "port": e.attrs.get("dst_port"),
                                      "host": e.attrs.get("dst_host")}, evidence=[e.event_id]))
        if e.attrs.get("dst_host"):
            did = pg.add_node(Node(id=f"domain:{e.attrs['dst_host'].lower()}", kind=NodeKind.DOMAIN,
                                   label=e.attrs["dst_host"], evidence=[e.event_id]))
            pg.add_edge(Edge(src=did, dst=nid, relation="resolved_to", status=EdgeStatus.OBSERVED, evidence=[e.event_id]))
        return nid
    return pg.add_node(Node(id=f"domain:{e.object.lower()}", kind=NodeKind.DOMAIN, label=e.object,
                            evidence=[e.event_id]))


def _match_conn(e: CanonicalEvent, zeek: list[CanonicalEvent], tol: float = 3.0) -> CanonicalEvent | None:
    best = None
    for z in zeek:
        if z.object == e.object and abs(z.ts() - e.ts()) <= tol:
            if best is None or abs(z.ts() - e.ts()) < abs(best.ts() - e.ts()):
                best = z
    return best


def _claimed_objects(res: CanonicalEvent | None) -> list[str]:
    if not res:
        return []
    out = []
    for k in ("files_read", "files_written", "urls"):
        for item in res.attrs.get(k) or []:
            v = item["path"] if isinstance(item, dict) else item
            v = str(v).lower()
            out.append(v)
            m = re.match(r"https?://([^/:]+)", v)
            if m:
                out.append(m.group(1))
    return out
