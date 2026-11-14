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
        if node.id in self.g:
            cur: Node = self.g.nodes[node.id]["node"]
            cur.evidence = sorted(set(cur.evidence) | set(node.evidence))
            cur.attrs.update({k: v for k, v in node.attrs.items() if v is not None})
        else:
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
        return [d["node"] for _, d in self.g.nodes(data=True) if kind is None or d["node"].kind == kind]

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
                                "attribution_signals": a.signals if a else []},
                         evidence=[p.event_id]))
    for guid in in_graph:
        p = pidx.by_guid[guid]
        if p.parent_process_guid in in_graph:
            pg.add_edge(Edge(src=f"process:{p.parent_process_guid}", dst=f"process:{guid}",
                             relation="spawned", status=O, evidence=[p.event_id]))
    for s in sessions.values():
        if s.runtime_guid in in_graph:
            pg.add_edge(Edge(src=f"session:{s.session_id}", dst=f"process:{s.runtime_guid}",
                             relation="runs_in", status=O, evidence=[s.start.event_id]))
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

    # in-process effects of non-exec tool calls (e.g. http_get/write_file inside python.exe)
    host_fx = [e for e in events if e.action in HOST_EFFECTS and effect_guid.get(e.event_id)]
    for tcid, call in tool_calls.items():
        s = sessions.get(call.session_id or "")
        if not s or not s.runtime_guid:
            continue
        res = tool_results.get(tcid)
        lo, hi = call.ts() - 0.5, (res.ts() if res else call.ts() + 30) + 0.5
        claimed = _claimed_objects(res)
        for e in host_fx:
            if effect_guid[e.event_id] != s.runtime_guid or not (lo <= e.ts() <= hi) or not e.object:
                continue
            kind, rel = HOST_EFFECTS[e.action]
            oid = _effect_node(pg, e, kind)
            names = [x.lower() for x in (e.object, e.attrs.get("dst_host")) if x]
            match = any(c in n or n in c for c in claimed for n in names)
            pg.add_edge(Edge(src=f"tool_call:{tcid}", dst=oid, relation=rel,
                             status=C if match else I, confidence=0.9 if match else 0.5,
                             signals={"in_process_effect": True, "trace_claim_match": match},
                             evidence=[call.event_id, e.event_id]))

    # DNS answers -> network endpoints
    for e in events:
        if e.action == Action.DNS_QUERY and e.object and f"domain:{e.object.lower()}" in pg.g:
            for ip in _IP.findall(str(e.attrs.get("results") or "")):
                for n in pg.nodes(NodeKind.NETWORK):
                    if n.attrs.get("ip") == ip:
                        pg.add_edge(Edge(src=f"domain:{e.object.lower()}", dst=n.id, relation="resolved_to",
                                         status=O, evidence=[e.event_id]))
    return pg


# ---------------- helpers ----------------
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
