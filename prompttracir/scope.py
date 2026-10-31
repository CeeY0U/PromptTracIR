"""Deterministic deviation rules (the "resource envelope" check).

The case envelope records what the user's request legitimately needed:
    {"allowed_paths": ["C:\\\\Users\\\\lab\\\\project"], "allowed_domains": ["docs.python.org"],
     "model_api_domains": ["127.0.0.1", "api.anthropic.com"]}
Anything an agent-attributed action touches outside it becomes a Finding.
The LLM never creates findings; it only explains them.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from .graph import ProvGraph
from .schema import EdgeStatus, Finding, NodeKind

DEFAULT_SENSITIVE = [r"secret", r"\.ssh", r"credential", r"password", r"login data", r"\.env\b",
                     r"id_rsa", r"\.kdbx", r"wallet", r"cookies", r"token"]
PERSIST_CMD = [r"schtasks(\.exe)?\s+/create", r"new-scheduledtask", r"register-scheduledtask",
               r"\\currentversion\\run", r"start menu\\programs\\startup", r"sc(\.exe)?\s+create"]
CRED_CMD = [r"protecteddata", r"login data", r"dpapi", r"cmdkey", r"vaultcmd", r"mimikatz",
            r"sekurlsa", r"lsass"]
PATH_RE = re.compile(r"(?:[a-zA-Z]:\\|\\\\|~[\\/]|%\w+%\\)[^\s\"'|<>*?]+")


def _under(path: str, roots: list[str]) -> bool:
    p = path.replace("/", "\\").lower().rstrip("\\")
    return any(p == r.replace("/", "\\").lower().rstrip("\\") or
               p.startswith(r.replace("/", "\\").lower().rstrip("\\") + "\\") for r in roots)


def is_sensitive(path: str, patterns: list[str] | None = None) -> bool:
    return any(re.search(p, path, re.I) for p in (patterns or DEFAULT_SENSITIVE))


def _external(host_or_ip: str | None) -> bool:
    if not host_or_ip:
        return False
    h = host_or_ip.split(":")[0]
    try:
        ip = ipaddress.ip_address(h)
        return not (ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return h not in ("localhost",)


def owning_tool_call(pg: ProvGraph, nid: str) -> str | None:
    """Walk predecessors until a tool_call node is found (nearest first)."""
    seen, frontier = {nid}, [nid]
    while frontier:
        nxt = []
        for n in frontier:
            if pg.node(n).kind == NodeKind.TOOL_CALL:
                return n
            for p in pg.g.predecessors(n):
                if p not in seen and pg.node(p).kind in (NodeKind.TOOL_CALL, NodeKind.PROCESS):
                    seen.add(p); nxt.append(p)
        frontier = nxt
    return None


def agent_actors(pg: ProvGraph) -> set[str]:
    """Tool calls and processes the system attributes to the agent."""
    out = {n.id for n in pg.nodes(NodeKind.TOOL_CALL)}
    for n in pg.nodes(NodeKind.PROCESS):
        if n.attrs.get("attribution") in ("agent", "mixed"):
            out.add(n.id)
    return out


def run_rules(pg: ProvGraph, envelope: dict) -> list[Finding]:
    allowed_paths = envelope.get("allowed_paths", [])
    allowed_domains = {d.lower() for d in envelope.get("allowed_domains", [])}
    model_domains = {d.lower() for d in envelope.get("model_api_domains", [])}
    sens = envelope.get("sensitive_patterns") or DEFAULT_SENSITIVE
    actors = agent_actors(pg)
    findings: dict[tuple, Finding] = {}

    def add(kind, sev, summary, nodes, evidence, **attrs):
        tc = attrs.get("tool_call") or next((t for n in nodes if (t := owning_tool_call(pg, n))), None)
        target = (attrs.get("path") or attrs.get("destination") or "").lower()
        # one finding per (kind, tool call, target); extra actors/evidence are merged in
        key = (kind, tc, target) if target else (kind, tc, tuple(sorted(nodes)))
        if key in findings:
            f = findings[key]
            f.nodes = sorted(set(f.nodes) | set(nodes))
            f.evidence = sorted(set(f.evidence) | set(evidence))
            return
        findings[key] = Finding(finding_id="", kind=kind, severity=sev, summary=summary, nodes=nodes,
                                evidence=sorted(set(evidence)), attrs={**attrs, "tool_call": tc})

    # 1. files touched by agent actors
    for e in pg.edges():
        if e.src not in actors:
            continue
        dst = pg.node(e.dst)
        if dst.kind == NodeKind.FILE and e.relation in ("read", "wrote", "created", "deleted"):
            path = dst.attrs.get("path", "")
            # ignore the runtime's own bookkeeping files that are not tied to a tool call
            if pg.node(e.src).kind == NodeKind.PROCESS and owning_tool_call(pg, e.src) is None:
                continue
            s = is_sensitive(path, sens)
            # in-process effects that the trace never claimed are timing-only links; flag them only if sensitive
            if e.status == EdgeStatus.INFERRED and not s:
                continue
            if not _under(path, allowed_paths):
                add("out_of_scope_file", "high" if s else "medium",
                    f"{pg.node(e.src).label} {e.relation} {path} outside the task scope"
                    + (" (sensitive)" if s else ""), [e.src, e.dst], e.evidence,
                    path=path, sensitive=s, relation=e.relation, status=e.status.value)

    # 2. paths referenced in agent command lines (Sysmon has no file-read events)
    for nid in actors:
        n = pg.node(nid)
        args = n.attrs.get("args")
        cmd = n.attrs.get("command_line") or (args.get("command") if isinstance(args, dict) else None)
        own_image = (n.attrs.get("image") or "").lower()
        for path in PATH_RE.findall(cmd or ""):
            if path.lower() == own_image or path.lower().endswith((".exe", ".dll")):
                continue   # program paths are not data access
            if not _under(path, allowed_paths):
                s = is_sensitive(path, sens)
                add("out_of_scope_file", "high" if s else "medium",
                    f"{n.label} references {path} outside the task scope" + (" (sensitive)" if s else ""),
                    [nid], n.evidence, path=path, sensitive=s, relation="referenced",
                    status=EdgeStatus.INFERRED.value)
        low = (cmd or "").lower()
        if any(re.search(p, low) for p in PERSIST_CMD):
            add("persistence", "high", f"{n.label} creates persistence", [nid], n.evidence)
        if any(re.search(p, low) for p in CRED_CMD):
            add("credential_access", "high", f"{n.label} touches credential stores", [nid], n.evidence)

    # 3. registry persistence and external egress
    for e in pg.edges():
        if e.src not in actors:
            continue
        dst = pg.node(e.dst)
        if dst.kind == NodeKind.REGISTRY and re.search(r"\\currentversion\\run", dst.attrs.get("key", ""), re.I):
            add("persistence", "high", f"{pg.node(e.src).label} sets Run key {dst.attrs['key']}",
                [e.src, e.dst], e.evidence)
        if dst.kind in (NodeKind.NETWORK, NodeKind.DOMAIN) and e.relation in ("connected", "resolved"):
            host = (dst.attrs.get("host") or (dst.label if dst.kind == NodeKind.DOMAIN else "")).lower()
            ip = dst.attrs.get("ip") or ""
            names = {host, ip} - {""}
            if names & (allowed_domains | model_domains):
                continue
            if dst.kind == NodeKind.NETWORK and not _external(ip):
                continue
            add("external_egress", "high", f"{pg.node(e.src).label} contacted {host or ip}",
                [e.src, e.dst], e.evidence, destination=host or ip, status=e.status.value)

    out = sorted(findings.values(), key=lambda f: _tc_time(pg, f.attrs.get("tool_call")))
    for i, f in enumerate(out, 1):
        f.finding_id = f"F{i:03d}"
    return out


def _tc_time(pg: ProvGraph, tc: str | None) -> str:
    if tc and tc in pg.g:
        return pg.node(tc).attrs.get("ts", "")
    return "9999"


def first_deviation(pg: ProvGraph, findings: list[Finding]) -> str | None:
    """The earliest tool call responsible for any finding."""
    tcs = [f.attrs.get("tool_call") for f in findings if f.attrs.get("tool_call")]
    if not tcs:
        return None
    return min(tcs, key=lambda t: datetime.fromisoformat(pg.node(t).attrs["ts"]))
