"""Correlation: process tree, tool-call-to-process links, and human/agent attribution.

Every link and label carries the signals that produced it so an analyst (and the
report) can see why the system decided what it did.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .schema import (Action, Attribution, AttributionLabel, CanonicalEvent, EdgeStatus,
                     EventSource)

EXEC_TOOLS = {"shell", "run", "exec", "bash", "powershell", "cmd", "terminal", "run_command"}
AGENT_RUNTIMES = {"python.exe", "pythonw.exe", "node.exe", "claude.exe", "uv.exe"}
INTERACTIVE_ROOTS = {"explorer.exe", "windowsterminal.exe", "openconsole.exe"}

# Weights for the explainable attribution score. Tune these on labelled lab runs
# and report the final values; do not tune on the test split.
W = {
    "linked_tool_call": 3.0,
    "descendant_of_linked": 2.5,
    "descendant_of_runtime": 2.0,
    "noninteractive_flags": 0.5,
    "interactive_root": 2.0,
    "psreadline_match": 1.0,
}
DECISION_MARGIN = 1.5


def basename(path: str | None) -> str:
    return re.split(r"[\\/]", path or "")[-1].lower()


def norm_cmd(cmd: str | None) -> str:
    s = (cmd or "").lower().replace('"', "").replace("'", "")
    return re.sub(r"\s+", " ", s).strip()


def cmd_similarity(a: str | None, b: str | None) -> float:
    na, nb = norm_cmd(a), norm_cmd(b)
    if not na or not nb:
        return 0.0
    if na in nb or nb in na:
        return 1.0
    return SequenceMatcher(None, na, nb).ratio()


@dataclass
class ProcessIndex:
    by_guid: dict[str, CanonicalEvent] = field(default_factory=dict)
    children: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def build(cls, events: list[CanonicalEvent]) -> "ProcessIndex":
        idx = cls()
        for e in events:
            if e.action != Action.PROCESS_CREATE:
                continue
            guid = e.process_guid or f"pid{e.pid}@{e.ts():.3f}"   # 4688 has no GUID
            if guid in idx.by_guid and e.source != EventSource.SYSMON:
                continue   # Sysmon wins over 4688 for the same process
            idx.by_guid[guid] = e
        for guid, e in idx.by_guid.items():
            if e.parent_process_guid:
                idx.children.setdefault(e.parent_process_guid, []).append(guid)
        return idx

    def guid_of(self, e: CanonicalEvent) -> str:
        return e.process_guid or f"pid{e.pid}@{e.ts():.3f}"

    def find_by_pid(self, pid: int, before_ts: float | None = None) -> str | None:
        """Most recent process with this PID created at or before before_ts (handles PID reuse)."""
        best, best_t = None, None
        for g, e in self.by_guid.items():
            if e.pid != pid:
                continue
            t = e.ts()
            if before_ts is not None and t > before_ts + 1.0:
                continue
            if best_t is None or t > best_t:
                best, best_t = g, t
        return best

    def ancestors(self, guid: str, limit: int = 64) -> list[str]:
        out, cur = [], self.by_guid.get(guid)
        while cur is not None and cur.parent_process_guid and len(out) < limit:
            out.append(cur.parent_process_guid)
            cur = self.by_guid.get(cur.parent_process_guid)
        return out

    def descendants(self, guid: str) -> list[str]:
        out, stack = [], list(self.children.get(guid, []))
        while stack:
            g = stack.pop()
            out.append(g)
            stack.extend(self.children.get(g, []))
        return out

    def image_of(self, guid: str) -> str:
        e = self.by_guid.get(guid)
        return basename(e.image) if e else ""


@dataclass
class ToolLink:
    tool_call_id: str
    process_guid: str
    score: float
    status: EdgeStatus
    signals: dict
    evidence: list[str]


@dataclass
class Session:
    session_id: str
    start: CanonicalEvent
    runtime_guid: str | None
    end_ts: float


def find_sessions(events: list[CanonicalEvent], pidx: ProcessIndex) -> dict[str, Session]:
    sessions: dict[str, Session] = {}
    for e in events:
        if e.action == Action.SESSION_START and e.session_id:
            g = e.process_guid
            if not g and e.pid is not None:
                g = pidx.find_by_pid(e.pid, before_ts=e.ts())
            sessions[e.session_id] = Session(e.session_id, e, g, e.ts())
    for e in events:
        s = sessions.get(e.session_id or "")
        if s and e.source == EventSource.AGENT_TRACE:
            s.end_ts = max(s.end_ts, e.ts())
    return sessions


def link_tool_calls(events: list[CanonicalEvent], pidx: ProcessIndex,
                    sessions: dict[str, Session], min_score: float = 0.5) -> list[ToolLink]:
    """Link each execution tool call to the process it created."""
    calls = {e.tool_call_id: e for e in events if e.action == Action.TOOL_CALL}
    results = {e.tool_call_id: e for e in events if e.action == Action.TOOL_RESULT}
    links: list[ToolLink] = []
    for tcid, call in calls.items():
        tool = str(call.attrs.get("tool", "")).lower()
        if tool not in EXEC_TOOLS and not call.command_line:
            continue
        res = results.get(tcid)
        lo = call.ts() - 1.0
        hi = (res.ts() if res else call.ts() + 30.0) + 1.0
        sess = sessions.get(call.session_id or "")
        runtime = sess.runtime_guid if sess else None
        best: ToolLink | None = None
        for guid, p in pidx.by_guid.items():
            if not (lo <= p.ts() <= hi):
                continue
            sig, score, ev = {}, 0.0, [call.event_id, p.event_id]
            if res and res.process_guid and res.process_guid.lower() == guid:
                sig["process_guid_match"] = True
                score += 1.0
            elif res and res.pid is not None and res.pid == p.pid:
                sig["child_pid_match"] = True
                score += 0.6
            anc = pidx.ancestors(guid)
            if runtime and runtime in anc:
                sig["descends_from_runtime"] = True
                score += 0.2
                if p.parent_process_guid == runtime:
                    sig["direct_child_of_runtime"] = True
                    score += 0.1
            sim = cmd_similarity(call.command_line, p.command_line)
            if sim:
                sig["command_similarity"] = round(sim, 3)
                score += 0.3 * sim
            if res:
                ev.append(res.event_id)
            if score >= min_score and (best is None or score > best.score):
                independent = sig.get("process_guid_match") or sig.get("child_pid_match")
                best = ToolLink(tcid, guid, round(min(score, 1.0), 3),
                                EdgeStatus.CORROBORATED if independent else EdgeStatus.INFERRED, sig, ev)
        if best:
            links.append(best)
    return links


def attribute_processes(events: list[CanonicalEvent], pidx: ProcessIndex,
                        sessions: dict[str, Session], links: list[ToolLink]) -> list[Attribution]:
    history = [e.command_line for e in events if e.action == Action.CONSOLE_HISTORY]
    runtimes = {s.runtime_guid for s in sessions.values() if s.runtime_guid}
    linked = {l.process_guid: l for l in links}
    linked_desc: dict[str, str] = {}
    for g, l in linked.items():
        for d in pidx.descendants(g):
            linked_desc.setdefault(d, l.tool_call_id)

    out = []
    for guid, p in pidx.by_guid.items():
        if guid in runtimes:
            continue   # the agent runtime itself is labelled by the session, not scored
        a = h = 0.0
        sig: list[str] = []
        tcid = None
        anc = pidx.ancestors(guid)
        if guid in linked:
            a += W["linked_tool_call"]; tcid = linked[guid].tool_call_id
            sig.append(f"agent: created by tool call {tcid} (score {linked[guid].score})")
        elif guid in linked_desc:
            a += W["descendant_of_linked"]; tcid = linked_desc[guid]
            sig.append(f"agent: descendant of process created by tool call {tcid}")
        runtime_hit = next((r for r in runtimes if r in anc), None)
        if runtime_hit:
            a += W["descendant_of_runtime"]
            sig.append(f"agent: descends from agent runtime {pidx.image_of(runtime_hit)}")
        cl = norm_cmd(p.command_line)
        if "-noninteractive" in cl or "-noni " in cl:
            a += W["noninteractive_flags"]; sig.append("agent (weak): non-interactive shell flags")
        # Interactive root: an explorer/terminal ancestor reached WITHOUT passing through an agent runtime.
        for g in anc:
            if g in runtimes:
                break
            if pidx.image_of(g) in INTERACTIVE_ROOTS:
                h += W["interactive_root"]
                sig.append(f"human: launched from interactive shell chain ({pidx.image_of(g)})")
                break
        if any(cmd_similarity(hc, p.command_line) >= 0.9 for hc in history):
            h += W["psreadline_match"]
            sig.append("human (weak): command appears in PSReadLine console history")

        if a - h >= DECISION_MARGIN:
            label = AttributionLabel.AGENT
        elif h - a >= DECISION_MARGIN:
            label = AttributionLabel.HUMAN
        elif a >= DECISION_MARGIN and h >= DECISION_MARGIN:
            label = AttributionLabel.MIXED
        else:
            label = AttributionLabel.UNKNOWN
            if not sig:
                sig.append("no attribution signals")
        out.append(Attribution(process_guid=guid, pid=p.pid, image=p.image, label=label, agent_score=a, human_score=h,
                               signals=sig, tool_call_id=tcid))
    return out
