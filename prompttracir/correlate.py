"""Correlation: process tree, tool-call-to-process links, and human/agent attribution.

Every link and label carries the signals that produced it so an analyst (and the
report) can see why the system decided what it did. All weights, thresholds and time
windows come from prompttracir.config (v0.4), so they can be tuned and reported.

Process tree sources, best first: Sysmon event 1 (ProcessGuid, parent GUID), then Security
4688 (PID only; parent found by parent PID and time). A 4688 that matches a Sysmon event
(same PID and image, within process.dedupe_window_s) is the same process: it is not added
twice, and the process is recorded as seen by both.
"""
from __future__ import annotations

import bisect
import math
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from . import config as config_mod
from .shellwrap import effective_command, unwrap
from .schema import (Action, Attribution, AttributionLabel, CanonicalEvent, EdgeStatus,
                     EventSource)

EXEC_TOOLS = {"shell", "run", "exec", "bash", "powershell", "cmd", "terminal", "run_command"}
AGENT_RUNTIMES = {"python.exe", "pythonw.exe", "node.exe", "claude.exe", "uv.exe", "bun.exe"}
INTERACTIVE_ROOTS = {"explorer.exe", "windowsterminal.exe", "openconsole.exe"}

# v0.1-v0.3 names, kept for scripts that import them. The live values are in config.DEFAULTS.
W = config_mod.DEFAULTS["weights"]
DECISION_MARGIN = config_mod.DEFAULTS["decision_margin"]


def basename(path: str | None) -> str:
    return re.split(r"[\\/]", path or "")[-1].lower()


_PROGRAM = re.compile(r"(?:^|(?<= ))(?:[a-z]:\\|\\)?(?:[^ \\]+\\)*([^ \\]+)\.exe(?= |$)")


def norm_cmd(cmd: str | None) -> str:
    """Lower case, no quotes, single spaces, and programs without folder or ``.exe``.

    A typed ``schtasks /query`` and Sysmon's ``"C:\\WINDOWS\\system32\\schtasks.exe" /query``
    are the same command; so are ``curl`` and ``curl.exe``. Folders with spaces in them are left
    as they are."""
    s = (cmd or "").lower().replace('"', "").replace("'", "")
    s = re.sub(r"\s+", " ", s).strip()
    return _PROGRAM.sub(r"\1", s)


def norm_dir(path: str | None) -> str:
    """Windows directory for comparison: drive path only (ShellBags prefix 'My Computer\\'), no trailing slash."""
    m = re.search(r"[A-Za-z]:\\.*", path or "")
    return (m.group(0) if m else (path or "")).rstrip("\\/").lower()


def cmd_similarity(a: str | None, b: str | None) -> float:
    na, nb = norm_cmd(a), norm_cmd(b)
    if not na or not nb:
        return 0.0
    if na in nb or nb in na:
        return 1.0
    return SequenceMatcher(None, na, nb).ratio()


def _cfg(cfg: dict | None) -> dict:
    return cfg if cfg is not None else config_mod.DEFAULTS


# ---------------- process index ----------------
@dataclass
class ProcessIndex:
    by_guid: dict[str, CanonicalEvent] = field(default_factory=dict)
    children: dict[str, list[str]] = field(default_factory=dict)
    parent_of: dict[str, str] = field(default_factory=dict)
    seen_by: dict[str, list[str]] = field(default_factory=dict)      # guid -> ["sysmon", "security_4688"]
    corroborating: dict[str, list[str]] = field(default_factory=dict)   # guid -> extra event ids

    @classmethod
    def build(cls, events: list[CanonicalEvent], cfg: dict | None = None) -> "ProcessIndex":
        win = _cfg(cfg)["process"]["dedupe_window_s"]
        idx = cls()
        creates = [e for e in events if e.action == Action.PROCESS_CREATE]
        by_pid: dict[int, list[str]] = defaultdict(list)
        for e in creates:
            if e.source != EventSource.SYSMON:
                continue
            g = e.process_guid or f"pid{e.pid}@{e.ts():.3f}"
            idx.by_guid[g] = e
            idx.seen_by[g] = ["sysmon"]
            by_pid[e.pid].append(g)
        for e in creates:
            if e.source == EventSource.SYSMON:
                continue
            dup = next((g for g in by_pid.get(e.pid, [])
                        if abs(idx.by_guid[g].ts() - e.ts()) <= win
                        and basename(idx.by_guid[g].image) == basename(e.image)), None)
            if dup:
                idx.seen_by[dup].append("security_4688")
                idx.corroborating.setdefault(dup, []).append(e.event_id)
                continue
            g = e.process_guid or f"pid{e.pid}@{e.ts():.3f}"
            if g in idx.by_guid:
                continue
            idx.by_guid[g] = e
            idx.seen_by[g] = ["security_4688" if e.attrs.get("via") == "4688" else e.source.value]
        for g, e in idx.by_guid.items():
            parent = e.parent_process_guid
            if parent is None and e.parent_pid is not None:
                parent = idx.find_by_pid(e.parent_pid, before_ts=e.ts(), exclude=g)
            if parent and parent != g:
                idx.parent_of[g] = parent
                idx.children.setdefault(parent, []).append(g)
        return idx

    def guid_of(self, e: CanonicalEvent) -> str:
        return e.process_guid or f"pid{e.pid}@{e.ts():.3f}"

    def find_by_pid(self, pid: int, before_ts: float | None = None, exclude: str | None = None) -> str | None:
        """Most recent process with this PID created at or before before_ts (handles PID reuse)."""
        best, best_t = None, None
        for g, e in self.by_guid.items():
            if e.pid != pid or g == exclude:
                continue
            t = e.ts()
            if before_ts is not None and t > before_ts + 1.0:
                continue
            if best_t is None or t > best_t:
                best, best_t = g, t
        return best

    def ancestors(self, guid: str, limit: int = 64) -> list[str]:
        out, cur = [], guid
        while cur in self.parent_of and len(out) < limit:
            cur = self.parent_of[cur]
            if cur in out or cur == guid:
                break                    # PID-reuse loop in PID-only data
            out.append(cur)
        return out

    def descendants(self, guid: str) -> list[str]:
        out, seen, stack = [], {guid}, list(self.children.get(guid, []))
        while stack:
            g = stack.pop()
            if g in seen:
                continue
            seen.add(g)
            out.append(g)
            stack.extend(self.children.get(g, []))
        return out

    def image_of(self, guid: str) -> str:
        e = self.by_guid.get(guid)
        return basename(e.image) if e else ""


# ---------------- sessions ----------------
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
    runtime_method: str | None = None      # "process_guid", "pid", "inferred" or None
    runtime_signals: dict = field(default_factory=dict)
    clock_offset: float = 0.0              # host clock minus trace clock, seconds
    clock_offset_method: str = "assumed"   # "child_pid" (estimated) or "assumed"
    clock_offset_pairs: int = 0
    cwd: str | None = None

    def host_span(self, margin: float = 0.0) -> tuple[float, float]:
        return self.start.ts() + self.clock_offset - margin, self.end_ts + self.clock_offset + margin

    def summary(self) -> dict:
        return {"session_id": self.session_id, "runtime_guid": self.runtime_guid,
                "runtime_method": self.runtime_method, "runtime_signals": self.runtime_signals,
                "clock_offset_s": round(self.clock_offset, 3), "clock_offset_method": self.clock_offset_method,
                "clock_offset_pairs": self.clock_offset_pairs, "cwd": self.cwd,
                "start": self.start.timestamp.isoformat()}


def _exec_calls(events: list[CanonicalEvent], session_id: str | None = None) -> list[CanonicalEvent]:
    out = []
    for e in events:
        if e.action != Action.TOOL_CALL or (session_id and e.session_id != session_id):
            continue
        if str(e.attrs.get("tool", "")).lower() in EXEC_TOOLS or e.command_line:
            out.append(e)
    return out


def find_sessions(events: list[CanonicalEvent], pidx: ProcessIndex, cfg: dict | None = None) -> dict[str, Session]:
    cfg = _cfg(cfg)
    sessions: dict[str, Session] = {}
    for e in events:
        if e.action == Action.SESSION_START and e.session_id:
            g, method = e.process_guid, "process_guid" if e.process_guid else None
            if not g and e.pid is not None:
                g = pidx.find_by_pid(e.pid, before_ts=e.ts())
                method = "pid" if g else None
            sessions[e.session_id] = Session(e.session_id, e, g, e.ts(), runtime_method=method,
                                             cwd=e.attrs.get("cwd"))
    for e in events:
        s = sessions.get(e.session_id or "")
        if s and e.source == EventSource.AGENT_TRACE:
            s.end_ts = max(s.end_ts, e.ts())
    results = {e.tool_call_id: e for e in events if e.action == Action.TOOL_RESULT}
    for s in sessions.values():
        _estimate_clock_offset(s, events, results, pidx, cfg)
        if s.runtime_guid is None:
            _identify_runtime(s, events, results, pidx, cfg)
    return sessions


def _estimate_clock_offset(s: Session, events, results, pidx: ProcessIndex, cfg: dict) -> None:
    """Host minus trace clock, from tool calls whose child PID the trace recorded."""
    link = cfg["link"]
    s.clock_offset, s.clock_offset_method = float(link["assumed_clock_offset_s"]), "assumed"
    if not link["estimate_clock_offset"]:
        return
    deltas = []
    for call in events:
        if call.action != Action.TOOL_CALL or call.session_id != s.session_id:
            continue
        res = results.get(call.tool_call_id)
        if not res or res.pid is None:
            continue
        cands = [p.ts() - call.ts() for p in pidx.by_guid.values()
                 if p.pid == res.pid and abs(p.ts() - call.ts()) <= link["max_clock_offset_s"]]
        if cands:
            deltas.append(min(cands, key=abs))
    if deltas:
        s.clock_offset, s.clock_offset_method, s.clock_offset_pairs = statistics.median(deltas), "child_pid", len(deltas)


def _call_window(call: CanonicalEvent, res: CanonicalEvent | None, offset: float, link: dict) -> tuple[float, float]:
    lo = call.ts() + offset - link["window_before_s"]
    hi = (res.ts() if res else call.ts() + 30.0) + offset + link["window_after_s"]
    return lo, hi


def _identify_runtime(s: Session, events, results, pidx: ProcessIndex, cfg: dict) -> None:
    """Find the agent runtime of a session whose trace has no PID (Claude Code).

    Candidates are processes with a runtime image started before the session. Each scores
    3 per exec tool call of the session matched by one of its descendants (command similarity
    >= 0.8 inside the call window), 1 for a claude image or command line, and 1 when its
    working directory is the session's. The best candidate at or above min_score wins (ties:
    the most recent). The choice and its signals are recorded; the runtime is INFERRED."""
    rid = cfg["runtime_identification"]
    images = {i.lower() for i in rid["images"]}
    start = s.start.ts() + s.clock_offset
    calls = _exec_calls(events, s.session_id)
    best = None
    for g, p in pidx.by_guid.items():
        if basename(p.image) not in images or not (start - rid["max_age_s"] <= p.ts() <= start + 1.0):
            continue
        sig, score = {}, 0.0
        desc = [pidx.by_guid[d] for d in pidx.descendants(g)]
        matched = []
        for call in calls:
            lo, hi = _call_window(call, results.get(call.tool_call_id), s.clock_offset, cfg["link"])
            if any(lo <= d.ts() <= hi and cmd_similarity(call.command_line, effective_command(d.command_line)) >= 0.8
                   for d in desc):
                matched.append(call.tool_call_id)
        if matched:
            sig["tool_calls_matched_by_children"] = matched
            score += 3.0 * len(matched)
        if basename(p.image) == "claude.exe" or "claude" in norm_cmd(p.command_line):
            sig["claude_image_or_command"] = True
            score += 1.0
        if s.cwd and norm_dir(p.attrs.get("current_directory")) == norm_dir(s.cwd):
            sig["working_directory_match"] = True
            score += 1.0
        if score >= rid["min_score"] and (best is None or (score, p.ts()) > (best[0], best[2].ts())):
            best = (score, g, p, sig)
    if best:
        score, g, p, sig = best
        s.runtime_guid, s.runtime_method = g, "inferred"
        s.runtime_signals = {**sig, "score": score, "image": p.image, "pid": p.pid}


# ---------------- tool-call-to-process links ----------------
def link_tool_calls(events: list[CanonicalEvent], pidx: ProcessIndex,
                    sessions: dict[str, Session], cfg: dict | None = None,
                    min_score: float | None = None, timestamp_only: bool = False) -> list[ToolLink]:
    """Link each execution tool call to the process it created. timestamp_only (v0.8 baseline):
    the process that started nearest to the call inside its window, nothing else."""
    cfg = _cfg(cfg)
    link = cfg["link"]
    if timestamp_only:
        return _link_by_time(events, pidx, sessions, link)
    min_score = link["min_score"] if min_score is None else min_score
    results = {e.tool_call_id: e for e in events if e.action == Action.TOOL_RESULT}
    blocks: dict[int, list[CanonicalEvent]] = defaultdict(list)
    for e in events:
        if e.action == Action.SCRIPT_BLOCK and e.pid is not None and e.command_line:
            blocks[e.pid].append(e)
    links: list[ToolLink] = []
    for call in _exec_calls(events):
        tcid = call.tool_call_id
        res = results.get(tcid)
        sess = sessions.get(call.session_id or "")
        offset = sess.clock_offset if sess else float(link["assumed_clock_offset_s"])
        lo, hi = _call_window(call, res, offset, link)
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
            if runtime and runtime in pidx.ancestors(guid):
                sig["descends_from_runtime"] = True
                score += 0.2
                if pidx.parent_of.get(guid) == runtime:
                    sig["direct_child_of_runtime"] = True
                    score += 0.1
                if sess and sess.runtime_method == "inferred":
                    sig["runtime_inferred"] = True
            wrapped = unwrap(p.command_line)
            sim = cmd_similarity(call.command_line, wrapped or p.command_line)
            if sim:
                sig["command_similarity"] = round(sim, 3)
            if wrapped is not None:
                sig["compared_wrapped_command"] = True     # v0.6: Claude Code's Bash wrapper
            sb_sim, sb_ev = 0.0, None
            for b in blocks.get(p.pid, []):
                if p.ts() - 1.0 <= b.ts() <= hi + 5.0:
                    bs = cmd_similarity(call.command_line, b.command_line)
                    if bs > sb_sim:
                        sb_sim, sb_ev = bs, b.event_id
            if sb_sim >= link["script_block_similarity"]:
                sig["script_block_match"] = round(sb_sim, 3)     # 4104: PowerShell ran the tool's script
                ev.append(sb_ev)
            else:
                sb_sim = 0.0
            score += 0.3 * max(sim, sb_sim)
            if res:
                ev.append(res.event_id)
            if score >= min_score and (best is None or score > best.score):
                independent = sig.get("process_guid_match") or sig.get("child_pid_match")
                best = ToolLink(tcid, guid, round(min(score, 1.0), 3),
                                EdgeStatus.CORROBORATED if independent else EdgeStatus.INFERRED, sig, ev)
        if best:
            links.append(best)
    return links


def _link_by_time(events, pidx: ProcessIndex, sessions: dict[str, Session], link: dict) -> list[ToolLink]:
    results = {e.tool_call_id: e for e in events if e.action == Action.TOOL_RESULT}
    runtimes = {s.runtime_guid for s in sessions.values() if s.runtime_guid}
    links = []
    for call in _exec_calls(events):
        res = results.get(call.tool_call_id)
        sess = sessions.get(call.session_id or "")
        offset = sess.clock_offset if sess else float(link["assumed_clock_offset_s"])
        lo, hi = _call_window(call, res, offset, link)
        t0 = call.ts() + offset
        cands = [(abs(p.ts() - t0), g, p) for g, p in pidx.by_guid.items()
                 if lo <= p.ts() <= hi and g not in runtimes]
        if not cands:
            continue
        _, g, p = min(cands, key=lambda c: (c[0], c[1]))
        links.append(ToolLink(call.tool_call_id, g, 0.5, EdgeStatus.INFERRED, {"time_window": True},
                              [call.event_id, p.event_id] + ([res.event_id] if res else [])))
    return links


def attribute_by_time(pidx: ProcessIndex, sessions: dict[str, Session], links: list[ToolLink],
                      cfg: dict | None = None) -> list[Attribution]:
    """v0.8 timestamp baseline: a process that started inside an agent session is the agent's,
    any other one the human's. No ancestry, PIDs, command lines or human-side artifacts."""
    cfg = _cfg(cfg)
    spans = [s.host_span(cfg["human"]["session_margin_s"]) for s in sessions.values()]
    runtimes = {s.runtime_guid for s in sessions.values() if s.runtime_guid}
    linked = {l.process_guid: l.tool_call_id for l in links}
    out = []
    for guid, p in pidx.by_guid.items():
        if guid in runtimes:
            continue
        inside = any(lo <= p.ts() <= hi for lo, hi in spans)
        label = AttributionLabel.AGENT if inside else AttributionLabel.HUMAN
        out.append(Attribution(process_guid=guid, pid=p.pid, image=p.image, label=label,
                               agent_score=1.0 if inside else 0.0, human_score=0.0 if inside else 1.0,
                               signals=["baseline: started inside an agent session" if inside
                                        else "baseline: started outside every agent session"],
                               tool_call_id=linked.get(guid), agent_probability=1.0 if inside else 0.0,
                               seen_by=pidx.seen_by.get(guid, [])))
    return out


# ---------------- attribution ----------------
class _TimeIndex:
    """Events sorted by time, for window lookups."""

    def __init__(self, events: list[CanonicalEvent]):
        self.events = sorted(events, key=lambda e: e.ts())
        self.times = [e.ts() for e in self.events]

    def between(self, lo: float, hi: float) -> list[CanonicalEvent]:
        return self.events[bisect.bisect_left(self.times, lo):bisect.bisect_right(self.times, hi)]


def agent_probability(agent: float, human: float, temperature: float) -> float:
    return round(1.0 / (1.0 + math.exp(-(agent - human) / max(temperature, 1e-6))), 4)


def attribute_processes(events: list[CanonicalEvent], pidx: ProcessIndex,
                        sessions: dict[str, Session], links: list[ToolLink],
                        cfg: dict | None = None) -> list[Attribution]:
    cfg = _cfg(cfg)
    W_, H = cfg["weights"], cfg["human"]
    margin = cfg["decision_margin"]
    history = [e.command_line for e in events if e.action == Action.CONSOLE_HISTORY]
    gui = _TimeIndex([e for e in events if e.action == Action.GUI_LAUNCH and e.image])
    opens = _TimeIndex([e for e in events if e.action == Action.FILE_OPEN and e.object])
    bags = _TimeIndex([e for e in events if e.action == Action.FOLDER_OPEN and e.object])
    logon_type = {e.logon_id.lower(): e.attrs.get("logon_type") for e in events
                  if e.action == Action.LOGON and e.logon_id and e.attrs.get("logon_type") is not None}
    spans = [s.host_span(H["session_margin_s"]) for s in sessions.values()]
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
        contrib: list[dict] = []
        tcid = None

        def add(side: str, key: str, text: str):
            contrib.append({"side": side, "signal": key, "weight": W_[key], "detail": text})

        anc = pidx.ancestors(guid)
        t = p.ts()
        # ---- agent side
        if guid in linked:
            tcid = linked[guid].tool_call_id
            add("agent", "linked_tool_call", f"agent: created by tool call {tcid} (score {linked[guid].score})")
        elif guid in linked_desc:
            tcid = linked_desc[guid]
            add("agent", "descendant_of_linked", f"agent: descendant of process created by tool call {tcid}")
        runtime_hit = next((r for r in runtimes if r in anc), None)
        if runtime_hit:
            add("agent", "descendant_of_runtime", f"agent: descends from agent runtime {pidx.image_of(runtime_hit)}")
        cl = norm_cmd(p.command_line)
        if "-noninteractive" in cl or "-noni " in cl:
            add("agent", "noninteractive_flags", "agent (weak): non-interactive shell flags")
        # ---- human side
        for g in anc:   # explorer/terminal ancestor reached WITHOUT passing through an agent runtime
            if g in runtimes:
                break
            if pidx.image_of(g) in INTERACTIVE_ROOTS:
                add("human", "interactive_root", f"human: launched from interactive shell chain ({pidx.image_of(g)})")
                break
        if any(cmd_similarity(hc, p.command_line) >= 0.9 for hc in history):
            add("human", "psreadline_match", "human (weak): command appears in PSReadLine console history")
        img = basename(p.image)
        ua = next((e for e in gui.between(t - H["userassist_window_s"], t + H["userassist_window_s"])
                   if basename(e.image) == img), None)
        if ua:
            add("human", "userassist_launch",
                f"human: UserAssist records {img} started from the Explorer shell at {ua.timestamp.isoformat()}")
        low = (p.command_line or "").lower()
        if low:
            for e in opens.between(t - H["shell_open_window_s"], t + H["shell_open_window_s"]):
                obj = e.object.lower()
                if obj in low or (len(basename(obj)) > 4 and basename(obj) in low):
                    add("human", "shell_file_open",
                        f"human: {e.object} was opened through Explorer ({e.source.value}) at {e.timestamp.isoformat()}")
                    break
        cwd = norm_dir(p.attrs.get("current_directory"))
        if cwd:
            bag = next((e for e in bags.between(t - H["shellbag_window_s"], t + 5.0) if norm_dir(e.object) == cwd), None)
            if bag:
                add("human", "shellbag_folder", f"human (weak): {bag.object} browsed in Explorer before the process started")
        if spans and not any(lo <= t <= hi for lo, hi in spans):
            add("human", "outside_agent_session", "human (weak): started while no agent session was running")
        # ---- logon context
        lt = logon_type.get((p.logon_id or "").lower())
        context = []
        if lt is not None:
            if lt in H["interactive_logon_types"]:
                context.append(f"context: interactive logon (type {lt})")
            else:
                dropped = [c for c in contrib if c["side"] == "human"]
                contrib = [c for c in contrib if c["side"] != "human"]
                context.append(f"context: non-interactive logon (type {lt}); "
                               f"{len(dropped)} human signal(s) not counted")

        a = sum(c["weight"] for c in contrib if c["side"] == "agent")
        h = sum(c["weight"] for c in contrib if c["side"] == "human")
        if a - h >= margin:
            label = AttributionLabel.AGENT
        elif h - a >= margin:
            label = AttributionLabel.HUMAN
        elif a >= margin and h >= margin:
            label = AttributionLabel.MIXED
        else:
            label = AttributionLabel.UNKNOWN
        sig = [c["detail"] for c in contrib] + context
        if not sig:
            sig.append("no attribution signals")
        out.append(Attribution(process_guid=guid, pid=p.pid, image=p.image, label=label, agent_score=a,
                               human_score=h, signals=sig, tool_call_id=tcid,
                               agent_probability=agent_probability(a, h, cfg["calibration_temperature"]),
                               contributions=contrib, seen_by=pidx.seen_by.get(guid, [])))
    return out
