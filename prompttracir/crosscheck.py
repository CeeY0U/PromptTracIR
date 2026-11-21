"""Cross-check the agent's transcript against independent host evidence (roadmap v0.5).

The trace is written by the agent (or the harness around it) and can be edited after the run.
Sysmon / Security 4688 and the memory image are recorded by Windows, not by the agent, so they
can confirm or contradict what the trace says:

  command    each linked tool call's command against the command line Windows recorded for the
             process it started, and against the command line in memory when the process is
             still there: transcript_check edge, CORROBORATED or CONTRADICTED
  untraced   shell processes the agent runtime started during the session that no tool call in
             the trace accounts for (a tool call deleted from the trace): CONTRADICTED
             "unexplained" edge from the session, and a finding

v0.6: a runtime that wraps every tool execution (Claude Code's Bash wrapper, see shellwrap.py)
is compared on the wrapped command, and its other shells (the start-up probes `bash -c env`,
`bash -lc "echo $PATH"` and the shell-snapshot builder) are logged as runtime bookkeeping
instead of untraced tool calls. A Bash call deleted from the transcript still runs inside the
wrapper, so it is still caught.
  sockets    connections Volatility finds in memory for processes in the graph corroborate the
             network edges Sysmon recorded

Contradictions become findings (transcript_mismatch, untraced_agent_process). Like every
other rule here they come from parsed records only; nothing is inferred by a model.
"""
from __future__ import annotations

from .correlate import ProcessIndex, Session, ToolLink, basename, cmd_similarity
from .graph import ProvGraph
from .schema import Action, CanonicalEvent, Edge, EdgeStatus, Finding, NodeKind
from .shellwrap import unwrap

SHELL_IMAGES = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe"}
AGREE = 0.8          # command similarity at or above: the host confirms the transcript
DISAGREE = 0.5       # below: the host contradicts it; in between: no verdict
MEM_START_TOL_S = 2.0
# runtimes that start every tool execution inside a recognisable wrapper (shellwrap.py)
WRAPPING_RUNTIMES = {"claude-code"}


def _trace_command(pg: ProvGraph, tc: str) -> str | None:
    args = pg.node(tc).attrs.get("args")
    if isinstance(args, dict):
        return args.get("command") or args.get("cmd")
    return args if isinstance(args, str) else None


def cross_check(pg: ProvGraph, events: list[CanonicalEvent], pidx: ProcessIndex,
                sessions: dict[str, Session], links: list[ToolLink]) -> tuple[list[dict], list[Finding]]:
    log: list[dict] = []
    findings: list[Finding] = []
    C, X = EdgeStatus.CORROBORATED, EdgeStatus.CONTRADICTED

    mem_cmd: dict[int, list[CanonicalEvent]] = {}
    mem_proc: dict[int, list[CanonicalEvent]] = {}
    for e in events:
        if e.action == Action.MEM_CMDLINE and e.pid is not None and e.command_line:
            mem_cmd.setdefault(e.pid, []).append(e)
        elif e.action == Action.MEM_PROCESS and e.pid is not None:
            mem_proc.setdefault(e.pid, []).append(e)

    def in_memory(guid: str) -> CanonicalEvent | None:
        """Memory's command line for this very process (same PID, same start time)."""
        p = pidx.by_guid[guid]
        cands = mem_cmd.get(p.pid or -1) or []
        if not cands:
            return None
        starts = [m for m in mem_proc.get(p.pid, []) if m.ts_precision != "none"]
        if starts and not any(abs(m.ts() - p.ts()) <= MEM_START_TOL_S for m in starts):
            return None           # the PID was reused by another process
        return cands[0]

    # 1. linked tool calls: the command the trace claims vs what Windows and memory recorded
    for l in links:
        tc = f"tool_call:{l.tool_call_id}"
        if tc not in pg.g or f"process:{l.process_guid}" not in pg.g:
            continue
        claimed = _trace_command(pg, tc)
        if not claimed:
            continue
        host = pidx.by_guid[l.process_guid]
        checks = []
        if host.command_line:
            checks.append(("process_create", host.command_line, [host.event_id]))
        mem = in_memory(l.process_guid)
        if mem is not None:
            checks.append(("memory", mem.command_line, [mem.event_id]))
        for source, recorded, ev in checks:
            wrapped = unwrap(recorded)
            sim = round(cmd_similarity(claimed, wrapped if wrapped is not None else recorded), 3)
            verdict = "agree" if sim >= AGREE else "contradict" if sim < DISAGREE else "unclear"
            log.append({"tool_call": tc, "process": f"process:{l.process_guid}", "source": source,
                        "trace_command": claimed, "recorded_command": recorded, "similarity": sim,
                        "verdict": verdict, **({"wrapped_command": wrapped} if wrapped is not None else {})})
            if verdict == "unclear":
                continue
            pg.add_edge(Edge(src=tc, dst=f"process:{l.process_guid}", relation="transcript_check",
                             status=C if verdict == "agree" else X, confidence=1.0,
                             signals={"source": source, "similarity": sim, "trace_command": claimed,
                                      "recorded_command": recorded},
                             evidence=pg.node(tc).evidence + ev))
            if verdict == "contradict":
                findings.append(Finding(
                    finding_id="", kind="transcript_mismatch", severity="high",
                    summary=f"{pg.node(tc).label}: the trace says {claimed!r}, "
                            f"{'memory' if source == 'memory' else 'Windows'} recorded {recorded!r}",
                    nodes=[tc, f"process:{l.process_guid}"], evidence=sorted(set(pg.node(tc).evidence + ev)),
                    attrs={"tool_call": tc, "source": source, "similarity": sim}))

    # 2. shells the runtime started that no tool call accounts for
    linked = {l.process_guid for l in links}
    for s in sessions.values():
        if not s.runtime_guid or s.runtime_guid not in pidx.by_guid:
            continue
        lo, hi = s.host_span(margin=2.0)
        wraps_tools = str(s.start.attrs.get("agent") or "").lower() in WRAPPING_RUNTIMES
        for child in pidx.children.get(s.runtime_guid, []):
            p = pidx.by_guid[child]
            if child in linked or basename(p.image) not in SHELL_IMAGES or not lo <= p.ts() <= hi:
                continue
            pid_ = f"process:{child}"
            sid = f"session:{s.session_id}"
            if pid_ not in pg.g or sid not in pg.g:
                continue
            if wraps_tools and unwrap(p.command_line) is None:
                log.append({"session": sid, "process": pid_, "source": "process_create",
                            "recorded_command": p.command_line, "verdict": "runtime_bookkeeping"})
                continue
            pg.add_edge(Edge(src=sid, dst=pid_, relation="unexplained", status=X, confidence=1.0,
                             signals={"reason": "started by the agent runtime during the session, "
                                                "but no tool call in the trace accounts for it",
                                      "command_line": p.command_line}, evidence=[p.event_id]))
            log.append({"session": sid, "process": pid_, "source": "process_create",
                        "recorded_command": p.command_line, "verdict": "untraced"})
            findings.append(Finding(
                finding_id="", kind="untraced_agent_process", severity="high",
                summary=f"{basename(p.image)} ({p.pid}) was started by the agent runtime but is missing "
                        f"from the trace: {p.command_line!r}",
                nodes=[sid, pid_], evidence=[p.event_id],
                attrs={"tool_call": None, "process": pid_, "command_line": p.command_line}))

    # 3. sockets in memory corroborate network edges of processes in the graph
    for e in events:
        if e.action != Action.MEM_CONN or e.pid is None or not e.object:
            continue
        net = f"net:{e.object}"
        if net not in pg.g:
            continue
        for n in pg.nodes(NodeKind.PROCESS):
            if n.attrs.get("pid") == e.pid and pg.g.has_edge(n.id, net, "connected"):
                pg.add_edge(Edge(src=n.id, dst=net, relation="connected", status=C,
                                 signals={"memory_socket": e.attrs.get("state")}, evidence=[e.event_id]))
                log.append({"process": n.id, "network": net, "source": "memory", "verdict": "agree"})
    return log, findings
