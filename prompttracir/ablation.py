"""Ablations and baselines that change what the analysis may use, not which files it reads (v0.8).

`--without KIND` (pipeline.excluded_evidence) leaves whole evidence kinds out. The conditions here
remove information *inside* the agent trace, or replace the correlation method, so the proposal's
remaining ablations and the timestamp baseline can be measured on the same frozen runs:

  pids             the trace records no runtime or child PIDs and no ProcessGuids (what a trace
                   without process capture, such as a Claude Code transcript, gives). Links fall
                   back to time and command similarity; the runtime is found by image only, and
                   the clock offset cannot be estimated from child PIDs.
  context_ids      the trace records no context identifiers: which fragments were in a model
                   call's context, which tool call returned a fragment, which model call issued a
                   tool call. They are rebuilt from time order within the session (a model call
                   saw every earlier fragment; a fragment came from the last tool result before it;
                   a tool call came from the last model call before it).
  timestamp_links  baseline: each execution tool call is linked to the process that started
                   nearest to it inside its time window, and every process that started inside an
                   agent session is labelled agent, every other one human. No PIDs, ancestry,
                   command lines or human-side artifacts. Implies pids.

Events are copied, never changed in the case.
"""
from __future__ import annotations

from .schema import Action, CanonicalEvent

ABLATIONS = {
    "pids": "trace without runtime / child PIDs and ProcessGuids",
    "context_ids": "trace without context identifiers (rebuilt from time order)",
    "timestamp_links": "baseline: links and attribution from time windows only",
}

TRACE_SOURCES = {"agent_trace", "claude_code", "otel_trace"}


def check(ablate: list[str] | None) -> set[str]:
    names = set(ablate or [])
    unknown = sorted(names - set(ABLATIONS))
    if unknown:
        raise ValueError(f"unknown ablation(s): {', '.join(unknown)} (known: {', '.join(sorted(ABLATIONS))})")
    if "timestamp_links" in names:
        names.add("pids")
    return names


def _is_trace(e: CanonicalEvent) -> bool:
    return getattr(e.source, "value", e.source) in TRACE_SOURCES


def apply(events: list[CanonicalEvent], ablate: set[str]) -> list[CanonicalEvent]:
    if not ablate:
        return events
    out = list(events)
    if "pids" in ablate:
        out = [e.model_copy(update={"pid": None, "process_guid": None})
               if _is_trace(e) and e.action in (Action.SESSION_START, Action.TOOL_RESULT, Action.TOOL_CALL) else e
               for e in out]
    if "context_ids" in ablate:
        out = _rebuild_context(out)
    return out


def _rebuild_context(events: list[CanonicalEvent]) -> list[CanonicalEvent]:
    order = sorted(range(len(events)), key=lambda i: (events[i].ts(), i))
    seen_frags: dict[str, list[str]] = {}
    last_result: dict[str, str] = {}
    last_model: dict[str, str] = {}
    out = list(events)
    for i in order:
        e = events[i]
        if not _is_trace(e):
            continue
        sid = e.session_id or ""
        if e.action == Action.MODEL_CALL:
            attrs = dict(e.attrs)
            attrs["input_fragments"] = list(seen_frags.get(sid, []))
            out[i] = e.model_copy(update={"attrs": attrs})
            if e.model_call_id:
                last_model[sid] = e.model_call_id
        elif e.action == Action.CONTEXT_FRAGMENT:
            out[i] = e.model_copy(update={"tool_call_id": last_result.get(sid)})
            if e.fragment_id:
                seen_frags.setdefault(sid, []).append(e.fragment_id)
        elif e.action == Action.TOOL_CALL:
            out[i] = e.model_copy(update={"model_call_id": last_model.get(sid)})
        elif e.action == Action.TOOL_RESULT and e.tool_call_id:
            last_result[sid] = e.tool_call_id
    return out
