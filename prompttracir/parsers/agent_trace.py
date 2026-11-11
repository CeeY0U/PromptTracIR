"""Parser for the PromptTracIR harness trace format (one JSON object per line).

Record types (all carry "type", "ts" ISO-8601 UTC, "session_id"):

  session_start     {"agent", "model", "pid", "process_guid"?, "image"?, "host"?, "user"?, "scenario_id"?}
  user_prompt       {"span_id", "text"}
  context_fragment  {"fragment_id", "tool_call_id"?, "text", "index",
                     "source": {"kind", "uri", "sha256", "acquired"?, "text_sha256"?,
                                "raw_sha256"?, "raw_size"?}}
  model_call        {"model_call_id", "input_fragments": [...], "request_ref"?}
  tool_call         {"tool_call_id", "model_call_id", "tool", "args"}
  tool_result       {"tool_call_id", "child_pid"?, "child_process_guid"?, "exit_code"?, "output_preview"?,
                     "files_read"?: [...], "files_written"?: [...], "urls"?: [...],
                     "source_raw"?: {"sha256", "size", "path"}, "http"?: {...}}
  source_rendered   {"tool_call_id", "uri", "model_visible_sha256"}   (preserved, not parsed)

Source hashes: raw_sha256 is the bytes as acquired (kept under sources/ by the
harness), text_sha256 the decoded text, and source_rendered the text the model
actually received. Comparing them shows what parsing or truncation changed.

Write an adapter that converts other formats (AgentDFIR, OpenTelemetry) into these
records rather than teaching the rest of the pipeline about each format.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER = "agent_trace"


def _g(v):
    return v.strip("{}").lower() if v else None


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    from . import parse_time

    session_meta: dict[str, dict] = {}
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            t = r["type"]
            sid = r.get("session_id")
            base = dict(
                source=EventSource.AGENT_TRACE,
                timestamp=parse_time(r["ts"]),
                session_id=sid,
                raw=RawRef(evidence_id=evidence_id, locator=f"line:{lineno}", parser=PARSER),
            )
            eid = f"trace:{evidence_id[:12]}:{lineno}"
            if t == "session_start":
                session_meta[sid] = r
                yield CanonicalEvent(
                    event_id=eid, action=Action.SESSION_START, pid=r.get("pid"),
                    process_guid=_g(r.get("process_guid")), host=r.get("host"), user=r.get("user"),
                    image=r.get("image"),
                    attrs={"agent": r.get("agent"), "model": r.get("model"),
                           "scenario_id": r.get("scenario_id")}, **base)
            elif t == "user_prompt":
                yield CanonicalEvent(
                    event_id=eid, action=Action.USER_PROMPT,
                    attrs={"span_id": r.get("span_id"), "text": r["text"]}, **base)
            elif t == "context_fragment":
                yield CanonicalEvent(
                    event_id=eid, action=Action.CONTEXT_FRAGMENT, fragment_id=r["fragment_id"],
                    tool_call_id=r.get("tool_call_id"), object=r.get("source", {}).get("uri"),
                    attrs={"text": r["text"], "source": r.get("source", {}), "index": r.get("index")}, **base)
            elif t == "model_call":
                yield CanonicalEvent(
                    event_id=eid, action=Action.MODEL_CALL, model_call_id=r["model_call_id"],
                    attrs={"input_fragments": r.get("input_fragments", []),
                           "request_ref": r.get("request_ref")}, **base)
            elif t == "tool_call":
                args = r.get("args", {})
                yield CanonicalEvent(
                    event_id=eid, action=Action.TOOL_CALL, tool_call_id=r["tool_call_id"],
                    model_call_id=r.get("model_call_id"),
                    command_line=args.get("command") if isinstance(args, dict) else None,
                    attrs={"tool": r["tool"], "args": args}, **base)
            elif t == "tool_result":
                yield CanonicalEvent(
                    event_id=eid, action=Action.TOOL_RESULT, tool_call_id=r["tool_call_id"],
                    pid=r.get("child_pid"), process_guid=_g(r.get("child_process_guid")),
                    attrs={k: r.get(k) for k in ("exit_code", "output_preview", "files_read",
                                                 "files_written", "urls", "error", "source_raw",
                                                 "http")}, **base)
            # unknown record types are ignored on purpose (forward compatibility)
