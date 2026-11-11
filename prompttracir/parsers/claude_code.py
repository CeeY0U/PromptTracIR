"""Claude Code session transcript parser (~/.claude/projects/<project>/<session>.jsonl).

This is the format AgentDFIR collects for Claude Code (artifact_type agent_session);
`ptir import-adfir` extracts these files from a sealed .adfir package and adds them
with this kind. One JSON object per line:

  {"type": "user", "sessionId", "timestamp", "uuid", "cwd", "version",
   "message": {"role": "user", "content": "text" | [{"type": "tool_result", "tool_use_id", "content", "is_error"?}]}}
  {"type": "assistant", ..., "message": {"id", "model", "content": [{"type": "text"} | {"type": "tool_use", "id", "name", "input"}]}}

Mapping to the trace format:
  first line of a session      -> session_start (no PID: transcripts do not record one)
  user text message            -> user_prompt
  new assistant message.id     -> model_call (input_fragments = all fragments so far)
  tool_use                     -> tool_call (Bash/PowerShell command -> command_line)
  tool_result                  -> tool_result + context fragments (same paragraph split as the harness)

Limits, recorded so the analysis does not over-claim:
  * no child PID or ProcessGuid, so tool-call-to-process links are timing and command
    similarity only (INFERRED, never CORROBORATED);
  * WebFetch results are the summary Claude Code's fetch model produced, not the page;
  * there is no request log, so counterfactual replay needs a surrogate model.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterator

from ..schema import CanonicalEvent
from .agent_trace import events_from_records, split_fragments

PARSER = "claude_code"

FILE_READ_TOOLS = {"read": "file_path", "notebookread": "notebook_path"}
FILE_WRITE_TOOLS = {"write": "file_path", "edit": "file_path", "multiedit": "file_path",
                    "notebookedit": "notebook_path"}


def _text(content) -> str:
    """tool_result / message content as plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
            elif isinstance(c, dict) and c.get("type") == "image":
                parts.append("[image]")
            elif isinstance(c, str):
                parts.append(c)
        return "\n\n".join(parts)
    return "" if content is None else json.dumps(content)


def _source(tool: str, args: dict) -> dict:
    t = tool.lower()
    if t in FILE_READ_TOOLS:
        return {"kind": "file", "uri": args.get(FILE_READ_TOOLS[t])}
    if t == "webfetch":
        return {"kind": "url", "uri": args.get("url"), "note": "summary produced by the fetch model"}
    if t == "websearch":
        return {"kind": "search", "uri": args.get("query")}
    if t in ("bash", "powershell"):
        return {"kind": "command", "uri": args.get("command")}
    if t.startswith("mcp__"):
        return {"kind": "mcp", "uri": tool}
    if t == "task":
        return {"kind": "subagent", "uri": args.get("description") or "task"}
    return {"kind": t, "uri": args.get("path") or args.get("pattern") or tool}


def convert(path: Path) -> Iterator[tuple[str, str, dict]]:
    """Yield (key, locator, trace record) from a Claude Code transcript."""
    sessions: set[str] = set()
    fragments: dict[str, list[str]] = {}
    model_calls: set[str] = set()
    pending: dict[str, dict] = {}            # tool_use_id -> tool name and input
    rows: list[tuple[int, dict]] = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append((lineno, json.loads(line)))
            except json.JSONDecodeError:
                continue                       # torn last line of a live transcript
    models: dict[str, str] = {}              # the session's model, from its first assistant message
    for _, r in rows:
        m = (r.get("message") or {}).get("model") if r.get("type") == "assistant" else None
        if m and r.get("sessionId") and r["sessionId"] not in models:
            models[r["sessionId"]] = m
    for lineno, r in rows:
        ts, sid = r.get("timestamp"), r.get("sessionId")
        if not ts or not sid or r.get("type") not in ("user", "assistant"):
            continue                       # summaries, snapshots, metadata
        sub = 0

        def out(rec: dict, where: str = ""):
            nonlocal sub
            sub += 1
            return (f"{lineno:07d}.{sub:03d}", f"line:{lineno}{where}",
                    {"ts": ts, "session_id": sid, **rec})

        msg = r.get("message") or {}
        if sid not in sessions:
            sessions.add(sid)
            fragments[sid] = []
            yield out({"type": "session_start", "agent": "claude-code", "model": models.get(sid),
                       "cwd": r.get("cwd"), "version": r.get("version")})
        content = msg.get("content")

        if r["type"] == "user":
            if isinstance(content, str) or (isinstance(content, list) and not any(
                    isinstance(c, dict) and c.get("type") == "tool_result" for c in content)):
                if not r.get("isMeta"):
                    yield out({"type": "user_prompt", "span_id": r.get("uuid"), "text": _text(content)})
                continue
            for i, c in enumerate(content):
                if not isinstance(c, dict) or c.get("type") != "tool_result":
                    continue
                tcid = c.get("tool_use_id")
                call = pending.get(tcid, {"tool": "unknown", "args": {}})
                text = _text(c.get("content"))
                tool, args = call["tool"], call["args"]
                res = {"type": "tool_result", "tool_call_id": tcid, "output_preview": text[:500]}
                if c.get("is_error"):
                    res["error"] = text[:500]
                t = tool.lower()
                if t in FILE_READ_TOOLS and args.get(FILE_READ_TOOLS[t]):
                    res["files_read"] = [{"path": args[FILE_READ_TOOLS[t]]}]
                if t in FILE_WRITE_TOOLS and args.get(FILE_WRITE_TOOLS[t]):
                    res["files_written"] = [args[FILE_WRITE_TOOLS[t]]]
                if t == "webfetch" and args.get("url"):
                    res["urls"] = [args["url"]]
                yield out(res, f"/content[{i}]")
                src = _source(tool, args)
                src["sha256"] = src["text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
                for j, part in enumerate(split_fragments(text)):
                    fid = f"{tcid}-{j}"
                    fragments[sid].append(fid)
                    yield out({"type": "context_fragment", "fragment_id": fid, "tool_call_id": tcid,
                               "index": j, "text": part, "source": src}, f"/content[{i}]")

        else:  # assistant
            mcid = msg.get("id") or r.get("uuid")
            if mcid not in model_calls:
                model_calls.add(mcid)
                yield out({"type": "model_call", "model_call_id": mcid,
                           "input_fragments": list(fragments[sid])})
            for i, c in enumerate(content if isinstance(content, list) else []):
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    args = c.get("input") if isinstance(c.get("input"), dict) else {"_raw": c.get("input")}
                    pending[c["id"]] = {"tool": c.get("name", "unknown"), "args": args}
                    yield out({"type": "tool_call", "tool_call_id": c["id"], "model_call_id": mcid,
                               "tool": c.get("name", "unknown"), "args": args}, f"/content[{i}]")


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    yield from events_from_records(convert(Path(path)), evidence_id, PARSER, "cc")
