"""OpenTelemetry trace parser for agents instrumented with the GenAI semantic conventions.

Input: OTLP/JSON, either one document ({"resourceSpans": [...]}) or one document per line
(the OpenTelemetry Collector `file` exporter). Spans are mapped by gen_ai.operation.name:

  invoke_agent / first span of a trace -> session_start   (pid from resource process.pid)
  chat / text_completion / generate_content -> model_call (input_fragments = fragments so far)
  execute_tool                          -> tool_call at span start, tool_result at span end,
                                           context fragments from the tool result
  first user message seen               -> user_prompt

Attributes read (GenAI semconv, still "Development" status, so older names are accepted too):
  gen_ai.operation.name, gen_ai.conversation.id, gen_ai.request.model, gen_ai.agent.name,
  gen_ai.input.messages, gen_ai.tool.name, gen_ai.tool.call.id,
  gen_ai.tool.call.arguments | gen_ai.tool.arguments | input.value,
  gen_ai.tool.call.result | output.value,
  gen_ai.prompt.N.role / gen_ai.prompt.N.content (OpenLLMetry)
  resource: process.pid, process.executable.path, process.owner, host.name, service.name

PromptTracIR extension: an instrumented tool span may set ptir.child_pid and
ptir.child_process_guid. With them, tool-call-to-process links can be corroborated by
Sysmon, exactly as with the lab harness.

Content attributes are opt-in in most instrumentations: without them the trace still
gives tool names and timing, but no fragments for traceback.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import CanonicalEvent
from .agent_trace import events_from_records, split_fragments

PARSER = "otel_trace"
CHAT_OPS = {"chat", "text_completion", "generate_content"}
READ_TOOLS = {"read_file", "read", "file_read"}
WRITE_TOOLS = {"write_file", "write", "edit", "file_write"}
FETCH_TOOLS = {"http_get", "web_fetch", "webfetch", "fetch"}
ORDER = {"session_start": 0, "user_prompt": 1, "model_call": 2, "tool_call": 3, "tool_result": 4,
         "context_fragment": 5}


def _value(v: dict):
    if not isinstance(v, dict):
        return v
    for k in ("stringValue", "boolValue", "doubleValue"):
        if k in v:
            return v[k]
    if "intValue" in v:
        return int(v["intValue"])
    if "arrayValue" in v:
        return [_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {kv["key"]: _value(kv.get("value")) for kv in v["kvlistValue"].get("values", [])}
    if "bytesValue" in v:
        return v["bytesValue"]
    return None


def _attrs(items) -> dict:
    return {a["key"]: _value(a.get("value")) for a in items or []}


def _ts(nanos) -> str:
    return datetime.fromtimestamp(int(nanos) / 1e9, tz=timezone.utc).isoformat()


def _json(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v
    return v


def _operation(name: str, a: dict) -> str:
    op = a.get("gen_ai.operation.name") or a.get("llm.request.type")
    if op:
        return str(op)
    first = (name or "").split(" ")[0].split(".")[-1]
    return first


def _first_user_text(a: dict) -> str | None:
    msgs = _json(a.get("gen_ai.input.messages"))
    if isinstance(msgs, list):
        for m in msgs:
            if isinstance(m, dict) and m.get("role") == "user":
                parts = m.get("parts") or m.get("content") or []
                if isinstance(parts, str):
                    return parts
                texts = [p.get("content") or p.get("text") for p in parts
                         if isinstance(p, dict) and p.get("type") == "text"]
                if texts:
                    return "\n".join(t for t in texts if t)
    i = 0
    while f"gen_ai.prompt.{i}.role" in a:                        # OpenLLMetry
        if a[f"gen_ai.prompt.{i}.role"] == "user":
            return a.get(f"gen_ai.prompt.{i}.content")
        i += 1
    return None


def _documents(path: Path) -> Iterator[tuple[int, dict]]:
    text = path.read_text(encoding="utf-8-sig")
    try:
        yield 1, json.loads(text)
        return
    except json.JSONDecodeError:
        pass
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip():
            yield lineno, json.loads(line)


def convert(path: Path) -> Iterator[tuple[str, str, dict]]:
    spans = []
    for lineno, doc in _documents(Path(path)):
        for rs in doc.get("resourceSpans", []):
            res = _attrs((rs.get("resource") or {}).get("attributes"))
            for ss in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []):
                for sp in ss.get("spans", []):
                    spans.append((lineno, res, sp, _attrs(sp.get("attributes"))))
    spans.sort(key=lambda x: int(x[2]["startTimeUnixNano"]))

    by_trace: dict[str, list] = {}
    for item in spans:
        by_trace.setdefault(item[2]["traceId"], []).append(item)

    out: list[tuple[int, int, str, dict]] = []    # (ts nanos, order, locator, record)
    for trace_id, items in by_trace.items():
        conv = next((a.get("gen_ai.conversation.id") for _, _, _, a in items if a.get("gen_ai.conversation.id")),
                    None)
        sid = str(conv or f"otel-{trace_id[:16]}")
        root = next((x for x in items if _operation(x[2].get("name", ""), x[3]) == "invoke_agent"), items[0])
        lineno, res, sp, a = root
        first_model = next((x[3].get("gen_ai.request.model") for x in items if x[3].get("gen_ai.request.model")),
                           None)
        t0 = int(items[0][2]["startTimeUnixNano"])
        out.append((t0, 0, f"line:{lineno}/span:{sp['spanId']}", {
            "type": "session_start", "session_id": sid, "agent": a.get("gen_ai.agent.name") or res.get("service.name"),
            "model": first_model, "pid": res.get("process.pid"), "image": res.get("process.executable.path"),
            "host": res.get("host.name"), "user": res.get("process.owner")}))

        prompted = False
        chats: list[tuple[int, str]] = []
        for lineno, res, sp, a in items:
            op = _operation(sp.get("name", ""), a)
            start, end = int(sp["startTimeUnixNano"]), int(sp.get("endTimeUnixNano") or sp["startTimeUnixNano"])
            loc = f"line:{lineno}/span:{sp['spanId']}"
            if not prompted:
                text = _first_user_text(a)
                if text:
                    prompted = True
                    out.append((start, 1, loc, {"type": "user_prompt", "session_id": sid,
                                                "span_id": sp["spanId"], "text": text}))
            if op in CHAT_OPS:
                chats.append((start, sp["spanId"]))
                out.append((start, 2, loc, {"type": "model_call", "session_id": sid,
                                            "model_call_id": sp["spanId"], "input_fragments": None}))
            elif op == "execute_tool":
                tcid = str(a.get("gen_ai.tool.call.id") or sp["spanId"])
                tool = a.get("gen_ai.tool.name") or sp.get("name", "").replace("execute_tool", "").strip() or "tool"
                args = _json(a.get("gen_ai.tool.call.arguments") or a.get("gen_ai.tool.arguments")
                             or a.get("input.value") or {})
                if not isinstance(args, dict):
                    args = {"_raw": args}
                parent_chat = max((c for c in chats if c[0] <= start), default=(0, None))[1]
                out.append((start, 3, loc, {"type": "tool_call", "session_id": sid, "tool_call_id": tcid,
                                            "model_call_id": parent_chat, "tool": tool, "args": args}))
                result = a.get("gen_ai.tool.call.result") or a.get("output.value")
                text = result if isinstance(result, str) else (json.dumps(result) if result is not None else "")
                r = {"type": "tool_result", "session_id": sid, "tool_call_id": tcid,
                     "output_preview": text[:500], "child_pid": a.get("ptir.child_pid"),
                     "child_process_guid": a.get("ptir.child_process_guid")}
                path = args.get("path") or args.get("file_path")
                if tool.lower() in READ_TOOLS and path:
                    r["files_read"] = [{"path": path}]
                if tool.lower() in WRITE_TOOLS and path:
                    r["files_written"] = [path]
                if tool.lower() in FETCH_TOOLS and args.get("url"):
                    r["urls"] = [args["url"]]
                if (sp.get("status") or {}).get("code") in (2, "STATUS_CODE_ERROR"):
                    r["error"] = (sp.get("status") or {}).get("message") or "error"
                out.append((end, 4, loc, r))
                if text:
                    src = {"kind": tool, "uri": args.get("url") or args.get("path") or args.get("command") or tool,
                           "sha256": hashlib.sha256(text.encode()).hexdigest()}
                    src["text_sha256"] = src["sha256"]
                    for j, part in enumerate(split_fragments(text)):
                        out.append((end, 5, loc, {"type": "context_fragment", "session_id": sid,
                                                  "fragment_id": f"{tcid}-{j}", "tool_call_id": tcid,
                                                  "index": j, "text": part, "source": src}))

    out.sort(key=lambda x: (x[0], x[1]))
    seen: dict[str, list[str]] = {}
    for n, (nanos, _, loc, rec) in enumerate(out, 1):
        sid = rec["session_id"]
        if rec["type"] == "context_fragment":
            seen.setdefault(sid, []).append(rec["fragment_id"])
        if rec["type"] == "model_call":
            rec["input_fragments"] = list(seen.get(sid, []))
        rec["ts"] = _ts(nanos)
        yield f"{n:07d}", loc, rec


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    yield from events_from_records(convert(Path(path)), evidence_id, PARSER, "otel")
