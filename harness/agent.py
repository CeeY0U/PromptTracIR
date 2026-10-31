"""Traced evaluation agent for the PromptTracIR lab.

A minimal tool-calling loop against any OpenAI-compatible endpoint (llama.cpp
`llama-server`, vLLM, or Ollama's /v1). It is deliberately small so that every
model request is recorded verbatim and can be replayed for traceback.

Outputs (in --out):
  trace.jsonl     PromptTracIR agent trace (see prompttracir/parsers/agent_trace.py)
  requests.jsonl  full chat request per model call, for counterfactual replay

WARNING: this agent executes shell commands chosen by a language model that is
being fed attacker content on purpose. Run it ONLY inside the isolated lab VM.
It refuses to start unless PTIR_LAB=1 is set.

Swap this loop for LangGraph later if you want; keep the Tracer calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLS = [
    {"type": "function", "function": {"name": "read_file", "description": "Read a text file.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "write_file", "description": "Write a text file.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "list_dir", "description": "List a directory.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "http_get", "description": "Fetch a URL and return its text.",
     "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "shell", "description": "Run a shell command.",
     "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
]
SYSTEM = "You are a helpful assistant that completes the user's task using the available tools."


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Tracer:
    def __init__(self, out: Path, session_id: str):
        out.mkdir(parents=True, exist_ok=True)
        self.trace = open(out / "trace.jsonl", "a", encoding="utf-8")
        self.requests = open(out / "requests.jsonl", "a", encoding="utf-8")
        self.sid = session_id
        self.fragments: list[str] = []

    def emit(self, type_: str, **fields) -> None:
        self.trace.write(json.dumps({"type": type_, "ts": now(), "session_id": self.sid, **fields}) + "\n")
        self.trace.flush()

    def save_request(self, model_call_id: str, request: dict) -> None:
        self.requests.write(json.dumps({"model_call_id": model_call_id, "request": request}) + "\n")
        self.requests.flush()

    def fragments_from(self, tool_call_id: str, text: str, source: dict, max_len: int = 1200) -> str:
        """Split tool output into paragraph fragments, record them, and return the exact
        model-visible text (fragments joined by blank lines) so replay can remove each one."""
        parts = []
        for para in re.split(r"\n\s*\n", text):
            para = para.strip()
            while para:
                parts.append(para[:max_len]); para = para[max_len:]
        for i, p in enumerate(parts):
            fid = f"{tool_call_id}-{i}"
            self.emit("context_fragment", fragment_id=fid, tool_call_id=tool_call_id, index=i, text=p, source=source)
            self.fragments.append(fid)
        return "\n\n".join(parts)


def run_tool(name: str, args: dict, timeout: int) -> tuple[str, dict]:
    """Execute a tool. Returns (output text, extra fields for the tool_result record)."""
    extra: dict = {}
    try:
        if name == "read_file":
            p = Path(args["path"])
            data = p.read_bytes()
            extra["files_read"] = [{"path": str(p.resolve()), "size": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()}]
            return data.decode("utf-8", errors="replace"), extra
        if name == "write_file":
            p = Path(args["path"])
            p.write_text(args.get("content", ""), encoding="utf-8")
            extra["files_written"] = [str(p.resolve())]
            return f"wrote {len(args.get('content', ''))} chars to {p}", extra
        if name == "list_dir":
            return "\n".join(sorted(os.listdir(args["path"]))), extra
        if name == "http_get":
            extra["urls"] = [args["url"]]
            with urllib.request.urlopen(args["url"], timeout=timeout) as r:
                return r.read(200_000).decode("utf-8", errors="replace"), extra
        if name == "shell":
            argv = (["cmd.exe", "/d", "/s", "/c", args["command"]] if platform.system() == "Windows"
                    else ["/bin/sh", "-c", args["command"]])
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    errors="replace")
            extra["child_pid"] = proc.pid          # the key attribution link to Sysmon
            try:
                outp, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill(); outp, _ = proc.communicate()
                extra["error"] = "timeout"
            extra["exit_code"] = proc.returncode
            return outp[-20_000:], extra
        return f"unknown tool {name}", {"error": "unknown_tool"}
    except Exception as e:  # tool errors go back to the model, like a real agent
        extra["error"] = repr(e)
        return f"error: {e!r}", extra


def run(prompt: str, base_url: str, model: str, out: Path, max_steps: int = 10, timeout: int = 60,
        seed: int = 1234) -> str:
    import httpx

    sid = "s-" + uuid.uuid4().hex[:8]
    tr = Tracer(out, sid)
    tr.emit("session_start", agent="ptir-harness", model=model, pid=os.getpid(), host=platform.node(),
            user=os.environ.get("USERNAME") or os.environ.get("USER"))
    tr.emit("user_prompt", span_id="p1", text=prompt)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
    client = httpx.Client(base_url=base_url.rstrip("/"), timeout=600)
    for step in range(1, max_steps + 1):
        mc = f"m{step}"
        request = {"model": model, "messages": messages, "tools": TOOLS, "temperature": 0, "seed": seed}
        tr.save_request(mc, request)
        tr.emit("model_call", model_call_id=mc, input_fragments=list(tr.fragments), request_ref=mc)
        resp = client.post("/v1/chat/completions", json=request)
        resp.raise_for_status()
        msg = resp.json()["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content"), "tool_calls": calls or None})
        if not calls:
            tr.emit("final_answer", model_call_id=mc, text=msg.get("content"))
            return msg.get("content") or ""
        for c in calls:
            tcid = f"t{step}-{c.get('id', uuid.uuid4().hex[:6])}"
            name = c["function"]["name"]
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_raw": c["function"].get("arguments")}
            tr.emit("tool_call", tool_call_id=tcid, model_call_id=mc, tool=name, args=args)
            output, extra = run_tool(name, args, timeout)
            tr.emit("tool_result", tool_call_id=tcid, output_preview=output[:500], **extra)
            # untrusted content returned to the model becomes recorded fragments
            if name in ("read_file", "http_get", "shell", "list_dir"):
                src = {"kind": {"read_file": "file", "http_get": "url"}.get(name, name),
                       "uri": args.get("path") or args.get("url") or args.get("command"),
                       "sha256": hashlib.sha256(output.encode()).hexdigest()}
                output = tr.fragments_from(tcid, output, src)
            messages.append({"role": "tool", "tool_call_id": c.get("id"), "content": output})
    tr.emit("final_answer", text=None, error="max_steps")
    return ""


def main() -> int:
    if os.environ.get("PTIR_LAB") != "1":
        print("Refusing to run: set PTIR_LAB=1 inside the isolated lab VM.", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser()
    ap.add_argument("prompt")
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--model", default="local")
    ap.add_argument("--out", default="run")
    ap.add_argument("--max-steps", type=int, default=10)
    a = ap.parse_args()
    print(run(a.prompt, a.base_url, a.model, Path(a.out), a.max_steps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
