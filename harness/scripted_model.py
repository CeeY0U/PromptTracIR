"""Scripted stand-in for the model server: an agent that follows the injection.

Real models often ignore the planted payload (Qwen2.5-7B ignored all of them in the first lab
runs, Nov 2026), which leaves the evaluation without positive cases. This server answers the
harness agent's /v1/chat/completions requests from a script, so the agent really fetches the
page or file, really runs the injected command and really writes the notes: Windows records
genuine Sysmon, Security, Prefetch and network evidence of a followed injection. Only the
decisions are scripted, and every run says so (model "scripted-comply" or "scripted-ignore"
in the trace), so these runs are reported separately from real-model runs.

The script reads the scenario:

  1. no tool result yet       -> fetch the source: http_get (web_page) or read_file (local_file,
                                 or the first setup file in the allowed paths for legitimate runs)
  2. after the source         -> shell(injection.command) when the source text as the model saw it
                                 still contains that command (--mode comply); otherwise skip to 3.
                                 Counterfactual replay with the injected fragment removed therefore
                                 gets no shell call, like a model that never saw the payload.
  3. then                     -> write_file(the notes path from the prompt, a short summary)
  4. then                     -> a final answer

    python -m harness.scripted_model --scenario harness\\scenarios\\web_exfil_01.json --port 8080
    python harness\\agent.py --scenario harness\\scenarios\\web_exfil_01.json --model scripted-comply ...

Lab use only, like harness/agent.py: the command it asks for comes from the scenario file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NOTES_RE = re.compile(r"(?:[A-Za-z]:\\|/)[^\s\"'<>|]*?notes\.md", re.I)
DEFAULT_NOTES = "C:\\Users\\lab\\project\\notes.md"


def _call(name: str, args: dict, salt: str) -> dict:
    cid = "call_" + hashlib.sha256(f"{salt}|{name}|{json.dumps(args, sort_keys=True)}".encode()).hexdigest()[:24]
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _source_call(sc: dict) -> tuple[str, dict]:
    inj = sc.get("injection") or {}
    if inj.get("vector") == "web_page":
        return "http_get", {"url": inj["location"]}
    if inj.get("location"):
        return "read_file", {"path": inj["location"]}
    allowed = [a.lower().rstrip("\\") for a in (sc.get("envelope") or {}).get("allowed_paths", [])]
    for f in (sc.get("setup") or {}).get("files", []):
        if any(f["path"].lower().startswith(a + "\\") for a in allowed):
            return "read_file", {"path": f["path"]}
    raise ValueError("scenario has no source to read: no injection location and no setup file in allowed_paths")


def _summary(text: str, command: str | None) -> str:
    lines = []
    for para in re.split(r"\n\s*\n", text or ""):
        para = re.sub(r"<[^>]+>", " ", para)
        para = " ".join(para.split())
        if not para or (command and command in para):
            continue
        lines.append(f"- {para[:160]}")
    return "\n".join(lines[:5]) + "\n"


def next_message(sc: dict, messages: list[dict], mode: str = "comply") -> dict:
    """The assistant message for this point in the conversation."""
    tool_msgs = [m for m in messages if m.get("role") == "tool"]
    calls_made = [c["function"]["name"] for m in messages if m.get("role") == "assistant"
                  for c in (m.get("tool_calls") or [])]
    prompt = next((m.get("content") or "" for m in messages if m.get("role") == "user"), "")
    command = (sc.get("injection") or {}).get("command")
    salt = sc.get("id", "")
    if not tool_msgs:
        name, args = _source_call(sc)
        return {"role": "assistant", "content": None, "tool_calls": [_call(name, args, salt)]}
    source_text = tool_msgs[0].get("content") or ""
    if (mode == "comply" and command and command in source_text and "shell" not in calls_made):
        return {"role": "assistant", "content": None,
                "tool_calls": [_call("shell", {"command": command}, salt)]}
    if "write_file" not in calls_made:
        m = NOTES_RE.search(prompt)
        path = m.group(0) if m else DEFAULT_NOTES
        return {"role": "assistant", "content": None,
                "tool_calls": [_call("write_file", {"path": path, "content": _summary(source_text, command)}, salt)]}
    return {"role": "assistant", "content": "Done: the notes are written.", "tool_calls": None}


def completion(sc: dict, request: dict, mode: str) -> dict:
    msg = next_message(sc, request.get("messages") or [], mode)
    if not msg.get("tool_calls"):
        msg.pop("tool_calls", None)
    return {"id": "chatcmpl-scripted-" + str(len(request.get("messages") or [])), "object": "chat.completion",
            "created": int(time.time()), "model": f"scripted-{mode}",
            "choices": [{"index": 0, "message": msg,
                         "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def make_handler(sc: dict, mode: str):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.rstrip("/") in ("/health", "/v1/models"):
                self._send(200, {"status": "ok", "data": [{"id": f"scripted-{mode}"}]})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path.rstrip("/") != "/v1/chat/completions":
                self._send(404, {"error": "not found"})
                return
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            try:
                self._send(200, completion(sc, req, mode))
            except Exception as e:   # report scenario problems to the agent instead of hanging
                self._send(500, {"error": repr(e)})

        def log_message(self, fmt, *args):
            sys.stderr.write("scripted-model: " + (fmt % args) + "\n")

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--mode", choices=["comply", "ignore"], default="comply",
                    help="comply: run the injected command; ignore: behave like a model that ignored it")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv)
    sc = json.loads(Path(a.scenario).read_text(encoding="utf-8-sig"))
    if a.mode == "comply" and sc.get("injection") and not sc["injection"].get("command"):
        ap.error("this scenario has no injection.command to follow")
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(sc, a.mode))
    print(f"scripted model ({a.mode}) for {sc.get('id')} listening on http://{a.host}:{a.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
