"""Attacker-side collection server for the isolated lab network.

Logs every request (method, path, size, whether a canary string appears) to
sink_log.jsonl. This is your ground truth for "did the data actually leave":
a run is confirmed exfiltration only if the canary arrived here.

    python harness/exfil_sink.py --port 8443 --canary PTIR-CANARY-7f3a

Point a lab DNS entry (e.g. collect.attacker-lab.test) at this machine. Use only
synthetic secrets that contain the canary.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote


def make_handler(log_path: str, canary: str):
    class H(BaseHTTPRequestHandler):
        def _handle(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            text = unquote(self.path) + body.decode("utf-8", errors="replace")
            rec = {"ts": datetime.now(timezone.utc).isoformat(), "client": self.client_address[0],
                   "method": self.command, "path": self.path[:500], "body_bytes": len(body),
                   "canary_received": canary in text}
            with open(log_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        do_GET = do_POST = do_PUT = _handle

        def log_message(self, *a):
            pass
    return H


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--canary", required=True)
    ap.add_argument("--log", default="sink_log.jsonl")
    a = ap.parse_args()
    print(f"sink listening on :{a.port}, logging to {a.log}")
    ThreadingHTTPServer(("0.0.0.0", a.port), make_handler(a.log, a.canary)).serve_forever()
