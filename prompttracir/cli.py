"""Command-line interface.

  ptir init CASE --name NAME [--envelope envelope.json]
  ptir add CASE FILE --kind {agent_trace,agent_requests,sysmon,security,powershell,psreadline,zeek_conn,memory_image,pcap,other}
  ptir ingest CASE
  ptir analyze CASE [--replay-url URL --replay-model M] [--llm-url URL --llm-model M]
  ptir verify CASE
  ptir serve CASE [--port 8000]
  ptir eval CASE GROUND_TRUTH.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .case import Case


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ptir", description="PromptTracIR incident reconstruction")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a case directory")
    p.add_argument("case"); p.add_argument("--name", required=True); p.add_argument("--envelope")

    p = sub.add_parser("add", help="preserve and hash an evidence file")
    p.add_argument("case"); p.add_argument("file"); p.add_argument("--kind", required=True)

    p = sub.add_parser("ingest", help="parse evidence into canonical events")
    p.add_argument("case")

    p = sub.add_parser("analyze", help="correlate, build graph, run rules, traceback, impact")
    p.add_argument("case")
    p.add_argument("--replay-url"); p.add_argument("--replay-model"); p.add_argument("--samples", type=int, default=3)
    p.add_argument("--llm-url"); p.add_argument("--llm-model")

    p = sub.add_parser("verify", help="re-hash preserved evidence")
    p.add_argument("case")

    p = sub.add_parser("serve", help="start the analyst web UI")
    p.add_argument("case"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8000)

    p = sub.add_parser("eval", help="score a case against ground truth")
    p.add_argument("case"); p.add_argument("ground_truth")

    a = ap.parse_args(argv)

    if a.cmd == "init":
        env = json.loads(Path(a.envelope).read_text()) if a.envelope else None
        Case.create(a.case, a.name, env)
        print(f"case created at {a.case}")
    elif a.cmd == "add":
        d = Case(a.case).add_evidence(a.file, a.kind)
        print(f"{a.kind}: {d}")
    elif a.cmd == "ingest":
        from .pipeline import ingest
        for k, n in ingest(Case(a.case)).items():
            print(f"{k}: {n} events")
    elif a.cmd == "analyze":
        from .pipeline import analyze
        replayer = llm = None
        if a.replay_url:
            from .traceback import OpenAICompatReplayer
            replayer = OpenAICompatReplayer(a.replay_url, a.replay_model)
        if a.llm_url:
            from .llm import LocalLLM
            llm = LocalLLM(a.llm_url, a.llm_model or "local")
        print(json.dumps(analyze(Case(a.case), replayer, llm, a.samples), indent=2))
    elif a.cmd == "verify":
        res = Case(a.case).verify_evidence()
        for d, ok in res.items():
            print(f"{'OK  ' if ok else 'FAIL'} {d}")
        return 0 if all(res.values()) else 1
    elif a.cmd == "serve":
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(Case(a.case)), host=a.host, port=a.port)
    elif a.cmd == "eval":
        from .evaluate import evaluate_case
        print(json.dumps(evaluate_case(Case(a.case), json.loads(Path(a.ground_truth).read_text())), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
