"""Command-line interface.

  ptir init CASE --name NAME [--envelope envelope.json]
  ptir add CASE FILE_OR_DIR --kind KIND          (ptir kinds lists them)
  ptir add-run RUN_DIR [--case CASE] [--scenario S.json]
  ptir kinds
  ptir import-adfir CASE PACKAGE_DIR [--force]
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

    p = sub.add_parser("add", help="preserve and hash an evidence file (or every file in a directory)")
    p.add_argument("case"); p.add_argument("file"); p.add_argument("--kind", required=True)

    p = sub.add_parser("add-run", help="create/extend a case from a lab run folder")
    p.add_argument("run_dir")
    p.add_argument("--case", help="case directory (default: RUN_DIR/case)")
    p.add_argument("--scenario", help="scenario file for the envelope (default: RUN_DIR/scenario.json)")
    p.add_argument("--name")
    p.add_argument("--dry-run", action="store_true", help="show what would be added")

    sub.add_parser("kinds", help="list evidence kinds")

    p = sub.add_parser("import-adfir", help="verify an AgentDFIR package and import its agent transcripts")
    p.add_argument("case"); p.add_argument("package")
    p.add_argument("--force", action="store_true", help="import even if SHA256SUMS verification fails")

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
        from .parsers import KNOWN_KINDS
        if a.kind not in KNOWN_KINDS:
            print(f"unknown kind '{a.kind}'. Run `ptir kinds` to list them.", file=sys.stderr)
            return 2
        c = Case(a.case)
        if Path(a.file).is_dir():
            digests = c.add_evidence_dir(a.file, a.kind)
            print(f"{a.kind}: {len(digests)} files from {a.file}")
        else:
            print(f"{a.kind}: {c.add_evidence(a.file, a.kind)}")
    elif a.cmd == "add-run":
        from .runs import add_run, plan
        case_dir = a.case or str(Path(a.run_dir) / "case")
        if a.dry_run:
            for f, k in plan(a.run_dir):
                print(f"{k:15} {f}")
            return 0
        _, added = add_run(case_dir, a.run_dir, a.scenario, a.name)
        for f, k, d in added:
            print(f"{k:15} {d[:12]}  {Path(f).relative_to(a.run_dir).as_posix()}")
        print(f"{len(added)} files added to {case_dir}")
    elif a.cmd == "import-adfir":
        from .adfir import PackageError, import_package
        try:
            res = import_package(Case(a.case), a.package, a.force)
        except PackageError as e:
            print(e, file=sys.stderr)
            return 1
        for p_ in res["verification_problems"]:
            print(f"WARNING {p_}")
        for it in res["imported"]:
            print(f"claude_code     {it['artifact_id'][:12]}  {it['logical_path']}")
        for it in res["unreadable"]:
            print(f"UNREADABLE      {it['artifact_id'][:12]}  {it['logical_path']}: {it['error']}")
        for k, n in res["skipped_by_product"].items():
            print(f"skipped         {n} artifact(s) of {k} (no parser yet)")
        print(f"{len(res['imported'])} transcript(s) imported from AgentDFIR case {res['adfir_case_id']}")
    elif a.cmd == "kinds":
        from .parsers import PARSERS, PRESERVE_ONLY
        for k in sorted(PARSERS):
            print(f"{k:16} parsed")
        for k, desc in sorted(PRESERVE_ONLY.items()):
            print(f"{k:16} preserved only: {desc}")
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
