"""Command-line interface.

  ptir init CASE --name NAME [--envelope envelope.json]
  ptir add CASE FILE_OR_DIR --kind KIND          (ptir kinds lists them)
  ptir add-run RUN_DIR [--case CASE] [--scenario S.json]
  ptir kinds
  ptir import-adfir CASE PACKAGE_DIR [--force]
  ptir ingest CASE
  ptir analyze CASE [--config FILE] [--without KIND ...] [--tag NAME]
                    [--replay-url URL --replay-model M] [--llm-url URL --llm-model M]
  ptir config                                    (print the default attribution settings)
  ptir verify CASE
  ptir serve CASE [--port 8000]
  ptir eval CASE GROUND_TRUTH.json
  ptir eval-batch ROOT [--out DIR] [--reviewed-only] [--families F,...] [--exclude-families F,...]
                       [--reanalyze] [--config FILE] [--without KIND ...] [--tag NAME]
  ptir explain CASE_OR_ROOT --llm-url URL [--llm-model M] [--tag NAME] [--families F,...] [--timeout S]
  ptir explain CASE_OR_ROOT --revalidate         (v0.7: re-check stored summaries, no model)
  ptir llm-pin                                   (print the pinned local model and server settings)
  ptir export-stix CASE [--out FILE] [--tag NAME] [--validate]   (v0.7: STIX 2.1 bundle, ATLAS/ATT&CK tags)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .case import Case

LOCALIZERS = ["auto", "segment", "heuristic", "heuristic-v01", "replay", "group"]
from .ablation import ABLATIONS  # noqa: E402


CASE_COMMANDS = {"add", "import-adfir", "ingest", "analyze", "verify", "serve", "eval", "export-stix"}


def _msys_hint(path: str) -> str:
    """Git Bash turns an argument like /envelope.json into C:/Program Files/Git/envelope.json."""
    if "Program Files/Git" in path.replace("\\", "/") or path.startswith("/"):
        return " (in Git Bash, write a relative path such as ./envelope.json, not /envelope.json)"
    return ""


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
    p.add_argument("--localizer", default="auto", choices=LOCALIZERS,
                   help="traceback method (default auto: replay with --replay-url, else segment)")
    p.add_argument("--llm-url"); p.add_argument("--llm-model")
    p.add_argument("--config", help="attribution settings JSON (only the keys you change; see `ptir config`)")
    p.add_argument("--without", action="append", metavar="KIND", default=[],
                   help="leave this evidence kind out (ablation); repeat for several")
    p.add_argument("--ablate", action="append", metavar="NAME", default=[], choices=sorted(ABLATIONS),
                   help="v0.8: remove information inside the trace (pids, context_ids) or use the "
                        "timestamp baseline (timestamp_links); repeat for several")
    p.add_argument("--tag", help="write outputs to output/TAG/ instead of output/")

    sub.add_parser("config", help="print the default attribution settings as JSON")

    p = sub.add_parser("verify", help="re-hash preserved evidence")
    p.add_argument("case")

    p = sub.add_parser("serve", help="start the analyst web UI")
    p.add_argument("case"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8000)

    p = sub.add_parser("eval", help="score a case against ground truth")
    p.add_argument("case"); p.add_argument("ground_truth")

    p = sub.add_parser("eval-batch", help="score every analysed run under ROOT and aggregate")
    p.add_argument("root", help="folder of runs: ROOT/<run>/ground_truth.json and ROOT/<run>/case/")
    p.add_argument("--out", help="write results.json and per_run.csv here (default: ROOT/results); "
                                  "an ablation or --tag goes to OUT/<tag>/")
    p.add_argument("--case-name", default="case")
    p.add_argument("--reviewed-only", action="store_true", help="skip runs whose labels were not reviewed")
    p.add_argument("--families", help="only these scenario families (comma-separated), e.g. the training split")
    p.add_argument("--exclude-families", help="skip these scenario families (comma-separated)")
    p.add_argument("--reanalyze", action="store_true", help="analyze every run again before scoring")
    p.add_argument("--config", help="attribution settings for --reanalyze")
    p.add_argument("--without", action="append", metavar="KIND", default=[],
                   help="ablation: leave this evidence kind out when re-analysing; repeat for several")
    p.add_argument("--tag", help="output/TAG/ for the re-analysis (default: derived from --without)")
    p.add_argument("--localizer", choices=LOCALIZERS,
                   help="re-analyse with this traceback method (heuristic-v01: the v0.1 cue-only baseline)")
    p.add_argument("--ablate", action="append", metavar="NAME", default=[], choices=sorted(ABLATIONS),
                   help="v0.8: re-analyse with this ablation (pids, context_ids, timestamp_links)")

    p = sub.add_parser("freeze", help="v0.8: record the runs, their evidence hashes and the settings (dataset freeze)")
    p.add_argument("root", help="folder of runs: ROOT/<run>/ground_truth.json and ROOT/<run>/case/")
    p.add_argument("--out", default="configs/frozen-runs.json", help="manifest to write (default %(default)s)")
    p.add_argument("--case-name", default="case")

    p = sub.add_parser("experiments", help="v0.8: Table III, baselines and ablations from the frozen runs")
    p.add_argument("root", help="folder of runs (the frozen dataset)")
    p.add_argument("--out", help="results folder (default: ROOT/results-v0.8)")
    p.add_argument("--freeze", default="configs/frozen-runs.json",
                   help="manifest from `ptir freeze` to check the runs and settings against (default %(default)s)")
    p.add_argument("--force", action="store_true", help="run even if the runs or settings differ from the freeze")
    p.add_argument("--only", help="comma-separated condition keys (full always runs), e.g. full,no-sysmon")
    p.add_argument("--case-name", default="case")

    p = sub.add_parser("explain", help="local-model verdicts and grounded summary for analysed case(s)")
    p.add_argument("target", help="a case directory, or a folder of runs (ROOT/<run>/case)")
    p.add_argument("--llm-url", help="OpenAI-compatible server, e.g. http://127.0.0.1:8080")
    p.add_argument("--llm-model", default="local")
    p.add_argument("--timeout", type=float, default=1800,
                   help="seconds per model call (a CPU-only summary takes minutes; default 1800)")
    p.add_argument("--revalidate", action="store_true",
                   help="no model: check the stored summaries again with the current validation (v0.7)")
    p.add_argument("--tag", help="explain output/TAG/ instead of output/")
    p.add_argument("--case-name", default="case")
    p.add_argument("--families", help="only runs of these families (comma-separated): the training split")

    sub.add_parser("llm-pin", help="print the pinned local model and server settings (configs/local-model.json)")

    p = sub.add_parser("export-stix", help="write the case as a STIX 2.1 bundle tagged with MITRE ATLAS / ATT&CK")
    p.add_argument("case")
    p.add_argument("--out", help="output file (default: CASE/output/stix_bundle.json)")
    p.add_argument("--tag", help="export output/TAG/ instead of output/")
    p.add_argument("--validate", action="store_true", help="check it with the OASIS validator (pip install stix2-validator)")

    a = ap.parse_args(argv)

    if a.cmd in CASE_COMMANDS and not (Path(a.case) / "case.json").exists():
        print(f"no case at {a.case} (case.json not found). Create one with `ptir init {a.case} --name NAME` "
              f"or `ptir add-run RUN_DIR`.", file=sys.stderr)
        return 2

    if a.cmd == "init":
        env = None
        if a.envelope:
            if not Path(a.envelope).is_file():
                print(f"envelope file not found: {a.envelope}" + _msys_hint(a.envelope), file=sys.stderr)
                return 2
            env = json.loads(Path(a.envelope).read_text(encoding="utf-8-sig"))
        try:
            Case.create(a.case, a.name, env)
        except FileExistsError as e:
            print(e, file=sys.stderr)
            return 2
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
        before = set(Case(case_dir).meta["evidence"]) if (Path(case_dir) / "case.json").exists() else set()
        _, added = add_run(case_dir, a.run_dir, a.scenario, a.name)
        new = [(f, k, d) for f, k, d in added if d not in before]
        for f, k, d in new:
            print(f"{k:15} {d[:12]}  {Path(f).relative_to(a.run_dir).as_posix()}")
        print(f"{len(new)} new file{'' if len(new) == 1 else 's'} added to {case_dir}"
              + (f" ({len(added) - len(new)} already in the case, skipped)" if len(added) > len(new) else ""))
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
        from . import config as config_mod
        try:
            cfg = config_mod.load(a.config)
            from .batch import condition_tag
            res = analyze(Case(a.case), replayer, llm, a.samples, config=cfg, without=a.without,
                          tag=condition_tag(a.without, a.tag, None, a.ablate),
                          localizer=a.localizer, ablate=a.ablate)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        print(json.dumps(res, indent=2))
    elif a.cmd == "explain":
        return _explain(a)
    elif a.cmd == "export-stix":
        from .stix import export_case, validate
        case = Case(a.case)
        bundle = export_case(case, tag=a.tag)
        out = Path(a.out) if a.out else case.root / "output" / (f"{a.tag}/" if a.tag else "") / "stix_bundle.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        kinds = {}
        for o in bundle["objects"]:
            kinds[o["type"]] = kinds.get(o["type"], 0) + 1
        techs = sorted(r["external_id"] for o in bundle["objects"] if o["type"] == "attack-pattern"
                       for r in o["external_references"])
        print(f"wrote {out}: {len(bundle['objects'])} objects {kinds}")
        print(f"techniques: {', '.join(techs) or 'none'}")
        if a.validate:
            ok, msgs = validate(bundle)
            for m in msgs:
                print("  " + m)
            print("STIX 2.1 validator: " + ("valid" if ok else "INVALID"))
            return 0 if ok else 1
    elif a.cmd == "llm-pin":
        from .llm import PIN_FILE, load_pin
        print(f"# {PIN_FILE}")
        print(json.dumps(load_pin(), indent=2))
    elif a.cmd == "config":
        from . import config as config_mod
        print(json.dumps(config_mod.DEFAULTS, indent=2))
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
        if not Path(a.ground_truth).is_file():
            print(f"ground truth not found: {a.ground_truth}" + _msys_hint(a.ground_truth), file=sys.stderr)
            return 2
        gt = json.loads(Path(a.ground_truth).read_text(encoding="utf-8-sig"))
        sc_path = Path(a.ground_truth).parent / "scenario.json"
        payload = None
        if sc_path.exists():
            payload = (json.loads(sc_path.read_text(encoding="utf-8-sig")).get("injection") or {}).get("payload")
        print(json.dumps(evaluate_case(Case(a.case), gt, payload=payload), indent=2))
    elif a.cmd == "freeze":
        from .experiments import freeze
        manifest = freeze(a.root, a.case_name)
        if not manifest["runs"]:
            print(f"no runs under {a.root}", file=sys.stderr)
            return 1
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(manifest, indent=2) + "\n")
        n = len(manifest["runs"])
        print(f"froze {n} runs ({sum(r['tampered'] for r in manifest['runs'])} tampered copies) "
              f"and settings {manifest['settings']} into {a.out}")
    elif a.cmd == "experiments":
        from .experiments import check_freeze, run_experiments
        fz = Path(a.freeze)
        if fz.exists():
            problems = check_freeze(a.root, json.loads(fz.read_text(encoding="utf-8-sig")), a.case_name)
            if problems:
                print(f"differences from {fz}:\n  " + "\n  ".join(problems), file=sys.stderr)
                if not a.force:
                    print("stopping (use --force to run anyway)", file=sys.stderr)
                    return 2
            else:
                print(f"runs and settings match {fz}")
        else:
            print(f"no freeze manifest at {fz}: the runs are not checked (ptir freeze ROOT)", file=sys.stderr)
        out = Path(a.out or Path(a.root) / "results-v0.8")
        only = [x.strip() for x in a.only.split(",")] if a.only else None
        run_experiments(a.root, out, a.case_name, only=only, progress=lambda m: print(m, flush=True))
        print((out / "RESULTS.md").read_text())
        print(f"wrote {out / 'RESULTS.md'}, {out / 'experiments.json'} and one folder per condition")
    elif a.cmd == "eval-batch":
        from .batch import evaluate_runs, find_runs, summary_lines, write_report
        runs = find_runs(a.root, a.case_name)
        if not runs:
            print(f"no runs under {a.root} with ground_truth.json and {a.case_name}/case.json", file=sys.stderr)
            return 1
        from . import config as config_mod
        split = lambda v: [x.strip() for x in v.split(",") if x.strip()] if v else None  # noqa: E731
        try:
            cfg = config_mod.load(a.config) if a.config else None
            report = evaluate_runs(runs, a.case_name, a.reviewed_only, families=split(a.families),
                                   exclude_families=split(a.exclude_families), reanalyze=a.reanalyze,
                                   config=cfg, without=a.without, tag=a.tag, localizer=a.localizer,
                                   ablate=a.ablate)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        tag = report["condition"]["tag"]
        # every condition gets its own folder, also under --out, so an ablation never
        # overwrites the full-evidence results.json
        j, c = write_report(report, Path(a.out or Path(a.root) / "results") / (tag or ""))
        print("\n".join(summary_lines(report)))
        print(f"\nwrote {j} and {c}")
    return 0




def _explain(a) -> int:
    from .batch import find_runs
    from .llm import LocalLLM
    from .pipeline import explain
    target = Path(a.target)
    if (target / "case.json").exists():
        cases = [(target.name, target)]
    else:
        fams = set(a.families.split(",")) if a.families else None
        cases = []
        for run in find_runs(target, a.case_name):
            gt = json.loads((run / "ground_truth.json").read_text(encoding="utf-8-sig"))
            if fams and gt.get("family") not in fams:
                continue
            cases.append((run.name, run / a.case_name))
    if not cases:
        print(f"no analysed case under {target}", file=sys.stderr)
        return 2
    if a.revalidate:
        from .pipeline import revalidate_case
        sent = drop = 0
        for name, c in cases:
            rec = revalidate_case(Case(c), tag=a.tag)
            if rec is None:
                continue
            s, b = rec["summary"], rec["summary_before_revalidation"]
            sent += s["sentences"]
            drop += len(s["dropped"])
            print(f"{name:28} sentences {s['sentences']}  dropped {len(s['dropped'])} (was "
                  f"{b['sentences'] - b['kept'] if b.get('kept') is not None else '?'})  {s['unsupported_by_reason']}")
        if sent:
            print(f"all: {drop} of {sent} sentences unsupported before validation ({drop / sent:.3f}), 0 after")
        return 0
    if not a.llm_url:
        print("--llm-url is required (or --revalidate)", file=sys.stderr)
        return 2
    llm = LocalLLM(a.llm_url, a.llm_model, timeout=a.timeout)
    served = llm.served_model()
    pinned = (llm.pin.get("model") or {}).get("file")
    print(f"server model: {served}   pinned: {pinned}")
    if served and pinned and pinned.lower() not in served.lower():
        print("warning: the server is not running the pinned model file", file=sys.stderr)
    sent = drop = 0
    for name, c in cases:
        try:
            rec = explain(Case(c), llm, tag=a.tag)
        except Exception as e:  # noqa: BLE001 - one failed run (timeout, server error) does not stop the rest
            print(f"{name}: FAILED {e!r}", file=sys.stderr)
            continue
        s = rec.get("summary") or {}
        sent += s.get("sentences", 0)
        drop += len(s.get("dropped") or [])
        print(f"{name:28} calls {len(rec['classifications'])}  sentences {s.get('sentences', 0)}  "
              f"unsupported before {s.get('unsupported_rate_before_validation')}  ({llm.schema_mode})")
    if sent:
        print(f"all: {drop} of {sent} sentences unsupported before validation ({drop / sent:.3f}), 0 after")
    return 0


if __name__ == "__main__":
    sys.exit(main())
