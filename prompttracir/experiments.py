"""v0.8 evaluation release: freeze the dataset and settings, then regenerate every results table.

    ptir freeze RUNS --out configs/frozen-runs.json     # once, when the dataset is final
    ptir experiments RUNS --out RESULTS_DIR             # Table III, baselines, ablations, ...

`freeze` records, per run, the ground truth (hashed as canonical JSON, so line endings do not
matter), the SHA-256 of every preserved evidence file, the scenario family and the agent class,
plus the settings that produce the results (attribution config fingerprint, summary prompt
version, pinned local model, localizer). `experiments` checks the runs and settings against that
file and reports any difference before it scores anything.

`experiments` scores the analysis already in each run's case/output/ (the full system, with the
local-model summaries written by `ptir explain`), then re-analyses every run once per baseline
and ablation into case/output/<tag>/ (the full analysis is never touched) and scores those. It
writes OUT/RESULTS.md (the tables), OUT/experiments.json (every aggregate) and, per condition,
OUT/<condition>/results.json and per_run.csv. RESULTS.md holds no dates or paths, so running it
again on the frozen runs must give the same file.

Splits and groups (ROADMAP section 5):
  training families  legitimate, data_transmission, persistence (prompts and weights tuned here)
  test families      file_change, download (never tuned on)
  agent classes      real local model, scripted model (host-side metrics only), Claude Code
Tampered copies count only for tamper detection, as in eval-batch.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .batch import aggregate, evaluate_runs, find_runs, write_report
from .case import Case
from .evaluate import run_conditions
from .parsers import KNOWN_KINDS

TRAINING = ["legitimate", "data_transmission", "persistence"]
TEST = ["file_change", "download"]
TRACE_KINDS = {"agent_trace", "agent_requests", "agent_sources", "claude_code", "otel_trace", "adfir_meta"}
MEMORY_KINDS = ["memory_image", "vol_cmdline", "vol_netscan", "vol_pslist"]
NETWORK_KINDS = ["pcap", "zeek_conn", "zeek_dns", "zeek_http"]

# key, group, label, evaluate_runs arguments (None: the analysis already in case/output/)
CONDITIONS = [
    ("full", "full", "Full system (all evidence)", None),
    ("trace-only", "baseline", "Trace only (agent-side records, as AgentDFIR uses)",
     {"without": sorted(KNOWN_KINDS - TRACE_KINDS), "tag": "baseline-trace-only"}),
    ("endpoint-only", "baseline", "Endpoint only (host evidence, no agent trace)",
     {"without": sorted(TRACE_KINDS), "tag": "baseline-endpoint-only"}),
    ("timestamp-only", "baseline", "Timestamp only (time-window links and attribution)",
     {"ablate": ["timestamp_links"], "tag": "baseline-timestamp-only"}),
    ("cue-v01", "baseline", "Cue-only localizer, frozen v0.1 cues", {"localizer": "heuristic-v01"}),
    ("cue", "baseline", "Cue-only localizer, current cues", {"localizer": "heuristic"}),
    ("no-pids", "ablation", "Without PID capture", {"ablate": ["pids"]}),
    ("no-context-ids", "ablation", "Without context identifiers", {"ablate": ["context_ids"]}),
    ("no-memory", "ablation", "Without memory (Volatility)", {"without": MEMORY_KINDS}),
    ("no-network", "ablation", "Without network evidence (Zeek, PCAP)", {"without": NETWORK_KINDS}),
    ("no-sysmon", "ablation", "Without Sysmon", {"without": ["sysmon"]}),
    ("no-local-model", "ablation", "Without local-model analysis", "derived"),
]


# ---------------------------------------------------------------- freeze

def canonical_sha256(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def agent_class(gt: dict, graph: dict | None) -> str:
    if gt.get("trace_format") == "claude_code":
        return "claude_code"
    return "scripted" if run_conditions(graph or {}).get("scripted") else "real_local"


def settings() -> dict:
    from . import config as config_mod
    from .llm import PROMPT_VERSION
    pin_path = Path(__file__).resolve().parents[1] / "configs" / "local-model.json"
    pin = json.loads(pin_path.read_text()) if pin_path.exists() else {}
    return {"config_fingerprint": config_mod.fingerprint(config_mod.load()),
            "prompt_version": PROMPT_VERSION,
            "model": " ".join(str(x) for x in ((pin.get("model") or {}).get("name"),
                                                 (pin.get("model") or {}).get("quantisation")) if x) or None,
            "model_pin_sha256": canonical_sha256(pin_path) if pin_path.exists() else None,
            "localizer": "auto (segment without a replayer)"}


def run_record(run: Path, case_name: str = "case") -> dict:
    gt = json.loads((run / "ground_truth.json").read_text(encoding="utf-8-sig"))
    case = Case(run / case_name)
    return {"run": run.name, "family": gt.get("family"), "scenario": gt.get("scenario"),
            "agent": agent_class(gt, case.read_output("graph.json")),
            "reviewed": bool(gt.get("reviewed")), "tampered": bool(gt.get("tampered")),
            "ground_truth_sha256": canonical_sha256(run / "ground_truth.json"),
            "evidence": sorted(case.meta["evidence"])}


def freeze(root: str | Path, case_name: str = "case") -> dict:
    runs = find_runs(root, case_name)
    return {"frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "prompttracir": __version__, "settings": settings(),
            "runs": [run_record(r, case_name) for r in runs]}


def check_freeze(root: str | Path, frozen: dict, case_name: str = "case") -> list[str]:
    """Differences between the runs and settings now and the freeze (empty list: identical)."""
    problems = []
    now = {r["run"]: r for r in (run_record(p, case_name) for p in find_runs(root, case_name))}
    then = {r["run"]: r for r in frozen.get("runs", [])}
    for name in sorted(set(then) - set(now)):
        problems.append(f"{name}: frozen run is missing")
    for name in sorted(set(now) - set(then)):
        problems.append(f"{name}: run is not in the freeze")
    for name in sorted(set(now) & set(then)):
        a, b = then[name], now[name]
        if a["ground_truth_sha256"] != b["ground_truth_sha256"]:
            problems.append(f"{name}: ground truth changed since the freeze")
        if a["evidence"] != b["evidence"]:
            problems.append(f"{name}: evidence set changed since the freeze")
    cur = settings()
    for k, v in (frozen.get("settings") or {}).items():
        if cur.get(k) != v:
            problems.append(f"setting {k}: {cur.get(k)!r} now, {v!r} when frozen")
    return problems


# ---------------------------------------------------------------- experiments

def _subset(results: list[dict], pred) -> dict:
    sel = [r for r in results if pred(r)]
    return aggregate(sel) if sel else {"runs": 0}


def groups_of(report: dict) -> dict:
    per = report["per_run"]
    cls = {r["_run"]: agent_class(r["_gt"], {"nodes": [{"kind": "session", "attrs": {
        "model": (r.get("run_conditions") or {}).get("model")}}]}) for r in per}
    fam = lambda r: r["_gt"].get("family")          # noqa: E731
    return {"all": report["overall"],
            "training": _subset(per, lambda r: fam(r) in TRAINING),
            "test": _subset(per, lambda r: fam(r) in TEST),
            "real_local": _subset(per, lambda r: cls[r["_run"]] == "real_local"),
            "scripted": _subset(per, lambda r: cls[r["_run"]] == "scripted"),
            "claude_code": _subset(per, lambda r: cls[r["_run"]] == "claude_code")}


def run_experiments(root: str | Path, out: str | Path, case_name: str = "case",
                    only: list[str] | None = None, progress=print) -> dict:
    runs = find_runs(root, case_name)
    out = Path(out)
    reports, summary = {}, {}
    for key, group, label, kwargs in CONDITIONS:
        if only and key not in only and key != "full":
            continue
        if kwargs == "derived":
            continue
        progress(f"[{key}] {label}")
        rep = evaluate_runs(runs, case_name, reviewed_only=True, **(kwargs or {}))
        write_report(rep, out / key)
        reports[key] = rep
        summary[key] = {"group": group, "label": label, "condition": rep["condition"],
                        "skipped": rep["skipped"], "groups": groups_of(rep)}
        abl = [a for a in (kwargs or {}).get("ablate", []) if a != "timestamp_links"]
        if abl:
            changed, total = trace_changes(runs, abl, case_name)
            summary[key]["note"] = (f"{changed} of {total} agent-trace events changed by the ablation "
                                    "in the scored runs.")
    if "full" in summary and (not only or "no-local-model" in only):
        derived = json.loads(json.dumps(summary["full"]))
        for g in derived["groups"].values():
            if "narrative" in g:
                g["narrative"] = {"runs": 0, "sentences": 0, "unsupported_before": None}
        derived.update(group="ablation", label="Without local-model analysis",
                       note="identical to the full system except the narrative row: every other "
                            "metric is computed without the local model (segment localizer).")
        summary["no-local-model"] = derived
    dataset = dataset_counts(reports["full"]) if "full" in reports else {}
    result = {"prompttracir": __version__, "settings": settings(), "dataset": dataset,
              "conditions": summary}
    (out / "experiments.json").write_text(json.dumps(result, indent=2, default=str))
    (out / "RESULTS.md").write_text(render(result))
    return result


def trace_changes(runs: list[Path], ablate: list[str], case_name: str = "case") -> tuple[int, int]:
    """How many agent-trace events an in-trace ablation actually changes (a zero means the runs
    carry no information the ablation could remove)."""
    from . import ablation
    names = ablation.check(ablate)
    changed = total = 0
    for run in runs:
        gt = json.loads((run / "ground_truth.json").read_text(encoding="utf-8-sig"))
        if not gt.get("reviewed") or gt.get("tampered"):
            continue
        events = [e for e in Case(run / case_name).load_events() if ablation._is_trace(e)]
        after = ablation.apply(events, names)
        total += len(events)
        changed += sum(a.model_dump(exclude={"raw"}) != b.model_dump(exclude={"raw"}) for a, b in zip(events, after))
    return changed, total


def dataset_counts(full: dict) -> dict:
    counts: dict[str, dict[str, int]] = {}
    tampered = 0
    for r in full["per_run"]:
        if (r.get("tamper_detection") or {}).get("tampered"):
            tampered += 1
            continue
        gt = r["_gt"]
        cls = agent_class(gt, {"nodes": [{"kind": "session", "attrs": {
            "model": (r.get("run_conditions") or {}).get("model")}}]})
        if not gt.get("injection_present", bool(gt.get("injected_fragments"))):
            outcome = "legitimate"
        elif gt.get("injection_followed") is False:
            outcome = "injection_ignored"
        else:
            outcome = gt.get("family") or "unknown"
        counts.setdefault(outcome, {}).setdefault(cls, 0)
        counts[outcome][cls] += 1
    return {"by_outcome": counts, "scored_runs": sum(sum(v.values()) for v in counts.values()),
            "tampered_copies": tampered}


# ---------------------------------------------------------------- rendering

def _f(x, nd=3) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, bool):
        return "yes" if x else "no"
    if isinstance(x, float):
        t = f"{x:.{nd}f}".rstrip("0")
        return t + "0" if t.endswith(".") else t
    return str(x)


def _get(agg: dict, *path):
    cur = agg
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def metrics(agg: dict) -> dict:
    """The numbers the tables show, from one aggregate (None when nothing was scorable)."""
    if not agg or not agg.get("runs"):
        return {}
    links = agg.get("tool_process_links") or {}
    narr = agg.get("narrative") or {}
    att = agg.get("attribution") or {}
    attc = agg.get("attribution_complete_evidence") or {}
    return {
        "runs": agg.get("runs"),
        "link_precision": links.get("precision") if links.get("pred") else None,
        "link_recall": links.get("recall") if links.get("gold") else None,
        "links_pred_gold": f"{links.get('tp', 0)}/{links.get('pred', 0)}/{links.get('gold', 0)}",
        "attribution_f1": att.get("macro_f1") if att.get("rows") else None,
        "attribution_f1_complete": attc.get("macro_f1") if attc.get("rows") else None,
        "abstention": att.get("abstention_rate") if att.get("rows") else None,
        "localization_f1": _get(agg, "injected_fragment_localization_successful", "f1"),
        "span_f1": _get(agg, "injected_span_localization_successful", "f1"),
        "malicious_f1": _get(agg, "malicious_tool_calls", "f1"),
        "first_deviation": agg.get("first_deviation_accuracy"),
        "chain_edge_f1": _get(agg, "chain_edges", "f1"),
        "chain_edge_f1_complete": _get(agg, "chain_edges_complete_evidence", "f1"),
        "chain_node_f1": _get(agg, "chain_nodes", "f1"),
        "path_exact": agg.get("path_exact_match"),
        "impact_accuracy": agg.get("impact_accuracy"),
        "connection_only_confirmed": agg.get("connection_only_labelled_confirmed"),
        "clean_flagged": f"{agg.get('clean_runs_with_findings', 0)} of {agg.get('clean_runs', 0)}",
        "tamper": f"{agg.get('tampering_detected', 0)} of {agg.get('tampered_runs', 0)}",
        "contradictions": agg.get("contradictions_on_untampered_runs"),
        "narrative_before": narr.get("unsupported_before"),
        "narrative_sentences": narr.get("sentences") if narr.get("runs") else None,
        "narrative_summaries": narr.get("runs") or None,
        "narrative_after": narr.get("unsupported_after"),
        "verdicts": narr.get("classification_accuracy"),
    }


def _sentences(m: dict) -> str:
    return "n/a" if not m.get("narrative_summaries") else f"{m['narrative_sentences']} in {m['narrative_summaries']}"


TABLE_III = [
    # label, criterion, metric key, group used for "met", test
    ("Tool-to-process correlation", "precision >= 0.95 with ProcessGuid or child PID", "link_precision", "all",
     lambda v: v is not None and v >= 0.95),
    ("Human-agent attribution", "macro-F1 >= 0.85 on complete evidence", "attribution_f1_complete", "all",
     lambda v: v is not None and v >= 0.85),
    ("Injected-span localization", "F1 >= 0.80 on successful injections", "localization_f1", "all",
     lambda v: v is not None and v >= 0.80),
    ("Attack-chain reconstruction", "edge F1 >= 0.85 on complete evidence", "chain_edge_f1_complete", "all",
     lambda v: v is not None and v >= 0.85),
    ("Impact assessment", "no connection-only case labelled confirmed", "connection_only_confirmed", "all",
     lambda v: v == 0),
    ("Narrative grounding", "<= 5% unsupported before validation (training split)", "narrative_before",
     "training", lambda v: v is not None and v <= 0.05),
    ("Narrative grounding", "zero unsupported after validation", "narrative_after", "all",
     lambda v: v == 0),
]
GROUP_COLS = [("all", "All runs"), ("training", "Training families"), ("test", "Test families"),
              ("real_local", "Real local model"), ("scripted", "Scripted model"), ("claude_code", "Claude Code")]
COMPARE_COLS = [
    ("link_precision", "Link P"), ("link_recall", "Link R"), ("attribution_f1", "Attrib. F1"),
    ("localization_f1", "Loc. F1"), ("span_f1", "Span F1"), ("malicious_f1", "Malicious F1"),
    ("first_deviation", "First dev."), ("chain_edge_f1", "Chain edge F1"), ("path_exact", "Path exact"),
    ("impact_accuracy", "Impact acc."), ("clean_flagged", "Clean runs flagged"), ("tamper", "Tamper det."),
    ("contradictions", "Contradictions (untampered)"),
]


def _table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def render(result: dict) -> str:
    conds = result["conditions"]
    full = {g: metrics(a) for g, a in conds["full"]["groups"].items()} if "full" in conds else {}
    s = result["settings"]
    lines = ["# PromptTracIR results (v0.8)", "",
             "Generated by `ptir experiments` from the frozen runs. Do not edit by hand: run it again.", "",
             f"Settings: attribution config `{s['config_fingerprint']}`, summary prompt `{s['prompt_version']}`, "
             f"local model `{s['model']}`, localizer {s['localizer']}. Narrative figures come from the "
             "summaries stored in each run (`ptir explain`).", ""]
    ds = result.get("dataset") or {}
    if ds:
        classes = ["real_local", "scripted", "claude_code"]
        order = ["legitimate", "injection_ignored", "data_transmission", "persistence", "file_change", "download"]
        outcomes = [o for o in order if o in ds["by_outcome"]] + sorted(set(ds["by_outcome"]) - set(order))
        rows = [[o.replace("_", " ")] + [str(ds["by_outcome"][o].get(c, 0)) for c in classes]
                + [str(sum(ds["by_outcome"][o].values()))] for o in outcomes]
        rows.append(["**total**"] + [str(sum(ds["by_outcome"][o].get(c, 0) for o in outcomes)) for c in classes]
                    + [str(ds["scored_runs"])])
        lines += ["## Dataset", "",
                  f"{ds['scored_runs']} scored runs by outcome (the 30 planned slots and the extra runs in "
                  f"docs/DATASET_PROGRESS.md), plus {ds['tampered_copies']} tampered copies scored for tamper "
                  "detection only.", "",
                  _table(["Outcome", "Real local", "Scripted", "Claude Code", "Total"], rows), ""]
    if full:
        rows = []
        for label, crit, key, grp, ok in TABLE_III:
            v = full.get(grp, {}).get(key)
            rows.append([label, crit] + [_f(full.get(g, {}).get(key)) for g, _ in GROUP_COLS]
                        + ["**met**" if ok(v) else "**missed**"])
        rows.append(["Analyst utility", "faster than the Plaso / Timesketch baseline"] + ["not measured"] * len(GROUP_COLS)
                    + ["**not measured** (study cut, ROADMAP section 6)"])
        lines += ["## Table III", "",
                  "Met / missed is judged on the column the criterion names (all runs, or the training split "
                  "for the narrative). Scripted-model runs measure the host side only; real-model "
                  "localization rests on the real-local column.", "",
                  _table(["Target", "Criterion"] + [c for _, c in GROUP_COLS] + ["Result"], rows), ""]
        extra = [["Impact accuracy (per destination)"] + [_f(full.get(g, {}).get("impact_accuracy")) for g, _ in GROUP_COLS],
                 ["First-deviation accuracy"] + [_f(full.get(g, {}).get("first_deviation")) for g, _ in GROUP_COLS],
                 ["Malicious tool-call F1"] + [_f(full.get(g, {}).get("malicious_f1")) for g, _ in GROUP_COLS],
                 ["Span overlap F1 (characters)"] + [_f(full.get(g, {}).get("span_f1")) for g, _ in GROUP_COLS],
                 ["Chain node F1 / path exact match"] + [f"{_f(full.get(g, {}).get('chain_node_f1'))} / "
                                                          f"{_f(full.get(g, {}).get('path_exact'))}" for g, _ in GROUP_COLS],
                 ["Attribution abstention"] + [_f(full.get(g, {}).get("abstention")) for g, _ in GROUP_COLS],
                 ["Clean runs with any finding"] + [full.get(g, {}).get("clean_flagged", "n/a") for g, _ in GROUP_COLS],
                 ["Tampered traces detected"] + [full.get(g, {}).get("tamper", "n/a") for g, _ in GROUP_COLS],
                 ["Narrative: sentences in summaries"] + [_sentences(full.get(g, {})) for g, _ in GROUP_COLS],
                 ["Local-model call verdicts"] + [_f(full.get(g, {}).get("verdicts")) for g, _ in GROUP_COLS]]
        lines += ["### Supporting figures (full system)", "",
                  _table(["Metric"] + [c for _, c in GROUP_COLS], extra), ""]
    for group, title, intro in [
            ("baseline", "Baselines",
             "Every baseline runs on the same frozen runs (all scored runs). Trace only stands in for "
             "AgentDFIR, which reads the same agent-side records; AgentDFIR itself was not run."),
            ("ablation", "Ablations",
             "Each row removes one input from the full system and re-analyses every run.")]:
        keys = ["full"] + [k for k, g, _, _ in CONDITIONS if g == group and k in conds]
        rows = [[conds[k]["label"]] + [_f(metrics(conds[k]["groups"]["all"]).get(m)) for m, _ in COMPARE_COLS]
                for k in keys]
        lines += [f"## {title}", "", intro, "", _table(["Condition"] + [c for _, c in COMPARE_COLS], rows), ""]
        notes = [f"- {conds[k]['label']}: {conds[k]['note']}" for k in keys if conds[k].get("note")]
        if notes:
            lines += notes + [""]
    if "full" in conds:
        n = {g: metrics(a) for g, a in conds["full"]["groups"].items()}
        rows = [[c, _f(n.get(g, {}).get("narrative_before")), _f(n.get(g, {}).get("narrative_after")),
                 _sentences(n.get(g, {})),
                 _f(n.get(g, {}).get("verdicts"))] for g, c in GROUP_COLS[:3]]
        lines += ["## Narrative grounding (RQ4)", "",
                  _table(["Split", "Unsupported before validation", "After", "Sentences in summaries",
                          "Call verdicts"], rows), ""]
    return "\n".join(lines).rstrip() + "\n"
