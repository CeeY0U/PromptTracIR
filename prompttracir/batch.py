"""Score many runs at once (`ptir eval-batch`) and aggregate them into report tables.

Layout expected under ROOT (what `ptir add-run` and harness/label_run.py produce):

    ROOT/run01/ground_truth.json
    ROOT/run01/case/            analysed case (ptir ingest + ptir analyze)
    ROOT/run02/...

Aggregation rules:
  * set metrics (fragments, malicious tool calls, tool-process links) are micro-averaged:
    true positives, predictions and gold items are summed over runs, then P/R/F1 computed;
  * injected-fragment localization is also reported on successful-injection runs only,
    because that is the proposal's target (F1 >= 0.80 on successful injections);
  * attribution pools every process row, then computes accuracy, macro-F1 and abstention;
  * first deviation: accuracy on attack runs, false-alarm rate on legitimate runs;
  * impact: per-destination accuracy, plus the count of connection-only destinations
    labelled confirmed (target: zero).
Runs whose ground truth is not marked "reviewed": true are flagged; --reviewed-only drops them.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .case import Case
from .evaluate import evaluate_case, prf


def find_runs(root: str | Path, case_name: str = "case") -> list[Path]:
    root = Path(root)
    return sorted(p.parent for p in root.glob("*/ground_truth.json") if (p.parent / case_name / "case.json").exists())


def _micro(results: list[dict], key: str) -> dict:
    parts = [r[key] for r in results if isinstance(r.get(key), dict) and "tp" in r[key]]
    tp, pred, gold = (sum(p[k] for p in parts) for k in ("tp", "pred", "gold"))
    p = tp / pred if pred else (1.0 if not gold else 0.0)
    rr = tp / gold if gold else 1.0
    f = 2 * p * rr / (p + rr) if p + rr else 0.0
    return {"precision": round(p, 3), "recall": round(rr, 3), "f1": round(f, 3), "tp": tp, "pred": pred,
            "gold": gold, "runs": len(parts)}


def _attribution(results: list[dict]) -> dict:
    rows = [row for r in results for row in r["attribution"]["rows"]]
    if not rows:
        return {"rows": 0}
    classes = sorted({g for g in (row["gold"] for row in rows)})
    per_class = {c: prf({i for i, row in enumerate(rows) if row["pred"] == c},
                        {i for i, row in enumerate(rows) if row["gold"] == c}) for c in classes}
    return {"rows": len(rows),
            "accuracy": round(sum(row["gold"] == row["pred"] for row in rows) / len(rows), 3),
            "macro_f1": round(sum(v["f1"] for v in per_class.values()) / len(per_class), 3),
            "abstention_rate": round(sum(row["pred"] == "unknown" for row in rows) / len(rows), 3),
            "per_class_f1": {c: v["f1"] for c, v in per_class.items()}}


def aggregate(results: list[dict]) -> dict:
    attack = [r for r in results if r["_gt"].get("first_deviation")]
    legit = [r for r in results if not r["_gt"].get("injection_present", bool(r["_gt"].get("injected_fragments")))]
    success = [r for r in results if r["_gt"].get("attack_succeeded")]
    impacts = [v for r in results for v in r["impact"].values()]
    return {
        "runs": len(results),
        "attack_runs": len(attack), "legitimate_runs": len(legit), "successful_attacks": len(success),
        "unreviewed_runs": sum(not r["_gt"].get("reviewed", False) for r in results),
        "injected_fragment_localization": _micro(results, "injected_fragment_localization"),
        "injected_fragment_localization_successful": _micro(success, "injected_fragment_localization"),
        "malicious_tool_calls": _micro(results, "malicious_tool_calls"),
        "tool_process_links": _micro(results, "tool_process_links"),
        "first_deviation_accuracy": round(sum(r["first_deviation_correct"] for r in attack) / len(attack), 3)
        if attack else None,
        "legitimate_false_alarm_rate": round(sum(bool(r["_pred_first"]) for r in legit) / len(legit), 3)
        if legit else None,
        "attribution": _attribution(results),
        "impact_accuracy": round(sum(v["gold"] == v["pred"] for v in impacts) / len(impacts), 3) if impacts else None,
        "connection_only_labelled_confirmed": sum(r["connection_only_labelled_confirmed"] for r in results),
    }


def evaluate_runs(runs: list[Path], case_name: str = "case", reviewed_only: bool = False) -> dict:
    results, skipped = [], []
    for run in runs:
        gt = json.loads((run / "ground_truth.json").read_text(encoding="utf-8-sig"))
        if reviewed_only and not gt.get("reviewed"):
            skipped.append({"run": run.name, "reason": "ground truth not reviewed"})
            continue
        case = Case(run / case_name)
        chain = case.read_output("chain.json")
        if chain is None:
            skipped.append({"run": run.name, "reason": "case not analysed (run ptir ingest and ptir analyze)"})
            continue
        r = evaluate_case(case, gt)
        r.update(_run=run.name, _gt=gt, _pred_first=chain.get("first_deviation"))
        results.append(r)
    groups: dict[str, list[dict]] = {}
    for r in results:
        groups.setdefault(r["_gt"].get("family") or "unknown", []).append(r)
    return {"overall": aggregate(results) if results else {"runs": 0},
            "by_family": {k: aggregate(v) for k, v in sorted(groups.items())},
            "skipped": skipped, "per_run": results}


def per_run_rows(report: dict) -> list[dict]:
    rows = []
    for r in report["per_run"]:
        gt = r["_gt"]
        rows.append({
            "run": r["_run"], "scenario": gt.get("scenario"), "family": gt.get("family"),
            "reviewed": gt.get("reviewed", False), "attack_succeeded": gt.get("attack_succeeded"),
            "fragment_f1": r["injected_fragment_localization"]["f1"],
            "malicious_call_f1": r["malicious_tool_calls"]["f1"],
            "tool_link_f1": (r.get("tool_process_links") or {}).get("f1"),
            "first_deviation_correct": r["first_deviation_correct"],
            "predicted_first_deviation": r["_pred_first"], "gold_first_deviation": gt.get("first_deviation"),
            "attribution_accuracy": r["attribution"]["accuracy"],
            "abstention_rate": r["attribution"]["abstention_rate"],
            "impact": "; ".join(f"{d}:{v['gold']}->{v['pred']}" for d, v in r["impact"].items()),
        })
    return rows


def write_report(report: dict, out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    clean = {k: v for k, v in report.items() if k != "per_run"}
    clean["per_run"] = per_run_rows(report)
    j = out / "results.json"
    j.write_text(json.dumps(clean, indent=2))
    c = out / "per_run.csv"
    rows = clean["per_run"]
    with open(c, "w", newline="") as f:
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader(); w.writerows(rows)
    return j, c


def summary_lines(report: dict) -> list[str]:
    o = report["overall"]
    if not o.get("runs"):
        return ["no analysed runs found"]
    a = o["attribution"]
    lines = [
        f"runs {o['runs']} (attack {o['attack_runs']}, legitimate {o['legitimate_runs']}, "
        f"successful attacks {o['successful_attacks']}, unreviewed {o['unreviewed_runs']})",
        f"injected-span localization F1      {o['injected_fragment_localization']['f1']}"
        f"   (successful injections: {o['injected_fragment_localization_successful']['f1']}, target >= 0.80)",
        f"malicious tool calls F1            {o['malicious_tool_calls']['f1']}",
        f"tool-to-process link precision     {o['tool_process_links']['precision']}"
        f"   (recall {o['tool_process_links']['recall']}, target precision >= 0.95)",
        f"first deviation accuracy           {o['first_deviation_accuracy']}",
        f"legitimate-run false alarms        {o['legitimate_false_alarm_rate']}",
        f"attribution macro-F1               {a.get('macro_f1')}   (abstention {a.get('abstention_rate')}, target >= 0.85)",
        f"impact accuracy                    {o['impact_accuracy']}",
        f"connection-only labelled confirmed {o['connection_only_labelled_confirmed']}   (target 0)",
    ]
    for s in report["skipped"]:
        lines.append(f"skipped {s['run']}: {s['reason']}")
    return lines
