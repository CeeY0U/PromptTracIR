"""Score one analysed case against harness ground truth.

Aggregate these per-run dicts across all runs (and per evidence condition for the
ablations) to produce the evaluation tables in the report.
"""
from __future__ import annotations

from .case import Case


def prf(pred: set, gold: set) -> dict:
    tp = len(pred & gold)
    p = tp / len(pred) if pred else (1.0 if not gold else 0.0)
    r = tp / len(gold) if gold else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3), "tp": tp,
            "pred": len(pred), "gold": len(gold)}


def evaluate_case(case: Case, gt: dict, influence_threshold: float = 0.3) -> dict:
    chain = case.read_output("chain.json") or {}
    graph = case.read_output("graph.json") or {"edges": []}
    attrs = case.read_output("attribution.json") or []
    impact = case.read_output("impact.json") or []
    findings = case.read_output("findings.json") or []
    out = {}

    pred_frags = {e["src"] for e in graph["edges"]
                  if e["relation"] == "influenced" and e["confidence"] >= influence_threshold}
    if gt.get("injected_fragments") and gt.get("injection_followed") is False:
        # the model ignored the payload: nothing deviated, so there is nothing to trace back
        # from, and a 0 here would measure the model rather than PromptTracIR
        out["injected_fragment_localization"] = {
            "scored": False, "reason": "injection present but not followed", "f1": None,
            "pred": len(pred_frags), "gold": len(gt["injected_fragments"])}
    else:
        out["injected_fragment_localization"] = prf(pred_frags, set(gt.get("injected_fragments", [])))
    out["first_deviation_correct"] = chain.get("first_deviation") == gt.get("first_deviation")

    pred_mal = {f["attrs"]["tool_call"] for f in findings if f["attrs"].get("tool_call")}
    out["malicious_tool_calls"] = prf(pred_mal, set(gt.get("malicious_tool_calls", [])))

    gold_labels = dict(gt.get("process_labels", {}))
    gold_labels.update(_labels_from_pids(case, gt))
    by_guid = {a["process_guid"]: a["label"] for a in attrs}
    rows = [(gold, by_guid.get(g, "missing")) for g, gold in gold_labels.items()]
    classes = sorted({g for g, _ in rows})
    per_class = {c: prf({i for i, (_, p) in enumerate(rows) if p == c},
                        {i for i, (g, _) in enumerate(rows) if g == c}) for c in classes}
    out["attribution"] = {
        "accuracy": round(sum(g == p for g, p in rows) / len(rows), 3) if rows else None,
        "macro_f1": round(sum(v["f1"] for v in per_class.values()) / len(per_class), 3) if per_class else None,
        "abstention_rate": round(sum(p == "unknown" for _, p in rows) / len(rows), 3) if rows else None,
        "rows": [{"gold": g, "pred": p} for g, p in rows],
    }
    if "tool_process_links" in gt:   # written by harness/label_run.py from child PID + Sysmon
        links = case.read_output("tool_links.json") or []
        pred_links = {(f"tool_call:{l['tool_call_id']}", l["process_guid"]) for l in links}
        gold_links = {(tc, g) for tc, g in gt["tool_process_links"].items()}
        out["tool_process_links"] = prf(pred_links, gold_links)
    pred_imp = {i["destination"]: i["level"] for i in impact}
    # "unknown" means the labeller had no sink evidence either way: shown, but not scored
    out["impact"] = {d: {"gold": lvl, "pred": pred_imp.get(d, "missing"), "scored": lvl != "unknown"}
                     for d, lvl in gt.get("exfiltration", {}).items()}
    out["connection_only_labelled_confirmed"] = sum(
        1 for d, lvl in gt.get("exfiltration", {}).items()
        if lvl == "connection_only" and pred_imp.get(d) == "confirmed")
    return out


SHELL_IMAGES = {"powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe", "openconsole.exe"}
ORPHAN_MARGIN_S = 600.0


def _labels_from_pids(case: Case, gt: dict) -> dict[str, str]:
    """Expand harness-recorded root PIDs into per-process gold labels via the Sysmon tree.

    A root that started before the evidence window (typically the human's shell) has no
    process-creation record of its own. Its children still name it: Sysmon records the
    parent's PID and its ProcessGuid, which is unique, so PID reuse cannot mix two shells up."""
    roots = [(pid, "agent") for pid in gt.get("agent_runtime_pids", [])] + \
            [(pid, "human") for pid in gt.get("human_shell_pids", [])]
    if not roots:
        return {}
    from .correlate import ProcessIndex
    pidx = ProcessIndex.build(case.load_events())
    window = _run_window(gt)
    out = {}
    for pid, label in roots:
        root = pidx.find_by_pid(pid)
        for r in ([root] if root else _orphan_roots(pidx, pid, label, window)):
            for g in pidx.descendants(r):
                out[g] = label
    return out


def _run_window(gt: dict) -> tuple[float, float] | None:
    from .parsers import parse_time
    w = gt.get("run_window") or {}
    try:
        lo = parse_time(w["start"]).timestamp()
        hi = parse_time(w["end"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return None
    return lo - ORPHAN_MARGIN_S, hi + ORPHAN_MARGIN_S


def _orphan_roots(pidx, pid: int, label: str, window: tuple[float, float] | None) -> list[str]:
    """ProcessGuid of a root seen only as its children's parent; [] when absent or ambiguous."""
    from .correlate import basename
    found: set[str] = set()
    for g, e in pidx.by_guid.items():
        parent = e.parent_process_guid
        if e.parent_pid != pid or not parent or parent in pidx.by_guid:
            continue
        if window and not window[0] <= e.ts() <= window[1]:
            continue
        parent_image = basename(e.attrs.get("parent_image"))
        if label == "human" and parent_image and parent_image not in SHELL_IMAGES:
            continue
        found.add(parent)
    return sorted(found) if len(found) == 1 else []
