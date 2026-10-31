"""Exfiltration impact assessment.

  confirmed        transmitted bytes (Zeek/SRUM) cover the sensitive object's size
  probable         upload semantics reference the sensitive object, or timing and volume fit
  possible         sensitive access precedes egress, but nothing ties the two together
  connection_only  egress with no linked sensitive access
  unknown          not enough evidence

A connection alone is never labelled confirmed.
"""
from __future__ import annotations

import re
from datetime import datetime

from .graph import ProvGraph
from .schema import Finding, ImpactLevel

UPLOAD_PATTERNS = [r"\s-f\s", r"--form", r"\s-d\s*@", r"--data(-binary|-raw)?\s*@", r"\s-t\s", r"--upload-file",
                   r"-infile", r"-body", r"invoke-restmethod.*-method\s+post", r"\bpost\b", r"\bput\b"]
ENCODED_URL = re.compile(r"[?&=/][A-Za-z0-9+/_\-]{40,}={0,2}")


def _ts(pg: ProvGraph, tc: str | None) -> datetime | None:
    if tc and tc in pg.g and pg.node(tc).attrs.get("ts"):
        return datetime.fromisoformat(pg.node(tc).attrs["ts"])
    return None


def _cmd_of(pg: ProvGraph, nid: str) -> str:
    n = pg.node(nid)
    args = n.attrs.get("args")
    parts = [n.attrs.get("command_line") or ""]
    if isinstance(args, dict):
        parts += [str(v) for v in args.values()]
    return " ".join(parts)


def assess(pg: ProvGraph, findings: list[Finding]) -> list[dict]:
    sensitive = [f for f in findings if f.kind == "out_of_scope_file" and f.attrs.get("sensitive")]
    egress = [f for f in findings if f.kind == "external_egress"]
    results = []
    for eg in egress:
        tc = eg.attrs.get("tool_call")
        t_eg = _ts(pg, tc)
        actor = eg.nodes[0]
        net = pg.node(eg.nodes[1])
        cmd = (_cmd_of(pg, actor) + " " + (_cmd_of(pg, tc) if tc else "")).lower()
        sent = net.attrs.get("orig_bytes")
        prior = [s for s in sensitive
                 if (t_s := _ts(pg, s.attrs.get("tool_call"))) is not None and t_eg is not None and t_s <= t_eg]
        level, why, obj = ImpactLevel.CONNECTION_ONLY, ["egress observed, no sensitive access linked"], None
        for s in prior:
            path = s.attrs["path"]
            fnode = next((pg.node(n) for n in s.nodes if n.startswith("file:")), None)
            size = fnode.attrs.get("size") if fnode else None
            referenced = path.lower() in cmd or path.lower().split("\\")[-1] in cmd
            upload = any(re.search(p, " " + cmd + " ") for p in UPLOAD_PATTERNS)
            encoded = bool(ENCODED_URL.search(cmd))
            cand, reasons = ImpactLevel.POSSIBLE, [f"sensitive access to {path} precedes egress"]
            if referenced and upload:
                cand = ImpactLevel.PROBABLE; reasons.append("upload command references the sensitive file")
            elif encoded:
                cand = ImpactLevel.PROBABLE; reasons.append("request URL carries a long encoded payload")
            if sent is not None and size and sent >= 0.9 * size and (referenced or encoded or upload):
                cand = ImpactLevel.CONFIRMED
                reasons.append(f"{sent} bytes sent >= 90% of {size}-byte object")
            elif sent is not None and size is None and sent > 1024 and cand == ImpactLevel.POSSIBLE:
                cand = ImpactLevel.PROBABLE; reasons.append(f"{sent} bytes sent after access (size unknown)")
            if _rank(cand) > _rank(level):
                level, why, obj = cand, reasons, path
        prev = next((r for r in results if r["destination"] == eg.attrs.get("destination")
                     and r["tool_call"] == tc), None)
        if prev and _rank(ImpactLevel(prev["level"])) >= _rank(level):
            prev["egress_findings"].append(eg.finding_id)
            continue
        if prev:
            results.remove(prev)
        results.append({"egress_findings": [eg.finding_id], "destination": eg.attrs.get("destination"),
                        "level": level.value, "object": obj, "bytes_sent": sent, "reasons": why,
                        "tool_call": tc})
    return results


def _rank(l: ImpactLevel) -> int:
    return {ImpactLevel.UNKNOWN: 0, ImpactLevel.CONNECTION_ONLY: 1, ImpactLevel.POSSIBLE: 2,
            ImpactLevel.PROBABLE: 3, ImpactLevel.CONFIRMED: 4}[l]
