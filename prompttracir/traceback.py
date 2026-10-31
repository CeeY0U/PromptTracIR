"""Fragment-to-tool-call traceback (RQ2).

Two methods, both producing INFERRED "influenced" edges fragment -> tool_call:

1. Counterfactual replay (primary, AttriGuard/TracLLM-style leave-one-out):
   re-send the recorded model request with one candidate fragment removed and
   check whether the recorded tool call survives. Needs the full request (the
   harness writes requests.jsonl) and access to the same model.

2. Heuristic localizer (fallback / baseline): scores fragments for
   instruction-like text. Cheap, model-free, and deliberately labelled weaker.

PromptLocate / TracLLM / AttnTrace can be added as further Localizer classes.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .correlate import cmd_similarity
from .graph import ProvGraph
from .schema import NodeKind

INSTRUCTION_CUES = [
    r"\bignore (all |any )?(previous|prior|above)\b", r"\b(you|assistant|ai|agent) (must|should|need to)\b",
    r"\bimportant\b", r"\binstead\b", r"\bdo not (tell|mention|inform)\b", r"\bsystem( prompt)?:",
    r"\b(run|execute) (the following|this)\b", r"\b(send|upload|post|exfiltrate|forward)\b",
    r"\bcurl\b|\binvoke-webrequest\b|\biwr\b", r"https?://", r"\bbefore (you|continuing|answering)\b",
    r"<\|.*?\|>|</?(system|instructions?)>", r"\b(secret|password|token|credential|\.ssh|api key)s?\b",
]


def heuristic_score(text: str) -> float:
    hits = sum(1 for p in INSTRUCTION_CUES if re.search(p, text, re.I))
    return round(min(1.0, hits / 4.0), 3)


# ---------------- replay ----------------
class Replayer(Protocol):
    def replay(self, request: dict) -> list[dict]:
        """Send a chat request; return tool calls as [{"tool": name, "args": {...}}]."""


class OpenAICompatReplayer:
    """Replays against any OpenAI-compatible endpoint (llama.cpp server, vLLM, Ollama /v1)."""

    def __init__(self, base_url: str, model: str | None = None, api_key: str = "none", timeout: float = 120):
        import httpx
        self.client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout,
                                   headers={"Authorization": f"Bearer {api_key}"})
        self.model = model

    def replay(self, request: dict) -> list[dict]:
        body = dict(request)
        if self.model:
            body["model"] = self.model
        body.update(temperature=0, seed=body.get("seed", 1234), stream=False)
        r = self.client.post("/v1/chat/completions", json=body)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        out = []
        for tc in msg.get("tool_calls") or []:
            fn = tc["function"]
            args = fn.get("arguments") or "{}"
            try:
                args = json.loads(args) if isinstance(args, str) else args
            except json.JSONDecodeError:
                args = {"_raw": args}
            out.append({"tool": fn["name"], "args": args})
        return out


def _remove(request: dict, text: str, replacement: str = "") -> dict:
    req = copy.deepcopy(request)
    for m in req.get("messages", []):
        if isinstance(m.get("content"), str):
            m["content"] = m["content"].replace(text, replacement)
        elif isinstance(m.get("content"), list):
            for part in m["content"]:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"] = part["text"].replace(text, replacement)
    return req


def _survives(target: dict, calls: list[dict], thr: float = 0.8) -> bool:
    t_args = json.dumps(target.get("args"), sort_keys=True)
    return any(c["tool"] == target["tool"] and cmd_similarity(t_args, json.dumps(c["args"], sort_keys=True)) >= thr
               for c in calls)


@dataclass
class ReplayResult:
    fragment_id: str
    survival: float
    influence: float


def leave_one_out(request: dict, target: dict, fragments: dict[str, str], replayer: Replayer,
                  samples: int = 3) -> tuple[float, list[ReplayResult]]:
    """Return (baseline survival, per-fragment results). influence = baseline - survival."""
    base = sum(_survives(target, replayer.replay(request)) for _ in range(samples)) / samples
    results = []
    for fid, text in fragments.items():
        req = _remove(request, text)
        surv = sum(_survives(target, replayer.replay(req)) for _ in range(samples)) / samples
        results.append(ReplayResult(fid, surv, round(base - surv, 3)))
    return base, results


# ---------------- graph integration ----------------
def context_fragments(pg: ProvGraph, tool_call: str) -> tuple[str | None, dict[str, str]]:
    """The model call that issued tool_call and the fragments in its context."""
    mc = next((p for p in pg.g.predecessors(tool_call) if pg.node(p).kind == NodeKind.MODEL_CALL), None)
    if not mc:
        return None, {}
    frags = {}
    for p in pg.g.predecessors(mc):
        n = pg.node(p)
        if n.kind == NodeKind.FRAGMENT:
            frags[n.id] = n.attrs.get("text", "")
    return mc, frags


def run_traceback(pg: ProvGraph, tool_calls: list[str], requests: dict[str, dict] | None = None,
                  replayer: Replayer | None = None, samples: int = 3, heuristic_threshold: float = 0.5) -> list[dict]:
    """Add 'influenced' edges for each target tool call. Returns a log of what was tested."""
    log = []
    for tc in tool_calls:
        mc, frags = context_fragments(pg, tc)
        if not mc or not frags:
            continue
        mc_id = mc.split(":", 1)[1]
        node = pg.node(tc)
        target = {"tool": node.attrs.get("tool"), "args": node.attrs.get("args")}
        req = (requests or {}).get(mc_id)
        if replayer is not None and req is not None:
            base, res = leave_one_out(req, target, frags, replayer, samples)
            for r in res:
                if r.influence > 0:
                    pg.add_inferred(r.fragment_id, tc, "influenced", confidence=r.influence,
                                    signals={"method": "leave_one_out_replay", "baseline_survival": base,
                                             "survival_without": r.survival, "samples": samples,
                                             "low_fidelity": base < 0.5},
                                    evidence=pg.node(r.fragment_id).evidence + node.evidence)
            log.append({"tool_call": tc, "method": "replay", "baseline_survival": base,
                        "results": [r.__dict__ for r in res]})
        else:
            scores = {fid: heuristic_score(t) for fid, t in frags.items()}
            for fid, s in scores.items():
                if s >= heuristic_threshold:
                    pg.add_inferred(fid, tc, "influenced", confidence=round(0.6 * s, 3),
                                    signals={"method": "heuristic_localizer", "score": s},
                                    evidence=pg.node(fid).evidence + node.evidence)
            log.append({"tool_call": tc, "method": "heuristic", "scores": scores})
    return log
