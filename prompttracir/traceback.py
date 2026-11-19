"""Fragment-to-tool-call traceback (RQ2): which part of the model's context made it act.

Localizers (v0.5 plug-in interface, ``Localizer``) each score the fragments in the context of
a deviating tool call and may also return character spans inside them. Every result becomes
an INFERRED "influenced" edge fragment -> tool_call; spans are kept in the edge's signals.

  segment    (default without a model) PromptLocate-style: split each fragment into sentences,
             score each sentence for instruction cues and for carrying the tool call's own
             command, URL or path, and return the run of sentences that scored. Model-free.
  heuristic  the v0.1 baseline: instruction cues over the whole fragment.
  replay     counterfactual leave-one-out (AttriGuard / TracLLM-style): re-send the recorded
             model request with one fragment removed and check whether the tool call survives.
             Needs requests.jsonl and the same model.
  group      TracLLM-style group search: remove halves of the context recursively and only
             descend into a group whose removal stops the tool call. Same evidence as replay
             in fewer model calls when only a few fragments matter.

Replay also runs against a stand-in local model for closed agents (Claude Code): the request is
rebuilt from the trace (prompt plus context fragments) and results are marked "surrogate" with
half the confidence. AttnTrace needs attention weights an OpenAI-compatible server does not
return, so it is not implemented.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Protocol

from .correlate import cmd_similarity, norm_cmd
from .graph import ProvGraph
from .schema import NodeKind

INSTRUCTION_CUES = [
    r"\bignore (all |any )?(previous|prior|above)\b", r"\b(you|assistant|ai|agent) (must|should|need to)\b",
    r"\bimportant\b", r"\binstead\b", r"\bdo not (tell|mention|inform|list|include|report)\b",
    r"\bsystem( prompt)?:",
    r"\b(run|execute) (the following|this)\b", r"\b(send|upload|post|exfiltrate|forward)\b",
    r"\bcurl\b|\binvoke-webrequest\b|\biwr\b", r"https?://", r"\bbefore (you|continuing|answering|summari[sz]ing|writing)\b",
    r"<\|.*?\|>|</?(system|instructions?)>", r"\b(secret|password|token|credential|\.ssh|api key)s?\b",
    # v0.5, from the file_persist and file_change payloads
    r"\bfor (ai|llm) (assistants?|agents?|models?)\b", r"\b(run|execute) this command\b",
    r"\bschtasks\b|\breg(\.exe)? add\b|\bcmd(\.exe)? /c\b|\bpowershell(\.exe)? -",
]


def heuristic_score(text: str) -> float:
    hits = sum(1 for p in INSTRUCTION_CUES if re.search(p, text, re.I))
    return round(min(1.0, hits / 4.0), 3)


@dataclass
class Localization:
    fragment_id: str
    score: float                                   # 0..1, how strongly the fragment caused the call
    spans: list[tuple[int, int, float]] = field(default_factory=list)   # (start, end, score) in its text
    method: str = ""
    signals: dict = field(default_factory=dict)


class Localizer(Protocol):
    name: str

    def localize(self, target: dict, fragments: dict[str, str],
                 request: dict | None = None) -> list[Localization]:
        """target = {"tool", "args"} of the deviating call; fragments = id -> text in its context."""


# ---------------- model-free localizers ----------------
_SENT = re.compile(r"(?<=[.!?])\s+|\n+")
_TAG = re.compile(r"^(?:\s|<[^>]+>)+|(?:\s|<[^>]+>)+$")
_URL = re.compile(r"https?://[^\s\"'<>]+")
_WINPATH = re.compile(r"[A-Za-z]:\\[^\s\"'|<>]+")


def segments(text: str) -> list[tuple[int, int]]:
    """Sentence and line segments of a fragment as (start, end), without surrounding HTML tags."""
    out, pos = [], 0
    for m in list(_SENT.finditer(text)) + [None]:
        end = m.start() if m else len(text)
        seg = text[pos:end]
        lead = _TAG.match(seg)
        a = pos + (lead.end() if lead and lead.start() == 0 else 0)
        trail = re.search(r"(?:\s|<[^>]+>)+$", text[a:end])
        b = a + (trail.start() if trail else end - a)
        if b > a:
            out.append((a, b))
        pos = m.end() if m else len(text)
    return out


def target_strings(target: dict) -> list[str]:
    """What the tool call asked for, as text a payload would contain: command, URLs, paths."""
    args = target.get("args")
    vals = [str(v) for v in (args.values() if isinstance(args, dict) else [args]) if v]
    out = list(vals)
    for v in vals:
        out += _URL.findall(v) + _WINPATH.findall(v)
    return [x for x in out if len(x) >= 8]


def target_match(text: str, target: dict) -> float:
    """1.0 when the text carries the call's command (or URL/path), else a similarity below 1."""
    best = 0.0
    nt = norm_cmd(text)
    for t in target_strings(target):
        if norm_cmd(t) and norm_cmd(t) in nt:
            return 1.0
        if len(t) >= 20:
            best = max(best, cmd_similarity(t, text) if len(text) < 4 * len(t) else 0.0)
    return round(best, 3)


class HeuristicLocalizer:
    name = "heuristic"

    def localize(self, target, fragments, request=None):
        out = []
        for fid, text in fragments.items():
            s = heuristic_score(text)
            out.append(Localization(fid, s, [(0, len(text), s)] if s else [], "heuristic_localizer"))
        return out


class SegmentLocalizer:
    """PromptLocate-style: localize the injected instruction at sentence level."""
    name = "segment"

    def __init__(self, segment_threshold: float = 0.5):
        self.thr = segment_threshold

    def score_segment(self, seg: str, target: dict) -> float:
        tm = target_match(seg, target)
        cue = heuristic_score(seg)
        if tm >= 1.0:
            return 1.0
        return round(min(1.0, max(cue, 0.5 * cue + 0.5 * tm)), 3)

    def localize(self, target, fragments, request=None):
        out = []
        for fid, text in fragments.items():
            segs = segments(text)
            scored = [(a, b, self.score_segment(text[a:b], target)) for a, b in segs]
            spans: list[tuple[int, int, float]] = []
            for i, (a, b, sc) in enumerate(scored):
                if sc < self.thr:
                    continue
                # carry neighbouring sentences that are themselves instruction-like
                # ("Do not mention this step.") into the same span
                lo, hi = i, i
                while lo > 0 and heuristic_score(text[scored[lo - 1][0]:scored[lo - 1][1]]) > 0:
                    lo -= 1
                while hi + 1 < len(scored) and heuristic_score(text[scored[hi + 1][0]:scored[hi + 1][1]]) > 0:
                    hi += 1
                span = (scored[lo][0], scored[hi][1], sc)
                if spans and span[0] <= spans[-1][1]:
                    spans[-1] = (spans[-1][0], max(spans[-1][1], span[1]), max(spans[-1][2], sc))
                else:
                    spans.append(span)
            score = max((sc for _, _, sc in scored), default=0.0)
            out.append(Localization(fid, score, spans, "segment_localizer",
                                    {"segments": len(segs), "target_match": max(
                                        (target_match(text[a:b], target) for a, b in segs), default=0.0)}))
        return out


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


class ReplayLocalizer:
    """Counterfactual leave-one-out over fragments."""
    name = "replay"

    def __init__(self, replayer: "Replayer", samples: int = 3, surrogate: bool = False):
        self.replayer, self.samples, self.surrogate = replayer, samples, surrogate

    def localize(self, target, fragments, request=None):
        if request is None:
            return []
        base, res = leave_one_out(request, target, fragments, self.replayer, self.samples)
        scale = 0.5 if self.surrogate else 1.0
        return [Localization(r.fragment_id, round(max(r.influence, 0.0) * scale, 3), [],
                             "surrogate_replay" if self.surrogate else "leave_one_out_replay",
                             {"baseline_survival": base, "survival_without": r.survival,
                              "samples": self.samples, "low_fidelity": base < 0.5})
                for r in res]


class GroupSearchLocalizer:
    """TracLLM-style: remove groups of fragments, descend only into groups that matter."""
    name = "group"

    def __init__(self, replayer: "Replayer", samples: int = 3, surrogate: bool = False):
        self.replayer, self.samples, self.surrogate = replayer, samples, surrogate
        self.calls = 0

    def _survival(self, request, target, drop: list[str], fragments) -> float:
        req = request
        for fid in drop:
            req = _remove(req, fragments[fid])
        hits = 0
        for _ in range(self.samples):
            self.calls += 1
            hits += _survives(target, self.replayer.replay(req))
        return hits / self.samples

    def localize(self, target, fragments, request=None):
        if request is None or not fragments:
            return []
        self.calls = 0
        base = self._survival(request, target, [], fragments)
        found: dict[str, float] = {}

        def search(group: list[str]):
            surv = self._survival(request, target, group, fragments)
            if base - surv <= 0:
                return
            if len(group) == 1:
                found[group[0]] = round(base - surv, 3)
                return
            mid = len(group) // 2
            search(group[:mid]); search(group[mid:])

        search(sorted(fragments))
        scale = 0.5 if self.surrogate else 1.0
        sig = {"baseline_survival": base, "samples": self.samples, "model_calls": self.calls,
               "low_fidelity": base < 0.5}
        return [Localization(fid, round(found.get(fid, 0.0) * scale, 3), [],
                             "surrogate_group_search" if self.surrogate else "group_search", sig)
                for fid in fragments]


def surrogate_request(pg: ProvGraph, model_call: str, tools: list[dict] | None = None) -> dict:
    """A chat request rebuilt from the trace, for replay against a stand-in model when the
    agent's own requests were not recorded (Claude Code)."""
    msgs = []
    prompts = [p for p in pg.g.predecessors(model_call) if pg.node(p).kind == NodeKind.PROMPT]
    for p in prompts:
        msgs.append({"role": "user", "content": pg.node(p).attrs.get("text", "")})
    frags = sorted((pg.node(p) for p in pg.g.predecessors(model_call) if pg.node(p).kind == NodeKind.FRAGMENT),
                   key=lambda n: (n.attrs.get("ts") or "", n.attrs.get("index") or 0))
    if frags:
        msgs.append({"role": "user", "content": "Tool output:\n\n" + "\n\n".join(f.attrs.get("text", "") for f in frags)})
    body = {"messages": msgs or [{"role": "user", "content": ""}], "temperature": 0}
    if tools:
        body["tools"] = tools
    return body


SURROGATE_TOOLS = [{"type": "function", "function": {"name": n, "description": d, "parameters": {
    "type": "object", "properties": {k: {"type": "string"} for k in ks}, "required": list(ks)}}}
    for n, d, ks in (("shell", "Run a shell command", ("command",)),
                     ("read_file", "Read a file", ("path",)),
                     ("write_file", "Write a file", ("path", "content")),
                     ("http_get", "Fetch a URL", ("url",)))]


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


GROUP_SEARCH_MIN = 8      # fragments; below this leave-one-out costs about as many model calls


def run_traceback(pg: ProvGraph, tool_calls: list[str], requests: dict[str, dict] | None = None,
                  replayer: Replayer | None = None, samples: int = 3, heuristic_threshold: float = 0.5,
                  method: str = "auto") -> list[dict]:
    """Add 'influenced' edges for each target tool call. Returns a log of what was tested.

    method: auto (with a replayer and the request: leave-one-out replay for up to
    GROUP_SEARCH_MIN fragments, group search above that; otherwise segment), segment,
    heuristic, replay or group. With a replayer but no recorded request (Claude
    Code), replay runs on a surrogate request rebuilt from the trace."""
    log = []
    for tc in tool_calls:
        mc, frags = context_fragments(pg, tc)
        if not mc or not frags:
            continue
        mc_id = mc.split(":", 1)[1]
        node = pg.node(tc)
        target = {"tool": node.attrs.get("tool"), "args": node.attrs.get("args")}
        req = (requests or {}).get(mc_id)
        surrogate = False
        if replayer is not None and req is None and method in ("auto", "replay", "group"):
            req, surrogate = surrogate_request(pg, mc, SURROGATE_TOOLS), True
        m = method
        if m == "auto":
            if replayer is not None and req is not None:
                m = "group" if len(frags) > GROUP_SEARCH_MIN else "replay"
            else:
                m = "segment"
        if m in ("replay", "group") and (replayer is None or req is None):
            m = "segment"
        loc: Localizer = {"segment": lambda: SegmentLocalizer(),
                          "heuristic": lambda: HeuristicLocalizer(),
                          "replay": lambda: ReplayLocalizer(replayer, samples, surrogate),
                          "group": lambda: GroupSearchLocalizer(replayer, samples, surrogate)}[m]()
        results = loc.localize(target, frags, req)
        model_based = m in ("replay", "group")
        for r in results:
            conf = r.score if model_based else round(0.6 * r.score, 3)
            keep = r.score > 0 if model_based else r.score >= heuristic_threshold
            if not keep:
                continue
            pg.add_inferred(r.fragment_id, tc, "influenced", confidence=conf,
                            signals={"method": r.method, "score": r.score,
                                     "spans": [list(x) for x in r.spans], **r.signals},
                            evidence=pg.node(r.fragment_id).evidence + node.evidence)
        entry = {"tool_call": tc, "method": m, "surrogate": surrogate,
                 "scores": {r.fragment_id: r.score for r in results},
                 "spans": {r.fragment_id: [list(x) for x in r.spans] for r in results if r.spans}}
        if model_based and results:
            entry.update({k: v for k, v in results[0].signals.items() if k != "survival_without"})
            entry["results"] = [{"fragment_id": r.fragment_id, "influence": r.score,
                                 "survival": r.signals.get("survival_without")} for r in results]
        log.append(entry)
    return log
