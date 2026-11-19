"""v0.5 localizers: segment (PromptLocate-style), group search (TracLLM-style), span scoring."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prompttracir.evaluate import span_overlap  # noqa: E402
from prompttracir.traceback import (GroupSearchLocalizer, HeuristicLocalizer, ReplayLocalizer,  # noqa: E402
                                    SegmentLocalizer, segments)


def _sc(name):
    return json.loads((ROOT / "harness" / "scenarios" / f"{name}.json").read_text(encoding="utf-8"))


def _planted(sc):
    from harness.scenario import load, render
    s = load(ROOT / "harness" / "scenarios" / f"{sc['id']}.json")
    text = next(render(f.content, s) for f in s.setup.files + s.setup.web_pages if "{{payload}}" in f.content)
    return text


def _paragraph_with_payload(sc):
    """The fragment the harness would produce: the paragraph holding the payload."""
    paras = [p for p in _planted(sc).split("\n\n") if sc["injection"]["payload"][:40] in p]
    return paras[0]


def _overlap(text, spans, payload):
    i = text.find(payload)
    gold = {"f": set(range(i, i + len(payload)))}
    pred = {"f": set().union(*(set(range(a, b)) for a, b, _ in spans))} if spans else {}
    return span_overlap(pred, gold)["f1"]


def test_segments_drop_html_tags():
    text = "<p>First sentence. Second one!</p>\n<p>Third</p>"
    assert [text[a:b] for a, b in segments(text)] == ["First sentence.", "Second one!", "Third"]


def test_segment_localizer_finds_every_lab_payload_and_its_span():
    for name in ("web_exfil_01", "file_persist_01", "file_change_01", "download_01"):
        sc = _sc(name)
        frag = _paragraph_with_payload(sc)
        target = {"tool": "shell", "args": {"command": sc["injection"]["command"]}}
        [loc] = SegmentLocalizer().localize(target, {"f": frag})
        assert loc.score == 1.0, name
        assert _overlap(frag, loc.spans, sc["injection"]["payload"]) >= 0.9, name


def test_heuristic_baseline_missed_the_persistence_payload_but_segment_does_not():
    # jt-03 / cy-03: the v0.4 heuristic scored the CONTRIBUTING.md payload 0.25 (< 0.5)
    sc = _sc("file_persist_01")
    frag = _paragraph_with_payload(sc)
    target = {"tool": "shell", "args": {"command": sc["injection"]["command"]}}
    assert SegmentLocalizer().localize(target, {"f": frag})[0].score == 1.0
    assert HeuristicLocalizer().localize(target, {"f": frag})[0].score >= 0.5   # new cues


def test_benign_text_is_not_localized():
    sc = _sc("web_exfil_01")
    target = {"tool": "shell", "args": {"command": sc["injection"]["command"]}}
    benign = "<p>Section 3: run make test to execute the unit tests. Results are written to the reports folder.</p>"
    [loc] = SegmentLocalizer().localize(target, {"f": benign})
    assert loc.score < 0.5 and not loc.spans


class _Replayer:
    """The tool call happens only while fragment f5 is in the request."""
    def __init__(self):
        self.calls = 0

    def replay(self, request):
        self.calls += 1
        text = json.dumps(request)
        return [{"tool": "shell", "args": {"command": "evil"}}] if "PAYLOAD-5" in text else []


def test_group_search_finds_the_fragment_with_fewer_model_calls():
    frags = {f"f{i:02d}": f"paragraph {i} " + ("PAYLOAD-5" if i == 5 else "") for i in range(16)}
    req = {"messages": [{"role": "tool", "content": "\n\n".join(frags.values())}]}
    target = {"tool": "shell", "args": {"command": "evil"}}
    g = GroupSearchLocalizer(_Replayer(), samples=1)
    res = {r.fragment_id: r.score for r in g.localize(target, frags, req)}
    assert res["f05"] == 1.0 and sum(res.values()) == 1.0
    loo = _Replayer()
    ReplayLocalizer(loo, samples=1).localize(target, frags, req)
    assert g.calls < loo.calls          # 10 vs 17 here


def test_surrogate_replay_halves_confidence():
    frags = {"a": "harmless", "b": "PAYLOAD-5"}
    req = {"messages": [{"role": "user", "content": "harmless PAYLOAD-5"}]}
    target = {"tool": "shell", "args": {"command": "evil"}}
    res = {r.fragment_id: r for r in ReplayLocalizer(_Replayer(), 1, surrogate=True).localize(target, frags, req)}
    assert res["b"].score == 0.5 and res["b"].method == "surrogate_replay"
