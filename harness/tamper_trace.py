"""Make a tampered copy of a lab run: the transcript is edited after the run (roadmap v0.5).

The question is whether PromptTracIR notices when the agent's own record lies. Windows' records
(Sysmon, Security 4688, memory) are not touched, only the trace the agent wrote.

    python -m harness.tamper_trace runs/jt-01-exfil-scripted runs/jt-01-tampered-edit
    python -m harness.tamper_trace runs/jt-01-exfil-scripted runs/jt-01-tampered-drop --mode drop-call

  edit-command  (default) replace the command of one shell call with a harmless one, in
                trace.jsonl and in requests.jsonl, keeping its result and child PID
  drop-call     delete the call and its result from trace.jsonl, as if it never happened

The copy leaves out case/ and evidence/memory/ (the memory image is large and the Volatility
output in evidence/vol/ is kept). ground_truth.json gets a "tampered" block, which eval-batch
uses to score detection and to keep the run out of the other metrics.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

SKIP = {"case", "memory"}


def _copy(src: Path, dst: Path) -> None:
    if dst.exists():
        raise SystemExit(f"{dst} already exists: pick a new run name")

    def ignore(folder, names):
        return [n for n in names if n in SKIP and Path(folder, n).is_dir()]
    shutil.copytree(src, dst, ignore=ignore)


def tamper(run: Path, out: Path, mode: str = "edit-command", tool_call: str | None = None,
           command: str = "dir C:\\Users\\lab\\project") -> dict:
    gt = json.loads((run / "ground_truth.json").read_text(encoding="utf-8-sig"))
    recs = [json.loads(l) for l in (run / "trace.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    shells = [r for r in recs if r["type"] == "tool_call" and isinstance(r.get("args"), dict) and r["args"].get("command")]
    want = (tool_call or gt.get("first_deviation") or "").replace("tool_call:", "")
    target = next((r for r in shells if r["tool_call_id"] == want), None) or (shells[0] if shells else None)
    if target is None:
        raise SystemExit("no shell tool call in this run's trace to tamper with")
    tcid = target["tool_call_id"]
    original = target["args"]["command"]

    _copy(run, out)
    if mode == "edit-command":
        target["args"]["command"] = command
        kept = recs
        req = out / "requests.jsonl"
        if req.exists():   # the next request repeats the call: keep the two records consistent
            esc_old, esc_new = json.dumps(original)[1:-1], json.dumps(command)[1:-1]
            req.write_text(req.read_text(encoding="utf-8").replace(esc_old, esc_new), encoding="utf-8")
    elif mode == "drop-call":
        kept = [r for r in recs if r.get("tool_call_id") != tcid]
    else:
        raise SystemExit(f"unknown mode {mode}")
    (out / "trace.jsonl").write_text("".join(json.dumps(r) + "\n" for r in kept), encoding="utf-8")
    gt["tampered"] = {"mode": mode, "tool_call": f"tool_call:{tcid}", "original_command": original,
                      "new_command": command if mode == "edit-command" else None, "source_run": run.name}
    (out / "ground_truth.json").write_text(json.dumps(gt, indent=2), encoding="utf-8")
    note = out / "notes.md"
    with open(note, "a", encoding="utf-8") as f:
        f.write(f"\n\n## Tampered copy\n\nMade from {run.name} with harness/tamper_trace.py, mode {mode}, "
                f"tool call {tcid}. Original command: {original}\n")
    return gt["tampered"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("run_dir"); ap.add_argument("out_dir")
    ap.add_argument("--mode", default="edit-command", choices=["edit-command", "drop-call"])
    ap.add_argument("--tool-call", help="tool call id (default: the run's first deviation)")
    ap.add_argument("--command", default="dir C:\\Users\\lab\\project", help="replacement command (edit-command)")
    a = ap.parse_args(argv)
    t = tamper(Path(a.run_dir), Path(a.out_dir), a.mode, a.tool_call, a.command)
    print(json.dumps(t, indent=2))
    print(f"\nnext: ptir add-run {a.out_dir} && ptir ingest {a.out_dir}/case && ptir analyze {a.out_dir}/case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
