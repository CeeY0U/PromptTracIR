#!/usr/bin/env bash
# Run AgentDFIR on the Claude Code runs and summarise its findings (docs/AGENTDFIR.md).
#   usage: bash tools/agentdfir-compare.sh RUNS_DIR [AGENTDFIR_BINARY]
# Claude Code runs are the run folders ending in -cc that hold claude_session.jsonl.
# Writes RUNS_DIR/_adfir/<run>/: pkg (AgentDFIR package), collect.txt, verify.txt, analyze.txt,
# findings.json. Linux, macOS or Git Bash; needs Python 3 for the session id and the summary.
set -euo pipefail
root="${1:?usage: bash tools/agentdfir-compare.sh RUNS_DIR [AGENTDFIR_BINARY]}"
A="${2:-agentdfir}"
py="$(command -v python3 || command -v python)"
"$A" version

for run in "$root"/*-cc; do
  [ -f "$run/claude_session.jsonl" ] || continue
  R="$(basename "$run")"; W="$root/_adfir/$R"; E="$run/evidence"
  P="$W/home/.claude/projects/C--Users-lab-project"
  mkdir -p "$P"
  SID="$("$py" -c 'import json,sys
for l in open(sys.argv[1], encoding="utf-8"):
    if "\"sessionId\"" in l:
        print(json.loads(l)["sessionId"]); break' "$run/claude_session.jsonl")"
  cp "$run/claude_session.jsonl" "$P/$SID.jsonl"
  [ -d "$W/pkg" ] || "$A" collect --path "$W/home" --product claude --out "$W/pkg" --case-id "$R" > "$W/collect.txt" 2>&1
  "$A" verify "$W/pkg" > "$W/verify.txt" 2>&1 || true
  args=()
  for f in Sysmon.evtx Security.evtx PowerShell.evtx; do [ -f "$E/$f" ] && args+=(--endpoint "$E/$f"); done
  [ -f "$E/ConsoleHost_history.txt" ] && args+=(--shell-history "$E/ConsoleHost_history.txt")
  "$A" analyze "$W/pkg" "${args[@]}" > "$W/analyze.txt" 2>&1 || true
  "$A" analyze "$W/pkg" "${args[@]}" --json > "$W/findings.json" 2>/dev/null || true
  echo "analysed $R"
done

"$py" - "$root" <<'EOF'
import collections, datetime as dt, glob, json, os, re, sys
root = sys.argv[1]
def t(s): return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
print("| Run | Verified | Checked | Corroborated | Contradicted | Findings (high / medium / low / info) | During the session |")
print("|---|---|---|---|---|---|---|")
tot = collections.Counter()
for d in sorted(glob.glob(os.path.join(root, "_adfir", "*", ""))):
    run = os.path.basename(os.path.dirname(d))
    an = open(os.path.join(d, "analyze.txt"), encoding="utf-8", errors="replace").read()
    m = re.search(r"(\d+) checked .*? (\d+) CORROBORATED, (\d+) CONTRADICTED", an)
    chk, cor, con = (int(x) for x in m.groups()) if m else (0, 0, 0)
    ok = "VERIFIED" in open(os.path.join(d, "verify.txt"), encoding="utf-8", errors="replace").read()
    fs = json.load(open(os.path.join(d, "findings.json"), encoding="utf-8"))
    fs = fs if isinstance(fs, list) else fs.get("findings", [])
    sev = collections.Counter((f.get("severity") or "").lower() for f in fs)
    times = [t(m.group(1)) for l in open(os.path.join(root, run, "claude_session.jsonl"), encoding="utf-8")
             for m in [re.search(r'"timestamp":"([^"]+)"', l)] if m]
    start, end = min(times), max(times)
    during = 0
    for f in fs:
        m = re.search(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)", f.get("description", ""))
        if m and start <= t(m.group(1)) <= end:   # endpoint findings timed inside the session
            during += 1
    s = f"{len(fs)} ({sev['high']} / {sev['medium']} / {sev['low']} / {sev['info']})"
    print(f"| {run} | {'yes' if ok else 'NO'} | {chk} | {cor} | {con} | {s} | {during} |")
    tot.update(runs=1, ok=ok, chk=chk, cor=cor, con=con, n=len(fs), during=during)
print(f"| Total | {tot['ok']} of {tot['runs']} | {tot['chk']} | {tot['cor']} | {tot['con']} | {tot['n']} | {tot['during']} |")
EOF
