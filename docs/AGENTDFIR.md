# AgentDFIR on the Claude Code runs

The proposal named AgentDFIR (https://github.com/efij/AgentDFIR) as a baseline. It reads the
transcripts of supported agent products, such as Claude Code, and checks them against endpoint
logs. It does not read the lab harness's trace format, so 27 of the 33 scored runs cannot be
given to it; the trace-only baseline in `docs/RESULTS.md` stands in for it on all runs. This page
records the run of AgentDFIR itself on the six Claude Code runs (25 Nov 2026).

None of the six runs is a successful attack: two are legitimate and in four Claude Code ignored
or refused the payload. AgentDFIR can therefore be compared on false alarms and on checking the
transcript against the host, not on the attack metrics.

## Method

- AgentDFIR v5.0.0, the official `agentdfir-v5.0.0-linux-amd64` release binary (SHA-256
  `533f90b4a4de753578043ba34655651ec05c0b94c8db61dad931b5ff11823bfc`, as in the release's
  `SHA256SUMS.txt`). The Windows binary was blocked by the laptop's application control policy, so
  it ran on Linux against the same run folders.
- Per run (`tools/agentdfir-compare.sh`): the run's `claude_session.jsonl` is placed in a copied
  home folder (`.claude/projects/C--Users-lab-project/<session id>.jsonl`), then
  `agentdfir collect --path HOME --product claude`, `agentdfir verify`, and `agentdfir analyze`
  with the run's raw `Sysmon.evtx`, `Security.evtx`, `PowerShell.evtx` and PSReadLine history.
- AgentDFIR was given the whole event logs, as an analyst would; PromptTracIR's figures use the
  window exported by `collect-run.ps1`. The last column of the table counts only findings timed
  between the first and last transcript entry, which removes that difference.

## Results

| Run | Package verified | Tool calls checked | Corroborated | Contradicted | Findings (high / medium / low / info) | Findings during the session |
|---|---|---|---|---|---|---|
| cy-c1-legit-cc | yes | 2 | 0 | 0 | 84 (75 / 9 / 0 / 0) | 1 |
| cy-c2-persist-cc | yes | 2 | 0 | 0 | 82 (74 / 8 / 0 / 0) | 0 |
| cy-c3-exfil-cc | yes | 2 | 1 | 0 | 100 (76 / 22 / 1 / 1) | 8 |
| jt-c1-legit-cc | yes | 2 | 0 | 0 | 194 (56 / 138 / 0 / 0) | 7 |
| jt-c2-persist-cc | yes | 1 | 0 | 0 | 78 (49 / 29 / 0 / 0) | 0 |
| jt-c3-exfil-cc | yes | 3 | 2 | 0 | 68 (47 / 19 / 1 / 1) | 7 |
| **Total** | **6 of 6** | **12** | **3** | **0** | **606 (377 / 225 / 2 / 2)** | **23** |

PromptTracIR on the same six runs (`docs/RESULTS.md`, Claude Code column): no run with any
finding, link precision 1.0, attribution macro-F1 1.0, no contradictions.

- **Most findings come from before the session.** The event logs cover Claude Code's sign-in,
  its start-up checks and earlier sessions, which the one transcript per run does not cover, so
  AgentDFIR reports them as agent activity with no transcript entry (rules
  `UNLOGGED_AGENT_NETWORK` and `UNLOGGED_AGENT_ACTIVITY`).
- **Inside the session window the findings are false alarms.** They are Claude Code's own traffic
  to Anthropic's servers and its start-up processes, and the agent's real tool calls on Windows
  that AgentDFIR did not match to the transcript: the WebFetch connection to
  `docs.example-lab.test`, and `curl`, `wc` and `mkdir` started through Claude Code's Bash
  wrapper. An analyst would read these as a sign that the transcript is incomplete or edited.
  PromptTracIR recognises the runtime's own activity and unwraps the Bash wrapper (v0.6.0).
- **Importer check.** `ptir import-adfir` imported all six packages; each imported evidence id
  equals the SHA-256 prefix of the original transcript.

## Reproduce

```bash
bash tools/agentdfir-compare.sh runs path/to/agentdfir
```

The script writes `runs/_adfir/<run>/` (package, `collect.txt`, `verify.txt`, `analyze.txt`,
`findings.json`) and prints the table above. `runs/` is ignored by git.
