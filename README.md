# PromptTracIR

Incident reconstruction and attribution for prompt-injection attacks on tool-enabled AI agents.
ICT3215 Digital Forensics project, Group 17.

PromptTracIR takes agent traces plus Windows host and network evidence, then answers:

* **How did the attacker get in?** Which external source and which fragment of it steered the agent.
* **What did the agent do?** Which tool calls, processes, files and network destinations followed.
* **Who did it?** Whether each process was started by the agent or by the human sharing the same account.
* **Did data leave?** Exfiltration impact graded confirmed / probable / possible / connection-only / unknown.

Every relationship in the output carries an evidence state (observed, corroborated, inferred,
contradicted, unknown) and links back to the exact raw record it came from.

> Status: v0.4.1 (16 Nov 2026). The full pipeline has run on real lab evidence (five runs on a
> Windows 11 24H2 VM, Nov 2026), v0.3.1 fixed what those runs exposed, and v0.4.0 adds the
> attribution engine: a settings file, clock-offset estimation, 4688 / 4104 coverage, human-side
> signals from UserAssist, LNK, ShellBags and logon types, Claude Code runtime inference,
> calibrated P(agent) and ablations; v0.4.1 fixes trace ordering found in the first v0.4.0 lab run.
> The weights are still the defaults until they are tuned on
> real runs. Submission deadline: 29 Nov 2026, 23:59. See [ROADMAP.md](ROADMAP.md),
> [docs/TESTING.md](docs/TESTING.md) and [What is not built yet](#what-is-not-built-yet).

---

## Install

```bash
git clone <repo> && cd prompttracir
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[evtx,dev]"
pytest -q                                               # no model or VM needed
```

Python 3.10+. The analyst machine can be Linux, macOS or Windows; only the lab VM has to be Windows.

## Quick start (synthetic sample)

```bash
python samples/make_sample.py                           # writes samples/scenario_exfil/
S=samples/scenario_exfil
ptir init cases/demo --name "demo" --envelope $S/envelope.json
ptir add cases/demo $S/trace.jsonl            --kind agent_trace
ptir add cases/demo $S/requests.jsonl         --kind agent_requests
ptir add cases/demo $S/sysmon.jsonl           --kind sysmon
ptir add cases/demo $S/ConsoleHost_history.txt --kind psreadline
ptir add cases/demo $S/zeek_conn.json         --kind zeek_conn
ptir ingest  cases/demo
ptir analyze cases/demo
ptir eval    cases/demo $S/ground_truth.json
ptir serve   cases/demo                                  # http://127.0.0.1:8000
```

The sample is one indirect-injection run: a web page tells the agent to upload
`C:\Users\lab\secrets\api_keys.txt` with curl, while the human runs `git status` in another tab.
Expected result: entry point `fragment:f2`, first deviation `tool_call:t2`, curl attributed to the
agent, git attributed to the human, exfiltration to `collect.attacker-lab.test` **confirmed**.

## Commands

| Command | What it does |
|---|---|
| `ptir init CASE --name N [--envelope F]` | Create a case directory. The envelope lists what the user's task legitimately needed. |
| `ptir add CASE FILE_OR_DIR --kind K` | Copy the file (or every file in a directory) into the case, SHA-256 it, make it read-only, log chain of custody. |
| `ptir add-run RUN_DIR [--case C]` | Create a case from a lab run folder in one step (kinds from `evidence/collection.json` or file names). |
| `ptir import-adfir CASE PACKAGE` | Verify an AgentDFIR `.adfir` package and import its Claude Code transcripts. |
| `ptir kinds` | List evidence kinds and whether each is parsed or preserved only. |
| `ptir ingest CASE` | Parse evidence into canonical events (DuckDB). |
| `ptir analyze CASE [options]` | Correlate, attribute, build the graph, run rules, traceback, impact. |
| `ptir config` | Print the attribution settings (weights, thresholds, time windows) as JSON. |
| `ptir verify CASE` | Re-hash every preserved file. |
| `ptir serve CASE` | Analyst UI: attack-flow graph, findings, impact, timeline, raw records. |
| `ptir eval CASE GROUND_TRUTH` | Score the case against harness ground truth. |
| `ptir eval-batch ROOT [options]` | Score every analysed run under `ROOT` and write `results.json` and `per_run.csv`. `--families` / `--exclude-families` pick a split; `--without KIND`, `--config F` or `--tag T` re-analyse every run into `output/<tag>/` first (ablations, tuning). |

`analyze` options:

* `--replay-url URL --replay-model M [--samples N]` leave-one-out counterfactual replay against the same local model the agent used. Without it, a heuristic localizer is used and its edges are marked as weaker.
* `--llm-url URL --llm-model M` local-LLM intent classification and an evidence-cited summary.
* `--config FILE` attribution settings; only the keys you change (see `configs/README.md`).
* `--without KIND` (repeatable) ignore that evidence kind, for ablations. Outputs go to
  `output/without-<kinds>/` (or `--tag NAME`), so the full analysis in `output/` is kept.

Both expect an OpenAI-compatible server, e.g. `llama-server -m model.gguf --port 8080 --jinja`
(llama.cpp) or Ollama at `http://127.0.0.1:11434`.

## Evidence kinds

| `--kind` | Input | Produces |
|---|---|---|
| `agent_trace` | `trace.jsonl` from `harness/agent.py` (format in `prompttracir/parsers/agent_trace.py`) | sessions, prompts, fragments, model calls, tool calls/results |
| `claude_code` | Claude Code session `.jsonl` (directly, or via `ptir import-adfir`) | same as `agent_trace`, without child PIDs |
| `otel_trace` | OTLP/JSON spans using the OpenTelemetry GenAI conventions | same as `agent_trace`; PIDs if the instrumentation sets them |
| `agent_requests` | `requests.jsonl` from the harness | preserved only; used for replay |
| `sysmon` | `.evtx` or JSONL from `tools/export-events.ps1` | events 1, 3, 11, 13, 22, 23, 26 |
| `security` | same | 4624 logons, 4663 file access on audited paths (`tools/audit-canary.ps1`), 4688 process creation |
| `powershell` | same | 4104 script blocks |
| `psreadline` | `ConsoleHost_history.txt` | interactive command history (no timestamps) |
| `zeek_conn` | Zeek `conn.log` (JSON or tab-separated) | connection byte counts |
| `zeek_dns` | Zeek `dns.log` | queries and answers (names IP-only connections) |
| `zeek_http` | Zeek `http.log` | method, host, URI, request and response body sizes |
| `ez_mft` | MFTECmd `$MFT` CSV | file created / modified ($SI times; $FN and timestomp flags in attrs) |
| `ez_usn` | MFTECmd `$J` CSV (`-m $MFT` for paths) | file create / delete / rename / modify, one per closed change |
| `ez_prefetch` | PECmd CSV | program run, one per recorded run time (weak for authorship) |
| `ez_amcache` | AmcacheParser `*FileEntries.csv` | program present with SHA-1 (key last-write, not execution time) |
| `ez_srum` | SrumECmd `NetworkUsages` CSV | bytes sent / received per app per ~1 h interval |
| `ez_registry` | RECmd batch CSV (e.g. `Kroll_Batch.reb`) | UserAssist GUI launches, autoruns, other key/values |
| `ez_lnk`, `ez_jumplist`, `ez_shellbags` | LECmd / JLECmd / SBECmd CSV | files opened and folders browsed through the Explorer shell |
| `vol_pslist`, `vol_cmdline`, `vol_netscan` | Volatility 3 `-r json` / `-r jsonl` of `windows.pslist` or `pstree`, `cmdline`, `netscan` | processes, command lines, sockets from memory |
| `agent_sources`, `evtx_raw`, `memory_image`, `pcap`, `srum`, `prefetch`, `amcache`, `registry_hive`, `mft`, `usn_journal`, `triage_archive`, `adfir_meta`, `other` | see `ptir kinds` | hashed and preserved, not parsed; the raw originals of the `ez_*` / `vol_*` outputs stay here for custody |

The `ez_*` and `vol_*` kinds are derived files: run the tools on the raw artifacts
(`tools/parse-artifacts.ps1` does all of them for a run folder) and add their output.
Every event they produce records what its timestamp means in `attrs.ts_meaning`, and none of
them carries a ProcessGuid, so on their own they never create observed edges in the graph;
attribution (v0.4) and reconstruction (v0.5) use them as independent signals.

## Outputs (`CASE/output/`)

| File | Contents |
|---|---|
| `graph.json` | Provenance graph: nodes, edges, evidence state, confidence, signals, supporting event IDs |
| `chain.json` | Entry points, first deviating tool call, the attack-chain node set |
| `findings.json` | Scope violations: out-of-scope files, external egress, persistence, credential access |
| `impact.json` | Exfiltration level per destination with reasons |
| `attribution.json` | agent / human / mixed / unknown per process, with the weighted signals behind each label, `agent_probability`, and the logs that saw the process |
| `tool_links.json` | Tool call to process links with scores |
| `correlation.json` | Per agent session: how the runtime process was found (PID, GUID or inferred) and the trace-to-host clock offset |
| `config.json` | The settings used, their fingerprint, evidence kinds used and any `--without` |
| `traceback.json` | What replay or the heuristic tested and found |
| `llm.json` | LLM classifications, validated summary, unsupported-claim rate |

---

## How it works

```
evidence files ──► case (hash, read-only copy, custody log)
                     │
                     ▼ parsers
               canonical events (DuckDB)            prompttracir/schema.py is the contract
                     │
                     ▼ correlate.py
   process tree · tool call → process links · human/agent attribution
                     │
                     ▼ graph.py
   provenance graph: prompt → model call → tool call → process → file / registry / network
                     │
       ┌─────────────┼──────────────┬──────────────┐
       ▼             ▼              ▼              ▼
   scope.py     traceback.py      llm.py        impact.py
   findings     fragment →        classify,     exfil level
                tool call         summarise
                (INFERRED)        (validated)
                     │
                     ▼
               api.py + web/index.html (Cytoscape attack-flow view)
```

Design rules worth keeping:

1. Only parsed records create observed or corroborated edges. Traceback and the LLM can only add
   inferred edges through `ProvGraph.add_inferred`, and LLM citations to unknown IDs are dropped.
2. A link is corroborated only when two independent sources agree (e.g. the harness recorded child
   PID 5200 and Sysmon shows PID 5200 created in the tool-call window).
3. No single attribution signal decides a label. The weights are in `prompttracir/config.py`
   (`ptir config`); tune them on training runs only and report the file (`configs/README.md`).
4. A connection alone is never confirmed exfiltration.

### Attribution signals (`correlate.py`, weights in `config.py`)

| Signal | Side | Default weight | Evidence |
|---|---|---|---|
| process created by a tool call (PID/GUID match) | agent | 3.0 | trace + Sysmon / 4688 |
| descendant of such a process | agent | 2.5 | process tree |
| descendant of the agent runtime (python/node/claude) | agent | 2.0 | process tree |
| non-interactive shell flags | agent (weak) | 0.5 | command line |
| explorer / terminal ancestry without passing through the agent runtime | human | 2.0 | process tree |
| command appears in PSReadLine history | human (weak) | 1.0 | PSReadLine |
| image started from the Explorer shell | human | 2.0 | UserAssist (`ez_registry`) |
| a file named in the command line was opened through Explorer | human | 1.5 | LNK / Jump Lists |
| working directory browsed in Explorer shortly before | human (weak) | 0.5 | ShellBags |
| started while no agent session was running | human (weak) | 1.0 | trace + process time |
| non-interactive logon (4624 type 3, 4, 5, ...) | context | human signals not counted | Security 4624 |

Label is agent or human when one side leads by 1.5, mixed when both are high, otherwise unknown.
`agent_probability` is `1 / (1 + exp(-(agent - human) / 1.5))`; the temperature is a setting, tuned
for calibration (ECE in `eval-batch`).

Tool-call-to-process links use child PID or ProcessGuid (corroborated), else descent from the
agent runtime plus command similarity, or a PowerShell 4104 script block matching the tool's
command (inferred). The trace-to-host clock offset is estimated per session from child PIDs.
When Sysmon is missing, Security 4688 builds the process tree. For traces without a runtime PID
(Claude Code) the runtime is inferred from `claude.exe` / `node.exe` processes whose children
match the session's tool calls.

---

## Lab setup (Windows 11 VM)

Isolate the VM network. Use synthetic secrets only.

1. Auditing (admin PowerShell):
   ```powershell
   auditpol /set /subcategory:"Process Creation" /success:enable
   auditpol /set /subcategory:"Logon" /success:enable
   reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
   reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
   ```
2. Sysmon: `Sysmon64.exe -accepteula -i tools\sysmon-lab.xml`. Sysmon must be running **before**
   the agent starts so the runtime process appears in the process tree.
3. Local model on the VM or a host-only neighbour, e.g. a 7–8B instruct GGUF with tool calling,
   served by `llama-server --jinja --port 8080`.
4. Attacker side: a lab web server for the poisoned page, and `harness/exfil_sink.py` behind a lab
   DNS name such as `collect.attacker-lab.test`. Optional: Zeek on the capture interface.
5. Take a clean snapshot.

### One run

The full procedure, with the attacker box, scenario setup and the paired human session, is in
[docs/TESTING.md](docs/TESTING.md#part-4-one-real-lab-run). In short, on the lab VM:

```powershell
python -m harness.scenario prepare harness\scenarios\web_exfil_01.json --files-only   # secrets, poisoned files
.\tools\collect-run.ps1 -Phase Start -RunDir C:\lab\runs\run01             # elevated
$env:PTIR_LAB = "1"
python harness\agent.py --scenario harness\scenarios\web_exfil_01.json --base-url http://127.0.0.1:8080 --out C:\lab\runs\run01
# for a guaranteed followed injection, serve the scripted model instead of llama-server:
#   python -m harness.scripted_model --scenario harness\scenarios\web_exfil_01.json --port 8080
# second window: . .\tools\human-session.ps1 -Run run01 -OutDir C:\lab\runs\run01 -Scenario harness\scenarios\web_exfil_01.json
.\tools\collect-run.ps1 -Phase Stop -RunDir C:\lab\runs\run01 -WinPmem C:\tools\winpmem.exe
python harness\label_run.py C:\lab\runs\run01 --sink \\attacker\share\sink_log.jsonl
```

Then, on the analyst machine: `ptir add-run runs/run01`, `ptir ingest runs/run01/case`,
`ptir analyze runs/run01/case`, `ptir eval runs/run01/case runs/run01/ground_truth.json`.

---

## What is not built yet

Mapped to the proposal so the team can split it up:

| Proposal item | Status | Notes |
|---|---|---|
| Case format, hashing, custody, canonical schema | done | |
| Agent trace + harness with child-PID capture and request logging | done | plain loop; LangGraph optional; raw source bytes kept (v0.2) |
| Scenario schema, setup, labelling with ProcessGuid and sink window | done (v0.2) | 3 scenarios; the dataset needs 60+ runs |
| Lab collection script (logs, pcap, SRUM, Prefetch, Amcache, hives, LNK, memory, KAPE) | done (v0.2), run on the lab VM (v0.3.1) | exports logs from boot; copies hive transaction logs |
| Sysmon / Security / PowerShell / PSReadLine / Zeek parsers | done | |
| Tool-to-process correlation, human/agent attribution | done (v0.4) | settings file, clock offset, 4688/4104 coverage, UserAssist / LNK / ShellBags / logon signals, Claude Code runtime inference, calibrated P(agent); weights not yet tuned on real runs |
| Provenance graph, backward/forward traversal | done | |
| Scope rules, first deviation, exfil impact | done | |
| Leave-one-out replay traceback | done | needs a followed injection on a real model; the scripted model (v0.3.1) gives positive cases meanwhile |
| Local LLM classification + validated summary | done | needs prompt tuning on real runs |
| Analyst UI | done (single page + Cytoscape) | proposal said React; either port or note the change |
| MFT/USN, Prefetch, Amcache, SRUM, registry parsers | done (v0.3), checked on real output (v0.3.1) | EZ Tools CSV adapters, plus LNK / Jump Lists / ShellBags; `$MFT`/`$J` only with KAPE |
| Zeek DNS / HTTP, Security 4663 file reads | done (v0.3) | 4663 needs `tools/audit-canary.ps1` on the VM |
| Volatility 3 cross-check of the transcript | parsers done (v0.3) | `vol_pslist`, `vol_cmdline`, `vol_netscan` ingest (netstat fallback on 24H2); the transcript cross-check itself is v0.5 |
| AgentDFIR / OpenTelemetry trace adapters | done (v0.2) | Claude Code transcripts have no PIDs; signature check left to `agentdfir verify` |
| PromptLocate / TracLLM / AttnTrace modules | optional | add as further localizers in `traceback.py` |
| STIX 2.1 export with ATLAS tags | **todo** | |
| Multi-run evaluation | done (v0.2) | `ptir eval-batch` |
| Ablations | done (v0.4) | `ptir analyze --without KIND`, `ptir eval-batch --without KIND` |
| Baselines | **todo** | v0.8 |

## Repository layout

```
prompttracir/   schema, case, parsers/, correlate, graph, scope, impact, traceback, llm, pipeline,
                runs (add-run), adfir (import), batch (eval-batch), config, api, cli, web/
harness/        agent.py (traced lab agent), scripted_model.py, scenario.py, exfil_sink.py, label_run.py,
                scenarios/
tools/          collect-run.ps1, parse-artifacts.ps1, export-events.ps1, human-session.ps1, audit-canary.ps1,
                sysmon-lab.xml
configs/        attribution-defaults.json, tuned settings files, tuning procedure
docs/           TESTING.md (automated tests, lab runs, acceptance checks)
samples/        make_sample.py (synthetic evidence for development and tests)
tests/          end-to-end tests
```
