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

> Status: v0.7.1 (22 Nov 2026). The pipeline runs on real lab evidence (Windows 11 24H2 VM,
> Nov 2026). v0.4 added the attribution engine, v0.5 causal reconstruction, v0.6 a checkable
> local-model layer (schema-constrained replies, entity-checked summaries, a pinned model,
> `ptir explain`). v0.7 adds the analyst views (attack flow, timeline, evidence, raw records),
> a STIX 2.1 export tagged with MITRE ATLAS and ATT&CK, Docker Compose, and a relationship check
> that drops summary sentences whose claims do not match the graph. On the 33 lab runs (v0.6.0):
> localization F1 1.0, chain edge F1 1.0, link precision 1.0, attribution macro-F1 0.99, two of
> two tampered traces detected, no finding on any of the 21 runs without an attack. Local-model
> summaries: 1 of 75 sentences unsupported with the v0.6 checks, 16 of 75 once wrong relations
> count (v0.7 check), 0 after validation; the v0.7 prompt brings the training split to 0.113 (v0.7.1
> fixes under measurement). Submission deadline: 29 Nov 2026, 23:59. See
> [ROADMAP.md](ROADMAP.md), [docs/TESTING.md](docs/TESTING.md), dataset progress in
> [docs/DATASET_PROGRESS.md](docs/DATASET_PROGRESS.md) (30 of 30 slots, 33 scored runs) and
> [What is not built yet](#what-is-not-built-yet).

---

## Install

```bash
git clone <repo> && cd prompttracir
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[evtx,stix,dev]"
pytest -q                                               # no model or VM needed
```

Python 3.10+. The analyst machine can be Linux, macOS or Windows; only the lab VM has to be Windows.

### Docker (v0.7)

```bash
CASE=./cases/demo docker compose up --build ui           # UI on http://127.0.0.1:8000
CASE=./cases/demo docker compose run --rm ui ptir export-stix /case --validate
# pinned local model (configs/local-model.json); put the GGUF in ./models as model.gguf
docker compose --profile llm up -d model
CASE=./cases/demo docker compose run --rm ui ptir explain /case --llm-url http://model:8080
```

`CASE` must be the folder that holds `case.json` (for a lab run, `runs/<run>/case`); Docker
creates a missing folder empty, and the UI then exits with "no case at /case". A case made on
Windows works as it is. The case folder is mounted read-write at `/case` (verifying hashes adds
custody entries). Ports
bind to 127.0.0.1 only: the UI has no login. `MODELS`, `MODEL_FILE`, `LLM_THREADS`, `PTIR_PORT`
and `LLM_PORT` override the defaults in `docker-compose.yml`.

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
ptir export-stix cases/demo --validate                   # cases/demo/output/stix_bundle.json
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
| `ptir serve CASE [--host H] [--port P]` | Analyst UI (below). |
| `ptir export-stix CASE [--out F] [--validate]` | (v0.7) STIX 2.1 bundle of the analysis, tagged with MITRE ATLAS / ATT&CK techniques; `--validate` runs the OASIS validator (`pip install -e ".[stix]"`). Extension properties: [docs/STIX_EXTENSION.md](docs/STIX_EXTENSION.md). |
| `ptir eval CASE GROUND_TRUTH` | Score the case against harness ground truth. |
| `ptir eval-batch ROOT [options]` | Score every analysed run under `ROOT` and write `results.json` and `per_run.csv`. `--families` / `--exclude-families` pick a split; `--without KIND`, `--config F` or `--tag T` re-analyse every run into `output/<tag>/` first (ablations, tuning); `--localizer heuristic-v01` scores the frozen v0.1 cue-only baseline. |
| `ptir explain CASE_OR_ROOT --llm-url URL` | (v0.6) Run only the local-model layer on analysed case(s): a verdict per deviating tool call and a grounded summary, into `llm.json`. `--families` picks the training split; `eval-batch` then reports unsupported claims before and after validation. `--timeout S` per model request (default 1800). |
| `ptir explain CASE_OR_ROOT --revalidate` | (v0.7) Re-check the stored summaries with the current validation (IDs, entities and relations) without calling the model; the previous summary is kept in `llm.json` as `summary_before_revalidation`. |
| `ptir llm-pin` | Print the pinned local model, quantisation, server command and sampling (`configs/local-model.json`). |

`analyze` options:

* `--replay-url URL --replay-model M [--samples N]` counterfactual replay against the same local model the agent used (leave-one-out, or group search for long contexts). Without a recorded request (Claude Code) the request is rebuilt from the trace and the results count half. Without `--replay-url`, the model-free segment localizer is used and its edges are marked as weaker.
* `--localizer auto|segment|heuristic|heuristic-v01|replay|group` pick the traceback method (`heuristic` scores whole fragments by instruction cues only; `heuristic-v01` does so with the v0.1 cue list, frozen, as the report's baseline).
* `--llm-url URL --llm-model M` local-LLM intent classification and an evidence-cited summary (v0.6: schema-constrained, with entity-level validation; settings from `configs/local-model.json`).
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
| `file_inventory` | `evidence/file_inventory.json` from `collect-run.ps1` (v0.5) | size and SHA-256 of files in the scenario folders at collection time; gives impact the file size without KAPE |
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
| `findings.json` | Scope violations: out-of-scope files, external egress, persistence, credential access; transcript mismatches and untraced agent processes (v0.5) |
| `impact.json` | Exfiltration level per destination with reasons |
| `attribution.json` | agent / human / mixed / unknown per process, with the weighted signals behind each label, `agent_probability`, and the logs that saw the process. The agent runtime itself (e.g. the harness's `python.exe`) is identified through its session in `correlation.json` and has no row here; a run whose agent made no shell call therefore has no "agent" row. |
| `tool_links.json` | Tool call to process links with scores |
| `correlation.json` | Per agent session: how the runtime process was found (PID, GUID or inferred) and the trace-to-host clock offset |
| `config.json` | The settings used, their fingerprint, evidence kinds used and any `--without` |
| `traceback.json` | What the localizer (segment, replay, group search) tested and found, with spans |
| `crosscheck.json` | Transcript cross-check: each tool call's command against Sysmon / 4688 and memory, and shells the runtime started that the trace does not mention (v0.5) |
| `graph_reduced.json` | The attack chain plus one hop around it, for large cases (v0.5) |
| `llm.json` | LLM classifications, validated summary, unsupported-claim rate by reason (`relation_not_in_graph` since v0.7), and the model pin, served model and prompt version (v0.6) |
| `stix_bundle.json` | STIX 2.1 bundle from `ptir export-stix` (v0.7) |

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
               api.py + web/index.html (attack flow, graphs, timeline, evidence)
               stix.py (STIX 2.1 export, ATLAS / ATT&CK tags)
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

### Analyst UI (`ptir serve`)

One page (`prompttracir/web/index.html`, Cytoscape vendored under `web/vendor/`, so it works
offline). The sidebar shows the entry point, impact, findings and the validated local-model
summary with the sentences validation dropped and why. Tabs:

| Tab | Shows |
|---|---|
| Attack flow | User request, then the entry point with the injected text, then each tool call with the processes it ran, its effects (each with its evidence state) and findings; the first deviation is outlined |
| Chain graph / Full graph | The provenance graph; edges coloured by evidence state (corroborated, observed, inferred dashed, contradicted), processes outlined by attribution |
| Timeline | Every canonical event; filter by source, text, or attack-chain membership; rows marked with the evidence state of the edges they support |
| Evidence | Preserved files with SHA-256, the custody log, and a "Verify hashes" button |

Clicking a step, node, edge, finding or timeline row lists its supporting records; clicking a
record opens the raw record read from the preserved copy (JSON line, CSV row with its header,
Zeek row, EVTX record, Volatility row). "Export STIX" downloads the bundle.

### Local-model validation (v0.6, v0.7)

A summary sentence is kept only if (1) every ID it cites exists, (2) every file, program, domain
or address it names appears in the cited nodes, and (3) since v0.7, its claims match the graph:
a sentence about the injection's origin must cite the entry-point fragment or its source, a
"first deviation" claim must cite the first deviating call, an effect it cites must be reachable
from the tool call or process it cites, and its verb must be something that actor can do (a
`read_file` call does not upload; a process cannot "create" a file it has no edge to). Since
v0.7.1 a denied action ("did not write") fails only if the graph shows it. The summary's context
leaves out what the agent runtime does for itself (traffic to `model_api_domains`, the harness's
source copies), marked `agent_internal` in the graph.

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
| Scenario schema, setup, labelling with ProcessGuid and sink window | done (v0.2) | 5 scenarios (v0.5 adds file change and download); dataset 30 of 30 slots, counted by outcome (`docs/DATASET_PROGRESS.md`) |
| Lab collection script (logs, pcap, SRUM, Prefetch, Amcache, hives, LNK, memory, KAPE) | done (v0.2), run on the lab VM (v0.3.1) | exports logs from boot; copies hive transaction logs |
| Sysmon / Security / PowerShell / PSReadLine / Zeek parsers | done | |
| Tool-to-process correlation, human/agent attribution | done (v0.4) | settings file, clock offset, 4688/4104 coverage, UserAssist / LNK / ShellBags / logon signals, Claude Code runtime inference, calibrated P(agent); weights not yet tuned on real runs |
| Provenance graph, backward/forward traversal | done | |
| Scope rules, first deviation, exfil impact | done | |
| Leave-one-out replay traceback | done | the real model followed the injection in 2 of 2 runs at temperature 0.7; replay fidelity is recorded per call (`baseline_survival`) |
| Local LLM classification + validated summary | done (v0.6), relation check (v0.7) | schema-constrained, entity- and relation-checked, pinned model; measured on the VM with the v0.6 and v0.7 prompts (ROADMAP v0.6 and v0.7 status); the v0.7.1 prompt still has to be measured |
| Analyst UI | done (v0.7) | single page + Cytoscape: attack flow, graphs, timeline, evidence, raw records; decided to keep it instead of React (ROADMAP section 6) |
| Docker Compose | done (v0.7) | `ui` and the pinned llama.cpp server (`--profile llm`); `ui` checked on Kali with a lab case, the model service not yet |
| MFT/USN, Prefetch, Amcache, SRUM, registry parsers | done (v0.3), checked on real output (v0.3.1) | EZ Tools CSV adapters, plus LNK / Jump Lists / ShellBags; `$MFT`/`$J` only with KAPE |
| Zeek DNS / HTTP, Security 4663 file reads | done (v0.3) | 4663 needs `tools/audit-canary.ps1` on the VM |
| Volatility 3 cross-check of the transcript | done (v0.5) | `crosscheck.py` compares the trace with Sysmon / 4688 and memory; processes from a finished run are usually gone from memory, so Sysmon carries most checks |
| AgentDFIR / OpenTelemetry trace adapters | done (v0.2) | Claude Code transcripts have no PIDs; signature check left to `agentdfir verify` |
| PromptLocate / TracLLM / AttnTrace modules | done (v0.5) except AttnTrace | segment (PromptLocate-style) and group search (TracLLM-style) localizers; AttnTrace needs attention weights an OpenAI-compatible server does not return |
| STIX 2.1 export with ATLAS tags | done (v0.7) | `ptir export-stix`; all 35 lab cases pass the OASIS validator |
| Multi-run evaluation | done (v0.2) | `ptir eval-batch` |
| Ablations | done (v0.4) | `ptir analyze --without KIND`, `ptir eval-batch --without KIND` |
| Baselines | **todo** | v0.8 |

## Repository layout

```
prompttracir/   schema, case, parsers/, correlate, graph, scope, impact, traceback, crosscheck, shellwrap, llm,
                pipeline, runs (add-run), adfir (import), batch (eval-batch), config, views, stix, api, cli, web/
harness/        agent.py (traced lab agent), scripted_model.py, scenario.py, exfil_sink.py, label_run.py,
                tamper_trace.py (edited-transcript test copies), scenarios/
tools/          collect-run.ps1, parse-artifacts.ps1, export-events.ps1, human-session.ps1, audit-canary.ps1,
                sysmon-lab.xml
configs/        attribution-defaults.json, local-model.json (pinned model and server), tuning procedure
docs/           TESTING.md (automated tests, lab runs, acceptance checks), DATASET_PROGRESS.md, STIX_EXTENSION.md
Dockerfile, docker-compose.yml   UI / CLI image and the pinned local model server (v0.7)
samples/        make_sample.py (synthetic evidence for development and tests)
tests/          end-to-end tests
```
