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

> Status: v0.2.0. The full pipeline runs end to end on synthetic evidence and on the formats
> listed below; lab tooling for real runs is in place. See [ROADMAP.md](ROADMAP.md),
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
| `ptir verify CASE` | Re-hash every preserved file. |
| `ptir serve CASE` | Analyst UI: attack-flow graph, findings, impact, timeline, raw records. |
| `ptir eval CASE GROUND_TRUTH` | Score the case against harness ground truth. |
| `ptir eval-batch ROOT` | Score every analysed run under `ROOT` and write `results.json` and `per_run.csv`. |

`analyze` options:

* `--replay-url URL --replay-model M [--samples N]` leave-one-out counterfactual replay against the same local model the agent used. Without it, a heuristic localizer is used and its edges are marked as weaker.
* `--llm-url URL --llm-model M` local-LLM intent classification and an evidence-cited summary.

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
| `security` | same | 4624 logons, 4688 process creation |
| `powershell` | same | 4104 script blocks |
| `psreadline` | `ConsoleHost_history.txt` | interactive command history (no timestamps) |
| `zeek_conn` | Zeek `conn.log` in JSON | connection byte counts |
| `agent_sources`, `evtx_raw`, `memory_image`, `pcap`, `srum`, `prefetch`, `amcache`, `registry_hive`, `mft`, `usn_journal`, `triage_archive`, `adfir_meta`, `other` | see `ptir kinds` | hashed and preserved, not parsed yet; `ptir ingest` picks them up once a parser exists |

## Outputs (`CASE/output/`)

| File | Contents |
|---|---|
| `graph.json` | Provenance graph: nodes, edges, evidence state, confidence, signals, supporting event IDs |
| `chain.json` | Entry points, first deviating tool call, the attack-chain node set |
| `findings.json` | Scope violations: out-of-scope files, external egress, persistence, credential access |
| `impact.json` | Exfiltration level per destination with reasons |
| `attribution.json` | agent / human / mixed / unknown per process, with the signals behind each label |
| `tool_links.json` | Tool call to process links with scores |
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
3. No single attribution signal decides a label. The weights are in `correlate.W`; tune them on
   training runs only and report them.
4. A connection alone is never confirmed exfiltration.

### Attribution signals (`correlate.py`)

| Signal | Side | Weight |
|---|---|---|
| process created by a tool call (PID/GUID match) | agent | 3.0 |
| descendant of such a process | agent | 2.5 |
| descendant of the agent runtime (python/node) | agent | 2.0 |
| non-interactive shell flags | agent (weak) | 0.5 |
| explorer / terminal ancestry without passing through the agent runtime | human | 2.0 |
| command appears in PSReadLine history | human (weak) | 1.0 |

Label is agent or human when one side leads by 1.5, mixed when both are high, otherwise unknown.

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
| Lab collection script (logs, pcap, SRUM, Prefetch, Amcache, hives, LNK, memory, KAPE) | done (v0.2) | not yet run on a real VM |
| Sysmon / Security / PowerShell / PSReadLine / Zeek parsers | done | |
| Tool-to-process correlation, human/agent attribution | done | add 4104, logon-type, UserAssist signals |
| Provenance graph, backward/forward traversal | done | |
| Scope rules, first deviation, exfil impact | done | |
| Leave-one-out replay traceback | done | needs real model runs to validate |
| Local LLM classification + validated summary | done | needs prompt tuning on real runs |
| Analyst UI | done (single page + Cytoscape) | proposal said React; either port or note the change |
| MFT/USN, Prefetch, Amcache, SRUM, registry parsers | **todo** | write adapters for EZ Tools CSV output |
| Volatility 3 cross-check of the transcript | **todo** | `windows.cmdline`, `windows.netscan`, memmap of the agent PID |
| AgentDFIR / OpenTelemetry trace adapters | done (v0.2) | Claude Code transcripts have no PIDs; signature check left to `agentdfir verify` |
| PromptLocate / TracLLM / AttnTrace modules | optional | add as further localizers in `traceback.py` |
| STIX 2.1 export with ATLAS tags | **todo** | |
| Multi-run evaluation | done (v0.2) | `ptir eval-batch` |
| Baselines, ablations | **todo** | v0.4 adds `--without KIND`; baselines in v0.8 |

## Repository layout

```
prompttracir/   schema, case, parsers/, correlate, graph, scope, impact, traceback, llm, pipeline,
                runs (add-run), adfir (import), batch (eval-batch), api, cli, web/
harness/        agent.py (traced lab agent), scenario.py, exfil_sink.py, label_run.py, scenarios/
tools/          collect-run.ps1, export-events.ps1, human-session.ps1, sysmon-lab.xml
docs/           TESTING.md (automated tests, lab runs, acceptance checks)
samples/        make_sample.py (synthetic evidence for development and tests)
tests/          end-to-end tests
```
