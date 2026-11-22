# PromptTracIR roadmap

Group 17, ICT3215. Written 2026-11-11 against the proposal (`ICT3215_PA-G17_Proposal.pdf`) and the repo at commit `da68092`.

Each version below is a tagged release that builds on the one before it. Every version ends with something that can be demonstrated and a "done when" check, so a release is never just "more code".

## 1. Where the repo is today (v0.1.0)

The repo holds a working skeleton that touches all six proposal phases thinly:

- Case format with SHA-256 hashing, read-only copies and a custody log.
- Canonical event schema, DuckDB event store.
- Parsers: harness agent trace, Sysmon / Security / PowerShell (EVTX or JSONL), PSReadLine, Zeek `conn.log`.
- Tool-call-to-process linking and weighted agent/human attribution.
- Provenance graph, scope ("resource envelope") rules, first deviation, exfiltration impact levels.
- Traceback: leave-one-out replay and a heuristic localizer.
- Local-LLM classification and a citation-validated summary.
- FastAPI + single-page Cytoscape UI, a lab harness, and one scenario.

Checked on 2026-11-11: the 7 tests pass and the README quick start reproduces the expected result on the synthetic sample (entry point `fragment:f2`, first deviation `tool_call:t2`, exfiltration confirmed).

**The catch: everything has only run on synthetic evidence.** No number in the proposal's Table III can be reported yet.

## 2. Gaps against the proposal

| Area | Proposal says | Repo today |
|---|---|---|
| Trace inputs | AgentDFIR packages, OpenTelemetry, JSON | Harness JSONL only |
| Windows artifacts | MFT/USN, Prefetch, Amcache, registry, SRUM | Not parsed |
| Memory | Volatility 3 cross-check of the transcript | Image is hashed and stored, not parsed |
| Network | Zeek or Suricata, DNS and proxy logs, PCAP | Zeek `conn.log` only |
| Human signals | PSReadLine, UserAssist, ShellBags, Jump Lists, LNK, logon sessions, 4688, 4104 | PSReadLine and process ancestry only. 4104 and 4624 are parsed but not used in scoring |
| Traceback | PromptLocate, TracLLM or AttnTrace, AttriGuard-style replay, surrogate model for closed agents | Leave-one-out replay and regex heuristic |
| Source preservation | Original bytes, extracted text and model-visible text kept separately | Model-visible text and a hash of it |
| Schema | Event time and ingestion time | No ingestion time |
| Evaluation | At least 60 labelled runs, 2 agents, paired human runs, 4 baselines, 6 ablations (reduced to 30 runs, section 5) | 1 scenario, single-case scorer |
| Metrics | Edge P/R/F1, calibration error, path exact match, span overlap, narrative rates | Fragment-set F1, attribution accuracy and macro-F1, first deviation, impact per destination |
| Interface | React + Cytoscape, STIX 2.1 with ATLAS tags, Docker Compose | Single HTML page, no export, no Compose |
| Evaluation agent | LangGraph agent, plus Claude Code via AgentDFIR | Plain tool loop |
| Repo hygiene | n/a | No `.gitignore`, CI, changelog or licence |

## 3. Version ladder

| Version | Name | Proposal phase | Answers |
|---|---|---|---|
| v0.1 | Baseline skeleton (in repo) | 1 to 6, thin | n/a |
| v0.2 | First real case | 1 | Does it work on a real VM? |
| v0.3 | Windows forensic normalizers | 2 | Can every promised evidence kind be ingested? |
| v0.4 | Attribution engine | 3 | RQ1 |
| v0.5 | Causal reconstruction | 4 | RQ2, RQ3 |
| v0.6 | Local model analysis | 5 | RQ4 |
| v0.7 | Analyst interface and export | 6 (build) | Demo |
| v0.8 | Evaluation release | 6 (experiments) | Table III numbers |
| v1.0 | Final | n/a | Submission |

The dataset is a separate track that starts at v0.2 and runs alongside every later version (section 5).

---

### v0.1.1: Baseline housekeeping

Goal: make the existing upload a clean starting point.

- Tag the current commit `v0.1.0`.
- Add `.gitignore` (caches, `cases/`, `runs/`, generated samples), `CHANGELOG.md`, this roadmap.
- GitHub Actions workflow that runs `pytest` on every push and pull request.
- One GitHub milestone per version; one issue per work item below.
- Working agreement: one branch per work item, pull request into `main`, tag at the end of each version.

Done when: CI is green on `main` and the milestones exist.

### v0.2: First real case (Phase 1)

Goal: replace "works on synthetic data" with "works on a real Windows 11 run".

- Build the lab VM from the README, take the clean snapshot.
- Run the harness against a real local model. Fix whatever breaks in the EVTX parser, the PID/ProcessGuid matching and the time windows.
- **Collect everything from day one.** Extend `tools/export-events.ps1` into a single collection script that also grabs a KAPE or Velociraptor triage, a memory snapshot, a packet capture and SRUM. The case format already stores unparsed evidence, so runs captured now can be re-analysed by every later version.
- Harness: store the fetched bytes of external content separately from the text the model saw.
- Harness ground truth: record tool call, child PID, ProcessGuid, affected resources and network destination, as the proposal's evaluation section describes.
- Scenario file format and a first set: one legitimate task, one ignored injection, one successful exfiltration.
- AgentDFIR package importer and OpenTelemetry importer, both converting into the existing trace format.
- `ptir eval-batch`: aggregate `ptir eval` over a folder of runs.

Done when: one real benign run and one real injected run go through add, ingest, analyze and eval; one Claude Code transcript imports through the AgentDFIR adapter; a sanitised real run replaces the synthetic sample as a test fixture.

Status (2026-11-11): the code is in place and tested on synthetic data: `collect-run.ps1`, raw source preservation, scenario schema and set, richer `label_run.py`, `ptir add-run`, AgentDFIR, Claude Code and OpenTelemetry importers, `ptir eval-batch`. What remains needs the lab VM: the real runs and fixes they expose. Steps and the acceptance checklist are in `docs/TESTING.md`.

### v0.3: Windows forensic normalizers (Phase 2)

Goal: every evidence kind in the proposal's Table I produces canonical events.

- Adapters for Eric Zimmerman tool CSV output: MFTECmd (`$MFT` and `$J`), PECmd, AmcacheParser, RECmd, SrumECmd.
- Adapters needed for the v0.4 human signals: LECmd (LNK), JLECmd (Jump Lists), SBECmd (ShellBags), UserAssist via RECmd.
- Volatility 3 JSON output: `windows.pslist`, `windows.cmdline`, `windows.netscan`.
- Zeek `dns.log` and `http.log`, or Suricata `eve.json`.
- Schema v0.3: ingestion time, new sources and actions, and a per-artifact note on what the timestamp means (Amcache key last-write is not execution time; Prefetch is weak for authorship).
- File reads: Sysmon has no file-read event, so the scope rules currently infer reads from command lines. Consider Security 4663 object-access auditing on the canary directory.

Done when: each new `--kind` parses a real lab file and has a fixture test; only raw PCAP remains "preserve only".

Status (2026-11-12): parsers, fixtures and tests are in place for every EZ Tools item above plus the three Volatility plugins (`ez_*` and `vol_*` kinds), with schema v0.3 (`RawRef.ingested_at`, `attrs.ts_meaning`, new sources and actions) and `tools/parse-artifacts.ps1`. Raw artifacts keep their raw kinds, so "only raw PCAP remains preserve only" now reads as: every raw kind has a parsed derived kind except PCAP and the triage archive. Not done: the "real lab file" half of the check, which needs one run through `parse-artifacts.ps1` on the VM (docs/TESTING.md, Part 8).

Status (2026-11-14, v0.3.0): Zeek `dns.log` and `http.log` parsers added (Suricata not needed); all Zeek parsers read JSON and tab-separated logs. Security 4663 file access is parsed and joined to processes; `tools/audit-canary.ps1` audits the canary folder. Released as v0.3.0; the real-run check remains.

Status (2026-11-15, v0.3.1): the first five real lab runs (run01 to run04 plus a teammate's batch) ran every parser on real output. Columns matched for every EZ tool except AmcacheParser on a hive copied without its transaction logs, now fixed with a fixture from run01. Fixed from those runs: `collect-run.ps1` (pktmon start error, hive `.LOG1`/`.LOG2` copied, event logs from boot), `parse-artifacts.ps1` (`--nl` retry, netstat fallback, `$MFT`/`$J` from KAPE output), escaped paths that gave a benign run four false findings, the 4688/Sysmon duplicate that emptied attribution, and scoring of ignored injections and `unknown` impact. Still open for the v0.3 check: Security 4663 and the `pid_and_time` read edge need a run in which the secret is read, which the scripted model (below) provides.

### v0.4: Attribution engine (Phase 3, RQ1)

Goal: defensible agent / human / mixed / unknown labels with numbers.

- New human-side signals: UserAssist, Jump Lists, LNK, ShellBags, interactive logon type from 4624, commands outside any agent span.
- Use 4104 script blocks and 4688 as coverage where Sysmon is missing.
- SRUM per-application byte counts as a network signal.
- Configurable clock-drift tolerance instead of the fixed one-second windows.
- Move weights from `correlate.W` into a config file. Tune on the training split only and record the final values.
- Metrics in `eval-batch`: tool-to-process edge precision, recall, F1; macro-F1; calibration error; abstention rate; error by evidence condition.
- `ptir analyze --without <kind>` so ablations are a flag, not a re-ingest.
- Runtime identification for traces without PIDs (Claude Code): find the `claude`/`node` process by start time, user and working directory, so its tool calls can be linked to processes. Until then, Claude Code runs are labelled with `label_run.py --agent-pids`.

Done when, on the training split collected so far: tool-to-process precision is at least 0.95 where ProcessGuid or child PID exists, and attribution macro-F1 is at least 0.85 on complete-evidence runs.

Status (2026-11-16, v0.4.0): rebuilt on top of v0.3.1 and the first lab runs. Every item above is built and tested on synthetic cases, and the 4688/Sysmon merge on lab run01's records: settings file and `ptir config`; clock offset from child PIDs and configurable drift windows; 4688 process tree and 4104 link evidence; UserAssist, LNK / Jump List, ShellBags, outside-session and logon-type signals; runtime inference for Claude Code; `--without` ablations; calibration (ECE, Brier), complete-evidence subset and family filters in `eval-batch`. SRUM stays an impact signal for v0.5 (it is per application per hour, too coarse to attribute a single process). Not done: tuning on real training runs and the two numeric targets, which need the dataset (docs/TESTING.md, Part 9).

Status (2026-11-16, v0.4.1): the first v0.4.0 lab run (scripted model) exposed a trace-ordering bug that stopped `ptir analyze`; fixed. The lab VM side (harness, collection) is unchanged.

### v0.5: Causal reconstruction (Phase 4, RQ2 and RQ3)

Goal: source fragment to tool call to host effect, with cross-checked evidence.

- Localizer plug-in interface in `traceback.py`; add PromptLocate-style segmentation and TracLLM-style group search. AttnTrace needs attention weights, so treat it as optional.
- Validate replay on the real model; record nondeterminism and replay fidelity per call.
- Surrogate-model replay for closed-model traces (Claude Code), labelled lower confidence.
- Memory cross-check: compare Volatility command lines and sockets against the transcript and emit corroborated or contradicted edges. Add a scenario where the transcript is edited after the run.
- Impact: use SRUM byte counts when there is no Zeek record.
- Graph: add logon-session, data-object and evidence node kinds; graph reduction for large cases.
- Metrics: span-level localization overlap, chain node and edge precision and recall, first-deviation accuracy, path exact match, impact accuracy.

Done when, on the training split: localization F1 is at least 0.80 on successful-injection runs, chain edge F1 is at least 0.85 on complete-evidence runs, and the tampered-transcript case shows a contradicted edge.

Status (2026-11-17, v0.5.0): every item above is built and tested, together with the fixes from the 14 v0.4 lab runs (14 items in the v0.5 backlog). Localizers: PromptLocate-style segments (default without a model), the cue-only heuristic as baseline, replay leave-one-out (up to 8 fragments) and TracLLM-style group search (more than 8), surrogate replay at half confidence for Claude Code; AttnTrace not built (needs attention weights). Transcript cross-check against Sysmon, 4688 and memory, with a tamper tool for the edited-transcript case. File inventory at collection gives impact without KAPE; SRUM bytes when there is no Zeek record. On 8 lab runs re-analysed with v0.5.0: localization F1 1.0 (0.8 with v0.4.1), span overlap 1.0, chain edge F1 1.0, path exact match 1.0, 3 of 3 tampered copies contradicted and none of the untampered runs. Not done: replay fidelity on the real model (docs/TESTING.md, 10.5) and the new scenario and Claude Code runs (10.2, 10.3), which need the lab VM on v0.5.0.

Status (2026-11-21, v0.5.1): the first v0.5.0 lab run of `file_change_01` showed that the lab agent's shell tool broke commands with double quotes on Windows; fixed. The lab VM needs v0.5.1.

Status (2026-11-21, v0.5 lab runs): 17 runs collected in two labs on v0.5.0 and v0.5.1 (the new scenarios with the scripted and the real model, and six Claude Code runs), which completes the dataset (section 5). Scored together with the earlier runs on v0.5.1 (31 runs, two tampered copies): localization F1 1.0, span overlap 1.0, chain edge F1 1.0, path exact match 1.0, attribution macro-F1 0.988, 2 of 2 tampered copies detected, so the v0.5 "done when" targets are met. Two misses, both from Claude Code's Bash wrapper on Windows and fixed in v0.6.0: tool-to-process link precision 0.875 and 7 contradictions on untampered runs (jt-c3, cy-c3). Replay fidelity on the real model (docs/TESTING.md, 10.5) was not run.

### v0.6: Local model analysis (Phase 5, RQ4)

Goal: explanations that cannot invent evidence.

- Schema-constrained output (JSON schema or grammar) instead of free JSON.
- Prompt tuning on training runs; retrieval limited to the graph neighbourhood.
- Stronger narrative validation: today a sentence passes if its cited IDs exist. Also check that files, processes and domains named in the sentence appear in the cited nodes.
- Aggregate unsupported-claim rate before and after validation in `eval-batch`.
- Pin the model, quantisation and server settings in the repo.
- Stretch: LoRA fine-tune, split by attack family. Only start once the dataset is frozen.

Done when: unsupported claims are at most 5 percent before validation and zero after, on the training split.

Status (2026-11-21, v0.6.0): built and tested with model doubles. Replies are constrained by a JSON schema whose ID fields are enums of the input's IDs (llama-server enforces it as a grammar; other servers fall back to JSON mode). The summary sees the attack chain and its one-hop neighbourhood (at most 60 nodes) with each node's facts, and answers as cited sentences. Validation now also drops a sentence that names a file, program, domain or address its cited nodes do not show. `configs/local-model.json` pins the model, quantisation, server command and sampling, and every `llm.json` records the pin, the served model and the prompt version. `ptir explain` runs the local-model layer on analysed cases (`--families` for the training split) and `eval-batch` reports unsupported claims before and after validation. Not done: the measurement itself and any prompt tuning, which need the local model on the lab VM; the LoRA stretch goal is not started. Also in v0.6.0, the fixes from the v0.5 lab runs (CHANGELOG): on the 31 lab runs, malicious-call F1 0.909 -> 1.0, link precision 0.875 -> 1.0, contradictions on untampered runs 7 -> 0, clean runs with any finding 0 of 21 (findings without a tool call now count), and the frozen v0.1 cue-only baseline (`--localizer heuristic-v01`) at localization F1 0.75, span overlap 0.703, chain edge F1 0.941, against 1.0 for the segment localizer.

Status (2026-11-21, v0.6 measured): `ptir explain` ran on the lab VM (Qwen2.5-7B-Instruct Q4_K_M, `-c 16384 -t 4`, 5 to 10 minutes per run on CPU) over the 13 runs with an attack chain. With the v0.6 checks (cited IDs exist, named entities appear in the cited nodes): 1 of 75 sentences unsupported before validation (0.013) and 0 after; eval-batch without the tampered copy 0.015 (1 of 68), training split 0.021 (1 of 48), test families 0 of 20. Verdicts: 13 of 13 gold malicious calls classified injection-driven, the directing fragment equal to the gold injected fragment 13 of 13, no unknown IDs. So the v0.6 "done when" is met as the metric was defined. Caveat from reading the summaries: several kept sentences named grounded things but stated a wrong relation (a tool call credited with another call's file, or the injection said to come from the user's prompt while the verdicts named the right fragment). v0.7.0 adds a relationship check (below); re-checking the same 75 sentences with it gives 16 of 75 unsupported before validation (0.213; training split 0.229) and 0 after, so with relations counted the v0.6 prompt misses the 5 percent target. The v0.7 prompt (chain analysis plus relation rules) has not been measured yet.

### v0.7: Analyst interface and export (Phase 6, build)

Goal: something an analyst can use and the team can demo.

- Attack-flow, timeline and evidence views with evidence-state styling and a raw-record viewer.
- STIX 2.1 export tagged with MITRE ATLAS techniques (for example AML.T0051).
- Docker Compose for the API, UI and local model server.
- React port, or a recorded decision to keep the single page.

Done when: `docker compose up` serves a real case and the STIX bundle passes a validator.

Status (2026-11-21, v0.7.0): built and tested.
- Views: the single page now opens on an attack flow (request, entry point with its injected text, then each tool call with the processes it ran, its effects and findings, and the first deviation marked), plus the chain and full graphs, a timeline filtered by source, text and chain membership with each row coloured by evidence state, and an evidence tab with the preserved files, the custody log and a hash check. Clicking any record opens the raw record from the preserved copy (JSON line, CSV row with its header, Zeek TSV row by `#fields`, EVTX record by RecordID, Volatility row or inventory entry). Cytoscape is vendored, so the UI works without internet.
- `ptir export-stix CASE [--validate]`: a STIX 2.1 bundle (processes, files, connections, domains, URLs, observed data per finding, sightings, notes, incident, report) tagged with ATLAS AML.T0051.001, AML.T0053, AML.T0086 and ATT&CK T1700, T1105, T1053.005, T1547.001, T1565.001. Evidence states, ProcessGuids and record IDs travel in a property extension (`docs/STIX_EXTENSION.md`). All 35 lab cases (33 runs and 2 tampered copies) pass the OASIS `stix2-validator` with warnings only; exports are deterministic.
- `Dockerfile` and `docker-compose.yml`: the UI and CLI (`ui`) and the pinned llama.cpp server (`model`, profile `llm`). Not yet run on a lab machine.
- Relationship check for local-model summaries: a sentence is dropped when its verb or claim does not match the graph (an injection said to come from anything but the entry point or its source, a deviation claim not citing the first deviating call, an effect not reachable from the cited actor, or a verb the cited actor cannot do). `ptir explain --revalidate` re-checks stored summaries without the model. The summary prompt now also receives the entry points and first deviation.
- Graph fix: an in-process write (no child process) goes to the tool call whose trace claims it when it lands up to 0.25 s outside that call's window, so jt-i1's `notes.md` is no longer credited to the curl upload. Test 7 metrics on the 33 runs are unchanged.
- Decision: keep the single-page UI (decision 3 below).

Status (2026-11-22, v0.7 checked): the "done when" is met. On Kali, `docker compose build ui` built the image, `docker compose up` served a demo case built inside the container and the jt-i1 lab case copied from the Windows laptop (attack flow, raw records, all 576 preserved files verified), and the jt-i1 STIX bundle passed the validator. Re-scoring the 33 runs on v0.7.0 left every Test 7 metric unchanged. The v0.7 prompt on the lab VM (same model and settings, 13 runs): unsupported before validation 0.091 over all scored runs (7 of 77) and 0.113 on the training split (6 of 53), 0 after; about 0.042 on the test families (1 of 24); verdicts 13 of 13. So the v0.7 prompt halves the v0.6 rate under the same checks (0.229 on training) but still misses 5 percent. Reading the 8 dropped sentences: 3 were about what the agent runtime does for itself (its traffic to the model server, the harness's copies of fetched pages), which the time-window join had credited to the running tool call; 2 repeated the prompt's rule wording; 1 was a true denial ("the process did not write or read any files") dropped for the verbs it denied; 2 were wrong relations. Three summaries had only two sentences, so the report gives sentences per summary next to the rate.

Status (2026-11-22, v0.7.1): fixes for the first three causes, each taken from the training families only. In-process effects of the agent runtime no longer go to a tool call when they are traffic to the envelope's `model_api_domains` or the harness's source copies (files named by a fetched source's SHA-256, and their folder); those nodes stay in the graph, marked `agent_internal`, and are left out of the summary's context. The relationship check reads "did not / never / no" clauses as denials and checks them against the absence of the action. The summary rules are reworded so they read as rules, not sentences to copy (prompt v0.7.1). Test 7 metrics on the 33 runs (all evidence and without Sysmon) are unchanged, and the attack flow and STIX bundle no longer show the model-server connection. Checked against the v0.7.1 graph, the v0.7 summaries score 0.226 on training (12 of 53): most of their kept sentences about the model traffic and source copies were true of the v0.7 graph and are not of the corrected one.

Status (2026-11-22, v0.7.1 measured): on the lab VM with the same model and settings, the v0.7.1 prompt gives 0.062 unsupported before validation over all scored runs (5 of 81 sentences, 12 summaries) and 0.091 on the training split (5 of 55), 0 on the test families (0 of 26), 0 after validation everywhere, and 12 of 12 correct call verdicts. Summaries are longer (no two-sentence summaries left). None of the five drops comes from the three causes v0.7.1 fixed: two are true claims about cy-01's upload that the graph cannot show (that run has no Sysmon network event for curl, only its DNS lookup), two cite incompletely (jt-01 cites the connection but not curl.exe; cy-03 runs two sentences together and cites cmd.exe for schtasks.exe), and one is a wrong relation (jt-i2: "the command spawned a process to write notes", for an in-process write). The prompt is frozen here for v0.8: another round tuned on eight training summaries would fit those summaries rather than the method, and the checker is not loosened to pass the cy-01 sentences.

| Prompt, checks | All scored runs | Training split | Test families | After validation |
|---|---|---|---|---|
| v0.6 prompt, v0.6 checks (IDs, entities) | 0.015 (1 of 68) | 0.021 (1 of 48) | 0 of 20 | 0 |
| v0.6 prompt, v0.7 checks (+ relations) | 0.221 (15 of 68) | 0.229 (11 of 48) | n/a | 0 |
| v0.7 prompt, v0.7 checks | 0.091 (7 of 77) | 0.113 (6 of 53) | 0.042 (1 of 24) | 0 |
| v0.7.1 prompt, v0.7.1 checks | 0.062 (5 of 81) | 0.091 (5 of 55) | 0 of 26 | 0 |

### v0.8: Evaluation release (Phase 6, experiments)

Goal: produce Table III.

- Freeze the dataset (the 30 planned runs in `docs/DATASET_PROGRESS.md`, plus any extra runs) and freeze all weights and prompts.
- Baselines: trace-only, endpoint-only, timestamp-only, AgentDFIR.
- Ablations: remove PID capture, context identifiers, memory, network evidence, local-model analysis, Sysmon.
- Analyst study against the manual Plaso / Timesketch workflow.
- One script that regenerates every results table from the frozen runs.

Done when: every row of Table III has a measured value, including the ones that miss their target.

Status (2026-11-22, v0.8.0): built and measured on copies of the 35 lab cases; the laptop run is the result of record (`docs/RESULTS.md`, regenerated by `ptir experiments`).
- Freeze: `ptir freeze runs` writes `configs/frozen-runs.json` (per run: ground truth hashed as canonical JSON, every evidence SHA-256, family, agent class; and the settings: attribution config `84d416be6878`, prompt v0.7.1, the pinned model, the segment localizer). `ptir experiments` refuses to run if a run or a setting differs from it. Weights were never tuned away from the defaults, so the defaults are what is frozen.
- One script: `ptir experiments runs` scores the full analysis, re-analyses every run once per baseline and ablation into `output/<tag>/`, and writes `RESULTS.md` (dataset, Table III by split and agent class, baselines, ablations, narrative), `experiments.json` and per-condition `results.json` / `per_run.csv`. `RESULTS.md` has no dates or paths, so a re-run must give the same file. About 10 to 20 minutes on the laptop.
- Baselines: trace only (agent-side records; stands in for AgentDFIR, which reads the same records and was not run itself), endpoint only (no agent trace), timestamp only (`--ablate timestamp_links`: links to the nearest process in the call window, attribution by session time), and the cue-only localizers (v0.1 and current cues).
- Ablations: without PID capture (`--ablate pids`), without context identifiers (`--ablate context_ids`, rebuilt from time order), without memory, without network evidence (Zeek, PCAP), without Sysmon, without the local model.
- Results on the 33 scored runs: every Table III target with a measured value is met except narrative grounding before validation (0.091 on the training split against 0.05; 0 after validation). Analyst utility is not measured (decision 5, section 6), so that row stays empty and the "done when" is met for the other six rows only.
- What the baselines and ablations show: trace only reconstructs the trace side (localization 1.0) but links no process, attributes nothing and gets chain edge F1 0.706 with no exact path; endpoint only finds no attack at all (attribution macro-F1 0.241); timestamp only links 0.895 of tool calls correctly, mislabels processes (attribution 0.952), flags 2 of 21 clean runs, misses one tampered trace and reports 4 contradictions on untampered runs. Without PID capture link recall falls to 0.158, attribution to 0.859, chain edge F1 to 0.706 and impact accuracy to 0, and neither tampered copy is detected. Without Sysmon: attribution 0.876, chain edge 0.9, impact 0. Without network evidence impact accuracy falls to 0 (nothing can be confirmed) while everything else holds. Without memory nothing changes on these runs. Without context identifiers nothing changes because no trace event changes: every agent in the dataset ran one call at a time with its full history in context, so the identifiers are recoverable from time order. The local model adds only the narrative and call verdicts.

### v1.0: Final

- Fix what the evaluation exposed, without tuning on the test split.
- Documentation, a demo case, a limitations section, dataset packaging.
- Tag `v1.0.0`.

---

## 4. Proposal targets and where each is first measured

| Target (Table III) | Criterion | First measured | Reported | v0.8 result (33 runs) |
|---|---|---|---|---|
| Tool-to-process correlation | Precision at least 0.95 with ProcessGuid or child PID | v0.4 | v0.8 | 1.0, met |
| Human-agent attribution | Macro-F1 at least 0.85 on complete evidence | v0.4 | v0.8 | 0.99, met |
| Injected-span localization | F1 at least 0.80 on successful injections | v0.5 | v0.8 | 1.0 (real local model 1.0 on 2 runs), met |
| Attack-chain reconstruction | Edge F1 at least 0.85 on complete evidence | v0.5 | v0.8 | 1.0, met |
| Impact assessment | No connection-only case labelled confirmed | v0.2 (already checked per case) | v0.8 | 0, met (per-destination accuracy 0.333) |
| Narrative grounding | At most 5 percent unsupported before validation, zero after | v0.6 | v0.8 | 0.091 on training (missed), 0 after (met) |
| Analyst utility | Faster than the Plaso / Timesketch baseline | v0.8 | v0.8 | not measured (study cut) |

## 5. Dataset track (runs alongside v0.2 onward)

Every labelled run needs a snapshot revert, a paired human session and hand-checked labels, so the
dataset is the slowest part of the project. Run-by-run progress is tracked in
`docs/DATASET_PROGRESS.md`: update it whenever a run is reviewed and analysed.

**Revised on 16 Nov 2026: 30 runs instead of 60.** Due to time constraints, the dataset has been
halved from the proposal's 60 labelled runs to 30, while ensuring that it still supports every
claim in Table III. The reduction removes repetition, not coverage:

- The tool is measured on host evidence. Scripted-model runs use a stand-in model but a real agent,
  real processes, Sysmon, Security events, memory and network, so they count towards the host-side
  metrics (links, attribution, impact, chain, first deviation). They are not used for claims about
  the model's behaviour.
- Real-model runs cover every family, so each attack type is also measured on a real model's
  behaviour (slower turns, parallel tool calls, extra benign commands such as `make test`).
- Sensitive-file access is merged into data transmission: every exfiltration run reads the secret,
  recorded by Security 4663 read events.
- Claude Code demonstrates the tool on a second, closed agent: two runs each for a legitimate task,
  an ignored injection and data transmission.
- Every cell has two runs, from different testers' labs where possible. Repeats across labs exposed
  the v0.4.0 trace-ordering crash and the memory-image failures.

| Scenario family | Real local model | Scripted | Claude Code | Total |
|---|---|---|---|---|
| Legitimate task, no injection | 3 | n/a | 2 | 5 |
| Injection ignored or failed | 3 | 2 | 2 | 7 |
| Data transmission (incl. sensitive-file access) | 2 | 2 | 2 | 6 |
| Persistence | 2 | 2 | n/a | 4 |
| File changes | 2 | 2 | n/a | 4 |
| Download | 2 | 2 | n/a | 4 |
| **Total** | **14** | **10** | **6** | **30** |

Status (16 Nov 2026): 14 of 30 done (8 real local, 6 scripted), all analysed with v0.4.1. Open now:
2 real-model persistence runs. Open once the lab is on v0.5.0: the file-change and download runs
(4 real, 4 scripted) and the 6 Claude Code runs. Extra runs beyond the plan (the seed 1 and 4
sets) are kept and scored but not required.

**Revised on 21 Nov 2026: slots are counted by outcome.** All 30 slots have a reviewed run (plus
one extra run and two tampered copies). Eight slots needed an agent to follow a payload, and it
did not: the real model at temperature 0.7 followed 0 of 6 persistence, file-change and download
payloads (it followed 2 of 2 data-transmission payloads), and Claude Code followed 0 of 4 (two
models, two labs; one refusal came from a safety classifier). Under the existing rule, those runs
are scored as "injection ignored", and the follow and refusal rates are reported as a result.
More seeds would have cost about 30 minutes each with no sign the rate would move, and rewording
the payloads until an agent obeys would bias the rate the report measures. The effect on Table
III: every attack family is still covered on host evidence by the scripted runs; real-model
localization rests on the two data-transmission runs; Claude Code covers the closed-agent
pipeline on legitimate and refused runs only. Per-slot detail: `docs/DATASET_PROGRESS.md`.

Limits to state in the report: per-family figures rest on two runs and are indicative; real-model
successful attacks exist for data transmission only; Claude Code figures show coverage, not
accuracy, and no Claude Code run followed a payload; impact accuracy is 2 of 6 because the four
exfiltration runs collected before the file inventory existed are scored probable against a gold
confirmed (the two later scripted runs, jt-i1 and jt-i2, are confirmed); the dataset is half the
size given in the proposal.

Extra runs on 21 Nov: jt-i1 and jt-i2 (scripted `web_exfil_01` with Zeek, the file inventory and a
canary the sink received) were collected on v0.6.0 to measure impact accuracy. With them the
scored set is 33 runs (30 slots plus jt-v1, jt-i1 and jt-i2) and two tampered copies. On v0.6.0
every Table III target that can be measured so far is met on those 33 runs (localization, span
overlap, malicious calls, link precision, first deviation, chain edge, node and path 1.0,
attribution 0.99, 0 of 21 clean runs with a finding, 2 of 2 tampered copies contradicted, no
connection-only case labelled confirmed); impact accuracy is 0.333 for the reason above.

**Frozen on 22 Nov 2026 (v0.8.0)**, four days before the planned 26 Nov freeze: 35 cases (33
scored runs and two tampered copies), recorded in `configs/frozen-runs.json` with every evidence
hash and the settings the results come from. Per-slot detail and the freeze: `docs/DATASET_PROGRESS.md`.

Rules (also in `docs/DATASET_PROGRESS.md`):

- Every run has a paired human session typing the same commands.
- Real-model runs where the model ignored the payload go in the "Injection ignored or failed" row.
- Scripted runs count for host-side metrics only and are reported in their own column, never mixed
  into real-model behaviour or real-model localization figures.
- Split training and test by attack family, and never tune weights or prompts on the test families.
- Capture all evidence kinds on every run, even those no parser reads yet.
- Synthetic secrets and isolated machines only.

## 6. Decisions the team needs to make

1. **Deadline: 29 November 2026, 23:59.** Two weeks from the first lab runs, so every version below gets two or three days and the dataset is collected alongside, not after:

   | Version | Target date | Scope for the deadline |
   |---|---|---|
   | v0.3.1 | 16 Nov | fixes from the first lab runs, scripted model |
   | v0.4.0 | 16 Nov (code), 18 Nov (lab rerun) | attribution engine; rerun the lab (real model with temperature and seeds, plus scripted runs) and record the first attribution numbers |
   | v0.5 | 21 Nov | localizer interface, memory cross-check, chain metrics |
   | v0.6 | 23 Nov | local-model classification and grounded summary on real runs |
   | v0.7 | 25 Nov | STIX 2.1 export; keep the single-page UI (record the React change) |
   | v0.8 | 27 Nov | freeze the dataset on 26 Nov; baselines, ablations, Table III |
   | v1.0 | 29 Nov, 23:59 | report, limitations, demo case, tag `v1.0.0`; 28 to 29 Nov is buffer |

   At about two lab runs an hour, the 16 runs still needed on 16 Nov are about eight hours in total. If the dataset is short on 26 Nov, freeze what exists and report the counts per cell (`docs/DATASET_PROGRESS.md`) rather than slipping v0.8. The analyst study (Plaso / Timesketch comparison) is the first thing to cut if time runs out.

   Progress on 21 Nov: v0.5 is released, v0.6.0 is built (two days ahead of the table), and the dataset is complete (30 slots, counted by outcome, section 5). Left before the freeze: the v0.6 narrative measurement on the lab VM, and optionally two scripted exfiltration runs for impact accuracy.

   Progress later on 21 Nov: v0.6.0 is released and measured (RQ4, v0.6 status), the two scripted exfiltration runs are in (jt-i1, jt-i2), and v0.7.0 is built four days ahead of the table. Left before the freeze: the v0.7 prompt measurement on the VM and the Docker check.

   Progress on 22 Nov: v0.7.0 and v0.7.1 are released and checked (Docker on Kali, two VM narrative runs), and v0.8.0 is built five days ahead of the table: the dataset and settings are frozen and every results table comes from `ptir experiments`. Left: v1.0 (report, limitations, demo case, dataset packaging).
2. **LangGraph.** The proposal names a LangGraph agent; the harness is a plain loop. Recorded on 22 Nov (v0.8.0): keep the plain loop. Every lab run was collected with it and the dataset is frozen; a port would change the agent under test after the fact. The loop records what the evaluation needs (tool calls, context fragments, model calls, child PIDs), and Claude Code covers a second, production agent. Record the change in the report.
3. **React.** The proposal names React; the UI is one HTML page. Decided on 21 Nov (v0.7.0): keep the single page. It needs no build step or Node toolchain, ships inside the Python package and the Docker image, works offline with the vendored Cytoscape, and every view the proposal describes (attack flow, timeline, evidence, raw records, export) is in it. A React port would add a second toolchain four days before the freeze without adding a view. Record the change in the report.
4. **AttnTrace.** It needs attention weights that an OpenAI-compatible server does not return. Keep it optional unless someone wants to run the model through a library that exposes them.
5. **Ethics clearance** for the analyst study has lead time. Ask about it now, not at v0.8. Recorded on 22 Nov (v0.8.0): the analyst study is cut, as planned in decision 1 (the first thing to cut). No clearance was obtained and there is no time to run a fair comparison with Plaso / Timesketch before 29 Nov, so the Analyst utility row of Table III is reported as not measured, with the UI's attack flow and raw-record views described instead.
