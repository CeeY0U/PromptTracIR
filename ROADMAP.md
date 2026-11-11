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
| Evaluation | At least 60 labelled runs, 2 agents, paired human runs, 4 baselines, 6 ablations | 1 scenario, single-case scorer |
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

### v0.6: Local model analysis (Phase 5, RQ4)

Goal: explanations that cannot invent evidence.

- Schema-constrained output (JSON schema or grammar) instead of free JSON.
- Prompt tuning on training runs; retrieval limited to the graph neighbourhood.
- Stronger narrative validation: today a sentence passes if its cited IDs exist. Also check that files, processes and domains named in the sentence appear in the cited nodes.
- Aggregate unsupported-claim rate before and after validation in `eval-batch`.
- Pin the model, quantisation and server settings in the repo.
- Stretch: LoRA fine-tune, split by attack family. Only start once the dataset is frozen.

Done when: unsupported claims are at most 5 percent before validation and zero after, on the training split.

### v0.7: Analyst interface and export (Phase 6, build)

Goal: something an analyst can use and the team can demo.

- Attack-flow, timeline and evidence views with evidence-state styling and a raw-record viewer.
- STIX 2.1 export tagged with MITRE ATLAS techniques (for example AML.T0051).
- Docker Compose for the API, UI and local model server.
- React port, or a recorded decision to keep the single page.

Done when: `docker compose up` serves a real case and the STIX bundle passes a validator.

### v0.8: Evaluation release (Phase 6, experiments)

Goal: produce Table III.

- Freeze the dataset at 60 or more labelled runs and freeze all weights and prompts.
- Baselines: trace-only, endpoint-only, timestamp-only, AgentDFIR.
- Ablations: remove PID capture, context identifiers, memory, network evidence, local-model analysis, Sysmon.
- Analyst study against the manual Plaso / Timesketch workflow.
- One script that regenerates every results table from the frozen runs.

Done when: every row of Table III has a measured value, including the ones that miss their target.

### v1.0: Final

- Fix what the evaluation exposed, without tuning on the test split.
- Documentation, a demo case, a limitations section, dataset packaging.
- Tag `v1.0.0`.

---

## 4. Proposal targets and where each is first measured

| Target (Table III) | Criterion | First measured | Reported |
|---|---|---|---|
| Tool-to-process correlation | Precision at least 0.95 with ProcessGuid or child PID | v0.4 | v0.8 |
| Human-agent attribution | Macro-F1 at least 0.85 on complete evidence | v0.4 | v0.8 |
| Injected-span localization | F1 at least 0.80 on successful injections | v0.5 | v0.8 |
| Attack-chain reconstruction | Edge F1 at least 0.85 on complete evidence | v0.5 | v0.8 |
| Impact assessment | No connection-only case labelled confirmed | v0.2 (already checked per case) | v0.8 |
| Narrative grounding | At most 5 percent unsupported before validation, zero after | v0.6 | v0.8 |
| Analyst utility | Faster than the Plaso / Timesketch baseline | v0.8 | v0.8 |

## 5. Dataset track (runs alongside v0.2 onward)

The 60 labelled runs are the slowest part of the project: each one needs a snapshot revert, a paired human session and hand-checked labels. Start at v0.2 and add runs every week.

A starting matrix, to adjust:

| Scenario family | Local-model agent | Claude Code | Total |
|---|---|---|---|
| Legitimate task, no injection | 6 | 6 | 12 |
| Injection ignored or failed | 4 | 4 | 8 |
| Sensitive-file access | 4 | 4 | 8 |
| File changes | 4 | 4 | 8 |
| Persistence | 4 | 4 | 8 |
| Download | 4 | 4 | 8 |
| Data transmission | 4 | 4 | 8 |
| **Total** | 30 | 30 | **60** |

Rules:

- Every run has a paired human session typing the same commands.
- Split training and test by attack family, and never tune weights or prompts on the test families.
- Capture all evidence kinds on every run, even those no parser reads yet.
- Synthetic secrets and isolated machines only.

## 6. Decisions the team needs to make

1. **Deadline.** The versions have no dates yet. With the submission date, they can be sized into weeks.
2. **LangGraph.** The proposal names a LangGraph agent; the harness is a plain loop. Port it, or record the change in the report.
3. **React.** The proposal names React; the UI is one HTML page. Same choice.
4. **AttnTrace.** It needs attention weights that an OpenAI-compatible server does not return. Keep it optional unless someone wants to run the model through a library that exposes them.
5. **Ethics clearance** for the analyst study has lead time. Ask about it now, not at v0.8.
