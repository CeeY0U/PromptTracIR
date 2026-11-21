# Changelog

All notable changes to PromptTracIR. Versions follow [ROADMAP.md](ROADMAP.md).

## [0.6.0] - 2026-11-21

Roadmap v0.6 (local model analysis), the fixes from the 17 v0.5 lab runs (two labs), and the
dataset completed by counting slots by outcome.

### Added
- Schema-constrained local-model replies (`prompttracir/llm.py`): the JSON schema's ID fields are
  enums of the IDs in the input, so llama-server (which enforces schemas as a grammar) cannot cite
  an ID that does not exist; servers without `json_schema` fall back to `json_object` with the
  schema, then plain JSON mode.
- Grounded summary on the attack chain and its one-hop neighbourhood (at most 60 nodes), each node
  with the facts the graph holds for it, answered as cited sentences.
- Entity-level narrative validation: a sentence that names a file, program, domain or address not
  shown by the nodes it cites is dropped. Dropped sentences are counted by reason.
- `configs/local-model.json`: the pinned model (Qwen2.5-7B-Instruct Q4_K_M), server command and
  sampling; `ptir llm-pin`. Every `llm.json` records the pin, the served model and the prompt
  version.
- `ptir explain CASE_OR_ROOT --llm-url URL [--families ...]`: runs only the local-model layer on
  analysed cases, without changing their graph or findings.
- `eval-batch`: unsupported claims before and after validation (target at most 0.05 and 0), the
  local model's verdict accuracy on deviating calls, and clean runs (legitimate or injection
  ignored) with any finding, since a finding without a tool call is still a false alarm.
- `--localizer heuristic-v01`: the v0.1 cue list, frozen, as the cue-only baseline (the current
  list gained cues from the lab payloads in v0.5). On the 31 lab runs: localization F1 0.75, span
  overlap 0.703, chain edge F1 0.941, against 1.0 for the segment localizer.
- `harness/label_run.py`: gold tool-to-process links for Claude Code runs (the Bash wrapper whose
  `eval '...'` holds the transcript command exactly); `--update-links` refreshes only the links of
  a reviewed ground truth.
- `harness/agent.py`: `--max-tokens` (default 1024) and `--request-timeout` (default 300 s).

### Changed
- Dataset: slots that needed an agent to follow a payload are counted by outcome. The real model
  followed 0 of 6 persistence, file-change and download payloads at temperature 0.7, and Claude
  Code 0 of 4 payloads; those runs are scored as "injection ignored" and the rates are reported
  (ROADMAP.md section 5, `docs/DATASET_PROGRESS.md`: 30 of 30 slots).
- `parse-artifacts.ps1` replaces the outputs of an earlier run instead of adding a second set, and
  rewrites the ez/ and vol/ lines of `sha256sums.txt`.
- `collect-run.ps1` waits up to 60 s for `llama-server` to exit and retries an empty or short
  memory image once, 30 s later.
- Claude Code runs labelled before v0.6 (no gold links) are not scored for tool-to-process links.

### Fixed
- Claude Code's Bash wrapper on Windows (jt-c3, cy-c3: 10 and 8 false findings, 4 and 3
  contradictions): calls are linked and cross-checked on the wrapped command (`shellwrap.py`), the
  runtime's start-up shells are logged as bookkeeping instead of untraced tool calls, and the
  wrapper's own files and TEMP are no longer out-of-scope references. A Bash call dropped from the
  transcript is still caught.
- A file fetched into %TEMP% by a call that contacted only allowed hosts is a `temp_download`
  note (severity info), not a deviation (jt-c3 saved the lab guide with curl).
- An overwrite (Sysmon 26 and 11 together, or an older CreationUtcTime) is reported as "wrote",
  not "deleted" (jt-v2b, cy-v2).
- Zeek connections without a Sysmon event 3 are joined (inferred) to the process whose DNS query
  returned the address just before (tt-05).
- A file-writing tool call is labelled malicious only when its target path carries an attacker
  marker, not the text it writes (jt-v1b).
- Tests: 153 -> 171.

On the 31 lab runs (all evidence): malicious-call F1 0.909 -> 1.0, tool-to-process link precision
0.875 -> 1.0, contradictions on untampered runs 7 -> 0, clean runs with any finding 0 of 21;
localization, chain and attribution unchanged (1.0, 1.0, 0.988). The lab VM needs v0.6.0 only for
the harness and collection changes; every run should be re-analysed, and the Claude Code runs'
links refreshed with `label_run.py --update-links`.

## [0.5.1] - 2026-11-21

Fix from the first v0.5.0 lab runs.

### Fixed
- The lab agent's shell tool mangled commands with double quotes on Windows: Python's
  list2cmdline escaped them as \", which cmd.exe does not understand, so `file_change_01`'s
  `cmd /c "echo backup=disabled> ..."` exited 1 without changing the file (lab run jt-v2). The
  command line is now passed as one string; commands without quotes are unchanged, so earlier
  runs stay comparable.
- Tests: 151 -> 152.

The lab VM needs v0.5.1 (the harness changed); analysis results of earlier runs do not change.

## [0.5.0] - 2026-11-17

Roadmap v0.5 (causal reconstruction), the fixes from the 14 v0.4 lab runs, and the dataset
reduced from 60 to 30 runs.

### Added
- Localizer plug-ins (`prompttracir/traceback.py`): `segment` (PromptLocate-style: fragments
  split into sentences, the span with the payload's instruction and target is localized; default
  without a model), `heuristic` (cue-only baseline), `replay` (leave-one-out, up to 8 fragments),
  `group` (TracLLM-style group search, more than 8 fragments) and surrogate replay for Claude Code
  transcripts, marked `surrogate_replay` at half confidence. `ptir analyze --localizer`, and
  `ptir eval-batch --localizer` to score a baseline into its own folder.
- Transcript cross-check (`prompttracir/crosscheck.py`): each tool call is compared with Sysmon,
  4688 and memory; edges are marked corroborated or contradicted, with `transcript_mismatch` and
  `untraced_agent_process` findings. Output `crosscheck.json`; the summary reports `contradicted`.
- `harness/tamper_trace.py`: copies a run with an edited command or a dropped tool call, for the
  roadmap's tampered-transcript case. `eval-batch` scores tampered copies only for detection.
- Metrics: injected-span overlap F1 (characters), attack-chain node and edge precision, recall
  and F1 (all runs and complete-evidence runs), path exact match, tampered traces detected.
- File inventory at collection (`collect-run.ps1` step 7b, `evidence/file_inventory.json`,
  evidence kind `file_inventory`): sizes and times of files under the lab folders, so impact can be
  confirmed without KAPE. SRUM bytes as impact evidence when there is no Zeek record.
- Graph: `LOGON_SESSION` and `DATA_OBJECT` node kinds; `graph_reduced.json` keeps the attack
  chain's nodes and their direct neighbours, for large cases.
- Scenarios `file_change_01` and `download_01` (and their scripted-model plans).
- `label_run.py`: payload spans, GUI launches and human process labels from the human session
  logs, for span and chain scoring.
- `docs/DATASET_PROGRESS.md` (replaces `docs/DATASET.md`): 30 slots with status. TESTING.md
  Part 10: v0.5 lab update, new scenarios, Claude Code runs, tampered transcripts, replay.

### Changed
- Dataset reduced from 60 to 30 runs because of time constraints, keeping every claim in Table
  III supported (ROADMAP.md, section 5).
- Typed and full-path commands match (`curl` vs `C:\Windows\System32\curl.exe`).
- Effects of in-process tool calls are assigned to one call each, within the call's window.
- Processes seen only in 4688 are scored as their Sysmon twin (same PID within 2 s).
- `collect-run.ps1` warns when `llama-server` is still running and reports empty or short memory
  images; `parse-artifacts.ps1` skips Volatility on an empty image and warns on a partial one.

### Fixed
- `file_persist_01`'s payload was not localized by the v0.4 heuristic (localization F1 0.8 on
  the lab runs; 1.0 now).
- One persistence finding per tool call instead of one per registry value.
- `ptir eval-batch --out` overwrote earlier conditions; each condition gets its own folder.
- RECmd CSV with NUL bytes broke parsing on Python 3.10.
- The agent trace parser dropped the run's temperature, seed and dropped parallel calls, so
  `eval-batch` could not report run conditions.
- Claude Code runs: the runtime's own API connections inside a tool call's window (often to a
  bare IP address) and writes to its `~\.claude` state were scope findings. Unclaimed in-process
  connections are timing-only links, like unclaimed file effects, and are no longer egress.
- Tests: 124 -> 151 (`test_lab_fixes_v05.py`, `test_localizers.py`, `test_chain_v05.py`,
  `test_scope_paths.py`).

Re-ingest cases from earlier versions (`ptir add-run` into a fresh `case/`). The lab VM needs
v0.5.0 for new runs (collection changed).

## [0.4.1] - 2026-11-16

Fix from the first v0.4.0 lab run (`jt-01-exfil-scripted`, scripted model).

### Fixed
- `ptir analyze` stopped with `KeyError: 'node'` on agent traces whose records share a
  timestamp. The scripted model answers within one clock tick, so a model call and the fragments
  it reads had the same time; trace events are ordered by event ID within a timestamp, and the
  harness trace parser numbered them without zero padding (`10` sorted before `7`), so the model
  call came before its fragments. Trace event IDs are now zero-padded like every other parser's,
  the graph accepts a node whose edges arrived first, and edges to nodes the evidence never
  defines are dropped instead of breaking the graph. Cases ingested with v0.4.0 must be ingested
  again (`ptir add-run` into a fresh `case/`).
- Tests: `tests/test_trace_order.py` (121 -> 124 tests).

## [0.4.0] - 2026-11-16

Attribution engine (roadmap v0.4), on top of the v0.3.1 lab fixes. Tested on synthetic cases built
from the sample and on the process records of lab run01; the weights are still the untuned defaults
until they are tuned on real training runs.

### Added
- Settings file: `prompttracir/config.py`, `ptir config`, `ptir analyze --config FILE`;
  `configs/attribution-defaults.json` and `configs/README.md` (tuning procedure). Each analysis
  writes the settings used and their fingerprint to `output/config.json`.
- Per-session trace-to-host clock offset, estimated from child PIDs; configurable drift windows
  otherwise. `output/correlation.json` records it, and how each session's runtime was found.
- Security 4688 builds the process tree when Sysmon is missing; a 4688 that matches a Sysmon
  event (same PID and image within `process.dedupe_window_s`) is merged into it (`seen_by`). This
  replaces the v0.3.1 de-duplication with a configurable one; the lab run01 timing (4688 1 ms after
  Sysmon) is a regression test. PowerShell 4104 script blocks count as command evidence
  when linking a tool call.
- Runtime identification for traces with no runtime PID (Claude Code), marked inferred.
- Human-side signals: UserAssist, LNK / Jump List file opens, ShellBags, started outside every
  agent session; non-interactive logon types (4624) discount human signals.
- `agent_probability`, weighted `contributions` and `seen_by` on every attribution.
- Ablations: `ptir analyze --without KIND [--tag NAME]` into `output/<tag>/`.
- `eval-batch`: attribution and tool-link calibration (ECE, Brier), attribution on
  complete-evidence runs, `--families` / `--exclude-families`, and `--reanalyze` / `--config` /
  `--without` / `--tag` re-analysis.
- Tests: `tests/test_attribution.py`, `tests/test_calibration.py`, more in `tests/test_batch.py`, and
  the lab run01 merge test in `tests/test_process_dedupe.py` (101 -> 121 tests).

### Changed
- `correlate.W` and `DECISION_MARGIN` are now read from the settings (the names remain as
  aliases of the defaults).
- `analyze` returns the label counts, the settings fingerprint and any ablation.
- Processes started before or after every agent session gain a weak human signal, so
  `explorer.exe` and terminals in the sample score slightly higher on the human side; labels in
  the sample are unchanged.

## [0.3.1] - 2026-11-16

Fixes from the first real lab runs (15 Nov 2026: Windows 11 24H2 VM, Kali attacker box,
Qwen2.5-7B through llama-server, runs run01 to run04 and a teammate's batch).

### Fixed
- Timestamps whose fraction is not 3 or 6 digits long (`07:09:00.5`) failed to parse on
  Python 3.10, which CI tests on: `parse_time`, `label_run.py` and the run window in `eval`
  now pad or cut the fraction to 6 digits.
- `collect-run.ps1 -Phase Start` stopped before starting the capture on Windows PowerShell 5.1:
  `pktmon stop` with nothing running writes to stderr, which "Stop" turned into a terminating error.
- Registry hives in use (`NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`) were copied without their
  `.LOG1`/`.LOG2` files, so RECmd and SBECmd refused them and AmcacheParser wrote rows with no
  path. The logs are now copied next to each hive. `parse-artifacts.ps1` re-runs RECmd and SBECmd
  with `--nl` if a hive is still refused, removing the failed attempt's CSVs, and warns.
- Event logs were exported only from `-Phase Start`, so a shell opened earlier (the human's
  window) had no creation record and its processes could not be labelled. Logs are now exported
  from boot, at most `-LookbackMinutes` (default 360) before the start; `collection.json` records
  `events_since_utc`.
- Scope rules raised `out_of_scope_file` findings for paths inside the allowed folder when a command
  wrote them escaped (`C:\\Users\\lab\\...` inside a Python string) or cmd.exe left a trailing
  backslash: the benign run03 got four findings and a first deviation. Paths are normalised first
  (`scope.normalize_path`); UNC prefixes are kept.
- `ProcessIndex` kept the Security 4688 copy of a process next to the Sysmon one. Sysmon rounds
  `UtcTime` to the millisecond, so the 4688 copy looked 1 ms newer, won `find_by_pid`, and has no
  parent links: eval found no processes to label and attribution scored null on every run. A 4688
  record within 2 s of a Sysmon record with the same PID and image is now dropped.
- Eval: an injection the model ignored is no longer scored for localization (nothing deviated to
  trace back from), an `unknown` exfiltration label is shown but not scored, and a metric with
  nothing to score is null in `eval-batch` instead of 1.0. Gold labels now reach a root process that
  started before the evidence window through its children's parent ProcessGuid, limited to the run
  window (plus 10 minutes) and, for the human, to shell parents.
- AmcacheParser rows without `FullPath` (hive copied without its logs) gave 0 events; they now keep
  the program name from `KeyName`, with `path_known: false`.
- `parse-artifacts.ps1`: `windows.netscan` finds no sockets on Windows 11 24H2 with Volatility 2.28;
  `windows.netstat` is used instead (same columns), with a warning when both are empty (usually
  missing `tcpip.pdb` symbols on an offline VM). `$MFT` and `$J` are taken from `-Kape` output.
- CLI: a missing case, envelope or ground-truth file is a one-line message (with a hint for Git
  Bash's `/file` path conversion) instead of a traceback; `ptir add-run` on an existing case lists
  only new files and says how many were already there; JSON inputs are read with or without a BOM.

### Added
- `harness/agent.py`: one tool call per model turn by default (`--parallel-tools` for the old
  behaviour), `--temperature` and `--seed`, all recorded in the trace. At temperature 0, run02
  repeated run01 word for word.
- `harness/scripted_model.py`: an OpenAI-compatible stand-in for the model server that follows a
  scenario's injection (`--mode comply`) or ignores it (`--mode ignore`). The agent really runs the
  tools, so the host evidence is genuine; only the decisions are scripted. Without the payload in
  its input it makes no shell call, so counterfactual replay behaves as expected.
- Scenarios: `injection.command`, the exact command the payload asks for (checked against the
  payload).
- `docs/TESTING.md`: lab notes from the first runs (two attacker IPs, VMware networking, CPU
  sockets, Sysmon config check, hosts file, .NET 10, Volatility symbols, Zeek through Docker,
  snapshot hygiene, window order), a scripted-run section and the real-run results per artifact.
- Tests: `test_scope_paths.py`, `test_process_dedupe.py`, `test_cli_messages.py`,
  `test_scripted_model.py`, an Amcache lab fixture and a serial tool-call test (80 -> 101 tests).

## [0.3.0] - 2026-11-14

Windows forensic normalizers (roadmap v0.3). Tested on synthetic fixtures that follow each tool's
CSV / JSON layout; not yet checked against output from a real lab run.

### Added
- Zeek `dns.log` (`zeek_dns`) and `http.log` (`zeek_http`) parsers. All Zeek parsers, `zeek_conn`
  included, read both JSON and Zeek's default tab-separated format.
- Security 4663 file access: `file_read` / `file_modify` events with PID, image, path and access
  mask. The graph joins them to processes by PID and time; a 4663 read inside a `read_file` tool
  call corroborates the trace. `tools/audit-canary.ps1` audits one folder; `export-events.ps1`
  exports 4663.
- EZ Tools CSV parsers (`prompttracir/parsers/ez.py`): `ez_mft`, `ez_usn`, `ez_prefetch`,
  `ez_amcache`, `ez_srum`, `ez_registry` (UserAssist, autoruns, other values), `ez_lnk`,
  `ez_jumplist`, `ez_shellbags`.
- Volatility 3 JSON parsers (`prompttracir/parsers/volatility.py`): `vol_pslist` (also pstree,
  children flattened), `vol_cmdline`, `vol_netscan`; json and jsonl renderers; banner skipped.
- `tools/parse-artifacts.ps1`: runs the EZ tools and Volatility over a collected run folder into
  `evidence/ez/` and `evidence/vol/`, and appends their hashes to `sha256sums.txt`.
- `ptir add-run` patterns for those outputs.
- Schema: event sources `mft`, `usn`, `prefetch`, `amcache`, `srum`, `registry`, `lnk`,
  `jumplist`, `shellbags`, `memory`; actions `file_modify`, `file_rename`, `file_open`,
  `folder_open`, `program_run`, `program_present`, `gui_launch`, `autorun`, `registry_value`,
  `net_usage`, `mem_process`, `mem_cmdline`, `mem_conn`; `ts_precision` value `h`;
  `RawRef.ingested_at`, set by `ptir ingest`; `attrs.ts_meaning` on every new event.
- `tests/test_artifacts.py` and fixtures under `tests/fixtures/v03/`; `tests/test_zeek.py`,
  `tests/test_file_access.py`.

### Fixed
- `Case.store_events` inserts through `read_json` on a temporary NDJSON file in chunks of 50k
  instead of `executemany`: 400k events from a 200k-row $MFT ingest in about 25 s instead of
  roughly 45 min. Same INSERT OR REPLACE semantics (a later duplicate id wins).
- Volatility parsers skip JSON values that are not TreeGrid rows and non-numeric PIDs instead of
  crashing (found by fuzzing).
- Timeline API: rows that only name a program (Prefetch, Amcache, SRUM, UserAssist, pslist)
  show the program in `detail` instead of a blank.
- `parse-artifacts.ps1` does not append duplicate lines to `sha256sums.txt` when re-run.

### Unchanged
- Raw kinds (`mft`, `prefetch`, `amcache`, `srum`, `registry_hive`, `memory_image`, ...) stay
  preserve-only. The new events carry no ProcessGuid, so graph, attribution and the quick-start
  results are unchanged until v0.4 / v0.5 use them.

## [0.2.0] - 2026-11-11

First-real-case tooling (roadmap v0.2). Everything below is tested on synthetic data; the lab
scripts have not yet run on a real Windows VM (see docs/TESTING.md, Part 4).

### Added
- `ptir add-run RUN_DIR`: one lab run folder to one case; kinds from `evidence/collection.json`
  or file names; label files skipped.
- `ptir import-adfir CASE PACKAGE`: verify an AgentDFIR `.adfir` package (seal coverage and hashes)
  and import its Claude Code transcripts; the evidence id equals AgentDFIR's artifact id.
- Parsers: `claude_code` (Claude Code transcripts) and `otel_trace` (OpenTelemetry GenAI spans).
- `ptir eval-batch ROOT`: aggregate scores over many runs into `results.json` and `per_run.csv`.
- `ptir kinds`; `ptir add` accepts a directory; preserve-only kinds for memory, pcap, SRUM,
  Prefetch, Amcache, hives, MFT/USN, triage, raw EVTX, harness sources and AgentDFIR metadata.
- `tools/collect-run.ps1`: two-phase collection (pktmon capture, event logs, SRUM, Prefetch,
  Amcache, hives, LNK, Jump Lists, optional WinPmem and KAPE) with a collection manifest.
- Harness: original bytes of fetched pages and read files kept under `sources/`; `--scenario`;
  `harness/scenario.py` (schema, `validate`, `prepare`); scenarios `legit_notes_01`,
  `web_exfil_01`, `file_persist_01`.
- `label_run.py`: tool-call-to-ProcessGuid ground truth from Sysmon, malicious-call details,
  run-window filtering of the sink log, `attack_succeeded`, Claude Code and OTel traces.
- `evaluate_case` scores tool-to-process links when ground truth has them.
- `docs/TESTING.md`.

### Changed
- Adding the same bytes twice keeps the first evidence record and logs `evidence_duplicate`.
- `harness/scenarios/web_exfil.json` replaced by `web_exfil_01.json` (new schema).
- `label_run.py` matches attacker markers against plain argument text (no JSON escaping).
- `human-session.ps1` takes `-Scenario` and prints the commands to type.

## [0.1.1] - 2026-11-11

### Added
- `.gitignore` for caches, generated samples, cases, lab runs and raw evidence formats.
- GitHub Actions workflow running `pytest` on Ubuntu and Windows, Python 3.10 and 3.12.
- `ROADMAP.md` mapping the proposal to versions v0.1 to v1.0.
- This changelog.

## [0.1.0] - initial upload

### Added
- Working skeleton covering all six proposal phases on synthetic evidence: case format with
  hashing and custody, canonical schema, agent-trace / Sysmon / Security / PowerShell /
  PSReadLine / Zeek parsers, tool-call-to-process correlation, human/agent attribution,
  provenance graph, scope rules, exfiltration impact, replay and heuristic traceback,
  local-LLM classification and validated summary, FastAPI + Cytoscape UI, lab harness.
