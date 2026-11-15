# Changelog

All notable changes to PromptTracIR. Versions follow [ROADMAP.md](ROADMAP.md).

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
