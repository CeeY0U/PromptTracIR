# Changelog

All notable changes to PromptTracIR. Versions follow [ROADMAP.md](ROADMAP.md).

## [Unreleased]

Windows forensic normalizers (roadmap v0.3). Tested on synthetic fixtures that follow each tool's
CSV / JSON layout; not yet checked against output from a real lab run.

### Added
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
- `tests/test_artifacts.py` and fixtures under `tests/fixtures/v03/`.

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
