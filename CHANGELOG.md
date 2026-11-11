# Changelog

All notable changes to PromptTracIR. Versions follow [ROADMAP.md](ROADMAP.md).

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
