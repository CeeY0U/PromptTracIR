"""Load one lab run folder into a case in a single step (`ptir add-run`).

A run folder is what the harness and tools/collect-run.ps1 leave behind:

    runs/run01/
      trace.jsonl  requests.jsonl  sources/        harness/agent.py
      scenario.json                                copied by the harness when --scenario is used
      ground_truth.json  human_run01.json          labels: never added as evidence
      evidence/collection.json                     written by collect-run.ps1 (path -> kind)
      evidence/...                                 exported logs, hives, captures, memory

If evidence/collection.json exists it decides the kinds. Otherwise DEFAULT_PATTERNS
does. Files that match nothing are added as "other" so nothing collected is lost;
label files are skipped because they are ground truth, not evidence.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from .case import Case
from .parsers import KNOWN_KINDS

# (glob relative to the run folder, kind). First match wins. Globs are matched
# case-insensitively against "/"-separated relative paths.
DEFAULT_PATTERNS: list[tuple[str, str]] = [
    ("trace.jsonl", "agent_trace"),
    ("requests.jsonl", "agent_requests"),
    ("sources/*", "agent_sources"),
    ("evidence/sysmon.jsonl", "sysmon"),
    ("evidence/security.jsonl", "security"),
    ("evidence/powershell.jsonl", "powershell"),
    ("evidence/*.evtx", "evtx_raw"),
    ("evidence/consolehost_history.txt", "psreadline"),
    ("evidence/zeek/conn.log", "zeek_conn"),
    ("evidence/conn.log", "zeek_conn"),
    ("evidence/*.pcap", "pcap"),
    ("evidence/*.pcapng", "pcap"),
    ("evidence/*.etl", "pcap"),
    ("evidence/memory/*", "memory_image"),
    ("evidence/srum/*", "srum"),
    ("evidence/prefetch/*", "prefetch"),
    ("evidence/amcache/*", "amcache"),
    ("evidence/registry/*", "registry_hive"),
    ("evidence/ntfs/$mft", "mft"),
    ("evidence/ntfs/*$j", "usn_journal"),
    ("evidence/triage/*", "triage_archive"),
]

# Ground truth and run bookkeeping: these describe the run, they are not evidence of it.
LABEL_FILES = ["ground_truth.json", "human_*.json", "scenario.json", "sink_log*.jsonl",
               "evidence/collection.json", "evidence/sha256sums.txt", "notes.md"]


def _match(rel: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(rel.lower(), pattern.lower())


def plan(run_dir: str | Path) -> list[tuple[Path, str]]:
    """Return [(file, kind)] for everything in the run folder that should be added."""
    run = Path(run_dir)
    manifest = run / "evidence" / "collection.json"
    explicit: dict[str, str] = {}
    if manifest.exists():
        for item in json.loads(manifest.read_text(encoding="utf-8-sig")).get("files", []):
            explicit[("evidence/" + item["path"]).replace("\\", "/").lower()] = item["kind"]
    out = []
    for f in sorted(run.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(run).as_posix()
        if any(_match(rel, p) for p in LABEL_FILES) or rel.startswith("case/"):
            continue
        kind = explicit.get(rel.lower()) or next((k for p, k in DEFAULT_PATTERNS if _match(rel, p)), "other")
        if kind not in KNOWN_KINDS:
            raise ValueError(f"{rel}: unknown evidence kind '{kind}' (known: {sorted(KNOWN_KINDS)})")
        out.append((f, kind))
    return out


def add_run(case_dir: str | Path, run_dir: str | Path, scenario: str | Path | None = None,
            name: str | None = None) -> tuple[Case, list[tuple[Path, str, str]]]:
    """Create the case if needed (envelope from the scenario) and add every evidence file."""
    run = Path(run_dir)
    case = Case(case_dir)
    if not (case.root / "case.json").exists():
        sc_path = Path(scenario) if scenario else run / "scenario.json"
        envelope = None
        if sc_path.exists():
            envelope = json.loads(sc_path.read_text(encoding="utf-8-sig")).get("envelope")
        case = Case.create(case_dir, name or run.name, envelope)
    added = []
    for f, kind in plan(run):
        added.append((f, kind, case.add_evidence(f, kind)))
    case._custody("run_added", {"run_dir": str(run.resolve()), "files": len(added)})
    return case, added
