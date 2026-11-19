"""File inventory written by tools/collect-run.ps1 (evidence/file_inventory.json).

Size, SHA-256 and times of the files in the scenario folders at collection time. Sysmon and
Security events say a file was touched, not how big it is; without KAPE's $MFT this is the only
source of a file's size, which impact assessment needs to call an upload confirmed.

    {"collected_utc": "2026-11-16T11:46:00Z", "roots": [...],
     "files": [{"path": "C:\\\\Users\\\\lab\\\\secrets\\\\api_keys.txt", "size": 214,
                "sha256": "...", "created_utc": "...", "modified_utc": "..."}]}
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER_VERSION = "0.5.0"


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    from . import parse_time
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    ts = parse_time(data["collected_utc"])
    for i, f in enumerate(data.get("files") or []):
        if not f.get("path"):
            continue
        yield CanonicalEvent(
            event_id=f"inventory:{evidence_id[:12]}:{i:08d}", source=EventSource.INVENTORY,
            action=Action.FILE_STAT, timestamp=ts, ts_precision="s", object=f["path"],
            raw=RawRef(evidence_id=evidence_id, locator=f"files[{i}]", parser="file_inventory",
                       parser_version=PARSER_VERSION),
            attrs={"size": f.get("size"), "sha256": (f.get("sha256") or "").lower() or None,
                   "created_utc": f.get("created_utc"), "modified_utc": f.get("modified_utc"),
                   "ts_meaning": "collection time (size and hash as found then)"})
