"""PSReadLine ConsoleHost_history.txt parser.

PSReadLine only records commands typed in an interactive PowerShell console, so a
command appearing here is a human-initiation signal. The file has no timestamps,
so events carry ts_precision="none" and the evidence file's mtime; attribution
uses them only for command matching, never for timing.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER = "psreadline"


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    mtime = datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        lines = f.read().splitlines()
    buf, start = [], 1
    for lineno, line in enumerate(lines, 1):
        # PSReadLine stores multi-line commands with a trailing backtick per line
        if line.endswith("`"):
            if not buf:
                start = lineno
            buf.append(line[:-1])
            continue
        if buf:
            buf.append(line)
            cmd, loc = "\n".join(buf), f"line:{start}-{lineno}"
            buf = []
        else:
            cmd, loc = line, f"line:{lineno}"
        if not cmd.strip():
            continue
        yield CanonicalEvent(
            event_id=f"psreadline:{evidence_id[:12]}:{loc}", source=EventSource.PSREADLINE,
            action=Action.CONSOLE_HISTORY, timestamp=mtime, ts_precision="none",
            command_line=cmd, attrs={"position": lineno},
            raw=RawRef(evidence_id=evidence_id, locator=loc, parser=PARSER))
