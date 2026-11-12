"""Volatility 3 JSON output: windows.pslist / windows.pstree, windows.cmdline, windows.netscan.

Produce the input on the analyst machine, one plugin per file:

    vol -q -r json -f memory.raw windows.pslist  > vol_pslist.json
    vol -q -r json -f memory.raw windows.cmdline > vol_cmdline.json
    vol -q -r json -f memory.raw windows.netscan > vol_netscan.json

Both the json renderer (one array, children nested under "__children", as pstree emits) and
the jsonl renderer (one object per line) are accepted. Column names are the plugins' TreeGrid
columns. Memory events never become process_create or net_connect: they are an independent
view used to corroborate or contradict the transcript and Sysmon (v0.5), not a second copy.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER_VERSION = "0.3.0"


def _records(path: Path) -> Iterator[dict]:
    text = Path(path).read_text(encoding="utf-8-sig")
    # Skip anything printed before the JSON (a banner when -q was not given).
    start = min((i for i in (text.find("["), text.find("{")) if i >= 0), default=-1)
    if start < 0:
        return
    body = text[start:]
    try:
        data = json.loads(body)
        items = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        items = [json.loads(line) for line in body.splitlines() if line.strip()]

    def walk(nodes):
        for n in nodes:
            if not isinstance(n, dict):
                continue            # not a TreeGrid row (hand-edited or foreign JSON)
            yield n
            children = n.get("__children")
            if isinstance(children, list):
                yield from walk(children)

    yield from walk(items)


def _int(v) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _str(v) -> str | None:
    return v if isinstance(v, str) and v else None


def _time(v) -> datetime | None:
    from . import parse_time

    if not v:
        return None
    try:
        return parse_time(v)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _event(kind: str, action: Action, ts: datetime, precision: str, evidence_id: str, i: int,
           **fields) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"{kind}:{evidence_id[:12]}:{i:07d}", source=EventSource.MEMORY, action=action,
        timestamp=ts, ts_precision=precision,
        raw=RawRef(evidence_id=evidence_id, locator=f"record:{i}", parser=kind,
                   parser_version=PARSER_VERSION),
        **fields)


def _file_time(path: Path) -> datetime:
    return datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)


def parse_pslist(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    fallback = _file_time(path)
    for i, r in enumerate(_records(path)):
        pid = _int(r.get("PID"))
        if pid is None:
            continue
        created = _time(r.get("CreateTime"))
        yield _event("vol_pslist", Action.MEM_PROCESS, created or fallback, "ms" if created else "none",
                     evidence_id, i, pid=pid, parent_pid=_int(r.get("PPID")),
                     image=_str(r.get("ImageFileName")),
                     attrs={"exit_time": r.get("ExitTime"), "session_id": r.get("SessionId"),
                            "threads": r.get("Threads"), "handles": r.get("Handles"),
                            "wow64": r.get("Wow64"),
                            "offset": r.get("Offset(V)") or r.get("Offset(P)") or r.get("Offset"),
                            # pstree adds the full image path and command line
                            "path": r.get("Path") or r.get("ImagePath"), "cmd": r.get("Cmd"),
                            "ts_meaning": "EPROCESS create time" if created else
                                          "no create time; memory file modified time"})


def parse_cmdline(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """windows.cmdline has no time column: events carry the memory file's mtime with
    ts_precision='none' (same convention as psreadline). Join to vol_pslist on PID."""
    ts = _file_time(path)
    for i, r in enumerate(_records(path)):
        pid = _int(r.get("PID"))
        if pid is None:
            continue
        args = r.get("Args")
        readable = bool(_str(args)) and not args.lower().startswith(("required memory", "process "))
        yield _event("vol_cmdline", Action.MEM_CMDLINE, ts, "none", evidence_id, i,
                     pid=pid, image=_str(r.get("Process")),
                     command_line=args if readable else None,
                     attrs={"readable": readable, "note": None if readable else _str(args),
                            "ts_meaning": "no time in artifact; memory file modified time"})


def parse_netscan(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    fallback = _file_time(path)
    for i, r in enumerate(_records(path)):
        if not any(k in r for k in ("Proto", "LocalAddr", "ForeignAddr")):
            continue            # not a netscan row
        foreign = _str(r.get("ForeignAddr"))
        created = _time(r.get("Created"))
        obj = f"{foreign}:{r.get('ForeignPort')}" if foreign not in (None, "*", "0.0.0.0", "::") else None
        yield _event("vol_netscan", Action.MEM_CONN, created or fallback, "ms" if created else "none",
                     evidence_id, i, pid=_int(r.get("PID")), image=_str(r.get("Owner")), object=obj,
                     attrs={"proto": r.get("Proto"), "local_addr": r.get("LocalAddr"),
                            "local_port": r.get("LocalPort"), "foreign_addr": foreign,
                            "foreign_port": r.get("ForeignPort"), "state": r.get("State"),
                            "offset": r.get("Offset"),
                            "ts_meaning": "socket created" if created else
                                          "no create time; memory file modified time"})
