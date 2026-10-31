"""Zeek conn.log parser (JSON output: `zeek -r capture.pcap LogAscii::use_json=T`)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER = "zeek_conn"


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    from . import parse_time

    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            r = json.loads(line)
            yield CanonicalEvent(
                event_id=f"zeek:{evidence_id[:12]}:{r.get('uid', lineno)}",
                source=EventSource.ZEEK, action=Action.CONN, timestamp=parse_time(r["ts"]),
                object=f'{r["id.resp_h"]}:{r["id.resp_p"]}',
                attrs={"uid": r.get("uid"), "orig_h": r.get("id.orig_h"), "orig_p": r.get("id.orig_p"),
                       "resp_h": r["id.resp_h"], "resp_p": r["id.resp_p"], "proto": r.get("proto"),
                       "service": r.get("service"), "duration": r.get("duration"),
                       "orig_bytes": r.get("orig_bytes") or 0, "resp_bytes": r.get("resp_bytes") or 0},
                raw=RawRef(evidence_id=evidence_id, locator=f"line:{lineno}", parser=PARSER))
