"""Zeek log parsers: conn.log, dns.log and http.log.

Both Zeek output formats are read:
  * JSON, one object per line (`zeek -r capture.pcapng LogAscii::use_json=T`);
  * Zeek's default tab-separated format, with its `#separator` / `#fields` header lines.

| kind       | one event per          | action       | object                    |
|------------|------------------------|--------------|---------------------------|
| zeek_conn  | connection             | conn         | resp_h:resp_p             |
| zeek_dns   | DNS query              | dns_query    | queried name              |
| zeek_http  | HTTP request/response  | http_request | host + URI                |

Zeek sees the network, not processes: none of these events carry a PID or ProcessGuid.
conn byte counts corroborate Sysmon connections; DNS answers name IP-only connections;
HTTP request body sizes show what was uploaded over plain HTTP.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER_VERSION = "0.3.0"
UNSET = {"-", "(empty)"}


def _records(path: Path) -> Iterator[tuple[int, dict]]:
    """(line number, record) from a JSON or tab-separated Zeek log."""
    sep, fields, set_sep = "\t", None, ","
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
                elif line.startswith("#set_separator"):
                    set_sep = line.split(sep, 1)[1]
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if line.lstrip().startswith("{"):
                yield lineno, json.loads(line)
                continue
            if fields is None:
                raise ValueError(f"{path}: line {lineno} is neither JSON nor preceded by a #fields header")
            rec = {}
            for k, v in zip(fields, line.split(sep)):
                if v in UNSET:
                    continue
                rec[k] = v
            for k in ("answers", "TTLs", "tags", "resp_mime_types", "orig_mime_types"):
                if k in rec and isinstance(rec[k], str):
                    rec[k] = rec[k].split(set_sep)
            yield lineno, rec


def _num(v, cast=int):
    if v is None or v in UNSET:
        return None
    try:
        return cast(v)
    except (TypeError, ValueError):
        return None


def _raw(evidence_id: str, lineno: int, kind: str) -> RawRef:
    return RawRef(evidence_id=evidence_id, locator=f"line:{lineno}", parser=kind, parser_version=PARSER_VERSION)


def _ts(r: dict):
    from . import parse_time
    return parse_time(float(r["ts"]))


def parse_conn(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    for lineno, r in _records(Path(path)):
        yield CanonicalEvent(
            event_id=f"zeek:{evidence_id[:12]}:{r.get('uid', lineno)}",
            source=EventSource.ZEEK, action=Action.CONN, timestamp=_ts(r),
            object=f'{r["id.resp_h"]}:{r["id.resp_p"]}',
            attrs={"uid": r.get("uid"), "orig_h": r.get("id.orig_h"), "orig_p": _num(r.get("id.orig_p")),
                   "resp_h": r["id.resp_h"], "resp_p": _num(r["id.resp_p"]), "proto": r.get("proto"),
                   "service": r.get("service"), "duration": _num(r.get("duration"), float),
                   "orig_bytes": _num(r.get("orig_bytes")) or 0, "resp_bytes": _num(r.get("resp_bytes")) or 0},
            raw=_raw(evidence_id, lineno, "zeek_conn"))


parse = parse_conn   # v0.1/v0.2 name


def parse_dns(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    for lineno, r in _records(Path(path)):
        query = r.get("query")
        if not query:
            continue
        answers = r.get("answers") or []
        if isinstance(answers, str):
            answers = answers.split(",")
        yield CanonicalEvent(
            event_id=f"zeek_dns:{evidence_id[:12]}:{lineno:08d}",
            source=EventSource.ZEEK, action=Action.DNS_QUERY, timestamp=_ts(r), object=query,
            attrs={"uid": r.get("uid"), "orig_h": r.get("id.orig_h"), "resp_h": r.get("id.resp_h"),
                   "qtype": r.get("qtype_name"), "rcode": r.get("rcode_name"),
                   "answers": answers,
                   # same key Sysmon event 22 uses, so DNS answers name IP-only connections either way
                   "results": ";".join(answers)},
            raw=_raw(evidence_id, lineno, "zeek_dns"))


def parse_http(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    for lineno, r in _records(Path(path)):
        host = r.get("host") or r.get("id.resp_h")
        uri = r.get("uri") or "/"
        yield CanonicalEvent(
            event_id=f"zeek_http:{evidence_id[:12]}:{lineno:08d}",
            source=EventSource.ZEEK, action=Action.HTTP_REQUEST, timestamp=_ts(r),
            object=f"{host}{uri}" if host else uri,
            attrs={"uid": r.get("uid"), "orig_h": r.get("id.orig_h"), "resp_h": r.get("id.resp_h"),
                   "resp_p": _num(r.get("id.resp_p")), "method": r.get("method"), "host": host,
                   "uri": uri, "status_code": _num(r.get("status_code")),
                   "user_agent": r.get("user_agent"),
                   "request_body_len": _num(r.get("request_body_len")) or 0,
                   "response_body_len": _num(r.get("response_body_len")) or 0},
            raw=_raw(evidence_id, lineno, "zeek_http"))
