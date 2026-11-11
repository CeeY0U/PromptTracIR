"""Evidence parsers. Each parser takes (path, evidence_id) and yields CanonicalEvents."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from . import agent_trace, psreadline, windows, zeek

PARSERS = {
    "agent_trace": agent_trace.parse,      # PromptTracIR harness JSONL trace
    "sysmon": windows.parse,               # .evtx or JSONL export of Sysmon/Operational
    "security": windows.parse,             # .evtx or JSONL export of Security (4624, 4688)
    "powershell": windows.parse,           # .evtx or JSONL export of PowerShell/Operational (4104)
    "psreadline": psreadline.parse,        # ConsoleHost_history.txt
    "zeek_conn": zeek.parse,               # Zeek conn.log in JSON format
}

# Kinds that are hashed and preserved but not parsed into events (yet). Collect them
# anyway: once a parser lands, `ptir ingest` picks up every file of that kind that was
# never ingested, so runs captured today can be re-analysed by later versions.
PRESERVE_ONLY = {
    "agent_requests": "full model request per model call (harness requests.jsonl), used for replay",
    "agent_sources": "original bytes of fetched pages and read files (harness sources/)",
    "evtx_raw": "raw .evtx copy kept for custody when the JSONL export is the parsed copy",
    "memory_image": "full memory image (WinPmem, hypervisor snapshot)",
    "pcap": "packet capture (pcap, pcapng, pktmon .etl)",
    "srum": "SRUDB.dat and its SOFTWARE hive",
    "prefetch": "C:\\Windows\\Prefetch\\*.pf",
    "amcache": "Amcache.hve and its transaction logs",
    "registry_hive": "NTUSER.DAT, UsrClass.dat, SYSTEM, SOFTWARE and their logs",
    "mft": "$MFT",
    "usn_journal": "$UsnJrnl:$J",
    "triage_archive": "KAPE or Velociraptor triage output",
    "other": "anything else worth preserving",
}

KNOWN_KINDS = set(PARSERS) | set(PRESERVE_ONLY)

_FRAC = re.compile(r"(\.\d{6})\d+")


def parse_time(value: str) -> datetime:
    """Parse ISO-8601, Sysmon UtcTime ('2026-10-29 07:01:02.123'), or epoch seconds into aware UTC."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    s = _FRAC.sub(r"\1", s)
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
