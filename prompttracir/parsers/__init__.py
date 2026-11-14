"""Evidence parsers. Each parser takes (path, evidence_id) and yields CanonicalEvents."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from . import agent_trace, claude_code, ez, otel, psreadline, volatility, windows, zeek

PARSERS = {
    "agent_trace": agent_trace.parse,      # PromptTracIR harness JSONL trace
    "claude_code": claude_code.parse,      # Claude Code session transcript (also via ptir import-adfir)
    "otel_trace": otel.parse,              # OTLP/JSON spans using the GenAI semantic conventions
    "sysmon": windows.parse,               # .evtx or JSONL export of Sysmon/Operational
    "security": windows.parse,             # .evtx or JSONL export of Security (4624, 4663, 4688)
    "powershell": windows.parse,           # .evtx or JSONL export of PowerShell/Operational (4104)
    "psreadline": psreadline.parse,        # ConsoleHost_history.txt
    "zeek_conn": zeek.parse_conn,          # Zeek conn.log (JSON or tab-separated)
    "zeek_dns": zeek.parse_dns,            # Zeek dns.log (JSON or tab-separated)
    "zeek_http": zeek.parse_http,          # Zeek http.log (JSON or tab-separated)
    # v0.3: CSV output of Eric Zimmerman's tools (raw artifacts stay under the raw kinds below)
    "ez_mft": ez.parse_mft,                # MFTECmd $MFT CSV
    "ez_usn": ez.parse_usn,                # MFTECmd $J CSV
    "ez_prefetch": ez.parse_prefetch,      # PECmd CSV
    "ez_amcache": ez.parse_amcache,        # AmcacheParser *FileEntries.csv
    "ez_srum": ez.parse_srum,              # SrumECmd NetworkUsages CSV
    "ez_registry": ez.parse_registry,      # RECmd batch CSV (UserAssist, Run keys, ...)
    "ez_lnk": ez.parse_lnk,                # LECmd CSV
    "ez_jumplist": ez.parse_jumplist,      # JLECmd CSV
    "ez_shellbags": ez.parse_shellbags,    # SBECmd CSV
    # v0.3: Volatility 3 JSON (-r json or -r jsonl)
    "vol_pslist": volatility.parse_pslist,     # windows.pslist / windows.pstree
    "vol_cmdline": volatility.parse_cmdline,   # windows.cmdline
    "vol_netscan": volatility.parse_netscan,   # windows.netscan
}

# Kinds that are hashed and preserved but not parsed into events (yet). Collect them
# anyway: once a parser lands, `ptir ingest` picks up every file of that kind that was
# never ingested, so runs captured today can be re-analysed by later versions.
PRESERVE_ONLY = {
    "agent_requests": "full model request per model call (harness requests.jsonl), used for replay",
    "agent_sources": "original bytes of fetched pages and read files (harness sources/)",
    "adfir_meta": "AgentDFIR package metadata: case.json, manifest, logs, SHA256SUMS, SEAL.sig",
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
