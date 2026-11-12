"""Canonical evidence schema.

This module is the contract between every part of the pipeline. Parsers emit
CanonicalEvent objects; the correlation and graph layers consume them and emit
Node / Edge objects. Change it deliberately and tell the team when you do.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventSource(str, Enum):
    AGENT_TRACE = "agent_trace"
    SYSMON = "sysmon"
    SECURITY = "security"
    POWERSHELL = "powershell"
    PSREADLINE = "psreadline"
    ZEEK = "zeek"
    # v0.3: Windows artifacts via EZ Tools CSV, and memory via Volatility 3
    MFT = "mft"
    USN = "usn"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    SRUM = "srum"
    REGISTRY = "registry"
    LNK = "lnk"
    JUMPLIST = "jumplist"
    SHELLBAGS = "shellbags"
    MEMORY = "memory"


class Action(str, Enum):
    # agent trace
    SESSION_START = "session_start"
    USER_PROMPT = "user_prompt"
    CONTEXT_FRAGMENT = "context_fragment"
    MODEL_CALL = "model_call"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    # host
    PROCESS_CREATE = "process_create"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    REGISTRY_SET = "registry_set"
    NET_CONNECT = "net_connect"
    DNS_QUERY = "dns_query"
    LOGON = "logon"
    SCRIPT_BLOCK = "script_block"
    CONSOLE_HISTORY = "console_history"
    # network
    CONN = "conn"
    # v0.3 artifacts. These carry no ProcessGuid; attrs["ts_meaning"] says what the time is.
    FILE_MODIFY = "file_modify"
    FILE_RENAME = "file_rename"
    FILE_OPEN = "file_open"            # LNK / Jump List: a user opened a file through the shell
    FOLDER_OPEN = "folder_open"        # ShellBags: a user browsed a folder in Explorer
    PROGRAM_RUN = "program_run"        # Prefetch run time
    PROGRAM_PRESENT = "program_present"  # Amcache file entry (key last-write, not execution)
    GUI_LAUNCH = "gui_launch"          # UserAssist: started from the Explorer shell
    AUTORUN = "autorun"                # Run / RunOnce and other autostart registry values
    REGISTRY_VALUE = "registry_value"  # any other RECmd batch row
    NET_USAGE = "net_usage"            # SRUM bytes per app per interval
    MEM_PROCESS = "mem_process"        # Volatility pslist / pstree
    MEM_CMDLINE = "mem_cmdline"        # Volatility cmdline
    MEM_CONN = "mem_conn"              # Volatility netscan


class EdgeStatus(str, Enum):
    """Evidence states, adapted from AgentDFIR and extended with INFERRED."""
    OBSERVED = "observed"          # recorded directly by one source
    CORROBORATED = "corroborated"  # recorded by two independent sources
    INFERRED = "inferred"          # derived from timing, similarity or traceback
    CONTRADICTED = "contradicted"  # one source claims it, another disproves it
    UNKNOWN = "unknown"


class RawRef(BaseModel):
    """Pointer back to the exact raw record an event came from."""
    evidence_id: str               # SHA-256 of the evidence file
    locator: str                   # record number, line number, etc.
    parser: str
    parser_version: str = "0.1.0"
    # When `ptir ingest` parsed the record (UTC ISO-8601). Distinct from the event time, so
    # re-ingesting after a parser fix is visible.
    ingested_at: str | None = None


class CanonicalEvent(BaseModel):
    event_id: str
    source: EventSource
    action: Action
    timestamp: datetime
    ts_precision: str = "ms"       # "ms", "s", "h" (SRUM intervals), or "none" when the artifact has no time
    host: str | None = None
    user: str | None = None
    logon_id: str | None = None
    # process context
    pid: int | None = None
    process_guid: str | None = None
    parent_pid: int | None = None
    parent_process_guid: str | None = None
    image: str | None = None
    command_line: str | None = None
    # the thing acted on: file path, registry key, "ip:port", domain
    object: str | None = None
    # agent context
    session_id: str | None = None
    model_call_id: str | None = None
    tool_call_id: str | None = None
    fragment_id: str | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)
    raw: RawRef

    def ts(self) -> float:
        t = self.timestamp
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t.timestamp()


class NodeKind(str, Enum):
    SESSION = "session"
    PROMPT = "prompt"
    SOURCE = "source"
    FRAGMENT = "fragment"
    MODEL_CALL = "model_call"
    TOOL_CALL = "tool_call"
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    NETWORK = "network"
    DOMAIN = "domain"


class Node(BaseModel):
    id: str
    kind: NodeKind
    label: str
    attrs: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)   # event_ids


class Edge(BaseModel):
    src: str
    dst: str
    relation: str
    status: EdgeStatus
    confidence: float = 1.0
    evidence: list[str] = Field(default_factory=list)   # event_ids
    signals: dict[str, Any] = Field(default_factory=dict)


class AttributionLabel(str, Enum):
    AGENT = "agent"
    HUMAN = "human"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class Attribution(BaseModel):
    process_guid: str
    pid: int | None = None
    image: str | None = None
    label: AttributionLabel
    agent_score: float
    human_score: float
    signals: list[str]
    tool_call_id: str | None = None


class ImpactLevel(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    CONNECTION_ONLY = "connection_only"
    UNKNOWN = "unknown"


class Finding(BaseModel):
    finding_id: str
    kind: str            # e.g. "out_of_scope_file", "external_egress", "persistence", "exfiltration"
    severity: str        # "low" | "medium" | "high"
    summary: str
    nodes: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    attrs: dict[str, Any] = Field(default_factory=dict)
