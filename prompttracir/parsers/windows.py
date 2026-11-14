"""Windows event log parser for Sysmon, Security and PowerShell channels.

Accepts either:
  * a native .evtx file (needs `pip install python-evtx`), or
  * a JSONL export, one record per line:
      {"EventID": 1, "TimeCreated": "...", "Computer": "...", "RecordID": 42,
       "Channel": "Microsoft-Windows-Sysmon/Operational", "EventData": {...}}
    A matching export can be produced on the VM with tools/export-events.ps1.

Mapped events:
  Sysmon 1 process create, 3 network connect, 11 file create, 13 registry set,
          22 DNS query, 23/26 file delete
  Security 4624 logon, 4663 object access (file reads on audited paths), 4688 process create
  PowerShell 4104 script block
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER = "windows_evtx"
# 4663 AccessMask bits for files: 0x1 ReadData, 0x20 Execute. Write bits (0x2 WriteData,
# 0x4 AppendData) become file_modify. Only paths with an audit SACL produce 4663 at all
# (tools/audit-canary.ps1 sets one on the canary folder).
READ_MASK = 0x1 | 0x20
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _records_from_evtx(path: Path) -> Iterator[dict]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("Reading .evtx needs python-evtx: pip install python-evtx") from e
    with Evtx(str(path)) as log:
        for rec in log.records():
            root = ET.fromstring(rec.xml())
            sysn = root.find(f"{NS}System")
            data = {}
            ed = root.find(f"{NS}EventData")
            if ed is not None:
                for d in ed.findall(f"{NS}Data"):
                    data[d.get("Name")] = d.text
            yield {
                "EventID": int(sysn.find(f"{NS}EventID").text),
                "TimeCreated": sysn.find(f"{NS}TimeCreated").get("SystemTime"),
                "Computer": sysn.findtext(f"{NS}Computer"),
                "Channel": sysn.findtext(f"{NS}Channel"),
                "RecordID": int(sysn.findtext(f"{NS}EventRecordID")),
                "EventData": data,
            }


def _records_from_jsonl(path: Path) -> Iterator[dict]:
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _int(v) -> int | None:
    if v in (None, "", "-"):
        return None
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except ValueError:
        return None


def _guid(v) -> str | None:
    return v.strip("{}").lower() if v else None


def _channel_source(channel: str | None, eid: int) -> EventSource:
    ch = (channel or "").lower()
    if "sysmon" in ch:
        return EventSource.SYSMON
    if "powershell" in ch or eid == 4104:
        return EventSource.POWERSHELL
    if "security" in ch or eid in (4624, 4663, 4688):
        return EventSource.SECURITY
    return EventSource.SYSMON


def parse(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    from . import parse_time

    path = Path(path)
    records = _records_from_evtx(path) if path.suffix.lower() == ".evtx" else _records_from_jsonl(path)
    for i, r in enumerate(records):
        eid = int(r["EventID"])
        d = r.get("EventData") or {}
        src = _channel_source(r.get("Channel"), eid)
        rec_id = r.get("RecordID", i)
        # Sysmon carries its own precise UtcTime; prefer it over TimeCreated.
        ts = parse_time(d.get("UtcTime") or r["TimeCreated"])
        common = dict(
            event_id=f"{src.value}:{evidence_id[:12]}:{rec_id}",
            source=src, timestamp=ts, host=r.get("Computer"),
            raw=RawRef(evidence_id=evidence_id, locator=f"record:{rec_id}", parser=PARSER),
        )
        proc = dict(pid=_int(d.get("ProcessId")), process_guid=_guid(d.get("ProcessGuid")),
                    image=d.get("Image"), user=d.get("User"))

        if src == EventSource.SYSMON:
            if eid == 1:
                yield CanonicalEvent(
                    action=Action.PROCESS_CREATE, **proc, **common,
                    command_line=d.get("CommandLine"), logon_id=d.get("LogonId"),
                    parent_pid=_int(d.get("ParentProcessId")),
                    parent_process_guid=_guid(d.get("ParentProcessGuid")),
                    attrs={"parent_image": d.get("ParentImage"),
                           "parent_command_line": d.get("ParentCommandLine"),
                           "current_directory": d.get("CurrentDirectory"),
                           "integrity_level": d.get("IntegrityLevel"),
                           "hashes": d.get("Hashes")})
            elif eid == 3:
                dst = f'{d.get("DestinationIp")}:{d.get("DestinationPort")}'
                yield CanonicalEvent(
                    action=Action.NET_CONNECT, **proc, **common, object=dst,
                    attrs={"dst_ip": d.get("DestinationIp"), "dst_port": _int(d.get("DestinationPort")),
                           "dst_host": d.get("DestinationHostname"), "protocol": d.get("Protocol"),
                           "initiated": str(d.get("Initiated", "true")).lower() == "true"})
            elif eid == 11:
                yield CanonicalEvent(action=Action.FILE_CREATE, **proc, **common, object=d.get("TargetFilename"))
            elif eid in (23, 26):
                yield CanonicalEvent(action=Action.FILE_DELETE, **proc, **common, object=d.get("TargetFilename"),
                                     attrs={"archived": eid == 23})
            elif eid == 13:
                yield CanonicalEvent(action=Action.REGISTRY_SET, **proc, **common, object=d.get("TargetObject"),
                                     attrs={"details": d.get("Details")})
            elif eid == 22:
                yield CanonicalEvent(action=Action.DNS_QUERY, **proc, **common, object=d.get("QueryName"),
                                     attrs={"results": d.get("QueryResults")})
        elif src == EventSource.SECURITY:
            if eid == 4624:
                yield CanonicalEvent(
                    action=Action.LOGON, **common, logon_id=d.get("TargetLogonId"),
                    user=f'{d.get("TargetDomainName")}\\{d.get("TargetUserName")}',
                    attrs={"logon_type": _int(d.get("LogonType")), "process": d.get("ProcessName")})
            elif eid == 4663 and (d.get("ObjectType") or "File") == "File":
                mask = _int(d.get("AccessMask")) or 0
                yield CanonicalEvent(
                    action=Action.FILE_READ if mask & READ_MASK else Action.FILE_MODIFY, **common,
                    pid=_int(d.get("ProcessId")), image=d.get("ProcessName"), object=d.get("ObjectName"),
                    logon_id=d.get("SubjectLogonId"),
                    user=f'{d.get("SubjectDomainName")}\\{d.get("SubjectUserName")}',
                    attrs={"access_mask": hex(mask), "accesses": (d.get("AccessList") or "").split(),
                           "handle_id": d.get("HandleId"), "via": "4663",
                           "ts_meaning": "handle access audited by the SACL on the object"})
            elif eid == 4688:
                yield CanonicalEvent(
                    action=Action.PROCESS_CREATE, **common, pid=_int(d.get("NewProcessId")),
                    image=d.get("NewProcessName"), command_line=d.get("CommandLine"),
                    parent_pid=_int(d.get("ProcessId")), logon_id=d.get("SubjectLogonId"),
                    user=f'{d.get("SubjectDomainName")}\\{d.get("SubjectUserName")}',
                    attrs={"parent_image": d.get("ParentProcessName"), "via": "4688"})
        elif src == EventSource.POWERSHELL and eid == 4104:
            yield CanonicalEvent(
                action=Action.SCRIPT_BLOCK, **common, pid=_int(r.get("ProcessID")),
                command_line=d.get("ScriptBlockText"),
                attrs={"script_block_id": d.get("ScriptBlockId"), "path": d.get("Path")})
