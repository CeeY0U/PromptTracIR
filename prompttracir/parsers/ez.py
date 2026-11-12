"""Adapters for Eric Zimmerman tool CSV output (the "EZ Tools").

The raw artifacts ($MFT, $J, .pf, Amcache.hve, SRUDB.dat, hives, .lnk, Jump Lists) stay
preserved under their raw kinds. Run the matching tool on the analyst machine (or with
tools/parse-artifacts.ps1 on the VM) and add its CSV under the ez_* kind below. Column names
follow the tools' own CSV classes; unknown extra columns are ignored, missing ones read as blank.

| kind          | tool          | one event per                       | action           | timestamp means            |
|---------------|---------------|-------------------------------------|------------------|----------------------------|
| ez_mft        | MFTECmd $MFT  | file record (create, +modify)       | file_create/_modify | $SI created / modified (can be timestomped; $FN kept in attrs) |
| ez_usn        | MFTECmd $J    | closed USN change                   | file_create/_delete/_rename/_modify | USN record time (reliable) |
| ez_prefetch   | PECmd         | recorded run time (up to 8)         | program_run      | run time; weak for authorship |
| ez_amcache    | AmcacheParser | file entry                          | program_present  | key last-write, NOT execution time |
| ez_srum       | SrumECmd NetworkUsages | app x hour record          | net_usage        | end of an ~1 h SRUM interval |
| ez_registry   | RECmd batch   | key/value row                       | gui_launch / autorun / registry_value | UserAssist last run, else key last-write |
| ez_lnk        | LECmd         | .lnk file                           | file_open        | .lnk modified = last open via Explorer |
| ez_jumplist   | JLECmd        | DestList entry                      | file_open        | DestList entry last modified |
| ez_shellbags  | SBECmd        | shell bag                           | folder_open      | last interacted, else key last-write |

None of these events carry a ProcessGuid, so they never create observed edges in the
provenance graph by themselves; attribution (v0.4) and reconstruction (v0.5) consume them as
independent signals. Every event records what its timestamp means in attrs["ts_meaning"].
"""
from __future__ import annotations

import csv
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ..schema import Action, CanonicalEvent, EventSource, RawRef

PARSER_VERSION = "0.3.0"
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))   # MFTECmd resident data columns can be large


# ---------------- helpers ----------------
def _rows(path: Path) -> Iterator[tuple[int, dict]]:
    """Yield (line number, row) from an EZ Tools CSV (UTF-8 with or without BOM)."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield reader.line_num, {k.strip(): (v or "").strip() for k, v in row.items() if k}


def _time(value: str | None) -> datetime | None:
    """EZ Tools write UTC as 'yyyy-MM-dd HH:mm:ss[.fffffff]'. Blank, '0001-01-01...' and
    '1601-01-01...' (an unset FILETIME) mean no time."""
    from . import parse_time

    if not value or value.startswith(("0001-01-01", "1601-01-01")):
        return None
    try:
        return parse_time(value)
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    try:
        return int(str(value).replace(",", "")) if value not in (None, "") else None
    except ValueError:
        return None


def _bool(value: str | None) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _join(parent: str | None, name: str | None) -> str | None:
    if not name:
        return parent or None
    if not parent:
        return name
    parent = parent.rstrip("\\")
    if parent in (".", ""):
        return name
    return f"{parent}\\{name}"


def _abs(path: str | None) -> str | None:
    """MFTECmd writes paths relative to the volume root ('.\\Users\\lab'); make them C:\\-style
    so they compare with Sysmon paths. The drive letter is assumed to be C:."""
    if not path:
        return path
    if path.startswith(".\\"):
        return "C:\\" + path[2:]
    if path == ".":
        return "C:\\"
    return path


def _event(kind: str, source: EventSource, action: Action, ts: datetime, evidence_id: str,
           lineno: int, suffix: str = "", precision: str = "ms", **fields) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"{kind}:{evidence_id[:12]}:{lineno:08d}{suffix}",
        source=source, action=action, timestamp=ts, ts_precision=precision,
        raw=RawRef(evidence_id=evidence_id, locator=f"line:{lineno}", parser=kind,
                   parser_version=PARSER_VERSION),
        **fields)


# ---------------- NTFS ----------------
def parse_mft(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """MFTECmd -f $MFT --csv. Directories are skipped; deleted (not in-use) records are kept."""
    for lineno, r in _rows(path):
        if _bool(r.get("IsDirectory")):
            continue
        target = _abs(_join(r.get("ParentPath"), r.get("FileName")))
        if not target:
            continue
        attrs = {
            "entry": _int(r.get("EntryNumber")), "sequence": _int(r.get("SequenceNumber")),
            "in_use": _bool(r.get("InUse")) if r.get("InUse") else True,
            "size": _int(r.get("FileSize")), "extension": r.get("Extension") or None,
            "has_ads": _bool(r.get("HasAds")), "zone_id": r.get("ZoneIdContents") or None,
            "si_created": r.get("Created0x10") or None, "fn_created": r.get("Created0x30") or None,
            "si_modified": r.get("LastModified0x10") or None,
            "fn_modified": r.get("LastModified0x30") or None,
            "si_record_change": r.get("LastRecordChange0x10") or None,
            "si_access": r.get("LastAccess0x10") or None,
            # MFTECmd's own SI<FN / uSecZeros checks, the usual timestomping indicators
            "timestomped": _bool(r.get("Timestomped")) or _bool(r.get("SI<FN")),
            "usec_zeros": _bool(r.get("uSecZeros")), "copied": _bool(r.get("Copied")),
        }
        created = _time(r.get("Created0x10"))
        modified = _time(r.get("LastModified0x10"))
        if created:
            yield _event("ez_mft", EventSource.MFT, Action.FILE_CREATE, created, evidence_id, lineno,
                         ":c", object=target, attrs=attrs | {"ts_meaning": "$SI created"})
        if modified and modified != created:
            yield _event("ez_mft", EventSource.MFT, Action.FILE_MODIFY, modified, evidence_id, lineno,
                         ":m", object=target, attrs=attrs | {"ts_meaning": "$SI last modified"})


# USN reasons -> action, by priority. Only records with "Close" are emitted: NTFS writes
# one record per change while a handle is open, and the Close record carries all of them.
_USN_ACTIONS = [("FileDelete", Action.FILE_DELETE), ("FileCreate", Action.FILE_CREATE),
                ("RenameNewName", Action.FILE_RENAME), ("DataOverwrite", Action.FILE_MODIFY),
                ("DataExtend", Action.FILE_MODIFY), ("DataTruncation", Action.FILE_MODIFY)]


def parse_usn(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """MFTECmd -f $J --csv (add -m $MFT so ParentPath is resolved)."""
    old_names: dict[tuple, str] = {}
    for lineno, r in _rows(path):
        reasons = {x.strip() for x in (r.get("UpdateReasons") or "").split("|")}
        key = (r.get("EntryNumber"), r.get("SequenceNumber"))
        name = _abs(_join(r.get("ParentPath"), r.get("Name")))
        if "RenameOldName" in reasons:
            old_names[key] = name
            continue
        if "Close" not in reasons:
            continue
        action = next((a for reason, a in _USN_ACTIONS if reason in reasons), None)
        ts = _time(r.get("UpdateTimestamp"))
        if action is None or ts is None or not name:
            continue
        attrs = {"reasons": sorted(reasons), "entry": _int(key[0]), "sequence": _int(key[1]),
                 "usn": _int(r.get("UpdateSequenceNumber")), "file_attributes": r.get("FileAttributes"),
                 "path_resolved": bool(r.get("ParentPath")), "ts_meaning": "USN record time"}
        if action == Action.FILE_RENAME and key in old_names:
            attrs["old_name"] = old_names.pop(key)
        yield _event("ez_usn", EventSource.USN, action, ts, evidence_id, lineno, object=name, attrs=attrs)


# ---------------- execution ----------------
def _prefetch_image(r: dict) -> str | None:
    """PECmd's FullPath column (newer versions), else the FilesLoaded entry that matches."""
    if r.get("FullPath"):
        return r["FullPath"]
    exe = (r.get("ExecutableName") or "").upper()
    for f in (r.get("FilesLoaded") or "").split(","):
        f = f.strip()
        if exe and f.upper().endswith("\\" + exe):
            # \VOLUME{01d...-1234}\WINDOWS\SYSTEM32\CURL.EXE -> C:\WINDOWS\SYSTEM32\CURL.EXE
            return re.sub(r"^\\VOLUME\{[^}]*\}", "C:", f, flags=re.I)
    return r.get("ExecutableName") or None


def parse_prefetch(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """PECmd -d C:\\Windows\\Prefetch --csv (the main CSV, not *_Timeline.csv)."""
    for lineno, r in _rows(path):
        if not r.get("ExecutableName"):
            continue
        image = _prefetch_image(r)
        times = [r.get("LastRun")] + [r.get(f"PreviousRun{i}") for i in range(7)]
        base = {"run_count": _int(r.get("RunCount")), "prefetch_hash": r.get("Hash") or None,
                "prefetch_file": r.get("SourceFilename") or None, "executable": r.get("ExecutableName"),
                # Prefetch says a binary ran, not who started it; it must not decide authorship alone.
                "authorship_weight": "weak", "ts_meaning": "Prefetch recorded run time"}
        for i, t in enumerate(times):
            ts = _time(t)
            if ts:
                yield _event("ez_prefetch", EventSource.PREFETCH, Action.PROGRAM_RUN, ts, evidence_id,
                             lineno, f":{i}", image=image, precision="s",
                             attrs=base | {"run_index": i})


def _amcache_sha1(v: str | None) -> str | None:
    if not v:
        return None
    v = v.lower()
    return v[4:] if len(v) == 44 and v.startswith("0000") else v   # Amcache pads SHA-1 with 0000


def parse_amcache(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """AmcacheParser -f Amcache.hve --csv: the *FileEntries.csv outputs (Win10+ and Win8 layouts).
    Other AmcacheParser CSVs (programs, drivers, shortcuts) have no FullPath column and yield nothing."""
    for lineno, r in _rows(path):
        full = r.get("FullPath")
        ts = _time(r.get("FileKeyLastWriteTimestamp") or r.get("FileIDLastWriteTimestamp"))
        if not full or ts is None:
            continue
        yield _event("ez_amcache", EventSource.AMCACHE, Action.PROGRAM_PRESENT, ts, evidence_id, lineno,
                     image=full, precision="s",
                     attrs={"sha1": _amcache_sha1(r.get("SHA1")), "sha256": r.get("Sha256") or None,
                            "name": r.get("Name") or None, "product": r.get("ProductName") or None,
                            "publisher": r.get("Publisher") or None,
                            "program": r.get("ApplicationName") or r.get("ProgramName") or None,
                            "is_os_component": _bool(r.get("IsOsComponent")),
                            "link_date": r.get("LinkDate") or None,
                            "ts_meaning": "Amcache key last-write (not execution time)"})


# ---------------- network usage ----------------
def parse_srum(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """SrumECmd -f SRUDB.dat -r SOFTWARE --csv: the *_SrumECmd_NetworkUsages_Output.csv file."""
    for lineno, r in _rows(path):
        if "BytesSent" not in r:
            continue
        ts = _time(r.get("Timestamp"))
        if ts is None:
            continue
        sent, recv = _int(r.get("BytesSent")) or 0, _int(r.get("BytesReceived")) or 0
        yield _event("ez_srum", EventSource.SRUM, Action.NET_USAGE, ts, evidence_id, lineno,
                     image=r.get("ExeInfo") or None, user=r.get("UserName") or r.get("Sid") or None,
                     precision="h",
                     attrs={"bytes_sent": sent, "bytes_received": recv, "app_id": _int(r.get("AppId")),
                            "interface_type": r.get("InterfaceType") or None,
                            "profile": r.get("ProfileName") or None, "srum_id": _int(r.get("Id")),
                            "ts_meaning": "end of a SRUM interval (about 1 hour)"})


# ---------------- registry ----------------
_UA_LAST = re.compile(r"Last executed:\s*(.+)", re.I)
_UA_COUNT = re.compile(r"Run count:\s*([\d,]+)", re.I)


def parse_registry(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """RECmd --bn <batch>.reb --csv (e.g. the Kroll or DFIR batch file).

    UserAssist rows (decoded by the UserAssist plugin) become gui_launch, a human-side signal:
    the program was started from the Explorer shell. Rows in the Autoruns category become
    autorun (persistence). Everything else becomes registry_value."""
    for lineno, r in _rows(path):
        key = r.get("KeyPath") or ""
        value = r.get("ValueName") or ""
        desc, category = r.get("Description") or "", r.get("Category") or ""
        key_ts = _time(r.get("LastWriteTimestamp"))
        common = {"category": category or None, "description": desc or None,
                  "hive": r.get("HivePath") or None, "hive_type": r.get("HiveType") or None,
                  "deleted": _bool(r.get("Deleted")), "key": key or None}
        if desc.lower() == "userassist":
            m = _UA_LAST.search(r.get("ValueData2") or "")
            ts = _time(m.group(1).strip()) if m else None
            c = _UA_COUNT.search(r.get("ValueData3") or "")
            meaning = "UserAssist last executed"
            if ts is None:
                ts, meaning = key_ts, "UserAssist key last-write (no last-executed time)"
            if ts is None:
                continue
            yield _event("ez_registry", EventSource.REGISTRY, Action.GUI_LAUNCH, ts, evidence_id, lineno,
                         image=r.get("ValueData") or value or None, precision="ms",
                         attrs=common | {"run_count": _int(c.group(1)) if c else None,
                                         "ts_meaning": meaning})
            continue
        if key_ts is None:
            continue
        action = Action.AUTORUN if category.lower() == "autoruns" else Action.REGISTRY_VALUE
        yield _event("ez_registry", EventSource.REGISTRY, action, key_ts, evidence_id, lineno,
                     object=f"{key}\\{value}" if value else key, precision="ms",
                     attrs=common | {"value": value or None, "data": r.get("ValueData") or None,
                                     "data2": r.get("ValueData2") or None,
                                     "data3": r.get("ValueData3") or None,
                                     "ts_meaning": "registry key last-write"})


# ---------------- user activity ----------------
def _lnk_target(r: dict) -> str | None:
    return (r.get("LocalPath") or r.get("NetworkPath") or r.get("TargetIDAbsolutePath")
            or r.get("Path") or None)


def parse_lnk(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """LECmd -d <Recent> --csv. Explorer creates or updates a .lnk in Recent when a user opens a file."""
    for lineno, r in _rows(path):
        target = _lnk_target(r)
        ts = _time(r.get("SourceModified")) or _time(r.get("SourceCreated"))
        if not target or ts is None:
            continue
        yield _event("ez_lnk", EventSource.LNK, Action.FILE_OPEN, ts, evidence_id, lineno,
                     object=target,
                     attrs={"lnk_file": r.get("SourceFile") or None,
                            "first_opened": r.get("SourceCreated") or None,
                            "arguments": r.get("Arguments") or None,
                            "working_directory": r.get("WorkingDirectory") or None,
                            "machine_id": r.get("MachineID") or None,
                            "ts_meaning": ".lnk modified (last open via the shell)"})


def parse_jumplist(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """JLECmd -d <AutomaticDestinations> --csv. CustomDestinations rows have no DestList time and
    fall back to the jump list file's modified time."""
    for lineno, r in _rows(path):
        target = _lnk_target(r)
        ts, meaning = _time(r.get("LastModified")), "DestList entry last modified"
        if ts is None:
            ts, meaning = _time(r.get("SourceModified")), "jump list file modified"
        if not target or ts is None:
            continue
        yield _event("ez_jumplist", EventSource.JUMPLIST, Action.FILE_OPEN, ts, evidence_id, lineno,
                     object=target,
                     attrs={"app_id": r.get("AppId") or None, "app": r.get("AppIdDescription") or None,
                            "interaction_count": _int(r.get("InteractionCount")),
                            "pinned": _bool(r.get("PinStatus")) if r.get("PinStatus") else None,
                            "jumplist_file": r.get("SourceFile") or None,
                            "arguments": r.get("Arguments") or None, "ts_meaning": meaning})


def parse_shellbags(path: Path, evidence_id: str) -> Iterator[CanonicalEvent]:
    """SBECmd -d <dir with NTUSER.DAT / UsrClass.dat> --csv. Shell bags record folders a user
    browsed in Explorer, so they are a human-side signal."""
    for lineno, r in _rows(path):
        target = r.get("AbsolutePath")
        ts, meaning = _time(r.get("LastInteracted")), "shell bag last interacted"
        if ts is None:
            ts, meaning = _time(r.get("LastWriteTime")), "shell bag key last-write"
        if not target or ts is None:
            continue
        yield _event("ez_shellbags", EventSource.SHELLBAGS, Action.FOLDER_OPEN, ts, evidence_id, lineno,
                     object=target,
                     attrs={"shell_type": r.get("ShellType") or None, "bag_path": r.get("BagPath") or None,
                            "first_interacted": r.get("FirstInteracted") or None,
                            "has_explored": _bool(r.get("HasExplored")), "ts_meaning": meaning})
