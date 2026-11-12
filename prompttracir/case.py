"""Case directory: hashed evidence storage, chain of custody, and the event store.

Layout:
    <case>/
      case.json            case metadata and task envelope
      custody.jsonl        append-only chain-of-custody log
      evidence/<sha256>/   preserved copy of each evidence file (read-only)
      events.duckdb        canonical events
      output/              analysis results (graph.json, findings.json, ...)
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import duckdb

from .schema import CanonicalEvent, RawRef

EVENT_COLUMNS = [
    "event_id", "source", "action", "timestamp", "ts_precision", "host", "user", "logon_id",
    "pid", "process_guid", "parent_pid", "parent_process_guid", "image", "command_line",
    "object", "session_id", "model_call_id", "tool_call_id", "fragment_id", "attrs", "raw",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Case:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.evidence_dir = self.root / "evidence"
        self.output_dir = self.root / "output"
        self.db_path = self.root / "events.duckdb"

    # ---------- lifecycle ----------
    @classmethod
    def create(cls, root: str | Path, name: str, envelope: dict | None = None) -> "Case":
        c = cls(root)
        if (c.root / "case.json").exists():
            raise FileExistsError(f"case already exists at {c.root}")
        c.evidence_dir.mkdir(parents=True, exist_ok=True)
        c.output_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "name": name,
            "created": _now(),
            # The task envelope describes what the user's request legitimately needed.
            # Scope rules flag actions outside it.
            "envelope": envelope or {"allowed_paths": [], "allowed_domains": [], "model_api_domains": []},
            "evidence": {},
        }
        (c.root / "case.json").write_text(json.dumps(meta, indent=2))
        c._custody("case_created", {"name": name})
        c._init_db()
        return c

    @property
    def meta(self) -> dict:
        return json.loads((self.root / "case.json").read_text())

    def _save_meta(self, meta: dict) -> None:
        (self.root / "case.json").write_text(json.dumps(meta, indent=2))

    def set_envelope(self, envelope: dict) -> None:
        meta = self.meta
        meta["envelope"] = envelope
        self._save_meta(meta)
        self._custody("envelope_set", envelope)

    def _custody(self, action: str, details: dict) -> None:
        rec = {"time": _now(), "actor": getpass.getuser(), "action": action, "details": details}
        with open(self.root / "custody.jsonl", "a") as f:
            f.write(json.dumps(rec) + "\n")

    # ---------- evidence ----------
    def add_evidence(self, path: str | Path, kind: str) -> str:
        """Copy an evidence file into the case, hash it, and make the copy read-only.

        kind tells `ingest` which parser to use (see parsers.PARSERS).
        Returns the evidence id (SHA-256)."""
        src = Path(path)
        digest = sha256_file(src)
        meta = self.meta
        if digest in meta["evidence"]:
            # Same bytes already preserved: keep the first record (and its ingest state).
            self._custody("evidence_duplicate", {"sha256": digest, "kind": kind,
                                                 "original_path": str(src.resolve())})
            return digest
        dest_dir = self.evidence_dir / digest
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        if not dest.exists():
            shutil.copy2(src, dest)
            os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        meta["evidence"][digest] = {
            "kind": kind, "file": str(dest.relative_to(self.root)), "original_path": str(src.resolve()),
            "size": src.stat().st_size, "added": _now(),
        }
        self._save_meta(meta)
        self._custody("evidence_added", {"sha256": digest, "kind": kind, "original_path": str(src.resolve())})
        return digest

    def add_evidence_dir(self, path: str | Path, kind: str) -> list[str]:
        """Add every file under a directory (recursively, in sorted order) with the same kind."""
        root = Path(path)
        return [self.add_evidence(f, kind) for f in sorted(root.rglob("*")) if f.is_file()]

    def verify_evidence(self) -> dict[str, bool]:
        """Re-hash every preserved file and report whether it still matches."""
        out = {}
        for digest, info in self.meta["evidence"].items():
            out[digest] = sha256_file(self.root / info["file"]) == digest
        self._custody("evidence_verified", {"results": out})
        return out

    def evidence_path(self, digest: str) -> Path:
        return self.root / self.meta["evidence"][digest]["file"]

    # ---------- event store ----------
    def _connect(self) -> duckdb.DuckDBPyConnection:
        return duckdb.connect(str(self.db_path))

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id VARCHAR PRIMARY KEY, source VARCHAR, action VARCHAR,
                    timestamp TIMESTAMPTZ, ts_precision VARCHAR, host VARCHAR, "user" VARCHAR,
                    logon_id VARCHAR, pid BIGINT, process_guid VARCHAR, parent_pid BIGINT,
                    parent_process_guid VARCHAR, image VARCHAR, command_line VARCHAR,
                    object VARCHAR, session_id VARCHAR, model_call_id VARCHAR,
                    tool_call_id VARCHAR, fragment_id VARCHAR, attrs JSON, raw JSON
                )
                """
            )

    def store_events(self, events: Iterable[CanonicalEvent]) -> int:
        """Bulk insert through a temporary NDJSON file and read_json. DuckDB's executemany
        inserts row by row (about 150 rows/s), far too slow for a $MFT with 10^5-10^6 records.
        Same semantics as before: INSERT OR REPLACE, and a later duplicate event_id wins."""
        total, rows = 0, {}
        for e in events:
            d = e.model_dump(mode="json")
            d["attrs"] = json.dumps(d["attrs"])
            d["raw"] = json.dumps(d["raw"])
            rows[d["event_id"]] = {c: d[c] for c in EVENT_COLUMNS}
            if len(rows) >= self.STORE_CHUNK:     # bounded memory; a later chunk still replaces
                total += self._bulk_insert(rows)
                rows = {}
        return total + (self._bulk_insert(rows) if rows else 0)

    STORE_CHUNK = 50_000

    def _bulk_insert(self, rows: dict[str, dict]) -> int:
        tmp = self.root / f".ingest-{os.getpid()}.ndjson"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for r in rows.values():
                    f.write(json.dumps(r) + "\n")
            types = {c: ("BIGINT" if c in ("pid", "parent_pid") else "VARCHAR") for c in EVENT_COLUMNS}
            casts = ", ".join(
                f'CAST("{c}" AS TIMESTAMPTZ)' if c == "timestamp" else
                f'CAST("{c}" AS JSON)' if c in ("attrs", "raw") else f'"{c}"' for c in EVENT_COLUMNS)
            cols = ", ".join(f'"{c}"' for c in EVENT_COLUMNS)
            with self._connect() as con:
                con.execute(
                    f"INSERT OR REPLACE INTO events ({cols}) SELECT {casts} FROM read_json(?, "
                    f"format='newline_delimited', columns={types!r})", [str(tmp)])
        finally:
            tmp.unlink(missing_ok=True)
        return len(rows)

    def load_events(self, where: str = "", params: list | None = None) -> list[CanonicalEvent]:
        # epoch_us avoids DuckDB's optional pytz dependency for TIMESTAMPTZ
        cols = ", ".join('epoch_us("timestamp")' if c == "timestamp" else f'"{c}"' for c in EVENT_COLUMNS)
        sql = f'SELECT {cols} FROM events {("WHERE " + where) if where else ""} ORDER BY "timestamp", event_id'
        with self._connect() as con:
            rows = con.execute(sql, params or []).fetchall()
        out = []
        for r in rows:
            d = dict(zip(EVENT_COLUMNS, r))
            d["timestamp"] = datetime.fromtimestamp(d["timestamp"] / 1e6, tz=timezone.utc)
            d["attrs"] = json.loads(d["attrs"]) if d["attrs"] else {}
            d["raw"] = RawRef(**json.loads(d["raw"]))
            out.append(CanonicalEvent(**{k: v for k, v in d.items() if v is not None or k in ("attrs", "raw")}))
        return out

    def write_output(self, name: str, data) -> Path:
        self.output_dir.mkdir(exist_ok=True)
        p = self.output_dir / name
        p.write_text(json.dumps(data, indent=2, default=str))
        return p

    def read_output(self, name: str):
        p = self.output_dir / name
        return json.loads(p.read_text()) if p.exists() else None
