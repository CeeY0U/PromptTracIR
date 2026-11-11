"""Import agent transcripts from an AgentDFIR .adfir evidence package.

AgentDFIR (https://github.com/efij/AgentDFIR) collects agent transcripts into a sealed,
content-addressed package (spec: docs/adfir-spec.md in that repo, package version 0.2):

    case.adfir/
      raw/<sha256>[.gz]   sealed evidence blobs, named by the SHA-256 of the plaintext
      manifest.jsonl      one record per artifact (artifact_id, logical_path, product,
                          artifact_type, status, codec, size, chunks[] ...)
      SHA256SUMS          hashes of every sealed file
      case.json, collection.jsonl, chain-of-custody.jsonl, SEAL.sig, seals/

`ptir import-adfir CASE PACKAGE`:
  1. checks that SHA256SUMS covers the sealed zone exactly and that every line matches
     the file it names. The ed25519 signature is NOT checked here, so a package that was
     edited and then re-sealed passes: run `agentdfir verify PACKAGE` for that;
  2. rebuilds each Claude Code session transcript from its blob(s), bounded by the
     recorded size, and checks that its SHA-256 equals the artifact_id;
  3. adds each transcript as evidence kind `claude_code`. The PromptTracIR evidence id is
     the SHA-256 of the same bytes, so it equals AgentDFIR's artifact_id and both tools
     point at the same evidence;
  4. preserves the package's sealed metadata files as kind `adfir_meta` and logs the
     import in the case's custody log.

Normalized AgentDFIR events (normalized/events.jsonl) are not used: they keep only short
summaries, and traceback needs the full text the model saw.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tempfile
from pathlib import Path, PurePosixPath

from .case import Case

META_FILES = ["case.json", "manifest.jsonl", "collection.jsonl", "chain-of-custody.jsonl", "SHA256SUMS",
              "SEAL.sig"]
SUPPORTED = {("claude-code", "agent_session")}
REQUIRED_SEALED = ["case.json", "manifest.jsonl", "collection.jsonl", "chain-of-custody.jsonl"]
UNSEALED_TOP = {"SHA256SUMS", "SEAL.sig", ".lock", "redaction-manifest.json"}


class PackageError(Exception):
    pass


def _safe(rel: str) -> bool:
    p = PurePosixPath(rel)
    return not p.is_absolute() and all(part not in ("", ".", "..") for part in p.parts) and "\\" not in rel


def verify(pkg: str | Path) -> list[str]:
    """Return a list of problems (empty when every SHA256SUMS entry matches)."""
    pkg = Path(pkg)
    sums = pkg / "SHA256SUMS"
    if not sums.exists():
        return ["SHA256SUMS missing: not an .adfir package, or it was never sealed"]
    problems, listed = [], set()
    for n, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        if not rel or len(digest) != 64:
            problems.append(f"SHA256SUMS line {n} is malformed")
            continue
        if not _safe(rel):
            problems.append(f"SHA256SUMS line {n} names an unsafe path: {rel}")
            continue
        if rel in listed:
            problems.append(f"SHA256SUMS lists {rel} twice")
        listed.add(rel)
        f = pkg / rel
        if not f.is_file():
            problems.append(f"missing: {rel}")
        elif hashlib.sha256(f.read_bytes()).hexdigest() != digest:
            problems.append(f"hash mismatch: {rel}")
    # the seal must cover the sealed zone exactly: required files, every blob, every archived seal
    for req in REQUIRED_SEALED:
        if req not in listed:
            problems.append(f"{req} is not covered by SHA256SUMS")
    for sub in ("raw", "seals"):
        for f in sorted((pkg / sub).glob("*")) if (pkg / sub).exists() else []:
            if f.is_file() and f"{sub}/{f.name}" not in listed:
                problems.append(f"{sub}/{f.name} is not covered by SHA256SUMS")
    for f in sorted(pkg.iterdir()):
        if f.is_file() and f.name not in UNSEALED_TOP and f.name not in listed:
            problems.append(f"{f.name} sits in the sealed zone but is not covered by SHA256SUMS")
    return problems


def manifest(pkg: str | Path) -> list[dict]:
    """Artifact records (the header line, which has no artifact_id, is skipped)."""
    out = []
    for line in (Path(pkg) / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("artifact_id"):
                out.append(r)
    return out


def _blob(pkg: Path, ident: str, codec: str | None, size: int) -> bytes:
    name = f"raw/{ident}.gz" if (codec or "none") == "gzip" else f"raw/{ident}"
    data = (pkg / name).read_bytes()
    if (codec or "none") == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                data = g.read(size + 1)       # bounded by the recorded size
        except (OSError, EOFError) as e:      # BadGzipFile, CRC errors, truncation
            raise PackageError(f"{name}: cannot decompress ({e})") from e
    if len(data) != size:
        raise PackageError(f"{name}: expected {size} bytes, got {len(data)}{'+' if len(data) > size else ''}")
    return data


def read_artifact(pkg: str | Path, rec: dict) -> bytes:
    pkg = Path(pkg)
    if rec.get("chunks"):
        data = b"".join(_blob(pkg, c["id"], c.get("codec"), int(c["size"])) for c in rec["chunks"])
    else:
        data = _blob(pkg, rec["artifact_id"], rec.get("codec"), int(rec["size"]))
    if hashlib.sha256(data).hexdigest() != rec["artifact_id"]:
        raise PackageError(f"artifact {rec['artifact_id'][:12]} ({rec.get('logical_path')}) does not match its id")
    return data


def import_package(case: Case, pkg: str | Path, force: bool = False) -> dict:
    pkg = Path(pkg)
    problems = verify(pkg)
    if problems and not force:
        raise PackageError("package failed verification:\n  " + "\n  ".join(problems))
    header = json.loads((pkg / "manifest.jsonl").read_text(encoding="utf-8").splitlines()[0])
    seen, imported, skipped, unreadable = set(), [], {}, []
    with tempfile.TemporaryDirectory() as tmp:
        for rec in manifest(pkg):
            key = (rec.get("product"), rec.get("artifact_type"))
            if rec.get("status") != "OK" or rec["artifact_id"] in seen:
                continue
            if key not in SUPPORTED or not str(rec.get("logical_path", "")).endswith(".jsonl"):
                label = f"{key[0]}/{key[1]}"
                skipped[label] = skipped.get(label, 0) + 1
                continue
            seen.add(rec["artifact_id"])
            try:
                data = read_artifact(pkg, rec)
            except (PackageError, FileNotFoundError) as e:
                if not force:
                    raise PackageError(str(e)) from e
                unreadable.append({"artifact_id": rec["artifact_id"], "logical_path": rec.get("logical_path"),
                                   "error": str(e)})
                continue
            name = PurePosixPath(str(rec.get("logical_path")).replace("\\", "/")).name or rec["artifact_id"]
            out = Path(tmp) / rec["artifact_id"][:12] / name
            out.parent.mkdir(parents=True)
            out.write_bytes(data)
            digest = case.add_evidence(out, "claude_code")
            assert digest == rec["artifact_id"]
            imported.append({"artifact_id": digest, "logical_path": rec.get("logical_path"),
                             "source_path": rec.get("source_path"), "round": rec.get("round")})
    for m in META_FILES:
        if (pkg / m).exists():
            case.add_evidence(pkg / m, "adfir_meta")
    summary = {"package": str(pkg.resolve()), "adfir_version": header.get("adfir_version"),
               "adfir_case_id": header.get("case_id"), "collector_version": header.get("collector_version"),
               "verification_problems": problems, "forced": bool(problems and force),
               "imported": imported, "unreadable": unreadable, "skipped_by_product": skipped}
    case._custody("adfir_imported", summary)
    return summary
