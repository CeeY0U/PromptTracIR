"""STIX 2.1 export of an analysed case, tagged with MITRE ATLAS and ATT&CK techniques (v0.7).

    ptir export-stix CASE [--out bundle.json] [--validate]

The bundle holds what the analysis found, in STIX terms:

  identity        PromptTracIR (the producer) and the analysed system (where things were sighted)
  SCOs            the processes, files (with their directories), network connections, IPv4
                  addresses, domains and source URLs of the attack chain and of every finding
  observed-data   one per finding and one for the whole chain, over those SCOs
  attack-pattern  the ATLAS / ATT&CK techniques the case shows (TECHNIQUES, mapping below)
  sighting        one per technique: which observed data shows it, on which system
  note            one per finding (its summary, severity, evidence state and record IDs), and the
                  validated local-model summary when the case has one
  incident        the case, related to every technique sighted
  report          wraps all of the above

How findings map to techniques (documented in the README):
  entry point found (an injected fragment)  AML.T0051.001 LLM Prompt Injection: Indirect
  any tool call the injection drove          AML.T0053 AI Agent Tool Invocation
  egress with impact confirmed or probable,  AML.T0086 Exfiltration via AI Agent Tool Invocation,
    or egress by a call that read a secret     ATT&CK T1700 AI-Enabled Exfiltration
  egress by a call that also created a file  ATT&CK T1105 Ingress Tool Transfer
  persistence (schtasks / Run key)           ATT&CK T1053.005 / T1547.001
  a non-sensitive file written or deleted    ATT&CK T1565.001 Stored Data Manipulation

Evidence states (observed, corroborated, inferred, contradicted) and PromptTracIR's own IDs
(ProcessGuid, attribution, finding and record IDs) travel in a STIX 2.1 property extension
(docs/STIX_EXTENSION.md). IDs are deterministic: SCOs follow the STIX 2.1 UUIDv5 rule; other
objects get a UUIDv4-form ID derived from the case and the object, so exporting the same
analysis twice gives the same bundle.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import PureWindowsPath

from .case import Case
from .graph import ProvGraph
from .schema import NodeKind

STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")     # STIX 2.1, section 2.9
PTIR_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/CeeY0U/PromptTracIR")

TECHNIQUES = {
    "AML.T0051.001": ("mitre-atlas", "LLM Prompt Injection: Indirect", "https://atlas.mitre.org/techniques/AML.T0051.001"),
    "AML.T0053": ("mitre-atlas", "AI Agent Tool Invocation", "https://atlas.mitre.org/techniques/AML.T0053"),
    "AML.T0086": ("mitre-atlas", "Exfiltration via AI Agent Tool Invocation", "https://atlas.mitre.org/techniques/AML.T0086"),
    "T1700": ("mitre-attack", "AI-Enabled Exfiltration", "https://attack.mitre.org/techniques/T1700/"),
    "T1105": ("mitre-attack", "Ingress Tool Transfer", "https://attack.mitre.org/techniques/T1105/"),
    "T1053.005": ("mitre-attack", "Scheduled Task/Job: Scheduled Task", "https://attack.mitre.org/techniques/T1053/005/"),
    "T1547.001": ("mitre-attack", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  "https://attack.mitre.org/techniques/T1547/001/"),
    "T1565.001": ("mitre-attack", "Data Manipulation: Stored Data Manipulation",
                  "https://attack.mitre.org/techniques/T1565/001/"),
}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _ts(value) -> str:
    """STIX timestamp, UTC, millisecond precision."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _canon(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _uuid4_from(key: str) -> uuid.UUID:
    """A UUIDv4-form ID derived from `key`: STIX wants v4 for objects without ID-contributing
    properties; deriving it keeps a re-export of the same analysis identical."""
    import hashlib
    return uuid.UUID(bytes=hashlib.sha256(key.encode()).digest()[:16], version=4)


EXTENSION_SCHEMA = "https://github.com/CeeY0U/PromptTracIR/blob/main/docs/STIX_EXTENSION.md"


class _Bundle:
    def __init__(self, case_key: str, created: str):
        self.case_key, self.created = case_key, created
        self.objects: dict[str, dict] = {}
        self.ext: str | None = None

    def x(self, props: dict) -> dict:
        """PromptTracIR's own properties, as a STIX 2.1 property extension."""
        props = {k: v for k, v in props.items() if v not in (None, "", [], {})}
        return {"extensions": {self.ext: {"extension_type": "property-extension", **props}}} if props else {}

    def sco(self, type_: str, contributing: dict, key: str | None = None, **props) -> str:
        """An SCO: UUIDv5 over its ID-contributing properties (STIX 2.1, 2.9), or a derived v4
        for types without any (process)."""
        if contributing:
            sid = f"{type_}--{uuid.uuid5(STIX_NS, _canon(contributing))}"
        else:
            sid = f"{type_}--{_uuid4_from(f'{self.case_key}|{type_}|{key}')}"
        if sid not in self.objects:
            self.objects[sid] = {"type": type_, "spec_version": "2.1", "id": sid, **contributing, **props}
        return sid

    def sdo(self, type_: str, key: str, **props) -> str:
        sid = f"{type_}--{_uuid4_from(f'{self.case_key}|{type_}|{key}')}"
        if sid not in self.objects:
            self.objects[sid] = {"type": type_, "spec_version": "2.1", "id": sid,
                                 "created": self.created, "modified": self.created, **props}
        return sid


def _file(b: _Bundle, path: str, size=None, sha256=None) -> str:
    p = PureWindowsPath(path)
    contrib = {"name": p.name or str(p)}
    if sha256:
        contrib["hashes"] = {"SHA-256": sha256}
    parent = str(p.parent) if p.parent != p else None
    if parent:
        contrib["parent_directory_ref"] = b.sco("directory", {"path": parent})
    props = {"size": int(size)} if str(size or "").isdigit() else {}
    return b.sco("file", contrib, **props)


def _node_sco(b: _Bundle, pg: ProvGraph, nid: str, done: dict[str, str | None]) -> str | None:
    """The SCO for a graph node (None for nodes STIX has no observable for)."""
    if nid in done:
        return done[nid]
    done[nid] = None
    n = pg.node(nid)
    a = n.attrs
    sid = None
    if n.kind == NodeKind.PROCESS:
        props = b.x({"process_guid": nid.split(":", 1)[1], "attribution": a.get("attribution")})
        if str(a.get("pid") or "").isdigit():
            props["pid"] = int(a["pid"])
        if a.get("command_line"):
            props["command_line"] = a["command_line"]
        if a.get("ts"):
            props["created_time"] = _ts(a["ts"])
        if a.get("image"):
            props["image_ref"] = _file(b, a["image"])
        sid = b.sco("process", {}, key=nid, **props)
    elif n.kind == NodeKind.FILE and a.get("path"):
        sid = _file(b, a["path"], a.get("size"), a.get("sha256"))
    elif n.kind == NodeKind.NETWORK and a.get("ip"):
        ip = a["ip"]
        dst = b.sco("ipv4-addr" if _IPV4.match(ip) else "ipv6-addr", {"value": ip})
        contrib = {"dst_ref": dst, "protocols": ["tcp"]}
        if str(a.get("port") or "").isdigit():
            contrib["dst_port"] = int(a["port"])
        sid = b.sco("network-traffic", contrib)
    elif n.kind == NodeKind.DOMAIN and "." in n.label and not n.label.endswith(".arpa."):
        sid = b.sco("domain-name", {"value": n.label.rstrip(".").lower()})
    elif n.kind == NodeKind.SOURCE and re.match(r"^[a-z][a-z0-9+.-]*://", n.label, re.I):
        sid = b.sco("url", {"value": n.label})
    done[nid] = sid
    return sid


def _link_processes(b: _Bundle, pg: ProvGraph, done: dict[str, str | None]) -> None:
    """parent_ref / child_refs for spawned edges between exported processes."""
    for e in pg.edges():
        if e.relation != "spawned":
            continue
        p, c = done.get(e.src), done.get(e.dst)
        if p and c and p.startswith("process--") and c.startswith("process--"):
            b.objects[c]["parent_ref"] = p
            kids = b.objects[p].setdefault("child_refs", [])
            if c not in kids:
                kids.append(c)


def techniques_for(finding: dict, findings: list[dict], impact: list[dict], pg: ProvGraph) -> list[str]:
    """ATLAS / ATT&CK techniques one finding shows (mapping in the module docstring)."""
    kind, attrs = finding["kind"], finding.get("attrs") or {}
    tc = attrs.get("tool_call")
    out = ["AML.T0053"] if tc else []
    if kind == "external_egress":
        level = {i["destination"]: i["level"] for i in impact}.get(attrs.get("destination"))
        secret = any(f["kind"] == "out_of_scope_file" and (f.get("attrs") or {}).get("sensitive")
                     and (f.get("attrs") or {}).get("tool_call") == tc for f in findings)
        created = any(f["kind"] in ("out_of_scope_file", "temp_download")
                      and (f.get("attrs") or {}).get("relation") in ("created", "wrote")
                      and not (f.get("attrs") or {}).get("sensitive")
                      and tc in ((f.get("attrs") or {}).get("tool_call"), (f.get("attrs") or {}).get("context_tool_call"))
                      for f in findings)
        if level in ("confirmed", "probable") or secret:
            out += ["AML.T0086", "T1700"]
        elif created:
            out.append("T1105")
    elif kind == "persistence":
        cmd = " ".join(str(pg.node(n).attrs.get("command_line") or "") for n in finding.get("nodes") or []
                       if n in pg.g).lower() + " " + finding.get("summary", "").lower()
        out.append("T1547.001" if re.search(r"currentversion\\run|startup", cmd) else "T1053.005")
    elif kind == "out_of_scope_file" and not attrs.get("sensitive") \
            and attrs.get("relation") in ("wrote", "modified", "deleted"):
        out.append("T1565.001")
    return out


def export_case(case: Case, tag: str | None = None) -> dict:
    """The STIX 2.1 bundle for an analysed case."""
    out = case.view(tag) if tag else case
    graph = out.read_output("graph.json")
    if graph is None:
        raise ValueError(f"{case.root}: not analysed (run ptir analyze first)")
    pg = ProvGraph.from_json(graph)
    findings = out.read_output("findings.json") or []
    impact = out.read_output("impact.json") or []
    chain = out.read_output("chain.json") or {}
    llm = out.read_output("llm.json") or {}
    meta = case.meta
    created = _ts(chain.get("generated") or meta.get("created") or datetime.now(timezone.utc))
    b = _Bundle(f"{meta.get('name')}|{meta.get('created')}|{tag or ''}", created)

    me = b.sdo("identity", "producer", name="PromptTracIR", identity_class="system",
               description="Forensic attribution and reconstruction of prompt-injection incidents in AI agents")
    b.ext = b.sdo("extension-definition", "prompttracir", created_by_ref=me, name="PromptTracIR evidence",
                  description="PromptTracIR's own identifiers and evidence states (ProcessGuid, attribution, "
                              "finding, edge status, record IDs)",
                  schema=EXTENSION_SCHEMA, version="1.0.0", extension_types=["property-extension"])
    host = b.sdo("identity", "host", name=f"analysed system (case {meta.get('name')})", identity_class="system",
                 created_by_ref=me)
    done: dict[str, str | None] = {}
    events = {}
    ev_ids = sorted({e for f in findings for e in f.get("evidence") or []})
    if ev_ids:
        try:
            marks = ",".join("?" * len(ev_ids))
            events = {e.event_id: e for e in case.load_events(f"event_id IN ({marks})", ev_ids)}
        except Exception:      # noqa: BLE001 - a case without its event store still exports
            events = {}

    def window(ids: list[str]) -> tuple[str, str]:
        ts = sorted(events[i].timestamp for i in ids if i in events)
        return (_ts(ts[0]), _ts(ts[-1])) if ts else (created, created)

    observed: dict[str, list[str]] = {}          # technique -> observed-data ids
    notes = []
    for f in findings:
        scos = [s for s in (_node_sco(b, pg, n, done) for n in f.get("nodes") or [] if n in pg.g) if s]
        if not scos:
            continue
        first, last = window(f.get("evidence") or [])
        statuses = sorted({e.status.value for e in pg.edges()
                           if e.src in (f.get("nodes") or []) or e.dst in (f.get("nodes") or [])})
        od = b.sdo("observed-data", f["finding_id"], created_by_ref=me, first_observed=first, last_observed=last,
                   number_observed=1, object_refs=sorted(set(scos)),
                   **b.x({"finding": f["finding_id"], "finding_kind": f["kind"], "severity": f["severity"],
                          "evidence_status": statuses, "records": f.get("evidence") or []}))
        techs = techniques_for(f, findings, impact, pg)
        for t in techs:
            observed.setdefault(t, []).append(od)
        notes.append((f, od, techs))

    chain_scos = [s for s in (_node_sco(b, pg, n, done) for n in chain.get("nodes") or [] if n in pg.g) if s]
    chain_od = None
    if chain_scos:
        chain_od = b.sdo("observed-data", "chain", created_by_ref=me, first_observed=created,
                         last_observed=created, number_observed=1, object_refs=sorted(set(chain_scos)),
                         **b.x({"first_deviation": chain.get("first_deviation"),
                                "entry_points": [e.get("fragment") for e in chain.get("entry_points") or []]}))
        if chain.get("entry_points"):
            observed.setdefault("AML.T0051.001", []).append(chain_od)
        times = sorted(o.get("first_observed") for o in b.objects.values() if o["type"] == "observed-data"
                       and o["id"] != chain_od)
        if times:
            b.objects[chain_od]["first_observed"] = times[0]
            b.objects[chain_od]["last_observed"] = max(o.get("last_observed") for o in b.objects.values()
                                                       if o["type"] == "observed-data" and o["id"] != chain_od)
    _link_processes(b, pg, done)

    patterns = {}
    for t in sorted(observed):
        src, name, url = TECHNIQUES[t]
        patterns[t] = b.sdo("attack-pattern", t, created_by_ref=me, name=name,
                            external_references=[{"source_name": src, "external_id": t, "url": url}])
        ods = sorted(set(observed[t]))
        seen = [b.objects[o] for o in ods]
        b.sdo("sighting", t, created_by_ref=me, sighting_of_ref=patterns[t], observed_data_refs=ods,
              where_sighted_refs=[host], count=len(ods),
              first_seen=min(o["first_observed"] for o in seen), last_seen=max(o["last_observed"] for o in seen))
    for f, od, techs in notes:
        b.sdo("note", f["finding_id"], created_by_ref=me, authors=["PromptTracIR"],
              abstract=f"{f['finding_id']} {f['kind']} ({f['severity']})", content=f["summary"],
              object_refs=[od] + [patterns[t] for t in techs])
    summary = (llm.get("summary") or {}).get("summary")
    description = (f"First deviating tool call: {chain.get('first_deviation')}. "
                   f"{len(findings)} findings.") if chain.get("first_deviation") else f"{len(findings)} findings."
    incident = b.sdo("incident", "case", created_by_ref=me, name=f"PromptTracIR case {meta.get('name')}",
                     description=description)
    if summary:
        s = llm["summary"]
        b.sdo("note", "narrative", created_by_ref=me, authors=["PromptTracIR local-model summary (validated)"],
              abstract="Validated summary", object_refs=[incident],
              content=f"{summary}\n\n({s.get('kept')} of {s.get('sentences')} sentences kept; checks: "
                      f"{s.get('validation') or 'ids+entities'})")
    for t, pid in patterns.items():
        b.sdo("relationship", f"incident-{t}", created_by_ref=me, relationship_type="related-to",
              source_ref=incident, target_ref=pid)
    refs = sorted(o for o in b.objects if not o.startswith("report--"))
    b.sdo("report", "case", created_by_ref=me, name=f"PromptTracIR analysis of case {meta.get('name')}",
          published=created, report_types=["threat-report"], object_refs=refs,
          description=description)
    return {"type": "bundle", "id": f"bundle--{_uuid4_from(b.case_key + '|bundle')}",
            "objects": list(b.objects.values())}


def validate(bundle: dict) -> tuple[bool, list[str]]:
    """Run the OASIS STIX 2.1 validator when it is installed (pip install stix2-validator)."""
    try:
        from stix2validator import ValidationOptions, validate_parsed_json
    except ImportError:
        return True, ["stix2-validator not installed: not validated"]
    res = validate_parsed_json(bundle, ValidationOptions(version="2.1"))
    msgs = [f"error: {e}" for e in getattr(res, "errors", [])] + [f"warning: {w}" for w in getattr(res, "warnings", [])]
    for obj in getattr(res, "object_results", []) or []:
        msgs += [f"{obj.object_id}: error: {e}" for e in obj.errors] + [f"{obj.object_id}: warning: {w}" for w in obj.warnings]
    return bool(res.is_valid), msgs
