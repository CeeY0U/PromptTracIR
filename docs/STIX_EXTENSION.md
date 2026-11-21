# PromptTracIR evidence: STIX 2.1 property extension

`ptir export-stix CASE` writes `CASE/output/stix_bundle.json`, a STIX 2.1 bundle of what the
analysis found, tagged with MITRE ATLAS and ATT&CK techniques. Most of it is plain STIX. What
STIX has no property for (evidence states, ProcessGuids, attribution, PromptTracIR's finding and
record IDs) travels in one property extension, defined in the bundle by this object:

| Property | Value |
| --- | --- |
| `type` | `extension-definition` |
| `name` | `PromptTracIR evidence` |
| `schema` | this page |
| `version` | `1.0.0` |
| `extension_types` | `["property-extension"]` |

A consumer that does not know the extension can ignore it; every object stays valid STIX 2.1
(checked with the OASIS `stix2-validator`, `ptir export-stix CASE --validate`).

## Properties

All properties are optional. An object carries the extension only when it has one of them.

### On `process` SCOs

| Property | Type | Meaning |
| --- | --- | --- |
| `process_guid` | string | Sysmon ProcessGuid of the process (the graph node `process:{guid}`). PIDs are reused; the GUID is not. |
| `attribution` | string | `agent`, `human`, `mixed` or `unknown`: who caused the process, from PromptTracIR's attribution layer. |

### On `observed-data` for a finding

| Property | Type | Meaning |
| --- | --- | --- |
| `finding` | string | Finding ID in `findings.json` (`F001`, ...). |
| `finding_kind` | string | `out_of_scope_file`, `external_egress`, `persistence`, `credential_access`, `temp_download`, `transcript_mismatch`, `untraced_agent_process` |
| `severity` | string | `high`, `medium` or `info`. |
| `evidence_status` | list of string | Evidence states of the graph edges touching the finding's nodes: `observed` (one parsed record), `corroborated` (two independent sources agree), `inferred` (traceback or a time-window join, no record links the two ends), `contradicted` (sources disagree). |
| `records` | list of string | Canonical event IDs that support the finding. Each resolves to a preserved evidence file and a locator in the case (`/api/raw/{id}` in the UI). |

### On the chain `observed-data`

| Property | Type | Meaning |
| --- | --- | --- |
| `first_deviation` | string | Graph ID of the first tool call that left the user's task. |
| `entry_points` | list of string | Graph IDs of the injected fragments the chain starts from. |

## Technique mapping

| Evidence in the case | Technique |
| --- | --- |
| An entry point (injected fragment) was found | ATLAS AML.T0051.001 LLM Prompt Injection: Indirect |
| A tool call the injection drove | ATLAS AML.T0053 AI Agent Tool Invocation |
| Egress with impact confirmed or probable, or by a call that read a sensitive file | ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation; ATT&CK T1700 AI-Enabled Exfiltration |
| Egress by a call that also created a file | ATT&CK T1105 Ingress Tool Transfer |
| Scheduled task / Run key | ATT&CK T1053.005 / T1547.001 |
| A non-sensitive file outside the task written or deleted | ATT&CK T1565.001 Stored Data Manipulation |

Each technique is an `attack-pattern` with an `external_references` entry (`mitre-atlas` or
`mitre-attack`), and a `sighting` lists the observed data that shows it on the analysed host.

## IDs

SCO IDs follow the STIX 2.1 UUIDv5 rule (namespace `00abedb4-aa42-466c-9c01-fed23315a9b7`, over
the SCO's ID-contributing properties). Other objects get a UUIDv4-form ID derived from the case
and the object, so exporting the same analysis twice gives the same bundle and a re-export can be
diffed.
