# Limitations

What the v1.0 results do and do not show. The numbers are in [RESULTS.md](RESULTS.md); the
decisions behind several of these points are in [ROADMAP.md](../ROADMAP.md), section 6.

## Dataset

- **Size.** 33 scored runs and 2 tampered copies, half the 60 in the proposal (ROADMAP section 5).
  Per-family and per-agent figures rest on two to six runs and are indicative only.
- **Successful attacks by a real model exist for data transmission only.** Qwen2.5-7B at
  temperature 0.7 followed 2 of 2 data-transmission payloads and 0 of 6 others; the persistence,
  file-change and download families are covered on host evidence by scripted runs only. The
  real-model localization figure (1.0) rests on 2 runs.
- **Claude Code never followed a payload** (0 of 4, two models, two labs). Its figures show that
  the pipeline handles a closed agent (runtime inference, the Bash wrapper, transcript
  cross-check), not how accurate it is on a Claude Code attack.
- **Scripted runs** use a stand-in model with a real agent, processes and host evidence. They count
  for host-side metrics only and are never mixed into real-model figures.
- **One lab setup.** Every run is a Windows 11 24H2 VM with Sysmon, the lab harness or Claude Code,
  and a Kali host for web, exfiltration sink and Zeek. Other Windows builds, EDR stacks or agents
  were not tested.

## Metrics and targets

- **Narrative grounding misses its target**: 0.091 unsupported sentences before validation on the
  training split against 0.05 (0 after validation, as required). Of the five dropped sentences,
  two are true claims the graph cannot show (cy-01 has no Sysmon network event for curl), two cite
  incompletely and one states a wrong relation. The prompt was frozen rather than tuned further on
  eight summaries.
- **The entity check matches text, not meaning.** A sentence passes if a named file or program
  appears in a cited node's facts; "t2 spawned curl.exe" citing cmd.exe passes because cmd.exe's
  command line contains curl.exe.
- **Impact accuracy is 0.333** (2 of 6). The four exfiltration runs collected before the file
  inventory can only be rated probable against a gold confirmed; the two later runs are exact.
- **Analyst utility is not measured.** The Plaso / Timesketch comparison was cut (no ethics
  clearance, no time).
- **Several targets are at 1.0 on a small set.** Perfect scores on 2 to 12 attack runs do not mean
  perfect accuracy in general; the baselines and ablations show which inputs those scores depend
  on (PID capture above all).

## Method

- **Context identifiers made no difference** because every agent in the dataset ran one call at a
  time with its full history in context, so the identifiers are recoverable from time order. An
  agent with parallel calls or a pruned context would need them; that case is untested.
- **AttnTrace is not built** (it needs attention weights the model server does not return), and
  leave-one-out replay was not validated on the real model (replay fidelity, docs/TESTING.md 10.5).
  The frozen results use the segment localizer, which needs no model.
- **AgentDFIR was not run.** The trace-only baseline reads the same agent-side records and stands
  in for it.
- **The agent's own activity is recognised by convention.** Model-server traffic is identified by
  the envelope's `model_api_domains`, and the harness's source copies by their SHA-256 file names.
  Another agent that writes its own records elsewhere would need the same treatment.
- **Clock alignment** relies on child PIDs where the trace has them; without PID capture the
  link recall falls to 0.158.
- **The local model is a 7B model on CPU** (5 to 10 minutes per summary). A larger model was not
  tried, so the narrative figures describe this pinned model only.

## Software

- **LangGraph and React were not used**; the harness is a plain loop and the UI a single page
  (ROADMAP section 6).
- **Docker**: the `ui` service was checked on Kali with a lab case; the `model` service
  (llama.cpp server, profile `llm`) was not run.
- **The UI has no login** and binds to 127.0.0.1; a case holds evidence and should not be served
  on a shared network.
- **The dataset package leaves out raw evidence** (memory-derived and host data). The published
  numbers can be checked against the package's analysis output and ground truths, and fully
  regenerated only from the original runs, whose evidence hashes the package records.
