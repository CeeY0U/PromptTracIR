# Testing guide: v0.1.1 to v0.3.0

This guide covers every check up to v0.3.0, in the order to run them:

| Part | Where | Needs | Time |
|---|---|---|---|
| [1. Automated tests](#part-1-automated-tests) | any machine | Python 3.10+ | 5 min |
| [2. CI on GitHub](#part-2-ci-on-github) | GitHub | a push | 5 min |
| [3. CLI smoke test](#part-3-cli-smoke-test-on-synthetic-data) | any machine | Part 1 | 10 min |
| [4. One real lab run](#part-4-one-real-lab-run) | lab VM + attacker box | lab built | 1 h first time |
| [5. Claude Code through AgentDFIR](#part-5-claude-code-through-agentdfir) | lab VM | Claude Code, AgentDFIR | 30 min |
| [6. Scoring many runs](#part-6-scoring-many-runs) | analyst machine | 2+ labelled runs | 5 min |
| [7. v0.2 acceptance checklist](#part-7-v02-acceptance-checklist) | n/a | Parts 1 to 6 | n/a |

Parts 1 to 3 need no VM, model or network. Parts 4 to 6 are the real v0.2 milestone: nothing in
`tools/collect-run.ps1` has run on a real Windows VM yet, so expect to fix things on the first run.
That is the point of v0.2.

---

## Part 1: Automated tests

### 1.1 Set up

Linux or macOS:

```bash
git clone https://github.com/CeeY0U/PromptTracIR.git && cd PromptTracIR
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[evtx,dev]"
```

Windows (PowerShell):

```powershell
git clone https://github.com/CeeY0U/PromptTracIR.git; cd PromptTracIR
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[evtx,dev]"
```

If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### 1.2 Run

```bash
pytest -q
```

Expected: `80 passed`. Run one file with `pytest -q tests/test_importers.py`, or one test with
`pytest -q -k adfir_tampering`.

### 1.3 What the tests cover

| File | Version | Covers |
|---|---|---|
| `tests/test_pipeline.py` | v0.1 | hashing and custody; end-to-end analysis; corroborated tool links; replay traceback; LLM output validation; harness agent against a fake model |
| `tests/test_runs.py` | v0.2 | `ptir add-run` kind mapping, `collection.json` override, label files skipped, unknown kinds rejected, re-adding is idempotent, `ptir add` on a directory |
| `tests/test_harness.py` | v0.2 | raw source bytes kept under `sources/`; scenario schema rules; `prepare` writes and splits VM files from web pages; `label_run` matches the sample's ground truth, resolves child PID to ProcessGuid, ignores sink hits from other runs, labels legitimate and Claude Code runs |
| `tests/test_importers.py` | v0.2 | Claude Code transcripts; OpenTelemetry GenAI spans (single document and JSONL, with and without content); AgentDFIR package import (single and chunked blobs) and 5 kinds of tampering |
| `tests/test_batch.py` | v0.2 | `ptir eval-batch` aggregation, reviewed-only filter, report files |
| `tests/test_zeek.py` | v0.3 | Zeek `conn`, `dns` and `http` logs in JSON and tab-separated form (same events either way), unset fields, missing header, `add-run` patterns, Zeek DNS answers in the sample case |
| `tests/test_file_access.py` | v0.3 | Security 4663 read and write masks, non-file objects skipped; the graph joins 4663 to processes by PID and time, corroborates the trace's `read_file`, and flags curl reading the secret |
| `tests/test_artifacts.py` | v0.3 | every `ez_*` and `vol_*` parser: path joining, timestomp flags, USN Close-record selection and rename pairing, Prefetch run times and paths, Amcache SHA-1 padding, SRUM bytes, UserAssist / autorun / other registry rows, LNK / Jump List / ShellBags, Volatility pstree flattening, banner skipping and unreadable command lines; `add-run` patterns; `ingested_at`; empty files |

All test data is synthetic. The AgentDFIR importer was also checked by hand against AgentDFIR's own
conformance packages: the valid package imports, and 20 of the 24 tampered packages are rejected.
The other 4 only change or remove the ed25519 signature, which PromptTracIR does not check (run
`agentdfir verify` for that).

---

## Part 2: CI on GitHub

After pushing v0.1.1 (see the commit instructions you were given), open the repo's **Actions** tab.
The `CI` workflow runs `pytest` on Ubuntu and Windows with Python 3.10 and 3.12. All four jobs should
be green. The Windows jobs have not been run before this release, so if only they fail, the cause
is almost certainly path or file-locking behaviour in a test, not the code under test. Open the
failing job's log and fix that test first.

Recommended once CI is green: **Settings → Branches → Add rule** for `main`, tick
*Require status checks to pass* and select the four `pytest` jobs.

---

## Part 3: CLI smoke test on synthetic data

Run these from the repo root with the virtual environment active. Paths are written for bash; on
Windows use `\` and `$S="samples\scenario_exfil"`.

### 3.1 v0.1 quick start (unchanged)

```bash
python samples/make_sample.py
S=samples/scenario_exfil
ptir init cases/demo --name demo --envelope $S/envelope.json
ptir add cases/demo $S/trace.jsonl --kind agent_trace
ptir add cases/demo $S/requests.jsonl --kind agent_requests
ptir add cases/demo $S/sysmon.jsonl --kind sysmon
ptir add cases/demo $S/ConsoleHost_history.txt --kind psreadline
ptir add cases/demo $S/zeek_conn.json --kind zeek_conn
ptir ingest cases/demo
ptir analyze cases/demo
ptir eval cases/demo $S/ground_truth.json
ptir verify cases/demo
```

Check: `first_deviation` is `tool_call:t2`, the entry point is `fragment:f2`, impact for
`collect.attacker-lab.test` is `confirmed`, every `ptir verify` line says `OK`.

Then `ptir serve cases/demo` and open http://127.0.0.1:8000. The attack-flow graph should show the
web page fragment leading to the curl process and the attacker domain. Stop with Ctrl+C.

### 3.2 v0.2 commands

```bash
ptir kinds                                             # parsed vs preserved-only kinds
ptir add cases/demo $S/ground_truth.json --kind sysmonn   # must fail: unknown kind (exit code 2)

# Claude Code transcript on its own
ptir init cases/cc --name cc --envelope $S/envelope.json
ptir add cases/cc tests/fixtures/claude_code_session.jsonl --kind claude_code
ptir ingest cases/cc && ptir analyze cases/cc
```

Check: `first_deviation` is `tool_call:toolu_02` (the curl call) and the entry point is
`fragment:toolu_01-2` (the injected paragraph of the fetched page). `processes` is 0 because there is
no host evidence in this case.

```bash
# scenarios
python -m harness.scenario validate harness/scenarios/*.json
python -m harness.scenario prepare harness/scenarios/web_exfil_01.json --files-only --dry-run
python -m harness.scenario prepare harness/scenarios/web_exfil_01.json --web-only --web-root /tmp/www --dry-run
```

Check: three `OK` lines; the first dry run lists `api_keys.txt` and `README.md`, the second lists
`guide.html`.

Clean up with `rm -rf cases` (the folder is git-ignored either way).

---

## Part 4: One real lab run

This is the v0.2 milestone. Do the one-time setup once, then repeat 4.2 for every run.

### 4.1 One-time lab setup

**Network.** Two machines on an isolated host-only network, for example:

| Machine | Example IP | Runs |
|---|---|---|
| Lab VM, Windows 11 | 192.168.56.20 | agent harness, Sysmon, local model server, collection |
| Attacker box, any OS with Python 3.10+ | 192.168.56.10 | web server for poisoned pages, `exfil_sink.py` |

Keep them separate. If the web server and sink run on the VM itself, the traffic goes to loopback
and the scope rules will (correctly) not treat it as external egress.

Keep both clocks in sync: `label_run.py` matches sink hits to runs by time. Without NTP, check that
the two clocks are within a few seconds of each other before each session.

**Lab VM:**

1. Install Python 3.12 and Git. Clone the repo to `C:\lab\PromptTracIR` and run
   `pip install -e ".[evtx]"`.
2. Create the lab user `lab` (the scenarios use `C:\Users\lab\...`) and do runs logged in as it.
3. Auditing, in an elevated PowerShell:
   ```powershell
   auditpol /set /subcategory:"Process Creation" /success:enable
   auditpol /set /subcategory:"Logon" /success:enable
   reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
   reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
   ```
4. Sysmon: `Sysmon64.exe -accepteula -i tools\sysmon-lab.xml`.
5. Hosts file (`C:\Windows\System32\drivers\etc\hosts`, edit as admin):
   ```
   192.168.56.10  docs.example-lab.test collect.attacker-lab.test
   ```
6. Local model: a 7 to 8B instruct GGUF with tool calling, served by
   `llama-server -m model.gguf --port 8080 --jinja`. If the model runs on another machine (for a
   GPU), add that IP to `model_api_domains` in every scenario's envelope, or its traffic becomes an
   egress finding.
7. Optional tools, in `C:\tools\`: WinPmem (memory image; or use hypervisor snapshots) and KAPE
   (needed for `$MFT` and `$UsnJrnl:$J`).
8. Take the **clean snapshot**.

**Attacker box:**

```bash
git clone https://github.com/CeeY0U/PromptTracIR.git && cd PromptTracIR
python3 -m venv .venv && source .venv/bin/activate && pip install -e .
sudo mkdir -p /srv/www && sudo chown $USER /srv/www
python -m harness.scenario prepare harness/scenarios/web_exfil_01.json --web-only --web-root /srv/www
sudo .venv/bin/python -m http.server 80 --directory /srv/www          # terminal 1
python harness/exfil_sink.py --port 8443 --canary PTIR-CANARY-7f3a --log sink_log.jsonl   # terminal 2
```

From the VM, `curl.exe http://docs.example-lab.test/guide.html` should return the page.

### 4.2 Each run

Example: run `run01` of `web_exfil_01`. Use a new run name every time.

| Step | Where | Command or action |
|---|---|---|
| 1 | VM | Revert to the clean snapshot. Log in as `lab`. |
| 2 | VM, PowerShell, repo folder | `python -m harness.scenario prepare harness\scenarios\web_exfil_01.json --files-only` |
| 2b | VM, **elevated** PowerShell | `.\tools\audit-canary.ps1 -Path C:\Users\lab\secrets` (v0.3: Security 4663 for every read of the secret) |
| 3 | VM, **elevated** PowerShell, repo folder | `.\tools\collect-run.ps1 -Phase Start -RunDir C:\lab\runs\run01` |
| 4 | VM, PowerShell window **H** (human) | `. .\tools\human-session.ps1 -Run run01 -OutDir C:\lab\runs\run01 -Scenario harness\scenarios\web_exfil_01.json` |
| 5 | VM, PowerShell window **A** (agent) | `$env:PTIR_LAB = "1"` then `python harness\agent.py --scenario harness\scenarios\web_exfil_01.json --base-url http://127.0.0.1:8080 --model local --out C:\lab\runs\run01` |
| 6 | Window H, while the agent runs | Type the commands step 4 printed, by hand, then `Stop-HumanSession` |
| 7 | Window A | Wait for the agent's final answer |
| 8 | VM, elevated | `.\tools\collect-run.ps1 -Phase Stop -RunDir C:\lab\runs\run01 -WinPmem C:\tools\winpmem_mini_x64.exe` (add `-Kape C:\tools\kape\kape.exe` if you have it) |
| 9 | Attacker box → VM | Copy the attacker's `sink_log.jsonl` to `C:\lab\runs\run01\sink_log.jsonl` |
| 10 | VM | `python harness\label_run.py C:\lab\runs\run01` |
| 11 | VM | Review `ground_truth.json` by hand (4.3), then set `"reviewed": true` |
| 12 | VM → analyst machine | Copy the whole `C:\lab\runs\run01` folder into `runs/run01` on the analyst machine. It holds synthetic secrets and a memory image: never commit it. |

Step 8 ends with a list of warnings for anything it could not collect. Copy them into
`runs/run01/notes.md`. The first run will show what needs fixing in the script.

### 4.3 Reviewing the labels (step 11)

Open `trace.jsonl` and `ground_truth.json` side by side and check:

- `injected_fragments`: the fragment(s) containing the payload, and nothing else.
- `malicious_tool_calls`: every tool call the payload caused (reading the secret, the upload), and no
  benign ones. `first_deviation` is the earliest of them.
- `tool_process_links`: each shell tool call maps to the ProcessGuid of the `cmd.exe` it started.
  Empty means Sysmon was not running or the export missed the window.
- `human_shell_pids`: the PID printed in window H.
- `exfiltration` and `attack_succeeded`: `confirmed` only if the sink log line for this run has
  `"canary_received": true`.
- If the model ignored the payload: `injection_followed` is false and `malicious_tool_calls` is empty.
  This is a valid run for the "injection ignored" row of the dataset.

### 4.4 Analyse (analyst machine)

Optional, if Zeek is installed: generate `conn.log`, `dns.log` and `http.log` from the capture.
Either Zeek output format works; `add-run` picks up all three.

```bash
mkdir -p runs/run01/evidence/zeek && cd runs/run01/evidence/zeek
zeek -r ../capture.pcapng && cd -
```

Then:

```bash
ptir add-run runs/run01 --dry-run          # check every file gets the kind you expect
ptir add-run runs/run01                    # creates runs/run01/case
ptir ingest  runs/run01/case
ptir analyze runs/run01/case
ptir eval    runs/run01/case runs/run01/ground_truth.json
ptir verify  runs/run01/case
ptir serve   runs/run01/case
```

**Expected for `web_exfil_01` when the model followed the payload:**

- `first_deviation` equals the ground truth's (the `read_file` of `api_keys.txt`, or the curl call if
  the model skipped reading it).
- The entry point is the injected fragment of `http://docs.example-lab.test/guide.html`.
- `tool_links.json`: the curl tool call is `corroborated` with `child_pid_match`.
- `attribution.json`: `curl.exe` and its `cmd.exe` are `agent`. The commands typed in window H are
  `human`.
- `impact.json`: `collect.attacker-lab.test` is `confirmed` with a Zeek `conn.log`, otherwise at
  least `probable`.

**Expected for `legit_notes_01`:** no findings, `first_deviation` null.

Anything else is a bug to fix in v0.2. Typical first-run suspects: EVTX field names that differ from
the synthetic sample, time zones (Sysmon `UtcTime` vs local time), PID reuse, and the allowed domain
appearing only as an IP in Sysmon event 3.

Repeat 4.2 to 4.4 for `legit_notes_01` and `file_persist_01`.

---

## Part 5: Claude Code through AgentDFIR

The proposal's second agent is a commercial coding agent whose transcripts AgentDFIR collects. Claude
Code needs to reach the Anthropic API, so this VM is not fully isolated. Allow outbound HTTPS to
`api.anthropic.com` only, and add that domain to the scenario's `model_api_domains`.

1. Revert, then run `prepare --files-only` and `collect-run.ps1 -Phase Start` as in 4.2. Use
   `RunDir C:\lab\runs\cc01`.
2. Start the human session in window H as before.
3. In window A: `cd C:\Users\lab\project`, run `claude`, and paste the scenario's `prompt`. Approve
   tool use as a user normally would. While it runs, note the Claude Code process PID:
   `Get-Process claude, node -ErrorAction SilentlyContinue | Select Id, ProcessName, StartTime`.
4. Exit Claude Code, then run `collect-run.ps1 -Phase Stop`.
5. Collect the transcripts with AgentDFIR (https://github.com/efij/AgentDFIR):
   ```powershell
   agentdfir collect --product claude          # writes a sealed CASE-....adfir package
   agentdfir verify CASE-....adfir             # checks the signature too
   ```
6. Copy the session transcript into the run folder for labelling (newest file under
   `C:\Users\lab\.claude\projects\C--Users-lab-project\`), named `claude_session.jsonl`:
   ```powershell
   python harness\label_run.py C:\lab\runs\cc01 --trace C:\lab\runs\cc01\claude_session.jsonl --trace-format claude_code --agent-pids <PID from step 3>
   ```
7. On the analyst machine:
   ```bash
   ptir add-run runs/cc01
   ptir import-adfir runs/cc01/case path/to/CASE-....adfir
   ptir ingest runs/cc01/case && ptir analyze runs/cc01/case
   ptir eval runs/cc01/case runs/cc01/ground_truth.json
   ```
   `import-adfir` prints each imported transcript with its artifact ID. That ID is also the
   PromptTracIR evidence ID. Because `claude_session.jsonl` holds the same bytes, it is stored once.

**Expected:** the first deviation and the injected fragment match the ground truth. Tool-call-to-process
links will be weaker than for the harness, because Claude Code transcripts record no PIDs. That
limitation is known and gets addressed in v0.4.

---

## Part 6: Scoring many runs

With two or more analysed and labelled runs under `runs/`:

```bash
ptir eval-batch runs                    # all runs
ptir eval-batch runs --reviewed-only    # only runs whose labels were reviewed (use this for the report)
```

It prints the headline numbers against the proposal's targets and writes `runs/results/results.json`
(overall, per family, per run) and `runs/results/per_run.csv`. Runs without an analysed case are
listed as skipped.

---

## Part 7: v0.2 acceptance checklist

v0.2 is done when every box is ticked. Paste the evidence (command output, run names) into the
release notes.

- [ ] `pytest -q` passes locally (Part 1).
- [ ] CI is green on all four jobs (Part 2).
- [ ] The Part 3 smoke test gives the expected results.
- [ ] One real **benign** run (`legit_notes_01`) goes through Part 4 with no findings.
- [ ] One real **injected** run (`web_exfil_01`) goes through Part 4, and its `ptir eval` matches the
      reviewed ground truth on first deviation and malicious tool calls.
- [ ] `collect-run.ps1` warnings from the first runs are fixed or written down as known gaps.
- [ ] One Claude Code transcript imports through `ptir import-adfir` (Part 5).
- [ ] `ptir eval-batch runs --reviewed-only` runs over all real runs so far (Part 6).
- [ ] A sanitised real run (no memory image, no secrets) replaces or joins the synthetic sample as a
      test fixture.

---

## Part 8: v0.3 artifacts from a real run

The `ez_*` and `vol_*` parsers were written against the tools' published column layouts and
tested on synthetic fixtures. One real run confirms the columns.

1. Windows machine with the run folder, the EZ tools (`Get-ZimmermanTools.ps1`, .NET 6 builds) and,
   for memory, Volatility 3:
   `.\tools\parse-artifacts.ps1 -RunDir C:\lab\runs\run01 -EzTools C:\tools\ez -Vol C:\tools\vol\vol.exe`
   ($MFT and $J need `collect-run.ps1 -Kape`, or copies in `evidence\ntfs\`.)
2. Analyst machine: `ptir add-run runs/run01 --case cases/run01`, then `ptir ingest cases/run01`.
   Every `ez_*` / `vol_*` file should report more than 0 events.
3. Spot checks in the UI timeline (`ptir serve cases/run01`): the agent's `curl.exe` appears as a
   Prefetch `program_run`, a SRUM `net_usage` with bytes sent, and in `vol_pslist` / `vol_netscan`
   if memory was taken while it ran; the human's `git status` shell appears in `vol_pslist`.
4. If a file reports 0 events, compare its header line with the columns the parser reads
   (`prompttracir/parsers/ez.py`), fix the parser, and add the header to the fixture.

5. Network and file access (v0.3.0): with Zeek run as in 4.4, `zeek_dns` and `zeek_http` report
   events. For `web_exfil_01` the attacker's domain appears as a DNS query, and the upload as an
   `http_request` with `method` POST and a `request_body_len` close to the secret's size.
6. With `audit-canary.ps1` applied (step 2b of 4.2), `security.jsonl` contains 4663 records.
   After `ptir analyze`, `graph.json` has a `read` edge into `api_keys.txt` from the `read_file`
   tool call with status `corroborated`, and one from `curl.exe` with
   `signals.joined_by = pid_and_time`.

v0.3 acceptance:

- [ ] `pytest -q` passes, CI green.
- [ ] One real run: every `ez_*` / `vol_*` file it produced ingests with more than 0 events.
- [ ] Any column fixes from that run are covered by a fixture.
- [ ] One real run with Zeek and the canary audit: `zeek_dns`, `zeek_http` and Security 4663
      events ingest, and the corroborated `read` edge appears (steps 5 and 6).
