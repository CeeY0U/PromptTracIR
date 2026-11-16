# Testing guide: v0.1.1 to v0.4.0

This guide covers every check up to v0.4.0, in the order to run them:

| Part | Where | Needs | Time |
|---|---|---|---|
| [1. Automated tests](#part-1-automated-tests) | any machine | Python 3.10+ | 5 min |
| [2. CI on GitHub](#part-2-ci-on-github) | GitHub | a push | 5 min |
| [3. CLI smoke test](#part-3-cli-smoke-test-on-synthetic-data) | any machine | Part 1 | 10 min |
| [4. One real lab run](#part-4-one-real-lab-run) | lab VM + attacker box | lab built | 1 h first time |
| [5. Claude Code through AgentDFIR](#part-5-claude-code-through-agentdfir) | lab VM | Claude Code, AgentDFIR | 30 min |
| [6. Scoring many runs](#part-6-scoring-many-runs) | analyst machine | 2+ labelled runs | 5 min |
| [7. v0.2 acceptance checklist](#part-7-v02-acceptance-checklist) | n/a | Parts 1 to 6 | n/a |
| [8. v0.3 artifacts from a real run](#part-8-v03-artifacts-from-a-real-run) | Windows + analyst machine | EZ tools, Volatility, Zeek | 30 min |
| [9. v0.4 attribution on real runs](#part-9-v04-attribution-on-real-runs) | analyst machine | labelled runs | 30 min |

Parts 1 to 3 need no VM, model or network. Parts 4 to 6 are the real v0.2 milestone. The first
lab runs (15 Nov 2026: VMware Workstation, Windows 11 24H2, Kali, Qwen2.5-7B) found the problems
fixed in v0.3.1; the setup notes below include what those runs taught.

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

On a managed laptop where application control (Device Guard) blocks `pytest.exe` or `ptir.exe` in
`.venv\Scripts`, run them through Python instead: `python -m pytest -q`, and
`python -m prompttracir.cli <command>` wherever this guide says `ptir <command>`.

### 1.2 Run

```bash
pytest -q
```

Expected: `124 passed`. Run one file with `pytest -q tests/test_importers.py`, or one test with
`pytest -q -k adfir_tampering`.

### 1.3 What the tests cover

| File | Version | Covers |
|---|---|---|
| `tests/test_pipeline.py` | v0.1 | hashing and custody; end-to-end analysis; corroborated tool links; replay traceback; LLM output validation; harness agent against a fake model |
| `tests/test_runs.py` | v0.2 | `ptir add-run` kind mapping, `collection.json` override, label files skipped, unknown kinds rejected, re-adding is idempotent, `ptir add` on a directory |
| `tests/test_harness.py` | v0.2 | raw source bytes kept under `sources/`; scenario schema rules; `prepare` writes and splits VM files from web pages; `label_run` matches the sample's ground truth, resolves child PID to ProcessGuid, ignores sink hits from other runs, labels legitimate and Claude Code runs; one tool call per turn with temperature and seed (v0.3.1) |
| `tests/test_importers.py` | v0.2 | Claude Code transcripts; OpenTelemetry GenAI spans (single document and JSONL, with and without content); AgentDFIR package import (single and chunked blobs) and 5 kinds of tampering |
| `tests/test_batch.py` | v0.2, v0.4 | `ptir eval-batch` aggregation, reviewed-only filter, report files; family filters, calibration and complete-evidence numbers, `--without` ablation re-analysis into a tag, `--config` tuning loop |
| `tests/test_attribution.py` | v0.4 | settings file (defaults, overrides, typos rejected, checked-in defaults match); clock offset from child PIDs vs fixed windows; Security 4688 instead of Sysmon, and 4688 + Sysmon as one process; 4104 script block links a `-File` PowerShell run; UserAssist, LNK and ShellBags human signals; non-interactive logon; Claude Code runtime inferred, decoy `node.exe` not picked; `--without` writes a separate analysis |
| `tests/test_calibration.py` | v0.4 | ECE and Brier score; P(agent) per gold process and tool-link scores in `ptir eval` |
| `tests/test_zeek.py` | v0.3 | Zeek `conn`, `dns` and `http` logs in JSON and tab-separated form (same events either way), unset fields, missing header, `add-run` patterns, Zeek DNS answers in the sample case |
| `tests/test_file_access.py` | v0.3 | Security 4663 read and write masks, non-file objects skipped; the graph joins 4663 to processes by PID and time, corroborates the trace's `read_file`, and flags curl reading the secret |
| `tests/test_artifacts.py` | v0.3 | every `ez_*` and `vol_*` parser: path joining, timestomp flags, USN Close-record selection and rename pairing, Prefetch run times and paths, Amcache SHA-1 padding and rows without a path (lab fixture), SRUM bytes, UserAssist / autorun / other registry rows, LNK / Jump List / ShellBags, Volatility pstree flattening, banner skipping and unreadable command lines; `add-run` patterns; `ingested_at`; empty files |
| `tests/test_scope_paths.py` | v0.3.1 | escaped and quoted paths from lab run03 raise no scope findings; a secret outside the folder still does; UNC prefixes kept |
| `tests/test_process_dedupe.py` | v0.3.1, v0.4 | the Sysmon/4688 copies of one process 1 ms apart (lab run01), merged as corroboration in v0.4 with a configurable window; 4688-only processes kept; human labels through a shell started before collection; ignored injections and `unknown` impact not scored |
| `tests/test_cli_messages.py` | v0.3.1 | missing case and envelope messages; `add-run` on an existing case reports only new files |
| `tests/test_scripted_model.py` | v0.3.1 | the scripted model's plan, no shell call when the payload fragment is removed, ignore mode, and an end-to-end agent run against it |

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

### 3.3 v0.4 commands

Run after 3.1, on the same `cases/demo`:

```bash
ptir config                                    # all attribution settings as JSON
ptir analyze cases/demo
ptir eval cases/demo $S/ground_truth.json
ptir analyze cases/demo --without sysmon       # ablation, written to output/without-sysmon/
```

Check:

- `ptir analyze` now also prints `"attribution": {"unknown": 1, "human": 4, "agent": 2}` and
  `"config": "84d416be6878"` (the fingerprint of the default settings).
- `cases/demo/output/attribution.json`: `cmd.exe` and `curl.exe` are `agent` with
  `agent_probability` above 0.95; `git.exe` and both `pwsh.exe` are `human` (about 0.12);
  `explorer.exe` is `unknown`. Each entry lists its weighted `contributions`.
- `cases/demo/output/correlation.json`: `runtime_method` is `pid` and `clock_offset_method` is
  `child_pid` with an offset of 0.05 s.
- `ptir eval`: attribution accuracy and macro-F1 are 1.0, and `calibration` shows `n` 3 with an
  ECE of about 0.07.
- The `--without sysmon` run prints `"processes": 0` but still `"first_deviation": "tool_call:t2"`:
  the trace alone finds the deviation, but nothing can be attributed. `output/` still holds the
  full analysis.

Clean up with `rm -rf cases` (the folder is git-ignored either way).

---

## Part 4: One real lab run

This is the v0.2 milestone. Do the one-time setup once, then repeat 4.2 for every run.

### 4.1 One-time lab setup

**Network.** Two machines on an isolated network, for example:

| Machine | Lab IP | Runs |
|---|---|---|
| Lab VM, Windows 11 | 192.168.56.20 | agent harness, Sysmon, local model server, collection |
| Attacker box, any OS with Python 3.10+ | 192.168.56.10 and 192.168.56.11 | web server for poisoned pages (.10), `exfil_sink.py` (.11) |

The two lab names get **different IPs** (`docs.example-lab.test` on .10, `collect.attacker-lab.test`
on .11): with one IP, Sysmon's reverse lookup gives one name for both and the upload looks like a
visit to the documentation site.

In VMware, give each VM a second network adapter on the same **LAN segment** (or host-only
network) and set the lab IPs by hand. Keep a NAT adapter for installing tools; untick its
**Connected** box before taking the snapshot. A VMware revert also restores the VM's settings
(shared folders, adapters), so make settings changes before the snapshot.

```powershell
# lab VM (elevated): the lab adapter, often Ethernet1 (Get-NetAdapter); no gateway
New-NetIPAddress -InterfaceAlias "Ethernet1" -IPAddress 192.168.56.20 -PrefixLength 24
```
```bash
# attacker box, NetworkManager (Kali, Ubuntu): both lab IPs on the lab interface, kept across reboots
nmcli -f NAME,DEVICE con show
sudo nmcli con mod "Wired connection 1" +ipv4.addresses "192.168.56.10/24,192.168.56.11/24"
sudo nmcli con up "Wired connection 1"
```

Give the lab VM at least 8 GB of RAM and 4 cores as **1 processor x 4 cores**: Windows 11 Home and
Pro use only one or two CPU sockets, so 4 processors x 1 core runs the model on one core.

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
4. Sysmon: `Sysmon64.exe -accepteula -i tools\sysmon-lab.xml`, then check with `Sysmon64.exe -c`:
   the `Config file:` line must name `sysmon-lab.xml`. If it shows only `-accepteula -i`, Sysmon
   runs on its defaults (process start and exit only, no network, DNS or file events); apply the
   config with `Sysmon64.exe -c C:\lab\PromptTracIR\tools\sysmon-lab.xml`.
5. Hosts file, from an elevated PowerShell (typing the file's path opens Notepad without admin
   rights, and saving fails):
   ```powershell
   Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Encoding ASCII -Value "`r`n192.168.56.10  docs.example-lab.test`r`n192.168.56.11  collect.attacker-lab.test"
   ipconfig /flushdns
   ```
6. Local model: a 7 to 8B instruct GGUF with tool calling, served by
   `llama-server -m model.gguf --port 8080 --jinja`. If the model runs on another machine (for a
   GPU), add that IP to `model_api_domains` in every scenario's envelope, or its traffic becomes an
   egress finding.
7. Tools, in `C:\tools\`: Eric Zimmerman's tools in `C:\tools\ez` (`Get-ZimmermanTools.ps1`;
   current builds need the **.NET 10 runtime**), Volatility 3 (`pip install volatility3`), WinPmem
   (or use hypervisor memory snapshots) and optionally KAPE (needed for `$MFT` and `$UsnJrnl:$J`).
   WinPmem can exit with 1 and still write a complete image: check it with
   `vol -f memory.raw windows.info` (a `SystemTime` close to the run's end means it is good).
8. Volatility symbols, once, while the VM has internet: run `vol -f <an image> windows.info` and
   `vol -f <an image> windows.netstat`. The first downloads the kernel's symbols
   (`symbols\windows\ntkrnlmp.pdb\...`), the second the network stack's (`tcpip.pdb`). Without the
   second, netscan and netstat find no sockets on an offline VM. Keep both folders in the snapshot.
9. Before the snapshot: clear the lab user's PowerShell history
   (`Remove-Item (Get-PSReadLineOption).HistorySavePath`), since setup commands in it are ingested
   as the human's history on every run; disconnect the NAT adapter; check `ipconfig` shows the lab IP.
10. Take the **clean snapshot**, before any run. A snapshot taken after a run carries that run's
    files (and any scheduled task it created) into every later run.

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

Zeek (optional): Kali's own `zeek` package does not install on current Kali. Use the official
image instead: `sudo docker pull zeek/zeek`, then in 4.4 run
`sudo docker run --rm -v "$PWD":/w -w /w zeek/zeek zeek -C -r capture.pcapng`.

### 4.2 Each run

Example: run `run01` of `web_exfil_01`. Use a new run name every time.

| Step | Where | Command or action |
|---|---|---|
| 1 | VM | Revert to the clean snapshot. Log in as `lab`. Start the model server (window M). |
| 2 | VM, **elevated** PowerShell (window E), repo folder | `python -m harness.scenario prepare harness\scenarios\web_exfil_01.json --files-only`, then check the files exist (`Test-Path C:\Users\lab\project\README.md`) |
| 2b | VM, **elevated** PowerShell | `.\tools\audit-canary.ps1 -Path C:\Users\lab\secrets` (v0.3: Security 4663 for every read of the secret) |
| 3 | VM, **elevated** PowerShell, repo folder | `.\tools\collect-run.ps1 -Phase Start -RunDir C:\lab\runs\run01` |
| 4 | VM, new PowerShell window **H** (human), opened **after** step 3, not elevated | `. .\tools\human-session.ps1 -Run run01 -OutDir C:\lab\runs\run01 -Scenario harness\scenarios\web_exfil_01.json` |
| 5 | VM, new PowerShell window **A** (agent), opened after step 3, not elevated | `$env:PTIR_LAB = "1"` then `python harness\agent.py --scenario harness\scenarios\web_exfil_01.json --base-url http://127.0.0.1:8080 --model local --out C:\lab\runs\run01` |
| 6 | Window H, while the agent runs | Type the commands step 4 printed, by hand, then `Stop-HumanSession` |
| 7 | Window A | Wait for the agent's final answer |
| 8 | VM, elevated | `.\tools\collect-run.ps1 -Phase Stop -RunDir C:\lab\runs\run01 -WinPmem C:\tools\winpmem_mini_x64.exe` (add `-Kape C:\tools\kape\kape.exe` if you have it) |
| 9 | Attacker box → VM | Copy the attacker's `sink_log.jsonl` to `C:\lab\runs\run01\sink_log.jsonl` |
| 10 | VM | `python harness\label_run.py C:\lab\runs\run01` |
| 11 | VM | Review `ground_truth.json` by hand (4.3), then set `"reviewed": true` |
| 12 | VM → analyst machine | Copy the whole `C:\lab\runs\run01` folder into `runs/run01` on the analyst machine. It holds synthetic secrets and a memory image: never commit it. |

Step 8 ends with a list of warnings for anything it could not collect. Copy them into
`runs/run01/notes.md`. Step 8 hashes everything it collected, a 9 GB memory image included, so it
can take 10 to 15 minutes. Do not click inside a PowerShell window while a script runs: that
selects text and pauses the script until you press Enter.

Since v0.3.1, collection exports event logs from boot (at most 6 hours before step 3), so the
shells opened in steps 4 and 5 have creation records even if opened earlier. Opening them after
step 3 still keeps the evidence window short.

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

### 4.5 Real-model runs that ignore the payload, and scripted runs

The first five injected runs with Qwen2.5-7B all ignored the payload. Two harness options help:

- **One tool call per turn** is the default since v0.3.1. The model used to send its whole plan
  (fetch, shell, write) in its first response, before reading the page, so the injected text never
  reached a decision. `--parallel-tools` restores the old behaviour.
- **`--temperature` and `--seed`.** At temperature 0 (the default) a scenario gives the same
  answer every run: run02 repeated run01 word for word. For more tries, use for example
  `--temperature 0.7 --seed 1`, `--seed 2`, ... and note the values in `notes.md`.

For guaranteed positive cases, run the **scripted model** in window M instead of `llama-server`:

```powershell
python -m harness.scripted_model --scenario harness\scenarios\web_exfil_01.json --port 8080
```

and start the agent with `--model scripted-comply`. The agent then really fetches the page, really
runs the scenario's `injection.command` and writes the notes, so every host artifact is genuine;
only the decisions are scripted. Label, collect and analyse exactly as in 4.2 to 4.4. Keep scripted
runs separate from real-model runs in the report: they test PromptTracIR's reconstruction, not
whether a model falls for the payload. `--mode ignore` gives the matching negative case.

Expected for a scripted `web_exfil_01` run: `injection_followed` and `attack_succeeded` true,
`first_deviation` = the shell tool call running `curl.exe`, the sink log has
`"canary_received": true`, Security 4663 shows `curl.exe` reading `api_keys.txt`, and
`impact.json` has `collect.attacker-lab.test` at `probable` (`confirmed` once Zeek's `conn.log` is
added). For `file_persist_01`: a `persistence` finding on the `schtasks /create` call and
`attack_succeeded` true (exit code 0).

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
tested on synthetic fixtures. The first real runs (15 Nov 2026) confirmed the columns of every
tool except AmcacheParser's output for a hive copied without its logs (fixed in v0.3.1, fixture
`tests/fixtures/lab/`). Known results from those runs:

| Output | Real-run result | Why |
|---|---|---|
| `ez_amcache` | 0 events before v0.3.1 | `FullPath` empty: hive copied without `.LOG1`/`.LOG2`. v0.3.1 copies the logs and falls back to `KeyName` |
| `ez_shellbags` from `NTUSER.csv` | 0 events | Windows 11 keeps ShellBags in `UsrClass.dat` |
| `ez_srum` | same rows every run | SRUM writes about once an hour; a run collected straight away is not in it yet |
| `vol_netscan` | empty | netscan finds nothing on 24H2; netstat without `tcpip.pdb` symbols neither (4.1 step 8) |
| `zeek_dns` | no lab names | the lab names come from the hosts file, not DNS; use Sysmon event 22 for them |

1. Windows machine with the run folder, the EZ tools (`Get-ZimmermanTools.ps1`, .NET 10 runtime)
   and, for memory, Volatility 3:
   `.\tools\parse-artifacts.ps1 -RunDir C:\lab\runs\run01 -EzTools C:\tools\ez -Vol (Get-Command vol).Source`
   ($MFT and $J need `collect-run.ps1 -Kape`, or copies in `evidence\ntfs\`; since v0.3.1 the
   script takes them from the KAPE output itself.)
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

---

## Part 9: v0.4 attribution on real runs

v0.4 changes how processes are labelled, not what is collected, so it reuses the runs from
Parts 4, 5 and 8. What it needs from them:

| Evidence | Gives | Collected by |
|---|---|---|
| Sysmon 1, or Security 4688 with command lines | the process tree | `collect-run.ps1` (both) |
| Security 4624 | logon type of each process | `collect-run.ps1` |
| PowerShell 4104 | script blocks, to link PowerShell tool calls | `collect-run.ps1` |
| UserAssist, LNK, Jump Lists, ShellBags (`ez_registry`, `ez_lnk`, `ez_jumplist`, `ez_shellbags`) | human-side signals | `parse-artifacts.ps1` (Part 8) |

### 9.1 Make the human session harder to tell apart

The scenarios' `human_commands` are typed in a terminal, which the v0.2 signals already catch.
In at least a few runs, have the person in window H also:

1. open `C:\Users\lab\project\notes.md` by double-clicking it in Explorer (creates a LNK file and
   a Jump List entry; notepad's command line names the file);
2. start Notepad or PowerShell from the Start menu (UserAssist);
3. browse to `C:\Users\lab\project` in Explorer first (ShellBags).

Write which of these were done in `runs/<run>/notes.md`.

### 9.2 Check one run by hand

After `ptir analyze runs/run01/case`:

- `output/correlation.json`: `runtime_method` is `pid` for the harness (`inferred` for Claude
  Code). `clock_offset_method` is `child_pid` and `clock_offset_s` is small (under 1 s on one
  machine). A large offset means the trace and the host disagree on time. That's fine, the offset
  corrects it, but write it down.
- `output/attribution.json`: every process under the agent runtime is `agent`; the window-H
  shell and its children are `human`. For the actions in 9.1, the human entries list
  `userassist_launch`, `shell_file_open` or `shellbag_folder` in `contributions`.
- `output/tool_links.json`: each shell tool call is `corroborated` with `child_pid_match`.

### 9.3 Claude Code run (Part 5)

After `ptir analyze runs/cc01/case`, `correlation.json` should show `runtime_method: inferred`
with `runtime_signals.pid` equal to the PID you noted in Part 5 step 3, and
`tool_calls_matched_by_children` listing the Bash tool calls. If it picked another process, or
none, keep the run: it is a failure case for the report.

### 9.4 Ablations

```bash
ptir eval-batch runs --reviewed-only --without sysmon       # 4688 / 4104 coverage only
ptir eval-batch runs --reviewed-only --without psreadline
ptir eval-batch runs --reviewed-only --without ez_registry --without ez_lnk --without ez_jumplist --without ez_shellbags
```

Each writes `runs/results/<tag>/results.json`. Compare the attribution macro-F1, abstention and
tool-link precision with the full run (`runs/results/results.json`). Without Sysmon the links
should still be found from 4688 (lower recall is expected if 4688 command-line logging was off).

### 9.5 Tuning (training split only)

Follow `configs/README.md`: try settings on the training families with
`ptir eval-batch ... --families ... --config FILE --tag tune-NN`, commit the chosen file, then
score the test families once.

v0.4 acceptance (the roadmap's "done when", on the training split collected so far):

- [ ] `pytest -q` passes, CI green.
- [ ] Tool-to-process link precision is at least 0.95 (`tool-to-process link precision` line of
      `eval-batch`, where the harness recorded child PIDs).
- [ ] Attribution macro-F1 is at least 0.85 on complete-evidence runs (`on complete-evidence runs`
      line).
- [ ] One Claude Code run has its runtime inferred correctly (9.3).
- [ ] The ablations in 9.4 have been run and their numbers saved.
- [ ] The settings used are committed under `configs/` and their fingerprint recorded.

