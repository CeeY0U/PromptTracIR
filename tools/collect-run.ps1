<#
.SYNOPSIS
  Collect everything for one PromptTracIR lab run, in two phases around the agent run.

.DESCRIPTION
  Run as Administrator in Windows PowerShell 5.1 or PowerShell 7 on the lab VM.

  -Phase Start   before the agent starts:
                   * creates RUN\evidence and records the start time
                   * starts a full-packet capture with the built-in pktmon (skip with -NoCapture)
  -Phase Stop    after the agent and the paired human session have finished:
                   * stops the capture and converts it to pcapng
                   * exports Sysmon / Security / PowerShell logs from boot (at most -LookbackMinutes
                     before the start), so shells opened before Start are in the evidence
                   * copies SRUM, Prefetch, Amcache, registry hives with their transaction logs,
                     LNK files and Jump Lists
                   * optional: memory image (-WinPmem), KAPE triage incl. $MFT and $J (-Kape)
                   * writes evidence\collection.json (file -> evidence kind for `ptir add-run`)
                     and evidence\sha256sums.txt

  Everything is collected on every run, including artifacts PromptTracIR cannot parse yet:
  `ptir ingest` picks them up once a parser exists, so today's runs stay useful.

  Locked files (SRUDB.dat, Amcache.hve, NTUSER.DAT, UsrClass.dat) are copied with
  `esentutl /y /vss`, which reads them from a volume shadow copy. A hive in use is "dirty":
  its latest changes are still in HIVE.LOG1 / HIVE.LOG2, so those are copied next to it
  (RECmd, SBECmd and AmcacheParser replay them; without them the run's own activity is lost).

.EXAMPLE
  .\tools\collect-run.ps1 -Phase Start -RunDir C:\lab\runs\run01
  # ... run the agent and the paired human session ...
  .\tools\collect-run.ps1 -Phase Stop -RunDir C:\lab\runs\run01 -WinPmem C:\tools\winpmem_mini_x64.exe

.NOTES
  pktmon needs Windows 10 2004 or later. Without -Kape, $MFT and $UsnJrnl:$J are not collected.
  A hypervisor memory snapshot is an alternative to -WinPmem; copy it into RUN\evidence\memory\.
#>
param(
  [Parameter(Mandatory = $true)][ValidateSet("Start", "Stop")][string]$Phase,
  [Parameter(Mandatory = $true)][string]$RunDir,
  [string]$LabUser = $env:USERNAME,
  [string]$WinPmem,
  [string]$Kape,
  [switch]$NoCapture,
  [switch]$NoMemory,
  [int]$LookbackMinutes = 360
)
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated (Administrator) PowerShell."
}

$Ev = Join-Path $RunDir "evidence"
$StateFile = Join-Path $Ev "collect_state.json"
$Etl = Join-Path $Ev "capture.etl"
$script:Warnings = @()

function Warn([string]$msg) {
  $script:Warnings += $msg
  Write-Warning $msg
}

function Copy-Locked([string]$Source, [string]$DestDir) {
  # esentutl /y /vss copies a file that is open by the OS through a shadow copy
  if (-not (Test-Path -LiteralPath $Source)) { Warn "not found: $Source"; return }
  New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
  $dest = Join-Path $DestDir (Split-Path $Source -Leaf)
  & esentutl.exe /y $Source /vss /d $dest | Out-Null
  if ($LASTEXITCODE -ne 0) { Warn "esentutl could not copy $Source (exit $LASTEXITCODE)" }
}

function Copy-Hive([string]$Source, [string]$DestDir) {
  # the hive first, then its transaction logs, so the logs are at least as new as the hive
  Copy-Locked $Source $DestDir
  foreach ($ext in @(".LOG1", ".LOG2")) {
    if (Test-Path -LiteralPath ($Source + $ext)) { Copy-Locked ($Source + $ext) $DestDir }
  }
}

function Copy-Plain([string]$Pattern, [string]$DestDir) {
  $items = @(Get-ChildItem -Path $Pattern -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })
  if ($items.Count -eq 0) { Warn "nothing matched: $Pattern"; return }
  New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
  foreach ($i in $items) {
    try { Copy-Item -LiteralPath $i.FullName -Destination $DestDir -Force }
    catch { Warn "could not copy $($i.FullName): $($_.Exception.Message)" }
  }
}

# ---------------------------------------------------------------- Start
if ($Phase -eq "Start") {
  New-Item -ItemType Directory -Force -Path $Ev | Out-Null
  $sysmon = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
  if (-not $sysmon) { Warn "Sysmon is not running: process attribution will fail for this run." }
  $state = [ordered]@{
    start_utc = (Get-Date).ToUniversalTime().ToString("o")
    host      = $env:COMPUTERNAME
    lab_user  = $LabUser
    capture   = (-not $NoCapture)
  }
  if (-not $NoCapture) {
    # clear any capture left running. pktmon writes "not running" to stderr when there is
    # none; under "Stop" Windows PowerShell 5.1 turns that into a terminating error.
    $eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & pktmon.exe stop *> $null
    $ErrorActionPreference = $eap
    & pktmon.exe start --capture --pkt-size 0 --file-name $Etl | Out-Null
    if ($LASTEXITCODE -ne 0) { Warn "pktmon failed to start (exit $LASTEXITCODE)"; $state.capture = $false }
  }
  $state | ConvertTo-Json | Set-Content -Encoding UTF8 -Path $StateFile
  Write-Host "Collection started at $($state.start_utc). Start the agent and the human session now."
  return
}

# ---------------------------------------------------------------- Stop
if (-not (Test-Path $StateFile)) { throw "No $StateFile. Run -Phase Start before the agent run." }
$state = Get-Content -Raw $StateFile | ConvertFrom-Json
# PowerShell 7 turns ISO strings into DateTime on ConvertFrom-Json; 5.1 leaves them as strings
$startUtc = $state.start_utc
if ($startUtc -isnot [datetime]) {
  $startUtc = [datetime]::Parse($startUtc, [Globalization.CultureInfo]::InvariantCulture,
                                [Globalization.DateTimeStyles]::RoundtripKind)
}
# Events from boot, so processes that started before -Phase Start (the human's shell, the
# agent's parent) have creation records. Capped at -LookbackMinutes before the start for a VM
# that was resumed from a memory snapshot rather than booted.
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$since = $startUtc.ToLocalTime().AddMinutes(-$LookbackMinutes)
if ($boot -gt $since) { $since = $boot }
Write-Host ("Exporting events since {0:u} (boot {1:u})" -f $since.ToUniversalTime(), $boot.ToUniversalTime())
$userHome = Join-Path $env:SystemDrive ("Users\" + $LabUser)

# 1. network capture
if ($state.capture) {
  & pktmon.exe stop | Out-Null
  & pktmon.exe etl2pcap $Etl --out (Join-Path $Ev "capture.pcapng") | Out-Null
  if ($LASTEXITCODE -ne 0) { Warn "pktmon etl2pcap failed; the .etl is kept" }
}

# 2. event logs and PSReadLine (JSONL for parsing, .evtx for custody)
& (Join-Path $PSScriptRoot "export-events.ps1") -Out $Ev -Since $since
$hist = Join-Path $userHome "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $hist) { Copy-Item $hist (Join-Path $Ev "ConsoleHost_history.txt") -Force }
else { Warn "no PSReadLine history for $LabUser" }

# 3. SRUM (needs the SOFTWARE hive to resolve app names)
Copy-Locked "$env:SystemRoot\System32\sru\SRUDB.dat" (Join-Path $Ev "srum")

# 4. Prefetch and Amcache
Copy-Plain "$env:SystemRoot\Prefetch\*.pf" (Join-Path $Ev "prefetch")
Copy-Hive "$env:SystemRoot\appcompat\Programs\Amcache.hve" (Join-Path $Ev "amcache")

# 5. registry: machine hives via reg save, user hives via shadow copy
$reg = Join-Path $Ev "registry"
New-Item -ItemType Directory -Force -Path $reg | Out-Null
foreach ($h in @("SYSTEM", "SOFTWARE", "SAM")) {
  & reg.exe save "HKLM\$h" (Join-Path $reg $h) /y | Out-Null
  if ($LASTEXITCODE -ne 0) { Warn "reg save HKLM\$h failed" }
}
Copy-Item (Join-Path $reg "SOFTWARE") (Join-Path $Ev "srum\SOFTWARE") -ErrorAction SilentlyContinue
Copy-Hive (Join-Path $userHome "NTUSER.DAT") $reg
Copy-Hive (Join-Path $userHome "AppData\Local\Microsoft\Windows\UsrClass.dat") $reg

# 6. LNK files and Jump Lists (human-activity signals for v0.4)
$recent = Join-Path $userHome "AppData\Roaming\Microsoft\Windows\Recent"
Copy-Plain (Join-Path $recent "*.lnk") (Join-Path $Ev "triage\recent")
Copy-Plain (Join-Path $recent "AutomaticDestinations\*") (Join-Path $Ev "triage\jumplists\automatic")
Copy-Plain (Join-Path $recent "CustomDestinations\*") (Join-Path $Ev "triage\jumplists\custom")

# 7. optional KAPE triage ($MFT, $J and everything else KapeTriage covers)
if ($Kape) {
  & $Kape --tsource $env:SystemDrive --tdest (Join-Path $Ev "triage\kape") --target KapeTriage --zip kape | Out-Null
  if ($LASTEXITCODE -ne 0) { Warn "KAPE exited with $LASTEXITCODE" }
} else {
  Warn "no -Kape: `$MFT and `$UsnJrnl:`$J were not collected"
}

# 7b. file inventory: size and SHA-256 of the files in the scenario folders. Event logs say a
# file was read or written but not how big it is; impact assessment needs the size to call an
# upload confirmed, and without -Kape there is no $MFT to take it from.
$invRoots = @("project", "secrets", "Documents", "Downloads", "Desktop", "AppData\Local\ptir-lab",
              "AppData\Local\Temp\ptir-lab") | ForEach-Object { Join-Path $userHome $_ } |
            Where-Object { Test-Path $_ }
$invFiles = @()
foreach ($root in $invRoots) {
  Get-ChildItem -Path $root -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 2000 | ForEach-Object {
    $hash = if ($_.Length -le 50MB) { (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName -ErrorAction SilentlyContinue).Hash } else { $null }
    $invFiles += [ordered]@{ path = $_.FullName; size = $_.Length; sha256 = $hash
                             created_utc = $_.CreationTimeUtc.ToString("o"); modified_utc = $_.LastWriteTimeUtc.ToString("o") }
  }
}
$inventory = [ordered]@{ collected_utc = (Get-Date).ToUniversalTime().ToString("o"); roots = @($invRoots); files = $invFiles }
[IO.File]::WriteAllText((Join-Path $Ev "file_inventory.json"), ($inventory | ConvertTo-Json -Depth 4),
                        (New-Object Text.UTF8Encoding($false)))
Write-Host "file inventory: $($invFiles.Count) files under $($invRoots.Count) folders"

# 8. memory image (last, so collection activity above is visible in it)
if ($WinPmem -and -not $NoMemory) {
  $memDir = Join-Path $Ev "memory"
  New-Item -ItemType Directory -Force -Path $memDir | Out-Null
  # A local model server holding most of the VM's RAM left WinPmem with an empty (jt-04) or
  # partial (cy-04) image in the v0.4 lab runs: stop it before collecting.
  # v0.6: wait up to 60 s for a model server that is shutting down (Ctrl+C) to exit.
  for ($i = 0; $i -lt 12 -and (Get-Process -Name "llama-server" -ErrorAction SilentlyContinue); $i++) {
    if ($i -eq 0) { Write-Host "waiting for llama-server to exit before the memory image ..." }
    Start-Sleep -Seconds 5
  }
  $llama = Get-Process -Name "llama-server" -ErrorAction SilentlyContinue
  if ($llama) { Warn "llama-server is still running (PID $($llama.Id -join ', ')): stop it (Ctrl+C in window M) before -Phase Stop, or the memory image may be empty or partial" }
  $memFile = Join-Path $memDir "memory.raw"
  $ramBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
  # v0.6: the first image after a real-model run came out empty twice (jt-v1, jt-v1b) although
  # llama-server had exited, and a second Stop then worked. Retry once, 30 s later.
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    if (Test-Path $memFile) { Remove-Item -Force $memFile }
    & $WinPmem $memFile | Out-Null
    $pmemExit = $LASTEXITCODE
    $imgBytes = if (Test-Path $memFile) { (Get-Item $memFile).Length } else { 0 }
    if ($imgBytes -ge 0.9 * $ramBytes -or $attempt -eq 2) { break }
    Write-Host ("memory image attempt 1: {0:N2} GB for {1:N1} GB of RAM (WinPmem exit $pmemExit); retrying in 30 s" -f ($imgBytes / 1GB), ($ramBytes / 1GB))
    Start-Sleep -Seconds 30
  }
  if ($attempt -eq 2) { Write-Host ("memory image attempt 2: {0:N2} GB" -f ($imgBytes / 1GB)) }
  if ($imgBytes -eq 0) {
    Warn "memory image is EMPTY (0 bytes, WinPmem exit $pmemExit): memory evidence for this run is missing"
  } elseif ($imgBytes -lt 0.9 * $ramBytes) {
    Warn ("memory image is short: {0:N1} GB for {1:N1} GB of RAM (WinPmem exit $pmemExit)" -f ($imgBytes / 1GB), ($ramBytes / 1GB))
  } elseif ($pmemExit -ne 0) {
    # WinPmem mini exits 1 on most Windows 11 builds while still writing a complete image
    Write-Host ("WinPmem exited with $pmemExit; image {0:N2} GB looks complete" -f ($imgBytes / 1GB))
  }
} elseif (-not $NoMemory) {
  Warn "no -WinPmem: take a hypervisor memory snapshot and copy it to evidence\memory\"
}

# 9. collection manifest: relative path -> evidence kind for `ptir add-run`
function Get-Kind([string]$rel) {
  $r = $rel.ToLower()
  switch -Wildcard ($r) {
    "sysmon.jsonl"              { return "sysmon" }
    "security.jsonl"            { return "security" }
    "powershell.jsonl"          { return "powershell" }
    "*.evtx"                    { return "evtx_raw" }
    "consolehost_history.txt"   { return "psreadline" }
    "file_inventory.json"       { return "file_inventory" }
    "zeek\conn.log"             { return "zeek_conn" }
    "zeek\dns.log"              { return "zeek_dns" }
    "zeek\http.log"             { return "zeek_http" }
    "*.pcapng"                  { return "pcap" }
    "*.etl"                     { return "pcap" }
    "memory\*"                  { return "memory_image" }
    "srum\*"                    { return "srum" }
    "prefetch\*"                { return "prefetch" }
    "amcache\*"                 { return "amcache" }
    "registry\*"                { return "registry_hive" }
    "triage\*"                  { return "triage_archive" }
  }
  return "other"
}

$skip = @("collection.json", "sha256sums.txt", "collect_state.json")
$prefix = (Resolve-Path $Ev).Path.TrimEnd("\") + "\"
$files = @()
$sums = @()
foreach ($f in (Get-ChildItem -Path $Ev -Recurse -File -Force | Sort-Object FullName)) {
  $rel = $f.FullName.Substring($prefix.Length)
  if ($skip -contains $rel.ToLower()) { continue }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLower()
  $files += [ordered]@{ path = $rel; kind = (Get-Kind $rel); size = $f.Length; sha256 = $hash }
  $sums += "$hash  $($rel.Replace('\', '/'))"
}
$manifest = [ordered]@{
  collector   = "tools/collect-run.ps1"
  host        = $env:COMPUTERNAME
  lab_user    = $LabUser
  start_utc   = $startUtc.ToUniversalTime().ToString("o")
  events_since_utc = $since.ToUniversalTime().ToString("o")
  stop_utc    = (Get-Date).ToUniversalTime().ToString("o")
  warnings    = $script:Warnings
  files       = $files
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $Ev "collection.json"), ($manifest | ConvertTo-Json -Depth 5), $utf8)
[IO.File]::WriteAllLines((Join-Path $Ev "sha256sums.txt"), [string[]]$sums, $utf8)

Write-Host ""
Write-Host ("Collected {0} files into {1}" -f $files.Count, $Ev)
if ($script:Warnings.Count) {
  Write-Host "Warnings:" -ForegroundColor Yellow
  $script:Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
