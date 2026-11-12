<#
.SYNOPSIS
  Turn the raw artifacts of one collected lab run into the CSV / JSON that PromptTracIR parses.

.DESCRIPTION
  Run after `collect-run.ps1 -Phase Stop`, on the VM or on an analyst Windows machine with a copy
  of the run folder. It runs Eric Zimmerman's tools and (optionally) Volatility 3 and writes:

    RUN\evidence\ez\            MFTECmd ($MFT, $J), PECmd, AmcacheParser, SrumECmd, RECmd, LECmd, JLECmd
    RUN\evidence\ez\shellbags\  SBECmd
    RUN\evidence\vol\           vol_pstree.json, vol_cmdline.json, vol_netscan.json

  `ptir add-run` then picks these up as the ez_* and vol_* kinds (prompttracir/runs.py). The raw
  files stay where they are and keep their raw kinds, so custody is unchanged. New outputs are
  appended to evidence\sha256sums.txt.

  Tools that are missing, and artifacts that were not collected, are skipped with a warning.

.EXAMPLE
  .\tools\parse-artifacts.ps1 -RunDir C:\lab\runs\run01 -EzTools C:\tools\ez -Vol "C:\tools\vol\vol.exe"

.NOTES
  Not yet run against a real lab VM (same status as collect-run.ps1); see docs/TESTING.md.
  $MFT and $J are only present when collect-run.ps1 ran with -Kape, or were copied by hand into
  RUN\evidence\ntfs\ ($MFT and $J). Get the EZ tools with Get-ZimmermanTools.ps1 (.NET 6 builds).
#>
param(
  [Parameter(Mandatory = $true)][string]$RunDir,
  [Parameter(Mandatory = $true)][string]$EzTools,
  [string]$Vol,
  [string]$Batch
)
$ErrorActionPreference = "Stop"
$Ev = Join-Path $RunDir "evidence"
$Ez = Join-Path $Ev "ez"
$VolOut = Join-Path $Ev "vol"
New-Item -ItemType Directory -Force -Path $Ez, (Join-Path $Ez "shellbags") | Out-Null
$script:Warnings = @()
function Warn([string]$msg) { $script:Warnings += $msg; Write-Warning $msg }

function Find-Tool([string]$name) {
  $hit = Get-ChildItem -Path $EzTools -Recurse -Filter "$name.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $hit) { Warn "$name.exe not found under $EzTools"; return $null }
  return $hit.FullName
}

function Run-Ez([string]$tool, [string]$src, [string[]]$toolArgs, [string]$out = $Ez) {
  if (-not (Test-Path $src)) { Warn "${tool}: $src not collected, skipped"; return }
  $exe = Find-Tool $tool
  if (-not $exe) { return }
  Write-Host "$tool $src"
  & $exe @toolArgs --csv $out | Out-Null
  if ($LASTEXITCODE -ne 0) { Warn "$tool exited with $LASTEXITCODE" }
}

# NTFS ($J needs $MFT to resolve parent paths)
$ntfs = Join-Path $Ev "ntfs"
$mft = Join-Path $ntfs '$MFT'
$usn = Get-ChildItem -Path $ntfs -Filter '*$J' -ErrorAction SilentlyContinue | Select-Object -First 1
Run-Ez "MFTECmd" $mft @("-f", $mft)
if ($usn) {
  $jArgs = @("-f", $usn.FullName)
  if (Test-Path $mft) { $jArgs += @("-m", $mft) }
  Run-Ez "MFTECmd" $usn.FullName $jArgs
} else { Warn "MFTECmd: no `$J under $ntfs, skipped" }

# Execution and network usage
Run-Ez "PECmd" (Join-Path $Ev "prefetch") @("-d", (Join-Path $Ev "prefetch"), "-q")
Run-Ez "AmcacheParser" (Join-Path $Ev "amcache\Amcache.hve") @("-f", (Join-Path $Ev "amcache\Amcache.hve"), "-i")
Run-Ez "SrumECmd" (Join-Path $Ev "srum\SRUDB.dat") @("-f", (Join-Path $Ev "srum\SRUDB.dat"), "-r", (Join-Path $Ev "srum\SOFTWARE"))

# Registry (UserAssist, Run keys, ...) and user activity
if (-not $Batch) {
  $b = Get-ChildItem -Path $EzTools -Recurse -Filter "Kroll_Batch.reb" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($b) { $Batch = $b.FullName }
}
if ($Batch) {
  Run-Ez "RECmd" (Join-Path $Ev "registry") @("-d", (Join-Path $Ev "registry"), "--bn", $Batch)
} else { Warn "RECmd: no batch file (pass -Batch or keep BatchExamples next to RECmd), skipped" }
Run-Ez "LECmd" (Join-Path $Ev "triage\recent") @("-d", (Join-Path $Ev "triage\recent"), "-q")
Run-Ez "JLECmd" (Join-Path $Ev "triage\jumplists") @("-d", (Join-Path $Ev "triage\jumplists"), "-q")
Run-Ez "SBECmd" (Join-Path $Ev "registry") @("-d", (Join-Path $Ev "registry")) (Join-Path $Ez "shellbags")

# Memory
$mem = Get-ChildItem -Path (Join-Path $Ev "memory") -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Vol -and $mem) {
  New-Item -ItemType Directory -Force -Path $VolOut | Out-Null
  foreach ($p in @(@("windows.pstree", "vol_pstree.json"), @("windows.cmdline", "vol_cmdline.json"),
                   @("windows.netscan", "vol_netscan.json"))) {
    Write-Host "volatility $($p[0])"
    $json = & $Vol -q -r json -f $mem.FullName $p[0]
    if ($LASTEXITCODE -ne 0) { Warn "volatility $($p[0]) exited with $LASTEXITCODE"; continue }
    [IO.File]::WriteAllLines((Join-Path $VolOut $p[1]), [string[]]$json, (New-Object Text.UTF8Encoding($false)))
  }
} elseif (-not $mem) { Warn "no memory image under evidence\memory, Volatility skipped" }
else { Warn "no -Vol given, Volatility skipped" }

# Hashes of the new outputs
$sums = Join-Path $Ev "sha256sums.txt"
$prefix = (Resolve-Path $Ev).Path.TrimEnd("\") + "\"
$new = @(Get-ChildItem -Path $Ez, $VolOut -Recurse -File -ErrorAction SilentlyContinue)
$lines = $new | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.FullName.Substring($prefix.Length))" }
if ($lines) { Add-Content -Path $sums -Value $lines -Encoding utf8 }

Write-Host ""
Write-Host "$($new.Count) output files. Next: ptir add-run $RunDir"
if ($script:Warnings.Count) { Write-Host "$($script:Warnings.Count) warning(s):"; $script:Warnings | ForEach-Object { Write-Host "  $_" } }
