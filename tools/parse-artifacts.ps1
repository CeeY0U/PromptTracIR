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
  First run on the lab VM on 15 Nov 2026 (Windows 11 24H2, EZ Tools 2026.10, Volatility 2.28.2).
  $MFT and $J come from a -Kape collection (taken from RUN\evidence\triage\kape\, zipped or not)
  or are copied by hand into RUN\evidence\ntfs\. Get the EZ tools with Get-ZimmermanTools.ps1;
  current builds need the .NET 10 runtime.
  Registry hives in use are "dirty". collect-run.ps1 copies their .LOG1/.LOG2 files so the tools
  can replay them; if RECmd or SBECmd still refuse a hive, it is re-run with --nl (logs ignored,
  the run's latest user activity may be missing) and a warning says so.
  Volatility's network plugins need the tcpip.pdb symbols as well as the kernel's: on an offline
  VM, copy both from a machine that has downloaded them (docs/TESTING.md, Stage 3).
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
  $existing = @(Get-ChildItem -LiteralPath $out -Recurse -File -Filter *.csv -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName })
  & $exe @toolArgs --csv $out | Out-Null
  $code = $LASTEXITCODE
  if ($code -ne 0 -and $NlRetry -contains $tool) {
    # a dirty hive without usable transaction logs: process it as it is, and say so. The
    # failed attempt's CSVs go first (its console log stays), so no row is ingested twice.
    Get-ChildItem -LiteralPath $out -Recurse -File -Filter *.csv -ErrorAction SilentlyContinue |
      Where-Object { $existing -notcontains $_.FullName } | Remove-Item -Force
    & $exe @toolArgs --nl --csv $out | Out-Null
    if ($LASTEXITCODE -eq 0) { Warn "${tool}: dirty hive without usable .LOG files, processed with --nl (latest changes may be missing)"; return }
    $code = $LASTEXITCODE
  }
  if ($code -ne 0) { Warn "$tool exited with $code" }
}
$NlRetry = @("RECmd", "SBECmd")

# NTFS ($J needs $MFT to resolve parent paths)
$ntfs = Join-Path $Ev "ntfs"
$mft = Join-Path $ntfs '$MFT'
$kapeDir = Join-Path $Ev "triage\kape"
if ((Test-Path $kapeDir) -and -not (Test-Path -LiteralPath $mft)) {
  # take $MFT and $J from a -Kape collection: loose files, or inside KAPE's zip
  New-Item -ItemType Directory -Force -Path $ntfs | Out-Null
  $loose = @(Get-ChildItem -LiteralPath $kapeDir -Recurse -File -Force -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -eq '$MFT' -or $_.Name -eq '$J' })
  foreach ($f in $loose) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $ntfs $f.Name) -Force }
  if (-not $loose) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($z in @(Get-ChildItem -LiteralPath $kapeDir -Recurse -Filter *.zip -ErrorAction SilentlyContinue)) {
      $zip = [IO.Compression.ZipFile]::OpenRead($z.FullName)
      try {
        foreach ($entry in $zip.Entries) {
          if ($entry.Name -eq '$MFT' -or $entry.Name -eq '$J') {
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $ntfs $entry.Name), $true)
          }
        }
      } finally { $zip.Dispose() }
    }
  }
  if (-not (Test-Path -LiteralPath $mft)) { Warn "no `$MFT found in the KAPE output under $kapeDir" }
}
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
    if ($p[0] -eq "windows.netscan" -and -not (($json -join "") -match '"PID"')) {
      # netscan finds nothing on Windows 11 24H2 with Volatility 2.28; netstat has the same columns
      Write-Host "volatility windows.netstat (netscan found no sockets)"
      $json = & $Vol -q -r json -f $mem.FullName "windows.netstat"
      if (-not (($json -join "") -match '"PID"')) {
        Warn "volatility found no sockets with netscan or netstat: usually missing tcpip.pdb symbols on an offline VM"
      } else { Warn "vol_netscan.json comes from windows.netstat (netscan found no sockets)" }
    }
    [IO.File]::WriteAllLines((Join-Path $VolOut $p[1]), [string[]]$json, (New-Object Text.UTF8Encoding($false)))
  }
} elseif (-not $mem) { Warn "no memory image under evidence\memory, Volatility skipped" }
else { Warn "no -Vol given, Volatility skipped" }

# Hashes of the new outputs
$sums = Join-Path $Ev "sha256sums.txt"
$prefix = (Resolve-Path $Ev).Path.TrimEnd("\") + "\"
$new = @(Get-ChildItem -Path $Ez, $VolOut -Recurse -File -ErrorAction SilentlyContinue)
$lines = $new | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.FullName.Substring($prefix.Length))" }
$have = @(if (Test-Path $sums) { Get-Content $sums })
$lines = @($lines | Where-Object { $have -notcontains $_ })   # re-running adds no duplicate lines
if ($lines) { Add-Content -Path $sums -Value $lines -Encoding utf8 }

Write-Host ""
Write-Host "$($new.Count) output files. Next: ptir add-run $RunDir"
if ($script:Warnings.Count) { Write-Host "$($script:Warnings.Count) warning(s):"; $script:Warnings | ForEach-Object { Write-Host "  $_" } }
