<#
.SYNOPSIS
  Export lab evidence after a run into a folder PromptTracIR can ingest.

.DESCRIPTION
  Writes JSONL exports (what `ptir add --kind sysmon|security|powershell` reads), raw .evtx
  copies for preservation, and the PSReadLine history. Run as Administrator (Security log).

.EXAMPLE
  .\export-events.ps1 -Out C:\lab\runs\run01\evidence -Since (Get-Date).AddMinutes(-30)
#>
param(
  [string]$Out = ".\evidence",
  [datetime]$Since = (Get-Date).AddHours(-1)
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Export-Channel([string]$LogName, [int[]]$Ids, [string]$File) {
  $filter = @{ LogName = $LogName; StartTime = $Since }
  if ($Ids) { $filter.Id = $Ids }
  $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | Sort-Object RecordId)
  $path = Join-Path $Out $File
  $sw = [System.IO.StreamWriter]::new($path, $false, [System.Text.UTF8Encoding]::new($false))
  try {
    foreach ($e in $events) {
      $xml = [xml]$e.ToXml()
      $data = [ordered]@{}
      foreach ($d in @($xml.Event.EventData.Data)) { if ($d.Name) { $data[$d.Name] = $d.'#text' } }
      $rec = [ordered]@{
        EventID     = $e.Id
        TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("o")
        Computer    = $e.MachineName
        Channel     = $e.LogName
        RecordID    = $e.RecordId
        ProcessID   = $e.ProcessId
        EventData   = $data
      }
      $sw.WriteLine(($rec | ConvertTo-Json -Compress -Depth 4))
    }
  } finally { $sw.Close() }
  Write-Host ("{0,-45} {1,6} events -> {2}" -f $LogName, $events.Count, $path)
}

Export-Channel "Microsoft-Windows-Sysmon/Operational" $null "sysmon.jsonl"
Export-Channel "Security" @(4624, 4688) "security.jsonl"
Export-Channel "Microsoft-Windows-PowerShell/Operational" @(4104) "powershell.jsonl"

# Raw copies for chain of custody (python-evtx can also read these directly)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" (Join-Path $Out "Sysmon.evtx") /ow:true
wevtutil epl "Security" (Join-Path $Out "Security.evtx") /ow:true
wevtutil epl "Microsoft-Windows-PowerShell/Operational" (Join-Path $Out "PowerShell.evtx") /ow:true

# PSReadLine history of the lab user
$hist = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $hist) { Copy-Item $hist (Join-Path $Out "ConsoleHost_history.txt") }

Get-ChildItem $Out | Get-FileHash -Algorithm SHA256 | Format-Table -AutoSize
