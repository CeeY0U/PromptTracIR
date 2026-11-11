<#
.SYNOPSIS
  Mark a paired human run for ground truth.

.DESCRIPTION
  Dot-source this in the PowerShell tab the team member will TYPE commands in:
      . .\tools\human-session.ps1 -Run run01 -OutDir C:\lab\runs\run01 -Scenario harness\scenarios\web_exfil_01.json
  It records this shell's PID and start time and prints the scenario's human_commands;
  type them by hand, then run
      Stop-HumanSession
  It writes OutDir\human_<run>.json, which harness/label_run.py reads automatically.
  Nothing here automates typing: the point is genuinely interactive activity.
#>
param([string]$Run = "run", [string]$OutDir = ".", [string]$Scenario)
$global:PtirHuman = [ordered]@{ run = $Run; shell_pid = $PID; start = (Get-Date).ToUniversalTime().ToString("o") }
$global:PtirHumanOut = $OutDir
Write-Host "Human session '$Run' started in shell PID $PID."
if ($Scenario) {
  $sc = Get-Content -Raw $Scenario | ConvertFrom-Json
  $global:PtirHuman.scenario = $sc.id
  Write-Host "Type these commands yourself (do not paste):" -ForegroundColor Cyan
  foreach ($c in $sc.human_commands) { Write-Host "  $c" }
}
Write-Host "Then run Stop-HumanSession."

function global:Stop-HumanSession {
  $global:PtirHuman.end = (Get-Date).ToUniversalTime().ToString("o")
  $path = Join-Path $global:PtirHumanOut ("human_" + $global:PtirHuman.run + ".json")
  $global:PtirHuman | ConvertTo-Json | Set-Content -Encoding utf8 $path
  Write-Host "Saved $path"
}
