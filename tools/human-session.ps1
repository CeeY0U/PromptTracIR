<#
.SYNOPSIS
  Mark a paired human run for ground truth.

.DESCRIPTION
  Dot-source this in the PowerShell tab the team member will TYPE commands in:
      . .\human-session.ps1 -Run run01
  It records this shell's PID and start time; type the commands by hand, then run
      Stop-HumanSession
  Pass the recorded PID to harness/label_run.py with --human-pids.
  Nothing here automates typing: the point is genuinely interactive activity.
#>
param([string]$Run = "run", [string]$OutDir = ".")
$global:PtirHuman = [ordered]@{ run = $Run; shell_pid = $PID; start = (Get-Date).ToUniversalTime().ToString("o") }
Write-Host "Human session '$Run' started in shell PID $PID. Type your commands, then run Stop-HumanSession."

function global:Stop-HumanSession {
  $global:PtirHuman.end = (Get-Date).ToUniversalTime().ToString("o")
  $path = Join-Path $OutDir ("human_" + $global:PtirHuman.run + ".json")
  $global:PtirHuman | ConvertTo-Json | Set-Content -Encoding utf8 $path
  Write-Host "Saved $path"
}
