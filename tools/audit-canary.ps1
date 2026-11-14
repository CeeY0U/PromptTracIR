<#
.SYNOPSIS
  Audit reads of the canary folder so Windows logs Security event 4663 for every file opened in it.

.DESCRIPTION
  Sysmon has no file-read event, so without this PromptTracIR only infers reads of the canary
  secret from command lines and the agent's own trace. With it, every process that opens a file
  under -Path for reading leaves a 4663 record (process ID, image, file, access mask), which
  `ptir analyze` joins to the process tree and uses to corroborate or contradict the trace.

  Run once per clean snapshot, in an elevated PowerShell, after `harness.scenario prepare` has
  created the folder. It:
    1. enables the "File System" audit subcategory (success);
    2. adds an audit rule (SACL) for Everyone: ReadData and WriteData, success, on the folder
       and everything below it.
  Only the folder you pass is audited, so the Security log does not fill with unrelated reads.

.EXAMPLE
  .\tools\audit-canary.ps1 -Path C:\Users\lab\secrets
#>
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [switch]$Remove
)
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated (Administrator) PowerShell."
}
if (-not (Test-Path -LiteralPath $Path)) { throw "Not found: $Path (run harness.scenario prepare first)" }

$rights = [Security.AccessControl.FileSystemRights]"ReadData, WriteData"
$inherit = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$prop = [Security.AccessControl.PropagationFlags]::None
$rule = New-Object Security.AccessControl.FileSystemAuditRule("Everyone", $rights, $inherit, $prop, "Success")

$acl = Get-Acl -LiteralPath $Path -Audit
if ($Remove) {
  [void]$acl.RemoveAuditRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
  Write-Host "Removed the audit rule from $Path"
  return
}
& auditpol.exe /set /subcategory:"File System" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw "auditpol failed (exit $LASTEXITCODE)" }
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $Path -AclObject $acl

$check = (Get-Acl -LiteralPath $Path -Audit).Audit | Where-Object { $_.IdentityReference -like "*Everyone" }
if (-not $check) { throw "The audit rule did not apply to $Path" }
Write-Host "Auditing reads and writes under $Path (Security event 4663)."
Write-Host "Test: Get-Content <a file in it>, then: Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 1"
