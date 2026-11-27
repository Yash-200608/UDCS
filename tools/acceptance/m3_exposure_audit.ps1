<#
.SYNOPSIS
  AppContainer exposure audit of THIS machine's Windows image (ADR 0001 gate 2,
  ADR 0003): which filesystem, registry, process, named-pipe, named-object, network,
  service and window-station resources a UDCS package sandbox can still reach.

    .\m3_exposure_audit.ps1            DIAGNOSTIC: as the current user; never evidence
    .\m3_exposure_audit.ps1 -AsSystem  EVIDENCE for this image: as LocalSystem (session 0)

  The script never elevates by itself. -AsSystem refuses to run unless this PowerShell
  is already elevated. It runs the repository's agent code (not the installed service)
  once as LocalSystem through a temporary scheduled task. The installed UDCSAgent
  service is not stopped, started, reconfigured or upgraded.

  Every result is labelled with the machine (a hash of its name, never the name), its
  Windows image (release, build, patch, edition) and the execution identity. Only a
  LocalSystem session-0 result is written to docs\acceptance\data; everything else goes
  to the diagnostics folder outside the repository.

  What it changes on this PC (and how it is undone):
    - one AppContainer profile (udcs.<scope>.<hash>): deleted when the audit ends;
    - a scratch/runtime directory: %LOCALAPPDATA%\UDCS\exposure-audit (user) or
      %ProgramData%\UDCS\exposure-audit (-AsSystem). Kept, so the report can be
      uploaded; delete it afterwards;
    - an ACE granting the UDCS runtime capability read/execute on the Python
      installation the repository uses (as the agent does for its own runtime). Kept;
    - -AsSystem only: one scheduled task, UDCS-ExposureAudit-<id>. Cleanup is
      deterministic:
        1. any stale UDCS-ExposureAudit-* task from an earlier interrupted run is
           removed first (listed on screen);
        2. the task is removed in a finally block (success, failure, Ctrl+C);
        3. if this console is killed, the task still expires 45 minutes after creation
           and Task Scheduler deletes it itself (DeleteExpiredTaskAfter), and a running
           audit is stopped after 30 minutes (ExecutionTimeLimit). The trigger is in
           the past and never fires, so the task never runs again on its own.
  The probe opens each named pipe read-only and closes it at once.
#>
[CmdletBinding()]
param([switch]$AsSystem, [int]$TimeoutMinutes = 25)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Venv = Join-Path $Repo '.venv\Scripts\python.exe'
if (-not (Test-Path $Venv)) { throw "No repository environment ($Venv). Run: uv sync --frozen" }
$TaskPrefix = 'UDCS-ExposureAudit-'

if ($AsSystem) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '-AsSystem needs an already elevated PowerShell. This script never elevates itself.'
    }
    $Scratch = "$env:ProgramData\UDCS\exposure-audit"
} else {
    $Scratch = "$env:LOCALAPPDATA\UDCS\exposure-audit"
}
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Report = Join-Path $Scratch "exposure-report-$Stamp.json"
$SummaryTmp = Join-Path $Scratch "exposure-summary-$Stamp.json"
$Log = Join-Path $Scratch "exposure-audit-$Stamp.log"
$Diagnostics = "$env:LOCALAPPDATA\UDCS\diagnostics"
New-Item -ItemType Directory -Force -Path $Scratch, $Diagnostics | Out-Null

# A runner file avoids quoting a Python program through the task scheduler.
$Runner = Join-Path $Scratch 'run_audit.py'
@"
import sys
log = open(r'$Log', 'w', encoding='utf-8', buffering=1)
sys.stdout = sys.stderr = log
from udcs_agent.cli import main
sys.exit(main(['audit-exposure', '--out', r'$Report', '--summary-out', r'$SummaryTmp', '--data-dir', r'$Scratch']))
"@ | Set-Content -Path $Runner -Encoding utf8

if ($AsSystem) {
    foreach ($stale in @(Get-ScheduledTask -TaskName "$TaskPrefix*" -ErrorAction SilentlyContinue)) {
        Write-Host "Removing a stale task from an interrupted run: $($stale.TaskName)" -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $stale.TaskName -Confirm:$false
    }
    $name = "$TaskPrefix$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $action = New-ScheduledTaskAction -Execute $Venv -Argument "-I `"$Runner`"" -WorkingDirectory $Scratch
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(-5)  # in the past: never fires
    $trigger.EndBoundary = (Get-Date).AddMinutes(45).ToString('s')
    $settings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 0) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $settings.StartWhenAvailable = $false
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal | Out-Null
    try {
        Start-ScheduledTask -TaskName $name
        Write-Host "Running the audit as LocalSystem (task $name), up to $TimeoutMinutes min..."
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        do {
            Start-Sleep -Seconds 3
            $state = (Get-ScheduledTask -TaskName $name).State
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
        if ($state -eq 'Running') { Stop-ScheduledTask -TaskName $name; throw 'The audit did not finish in time.' }
    } finally {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Write-Host "WARNING: could not remove task $name; it expires and deletes itself within 45 minutes." -ForegroundColor Yellow
        }
    }
} else {
    & $Venv -I $Runner
}
if (-not (Test-Path $SummaryTmp)) {
    Write-Host (Get-Content $Log -Raw -ErrorAction SilentlyContinue)
    throw 'No result was produced; see the log above.'
}
$wrapped = Get-Content $SummaryTmp -Raw | ConvertFrom-Json
$isEvidence = [bool]$wrapped.evidence -and $AsSystem
$label = $wrapped.machine.label
$dest = if ($isEvidence) {
    Join-Path $Repo "docs\acceptance\data\m3-exposure-audit-$label-$Stamp.json"
} else {
    Join-Path $Diagnostics "exposure-audit-$($wrapped.identity.context)-$label-$Stamp.json"
}
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Copy-Item $SummaryTmp $dest -Force
$r = $wrapped.result
Write-Host ("Machine label: {0}   image: {1}   build {2}.{3}   edition: {4}" -f $label, $wrapped.machine.image, $wrapped.machine.build, $wrapped.machine.patch, $wrapped.machine.edition)
Write-Host ("Identity: {0} (session {1}, elevated: {2})" -f $wrapped.identity.context, $wrapped.identity.session_id, $wrapped.identity.elevated)
Write-Host ("Reachable: {0}" -f ($r.reachable | ConvertTo-Json -Compress -Depth 4))
foreach ($v in @($r.violations | Select-Object -First 40)) { Write-Host "VIOLATION: $v" -ForegroundColor Red }
Write-Host "Full report (contains this PC's paths; keep private): $Report"
if ($isEvidence) {
    Write-Host "Summary (EVIDENCE for this image): $dest"
} else {
    Write-Host "Summary (DIAGNOSTIC ONLY, not acceptance evidence): $dest" -ForegroundColor Yellow
}
if ($r.passed) {
    Write-Host "EXPOSURE AUDIT ($($wrapped.identity.context)): no violations. Review the reachable items before any grant." -ForegroundColor Green
    if ($isEvidence) { Write-Host "Record it:  udcs admin audit-upload <node-id> `"$Report`"" }
    exit 0
}
Write-Host "EXPOSURE AUDIT ($($wrapped.identity.context)): $($r.violation_count) violations. Do not grant eligibility." -ForegroundColor Red
exit 1
