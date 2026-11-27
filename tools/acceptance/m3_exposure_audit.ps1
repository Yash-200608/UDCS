<#
.SYNOPSIS
  AppContainer exposure audit of THIS machine's Windows image (ADR 0001 gate 2,
  ADR 0003). Records exactly which filesystem, registry, process, named-pipe,
  named-object, network, service and window-station resources a UDCS package sandbox
  can still reach.

    .\m3_exposure_audit.ps1            as the current user (a tool check; NOT the gate)
    .\m3_exposure_audit.ps1 -AsSystem  as LocalSystem, the service context (the gate)

  -AsSystem runs the repository's agent code (not the installed service) once as SYSTEM
  through a temporary scheduled task, then deletes the task. The installed UDCSAgent
  service is not stopped, started, reconfigured or upgraded.

  What it changes on this PC:
    - creates and deletes one AppContainer profile (udcs.<scope>.<hash>);
    - creates a scratch/runtime directory: %ProgramData%\UDCS\exposure-audit (-AsSystem)
      or %LOCALAPPDATA%\UDCS\exposure-audit;
    - grants the UDCS runtime capability SID read/execute on the Python installation the
      repository environment uses (the same grant the agent makes for its own runtime);
    - -AsSystem: one scheduled task, removed when the script ends (even on failure).
  The probe opens each named pipe read-only and closes it at once.

  Outputs:
    - the full report (contains paths and names from this PC): kept OUTSIDE the
      repository, in the scratch directory, for `udcs admin audit-upload`;
    - a summary without host or user names: docs\acceptance\data\m3-exposure-audit-<context>.json
#>
[CmdletBinding()]
param([switch]$AsSystem, [int]$TimeoutMinutes = 20)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Venv = Join-Path $Repo '.venv\Scripts\python.exe'
if (-not (Test-Path $Venv)) { throw "No repository environment ($Venv). Run: uv sync --frozen" }
$Context = if ($AsSystem) { 'system' } else { 'user' }
$Scratch = if ($AsSystem) { "$env:ProgramData\UDCS\exposure-audit" } else { "$env:LOCALAPPDATA\UDCS\exposure-audit" }
$Report = Join-Path $Scratch 'exposure-report.json'
$Log = Join-Path $Scratch 'exposure-audit.log'
$Summary = Join-Path $Repo "docs\acceptance\data\m3-exposure-audit-$Context.json"
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
Remove-Item $Report, $Log -ErrorAction SilentlyContinue
# A runner file avoids quoting a Python program through cmd.exe and the task scheduler.
$Runner = Join-Path $Scratch 'run_audit.py'
@"
import sys
log = open(r'$Log', 'w', encoding='utf-8', buffering=1)
sys.stdout = sys.stderr = log
from udcs_agent.cli import main
sys.exit(main(['audit-exposure', '--out', r'$Report', '--data-dir', r'$Scratch']))
"@ | Set-Content -Path $Runner -Encoding utf8

if ($AsSystem) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run from an elevated PowerShell (Run as administrator) for -AsSystem.'
    }
    $name = "UDCS-ExposureAudit-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $action = New-ScheduledTaskAction -Execute $Venv -Argument "-I `"$Runner`"" -WorkingDirectory $Scratch
    $task = Register-ScheduledTask -TaskName $name -Action $action -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest -Force
    try {
        Start-ScheduledTask -TaskName $name
        Write-Host "Running the audit as SYSTEM (task $name), up to $TimeoutMinutes min..."
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        do {
            Start-Sleep -Seconds 3
            $state = (Get-ScheduledTask -TaskName $name).State
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
        if ($state -eq 'Running') { Stop-ScheduledTask -TaskName $name; throw 'The audit did not finish in time.' }
    } finally {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
} else {
    & $Venv -I $Runner
}
if (-not (Test-Path $Report)) {
    Write-Host (Get-Content $Log -Raw -ErrorAction SilentlyContinue)
    throw 'No report was produced; see the log above.'
}
$summaryJson = & $Venv -I -c "import json,sys; from udcs_shared.exposure import ExposureReport, summary; r = ExposureReport.model_validate_json(open(sys.argv[1], 'rb').read()); s = summary(r); s.pop('runner', None); s['runner_context'] = sys.argv[2]; s['generated_at'] = r.generated_at.isoformat(); print(json.dumps(s, indent=1))" $Report $Context
New-Item -ItemType Directory -Force -Path (Split-Path $Summary) | Out-Null
[IO.File]::WriteAllText($Summary, ($summaryJson -join "`n"), (New-Object Text.UTF8Encoding $false))  # no BOM: plain JSON
$s = $summaryJson | ConvertFrom-Json
Write-Host ("Context: {0}   image: {1}   build: {2}" -f $Context, $s.image, $s.build)
Write-Host ("Reachable: {0}" -f ($s.reachable | ConvertTo-Json -Compress -Depth 4))
foreach ($v in @($s.violations | Select-Object -First 40)) { Write-Host "VIOLATION: $v" -ForegroundColor Red }
Write-Host "Full report (keep private): $Report"
Write-Host "Summary: $Summary"
if ($s.passed) {
    Write-Host "EXPOSURE AUDIT ($Context): no violations. Review the reachable items before any grant." -ForegroundColor Green
    if ($AsSystem) { Write-Host "Record it:  udcs admin audit-upload <node-id> `"$Report`"" }
    exit 0
}
Write-Host "EXPOSURE AUDIT ($Context): $($s.violation_count) violations. Do not grant eligibility." -ForegroundColor Red
exit 1
