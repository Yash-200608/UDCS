<#
.SYNOPSIS
  Isolation acceptance FROM THE INSTALLED SERVICE (LocalSystem, session 0). Needs an
  elevated PowerShell, and the UDCSAgent service installed and running (for example
  by m15_service_acceptance.ps1).

  The script asks the running service to run the isolation self-test from inside the
  service process: it drops diagnostics\isolation-request into the protected data
  directory. It then waits for diagnostics\isolation-result.json and records the
  result in docs\acceptance\data\m2-isolation-service.json.

  Gate to pass (ADR 0001):
  - the agent identity is NT AUTHORITY\SYSTEM in session 0;
  - every check passes, including the process-tree kill;
  - the SYSTEM-parented workload token has no privileges beyond SeChangeNotify.

  What it changes on this PC: the self-test creates and deletes AppContainer profiles
  under the SYSTEM profile, and temporary files and a temporary HKCU (SYSTEM hive)
  value, all removed afterwards. The first run grants read/execute on the agent's
  private interpreter directory to the UDCS runtime capability SID.

  Only a result whose agent identity is SYSTEM in session 0 is written to
  docs\acceptance\data. Any other result goes to %LOCALAPPDATA%\UDCS\diagnostics.

  -Diagnostic: no elevation, no service. Runs the same self-test in THIS PowerShell's
  user context from the repository environment (udcs-agent isolation-selftest). The
  result is labelled interactive-user and is never acceptance evidence. It creates and
  deletes two AppContainer profiles (udcs.wl.selftest-*) and a temporary HKCU key
  (Software\UDCS-IsolationSelftest) in the current user's profile, plus scratch files
  under %LOCALAPPDATA%\UDCS\isolation-selftest.
#>
[CmdletBinding()]
param([int]$TimeoutSeconds = 300, [switch]$Diagnostic)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Out = Join-Path $Repo 'docs\acceptance\data\m2-isolation-service.json'
$Diagnostics = "$env:LOCALAPPDATA\UDCS\diagnostics"
$Data = "$env:ProgramData\UDCS\agent"
$Diag = Join-Path $Data 'diagnostics'
$Result = Join-Path $Diag 'isolation-result.json'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ($Diagnostic) {
    $venv = Join-Path $Repo '.venv\Scripts\python.exe'
    if (-not (Test-Path $venv)) { throw "No repository environment ($venv). Run: uv sync --frozen" }
    $dest = Join-Path $Diagnostics "isolation-selftest-$Stamp.json"
    & $venv -I -m udcs_agent.cli --plain-logs isolation-selftest --out $dest
    $code = $LASTEXITCODE
    Write-Host "DIAGNOSTIC ONLY (interactive user, not the LocalSystem service): $dest" -ForegroundColor Yellow
    exit $code
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell (Run as administrator), or use -Diagnostic. This script never elevates itself.'
}
$svc = Get-Service UDCSAgent -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    throw 'The UDCSAgent service is not running. Install it first (m15_service_acceptance.ps1).'
}

New-Item -ItemType Directory -Force -Path $Diag | Out-Null
Remove-Item $Result -ErrorAction SilentlyContinue
New-Item -ItemType File -Force -Path (Join-Path $Diag 'isolation-request') | Out-Null
Write-Host "Requested the isolation self-test from the service; waiting up to $TimeoutSeconds s..."
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while (-not (Test-Path $Result) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
if (-not (Test-Path $Result)) { throw 'No isolation-result.json: the service did not run the self-test.' }

$report = Get-Content $Result -Raw | ConvertFrom-Json
$identity = $report.agent_identity
$isSystem = ($identity.user -match 'SYSTEM$') -and ($identity.session_id -eq 0)
$failed = @($report.checks | Where-Object { -not $_.pass })
if (-not $isSystem) {  # never evidence: keep it out of docs\acceptance\data
    $Out = Join-Path $Diagnostics "isolation-not-system-$Stamp.json"
    Write-Host "The result is not from SYSTEM in session 0; written as a diagnostic: $Out" -ForegroundColor Yellow
}
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
[IO.File]::WriteAllText($Out, ($report | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))

Write-Host ("Agent identity : {0} (session {1})" -f $identity.user, $identity.session_id)
foreach ($c in $report.checks) {
    $mark = if ($c.pass) { 'PASS' } else { 'FAIL' }
    Write-Host ("{0}  {1,-48} sandbox: {2}" -f $mark, $c.name, $c.sandbox)
}
Write-Host ("Process tree kill: {0}" -f ($(if ($report.kill_tree.pass) { 'PASS' } else { 'FAIL' })))
Write-Host ("CUDA inside the sandbox: {0}" -f ($report.cuda_in_sandbox | ConvertTo-Json -Compress))
if ($isSystem -and $report.passed -and $failed.Count -eq 0) {
    Write-Host 'ISOLATION ACCEPTANCE (service path): PASSED' -ForegroundColor Green
    exit 0
}
if (-not $isSystem) { Write-Host 'The self-test did not run as SYSTEM in session 0.' -ForegroundColor Red }
Write-Host 'ISOLATION ACCEPTANCE (service path): FAILED' -ForegroundColor Red
exit 1
