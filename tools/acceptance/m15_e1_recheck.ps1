<#
.SYNOPSIS
  One targeted re-check of M1.5 experiment E1 (CUDA from the service and its child
  workers) after replacing ONLY gpu_probe.py in the installed agent. Elevated.

.DESCRIPTION
  Why: on build c5dd16f every E1 child probe died on a pywin32 import (fixed in cd02387,
  gpu_probe.py only). The service lifecycle evidence (pass 1 run 2, pass 2) stays as
  recorded; this closes only the E1 gap.

  What it does, and nothing else:
    1. refuses unless UDCSAgent is running and the installed gpu_probe.py is exactly the
       c5dd16f version and the repository's is exactly the fixed version (SHA-256 of the
       content with CRLF normalised to LF);
    2. keeps the installed file as gpu_probe.py.c5dd16f-backup and replaces it (and drops
       its cached .pyc); no restart: the service imports the probe only when E1 runs;
    3. requests E1 from the running service (diagnostics\gpu-request), waits for the result;
    4. writes docs\acceptance\data\machines\<label>\m15-e1-recheck-cd02387.json (refuses to
       overwrite). m15-service-acceptance.json is never touched.
  No reboot, no reinstall, no service restart, no other file changed.
#>
[CmdletBinding()]
param([int]$TimeoutSeconds = 240)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'evidence_paths.ps1')
$Service = 'UDCSAgent'
$Install = "$env:ProgramFiles\UDCS\Agent"
$Data = "$env:ProgramData\UDCS\agent"
$Installed = Join-Path $Install 'site\udcs_agent\diagnostics\gpu_probe.py'
$Fixed = Join-Path $Repo 'node_agent\src\udcs_agent\diagnostics\gpu_probe.py'
$OldSha = '7cabd5f2f65c9f180844276b86a393e7e4b4c1c488904cf21cd21011cac83976'  # git c5dd16f
$NewSha = '378984372ae77fbcaf0fde50c39b88e0c6f4eec59f2543e310864f24a06e0e26'  # git cd02387
$Out = Join-Path (Split-Path (Get-MachineEvidencePath (Join-Path $Repo 'docs\acceptance\data'))) 'm15-e1-recheck-cd02387.json'

function Get-ContentSha([string]$Path) {
    $text = [IO.File]::ReadAllText($Path) -replace "`r`n", "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($text)) } finally { $sha.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
function Stop-Unchanged([string]$Why) {
    Write-Host "Stopped, nothing changed: $Why" -ForegroundColor Yellow
    exit 2
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell. This script never elevates itself.'
}
if (Test-Path -LiteralPath $Out) { Stop-Unchanged "$Out already exists." }
$svc = Get-Service $Service -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') { Stop-Unchanged 'UDCSAgent is not running.' }
if (-not (Test-Path -LiteralPath $Installed)) { Stop-Unchanged "no installed probe at $Installed." }
$before = Get-ContentSha $Installed
if ($before -ne $OldSha) { Stop-Unchanged "the installed gpu_probe.py is not the c5dd16f version (sha256 $before)." }
if ((Get-ContentSha $Fixed) -ne $NewSha) { Stop-Unchanged 'the repository gpu_probe.py is not the cd02387 version.' }

# -- the one change: gpu_probe.py ------------------------------------------------------------
$backup = "$Installed.c5dd16f-backup"
Copy-Item -LiteralPath $Installed -Destination $backup -Force
Copy-Item -LiteralPath $Fixed -Destination $Installed -Force
Get-ChildItem -LiteralPath (Join-Path (Split-Path $Installed) '__pycache__') -Filter 'gpu_probe.*.pyc' -ErrorAction SilentlyContinue |
    Remove-Item -Force
$after = Get-ContentSha $Installed
if ($after -ne $NewSha) { throw "the copied probe does not hash as expected ($after); backup at $backup." }
Write-Host "gpu_probe.py replaced (backup: $backup)."

# -- E1 from the running service ----------------------------------------------------------
$diag = Join-Path $Data 'diagnostics'
New-Item -ItemType Directory -Force -Path $diag | Out-Null
Remove-Item (Join-Path $diag 'gpu-result.json') -ErrorAction SilentlyContinue
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='$Service'").ProcessId
New-Item -ItemType File -Force -Path (Join-Path $diag 'gpu-request') | Out-Null
Write-Host "Requested E1 from the service (pid $svcPid); waiting up to $TimeoutSeconds s..."
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path (Join-Path $diag 'gpu-result.json')) -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path (Join-Path $diag 'gpu-result.json'))) { throw 'No gpu-result.json: the service did not run E1. Nothing recorded.' }
$seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
$matrix = Get-Content (Join-Path $diag 'gpu-result.json') -Raw | ConvertFrom-Json
$samePid = ((Get-CimInstance Win32_Service -Filter "Name='$Service'").ProcessId -eq $svcPid)

$used = @('service_process', 'service_child_worker')
$usedOk = (@($used | Where-Object { -not $matrix.arrangements.$_.ok }).Count -eq 0)
$record = [ordered]@{
    kind = 'm15-e1-recheck'
    note = 'Targeted re-check of E1 only, after replacing gpu_probe.py in the installed c5dd16f agent with the cd02387 version. Service lifecycle evidence is in m15-service-acceptance.json and was not re-run.'
    generated_at = (Get-Date).ToString('o')
    machine = Get-MachineFacts
    installed_agent = [ordered]@{ build = 'c5dd16f'; replaced = 'site\udcs_agent\diagnostics\gpu_probe.py'
        probe_sha256_before = $before; probe_sha256_after = $after; probe_build = 'cd02387' }
    service = [ordered]@{ pid = $svcPid; same_process_throughout = $samePid; restarted = $false }
    e1_seconds = $seconds
    e1_gpu_matrix = $matrix
    checks = [ordered]@{
        e1_used_arrangements_ok = [ordered]@{ pass = $usedOk; detail = [ordered]@{
            service_process = $matrix.arrangements.service_process.ok; service_child_worker = $matrix.arrangements.service_child_worker.ok } }
    }
}
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$fs = New-Object IO.FileStream($Out, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try {
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes(($record | ConvertTo-Json -Depth 12))
    $fs.Write($bytes, 0, $bytes.Length)
} finally { $fs.Dispose() }

foreach ($name in 'service_process', 'service_child_worker', 'session_worker_system', 'session_worker_user') {
    $a = $matrix.arrangements.$name
    $mark = if ($a.ok) { ' OK ' } else { 'FAIL' }
    Write-Host ("[{0}] {1,-22} account={2} device={3} kernel_ms={4} {5}" -f $mark, $name, $a.account, $a.device, $a.kernel_ms_median, $a.error)
}
$verdict = if ($usedOk) { 'PASS' } else { 'FAIL' }
Write-Host "e1_used_arrangements_ok: $verdict   (service pid unchanged: $samePid)"
Write-Host "Recorded: $Out"
if (-not $usedOk) { exit 1 }
