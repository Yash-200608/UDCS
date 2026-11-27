<#
.SYNOPSIS
  Read-only readiness check before the acceptance runs on the ORIGINAL machine (the PC
  where m15_service_acceptance.ps1 pass 1 installed the UDCSAgent service). Safe on any
  machine, with or without elevation.

  It changes nothing: no service start/stop/install, no ACLs, no scheduled tasks, no
  acceptance evidence. Its result is a DIAGNOSTIC, written outside the repository
  (%LOCALAPPDATA%\UDCS\diagnostics), never to docs\acceptance\data.

  It reports every mismatch it finds (it does not stop at the first):
    - is this the pass-1 machine (recorded Windows build and GPUs), and has it rebooted
      since pass 1 (pass 2 needs both)?
    - is the installed UDCSAgent service present, running, LocalSystem, and which agent
      version is installed (left exactly as it is)?
    - can the repository environment run the diagnostics and the exposure audit?
    - are repository files local (OneDrive online-only files are unreadable for SYSTEM)?
    - is this PowerShell elevated (pass 2 and -AsSystem need it)?

  Exit code: 0 = this machine is ready for pass 2 and the service-path runs;
             3 = not ready (every reason is listed). Never 0 on a development PC.
#>
[CmdletBinding()]
param([string]$Out)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Pass1 = Join-Path $Repo 'docs\acceptance\data\m15-service-acceptance.json'
$Install = "$env:ProgramFiles\UDCS\Agent"
$Service = 'UDCSAgent'
if (-not $Out) {
    $Out = Join-Path "$env:LOCALAPPDATA\UDCS\diagnostics" ("preflight-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$checks = [ordered]@{}
$mismatches = New-Object System.Collections.Generic.List[string]
function Note($name, [bool]$ok, $detail, [string]$why) {
    $checks[$name] = [ordered]@{ ok = $ok; detail = $detail }
    $mark = if ($ok) { ' OK ' } else { 'MISMATCH' }
    if (-not $ok) { $mismatches.Add("${name}: $why") }
    Write-Host ("[{0}] {1}: {2}" -f $mark, $name, ($detail | ConvertTo-Json -Compress -Depth 5))
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Note 'elevated' $elevated @{ elevated = $elevated } 'pass 2, the isolation service run and -AsSystem need an elevated PowerShell (this script never elevates)'

$build = [Environment]::OSVersion.Version.ToString()
$gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { "$($_.Name) ($($_.DriverVersion))" })
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if (Test-Path $Pass1) {
    $report = Get-Content $Pass1 -Raw | ConvertFrom-Json
    $buildOk = $report.machine.build -eq $build
    $gpuOk = -not (Compare-Object @($report.machine.gpu) $gpus)
    Note 'pass1_machine_build' $buildOk @{ recorded = $report.machine.build; this = $build } 'Windows build differs from the pass-1 machine'
    Note 'pass1_machine_gpus' $gpuOk @{ recorded = @($report.machine.gpu); this = $gpus } 'GPUs differ from the pass-1 machine'
    $marker = $report.reboot_marker
    # A later boot time means nothing on another machine: only judge it on the pass-1 PC.
    $rebooted = [bool]($buildOk -and $gpuOk -and $marker -and ([datetime]$marker.boot_before -lt $boot))
    Note 'rebooted_since_pass1' $rebooted @{ pass1_boot = $marker.boot_before; this_boot = $boot.ToString('o'); same_machine = ($buildOk -and $gpuOk) } 'no reboot of the pass-1 machine since pass 1 (another machine, or no pass-1 marker)'
    Note 'pass2_not_yet_recorded' (-not $report.checks.starts_after_reboot) @{ starts_after_reboot = $report.checks.starts_after_reboot } 'pass 2 is already recorded'
} else {
    Note 'pass1_evidence' $false @{ path = $Pass1 } 'no pass-1 report in docs\acceptance\data'
}

$svc = Get-CimInstance Win32_Service -Filter "Name='$Service'" -ErrorAction SilentlyContinue
Note 'service_installed' ($null -ne $svc) @{ state = $svc.State; start_mode = $svc.StartMode; account = $svc.StartName } 'UDCSAgent is not installed on this PC'
if ($svc) {
    Note 'service_running_localsystem' (($svc.State -eq 'Running') -and ($svc.StartName -eq 'LocalSystem')) @{} 'the service is not running as LocalSystem'
    $python = Join-Path $Install 'python\python.exe'
    if (Test-Path $python) {
        $version = & $python -I -c "import udcs_agent; print(udcs_agent.__version__)" 2>$null
        Note 'installed_agent' $true @{ version = "$version"; note = 'left exactly as installed; these scripts never upgrade it' } ''
    }
}

$venv = Join-Path $Repo '.venv\Scripts\python.exe'
$envOk = $false
if (Test-Path $venv) {
    $envOk = (& $venv -I -c "import udcs_agent.diagnostics.exposure_audit, udcs_agent.diagnostics.context; print('ok')" 2>$null) -eq 'ok'
}
Note 'repo_environment' $envOk @{ python = $venv } 'repository environment missing or outdated (run: uv sync --frozen)'

# FILE_ATTRIBUTE_OFFLINE 0x1000, RECALL_ON_OPEN 0x40000, RECALL_ON_DATA_ACCESS 0x400000
$placeholders = @(Get-ChildItem -Path (Join-Path $Repo 'node_agent'), (Join-Path $Repo 'shared') -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { ([int]$_.Attributes -band (0x1000 -bor 0x40000 -bor 0x400000)) -ne 0 })
Note 'repo_files_local' ($placeholders.Count -eq 0) @{ online_only_files = $placeholders.Count } 'OneDrive online-only files: keep the folder on this device'

$identity = if ($envOk) { & $venv -I -c "import json; from udcs_agent.diagnostics.context import execution_context, machine_label; print(json.dumps({'identity': execution_context(), 'machine': machine_label()}))" | ConvertFrom-Json } else { $null }
$result = [ordered]@{
    kind = 'preflight'; evidence = $false
    note = 'DIAGNOSTIC ONLY: preflight results are never acceptance evidence'
    generated_at = (Get-Date).ToString('o')
    machine = $identity.machine; identity = $identity.identity
    ready_for_original_machine_runs = ($mismatches.Count -eq 0)
    mismatches = $mismatches; checks = $checks
}
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
[IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
Write-Host "`nDiagnostic written (not evidence): $Out"
if ($mismatches.Count -eq 0) {
    Write-Host 'READY: this is the pass-1 machine, rebooted, with the service installed.' -ForegroundColor Green
    Write-Host '  1. tools\acceptance\m15_service_acceptance.ps1 -AfterReboot'
    Write-Host '  2. tools\acceptance\m2_isolation_service_acceptance.ps1'
    Write-Host '  3. tools\acceptance\m3_exposure_audit.ps1 -AsSystem'
    exit 0
}
Write-Host ("NOT READY for the original-machine runs ({0} mismatches):" -f $mismatches.Count) -ForegroundColor Yellow
foreach ($m in $mismatches) { Write-Host "  - $m" }
exit 3
