<#
.SYNOPSIS
  Read-only readiness check for the original acceptance machine (the PC where the
  UDCSAgent service was installed by m15_service_acceptance.ps1 pass 1).

  It changes NOTHING: no service start/stop/install, no files outside its own report,
  no ACLs, no scheduled tasks. It answers, with evidence:
    - is this the pass-1 machine, and has it rebooted since pass 1 (M1.5 pass 2 ready)?
    - is the installed UDCSAgent service present, running, LocalSystem, and which agent
      version is installed (left exactly as it is)?
    - can the repository's environment run the exposure audit (m3_exposure_audit.ps1)?
    - are the repository files local (OneDrive "online-only" files cannot be read by a
      SYSTEM task)?

  Report: docs\acceptance\data\m3-preflight.json (no host name, no user names).
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Out = Join-Path $Repo 'docs\acceptance\data\m3-preflight.json'
$Pass1 = Join-Path $Repo 'docs\acceptance\data\m15-service-acceptance.json'
$Install = "$env:ProgramFiles\UDCS\Agent"
$Service = 'UDCSAgent'
$checks = [ordered]@{}
function Note($name, [bool]$ok, $detail) {
    $checks[$name] = [ordered]@{ ok = $ok; detail = $detail }
    $mark = if ($ok) { ' OK ' } else { 'WARN' }
    Write-Host ("[{0}] {1}: {2}" -f $mark, $name, ($detail | ConvertTo-Json -Compress -Depth 5))
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Note 'elevated' ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) @{ needed_for = 'pass 2, -AsSystem audit' }

$build = [Environment]::OSVersion.Version.ToString()
$gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { "$($_.Name) ($($_.DriverVersion))" })
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if (Test-Path $Pass1) {
    $report = Get-Content $Pass1 -Raw | ConvertFrom-Json
    $same = ($report.machine.build -eq $build) -and -not (Compare-Object @($report.machine.gpu) $gpus)
    Note 'pass1_machine' $same @{ recorded_build = $report.machine.build; this_build = $build }
    $marker = $report.reboot_marker
    $rebooted = $marker -and ([datetime]$marker.boot_before -lt $boot)
    Note 'rebooted_since_pass1' ([bool]$rebooted) @{ pass1_boot = $marker.boot_before; this_boot = $boot.ToString('o') }
    $pass1 = @($report.checks.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value.pass)" })
    Note 'pass1_checks' $true @{ results = $pass1 }
} else {
    Note 'pass1_machine' $false @{ reason = 'no pass-1 report in docs\acceptance\data' }
}

$svc = Get-CimInstance Win32_Service -Filter "Name='$Service'" -ErrorAction SilentlyContinue
if ($svc) {
    Note 'service_installed' $true @{ state = $svc.State; start_mode = $svc.StartMode; account = $svc.StartName }
    Note 'service_running_as_localsystem' (($svc.State -eq 'Running') -and ($svc.StartName -eq 'LocalSystem')) @{}
    $python = Join-Path $Install 'python\python.exe'
    if (Test-Path $python) {
        $version = & $python -I -c "import udcs_agent; print(udcs_agent.__version__)" 2>$null
        $hasAudit = & $python -I -c "import importlib.util as u; print(bool(u.find_spec('udcs_agent.diagnostics.exposure_audit')))" 2>$null
        Note 'installed_agent' $true @{ version = "$version"; has_exposure_audit = "$hasAudit"; note = 'left as installed; never upgraded by these scripts' }
    }
} else {
    Note 'service_installed' $false @{ reason = 'UDCSAgent not installed on this PC' }
}

$venv = Join-Path $Repo '.venv\Scripts\python.exe'
if (Test-Path $venv) {
    $ok = & $venv -c "import udcs_agent.diagnostics.exposure_audit, udcs_shared.exposure; print('ok')" 2>$null
    Note 'repo_environment' ($ok -eq 'ok') @{ python = $venv }
} else {
    Note 'repo_environment' $false @{ fix = 'run: uv sync --frozen (in the repository)' }
}

# FILE_ATTRIBUTE_OFFLINE 0x1000, RECALL_ON_OPEN 0x40000, RECALL_ON_DATA_ACCESS 0x400000
$placeholders = @(Get-ChildItem -Path (Join-Path $Repo 'node_agent'), (Join-Path $Repo 'shared') -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { ([int]$_.Attributes -band (0x1000 -bor 0x40000 -bor 0x400000)) -ne 0 })
Note 'repo_files_local' ($placeholders.Count -eq 0) @{ online_only_files = $placeholders.Count; fix = 'OneDrive: right-click the repo folder > Always keep on this device' }

$result = [ordered]@{ generated = (Get-Date).ToString('o'); checks = $checks }
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
[IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))  # no BOM
Write-Host "`nReport: $Out"
Write-Host 'Next, in this order (each documented in DEVELOPMENT_STATUS.md, "Acceptance on the original machine"):'
Write-Host '  1. tools\acceptance\m15_service_acceptance.ps1 -AfterReboot   (read-only; needs a reboot since pass 1)'
Write-Host '  2. tools\acceptance\m2_isolation_service_acceptance.ps1       (asks the installed service for its self-test)'
Write-Host '  3. tools\acceptance\m3_exposure_audit.ps1 -AsSystem            (temporary SYSTEM task; service untouched)'
