<#
.SYNOPSIS
  Milestone 1.5 service acceptance (needs an elevated PowerShell). Two passes:
    1)  .\m15_service_acceptance.ps1            install + live checks, then asks you to reboot
    2)  .\m15_service_acceptance.ps1 -AfterReboot   verifies the service came back on its own
  Results: docs\acceptance\data\machines\<label>\m15-service-acceptance.json (merged across
  passes), where <label> is a hash of the host name (evidence_paths.ps1). The top-level
  docs\acceptance\data\m15-service-acceptance.json is the retired build 22000 machine's
  record and is never written.

  What it changes on this PC: installs the UDCSAgent service (Program Files\UDCS\Agent,
  ProgramData\UDCS\agent), one HKLM Run value for the session helper, and runs one
  synthetic CPU validation workload. Remove everything afterwards with
  infrastructure\windows\uninstall-agent.ps1 -RemoveData.

  Evidence protection:
    - pass 1 refuses to run when this machine's report already holds pass-1 evidence (it
      would be overwritten) or when UDCSAgent is already installed (it would be reinstalled).
      -ReplaceEvidence overrides only the first, and keeps a timestamped copy of the
      old report next to it. An installed service must be removed deliberately first.
    - pass 2 records nothing unless it runs on the pass-1 machine after a reboot.
    - -Preflight: read-only, needs no elevation. It prints which file this pass would write
      and whether it would refuse, then exits (0 = would proceed, 2 = would refuse) before
      anything is installed, created or written. -EvidenceRoot exists for its tests.
    - for a read-only readiness check on any PC, use m3_preflight.ps1 instead.
#>
[CmdletBinding()]
param([switch]$AfterReboot, [string]$Staging, [switch]$ReplaceEvidence, [switch]$Preflight, [string]$EvidenceRoot)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'evidence_paths.ps1')
if ($EvidenceRoot -and -not $Preflight) { throw '-EvidenceRoot is only for -Preflight (tests); real evidence always goes to docs\acceptance\data\machines\<label>.' }
if (-not $EvidenceRoot) { $EvidenceRoot = Join-Path $Repo 'docs\acceptance\data' }
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
$Legacy = Get-LegacyEvidencePath $EvidenceRoot
$Label = Get-MachineLabel
$Out = Get-MachineEvidencePath $EvidenceRoot $Label
if ([IO.Path]::GetFullPath($Out) -eq [IO.Path]::GetFullPath($Legacy)) { throw "Refusing: $Out is the retired machine's record." }
$Data = "$env:ProgramData\UDCS\agent"
$Install = "$env:ProgramFiles\UDCS\Agent"
$Service = 'UDCSAgent'

function Read-Report {
    if (Test-Path -LiteralPath $Out) { return Get-Content -LiteralPath $Out -Raw | ConvertFrom-Json }
    return New-Object PSObject
}
function Get-Decision($report) {
    # Every refusal, in the order the passes apply them; the first one wins. $null = proceed.
    if (-not $AfterReboot) {
        if (Get-Service $Service -ErrorAction SilentlyContinue) { return 'UDCSAgent is already installed on this PC; pass 1 would reinstall it' }
        if (($report.reboot_marker -or $report.checks) -and -not $ReplaceEvidence) { return "this machine's report already holds pass-1 evidence; pass 1 would overwrite it" }
        return $null
    }
    if (-not $report.reboot_marker) { return 'no pass-1 record (reboot_marker) for this machine: run pass 1 here first' }
    # GPU names only: Windows Update often installs a GPU driver across exactly this reboot.
    $gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name })
    $recorded = @($report.machine.gpu | ForEach-Object { $_ -replace '\s\([^)]*\)$', '' })
    if (-not $report.machine -or $report.machine.label -ne $Label -or $report.machine.build -ne [Environment]::OSVersion.Version.ToString() -or (Compare-Object $recorded $gpus)) {
        return 'the report was not recorded on this machine (label, build or GPUs differ)'
    }
    if (-not ([datetime]$report.reboot_marker.boot_before -lt (Get-CimInstance Win32_OperatingSystem).LastBootUpTime)) { return 'this PC has not rebooted since pass 1' }
    return $null
}

if ($Preflight) {
    $refusal = Get-Decision (Read-Report)
    $pass = '1'
    if ($AfterReboot) { $pass = '2' }
    [ordered]@{
        kind = 'm15-preflight'; pass = $pass; machine_label = $Label; target = $Out
        retired_record = $Legacy; would_refuse = ($null -ne $refusal); reason = $refusal
    } | ConvertTo-Json | Write-Output
    if ($refusal) { exit 2 }
    exit 0
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell (Run as administrator). This script never elevates itself.'
}

function Save-Report($report) {
    if ([IO.Path]::GetFullPath($Out) -eq [IO.Path]::GetFullPath($Legacy)) { throw "Refusing to write the retired machine's record $Legacy." }
    New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
    [IO.File]::WriteAllText($Out, ($report | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
}
function Set-Field($obj, $name, $value) {
    $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
}
function Get-ServicePid { (Get-CimInstance Win32_Service -Filter "Name='$Service'").ProcessId }
function Get-Status {
    $p = Join-Path $Data 'status\governor.json'
    if (Test-Path $p) { return Get-Content $p -Raw | ConvertFrom-Json }
    return $null
}
function Wait-Until([scriptblock]$cond, [int]$seconds) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $seconds) {
        if (& $cond) { return $sw.Elapsed.TotalSeconds }
        Start-Sleep -Milliseconds 250
    }
    return $null
}
function Check($report, $name, [bool]$pass, $detail) {
    $checks = $report.checks
    if (-not $checks) { $checks = New-Object PSObject; Set-Field $report 'checks' $checks }
    Set-Field $checks $name ([ordered]@{ pass = $pass; detail = $detail })
    $mark = 'FAIL'
    if ($pass) { $mark = 'PASS' }
    Write-Host ("[{0}] {1}: {2}" -f $mark, $name, ($detail | ConvertTo-Json -Compress -Depth 6))
}

$report = Read-Report
$python = Join-Path $Install 'python\python.exe'

if (-not $AfterReboot) {
    $refusal = Get-Decision $report
    if ($refusal) {
        Write-Host "Pass 1: $refusal. Nothing changed ($Out)." -ForegroundColor Yellow
        Write-Host 'After a reboot, run -AfterReboot. -ReplaceEvidence deliberately starts a new run on this machine (the old report is kept); an installed service must be uninstalled deliberately first.'
        exit 2
    }
    if ($report.reboot_marker -or $report.checks) {
        $backup = "$Out.replaced-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item $Out $backup
        Write-Host "Previous evidence kept at $backup" -ForegroundColor Yellow
        $report = New-Object PSObject
    }
    # Edition, build, CPU, RAM and GPUs, with a hashed label; never the host name.
    Set-Field $report 'machine' (Get-MachineFacts)
    Set-Field $report 'started' (Get-Date).ToString('o')

    # -- 1. package + install (local-only: protection must work without a controller) ----
    if (-not $Staging) {
        $Staging = Join-Path $env:TEMP ("udcs-agent-" + (Get-Date -Format 'yyyyMMddHHmmss'))
        Push-Location $Repo
        uv run python tools/package_agent.py $Staging
        Pop-Location
        if ($LASTEXITCODE -ne 0) { throw 'packaging failed' }
    }
    & (Join-Path $Repo 'infrastructure\windows\install-agent.ps1') -Staging $Staging -NoStart
    & $python -I (Join-Path $Install 'run_agent.py') --data-dir $Data workload add --id accept-cpu --kind cpu
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Service $Service
    (Get-Service $Service).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $startSeconds = $sw.Elapsed.TotalSeconds
    $ticking = Wait-Until { $s = Get-Status; $s -and $s.ticks -ge 3 } 60
    Check $report 'service_starts' ($null -ne $ticking) @{ start_s = [math]::Round($startSeconds, 2); first_status_s = $ticking }

    # -- 2. runs in session 0 as LocalSystem, no windows, overhead -----------------------
    $svcPid = Get-ServicePid
    $proc = Get-Process -Id $svcPid
    $cim = Get-CimInstance Win32_Service -Filter "Name='$Service'"
    Check $report 'session0_localsystem' (($proc.SessionId -eq 0) -and ($cim.StartName -eq 'LocalSystem')) @{
        session = $proc.SessionId; account = $cim.StartName; start_mode = $cim.StartMode; delayed = $cim.DelayedAutoStart }
    $windows = Get-Process python, pythonw -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
    Check $report 'no_visible_windows' ($null -eq $windows) @{ windowed_processes = @($windows).Count }
    $cpu0 = $proc.TotalProcessorTime.TotalSeconds; Start-Sleep -Seconds 30; $proc.Refresh()
    $svcCpu = ($proc.TotalProcessorTime.TotalSeconds - $cpu0) / 30 * 100
    Check $report 'service_overhead' (($proc.WorkingSet64 / 1MB -le 80) -and ($svcCpu -le 0.5 * [Environment]::ProcessorCount)) @{
        rss_mib = [math]::Round($proc.WorkingSet64 / 1MB, 1); private_mib = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
        cpu_percent_one_core = [math]::Round($svcCpu, 3); note = 'service process only; workload jobs excluded' }

    # -- 3. per-session helper reports through the hardened pipe ------------------------
    Start-Process -FilePath (Join-Path $Install 'python\pythonw.exe') -ArgumentList @('-I', "`"$(Join-Path $Install 'run_helper.py')`"")
    Start-Sleep -Seconds 8
    $s = Get-Status
    Check $report 'helper_and_presence' ($s.interactive -in @('active', 'idle')) @{ interactive = $s.interactive; level = $s.protection.level; reasons = $s.protection.reasons }

    # -- 4. managed workload runs under protection --------------------------------------
    $wl = Wait-Until { $st = Get-Status; $st.workloads.'accept-cpu' -in @('running', 'throttled') } 60
    $before = (Get-Content (Join-Path $Data 'workloads\accept-cpu\status.json') -Raw | ConvertFrom-Json).units_done
    Check $report 'workload_managed' ($null -ne $wl) @{ state = (Get-Status).workloads.'accept-cpu'; units_done = $before; level = (Get-Status).protection.level }

    # -- 5. crash recovery + workload state recovery -------------------------------------
    Start-Sleep -Seconds 5
    $oldPid = Get-ServicePid
    Stop-Process -Id $oldPid -Force
    $back = Wait-Until { $n = Get-ServicePid; ($n -ne 0) -and ($n -ne $oldPid) -and ((Get-Service $Service).Status -eq 'Running') } 60
    $resumed = Wait-Until {
        $w = Get-Content (Join-Path $Data 'workloads\accept-cpu\status.json') -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        $w -and ($w.resumed_from -gt 0) } 90
    $w = Get-Content (Join-Path $Data 'workloads\accept-cpu\status.json') -Raw | ConvertFrom-Json
    Check $report 'crash_recovery' (($null -ne $back) -and ($null -ne $resumed)) @{
        restarted_after_s = $back; workload_resumed_after_s = $resumed; resumed_from_units = $w.resumed_from }

    # -- 6. GPU execution-context experiment (E1) inside the real service -----------------
    New-Item -ItemType Directory -Force -Path (Join-Path $Data 'diagnostics') | Out-Null
    Remove-Item (Join-Path $Data 'diagnostics\gpu-result.json') -ErrorAction SilentlyContinue
    New-Item -ItemType File -Force -Path (Join-Path $Data 'diagnostics\gpu-request') | Out-Null
    $e1 = Wait-Until { Test-Path (Join-Path $Data 'diagnostics\gpu-result.json') } 240
    if ($e1) {
        $matrix = Get-Content (Join-Path $Data 'diagnostics\gpu-result.json') -Raw | ConvertFrom-Json
        Set-Field $report 'e1_gpu_matrix' $matrix
        Write-Host ($matrix.arrangements | ConvertTo-Json -Depth 4)
    }
    Check $report 'e1_completed' ($null -ne $e1) @{ seconds = $e1 }

    # -- 7. graceful stop ----------------------------------------------------------------
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Stop-Service $Service
    (Get-Service $Service).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $stopSeconds = $sw.Elapsed.TotalSeconds
    $leftovers = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -like '*udcs_agent.workloads.synthetic*' }
    $reg = Get-Content (Join-Path $Data 'workloads\registry.json') -Raw | ConvertFrom-Json
    Check $report 'graceful_stop' (($stopSeconds -le 10) -and ($null -eq $leftovers)) @{
        stop_s = [math]::Round($stopSeconds, 2); workload_processes_left = @($leftovers).Count
        registry_state = ($reg.workloads | ForEach-Object { $_.state }) }

    # -- 8. prepare the reboot check -----------------------------------------------------
    Start-Service $Service
    Set-Field $report 'reboot_marker' ([ordered]@{ boot_before = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o') })
    Save-Report $report
    Write-Host "`nPass 1 done. Reboot this PC, sign in, then run:  .\m15_service_acceptance.ps1 -AfterReboot"
    exit 0
}

# -- pass 2: after reboot -------------------------------------------------------------------
# Read-only: pass 2 installs, stops or reconfigures nothing. It records results only when
# it is on the pass-1 machine and that machine has rebooted since, so running it early
# (or elsewhere) can never overwrite the report with a misleading FAIL.
$refusal = Get-Decision $report
if ($refusal) {
    Write-Host "Pass 2: $refusal. Nothing recorded ($Out)." -ForegroundColor Yellow
    exit 2
}
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$rebooted = $true  # Get-Decision refused unless boot_before < this boot
$svc = Get-Service $Service
$svcPid = Get-ServicePid
$started = (Get-Process -Id $svcPid).StartTime
$fresh = Wait-Until { $s = Get-Status; $s -and ([DateTimeOffset]::FromUnixTimeSeconds([int64]$s.wall).LocalDateTime -gt $boot) } 120
Check $report 'starts_after_reboot' ($rebooted -and ($svc.Status -eq 'Running') -and ($started -gt $boot) -and ($null -ne $fresh)) @{
    rebooted = $rebooted; status = "$($svc.Status)"; service_started_after_boot_s = [math]::Round(($started - $boot).TotalSeconds, 1)
    governor_status_fresh = ($null -ne $fresh) }
$helper = Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" | Where-Object { $_.CommandLine -like '*run_helper.py*' }
Check $report 'helper_started_at_logon' ($null -ne $helper) @{ helper_sessions = @($helper | ForEach-Object { (Get-Process -Id $_.ProcessId).SessionId }) }
Set-Field $report 'finished' (Get-Date).ToString('o')
Save-Report $report
Write-Host "`nDone. Report: $Out"
Write-Host "To remove everything: infrastructure\windows\uninstall-agent.ps1 -RemoveData"
