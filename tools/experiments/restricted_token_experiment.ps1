<#
.SYNOPSIS
  Decision D-4, Option B feasibility experiment (restricted SYSTEM token + AppContainer).
  DIAGNOSTIC ONLY: the result is never acceptance evidence and goes to
  %LOCALAPPDATA%\UDCS\diagnostics.

    .\restricted_token_experiment.ps1 -Staging <dir>             as the current user
    .\restricted_token_experiment.ps1 -Staging <dir> -AsSystem   as LocalSystem (elevated)

  Build <dir> first, from a NORMAL PowerShell:
    uv run python tools/package_agent.py $env:TEMP\udcs-exp-stage

  Both modes run a snapshot copy of the package (plus restricted_token_experiment.py),
  never the repository's .venv. Grants made by the experiment land on the snapshot, which
  is deleted afterwards.

  -AsSystem reuses the hardened machinery of tools\acceptance\m3_exposure_audit.ps1 (its
  helper functions are loaded from that file, not copied):
    - a new %ProgramData%\UDCS-TokenExperiment-<id> folder, owned by Administrators and
      accessible only to SYSTEM and Administrators, verified, with no reparse points;
    - a SHA-256 manifest of the snapshot, before and after the run;
    - a one-off scheduled task as NT AUTHORITY\SYSTEM with ProcessTokenSidType
      Unrestricted, so the token carries an NT TASK\ SID: the closest non-invasive
      analogue of the service SID the installed agent gets from `sc sidtype unrestricted`;
    - cleanup in finally: the task is stopped and unregistered and the folder removed
      with rd /s /q. A stale task or folder from an interrupted run is removed first.
      The task also expires 45 minutes after creation (DeleteExpiredTaskAfter) and is
      stopped after 40 minutes (ExecutionTimeLimit).
  What it changes on this PC: the folder and task above (removed). It also creates and
  deletes AppContainer profiles in the running account's profile, and creates a private
  window station and desktop that exist only while the experiment process runs. Nothing
  system-wide: no ACL outside the snapshot, no service, no acceptance evidence.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Staging, [switch]$AsSystem, [switch]$AsService, [int]$TimeoutMinutes = 35,
    # Comma-separated variant labels; empty runs all (V0, V1, V2, V3, V4).
    [ValidatePattern('^[A-Za-z0-9_,]*$')][string]$Variants = '')
# -AsService: the same experiment inside a TEMPORARY Windows service, hosted exactly like
# the agent (python.exe -I <script>, pywin32 ServiceFramework, LocalSystem,
# `sc sidtype unrestricted`), so its token is the real service-token shape, with its own
# NT SERVICE\UDCSTokenExperiment SID as the production analogue of NT SERVICE\UDCSAgent.
# Cleanup: the service deletes itself when the experiment ends (DeleteService from inside,
# effective once it stops); the finally block stops it (killing a hung process), deletes it
# and removes the folder; it is start=demand with no restart actions, so it never starts by
# itself; a leftover from a killed console is removed by the next run.
if ($AsService) { $AsSystem = $true }
$ServiceName = 'UDCSTokenExperiment'
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$m3 = Join-Path $Repo 'tools\acceptance\m3_exposure_audit.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($m3, [ref]$null, [ref]$null)
foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($f.Extent.Text))
}
$SystemSid = 'S-1-5-18'; $AdminsSid = 'S-1-5-32-544'  # used by New-ProtectedDirectory
$Prefix = 'UDCS-TokenExperiment-'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Diagnostics = "$env:LOCALAPPDATA\UDCS\diagnostics"
$Experiment = Join-Path $PSScriptRoot 'restricted_token_experiment.py'
$Staging = [IO.Path]::GetFullPath($Staging)
foreach ($need in 'python\python.exe', 'site\udcs_agent\cli.py') {
    if (-not (Test-Path -LiteralPath (Join-Path $Staging $need))) { throw "$Staging is not a package_agent.py staging folder (missing $need)." }
}
$mode = if ($AsService) { 'service' } elseif ($AsSystem) { 'system' } else { 'user' }
$dest = Join-Path $Diagnostics ("restricted-token-experiment-{0}-{1}.json" -f $mode, $Stamp)

function Get-ManifestLines([string]$Path) {
    # Per-file hashes, to name what changed (the hash-only manifest changed once, cause unknown).
    $base = (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\') + '\'
    $map = @{}
    Get-ChildItem -LiteralPath $Path -Recurse -File -Force | ForEach-Object {
        $map[$_.FullName.Substring($base.Length)] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
    return $map
}
function Show-ManifestDiff($Before, $After) {
    $changes = @()
    foreach ($k in $After.Keys) {
        if (-not $Before.ContainsKey($k)) { $changes += "added    $k" }
        elseif ($Before[$k] -ne $After[$k]) { $changes += "changed  $k" }
    }
    foreach ($k in $Before.Keys) { if (-not $After.ContainsKey($k)) { $changes += "removed  $k" } }
    if ($changes.Count) {
        Write-Host "Snapshot changes ($($changes.Count)):" -ForegroundColor Yellow
        $changes | Sort-Object | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" }
    } else { Write-Host 'Snapshot unchanged (per-file).' }
}
function Remove-ExperimentService {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc) { return $true }
    if ($svc.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-Service $ServiceName -ErrorAction SilentlyContinue).Status -ne 'Stopped' -and $sw.Elapsed.TotalSeconds -lt 20) { Start-Sleep 1 }
        $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.ProcessId) { Stop-Process -Id $svc.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    & sc.exe delete $ServiceName | Out-Null
    for ($i = 0; $i -lt 15 -and (Get-Service $ServiceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep 1 }
    return -not (Get-Service $ServiceName -ErrorAction SilentlyContinue)
}

function Copy-Snapshot([string]$App) {
    & robocopy.exe $Staging $App /E /XJ /COPY:D /DCOPY:D /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copying the staging folder failed (robocopy exit $LASTEXITCODE)." }
    [IO.File]::WriteAllBytes((Join-Path $App 'restricted_token_experiment.py'), [IO.File]::ReadAllBytes($Experiment))
    $links = @(Get-ChildItem -LiteralPath $App -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
    if ($links.Count) { throw "The copy contains reparse points, for example $($links[0].FullName)." }
}

if (-not $AsSystem) {
    $Root = Join-Path $env:TEMP "$Prefix$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    New-Item -ItemType Directory -Path $Root | Out-Null
    try {
        $App = Join-Path $Root 'app'
        Copy-Snapshot $App
        $out = Join-Path $Root 'result.json'
        $pyArgs = @('-I', '-B', (Join-Path $App 'restricted_token_experiment.py'), '--out', $out, '--work', (Join-Path $Root 'work'))
        if ($Variants) { $pyArgs += @('--variants', $Variants) }  # PS 5.1 drops empty native arguments
        & (Join-Path $App 'python\python.exe') @pyArgs
        if (-not (Test-Path -LiteralPath $out)) { throw "No result (exit $LASTEXITCODE)." }
        Copy-Safe $out $dest
    } finally {
        if (-not (Remove-TreeNoFollow $Root)) { Write-Host "WARNING: could not remove $Root" -ForegroundColor Yellow }
    }
    Write-Host "DIAGNOSTIC ONLY (current user): $dest" -ForegroundColor Yellow
    exit 0
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '-AsSystem needs an already elevated PowerShell. This script never elevates itself.'
}
foreach ($stale in @(Get-ScheduledTask -TaskName "$Prefix*" -ErrorAction SilentlyContinue)) {
    Write-Host "Removing a stale task: $($stale.TaskName)" -ForegroundColor Yellow
    if ($stale.State -eq 'Running') { Stop-ScheduledTask -TaskName $stale.TaskName }
    Unregister-ScheduledTask -TaskName $stale.TaskName -Confirm:$false
}
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing a stale service from an interrupted run: $ServiceName" -ForegroundColor Yellow
    if (-not (Remove-ExperimentService)) { throw "Could not remove the stale service $ServiceName." }
}
foreach ($old in @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter "$Prefix*" -ErrorAction SilentlyContinue)) {
    Write-Host "Removing a stale folder: $($old.FullName)" -ForegroundColor Yellow
    if (-not (Remove-TreeNoFollow $old.FullName)) { throw "Could not remove $($old.FullName)." }
}

if ($AsService) {
    $Root = Join-Path $env:ProgramData "$Prefix$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    $App = Join-Path $Root 'app'
    $out = Join-Path $Root 'result.json'
    $log = Join-Path $Root 'experiment.log'
    $created = $false
    try {
        New-ProtectedDirectory $Root
        Write-Host "Protected folder: $Root (SYSTEM and Administrators only)"
        Copy-Snapshot $App
        $runner = Join-Path $App 'run_service_experiment.py'
        $body = @"
import os, site, sys
ROOT = os.path.dirname(os.path.abspath(__file__))
site.addsitedir(os.path.join(ROOT, 'site'))
import runpy, traceback
import servicemanager, win32service, win32serviceutil

NAME = '$ServiceName'
EXPERIMENT = r'$App\restricted_token_experiment.py'


class ExperimentService(win32serviceutil.ServiceFramework):
    _svc_name_ = NAME
    _svc_display_name_ = 'UDCS token experiment (temporary, deletes itself)'

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

    def SvcDoRun(self):
        log = open(r'$log', 'w', encoding='utf-8', buffering=1)
        sys.stdout = sys.stderr = log
        try:
            sys.argv = [EXPERIMENT, '--out', r'$out', '--work', r'$Root\work', '--variants', '$Variants']
            runpy.run_path(EXPERIMENT, run_name='__main__')
        except SystemExit:
            pass
        except BaseException:
            traceback.print_exc()
        finally:
            try:  # deterministic cleanup even if the console that started us is gone
                scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
                handle = win32service.OpenService(scm, NAME, 0x00010000)  # DELETE
                win32service.DeleteService(handle)
                print('service deletion requested (effective when stopped)')
            except Exception:
                traceback.print_exc()


servicemanager.Initialize()
servicemanager.PrepareToHostSingle(ExperimentService)
servicemanager.StartServiceCtrlDispatcher()
"@
        [IO.File]::WriteAllText($runner, $body, (New-Object Text.UTF8Encoding $false))
        $beforeMap = Get-ManifestLines $App
        $before = Get-Manifest $App
        Write-Host ("Snapshot: {0} files, manifest sha256 {1}" -f $before.files, $before.sha256)
        $python = Join-Path $App 'python\python.exe'
        New-Service -Name $ServiceName -BinaryPathName "`"$python`" -I -B `"$runner`"" `
            -DisplayName 'UDCS token experiment (temporary)' -StartupType Manual | Out-Null
        $created = $true
        & sc.exe sidtype $ServiceName unrestricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc sidtype failed ($LASTEXITCODE)" }
        & sc.exe failure $ServiceName reset= 0 actions= "" | Out-Null  # never restart
        Start-Service $ServiceName
        Write-Host "Running the experiment inside the temporary LocalSystem service $ServiceName, up to $TimeoutMinutes min..."
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        do { Start-Sleep -Seconds 5 } while (-not (Test-Path -LiteralPath $out) -and (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status -eq 'Running' -and (Get-Date) -lt $deadline)
        Start-Sleep -Seconds 3  # let the service finish writing and request its deletion
        Show-ManifestDiff $beforeMap (Get-ManifestLines $App)
        if (-not (Test-Path -LiteralPath $out)) {
            Write-Host (Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue)
            throw 'No result was produced; see the log above.'
        }
        Write-Host ((Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue) -split "`n" | Select-String 'deletion requested')
        Copy-Safe $out $dest
    } finally {
        if ($created -or (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
            if (Remove-ExperimentService) { Write-Host "Service $ServiceName removed." }
            else { Write-Host "WARNING: could not remove service $ServiceName; the next run removes it, or: sc.exe delete $ServiceName" -ForegroundColor Yellow }
        }
        if ((Test-Path -LiteralPath $Root) -and -not (Remove-TreeNoFollow $Root)) {
            Write-Host "WARNING: could not remove $Root; the next run removes it." -ForegroundColor Yellow
        }
    }
    Write-Host "DIAGNOSTIC ONLY (temporary LocalSystem service, not acceptance evidence): $dest" -ForegroundColor Yellow
    exit 0
}
$name = "$Prefix$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$Root = Join-Path $env:ProgramData $name
$App = Join-Path $Root 'app'
$out = Join-Path $Root 'result.json'
$log = Join-Path $Root 'experiment.log'
$registered = $false
try {
    New-ProtectedDirectory $Root
    Write-Host "Protected folder: $Root (SYSTEM and Administrators only)"
    Copy-Snapshot $App
    $runner = Join-Path $App 'run_experiment.py'
    $body = @"
import runpy, sys
log = open(r'$log', 'w', encoding='utf-8', buffering=1)
sys.stdout = sys.stderr = log
sys.argv = [r'$App\restricted_token_experiment.py', '--out', r'$out', '--work', r'$Root\work', '--variants', '$Variants']
runpy.run_path(r'$App\restricted_token_experiment.py', run_name='__main__')
"@
    [IO.File]::WriteAllText($runner, $body, (New-Object Text.UTF8Encoding $false))
    $before = Get-Manifest $App
    Write-Host ("Snapshot: {0} files, manifest sha256 {1}" -f $before.files, $before.sha256)
    $action = New-ScheduledTaskAction -Execute (Join-Path $App 'python\python.exe') -Argument "-I -B `"$runner`"" -WorkingDirectory $Root
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(-5)
    $trigger.EndBoundary = (Get-Date).AddMinutes(45).ToString('s')
    $settings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 0) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 40) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $settings.StartWhenAvailable = $false
    # ProcessTokenSidType Unrestricted (a task SID) was refused for a SYSTEM task, also with
    # Win8 compatibility (measured: 0x80041316). The experiment falls back to a labelled,
    # experiment-only grant SID instead (see pick_grant_sid).
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal | Out-Null
    $registered = $true
    Start-ScheduledTask -TaskName $name
    Write-Host "Running the experiment as LocalSystem (task $name), up to $TimeoutMinutes min..."
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do { Start-Sleep -Seconds 5; $state = (Get-ScheduledTask -TaskName $name).State } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    if ($state -eq 'Running') { throw 'The experiment did not finish in time.' }
    $after = Get-Manifest $App
    Write-Host ("Task result: {0}; snapshot unchanged: {1}" -f (Get-ScheduledTaskInfo -TaskName $name).LastTaskResult, ($before.sha256 -eq $after.sha256))
    if (-not (Test-Path -LiteralPath $out)) {
        Write-Host (Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue)
        throw 'No result was produced; see the log above.'
    }
    Copy-Safe $out $dest
} finally {
    if ($registered) {
        if ((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue).State -eq 'Running') {
            Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3
        }
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ((Test-Path -LiteralPath $Root) -and -not (Remove-TreeNoFollow $Root)) {
        Write-Host "WARNING: could not remove $Root; the next run removes it." -ForegroundColor Yellow
    }
}
Write-Host "DIAGNOSTIC ONLY (LocalSystem experiment, not acceptance evidence): $dest" -ForegroundColor Yellow
