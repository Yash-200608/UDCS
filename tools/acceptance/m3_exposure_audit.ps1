<#
.SYNOPSIS
  AppContainer exposure audit of THIS machine's Windows image (ADR 0001 gate 2,
  ADR 0003): which filesystem, registry, process, named-pipe, named-object, network,
  service and window-station resources a UDCS package sandbox can still reach.

    .\m3_exposure_audit.ps1                     DIAGNOSTIC: as the current user; never evidence
    .\m3_exposure_audit.ps1 -AsSystem -Staging <dir>
                                                EVIDENCE for this image: as LocalSystem (session 0)

  -AsSystem: two steps, so that nothing writable by a normal user ever runs elevated or as SYSTEM.
    1. From a NORMAL (not elevated) PowerShell, build a self-contained agent package:
         uv run python tools/package_agent.py $env:TEMP\udcs-audit-stage
    2. From an ELEVATED PowerShell:
         tools\acceptance\m3_exposure_audit.ps1 -AsSystem -Staging $env:TEMP\udcs-audit-stage
  The script never elevates by itself. It does not run the repository's .venv or any
  code from the repository or your user profile while elevated. It:
    - creates a new folder %ProgramData%\UDCS-ExposureAudit-<random id>. The folder is
      owned by Administrators, only SYSTEM and Administrators can access it, and it does
      not inherit permissions. The script refuses to continue if the folder already
      existed, if its access rules are not exactly those, or if any part of its path is
      a reparse point;
    - copies the package into it (data only, skipping junctions and links) and refuses
      if the copy contains any reparse point;
    - hashes every file of the copy (SHA-256 manifest), before and after the run;
    - runs only that copy, as LocalSystem, through a one-off scheduled task
      UDCS-ExposureAudit-<id>. The task's program, arguments and working directory
      are inside the protected folder;
    - treats the result as evidence only if all of these hold: the audit reports
      LocalSystem in session 0, the task ran as NT AUTHORITY\SYSTEM, it finished with
      the audit's own exit code (0 or 1), and the manifest did not change;
    - copies the summary and the full report out (refusing to write through reparse
      points or over existing files), then deletes the protected folder with rd /s /q
      (which never follows junctions).
  The installed UDCSAgent service is not stopped, started, reconfigured or upgraded.
  Remaining trust assumption: the copy is only as trustworthy as the staging folder at
  the moment it is copied. Build it yourself, immediately before the run.

  Every result is labelled with the machine (a hash of its name, never the name), its
  Windows image and the execution identity. Only a verified LocalSystem result is
  written to docs\acceptance\data; everything else goes to %LOCALAPPDATA%\UDCS\diagnostics.

  What -AsSystem changes on this PC, and how it is undone:
    - the protected folder: deleted at the end, including on failure and Ctrl+C. A
      leftover from a killed console is deleted by the next run (stale sweep);
    - one AppContainer profile in the SYSTEM profile, unique to this run: deleted by the
      audit. If the audit process is killed, the profile is left behind and its name is
      printed (only a LocalSystem process can delete it);
    - the scheduled task. It is removed in a finally block (success, failure, timeout,
      Ctrl+C). Any stale UDCS-ExposureAudit-* task from an interrupted run is removed
      first. If this console is force-killed, the running audit is stopped after 30
      minutes (ExecutionTimeLimit). The trigger lies in the past and never fires, so the
      task never runs again by itself. The task also expires 45 minutes after creation,
      and Task Scheduler then deletes it (DeleteExpiredTaskAfter). That self-deletion has
      not yet been verified on a real machine.
  Without -AsSystem, it changes only per-user state: an AppContainer profile (deleted),
  %LOCALAPPDATA%\UDCS\exposure-audit (kept) and an ACE granting the UDCS runtime
  capability read/execute on the Python installation the repository uses (kept).
  The probe opens each named pipe read-only and closes it at once.
#>
[CmdletBinding()]
param([switch]$AsSystem, [string]$Staging, [int]$TimeoutMinutes = 25)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$TaskPrefix = 'UDCS-ExposureAudit-'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Diagnostics = "$env:LOCALAPPDATA\UDCS\diagnostics"
$UserScratch = "$env:LOCALAPPDATA\UDCS\exposure-audit"
$SystemSid = 'S-1-5-18'
$AdminsSid = 'S-1-5-32-544'

function Test-NoReparse([string]$Path) {
    # True when neither $Path nor any existing parent is a reparse point (junction, link, mount).
    $p = [IO.Path]::GetFullPath($Path)
    while ($p) {
        if (Test-Path -LiteralPath $p) {
            if ([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) { return $false }
        }
        $parent = [IO.Path]::GetDirectoryName($p)
        if (-not $parent -or $parent -eq $p) { break }
        $p = $parent
    }
    return $true
}
function Copy-Safe([string]$Source, [string]$Dest) {
    # Elevated writes into user-writable places: no reparse point on the way, never over an
    # existing file (CreateNew also refuses a planted hard link or file symlink).
    $dir = Split-Path $Dest
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    if (-not (Test-NoReparse $dir)) { throw "Refusing to write through a reparse point: $dir" }
    $bytes = [IO.File]::ReadAllBytes($Source)
    $fs = New-Object IO.FileStream($Dest, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
}
function Remove-TreeNoFollow([string]$Path) {
    # Windows PowerShell 5.1's Remove-Item -Recurse can follow junctions; rd /s /q never does.
    for ($i = 0; $i -lt 5 -and (Test-Path -LiteralPath $Path); $i++) {
        & cmd.exe /d /c "rd /s /q `"$Path`"" 2>$null
        if (Test-Path -LiteralPath $Path) { Start-Sleep -Seconds 2 }
    }
    return -not (Test-Path -LiteralPath $Path)
}
function New-ProtectedDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw "$Path already exists; refusing to reuse it." }
    if (-not (Test-NoReparse (Split-Path $Path))) { throw "A parent of $Path is a reparse point." }
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    $sec.SetOwner([Security.Principal.SecurityIdentifier]$AdminsSid)
    foreach ($sid in $SystemSid, $AdminsSid) {
        $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    [IO.Directory]::CreateDirectory($Path, $sec) | Out-Null  # created with this DACL, no window
    $acl = Get-Acl -LiteralPath $Path
    $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $ok = $acl.AreAccessRulesProtected -and ($owner -eq $AdminsSid) -and
        ($null -eq (Compare-Object $sids @($AdminsSid, $SystemSid))) -and
        (-not ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint)) -and
        (@(Get-ChildItem -LiteralPath $Path -Force).Count -eq 0)
    if (-not $ok) { throw "$Path does not have the expected owner and access rules; refusing to continue." }
}
function Get-Manifest([string]$Path) {
    $base = (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\') + '\'
    $lines = Get-ChildItem -LiteralPath $Path -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($base.Length)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    $digest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join "`n")))
    return [ordered]@{ sha256 = ([BitConverter]::ToString($digest) -replace '-', '').ToLower(); files = @($lines).Count }
}
function Get-RepoHead {
    # Read .git files directly: running git elevated in a user-writable repository could
    # execute its configuration (for example core.fsmonitor).
    try {
        $head = (Get-Content -LiteralPath (Join-Path $Repo '.git\HEAD') -Raw).Trim()
        if ($head -notlike 'ref: *') { return @{ commit = $head } }
        $ref = $head.Substring(5)
        $loose = Join-Path $Repo ('.git\' + $ref.Replace('/', '\'))
        $commit = if (Test-Path -LiteralPath $loose) { (Get-Content -LiteralPath $loose -Raw).Trim() } else { $null }
        return @{ ref = $ref; commit = $commit; note = 'working-tree state not checked' }
    } catch { return @{ error = "$_" } }
}

$provenance = $null
if ($AsSystem) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '-AsSystem needs an already elevated PowerShell. This script never elevates itself.'
    }
    if (-not $Staging) {
        throw ('-AsSystem needs -Staging. From a NORMAL PowerShell first run:' +
            "`n  uv run python tools/package_agent.py `$env:TEMP\udcs-audit-stage")
    }
    $Staging = [IO.Path]::GetFullPath($Staging)
    foreach ($need in 'python\python.exe', 'site\udcs_agent\cli.py', 'site\udcs_shared\exposure.py') {
        if (-not (Test-Path -LiteralPath (Join-Path $Staging $need))) { throw "$Staging is not a package_agent.py staging folder (missing $need)." }
    }

    foreach ($stale in @(Get-ScheduledTask -TaskName "$TaskPrefix*" -ErrorAction SilentlyContinue)) {
        Write-Host "Removing a stale task from an interrupted run: $($stale.TaskName)" -ForegroundColor Yellow
        if ($stale.State -eq 'Running') { Stop-ScheduledTask -TaskName $stale.TaskName }
        Unregister-ScheduledTask -TaskName $stale.TaskName -Confirm:$false
    }
    foreach ($old in @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter "$TaskPrefix*" -ErrorAction SilentlyContinue)) {
        Write-Host "Removing a stale audit folder from an interrupted run: $($old.FullName)" -ForegroundColor Yellow
        if (-not (Remove-TreeNoFollow $old.FullName)) { throw "Could not remove $($old.FullName)." }
    }

    $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $name = "$TaskPrefix$id"
    $Root = Join-Path $env:ProgramData $name
    $App = Join-Path $Root 'app'
    $Work = Join-Path $Root 'data'
    $Report = Join-Path $Root "exposure-report-$Stamp.json"
    $SummaryTmp = Join-Path $Root "exposure-summary-$Stamp.json"
    $Log = Join-Path $Root "exposure-audit-$Stamp.log"
    $Runner = Join-Path $App 'run_audit.py'
    $registered = $false
    try {
        New-ProtectedDirectory $Root
        Write-Host "Protected folder: $Root (SYSTEM and Administrators only)"
        # /COPY:D copies data only, so the copy inherits the protected DACL; /XJ skips junctions.
        & robocopy.exe $Staging $App /E /XJ /COPY:D /DCOPY:D /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Copying the staging folder failed (robocopy exit $LASTEXITCODE)." }
        $links = @(Get-ChildItem -LiteralPath $App -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
        if ($links.Count) { throw "The copy contains $($links.Count) reparse point(s), for example $($links[0].FullName)." }
        # The runner is written by this script: constant code, paths inside the protected folder.
        $runnerBody = @"
import os, site, sys
ROOT = os.path.dirname(os.path.abspath(__file__))
site.addsitedir(os.path.join(ROOT, 'site'))
log = open(r'$Log', 'w', encoding='utf-8', buffering=1)
sys.stdout = sys.stderr = log
from udcs_agent.cli import main
sys.exit(main(['--plain-logs', 'audit-exposure', '--out', r'$Report', '--summary-out', r'$SummaryTmp', '--data-dir', r'$Work']))
"@
        [IO.File]::WriteAllText($Runner, $runnerBody, (New-Object Text.UTF8Encoding $false))
        $before = Get-Manifest $App
        Write-Host ("Snapshot: {0} files, manifest sha256 {1}" -f $before.files, $before.sha256)

        $python = Join-Path $App 'python\python.exe'
        # -I: no environment variables, user site or script directory on sys.path;
        # -B: no .pyc writes, so the snapshot stays byte-identical (checked by the manifest).
        $action = New-ScheduledTaskAction -Execute $python -Argument "-I -B `"$Runner`"" -WorkingDirectory $Root
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(-5)  # in the past: never fires
        $trigger.EndBoundary = (Get-Date).AddMinutes(45).ToString('s')
        $settings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 0) `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $settings.StartWhenAvailable = $false
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $name
        Write-Host "Running the audit as LocalSystem (task $name), up to $TimeoutMinutes min..."
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        do {
            Start-Sleep -Seconds 3
            $state = (Get-ScheduledTask -TaskName $name).State
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
        if ($state -eq 'Running') { throw 'The audit did not finish in time.' }

        $task = Get-ScheduledTask -TaskName $name
        $taskResult = (Get-ScheduledTaskInfo -TaskName $name).LastTaskResult
        $after = Get-Manifest $App
        if (-not (Test-Path -LiteralPath $SummaryTmp)) {
            Write-Host (Get-Content -LiteralPath $Log -Raw -ErrorAction SilentlyContinue)
            throw "No result was produced (task result $taskResult); see the log above."
        }
        $provenance = [ordered]@{
            task_user = $task.Principal.UserId
            task_result = $taskResult
            manifest_before = $before
            manifest_after = $after
            manifest_unchanged = ($before.sha256 -eq $after.sha256)
            staging = $Staging
            repository = Get-RepoHead
        }
        $Report = Join-Path $UserScratch "exposure-report-$Stamp.json"
        Copy-Safe (Join-Path $Root "exposure-report-$Stamp.json") $Report
        $copiedSummary = Join-Path $UserScratch "exposure-summary-$Stamp.json"
        Copy-Safe $SummaryTmp $copiedSummary
        $SummaryTmp = $copiedSummary
    } finally {
        if ($registered) {
            if ((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue).State -eq 'Running') {
                Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
            if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
                Write-Host "WARNING: could not remove task $name; it expires 45 minutes after creation." -ForegroundColor Yellow
            }
        }
        if ((Test-Path -LiteralPath $Root) -and -not (Remove-TreeNoFollow $Root)) {
            Write-Host "WARNING: could not remove $Root; the next -AsSystem run removes it." -ForegroundColor Yellow
        }
    }
} else {
    $Venv = Join-Path $Repo '.venv\Scripts\python.exe'
    if (-not (Test-Path $Venv)) { throw "No repository environment ($Venv). Run: uv sync --frozen" }
    New-Item -ItemType Directory -Force -Path $UserScratch | Out-Null
    $Report = Join-Path $UserScratch "exposure-report-$Stamp.json"
    $SummaryTmp = Join-Path $UserScratch "exposure-summary-$Stamp.json"
    & $Venv -I -m udcs_agent.cli --plain-logs audit-exposure --out $Report --summary-out $SummaryTmp --data-dir $UserScratch
    if (-not (Test-Path $SummaryTmp)) { throw 'No result was produced; see the output above.' }
}

$wrapped = Get-Content -LiteralPath $SummaryTmp -Raw | ConvertFrom-Json
$checks = [ordered]@{
    reported_localsystem_session0 = ([bool]$wrapped.identity.is_local_system -and ($wrapped.identity.session_id -eq 0))
    task_ran_as_system = ($AsSystem -and $provenance -and ($provenance.task_user -match 'SYSTEM$'))
    audit_exit_code = ($AsSystem -and $provenance -and ($provenance.task_result -in 0, 1))
    snapshot_unchanged = ($AsSystem -and $provenance -and $provenance.manifest_unchanged)
}
$isEvidence = [bool]$wrapped.evidence -and (@($checks.Values | Where-Object { -not $_ }).Count -eq 0)
if (-not $isEvidence -and $wrapped.evidence) {
    $wrapped.evidence = $false
    $wrapped.note = 'DIAGNOSTIC ONLY: the LocalSystem cross-checks did not all pass'
}
$wrapped | Add-Member -NotePropertyName 'verification' -NotePropertyValue $checks -Force
if ($provenance) { $wrapped | Add-Member -NotePropertyName 'provenance' -NotePropertyValue $provenance -Force }
$label = $wrapped.machine.label
$dest = if ($isEvidence) {
    Join-Path $Repo "docs\acceptance\data\m3-exposure-audit-$label-$Stamp.json"
} else {
    Join-Path $Diagnostics "exposure-audit-$($wrapped.identity.context)-$label-$Stamp.json"
}
$final = Join-Path ([IO.Path]::GetTempPath()) "udcs-exposure-summary-$Stamp-$([guid]::NewGuid().ToString('N')).json"
[IO.File]::WriteAllText($final, ($wrapped | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding $false))
try { Copy-Safe $final $dest } finally { Remove-Item -LiteralPath $final -Force -ErrorAction SilentlyContinue }

$r = $wrapped.result
Write-Host ("Machine label: {0}   image: {1}   build {2}.{3}   edition: {4}" -f $label, $wrapped.machine.image, $wrapped.machine.build, $wrapped.machine.patch, $wrapped.machine.edition)
Write-Host ("Identity: {0} (session {1}, elevated: {2})" -f $wrapped.identity.context, $wrapped.identity.session_id, $wrapped.identity.elevated)
if ($AsSystem) { Write-Host ("Cross-checks: {0}" -f ($checks | ConvertTo-Json -Compress)) }
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
