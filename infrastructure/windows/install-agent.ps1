<#
.SYNOPSIS
  Install (or upgrade) the UDCS Node Agent as a Windows service. Run elevated.

.DESCRIPTION
  - Copies a staged agent (tools/package_agent.py) to "C:\Program Files\UDCS\Agent"
    (admin-writable only; the service never runs code from a user-writable folder).
  - Creates C:\ProgramData\UDCS\agent with an ACL of SYSTEM + Administrators only
    (node credential, policy, workload state, logs).
  - Optionally enrolls the machine. The LAB ENROLLMENT KEY is read from the environment
    variable UDCS_ENROLLMENT_TOKEN and is never written to disk; only the node's own
    credential (DPAPI-encrypted) is stored.
  - Registers the service: delayed auto-start, LocalSystem, restart on failure
    (5 s / 15 s / 60 s), failure flag on, reset after 1 day.
  - Registers the per-session helper (pythonw.exe: no window) under HKLM Run.

.EXAMPLE
  $env:UDCS_ENROLLMENT_TOKEN = "<lab key from IT>"
  .\install-agent.ps1 -Staging C:\build\udcs-agent -ControllerUrl https://udcs.campus.edu:8443 -CaBundle C:\build\campus-ca.pem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Staging,
    [string]$ControllerUrl,
    [string]$CaBundle,
    [string]$NodeName,
    [string]$InstallDir = "$env:ProgramFiles\UDCS\Agent",
    [string]$DataDir = "$env:ProgramData\UDCS\agent",
    [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
$ServiceName = 'UDCSAgent'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (Run as administrator).'
}
if (-not (Test-Path (Join-Path $Staging 'run_service.py'))) { throw "No staged agent at $Staging" }

# 1. Stop an existing installation (upgrade path). Its workloads checkpoint continuously.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    (Get-Service $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

# 2. Program files (admin-only by inheritance from Program Files).
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
robocopy $Staging $InstallDir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }

# 3. Data directory: SYSTEM + Administrators only.
#    Users may create folders under C:\ProgramData by default, so a student could have
#    pre-created (and still own) these folders, added their own ACEs, or planted junctions
#    that the SYSTEM service would write through. Anything not admin-owned, or containing
#    a reparse point, is moved aside; then a fresh owner + protected ACL is applied.
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Protect-AgentDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
        $planted = Get-ChildItem -LiteralPath $Path -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue
        $isReparse = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        if ($isReparse -or ($TrustedOwners -notcontains $owner) -or $planted) {
            $aside = "$Path.untrusted-" + (Get-Date -Format 'yyyyMMddHHmmss')
            Write-Warning "$Path is not admin-controlled (owner $owner, reparse points: $($isReparse -or [bool]$planted)); moving it to $aside"
            icacls $Path /setowner '*S-1-5-32-544' /C /Q | Out-Null
            Rename-Item -LiteralPath $Path -NewName (Split-Path $aside -Leaf)
        }
    }
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    icacls $Path /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
    icacls $Path /reset /T /C /Q | Out-Null  # drop every explicit ACE, including foreign ones
    icacls $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}
Protect-AgentDirectory (Split-Path $DataDir -Parent)
Protect-AgentDirectory $DataDir

$python = Join-Path $InstallDir 'python\python.exe'
$pythonw = Join-Path $InstallDir 'python\pythonw.exe'

# 4. Optional enrollment (lab key from the environment only).
if ($ControllerUrl) {
    if (-not $env:UDCS_ENROLLMENT_TOKEN) { throw 'Set $env:UDCS_ENROLLMENT_TOKEN to the lab enrollment key.' }
    $enrollArgs = @('-I', (Join-Path $InstallDir 'run_agent.py'), '--data-dir', $DataDir, 'enroll',
                    '--controller-url', $ControllerUrl)
    if ($CaBundle) {
        Copy-Item $CaBundle (Join-Path $DataDir 'controller-ca.pem') -Force
        $enrollArgs += @('--ca-bundle', (Join-Path $DataDir 'controller-ca.pem'))
    }
    if ($NodeName) { $enrollArgs += @('--name', $NodeName) }
    & $python @enrollArgs
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed (see message above).' }
}

# 5. Service registration.
$binPath = "`"$python`" -I `"$(Join-Path $InstallDir 'run_service.py')`""
if (-not $existing) {
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'UDCS Node Agent' `
        -StartupType Automatic -Description 'Lends spare CPU/GPU capacity to the university UDCS pool. The local user always has priority.' | Out-Null
} else {
    sc.exe config $ServiceName binPath= $binPath | Out-Null
}
sc.exe config $ServiceName start= delayed-auto | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null
sc.exe sidtype $ServiceName unrestricted | Out-Null

# 6. Per-session helper at every logon (no window: pythonw).
$run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $run -Name 'UDCSSessionHelper' -Value "`"$pythonw`" -I `"$(Join-Path $InstallDir 'run_helper.py')`""

if (-not $NoStart) { Start-Service -Name $ServiceName }
Get-Service $ServiceName | Format-Table Name, Status, StartType -AutoSize
Write-Host "Installed. Logs: $DataDir\logs\agent.log   Status: $DataDir\status\governor.json"
