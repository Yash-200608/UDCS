<#
.SYNOPSIS
  Remove the UDCS Node Agent service. Run elevated.
  -RemoveData also deletes C:\ProgramData\UDCS\agent (node identity, checkpoints, logs);
  without it, a reinstall keeps the same node identity.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\UDCS\Agent",
    [string]$DataDir = "$env:ProgramData\UDCS\agent",
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
$ServiceName = 'UDCSAgent'
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    sc.exe delete $ServiceName | Out-Null
}
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'UDCSSessionHelper' -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe'" |
    Where-Object { $_.CommandLine -like '*run_helper.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
if ($RemoveData -and (Test-Path $DataDir)) { Remove-Item -Recurse -Force $DataDir }
Write-Host 'UDCS Node Agent removed.'
