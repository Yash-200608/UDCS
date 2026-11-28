# Shared by the acceptance scripts (dot-source it). Read-only: nothing here writes.
#
# Evidence is kept per machine, under docs\acceptance\data\machines\<label>\, where <label>
# is the first 12 hex characters of SHA-256(lower-case host name), the same label that
# udcs_agent.diagnostics.context.machine_label() uses. The host name itself is never
# recorded. The top-level docs\acceptance\data\m15-service-acceptance.json belongs to the
# retired build 22000 machine and is history: no script may write it.

function Get-MachineLabel {
    $hostName = [Net.Dns]::GetHostName().ToLowerInvariant()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hostName)) } finally { $sha.Dispose() }
    return (-join ($bytes | ForEach-Object { $_.ToString('x2') })).Substring(0, 12)
}

function Get-LegacyEvidencePath([string]$Root) { Join-Path $Root 'm15-service-acceptance.json' }

function Get-MachineEvidencePath([string]$Root, [string]$Label = (Get-MachineLabel)) {
    Join-Path (Join-Path (Join-Path $Root 'machines') $Label) 'm15-service-acceptance.json'
}

function Get-MachineFacts {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cpu = @(Get-CimInstance Win32_Processor)
    return [ordered]@{
        label           = Get-MachineLabel
        edition         = $os.Caption
        edition_id      = $cv.EditionID
        display_version = $cv.DisplayVersion
        build           = [Environment]::OSVersion.Version.ToString()
        build_ubr       = '{0}.{1}' -f $os.BuildNumber, $cv.UBR
        cpu             = ($cpu | ForEach-Object { $_.Name.Trim() }) -join '; '
        cores           = ($cpu | Measure-Object NumberOfCores -Sum).Sum
        logical         = ($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
        ram_gib         = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
        gpu             = @(Get-CimInstance Win32_VideoController | ForEach-Object { "$($_.Name) ($($_.DriverVersion))" })
        scope           = 'one machine; not a lab image'
    }
}
