<#
.SYNOPSIS
  Build a portable bundle of the D-5 / ADR 0004 restricted-token experiment, to run on
  another machine (a second PC or a lab image) without a repository checkout.

.DESCRIPTION
  Run unelevated on the dev PC, from a clean working tree:
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\experiments\make_d5_bundle.ps1 -Out C:\Users\<you>\udcs-d5-bundle

  Produces <Out>\ (and <Out>.zip):
      stage\                                      package_agent.py staging of this commit
      tools\experiments\restricted_token_experiment.ps1/.py
      tools\acceptance\m3_exposure_audit.ps1      (its hardened helpers are loaded by the above)
      RUNBOOK-other-machine.md, BUNDLE.txt           (commit, file count, SHA-256 of every file)

  Nothing is installed or changed on either machine. It prints the zip's SHA-256, to be
  compared on the target before extracting.
#>
param([Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Out = [IO.Path]::GetFullPath($Out)
if (Test-Path -LiteralPath $Out) { throw "$Out already exists; choose a new folder." }
if (Test-Path -LiteralPath "$Out.zip") { throw "$Out.zip already exists." }

$dirty = & git -C $Repo status --porcelain
if ($dirty) { throw "The working tree is not clean; commit first so the bundle matches a commit.`n$dirty" }
$commit = (& git -C $Repo rev-parse HEAD).Trim()

$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $uv) { $uv = Join-Path $env:APPDATA 'Python\Python312\Scripts\uv.exe' }
if (-not (Test-Path -LiteralPath $uv)) { throw 'uv not found (PATH or %APPDATA%\Python\Python312\Scripts).' }

New-Item -ItemType Directory -Path $Out | Out-Null
Push-Location $Repo
try {
    & $uv run python tools/package_agent.py (Join-Path $Out 'stage')
    if ($LASTEXITCODE -ne 0) { throw "package_agent.py failed ($LASTEXITCODE)" }
} finally { Pop-Location }

foreach ($rel in @(
        'tools\experiments\restricted_token_experiment.ps1',
        'tools\experiments\restricted_token_experiment.py',
        'tools\acceptance\m3_exposure_audit.ps1')) {
    $dest = Join-Path $Out $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    Copy-Item -LiteralPath (Join-Path $Repo $rel) -Destination $dest
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'RUNBOOK-other-machine.md') -Destination $Out

$files = Get-ChildItem -LiteralPath $Out -Recurse -File | Sort-Object FullName
$lines = foreach ($f in $files) {
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLower(), $f.FullName.Substring($Out.Length + 1)
}
$header = @("UDCS D-5 / ADR 0004 experiment bundle. DIAGNOSTIC ONLY, never acceptance evidence.",
    "commit $commit", "files $($files.Count)", "")
[IO.File]::WriteAllLines((Join-Path $Out 'BUNDLE.txt'), [string[]]($header + $lines))

Compress-Archive -Path (Join-Path $Out '*') -DestinationPath "$Out.zip"
$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath "$Out.zip").Hash.ToLower()
Write-Host "Bundle: $Out.zip  ($($files.Count) files, commit $($commit.Substring(0, 10)))"
Write-Host "SHA-256: $zipHash"
