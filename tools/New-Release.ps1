<#
.SYNOPSIS
    Builds a release folder and zip in dist\ (catalog check, docs, optional tests, SHA256 manifest).
.DESCRIPTION
    Read-only for the system: it only reads the project and writes into dist\. Ships plain
    .ps1/.psm1/.psd1/.json/.xaml files plus the .cmd launcher; no EXE packaging.
.PARAMETER SkipTests
    Do not run Pester and PSScriptAnalyzer before packaging.
.EXAMPLE
    .\tools\New-Release.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Import-PowerShellDataFile (Join-Path $root 'src\iGWindowsTuner.psd1')).ModuleVersion

& (Join-Path $PSScriptRoot 'Test-Catalog.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Catalog validation failed.' }
& (Join-Path $PSScriptRoot 'Build-Docs.ps1')
if (-not $SkipTests) {
    & (Join-Path $PSScriptRoot 'Invoke-QualityChecks.ps1') -SkipDefenderScan
    if ($LASTEXITCODE -ne 0) { throw 'Quality checks failed.' }
}

$dist = Join-Path $root 'dist'
$stage = Join-Path $dist "iGWindowsTuner-$version"
if (-not $PSCmdlet.ShouldProcess($stage, 'Create release folder')) { return }
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
$null = New-Item -ItemType Directory -Path $stage -Force
foreach ($item in 'iGWindowsTuner.ps1', 'Start-iGWindowsTuner.cmd', 'CONTRIBUTING.md', 'LICENSE', 'README.md', 'PSScriptAnalyzerSettings.psd1', 'src', 'data', 'docs', 'tools', 'tests') {
    $src = Join-Path $root $item
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $stage -Recurse -Force }
}
$lines = foreach ($f in (Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName)) {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $f.FullName.Substring($stage.Length + 1).Replace('\', '/')
}
[System.IO.File]::WriteAllLines((Join-Path $stage 'SHA256SUMS.txt'), [string[]]@($lines), (New-Object System.Text.UTF8Encoding($false)))
$zip = Join-Path $dist "iGWindowsTuner-$version.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$zip.sha256" -Value "$hash  iGWindowsTuner-$version.zip" -Encoding ASCII
Write-Output "Release: $zip"
Write-Output "SHA256:  $hash"
Write-Output 'Note: files extracted from a downloaded zip carry Mark-of-the-Web; review them, then Unblock-File if you trust them.'
