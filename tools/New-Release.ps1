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
# The package is built from the last commit (git archive HEAD), and the checks below run on the
# working folder: both must be the same, so uncommitted edits to tracked files stop the build
# (review T-02). Build-Docs may have just changed docs\: commit them first.
Push-Location -LiteralPath $root
try { $dirty = @(git status --porcelain --untracked-files=no 2>$null) } finally { Pop-Location }
if ($dirty.Count) { throw "Tracked files have uncommitted changes, so the tested files would differ from the package: $(($dirty | ForEach-Object { $_.Trim() }) -join ', '). Commit them, then build the release." }
if (-not $SkipTests) {
    & (Join-Path $PSScriptRoot 'Invoke-QualityChecks.ps1') -SkipDefenderScan
    if ($LASTEXITCODE -ne 0) { throw 'Quality checks failed.' }
}

$dist = Join-Path $root 'dist'
$stage = Join-Path $dist "iGWindowsTuner-$version"
if (-not $PSCmdlet.ShouldProcess($stage, 'Create release folder')) { return }
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
$null = New-Item -ItemType Directory -Path $stage -Force
$items = @('iGWindowsTuner.ps1', 'Start-iGWindowsTuner.cmd', 'CONTRIBUTING.md', 'LICENSE', 'README.md', 'PSScriptAnalyzerSettings.psd1', 'src', 'data', 'docs', 'tools', 'tests')
# Only the last commit goes into the package (review T-02): paths AND contents come from HEAD, so
# git-ignored local files (screenshots with user names and device details, the local Sandbox
# configuration, logs, reports) and uncommitted edits never reach it.
$files = @()
Push-Location -LiteralPath $root
try { $files = @(git ls-tree -r --name-only HEAD -- @items 2>$null) } catch { $files = @() } finally { Pop-Location }
if (-not $files.Count) { throw 'git ls-tree returned nothing: the release is built from a git checkout only.' }
$headZip = Join-Path $dist 'igwt-head-archive.zip'
if (Test-Path -LiteralPath $headZip) { Remove-Item -LiteralPath $headZip -Force }
Push-Location -LiteralPath $root
try {
    git archive --format=zip --output="$headZip" HEAD -- @items
    if ($LASTEXITCODE -ne 0) { throw "git archive failed (exit $LASTEXITCODE)." }
} finally { Pop-Location }
try { Expand-Archive -LiteralPath $headZip -DestinationPath $stage -Force } finally { Remove-Item -LiteralPath $headZip -Force -ErrorAction SilentlyContinue }
$packaged = @(Get-ChildItem -LiteralPath $stage -Recurse -File)
if ($packaged.Count -ne $files.Count) { throw "The archive holds $($packaged.Count) files, HEAD lists $($files.Count)." }
# Belt and braces: nothing in the package may match the ignore rules.
Push-Location -LiteralPath $root
try { $ignored = @($files | git check-ignore --no-index --stdin 2>$null) } finally { Pop-Location }
if ($ignored.Count) { throw "Files matching .gitignore would be packaged: $($ignored -join ', ')" }
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
# git check-ignore exits with 1 when nothing is ignored (the good case): report success explicitly.
exit 0
