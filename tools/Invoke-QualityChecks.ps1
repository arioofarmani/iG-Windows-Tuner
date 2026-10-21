<#
.SYNOPSIS
    Runs every build-time check: catalog validation, Pester 5, PSScriptAnalyzer and a Microsoft
    Defender custom scan of the project folder. Read-only for the system.
.DESCRIPTION
    Pester 5 and PSScriptAnalyzer are development dependencies (install them for the current user:
    Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -SkipPublisherCheck;
    Install-Module PSScriptAnalyzer -Scope CurrentUser). iG Windows Tuner itself has no dependencies.
    Run from a NON-elevated PowerShell: the tests refuse to run elevated on a real machine.
    Results are written to artifacts\ (Pester NUnit XML, analyzer and Defender output).
.PARAMETER SkipDefenderScan
    Skip the MpCmdRun custom scan.
.EXAMPLE
    .\tools\Invoke-QualityChecks.ps1
#>
[CmdletBinding()]
param([switch]$SkipDefenderScan)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$artifacts = Join-Path $root 'artifacts'
if (-not (Test-Path -LiteralPath $artifacts)) { $null = New-Item -ItemType Directory -Path $artifacts -Force }
$failed = $false

Write-Output '== Catalog'
& (Join-Path $PSScriptRoot 'Test-Catalog.ps1')
if ($LASTEXITCODE -ne 0) { $failed = $true }

Write-Output '== Pester 5'
Import-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99 -ErrorAction Stop
$cfg = New-PesterConfiguration
$cfg.Run.Path = (Join-Path $root 'tests')
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Normal'
$cfg.TestResult.Enabled = $true
$cfg.TestResult.OutputPath = (Join-Path $artifacts 'pester-results.xml')
$result = Invoke-Pester -Configuration $cfg
Write-Output ("Pester: {0} passed, {1} failed, {2} skipped" -f $result.PassedCount, $result.FailedCount, $result.SkippedCount)
if ($result.FailedCount -gt 0) { $failed = $true }

Write-Output '== PSScriptAnalyzer'
Import-Module PSScriptAnalyzer -ErrorAction Stop
$findings = @(Invoke-ScriptAnalyzer -Path $root -Recurse)
$findings | Select-Object Severity, RuleName, ScriptName, Line, Message | Format-Table -AutoSize | Out-String -Width 250 | Set-Content -LiteralPath (Join-Path $artifacts 'scriptanalyzer.txt') -Encoding UTF8
Write-Output ("ScriptAnalyzer: {0} error(s), {1} warning(s), {2} information" -f @($findings | Where-Object Severity -EQ 'Error').Count, @($findings | Where-Object Severity -EQ 'Warning').Count, @($findings | Where-Object Severity -EQ 'Information').Count)
if (@($findings | Where-Object { $_.Severity -in 'Error', 'Warning' }).Count -gt 0) { $failed = $true }

if (-not $SkipDefenderScan) {
    Write-Output '== Microsoft Defender custom scan'
    $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path -LiteralPath $mp) {
        $out = & $mp -Scan -ScanType 3 -File $root 2>&1 | Out-String
        $code = $LASTEXITCODE
        Set-Content -LiteralPath (Join-Path $artifacts 'defender-scan.txt') -Value ("Exit code: $code`r`n" + $out) -Encoding UTF8
        Write-Output $out.Trim()
        Write-Output "MpCmdRun exit code: $code (0 = no threats found)"
        if ($code -ne 0) { $failed = $true }
    } else { Write-Output 'MpCmdRun.exe not found; scan skipped.' }
}

if ($failed) { Write-Output 'RESULT: FAILED'; exit 1 }
Write-Output 'RESULT: all checks passed'
exit 0
