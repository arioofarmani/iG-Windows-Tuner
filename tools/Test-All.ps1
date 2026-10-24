<#
.SYNOPSIS
    Runs every check: the quality gate (Pester, PSScriptAnalyzer, Defender scan of the project
    folder), the offscreen GUI render suite (mocked data, every theme and scale) and the UI
    Automation smoke suite (the real GUI in read-only mode). Writes artifacts\test-all.json.
.PARAMETER SkipAutomation
    Skip the UI Automation suite (it opens the real GUI window in read-only mode for a few minutes).
.PARAMETER SkipRender
    Skip the offscreen render suite.
.PARAMETER RenderScale
    Display scales for the render suite (default 1, 1.5, 2).
#>
[CmdletBinding()]
param([switch]$SkipAutomation, [switch]$SkipRender, [double[]]$RenderScale = @(1, 1.5, 2))
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$art = Join-Path $root 'artifacts'
if (-not (Test-Path -LiteralPath $art)) { $null = New-Item -ItemType Directory -Path $art -Force }
$result = [ordered]@{ Started = (Get-Date).ToString('o') }

Write-Output '== Quality gate (Pester, PSScriptAnalyzer, Defender scan)'
& (Join-Path $PSScriptRoot 'Invoke-QualityChecks.ps1')
$result.QualityGate = ($LASTEXITCODE -eq 0)

if (-not $SkipRender) {
    Write-Output '== Offscreen render suite'
    & (Join-Path $PSScriptRoot 'Test-GuiRender.ps1') -OutDir (Join-Path $art 'gui-render') -Scale $RenderScale
    $result.Render = ($LASTEXITCODE -eq 0)
    # The minimum window size (1100 x 720) at 100 and 200 %: nothing may clip.
    & (Join-Path $PSScriptRoot 'Test-GuiRender.ps1') -OutDir (Join-Path $art 'gui-render') -Theme Dark -Scale 1, 2 -Size '1100x720'
    $result.Render = $result.Render -and ($LASTEXITCODE -eq 0)
}
if (-not $SkipAutomation) {
    Write-Output '== UI Automation suite (read-only GUI)'
    & (Join-Path $PSScriptRoot 'Test-GuiAutomation.ps1') -OutDir (Join-Path $art 'gui-automation')
    $result.Automation = ($LASTEXITCODE -eq 0)
    $rep = Join-Path $art 'gui-automation\automation-report.json'
    if (Test-Path -LiteralPath $rep) {
        $r = Get-Content -LiteralPath $rep -Raw | ConvertFrom-Json
        $result.AutomationClean = ($r.ReadOnlyVerified -and @($r.Exceptions).Count -eq 0 -and $r.BindingErrors -eq 0 -and $r.StallsOver200 -eq 0 -and $r.MemoryGrowthMB -lt 50)
        $result.AutomationSummary = [ordered]@{ Exceptions = @($r.Exceptions).Count; BindingErrors = $r.BindingErrors; StallsOver200 = $r.StallsOver200; MemoryGrowthMB = $r.MemoryGrowthMB }
    }
}
$result.Finished = (Get-Date).ToString('o')
[pscustomobject]$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $art 'test-all.json') -Encoding UTF8
[pscustomobject]$result | Format-List | Out-String | Write-Output
$failed = @($result.Keys | Where-Object { $_ -in 'QualityGate', 'Render', 'Automation' -and -not $result[$_] })
if ($failed.Count) { Write-Output "FAILED: $($failed -join ', ')"; exit 1 }
Write-Output 'All checks passed.'
exit 0
