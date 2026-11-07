<#
.SYNOPSIS
    Offscreen GUI render suite: renders every page to PNG (WPF RenderTargetBitmap) with the mocked
    data providers in tests\gui\GuiMocks.ps1, for each theme and display scale. No window is shown,
    nothing on the PC is read for page data and nothing is changed (the engine runs in read-only
    mode). Writes <OutDir>\<theme>-<scale>\NN-Page-scale.png and a summary.json. Every rendered view is
    checked for text that looks like a leaked type name or hashtable (text-leaks.json beside the PNGs,
    counted in summary.json); any leak fails the run with exit code 1. With the mocks, the run also
    fails when a list in $requiredLists never has items, because the check would be blind there.
.PARAMETER OutDir
    Output folder (default artifacts\gui-render).
.PARAMETER Theme
    Themes to render (Dark, Light, HighContrast). Default: all.
.PARAMETER Scale
    Display scales to emulate (1 = 100 %). Default: 1, 1.5, 2.
.PARAMETER Size
    Window size in device-independent pixels (default 1280x820; the minimum supported size is 1100x720).
.PARAMETER Live
    Use live data from this PC instead of the mocks (read-only; screenshots may contain machine details).
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\gui-render'),
    [ValidateSet('Dark', 'Light', 'HighContrast')][string[]]$Theme = @('Dark', 'Light', 'HighContrast'),
    [double[]]$Scale = @(1, 1.5, 2),
    [ValidatePattern('^\d{3,4}x\d{3,4}$')][string]$Size = '1280x820',
    [switch]$Live
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $OutDir)) { $null = New-Item -ItemType Directory -Path $OutDir -Force }
$child = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-render-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
@'
param([string]$Root, [string]$Dir, [double]$Scale, [string]$Theme, [string]$Size = '1280x820', [switch]$Live)
$env:IGWT_RENDER_SIZE = $Size
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $Root 'src\iGWindowsTuner.psd1') -Force
Set-IgwtEnvironment -ReadOnly
$m = Get-Module iGWindowsTuner
$mocks = Join-Path $Root 'tests\gui\GuiMocks.ps1'
& $m {
    param($MockFile, $UseLive)
    if (-not $UseLive) { . $MockFile }
    # Show the full (administrator) view in the screenshots; the engine stays read-only.
    function script:Test-IgwtReadOnly { return $false }
} $mocks ([bool]$Live)
$gui = Get-Command Show-IgwtGui
$args2 = @{ RenderTo = $Dir; Scale = $Scale }
if ($gui.Parameters.ContainsKey('Theme')) { $args2.Theme = $Theme }
# The mocked network test sends nothing and fills the result lists of the Network test page.
if (-not $Live) { $args2.WithNetworkTest = $true }
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$files = @(Show-IgwtGui @args2)
[pscustomobject]@{ Theme = $Theme; Scale = $Scale; Pages = $files.Count; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) } | ConvertTo-Json -Compress
'@ | Set-Content -LiteralPath $child -Encoding UTF8
$summary = New-Object System.Collections.Generic.List[object]
# Lists the mocks must fill: an empty list cannot show a leak.
$requiredLists = @('FwOvRecentList', 'FwDetFindings', 'AsrExclusionList', 'NetTargetList', 'NetRecoList', 'NetGuidanceList')
$gateFailed = $false
try {
    foreach ($t in $Theme) {
        foreach ($s in $Scale) {
            $dir = Join-Path $OutDir ("{0}-{1}{2}" -f $t.ToLowerInvariant(), [int]($s * 100), $(if ($Size -ne '1280x820') { "-$Size" } else { '' }))
            if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
            $null = New-Item -ItemType Directory -Path $dir -Force
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', $child, '-Root', $root, '-Dir', $dir, '-Scale', $s, '-Theme', $t, '-Size', $Size)
            if ($Live) { $argList += '-Live' }
            $out = & $psExe @argList 2>&1
            $line = @($out | Where-Object { "$_" -like '{*' }) | Select-Object -Last 1
            if ($LASTEXITCODE -ne 0 -or -not $line) {
                $summary.Add([pscustomobject]@{ Theme = $t; Scale = $s; Pages = 0; Error = (($out | Select-Object -Last 8) -join ' ') })
                Write-Warning "Render $t at $([int]($s * 100)) % failed: $(($out | Select-Object -Last 3) -join ' ')"
            } else {
                $r = $line | ConvertFrom-Json
                $warn = @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] -or "$_" -like 'WARNING:*' } | ForEach-Object { "$_" -replace '^WARNING:\s*', '' })
                $r | Add-Member -NotePropertyName Warnings -NotePropertyValue $warn -Force
                foreach ($w in $warn) { Write-Warning "$t $([int]($s * 100)) %: $w" }
                # Text gate: a missing or empty report counts as a failure, not as a pass.
                $leakFile = Join-Path $dir 'text-leaks.json'
                $scan = $(if (Test-Path -LiteralPath $leakFile) { Get-Content -LiteralPath $leakFile -Raw -Encoding UTF8 | ConvertFrom-Json })
                $leaks = $(if ($scan) { @($scan.Leaks) } else { @() })
                $blind = $(if ($scan -and -not $Live) { @($requiredLists | Where-Object { @($scan.FilledLists) -notcontains $_ }) } else { @() })
                $r | Add-Member -NotePropertyName TextsChecked -NotePropertyValue $(if ($scan) { [int]$scan.Checked } else { 0 }) -Force
                $r | Add-Member -NotePropertyName TextLeaks -NotePropertyValue $leaks -Force
                $r | Add-Member -NotePropertyName EmptyLists -NotePropertyValue $(if ($scan) { @($scan.EmptyLists) } else { @() }) -Force
                if (-not $scan -or $r.TextsChecked -eq 0) { $gateFailed = $true; Write-Warning "$t $([int]($s * 100)) %: the text check did not run (no $leakFile)." }
                foreach ($l in $leaks) { $gateFailed = $true; Write-Warning "$t $([int]($s * 100)) %: leaked text in $($l.Image) [$($l.Rule), $($l.Control)]: $($l.Text)" }
                if ($blind.Count) { $gateFailed = $true; Write-Warning "$t $([int]($s * 100)) %: the mocks leave these lists empty, so the text check is blind there: $($blind -join ', ')" }
                $summary.Add($r)
                Write-Output ("{0,-13} {1,4} %  {2,3} page(s)  {3,5} s  -> {4}" -f $t, [int]($s * 100), $r.Pages, $r.Seconds, $dir)
            }
        }
    }
} finally { Remove-Item -LiteralPath $child -Force -ErrorAction SilentlyContinue }
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir 'summary.json') -Encoding UTF8
if (@($summary | Where-Object { -not $_.Pages }).Count -or $gateFailed) { exit 1 }
exit 0
