<#
.SYNOPSIS
    Migrates iG Windows Tuner 1.x data to schema v2.
.DESCRIPTION
    Converts the catalog files under a data folder (tweaks\*.json, presets\*.json, cleaner\*.json)
    to schema v2 in place: adds level, antiCheat, reversible, sideEffects, source and hardware,
    moves appliesTo.hardware conditions to appliesTo.conditions, and turns v1 presets into intent
    presets (include, exclude, levelCeiling, antiCheatPolicy). Action definitions are never changed,
    so every existing snapshot still matches the catalog. Running it twice changes nothing.

    With -SnapshotFolder it also writes schema 2 copies of snapshot files to -SnapshotDestination.
    Originals are never modified (iG Windows Tuner reads v1 snapshots directly and upgrades them in memory),
    and the destination must be a different folder.

    This only edits files; it changes no Windows setting.
.PARAMETER DataFolder
    Data folder to convert (default: the project's data folder).
.PARAMETER SnapshotFolder
    Optional folder with snapshot-*.json files to copy as schema 2.
.PARAMETER SnapshotDestination
    Folder for the schema 2 snapshot copies (required with -SnapshotFolder).
.EXAMPLE
    .\tools\Convert-IgwtV1Data.ps1 -WhatIf
.EXAMPLE
    .\tools\Convert-IgwtV1Data.ps1 -DataFolder D:\old\AegisTune\data
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param([string]$DataFolder, [string]$SnapshotFolder, [string]$SnapshotDestination)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\iGWindowsTuner.psd1') -Force
if (-not $DataFolder) { $DataFolder = Join-Path $root 'data' }
$DataFolder = (Resolve-Path -LiteralPath $DataFolder).ProviderPath
if ($SnapshotFolder -and -not $SnapshotDestination) { throw '-SnapshotFolder needs -SnapshotDestination (snapshots are copied, never converted in place).' }

Set-IgwtEnvironment -DataFolder $DataFolder -WhatIf:$false
try {
    $report = @(Convert-IgwtDataToV2 -DataFolder $DataFolder)
    $report | Format-Table -AutoSize File, Kind, Items, FromSchema, Changed | Out-String -Width 160 | Write-Output
    Write-Output ("{0} file(s) checked, {1} converted{2}." -f $report.Count, @($report | Where-Object { $_.Changed }).Count, $(if ($WhatIfPreference) { ' (WhatIf: nothing written)' } else { '' }))
    if ($SnapshotFolder) {
        foreach ($f in (Get-ChildItem -LiteralPath $SnapshotFolder -Filter 'snapshot-*.json' -File)) {
            $out = Convert-IgwtSnapshotToV2 -Path $f.FullName -Destination $SnapshotDestination
            if ($out) { Write-Output "Snapshot copy: $out" }
        }
    }
    if (-not $WhatIfPreference) {
        $errors = @(Test-IgwtCatalog)
        if ($errors.Count -gt 0) { Write-Warning ("Catalog validation after migration found {0} problem(s):`n{1}" -f $errors.Count, ($errors -join "`n")) }
        else { Write-Output 'Catalog validation after migration: OK.' }
    }
} finally {
    Set-IgwtEnvironment -DataFolder '' -WhatIf:$false
}
