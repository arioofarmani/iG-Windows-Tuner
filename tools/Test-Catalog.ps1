<#
.SYNOPSIS
    Validates data\tweaks\*.json, presets and the rejected list. Read-only.
.DESCRIPTION
    Checks required fields, hint length, sources for Tier A/B, unique ids, revert paths,
    preset references, conflicts, expert/anti-cheat rules and the rejected list.
    Exit code 0 = valid, 1 = errors found.
.EXAMPLE
    .\tools\Test-Catalog.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\iGWindowsTuner.psd1') -Force
$errors = @(Test-IgwtCatalog)
$catalog = @(Get-IgwtCatalog)
if ($errors.Count -eq 0) {
    Write-Output ("Catalog OK: {0} tweaks ({1} Tier A, {2} Tier B), {3} presets, {4} rejected entries." -f $catalog.Count,
        @($catalog | Where-Object { $_.evidence.tier -eq 'A' }).Count, @($catalog | Where-Object { $_.evidence.tier -eq 'B' }).Count,
        @(Get-IgwtPreset).Count, @(Get-IgwtRejectedTweaks).Count)
    exit 0
}
Write-Output "Catalog has $($errors.Count) error(s):"
$errors | ForEach-Object { Write-Output "  - $_" }
exit 1
