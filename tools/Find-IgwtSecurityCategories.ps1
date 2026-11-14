<#
.SYNOPSIS
    Maintainer review for the Security Settings Manager (DECISIONS SM6). Read-only: parses ADMX files
    and prints findings; writes no file.
.DESCRIPTION
    Reports four kinds of finding for data\security to review:
    Category  - a category not covered by categories.json whose name contains a security keyword.
    UefiLock  - an enum item in scope whose name contains 'UEFI' or 'lock' and that is not a
                uefiLockValues tuple in settings-meta.json.
    Weakening - an Enabled or Disabled value in scope named like Disable*, *Insecure*,
                AlwaysInstallElevated or Enable*Logging with data 0 that is neither in
                weakening.json nor in settings-meta.json reviewedAllowed.
    Overlap   - two policies in scope whose registry entries overlap (SM8 condition 6) and that are
                not in reviewedOverlaps.
.PARAMETER AdmxFolder
    The folder with the .admx files and their en-US .adml files. Default: %SystemRoot%\PolicyDefinitions.
.EXAMPLE
    .\tools\Find-IgwtSecurityCategories.ps1 | Format-Table -AutoSize
#>
[CmdletBinding()]
param([string]$AdmxFolder = (Join-Path $env:SystemRoot 'PolicyDefinitions'))
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\iGWindowsTuner.psd1') -Force
& (Get-Module iGWindowsTuner) {
    param($Folder)
    $read = Read-IgwtAdmxFolder -Folder $Folder
    $catalog = [pscustomobject]@{ Categories = @($read.Files | ForEach-Object { $_.Categories }); Policies = @($read.Files | ForEach-Object { $_.Policies }) }
    $data = Get-IgwtSecSettingsData
    $finding = { param($check, $item, $detail) [pscustomobject]@{ Check = $check; Item = $item; Detail = $detail } }

    # 1. Unlisted categories with a security keyword.
    $keywords = 'security|credential|authentication|encryption|defender|firewall|smartscreen|exploit|malware|password|certificate|audit|lsa|tpm|virtualization based'
    $whole = @{}; $named = @{}
    foreach ($e in @($data.Categories.entries)) {
        if ([string]$e.category -eq '*') { $whole[([string]$e.namespace).ToLowerInvariant()] = $true } else { $named[("$($e.namespace):$($e.category)").ToLowerInvariant()] = $true }
    }
    foreach ($f in $read.Files) {
        foreach ($c in @($f.Categories)) {
            $id = ([string]$c.Id).ToLowerInvariant()
            if ($whole.ContainsKey(([string]$f.Namespace).ToLowerInvariant()) -or $named.ContainsKey($id)) { continue }
            if ([string]$c.DisplayName -match "(?i)($keywords)") { & $finding 'Category' $c.Id "'$($c.DisplayName)' contains a security keyword and is not in categories.json." }
        }
    }

    $inScope = @(Get-IgwtSecSettingDefinitions -Catalog $catalog | ForEach-Object { $_.Policy })

    # 2. UEFI or lock enum items that are not a reviewed tuple.
    $tuples = @{}
    foreach ($t in @($data.Meta.uefiLockValues)) { $tuples[("$($t.key)|$($t.valueName)|$($t.value)").ToLowerInvariant()] = $true }
    foreach ($p in $inScope) {
        foreach ($e in @($p.Elements | Where-Object { $_ -and [string]$_.Type -eq 'enum' })) {
            foreach ($it in @($e.Items)) {
                if ([string]$it.DisplayName -notmatch '(?i)uefi|\block\b') { continue }
                $v = $(if ($it.Value) { [string]$it.Value.Value } else { '' })
                if (-not $tuples.ContainsKey(("$($e.Key)|$($e.ValueName)|$v").ToLowerInvariant())) { & $finding 'UefiLock' $p.Id "$($e.ValueName)=$v ('$($it.DisplayName)') is not a uefiLockValues tuple." }
            }
        }
    }

    # 3. Weakening-looking values that are not reviewed.
    $allowed = @{}
    foreach ($a in @($data.Meta.reviewedAllowed)) { if ($a -and $a.valueName) { $allowed[("$($a.key)|$($a.valueName)").ToLowerInvariant()] = $true } }
    $weak = @($data.Weakening.entries)
    $isWeakName = { param($n) [string]$n -match '(?i)^(Disable.*|.*Insecure.*|AlwaysInstallElevated|Enable.*Logging)$' }
    $listed = {
        param($k, $n, $v)
        foreach ($w in $weak) { if ($k -match "^(?i:$($w.key))$" -and $n -match "^(?i:$($w.valueName))$" -and (@($w.values) -contains $v -or @($w.values) -contains 'any')) { return $true } }
        return $allowed.ContainsKey(("$k|$n").ToLowerInvariant())
    }
    foreach ($p in $inScope) {
        $ops = New-Object System.Collections.Generic.List[object]
        foreach ($v in @($p.EnabledValue, $p.DisabledValue)) { if ($v -and $p.ValueName) { $ops.Add([pscustomobject]@{ Key = $p.Key; ValueName = $p.ValueName; Data = [string]$v.Value }) } }
        foreach ($i in @($p.EnabledList) + @($p.DisabledList)) { if ($i -and $i.Value) { $ops.Add([pscustomobject]@{ Key = $i.Key; ValueName = $i.ValueName; Data = [string]$i.Value.Value }) } }
        foreach ($o in $ops) {
            if ((& $isWeakName $o.ValueName) -and $o.Data -eq '0' -and -not (& $listed $o.Key $o.ValueName '0')) { & $finding 'Weakening' $p.Id "$($o.Key)\$($o.ValueName)=0 is neither in weakening.json nor reviewedAllowed." }
        }
    }

    # 4. Overlaps between policies in scope.
    $index = Get-IgwtSecSettingOverlapIndex -Catalog $catalog
    $ids = @{}
    foreach ($p in $inScope) { $ids[[string]$p.Id] = $true }
    foreach ($k in @($index.Keys | Sort-Object)) {
        if (-not $ids.ContainsKey($k)) { continue }
        foreach ($o in @($index[$k])) { if ([string]::CompareOrdinal($k, $o) -lt 0) { & $finding 'Overlap' $k "Shares registry entries with $o." } }
    }
} $AdmxFolder
