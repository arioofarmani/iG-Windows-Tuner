# Schema.ps1
# Schema v2 vocabulary and the field checks shared by every catalog item kind (tweaks, cleaner
# rules, presets, hardware tags). Data files declare "schemaVersion": 2. Entries without the v2
# fields (v1 data) are upgraded in memory when they are loaded (see Migration.ps1), and
# tools\Convert-IgwtV1Data.ps1 rewrites v1 files on disk.

$script:IgwtSchemaVersion = 2
$script:IgwtItemLevels = @('Standard', 'Advanced', 'Expert', 'Lab')
$script:IgwtTiers = @('A', 'B', 'R')   # R = rejected tweak offered at the user's own risk (Risk Zone)
$script:IgwtReversibleValues = @('full', 'partial', 'none')
$script:IgwtItemSources = @('igwt', 'winutil', 'microsoft')
$script:IgwtAntiCheatPolicies = @('safeOnly', 'any')
# Runtime applicability checks (appliesTo.conditions); evaluated against the engine context.
$script:IgwtConditions = @('wiredAdapter', 'multipleGpus', 'nvidiaGpu', 'defenderActive', 'notRdp')
# Anti-cheat names recognised when v1 warnings are migrated (text -> canonical name).
$script:IgwtAntiCheatNames = [ordered]@{
    'FACEIT' = 'FACEIT'; 'Vanguard' = 'Riot Vanguard'; 'Easy Anti-Cheat' = 'Easy Anti-Cheat'; 'EasyAntiCheat' = 'Easy Anti-Cheat'
    'BattlEye' = 'BattlEye'; 'RICOCHET' = 'RICOCHET'; 'Javelin' = 'Javelin'
}
$script:IgwtHardwareTagCache = $null

function Get-IgwtHardwareTagDefinitions {
    <# .SYNOPSIS Hardware tag vocabulary from data\hardware\tags.json (id, name, group, hint, description). #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtHardwareTagCache -and -not $Force) { return $script:IgwtHardwareTagCache }
    $file = Join-Path (Get-IgwtDataFolder) 'hardware\tags.json'
    $tags = @()
    if (Test-Path -LiteralPath $file) { $tags = @((Read-IgwtJsonFile -Path $file).tags | Where-Object { $_ }) }
    $script:IgwtHardwareTagCache = $tags
    return $tags
}

function Get-IgwtLevelRank {
    <# .SYNOPSIS 0 = Standard ... 3 = Lab; -1 for an unknown level. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowEmptyString()][string]$Level)
    return [array]::IndexOf($script:IgwtItemLevels, $Level)
}

function ConvertTo-IgwtAntiCheatInfo {
    <#
    .SYNOPSIS
        Interprets an antiCheat field: "safe", "unknown" or { "breaks": [names] }. Returns Valid,
        Safe, Unknown, Breaks and a short Text for badges.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    $info = [pscustomobject]@{ Valid = $false; Safe = $false; Unknown = $false; Breaks = @(); Text = 'Anti-cheat: invalid' }
    if ($Value -is [string]) {
        if ($Value -eq 'safe') { $info.Valid = $true; $info.Safe = $true; $info.Text = 'Anti-cheat safe' }
        elseif ($Value -eq 'unknown') { $info.Valid = $true; $info.Unknown = $true; $info.Text = 'Anti-cheat: unknown' }
        return $info
    }
    if ($null -ne $Value -and ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject])) {
        $breaks = $null
        if ($Value -is [System.Collections.IDictionary]) { $breaks = $Value['breaks'] } else { $breaks = $Value.breaks }
        $names = @($breaks | Where-Object { $_ -is [string] -and $_.Trim() })
        if ($names.Count -gt 0 -and $names.Count -eq @($breaks).Count) {
            $info.Valid = $true; $info.Breaks = $names; $info.Text = "Breaks $($names -join ', ')"
        }
    }
    return $info
}

function Get-IgwtItemTier {
    <# .SYNOPSIS Evidence tier of an item: evidence.tier for tweaks, the top-level tier otherwise. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Item)
    if ($null -ne $Item.PSObject.Properties['evidence'] -and $Item.evidence -and $null -ne $Item.evidence.PSObject.Properties['tier']) { return [string]$Item.evidence.tier }
    if ($null -ne $Item.PSObject.Properties['tier']) { return [string]$Item.tier }
    return ''
}

function Test-IgwtItemText {
    <# .SYNOPSIS Every user-facing item: a hint of 140 characters or fewer and a real description. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Item, [Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    $hint = [string]$Item.hint
    $desc = [string]$Item.description
    if (-not $hint.Trim()) { $Errors.Add("${Label}: missing 'hint'.") }
    elseif ($hint.Length -gt 140) { $Errors.Add("${Label}: hint is $($hint.Length) characters (max 140).") }
    if (-not $desc.Trim()) { $Errors.Add("${Label}: missing 'description'.") }
    elseif ($desc.Length -lt 40) { $Errors.Add("${Label}: description is too short (at least 40 characters).") }
}

function Test-IgwtItemMetadata {
    <#
    .SYNOPSIS
        Schema v2 metadata shared by tweaks and cleaner rules: level, tier, antiCheat, reversible,
        sideEffects, source (+ attribution for WinUtil items) and hardware tags.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Item, [Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    if ($script:IgwtItemLevels -notcontains [string]$Item.level) { $Errors.Add("${Label}: level must be Standard, Advanced, Expert or Lab (got '$($Item.level)').") }
    if ($script:IgwtTiers -notcontains (Get-IgwtItemTier -Item $Item)) { $Errors.Add("${Label}: tier must be A, B or R (R only for Risk Zone items).") }
    if (-not (ConvertTo-IgwtAntiCheatInfo -Value $Item.antiCheat).Valid) { $Errors.Add("${Label}: antiCheat must be ""safe"", ""unknown"" or { ""breaks"": [names] }.") }
    if ($script:IgwtReversibleValues -notcontains [string]$Item.reversible) { $Errors.Add("${Label}: reversible must be full, partial or none.") }
    if ($null -eq $Item.PSObject.Properties['sideEffects'] -or ($null -ne $Item.sideEffects -and $Item.sideEffects -isnot [string])) { $Errors.Add("${Label}: 'sideEffects' must be a string (empty when there are none).") }
    if ($script:IgwtItemSources -notcontains [string]$Item.source) { $Errors.Add("${Label}: source must be igwt, winutil or microsoft.") }
    if ([string]$Item.source -eq 'winutil' -and -not ([string]$Item.attribution).Trim()) { $Errors.Add("${Label}: WinUtil-derived items need an 'attribution'.") }
    $hw = $Item.hardware
    if ($null -eq $hw) { $Errors.Add("${Label}: missing 'hardware' ({ tags, excludeTags }).") }
    else {
        $known = @(Get-IgwtHardwareTagDefinitions | ForEach-Object { [string]$_.id })
        $tags = @($hw.tags | Where-Object { $_ }); $ex = @($hw.excludeTags | Where-Object { $_ })
        foreach ($t in $tags + $ex) { if ($known -notcontains [string]$t) { $Errors.Add("${Label}: unknown hardware tag '$t'.") } }
        foreach ($t in $tags) { if ($ex -contains $t) { $Errors.Add("${Label}: hardware tag '$t' is both required and excluded.") } }
    }
}
