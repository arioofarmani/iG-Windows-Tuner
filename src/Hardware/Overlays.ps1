# Overlays.ps1
# Hardware overlays (data\hardware\overlays.json) and preset resolution.
# Final plan = intent preset -> hardware overlays -> user add-ons. Blocks are enforced in state
# detection (blocked items are Not applicable, so neither presets nor -Apply can turn them on),
# adds put items into presets when the preset's level ceiling and anti-cheat policy allow it.

$script:IgwtOverlayCache = $null
$script:IgwtOverlayMatchKeys = @('type', 'handler', 'name', 'setting', 'subgroup', 'scheme', 'keyword', 'feature', 'id', 'fieldPresent')

function Get-IgwtHardwareOverlays {
    <# .SYNOPSIS All overlay definitions from data\hardware\overlays.json. #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtOverlayCache -and -not $Force) { return $script:IgwtOverlayCache }
    $file = Join-Path (Get-IgwtDataFolder) 'hardware\overlays.json'
    $list = @()
    if (Test-Path -LiteralPath $file) { $list = @((Read-IgwtJsonFile -Path $file).overlays | Where-Object { $_ }) }
    $script:IgwtOverlayCache = $list
    return $list
}

function Get-IgwtActiveOverlays {
    <# .SYNOPSIS Overlays that apply to the given hardware tags (an overlay is active when any of its tags is present). #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Tags = @())
    foreach ($o in @(Get-IgwtHardwareOverlays)) {
        $hit = @(@($o.tags) | Where-Object { $Tags -contains [string]$_ })
        if ($hit.Count -gt 0) {
            $copy = $o.PSObject.Copy()
            $copy | Add-Member -NotePropertyName MatchedTags -NotePropertyValue $hit -Force -PassThru
        }
    }
}

function Test-IgwtOverlayActionMatch {
    <# .SYNOPSIS True when one action matches an overlay matcher (every listed field equals one of its values, case-insensitive). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Matcher)
    foreach ($p in $Matcher.PSObject.Properties) {
        $allowed = @($p.Value | ForEach-Object { [string]$_ })
        if ($p.Name -eq 'fieldPresent') {
            foreach ($f in $allowed) { if ($null -eq $Action.PSObject.Properties[$f] -or $null -eq $Action.$f) { return $false } }
            continue
        }
        if ($null -eq $Action.PSObject.Properties[$p.Name]) { return $false }
        $actual = [string]$Action.($p.Name)
        if (@($allowed | Where-Object { [string]::Equals($_, $actual, [System.StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) { return $false }
    }
    return $true
}

function Get-IgwtHardwareBlock {
    <#
    .SYNOPSIS
        Why an item cannot be applied on this hardware, or $null: missing required hardware tags,
        an excluded tag, or an active overlay that blocks it (by id or by action match).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, [AllowEmptyCollection()][string[]]$Tags = @())
    $need = @($Tweak.hardware.tags | Where-Object { $_ })
    $missing = @($need | Where-Object { $Tags -notcontains [string]$_ })
    if ($missing.Count -gt 0) { return [pscustomobject]@{ Kind = 'tags'; OverlayId = ''; Reason = "Needs hardware tag(s) $($missing -join ', ') that this PC does not have." } }
    $excluded = @(@($Tweak.hardware.excludeTags | Where-Object { $_ }) | Where-Object { $Tags -contains [string]$_ })
    if ($excluded.Count -gt 0) { return [pscustomobject]@{ Kind = 'tags'; OverlayId = ''; Reason = "Not used on this hardware ($($excluded -join ', '))." } }
    foreach ($o in @(Get-IgwtActiveOverlays -Tags $Tags)) {
        $hit = (@($o.block) -contains [string]$Tweak.id)
        if (-not $hit) {
            foreach ($m in @($o.blockMatching | Where-Object { $_ })) {
                foreach ($a in @($Tweak.actions)) { if (Test-IgwtOverlayActionMatch -Action $a -Matcher $m) { $hit = $true; break } }
                if ($hit) { break }
            }
        }
        if ($hit) {
            return [pscustomobject]@{ Kind = 'overlay'; OverlayId = [string]$o.id; Reason = "Blocked on this hardware by '$($o.name)' ($(@($o.MatchedTags) -join ', ')): $($o.hint)" }
        }
    }
    return $null
}

function Resolve-IgwtPresetSelection {
    <#
    .SYNOPSIS
        Resolves a preset for the given hardware tags: intent preset -> hardware overlays -> user
        add-ons/removals. Returns the final ids plus every item's origin and the reasons.
    .PARAMETER Preset
        Preset name/id or preset object.
    .PARAMETER Tags
        Hardware tags (default: this PC's profile).
    .PARAMETER AddIds
        Your add-ons (still subject to hardware blocks).
    .PARAMETER RemoveIds
        Items you want left out.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [string[]]$Tags, [string[]]$AddIds = @(), [string[]]$RemoveIds = @())
    if ($Preset -is [string]) { $Preset = Get-IgwtPreset -Name $Preset }
    if ($null -eq $Tags) { $Tags = @((Get-IgwtHardwareProfile).Tags) }
    $catalog = @{}
    foreach ($t in @(Get-IgwtCatalog)) { $catalog[[string]$t.id] = $t }
    $active = @(Get-IgwtActiveOverlays -Tags $Tags)
    $excluded = @($Preset.exclude | Where-Object { $_ })
    $ceiling = Get-IgwtLevelRank -Level ([string]$Preset.levelCeiling)
    $items = New-Object System.Collections.Generic.List[object]
    $index = @{}
    $addItem = {
        param([string]$Id, [string]$Origin, [bool]$Included, [string]$Note)
        if ($index.ContainsKey($Id)) {
            $it = $index[$Id]
            if ($Note) { $it.Notes.Add($Note) }
            return
        }
        $it = [pscustomobject]@{ Id = $Id; Origin = $Origin; Included = $Included; Blocked = $false; Notes = (New-Object System.Collections.Generic.List[string]) }
        if ($Note) { $it.Notes.Add($Note) }
        $items.Add($it); $index[$Id] = $it
    }
    $checkBlock = {
        param($It)
        $t = $catalog[$It.Id]
        if (-not $t) { $It.Included = $false; $It.Notes.Add('Unknown item.'); return }
        if ($It.Origin -eq 'preset' -and ([string]$t.level -eq 'Lab' -or [string]$t.evidence.tier -eq 'R')) { $It.Included = $false; $It.Notes.Add('Lab and Risk Zone items are never part of a preset.'); return }
        $b = Get-IgwtHardwareBlock -Tweak $t -Tags $Tags
        if ($b) { $It.Included = $false; $It.Blocked = $true; $It.Notes.Add($b.Reason) }
    }

    # 1. Intent preset
    foreach ($id in @($Preset.include | Where-Object { $_ -and $excluded -notcontains $_ })) { & $addItem ([string]$id) 'preset' $true '' }
    foreach ($it in $items.ToArray()) { & $checkBlock $it }

    # 2. Hardware overlays (adds)
    foreach ($o in $active) {
        foreach ($id in @($o.add | Where-Object { $_ })) {
            $label = "'$($o.name)' ($(@($o.MatchedTags) -join ', '))"
            if ($index.ContainsKey([string]$id)) { if ($index[[string]$id].Included) { $index[[string]$id].Notes.Add("Also required by $label.") }; continue }
            $t = $catalog[[string]$id]
            if ($excluded -contains $id) { & $addItem ([string]$id) 'overlay' $false "Suggested by $label but excluded by the preset."; continue }
            if (-not $t) { continue }
            $rank = Get-IgwtLevelRank -Level ([string]$t.level)
            if ([string]$t.level -eq 'Lab' -or ($ceiling -ge 0 -and $rank -gt $ceiling)) { & $addItem ([string]$id) 'overlay' $false "Suggested by $label but above the preset's level ceiling ($($Preset.levelCeiling))."; continue }
            if ([string]$Preset.antiCheatPolicy -eq 'safeOnly' -and -not $t.antiCheatSafe) { & $addItem ([string]$id) 'overlay' $false "Suggested by $label but not anti-cheat safe."; continue }
            & $addItem ([string]$id) 'overlay' $true "Added by ${label}: $($o.hint)"
            & $checkBlock $index[[string]$id]
        }
    }

    # 3. User add-ons and removals
    foreach ($id in @($AddIds | Where-Object { $_ })) {
        if ($index.ContainsKey([string]$id)) {
            $it = $index[[string]$id]
            if (-not $it.Included -and -not $it.Blocked) { $it.Included = $true; $it.Origin = 'user'; $it.Notes.Add('Added by you.') }
            continue
        }
        & $addItem ([string]$id) 'user' $true 'Added by you.'
        & $checkBlock $index[[string]$id]
    }
    foreach ($id in @($RemoveIds | Where-Object { $_ })) {
        if ($index.ContainsKey([string]$id)) { $index[[string]$id].Included = $false; $index[[string]$id].Notes.Add('Removed by you.') }
    }

    [pscustomobject]@{
        Preset   = [string]$Preset.id
        Name     = [string]$Preset.name
        Tags     = @($Tags)
        Overlays = @($active | ForEach-Object { [pscustomobject]@{ Id = [string]$_.id; Name = [string]$_.name; Tags = @($_.MatchedTags); Hint = [string]$_.hint; Guidance = @($_.guidance | Where-Object { $_ }) } })
        Items    = $items.ToArray()
        Ids      = @($items | Where-Object { $_.Included } | ForEach-Object { $_.Id })
        Blocked  = @($items | Where-Object { $_.Blocked } | ForEach-Object { $_.Id })
        Guidance = @($active | ForEach-Object { @($_.guidance | Where-Object { $_ }) })
    }
}

function Test-IgwtHardwareCatalog {
    <# .SYNOPSIS Validates data\hardware (tags, detection rules, overlays). Returns error strings. #>
    [CmdletBinding()]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $tagIds = @(Get-IgwtHardwareTagDefinitions -Force | ForEach-Object { [string]$_.id })
    $catalogIds = @(Get-IgwtCatalog | ForEach-Object { [string]$_.id })
    $detected = @{}
    foreach ($r in @(Get-IgwtDetectionRules -Force)) {
        $label = "detection rule for '$($r.tag)'"
        if ($tagIds -notcontains [string]$r.tag) { $errors.Add("${label}: unknown tag.") }
        $detected[[string]$r.tag] = $true
        if (-not $r.basis) { $errors.Add("${label}: missing 'basis'.") }
        if ($r.source -and [string]$r.source -notmatch '^https://') { $errors.Add("${label}: source must be https.") }
        $conds = @()
        if ($null -ne $r.PSObject.Properties['anyOf']) { $conds = @($r.anyOf) } elseif ($null -ne $r.PSObject.Properties['when']) { $conds = @($r.when) }
        if ($conds.Count -eq 0) { $errors.Add("${label}: needs 'when' or 'anyOf'.") }
        foreach ($c in $conds) {
            foreach ($p in $c.PSObject.Properties) {
                if ($script:IgwtDetectionKeys -notcontains $p.Name) { $errors.Add("${label}: unknown condition '$($p.Name)'.") ; continue }
                if ($p.Name -in 'cpuVendor', 'cpuName', 'cpuNameNot', 'gpuName', 'gpuPnp', 'nicName', 'nicPnp', 'systemDiskBus', 'systemDiskMedia') {
                    try { $null = [regex]::new([string]$p.Value) } catch { $errors.Add("${label}: invalid regex in '$($p.Name)'.") }
                }
            }
        }
    }
    foreach ($t in $tagIds) { if (-not $detected.ContainsKey($t)) { $errors.Add("hardware tag '$t': no detection rule.") } }
    $ids = @{}
    foreach ($o in @(Get-IgwtHardwareOverlays -Force)) {
        $oid = [string]$o.id
        $label = "overlay '$oid'"
        if ($oid -notmatch '^overlay\.[a-z0-9\-]+$') { $errors.Add("${label}: id must look like 'overlay.name'.") }
        if ($ids.ContainsKey($oid)) { $errors.Add("${label}: duplicate id.") } else { $ids[$oid] = $true }
        if (-not $o.name) { $errors.Add("${label}: missing 'name'.") }
        Test-IgwtItemText -Item $o -Label $label -Errors $errors
        if (@($o.tags).Count -eq 0) { $errors.Add("${label}: needs at least one tag.") }
        foreach ($t in @($o.tags)) { if ($tagIds -notcontains [string]$t) { $errors.Add("${label}: unknown tag '$t'.") } }
        if ([string]$o.basis -notin 'vendor', 'reviewer', 'igwt') { $errors.Add("${label}: basis must be vendor, reviewer or igwt.") }
        $sources = @($o.sources | Where-Object { $_ })
        if ($sources.Count -eq 0) { $errors.Add("${label}: needs at least one source.") }
        foreach ($s in $sources) { if ([string]$s -notmatch '^https://') { $errors.Add("${label}: source '$s' must be https.") } }
        $block = @($o.block | Where-Object { $_ }); $add = @($o.add | Where-Object { $_ }); $guide = @($o.guidance | Where-Object { $null -ne $_ })
        $effects = $block.Count + @($o.blockMatching | Where-Object { $_ }).Count + $add.Count + $guide.Count
        if ($effects -eq 0) { $errors.Add("${label}: needs block, blockMatching, add or guidance.") }
        foreach ($id in $block + $add) { if ($catalogIds -notcontains [string]$id) { $errors.Add("${label}: unknown item '$id'.") } }
        foreach ($id in $add) { if ($block -contains $id) { $errors.Add("${label}: '$id' is both added and blocked.") } }
        foreach ($m in @($o.blockMatching | Where-Object { $_ })) {
            if ($null -eq $m.PSObject.Properties['type']) { $errors.Add("${label}: every blockMatching entry needs 'type'.") }
            foreach ($p in $m.PSObject.Properties) { if ($script:IgwtOverlayMatchKeys -notcontains $p.Name) { $errors.Add("${label}: unknown blockMatching field '$($p.Name)'.") } }
        }
        foreach ($g in $guide) { if (-not ([string]$g).Trim()) { $errors.Add("${label}: empty guidance text.") } }
    }
    return $errors.ToArray()
}
