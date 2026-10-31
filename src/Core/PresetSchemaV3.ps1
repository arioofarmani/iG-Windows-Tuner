# PresetSchemaV3.ps1
# Declarative presets, schema v3 (3.6, DECISIONS T9 and T16): a preset is a list of catalog item ids
# with a desired value (on, default, unchanged), what it requires (build, edition, hardware), what
# it conflicts with, and notes. No paths, values or commands: the catalog says how an item is
# changed. In memory a v3 preset also carries the v2 fields (include, exclude, reset) that the
# resolver, the engine, the CLI and the GUI use. User presets are untrusted and validated strictly.

$script:IgwtPresetV3Keys = @('schemaVersion', 'id', 'name', 'version', 'description', 'order', 'code', 'tagline', 'hint', 'gaming', 'levelCeiling', 'antiCheatPolicy',
    'firewallScope', 'session', 'sessionPowerPlan', 'closeApps', 'guidance', 'requires', 'changes', 'conflicts', 'notes',
    'custom', 'basedOn', 'sha256', 'created')
$script:IgwtPresetV3Desired = @('on', 'default', 'unchanged')
$script:IgwtPresetV3RequiresKeys = @('minBuild', 'maxBuild', 'editions', 'hardware')
$script:IgwtPresetV3HardwareKeys = @('tags', 'excludeTags', 'battery', 'hybridCpu', 'gpuVendor')

function ConvertFrom-IgwtPresetV3 {
    <#
    .SYNOPSIS
        A schema v3 preset in the in-memory shape the resolver and engine use: include (desired
        on), exclude (desired unchanged: left as it is, and not added by a hardware overlay), reset
        (desired default), plus the v3 fields. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset)
    $p = [ordered]@{}
    foreach ($prop in $Preset.PSObject.Properties) { $p[$prop.Name] = $prop.Value }
    $changes = @($Preset.changes | Where-Object { $_ })
    $p['include'] = @($changes | Where-Object { [string]$_.desired -eq 'on' } | ForEach-Object { [string]$_.item })
    $p['exclude'] = @($changes | Where-Object { [string]$_.desired -eq 'unchanged' } | ForEach-Object { [string]$_.item })
    $p['reset'] = @($changes | Where-Object { [string]$_.desired -eq 'default' } | ForEach-Object { [string]$_.item })
    if (-not $p.Contains('levelCeiling')) { $p['levelCeiling'] = 'Advanced' }
    if (-not $p.Contains('antiCheatPolicy')) { $p['antiCheatPolicy'] = 'safeOnly' }
    if (-not $p.Contains('conflicts')) { $p['conflicts'] = @() }
    return [pscustomobject]$p
}

function Test-IgwtPresetV3Document {
    <#
    .SYNOPSIS
        Strict structure check of a schema v3 preset document (built-in or a user's, which is
        untrusted): only known fields with the right types, item ids that exist, desired values
        on, default or unchanged, no duplicates, sane sizes. Adds readable error strings to Errors.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Document, [Parameter(Mandatory = $true)][hashtable]$CatalogIndex,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    $d = $Document
    $label = "preset $(if ($d.id) { [string]$d.id } else { '(no id)' })"
    foreach ($k in @($d.PSObject.Properties.Name)) { if ($script:IgwtPresetV3Keys -notcontains $k) { $Errors.Add("${label}: unknown field '$k'.") } }
    if ([int]$d.schemaVersion -ne 3) { $Errors.Add("${label}: schemaVersion must be 3.") }
    if ([string]$d.id -notmatch '^[a-z0-9][a-z0-9\-]{1,39}$') { $Errors.Add("${label}: id must be 2-40 lower-case letters, digits or hyphens.") }
    if (-not [string]$d.name -or ([string]$d.name).Length -gt 60) { $Errors.Add("${label}: name is required (60 characters or fewer).") }
    if ($d.PSObject.Properties['version'] -and [string]$d.version -notmatch '^\d+\.\d+(\.\d+)?$') { $Errors.Add("${label}: version must look like 1.0 or 1.0.0.") }
    if ($d.PSObject.Properties['notes'] -and $d.notes -isnot [string]) { $Errors.Add("${label}: notes must be text.") }
    $changes = @($d.changes)
    if (-not $d.PSObject.Properties['changes'] -or $changes.Count -eq 0) { $Errors.Add("${label}: changes must list at least one item.") }
    if ($changes.Count -gt 500) { $Errors.Add("${label}: more than 500 changes.") }
    $seen = @{}
    foreach ($c in $changes) {
        if (-not $c -or $c -is [string] -or -not $c.PSObject.Properties['item']) { $Errors.Add("${label}: every change is an object with item and desired."); continue }
        foreach ($k in @($c.PSObject.Properties.Name)) { if ($k -notin 'item', 'desired') { $Errors.Add("${label}: change '$($c.item)' has unknown field '$k' (only item and desired; the catalog says how an item is changed).") } }
        $id = [string]$c.item
        if (-not $CatalogIndex.ContainsKey($id)) { $Errors.Add("${label}: unknown item '$id'.") }
        if ($script:IgwtPresetV3Desired -notcontains [string]$c.desired) { $Errors.Add("${label}: item '$id' has desired '$($c.desired)'; use on, default or unchanged.") }
        if ($seen.ContainsKey($id)) { $Errors.Add("${label}: item '$id' is listed twice.") } else { $seen[$id] = $true }
    }
    if ($d.PSObject.Properties['requires'] -and $null -ne $d.requires) {
        $r = $d.requires
        foreach ($k in @($r.PSObject.Properties.Name)) { if ($script:IgwtPresetV3RequiresKeys -notcontains $k) { $Errors.Add("${label}: requires has unknown field '$k'.") } }
        foreach ($k in 'minBuild', 'maxBuild') { if ($r.PSObject.Properties[$k] -and "$($r.$k)" -notmatch '^\d{5}$') { $Errors.Add("${label}: requires.$k must be a Windows build number.") } }
        foreach ($e in @($r.editions | Where-Object { $_ })) { if ([string]$e -notin 'Home', 'Professional', 'Enterprise', 'Education', 'Server') { $Errors.Add("${label}: requires.editions '$e' is not Home, Professional, Enterprise, Education or Server.") } }
        if ($r.PSObject.Properties['hardware'] -and $r.hardware) {
            foreach ($k in @($r.hardware.PSObject.Properties.Name)) { if ($script:IgwtPresetV3HardwareKeys -notcontains $k) { $Errors.Add("${label}: requires.hardware has unknown field '$k'.") } }
            $known = @{}; foreach ($tg in @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'hardware\tags.json')).tags)) { $known[[string]$tg.id] = $true }
            foreach ($tg in @($r.hardware.tags) + @($r.hardware.excludeTags) | Where-Object { $_ }) { if (-not $known.ContainsKey([string]$tg)) { $Errors.Add("${label}: unknown hardware tag '$tg'.") } }
            foreach ($k in 'battery', 'hybridCpu') { if ($r.hardware.PSObject.Properties[$k] -and $r.hardware.$k -isnot [bool]) { $Errors.Add("${label}: requires.hardware.$k must be true or false.") } }
            if ($r.hardware.PSObject.Properties['gpuVendor'] -and [string]$r.hardware.gpuVendor -notin 'nvidia', 'amd', 'intel') { $Errors.Add("${label}: requires.hardware.gpuVendor must be nvidia, amd or intel.") }
        }
    }
    foreach ($c in @($d.conflicts | Where-Object { $_ })) {
        if ($c -is [string]) { $Errors.Add("${label}: every conflict is an object with item or feature, reason and source."); continue }
        foreach ($k in @($c.PSObject.Properties.Name)) { if ($k -notin 'item', 'feature', 'reason', 'source') { $Errors.Add("${label}: a conflict has unknown field '$k'.") } }
        if ([string]$c.item -and -not $CatalogIndex.ContainsKey([string]$c.item)) { $Errors.Add("${label}: conflict names unknown item '$($c.item)'.") }
        if (-not [string]$c.item -and -not [string]$c.feature) { $Errors.Add("${label}: a conflict needs an item or a feature.") }
        if (-not [string]$c.reason) { $Errors.Add("${label}: a conflict needs a reason.") }
        if ([string]$c.source -and [string]$c.source -notmatch '^https://|^DECISIONS [A-Z]{1,3}\d{1,3}[a-z]?$') { $Errors.Add("${label}: a conflict source must be an https URL or a DECISIONS ID.") }
    }
    # No raw paths, registry keys or commands in what a preset changes (the catalog owns how items change;
    # names, descriptions and notes are text, shown and never run).
    $json = ConvertTo-Json -InputObject ([ordered]@{ changes = $d.changes; requires = $d.requires; conflicts = @($d.conflicts | Where-Object { $_ -and $_ -isnot [string] } | ForEach-Object { [ordered]@{ item = $_.item; feature = $_.feature } }) }) -Depth 8 -Compress
    if ($json -match '(?i)HK(LM|CU|U|CR)[:\\]|\\\\[a-z]|[a-z]:\\\\|cmd\.exe|reg\.exe|\.(ps1|exe|bat|cmd)\b') { $Errors.Add("${label}: contains a path or command; presets only name catalog items.") }
}

function Test-IgwtPresetRequirement {
    <#
    .SYNOPSIS
        Why a preset does not apply to this PC (requires: build, edition, hardware), or '' when it
        does. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Preset, $Context)
    $r = $Preset.requires
    if (-not $r) { return '' }
    if (-not $Context) { $Context = New-IgwtContext }
    $build = [int](Get-IgwtWindowsBuildInfo).Build
    if ($r.PSObject.Properties['minBuild'] -and $build -lt [int]$r.minBuild) { return "Needs Windows build $($r.minBuild) or later; this PC runs $build." }
    if ($r.PSObject.Properties['maxBuild'] -and $build -gt [int]$r.maxBuild) { return "Made for Windows builds up to $($r.maxBuild); this PC runs $build." }
    $eds = @($r.editions | Where-Object { $_ })
    if ($eds.Count) { $fam = [string](Get-IgwtEditionFamily -EditionId ([string](Get-IgwtOsInfo).EditionId)); if ($eds -notcontains $fam) { return "Needs Windows $($eds -join ' or '); this PC runs $fam." } }
    $hw = $r.hardware
    if ($hw) {
        $tags = @($Context.HardwareTags)
        foreach ($tg in @($hw.tags | Where-Object { $_ })) { if ($tags -notcontains [string]$tg) { return "Needs hardware '$tg'." } }
        foreach ($tg in @($hw.excludeTags | Where-Object { $_ })) { if ($tags -contains [string]$tg) { return "Not for hardware '$tg'." } }
        if ($hw.PSObject.Properties['battery'] -and [bool]$hw.battery -ne ($tags -contains 'formfactor.laptop')) { return $(if ($hw.battery) { 'Made for PCs with a battery.' } else { 'Made for PCs without a battery.' }) }
        if ($hw.PSObject.Properties['hybridCpu'] -and [bool]$hw.hybridCpu -ne ($tags -contains 'intel.hybrid')) { return $(if ($hw.hybridCpu) { 'Made for hybrid CPUs (P-cores and E-cores).' } else { 'Made for CPUs without E-cores.' }) }
        if ($hw.PSObject.Properties['gpuVendor'] -and $tags -notcontains ('gpu.' + [string]$hw.gpuVendor)) { return "Made for $($hw.gpuVendor) graphics." }
    }
    return ''
}

function Get-IgwtPresetPreview {
    <#
    .SYNOPSIS
        What applying a preset would do on this PC, read-only (DECISIONS T16): one row per item with
        Class AlreadySet, WillChange, NotApplicable, Conflict or ManagedByPolicy and the reason, and
        a summary line ("12 will change, 30 already set, ..."). Hardware overlays, the preset's
        requirements and conflicts and the catalog's conflicting pairs are taken into account.
    .PARAMETER States
        Item states already read (id -> Get-IgwtTweakState result); missing ones are detected.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [string[]]$Tags, $Context, [string[]]$AddIds = @(), [string[]]$RemoveIds = @(), [hashtable]$States)
    if ($Preset -is [string]) { $Preset = Get-IgwtPreset -Name $Preset }
    if (-not $Context) { $Context = New-IgwtContext }
    if ($null -eq $Tags) { $Tags = @($Context.HardwareTags) }
    $req = Test-IgwtPresetRequirement -Preset $Preset -Context $Context
    $sel = Resolve-IgwtPresetSelection -Preset $Preset -Tags $Tags -AddIds $AddIds -RemoveIds $RemoveIds
    $catalog = @{}; foreach ($t in @(Get-IgwtCatalog)) { $catalog[[string]$t.id] = $t }
    # Item states the caller already has (the GUI keeps them from its last refresh); the rest are detected.
    $known = @{}
    if ($States) { foreach ($k in $States.Keys) { $known[[string]$k] = $States[$k] } }
    $stateOf = { param($id) if (-not $known.ContainsKey($id)) { $known[$id] = $(if ($catalog[$id]) { Get-IgwtTweakState -Tweak $catalog[$id] -Context $Context } else { $null }) }; $known[$id] }
    $rows = New-Object System.Collections.Generic.List[object]
    $resetIds = @($Preset.reset | Where-Object { $_ })
    $wanted = @($sel.Ids) + $resetIds
    $presetConflicts = @($Preset.conflicts | Where-Object { $_ -and [string]$_.item })
    foreach ($it in @($sel.Items) + @($resetIds | ForEach-Object { [pscustomobject]@{ Id = $_; Included = $true; Blocked = $false; Origin = 'preset'; Notes = @() } })) {
        $id = [string]$it.Id
        $t = $catalog[$id]
        $desired = $(if ($resetIds -contains $id) { 'default' } else { 'on' })
        $row = [ordered]@{ Id = $id; Name = $(if ($t) { [string]$t.name } else { $id }); Desired = $desired; Origin = [string]$it.Origin; Class = ''; Reason = (@($it.Notes) -join ' ') }
        if (-not $it.Included) {
            if (-not $it.Blocked -and [string]$it.Origin -eq 'overlay') { continue }   # a suggestion the preset's rules left out
            $row.Class = 'NotApplicable'
        } elseif ($req) { $row.Class = 'NotApplicable'; $row.Reason = $req }
        else {
            $s = & $stateOf $id
            if (-not $s) { $row.Class = 'NotApplicable'; $row.Reason = 'Unknown item.' }
            elseif ($s.State -eq 'NotApplicable') { $row.Class = 'NotApplicable'; $row.Reason = [string]$s.Reason }
            elseif ($s.State -eq 'ManagedByPolicy' -or ($s.PSObject.Properties['Authority'] -and $s.Authority)) { $row.Class = 'ManagedByPolicy'; $row.Reason = $(if ($s.Authority) { [string]$s.Authority } else { [string]$s.Reason }) }
            elseif ($desired -eq 'default') {
                $changed = Test-IgwtTweakChangedFromDefault -Tweak $t -State $s -Context $Context
                $row.Class = $(if ($changed) { 'WillChange' } else { 'AlreadySet' })
                if ($changed) { $row.Reason = 'Reset to the Windows default.' }
            } else { $row.Class = $(if ($s.State -eq 'On') { 'AlreadySet' } else { 'WillChange' }) }
            # A catalog pair (conflictsWith) is two values of the same setting: turning this one on
            # replaces the other, so it is noted, not a conflict. Conflicts are the ones a preset names.
            if ($row.Class -eq 'WillChange' -and $desired -eq 'on') {
                foreach ($c in @($t.conflictsWith | Where-Object { $_ })) {
                    if ($wanted -contains [string]$c) { continue }
                    $cs = & $stateOf ([string]$c)
                    if ($cs -and $cs.State -in 'On', 'Partial') { $row.Reason = (("$($row.Reason) Replaces '$c', which is on now.").Trim()) }
                }
            }
        }
        $rows.Add([pscustomobject]$row)
    }
    foreach ($c in $presetConflicts) {
        $cs = & $stateOf ([string]$c.item)
        if ($cs -and $cs.State -in 'On', 'Partial') { $rows.Add([pscustomobject]@{ Id = [string]$c.item; Name = $(if ($catalog[[string]$c.item]) { [string]$catalog[[string]$c.item].name } else { [string]$c.item }); Desired = 'conflict'; Origin = 'preset'; Class = 'Conflict'; Reason = [string]$c.reason }) }
    }
    $count = { param($k) @($rows | Where-Object { $_.Class -eq $k }).Count }
    $summary = '{0} will change, {1} already set, {2} not applicable, {3} conflict(s), {4} managed by policy.' -f (& $count 'WillChange'), (& $count 'AlreadySet'), (& $count 'NotApplicable'), (& $count 'Conflict'), (& $count 'ManagedByPolicy')
    if ($req) { $summary = "$req $summary" }
    $features = @($Preset.conflicts | Where-Object { $_ -and [string]$_.feature } | ForEach-Object { "$($_.feature): $($_.reason)" })
    return [pscustomobject]@{ Preset = [string]$Preset.id; Name = [string]$Preset.name; Requirement = $req; Summary = $summary; Rows = $rows.ToArray(); Notes = [string]$Preset.notes; FeatureConflicts = $features; Selection = $sel }
}
