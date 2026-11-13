# SecSettingsCatalog.ps1
# Security Settings Manager (3.8, DECISIONS SM1-SM43): the data files in data\security, the ADMX
# policies in scope (SM5) and the owned-set overlap index (SM8). Read-only. Defender preference
# names, exclusion names and Tamper-locked names live only in the JSON data (SM2).

$script:IgwtSecSettingsData = $null

function Get-IgwtSecSettingsData {
    <#
    .SYNOPSIS
        The four data\security files (categories, settings-meta, weakening, baseline), loaded once
        and cached: {Categories; Meta; Weakening; Baseline}. Read-only.
    #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSecSettingsData) { return $script:IgwtSecSettingsData }
    $dir = Join-Path (Get-IgwtDataFolder) 'security'
    $read = { param($n) Get-Content -LiteralPath (Join-Path $dir $n) -Raw -ErrorAction Stop | ConvertFrom-Json }
    $script:IgwtSecSettingsData = [pscustomobject]@{
        Categories = (& $read 'categories.json'); Meta = (& $read 'settings-meta.json')
        Weakening = (& $read 'weakening.json'); Baseline = (& $read 'baseline.json')
    }
    return $script:IgwtSecSettingsData
}

function Test-IgwtSecSettingsCatalog {
    <#
    .SYNOPSIS
        Validates data\security (DECISIONS SM2, SM5, SM14, SM18, SM25, SM32): schema versions, https
        sources, enums, the UEFI-lock tuple shape, regular expressions that compile, and, with
        -DocumentedPath, that mpCoverage maps every documented Defender preference parameter. Returns error
        strings (empty when valid). Read-only.
    .PARAMETER DocumentedPath
        The documented Defender preference parameter list (the JSON fixture in tests\fixtures\secsettings).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$DocumentedPath)
    $dir = Join-Path (Get-IgwtDataFolder) 'security'
    $docs = @{}
    foreach ($n in 'categories.json', 'settings-meta.json', 'weakening.json', 'baseline.json') {
        $p = Join-Path $dir $n
        if (-not (Test-Path -LiteralPath $p)) { "security\${n}: missing."; continue }
        try { $docs[$n] = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } catch { "security\${n}: not valid JSON ($($_.Exception.Message))."; continue }
        if ([int]$docs[$n].schemaVersion -ne 1) { "security\${n}: schemaVersion must be 1." }
    }
    $https = { param($u) [string]$u -match '^https://' }
    if ($docs['categories.json']) {
        $seen = @{}
        foreach ($e in @($docs['categories.json'].entries)) {
            if (-not $e.namespace -or -not $e.category -or -not $e.label -or -not $e.reason) { "security\categories.json: every entry needs namespace, category, label and reason."; continue }
            $k = "$($e.namespace)|$($e.category)".ToLowerInvariant()
            if ($seen.ContainsKey($k)) { "security\categories.json: duplicate entry $($e.namespace) $($e.category)." }
            $seen[$k] = $true
        }
    }
    if ($docs['weakening.json']) {
        foreach ($e in @($docs['weakening.json'].entries)) {
            foreach ($rx in @($e.key, $e.valueName)) { try { $null = [regex]::new([string]$rx) } catch { "security\weakening.json: '$rx' is not a valid regular expression." } }
            if (-not @($e.values).Count) { "security\weakening.json: $($e.valueName) has no values." }
            if (-not $e.reason) { "security\weakening.json: $($e.valueName) has no reason." }
            if ([string]$e.source -ne 'source pending' -and -not (& $https $e.source)) { "security\weakening.json: $($e.valueName) needs an https source or 'source pending'." }
            if ([string]$e.class -notin 'Machine', 'User', 'Both') { "security\weakening.json: $($e.valueName) class must be Machine, User or Both." }
        }
    }
    if ($docs['settings-meta.json']) {
        $m = $docs['settings-meta.json']
        foreach ($p in @($m.settings.PSObject.Properties)) {
            $s = $p.Value
            if ([string]$s.risk -notin 'normal', 'medium', 'high') { "security\settings-meta.json: $($p.Name) risk must be normal, medium or high." }
            if ($s.restart -and [string]$s.restart -notin 'none', 'reboot', 'signOut', 'appRestart', 'immediate', 'unknown') { "security\settings-meta.json: $($p.Name) has an unknown restart value '$($s.restart)'." }
            foreach ($c in @($s.riskClass)) { if ($c -and [string]$c -notin 'lockout', 'uefiLock', 'oneWay') { "security\settings-meta.json: $($p.Name) has an unknown riskClass '$c'." } }
            foreach ($u in @($s.sources)) { if (-not (& $https $u)) { "security\settings-meta.json: $($p.Name) source '$u' is not https." } }
            foreach ($x in @($s.sideEffects)) { if (-not $x.text -or -not (& $https $x.url)) { "security\settings-meta.json: $($p.Name) side effects need text and an https url." } }
        }
        foreach ($t in @($m.uefiLockValues)) {
            if ([string]$t.class -notin 'Machine', 'User' -or -not $t.key -or -not $t.valueName -or $null -eq $t.value -or -not (& $https $t.source)) { "security\settings-meta.json: every uefiLockValues tuple needs class, key, valueName, value and an https source." }
        }
        $cov = @{}
        foreach ($p in @($m.mpCoverage.PSObject.Properties)) {
            $cov[$p.Name] = [string]$p.Value
            if ([string]$p.Value -notin 'catalog', 'excluded', 'readOnly', 'coveredElsewhere:asr', 'coveredElsewhere:exclusion', 'coveredElsewhere:cfa') { "security\settings-meta.json: mpCoverage '$($p.Name)' has an unknown value '$($p.Value)'." }
        }
        if ($DocumentedPath) {
            $doc = Get-Content -LiteralPath $DocumentedPath -Raw | ConvertFrom-Json
            foreach ($d in @($doc.parameters)) { if (-not $cov.ContainsKey([string]$d.name)) { "security\settings-meta.json: the documented Defender preference parameter '$($d.name)' is not in mpCoverage." } }
        }
        foreach ($o in @($m.reviewedOverlaps)) { if (-not $o.a -or -not $o.b -or -not $o.reason) { "security\settings-meta.json: every reviewedOverlaps entry needs a, b and reason." } }
    }
    if ($docs['baseline.json']) {
        $b = $docs['baseline.json']
        if (-not $b.baseline -or -not (& $https $b.baseline.url)) { "security\baseline.json: baseline needs a name, version and an https url." }
        foreach ($e in @($b.entries)) { if (-not $e.id -or $null -eq $e.value -or -not (& $https $e.source)) { "security\baseline.json: every entry needs id, value and an https source." } }
    }
}

function Get-IgwtSecSettingMeta {
    <#
    .SYNOPSIS
        The settings-meta.json facts of one setting id, or $null. A key ending in * matches every id
        with that prefix; an exact key wins over a prefix key, and a longer prefix over a shorter one.
        Read-only.
    .PARAMETER Id
        The setting id (DECISIONS SM3).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $settings = (Get-IgwtSecSettingsData).Meta.settings
    $best = $null; $bestLen = -1
    foreach ($p in @($settings.PSObject.Properties)) {
        $k = [string]$p.Name
        if ([string]::Equals($k, $Id, [System.StringComparison]::OrdinalIgnoreCase)) { return $p.Value }
        if ($k.EndsWith('*') -and $Id.StartsWith($k.Substring(0, $k.Length - 1), [System.StringComparison]::OrdinalIgnoreCase) -and $k.Length -gt $bestLen) { $best = $p.Value; $bestLen = $k.Length }
    }
    return $best
}

function Get-IgwtSecSettingDefinitions {
    <#
    .SYNOPSIS
        The ADMX policies in scope of the Security Settings Manager (DECISIONS SM5): a policy is in
        scope when its namespace has a '*' entry in categories.json, or its category or any parent
        category is listed. ASR, exclusion and Controlled Folder Access policies are left out: they
        have their own source kinds (SM3). Returns {Policy; CategoryLabel}. Read-only.
    .PARAMETER Catalog
        A Get-IgwtAdmxCatalog result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Catalog)
    $entries = @((Get-IgwtSecSettingsData).Categories.entries)
    $whole = @{}; $named = @{}
    foreach ($e in $entries) {
        if ([string]$e.category -eq '*') { $whole[([string]$e.namespace).ToLowerInvariant()] = [string]$e.label }
        else { $named[("$($e.namespace):$($e.category)").ToLowerInvariant()] = [string]$e.label }
    }
    $parents = @{}
    foreach ($c in @($Catalog.Categories)) { if ($c -and $c.Id) { $parents[([string]$c.Id).ToLowerInvariant()] = ([string]$c.Parent).ToLowerInvariant() } }
    $skip = '(?i):(ExploitGuard_ASR|Exclusions|ExploitGuard_ControlledFolderAccess)$'
    foreach ($p in @($Catalog.Policies)) {
        if (-not $p) { continue }
        $ns = ([string]$p.Namespace).ToLowerInvariant()
        $label = $null
        $cur = ([string]$p.Category).ToLowerInvariant(); $guard = 0; $chain = @()
        while ($cur -and $guard -lt 20) {
            $chain += $cur
            if (-not $label -and $named.ContainsKey($cur)) { $label = $named[$cur] }
            $cur = $(if ($parents.ContainsKey($cur)) { $parents[$cur] } else { '' }); $guard++
        }
        if (-not $label -and $whole.ContainsKey($ns)) { $label = $whole[$ns] }
        if (-not $label) { continue }
        if (@($chain | Where-Object { $_ -match $skip }).Count) { continue }
        [pscustomobject]@{ Policy = $p; CategoryLabel = $label }
    }
}

function Get-IgwtSecSettingOwnedSet {
    <#
    .SYNOPSIS
        The registry entries one ADMX policy writes (DECISIONS SM8): Pairs (lower-case 'key|valueName')
        and ListKeys (lower-case keys a list element owns entirely). Pure.
    .PARAMETER Policy
        A policy from Get-IgwtAdmxCatalog.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy)
    $pairs = New-Object 'System.Collections.Generic.HashSet[string]'
    $lists = New-Object 'System.Collections.Generic.HashSet[string]'
    $add = { param($k, $v) if ($k -and $v) { $null = $pairs.Add(("$k|$v").ToLowerInvariant()) } }
    $addList = { param($items) foreach ($i in @($items)) { if ($i) { & $add $i.Key $i.ValueName } } }
    & $add $Policy.Key $Policy.ValueName
    & $addList $Policy.EnabledList
    & $addList $Policy.DisabledList
    foreach ($e in @($Policy.Elements)) {
        if (-not $e) { continue }
        if ([string]$e.Type -eq 'list') { if ($e.Key) { $null = $lists.Add(([string]$e.Key).ToLowerInvariant()) }; continue }
        & $add $e.Key $e.ValueName
        if ($e.PSObject.Properties['TrueList']) { & $addList $e.TrueList; & $addList $e.FalseList }
        if ($e.PSObject.Properties['Items']) { foreach ($it in @($e.Items)) { if ($it) { & $addList $it.ValueList } } }
    }
    return [pscustomobject]@{ Pairs = $pairs; ListKeys = $lists }
}

function Get-IgwtSecSettingOverlapIndex {
    <#
    .SYNOPSIS
        Which policies share registry entries with another policy of the parsed catalog (DECISIONS
        SM8 condition 6): a shared key and value name, or a list key equal to or a parent of a key
        another policy writes. Pairs listed in settings-meta.json reviewedOverlaps are ignored.
        Returns a hashtable policy id -> sorted ids of the other policies. Computed over every
        policy of the catalog, because a write outside the security scope can collide too. Read-only.
    .PARAMETER Catalog
        A Get-IgwtAdmxCatalog result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Catalog)
    $reviewed = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($o in @((Get-IgwtSecSettingsData).Meta.reviewedOverlaps)) {
        if ($o -and $o.a -and $o.b) { $null = $reviewed.Add(("$($o.a)|$($o.b)").ToLowerInvariant()); $null = $reviewed.Add(("$($o.b)|$($o.a)").ToLowerInvariant()) }
    }
    $byPair = @{}; $byKey = @{}; $listOwners = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Catalog.Policies)) {
        if (-not $p) { continue }
        $owned = Get-IgwtSecSettingOwnedSet -Policy $p
        foreach ($pair in $owned.Pairs) {
            if (-not $byPair.ContainsKey($pair)) { $byPair[$pair] = New-Object System.Collections.Generic.List[string] }
            $byPair[$pair].Add([string]$p.Id)
            $k = $pair.Substring(0, $pair.LastIndexOf('|'))
            if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object 'System.Collections.Generic.HashSet[string]' }
            $null = $byKey[$k].Add([string]$p.Id)
        }
        foreach ($lk in $owned.ListKeys) {
            $listOwners.Add([pscustomobject]@{ Key = $lk; Id = [string]$p.Id })
            if (-not $byKey.ContainsKey($lk)) { $byKey[$lk] = New-Object 'System.Collections.Generic.HashSet[string]' }
            $null = $byKey[$lk].Add([string]$p.Id)
        }
    }
    $result = @{}
    $link = {
        param($a, $b)
        if ($a -eq $b -or $reviewed.Contains(("$a|$b").ToLowerInvariant())) { return }
        if (-not $result.ContainsKey($a)) { $result[$a] = New-Object 'System.Collections.Generic.HashSet[string]' }
        if (-not $result.ContainsKey($b)) { $result[$b] = New-Object 'System.Collections.Generic.HashSet[string]' }
        $null = $result[$a].Add($b)
        $null = $result[$b].Add($a)
    }
    foreach ($ids in $byPair.Values) { if ($ids.Count -gt 1) { foreach ($a in $ids) { foreach ($b in $ids) { & $link $a $b } } } }
    foreach ($lo in $listOwners) {
        foreach ($k in @($byKey.Keys)) {
            if ($k -eq $lo.Key -or $k.StartsWith($lo.Key + '\')) { foreach ($b in $byKey[$k]) { & $link $lo.Id $b } }
        }
    }
    $out = @{}
    foreach ($k in @($result.Keys)) { $out[$k] = @($result[$k] | Sort-Object) }
    return $out
}
