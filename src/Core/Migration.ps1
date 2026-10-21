# Migration.ps1
# v1 -> v2 data migration. The converters are pure (objects in, ordered dictionaries out) and are
# used in two places: the loaders upgrade v1 entries in memory, so old files and snapshots keep
# working, and tools\Convert-IgwtV1Data.ps1 rewrites v1 data files on disk. Action definitions are
# never changed, so snapshot fingerprints (and therefore every v1 snapshot) stay valid.

$script:IgwtTweakKeyOrder = @('id', 'name', 'category', 'group', 'order', 'level', 'hint', 'description', 'warning', 'evidence', 'impact', 'risk',
    'antiCheat', 'reversible', 'sideEffects', 'requires', 'appliesTo', 'hardware', 'source', 'attribution', 'conflictsWith', 'status', 'statusReason',
    'policyKeys', 'postApply', 'revertNote')
$script:IgwtCleanerKeyOrder = @('id', 'name', 'category', 'level', 'tier', 'method', 'default', 'hint', 'description', 'sideEffects', 'antiCheat',
    'reversible', 'source', 'attribution', 'hardware', 'requiresAdmin')
$script:IgwtPresetKeyOrder = @('id', 'name', 'order', 'tagline', 'hint', 'description', 'gaming', 'levelCeiling', 'antiCheatPolicy', 'include', 'exclude')
$script:IgwtV1ConditionMap = [ordered]@{ wiredAdapter = 'wiredAdapter'; multipleGpus = 'multipleGpus'; nvidiaGpu = 'nvidiaGpu'; defender = 'defenderActive'; notRdp = 'notRdp' }

#region Helpers

function Test-IgwtHasProperty {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Get-IgwtPropertyNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()]$Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys | ForEach-Object { [string]$_ }) }
    return @($Object.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object { $_.Name })
}

function ConvertTo-IgwtOrderedCopy {
    <# .SYNOPSIS Shallow copy with the given keys first (when present), then the rest in their original order, Last keys at the end. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Object, [string[]]$Order = @(), [string[]]$Last = @(), [string[]]$Drop = @())
    $names = @(Get-IgwtPropertyNames -Object $Object)
    $out = [ordered]@{}
    foreach ($k in $Order) { if ($names -contains $k -and $Drop -notcontains $k) { $out[$k] = $Object.$k } }
    foreach ($k in $names) { if (-not $out.Contains($k) -and $Last -notcontains $k -and $Drop -notcontains $k) { $out[$k] = $Object.$k } }
    foreach ($k in $Last) { if ($names -contains $k -and -not $out.Contains($k) -and $Drop -notcontains $k) { $out[$k] = $Object.$k } }
    return $out
}

function ConvertTo-IgwtPSObject {
    <# .SYNOPSIS Deep copy that turns dictionaries into PSCustomObjects (the shape ConvertFrom-Json produces). #>
    [CmdletBinding()]
    param([AllowNull()]$InputObject)
    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary] -or $InputObject -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($k in @(Get-IgwtPropertyNames -Object $InputObject)) { $o[$k] = ConvertTo-IgwtPSObject -InputObject $InputObject.$k }
        return [pscustomobject]$o
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($x in $InputObject) { $list.Add((ConvertTo-IgwtPSObject -InputObject $x)) }
        return , $list.ToArray()
    }
    return $InputObject
}

function Get-IgwtIdMap {
    <# .SYNOPSIS Renamed item ids (old -> new) from data\migration\id-map.json, applied to v1 snapshots and presets. #>
    [CmdletBinding()]
    param([string]$DataFolder)
    if (-not $DataFolder) { $DataFolder = Get-IgwtDataFolder }
    $map = @{}
    $file = Join-Path $DataFolder 'migration\id-map.json'
    if (Test-Path -LiteralPath $file) {
        $doc = Read-IgwtJsonFile -Path $file
        foreach ($n in @(Get-IgwtPropertyNames -Object $doc.renamed)) { $map[$n] = [string]$doc.renamed.$n }
    }
    return $map
}

function Resolve-IgwtMappedId {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Id, [hashtable]$IdMap = @{})
    if ($Id -and $IdMap.ContainsKey($Id)) { return [string]$IdMap[$Id] }
    return $Id
}

#endregion

#region Item converters

function Get-IgwtV1TweakLevel {
    <#
    .SYNOPSIS
        Level for a v1 tweak: expert + not anti-cheat safe = Lab, other expert toggles = Expert,
        Tier B or medium/high risk = Advanced, everything else = Standard.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Tweak)
    $expert = [bool]$Tweak.expert
    $safe = $true
    if (Test-IgwtHasProperty -Object $Tweak -Name 'antiCheatSafe') { $safe = [bool]$Tweak.antiCheatSafe }
    if (-not $safe) { return 'Lab' }
    if ($expert) { return 'Expert' }
    if ([string]$Tweak.evidence.tier -eq 'B' -or [string]$Tweak.risk -in 'medium', 'high') { return 'Advanced' }
    return 'Standard'
}

function ConvertFrom-IgwtV1AntiCheat {
    <# .SYNOPSIS v1 antiCheatSafe (+ warning text) -> v2 antiCheat ("safe", "unknown" or { breaks }). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak)
    if (-not (Test-IgwtHasProperty -Object $Tweak -Name 'antiCheatSafe') -or [bool]$Tweak.antiCheatSafe) { return 'safe' }
    $text = "$($Tweak.warning) $($Tweak.description)"
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($k in $script:IgwtAntiCheatNames.Keys) {
        if ($text -match [regex]::Escape($k) -and -not $names.Contains($script:IgwtAntiCheatNames[$k])) { $names.Add($script:IgwtAntiCheatNames[$k]) }
    }
    if ($names.Count -eq 0) { return 'unknown' }
    return [ordered]@{ breaks = $names.ToArray() }
}

function ConvertTo-IgwtV2Tweak {
    <#
    .SYNOPSIS
        v1 tweak -> v2 tweak (ordered). Adds level, antiCheat, reversible, sideEffects, source and
        hardware; moves appliesTo.hardware conditions to appliesTo.conditions; drops antiCheatSafe
        and expert. Actions are copied unchanged. Already-v2 entries are only re-ordered.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak)
    $o = ConvertTo-IgwtOrderedCopy -Object $Tweak -Order $script:IgwtTweakKeyOrder -Last @('actions') -Drop @('antiCheatSafe', 'expert', 'sourceFile', 'sourceSchema', 'legacyFields', 'antiCheatText', 'tier')
    if (-not $o.Contains('level')) { $o['level'] = Get-IgwtV1TweakLevel -Tweak $Tweak }
    if (-not $o.Contains('antiCheat')) { $o['antiCheat'] = ConvertFrom-IgwtV1AntiCheat -Tweak $Tweak }
    if (-not $o.Contains('reversible')) { $o['reversible'] = 'full' }
    if (-not $o.Contains('sideEffects')) { $o['sideEffects'] = '' }
    if (-not $o.Contains('source')) { $o['source'] = 'igwt' }
    if (-not $o.Contains('hardware')) { $o['hardware'] = [ordered]@{ tags = @(); excludeTags = @() } }

    # appliesTo: build/edition limits plus runtime conditions (v1 kept them in appliesTo.hardware).
    $a = $null
    if ($o.Contains('appliesTo')) { $a = $o['appliesTo'] }
    $applies = [ordered]@{ minBuild = 26100 }
    if ($a) {
        foreach ($k in @(Get-IgwtPropertyNames -Object $a)) {
            if ($k -eq 'hardware') { continue }
            $applies[$k] = $a.$k
        }
        if ((Test-IgwtHasProperty -Object $a -Name 'hardware') -and $a.hardware) {
            $conds = New-Object System.Collections.Generic.List[string]
            foreach ($c in @(if ($applies.Contains('conditions')) { $applies['conditions'] })) { if ($c -and -not $conds.Contains([string]$c)) { $conds.Add([string]$c) } }
            foreach ($k in @(Get-IgwtPropertyNames -Object $a.hardware)) {
                if (-not $a.hardware.$k) { continue }
                $name = $k
                if ($script:IgwtV1ConditionMap.Contains($k)) { $name = $script:IgwtV1ConditionMap[$k] }
                if (-not $conds.Contains($name)) { $conds.Add($name) }
            }
            if ($conds.Count -gt 0) { $applies['conditions'] = $conds.ToArray() }
        }
    }
    $o['appliesTo'] = $applies
    return (ConvertTo-IgwtOrderedCopy -Object $o -Order $script:IgwtTweakKeyOrder -Last @('actions'))
}

function ConvertTo-IgwtV2CleanerRule {
    <#
    .SYNOPSIS
        Pre-v2 cleaner rule -> v2 rule (ordered): adds tier (A when the rule cites a source),
        antiCheat "safe", reversible (none, partial for Recycle Bin rules, full for guidance),
        source "igwt" and hardware. Existing values are kept.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule)
    $o = ConvertTo-IgwtOrderedCopy -Object $Rule -Order $script:IgwtCleanerKeyOrder -Last @('notes', 'sources') -Drop @('sourceFile', 'sourceSchema')
    if (-not $o.Contains('level')) { $o['level'] = 'Standard' }
    if (-not $o.Contains('tier')) { $o['tier'] = $(if (@($Rule.sources | Where-Object { $_ }).Count -gt 0) { 'A' } else { 'B' }) }
    if (-not $o.Contains('sideEffects')) { $o['sideEffects'] = '' }
    if (-not $o.Contains('antiCheat')) { $o['antiCheat'] = 'safe' }
    if (-not $o.Contains('reversible')) {
        $rev = 'none'
        if ([string]$Rule.method -eq 'guidance') { $rev = 'full' } elseif ([bool]$Rule.recycle) { $rev = 'partial' }
        $o['reversible'] = $rev
    }
    if (-not $o.Contains('source')) { $o['source'] = 'igwt' }
    if (-not $o.Contains('hardware')) { $o['hardware'] = [ordered]@{ tags = @(); excludeTags = @() } }
    return (ConvertTo-IgwtOrderedCopy -Object $o -Order $script:IgwtCleanerKeyOrder -Last @('notes', 'sources'))
}

function Get-IgwtDefaultPresetHint {
    <# .SYNOPSIS A preset hint (max 140 characters) from its tagline and the first sentence of its description. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Tagline, [string]$Description)
    $first = ''
    if ($Description -match '^(.+?[.!?])(\s|$)') { $first = $Matches[1] }
    $hint = ([string]$Tagline).Trim().TrimEnd('.')
    if ($hint -and $first -and ($hint.Length + 2 + $first.Length) -le 140) { return "${hint}: $first" }
    if ($hint) { if ($hint.Length -gt 140) { return $hint.Substring(0, 139).TrimEnd() + '.' } else { return "$hint." } }
    if ($first.Length -le 140) { return $first }
    return $first.Substring(0, 139).TrimEnd() + '.'
}

function ConvertTo-IgwtV2Preset {
    <#
    .SYNOPSIS
        v1 preset ({ tweaks }) -> v2 intent preset: include, exclude, levelCeiling, antiCheatPolicy,
        gaming and a hint. Renamed ids are mapped. Already-v2 presets are only re-ordered.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [hashtable]$IdMap = @{})
    $o = ConvertTo-IgwtOrderedCopy -Object $Preset -Order $script:IgwtPresetKeyOrder -Drop @('tweaks', 'sourceSchema', 'sourceFile')
    if (-not $o.Contains('include')) { $o['include'] = @(@($Preset.tweaks) | Where-Object { $_ } | ForEach-Object { Resolve-IgwtMappedId -Id ([string]$_) -IdMap $IdMap }) }
    if (-not $o.Contains('exclude')) { $o['exclude'] = @() }
    if (-not $o.Contains('levelCeiling')) { $o['levelCeiling'] = 'Advanced' }
    if (-not $o.Contains('antiCheatPolicy')) { $o['antiCheatPolicy'] = 'safeOnly' }
    if (-not $o.Contains('gaming')) { $o['gaming'] = $true }
    if (-not $o.Contains('hint')) { $o['hint'] = Get-IgwtDefaultPresetHint -Tagline ([string]$Preset.tagline) -Description ([string]$Preset.description) }
    return (ConvertTo-IgwtOrderedCopy -Object $o -Order $script:IgwtPresetKeyOrder)
}

function ConvertTo-IgwtV2Snapshot {
    <#
    .SYNOPSIS
        Upgrades a snapshot document to schema 2 (in memory): maps renamed ids, records the item
        level of each entry when the catalog knows it, and adds catalogSchema/hardwareTags.
        Captured action data and fingerprints are not touched, so the restore logic is unchanged.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Document, [object[]]$Catalog = @(), [hashtable]$IdMap = @{})
    $o = ConvertTo-IgwtOrderedCopy -Object $Document -Order @('schema', 'tool', 'version', 'id', 'created', 'operation', 'detail') -Last @('entries')
    $from = [int]$o['schema']
    if ($from -lt 2) { $o['migratedFrom'] = $from }
    $o['schema'] = 2
    if (-not $o.Contains('catalogSchema')) { $o['catalogSchema'] = $(if ($from -lt 2) { 1 } else { 2 }) }
    if (-not $o.Contains('hardwareTags')) { $o['hardwareTags'] = @() }
    $levels = @{}
    foreach ($t in @($Catalog)) { if ($t) { $levels[[string]$t.id] = [string]$t.level } }
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Document.entries | Where-Object { $null -ne $_ })) {
        $ne = ConvertTo-IgwtOrderedCopy -Object $e -Order @('tweakId', 'level', 'result', 'message', 'time') -Last @('actions')
        $mapped = Resolve-IgwtMappedId -Id ([string]$ne['tweakId']) -IdMap $IdMap
        if ($mapped -ne [string]$ne['tweakId']) { $ne['originalTweakId'] = [string]$ne['tweakId']; $ne['tweakId'] = $mapped }
        if (-not $ne.Contains('level') -and $levels.ContainsKey($mapped)) { $ne['level'] = $levels[$mapped] }
        $entries.Add([pscustomobject](ConvertTo-IgwtOrderedCopy -Object $ne -Order @('tweakId', 'originalTweakId', 'level', 'result', 'message', 'time') -Last @('actions')))
    }
    $o['entries'] = $entries.ToArray()
    return [pscustomobject]$o
}

#endregion

#region JSON writer

function ConvertTo-IgwtJsonString {
    <# .SYNOPSIS JSON string literal; non-ASCII and control characters are \u-escaped so data files stay ASCII. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    $sb = New-Object System.Text.StringBuilder ($Text.Length + 2)
    $null = $sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) { $null = $sb.Append('\"') }
        elseif ($code -eq 92) { $null = $sb.Append('\\') }
        elseif ($code -eq 10) { $null = $sb.Append('\n') }
        elseif ($code -eq 13) { $null = $sb.Append('\r') }
        elseif ($code -eq 9) { $null = $sb.Append('\t') }
        elseif ($code -lt 32 -or $code -gt 126) { $null = $sb.Append(('\u{0:x4}' -f $code)) }
        else { $null = $sb.Append($ch) }
    }
    $null = $sb.Append('"')
    return $sb.ToString()
}

function Test-IgwtJsonScalar {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Value)
    return ($null -eq $Value -or $Value -is [string] -or $Value -is [bool] -or $Value -is [char] -or $Value -is [datetime] -or $Value -is [enum] -or
        $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or
        $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte] -or $Value -is [uint16])
}

function ConvertTo-IgwtJsonScalar {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [enum]) { return (ConvertTo-IgwtJsonString -Text ([string]$Value)) }
    if ($Value -is [datetime]) { return (ConvertTo-IgwtJsonString -Text $Value.ToString('o', $inv)) }
    if ($Value -is [double] -or $Value -is [single]) { return ([double]$Value).ToString('R', $inv) }
    return ([System.IFormattable]$Value).ToString($null, $inv)
}

function ConvertTo-IgwtJsonText {
    <# .SYNOPSIS Recursive part of ConvertTo-IgwtJson. Inline when it fits in Width; otherwise one member per line. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value, [int]$Indent, [int]$Width, [string]$NewLine)
    if (Test-IgwtJsonScalar -Value $Value) { return (ConvertTo-IgwtJsonScalar -Value $Value) }
    $pad = ' ' * $Indent
    $inner = ' ' * ($Indent + 2)
    $isMap = ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject])
    if ($isMap) {
        $keys = @(Get-IgwtPropertyNames -Object $Value)
        if ($keys.Count -eq 0) { return '{}' }
        $parts = New-Object System.Collections.Generic.List[string]
        $simple = $true
        foreach ($k in $keys) {
            $v = $Value.$k
            if (-not (Test-IgwtJsonScalar -Value $v)) {
                if ($v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject]) { $simple = $false }
                else { foreach ($x in @($v)) { if (-not (Test-IgwtJsonScalar -Value $x)) { $simple = $false } } }
            }
            $parts.Add((ConvertTo-IgwtJsonString -Text $k) + ': ' + (ConvertTo-IgwtJsonText -Value $v -Indent ($Indent + 2) -Width $Width -NewLine $NewLine))
        }
        $line = '{ ' + ($parts -join ', ') + ' }'
        if ($simple -and ($Indent + $line.Length) -le $Width -and $line -notmatch "`n") { return $line }
        return '{' + $NewLine + (($parts | ForEach-Object { $inner + $_ }) -join (',' + $NewLine)) + $NewLine + $pad + '}'
    }
    # Any other enumerable is a JSON array.
    $items = @($Value)
    if ($items.Count -eq 0) { return '[]' }
    $rendered = @($items | ForEach-Object { ConvertTo-IgwtJsonText -Value $_ -Indent ($Indent + 2) -Width $Width -NewLine $NewLine })
    $allScalar = (@($items | Where-Object { -not (Test-IgwtJsonScalar -Value $_) }).Count -eq 0)
    $line = '[ ' + ($rendered -join ', ') + ' ]'
    if ($allScalar -and ($Indent + $line.Length) -le $Width) { return $line }
    return '[' + $NewLine + (($rendered | ForEach-Object { $inner + $_ }) -join (',' + $NewLine)) + $NewLine + $pad + ']'
}

function ConvertTo-IgwtJson {
    <#
    .SYNOPSIS
        Readable, ASCII-only JSON for data files (2-space indent; short objects and scalar arrays on
        one line). Unlike ConvertTo-Json in Windows PowerShell 5.1 it does not escape <, > or ' and
        has no depth limit.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowNull()]$InputObject, [int]$Width = 160)
    $nl = "`r`n"
    return (ConvertTo-IgwtJsonText -Value $InputObject -Indent 0 -Width $Width -NewLine $nl) + $nl
}

#endregion

#region File and folder conversion

function Get-IgwtDataFileKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Document)
    # v1 presets also have a 'tweaks' member, but it lists id strings instead of tweak objects.
    $firstTweak = $null
    if (Test-IgwtHasProperty -Object $Document -Name 'tweaks') { $firstTweak = @($Document.tweaks | Where-Object { $null -ne $_ }) | Select-Object -First 1 }
    if ((Test-IgwtHasProperty -Object $Document -Name 'include') -or (Test-IgwtHasProperty -Object $Document -Name 'tagline') -or $firstTweak -is [string]) { return 'preset' }
    if (Test-IgwtHasProperty -Object $Document -Name 'tweaks') { return 'tweaks' }
    if (Test-IgwtHasProperty -Object $Document -Name 'rules') { return 'cleaner' }
    return ''
}

function ConvertTo-IgwtV2DataDocument {
    <# .SYNOPSIS Converts one parsed data file (tweaks, cleaner rules or a preset) to its v2 document. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Document, [hashtable]$IdMap = @{})
    switch (Get-IgwtDataFileKind -Document $Document) {
        'tweaks' {
            $o = ConvertTo-IgwtOrderedCopy -Object $Document -Order @('schemaVersion', 'category') -Last @('tweaks')
            $o['schemaVersion'] = $script:IgwtSchemaVersion
            $o['tweaks'] = @(@($Document.tweaks) | Where-Object { $_ } | ForEach-Object { ConvertTo-IgwtV2Tweak -Tweak $_ })
            return (ConvertTo-IgwtOrderedCopy -Object $o -Order @('schemaVersion', 'category') -Last @('tweaks'))
        }
        'cleaner' {
            $o = ConvertTo-IgwtOrderedCopy -Object $Document -Order @('schemaVersion', 'category') -Last @('rules')
            $o['schemaVersion'] = $script:IgwtSchemaVersion
            $o['rules'] = @(@($Document.rules) | Where-Object { $_ } | ForEach-Object { ConvertTo-IgwtV2CleanerRule -Rule $_ })
            return (ConvertTo-IgwtOrderedCopy -Object $o -Order @('schemaVersion', 'category') -Last @('rules'))
        }
        'preset' {
            $p = ConvertTo-IgwtV2Preset -Preset $Document -IdMap $IdMap
            $o = [ordered]@{ schemaVersion = $script:IgwtSchemaVersion }
            foreach ($k in $p.Keys) { if ($k -ne 'schemaVersion') { $o[$k] = $p[$k] } }
            return $o
        }
        default { throw 'Not an iG Windows Tuner tweak, cleaner or preset document.' }
    }
}

function Convert-IgwtDataToV2 {
    <#
    .SYNOPSIS
        Converts the v1 data files under a data folder (tweaks\*.json, presets\*.json, cleaner\*.json)
        to schema v2 in place. Files that are already v2 and unchanged are left alone.
    .PARAMETER DataFolder
        The data folder to convert (default: this installation's data folder).
    .OUTPUTS
        One object per file: File, Kind, Items, FromSchema, Changed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$DataFolder)
    if (-not $DataFolder) { $DataFolder = Get-IgwtDataFolder }
    $idMap = Get-IgwtIdMap -DataFolder $DataFolder
    foreach ($sub in 'tweaks', 'presets', 'cleaner') {
        $dir = Join-Path $DataFolder $sub
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Sort-Object Name)) {
            $raw = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
            $doc = Read-IgwtJsonFile -Path $f.FullName
            $from = 1
            if (Test-IgwtHasProperty -Object $doc -Name 'schemaVersion') { $from = [int]$doc.schemaVersion }
            if ($from -gt $script:IgwtSchemaVersion) { throw "$($f.Name): schemaVersion $from is newer than this version of iG Windows Tuner supports." }
            $v2 = ConvertTo-IgwtV2DataDocument -Document $doc -IdMap $idMap
            $text = ConvertTo-IgwtJson -InputObject $v2
            $changed = ($text -ne $raw)
            $count = 1
            if ($v2.Contains('tweaks')) { $count = @($v2['tweaks']).Count } elseif ($v2.Contains('rules')) { $count = @($v2['rules']).Count }
            if ($changed -and $PSCmdlet.ShouldProcess($f.FullName, "Write schema v$($script:IgwtSchemaVersion)")) {
                [System.IO.File]::WriteAllText($f.FullName, $text, (New-Object System.Text.UTF8Encoding($false)))
            }
            [pscustomobject]@{ File = "$sub\$($f.Name)"; Kind = (Get-IgwtDataFileKind -Document $doc); Items = $count; FromSchema = $from; Changed = $changed }
        }
    }
    $script:IgwtCatalogCache = $null
    $script:IgwtCleanerRuleCache = $null
}

function Convert-IgwtSnapshotToV2 {
    <#
    .SYNOPSIS
        Writes a schema 2 copy of a snapshot file to another folder (archival). The original is never
        modified: iG Windows Tuner also reads v1 snapshots directly and upgrades them in memory.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Destination)
    $src = (Resolve-Path -LiteralPath $Path).ProviderPath
    if (-not (Test-Path -LiteralPath $Destination)) { if ($PSCmdlet.ShouldProcess($Destination, 'Create folder')) { $null = New-Item -ItemType Directory -Path $Destination -Force } }
    $dest = Join-Path (Resolve-Path -LiteralPath $Destination).ProviderPath (Split-Path $src -Leaf)
    if ([string]::Equals($dest, $src, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to overwrite the original snapshot; choose another destination folder.' }
    $doc = Read-IgwtJsonFile -Path $src
    if ($script:IgwtSnapshotToolNames -notcontains [string]$doc.tool) { throw "$src is not an iG Windows Tuner snapshot." }
    $v2 = ConvertTo-IgwtV2Snapshot -Document $doc -Catalog @(Get-IgwtCatalog) -IdMap (Get-IgwtIdMap)
    if ($PSCmdlet.ShouldProcess($dest, 'Write schema 2 snapshot copy')) {
        [System.IO.File]::WriteAllText($dest, (ConvertTo-IgwtJson -InputObject $v2), (New-Object System.Text.UTF8Encoding($false)))
    }
    return $dest
}

#endregion
