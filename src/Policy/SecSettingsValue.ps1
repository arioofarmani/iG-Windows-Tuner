# SecSettingsValue.ps1
# Security Settings Manager (3.8): value specs (DECISIONS SM4), decoding of Registry.pol entries
# into a policy state and element values (SM10), the round-trip and writability gate (SM8), the
# sceregvl.inf reader (SM22) and the unified row (SM3). Pure or read-only.

#region Value specs (SM4)

function New-IgwtSecSettingElement {
    <# .SYNOPSIS One value-spec element with every SM4 field (unused fields $null). Pure. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$Kind, [string]$Label = '', [hashtable]$More = @{})
    $e = [ordered]@{ Id = $Id; Kind = $Kind; Label = $(if ($Label) { $Label } else { $Id }); Required = $false; Default = $null; Min = $null; Max = $null; Unit = ''; Step = $null
        MaxLength = $null; Pattern = ''; MaxStrings = $null; Expandable = $false; PathKind = ''; Choices = @(); Bits = @(); ValuePrefix = ''; Additive = $false; Suggestions = @() }
    foreach ($k in @($More.Keys)) { $e[$k] = $More[$k] }
    return [pscustomobject]$e
}

function ConvertTo-IgwtSecSettingValueSpec {
    <#
    .SYNOPSIS
        The value spec of a setting (DECISIONS SM4): @{ Mode = tristate | value | none; Elements }.
        admx: one element per ADMX element (list with explicitValue becomes keyValueList; enum
        choices carry their Index). defender: from a data\defender\settings.json entry. secpol: from
        a Read-IgwtSceRegVlInf entry (RegType 3 = binary: Mode none). audit: one enum. Pure.
    .PARAMETER SourceKind
        admx, defender, secpol or audit.
    .PARAMETER Definition
        The ADMX policy, Defender catalog entry or sceregvl entry.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('admx', 'defender', 'secpol', 'audit')][string]$SourceKind, $Definition)
    switch ($SourceKind) {
        'admx' {
            $els = foreach ($e in @($Definition.Elements | Where-Object { $_ })) {
                $more = @{ Required = [bool]$e.Required; Default = $e.Default }
                $label = [string]$e.Label
                switch ([string]$e.Type) {
                    'boolean' { $kind = 'bool'; $more.Choices = @([pscustomobject]@{ Value = $true; Label = 'On'; Index = 0 }, [pscustomobject]@{ Value = $false; Label = 'Off'; Index = 1 }) }
                    'decimal' { $kind = 'decimal'; $more.Min = [uint64]$e.Min; $more.Max = [uint64]$e.Max; $more.Unit = $label; $more.Step = $(if ($e.PSObject.Properties['SpinStep'] -and $e.SpinStep) { [uint64]$e.SpinStep } else { [uint64]1 }) }
                    'longDecimal' { $kind = 'longDecimal'; $more.Min = [uint64]$e.Min; $more.Max = [uint64]$e.Max; $more.Unit = $label; $more.Step = $(if ($e.PSObject.Properties['SpinStep'] -and $e.SpinStep) { [uint64]$e.SpinStep } else { [uint64]1 }) }
                    'text' { $kind = 'text'; $more.MaxLength = [int]$e.MaxLength; $more.Expandable = [bool]$e.Expandable; if ($e.PSObject.Properties['Suggestions']) { $more.Suggestions = @($e.Suggestions) } }
                    'multiText' { $kind = 'multiText'; $more.MaxLength = [int]$e.MaxLength; $more.MaxStrings = $(if ($e.PSObject.Properties['MaxStrings']) { [int]$e.MaxStrings } else { 0 }) }
                    'enum' {
                        $kind = 'enum'; $i = 0
                        $more.Choices = @(foreach ($it in @($e.Items)) { [pscustomobject]@{ Value = [string]$it.DisplayName; Label = [string]$it.DisplayName; Index = $i }; $i++ })
                    }
                    'list' { $kind = $(if ($e.ExplicitValue) { 'keyValueList' } else { 'list' }); $more.ValuePrefix = [string]$e.ValuePrefix; $more.Additive = [bool]$e.Additive; $more.Expandable = [bool]$e.Expandable }
                    default { $kind = 'unsupported' }
                }
                New-IgwtSecSettingElement -Id ([string]$e.Id) -Kind $kind -Label $label -More $more
            }
            return @{ Mode = 'tristate'; Elements = @($els) }
        }
        'defender' {
            $d = $Definition
            $more = @{}
            $kind = switch ([string]$d.type) { 'bool' { 'bool' } 'enum' { 'enum' } 'uint' { 'decimal' } 'time' { 'time' } 'text' { 'text' } 'list' { 'list' } default { 'unsupported' } }
            if ($kind -eq 'bool') { $more.Choices = @([pscustomobject]@{ Value = $true; Label = 'On'; Index = 0 }, [pscustomobject]@{ Value = $false; Label = 'Off'; Index = 1 }) }
            if ($kind -eq 'enum') { $i = 0; $more.Choices = @(foreach ($v in @($d.values)) { [pscustomobject]@{ Value = $v.v; Label = [string]$v.label; Index = $i }; $i++ }) }
            if ($kind -eq 'decimal') { $more.Min = $(if ($null -ne $d.min) { [uint64]$d.min } else { [uint64]0 }); $more.Max = $(if ($null -ne $d.max) { [uint64]$d.max } else { [uint64][uint32]::MaxValue }); $more.Unit = [string]$d.unit; $more.Step = [uint64]1 }
            if ($kind -eq 'text' -and $d.pattern) { $more.Pattern = [string]$d.pattern }
            $mode = $(if ($kind -eq 'unsupported' -or [string]$d.edit -notin 'set', 'parser') { 'none' } else { 'value' })
            return @{ Mode = $mode; Elements = @(New-IgwtSecSettingElement -Id ([string]$d.mp) -Kind $kind -Label ([string]$d.name) -More $more) }
        }
        'secpol' {
            $s = $Definition
            if ([int]$s.RegType -eq 3) { return @{ Mode = 'none'; Elements = @(); Reason = 'Binary values are not edited by iG.' } }
            $more = @{}
            switch ([int]$s.DisplayType) {
                0 { $kind = 'bool'; $more.Choices = @([pscustomobject]@{ Value = 1; Label = 'Enabled'; Index = 0 }, [pscustomobject]@{ Value = 0; Label = 'Disabled'; Index = 1 }) }
                1 { $kind = 'decimal'; $more.Min = [uint64]0; $more.Max = [uint64][uint32]::MaxValue; $more.Unit = [string]$s.Unit; $more.Step = [uint64]1 }
                2 { $kind = 'text' }
                3 { $kind = 'enum'; $i = 0; $more.Choices = @(foreach ($c in @($s.Choices)) { [pscustomobject]@{ Value = $c.Value; Label = [string]$c.Label; Index = $i }; $i++ }) }
                4 { $kind = 'multiText' }
                5 { $kind = 'flags'; $more.Bits = @(foreach ($c in @($s.Choices)) { [pscustomobject]@{ Value = $c.Value; Label = [string]$c.Label } }) }
                default { return @{ Mode = 'none'; Elements = @(); Reason = "The display type $($s.DisplayType) is not known to iG." } }
            }
            return @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id 'value' -Kind $kind -Label ([string]$s.Name) -More $more) }
        }
        'audit' {
            $i = 0
            $choices = @(foreach ($v in 'None', 'Success', 'Failure', 'SuccessAndFailure') { [pscustomobject]@{ Value = $v; Label = $(if ($v -eq 'SuccessAndFailure') { 'Success and Failure' } elseif ($v -eq 'None') { 'No auditing' } else { $v }); Index = $i }; $i++ })
            return @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id 'value' -Kind 'enum' -Label 'Auditing' -More @{ Choices = $choices }) }
        }
    }
}

#endregion

#region Decoding Registry.pol entries (SM10)

function Get-IgwtSecSettingPolicyEntries {
    <#
    .SYNOPSIS
        The Registry.pol entries (of one class) that belong to a policy: its owned values, their
        **del. markers, and every entry under a list key it owns. Pure.
    .PARAMETER Policy
        A policy from Get-IgwtAdmxCatalog.
    .PARAMETER Entries
        Read-IgwtRegistryPol entries of the policy's class.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [AllowEmptyCollection()][object[]]$Entries = @())
    $owned = Get-IgwtSecSettingOwnedSet -Policy $Policy
    foreach ($e in @($Entries)) {
        if (-not $e) { continue }
        $k = ([string]$e.Key).ToLowerInvariant()
        $n = [string]$e.ValueName
        if ($owned.ListKeys.Contains($k)) { $e; continue }
        $plain = $(if ($n -match '^\*\*del\.(.+)$') { $Matches[1] } else { $n })
        if ($owned.Pairs.Contains(("$k|$plain").ToLowerInvariant())) { $e }
    }
}

function Test-IgwtSecSettingPolMatch {
    <# .SYNOPSIS True when a Registry.pol value (or $null for missing) equals an ADMX value (Type DWord/QWord/String/Delete). Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Entry, $DeleteMarker, $AdmxValue)
    if (-not $AdmxValue) { return $false }
    if ([string]$AdmxValue.Type -eq 'Delete') { return [bool]$DeleteMarker }
    if (-not $Entry) { return $false }
    switch ([string]$AdmxValue.Type) {
        'DWord' { return ([int]$Entry.Type -eq 4 -and [uint64]$Entry.Value -eq [uint64]$AdmxValue.Value) }
        'QWord' { return ([int]$Entry.Type -eq 11 -and [uint64]$Entry.Value -eq [uint64]$AdmxValue.Value) }
        'String' { return ([int]$Entry.Type -in 1, 2 -and [string]$Entry.Value -ceq [string]$AdmxValue.Value) }
    }
    return $false
}

function ConvertFrom-IgwtPolicyEntries {
    <#
    .SYNOPSIS
        Reverses Get-IgwtPolicyRegistryOps (DECISIONS SM10): from a policy's Registry.pol entries,
        returns @{ State = NotConfigured | Enabled | Disabled | Configured; Values = element id ->
        typed value; Indexes = enum element id -> item index }. Enum items are matched by value and
        value list, never by position. Configured means the entries match no rule (read-only row). Pure.
    .PARAMETER Policy
        A policy from Get-IgwtAdmxCatalog.
    .PARAMETER Entries
        Registry.pol entries of the policy's class (other policies' entries are ignored).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [AllowEmptyCollection()][object[]]$Entries = @())
    $mine = @(Get-IgwtSecSettingPolicyEntries -Policy $Policy -Entries $Entries)
    $result = @{ State = 'NotConfigured'; Values = @{}; Indexes = @{} }
    if (-not $mine.Count) { return $result }
    $val = @{}; $del = @{}; $delvals = @{}
    foreach ($e in $mine) {
        $k = ([string]$e.Key).ToLowerInvariant(); $n = [string]$e.ValueName
        if ($n -eq '**delvals.') { $delvals[$k] = $true }
        elseif ($n -match '^\*\*del\.(.+)$') { $del[("$k|$($Matches[1])").ToLowerInvariant()] = $true }
        elseif ($n -notmatch '^\*\*') { $val[("$k|$n").ToLowerInvariant()] = $e }
    }
    $get = { param($k, $n) $val[("$k|$n").ToLowerInvariant()] }
    $isDel = { param($k, $n) $del.ContainsKey(("$k|$n").ToLowerInvariant()) }
    $match = { param($k, $n, $v) Test-IgwtSecSettingPolMatch -Entry (& $get $k $n) -DeleteMarker (& $isDel $k $n) -AdmxValue $v }
    $listMatch = { param($items) if (-not @($items).Count) { return $false }; foreach ($i in @($items)) { if (-not (& $match $i.Key $i.ValueName $i.Value)) { return $false } }; return $true }
    $state = $null
    if ($Policy.ValueName) {
        $on = $(if ($Policy.EnabledValue) { $Policy.EnabledValue } elseif (-not @($Policy.EnabledList).Count) { [pscustomobject]@{ Type = 'DWord'; Value = 1 } } else { $null })
        $off = $(if ($Policy.DisabledValue) { $Policy.DisabledValue } elseif (-not @($Policy.DisabledList).Count) { [pscustomobject]@{ Type = 'DWord'; Value = 0 } } else { $null })
        if ($on -and (& $match $Policy.Key $Policy.ValueName $on)) { $state = 'Enabled' }
        elseif ($off -and (& $match $Policy.Key $Policy.ValueName $off)) { $state = 'Disabled' }
    }
    if (-not $state -and (& $listMatch $Policy.EnabledList)) { $state = 'Enabled' }
    if (-not $state -and (& $listMatch $Policy.DisabledList)) { $state = 'Disabled' }
    if (-not $state -and -not $Policy.ValueName -and -not @($Policy.EnabledList).Count) {
        # Element-only policies: Disabled writes **del. markers or **delvals.; Enabled writes values.
        $anyValue = $false; $allDeleted = $true
        foreach ($e in @($Policy.Elements | Where-Object { $_ })) {
            if ([string]$e.Type -eq 'list') { if ($delvals.ContainsKey(([string]$e.Key).ToLowerInvariant())) { if (@($mine | Where-Object { [string]::Equals([string]$_.Key, [string]$e.Key, [System.StringComparison]::OrdinalIgnoreCase) -and [string]$_.ValueName -notmatch '^\*\*' }).Count) { $anyValue = $true; $allDeleted = $false } } else { $allDeleted = $false; if (@($mine | Where-Object { [string]::Equals([string]$_.Key, [string]$e.Key, [System.StringComparison]::OrdinalIgnoreCase) -and [string]$_.ValueName -notmatch '^\*\*' }).Count) { $anyValue = $true } } }
            elseif ($e.ValueName) { if (& $get $e.Key $e.ValueName) { $anyValue = $true; $allDeleted = $false } elseif (-not (& $isDel $e.Key $e.ValueName)) { $allDeleted = $false } }
        }
        if ($anyValue) { $state = 'Enabled' } elseif ($allDeleted) { $state = 'Disabled' }
    }
    if (-not $state) { $result.State = 'Configured'; return $result }
    $result.State = $state
    if ($state -ne 'Enabled') { return $result }
    foreach ($e in @($Policy.Elements | Where-Object { $_ })) {
        $id = [string]$e.Id
        switch ([string]$e.Type) {
            { $_ -in 'decimal', 'longDecimal' } {
                $x = & $get $e.Key $e.ValueName
                if ($x) { if ($e.StoreAsText) { if ([string]$x.Value -match '^\d+$') { $result.Values[$id] = [uint64][string]$x.Value } } else { $result.Values[$id] = [uint64]$x.Value } }
            }
            'text' { $x = & $get $e.Key $e.ValueName; if ($x) { $result.Values[$id] = [string]$x.Value } }
            'multiText' { $x = & $get $e.Key $e.ValueName; if ($x) { $result.Values[$id] = @($x.Value | ForEach-Object { [string]$_ }) } }
            'boolean' {
                $t = $(if ($e.TrueValue) { $e.TrueValue } else { [pscustomobject]@{ Type = 'DWord'; Value = 1 } })
                $f = $(if ($e.FalseValue) { $e.FalseValue } else { [pscustomobject]@{ Type = 'DWord'; Value = 0 } })
                if ((& $match $e.Key $e.ValueName $t) -or ((& $listMatch $e.TrueList) -and -not (& $get $e.Key $e.ValueName))) { $result.Values[$id] = $true }
                elseif ((& $match $e.Key $e.ValueName $f) -or ((& $listMatch $e.FalseList) -and -not (& $get $e.Key $e.ValueName))) { $result.Values[$id] = $false }
            }
            'enum' {
                $i = 0; $hit = $null
                foreach ($it in @($e.Items)) {
                    $ok = $(if ($it.Value) { & $match $e.Key $e.ValueName $it.Value } else { $true })
                    if ($ok -and @($it.ValueList).Count) { $ok = & $listMatch $it.ValueList }
                    if ($ok -and ($it.Value -or @($it.ValueList).Count)) { $hit = $i; break }
                    $i++
                }
                if ($null -ne $hit) { $result.Values[$id] = [string]@($e.Items)[$hit].DisplayName; $result.Indexes[$id] = $hit }
            }
            'list' {
                $items = @($mine | Where-Object { [string]::Equals([string]$_.Key, [string]$e.Key, [System.StringComparison]::OrdinalIgnoreCase) -and [string]$_.ValueName -notmatch '^\*\*' })
                if ($e.ExplicitValue) {
                    $h = [ordered]@{}
                    foreach ($x in $items) { $h[[string]$x.ValueName] = [string]$x.Value }
                    if ($h.Count) { $result.Values[$id] = $h }
                } elseif ($e.ValuePrefix) {
                    $byN = @{}
                    foreach ($x in $items) { if ([string]$x.ValueName -match ('^' + [regex]::Escape([string]$e.ValuePrefix) + '(\d+)$')) { $byN[[int]$Matches[1]] = [string]$x.Value } }
                    if ($byN.Count) { $result.Values[$id] = @($byN.Keys | Sort-Object | ForEach-Object { $byN[$_] }) }
                } else {
                    if ($items.Count) { $result.Values[$id] = @($items | ForEach-Object { [string]$_.Value }) }
                }
            }
        }
    }
    return $result
}

function ConvertTo-IgwtSecSettingCanonicalEntries {
    <# .SYNOPSIS Registry.pol entries as sorted canonical strings 'key|valueName|type|value' (for comparison). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Entries = @())
    @(foreach ($e in @($Entries)) {
            if (-not $e) { continue }
            $v = $(if ([string]$e.ValueName -match '^\*\*') { '' } else { ConvertTo-IgwtCanonicalJson $e.Value })
            ("{0}|{1}|{2}|{3}" -f ([string]$e.Key).ToLowerInvariant(), ([string]$e.ValueName).ToLowerInvariant(), $(if ([string]$e.ValueName -match '^\*\*') { '' } else { [int]$e.Type }), $v)
        }) | Sort-Object
}

function Test-IgwtSecSettingRoundTrip {
    <#
    .SYNOPSIS
        The SM8 round-trip gate: decodes the policy's entries, encodes them again with
        Get-IgwtPolicyRegistryOps (enum values passed as the [int] Index, booleans as [bool]) and
        compares the resulting entries with the ones on disk. @{ Ok; Reason; Decoded }. Pure.
    .PARAMETER Policy
        A policy from Get-IgwtAdmxCatalog.
    .PARAMETER Entries
        Registry.pol entries of the policy's class.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [AllowEmptyCollection()][object[]]$Entries = @())
    $mine = @(Get-IgwtSecSettingPolicyEntries -Policy $Policy -Entries $Entries)
    $dec = ConvertFrom-IgwtPolicyEntries -Policy $Policy -Entries $mine
    if (-not $mine.Count) { return @{ Ok = $true; Reason = ''; Decoded = $dec } }
    if ($dec.State -eq 'Configured') { return @{ Ok = $false; Reason = 'The policy''s entries do not match its definition, so iG does not change it.'; Decoded = $dec } }
    $values = @{}
    foreach ($k in @($dec.Values.Keys)) { $values[$k] = $(if ($dec.Indexes.ContainsKey($k)) { [int]$dec.Indexes[$k] } else { $dec.Values[$k] }) }
    try {
        $ops = @(Get-IgwtPolicyRegistryOps -Policy $Policy -State $dec.State -Values $values)
        $again = @(Update-IgwtPolEntries -Entries @() -Ops $ops)
    } catch { return @{ Ok = $false; Reason = "Encoding the current value failed: $($_.Exception.Message)"; Decoded = $dec } }
    $a = @(ConvertTo-IgwtSecSettingCanonicalEntries -Entries $mine)
    $b = @(ConvertTo-IgwtSecSettingCanonicalEntries -Entries $again)
    if (($a -join "`n") -ne ($b -join "`n")) { return @{ Ok = $false; Reason = 'Writing the current value again would not give the same entries, so iG does not change it.'; Decoded = $dec } }
    return @{ Ok = $true; Reason = ''; Decoded = $dec }
}

function Test-IgwtSecSettingWritable {
    <#
    .SYNOPSIS
        The SM8 gate for one ADMX policy: @{ Writable; Reason }. Every element kind supported, the
        round trip of its current entries, its keys below the Policies roots of its class, a valid
        clientExtension, and no overlap with another policy (unless reviewed). Pure.
    .PARAMETER Policy
        A policy from Get-IgwtAdmxCatalog.
    .PARAMETER Entries
        Registry.pol entries of the policy's class.
    .PARAMETER OverlapIndex
        Get-IgwtSecSettingOverlapIndex.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [AllowEmptyCollection()][object[]]$Entries = @(), [hashtable]$OverlapIndex = @{})
    $no = { param($why) @{ Writable = $false; Reason = $why } }
    foreach ($e in @($Policy.Elements | Where-Object { $_ })) { if ([string]$e.Type -notin 'boolean', 'decimal', 'longDecimal', 'text', 'multiText', 'enum', 'list') { return (& $no "The element kind '$($e.Type)' is not supported by iG.") } }
    $roots = '^(?i)(Software\\Policies\\|Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\)'
    $owned = Get-IgwtSecSettingOwnedSet -Policy $Policy
    $keys = @($owned.ListKeys) + @($owned.Pairs | ForEach-Object { $_.Substring(0, $_.LastIndexOf('|')) })
    foreach ($k in $keys) { if ($k -notmatch $roots) { return (& $no "It writes outside the Policies keys ($k), so iG does not change it.") } }
    if ([string]$Policy.Class -notin 'Machine', 'User') { return (& $no 'iG changes Machine and User policies one class at a time; this policy is for both.') }
    if ($Policy.PSObject.Properties['ClientExtension'] -and $Policy.ClientExtension -and [string]$Policy.ClientExtension -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') { return (& $no 'Its client extension is not a valid GUID.') }
    if ($OverlapIndex.ContainsKey([string]$Policy.Id)) { return (& $no "Shares registry values with $(@($OverlapIndex[[string]$Policy.Id]) -join ', '), so iG does not change it.") }
    $rt = Test-IgwtSecSettingRoundTrip -Policy $Policy -Entries $Entries
    if (-not $rt.Ok) { return (& $no $rt.Reason) }
    return @{ Writable = $true; Reason = '' }
}

#endregion

#region sceregvl.inf (SM22)

function Read-IgwtSceRegVlInf {
    <#
    .SYNOPSIS
        Reads the security option definitions of sceregvl.inf (DECISIONS SM22; the format is
        UNVERIFIED, SM39h): one object per registry value with Key ('MACHINE\...'), RegType,
        Name (the display string, raw when it is a resource reference), DisplayType, Choices
        (enum and flags: Value and Label) and Unit. Lines it cannot read are skipped. Read-only.
    .PARAMETER Path
        The file; default %SystemRoot%\inf\sceregvl.inf.
    #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path $env:SystemRoot 'inf\sceregvl.inf'))
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    $strings = @{}
    $section = ''
    foreach ($l in $lines) {
        $t = $l.Trim()
        if ($t -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if ($section -eq 'Strings' -and $t -match '^([^=;]+?)\s*=\s*"?(.*?)"?$') { $strings[$Matches[1].Trim()] = $Matches[2] }
    }
    $resolve = { param($s) $s = [string]$s; if ($s -match '^%(.+)%$' -and $strings.ContainsKey($Matches[1])) { return [string]$strings[$Matches[1]] }; return $s.Trim('%') }
    $section = ''
    foreach ($l in $lines) {
        $t = $l.Trim()
        if ($t -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if ($section -ne 'Register Registry Values' -or $t -notmatch '^MACHINE\\') { continue }
        $parts = $t.Split(',')
        if ($parts.Count -lt 4) { continue }
        $regType = 0; $display = 0
        if (-not [int]::TryParse($parts[1], [ref]$regType) -or -not [int]::TryParse($parts[3], [ref]$display)) { continue }
        $choices = @(); $unit = ''
        if ($display -in 3, 5) {
            $choices = @(for ($i = 4; $i -lt $parts.Count; $i++) {
                    if ($parts[$i] -match '^(\d+)\|(.*)$') { [pscustomobject]@{ Value = [uint32]$Matches[1]; Label = (& $resolve $Matches[2]) } }
                })
        } elseif ($display -eq 1 -and $parts.Count -gt 4) { $unit = & $resolve $parts[4] }
        [pscustomobject]@{ Key = $parts[0]; RegType = $regType; Name = (& $resolve $parts[2]); DisplayType = $display; Choices = $choices; Unit = $unit }
    }
}

#endregion

#region Rows (SM3)

function New-IgwtSecSettingRow {
    <#
    .SYNOPSIS
        One row of the unified setting model (DECISIONS SM3). Missing fields get their neutral value;
        Search is built from the name, category, explain text and id; Configured follows the rule of
        the row's source kind unless given. Pure.
    .PARAMETER Fields
        The row's fields (Id, SourceKind, Category, Name, ... as in SM3).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Fields)
    $r = [ordered]@{
        Id = ''; SourceKind = ''; Category = @(); Name = ''; Explain = ''; SupportedOn = ''; Class = ''; AppliesTo = 'this PC'
        ValueSpec = @{ Mode = 'none'; Elements = @() }; Current = $null; CurrentText = ''; State = 'Unknown'; Origin = 'Unknown'; Configured = $null
        ReadOnly = $false; ReadOnlyReason = ''; Writer = 'none'; Baseline = $null; BaselineSource = 'Not bundled'; Risk = 'normal'; RiskClass = @()
        Restart = 'none'; SideEffects = @(); Prerequisites = @(); Search = ''
    }
    foreach ($k in @($Fields.Keys)) { $r[$k] = $Fields[$k] }
    if ([string]$r.Class -eq 'User') { $r.AppliesTo = 'every user of this PC' }
    if ($null -eq $r.Configured) {
        $r.Configured = switch ([string]$r.SourceKind) {
            'admx' { [string]$r.State -ne 'NotConfigured' }
            'asr' { [string]$r.State -ne 'NotConfigured' }
            'exclusionList' { @($r.Current).Count -gt 0 }
            'deviceguardState' { [string]$r.State -eq 'Configured' }
            default { $true }
        }
    }
    if ($r.ReadOnly -and $r.Writer -ne 'none') { $r.Writer = 'none' }
    $r.Search = ("{0}`n{1}`n{2}`n{3}`n{4}" -f $r.Name, (@($r.Category) -join ' > '), $r.Explain, $r.Id, $r.CurrentText).ToLowerInvariant()
    return [pscustomobject]$r
}

#endregion
