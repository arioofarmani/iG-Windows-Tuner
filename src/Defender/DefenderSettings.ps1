# DefenderSettings.ps1
# Defender settings editor: every Microsoft Defender Antivirus preference in
# data\defender\settings.json with its typed value, the values that may be set, a dry-run plan, the
# change itself (snapshot operation 'Defender', revert through Invoke-IgwtRevert) and every Defender
# Group Policy setting. Forward changes never lower protection: protection and hardening settings
# move only toward on, refused values (Off, Never send, Allow, ...) are never set, settings a policy
# controls are changed through that policy, and read-only settings (Tamper Protection, exclusion
# lists, undocumented ones) are never touched. A revert writes back earlier option values exactly
# and never turns a protection off or lowers a protection level (DECISIONS D1, D8).
# Set-MpPreference itself is called only by Invoke-IgwtMpPreferenceWrite (DefenderCenter.ps1).

$script:IgwtUInt32Max = [long][uint32]::MaxValue

function Get-IgwtDefenderSettingDefinition {
    <# .SYNOPSIS One catalog entry by its Get-MpPreference property name (case-insensitive). Throws for names that are not in the catalog. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $s = @((Get-IgwtDefenderSettingCatalog).settings | Where-Object { [string]::Equals([string]$_.mp, $Name.Trim(), [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $s) { throw "'$Name' is not a Defender setting of the catalog (data\defender\settings.json)." }
    return $s
}

function Get-IgwtDefenderEnumValues {
    <# .SYNOPSIS The value list of an enum setting (named lists such as 'day' are resolved). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition)
    $v = $Definition.values
    if ($v -is [string]) { return @((Get-IgwtDefenderSettingCatalog).enums.$v) }
    return @($v)
}

function ConvertFrom-IgwtMpRawValue {
    <# .SYNOPSIS Normalizes a Get-MpPreference value for the setting type: bool, number, minutes after midnight (time), string or string array. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$Raw)
    switch ([string]$Definition.type) {
        'bool' { if ($null -eq $Raw) { return $null }; return [bool]$Raw }
        { $_ -in 'enum', 'uint' } { if ($null -eq $Raw) { return $null }; return [long]$Raw }
        'time' {
            if ($null -eq $Raw) { return $null }
            if ($Raw -is [timespan]) { return [int][math]::Floor($Raw.TotalMinutes) % 1440 }
            if ($Raw -is [datetime]) { return [int]($Raw.Hour * 60 + $Raw.Minute) }
            return [int]$Raw
        }
        'list' { return @(@($Raw) | Where-Object { $null -ne $_ -and [string]$_ -ne '' } | ForEach-Object { [string]$_ }) }
        default { if ($null -eq $Raw) { return '' }; return [string]$Raw }
    }
}

function ConvertTo-IgwtDefenderSettingValue {
    <#
    .SYNOPSIS
        Parses a value for a setting: bool (true/false, 1/0, yes/no, or on/off meaning the
        protection for protection, hardening and parser settings), enum (the number or its label),
        uint, time (HH:mm or minutes after midnight), text or list (items separated by |). Throws
        when the value does not parse; Test-IgwtDefenderSettingValue decides whether it may be set.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$Value)
    $mp = [string]$Definition.mp
    if ($null -eq $Value) { throw "No value given for $mp." }
    $s = ([string]$Value).Trim()
    switch ([string]$Definition.type) {
        'bool' {
            if ($Value -is [bool]) { return $Value }
            if ($s -in 'on', 'off' -and $Definition.kind -in 'protection', 'hardening', 'parser' -and $Definition.on -is [bool]) { return $(if ($s -eq 'on') { [bool]$Definition.on } else { -not [bool]$Definition.on }) }
            if ($s -in 'true', '1', 'yes', '$true') { return $true }
            if ($s -in 'false', '0', 'no', '$false') { return $false }
            throw "'$s' is not a valid value for $mp (true or false)."
        }
        'enum' {
            $vals = @(Get-IgwtDefenderEnumValues -Definition $Definition)
            $n = 0L
            if ([long]::TryParse($s, [ref]$n)) { $hit = @($vals | Where-Object { [long]$_.v -eq $n }) }
            else { $hit = @($vals | Where-Object { [string]::Equals([string]$_.label, $s, [System.StringComparison]::OrdinalIgnoreCase) }) }
            if (-not $hit.Count) { throw "'$s' is not a valid value for $mp (allowed: $(@($vals | ForEach-Object { "$($_.v) $($_.label)" }) -join ', '))." }
            return [long]$hit[0].v
        }
        'uint' {
            $n = 0L
            if (-not [long]::TryParse($s, [ref]$n) -or $n -lt 0 -or $n -gt $script:IgwtUInt32Max) { throw "'$s' is not a valid whole number for $mp." }
            return $n
        }
        'time' {
            $n = 0
            if ([int]::TryParse($s, [ref]$n)) { $m = $n }
            elseif ($s -match '^(\d{1,2}):(\d{2})(:\d{2})?$') { $m = [int]$Matches[1] * 60 + [int]$Matches[2]; if ([int]$Matches[1] -gt 23 -or [int]$Matches[2] -gt 59) { $m = -1 } }
            else { $m = -1 }
            if ($m -lt 0 -or $m -gt 1439) { throw "'$s' is not a valid time for $mp (HH:mm, 00:00-23:59)." }
            return $m
        }
        'list' { return @(@($Value) | ForEach-Object { ([string]$_).Split('|') } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        default { return $s }
    }
}

function Format-IgwtDefenderSettingValue {
    <# .SYNOPSIS A value as shown to the user: On/Off for protection settings, Yes/No for options, enum labels, HH:mm for times, units for numbers. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$Value)
    if ($null -eq $Value) { return '(not reported)' }
    switch ([string]$Definition.type) {
        'bool' {
            if ($Definition.kind -in 'protection', 'hardening', 'parser' -and $Definition.on -is [bool]) { return $(if ([bool]$Value -eq [bool]$Definition.on) { 'On' } else { 'Off' }) }
            return $(if ([bool]$Value) { 'Yes' } else { 'No' })
        }
        'enum' {
            $hit = @(Get-IgwtDefenderEnumValues -Definition $Definition | Where-Object { [long]$_.v -eq [long]$Value }) | Select-Object -First 1
            if ($hit) { return [string]$hit.label }
            return "$Value"
        }
        'uint' { if ($Definition.unit) { return "$Value $($Definition.unit)" }; return "$Value" }
        'time' { return ('{0:00}:{1:00}' -f [math]::Floor([int]$Value / 60), ([int]$Value % 60)) }
        'list' { $a = @($Value); if (-not $a.Count) { return '(empty)' }; return ($a -join ' | ') }
        default { if ([string]$Value -eq '') { return '(empty)' }; return [string]$Value }
    }
}

function Test-IgwtDefenderValueEqual {
    <# .SYNOPSIS True when two normalized values of a setting are the same. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$A, [AllowNull()]$B)
    if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
    if ([string]$Definition.type -eq 'list') { return ((@($A) -join '|') -eq (@($B) -join '|')) }
    if ([string]$Definition.type -eq 'bool') { return ([bool]$A -eq [bool]$B) }
    if ([string]$Definition.type -in 'enum', 'uint', 'time') { return ([long]$A -eq [long]$B) }
    return ([string]$A -ceq [string]$B)
}

function Get-IgwtDefenderSettingStatus {
    <#
    .SYNOPSIS
        Status of a setting value: On, Off, Below (a weaker level), Optional (extra hardening that is
        off by default), Info (options and shown-only settings) or Unknown.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$Value)
    $kind = [string]$Definition.kind
    if ($kind -in 'option', 'info' -or $null -eq $Definition.on) { return 'Info' }
    if ($null -eq $Value) { return 'Unknown' }
    $good = @(@($Definition.on) + @($Definition.alsoOn) | Where-Object { $null -ne $_ })
    $isOn = @($good | Where-Object { Test-IgwtDefenderValueEqual -Definition $Definition -A $Value -B (ConvertTo-IgwtDefenderSettingValue -Definition $Definition -Value $_) }).Count -gt 0
    if ($kind -eq 'level' -and [string]$Definition.type -eq 'uint') { $isOn = ([long]$Value -ge [long]$Definition.on) }
    if ($isOn) { return 'On' }
    switch ($kind) {
        'hardening' { return 'Optional' }
        'level' {
            $refused = @(Get-IgwtDefenderEnumValues -Definition $Definition | Where-Object { $_.refused -and [long]$_.v -eq [long]$Value }).Count -gt 0
            return $(if ($refused) { 'Off' } else { 'Below' })
        }
        default { return 'Off' }
    }
}

function Test-IgwtDefenderSettingValue {
    <#
    .SYNOPSIS
        The reason a value may not be set for a setting, or $null when it may: read-only and
        policy-only settings, parsers (only on), protection and hardening settings (only the
        protective value), refused enum values, ranges, text patterns, and (with -Current) a level
        setting that would drop below its recommended level. Never weakens protection.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$Value, [AllowNull()]$Current)
    switch ([string]$Definition.edit) {
        'readonly' { if ($Definition.note) { return [string]$Definition.note }; return 'Shown only.' }
        'policy' { return "Set only through Group Policy: $($Definition.policy) (-PolicySet $($Definition.policy) -PolicyState ...)." }
    }
    $kind = [string]$Definition.kind
    if ($kind -in 'protection', 'hardening', 'parser') {
        $good = @(@($Definition.on) + @($Definition.alsoOn) | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-IgwtDefenderSettingValue -Definition $Definition -Value $_ })
        if (-not @($good | Where-Object { Test-IgwtDefenderValueEqual -Definition $Definition -A $Value -B $_ }).Count) {
            $labels = @($good | ForEach-Object { Format-IgwtDefenderSettingValue -Definition $Definition -Value $_ }) -join ' or '
            if ($kind -eq 'parser') { return "Network Inspection parsers are only ever turned on ($labels)." }
            return "Only the protective value can be set ($labels): iG Windows Tuner never turns a protection off."
        }
        return $null
    }
    switch ([string]$Definition.type) {
        'enum' {
            $hit = @(Get-IgwtDefenderEnumValues -Definition $Definition | Where-Object { [long]$_.v -eq [long]$Value }) | Select-Object -First 1
            if (-not $hit) { return "$Value is not a listed value." }
            if ($hit.refused) { return "'$($hit.label)' is refused: $($hit.why)" }
            if ($hit.noSet) { return "'$($hit.label)' cannot be set directly." }
        }
        'uint' {
            $min = $(if ($null -ne $Definition.min) { [long]$Definition.min } else { 0L })
            $max = $(if ($null -ne $Definition.max) { [long]$Definition.max } else { $script:IgwtUInt32Max })
            $extra = @(@($Definition.alsoAllowed) | Where-Object { $null -ne $_ } | ForEach-Object { [long]$_ })
            if (([long]$Value -lt $min -or [long]$Value -gt $max) -and $extra -notcontains [long]$Value) {
                return "$Value is outside $min-$max$(if ($extra.Count) { " (or $($extra -join ', '))" })$(if ($Definition.unit) { " $($Definition.unit)" })."
            }
        }
        'time' { if ([int]$Value -lt 0 -or [int]$Value -gt 1439) { return 'The time must be between 00:00 and 23:59.' } }
        'text' {
            $t = [string]$Value
            if ($Definition.pattern -and $t -notmatch [string]$Definition.pattern) { return "'$t' does not have the expected format." }
            if ($Definition.mustMatch -and $t -notmatch [string]$Definition.mustMatch.regex) { return [string]$Definition.mustMatch.why }
            if (-not $Definition.pattern) { return 'Free text values are set through Group Policy only.' }
        }
        'list' { return 'Lists are set through Group Policy only.' }
    }
    if ($kind -eq 'level' -and $PSBoundParameters.ContainsKey('Current') -and $null -ne $Current -and (Get-IgwtDefenderSettingStatus -Definition $Definition -Value $Current) -eq 'On' -and (Get-IgwtDefenderSettingStatus -Definition $Definition -Value $Value) -ne 'On') {
        return "Lowers $($Definition.name) from $(Format-IgwtDefenderSettingValue -Definition $Definition -Value $Current) to $(Format-IgwtDefenderSettingValue -Definition $Definition -Value $Value): iG Windows Tuner never lowers a protection level."
    }
    return $null
}

function Get-IgwtDefenderSettingChoices {
    <# .SYNOPSIS The selectable values of a bool or enum setting (Value, Label, Allowed, Why), for editors. Empty for typed values. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [AllowNull()]$Current)
    $opts = @()
    if ([string]$Definition.type -eq 'bool') { $opts = @($true, $false) }
    elseif ([string]$Definition.type -eq 'enum') { $opts = @(Get-IgwtDefenderEnumValues -Definition $Definition | ForEach-Object { [long]$_.v }) }
    else { return @() }
    foreach ($o in $opts) {
        $why = Test-IgwtDefenderSettingValue -Definition $Definition -Value $o -Current $Current
        [pscustomobject]@{ Value = $o; Label = (Format-IgwtDefenderSettingValue -Definition $Definition -Value $o); Allowed = (-not $why); Why = [string]$why }
    }
}

function Get-IgwtDefenderSettingDoc {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Definition)
    $key = $(if ($Definition.doc) { [string]$Definition.doc } else { 'mp' })
    return [string](Get-IgwtDefenderSettingCatalog).docs.$key
}

function Get-IgwtDefenderSettingChangePlan {
    <#
    .SYNOPSIS
        Dry run of Invoke-IgwtDefenderSettingChange: for each setting the current and new value,
        whether it changes, and why it is refused (rules of Test-IgwtDefenderSettingValue, Defender
        not active, or a policy or MDM that sets it). Read-only.
    .PARAMETER Setting
        Property name to value, for example @{ CloudBlockLevel = 'High'; ScanScheduleTime = '03:30' }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Setting)
    if ($Setting.Count -eq 0) { throw 'No Defender setting given.' }
    $pref = Get-IgwtMpPreferenceSafe
    $active = Test-IgwtDefenderActive
    $admx = $null
    try { $admx = Get-IgwtAdmxCatalog } catch { Write-Verbose "ADMX catalog unavailable: $($_.Exception.Message)" }
    $rows = foreach ($k in @($Setting.Keys)) {
        $def = Get-IgwtDefenderSettingDefinition -Name ([string]$k)
        $mp = [string]$def.mp
        $value = ConvertTo-IgwtDefenderSettingValue -Definition $def -Value $Setting[$k]
        $reported = [bool]$pref.PSObject.Properties[$mp]
        $cur = $(if ($reported) { ConvertFrom-IgwtMpRawValue -Definition $def -Raw $pref.$mp } else { $null })
        $why = Test-IgwtDefenderSettingValue -Definition $def -Value $value -Current $cur
        $pd = $null
        if ($def.policy -and $admx) { $pd = @($admx.Policies | Where-Object { $_.Id -eq [string]$def.policy }) | Select-Object -First 1 }
        $source = Get-IgwtDefenderSettingSource -Setting $def -PolicyDefinition $pd
        if (-not $why -and -not $reported) { $why = "This Defender platform does not report $mp." }
        if (-not $why -and -not $active) { $why = 'Microsoft Defender Antivirus is not the active antivirus.' }
        if (-not $why -and $source -ne 'Local') { $why = "Set by $source, which wins over a local change.$(if ($def.policy -and $source -like '*GPO*') { " Change the policy instead: -PolicySet $($def.policy)." })" }
        $has = -not (Test-IgwtDefenderValueEqual -Definition $def -A $cur -B $value)
        [pscustomobject]@{
            Property = $mp; Name = [string]$def.name; Category = [string]$def.category; Kind = [string]$def.kind; Type = [string]$def.type
            CurrentValue = $cur; NewValue = $value
            Current = (Format-IgwtDefenderSettingValue -Definition $def -Value $cur); New = (Format-IgwtDefenderSettingValue -Definition $def -Value $value)
            HasChange = $has; Refused = [string]$why; Source = $source
            Route = $(if ([string]$def.edit -eq 'parser') { 'parser' } else { 'set' })
        }
    }
    $m = Get-IgwtManagementState
    [pscustomobject]@{ Rows = @($rows); Managed = [bool]$m.Managed; Authorities = @($m.Authorities); Refused = @(@($rows) | Where-Object { $_.Refused }).Count; Changes = @(@($rows) | Where-Object { $_.HasChange -and -not $_.Refused }).Count }
}

function Invoke-IgwtDefenderSettingChange {
    <#
    .SYNOPSIS
        Changes Defender settings after a snapshot (operation 'Defender'): each value is checked
        with Get-IgwtDefenderSettingChangePlan first and nothing changes when any setting is refused.
        Each write is verified by reading the preference back (Tamper Protection or a policy can
        keep the old value). Parsers go through Set-IgwtDefenderParsersOn (only on, no revert).
        Revert with Invoke-IgwtRevert -SnapshotPath.
    .PARAMETER Setting
        Property name to value, for example @{ CloudBlockLevel = 'High'; ScanScheduleTime = '03:30' }.
    .PARAMETER AcknowledgeManaged
        Confirms a local change on a domain-joined or MDM-enrolled PC.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Setting, [switch]$AcknowledgeManaged)
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Changing Defender settings needs administrator rights.' }
        Initialize-IgwtDataRoot
    }
    $plan = Get-IgwtDefenderSettingChangePlan -Setting $Setting
    $refused = @($plan.Rows | Where-Object { $_.Refused })
    if ($refused.Count) { throw "Refused: $(@($refused | ForEach-Object { "$($_.Name) -> $($_.New): $($_.Refused)" }) -join ' ')" }
    if ($plan.Managed -and -not $AcknowledgeManaged) { throw "This PC is managed ($($plan.Authorities -join ', ')); Defender settings may come from your organization. Pass -AcknowledgeManaged to change them locally." }
    $todo = @($plan.Rows | Where-Object { $_.HasChange })
    $results = New-Object System.Collections.Generic.List[object]
    $none = [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @() }
    if (-not $todo.Count) { return $none }
    $parsers = @($todo | Where-Object { $_.Route -eq 'parser' })
    $sets = @($todo | Where-Object { $_.Route -eq 'set' })
    if (-not $PSCmdlet.ShouldProcess("$($todo.Count) Defender setting(s)", 'Change')) { return $none }
    if ($parsers.Count) {
        $r = Set-IgwtDefenderParsersOn -Name @($parsers | ForEach-Object { $_.Property }) -AcknowledgeManaged:$AcknowledgeManaged -Confirm:$false
        foreach ($p in $parsers) { $results.Add([pscustomobject]@{ Target = $p.Name; Change = "$($p.Current) -> $($p.New)"; Result = 'Applied'; Message = 'Network Inspection parser: only ever turned on, so there is nothing to revert.' }) }
        $null = $r
    }
    $snap = $null
    if ($sets.Count) {
        $snap = New-IgwtSnapshot -Operation 'Defender' -Detail (@($sets | ForEach-Object { "$($_.Property)=$($_.New)" }) -join '; ')
        Save-IgwtSnapshot -Snapshot $snap
        foreach ($row in $sets) {
            $def = Get-IgwtDefenderSettingDefinition -Name $row.Property
            $tid = "defender:$($row.Property)"
            $actions = @([ordered]@{ index = 0; type = 'defenderSetting'; fingerprint = "defenderSetting|$($row.Property)"; data = [ordered]@{ mp = $row.Property; value = $row.CurrentValue } })
            $change = "$($row.Current) -> $($row.New)"
            Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions $actions -Result 'Applied' -Message $change
            try {
                Invoke-IgwtMpPreferenceWrite -Definition $def -Value $row.NewValue -Confirm:$false
                $after = ConvertFrom-IgwtMpRawValue -Definition $def -Raw (Get-IgwtMpPreferenceSafe).($row.Property)
                if (Test-IgwtDefenderValueEqual -Definition $def -A $after -B $row.NewValue) {
                    $results.Add([pscustomobject]@{ Target = $row.Name; Change = $change; Result = 'Applied'; Message = '' })
                    Write-IgwtLog -Message "Defender $($row.Property): $change. Snapshot: $($snap.Path)"
                } else {
                    $msg = "Defender still reports $(Format-IgwtDefenderSettingValue -Definition $def -Value $after): Tamper Protection or a policy keeps the earlier value."
                    $results.Add([pscustomobject]@{ Target = $row.Name; Change = $change; Result = 'NotApplied'; Message = $msg })
                    Write-IgwtLog -Level Warn -Message "Defender $($row.Property): $msg"
                }
            } catch {
                Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions $actions -Result 'Failed' -Message $_.Exception.Message
                $results.Add([pscustomobject]@{ Target = $row.Name; Change = $change; Result = 'Failed'; Message = $_.Exception.Message })
                Write-IgwtLog -Level Error -Message "Defender $($row.Property): $($_.Exception.Message)"
            }
        }
    }
    return [pscustomobject]@{ Snapshot = $(if ($snap) { $snap.Path } else { $null }); Changes = $todo.Count; Results = $results.ToArray() }
}

function Restore-IgwtDefenderSettingSnapshot {
    <#
    .SYNOPSIS
        Reverts a 'Defender' snapshot: writes back each setting's earlier value. Property names are
        checked against the catalog (only settings the editor changes) and values against the
        setting type; the current values are saved in a new 'Defender' snapshot first. An earlier
        value that would turn a protection off or lower a protection level is not written back
        (result Kept): the protection stays on, as with the Defender policy presets.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    if ([string]$doc.operation -ne 'Defender') { throw 'This is not a Defender settings snapshot.' }
    $seen = @{}
    $entries = @($doc.entries | Where-Object { $_ -and [string]$_.result -in 'Applied', 'Failed' } | Where-Object { $k = [string]$_.tweakId; if ($seen.ContainsKey($k)) { $false } else { $seen[$k] = $true; $true } })
    [array]::Reverse($entries)
    $results = New-Object System.Collections.Generic.List[object]
    if ($entries.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($entries.Count) Defender setting(s) from $(Split-Path $SnapshotPath -Leaf)", 'Revert')) { return [pscustomobject]@{ Snapshot = $null; Results = @() } }
    $undo = New-IgwtSnapshot -Operation 'Defender' -Detail "revert of $(Split-Path $SnapshotPath -Leaf)"
    Save-IgwtSnapshot -Snapshot $undo
    foreach ($e in $entries) {
        $tid = [string]$e.tweakId
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            try {
                if ([string]$a.type -ne 'defenderSetting') { throw "Unknown Defender snapshot action '$($a.type)'." }
                $def = Get-IgwtDefenderSettingDefinition -Name ([string]$a.data.mp)
                if ([string]$def.edit -ne 'set') { throw "$($def.mp) is not changed by the Defender settings editor." }
                if ($null -eq $a.data.value) { $results.Add([pscustomobject]@{ Id = $tid; Result = 'Skipped'; Message = 'The earlier value was not reported; nothing to write back.' }); continue }
                $value = ConvertTo-IgwtDefenderSettingValue -Definition $def -Value $a.data.value
                if ([string]$def.type -eq 'text' -and $def.pattern -and [string]$value -notmatch [string]$def.pattern) { throw "Snapshot value for $($def.mp) does not have the expected format." }
                $cur = ConvertFrom-IgwtMpRawValue -Definition $def -Raw (Get-IgwtMpPreferenceSafe).([string]$def.mp)
                if ([string]$def.kind -in 'protection', 'hardening', 'level' -and -not (Test-IgwtDefenderValueEqual -Definition $def -A $cur -B $value)) {
                    $why = Test-IgwtDefenderSettingValue -Definition $def -Value $value -Current $cur
                    if ($why) {
                        $results.Add([pscustomobject]@{ Id = $tid; Result = 'Kept'; Message = "$($def.name) stays $(Format-IgwtDefenderSettingValue -Definition $def -Value $cur): a revert never turns a protection off or lowers it." })
                        continue
                    }
                }
                Add-IgwtSnapshotEntry -Snapshot $undo -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'defenderSetting'; fingerprint = "defenderSetting|$($def.mp)"; data = [ordered]@{ mp = [string]$def.mp; value = $cur } }) -Result 'Applied' -Message 'before revert'
                if (-not (Test-IgwtDefenderValueEqual -Definition $def -A $cur -B $value)) { Invoke-IgwtMpPreferenceWrite -Definition $def -Value $value -Confirm:$false }
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Reverted'; Message = '' })
            } catch {
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = $_.Exception.Message })
                Write-IgwtLog -Level Error -Message "Defender revert of ${tid}: $($_.Exception.Message)"
            }
        }
    }
    Write-IgwtLog -Message "Defender snapshot $(Split-Path $SnapshotPath -Leaf) reverted. Undo snapshot: $($undo.Path)"
    return [pscustomobject]@{ Snapshot = $undo.Path; Results = $results.ToArray() }
}

function Get-IgwtDefenderPolicySettings {
    <#
    .SYNOPSIS
        Every Microsoft Defender Antivirus Group Policy setting of the installed ADMX files (also
        the ones without a Defender preference, such as heuristics, packed executables, update on
        startup or notifications), with the Local GPO state, the winning source, the preference it
        sets and the states the denylist refuses. Exclusions, ASR and controlled folder access are
        left to their own areas. Change them with Set-IgwtLocalPolicy (-PolicySet). Read-only.
    #>
    [CmdletBinding()]
    param([string]$Search)
    $linked = @{}
    foreach ($s in @((Get-IgwtDefenderSettingCatalog).settings | Where-Object { $_.policy })) { $linked[[string]$s.policy] = @(@($linked[[string]$s.policy]) + [string]$s.mp | Where-Object { $_ }) }
    $policies = @((Get-IgwtAdmxCatalog).Policies | Where-Object { [string]$_.Id -like 'WindowsDefender:*' })
    foreach ($p in $policies) {
        if ([string]$p.Key -match '(?i)\\Exclusions$' -or [string]$p.Id -match '(?i)ExploitGuard_(ASR|ControlledFolderAccess)') { continue }
        if ($Search -and ("$($p.DisplayName) $($p.Id) $($p.CategoryPath)").IndexOf($Search, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $state = $null
        try { $state = Get-IgwtPolicyState -Policy $p } catch { Write-Verbose "Policy state of $($p.Id): $($_.Exception.Message)" }
        $refused = New-Object System.Collections.Generic.List[string]
        $simple = (@($p.Elements).Count -eq 0)
        foreach ($st in 'Enabled', 'Disabled') {
            try { foreach ($o in @(Get-IgwtPolicyRegistryOps -Policy $p -State $st)) { $why = Test-IgwtPolicyOpAllowed -Op $o; if ($why) { $refused.Add("${st}: $why"); break } } }
            catch { Write-Verbose "Policy ops of $($p.Id) ($st): $($_.Exception.Message)" }
        }
        [pscustomobject]@{
            Id = [string]$p.Id; Name = [string]$p.DisplayName; Category = [string]$p.CategoryPath
            State = $(if ($state) { [string]$state.LocalGpo } else { 'Unknown' }); Source = $(if ($state) { [string]$state.Source } else { '' })
            Preference = (@($linked[[string]$p.Id]) -join ', '); Simple = $simple; Refused = $refused.ToArray()
            Explain = [string]$p.Explain
        }
    }
}
