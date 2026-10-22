# PolicyEngine.ps1
# Group Policy engine: turns an ADMX policy state (Enabled with element values, Disabled, Not
# configured) into Registry.pol operations exactly as the Group Policy editor writes them, shows
# the effective state and source (Local GPO, registry, domain GPO from gpresult, MDM PolicyManager),
# finds tattooed values, and writes the Local GPO the professional way: backup, Registry.pol and
# gpt.ini, targeted gpupdate, then verification. Values on the denylist are never written.

$script:IgwtPolicyDenylist = $null

#region Registry operations

function Get-IgwtPolicyRegistryOps {
    <#
    .SYNOPSIS
        The Registry.pol operations for a policy state: Set (Key, ValueName, Type, Value), Delete
        (a **del. marker) and DeleteValues (a **delvals. marker, for non-additive lists), following
        the ADMX semantics. Not configured returns the entries to remove. Pure.
    .PARAMETER Values
        Element values keyed by element id (enum: the item display name or index; list: an array,
        or a hashtable for explicitValue lists; boolean: $true/$false).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled', 'NotConfigured')][string]$State, [hashtable]$Values = @{})
    $ops = New-Object System.Collections.Generic.List[object]
    $add = { param($op, $k, $n, $t, $v) $ops.Add([pscustomobject]@{ Op = $op; Key = [string]$k; ValueName = [string]$n; Type = [string]$t; Value = $v }) }
    $addValue = { param($k, $n, $v) if (-not $v -or -not $n) { return }; if ($v.Type -eq 'Delete') { & $add 'Delete' $k $n '' $null } else { & $add 'Set' $k $n $v.Type $v.Value } }
    $addList = { param($list) foreach ($i in @($list)) { & $addValue $i.Key $i.ValueName $i.Value } }
    if ($State -eq 'NotConfigured') {
        if ($Policy.ValueName) { & $add 'Remove' $Policy.Key $Policy.ValueName '' $null }
        foreach ($i in @($Policy.EnabledList) + @($Policy.DisabledList)) { if ($i.ValueName) { & $add 'Remove' $i.Key $i.ValueName '' $null } }
        foreach ($e in @($Policy.Elements)) {
            if ($e.Type -eq 'list') { & $add 'RemoveKeyValues' $e.Key '' '' $null }
            elseif ($e.ValueName) { & $add 'Remove' $e.Key $e.ValueName '' $null }
            if ($e.Type -eq 'boolean') { foreach ($i in @($e.TrueList) + @($e.FalseList)) { if ($i.ValueName) { & $add 'Remove' $i.Key $i.ValueName '' $null } } }
            if ($e.Type -eq 'enum') { foreach ($it in @($e.Items)) { foreach ($vl in @($it.ValueList)) { if ($vl.ValueName) { & $add 'Remove' $vl.Key $vl.ValueName '' $null } } } }
        }
        return $ops.ToArray()
    }
    if ($State -eq 'Disabled') {
        if ($Policy.DisabledValue) { & $addValue $Policy.Key $Policy.ValueName $Policy.DisabledValue }
        elseif ($Policy.ValueName -and @($Policy.DisabledList).Count -eq 0) { & $add 'Set' $Policy.Key $Policy.ValueName 'DWord' ([uint32]0) }
        & $addList $Policy.DisabledList
        foreach ($e in @($Policy.Elements)) {
            if ($e.Type -eq 'list') { & $add 'DeleteValues' $e.Key '' '' $null }
            elseif ($e.ValueName) { & $add 'Delete' $e.Key $e.ValueName '' $null }
        }
        return $ops.ToArray()
    }
    # Enabled
    if ($Policy.EnabledValue) { & $addValue $Policy.Key $Policy.ValueName $Policy.EnabledValue }
    elseif ($Policy.ValueName -and @($Policy.EnabledList).Count -eq 0) { & $add 'Set' $Policy.Key $Policy.ValueName 'DWord' ([uint32]1) }
    & $addList $Policy.EnabledList
    foreach ($e in @($Policy.Elements)) {
        $has = $Values.ContainsKey($e.Id)
        $v = $(if ($has) { $Values[$e.Id] } else { $e.Default })
        if ($null -eq $v -or [string]$v -eq '') {
            if ($e.Required) { throw "Element '$($e.Label)' ($($e.Id)) of '$($Policy.DisplayName)' needs a value." }
            continue
        }
        switch ($e.Type) {
            { $_ -in 'decimal', 'longDecimal' } {
                $n = [uint64]$v
                if ($n -lt [uint64]$e.Min -or $n -gt [uint64]$e.Max) { throw "Element '$($e.Label)' must be between $($e.Min) and $($e.Max)." }
                if ($e.StoreAsText) { & $add 'Set' $e.Key $e.ValueName 'String' ([string]$n) }
                elseif ($e.Type -eq 'longDecimal') { & $add 'Set' $e.Key $e.ValueName 'QWord' $n }
                else { & $add 'Set' $e.Key $e.ValueName 'DWord' ([uint32]$n) }
            }
            'text' {
                $s = [string]$v
                if ($s.Length -gt [int]$e.MaxLength) { throw "Element '$($e.Label)' is longer than $($e.MaxLength) characters." }
                & $add 'Set' $e.Key $e.ValueName $(if ($e.Expandable) { 'ExpandString' } else { 'String' }) $s
            }
            'multiText' { & $add 'Set' $e.Key $e.ValueName 'MultiString' @(@($v) | ForEach-Object { [string]$_ }) }
            'boolean' {
                $on = [bool]$v
                $val = $(if ($on) { $e.TrueValue } else { $e.FalseValue })
                if ($val) { & $addValue $e.Key $e.ValueName $val } else { & $add 'Set' $e.Key $e.ValueName 'DWord' ([uint32]$(if ($on) { 1 } else { 0 })) }
                & $addList $(if ($on) { $e.TrueList } else { $e.FalseList })
            }
            'enum' {
                $items = @($e.Items)
                $item = $null
                if ($v -is [int] -or [string]$v -match '^\d+$') { if ([int]$v -lt $items.Count) { $item = $items[[int]$v] } }
                if (-not $item) { $item = @($items | Where-Object { [string]$_.DisplayName -eq [string]$v }) | Select-Object -First 1 }
                if (-not $item) { throw "'$v' is not an option of '$($e.Label)' (options: $(@($items | ForEach-Object { $_.DisplayName }) -join '; '))." }
                & $addValue $e.Key $e.ValueName $item.Value
                & $addList $item.ValueList
            }
            'list' {
                if (-not $e.Additive) { & $add 'DeleteValues' $e.Key '' '' $null }
                if ($e.ExplicitValue) {
                    if (-not ($v -is [hashtable] -or $v -is [System.Collections.IDictionary])) { throw "Element '$($e.Label)' needs name=value pairs." }
                    foreach ($k in @($v.Keys)) { & $add 'Set' $e.Key ([string]$k) $(if ($e.Expandable) { 'ExpandString' } else { 'String' }) ([string]$v[$k]) }
                } else {
                    $n = 0
                    foreach ($item in @($v)) { $n++; & $add 'Set' $e.Key ("{0}{1}" -f $(if ($e.ValuePrefix) { $e.ValuePrefix } else { '' }), $(if ($e.ValuePrefix) { $n } else { [string]$item })) $(if ($e.Expandable) { 'ExpandString' } else { 'String' }) ([string]$item) }
                }
            }
        }
    }
    return $ops.ToArray()
}

function Get-IgwtPolicyDenylist {
    [CmdletBinding()]
    param()
    if (-not $script:IgwtPolicyDenylist) { $script:IgwtPolicyDenylist = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'policy\denylist.json')).entries) }
    return $script:IgwtPolicyDenylist
}

function Test-IgwtPolicyOpAllowed {
    <# .SYNOPSIS The denylist reason when an operation would turn off a security protection, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Op)
    if ($Op.Op -ne 'Set') { return $null }
    foreach ($d in @(Get-IgwtPolicyDenylist)) {
        if ([string]$Op.Key -notmatch "^(?i)(?:$($d.key))$") { continue }
        if ([string]$Op.ValueName -notmatch "^(?i)(?:$($d.valueName))$") { continue }
        $vals = @($d.values | ForEach-Object { [string]$_ })
        if ($vals -contains 'any' -or $vals -contains ([string](@($Op.Value) -join ','))) { return [string]$d.reason }
    }
    return $null
}

function ConvertTo-IgwtPolTypeNumber {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Type)
    switch ($Type) { 'String' { 1 } 'ExpandString' { 2 } 'Binary' { 3 } 'DWord' { 4 } 'MultiString' { 7 } 'QWord' { 11 } default { throw "Unsupported type $Type." } }
}

function Update-IgwtPolEntries {
    <# .SYNOPSIS Applies operations to Registry.pol entries (Set, Delete marker, DeleteValues marker, Remove, RemoveKeyValues). Pure. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure function over an in-memory list.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Ops)
    $list = @($Entries)
    foreach ($o in $Ops) {
        switch ($o.Op) {
            'Set' { $list = @(Set-IgwtPolEntry -Entries $list -Key $o.Key -ValueName $o.ValueName -Type (ConvertTo-IgwtPolTypeNumber -Type $o.Type) -Value $o.Value) }
            'Delete' { $list = @(Add-IgwtPolDeleteMarker -Entries $list -Key $o.Key -ValueName $o.ValueName) }
            'Remove' { $list = @(Remove-IgwtPolEntry -Entries $list -Key $o.Key -ValueName $o.ValueName) }
            'DeleteValues' {
                $list = @($list | Where-Object { -not [string]::Equals([string]$_.Key, $o.Key, [System.StringComparison]::OrdinalIgnoreCase) })
                $list = @($list + (New-IgwtPolEntryObject -Key $o.Key -ValueName '**delvals.' -Type 1 -Data ([System.Text.Encoding]::Unicode.GetBytes(' ' + [char]0))))
            }
            'RemoveKeyValues' { $list = @($list | Where-Object { -not [string]::Equals([string]$_.Key, $o.Key, [System.StringComparison]::OrdinalIgnoreCase) }) }
        }
    }
    return $list
}

#endregion

#region Effective state and source

function Get-IgwtPolicyRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class)
    if ($Class -eq 'Machine') { return 'HKLM:\' } else { return 'HKCU:\' }
}

function Get-IgwtLocalPolicyEntries {
    <# .SYNOPSIS Entries of the Local GPO Registry.pol for Machine or User (empty when the file does not exist). Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class)
    $cacheKey = "pol:$Class"
    return @(Get-IgwtCached -Key $cacheKey -TtlSeconds 30 -ScriptBlock { @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $Class)).Entries) })
}

function Get-IgwtDomainPolicyResult {
    <#
    .SYNOPSIS
        Registry policy results from domain GPOs: gpresult /x to a temporary file (domain-joined PCs
        only), parsed for the registry extension. Read-only; cached for the session.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    $m = Get-IgwtManagementState
    if (-not $m.DomainJoined) { return @() }
    if ($script:IgwtDomainRsop -and -not $Force) { return $script:IgwtDomainRsop }
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: gpresult must be mocked in tests.' }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-rsop-{0}.xml" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & (Join-Path $env:SystemRoot 'System32\gpresult.exe') /x $tmp /f 2>&1
        if (-not (Test-Path -LiteralPath $tmp)) { return @() }
        $script:IgwtDomainRsop = @(ConvertFrom-IgwtRsopXml -Xml ([System.IO.File]::ReadAllText($tmp)))
        return $script:IgwtDomainRsop
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function ConvertFrom-IgwtRsopXml {
    <# .SYNOPSIS Registry settings from gpresult XML: Scope (Machine/User), Key, ValueName, Value, Gpo. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Xml)
    $doc = New-Object System.Xml.XmlDocument; $doc.XmlResolver = $null; $doc.LoadXml($Xml)
    foreach ($scope in @(@('ComputerResults', 'Machine'), @('UserResults', 'User'))) {
        $node = $doc.DocumentElement[$scope[0]]
        if (-not $node) { continue }
        foreach ($rs in @($node.SelectNodes(".//*[local-name()='RegistrySetting']"))) {
            $key = ''; $name = ''; $val = ''; $gpo = ''
            foreach ($c in $rs.ChildNodes) {
                switch ($c.LocalName) {
                    'KeyPath' { $key = $c.InnerText } 'AdmSetting' { } 'Value' { $name = [string]$c.SelectSingleNode("*[local-name()='Name']").InnerText; $val = [string]$c.SelectSingleNode("*[local-name()='Number' or local-name()='String']").InnerText }
                    'GPO' { $gpo = [string]$c.SelectSingleNode("*[local-name()='Identifier']").InnerText }
                }
            }
            [pscustomobject]@{ Scope = $scope[1]; Key = $key; ValueName = $name; Value = $val; Gpo = $gpo }
        }
    }
}

function Get-IgwtMdmPolicyValue {
    <#
    .SYNOPSIS
        An MDM (PolicyManager) value for a policy, or $null: ADMX-backed MDM policies are stored
        under PolicyManager\current\device\<area> with the policy name. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy)
    $root = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
    try {
        if (-not (Test-IgwtRegistryKey -Path $root)) { return $null }
        foreach ($area in @(Get-ChildItem -LiteralPath (Resolve-IgwtRegistryPath -Path $root) -ErrorAction Stop)) {
            foreach ($n in @($Policy.Name, $Policy.ValueName) | Where-Object { $_ }) {
                $v = $area.GetValue($n)
                if ($null -ne $v) { return [pscustomobject]@{ Area = $area.PSChildName; Name = $n; Value = $v } }
            }
        }
    } catch { Write-Verbose "PolicyManager unreadable: $($_.Exception.Message)" }
    return $null
}

function Get-IgwtPolicyState {
    <#
    .SYNOPSIS
        Effective state of one policy per class: the Local GPO state (Enabled, Disabled, Not
        configured, Configured), the actual registry values, domain GPO and MDM values, the winning
        source and conflicts. Flags a value present in the registry but in no Registry.pol as
        tattooed. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [ValidateSet('Machine', 'User')][string]$Class)
    if (-not $Class) { $Class = $(if ([string]$Policy.Class -eq 'User') { 'User' } else { 'Machine' }) }
    $entries = @(Get-IgwtLocalPolicyEntries -Class $Class)
    $enabledOps = @(Get-IgwtPolicyRegistryOps -Policy $Policy -State NotConfigured)
    $names = @($enabledOps | Where-Object { $_.Op -eq 'Remove' } | ForEach-Object { "$($_.Key)|$($_.ValueName)".ToLowerInvariant() })
    $keys = @($enabledOps | Where-Object { $_.Op -eq 'RemoveKeyValues' } | ForEach-Object { ([string]$_.Key).ToLowerInvariant() })
    $mine = @($entries | Where-Object { $names -contains "$($_.Key)|$($_.ValueName -replace '^\*\*del\.', '')".ToLowerInvariant() -or $keys -contains ([string]$_.Key).ToLowerInvariant() })
    $local = 'NotConfigured'
    if ($mine.Count) {
        $main = @($mine | Where-Object { [string]::Equals($_.ValueName, [string]$Policy.ValueName, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
        $local = 'Configured'
        if ($main) {
            if ($Policy.EnabledValue -and $Policy.EnabledValue.Type -ne 'Delete' -and [string]$main.Value -eq [string]$Policy.EnabledValue.Value) { $local = 'Enabled' }
            elseif ($Policy.DisabledValue -and $Policy.DisabledValue.Type -ne 'Delete' -and [string]$main.Value -eq [string]$Policy.DisabledValue.Value) { $local = 'Disabled' }
            elseif (-not $Policy.EnabledValue -and -not $Policy.DisabledValue) { $local = $(if ([string]$main.Value -eq '1') { 'Enabled' } elseif ([string]$main.Value -eq '0') { 'Disabled' } else { 'Configured' }) }
        } elseif (@($mine | Where-Object { $_.Special -eq 'del' -or $_.Special -eq 'delvals' }).Count -eq $mine.Count) { $local = 'Disabled' }
    }
    $root = Get-IgwtPolicyRoot -Class $Class
    $registry = @(foreach ($o in $enabledOps | Where-Object { $_.Op -eq 'Remove' }) {
            $v = $null
            try { $v = Get-IgwtRegistryValue -Path ($root + $o.Key) -Name $o.ValueName } catch { $v = [pscustomobject]@{ Exists = $false; Value = $null } }
            [pscustomobject]@{ Key = $o.Key; ValueName = $o.ValueName; Exists = [bool]$v.Exists; Value = $v.Value; InLocalGpo = (@($mine | Where-Object { [string]::Equals($_.ValueName, $o.ValueName, [System.StringComparison]::OrdinalIgnoreCase) -and [string]::Equals($_.Key, $o.Key, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) }
        })
    $domain = @()
    try { $domain = @(Get-IgwtDomainPolicyResult | Where-Object { $_.Scope -eq $Class -and [string]::Equals($_.Key, [string]$Policy.Key, [System.StringComparison]::OrdinalIgnoreCase) }) } catch { Write-Verbose "Domain policy results unavailable: $($_.Exception.Message)" }
    $mdm = Get-IgwtMdmPolicyValue -Policy $Policy
    $present = @($registry | Where-Object { $_.Exists })
    $tattooed = @($present | Where-Object { $r = $_; -not $r.InLocalGpo -and @($domain | Where-Object { [string]::Equals($_.ValueName, $r.ValueName, [System.StringComparison]::OrdinalIgnoreCase) }).Count -eq 0 })
    $source = $(if ($domain.Count) { 'Domain GPO' } elseif ($mdm) { 'MDM' } elseif ($local -ne 'NotConfigured') { 'Local GPO' } elseif ($present.Count) { 'Registry only (tattooed)' } else { 'Not configured' })
    $conflicts = New-Object System.Collections.Generic.List[string]
    if ($domain.Count -and $local -ne 'NotConfigured') { $conflicts.Add('Local GPO and a domain GPO both configure it; the domain GPO wins.') }
    if ($mdm -and ($domain.Count -or $local -ne 'NotConfigured')) { $conflicts.Add('MDM and Group Policy both configure it; Group Policy wins unless MDM is set to win (ControlPolicyConflict).') }
    [pscustomobject]@{ Id = $Policy.Id; Class = $Class; LocalGpo = $local; Registry = $registry; Domain = $domain; Mdm = $mdm; Source = $source; Tattooed = ($tattooed.Count -gt 0 -and $local -eq 'NotConfigured'); Conflicts = $conflicts.ToArray() }
}

function Get-IgwtTattooedPolicyValues {
    <#
    .SYNOPSIS
        Values under the Policies keys that no Registry.pol (Local GPO) or domain GPO sets:
        "tattooed" settings left by earlier policies or tools. Values written directly by iG
        Windows Tuner catalog items are marked with the item id. Read-only.
    #>
    [CmdletBinding()]
    param()
    $catalogMap = @{}
    foreach ($t in @(Get-IgwtCatalog)) { foreach ($a in @($t.actions | Where-Object { [string]$_.type -eq 'registry' })) { $catalogMap[("$($a.path)|$($a.name)").ToLowerInvariant()] = [string]$t.id } }
    $domain = @()
    try { $domain = @(Get-IgwtDomainPolicyResult) } catch { $domain = @() }
    foreach ($class in 'Machine', 'User') {
        $root = Get-IgwtPolicyRoot -Class $class
        $entries = @(Get-IgwtLocalPolicyEntries -Class $class)
        $known = @{}
        foreach ($e in $entries) { $known[("$($e.Key)|$($e.ValueName)").ToLowerInvariant()] = $true }
        foreach ($d in @($domain | Where-Object { $_.Scope -eq $class })) { $known[("$($d.Key)|$($d.ValueName)").ToLowerInvariant()] = $true }
        foreach ($base in @('SOFTWARE\Policies', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies')) {
            $path = $root + $base
            if (-not (Test-IgwtRegistryKey -Path $path)) { continue }
            $resolved = Resolve-IgwtRegistryPath -Path $path
            $baseKey = Get-Item -LiteralPath $resolved -ErrorAction SilentlyContinue
            if (-not $baseKey) { continue }
            foreach ($k in @(@($baseKey) + @(Get-ChildItem -LiteralPath $resolved -Recurse -ErrorAction SilentlyContinue))) {
                # The key path relative to the hive, as Registry.pol stores it (works for TestRegistry too).
                $rel = $base + $k.Name.Substring($baseKey.Name.Length)
                foreach ($n in @($k.GetValueNames())) {
                    $id = ("$rel|$n").ToLowerInvariant()
                    if ($known.ContainsKey($id)) { continue }
                    $item = $catalogMap[("$($root)$rel|$n").ToLowerInvariant()]
                    [pscustomobject]@{ Class = $class; Key = $rel; ValueName = $n; Value = $k.GetValue($n); WrittenBy = $(if ($item) { "iG Windows Tuner item $item (direct registry write)" } else { 'unknown (an earlier policy or tool)' }) }
                }
            }
        }
    }
}

#endregion

#region Write path

function Get-IgwtPolicyChangePlan {
    <#
    .SYNOPSIS
        Dry run of Set-IgwtLocalPolicy: the Registry.pol operations, the denylist and edition or
        management refusals, and the current state. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled', 'NotConfigured')][string]$State,
        [hashtable]$Values = @{}, [ValidateSet('Machine', 'User')][string]$Class)
    $p = Get-IgwtPolicyDefinition -Id $Id
    if (-not $Class) { $Class = $(if ([string]$p.Class -eq 'User') { 'User' } else { 'Machine' }) }
    if ([string]$p.Class -ne 'Both' -and [string]$p.Class -ne $Class) { throw "'$($p.DisplayName)' is a $($p.Class) policy." }
    $ops = @(Get-IgwtPolicyRegistryOps -Policy $p -State $State -Values $Values)
    $refusals = New-Object System.Collections.Generic.List[string]
    foreach ($o in $ops) { $why = Test-IgwtPolicyOpAllowed -Op $o; if ($why) { $refusals.Add("$($o.Key)\$($o.ValueName) = $(@($o.Value) -join ','): $why") } }
    $m = Get-IgwtManagementState
    if (-not $m.LocalGroupPolicy) { $refusals.Add('Windows Home has no Local Group Policy: policy features are report-only on this edition.') }
    [pscustomobject]@{ Policy = $p; Class = $Class; State = $State; Ops = $ops; Refusals = $refusals.ToArray(); Managed = [bool]$m.Managed; Authorities = @($m.Authorities); Current = (Get-IgwtPolicyState -Policy $p -Class $Class) }
}

function Set-IgwtLocalPolicy {
    <#
    .SYNOPSIS
        Sets a policy in the Local GPO: backup of the GroupPolicy folders, Registry.pol update
        (preserving every other entry), gpt.ini version and client-side extension, targeted
        gpupdate, then verification of the resulting registry values. Revert with
        Restore-IgwtLocalGpo -BackupPath <Backup>.
    .PARAMETER AcknowledgeManaged
        Confirms a local change on a domain-joined or MDM-enrolled PC (a domain or MDM policy may override it).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled', 'NotConfigured')][string]$State,
        [hashtable]$Values = @{}, [ValidateSet('Machine', 'User')][string]$Class, [switch]$AcknowledgeManaged, [switch]$NoRefresh)
    $classArg = @{}; if ($Class) { $classArg.Class = $Class }
    $plan = Get-IgwtPolicyChangePlan -Id $Id -State $State -Values $Values @classArg
    if ($plan.Refusals.Count) { throw "Refused: $($plan.Refusals -join ' ')" }
    if ($plan.Managed -and -not $AcknowledgeManaged) { throw "This PC is managed ($($plan.Authorities -join ', ')); a domain or MDM policy can override local policies. Pass -AcknowledgeManaged to change it locally." }
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Changing Local Group Policy needs administrator rights.' }
    if (-not $PSCmdlet.ShouldProcess("$($plan.Policy.DisplayName) ($($plan.Class))", "Set $State")) { return $null }
    $backup = Backup-IgwtLocalGpo -Reason "before $($plan.Policy.Id) -> $State"
    $polPath = Get-IgwtLocalPolPath -Class $plan.Class
    $before = @((Read-IgwtRegistryPol -Path $polPath).Entries)
    $after = @(Update-IgwtPolEntries -Entries $before -Ops $plan.Ops)
    Write-IgwtRegistryPol -Path $polPath -Entries $after
    $gpt = Join-Path (Get-IgwtGpoRoot) 'gpt.ini'
    Assert-IgwtGpoPathAllowed -Path $gpt
    $text = $(if (Test-Path -LiteralPath $gpt) { [System.IO.File]::ReadAllText($gpt) } else { '' })
    [System.IO.File]::WriteAllText($gpt, (Update-IgwtGptIniText -Text $text -Class $plan.Class), [System.Text.Encoding]::ASCII)
    Clear-IgwtCache -Prefix 'pol:' -WhatIf:$false
    Write-IgwtLog -Message "Local Group Policy: $($plan.Policy.Id) ($($plan.Class)) -> $State. Backup: $backup"
    $verified = $null; $mismatch = @()
    if (-not $NoRefresh) {
        Invoke-IgwtGpUpdate -Target $plan.Class
        $root = Get-IgwtPolicyRoot -Class $plan.Class
        foreach ($o in @($plan.Ops | Where-Object { $_.Op -in 'Set', 'Delete' })) {
            $v = Get-IgwtRegistryValue -Path ($root + $o.Key) -Name $o.ValueName
            $ok = $(if ($o.Op -eq 'Delete') { -not $v.Exists } else { $v.Exists -and ((@($v.Value) -join ',') -eq (@($o.Value) -join ',')) })
            if (-not $ok) { $mismatch += "$($o.Key)\$($o.ValueName)" }
        }
        $verified = ($mismatch.Count -eq 0)
    }
    return [pscustomobject]@{ Id = $plan.Policy.Id; Class = $plan.Class; State = $State; Backup = $backup; Ops = $plan.Ops; Verified = $verified; Mismatch = $mismatch }
}

#endregion
