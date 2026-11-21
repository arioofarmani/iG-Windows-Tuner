# RegistryCleanerProvider.ps1
# The registry cleaner's change provider 'regClean' (DECISIONS RG16, RG17, RG20): every removal
# and every restore of a cleaner entry is one step of the change engine (Invoke-IgwtChangeStep), so
# intent, read-back, rollback, recovery, revert plans, drift and the journal tab work unchanged.
# Resolve is structural (the target's own fields, the category roots and the deny list); Get is the
# exact snapshot; Set runs the protection and evidence re-check (RG14 point 3) and refuses
# everything it cannot prove; Restore is additive only. The only registry writes of the cleaner are
# the four internals below (Remove-IgwtRegCleanKeyTree, Remove-IgwtRegCleanValue,
# Restore-IgwtRegCleanKeyTree, Restore-IgwtRegCleanValue), reached only through this provider.

# The protection context of the running cleanup (Invoke-IgwtRegistryCleanup), read by Set (RG14).
$script:IgwtRegCleanStep = $null
$script:IgwtRegCleanUserSidPattern = '^S-1-5-21(-[0-9]+){4}$'
$script:IgwtRegCleanSignInMessage = 'Refused: This entry belongs to a user who is not signed in; sign in as that user.'
$script:IgwtRegCleanReappearedMessage = 'Refused: the key exists again with other data; nothing changed.'

#region Targets

function Get-IgwtRegCleanTarget {
    <#
    .SYNOPSIS
        The journal target of one cleaner finding (RG16): [ordered]{provider 'regClean'; key
        'regclean|<kind>|<hive>|<sid or ->|<view>|<path>[|<value or rule name>]'; item
        'regclean:<category>'; kind; hive; sid; view; path; valueName; ruleName; category}. Pure.
    .PARAMETER Finding
        A finding (RG3 shape) of kind regKeyTree, regValue or firewallRule.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $s = { param($n) if ($Finding.PSObject.Properties[$n] -and $null -ne $Finding.$n) { [string]$Finding.$n } else { '' } }
    $kind = & $s 'Kind'
    $isReg = $kind -in 'regKeyTree', 'regValue'
    $hive = $(if ($isReg) { & $s 'Hive' } else { '' })
    $sid = $(if ($hive -eq 'HKCU') { & $s 'Sid' } else { '' })
    $view = $(if ($isReg) { $(if ($hive -eq 'HKLM' -and (& $s 'View') -eq '32') { '32' } else { '64' }) } else { '' })
    $path = $(if ($isReg) { (& $s 'Path').Trim('\') } else { '' })
    $valueName = $(if ($kind -eq 'regValue') { & $s 'ValueName' } else { '' })
    $ruleName = $(if ($kind -eq 'firewallRule') { & $s 'RuleName' } else { '' })
    $category = & $s 'Category'
    $key = Get-IgwtRegCleanTargetKey -Kind $kind -Hive $hive -Sid $sid -View $view -Path $path -Name $(if ($kind -eq 'regValue') { $valueName } else { $ruleName })
    return [ordered]@{
        provider = 'regClean'; key = $key; item = ('regclean:' + $category); kind = $kind; hive = $hive; sid = $sid; view = $view
        path = $path; valueName = $valueName; ruleName = $ruleName; category = $category
    }
}

function Test-IgwtRegCleanHiveLoaded {
    <#
    .SYNOPSIS
        True when the hive of a user SID is loaded (HKEY_USERS\<sid> exists, through
        Resolve-IgwtRegistryPath so TestMode reads TestRegistry). Read-only.
    .PARAMETER Sid
        The user SID.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Sid)
    $loc = Get-IgwtRegCleanKeyLocation -Hive HKCU -Path '' -Sid $Sid
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($loc.Hive, $loc.View)
    try {
        $k = $base.OpenSubKey($loc.SubKey, $false)
        if ($null -eq $k) { return $false }
        $k.Dispose()
        return $true
    } finally { $base.Dispose() }
}

function Resolve-IgwtRegCleanTarget {
    <#
    .SYNOPSIS
        The provider's Resolve (RG16): checks a 'regClean' journal target from its own fields and
        returns {Key; Category; Kind; Hive; Sid; View; Path; ValueName; RuleName}. Throws for
        anything the cleaner does not own. Structural: it reads the category data and, for HKCU,
        only whether the user's hive is loaded.
    .DESCRIPTION
        The kind must be regKeyTree, regValue or firewallRule and match the category in
        data\registry\categories.json; the key must be the one the fields give. Registry targets:
        hive HKLM or HKCU, an HKCU target needs a user SID (S-1-5-21-...) and view 64, the path lies
        below a root of its category (a key tree never is the root itself) and no segment below the
        root is on the RG32 deny list. An HKCU target whose hive is not loaded is refused with the
        sign-in message (RG33).
    .PARAMETER Target
        The journal target (dictionary).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target)
    $f = { param($n) if ($Target -is [System.Collections.IDictionary]) { [string]$Target[$n] } elseif ($Target.PSObject.Properties[$n]) { [string]$Target.$n } else { '' } }
    $no = 'is not a registry cleaner entry the tool owns'
    if ((& $f 'provider') -ne 'regClean') { throw "'$(& $f 'key')' $no." }
    $kind = & $f 'kind'
    $cat = & $f 'category'
    if ($kind -notin 'regKeyTree', 'regValue', 'firewallRule') { throw "'$(& $f 'key')' $no (kind '$kind')." }
    $c = @(@((Get-IgwtRegCleanCategories).categories) | Where-Object { $_ -and [string]$_.id -eq $cat })
    if ($c.Count -ne 1 -or [string]$c[0].kind -ne $kind) { throw "'$(& $f 'key')' $no (category '$cat')." }
    if ((& $f 'item') -ne ('regclean:' + $cat)) { throw "'$(& $f 'key')' $no (item)." }
    $hive = & $f 'hive'; $sid = & $f 'sid'; $view = & $f 'view'; $path = & $f 'path'; $valueName = & $f 'valueName'; $ruleName = & $f 'ruleName'
    if ($kind -eq 'firewallRule') {
        if (-not $ruleName -or $hive -or $sid -or $view -or $path) { throw "'$(& $f 'key')' $no (firewall rule fields)." }
    } else {
        if ($hive -notin 'HKLM', 'HKCU') { throw "'$(& $f 'key')' $no (hive '$hive')." }
        if ($hive -eq 'HKCU') {
            if ($sid -notmatch $script:IgwtRegCleanUserSidPattern) { throw "'$(& $f 'key')' $no (an HKCU entry needs a user SID)." }
            if ($view -ne '64') { throw "'$(& $f 'key')' $no (view)." }
        } elseif ($sid) { throw "'$(& $f 'key')' $no (an HKLM entry has no SID)." }
        if ($view -notin '64', '32') { throw "'$(& $f 'key')' $no (view '$view')." }
        if ($kind -ne 'regValue' -and $valueName) { throw "'$(& $f 'key')' $no (value name)." }
        if ($ruleName) { throw "'$(& $f 'key')' $no (rule name)." }
        if (-not $path -or $path -ne $path.Trim('\') -or $path -match '\\\\' -or $path -match '[\x00-\x1F]') { throw "'$(& $f 'key')' $no (path)." }
        $segments = $path.Split('\')
        if (@($segments | Where-Object { $_ -in '.', '..' }).Count) { throw "'$(& $f 'key')' $no (path)." }
        $root = $null
        foreach ($r in @(Get-IgwtRegCleanCategoryRoots | Where-Object { $_.Category -eq $cat -and $_.Hive -eq $hive -and $_.View -eq $view })) {
            if ([string]::Equals($path, $r.Path, [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith($r.Path + '\', [StringComparison]::OrdinalIgnoreCase)) {
                if ($null -eq $root -or $r.Path.Length -gt $root.Path.Length) { $root = $r }
            }
        }
        if ($null -eq $root) { throw "'$(& $f 'key')' $no (outside the keys its category may remove)." }
        $below = @()
        if ($path.Length -gt $root.Path.Length) { $below = @($path.Substring($root.Path.Length + 1).Split('\')) }
        if ($kind -eq 'regKeyTree' -and $below.Count -eq 0) { throw "'$(& $f 'key')' $no (a category root is never removed)." }
        $deny = @(@((Get-IgwtRegCleanCategories).denyList.segmentNames) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        foreach ($seg in $below) { if ($deny -contains $seg) { throw "'$(& $f 'key')' $no (shared or linked key '$seg')." } }
    }
    $expect = Get-IgwtRegCleanTargetKey -Kind $kind -Hive $hive -Sid $sid -View $view -Path $path -Name $(if ($kind -eq 'regValue') { $valueName } else { $ruleName })
    if ((& $f 'key') -ne $expect) { throw "'$(& $f 'key')' $no (the key does not match its fields)." }
    if ($hive -eq 'HKCU' -and -not (Test-IgwtRegCleanHiveLoaded -Sid $sid)) { throw $script:IgwtRegCleanSignInMessage }
    return [pscustomobject]@{ Key = $expect; Category = $cat; Kind = $kind; Hive = $hive; Sid = $sid; View = $view; Path = $path; ValueName = $valueName; RuleName = $ruleName }
}

#endregion

#region Snapshots and checks

function Get-IgwtRegCleanFirewallSnapshot {
    <#
    .SYNOPSIS
        The firewall rule snapshot (RG17): Get-IgwtFirewallRuleDefinition of the rule plus exists,
        kind 'firewallRule' and value (the display name); {exists $false; kind; value ''; name} when
        the rule is gone from the persistent store. Read-only.
    .PARAMETER RuleName
        The rule name (not the display name).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RuleName)
    $rules = @()
    try { $rules = @(Get-NetFirewallRule -Name $RuleName -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_ }) }
    catch { if ([string]$_.CategoryInfo.Category -eq 'ObjectNotFound') { $rules = @() } else { throw } }
    if ($rules.Count -eq 0) { return [ordered]@{ exists = $false; kind = 'firewallRule'; value = ''; name = $RuleName } }
    $def = Get-IgwtFirewallRuleDefinition -Name $RuleName
    $snap = [ordered]@{ exists = $true; kind = 'firewallRule'; value = [string]$def['displayName'] }
    foreach ($k in @($def.Keys)) { if ([string]$k -notin 'exists', 'kind', 'value') { $snap[[string]$k] = $def[$k] } }
    return $snap
}

function Get-IgwtRegCleanTargetSnapshot {
    <#
    .SYNOPSIS
        The provider's Get (RG16, RG17): the exact snapshot of a resolved target (key tree, value or
        firewall rule). Throws when it cannot be exact, so a step ends with nothing changed.
        Read-only.
    .PARAMETER Resolved
        A Resolve-IgwtRegCleanTarget result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resolved)
    switch ($Resolved.Kind) {
        'regKeyTree' { return (Get-IgwtRegCleanKeySnapshot -Hive $Resolved.Hive -Sid $Resolved.Sid -View $Resolved.View -Path $Resolved.Path) }
        'regValue' { return (Get-IgwtRegCleanValueSnapshot -Hive $Resolved.Hive -Sid $Resolved.Sid -View $Resolved.View -Path $Resolved.Path -Name $Resolved.ValueName) }
        'firewallRule' { return (Get-IgwtRegCleanFirewallSnapshot -RuleName $Resolved.RuleName) }
    }
    throw "Unknown registry cleaner kind '$($Resolved.Kind)'."
}

function Get-IgwtRegCleanSnapshotField {
    <#
    .SYNOPSIS
        One field of a snapshot that may be an ordered dictionary, a journal dictionary or an object
        read back from JSON ($null when missing). Pure.
    .PARAMETER Snapshot
        The snapshot.
    .PARAMETER Name
        The field name.
    #>
    [CmdletBinding()]
    param($Snapshot, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Snapshot) { return $null }
    if ($Snapshot -is [System.Collections.IDictionary]) {
        if (Test-IgwtMapKey $Snapshot $Name) { return $Snapshot[$Name] }
        return $null
    }
    if ($Snapshot.PSObject.Properties[$Name]) { return $Snapshot.$Name }
    return $null
}

function Test-IgwtRegCleanSnapshotEqual {
    <#
    .SYNOPSIS
        True when two snapshots hold the same compared data (canonical JSON without the applied
        data). Pure.
    .PARAMETER Left
        A snapshot.
    .PARAMETER Right
        A snapshot.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Left, $Right)
    return ((ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $Left)) -eq (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $Right)))
}

function Get-IgwtRegCleanSecurityRefusal {
    <#
    .SYNOPSIS
        Why a key tree must not be removed because of its permissions (RG17 offer rule), or '': a
        key with a protected ACL, an explicit ACE, or an owner other than SYSTEM, Administrators or
        the scanned user. Pure.
    .PARAMETER Rows
        Get-IgwtRegCleanTreeSecurity rows.
    .PARAMETER Sid
        The scanned user's SID (HKCU entries), or ''.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyString()][string]$Sid = '')
    $owners = @($script:IgwtRegCleanOwnerSids) + @($(if ($Sid) { $Sid }))
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = [string](Get-IgwtRegCleanSnapshotField $r 'key')
        $label = $(if ($k) { "the subkey '$k'" } else { 'the key' })
        if ([bool](Get-IgwtRegCleanSnapshotField $r 'aclProtected') -or [int](Get-IgwtRegCleanSnapshotField $r 'explicitAceCount') -gt 0) { return "$label has its own permissions" }
        if ($owners -notcontains [string](Get-IgwtRegCleanSnapshotField $r 'owner')) { return "$label is owned by another account" }
    }
    return ''
}

#endregion

#region Registry writes (provider internals, reached only through the regClean provider)

function Remove-IgwtRegCleanKeyTree {
    <#
    .SYNOPSIS
        Removes one key tree bottom-up (RG17): reads the tree again, refuses when it differs from
        the snapshot taken before, then deletes the recorded values of each key and the key itself
        with DeleteSubKey, leaf first over the ordinally sorted key list in reverse. A key that
        still has a subkey makes DeleteSubKey fail, so nothing that was not backed up is removed.
        Provider internal: called only by the regClean provider's Set.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER Sid
        The user SID for HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Before
        The snapshot the removal was approved for (Get-IgwtRegCleanKeySnapshot).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [AllowEmptyString()][AllowNull()][string]$Sid = '',
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Before
    )
    Assert-IgwtWritable -Operation 'Remove-IgwtRegCleanKeyTree'
    $now = Get-IgwtRegCleanKeySnapshot -Hive $Hive -Sid $Sid -View $View -Path $Path
    if (-not $now.exists) { throw 'Refused: the key no longer exists; nothing changed.' }
    if (-not (Test-IgwtRegCleanSnapshotEqual -Left $now -Right $Before)) { throw 'Refused: changed since the preview; nothing changed.' }
    if (-not $PSCmdlet.ShouldProcess("$Hive\$Path", 'Remove registry key tree')) { return }
    $loc = Get-IgwtRegCleanKeyLocation -Hive $Hive -View $View -Path $Path -Sid $Sid
    $byKey = @{}
    foreach ($v in @($now.valueList)) {
        $k = [string]$v['key']
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.Generic.List[string] }
        $byKey[$k].Add([string]$v['name'])
    }
    $keys = [string[]]@($now.keyList)
    [Array]::Reverse($keys)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($loc.Hive, $loc.View)
    try {
        foreach ($rel in $keys) {
            $sub = $(if ($rel) { $loc.SubKey + '\' + $rel } else { $loc.SubKey })
            $cut = $sub.LastIndexOf('\')
            if ($cut -lt 1) { throw "The key '$sub' has no parent key." }
            $key = $base.OpenSubKey($sub, $true)
            if ($null -eq $key) { throw "The key '$rel' disappeared during the removal." }
            try { if ($byKey.ContainsKey($rel)) { foreach ($n in $byKey[$rel]) { $key.DeleteValue($n, $false) } } } finally { $key.Dispose() }
            $parent = $base.OpenSubKey($sub.Substring(0, $cut), $true)
            if ($null -eq $parent) { throw "The parent of '$rel' disappeared during the removal." }
            try { $parent.DeleteSubKey($sub.Substring($cut + 1), $false) } finally { $parent.Dispose() }
        }
    } finally { $base.Dispose() }
}

function Remove-IgwtRegCleanValue {
    <#
    .SYNOPSIS
        Removes one registry value (RG17) after reading it again and refusing when it differs from
        the snapshot taken before. Provider internal: called only by the regClean provider's Set.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER Sid
        The user SID for HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Name
        The value name.
    .PARAMETER Before
        The snapshot the removal was approved for (Get-IgwtRegCleanValueSnapshot).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [AllowEmptyString()][AllowNull()][string]$Sid = '',
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)]$Before
    )
    Assert-IgwtWritable -Operation 'Remove-IgwtRegCleanValue'
    $now = Get-IgwtRegCleanValueSnapshot -Hive $Hive -Sid $Sid -View $View -Path $Path -Name $Name
    if (-not $now.exists) { throw 'Refused: the value no longer exists; nothing changed.' }
    if (-not (Test-IgwtRegCleanSnapshotEqual -Left $now -Right $Before)) { throw 'Refused: changed since the preview; nothing changed.' }
    if (-not $PSCmdlet.ShouldProcess("$Hive\$Path\$Name", 'Remove registry value')) { return }
    $loc = Get-IgwtRegCleanKeyLocation -Hive $Hive -View $View -Path $Path -Sid $Sid
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($loc.Hive, $loc.View)
    try {
        $key = $base.OpenSubKey($loc.SubKey, $true)
        if ($null -eq $key) { throw 'The key of the value disappeared during the removal.' }
        try { $key.DeleteValue([string]$now.name, $true) } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function ConvertTo-IgwtRegCleanRawValue {
    <#
    .SYNOPSIS
        What RegistryKey.SetValue needs for one value of a cleaner snapshot (kind kept exactly,
        strings never expanded): the raw data, in a one-element wrapper so arrays stay whole. Throws
        for a kind that cannot be restored. Pure.
    .PARAMETER Kind
        The RegistryValueKind name.
    .PARAMETER Data
        The snapshot data.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [AllowNull()]$Data)
    if ($Kind -notin 'String', 'ExpandString', 'MultiString', 'DWord', 'QWord', 'Binary', 'None') { throw "A value of kind '$Kind' cannot be restored." }
    $norm = ConvertFrom-IgwtSerializableValue -Data $Data -Kind $Kind
    if ($null -eq $norm) {
        if ($Kind -in 'String', 'ExpandString') { $norm = '' }
        elseif ($Kind -eq 'MultiString') { $norm = [string[]]@() }
        elseif ($Kind -in 'Binary', 'None') { $norm = [byte[]]@() }
    }
    $raw = ConvertTo-IgwtRawRegistryValue -Value $norm -Kind $Kind
    if ($Kind -eq 'MultiString' -and $null -eq $raw) { $raw = [string[]]@() }
    if ($Kind -in 'Binary', 'None' -and $null -eq $raw) { $raw = [byte[]]@() }
    return , @(, $raw)
}

function Restore-IgwtRegCleanKeyTree {
    <#
    .SYNOPSIS
        Restores a removed key tree from its snapshot, additively (RG20): only missing keys and
        values are created; nothing is deleted or overwritten. Provider internal: called only by the
        regClean provider's Restore.
    .DESCRIPTION
        If a key or value is present that the snapshot does not hold, or a present value differs,
        it throws 'Refused: the key exists again with other data; nothing changed' before writing
        anything. When everything present equals the snapshot it fills in the rest, so a rollback
        after a partial removal is exact and a restore of an unchanged key changes nothing. A
        snapshot of a key that did not exist is restored only when the key is still absent.
    .PARAMETER Hive
        HKLM or HKCU (from the target, never from journal data).
    .PARAMETER Sid
        The user SID for HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Snapshot
        The recorded key tree snapshot (Get-IgwtRegCleanKeySnapshot shape, or the same data from
        the journal).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [AllowEmptyString()][AllowNull()][string]$Sid = '',
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Snapshot
    )
    Assert-IgwtWritable -Operation 'Restore-IgwtRegCleanKeyTree'
    if ([string](Get-IgwtRegCleanSnapshotField $Snapshot 'kind') -ne 'keyTree') { throw 'This is not a key tree snapshot.' }
    $sp = [string](Get-IgwtRegCleanSnapshotField $Snapshot 'path')
    if (-not [string]::Equals($sp.Trim('\'), $Path.Trim('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'The snapshot belongs to another key.' }
    $now = $null
    try { $now = Get-IgwtRegCleanKeySnapshot -Hive $Hive -Sid $Sid -View $View -Path $Path }
    catch { throw "Refused: the key exists again and cannot be compared ($($_.Exception.Message)); nothing changed." }
    if (-not [bool](Get-IgwtRegCleanSnapshotField $Snapshot 'exists')) {
        if ($now.exists) { throw $script:IgwtRegCleanReappearedMessage }
        return
    }
    $wantKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $orderedKeys = New-Object System.Collections.Generic.List[string]
    foreach ($k in @(Get-IgwtRegCleanSnapshotField $Snapshot 'keyList')) { if ($wantKeys.Add([string]$k)) { $orderedKeys.Add([string]$k) } }
    $want = @{}
    foreach ($v in @(Get-IgwtRegCleanSnapshotField $Snapshot 'valueList')) {
        if ($null -eq $v) { continue }
        $want[([string](Get-IgwtRegCleanSnapshotField $v 'key') + '|' + [string](Get-IgwtRegCleanSnapshotField $v 'name')).ToLowerInvariant()] = $v
    }
    # Everything present must be part of the snapshot and equal to it.
    $have = @{}
    foreach ($k in @($now.keyList)) { if (-not $wantKeys.Contains([string]$k)) { throw $script:IgwtRegCleanReappearedMessage } }
    foreach ($v in @($now.valueList)) {
        $id = ([string]$v['key'] + '|' + [string]$v['name']).ToLowerInvariant()
        if (-not $want.ContainsKey($id)) { throw $script:IgwtRegCleanReappearedMessage }
        $w = $want[$id]
        $same = ([string](Get-IgwtRegCleanSnapshotField $w 'kind') -eq [string]$v['kind']) -and ((ConvertTo-IgwtCanonicalJson (Get-IgwtRegCleanSnapshotField $w 'data')) -eq (ConvertTo-IgwtCanonicalJson $v['data']))
        if (-not $same) { throw $script:IgwtRegCleanReappearedMessage }
        $have[$id] = $true
    }
    if (-not $PSCmdlet.ShouldProcess("$Hive\$Path", 'Restore registry key tree')) { return }
    $loc = Get-IgwtRegCleanKeyLocation -Hive $Hive -View $View -Path $Path -Sid $Sid
    $sorted = $orderedKeys.ToArray()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($loc.Hive, $loc.View)
    try {
        foreach ($rel in $sorted) {
            $sub = $(if ($rel) { $loc.SubKey + '\' + $rel } else { $loc.SubKey })
            $key = $base.CreateSubKey($sub)
            if ($null -eq $key) { throw "The key '$rel' could not be created." }
            try {
                foreach ($id in @($want.Keys)) {
                    $w = $want[$id]
                    if ([string](Get-IgwtRegCleanSnapshotField $w 'key') -ne $rel -or $have.ContainsKey($id)) { continue }
                    $vk = [string](Get-IgwtRegCleanSnapshotField $w 'kind')
                    $raw = ConvertTo-IgwtRegCleanRawValue -Kind $vk -Data (Get-IgwtRegCleanSnapshotField $w 'data')
                    $key.SetValue([string](Get-IgwtRegCleanSnapshotField $w 'name'), $raw[0], [Microsoft.Win32.RegistryValueKind]$vk)
                }
            } finally { $key.Dispose() }
        }
    } finally { $base.Dispose() }
}

function Restore-IgwtRegCleanValue {
    <#
    .SYNOPSIS
        Restores a removed registry value from its snapshot, additively (RG20): creates it (and its
        key) only when it is missing; an equal value is left as it is; a different value is refused
        ('Refused: the key exists again with other data; nothing changed'). Provider internal:
        called only by the regClean provider's Restore.
    .PARAMETER Hive
        HKLM or HKCU (from the target).
    .PARAMETER Sid
        The user SID for HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Name
        The value name (from the target).
    .PARAMETER Snapshot
        The recorded value snapshot (Get-IgwtRegCleanValueSnapshot shape or journal data).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [AllowEmptyString()][AllowNull()][string]$Sid = '',
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)]$Snapshot
    )
    Assert-IgwtWritable -Operation 'Restore-IgwtRegCleanValue'
    $now = $null
    try { $now = Get-IgwtRegCleanValueSnapshot -Hive $Hive -Sid $Sid -View $View -Path $Path -Name $Name }
    catch { throw "Refused: the value exists again and cannot be compared ($($_.Exception.Message)); nothing changed." }
    if (-not [bool](Get-IgwtRegCleanSnapshotField $Snapshot 'exists')) {
        if ($now.exists) { throw $script:IgwtRegCleanReappearedMessage }
        return
    }
    $kind = [string](Get-IgwtRegCleanSnapshotField $Snapshot 'kind')
    $data = Get-IgwtRegCleanSnapshotField $Snapshot 'value'
    if ($now.exists) {
        if ([string]$now.kind -eq $kind -and (ConvertTo-IgwtCanonicalJson $now.value) -eq (ConvertTo-IgwtCanonicalJson $data)) { return }
        throw $script:IgwtRegCleanReappearedMessage
    }
    if (-not $PSCmdlet.ShouldProcess("$Hive\$Path\$Name", 'Restore registry value')) { return }
    $loc = Get-IgwtRegCleanKeyLocation -Hive $Hive -View $View -Path $Path -Sid $Sid
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($loc.Hive, $loc.View)
    try {
        $key = $base.CreateSubKey($loc.SubKey)
        if ($null -eq $key) { throw 'The key of the value could not be created.' }
        $raw = ConvertTo-IgwtRegCleanRawValue -Kind $kind -Data $data
        try { $key.SetValue($Name, $raw[0], [Microsoft.Win32.RegistryValueKind]$kind) } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

#endregion

#region Provider Set and Restore

function Invoke-IgwtRegCleanProviderSet {
    <#
    .SYNOPSIS
        The provider's Set (RG16): (a) refuses unless Invoke-IgwtRegistryCleanup of this session
        handed over its context; (b) runs Test-IgwtRegCleanProtected and Get-IgwtRegCleanFinding with
        that context (RG14 point 3); (c) reads the target again and refuses when it changed since the
        step's Get; (d) refuses a key tree with its own permissions or another owner; (e) only then
        removes it (or deletes the firewall rule through Invoke-IgwtFirewallChange). Every refusal
        throws with the prefix 'Refused:' and changes nothing. Returns the applied data {ref
        (firewall rules: the firewall snapshot); security {owner; sddl} (information); backup}.
    .PARAMETER Resolved
        A Resolve-IgwtRegCleanTarget result.
    .PARAMETER Desired
        The step's desired data {action 'remove'; finding; session}.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resolved, $Desired)
    $step = $script:IgwtRegCleanStep
    $session = [string](Get-IgwtRegCleanSnapshotField $Desired 'session')
    if ($null -eq $step -or -not $script:IgwtChangeLock -or -not [object]::ReferenceEquals($step.Lock, $script:IgwtChangeLock) -or -not $session -or $session -ne [string]$step.SessionId) {
        throw 'Refused: a registry cleaner entry is removed only by Invoke-IgwtRegistryCleanup in its own session; nothing changed.'
    }
    $finding = $step.Findings[$Resolved.Key]
    if ($null -eq $finding) { throw 'Refused: this entry is not part of the cleanup plan; nothing changed.' }
    # (b) RG14 point 3: the same function and the same evidence rules as the scan and the preview.
    $prot = Test-IgwtRegCleanProtected -Finding $finding -Context $step.Context.Protection
    if ($prot) { throw "Refused: protected ($([string]$prot.Reason)); nothing changed." }
    $fresh = Get-IgwtRegCleanFinding -Target $finding -Context $step.Context
    if ($null -eq $fresh) { throw 'Refused: no longer a provable leftover (it is gone, in use, protected or excluded); nothing changed.' }
    if ([string]$fresh.Confidence -notin 'Safe', 'Review' -or -not $fresh.Selectable) { throw "Refused: not removable now ($([string]$fresh.Reason)); nothing changed." }
    # (c) Changed between the step's Get and now (keys or values added meanwhile).
    if (-not $step.Before.ContainsKey($Resolved.Key)) { throw 'Refused: the entry was not read before the removal; nothing changed.' }
    $before = $step.Before[$Resolved.Key]
    $now = Get-IgwtRegCleanTargetSnapshot -Resolved $Resolved
    if (-not [bool]$now['exists']) { throw 'Refused: the entry no longer exists; nothing changed.' }
    if (-not (Test-IgwtRegCleanSnapshotEqual -Left $now -Right $before)) { throw 'Refused: changed since the preview; nothing changed.' }
    # (c2) Review RC-3: compared with what the preview itself showed, not only with the step's Get.
    if (-not $finding.PSObject.Properties['PreviewDigest'] -or -not [string]$finding.PreviewDigest) { throw 'Refused: the plan does not record what the preview showed; preview again. Nothing changed.' }
    if ((ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $now)) -ne [string]$finding.PreviewDigest) { throw 'Refused: changed since the preview; nothing changed.' }
    $security = [ordered]@{ owner = ''; sddl = '' }
    switch ($Resolved.Kind) {
        'regKeyTree' {
            # (d) The offer rule again (RG17): inherited permissions only and a known owner.
            $rows = @()
            # The function returns its rows as one array (no @(), which would nest it).
            try { $rows = Get-IgwtRegCleanTreeSecurity -Snapshot $now } catch { throw "Refused: the permissions cannot be read ($($_.Exception.Message)); nothing changed." }
            $why = Get-IgwtRegCleanSecurityRefusal -Rows $rows -Sid $Resolved.Sid
            if ($why) { throw "Refused: $why; nothing changed." }
            if ($rows.Count) { $security = [ordered]@{ owner = [string]$rows[0]['owner']; sddl = [string]$rows[0]['sddl'] } }
            Remove-IgwtRegCleanKeyTree -Hive $Resolved.Hive -Sid $Resolved.Sid -View $Resolved.View -Path $Resolved.Path -Before $now -Confirm:$false
            return [ordered]@{ security = $security; backup = [string]$step.Backup }
        }
        'regValue' {
            Remove-IgwtRegCleanValue -Hive $Resolved.Hive -Sid $Resolved.Sid -View $Resolved.View -Path $Resolved.Path -Name $Resolved.ValueName -Before $now -Confirm:$false
            return [ordered]@{ security = $security; backup = [string]$step.Backup }
        }
        'firewallRule' {
            $res = Invoke-IgwtFirewallChange -Operation Delete -Name @($Resolved.RuleName) -Confirm:$false
            $snapPath = $(if ($res -and $res.PSObject.Properties['Snapshot']) { [string]$res.Snapshot } else { '' })
            $changes = $(if ($res -and $res.PSObject.Properties['Changes']) { [int]$res.Changes } else { 0 })
            if ($changes -ne 1 -or -not $snapPath) {
                $msg = @(@($(if ($res -and $res.PSObject.Properties['Results']) { $res.Results })) | Where-Object { $_ -and $_.Message } | ForEach-Object { [string]$_.Message }) -join '; '
                if (-not $msg) { $msg = 'the firewall did not report the deletion' }
                throw "Refused: the firewall rule was not deleted ($msg)."
            }
            if ($step.FirewallSnapshots) { $step.FirewallSnapshots[$Resolved.RuleName] = $snapPath }
            return [ordered]@{ ref = $snapPath; security = $security; backup = [string]$step.Backup }
        }
    }
    throw "Refused: unknown kind '$($Resolved.Kind)'; nothing changed."
}

function Invoke-IgwtRegCleanProviderRestore {
    <#
    .SYNOPSIS
        The provider's Restore (RG16, RG20): key trees and values through the additive restore
        internals; a firewall rule through Invoke-IgwtRevert -SnapshotPath with the recorded
        firewall snapshot, after checking that it lies under the tool's data folder. Restores are
        never blocked by an exclusion or by the protection check (RG14).
    .PARAMETER Resolved
        A Resolve-IgwtRegCleanTarget result.
    .PARAMETER Data
        The recorded "before" (with 'applied' from the step, when the engine adds it).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resolved, [Parameter(Mandatory = $true)]$Data)
    switch ($Resolved.Kind) {
        'regKeyTree' { Restore-IgwtRegCleanKeyTree -Hive $Resolved.Hive -Sid $Resolved.Sid -View $Resolved.View -Path $Resolved.Path -Snapshot $Data -Confirm:$false; return }
        'regValue' { Restore-IgwtRegCleanValue -Hive $Resolved.Hive -Sid $Resolved.Sid -View $Resolved.View -Path $Resolved.Path -Name $Resolved.ValueName -Snapshot $Data -Confirm:$false; return }
        'firewallRule' {
            $now = Get-IgwtRegCleanFirewallSnapshot -RuleName $Resolved.RuleName
            if (-not [bool](Get-IgwtRegCleanSnapshotField $Data 'exists')) {
                if ($now['exists']) { throw $script:IgwtRegCleanReappearedMessage }
                return
            }
            if ($now['exists']) {
                if (Test-IgwtRegCleanSnapshotEqual -Left $now -Right $Data) { return }
                throw 'Refused: a firewall rule with this name exists again with other settings; nothing changed.'
            }
            $ap = Get-IgwtRegCleanSnapshotField $Data 'applied'
            $ref = [string](Get-IgwtRegCleanSnapshotField $ap 'ref')
            if (-not $ref) { throw 'No firewall snapshot was recorded for this rule, so it cannot be restored from the journal.' }
            $root = [string]$script:IgwtSettings.DataRoot
            if (-not $root -or -not (Test-IgwtPathUnder -Path $ref -Parent $root)) { throw "The recorded firewall snapshot '$ref' is outside the tool's data folder: it is not used." }
            $script:IgwtModuleDepth++
            try { $res = Invoke-IgwtRevert -SnapshotPath $ref -Confirm:$false } finally { $script:IgwtModuleDepth-- }
            if (Test-IgwtModuleOperationFailed -Result $res) { throw "The restore from '$ref' reported a failure." }
            return
        }
    }
    throw "Unknown registry cleaner kind '$($Resolved.Kind)'."
}

#endregion

$script:IgwtChangeProviders['regClean'] = @{
    Reversible = { param($r) $null = $r; 'exact' }
    # Structural only (RG16): the target's own fields, the category roots, the deny list.
    Resolve    = { param($t, $catalog) $null = $catalog; Resolve-IgwtRegCleanTarget -Target $t }
    # The exact snapshot; during a cleanup the first read of each target is kept for Set's re-check.
    Get        = {
        param($r, $ctx)
        $null = $ctx
        $snap = Get-IgwtRegCleanTargetSnapshot -Resolved $r
        $step = $script:IgwtRegCleanStep
        if ($step -and -not $step.Before.ContainsKey($r.Key)) { $step.Before[$r.Key] = $snap }
        $snap
    }
    Set        = { param($r, $desired, $ctx) $null = $ctx; Invoke-IgwtRegCleanProviderSet -Resolved $r -Desired $desired }
    Restore    = { param($r, $data, $ctx) $null = $ctx; Invoke-IgwtRegCleanProviderRestore -Resolved $r -Data $data }
    TestSet    = {
        param($r, $desired, $ctx)
        $null = $desired; $null = $ctx
        $after = Get-IgwtRegCleanTargetSnapshot -Resolved $r
        $gone = -not [bool]$after['exists']
        [pscustomobject]@{ Ok = $gone; State = $(if ($gone) { 'removed' } else { 'present' }); Note = $(if ($gone) { '' } else { 'Read back after the removal and the entry is still there.' }) }
    }
}
