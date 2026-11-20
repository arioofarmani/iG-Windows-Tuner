# SecSettingsProtect.ps1
# Security Settings Manager (3.8): the protected set (DECISIONS SM13, SM14, SM15, SM18). Pure checks:
# which registry operations would lower protection (comparing before and after, not only the new
# value), UEFI-lock choices, add-only audit, and the lockout checks. A check that cannot answer
# refuses (NotChecked), it never allows.

function Get-IgwtSecSettingOpRefusal {
    <#
    .SYNOPSIS
        Why one registry operation is never written (DECISIONS SM13, SM14, SM18), or '': a Set refused
        by the policy denylist, by data\security\weakening.json or by a UEFI-lock tuple of
        settings-meta.json (matched on class, key, value name and value, never on the value alone);
        a Delete or Remove refused by a weakening entry that lists 'delete'. Pure.
    .PARAMETER Class
        Machine or User.
    .PARAMETER Op
        @{ Op = Set | Delete | Remove | DeleteValues | RemoveKeyValues; Key; ValueName; Value }.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class, [Parameter(Mandatory = $true)]$Op)
    if ([string]$Op.Op -eq 'Set') {
        $deny = Test-IgwtPolicyOpAllowed -Op $Op -Class $Class
        if ($deny) { return [string]$deny }
        return ''
    }
    return (Get-IgwtPolicyLockOrWeakeningReason -Op $Op -Class $Class)
}

function Get-IgwtPolicyLockOrWeakeningReason {
    <#
    .SYNOPSIS
        Why a registry operation is refused by a UEFI-lock tuple (settings-meta.json uefiLockValues)
        or a weakening entry (weakening.json), or ''. Matched on class (when given), key, value
        name and value, never on the value alone. A Set is checked against both; a Delete or
        Remove only against weakening entries that list 'delete'. Used by every policy write path
        through Test-IgwtPolicyOpAllowed (review 3.8.1 P-26, P-28). Pure.
    .PARAMETER Op
        @{ Op; Key; ValueName; Value }.
    .PARAMETER Class
        Machine or User, or empty to match entries of either class (the cautious choice).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Op, [AllowEmptyString()][string]$Class = '')
    $data = Get-IgwtSecSettingsData
    $value = [string](@($Op.Value) -join ',')
    $classOk = { param($c) (-not $Class) -or [string]$c -eq 'Both' -or [string]$c -eq $Class }
    if ([string]$Op.Op -eq 'Set') {
        foreach ($t in @($data.Meta.uefiLockValues)) {
            if ((& $classOk $t.class) -and [string]::Equals([string]$t.key, [string]$Op.Key, [System.StringComparison]::OrdinalIgnoreCase) -and [string]::Equals([string]$t.valueName, [string]$Op.ValueName, [System.StringComparison]::OrdinalIgnoreCase) -and [string]$t.value -eq $value) {
                return "$($t.label): a UEFI lock cannot be removed by software, so iG never sets it."
            }
        }
    }
    foreach ($w in @($data.Weakening.entries)) {
        if (-not (& $classOk $w.class)) { continue }
        if ([string]$Op.Key -notmatch "^(?i)(?:$($w.key))$" -or [string]$Op.ValueName -notmatch "^(?i)(?:$($w.valueName))$") { continue }
        $vals = @($w.values | ForEach-Object { [string]$_ })
        if ([string]$Op.Op -eq 'Set' -and ($vals -contains 'any' -or $vals -contains $value -or @($vals | Where-Object { $_ -match '[\\*]' -and $value -match "^(?:$_)$" }).Count)) { return [string]$w.reason }
        if ([string]$Op.Op -in 'Delete', 'Remove', 'DeleteValues', 'RemoveKeyValues' -and $vals -contains 'delete') { return [string]$w.reason }
    }
    return ''
}

function Get-IgwtSecSettingEffectiveValue {
    <#
    .SYNOPSIS
        The effective Registry.pol state of one key and value name: @{ Kind = Value | Deleted | Absent;
        Value }. A **del. marker or a **delvals. marker without the value means Deleted. Pure.
    .PARAMETER Entries
        Registry.pol entries.
    .PARAMETER Key
        The key.
    .PARAMETER ValueName
        The value name.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Entries = @(), [string]$Key, [string]$ValueName)
    $eq = { param($a, $b) [string]::Equals([string]$a, [string]$b, [System.StringComparison]::OrdinalIgnoreCase) }
    $hit = @($Entries | Where-Object { $_ -and (& $eq $_.Key $Key) -and (& $eq $_.ValueName $ValueName) }) | Select-Object -Last 1
    if ($hit) { return @{ Kind = 'Value'; Value = ([string](@($hit.Value) -join ',')) } }
    if (@($Entries | Where-Object { $_ -and (& $eq $_.Key $Key) -and ((& $eq $_.ValueName "**del.$ValueName") -or (& $eq $_.ValueName '**delvals.')) }).Count) { return @{ Kind = 'Deleted'; Value = $null } }
    return @{ Kind = 'Absent'; Value = $null }
}

function Test-IgwtSecSettingOpsLowerProtection {
    <#
    .SYNOPSIS
        Compares before and after for every key and value name the operations touch (DECISIONS SM13)
        and returns the reasons the change is refused (empty when allowed): (a) a changed after value
        refused by Get-IgwtSecSettingOpRefusal; (b) a protective value before (one a denylist or
        weakening entry covers and does not refuse) that is absent, deleted or refused after. So a
        Disabled or Not configured choice cannot turn a protection off by removing its value. Pure.
    .PARAMETER Class
        Machine or User.
    .PARAMETER Ops
        Operations from Get-IgwtPolicyRegistryOps.
    .PARAMETER CurrentEntries
        The current Registry.pol entries of the class.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class, [AllowEmptyCollection()][object[]]$Ops = @(), [AllowEmptyCollection()][object[]]$CurrentEntries = @())
    $data = Get-IgwtSecSettingsData
    $after = @(Update-IgwtPolEntries -Entries @($CurrentEntries) -Ops @($Ops))
    $pairs = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $addPair = { param($k, $n) $id = ("$k|$n").ToLowerInvariant(); if ($n -and -not $seen.ContainsKey($id)) { $seen[$id] = $true; $pairs.Add([pscustomobject]@{ Key = [string]$k; ValueName = [string]$n }) } }
    foreach ($o in @($Ops)) {
        if ([string]$o.Op -in 'DeleteValues', 'RemoveKeyValues') {
            foreach ($e in @($CurrentEntries | Where-Object { $_ -and [string]::Equals([string]$_.Key, [string]$o.Key, [System.StringComparison]::OrdinalIgnoreCase) -and [string]$_.ValueName -notmatch '^\*\*' })) { & $addPair $e.Key $e.ValueName }
        } else { & $addPair $o.Key $o.ValueName }
    }
    $guards = @(@((Get-IgwtPolicyDenylist) | ForEach-Object { [pscustomobject]@{ key = $_.key; valueName = $_.valueName; values = @($_.values); class = 'Both' } }) + @($data.Weakening.entries))
    foreach ($p in $pairs) {
        $b = Get-IgwtSecSettingEffectiveValue -Entries $CurrentEntries -Key $p.Key -ValueName $p.ValueName
        $a = Get-IgwtSecSettingEffectiveValue -Entries $after -Key $p.Key -ValueName $p.ValueName
        $changed = ($a.Kind -ne $b.Kind) -or ([string]$a.Value -ne [string]$b.Value)
        if (-not $changed) { continue }
        if ($a.Kind -eq 'Value') {
            $why = Get-IgwtSecSettingOpRefusal -Class $Class -Op ([pscustomobject]@{ Op = 'Set'; Key = $p.Key; ValueName = $p.ValueName; Value = $a.Value })
            if ($why) { "$($p.ValueName): $why"; continue }
        }
        if ($b.Kind -ne 'Value') { continue }
        foreach ($g in $guards) {
            if ([string]$g.class -ne 'Both' -and [string]$g.class -ne $Class) { continue }
            if ($p.Key -notmatch "^(?i)(?:$($g.key))$" -or $p.ValueName -notmatch "^(?i)(?:$($g.valueName))$") { continue }
            $vals = @($g.values | ForEach-Object { [string]$_ })
            if ($vals -contains 'any' -or $vals -contains [string]$b.Value) { continue }
            if ($a.Kind -ne 'Value') { "$($p.ValueName): removing it would turn a protection off ($($g.reason))"; break }
        }
    }
}

function Test-IgwtSecSettingAuditAddOnly {
    <#
    .SYNOPSIS
        Why an audit change is refused (DECISIONS SM13 item 6: audit is add-only), or '': the new
        setting must keep every kind (Success, Failure) the current one audits. Pure.
    .PARAMETER Before
        None, Success, Failure or SuccessAndFailure.
    .PARAMETER After
        None, Success, Failure or SuccessAndFailure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Before, [Parameter(Mandatory = $true)][string]$After)
    $has = { param($v, $k) [string]$v -eq 'SuccessAndFailure' -or [string]$v -eq $k }
    foreach ($k in 'Success', 'Failure') {
        if ((& $has $Before $k) -and -not (& $has $After $k)) { return "This would stop auditing $($k.ToLowerInvariant()) events; iG only adds auditing." }
    }
    return ''
}

function Get-IgwtSecSettingLockoutChecks {
    <#
    .SYNOPSIS
        The lockout checks of one change (DECISIONS SM15): rows @{ Check; Result = Pass | Fail |
        NotChecked; Text }. The plan refuses the change when any row is Fail or NotChecked. Pure:
        the identity and the BitLocker recovery result are passed in.
    .PARAMETER ValueName
        The registry value name or security option the change writes.
    .PARAMETER Value
        The new value.
    .PARAMETER Identity
        Get-IgwtCurrentIdentity (Name, Sid, GroupSids, IsRemote); $null means unknown.
    .PARAMETER RecoveryCheck
        The BitLocker recovery check result (Pass, Fail or NotChecked), SM17.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ValueName, $Value, $Identity, [ValidateSet('Pass', 'Fail', 'NotChecked')][string]$RecoveryCheck = 'NotChecked')
    $row = { param($c, $r, $t) [pscustomobject]@{ Check = $c; Result = $r; Text = $t } }
    $v = [string](@($Value) -join ',')
    switch -Regex ($ValueName) {
        '^ScForceOption$' { if ($v -eq '1') { & $row 'Smart card required' 'NotChecked' 'Windows offers no documented way for iG to see whether you have a smart card or a Windows Hello credential, so iG does not require one: you could be locked out.' } }
        '^NoConnectedUser$' {
            if ($v -eq '3') {
                $type = $(if ($Identity -and $Identity.PSObject.Properties['AccountType']) { [string]$Identity.AccountType } else { '' })
                if ($type -eq 'Local') { & $row 'Microsoft accounts blocked' 'Pass' 'You are signed in with a local account.' }
                elseif ($type -eq 'Microsoft') { & $row 'Microsoft accounts blocked' 'Fail' 'You are signed in with a Microsoft account; blocking Microsoft accounts would lock you out.' }
                else { & $row 'Microsoft accounts blocked' 'NotChecked' 'iG cannot prove that you are not signed in with a Microsoft account, so it does not block them.' }
            }
        }
        '^ConsentPromptBehaviorUser$' {
            if ($v -eq '0') {
                if ($null -eq $Identity) { & $row 'Standard users cannot elevate' 'NotChecked' 'The signed-in user could not be read.' }
                elseif (@($Identity.GroupSids) -contains 'S-1-5-32-544') { & $row 'Standard users cannot elevate' 'Pass' 'The signed-in user is an administrator.' }
                else { & $row 'Standard users cannot elevate' 'Fail' 'The signed-in user is not an administrator and could no longer elevate.' }
            }
        }
        '^CrashOnAuditFail$' { if ($v -eq '1') { & $row 'Shut down when the audit log is full' 'Fail' 'Windows would stop and only administrators could sign in until the log is cleared; iG never sets this.' } }
        '^MaxDevicePasswordFailedAttempts$' {
            if ($v -and $v -ne '0') {
                if ($RecoveryCheck -eq 'Pass') { & $row 'BitLocker recovery key' 'Pass' 'The system drive has a recovery password protector.' }
                else { & $row 'BitLocker recovery key' $(if ($RecoveryCheck -eq 'Fail') { 'Fail' } else { 'NotChecked' }) 'After too many wrong passwords the PC restarts into BitLocker recovery; make sure a recovery password exists first.' }
            }
        }
        '^(fDenyTSConnections|UserAuthentication|SecurityLayer|DoNotAllowExceptions|EnableFirewall)$' {
            if ($null -eq $Identity) { & $row 'Remote Desktop session' 'NotChecked' 'The session type could not be read.' }
            elseif ([bool]$Identity.IsRemote) { & $row 'Remote Desktop session' 'Fail' 'You are connected over Remote Desktop; this change could disconnect this session.' }
            else { & $row 'Remote Desktop session' 'Pass' 'You are signed in locally.' }
        }
    }
}
