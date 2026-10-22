# SecurityPolicy.ps1
# Security templates (secedit INF): account policies, user rights assignment and security options.
# Reads with `secedit /export` to a temporary file, writes with `secedit /configure` from a template
# that holds only the changed settings, after an export snapshot. Lockout safeguards refuse any
# change that would lock out the current user or the administrators, and changes that weaken
# security (the policy denylist, reversible passwords, the Guest account, sensitive privileges for
# broad groups). secedit throws in TestMode unless Invoke-IgwtSecedit is mocked.

$script:IgwtSecuritySettings = $null
$script:IgwtAdministratorsSid = 'S-1-5-32-544'

#region INF format

function New-IgwtInfSectionTable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory table only.')]
    [CmdletBinding()]
    param()
    return (New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase))
}

function ConvertFrom-IgwtSecurityInf {
    <#
    .SYNOPSIS
        Parses security template text (secedit INF) into an ordered, case-insensitive table of
        sections, each an ordered table of key to raw value. Comments and blank lines are dropped.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $sections = New-IgwtInfSectionTable
    $cur = $null
    foreach ($raw in @(([string]$Text) -split "`r?`n")) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[(.+)\]$') {
            $name = $Matches[1].Trim()
            if (-not $sections.Contains($name)) { $sections[$name] = New-IgwtInfSectionTable }
            $cur = $sections[$name]
            continue
        }
        if ($null -eq $cur) { throw "Security template line outside a section: '$line'." }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { throw "Security template line without '=': '$line'." }
        $cur[$line.Substring(0, $eq).Trim()] = $line.Substring($eq + 1).Trim()
    }
    return $sections
}

function ConvertTo-IgwtSecurityInfText {
    <#
    .SYNOPSIS
        Serializes sections to security template text: [Unicode] first, [Version] last, the other
        sections in order. secedit expects "key = value" (registry values keep "key=value").
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Sections)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("[Unicode]`r`nUnicode=yes`r`n")
    foreach ($name in @($Sections.Keys)) {
        if ($name -in 'Unicode', 'Version') { continue }
        $null = $sb.Append("[$name]`r`n")
        $sep = $(if ($name -eq 'Registry Values') { '=' } else { ' = ' })
        foreach ($k in @($Sections[$name].Keys)) { $null = $sb.Append("$k$sep$($Sections[$name][$k])`r`n") }
    }
    $null = $sb.Append("[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n")
    return $sb.ToString()
}

function Read-IgwtSecurityInfFile {
    <# .SYNOPSIS Reads a security template file (secedit writes UTF-16LE with a BOM; other encodings are detected). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    return (ConvertFrom-IgwtSecurityInf -Text ([System.IO.File]::ReadAllText($Path)))
}

function Write-IgwtSecurityInfFile {
    <# .SYNOPSIS Writes a security template as UTF-16LE with a BOM, the encoding secedit uses. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Sections)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write security template')) { return }
    [System.IO.File]::WriteAllText($Path, (ConvertTo-IgwtSecurityInfText -Sections $Sections), [System.Text.Encoding]::Unicode)
}

function Copy-IgwtInfSections {
    <# .SYNOPSIS Deep copy of a sections table. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Sections)
    $copy = New-IgwtInfSectionTable
    foreach ($s in @($Sections.Keys)) { $copy[$s] = New-IgwtInfSectionTable; foreach ($k in @($Sections[$s].Keys)) { $copy[$s][$k] = $Sections[$s][$k] } }
    return $copy
}

#endregion

#region Reading

function Invoke-IgwtSecedit {
    <# .SYNOPSIS Runs secedit.exe with the given arguments; returns the exit code and output. Refuses to run in TestMode (tests mock it). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: secedit must be mocked in tests.' }
    if ($Arguments[0] -notin '/export', '/configure') { throw "secedit $($Arguments[0]) is not used by iG Windows Tuner." }
    if ($Arguments[0] -eq '/configure' -and -not $PSCmdlet.ShouldProcess('Local security policy', 'secedit /configure')) { return [pscustomobject]@{ ExitCode = 0; Output = 'WhatIf' } }
    $exe = Join-Path $env:SystemRoot 'System32\secedit.exe'
    $out = & $exe @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
}

function Export-IgwtSecurityPolicy {
    <#
    .SYNOPSIS
        Exports the local security policy (account policies, security options, user rights) with
        `secedit /export` and returns the parsed sections. Read-only; needs administrator rights.
    .PARAMETER Path
        Keeps the exported template at this path (a temporary file is used and deleted otherwise).
    #>
    [CmdletBinding()]
    param([string]$Path)
    $keep = [bool]$Path
    if (-not $Path) { $Path = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-secpol-{0}.inf" -f [guid]::NewGuid().ToString('N')) }
    try {
        $r = Invoke-IgwtSecedit -Arguments @('/export', '/cfg', $Path, '/areas', 'SECURITYPOLICY', 'USER_RIGHTS', '/quiet')
        if ($r.ExitCode -eq 740) { throw 'Reading the local security policy needs administrator rights (secedit /export).' }
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $Path)) { throw "secedit /export failed (exit $($r.ExitCode)): $($r.Output)" }
        return (Read-IgwtSecurityInfFile -Path $Path)
    } finally { if (-not $keep) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue } }
}

function Get-IgwtSecuritySettingCatalog {
    [CmdletBinding()]
    param()
    if (-not $script:IgwtSecuritySettings) { $script:IgwtSecuritySettings = Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'policy\security-settings.json') }
    return $script:IgwtSecuritySettings
}

function ConvertTo-IgwtSidList {
    <# .SYNOPSIS A user-rights value ("*S-1-5-32-544,Name") as SIDs (names are translated; untranslatable names are kept). #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    @(([string]$Value).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
            if ($_ -match '^\*?(S-1-[\d-]+)$') { $Matches[1] }
            else { try { (New-Object System.Security.Principal.NTAccount($_)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $_ } }
        })
}

function Resolve-IgwtSidName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Sid)
    $broad = @((Get-IgwtSecuritySettingCatalog).broadPrincipals | Where-Object { $_.sid -eq $Sid }) | Select-Object -First 1
    if ($broad) { return [string]$broad.name }
    if ($Sid -eq $script:IgwtAdministratorsSid) { return 'Administrators' }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { return $Sid }
}

function Get-IgwtSecurityPolicy {
    <#
    .SYNOPSIS
        The local security policy as rows (Section, Key, Name, Group, Value, Accounts for user
        rights, Hint), from `secedit /export`. Read-only; needs administrator rights.
    .PARAMETER Sections
        Use already exported sections instead of running secedit.
    #>
    [CmdletBinding()]
    param([System.Collections.IDictionary]$Sections)
    if (-not $Sections) { $Sections = Export-IgwtSecurityPolicy }
    $cat = Get-IgwtSecuritySettingCatalog
    foreach ($sec in @('System Access', 'Privilege Rights', 'Registry Values', 'Event Audit')) {
        if (-not $Sections.Contains($sec)) { continue }
        foreach ($k in @($Sections[$sec].Keys)) {
            $v = [string]$Sections[$sec][$k]
            $meta = $null
            if ($sec -eq 'System Access') { $meta = @($cat.systemAccess | Where-Object { $_.key -eq $k }) | Select-Object -First 1 }
            if ($sec -eq 'Privilege Rights') { $meta = @($cat.privilegeRights | Where-Object { $_.key -eq $k }) | Select-Object -First 1 }
            [pscustomobject]@{
                Section  = $sec; Key = $k; Value = $v
                Name     = $(if ($meta) { [string]$meta.name } else { $k })
                Group    = $(if ($meta -and $meta.group) { [string]$meta.group } elseif ($sec -eq 'Privilege Rights') { 'User rights assignment' } elseif ($sec -eq 'Registry Values') { 'Security options (registry)' } elseif ($sec -eq 'Event Audit') { 'Legacy audit policy' } else { 'Other' })
                Accounts = $(if ($sec -eq 'Privilege Rights') { @(ConvertTo-IgwtSidList -Value $v | ForEach-Object { Resolve-IgwtSidName -Sid $_ }) } else { @() })
                Hint     = $(if ($meta) { [string]$meta.hint } else { '' })
            }
        }
    }
}

#endregion

#region Lockout safeguards

function Get-IgwtCurrentIdentity {
    <# .SYNOPSIS The current user's SID, group SIDs, name and whether the session is Remote Desktop. Read-only. #>
    [CmdletBinding()]
    param()
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [pscustomobject]@{
        Name      = $id.Name
        Sid       = $id.User.Value
        GroupSids = @($id.Groups | ForEach-Object { $_.Value })
        IsRemote  = [bool](Test-IgwtRdpSession)
    }
}

function Test-IgwtSecurityPolicySafeguards {
    <#
    .SYNOPSIS
        Lockout safeguards for a proposed security policy. Returns refusal texts (empty when the
        change is safe):
        1. Administrators and the current user keep the logon rights they need (local logon; when
           the session is Remote Desktop also network and Remote Desktop logon) and are never in a
           matching deny right.
        2. Password and lockout settings never lock out the current account immediately (password
           older than the new maximum age, invalid lockout combinations, lockout without automatic
           unlock when only one administrator is enabled, a threshold of 1 or 2).
        3. The last enabled administrator is never disabled.
        4. No weakening: reversible passwords, the Guest account, anonymous name lookup, sensitive
           privileges for broad groups, and policy denylist values in Registry Values.
    .PARAMETER Changed
        "Section\Key" names of the changed settings; rules about grants check only those.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Proposed, [Parameter(Mandatory = $true)][string[]]$Changed,
        [Parameter(Mandatory = $true)]$Identity, [Parameter(Mandatory = $true)]$Accounts)
    $refusals = New-Object System.Collections.Generic.List[string]
    $cat = Get-IgwtSecuritySettingCatalog
    $changedSet = @($Changed | ForEach-Object { $_.ToLowerInvariant() })
    $isChanged = { param($s, $k) $changedSet -contains ("$s\$k").ToLowerInvariant() }
    $get = { param($s, $k) if ($Proposed.Contains($s) -and $Proposed[$s].Contains($k)) { [string]$Proposed[$s][$k] } else { $null } }
    $me = @(@($Identity.Sid) + @($Identity.GroupSids) | Where-Object { $_ })

    # 1. Logon rights.
    $needs = @(@{ Right = 'SeInteractiveLogonRight'; Who = @($script:IgwtAdministratorsSid, 'me'); Why = 'sign in at this PC' })
    if ($Identity.IsRemote) {
        $needs += @{ Right = 'SeRemoteInteractiveLogonRight'; Who = @('me'); Why = 'stay connected over Remote Desktop' }
        $needs += @{ Right = 'SeNetworkLogonRight'; Who = @('me'); Why = 'connect over Remote Desktop with Network Level Authentication' }
    }
    foreach ($n in $needs) {
        if (-not (& $isChanged 'Privilege Rights' $n.Right)) { continue }
        $granted = @(ConvertTo-IgwtSidList -Value (& $get 'Privilege Rights' $n.Right))
        foreach ($w in $n.Who) {
            if ($w -eq 'me') { if (-not @($me | Where-Object { $granted -contains $_ }).Count) { $refusals.Add("$($n.Right): you ($($Identity.Name)) would lose the right to $($n.Why).") } }
            elseif ($granted -notcontains $w) { $refusals.Add("$($n.Right): Administrators would lose the right to $($n.Why).") }
        }
    }
    $denies = @(@{ Right = 'SeDenyInteractiveLogonRight'; Admins = $true })
    if ($Identity.IsRemote) { $denies += @{ Right = 'SeDenyRemoteInteractiveLogonRight'; Admins = $false }; $denies += @{ Right = 'SeDenyNetworkLogonRight'; Admins = $false } }
    foreach ($d in $denies) {
        if (-not (& $isChanged 'Privilege Rights' $d.Right)) { continue }
        $denied = @(ConvertTo-IgwtSidList -Value (& $get 'Privilege Rights' $d.Right))
        $hit = @($me | Where-Object { $denied -contains $_ })
        if ($hit.Count) { $refusals.Add("$($d.Right): it would deny you ($($Identity.Name)) through $(@($hit | ForEach-Object { Resolve-IgwtSidName -Sid $_ }) -join ', ').") }
        elseif ($d.Admins -and $denied -contains $script:IgwtAdministratorsSid) { $refusals.Add("$($d.Right): it would deny Administrators.") }
    }

    # 2. Password and lockout.
    $num = { param($k) $v = & $get 'System Access' $k; if ($null -eq $v -or $v -notmatch '^-?\d+$') { $null } else { [int64]$v } }
    $maxAge = & $num 'MaximumPasswordAge'; $minAge = & $num 'MinimumPasswordAge'
    $threshold = & $num 'LockoutBadCount'; $duration = & $num 'LockoutDuration'; $reset = & $num 'ResetLockoutCount'
    $enabledAdmins = @(@($Accounts.Accounts) | Where-Object { $_.Enabled -and $_.IsAdmin -eq $true })
    $mine = @(@($Accounts.Accounts) | Where-Object { $_.Sid -and $_.Sid -eq $Identity.Sid }) | Select-Object -First 1
    if ((& $isChanged 'System Access' 'MaximumPasswordAge') -and $maxAge -gt 0) {
        if ($mine -and $mine.PasswordLastSet) {
            $age = ((Get-Date) - [datetime]$mine.PasswordLastSet).TotalDays
            if ($age -ge $maxAge) { $refusals.Add(("MaximumPasswordAge {0}: your password is {1:N0} days old and would expire immediately. Change your password first." -f $maxAge, $age)) }
        }
        if ($null -ne $minAge -and $minAge -ge $maxAge) { $refusals.Add("MinimumPasswordAge ($minAge) must be lower than MaximumPasswordAge ($maxAge).") }
    }
    $lockoutChanged = (& $isChanged 'System Access' 'LockoutBadCount') -or (& $isChanged 'System Access' 'LockoutDuration') -or (& $isChanged 'System Access' 'ResetLockoutCount')
    if ($lockoutChanged -and $threshold -gt 0) {
        if ($threshold -lt 3) { $refusals.Add("LockoutBadCount $($threshold): one or two mistyped or stale passwords (a mapped drive, a phone) would lock the account at once. Use 3 or more (Microsoft's baselines use 10).") }
        if ($null -ne $duration -and $null -ne $reset -and $duration -gt 0 -and $duration -lt $reset) { $refusals.Add("LockoutDuration ($duration) must be at least ResetLockoutCount ($reset) when a lockout threshold is set.") }
        if ($duration -eq 0 -and $enabledAdmins.Count -le 1) { $refusals.Add('LockoutDuration 0 keeps accounts locked until an administrator unlocks them, and this PC has only one enabled administrator who could do that.') }
    }

    # 3. Last enabled administrator.
    if ((& $isChanged 'System Access' 'EnableAdminAccount') -and (& $get 'System Access' 'EnableAdminAccount') -eq '0') {
        $builtin = @(@($Accounts.Accounts) | Where-Object { $_.Role -eq 'BuiltinAdministrator' }) | Select-Object -First 1
        if (-not $Accounts.AdminsKnown) { $refusals.Add('EnableAdminAccount 0: the Administrators group could not be read, so it is unknown whether another administrator stays enabled.') }
        elseif ($builtin -and $builtin.Enabled -and @($enabledAdmins | Where-Object { $_.Role -ne 'BuiltinAdministrator' }).Count -eq 0) { $refusals.Add('EnableAdminAccount 0: the built-in Administrator is the last enabled administrator.') }
        elseif ($builtin -and $builtin.Sid -and $builtin.Sid -eq $Identity.Sid) { $refusals.Add('EnableAdminAccount 0: you are signed in with the built-in Administrator account.') }
    }

    # 4. Weakening.
    foreach ($w in @($cat.weakening)) {
        if ((& $isChanged 'System Access' $w.key) -and @($w.values) -contains (& $get 'System Access' $w.key)) { $refusals.Add("$($w.key) $(& $get 'System Access' $w.key): $($w.reason)") }
    }
    $broad = @($cat.broadPrincipals | ForEach-Object { [string]$_.sid })
    foreach ($p in @($cat.privilegeRights | Where-Object { $_.sensitive })) {
        if (-not (& $isChanged 'Privilege Rights' $p.key)) { continue }
        $hit = @(ConvertTo-IgwtSidList -Value (& $get 'Privilege Rights' $p.key) | Where-Object { $broad -contains $_ })
        if ($hit.Count) { $refusals.Add("$($p.key) ($($p.name)) would be granted to $(@($hit | ForEach-Object { Resolve-IgwtSidName -Sid $_ }) -join ', ').") }
    }
    if ($Proposed.Contains('Registry Values')) {
        foreach ($k in @($Proposed['Registry Values'].Keys)) {
            if (-not (& $isChanged 'Registry Values' $k)) { continue }
            if ($k -notmatch '^(?i)(MACHINE|USER)\\(.+)\\([^\\]+)$') { continue }
            $val = ([string]$Proposed['Registry Values'][$k]) -replace '^\d+,', ''
            $why = Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = $Matches[2]; ValueName = $Matches[3]; Type = 'DWord'; Value = $val })
            if ($why) { $refusals.Add("$k = $($val): $why") }
        }
    }
    return $refusals.ToArray()
}

#endregion

#region Write path

function ConvertFrom-IgwtSecurityChangeText {
    <#
    .SYNOPSIS
        Parses "Section\Key=Value;Section\Key=Value" (sections: SystemAccess or "System Access",
        PrivilegeRights, RegistryValues) into change objects. User-rights values may use account
        names, which are translated to *SID form.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)
    $alias = @{ 'systemaccess' = 'System Access'; 'system access' = 'System Access'; 'privilegerights' = 'Privilege Rights'; 'privilege rights' = 'Privilege Rights'; 'registryvalues' = 'Registry Values'; 'registry values' = 'Registry Values' }
    foreach ($part in @($Text -split ';' | Where-Object { $_.Trim() })) {
        $eq = $part.IndexOf('=')
        if ($eq -lt 1) { throw "Invalid change '$part' (use Section\Key=Value)." }
        $name = $part.Substring(0, $eq).Trim(); $value = $part.Substring($eq + 1).Trim()
        $slash = $name.IndexOf('\')
        if ($slash -lt 1) { throw "Invalid change '$part': the key needs a section (SystemAccess\, PrivilegeRights\ or RegistryValues\)." }
        $sec = $alias[$name.Substring(0, $slash).ToLowerInvariant()]
        if (-not $sec) { throw "Unknown section '$($name.Substring(0, $slash))' (use SystemAccess, PrivilegeRights or RegistryValues)." }
        $key = $name.Substring($slash + 1)
        if ($sec -eq 'Privilege Rights') { $value = (@(ConvertTo-IgwtSidList -Value ($value -replace '\|', ',') | ForEach-Object { if ($_ -match '^S-1-') { "*$_" } else { $_ } }) -join ',') }
        [pscustomobject]@{ Section = $sec; Key = $key; Value = $value }
    }
}

function Get-IgwtSecurityChangePlan {
    <#
    .SYNOPSIS
        Dry run of Set-IgwtSecurityPolicy: current and new values, the template that would be
        applied, and the lockout-safeguard refusals. Read-only (exports the policy).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Changes, [System.Collections.IDictionary]$Current)
    if (-not $Current) { $Current = Export-IgwtSecurityPolicy }
    $proposed = Copy-IgwtInfSections -Sections $Current
    $template = New-IgwtInfSectionTable
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Changes) {
        if ($c.Section -notin 'System Access', 'Privilege Rights', 'Registry Values') { throw "Section '$($c.Section)' cannot be changed." }
        if ($c.Section -eq 'System Access' -and [string]$c.Value -notmatch '^-?\d+$|^".*"$') { throw "$($c.Key): System Access values are numbers (names are quoted)." }
        if ($c.Section -eq 'Registry Values' -and [string]$c.Value -notmatch '^\d+,') { throw "$($c.Key): Registry Values need type,value (for example 4,1)." }
        foreach ($t in @($proposed, $template)) { if (-not $t.Contains($c.Section)) { $t[$c.Section] = New-IgwtInfSectionTable } }
        $old = $(if ($Current.Contains($c.Section) -and $Current[$c.Section].Contains($c.Key)) { [string]$Current[$c.Section][$c.Key] } else { $null })
        $proposed[$c.Section][$c.Key] = [string]$c.Value
        $template[$c.Section][$c.Key] = [string]$c.Value
        $rows.Add([pscustomobject]@{ Section = $c.Section; Key = $c.Key; Current = $old; New = [string]$c.Value; Changes = ($old -ne [string]$c.Value) })
    }
    $changed = @($rows | ForEach-Object { "$($_.Section)\$($_.Key)" })
    $refusals = @(Test-IgwtSecurityPolicySafeguards -Proposed $proposed -Changed $changed -Identity (Get-IgwtCurrentIdentity) -Accounts (Get-IgwtLocalAccountAudit))
    $m = Get-IgwtManagementState
    $notes = @()
    if ($m.DomainJoined) { $notes += 'Domain-joined: account policies for domain accounts come from the domain; a domain GPO overrides local security settings at the next refresh.' }
    [pscustomobject]@{ Rows = $rows.ToArray(); Template = $template; Proposed = $proposed; Refusals = $refusals; Managed = [bool]$m.Managed; Authorities = @($m.Authorities); Notes = $notes }
}

function Set-IgwtSecurityPolicy {
    <#
    .SYNOPSIS
        Applies security policy changes: export snapshot (backup folder with manifest), template
        with only the changed settings, `secedit /configure`, then a fresh export to verify.
        Revert with Restore-IgwtSecurityPolicy -BackupPath <Backup>.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][object[]]$Changes, [switch]$AcknowledgeManaged)
    $before = Export-IgwtSecurityPolicy
    $plan = Get-IgwtSecurityChangePlan -Changes $Changes -Current $before
    if ($plan.Refusals.Count) { throw "Refused: $($plan.Refusals -join ' ')" }
    if ($plan.Managed -and -not $AcknowledgeManaged) { throw "This PC is managed ($($plan.Authorities -join ', ')); a domain or MDM policy can override local security settings. Pass -AcknowledgeManaged to change it locally." }
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Changing the local security policy needs administrator rights.' }
    if (-not $PSCmdlet.ShouldProcess('Local security policy', "Set $(@($plan.Rows).Count) setting(s)")) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $dir = Join-Path (Get-IgwtDataPath -Kind Backups) ("secpol-{0}" -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    $null = New-Item -ItemType Directory -Path $dir -Force
    $beforeFile = Join-Path $dir 'before.inf'
    Write-IgwtSecurityInfFile -Path $beforeFile -Sections $before -WhatIf:$false
    $changeFile = Join-Path $dir 'change.inf'
    Write-IgwtSecurityInfFile -Path $changeFile -Sections $plan.Template -WhatIf:$false
    $manifest = [ordered]@{ kind = 'igwt-secpol-backup'; created = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME; sha256 = (Get-FileHash -LiteralPath $beforeFile -Algorithm SHA256).Hash
        changes = @($plan.Rows | ForEach-Object { [ordered]@{ section = $_.Section; key = $_.Key; before = $_.Current; after = $_.New } }) }
    [System.IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), (ConvertTo-IgwtJson -InputObject $manifest), (New-Object System.Text.UTF8Encoding($false)))
    $db = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-secpol-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
    try {
        $r = Invoke-IgwtSecedit -Arguments @('/configure', '/db', $db, '/cfg', $changeFile, '/areas', 'SECURITYPOLICY', 'USER_RIGHTS', '/log', (Join-Path $dir 'configure.log'), '/quiet')
        if ($r.ExitCode -ne 0) { throw "secedit /configure failed (exit $($r.ExitCode)): $($r.Output). The backup is in $dir." }
    } finally { Remove-Item -LiteralPath $db, "$db.jfm", ([System.IO.Path]::ChangeExtension($db, '.jfm')) -Force -ErrorAction SilentlyContinue }
    Write-IgwtLog -Message "Security policy: $(@($plan.Rows | ForEach-Object { "$($_.Section)\$($_.Key)=$($_.New)" }) -join '; '). Backup: $dir"
    $after = Export-IgwtSecurityPolicy
    $mismatch = @(foreach ($row in $plan.Rows) {
            $now = $(if ($after.Contains($row.Section) -and $after[$row.Section].Contains($row.Key)) { [string]$after[$row.Section][$row.Key] } else { '' })
            $want = [string]$row.New
            if ($row.Section -eq 'Privilege Rights') { $now = (@(ConvertTo-IgwtSidList -Value $now) | Sort-Object) -join ','; $want = (@(ConvertTo-IgwtSidList -Value $want) | Sort-Object) -join ',' }
            if ($now -ne $want) { "$($row.Section)\$($row.Key)" }
        })
    return [pscustomobject]@{ Backup = $dir; Rows = $plan.Rows; Verified = ($mismatch.Count -eq 0); Mismatch = $mismatch }
}

function Restore-IgwtSecurityPolicy {
    <#
    .SYNOPSIS
        Restores the settings a Set-IgwtSecurityPolicy backup changed, from its export snapshot.
        Settings that were not defined before cannot be removed by secedit and are reported.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$BackupPath)
    $mf = Join-Path $BackupPath 'manifest.json'
    if (-not (Test-Path -LiteralPath $mf)) { throw "'$BackupPath' is not a security policy backup (manifest.json missing)." }
    $m = Read-IgwtJsonFile -Path $mf
    if ([string]$m.kind -ne 'igwt-secpol-backup') { throw "'$BackupPath' is not an iG Windows Tuner security policy backup." }
    $beforeFile = Join-Path $BackupPath 'before.inf'
    if (-not (Test-Path -LiteralPath $beforeFile) -or (Get-FileHash -LiteralPath $beforeFile -Algorithm SHA256).Hash -ne [string]$m.sha256) { throw 'The backup snapshot is missing or was changed; nothing was restored.' }
    $before = Read-IgwtSecurityInfFile -Path $beforeFile
    $template = New-IgwtInfSectionTable
    $undefined = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($m.changes)) {
        $s = [string]$c.section; $k = [string]$c.key
        if ($before.Contains($s) -and $before[$s].Contains($k)) {
            if (-not $template.Contains($s)) { $template[$s] = New-IgwtInfSectionTable }
            $template[$s][$k] = [string]$before[$s][$k]
        } elseif ($s -eq 'Privilege Rights') {
            if (-not $template.Contains($s)) { $template[$s] = New-IgwtInfSectionTable }
            $template[$s][$k] = ''
        } else { $undefined.Add("$s\$k") }
    }
    if (-not $PSCmdlet.ShouldProcess('Local security policy', "Restore from $BackupPath")) { return $null }
    $file = Join-Path $BackupPath ("restore-{0}.inf" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    Write-IgwtSecurityInfFile -Path $file -Sections $template -WhatIf:$false
    $db = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-secpol-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
    try {
        $r = Invoke-IgwtSecedit -Arguments @('/configure', '/db', $db, '/cfg', $file, '/areas', 'SECURITYPOLICY', 'USER_RIGHTS', '/quiet')
        if ($r.ExitCode -ne 0) { throw "secedit /configure failed (exit $($r.ExitCode)): $($r.Output)" }
    } finally { Remove-Item -LiteralPath $db, ([System.IO.Path]::ChangeExtension($db, '.jfm')) -Force -ErrorAction SilentlyContinue }
    Write-IgwtLog -Message "Security policy restored from $BackupPath"
    return [pscustomobject]@{ Restored = $BackupPath; Settings = @($m.changes).Count; NotRemovable = $undefined.ToArray() }
}

#endregion
