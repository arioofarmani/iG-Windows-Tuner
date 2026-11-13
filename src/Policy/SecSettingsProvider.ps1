# SecSettingsProvider.ps1
# Security Settings Manager (3.8): the change provider 'localPolicy' (DECISIONS SM20, SM21). One
# target per ADMX policy and class; it owns exactly the registry entries the policy writes. Resolve
# never parses ADMX (the owned set travels in the target), Get reads Registry.pol directly, and the
# only writers (Set-IgwtSecSettingPolEntries, Restore-IgwtSecSettingPolEntries) check their own hard
# rules before they write. Registered here because src\Policy loads after src\Core\Transaction.ps1.

$script:IgwtSecSettingUserTool = '{D02B1F73-3407-48AE-BA88-E8213C6761F1}'
$script:IgwtSecSettingHardBlock = '(?i)\\Windows Defender\\Exclusions(\\|$)|\\Windows Defender Exploit Guard\\(ASR|Controlled Folder Access)(\\|$)'

function New-IgwtSecSettingPolTarget {
    <#
    .SYNOPSIS
        The journal target of one ADMX policy and class (DECISIONS SM20): provider 'localPolicy', key
        'localPolicy|<class>|<policy id>|<16 hex of SHA256 of the owned set>', the sorted owned set
        ('pair:key|valueName' and 'list:key', lower case) and the policy's client extension. Pure.
    .PARAMETER Policy
        A policy from Get-IgwtAdmxCatalog.
    .PARAMETER Class
        Machine or User.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory target only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy, [Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class)
    $o = Get-IgwtSecSettingOwnedSet -Policy $Policy
    $owned = @(@($o.Pairs | ForEach-Object { "pair:$_" }) + @($o.ListKeys | ForEach-Object { "list:$_" }) | Sort-Object -CaseSensitive)
    $hash = (Get-IgwtJournalHash -Line ($owned -join "`n")).Substring(0, 16)
    $cse = $(if ($Policy.PSObject.Properties['ClientExtension'] -and $Policy.ClientExtension) { [string]$Policy.ClientExtension } else { '' })
    return [ordered]@{ provider = 'localPolicy'; key = "localPolicy|$Class|$($Policy.Id)|$hash"; item = "localPolicy:$($Policy.Id):$Class"; class = $Class; policyId = [string]$Policy.Id; owned = $owned; cse = $cse }
}

function Resolve-IgwtSecSettingPolTarget {
    <#
    .SYNOPSIS
        The provider's Resolve (DECISIONS SM20, T4): checks the target from its own fields only (class,
        owned set below the Policies keys, the hash in the key, a valid client extension) and returns
        {Class; PolicyId; Pairs; ListKeys; Cse}. Throws for anything else. Pure.
    .PARAMETER Target
        The journal target.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target)
    $f = { param($n) if ($Target -is [System.Collections.IDictionary]) { $Target[$n] } elseif ($Target.PSObject.Properties[$n]) { $Target.$n } else { $null } }
    $no = "'$(& $f 'key')' is not a local policy target the manager owns"
    if ([string](& $f 'provider') -ne 'localPolicy') { throw "$no." }
    $class = [string](& $f 'class')
    if ($class -notin 'Machine', 'User') { throw "$no (class)." }
    $owned = @(& $f 'owned' | ForEach-Object { [string]$_ })
    if (-not $owned.Count) { throw "$no (no owned entries)." }
    $hash = (Get-IgwtJournalHash -Line ((@($owned | Sort-Object -CaseSensitive)) -join "`n")).Substring(0, 16)
    if ([string](& $f 'key') -ne "localPolicy|$class|$(& $f 'policyId')|$hash") { throw "$no (the key does not match its owned set)." }
    $pairs = New-Object 'System.Collections.Generic.HashSet[string]'; $lists = New-Object 'System.Collections.Generic.HashSet[string]'
    $roots = '^(software\\policies\\|software\\microsoft\\windows\\currentversion\\policies\\)'
    foreach ($o in $owned) {
        if ($o -match '^pair:(.+)\|([^|]*)$') { $k = $Matches[1]; $null = $pairs.Add($o.Substring(5)) }
        elseif ($o -match '^list:(.+)$') { $k = $Matches[1]; $null = $lists.Add($k) }
        else { throw "$no (owned entry '$o')." }
        if ($k -cne $k.ToLowerInvariant() -or $k -notmatch $roots -or $k -match '\\\.\.(\\|$)') { throw "$no (key '$k' is outside the Policies keys)." }
    }
    $cse = [string](& $f 'cse')
    if ($cse -and $cse -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') { throw "$no (client extension)." }
    return [pscustomobject]@{ Key = [string](& $f 'key'); Class = $class; PolicyId = [string](& $f 'policyId'); Pairs = $pairs; ListKeys = $lists; Cse = $cse }
}

function Test-IgwtSecSettingPolOwned {
    <# .SYNOPSIS True when a Registry.pol entry belongs to the resolved target's owned set (its value, **del. marker or a list key). Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Resolved, [Parameter(Mandatory = $true)]$Entry)
    $k = ([string]$Entry.Key).ToLowerInvariant()
    if ($Resolved.ListKeys.Contains($k)) { return $true }
    $n = [string]$Entry.ValueName
    $plain = $(if ($n -match '^\*\*del\.(.+)$') { $Matches[1] } else { $n })
    return $Resolved.Pairs.Contains(("$k|$plain").ToLowerInvariant())
}

function Get-IgwtSecSettingPolSnapshot {
    <#
    .SYNOPSIS
        The provider's Get (DECISIONS SM20): the owned Registry.pol entries of the target's class,
        read directly from the file (never the 30 s cache), as a sorted list of {key; valueName;
        type; dataHex}. Read-only.
    .PARAMETER Resolved
        Resolve-IgwtSecSettingPolTarget.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resolved)
    $all = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $Resolved.Class)).Entries)
    $mine = @($all | Where-Object { $_ -and (Test-IgwtSecSettingPolOwned -Resolved $Resolved -Entry $_) } | ForEach-Object {
            [ordered]@{ key = [string]$_.Key; valueName = [string]$_.ValueName; type = [int]$_.Type; dataHex = (ConvertTo-IgwtHexString ([byte[]]$_.Data)) }
        })
    $sorted = @($mine | Sort-Object -Property @{ Expression = { ("{0}|{1}" -f $_['key'], $_['valueName']).ToLowerInvariant() } } -CaseSensitive)
    return [ordered]@{ entries = $sorted }
}

function ConvertFrom-IgwtSecSettingPolSnapshot {
    <# .SYNOPSIS Registry.pol entry objects from a provider snapshot's entries. Pure. #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Entries = @())
    foreach ($e in @($Entries)) {
        if (-not $e) { continue }
        $g = { param($n) if ($e -is [System.Collections.IDictionary]) { $e[$n] } else { $e.$n } }
        New-IgwtPolEntryObject -Key ([string](& $g 'key')) -ValueName ([string](& $g 'valueName')) -Type ([int](& $g 'type')) -Data (ConvertTo-IgwtByteArray ([string](& $g 'dataHex')))
    }
}

function Assert-IgwtSecSettingPolEntries {
    <#
    .SYNOPSIS
        The provider's own hard rules (DECISIONS SM20): every entry in the owned set and none under a
        hard-blocked key (exclusions, ASR, Controlled Folder Access, Tamper Protection); with -Write,
        every value also passes the denylist, weakening.json and the UEFI-lock tuples. Throws. Pure.
    .PARAMETER Resolved
        Resolve-IgwtSecSettingPolTarget.
    .PARAMETER Entries
        Registry.pol entry objects.
    .PARAMETER Write
        The entries are new values (Set), not a restore.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resolved, [AllowEmptyCollection()][object[]]$Entries = @(), [switch]$Write)
    foreach ($e in @($Entries)) {
        if (-not (Test-IgwtSecSettingPolOwned -Resolved $Resolved -Entry $e)) { throw "Refused: $($e.Key)\$($e.ValueName) is not part of $($Resolved.PolicyId); nothing was written." }
        if ([string]$e.Key -match $script:IgwtSecSettingHardBlock -or [string]$e.ValueName -eq 'TamperProtection') { throw "Refused: $($e.Key)\$($e.ValueName) is never written by iG; nothing was written." }
        if ($Write -and [string]$e.ValueName -notmatch '^\*\*') {
            $why = Get-IgwtSecSettingOpRefusal -Class $Resolved.Class -Op ([pscustomobject]@{ Op = 'Set'; Key = [string]$e.Key; ValueName = [string]$e.ValueName; Value = $e.Value })
            if ($why) { throw "Refused: $why Nothing was written." }
        }
    }
}

function Write-IgwtSecSettingPolOwned {
    <#
    .SYNOPSIS
        Replaces the owned entries of one target in Registry.pol and updates gpt.ini like the Group
        Policy editor (DECISIONS SM21): version half of the class, the registry extension with the
        class's tool GUID, and the policy's client extension. Provider internal.
    .PARAMETER Resolved
        Resolve-IgwtSecSettingPolTarget.
    .PARAMETER Entries
        The new owned entries.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Resolved, [AllowEmptyCollection()][object[]]$Entries = @())
    Assert-IgwtWritable -Operation 'Write-IgwtSecSettingPolOwned'
    if (-not $PSCmdlet.ShouldProcess("$($Resolved.PolicyId) ($($Resolved.Class))", 'Write local Group Policy')) { return }
    $path = Get-IgwtLocalPolPath -Class $Resolved.Class
    $current = @((Read-IgwtRegistryPol -Path $path).Entries)
    $keep = @($current | Where-Object { $_ -and -not (Test-IgwtSecSettingPolOwned -Resolved $Resolved -Entry $_) })
    Write-IgwtRegistryPol -Path $path -Entries @($keep + @($Entries)) -Confirm:$false
    $gpt = Join-Path (Get-IgwtGpoRoot) 'gpt.ini'
    Assert-IgwtGpoPathAllowed -Path $gpt
    $tool = $(if ($Resolved.Class -eq 'User') { $script:IgwtSecSettingUserTool } else { $script:IgwtRegistryTool })
    $text = $(if (Test-Path -LiteralPath $gpt) { [System.IO.File]::ReadAllText($gpt) } else { '' })
    $text = Update-IgwtGptIniText -Text $text -Class $Resolved.Class -Tool $tool
    if ($Resolved.Cse) { $text = Update-IgwtGptIniText -Text $text -Class $Resolved.Class -Cse $Resolved.Cse -Tool $tool }
    [System.IO.File]::WriteAllText($gpt, $text, [System.Text.Encoding]::ASCII)
    Clear-IgwtCache -Prefix 'pol:' -WhatIf:$false
}

function Set-IgwtSecSettingPolEntries {
    <#
    .SYNOPSIS
        The provider's Set (DECISIONS SM20): checks the new owned entries (owned set, hard-blocked
        keys, denylist, weakening, UEFI lock) and writes them. Provider internal.
    .PARAMETER Resolved
        Resolve-IgwtSecSettingPolTarget.
    .PARAMETER Desired
        @{ entries = provider snapshot entries } (what Get must read back).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Resolved, [Parameter(Mandatory = $true)]$Desired)
    Assert-IgwtWritable -Operation 'Set-IgwtSecSettingPolEntries'
    $entries = @(ConvertFrom-IgwtSecSettingPolSnapshot -Entries @($Desired['entries']))
    Assert-IgwtSecSettingPolEntries -Resolved $Resolved -Entries $entries -Write
    if (-not $PSCmdlet.ShouldProcess($Resolved.PolicyId, 'Set local policy')) { return }
    Write-IgwtSecSettingPolOwned -Resolved $Resolved -Entries $entries -Confirm:$false
    return 'set'
}

function Restore-IgwtSecSettingPolEntries {
    <#
    .SYNOPSIS
        The provider's Restore (DECISIONS SM20): puts back recorded owned entries exactly (owned set
        and hard-blocked keys checked). Provider internal.
    .PARAMETER Resolved
        Resolve-IgwtSecSettingPolTarget.
    .PARAMETER Data
        A provider snapshot (@{ entries }).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Resolved, [Parameter(Mandatory = $true)]$Data)
    Assert-IgwtWritable -Operation 'Restore-IgwtSecSettingPolEntries'
    $list = $(if ($Data -is [System.Collections.IDictionary]) { $Data['entries'] } else { $Data.entries })
    $entries = @(ConvertFrom-IgwtSecSettingPolSnapshot -Entries @($list))
    Assert-IgwtSecSettingPolEntries -Resolved $Resolved -Entries $entries
    if (-not $PSCmdlet.ShouldProcess($Resolved.PolicyId, 'Restore local policy')) { return }
    Write-IgwtSecSettingPolOwned -Resolved $Resolved -Entries $entries -Confirm:$false
}

function ConvertTo-IgwtSecSettingPolDesired {
    <#
    .SYNOPSIS
        The desired provider snapshot for a planned change: the owned entries after applying the
        policy's Registry.pol operations, in the Get shape. Pure.
    .PARAMETER Resolved
        Resolve-IgwtSecSettingPolTarget.
    .PARAMETER CurrentEntries
        All Registry.pol entries of the class now.
    .PARAMETER Ops
        The plan's operations.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Resolved, [AllowEmptyCollection()][object[]]$CurrentEntries = @(), [AllowEmptyCollection()][object[]]$Ops = @())
    $after = @(Update-IgwtPolEntries -Entries @($CurrentEntries | Where-Object { $_ -and (Test-IgwtSecSettingPolOwned -Resolved $Resolved -Entry $_) }) -Ops $Ops)
    $mine = @($after | Where-Object { $_ -and (Test-IgwtSecSettingPolOwned -Resolved $Resolved -Entry $_) } | ForEach-Object { [ordered]@{ key = [string]$_.Key; valueName = [string]$_.ValueName; type = [int]$_.Type; dataHex = (ConvertTo-IgwtHexString ([byte[]]$_.Data)) } })
    return [ordered]@{ entries = @($mine | Sort-Object -Property @{ Expression = { ("{0}|{1}" -f $_['key'], $_['valueName']).ToLowerInvariant() } } -CaseSensitive) }
}

function Invoke-IgwtSecSettingRefresh {
    <#
    .SYNOPSIS
        One Group Policy refresh per touched class after a manager apply (DECISIONS SM21). Returns
        @{ Class; Ok; Message } per class.
    .PARAMETER Classes
        Machine and/or User.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]]$Classes = @())
    Assert-IgwtWritable -Operation 'Invoke-IgwtSecSettingRefresh'
    foreach ($c in @($Classes | Select-Object -Unique)) {
        if ($c -notin 'Machine', 'User') { continue }
        if (-not $PSCmdlet.ShouldProcess($c, 'Refresh Group Policy')) { continue }
        try { $null = Invoke-IgwtGpUpdate -Target $c -Confirm:$false; [pscustomobject]@{ Class = $c; Ok = $true; Message = '' } }
        catch { [pscustomobject]@{ Class = $c; Ok = $false; Message = $_.Exception.Message } }
    }
}

$script:IgwtChangeProviders['localPolicy'] = @{
    Reversible = { param($r) $null = $r; 'exact' }
    Resolve    = { param($t, $catalog) $null = $catalog; Resolve-IgwtSecSettingPolTarget -Target $t }
    Get        = { param($r, $ctx) $null = $ctx; Get-IgwtSecSettingPolSnapshot -Resolved $r }
    Set        = { param($r, $desired, $ctx) $null = $ctx; Set-IgwtSecSettingPolEntries -Resolved $r -Desired $desired -Confirm:$false }
    Restore    = { param($r, $data, $ctx) $null = $ctx; Restore-IgwtSecSettingPolEntries -Resolved $r -Data $data -Confirm:$false }
    TestSet    = {
        param($r, $desired, $ctx)
        $null = $ctx
        $now = Get-IgwtSecSettingPolSnapshot -Resolved $r
        $ok = ((ConvertTo-IgwtCanonicalJson $now) -eq (ConvertTo-IgwtCanonicalJson $desired))
        return [pscustomobject]@{ Ok = $ok; State = $(if ($ok) { 'set' } else { 'differs' }); Note = $(if ($ok) { '' } else { 'Registry.pol does not read back as written.' }) }
    }
}
