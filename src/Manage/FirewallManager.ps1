# FirewallManager.ps1
# The Firewall Manager (3.3): every rule of the effective policy (ActiveStore), loaded with one bulk
# query per class (rules and each filter class) and joined in memory on InstanceID, with its source
# (Windows, third-party app, Store app, iG Windows Tuner, Group Policy/MDM), risk flags and a
# program-exists check. Changes (enable, disable, Allow/Block, edit, new, duplicate, delete, import)
# are validated first, write an 'Firewall' snapshot with the full rule definitions, and are
# reverted from it. Group Policy and MDM rules are locked; Windows rules can be enabled or disabled
# but not edited or deleted; rules that keep a remote session (Remote Desktop, WinRM) alive are not
# changed while such a session is active. Profile changes only move toward more protection: the
# firewall is never turned off and the default inbound action is never set to Allow.

$script:IgwtFirewallOwnedPrefix = 'iGWindowsTuner-'
$script:IgwtFirewallOwnedGroup = 'iG Windows Tuner'
$script:IgwtFirewallPortKeywords = @('Any', 'RPC', 'RPCEPMap', 'IPHTTPSIn', 'IPHTTPSOut', 'Teredo', 'PlayToDiscovery', 'mDNS', 'Ply2Disc')
$script:IgwtFirewallAddressKeywords = @('Any', 'LocalSubnet', 'DNS', 'DHCP', 'WINS', 'DefaultGateway', 'Internet', 'Intranet', 'IntranetRemoteAccess', 'PlayToDevice', 'LocalSubnet4', 'LocalSubnet6')
$script:IgwtFirewallProtocols = @('Any', 'TCP', 'UDP', 'ICMPv4', 'ICMPv6')
# Rules that keep a remote session alive: never changed while a remote session is active.
$script:IgwtFirewallRemoteGroups = @('Remote Desktop', 'Remote Desktop (WebSocket)', 'Windows Remote Management', 'Windows Remote Management (Compatibility)', 'Remote Desktop - Shadow')
$script:IgwtFirewallRemotePorts = @('3389', '5985', '5986')
# Windows rules whose loss breaks networking: never disabled.
$script:IgwtFirewallCoreGroups = @('Core Networking', 'Core Networking Diagnostics')

#region Inventory (read-only)

function Test-IgwtFirewallUserWritablePath {
    <# .SYNOPSIS True for program paths under folders standard users can write (user profile, temp, downloads, public). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Path)
    if (-not $Path -or $Path -in 'Any', 'System') { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path)
    return [bool]($p -match '(?i)^[a-z]:\\Users\\' -or $p -match '(?i)\\AppData\\' -or $p -match '(?i)\\(Temp|Tmp|Downloads)\\' -or $p -match '(?i)^[a-z]:\\(Temp|Tmp)\\')
}

function Get-IgwtFirewallRuleSource {
    <#
    .SYNOPSIS
        Where a rule comes from: GroupPolicy (also MDM; locked), Owned (iG Windows Tuner), StoreApp
        (AppContainer/package), Windows (ships with Windows) or ThirdParty (added by an app or a user).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Rule, [string]$Package)
    $type = [string]$Rule.PolicyStoreSourceType
    if ($type -in 'GroupPolicy', 'MDM') { return 'GroupPolicy' }
    if ([string]$Rule.Name -like "$script:IgwtFirewallOwnedPrefix*") { return 'Owned' }
    if ([string]$Rule.Owner -or $Package) { return 'StoreApp' }
    if ([string]$Rule.Group -like '@*' -or [string]$Rule.DisplayGroup -like '@*' -or [string]$Rule.DisplayName -like '@*') { return 'Windows' }
    return 'ThirdParty'
}

function ConvertTo-IgwtFirewallList {
    <# .SYNOPSIS A filter value (string, array or $null) as text; empty means Any. #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)
    $items = @($Value | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ })
    if ($items.Count -eq 0) { return 'Any' }
    return ($items -join ', ')
}

function Join-IgwtFirewallData {
    <#
    .SYNOPSIS
        Joins rules with their filters (bulk query results) on InstanceID and adds the source,
        lock, program-exists check and risk flags. Pure: the tests feed it mocks.
    #>
    [CmdletBinding()]
    param([object[]]$Rules = @(), [object[]]$ApplicationFilters = @(), [object[]]$PortFilters = @(), [object[]]$AddressFilters = @(),
        [object[]]$ServiceFilters = @(), [object[]]$InterfaceFilters = @(), [scriptblock]$PathExists = { param($p) Test-Path -LiteralPath $p -PathType Leaf })
    $index = { param($list) $h = @{}; foreach ($f in @($list)) { if ($f -and $f.InstanceID) { $h[[string]$f.InstanceID] = $f } }; $h }
    $app = & $index $ApplicationFilters; $port = & $index $PortFilters; $addr = & $index $AddressFilters; $svc = & $index $ServiceFilters; $ift = & $index $InterfaceFilters
    $exists = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules | Where-Object { $_ })) {
        $id = [string]$r.InstanceID
        if (-not $id) { $id = [string]$r.Name }
        $a = $app[$id]; $p = $port[$id]; $ad = $addr[$id]; $s = $svc[$id]; $i = $ift[$id]
        $program = $(if ($a -and [string]$a.Program) { [string]$a.Program } else { 'Any' })
        $package = $(if ($a -and [string]$a.Package) { [string]$a.Package } else { '' })
        $source = Get-IgwtFirewallRuleSource -Rule $r -Package $package
        $programExists = ''
        if ($program -notin 'Any', 'System') {
            $expanded = [Environment]::ExpandEnvironmentVariables($program)
            if (-not $exists.ContainsKey($expanded)) { $exists[$expanded] = [bool](& $PathExists $expanded) }
            $programExists = $(if ($exists[$expanded]) { 'Yes' } else { 'No' })
        }
        $profileText = [string]$r.Profile
        if (-not $profileText -or $profileText -eq '0') { $profileText = 'Any' }
        $profiles = @($profileText -split ',\s*' | Where-Object { $_ })
        $row = [ordered]@{
            Key = [string]$r.Name; Name = [string]$r.Name; DisplayName = $(if ([string]$r.DisplayName) { [string]$r.DisplayName } else { [string]$r.Name })
            Group = [string]$r.DisplayGroup; Enabled = ([string]$r.Enabled -eq 'True'); Direction = [string]$r.Direction; Action = [string]$r.Action
            Profiles = $profileText; ProfileList = $profiles; Program = $program; Package = $package; Owner = [string]$r.Owner
            Service = $(if ($s -and [string]$s.Service) { [string]$s.Service } else { 'Any' })
            Protocol = $(if ($p -and [string]$p.Protocol) { [string]$p.Protocol } elseif ($p) { 'Any' } else { '' })
            LocalPort = $(if ($p) { ConvertTo-IgwtFirewallList $p.LocalPort } else { '' })
            RemotePort = $(if ($p) { ConvertTo-IgwtFirewallList $p.RemotePort } else { '' })
            LocalAddress = $(if ($ad) { ConvertTo-IgwtFirewallList $ad.LocalAddress } else { '' })
            RemoteAddress = $(if ($ad) { ConvertTo-IgwtFirewallList $ad.RemoteAddress } else { '' })
            InterfaceType = $(if ($i -and [string]$i.InterfaceType) { [string]$i.InterfaceType } elseif ($i) { 'Any' } else { '' })
            EdgeTraversal = [string]$r.EdgeTraversalPolicy; Source = $source; StoreSource = [string]$r.PolicyStoreSource
            Locked = ($source -eq 'GroupPolicy'); LockReason = $(if ($source -eq 'GroupPolicy') { "Set by $(if ([string]$r.PolicyStoreSourceType -eq 'MDM') { 'MDM' } else { 'Group Policy' }) ($($r.PolicyStoreSource)); change it there." } else { '' })
            ProgramExists = $programExists; Description = [string]$r.Description; Risks = @(); RiskText = ''
        }
        $rows.Add($row)
    }
    $out = @(foreach ($row in $rows) { [pscustomobject]$row })
    Add-IgwtFirewallRisk -Rows $out
    return , $out
}

function Add-IgwtFirewallRisk {
    <#
    .SYNOPSIS
        Sets Risks and RiskText on every row (in place): inbound allow on Public, any program/any
        port, program not found, program in a user-writable folder, duplicates (needs all rows)
        and disabled Windows defaults. Also used after a partial refresh of a few rows.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates in-memory rows only.')]
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $labels = @{ InboundPublic = 'Inbound allow on Public'; Broad = 'Any program, any port'; ProgramMissing = 'Program not found'; UserWritable = 'Program in a user-writable folder'; Duplicate = 'Duplicate'; DisabledWindows = 'Disabled Windows default' }
    $keyOf = { param($r) ('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}' -f $r.Direction, $r.Action, ([string]$r.Program).ToLowerInvariant(), $r.Service, $r.Package, $r.Protocol, $r.LocalPort, $r.RemotePort, $r.RemoteAddress, $r.Profiles) }
    $count = @{}
    # Duplicates are counted among app, Store and user rules only: Windows ships many look-alike rules
    # that differ in settings this view does not read, and Group Policy rules are not ours to merge.
    $dupCandidate = { param($r) [string]$r.Source -notin 'Windows', 'GroupPolicy' }
    foreach ($r in $Rows) { if (-not (& $dupCandidate $r)) { continue }; $k = & $keyOf $r; if ($count.ContainsKey($k)) { $count[$k]++ } else { $count[$k] = 1 } }
    foreach ($r in $Rows) {
        $risks = New-Object System.Collections.Generic.List[string]
        $inboundAllow = $r.Enabled -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow'
        if ($inboundAllow -and (@($r.ProfileList) -contains 'Public' -or @($r.ProfileList) -contains 'Any')) { $risks.Add('InboundPublic') }
        if ($inboundAllow -and $r.Program -eq 'Any' -and $r.Service -eq 'Any' -and -not $r.Package -and $r.LocalPort -in 'Any', '' -and $r.RemoteAddress -in 'Any', '') { $risks.Add('Broad') }
        if ($r.ProgramExists -eq 'No') { $risks.Add('ProgramMissing') }
        if (Test-IgwtFirewallUserWritablePath -Path $r.Program) { $risks.Add('UserWritable') }
        if ((& $dupCandidate $r) -and $count[(& $keyOf $r)] -gt 1) { $risks.Add('Duplicate') }
        if ($r.Source -eq 'Windows' -and -not $r.Enabled) { $risks.Add('DisabledWindows') }
        $r.Risks = $risks.ToArray()
        $r.RiskText = (@($risks | Where-Object { $_ -ne 'DisabledWindows' } | ForEach-Object { $labels[$_] }) -join '; ')
    }
}

function Get-IgwtFirewallRuleRows {
    <#
    .SYNOPSIS
        Inventory rows for a few rules (after a change), read from the ActiveStore with their
        filters. Rules that no longer exist are listed in Missing. Risk flags are not set (they
        need every row; the GUI recomputes them with Add-IgwtFirewallRisk). Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Name)
    $rules = New-Object System.Collections.Generic.List[object]
    $app = New-Object System.Collections.Generic.List[object]; $port = New-Object System.Collections.Generic.List[object]; $addr = New-Object System.Collections.Generic.List[object]
    $svc = New-Object System.Collections.Generic.List[object]; $ift = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Name | Select-Object -Unique)) {
        $r = @(Get-NetFirewallRule -Name $n -PolicyStore ActiveStore -ErrorAction SilentlyContinue) | Select-Object -First 1
        if (-not $r) { $missing.Add($n); continue }
        $rules.Add($r)
        foreach ($pair in @(@($app, { $r | Get-NetFirewallApplicationFilter }), @($port, { $r | Get-NetFirewallPortFilter }), @($addr, { $r | Get-NetFirewallAddressFilter }), @($svc, { $r | Get-NetFirewallServiceFilter }), @($ift, { $r | Get-NetFirewallInterfaceTypeFilter }))) {
            try { foreach ($x in @(& $pair[1] -ErrorAction Stop)) { if ($x) { $pair[0].Add($x) } } } catch { Write-Verbose "Filter of $n not readable: $($_.Exception.Message)" }
        }
    }
    $rows = Join-IgwtFirewallData -Rules $rules.ToArray() -ApplicationFilters $app.ToArray() -PortFilters $port.ToArray() -AddressFilters $addr.ToArray() -ServiceFilters $svc.ToArray() -InterfaceFilters $ift.ToArray()
    [pscustomobject]@{ Rows = $rows; Missing = $missing.ToArray() }
}

function Get-IgwtFirewallInventory {
    <#
    .SYNOPSIS
        Every firewall rule of the effective policy with its filters, source, risk flags and the
        firewall profiles, plus the load timings. Read-only. Without administrator rights the port,
        address and interface filters cannot be read; the result says so (Partial).
    .PARAMETER PolicyStore
        ActiveStore (effective policy, default) or PersistentStore (local rules only).
    #>
    [CmdletBinding()]
    param([ValidateSet('ActiveStore', 'PersistentStore')][string]$PolicyStore = 'ActiveStore')
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timing = [ordered]@{}
    $notes = New-Object System.Collections.Generic.List[string]
    $read = {
        param($name, $block)
        $t0 = $sw.ElapsedMilliseconds
        try { $v = @(& $block) } catch { $notes.Add("$name could not be read: $($_.Exception.Message)"); $v = $null }
        $timing[$name] = $sw.ElapsedMilliseconds - $t0
        , $v
    }
    $rules = & $read 'Rules' { Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop }
    if ($null -eq $rules) { throw ($notes -join ' ') }
    $appF = & $read 'Programs' { Get-NetFirewallApplicationFilter -PolicyStore $PolicyStore -ErrorAction Stop }
    $portF = & $read 'Ports' { Get-NetFirewallPortFilter -PolicyStore $PolicyStore -ErrorAction Stop }
    $addrF = & $read 'Addresses' { Get-NetFirewallAddressFilter -PolicyStore $PolicyStore -ErrorAction Stop }
    $svcF = & $read 'Services' { Get-NetFirewallServiceFilter -PolicyStore $PolicyStore -ErrorAction Stop }
    $ifF = & $read 'Interfaces' { Get-NetFirewallInterfaceTypeFilter -PolicyStore $PolicyStore -ErrorAction Stop }
    $t0 = $sw.ElapsedMilliseconds
    $rows = Join-IgwtFirewallData -Rules $rules -ApplicationFilters @($appF) -PortFilters @($portF) -AddressFilters @($addrF) -ServiceFilters @($svcF) -InterfaceFilters @($ifF)
    $timing['Join'] = $sw.ElapsedMilliseconds - $t0
    $partial = ($null -eq $portF -or $null -eq $addrF -or $null -eq $ifF)
    if ($partial) { $notes.Add('Ports, addresses and interface types need administrator rights; restart as administrator to see them.') }
    $total = $sw.ElapsedMilliseconds
    Write-IgwtLog -Message ("Firewall inventory: {0} rules in {1} ms ({2})" -f @($rows).Count, $total, (@($timing.Keys | ForEach-Object { "$_ $($timing[$_]) ms" }) -join ', '))
    [pscustomobject]@{
        Rules = $rows; Count = @($rows).Count; PolicyStore = $PolicyStore; Partial = $partial; Notes = $notes.ToArray(); Timing = [pscustomobject]$timing; LoadMs = $total
        Counts = [pscustomobject]@{
            Enabled = @($rows | Where-Object { $_.Enabled }).Count
            Risky = @($rows | Where-Object { @($_.Risks | Where-Object { $_ -ne 'DisabledWindows' }).Count }).Count
            Locked = @($rows | Where-Object { $_.Locked }).Count
        }
        Read = (Get-Date)
    }
}

function Get-IgwtFirewallProfileStatus {
    <#
    .SYNOPSIS
        The Domain, Private and Public profiles (on/off, default actions, notifications, unicast
        response, logging) and the network category of each connected adapter. Read-only.
    #>
    [CmdletBinding()]
    param()
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True'); DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction
                Notifications = ([string]$_.NotifyOnListen -eq 'True'); UnicastResponse = ([string]$_.AllowUnicastResponseToMulticast -eq 'True')
                LogAllowed = ([string]$_.LogAllowed -eq 'True'); LogBlocked = ([string]$_.LogBlocked -eq 'True'); LogFile = [string]$_.LogFileName; LogMaxKB = [int]$_.LogMaxSizeKilobytes
            }
        })
    $networks = @()
    try {
        $networks = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ InterfaceAlias = [string]$_.InterfaceAlias; InterfaceIndex = [int]$_.InterfaceIndex; Network = [string]$_.Name; Category = [string]$_.NetworkCategory; IPv4 = [string]$_.IPv4Connectivity }
            })
    } catch { Write-Verbose "Network profiles unavailable: $($_.Exception.Message)" }
    [pscustomobject]@{ Profiles = $profiles; Networks = $networks }
}

function Test-IgwtRemoteSession {
    <# .SYNOPSIS True in a Remote Desktop session or a PowerShell remoting (WinRM) session. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (Test-IgwtRdpSession) { return $true }
    return [bool]$PSSenderInfo
}

#endregion

#region Validation and plans

function Test-IgwtFirewallPortList {
    <# .SYNOPSIS '' when the port list is valid (numbers, ranges, keywords), otherwise the reason. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    if (-not $Value) { return '' }
    foreach ($part in @($Value -split '\s*,\s*' | Where-Object { $_ })) {
        if ($script:IgwtFirewallPortKeywords -contains $part) { continue }
        if ($part -match '^(\d{1,5})(?:-(\d{1,5}))?$') {
            $a = [int]$Matches[1]; $b = $(if ($Matches[2]) { [int]$Matches[2] } else { $a })
            if ($a -lt 1 -or $b -gt 65535 -or $b -lt $a) { return "'$part' is not a port or port range between 1 and 65535." }
            continue
        }
        return "'$part' is not a port, a port range (for example 27015-27030) or a keyword ($($script:IgwtFirewallPortKeywords -join ', '))."
    }
    return ''
}

function Test-IgwtFirewallAddressList {
    <# .SYNOPSIS '' when every address is an IP, a subnet (CIDR or mask), a range or a keyword, otherwise the reason. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    if (-not $Value) { return '' }
    foreach ($part in @($Value -split '\s*,\s*' | Where-Object { $_ })) {
        if ($script:IgwtFirewallAddressKeywords -contains $part) { continue }
        $ip = $null
        $pieces = @($part -split '-')
        if ($pieces.Count -eq 2 -and [System.Net.IPAddress]::TryParse($pieces[0], [ref]$ip) -and [System.Net.IPAddress]::TryParse($pieces[1], [ref]$ip)) { continue }
        $cidr = @($part -split '/')
        if ([System.Net.IPAddress]::TryParse($cidr[0], [ref]$ip)) {
            if ($cidr.Count -eq 1) { continue }
            $max = $(if ($ip.AddressFamily -eq 'InterNetworkV6') { 128 } else { 32 })
            $m = $null
            # A prefix length (/24) or a dotted mask (/255.255.255.0); a bare number is a prefix, never an address.
            if ($cidr.Count -eq 2 -and (($cidr[1] -match '^\d{1,3}$' -and [int]::TryParse($cidr[1], [ref]$m) -and $m -ge 0 -and $m -le $max) -or ($cidr[1] -match '[.:]' -and [System.Net.IPAddress]::TryParse($cidr[1], [ref]$ip)))) { continue }
        }
        return "'$part' is not an IP address, subnet (192.0.2.0/24), range (192.0.2.1-192.0.2.9) or keyword ($($script:IgwtFirewallAddressKeywords -join ', '))."
    }
    return ''
}

function Test-IgwtFirewallRemoteRelevant {
    <# .SYNOPSIS True when a rule (row or definition) is one a remote session depends on. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Rule)
    if ($script:IgwtFirewallRemoteGroups -contains [string]$Rule.Group) { return $true }
    foreach ($p in @(([string]$Rule.LocalPort) -split '\s*,\s*')) { if ($script:IgwtFirewallRemotePorts -contains $p) { return $true } }
    return $false
}

function Get-IgwtFirewallChangeBlock {
    <#
    .SYNOPSIS
        Why an operation is not allowed on a rule ('' when allowed). Rule is an inventory row.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable', 'SetAction', 'Edit', 'Duplicate', 'Delete')][string]$Operation, [Parameter(Mandatory = $true)]$Rule,
        [hashtable]$Settings = @{}, [bool]$RemoteSession = $false)
    if ($Rule.Locked) { return [string]$Rule.LockReason }
    if ($RemoteSession -and $Operation -ne 'Enable' -and $Operation -ne 'Duplicate' -and (Test-IgwtFirewallRemoteRelevant -Rule $Rule)) { return 'This rule keeps remote sessions (Remote Desktop or WinRM) working and a remote session is active; change it from the local console.' }
    switch ($Operation) {
        'Disable' { if ($Rule.Source -eq 'Windows' -and $script:IgwtFirewallCoreGroups -contains [string]$Rule.Group) { return 'Core Networking rules (DHCP, DNS, IPv6 neighbor discovery) keep the network working and are never disabled.' } }
        'SetAction' {
            if ($Rule.Source -eq 'Windows') { return 'Windows rules can be enabled or disabled, not changed. Duplicate it and change the copy instead.' }
            if ($Settings.Action -notin 'Allow', 'Block') { return 'The action must be Allow or Block.' }
        }
        'Edit' { if ($Rule.Source -eq 'Windows') { return 'Windows rules can be enabled or disabled, not edited. Duplicate it and edit the copy instead.' } }
        'Delete' { if ($Rule.Source -eq 'Windows') { return 'Windows rules are never deleted; disable it instead.' } }
    }
    return ''
}

function Test-IgwtFirewallRuleSettings {
    <#
    .SYNOPSIS
        Validates new or edited rule settings (hashtable). Returns the list of problems (empty when
        valid) and normalizes values in place.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Settings, [switch]$New)
    $errs = New-Object System.Collections.Generic.List[string]
    if ($New -and -not ([string]$Settings.DisplayName).Trim()) { $errs.Add('Give the rule a name.') }
    if ($Settings.ContainsKey('DisplayName') -and ([string]$Settings.DisplayName).Length -gt 200) { $errs.Add('The name is longer than 200 characters.') }
    if ($Settings.ContainsKey('Direction') -and $Settings.Direction -notin 'Inbound', 'Outbound') { $errs.Add('Direction must be Inbound or Outbound.') }
    if ($Settings.ContainsKey('Action') -and $Settings.Action -notin 'Allow', 'Block') { $errs.Add('Action must be Allow or Block.') }
    if ($Settings.ContainsKey('Profiles')) {
        $p = @($Settings.Profiles | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if ($p.Count -eq 0) { $errs.Add('Pick at least one profile.') }
        elseif (@($p | Where-Object { $_ -notin 'Domain', 'Private', 'Public', 'Any' }).Count) { $errs.Add('Profiles are Domain, Private, Public or Any.') }
        $Settings.Profiles = $p
    }
    if ($Settings.ContainsKey('Protocol')) {
        $proto = [string]$Settings.Protocol
        if ($proto -and $script:IgwtFirewallProtocols -notcontains $proto -and -not ($proto -match '^\d{1,3}$' -and [int]$proto -le 255)) { $errs.Add("Protocol must be $($script:IgwtFirewallProtocols -join ', ') or a protocol number (0-255).") }
    }
    foreach ($k in 'LocalPort', 'RemotePort') {
        if ($Settings.ContainsKey($k) -and [string]$Settings[$k] -and [string]$Settings[$k] -ne 'Any') {
            $why = Test-IgwtFirewallPortList -Value ([string]$Settings[$k])
            if ($why) { $errs.Add("${k}: $why") }
            elseif ([string]$Settings.Protocol -notin 'TCP', 'UDP') { $errs.Add('Ports need protocol TCP or UDP.') }
        }
    }
    foreach ($k in 'LocalAddress', 'RemoteAddress') {
        if ($Settings.ContainsKey($k) -and [string]$Settings[$k]) { $why = Test-IgwtFirewallAddressList -Value ([string]$Settings[$k]); if ($why) { $errs.Add("${k}: $why") } }
    }
    if ($Settings.ContainsKey('Program') -and [string]$Settings.Program -and [string]$Settings.Program -notin 'Any', 'System') {
        $prog = [string]$Settings.Program
        if ($prog -notmatch '^(%[A-Za-z]+%|[A-Za-z]:)\\' -or $prog.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) { $errs.Add('The program must be a full path, for example C:\Games\Game\game.exe.') }
    }
    if ($Settings.ContainsKey('Service') -and [string]$Settings.Service -and [string]$Settings.Service -ne 'Any' -and [string]$Settings.Service -notmatch '^[\w\.\-\$ ]{1,256}$') { $errs.Add('The service name is not valid.') }
    return $errs.ToArray()
}

function Get-IgwtFirewallRuleTemplates {
    <# .SYNOPSIS Starting points for the new-rule wizard. #>
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{ Id = 'game-udp-private'; Name = 'Allow a game inbound (UDP), Private networks only'; Settings = @{ Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; Profiles = @('Private'); RemoteAddress = 'Any' }; Needs = 'Program' }
        [pscustomobject]@{ Id = 'game-tcp-private'; Name = 'Allow a game inbound (TCP), Private networks only'; Settings = @{ Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; Profiles = @('Private'); RemoteAddress = 'Any' }; Needs = 'Program' }
        [pscustomobject]@{ Id = 'block-app-out'; Name = 'Block a program from the internet (outbound)'; Settings = @{ Direction = 'Outbound'; Action = 'Block'; Protocol = 'Any'; Profiles = @('Any') }; Needs = 'Program' }
        [pscustomobject]@{ Id = 'lan-only'; Name = 'Allow a program inbound from the local network only'; Settings = @{ Direction = 'Inbound'; Action = 'Allow'; Protocol = 'Any'; Profiles = @('Private'); RemoteAddress = 'LocalSubnet' }; Needs = 'Program' }
        [pscustomobject]@{ Id = 'block-port-in'; Name = 'Block an inbound port on every network'; Settings = @{ Direction = 'Inbound'; Action = 'Block'; Protocol = 'TCP'; Profiles = @('Any') }; Needs = 'LocalPort' }
    )
}

function Get-IgwtFirewallChangePlan {
    <#
    .SYNOPSIS
        Dry run of Invoke-IgwtFirewallChange: per rule what would change, or why it is refused.
        Read-only.
    .PARAMETER Operation
        Enable, Disable, SetAction, Edit, New, Duplicate or Delete.
    .PARAMETER Rules
        Inventory rows (Get-IgwtFirewallInventory) the operation applies to (not used by New).
    .PARAMETER Settings
        SetAction: Action. Edit: any of DisplayName, Profiles, Protocol, LocalPort, RemotePort,
        LocalAddress, RemoteAddress, Program, Description. New: the full rule.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable', 'SetAction', 'Edit', 'New', 'Duplicate', 'Delete')][string]$Operation,
        [object[]]$Rules = @(), [hashtable]$Settings = @{}, [Nullable[bool]]$RemoteSession)
    $remote = $(if ($null -ne $RemoteSession) { [bool]$RemoteSession } else { Test-IgwtRemoteSession })
    $items = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($Operation -eq 'New') {
        $s = @{} + $Settings
        $errs = @(Test-IgwtFirewallRuleSettings -Settings $s -New)
        if ($remote -and $s.Direction -eq 'Inbound' -and $s.Action -eq 'Block' -and (([string]$s.LocalPort) -in '', 'Any' -or (Test-IgwtFirewallRemoteRelevant -Rule ([pscustomobject]@{ Group = ''; LocalPort = [string]$s.LocalPort })))) {
            $errs = @($errs) + 'A remote session is active: an inbound block rule on every port or on the remote-access ports could cut it off. Create it from the local console.'
        }
        $items.Add([pscustomobject]@{ Name = ''; DisplayName = [string]$s.DisplayName; Allowed = (@($errs).Count -eq 0); Reason = (@($errs) -join ' '); Change = "Create $($s.Direction) $($s.Action) rule '$($s.DisplayName)'" })
        if ($s.Direction -eq 'Inbound' -and $s.Action -eq 'Allow' -and (@($s.Profiles) -contains 'Public' -or @($s.Profiles) -contains 'Any')) { $warnings.Add('This allows inbound traffic on public networks (cafes, hotels). Prefer Private only.') }
    } else {
        $errs = @()
        if ($Operation -eq 'Edit') { $errs = @(Test-IgwtFirewallRuleSettings -Settings $Settings) }
        foreach ($r in @($Rules | Where-Object { $_ })) {
            $why = Get-IgwtFirewallChangeBlock -Operation $Operation -Rule $r -Settings $Settings -RemoteSession $remote
            if (-not $why -and @($errs).Count) { $why = @($errs) -join ' ' }
            $change = switch ($Operation) {
                'Enable' { if ($r.Enabled) { '' } else { 'Enable' } }
                'Disable' { if (-not $r.Enabled) { '' } else { 'Disable' } }
                'SetAction' { if ($r.Action -eq $Settings.Action) { '' } else { "$($r.Action) -> $($Settings.Action)" } }
                'Edit' { 'Edit ' + (@($Settings.Keys | Sort-Object) -join ', ') }
                'Duplicate' { 'Copy as a new rule' }
                'Delete' { 'Delete (a snapshot keeps the full rule)' }
            }
            $items.Add([pscustomobject]@{ Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; Allowed = (-not $why); Reason = $why; Change = $(if ($why) { '' } elseif ($change) { $change } else { 'Already set' }); NoOp = (-not $why -and -not $change) })
        }
        if ($Operation -eq 'SetAction' -and $Settings.Action -eq 'Allow' -and @($Rules | Where-Object { $_.Direction -eq 'Inbound' }).Count) { $warnings.Add('Switching inbound rules to Allow opens the PC to that traffic.') }
        if ($Operation -eq 'SetAction' -and $Settings.Action -eq 'Block') { $warnings.Add('Blocking can stop the program from working (online play, updates, voice chat).') }
        if ($Operation -eq 'Disable' -and @($Rules | Where-Object { $_.Source -eq 'Windows' }).Count) { $warnings.Add('Disabling Windows rules can stop Windows features (file sharing, casting, remote help) from working.') }
    }
    $ok = @($items | Where-Object { $_.Allowed -and -not $_.NoOp })
    [pscustomobject]@{
        Operation = $Operation; Items = $items.ToArray(); Count = $ok.Count; Refused = @($items | Where-Object { -not $_.Allowed }).Count; Warnings = $warnings.ToArray()
        RemoteSession = $remote; NeedsConfirmTimer = ($remote -and $ok.Count -gt 0)
        Summary = $(if ($ok.Count -eq 0) { 'Nothing to change.' } else { "$Operation $($ok.Count) rule(s)" + $(if (@($items | Where-Object { -not $_.Allowed }).Count) { "; $(@($items | Where-Object { -not $_.Allowed }).Count) refused" } else { '' }) })
    }
}

#endregion

#region Rule definitions (snapshot data)

function Get-IgwtFirewallRuleDefinition {
    <# .SYNOPSIS The full definition of one rule (rule and filters) as a hashtable, for snapshots and export. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $r = @(Get-NetFirewallRule -Name $Name -ErrorAction Stop) | Select-Object -First 1
    $a = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $p = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $ad = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    $s = $r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
    $i = $r | Get-NetFirewallInterfaceTypeFilter -ErrorAction SilentlyContinue
    return [ordered]@{
        name = [string]$r.Name; displayName = [string]$r.DisplayName; description = [string]$r.Description; group = [string]$r.Group
        enabled = ([string]$r.Enabled -eq 'True'); direction = [string]$r.Direction; action = [string]$r.Action; profile = [string]$r.Profile
        edgeTraversal = [string]$r.EdgeTraversalPolicy; owner = [string]$r.Owner
        program = $(if ($a) { [string]$a.Program } else { 'Any' }); package = $(if ($a) { [string]$a.Package } else { '' })
        service = $(if ($s) { [string]$s.Service } else { 'Any' })
        protocol = $(if ($p) { [string]$p.Protocol } else { 'Any' }); localPort = @($(if ($p) { $p.LocalPort })); remotePort = @($(if ($p) { $p.RemotePort }))
        localAddress = @($(if ($ad) { $ad.LocalAddress })); remoteAddress = @($(if ($ad) { $ad.RemoteAddress }))
        interfaceType = $(if ($i) { [string]$i.InterfaceType } else { 'Any' })
    }
}

function ConvertTo-IgwtFirewallRuleParameters {
    <#
    .SYNOPSIS
        New-NetFirewallRule / Set-NetFirewallRule parameters from a definition (snapshot, export or
        wizard). Values are validated; -ForSet leaves out what Set-NetFirewallRule cannot change.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [switch]$ForSet)
    $d = $Definition
    $get = { param($n) if ($d -is [System.Collections.IDictionary]) { $d[$n] } else { $d.$n } }
    $p = @{ ErrorAction = 'Stop' }
    if (-not $ForSet) {
        $p.Name = [string](& $get 'name')
        $p.DisplayName = [string](& $get 'displayName')
        $g = [string](& $get 'group'); if ($g) { $p.Group = $g }
        $p.Direction = [string](& $get 'direction')
        $own = [string](& $get 'owner'); if ($own) { $p.Owner = $own }
        $pkg = [string](& $get 'package'); if ($pkg) { $p.Package = $pkg }
    } else {
        $dn = [string](& $get 'displayName'); if ($dn) { $p.NewDisplayName = $dn }
    }
    $desc = [string](& $get 'description'); if ($desc) { $p.Description = $desc }
    $p.Enabled = $(if ([bool](& $get 'enabled')) { 'True' } else { 'False' })
    $act = [string](& $get 'action'); if ($act) { $p.Action = $act }
    $prof = [string](& $get 'profile'); if ($prof) { $p.Profile = @($prof -split ',\s*') }
    $edge = [string](& $get 'edgeTraversal'); if ($edge) { $p.EdgeTraversalPolicy = $edge }
    $prog = [string](& $get 'program'); if ($prog) { $p.Program = $prog }
    $svc = [string](& $get 'service'); if ($svc) { $p.Service = $svc }
    $proto = [string](& $get 'protocol'); if ($proto) { $p.Protocol = $proto }
    foreach ($k in @(@('localPort', 'LocalPort'), @('remotePort', 'RemotePort'), @('localAddress', 'LocalAddress'), @('remoteAddress', 'RemoteAddress'))) {
        $v = @(& $get $k[0] | Where-Object { $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ })
        # Ports exist only for TCP and UDP rules.
        if ($k[1] -like '*Port' -and $proto -notin 'TCP', 'UDP') { continue }
        if ($v.Count) { $p[$k[1]] = $v }
    }
    $it = [string](& $get 'interfaceType'); if ($it) { $p.InterfaceType = $it }
    return $p
}

#endregion

#region Changes (snapshot first)

function New-IgwtFirewallRuleName {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a new name only.')]
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return "$($script:IgwtFirewallOwnedPrefix)User-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
}

function Invoke-IgwtFirewallChange {
    <#
    .SYNOPSIS
        Applies a firewall rule change after validating it and writing a 'Firewall' snapshot with
        the full definition of every rule it touches. Revert with Invoke-IgwtRevert -SnapshotPath.
    .PARAMETER Operation
        Enable, Disable, SetAction, Edit, New, Duplicate or Delete.
    .PARAMETER Name
        Rule names (Name, not display name). Not used by New.
    .PARAMETER Settings
        See Get-IgwtFirewallChangePlan.
    .PARAMETER AllowRemoteSession
        Allow changes during a remote session (the GUI then asks to keep them within 60 seconds and
        reverts them automatically otherwise). Rules a remote session depends on stay refused.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable', 'SetAction', 'Edit', 'New', 'Duplicate', 'Delete')][string]$Operation,
        [string[]]$Name = @(), [hashtable]$Settings = @{}, [switch]$AllowRemoteSession)
    Assert-IgwtWritable -Operation 'Invoke-IgwtFirewallChange'
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Firewall changes need administrator rights.' }
        Initialize-IgwtDataRoot
    }
    $remote = Test-IgwtRemoteSession
    if ($remote -and -not $AllowRemoteSession) { throw 'A remote session (Remote Desktop or WinRM) is active. Firewall changes are refused unless -AllowRemoteSession is given (the GUI reverts them automatically when they are not confirmed within 60 seconds).' }
    $rows = @()
    if ($Operation -ne 'New') {
        if (@($Name).Count -eq 0) { throw 'Give at least one rule name.' }
        if (@($Name).Count -gt 1000) { throw 'At most 1,000 rules per change.' }
        $inv = Get-IgwtFirewallInventory
        $byName = @{}; foreach ($r in $inv.Rules) { $byName[$r.Name] = $r }
        $missing = @($Name | Where-Object { -not $byName.ContainsKey($_) })
        if ($missing.Count) { throw "Rule(s) not found: $($missing -join ', ')" }
        $rows = @($Name | ForEach-Object { $byName[$_] })
    }
    $plan = Get-IgwtFirewallChangePlan -Operation $Operation -Rules $rows -Settings $Settings -RemoteSession $remote
    $todo = @($plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp })
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($plan.Items | Where-Object { -not $_.Allowed })) { $results.Add([pscustomobject]@{ Target = $(if ($i.DisplayName) { $i.DisplayName } else { $i.Name }); Change = $Operation; Result = 'Refused'; Message = $i.Reason }) }
    if ($todo.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($todo.Count) firewall rule(s)", $Operation)) { return [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = $results.ToArray(); Plan = $plan } }
    $snap = New-IgwtSnapshot -Operation 'Firewall' -Detail "$Operation $($todo.Count) rule(s)"
    Save-IgwtSnapshot -Snapshot $snap
    $n = 0
    foreach ($item in $todo) {
        $n++
        $tid = "firewall:$Operation`:$n"
        $before = $null
        $created = ''
        try {
            switch ($Operation) {
                'New' {
                    $def = [ordered]@{ name = (New-IgwtFirewallRuleName); displayName = [string]$Settings.DisplayName; description = [string]$Settings.Description; group = $script:IgwtFirewallOwnedGroup
                        enabled = $true; direction = [string]$Settings.Direction; action = [string]$Settings.Action; profile = (@($Settings.Profiles) -join ', ')
                        program = [string]$Settings.Program; service = [string]$Settings.Service; protocol = [string]$Settings.Protocol
                        localPort = @(([string]$Settings.LocalPort) -split '\s*,\s*' | Where-Object { $_ }); remotePort = @(([string]$Settings.RemotePort) -split '\s*,\s*' | Where-Object { $_ })
                        remoteAddress = @(([string]$Settings.RemoteAddress) -split '\s*,\s*' | Where-Object { $_ }); localAddress = @(([string]$Settings.LocalAddress) -split '\s*,\s*' | Where-Object { $_ }) }
                    $created = $def.name
                    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'created'; name = $created }) -Result 'Applied' -Message "create $($def.displayName)"
                    $np = ConvertTo-IgwtFirewallRuleParameters -Definition $def; $null = New-NetFirewallRule @np
                }
                'Duplicate' {
                    $def = Get-IgwtFirewallRuleDefinition -Name $item.Name
                    $def.name = New-IgwtFirewallRuleName; $def.displayName = "$($def.displayName) (copy)"; $def.group = $script:IgwtFirewallOwnedGroup; $def.owner = ''
                    $created = $def.name
                    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'created'; name = $created }) -Result 'Applied' -Message "duplicate $($item.Name)"
                    $np = ConvertTo-IgwtFirewallRuleParameters -Definition $def; $null = New-NetFirewallRule @np
                }
                default {
                    $before = Get-IgwtFirewallRuleDefinition -Name $item.Name
                    $op = $(if ($Operation -eq 'Delete') { 'deleted' } else { 'changed' })
                    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = $op; name = $item.Name; definition = $before }) -Result 'Applied' -Message "$Operation $($item.Name)"
                    switch ($Operation) {
                        'Enable' { Enable-NetFirewallRule -Name $item.Name -ErrorAction Stop }
                        'Disable' { Disable-NetFirewallRule -Name $item.Name -ErrorAction Stop }
                        'SetAction' { Set-NetFirewallRule -Name $item.Name -Action ([string]$Settings.Action) -ErrorAction Stop }
                        'Delete' { Remove-NetFirewallRule -Name $item.Name -ErrorAction Stop }
                        'Edit' {
                            $p = @{ Name = $item.Name; ErrorAction = 'Stop' }
                            if ($Settings.ContainsKey('DisplayName')) { $p.NewDisplayName = [string]$Settings.DisplayName }
                            if ($Settings.ContainsKey('Description')) { $p.Description = [string]$Settings.Description }
                            if ($Settings.ContainsKey('Profiles')) { $p.Profile = @($Settings.Profiles) }
                            if ($Settings.ContainsKey('Protocol')) { $p.Protocol = [string]$Settings.Protocol }
                            foreach ($k in 'LocalPort', 'RemotePort', 'LocalAddress', 'RemoteAddress') { if ($Settings.ContainsKey($k)) { $p[$k] = @(([string]$Settings[$k]) -split '\s*,\s*' | Where-Object { $_ }); if (@($p[$k]).Count -eq 0) { $p[$k] = @('Any') } } }
                            if ($Settings.ContainsKey('Program')) { $p.Program = $(if ([string]$Settings.Program) { [string]$Settings.Program } else { 'Any' }) }
                            Set-NetFirewallRule @p
                        }
                    }
                }
            }
            $results.Add([pscustomobject]@{ Target = $(if ($item.DisplayName) { $item.DisplayName } else { $created }); Change = $item.Change; Result = 'Applied'; Message = $(if ($created) { "New rule $created" } else { '' }) })
        } catch {
            Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = $(if ($created) { 'created' } else { 'changed' }); name = $(if ($created) { $created } else { $item.Name }); definition = $before }) -Result 'Failed' -Message $_.Exception.Message
            $results.Add([pscustomobject]@{ Target = $(if ($item.DisplayName) { $item.DisplayName } else { $item.Name }); Change = $item.Change; Result = 'Failed'; Message = $_.Exception.Message })
        }
    }
    Write-IgwtLog -Message "Firewall change: $Operation, $(@($results | Where-Object Result -EQ 'Applied').Count) applied, $(@($results | Where-Object Result -NE 'Applied').Count) refused or failed. Snapshot: $($snap.Path)"
    return [pscustomobject]@{ Snapshot = $snap.Path; Changes = @($results | Where-Object Result -EQ 'Applied').Count; Results = $results.ToArray(); Plan = $plan; RemoteSession = $remote }
}

function Restore-IgwtFirewallSnapshot {
    <#
    .SYNOPSIS
        Reverts a 'Firewall' snapshot: removes rules it created (only iG Windows Tuner rules),
        recreates rules it deleted and writes back changed rules from their saved definitions.
        The current state is saved in a new 'Firewall' snapshot first.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    Assert-IgwtWritable -Operation 'Restore-IgwtFirewallSnapshot'
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    if ([string]$doc.operation -ne 'Firewall') { throw 'This is not a firewall snapshot.' }
    $seen = @{}
    $entries = @($doc.entries | Where-Object { $_ -and [string]$_.result -in 'Applied', 'Failed' } | Where-Object { $k = [string]$_.tweakId; if ($seen.ContainsKey($k)) { $false } else { $seen[$k] = $true; $true } })
    [array]::Reverse($entries)
    $results = New-Object System.Collections.Generic.List[object]
    if ($entries.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($entries.Count) rule change(s) from $(Split-Path $SnapshotPath -Leaf)", 'Revert')) { return [pscustomobject]@{ Snapshot = $null; Results = @() } }
    $undo = New-IgwtSnapshot -Operation 'Firewall' -Detail "revert of $(Split-Path $SnapshotPath -Leaf)"
    Save-IgwtSnapshot -Snapshot $undo
    $n = 0
    foreach ($e in $entries) {
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            $n++
            $name = [string]$a.name
            try {
                if ([string]$a.type -ne 'firewallManager') { throw 'Unknown snapshot action.' }
                $exists = [bool](@(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue).Count)
                switch ([string]$a.op) {
                    'created' {
                        if (-not $name.StartsWith($script:IgwtFirewallOwnedPrefix)) { throw "Only rules created by iG Windows Tuner are removed on revert ('$name')." }
                        if ($exists) {
                            Add-IgwtSnapshotEntry -Snapshot $undo -TweakId "firewall:revert:$n" -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'deleted'; name = $name; definition = (Get-IgwtFirewallRuleDefinition -Name $name) }) -Result 'Applied' -Message 'before revert'
                            Remove-NetFirewallRule -Name $name -ErrorAction Stop
                        }
                    }
                    { $_ -in 'changed', 'deleted' } {
                        $def = $a.definition
                        if (-not $def) { throw 'The snapshot has no rule definition.' }
                        if ([string]$def.name -ne $name) { throw 'The snapshot definition does not match the rule.' }
                        if ($exists) {
                            Add-IgwtSnapshotEntry -Snapshot $undo -TweakId "firewall:revert:$n" -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'changed'; name = $name; definition = (Get-IgwtFirewallRuleDefinition -Name $name) }) -Result 'Applied' -Message 'before revert'
                            $p = ConvertTo-IgwtFirewallRuleParameters -Definition $def -ForSet
                            Set-NetFirewallRule -Name $name @p
                        } else {
                            Add-IgwtSnapshotEntry -Snapshot $undo -TweakId "firewall:revert:$n" -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'created'; name = $name }) -Result 'Applied' -Message 'before revert'
                            $np = ConvertTo-IgwtFirewallRuleParameters -Definition $def; $null = New-NetFirewallRule @np
                        }
                    }
                    default { throw "Unknown snapshot operation '$($a.op)'." }
                }
                $results.Add([pscustomobject]@{ Id = $name; Result = 'Reverted'; Message = '' })
            } catch {
                $results.Add([pscustomobject]@{ Id = $name; Result = 'Failed'; Message = $_.Exception.Message })
                Write-IgwtLog -Level Error -Message "Firewall revert of ${name}: $($_.Exception.Message)"
            }
        }
    }
    Write-IgwtLog -Message "Firewall snapshot $(Split-Path $SnapshotPath -Leaf) reverted. Undo snapshot: $($undo.Path)"
    return [pscustomobject]@{ Snapshot = $undo.Path; Results = $results.ToArray() }
}

#endregion

#region Export and import

function Export-IgwtFirewallRules {
    <#
    .SYNOPSIS
        Writes rules (all, or -Name) to JSON (full definitions, importable) or CSV (inventory
        columns). Reads the firewall and writes only the export file.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [string[]]$Name, [ValidateSet('Json', 'Csv')][string]$Format = 'Json')
    $inv = Get-IgwtFirewallInventory
    $rows = @($inv.Rules | Where-Object { -not $Name -or $Name -contains $_.Name })
    if (-not $PSCmdlet.ShouldProcess($Path, "Export $($rows.Count) firewall rule(s)")) { return }
    if ($Format -eq 'Csv') {
        $rows | Select-Object DisplayName, Name, Group, Enabled, Direction, Action, Profiles, Program, Service, Package, Protocol, LocalPort, RemotePort, LocalAddress, RemoteAddress, InterfaceType, EdgeTraversal, Source, ProgramExists, RiskText, Description |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    } else {
        $defs = @(foreach ($r in $rows) {
                [ordered]@{ name = $r.Name; displayName = $r.DisplayName; description = $r.Description; group = $r.Group; enabled = $r.Enabled; direction = $r.Direction; action = $r.Action
                    profile = $r.Profiles; program = $r.Program; service = $r.Service; package = $r.Package; protocol = $r.Protocol
                    localPort = @(($r.LocalPort -split ',\s*') | Where-Object { $_ }); remotePort = @(($r.RemotePort -split ',\s*') | Where-Object { $_ })
                    localAddress = @(($r.LocalAddress -split ',\s*') | Where-Object { $_ }); remoteAddress = @(($r.RemoteAddress -split ',\s*') | Where-Object { $_ })
                    interfaceType = $r.InterfaceType; edgeTraversal = $r.EdgeTraversal; source = $r.Source }
            })
        $doc = [ordered]@{ tool = 'iG Windows Tuner'; kind = 'firewall-rules'; version = 1; exported = (Get-Date).ToUniversalTime().ToString('o'); rules = $defs }
        [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $doc -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    return $Path
}

function Export-IgwtFirewallPolicy {
    <# .SYNOPSIS Full firewall policy backup with 'netsh advfirewall export' (.wfw). Exporting does not change the firewall. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -notlike '*.wfw') { throw 'The policy file must end in .wfw.' }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export the firewall policy')) { return }
    $out = & "$env:SystemRoot\System32\netsh.exe" advfirewall export "$Path" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh advfirewall export failed: $($out -join ' ')" }
    return $Path
}

function Get-IgwtFirewallImportPlan {
    <#
    .SYNOPSIS
        Preview of importing an iG Windows Tuner firewall JSON export: which rules are new, changed
        or the same. Windows and Group Policy rules in the file are skipped (never imported).
        Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $doc = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    if ([string]$doc.kind -ne 'firewall-rules' -or [int]$doc.version -ne 1) { throw 'This is not an iG Windows Tuner firewall rule export.' }
    $inv = Get-IgwtFirewallInventory
    $byName = @{}; foreach ($r in $inv.Rules) { $byName[$r.Name] = $r }
    $items = foreach ($d in @($doc.rules)) {
        $name = [string]$d.name
        $status = ''; $reason = ''
        if ([string]$d.source -in 'Windows', 'GroupPolicy' -or [string]$d.group -like '@*') { $status = 'Skipped'; $reason = 'Windows and Group Policy rules are not imported.' }
        else {
            $settings = @{ DisplayName = [string]$d.displayName; Direction = [string]$d.direction; Action = [string]$d.action; Profiles = @(([string]$d.profile) -split ',\s*'); Protocol = [string]$d.protocol
                LocalPort = (@($d.localPort) -join ','); RemotePort = (@($d.remotePort) -join ','); RemoteAddress = (@($d.remoteAddress) -join ','); LocalAddress = (@($d.localAddress) -join ','); Program = [string]$d.program }
            $errs = @(Test-IgwtFirewallRuleSettings -Settings $settings -New)
            if (@($errs).Count) { $status = 'Invalid'; $reason = @($errs) -join ' ' }
            elseif (-not $byName.ContainsKey($name)) { $status = 'New' }
            else {
                $cur = $byName[$name]
                if ($cur.Locked -or $cur.Source -eq 'Windows') { $status = 'Skipped'; $reason = 'A Windows or Group Policy rule with this name exists.' }
                else {
                    $diff = @(foreach ($k in @(@('Enabled', 'enabled'), @('Direction', 'direction'), @('Action', 'action'), @('Profiles', 'profile'), @('Program', 'program'), @('Protocol', 'protocol'), @('LocalPort', 'localPort'), @('RemotePort', 'remotePort'), @('RemoteAddress', 'remoteAddress'))) {
                            $new = $(if ($d.($k[1]) -is [array]) { ConvertTo-IgwtFirewallList $d.($k[1]) } else { [string]$d.($k[1]) })
                            if ("$($cur.($k[0]))" -ne $new) { "$($k[0]): $($cur.($k[0])) -> $new" }
                        })
                    if ($diff.Count) { $status = 'Changed'; $reason = $diff -join '; ' } else { $status = 'Same' }
                }
            }
        }
        [pscustomobject]@{ Name = $name; DisplayName = [string]$d.displayName; Status = $status; Detail = $reason; Definition = $d }
    }
    $items = @($items)
    [pscustomobject]@{ Path = $Path; Items = $items; New = @($items | Where-Object Status -EQ 'New').Count; Changed = @($items | Where-Object Status -EQ 'Changed').Count; Same = @($items | Where-Object Status -EQ 'Same').Count; Skipped = @($items | Where-Object { $_.Status -in 'Skipped', 'Invalid' }).Count }
}

function Import-IgwtFirewallRules {
    <#
    .SYNOPSIS
        Imports the New and Changed rules of an iG Windows Tuner firewall export (see
        Get-IgwtFirewallImportPlan), after a 'Firewall' snapshot. New rules get an iG Windows Tuner
        name so a revert removes them.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-IgwtWritable -Operation 'Import-IgwtFirewallRules'
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Firewall changes need administrator rights.' }
        Initialize-IgwtDataRoot
    }
    if (Test-IgwtRemoteSession) { throw 'A remote session is active; import firewall rules from the local console.' }
    $plan = Get-IgwtFirewallImportPlan -Path $Path
    $todo = @($plan.Items | Where-Object { $_.Status -in 'New', 'Changed' })
    if ($todo.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($todo.Count) firewall rule(s)", 'Import')) { return [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @(); Plan = $plan } }
    $snap = New-IgwtSnapshot -Operation 'Firewall' -Detail "import $(Split-Path $Path -Leaf)"
    Save-IgwtSnapshot -Snapshot $snap
    $results = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($i in $todo) {
        $n++
        $d = $i.Definition
        try {
            $def = [ordered]@{}
            foreach ($p in $d.PSObject.Properties) { $def[$p.Name] = $p.Value }
            if ($i.Status -eq 'New') {
                $def.name = New-IgwtFirewallRuleName; $def.group = $script:IgwtFirewallOwnedGroup; $def.owner = ''
                Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "firewall:import:$n" -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'created'; name = $def.name }) -Result 'Applied' -Message "import $($i.DisplayName)"
                $np = ConvertTo-IgwtFirewallRuleParameters -Definition $def; $null = New-NetFirewallRule @np
            } else {
                Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "firewall:import:$n" -Actions @([ordered]@{ index = 0; type = 'firewallManager'; op = 'changed'; name = $i.Name; definition = (Get-IgwtFirewallRuleDefinition -Name $i.Name) }) -Result 'Applied' -Message "import $($i.DisplayName)"
                $p = ConvertTo-IgwtFirewallRuleParameters -Definition $def -ForSet
                Set-NetFirewallRule -Name $i.Name @p
            }
            $results.Add([pscustomobject]@{ Target = $i.DisplayName; Change = $i.Status; Result = 'Applied'; Message = $i.Detail })
        } catch { $results.Add([pscustomobject]@{ Target = $i.DisplayName; Change = $i.Status; Result = 'Failed'; Message = $_.Exception.Message }) }
    }
    Write-IgwtLog -Message "Firewall import of $(Split-Path $Path -Leaf): $(@($results | Where-Object Result -EQ 'Applied').Count) rule(s). Snapshot: $($snap.Path)"
    return [pscustomobject]@{ Snapshot = $snap.Path; Changes = @($results | Where-Object Result -EQ 'Applied').Count; Results = $results.ToArray(); Plan = $plan }
}

#endregion

#region Profiles and network category

function Get-IgwtFirewallProfileChangeBlock {
    <# .SYNOPSIS Why a profile change is refused ('' when allowed). Only changes toward more protection or neutral ones are allowed. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'Notifications', 'UnicastResponse', 'LogAllowed', 'LogBlocked', 'LogMaxKB')][string]$Setting, $Value)
    switch ($Setting) {
        'Enabled' { if (-not [bool]$Value) { return 'iG Windows Tuner never turns the firewall off.' } }
        'DefaultInboundAction' { if ([string]$Value -ne 'Block') { return 'The default inbound action stays Block; allow programs with rules instead.' } }
        'DefaultOutboundAction' { if ([string]$Value -notin 'Allow', 'Block') { return 'The default outbound action is Allow or Block.' } }
        'LogMaxKB' { if ([int]$Value -lt 1024 -or [int]$Value -gt 32767) { return 'The log size is between 1,024 and 32,767 KB.' } }
    }
    return ''
}

function Set-IgwtFirewallProfileSetting {
    <#
    .SYNOPSIS
        Changes one setting of one firewall profile after a 'FirewallProfile' snapshot of the
        profile. Turning the firewall off and allowing inbound traffic by default are refused.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Domain', 'Private', 'Public')][string]$Profile,
        [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'Notifications', 'UnicastResponse', 'LogAllowed', 'LogBlocked', 'LogMaxKB')][string]$Setting,
        [Parameter(Mandatory = $true)]$Value)
    Assert-IgwtWritable -Operation 'Set-IgwtFirewallProfileSetting'
    $why = Get-IgwtFirewallProfileChangeBlock -Setting $Setting -Value $Value
    if ($why) { throw $why }
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Firewall changes need administrator rights.' }
        Initialize-IgwtDataRoot
    }
    $map = @{ Enabled = 'Enabled'; DefaultInboundAction = 'DefaultInboundAction'; DefaultOutboundAction = 'DefaultOutboundAction'; Notifications = 'NotifyOnListen'; UnicastResponse = 'AllowUnicastResponseToMulticast'; LogAllowed = 'LogAllowed'; LogBlocked = 'LogBlocked'; LogMaxKB = 'LogMaxSizeKilobytes' }
    $prop = $map[$Setting]
    $cur = Get-NetFirewallProfile -Name $Profile -PolicyStore PersistentStore -ErrorAction Stop
    if (-not $PSCmdlet.ShouldProcess("Firewall profile $Profile", "$Setting -> $Value")) { return $null }
    $snap = New-IgwtSnapshot -Operation 'FirewallProfile' -Detail "$Profile $Setting -> $Value"
    Save-IgwtSnapshot -Snapshot $snap
    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "firewallProfile:$Profile`:$Setting" -Actions @([ordered]@{ index = 0; type = 'firewallProfile'; profile = $Profile; setting = $Setting; property = $prop; value = [string]$cur.$prop }) -Result 'Applied' -Message "$Setting -> $Value"
    $arg = @{ Name = $Profile; ErrorAction = 'Stop' }
    if ($Setting -eq 'LogMaxKB') { $arg[$prop] = [uint64]$Value }
    elseif ($Setting -in 'DefaultInboundAction', 'DefaultOutboundAction') { $arg[$prop] = [string]$Value }
    else { $arg[$prop] = $(if ([bool]$Value) { 'True' } else { 'False' }) }
    Set-NetFirewallProfile @arg
    Write-IgwtLog -Message "Firewall profile ${Profile}: $Setting -> $Value. Snapshot: $($snap.Path)"
    return [pscustomobject]@{ Snapshot = $snap.Path; Profile = $Profile; Setting = $Setting; Value = $Value; Before = [string]$cur.$prop }
}

function Set-IgwtNetworkCategory {
    <#
    .SYNOPSIS
        Sets a connected network to Private or Public after a 'FirewallProfile' snapshot. Public
        is the safer choice on networks you do not control; Private allows discovery and sharing
        rules for that network. Domain networks are not changed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex, [Parameter(Mandatory = $true)][ValidateSet('Private', 'Public')][string]$Category)
    Assert-IgwtWritable -Operation 'Set-IgwtNetworkCategory'
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Changing the network category needs administrator rights.' }
        Initialize-IgwtDataRoot
    }
    $cur = @(Get-NetConnectionProfile -InterfaceIndex $InterfaceIndex -ErrorAction Stop) | Select-Object -First 1
    if ([string]$cur.NetworkCategory -eq 'DomainAuthenticated') { throw 'Domain networks are set by the domain and are not changed.' }
    if ([string]$cur.NetworkCategory -eq $Category) { return [pscustomobject]@{ Snapshot = $null; Changed = $false } }
    if (-not $PSCmdlet.ShouldProcess("$($cur.InterfaceAlias) ($($cur.Name))", "Network category -> $Category")) { return $null }
    $snap = New-IgwtSnapshot -Operation 'FirewallProfile' -Detail "$($cur.InterfaceAlias) -> $Category"
    Save-IgwtSnapshot -Snapshot $snap
    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "networkCategory:$InterfaceIndex" -Actions @([ordered]@{ index = 0; type = 'networkCategory'; interfaceIndex = $InterfaceIndex; alias = [string]$cur.InterfaceAlias; value = [string]$cur.NetworkCategory }) -Result 'Applied' -Message "-> $Category"
    Set-NetConnectionProfile -InterfaceIndex $InterfaceIndex -NetworkCategory $Category -ErrorAction Stop
    Write-IgwtLog -Message "Network category of $($cur.InterfaceAlias): $($cur.NetworkCategory) -> $Category. Snapshot: $($snap.Path)"
    return [pscustomobject]@{ Snapshot = $snap.Path; Changed = $true; Before = [string]$cur.NetworkCategory }
}

function Restore-IgwtFirewallProfileSnapshot {
    <#
    .SYNOPSIS
        Reverts a 'FirewallProfile' snapshot (profile settings and network categories). A saved
        value that would turn the firewall off or allow inbound by default is not written back
        (result Kept).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    Assert-IgwtWritable -Operation 'Restore-IgwtFirewallProfileSnapshot'
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    if ([string]$doc.operation -ne 'FirewallProfile') { throw 'This is not a firewall profile snapshot.' }
    $results = New-Object System.Collections.Generic.List[object]
    $entries = @($doc.entries | Where-Object { $_ -and [string]$_.result -eq 'Applied' })
    if ($entries.Count -eq 0 -or -not $PSCmdlet.ShouldProcess((Split-Path $SnapshotPath -Leaf), 'Revert')) { return [pscustomobject]@{ Snapshot = $null; Results = @() } }
    foreach ($e in $entries) {
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            try {
                switch ([string]$a.type) {
                    'firewallProfile' {
                        $setting = [string]$a.setting
                        $value = [string]$a.value
                        $typed = $(if ($setting -in 'DefaultInboundAction', 'DefaultOutboundAction') { $value } elseif ($setting -eq 'LogMaxKB') { [int]$value } else { $value -eq 'True' })
                        $why = Get-IgwtFirewallProfileChangeBlock -Setting $setting -Value $typed
                        if ($why -and $setting -in 'Enabled', 'DefaultInboundAction') { $results.Add([pscustomobject]@{ Id = "$($a.profile) $setting"; Result = 'Kept'; Message = $why }); continue }
                        $null = Set-IgwtFirewallProfileSetting -Profile ([string]$a.profile) -Setting $setting -Value $typed -Confirm:$false
                        $results.Add([pscustomobject]@{ Id = "$($a.profile) $setting"; Result = 'Reverted'; Message = '' })
                    }
                    'networkCategory' {
                        if ([string]$a.value -notin 'Private', 'Public') { throw "Saved category '$($a.value)' is not restored." }
                        $null = Set-IgwtNetworkCategory -InterfaceIndex ([int]$a.interfaceIndex) -Category ([string]$a.value) -Confirm:$false
                        $results.Add([pscustomobject]@{ Id = [string]$a.alias; Result = 'Reverted'; Message = '' })
                    }
                    default { throw 'Unknown snapshot action.' }
                }
            } catch { $results.Add([pscustomobject]@{ Id = [string]$e.tweakId; Result = 'Failed'; Message = $_.Exception.Message }) }
        }
    }
    return [pscustomobject]@{ Snapshot = $null; Results = $results.ToArray() }
}

#endregion

#region Log report

function Get-IgwtFirewallLogReport {
    <#
    .SYNOPSIS
        Plain-text summary of the firewall log for the GUI: logging status per profile, then
        blocked and allowed counts, top blocked sources, ports and processes, and the last hours.
        Read-only (reading the log needs administrator rights).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$Top = 10)
    $lines = New-Object System.Collections.Generic.List[string]
    $status = @()
    try { $status = @(Get-IgwtFirewallLoggingStatus) } catch { $lines.Add("Logging status not readable: $($_.Exception.Message)") }
    foreach ($p in $status) { $lines.Add(("{0,-8} logs blocked: {1,-5} allowed: {2,-5} {3}" -f $p.Profile, $p.LogBlocked, $p.LogAllowed, $p.LogFile)) }
    if (-not @($status | Where-Object { $_.LogBlocked -eq 'True' -or $_.LogAllowed -eq 'True' }).Count) {
        $lines.Add(''); $lines.Add('Logging is off for every profile. Turn on "Log blocked connections" on the Profiles and networks tab, use the PC for a while, then analyze again.')
        return $lines.ToArray()
    }
    try { $entries = @(Read-IgwtFirewallLog) } catch { $lines.Add(''); $lines.Add($_.Exception.Message); return $lines.ToArray() }
    $an = Get-IgwtFirewallLogAnalysis -Entries $entries -Top $Top
    $lines.Add('')
    $lines.Add("$($an.Entries) entries from $($an.From) to $($an.To): $($an.Dropped) blocked, $($an.Allowed) allowed.")
    foreach ($pair in @(@('Top blocked sources', $an.TopBlockedSources), @('Top blocked ports', $an.TopBlockedPorts), @('Top blocked processes', $an.TopBlockedProcesses), @('Top allowed processes', $an.TopAllowedProcesses))) {
        $lines.Add(''); $lines.Add([string]$pair[0])
        foreach ($r in @($pair[1])) { $lines.Add(("  {0,7}  {1}" -f $r.Count, $r.Value)) }
        if (-not @($pair[1]).Count) { $lines.Add('  (none)') }
    }
    $lines.Add(''); $lines.Add('Last hours (blocked / allowed):')
    foreach ($r in @($an.Timeline | Select-Object -Last 24)) { $lines.Add(("  {0}  {1,6} / {2,6}" -f $r.Hour, $r.Dropped, $r.Allowed)) }
    return $lines.ToArray()
}

#endregion
