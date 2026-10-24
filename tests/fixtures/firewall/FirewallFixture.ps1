# FirewallFixture.ps1
# Synthetic firewall rule sets for the 3.4 Firewall Manager tests (never a rule export of a real PC).
# New-IgwtFirewallFixture builds raw rules and filters in the shape of the NetSecurity cmdlets
# (some rules as raw CIM values), plus the expected classification of every rule: origin category,
# confidence, facets, Bloated for the Gamer role and the risk findings.

function New-IgwtFirewallFixture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds in-memory test data only.')]
    [CmdletBinding()]
    param([int]$Scale = 1)
    $rules = New-Object System.Collections.Generic.List[object]
    $app = New-Object System.Collections.Generic.List[object]; $port = New-Object System.Collections.Generic.List[object]
    $addr = New-Object System.Collections.Generic.List[object]; $svc = New-Object System.Collections.Generic.List[object]; $ift = New-Object System.Collections.Generic.List[object]
    $expect = @{}; $missing = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase); $sigs = @{}
    $add = {
        param([hashtable]$R)
        $id = [string]$R.Id
        # App and custom rules carry a description unless the test needs one without (NoDesc).
        $desc = $(if ($R.Description) { [string]$R.Description } elseif (-not $R.NoDesc -and $R.Origin -in 'UserInstalled', 'CustomRules' -and -not ($R.Id -like 'iGWindowsTuner-*')) { 'Fixture rule' } else { '' })
        $rule = [pscustomobject]@{
            Name = $id; InstanceID = $id; DisplayName = $(if ($R.Display) { $R.Display } else { $id }); DisplayGroup = [string]$R.DisplayGroup; Group = [string]$R.Group
            Enabled = $(if ($R.ContainsKey('Enabled')) { $(if ($R.Enabled) { 'True' } else { 'False' }) } else { 'True' })
            Direction = $(if ($R.Dir) { $R.Dir } else { 'Inbound' }); Action = $(if ($R.Action) { $R.Action } else { 'Allow' }); Profile = $(if ($R.Profile) { $R.Profile } else { 'Any' })
            EdgeTraversalPolicy = $(if ($R.Edge) { $R.Edge } else { 'Block' }); Owner = [string]$R.Owner; Description = $desc
            PolicyStoreSource = $(if ($R.StoreSource) { $R.StoreSource } else { 'PersistentStore' }); PolicyStoreSourceType = $(if ($R.StoreType) { $R.StoreType } else { 'Local' })
        }
        if ($R.Raw) {
            # Raw CIM shape (the NetSecurity type data was not attached): numbers, no Name, Profiles.
            $rule = [pscustomobject]@{
                Name = ''; InstanceID = $id; DisplayName = $rule.DisplayName; DisplayGroup = $rule.DisplayGroup; Group = $rule.Group
                Enabled = $(if ($rule.Enabled -eq 'True') { 1 } else { 2 }); Direction = $(if ($rule.Direction -eq 'Inbound') { 1 } else { 2 }); Action = $(if ($rule.Action -eq 'Allow') { 2 } else { 4 })
                Profile = $null; Profiles = $(switch ($rule.Profile) { 'Public' { 4 } 'Private' { 2 } 'Domain' { 1 } 'Private, Public' { 6 } default { 0 } }); EdgeTraversalPolicy = 0
                Owner = $rule.Owner; Description = $rule.Description; PolicyStoreSource = $rule.PolicyStoreSource; PolicyStoreSourceType = $(if ($rule.PolicyStoreSourceType -eq 'GroupPolicy') { 2 } else { 1 })
            }
        }
        if ($R.Store) { $rule | Add-Member -NotePropertyName Store -NotePropertyValue $R.Store }
        $rules.Add($rule)
        if ($R.Program -or $R.Package) { $app.Add([pscustomobject]@{ InstanceID = $id; Program = $(if ($R.Program) { $R.Program } else { 'Any' }); Package = [string]$R.Package }) }
        $port.Add([pscustomobject]@{ InstanceID = $id; Protocol = $(if ($R.Protocol) { $R.Protocol } else { 'Any' }); LocalPort = $(if ($R.LocalPort) { $R.LocalPort } else { 'Any' }); RemotePort = 'Any' })
        $addr.Add([pscustomobject]@{ InstanceID = $id; LocalAddress = 'Any'; RemoteAddress = $(if ($R.Remote) { $R.Remote } else { 'Any' }) })
        if ($R.Service) { $svc.Add([pscustomobject]@{ InstanceID = $id; Service = $R.Service }) }
        if ($R.Missing) { $null = $missing.Add([Environment]::ExpandEnvironmentVariables([string]$R.Program)) }
        if ($R.Signer) { $sigs[([Environment]::ExpandEnvironmentVariables([string]$R.Program)).ToLowerInvariant()] = [pscustomobject]@{ Status = $(if ($R.Signer -eq '-') { 'NotSigned' } else { 'Valid' }); Signer = $(if ($R.Signer -eq '-') { '' } else { $R.Signer }) } }
        $expect[$id] = [pscustomobject]@{ Origin = $R.Origin; Confidence = $(if ($R.Confidence) { $R.Confidence } else { 'High' }); Bloated = [bool]$R.Bloated; Findings = @($R.Findings); Store = [string]$R.Store; Locked = [bool]$R.Locked }
    }
    for ($s = 1; $s -le $Scale; $s++) {
        $n = { param($base) if ($Scale -gt 1) { "$base-s$s" } else { $base } }
        # Core Services: Core Networking (stable IDs and group string), localized display names, raw CIM shape.
        foreach ($c in 'DHCP-In', 'DHCPV6-In', 'IPv6-In', 'ICMP6-NDA-In', 'ICMP6-NDS-In', 'ICMP6-RA-In', 'ICMP6-RS-In', 'IGMP-In', 'DNS-Out-UDP', 'Teredo-In') {
            & $add @{ Id = (& $n "CoreNet-$c"); Group = '@FirewallAPI.dll,-25000'; DisplayGroup = 'Core Networking'; Display = "Kernnetzwerk - $c"; Service = 'Dhcp'; Origin = 'CoreServices' }
        }
        & $add @{ Id = (& $n 'CoreNet-GP-Out'); Group = '@FirewallAPI.dll,-25000'; Dir = 'Outbound'; Raw = $true; Origin = 'CoreServices' }
        & $add @{ Id = (& $n 'CoreNet-Disabled-In'); Group = '@FirewallAPI.dll,-25000'; Enabled = $false; Origin = 'CoreServices'; Findings = @('disabled-security-rule') }
        # Windows Service Hardening (read-only store).
        foreach ($i in 1..20) { & $add @{ Id = (& $n "Svc$i-1"); Display = "Block any inbound traffic to Svc$i"; Action = 'Block'; Program = '%SystemRoot%\system32\svchost.exe'; Service = "Svc$i"; Store = 'StaticServiceStore'; Origin = 'CoreServices'; Locked = $true } }
        # Windows Connections: discovery (Private), file sharing (Public: risk), remote desktop (bloat + risk), media sharing (bloat), many variants.
        foreach ($i in 1..120) { & $add @{ Id = (& $n "NETDIS-Var$i-In"); Group = '@FirewallAPI.dll,-32752'; DisplayGroup = 'Netzwerkerkennung'; Profile = 'Private'; Protocol = 'UDP'; LocalPort = '1900'; Remote = 'LocalSubnet'; Enabled = ($i % 3 -eq 0); Origin = 'WindowsConnections' } }
        & $add @{ Id = (& $n 'FPS-SMB-In-TCP'); Group = '@FirewallAPI.dll,-28502'; Profile = 'Private, Public'; Protocol = 'TCP'; LocalPort = '445'; Origin = 'WindowsConnections'; Bloated = $true; Findings = @('public-admin-protocol', 'remote-any-local-service') }
        & $add @{ Id = (& $n 'FPS-NB_Name-In-UDP'); Group = '@FirewallAPI.dll,-28502'; Profile = 'Public'; Protocol = 'UDP'; LocalPort = '137'; Origin = 'WindowsConnections'; Bloated = $true; Findings = @('public-local-discovery', 'remote-any-local-service') }
        & $add @{ Id = (& $n 'RemoteDesktop-UserMode-In-TCP'); Group = '@FirewallAPI.dll,-28752'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '3389'; Origin = 'WindowsConnections'; Bloated = $true; Findings = @('public-admin-protocol') }
        foreach ($i in 1..40) { & $add @{ Id = (& $n "MCX-Var$i-In-TCP"); Group = '@FirewallAPI.dll,-30752'; Profile = 'Private'; Protocol = 'TCP'; LocalPort = "$(10240 + $i)"; Remote = 'LocalSubnet'; Enabled = ($i -le 4); Origin = 'WindowsConnections'; Bloated = ($i -le 4) } }
        foreach ($i in 1..60) { & $add @{ Id = (& $n "PlayTo-Var$i-In"); Group = '@FirewallAPI.dll,-36001'; Profile = 'Private'; Protocol = 'TCP'; LocalPort = "$(2869)"; Remote = 'LocalSubnet'; Enabled = $false; Origin = 'WindowsConnections' } }
        & $add @{ Id = (& $n 'DeliveryOptimization-TCP-In'); Group = '@%systemroot%\system32\dosvc.dll,-100'; Protocol = 'TCP'; LocalPort = '7680'; Origin = 'WindowsConnections' }
        & $add @{ Id = (& $n 'WinRM-Unknown-Group-In'); Group = '@FirewallAPI.dll,-99999'; Protocol = 'TCP'; LocalPort = '47001'; Enabled = $false; Origin = 'WindowsConnections'; Confidence = 'Medium' }
        # Microsoft Store apps (publisher IDs of Microsoft), Xbox apps (bloat only without the Xbox app), a third-party Store app.
        foreach ($i in 1..40) { & $add @{ Id = (& $n "Microsoft.App$($i)_8wekyb3d8bbweS-1-5-21-1-1001-Out-Allow-AllCapabilities"); Dir = 'Outbound'; Owner = 'S-1-5-21-1-1001'; Group = "@{Microsoft.App$($i)_1.0.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.App$i/Resources/AppName}"; Origin = 'WindowsConnections' } }
        & $add @{ Id = (& $n 'Microsoft.XboxGamingOverlay_8wekyb3d8bbweS-1-5-21-1-1001-Out-Allow-AllCapabilities'); Dir = 'Outbound'; Owner = 'S-1-5-21-1-1001'; Origin = 'WindowsConnections'; Bloated = $true }
        & $add @{ Id = (& $n 'Microsoft.SecHealthUI_8wekyb3d8bbweS-1-5-21-1-1001-Out-Allow-AllCapabilities'); Dir = 'Outbound'; Owner = 'S-1-5-21-1-1001'; Origin = 'CoreServices' }
        & $add @{ Id = (& $n 'Contoso.Notes_a1b2c3d4e5f6gS-1-5-21-1-1001-Out-Allow-AllCapabilities'); Dir = 'Outbound'; Owner = 'S-1-5-21-1-1001'; Group = '@{Contoso.Notes_2.0.0.0_x64__a1b2c3d4e5f6g?ms-resource://Contoso.Notes/Resources/AppName}'; Origin = 'UserInstalled' }
        # User Installed: games and launchers (protected), prompt pairs, user-writable, unsigned, orphaned.
        foreach ($i in 1..80) {
            $exe = "C:\Program Files (x86)\Steam\steamapps\common\Game$i\game$i.exe"
            & $add @{ Id = (& $n "{00000000-0000-0000-0001-$('{0:D12}' -f $i)}"); Display = "Game $i"; Program = $exe; Protocol = 'UDP'; Profile = 'Private, Public'; Signer = 'Valve Corp.'; Origin = 'UserInstalled'; Confidence = 'Medium' }
        }
        & $add @{ Id = (& $n 'Steam Web Helper'); Display = 'Steam Web Helper'; Program = 'C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\steamwebhelper.exe'; Signer = 'Valve Corp.'; Origin = 'UserInstalled' }
        foreach ($proto in 'TCP', 'UDP') { & $add @{ Id = (& $n "{00000000-0000-0000-0002-00000000000$(if ($proto -eq 'TCP') { 1 } else { 2 })}"); Display = 'chatapp.exe'; Program = 'C:\Program Files\ChatApp\chatapp.exe'; Protocol = $proto; Profile = 'Public'; Origin = 'UserInstalled'; Confidence = 'Medium' } }
        & $add @{ Id = (& $n 'UpdaterInAppData'); Display = 'Updater'; Program = '%LOCALAPPDATA%\Fabrikam\updater.exe'; Signer = 'Fabrikam Inc.'; Origin = 'UserInstalled'; Findings = @('user-writable-program') }
        & $add @{ Id = (& $n 'UnsignedTool'); Display = 'Tool'; Program = 'C:\Tools\tool.exe'; Signer = '-'; Origin = 'UserInstalled'; Confidence = 'Medium'; Findings = @('unsigned-program') }
        foreach ($i in 1..30) { & $add @{ Id = (& $n "OrphanApp$i"); Display = "Old app $i"; Program = "C:\Program Files\OldApp$i\old.exe"; Missing = $true; Enabled = ($i % 2 -eq 0); Description = 'Old app'; Origin = 'UserInstalled'; Confidence = 'Medium'; Bloated = $true; Findings = @('orphaned-program') } }
        & $add @{ Id = (& $n 'GameOutboundBlock'); Display = 'Block game updates'; Program = 'C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe'; Dir = 'Outbound'; Action = 'Block'; Signer = 'Valve Corp.'; Origin = 'UserInstalled' }
        # Custom Rules: iG Windows Tuner rules, manual port rules, risky custom rules, duplicates.
        foreach ($exe in 'mshta', 'wscript', 'cscript', 'regsvr32', 'certutil') { & $add @{ Id = (& $n "iGWindowsTuner-Block-Out-$exe-x64"); Display = "iG Windows Tuner - Block outbound $exe.exe"; Program = "C:\WINDOWS\System32\$exe.exe"; Dir = 'Outbound'; Action = 'Block'; Origin = 'CustomRules' } }
        & $add @{ Id = (& $n '{00000000-0000-0000-0003-000000000001}'); Display = 'My game server'; Protocol = 'UDP'; LocalPort = '27015'; Profile = 'Private'; Remote = 'LocalSubnet'; Description = 'Dedicated server'; Origin = 'CustomRules'; Confidence = 'Low' }
        & $add @{ Id = (& $n '{00000000-0000-0000-0003-000000000002}'); Display = 'Open everything'; NoDesc = $true; Origin = 'CustomRules'; Confidence = 'Low'; Findings = @('inbound-wide-open', 'no-description') }
        & $add @{ Id = (& $n '{00000000-0000-0000-0003-000000000003}'); Display = 'Range'; Protocol = 'TCP'; LocalPort = '1000-9000'; Profile = 'Private'; Description = 'Lab'; Remote = '10.0.0.0/8'; Origin = 'CustomRules'; Confidence = 'Low'; Findings = @('broad-port-range') }
        & $add @{ Id = (& $n '{00000000-0000-0000-0003-000000000004}'); Display = 'PowerShell out'; Program = 'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe'; Dir = 'Outbound'; Description = 'Admin script'; Origin = 'CustomRules'; Confidence = 'Medium'; Findings = @('script-host-allow') }
        & $add @{ Id = (& $n '{00000000-0000-0000-0003-000000000005}'); Display = 'P2P edge'; Program = 'C:\Program Files\Peer\peer.exe'; Edge = 'Allow'; Protocol = 'UDP'; LocalPort = '50000'; Profile = 'Private'; Signer = 'Peer Ltd.'; Description = 'Peer app'; Origin = 'UserInstalled'; Confidence = 'Medium'; Findings = @('edge-traversal') }
        foreach ($k in 1, 2) { & $add @{ Id = (& $n "DupRule$k"); Display = 'Duplicate'; Program = 'C:\Program Files\Dup\dup.exe'; Protocol = 'TCP'; LocalPort = '4000'; Profile = 'Private'; Signer = 'Dup Inc.'; Description = 'dup'; Origin = 'UserInstalled'; Findings = @('duplicate') } }
        # Group Policy and MDM rules: classified by content, locked.
        & $add @{ Id = (& $n 'GPO-Corp-Block'); Display = 'Corp block'; Action = 'Block'; Protocol = 'TCP'; LocalPort = '23'; StoreType = 'GroupPolicy'; StoreSource = 'corp.example'; Description = 'Policy'; Origin = 'CustomRules'; Confidence = 'Low'; Locked = $true }
        & $add @{ Id = (& $n 'GPO-Raw-Allow'); Display = 'Corp allow'; Protocol = 'TCP'; LocalPort = '8443'; Profile = 'Domain'; Remote = '10.0.0.0/8'; StoreType = 'GroupPolicy'; Raw = $true; Description = 'Policy'; Origin = 'CustomRules'; Confidence = 'Low'; Locked = $true }
        # Filler: more Windows rules in the knowledge base (disabled, harmless) to reach 1,000+.
        foreach ($i in 1..600) { & $add @{ Id = (& $n "WMPNSS-Var$i-In"); Group = '@FirewallAPI.dll,-31252'; Profile = 'Private'; Protocol = 'TCP'; LocalPort = '10243'; Remote = 'LocalSubnet'; Enabled = $false; Origin = 'WindowsConnections' } }
    }
    [pscustomobject]@{ Rules = $rules.ToArray(); App = $app.ToArray(); Port = $port.ToArray(); Addr = $addr.ToArray(); Svc = $svc.ToArray(); Ift = $ift.ToArray(); Expect = $expect; Missing = $missing; Signatures = $sigs }
}
