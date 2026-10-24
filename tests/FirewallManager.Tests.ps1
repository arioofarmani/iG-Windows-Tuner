BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    function New-FwRule {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test data builder.')]
        param([string]$Name, [string]$Display, [string]$Group = '', [string]$Enabled = 'True', [string]$Direction = 'Inbound', [string]$Action = 'Allow', [string]$Profiles = 'Any', [string]$StoreType = 'Local', [string]$Owner = '')
        [pscustomobject]@{ InstanceID = $Name; Name = $Name; DisplayName = $Display; DisplayGroup = $Group; Group = $Group; Enabled = $Enabled; Direction = $Direction; Action = $Action; Profile = $Profiless
            PolicyStoreSourceType = $StoreType; PolicyStoreSource = $(if ($StoreType -eq 'GroupPolicy') { 'contoso.test GPO' } else { 'PersistentStore' }); Owner = $Owner; EdgeTraversalPolicy = 'Block'; Description = "$Display rule" }
    }
    # A small in-memory firewall for the change tests: name -> definition.
    function Reset-FwStore {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test data builder.')]
        param()
        $script:FwStore = @{
            'App-Game-In' = @{ name = 'App-Game-In'; displayName = 'Game server'; description = ''; group = ''; enabled = $true; direction = 'Inbound'; action = 'Allow'; profile = 'Private'; program = 'C:\Games\game.exe'; protocol = 'UDP'; localPort = @('27015'); remotePort = @(); localAddress = @(); remoteAddress = @(); service = 'Any'; package = ''; owner = ''; edgeTraversal = 'Block'; interfaceType = 'Any' }
            'CoreNet-DHCP-In' = @{ name = 'CoreNet-DHCP-In'; displayName = 'Core Networking - DHCP'; description = ''; group = '@FirewallAPI.dll,-25000'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profile = 'Any'; program = 'System'; protocol = 'UDP'; localPort = @('68'); remotePort = @('67'); localAddress = @(); remoteAddress = @(); service = 'Dhcp'; package = ''; owner = ''; edgeTraversal = 'Block'; interfaceType = 'Any' }
            'Win-Cast-In' = @{ name = 'Win-Cast-In'; displayName = 'Cast to Device'; description = ''; group = '@FirewallAPI.dll,-36001'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profile = 'Private'; program = 'System'; protocol = 'TCP'; localPort = @('10246'); remotePort = @(); localAddress = @(); remoteAddress = @(); service = 'Any'; package = ''; owner = ''; edgeTraversal = 'Block'; interfaceType = 'Any' }
        }
    }
    function Get-FwRows {
        @(foreach ($d in $script:FwStore.Values) {
                $win = [string]$d.group -like '@*'
                $grp = $(if ($d.name -like 'CoreNet*') { 'Core Networking' } elseif ($win) { 'Cast to Device functionality' } else { [string]$d.group })
                [pscustomobject]@{ Key = $d.name; Name = $d.name; DisplayName = $d.displayName; Group = $grp; Enabled = [bool]$d.enabled; Direction = $d.direction; Action = $d.action; Profiles = $d.profile
                    ProfileList = @($d.profile -split ',\s*'); Program = $d.program; LocalPort = (@($d.localPort) -join ', '); Source = $(if ($d.name -like 'iGWindowsTuner-*') { 'Owned' } elseif ($win) { 'Windows' } else { 'ThirdParty' }); Locked = $false; LockReason = ''; Risks = @() }
            })
    }
}

Describe 'Firewall Manager: inventory join and risk flags' {
    BeforeAll {
        $script:Rules = @(
            New-FwRule 'Game-In' 'Game (inbound)' -Profiles 'Private, Public'
            New-FwRule 'Game-In-2' 'Game (inbound) again' -Profiles 'Private, Public'
            New-FwRule 'Open-All' 'Open everything' -Profiles 'Public'
            New-FwRule 'Win-Cast' '@{Microsoft.Cast}' -Group '@FirewallAPI.dll,-36001' -Enabled 'False' -Profiles 'Private'
            New-FwRule 'Gpo-Block' 'Corp block' -Direction 'Outbound' -Action 'Block' -StoreType 'GroupPolicy'
            New-FwRule 'Store-App' 'Store app' -Owner 'S-1-15-2-1' -Direction 'Outbound'
            New-FwRule 'iGWindowsTuner-User-abc' 'My rule' -Group 'iG Windows Tuner' -Direction 'Outbound' -Action 'Block'
            New-FwRule 'Temp-App' 'Downloaded tool' -Direction 'Outbound'
        )
        $script:App = @(
            [pscustomobject]@{ InstanceID = 'Game-In'; Program = 'C:\Games\game.exe'; Package = '' }
            [pscustomobject]@{ InstanceID = 'Game-In-2'; Program = 'C:\Games\game.exe'; Package = '' }
            [pscustomobject]@{ InstanceID = 'Open-All'; Program = 'Any'; Package = '' }
            [pscustomobject]@{ InstanceID = 'Store-App'; Program = 'Any'; Package = 'S-1-15-2-1' }
            [pscustomobject]@{ InstanceID = 'Temp-App'; Program = 'C:\Users\Player\Downloads\tool.exe'; Package = '' }
        )
        $script:Port = @(
            [pscustomobject]@{ InstanceID = 'Game-In'; Protocol = 'UDP'; LocalPort = @('27015', '27016'); RemotePort = 'Any' }
            [pscustomobject]@{ InstanceID = 'Game-In-2'; Protocol = 'UDP'; LocalPort = @('27015', '27016'); RemotePort = 'Any' }
            [pscustomobject]@{ InstanceID = 'Open-All'; Protocol = 'Any'; LocalPort = 'Any'; RemotePort = 'Any' }
        )
        $script:Addr = @([pscustomobject]@{ InstanceID = 'Open-All'; LocalAddress = 'Any'; RemoteAddress = 'Any' }, [pscustomobject]@{ InstanceID = 'Game-In'; LocalAddress = 'Any'; RemoteAddress = @('192.0.2.0/24') }, [pscustomobject]@{ InstanceID = 'Game-In-2'; LocalAddress = 'Any'; RemoteAddress = @('192.0.2.0/24') })
    }

    It 'joins every filter to its rule on InstanceID' {
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:Rules; A = $script:App; P = $script:Port; D = $script:Addr } {
            param($R, $A, $P, $D)
            $rows = Join-IgwtFirewallData -Rules $R -ApplicationFilters $A -PortFilters $P -AddressFilters $D -PathExists { param($x) $x -like 'C:\Games\*' }
            $rows.Count | Should -Be 8
            $g = $rows | Where-Object Name -EQ 'Game-In'
            $g.Program | Should -Be 'C:\Games\game.exe'
            $g.Protocol | Should -Be 'UDP'
            $g.LocalPort | Should -Be '27015, 27016'
            $g.RemoteAddress | Should -Be '192.0.2.0/24'
            $g.ProgramExists | Should -Be 'Yes'
            ($rows | Where-Object Name -EQ 'Win-Cast').Program | Should -Be 'Any'
        }
    }

    It 'reads raw CIM rules and filters (numbers, no Name, AppPath) like named ones' {
        # Seen in the elevated GUI: without the NetSecurity type data every rule showed Disabled, 2/4,
        # Program Any, and different programs counted as 422 duplicates.
        InModuleScope iGWindowsTuner {
            $raw = @(
                [pscustomobject]@{ InstanceID = 'iGWindowsTuner-Block-Out-mshta-x64'; Name = ''; DisplayName = 'iG Windows Tuner - Block outbound mshta.exe (System32)'; Enabled = 1; Direction = 2; Action = 4; Profile = $null; Profiles = 0; EdgeTraversalPolicy = 0; PolicyStoreSourceType = 1; DisplayGroup = ''; Owner = '' }
                [pscustomobject]@{ InstanceID = 'App-1'; Name = ''; DisplayName = 'Game'; Enabled = 2; Direction = 1; Action = 2; Profile = $null; Profiles = 6; EdgeTraversalPolicy = 1; PolicyStoreSourceType = 1; DisplayGroup = ''; Owner = '' }
                [pscustomobject]@{ InstanceID = 'App-2'; Name = ''; DisplayName = 'Game'; Enabled = 2; Direction = 1; Action = 2; Profile = $null; Profiles = 6; EdgeTraversalPolicy = 1; PolicyStoreSourceType = 1; DisplayGroup = ''; Owner = '' }
                [pscustomobject]@{ InstanceID = 'Gpo-1'; Name = ''; DisplayName = 'Corp'; Enabled = 1; Direction = 1; Action = 4; Profile = $null; Profiles = 4; EdgeTraversalPolicy = 0; PolicyStoreSourceType = 2; DisplayGroup = ''; Owner = '' }
            )
            $app = @(
                [pscustomobject]@{ InstanceID = 'iGWindowsTuner-Block-Out-mshta-x64'; AppPath = 'C:\WINDOWS\System32\mshta.exe'; Package = '' }
                [pscustomobject]@{ InstanceID = 'App-1'; AppPath = 'C:\Games\a.exe'; Package = '' }
                [pscustomobject]@{ InstanceID = 'App-2'; AppPath = 'C:\Games\b.exe'; Package = '' }
            )
            $svc = @([pscustomobject]@{ InstanceID = 'Gpo-1'; ServiceName = 'fdphost' })
            $ift = @([pscustomobject]@{ InstanceID = 'App-1'; InterfaceType = 3 })
            $rows = Join-IgwtFirewallData -Rules $raw -ApplicationFilters $app -ServiceFilters $svc -InterfaceFilters $ift -PathExists { $true }
            $m = $rows | Where-Object Name -EQ 'iGWindowsTuner-Block-Out-mshta-x64'
            $m.Enabled | Should -BeTrue; $m.Direction | Should -Be 'Outbound'; $m.DirectionText | Should -Be 'OUT'; $m.Action | Should -Be 'Block'
            $m.Profiles | Should -Be 'Any'; $m.EdgeTraversal | Should -Be 'Block'; $m.Program | Should -Be 'C:\WINDOWS\System32\mshta.exe'; $m.Source | Should -Be 'Owned'
            $a1 = $rows | Where-Object Name -EQ 'App-1'
            $a1.Enabled | Should -BeFalse; $a1.DirectionText | Should -Be 'IN'; $a1.Profiles | Should -Be 'Private, Public'; $a1.InterfaceType | Should -Be 'Wired, Wireless'
            @($rows | Where-Object { $_.Risks -contains 'Duplicate' }).Count | Should -Be 0 -Because 'different programs are different rules'
            $g = $rows | Where-Object Name -EQ 'Gpo-1'
            $g.Source | Should -Be 'GroupPolicy'; $g.Locked | Should -BeTrue; $g.Service | Should -Be 'fdphost'
            Get-IgwtFirewallDirectionText -Direction 'Inbound', 'Outbound' | Should -Be 'IN/OUT'
        }
    }

    It 'classifies the source and locks Group Policy rules' {
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:Rules; A = $script:App } {
            param($R, $A)
            $rows = Join-IgwtFirewallData -Rules $R -ApplicationFilters $A -PathExists { $true }
            $src = @{}; foreach ($r in $rows) { $src[$r.Name] = $r.Source }
            $src['Win-Cast'] | Should -Be 'Windows'
            $src['Gpo-Block'] | Should -Be 'GroupPolicy'
            $src['Store-App'] | Should -Be 'StoreApp'
            $src['iGWindowsTuner-User-abc'] | Should -Be 'Owned'
            $src['Game-In'] | Should -Be 'ThirdParty'
            $gpo = $rows | Where-Object Name -EQ 'Gpo-Block'
            $gpo.Locked | Should -BeTrue
            $gpo.LockReason | Should -Match 'Group Policy'
        }
    }

    It 'flags inbound allow on Public, broad, missing, user-writable, duplicate and disabled Windows rules' {
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:Rules; A = $script:App; P = $script:Port; D = $script:Addr } {
            param($R, $A, $P, $D)
            $rows = Join-IgwtFirewallData -Rules $R -ApplicationFilters $A -PortFilters $P -AddressFilters $D -PathExists { param($x) $x -like 'C:\Games\*' }
            $risk = @{}; foreach ($r in $rows) { $risk[$r.Name] = @($r.Risks) }
            $risk['Game-In'] | Should -Contain 'InboundPublic'
            $risk['Game-In'] | Should -Contain 'Duplicate'
            $risk['Game-In-2'] | Should -Contain 'Duplicate'
            $risk['Open-All'] | Should -Contain 'Broad'
            $risk['Open-All'] | Should -Contain 'InboundPublic'
            $risk['Temp-App'] | Should -Contain 'UserWritable'
            $risk['Temp-App'] | Should -Contain 'ProgramMissing'
            $risk['Win-Cast'] | Should -Contain 'DisabledWindows'
            $risk['Gpo-Block'] | Should -Not -Contain 'InboundPublic'
            ($rows | Where-Object Name -EQ 'Game-In').RiskText | Should -Match 'Inbound allow on Public'
        }
    }

    It 'loads the inventory with one bulk query per class and reports partial data without admin rights' {
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule { $script:Rules } -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallApplicationFilter { $script:App }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallPortFilter { throw 'Access is denied.' }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallAddressFilter { throw 'Access is denied.' }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallServiceFilter { @() }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallInterfaceTypeFilter { throw 'Access is denied.' }
        # Windows Service Hardening stores: one rule, tagged with its store and locked.
        $wsh = [pscustomobject]@{ Name = 'Svc-1'; InstanceID = 'Svc-1'; DisplayName = 'Block any inbound traffic to Svc'; Group = ''; DisplayGroup = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'; Profile = 'Any'; EdgeTraversalPolicy = 'Block'; Owner = ''; PolicyStoreSource = 'No Policy Store (Invalid)'; PolicyStoreSourceType = 'None'; Description = '' }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule { $wsh } -ParameterFilter { $PolicyStore -eq 'StaticServiceStore' }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule { @() } -ParameterFilter { $PolicyStore -eq 'ConfigurableServiceStore' }
        $inv = Get-IgwtFirewallInventory
        $inv.Count | Should -Be 9
        $inv.Partial | Should -BeTrue
        $inv.Notes -join ' ' | Should -Match 'administrator'
        $inv.Timing.Rules | Should -Not -BeNullOrEmpty
        $s = $inv.Rules | Where-Object Name -EQ 'Svc-1'
        $s.Store | Should -Be 'StaticServiceStore'
        $s.Locked | Should -BeTrue
        Should -Invoke -ModuleName iGWindowsTuner Get-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
        Should -Invoke -ModuleName iGWindowsTuner Get-NetFirewallApplicationFilter -Times 1 -Exactly -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
        # -NoServiceHardening reads the active store only.
        (Get-IgwtFirewallInventory -NoServiceHardening).Count | Should -Be 8
    }
}

Describe 'Firewall Manager: validation' {
    It 'validates ports, addresses and rule settings' {
        InModuleScope iGWindowsTuner {
            Test-IgwtFirewallPortList -Value '80, 443, 27015-27030, RPC' | Should -BeNullOrEmpty
            Test-IgwtFirewallPortList -Value '0' | Should -Not -BeNullOrEmpty
            Test-IgwtFirewallPortList -Value '70000' | Should -Not -BeNullOrEmpty
            Test-IgwtFirewallPortList -Value '30-20' | Should -Not -BeNullOrEmpty
            Test-IgwtFirewallPortList -Value 'http' | Should -Not -BeNullOrEmpty
            Test-IgwtFirewallAddressList -Value '192.0.2.10, 198.51.100.0/24, 203.0.113.1-203.0.113.9, LocalSubnet, 2001:db8::/32' | Should -BeNullOrEmpty
            Test-IgwtFirewallAddressList -Value '192.0.2.0/40' | Should -Not -BeNullOrEmpty
            Test-IgwtFirewallAddressList -Value 'example.test' | Should -Not -BeNullOrEmpty
            @(Test-IgwtFirewallRuleSettings -Settings @{ DisplayName = 'x'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; LocalPort = '27015'; Profiles = @('Private'); Program = 'C:\Games\g.exe' } -New).Count | Should -Be 0
            @(Test-IgwtFirewallRuleSettings -Settings @{ DisplayName = ''; Direction = 'Sideways' } -New).Count | Should -Be 2
            (Test-IgwtFirewallRuleSettings -Settings @{ Protocol = 'Any'; LocalPort = '80' }) -join ' ' | Should -Match 'TCP or UDP'
            (Test-IgwtFirewallRuleSettings -Settings @{ Program = 'game.exe' }) -join ' ' | Should -Match 'full path'
            (Test-IgwtFirewallRuleSettings -Settings @{ Profiles = @() }) -join ' ' | Should -Match 'at least one profile'
        }
    }

    It 'locks Group Policy rules, keeps Windows rules to enable and disable, protects Core Networking and remote access' {
        InModuleScope iGWindowsTuner {
            $win = [pscustomobject]@{ Name = 'w'; Source = 'Windows'; Locked = $false; Group = 'Cast to Device functionality'; LocalPort = '10246' }
            $core = [pscustomobject]@{ Name = 'c'; Source = 'Windows'; Locked = $false; Group = 'Core Networking'; LocalPort = '68' }
            $gpo = [pscustomobject]@{ Name = 'g'; Source = 'GroupPolicy'; Locked = $true; LockReason = 'Set by Group Policy'; Group = ''; LocalPort = '' }
            $app = [pscustomobject]@{ Name = 'a'; Source = 'ThirdParty'; Locked = $false; Group = ''; LocalPort = '27015' }
            $rdp = [pscustomobject]@{ Name = 'r'; Source = 'Windows'; Locked = $false; Group = 'Remote Desktop'; LocalPort = '3389' }
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule $win | Should -BeNullOrEmpty
            Get-IgwtFirewallChangeBlock -Operation Edit -Rule $win | Should -Match 'not edited'
            Get-IgwtFirewallChangeBlock -Operation Delete -Rule $win | Should -Match 'never deleted'
            Get-IgwtFirewallChangeBlock -Operation SetAction -Rule $win -Settings @{ Action = 'Block' } | Should -Not -BeNullOrEmpty
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule $core | Should -Match 'Core Networking'
            Get-IgwtFirewallChangeBlock -Operation Enable -Rule $gpo | Should -Match 'Group Policy'
            Get-IgwtFirewallChangeBlock -Operation Delete -Rule $app | Should -BeNullOrEmpty
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule $rdp -RemoteSession $true | Should -Match 'remote session'
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule $rdp -RemoteSession $false | Should -BeNullOrEmpty
        }
    }

    It 'plans changes with warnings and asks for a confirm timer in a remote session' {
        InModuleScope iGWindowsTuner {
            $app = [pscustomobject]@{ Name = 'a'; DisplayName = 'A'; Source = 'ThirdParty'; Locked = $false; Group = ''; LocalPort = ''; Enabled = $true; Direction = 'Inbound'; Action = 'Allow' }
            $plan = Get-IgwtFirewallChangePlan -Operation SetAction -Rules @($app) -Settings @{ Action = 'Block' } -RemoteSession $false
            $plan.Count | Should -Be 1
            $plan.Warnings -join ' ' | Should -Match 'stop the program'
            $plan.NeedsConfirmTimer | Should -BeFalse
            (Get-IgwtFirewallChangePlan -Operation Enable -Rules @($app) -RemoteSession $false).Count | Should -Be 0
            (Get-IgwtFirewallChangePlan -Operation Disable -Rules @($app) -RemoteSession $true).NeedsConfirmTimer | Should -BeTrue
            $new = Get-IgwtFirewallChangePlan -Operation New -Settings @{ DisplayName = 'Block all in'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'Any'; Profiles = @('Any') } -RemoteSession $true
            $new.Items[0].Allowed | Should -BeFalse
            $pub = Get-IgwtFirewallChangePlan -Operation New -Settings @{ DisplayName = 'Game'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; LocalPort = '27015'; Profiles = @('Public'); Program = 'C:\Games\g.exe' } -RemoteSession $false
            $pub.Items[0].Allowed | Should -BeTrue
            $pub.Warnings -join ' ' | Should -Match 'public networks'
        }
    }

    It 'never turns the firewall off or allows inbound traffic by default' {
        InModuleScope iGWindowsTuner {
            Get-IgwtFirewallProfileChangeBlock -Setting Enabled -Value $false | Should -Match 'never turns the firewall off'
            Get-IgwtFirewallProfileChangeBlock -Setting Enabled -Value $true | Should -BeNullOrEmpty
            Get-IgwtFirewallProfileChangeBlock -Setting DefaultInboundAction -Value 'Allow' | Should -Not -BeNullOrEmpty
            Get-IgwtFirewallProfileChangeBlock -Setting DefaultOutboundAction -Value 'Block' | Should -BeNullOrEmpty
            Get-IgwtFirewallProfileChangeBlock -Setting LogMaxKB -Value 100 | Should -Not -BeNullOrEmpty
        }
        { Set-IgwtFirewallProfileSetting -Profile Public -Setting Enabled -Value $false } | Should -Throw '*never turns the firewall off*'
    }

    It 'builds New-NetFirewallRule parameters without ports for protocols that have none' {
        InModuleScope iGWindowsTuner {
            $p = ConvertTo-IgwtFirewallRuleParameters -Definition @{ name = 'n'; displayName = 'd'; direction = 'Outbound'; action = 'Block'; enabled = $true; profile = 'Private, Public'; protocol = 'Any'; localPort = @('80'); remoteAddress = @('192.0.2.1'); program = 'C:\x.exe' }
            $p.ContainsKey('LocalPort') | Should -BeFalse
            $p.RemoteAddress | Should -Be @('192.0.2.1')
            $p.Profile | Should -Be @('Private', 'Public')
            $p.Enabled | Should -Be 'True'
            $s = ConvertTo-IgwtFirewallRuleParameters -Definition @{ name = 'n'; displayName = 'New name'; direction = 'Inbound'; action = 'Allow'; enabled = $false; protocol = 'TCP'; localPort = @('443') } -ForSet
            $s.ContainsKey('Name') | Should -BeFalse
            $s.ContainsKey('Direction') | Should -BeFalse
            $s.NewDisplayName | Should -Be 'New name'
            $s.LocalPort | Should -Be @('443')
        }
    }
}

Describe 'Firewall Manager: changes with snapshots (mocked firewall)' {
    BeforeEach {
        Reset-FwStore
        Mock -ModuleName iGWindowsTuner Test-IgwtRemoteSession { $false }
        Mock -ModuleName iGWindowsTuner Get-IgwtFirewallInventory { [pscustomobject]@{ Rules = (Get-FwRows); Count = $script:FwStore.Count } }
        Mock -ModuleName iGWindowsTuner Get-IgwtFirewallRuleDefinition { $d = $script:FwStore[$Name]; $c = [ordered]@{}; foreach ($k in $d.Keys) { $c[$k] = $d[$k] }; $c }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule { if ($script:FwStore.ContainsKey(@($Name)[0])) { [pscustomobject]@{ Name = @($Name)[0] } } } -ParameterFilter { $Name }
        Mock -ModuleName iGWindowsTuner Enable-NetFirewallRule { foreach ($n in $Name) { $script:FwStore[$n].enabled = $true } }
        Mock -ModuleName iGWindowsTuner Disable-NetFirewallRule { foreach ($n in $Name) { $script:FwStore[$n].enabled = $false } }
        Mock -ModuleName iGWindowsTuner Remove-NetFirewallRule { foreach ($n in $Name) { $script:FwStore.Remove($n) } }
        Mock -ModuleName iGWindowsTuner Set-NetFirewallRule {
            $d = $script:FwStore[@($Name)[0]]
            if ($PesterBoundParameters.ContainsKey('Action')) { $d.action = [string]$Action }
            if ($PesterBoundParameters.ContainsKey('Enabled')) { $d.enabled = ([string]$Enabled -eq 'True') }
            if ($PesterBoundParameters.ContainsKey('Profile')) { $d.profile = (@($Profile) -join ', ') }
            if ($PesterBoundParameters.ContainsKey('NewDisplayName')) { $d.displayName = $NewDisplayName }
            if ($PesterBoundParameters.ContainsKey('LocalPort')) { $d.localPort = @($LocalPort) }
        }
        Mock -ModuleName iGWindowsTuner New-NetFirewallRule {
            $script:FwStore[$Name] = @{ name = $Name; displayName = $DisplayName; description = ''; group = [string]$Group; enabled = ([string]$Enabled -eq 'True'); direction = [string]$Direction; action = [string]$Action
                profile = (@($Profile) -join ', '); program = [string]$Program; protocol = [string]$Protocol; localPort = @($LocalPort); remotePort = @($RemotePort); localAddress = @($LocalAddress); remoteAddress = @($RemoteAddress); service = 'Any'; package = ''; owner = ''; edgeTraversal = 'Block'; interfaceType = 'Any' }
        }
    }

    It 'disables rules in bulk with a Firewall snapshot and reverts them' {
        $r = Invoke-IgwtFirewallChange -Operation Disable -Name 'App-Game-In', 'Win-Cast-In'
        $r.Changes | Should -Be 2
        $script:FwStore['App-Game-In'].enabled | Should -BeFalse
        $script:FwStore['Win-Cast-In'].enabled | Should -BeFalse
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.operation | Should -Be 'Firewall'
        $doc.entries.Count | Should -Be 2
        $doc.entries[0].actions[0].definition.enabled | Should -BeTrue
        $rev = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        @($rev.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 2
        $script:FwStore['App-Game-In'].enabled | Should -BeTrue
        $script:FwStore['Win-Cast-In'].enabled | Should -BeTrue
    }

    It 'refuses Core Networking and Windows edits, and still applies the allowed part' {
        $r = Invoke-IgwtFirewallChange -Operation Disable -Name 'CoreNet-DHCP-In', 'App-Game-In'
        $r.Changes | Should -Be 1
        ($r.Results | Where-Object Result -EQ 'Refused').Message | Should -Match 'Core Networking'
        $script:FwStore['CoreNet-DHCP-In'].enabled | Should -BeTrue
        $e = Invoke-IgwtFirewallChange -Operation Edit -Name 'Win-Cast-In' -Settings @{ Profiles = @('Public') }
        $e.Changes | Should -Be 0
        $e.Snapshot | Should -BeNullOrEmpty
    }

    It 'changes Allow to Block and edits ports, and reverts both' {
        $a = Invoke-IgwtFirewallChange -Operation SetAction -Name 'App-Game-In' -Settings @{ Action = 'Block' }
        $script:FwStore['App-Game-In'].action | Should -Be 'Block'
        $e = Invoke-IgwtFirewallChange -Operation Edit -Name 'App-Game-In' -Settings @{ Protocol = 'UDP'; LocalPort = '27015-27030'; Profiles = @('Private') }
        $script:FwStore['App-Game-In'].localPort | Should -Be @('27015-27030')
        $null = Invoke-IgwtRevert -SnapshotPath $e.Snapshot
        $script:FwStore['App-Game-In'].localPort | Should -Be @('27015')
        $null = Invoke-IgwtRevert -SnapshotPath $a.Snapshot
        $script:FwStore['App-Game-In'].action | Should -Be 'Allow'
    }

    It 'creates and duplicates rules as iG Windows Tuner rules; revert removes them' {
        $n = Invoke-IgwtFirewallChange -Operation New -Settings @{ DisplayName = 'My game'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; LocalPort = '3074'; Profiles = @('Private'); Program = 'C:\Games\g.exe' }
        $n.Changes | Should -Be 1
        $created = @($script:FwStore.Keys | Where-Object { $_ -like 'iGWindowsTuner-User-*' })
        $created.Count | Should -Be 1
        $script:FwStore[$created[0]].group | Should -Be 'iG Windows Tuner'
        $d = Invoke-IgwtFirewallChange -Operation Duplicate -Name 'App-Game-In'
        @($script:FwStore.Keys | Where-Object { $_ -like 'iGWindowsTuner-User-*' }).Count | Should -Be 2
        $null = Invoke-IgwtRevert -SnapshotPath $d.Snapshot
        $null = Invoke-IgwtRevert -SnapshotPath $n.Snapshot
        @($script:FwStore.Keys | Where-Object { $_ -like 'iGWindowsTuner-User-*' }).Count | Should -Be 0
    }

    It 'deletes only non-Windows rules and recreates them on revert' {
        $w = Invoke-IgwtFirewallChange -Operation Delete -Name 'Win-Cast-In'
        $w.Changes | Should -Be 0
        $script:FwStore.ContainsKey('Win-Cast-In') | Should -BeTrue
        $r = Invoke-IgwtFirewallChange -Operation Delete -Name 'App-Game-In'
        $script:FwStore.ContainsKey('App-Game-In') | Should -BeFalse
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        $script:FwStore.ContainsKey('App-Game-In') | Should -BeTrue
        $script:FwStore['App-Game-In'].program | Should -Be 'C:\Games\game.exe'
        $script:FwStore['App-Game-In'].localPort | Should -Be @('27015')
    }

    It 'refuses changes in a remote session unless allowed, and never touches remote-access rules then' {
        Mock -ModuleName iGWindowsTuner Test-IgwtRemoteSession { $true }
        { Invoke-IgwtFirewallChange -Operation Disable -Name 'App-Game-In' } | Should -Throw '*remote session*'
        $r = Invoke-IgwtFirewallChange -Operation Disable -Name 'App-Game-In' -AllowRemoteSession
        $r.Changes | Should -Be 1
        $r.RemoteSession | Should -BeTrue
    }

    It 'is blocked in read-only mode' {
        try {
            Set-IgwtEnvironment -ReadOnly
            { Invoke-IgwtFirewallChange -Operation Disable -Name 'App-Game-In' } | Should -Throw 'Read-only mode:*'
            $script:FwStore['App-Game-In'].enabled | Should -BeTrue
        } finally { Remove-Item Env:\IGWT_READONLY -ErrorAction SilentlyContinue; InModuleScope iGWindowsTuner { $script:IgwtSettings.ReadOnly = $false } }
    }
}

Describe 'Firewall Manager: export and import plan' {
    It 'exports JSON that the import plan reads back, skipping Windows rules' {
        $rows = @(
            [pscustomobject]@{ Name = 'App-1'; DisplayName = 'App one'; Description = ''; Group = ''; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profiles = 'Private'; Program = 'C:\Games\a.exe'; Service = 'Any'; Package = ''; Protocol = 'UDP'; LocalPort = '27015'; RemotePort = 'Any'; LocalAddress = 'Any'; RemoteAddress = 'Any'; InterfaceType = 'Any'; EdgeTraversal = 'Block'; Source = 'ThirdParty'; Locked = $false; ProgramExists = 'Yes'; RiskText = '' }
            [pscustomobject]@{ Name = 'Win-1'; DisplayName = 'Windows one'; Description = ''; Group = '@FirewallAPI.dll,-1'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profiles = 'Any'; Program = 'System'; Service = 'Any'; Package = ''; Protocol = 'TCP'; LocalPort = '445'; RemotePort = 'Any'; LocalAddress = 'Any'; RemoteAddress = 'Any'; InterfaceType = 'Any'; EdgeTraversal = 'Block'; Source = 'Windows'; Locked = $false; ProgramExists = ''; RiskText = '' }
        )
        Mock -ModuleName iGWindowsTuner Get-IgwtFirewallInventory { [pscustomobject]@{ Rules = $rows } }
        $path = Join-Path $TestDrive 'rules.json'
        $null = Export-IgwtFirewallRules -Path $path
        (Get-Content $path -Raw | ConvertFrom-Json).rules.Count | Should -Be 2
        $plan = Get-IgwtFirewallImportPlan -Path $path
        $plan.Same | Should -Be 1
        $plan.Skipped | Should -Be 1
        $rows[0].Action = 'Block'
        $plan2 = Get-IgwtFirewallImportPlan -Path $path
        $plan2.Changed | Should -Be 1
        ($plan2.Items | Where-Object Status -EQ 'Changed').Detail | Should -Match 'Action: Block -> Allow'
        $csv = Join-Path $TestDrive 'rules.csv'
        $null = Export-IgwtFirewallRules -Path $csv -Format Csv
        @(Import-Csv $csv).Count | Should -Be 2
    }
}
