# 3.9 stage B: every revert goes through the change journal (B1).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe '3.9 B1: Invoke-IgwtRevert runs through the change journal' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            foreach ($d in @((Get-IgwtJournalFolder), (Get-IgwtDataPath -Kind Backups))) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force } }
            $script:IgwtJournal = $null
        }
    }
    It 'reverts by id through a journal revert session and records the revert for staging' {
        InModuleScope iGWindowsTuner {
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 1
            $r = Invoke-IgwtRevert -Id 'gfx.game-mode'
            @($r.Results)[0].Result | Should -Be 'Reverted'
            $r.Session | Should -Not -BeNullOrEmpty -Because 'it ran as a journal session'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
            Find-IgwtLatestSnapshotEntry -TweakId 'gfx.game-mode' | Should -BeNullOrEmpty -Because 'the revert record makes it no longer revertable'
        }
    }
    It 'does not overwrite a value changed since iG set it, and says where to decide' {
        InModuleScope iGWindowsTuner {
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 7
            $r = Invoke-IgwtRevert -Id 'gfx.game-mode'
            @($r.Results)[0].Result | Should -Be 'Failed'
            @($r.Results)[0].Message | Should -BeLike '*Change journal*'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 7 -Because 'nothing is overwritten'
        }
    }
    It 'reverts by the apply snapshot path (the GUI Revert buttons) through the journal' {
        InModuleScope iGWindowsTuner {
            $a = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            $r = Invoke-IgwtRevert -SnapshotPath $a.Snapshot
            $r.Session | Should -Not -BeNullOrEmpty
            @($r.Results)[0].Result | Should -Be 'Reverted'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
        }
    }
}

Describe '3.9 B2: module writes are read back' {
    It 'an ASR rule that keeps its old mode after the write is reported, not shown as applied' {
        InModuleScope iGWindowsTuner {
            Mock Set-IgwtAsrRule { }
            Mock Get-IgwtAsrRuleAction { 2 }
            Mock Clear-IgwtCache { }
            { Set-IgwtAsrRuleMode -RuleId '56a863a9-875e-4185-98a7-b882c64b5ce5' -Mode Block -Confirm:$false } | Should -Throw '*reads back as*'
            Mock Get-IgwtAsrRuleAction { 1 }
            { Set-IgwtAsrRuleMode -RuleId '56a863a9-875e-4185-98a7-b882c64b5ce5' -Mode Block -Confirm:$false } | Should -Not -Throw
        }
    }
}

Describe '3.9 B4: Explorer restart and pending feature states' {
    It 'TK-1: the icon-cache fix never starts Explorer from the elevated app' {
        InModuleScope iGWindowsTuner {
            Mock Get-Process { @() } -ParameterFilter { $Name -eq 'explorer' }
            Mock Start-Sleep { }
            Mock Start-Process { }
            $r = Invoke-IgwtFixStep -Step ([pscustomobject]@{ kind = 'explorer'; operation = 'start' }) -Stamp 'x'
            Should -Invoke Start-Process -Times 0 -Exactly
            $r.Output | Should -BeLike '*Run new task*'
        }
    }
    It 'OF-1: a feature waiting for the restart reads as its new state' {
        InModuleScope iGWindowsTuner {
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ FeatureName = 'SMB1Protocol'; State = 'DisablePending' } }
            Get-IgwtOptionalFeatureStateValue -Feature 'SMB1Protocol' | Should -Be 'Disabled'
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ FeatureName = 'SMB1Protocol'; State = 'EnablePending' } }
            Get-IgwtOptionalFeatureStateValue -Feature 'SMB1Protocol' | Should -Be 'Enabled'
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ FeatureName = 'SMB1Protocol'; State = 'DisabledWithPayloadRemoved' } }
            Get-IgwtOptionalFeatureStateValue -Feature 'SMB1Protocol' | Should -Be 'DisabledWithPayloadRemoved'
        }
    }
}

Describe '3.9 B4: protected services (review FW-4)' {
    It 'protects elevation, sign-in, Wi-Fi and gaming services on every path' {
        InModuleScope iGWindowsTuner {
            foreach ($n in 'Appinfo', 'NgcSvc', 'TokenBroker', 'wlidsvc', 'WlanSvc', 'Wcmsvc', 'iphlpsvc', 'GamingServices', 'XblAuthManager', 'ClipSVC') {
                Get-IgwtServiceProtection -Name $n | Should -Not -BeNullOrEmpty -Because $n
            }
            { Assert-IgwtServiceAllowed -Name 'Appinfo' } | Should -Throw '*protected*'
        }
    }
    It 'still lets you undo an earlier change to a service that is protected now' {
        InModuleScope iGWindowsTuner {
            { Set-IgwtServiceStartupType -Name 'WlanSvc' -StartupType 'Disabled' -WhatIf } | Should -Throw '*protected*' -Because 'a new change is refused'
            { Set-IgwtServiceStartupType -Name 'WlanSvc' -StartupType 'Automatic' -ForRestore -WhatIf } | Should -Not -Throw -Because 'the undo puts back what Windows had'
            { Set-IgwtServiceStartupType -Name 'WinDefend' -StartupType 'Disabled' -ForRestore -WhatIf } | Should -Throw '*protected*' -Because 'core security services were never changeable'
        }
    }
}

Describe '3.9 B4: the Recycle Bin is never overfilled by one clean (review CLN-1)' {
    It 'counts the whole run per drive and stops at half of the bin' {
        InModuleScope iGWindowsTuner {
            $script:IgwtRecycleSent = @{}
            Test-IgwtRecycleBudgetExceeded -Drive 'C:' -Bytes 400 -MaxBytes 1000 | Should -BeFalse
            $script:IgwtRecycleSent['C:'] = 400
            Test-IgwtRecycleBudgetExceeded -Drive 'C:' -Bytes 100 -MaxBytes 1000 | Should -BeFalse -Because 'exactly half is allowed'
            Test-IgwtRecycleBudgetExceeded -Drive 'C:' -Bytes 101 -MaxBytes 1000 | Should -BeTrue
            Test-IgwtRecycleBudgetExceeded -Drive 'D:' -Bytes 101 -MaxBytes 1000 | Should -BeFalse -Because 'each drive has its own bin'
        }
    }
}

Describe '3.9 B4: firewall rule definitions keep every narrowing filter (review FW-1)' {
    It 'captures ICMP types, interface aliases, the security filter and mappings, and passes them back' {
        InModuleScope iGWindowsTuner {
            $rule = [pscustomobject]@{ Name = 'r1'; DisplayName = 'Ping from LAN'; Description = ''; Group = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; EdgeTraversalPolicy = 'Block'; Owner = ''; LooseSourceMapping = $true; LocalOnlyMapping = $false; Platform = @('10.0') }
            Mock Get-NetFirewallRule { $rule }
            Mock Get-NetFirewallApplicationFilter { [pscustomobject]@{ Program = 'Any'; Package = '' } } -RemoveParameterType AssociatedNetFirewallRule
            Mock Get-NetFirewallPortFilter { [pscustomobject]@{ Protocol = 'ICMPv4'; LocalPort = 'Any'; RemotePort = 'Any'; IcmpType = @('8') } } -RemoveParameterType AssociatedNetFirewallRule
            Mock Get-NetFirewallAddressFilter { [pscustomobject]@{ LocalAddress = 'Any'; RemoteAddress = 'LocalSubnet' } } -RemoveParameterType AssociatedNetFirewallRule
            Mock Get-NetFirewallServiceFilter { [pscustomobject]@{ Service = 'Any' } } -RemoveParameterType AssociatedNetFirewallRule
            Mock Get-NetFirewallInterfaceTypeFilter { [pscustomobject]@{ InterfaceType = 'Any' } } -RemoveParameterType AssociatedNetFirewallRule
            Mock Get-NetFirewallInterfaceFilter { [pscustomobject]@{ InterfaceAlias = @('Ethernet') } } -RemoveParameterType AssociatedNetFirewallRule
            Mock Get-NetFirewallSecurityFilter { [pscustomobject]@{ Authentication = 'Required'; Encryption = 'NotRequired'; OverrideBlockRules = $false; LocalUser = 'Any'; RemoteUser = 'O:LSD:(A;;CC;;;S-1-5-21-1-2-3-1001)'; RemoteMachine = 'Any' } } -RemoveParameterType AssociatedNetFirewallRule
            $d = Get-IgwtFirewallRuleDefinition -Name 'r1'
            @($d.icmpType) | Should -Be @('8')
            @($d.interfaceAlias) | Should -Be @('Ethernet')
            $d.authentication | Should -Be 'Required'
            $p = ConvertTo-IgwtFirewallRuleParameters -Definition $d
            @($p.IcmpType) | Should -Be @('8')
            @($p.InterfaceAlias) | Should -Be @('Ethernet')
            $p.Authentication | Should -Be 'Required'
            $p.ContainsKey('Encryption') | Should -BeFalse -Because 'NotRequired is the default'
            $p.RemoteUser | Should -BeLike 'O:LSD:*'
            $p.LooseSourceMapping | Should -BeTrue
            @($p.Platform) | Should -Be @('10.0')
            @(Test-IgwtFirewallRuleDefinition -Definition $d).Count | Should -Be 0
        }
    }
    It 'a definition written before 3.9 gives exactly the parameters it gave before' {
        InModuleScope iGWindowsTuner {
            $old = [ordered]@{ name = 'r2'; displayName = 'Game'; description = ''; group = ''; enabled = $true; direction = 'Inbound'; action = 'Allow'; profile = 'Private'; edgeTraversal = 'Block'; owner = ''; program = 'C:\g.exe'; package = ''; service = 'Any'; protocol = 'UDP'; localPort = @('27015'); remotePort = @(); localAddress = @(); remoteAddress = @(); interfaceType = 'Any' }
            $p = ConvertTo-IgwtFirewallRuleParameters -Definition $old
            foreach ($k in 'IcmpType', 'InterfaceAlias', 'Authentication', 'Encryption', 'OverrideBlockRules', 'LocalUser', 'RemoteUser', 'RemoteMachine', 'LooseSourceMapping', 'LocalOnlyMapping', 'Platform') { $p.ContainsKey($k) | Should -BeFalse -Because $k }
        }
    }
}

Describe '3.9 B4: firewall profile undo returns to NotConfigured (review FW-2)' {
    It 'allows NotConfigured on every profile setting except the log size, and passes it through' {
        InModuleScope iGWindowsTuner {
            foreach ($s in 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'Notifications', 'UnicastResponse', 'LogAllowed', 'LogBlocked') {
                Get-IgwtFirewallProfileChangeBlock -Setting $s -Value 'NotConfigured' | Should -BeNullOrEmpty -Because $s
            }
            Get-IgwtFirewallProfileChangeBlock -Setting 'DefaultOutboundAction' -Value 'Sometimes' | Should -Not -BeNullOrEmpty
            Get-IgwtFirewallProfileChangeBlock -Setting 'Enabled' -Value $false | Should -Not -BeNullOrEmpty -Because 'turning the firewall off stays refused'
            Mock Test-IgwtRemoteSession { $false }
            Mock Get-NetFirewallProfile { [pscustomobject]@{ Name = 'Private'; DefaultOutboundAction = 'Block'; NotifyOnListen = 'True' } }
            Mock Set-NetFirewallProfile { }
            $null = Set-IgwtFirewallProfileSetting -Profile Private -Setting DefaultOutboundAction -Value 'NotConfigured' -Confirm:$false
            Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { [string]$DefaultOutboundAction -eq 'NotConfigured' }
            $null = Set-IgwtFirewallProfileSetting -Profile Private -Setting Notifications -Value 'NotConfigured' -Confirm:$false
            Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { [string]$NotifyOnListen -eq 'NotConfigured' }
        }
    }
}
