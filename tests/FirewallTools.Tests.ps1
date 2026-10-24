BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:Fx = New-IgwtFirewallFixture
    $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'state'
}
AfterAll { Remove-Item Env:\IGWT_GUI_STATE_DIR -ErrorAction SilentlyContinue }

# Firewall Manager 3.4 phases 7 and 8: rule templates and warnings, the Windows defaults comparison,
# live connections and the firewall-scope presets (SPEC-v3.4 sections 5 and 8). All read-only.
Describe 'Firewall rule templates and warnings' {
    It 'loads every scenario template from data and each one passes the rule validation' {
        InModuleScope iGWindowsTuner {
            $t = @(Get-IgwtFirewallRuleTemplates)
            $t.Count | Should -BeGreaterOrEqual 7
            foreach ($x in $t) {
                $s = $x.Settings.Clone(); $s.DisplayName = $x.Name
                @(Test-IgwtFirewallRuleSettings -Settings $s -New) | Should -BeNullOrEmpty -Because $x.Id
            }
        }
    }

    It 'warns before a wide-open rule is created and stays quiet for a narrow one' {
        InModuleScope iGWindowsTuner {
            $wide = @(Get-IgwtFirewallNewRuleWarnings -Settings @{ Direction = 'Inbound'; Action = 'Allow'; Profiles = @('Any') })
            $wide[0] | Should -Match '^Critical: '
            $narrow = @(Get-IgwtFirewallNewRuleWarnings -Settings @{ Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; LocalPort = '27015'; Profiles = @('Private'); RemoteAddress = 'LocalSubnet'; Program = 'C:\Games\game.exe' })
            @($narrow | Where-Object { $_ -match '^(Critical|High): ' }) | Should -BeNullOrEmpty
        }
    }

    It 'adds the risk warnings to the change plan of a new rule' {
        InModuleScope iGWindowsTuner {
            $p = Get-IgwtFirewallChangePlan -Operation New -Settings @{ DisplayName = 'Open all'; Direction = 'Inbound'; Action = 'Allow'; Profiles = @('Any'); Protocol = 'Any' } -RemoteSession $false
            @($p.Warnings | Where-Object { $_ -like 'Risk if created: Critical*' }).Count | Should -Be 1
        }
    }

    It 'marks rules it creates once in the description' {
        InModuleScope iGWindowsTuner {
            $once = Add-IgwtFirewallOwnedMarker -Description 'Game server'
            $once | Should -Be 'Game server [iG Windows Tuner]'
            Add-IgwtFirewallOwnedMarker -Description $once | Should -Be $once
        }
    }
}

Describe 'Comparison with the Windows default rules' {
    It 'lists added, removed and modified rules and skips app and service hardening rules' {
        InModuleScope iGWindowsTuner {
            $d = @{
                'A-In' = [pscustomobject]@{ Name = 'A-In'; DisplayName = 'A'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Source = 'SystemDefaults' }
                'B-In' = [pscustomobject]@{ Name = 'B-In'; DisplayName = 'B'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Source = 'SystemDefaults' }
                'C-Out' = [pscustomobject]@{ Name = 'C-Out'; DisplayName = 'C'; Enabled = $false; Direction = 'Outbound'; Action = 'Allow'; Profile = 'Any'; Source = 'SystemDefaults' }
            }
            $rows = @(
                [pscustomobject]@{ Name = 'A-In'; DisplayName = 'A'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profiles = 'Any'; Store = 'Active'; Owner = ''; OriginName = 'Windows Connections' }
                [pscustomobject]@{ Name = 'C-Out'; DisplayName = 'C'; Enabled = $true; Direction = 'Outbound'; Action = 'Allow'; Profiles = 'Any'; Store = 'Active'; Owner = ''; OriginName = 'Windows Connections' }
                [pscustomobject]@{ Name = 'Mine'; DisplayName = 'My rule'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profiles = 'Private'; Store = 'Active'; Owner = ''; OriginName = 'Custom Rules' }
                [pscustomobject]@{ Name = 'Store1'; DisplayName = 'Store app'; Enabled = $true; Direction = 'Outbound'; Action = 'Allow'; Profiles = 'Any'; Store = 'Active'; Owner = 'S-1-5-21-1'; OriginName = 'Windows Connections' }
                [pscustomobject]@{ Name = 'WSH1'; DisplayName = 'Hardening'; Enabled = $true; Direction = 'Inbound'; Action = 'Block'; Profiles = 'Any'; Store = 'StaticServiceStore'; Owner = ''; OriginName = 'Core Services' }
            )
            $c = @(Compare-IgwtFirewallDefaults -Rows $rows -Defaults $d)
            @($c | Where-Object Change -EQ 'Removed').RuleId | Should -Be 'B-In'
            @($c | Where-Object Change -EQ 'Modified').RuleId | Should -Be 'C-Out'
            @($c | Where-Object Change -EQ 'Modified')[0].Detail | Should -Match 'disabled by default, now enabled'
            @($c | Where-Object Change -EQ 'Added').RuleId | Should -Be 'Mine'
            @(Compare-IgwtFirewallDefaults -Rows $rows -Defaults $d -All | Where-Object Change -EQ 'Added').Count | Should -Be 3
            Compare-IgwtFirewallDefaults -Rows $rows -Defaults $null | Should -BeNullOrEmpty
        }
    }

    It 'falls back to a Sandbox baseline when the SystemDefaults store is not readable' {
        InModuleScope iGWindowsTuner {
            Mock Get-NetFirewallRule { throw 'not readable' }
            $p = Join-Path $TestDrive 'firewall-baseline-1.json'
            '{ "schemaVersion": 1, "kind": "igwtFirewallBaseline", "build": "1", "rules": [ { "Name": "X-In", "DisplayName": "X", "Enabled": true, "Direction": "Inbound", "Action": "Allow", "Profile": "Any" } ] }' | Set-Content -LiteralPath $p -Encoding ASCII
            $d = Get-IgwtFirewallDefaultRuleSet -BaselinePath $p
            $d['X-In'].Source | Should -Be 'Sandbox baseline'
            Get-IgwtFirewallDefaultRuleSet -BaselinePath (Join-Path $TestDrive 'none.json') | Should -BeNullOrEmpty
        }
    }
}

Describe 'Live connections' {
    It 'matches connections to the most specific rule, block over allow, and names the default otherwise' {
        InModuleScope iGWindowsTuner {
            Mock Get-Process { @([pscustomobject]@{ Id = 10; ProcessName = 'game'; Path = 'C:\Games\game.exe' }, [pscustomobject]@{ Id = 11; ProcessName = 'browser'; Path = 'C:\B\browser.exe' }) }
            Mock Get-CimInstance { @() }
            $rules = @(
                [pscustomobject]@{ Name = 'any-in'; DisplayName = 'Any inbound UDP'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; Program = 'Any'; Service = 'Any'; LocalPort = 'Any'; RemotePort = 'Any' }
                [pscustomobject]@{ Name = 'game-in'; DisplayName = 'Game UDP'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; Program = 'C:\Games\game.exe'; Service = 'Any'; LocalPort = '27015'; RemotePort = 'Any' }
                [pscustomobject]@{ Name = 'game-block'; DisplayName = 'Block game'; Enabled = $true; Direction = 'Outbound'; Action = 'Block'; Protocol = 'TCP'; Program = 'C:\Games\game.exe'; Service = 'Any'; LocalPort = 'Any'; RemotePort = 'Any' }
                [pscustomobject]@{ Name = 'game-allow'; DisplayName = 'Allow game'; Enabled = $true; Direction = 'Outbound'; Action = 'Allow'; Protocol = 'TCP'; Program = 'C:\Games\game.exe'; Service = 'Any'; LocalPort = 'Any'; RemotePort = '443' }
            )
            $conn = @(
                [pscustomobject]@{ Protocol = 'UDP'; LocalAddress = '0.0.0.0'; LocalPort = 27015; RemoteAddress = ''; RemotePort = 0; State = 'Endpoint'; ProcessId = 10 }
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '192.168.1.5'; LocalPort = 50000; RemoteAddress = '203.0.113.9'; RemotePort = 443; State = 'Established'; ProcessId = 10 }
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '192.168.1.5'; LocalPort = 50001; RemoteAddress = '203.0.113.10'; RemotePort = 443; State = 'Established'; ProcessId = 11 }
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '127.0.0.1'; LocalPort = 50002; RemoteAddress = '127.0.0.1'; RemotePort = 8080; State = 'Established'; ProcessId = 11 }
            )
            $r = @(Get-IgwtFirewallConnections -Rows $rules -Connections $conn -ListenPorts @())
            $r.Count | Should -Be 4
            $r[0].RuleId | Should -Be 'game-in' -Because 'the program and port rule is more specific than the any-program rule'
            $r[1].RuleId | Should -Be 'game-block' -Because 'a block wins over an allow'
            $r[2].Rule | Should -Match 'outbound is allowed by default'
            $r[3].Direction | Should -Be 'This PC'
        }
    }
}

Describe 'Firewall-scope presets' {
    BeforeAll {
        $script:Rows = InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
        }
    }

    It 'loads four valid scopes from data' {
        InModuleScope iGWindowsTuner {
            @(Get-IgwtFirewallScopes | ForEach-Object { $_.id }) | Should -Be @('gaming-pc', 'workstation', 'public-wifi-laptop', 'sysadmin-hardened')
            { Get-IgwtFirewallScopePlan -Scope 'nope' -Rows @([pscustomobject]@{ Name = 'x' }) } | Should -Throw '*Unknown firewall scope*'
        }
    }

    It 'plans only allowed changes and never touches Core Services, locked or game rules' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Rows; Fx = $script:Fx } {
            param($Rows, $Fx)
            Mock Get-IgwtFirewallInstalledPackages { @() }
            $sig = { param($x) @($x | ForEach-Object { "$($_.Origin)|$(@($_.Assessments) -join '+')|$(@($_.Findings).Count)|$(@($_.Groups) -join '+')" }) -join ',' }; $before = & $sig $Rows
            foreach ($id in 'gaming-pc', 'sysadmin-hardened') {
                $plan = Get-IgwtFirewallScopePlan -Scope $id -Rows $Rows -Signatures $Fx.Signatures -RemoteSession $false
                $plan.Count | Should -BeGreaterThan 0 -Because $id
                $byName = @{}; foreach ($r in $plan.Rows) { $byName[[string]$r.Name] = $r }
                foreach ($b in $plan.Batches) {
                    foreach ($i in @($b.Plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp })) {
                        $r = $byName[[string]$i.Name]
                        $r.Origin | Should -Not -Be 'CoreServices' -Because "$id must not change Core Services ($($i.Name))"
                        [bool]$r.Locked | Should -BeFalse
                        if ($r.Protected) { [string]$b.Operation | Should -Not -BeIn 'Disable', 'Delete' }
                        if ($r.IsWindows) { [string]$b.Operation | Should -Not -Be 'Delete' }
                    }
                }
            }
            (& $sig $Rows) | Should -Be $before -Because 'the plan works on copies'
        }
    }

    It 'every built-in preset names a known scope or none, and a wrong scope is an error' {
        InModuleScope iGWindowsTuner {
            $known = @(Get-IgwtFirewallScopes | ForEach-Object { [string]$_.id })
            foreach ($f in Get-ChildItem (Join-Path (Get-IgwtDataFolder) 'presets') -Filter *.json) {
                $p = Read-IgwtJsonFile -Path $f.FullName
                if ($p.PSObject.Properties['firewallScope']) { $known | Should -Contain ([string]$p.firewallScope) -Because $f.Name }
            }
            $errors = New-Object System.Collections.Generic.List[string]
            $bad = [pscustomobject]@{ id = 'x'; name = 'X'; hint = 'Test preset'; description = 'A test preset with a firewall scope that does not exist anywhere.'; levelCeiling = 'Standard'; antiCheatPolicy = 'safeOnly'; include = @(); firewallScope = 'nope' }
            Test-IgwtPresetDefinition -Preset $bad -CatalogIndex @{} -Errors $errors
            @($errors | Where-Object { $_ -like "*firewallScope 'nope'*" }).Count | Should -Be 1
        }
    }
}

# Fixes from the independent review (docs\REVIEW.md): the engine's own locks, no moves out of Core
# Services, Windows-category rules enable/disable only, remote-session checks on stable identifiers,
# offline drives, and queued GUI batches.
Describe 'Firewall review fixes' {
    BeforeAll {
        $script:Raw = InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
        }
    }

    It 'classifies plain inventory rows in the engine, so Core Services and Windows rules stay locked (H1, M2)' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Raw; Fx = $script:Fx } {
            param($Rows, $Fx)
            Mock Get-IgwtFirewallSignatures { $Fx.Signatures }
            $copies = @($Rows | ForEach-Object { $_.PSObject.Copy() })
            $core = @($copies | Where-Object { $_.Name -like '*SecHealthUI*' })[0]
            $win = @($copies | Where-Object { [string]$Fx.Expect[[string]$_.Name].Origin -eq 'WindowsConnections' -and [string]$_.Source -ne 'Windows' -and -not $_.Locked })[0]
            [string]$core.Origin | Should -BeNullOrEmpty -Because 'the inventory alone has no classification'
            Invoke-IgwtFirewallEngineClassification -Rows @($core, $win)
            $core.EngineOrigin | Should -Be 'CoreServices'
            foreach ($op in 'Disable', 'Edit', 'Delete', 'SetAction') { Get-IgwtFirewallChangeBlock -Operation $op -Rule $core -Settings @{ Action = 'Block' } | Should -Not -BeNullOrEmpty -Because "$op on a Core Services rule" }
            $win | Should -Not -BeNullOrEmpty
            Get-IgwtFirewallChangeBlock -Operation SetAction -Rule $win -Settings @{ Action = 'Block' } | Should -Match 'Windows rules'
            Get-IgwtFirewallChangeBlock -Operation Edit -Rule $win | Should -Match 'Windows rules'
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule $win | Should -BeNullOrEmpty
        }
    }

    It 'plans engine changes and imports only after classifying the rules (H1)' {
        InModuleScope iGWindowsTuner {
            foreach ($fn in 'Invoke-IgwtFirewallChange', 'Get-IgwtFirewallImportPlan') {
                $body = (Get-Command $fn).ScriptBlock.ToString()
                $c = $body.IndexOf('Invoke-IgwtFirewallEngineClassification')
                $c | Should -BeGreaterThan 0 -Because "$fn classifies"
                if ($fn -eq 'Invoke-IgwtFirewallChange') { $c | Should -BeLessThan $body.IndexOf('Get-IgwtFirewallChangePlan -Operation') }
            }
        }
    }

    It 'never moves a rule out of Core Services, while other moves still apply (M1)' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Raw; Fx = $script:Fx } {
            param($Rows, $Fx)
            $copies = @($Rows | ForEach-Object { $_.PSObject.Copy() })
            $core = @($copies | Where-Object { $_.Name -like '*SecHealthUI*' })[0]
            $app = @($copies | Where-Object { [string]$Fx.Expect[[string]$_.Name].Origin -eq 'UserInstalled' })[0]
            $ov = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{ $core.Name = 'CustomRules'; $app.Name = 'CustomRules' }; NotBloated = @(); Ignored = [pscustomobject]@{} }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides $ov
            Invoke-IgwtFirewallClassification -Rows @($core, $app) -Context $ctx
            $core.Origin | Should -Be 'CoreServices'
            $app.Origin | Should -Be 'CustomRules'
            $app.EngineOrigin | Should -Be 'UserInstalled'
        }
    }

    It 'recognises remote-access rules by group resource string, rule ID and port range, and guards block rules (M4)' {
        InModuleScope iGWindowsTuner {
            Test-IgwtFirewallRemoteRelevant -Rule ([pscustomobject]@{ Name = 'x'; Group = 'Remotedesktop'; RawGroup = '@FirewallAPI.dll,-28752'; LocalPort = 'Any' }) | Should -BeTrue
            Test-IgwtFirewallRemoteRelevant -Rule ([pscustomobject]@{ Name = 'RemoteDesktop-Shadow-In-TCP'; Group = 'Remotedesktop - Spiegeln'; RawGroup = ''; LocalPort = 'Any' }) | Should -BeTrue
            Test-IgwtFirewallRemoteRelevant -Rule ([pscustomobject]@{ Name = 'x'; Group = ''; RawGroup = ''; LocalPort = '3000-4000' }) | Should -BeTrue
            Test-IgwtFirewallRemoteRelevant -Rule ([pscustomobject]@{ Name = 'x'; Group = ''; RawGroup = ''; LocalPort = '80, 443' }) | Should -BeFalse
            $block = [pscustomobject]@{ Name = 'b'; DisplayName = 'Block all in'; Source = 'ThirdParty'; Origin = 'CustomRules'; EngineOrigin = 'CustomRules'; Locked = $false; Enabled = $false; Direction = 'Inbound'; Action = 'Block'; LocalPort = 'Any'; Group = ''; RawGroup = ''; ProgramExists = '' }
            Get-IgwtFirewallChangeBlock -Operation Enable -Rule $block -RemoteSession $true | Should -Match 'remote session'
            Get-IgwtFirewallChangeBlock -Operation Enable -Rule $block -RemoteSession $false | Should -BeNullOrEmpty
            $allow = [pscustomobject]@{ Name = 'a'; DisplayName = 'Game'; Source = 'ThirdParty'; Origin = 'CustomRules'; EngineOrigin = 'CustomRules'; Locked = $false; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; LocalPort = '27015'; Group = ''; RawGroup = ''; ProgramExists = '' }
            Get-IgwtFirewallChangeBlock -Operation Edit -Rule $allow -Settings @{ Action = 'Block'; LocalPort = '3389' } -RemoteSession $true | Should -Match 'remote session'
        }
    }

    It 'treats a program on a drive that is not there as Unknown, not orphaned (M6)' {
        InModuleScope iGWindowsTuner {
            $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
            $free = @([char[]]'QRSTUVWXYZ' | Where-Object { $used -notcontains [string]$_ })[0]
            $rules = @(
                [pscustomobject]@{ InstanceID = 'gone'; Name = 'gone'; DisplayName = 'Gone'; Group = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; PolicyStoreSourceType = 'Local'; PolicyStoreSource = 'PersistentStore'; Owner = ''; EdgeTraversalPolicy = 'Block'; Description = 'x' }
                [pscustomobject]@{ InstanceID = 'usb'; Name = 'usb'; DisplayName = 'USB'; Group = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; PolicyStoreSourceType = 'Local'; PolicyStoreSource = 'PersistentStore'; Owner = ''; EdgeTraversalPolicy = 'Block'; Description = 'x' }
            )
            $app = @([pscustomobject]@{ InstanceID = 'gone'; Program = 'C:\igwt-no-such-folder\old.exe'; Package = '' }, [pscustomobject]@{ InstanceID = 'usb'; Program = "${free}:\Games\game.exe"; Package = '' })
            $rows = Join-IgwtFirewallData -Rules $rules -ApplicationFilters $app -PathExists { param($p) $false }
            @($rows | Where-Object Name -EQ 'gone')[0].ProgramExists | Should -Be 'No'
            @($rows | Where-Object Name -EQ 'usb')[0].ProgramExists | Should -Be 'Unknown'
        }
    }

    It 'drops queued batches when a change is started by hand or cannot run (H2)' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ IsAdmin = $false; FirewallQueue = New-Object System.Collections.Generic.List[object] }
                $script:Gui.FirewallQueue.Add([pscustomobject]@{ Operation = 'Disable'; Rows = @(); Settings = @{} })
                Mock Set-IgwtGuiStatus { }
                Invoke-IgwtGuiFirewallChange -Operation Disable -Rows @()
                $script:Gui.FirewallQueue | Should -BeNullOrEmpty
                $script:Gui.FirewallQueue = New-Object System.Collections.Generic.List[object]
                $script:Gui.FirewallQueue.Add([pscustomobject]@{ Operation = 'Disable'; Rows = @(); Settings = @{} })
                Invoke-IgwtGuiFirewallChange -Operation Disable -Rows @() -NoConfirm
                $script:Gui.FirewallQueue | Should -BeNullOrEmpty -Because 'a queued batch that cannot run ends the run'
            } finally { $script:Gui = $saved }
        }
    }

    It 'warns when a new or re-enabled block rule hits a protected game program (L1)' {
        InModuleScope iGWindowsTuner {
            $steam = 'D:\SteamLibrary\steamapps\common\Some Game\game.exe'
            Test-IgwtFirewallProtectedProgram -Program $steam | Should -Not -BeNullOrEmpty -Because 'secondary Steam libraries are protected too'
            $p = Get-IgwtFirewallChangePlan -Operation New -Settings @{ DisplayName = 'Block game'; Direction = 'Outbound'; Action = 'Block'; Profiles = @('Any'); Protocol = 'Any'; Program = $steam } -RemoteSession $false
            @($p.Warnings | Where-Object { $_ -like '*may break online play*' }).Count | Should -Be 1
            $r = [pscustomobject]@{ Name = 'g'; DisplayName = 'Block game'; Source = 'ThirdParty'; Origin = 'CustomRules'; EngineOrigin = 'CustomRules'; Locked = $false; Enabled = $false; Direction = 'Outbound'; Action = 'Block'; Program = $steam; LocalPort = 'Any'; Group = ''; RawGroup = ''; ProgramExists = 'Yes'; Protected = $false }
            $p2 = Get-IgwtFirewallChangePlan -Operation Enable -Rules @($r) -RemoteSession $false
            @($p2.Warnings | Where-Object { $_ -like '*may break online play*' }).Count | Should -BeGreaterOrEqual 1
        }
    }
}