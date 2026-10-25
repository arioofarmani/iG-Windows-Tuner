BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:Fx = New-IgwtFirewallFixture
    $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'state'
}
AfterAll { Remove-Item Env:\IGWT_GUI_STATE_DIR -ErrorAction SilentlyContinue }

# Firewall Manager 3.4 audit: one read-only call from rules to the overview counts (SPEC-v3.4 sections 2-4).
Describe 'Firewall audit' {
    BeforeAll {
        $script:Audit = InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            Mock Get-IgwtSnapshotList { @([pscustomobject]@{ Path = 'C:\b\s1.json'; Created = '2026-10-20T10:00:00Z'; Operation = 'Firewall:Disable'; Detail = 'Disabled 2 rules'; Entries = @([pscustomobject]@{ Name = 'MCX-Var1-In-TCP' }) }, [pscustomobject]@{ Path = 'C:\b\s2.json'; Created = '2026-10-19T10:00:00Z'; Operation = 'Apply'; Detail = 'x'; Entries = @() }) }
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $inv = [pscustomobject]@{ Rules = $rows; Count = $rows.Count; Partial = $false; Notes = @(); LoadMs = 500 }
            $listeners = @([pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 3389; ProcessId = 1; ProcessName = 'svchost'; Path = 'C:\WINDOWS\system32\svchost.exe'; Services = @('TermService'); Local = $false },
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 9999; ProcessId = 2; ProcessName = 'nothing'; Path = 'C:\x\nothing.exe'; Services = @(); Local = $false },
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '127.0.0.1'; LocalPort = 5000; ProcessId = 3; ProcessName = 'local'; Path = 'C:\x\local.exe'; Services = @(); Local = $true })
            Get-IgwtFirewallAudit -Role Gamer -Inventory $inv -Listeners $listeners -InstalledPackages @() -DefaultRules @{ 'CoreNet-Disabled-In' = $true } -Signatures $Fx.Signatures
        }
    }

    It 'classifies, assesses and counts every rule' {
        $a = $script:Audit
        $a.Count | Should -BeGreaterOrEqual 1000
        @($a.Rules | Where-Object { -not $_.Origin -or -not $_.OriginReason -or -not $_.Confidence }).Count | Should -Be 0
        $s = $a.Summary
        ($s.Groups.CoreServices + $s.Groups.WindowsConnections + $s.Groups.UserInstalled + $s.Groups.CustomRules) | Should -Be $a.Count -Because 'every rule has exactly one origin category'
        ($s.Groups.Inbound + $s.Groups.Outbound) | Should -Be $a.Count
        $s.Severity.Critical | Should -BeGreaterOrEqual 2 -Because 'the wide-open rule, plus RDP exposed now (High raised to Critical)'
        $s.NeedsAttention | Should -Be ($s.Severity.Critical + $s.Severity.High)
        @($s.QuickWins) | Should -Contain 'MCX-Var1-In-TCP'
        @($s.QuickWins) | Should -Not -Contain 'Svc1-1' -Because 'locked rules are never quick wins'
        $a.Timing.Classify | Should -Not -BeNullOrEmpty
    }

    It 'maps open ports to the rules that expose them' {
        $map = @($script:Audit.Exposure)
        ($map | Where-Object LocalPort -EQ 3389).Status | Should -Be 'Exposed'
        ($map | Where-Object LocalPort -EQ 3389).RuleIds | Should -Contain 'RemoteDesktop-UserMode-In-TCP'
        ($map | Where-Object LocalPort -EQ 9999).RuleIds | Should -Contain '{00000000-0000-0000-0003-000000000002}' -Because 'the wide-open rule exposes even an unknown listener'
        InModuleScope iGWindowsTuner {
            $one = [pscustomobject]@{ Name = 'Only'; DisplayName = 'Only'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = '80'; Program = 'Any'; Service = 'Any'; ProfileList = @('Private') }
            $l = [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 9999; ProcessName = 'x'; Path = 'C:\x.exe'; Services = @(); Local = $false }
            (Get-IgwtFirewallExposureMap -Rows @($one) -Listeners @($l)).Status | Should -Be 'Blocked' -Because 'no allow rule matches: the default inbound block applies'
            $unread = [pscustomobject]@{ Name = 'U'; DisplayName = 'U'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = ''; LocalPort = ''; Program = 'Any'; Service = 'Any'; ProfileList = @('Any') }
            (Get-IgwtFirewallExposureMap -Rows @($unread) -Listeners @($l)).Status | Should -Be 'Unknown' -Because 'without administrator rights the port filters are not readable'
        }
        ($map | Where-Object LocalPort -EQ 5000).Status | Should -Be 'Local only'
        ($script:Audit.Rules | Where-Object Name -EQ 'CoreNet-Disabled-In').Findings.RiskId | Should -Contain 'disabled-security-rule' -Because 'it is enabled in the Windows defaults'
        @($script:Audit.RecentChanges).Count | Should -Be 1 -Because 'only firewall snapshots are recent firewall changes'
    }

    It 'orders the smart fix wizard by severity and plans fixes with skipped rules and reasons' {
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $steps = @(Get-IgwtFirewallWizardSteps -Rows $A.Rules)
            $steps.Count | Should -Be @($A.Findings | Where-Object { -not $_.Ignored }).Count
            $steps[0].Finding.Severity | Should -Be 'Critical'
            $decisions = @(
                [pscustomobject]@{ RuleId = 'OrphanApp2'; Action = 'Delete' }
                [pscustomobject]@{ RuleId = 'FPS-SMB-In-TCP'; Action = 'Disable' }
                [pscustomobject]@{ RuleId = 'Svc1-1'; Action = 'Disable' }
                [pscustomobject]@{ RuleId = 'UpdaterInAppData'; Action = 'RestrictPrivate' }
                [pscustomobject]@{ RuleId = 'UnsignedTool'; Action = 'Keep' }
            )
            $plans = @(Get-IgwtFirewallFixPlan -Decisions $decisions -Rows $A.Rules -RemoteSession $false)
            @($plans | ForEach-Object Action | Sort-Object) | Should -Be @('Delete', 'Disable', 'RestrictPrivate')
            $dis = $plans | Where-Object Action -EQ 'Disable'
            $dis.Plan.Count | Should -Be 1
            ($dis.Plan.Items | Where-Object Name -EQ 'Svc1-1').Reason | Should -Match 'Service Hardening'
            ($plans | Where-Object Action -EQ 'RestrictPrivate').Operation | Should -Be 'Edit'
            ($plans | Where-Object Action -EQ 'Delete').Plan.Count | Should -Be 1
        }
    }

    It 'refuses unsafe changes: Core Services, deleting Windows rules, locked rules; warns for games' {
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $get = { param($n) $A.Rules | Where-Object Name -EQ $n }
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule (& $get 'CoreNet-DHCP-In') | Should -Match 'Core Services'
            Get-IgwtFirewallChangeBlock -Operation Delete -Rule (& $get 'FPS-SMB-In-TCP') | Should -Match 'never deleted'
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule (& $get 'FPS-SMB-In-TCP') | Should -BeNullOrEmpty
            Get-IgwtFirewallChangeBlock -Operation Delete -Rule (& $get 'OrphanApp2') | Should -BeNullOrEmpty
            Get-IgwtFirewallChangeBlock -Operation Disable -Rule (& $get 'GPO-Corp-Block') | Should -Match 'Group Policy'
            $plan = Get-IgwtFirewallChangePlan -Operation Disable -Rules @(& $get 'Steam Web Helper') -RemoteSession $false
            ($plan.Warnings -join ' ') | Should -Match 'online play'
        }
    }

    It 'describes each rule in one plain sentence' {
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $get = { param($n) $A.Rules | Where-Object Name -EQ $n }
            Format-IgwtFirewallRuleSummary -Row (& $get 'FPS-SMB-In-TCP') | Should -Be 'Allows incoming TCP on port 445 to any program from any address, on Private and Public networks.'
            Format-IgwtFirewallRuleSummary -Row (& $get 'iGWindowsTuner-Block-Out-mshta-x64') | Should -Be 'Blocks outgoing traffic of any protocol from mshta.exe to any address, on all networks.'
            Format-IgwtFirewallRuleSummary -Row (& $get 'MCX-Var5-In-TCP') | Should -Match '^Turned off\. When on, it: allows incoming TCP on port 10245'
            Format-IgwtFirewallRuleSummary -Row ([pscustomobject]@{ Direction = 'Inbound'; Action = 'Allow'; Protocol = ''; Program = 'C:\a\b.exe'; RemoteAddress = ''; ProfileList = @('Private'); Enabled = $true; Service = 'Any' }) | Should -Match 'administrator rights'
        }
    }

    It 'audits 1,000+ rules within the cached budget (classification under 1 s)' {
        $script:Audit.Timing.Classify | Should -BeLessThan 1000
    }
}
