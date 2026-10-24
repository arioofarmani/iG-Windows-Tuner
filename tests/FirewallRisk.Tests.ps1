BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:Fx = New-IgwtFirewallFixture
    $script:None = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
}

# Firewall Manager 3.4 risk findings (SPEC-v3.4 section 2.3) and exposure correlation.
Describe 'Firewall risk findings' {
    It 'finds exactly the expected risks on every synthetic rule' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx; None = $script:None } {
            param($Fx, $None)
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides $None
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $null = Get-IgwtFirewallFindings -Rows $rows -Context $ctx
            $bad = New-Object System.Collections.Generic.List[string]
            foreach ($r in $rows) {
                $want = @($Fx.Expect[[string]$r.Name].Findings | Where-Object { $_ } | Sort-Object)
                $got = @($r.Findings | ForEach-Object { $_.RiskId } | Sort-Object)
                if (($want -join ',') -ne ($got -join ',')) { $bad.Add("$($r.Name): got [$($got -join ', ')], expected [$($want -join ', ')]") }
                if ($r.Findings.Count -and @($r.Assessments) -notcontains 'SecurityRisks') { $bad.Add("$($r.Name): findings but no SecurityRisks assessment") }
            }
            ($bad | Select-Object -First 15) -join "`n" | Should -BeNullOrEmpty
        }
    }

    It 'gives each finding an explanation, severity, recommended action and alternatives' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx; None = $script:None } {
            param($Fx, $None)
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides $None
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $all = @(Get-IgwtFirewallFindings -Rows $rows -Context $ctx)
            $all.Count | Should -BeGreaterThan 10
            foreach ($f in $all) { $f.Explanation | Should -Not -BeNullOrEmpty; $f.Severity | Should -BeIn 'Critical', 'High', 'Medium', 'Low'; $f.Recommended | Should -Not -BeNullOrEmpty }
            ($rows | Where-Object Name -EQ '{00000000-0000-0000-0003-000000000002}').RiskLevel | Should -Be 'Critical'
            # Windows rules are never offered Delete; Core Services only Keep or Ignore.
            foreach ($f in @($all | Where-Object { ($rows | Where-Object Name -EQ $_.RuleId).IsWindows })) { $f.Recommended | Should -Not -Be 'Delete'; @($f.Alternatives) | Should -Not -Contain 'Delete' }
            foreach ($f in @($all | Where-Object { ($rows | Where-Object Name -EQ $_.RuleId).Origin -eq 'CoreServices' })) { @(@($f.Recommended) + @($f.Alternatives)) | ForEach-Object { $_ | Should -BeIn 'Keep', 'Ignore' } }
            ($all | Where-Object { $_.RuleId -eq 'OrphanApp2' -and $_.RiskId -eq 'orphaned-program' }).Recommended | Should -Be 'Delete'
        }
    }

    It 'never recommends disabling or blocking a protected game, launcher or anti-cheat rule' {
        InModuleScope iGWindowsTuner -Parameters @{ None = $script:None } {
            param($None)
            $rule = [pscustomobject]@{ Name = 'Steam-Any'; InstanceID = 'Steam-Any'; DisplayName = 'Steam'; Group = ''; DisplayGroup = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; EdgeTraversalPolicy = 'Block'; Owner = ''; PolicyStoreSource = 'PersistentStore'; PolicyStoreSourceType = 'Local'; Description = '' }
            $rows = Join-IgwtFirewallData -Rules @($rule) -ApplicationFilters @([pscustomobject]@{ InstanceID = 'Steam-Any'; Program = 'C:\Program Files (x86)\Steam\steam.exe'; Package = '' }) -PortFilters @([pscustomobject]@{ InstanceID = 'Steam-Any'; Protocol = 'TCP'; LocalPort = '1000-9000'; RemotePort = 'Any' }) -AddressFilters @([pscustomobject]@{ InstanceID = 'Steam-Any'; LocalAddress = 'Any'; RemoteAddress = 'Any' }) -PathExists { $true }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides $None
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $rows[0].Protected | Should -BeTrue
            $f = @(Get-IgwtFirewallFindings -Rows $rows -Context $ctx)
            $f.Count | Should -BeGreaterThan 0
            foreach ($x in $f) { $x.Recommended | Should -Not -BeIn 'Disable', 'Delete' }
        }
    }

    It 'marks rules that match a live listener as Exposed now and raises the severity one level' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx; None = $script:None } {
            param($Fx, $None)
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides $None
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $listeners = @(
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 3389; ProcessId = 1; ProcessName = 'svchost'; Path = 'C:\WINDOWS\system32\svchost.exe'; Services = @('TermService'); Local = $false }
                [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '127.0.0.1'; LocalPort = 445; ProcessId = 4; ProcessName = 'System'; Path = ''; Services = @(); Local = $true }
            )
            $null = Get-IgwtFirewallFindings -Rows $rows -Context $ctx -Listeners $listeners
            $rdp = $rows | Where-Object Name -EQ 'RemoteDesktop-UserMode-In-TCP'
            $rdp.Exposed | Should -BeTrue
            ($rdp.Findings | Where-Object RiskId -EQ 'public-admin-protocol').Severity | Should -Be 'Critical'
            ($rdp.Findings | Where-Object RiskId -EQ 'public-admin-protocol').BaseSeverity | Should -Be 'High'
            ($rows | Where-Object Name -EQ 'FPS-SMB-In-TCP').Exposed | Should -BeFalse -Because 'a loopback-only listener is not reachable from the network'
            # A rule whose filters could not be read (not elevated) never claims exposure.
            $unread = [pscustomobject]@{ Name = 'x'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = ''; LocalPort = ''; Program = 'Any'; Service = 'Any' }
            Test-IgwtFirewallListenerMatch -Row $unread -Listener $listeners[0] | Should -BeFalse
        }
    }

    It 'respects ignored findings until they expire' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            $until = (Get-Date).AddDays(1).ToString('o')
            $ov = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{ 'UnsignedTool|unsigned-program' = [pscustomobject]@{ Reason = 'In-house tool'; Until = $until } } }
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PathExists { $true }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides $ov
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $null = Get-IgwtFirewallFindings -Rows $rows -Context $ctx
            $u = $rows | Where-Object Name -EQ 'UnsignedTool'
            ($u.Findings | Where-Object RiskId -EQ 'unsigned-program').Ignored | Should -BeTrue
            ($u.Findings | Where-Object RiskId -EQ 'unsigned-program').IgnoreReason | Should -Be 'In-house tool'
            @($u.Assessments) | Should -Not -Contain 'SecurityRisks'
            $null = Get-IgwtFirewallFindings -Rows $rows -Context $ctx -Now (Get-Date).AddDays(2)
            @($u.Assessments) | Should -Contain 'SecurityRisks'
        }
    }

    It 'checks signatures once and reads them from the cache afterwards' {
        InModuleScope iGWindowsTuner {
            $cache = Join-Path $TestDrive 'sig.json'
            $exe = Join-Path $TestDrive 'tool.exe'
            Set-Content -Path $exe -Value 'x'
            Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
            $a = Get-IgwtFirewallSignatures -Path @($exe) -CachePath $cache
            $a[$exe.ToLowerInvariant()].Status | Should -Be 'NotSigned'
            $b = Get-IgwtFirewallSignatures -Path @($exe, 'C:\does\not\exist.exe') -CachePath $cache
            $b.Count | Should -Be 1
            Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly
            # A changed file is checked again.
            Add-Content -Path $exe -Value 'more'
            $null = Get-IgwtFirewallSignatures -Path @($exe) -CachePath $cache
            Should -Invoke Get-AuthenticodeSignature -Times 2 -Exactly
        }
    }

    It 'evaluates every named check the knowledge base allows' {
        InModuleScope iGWindowsTuner {
            $row = [pscustomobject]@{ Name = 'x'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Program = 'Any'; Service = 'Any'; Package = ''; Owner = ''; LocalPort = 'Any'; RemoteAddress = 'Any'; Protocol = 'Any'; ProfileList = @('Any'); ProgramExists = ''; Origin = 'CustomRules'; EdgeTraversal = 'Block'; Description = ''; RawGroup = ''; Store = 'Active' }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides ([pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} })
            $facts = Get-IgwtFirewallRowFacts -Row $row -Context $ctx -State (Get-IgwtFirewallRiskState -Rows @($row) -Context $ctx)
            foreach ($check in $script:IgwtFirewallRiskChecks) { $facts.ContainsKey($check) | Should -BeTrue -Because "risk check '$check' needs an evaluator" }
        }
    }
    It 'reads port lists and ranges and counts wide ranges' {
        InModuleScope iGWindowsTuner {
            @(ConvertTo-IgwtFirewallPortRanges -Port '80, 443, 1000-2000').Count | Should -Be 3
            @(ConvertTo-IgwtFirewallPortRanges -Port 'Any').Count | Should -Be 0
            Test-IgwtFirewallPortInSet -Protocol 'TCP' -LocalPort '3000-4000' -Set ([pscustomobject]@{ tcp = @('3389'); udp = @() }) | Should -BeTrue
            Test-IgwtFirewallPortInSet -Protocol 'UDP' -LocalPort '3389' -Set ([pscustomobject]@{ tcp = @('3389'); udp = @() }) | Should -BeFalse
            Test-IgwtFirewallPortInSet -Protocol 'TCP' -LocalPort 'Any' -Set ([pscustomobject]@{ tcp = @('3389'); udp = @() }) | Should -BeFalse -Because 'an any-port rule is covered by the wide-open check'
        }
    }
}
