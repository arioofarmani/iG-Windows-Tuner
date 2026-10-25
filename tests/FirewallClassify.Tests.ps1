BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:Fx = New-IgwtFirewallFixture
    $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'state'
}
AfterAll { Remove-Item Env:\IGWT_GUI_STATE_DIR -ErrorAction SilentlyContinue }

# Firewall Manager 3.4 classification (SPEC-v3.4 section 2.2) on a synthetic 1,000+ rule set.
Describe 'Firewall rule classification' {
    It 'covers 1,000+ synthetic rules with every origin category' {
        $script:Fx.Rules.Count | Should -BeGreaterOrEqual 1000
        @($script:Fx.Expect.Values | ForEach-Object Origin | Select-Object -Unique).Count | Should -Be 4
    }

    It 'gives every rule the expected origin category and confidence, with a reason' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides ([pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} })
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $bad = New-Object System.Collections.Generic.List[string]
            foreach ($r in $rows) {
                $e = $Fx.Expect[[string]$r.Name]
                if (-not $e) { $bad.Add("$($r.Name): no expectation"); continue }
                if ($r.Origin -ne $e.Origin) { $bad.Add("$($r.Name): origin $($r.Origin), expected $($e.Origin) ($($r.OriginReason))") }
                if ($r.Confidence -ne $e.Confidence) { $bad.Add("$($r.Name): confidence $($r.Confidence), expected $($e.Confidence) ($($r.OriginReason))") }
                if (-not $r.OriginReason) { $bad.Add("$($r.Name): no reason") }
                if ([bool]($r.Assessments -contains 'Bloated') -ne $e.Bloated) { $bad.Add("$($r.Name): bloated $(@($r.Assessments) -contains 'Bloated'), expected $($e.Bloated)") }
            }
            ($bad | Select-Object -First 15) -join "`n" | Should -BeNullOrEmpty
        }
    }

    It 'derives facets from direction and action, and never matches on display names' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { $true }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides ([pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} })
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $dhcp = $rows | Where-Object Name -EQ 'CoreNet-DHCP-In'
            $dhcp.DisplayName | Should -Match 'Kernnetzwerk' -Because 'the fixture uses a localized display name'
            $dhcp.Origin | Should -Be 'CoreServices'
            @($dhcp.Facets) | Should -Be @('Inbound')
            $block = $rows | Where-Object Name -EQ 'iGWindowsTuner-Block-Out-mshta-x64'
            @($block.Facets) | Should -Be @('Outbound', 'Blocked')
            @($block.Groups) | Should -Contain 'CustomRules'
            ($rows | Where-Object Name -EQ 'Svc1-1').Locked | Should -BeTrue
            ($rows | Where-Object Name -EQ 'GPO-Raw-Allow').Locked | Should -BeTrue
        }
    }

    It 'makes Xbox app rules bloat only when the Xbox app is not installed, per role' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            $none = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
            $pick = { param($rows) $rows | Where-Object Name -Like 'Microsoft.XboxGamingOverlay*' }
            foreach ($case in @(@(@(), $true), @(@('Microsoft.GamingApp'), $false), @($null, $false))) {
                $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PathExists { $true }
                Invoke-IgwtFirewallClassification -Rows $rows -Context (Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages $case[0] -Overrides $none)
                [bool](@((& $pick $rows).Assessments) -contains 'Bloated') | Should -Be $case[1]
            }
            # Remote Desktop is bloat for a gamer, needed for a sysadmin.
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -PathExists { $true }
            Invoke-IgwtFirewallClassification -Rows $rows -Context (Get-IgwtFirewallClassificationContext -Role Sysadmin -InstalledPackages @() -Overrides $none)
            @(($rows | Where-Object Name -EQ 'RemoteDesktop-UserMode-In-TCP').Assessments) | Should -Not -Contain 'Bloated'
            @(($rows | Where-Object Name -EQ 'MCX-Var1-In-TCP').Assessments) | Should -Contain 'Bloated'
        }
    }

    It 'applies and persists user overrides: move to category, not bloated, ignored findings, role' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            $path = Join-Path $env:IGWT_GUI_STATE_DIR 'firewall-overrides.json'
            $null = Set-IgwtFirewallOverride -RuleId '{00000000-0000-0000-0003-000000000001}' -Category UserInstalled -Path $path
            $null = Set-IgwtFirewallOverride -RuleId 'MCX-Var1-In-TCP' -NotBloated -Path $path
            $null = Set-IgwtFirewallOverride -RuleId 'UnsignedTool' -IgnoreFinding 'unsigned-program' -Reason 'Built in-house' -Until (Get-Date).AddDays(30) -Path $path
            $o = Set-IgwtFirewallOverride -Role PowerUser -Path $path
            $o.Role | Should -Be 'PowerUser'
            { Set-IgwtFirewallOverride -IgnoreFinding 'x' -Path $path } | Should -Throw '*reason*'
            $o = Get-IgwtFirewallOverrides -Path $path
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -PathExists { $true }
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides $o
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $m = $rows | Where-Object Name -EQ '{00000000-0000-0000-0003-000000000001}'
            $m.Origin | Should -Be 'UserInstalled'; $m.OriginReason | Should -Match 'moved here by you'
            @(($rows | Where-Object Name -EQ 'MCX-Var1-In-TCP').Assessments) | Should -Not -Contain 'Bloated'
            Test-IgwtFirewallIgnored -Overrides $o -RuleId 'UnsignedTool' -RiskId 'unsigned-program' | Should -BeTrue
            Test-IgwtFirewallIgnored -Overrides $o -RuleId 'UnsignedTool' -RiskId 'unsigned-program' -Now (Get-Date).AddDays(31) | Should -BeFalse -Because 'the ignore expired'
            # Export and import round trip; unknown categories are refused.
            $exp = Join-Path $TestDrive 'overrides-export.json'
            $env:IGWT_GUI_STATE_DIR | Should -Not -BeNullOrEmpty
            Copy-Item $path (Join-Path $env:IGWT_GUI_STATE_DIR 'firewall-overrides.json') -ErrorAction SilentlyContinue
            $null = Export-IgwtFirewallOverrides -Path $exp
            (Get-Content $exp -Raw | ConvertFrom-Json).kind | Should -Be 'igwtFirewallOverrides'
            $badFile = Join-Path $TestDrive 'bad.json'
            '{ "kind": "igwtFirewallOverrides", "Role": "Gamer", "Categories": { "x": "Nonsense" } }' | Set-Content $badFile
            { Import-IgwtFirewallOverrides -Path $badFile } | Should -Throw '*Unknown category*'
            (Import-IgwtFirewallOverrides -Path $exp).Role | Should -Be 'PowerUser'
        }
    }

    It 'finds the package publisher of AppContainer rules from the rule ID or the group' {
        InModuleScope iGWindowsTuner {
            Get-IgwtFirewallPackagePublisher -Name 'Microsoft.XboxGamingOverlay_8wekyb3d8bbweS-1-5-21-1-1001-Out-Allow-AllCapabilities' | Should -Be '8wekyb3d8bbwe'
            Get-IgwtFirewallPackagePublisher -Group '@{Contoso.Notes_2.0.0.0_x64__a1b2c3d4e5f6g?ms-resource://Contoso.Notes/Resources/AppName}' | Should -Be 'a1b2c3d4e5f6g'
            Get-IgwtFirewallPackagePublisher -Name 'CoreNet-DHCP-In' | Should -Be ''
        }
    }

    It 'classifies 1,000 rules within the budget (under 5 s cold, under 1 s once cached)' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -PathExists { $true }
            $none = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Signatures $Fx.Signatures -Overrides $none
            Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
            $sw.Stop()
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
        }
    }
}
