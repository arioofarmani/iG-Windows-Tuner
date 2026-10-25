BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:Fx = New-IgwtFirewallFixture
    $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'state'
}
AfterAll { Remove-Item Env:\IGWT_GUI_STATE_DIR -ErrorAction SilentlyContinue }

# Firewall Manager 3.4 performance budgets (SPEC-v3.4 section 2.2 and DECISIONS F9) on the 1,000+ rule
# synthetic fixture: the whole analysis stays well inside what a background runspace can do while the
# window is open. Budgets are generous for slow CI machines; the measured values are in PROGRESS.md.
Describe 'Firewall analysis performance' {
    It 'analyses 1,000+ rules (findings, conflicts, summary, exposure) in under 10 s and a scope plan in under 5 s' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            Mock Get-IgwtSnapshotList { @() }
            Mock Get-IgwtFirewallInstalledPackages { @() }
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $inv = [pscustomobject]@{ Rules = $rows; Count = $rows.Count; Partial = $false; Notes = @(); LoadMs = 0 }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $a = Get-IgwtFirewallAudit -Role Gamer -Inventory $inv -Listeners @() -InstalledPackages @() -DefaultRules @{} -Signatures $Fx.Signatures
            $audit = $sw.Elapsed.TotalSeconds
            $a.Count | Should -BeGreaterOrEqual 1000
            $audit | Should -BeLessThan 10 -Because "the audit of $($a.Count) rules took $([math]::Round($audit, 2)) s"
            $sw.Restart()
            $plan = Get-IgwtFirewallScopePlan -Scope 'sysadmin-hardened' -Rows $a.Rules -Signatures $Fx.Signatures -RemoteSession $false
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
            $plan.Count | Should -BeGreaterThan 0
        }
    }

    It 'compares 1,000+ rules with the defaults and matches 500 connections in under 2 s each' {
        InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
            param($Fx)
            Mock Get-Process { @() }
            Mock Get-CimInstance { @() }
            $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -InterfaceFilters $Fx.Ift -PathExists { param($p) -not $Fx.Missing.Contains($p) }
            $d = @{}; foreach ($r in @($rows | Select-Object -First 400)) { $d[[string]$r.Name] = [pscustomobject]@{ Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; Enabled = -not [bool]$r.Enabled; Direction = [string]$r.Direction; Action = [string]$r.Action; Profile = [string]$r.Profiles; Source = 'SystemDefaults' } }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $c = @(Compare-IgwtFirewallDefaults -Rows $rows -Defaults $d)
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 2
            @($c | Where-Object Change -EQ 'Modified').Count | Should -Be 400
            $conn = @(1..500 | ForEach-Object { [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '192.168.1.5'; LocalPort = 40000 + $_; RemoteAddress = '203.0.113.1'; RemotePort = 443; State = 'Established'; ProcessId = $_ } })
            $sw.Restart()
            $m = @(Get-IgwtFirewallConnections -Rows $rows -Connections $conn -ListenPorts @())
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 2 -Because "matching took $([math]::Round($sw.Elapsed.TotalSeconds, 2)) s"
            $m.Count | Should -Be 500
        }
    }
}
