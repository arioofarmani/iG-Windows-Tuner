BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:None = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
    # Small rule set for the precedence cases: [id, program, action, protocol, ports, profile, remote, windows group]
    $script:Cases = @(
        ,@('Shadowed-Allow', 'C:\Program Files\Shadow\app.exe', 'Allow', 'TCP', '6000', 'Private', 'LocalSubnet', '')
        ,@('Shadow-Block', 'C:\Program Files\Shadow\app.exe', 'Block', 'TCP', '6000-6010', 'Any', 'Any', '')
        ,@('Broad-Allow', 'C:\Program Files\Wide\app.exe', 'Allow', 'TCP', '7000-7100', 'Private', 'LocalSubnet', '')
        ,@('Narrow-Allow', 'C:\Program Files\Wide\app.exe', 'Allow', 'TCP', '7050', 'Private', 'LocalSubnet', '')
        ,@('Conflict-Allow', 'C:\Program Files\Mixed\app.exe', 'Allow', 'TCP', '8000-8100', 'Private', 'LocalSubnet', '')
        ,@('Conflict-Block', 'C:\Program Files\Mixed\app.exe', 'Block', 'TCP', '8050-8200', 'Private', 'LocalSubnet', '')
        ,@('Twin-A', 'C:\Program Files\Twin\app.exe', 'Allow', 'UDP', '9000', 'Private', 'LocalSubnet', '')
        ,@('Twin-B', 'C:\Program Files\Twin\app.exe', 'Allow', 'UDP', '9000', 'Private', 'LocalSubnet', '')
        ,@('Other-Protocol', 'C:\Program Files\Shadow\app.exe', 'Allow', 'UDP', '6000', 'Private', 'LocalSubnet', '')
        ,@('Block-Port-For-All', 'Any', 'Block', 'TCP', '7777', 'Any', 'Any', '')
        ,@('Program-7777', 'C:\Program Files\Seven\app.exe', 'Allow', 'TCP', '7777', 'Private', 'LocalSubnet', '')
        ,@('Win-A', 'Any', 'Allow', 'TCP', '445', 'Private', 'LocalSubnet', '@FirewallAPI.dll,-28502')
        ,@('Win-B', 'Any', 'Allow', 'TCP', '445', 'Private', 'LocalSubnet', '@FirewallAPI.dll,-28502')
    )
    function script:New-CaseRows {
        $rules = @(); $app = @(); $port = @(); $addr = @()
        foreach ($c in $script:Cases) {
            $rules += [pscustomobject]@{ Name = $c[0]; InstanceID = $c[0]; DisplayName = $c[0]; Group = $c[7]; DisplayGroup = ''; Enabled = 'True'; Direction = 'Inbound'; Action = $c[2]; Profile = $c[5]; EdgeTraversalPolicy = 'Block'; Owner = ''; PolicyStoreSource = 'PersistentStore'; PolicyStoreSourceType = 'Local'; Description = 'case' }
            if ($c[1] -ne 'Any') { $app += [pscustomobject]@{ InstanceID = $c[0]; Program = $c[1]; Package = '' } }
            $port += [pscustomobject]@{ InstanceID = $c[0]; Protocol = $c[3]; LocalPort = $c[4]; RemotePort = 'Any' }
            $addr += [pscustomobject]@{ InstanceID = $c[0]; LocalAddress = 'Any'; RemoteAddress = $c[6] }
        }
        return @{ Rules = $rules; App = $app; Port = $port; Addr = $addr }
    }
}

# Firewall Manager 3.4 conflict and precedence analysis (SPEC-v3.4 section 2.4, DECISIONS F3).
Describe 'Firewall precedence and conflicts' {
    It 'finds shadowed, redundant and conflicting rules with a plain explanation' {
        $set = New-CaseRows
        InModuleScope iGWindowsTuner -Parameters @{ Set = $set; None = $script:None } {
            param($Set, $None)
            $rows = Join-IgwtFirewallData -Rules $Set.Rules -ApplicationFilters $Set.App -PortFilters $Set.Port -AddressFilters $Set.Addr -PathExists { $true }
            Invoke-IgwtFirewallClassification -Rows $rows -Context (Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides $None)
            $rel = @(Get-IgwtFirewallConflicts -Rows $rows)
            $get = { param($n) $rows | Where-Object Name -EQ $n }
            (& $get 'Shadowed-Allow').Shadowed | Should -BeTrue
            @((& $get 'Shadowed-Allow').ShadowedBy) | Should -Be @('Shadow-Block')
            (& $get 'Shadowed-Allow').PrecedenceText | Should -Match 'never applies'
            (& $get 'Shadow-Block').Shadowed | Should -BeFalse
            (& $get 'Narrow-Allow').Redundant | Should -BeTrue
            (& $get 'Broad-Allow').Redundant | Should -BeFalse
            @((& $get 'Conflict-Allow').Conflicts) | Should -Be @('Conflict-Block')
            (& $get 'Conflict-Allow').PrecedenceText | Should -Match 'Partly blocked'
            (& $get 'Conflict-Allow').Shadowed | Should -BeFalse
            # Identical rules: only the second one (by name) is reported as redundant.
            (& $get 'Twin-B').Redundant | Should -BeTrue
            (& $get 'Twin-A').Redundant | Should -BeFalse
            (& $get 'Other-Protocol').Shadowed | Should -BeFalse -Because 'UDP is not covered by a TCP block'
            # Two Windows rules are never compared (settings the inventory does not read).
            (& $get 'Win-B').Redundant | Should -BeFalse
            # An any-program block shadows a program's allow on the same port.
            @((& $get 'Program-7777').ShadowedBy) | Should -Be @('Block-Port-For-All')
            @($rel | Where-Object Kind -EQ 'Shadowed').Count | Should -Be 2
        }
    }

    It 'compares rule dimensions: any covers everything, port ranges and keywords' {
        InModuleScope iGWindowsTuner {
            Test-IgwtFirewallSetCovers -A 'Any' -B '445' | Should -BeTrue
            Test-IgwtFirewallSetCovers -A '445' -B 'Any' | Should -BeFalse
            Test-IgwtFirewallSetCovers -A '445' -B 'Any' -Mode Overlaps | Should -BeTrue
            Test-IgwtFirewallSetCovers -A '1000-2000' -B '1500, 1600' -Ports | Should -BeTrue
            Test-IgwtFirewallSetCovers -A '1000-2000' -B '1500-2500' -Ports | Should -BeFalse
            Test-IgwtFirewallSetCovers -A '1000-2000' -B '1500-2500' -Ports -Mode Overlaps | Should -BeTrue
            Test-IgwtFirewallSetCovers -A 'RPC' -B 'RPC' -Ports | Should -BeTrue
            Test-IgwtFirewallSetCovers -A 'RPC' -B '135' -Ports -Mode Overlaps | Should -BeFalse
        }
    }

    It 'does not compare rules whose filters could not be read' {
        InModuleScope iGWindowsTuner {
            $a = [pscustomobject]@{ Program = 'Any'; Service = 'Any'; Package = '|'; Protocol = '?'; LocalPort = ''; RemoteAddress = ''; IcmpType = ''; Profiles = 'Any'; Interface = 'Any' }
            Test-IgwtFirewallScopeRelation -A $a -B $a | Should -Be ''
        }
    }

    It 'analyses 1,000+ rules within the budget' {
        # In a clean process: after a thousand tests and many module reloads this process runs the same
        # code about 3.5 times slower (0.9 s alone, 3.1 s here), so a timing here measures the suite.
        $child = Join-Path $TestDrive 'firewall-budget.ps1'
        $body = @"
`$ErrorActionPreference = 'Stop'
Import-Module '$(Join-Path $PSScriptRoot '..\src\iGWindowsTuner.psd1')' -Force
Set-IgwtEnvironment -TestMode -DataRoot '$(Join-Path $TestDrive 'IgwtBudget')'
. '$(Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')'
`$fx = New-IgwtFirewallFixture
`$none = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
& (Get-Module iGWindowsTuner) {
    param(`$fx, `$None)
    `$rows = Join-IgwtFirewallData -Rules `$fx.Rules -ApplicationFilters `$fx.App -PortFilters `$fx.Port -AddressFilters `$fx.Addr -ServiceFilters `$fx.Svc -PathExists { `$true }
    Invoke-IgwtFirewallClassification -Rows `$rows -Context (Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides `$None)
    if (@(`$rows).Count -lt 1000) { throw 'The fixture has fewer than 1,000 rules.' }
    [GC]::Collect()
    `$sw = [System.Diagnostics.Stopwatch]::StartNew()
    `$null = Get-IgwtFirewallConflicts -Rows `$rows
    'SECONDS=' + `$sw.Elapsed.TotalSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)
} `$fx `$none
"@
        Set-Content -LiteralPath $child -Value $body -Encoding UTF8
        $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $child 2>&1 | ForEach-Object { "$_" }
        $line = @($out | Where-Object { $_ -like 'SECONDS=*' }) | Select-Object -Last 1
        $line | Should -Not -BeNullOrEmpty -Because ($out -join ' ')
        [double]::Parse($line.Substring(8), [System.Globalization.CultureInfo]::InvariantCulture) | Should -BeLessThan 3
    }

}
