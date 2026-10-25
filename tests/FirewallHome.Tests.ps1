BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    . (Join-Path $PSScriptRoot 'fixtures\firewall\FirewallFixture.ps1')
    $script:Fx = New-IgwtFirewallFixture
    $script:Audit = InModuleScope iGWindowsTuner -Parameters @{ Fx = $script:Fx } {
        param($Fx)
        Mock Get-IgwtSnapshotList { @() }
        $rows = Join-IgwtFirewallData -Rules $Fx.Rules -ApplicationFilters $Fx.App -PortFilters $Fx.Port -AddressFilters $Fx.Addr -ServiceFilters $Fx.Svc -PathExists { param($p) -not $Fx.Missing.Contains($p) }
        Get-IgwtFirewallAudit -Role Gamer -Inventory ([pscustomobject]@{ Rules = $rows; Partial = $false; Notes = @(); LoadMs = 1 }) -Listeners @() -InstalledPackages @() -DefaultRules @{} -Signatures $Fx.Signatures
    }
}

# Firewall Manager 3.4 interface pieces (no window is shown) and the audit report.
Describe 'Firewall Manager home' {
    It 'lists All rules and the nine groups with live counts, icons and hints' {
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $items = @(Get-IgwtGuiFirewallGroupItems -Summary $A.Summary)
            $items.Count | Should -Be 10
            $items[0].Id | Should -Be 'All'
            $items[0].Count | Should -Be $A.Count
            ($items | Where-Object Id -EQ 'Bloated').Count | Should -Be $A.Summary.Groups.Bloated
            foreach ($i in $items) { $i.Glyph | Should -Not -BeNullOrEmpty; $i.Tip | Should -Not -BeNullOrEmpty }
        }
    }

    It 'previews a group change with what stops working and the skip reasons in the headline' {
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $rows = @($A.Rules | Where-Object { $_.Name -in 'MCX-Var1-In-TCP', 'CoreNet-DHCP-In', 'GPO-Corp-Block' })
            $plan = Get-IgwtFirewallChangePlan -Operation Disable -Rules $rows -RemoteSession $false
            $text = Format-IgwtGuiFirewallPlanText -Plan $plan -Label 'Disable all Bloated' -Rows $rows
            $text | Should -Match '^Disable all Bloated \(1\) - 2 skipped: '
            $text | Should -Match 'Core Services rule'
            $text | Should -Match 'Stops working: Streaming a legacy'
            $text | Should -Match 'Undo restores every rule exactly'
        }
    }

    It 'disables a finding''s change buttons in read-only mode and on locked rules, with the reason' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $w = New-IgwtMainWindow
            $null = Set-IgwtGuiTheme -Target $w -Name Dark
            $script:Gui = @{ Window = $w }
            try {
                $buttons = { param($card) @($card.Child.Children[2].Children) }
                $f = [pscustomobject]@{ RiskId = 'x'; Severity = 'High'; Title = 'T'; Explanation = 'E'; Recommended = 'Disable'; Alternatives = @('Keep', 'Ignore'); ExposedNow = $false; Ignored = $false; IgnoreReason = '' }
                $open = $A.Rules | Where-Object Name -EQ 'MCX-Var1-In-TCP'
                $locked = $A.Rules | Where-Object Name -EQ 'GPO-Corp-Block'
                (& $buttons (New-IgwtGuiFindingCard -Finding $f -ReadOnly $false -Rule $open))[0].IsEnabled | Should -BeTrue
                $ro = (& $buttons (New-IgwtGuiFindingCard -Finding $f -ReadOnly $true -Rule $open))[0]
                $ro.IsEnabled | Should -BeFalse; [string]$ro.ToolTip | Should -Match 'Read-only'
                $lk = (& $buttons (New-IgwtGuiFindingCard -Finding $f -ReadOnly $false -Rule $locked))[0]
                $lk.IsEnabled | Should -BeFalse; [string]$lk.ToolTip | Should -Match 'Group Policy'
                (& $buttons (New-IgwtGuiFindingCard -Finding $f -ReadOnly $true -Rule $open))[1].IsEnabled | Should -BeTrue -Because 'Keep changes nothing'
                $panel = New-Object System.Windows.Controls.StackPanel
                Set-IgwtGuiFirewallChart -Panel $panel -Bars @([pscustomobject]@{ Label = 'A'; Value = 3; Brush = $null }, [pscustomobject]@{ Label = 'B'; Value = 0; Brush = $null })
                $panel.Children.Count | Should -Be 2
            } finally { $script:Gui = $null }
        }
    }

    It 'shows exposure rows with a plain status' {
        InModuleScope iGWindowsTuner {
            (New-IgwtGuiExposureRow -Entry ([pscustomobject]@{ Key = 'k'; Protocol = 'TCP'; LocalPort = 3389; LocalAddress = '0.0.0.0'; Process = 'svchost'; Path = ''; Services = 'TermService'; Rules = 'RDP'; Profiles = 'All networks'; Status = 'Exposed'; Public = $true })).StatusCol | Should -Be 'Reachable (also on public networks)'
            (New-IgwtGuiExposureRow -Entry ([pscustomobject]@{ Key = 'k'; Protocol = 'UDP'; LocalPort = 5353; Status = 'Blocked'; Public = $false })).StatusCol | Should -Be 'Blocked by default'
        }
    }
}

Describe 'Firewall audit report' {
    It 'writes HTML (encoded, self-contained), CSV (one line per rule) and JSON' {
        InModuleScope iGWindowsTuner -Parameters @{ A = $script:Audit } {
            param($A)
            $r = $A.Rules | Where-Object Name -EQ 'UnsignedTool'
            $r.DisplayName = 'Tool <script>alert(1)</script>'
            $html = Join-Path $TestDrive 'audit.html'; $csv = Join-Path $TestDrive 'audit.csv'; $json = Join-Path $TestDrive 'audit.json'
            $null = Export-IgwtFirewallAuditReport -Audit $A -Path $html
            $t = Get-Content $html -Raw
            $t | Should -Match 'Tool &lt;script&gt;alert\(1\)&lt;/script&gt;'
            $t | Should -Not -Match '<script>'
            $t | Should -Match 'Quick wins'
            $null = Export-IgwtFirewallAuditReport -Audit $A -Path $csv
            @(Import-Csv $csv).Count | Should -Be $A.Count
            $null = Export-IgwtFirewallAuditReport -Audit $A -Path $json
            $j = Get-Content $json -Raw | ConvertFrom-Json
            $j.kind | Should -Be 'igwtFirewallAudit'
            @($j.rules).Count | Should -Be $A.Count
            { Export-IgwtFirewallAuditReport -Audit $A -Path (Join-Path $TestDrive 'audit.txt') } | Should -Throw '*.html, .csv or .json*'
        }
    }
}
