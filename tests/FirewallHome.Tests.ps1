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

    It 'shows a recent change as a real row with a working Undo tag, not as a type name' {
        InModuleScope iGWindowsTuner {
            $snap = [pscustomobject]@{ Path = 'C:\demo\snapshot-1.json'; Created = [datetime]'2026-11-01T10:00:00'; Detail = 'Disabled 4 rules' }
            $list = New-Object System.Windows.Controls.ItemsControl
            Set-IgwtGuiFirewallRecentRows -List $list -Snapshots @($snap)
            $list.Measure((New-Object System.Windows.Size(600, 200)))
            $list.Arrange((New-Object System.Windows.Rect(0, 0, 600, 200)))
            $list.UpdateLayout()
            # A wrapped item would get a ContentPresenter that prints its type name; a real element is its own container.
            $container = $list.ItemContainerGenerator.ContainerFromIndex(0)
            $container | Should -BeOfType System.Windows.Controls.DockPanel
            $button = @($container.Children | Where-Object { $_ -is [System.Windows.Controls.Button] })[0]
            $button.Tag | Should -Be 'C:\demo\snapshot-1.json'
            @($container.Children | Where-Object { $_ -is [System.Windows.Controls.TextBlock] })[0].Text | Should -Match 'Disabled 4 rules'
            @((Find-IgwtGuiRenderedLeak -Root $list).Leaks).Count | Should -Be 0
            # Filling it again replaces the rows.
            Set-IgwtGuiFirewallRecentRows -List $list -Snapshots @($snap, $snap)
            $list.Items.Count | Should -Be 2
            Set-IgwtGuiFirewallRecentRows -List $list
            $list.Items.Count | Should -Be 0
        }
    }
}

Describe 'Render gate: text that leaks a type name' {
    It 'flags <Text>' -ForEach @(
        @{ Text = 'System.Windows.Controls.DockPanel' }
        @{ Text = 'System.Windows.Controls.Button: Undo' }
        @{ Text = 'System.Object[]' }
        @{ Text = 'Ports: System.Object[]' }
        @{ Text = 'System.String[]' }
        @{ Text = 'System.Collections.Hashtable' }
        @{ Text = 'Result: System.Collections.Generic.List`1[System.Object]' }
        @{ Text = 'System.Management.Automation.PSCustomObject' }
        @{ Text = 'System.__ComObject' }
        @{ Text = 'Microsoft.PowerShell.Commands.MatchInfo' }
        @{ Text = 'Microsoft.Management.Infrastructure.CimInstance' }
        @{ Text = '@{Id=1; Name=x}' }
        @{ Text = '@{}' }
        @{ Text = 'PSCustomObject' }
        @{ Text = "First line`r`nSystem.Windows.Controls.Border" }
    ) {
        InModuleScope iGWindowsTuner -Parameters @{ T = $Text } { param($T); Get-IgwtGuiTextLeakRule -Text $T | Should -Not -BeNullOrEmpty }
    }

    It 'passes <Text>' -ForEach @(
        @{ Text = '' }
        @{ Text = 'System' }
        @{ Text = 'System and diagnostics' }
        @{ Text = 'System Guard Secure Launch' }
        @{ Text = 'System.' }
        @{ Text = 'System.evtx' }
        @{ Text = 'System.Data.SQLite.dll' }
        @{ Text = 'C:\Windows\System32\drivers\etc\hosts' }
        @{ Text = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' }
        @{ Text = 'HKLM\Software\System.Windows.Controls.Foo' }
        @{ Text = 'This rule lets System services reach the network. See System.Net for details.' }
        @{ Text = 'Microsoft.PowerShell' }
        @{ Text = 'Microsoft.PowerShell.Preview' }
        @{ Text = 'Microsoft.PowerShell_8wekyb3d8bbwe' }
        @{ Text = '@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}' }
        @{ Text = '@FirewallAPI.dll,-25000' }
        @{ Text = 'Use a PSCustomObject when you script this' }
    ) {
        InModuleScope iGWindowsTuner -Parameters @{ T = $Text } { param($T); Get-IgwtGuiTextLeakRule -Text $T | Should -BeNullOrEmpty }
    }

    It 'finds a leak anywhere in a rendered tree and skips what is not visible' {
        InModuleScope iGWindowsTuner {
            $panel = New-Object System.Windows.Controls.StackPanel
            $clean = New-Object System.Windows.Controls.TextBlock; $clean.Text = 'Fine'
            $box = New-Object System.Windows.Controls.TextBox; $box.Text = 'System.Object[]'
            $hidden = New-Object System.Windows.Controls.TextBlock; $hidden.Text = 'System.Collections.Hashtable'; $hidden.Visibility = 'Collapsed'
            $button = New-Object System.Windows.Controls.Button; $button.Content = '@{Id=1}'
            # The bug itself: an array of function output keeps the PSObject wrapper around each element.
            $wrapped = New-Object System.Windows.Controls.ItemsControl; $wrapped.Name = 'WrappedList'
            $wrapped.ItemsSource = @(1 | ForEach-Object { New-Object System.Windows.Controls.DockPanel })
            $plain = New-Object System.Windows.Controls.ListBox; $plain.Name = 'PlainList'; $plain.ItemsSource = @([pscustomobject]@{ Id = 7 })
            $none = New-Object System.Windows.Controls.ItemsControl; $none.Name = 'EmptyOne'
            foreach ($e in @($clean, $box, $hidden, $button, $wrapped, $plain, $none)) { $null = $panel.Children.Add($e) }
            $panel.Measure((New-Object System.Windows.Size(600, 400)))
            $panel.Arrange((New-Object System.Windows.Rect(0, 0, 600, 400)))
            $panel.UpdateLayout()
            $r = Find-IgwtGuiRenderedLeak -Root $panel
            $texts = @($r.Leaks | ForEach-Object { $_.Text })
            $texts | Should -Contain 'System.Object[]'
            $texts | Should -Contain '@{Id=1}'
            $texts | Should -Contain 'System.Windows.Controls.DockPanel'
            $texts | Should -Contain '@{Id=7}'
            $texts | Should -Not -Contain 'System.Collections.Hashtable'
            $r.Checked | Should -BeGreaterThan 3
            $r.FilledLists | Should -Contain 'WrappedList'
            $r.EmptyLists | Should -Contain 'EmptyOne'
        }
    }

    It 'makes the render suite fail on a leak and on a text check that did not run' {
        $t = Get-Content (Join-Path $PSScriptRoot '..\tools\Test-GuiRender.ps1') -Raw
        $t | Should -Match 'text-leaks\.json'
        $t | Should -Match '\$gateFailed\) \{ exit 1 \}'
        $t | Should -Match "requiredLists = @\('FwOvRecentList'"
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
