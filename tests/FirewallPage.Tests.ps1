BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

# The Firewall page's rule dialog, built without showing it (no window is opened).
Describe 'Firewall page: rule dialog (headless)' {
    BeforeEach {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { return }
        InModuleScope iGWindowsTuner {
            $script:TestMain = New-IgwtMainWindow
            $null = Set-IgwtGuiTheme -Target $script:TestMain -Name Dark
            $script:Gui = @{ Window = $script:TestMain; ViewState = @{}; NoStateSave = $true; ReadOnly = $false; IsAdmin = $true }
            $w = New-Object System.Windows.Window
            Copy-IgwtGuiResources -Target $w
            $root = [Windows.Markup.XamlReader]::Parse((Get-IgwtGuiFirewallRuleDialogXaml))
            $w.Content = $root
            $f = @{}
            foreach ($n in 'StepText', 'TitleText', 'Step1', 'Step2', 'Step3', 'Step4', 'Step5', 'TemplateBox', 'NameBox', 'BrowseButton', 'ProgramBox', 'DescBox', 'DirIn', 'DirOut', 'ActAllow', 'ActBlock', 'ProtoBox', 'LocalPortBox', 'RemotePortBox',
                'ProfPrivate', 'ProfPublic', 'ProfDomain', 'ProfileHint', 'RemoteAddrBox', 'SummaryText', 'ErrorBox', 'ErrorText', 'CancelButton', 'BackButton', 'NextButton') { $f[$n] = $root.FindName($n) }
            $f.ProtoBox.ItemsSource = @('Any', 'TCP', 'UDP', 'ICMPv4', 'ICMPv6'); $f.ProtoBox.SelectedItem = 'TCP'
            $templates = @(Get-IgwtFirewallRuleTemplates)
            $f.TemplateBox.ItemsSource = @(@('Custom rule') + @($templates | ForEach-Object { $_.Name }))
            $f.ProfPrivate.IsChecked = $true
            $script:IgwtFwDlg = @{ F = $f; Step = 1; Result = $null; Mode = 'New'; W = $w; Templates = $templates; Rule = $null }
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:IgwtFwDlg = $null; $script:Gui = $null } }

    It 'has every control the dialog code uses' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner { foreach ($k in @($script:IgwtFwDlg.F.Keys)) { $script:IgwtFwDlg.F[$k] | Should -Not -BeNullOrEmpty -Because $k } }
    }

    It 'walks the five steps, keeps values when going back and validates before moving on' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $d = $script:IgwtFwDlg; $f = $d.F
            Show-IgwtGuiFirewallDialogStep -Step 1
            Invoke-IgwtGuiFirewallDialogNext
            $d.Step | Should -Be 1
            $f.ErrorBox.Visibility | Should -Be 'Visible'
            $f.NameBox.Text = 'My game'; $f.ProgramBox.Text = 'C:\Games\g.exe'
            Invoke-IgwtGuiFirewallDialogNext; $d.Step | Should -Be 2
            $f.ActAllow.IsChecked = $true
            Invoke-IgwtGuiFirewallDialogNext; $d.Step | Should -Be 3
            $f.ProtoBox.SelectedItem = 'UDP'; $f.LocalPortBox.Text = '99999'
            Invoke-IgwtGuiFirewallDialogNext
            $d.Step | Should -Be 3 -Because 'an invalid port stops the wizard'
            $f.ErrorText.Text | Should -Match 'port'
            $f.LocalPortBox.Text = '27015-27030'
            Invoke-IgwtGuiFirewallDialogNext; $d.Step | Should -Be 4
            $f.BackButton.IsEnabled | Should -BeTrue
            Show-IgwtGuiFirewallDialogStep -Step 2
            $f.NameBox.Text | Should -Be 'My game'
            Show-IgwtGuiFirewallDialogStep -Step 4
            $f.ProfPublic.IsChecked = $true; $f.ProfDomain.IsChecked = $true
            Invoke-IgwtGuiFirewallDialogNext; $d.Step | Should -Be 5
            $f.SummaryText.Text | Should -Match 'local ports 27015-27030'
            Invoke-IgwtGuiFirewallDialogNext
            $d.Result.DisplayName | Should -Be 'My game'
            $d.Result.Protocol | Should -Be 'UDP'
            $d.Result.Profiles | Should -Be @('Any')
            $d.Result.Direction | Should -Be 'Inbound'
        }
    }

    It 'fills the wizard from a template' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $f = $script:IgwtFwDlg.F
            $ids = @(@($script:IgwtFwDlg.Templates) | ForEach-Object { $_.Id })
            $f.TemplateBox.SelectedIndex = [array]::IndexOf($ids, 'block-app-out') + 1   # block a program outbound (index 0 is Custom rule)
            Use-IgwtGuiFirewallTemplate
            $f.DirOut.IsChecked | Should -BeTrue
            $f.ActBlock.IsChecked | Should -BeTrue
            $f.NameBox.Text | Should -Match 'Block'
            (Get-IgwtGuiFirewallDialogSettings).Profiles | Should -Be @('Any')
        }
    }

    It 'returns only what changed when editing, and keeps direction and action out of the form' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $d = $script:IgwtFwDlg; $f = $d.F
            $rule = [pscustomobject]@{ DisplayName = 'Voice'; Description = ''; Program = 'C:\V\v.exe'; Protocol = 'UDP'; LocalPort = '3478'; RemotePort = 'Any'; RemoteAddress = 'Any'; Profiles = 'Private'; ProfileList = @('Private'); Direction = 'Inbound'; Action = 'Allow' }
            $d.Mode = 'Edit'; $d.Rule = $rule
            $f.NameBox.Text = 'Voice'; $f.ProgramBox.Text = 'C:\V\v.exe'; $f.ProtoBox.SelectedItem = 'UDP'; $f.LocalPortBox.Text = '3478'; $f.ProfPrivate.IsChecked = $true
            Invoke-IgwtGuiFirewallDialogNext
            $d.Result | Should -BeNullOrEmpty
            $f.ErrorText.Text | Should -Match 'Nothing was changed'
            $f.LocalPortBox.Text = '3478-3480'
            Invoke-IgwtGuiFirewallDialogNext
            @($d.Result.Keys | Sort-Object) | Should -Be @('LocalPort', 'Protocol')
            $d.Result.LocalPort | Should -Be '3478-3480'
        }
    }
}

Describe 'Firewall page: actions in read-only mode' {
    It 'blocks every rule action in read-only mode with the reason' {
        InModuleScope iGWindowsTuner {
            $script:Gui = @{ ReadOnly = $true; IsAdmin = $true }
            try {
                $row = [pscustomobject]@{ Rule = [pscustomobject]@{ Name = 'x'; Source = 'ThirdParty'; Locked = $false } }
                foreach ($a in @(@{ Id = 'enable'; Changes = $true; Bulk = $true }, @{ Id = 'delete'; Changes = $true; Bulk = $true; Danger = $true })) { Get-IgwtGridActionBlock -Action $a -Rows @($row) | Should -Match 'Read-only' }
            } finally { $script:Gui = $null }
        }
    }
}
