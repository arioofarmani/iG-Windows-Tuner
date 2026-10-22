# GUI layout rules that do not need a window: Manage list sorting, the ASR Center as part of
# Security in the navigation, and the dashboard and Manage controls in the XAML.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Xaml = [xml](Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw)
    $script:Ns = New-Object System.Xml.XmlNamespaceManager($script:Xaml.NameTable)
    $script:Ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
}

Describe 'GUI layout' {
    It 'sorts Manage rows by text and by number, both directions, and leaves them unsorted by default' {
        InModuleScope iGWindowsTuner {
            $rows = @(
                [pscustomobject]@{ Title = 'beta'; Badge = 'Win32'; State = '120 MB' },
                [pscustomobject]@{ Title = 'Alpha'; Badge = 'Appx'; State = '9 MB' },
                [pscustomobject]@{ Title = 'gamma'; Badge = 'Win32'; State = '15 MB' })
            $script:Gui = [pscustomobject]@{ ManageSort = @{} }
            @(ConvertTo-IgwtGuiSortedRows -Rows $rows -Tab 'App' | ForEach-Object { $_.Title }) | Should -Be @('beta', 'Alpha', 'gamma')
            $script:Gui.ManageSort['App'] = [pscustomobject]@{ Key = 'Title'; Descending = $false }
            @(ConvertTo-IgwtGuiSortedRows -Rows $rows -Tab 'App' | ForEach-Object { $_.Title }) | Should -Be @('Alpha', 'beta', 'gamma')
            $script:Gui.ManageSort['App'] = [pscustomobject]@{ Key = 'State'; Descending = $false }
            @(ConvertTo-IgwtGuiSortedRows -Rows $rows -Tab 'App' | ForEach-Object { $_.State }) | Should -Be @('9 MB', '15 MB', '120 MB')
            $script:Gui.ManageSort['App'] = [pscustomobject]@{ Key = 'State'; Descending = $true }
            @(ConvertTo-IgwtGuiSortedRows -Rows $rows -Tab 'App' | ForEach-Object { $_.State }) | Should -Be @('120 MB', '15 MB', '9 MB')
            $script:Gui.ManageSort['App'] = [pscustomobject]@{ Key = 'Badge'; Descending = $false }
            $sorted = ConvertTo-IgwtGuiSortedRows -Rows $rows -Tab 'App'; $sorted[0].Badge | Should -Be 'Appx'
            $script:Gui = $null
        }
    }
    It 'has a sortable header for every column of every Manage tab' {
        $tags = @($script:Xaml.SelectNodes("//w:Button[starts-with(@Tag,'sort:')]", $script:Ns) | ForEach-Object { $_.Tag })
        foreach ($tab in 'Service', 'Task', 'App', 'Persist', 'Firewall') { foreach ($col in 'Title', 'Badge', 'State') { $tags | Should -Contain "sort:${tab}:$col" } }
    }
    It 'shows the ASR Center and the Defender settings directly under Security in the navigation and in every persona' {
        $nav = @($script:Xaml.SelectNodes("//w:ListBox[@*[local-name()='Name']='NavList']/w:ListBoxItem", $script:Ns) | ForEach-Object { $_.Tag })
        $nav[[array]::IndexOf($nav, 'Security') + 1] | Should -Be 'Asr'
        $nav[[array]::IndexOf($nav, 'Security') + 2] | Should -Be 'Defender'
        foreach ($p in 'Gamer', 'PowerUser', 'Sysadmin') {
            $order = @((InModuleScope iGWindowsTuner -Parameters @{ P = $p } { param($P) Get-IgwtPersonaProfile -Name $P }).NavOrder)
            if ($order.Count) { $order[[array]::IndexOf($order, 'Security') + 1] | Should -Be 'Asr' -Because $p; $order[[array]::IndexOf($order, 'Security') + 2] | Should -Be 'Defender' -Because $p }
        }
    }
    It 'defines every Defender page control the GUI code uses and builds its rows' {
        $names = @($script:Xaml.SelectNodes("//*[@*[local-name()='Name']]") | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') })
        $list = InModuleScope iGWindowsTuner { $script:IgwtGuiControlNames }
        foreach ($n in @($list | Where-Object { $_ -like 'Def*' -or $_ -in 'PageDefender', 'SecDefenderButton', 'AsrDefenderButton' })) { $names | Should -Contain $n }
        InModuleScope iGWindowsTuner {
            $row = New-IgwtGuiDefenderRow -Setting ([pscustomobject]@{ Property = 'CloudBlockLevel'; Name = 'Cloud block level'; Hint = 'h'; CategoryName = 'Cloud protection'; Edit = 'set'; Editable = $true; Source = 'Local'; Display = 'Default'; Status = 'Below'; ProtectiveDisplay = 'High' })
            $row.EditText | Should -Be 'Changeable'; $row.RecommendText | Should -Be 'Recommended: High'; $row.SourceVisibility | Should -Be 'Collapsed'
            $row = New-IgwtGuiDefenderRow -Setting ([pscustomobject]@{ Property = 'PUAProtection'; Name = 'PUA'; Hint = 'h'; CategoryName = 'PUA'; Edit = 'set'; Editable = $false; Source = 'MDM'; Display = 'Block'; Status = 'On'; ProtectiveDisplay = 'Block' })
            $row.EditText | Should -Be 'Set by MDM'; $row.RecommendText | Should -Be 'Meets recommendation'; $row.SourceVisibility | Should -Be 'Visible'
            $p = New-IgwtGuiDefenderPolicyRow -Policy ([pscustomobject]@{ Id = 'WindowsDefender:Scan_DisableHeuristics'; Name = 'Turn on heuristics'; Category = 'Windows Components > Microsoft Defender Antivirus > Scan'; State = 'NotConfigured'; Source = 'Not configured'; Preference = ''; Simple = $true; Refused = @('Disabled: Turns off a Defender scanning component.') })
            $p.StateText | Should -Be 'Not configured'; $p.RefusedText | Should -Be 'Refused: Disabled'; $p.CategoryText | Should -Be 'Microsoft Defender Antivirus > Scan'; $p.PreferenceVisibility | Should -Be 'Collapsed'
        }
    }
    It 'defines every named dashboard control the GUI code uses' {
        $names = @($script:Xaml.SelectNodes("//*[@*[local-name()='Name']]") | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') })
        $list = InModuleScope iGWindowsTuner { $script:IgwtGuiControlNames }
        foreach ($n in @($list | Where-Object { $_ -like 'Dash*' -or $_ -in 'SecuritySwitch', 'SecAsrButton', 'AsrHardeningButton' })) { $names | Should -Contain $n }
    }
}
