# 4.0 components (section 2, C2): src\Gui\Components.ps1, offscreen, no window.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

Describe '4.0 components' {
    BeforeAll {
        InModuleScope iGWindowsTuner {
            # A themed host, so styles and tokens resolve as in the window.
            $script:TestDict = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader(([xml](Get-Content -LiteralPath (Join-Path $script:IgwtModuleRoot 'Gui\Theme.xaml') -Raw)))))
            function script:Test-Host($el, [double]$Width = 1200) {
                $h = New-Object System.Windows.Controls.Border
                $h.Resources.MergedDictionaries.Add($script:TestDict)
                $null = Set-IgwtGuiTheme -Target $h -Name Dark
                $h.Child = $el
                $h.Measure([System.Windows.Size]::new($Width, [double]::PositiveInfinity)); $h.Arrange([System.Windows.Rect]::new(0, 0, $Width, $h.DesiredSize.Height)); $h.UpdateLayout()
                $h
            }
            function script:Get-Descendants($root) {
                $out = New-Object System.Collections.Generic.List[object]
                $q = New-Object System.Collections.Generic.Queue[object]; $q.Enqueue($root)
                while ($q.Count) { $n = $q.Dequeue(); $out.Add($n); foreach ($c in [System.Windows.LogicalTreeHelper]::GetChildren($n)) { if ($c -is [System.Windows.DependencyObject]) { $q.Enqueue($c) } } }
                $out
            }
        }
    }

    It 'names every button, toggle and switch for screen readers, with its object for repeated buttons' {
        InModuleScope iGWindowsTuner {
            $card = New-IgwtSessionCard -Title 'Competitive preset' -Meta 'Today' -Expanded -Steps @([pscustomobject]@{ Setting = 'Mouse acceleration'; Before = 'On'; After = 'Off'; Now = 'On'; Conflict = $true })
            $null = Test-Host $card
            $controls = @(Get-Descendants $card | Where-Object { $_ -is [System.Windows.Controls.Primitives.ButtonBase] })
            $controls.Count | Should -BeGreaterOrEqual 3
            foreach ($c in $controls) { [System.Windows.Automation.AutomationProperties]::GetName($c) | Should -Not -BeNullOrEmpty }
            @($controls | ForEach-Object { [System.Windows.Automation.AutomationProperties]::GetName($_) }) | Should -Contain 'Undo Competitive preset'
            @($controls | ForEach-Object { [System.Windows.Automation.AutomationProperties]::GetName($_) }) | Should -Contain 'Keep the current value (Mouse acceleration)'
            $row = New-IgwtSettingRow -Name 'Game Mode' -Hint 'Lets Windows give the game priority.' -IsOn $true
            [System.Windows.Automation.AutomationProperties]::GetName($row.Tag) | Should -Be 'Game Mode'
            [System.Windows.Automation.AutomationProperties]::GetHelpText($row.Tag) | Should -Match 'priority'
        }
    }
    It 'keeps buttons at least 44 px tall and chips at least 36 px' {
        InModuleScope iGWindowsTuner {
            foreach ($k in 'Primary', 'Secondary', 'Subtle', 'Danger') {
                $b = New-IgwtUiButton -Text 'Go' -Kind $k
                $null = Test-Host $b
                $b.ActualHeight | Should -BeGreaterOrEqual 44 -Because "$k button"
            }
            $chips = New-IgwtChipGroup -Labels 'All', 'Input'
            $null = Test-Host $chips
            foreach ($c in $chips.Children) { $c.ActualHeight | Should -BeGreaterOrEqual 36 }
        }
    }
    It 'shows status as a word, not colour alone (pill, switch state)' {
        InModuleScope iGWindowsTuner {
            $p = New-IgwtPill -Text 'Changed since' -Tone Warning
            @(Get-Descendants $p | Where-Object { $_ -is [System.Windows.Controls.TextBlock] -and $_.Text -eq 'Changed since' }).Count | Should -Be 1
            $row = New-IgwtSettingRow -Name 'Game Mode' -IsOn $false
            $sw = $row.Tag
            $sw.Tag.Text | Should -Be 'Off'
            $sw.IsChecked = $true
            $sw.Tag.Text | Should -Be 'On'
        }
    }
    It 'announces info bars politely and gives the page title a heading level' {
        InModuleScope iGWindowsTuner {
            $ib = New-IgwtInfoBar -Title 'Restart needed' -Message '2 changes take effect after a restart.' -Tone Warning
            [System.Windows.Automation.AutomationProperties]::GetLiveSetting($ib) | Should -Be ([System.Windows.Automation.AutomationLiveSetting]::Polite)
            $hdr = New-IgwtPageHeader -Title 'Optimize' -Subtitle 'Settings'
            $title = @(Get-Descendants $hdr | Where-Object { $_ -is [System.Windows.Controls.TextBlock] -and $_.Text -eq 'Optimize' })[0]
            [System.Windows.Automation.AutomationProperties]::GetHeadingLevel($title) | Should -Be ([System.Windows.Automation.AutomationHeadingLevel]::Level1)
        }
    }
    It 'makes single-choice chips exclusive' {
        InModuleScope iGWindowsTuner {
            $g = New-IgwtChipGroup -Labels 'All', 'Input', 'System' -Selected 'All' -Single
            $g.Children[2].IsChecked = $true
            @($g.Children | Where-Object { $_.IsChecked }).Count | Should -Be 1
            $g.Children[2].IsChecked | Should -BeTrue
        }
    }
    It 'puts the details beside the list at 1100 px and more, and below it under 1100 px (no fixed column)' {
        InModuleScope iGWindowsTuner {
            $main = New-Object System.Windows.Controls.TextBlock; $main.Text = 'list'
            $det = New-Object System.Windows.Controls.TextBlock; $det.Text = 'details'
            $g = New-IgwtSplitView -Main $main -Details $det
            Set-IgwtSplitLayout -Grid $g -Width 1280 | Should -Be 'Side'
            $g.ColumnDefinitions.Count | Should -Be 2
            Set-IgwtSplitLayout -Grid $g -Width 900 | Should -Be 'Sheet'
            $g.ColumnDefinitions.Count | Should -Be 0
            [System.Windows.Controls.Grid]::GetRow($g.Tag.Panel) | Should -Be 1
            # The layout follows the real width when the grid is laid out.
            $null = Test-Host $g -Width 1000
            $g.Tag.Mode | Should -Be 'Sheet'
            $null = Test-Host (New-IgwtSplitView -Main (New-Object System.Windows.Controls.TextBlock) -Details (New-Object System.Windows.Controls.TextBlock)) -Width 1300
        }
    }
}
