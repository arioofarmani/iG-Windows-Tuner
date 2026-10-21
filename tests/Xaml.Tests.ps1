BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'GUI XAML (headless)' {
    It 'Theme.xaml and MainWindow.xaml are well-formed XML' {
        $dir = Join-Path $script:IgwtProjectRoot 'src\Gui'
        { [xml](Get-Content (Join-Path $dir 'Theme.xaml') -Raw) } | Should -Not -Throw
        { [xml](Get-Content (Join-Path $dir 'MainWindow.xaml') -Raw) } | Should -Not -Throw
    }

    It 'parses into a WPF Window with every named control the GUI uses' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF parsing requires an STA thread (powershell.exe default).'; return }
        InModuleScope iGWindowsTuner {
            $w = New-IgwtMainWindow
            $w | Should -BeOfType System.Windows.Window
            foreach ($n in $script:IgwtGuiControlNames) { $w.FindName($n) | Should -Not -BeNullOrEmpty -Because "control $n" }
            $w.MinWidth | Should -Be 1100
            $w.MinHeight | Should -Be 720
        }
    }

    It 'defines the theme resources referenced by the window' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'STA required'; return }
        InModuleScope iGWindowsTuner {
            $w = New-IgwtMainWindow
            foreach ($k in 'BrushBackground', 'BrushAccent', 'ToggleSwitch', 'AccentButton', 'NavItem', 'RowItem', 'Card', 'Badge', 'FontIcons') {
                $w.FindResource($k) | Should -Not -BeNullOrEmpty -Because $k
            }
        }
    }

    It 'runs only exported module commands in the background worker' {
        $gui = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\Gui.ps1') -Raw
        $commands = @([regex]::Matches($gui, "Start-IgwtGuiJob -Command '([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $commands | Should -Contain 'Invoke-IgwtCleanerScan'
        $commands | Should -Contain 'Invoke-IgwtCleanerClean'
        $commands | Should -Contain 'Get-IgwtDiskUsage'
        $exported = @((Get-Module iGWindowsTuner).ExportedFunctions.Keys)
        foreach ($cmd in $commands) { $cmd | Should -BeIn $exported -Because "the worker runspace can only call exported commands ($cmd)" }
    }

    It 'gives every navigation entry a tooltip' {
        $xaml = [xml](Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw)
        $ns = New-Object System.Xml.XmlNamespaceManager($xaml.NameTable)
        $ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
        $items = @($xaml.SelectNodes("//w:ListBox[@*[local-name()='Name']='NavList']/w:ListBoxItem", $ns))
        $items.Count | Should -BeGreaterThan 10
        foreach ($i in $items) { $i.GetAttribute('ToolTip') | Should -Not -BeNullOrEmpty -Because $i.GetAttribute('Tag') }
        @($items | ForEach-Object { $_.GetAttribute('Tag') }) | Should -Contain 'Cleaner'
        @($items | ForEach-Object { $_.GetAttribute('Tag') }) | Should -Contain 'Storage'
        @($items | ForEach-Object { $_.GetAttribute('Tag') }) | Should -Contain 'Disk'
    }

    It 'gives every button, checkbox, combo box and text box a tooltip' {
        $xaml = [xml](Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw)
        $ns = New-Object System.Xml.XmlNamespaceManager($xaml.NameTable)
        $ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
        $controls = @($xaml.SelectNodes('//w:Button | //w:CheckBox | //w:ComboBox | //w:TextBox', $ns))
        $controls.Count | Should -BeGreaterThan 30
        foreach ($ctl in $controls) {
            $label = '{0} {1}{2}' -f $ctl.LocalName, $ctl.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml'), $ctl.GetAttribute('Content')
            $ctl.GetAttribute('ToolTip') | Should -Not -BeNullOrEmpty -Because $label
        }
    }

    It 'uses only inbox fonts and no external assets' {
        $dir = Join-Path $script:IgwtProjectRoot 'src\Gui'
        $text = (Get-ChildItem $dir -Filter *.xaml | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        $text | Should -Not -Match '(?i)(https?://(?!schemas\.microsoft\.com))'
        $text | Should -Not -Match '(?i)\.(png|jpg|ico|gif)\b'
        $text | Should -Match 'Segoe Fluent Icons'
    }
}
