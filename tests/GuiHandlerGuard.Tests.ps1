BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

Describe 'GUI event handler guard' {
    It 'attaches a handler once when the same code registers it again' {
        InModuleScope iGWindowsTuner {
            $b = New-Object System.Windows.Controls.Button
            $count = @{ N = 0 }
            $h = { $count.N++ }.GetNewClosure()
            $before = $script:IgwtHandlerDuplicates
            foreach ($i in 1..3) { Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler $h }
            $b.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $count.N | Should -Be 1
            ($script:IgwtHandlerDuplicates - $before) | Should -Be 2
        }
    }

    It 'allows different code lines, keys and controls' {
        InModuleScope iGWindowsTuner {
            $b1 = New-Object System.Windows.Controls.Button
            $b2 = New-Object System.Windows.Controls.Button
            $count = @{ N = 0 }
            $h = { $count.N++ }.GetNewClosure()
            Register-IgwtGuiHandler -Control $b1 -Event 'Click' -Handler $h
            Register-IgwtGuiHandler -Control $b1 -Event 'Click' -Handler $h -Key 'second'
            Register-IgwtGuiHandler -Control $b2 -Event 'Click' -Handler $h
            $b1.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $count.N | Should -Be 2
        }
    }

    It 'registers routed events for a subtree once' {
        InModuleScope iGWindowsTuner {
            $panel = New-Object System.Windows.Controls.StackPanel
            $btn = New-Object System.Windows.Controls.Button
            $null = $panel.Children.Add($btn)
            $count = @{ N = 0 }
            $h = { param($s, $e) $null = $s, $e; $count.N++ }.GetNewClosure()
            foreach ($i in 1..2) { Register-IgwtGuiHandler -Control $panel -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler $h }
            $btn.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $count.N | Should -Be 1
        }
    }

    It 'is the only way the GUI subscribes to control events' {
        $dir = Join-Path $script:IgwtProjectRoot 'src\Gui'
        $hits = @(Get-ChildItem $dir -Filter *.ps1 | Select-String -Pattern '\.Add_[A-Za-z]+\(|\.AddHandler\(' |
                Where-Object { $_.Line -notmatch '\$target\.' })
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber)" } | Should -BeNullOrEmpty
    }
}
