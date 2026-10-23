BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:GuiDir = Join-Path $script:IgwtProjectRoot 'src\Gui'
}

Describe 'GUI design system (3.3)' {
    It 'computes WCAG contrast ratios correctly' {
        InModuleScope iGWindowsTuner {
            $black = [System.Windows.Media.Colors]::Black; $white = [System.Windows.Media.Colors]::White
            Get-IgwtContrastRatio -Foreground $black -Background $white | Should -Be 21
            Get-IgwtContrastRatio -Foreground $white -Background $white | Should -Be 1
            # #767676 on white is the classic 4.54:1 boundary colour.
            Get-IgwtContrastRatio -Foreground ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF767676')) -Background $white | Should -BeGreaterOrEqual 4.5
        }
    }

    It 'defines every token in the Dark and Light palettes' {
        InModuleScope iGWindowsTuner {
            foreach ($name in 'Dark', 'Light') {
                $p = Get-IgwtGuiPalette -Name $name
                foreach ($t in $script:IgwtThemeTokens) { $p[$t] | Should -Not -BeNullOrEmpty -Because "$name $t" }
            }
        }
    }

    It 'keeps text at 4.5:1 or more on every surface it is drawn on, in Dark and Light' {
        InModuleScope iGWindowsTuner {
            $pairs = @(
                @('Text', 'Background'), @('Text', 'Surface'), @('Text', 'SurfaceAlt'), @('Text', 'SurfaceHover'), @('Text', 'Sidebar'), @('Text', 'AccentSoft'),
                @('TextMuted', 'Background'), @('TextMuted', 'Surface'), @('TextMuted', 'SurfaceAlt'), @('TextMuted', 'Sidebar'),
                @('Accent', 'Background'), @('Accent', 'Surface'), @('Link', 'Surface'), @('Link', 'Background'), @('OnAccent', 'Accent'), @('OnDanger', 'DangerStrong'),
                @('Success', 'Surface'), @('Warning', 'Surface'), @('Danger', 'Surface'), @('Info', 'Surface'),
                @('Success', 'SuccessSoft'), @('Warning', 'WarningSoft'), @('Danger', 'DangerSoft'), @('Info', 'InfoSoft'),
                @('Success', 'Background'), @('Warning', 'Background'), @('Danger', 'Background')
            )
            foreach ($name in 'Dark', 'Light') {
                $p = Get-IgwtGuiPalette -Name $name
                foreach ($pair in $pairs) {
                    $ratio = Get-IgwtContrastRatio -Foreground $p[$pair[0]] -Background $p[$pair[1]]
                    $ratio | Should -BeGreaterOrEqual 4.5 -Because "$name $($pair[0]) on $($pair[1]) is $ratio"
                }
            }
        }
    }

    It 'keeps focus rings, borders of inputs and disabled text visible (3:1 and more for non-text)' {
        InModuleScope iGWindowsTuner {
            foreach ($name in 'Dark', 'Light') {
                $p = Get-IgwtGuiPalette -Name $name
                foreach ($pair in @(@('Focus', 'Background'), @('Focus', 'Surface'), @('BorderStrong', 'Surface'), @('BorderStrong', 'Background'))) {
                    $ratio = Get-IgwtContrastRatio -Foreground $p[$pair[0]] -Background $p[$pair[1]]
                    $ratio | Should -BeGreaterOrEqual 3 -Because "$name $($pair[0]) on $($pair[1]) is $ratio"
                }
                # Disabled text is exempt from WCAG but must still be readable.
                (Get-IgwtContrastRatio -Foreground $p.TextDisabled -Background $p.Surface) | Should -BeGreaterOrEqual 2.5 -Because "$name disabled text"
            }
        }
    }

    It 'builds High Contrast from the Windows high-contrast colours' {
        InModuleScope iGWindowsTuner {
            $p = Get-IgwtGuiPalette -Name HighContrast
            $p.Text | Should -Be ([System.Windows.SystemColors]::WindowTextColor)
            $p.Background | Should -Be ([System.Windows.SystemColors]::WindowColor)
            $p.Accent | Should -Be ([System.Windows.SystemColors]::HighlightColor)
            $p.OnAccent | Should -Be ([System.Windows.SystemColors]::HighlightTextColor)
        }
    }

    It 'uses a 14 px body text and a type scale that grows with the text size' {
        InModuleScope iGWindowsTuner {
            $script:IgwtTypeScale.FontSizeBody | Should -Be 14
            $script:IgwtTypeScale.FontSizeCaption | Should -BeGreaterOrEqual 12
            $rd = New-Object System.Windows.ResourceDictionary
            $target = [pscustomobject]@{ Resources = $rd }
            Set-IgwtGuiTextScale -Target $target -Percent 150
            $rd['FontSizeBody'] | Should -Be 21
            Set-IgwtGuiTextScale -Target $target -Percent 100
            $rd['FontSizeBody'] | Should -Be 14
        }
    }

    It 'switches themes by recolouring the same live brushes (never frozen)' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $w = New-IgwtMainWindow
            Set-IgwtGuiTheme -Target $w -Name Dark | Should -Be 'Dark'
            $brush = $w.Resources['BrushText']
            Set-IgwtGuiTheme -Target $w -Name Light | Should -Be 'Light'
            [object]::ReferenceEquals($brush, $w.Resources['BrushText']) | Should -BeTrue
            $brush.Color | Should -Be ((Get-IgwtGuiPalette -Name Light).Text)
            @($script:IgwtThemeBrushes.Values | Where-Object { $_.IsFrozen }).Count | Should -Be 0
            $script:IgwtColor.Pass | Should -BeOfType System.Windows.Media.SolidColorBrush
            Set-IgwtGuiDensity -Target $w -Mode Compact
            $w.Resources['GridRowHeight'] | Should -BeLessThan 38
        }
    }

    It 'refers to colour tokens with DynamicResource only, and has no hard-coded colours in the window' {
        foreach ($file in 'MainWindow.xaml', 'Theme.xaml') {
            $text = Get-Content (Join-Path $script:GuiDir $file) -Raw
            ([regex]::Matches($text, '\{StaticResource (Brush|Color)\w+\}')).Count | Should -Be 0 -Because "$file must follow theme switches"
        }
        $main = Get-Content (Join-Path $script:GuiDir 'MainWindow.xaml') -Raw
        ([regex]::Matches($main, '(Background|Foreground|BorderBrush|Fill)="#[0-9A-Fa-f]{6,8}"')).Count | Should -Be 0
    }

    It 'uses the type-scale tokens for text sizes (only icons keep a fixed glyph size)' {
        $main = Get-Content (Join-Path $script:GuiDir 'MainWindow.xaml') -Raw
        $bad = @([regex]::Matches($main, '<[A-Za-z][^<>]*FontSize="[\d.]+"[^<>]*>') | ForEach-Object { $_.Value } | Where-Object { $_ -notmatch 'StaticResource Icon\}|FontIcons|ToneIcon' })
        $bad | Should -BeNullOrEmpty
    }

    It 'replaces MessageBox with the themed dialog when the window is up' {
        $gui = Get-Content (Join-Path $script:GuiDir 'Gui.ps1') -Raw
        $gui | Should -Match 'Show-IgwtGuiDialog -Text \$Text'
        InModuleScope iGWindowsTuner {
            (Get-Command Show-IgwtGuiDialog).Parameters.Buttons.Attributes.ValidValues | Should -Be @('OK', 'OKCancel', 'YesNo', 'YesNoCancel')
        }
    }

    It 'stores the view state per user, under IGWT_GUI_STATE_DIR when set' {
        InModuleScope iGWindowsTuner {
            $old = $env:IGWT_GUI_STATE_DIR
            try {
                $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'state'
                Get-IgwtGuiStatePath | Should -Be (Join-Path $TestDrive 'state\gui-state.json')
                $script:Gui = @{ NoStateSave = $false; ViewState = @{ Theme = 'Light'; TextScale = 130 } }
                Save-IgwtGuiState
                $read = Read-IgwtGuiState
                $read.Theme | Should -Be 'Light'
                $read.TextScale | Should -Be 130
                $script:Gui = @{ NoStateSave = $true; ViewState = @{ Theme = 'Dark' } }
                Save-IgwtGuiState
                (Read-IgwtGuiState).Theme | Should -Be 'Light'
            } finally { $env:IGWT_GUI_STATE_DIR = $old; $script:Gui = $null }
        }
    }
}
