# 4.0 section 3: navigation by sections (D1), Home (D2), Optimize (D3), screen-reader names (X-M2, X-M3).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:Xaml = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui\MainWindow.xaml') -Raw
}

Describe '4.0 navigation (D1)' {
    It 'has seven sections, then Advanced tools and Settings at the bottom' {
        InModuleScope iGWindowsTuner {
            @($script:IgwtGuiSections | Where-Object { -not $_.Bottom } | ForEach-Object { $_.Id }) | Should -Be @('Home', 'Play', 'Optimize', 'Security', 'Network', 'Clean', 'History')
            @($script:IgwtGuiSections | Where-Object { $_.Bottom } | ForEach-Object { $_.Id }) | Should -Be @('Advanced', 'Settings')
            foreach ($s in $script:IgwtGuiSections) { foreach ($p in $s.Pages) { Get-IgwtGuiPageLabel -Page $p | Should -Not -Match 'Igwt|regClean|SecSettings|NetTest' -Because "$p needs a plain tab name" } }
        }
    }
    It 'keeps Home first, follows the persona order for the rest, and hides Advanced tools unless asked' {
        InModuleScope iGWindowsTuner {
            $o = @(Get-IgwtGuiSectionOrder -PageOrder @('Security', 'Firewall', 'Dashboard', 'Presets') | ForEach-Object { $_.Id })
            $o[0] | Should -Be 'Home'
            $o[1] | Should -Be 'Security'
            $o | Should -Not -Contain 'Advanced'
            $o[-1] | Should -Be 'Settings'
            @(Get-IgwtGuiSectionOrder -ShowAdvanced | ForEach-Object { $_.Id }) | Should -Contain 'Advanced'
        }
    }
    It 'opens every 3.x page id in its section and tab, and turns Advanced tools on for an advanced page' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ C = @{ NavList = $null; SectionTabs = $null; ShowAdvancedBox = $null }; ShowAdvanced = $false; SectionPage = @{} }
                $script:Shown = New-Object System.Collections.Generic.List[string]
                Mock Show-IgwtGuiPage { $script:Shown.Add($Page) }
                Mock Set-IgwtGuiStatus { }
                Mock Set-IgwtGuiViewValue { }
                Open-IgwtGuiPage -Page 'Firewall'
                $script:Gui.SectionPage['Security'] | Should -Be 'Firewall'
                Show-IgwtGuiSection -Id 'Security'
                @($script:Shown)[-1] | Should -Be 'Firewall' -Because 'a section reopens on its last page'
                Open-IgwtGuiPage -Page 'Policy'
                $script:Gui.ShowAdvanced | Should -BeTrue
                Open-IgwtGuiPage -Page 'NoSuchPage'
                @($script:Shown)[-1] | Should -Be 'Home'
            } finally { $script:Gui = $saved }
        }
    }
    It 'shows a breadcrumb of section and page in plain words' {
        InModuleScope iGWindowsTuner {
            Get-IgwtGuiBreadcrumb -Page 'Asr' | Should -Be "Security  $([char]0x203A)  Attack surface rules"
            Get-IgwtGuiBreadcrumb -Page 'Backups' | Should -Be "History  $([char]0x203A)  Backups and logs"
            Get-IgwtGuiBreadcrumb -Page 'History' | Should -Be "History  $([char]0x203A)  Changes"
            Get-IgwtGuiBreadcrumb -Page 'About' | Should -Be "Settings  $([char]0x203A)  About"
        }
    }
    It 'routes every old menu lookup through Open-IgwtGuiPage (no page is picked from the list by its id)' {
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui') -Filter '*.ps1') {
            (Get-Content -LiteralPath $f.FullName -Raw) | Should -Not -Match 'NavList\.Items \| Where-Object \{ \[string\]\$_\.Tag -eq' -Because $f.Name
        }
    }
    It 'gives the sidebar 240 px and the old details column 320 px, not 380 (X-M1)' {
        $script:Xaml | Should -Match '<ColumnDefinition Width="240"/>'
        $script:Xaml | Should -Match 'x:Name="DetailsColumn" Width="320"'
    }
}

Describe '4.0 Home (D2)' {
    It 'greets by the time of day' {
        InModuleScope iGWindowsTuner {
            Get-IgwtGuiGreeting -Hour 8 | Should -Be 'Good morning'
            Get-IgwtGuiGreeting -Hour 14 | Should -Be 'Good afternoon'
            Get-IgwtGuiGreeting -Hour 21 | Should -Be 'Good evening'
        }
    }
    It 'counts Optimize settings in place among the readable ones, and reads the score and changes' {
        InModuleScope iGWindowsTuner {
            $cat = @(
                [pscustomobject]@{ id = 'a'; category = 'Input' }, [pscustomobject]@{ id = 'b'; category = 'Input' },
                [pscustomobject]@{ id = 'c'; category = 'Input' }, [pscustomobject]@{ id = 'd'; category = 'Security' })
            $data = [pscustomobject]@{
                States = @{ a = [pscustomobject]@{ State = 'On' }; b = [pscustomobject]@{ State = 'Off' }; c = [pscustomobject]@{ State = 'NotApplicable' }; d = [pscustomobject]@{ State = 'On' } }
                Health = [pscustomobject]@{ Security = [pscustomobject]@{ Score = 88; Grade = 'Good'; ToFix = @(1, 2) } }
                Snapshots = @(); Pending = $null; AntiCheat = [pscustomobject]@{ Overall = 'Green' }
            }
            $f = Get-IgwtGuiHomeFigures -Data $data -Catalog $cat -Categories @('Input')
            $f.InPlace | Should -Be 1
            $f.Total | Should -Be 2 -Because 'Not applicable items are not counted'
            $f.Score | Should -Be 88
            $f.ToFix | Should -Be 2
            $f.AntiCheat | Should -Be 'Green'
        }
    }
}

Describe '4.0 Optimize (D3)' {
    It 'uses the plain evidence and undo words of the design' {
        InModuleScope iGWindowsTuner {
            Get-IgwtGuiEvidenceWords -Tweak ([pscustomobject]@{ evidence = [pscustomobject]@{ tier = 'A' } }) | Should -Be 'Documented by Microsoft'
            Get-IgwtGuiEvidenceWords -Tweak ([pscustomobject]@{ evidence = [pscustomobject]@{ tier = 'B' } }) | Should -Be 'Measure it'
            (Get-IgwtGuiUndoWords -Tweak ([pscustomobject]@{ reversible = 'full' }))[0] | Should -Be 'Undo: exact'
            (Get-IgwtGuiUndoWords -Tweak ([pscustomobject]@{ reversible = 'partial' }))[0] | Should -Be 'Undo: partial'
            (Get-IgwtGuiUndoWords -Tweak ([pscustomobject]@{ reversible = 'none' }))[0] | Should -Be 'Cannot be undone'
        }
    }
    It 'lists the category, or with a search every Optimize category, never another section' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $cat = @(Get-IgwtCatalog -Force)
                $states = @{}; foreach ($t in $cat) { $states[[string]$t.id] = [pscustomobject]@{ State = 'Off'; Items = @() } }
                $staged = New-Object 'System.Collections.Generic.Dictionary[string,string]'
                $script:Gui = @{ Catalog = $cat; Data = [pscustomobject]@{ States = $states; Changed = @{} }; Staged = $staged; Persona = $null; FocusMode = $false; IsAdmin = $true }
                $inputs = @(Get-IgwtGuiOptimizeItems -Category 'Input')
                $inputs.Count | Should -BeGreaterThan 0
                @($inputs | Where-Object { $_.Tweak.category -ne 'Input' }).Count | Should -Be 0
                $all = @(Get-IgwtGuiOptimizeItems -Category 'Input' -Search 'e')
                @($all | ForEach-Object { $_.Tweak.category } | Select-Object -Unique).Count | Should -BeGreaterThan 1
                @($all | Where-Object { $_.Tweak.category -in 'Security', 'Network', 'Storage', 'Risk Zone' }).Count | Should -Be 0
            } finally { $script:Gui = $saved }
        }
    }
    It 'stages through the shared path: Expert items need their confirmation; returning to the current state unstages' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $staged = New-Object 'System.Collections.Generic.Dictionary[string,string]'
                $cat = @([pscustomobject]@{ id = 'x.expert'; expert = $true; warning = 'w'; description = 'd'; evidence = [pscustomobject]@{ tier = 'B' }; conflictsWith = @() }, [pscustomobject]@{ id = 'x.std'; expert = $false; evidence = [pscustomobject]@{ tier = 'A' }; conflictsWith = @() })
                $script:Gui = @{ Catalog = $cat; Data = [pscustomobject]@{ States = @{ 'x.expert' = [pscustomobject]@{ State = 'Off' }; 'x.std' = [pscustomobject]@{ State = 'On' } } }; Staged = $staged; Acked = @{} }
                Mock Show-IgwtGuiMessage { 'No' }
                Invoke-IgwtGuiStageToggle -Id 'x.expert' -Want $true | Should -BeFalse
                $staged.ContainsKey('x.expert') | Should -BeFalse
                Mock Show-IgwtGuiMessage { 'Yes' }
                Invoke-IgwtGuiStageToggle -Id 'x.expert' -Want $true | Should -BeTrue
                $staged['x.expert'] | Should -Be 'on'
                $script:Gui.Acked['x.expert'] | Should -BeTrue
                Invoke-IgwtGuiStageToggle -Id 'x.std' -Want $false | Should -BeTrue
                $staged['x.std'] | Should -Be 'off'
                Invoke-IgwtGuiStageToggle -Id 'x.std' -Want $true | Should -BeTrue
                $staged.ContainsKey('x.std') | Should -BeFalse
            } finally { $script:Gui = $saved }
        }
    }
}

Describe '4.0 screen-reader names (X-M2, X-M3)' {
    It 'names every text box, combo box and check box in the window' {
        $x = [xml]$script:Xaml
        $ns = @{ w = 'http://schemas.microsoft.com/winfx/2006/xaml/presentation' }
        $missing = foreach ($t in 'TextBox', 'ComboBox', 'CheckBox', 'PasswordBox', 'Slider') {
            foreach ($e in (Select-Xml -Xml $x -XPath "//w:$t" -Namespace $ns)) {
                $el = $e.Node
                if (-not $el.GetAttribute('AutomationProperties.Name') -and -not $el.GetAttribute('AutomationProperties.LabeledBy') -and -not $el.GetAttribute('Content')) { "$t $($el.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml'))" }
            }
        }
        @($missing) | Should -BeNullOrEmpty
    }
    It 'names the latency hosts box after what it holds' {
        $script:Xaml | Should -Not -Match 'Latency measurement duration'
        $script:Xaml | Should -Match 'AutomationProperties.Name="Hosts to measure latency"'
    }
}
