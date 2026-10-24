BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

# Every list of the window is a SmartGrid (spec 3.3: sorting and filtering everywhere).
Describe 'Page lists on SmartGrid' {
    It 'has no plain ListView tables left in the main window' {
        $xaml = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw
        $xaml | Should -Not -Match '<ListView\b'
    }

    It 'builds rows with keys, status icons and chip fields that never throw on sparse data' {
        InModuleScope iGWindowsTuner {
            $s = New-IgwtGuiStartupRow -Entry ([pscustomobject]@{ Scope = 'HKCU-Run'; Name = 'Steam'; Command = 'steam.exe'; Enabled = $false }) -CanToggle $false
            $s.Key | Should -Be 'HKCU-Run|Steam'; $s.ScopeText | Should -Be 'This user'; $s.On | Should -BeFalse; $s.OnEnabled | Should -BeFalse
            $n = New-IgwtGuiSnapshotRow -Snapshot ([pscustomobject]@{ Path = 'C:\b\s.json'; File = 's.json'; Created = '2026-10-20T10:00:00Z'; Operation = 'Revert:x'; Detail = ''; Applied = @(1, 2); Failed = 1 })
            $n.KindText | Should -Be 'Revert'; $n.Entries | Should -Be 2; $n.FailedCol | Should -Be '1 failed'; $n.FailedColGlyph | Should -Not -BeNullOrEmpty
            (New-IgwtGuiSnapshotRow -Snapshot ([pscustomobject]@{ Path = 'p'; Operation = 'Firewall' })).KindText | Should -Be 'Security'
            $r = New-IgwtGuiRejectedRow -Entry ([pscustomobject]@{ name = 'HPET off'; category = 'placebo'; riskItem = 'risk.hpet-disable' })
            $r.AvailCol | Should -Be 'In the Risk Zone'; $r.RiskKey | Should -Be 'Yes'
            $m = New-IgwtGuiManageRow -Title 'Driver' -State 'Old' -Tone 'Warn' -Key 'k' -Extra @{ Provider = 'Acme'; Title = 'ignored' }
            $m.Key | Should -Be 'k'; $m.Provider | Should -Be 'Acme'; $m.Title | Should -Be 'Driver'; $m.StateGlyph | Should -Be $script:IgwtToneGlyph['Warn']
            $c = New-IgwtGuiCleanerRow -RuleScan ([pscustomobject]@{ RuleId = 'clean.x'; Name = 'X'; Status = 'Refused'; Level = 'Expert'; Bytes = 10; Count = 1 }) -Selected $true
            $c.Key | Should -Be 'clean.x'; $c.On | Should -BeFalse -Because 'a refused rule cannot be ticked'; $c.StatusColGlyph | Should -Be $script:IgwtToneGlyph['Lock']; $c.LevelRank | Should -Be 2
            $k = New-IgwtGuiKernelRow -Value ([pscustomobject]@{ Name = 'V'; Status = 'Changed'; Current = '1'; Default = '0' }) -Key 'HKLM\K'
            $k.RowId | Should -Be 'HKLM\K\V'; $k.Status | Should -Be 'Differs'; $k.StatusKey | Should -Be 'Changed'
        }
    }

    It 'builds every page grid into its host and loads, scopes and selects rows' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $w = New-IgwtMainWindow
            $null = Set-IgwtGuiTheme -Target $w -Name Dark
            $script:Gui = @{ Window = $w; C = @{}; Grids = @{}; ViewState = @{}; NoStateSave = $true; ReadOnly = $true; IsAdmin = $false; DiagnosticsPath = $null; CleanSelected = @{} }
            try {
                foreach ($n in $script:IgwtGuiControlNames) { $script:Gui.C[$n] = $w.FindName($n) }
                Initialize-IgwtGuiListGrids
                foreach ($n in 'InspectPowerList', 'InspectIrqList', 'InspectKernelList', 'ToolkitAppList', 'ToolkitTweakList', 'ToolkitFeatureList', 'ToolkitFixList', 'ToolkitPanelList', 'ToolkitUpdateList',
                    'DiagDriverList', 'DiagAdapterList', 'DefList', 'DefPolicyList', 'CleanerList', 'DiskFolderList', 'DiskFileList', 'StartupList', 'SnapshotList', 'RejectedList') {
                    $script:Gui.Grids[$n] | Should -Not -BeNullOrEmpty -Because "$n needs a grid"
                    [object]::ReferenceEquals($script:Gui.C["${n}Host"].Content, $script:Gui.Grids[$n].Root) | Should -BeTrue -Because "$n sits in its host"
                }
                # Lists filled by a button press start empty (not loading).
                $script:Gui.Grids.CleanerList.State | Should -Be 'Ready'
                Set-IgwtGuiGridRows -Name 'StartupList' -Rows @(
                    (New-IgwtGuiStartupRow -Entry ([pscustomobject]@{ Scope = 'HKCU-Run'; Name = 'b'; Command = 'b.exe'; Enabled = $true }) -CanToggle $true),
                    (New-IgwtGuiStartupRow -Entry ([pscustomobject]@{ Scope = 'HKLM-Run'; Name = 'a'; Command = 'a.exe'; Enabled = $false }) -CanToggle $true))
                $g = $script:Gui.Grids.StartupList
                $g.C.CountText.Text | Should -Be '2 entries'
                @($g.C.Grid.ItemsSource | ForEach-Object { $_.Name }) | Should -Be @('a', 'b') -Because 'the default sort is by name'
                Set-IgwtGridChip -Grid $g -ChipId 'user'
                $g.C.CountText.Text | Should -Be '1 of 2 shown'
                # Defender preferences: the category box is a scope, not a user filter.
                $d = $script:Gui.Grids.DefList
                Set-IgwtGuiGridRows -Name 'DefList' -Rows @(
                    (New-IgwtGuiDefenderRow -Setting ([pscustomobject]@{ Property = 'A'; Name = 'A'; Category = 'cloud'; CategoryName = 'Cloud'; Edit = 'set'; Editable = $true; Source = 'Local'; Display = 'On'; Status = 'On' })),
                    (New-IgwtGuiDefenderRow -Setting ([pscustomobject]@{ Property = 'B'; Name = 'B'; Category = 'scan'; CategoryName = 'Scan'; Edit = 'set'; Editable = $false; Source = 'GroupPolicy'; Display = 'Off'; Status = 'Off' })))
                $d.Scope = @{ CategoryId = @('scan') }
                Update-IgwtGridView -Grid $d
                $d.C.CountText.Text | Should -Be '1 settings'
                $d.OnSelectionChanged = $null   # the details pane needs catalog settings; this test checks the grid
                $d.C.Grid.SelectedIndex = 0
                (Get-IgwtGuiGridItem -Name 'DefList').Id | Should -Be 'B'
                Set-IgwtGuiGridRows -Name 'DiagDriverList' -ErrorText 'Not readable: boom'
                $script:Gui.Grids.DiagDriverList.State | Should -Be 'Error'
            } finally {
                foreach ($k in @($script:IgwtGrids.Keys)) { $script:IgwtGrids.Remove($k) }
                $script:Gui = $null
            }
        }
    }
}
