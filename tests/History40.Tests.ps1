# 4.0 section 4: History (D4) with the revert plan in the card and JP-1, Play (D5), PP-2 and G-03.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Xaml = Get-Content -LiteralPath (Join-Path $script:Root 'src\Gui\MainWindow.xaml') -Raw
    # A timeline in the shape of Get-IgwtJournalTimeline (oldest session first, as a mock may give it).
    $script:Timeline = [pscustomobject]@{
        Status = 'Ok'; Reason = ''; Count = 9; Sessions = 3; Baselines = 3; Tracked = 2
        Rows = @(
            [pscustomobject]@{ Key = 's1|1'; Session = 's1'; SessionTitle = 'Preset:competitive (2 item(s))'; Origin = 'preset'; When = '2026-11-01T10:00:00.0000000Z'; Op = 'change'; Item = 'a.one'; Target = 'action|a.one|0|registry'; Result = 'Committed'; Before = 'DWord 0'; After = 'DWord 1'; InEffect = $true; OneWay = $false }
            [pscustomobject]@{ Key = 's1|2'; Session = 's1'; SessionTitle = 'Preset:competitive (2 item(s))'; Origin = 'preset'; When = '2026-11-01T10:00:00.0000000Z'; Op = 'change'; Item = 'a.two'; Target = 'action|a.two|0|registry'; Result = 'Committed'; Before = 'absent'; After = 'DWord 5'; InEffect = $true; OneWay = $false }
            [pscustomobject]@{ Key = 's2|1'; Session = 's2'; SessionTitle = 'Invoke-IgwtManagedChange service Fax Disabled'; Origin = 'module'; When = '2026-11-02T10:00:00.0000000Z'; Op = 'change'; Item = 'module:Invoke-IgwtManagedChange'; Target = 'module|x'; Result = 'Committed'; Before = ''; After = ''; InEffect = $false; OneWay = $false }
            [pscustomobject]@{ Key = 's3|1'; Session = 's3'; SessionTitle = 'Cleaner'; Origin = 'module'; When = '2026-11-03T10:00:00.0000000Z'; Op = 'change'; Item = 'module:Invoke-IgwtCleanerClean'; Target = 'module|y'; Result = 'Committed'; Before = ''; After = ''; InEffect = $true; OneWay = $true }
        )
    }
    $script:Plan = @(
        [pscustomobject]@{ Key = 'action|a.one|0|registry'; Item = 'a.one'; Session = 's1'; Status = 'Conflict'; Before = @{ exists = $true; kind = 'DWord'; value = 0 }; WeSet = @{ exists = $true; kind = 'DWord'; value = 1 }; Now = @{ exists = $false }; Message = '' }
        [pscustomobject]@{ Key = 'action|a.two|0|registry'; Item = 'a.two'; Session = 's1'; Status = 'Ready'; Before = @{ exists = $false }; WeSet = @{ exists = $true; kind = 'DWord'; value = 5 }; Now = @{ exists = $true; kind = 'DWord'; value = 5 }; Message = '' }
        [pscustomobject]@{ Key = 'module|y'; Item = 'module:Invoke-IgwtCleanerClean'; Session = 's3'; Status = 'Refused'; Before = $null; WeSet = $null; Now = $null; Message = 'one-way' }
    )
}

Describe '4.0 History view models (D4)' {
    It 'names sessions and items in plain words' {
        InModuleScope iGWindowsTuner {
            Get-IgwtGuiHistoryTitle -Title 'Preset:competitive (3 item(s))' -Presets @([pscustomobject]@{ id = 'competitive'; name = 'Competitive' }) | Should -Be 'Applied the Competitive preset'
            Get-IgwtGuiHistoryTitle -Title 'Preset:privacy-max (3 item(s))' | Should -Be 'Applied the Privacy Max preset'
            Get-IgwtGuiHistoryTitle -Title 'Invoke-IgwtManagedChange service Fax Disabled' | Should -Be 'Service Fax Disabled'
            Get-IgwtGuiHistoryTitle -Title 'Revert session: Invoke-IgwtManagedChange' | Should -Be 'Undo: System change'
            Get-IgwtGuiHistoryItemName -Item 'a.one' -Names @{ 'a.one' = 'Game Mode' } | Should -Be 'Game Mode'
            Get-IgwtGuiHistoryItemName -Item 'module:Invoke-IgwtManagedChange' | Should -Be 'Managed change'
            Get-IgwtGuiHistoryItemName -Item 'regclean:uninstall' | Should -Be 'Registry leftover (uninstall)'
        }
    }
    It 'builds one card per session, newest first, with counts from the timeline and the -All plan' {
        InModuleScope iGWindowsTuner -Parameters @{ T = $script:Timeline; P = $script:Plan } {
            param($T, $P)
            $s = @(Get-IgwtGuiHistorySessions -Timeline $T -Plan $P)
            @($s.Id) | Should -Be @('s3', 's2', 's1')
            $one = $s | Where-Object Id -EQ 's1'
            $one.Title | Should -Be 'Applied the Competitive preset'
            $one.Changes | Should -Be 2; $one.InPlace | Should -Be 2; $one.Conflicts | Should -Be 1
            $one.State | Should -Be 'InPlace'; $one.CanUndo | Should -BeTrue
            $one.Meta | Should -Match '2 settings  \|  2 still in place  \|  1 changed since'
            ($s | Where-Object Id -EQ 's2').State | Should -Be 'Undone'
            $three = $s | Where-Object Id -EQ 's3'
            $three.State | Should -Be 'InPlace'; $three.CanUndo | Should -BeFalse -Because 'its only change is one-way'
            $three.Meta | Should -Match '1 cannot be undone'
        }
    }
    It 'filters by the chips of mockup 3' {
        InModuleScope iGWindowsTuner -Parameters @{ T = $script:Timeline; P = $script:Plan } {
            param($T, $P)
            $s = @(Get-IgwtGuiHistorySessions -Timeline $T -Plan $P)
            $f = { param($n) @($s | Where-Object { Test-IgwtGuiHistoryFilter -Session $_ -Filter $n } | ForEach-Object { $_.Id }) }
            & $f 'All' | Should -Be @('s3', 's2', 's1')
            & $f 'Still in place' | Should -Be @('s3', 's1')
            & $f 'Changed since' | Should -Be @('s1')
            & $f 'Undone' | Should -Be @('s2')
            & $f 'Cannot be undone' | Should -Be @('s3')
        }
    }
    It 'enables Undo only when every changed value has a choice, and passes the choices on (JP-1)' {
        InModuleScope iGWindowsTuner -Parameters @{ P = $script:Plan } {
            param($P)
            $st = Get-IgwtGuiHistoryPlanState -Plan $P -Decisions @{}
            $st.CanConfirm | Should -BeFalse
            $st.Undecided | Should -Be 1
            $st.Summary | Should -Match '^Choose what happens to 1 setting'
            $st = Get-IgwtGuiHistoryPlanState -Plan $P -Decisions @{ 'action|a.one|0|registry' = 'Skip' }
            $st.CanConfirm | Should -BeTrue
            $st.ConfirmText | Should -Be 'Undo 1 setting'
            $st.Decisions['action|a.one|0|registry'] | Should -Be 'Skip'
            $st = Get-IgwtGuiHistoryPlanState -Plan $P -Decisions @{ 'action|a.one|0|registry' = 'Restore' }
            $st.ConfirmText | Should -Be 'Undo 2 settings'
            $st.Other | Should -Be 1
            $only = @($P | Where-Object Status -EQ 'Conflict')
            (Get-IgwtGuiHistoryPlanState -Plan $only -Decisions @{ 'action|a.one|0|registry' = 'Keep' }).ConfirmText | Should -Be 'Keep the current values'
            (Get-IgwtGuiHistoryPlanState -Plan $only -Decisions @{ 'action|a.one|0|registry' = 'Skip' }).CanConfirm | Should -BeFalse -Because 'nothing would happen'
        }
    }
}

Describe '4.0 History actions (revert plan in the card)' {
    BeforeEach {
        InModuleScope iGWindowsTuner -Parameters @{ T = $script:Timeline } {
            param($T)
            $script:SavedGui = $script:Gui
            $script:Gui = @{ IsAdmin = $true; C = @{}; Catalog = @(); Presets = @(); Hist = $null }
            $null = Get-IgwtGuiHistoryState
            $script:Gui.Hist.Timeline = $T
            $script:Calls = New-Object System.Collections.Generic.List[object]
            Mock Start-IgwtGuiJob { $script:Calls.Add([pscustomobject]@{ Command = $Command; Parameters = $Parameters; Blocking = [bool]$Blocking }); $true }
            Mock Show-IgwtGuiMessage { 'OK' }
            Mock Set-IgwtGuiStatus { }
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:Gui = $script:SavedGui } }
    It 'opens a session plan read-only (one session, or everything for Reset)' {
        InModuleScope iGWindowsTuner {
            Open-IgwtGuiHistoryUndo -Id 's1'
            $script:Gui.Hist.Open | Should -Be 's1'
            $script:Calls[0].Command | Should -Be 'Get-IgwtRevertPlan'
            $script:Calls[0].Parameters.SessionId | Should -Be 's1'
            $script:Calls[0].Blocking | Should -BeFalse
            Open-IgwtGuiHistoryUndo -Id '*'
            $script:Calls[1].Parameters.All | Should -BeTrue
        }
    }
    It 'refuses to open an undo when not an administrator' {
        InModuleScope iGWindowsTuner {
            $script:Gui.IsAdmin = $false
            Open-IgwtGuiHistoryUndo -Id 's1'
            $script:Calls.Count | Should -Be 0
            $script:Gui.Hist.Open | Should -Be ''
        }
    }
    It 'runs nothing while a changed value has no choice; runs one revert with the choices after' {
        InModuleScope iGWindowsTuner -Parameters @{ P = $script:Plan } {
            param($P)
            $script:Gui.Hist.Open = 's1'; $script:Gui.Hist.Plan = @($P | Where-Object Session -EQ 's1')
            Invoke-IgwtGuiHistoryUndo
            $script:Calls.Count | Should -Be 0
            Set-IgwtGuiHistoryDecision -Key 'action|a.one|0|registry' -Choice 'Keep'
            Invoke-IgwtGuiHistoryUndo
            $script:Calls.Count | Should -Be 1
            $script:Calls[0].Command | Should -Be 'Invoke-IgwtJournalRevert'
            $script:Calls[0].Blocking | Should -BeTrue
            $script:Calls[0].Parameters.Decisions['action|a.one|0|registry'] | Should -Be 'Keep'
            @($script:Calls[0].Parameters.Plan).Count | Should -Be 2
            $script:Calls[0].Parameters.Title | Should -Be 'Undo: Applied the Competitive preset'
        }
    }
    It 'Cancel closes the plan and changes nothing' {
        InModuleScope iGWindowsTuner -Parameters @{ P = $script:Plan } {
            param($P)
            $script:Gui.Hist.Open = 's1'; $script:Gui.Hist.Plan = @($P); $script:Gui.Hist.Decisions = @{ x = 'Keep' }
            Close-IgwtGuiHistoryUndo
            $script:Gui.Hist.Open | Should -Be ''
            $script:Gui.Hist.Decisions.Count | Should -Be 0
            $script:Calls.Count | Should -Be 0
        }
    }
}

Describe 'Change journal tab: Esc on a conflict stops the whole revert (JP-1)' {
    It 'returns no decisions on Cancel, and the revert is not started' {
        InModuleScope iGWindowsTuner -Parameters @{ P = $script:Plan } {
            param($P)
            $saved = $script:Gui
            try {
                $script:Gui = @{ IsAdmin = $true; C = @{} }
                Mock Show-IgwtGuiTextDialog { $true }
                Mock Set-IgwtGuiStatus { }
                Mock Start-IgwtGuiJob { $true }
                Mock Show-IgwtGuiMessage { 'Cancel' }
                Request-IgwtGuiJournalDecisions -Plan $P | Should -BeNullOrEmpty
                Show-IgwtGuiJournalPlan -Plan $P -Title 't'
                Should -Invoke Start-IgwtGuiJob -Times 0 -Exactly
                Mock Show-IgwtGuiMessage { 'No' }
                (Request-IgwtGuiJournalDecisions -Plan $P)['action|a.one|0|registry'] | Should -Be 'Keep'
                Show-IgwtGuiJournalPlan -Plan $P -Title 't'
                Should -Invoke Start-IgwtGuiJob -Times 1 -Exactly -ParameterFilter { $Command -eq 'Invoke-IgwtJournalRevert' -and $Parameters.Decisions['action|a.one|0|registry'] -eq 'Keep' }
            } finally { $script:Gui = $saved }
        }
    }
}

Describe '4.0 History page (offscreen)' {
    It 'shows the conflict choices in the card and enables Undo once one is chosen' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner -Parameters @{ T = $script:Timeline; P = $script:Plan } {
            param($T, $P)
            $saved = $script:Gui
            try {
                $window = New-IgwtMainWindow
                $c = @{ HistoryHost = $window.FindName('HistoryHost'); PageHistory = $window.FindName('PageHistory') }
                $c.PageHistory.Visibility = 'Visible'
                $script:Gui = @{ Window = $window; C = $c; IsAdmin = $true; Catalog = @([pscustomobject]@{ id = 'a.one'; name = 'Game Mode' }); Presets = @(); Hist = $null }
                $h = Get-IgwtGuiHistoryState
                $h.Timeline = $T; $h.AllPlan = $P; $h.Open = 's1'; $h.Plan = @($P | Where-Object Session -EQ 's1')
                Update-IgwtGuiHistoryPage
                $buttons = @(Get-IgwtUiDescendant -Root $c.HistoryHost | Where-Object { $_ -is [System.Windows.Controls.Button] })
                $names = @($buttons | ForEach-Object { [System.Windows.Automation.AutomationProperties]::GetName($_) })
                $names | Should -Contain 'Keep absent (Game Mode)'
                $names | Should -Contain 'Put back DWord 0 (Game Mode)'
                $names | Should -Contain 'Skip (Game Mode)'
                $names | Should -Contain 'Reset everything iG changed'
                $go = @($buttons | Where-Object { [string]$_.Content -like 'Undo*setting*' })[0]
                $go.IsEnabled | Should -BeFalse -Because 'Game Mode changed since iG set it and has no choice yet'
                Set-IgwtGuiHistoryDecision -Key 'action|a.one|0|registry' -Choice 'Restore'
                $buttons = @(Get-IgwtUiDescendant -Root $c.HistoryHost | Where-Object { $_ -is [System.Windows.Controls.Button] })
                $go = @($buttons | Where-Object { [string]$_.Content -like 'Undo*setting*' })[0]
                $go.IsEnabled | Should -BeTrue
                [string]$go.Content | Should -Be 'Undo 2 settings'
                $chosen = @($buttons | Where-Object { [System.Windows.Automation.AutomationProperties]::GetItemStatus($_) -eq 'Chosen' })
                @($chosen).Count | Should -Be 1
                [string]$chosen[0].Content | Should -Be 'Put back DWord 0'
            } finally { $script:Gui = $saved }
        }
    }
}

Describe '4.0 Play (D5)' {
    It 'puts Preview first on every preset card as the one accent button, with names that say which preset' {
        $card = [regex]::Match($script:Xaml, '(?s)<ItemsControl x:Name="PresetCards".*?</ItemsControl>').Value
        $btns = @([regex]::Matches($card, '<Button [^>]*/>') | ForEach-Object { $_.Value })
        $btns.Count | Should -Be 2
        $btns[0] | Should -Match 'Content="Preview"'
        $btns[0] | Should -Match 'AccentButton'
        $btns[0] | Should -Match 'AutomationProperties.Name="\{Binding PreviewName\}"'
        $btns[1] | Should -Not -Match 'AccentButton'
        $btns[1] | Should -Match 'AutomationProperties.Name="\{Binding StageName\}"'
    }
}

Describe 'Group Policy tree: scope instead of a rebuild (PP-2)' {
    It 'lists a category and each parent' {
        InModuleScope iGWindowsTuner {
            @(Get-IgwtGuiPolicyScopes -Category 'Windows Components > Search > Indexing') | Should -Be @('Windows Components', 'Windows Components > Search', 'Windows Components > Search > Indexing')
            @(Get-IgwtGuiPolicyScopes -Category '').Count | Should -Be 0
        }
    }
    It 'narrows the existing index on a tree click and never rebuilds it' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $grid = @{ Scope = @{} }
                $script:Gui = @{ PolicyRows = @([pscustomobject]@{ Id = 'p' }); Grids = @{ Policy = $grid }; C = @{ PolTree = [pscustomobject]@{ SelectedItem = [pscustomobject]@{ Tag = 'Windows Components > Search' } } } }
                Mock Set-IgwtGridRows { }
                Mock Set-IgwtGuiGridRows { }
                Mock Update-IgwtGridView { }
                Update-IgwtGuiPolicyScope
                @($grid.Scope.Scopes) | Should -Be @('Windows Components > Search')
                Should -Invoke Update-IgwtGridView -Times 1 -Exactly
                Should -Invoke Set-IgwtGridRows -Times 0 -Exactly
                $script:Gui.C.PolTree.SelectedItem.Tag = ''
                Update-IgwtGuiPolicyScope
                $grid.Scope.Count | Should -Be 0
            } finally { $script:Gui = $saved }
        }
    }
}

Describe 'Per-user settings under another administrator (G-03)' {
    It 'maps the signed-in user once per runspace, on the first per-user path' {
        InModuleScope iGWindowsTuner {
            $savedTest = $script:IgwtSettings.TestMode; $savedRedirect = $script:IgwtSettings.RegistryRedirect
            try {
                Mock Initialize-IgwtUserHive { }
                $script:IgwtUserHiveChecked = $false
                $script:IgwtSettings.TestMode = $false; $script:IgwtSettings.RegistryRedirect = $null
                $null = Resolve-IgwtRegistryPath -Path 'HKLM:\SOFTWARE\X'
                Should -Invoke Initialize-IgwtUserHive -Times 0 -Exactly -Because 'machine paths need no user hive'
                $null = Resolve-IgwtRegistryPath -Path 'HKCU:\Software\X'
                $null = Resolve-IgwtRegistryPath -Path 'HKCU:\Software\Y'
                Should -Invoke Initialize-IgwtUserHive -Times 1 -Exactly
            } finally { $script:IgwtSettings.TestMode = $savedTest; $script:IgwtSettings.RegistryRedirect = $savedRedirect; $script:IgwtUserHiveChecked = $false }
        }
    }
    It 'says whose per-user settings are shown: Same, Mapped or Unavailable' {
        InModuleScope iGWindowsTuner {
            $savedOther = $script:IgwtTestOtherAdmin; $savedSid = $script:IgwtSettings.UserHiveSid
            try {
                $script:IgwtTestOtherAdmin = ''
                (Get-IgwtUserHiveStatus).State | Should -Be 'Same'
                $script:IgwtTestOtherAdmin = 'S-1-5-21-1-2-3-1001'; $script:IgwtSettings.UserHiveSid = $null
                (Get-IgwtUserHiveStatus).State | Should -Be 'Unavailable'
                $script:IgwtSettings.UserHiveSid = 'S-1-5-21-1-2-3-1001'
                (Get-IgwtUserHiveStatus).State | Should -Be 'Mapped'
            } finally { $script:IgwtTestOtherAdmin = $savedOther; $script:IgwtSettings.UserHiveSid = $savedSid }
        }
    }
    It 'shows the banner only when another administrator started iG' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $window = New-IgwtMainWindow
                $script:Gui = @{ Window = $window; C = @{ UserHiveBanner = $window.FindName('UserHiveBanner'); UserHiveBannerText = $window.FindName('UserHiveBannerText') } }
                Update-IgwtGuiUserHiveBanner -Status ([pscustomobject]@{ State = 'Same' })
                $script:Gui.C.UserHiveBanner.Visibility | Should -Be 'Collapsed'
                Update-IgwtGuiUserHiveBanner -Status ([pscustomobject]@{ State = 'Unavailable' })
                $script:Gui.C.UserHiveBanner.Visibility | Should -Be 'Visible'
                $script:Gui.C.UserHiveBannerText.Text | Should -Match "cannot read the signed-in user's own settings"
                Update-IgwtGuiUserHiveBanner -Status ([pscustomobject]@{ State = 'Mapped' })
                $script:Gui.C.UserHiveBannerText.Text | Should -Match 'changed for the signed-in user'
            } finally { $script:Gui = $saved }
        }
    }
}
