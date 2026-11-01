# Home card (3.6, DECISIONS T11, T18): priority order, snooze persistence and expiry, every card
# action (always a preview or a page first), never writing, and keyboard/automation support.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    # Defined in the module's scope, so InModuleScope blocks can call it.
    InModuleScope iGWindowsTuner { function script:Get-AllInput {
        [pscustomobject]@{
            Journal    = [pscustomobject]@{ Status = 'Ok'; Reason = ''; Count = 10 }
            Incomplete = @([pscustomobject]@{ Id = 's1'; Title = 'Preset:competitive (3 item(s))'; StartedUtc = '2026-10-31T10:00:00Z'; Steps = @([pscustomobject]@{ Step = 1; Item = 'gfx.game-mode'; Result = 'InDoubt'; Before = $null }) })
            Drift      = [pscustomobject]@{ Status = 'Ok'; Summary = '0 still applied, 1 drifted, 0 missing, 0 cannot be read.'; Updates = @(); Rows = @([pscustomobject]@{ Key = 'action|gfx.game-mode|0|x'; Item = 'gfx.game-mode'; Status = 'Drifted'; Target = @{ provider = 'action' }; WeSet = 1; Now = 0 }) }
            Forensic   = [pscustomobject]@{ Expired = $true }
            Preset     = [pscustomobject]@{ Id = 'competitive'; Name = 'Competitive' }
            Unverified = @('sec.lolbin-outbound-block')
        }
    } }
}

Describe 'Home card: priority' {
    It 'shows one card in the fixed order: unfinished change, drift, expired session, Unverified items, suggestion, All clear' {
        InModuleScope iGWindowsTuner {
            $in = Get-AllInput
            (Select-IgwtHomeCard -InputData $in).Kind | Should -Be 'incomplete'
            $in.Incomplete = @(); (Select-IgwtHomeCard -InputData $in).Kind | Should -Be 'drift'
            $in.Drift = $null; (Select-IgwtHomeCard -InputData $in).Kind | Should -Be 'forensic'
            $in.Forensic = $null; (Select-IgwtHomeCard -InputData $in).Kind | Should -Be 'unverified'
            $in.Unverified = @(); $in.Preset = $null; $in.Journal = [pscustomobject]@{ Status = 'Empty'; Reason = ''; Count = 0 }
            (Select-IgwtHomeCard -InputData $in).Kind | Should -Be 'suggestion'
            $in.Preset = [pscustomobject]@{ Id = 'competitive'; Name = 'Competitive' }
            $c = Select-IgwtHomeCard -InputData $in
            $c.Kind | Should -Be 'clear'; $c.Title | Should -Be 'All clear'
        }
    }
    It 'puts a journal problem first' {
        InModuleScope iGWindowsTuner {
            $in = Get-AllInput; $in.Journal = [pscustomobject]@{ Status = 'Broken'; Reason = 'journal-0001.jsonl line 3 does not continue the chain.'; Count = 2 }
            $c = Select-IgwtHomeCard -InputData $in
            $c.Kind | Should -Be 'journal'; $c.Why | Should -BeLike '*line 3*'
        }
    }
    It 'gives every card a one-sentence title, a one-line reason and the details' {
        InModuleScope iGWindowsTuner {
            $in = Get-AllInput
            foreach ($k in 'Incomplete', 'Drift', 'Forensic', 'Unverified') {
                $c = Select-IgwtHomeCard -InputData $in
                $c.Title | Should -Not -Match "`n"; $c.Text | Should -Not -Match "`n"; $c.Why | Should -Not -BeNullOrEmpty
                $in.$k = $(if ($k -eq 'Unverified') { @() } else { $null })
            }
        }
    }
}

Describe 'Home card: Not now' {
    It 'skips a snoozed card until the snooze expires' {
        InModuleScope iGWindowsTuner {
            $in = Get-AllInput; $in.Incomplete = @()
            $drift = Select-IgwtHomeCard -InputData $in
            $snz = @{ ([string]$drift.Key) = (Get-Date).AddDays(1) }
            (Select-IgwtHomeCard -InputData $in -Snoozed $snz).Kind | Should -Be 'forensic'
            (Select-IgwtHomeCard -InputData $in -Snoozed $snz -Now (Get-Date).AddDays(2)).Kind | Should -Be 'drift' -Because 'the snooze expired'
        }
    }
    It 'remembers the snooze across a restart (view state file) for 1 or 7 days' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread'; return }
        $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'guistate'
        try {
            InModuleScope iGWindowsTuner {
                $w = New-IgwtMainWindow
                $script:Gui = @{ Window = $w; ViewState = @{}; NoStateSave = $false; IsAdmin = $true; C = @{} }
                foreach ($n in 'HomeCard', 'HomeCardTitle', 'HomeCardText', 'HomeCardOverline', 'HomeCardDoButton', 'HomeCardSnoozeButton', 'HomeCardSnoozeWeekButton', 'HomeCardWhyButton', 'HomeCardPagesButton') { $script:Gui.C[$n] = $w.FindName($n) }
                Mock Set-IgwtGuiStatus { }
                $in = Get-AllInput; $in.Incomplete = @()
                $script:Gui.HomeInput = $in
                Update-IgwtGuiHomeCard
                $script:Gui.HomeCardShown.Kind | Should -Be 'drift'
                Set-IgwtGuiHomeSnooze -Days 7
                $script:Gui.HomeCardShown.Kind | Should -Be 'forensic'
                # A restart: a new window reads the saved view state.
                $script:Gui.ViewState = Read-IgwtGuiState
                $snz = Get-IgwtGuiHomeSnoozed
                $snz.Count | Should -Be 1
                ([datetime]@($snz.Values)[0] - (Get-Date)).TotalDays | Should -BeGreaterThan 6.9
                (Select-IgwtHomeCard -InputData $in -Snoozed $snz).Kind | Should -Be 'forensic'
                (Select-IgwtHomeCard -InputData $in -Snoozed $snz -Now (Get-Date).AddDays(8)).Kind | Should -Be 'drift'
                $script:Gui = $null
            }
        } finally { Remove-Item Env:\IGWT_GUI_STATE_DIR -ErrorAction SilentlyContinue }
    }
}

Describe 'Home card: actions open a preview or a page, never a change' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            $script:Gui = @{ ViewState = @{}; NoStateSave = $true; IsAdmin = $true; Staged = @{}; C = @{ BackupTabs = [pscustomobject]@{ SelectedItem = $null }; BackupJournalTab = 'journalTab'; FwTabs = [pscustomobject]@{ SelectedItem = $null }; FwForensicTab = 'forensicTab' } }
            $script:Jobs = New-Object System.Collections.Generic.List[string]
            Mock Select-IgwtGuiNavPage { $script:LastNav = $Tag }
            Mock Start-IgwtGuiJob { $script:Jobs.Add($Command); $true }
            Mock Set-IgwtGuiStatus { }
            Mock Update-IgwtGuiPending { }
            Mock Set-IgwtGuiStage { $script:Gui.Staged[$Id] = $Mode }
            Mock Invoke-IgwtGuiPreview { $script:Previewed = $true }
            $script:Previewed = $false; $script:LastNav = ''
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:Gui = $null } }
    It 'opens the page for <Action>' -ForEach @(
        @{ Action = 'openJournal'; Page = 'Backups' }, @{ Action = 'forensic'; Page = 'Firewall' }, @{ Action = 'presets'; Page = 'Presets' }, @{ Action = 'unverified'; Page = 'Presets' }
    ) {
        InModuleScope iGWindowsTuner -Parameters @{ A = $Action; P = $Page } {
            param($A, $P)
            $script:Gui.HomeCardShown = [pscustomobject]@{ Action = $A; Kind = $A; Items = @('x') }
            Invoke-IgwtGuiHomeAction
            $script:LastNav | Should -Be $P
            $script:Jobs.Count | Should -Be 0
        }
    }
    It 'rolls back an unfinished change only after the preview is confirmed' {
        InModuleScope iGWindowsTuner {
            $in = Get-AllInput; $script:Gui.HomeInput = $in
            $script:Gui.HomeCardShown = Select-IgwtHomeCard -InputData $in
            Mock Show-IgwtGuiTextDialog { $false }
            Invoke-IgwtGuiHomeAction
            $script:Jobs.Count | Should -Be 0 -Because 'the preview was cancelled'
            Mock Show-IgwtGuiTextDialog { $true }
            Invoke-IgwtGuiHomeAction
            @($script:Jobs) | Should -Be @('Invoke-IgwtChangeRecovery')
        }
    }
    It 're-applies drift through the normal preview, and accepts it as a journaled change' {
        InModuleScope iGWindowsTuner {
            $in = Get-AllInput; $in.Incomplete = @(); $script:Gui.HomeInput = $in
            $script:Gui.HomeCardShown = Select-IgwtHomeCard -InputData $in
            Mock Show-IgwtGuiDriftDialog { @{ Action = 'Reapply'; Rows = @($Rows) } }
            Invoke-IgwtGuiHomeAction
            $script:Previewed | Should -BeTrue
            $script:Gui.Staged['gfx.game-mode'] | Should -Be 'on'
            $script:Gui.PresetOperation | Should -Be 'DriftFix'
            $script:Jobs.Count | Should -Be 0 -Because 'Do it never applies directly'
            Mock Show-IgwtGuiDriftDialog { @{ Action = 'Accept'; Rows = @($Rows) } }
            Invoke-IgwtGuiHomeAction
            @($script:Jobs) | Should -Be @('Invoke-IgwtDriftAccept')
            Mock Show-IgwtGuiDriftDialog { $null }
            Invoke-IgwtGuiHomeAction
            @($script:Jobs).Count | Should -Be 1 -Because 'Cancel does nothing'
        }
    }
}

Describe 'Home card: never writes' {
    It 'reads its inputs and chooses a card without writing the system or the journal' {
        InModuleScope iGWindowsTuner { Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0; $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null }
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            $script:IgwtJournal = $null
            $before = (Read-IgwtJournal -NoEntries).Hash
            $saved = @{}
            foreach ($k in @($script:IgwtChangeProviders.Keys)) { $p = $script:IgwtChangeProviders[$k]; $saved[$k] = @{ Set = $p.Set; Restore = $p.Restore }; $p.Set = { throw 'Set called' }; $p.Restore = { throw 'Restore called' } }
            try {
                Mock Add-IgwtJournalEntry { throw 'journal written' }
                Mock Invoke-IgwtActionApply { throw 'applied' }
                Mock Set-IgwtRegistryValue { throw 'registry written' }
                Mock Get-IgwtUpdateHistorySince { @() }
                $in = Get-IgwtHomeCardInput
                $c = Select-IgwtHomeCard -InputData $in
            } finally { foreach ($k in $saved.Keys) { $script:IgwtChangeProviders[$k].Set = $saved[$k].Set; $script:IgwtChangeProviders[$k].Restore = $saved[$k].Restore } }
            $c.Kind | Should -Be 'drift'
            $script:IgwtJournal = $null
            (Read-IgwtJournal -NoEntries).Hash | Should -Be $before
        }
    }
}

Describe 'Home card: keyboard and automation' {
    It 'names every control and reaches every button by keyboard' {
        $x = [xml](Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\src\Gui\MainWindow.xaml') -Raw)
        $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable); $ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation'); $ns.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
        $card = $x.SelectSingleNode("//*[@x:Name='HomeCard']", $ns)
        $card | Should -Not -BeNullOrEmpty
        $card.GetAttribute('AutomationProperties.Name') | Should -Not -BeNullOrEmpty
        $buttons = @($card.SelectNodes('.//w:Button', $ns))
        $buttons.Count | Should -Be 5
        foreach ($b in $buttons) {
            $b.GetAttribute('AutomationProperties.Name') | Should -Not -BeNullOrEmpty -Because $b.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
            $b.GetAttribute('AutomationProperties.AutomationId') | Should -Not -BeNullOrEmpty
            $b.GetAttribute('IsTabStop') | Should -Not -Be 'False'
            $b.GetAttribute('TabIndex') | Should -Not -BeNullOrEmpty -Because 'the buttons have a keyboard order'
        }
        foreach ($t in @($card.SelectNodes('.//w:TextBlock', $ns))) { $t.GetAttribute('AutomationProperties.AutomationId') | Should -Not -BeNullOrEmpty }
    }
}
