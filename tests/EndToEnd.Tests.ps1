# End to end (3.6, finishing prompt step 3): the whole story on the real engine, journal, drift
# guardian, home card and revert, in the test registry. Only window dialogs are mocked. Run once
# on a fresh install and once on a 3.5 install (snapshots, no journal) after the import.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    InModuleScope iGWindowsTuner {
        function script:Initialize-E2E {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            foreach ($n in 'NoDriveTypeAutoRun', 'NoAutorun') { Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name $n }
            Set-IgwtRegistryValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Kind 'String' -Value '1'
            Set-IgwtRegistryValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Kind 'String' -Value '6'
            Set-IgwtRegistryValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Kind 'String' -Value '10'
            foreach ($k in 'Journal', 'Backups') { $d = $(if ($k -eq 'Journal') { Get-IgwtJournalFolder } else { Get-IgwtDataPath -Kind Backups }); if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force } }
            $script:IgwtJournal = $null
            Exit-IgwtChangeLock
        }
        function script:Get-E2EValues {
            [ordered]@{
                GameMode = (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value
                AutoRun  = (Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun').Exists
                Mouse    = (Get-IgwtRegistryValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed').Value
            }
        }
        function script:Assert-E2EChain {
            $script:IgwtJournal = $null
            $j = Read-IgwtJournal
            $j.Status | Should -Be 'Ok' -Because 'the hash chain verifies'
            $j.Count | Should -BeGreaterThan 0
        }
        # The story after the first changes: drift, home card, preview, re-apply, revert, reset everything.
        function script:Invoke-E2EStory {
            param([string]$PresetSession, [switch]$SessionIncludesPointer)
            # 2. Windows (or an app) turns Game Mode back off: the drift guardian finds it.
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            $script:IgwtJournal = $null
            $drift = Get-IgwtDriftReport -NoUpdateHistory
            @($drift.Rows | Where-Object { $_.Status -eq 'Drifted' } | ForEach-Object Item) | Should -Be @('gfx.game-mode')
            # 3. The home card shows it; Do it opens the normal preview (nothing is applied).
            Mock Get-IgwtUpdateHistorySince { @() }
            $in = Get-IgwtHomeCardInput
            $card = Select-IgwtHomeCard -InputData $in
            $card.Kind | Should -Be 'drift'
            $script:Gui = @{ ViewState = @{}; NoStateSave = $true; IsAdmin = $true; Staged = @{}; C = @{}; HomeInput = $in; HomeCardShown = $card }
            Mock Show-IgwtGuiDriftDialog { @{ Action = 'Reapply'; Rows = @($Rows) } }
            Mock Set-IgwtGuiStage { $script:Gui.Staged[$Id] = $Mode }
            Mock Update-IgwtGuiPending { }
            Mock Invoke-IgwtGuiPreview { $script:E2EPreview = $true }
            $script:E2EPreview = $false
            try { Invoke-IgwtGuiHomeAction } finally { $staged = @($script:Gui.Staged.Keys); $op = $script:Gui.PresetOperation; $script:Gui = $null }
            $script:E2EPreview | Should -BeTrue
            (Get-E2EValues).GameMode | Should -Be 0 -Because 'Do it never applies'
            # 4. Re-apply: what Apply runs for the staged items (one session, origin driftFix).
            $r = Invoke-IgwtGuiBatch -ApplyIds $staged -Operation $op -Confirm:$false
            @($r.Results | Where-Object Result -EQ 'Applied' | ForEach-Object Id) | Should -Be @('gfx.game-mode')
            (Get-E2EValues).GameMode | Should -Be 1
            $script:IgwtJournal = $null
            @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['type'] -eq 'driftFix' }).Count | Should -Be 1
            # 5. The chain is valid.
            Assert-E2EChain
            # 6. Revert the preset session: its values go back to what they were before it.
            $plan = @(Get-IgwtRevertPlan -SessionId $PresetSession)
            @($plan | Where-Object { $_.Status -in 'Ready', 'Conflict' }).Count | Should -BeGreaterThan 0
            $res = Invoke-IgwtJournalRevert -Plan $plan -Decisions @{} -Title 'Revert the preset' -Confirm:$false
            (@($res.Results | Where-Object Result -EQ 'Failed' | ForEach-Object { "$($_.Key): $($_.Message)" }) -join ' || ') | Should -BeNullOrEmpty
            $v = Get-E2EValues
            $v.GameMode | Should -Be 0; $v.AutoRun | Should -BeFalse -Because 'the value did not exist before'
            if ($SessionIncludesPointer) { $v.Mouse | Should -Be '1' -Because 'the imported session holds every change still in effect' }
            else { $v.Mouse | Should -Be '0' -Because 'the separate pointer change is not part of the preset session' }
            # Then reset everything iG changed to the baseline ("value before iG").
            $all = @(Get-IgwtRevertPlan -All)
            if (-not $SessionIncludesPointer) { @($all | ForEach-Object Item | Select-Object -Unique) | Should -Contain 'input.pointer-precision-off' }
            $null = Invoke-IgwtJournalRevert -Plan $all -Decisions @{} -Title 'Reset everything iG changed' -Confirm:$false
            $v = Get-E2EValues
            $v.Mouse | Should -Be '1'; $v.GameMode | Should -Be 0; $v.AutoRun | Should -BeFalse
            $script:IgwtJournal = $null
            @(Get-IgwtRevertPlan -All | Where-Object { $_.Status -in 'Ready', 'Conflict' }).Count | Should -Be 0 -Because 'nothing iG changed is left'
            # 7. The chain is still valid; no session is left unfinished.
            Assert-E2EChain
            @(Get-IgwtIncompleteChangeSession).Count | Should -Be 0
        }
        function script:Invoke-E2EPreset {
            # 1. Apply a preset (schema v3) and, separately, one more item.
            $null = Invoke-IgwtApply -Id 'input.pointer-precision-off' -Context (New-IgwtContext)
            $p = ConvertFrom-IgwtPresetV3 -Preset ([pscustomobject]@{ schemaVersion = 3; id = 'e2e'; name = 'End to end'; levelCeiling = 'Advanced'; antiCheatPolicy = 'safeOnly'
                    changes = @([pscustomobject]@{ item = 'gfx.game-mode'; desired = 'on' }, [pscustomobject]@{ item = 'sec.autorun-off'; desired = 'on' }) })
            $sel = Resolve-IgwtPresetSelection -Preset $p -Tags @('formfactor.desktop')
            $r = Invoke-IgwtApply -Id $sel.Ids -Operation 'Preset:e2e' -Context (New-IgwtContext)
            @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 2
            $v = Get-E2EValues
            $v.GameMode | Should -Be 1; $v.AutoRun | Should -BeTrue; $v.Mouse | Should -Be '0'
            $script:IgwtJournal = $null
            return [string](@((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['type'] -eq 'preset' })[-1]['session'])
        }
    }
}

Describe 'End to end' {
    BeforeEach { InModuleScope iGWindowsTuner { Initialize-E2E } }

    It 'on a fresh install: preset, drift, home card, re-apply, revert, reset everything, valid chain' {
        InModuleScope iGWindowsTuner {
            $sid = Invoke-E2EPreset
            Assert-E2EChain
            Invoke-E2EStory -PresetSession $sid
        }
    }
    It 'on a 3.5 install: the import, then the same story' {
        InModuleScope iGWindowsTuner {
            # A 3.5 install: the pointer change and the preset exist only as 3.x snapshots.
            $null = Invoke-E2EPreset
            Remove-Item -LiteralPath (Get-IgwtJournalFolder) -Recurse -Force; $script:IgwtJournal = $null
            $u = Invoke-IgwtJournalUpgrade -Confirm:$false
            $u.Imported | Should -BeGreaterOrEqual 4 -Because 'the mouse values, Game Mode and the two AutoRun values are still applied'
            Assert-E2EChain
            $sid = [string](@((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['type'] -eq 'upgrade' })[0]['session'])
            # The same story, with the imported session in place of the preset session.
            Invoke-E2EStory -PresetSession $sid -SessionIncludesPointer
        }
    }
}
