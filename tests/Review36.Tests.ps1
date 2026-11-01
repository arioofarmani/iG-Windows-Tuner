# Regression tests for the 3.6 independent review (docs\REVIEW.md, findings R1-R22).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    InModuleScope iGWindowsTuner {
        function script:Initialize-R36 {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            foreach ($n in 'NoDriveTypeAutoRun', 'NoAutorun') { Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name $n }
            foreach ($d in @((Get-IgwtJournalFolder), (Get-IgwtDataPath -Kind Backups))) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force } }
            $script:IgwtJournal = $null
            Exit-IgwtChangeLock
        }
    }
}

Describe 'Review 3.6 regressions' {
    BeforeEach { InModuleScope iGWindowsTuner { Initialize-R36 } }

    It 'R1: the 3.x import ignores snapshot files a standard user could have written' {
        InModuleScope iGWindowsTuner {
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            Remove-Item -LiteralPath (Get-IgwtJournalFolder) -Recurse -Force; $script:IgwtJournal = $null
            Mock Test-IgwtTrustedFile { $Path -notlike '*snapshot-*' }
            $u = Invoke-IgwtJournalUpgrade -Confirm:$false
            $u.Imported | Should -Be 0
            $u.Baselines | Should -Be 0 -Because 'an untrusted snapshot never becomes a baseline'
        }
    }
    It 'R2: a write torn in the middle of an entry (right prefix, tail missing) is recorded, not a broken journal' {
        InModuleScope iGWindowsTuner {
            $e = [ordered]@{ kind = 'committed'; session = 's'; step = 1; target = @{ provider = 'registry'; key = 'k1' }; after = 1 }
            $null = Add-IgwtJournalEntry -Entry $e
            $j = Get-IgwtJournalState
            $file = @(Get-IgwtJournalSegments)[0]
            $line = '{"prev":"' + $j.Hash + '","seq":2,"id":"x","kind":"committed","session":"s","targ'
            [IO.File]::AppendAllText($file, $line)
            $script:IgwtJournal = $null
            $r = Read-IgwtJournal
            $r.Status | Should -Be 'Ok'; $r.TornPending | Should -BeTrue
            $null = Add-IgwtJournalEntry -Entry $e
            $script:IgwtJournal = $null
            $r2 = Read-IgwtJournal
            $r2.Status | Should -Be 'Ok'
            @($r2.Entries | Where-Object { $_['kind'] -eq 'chainNote' }).Count | Should -Be 1
        }
    }
    It 'R3 and R9: a legacy revert is one-way in the journal and its targets stop being tracked' {
        InModuleScope iGWindowsTuner {
            $r = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
            $script:IgwtJournal = $null
            $sid = @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['ref'] -eq 'Invoke-IgwtRevert' })[0]['session']
            @(Get-IgwtRevertPlan -SessionId $sid)[0].Status | Should -Be 'Refused' -Because 'its own snapshot cannot undo it'
            @((Get-IgwtDriftReport -NoUpdateHistory).Rows).Count | Should -Be 0 -Because 'the reverted target is no longer iG''s change'
            @(Get-IgwtRevertPlan -All | Where-Object { $_.Status -in 'Ready', 'Conflict' }).Count | Should -Be 0
            $script:IgwtModuleOperations['Restore-IgwtFirewallProfileSnapshot'] | Should -Be '' -Because 'R7: one-way'
        }
    }
    It 'R4: a journal folder that is not protected makes the journal read-only' {
        InModuleScope iGWindowsTuner {
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent' })
            Mock Test-IgwtTrustedFile { $false }
            $script:IgwtJournal = $null
            $r = Read-IgwtJournal
            $r.Status | Should -Be 'Broken'; $r.Reason | Should -BeLike '*not protected*'
            { Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 't' -Confirm:$false } | Should -Throw '*read-only*'
        }
    }
    It 'R5: a step interrupted after its intent stays visible to recovery although the session ended' {
        InModuleScope iGWindowsTuner {
            $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'interrupted' -Confirm:$false
            $tg = Get-IgwtActionTarget -ItemId 'gfx.game-mode' -Index 0 -Action @(@(Get-IgwtTweak -Id 'gfx.game-mode')[0].actions)[0]
            $s.Step++
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent'; session = $s.Id; step = $s.Step; op = 'change'; item = 'gfx.game-mode'; target = $tg; desired = 'on'; before = @{ x = 1 } })
            Complete-IgwtChangeSession -Session $s
            $script:IgwtJournal = $null
            $inc = @(Get-IgwtIncompleteChangeSession)
            $inc.Count | Should -Be 1
            @($inc[0].Steps)[0].Result | Should -Be 'InDoubt'
            @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionEnd' })[0]['outcome'] | Should -Be 'interrupted'
        }
    }
    It 'R6: an open reader does not make an append fail' {
        InModuleScope iGWindowsTuner {
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent' })
            $file = @(Get-IgwtJournalSegments)[0]
            $fs = New-Object System.IO.FileStream($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            try { { $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent' }) } | Should -Not -Throw } finally { $fs.Dispose() }
            $script:IgwtJournal = $null
            (Read-IgwtJournal).Count | Should -Be 2
        }
    }
    It 'R8: every backup-based writer records its backup as the undo reference before changing anything' {
        InModuleScope iGWindowsTuner {
            $root = Join-Path $PSScriptRoot '..\src\Policy'
            foreach ($f in 'GpoStore.ps1', 'AuditPolicy.ps1', 'SecurityPolicy.ps1', 'PolicyBridge.ps1', 'PolicyPresets.ps1') { (Get-Content -LiteralPath (Join-Path $root $f) -Raw) | Should -Match 'Set-IgwtModuleOperationRef -Path' -Because $f }
            $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'ref' -Confirm:$false
            try {
                $script:IgwtModuleStep = [pscustomobject]@{ Ref = ''; Session = $s.Id; Step = 1 }
                Set-IgwtModuleOperationRef -Path 'C:\backup-a'
                Set-IgwtModuleOperationRef -Path 'C:\backup-b'
            } finally { $script:IgwtModuleStep = $null; Complete-IgwtChangeSession -Session $s }
            $script:IgwtJournal = $null
            @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'moduleRef' } | ForEach-Object { $_['ref'] }) | Should -Be @('C:\backup-a') -Because 'the first backup is the one taken before the change'
        }
    }
    It 'R10: the import keeps a value changed since the 3.x apply as the original only (no silent overwrite)' {
        InModuleScope iGWindowsTuner {
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            Remove-Item -LiteralPath (Get-IgwtJournalFolder) -Recurse -Force; $script:IgwtJournal = $null
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            $u = Invoke-IgwtJournalUpgrade -Confirm:$false
            $u.Imported | Should -Be 0
            $u.Baselines | Should -Be 1
            @($u.Skipped)[0] | Should -BeLike '*no longer in the state iG set*'
        }
    }
    It 'R11: an item that is on without any snapshot is recorded as adopted, original unknown' {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Kind 'DWord' -Value 255
            Set-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Kind 'DWord' -Value 1
            $u = Invoke-IgwtJournalUpgrade -Confirm:$false
            $u.Adopted | Should -BeGreaterOrEqual 2
            $script:IgwtJournal = $null
            $a = @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'adopted' -and $_['item'] -eq 'sec.autorun-off' })
            $a.Count | Should -Be 2
            $a[0]['original'] | Should -Be 'unknown'
            @(Get-IgwtRevertPlan -All | Where-Object { $_.Item -eq 'sec.autorun-off' }).Count | Should -Be 0 -Because 'an unknown original is never restored'
        }
    }
    It 'R12: recovery leaves a value changed since iG set it, and skips a session that finished meanwhile' {
        InModuleScope iGWindowsTuner {
            $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'crash' -Confirm:$false
            $tg = Get-IgwtActionTarget -ItemId 'gfx.game-mode' -Index 0 -Action @(@(Get-IgwtTweak -Id 'gfx.game-mode')[0].actions)[0]
            $r = Invoke-IgwtChangeStep -Session $s -Target $tg -Desired 'on' -Group 'gfx.game-mode' -Confirm:$false
            $r.Result | Should -Be 'Committed'
            Exit-IgwtChangeLock   # the process stopped: no sessionEnd
            # Someone changes the value afterwards.
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 5
            $script:IgwtJournal = $null
            $rec = Invoke-IgwtChangeRecovery -SessionId $s.Id -Confirm:$false
            @($rec.Skipped).Count | Should -Be 1
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 5
            $script:IgwtJournal = $null
            @(Get-IgwtIncompleteChangeSession).Count | Should -Be 0
        }
    }
    It 'Q2: the journal page formats values parsed back from the journal (Dictionary keys in Windows PowerShell 5.1)' {
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            $script:IgwtJournal = $null
            $tl = Get-IgwtJournalTimeline
            $tl.Status | Should -Be 'Ok'
            @($tl.Rows | Where-Object { $_.Before -eq 'absent' }).Count | Should -BeGreaterThan 0
            @($tl.Rows | Where-Object { $_.After -like 'DWord*' }).Count | Should -BeGreaterThan 0
        }
    }
    It 'R14: a path that climbs out of its parent with .. is not under it' {
        InModuleScope iGWindowsTuner {
            Test-IgwtPathUnder -Path 'C:\Data\Backups\..\..\Windows\x' -Parent 'C:\Data' | Should -BeFalse
            Test-IgwtPathUnder -Path 'C:\Data\Backups\x.json' -Parent 'C:\Data' | Should -BeTrue
        }
    }
}
