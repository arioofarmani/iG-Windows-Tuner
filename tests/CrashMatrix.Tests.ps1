# 3.9 stage B (B3): crash matrix. A crash is simulated by letting every journal write after a chosen
# point fail, which is what the journal sees when the process dies there. After each crash the
# unfinished change must be offered for recovery, and recovery must restore every value exactly.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Item = 'gfx.background-recording-off'
}

Describe '3.9 B3: crash at every journal step, then recovery' {
    BeforeEach {
        InModuleScope iGWindowsTuner -Parameters @{ Item = $script:Item } {
            param($Item)
            foreach ($d in @((Get-IgwtJournalFolder), (Get-IgwtDataPath -Kind Backups))) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force } }
            $script:IgwtJournal = $null
            Exit-IgwtChangeLock
            # A known starting point: every action of the item at a value that is not its "on" value.
            $t = Get-IgwtTweak -Id $Item
            foreach ($a in @($t.actions)) { Set-IgwtRegistryValue -Path ([string]$a.path) -Name ([string]$a.name) -Kind 'DWord' -Value 7 }
            $script:CrashBefore = ConvertTo-IgwtCanonicalJson @(foreach ($a in @($t.actions)) { Remove-IgwtVolatileSnapshotKey (Get-IgwtActionSnapshot -Action $a -Context (New-IgwtContext)) })
        }
    }

    It 'crash <Name>: the change is offered for recovery and recovery restores every value exactly' -ForEach @(
        @{ Name = 'after the first intent (before any value changed)'; Kind = 'intent'; Nth = 1; ExpectSteps = $true }
        @{ Name = 'after the first value changed, before its commit'; Kind = 'committed'; Nth = 1; ExpectSteps = $true }
        @{ Name = 'in the middle of the item (second value before its commit)'; Kind = 'committed'; Nth = 2; ExpectSteps = $true }
        @{ Name = 'after every commit, before the session end'; Kind = 'sessionEnd'; Nth = 1; ExpectSteps = $true }
    ) {
        InModuleScope iGWindowsTuner -Parameters @{ Item = $script:Item; Kind = $Kind; Nth = $Nth } {
            param($Item, $Kind, $Nth)
            # A mock body does not capture locals: the crash point lives in module scope.
            $script:CrashReal = (Get-Item 'function:Add-IgwtJournalEntry').ScriptBlock
            $script:CrashKind = $Kind; $script:CrashNth = $Nth; $script:CrashSeen = 0; $script:Crashed = $false
            Mock Add-IgwtJournalEntry {
                if ($script:CrashKind -and -not $script:Crashed -and [string]$Entry['kind'] -eq $script:CrashKind) {
                    $script:CrashSeen++
                    # An intent is written, then the process dies; any other kind dies before it is written.
                    if ($script:CrashSeen -eq $script:CrashNth) {
                        $script:Crashed = $true
                        if ($script:CrashKind -eq 'intent') { $null = & $script:CrashReal -Entry $Entry }
                        throw 'simulated crash'
                    }
                }
                if ($script:Crashed -and $script:CrashKind) { throw 'simulated crash' }
                & $script:CrashReal -Entry $Entry
            }
            try { $null = Invoke-IgwtApply -Id $Item -Context (New-IgwtContext) } catch { $null = $_ }
            Exit-IgwtChangeLock
            $script:Crashed | Should -BeTrue -Because 'the crash point was reached'
            # The process "restarts": every journal write goes through the real writer again.
            $script:CrashKind = ''
        }
        # The process "restarts": the real journal writer is back.
        InModuleScope iGWindowsTuner -Parameters @{ Item = $script:Item } {
            param($Item)
            $script:IgwtJournal = $null
            $inc = @(Get-IgwtIncompleteChangeSession -Journal (Read-IgwtJournal) | Where-Object { @($_.Steps).Count })
            $inc.Count | Should -Be 1 -Because 'the unfinished change is offered'
            $r = Invoke-IgwtChangeRecovery -SessionId ([string]$inc[0].Id) -Confirm:$false
            $r.Complete | Should -BeTrue -Because (@($r.Errors) -join '; ')
            $t = Get-IgwtTweak -Id $Item
            $after = ConvertTo-IgwtCanonicalJson @(foreach ($a in @($t.actions)) { Remove-IgwtVolatileSnapshotKey (Get-IgwtActionSnapshot -Action $a -Context (New-IgwtContext)) })
            $after | Should -Be $script:CrashBefore -Because 'recovery restores every value exactly'
            $script:IgwtJournal = $null
            @(Get-IgwtIncompleteChangeSession -Journal (Read-IgwtJournal) | Where-Object { @($_.Steps).Count }).Count | Should -Be 0 -Because 'a finished recovery is not offered again'
        }
    }
}
