# Update drift guardian (3.6, DECISIONS T10, T17): read-only by construction, the four classes,
# updates reported as "installed in between", accept and re-apply, and the 500-settings budget.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:GameBar = 'HKCU:\Software\Microsoft\GameBar'
    $script:Explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    function Initialize-DriftState {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
            Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun'
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null
            Exit-IgwtChangeLock
        }
    }
}

Describe 'Update drift guardian' {
    BeforeEach { Initialize-DriftState }

    It 'reports still applied, drifted and missing values, and calls no Set or Restore' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode', 'sec.autorun-off' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            # Windows (or the user) changes one value and removes another.
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
            $saved = @{}
            foreach ($k in @($script:IgwtChangeProviders.Keys)) {
                $p = $script:IgwtChangeProviders[$k]; $saved[$k] = @{ Set = $p.Set; Restore = $p.Restore }
                $p.Set = { throw 'The drift check called Set.' }; $p.Restore = { throw 'The drift check called Restore.' }
            }
            try {
                Mock Invoke-IgwtActionApply { throw 'The drift check applied something.' }
                Mock Add-IgwtJournalEntry { throw 'The drift check wrote the journal.' }
                $script:IgwtJournal = $null
                $d = Get-IgwtDriftReport -NoUpdateHistory
            } finally { foreach ($k in $saved.Keys) { $script:IgwtChangeProviders[$k].Set = $saved[$k].Set; $script:IgwtChangeProviders[$k].Restore = $saved[$k].Restore } }
            $d.Status | Should -Be 'Ok'
            @($d.Rows | Where-Object { $_.Item -eq 'gfx.game-mode' })[0].Status | Should -Be 'Drifted'
            @($d.Rows | Where-Object { $_.Item -eq 'sec.autorun-off' -and $_.Status -eq 'Missing' }).Count | Should -Be 1
            @($d.Rows | Where-Object { $_.Item -eq 'sec.autorun-off' -and $_.Status -eq 'StillApplied' }).Count | Should -Be 1
            $d.Summary | Should -Be '1 still applied, 1 drifted, 1 missing, 0 cannot be read.'
        }
    }
    It 'reports a value it cannot read as Can''t read, not as drifted' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            $orig = $script:IgwtChangeProviders['action'].Get
            $script:IgwtChangeProviders['action'].Get = { throw (New-Object System.UnauthorizedAccessException('Access is denied.')) }
            try { $script:IgwtJournal = $null; $d = Get-IgwtDriftReport -NoUpdateHistory } finally { $script:IgwtChangeProviders['action'].Get = $orig }
            @($d.Rows)[0].Status | Should -Be 'CantRead'
            @($d.Rows)[0].Message | Should -BeLike '*administrator*'
        }
    }
    It 'names updates installed in between as such, never as the cause' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            Mock Get-IgwtUpdateHistorySince { [pscustomobject]@{ Time = (Get-Date); Title = '2026-10 Cumulative Update for Windows 11 (KB5099999)' } }
            $script:IgwtJournal = $null
            $d = Get-IgwtDriftReport
            @($d.Updates).Count | Should -Be 1
            $d.Summary | Should -BeLike '*installed in between (they may or may not be related)*'
            $d.Summary | Should -Not -BeLike '*caused*'
        }
    }
    It 'reads the update title by its Data Name from event 19' {
        InModuleScope iGWindowsTuner {
            $xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="updateTitle">Security Intelligence Update (KB2267602)</Data><Data Name="updateGuid">{X}</Data></EventData></Event>'
            Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = (Get-Date) } | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $xml } -PassThru }
            $u = @(Get-IgwtUpdateHistorySince -Since (Get-Date).AddDays(-1))
            $u[0].Title | Should -Be 'Security Intelligence Update (KB2267602)'
            Should -Invoke Get-WinEvent -ParameterFilter { $FilterHashtable.Id -eq 19 -and $FilterHashtable.LogName -eq 'System' -and $FilterHashtable.ProviderName -eq 'Microsoft-Windows-WindowsUpdateClient' }
        }
    }
    It 'accepts the current value (journaled, nothing changed) and then stops reporting it' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            $script:IgwtJournal = $null
            $d = Get-IgwtDriftReport -NoUpdateHistory
            (Invoke-IgwtDriftAccept -Rows $d.Rows -Confirm:$false).Accepted | Should -Be 1
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
            $script:IgwtJournal = $null
            @((Get-IgwtDriftReport -NoUpdateHistory).Rows).Count | Should -Be 0
            @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['type'] -eq 'driftAccept' }).Count | Should -Be 1
        }
    }
    It 'accepts or re-applies one item at a time as well as all of them' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode', 'sec.autorun-off' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
            $script:IgwtJournal = $null
            $rows = @((Get-IgwtDriftReport -NoUpdateHistory).Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' })
            $rows.Count | Should -Be 2
            # Accept only the Game Mode value; the AutoRun value is re-applied on its own.
            (Invoke-IgwtDriftAccept -Rows @($rows | Where-Object { $_.Item -eq 'gfx.game-mode' }) -Confirm:$false).Accepted | Should -Be 1
            $script:IgwtJournal = $null
            $left = @((Get-IgwtDriftReport -NoUpdateHistory).Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' })
            @($left | ForEach-Object Item) | Should -Be @('sec.autorun-off')
            $null = Invoke-IgwtApply -Id (Get-IgwtDriftReapplyIds -Rows $left) -Operation 'DriftFix' -Context (New-IgwtContext)
            $script:IgwtJournal = $null
            @((Get-IgwtDriftReport -NoUpdateHistory).Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' }).Count | Should -Be 0
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0 -Because 'the accepted value stays'
        }
    }
    It 're-applies drifted items as a journaled session with origin driftFix' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtTestContext)
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            $script:IgwtJournal = $null
            $ids = Get-IgwtDriftReapplyIds -Rows (Get-IgwtDriftReport -NoUpdateHistory).Rows
            $ids | Should -Be @('gfx.game-mode')
            @(Get-IgwtPlan -Id $ids)[0].Plan | Should -Be 'Change'
            $null = Invoke-IgwtApply -Id $ids -Operation 'DriftFix' -Context (New-IgwtContext)
            $script:IgwtJournal = $null
            @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['type'] -eq 'driftFix' }).Count | Should -Be 1
            @((Get-IgwtDriftReport -NoUpdateHistory).Rows)[0].Status | Should -Be 'StillApplied'
        }
    }
    It 'checks 500 settings in under 2 s' {
        InModuleScope iGWindowsTuner {
            # 500 tracked targets of a test provider (the budget is the check, not the registry).
            $script:IgwtChangeProviders['driftTest'] = @{ Reversible = { 'exact' }; Resolve = { param($t, $c) $null = $c; [pscustomobject]@{ N = [int]$t['n'] } }; Get = { param($r, $ctx) $null = $ctx; [ordered]@{ value = $(if ($r.N % 10) { 1 } else { 2 }) } }; Set = { throw 'no' }; Restore = { throw 'no' }; TestSet = { throw 'no' } }
            try {
                $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'drift budget' -Confirm:$false
                try { foreach ($i in 1..500) { $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'committed'; session = $s.Id; step = $i; op = 'change'; item = "x$i"; target = [ordered]@{ provider = 'driftTest'; key = "driftTest|$i"; n = $i }; after = [ordered]@{ value = 1 } }) } }
                finally { Complete-IgwtChangeSession -Session $s }
                $script:IgwtJournal = $null
                $j = Read-IgwtJournal -NoEntries
                $best = [double]::MaxValue
                foreach ($k in 1..3) { $sw = [Diagnostics.Stopwatch]::StartNew(); $d = Get-IgwtDriftReport -Journal $j -NoUpdateHistory; $best = [Math]::Min([double]$best, [double]$sw.Elapsed.TotalMilliseconds) }
                @($d.Rows).Count | Should -Be 500
                @($d.Rows | Where-Object Status -EQ 'Drifted').Count | Should -Be 50
                Write-Information -InformationAction Continue -MessageData ("    drift check: 500 settings in {0:N0} ms" -f $best)
                $best | Should -BeLessThan 2000
            } finally { $script:IgwtChangeProviders.Remove('driftTest') }
        }
    }
}
