BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Ctx = New-IgwtTestContext
    function Get-TestValue([string]$Path, [string]$Name) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Get-IgwtRegistryValue -Path $P -Name $N }
    }
    function Write-TestValue([string]$Path, [string]$Name, [string]$Kind, $Value) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name; K = $Kind; V = $Value } { param($P, $N, $K, $V) Set-IgwtRegistryValue -Path $P -Name $N -Kind $K -Value $V }
    }
    function Clear-TestValue([string]$Path, [string]$Name) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Remove-IgwtRegistryValue -Path $P -Name $N }
    }
    $script:GameBar = 'HKCU:\Software\Microsoft\GameBar'
    $script:Explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    function Initialize-TestState {
        Clear-TestValue -Path $script:GameBar -Name 'AutoGameModeEnabled'
        Write-TestValue -Path $script:GameBar -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
        Clear-TestValue -Path $script:Explorer -Name 'NoDriveTypeAutoRun'
        Clear-TestValue -Path $script:Explorer -Name 'NoAutorun'
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder
            if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
            $script:IgwtJournal = $null
            Exit-IgwtChangeLock
        }
    }
    function Get-TestJournal { InModuleScope iGWindowsTuner { $script:IgwtJournal = $null; Read-IgwtJournal } }
}

# The change engine (3.6, DECISIONS T2, T4, T5): steps, read-back, rollback, lock, recovery, revert.
Describe 'Change engine' {
    BeforeEach { Initialize-TestState }

    It 'compares values without the change details (applied, missingDepth at any depth)' {
        InModuleScope iGWindowsTuner {
            # A 3.x snapshot records missingDepth before an item's first action; the journal before each step.
            $snap = [pscustomobject]@{ items = @([pscustomobject]@{ exists = $false; kind = $null; missingDepth = 6; name = 'NoAutorun'; value = $null }) }
            $now = [ordered]@{ items = @([ordered]@{ exists = $false; kind = $null; missingDepth = 0; name = 'NoAutorun'; value = $null }); applied = @{ x = 1 } }
            (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $snap)) | Should -Be (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $now))
            $set = [ordered]@{ items = @([ordered]@{ exists = $true; kind = 'DWord'; missingDepth = 0; name = 'NoAutorun'; value = 1 }) }
            (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $set)) | Should -Not -Be (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $now)) -Because 'the value itself still counts'
        }
    }
    It 'imports the 3.x snapshots once (originals as baselines) and reverts them from the journal' {
        InModuleScope iGWindowsTuner { $b = Get-IgwtDataPath -Kind Backups; if (Test-Path -LiteralPath $b) { Remove-Item -LiteralPath $b -Recurse -Force } }
        $null = Invoke-IgwtApply -Id 'sec.autorun-off', 'gfx.game-mode' -Context $script:Ctx
        (Get-TestValue -Path $script:Explorer -Name 'NoDriveTypeAutoRun').Exists | Should -BeTrue
        # A 3.5 installation: snapshots, no journal.
        InModuleScope iGWindowsTuner { Remove-Item -LiteralPath (Get-IgwtJournalFolder) -Recurse -Force; $script:IgwtJournal = $null }
        $u = InModuleScope iGWindowsTuner { Invoke-IgwtJournalUpgrade -Confirm:$false }
        $u.Imported | Should -Be 3 -Because 'two autorun actions and Game Mode are still applied'
        $u.Baselines | Should -Be 3
        $j = Get-TestJournal
        @($j.Entries | Where-Object { $_['kind'] -eq 'sessionStart' })[0]['origin']['type'] | Should -Be 'upgrade'
        $j.Baselines.Count | Should -Be 3
        (InModuleScope iGWindowsTuner { Invoke-IgwtJournalUpgrade -Confirm:$false }).Message | Should -Be 'Already imported.'
        $plan = @(Get-IgwtRevertPlan -All)
        @($plan | Where-Object Status -EQ 'Ready').Count | Should -Be 3
        $null = Invoke-IgwtJournalRevert -Plan $plan -Title 'Reset everything' -Confirm:$false
        (Get-TestValue -Path $script:Explorer -Name 'NoDriveTypeAutoRun').Exists | Should -BeFalse -Because 'the value did not exist before iG'
        (Get-TestValue -Path $script:GameBar -Name 'AutoGameModeEnabled').Value | Should -Be 0
    }

    It 'journals an apply: session, baseline, intent and committed with the exact previous value' {
        $r = Invoke-IgwtApply -Id 'sec.autorun-off', 'gfx.game-mode' -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 2
        $j = Get-TestJournal
        $j.Status | Should -Be 'Ok'
        $kinds = @($j.Entries | ForEach-Object { [string]$_['kind'] })
        $kinds[0] | Should -Be 'sessionStart'; $kinds[-1] | Should -Be 'sessionEnd'
        @($kinds | Where-Object { $_ -eq 'committed' }).Count | Should -BeGreaterOrEqual 2
        $intents = @($j.Entries | Where-Object { $_['kind'] -eq 'intent' -and $_['item'] -eq 'sec.autorun-off' })
        $intents.Count | Should -Be 2 -Because 'one step per action'
        $intents[0]['origin']['type'] | Should -Be 'tweak'
        $noAutorun = @(foreach ($i in $intents) { foreach ($x in @($i['before']['items'])) { if ($x['name'] -eq 'NoAutorun') { $x } } })
        $noAutorun.Count | Should -Be 1
        $noAutorun[0]['exists'] | Should -BeFalse -Because 'value absent is recorded as absent'
        $gm = @($j.Entries | Where-Object { $_['kind'] -eq 'baseline' -and $_['item'] -eq 'gfx.game-mode' })[0]
        @($gm['before']['items'])[0]['kind'] | Should -Be 'DWord' -Because 'the exact registry kind is kept'
        foreach ($c in @($j.Entries | Where-Object { $_['kind'] -eq 'committed' })) { $c['readBack']['ok'] | Should -BeTrue }
    }
    It 'fails and rolls back an item whose read-back does not match' {
        Mock -ModuleName iGWindowsTuner Get-IgwtActionState { @([pscustomobject]@{ State = 'Off'; Target = 'x' }) } -ParameterFilter { [string]$Action.name -eq 'AutoGameModeEnabled' }
        $r = Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx
        $r.Results[0].Result | Should -Be 'Failed'
        $r.Results[0].Message | Should -Match 'Read back'
        (Get-TestValue $script:GameBar 'AutoGameModeEnabled').Value | Should -Be 0 -Because 'the value was rolled back'
        $kinds = @((Get-TestJournal).Entries | ForEach-Object { [string]$_['kind'] })
        $kinds | Should -Contain 'failed'; $kinds | Should -Contain 'rolledBack'
    }
    It 'refuses a second change while one runs, with a readable message' {
        $name = InModuleScope iGWindowsTuner { Get-IgwtChangeLockName }
        $ps = [powershell]::Create().AddScript({ param($n) $m = New-Object System.Threading.Mutex($false, $n); $null = $m.WaitOne(); Start-Sleep -Seconds 20; $m.ReleaseMutex() }).AddArgument($name)
        $null = $ps.BeginInvoke()
        try {
            Start-Sleep -Milliseconds 700
            InModuleScope iGWindowsTuner { [IO.File]::WriteAllText((Join-Path (Get-IgwtDataPath -Kind State) 'change-lock.json'), '{"title":"Preset Competitive","startedUtc":"2026-10-31T10:00:00.0000000Z"}') }
            { Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx } | Should -Throw '*Another change is running since*Preset Competitive*'
        } finally { $ps.Stop(); $ps.Dispose() }
        (Get-TestValue $script:GameBar 'AutoGameModeEnabled').Value | Should -Be 0
    }
    It 'finds a session cut off between intent and commit and rolls it back' {
        InModuleScope iGWindowsTuner -Parameters @{ Ctx = $script:Ctx } {
            param($Ctx)
            $item = @(Get-IgwtCatalog | Where-Object id -EQ 'gfx.game-mode')[0]
            $t = Get-IgwtActionTarget -ItemId $item.id -Index 0 -Action $item.actions[0]
            $before = Get-IgwtActionSnapshot -Action $item.actions[0] -Context $Ctx
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'sessionStart'; session = 'crashed'; origin = @{ type = 'tweak'; ref = 'Apply' }; title = 'Apply (1 item(s))' })
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'baseline'; session = 'crashed'; step = 1; item = $item.id; target = $t; before = $before })
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent'; session = 'crashed'; step = 1; group = $item.id; op = 'change'; item = $item.id; target = $t; desired = 'on'; before = $before })
            # The change happened, then the app died before writing "committed".
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 1
            $script:IgwtJournal = $null
            $inc = @(Get-IgwtIncompleteChangeSession)
            $inc.Count | Should -Be 1
            $inc[0].Steps[0].Result | Should -Be 'InDoubt'
            $res = Invoke-IgwtChangeRecovery -SessionId 'crashed' -Confirm:$false
            $res.Complete | Should -BeTrue
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
            $script:IgwtJournal = $null
            @(Get-IgwtIncompleteChangeSession).Count | Should -Be 0
        }
    }
    It 'reverts one entry exactly (a value that did not exist is deleted again)' {
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        (Get-TestValue $script:Explorer 'NoAutorun').Exists | Should -BeTrue
        $res = InModuleScope iGWindowsTuner {
            $j = Read-IgwtJournal
            # sec.autorun-off has two registry actions: revert the whole session (both values).
            $entry = @($j.Entries | Where-Object { $_['kind'] -eq 'committed' -and $_['item'] -eq 'sec.autorun-off' })[0]
            $plan = @(Get-IgwtRevertPlan -SessionId ([string]$entry['session']) -Journal $j)
            $plan.Count | Should -Be 2
            @($plan | Where-Object Status -NE 'Ready').Count | Should -Be 0
            Invoke-IgwtJournalRevert -Plan $plan -Confirm:$false
        }
        @($res.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 2
        (Get-TestValue $script:Explorer 'NoAutorun').Exists | Should -BeFalse
        (Get-TestValue $script:Explorer 'NoDriveTypeAutoRun').Exists | Should -BeFalse
    }
    It 'asks before reverting a value that changed since, and follows the choice' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx
        Write-TestValue -Path $script:GameBar -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 7
        InModuleScope iGWindowsTuner {
            $plan = @(Get-IgwtRevertPlan -All)
            $plan.Count | Should -Be 1
            $plan[0].Status | Should -Be 'Conflict'
            $r1 = Invoke-IgwtJournalRevert -Plan $plan -Confirm:$false
            $r1.Results[0].Result | Should -Be 'NeedsDecision'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 7 -Because 'nothing is overwritten silently'
            $r2 = Invoke-IgwtJournalRevert -Plan $plan -Decisions @{ $plan[0].Key = 'Restore' } -Confirm:$false
            $r2.Results[0].Result | Should -Be 'Reverted'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
        }
    }
    It 'keeps the current value when asked, and stops tracking it' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx
        Write-TestValue -Path $script:GameBar -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 7
        InModuleScope iGWindowsTuner {
            $plan = @(Get-IgwtRevertPlan -All)
            $r = Invoke-IgwtJournalRevert -Plan $plan -Decisions @{ $plan[0].Key = 'Keep' } -Confirm:$false
            $r.Results[0].Result | Should -Be 'Kept'
            $script:IgwtJournal = $null
            @(Get-IgwtRevertPlan -All).Count | Should -Be 0 -Because 'a retired value is no longer iG''s to revert'
        }
        (Get-TestValue $script:GameBar 'AutoGameModeEnabled').Value | Should -Be 7
    }
    It 'resets everything to the value before iG, even after several changes' {
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Mode default -Context $script:Ctx
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx
        InModuleScope iGWindowsTuner {
            $plan = @(Get-IgwtRevertPlan -All)
            $plan.Count | Should -Be 1
            $null = Invoke-IgwtJournalRevert -Plan $plan -Confirm:$false
        }
        $v = Get-TestValue $script:GameBar 'AutoGameModeEnabled'
        $v.Value | Should -Be 0; $v.Kind | Should -Be 'DWord'
    }
    It 'refuses targets that no catalog owns and changes nothing when the journal is broken' {
        InModuleScope iGWindowsTuner {
            $fake = [ordered]@{ provider = 'action'; key = 'action|no.such-item|0|x'; item = 'no.such-item'; index = 0; fingerprint = 'x' }
            { Resolve-IgwtChangeTarget -Target $fake } | Should -Throw '*does not exist*'
            { Resolve-IgwtChangeTarget -Target ([ordered]@{ provider = 'raw'; key = 'HKLM\x' }) } | Should -Throw '*not owned by a catalog*'
        }
        $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context $script:Ctx
        InModuleScope iGWindowsTuner {
            $f = @(Get-IgwtJournalSegments)[0]
            $lines = [IO.File]::ReadAllLines($f); $lines[1] = $lines[1].Replace('"session"', '"sessionX"'); [IO.File]::WriteAllLines($f, $lines)
            $script:IgwtJournal = $null
        }
        { Invoke-IgwtApply -Id 'gfx.game-mode' -Mode default -Context $script:Ctx } | Should -Throw '*journal is read-only*'
        (Get-TestValue $script:GameBar 'AutoGameModeEnabled').Value | Should -Be 1 -Because 'nothing changed'
    }
}
