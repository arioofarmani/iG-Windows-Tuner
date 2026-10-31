# Transaction.ps1
# The change engine (3.6, DECISIONS T1, T2, T5): every system change is a step of a session in
# the change journal (Journal.ps1). A step writes an "intent" entry with the captured "before",
# calls its provider's Set or Restore, reads the target back, and records "committed" or
# "failed". A failed step rolls back the steps of its group (one catalog item, or one forensic
# session) in reverse order. One change runs at a time machine-wide (named mutex); a second
# request gets a readable message. Providers are thin adapters over the tested handlers; the
# "action" provider covers every catalog action type through the engine dispatch (Engine.ps1).

$script:IgwtChangeLock = $null

#region Canonical comparison

function ConvertTo-IgwtCanonicalJson {
    <#
    .SYNOPSIS
        A value as JSON with object keys sorted and numbers in invariant form, so a value captured
        live and the same value read back from the journal compare equal. Pure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    $norm = {
        param($v)
        if ($null -eq $v) { return $null }
        if ($v -is [string] -or $v -is [bool] -or $v -is [char]) { return $v }
        if ($v -is [datetime]) { return $v.ToUniversalTime().ToString('o') }
        if ($v -is [byte] -or $v -is [int16] -or $v -is [int] -or $v -is [long] -or $v -is [uint16] -or $v -is [uint32] -or $v -is [uint64] -or $v -is [decimal] -or $v -is [double] -or $v -is [single]) { return [decimal]$v }
        if ($v -is [System.Collections.IDictionary]) {
            $o = [ordered]@{}
            foreach ($k in @($v.Keys | ForEach-Object { [string]$_ } | Sort-Object)) { $o[$k] = & $norm $v[$k] }
            return $o
        }
        if ($v -is [System.Management.Automation.PSCustomObject]) {
            $o = [ordered]@{}
            foreach ($k in @($v.PSObject.Properties.Name | Sort-Object)) { $o[$k] = & $norm $v.$k }
            return $o
        }
        if ($v -is [System.Collections.IEnumerable]) { return , @(foreach ($x in $v) { & $norm $x }) }
        return [string]$v
    }
    return (ConvertTo-Json -InputObject (& $norm $Value) -Compress -Depth 20)
}

function Remove-IgwtVolatileSnapshotKey {
    <# .SYNOPSIS A copy of snapshot data without the keys that describe the apply itself ("applied"), for read-back comparison. Pure. #>
    [CmdletBinding()]
    param([AllowNull()]$Data)
    if ($Data -isnot [System.Collections.IDictionary]) { return $Data }
    $o = [ordered]@{}
    foreach ($k in $Data.Keys) { if ([string]$k -ne 'applied') { $o[[string]$k] = $Data[$k] } }
    return $o
}

#endregion

#region Providers

function Get-IgwtActionTarget {
    <#
    .SYNOPSIS
        The journal target of one catalog action: provider "action", key "action|<item>|<index>|<fingerprint>".
        The fingerprint ties the target to the action's identifying fields (a changed catalog
        definition no longer matches). Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ItemId, [Parameter(Mandatory = $true)][int]$Index, [Parameter(Mandatory = $true)]$Action)
    $fp = Get-IgwtActionFingerprint $Action
    return [ordered]@{ provider = 'action'; key = "action|$ItemId|$Index|$fp"; item = $ItemId; index = $Index; type = [string]$Action.type; fingerprint = $fp }
}

function Resolve-IgwtChangeTarget {
    <#
    .SYNOPSIS
        Checks that a journal target is owned by a catalog (DECISIONS T4) and returns what its
        provider needs (for "action": the catalog action). Anything else is refused, whatever a
        journal entry says. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, $Catalog)
    $provider = [string]$Target['provider']
    $def = $script:IgwtChangeProviders[$provider]
    if (-not $def) { throw "No change provider '$provider': this target is not owned by a catalog and is not changed." }
    return (& $def.Resolve $Target $Catalog)
}

$script:IgwtChangeProviders = @{
    # Every catalog action type, through the engine dispatch (State/Snapshot/Apply/Restore per type).
    action = @{
        Reversible = { param($r) if ([string]$r.Action.type -in 'appx', 'winget', 'capability', 'cleanerRule') { 'oneWay' } else { 'exact' } }
        Resolve    = {
            param($t, $catalog)
            $null = $catalog
            # The same lookup the engine uses to select items (Get-IgwtTweak: the catalog by id).
            $item = $null
            try { $item = @(Get-IgwtTweak -Id ([string]$t['item']))[0] } catch { $item = $null }
            if (-not $item) { throw "Catalog item '$($t['item'])' does not exist: its journal target is not changed." }
            $i = [int]$t['index']
            $actions = @($item.actions)
            if ($i -lt 0 -or $i -ge $actions.Count) { throw "Catalog item '$($t['item'])' has no action ${i}: its journal target is not changed." }
            if ((Get-IgwtActionFingerprint $actions[$i]) -ne [string]$t['fingerprint']) { throw "The catalog definition of '$($t['item'])' changed since this entry: its target is not changed automatically." }
            return [pscustomobject]@{ Item = $item; Action = $actions[$i]; Index = $i }
        }
        Get        = { param($r, $ctx) Get-IgwtActionSnapshot -Action $r.Action -Context $ctx }
        Set        = { param($r, $desired, $ctx) Invoke-IgwtActionApply -Action $r.Action -Context $ctx -Mode $desired -Confirm:$false }
        Restore    = { param($r, $data, $ctx) Restore-IgwtActionSnapshot -Action $r.Action -Snapshot $data -Context $ctx -Confirm:$false }
        # After Set: the action's own state must be On (or not On after a reset to the Windows default).
        TestSet    = {
            param($r, $desired, $ctx)
            $a = $r.Action
            if ([string]$a.type -eq 'check') { return [pscustomobject]@{ Ok = $true; State = 'check'; Note = 'A check changes nothing.' } }
            if ($desired -eq 'default' -and [string]$a.type -in 'registry', 'adapterRegistry', 'netAdapterPower') {
                # Exact: every target now holds what "default" writes (the documented value, or absent).
                foreach ($t in @(Get-IgwtRegistryTargets -Action $a -Context $ctx)) {
                    $cur = Get-IgwtRegistryValue -Path $t.Path -Name $t.Name
                    $d = Get-IgwtRegistryDesired -Action $a -Current $cur -Mode 'default'
                    $okT = $(if ($d.Absent) { -not $cur.Exists } else { $cur.Exists -and (Test-IgwtRegistryValueEqual -Left $cur.Value -Right $d.Value -Kind $d.Kind) })
                    if (-not $okT) { return [pscustomobject]@{ Ok = $false; State = 'notDefault'; Note = "Read back $($t.Path)\$($t.Name) after resetting it, and it is not the Windows default (possibly a policy or Tamper Protection)." } }
                }
                return [pscustomobject]@{ Ok = $true; State = 'default'; Note = '' }
            }
            $states = @(Get-IgwtActionState -Action $a -Context $ctx | ForEach-Object { [string]$_.State })
            $roll = Get-IgwtStateRollup -States $states
            # A Windows default can equal the "on" value (for example Game Mode is on by default).
            $defaultIsOn = ($null -ne $a.default -and $null -ne $a.on -and [string]$a.default -eq [string]$a.on)
            $ok = $(if ($desired -eq 'on') { $roll -in 'On', 'NotApplicable' } else { $roll -in 'Off', 'NotApplicable' -or ($defaultIsOn -and $roll -eq 'On') })
            return [pscustomobject]@{ Ok = $ok; State = $roll; Note = $(if ($ok) { '' } else { "Read back '$roll' after setting it $desired (possibly blocked by Tamper Protection, a policy, or a value Windows rewrote)." }) }
        }
    }
}

#endregion

#region Lock

function Get-IgwtChangeLockName {
    <# .SYNOPSIS The machine-wide mutex name (a test data root gets its own, so tests never block a real change). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($script:IgwtSettings.TestMode) { return ('Global\iGWindowsTuner.Change.Test.{0}' -f ((Get-IgwtJournalHash -Line ([string]$script:IgwtSettings.DataRoot)).Substring(0, 12))) }
    return 'Global\iGWindowsTuner.Change'
}

function Enter-IgwtChangeLock {
    <#
    .SYNOPSIS
        Takes the machine-wide change lock or throws a readable message ("Another change is running
        since HH:MM ..."), never a raw exception. A lock left by a process that ended is taken over
        (the start-up check finds what that process left unfinished).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Takes an in-process lock and writes the tool''s own lock note.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title)
    if ($script:IgwtChangeLock) { throw "Another change is already running in this window ($($script:IgwtChangeLock.Title))." }
    $m = New-Object System.Threading.Mutex($false, (Get-IgwtChangeLockName))
    $got = $false
    try { $got = $m.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) {
        $m.Dispose()
        $info = ''
        try {
            $note = Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataPath -Kind State) 'change-lock.json')
            $since = [datetime]::Parse([string]$note.startedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
            $info = " since {0:HH:mm} ({1})" -f $since, [string]$note.title
        } catch { $info = '' }
        throw "Another change is running$info. Only one change runs at a time; try again when it has finished."
    }
    $script:IgwtChangeLock = @{ Mutex = $m; Title = $Title }
    try {
        $dir = Get-IgwtDataPath -Kind State
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        $n = [ordered]@{ title = $Title; startedUtc = [DateTime]::UtcNow.ToString('o'); pid = $PID; user = "$env:USERDOMAIN\$env:USERNAME" }
        [System.IO.File]::WriteAllText((Join-Path $dir 'change-lock.json'), (ConvertTo-Json -InputObject $n -Compress), (New-Object System.Text.UTF8Encoding($false)))
    } catch { Write-Verbose "Lock note not written: $($_.Exception.Message)" }
}

function Exit-IgwtChangeLock {
    <# .SYNOPSIS Releases the machine-wide change lock. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Releases an in-process lock.')]
    [CmdletBinding()]
    param()
    if (-not $script:IgwtChangeLock) { return }
    try { Remove-Item -LiteralPath (Join-Path (Get-IgwtDataPath -Kind State) 'change-lock.json') -Force -ErrorAction SilentlyContinue } catch { Write-Verbose 'Lock note not removed.' }
    try { $script:IgwtChangeLock.Mutex.ReleaseMutex() } catch { Write-Verbose "Lock not released: $($_.Exception.Message)" }
    $script:IgwtChangeLock.Mutex.Dispose()
    $script:IgwtChangeLock = $null
}

#endregion

#region Sessions and steps

function Start-IgwtChangeSession {
    <#
    .SYNOPSIS
        Starts a change session: takes the change lock, checks the journal is writable, and writes a
        sessionStart entry. Origin: @{ type = tweak | preset | forensic | revert | driftFix | recovery | ...; ref = ...; version = ... }.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Origin, [Parameter(Mandatory = $true)][string]$Title)
    Assert-IgwtWritable -Operation 'Start-IgwtChangeSession'
    if (-not $PSCmdlet.ShouldProcess($Title, 'Start a change session')) { return $null }
    Enter-IgwtChangeLock -Title $Title
    try {
        $j = Get-IgwtJournalState -Refresh
        if ($j.Status -eq 'Broken') { throw "The change journal is read-only, so no change runs: $($j.Reason)" }
        $id = [guid]::NewGuid().ToString()
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'sessionStart'; session = $id; origin = $Origin; title = $Title })
        return [pscustomobject]@{ Id = $id; Origin = $Origin; Title = $Title; Step = 0; Results = (New-Object System.Collections.Generic.List[object]); Context = $null; Catalog = $null }
    } catch { Exit-IgwtChangeLock; throw }
}

function Complete-IgwtChangeSession {
    <# .SYNOPSIS Writes the sessionEnd entry (outcome and counts) and releases the change lock. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Ends the session record; the changes went through ShouldProcess.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)
    try {
        $res = @($Session.Results.ToArray())
        $failed = @($res | Where-Object { $_.Result -notin 'Committed', 'Unchanged' }).Count
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'sessionEnd'; session = $Session.Id; outcome = $(if ($failed) { 'partial' } else { 'ok' }); steps = $res.Count; failed = $failed })
    } finally { Exit-IgwtChangeLock }
}

function Invoke-IgwtChangeStep {
    <#
    .SYNOPSIS
        One step of a session: captures "before", writes the intent (and the target's baseline the
        first time it is ever changed), calls Set (-Desired on/default) or Restore (-RestoreData),
        reads the target back and records committed or failed. Returns the step result; never
        throws for a provider failure (the caller decides on rollback).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Target, $Desired, $RestoreData, [string]$Group, [string]$Kind = 'change')
    Assert-IgwtWritable -Operation 'Invoke-IgwtChangeStep'
    if (-not $PSCmdlet.ShouldProcess([string]$Target['key'], "Change step ($Kind)")) { return $null }
    if (-not $Session.Context) { $Session.Context = New-IgwtContext }
    if (-not $Session.Catalog) { $Session.Catalog = Get-IgwtCatalog }
    $ctx = $Session.Context
    $Session.Step++
    $step = $Session.Step
    $def = $script:IgwtChangeProviders[[string]$Target['provider']]
    $r = $null; $before = $null
    $result = [pscustomobject]@{ Step = $step; Group = $Group; Item = [string]$Target['item']; Target = $Target; Kind = $Kind; Desired = $Desired; Before = $null; Applied = $null; Result = 'Failed'; Message = ''; ReadBack = $null }
    try {
        $r = Resolve-IgwtChangeTarget -Target $Target -Catalog $Session.Catalog
        $before = & $def.Get $r $ctx
    } catch {
        $result.Message = "Nothing changed: $($_.Exception.Message)"
        $Session.Results.Add($result)
        return $result
    }
    $result.Before = $before
    $j = Get-IgwtJournalState
    if (-not $j.Baselines.ContainsKey([string]$Target['key'])) {
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'baseline'; session = $Session.Id; step = $step; item = [string]$Target['item']; target = $Target; before = $before })
    }
    $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent'; session = $Session.Id; step = $step; group = $Group; op = $Kind; origin = $Session.Origin; item = [string]$Target['item']; target = $Target; desired = $Desired; before = $before })
    try {
        if ($Kind -eq 'restore') {
            & $def.Restore $r $RestoreData $ctx
            $after = & $def.Get $r $ctx
            $exact = ((ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $after)) -eq (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $RestoreData)))
            $rb = [pscustomobject]@{ Ok = $exact; State = $(if ($exact) { 'restored' } else { 'differs' }); Note = $(if ($exact) { '' } else { 'After the restore the target does not read back as the recorded value.' }) }
        } else {
            $applied = & $def.Set $r $Desired $ctx
            $result.Applied = $applied
            $after = & $def.Get $r $ctx
            $rb = & $def.TestSet $r $Desired $ctx
        }
        $result.ReadBack = $rb
        if (-not $rb.Ok) { throw $rb.Note }
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'committed'; session = $Session.Id; step = $step; group = $Group; op = $Kind; origin = $Session.Origin; item = [string]$Target['item']; target = $Target; desired = $Desired; before = $before; applied = $result.Applied; after = $after; readBack = @{ ok = $true; state = $rb.State } })
        $result.Result = 'Committed'
    } catch {
        $result.Message = $_.Exception.Message
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'failed'; session = $Session.Id; step = $step; group = $Group; op = $Kind; item = [string]$Target['item']; target = $Target; error = $result.Message; readBack = $(if ($result.ReadBack) { @{ ok = [bool]$result.ReadBack.Ok; state = [string]$result.ReadBack.State } } else { $null }) })
    }
    $Session.Results.Add($result)
    return $result
}

function Undo-IgwtChangeGroup {
    <#
    .SYNOPSIS
        Rolls back the steps of one group (a catalog item or a forensic session) that ran in this
        session, in reverse order: each changed target is restored to its captured "before" and read
        back; the result of every step is journaled (rolledBack or rollbackFailed). Returns the errors.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][string]$Group)
    Assert-IgwtWritable -Operation 'Undo-IgwtChangeGroup'
    if (-not $PSCmdlet.ShouldProcess($Group, 'Roll back')) { return @() }
    $errors = New-Object System.Collections.Generic.List[string]
    $steps = @($Session.Results.ToArray() | Where-Object { $_.Group -eq $Group -and $null -ne $_.Before } | Sort-Object Step -Descending)
    foreach ($s in $steps) {
        $def = $script:IgwtChangeProviders[[string]$s.Target['provider']]
        $data = $s.Before
        # Custom handlers return data at apply time (for example a created power scheme) that their restore needs.
        if ($s.Applied -is [System.Collections.IDictionary] -and $data -is [System.Collections.IDictionary]) {
            $copy = @{}; foreach ($k in $data.Keys) { $copy[$k] = $data[$k] }; $copy['applied'] = $s.Applied; $data = $copy
        }
        try {
            $r = Resolve-IgwtChangeTarget -Target $s.Target -Catalog $Session.Catalog
            & $def.Restore $r $data $Session.Context
            $after = & $def.Get $r $Session.Context
            $ok = ((ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $after)) -eq (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $s.Before)))
            if (-not $ok) { throw 'After the rollback the target does not read back as its value before.' }
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'rolledBack'; session = $Session.Id; step = $s.Step; group = $Group; item = $s.Item; target = $s.Target; after = $after; readBack = @{ ok = $true } })
            $s.Result = $(if ($s.Result -eq 'Committed') { 'RolledBack' } else { $s.Result })
        } catch {
            $errors.Add("$($s.Target['key']): $($_.Exception.Message)")
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'rollbackFailed'; session = $Session.Id; step = $s.Step; group = $Group; item = $s.Item; target = $s.Target; error = $_.Exception.Message })
        }
    }
    return $errors.ToArray()
}

#endregion

#region Recovery, history and revert

function Get-IgwtJournalSessions {
    <#
    .SYNOPSIS
        The journal grouped by session (oldest first): origin, title, start and end, outcome, and its
        steps with their final result (Committed, Failed, RolledBack, InDoubt = intent without an
        outcome, the case of a crash between intent and commit). Read-only.
    #>
    [CmdletBinding()]
    param($Journal)
    if (-not $Journal) { $Journal = Read-IgwtJournal }
    $map = [ordered]@{}
    foreach ($e in $Journal.Entries) {
        $sid = [string]$e['session']
        if (-not $sid) { continue }
        if (-not $map.Contains($sid)) { $map[$sid] = [pscustomobject]@{ Id = $sid; Origin = $null; Title = ''; StartedUtc = ''; EndedUtc = ''; Outcome = ''; Ended = $false; Steps = [ordered]@{} } }
        $s = $map[$sid]
        switch ([string]$e['kind']) {
            'sessionStart' { $s.Origin = $e['origin']; $s.Title = [string]$e['title']; $s.StartedUtc = [string]$e['tsUtc'] }
            'sessionEnd' { $s.Ended = $true; $s.EndedUtc = [string]$e['tsUtc']; $s.Outcome = [string]$e['outcome'] }
            'intent' { $s.Steps[[string]$e['step']] = [pscustomobject]@{ Step = [int]$e['step']; Group = [string]$e['group']; Op = [string]$e['op']; Item = [string]$e['item']; Target = $e['target']; Desired = [string]$e['desired']; Before = $e['before']; Applied = $null; After = $null; Result = 'InDoubt'; Error = ''; EntryId = [string]$e['id'] } }
            'committed' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'Committed'; $st.Applied = $e['applied']; $st.After = $e['after']; $st.EntryId = [string]$e['id'] } }
            'failed' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'Failed'; $st.Error = [string]$e['error'] } }
            'rolledBack' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'RolledBack' } }
            'rollbackFailed' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'RollbackFailed'; $st.Error = [string]$e['error'] } }
        }
    }
    return @($map.Values)
}

function Get-IgwtIncompleteChangeSession {
    <#
    .SYNOPSIS
        Sessions that started but never ended (the app or PC stopped mid-change). Each lists the steps
        that may have changed something (committed, in doubt or with a failed rollback). The home
        card offers to roll them back (DECISIONS T2, T11). Read-only.
    #>
    [CmdletBinding()]
    param($Journal)
    foreach ($s in @(Get-IgwtJournalSessions -Journal $Journal)) {
        if ($s.Ended) { continue }
        $open = @($s.Steps.Values | Where-Object { $_.Result -in 'Committed', 'InDoubt', 'RollbackFailed', 'Failed' })
        [pscustomobject]@{ Id = $s.Id; Title = $s.Title; Origin = $s.Origin; StartedUtc = $s.StartedUtc; Steps = $open }
    }
}

function Invoke-IgwtChangeRecovery {
    <#
    .SYNOPSIS
        Rolls back an incomplete session: every step that may have changed something is restored to
        its recorded "before" (reverse order, read back), as a new session with origin recovery, and
        the old session is closed as recovered (or recovery-incomplete).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SessionId)
    Assert-IgwtWritable -Operation 'Invoke-IgwtChangeRecovery'
    $inc = @(Get-IgwtIncompleteChangeSession | Where-Object { $_.Id -eq $SessionId }) | Select-Object -First 1
    if (-not $inc) { throw "Session $SessionId is not incomplete; nothing to recover." }
    if (-not $PSCmdlet.ShouldProcess($inc.Title, 'Roll back the unfinished change')) { return $null }
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'recovery'; ref = $SessionId }) -Title "Roll back: $($inc.Title)" -Confirm:$false
    $errors = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($st in @($inc.Steps | Sort-Object Step -Descending)) {
            $data = $st.Before
            if ($st.Applied -is [System.Collections.IDictionary] -and $data -is [System.Collections.IDictionary]) { $copy = @{}; foreach ($k in $data.Keys) { $copy[$k] = $data[$k] }; $copy['applied'] = $st.Applied; $data = $copy }
            $r = Invoke-IgwtChangeStep -Session $session -Target $st.Target -Kind 'restore' -RestoreData $data -Group "recovery:$($st.Step)" -Confirm:$false
            if ($r.Result -ne 'Committed') { $errors.Add("$($st.Target['key']): $($r.Message)") }
        }
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'sessionEnd'; session = $SessionId; outcome = $(if ($errors.Count) { 'recovery-incomplete' } else { 'recovered' }); by = $session.Id })
    } finally { Complete-IgwtChangeSession -Session $session }
    return [pscustomobject]@{ Session = $SessionId; Complete = ($errors.Count -eq 0); Errors = $errors.ToArray() }
}

function Get-IgwtRevertPlan {
    <#
    .SYNOPSIS
        What a revert would do, read-only: for one journal entry (-EntryId, a committed change), one
        session (-SessionId) or everything iG changed (-All: back to the baselines, "value before
        iG"). Per target: the value before, the value iG set, the value now, and Status Ready (now is
        what iG set), Conflict (someone or Windows changed it since: the user decides), Already
        (already the value before), Unreadable or Refused (not owned by a catalog).
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param([Parameter(ParameterSetName = 'Entry', Mandatory = $true)][string]$EntryId,
        [Parameter(ParameterSetName = 'Session', Mandatory = $true)][string]$SessionId,
        [Parameter(ParameterSetName = 'All')][switch]$All, $Journal)
    if (-not $Journal) { $Journal = Read-IgwtJournal }
    $sessions = @(Get-IgwtJournalSessions -Journal $Journal)
    $changes = @(foreach ($s in $sessions) { foreach ($st in $s.Steps.Values) { if ($st.Result -eq 'Committed' -and $st.Op -eq 'change') { $st | Add-Member -NotePropertyName Session -NotePropertyValue $s.Id -Force -PassThru } } })
    $picked = switch ($PSCmdlet.ParameterSetName) {
        'Entry' { @($changes | Where-Object { $_.EntryId -eq $EntryId }) }
        'Session' { @($changes | Where-Object { $_.Session -eq $SessionId } | Sort-Object Step -Descending) }
        default {
            # Everything: each target whose last state is a change by iG, back to its baseline (reverse first touch).
            $keys = @($Journal.Last.Keys | Where-Object { $e = $Journal.Last[$_]; [string]$e['kind'] -eq 'committed' -and [string]$e['op'] -eq 'change' })
            @($keys | ForEach-Object { $k = $_; $c = @($changes | Where-Object { [string]$_.Target['key'] -eq $k }) | Select-Object -Last 1; if ($c) { $c } }) | Sort-Object { [long]$Journal.Baselines[[string]$_.Target['key']]['seq'] } -Descending
        }
    }
    $ctx = New-IgwtContext; $catalog = Get-IgwtCatalog
    foreach ($st in @($picked)) {
        $key = [string]$st.Target['key']
        $restoreTo = $(if ($PSCmdlet.ParameterSetName -eq 'All' -and $Journal.Baselines.ContainsKey($key)) { $Journal.Baselines[$key]['before'] } else { $st.Before })
        $row = [ordered]@{ Key = $key; Item = $st.Item; Session = $st.Session; Step = $st.Step; Target = $st.Target; Before = $restoreTo; WeSet = $st.After; Applied = $st.Applied; Now = $null; Status = 'Ready'; Message = '' }
        try {
            $r = Resolve-IgwtChangeTarget -Target $st.Target -Catalog $catalog
            $def = $script:IgwtChangeProviders[[string]$st.Target['provider']]
            if ((& $def.Reversible $r) -eq 'oneWay') { $row.Status = 'Refused'; $row.Message = 'This change cannot be undone (one-way: packages, deleted files, restore points).' }
            else {
                $now = & $def.Get $r $ctx
                $row.Now = $now
                $nowJ = ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $now)
                if ($nowJ -eq (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $restoreTo))) { $row.Status = 'Already'; $row.Message = 'Already the value before.' }
                elseif ($nowJ -ne (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $st.After))) { $row.Status = 'Conflict'; $row.Message = 'Changed since iG set it (by you, an app, a policy or Windows): choose to restore anyway, keep the current value, or skip.' }
            }
        } catch { $row.Status = 'Refused'; $row.Message = $_.Exception.Message }
        [pscustomobject]$row
    }
}

function Invoke-IgwtJournalRevert {
    <#
    .SYNOPSIS
        Runs a revert plan as one session (origin revert). Ready rows are restored; Conflict rows
        follow -Decisions (target key -> Restore, Keep or Skip; without a decision they are skipped
        and reported); Keep is journaled as "retired" (iG stops tracking the value it set). Already,
        Refused and unreadable rows change nothing. Every restore is read back.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][object[]]$Plan, [hashtable]$Decisions = @{}, [string]$Title = 'Revert')
    Assert-IgwtWritable -Operation 'Invoke-IgwtJournalRevert'
    $todo = @($Plan | Where-Object { $_.Status -in 'Ready', 'Conflict' })
    if (-not $todo.Count) { return [pscustomobject]@{ Results = @($Plan | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Item = $_.Item; Result = $_.Status; Message = $_.Message } }) } }
    if (-not $PSCmdlet.ShouldProcess("$($todo.Count) value(s)", $Title)) { return $null }
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'revert'; ref = $Title }) -Title $Title -Confirm:$false
    $results = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($p in $Plan) {
            if ($p.Status -notin 'Ready', 'Conflict') { $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = $p.Status; Message = $p.Message }); continue }
            $choice = $(if ($p.Status -eq 'Ready') { 'Restore' } elseif ($Decisions.ContainsKey($p.Key)) { [string]$Decisions[$p.Key] } else { '' })
            if ($choice -eq 'Keep') {
                $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'retired'; session = $session.Id; item = $p.Item; target = $p.Target; now = $p.Now; note = 'Kept the current value; iG no longer tracks the value it set.' })
                $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = 'Kept'; Message = 'The current value is kept.' }); continue
            }
            if ($choice -ne 'Restore') { $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = $(if ($choice -eq 'Skip') { 'Skipped' } else { 'NeedsDecision' }); Message = $p.Message }); continue }
            $data = $p.Before
            if ($p.Applied -is [System.Collections.IDictionary] -and $data -is [System.Collections.IDictionary]) { $copy = @{}; foreach ($k in $data.Keys) { $copy[$k] = $data[$k] }; $copy['applied'] = $p.Applied; $data = $copy }
            $r = Invoke-IgwtChangeStep -Session $session -Target $p.Target -Kind 'restore' -RestoreData $data -Group "revert:$($p.Key)" -Confirm:$false
            $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = $(if ($r.Result -eq 'Committed') { 'Reverted' } else { 'Failed' }); Message = $r.Message })
        }
    } finally { Complete-IgwtChangeSession -Session $session }
    return [pscustomobject]@{ Session = $session.Id; Results = $results.ToArray() }
}

#endregion
