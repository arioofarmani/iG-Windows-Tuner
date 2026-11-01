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
    # Compiled (src\Core\JournalEngine.cs): every read-back, revert plan and drift row compares values.
    Initialize-IgwtJournalEngine
    return [IgwtJournal.Canonical]::ToJson($Value)
}

function Remove-IgwtVolatileSnapshotKey {
    <#
    .SYNOPSIS
        A copy of snapshot data without what describes the change rather than the value, for
        read-back comparison: "applied" (data from the apply) at the top, and "missingDepth" (how
        many key levels iG created, which the restore uses) at any depth. A 3.x snapshot records it
        for all of an item's actions before the first one, the journal before each step, so it can
        differ for the same value. Pure.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a filtered copy; changes nothing.')]
    [CmdletBinding()]
    param([AllowNull()]$Data, [switch]$Nested)
    if ($Data -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Data.Keys) { if (([string]$k -ne 'applied' -or $Nested) -and [string]$k -ne 'missingDepth') { $o[[string]$k] = Remove-IgwtVolatileSnapshotKey -Data $Data[$k] -Nested } }
        return $o
    }
    if ($Data -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($p in $Data.PSObject.Properties) { if (($p.Name -ne 'applied' -or $Nested) -and $p.Name -ne 'missingDepth') { $o[$p.Name] = Remove-IgwtVolatileSnapshotKey -Data $p.Value -Nested } }
        return $o
    }
    if ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string]) { return , @(foreach ($x in $Data) { Remove-IgwtVolatileSnapshotKey -Data $x -Nested }) }
    return $Data
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

# Module writers (DECISIONS T14): the exported writers of the modules (firewall, ASR, Defender,
# policy, audit, security policy, power, startup, management, toolkit, cleaner) run as one journaled
# step each. Their exact previous data is the writer's own 3.x snapshot or backup, which the step
# records ("ref") and its restore uses. Restore: the function that undoes that ref ('' = one-way).
$script:IgwtModuleOperations = @{
    'Import-IgwtFirewallRules'         = 'snapshot'
    'Invoke-IgwtFirewallChange'        = 'snapshot'
    'Set-IgwtFirewallProfileSetting'   = 'snapshot'
    'Set-IgwtNetworkCategory'          = 'snapshot'
    'Invoke-IgwtAsrChange'             = 'snapshot'
    'Invoke-IgwtDefenderSettingChange' = 'snapshot'
    'Invoke-IgwtManagedChange'         = 'snapshot'
    'Invoke-IgwtPowerSettingChange'    = 'snapshot'
    'Set-IgwtStartupItemEnabled'       = 'snapshot'
    # A revert's own snapshot holds Reverted entries, which Invoke-IgwtRevert does not restore (review 3.6 R3):
    # one-way in the journal; its targets are recorded as reverted, and each can be changed again normally.
    'Invoke-IgwtRevert'                = ''
    'Restore-IgwtFirewallSnapshot'     = 'snapshot'
    # It snapshots one setting at a time (no single undo snapshot): one-way (review 3.6 R7).
    'Restore-IgwtFirewallProfileSnapshot' = ''
    'Restore-IgwtDefenderSettingSnapshot' = 'snapshot'
    'Set-IgwtLocalPolicy'              = 'gpo'
    'Reset-IgwtLocalGpo'               = 'gpo'
    'Invoke-IgwtPolicyBatch'           = 'policyPreset'
    'Set-IgwtAuditPolicy'              = 'audit'
    'Set-IgwtSecurityPolicy'           = 'secpol'
    'Invoke-IgwtTattooAdoption'        = 'tattoo'
    # One-way: journaled and previewed as "cannot be undone", never offered for revert.
    'Restore-IgwtLocalGpo'             = ''
    'Restore-IgwtPolicyPreset'         = ''
    'Restore-IgwtAuditPolicy'          = ''
    'Restore-IgwtSecurityPolicy'       = ''
    'Restore-IgwtTattooRemoval'        = ''
    'Restore-IgwtForensicLogging'      = ''
    'Remove-IgwtDefenderExclusion'     = ''
    'Set-IgwtDefenderParsersOn'        = ''
    'Start-IgwtDefenderScan'           = ''
    'Remove-IgwtDefenderThreat'        = ''
    'Restore-IgwtQuarantineItem'       = ''
    'Invoke-IgwtCleanerClean'          = ''
    'Invoke-IgwtToolkitApp'            = ''
    'Invoke-IgwtToolkitFeature'        = ''
    'Invoke-IgwtToolkitFix'            = ''
    'Invoke-IgwtWingetUpgradeAll'      = ''
    'New-IgwtRestorePoint'             = ''
}
$script:IgwtModuleDepth = 0
# Segments (5,000 entries each) before a session start folds the oldest into the checkpoint.
$script:IgwtJournalCompactAt = 20
$script:IgwtModuleStep = $null

function Get-IgwtModuleOperationRef {
    <# .SYNOPSIS The undo reference in a module writer's result: its snapshot, backup or record path (or the path it returned). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Result)
    if ($Result -is [string]) { return $Result }
    foreach ($r in @($Result)) {
        if ($null -eq $r -or $r -is [string]) { continue }
        foreach ($p in 'Snapshot', 'Backup', 'Record') { if ($r.PSObject.Properties[$p] -and $r.$p) { return [string]$r.$p } }
    }
    return ''
}

function Test-IgwtModuleOperationFailed {
    <# .SYNOPSIS True when a module writer's result reports a failure or a read-back mismatch (Verified false, a Failed result, Stopped false). Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Result)
    foreach ($r in @($Result)) {
        if ($null -eq $r -or $r -is [string]) { continue }
        if ($r.PSObject.Properties['Verified'] -and $r.Verified -eq $false) { return $true }
        if ($r.PSObject.Properties['Results'] -and @($r.Results | Where-Object { $_ -and $_.PSObject.Properties['Result'] -and [string]$_.Result -eq 'Failed' }).Count) { return $true }
    }
    return $false
}

function ConvertTo-IgwtJournalParameters {
    <# .SYNOPSIS The parameters of a module writer as journal data: scalars, strings, switches and simple tables; anything else is named, not stored. Pure. #>
    [CmdletBinding()]
    param([System.Collections.IDictionary]$Parameters)
    $out = [ordered]@{}
    foreach ($k in @($Parameters.Keys | Sort-Object)) {
        $v = $Parameters[$k]
        if ($k -in 'WhatIf', 'Confirm', 'OnProgress', 'CancelToken') { continue }
        if ($null -eq $v -or $v -is [string] -or $v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double]) { $out[$k] = $v }
        elseif ($v -is [switch]) { $out[$k] = [bool]$v }
        elseif ($v -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($hk in $v.Keys) { $hv = $v[$hk]; $h[[string]$hk] = $(if ($null -eq $hv -or $hv -is [ValueType] -or $hv -is [string]) { $hv } else { [string]$hv }) }; $out[$k] = $h }
        elseif ($v -is [array] -and @($v | Where-Object { $_ -isnot [string] -and $_ -isnot [ValueType] }).Count -eq 0) { $out[$k] = @($v) }
        else { $out[$k] = "<$($v.GetType().Name)>" }
    }
    return $out
}

$script:IgwtChangeProviders['module'] = @{
    Reversible = { param($r) if ($script:IgwtModuleOperations[$r.Operation]) { 'exact' } else { 'oneWay' } }
    Resolve    = {
        param($t, $catalog)
        $null = $catalog
        $op = [string]$t['op']
        if (-not $script:IgwtModuleOperations.ContainsKey($op) -or -not ([string]$t['key']).StartsWith("module|$op|")) { throw "'$($t['key'])' is not a module writer the tool owns." }
        return [pscustomobject]@{ Operation = $op; Kind = $script:IgwtModuleOperations[$op] }
    }
    # The writer's state is in its own snapshot or backup; the journal holds the reference.
    Get        = { param($r, $ctx) $null = $ctx; [ordered]@{ op = $r.Operation } }
    Set        = {
        param($r, $desired, $ctx)
        $null = $desired; $null = $ctx
        $m = $script:IgwtModuleStep
        $script:IgwtModuleDepth++
        $p = $m.Parameters
        try { $m.Result = & $m.Command @p } finally { $script:IgwtModuleDepth-- }
        $ref = Get-IgwtModuleOperationRef -Result $m.Result
        if (-not $ref) { $ref = [string]$m.Ref }
        $action = $(foreach ($x in @($m.Result)) { if ($x -and $x -isnot [string] -and $x.PSObject.Properties['Action']) { [string]$x.Action } })
        return [ordered]@{ ref = $ref; action = [string](@($action) | Select-Object -First 1) }
    }
    Restore    = {
        param($r, $data, $ctx)
        $null = $ctx
        $ap = $data['applied']
        $ref = $(if ($ap) { [string]$ap['ref'] } else { '' })
        if (-not $r.Kind) { throw 'This change cannot be undone (one-way).' }
        if (-not $ref) { throw 'No snapshot or backup was recorded for this change, so it cannot be restored from the journal.' }
        $root = [string]$script:IgwtSettings.DataRoot
        if ($root -and -not (Test-IgwtPathUnder -Path $ref -Parent $root)) { throw "The recorded backup '$ref' is outside the tool's data folder: it is not used." }
        $script:IgwtModuleDepth++
        try {
            $res = switch ($r.Kind) {
                'snapshot' { Invoke-IgwtRevert -SnapshotPath $ref -Confirm:$false }
                'gpo' { Restore-IgwtLocalGpo -BackupPath $ref -Confirm:$false }
                'policyPreset' { Restore-IgwtPolicyPreset -Record $ref -Confirm:$false }
                'audit' { Restore-IgwtAuditPolicy -BackupPath $ref -Confirm:$false }
                'secpol' { Restore-IgwtSecurityPolicy -BackupPath $ref -Confirm:$false }
                # Adopt backs up the Local Group Policy (a folder); Remove writes a tattoo backup file.
                'tattoo' { if (Test-Path -LiteralPath $ref -PathType Container) { Restore-IgwtLocalGpo -BackupPath $ref -Confirm:$false } else { Restore-IgwtTattooRemoval -Path $ref -Confirm:$false } }
            }
        } finally { $script:IgwtModuleDepth-- }
        if (Test-IgwtModuleOperationFailed -Result $res) { throw "The restore from '$ref' reported a failure." }
    }
    TestSet    = {
        param($r, $desired, $ctx)
        $null = $desired; $null = $ctx
        $bad = Test-IgwtModuleOperationFailed -Result $script:IgwtModuleStep.Result
        return [pscustomobject]@{ Ok = (-not $bad); State = $(if ($bad) { 'failed' } else { 'done' }); Note = $(if ($bad) { "$($r.Operation) reported a failure or a value that did not read back (its own rollback ran where it has one)." } else { '' }) }
    }
    # The module's restore reads its own values back; the revert plan cannot compare values (T14).
    NoCompare  = $true
}

function Set-IgwtModuleOperationRef {
    <#
    .SYNOPSIS
        Inside a journaled module writer: records the path of its snapshot or backup as the step's
        undo reference the moment it exists (journal entry moduleRef), so a crash before the commit
        can still be rolled back (DECISIONS T14, review 3.6 R8). Outside a writer it does nothing.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Appends to the tool''s own journal only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $m = $script:IgwtModuleStep
    if (-not $m -or $m.Ref) { return }
    $m.Ref = $Path
    $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'moduleRef'; session = $m.Session; step = $m.Step; ref = $Path })
}

function Test-IgwtModuleOperationDirect {
    <#
    .SYNOPSIS
        True when a module writer runs its body directly: it is already inside a journaled step (a
        nested call, a restore, or a change session of this window), or it is a -WhatIf preview.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([System.Collections.IDictionary]$BoundParameters)
    if ($script:IgwtModuleDepth -gt 0 -or $script:IgwtChangeLock) { return $true }
    if ($WhatIfPreference -or ($BoundParameters -and $BoundParameters.ContainsKey('WhatIf') -and [bool]$BoundParameters['WhatIf'])) { return $true }
    return $false
}

function Invoke-IgwtModuleOperation {
    <#
    .SYNOPSIS
        Runs one module writer as a journaled change (DECISIONS T14): a session (origin module, unless
        one is given), one step whose target is the writer, its parameters as the desired state and
        its snapshot or backup as the exact previous data. Returns the writer's own result.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Command, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Parameters, [string]$Title, [System.Collections.IDictionary]$Origin)
    if (-not $script:IgwtModuleOperations.ContainsKey($Command)) { throw "$Command is not a registered module writer." }
    $desired = ConvertTo-IgwtJournalParameters -Parameters $Parameters
    if (-not $Title) { $Title = "$Command $(@($desired.Values | Where-Object { $_ -is [string] -or $_ -is [ValueType] }) -join ' ')".Trim() }
    if (-not $Origin) { $Origin = [ordered]@{ type = 'module'; ref = $Command } }
    $detail = (Get-IgwtJournalHash -Line (ConvertTo-IgwtCanonicalJson $desired)).Substring(0, 16)
    $target = [ordered]@{ provider = 'module'; key = "module|$Command|$detail"; item = "module:$Command"; op = $Command }
    $params = @{}; foreach ($k in $Parameters.Keys) { $params[$k] = $Parameters[$k] }
    $session = Start-IgwtChangeSession -Origin $Origin -Title $Title -Confirm:$false
    $script:IgwtModuleStep = [pscustomobject]@{ Command = $Command; Parameters = $params; Result = $null; Ref = ''; Session = $session.Id; Step = $session.Step + 1 }
    try {
        $r = Invoke-IgwtChangeStep -Session $session -Target $target -Desired $desired -Group $Command -Confirm:$false
        $out = $script:IgwtModuleStep.Result
        # A writer that threw: the step is journaled as failed, and the caller sees the same error.
        if ($r -and $r.Result -ne 'Committed' -and $null -eq $out -and $r.Message) { throw $r.Message }
        return $out
    } finally {
        $script:IgwtModuleStep = $null
        Complete-IgwtChangeSession -Session $session
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
    # Opening a lock that an elevated process created can be refused to a standard process: a readable message (review 3.6 Q1).
    try { $m = New-Object System.Threading.Mutex($false, (Get-IgwtChangeLockName)) }
    catch [System.UnauthorizedAccessException] { throw 'Another change is running in a process with other rights. Only one change runs at a time; try again when it has finished.' }
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
    # Changes and the journal need administrator rights (review 3.6 R21).
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Changes need administrator rights: restart iG Windows Tuner as administrator.' }
    # The first change after an upgrade from 3.x imports the old snapshots first (T6). Tests call the import directly.
    if (-not $script:IgwtSettings.TestMode -and [string]$Origin['type'] -ne 'upgrade' -and -not $script:IgwtChangeLock -and (Get-IgwtJournalState).Status -eq 'Empty') {
        try { $null = Invoke-IgwtJournalUpgrade -Confirm:$false } catch { Write-IgwtLog -Level Warn -Message "The 3.x snapshots were not imported into the change journal: $($_.Exception.Message)" }
    }
    Enter-IgwtChangeLock -Title $Title
    try {
        $j = Get-IgwtJournalState -Refresh
        if ($j.Status -eq 'Broken') { throw "The change journal is read-only, so no change runs: $($j.Reason)" }
        # A long journal is folded into its checkpoint first (DECISIONS T4: baselines are kept).
        if (@(Get-IgwtJournalSegments).Count -gt $script:IgwtJournalCompactAt) { try { $null = Invoke-IgwtJournalCompaction -Confirm:$false; $j = Get-IgwtJournalState } catch { Write-IgwtLog -Level Warn -Message "Journal compaction skipped: $($_.Exception.Message)" } }
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
        # A step that wrote its intent but returned no result was interrupted (Ctrl+C, an exception): the session
        # stays visible to recovery (review 3.6 R5).
        $outcome = $(if ($Session.Step -gt $res.Count) { 'interrupted' } elseif ($failed) { 'partial' } else { 'ok' })
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'sessionEnd'; session = $Session.Id; outcome = $outcome; steps = $res.Count; failed = $failed })
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
        if (-not $map.Contains($sid)) { $map[$sid] = [pscustomobject]@{ Id = $sid; Origin = $null; Title = ''; StartedUtc = ''; EndedUtc = ''; Outcome = ''; Ended = $false; Recovered = $false; Steps = [ordered]@{} } }
        $s = $map[$sid]
        switch ([string]$e['kind']) {
            'sessionStart' { $s.Origin = $e['origin']; $s.Title = [string]$e['title']; $s.StartedUtc = [string]$e['tsUtc'] }
            'sessionEnd' { $s.Ended = $true; $s.EndedUtc = [string]$e['tsUtc']; $s.Outcome = [string]$e['outcome']; if ($e.ContainsKey('by')) { $s.Recovered = $true } }
            'intent' { $s.Steps[[string]$e['step']] = [pscustomobject]@{ Step = [int]$e['step']; Group = [string]$e['group']; Op = [string]$e['op']; Item = [string]$e['item']; Target = $e['target']; Desired = [string]$e['desired']; Before = $e['before']; Applied = $null; After = $null; Result = 'InDoubt'; Error = ''; EntryId = [string]$e['id'] } }
            'committed' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'Committed'; $st.Applied = $e['applied']; $st.After = $e['after']; $st.EntryId = [string]$e['id'] } }
            'failed' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'Failed'; $st.Error = [string]$e['error'] } }
            'rolledBack' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'RolledBack' } }
            'rollbackFailed' { $st = $s.Steps[[string]$e['step']]; if ($st) { $st.Result = 'RollbackFailed'; $st.Error = [string]$e['error'] } }
            # A module writer's snapshot, recorded as it is created: a crash before the commit can still be rolled back.
            'moduleRef' { $st = $s.Steps[[string]$e['step']]; if ($st -and -not $st.Applied) { $st.Applied = [ordered]@{ ref = [string]$e['ref']; action = '' } } }
        }
    }
    return @($map.Values)
}

function Get-IgwtIncompleteChangeSession {
    <#
    .SYNOPSIS
        Sessions that need a rollback, not yet recovered: sessions that never ended (the app or PC
        stopped mid-change), with every step that may have changed something (committed, in doubt or
        with a failed rollback), and ended sessions with a step in doubt (interrupted after its
        intent: review 3.6 R5), with those steps. The home card offers to roll them back (DECISIONS
        T2, T11). Read-only.
    #>
    [CmdletBinding()]
    param($Journal)
    foreach ($s in @(Get-IgwtJournalSessions -Journal $Journal)) {
        if ($s.Recovered) { continue }
        $open = @(if ($s.Ended) { @($s.Steps.Values | Where-Object { $_.Result -eq 'InDoubt' }) } else { @($s.Steps.Values | Where-Object { $_.Result -in 'Committed', 'InDoubt', 'RollbackFailed', 'Failed' }) })
        if ($s.Ended -and -not $open.Count) { continue }
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
    $skippedSteps = New-Object System.Collections.Generic.List[string]
    try {
        # Read again under the lock: the session may have finished meanwhile in another process (review 3.6 R12).
        $inc = @(Get-IgwtIncompleteChangeSession -Journal (Read-IgwtJournal) | Where-Object { $_.Id -eq $SessionId }) | Select-Object -First 1
        if (-not $inc) { return [pscustomobject]@{ Session = $SessionId; Complete = $true; Errors = @(); Skipped = @(); Message = 'It finished meanwhile; nothing to roll back.' } }
        $ctx = New-IgwtContext
        foreach ($st in @($inc.Steps | Sort-Object Step -Descending)) {
            # A value changed since iG set it (by you, an app, a policy or Windows) is left as it is (review 3.6 R12).
            if ($null -ne $st.After) {
                try {
                    $def = $script:IgwtChangeProviders[[string]$st.Target['provider']]
                    if (-not $def.NoCompare) {
                        $now = & $def.Get (Resolve-IgwtChangeTarget -Target $st.Target) $ctx
                        $nowJ = ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $now)
                        if ($nowJ -ne (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $st.After))) {
                            if ($nowJ -ne (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $st.Before))) { $skippedSteps.Add("$($st.Target['key']): changed since iG set it; left as it is.") }
                            continue
                        }
                    }
                } catch { Write-Verbose "Recovery read of $($st.Target['key']) failed: $($_.Exception.Message)" }
            }
            $data = $st.Before
            if ($st.Applied -is [System.Collections.IDictionary] -and $data -is [System.Collections.IDictionary]) { $copy = @{}; foreach ($k in $data.Keys) { $copy[$k] = $data[$k] }; $copy['applied'] = $st.Applied; $data = $copy }
            $r = Invoke-IgwtChangeStep -Session $session -Target $st.Target -Kind 'restore' -RestoreData $data -Group "recovery:$($st.Step)" -Confirm:$false
            if ($r.Result -ne 'Committed') { $errors.Add("$($st.Target['key']): $($r.Message)") }
        }
        $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'sessionEnd'; session = $SessionId; outcome = $(if ($errors.Count) { 'recovery-incomplete' } else { 'recovered' }); by = $session.Id })
    } finally { Complete-IgwtChangeSession -Session $session }
    return [pscustomobject]@{ Session = $SessionId; Complete = ($errors.Count -eq 0); Errors = $errors.ToArray(); Skipped = $skippedSteps.ToArray(); Message = '' }
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
            # From the last-state index, which compaction keeps (the folded sessions' steps are gone).
            @($keys | ForEach-Object { $e = $Journal.Last[$_]; [pscustomobject]@{ Session = [string]$e['session']; Step = [int]$e['step']; Item = [string]$e['item']; Target = $e['target']; Before = $e['before']; After = $e['after']; Applied = $e['applied']; EntryId = [string]$e['id']; Op = 'change'; Result = 'Committed' } }) | Sort-Object { if ($Journal.Baselines.ContainsKey([string]$_.Target['key'])) { [long]$Journal.Baselines[[string]$_.Target['key']]['seq'] } else { 0 } } -Descending
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
            elseif ($def.NoCompare) {
                # A module writer: its own snapshot or backup holds the values (T14); the journal knows whether it was reverted.
                $last = $Journal.Last[$key]
                if ($last -and -not ([string]$last['kind'] -eq 'committed' -and [string]$last['op'] -eq 'change')) { $row.Status = 'Already'; $row.Message = 'Already reverted.' }
                else { $row.Message = 'Restored from the snapshot or backup taken before this change; the module reads each value back.' }
            } else {
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
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Plan, [hashtable]$Decisions = @{}, [string]$Title = 'Revert')
    Assert-IgwtWritable -Operation 'Invoke-IgwtJournalRevert'
    $todo = @($Plan | Where-Object { $_.Status -in 'Ready', 'Conflict' })
    if (-not $todo.Count) { return [pscustomobject]@{ Results = @($Plan | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Item = $_.Item; Result = $_.Status; Message = $_.Message } }) } }
    if (-not $PSCmdlet.ShouldProcess("$($todo.Count) value(s)", $Title)) { return $null }
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'revert'; ref = $Title }) -Title $Title -Confirm:$false
    $results = New-Object System.Collections.Generic.List[object]
    $ctxR = New-IgwtContext
    try {
        foreach ($p in $Plan) {
            if ($p.Status -notin 'Ready', 'Conflict') { $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = $p.Status; Message = $p.Message }); continue }
            $choice = $(if ($p.Status -eq 'Ready') { 'Restore' } elseif ($Decisions.ContainsKey($p.Key)) { [string]$Decisions[$p.Key] } else { '' })
            if ($choice -eq 'Keep') {
                $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'retired'; session = $session.Id; item = $p.Item; target = $p.Target; now = $p.Now; note = 'Kept the current value; iG no longer tracks the value it set.' })
                $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = 'Kept'; Message = 'The current value is kept.' }); continue
            }
            if ($choice -ne 'Restore') { $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = $(if ($choice -eq 'Skip') { 'Skipped' } else { 'NeedsDecision' }); Message = $p.Message }); continue }
            # Read again under the lock: a value changed between the preview and now needs a decision too (review 3.6 R22).
            if ($p.Status -eq 'Ready' -and $null -ne $p.WeSet) {
                $def = $script:IgwtChangeProviders[[string]$p.Target['provider']]
                if ($def -and -not $def.NoCompare) {
                    try {
                        $nowJ = ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey (& $def.Get (Resolve-IgwtChangeTarget -Target $p.Target) $ctxR))
                        if ($nowJ -ne (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $p.WeSet)) -and $nowJ -ne (ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $p.Before))) {
                            $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = 'NeedsDecision'; Message = 'Changed since the preview: choose to restore anyway, keep or skip.' }); continue
                        }
                    } catch { Write-Verbose "Re-read of $($p.Key) failed: $($_.Exception.Message)" }
                }
            }
            $data = $p.Before
            if ($p.Applied -is [System.Collections.IDictionary] -and $data -is [System.Collections.IDictionary]) { $copy = @{}; foreach ($k in $data.Keys) { $copy[$k] = $data[$k] }; $copy['applied'] = $p.Applied; $data = $copy }
            $r = Invoke-IgwtChangeStep -Session $session -Target $p.Target -Kind 'restore' -RestoreData $data -Group "revert:$($p.Key)" -Confirm:$false
            $results.Add([pscustomobject]@{ Key = $p.Key; Item = $p.Item; Result = $(if ($r.Result -eq 'Committed') { 'Reverted' } else { 'Failed' }); Message = $r.Message })
        }
    } finally { Complete-IgwtChangeSession -Session $session }
    return [pscustomobject]@{ Session = $session.Id; Results = $results.ToArray() }
}

#endregion

function Compress-IgwtJournal {
    <#
    .SYNOPSIS
        Folds the oldest journal segments into the checkpoint under the change lock (DECISIONS T4):
        baselines and the last state of every target are kept; the folded sessions' details are not.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([ValidateRange(1, 1000)][int]$KeepSegments = 2)
    Assert-IgwtWritable -Operation 'Compress-IgwtJournal'
    if (-not $PSCmdlet.ShouldProcess('Change journal', "Fold all but the newest $KeepSegments segment(s) into the checkpoint")) { return $null }
    Enter-IgwtChangeLock -Title 'Journal compaction'
    try { return (Invoke-IgwtJournalCompaction -KeepSegments $KeepSegments -Confirm:$false) } finally { Exit-IgwtChangeLock }
}

#region Timeline (Journal page)

function Test-IgwtMapKey {
    <#
    .SYNOPSIS
        True when a dictionary has a key: works for journal entries (Dictionary[string,object], whose
        Contains Windows PowerShell 5.1 cannot call) and for hashtables and ordered dictionaries. Pure.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Map, [Parameter(Mandatory = $true)][string]$Key)
    if ($Map -is [System.Collections.Generic.IDictionary[string, object]]) { return $Map.ContainsKey($Key) }
    if ($Map -is [System.Collections.IDictionary]) { return $Map.Contains($Key) }
    return $false
}

function Format-IgwtJournalValue {
    <# .SYNOPSIS A short one-line text for a journal value (before, after, now), for lists and previews. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value, [int]$Max = 120)
    if ($null -eq $Value) { return '' }
    $v = $Value
    if ($v -is [System.Collections.IDictionary]) {
        # Registry snapshots: the value or "absent"; module steps: the snapshot or backup file.
        if ((Test-IgwtMapKey $v 'ref')) { return "backup $(Split-Path -Leaf ([string]$v['ref']))" }
        if ((Test-IgwtMapKey $v 'op') -and $v.Count -eq 1) { return '(in its snapshot)' }
        if ((Test-IgwtMapKey $v 'exists') -and -not $v['exists']) { return 'absent' }
        if ((Test-IgwtMapKey $v 'exists')) { return '{0} {1}' -f $v['kind'], (@($v['value']) -join ',') }
        if ((Test-IgwtMapKey $v 'items') -and @($v['items']).Count -and @(@($v['items']) | Where-Object { $_ -isnot [System.Collections.IDictionary] -or -not (Test-IgwtMapKey $_ 'exists') }).Count -eq 0) {
            $t = (@($v['items']) | ForEach-Object { Format-IgwtJournalValue -Value $_ -Max $Max }) -join '; '
            return $(if ($t.Length -gt $Max) { $t.Substring(0, $Max - 3) + '...' } else { $t })
        }
    }
    $t = $(if ($v -is [string] -or $v -is [ValueType]) { [string]$v } else { ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $v) })
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Get-IgwtJournalTimeline {
    <#
    .SYNOPSIS
        The change journal as rows for the Journal page, newest session first: one row per step with
        the session (title, origin, start), the item, the result, the value before and the value set,
        and whether it can be reverted. Status is the journal check (Ok, Empty, Broken). Read-only.
    #>
    [CmdletBinding()]
    param($Journal)
    if (-not $Journal) { $Journal = Read-IgwtJournal }
    $rows = New-Object System.Collections.Generic.List[object]
    $sessions = @(Get-IgwtJournalSessions -Journal $Journal)
    [array]::Reverse($sessions)
    foreach ($s in $sessions) {
        $otype = $(if ($s.Origin) { [string]$s.Origin['type'] } else { '' })
        foreach ($st in @($s.Steps.Values | Sort-Object Step)) {
            $key = [string]$st.Target['key']
            $last = $Journal.Last[$key]
            $current = ($st.Result -eq 'Committed' -and $st.Op -eq 'change' -and $last -and [string]$last['kind'] -eq 'committed' -and [string]$last['session'] -eq $s.Id -and [string]$last['op'] -eq 'change')
            $oneWay = ([string]$st.Target['provider'] -eq 'module' -and $script:IgwtModuleOperations.ContainsKey([string]$st.Target['op']) -and -not $script:IgwtModuleOperations[[string]$st.Target['op']])
            $rows.Add([pscustomobject]@{
                    Key = "$($s.Id)|$($st.Step)"; Session = $s.Id; SessionTitle = $s.Title; Origin = $otype; When = $s.StartedUtc
                    Outcome = $(if ($s.Ended) { $s.Outcome } else { 'unfinished' }); Step = $st.Step; Op = $st.Op; Item = $st.Item; Target = $key
                    Result = $st.Result; Error = $st.Error; Before = (Format-IgwtJournalValue $st.Before); After = (Format-IgwtJournalValue $(if ($st.Applied -is [System.Collections.IDictionary] -and (Test-IgwtMapKey $st.Applied 'ref')) { $st.Applied } else { $st.After }))
                    EntryId = $st.EntryId; InEffect = $current; OneWay = $oneWay
                })
        }
    }
    # Values iG still tracks (last state = its change), from the index compaction keeps (review 3.6 R18).
    $tracked = @($Journal.Last.Keys | Where-Object { $e = $Journal.Last[$_]; [string]$e['kind'] -eq 'committed' -and [string]$e['op'] -eq 'change' }).Count
    return [pscustomobject]@{ Status = $Journal.Status; Reason = $Journal.Reason; Count = $Journal.Count; Sessions = $sessions.Count; Baselines = $Journal.Baselines.Count; Tracked = $tracked; Rows = $rows.ToArray() }
}

#endregion

#region Upgrade from 3.x

function Get-IgwtLegacySnapshotImport {
    <#
    .SYNOPSIS
        What the 3.x snapshots say about catalog actions (DECISIONS T6), read-only: per target key the
        oldest recorded previous value (the original, "value before iG"), the previous value of the
        newest apply, and whether that apply is still in effect (no revert since). Oldest first.
    #>
    [CmdletBinding()]
    param()
    $byKey = [ordered]@{}
    # Only the tool's own Backups folder, and only files a restore would trust (owner Administrators or SYSTEM, not
    # writable by standard users, a known tool and schema): a planted file never becomes a baseline (review 3.6 R1).
    $own = Get-IgwtDataPath -Kind Backups
    $list = @(Get-IgwtSnapshotList | Where-Object { (Test-IgwtPathUnder -Path $_.Path -Parent $own) -and (Test-IgwtTrustedFile -Path $_.Path) -and $script:IgwtSnapshotToolNames -contains [string]$_.Document.tool -and $script:IgwtSupportedSnapshotSchemas -contains [int]$_.Document.schema })
    [array]::Reverse($list)
    foreach ($s in $list) {
        $op = (([string]$s.Operation) -split ':')[0]
        if ($op -notin 'Apply', 'Preset', 'ResetDefault', 'Revert') { continue }
        foreach ($e in @($s.Entries)) {
            if ([string]$e.result -notin 'Applied', 'Reverted') { continue }
            foreach ($a in @($e.actions)) {
                if (-not $a -or $null -eq $a.data -or -not $a.fingerprint) { continue }
                $key = "action|$($e.tweakId)|$([int]$a.index)|$($a.fingerprint)"
                if ($op -eq 'Revert' -or [string]$e.result -eq 'Reverted') { if ($byKey.Contains($key)) { $byKey[$key].Applied = $false }; continue }
                if (-not $byKey.Contains($key)) { $byKey[$key] = [pscustomobject]@{ Key = $key; Item = [string]$e.tweakId; Index = [int]$a.index; Fingerprint = [string]$a.fingerprint; Type = [string]$a.type; Original = $a.data; Before = $a.data; ApplyData = $a.applied; Snapshot = $s.Path; Applied = $true; Op = $op } }
                else { $byKey[$key].Before = $a.data; $byKey[$key].ApplyData = $a.applied; $byKey[$key].Snapshot = $s.Path; $byKey[$key].Applied = $true; $byKey[$key].Op = $op }
            }
        }
    }
    return @($byKey.Values)
}

function Invoke-IgwtJournalUpgrade {
    <#
    .SYNOPSIS
        Imports the 3.x snapshots into the change journal once (DECISIONS T6, T13): each target gets
        its baseline (the oldest recorded previous value, origin upgrade); changes still in effect
        become committed changes of one upgrade session, so they can be reverted from the journal.
        Writes only the journal (no system state); runs once (a second call finds the upgrade session).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Assert-IgwtWritable -Operation 'Invoke-IgwtJournalUpgrade'
    $j = Get-IgwtJournalState -Refresh
    if ($j.Status -eq 'Broken') { return [pscustomobject]@{ Imported = 0; Baselines = 0; Skipped = @(); Message = "The change journal is read-only: $($j.Reason)" } }
    if (@((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin'] -and [string]$_['origin']['type'] -eq 'upgrade' }).Count) { return [pscustomobject]@{ Imported = 0; Baselines = 0; Skipped = @(); Message = 'Already imported.' } }
    $rows = @(Get-IgwtLegacySnapshotImport)
    # Without 3.x snapshots the import still records the adopted values (T6).
    if (-not $PSCmdlet.ShouldProcess("$($rows.Count) recorded value(s)", 'Import the 3.x snapshots into the change journal')) { return $null }
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'upgrade'; ref = 'snapshots'; version = $script:IgwtVersion }) -Title "Upgrade to 3.6: imported the 3.x snapshots ($($rows.Count) value(s))" -Confirm:$false
    $imported = 0; $baselines = 0
    $skipped = New-Object System.Collections.Generic.List[string]
    $adopted = 0
    try {
        # Under the lock: another window may have imported meanwhile (review 3.6 R16).
        if (@((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin'] -and [string]$_['origin']['type'] -eq 'upgrade' -and [string]$_['session'] -ne $session.Id }).Count) { return [pscustomobject]@{ Imported = 0; Baselines = 0; Adopted = 0; Skipped = @(); Message = 'Already imported.' } }
        $ctx = New-IgwtContext
        $j = Get-IgwtJournalState
        foreach ($row in $rows) {
            $target = [ordered]@{ provider = 'action'; key = $row.Key; item = $row.Item; index = $row.Index; type = $row.Type; fingerprint = $row.Fingerprint }
            if (-not $j.Baselines.ContainsKey($row.Key)) {
                $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'baseline'; session = $session.Id; item = $row.Item; target = $target; before = $row.Original; origin = 'upgrade'; snapshot = $row.Snapshot })
                $baselines++
            }
            # Only a change still in effect becomes iG's change; a reset to the default, or a value changed since,
            # stays a baseline only, so a revert never overwrites it silently (review 3.6 R10).
            if (-not $row.Applied -or $row.Op -eq 'ResetDefault') { continue }
            try {
                $r = Resolve-IgwtChangeTarget -Target $target
                $roll = Get-IgwtStateRollup -States @(Get-IgwtActionState -Action $r.Action -Context $ctx | ForEach-Object { [string]$_.State })
                if ($roll -ne 'On') { $skipped.Add("$($row.Key): no longer in the state iG set ($roll); kept as the original only."); continue }
                $now = & $script:IgwtChangeProviders['action'].Get $r $ctx
            } catch { $skipped.Add("$($row.Key): $($_.Exception.Message)"); continue }
            $session.Step++
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent'; session = $session.Id; step = $session.Step; group = $row.Item; op = 'change'; origin = $session.Origin; item = $row.Item; target = $target; desired = 'on'; before = $row.Before })
            $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'committed'; session = $session.Id; step = $session.Step; group = $row.Item; op = 'change'; origin = $session.Origin; item = $row.Item; target = $target; desired = 'on'; before = $row.Before; applied = $row.ApplyData; after = $now; readBack = @{ ok = $true; state = 'imported' }; snapshot = $row.Snapshot })
            $session.Results.Add([pscustomobject]@{ Step = $session.Step; Result = 'Committed' })
            $imported++
        }
        # Items on now with no snapshot at all (T6): recorded as adopted, original unknown, with the documented
        # Windows default where the catalog has one (review 3.6 R11). Not offered for revert; reset them to the default instead.
        $known = @{}; foreach ($row in $rows) { $known[[string]$row.Key] = $true }
        $j = Get-IgwtJournalState
        foreach ($t in @(Get-IgwtCatalog)) {
            $acts = @($t.actions)
            for ($i = 0; $i -lt $acts.Count; $i++) {
                $a = $acts[$i]
                if ([string]$a.type -eq 'check') { continue }
                $tg = Get-IgwtActionTarget -ItemId ([string]$t.id) -Index $i -Action $a
                if ($known.ContainsKey($tg['key']) -or $j.Baselines.ContainsKey($tg['key']) -or $j.Last.ContainsKey($tg['key'])) { continue }
                try {
                    $roll = Get-IgwtStateRollup -States @(Get-IgwtActionState -Action $a -Context $ctx | ForEach-Object { [string]$_.State })
                    if ($roll -ne 'On') { continue }
                    # A Windows default that already equals the on value is not a change by anyone.
                    if ($null -ne $a.default -and $null -ne $a.on -and [string]$a.default -eq [string]$a.on) { continue }
                    $now = Get-IgwtActionSnapshot -Action $a -Context $ctx
                } catch { continue }
                $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'adopted'; session = $session.Id; item = [string]$t.id; target = $tg; now = $now; original = 'unknown'; windowsDefault = $(if ($null -ne $a.default) { [string]$a.default } else { '' }); note = 'On when 3.6 was installed, with no 3.x snapshot: the value before is not known. Reset it to the Windows default on its page if you want.' })
                $adopted++
            }
        }
    } finally { Complete-IgwtChangeSession -Session $session }
    return [pscustomobject]@{ Imported = $imported; Baselines = $baselines; Adopted = $adopted; Skipped = $skipped.ToArray(); Message = "Imported $imported change(s) and $baselines original value(s) from the 3.x snapshots; $adopted value(s) adopted with the original unknown." }
}

#endregion
