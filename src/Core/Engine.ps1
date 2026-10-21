# Engine.ps1
# Generic engine: executes typed actions declared in the catalog.
# - Every tweak is applied atomically: snapshot first, then actions; on error the tweak's
#   already-applied actions are restored from the snapshot and the run continues.
# - Idempotent: a tweak that is already On is skipped; actions skip values already in place.
# - Dry run never calls an apply function.

#region Dispatch

function Get-IgwtActionSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    switch ([string]$Action.type) {
        'registry'           { return (Get-IgwtRegistrySnapshot -Action $Action -Context $Context) }
        'adapterRegistry'    { return (Get-IgwtRegistrySnapshot -Action $Action -Context $Context) }
        'netAdapterPower'    { return (Get-IgwtRegistrySnapshot -Action $Action -Context $Context) }
        'registryListMerge'  { return (Get-IgwtRegistrySnapshot -Action $Action -Context $Context) }
        'powercfgScheme'     { return (Get-IgwtPowerCfgSchemeSnapshot -Action $Action -Context $Context) }
        'powercfgSetting'    { return (Get-IgwtPowerCfgSettingSnapshot -Action $Action -Context $Context) }
        'service'            { return (Get-IgwtServiceSnapshot -Action $Action -Context $Context) }
        'netAdapterAdvanced' { return (Get-IgwtNetAdapterAdvancedSnapshot -Action $Action -Context $Context) }
        'netQosPolicy'       { return (Get-IgwtNetQosSnapshot -Action $Action -Context $Context) }
        'dnsDoh'             { return (Get-IgwtDnsDohSnapshot -Action $Action -Context $Context) }
        'mpPreference'       { return (Get-IgwtMpPreferenceSnapshot -Action $Action -Context $Context) }
        'asrRule'            { return (Get-IgwtAsrRuleSnapshot -Action $Action -Context $Context) }
        'optionalFeature'    { return (Get-IgwtOptionalFeatureSnapshot -Action $Action -Context $Context) }
        'custom'             { $h = Get-IgwtCustomHandler -Name ([string]$Action.handler); return (& $h.Snapshot $Action $Context) }
        'check'              { return @{} }
        { $_ -in 'storageSense', 'wufbPolicy', 'deviceInterrupt', 'serviceSet' } { return (Get-IgwtCompositeSnapshot -Action $Action -Context $Context) }
        'powercfgAttribute'  { return (Get-IgwtPowerAttributeSnapshot -Action $Action -Context $Context) }
        'powercfgSettingAcDc' { return (Get-IgwtPowerCfgSettingSnapshot -Action $Action -Context $Context) }
        'scheduledTask'      { return (Get-IgwtScheduledTaskSnapshot -Action $Action -Context $Context) }
        'firewallRule'       { return (Get-IgwtFirewallRuleSnapshot -Action $Action -Context $Context) }
        'appx'               { return (Get-IgwtAppxSnapshot -Action $Action -Context $Context) }
        'winget'             { return (Get-IgwtWingetSnapshot -Action $Action -Context $Context) }
        'capability'         { return (Get-IgwtCapabilitySnapshot -Action $Action -Context $Context) }
        { $_ -in 'processMitigation', 'exploitSystem' } { return (Get-IgwtMitigationSnapshot -Action $Action -Context $Context) }
        'cleanerRule'        { return (Get-IgwtCleanerRuleActionSnapshot -Action $Action -Context $Context) }
        default { throw "Unknown action type '$($Action.type)'." }
    }
}

function Invoke-IgwtActionApply {
    <# .SYNOPSIS Applies one action ('on' target or Windows 'default'). Custom handlers may return data for the snapshot. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    if (-not $PSCmdlet.ShouldProcess("$($Action.type) $(Get-IgwtActionFingerprint $Action)", "Apply ($Mode)")) { return $null }
    switch ([string]$Action.type) {
        'registry'           { Invoke-IgwtRegistryApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'adapterRegistry'    { Invoke-IgwtRegistryApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'netAdapterPower'    { Invoke-IgwtRegistryApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'registryListMerge'  { Invoke-IgwtListMergeApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'powercfgScheme'     { Invoke-IgwtPowerCfgSchemeApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'powercfgSetting'    { Invoke-IgwtPowerCfgSettingApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'service'            { Invoke-IgwtServiceApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'netAdapterAdvanced' { Invoke-IgwtNetAdapterAdvancedApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'netQosPolicy'       { Invoke-IgwtNetQosApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'dnsDoh'             { Invoke-IgwtDnsDohApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'mpPreference'       { Invoke-IgwtMpPreferenceApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'asrRule'            { Invoke-IgwtAsrRuleApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'optionalFeature'    { Invoke-IgwtOptionalFeatureApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'custom'             { $h = Get-IgwtCustomHandler -Name ([string]$Action.handler); return (& $h.Apply $Action $Context $Mode) }
        'check'              { return $null }
        { $_ -in 'storageSense', 'wufbPolicy', 'deviceInterrupt', 'serviceSet' } { Invoke-IgwtCompositeApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'powercfgAttribute'  { Invoke-IgwtPowerAttributeApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'powercfgSettingAcDc' { Invoke-IgwtPowerCfgSettingApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'scheduledTask'      { Invoke-IgwtScheduledTaskApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'firewallRule'       { Invoke-IgwtFirewallRuleApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'appx'               { Invoke-IgwtAppxApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'winget'             { Invoke-IgwtWingetApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'capability'         { Invoke-IgwtCapabilityApply -Action $Action -Context $Context -Mode $Mode; return $null }
        { $_ -in 'processMitigation', 'exploitSystem' } { Invoke-IgwtMitigationApply -Action $Action -Context $Context -Mode $Mode; return $null }
        'cleanerRule'        { Invoke-IgwtCleanerRuleActionApply -Action $Action -Context $Context -Mode $Mode; return $null }
        default { throw "Unknown action type '$($Action.type)'." }
    }
}

function Restore-IgwtActionSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if (-not $PSCmdlet.ShouldProcess("$($Action.type) $(Get-IgwtActionFingerprint $Action)", 'Restore snapshot')) { return }
    switch ([string]$Action.type) {
        'registry'           { Restore-IgwtRegistrySnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'adapterRegistry'    { Restore-IgwtRegistrySnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'netAdapterPower'    { Restore-IgwtRegistrySnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'registryListMerge'  { Restore-IgwtRegistrySnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'powercfgScheme'     { Restore-IgwtPowerCfgSchemeSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'powercfgSetting'    { Restore-IgwtPowerCfgSettingSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'service'            { Restore-IgwtServiceSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'netAdapterAdvanced' { Restore-IgwtNetAdapterAdvancedSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'netQosPolicy'       { Restore-IgwtNetQosSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'dnsDoh'             { Restore-IgwtDnsDohSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'mpPreference'       { Restore-IgwtMpPreferenceSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'asrRule'            { Restore-IgwtAsrRuleSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'optionalFeature'    { Restore-IgwtOptionalFeatureSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'custom'             { $h = Get-IgwtCustomHandler -Name ([string]$Action.handler); & $h.Restore $Action $Snapshot $Context }
        'check'              { }
        { $_ -in 'storageSense', 'wufbPolicy', 'deviceInterrupt', 'serviceSet' } { Restore-IgwtCompositeSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'powercfgAttribute'  { Restore-IgwtPowerAttributeSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'powercfgSettingAcDc' { Restore-IgwtPowerCfgSettingSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'scheduledTask'      { Restore-IgwtScheduledTaskSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'firewallRule'       { Restore-IgwtFirewallRuleSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'appx'               { Restore-IgwtAppxSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'winget'             { Restore-IgwtWingetSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'capability'         { Restore-IgwtCapabilitySnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        { $_ -in 'processMitigation', 'exploitSystem' } { Restore-IgwtMitigationSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        'cleanerRule'        { Restore-IgwtCleanerRuleActionSnapshot -Action $Action -Snapshot $Snapshot -Context $Context }
        default { throw "Unknown action type '$($Action.type)'." }
    }
}

#endregion

#region Single tweak

function Invoke-IgwtTweakChange {
    <#
    .SYNOPSIS
        Applies one tweak atomically ('on' or Windows 'default'). Records the snapshot entry before
        any change, rolls back this tweak on error, verifies the result afterwards.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Tweak,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$Snapshot,
        [ValidateSet('on', 'default')][string]$Mode = 'on'
    )
    $id = [string]$Tweak.id
    $actions = @($Tweak.actions)
    $captured = New-Object System.Collections.Generic.List[object]
    if (-not $PSCmdlet.ShouldProcess($id, "Apply ($Mode)")) { return [pscustomobject]@{ Id = $id; Result = 'Skipped'; Message = 'WhatIf' } }
    try {
        for ($i = 0; $i -lt $actions.Count; $i++) {
            $data = Get-IgwtActionSnapshot -Action $actions[$i] -Context $Context
            $captured.Add([ordered]@{ index = $i; type = [string]$actions[$i].type; fingerprint = (Get-IgwtActionFingerprint $actions[$i]); data = $data })
        }
    } catch {
        Write-IgwtLog -Level Error -TweakId $id -Message "Snapshot failed, nothing changed: $($_.Exception.Message)"
        return [pscustomobject]@{ Id = $id; Result = 'Failed'; Message = "Snapshot failed: $($_.Exception.Message)" }
    }
    Add-IgwtSnapshotEntry -Snapshot $Snapshot -TweakId $id -Actions $captured.ToArray() -Result 'Pending' -Level ([string]$Tweak.level)

    $done = -1
    try {
        for ($i = 0; $i -lt $actions.Count; $i++) {
            $done = $i
            $result = Invoke-IgwtActionApply -Action $actions[$i] -Context $Context -Mode $Mode
            if ($result -is [System.Collections.IDictionary]) { $captured[$i].data['applied'] = $result }
        }
    } catch {
        $err = $_.Exception.Message
        Write-IgwtLog -Level Error -TweakId $id -Message "Apply failed at action $done; rolling back this tweak: $err"
        $rollbackErrors = New-Object System.Collections.Generic.List[string]
        for ($j = $done; $j -ge 0; $j--) {
            try { Restore-IgwtActionSnapshot -Action $actions[$j] -Snapshot $captured[$j].data -Context $Context }
            catch { $rollbackErrors.Add("action ${j}: $($_.Exception.Message)") }
        }
        $msg = "Failed: $err"
        if ($rollbackErrors.Count -gt 0) { $msg += " | Rollback problems: $($rollbackErrors -join '; ')" }
        Add-IgwtSnapshotEntry -Snapshot $Snapshot -TweakId $id -Actions $captured.ToArray() -Result 'RolledBack' -Message $msg -Level ([string]$Tweak.level)
        return [pscustomobject]@{ Id = $id; Result = 'Failed'; Message = $msg }
    }

    Add-IgwtSnapshotEntry -Snapshot $Snapshot -TweakId $id -Actions $captured.ToArray() -Result 'Applied' -Level ([string]$Tweak.level)
    if ($Tweak.postApply) { Invoke-IgwtPostApplyHook -Hook ([string]$Tweak.postApply) }

    # Verify. Runtime checks (e.g. "HVCI running") legitimately stay Off until a reboot.
    $verified = $true
    $note = ''
    if ($Mode -eq 'on') {
        $after = Get-IgwtTweakState -Tweak $Tweak -Context $Context
        $configItems = @($after.Items | Where-Object { $_.ActionType -ne 'check' -and $_.State -ne 'NotApplicable' })
        $configState = Get-IgwtStateRollup -States @($configItems | ForEach-Object { [string]$_.State })
        if ($configState -notin 'On', 'NotApplicable') {
            $verified = $false
            $note = "Verification found state '$configState' (possibly blocked by Tamper Protection, policy, or a value Windows rewrote)."
            Write-IgwtLog -Level Warn -TweakId $id -Message $note
        }
    }
    Write-IgwtLog -TweakId $id -Message "Applied ($Mode). Requires: $($Tweak.requires)."
    return [pscustomobject]@{ Id = $id; Result = 'Applied'; Verified = $verified; Message = $note; Requires = [string]$Tweak.requires }
}

#endregion

#region Batch operations

function Get-IgwtRiskZoneSummary {
    <# .SYNOPSIS One paragraph for a Risk Zone item: warning, what it turns off and on, and its risks. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Tweak)
    $rz = $Tweak.riskZone
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add([string]$Tweak.warning)
    $off = @($rz.turnsOff | Where-Object { $_ }); $on = @($rz.turnsOn | Where-Object { $_ }); $risks = @($rz.risks | Where-Object { $_ })
    if ($off.Count) { $parts.Add("Turns off: $($off -join '; ').") }
    if ($on.Count) { $parts.Add("Turns on: $($on -join '; ').") }
    if ($risks.Count) { $parts.Add("Risks: $($risks -join '; ').") }
    return ($parts -join ' ')
}

function Resolve-IgwtTweakSelection {
    <# .SYNOPSIS Validates ids, conflicts and expert acknowledgement; returns tweaks sorted by order. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Id, [switch]$AcknowledgeRisk)
    $tweaks = @(Get-IgwtTweak -Id ($Id | Select-Object -Unique))
    foreach ($t in $tweaks) {
        foreach ($c in @($t.conflictsWith)) {
            if ($Id -contains [string]$c) { throw "Tweaks '$($t.id)' and '$c' conflict; select only one." }
        }
        if ($t.expert -and -not $AcknowledgeRisk) {
            if ([string]$t.evidence.tier -eq 'R') { throw "'$($t.id)' is a rejected tweak from the Risk Zone. $(Get-IgwtRiskZoneSummary -Tweak $t) Re-run with -AcknowledgeRisk to apply it at your own risk." }
            throw "'$($t.id)' is an expert toggle ($($t.level) level): $($t.warning) Re-run with -AcknowledgeRisk if you understand the consequences."
        }
    }
    return @($tweaks | Sort-Object order, id)
}

function Get-IgwtPlan {
    <#
    .SYNOPSIS
        Dry run: what would change for the given tweaks. Read-only.
    .OUTPUTS
        One object per tweak with Id, Name, Action (Change/Skip/NotApplicable/Policy), State, Items.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Id, [ValidateSet('on', 'default')][string]$Mode = 'on', $Context)
    if (-not $Context) { $Context = New-IgwtContext }
    foreach ($t in @(Get-IgwtTweak -Id $Id | Sort-Object order, id)) {
        $s = Get-IgwtTweakState -Tweak $t -Context $Context
        $plan = 'Change'
        switch ($s.State) {
            'On' { if ($Mode -eq 'on') { $plan = 'Skip' } }
            'NotApplicable' { $plan = 'NotApplicable' }
            'ManagedByPolicy' { $plan = 'Policy' }
        }
        [pscustomobject]@{
            Id       = $t.id
            Name     = $t.name
            Category = $t.category
            Tier     = $t.evidence.tier
            Level    = $t.level
            Risk     = $t.risk
            Requires = $t.requires
            Plan     = $plan
            State    = $s.State
            Reason   = $s.Reason
            Items    = @($s.Items | Where-Object { $_.State -ne 'On' -or $Mode -eq 'default' })
            AllItems = $s.Items
        }
    }
}

function Invoke-IgwtApply {
    <#
    .SYNOPSIS
        Applies tweaks (or resets them to Windows defaults) with restore point, JSON snapshot,
        per-tweak atomic rollback and logging.
    .PARAMETER Id
        Tweak ids.
    .PARAMETER Operation
        Label recorded in the snapshot (Apply, Preset:Competitive, ResetDefault).
    .PARAMETER Mode
        'on' applies the tweak; 'default' resets its settings to the documented Windows default.
    .PARAMETER SkipRestorePoint
        Do not create a System Restore point (the JSON snapshot is always written).
    .PARAMETER EnableSystemProtection
        Consent to turn on System Protection for the system drive if it is off.
    .PARAMETER AcknowledgeRisk
        Required for expert toggles.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string[]]$Id,
        [string]$Operation = 'Apply',
        [ValidateSet('on', 'default')][string]$Mode = 'on',
        [switch]$SkipRestorePoint,
        [switch]$EnableSystemProtection,
        [switch]$AcknowledgeRisk,
        $Context,
        [scriptblock]$OnProgress
    )
    $tweaks = Resolve-IgwtTweakSelection -Id $Id -AcknowledgeRisk:$AcknowledgeRisk
    if (-not $script:IgwtSettings.TestMode) {
        $pre = Get-IgwtPreflight -ForApply
        if (-not $pre.CanApply) { throw ($pre.Errors -join ' ') }
        foreach ($w in $pre.Warnings) { Write-IgwtLog -Level Warn -Message "Preflight: $w" }
        Initialize-IgwtDataRoot
        Initialize-IgwtUserHive
    }
    if (-not $Context) { $Context = New-IgwtContext }

    $todo = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($t in $tweaks) {
        $s = Get-IgwtTweakState -Tweak $t -Context $Context
        if ($s.State -eq 'NotApplicable') { $results.Add([pscustomobject]@{ Id = $t.id; Result = 'NotApplicable'; Message = $s.Reason }); continue }
        if ($Mode -eq 'on' -and $null -ne $s.PSObject.Properties['Blocked'] -and $s.Blocked -and $s.State -ne 'On') { $results.Add([pscustomobject]@{ Id = $t.id; Result = 'NotApplicable'; Message = $s.Reason }); continue }
        if ($s.State -eq 'ManagedByPolicy') { $results.Add([pscustomobject]@{ Id = $t.id; Result = 'ManagedByPolicy'; Message = $s.Reason }); continue }
        if ($Mode -eq 'on' -and $s.State -eq 'On') { $results.Add([pscustomobject]@{ Id = $t.id; Result = 'Unchanged'; Message = 'Already in target state.' }); continue }
        if ($Mode -eq 'default' -and @($t.actions | Where-Object { $_.type -ne 'check' }).Count -eq 0) { continue }
        $todo.Add($t)
    }
    if ($todo.Count -eq 0) {
        Write-IgwtLog -Message "$Operation`: nothing to change."
        return [pscustomobject]@{ Operation = $Operation; Snapshot = $null; RestorePoint = $null; Results = $results.ToArray(); Requires = 'none' }
    }
    if (-not $PSCmdlet.ShouldProcess("$($todo.Count) tweak(s): $(@($todo | ForEach-Object { $_.id }) -join ', ')", $Operation)) {
        return [pscustomobject]@{ Operation = $Operation; Snapshot = $null; RestorePoint = $null; Results = $results.ToArray(); Requires = 'none' }
    }

    $rp = $null
    if (-not $SkipRestorePoint -and -not $script:IgwtSettings.TestMode) {
        Send-IgwtProgress -Text 'Creating System Restore point...' -Percent 0 -Callback $OnProgress
        $rp = New-IgwtRestorePoint -Description "iG Windows Tuner: before $Operation" -EnableSystemProtection:$EnableSystemProtection
        if (-not $rp.Created) {
            if ($rp.Reason -eq 'SystemProtectionDisabled') {
                throw 'System Protection is off for the system drive, so no restore point can be created. Re-run with -EnableSystemProtection (consent) or -SkipRestorePoint (JSON snapshot only).'
            }
            Write-IgwtLog -Level Warn -Message "Restore point not created ($($rp.Reason)). Continuing with the JSON snapshot."
        }
    }

    $snap = New-IgwtSnapshot -Operation $Operation -Detail "$($todo.Count) tweak(s)"
    Save-IgwtSnapshot -Snapshot $snap
    Write-IgwtLog -Message "$Operation started: $(@($todo | ForEach-Object { $_.id }) -join ', '). Snapshot: $($snap.Path)"

    $n = 0
    foreach ($t in $todo) {
        $n++
        Send-IgwtProgress -Text "Applying $($t.name)" -Percent ([int](100 * ($n - 1) / $todo.Count)) -Callback $OnProgress
        $results.Add((Invoke-IgwtTweakChange -Tweak $t -Context $Context -Snapshot $snap -Mode $Mode))
    }

    $applied = @($results | Where-Object { $_.Result -eq 'Applied' })
    $requires = 'none'
    $rebootIds = @($applied | Where-Object { $_.Requires -eq 'reboot' } | ForEach-Object { $_.Id })
    $logoffIds = @($applied | Where-Object { $_.Requires -eq 'logoff' } | ForEach-Object { $_.Id })
    if ($rebootIds.Count -gt 0) { $requires = 'reboot' } elseif ($logoffIds.Count -gt 0) { $requires = 'logoff' }
    if ($requires -ne 'none' -and -not $script:IgwtSettings.TestMode) { Set-IgwtPendingRestartState -Requires $requires -TweakId (@($rebootIds) + @($logoffIds)) }
    Send-IgwtProgress -Text 'Done' -Percent 100 -Callback $OnProgress
    Write-IgwtLog -Message "$Operation finished: $($applied.Count) applied, $(@($results | Where-Object { $_.Result -eq 'Failed' }).Count) failed. Requires: $requires."
    return [pscustomobject]@{ Operation = $Operation; Snapshot = $snap.Path; RestorePoint = $rp; Results = $results.ToArray(); Requires = $requires }
}

function Invoke-IgwtRevert {
    <#
    .SYNOPSIS
        Restores exact snapshot values.
    .PARAMETER Id
        Revert these tweaks from their most recent apply.
    .PARAMETER SnapshotPath
        Revert from this snapshot file (all its applied entries, or only -Id).
    .PARAMETER Last
        Revert everything from the most recent apply/preset snapshot.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]]$Id, [string]$SnapshotPath, [switch]$Last, $Context, [scriptblock]$OnProgress)
    if (-not $script:IgwtSettings.TestMode) {
        $pre = Get-IgwtPreflight -ForApply
        if (-not $pre.CanApply) { throw ($pre.Errors -join ' ') }
        Initialize-IgwtDataRoot
        Initialize-IgwtUserHive
    }
    if (-not $Context) { $Context = New-IgwtContext }

    # Collect (tweak, entry) pairs to restore.
    $work = New-Object System.Collections.Generic.List[object]
    if ($SnapshotPath -or $Last) {
        if ($Last) {
            $latest = @(Get-IgwtSnapshotList | Where-Object { (($_.Operation -split ':')[0]) -in 'Apply', 'Preset', 'ResetDefault' -and $_.Applied.Count -gt 0 }) | Select-Object -First 1
            if (-not $latest) { throw 'No apply snapshot found to revert.' }
            $SnapshotPath = $latest.Path
        }
        $doc = Read-IgwtSnapshot -Path $SnapshotPath
        if ([string]$doc.operation -eq 'Startup') {
            Restore-IgwtStartupSnapshot -SnapshotPath $SnapshotPath
            return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $null; Results = @([pscustomobject]@{ Id = [string]$doc.detail; Result = 'Reverted'; Message = 'Startup entry restored.' }); Requires = 'none' }
        }
        if ([string]$doc.operation -eq 'ASR') {
            $asr = Restore-IgwtAsrSnapshot -SnapshotPath $SnapshotPath
            return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $asr.Snapshot; Results = @($asr.Results); Requires = 'none' }
        }
        if ([string]$doc.operation -eq 'Power') {
            $pw = Restore-IgwtPowerSettingSnapshot -SnapshotPath $SnapshotPath
            return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $pw.Snapshot; Results = @($pw.Results); Requires = 'none' }
        }
        if ([string]$doc.operation -eq 'Manage') {
            $mg = Restore-IgwtManagedSnapshot -SnapshotPath $SnapshotPath
            return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $mg.Snapshot; Results = @($mg.Results); Requires = 'none' }
        }
        foreach ($e in @($doc.entries | Where-Object { $_ -and $_.result -eq 'Applied' })) {
            if ($Id -and $Id -notcontains [string]$e.tweakId) { continue }
            $work.Add([pscustomobject]@{ Entry = $e; Source = $SnapshotPath })
        }
    } elseif ($Id) {
        foreach ($i in $Id) {
            $null = Get-IgwtTweak -Id $i
            $found = Find-IgwtLatestSnapshotEntry -TweakId $i
            if (-not $found) { Write-IgwtLog -Level Warn -TweakId $i -Message 'No un-reverted apply found in the backups; nothing to revert.'; continue }
            $null = Read-IgwtSnapshot -Path $found.Path   # trust check
            $work.Add([pscustomobject]@{ Entry = $found.Entry; Source = $found.Path })
        }
    } else {
        throw 'Specify -Id, -SnapshotPath or -Last.'
    }
    if ($work.Count -eq 0) {
        return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $null; Results = @(); Requires = 'none' }
    }
    if (-not $PSCmdlet.ShouldProcess("$($work.Count) tweak(s)", 'Revert')) {
        return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $null; Results = @(); Requires = 'none' }
    }

    $catalog = Get-IgwtCatalog
    # Reverse apply order: highest 'order' first.
    $ordered = @($work | ForEach-Object {
            $e = $_
            $t = $catalog | Where-Object { $_.id -eq [string]$e.Entry.tweakId } | Select-Object -First 1
            [pscustomobject]@{ Entry = $e.Entry; Source = $e.Source; Tweak = $t; Order = $(if ($t) { [int]$t.order } else { 0 }) }
        } | Sort-Object Order -Descending)

    $revSnap = New-IgwtSnapshot -Operation 'Revert' -Detail "from $(@($ordered | ForEach-Object { Split-Path $_.Source -Leaf } | Select-Object -Unique) -join ', ')"
    Save-IgwtSnapshot -Snapshot $revSnap
    $results = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($w in $ordered) {
        $n++
        $tid = [string]$w.Entry.tweakId
        Send-IgwtProgress -Text "Reverting $tid" -Percent ([int](100 * ($n - 1) / $ordered.Count)) -Callback $OnProgress
        if (-not $w.Tweak) { $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = 'Tweak no longer exists in the catalog.' }); continue }
        $actions = @($w.Tweak.actions)
        $entryActions = @($w.Entry.actions | Where-Object { $null -ne $_ })
        $mismatch = $false
        foreach ($ea in $entryActions) {
            $idx = [int]$ea.index
            if ($idx -ge $actions.Count -or (Get-IgwtActionFingerprint $actions[$idx]) -ne [string]$ea.fingerprint) { $mismatch = $true }
        }
        if ($mismatch) {
            $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = 'Catalog definition changed since the snapshot; not restored automatically.' })
            Write-IgwtLog -Level Error -TweakId $tid -Message 'Snapshot does not match the current catalog definition; skipped.'
            continue
        }
        # Capture the current state first so the revert itself can be undone.
        $captured = New-Object System.Collections.Generic.List[object]
        try {
            foreach ($ea in $entryActions) {
                $a = $actions[[int]$ea.index]
                $captured.Add([ordered]@{ index = [int]$ea.index; type = [string]$a.type; fingerprint = (Get-IgwtActionFingerprint $a); data = (Get-IgwtActionSnapshot -Action $a -Context $Context) })
            }
        } catch { Write-IgwtLog -Level Warn -TweakId $tid -Message "Could not capture pre-revert state: $($_.Exception.Message)" }
        $errs = New-Object System.Collections.Generic.List[string]
        foreach ($ea in @($entryActions | Sort-Object { [int]$_.index } -Descending)) {
            try { Restore-IgwtActionSnapshot -Action $actions[[int]$ea.index] -Snapshot $ea.data -Context $Context }
            catch { $errs.Add("action $($ea.index): $($_.Exception.Message)") }
        }
        if ($w.Tweak.postApply) { Invoke-IgwtPostApplyHook -Hook ([string]$w.Tweak.postApply) }
        if ($errs.Count -gt 0) {
            Add-IgwtSnapshotEntry -Snapshot $revSnap -TweakId $tid -Actions $captured.ToArray() -Result 'Failed' -Message ($errs -join '; ') -Level ([string]$w.Tweak.level)
            $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = ($errs -join '; '); Requires = [string]$w.Tweak.requires })
            Write-IgwtLog -Level Error -TweakId $tid -Message "Revert had errors: $($errs -join '; ')"
        } else {
            Add-IgwtSnapshotEntry -Snapshot $revSnap -TweakId $tid -Actions $captured.ToArray() -Result 'Reverted' -Level ([string]$w.Tweak.level)
            $results.Add([pscustomobject]@{ Id = $tid; Result = 'Reverted'; Message = ''; Requires = [string]$w.Tweak.requires })
            Write-IgwtLog -TweakId $tid -Message "Reverted from $(Split-Path $w.Source -Leaf)."
        }
    }
    $done = @($results | Where-Object { $_.Result -eq 'Reverted' })
    $requires = 'none'
    if (@($done | Where-Object { $_.Requires -eq 'reboot' }).Count -gt 0) { $requires = 'reboot' }
    elseif (@($done | Where-Object { $_.Requires -eq 'logoff' }).Count -gt 0) { $requires = 'logoff' }
    if ($requires -ne 'none' -and -not $script:IgwtSettings.TestMode) { Set-IgwtPendingRestartState -Requires $requires -TweakId @($done | ForEach-Object { $_.Id }) }
    Send-IgwtProgress -Text 'Done' -Percent 100 -Callback $OnProgress
    return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $revSnap.Path; Results = $results.ToArray(); Requires = $requires }
}

function Get-IgwtPresetPlan {
    <#
    .SYNOPSIS
        Preset diff against the current state, resolved through the hardware overlays: rows for
        every included item plus the items an overlay blocked, each with Origin (preset, overlay,
        user) and Notes (why it was added, blocked or skipped). Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Preset, $Context, [string[]]$AddIds = @(), [string[]]$RemoveIds = @())
    if (-not $Context) { $Context = New-IgwtContext }
    $tags = @()
    if ($null -ne $Context.PSObject.Properties['HardwareTags']) { $tags = @($Context.HardwareTags) }
    $sel = Resolve-IgwtPresetSelection -Preset $Preset -Tags $tags -AddIds $AddIds -RemoveIds $RemoveIds
    $show = @($sel.Items | Where-Object { $_.Included -or $_.Blocked })
    if ($show.Count -eq 0) { return @() }
    $byId = @{}
    foreach ($it in $show) { $byId[$it.Id] = $it }
    foreach ($row in @(Get-IgwtPlan -Id @($show | ForEach-Object { $_.Id }) -Context $Context)) {
        $it = $byId[[string]$row.Id]
        $row | Add-Member -NotePropertyName Origin -NotePropertyValue ([string]$it.Origin) -Force
        $row | Add-Member -NotePropertyName Notes -NotePropertyValue @($it.Notes) -Force
        $row
    }
}

#endregion
