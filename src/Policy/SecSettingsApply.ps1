# SecSettingsApply.ps1
# Security Settings Manager (3.8): the change plan and its preview (DECISIONS SM17, SM19, SM26,
# SM29, SM30 part 2). The plan is read-only and shared by the CLI and the GUI; the journaled apply
# is added in B8.

function ConvertTo-IgwtSecSettingText {
    <# .SYNOPSIS A value as short text for the preview. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '(none)' }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains('State')) {
            $vals = $Value['Values']
            $extra = $(if ($vals -is [System.Collections.IDictionary] -and $vals.Count) { ': ' + (@($vals.Keys | Sort-Object | ForEach-Object { "$_=$(@($vals[$_]) -join ',')" }) -join '; ') } else { '' })
            return "$($Value['State'])$extra"
        }
        return (@($Value.Keys | ForEach-Object { "$_=$($Value[$_])" }) -join '; ')
    }
    if ($Value -is [array]) { return (@($Value) -join ', ') }
    return [string]$Value
}

function Get-IgwtSecSettingChangePlan {
    <#
    .SYNOPSIS
        The read-only plan for security setting changes (DECISIONS SM29, SM30 part 2): one row per
        change with Id, Name, Writer, Before, After, Status (Change, InPlace, Refused,
        NeedsConfirmation, NeedsManagedAck, OneWay), Reason, Risk, Restart, Prerequisites, Checks,
        SideEffects and the writer's input (Registry.pol ops, Defender value, ASR mode, secpol
        change object, audit setting, exclusions to remove). A batch that mixes a one-way change
        with anything else is refused. Read-only.
    .PARAMETER Changes
        @{ Id; Value } per change (Value as Test-IgwtSecSettingValue takes it).
    .PARAMETER AcknowledgeRisk
        The user confirmed the high-risk changes (CLI -AcknowledgeRisk, GUI typed confirmation).
    .PARAMETER AcknowledgeManaged
        The user confirmed changes on a managed PC.
    .PARAMETER Rows
        The current rows (Get-IgwtSecSettings); read fresh when not given.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Changes, [switch]$AcknowledgeRisk, [switch]$AcknowledgeManaged, [object[]]$Rows)
    if (-not $Rows) { $Rows = @((Get-IgwtSecSettings).Rows) }
    $byId = @{}; foreach ($r in @($Rows)) { if ($r) { $byId[([string]$r.Id).ToLowerInvariant()] = $r } }
    $catalog = $null; $policyIndex = @{}
    $identity = $null; try { $identity = Get-IgwtCurrentIdentity } catch { $identity = $null }
    $managed = $false; try { $managed = [bool](Get-IgwtManagementState).MdmEnrolled } catch { $managed = $false }
    $pol = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Changes)) {
        $id = [string]$c.Id
        $row = $byId[$id.ToLowerInvariant()]
        $p = [ordered]@{ Id = $id; Name = $id; Writer = 'none'; Before = $null; After = $null; Status = 'Change'; Reason = ''; Risk = 'normal'; Restart = 'none'
            Prerequisites = @(); Checks = @(); SideEffects = @(); Ops = @(); Class = ''; PolicyId = ''; Input = $null; Removed = @() }
        if (-not $row) { $p.Status = 'Refused'; $p.Reason = 'iG does not know this setting.'; $out.Add([pscustomobject]$p); continue }
        $p.Name = [string]$row.Name; $p.Writer = [string]$row.Writer; $p.Before = $row.Current; $p.Risk = [string]$row.Risk; $p.Restart = [string]$row.Restart
        $p.SideEffects = @($row.SideEffects); $p.Class = [string]$row.Class
        $managedOnly = ($row.ReadOnly -and ([string]$row.ReadOnlyReason).StartsWith('This PC is managed'))
        if ($row.ReadOnly -and -not ($managedOnly -and $AcknowledgeManaged)) {
            $p.Status = $(if ($managedOnly) { 'NeedsManagedAck' } else { 'Refused' }); $p.Reason = [string]$row.ReadOnlyReason; $out.Add([pscustomobject]$p); continue
        }
        if ($managedOnly) { $p.Writer = $(if ([string]$row.SourceKind -eq 'admx') { 'localPolicy' } else { [string]$row.SourceKind }) }
        $v = Test-IgwtSecSettingValue -ValueSpec $row.ValueSpec -Value $c.Value -Current $row.Current
        if (-not $v.Ok) { $p.Status = 'Refused'; $p.Reason = (@($v.Errors) -join ' '); $out.Add([pscustomobject]$p); continue }
        $p.After = $v.Value
        $refusals = New-Object System.Collections.Generic.List[string]
        $same = $false
        switch ([string]$row.SourceKind) {
            'admx' {
                if (-not $catalog) { $catalog = Get-IgwtAdmxCatalog; foreach ($x in @($catalog.Policies)) { if ($x) { $policyIndex[[string]$x.Id] = $x } } }
                $policy = $policyIndex[[string]$row.PolicyId]
                if (-not $policy) { $refusals.Add('The policy definition is no longer on this PC.'); break }
                $class = [string]$row.Class
                if (-not $pol.ContainsKey($class)) { $pol[$class] = @(); try { $pol[$class] = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $class)).Entries) } catch { $pol[$class] = @() } }
                $ops = @(Get-IgwtPolicyRegistryOps -Policy $policy -State $v.Value.State -Values $v.Value.Values)
                $p.Ops = $ops; $p.PolicyId = [string]$policy.Id; $p.Writer = 'localPolicy'
                foreach ($r in @(Test-IgwtSecSettingOpsLowerProtection -Class $class -Ops $ops -CurrentEntries $pol[$class])) { $refusals.Add($r) }
                foreach ($o in @($ops | Where-Object { $_.Op -eq 'Set' })) { foreach ($chk in @(Get-IgwtSecSettingLockoutChecks -ValueName ([string]$o.ValueName) -Value $o.Value -Identity $identity)) { $p.Checks += $chk } }
                $before = @(Get-IgwtSecSettingPolicyEntries -Policy $policy -Entries $pol[$class])
                $after = @(Get-IgwtSecSettingPolicyEntries -Policy $policy -Entries @(Update-IgwtPolEntries -Entries $pol[$class] -Ops $ops))
                $same = ((@(ConvertTo-IgwtSecSettingCanonicalEntries -Entries $before) -join "`n") -eq (@(ConvertTo-IgwtSecSettingCanonicalEntries -Entries $after) -join "`n"))
                $p.Input = @{ PolicyId = [string]$policy.Id; Class = $class; State = $v.Value.State; Values = $v.Value.Values }
            }
            'defender' {
                $mp = $id.Substring('defender:'.Length)
                $def = @((Get-IgwtDefenderSettingCatalog).settings | Where-Object { [string]$_.mp -eq $mp }) | Select-Object -First 1
                if ($def) { $why = Test-IgwtDefenderSettingValue -Definition $def -Value $v.Value -Current $row.Current; if ($why) { $refusals.Add([string]$why) } }
                $same = ((ConvertTo-IgwtCanonicalJson $row.Current) -eq (ConvertTo-IgwtCanonicalJson $v.Value))
                $p.Input = @{ Setting = @{ $mp = $v.Value } }
            }
            'asr' {
                $same = ([string]$row.Current -eq [string]$v.Value)
                $p.Input = @{ Id = $id.Substring('asr:'.Length); Mode = [string]$v.Value }
            }
            'exclusionList' {
                $keep = @{}; foreach ($x in @($v.Value)) { $keep[([string]$x).ToLowerInvariant()] = $true }
                $removed = @(@($row.Current) | Where-Object { $_ -and -not $keep.ContainsKey(([string]$_).ToLowerInvariant()) })
                $p.Removed = $removed; $same = ($removed.Count -eq 0)
                $p.Input = @{ Kind = $id.Substring('exclusion:'.Length); Values = $removed }
                if (-not $same) { $p.Status = 'OneWay'; $p.Reason = "Removing an exclusion cannot be undone by iG; re-add it by hand in Windows Security if needed: $($removed -join ', ')." }
            }
            'secpolicy' {
                $section = [string]$row.Section; $key = [string]$row.Key
                if ($section -notin 'System Access', 'Registry Values') { $refusals.Add("The section '$section' is not changed by the manager."); break }
                $kind = [string]@($row.ValueSpec.Elements)[0].Kind
                $encoded = $(if ($section -eq 'System Access') { [string]$v.Value } else {
                        $t = switch ($kind) { 'text' { 1 } 'multiText' { 7 } default { 4 } }
                        "$t," + $(if ($kind -eq 'multiText') { (@($v.Value) -join ',') } elseif ($kind -eq 'bool') { $(if ($v.Value) { '1' } else { '0' }) } else { [string]$v.Value })
                    })
                $p.Input = [pscustomobject]@{ Section = $section; Key = $key; Value = $encoded }
                $same = ([string]$row.Current -eq ($encoded -replace '^\d+,', ''))
                foreach ($chk in @(Get-IgwtSecSettingLockoutChecks -ValueName ($key.Substring($key.LastIndexOf('\') + 1)) -Value ($encoded -replace '^\d+,', '') -Identity $identity)) { $p.Checks += $chk }
                foreach ($w in @((Get-IgwtSecSettingsData).Weakening.entries)) {
                    $vn = $key.Substring($key.LastIndexOf('\') + 1); $k = $key -replace '^MACHINE\\', '' -replace '\\[^\\]+$', ''
                    if ($k -match "^(?i)(?:$($w.key))$" -and $vn -match "^(?i)(?:$($w.valueName))$" -and @($w.values) -contains ($encoded -replace '^\d+,', '')) { $refusals.Add([string]$w.reason) }
                }
                if ($null -eq $row.Current -or [string]$row.Current -eq '') { $p.Status = 'OneWay'; $p.Reason = 'This option was not defined before; Windows cannot remove it again, so iG cannot undo this change.' }
            }
            'audit' {
                $why = Test-IgwtSecSettingAuditAddOnly -Before ([string]$row.Current) -After ([string]$v.Value)
                if ($why) { $refusals.Add($why) }
                $same = ([string]$row.Current -eq [string]$v.Value)
                $p.Input = @{ Guid = $id.Substring('audit:'.Length); Setting = [string]$v.Value }
            }
            default { $refusals.Add('This setting cannot be changed here.') }
        }
        foreach ($chk in @($p.Checks)) { if ([string]$chk.Result -in 'Fail', 'NotChecked') { $refusals.Add("$($chk.Check): $($chk.Text)") } }
        if ($p.Risk -eq 'high') {
            $p.Prerequisites = @(Get-IgwtSecSettingPrerequisites -Id $id)
            foreach ($chk in @($p.Prerequisites | Where-Object { [string]$_.Result -eq 'Fail' })) { $refusals.Add("$($chk.Check): $($chk.Text)") }
        }
        if ($refusals.Count) { $p.Status = 'Refused'; $p.Reason = ($refusals.ToArray() -join ' ') }
        elseif ($same) { $p.Status = 'InPlace'; $p.Reason = 'Already set to this value.' }
        elseif ($p.Status -eq 'OneWay') { }
        elseif ($p.Risk -eq 'high' -and -not $AcknowledgeRisk) { $p.Status = 'NeedsConfirmation'; $p.Reason = 'A high-risk change needs your explicit confirmation.' }
        elseif ($managed -and [string]$row.SourceKind -ne 'admx' -and -not $AcknowledgeManaged) { $p.Status = 'NeedsManagedAck'; $p.Reason = 'This PC is managed; confirm that you want to change it locally.' }
        $out.Add([pscustomobject]$p)
    }
    $rowsOut = $out.ToArray()
    $oneWay = @($rowsOut | Where-Object { $_.Status -eq 'OneWay' })
    $active = @($rowsOut | Where-Object { $_.Status -in 'Change', 'NeedsConfirmation', 'NeedsManagedAck', 'OneWay' })
    $mixed = ($oneWay.Count -gt 0 -and $active.Count -gt 1)
    if ($mixed) { foreach ($r in $rowsOut) { if ($r.Status -in 'Change', 'NeedsConfirmation', 'NeedsManagedAck', 'OneWay') { $r.Status = 'Refused'; $r.Reason = 'A change that iG cannot undo is applied on its own; apply it separately.' } } }
    return [pscustomobject]@{
        Rows = $rowsOut; Mixed = $mixed
        CanApply = (@($rowsOut | Where-Object { $_.Status -in 'Change', 'OneWay' }).Count -gt 0 -and -not @($rowsOut | Where-Object { $_.Status -in 'NeedsConfirmation', 'NeedsManagedAck' }).Count)
        Restart = $(if (@($rowsOut | Where-Object { $_.Status -in 'Change', 'NeedsConfirmation' -and $_.Restart -eq 'reboot' }).Count) { 'reboot' } elseif (@($rowsOut | Where-Object { $_.Status -in 'Change', 'NeedsConfirmation' -and $_.Restart -eq 'unknown' }).Count) { 'unknown' } else { 'none' })
    }
}

function Format-IgwtSecSettingPlan {
    <#
    .SYNOPSIS
        The preview text of a security settings plan (DECISIONS SM17-SM19, SM29): each change with
        before and after, its status and reason, prerequisite checks, side effects, and the restart,
        recovery-key, UEFI-lock and one-way notices. Pure.
    .PARAMETER Plan
        Get-IgwtSecSettingChangePlan.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Plan)
    $label = @{ Change = 'Will change'; InPlace = 'Already set'; Refused = 'Not changed'; NeedsConfirmation = 'Needs your confirmation'; NeedsManagedAck = 'Needs your confirmation (managed PC)'; OneWay = 'Cannot be undone by iG' }
    foreach ($r in @($Plan.Rows)) {
        "[$($label[[string]$r.Status])] $($r.Name)"
        "    Before: $(ConvertTo-IgwtSecSettingText $r.Before)"
        if ($r.Status -ne 'Refused') { "    After:  $(ConvertTo-IgwtSecSettingText $r.After)" }
        if ($r.Writer -and $r.Writer -ne 'none') { "    Written by: $($r.Writer)" }
        if ($r.Reason) { "    $($r.Reason)" }
        foreach ($c in @($r.Prerequisites) + @($r.Checks)) { if ($c) { "    Check: $($c.Check) - $($c.Result). $($c.Text)" } }
        foreach ($s in @($r.SideEffects)) { if ($s) { "    Side effect: $($s.text)" } }
        if ($r.Restart -eq 'reboot') { '    Needs a restart to take effect.' } elseif ($r.Restart -eq 'immediate') { '    Takes effect immediately.' } elseif ($r.Restart -eq 'unknown') { '    May need a restart or sign-out.' }
    }
    if ($Plan.Mixed) { 'A change that iG cannot undo is applied on its own: apply it in a separate step.' }
    if (@($Plan.Rows | Where-Object { $_.Status -ne 'Refused' -and $_.Restart -eq 'reboot' }).Count) { 'Restart Windows after applying. Have your BitLocker recovery key ready (aka.ms/myrecoverykey) if the system drive is encrypted.' }
}

#region Journaled apply (SM26-SM28)

function Invoke-IgwtSecSettingSecpolStep {
    <#
    .SYNOPSIS
        Module step wrapper (DECISIONS SM27): Set-IgwtSecurityPolicy for the manager's secpol changes.
        When the writer throws after its backup was recorded, returns @{ Backup; Verified = $false;
        Error } so the step fails with an undo reference and the engine rolls it back.
    .PARAMETER Changes
        Secpol change objects (Section, Key, Value).
    .PARAMETER AcknowledgeManaged
        Passed to the writer.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][object[]]$Changes, [switch]$AcknowledgeManaged)
    Assert-IgwtWritable -Operation 'Invoke-IgwtSecSettingSecpolStep'
    if (-not (Test-IgwtModuleOperationDirect -BoundParameters $PSBoundParameters)) { return (Invoke-IgwtModuleOperation -Command 'Invoke-IgwtSecSettingSecpolStep' -Parameters $PSBoundParameters) }
    if (-not $PSCmdlet.ShouldProcess("$(@($Changes).Count) security option(s)", 'Change')) { return }
    try { return (Set-IgwtSecurityPolicy -Changes $Changes -AcknowledgeManaged:$AcknowledgeManaged -Confirm:$false) }
    catch { $ref = $(if ($script:IgwtModuleStep) { [string]$script:IgwtModuleStep.Ref } else { '' }); if ($ref) { return [pscustomobject]@{ Backup = $ref; Verified = $false; Error = $_.Exception.Message } }; throw }
}

function Invoke-IgwtSecSettingAuditStep {
    <#
    .SYNOPSIS
        Module step wrapper (DECISIONS SM27): Set-IgwtAuditPolicy for the manager's audit changes,
        with the same undo reference handling as the secpol wrapper.
    .PARAMETER Changes
        Subcategory GUID -> None, Success, Failure or SuccessAndFailure.
    .PARAMETER AcknowledgeManaged
        Passed to the writer.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Changes, [switch]$AcknowledgeManaged)
    Assert-IgwtWritable -Operation 'Invoke-IgwtSecSettingAuditStep'
    if (-not (Test-IgwtModuleOperationDirect -BoundParameters $PSBoundParameters)) { return (Invoke-IgwtModuleOperation -Command 'Invoke-IgwtSecSettingAuditStep' -Parameters $PSBoundParameters) }
    if (-not $PSCmdlet.ShouldProcess("$($Changes.Count) audit subcategor(ies)", 'Change')) { return }
    try { return (Set-IgwtAuditPolicy -Changes $Changes -AcknowledgeManaged:$AcknowledgeManaged -Confirm:$false) }
    catch { $ref = $(if ($script:IgwtModuleStep) { [string]$script:IgwtModuleStep.Ref } else { '' }); if ($ref) { return [pscustomobject]@{ Backup = $ref; Verified = $false; Error = $_.Exception.Message } }; throw }
}

function Invoke-IgwtSecSettingAsrChange {
    <#
    .SYNOPSIS
        Module step wrapper (DECISIONS SM24, SM27): Invoke-IgwtAsrChange, then a read of the rule modes
        inside the same step; a rule that does not read back is reported NotApplied, so the step fails
        and its snapshot is restored.
    .PARAMETER RuleMode
        Rule GUID -> Block, Audit or Warn.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$RuleMode)
    Assert-IgwtWritable -Operation 'Invoke-IgwtSecSettingAsrChange'
    if (-not (Test-IgwtModuleOperationDirect -BoundParameters $PSBoundParameters)) { return (Invoke-IgwtModuleOperation -Command 'Invoke-IgwtSecSettingAsrChange' -Parameters $PSBoundParameters) }
    if (-not $PSCmdlet.ShouldProcess("$($RuleMode.Count) ASR rule(s)", 'Change')) { return }
    $res = $null
    try { $res = Invoke-IgwtAsrChange -RuleMode $RuleMode -Confirm:$false }
    catch { $ref = $(if ($script:IgwtModuleStep) { [string]$script:IgwtModuleStep.Ref } else { '' }); if ($ref) { return [pscustomobject]@{ Snapshot = $ref; Verified = $false; Error = $_.Exception.Message } }; throw }
    $now = @{}
    try { foreach ($r in @((Get-IgwtAsrStatus).Rules)) { if ($r) { $now[([string]$r.Id).ToLowerInvariant()] = [string]$r.Mode } } } catch { $now = $null }
    $checks = @(foreach ($k in @($RuleMode.Keys)) {
            $mode = $(if ($null -ne $now -and $now.ContainsKey(([string]$k).ToLowerInvariant())) { $now[([string]$k).ToLowerInvariant()] } else { $null })
            $ok = ($null -ne $mode -and $mode -eq [string]$RuleMode[$k])
            [pscustomobject]@{ Target = [string]$k; Result = $(if ($ok) { 'Applied' } else { 'NotApplied' }); Message = $(if ($ok) { '' } else { "Defender reports '$mode' instead of '$($RuleMode[$k])'." }) }
        })
    return [pscustomobject]@{ Snapshot = $(if ($res) { $res.Snapshot } else { $null }); Changes = $(if ($res) { $res.Changes } else { 0 }); Results = $checks }
}

$script:IgwtModuleOperations['Invoke-IgwtSecSettingSecpolStep'] = 'secpol'
$script:IgwtModuleOperations['Invoke-IgwtSecSettingAuditStep'] = 'audit'
$script:IgwtModuleOperations['Invoke-IgwtSecSettingAsrChange'] = 'snapshot'

function Invoke-IgwtSecSettingChange {
    <#
    .SYNOPSIS
        Applies security setting changes as one journaled session (DECISIONS SM26): the plan is made
        again under the lock, refused, unconfirmed and unacknowledged rows stop the whole apply, and
        the steps run in order (local policy, Defender, ASR, exclusions, one secpol step, one audit
        step). The first failed step rolls back the committed ones. Then one Group Policy refresh per
        touched class and the pending-restart record for reboot-class changes. Returns @{ SessionId;
        Results; Refresh; Restart }.
    .PARAMETER Changes
        @{ Id; Value } per change.
    .PARAMETER AcknowledgeRisk
        Confirms high-risk changes.
    .PARAMETER AcknowledgeManaged
        Confirms changes on a managed PC.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][object[]]$Changes, [switch]$AcknowledgeRisk, [switch]$AcknowledgeManaged)
    Assert-IgwtWritable -Operation 'Invoke-IgwtSecSettingChange'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { throw 'Refused: run iG in 64-bit PowerShell; a 32-bit process would write local policy where Windows ignores it.' }
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Changing security settings needs administrator rights.' }
    if (-not $PSCmdlet.ShouldProcess("$(@($Changes).Count) security setting(s)", 'Change')) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'secSettings' }) -Title "Security settings: $(@($Changes).Count) change(s)" -Confirm:$false
    $results = New-Object System.Collections.Generic.List[object]
    $classes = New-Object System.Collections.Generic.List[string]
    $restart = New-Object System.Collections.Generic.List[string]
    $refresh = @()
    $group = 'secsettings'
    try {
        $plan = Get-IgwtSecSettingChangePlan -Changes $Changes -AcknowledgeRisk:$AcknowledgeRisk -AcknowledgeManaged:$AcknowledgeManaged
        $stop = @($plan.Rows | Where-Object { $_.Status -in 'Refused', 'NeedsConfirmation', 'NeedsManagedAck' })
        if ($stop.Count -or $plan.Mixed) { throw "Refused, nothing changed: $(@($stop | ForEach-Object { "$($_.Name): $($_.Reason)" }) -join ' ')" }
        $todo = @($plan.Rows | Where-Object { $_.Status -in 'Change', 'OneWay' })
        foreach ($r in @($plan.Rows | Where-Object { $_.Status -eq 'InPlace' })) { $results.Add([pscustomobject]@{ Id = $r.Id; Name = $r.Name; Result = 'InPlace'; Message = $r.Reason }) }
        $failed = $null
        $ok = { param($row, $step) if ($step -and [string]$step.Result -eq 'Committed') { $results.Add([pscustomobject]@{ Id = $row.Id; Name = $row.Name; Result = 'Committed'; Message = '' }); if ($row.Restart -eq 'reboot') { $restart.Add($row.Id) }; return $true }; $results.Add([pscustomobject]@{ Id = $row.Id; Name = $row.Name; Result = 'Failed'; Message = $(if ($step) { [string]$step.Message } else { 'The step did not run.' }) }); return $false }
        # 1. Local policy, one step per policy and class.
        $policies = @{}
        foreach ($row in @($todo | Where-Object { $_.Writer -eq 'localPolicy' })) {
            if (-not $policies.Count) { foreach ($x in @((Get-IgwtAdmxCatalog).Policies)) { if ($x) { $policies[[string]$x.Id] = $x } } }
            $pd = $policies[[string]$row.PolicyId]
            $target = New-IgwtSecSettingPolTarget -Policy $pd -Class $row.Class
            $res = Resolve-IgwtSecSettingPolTarget -Target $target
            $cur = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $row.Class)).Entries)
            $desired = ConvertTo-IgwtSecSettingPolDesired -Resolved $res -CurrentEntries $cur -Ops @($row.Ops)
            $step = Invoke-IgwtChangeStep -Session $session -Target $target -Desired $desired -Group $group -Confirm:$false
            if (-not (& $ok $row $step)) { $failed = $row; break }
            $classes.Add([string]$row.Class)
        }
        # 2. Defender preferences, one step.
        $def = @($todo | Where-Object { $_.Writer -eq 'defender' })
        if (-not $failed -and $def.Count) {
            $setting = [ordered]@{}; foreach ($row in $def) { foreach ($k in $row.Input.Setting.Keys) { $setting[$k] = $row.Input.Setting[$k] } }
            $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Invoke-IgwtDefenderSettingChange' -Parameters @{ Setting = $setting; AcknowledgeManaged = [bool]$AcknowledgeManaged; Confirm = $false } -Group $group
            foreach ($row in $def) { if (-not (& $ok $row $s.Step)) { $failed = $row } }
        }
        # 3. ASR rules, one step.
        $asr = @($todo | Where-Object { $_.Writer -eq 'asr' })
        if (-not $failed -and $asr.Count) {
            $modes = @{}; foreach ($row in $asr) { $modes[[string]$row.Input.Id] = [string]$row.Input.Mode }
            $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Invoke-IgwtSecSettingAsrChange' -Parameters @{ RuleMode = $modes; Confirm = $false } -Group $group
            foreach ($row in $asr) { if (-not (& $ok $row $s.Step)) { $failed = $row } }
        }
        # 4. Exclusion removal (one-way, always alone).
        foreach ($row in @($todo | Where-Object { $_.Writer -eq 'exclusion' })) {
            foreach ($value in @($row.Input.Values)) {
                $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Remove-IgwtDefenderExclusion' -Parameters @{ Kind = [string]$row.Input.Kind; Value = [string]$value; Confirm = $false } -Group $group -Detail "$($row.Input.Kind)|$value"
                if (-not $s.Step -or [string]$s.Step.Result -ne 'Committed') { $failed = $row; break }
            }
            if ($failed) { $results.Add([pscustomobject]@{ Id = $row.Id; Name = $row.Name; Result = 'Failed'; Message = 'An exclusion could not be removed.' }) } else { $results.Add([pscustomobject]@{ Id = $row.Id; Name = $row.Name; Result = 'Committed'; Message = 'One-way: re-add by hand in Windows Security if needed.' }) }
        }
        # 5. Security options, one step.
        $sec = @($todo | Where-Object { $_.Writer -eq 'secpol' })
        if (-not $failed -and $sec.Count) {
            $objs = @($sec | ForEach-Object { $_.Input })
            $detail = (@($objs | ForEach-Object { "$($_.Section)\$($_.Key)=$($_.Value)" } | Sort-Object) -join "`n")
            $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Invoke-IgwtSecSettingSecpolStep' -Parameters @{ Changes = $objs; AcknowledgeManaged = [bool]$AcknowledgeManaged; Confirm = $false } -Group $group -Detail $detail
            foreach ($row in $sec) { if (-not (& $ok $row $s.Step)) { $failed = $row } }
        }
        # 6. Audit, one step.
        $aud = @($todo | Where-Object { $_.Writer -eq 'audit' })
        if (-not $failed -and $aud.Count) {
            $chg = @{}; foreach ($row in $aud) { $chg[[string]$row.Input.Guid] = [string]$row.Input.Setting }
            $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Invoke-IgwtSecSettingAuditStep' -Parameters @{ Changes = $chg; AcknowledgeManaged = [bool]$AcknowledgeManaged; Confirm = $false } -Group $group
            foreach ($row in $aud) { if (-not (& $ok $row $s.Step)) { $failed = $row } }
        }
        if ($failed) {
            $null = Undo-IgwtChangeGroup -Session $session -Group $group
            foreach ($x in $results) { if ($x.Result -eq 'Committed') { $x.Result = 'RolledBack'; $x.Message = "Rolled back because '$($failed.Name)' failed." } }
            $restart.Clear()
        } elseif ($classes.Count) {
            $refresh = @(Invoke-IgwtSecSettingRefresh -Classes @($classes | Select-Object -Unique) -Confirm:$false)
        }
        if ($restart.Count) { try { Set-IgwtPendingRestartState -Requires reboot -TweakId @($restart) -Confirm:$false } catch { Write-IgwtLog -Level Warn -Message "Pending restart not recorded: $($_.Exception.Message)" } }
    } finally {
        Complete-IgwtChangeSession -Session $session
    }
    Write-IgwtLog -Message "Security settings: $(@($results | Group-Object Result | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ') (session $($session.Id))."
    return [pscustomobject]@{ SessionId = $session.Id; Results = $results.ToArray(); Refresh = $refresh; Restart = $(if ($restart.Count) { 'reboot' } else { 'none' }) }
}

#endregion