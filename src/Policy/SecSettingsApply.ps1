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
