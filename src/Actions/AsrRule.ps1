# AsrRule.ps1
# 'asrRule' action: Microsoft Defender attack surface reduction rules by GUID
# (Add-MpPreference / Remove-MpPreference). Revert puts back the previous action or removes the
# rule when it was not configured before.

$script:IgwtAsrActionCodes = @{ Disabled = 0; Block = 1; Audit = 2; Warn = 6 }
$script:IgwtAsrActionNames = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }

function Get-IgwtAsrRuleAction {
    <# .SYNOPSIS Current action code of one rule, or $null when not configured. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RuleId)
    $pref = Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }
    $ids = @($pref.AttackSurfaceReductionRules_Ids)
    $acts = @($pref.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ([string]::Equals([string]$ids[$i], $RuleId, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($i -lt $acts.Count) { return [int]$acts[$i] }
            return $null
        }
    }
    return $null
}

function Format-IgwtAsrAction {
    [CmdletBinding()]
    param($Code)
    if ($null -eq $Code) { return 'Not configured' }
    switch ([int]$Code) { 0 { 'Disabled' } 1 { 'Block' } 2 { 'Audit' } 6 { 'Warn' } default { "Code $Code" } }
}

function Get-IgwtAsrRuleState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $id = [string]$Action.id
    if (-not (Test-IgwtDefenderActive)) {
        return [pscustomobject]@{ Target = "ASR $($Action.label)"; Current = 'Defender not active'; Desired = [string]$Action.on; State = 'NotApplicable'; Note = '' }
    }
    try { $cur = Get-IgwtAsrRuleAction -RuleId $id } catch {
        return [pscustomobject]@{ Target = "ASR $($Action.label)"; Current = 'unreadable'; Desired = [string]$Action.on; State = 'Unknown'; Note = $_.Exception.Message }
    }
    $want = $script:IgwtAsrActionCodes[[string]$Action.on]
    $isOn = ($null -ne $cur -and $cur -eq $want)
    # Audit is satisfied by Block (stronger); a preset never weakens an existing Block rule.
    if (-not $isOn -and [string]$Action.on -eq 'Audit' -and $cur -eq 1) { $isOn = $true }
    [pscustomobject]@{
        Target  = "ASR $($Action.label) ($id)"
        Current = (Format-IgwtAsrAction $cur)
        Desired = [string]$Action.on
        State   = $(if ($isOn) { 'On' } else { 'Off' })
        Note    = ''
    }
}

function Get-IgwtAsrRuleSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $cur = Get-IgwtAsrRuleAction -RuleId ([string]$Action.id)
    return @{ id = [string]$Action.id; configured = ($null -ne $cur); action = $cur }
}

function Set-IgwtAsrRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$RuleId, [Parameter(Mandatory = $true)][int]$Code)
    $name = $script:IgwtAsrActionNames[$Code]
    if (-not $name) { throw "Unsupported ASR action code $Code." }
    if ($PSCmdlet.ShouldProcess("ASR rule $RuleId", "Set $name")) {
        try { Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleId -AttackSurfaceReductionRules_Actions $name -ErrorAction Stop } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
    }
}

function Invoke-IgwtAsrRuleApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $id = [string]$Action.id
    if ($Mode -eq 'default') {
        if ($null -ne (Get-IgwtAsrRuleAction -RuleId $id) -and $PSCmdlet.ShouldProcess("ASR rule $id", 'Remove (not configured is the Windows default)')) {
            try { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction Stop } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
        }
        return
    }
    $want = $script:IgwtAsrActionCodes[[string]$Action.on]
    $cur = Get-IgwtAsrRuleAction -RuleId $id
    if ($cur -eq $want) { return }
    if ([string]$Action.on -eq 'Audit' -and $cur -eq 1) { return }
    Set-IgwtAsrRule -RuleId $id -Code $want
}

function Restore-IgwtAsrRuleSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $id = [string]$Action.id
    if (-not $Snapshot.configured) {
        if ($null -ne (Get-IgwtAsrRuleAction -RuleId $id) -and $PSCmdlet.ShouldProcess("ASR rule $id", 'Remove (was not configured)')) {
            try { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction Stop } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
        }
        return
    }
    Set-IgwtAsrRule -RuleId $id -Code ([int]$Snapshot.action)
}
