# CleanerRule.ps1
# 'cleanerRule' action: runs one cleaner rule (scan, then clean only what the scan found) as part
# of a tweak or preset. State is On when the rule has nothing to clean. Deleted files cannot be
# restored, so items using this action must declare reversible 'none' and their side effects.

function Get-IgwtCleanerRuleScan {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RuleId)
    return (Get-IgwtCached -Key "clean:$RuleId" -ScriptBlock { (Invoke-IgwtCleanerScan -RuleId $RuleId).Rules[0] })
}

function Get-IgwtCleanerRuleActionState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $rid = [string]$Action.rule
    $label = "Cleaner rule $rid"
    try { $r = Get-IgwtCleanerRuleScan -RuleId $rid } catch { return [pscustomobject]@{ Target = $label; Current = 'error'; Desired = 'nothing to clean'; State = 'Unknown'; Note = $_.Exception.Message } }
    $current = "$(Format-IgwtBytes $r.Bytes) in $($r.Count) item(s)"
    $state = switch ([string]$r.Status) {
        'Empty' { 'On' } 'NotPresent' { 'On' } 'Ready' { 'Off' } 'Refused' { 'NotApplicable' } 'GuidanceOnly' { 'NotApplicable' } default { 'Unknown' }
    }
    [pscustomobject]@{ Target = "$label ($($r.Name))"; Current = $current; Desired = 'nothing to clean'; State = $state; Note = [string]$r.Reason }
}

function Get-IgwtCleanerRuleActionSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    return @{ rule = [string]$Action.rule; note = 'Deleted files cannot be restored.' }
}

function Invoke-IgwtCleanerRuleActionApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    if ($Mode -eq 'default') { return }
    if (-not $PSCmdlet.ShouldProcess([string]$Action.rule, 'Scan and clean')) { return }
    $scan = Invoke-IgwtCleanerScan -RuleId ([string]$Action.rule)
    $r = Invoke-IgwtCleanerClean -Scan $scan -RuleId ([string]$Action.rule)
    Clear-IgwtCache -Prefix "clean:$($Action.rule)" -WhatIf:$false
    $res = @($r.Rules) | Select-Object -First 1
    if ($res -and $res.Status -eq 'Error') { throw "Cleaner rule $($Action.rule) failed: $($res.Reason)" }
}

function Restore-IgwtCleanerRuleActionSnapshot {
    <# .SYNOPSIS Nothing to restore: deleted files are gone. Logs a warning so the revert result says so. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    Write-IgwtLog -Level Warn -Message "Cleaner rule $($Action.rule): deleted files cannot be restored (nothing to revert)."
}
