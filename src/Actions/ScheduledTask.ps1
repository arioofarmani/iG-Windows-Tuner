# ScheduledTask.ps1
# 'scheduledTask' action: enables or disables an EXISTING scheduled task. iG Windows Tuner never creates,
# imports or deletes tasks (no persistence), and security, update and recovery tasks are refused.

$script:IgwtProtectedTaskPaths = @(
    '\Microsoft\Windows\Windows Defender\', '\Microsoft\Windows\UpdateOrchestrator\', '\Microsoft\Windows\WindowsUpdate\',
    '\Microsoft\Windows\WaaSMedic\', '\Microsoft\Windows\TPM\', '\Microsoft\Windows\BitLocker\', '\Microsoft\Windows\SystemRestore\',
    '\Microsoft\Windows\Time Synchronization\', '\Microsoft\Windows\AppID\', '\Microsoft\Windows\ExploitGuard\', '\Microsoft\Windows\Plug and Play\'
)

function Assert-IgwtTaskAllowed {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    foreach ($p in $script:IgwtProtectedTaskPaths) {
        if ($Path.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Scheduled tasks under '$p' are protected (security, update or recovery) and are never disabled by iG Windows Tuner." }
    }
}

function Get-IgwtTaskEnabled {
    <# .SYNOPSIS $true enabled, $false disabled, $null when the task does not exist. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action)
    $t = Get-ScheduledTask -TaskPath ([string]$Action.path) -TaskName ([string]$Action.name) -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $t) { return $null }
    return ([string]$t.State -ne 'Disabled')
}

function Get-IgwtScheduledTaskState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $label = "Scheduled task $($Action.path)$($Action.name)"
    $en = Get-IgwtTaskEnabled -Action $Action
    if ($null -eq $en) { return [pscustomobject]@{ Target = $label; Current = 'not present'; Desired = [string]$Action.on; State = 'NotApplicable'; Note = 'This task does not exist on this PC.' } }
    $cur = $(if ($en) { 'Enabled' } else { 'Disabled' })
    [pscustomobject]@{ Target = $label; Current = $cur; Desired = [string]$Action.on; State = $(if ($cur -eq [string]$Action.on) { 'On' } else { 'Off' }); Note = '' }
}

function Get-IgwtScheduledTaskSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $en = Get-IgwtTaskEnabled -Action $Action
    return @{ exists = ($null -ne $en); enabled = [bool]$en }
}

function Set-IgwtTaskEnabled {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)][bool]$Enabled)
    if (-not $Enabled) { Assert-IgwtTaskAllowed -Path ([string]$Action.path) }
    $what = $(if ($Enabled) { 'Enable' } else { 'Disable' })
    if (-not $PSCmdlet.ShouldProcess("$($Action.path)$($Action.name)", "$what scheduled task")) { return }
    if ($Enabled) { $null = Enable-ScheduledTask -TaskPath ([string]$Action.path) -TaskName ([string]$Action.name) -ErrorAction Stop }
    else { $null = Disable-ScheduledTask -TaskPath ([string]$Action.path) -TaskName ([string]$Action.name) -ErrorAction Stop }
}

function Invoke-IgwtScheduledTaskApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $en = Get-IgwtTaskEnabled -Action $Action
    if ($null -eq $en) { return }
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    $want = ($target -eq 'Enabled')
    if ($en -ne $want) { Set-IgwtTaskEnabled -Action $Action -Enabled $want }
}

function Restore-IgwtScheduledTaskSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if (-not $Snapshot.exists) { return }
    $en = Get-IgwtTaskEnabled -Action $Action
    if ($null -eq $en) { Write-IgwtLog -Level Warn -Message "Scheduled task $($Action.path)$($Action.name) no longer exists; not restored."; return }
    if ($en -ne [bool]$Snapshot.enabled) { Set-IgwtTaskEnabled -Action $Action -Enabled ([bool]$Snapshot.enabled) }
}
