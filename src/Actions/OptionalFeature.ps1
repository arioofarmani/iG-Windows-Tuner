# OptionalFeature.ps1
# 'optionalFeature' action: enable/disable a Windows optional feature (for example SMB1Protocol).
# Features are only disabled or re-enabled, never removed from the image (no DISM payload removal).

function Get-IgwtOptionalFeatureStateValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Feature)
    $f = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction Stop
    if (-not $f) { return $null }
    return [string]$f.State
}

function Get-IgwtOptionalFeatureState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $feature = [string]$Action.feature
    $isAdmin = $true
    if ($Context -and $null -ne $Context.IsAdmin) { $isAdmin = [bool]$Context.IsAdmin }
    if (-not $isAdmin) {
        return [pscustomobject]@{ Target = "Optional feature $feature"; Current = 'requires administrator to read'; Desired = [string]$Action.on; State = 'Unknown'; Note = '' }
    }
    try { $state = Get-IgwtOptionalFeatureStateValue -Feature $feature } catch {
        return [pscustomobject]@{ Target = "Optional feature $feature"; Current = 'unreadable'; Desired = [string]$Action.on; State = 'Unknown'; Note = $_.Exception.Message }
    }
    if (-not $state) {
        return [pscustomobject]@{ Target = "Optional feature $feature"; Current = 'not present'; Desired = [string]$Action.on; State = 'NotApplicable'; Note = '' }
    }
    $isOn = $state -like "$($Action.on)*"
    [pscustomobject]@{ Target = "Optional feature $feature"; Current = $state; Desired = [string]$Action.on; State = $(if ($isOn) { 'On' } else { 'Off' }); Note = '' }
}

function Get-IgwtOptionalFeatureSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    return @{ feature = [string]$Action.feature; state = (Get-IgwtOptionalFeatureStateValue -Feature ([string]$Action.feature)) }
}

function Set-IgwtOptionalFeature {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Feature, [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled')][string]$State)
    if (-not $PSCmdlet.ShouldProcess($Feature, "Set optional feature $State (no restart)")) { return }
    if ($State -eq 'Disabled') { $null = Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction Stop }
    else { $null = Enable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction Stop }
}

function Invoke-IgwtOptionalFeatureApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    $cur = Get-IgwtOptionalFeatureStateValue -Feature ([string]$Action.feature)
    if (-not $cur -or $cur -like "$target*") { return }
    Set-IgwtOptionalFeature -Feature ([string]$Action.feature) -State $target
}

function Restore-IgwtOptionalFeatureSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $prev = [string]$Snapshot.state
    if (-not $prev) { return }
    $target = 'Disabled'
    if ($prev -like 'Enable*') { $target = 'Enabled' }
    $cur = Get-IgwtOptionalFeatureStateValue -Feature ([string]$Action.feature)
    if ($cur -like "$target*") { return }
    Set-IgwtOptionalFeature -Feature ([string]$Action.feature) -State $target
}
