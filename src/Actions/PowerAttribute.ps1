# PowerAttribute.ps1
# 'powercfgAttribute' action: shows or hides a power setting in Power Options with
# 'powercfg -attributes <subgroup> <setting> -ATTRIB_HIDE / +ATTRIB_HIDE'. Visibility is read from
# the setting's Attributes value (bit 1 = hidden); revert writes that exact value back.

function Get-IgwtPowerAttributePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Action)
    return "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$($Action.subgroup)\$($Action.setting)"
}

function Get-IgwtPowerAttributeVisible {
    <# .SYNOPSIS $true visible, $false hidden, $null when the setting does not exist on this PC. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action)
    $path = Get-IgwtPowerAttributePath -Action $Action
    if (-not (Test-IgwtRegistryKey -Path $path)) { return $null }
    $v = Get-IgwtRegistryValue -Path $path -Name 'Attributes'
    if (-not $v.Exists) { return $true }
    return ((([long]$v.Value) -band 1) -eq 0)
}

function Get-IgwtPowerAttributeState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $label = "Power setting visibility: $($Action.label)"
    $vis = Get-IgwtPowerAttributeVisible -Action $Action
    if ($null -eq $vis) { return [pscustomobject]@{ Target = $label; Current = 'not present'; Desired = ''; State = 'NotApplicable'; Note = 'This power setting does not exist on this PC.' } }
    $want = [bool]$Action.visible
    [pscustomobject]@{
        Target  = $label
        Current = $(if ($vis) { 'shown in Power Options' } else { 'hidden' })
        Desired = $(if ($want) { 'shown in Power Options' } else { 'hidden' })
        State   = $(if ($vis -eq $want) { 'On' } else { 'Off' })
        Note    = ''
    }
}

function Get-IgwtPowerAttributeSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $path = Get-IgwtPowerAttributePath -Action $Action
    $cur = Get-IgwtRegistryValue -Path $path -Name 'Attributes'
    return @{ item = [ordered]@{ exists = [bool]$cur.Exists; kind = $cur.Kind; value = (ConvertTo-IgwtSerializableValue -Value $cur.Value -Kind $cur.Kind); missingDepth = 0 } }
}

function Set-IgwtPowerAttributeVisible {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)][bool]$Visible)
    $flag = '+ATTRIB_HIDE'
    if ($Visible) { $flag = '-ATTRIB_HIDE' }
    if (-not $PSCmdlet.ShouldProcess("$($Action.subgroup) $($Action.setting)", "powercfg -attributes $flag")) { return }
    $r = Invoke-IgwtPowerCfg -Arguments @('-attributes', [string]$Action.subgroup, [string]$Action.setting, $flag)
    if ($r.ExitCode -ne 0) { throw "powercfg -attributes failed: $($r.Output)" }
}

function Invoke-IgwtPowerAttributeApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $vis = Get-IgwtPowerAttributeVisible -Action $Action
    if ($null -eq $vis) { return }
    $want = [bool]$Action.visible
    if ($Mode -eq 'default') { $want = ([string]$Action.default -eq 'visible') }
    if ($vis -ne $want) { Set-IgwtPowerAttributeVisible -Action $Action -Visible $want }
}

function Restore-IgwtPowerAttributeSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if (-not (Test-IgwtRegistryKey -Path (Get-IgwtPowerAttributePath -Action $Action))) { return }
    if ($PSCmdlet.ShouldProcess($Action.label, 'Restore power setting visibility')) {
        Restore-IgwtRegistryItem -Path (Get-IgwtPowerAttributePath -Action $Action) -Name 'Attributes' -Item $Snapshot.item
    }
}
