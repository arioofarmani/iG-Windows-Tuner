# Firewall.ps1
# 'firewallRule' action, two forms (both only reduce network exposure):
#   - an iGWindowsTuner-owned BLOCK rule (rule name 'iGWindowsTuner-...'): created on apply, removed on revert
#     when it did not exist before
#   - an existing rule group (displayGroup, optional direction): its rules are disabled; revert
#     restores each rule's exact enabled state
# The Windows Firewall service and profiles are never touched here (see the FirewallProfiles handler).

function Test-IgwtOwnedFirewallAction {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Action)
    return ($null -ne $Action.PSObject.Properties['rule'] -and [string]$Action.rule)
}

function Get-IgwtFirewallGroupRules {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action)
    $rules = @(Get-NetFirewallRule -DisplayGroup ([string]$Action.displayGroup) -ErrorAction SilentlyContinue)
    if ($Action.direction) { $rules = @($rules | Where-Object { [string]$_.Direction -eq [string]$Action.direction }) }
    return $rules
}

function Get-IgwtFirewallRuleState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    if (Test-IgwtOwnedFirewallAction -Action $Action) {
        $r = Get-NetFirewallRule -Name ([string]$Action.rule) -ErrorAction SilentlyContinue | Select-Object -First 1
        $label = "Firewall rule $($Action.rule) ($($Action.direction) $($Action.action))"
        if (-not $r) { return [pscustomobject]@{ Target = $label; Current = 'not present'; Desired = 'present and enabled'; State = 'Off'; Note = '' } }
        $ok = ([string]$r.Enabled -eq 'True' -and [string]$r.Action -eq [string]$Action.action -and [string]$r.Direction -eq [string]$Action.direction)
        return [pscustomobject]@{ Target = $label; Current = "present, enabled $($r.Enabled), $($r.Direction) $($r.Action)"; Desired = 'present and enabled'; State = $(if ($ok) { 'On' } else { 'Off' }); Note = '' }
    }
    $rules = @(Get-IgwtFirewallGroupRules -Action $Action)
    $label = "Firewall rule group '$($Action.displayGroup)'$(if ($Action.direction) { " ($($Action.direction))" })"
    if ($rules.Count -eq 0) { return [pscustomobject]@{ Target = $label; Current = 'no rules'; Desired = 'disabled'; State = 'NotApplicable'; Note = 'This rule group does not exist on this PC.' } }
    $enabled = @($rules | Where-Object { [string]$_.Enabled -eq 'True' }).Count
    [pscustomobject]@{ Target = $label; Current = "$enabled of $($rules.Count) rule(s) enabled"; Desired = 'all disabled'; State = $(if ($enabled -eq 0) { 'On' } else { 'Off' }); Note = '' }
}

function Get-IgwtFirewallRuleSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    if (Test-IgwtOwnedFirewallAction -Action $Action) {
        $r = Get-NetFirewallRule -Name ([string]$Action.rule) -ErrorAction SilentlyContinue | Select-Object -First 1
        return @{ existed = [bool]$r; enabled = $(if ($r) { [string]$r.Enabled -eq 'True' } else { $false }) }
    }
    return @{ rules = @(Get-IgwtFirewallGroupRules -Action $Action | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } }) }
}

function Invoke-IgwtFirewallRuleApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    if (Test-IgwtOwnedFirewallAction -Action $Action) {
        $name = [string]$Action.rule
        if (-not $name.StartsWith('iGWindowsTuner-')) { throw "iG Windows Tuner only manages its own firewall rules (names starting with 'iGWindowsTuner-')." }
        $r = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($Mode -eq 'default') {
            if ($r -and $PSCmdlet.ShouldProcess($name, 'Remove iG Windows Tuner firewall rule')) { Remove-NetFirewallRule -Name $name -ErrorAction Stop }
            return
        }
        if ([string]$Action.action -ne 'Block') { throw 'iG Windows Tuner only creates Block rules.' }
        if ($r) {
            if ($PSCmdlet.ShouldProcess($name, 'Enable firewall rule')) { Set-NetFirewallRule -Name $name -Enabled True -Action Block -Direction ([string]$Action.direction) -ErrorAction Stop }
            return
        }
        if (-not $PSCmdlet.ShouldProcess($name, 'Create firewall block rule')) { return }
        $p = @{ Name = $name; DisplayName = [string]$Action.displayName; Group = 'iG Windows Tuner'; Direction = [string]$Action.direction; Action = 'Block'; Enabled = 'True'; ErrorAction = 'Stop' }
        $map = [ordered]@{ protocol = 'Protocol'; localPort = 'LocalPort'; remotePort = 'RemotePort'; program = 'Program'; profile = 'Profile' }
        foreach ($k in $map.Keys) {
            if ($null -ne $Action.PSObject.Properties[$k] -and $null -ne $Action.$k -and [string]$Action.$k) { $p[$map[$k]] = $Action.$k }
        }
        $null = New-NetFirewallRule @p
        return
    }
    $rules = @(Get-IgwtFirewallGroupRules -Action $Action)
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    $names = @($rules | Where-Object { ([string]$_.Enabled -eq 'True') -ne ($target -eq 'Enabled') } | ForEach-Object { [string]$_.Name })
    if ($names.Count -eq 0) { return }
    if (-not $PSCmdlet.ShouldProcess("$($names.Count) rule(s) in '$($Action.displayGroup)'", "Set $target")) { return }
    if ($target -eq 'Enabled') { Enable-NetFirewallRule -Name $names -ErrorAction Stop } else { Disable-NetFirewallRule -Name $names -ErrorAction Stop }
}

function Restore-IgwtFirewallRuleSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if (Test-IgwtOwnedFirewallAction -Action $Action) {
        $name = [string]$Action.rule
        $r = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $Snapshot.existed) {
            if ($r -and $PSCmdlet.ShouldProcess($name, 'Remove firewall rule created by iG Windows Tuner')) { Remove-NetFirewallRule -Name $name -ErrorAction Stop }
            return
        }
        if ($r -and $PSCmdlet.ShouldProcess($name, 'Restore enabled state')) { Set-NetFirewallRule -Name $name -Enabled $(if ($Snapshot.enabled) { 'True' } else { 'False' }) -ErrorAction Stop }
        return
    }
    $current = @{}
    foreach ($r in @(Get-IgwtFirewallGroupRules -Action $Action)) { $current[[string]$r.Name] = $r }
    $enable = @(); $disable = @()
    foreach ($s in @($Snapshot.rules | Where-Object { $_ })) {
        if (-not $current.ContainsKey([string]$s.name)) { continue }
        $isOn = ([string]$current[[string]$s.name].Enabled -eq 'True')
        if ([bool]$s.enabled -and -not $isOn) { $enable += [string]$s.name } elseif (-not [bool]$s.enabled -and $isOn) { $disable += [string]$s.name }
    }
    if ($enable.Count -and $PSCmdlet.ShouldProcess("$($enable.Count) rule(s)", 'Re-enable')) { Enable-NetFirewallRule -Name $enable -ErrorAction Stop }
    if ($disable.Count -and $PSCmdlet.ShouldProcess("$($disable.Count) rule(s)", 'Disable')) { Disable-NetFirewallRule -Name $disable -ErrorAction Stop }
}
