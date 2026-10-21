# NetQos.ps1
# 'netQosPolicy' action: policy-based QoS that marks a game's UDP traffic with a DSCP value
# (46 = Expedited Forwarding). It only helps when the router honors DSCP. Policies are named
# "iGWindowsTuner-<game>" so they are easy to find in Get-NetQosPolicy and are never confused with
# policies created by other tools. Policies created by pre-release
# preview builds are named "AegisTune-<game>"; they are detected, updated and removed under that name.

function Get-IgwtQosTargets {
    <# .SYNOPSIS One policy per game executable flagged "qos": true in data\games.json. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action)
    $prefix = 'iGWindowsTuner-'
    if ($Action.namePrefix) { $prefix = [string]$Action.namePrefix }
    $legacyPrefix = 'AegisTune-'
    $games = @((Get-IgwtGameDefinitions) | Where-Object { $_.qos })
    foreach ($g in $games) {
        $i = 0
        foreach ($exe in @($g.exe)) {
            $suffix = ''
            if ($i -gt 0) { $suffix = "-$i" }
            [pscustomobject]@{ Name = "$prefix$($g.id)$suffix"; LegacyName = $(if ($prefix -ne $legacyPrefix) { "$legacyPrefix$($g.id)$suffix" } else { '' }); Exe = [string]$exe; Game = [string]$g.name }
            $i++
        }
    }
}

function Get-IgwtQosPolicyByName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    try { return (Get-NetQosPolicy -Name $Name -ErrorAction Stop | Select-Object -First 1) } catch { return $null }
}

function Get-IgwtQosTargetPolicy {
    <# .SYNOPSIS The policy for a target under its current name, else under its pre-release preview-build name. Returns Name and Policy. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target)
    $p = Get-IgwtQosPolicyByName -Name $Target.Name
    if (-not $p -and $Target.LegacyName) {
        $old = Get-IgwtQosPolicyByName -Name $Target.LegacyName
        if ($old) { return [pscustomobject]@{ Name = [string]$Target.LegacyName; Policy = $old } }
    }
    return [pscustomobject]@{ Name = [string]$Target.Name; Policy = $p }
}

function Get-IgwtNetQosState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $dscp = [int]$Action.dscp
    $proto = [string]$Action.protocol
    foreach ($t in @(Get-IgwtQosTargets -Action $Action)) {
        $found = Get-IgwtQosTargetPolicy -Target $t
        $p = $found.Policy
        $isOn = $false
        $cur = 'not present'
        if ($p) {
            $cur = "app=$($p.AppPathName) proto=$($p.IPProtocol) dscp=$($p.DSCPValue)"
            $isOn = ([string]$p.AppPathName -eq $t.Exe -and [int]$p.DSCPValue -eq $dscp -and [string]$p.IPProtocol -eq $proto)
        }
        [pscustomobject]@{
            Target  = "QoS policy $($found.Name) ($($t.Game))"
            Current = $cur
            Desired = "app=$($t.Exe) proto=$proto dscp=$dscp"
            State   = $(if ($isOn) { 'On' } else { 'Off' })
            Note    = 'Only effective if your router honors DSCP markings.'
        }
    }
}

function Get-IgwtNetQosSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $items = foreach ($t in @(Get-IgwtQosTargets -Action $Action)) {
        $found = Get-IgwtQosTargetPolicy -Target $t
        $p = $found.Policy
        if ($p) {
            [ordered]@{ name = $found.Name; exists = $true; appPathName = [string]$p.AppPathName; ipProtocol = [string]$p.IPProtocol;
                dscp = [int]$p.DSCPValue; networkProfile = [string]$p.NetworkProfile }
        } else {
            [ordered]@{ name = $t.Name; exists = $false }
        }
    }
    return @{ items = @($items) }
}

function Invoke-IgwtNetQosApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $dscp = [sbyte]$Action.dscp
    $proto = [string]$Action.protocol
    foreach ($t in @(Get-IgwtQosTargets -Action $Action)) {
        if ($Mode -eq 'default') {
            foreach ($n in @($t.Name, $t.LegacyName) | Where-Object { $_ }) {
                if ((Get-IgwtQosPolicyByName -Name $n) -and $PSCmdlet.ShouldProcess($n, 'Remove QoS policy')) { Remove-NetQosPolicy -Name $n -Confirm:$false -ErrorAction Stop }
            }
            continue
        }
        $found = Get-IgwtQosTargetPolicy -Target $t
        $p = $found.Policy
        if (-not $p) {
            if ($PSCmdlet.ShouldProcess($t.Name, "Create QoS policy ($($t.Exe), $proto, DSCP $dscp)")) {
                $null = New-NetQosPolicy -Name $t.Name -AppPathNameMatchCondition $t.Exe -IPProtocolMatchCondition $proto -DSCPAction $dscp -NetworkProfile All -ErrorAction Stop
            }
        } elseif ([string]$p.AppPathName -ne $t.Exe -or [int]$p.DSCPValue -ne [int]$dscp -or [string]$p.IPProtocol -ne $proto) {
            if ($PSCmdlet.ShouldProcess($found.Name, 'Update QoS policy')) {
                Set-NetQosPolicy -Name $found.Name -AppPathNameMatchCondition $t.Exe -IPProtocolMatchCondition $proto -DSCPAction $dscp -ErrorAction Stop
            }
        }
    }
}

function Restore-IgwtNetQosSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $allowed = @(Get-IgwtQosTargets -Action $Action | ForEach-Object { $_.Name; $_.LegacyName } | Where-Object { $_ })
    foreach ($item in @($Snapshot.items)) {
        $name = [string]$item.name
        if ($allowed -notcontains $name) { Write-IgwtLog -Level Warn -Message "Snapshot names unknown QoS policy '$name'; skipped."; continue }
        $p = Get-IgwtQosPolicyByName -Name $name
        if (-not $item.exists) {
            if ($p -and $PSCmdlet.ShouldProcess($name, 'Remove QoS policy (did not exist before)')) { Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction Stop }
        } else {
            if ($p) {
                if ($PSCmdlet.ShouldProcess($name, 'Restore QoS policy')) {
                    Set-NetQosPolicy -Name $name -AppPathNameMatchCondition ([string]$item.appPathName) -IPProtocolMatchCondition ([string]$item.ipProtocol) -DSCPAction ([sbyte]$item.dscp) -ErrorAction Stop
                }
            } elseif ($PSCmdlet.ShouldProcess($name, 'Recreate QoS policy')) {
                $null = New-NetQosPolicy -Name $name -AppPathNameMatchCondition ([string]$item.appPathName) -IPProtocolMatchCondition ([string]$item.ipProtocol) -DSCPAction ([sbyte]$item.dscp) -NetworkProfile ([string]$item.networkProfile) -ErrorAction Stop
            }
        }
    }
}