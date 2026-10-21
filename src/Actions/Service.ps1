# Service.ps1
# 'service' action: startup type of one Windows service. Uses Set-Service (so the Service
# Control Manager picks the change up immediately) and records the exact registry Start and
# DelayedAutostart values for a faithful revert. Anti-cheat services are refused outright.

$script:IgwtProtectedServices = @('vgc', 'vgk', 'FACEIT', 'FACEITService', 'EasyAntiCheat', 'EasyAntiCheat_EOS', 'BEService', 'BEDaisy',
    'atvi-randgrid_sr', 'Javelin', 'mpssvc', 'WinDefend', 'WdNisSvc', 'SecurityHealthService', 'wscsvc', 'BFE', 'EventLog', 'wuauserv')

function Get-IgwtServiceStartup {
    <# .SYNOPSIS Reads Start/DelayedAutostart from the service key (works without elevation). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $start = Get-IgwtRegistryValue -Path $path -Name 'Start'
    if (-not $start.KeyExists) { return $null }
    $delayed = Get-IgwtRegistryValue -Path $path -Name 'DelayedAutostart'
    $type = 'Unknown'
    switch ([int]$start.Value) {
        0 { $type = 'Boot' }
        1 { $type = 'System' }
        2 { if ($delayed.Exists -and [int]$delayed.Value -eq 1) { $type = 'AutomaticDelayed' } else { $type = 'Automatic' } }
        3 { $type = 'Manual' }
        4 { $type = 'Disabled' }
    }
    [pscustomobject]@{ StartupType = $type; Start = $start; Delayed = $delayed }
}

function Assert-IgwtServiceAllowed {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:IgwtProtectedServices -contains $Name) { throw "Service '$Name' is protected (anti-cheat or core security) and is never modified by iG Windows Tuner." }
}

function Get-IgwtServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $name = [string]$Action.name
    $s = Get-IgwtServiceStartup -Name $name
    if (-not $s) {
        return [pscustomobject]@{ Target = "Service $name"; Current = 'not installed'; Desired = [string]$Action.startupType; State = 'NotApplicable'; Note = '' }
    }
    [pscustomobject]@{
        Target  = "Service $name startup type"
        Current = $s.StartupType
        Desired = [string]$Action.startupType
        State   = $(if ($s.StartupType -eq [string]$Action.startupType) { 'On' } else { 'Off' })
        Note    = ''
    }
}

function Get-IgwtServiceSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $name = [string]$Action.name
    $s = Get-IgwtServiceStartup -Name $name
    if (-not $s) { return @{ exists = $false } }
    $running = $false
    try { $running = ((Get-Service -Name $name -ErrorAction Stop).Status -eq 'Running') } catch { $running = $false }
    return @{
        exists         = $true
        start          = [int]$s.Start.Value
        delayedExists  = [bool]$s.Delayed.Exists
        delayed        = $(if ($s.Delayed.Exists) { [int]$s.Delayed.Value } else { $null })
        wasRunning     = $running
    }
}

function Set-IgwtServiceStartupType {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$StartupType)
    Assert-IgwtServiceAllowed -Name $Name
    if (-not $PSCmdlet.ShouldProcess($Name, "Set startup type $StartupType")) { return }
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    switch ($StartupType) {
        'AutomaticDelayed' {
            Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
            Set-IgwtRegistryValue -Path $path -Name 'DelayedAutostart' -Kind DWord -Value 1
        }
        'Automatic' {
            Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
            $d = Get-IgwtRegistryValue -Path $path -Name 'DelayedAutostart'
            if ($d.Exists -and [int]$d.Value -ne 0) { Set-IgwtRegistryValue -Path $path -Name 'DelayedAutostart' -Kind DWord -Value 0 }
        }
        'Manual' { Set-Service -Name $Name -StartupType Manual -ErrorAction Stop }
        'Disabled' { Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop }
        default { throw "Unsupported startup type '$StartupType'." }
    }
}

function Invoke-IgwtServiceApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $name = [string]$Action.name
    $s = Get-IgwtServiceStartup -Name $name
    if (-not $s) { return }
    $target = [string]$Action.startupType
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    if ($s.StartupType -ne $target) { Set-IgwtServiceStartupType -Name $name -StartupType $target }
    if ($Mode -eq 'on' -and $target -eq 'Disabled' -and $Action.stop) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running' -and $PSCmdlet.ShouldProcess($name, 'Stop service')) { Stop-Service -Name $name -Force -ErrorAction Stop }
    }
}

function Restore-IgwtServiceSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $name = [string]$Action.name
    if (-not $Snapshot.exists) { return }
    $type = 'Manual'
    switch ([int]$Snapshot.start) {
        2 { $type = 'Automatic' }
        3 { $type = 'Manual' }
        4 { $type = 'Disabled' }
        default { throw "Snapshot start value $($Snapshot.start) for $name is not restorable through the SCM." }
    }
    Set-IgwtServiceStartupType -Name $name -StartupType $type
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if ($Snapshot.delayedExists) {
        Set-IgwtRegistryValue -Path $path -Name 'DelayedAutostart' -Kind DWord -Value ([int]$Snapshot.delayed)
    } else {
        Remove-IgwtRegistryValue -Path $path -Name 'DelayedAutostart'
    }
    if ($Snapshot.wasRunning) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running' -and $PSCmdlet.ShouldProcess($name, 'Start service')) { Start-Service -Name $name -ErrorAction Stop }
    }
}
