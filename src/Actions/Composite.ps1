# Composite.ps1
# Typed actions that expand into plain 'registry' or 'service' parts and reuse their exact
# snapshot/restore code:
#   storageSense     documented Storage Sense policies (Policy CSP Storage)
#   wufbPolicy       Windows Update for Business deferral and target-release policies
#   deviceInterrupt  MSI mode, message limit and interrupt affinity policy of GPU, NIC and USB host controllers
#   serviceSet       several service startup types as one action
# The expansion comes from the catalog action (plus, for devices, the devices present now), never
# from a snapshot file, so a modified snapshot cannot redirect a restore.

$script:IgwtStorageSenseKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense'
$script:IgwtStorageSenseSettings = [ordered]@{
    enabled        = @{ Name = 'AllowStorageSenseGlobal'; Allowed = @(0, 1) }
    cadence        = @{ Name = 'ConfigStorageSenseGlobalCadence'; Allowed = @(0, 1, 7, 30) }
    temporaryFiles = @{ Name = 'AllowStorageSenseTemporaryFilesCleanup'; Allowed = @(0, 1) }
    recycleBinDays = @{ Name = 'ConfigStorageSenseRecycleBinCleanupThreshold'; Min = 0; Max = 365 }
    downloadsDays  = @{ Name = 'ConfigStorageSenseDownloadsCleanupThreshold'; Min = 0; Max = 365 }
}
$script:IgwtWufbKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$script:IgwtWufbSettings = @('featureDeferralDays', 'qualityDeferralDays', 'targetRelease')
$script:IgwtInterruptClasses = @('Display', 'Net', 'USB')
$script:IgwtInterruptFields = [ordered]@{
    msiSupported       = @{ Sub = 'MessageSignaledInterruptProperties'; Name = 'MSISupported'; Min = 0; Max = 1 }
    messageNumberLimit = @{ Sub = 'MessageSignaledInterruptProperties'; Name = 'MessageNumberLimit'; Min = 1; Max = 2048 }
    devicePolicy       = @{ Sub = 'Affinity Policy'; Name = 'DevicePolicy'; Min = 0; Max = 5 }
    devicePriority     = @{ Sub = 'Affinity Policy'; Name = 'DevicePriority'; Min = 0; Max = 3 }
}

function New-IgwtRegistryPart {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param([string]$Key, [string]$Path, [string]$Name, [string]$Kind = 'DWord', $On, $Default = '<absent>', [string]$Label = '')
    [pscustomobject]@{
        Key = $Key; Kind = 'registry'; Label = $Label; Reason = ''
        Action = [pscustomobject]@{ type = 'registry'; path = $Path; name = $Name; valueType = $Kind; on = $On; default = $Default; absentValue = $null; equivalentOn = $null; bitClear = $null; onlyIfAbsent = $false }
    }
}

function Get-IgwtInterruptDevices {
    <# .SYNOPSIS Present PCI devices of a class (Display, Net, USB host controllers), read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Class)
    $devices = @(Get-PnpDevice -Class $Class -PresentOnly -ErrorAction SilentlyContinue | Where-Object { [string]$_.InstanceId -like 'PCI\*' -and [string]$_.Status -eq 'OK' })
    if ($Class -eq 'USB') { $devices = @($devices | Where-Object { [string]$_.FriendlyName -match '(?i)host controller' }) }
    return $devices
}

function Get-IgwtCompositeParts {
    <#
    .SYNOPSIS
        The concrete registry/service parts of a composite action. Parts that cannot be applied
        on this PC carry a Reason (shown as Not applicable).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    switch ([string]$Action.type) {
        'storageSense' {
            $def = $script:IgwtStorageSenseSettings[[string]$Action.setting]
            if (-not $def) { throw "Unknown Storage Sense setting '$($Action.setting)'." }
            return @(New-IgwtRegistryPart -Key ([string]$Action.setting) -Path $script:IgwtStorageSenseKey -Name $def.Name -On ([int]$Action.value))
        }
        'wufbPolicy' {
            $k = $script:IgwtWufbKey
            switch ([string]$Action.setting) {
                'featureDeferralDays' {
                    return @((New-IgwtRegistryPart -Key 'DeferFeatureUpdates' -Path $k -Name 'DeferFeatureUpdates' -On 1),
                        (New-IgwtRegistryPart -Key 'DeferFeatureUpdatesPeriodInDays' -Path $k -Name 'DeferFeatureUpdatesPeriodInDays' -On ([int]$Action.value)))
                }
                'qualityDeferralDays' {
                    return @((New-IgwtRegistryPart -Key 'DeferQualityUpdates' -Path $k -Name 'DeferQualityUpdates' -On 1),
                        (New-IgwtRegistryPart -Key 'DeferQualityUpdatesPeriodInDays' -Path $k -Name 'DeferQualityUpdatesPeriodInDays' -On ([int]$Action.value)))
                }
                'targetRelease' {
                    return @((New-IgwtRegistryPart -Key 'TargetReleaseVersion' -Path $k -Name 'TargetReleaseVersion' -On 1),
                        (New-IgwtRegistryPart -Key 'ProductVersion' -Path $k -Name 'ProductVersion' -Kind 'String' -On ([string]$Action.value.product)),
                        (New-IgwtRegistryPart -Key 'TargetReleaseVersionInfo' -Path $k -Name 'TargetReleaseVersionInfo' -Kind 'String' -On ([string]$Action.value.version)))
                }
                default { throw "Unknown Windows Update policy setting '$($Action.setting)'." }
            }
        }
        'serviceSet' {
            return @(foreach ($s in @($Action.services)) {
                    [pscustomobject]@{ Key = [string]$s.name; Kind = 'service'; Label = ''; Reason = ''
                        Action = [pscustomobject]@{ type = 'service'; name = [string]$s.name; startupType = [string]$s.startupType; default = [string]$s.default; stop = [bool]$Action.stop } }
                })
        }
        'deviceInterrupt' {
            $class = [string]$Action.deviceClass
            if ($script:IgwtInterruptClasses -notcontains $class) { throw "Device class '$class' is not allowed (only Display, Net and USB host controllers)." }
            if ($class -eq 'USB' -and $Context -and $Context.HardwareProfile -and [string]$Context.HardwareProfile.Facts.systemDisk.bus -eq 'USB') {
                return @([pscustomobject]@{ Key = 'usb-boot'; Kind = 'none'; Label = 'USB host controllers'; Reason = 'Windows runs from a USB disk; its host controller is never changed.'; Action = $null })
            }
            $devices = @(Get-IgwtInterruptDevices -Class $class)
            if ($devices.Count -eq 0) { return @([pscustomobject]@{ Key = 'none'; Kind = 'none'; Label = "$class devices"; Reason = "No present PCI $class device."; Action = $null }) }
            $parts = foreach ($d in $devices) {
                $base = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($d.InstanceId)\Device Parameters\Interrupt Management"
                $msiKey = Test-IgwtRegistryKey -Path "$base\MessageSignaledInterruptProperties"
                foreach ($f in $script:IgwtInterruptFields.Keys) {
                    if ($null -eq $Action.PSObject.Properties[$f] -or $null -eq $Action.$f) { continue }
                    $spec = $script:IgwtInterruptFields[$f]
                    $p = New-IgwtRegistryPart -Key "$($d.InstanceId)|$($spec.Name)" -Path "$base\$($spec.Sub)" -Name $spec.Name -On ([int]$Action.$f) -Default $null -Label ([string]$d.FriendlyName)
                    if ($spec.Sub -eq 'MessageSignaledInterruptProperties' -and -not $msiKey) { $p.Reason = "$($d.FriendlyName) does not declare MSI support in its driver."; $p.Kind = 'none' }
                    $p
                }
            }
            return @($parts)
        }
        default { throw "'$($Action.type)' is not a composite action." }
    }
}

function Get-IgwtCompositeState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    foreach ($p in @(Get-IgwtCompositeParts -Action $Action -Context $Context)) {
        if ($p.Kind -eq 'none') { [pscustomobject]@{ Target = [string]$p.Label; Current = 'not applicable'; Desired = ''; State = 'NotApplicable'; Note = [string]$p.Reason }; continue }
        $items = @()
        if ($p.Kind -eq 'service') { $items = @(Get-IgwtServiceState -Action $p.Action -Context $Context) } else { $items = @(Get-IgwtRegistryState -Action $p.Action -Context $Context) }
        foreach ($it in $items) {
            if ($p.Label) { $it.Target = "[$($p.Label)] $($it.Target)" }
            $it
        }
    }
}

function Get-IgwtCompositeSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $parts = foreach ($p in @(Get-IgwtCompositeParts -Action $Action -Context $Context)) {
        if ($p.Kind -eq 'none') { continue }
        $data = $null
        if ($p.Kind -eq 'service') { $data = Get-IgwtServiceSnapshot -Action $p.Action -Context $Context } else { $data = Get-IgwtRegistrySnapshot -Action $p.Action -Context $Context }
        [ordered]@{ key = [string]$p.Key; data = $data }
    }
    return @{ parts = @($parts) }
}

function Invoke-IgwtCompositeApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    if ($Mode -eq 'default' -and [string]$Action.type -eq 'deviceInterrupt') { throw 'Device interrupt settings have no documented Windows default (the driver sets them); revert from the snapshot instead.' }
    if (-not $PSCmdlet.ShouldProcess([string]$Action.type, "Apply ($Mode)")) { return }
    foreach ($p in @(Get-IgwtCompositeParts -Action $Action -Context $Context)) {
        if ($p.Kind -eq 'none') { continue }
        if ($p.Kind -eq 'service') { Invoke-IgwtServiceApply -Action $p.Action -Context $Context -Mode $Mode }
        else { Invoke-IgwtRegistryApply -Action $p.Action -Context $Context -Mode $Mode }
    }
}

function Restore-IgwtCompositeSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if (-not $PSCmdlet.ShouldProcess([string]$Action.type, 'Restore snapshot')) { return }
    $current = @{}
    foreach ($p in @(Get-IgwtCompositeParts -Action $Action -Context $Context)) { $current[[string]$p.Key] = $p }
    $saved = @($Snapshot.parts | Where-Object { $_ })
    [array]::Reverse($saved)
    foreach ($s in $saved) {
        $p = $current[[string]$s.key]
        if (-not $p -or $p.Kind -eq 'none') { Write-IgwtLog -Level Warn -Message "$($Action.type): '$($s.key)' is no longer present; not restored."; continue }
        if ($p.Kind -eq 'service') { Restore-IgwtServiceSnapshot -Action $p.Action -Snapshot $s.data -Context $Context }
        else { Restore-IgwtRegistrySnapshot -Action $p.Action -Snapshot $s.data -Context $Context }
    }
}
