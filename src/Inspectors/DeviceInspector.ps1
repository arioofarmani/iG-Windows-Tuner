# DeviceInspector.ps1
# Interrupt and device inspector (read-only): present PCI devices with the interrupt types they
# support (line-based, MSI, MSI-X), the mode they use right now (from the allocated interrupt
# resources), the MSI and affinity-policy registry configuration and the CPUs an affinity override
# targets. Edits go through the deviceInterrupt catalog items, which apply only to GPU, NIC and USB
# host controllers that declare MSI support, and never to the boot-disk controller.

$script:IgwtInterruptPolicyNames = @{
    0 = 'Machine default'; 1 = 'All close processors'; 2 = 'One close processor'; 3 = 'All processors in machine'
    4 = 'Specified processors'; 5 = 'Spread messages across all processors'
}
$script:IgwtInterruptPriorityNames = @{ 0 = 'Undefined'; 1 = 'Low'; 2 = 'Normal'; 3 = 'High' }

function ConvertFrom-IgwtInterruptSupport {
    <# .SYNOPSIS DEVPKEY_PciDevice_InterruptSupport bit mask -> list of supported interrupt types. #>
    [CmdletBinding()]
    param($Mask)
    if ($null -eq $Mask -or [string]$Mask -eq '') { return @() }
    $m = [int]$Mask
    $list = @()
    if ($m -band 1) { $list += 'Line' }
    if ($m -band 2) { $list += 'MSI' }
    if ($m -band 4) { $list += 'MSI-X' }
    return $list
}

function ConvertFrom-IgwtAffinityMask {
    <# .SYNOPSIS AssignmentSetOverride bytes or number -> logical processor numbers. #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return @() }
    $bytes = @()
    if ($Value -is [byte[]] -or $Value -is [object[]]) { $bytes = @($Value | ForEach-Object { [byte]$_ }) }
    else { $bytes = [BitConverter]::GetBytes([uint64]$Value) }
    $cpus = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $bytes.Count; $i++) { for ($b = 0; $b -lt 8; $b++) { if ($bytes[$i] -band (1 -shl $b)) { $cpus.Add($i * 8 + $b) } } }
    return $cpus.ToArray()
}

function Get-IgwtAllocatedInterrupts {
    <# .SYNOPSIS Device instance id (upper case) -> allocated IRQ numbers (Win32_PnPAllocatedResource). #>
    [CmdletBinding()]
    param()
    $map = @{}
    try {
        foreach ($a in @(Get-CimInstance -ClassName Win32_PnPAllocatedResource -ErrorAction Stop)) {
            $ante = $a.Antecedent; $dep = $a.Dependent
            if (-not $ante -or [string]$ante.CimClass.CimClassName -ne 'Win32_IRQResource') { continue }
            $id = ([string]$dep.DeviceID).ToUpperInvariant()
            if (-not $id) { continue }
            if (-not $map.ContainsKey($id)) { $map[$id] = New-Object System.Collections.Generic.List[long] }
            $map[$id].Add([long]$ante.IRQNumber)
        }
    } catch { Write-Verbose "Allocated interrupt resources unavailable: $($_.Exception.Message)" }
    return $map
}

function Get-IgwtInterruptMode {
    <# .SYNOPSIS Current interrupt mode from allocated IRQ numbers: message-signaled IRQs are reported at 0x80000000 and above. #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][long[]]$Irqs)
    $all = @($Irqs)
    if ($all.Count -eq 0) { return [pscustomobject]@{ Mode = 'Unknown'; Messages = 0; Irqs = @() } }
    $msg = @($all | Where-Object { $_ -ge 2147483648 })
    if ($msg.Count -gt 0) { return [pscustomobject]@{ Mode = 'Message-signaled'; Messages = $msg.Count; Irqs = @() } }
    return [pscustomobject]@{ Mode = 'Line-based'; Messages = 0; Irqs = @($all) }
}

function Get-IgwtInterruptInspection {
    <#
    .SYNOPSIS
        Read-only interrupt view of present PCI devices: supported and current interrupt mode,
        MSISupported / MessageNumberLimit, affinity policy, priority and target CPUs, and whether
        a deviceInterrupt catalog item may change it.
    #>
    [CmdletBinding()]
    param()
    $devices = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { [string]$_.InstanceId -like 'PCI\*' })
    $props = @{}
    foreach ($d in $devices) {
        # One query per device: a batched query stops returning data after the first device without the keys.
        $k = ([string]$d.InstanceId).ToUpperInvariant()
        $props[$k] = @{}
        try {
            foreach ($p in @(Get-PnpDeviceProperty -InstanceId ([string]$d.InstanceId) -KeyName 'DEVPKEY_PciDevice_InterruptSupport', 'DEVPKEY_PciDevice_InterruptMessageMaximum' -ErrorAction Stop)) {
                $props[$k][[string]$p.KeyName] = $p.Data
            }
        } catch { Write-Verbose "Interrupt properties of $($d.InstanceId) unavailable." }
    }
    $irqs = Get-IgwtAllocatedInterrupts
    $rows = foreach ($d in $devices) {
        $id = [string]$d.InstanceId
        $up = $id.ToUpperInvariant()
        $base = "HKLM:\SYSTEM\CurrentControlSet\Enum\$id\Device Parameters\Interrupt Management"
        $read = { param($sub, $name) try { $v = Get-IgwtRegistryValue -Path "$base\$sub" -Name $name; if ($v.Exists) { $v.Value } else { $null } } catch { $null } }
        $msi = & $read 'MessageSignaledInterruptProperties' 'MSISupported'
        $limit = & $read 'MessageSignaledInterruptProperties' 'MessageNumberLimit'
        $policy = & $read 'Affinity Policy' 'DevicePolicy'
        $priority = & $read 'Affinity Policy' 'DevicePriority'
        $override = & $read 'Affinity Policy' 'AssignmentSetOverride'
        $p = $(if ($props.ContainsKey($up)) { $props[$up] } else { @{} })
        $support = @(ConvertFrom-IgwtInterruptSupport -Mask $p['DEVPKEY_PciDevice_InterruptSupport'])
        $mode = Get-IgwtInterruptMode -Irqs $(if ($irqs.ContainsKey($up)) { @($irqs[$up]) } else { @() })
        $class = [string]$d.Class
        $isUsbHost = ($class -eq 'USB' -and [string]$d.FriendlyName -match '(?i)host controller')
        $catalogClass = $(if ($class -in 'Display', 'Net') { $class } elseif ($isUsbHost) { 'USB' } else { '' })
        $note = ''
        if ($class -in 'SCSIAdapter', 'HDC') { $note = 'Storage controller: never changed by iG Windows Tuner (the boot disk depends on it).' }
        elseif (-not $catalogClass) { $note = 'Shown for information; iG Windows Tuner only changes GPU, network and USB host controllers.' }
        elseif ($support -notcontains 'MSI' -and $support -notcontains 'MSI-X') { $note = 'The device does not report MSI support.' }
        elseif ($mode.Mode -eq 'Line-based' -and $msi -ne 1) { $note = 'Supports MSI but uses a line-based interrupt; the MSI catalog item for this class could switch it (reboot, measure DPC latency).' }
        [pscustomobject]@{
            Name             = [string]$d.FriendlyName
            Class            = $class
            InstanceId       = $id
            Status           = [string]$d.Status
            Supports         = $support
            MessageMaximum   = $p['DEVPKEY_PciDevice_InterruptMessageMaximum']
            CurrentMode      = $mode.Mode
            Messages         = $mode.Messages
            Irqs             = @($mode.Irqs)
            MsiSupported     = $msi
            MessageLimit     = $limit
            DevicePolicy     = $policy
            PolicyName       = $(if ($null -ne $policy -and $script:IgwtInterruptPolicyNames.ContainsKey([int]$policy)) { $script:IgwtInterruptPolicyNames[[int]$policy] } elseif ($null -eq $policy) { 'Machine default (not set)' } else { "Policy $policy" })
            DevicePriority   = $priority
            PriorityName     = $(if ($null -ne $priority -and $script:IgwtInterruptPriorityNames.ContainsKey([int]$priority)) { $script:IgwtInterruptPriorityNames[[int]$priority] } else { 'Undefined' })
            TargetCpus       = @(ConvertFrom-IgwtAffinityMask -Value $override)
            CatalogClass     = $catalogClass
            Note             = $note
        }
    }
    $rows = @($rows | Sort-Object @{ Expression = { if ($_.CatalogClass) { 0 } else { 1 } } }, Class, Name)
    [pscustomobject]@{
        Devices          = $rows
        MessageSignaled  = @($rows | Where-Object { $_.CurrentMode -eq 'Message-signaled' }).Count
        LineBased        = @($rows | Where-Object { $_.CurrentMode -eq 'Line-based' }).Count
        Note             = 'Read-only. MSI and affinity changes need a reboot and are made only through the deviceInterrupt catalog items (GPU, network and USB host controllers that declare MSI support).'
    }
}
