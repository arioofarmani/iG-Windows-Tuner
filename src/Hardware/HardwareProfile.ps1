# HardwareProfile.ps1
# Read-only hardware profile: collects facts (CPU, GPUs, NICs, memory, form factor, system disk,
# virtual machine) and turns them into hardware tags with the data-driven detection rules in
# data\hardware\detection.json. Tags drive the overlays in Overlays.ps1. Nothing is changed.

$script:IgwtHardwareProfileCache = $null
$script:IgwtDetectionCache = $null
$script:IgwtVmPattern = '(?i)(Virtual Machine|VMware|VirtualBox|KVM|QEMU|Xen|Parallels|HVM domU|Bochs|innotek)'
$script:IgwtDetectionKeys = @('cpuVendor', 'cpuName', 'cpuNameNot', 'cpuFamily', 'cpuModels', 'hybrid', 'gpuName', 'gpuPnp', 'nicName', 'nicPnp',
    'laptop', 'vm', 'modernStandby', 'systemDiskBus', 'systemDiskMedia', 'memoryGBMin', 'memoryGBBelow')

#region Facts

function ConvertTo-IgwtPciId {
    <# .SYNOPSIS 'PCI\VEN_10DE&DEV_2216&SUBSYS_...' -> 'VEN_10DE&DEV_2216' (no serial or instance data). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$PnpDeviceId)
    if ($PnpDeviceId -match '(VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4})') { return $Matches[1].ToUpperInvariant() }
    return ''
}

function Test-IgwtModernStandby {
    <# .SYNOPSIS True when 'powercfg /a' lists Standby (S0 Low Power Idle) as available. Read-only. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $text = [string](Invoke-IgwtPowerCfg -Arguments @('/a')).Output
        $available = ($text -split '(?im)^.*not available.*$')[0]
        return ($available -match 'S0 Low Power Idle')
    } catch { return $false }
}

function Get-IgwtHardwareFacts {
    <#
    .SYNOPSIS
        Raw hardware facts for the profile (read-only, no serial numbers): CPU, active GPUs, network
        controllers, installed memory, battery/chassis, Modern Standby, system disk, VM indicators.
    #>
    [CmdletBinding()]
    param()
    $cpu = Get-IgwtCpuInfo
    $facts = [ordered]@{
        schemaVersion = 2
        name          = ''
        cpu           = [ordered]@{ name = [string]$cpu.Name; vendor = [string]$cpu.Vendor; family = $cpu.Family; model = $cpu.Model; cores = $cpu.Cores; threads = $cpu.Threads }
        gpus          = @()
        nics          = @()
        memoryGB      = 0
        battery       = $false
        portableChassis = $false
        modernStandby = $false
        systemDisk    = [ordered]@{ model = ''; bus = ''; media = '' }
        system        = [ordered]@{ manufacturer = ''; model = '' }
        os            = [ordered]@{ build = 0 }
    }
    try {
        $facts.gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.PNPDeviceID -like 'PCI\*' } | ForEach-Object {
                [ordered]@{ name = [string]$_.Name; vendor = [string]$_.AdapterCompatibility; pnp = (ConvertTo-IgwtPciId $_.PNPDeviceID); enabled = ([int]$_.ConfigManagerErrorCode -eq 0) }
            })
    } catch { Write-Verbose 'GPU facts unavailable.' }
    try {
        $facts.nics = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='Net'" -ErrorAction Stop | Where-Object { $_.PNPDeviceID -like 'PCI\*' } | ForEach-Object {
                [ordered]@{ name = [string]$_.Name; pnp = (ConvertTo-IgwtPciId $_.PNPDeviceID); enabled = ([int]$_.ConfigManagerErrorCode -eq 0) }
            })
    } catch { Write-Verbose 'NIC facts unavailable.' }
    $mem = Get-IgwtMemoryInfo
    $facts.memoryGB = [int]$mem.TotalGB
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $facts.system = [ordered]@{ manufacturer = [string]$cs.Manufacturer; model = [string]$cs.Model }
        if (-not $facts.memoryGB -and $cs.TotalPhysicalMemory) { $facts.memoryGB = [int][math]::Ceiling([double]$cs.TotalPhysicalMemory / 1GB) }
    } catch { Write-Verbose 'Win32_ComputerSystem unavailable.' }
    $power = Get-IgwtPowerSource
    $facts.battery = [bool]$power.HasBattery
    $facts.portableChassis = [bool]$power.IsPortable
    $facts.modernStandby = Test-IgwtModernStandby
    try {
        $num = (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop | Get-Disk -ErrorAction Stop).Number
        $pd = @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.DeviceId -eq [string]$num }) | Select-Object -First 1
        if ($pd) { $facts.systemDisk = [ordered]@{ model = [string]$pd.FriendlyName; bus = [string]$pd.BusType; media = [string]$pd.MediaType } }
    } catch { Write-Verbose 'System disk facts unavailable.' }
    $facts.os = [ordered]@{ build = [int](Get-IgwtOsInfo).Build }
    return [pscustomobject]$facts
}

function Get-IgwtDerivedFacts {
    <# .SYNOPSIS Values computed from raw facts: hybrid CPU, virtual machine, laptop. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Facts)
    $cores = [int]$Facts.cpu.cores; $threads = [int]$Facts.cpu.threads
    $vm = ("$($Facts.system.manufacturer) $($Facts.system.model)" -match $script:IgwtVmPattern)
    # In a VM, virtual processors usually appear as cores without Hyper-Threading, so the hybrid test is skipped.
    [pscustomobject]@{
        Hybrid = (-not $vm) -and ([string]$Facts.cpu.vendor -match 'Intel' -and $cores -gt 0 -and $threads -gt 0 -and $threads -lt (2 * $cores))
        Vm     = [bool]$vm
        Laptop = (-not $vm) -and ([bool]$Facts.battery -or [bool]$Facts.portableChassis)
    }
}

#endregion

#region Detection

function Get-IgwtDetectionRules {
    <# .SYNOPSIS Tag detection rules from data\hardware\detection.json. #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtDetectionCache -and -not $Force) { return $script:IgwtDetectionCache }
    $file = Join-Path (Get-IgwtDataFolder) 'hardware\detection.json'
    $rules = @()
    if (Test-Path -LiteralPath $file) { $rules = @((Read-IgwtJsonFile -Path $file).rules | Where-Object { $_ }) }
    $script:IgwtDetectionCache = $rules
    return $rules
}

function Test-IgwtDetectionCondition {
    <# .SYNOPSIS True when every key of one condition object holds for the facts (keys are ANDed). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Facts, [Parameter(Mandatory = $true)]$Derived, [Parameter(Mandatory = $true)]$When)
    $gpus = @($Facts.gpus | Where-Object { $_ -and $_.enabled })
    $nics = @($Facts.nics | Where-Object { $_ })
    foreach ($p in $When.PSObject.Properties) {
        $v = $p.Value
        $ok = switch ($p.Name) {
            'cpuVendor' { [string]$Facts.cpu.vendor -match [string]$v }
            'cpuName' { [string]$Facts.cpu.name -match [string]$v }
            'cpuNameNot' { [string]$Facts.cpu.name -notmatch [string]$v }
            'cpuFamily' { [int]$Facts.cpu.family -eq [int]$v }
            'cpuModels' { @($v | ForEach-Object { [int]$_ }) -contains [int]$Facts.cpu.model }
            'hybrid' { [bool]$Derived.Hybrid -eq [bool]$v }
            'gpuName' { @($gpus | Where-Object { [string]$_.name -match [string]$v }).Count -gt 0 }
            'gpuPnp' { @($gpus | Where-Object { [string]$_.pnp -match [string]$v }).Count -gt 0 }
            'nicName' { @($nics | Where-Object { [string]$_.name -match [string]$v }).Count -gt 0 }
            'nicPnp' { @($nics | Where-Object { [string]$_.pnp -match [string]$v }).Count -gt 0 }
            'laptop' { [bool]$Derived.Laptop -eq [bool]$v }
            'vm' { [bool]$Derived.Vm -eq [bool]$v }
            'modernStandby' { [bool]$Facts.modernStandby -eq [bool]$v }
            'systemDiskBus' { [string]$Facts.systemDisk.bus -match [string]$v }
            'systemDiskMedia' { [string]$Facts.systemDisk.media -match [string]$v }
            'memoryGBMin' { [double]$Facts.memoryGB -ge [double]$v }
            'memoryGBBelow' { [double]$Facts.memoryGB -gt 0 -and [double]$Facts.memoryGB -lt [double]$v }
            default { $false }
        }
        if (-not $ok) { return $false }
    }
    return $true
}

function Get-IgwtHardwareProfile {
    <#
    .SYNOPSIS
        Hardware tags for this PC (or for -Facts, used by the test fixtures), with the detection
        rule that produced each tag. Cached for the session; -Force re-detects. Read-only.
    .OUTPUTS
        Facts, Derived, Tags (sorted ids) and TagDetails (Id, Name, Group, Hint, Basis).
    #>
    [CmdletBinding()]
    param($Facts, [switch]$Force)
    $useCache = ($null -eq $Facts)
    if ($useCache -and $script:IgwtHardwareProfileCache -and -not $Force) { return $script:IgwtHardwareProfileCache }
    if ($null -eq $Facts) { $Facts = Get-IgwtHardwareFacts }
    if ($Facts -is [System.Collections.IDictionary]) { $Facts = ConvertTo-IgwtPSObject -InputObject $Facts }
    $derived = Get-IgwtDerivedFacts -Facts $Facts
    $defs = @{}
    foreach ($t in @(Get-IgwtHardwareTagDefinitions)) { $defs[[string]$t.id] = $t }
    $found = [ordered]@{}
    foreach ($r in @(Get-IgwtDetectionRules)) {
        $tag = [string]$r.tag
        if ($found.Contains($tag)) { continue }
        $conds = @()
        if ($null -ne $r.PSObject.Properties['anyOf']) { $conds = @($r.anyOf) } else { $conds = @($r.when) }
        foreach ($c in $conds) {
            if ($c -and (Test-IgwtDetectionCondition -Facts $Facts -Derived $derived -When $c)) { $found[$tag] = [string]$r.basis; break }
        }
    }
    $details = @(foreach ($k in $found.Keys) {
            $d = $defs[$k]
            [pscustomobject]@{ Id = $k; Name = $(if ($d) { [string]$d.name } else { $k }); Group = $(if ($d) { [string]$d.group } else { '' }); Hint = $(if ($d) { [string]$d.hint } else { '' }); Basis = $found[$k] }
        })
    $profileObj = [pscustomobject]@{
        Facts      = $Facts
        Derived    = $derived
        Tags       = @($found.Keys | Sort-Object)
        TagDetails = @($details | Sort-Object Group, Id)
    }
    if ($useCache) { $script:IgwtHardwareProfileCache = $profileObj }
    return $profileObj
}

#endregion
