# Hardware.ps1
# OS, CPU (including the 13th/14th-gen Vmin Shift microcode check) and memory. Read-only.

$script:IgwtMicrocodeMinimum = 0x12F
$script:IgwtVminModels = @(183, 191)   # Raptor Lake-S (0xB7) and Raptor Lake-S Refresh (0xBF), family 6

function ConvertFrom-IgwtMicrocodeRevision {
    <#
    .SYNOPSIS
        Parses the "Update Revision" REG_BINARY. Older builds store 8 bytes with the revision in the
        high DWORD (bytes 4-7); current builds store 4 bytes (little-endian DWORD).
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 4) { return -1 }
    if ($Bytes.Length -ge 8) {
        $high = [BitConverter]::ToUInt32($Bytes, 4)
        if ($high -ne 0) { return [long]$high }
    }
    return [long][BitConverter]::ToUInt32($Bytes, 0)
}

function Get-IgwtCpuInfo {
    [CmdletBinding()]
    param()
    $cpu = $null
    try { $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1 } catch { Write-Verbose 'Win32_Processor unavailable.' }
    $reg = Get-ItemProperty -LiteralPath 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction SilentlyContinue
    $rev = -1
    if ($reg -and $reg.'Update Revision') { $rev = ConvertFrom-IgwtMicrocodeRevision -Bytes ([byte[]]$reg.'Update Revision') }
    $family = $null; $model = $null; $stepping = $null
    if ($reg -and $reg.Identifier -match 'Family (\d+) Model (\d+) Stepping (\d+)') { $family = [int]$Matches[1]; $model = [int]$Matches[2]; $stepping = [int]$Matches[3] }
    $name = $(if ($cpu) { ($cpu.Name -replace '\s+', ' ').Trim() } elseif ($reg) { $reg.ProcessorNameString } else { 'Unknown CPU' })
    [pscustomobject]@{
        Name              = $name
        Cores             = $(if ($cpu) { [int]$cpu.NumberOfCores } else { $null })
        Threads           = $(if ($cpu) { [int]$cpu.NumberOfLogicalProcessors } else { $null })
        Vendor            = $(if ($reg) { $reg.VendorIdentifier } else { '' })
        Family            = $family
        Model             = $model
        Stepping          = $stepping
        MicrocodeRevision = $rev
        IsVminAffected    = ($family -eq 6 -and $script:IgwtVminModels -contains $model -and $name -match '1[34]th Gen Intel')
        IsHybrid          = ($cpu -and [int]$cpu.NumberOfLogicalProcessors -lt (2 * [int]$cpu.NumberOfCores))
    }
}

function Get-IgwtMemoryInfo {
    [CmdletBinding()]
    param()
    $modules = @()
    try { $modules = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop) } catch { $modules = @() }
    $total = ($modules | Measure-Object -Property Capacity -Sum).Sum
    $type = 'Unknown'
    $types = @($modules | ForEach-Object { [int]$_.SMBIOSMemoryType } | Select-Object -Unique)
    if ($types -contains 34) { $type = 'DDR5' } elseif ($types -contains 26) { $type = 'DDR4' }
    $configured = @($modules | ForEach-Object { [int]$_.ConfiguredClockSpeed } | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
    $rated = @($modules | ForEach-Object { [int]$_.Speed } | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
    $partRated = $null
    $part = (@($modules | ForEach-Object { ([string]$_.PartNumber).Trim() } | Select-Object -Unique) -join ', ')
    if ($part -match '(?<![0-9])([2-8][0-9])00(?![0-9])') { $partRated = [int]"$($Matches[1])00" }
    elseif ($part -match 'KF[45](\d{2})') { $partRated = [int]"$($Matches[1])00" }   # Kingston FURY: KF556C40 = 5600 MT/s
    [pscustomobject]@{
        TotalGB        = $(if ($total) { [math]::Round($total / 1GB) } else { 0 })
        Modules        = $modules.Count
        Type           = $type
        ConfiguredMTs  = $(if ($configured) { $configured[0] } else { $null })
        ReportedMaxMTs = $(if ($rated) { $rated[-1] } else { $null })
        PartRatedMTs   = $partRated
        PartNumbers    = $part
    }
}

function Get-IgwtHardwareChecks {
    [CmdletBinding()]
    param()
    $checks = New-Object System.Collections.Generic.List[object]
    $os = Get-IgwtOsInfo
    $pending = Get-IgwtPendingReboot
    $checks.Add([pscustomobject]@{ Section = 'System'; Id = 'os'; Name = 'Windows'; Status = $(if ($os.Build -ge 26100) { 'Pass' } else { 'Fail' })
            Value = "$($os.Caption) $($os.DisplayVersion) (build $($os.FullBuild))"; Detail = "Edition: $($os.EditionId)"; Advice = $(if ($os.Build -lt 26100) { 'iG Windows Tuner supports Windows 11 24H2 (26100) and newer.' } else { '' }); Source = '' })
    if ($os.Uptime) {
        $checks.Add([pscustomobject]@{ Section = 'System'; Id = 'uptime'; Name = 'Uptime'; Status = 'Info'; Value = ('{0}d {1}h {2}m' -f $os.Uptime.Days, $os.Uptime.Hours, $os.Uptime.Minutes); Detail = "Last boot $($os.LastBootUpTime)"; Advice = ''; Source = '' })
    }
    $checks.Add([pscustomobject]@{ Section = 'System'; Id = 'pendingReboot'; Name = 'Pending reboot'; Status = $(if ($pending.Count -gt 0) { 'Warn' } else { 'Pass' })
            Value = $(if ($pending.Count -gt 0) { $pending -join ', ' } else { 'None' }); Detail = ''; Advice = $(if ($pending.Count -gt 0) { 'Reboot before measuring performance or applying changes.' } else { '' }); Source = '' })

    $cpu = Get-IgwtCpuInfo
    $checks.Add([pscustomobject]@{ Section = 'CPU'; Id = 'cpu'; Name = 'Processor'; Status = 'Info'; Value = $cpu.Name
            Detail = "$($cpu.Cores) cores / $($cpu.Threads) threads$(if ($cpu.IsHybrid) { ', hybrid (P-cores + E-cores): Thread Director and the Windows scheduler stay in charge' })"; Advice = ''; Source = '' })
    $mcText = $(if ($cpu.MicrocodeRevision -ge 0) { '0x{0:X}' -f $cpu.MicrocodeRevision } else { 'unknown' })
    if ($cpu.IsVminAffected) {
        $ok = $cpu.MicrocodeRevision -ge $script:IgwtMicrocodeMinimum
        $checks.Add([pscustomobject]@{ Section = 'CPU'; Id = 'microcode'; Name = 'CPU microcode (Vmin Shift fix)'; Status = $(if ($ok) { 'Pass' } else { 'Fail' }); Value = $mcText
                Detail = '13th/14th-gen desktop CPUs need microcode 0x12F or newer to prevent Vmin Shift instability (permanent degradation).'
                Advice = $(if ($ok) { 'Keep the BIOS current and use the "Intel Default Settings" profile.' } else { 'Update the motherboard BIOS (Gigabyte: download the latest BIOS for your board) and load the "Intel Default Settings" BIOS profile. iG Windows Tuner never changes firmware, voltages or power limits.' })
                Source = 'https://www.intel.com/content/www/us/en/support/articles/000102331/processors.html' })
    } else {
        $checks.Add([pscustomobject]@{ Section = 'CPU'; Id = 'microcode'; Name = 'CPU microcode'; Status = 'Info'; Value = $mcText; Detail = 'Not a 13th/14th-gen desktop CPU affected by Vmin Shift.'; Advice = ''; Source = '' })
    }

    $mem = Get-IgwtMemoryInfo
    $memStatus = 'Pass'
    $memAdvice = ''
    $rated = $mem.PartRatedMTs
    if (-not $rated) { $rated = $mem.ReportedMaxMTs }
    if ($mem.ConfiguredMTs -and $rated -and $mem.ConfiguredMTs -lt ($rated - 100)) {
        $memStatus = 'Warn'
        $memAdvice = "Memory runs at $($mem.ConfiguredMTs) MT/s but the kit is rated $rated MT/s. Enable XMP in BIOS if you want rated speed (validate stability). iG Windows Tuner never changes memory settings."
    }
    $checks.Add([pscustomobject]@{ Section = 'Memory'; Id = 'memory'; Name = 'Memory'; Status = $memStatus
            Value = "$($mem.TotalGB) GB $($mem.Type), $($mem.Modules) module(s), configured $($mem.ConfiguredMTs) MT/s"
            Detail = "Reported max $($mem.ReportedMaxMTs) MT/s; part number(s) $($mem.PartNumbers)"; Advice = $memAdvice; Source = '' })
    return $checks.ToArray()
}
