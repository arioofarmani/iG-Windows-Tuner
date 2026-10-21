# Diagnostics.ps1
# Read-only diagnostics: DPC and ISR percentages from performance counters with top processes,
# reliability history, crashes (BugCheck, Kernel-Power 41, unexpected shutdowns, app crashes and
# the minidump list), boot performance (Diagnostics-Performance event 100) and the driver inventory
# with date and signer. Nothing here changes the system.

function Get-IgwtProcessorRawSample {
    <#
    .SYNOPSIS
        One raw sample of the _Total processor counters. Formatted (cooked) WMI counters need two
        reads in the same query, so percentages are computed from raw deltas instead. Mock this in tests.
    #>
    [CmdletBinding()]
    param()
    $c = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
    [pscustomobject]@{
        Dpc = [double]$c.PercentDPCTime; Isr = [double]$c.PercentInterruptTime; Idle = [double]$c.PercentIdleTime; Interrupts = [double]$c.InterruptsPersec; Dpcs = [double]$c.DPCsQueuedPersec
        Time100ns = [double]$c.Timestamp_Sys100NS; PerfTime = [double]$c.Timestamp_PerfTime; PerfFreq = [double]$c.Frequency_PerfTime
    }
}

function ConvertFrom-IgwtProcessorRawPair {
    <# .SYNOPSIS Percentages and rates between two raw samples (100 ns timers against Timestamp_Sys100NS, counts against the performance clock). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$First, [Parameter(Mandatory = $true)]$Second)
    $dt = $Second.Time100ns - $First.Time100ns
    $sec = $(if ($Second.PerfFreq -gt 0) { ($Second.PerfTime - $First.PerfTime) / $Second.PerfFreq } else { $dt / 1e7 })
    if ($dt -le 0 -or $sec -le 0) { return $null }
    # Double literals: with an int first argument PowerShell picks Math.Min(int, int) and truncates fractions.
    $pct = { param($a, $b) [Math]::Max([double]0, [Math]::Min([double]100, [double](100 * ($b - $a) / $dt))) }
    [pscustomobject]@{
        Dpc = (& $pct $First.Dpc $Second.Dpc); Isr = (& $pct $First.Isr $Second.Isr); Cpu = (100 - (& $pct $First.Idle $Second.Idle))
        InterruptsPerSec = [Math]::Max([double]0, [double](($Second.Interrupts - $First.Interrupts) / $sec)); DpcRate = [Math]::Max([double]0, [double](($Second.Dpcs - $First.Dpcs) / $sec))
    }
}

function Get-IgwtDpcIsrSample {
    <#
    .SYNOPSIS
        Samples the DPC and ISR percentages Samples times (one second apart) and lists the top
        processes by CPU. Windows only exposes totals; LatencyMon or WPA name the driver behind
        high DPC time.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 60)][int]$Samples = 5, [ValidateRange(1, 50)][int]$Top = 10)
    $rows = New-Object System.Collections.Generic.List[object]
    $cpuTimes = { $h = @{}; foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { try { $h[[int]$p.Id] = [pscustomobject]@{ Name = [string]$p.ProcessName; Cpu = [double]$p.TotalProcessorTime.TotalSeconds; WorkingSet = [double]$p.WorkingSet64 } } catch { Write-Verbose "No CPU time for $($p.Id)" } }; $h }
    $before = & $cpuTimes
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $prev = Get-IgwtProcessorRawSample
    for ($i = 0; $i -lt $Samples; $i++) {
        Start-Sleep -Seconds 1
        $cur = Get-IgwtProcessorRawSample
        $pair = ConvertFrom-IgwtProcessorRawPair -First $prev -Second $cur
        if ($pair) { $rows.Add($pair) }
        $prev = $cur
    }
    if ($rows.Count -eq 0) { throw 'The processor counters did not advance.' }
    $list = $rows.ToArray()
    $stat = { param($p) $m = $list | Measure-Object -Property $p -Average -Maximum; [pscustomobject]@{ Average = [Math]::Round([double]$m.Average, 3); Max = [Math]::Round([double]$m.Maximum, 3) } }
    # Top processes: CPU time used during the sampling window, as a share of all logical processors.
    $after = & $cpuTimes
    $window = [Math]::Max(0.5, $clock.Elapsed.TotalSeconds) * [Math]::Max(1, [Environment]::ProcessorCount)
    $procs = @($after.Keys | Where-Object { $before.ContainsKey($_) -and $_ -ne 0 } | ForEach-Object {
            $b = $before[$_]; $a = $after[$_]
            [pscustomobject]@{ Name = $a.Name; ProcessId = [int]$_; CpuPercent = [Math]::Round([Math]::Max([double]0, [double](100 * ($a.Cpu - $b.Cpu) / $window)), 2); WorkingSetMB = [Math]::Round($a.WorkingSet / 1MB, 1) }
        } | Sort-Object CpuPercent, WorkingSetMB -Descending | Select-Object -First $Top)
    $dpc = & $stat 'Dpc'; $isr = & $stat 'Isr'
    $advice = New-Object System.Collections.Generic.List[string]
    if ($dpc.Average -ge 2 -or $isr.Average -ge 1) { $advice.Add('DPC or interrupt time is high for an idle desktop. Run LatencyMon to find the driver; update chipset, network, audio and GPU drivers first.') }
    elseif ($dpc.Max -ge 5) { $advice.Add('Short DPC spikes were measured. Check again while idle; if they repeat, LatencyMon names the driver.') }
    [pscustomobject]@{
        Samples   = $list
        Dpc       = $dpc
        Isr       = $isr
        DpcRate   = & $stat 'DpcRate'
        Interrupts = & $stat 'InterruptsPerSec'
        Cpu       = & $stat 'Cpu'
        TopProcesses = $procs
        Advice    = $advice.ToArray()
        Note      = 'Percentages of total CPU time across all cores. Below 1 % DPC and 0.5 % ISR while idle is normal. Measure while the PC is otherwise idle.'
    }
}

function Get-IgwtReliabilityHistory {
    <# .SYNOPSIS Reliability Monitor data: stability index trend and recent reliability records (read-only). #>
    [CmdletBinding()]
    param([ValidateRange(1, 365)][int]$Days = 30, [ValidateRange(1, 500)][int]$Max = 100)
    $since = (Get-Date).AddDays(-$Days)
    $index = @(); $records = @(); $err = ''
    try {
        $index = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction Stop | Where-Object { $_.TimeGenerated -ge $since } |
                Sort-Object TimeGenerated | ForEach-Object { [pscustomobject]@{ Time = $_.TimeGenerated; Index = [Math]::Round([double]$_.SystemStabilityIndex, 2) } })
    } catch { $err = 'Reliability metrics unavailable (the RacTask scheduled task collects them).' }
    try {
        $records = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop | Where-Object { $_.TimeGenerated -ge $since } |
                Sort-Object TimeGenerated -Descending | Select-Object -First $Max | ForEach-Object {
                    [pscustomobject]@{ Time = $_.TimeGenerated; Source = [string]$_.SourceName; Product = [string]$_.ProductName; EventId = [int]$_.EventIdentifier; Message = ([string]$_.Message -replace '\s+', ' ').Trim() }
                })
    } catch { if (-not $err) { $err = 'Reliability records unavailable.' } }
    [pscustomobject]@{
        Days = $Days; Index = $index; Current = $(if ($index.Count) { $index[$index.Count - 1].Index } else { $null })
        Records = $records; Error = $err; Note = 'Stability index from 1 (unstable) to 10 (stable), the same data as Reliability Monitor (perfmon /rel).'
    }
}

function Get-IgwtEventSafe {
    <# .SYNOPSIS Get-WinEvent with a filter hashtable; returns an empty list when the log has no match or is unreadable. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Filter, [int]$Max = 50)
    try { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) } catch { @() }
}

function Get-IgwtCrashHistory {
    <#
    .SYNOPSIS
        Crashes from the event logs: BugCheck (blue screens), Kernel-Power 41 (lost power or hard
        hang), EventLog 6008 (unexpected shutdown) and application crashes (event 1000), plus the
        minidump list.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 365)][int]$Days = 30)
    $since = (Get-Date).AddDays(-$Days)
    $rows = New-Object System.Collections.Generic.List[object]
    $specs = @(
        @{ Kind = 'BugCheck'; Filter = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since } }
        @{ Kind = 'KernelPower41'; Filter = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since } }
        @{ Kind = 'UnexpectedShutdown'; Filter = @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008; StartTime = $since } }
        @{ Kind = 'AppCrash'; Filter = @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $since } }
    )
    foreach ($s in $specs) {
        foreach ($ev in @(Get-IgwtEventSafe -Filter $s.Filter -Max 50)) {
            $msg = ([string]$ev.Message -replace '\s+', ' ').Trim()
            $detail = $msg
            if ($s.Kind -eq 'BugCheck' -and $msg -match '(0x[0-9a-fA-F]{8})') { $detail = "Stop code $($Matches[1]). $msg" }
            elseif ($s.Kind -eq 'AppCrash' -and $ev.Properties.Count -ge 4) { $detail = "$($ev.Properties[0].Value) crashed in $($ev.Properties[3].Value)" }
            $rows.Add([pscustomobject]@{ Time = $ev.TimeCreated; Kind = $s.Kind; EventId = [int]$ev.Id; Detail = $(if ($detail.Length -gt 300) { $detail.Substring(0, 300) } else { $detail }) })
        }
    }
    $crash = Get-IgwtCrashInspection
    $minis = @()
    try { if (Test-Path -LiteralPath $crash.MinidumpFolder) { $minis = @(Get-ChildItem -LiteralPath $crash.MinidumpFolder -Filter '*.dmp' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Time = $_.LastWriteTime; SizeKB = [Math]::Round($_.Length / 1KB) } }) } }
    catch { $minis = @() }
    $list = @($rows.ToArray() | Sort-Object Time -Descending)
    $count = { param($k) @($list | Where-Object { $_.Kind -eq $k }).Count }
    $advice = New-Object System.Collections.Generic.List[string]
    if ((& $count 'BugCheck') -gt 0) { $advice.Add('Blue screens were recorded. The stop code and the minidump (WinDbg: !analyze -v) name the cause; undo recent overclocks and update drivers first.') }
    if ((& $count 'KernelPower41') -gt (& $count 'BugCheck')) { $advice.Add('Kernel-Power 41 without a blue screen usually means a hard hang or power loss: check memory/CPU stability (XMP, undervolt), PSU and the latest BIOS microcode.') }
    [pscustomobject]@{
        Days = $Days; Events = $list
        Counts = [pscustomobject]@{ BugCheck = & $count 'BugCheck'; KernelPower41 = & $count 'KernelPower41'; UnexpectedShutdown = & $count 'UnexpectedShutdown'; AppCrash = & $count 'AppCrash' }
        Minidumps = $minis; MinidumpFolder = $crash.MinidumpFolder; DumpType = $crash.DumpTypeName; Advice = $advice.ToArray()
        Note = 'Read-only. Minidumps are never deleted here; the cleaner handles them with its own rule.'
    }
}

function Get-IgwtBootPerformance {
    <# .SYNOPSIS Boot durations from Diagnostics-Performance event 100 (administrator rights needed to read that log). #>
    [CmdletBinding()]
    param([ValidateRange(1, 100)][int]$Max = 10)
    $events = @(Get-IgwtEventSafe -Filter @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -Max $Max)
    $rows = foreach ($ev in $events) {
        $data = @{}
        try { foreach ($d in ([xml]$ev.ToXml()).Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' } } catch { Write-Verbose 'Event XML unreadable.' }
        $ms = { param($n) if ($data.ContainsKey($n) -and $data[$n] -match '^\d+$') { [long]$data[$n] } else { $null } }
        [pscustomobject]@{ Time = $ev.TimeCreated; BootMs = & $ms 'BootTime'; MainPathMs = & $ms 'MainPathBootTime'; PostBootMs = & $ms 'BootPostBootTime'; Degraded = ([string]$ev.LevelDisplayName -ne 'Information') }
    }
    $rows = @($rows)
    [pscustomobject]@{
        Boots = $rows
        AverageBootSeconds = $(if (@($rows | Where-Object { $_.BootMs }).Count) { [Math]::Round((@($rows | Where-Object { $_.BootMs }) | Measure-Object -Property BootMs -Average).Average / 1000, 1) } else { $null })
        Error = $(if ($rows.Count -eq 0) { 'No boot records readable (the Diagnostics-Performance log needs administrator rights).' } else { '' })
        Note = 'MainPath is the time to the desktop; PostBoot is the time until the system is idle. Startup apps mostly add PostBoot time.'
    }
}

function Get-IgwtDriverInventory {
    <#
    .SYNOPSIS
        Signed PnP drivers with device, class, version, date, provider and signer. Flags unsigned
        drivers and non-Microsoft drivers older than three years.
    #>
    [CmdletBinding()]
    param([switch]$IncludeMicrosoft)
    $cut = (Get-Date).AddYears(-3)
    $rows = foreach ($d in @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.DeviceName -and $_.DriverVersion })) {
        $ms = ([string]$d.DriverProviderName -eq 'Microsoft')
        if ($ms -and -not $IncludeMicrosoft) { continue }
        $date = $d.DriverDate
        $flag = ''
        # Intel chipset INFs use the placeholder date 1968-07-18 on purpose (so any real driver ranks higher); not old.
        if (-not $d.IsSigned) { $flag = 'Unsigned' } elseif (-not $ms -and $date -and $date -lt $cut -and $date.Year -ge 2000) { $flag = 'Old' }
        [pscustomobject]@{
            Device = [string]$d.DeviceName; Class = [string]$d.DeviceClass; Version = [string]$d.DriverVersion; Date = $(if ($date) { $date.ToString('yyyy-MM-dd') } else { '' })
            Provider = [string]$d.DriverProviderName; Signer = [string]$d.Signer; Inf = [string]$d.InfName; Signed = [bool]$d.IsSigned; Flag = $flag
        }
    }
    $rows = @($rows | Sort-Object Class, Device)
    [pscustomobject]@{
        Drivers = $rows
        Counts = [pscustomobject]@{ Total = $rows.Count; Unsigned = @($rows | Where-Object { $_.Flag -eq 'Unsigned' }).Count; Old = @($rows | Where-Object { $_.Flag -eq 'Old' }).Count }
        Note = 'Read-only. Old is a hint, not a fault: some devices never get newer drivers. Update GPU, chipset, network and audio drivers from the vendor.'
    }
}

function Get-IgwtDiagnostics {
    <# .SYNOPSIS Runs the selected diagnostics (DpcIsr, Reliability, Crashes, Boot, Drivers); each failure is reported, not thrown. #>
    [CmdletBinding()]
    param([ValidateSet('DpcIsr', 'Reliability', 'Crashes', 'Boot', 'Drivers')][string[]]$Area = @('DpcIsr', 'Reliability', 'Crashes', 'Boot', 'Drivers'), [int]$Days = 30, [int]$Samples = 5)
    $out = [ordered]@{ Generated = (Get-Date).ToString('o') }
    foreach ($a in $Area) {
        try {
            $out[$a] = switch ($a) {
                'DpcIsr' { Get-IgwtDpcIsrSample -Samples $Samples }
                'Reliability' { Get-IgwtReliabilityHistory -Days $Days }
                'Crashes' { Get-IgwtCrashHistory -Days $Days }
                'Boot' { Get-IgwtBootPerformance }
                'Drivers' { Get-IgwtDriverInventory }
            }
        } catch { $out[$a] = [pscustomobject]@{ Error = $_.Exception.Message } }
    }
    return [pscustomobject]$out
}

function Format-IgwtDiagnostics {
    <# .SYNOPSIS Plain-text rendering of Get-IgwtDiagnostics. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Diagnostics)
    $sb = New-Object System.Text.StringBuilder
    $p = $Diagnostics.PSObject.Properties
    if ($p['DpcIsr'] -and -not $Diagnostics.DpcIsr.PSObject.Properties['Error']) {
        $d = $Diagnostics.DpcIsr
        $null = $sb.AppendLine("[DPC / ISR] DPC avg $($d.Dpc.Average) % (max $($d.Dpc.Max) %), ISR avg $($d.Isr.Average) % (max $($d.Isr.Max) %), $([Math]::Round($d.Interrupts.Average)) interrupts/s")
        foreach ($t in @($d.TopProcesses | Select-Object -First 5)) { $null = $sb.AppendLine(('    {0,-30} {1,5} % CPU  {2,8} MB' -f $t.Name, $t.CpuPercent, $t.WorkingSetMB)) }
        foreach ($a in $d.Advice) { $null = $sb.AppendLine("    -> $a") }
    }
    if ($p['Reliability'] -and -not $Diagnostics.Reliability.PSObject.Properties['Records']) { $null = $sb.AppendLine("[Reliability] $($Diagnostics.Reliability.Error)") }
    elseif ($p['Reliability']) {
        $r = $Diagnostics.Reliability
        $null = $sb.AppendLine("[Reliability] Stability index: $(if ($null -ne $r.Current) { $r.Current } else { 'n/a' }); $(@($r.Records).Count) records in $($r.Days) days $(if ($r.Error) { "($($r.Error))" })")
        foreach ($x in @($r.Records | Select-Object -First 8)) { $null = $sb.AppendLine("    $($x.Time) $($x.Source): $($x.Product)") }
    }
    if ($p['Crashes'] -and $Diagnostics.Crashes.PSObject.Properties['Counts']) {
        $c = $Diagnostics.Crashes
        $null = $sb.AppendLine("[Crashes, $($c.Days) days] BugCheck $($c.Counts.BugCheck), Kernel-Power 41 $($c.Counts.KernelPower41), unexpected shutdown $($c.Counts.UnexpectedShutdown), app crashes $($c.Counts.AppCrash); minidumps $(@($c.Minidumps).Count) ($($c.DumpType))")
        foreach ($x in @($c.Events | Where-Object { $_.Kind -ne 'AppCrash' } | Select-Object -First 8)) { $null = $sb.AppendLine("    $($x.Time) $($x.Kind): $($x.Detail)") }
        foreach ($a in $c.Advice) { $null = $sb.AppendLine("    -> $a") }
    }
    if ($p['Boot'] -and $Diagnostics.Boot.PSObject.Properties['Boots']) {
        $b = $Diagnostics.Boot
        $null = $sb.AppendLine("[Boot] $(if ($b.Error) { $b.Error } else { "Average boot $($b.AverageBootSeconds) s over $(@($b.Boots).Count) boots" })")
        foreach ($x in @($b.Boots | Select-Object -First 5)) { $null = $sb.AppendLine("    $($x.Time) total $($x.BootMs) ms, main path $($x.MainPathMs) ms, post boot $($x.PostBootMs) ms") }
    }
    if ($p['Drivers'] -and $Diagnostics.Drivers.PSObject.Properties['Counts']) {
        $dr = $Diagnostics.Drivers
        $null = $sb.AppendLine("[Drivers] $($dr.Counts.Total) non-Microsoft drivers, $($dr.Counts.Unsigned) unsigned, $($dr.Counts.Old) older than three years")
        foreach ($x in @($dr.Drivers | Where-Object { $_.Flag } | Select-Object -First 10)) { $null = $sb.AppendLine("    [$($x.Flag)] $($x.Device) $($x.Version) $($x.Date) ($($x.Provider))") }
    }
    foreach ($a in $p) { if ($a.Value -and $a.Value.PSObject.Properties['Error'] -and $a.Value.PSObject.Properties.Name.Count -eq 1) { $null = $sb.AppendLine("[$($a.Name)] error: $($a.Value.Error)") } }
    return $sb.ToString()
}
