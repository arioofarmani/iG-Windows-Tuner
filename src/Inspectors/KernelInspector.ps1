# KernelInspector.ps1
# Read-only kernel, memory, timer and crash-dump inspectors.
#   - Kernel and memory: every value under Session Manager\kernel, Memory Management,
#     PriorityControl, Multimedia\SystemProfile (+ the Games task) and CrashControl, annotated from
#     data\inspectors\kernel.json with meaning, Windows default and the catalog item (the only way to
#     change it) or the rejected entry that explains why iG Windows Tuner leaves it alone.
#   - Timer: the GlobalTimerResolutionRequests setting and how to see current requests.
#   - Crash and page file: dump type, dump files on disk, verbose status messages and page files.

function Get-IgwtKernelInspectorCatalog {
    <# .SYNOPSIS Registry keys and documented values from data\inspectors\kernel.json (cached). #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtKernelInspectorCache -and -not $Force) { return $script:IgwtKernelInspectorCache }
    $file = Join-Path (Get-IgwtDataFolder) 'inspectors\kernel.json'
    $keys = @()
    if (Test-Path -LiteralPath $file) { $keys = @((Read-IgwtJsonFile -Path $file).keys | Where-Object { $_ }) }
    $script:IgwtKernelInspectorCache = $keys
    return $keys
}

function Test-IgwtKernelInspectorCatalog {
    <# .SYNOPSIS Validates data\inspectors\kernel.json (paths, texts, linked catalog and rejected ids). Returns error strings. #>
    [CmdletBinding()]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $file = Join-Path (Get-IgwtDataFolder) 'inspectors\kernel.json'
    if (-not (Test-Path -LiteralPath $file)) { $errors.Add('inspectors\kernel.json: missing (kernel and memory inspector).'); return $errors.ToArray() }
    if ((Get-IgwtFileSchemaVersion -Document (Read-IgwtJsonFile -Path $file)) -lt $script:IgwtSchemaVersion) { $errors.Add('inspectors\kernel.json: schemaVersion must be 2.') }
    $tweakIds = @{}; foreach ($t in @(Get-IgwtCatalog)) { $tweakIds[[string]$t.id] = $true }
    $rejectedIds = @{}; foreach ($r in @(Get-IgwtRejectedTweaks)) { $rejectedIds[[string]$r.id] = $true }
    $seen = @{}
    foreach ($k in @(Get-IgwtKernelInspectorCatalog -Force)) {
        $label = "inspector key '$($k.id)'"
        if ($seen.ContainsKey([string]$k.id)) { $errors.Add("${label}: duplicate id.") } else { $seen[[string]$k.id] = $true }
        if ([string]$k.path -notmatch '^HKLM:\\') { $errors.Add("${label}: path must start with HKLM:\.") }
        Test-IgwtItemText -Item $k -Label $label -Errors $errors
        $names = @{}
        foreach ($v in @($k.values | Where-Object { $_ })) {
            $vl = "$label value '$($v.name)'"
            if (-not $v.name) { $errors.Add("${label}: a value has no name."); continue }
            if ($names.ContainsKey(([string]$v.name).ToLowerInvariant())) { $errors.Add("${vl}: duplicate.") } else { $names[([string]$v.name).ToLowerInvariant()] = $true }
            if (([string]$v.meaning).Trim().Length -lt 15) { $errors.Add("${vl}: needs a meaning.") }
            if ($null -eq $v.PSObject.Properties['default']) { $errors.Add("${vl}: needs the Windows default (or <absent>).") }
            if ($v.item -and -not $tweakIds.ContainsKey([string]$v.item)) { $errors.Add("${vl}: unknown catalog item '$($v.item)'.") }
            if ($v.rejected -and -not $rejectedIds.ContainsKey([string]$v.rejected)) { $errors.Add("${vl}: unknown rejected entry '$($v.rejected)'.") }
            foreach ($u in @($v.sources | Where-Object { $_ })) { if ([string]$u -notmatch '^https://') { $errors.Add("${vl}: source '$u' must be https.") } }
        }
    }
    return $errors.ToArray()
}

function ConvertTo-IgwtDwordNumber {
    <# .SYNOPSIS A REG_DWORD as an unsigned number (the registry API returns DWORDs as signed Int32). #>
    [CmdletBinding()]
    [OutputType([uint32])]
    param([Parameter(Mandatory = $true)]$Value)
    if ($Value -is [int]) { return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Value), 0) }
    $n = [int64]$Value
    if ($n -lt 0) { return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$n), 0) }
    return [uint32]$n
}

function Format-IgwtRegistryDisplay {
    <# .SYNOPSIS Short display text for a registry value (DWORDs above 9999 also in hex, binary as a length). #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value, [string]$Kind)
    if ($null -eq $Value) { return '' }
    switch ($Kind) {
        'Binary' { return "binary ($(@($Value).Count) bytes)" }
        'MultiString' { return (@($Value) -join '; ') }
        'DWord' {
            $u = ConvertTo-IgwtDwordNumber -Value $Value
            if ($u -gt 9999) { return ('{0} (0x{1:X8})' -f $u, $u) }
            return [string]$u
        }
        'QWord' { return [string]$Value }
        default { return [string]$Value }
    }
}

function Test-IgwtInspectorValueDefault {
    <# .SYNOPSIS True when a current value equals a documented default (numbers, strings or string lists). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Current, [string]$Kind, $Default)
    if ($Default -is [array] -or $Kind -eq 'MultiString') { return ((@($Current) -join '|').ToLowerInvariant() -eq (@($Default) -join '|').ToLowerInvariant()) }
    if ($Kind -eq 'DWord') {
        $n = 0L
        if (-not [long]::TryParse([string]$Default, [ref]$n)) { return $false }
        return ((ConvertTo-IgwtDwordNumber -Value $Current) -eq (ConvertTo-IgwtDwordNumber -Value $n))
    }
    if ($Kind -eq 'QWord') { return ([string]$Current -eq [string]$Default) }
    return [string]::Equals([string]$Current, [string]$Default, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-IgwtKernelInspection {
    <#
    .SYNOPSIS
        Read-only view of the kernel, memory, priority, multimedia and crash registry keys. Each
        value shows its current data, the Windows default when documented, a status (Default,
        Changed, Absent, Undocumented) and the catalog item or rejected entry it belongs to.
    #>
    [CmdletBinding()]
    param()
    $keys = foreach ($k in @(Get-IgwtKernelInspectorCatalog)) {
        $known = @{}; foreach ($v in @($k.values | Where-Object { $_ })) { $known[([string]$v.name).ToLowerInvariant()] = $v }
        $actual = @{}
        $readable = $true
        try {
            $item = Get-Item -LiteralPath (Resolve-IgwtRegistryPath ([string]$k.path)) -ErrorAction Stop
            foreach ($n in $item.GetValueNames()) {
                if (-not $n) { continue }
                $actual[$n.ToLowerInvariant()] = [pscustomobject]@{ Name = $n; Kind = $item.GetValueKind($n).ToString(); Value = $item.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
            }
        } catch { $readable = $false }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($lower in @($actual.Keys | Sort-Object)) {
            $a = $actual[$lower]; $meta = $known[$lower]
            $status = 'Undocumented'; $defText = ''
            if ($meta) {
                $defText = $(if ([string]$meta.default -eq '<absent>') { 'not set' } else { Format-IgwtRegistryDisplay -Value $meta.default -Kind $a.Kind })
                if ([string]$meta.default -eq '<absent>') {
                    $status = 'Changed'
                    if ($null -ne $meta.PSObject.Properties['absentMeans'] -and (Test-IgwtInspectorValueDefault -Current $a.Value -Kind $a.Kind -Default $meta.absentMeans)) { $status = 'Default' }
                } elseif (Test-IgwtInspectorValueDefault -Current $a.Value -Kind $a.Kind -Default $meta.default) { $status = 'Default' } else { $status = 'Changed' }
            }
            $rows.Add([pscustomobject]@{
                    Name = $a.Name; Kind = $a.Kind; Current = (Format-IgwtRegistryDisplay -Value $a.Value -Kind $a.Kind); Default = $defText; Status = $status
                    Meaning = $(if ($meta) { [string]$meta.meaning } else { 'Not documented by iG Windows Tuner. Leave it unless its vendor documents it.' })
                    Item = $(if ($meta) { [string]$meta.item } else { '' }); Rejected = $(if ($meta) { [string]$meta.rejected } else { '' })
                    Sources = $(if ($meta) { @($meta.sources) } else { @() })
                })
        }
        foreach ($lower in @($known.Keys | Sort-Object)) {
            if ($actual.ContainsKey($lower)) { continue }
            $meta = $known[$lower]
            $isDefault = ([string]$meta.default -eq '<absent>')
            $rows.Add([pscustomobject]@{
                    Name = [string]$meta.name; Kind = ''; Current = 'not set'; Default = $(if ($isDefault) { 'not set' } else { Format-IgwtRegistryDisplay -Value $meta.default -Kind $(if ($meta.default -is [array]) { 'MultiString' } elseif ($meta.default -is [string]) { 'String' } else { 'DWord' }) })
                    Status = $(if ($isDefault) { 'Default' } else { 'Absent' }); Meaning = [string]$meta.meaning; Item = [string]$meta.item; Rejected = [string]$meta.rejected; Sources = @($meta.sources)
                })
        }
        [pscustomobject]@{
            Id = [string]$k.id; Name = [string]$k.name; Path = [string]$k.path; Hint = [string]$k.hint; Description = [string]$k.description; Readable = $readable
            Values = $rows.ToArray(); Changed = @($rows | Where-Object { $_.Status -eq 'Changed' }).Count
        }
    }
    $keys = @($keys)
    [pscustomobject]@{
        Keys    = $keys
        Changed = [int](($keys | Measure-Object -Property Changed -Sum).Sum)
        Note    = 'Read-only. Values can be changed only through the linked catalog item; values linked to a rejected entry are explained and left alone.'
    }
}

function Get-IgwtTimerInspection {
    <# .SYNOPSIS Timer settings (read-only): GlobalTimerResolutionRequests and how to see current resolution requests. #>
    [CmdletBinding()]
    param()
    $v = $null
    try { $v = Get-IgwtRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'GlobalTimerResolutionRequests' } catch { $v = $null }
    $on = ($v -and $v.Exists -and [int]$v.Value -eq 1)
    [pscustomobject]@{
        GlobalTimerResolutionRequests = $(if ($v -and $v.Exists) { [int]$v.Value } else { $null })
        Behaviour  = $(if ($on) { 'Global: one process''s timer-resolution request affects the whole system (pre-2004 behaviour).' } else { 'Per process (Windows default since Windows 10 2004): each process gets the resolution it asks for; minimized or occluded windows are ignored on Windows 11.' })
        Item       = 'sched.global-timer-resolution'
        CurrentResolution = $null
        Note       = 'The current timer resolution is not shown: reading it needs an undocumented native call (NtQueryTimerResolution) and iG Windows Tuner keeps a single, documented P/Invoke. As administrator, "powercfg /energy" lists the processes that request a higher timer resolution.'
        Sources    = @('https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod')
    }
}

function Get-IgwtCrashInspection {
    <# .SYNOPSIS Crash dump, stop screen, verbose status and page file configuration (read-only). #>
    [CmdletBinding()]
    param()
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $read = { param($p, $n) try { $r = Get-IgwtRegistryValue -Path $p -Name $n; if ($r.Exists) { $r.Value } else { $null } } catch { $null } }
    $dumpType = & $read $cc 'CrashDumpEnabled'
    $dumpNames = @{ 0 = 'None'; 1 = 'Complete memory dump'; 2 = 'Kernel memory dump'; 3 = 'Small memory dump (minidump)'; 7 = 'Automatic memory dump (Windows default)' }
    $dumpFile = [string](& $read $cc 'DumpFile'); if (-not $dumpFile) { $dumpFile = '%SystemRoot%\MEMORY.DMP' }
    $miniDir = [string](& $read $cc 'MinidumpDir'); if (-not $miniDir) { $miniDir = '%SystemRoot%\Minidump' }
    $dumpPath = [Environment]::ExpandEnvironmentVariables($dumpFile)
    $miniPath = [Environment]::ExpandEnvironmentVariables($miniDir)
    $dumpSize = $null
    try { if (Test-Path -LiteralPath $dumpPath -PathType Leaf) { $dumpSize = (Get-Item -LiteralPath $dumpPath -Force -ErrorAction Stop).Length } } catch { $dumpSize = $null }
    $minis = @()
    try { if (Test-Path -LiteralPath $miniPath) { $minis = @(Get-ChildItem -LiteralPath $miniPath -Filter '*.dmp' -File -ErrorAction Stop) } } catch { $minis = @() }
    $paging = & $read 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'PagingFiles'
    $pagingList = @($paging | Where-Object { $null -ne $_ -and [string]$_ -ne '' } | ForEach-Object { [string]$_ })
    $mode = 'Custom'
    if ($pagingList.Count -eq 0) { $mode = 'None' }
    elseif ($pagingList.Count -eq 1 -and $pagingList[0] -match '^\?:\\pagefile\.sys$') { $mode = 'SystemManagedAllDrives' }
    elseif (@($pagingList | Where-Object { $_ -notmatch '\s0\s+0\s*$' -and $_ -notmatch '^[A-Za-z]:\\pagefile\.sys$' }).Count -eq 0) { $mode = 'SystemManaged' }
    $usage = @()
    try { $usage = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Path = [string]$_.Name; AllocatedMB = [int]$_.AllocatedBaseSize; CurrentMB = [int]$_.CurrentUsage; PeakMB = [int]$_.PeakUsage } }) } catch { $usage = @() }
    $verbose = & $read 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'VerboseStatus'
    $advice = New-Object System.Collections.Generic.List[string]
    if ($mode -eq 'None') { $advice.Add('No page file is configured. Windows needs one for crash dumps and as commit headroom; never disable it (see rejected.pagefile-off). Catalog item system.pagefile-auto restores a system-managed page file.') }
    if ($null -ne $dumpType -and [int]$dumpType -eq 0) { $advice.Add('Crash dumps are off, so a blue screen leaves nothing to analyze. Small or automatic dumps are recommended.') }
    if ($null -ne $dumpSize -and $dumpSize -gt 1GB) { $advice.Add("An old memory dump of $([Math]::Round($dumpSize / 1GB, 1)) GB is on disk ($dumpPath). Settings > System > Storage > Temporary files can remove it once you have analyzed it.") }
    [pscustomobject]@{
        DumpType         = $dumpType
        DumpTypeName     = $(if ($null -ne $dumpType -and $dumpNames.ContainsKey([int]$dumpType)) { $dumpNames[[int]$dumpType] } elseif ($null -eq $dumpType) { 'Not set (automatic)' } else { "Type $dumpType" })
        AutoReboot       = & $read $cc 'AutoReboot'
        DisplayParameters = & $read $cc 'DisplayParameters'
        DumpFile         = $dumpPath
        DumpFileBytes    = $dumpSize
        MinidumpFolder   = $miniPath
        Minidumps        = $minis.Count
        MinidumpBytes    = [long](($minis | Measure-Object -Property Length -Sum).Sum)
        LatestMinidump   = $(if ($minis.Count) { ($minis | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime } else { $null })
        VerboseStatus    = $verbose
        PageFileMode     = $mode
        PagingFiles      = $pagingList
        PageFiles        = $usage
        Advice           = $advice.ToArray()
        Items            = @('system.dump-small', 'system.bsod-details', 'system.verbose-status', 'system.pagefile-auto')
    }
}
