# FirewallLog.ps1
# Windows Firewall as a detection source: per-profile logging status, a parser and analyzer for
# the W3C firewall log (pfirewall.log: top blocked sources, ports and apps, an hourly timeline,
# export), and an outbound allow-list builder that produces a reviewable plan only. Logging is
# turned on through the Local GPO (policy preset policy.firewall-logging). iG Windows Tuner never
# creates allow rules or switches outbound traffic to default-block itself (DECISIONS D3).

function Get-IgwtFirewallLoggingStatus {
    <# .SYNOPSIS Logging per firewall profile: dropped and allowed packets, log file and size, with a finding. Read-only. #>
    [CmdletBinding()]
    param()
    foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
        $file = [Environment]::ExpandEnvironmentVariables([string]$p.LogFileName)
        $dropped = [string]$p.LogBlocked -eq 'True'
        [pscustomobject]@{
            Profile = [string]$p.Name; Enabled = [string]$p.Enabled -eq 'True'
            LogBlocked = [string]$p.LogBlocked; LogAllowed = [string]$p.LogAllowed; LogFile = $file; MaxSizeKB = [int]$p.LogMaxSizeKilobytes
            DefaultOutbound = [string]$p.DefaultOutboundAction
            Finding = $(if (-not $dropped) { 'Dropped packets are not logged; turn it on with the Firewall Logging policy preset to see what the firewall blocks.' } elseif ([int]$p.LogMaxSizeKilobytes -lt 16384) { 'The log is under 16 MB and fills quickly; the preset sets 32 MB.' } else { '' })
        }
    }
}

function ConvertFrom-IgwtFirewallLogText {
    <#
    .SYNOPSIS
        Parses a W3C firewall log from a TextReader in one pass. The columns come from the file's own
        #Fields: header (the field list differs between Windows versions; DECISIONS F10), never from a
        fixed order. Empty lines are allowed (pfirewall.log has one after the header); comment, data
        lines before a header, lines whose field count does not match the header, and a last line
        still being written are skipped and counted by reason. Pure.
    .PARAMETER Reader
        System.IO.TextReader (StreamReader or StringReader).
    .PARAMETER Partial
        The text does not end with a line break: its last line is still being written and is skipped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.IO.TextReader]$Reader, [switch]$Partial, [int]$Capacity = 1024)
    $entries = New-Object System.Collections.Generic.List[object]($Capacity)
    $skipped = [ordered]@{ Empty = 0; NoHeader = 0; FieldCount = 0; Partial = 0 }
    $fields = $null; $ix = @{}; $n = 0
    $sep = [char[]]@(' ', "`t")
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $line = $Reader.ReadLine()
    while ($null -ne $line) {
        $next = $Reader.ReadLine()
        if ($line.Length -eq 0 -or $line.Trim().Length -eq 0) { $skipped.Empty++; $line = $next; continue }
        if ($line[0] -eq '#') {
            if ($line.StartsWith('#Fields:')) {
                $fields = @($line.Substring(8).Split($sep, [System.StringSplitOptions]::RemoveEmptyEntries))
                $ix = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $ix[$fields[$i]] = $i }
                $n = $fields.Count
            }
            $line = $next; continue
        }
        if ($Partial -and $null -eq $next) { $skipped.Partial++; break }
        if ($null -eq $fields) { $skipped.NoHeader++; $line = $next; continue }
        $p = $line.Split($sep, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($p.Length -ne $n) { $skipped.FieldCount++; $line = $next; continue }
        for ($i = 0; $i -lt $n; $i++) { if ($p[$i] -eq '-') { $p[$i] = '' } }
        $t = $null
        if ($ix.ContainsKey('date') -and $ix.ContainsKey('time')) {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParseExact(($p[$ix['date']] + ' ' + $p[$ix['time']]), 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) { $t = $dt }
        }
        $entries.Add([pscustomobject]@{
                Time = $t
                Action = $(if ($ix.ContainsKey('action')) { $p[$ix['action']] } else { '' })
                Protocol = $(if ($ix.ContainsKey('protocol')) { $p[$ix['protocol']] } else { '' })
                Source = $(if ($ix.ContainsKey('src-ip')) { $p[$ix['src-ip']] } else { '' })
                Destination = $(if ($ix.ContainsKey('dst-ip')) { $p[$ix['dst-ip']] } else { '' })
                SourcePort = $(if ($ix.ContainsKey('src-port')) { $p[$ix['src-port']] } else { '' })
                DestinationPort = $(if ($ix.ContainsKey('dst-port')) { $p[$ix['dst-port']] } else { '' })
                Size = $(if ($ix.ContainsKey('size')) { $p[$ix['size']] } else { '' })
                TcpFlags = $(if ($ix.ContainsKey('tcpflags')) { $p[$ix['tcpflags']] } else { '' })
                Info = $(if ($ix.ContainsKey('info')) { $p[$ix['info']] } else { '' })
                # The raw "path" value (SEND, RECEIVE, ...): shown as written in the log (DECISIONS F10).
                Direction = $(if ($ix.ContainsKey('path')) { $p[$ix['path']] } else { '' })
                ProcessId = $(if ($ix.ContainsKey('pid')) { $p[$ix['pid']] } else { '' })
            })
        $line = $next
    }
    [pscustomobject]@{ Fields = $(if ($fields) { $fields } else { @() }); Entries = $entries; Skipped = $skipped }
}

function ConvertFrom-IgwtFirewallLog {
    <#
    .SYNOPSIS
        Parses W3C firewall log lines (see ConvertFrom-IgwtFirewallLogText; the #Fields header names
        the columns). Empty lines are allowed. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][AllowNull()][string[]]$Lines)
    $reader = New-Object System.IO.StringReader((@($Lines) -join "`n"))
    try { return (ConvertFrom-IgwtFirewallLogText -Reader $reader).Entries.ToArray() } finally { $reader.Dispose() }
}

function Open-IgwtFirewallLogStream {
    <#
    .SYNOPSIS
        Opens a firewall log for reading while the firewall service keeps writing (and may rotate) it:
        FileShare ReadWrite and Delete. Throws the original .NET exception (access denied, not found,
        sharing violation) for Read-IgwtFirewallLogFile to classify. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    return (New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share, 65536, [System.IO.FileOptions]::SequentialScan))
}

function Get-IgwtFirewallLogReadProblem {
    <#
    .SYNOPSIS
        Turns an exception from opening a firewall log into a reason and an actionable message:
        AccessDenied (not elevated), NotFound, FolderNotFound, Locked, Error. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Exception]$Exception, [Parameter(Mandatory = $true)][string]$Path)
    $ex = $Exception
    while ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
    $folder = Split-Path -Parent $Path
    if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException]) {
        return [pscustomobject]@{ Reason = 'AccessDenied'; Message = "Reading the firewall log needs administrator rights: Windows protects $folder. Use Restart as administrator and analyze again." }
    }
    if ($ex -is [System.IO.DirectoryNotFoundException]) {
        return [pscustomobject]@{ Reason = 'FolderNotFound'; Message = "The log folder $folder does not exist. Windows does not create a custom log folder: create it and give the Windows Defender Firewall service (NT SERVICE\mpssvc) write access, or use the default path %windir%\system32\LogFiles\Firewall\pfirewall.log." }
    }
    if ($ex -is [System.IO.FileNotFoundException]) {
        return [pscustomobject]@{ Reason = 'NotFound'; Message = "The log file $Path does not exist yet. Windows writes it once logging is on for a profile and the firewall has logged a packet; use the PC for a while and analyze again. If it stays missing, check that the Windows Defender Firewall service (NT SERVICE\mpssvc) can write to $folder." }
    }
    if ($ex -is [System.IO.IOException] -and (($ex.HResult -band 0xFFFF) -in 32, 33)) {
        return [pscustomobject]@{ Reason = 'Locked'; Message = "The log file $Path is locked by another program (sharing violation). Close programs that have it open and analyze again." }
    }
    return [pscustomobject]@{ Reason = 'Error'; Message = "The firewall log $Path could not be read: $($ex.Message)" }
}

function Read-IgwtFirewallLogFile {
    <#
    .SYNOPSIS
        Reads one firewall log file with a streaming reader (shared open, see Open-IgwtFirewallLogStream)
        and parses it by its #Fields header. Never throws for a file problem: the result carries
        Reason (Ok, AccessDenied, NotFound, FolderNotFound, Locked, Error) and an actionable Message.
        A last line without a line break (still being written) is skipped. Read-only.
    .PARAMETER MaxLines
        Keep only the newest entries (0 = all).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [int]$MaxLines = 0)
    $res = [ordered]@{ Path = $Path; Reason = 'Ok'; Message = ''; Fields = @(); Entries = @(); Skipped = [ordered]@{}; Bytes = [long]0; ReadMs = 0 }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $fs = $null
    try { $fs = Open-IgwtFirewallLogStream -Path $Path }
    catch {
        $problem = Get-IgwtFirewallLogReadProblem -Exception $_.Exception -Path $Path
        $res.Reason = $problem.Reason; $res.Message = $problem.Message
        return [pscustomobject]$res
    }
    try {
        $res.Bytes = $fs.Length
        $partial = $false
        if ($fs.Length -gt 0) {
            $null = $fs.Seek(-1, [System.IO.SeekOrigin]::End)
            $partial = ($fs.ReadByte() -ne 10)
            $null = $fs.Seek(0, [System.IO.SeekOrigin]::Begin)
        }
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true, 65536)
        # About 110 bytes per line in a typical log: pre-size the list.
        $parsed = ConvertFrom-IgwtFirewallLogText -Reader $sr -Partial:$partial -Capacity ([int][Math]::Min([double]2000000, [Math]::Max([double]1024, [double]($fs.Length / 110))))
        $sr.Dispose()
        $all = $parsed.Entries
        $res.Fields = $parsed.Fields; $res.Skipped = $parsed.Skipped
        $res.Entries = $(if ($MaxLines -gt 0 -and $all.Count -gt $MaxLines) { $all.GetRange($all.Count - $MaxLines, $MaxLines).ToArray() } else { $all.ToArray() })
        if (-not $parsed.Fields.Count -and $all.Count -eq 0 -and $fs.Length -gt 0) { $res.Reason = 'Error'; $res.Message = "$Path has no #Fields: header; it does not look like a Windows Firewall log." }
    } catch {
        $problem = Get-IgwtFirewallLogReadProblem -Exception $_.Exception -Path $Path
        $res.Reason = $problem.Reason; $res.Message = $problem.Message
    } finally { $fs.Dispose() }
    $res.ReadMs = [int]$watch.ElapsedMilliseconds
    return [pscustomobject]$res
}

function Get-IgwtFirewallLogFiles {
    <#
    .SYNOPSIS
        The log files of the profiles that log something (expanded paths, each once), with the
        profiles that write to each and the profiles that log nothing. Read-only.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Status)
    if ($null -eq $Status) { $Status = @(Get-IgwtFirewallLoggingStatus) }
    $on = @($Status | Where-Object { $_.LogBlocked -eq 'True' -or $_.LogAllowed -eq 'True' })
    $off = @($Status | Where-Object { -not ($_.LogBlocked -eq 'True' -or $_.LogAllowed -eq 'True') } | ForEach-Object { [string]$_.Profile })
    $files = @($on | Where-Object { $_.LogFile } | Group-Object { ([string]$_.LogFile).ToLowerInvariant() } | ForEach-Object { [pscustomobject]@{ Path = [string]$_.Group[0].LogFile; Profiles = @($_.Group | ForEach-Object { [string]$_.Profile }) } })
    [pscustomobject]@{ Files = $files; ProfilesOff = $off }
}

function Read-IgwtFirewallLog {
    <#
    .SYNOPSIS
        Reads and parses a firewall log (default: the log file of the profiles that log), newest
        -MaxLines entries. With -IncludeOld the rotated <file>.old is read first when it exists.
        Throws an actionable message when the log cannot be read (administrator rights are needed
        for the default log). Read-only.
    #>
    [CmdletBinding()]
    param([string]$Path, [int]$MaxLines = 200000, [switch]$IncludeOld)
    if (-not $Path) {
        $set = Get-IgwtFirewallLogFiles
        if (-not @($set.Files).Count) { throw "Logging is off for every firewall profile ($(@($set.ProfilesOff) -join ', ')). Turn on 'Log blocked connections' on the Profiles and networks tab, use the PC for a while, then analyze again." }
        $Path = [string]@($set.Files)[0].Path
    }
    $out = New-Object System.Collections.Generic.List[object]
    if ($IncludeOld) {
        $old = Read-IgwtFirewallLogFile -Path "$Path.old"
        if ($old.Reason -eq 'Ok') { $out.AddRange([object[]]$old.Entries) }
    }
    $r = Read-IgwtFirewallLogFile -Path $Path
    if ($r.Reason -ne 'Ok') { throw $r.Message }
    $out.AddRange([object[]]$r.Entries)
    if ($MaxLines -gt 0 -and $out.Count -gt $MaxLines) { return $out.GetRange($out.Count - $MaxLines, $MaxLines).ToArray() }
    return $out.ToArray()
}

function Get-IgwtFirewallLogAnalysis {
    <#
    .SYNOPSIS
        Analysis of firewall log entries: counts by action, top blocked sources, top blocked
        destination ports (with protocol), top processes (by process id, named when the process
        still runs), and an hourly timeline of blocked and allowed packets. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [int]$Top = 10)
    $drop = @($Entries | Where-Object { $_.Action -eq 'DROP' })
    $allow = @($Entries | Where-Object { $_.Action -eq 'ALLOW' })
    $proc = @{}
    foreach ($id in @($Entries | Where-Object { $_.ProcessId } | ForEach-Object { $_.ProcessId } | Select-Object -Unique)) { $p = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue; $proc[$id] = $(if ($p) { $p.ProcessName } else { "pid $id (ended)" }) }
    $topOf = { param($set, $sb) @($set | Group-Object -Property $sb | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Value = $_.Name; Count = $_.Count } }) }
    [pscustomobject]@{
        Entries = $Entries.Count; Dropped = $drop.Count; Allowed = $allow.Count
        From = @($Entries | Where-Object Time | Sort-Object Time | Select-Object -First 1).Time; To = @($Entries | Where-Object Time | Sort-Object Time -Descending | Select-Object -First 1).Time
        TopBlockedSources = (& $topOf $drop { $_.Source })
        TopBlockedPorts = (& $topOf $drop { "$($_.Protocol)/$($_.DestinationPort)" })
        TopBlockedProcesses = (& $topOf @($drop | Where-Object ProcessId) { $proc[$_.ProcessId] })
        TopAllowedProcesses = (& $topOf @($allow | Where-Object ProcessId) { $proc[$_.ProcessId] })
        Timeline = @($Entries | Where-Object Time | Group-Object { $_.Time.ToString('yyyy-MM-dd HH:00') } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Hour = $_.Name; Dropped = @($_.Group | Where-Object Action -EQ 'DROP').Count; Allowed = @($_.Group | Where-Object Action -EQ 'ALLOW').Count } })
    }
}

function Export-IgwtFirewallLogAnalysis {
    <# .SYNOPSIS Writes a firewall log analysis as JSON, or the parsed entries as CSV (by file extension). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Analysis, [AllowEmptyCollection()][object[]]$Entries = @(), [Parameter(Mandatory = $true)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export firewall log analysis')) { return }
    $utf = New-Object System.Text.UTF8Encoding($false)
    if ($Path -match '\.csv$') { [System.IO.File]::WriteAllText($Path, ((@($Entries | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"), $utf) }
    else { [System.IO.File]::WriteAllText($Path, ($Analysis | ConvertTo-Json -Depth 5), $utf) }
}

function Get-IgwtOutboundAllowListPlan {
    <#
    .SYNOPSIS
        Expert planning aid for default-block outbound: the programs that made allowed outbound
        connections (from the firewall log, with logging of allowed packets on) and the Windows
        components that always need outbound access. It returns a plan only; iG Windows Tuner does
        not create allow rules or switch outbound traffic to block (an incomplete list cuts off
        Windows Update, Defender updates, activation, time sync and DNS).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Entries = @())
    $warnings = @(
        'Default-block outbound breaks everything that is not on the allow-list, including Windows Update, Defender security intelligence updates, Microsoft Store, activation, time sync, game launchers, anti-cheat services and voice chat.',
        'Programs that update themselves change their path; allow rules by path then silently stop matching.',
        'svchost.exe hosts many services: allow it per service, never as a whole.',
        'Test on a PC you can reach locally; keep a way back (Windows Security > Firewall > Restore defaults).'
    )
    $essential = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'defender\outbound-essentials.json')).essential | ForEach-Object { [pscustomobject]@{ Program = [string]$_.program; Service = [string]$_.service; Why = [string]$_.why } })
    $proc = @{}
    foreach ($e in @($Entries | Where-Object { $_.Action -eq 'ALLOW' -and $_.Direction -eq 'SEND' -and $_.ProcessId })) {
        if ($proc.ContainsKey($e.ProcessId)) { $proc[$e.ProcessId].Connections++; continue }
        $p = Get-Process -Id ([int]$e.ProcessId) -ErrorAction SilentlyContinue
        $path = $(if ($p) { try { $p.Path } catch { '' } } else { '' })
        $proc[$e.ProcessId] = [pscustomobject]@{ Program = $(if ($path) { $path } else { "pid $($e.ProcessId) (ended; path unknown)" }); Process = $(if ($p) { $p.ProcessName } else { '' }); Connections = 1 }
    }
    $observed = @($proc.Values | Group-Object Program | ForEach-Object { [pscustomobject]@{ Program = $_.Name; Process = $_.Group[0].Process; Connections = ($_.Group | Measure-Object Connections -Sum).Sum } } | Sort-Object Connections -Descending)
    [pscustomobject]@{ Warnings = $warnings; Essential = $essential; Observed = $observed
        Steps = @('Review the list and remove anything you do not recognize.', 'Create allow rules for each program (Windows Defender Firewall with Advanced Security > Outbound Rules), per service for svchost.exe.', 'Only then set the outbound default to Block per profile, and watch the firewall log for drops.', 'iG Windows Tuner does not do these steps for you.') }
}
