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

function Initialize-IgwtFirewallLogEngine {
    <#
    .SYNOPSIS
        Loads the compiled firewall log engine (src\Defender\FirewallLogEngine.cs: parser, live
        tail, query, aggregates; managed code only) once per process. PowerShell alone missed the
        3.5 budgets several times over (DECISIONS F11). Read-only.
    #>
    [CmdletBinding()]
    param()
    if ('IgwtFirewallLog.Parser' -as [type]) { return }
    $source = Join-Path $PSScriptRoot 'FirewallLogEngine.cs'
    # The GUI's background runspaces may ask at the same time: one process-wide lock (an interned
    # string is the same object in every runspace), so the engine is compiled once.
    $gate = [string]::Intern('IgwtFirewallLogEngine')
    [System.Threading.Monitor]::Enter($gate)
    try {
        if (-not ('IgwtFirewallLog.Parser' -as [type])) { Add-Type -Path $source -ReferencedAssemblies System, System.Core -ErrorAction Stop }
    } finally { [System.Threading.Monitor]::Exit($gate) }
}

function ConvertFrom-IgwtFirewallLogText {
    <#
    .SYNOPSIS
        Parses firewall log text with the engine. The columns come from the text's own #Fields:
        header (the field list differs between Windows versions; DECISIONS F10), never from a fixed
        order. Empty lines are allowed (pfirewall.log has one after the header); data lines before
        a header, lines whose field count does not match the header and a last line without a line
        break (still being written) are skipped and counted by reason. Pure.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text = '', [string]$File = '')
    Initialize-IgwtFirewallLogEngine
    $ms = New-Object System.IO.MemoryStream(, [System.Text.Encoding]::UTF8.GetBytes($Text))
    try { return [IgwtFirewallLog.Parser]::Parse($ms, 0, $null, $false, $File, $true, $null) } finally { $ms.Dispose() }
}

function ConvertFrom-IgwtFirewallLog {
    <#
    .SYNOPSIS
        Parses W3C firewall log lines (see ConvertFrom-IgwtFirewallLogText; the #Fields header names
        the columns). Empty lines are allowed. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][AllowNull()][string[]]$Lines)
    $text = $(if (@($Lines).Count) { (@($Lines) -join "`n") + "`n" } else { '' })
    return (ConvertFrom-IgwtFirewallLogText -Text $text).Entries.ToArray()
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
    Initialize-IgwtFirewallLogEngine
    return [IgwtFirewallLog.Parser]::OpenShared($Path)
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
        Reads one firewall log file with the engine (shared open, see Open-IgwtFirewallLogStream) and
        parses it by its #Fields header. Never throws for a file problem: the result carries Reason
        (Ok, AccessDenied, NotFound, FolderNotFound, Locked, Error) and an actionable Message. A last
        line without a line break (still being written) is skipped. Read-only.
    .PARAMETER MaxLines
        Keep only the newest entries (0 = all).
    .PARAMETER TailBytes
        Read only the newest part of the file (about this many bytes), for showing first rows at once.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [int]$MaxLines = 0, [long]$TailBytes = 0)
    $res = [ordered]@{ Path = $Path; Reason = 'Ok'; Message = ''; Fields = @(); Entries = @(); Skipped = @{}; Bytes = [long]0; EndOffset = [long]0; TimeIsUtc = $false; ReadMs = 0 }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $fs = $null
    try { $fs = Open-IgwtFirewallLogStream -Path $Path }
    catch {
        $problem = Get-IgwtFirewallLogReadProblem -Exception $_.Exception -Path $Path
        $res.Reason = $problem.Reason; $res.Message = $problem.Message
        return [pscustomobject]$res
    }
    try {
        $parsed = $(if ($TailBytes -gt 0) { [IgwtFirewallLog.Parser]::ParseTail($fs, $TailBytes, $Path) } else { [IgwtFirewallLog.Parser]::Parse($fs, 0, $null, $false, $Path, $true, $null) })
        $all = $parsed.Entries
        $res.Bytes = $parsed.Length; $res.EndOffset = $parsed.EndOffset; $res.TimeIsUtc = $parsed.TimeIsUtc
        $res.Fields = $(if ($parsed.Fields) { [string[]]$parsed.Fields } else { @() }); $res.Skipped = $parsed.Skipped
        # No $( ) here: it would unroll hundreds of thousands of entries through the pipeline.
        if ($MaxLines -gt 0 -and $all.Count -gt $MaxLines) { $res.Entries = $all.GetRange($all.Count - $MaxLines, $MaxLines).ToArray() } else { $res.Entries = $all.ToArray() }
        if (-not $res.Fields.Count -and $all.Count -eq 0 -and $parsed.Length -gt 0) { $res.Reason = 'Error'; $res.Message = "$Path has no #Fields: header; it does not look like a Windows Firewall log." }
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

function Read-IgwtFirewallLogSession {
    <#
    .SYNOPSIS
        Reads the firewall logs of every profile that logs (each file once, its rotated .old file
        first) into one list of engine entries, with process names (best effort: the process that has
        the id now) and the user's notes, and an actionable message for every problem. -Quick reads
        only the newest part of each current file, for showing first rows at once. Read-only.
    .PARAMETER Notes
        Note key -> text (see [IgwtFirewallLog.Engine]::NoteKey), applied to the entries.
    #>
    [CmdletBinding()]
    param([switch]$Quick, [long]$TailBytes = 1MB, [hashtable]$Notes = @{})
    Initialize-IgwtFirewallLogEngine
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $messages = New-Object System.Collections.Generic.List[string]
    $files = New-Object System.Collections.Generic.List[object]
    $rows = New-Object 'System.Collections.Generic.List[IgwtFirewallLog.Entry]'
    $status = @()
    try { $status = @(Get-IgwtFirewallLoggingStatus) } catch { $messages.Add("The firewall profiles could not be read: $($_.Exception.Message)") }
    $set = Get-IgwtFirewallLogFiles -Status $status
    foreach ($name in @($set.ProfilesOff)) { $messages.Add("Logging is off for the $name profile. Turn on ""Log blocked connections"" for it on the Profiles and networks tab to see what the firewall blocks there.") }
    if ($status.Count -and -not @($set.Files).Count) { $messages.Add('Nothing is logged, so there is nothing to read yet. Turn logging on, use the PC for a while, then read again.') }
    foreach ($f in @($set.Files)) {
        $paths = $(if ($Quick) { @($f.Path) } else { @("$($f.Path).old", $f.Path) })
        foreach ($path in $paths) {
            $r = $(if ($Quick) { Read-IgwtFirewallLogFile -Path $path -TailBytes $TailBytes } else { Read-IgwtFirewallLogFile -Path $path })
            if ($r.Reason -eq 'NotFound' -and $path.EndsWith('.old')) { continue }
            if ($r.Reason -ne 'Ok') { if (-not $messages.Contains($r.Message)) { $messages.Add($r.Message) }; continue }
            $rows.AddRange([IgwtFirewallLog.Entry[]]$r.Entries)
            $files.Add([pscustomobject]@{ Path = $path; Profiles = @($f.Profiles); Entries = @($r.Entries).Count; Bytes = $r.Bytes; EndOffset = $r.EndOffset; Fields = $r.Fields; TimeIsUtc = $r.TimeIsUtc; Skipped = $r.Skipped; ReadMs = $r.ReadMs; Current = (-not $path.EndsWith('.old')) })
        }
    }
    $names = New-Object 'System.Collections.Generic.Dictionary[int,string]'
    $ids = [IgwtFirewallLog.Engine]::ProcessIds($rows)
    if ($ids.Count) { foreach ($p in @(Get-Process -Id $ids -ErrorAction SilentlyContinue)) { $names[[int]$p.Id] = [string]$p.ProcessName } }
    $null = [IgwtFirewallLog.Engine]::SetProcessNames($rows, $names, 'pid {0} (ended)')
    if ($Notes.Count) {
        $d = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        foreach ($k in $Notes.Keys) { $d[[string]$k] = [string]$Notes[$k] }
        $null = [IgwtFirewallLog.Engine]::ApplyNotes($rows, $d)
    }
    [pscustomobject]@{ Entries = $rows; Files = $files.ToArray(); ProfilesOff = @($set.ProfilesOff); Messages = $messages.ToArray(); Quick = [bool]$Quick; ReadMs = [int]$watch.ElapsedMilliseconds; ReadAt = Get-Date }
}

function New-IgwtFirewallLogTail {
    <# .SYNOPSIS A live tail of a log file from where a read ended (Read-IgwtFirewallLogSession Files: Path, EndOffset, Fields, TimeIsUtc). Read-only. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory reader only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [long]$Offset = 0, [string[]]$Fields, [bool]$TimeIsUtc = $false)
    Initialize-IgwtFirewallLogEngine
    return (New-Object IgwtFirewallLog.Tail($Path, $Offset, [string[]]$Fields, $TimeIsUtc))
}

function Invoke-IgwtFirewallLogTail {
    <#
    .SYNOPSIS
        Reads what was appended to the followed logs since the last poll (starting over after a
        rotation), with process names. Returns the new entries and any problem. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Tail)
    $rows = New-Object 'System.Collections.Generic.List[IgwtFirewallLog.Entry]'
    $messages = New-Object System.Collections.Generic.List[string]
    $rotated = 0
    foreach ($t in $Tail) {
        $before = $t.Rotations
        try { $r = $t.Poll(); $rows.AddRange([IgwtFirewallLog.Entry[]]$r.Entries) }
        catch { $messages.Add((Get-IgwtFirewallLogReadProblem -Exception $_.Exception -Path $t.Path).Message) }
        if ($t.Rotations -ne $before) { $rotated++ }
    }
    if ($rows.Count) {
        $names = New-Object 'System.Collections.Generic.Dictionary[int,string]'
        $ids = [IgwtFirewallLog.Engine]::ProcessIds($rows)
        if ($ids.Count) { foreach ($p in @(Get-Process -Id $ids -ErrorAction SilentlyContinue)) { $names[[int]$p.Id] = [string]$p.ProcessName } }
        $null = [IgwtFirewallLog.Engine]::SetProcessNames($rows, $names, 'pid {0} (ended)')
    }
    [pscustomobject]@{ Entries = $rows; Rotated = $rotated; Messages = $messages.ToArray() }
}

function Get-IgwtFirewallLogAnalysis {
    <#
    .SYNOPSIS
        Analysis of firewall log entries (from the engine): counts by action, top blocked sources,
        top blocked destination ports (with protocol), top processes (by process id, named after
        the process that has that id now; ids reused after a process ends make this best effort),
        and an hourly timeline of blocked and allowed packets. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [int]$Top = 10)
    Initialize-IgwtFirewallLogEngine
    $rows = New-Object 'System.Collections.Generic.List[IgwtFirewallLog.Entry]'
    foreach ($e in $Entries) { if ($e -is [IgwtFirewallLog.Entry]) { $rows.Add($e) } }   # a typed list for the engine
    $names = New-Object 'System.Collections.Generic.Dictionary[int,string]'
    $ids = [IgwtFirewallLog.Engine]::ProcessIds($rows)
    if ($ids.Count) { foreach ($p in @(Get-Process -Id $ids -ErrorAction SilentlyContinue)) { $names[[int]$p.Id] = [string]$p.ProcessName } }
    $null = [IgwtFirewallLog.Engine]::SetProcessNames($rows, $names, 'pid {0} (ended)')
    $s = [IgwtFirewallLog.Engine]::Summarize($rows)
    $topOf = { param($key, $action) @([IgwtFirewallLog.Engine]::Top($rows, $key, $action, $Top) | ForEach-Object { [pscustomobject]@{ Value = $_.Value; Count = [int]$_.Hits } }) }
    [pscustomobject]@{
        Entries = [int]$s.Entries; Dropped = [int]$s.Dropped; Allowed = [int]$s.Allowed
        From = $(if ($s.From) { [datetime]$s.From } else { $null }); To = $(if ($s.To) { [datetime]$s.To } else { $null })
        TopBlockedSources = (& $topOf 'Source' 'DROP')
        TopBlockedPorts = (& $topOf 'Port' 'DROP')
        TopBlockedProcesses = (& $topOf 'Process' 'DROP')
        TopAllowedProcesses = (& $topOf 'Process' 'ALLOW')
        Timeline = @([IgwtFirewallLog.Engine]::Histogram($rows, 60) | ForEach-Object { [pscustomobject]@{ Hour = $_.Start.ToString('yyyy-MM-dd HH:00'); Dropped = [int]$_.Dropped; Allowed = [int]$_.Allowed } })
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
