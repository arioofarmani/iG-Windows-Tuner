# Logging.ps1
# Human-readable log plus JSON-lines log. Both are plain text files; nothing is hidden.

$script:IgwtLogBuffer = New-Object System.Collections.Generic.List[object]
$script:IgwtLogSink = $null       # optional scriptblock called with each entry (same runspace)
$script:IgwtLogQueue = $null      # optional ConcurrentQueue; the GUI's background worker uses it
$script:IgwtSessionId = [guid]::NewGuid().ToString('N').Substring(0, 8)

function Write-IgwtLog {
    <#
    .SYNOPSIS
        Writes a log entry to %ProgramData%\iGWindowsTuner\Logs (or %LOCALAPPDATA% when not elevated).
    .PARAMETER Level
        Debug, Info, Warn or Error.
    .PARAMETER Message
        Human-readable message.
    .PARAMETER TweakId
        Optional tweak id the entry belongs to.
    .PARAMETER Data
        Optional structured data written to the JSON-lines log.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')]
        [string]$Level = 'Info',
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,
        [string]$TweakId,
        [System.Collections.IDictionary]$Data
    )
    $now = Get-Date
    $entry = [ordered]@{
        time    = $now.ToString('o')
        session = $script:IgwtSessionId
        level   = $Level
        message = $Message
    }
    if ($TweakId) { $entry.tweak = $TweakId }
    if ($Data) { $entry.data = $Data }

    $script:IgwtLogBuffer.Add([pscustomobject]$entry)
    if ($script:IgwtLogBuffer.Count -gt 2000) { $script:IgwtLogBuffer.RemoveRange(0, 500) }

    Write-Verbose ("[{0}] {1}{2}" -f $Level.ToUpperInvariant(), $(if ($TweakId) { "$TweakId - " } else { '' }), $Message)

    if ($script:IgwtLogSink) {
        try { & $script:IgwtLogSink ([pscustomobject]$entry) } catch { Write-Verbose "Log sink failed: $($_.Exception.Message)" }
    }
    $q = Get-IgwtLogQueue
    if ($null -ne $q) { $q.Enqueue([pscustomobject]@{ Kind = 'log'; Entry = [pscustomobject]$entry }) }

    try {
        $dir = Get-IgwtDataPath -Kind Logs
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        $stamp = $now.ToString('yyyyMMdd')
        $text = "{0} [{1}] [{2}] {3}{4}" -f $now.ToString('yyyy-MM-dd HH:mm:ss'), $script:IgwtSessionId, $Level.ToUpperInvariant(),
            $(if ($TweakId) { "$TweakId - " } else { '' }), $Message
        Add-Content -LiteralPath (Join-Path $dir "iGWindowsTuner-$stamp.log") -Value $text -Encoding UTF8
        Add-Content -LiteralPath (Join-Path $dir "iGWindowsTuner-$stamp.jsonl") -Value (ConvertTo-Json -InputObject $entry -Compress -Depth 8) -Encoding UTF8
    } catch {
        Write-Verbose "Could not write log file: $($_.Exception.Message)"
    }
}

function Get-IgwtLogEntries {
    <#
    .SYNOPSIS
        Log entries of the last days from the JSON-lines logs (newest first), for the log viewer.
        Reads the administrator and the per-user log folders. Read-only.
    .PARAMETER Days
        How many days back (by log file date).
    .PARAMETER Max
        At most this many entries (the newest).
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 90)][int]$Days = 7, [ValidateRange(1, 50000)][int]$Max = 5000, [string[]]$Folder)
    if (-not $Folder) {
        $Folder = @((Join-Path $script:IgwtSettings.DataRoot 'Logs'), (Join-Path ([string]$script:IgwtSettings.UserLogRoot) 'Logs')) | Select-Object -Unique
    }
    $since = (Get-Date).Date.AddDays(-($Days - 1)).ToString('yyyyMMdd')
    $files = @(foreach ($d in $Folder) { if ($d -and (Test-Path -LiteralPath $d)) { Get-ChildItem -LiteralPath $d -Filter 'iGWindowsTuner-*.jsonl' -File -ErrorAction SilentlyContinue } }) |
        Where-Object { ($_.BaseName -replace '^iGWindowsTuner-', '') -ge $since }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $lines = @(); try { $lines = [System.IO.File]::ReadAllLines($f.FullName) } catch { Write-Verbose "Log not readable: $($f.Name): $($_.Exception.Message)"; continue }
        foreach ($l in $lines) {
            if (-not $l) { continue }
            try { $e = $l | ConvertFrom-Json } catch { continue }
            $t = $null; try { $t = [datetime]::Parse([string]$e.time, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { $t = $null }
            $out.Add([pscustomobject]@{ Time = $t; Level = [string]$e.level; Session = [string]$e.session; Tweak = [string]$e.tweak; Message = [string]$e.message; File = $f.Name })
        }
    }
    return @($out.ToArray() | Sort-Object Time -Descending | Select-Object -First $Max)
}

function Get-IgwtLogBuffer {
    <# .SYNOPSIS Returns the in-memory log entries of this session. #>
    [CmdletBinding()]
    param([int]$Last = 0)
    if ($Last -gt 0 -and $script:IgwtLogBuffer.Count -gt $Last) {
        return $script:IgwtLogBuffer.GetRange($script:IgwtLogBuffer.Count - $Last, $Last).ToArray()
    }
    return $script:IgwtLogBuffer.ToArray()
}

function Set-IgwtLogSink {
    <#
    .SYNOPSIS
        Registers a receiver for log and progress entries: a scriptblock (same runspace) or a
        ConcurrentQueue (the GUI's background runspace hands entries to the UI thread this way).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([scriptblock]$Sink, [System.Collections.Concurrent.ConcurrentQueue[object]]$Queue)
    if (-not $PSCmdlet.ShouldProcess('log sink', 'Set')) { return }
    if ($PSBoundParameters.ContainsKey('Sink')) { $script:IgwtLogSink = $Sink }
    if ($PSBoundParameters.ContainsKey('Queue')) { $script:IgwtLogQueue = $Queue }
}

function Get-IgwtLogQueue {
    <#
    .SYNOPSIS
        The GUI queue that receives log and progress entries: the one set with Set-IgwtLogSink, or
        the IgwtGuiLogQueue variable the GUI gives every runspace of its background pool.
    #>
    [CmdletBinding()]
    param()
    if ($null -ne $script:IgwtLogQueue) { return , $script:IgwtLogQueue }
    $g = Get-Variable -Name 'IgwtGuiLogQueue' -Scope Global -ValueOnly -ErrorAction Ignore
    if ($g -is [System.Collections.Concurrent.ConcurrentQueue[object]]) { return , $g }
    return $null
}

function Send-IgwtProgress {
    <# .SYNOPSIS Reports progress to the GUI queue (if any) and to an optional callback. #>
    [CmdletBinding()]
    param([string]$Text, [int]$Percent, [scriptblock]$Callback)
    $q = Get-IgwtLogQueue
    if ($null -ne $q) { $q.Enqueue([pscustomobject]@{ Kind = 'progress'; Text = $Text; Percent = $Percent }) }
    if ($Callback) { & $Callback $Text $Percent }
}
