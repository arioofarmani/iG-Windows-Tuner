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
    if ($script:IgwtLogQueue) { $script:IgwtLogQueue.Enqueue([pscustomobject]@{ Kind = 'log'; Entry = [pscustomobject]$entry }) }

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

function Send-IgwtProgress {
    <# .SYNOPSIS Reports progress to the GUI queue (if any) and to an optional callback. #>
    [CmdletBinding()]
    param([string]$Text, [int]$Percent, [scriptblock]$Callback)
    if ($script:IgwtLogQueue) { $script:IgwtLogQueue.Enqueue([pscustomobject]@{ Kind = 'progress'; Text = $Text; Percent = $Percent }) }
    if ($Callback) { & $Callback $Text $Percent }
}
