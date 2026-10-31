# Journal.ps1
# The change journal (3.6, DECISIONS T3 and T4): append-only JSON Lines in the machine-wide data
# root (Journal\journal-0001.jsonl, ...), one entry per line, each starting with "prev": the SHA256
# of the previous line's exact UTF-8 bytes (64 zeros for the first line). Verification walks the
# chain; a break makes the journal read-only and names the first bad line. A line cut off by a
# crash or power loss (no line break at the end) is not tampering: the next append records it in a
# chainNote entry and verification accepts exactly that pattern. While verifying, the journal
# builds two indexes: the baseline of every target (the first "before" ever recorded, kept forever)
# and the last state of every target. Entries are written by the transaction engine only, under
# the machine-wide change mutex (Transaction.ps1).

$script:IgwtJournalSegmentLines = 5000
$script:IgwtJournalZeroHash = '0000000000000000000000000000000000000000000000000000000000000000'
$script:IgwtJournal = $null

function Get-IgwtJournalFolder {
    <# .SYNOPSIS The journal folder in the machine-wide data root (protected ACL: SYSTEM and Administrators write, Users read). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Get-IgwtDataPath -Kind Root) 'Journal')
}

function Get-IgwtJournalHash {
    <# .SYNOPSIS SHA256 (lower-case hex) of a journal line's UTF-8 bytes. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Line))
        return ([System.BitConverter]::ToString($h).Replace('-', '').ToLowerInvariant())
    } finally { $sha.Dispose() }
}

function Get-IgwtWindowsBuildInfo {
    <# .SYNOPSIS Windows build and UBR (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion), cached per process. Read-only. #>
    [CmdletBinding()]
    param()
    if ($script:IgwtBuildInfo) { return $script:IgwtBuildInfo }
    $build = [string][Environment]::OSVersion.Version.Build; $ubr = ''
    if (-not $script:IgwtSettings.TestMode) {
        try {
            $k = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64).OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
            if ($k) { try { $b = $k.GetValue('CurrentBuildNumber'); if ($b) { $build = [string]$b }; $u = $k.GetValue('UBR'); if ($null -ne $u) { $ubr = [string]$u } } finally { $k.Dispose() } }
        } catch { Write-Verbose "Build info not read: $($_.Exception.Message)" }
    }
    $script:IgwtBuildInfo = [pscustomobject]@{ Build = $build; Ubr = $ubr }
    return $script:IgwtBuildInfo
}

function Get-IgwtJournalSegments {
    <# .SYNOPSIS The journal segment files in order (oldest first). Read-only. #>
    [CmdletBinding()]
    param()
    $dir = Get-IgwtJournalFolder
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    return @(Get-ChildItem -LiteralPath $dir -File -Filter 'journal-*.jsonl' | Where-Object { $_.Name -match '^journal-\d{4}\.jsonl$' } | Sort-Object Name | ForEach-Object { $_.FullName })
}

function ConvertFrom-IgwtJournalLine {
    <# .SYNOPSIS One journal line as a dictionary (JavaScriptSerializer: fast and strict), or $null when it is not valid JSON. Pure. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)
    if (-not $script:IgwtJsonSerializer) {
        Add-Type -AssemblyName System.Web.Extensions
        $script:IgwtJsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $script:IgwtJsonSerializer.MaxJsonLength = [int]::MaxValue
    }
    try { $o = $script:IgwtJsonSerializer.DeserializeObject($Line) } catch { return $null }
    if ($o -is [System.Collections.Generic.Dictionary[string, object]]) { return $o }
    return $null
}

function Read-IgwtJournal {
    <#
    .SYNOPSIS
        Reads and verifies the whole journal: the hash chain, line by line. Returns the entries (as
        dictionaries), the head (seq, hash, segment, lines in it), the status (Ok, Empty, Broken),
        the reason and line of a break, and the indexes Baselines (target key -> baseline entry) and
        Last (target key -> last state entry). Read-only.
    .PARAMETER NoEntries
        Verify and index only (the entries are not returned).
    #>
    [CmdletBinding()]
    param([switch]$NoEntries)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $baselines = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $last = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $res = [ordered]@{ Status = 'Empty'; Reason = ''; BadFile = ''; BadLine = 0; Seq = 0; Hash = $script:IgwtJournalZeroHash; Segment = ''; SegmentLines = 0; TornPending = $false; TornHash = ''; NeedsBreak = $false; Count = 0 }
    $hash = $script:IgwtJournalZeroHash
    $torn = $null
    $segments = @(Get-IgwtJournalSegments)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($file in $segments) {
            $lineNo = 0; $segLines = 0
            $bytes = [System.IO.File]::ReadAllBytes($file)
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            $endsWithBreak = ($text.Length -eq 0 -or $text[$text.Length - 1] -eq "`n")
            $lines = $text.Split([char]10)
            $count = $lines.Length; if ($endsWithBreak) { $count-- }
            for ($i = 0; $i -lt $count; $i++) {
                $line = $lines[$i].TrimEnd([char]13)
                $lineNo++
                $isLast = ($file -eq $segments[-1] -and $i -eq $count - 1)
                $prefix = '{"prev":"' + $hash + '"'
                if (-not $line.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                    # A torn write: an unterminated last line, or a malformed line that the next line's chainNote names.
                    $lh = [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($line))).Replace('-', '').ToLowerInvariant()
                    if ($isLast -and -not $endsWithBreak) { $res.TornPending = $true; $res.TornHash = $lh; continue }
                    if ($null -eq $torn -and $null -eq (ConvertFrom-IgwtJournalLine -Line $line)) { $torn = @{ Hash = $lh; Line = $lineNo; File = $file }; continue }
                    $res.Status = 'Broken'; $res.Reason = "The chain is broken at $([IO.Path]::GetFileName($file)) line ${lineNo}: it does not continue from the line before (an entry was changed, removed or reordered)."; $res.BadFile = $file; $res.BadLine = $lineNo
                    return [pscustomobject]$res
                }
                $e = ConvertFrom-IgwtJournalLine -Line $line
                if ($null -eq $e) { $res.Status = 'Broken'; $res.Reason = "$([IO.Path]::GetFileName($file)) line $lineNo is not a valid entry."; $res.BadFile = $file; $res.BadLine = $lineNo; return [pscustomobject]$res }
                if ($null -ne $torn) {
                    if ([string]$e['kind'] -ne 'chainNote' -or [string]$e['torn'] -ne $torn.Hash) { $res.Status = 'Broken'; $res.Reason = "$([IO.Path]::GetFileName($torn.File)) line $($torn.Line) is not a valid entry."; $res.BadFile = $torn.File; $res.BadLine = $torn.Line; return [pscustomobject]$res }
                    $torn = $null
                }
                $expectSeq = $res.Seq + 1
                if ([long]$e['seq'] -ne $expectSeq) { $res.Status = 'Broken'; $res.Reason = "$([IO.Path]::GetFileName($file)) line ${lineNo}: sequence $($e['seq']) where $expectSeq was expected."; $res.BadFile = $file; $res.BadLine = $lineNo; return [pscustomobject]$res }
                $res.Seq = $expectSeq
                $hash = [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($line))).Replace('-', '').ToLowerInvariant()
                $segLines++
                $key = $(if ($e.ContainsKey('target') -and $e['target'] -is [System.Collections.IDictionary]) { [string]$e['target']['key'] } else { '' })
                if ($key) {
                    $kind = [string]$e['kind']
                    if ($kind -eq 'baseline' -and -not $baselines.ContainsKey($key)) { $baselines[$key] = $e }
                    if ($kind -in 'committed', 'reverted', 'retired', 'adopted', 'rolledBack') { $last[$key] = $e }
                }
                if (-not $NoEntries) { $entries.Add($e) }
            }
            $res.Segment = $file; $res.SegmentLines = $segLines
            # A complete last line without its line break (cut off right after it): the next append adds the break first.
            if ($file -eq $segments[-1]) { $res.NeedsBreak = (-not $endsWithBreak -and -not $res.TornPending) }
        }
        if ($null -ne $torn) { $res.Status = 'Broken'; $res.Reason = "$([IO.Path]::GetFileName($torn.File)) line $($torn.Line) is not a valid entry."; $res.BadFile = $torn.File; $res.BadLine = $torn.Line; return [pscustomobject]$res }
    } finally { $sha.Dispose() }
    if ($res.Seq -gt 0) { $res.Status = 'Ok' }
    $res.Hash = $hash; $res.Count = $res.Seq
    $o = [pscustomobject]$res
    $o | Add-Member -NotePropertyName Entries -NotePropertyValue $entries
    $o | Add-Member -NotePropertyName Baselines -NotePropertyValue $baselines
    $o | Add-Member -NotePropertyName Last -NotePropertyValue $last
    return $o
}

function Get-IgwtJournalState {
    <#
    .SYNOPSIS
        The verified journal head and indexes, cached per process (-Refresh reads it again). Status
        Broken means read-only: no entry is appended and no change runs until it is resolved.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)
    if ($Refresh -or $null -eq $script:IgwtJournal -or $script:IgwtJournal.Folder -ne (Get-IgwtJournalFolder)) {
        $r = Read-IgwtJournal -NoEntries
        $r | Add-Member -NotePropertyName Folder -NotePropertyValue (Get-IgwtJournalFolder) -Force
        $script:IgwtJournal = $r
    }
    return $script:IgwtJournal
}

function Add-IgwtJournalEntry {
    <#
    .SYNOPSIS
        Appends one entry to the journal and returns it: sets prev (the hash chain), seq, id, tsUtc,
        appVersion, build, ubr and user, writes the line and flushes it to disk before returning.
        Refuses when the journal is broken (read-only). Called by the transaction engine only, under
        the change mutex. A baseline entry is written once per target (later ones are ignored).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Appends to the tool''s own journal; the system change it records went through ShouldProcess.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Entry)
    $j = Get-IgwtJournalState
    if ($j.Status -eq 'Broken') { throw "The change journal is read-only: $($j.Reason)" }
    $key = $(if ($Entry.Contains('target') -and $Entry['target']) { [string]$Entry['target']['key'] } else { '' })
    if ([string]$Entry['kind'] -eq 'baseline' -and $key -and $j.Baselines.ContainsKey($key)) { return $j.Baselines[$key] }
    $dir = Get-IgwtJournalFolder
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $segment = $j.Segment
    $segLines = [int]$j.SegmentLines
    # A cut-off or unterminated last line is finished in its own segment before any rollover.
    if (-not $segment -or ($segLines -ge $script:IgwtJournalSegmentLines -and -not $j.TornPending -and -not $j.NeedsBreak)) {
        $n = @(Get-IgwtJournalSegments).Count + 1
        $segment = Join-Path $dir ('journal-{0:0000}.jsonl' -f $n); $segLines = 0
    }
    $bi = Get-IgwtWindowsBuildInfo
    $prefix = New-Object System.Collections.Generic.List[string]
    # A torn last line first gets its chainNote, so the chain shows what happened instead of breaking.
    if ($j.TornPending) {
        $note = [ordered]@{ prev = $j.Hash; seq = [long]$j.Seq + 1; id = [guid]::NewGuid().ToString(); kind = 'chainNote'; torn = $j.TornHash; tsUtc = [DateTime]::UtcNow.ToString('o'); note = 'The previous write was cut off (crash or power loss); the cut-off line is kept and skipped.' }
        $noteLine = ConvertTo-Json -InputObject $note -Compress -Depth 4
        $prefix.Add("`n" + $noteLine)
        $j.Hash = Get-IgwtJournalHash -Line $noteLine; $j.Seq = [long]$j.Seq + 1; $j.TornPending = $false; $j.TornHash = ''
    }
    $o = [ordered]@{ prev = $j.Hash; seq = [long]$j.Seq + 1 }
    $o.id = $(if ($Entry.Contains('id') -and $Entry['id']) { [string]$Entry['id'] } else { [guid]::NewGuid().ToString() })
    foreach ($k in $Entry.Keys) { if ($k -notin 'prev', 'seq', 'id') { $o[$k] = $Entry[$k] } }
    if (-not $o.Contains('tsUtc')) { $o.tsUtc = [DateTime]::UtcNow.ToString('o') }
    if (-not $o.Contains('appVersion')) { $o.appVersion = $script:IgwtVersion }
    if (-not $o.Contains('build')) { $o.build = $bi.Build }
    if (-not $o.Contains('ubr')) { $o.ubr = $bi.Ubr }
    if (-not $o.Contains('user')) { $o.user = "$env:USERDOMAIN\$env:USERNAME" }
    $line = ConvertTo-Json -InputObject $o -Compress -Depth 12
    $text = (($prefix.ToArray() + @($line)) -join "`n") + "`n"
    if ($prefix.Count -eq 0 -and $j.NeedsBreak -and $segment -eq $j.Segment) { $text = "`n" + $text }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $fs = New-Object System.IO.FileStream($segment, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 4096, [System.IO.FileOptions]::WriteThrough)
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    $j.Hash = Get-IgwtJournalHash -Line $line; $j.Seq = [long]$o.seq; $j.Count = $j.Seq; $j.Status = 'Ok'
    $j.Segment = $segment; $j.SegmentLines = $segLines + $prefix.Count + 1; $j.NeedsBreak = $false
    $e = ConvertFrom-IgwtJournalLine -Line $line
    if ($key) {
        $kind = [string]$o.kind
        if ($kind -eq 'baseline' -and -not $j.Baselines.ContainsKey($key)) { $j.Baselines[$key] = $e }
        if ($kind -in 'committed', 'reverted', 'retired', 'adopted', 'rolledBack') { $j.Last[$key] = $e }
    }
    return $e
}
