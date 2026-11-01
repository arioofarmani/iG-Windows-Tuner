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

function Read-IgwtJournalText {
    <#
    .SYNOPSIS
        A journal file's text, read with read, write and delete sharing so a reader never blocks
        the writer (and the other way round); a short retry covers a sharing violation. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    for ($try = 1; ; $try++) {
        try {
            $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            try { $ms = New-Object System.IO.MemoryStream; $fs.CopyTo($ms); return [System.Text.Encoding]::UTF8.GetString($ms.ToArray()) } finally { $fs.Dispose() }
        } catch [System.IO.IOException] { if ($try -ge 5 -or $_.Exception -is [System.IO.FileNotFoundException]) { throw }; Start-Sleep -Milliseconds (40 * $try) }
    }
}

function Test-IgwtJournalTrusted {
    <#
    .SYNOPSIS
        '' when the journal folder and its files are protected (owned by Administrators or SYSTEM,
        not writable by standard users: Test-IgwtTrustedFile), else the reason. A journal that a
        standard user could have written is never used for a restore (review 3.6 R4). Read-only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $dir = Get-IgwtJournalFolder
    if (-not (Test-Path -LiteralPath $dir)) { return '' }
    foreach ($p in @($dir) + @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(journal-\d{4}\.jsonl|checkpoint\.json|head\.json)$' } | ForEach-Object { $_.FullName })) {
        if (-not (Test-IgwtTrustedFile -Path $p)) { return "'$([IO.Path]::GetFileName($p))' is not protected (it must be owned by Administrators or SYSTEM and not writable by standard users)." }
    }
    return ''
}

function Get-IgwtJournalSegments {
    <# .SYNOPSIS The journal segment files in order (oldest first). Read-only. #>
    [CmdletBinding()]
    param()
    $dir = Get-IgwtJournalFolder
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    # Segments folded into the checkpoint are skipped (compaction deletes them after writing it).
    $cp = Read-IgwtJournalCheckpoint
    $after = $(if ($cp) { [string]$cp['folded'] } else { '' })
    return @(Get-ChildItem -LiteralPath $dir -File -Filter 'journal-*.jsonl' | Where-Object { $_.Name -match '^journal-\d{4}\.jsonl$' -and (-not $after -or [string]::CompareOrdinal($_.Name, $after) -gt 0) } | Sort-Object Name | ForEach-Object { $_.FullName })
}

function Get-IgwtJournalCheckpointHash {
    <# .SYNOPSIS SHA256 of a checkpoint's content (every field but "hash"), to detect a damaged checkpoint file. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Checkpoint)
    $copy = [ordered]@{}
    foreach ($k in @($Checkpoint.Keys | Sort-Object)) { if ($k -ne 'hash') { $copy[$k] = $Checkpoint[$k] } }
    return (Get-IgwtJournalHash -Line (ConvertTo-IgwtCanonicalJson $copy))
}

function Read-IgwtJournalCheckpoint {
    <#
    .SYNOPSIS
        The compaction checkpoint (Journal\checkpoint.json) as a dictionary, or $null when there is
        none: the sequence and hash of the last folded line, the last folded segment, and every
        baseline and last state of the folded entries (DECISIONS T4). Throws when it is damaged. Read-only.
    #>
    [CmdletBinding()]
    param()
    $p = Join-Path (Get-IgwtJournalFolder) 'checkpoint.json'
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $cp = ConvertFrom-IgwtJournalLine -Line (Read-IgwtJournalText -Path $p)
    if ($null -eq $cp -or [string]$cp['hash'] -ne (Get-IgwtJournalCheckpointHash -Checkpoint $cp)) { throw 'The journal checkpoint (checkpoint.json) is damaged or was edited.' }
    return $cp
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

function Initialize-IgwtJournalEngine {
    <#
    .SYNOPSIS
        Loads the compiled journal engine (src\Core\JournalEngine.cs: chain, parse, index and the
        canonical comparison;
        managed code only) once per process. Read-only.
    #>
    [CmdletBinding()]
    param()
    if ('IgwtJournal.Verifier' -as [type]) { return }
    $source = Join-Path $PSScriptRoot 'JournalEngine.cs'
    # One process-wide lock (an interned string is the same object in every runspace), so it compiles once.
    $gate = [string]::Intern('IgwtJournalEngine')
    [System.Threading.Monitor]::Enter($gate)
    try {
        if (-not ('IgwtJournal.Verifier' -as [type])) { Add-Type -Path $source -ReferencedAssemblies System, System.Core, System.Web.Extensions, ([psobject].Assembly.Location) -ErrorAction Stop }
    } finally { [System.Threading.Monitor]::Exit($gate) }
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
    $why = Test-IgwtJournalTrusted
    if ($why) { $res.Status = 'Broken'; $res.Reason = "The journal is not protected: $why"; return [pscustomobject]$res }
    # After a compaction the chain continues from the checkpoint, which carries the folded indexes.
    try { $cp = Read-IgwtJournalCheckpoint } catch { $res.Status = 'Broken'; $res.Reason = $_.Exception.Message; $res.BadFile = 'checkpoint.json'; return [pscustomobject]$res }
    if ($cp) {
        $hash = [string]$cp['head']; $res.Seq = [long]$cp['seq']
        foreach ($k in @($cp['baselines'].Keys)) { $baselines[$k] = $cp['baselines'][$k] }
        foreach ($k in @($cp['last'].Keys)) { $last[$k] = $cp['last'][$k] }
    }
    $segments = @(Get-IgwtJournalSegments)
    Initialize-IgwtJournalEngine
    $st = New-Object IgwtJournal.ChainState
    $st.Hash = $hash; $st.Seq = [long]$res.Seq
    $tornFile = ''
    # The list itself, never unrolled: $null means verify and index only.
    $collect = $null
    if (-not $NoEntries) { $collect = $entries }
    foreach ($file in $segments) {
        $text = Read-IgwtJournalText -Path $file
        $hadTorn = $st.HasTorn
        $ok = [IgwtJournal.Verifier]::VerifySegment($text, ($file -eq $segments[-1]), $st, $collect, $baselines, $last)
        if ($st.HasTorn -and -not $hadTorn) { $tornFile = $file }
        if (-not $ok) {
            $name = [IO.Path]::GetFileName($file)
            $res.Status = 'Broken'; $res.BadFile = $file; $res.BadLine = $st.BadLine
            $res.Reason = switch ($st.Reason) {
                'chain' { "The chain is broken at $name line $($st.BadLine): it does not continue from the line before (an entry was changed, removed or reordered)." }
                'seq' { "$name line $($st.BadLine): sequence $($st.FoundSeq) where $($st.Seq + 1) was expected." }
                'torn' { $res.BadFile = $tornFile; "$([IO.Path]::GetFileName($tornFile)) line $($st.BadLine) is not a valid entry." }
                default { "$name line $($st.BadLine) is not a valid entry." }
            }
            return [pscustomobject]$res
        }
        $res.Segment = $file; $res.SegmentLines = $st.SegmentLines
    }
    if ($st.HasTorn) { $res.Status = 'Broken'; $res.Reason = "$([IO.Path]::GetFileName($tornFile)) line $($st.TornLine) is not a valid entry."; $res.BadFile = $tornFile; $res.BadLine = $st.TornLine; return [pscustomobject]$res }
    # A complete last line without its line break (cut off right after it): the next append adds the break first.
    $res.TornPending = $st.TornPending; $res.TornHash = $st.PendingHash; $res.NeedsBreak = $st.NeedsBreak
    $res.Seq = $st.Seq; $hash = $st.Hash
    # The head record (head.json, written after every append) makes removed entries at the end visible (review 3.6 R13).
    $hp = Join-Path (Get-IgwtJournalFolder) 'head.json'
    if (Test-Path -LiteralPath $hp) {
        $hd = ConvertFrom-IgwtJournalLine -Line (Read-IgwtJournalText -Path $hp)
        if ($null -eq $hd) { $res.Status = 'Broken'; $res.Reason = 'The journal head record (head.json) is damaged.'; $res.BadFile = $hp; return [pscustomobject]$res }
        if ([long]$hd['seq'] -gt $res.Seq) { $res.Status = 'Broken'; $res.Reason = "Entries were removed from the end of the journal: it ends at entry $($res.Seq), the head record says $($hd['seq'])."; $res.BadFile = $hp; return [pscustomobject]$res }
        if ([long]$hd['seq'] -eq $res.Seq -and [string]$hd['hash'] -ne $hash) { $res.Status = 'Broken'; $res.Reason = "The last journal entry ($($res.Seq)) is not the one the head record names."; $res.BadFile = $hp; return [pscustomobject]$res }
    }
    if ($res.Seq -gt 0) { $res.Status = 'Ok' }
    $res.Hash = $hash; $res.Count = $res.Seq
    $o = [pscustomobject]$res
    $o | Add-Member -NotePropertyName Entries -NotePropertyValue $entries
    $o | Add-Member -NotePropertyName Baselines -NotePropertyValue $baselines
    $o | Add-Member -NotePropertyName Last -NotePropertyValue $last
    return $o
}

function Invoke-IgwtJournalCompaction {
    <#
    .SYNOPSIS
        Folds the oldest full segments into the checkpoint (DECISIONS T4): every baseline, the last
        state of every target, and the sequence and hash of the last folded line are kept, so the
        chain stays verifiable and "Reset everything iG changed" keeps working; the folded segments
        are deleted after the checkpoint is written. Only when the journal is intact and no session
        is unfinished. Called under the change lock (Compress-IgwtJournal, or the start of a session).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([ValidateRange(1, 1000)][int]$KeepSegments = 2)
    $j = Read-IgwtJournal
    if ($j.Status -ne 'Ok') { return [pscustomobject]@{ Folded = 0; Message = "Not compacted: the journal is $($j.Status.ToLowerInvariant())." } }
    if (@(Get-IgwtIncompleteChangeSession -Journal $j | Where-Object { @($_.Steps).Count }).Count) { return [pscustomobject]@{ Folded = 0; Message = 'Not compacted: a change session is unfinished.' } }
    $segs = @(Get-IgwtJournalSegments)
    if ($segs.Count -le $KeepSegments) { return [pscustomobject]@{ Folded = 0; Message = 'Nothing to compact.' } }
    $fold = @($segs | Select-Object -First ($segs.Count - $KeepSegments))
    $lastFolded = $fold[-1]
    # The head of the folded part: the last entry of the last folded segment.
    $lines = @((Read-IgwtJournalText -Path $lastFolded).Split([char]10) | ForEach-Object { $_.TrimEnd([char]13) } | Where-Object { $_ })
    $headLine = $lines[-1]
    $head = ConvertFrom-IgwtJournalLine -Line $headLine
    if ($null -eq $head) { return [pscustomobject]@{ Folded = 0; Message = 'Not compacted: the last folded line is not an entry.' } }
    $headSeq = [long]$head['seq']
    if (-not $PSCmdlet.ShouldProcess("$($fold.Count) segment(s)", 'Fold into the journal checkpoint')) { return $null }
    $base = [ordered]@{}; $lastIdx = [ordered]@{}
    $old = $null; try { $old = Read-IgwtJournalCheckpoint } catch { $old = $null }
    if ($old) { foreach ($k in $old['baselines'].Keys) { $base[$k] = $old['baselines'][$k] }; foreach ($k in $old['last'].Keys) { $lastIdx[$k] = $old['last'][$k] } }
    foreach ($e in $j.Entries) {
        if ([long]$e['seq'] -gt $headSeq) { break }
        $t = $e['target']
        if (-not ($t -is [System.Collections.IDictionary])) { continue }
        $key = [string]$t['key']; $kind = [string]$e['kind']
        if ($kind -eq 'baseline' -and -not $base.Contains($key)) { $base[$key] = $e }
        if ($kind -in 'committed', 'reverted', 'retired', 'adopted', 'rolledBack') { $lastIdx[$key] = $e }
    }
    $cp = [ordered]@{ schema = 1; seq = $headSeq; head = (Get-IgwtJournalHash -Line $headLine); folded = [IO.Path]::GetFileName($lastFolded); createdUtc = [DateTime]::UtcNow.ToString('o'); baselines = $base; last = $lastIdx }
    $cp.hash = Get-IgwtJournalCheckpointHash -Checkpoint $cp
    $p = Join-Path (Get-IgwtJournalFolder) 'checkpoint.json'
    [System.IO.File]::WriteAllText("$p.tmp", (ConvertTo-Json -InputObject $cp -Compress -Depth 14), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath "$p.tmp" -Destination $p -Force
    foreach ($f in $fold) { Remove-Item -LiteralPath $f -Force }
    $script:IgwtJournal = $null
    $check = Get-IgwtJournalState -Refresh
    return [pscustomobject]@{ Folded = $fold.Count; Message = "Folded $($fold.Count) segment(s) up to entry $headSeq into the checkpoint; the journal is $($check.Status.ToLowerInvariant())." }
}

function Write-IgwtJournalHead {
    <# .SYNOPSIS Records the journal head (sequence and hash of the last entry) in Journal\head.json, replaced atomically. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the tool''s own journal head record.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][long]$Seq, [Parameter(Mandatory = $true)][string]$Hash)
    $p = Join-Path (Get-IgwtJournalFolder) 'head.json'
    [System.IO.File]::WriteAllText("$p.tmp", (ConvertTo-Json -InputObject ([ordered]@{ seq = $Seq; hash = $Hash }) -Compress), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath "$p.tmp" -Destination $p -Force
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
    # Journal writes need administrator rights; the folder gets the protected ACL when it is created (review 3.6 R4).
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'The change journal is written with administrator rights only.' }
    $dir = Get-IgwtJournalFolder
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
        if (-not $script:IgwtSettings.TestMode) { Protect-IgwtDataRoot -Path $dir -Confirm:$false }
    }
    $segment = $j.Segment
    $segLines = [int]$j.SegmentLines
    # A cut-off or unterminated last line is finished in its own segment before any rollover.
    if (-not $segment -or ($segLines -ge $script:IgwtJournalSegmentLines -and -not $j.TornPending -and -not $j.NeedsBreak)) {
        # The next number after every segment file present (folded ones may already be deleted).
        # After a compaction the numbering continues after the folded segments too (review 3.6 R13).
        $folded = 0
        try { $cpx = Read-IgwtJournalCheckpoint; if ($cpx -and [string]$cpx['folded'] -match '^journal-(\d{4})\.jsonl$') { $folded = [int]$Matches[1] } } catch { $folded = 0 }
        $n = 1 + [int](@(Get-ChildItem -LiteralPath $dir -File -Filter 'journal-*.jsonl' | Where-Object { $_.Name -match '^journal-(\d{4})\.jsonl$' } | ForEach-Object { [int]$_.Name.Substring(8, 4) }) + @($folded) | Measure-Object -Maximum).Maximum
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
    # Readers share read and write, so an open reader never makes the append fail; a short retry covers the rest (review 3.6 R6).
    for ($try = 1; ; $try++) {
        try { $fs = New-Object System.IO.FileStream($segment, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete), 4096, [System.IO.FileOptions]::WriteThrough); break }
        catch [System.IO.IOException] { if ($try -ge 5) { throw }; Start-Sleep -Milliseconds (40 * $try) }
    }
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    $j.Hash = Get-IgwtJournalHash -Line $line; $j.Seq = [long]$o.seq; $j.Count = $j.Seq; $j.Status = 'Ok'
    $j.Segment = $segment; $j.SegmentLines = $segLines + $prefix.Count + 1; $j.NeedsBreak = $false
    Write-IgwtJournalHead -Seq $j.Seq -Hash $j.Hash
    $e = ConvertFrom-IgwtJournalLine -Line $line
    if ($key) {
        $kind = [string]$o.kind
        if ($kind -eq 'baseline' -and -not $j.Baselines.ContainsKey($key)) { $j.Baselines[$key] = $e }
        if ($kind -in 'committed', 'reverted', 'retired', 'adopted', 'rolledBack') { $j.Last[$key] = $e }
    }
    return $e
}
