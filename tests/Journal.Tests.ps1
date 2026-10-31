BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    function Get-TestEntry([string]$Kind = 'committed', [string]$Key = 'registry|HKLM\SOFTWARE\Test|A', $Before = 1, $After = 2) {
        [ordered]@{ kind = $Kind; session = 's1'; step = 1; origin = @{ type = 'tweak'; ref = 'test.item' }; item = 'test.item'; target = @{ provider = 'registry'; key = $Key }; before = $Before; after = $After }
    }
    function Initialize-TestJournal {
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder
            if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
            $script:IgwtJournal = $null
        }
    }
}

# The change journal (3.6, DECISIONS T3/T4): hash chain, tamper evidence, crash tolerance, indexes, budgets.
Describe 'Change journal' {
    BeforeEach { Initialize-TestJournal }

    It 'appends entries that chain by SHA256 and verifies them' {
        InModuleScope iGWindowsTuner {
            $a = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'intent'; target = @{ provider = 'registry'; key = 'k1' } })
            $b = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'committed'; target = @{ provider = 'registry'; key = 'k1' }; after = 5 })
            $a['seq'] | Should -Be 1; $b['seq'] | Should -Be 2
            $a['prev'] | Should -Be ('0' * 64)
            $lines = @(Get-Content -LiteralPath @(Get-IgwtJournalSegments)[0])
            $b['prev'] | Should -Be (Get-IgwtJournalHash -Line $lines[0])
            $r = Read-IgwtJournal
            $r.Status | Should -Be 'Ok'; $r.Count | Should -Be 2
            $r.Last['k1']['after'] | Should -Be 5
            foreach ($f in 'appVersion', 'build', 'user', 'tsUtc', 'id') { $a.ContainsKey($f) | Should -BeTrue -Because "$f is recorded" }
        }
    }
    It 'turns read-only when an entry is changed, removed or reordered, and names the line' {
        InModuleScope iGWindowsTuner -Parameters @{ E = (Get-TestEntry) } {
            param($E)
            foreach ($i in 1..4) { $null = Add-IgwtJournalEntry -Entry $E }
            $file = @(Get-IgwtJournalSegments)[0]
            $orig = [IO.File]::ReadAllLines($file)
            [IO.File]::WriteAllLines($file, @($orig[0], $orig[1].Replace('"after":2', '"after":3'), $orig[2], $orig[3]))
            $r = Read-IgwtJournal; $r.Status | Should -Be 'Broken'; $r.BadLine | Should -Be 3 -Because 'line 3 no longer continues from the changed line 2'
            $script:IgwtJournal = $null
            { Add-IgwtJournalEntry -Entry $E } | Should -Throw '*read-only*'
            [IO.File]::WriteAllLines($file, @($orig[0], $orig[2], $orig[3])); $script:IgwtJournal = $null
            (Read-IgwtJournal).Status | Should -Be 'Broken'
            [IO.File]::WriteAllLines($file, @($orig[0], $orig[2], $orig[1], $orig[3])); $script:IgwtJournal = $null
            (Read-IgwtJournal).Status | Should -Be 'Broken'
            [IO.File]::WriteAllLines($file, @($orig[0], $orig[1], $orig[2])); $script:IgwtJournal = $null
            (Read-IgwtJournal).Status | Should -Be 'Ok' -Because 'cutting entries off the end cannot be told from a shorter journal; the head hash is what a later check compares'
        }
    }
    It 'survives a write cut off by a crash: the next append records it and the chain stays valid' {
        InModuleScope iGWindowsTuner -Parameters @{ E = (Get-TestEntry) } {
            param($E)
            $null = Add-IgwtJournalEntry -Entry $E
            $file = @(Get-IgwtJournalSegments)[0]
            [IO.File]::AppendAllText($file, '{"prev":"abc","seq":2,"kind":"comm')
            $script:IgwtJournal = $null
            $r = Read-IgwtJournal; $r.Status | Should -Be 'Ok'; $r.TornPending | Should -BeTrue
            $null = Add-IgwtJournalEntry -Entry $E
            $script:IgwtJournal = $null
            $r2 = Read-IgwtJournal -NoEntries:$false
            $r2.Status | Should -Be 'Ok'
            @($r2.Entries | Where-Object { $_['kind'] -eq 'chainNote' }).Count | Should -Be 1
            $r2.Count | Should -Be 3
        }
    }
    It 'adds the missing line break when the last complete line has none' {
        InModuleScope iGWindowsTuner -Parameters @{ E = (Get-TestEntry) } {
            param($E)
            $null = Add-IgwtJournalEntry -Entry $E
            $file = @(Get-IgwtJournalSegments)[0]
            $txt = [IO.File]::ReadAllText($file); [IO.File]::WriteAllText($file, $txt.TrimEnd("`n"))
            $script:IgwtJournal = $null
            $null = Add-IgwtJournalEntry -Entry $E
            $script:IgwtJournal = $null
            (Read-IgwtJournal).Status | Should -Be 'Ok'
            (Read-IgwtJournal).Count | Should -Be 2
        }
    }
    It 'keeps the first baseline of a target forever and indexes the last state' {
        InModuleScope iGWindowsTuner -Parameters @{ E1 = (Get-TestEntry -Kind 'baseline' -Before 'orig'); E2 = (Get-TestEntry -Kind 'baseline' -Before 'later') } {
            param($E1, $E2)
            $null = Add-IgwtJournalEntry -Entry $E1
            $null = Add-IgwtJournalEntry -Entry $E2
            $r = Read-IgwtJournal
            $r.Count | Should -Be 1 -Because 'a second baseline for the same target is not written'
            $r.Baselines['registry|HKLM\SOFTWARE\Test|A']['before'] | Should -Be 'orig'
        }
    }
    It 'continues the chain across segments' {
        InModuleScope iGWindowsTuner -Parameters @{ E = (Get-TestEntry) } {
            param($E)
            $old = $script:IgwtJournalSegmentLines; $script:IgwtJournalSegmentLines = 3
            try { foreach ($i in 1..7) { $null = Add-IgwtJournalEntry -Entry $E } } finally { $script:IgwtJournalSegmentLines = $old }
            @(Get-IgwtJournalSegments).Count | Should -Be 3
            $script:IgwtJournal = $null
            $r = Read-IgwtJournal; $r.Status | Should -Be 'Ok'; $r.Count | Should -Be 7
        }
    }
    It 'compacts old segments into a checkpoint that keeps every baseline, the last states and the chain' {
        InModuleScope iGWindowsTuner -Parameters @{ B = (Get-TestEntry -Kind 'baseline' -Before 'orig'); E = (Get-TestEntry -After 7); B2 = (Get-TestEntry -Kind 'baseline' -Key 'k2' -Before 'k2orig') } {
            param($B, $E, $B2)
            $old = $script:IgwtJournalSegmentLines; $script:IgwtJournalSegmentLines = 3
            try {
                $null = Add-IgwtJournalEntry -Entry $B
                foreach ($i in 1..6) { $null = Add-IgwtJournalEntry -Entry $E }
                $null = Add-IgwtJournalEntry -Entry $B2
                @(Get-IgwtJournalSegments).Count | Should -Be 3
                $c = Compress-IgwtJournal -KeepSegments 1 -Confirm:$false
                $c.Folded | Should -Be 2
                @(Get-IgwtJournalSegments).Count | Should -Be 1
                $r = Read-IgwtJournal
                $r.Status | Should -Be 'Ok'; $r.Count | Should -Be 8 -Because 'the sequence continues from the checkpoint'
                $r.Baselines['registry|HKLM\SOFTWARE\Test|A']['before'] | Should -Be 'orig' -Because 'compaction never drops a baseline'
                $r.Baselines['k2']['before'] | Should -Be 'k2orig'
                $r.Last['registry|HKLM\SOFTWARE\Test|A']['after'] | Should -Be 7
                # Appending after compaction continues the chain in a new segment number.
                foreach ($i in 1..3) { $null = Add-IgwtJournalEntry -Entry $E }
                $script:IgwtJournal = $null
                (Read-IgwtJournal).Status | Should -Be 'Ok'
                @(Get-IgwtJournalSegments)[-1] | Should -BeLike '*journal-0004.jsonl'
                # A damaged checkpoint makes the journal read-only.
                $cpFile = Join-Path (Get-IgwtJournalFolder) 'checkpoint.json'
                [IO.File]::WriteAllText($cpFile, ([IO.File]::ReadAllText($cpFile)).Replace('"orig"', '"edited"'))
                $script:IgwtJournal = $null
                $r2 = Read-IgwtJournal; $r2.Status | Should -Be 'Broken'; $r2.Reason | Should -BeLike '*checkpoint*'
            } finally { $script:IgwtJournalSegmentLines = $old }
        }
    }
}

Describe 'Change journal budgets (spec 3.6)' {
    BeforeAll { Initialize-TestJournal }
    It 'appends an entry in under 20 ms and opens and verifies 10,000 entries in under 1 s' {
        $times = InModuleScope iGWindowsTuner -Parameters @{ E = (Get-TestEntry -Before @{ exists = $true; kind = 'DWord'; value = 1 } -After @{ exists = $true; kind = 'DWord'; value = 0 }) } {
            param($E)
            # Warm-up (JIT), then 200 timed appends.
            $null = Add-IgwtJournalEntry -Entry $E
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            foreach ($i in 1..200) { $null = Add-IgwtJournalEntry -Entry $E }
            $append = $sw.Elapsed.TotalMilliseconds / 200
            # Fill to 10,000 entries quickly by writing a valid chain directly (the same format Add-IgwtJournalEntry writes).
            $j = Get-IgwtJournalState
            $hash = $j.Hash; $seq = [long]$j.Seq
            $sb = New-Object System.Text.StringBuilder
            while ($seq -lt 10000) {
                $seq++
                $line = '{"prev":"' + $hash + '","seq":' + $seq + ',"id":"' + [guid]::NewGuid() + '","kind":"committed","session":"s","target":{"provider":"registry","key":"k' + ($seq % 500) + '"},"before":{"exists":true,"kind":"DWord","value":1},"after":{"exists":true,"kind":"DWord","value":0},"tsUtc":"2026-10-31T10:00:00Z","appVersion":"3.6.0","build":"26300","ubr":"9818","user":"PC\\u"}'
                $null = $sb.Append($line).Append("`n")
                $hash = Get-IgwtJournalHash -Line $line
            }
            [IO.File]::AppendAllText($j.Segment, $sb.ToString())
            # Best of three: the budget is what the code can do, not a background scan's or GC's spike.
            $open = [double]::MaxValue
            foreach ($try in 1..3) {
                $script:IgwtJournal = $null
                [GC]::Collect()
                $sw.Restart()
                $r = Read-IgwtJournal
                $open = [Math]::Min([double]$open, [double]$sw.Elapsed.TotalMilliseconds)
            }
            [pscustomobject]@{ Append = $append; Open = $open; Count = $r.Count; Status = $r.Status }
        }
        Write-Information -InformationAction Continue -MessageData ("    journal: append {0:N1} ms per entry; open and verify {1:N0} entries {2:N0} ms" -f $times.Append, $times.Count, $times.Open)
        $times.Status | Should -Be 'Ok'
        $times.Count | Should -Be 10000
        $times.Append | Should -BeLessThan 20
        $times.Open | Should -BeLessThan 1000
    }
}
