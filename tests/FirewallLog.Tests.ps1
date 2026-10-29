BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $env:IGWT_GUI_STATE_DIR = Join-Path $TestDrive 'state'
    InModuleScope iGWindowsTuner { Initialize-IgwtFirewallLogEngine }
    $script:Header = "#Version: 1.5`r`n#Software: Microsoft Windows Firewall`r`n#Time Format: Local`r`n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid`r`n`r`n"
    function Format-TestLogLine([string]$Time = '2026-10-29 20:00:01', [string]$Action = 'DROP', [string]$Proto = 'TCP', [string]$Src = '203.0.113.5', [string]$Dst = '192.168.1.10', [string]$SrcPort = '51000', [string]$DstPort = '3389', [string]$Path = 'RECEIVE', [string]$ProcessId = '4') {
        "$Time $Action $Proto $Src $Dst $SrcPort $DstPort 52 S 1 0 64240 - - - $Path $ProcessId`r`n"
    }
    function Read-TestText([string]$Text) { InModuleScope iGWindowsTuner -Parameters @{ T = $Text } { param($T) ConvertFrom-IgwtFirewallLogText -Text $T } }
}
AfterAll { Remove-Item Env:\IGWT_GUI_STATE_DIR -ErrorAction SilentlyContinue }

# Firewall log engine (src\Defender\FirewallLogEngine.cs, DECISIONS F11): parser, live tail, query,
# aggregates and exports. Fixtures follow the real pfirewall.log layout (an empty line after the header).
Describe 'Firewall log parser' {
    It 'parses by the #Fields header, with typed numbers and local and UTC time texts' {
        $r = Read-TestText ($script:Header + (Format-TestLogLine) + (Format-TestLogLine -Action ALLOW -Proto UDP -Path SEND -ProcessId 999 -DstPort 53))
        $r.Entries.Count | Should -Be 2
        $r.Skipped.Empty | Should -Be 1
        $e = $r.Entries[0]
        $e.Action | Should -Be 'DROP'; $e.DestinationPortNumber | Should -Be 3389; $e.Pid | Should -Be 4; $e.SizeNumber | Should -Be 52
        $e.TimeText | Should -Be '2026-10-29 20:00:01'
        $e.TimeUtcText | Should -Be (([datetime]'2026-10-29 20:00:01').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC')
        $e.Info | Should -Be '' -Because 'a dash means no value'
        $r.Entries[1].Direction | Should -Be 'SEND'
    }
    It 'reads a header without pid and a header in another order' {
        $r = Read-TestText "#Fields: action dst-port date time`n`nDROP 445 2026-10-29 21:00:00`n"
        $r.Entries.Count | Should -Be 1
        $r.Entries[0].DestinationPort | Should -Be '445'; $r.Entries[0].ProcessId | Should -Be ''; $r.Entries[0].Pid | Should -Be -1
        $r.Entries[0].TimeText | Should -Be '2026-10-29 21:00:00'
    }
    It 'counts malformed, headerless and partial lines by reason' {
        $r = Read-TestText ("2026 before any header`n" + $script:Header + "too few fields`n" + (Format-TestLogLine) + '2026-10-29 20:00:02 DROP TC')
        $r.Entries.Count | Should -Be 1
        $r.Skipped.NoHeader | Should -Be 1; $r.Skipped.FieldCount | Should -Be 1; $r.Skipped.Partial | Should -Be 1
    }
    It 'converts times when the header says UTC (UNVERIFIED format, handled defensively)' {
        $r = Read-TestText "#Time Format: UTC`n#Fields: date time action`n2026-10-29 20:00:00 DROP`n"
        $r.Entries[0].Time | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-29 20:00:00', 'Utc').ToLocalTime())
    }
    It 'reads only the newest part of a file, starting at a full line' {
        $f = Join-Path $TestDrive 'tail.log'
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append($script:Header)
        for ($i = 0; $i -lt 2000; $i++) { $null = $sb.Append((Format-TestLogLine -SrcPort ([string](10000 + $i)))) }
        [IO.File]::WriteAllText($f, $sb.ToString())
        $r = InModuleScope iGWindowsTuner -Parameters @{ P = $f } { param($P) Read-IgwtFirewallLogFile -Path $P -TailBytes 5000 }
        $r.Reason | Should -Be 'Ok'
        @($r.Entries).Count | Should -BeGreaterThan 10
        @($r.Entries).Count | Should -BeLessThan 100
        $r.Entries[-1].SourcePort | Should -Be '11999'
        $r.Skipped.FieldCount | Should -Be 0 -Because 'the cut line before the first full line is dropped, not parsed'
    }
}

Describe 'Firewall log live tail' {
    It 'reads appended lines only, waits for a partial line, and starts over after a rotation' {
        $f = Join-Path $TestDrive 'live.log'
        [IO.File]::WriteAllText($f, $script:Header + (Format-TestLogLine))
        $first = InModuleScope iGWindowsTuner -Parameters @{ P = $f } { param($P) Read-IgwtFirewallLogFile -Path $P }
        $tail = InModuleScope iGWindowsTuner -Parameters @{ P = $f; O = $first.EndOffset; F = [string[]]$first.Fields } { param($P, $O, $F) New-IgwtFirewallLogTail -Path $P -Offset $O -Fields $F }
        [IO.File]::AppendAllText($f, (Format-TestLogLine -SrcPort 1) + '2026-10-29 20:00:09 DROP')
        $r = InModuleScope iGWindowsTuner -Parameters @{ T = $tail } { param($T) Invoke-IgwtFirewallLogTail -Tail @($T) }
        $r.Entries.Count | Should -Be 1
        $r.Entries[0].SourcePort | Should -Be '1'
        [IO.File]::AppendAllText($f, " TCP 1.1.1.1 2.2.2.2 5 6 52 S 1 0 64240 - - - RECEIVE 4`r`n")
        $r = InModuleScope iGWindowsTuner -Parameters @{ T = $tail } { param($T) Invoke-IgwtFirewallLogTail -Tail @($T) }
        $r.Entries.Count | Should -Be 1 -Because 'the partial line is read once it is complete'
        $r.Entries[0].Source | Should -Be '1.1.1.1'
        [IO.File]::WriteAllText($f, $script:Header + (Format-TestLogLine -SrcPort 7))
        $r = InModuleScope iGWindowsTuner -Parameters @{ T = $tail } { param($T) Invoke-IgwtFirewallLogTail -Tail @($T) }
        $r.Rotated | Should -Be 1
        $r.Entries.Count | Should -Be 1; $r.Entries[0].SourcePort | Should -Be '7'
    }
    It 'reports a problem instead of throwing when the file disappears' {
        $f = Join-Path $TestDrive 'gone.log'
        [IO.File]::WriteAllText($f, $script:Header)
        $tail = InModuleScope iGWindowsTuner -Parameters @{ P = $f } { param($P) New-IgwtFirewallLogTail -Path $P }
        Remove-Item -LiteralPath $f
        $r = InModuleScope iGWindowsTuner -Parameters @{ T = $tail } { param($T) Invoke-IgwtFirewallLogTail -Tail @($T) }
        @($r.Messages).Count | Should -Be 1
        $r.Messages[0] | Should -Match 'does not exist'
    }
}

Describe 'Firewall log query and aggregates' {
    BeforeAll {
        $lines = @(
            (Format-TestLogLine -Time '2026-10-29 20:00:00' -Src '203.0.113.5' -DstPort 3389)
            (Format-TestLogLine -Time '2026-10-29 20:10:00' -Src '203.0.113.9' -DstPort 445)
            (Format-TestLogLine -Time '2026-10-29 21:00:00' -Src '198.51.100.7' -DstPort 3389 -Proto UDP)
            (Format-TestLogLine -Time '2026-10-29 21:30:00' -Action ALLOW -Src '192.168.1.10' -Dst '13.107.4.50' -SrcPort 50123 -DstPort 443 -Path SEND -ProcessId 999)
            (Format-TestLogLine -Time '2026-10-29 21:40:00' -Src '2001:db8::5' -Dst '2001:db8::1' -DstPort 3389)
        )
        $script:All = (Read-TestText ($script:Header + ($lines -join ''))).Entries
    }
    It 'filters by action, direction, protocol, port and time' {
        $q = New-Object IgwtFirewallLog.Query; $q.Actions = [string[]]@('DROP'); $q.Protocols = [string[]]@('TCP'); $q.Ports = [int[]]@(3389)
        @([IgwtFirewallLog.Engine]::Run($script:All, $q)).Count | Should -Be 2
        $q = New-Object IgwtFirewallLog.Query; $q.Directions = [string[]]@('SEND')
        @([IgwtFirewallLog.Engine]::Run($script:All, $q)).Count | Should -Be 1
        $q = New-Object IgwtFirewallLog.Query; $q.From = [datetime]'2026-10-29 21:00:00'; $q.To = [datetime]'2026-10-29 21:35:00'
        @([IgwtFirewallLog.Engine]::Run($script:All, $q)).Count | Should -Be 2
    }
    It 'matches exact addresses and CIDR networks (IPv4 and IPv6) on either side' {
        foreach ($case in @(@('203.0.113.0/28', 2), @('203.0.113.9', 1), @('13.107.0.0/16', 1), @('2001:db8::/32', 1), @('10.0.0.0/8', 0))) {
            $q = New-Object IgwtFirewallLog.Query; $q.Address = $case[0]
            @([IgwtFirewallLog.Engine]::Run($script:All, $q)).Count | Should -Be $case[1] -Because $case[0]
        }
        $net = $null; $prefix = 0
        [IgwtFirewallLog.Engine]::TryParseNetwork('300.1.1.1', [ref]$net, [ref]$prefix) | Should -BeFalse
        [IgwtFirewallLog.Engine]::TryParseNetwork('10.0.0.0/33', [ref]$net, [ref]$prefix) | Should -BeFalse
    }
    It 'searches every word in any field (case-insensitive) and sorts by several keys' {
        $q = New-Object IgwtFirewallLog.Query; $q.Search = 'receive 3389'
        @([IgwtFirewallLog.Engine]::Run($script:All, $q)).Count | Should -Be 3
        $q = New-Object IgwtFirewallLog.Query; $q.SortKeys = [string[]]@('DestinationPort', 'TimeText'); $q.SortDescending = [bool[]]@($false, $true)
        $s = [IgwtFirewallLog.Engine]::Run($script:All, $q)
        @($s | ForEach-Object { $_.DestinationPort }) | Should -Be @('443', '445', '3389', '3389', '3389')
        $s[2].TimeText | Should -Be '2026-10-29 21:40:00' -Because 'time is the second key, newest first'
    }
    It 'counts top values, a histogram and a summary' {
        $top = [IgwtFirewallLog.Engine]::Top($script:All, 'Port', 'DROP', 2)
        $top[0].Value | Should -Be 'TCP/3389'; $top[0].Hits | Should -Be 2
        $h = [IgwtFirewallLog.Engine]::Histogram($script:All, 60)
        @($h).Count | Should -Be 2; $h[0].Dropped | Should -Be 2; $h[1].Allowed | Should -Be 1
        $s = [IgwtFirewallLog.Engine]::Summarize($script:All)
        $s.Dropped | Should -Be 4; $s.Allowed | Should -Be 1; $s.From | Should -Be ([datetime]'2026-10-29 20:00:00')
        @([IgwtFirewallLog.Engine]::Top($script:All, 'Remote', '', 0) | ForEach-Object { $_.Value }) | Should -Contain '13.107.4.50' -Because 'outbound entries count the destination as remote'
    }
    It 'names processes best effort and keeps notes by a stable key' {
        $names = New-Object 'System.Collections.Generic.Dictionary[int,string]'; $names[4] = 'System'
        [IgwtFirewallLog.Engine]::SetProcessNames($script:All, $names, 'pid {0} (ended)') | Should -Be 4
        $script:All[3].Process | Should -Be 'pid 999 (ended)'
        $notes = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $notes[[IgwtFirewallLog.Engine]::NoteKey($script:All[1])] = 'port scan?'
        $again = (Read-TestText ($script:Header + (Format-TestLogLine -Time '2026-10-29 20:10:00' -Src '203.0.113.9' -DstPort 445))).Entries
        [IgwtFirewallLog.Engine]::ApplyNotes($again, $notes) | Should -Be 1
        $again[0].Note | Should -Be 'port scan?'
        $q = New-Object IgwtFirewallLog.Query; $q.NotesOnly = $true
        @([IgwtFirewallLog.Engine]::Run($again, $q)).Count | Should -Be 1
    }
}

Describe 'Firewall log exports treat field values as untrusted' {
    It 'protects CSV cells from formula injection (engine and PowerShell agree)' {
        foreach ($v in '=cmd|calc', '+1', '-2', '@SUM(A1)', "`tx", "`rx") {
            [IgwtFirewallLog.Engine]::CsvCell($v) | Should -Be ('"' + "'" + $v + '"')
            InModuleScope iGWindowsTuner -Parameters @{ V = $v } { param($V) Protect-IgwtCsvValue $V } | Should -Be ("'" + $v)
        }
        [IgwtFirewallLog.Engine]::CsvCell('a "b"') | Should -Be '"a ""b"""'
        $lines = InModuleScope iGWindowsTuner { ConvertTo-IgwtSafeCsv -Rows @([pscustomobject]@{ A = '=1+1'; B = 'ok' }) }
        $lines[1] | Should -Be '"''=1+1","ok"'
    }
    It 'escapes JSON so a value cannot break out of its string' {
        [IgwtFirewallLog.Engine]::JsonString("a`"b\c`nd$([char]0x2028)") | Should -Be ('"a\"b\\c\nd\' + 'u2028"')
        $e = (Read-TestText ($script:Header + (Format-TestLogLine))).Entries
        $json = ([IgwtFirewallLog.Engine]::JsonArrayLines($e, [string[]]@('Source', 'Action'), [string[]]@('Source', 'Action'))) -join "`n"
        $o = $json | ConvertFrom-Json
        $o[0].Source | Should -Be '203.0.113.5'
    }
}

Describe 'Firewall log filter row' {
    It 'validates address, port and time filters with clear messages' {
        InModuleScope iGWindowsTuner {
            (Test-IgwtGuiFirewallLogFilter -Address '192.168.1.0/24' -Port '80, 443' -From '2026-10-29 20:00').Filters['@Port'] | Should -Be @('80', '443')
            (Test-IgwtGuiFirewallLogFilter -Address 'not-an-ip').Error | Should -Match 'not an IP address'
            (Test-IgwtGuiFirewallLogFilter -Port '70000').Error | Should -Match '0 to 65535'
            (Test-IgwtGuiFirewallLogFilter -From '29.10.2026').Error | Should -Match 'yyyy-MM-dd HH:mm'
            (Test-IgwtGuiFirewallLogFilter -From '2026-10-29 21:00' -To '2026-10-29 20:00').Error | Should -Match 'after'
        }
    }
    It 'turns chips and filters into an engine query (newest first by default)' {
        InModuleScope iGWindowsTuner {
            $grid = @{ Search = 'x'; Chips = @(Get-IgwtGuiFirewallLogChips); ActiveChips = (New-Object 'System.Collections.Generic.HashSet[string]'); ColumnFilters = @{ '@Address' = @('10.0.0.0/8'); '@Port' = @('53'); Source = @('1.2.3.4') }; Sort = @() }
            $null = $grid.ActiveChips.Add('drop'); $null = $grid.ActiveChips.Add('t60'); $null = $grid.ActiveChips.Add('out')
            $now = [datetime]'2026-10-29 22:00'
            $q = ConvertTo-IgwtGuiFirewallLogQuery -Grid $grid -Now $now
            $q.Actions | Should -Be @('DROP'); $q.Directions | Should -Be @('SEND'); $q.From | Should -Be $now.AddMinutes(-60)
            $q.Address | Should -Be '10.0.0.0/8'; $q.Ports | Should -Be @(53); $q.Columns['Source'] | Should -Be @('1.2.3.4')
            $q.SortKeys | Should -Be @('TimeText'); $q.SortDescending | Should -Be @($true)
        }
    }
}

Describe 'Firewall log performance budgets (spec 3.5 section 3.1)' {
    BeforeAll {
        # A 32 MB log with the real column layout, built from a block of varied lines.
        $block = New-Object System.Text.StringBuilder
        $rnd = New-Object System.Random(7)
        for ($i = 0; $i -lt 1000; $i++) {
            $null = $block.Append((Format-TestLogLine -Time ('2026-10-29 {0:00}:{1:00}:{2:00}' -f ($i % 24), ($i % 60), ($i % 60)) -Action $(if ($i % 3) { 'DROP' } else { 'ALLOW' }) -Proto $(if ($i % 2) { 'TCP' } else { 'UDP' }) -Src "203.0.113.$($rnd.Next(255))" -Dst "192.168.1.$($rnd.Next(255))" -SrcPort ([string]$rnd.Next(1024, 65535)) -DstPort ([string]@(443, 80, 53, 3389, 445)[$i % 5]) -Path $(if ($i % 2) { 'SEND' } else { 'RECEIVE' }) -ProcessId ([string]$rnd.Next(4, 20000))))
        }
        $text = $block.ToString()
        $script:Big = Join-Path $TestDrive 'big.log'
        $w = New-Object System.IO.StreamWriter($script:Big, $false, (New-Object System.Text.UTF8Encoding($false)))
        try { $w.Write($script:Header); while ($w.BaseStream.Length -lt 32MB) { $w.Write($text); $w.Flush() } } finally { $w.Dispose() }
    }
    It 'parses 32 MB in under 5 s and shows the newest rows in under 1 s' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $first = InModuleScope iGWindowsTuner -Parameters @{ P = $script:Big } { param($P) Read-IgwtFirewallLogFile -Path $P -TailBytes 1MB }
        $firstMs = $sw.ElapsedMilliseconds
        $sw.Restart()
        $r = InModuleScope iGWindowsTuner -Parameters @{ P = $script:Big } { param($P) Read-IgwtFirewallLogFile -Path $P }
        $fullMs = $sw.ElapsedMilliseconds
        Write-Information -InformationAction Continue -MessageData ("    32 MB log: {0:N0} entries in {1:N0} ms; newest {2:N0} in {3:N0} ms" -f @($r.Entries).Count, $fullMs, @($first.Entries).Count, $firstMs)
        @($r.Entries).Count | Should -BeGreaterThan 250000
        $fullMs | Should -BeLessThan 5000
        $firstMs | Should -BeLessThan 1000
        $script:BigRows = New-Object 'System.Collections.Generic.List[IgwtFirewallLog.Entry]'
        $script:BigRows.AddRange([IgwtFirewallLog.Entry[]]$r.Entries)
    }
    It 'filters, searches and sorts 250,000+ rows in under 300 ms each' {
        $cases = @(
            @{ Name = 'action'; Q = { $q = New-Object IgwtFirewallLog.Query; $q.Actions = [string[]]@('DROP'); $q } }
            @{ Name = 'CIDR'; Q = { $q = New-Object IgwtFirewallLog.Query; $q.Address = '203.0.113.0/28'; $q } }
            @{ Name = 'search'; Q = { $q = New-Object IgwtFirewallLog.Query; $q.Search = '3389 receive'; $q } }
            @{ Name = 'sort 2 keys'; Q = { $q = New-Object IgwtFirewallLog.Query; $q.SortKeys = [string[]]@('Source', 'TimeText'); $q.SortDescending = [bool[]]@($false, $true); $q } }
        )
        # Warm-up (first CIDR query parses the addresses once).
        $null = [IgwtFirewallLog.Engine]::Run($script:BigRows, (& $cases[1].Q))
        foreach ($case in $cases) {
            $q = & $case.Q
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $n = @([IgwtFirewallLog.Engine]::Run($script:BigRows, $q)).Count
            $ms = $sw.ElapsedMilliseconds
            Write-Information -InformationAction Continue -MessageData ("    {0}: {1:N0} rows in {2} ms" -f $case.Name, $n, $ms)
            $ms | Should -BeLessThan 300 -Because "$($case.Name) on $($script:BigRows.Count) rows"
        }
    }
}
