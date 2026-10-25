BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Xaml = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\src\Gui\MainWindow.xaml'))
}

# 3.3 phase 5, the remaining sections: grouped navigation (X11), dashboard (D1, D2), presets
# compare (O3), network test history (N1, N2), compliance (R1), log viewer (L1), About (B1).
Describe '3.3 professional pass: remaining sections' {
    It 'puts every navigation page in a group' {
        $tags = @([regex]::Matches($script:Xaml, '<ListBoxItem Tag="([^"]+)"') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) })
        $tags.Count | Should -BeGreaterThan 20
        InModuleScope iGWindowsTuner -Parameters @{ Tags = $tags } {
            param($Tags)
            $grouped = @($script:IgwtGuiNavGroups.Values | ForEach-Object { $_ })
            foreach ($t in $Tags) { $grouped | Should -Contain $t -Because "$t needs a navigation group" }
            Test-IgwtGuiNavHeader -Item ([pscustomobject]@{ Tag = '#group:Start' }) | Should -BeTrue
            Test-IgwtGuiNavHeader -Item ([pscustomobject]@{ Tag = 'Dashboard' }) | Should -BeFalse
        }
    }

    It 'never shows an empty "Fix:" route (D2)' {
        InModuleScope iGWindowsTuner {
            (New-IgwtGuiSecurityCheckRow -Check ([pscustomobject]@{ Status = 'Fail'; Name = 'x'; Value = 'Off'; Fix = 'Tweak'; Target = ''; Hint = 'h' })).Route | Should -Be ''
            (New-IgwtGuiSecurityCheckRow -Check ([pscustomobject]@{ Status = 'Fail'; Name = 'x'; Value = 'Off'; Fix = 'Tweak'; Target = 'sec.a'; Hint = 'h' })).Route | Should -Be 'Fix: sec.a'
            (New-IgwtGuiSecurityCheckRow -Check ([pscustomobject]@{ Status = 'Fail'; Name = 'x'; Value = 'Off'; Fix = 'AsrCenter'; Target = ''; Hint = 'h' })).Route | Should -Be 'Fix: ASR Center'
        }
    }

    It 'compares a preset with the current state by category, highest impact first (O3)' {
        InModuleScope iGWindowsTuner {
            $cat = @(
                [pscustomobject]@{ id = 'a.one'; name = 'One'; category = 'Network'; level = 'Standard'; impact = [pscustomobject]@{ performance = 'low'; latency = 'high' } }
                [pscustomobject]@{ id = 'a.two'; name = 'Two'; category = 'Network'; level = 'Advanced'; impact = [pscustomobject]@{ performance = 'low'; latency = 'low' } }
                [pscustomobject]@{ id = 'b.one'; name = 'Three'; category = 'Input'; level = 'Standard'; impact = [pscustomobject]@{ performance = 'medium'; latency = 'none' } }
                [pscustomobject]@{ id = 'b.two'; name = 'Four'; category = 'Input'; level = 'Standard'; impact = $null }
            )
            $states = @{ 'a.one' = [pscustomobject]@{ State = 'Off' }; 'a.two' = [pscustomobject]@{ State = 'Partial' }; 'b.one' = [pscustomobject]@{ State = 'Off' }; 'b.two' = [pscustomobject]@{ State = 'On' } }
            Mock Get-IgwtGuiPresetMembers { @('a.one', 'a.two', 'b.one', 'b.two') }
            $d = Get-IgwtGuiPresetDiff -Preset ([pscustomobject]@{ id = 'p' }) -Catalog $cat -States $states
            $d.Count | Should -Be 3 -Because 'items already on are not changes'
            ($d.ByCategory | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ',' | Should -Be 'Network=2,Input=1'
            @($d.Rows | Where-Object Category -EQ 'Network')[0].Name | Should -Be 'One' -Because 'high impact first'
            @($d.Rows | Where-Object Id -EQ 'a.one')[0].Impact | Should -Be 'high'
        }
    }

    It 'keeps the last 50 network test summaries without addresses and compares each run with the one before (N2)' {
        InModuleScope iGWindowsTuner {
            $p = Join-Path $TestDrive 'network-history.json'
            $mk = { param($t, $ping) [pscustomobject]@{ Generated = $t; Duration = 'Quick'; Score = [pscustomobject]@{ Grade = 'A'; Score = 90; Mos = 4.3; Stability = 'A' }; Internet = [pscustomobject]@{ Stats = [pscustomobject]@{ MedianMs = $ping; JitterMs = 1; LossPercent = 0 } }; Bufferbloat = $null; TypeGuess = [pscustomobject]@{ Access = 'Fiber' }; Connection = [pscustomobject]@{ Gateway = '192.168.1.1' } } }
            foreach ($i in 1..52) { Add-IgwtGuiNetHistory -Result (& $mk ([datetime]'2026-10-01').AddHours($i) (10 + $i)) -Path $p }
            $h = @(Get-IgwtGuiNetHistory -Path $p)
            $h.Count | Should -Be 50
            $h[0].PingMs | Should -Be 62 -Because 'newest first'
            [IO.File]::ReadAllText($p) | Should -Not -Match '192\.168' -Because 'no addresses are kept'
            $rows = @(New-IgwtGuiNetHistoryRows -Runs $h)
            $rows[0].PingChange | Should -Be '+1 ms'
            $rows[-1].PingChange | Should -Be 'first run'
            @(Get-IgwtGuiNetHistory -Path (Join-Path $TestDrive 'none.json')).Count | Should -Be 0
        }
    }

    It 'reads the log of the last days, newest first, from the JSON-lines files (L1)' {
        InModuleScope iGWindowsTuner {
            $dir = Join-Path $TestDrive 'logs'; $null = New-Item -ItemType Directory -Path $dir -Force
            $today = (Get-Date).ToString('yyyyMMdd'); $old = (Get-Date).AddDays(-30).ToString('yyyyMMdd')
            @(('{"time":"' + (Get-Date).AddMinutes(-5).ToString('o') + '","session":"s1","level":"Info","message":"first"}'), 'not json', ('{"time":"' + (Get-Date).ToString('o') + '","session":"s1","level":"Error","message":"second","tweak":"net.x"}')) | Set-Content -LiteralPath (Join-Path $dir "iGWindowsTuner-$today.jsonl") -Encoding UTF8
            '{"time":"2026-01-01T00:00:00Z","session":"s0","level":"Info","message":"old"}' | Set-Content -LiteralPath (Join-Path $dir "iGWindowsTuner-$old.jsonl") -Encoding UTF8
            $e = @(Get-IgwtLogEntries -Days 7 -Folder $dir)
            $e.Count | Should -Be 2
            $e[0].Message | Should -Be 'second'
            $e[0].Tweak | Should -Be 'net.x'
            (New-IgwtGuiLogRow -Entry $e[0] -Index 1).Level | Should -Be 'Error'
        }
    }

    It 'compares a baseline folder read-only and maps the statuses (R1)' {
        InModuleScope iGWindowsTuner {
            Mock Import-IgwtPolicyBaseline { [pscustomobject]@{ Path = $Path; Gpos = @() } }
            Mock Compare-IgwtPolicyBaseline { @([pscustomobject]@{ Gpo = 'G'; Area = 'Audit'; Setting = 'Logon'; Baseline = 'Success'; LocalGpo = ''; Effective = ''; Status = 'NotSet'; Ref = 'Audit|x' }) }
            $r = @(Get-IgwtPolicyBaselineComparison -Path 'C:\baseline')
            $r.Count | Should -Be 1
            Should -Invoke Import-IgwtPolicyBaseline -Times 1 -Exactly -ParameterFilter { $Path -eq 'C:\baseline' }
            $row = New-IgwtGuiComplianceRow -Row $r[0] -Index 1
            $row.StatusRank | Should -Be 1
            $row.StatusCol | Should -Be 'Not set'
        }
    }

    It 'shows build information without user or device names and notes missing documents (B1)' {
        InModuleScope iGWindowsTuner {
            $b = Get-IgwtGuiBuildInfo
            $b | Should -Match "Version\s+$([regex]::Escape($script:IgwtVersion))"
            $b | Should -Not -Match ([regex]::Escape($env:COMPUTERNAME))
            $b | Should -Not -Match ([regex]::Escape($env:USERNAME))
            Get-IgwtGuiDocText -Name 'no-such-file.md' | Should -Match 'not included'
            Get-IgwtGuiDocText -Name 'THIRD_PARTY_NOTICES.md' | Should -Match 'WinUtil'
        }
    }

    It 'loads and normalizes the tweak catalog within 1 s (3.3 phase 7: it was about 0.6 s, now about 0.15 s)' {
        InModuleScope iGWindowsTuner {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $c = @(Get-IgwtCatalog -Force)
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 1
            $c.Count | Should -BeGreaterThan 100
            @($c | Where-Object { $null -eq $_.conflictsWith }).Count | Should -Be 0 -Because 'defaults are arrays, never $null'
        }
    }
}
