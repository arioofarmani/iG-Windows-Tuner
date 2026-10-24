BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'SmartGrid query engine' {
    BeforeAll {
        $script:Rows = @(
            [pscustomobject]@{ Name = 'Steam'; Group = 'Games'; Port = 27015; Direction = 'Inbound'; Profiles = @('Private', 'Public'); When = [datetime]'2026-01-03' }
            [pscustomobject]@{ Name = 'apex'; Group = 'Games'; Port = 37005; Direction = 'Outbound'; Profiles = @('Private'); When = [datetime]'2026-03-01' }
            [pscustomobject]@{ Name = 'Core Networking'; Group = 'Windows'; Port = 80; Direction = 'Inbound'; Profiles = @('Domain'); When = [datetime]'2025-12-24' }
            [pscustomobject]@{ Name = 'Discord'; Group = 'Chat'; Port = 443; Direction = 'Outbound'; Profiles = @('Public'); When = $null }
            [pscustomobject]@{ Name = 'Battle.net'; Group = 'Games'; Port = 1119; Direction = 'Inbound'; Profiles = @('Public'); When = [datetime]'2026-02-10' }
        )
        $script:Cols = @(@{ Key = 'Name' }, @{ Key = 'Group' }, @{ Key = 'Port'; Kind = 'Number' }, @{ Key = 'Direction' }, @{ Key = 'Profiles' }, @{ Key = 'When'; Kind = 'Date'; Search = $false })
    }

    It 'normalizes column definitions with safe defaults' {
        InModuleScope iGWindowsTuner {
            $c = ConvertTo-IgwtGridColumn -Definition @{ Key = 'Port'; Kind = 'Weird'; Template = 'Nope' }
            $c.Kind | Should -Be 'Text'
            $c.Template | Should -Be 'Text'
            $c.Header | Should -Be 'Port'
            $c.SortKey | Should -Be 'Port'
            { ConvertTo-IgwtGridColumn -Definition @{ Header = 'x' } } | Should -Throw
        }
    }

    It 'sorts text case-insensitively, numbers numerically and dates by time, both directions' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Rows; Cols = $script:Cols } {
            param($Rows, $Cols)
            $ix = New-IgwtGridIndex -Rows $Rows -Columns $Cols
            $names = { param($o) @($o | ForEach-Object { $ix.Rows[$_].Name }) }
            (& $names (Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Name' }))) | Should -Be @('apex', 'Battle.net', 'Core Networking', 'Discord', 'Steam')
            (& $names (Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Port'; Descending = $true }))) | Should -Be @('apex', 'Steam', 'Battle.net', 'Discord', 'Core Networking')
            (& $names (Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Port' })))[0] | Should -Be 'Core Networking'
            # Missing dates sort first ascending.
            (& $names (Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'When' }))) | Should -Be @('Discord', 'Core Networking', 'Steam', 'Battle.net', 'apex')
        }
    }

    It 'sorts by several columns, keeping ties in their original order' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Rows; Cols = $script:Cols } {
            param($Rows, $Cols)
            $ix = New-IgwtGridIndex -Rows $Rows -Columns $Cols
            $o = Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Group' }, @{ Key = 'Port'; Descending = $true })
            @($o | ForEach-Object { $ix.Rows[$_].Name }) | Should -Be @('Discord', 'apex', 'Steam', 'Battle.net', 'Core Networking')
            $o2 = Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Direction' })
            # Stable: within Inbound the original order Steam, Core Networking, Battle.net is kept.
            @($o2 | ForEach-Object { $ix.Rows[$_].Name }) | Should -Be @('Steam', 'Core Networking', 'Battle.net', 'apex', 'Discord')
        }
    }

    It 'searches all words across the searchable columns, case-insensitively' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Rows; Cols = $script:Cols } {
            param($Rows, $Cols)
            $ix = New-IgwtGridIndex -Rows $Rows -Columns $Cols
            (Invoke-IgwtGridQuery -Index $ix -Search 'GAMES inbound').Count | Should -Be 2
            (Invoke-IgwtGridQuery -Index $ix -Search '443').Count | Should -Be 1
            (Invoke-IgwtGridQuery -Index $ix -Search 'public').Count | Should -Be 3
            (Invoke-IgwtGridQuery -Index $ix -Search 'nothing-like-this').Count | Should -Be 0
            (Invoke-IgwtGridQuery -Index $ix -Search '   ').Count | Should -Be 5
        }
    }

    It 'ORs chips within a group and ANDs groups, also on array values and with Test chips' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Rows; Cols = $script:Cols } {
            param($Rows, $Cols)
            $ix = New-IgwtGridIndex -Rows $Rows -Columns $Cols
            $in = @{ Id = 'in'; Group = 'dir'; Field = 'Direction'; Values = @('Inbound') }
            $out = @{ Id = 'out'; Group = 'dir'; Field = 'Direction'; Values = @('Outbound') }
            $pub = @{ Id = 'pub'; Group = 'profile'; Field = 'Profiles'; Values = @('Public') }
            $high = @{ Id = 'high'; Group = 'port'; Test = { param($r) $r.Port -gt 1000 } }
            (Invoke-IgwtGridQuery -Index $ix -Chips @($in)).Count | Should -Be 3
            (Invoke-IgwtGridQuery -Index $ix -Chips @($in, $out)).Count | Should -Be 5
            (Invoke-IgwtGridQuery -Index $ix -Chips @($in, $pub)).Count | Should -Be 2
            (Invoke-IgwtGridQuery -Index $ix -Chips @($pub, $high)).Count | Should -Be 2
            $single = Invoke-IgwtGridQuery -Index $ix -Chips @($high) -Search 'steam'
            @($single).Count | Should -Be 1
            $ix.Rows[$single[0]].Name | Should -Be 'Steam'
        }
    }

    It 'applies per-column filters and never throws on rows with missing properties' {
        InModuleScope iGWindowsTuner -Parameters @{ Rows = $script:Rows; Cols = $script:Cols } {
            param($Rows, $Cols)
            $odd = @($Rows) + @([pscustomobject]@{ Name = 'Odd' }, @{ Name = 'Hash row'; Group = 'Games' }, $null)
            $ix = New-IgwtGridIndex -Rows $odd -Columns $Cols
            $ix.Count | Should -Be 7
            (Invoke-IgwtGridQuery -Index $ix -ColumnFilters @{ Group = @('Games') }).Count | Should -Be 4
            (Invoke-IgwtGridQuery -Index $ix -ColumnFilters @{ Group = @('Games', 'Chat'); Direction = @('Outbound') }).Count | Should -Be 2
            { Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Port' }, @{ Key = 'When' }, @{ Key = 'Missing' }) } | Should -Not -Throw
        }
    }

    It 'sorts and filters 5,000 rows within the 200 ms budget once indexed' {
        InModuleScope iGWindowsTuner {
            $rnd = New-Object Random 3
            $rows = for ($i = 0; $i -lt 5000; $i++) { [pscustomobject]@{ Name = "Rule $($rnd.Next(100000))"; Group = "G$($rnd.Next(40))"; Dir = @('Inbound', 'Outbound')[$rnd.Next(2)]; Port = $rnd.Next(65535) } }
            $ix = New-IgwtGridIndex -Rows $rows -Columns @(@{ Key = 'Name' }, @{ Key = 'Group' }, @{ Key = 'Dir' }, @{ Key = 'Port'; Kind = 'Number' })
            $null = Invoke-IgwtGridQuery -Index $ix -Sort @(@{ Key = 'Name' })   # first sort builds the rank cache
            $chip = @{ Id = 'in'; Group = 'd'; Field = 'Dir'; Values = @('Inbound') }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-IgwtGridQuery -Index $ix -Search 'rule 1' -Chips @($chip) -Sort @(@{ Key = 'Group' }, @{ Key = 'Name'; Descending = $true })
            $sw.Stop()
            @($r).Count | Should -BeGreaterThan 0
            $sw.ElapsedMilliseconds | Should -BeLessThan 200
        }
    }

    It 'merges changed rows by key, keeping order and appending new ones' {
        InModuleScope iGWindowsTuner {
            $old = @([pscustomobject]@{ Id = 'a'; V = 1 }, [pscustomobject]@{ Id = 'b'; V = 1 }, [pscustomobject]@{ Id = 'c'; V = 1 })
            $m = Merge-IgwtGridRows -Existing $old -Changed @([pscustomobject]@{ Id = 'b'; V = 2 }, [pscustomobject]@{ Id = 'd'; V = 9 }) -RowKey 'Id'
            @($m | ForEach-Object { "$($_.Id)$($_.V)" }) | Should -Be @('a1', 'b2', 'c1', 'd9')
        }
    }

    It 'formats the data age for the stale indicator' {
        InModuleScope iGWindowsTuner {
            $now = [datetime]'2026-10-23 12:00'
            Format-IgwtGridAge -Time $now.AddSeconds(-20) -Now $now | Should -Be 'Updated just now'
            Format-IgwtGridAge -Time $now.AddMinutes(-3) -Now $now | Should -Be 'Updated 3 min ago'
            Format-IgwtGridAge -Time $now.AddHours(-2) -Now $now | Should -Match '^Updated \d'
        }
    }
}

Describe 'SmartGrid control (WPF)' {
    It 'builds a grid, sorts with Shift for several levels, filters and restores a saved view' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $w = New-IgwtMainWindow
            $null = Set-IgwtGuiTheme -Target $w -Name Dark
            $script:Gui = @{ Window = $w; ViewState = @{}; NoStateSave = $true; ReadOnly = $true; IsAdmin = $false; DiagnosticsPath = $null }
            try {
                $chips = @(@{ Id = 'in'; Label = 'Inbound'; Group = 'dir'; Field = 'Dir'; Values = @('Inbound') })
                $actions = @(@{ Id = 'disable'; Label = 'Disable'; Bulk = $true; Changes = $true; Run = { param($rows) $null = $rows } })
                $g = New-IgwtSmartGrid -Id 'test.grid' -Columns @(@{ Key = 'Name'; Width = 200 }, @{ Key = 'Dir' }, @{ Key = 'Port'; Kind = 'Number' }) -Chips $chips -Actions $actions -RowKey 'Name' -Noun 'rules'
                $g.Root | Should -BeOfType System.Windows.Controls.DockPanel
                $g.C.Grid.Columns.Count | Should -Be 3
                $rows = @([pscustomobject]@{ Name = 'b'; Dir = 'Inbound'; Port = 2 }, [pscustomobject]@{ Name = 'a'; Dir = 'Outbound'; Port = 1 }, [pscustomobject]@{ Name = 'c'; Dir = 'Inbound'; Port = 1 })
                Set-IgwtGridRows -Grid $g -Rows $rows
                $g.C.CountText.Text | Should -Be '3 rules'
                Set-IgwtGridSort -Grid $g -Key 'Port' -NoSave
                Set-IgwtGridSort -Grid $g -Key 'Name' -Add -NoSave
                @($g.C.Grid.ItemsSource | ForEach-Object { $_.Name }) | Should -Be @('a', 'c', 'b')
                $g.DataColumns['Port'].SortDirection | Should -Be 'Ascending'
                $g.DataColumns['Name'].Header | Should -Be 'Name (2)'
                Set-IgwtGridSort -Grid $g -Key 'Port' -NoSave
                @($g.C.Grid.ItemsSource | ForEach-Object { $_.Name })[0] | Should -Be 'b'
                Set-IgwtGridChip -Grid $g -ChipId 'in'
                $g.C.CountText.Text | Should -Be '2 of 3 shown'
                $g.C.ClearButton.IsEnabled | Should -BeTrue
                $snap = Get-IgwtGridViewSnapshot -Grid $g
                Clear-IgwtGridFilters -Grid $g
                $g.C.CountText.Text | Should -Be '3 rules'
                Set-IgwtGridViewSnapshot -Grid $g -View ($snap | ConvertTo-Json -Depth 5 | ConvertFrom-Json)
                Update-IgwtGridView -Grid $g
                $g.C.CountText.Text | Should -Be '2 of 3 shown'
                $g.ChipButtons['in'].IsChecked | Should -BeTrue
                # A change action is blocked in read-only mode, with the reason.
                Get-IgwtGridActionBlock -Action $actions[0] -Rows $rows | Should -Match 'Read-only'
                # A page scope narrows the rows but does not count as a user filter.
                Clear-IgwtGridFilters -Grid $g
                $g.Scope = @{ Dir = @('Inbound') }
                Update-IgwtGridView -Grid $g
                $g.C.CountText.Text | Should -Be '2 rules'
                $g.C.ClearButton.IsEnabled | Should -BeFalse
                $g.Scope = @{}
                Set-IgwtGridRows -Grid $g -Rows @()
                $g.C.StatePanel.Visibility | Should -Be 'Visible'
                Set-IgwtGridState -Grid $g -State Error -Message 'boom'
                $g.C.StateText.Text | Should -Be 'boom'
            } finally { $script:Gui = $null; $script:IgwtGrids.Remove('test.grid') }
        }
    }

    It 'restores the scroll position from a dispatcher callback without throwing' {
        # A scrolled list that refreshed threw "cannot call a method on a null-valued expression":
        # the callback read a local variable of the function that queued it.
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $sv = New-Object System.Windows.Controls.ScrollViewer
            Restore-IgwtGridScroll -Viewer $sv -Offset 120
            # Run the queued callback now (an exception in it surfaces here).
            { [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action] { }, [System.Windows.Threading.DispatcherPriority]::ContextIdle) } | Should -Not -Throw
        }
    }

    It 'never lets a dispatcher callback read a local variable of the code that queued it' {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($f in Get-ChildItem (Join-Path $script:IgwtProjectRoot 'src\Gui') -Filter *.ps1) {
            $tk = $null; $er = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tk, [ref]$er)
            $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and [string]$n.Member.Value -eq 'BeginInvoke' }, $true)
            foreach ($call in $calls) {
                foreach ($sb in @($call.Arguments | Where-Object { $_ } | ForEach-Object { $_.FindAll({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true) })) {
                    $own = @{}
                    foreach ($p in @($sb.ScriptBlock.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true))) { $own[$p.Name.VariablePath.UserPath] = $true }
                    foreach ($a in @($sb.ScriptBlock.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) { $own[$a.Left.VariablePath.UserPath] = $true }
                    foreach ($v in @($sb.ScriptBlock.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
                        $name = $v.VariablePath.UserPath
                        if ($v.VariablePath.IsScript -or $v.VariablePath.IsGlobal -or $own.ContainsKey($name) -or $name -in 'null', 'true', 'false', '_', 'PSItem', 'args', 'this') { continue }
                        $found.Add("$($f.Name):$($v.Extent.StartLineNumber) `$$name")
                    }
                }
            }
        }
        $found | Should -BeNullOrEmpty -Because 'pass values to the callback as arguments or use $script: state'
    }

    It 'keeps the selected row of a single-select grid when its rows reload' {
        # Single-select grids (tweaks, Defender, power plan) used SelectedItems.Add, which throws.
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $w = New-IgwtMainWindow
            $null = Set-IgwtGuiTheme -Target $w -Name Dark
            $script:Gui = @{ Window = $w; ViewState = @{}; NoStateSave = $true; ReadOnly = $true; IsAdmin = $false; DiagnosticsPath = $null }
            try {
                $g = New-IgwtSmartGrid -Id 'test.single' -Columns @(@{ Key = 'Name' }) -RowKey 'Name' -SelectionMode Single
                Set-IgwtGridRows -Grid $g -Rows @([pscustomobject]@{ Name = 'a' }, [pscustomobject]@{ Name = 'b' })
                $g.C.Grid.SelectedIndex = 1
                { Set-IgwtGridRows -Grid $g -Rows @([pscustomobject]@{ Name = 'a' }, [pscustomobject]@{ Name = 'b' }, [pscustomobject]@{ Name = 'c' }) } | Should -Not -Throw
                $g.C.Grid.SelectedItem.Name | Should -Be 'b'
            } finally { $script:Gui = $null; $script:IgwtGrids.Remove('test.single') }
        }
    }
}
