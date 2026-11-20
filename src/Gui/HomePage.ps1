# HomePage.ps1
# 4.0 section 3 (D2): Home, as in Phase 3 mockup 1. A greeting with the PC line and status pills, the one
# next step (the home card engine, Select-IgwtHomeCard), three status tiles, Recent changes with Undo next
# to "Before you play". Built from the 4.0 components (Components.ps1) on every visit and refresh; the
# data comes from the window's last read (Get-IgwtGuiData) and changes nothing.

function Get-IgwtGuiGreeting {
    <# .SYNOPSIS "Good morning", "Good afternoon" or "Good evening" for an hour of the day. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$Hour = (Get-Date).Hour)
    if ($Hour -lt 5) { return 'Good evening' }
    if ($Hour -lt 12) { return 'Good morning' }
    if ($Hour -lt 18) { return 'Good afternoon' }
    return 'Good evening'
}

function Get-IgwtGuiHomeFigures {
    <#
    .SYNOPSIS
        The numbers behind the Home tiles, from the window's data: Optimize settings in place (of those
        the persona shows and iG can read), the security score, and the changes that can be undone.
        Pure over its inputs.
    #>
    [CmdletBinding()]
    param($Data, [object[]]$Catalog = @(), $Persona, [string[]]$Categories = @())
    $inPlace = 0; $total = 0
    if ($Data -and $Data.States) {
        foreach ($t in @($Catalog | Where-Object { $Categories -contains [string]$_.category })) {
            if ($Persona -and -not (Test-IgwtItemVisible -Tweak $t -Persona $Persona)) { continue }
            $st = $Data.States[[string]$t.id]
            if (-not $st -or [string]$st.State -notin 'On', 'Off', 'Partial') { continue }
            $total++
            if ([string]$st.State -eq 'On') { $inPlace++ }
        }
    }
    $sec = $null
    if ($Data -and $Data.Health -and $Data.Health.PSObject.Properties['Security']) { $sec = $Data.Health.Security }
    $changes = @($(if ($Data) { $Data.Snapshots }) | Where-Object { $_ -and (Test-IgwtSnapshotHasChange -Snapshot $_) }).Count
    [pscustomobject]@{
        InPlace = $inPlace; Total = $total
        Score = $(if ($sec) { [int]$sec.Score } else { $null }); Grade = $(if ($sec) { [string]$sec.Grade } else { '' }); ToFix = $(if ($sec) { @($sec.ToFix).Count } else { 0 })
        Changes = $changes
        Pending = $(if ($Data -and $Data.Pending) { [string]$Data.Pending.Requires } else { '' })
        AntiCheat = $(if ($Data -and $Data.AntiCheat) { [string]$Data.AntiCheat.Overall } else { '' })
    }
}

function Update-IgwtGuiHomePage {
    <# .SYNOPSIS Builds Home from the window's last data read. Display only. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window content only; every change runs after its own preview and confirmation.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $h = $c.HomeHost
    if (-not $h) { return }
    $h.Children.Clear()
    $data = $script:Gui.Data
    $optimize = @(@($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Optimize' })[0].Pages)
    $f = Get-IgwtGuiHomeFigures -Data $data -Catalog @($script:Gui.Catalog) -Persona $script:Gui.Persona -Categories $optimize

    # 1. Greeting, PC line and pills.
    $pc = ''
    if ($data -and $data.Preflight -and $data.Preflight.Os) { $os = $data.Preflight.Os; $pc = "$(([string]$os.Caption) -replace '^Microsoft ', '') $($os.DisplayVersion), build $($os.FullBuild)" }
    $pills = New-Object System.Windows.Controls.StackPanel; $pills.Orientation = 'Horizontal'
    $acWord = switch ($f.AntiCheat) { 'Green' { @('Anti-cheat ready', 'Success') } 'Amber' { @('Anti-cheat partly ready', 'Warning') } '' { @('Anti-cheat not read yet', 'Neutral') } default { @('Anti-cheat needs a setting', 'Danger') } }
    $null = $pills.Children.Add((New-IgwtPill -Text $acWord[0] -Tone $acWord[1]))
    $null = $pills.Children.Add((New-IgwtPill -Text $(if ($script:Gui.IsAdmin) { 'Administrator' } else { 'Read-only' }) -Tone $(if ($script:Gui.IsAdmin) { 'Success' } else { 'Info' })))
    $null = $h.Children.Add((New-IgwtPageHeader -Title (Get-IgwtGuiGreeting) -Subtitle $(if ($pc) { $pc } else { 'Reading this PC (read-only)...' }) -Right $pills))

    # 2. The one next step (home card engine).
    $card = $script:Gui.HomeCardShown
    if ($card) {
        $label = switch ([string]$card.Kind) { 'journal' { 'Needs attention' } 'incomplete' { 'Needs attention' } 'drift' { 'Settings changed back' } 'forensic' { 'Forensic logging' } 'unverified' { 'Check this' } 'suggestion' { 'Suggestion' } default { 'All clear' } }
        $isClear = ([string]$card.Kind -eq 'clear')
        $ns = New-IgwtNextStepCard -Title ([string]$card.Title) -Text ([string]$card.Text) -Label $label -PrimaryText $(if ($card.Action) { 'Do it' }) -SecondaryText $(if (-not $isClear) { 'Not now' }) -Glyph $(if ($isClear) { [string][char]0xE73E } else { [string][char]0xE7C1 })
        $ns.Margin = [System.Windows.Thickness]::new(0, 0, 0, 20)
        foreach ($b in @(Get-IgwtUiDescendant -Root $ns | Where-Object { $_ -is [System.Windows.Controls.Button] })) {
            if ([string]$b.Content -eq 'Do it') {
                $b.IsEnabled = -not ($card.Action -in 'recover', 'drift' -and -not $script:Gui.IsAdmin)
                Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { Invoke-IgwtGuiHomeAction }
            } else { Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { Set-IgwtGuiHomeSnooze -Days 1; Update-IgwtGuiHomePage } }
        }
        $null = $h.Children.Add($ns)
    }

    # 3. Three status tiles.
    $tiles = New-Object System.Windows.Controls.Primitives.UniformGrid; $tiles.Columns = 3; $tiles.Margin = [System.Windows.Thickness]::new(0, 0, -16, 20)
    $t1 = New-IgwtStatusTile -Label 'Performance' -Value $(if ($f.Total) { "$($f.InPlace) of $($f.Total)" } else { '-' }) -Line 'Optimize settings in place' -LinkText 'Open Optimize'
    $t2 = New-IgwtStatusTile -Label 'Security' -Value $(if ($null -ne $f.Score) { "$($f.Score)" } else { '-' }) -Line $(if ($null -ne $f.Score) { "out of 100. $(if ($f.ToFix) { "$($f.ToFix) to fix" } else { 'Nothing to fix' })" } else { 'Refresh to read the score' }) -LinkText 'What raises it'
    $t3 = New-IgwtStatusTile -Label 'Changes' -Value $(if ($f.Pending -eq 'reboot') { 'Restart' } elseif ($f.Pending) { 'Sign out' } else { "$($f.Changes)" }) -Line $(if ($f.Pending) { 'needed to finish your changes' } elseif ($f.Changes) { 'recent changes, each can be undone' } else { 'No changes yet' }) -LinkText 'Open History'
    $targets = @{ 'Open Optimize' = 'Power & CPU'; 'What raises it' = 'Security'; 'Open History' = 'Backups' }
    foreach ($t in $t1, $t2, $t3) {
        $t.Margin = [System.Windows.Thickness]::new(0, 0, 16, 0)
        foreach ($b in @(Get-IgwtUiDescendant -Root $t | Where-Object { $_ -is [System.Windows.Controls.Button] })) { $b.Tag = $targets[[string]$b.Content]; Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { param($s, $e) Open-IgwtGuiPage -Page ([string]$s.Tag) } }
        $null = $tiles.Children.Add($t)
    }
    $null = $h.Children.Add($tiles)

    # 4. Recent changes (2/3) next to Before you play (1/3).
    $row = New-Object System.Windows.Controls.Grid
    foreach ($w in '2*', '1*') { $cd = New-Object System.Windows.Controls.ColumnDefinition; $cd.Width = (New-Object System.Windows.GridLengthConverter).ConvertFromString($w); $row.ColumnDefinitions.Add($cd) }
    $recent = New-Object System.Windows.Controls.Border; $recent.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Card4'); $recent.Margin = [System.Windows.Thickness]::new(0, 0, 16, 0)
    $rs = New-Object System.Windows.Controls.StackPanel
    $null = $rs.Children.Add((New-IgwtUiText -Text 'Recent changes' -Style 'TextSubtitle'))
    $items = @($c.DashRecentList.ItemsSource | Where-Object { $_ })
    if (-not $items.Count) { $null = $rs.Children.Add((New-IgwtEmptyState -Text 'No changes yet. Every change you make appears here with Undo.')) }
    foreach ($it in $items) {
        $dp = New-Object System.Windows.Controls.DockPanel; $dp.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
        $u = New-IgwtUiButton -Text 'Undo' -Kind Secondary -ObjectName ([string]$it.Title)
        $u.Tag = [string]$it.Path; $u.IsEnabled = [bool]$it.CanUndo; $u.ToolTip = [string]$it.UndoTip; $u.VerticalAlignment = 'Center'
        Register-IgwtGuiHandler -Control $u -Event 'Click' -Handler { param($s, $e) Invoke-IgwtGuiRevert -SnapshotPath ([string]$s.Tag) }
        [System.Windows.Controls.DockPanel]::SetDock($u, 'Right'); $null = $dp.Children.Add($u)
        $tx = New-Object System.Windows.Controls.StackPanel
        $null = $tx.Children.Add((New-IgwtUiText -Text ([string]$it.Title) -Style 'TextBodyStrong'))
        $null = $tx.Children.Add((New-IgwtUiText -Text ([string]$it.When) -Style 'TextCaption' -Brush 'BrushTextMuted'))
        $null = $dp.Children.Add($tx)
        $null = $rs.Children.Add($dp)
    }
    $recent.Child = $rs
    $null = $row.Children.Add($recent)
    $play = New-Object System.Windows.Controls.Border; $play.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Card4')
    [System.Windows.Controls.Grid]::SetColumn($play, 1)
    $ps = New-Object System.Windows.Controls.StackPanel
    $null = $ps.Children.Add((New-IgwtUiText -Text 'Before you play' -Style 'TextSubtitle'))
    $acLine = New-IgwtPill -Text $acWord[0] -Tone $acWord[1]; $acLine.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0); $null = $ps.Children.Add($acLine)
    if ($f.Pending) { $pend = New-IgwtPill -Text $(if ($f.Pending -eq 'reboot') { 'Restart to finish changes' } else { 'Sign out to finish changes' }) -Tone Warning; $pend.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0); $null = $ps.Children.Add($pend) }
    $hint = New-IgwtUiText -Text 'Session Mode turns off background apps and notifications while you play, and puts them back after.' -Style 'TextBody' -Brush 'BrushTextMuted'; $hint.Margin = [System.Windows.Thickness]::new(0, 12, 0, 8); $null = $ps.Children.Add($hint)
    foreach ($a in @(@('Open Play', 'Presets', 'Primary'), @('Test the network', 'NetTest', 'Subtle'))) {
        $b = New-IgwtUiButton -Text $a[0] -Kind $a[2]; $b.Tag = $a[1]; $b.HorizontalAlignment = 'Left'; $b.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { param($s, $e) Open-IgwtGuiPage -Page ([string]$s.Tag) }
        $null = $ps.Children.Add($b)
    }
    $play.Child = $ps
    $null = $row.Children.Add($play)
    $null = $h.Children.Add($row)
}

function Get-IgwtUiDescendant {
    <# .SYNOPSIS Every element in the logical tree under -Root (breadth first). Pure. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Root)
    $q = New-Object System.Collections.Generic.Queue[object]; $q.Enqueue($Root)
    while ($q.Count) {
        $n = $q.Dequeue(); $n
        foreach ($ch in [System.Windows.LogicalTreeHelper]::GetChildren($n)) { if ($ch -is [System.Windows.DependencyObject]) { $q.Enqueue($ch) } }
    }
}
