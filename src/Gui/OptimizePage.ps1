# OptimizePage.ps1
# 4.0 section 3 (D3): Optimize, as in Phase 3 mockup 2. One page for the five Optimize categories:
# header with search, category chips, the settings as SettingRows (name, plain hint, evidence, switch
# with an On/Off word) next to a DetailsPanel that becomes a bottom sheet under 1100 px. A switch only
# stages (Invoke-IgwtGuiStageToggle, the same path as the table, with the Expert and Risk Zone
# dialogs); the ChangeBar applies. The table view (filters, columns, sorting) stays one click away.

function Get-IgwtGuiEvidenceWords {
    <# .SYNOPSIS Plain evidence words for a catalog item (Phase 3 writing rules). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Tweak)
    switch ([string]$Tweak.evidence.tier) { 'A' { return 'Documented by Microsoft' } 'B' { return 'Measure it' } 'R' { return 'Risk Zone: rejected tweak' } default { return 'Not documented' } }
}

function Get-IgwtGuiUndoWords {
    <# .SYNOPSIS "Undo: exact", "Undo: partial" or "Cannot be undone", with the tone of its pill. Pure. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak)
    switch ([string]$Tweak.reversible) { 'full' { return @('Undo: exact', 'Success') } 'partial' { return @('Undo: partial', 'Warning') } default { return @('Cannot be undone', 'Danger') } }
}

function Initialize-IgwtGuiOptimizePage {
    <# .SYNOPSIS Builds the page once: header with search and Table view, category chips, list and details. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window content only.')]
    [CmdletBinding()]
    param()
    if ($script:Gui.Opt) { return }
    $cats = @(@($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Optimize' })[0].Pages)
    $root = New-Object System.Windows.Controls.DockPanel
    $right = New-Object System.Windows.Controls.StackPanel; $right.Orientation = 'Horizontal'
    $search = New-Object System.Windows.Controls.TextBox
    $search.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'SearchBox')
    $search.Tag = 'Search settings'; $search.Width = 260; $search.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0); $search.VerticalAlignment = 'Center'
    [System.Windows.Automation.AutomationProperties]::SetName($search, 'Search settings')
    $search.ToolTip = 'Search names and descriptions in every Optimize category.'
    $table = New-IgwtUiButton -Text 'Table view' -Kind Subtle -ObjectName '(filters, columns and sorting)'
    $table.ToolTip = 'The full table with filters, columns and sorting.'
    $null = $right.Children.Add($search); $null = $right.Children.Add($table)
    $header = New-IgwtPageHeader -Title 'Optimize' -Subtitle 'Settings that change how Windows runs games. A switch stages a change; Apply in the bar below makes it, and every change can be undone.' -Right $right
    [System.Windows.Controls.DockPanel]::SetDock($header, 'Top'); $null = $root.Children.Add($header)
    $chips = New-IgwtChipGroup -Labels $cats -GroupName 'Category' -Single
    $chips.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    [System.Windows.Controls.DockPanel]::SetDock($chips, 'Top'); $null = $root.Children.Add($chips)
    $list = New-Object System.Windows.Controls.StackPanel
    [System.Windows.Automation.AutomationProperties]::SetName($list, 'Settings')
    $scroll = New-Object System.Windows.Controls.ScrollViewer; $scroll.VerticalScrollBarVisibility = 'Auto'; $scroll.HorizontalScrollBarVisibility = 'Disabled'; $scroll.Content = $list
    $details = New-Object System.Windows.Controls.StackPanel
    # The content area is about 860 px wide at the 1100 px minimum window: details move below only under 760 px.
    $split = New-IgwtSplitView -Main $scroll -Details $details -Breakpoint 760
    $null = $root.Children.Add($split)
    $script:Gui.C.PageOptimize.Child = $root
    $script:Gui.Opt = @{ Search = $search; Chips = $chips; List = $list; Scroll = $scroll; Details = $details; Split = $split; Selected = '' }
    Register-IgwtGuiHandler -Control $search -Event 'TextChanged' -Handler { Update-IgwtGuiOptimizeList }
    Register-IgwtGuiHandler -Control $table -Event 'Click' -Handler { $script:Gui.OptimizeTable = $true; Open-IgwtGuiPage -Page ([string]$script:Gui.Category) }
    foreach ($ch in $chips.Children) { Register-IgwtGuiHandler -Control $ch -Event 'Click' -Handler { param($s, $e) $s.IsChecked = $true; Open-IgwtGuiPage -Page ([string]$s.Tag) } }
}

function Show-IgwtGuiOptimizePage {
    <# .SYNOPSIS Shows Optimize on a category. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Category)
    $w = [System.Diagnostics.Stopwatch]::StartNew()
    Initialize-IgwtGuiOptimizePage
    $init = $w.Elapsed.TotalMilliseconds
    foreach ($ch in $script:Gui.Opt.Chips.Children) { $ch.IsChecked = ([string]$ch.Tag -eq $Category) }
    Update-IgwtGuiOptimizeList
    if ($script:Gui.DiagnosticsPath) { Write-IgwtGuiDiagnostic -Kind 'draw' -Text ('Optimize	{0:N0} ms	setup {1:N0} ms' -f $w.Elapsed.TotalMilliseconds, $init) }
}

function Get-IgwtGuiOptimizeItems {
    <#
    .SYNOPSIS
        The rows Optimize lists: the category's items the window shows (Test-IgwtGuiTweakShown), or
        with a search every Optimize category's matching items, in catalog order.
    #>
    [CmdletBinding()]
    param([string]$Category, [string]$Search = '')
    if (-not $script:Gui.Data) { return }
    $cats = @(@($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Optimize' })[0].Pages)
    $q = $Search.Trim()
    foreach ($t in @($script:Gui.Catalog)) {
        if ($cats -notcontains [string]$t.category) { continue }
        if (-not $q -and [string]$t.category -ne $Category) { continue }
        if ($q -and -not ("$($t.name) $($t.hint) $($t.description) $($t.id)" -like "*$q*")) { continue }
        $st = $script:Gui.Data.States[[string]$t.id]
        if (-not (Test-IgwtGuiTweakShown -Tweak $t -State $st)) { continue }
        [pscustomobject]@{ Tweak = $t; Row = (New-IgwtGuiTweakRow -Tweak $t -State $st -Changed ([bool]$script:Gui.Data.Changed[$t.id]) -Staged ([string]$script:Gui.Staged[$t.id]) -IsAdmin $script:Gui.IsAdmin) }
    }
}

function Update-IgwtGuiOptimizeList {
    <# .SYNOPSIS Rebuilds the setting rows (keeps the scroll position and the selected item). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window content only; a switch only stages.')]
    [CmdletBinding()]
    param()
    $o = $script:Gui.Opt
    if (-not $o) { return }
    # Same category, search, settings, staging and persona as the list on screen: keep it (a rebuild cost 100-230 ms
    # on every visit, 4.0 section 8). A row selection never needs a rebuild (Select-IgwtGuiOptimizeItem).
    $st = $(if ($script:Gui.Data -and $script:Gui.Data.States) { $script:Gui.Data.States } else { @{} })
    $key = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f [string]$script:Gui.Category, [string]$o.Search.Text, $(if ($script:Gui.Data) { [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($script:Gui.Data) } else { 0 }), (Get-IgwtGuiStagedKey), $(if ($script:Gui.Persona) { [string]$script:Gui.Persona.Name }), [bool]$script:Gui.FocusMode, [bool]$script:Gui.IsAdmin, (@($st.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $st[$_].State }) -join '|')
    if ($o.ListKey -eq $key -and $o.List.Children.Count) { return }
    $o.ListKey = $key
    $offset = $o.Scroll.VerticalOffset
    $o.List.Children.Clear()
    if (-not $script:Gui.Data) { $null = $o.List.Children.Add((New-IgwtEmptyState -Text 'Reading the current settings (read-only)...')); Show-IgwtGuiOptimizeDetails -Id ''; return }
    $items = @(Get-IgwtGuiOptimizeItems -Category ([string]$script:Gui.Category) -Search ([string]$o.Search.Text))
    if (-not $items.Count) { $null = $o.List.Children.Add((New-IgwtEmptyState -Text $(if ($o.Search.Text) { 'No setting matches the search.' } else { 'Nothing to show in this category for your persona.' }))) }
    # In the shown window the first rows are drawn now and the rest in the next dispatcher slice, so a first visit
    # never blocks the window for the whole list (4.0 section 8); offscreen renders build everything at once.
    $o.Gen = [int]$o.Gen + 1
    $now = $items
    if ($items.Count -gt 5 -and $script:Gui.Window -and $script:Gui.Window.IsLoaded) {
        $now = @($items | Select-Object -First 5)
        $o.Rest = @($items | Select-Object -Skip 5); $o.RestGen = $o.Gen; $o.RestOffset = $offset
        $null = $script:Gui.Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [Action] { Add-IgwtGuiOptimizeRest })
    }
    foreach ($it in $now) { Add-IgwtGuiOptimizeRow -Item $it }
    if (-not $o.Selected -or -not @($items | Where-Object { [string]$_.Tweak.id -eq $o.Selected }).Count) { $o.Selected = $(if ($items.Count) { [string]$items[0].Tweak.id } else { '' }) }
    Show-IgwtGuiOptimizeDetails -Id $o.Selected
    $o.Scroll.ScrollToVerticalOffset($offset)
}

function Add-IgwtGuiOptimizeRest {
    <# .SYNOPSIS Adds the rows held back by Update-IgwtGuiOptimizeList, unless the list was rebuilt since. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $o = $script:Gui.Opt
    if (-not $o -or [int]$o.RestGen -ne [int]$o.Gen -or -not $o.Rest) { return }
    $rest = @($o.Rest); $o.Rest = $null
    foreach ($it in $rest) { Add-IgwtGuiOptimizeRow -Item $it }
    $o.Scroll.ScrollToVerticalOffset([double]$o.RestOffset)
}

function Add-IgwtGuiOptimizeRow {
    <# .SYNOPSIS One setting row of Optimize: name, hint, evidence line and switch; a click selects, the switch stages. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only; a switch only stages.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Item)
    $o = $script:Gui.Opt
    $it = $Item
    $r = $it.Row; $t = $it.Tweak
    $evidence = (Get-IgwtGuiEvidenceWords -Tweak $t) + "  |  $($r.AcText)"
    if ($r.PendingText) { $evidence += "  |  $($r.PendingText)" }
    if ($r.RestartText) { $evidence += "  |  $($r.RestartText) needed" }
    $row = New-IgwtSettingRow -Name ([string]$r.Name) -Hint ([string]$r.Hint) -Evidence $evidence -IsOn ([bool]$r.Desired) -Disabled:(-not $r.CanToggle) -DisabledReason $(if (-not $r.CanToggle) { [string]$r.ToggleTip })
    $row.Tag.Tag.Tag = [string]$r.Id
    $row.Tag.ToolTip = [string]$r.ToggleTip
    $row.Resources['IgwtId'] = [string]$r.Id
    if ([string]$r.Id -eq $o.Selected) { $row.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'BrushSurfaceSelected') }
    Register-IgwtGuiHandler -Control $row -Event 'PreviewMouseLeftButtonDown' -Handler { param($s, $e) Select-IgwtGuiOptimizeItem -Id ([string]$s.Resources['IgwtId']) }
    Register-IgwtGuiHandler -Control $row -Event 'GotKeyboardFocus' -Handler { param($s, $e) if ([object]::ReferenceEquals($e.NewFocus, $s)) { Select-IgwtGuiOptimizeItem -Id ([string]$s.Resources['IgwtId']) } }
    Register-IgwtGuiHandler -Control $row.Tag -Event 'Click' -Handler {
        param($s, $e)
        $id = [string]$s.Tag.Tag
        $ok = Invoke-IgwtGuiStageToggle -Id $id -Want ([bool]$s.IsChecked)
        if (-not $ok) { $s.IsChecked = -not [bool]$s.IsChecked }
        Update-IgwtGuiTweakList
    }
    $null = $o.List.Children.Add($row)
}

function Select-IgwtGuiOptimizeItem {
    <# .SYNOPSIS Marks a row as selected (fill plus details), without rebuilding the list. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $o = $script:Gui.Opt
    if (-not $o -or $o.Selected -eq $Id) { return }
    $o.Selected = $Id
    foreach ($row in $o.List.Children) {
        if ($row -isnot [System.Windows.Controls.Border]) { continue }
        if ([string]$row.Resources['IgwtId'] -eq $Id) { $row.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'BrushSurfaceSelected') }
        else { $row.ClearValue([System.Windows.Controls.Border]::BackgroundProperty) }
    }
    Show-IgwtGuiOptimizeDetails -Id $Id
}

function Show-IgwtGuiOptimizeDetails {
    <#
    .SYNOPSIS
        The details panel: name, pills (evidence, anti-cheat, undo, restart), description, warning,
        what changes (current -> target), how to undo and the sources.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window content only.')]
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Id)
    $d = $script:Gui.Opt.Details
    $d.Children.Clear()
    if (-not $Id) { $null = $d.Children.Add((New-IgwtUiText -Text 'Select a setting to see what it changes.' -Style 'TextBody' -Brush 'BrushTextMuted')); return }
    $t = @($script:Gui.Catalog | Where-Object { [string]$_.id -eq $Id })[0]
    if (-not $t) { return }
    $st = $(if ($script:Gui.Data) { $script:Gui.Data.States[$Id] })
    $null = $d.Children.Add((New-IgwtUiText -Text ([string]$t.name) -Style 'TextSubtitle'))
    $pills = New-Object System.Windows.Controls.WrapPanel; $pills.Margin = [System.Windows.Thickness]::new(0, 8, 0, 8)
    $null = $pills.Children.Add((New-IgwtPill -Text (Get-IgwtGuiEvidenceWords -Tweak $t) -Tone $(switch ([string]$t.evidence.tier) { 'A' { 'Info' } 'R' { 'Danger' } default { 'Neutral' } })))
    $null = $pills.Children.Add((New-IgwtPill -Text $(if ($t.antiCheatSafe) { 'Anti-cheat safe' } else { 'Check anti-cheat' }) -Tone $(if ($t.antiCheatSafe) { 'Success' } else { 'Warning' })))
    $u = Get-IgwtGuiUndoWords -Tweak $t
    $null = $pills.Children.Add((New-IgwtPill -Text $u[0] -Tone $u[1]))
    if ($t.requires -in 'reboot', 'logoff') { $null = $pills.Children.Add((New-IgwtPill -Text $(if ($t.requires -eq 'reboot') { 'Restart needed' } else { 'Sign-out needed' }) -Tone Warning)) }
    foreach ($p in $pills.Children) { $p.Margin = [System.Windows.Thickness]::new(0, 0, 6, 6) }
    $null = $d.Children.Add($pills)
    if ([string]$t.evidence.tier -eq 'R') { $null = $d.Children.Add((New-IgwtInfoBar -Title 'Risk Zone' -Message (Get-IgwtRiskZoneSummary -Tweak $t) -Tone Danger)) }
    elseif ($t.warning) { $null = $d.Children.Add((New-IgwtInfoBar -Title 'Before you turn this on' -Message ([string]$t.warning) -Tone Warning)) }
    $null = $d.Children.Add((New-IgwtUiText -Text ([string]$t.description) -Style 'TextBody'))
    if ($st -and $st.Reason) { $why = New-IgwtUiText -Text "Now: $([string]$st.Reason)" -Style 'TextBody' -Brush 'BrushTextMuted'; $why.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0); $null = $d.Children.Add($why) }
    $items = @($(if ($st) { $st.Items }) | Where-Object { $_ })
    if ($items.Count) {
        $h = New-IgwtUiText -Text 'What changes' -Style 'TextBodyStrong'; $h.Margin = [System.Windows.Thickness]::new(0, 14, 0, 4); $null = $d.Children.Add($h)
        foreach ($i in $items) {
            $null = $d.Children.Add((New-IgwtUiText -Text (Format-IgwtGuiChangeTarget -Target ([string]$i.Target)) -Style 'TextValue'))
            if ([string]$i.Current -or [string]$i.Desired) { $v = New-IgwtUiText -Text ("{0} -> {1}" -f [string]$i.Current, [string]$i.Desired) -Style 'TextValue' -Brush 'BrushAccent'; $v.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6); $null = $d.Children.Add($v) }
        }
    }
    $h2 = New-IgwtUiText -Text 'How to undo' -Style 'TextBodyStrong'; $h2.Margin = [System.Windows.Thickness]::new(0, 10, 0, 4); $null = $d.Children.Add($h2)
    $null = $d.Children.Add((New-IgwtUiText -Text (Get-IgwtTweakRevertDescription -Tweak $t) -Style 'TextBody' -Brush 'BrushTextMuted'))
    $src = @($t.evidence.sources | Where-Object { $_ })
    if ($src.Count) {
        $h3 = New-IgwtUiText -Text 'Sources' -Style 'TextBodyStrong'; $h3.Margin = [System.Windows.Thickness]::new(0, 10, 0, 4); $null = $d.Children.Add($h3)
        foreach ($s in $src) { $null = $d.Children.Add((New-IgwtUiText -Text ([string]$s) -Style 'TextValue' -Brush 'BrushLink')) }
    }
}
