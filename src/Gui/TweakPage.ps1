# TweakPage.ps1
# The tweak category pages (Power & CPU, Graphics, Network, Security, Risk Zone ...): one SmartGrid
# with every tweak the persona shows, filtered to the page's category (a search covers every
# category), with a switch per row that stages a change (nothing changes until Apply), sortable
# columns for state, group, tier, risk, level and anti-cheat, and chips instead of check boxes.

function Initialize-IgwtGuiTweakGrid {
    <# .SYNOPSIS Builds the tweak grid (called once at start). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $g = New-IgwtSmartGrid -Id 'tweaks' -Noun 'tweaks' -RowKey 'Key' -SearchPlaceholder 'Search all tweaks (names, hints, ids)' -SelectionMode Single `
        -EmptyTitle 'No tweaks on this page' -EmptyText 'Your persona hides the advanced items here; switch persona in the header to see them.' `
        -Columns @(
        @{ Key = 'On'; Header = 'On'; Width = 64; MinWidth = 56; Template = 'Toggle'; Search = $false }
        @{ Key = 'Name'; Header = 'Tweak'; MinWidth = 220; Tip = 'Hint' }
        @{ Key = 'StateCol'; Header = 'Current'; Width = 130; Template = 'Status'; SortKey = 'State' }
        @{ Key = 'PendingCol'; Header = 'Pending'; Width = 100; Template = 'Status' }
        @{ Key = 'Group'; Header = 'Group'; Width = 150 }
        @{ Key = 'TierText'; Header = 'Evidence'; Width = 90 }
        @{ Key = 'RiskCol'; Header = 'Risk'; Width = 90; Template = 'Status'; Kind = 'Number'; SortKey = 'RiskRank' }
        @{ Key = 'LevelText'; Header = 'Level'; Width = 100; Kind = 'Number'; SortKey = 'LevelRank' }
        @{ Key = 'AcCol'; Header = 'Anti-cheat'; Width = 150; Template = 'Status'; Visible = $false }
        @{ Key = 'RestartText'; Header = 'Restart'; Width = 90 }
        @{ Key = 'Id'; Header = 'Id'; Width = 200; Visible = $false; Template = 'Mono' }
        @{ Key = 'Category'; Header = 'Category'; Width = 150; Visible = $false }
    ) -Chips @(
        @{ Id = 'off'; Label = 'Off'; Group = 'state'; Field = 'State'; Values = @('Off', 'Partial'); Tip = 'Tweaks that are off or partly on: the ones you can still turn on' }
        @{ Id = 'on'; Label = 'On'; Group = 'state'; Field = 'State'; Values = @('On') }
        @{ Id = 'pending'; Label = 'Pending'; Group = 'pending'; Field = 'StagedKey'; Values = @('Yes'); Tip = 'Changes waiting for Apply' }
        @{ Id = 'changed'; Label = 'Changed from default'; Group = 'changed'; Field = 'ChangedText'; Values = @('Changed'); Tip = 'Current values differ from the Windows default' }
        @{ Id = 'tier-a'; Label = 'Tier A'; Group = 'tier'; Field = 'Tier'; Values = @('A'); Tip = 'Documented by Microsoft or the vendor' }
        @{ Id = 'tier-b'; Label = 'Tier B'; Group = 'tier'; Field = 'Tier'; Values = @('B'); Tip = 'Situational: measure before and after' }
        @{ Id = 'risk-low'; Label = 'Low risk'; Group = 'risk'; Field = 'Risk'; Values = @('low'); More = $true }
        @{ Id = 'risk-medium'; Label = 'Medium risk'; Group = 'risk'; Field = 'Risk'; Values = @('medium'); More = $true }
        @{ Id = 'risk-high'; Label = 'High risk'; Group = 'risk'; Field = 'Risk'; Values = @('high'); More = $true }
        @{ Id = 'restart'; Label = 'Needs restart'; Group = 'restart'; Field = 'RestartKey'; Values = @('Yes'); More = $true }
        @{ Id = 'acsafe'; Label = 'Anti-cheat safe'; Group = 'ac'; Field = 'AcText'; Values = @('Anti-cheat safe'); More = $true }
        @{ Id = 'lvl-standard'; Label = 'Standard'; Group = 'level'; Field = 'Level'; Values = @('Standard', ''); More = $true }
        @{ Id = 'lvl-advanced'; Label = 'Advanced'; Group = 'level'; Field = 'Level'; Values = @('Advanced'); More = $true }
        @{ Id = 'lvl-expert'; Label = 'Expert and Lab'; Group = 'level'; Field = 'Level'; Values = @('Expert', 'Lab'); More = $true }
    ) -OnSelectionChanged { param($grid, $sel) $null = $grid, $sel; Update-IgwtGuiDetails } -OnBeforeQuery { param($grid) Update-IgwtGuiTweakScope -Grid $grid } -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiRefresh }
    # Grouped by default: group, then name.
    if (-not @($g.Sort).Count) { Set-IgwtGridSort -Grid $g -Key 'Group' -NoSave; Set-IgwtGridSort -Grid $g -Key 'Name' -Add -NoSave }
    $script:Gui.Grids.Tweaks = $g
    $c.TweakGridHost.Content = $g.Root
    # A switch in a row stages a change (the details pane shows what it changes).
    Register-IgwtGuiHandler -Control $g.Root -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
        param($s, $e)
        $null = $s
        $src = $e.OriginalSource
        if ($src -is [System.Windows.Controls.CheckBox] -and $src.Tag) { Invoke-IgwtGuiToggle -CheckBox $src }
    }
}

function Set-IgwtGuiTweakPageChips {
    <# .SYNOPSIS Hides chips that mean nothing on the current page (tiers on the Risk Zone page, where every item is tier R). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param()
    $g = $script:Gui.Grids.Tweaks
    if (-not $g) { return }
    $risk = ([string]$script:Gui.Category -eq 'Risk Zone')
    foreach ($id in 'tier-a', 'tier-b') {
        $b = $g.ChipButtons[$id]
        if (-not $b) { continue }
        $b.Visibility = $(if ($risk) { 'Collapsed' } else { 'Visible' })
        if ($risk -and $g.ActiveChips.Contains($id)) { $null = $g.ActiveChips.Remove($id); $b.IsChecked = $false }
    }
}
