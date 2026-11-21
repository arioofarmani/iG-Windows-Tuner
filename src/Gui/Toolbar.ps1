# Toolbar.ps1
# 4.0 section 5b (D6): at most six buttons in a page toolbar or a details pane. Less frequent actions
# move into one "More" button: each moved button is hidden and stays the source of truth (its Click
# handler, IsEnabled and ToolTip); the menu reads them when it opens and raises the button's Click,
# so no handler is duplicated. Handlers use Tags, never closures (DECISIONS U9).

function Set-IgwtGuiToolbarOverflow {
    <#
    .SYNOPSIS
        Moves -Buttons into a "More" menu button placed after the last visible button of their panel.
        Returns the More button. Idempotent per panel (a second call adds to the same menu).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Buttons, [string]$Label = 'More', [string]$ObjectName = '')
    $list = @($Buttons | Where-Object { $_ -is [System.Windows.Controls.Button] })
    if (-not $list.Count) { return $null }
    $panel = $list[0].Parent
    if (-not ($panel -is [System.Windows.Controls.Panel])) { throw 'Toolbar overflow: the buttons must sit in a panel.' }
    $more = @($panel.Children | Where-Object { $_ -is [System.Windows.Controls.Button] -and [string]$_.Tag -eq 'igwt-more' }) | Select-Object -First 1
    if (-not $more) {
        $more = New-Object System.Windows.Controls.Button
        $more.Content = "$Label $([char]0x25BE)"; $more.Tag = 'igwt-more'
        $more.ToolTip = 'More actions'
        [System.Windows.Automation.AutomationProperties]::SetName($more, $(if ($ObjectName) { "$Label actions: $ObjectName" } else { "$Label actions" }))
        $more.ContextMenu = New-Object System.Windows.Controls.ContextMenu
        $more.ContextMenu.PlacementTarget = $more
        Register-IgwtGuiHandler -Control $more -Event 'Click' -Handler { param($s, $e) $null = $e; Update-IgwtGuiOverflowMenu -Menu $s.ContextMenu; $s.ContextMenu.PlacementTarget = $s; $s.ContextMenu.Placement = 'Bottom'; $s.ContextMenu.IsOpen = $true }
        $last = -1
        for ($i = 0; $i -lt $panel.Children.Count; $i++) { if ($panel.Children[$i] -is [System.Windows.Controls.Button] -and $list -notcontains $panel.Children[$i]) { $last = $i } }
        $panel.Children.Insert($last + 1, $more)
    }
    foreach ($b in $list) {
        $mi = New-Object System.Windows.Controls.MenuItem
        $mi.Header = [string]$b.Content; $mi.Tag = $b
        if ($b.ToolTip) { $mi.ToolTip = $b.ToolTip }
        [System.Windows.Automation.AutomationProperties]::SetName($mi, [string]$b.Content)
        Register-IgwtGuiHandler -Control $mi -Event 'Click' -Handler { param($s, $e) $null = $e; $src = $s.Tag; if ($src.IsEnabled) { $src.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } }
        $null = $more.ContextMenu.Items.Add($mi)
        $b.Visibility = 'Collapsed'
    }
    return $more
}

function Update-IgwtGuiOverflowMenu {
    <# .SYNOPSIS Copies each source button's IsEnabled and ToolTip to its menu item before the menu opens. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Menu)
    foreach ($mi in @($Menu.Items)) {
        $src = $mi.Tag
        if (-not $src) { continue }
        $mi.IsEnabled = [bool]$src.IsEnabled
        if ($src.ToolTip) { $mi.ToolTip = $src.ToolTip }
    }
}

function Initialize-IgwtGuiSecurityToolbars {
    <#
    .SYNOPSIS
        The Security tab toolbars within six buttons (4.0 D6): the Firewall rules toolbar (Import, Export,
        Report and Export policy under More), the selected rule's actions (Allow, Block, Duplicate and
        Delete under More) and the forensic toolbar (Estimate and Refresh under More).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $null = Set-IgwtGuiToolbarOverflow -Buttons @($c.FwImportButton, $c.FwExportButton, $c.FwReportButton, $c.FwExportPolicyButton) -ObjectName 'firewall rules'
    $null = Set-IgwtGuiToolbarOverflow -Buttons @($c.FwAllowButton, $c.FwBlockButton, $c.FwDuplicateButton, $c.FwDeleteButton) -ObjectName 'selected rule'
    $null = Set-IgwtGuiToolbarOverflow -Buttons @($c.FwForEstimateButton, $c.FwForRefreshButton) -ObjectName 'forensic logging'
}
