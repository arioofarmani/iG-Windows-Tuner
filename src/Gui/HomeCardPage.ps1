# HomeCardPage.ps1
# The home card on the Dashboard (3.6, DECISIONS T11, T18): one "next best action" with Do it, Not
# now (1 or 7 days, remembered per situation in the window's view state) and Why?. The inputs are
# read in the worker at every refresh (so at start too); choosing the card never writes. Do it
# always opens a preview or a page first. Handlers use $script:Gui state (DECISIONS U9).

function Start-IgwtGuiHomeCard {
    <# .SYNOPSIS Reads the home card inputs in the worker (read-only), then shows the card. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only check.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.C -or -not $script:Gui.C.HomeCard) { return }
    # Until the first check returns, the card says what is happening; the window stays usable.
    if (-not $script:Gui.HomeInput) { Set-IgwtGuiHomeChecking }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtHomeCardInput' -Channel 'homecard' -BusyText 'Checking what needs attention...' -OnComplete {
        param($out, $errs)
        $in = @($out | Where-Object { $_ }) | Select-Object -Last 1
        if (-not $in) { Write-Verbose "Home card not read: $(@($errs) | Select-Object -First 1)"; return }
        $script:Gui.HomeInput = $in
        Update-IgwtGuiHomeCard
    }
}

function Set-IgwtGuiHomeChecking {
    <# .SYNOPSIS The card while the startup check runs: says so, offers only Why? and All pages. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $script:Gui.HomeCardShown = [pscustomobject]@{ Key = 'checking'; Kind = 'checking'; Title = 'Checking what needs your attention...'; Action = ''
        Why = 'At start and after every refresh, iG checks the change journal, unfinished changes and the settings it set (read-only, in the background). The card updates when the check finishes.' }
    $c.HomeCardOverline.Text = 'CHECKING'
    $c.HomeCardTitle.Text = 'Checking what needs your attention...'
    $c.HomeCardText.Text = 'The change journal and the settings iG set are being checked (read-only). The window stays usable meanwhile.'
    foreach ($b in 'HomeCardDoButton', 'HomeCardSnoozeButton', 'HomeCardSnoozeWeekButton') { $c[$b].Visibility = 'Collapsed' }
    [System.Windows.Automation.AutomationProperties]::SetName($c.HomeCard, 'Next best action: checking')
    $c.HomeCard.Visibility = 'Visible'
}

function Show-IgwtGuiAllPages {
    <# .SYNOPSIS "All pages": leaves focus mode when it hides pages and moves the keyboard focus to the page list. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    if ($script:Gui.ViewState -and [bool]$script:Gui.ViewState.FocusMode) { Set-IgwtGuiFocusMode -On $false }
    $nav = $script:Gui.C.NavList
    if ($nav) { $item = $nav.ItemContainerGenerator.ContainerFromItem($nav.SelectedItem); if ($item) { $null = $item.Focus() } else { $null = $nav.Focus() } }
    Set-IgwtGuiStatus 'Every page is in the list on the left (arrow keys to move, Enter to open).'
}
function Get-IgwtGuiHomeSnoozed {
    <# .SYNOPSIS The snoozed cards (key -> until) from the window's view state. #>
    [CmdletBinding()]
    param()
    $out = @{}
    $raw = $(if ($script:Gui.ViewState) { $script:Gui.ViewState['HomeSnooze'] })
    if ($raw -is [System.Collections.IDictionary]) { foreach ($k in $raw.Keys) { $dt = [datetime]::MinValue; if ([datetime]::TryParse([string]$raw[$k], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) { $out[[string]$k] = $dt.ToLocalTime() } } }
    elseif ($raw) { foreach ($p in $raw.PSObject.Properties) { $dt = [datetime]::MinValue; if ([datetime]::TryParse([string]$p.Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) { $out[$p.Name] = $dt.ToLocalTime() } } }
    return $out
}

function Update-IgwtGuiHomeCard {
    <# .SYNOPSIS Shows the chosen card (Select-IgwtHomeCard) in the Dashboard. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if (-not $script:Gui.HomeInput) { $c.HomeCard.Visibility = 'Collapsed'; return }
    $card = Select-IgwtHomeCard -InputData $script:Gui.HomeInput -Snoozed (Get-IgwtGuiHomeSnoozed)
    $script:Gui.HomeCardShown = $card
    $c.HomeCardTitle.Text = [string]$card.Title
    $c.HomeCardText.Text = [string]$card.Text
    $c.HomeCardOverline.Text = $(switch ([string]$card.Kind) { 'journal' { 'NEEDS ATTENTION' } 'incomplete' { 'NEEDS ATTENTION' } 'drift' { 'DRIFT' } 'forensic' { 'FORENSIC LOGGING' } 'unverified' { 'CONFIDENCE' } 'suggestion' { 'SUGGESTION' } default { 'ALL CLEAR' } })
    $isClear = ([string]$card.Kind -eq 'clear')
    $c.HomeCardDoButton.Visibility = $(if ($card.Action) { 'Visible' } else { 'Collapsed' })
    $c.HomeCardSnoozeButton.Visibility = $(if ($isClear) { 'Collapsed' } else { 'Visible' })
    $c.HomeCardSnoozeWeekButton.Visibility = $(if ($isClear) { 'Collapsed' } else { 'Visible' })
    $c.HomeCardDoButton.IsEnabled = -not ($card.Action -in 'recover', 'drift' -and -not $script:Gui.IsAdmin)
    $c.HomeCardDoButton.ToolTip = $(if (-not $c.HomeCardDoButton.IsEnabled) { Get-IgwtGuiChangeBlockReason -What 'fix this' } else { 'Opens a preview first; nothing changes until you confirm.' })
    [System.Windows.Automation.AutomationProperties]::SetName($c.HomeCard, "Next best action: $($card.Title)")
    $c.HomeCard.Visibility = 'Visible'
}

function Set-IgwtGuiHomeSnooze {
    <# .SYNOPSIS "Not now": hides the current card for 1 or 7 days (remembered in the window's view state). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state of the window only.')]
    [CmdletBinding()]
    param([ValidateSet(1, 7)][int]$Days = 1)
    $card = $script:Gui.HomeCardShown
    if (-not $card -or [string]$card.Kind -eq 'clear') { return }
    $map = [ordered]@{}
    $now = Get-Date
    foreach ($kv in (Get-IgwtGuiHomeSnoozed).GetEnumerator()) { if ($kv.Value -gt $now) { $map[$kv.Key] = $kv.Value.ToUniversalTime().ToString('o') } }
    $map[[string]$card.Key] = $now.AddDays($Days).ToUniversalTime().ToString('o')
    Set-IgwtGuiViewValue -Name 'HomeSnooze' -Value $map
    Update-IgwtGuiHomeCard
    Set-IgwtGuiStatus "Hidden for $Days day(s): $($card.Title)."
}

function Show-IgwtGuiHomeWhy {
    <# .SYNOPSIS "Why?": the details of the current card. #>
    [CmdletBinding()]
    param()
    $card = $script:Gui.HomeCardShown
    if ($card) { $null = Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $($card.Title)" -Text ([string]$card.Why) }
}

function Invoke-IgwtGuiHomeAction {
    <# .SYNOPSIS "Do it": opens the preview or the page for the current card; changes run only after confirmation. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Every change runs after its own preview and confirmation.')]
    [CmdletBinding()]
    param()
    $card = $script:Gui.HomeCardShown
    if (-not $card) { return }
    $in = $script:Gui.HomeInput
    switch ([string]$card.Action) {
        'openJournal' { Select-IgwtGuiNavPage -Tag 'Backups'; $script:Gui.C.BackupTabs.SelectedItem = $script:Gui.C.BackupJournalTab }
        'forensic' { Select-IgwtGuiNavPage -Tag 'Firewall'; $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwForensicTab }
        'presets' { Select-IgwtGuiNavPage -Tag 'Presets' }
        'unverified' { Select-IgwtGuiNavPage -Tag 'Presets'; Set-IgwtGuiStatus "Unverified in your preset: $(@($card.Items) -join ', '). Customize the preset to leave them out." }
        'recover' {
            $s = @($in.Incomplete | Where-Object { [string]$_.Id -eq [string]$card.SessionId }) | Select-Object -First 1
            if (-not $s) { return }
            $lines = @("Roll back '$($s.Title)' (started $($s.StartedUtc)). Each step below is restored to the value recorded before it, newest first, as a new journaled change:", '')
            $lines += @($s.Steps | Sort-Object Step -Descending | ForEach-Object { "  {0,-12} {1}   before: {2}" -f $_.Result, $_.Item, (Format-IgwtJournalValue -Value $_.Before) })
            if (-not (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - roll back an unfinished change' -Text ($lines -join [Environment]::NewLine) -AcceptText 'Roll back' -CancelText 'Cancel')) { return }
            $null = Start-IgwtGuiJob -Command 'Invoke-IgwtChangeRecovery' -Parameters @{ SessionId = [string]$s.Id; Confirm = $false } -Blocking -BusyText 'Rolling back the unfinished change...' -OnComplete {
                param($out, $errs)
                $r = @($out | Where-Object { $_ }) | Select-Object -Last 1
                if ($r) { $null = Show-IgwtGuiMessage -Text $(if ($r.Complete) { 'The unfinished change was rolled back.' } else { "Rolled back with errors: $(@($r.Errors) -join ' ')" }) -Icon $(if ($r.Complete) { 'Information' } else { 'Warning' }) }
                elseif (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The rollback failed: $(@($errs)[0])" -Icon 'Error' }
                Start-IgwtGuiRefresh
            }
        }
        'drift' {
            $rows = @($in.Drift.Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' })
            if (-not $rows.Count) { return }
            $pick = Show-IgwtGuiDriftDialog -Drift $in.Drift -Rows $rows
            if (-not $pick -or -not @($pick.Rows).Count) { return }
            if ($pick.Action -eq 'Reapply') {
                # The normal path: stage the items, then the normal preview; Apply runs them as one session (origin driftFix).
                $ids = @(Get-IgwtDriftReapplyIds -Rows $pick.Rows)
                if (-not $ids.Count) { return }
                $script:Gui.Staged.Clear()
                foreach ($id in $ids) { Set-IgwtGuiStage -Id $id -Mode 'on' }
                $script:Gui.PresetOperation = 'DriftFix'
                Update-IgwtGuiPending
                Invoke-IgwtGuiPreview
            } elseif ($pick.Action -eq 'Accept') {
                $null = Start-IgwtGuiJob -Command 'Invoke-IgwtDriftAccept' -Parameters @{ Rows = @($pick.Rows); Confirm = $false } -Blocking -BusyText 'Recording the accepted values...' -OnComplete {
                    param($out, $errs)
                    $r = @($out | Where-Object { $_ }) | Select-Object -Last 1
                    if ($r) { Set-IgwtGuiStatus "Accepted the current value of $($r.Accepted) setting(s); iG no longer tracks the values it set there." }
                    elseif (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "Not recorded: $(@($errs)[0])" -Icon 'Error' }
                    Start-IgwtGuiHomeCard
                }
            }
        }
    }
}

function Show-IgwtGuiDriftDialog {
    <#
    .SYNOPSIS
        The drifted settings with what iG set and what is there now, one check box per item (all
        ticked), and the updates installed in between. Returns @{ Action = Reapply | Accept; Rows }
        or $null. Changes nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Drift, [Parameter(Mandatory = $true)][object[]]$Rows)
    $w = New-Object System.Windows.Window
    $w.Title = 'iG Windows Tuner - settings that changed'
    $w.Width = 820; $w.Height = 560; $w.MinWidth = 560; $w.MinHeight = 360
    $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'
    $w.Background = $script:Gui.Window.FindResource('BrushBackground')
    [System.Windows.Automation.AutomationProperties]::SetName($w, 'Settings that changed')
    $grid = New-Object System.Windows.Controls.Grid; $grid.Margin = '14'
    foreach ($h in 'Auto', '*', 'Auto') { $rd = New-Object System.Windows.Controls.RowDefinition; $rd.Height = $h; $grid.RowDefinitions.Add($rd) }
    $head = New-Object System.Windows.Controls.TextBlock
    $head.TextWrapping = 'Wrap'; $head.Margin = '0,0,0,8'; $head.Foreground = $script:Gui.Window.FindResource('BrushText')
    $head.Text = "$($Drift.Summary) Tick the settings to act on." + $(if (@($Drift.Updates).Count) { ' Installed in between: ' + ((@($Drift.Updates) | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; ') + '.' } else { '' })
    [System.Windows.Controls.Grid]::SetRow($head, 0)
    $list = New-Object System.Windows.Controls.StackPanel
    $boxes = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.IsChecked = $true; $cb.Margin = '0,0,0,8'; $cb.Tag = $r
        $cb.Content = "$(if ($r.PSObject.Properties['Name'] -and $r.Name) { $r.Name } else { $r.Item })  ($($r.Status))`n   iG set: $(Format-IgwtJournalValue -Value $r.WeSet)`n   now:    $(Format-IgwtJournalValue -Value $r.Now)"
        $cb.Foreground = $script:Gui.Window.FindResource('BrushText')
        [System.Windows.Automation.AutomationProperties]::SetName($cb, "$($r.Item), $($r.Status)")
        $null = $list.Children.Add($cb); $boxes.Add($cb)
    }
    $sv = New-Object System.Windows.Controls.ScrollViewer; $sv.VerticalScrollBarVisibility = 'Auto'; $sv.Content = $list
    [System.Windows.Controls.Grid]::SetRow($sv, 1)
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,12,0,0'
    [System.Windows.Controls.Grid]::SetRow($panel, 2)
    $result = @{ Action = '' }
    $re = New-Object System.Windows.Controls.Button; $re.Content = 'Re-apply selected...'; $re.Style = $script:Gui.Window.FindResource('AccentButton'); $re.IsDefault = $true
    [System.Windows.Automation.AutomationProperties]::SetName($re, 'Re-apply selected')
    Register-IgwtGuiHandler -Control $re -Event 'Click' -Handler { $result.Action = 'Reapply'; $w.Close() }.GetNewClosure()
    $ac = New-Object System.Windows.Controls.Button; $ac.Content = 'Accept current values'
    [System.Windows.Automation.AutomationProperties]::SetName($ac, 'Accept current values of the selected settings')
    Register-IgwtGuiHandler -Control $ac -Event 'Click' -Handler { $result.Action = 'Accept'; $w.Close() }.GetNewClosure()
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.IsCancel = $true
    [System.Windows.Automation.AutomationProperties]::SetName($cancel, 'Cancel')
    foreach ($b in $re, $ac, $cancel) { $b.Margin = '8,0,0,0'; $null = $panel.Children.Add($b) }
    foreach ($x in $head, $sv, $panel) { $null = $grid.Children.Add($x) }
    $w.Content = $grid
    $null = $w.ShowDialog()
    if (-not $result.Action) { return $null }
    return @{ Action = $result.Action; Rows = @($boxes | Where-Object { $_.IsChecked } | ForEach-Object { $_.Tag }) }
}