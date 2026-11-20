# HistoryPage.ps1
# 4.0 History (D4, mockup 3): every change session from the change journal as a card, newest first,
# with filter chips and one Undo per session. Undo opens the session's revert plan inside its card
# (value before, value iG set, state now); a value that changed since iG set it gets its choices in
# the row, and nothing runs until the card's own Undo button is pressed: there is no chain of message
# boxes, so Esc can never skip one value and carry on with the rest (review JP-1). "Reset everything
# iG changed" opens the same view for every value iG still has changed. The page reads with
# Get-IgwtJournalTimeline and Get-IgwtRevertPlan and changes only through Invoke-IgwtJournalRevert,
# all in the worker (DECISIONS HS1-HS7). Handlers use $script:Gui state and Tags, never closures.

$script:IgwtGuiHistoryFilters = @('All', 'Still in place', 'Changed since', 'Undone', 'Cannot be undone')

#region View models (pure)

function Get-IgwtGuiHistoryTitle {
    <# .SYNOPSIS A journal session title in plain words ("Preset:competitive (3 item(s))" -> "Applied the Competitive preset"). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Title, [object[]]$Presets = @())
    $t = [string]$Title
    if ($t -match '^Preset:([\w\-]+)') {
        $id = $Matches[1]
        $p = @($Presets | Where-Object { $_ -and [string]$_.id -eq $id }) | Select-Object -First 1
        $name = $(if ($p) { [string]$p.name } else { (Get-Culture).TextInfo.ToTitleCase(($id -replace '-', ' ')) })
        return "Applied the $name preset"
    }
    if ($t -match '^Revert session: (.+)$') { return "Undo: $(Get-IgwtGuiHistoryTitle -Title $Matches[1] -Presets $Presets)" }
    $t = $t -replace '^Invoke-Igwt\w+$', 'System change' -replace '^Invoke-Igwt\w+\s+', ''
    if (-not $t) { return 'Change' }
    return $t.Substring(0, 1).ToUpperInvariant() + $t.Substring(1)
}

function Get-IgwtGuiHistoryItemName {
    <# .SYNOPSIS The name to show for a journal item: the catalog name, or plain words for module and cleaner items. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Item, [hashtable]$Names = @{})
    if ($Names.ContainsKey($Item)) { return [string]$Names[$Item] }
    if ($Item -match '^module:Invoke-Igwt(\w+)$') {
        $w = ($Matches[1] -creplace '(?<=[a-z])(?=[A-Z])', ' ').ToLowerInvariant()
        return $w.Substring(0, 1).ToUpperInvariant() + $w.Substring(1)
    }
    if ($Item -match '^regclean:(.+)$') { return "Registry leftover ($($Matches[1]))" }
    return $Item
}

function Get-IgwtGuiHistorySessions {
    <#
    .SYNOPSIS
        The change sessions of a Get-IgwtJournalTimeline result as History cards, newest first: title,
        time, counts (settings, still in place, changed since, cannot be undone, failed), a state and
        one metadata line. -Plan is a Get-IgwtRevertPlan -All result; its Conflict rows mark the values
        changed since iG set them. Pure.
    #>
    [CmdletBinding()]
    param($Timeline, [object[]]$Plan = @(), [object[]]$Presets = @())
    $conflict = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in @($Plan | Where-Object { $_ -and [string]$_.Status -eq 'Conflict' })) { $null = $conflict.Add([string]$p.Key) }
    $groups = [ordered]@{}
    foreach ($r in @($Timeline.Rows | Where-Object { $_ })) {
        $k = [string]$r.Session
        if (-not $groups.Contains($k)) { $groups[$k] = New-Object System.Collections.Generic.List[object] }
        $groups[$k].Add($r)
    }
    $out = foreach ($k in $groups.Keys) {
        $rows = $groups[$k].ToArray()
        $first = $rows[0]
        $changes = @($rows | Where-Object { [string]$_.Op -eq 'change' -and [string]$_.Result -eq 'Committed' })
        $restores = @($rows | Where-Object { [string]$_.Op -eq 'restore' -and [string]$_.Result -eq 'Committed' })
        $inPlace = @($changes | Where-Object { $_.InEffect })
        $undoable = @($inPlace | Where-Object { -not $_.OneWay })
        $oneWay = @($changes | Where-Object { $_.OneWay })
        $changed = @($inPlace | Where-Object { $conflict.Contains([string]$_.Target) })
        $failed = @($rows | Where-Object { [string]$_.Result -in 'Failed', 'RollbackFailed', 'InDoubt' })
        $dt = [datetime]::MinValue
        $null = [datetime]::TryParse([string]$first.When, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)
        $state = $(if ($inPlace.Count) { 'InPlace' } elseif ($changes.Count -and $oneWay.Count -eq $changes.Count) { 'OneWay' } elseif ($changes.Count) { 'Undone' } else { 'Record' })
        $n = $(if ($changes.Count) { $changes.Count } else { $restores.Count })
        $meta = New-Object System.Collections.Generic.List[string]
        if ($dt -ne [datetime]::MinValue) { $meta.Add($dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm')) }
        $meta.Add("$n setting$(if ($n -ne 1) { 's' })$(if ($state -eq 'Record') { ' put back' })")
        if ($state -eq 'InPlace') { $meta.Add("$($inPlace.Count) still in place") }
        elseif ($state -eq 'Undone') { $meta.Add('no longer in place') }
        if ($changed.Count) { $meta.Add("$($changed.Count) changed since") }
        if ($oneWay.Count) { $meta.Add("$($oneWay.Count) cannot be undone") }
        if ($failed.Count) { $meta.Add("$($failed.Count) failed or unfinished") }
        [pscustomobject]@{
            Id = $k; Title = (Get-IgwtGuiHistoryTitle -Title ([string]$first.SessionTitle) -Presets $Presets); RawTitle = [string]$first.SessionTitle
            When = $dt; Origin = [string]$first.Origin; Steps = $rows; Changes = $changes.Count; InPlace = $inPlace.Count
            Undoable = $undoable.Count; Conflicts = $changed.Count; OneWay = $oneWay.Count; Failed = $failed.Count
            State = $state; CanUndo = [bool]$undoable.Count; Meta = ($meta -join '  |  ')
        }
    }
    return @($out | Sort-Object -Property @{ Expression = { $_.When }; Descending = $true }, @{ Expression = { $_.Id }; Descending = $true })
}

function Test-IgwtGuiHistoryFilter {
    <# .SYNOPSIS True when a History session card matches a filter chip. Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Session, [string]$Filter = 'All')
    switch ($Filter) {
        'Still in place' { return [bool]($Session.InPlace -gt 0) }
        'Changed since' { return [bool]($Session.Conflicts -gt 0) }
        'Undone' { return [bool]($Session.State -eq 'Undone') }
        'Cannot be undone' { return [bool]($Session.OneWay -gt 0) }
        default { return $true }
    }
}

function Get-IgwtGuiHistoryPlanState {
    <#
    .SYNOPSIS
        What the card's Undo button would do with a revert plan and the choices made so far: Ready rows
        are put back; each Conflict row needs a choice (Restore, Keep or Skip) before the button is
        enabled. Returns the counts, CanConfirm, the button text, a summary and the decisions for
        Invoke-IgwtJournalRevert (JP-1: no value is decided by pressing Esc). Pure.
    #>
    [CmdletBinding()]
    param([object[]]$Plan = @(), [hashtable]$Decisions = @{})
    $restore = 0; $keep = 0; $skip = 0; $undecided = 0; $other = 0
    $out = @{}
    foreach ($p in @($Plan | Where-Object { $_ })) {
        $key = [string]$p.Key
        switch ([string]$p.Status) {
            'Ready' { $restore++ }
            'Conflict' {
                $d = $(if ($Decisions.ContainsKey($key)) { [string]$Decisions[$key] } else { '' })
                switch ($d) {
                    'Restore' { $restore++; $out[$key] = 'Restore' }
                    'Keep' { $keep++; $out[$key] = 'Keep' }
                    'Skip' { $skip++; $out[$key] = 'Skip' }
                    default { $undecided++ }
                }
            }
            default { $other++ }
        }
    }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($undecided) { $parts.Add("Choose what happens to $undecided setting$(if ($undecided -ne 1) { 's' }) that changed since iG set $(if ($undecided -ne 1) { 'them' } else { 'it' }).") }
    $parts.Add("$restore will be put back")
    if ($keep) { $parts.Add("$keep kept as they are now") }
    if ($skip) { $parts.Add("$skip skipped") }
    if ($other) { $parts.Add("$other already back or cannot be undone") }
    $summary = $(if ($undecided) { $parts[0] + ' ' + (($parts | Select-Object -Skip 1) -join ', ') + '.' } else { ($parts -join ', ') + '.' })
    $text = $(if ($restore) { "Undo $restore setting$(if ($restore -ne 1) { 's' })" } elseif ($keep) { 'Keep the current values' } else { 'Undo' })
    [pscustomobject]@{
        Restore = $restore; Keep = $keep; Skip = $skip; Undecided = $undecided; Other = $other
        CanConfirm = [bool](-not $undecided -and ($restore + $keep) -gt 0); ConfirmText = $text; Summary = $summary; Decisions = $out
    }
}

#endregion

#region Loading

function Set-IgwtGuiHistoryData {
    <# .SYNOPSIS Stores a timeline (and optionally the -All revert plan) for History and redraws it when visible. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Timeline, [object[]]$Plan, [switch]$KeepPlan)
    $h = Get-IgwtGuiHistoryState
    if ($PSBoundParameters.ContainsKey('Timeline')) { $h.Timeline = $Timeline }
    if ($PSBoundParameters.ContainsKey('Plan')) { $h.AllPlan = @($Plan | Where-Object { $_ }) } elseif (-not $KeepPlan) { $h.AllPlan = @() }
    Update-IgwtGuiHistoryIfVisible
}

function Get-IgwtGuiHistoryState {
    <# .SYNOPSIS The History page state ($script:Gui.Hist), created on first use. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates window state only.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.Hist) { $script:Gui.Hist = @{ Timeline = $null; AllPlan = @(); Filter = 'All'; Open = ''; Plan = $null; Decisions = @{}; Shown = 20; Result = $null; Error = '' } }
    return $script:Gui.Hist
}

function Update-IgwtGuiHistoryIfVisible {
    <# .SYNOPSIS Redraws History when it is the page on screen. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if ($c -and $c.PageHistory -and $c.PageHistory.Visibility -eq 'Visible') { Update-IgwtGuiHistoryPage }
}

function Start-IgwtGuiHistoryLoad {
    <# .SYNOPSIS Reads the change journal (read-only), then compares every value iG still has changed with its value now. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts read-only queries.')]
    [CmdletBinding()]
    param()
    $h = Get-IgwtGuiHistoryState
    $h.Error = ''
    $started = Start-IgwtGuiJob -Command 'Get-IgwtJournalTimeline' -Channel 'history' -BusyText 'Reading the change journal...' -OnComplete {
        param($out, $errs)
        $t = @($out | Where-Object { $_ }) | Select-Object -Last 1
        $hs = Get-IgwtGuiHistoryState
        if (-not $t) { $hs.Error = $(if (@($errs).Count) { [string]@($errs)[0] } else { 'The change journal could not be read.' }); Update-IgwtGuiHistoryIfVisible; return }
        Set-IgwtGuiHistoryData -Timeline $t -KeepPlan
        if ([string]$t.Status -eq 'Ok' -and [int]$t.Tracked -gt 0) {
            $null = Start-IgwtGuiJob -Command 'Get-IgwtRevertPlan' -Parameters @{ All = $true } -Channel 'historyplan' -BusyText 'Comparing with the values now...' -OnComplete {
                param($o2, $e2)
                $null = $e2
                Set-IgwtGuiHistoryData -Plan @($o2 | Where-Object { $_ })
            }
        } else { Set-IgwtGuiHistoryData -Plan @() }
    }
    if ($started) { Update-IgwtGuiHistoryIfVisible }
}

function Open-IgwtGuiHistoryUndo {
    <#
    .SYNOPSIS
        Opens the revert plan of one session (-Id) or of everything iG changed (-Id '*') in its card:
        read in the worker, nothing changes until the card's Undo button.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text (Get-IgwtGuiChangeBlockReason -What 'undo changes'); return }
    $h = Get-IgwtGuiHistoryState
    $h.Open = $Id; $h.Plan = $null; $h.Decisions = @{}; $h.Result = $null
    $p = $(if ($Id -eq '*') { @{ All = $true } } else { @{ SessionId = $Id } })
    $null = Start-IgwtGuiJob -Command 'Get-IgwtRevertPlan' -Parameters $p -Channel 'historyundo' -BusyText 'Comparing each value with the value now...' -Context @{ Id = $Id } -OnComplete {
        param($out, $errs, $ctx)
        $hs = Get-IgwtGuiHistoryState
        if ($hs.Open -ne $ctx.Id) { return }
        if (@($errs).Count -and -not @($out).Count) { $hs.Open = ''; $null = Show-IgwtGuiMessage -Text "The undo preview failed: $(@($errs)[0])" -Icon 'Error'; Update-IgwtGuiHistoryIfVisible; return }
        $hs.Plan = @($out | Where-Object { $_ })
        Update-IgwtGuiHistoryIfVisible
    }
    Update-IgwtGuiHistoryIfVisible
}

function Set-IgwtGuiHistoryDecision {
    <# .SYNOPSIS Records the choice for one value that changed since iG set it (Restore, Keep or Skip). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][ValidateSet('Restore', 'Keep', 'Skip')][string]$Choice)
    $h = Get-IgwtGuiHistoryState
    $h.Decisions[$Key] = $Choice
    Update-IgwtGuiHistoryIfVisible
}

function Close-IgwtGuiHistoryUndo {
    <# .SYNOPSIS Closes the open undo view; nothing was changed. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param()
    $h = Get-IgwtGuiHistoryState
    $h.Open = ''; $h.Plan = $null; $h.Decisions = @{}
    Set-IgwtGuiStatus 'Undo cancelled; nothing was changed.'
    Update-IgwtGuiHistoryIfVisible
}

function Invoke-IgwtGuiHistoryUndo {
    <# .SYNOPSIS Runs the open plan with the choices made in the card, as one journaled revert session in the worker. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs only from the card''s Undo button, after the plan and every choice are shown.')]
    [CmdletBinding()]
    param()
    $h = Get-IgwtGuiHistoryState
    if (-not $h.Open -or $null -eq $h.Plan -or -not $script:Gui.IsAdmin) { return }
    $st = Get-IgwtGuiHistoryPlanState -Plan @($h.Plan) -Decisions $h.Decisions
    if (-not $st.CanConfirm) { Set-IgwtGuiStatus $st.Summary; return }
    $title = $(if ($h.Open -eq '*') { 'Reset everything iG changed' } else { $s = @(Get-IgwtGuiHistorySessions -Timeline $h.Timeline -Presets @($script:Gui.Presets) | Where-Object { $_.Id -eq $h.Open }) | Select-Object -First 1; "Undo: $(if ($s) { $s.Title } else { $h.Open })" })
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtJournalRevert' -Parameters @{ Plan = @($h.Plan); Decisions = $st.Decisions; Title = $title; Confirm = $false } -Blocking -BusyText 'Undoing through the change journal...' -OnComplete {
        param($out, $errs)
        $hs = Get-IgwtGuiHistoryState
        $r = @($out | Where-Object { $_ }) | Select-Object -Last 1
        $hs.Open = ''; $hs.Plan = $null; $hs.Decisions = @{}
        if ($r) {
            $res = @($r.Results)
            $ok = @($res | Where-Object { $_.Result -in 'Reverted', 'Kept' }).Count
            $bad = @($res | Where-Object { $_.Result -in 'Failed', 'NeedsDecision' })
            $hs.Result = [pscustomobject]@{ Tone = $(if ($bad.Count) { 'Warning' } else { 'Success' }); Title = $(if ($bad.Count) { "$ok done, $($bad.Count) not undone" } else { "Undone: $ok setting$(if ($ok -ne 1) { 's' })" }); Text = (@($bad | ForEach-Object { "$($_.Item): $($_.Message)" }) -join ' ') }
        } elseif (@($errs).Count) { $hs.Result = [pscustomobject]@{ Tone = 'Danger'; Title = 'Undo failed'; Text = [string]@($errs)[0] } }
        $script:Gui.Journal = $null
        Start-IgwtGuiHistoryLoad
        Start-IgwtGuiRefresh
    }
    Update-IgwtGuiHistoryIfVisible
}

#endregion

#region Drawing

function Update-IgwtGuiHistoryPage {
    <# .SYNOPSIS Draws History (mockup 3) into HistoryHost from the stored timeline, plans and choices. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $host_ = $c.HistoryHost
    if (-not $host_) { return }
    $h = Get-IgwtGuiHistoryState
    $host_.Children.Clear()
    $t = $h.Timeline
    $ok = ($t -and [string]$t.Status -eq 'Ok')
    $busy = [bool]$script:Gui.Job
    $names = @{}; foreach ($x in @($script:Gui.Catalog)) { if ($x) { $names[[string]$x.id] = [string]$x.name } }

    $reset = New-IgwtUiButton -Text 'Reset everything iG changed' -Kind Danger
    $reset.IsEnabled = $ok -and [bool]$script:Gui.IsAdmin -and -not $busy -and [int]$t.Tracked -gt 0 -and $h.Open -ne '*'
    $reset.ToolTip = 'Shows every value iG still has changed next to its value before iG; nothing changes until you press Undo there.'
    Register-IgwtGuiHandler -Control $reset -Event 'Click' -Handler { Open-IgwtGuiHistoryUndo -Id '*' }
    $null = $host_.Children.Add((New-IgwtPageHeader -Title 'History' -Subtitle 'Everything iG changed, newest first. Undo checks each value first and asks when something else changed it since.' -Right $reset))

    if ($h.Result) {
        $ib = New-IgwtInfoBar -Title $h.Result.Title -Message $h.Result.Text -Tone $h.Result.Tone
        $ib.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16); $null = $host_.Children.Add($ib)
    }
    if ($h.Error) { $null = $host_.Children.Add((New-IgwtInfoBar -Title 'The change journal could not be read' -Message $h.Error -Tone Danger)); return }
    if (-not $t) { $null = $host_.Children.Add((New-IgwtEmptyState -Text 'Reading the change journal (read-only)...')); return }
    if ([string]$t.Status -eq 'Broken') {
        $ib = New-IgwtInfoBar -Title 'The change journal failed its check' -Message "Nothing can be undone from it until it is set aside (nothing is deleted). $($t.Reason)" -Tone Danger -ActionText 'Set it aside...'
        foreach ($b in @(Get-IgwtUiDescendant -Root $ib | Where-Object { $_ -is [System.Windows.Controls.Button] })) { $b.IsEnabled = [bool]$script:Gui.IsAdmin -and -not $busy; Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { Start-IgwtGuiJournalReset } }
        $null = $host_.Children.Add($ib)
        return
    }
    if (-not $script:Gui.IsAdmin) {
        $ib = New-IgwtInfoBar -Title 'Read-only' -Message 'Restart iG Windows Tuner as administrator to undo changes.' -Tone Info
        $ib.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16); $null = $host_.Children.Add($ib)
    }
    if ($h.Open -eq '*') {
        $card = New-IgwtGuiHistoryCardFrame -Title 'Reset everything iG changed' -Meta "$([int]$t.Tracked) value$(if ([int]$t.Tracked -ne 1) { 's' }) iG still has changed, each back to its value before iG"
        Add-IgwtGuiHistoryPlanView -Panel $card.Body -Names $names -ObjectName 'everything iG changed'
        $card.Frame.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
        $null = $host_.Children.Add($card.Frame)
    }

    $chips = New-IgwtChipGroup -Labels $script:IgwtGuiHistoryFilters -Selected @($h.Filter) -GroupName 'Show' -Single
    $chips.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
    foreach ($ch in $chips.Children) { Register-IgwtGuiHandler -Control $ch -Event 'Click' -Handler { param($s, $e) $hs = Get-IgwtGuiHistoryState; $hs.Filter = [string]$s.Tag; $hs.Shown = 20; Update-IgwtGuiHistoryPage } }
    $null = $host_.Children.Add($chips)

    $sessions = @(Get-IgwtGuiHistorySessions -Timeline $t -Plan @($h.AllPlan) -Presets @($script:Gui.Presets))
    $shown = @($sessions | Where-Object { Test-IgwtGuiHistoryFilter -Session $_ -Filter $h.Filter })
    if (-not $sessions.Count) { $null = $host_.Children.Add((New-IgwtEmptyState -Text 'No changes yet. Every change iG makes is recorded here before it is made, with the value before and the value set.')) }
    elseif (-not $shown.Count) { $null = $host_.Children.Add((New-IgwtEmptyState -Text "No change matches '$($h.Filter)'.")) }
    foreach ($s in @($shown | Select-Object -First ([int]$h.Shown))) { $null = $host_.Children.Add((New-IgwtGuiHistoryCard -Session $s -Names $names -Busy $busy)) }
    if ($shown.Count -gt [int]$h.Shown) {
        $more = New-IgwtUiButton -Text "Show $([Math]::Min(20, $shown.Count - [int]$h.Shown)) more" -Kind Subtle -ObjectName 'sessions'
        $more.HorizontalAlignment = 'Left'
        Register-IgwtGuiHandler -Control $more -Event 'Click' -Handler { $hs = Get-IgwtGuiHistoryState; $hs.Shown = [int]$hs.Shown + 20; Update-IgwtGuiHistoryPage }
        $null = $host_.Children.Add($more)
    }
    # S1: only iG's own records are restored.
    $note = New-IgwtUiText -Text 'Backups from iG 3.x are imported here once. Backup files from anywhere else are never restored. The full change table, the 3.x snapshots and the log are on the Backups and logs tab.' -Style 'TextCaption' -Brush 'BrushTextMuted'
    $note.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0); $null = $host_.Children.Add($note)
}

function New-IgwtGuiHistoryCardFrame {
    <# .SYNOPSIS The card shell: title, metadata line, an optional element on the right, and a body panel. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title, [string]$Meta = '', $Right = $null)
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'SessionCard')
    $sp = New-Object System.Windows.Controls.StackPanel
    $top = New-Object System.Windows.Controls.DockPanel
    if ($Right) { [System.Windows.Controls.DockPanel]::SetDock($Right, 'Right'); $Right.VerticalAlignment = 'Center'; $null = $top.Children.Add($Right) }
    $hd = New-Object System.Windows.Controls.StackPanel
    $tt = New-IgwtUiText -Text $Title -Style 'TextSubtitle'
    [System.Windows.Automation.AutomationProperties]::SetHeadingLevel($tt, [System.Windows.Automation.AutomationHeadingLevel]::Level2)
    $null = $hd.Children.Add($tt)
    if ($Meta) { $null = $hd.Children.Add((New-IgwtUiText -Text $Meta -Style 'TextBody' -Brush 'BrushTextMuted')) }
    $null = $top.Children.Add($hd)
    $null = $sp.Children.Add($top)
    $body = New-Object System.Windows.Controls.StackPanel
    $null = $sp.Children.Add($body)
    $b.Child = $sp
    $null = Set-IgwtUiName -Element $b -Name "$Title. $Meta".TrimEnd(' ', '.')
    return [pscustomobject]@{ Frame = $b; Body = $body }
}

function New-IgwtGuiHistoryCard {
    <# .SYNOPSIS One session card: Undo (or why not), and either its settings or, when opened, its undo plan. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session, [hashtable]$Names = @{}, [bool]$Busy)
    $h = Get-IgwtGuiHistoryState
    $open = ($h.Open -eq [string]$Session.Id)
    $right = $null
    if ($Session.CanUndo) {
        $right = New-IgwtUiButton -Text 'Undo' -Kind Secondary -ObjectName $Session.Title
        $right.Tag = [string]$Session.Id
        $right.IsEnabled = [bool]$script:Gui.IsAdmin -and -not $Busy -and -not $open
        $right.ToolTip = 'Shows each setting with its value before, the value iG set and the value now; nothing changes until you press Undo in the card.'
        Register-IgwtGuiHandler -Control $right -Event 'Click' -Handler { param($s, $e) Open-IgwtGuiHistoryUndo -Id ([string]$s.Tag) }
    } elseif ($Session.State -eq 'OneWay') { $right = New-IgwtPill -Text 'Cannot be undone' -Tone Neutral }
    elseif ($Session.State -eq 'Undone') { $right = New-IgwtPill -Text 'No longer in place' -Tone Neutral }
    $card = New-IgwtGuiHistoryCardFrame -Title $Session.Title -Meta $Session.Meta -Right $right
    $card.Frame.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)
    if ($open) { Add-IgwtGuiHistoryPlanView -Panel $card.Body -Names $Names -ObjectName $Session.Title; return $card.Frame }
    $steps = @($Session.Steps | Where-Object { $_ })
    if (-not $steps.Count) { return $card.Frame }
    $conflict = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in @($h.AllPlan | Where-Object { [string]$_.Status -eq 'Conflict' })) { $null = $conflict.Add([string]$p.Key) }
    $ex = New-Object System.Windows.Controls.Expander
    $ex.Header = "$($steps.Count) setting$(if ($steps.Count -ne 1) { 's' })"
    $ex.Margin = [System.Windows.Thickness]::new(0, 10, 0, 0)
    $ex.IsExpanded = ($Session.Conflicts -gt 0 -and $steps.Count -le 6)
    $null = Set-IgwtUiName -Element $ex -Name "Settings in $($Session.Title)"
    $list = New-Object System.Windows.Controls.StackPanel
    $null = $list.Children.Add((New-IgwtGuiHistoryStepRow -Setting 'Setting' -Values 'Before  >  set by iG' -Status 'Now' -Header))
    foreach ($st in $steps) {
        $word = $(if ([string]$st.Result -ne 'Committed') { @('Failed or unfinished', 'Danger') } elseif ([string]$st.Op -eq 'restore') { @('Restored', 'Neutral') } elseif ($st.OneWay) { @('Cannot be undone', 'Neutral') } elseif ($st.InEffect -and $conflict.Contains([string]$st.Target)) { @('Changed since', 'Warning') } elseif ($st.InEffect) { @('In place', 'Success') } else { @('No longer in place', 'Neutral') })
        $null = $list.Children.Add((New-IgwtGuiHistoryStepRow -Setting (Get-IgwtGuiHistoryItemName -Item ([string]$st.Item) -Names $Names) -Values ("{0}  >  {1}" -f $st.Before, $st.After) -Status $word[0] -Tone $word[1]))
    }
    $ex.Content = $list
    $null = $card.Body.Children.Add($ex)
    return $card.Frame
}

function New-IgwtGuiHistoryStepRow {
    <# .SYNOPSIS One row of a card: setting, values, and a status word (or the column header). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([string]$Setting, [string]$Values, [string]$Status, [string]$Tone = 'Neutral', [switch]$Header)
    $g = New-Object System.Windows.Controls.Grid
    $g.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
    foreach ($w in '2*', '2*', '160') { $cd = New-Object System.Windows.Controls.ColumnDefinition; $cd.Width = (New-Object System.Windows.GridLengthConverter).ConvertFromString($w); $g.ColumnDefinitions.Add($cd) }
    $a = New-IgwtUiText -Text $Setting -Style $(if ($Header) { 'TextCaption' } else { 'TextBodyStrong' }) -Brush $(if ($Header) { 'BrushTextMuted' } else { '' })
    $b = New-IgwtUiText -Text $Values -Style $(if ($Header) { 'TextCaption' } else { 'TextValue' }) -Brush 'BrushTextMuted'
    foreach ($x in $a, $b) { $x.TextTrimming = 'CharacterEllipsis'; $x.Margin = [System.Windows.Thickness]::new(0, 0, 12, 0); $x.VerticalAlignment = 'Center' }
    $b.ToolTip = $Values
    [System.Windows.Controls.Grid]::SetColumn($b, 1)
    $null = $g.Children.Add($a); $null = $g.Children.Add($b)
    $s = $(if ($Header) { New-IgwtUiText -Text $Status -Style 'TextCaption' -Brush 'BrushTextMuted' } else { New-IgwtPill -Text $Status -Tone $Tone })
    $s.HorizontalAlignment = 'Left'; $s.VerticalAlignment = 'Center'
    [System.Windows.Controls.Grid]::SetColumn($s, 2)
    $null = $g.Children.Add($s)
    if (-not $Header) { $null = Set-IgwtUiName -Element $g -Name "$Setting. $Values. $Status" }
    return $g
}

function Add-IgwtGuiHistoryPlanView {
    <#
    .SYNOPSIS
        The undo plan inside a card: each value with its state now; a value changed since iG set it
        gets its three choices in place; then the summary, Undo (enabled once every choice is made)
        and Cancel.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window elements only; the change runs from its Undo button.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Panel, [hashtable]$Names = @{}, [string]$ObjectName = '')
    $h = Get-IgwtGuiHistoryState
    if ($null -eq $h.Plan) {
        $w = New-IgwtUiText -Text 'Comparing each value with the value now (read-only)...' -Style 'TextBody' -Brush 'BrushTextMuted'
        $w.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0); $null = $Panel.Children.Add($w)
        $x = New-IgwtUiButton -Text 'Cancel' -Kind Subtle -ObjectName "undo of $ObjectName"; $x.HorizontalAlignment = 'Left'; $x.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)
        Register-IgwtGuiHandler -Control $x -Event 'Click' -Handler { Close-IgwtGuiHistoryUndo }
        $null = $Panel.Children.Add($x)
        return
    }
    $plan = @($h.Plan)
    $sep = New-Object System.Windows.Controls.Border; $sep.Height = 1; $sep.Margin = [System.Windows.Thickness]::new(0, 12, 0, 4); $sep.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'BrushBorder')
    $null = $Panel.Children.Add($sep)
    if (-not $plan.Count) { $null = $Panel.Children.Add((New-IgwtUiText -Text 'Nothing to undo: no change of this session is still in place.' -Style 'TextBody' -Brush 'BrushTextMuted')) }
    else { $null = $Panel.Children.Add((New-IgwtGuiHistoryStepRow -Setting 'Setting' -Values 'Before  >  set by iG' -Status 'Now' -Header)) }
    foreach ($p in $plan) {
        $name = Get-IgwtGuiHistoryItemName -Item ([string]$p.Item) -Names $Names
        $before = Format-IgwtJournalValue -Value $p.Before -Max 60
        $vals = "{0}  >  {1}" -f $before, (Format-IgwtJournalValue -Value $p.WeSet -Max 60)
        $word = switch ([string]$p.Status) { 'Ready' { @('Will be put back', 'Info') } 'Conflict' { @('Changed since', 'Warning') } 'Already' { @('Already back', 'Neutral') } 'Refused' { @('Cannot be undone', 'Neutral') } default { @([string]$p.Status, 'Neutral') } }
        $row = New-IgwtGuiHistoryStepRow -Setting $name -Values $vals -Status $word[0] -Tone $word[1]
        if ($p.Message -and [string]$p.Status -ne 'Conflict') { $row.ToolTip = [string]$p.Message }
        $null = $Panel.Children.Add($row)
        if ([string]$p.Status -ne 'Conflict') { continue }
        # The choice, in the row (mockup 3); the chosen one is the accent button.
        $box = New-Object System.Windows.Controls.Border
        $box.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'BrushWarningSoft')
        $box.CornerRadius = [System.Windows.CornerRadius]::new(6); $box.Padding = [System.Windows.Thickness]::new(12, 8, 12, 8); $box.Margin = [System.Windows.Thickness]::new(0, 6, 0, 6)
        $dp = New-Object System.Windows.Controls.DockPanel
        $now = Format-IgwtJournalValue -Value $p.Now -Max 40
        if (-not $now) { $now = 'unknown' }
        $chosen = $(if ($h.Decisions.ContainsKey([string]$p.Key)) { [string]$h.Decisions[[string]$p.Key] } else { '' })
        $btns = New-Object System.Windows.Controls.WrapPanel
        [System.Windows.Controls.DockPanel]::SetDock($btns, 'Right')
        foreach ($o in @(@('Keep', "Keep $now"), @('Restore', "Put back $before"), @('Skip', 'Skip'))) {
            $b = New-IgwtUiButton -Text $o[1] -Kind $(if ($chosen -eq $o[0]) { 'Primary' } else { 'Secondary' }) -ObjectName "($name)"
            $b.Tag = "$($o[0])|$([string]$p.Key)"; $b.Margin = [System.Windows.Thickness]::new(8, 0, 0, 0)
            [System.Windows.Automation.AutomationProperties]::SetItemStatus($b, $(if ($chosen -eq $o[0]) { 'Chosen' } else { '' }))
            Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { param($s, $e) $parts = ([string]$s.Tag) -split '\|', 2; Set-IgwtGuiHistoryDecision -Key $parts[1] -Choice $parts[0] }
            $null = $btns.Children.Add($b)
        }
        $null = $dp.Children.Add($btns)
        $q = New-IgwtUiText -Text "Now ${now}: something else changed it after iG set it. If you undo, what should happen to it?" -Style 'TextBody'
        $q.VerticalAlignment = 'Center'; $null = $dp.Children.Add($q)
        $box.Child = $dp
        $null = $Panel.Children.Add($box)
    }
    $st = Get-IgwtGuiHistoryPlanState -Plan $plan -Decisions $h.Decisions
    $foot = New-Object System.Windows.Controls.DockPanel; $foot.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
    $acts = New-Object System.Windows.Controls.StackPanel; $acts.Orientation = 'Horizontal'
    [System.Windows.Controls.DockPanel]::SetDock($acts, 'Right')
    $go = New-IgwtUiButton -Text $st.ConfirmText -Kind Primary -ObjectName $ObjectName
    $go.IsEnabled = $st.CanConfirm -and [bool]$script:Gui.IsAdmin -and -not $script:Gui.Job
    Register-IgwtGuiHandler -Control $go -Event 'Click' -Handler { Invoke-IgwtGuiHistoryUndo }
    $cancel = New-IgwtUiButton -Text 'Cancel' -Kind Subtle -ObjectName "undo of $ObjectName"; $cancel.Margin = [System.Windows.Thickness]::new(8, 0, 0, 0)
    Register-IgwtGuiHandler -Control $cancel -Event 'Click' -Handler { Close-IgwtGuiHistoryUndo }
    $null = $acts.Children.Add($go); $null = $acts.Children.Add($cancel)
    $null = $foot.Children.Add($acts)
    $sum = New-IgwtUiText -Text $st.Summary -Style 'TextBody' -Brush 'BrushTextMuted'; $sum.VerticalAlignment = 'Center'; $sum.Margin = [System.Windows.Thickness]::new(0, 0, 12, 0)
    [System.Windows.Automation.AutomationProperties]::SetLiveSetting($sum, [System.Windows.Automation.AutomationLiveSetting]::Polite)
    $null = $foot.Children.Add($sum)
    $null = $Panel.Children.Add($foot)
}

#endregion
