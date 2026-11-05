# JournalPage.ps1
# Backups & Logs > Change journal (3.6, DECISIONS T5): the journal as a timeline grouped by
# session, with filters and reverts per change, per session or for everything. The page reads with
# Get-IgwtJournalTimeline and Get-IgwtRevertPlan and changes only through Invoke-IgwtJournalRevert,
# all in the worker. Handlers use $script:Gui state, never closures (DECISIONS U9).

function New-IgwtGuiJournalRow {
    <# .SYNOPSIS SmartGrid row for one journal step. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param($Step)
    $when = ''
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Step.When, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) { $when = $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') }
    $origin = switch ([string]$Step.Origin) {
        'tweak' { 'Tweaks' } 'preset' { 'Preset' } 'resetDefault' { 'Reset to default' } 'forensic' { 'Forensic logging' } 'revert' { 'Revert' }
        'recovery' { 'Recovery' } 'upgrade' { 'Imported (3.x)' } 'module' { 'Module' } default { [string]$Step.Origin }
    }
    $what = $(if ($Step.Op -eq 'restore') { 'Restored' } else { 'Changed' })
    $text = switch ([string]$Step.Result) {
        'Committed' { $(if ($Step.InEffect) { "$what (in effect)" } else { $what }) }
        'Failed' { 'Failed' } 'RolledBack' { 'Rolled back' } 'RollbackFailed' { 'Rollback failed' } 'InDoubt' { 'Unfinished' } default { [string]$Step.Result }
    }
    $tone = switch ([string]$Step.Result) { 'Committed' { $(if ($Step.InEffect) { 'Info' } else { 'Pass' }) } 'RolledBack' { 'Muted' } 'Failed' { 'Fail' } 'RollbackFailed' { 'Fail' } 'InDoubt' { 'Warn' } default { 'Muted' } }
    $r = [ordered]@{
        Key = [string]$Step.Key; When = $when; Session = [string]$Step.Session; SessionTitle = [string]$Step.SessionTitle; OriginText = $origin; Item = [string]$Step.Item
        Before = [string]$Step.Before; After = [string]$Step.After; Detail = $(if ($Step.Error) { [string]$Step.Error } elseif ($Step.OneWay) { 'One-way: cannot be undone.' } else { '' })
        Target = [string]$Step.Target; EntryId = [string]$Step.EntryId; InEffect = [bool]$Step.InEffect; OneWay = [bool]$Step.OneWay; ResultKey = [string]$Step.Result; Step = [int]$Step.Step
        Tip = "$($Step.SessionTitle)`n$($Step.Target)"
    }
    Add-IgwtGuiStatusField -Row $r -Name 'ResultCol' -Text $text -Tone $tone
    [pscustomobject]$r
}

function Initialize-IgwtGuiJournalGrid {
    <# .SYNOPSIS Builds the Change journal grid (timeline grouped by session through the session column and sort). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $g = New-IgwtSmartGrid -Id 'backups.journal' -Noun 'changes' -RowKey 'Key' -SearchPlaceholder 'Search items, sessions and values' -SelectionMode Single `
        -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiJournalLoad } -OnSelectionChanged { param($grid, $rows) $null = $grid, $rows; Update-IgwtGuiJournalButtons } `
        -EmptyTitle 'No changes recorded yet' -EmptyText 'Every change iG makes is recorded here before it is made, with the value before and the value set.' -Columns @(
        @{ Key = 'When'; Header = 'Session started'; Width = 150; Kind = 'Date' }
        @{ Key = 'SessionTitle'; Header = 'Session'; Width = 230; Tip = 'Tip' }
        @{ Key = 'OriginText'; Header = 'Origin'; Width = 120 }
        @{ Key = 'Item'; Header = 'Item'; Width = 200; Tip = 'Tip' }
        @{ Key = 'ResultCol'; Header = 'Result'; Width = 175; Template = 'Status' }
        @{ Key = 'Before'; Header = 'Before'; MinWidth = 120; Template = 'Mono' }
        @{ Key = 'After'; Header = 'Set to'; MinWidth = 120; Template = 'Mono' }
        @{ Key = 'Detail'; Header = 'Detail'; MinWidth = 160 }
        @{ Key = 'Target'; Header = 'Target'; Width = 260; Template = 'Mono'; Visible = $false }
    ) -Chips @(
        @{ Id = 'effect'; Label = 'In effect'; Group = 'state'; Test = { param($row) [bool]$row.InEffect } }
        @{ Id = 'failed'; Label = 'Failed or unfinished'; Group = 'state'; Test = { param($row) [string]$row.ResultKey -in 'Failed', 'RollbackFailed', 'InDoubt' } }
        @{ Id = 'tweaks'; Label = 'Tweaks and presets'; Group = 'origin'; Field = 'OriginText'; Values = @('Tweaks', 'Preset', 'Reset to default', 'Imported (3.x)') }
        @{ Id = 'module'; Label = 'Security and system'; Group = 'origin'; Field = 'OriginText'; Values = @('Module', 'Forensic logging') }
        @{ Id = 'revert'; Label = 'Reverts'; Group = 'origin'; Field = 'OriginText'; Values = @('Revert', 'Recovery') }
        @{ Id = 'week'; Label = 'Last 7 days'; Group = 'age'; Test = { param($row) $dt = [datetime]::MinValue; [datetime]::TryParse([string]$row.When, [ref]$dt) -and $dt -ge (Get-Date).AddDays(-7) } }
    )
    Add-IgwtGuiListGrid -Name 'JournalList' -Grid $g -SortBy 'When', 'Key' -Descending
}

function Set-IgwtGuiJournal {
    <# .SYNOPSIS Fills the Change journal tab from a Get-IgwtJournalTimeline result. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Timeline)
    $c = $script:Gui.C
    $script:Gui.Journal = $Timeline
    $rows = @($Timeline.Rows | Where-Object { $_ })
    Set-IgwtGuiGridRows -Name 'JournalList' -Rows @($rows | ForEach-Object { New-IgwtGuiJournalRow -Step $_ })
    $inEffect = @($rows | Where-Object { $_.InEffect }).Count
    $c.JournalStatusText.Text = switch ([string]$Timeline.Status) {
        'Empty' { 'No changes recorded yet. The journal starts with the first change.' }
        'Broken' { "The journal failed its integrity check and is read-only, so no change runs: $($Timeline.Reason)" }
        default { "$($Timeline.Sessions) session(s), $($rows.Count) change(s); $inEffect still in effect. Integrity check passed ($($Timeline.Count) entries)." }
    }
    Update-IgwtGuiJournalButtons
}

function Update-IgwtGuiJournalButtons {
    <# .SYNOPSIS Enables the journal revert buttons for an administrator, an idle window and a revertible selection. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if (-not $c -or -not $c.JournalRevertAllButton) { return }
    $ok = [bool]$script:Gui.IsAdmin -and -not $script:Gui.Job -and $script:Gui.Journal -and [string]$script:Gui.Journal.Status -eq 'Ok'
    $sel = Get-IgwtGuiGridItem -Name JournalList
    $c.JournalRevertEntryButton.IsEnabled = $ok -and $sel -and $sel.InEffect -and -not $sel.OneWay
    $c.JournalRevertSessionButton.IsEnabled = $ok -and $sel
    # From the engine's count, which also covers changes folded into the checkpoint (review 3.6 R18).
    $c.JournalRevertAllButton.IsEnabled = $ok -and [int]$script:Gui.Journal.Tracked -gt 0
    # The way out of a journal that failed its check, shown only then.
    $broken = ($script:Gui.Journal -and [string]$script:Gui.Journal.Status -eq 'Broken')
    $c.JournalResetButton.Visibility = $(if ($broken) { 'Visible' } else { 'Collapsed' })
    $c.JournalResetButton.IsEnabled = $broken -and [bool]$script:Gui.IsAdmin -and -not $script:Gui.Job
}

function Start-IgwtGuiJournalLoad {
    <# .SYNOPSIS Reads and verifies the change journal in the background (read-only) into the Change journal tab. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $grid = $script:Gui.Grids.JournalList
    if (-not $grid) { return }
    Set-IgwtGridState -Grid $grid -State Loading
    $null = Start-IgwtGuiJob -Command 'Get-IgwtJournalTimeline' -Channel 'journal' -BusyText 'Reading the change journal...' -OnComplete {
        param($out, $errs)
        $t = @($out | Where-Object { $_ }) | Select-Object -Last 1
        if (-not $t) { Set-IgwtGridState -Grid $script:Gui.Grids.JournalList -State Error -Message $(if (@($errs).Count) { [string]@($errs)[0] } else { 'The change journal could not be read.' }); return }
        Set-IgwtGuiJournal -Timeline $t
    }
}

function Start-IgwtGuiJournalReset {
    <# .SYNOPSIS After a confirmation, sets a journal that failed its check aside in the worker (nothing is deleted). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs only after the user confirms; changes the tool''s own journal folder.')]
    [CmdletBinding()]
    param()
    $why = $(if ($script:Gui.Journal) { [string]$script:Gui.Journal.Reason } else { '' })
    if ((Show-IgwtGuiMessage -Title 'Set the change journal aside' -Buttons 'YesNo' -Icon 'Warning' -Text "$why`n`nThe journal is moved aside and kept (nothing is deleted), and the next change starts a new one. The history in it can then no longer be reverted from this tab; the 3.x snapshots are imported again. Continue?") -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Reset-IgwtChangeJournal' -Parameters @{ Confirm = $false } -Blocking -BusyText 'Setting the change journal aside...' -OnComplete {
        param($out, $errs)
        $r = @($out | Where-Object { $_ }) | Select-Object -Last 1
        if ($r) { Set-IgwtGuiStatus "The change journal was set aside: $($r.SetAside)" }
        elseif (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "Not set aside: $(@($errs)[0])" -Icon 'Error' }
        Start-IgwtGuiJournalLoad
        Start-IgwtGuiHomeCard
    }
}

function Start-IgwtGuiJournalRevert {
    <#
    .SYNOPSIS
        Builds a revert plan in the worker (read-only) for the selected change (Entry), its session
        (Session) or everything iG changed (All), then shows the preview (Show-IgwtGuiJournalPlan).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query; the change runs after the confirmed preview.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Entry', 'Session', 'All')][string]$Scope)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text (Get-IgwtGuiChangeBlockReason -What 'revert changes'); return }
    $sel = Get-IgwtGuiGridItem -Name JournalList
    $p = @{}; $title = 'Reset everything iG changed'
    if ($Scope -eq 'Entry') { if (-not $sel -or -not $sel.EntryId) { Set-IgwtGuiStatus 'Select a change first.'; return }; $p.EntryId = $sel.EntryId; $title = "Revert: $($sel.Item)" }
    elseif ($Scope -eq 'Session') { if (-not $sel) { Set-IgwtGuiStatus 'Select a change of the session first.'; return }; $p.SessionId = $sel.Session; $title = "Revert session: $($sel.SessionTitle)" }
    else { $p.All = $true }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtRevertPlan' -Parameters $p -Channel 'journalplan' -BusyText 'Comparing the journal with the values now...' -Context @{ Title = $title } -OnComplete {
        param($out, $errs, $ctx)
        if (@($errs).Count -and -not @($out).Count) { $null = Show-IgwtGuiMessage -Text "The revert preview failed: $(@($errs)[0])" -Icon 'Error'; return }
        Show-IgwtGuiJournalPlan -Plan @($out | Where-Object { $_ }) -Title $ctx.Title
    }
}

function Format-IgwtGuiJournalPlan {
    <# .SYNOPSIS The revert preview text: per value the status, value before, value iG set and value now. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([object[]]$Plan)
    $nl = [Environment]::NewLine
    $lines = New-Object System.Collections.Generic.List[string]
    $ready = @($Plan | Where-Object Status -EQ 'Ready').Count; $conf = @($Plan | Where-Object Status -EQ 'Conflict').Count
    $lines.Add("$ready value(s) will be restored; $conf changed since iG set them (you choose); $(@($Plan).Count - $ready - $conf) unchanged or refused.")
    $lines.Add('')
    foreach ($p in $Plan) {
        $lines.Add(('{0,-9} {1}' -f $p.Status, $p.Item))
        $lines.Add("          before:  $(Format-IgwtJournalValue $p.Before)")
        $lines.Add("          iG set:  $(Format-IgwtJournalValue $p.WeSet)")
        if ($null -ne $p.Now) { $lines.Add("          now:     $(Format-IgwtJournalValue $p.Now)") }
        if ($p.Message) { $lines.Add("          $($p.Message)") }
    }
    return ($lines -join $nl)
}

function Show-IgwtGuiJournalPlan {
    <#
    .SYNOPSIS
        Shows the revert preview; on confirmation asks for each conflict (restore anyway, keep the
        current value, skip) and runs the revert as one journaled session in the worker.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The change runs only after the user confirms the preview.')]
    [CmdletBinding()]
    param([object[]]$Plan, [string]$Title)
    if (-not @($Plan).Count) { $null = Show-IgwtGuiMessage -Text 'Nothing to revert: no change of this selection is still in effect.'; return }
    $todo = @($Plan | Where-Object { $_.Status -in 'Ready', 'Conflict' })
    $text = Format-IgwtGuiJournalPlan -Plan $Plan
    if (-not $todo.Count) { $null = Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $Title" -Text $text; return }
    if (-not (Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $Title" -Text $text -AcceptText 'Revert...' -CancelText 'Cancel')) { return }
    $decisions = @{}
    foreach ($p in @($todo | Where-Object Status -EQ 'Conflict')) {
        $ans = Show-IgwtGuiMessage -Title 'Changed since iG set it' -Buttons 'YesNoCancel' -Icon 'Question' -Text ("{0}`n`nBefore: {1}`niG set: {2}`nNow: {3}`n`nYes: restore the value before anyway. No: keep the current value (iG stops tracking it). Cancel: skip it." -f $p.Item, (Format-IgwtJournalValue $p.Before), (Format-IgwtJournalValue $p.WeSet), (Format-IgwtJournalValue $p.Now))
        $decisions[[string]$p.Key] = switch ($ans) { 'Yes' { 'Restore' } 'No' { 'Keep' } default { 'Skip' } }
    }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtJournalRevert' -Parameters @{ Plan = $Plan; Decisions = $decisions; Title = $Title; Confirm = $false } -Blocking -BusyText 'Reverting from the change journal...' -OnComplete {
        param($out, $errs)
        $r = @($out | Where-Object { $_ }) | Select-Object -Last 1
        if ($r) {
            $lines = @($r.Results | ForEach-Object { '{0,-13} {1}  {2}' -f $_.Result, $_.Item, $_.Message })
            $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - revert result' -Text ($lines -join [Environment]::NewLine)
        } elseif (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "Revert failed: $(@($errs)[0])" -Icon 'Error' }
        Start-IgwtGuiJournalLoad
        Start-IgwtGuiRefresh
    }
}
