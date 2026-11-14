# StartupPage.ps1
# Startup apps page actions (DECISIONS SA7): turn on, turn off, delete with a backup, open the file
# location, copy the command, and the details line of the selected entry. The engine work runs in
# the worker (Set-IgwtStartupItemEnabled, Get-IgwtStartupRemovePlan, Remove-IgwtStartupItem); a
# delete is undone from its toast or from Backups & Logs. No scriptblock here is a closure (U9).

function Get-IgwtGuiStartupActions {
    <# .SYNOPSIS The Startup grid's row actions (toolbar, bulk bar and right-click menu). #>
    [CmdletBinding()]
    param()
    @(
        @{ Id = 'on'; Label = 'Turn on'; Bulk = $true; Changes = $true; Tip = 'Start the selected entries with Windows again.'
            CanRun = { param($r) if (@($r | Where-Object { -not $_.Enabled }).Count) { '' } else { 'The selected entries are already on.' } }
            Run = { param($r) Invoke-IgwtGuiStartupToggle -Rows $r -Enabled $true } }
        @{ Id = 'off'; Label = 'Turn off'; Bulk = $true; Changes = $true; Tip = 'Stop the selected entries from starting with Windows (like Task Manager; nothing is deleted).'
            CanRun = { param($r) if (@($r | Where-Object { $_.Enabled }).Count) { '' } else { 'The selected entries are already off.' } }
            Run = { param($r) Invoke-IgwtGuiStartupToggle -Rows $r -Enabled $false } }
        @{ Id = 'delete'; Label = 'Delete...'; Bulk = $true; Danger = $true; Changes = $true; Tip = 'Delete the selected entries. A backup is made first; Undo or Backups & Logs restores them.'
            CanRun = { param($r) if (@($r | Where-Object { -not $_.DeleteBlock }).Count) { '' } else { [string]@($r)[0].DeleteBlock } }
            Run = { param($r) Invoke-IgwtGuiStartupDelete -Rows $r } }
        @{ Id = 'open'; Label = 'Open file location'; Tip = 'Show the file in File Explorer (it is not started).'
            CanRun = { param($r) if ([bool]@($r)[0].TargetExists) { '' } else { 'The file is missing or could not be found.' } }
            Run = { param($r) Show-IgwtGuiInExplorer -Path ([string]@($r)[0].Target) -Confirm:$false } }
        @{ Id = 'copy'; Label = 'Copy command'; Bulk = $true; Tip = 'Copy the command lines of the selected entries.'
            Run = { param($r) Copy-IgwtGuiStartupCommand -Rows $r } }
    )
}

function Copy-IgwtGuiStartupCommand {
    <# .SYNOPSIS Copies the command lines of the given rows to the clipboard. #>
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $text = (@($Rows | ForEach-Object { [string]$_.Command }) -join [Environment]::NewLine)
    try { [System.Windows.Clipboard]::SetText($text); Set-IgwtGuiStatus "$(@($Rows).Count) command(s) copied." } catch { Set-IgwtGuiStatus 'The clipboard is not available.' }
}

function Invoke-IgwtGuiStartupToggle {
    <# .SYNOPSIS Turns the given entries on or off, one worker job after the other, then refreshes. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts worker jobs; Set-IgwtStartupItemEnabled snapshots each change.')]
    [CmdletBinding()]
    param([object[]]$Rows = @(), [bool]$Enabled)
    $queue = @($Rows | Where-Object { $_ -and [bool]$_.Enabled -ne $Enabled } | ForEach-Object { @{ Scope = [string]$_.Scope; Name = [string]$_.Name; Enabled = $Enabled } })
    if (-not $queue.Count) { return }
    Start-IgwtGuiStartupToggleNext -Queue $queue -Index 0 -Errors @()
}

function Start-IgwtGuiStartupToggleNext {
    <# .SYNOPSIS Runs one toggle job of the queue; its completion starts the next one. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a worker job.')]
    [CmdletBinding()]
    param([object[]]$Queue, [int]$Index, [object[]]$Errors = @())
    if ($Index -ge $Queue.Count) {
        if ($Errors.Count) { $null = Show-IgwtGuiMessage -Text "Some entries were not changed:`n$($Errors -join "`n")" -Icon 'Error' }
        else { Set-IgwtGuiStatus "$($Queue.Count) startup entr$(if ($Queue.Count -eq 1) { 'y' } else { 'ies' }) turned $(if ($Queue[0].Enabled) { 'on' } else { 'off' }) (snapshot written)." }
        Start-IgwtGuiRefresh
        return
    }
    $q = $Queue[$Index]
    $null = Start-IgwtGuiJob -Command 'Set-IgwtStartupItemEnabled' -Parameters $q -Blocking -BusyText "$(if ($q.Enabled) { 'Turning on' } else { 'Turning off' }) $($q.Name)..." -Context @{ Queue = $Queue; Index = $Index; Errors = $Errors } -OnComplete {
        param($out, $errs, $ctx)
        $null = $out
        $e = @($ctx.Errors)
        if (@($errs).Count) { $e += "$($ctx.Queue[$ctx.Index].Name): $(@($errs)[0])" }
        Start-IgwtGuiStartupToggleNext -Queue $ctx.Queue -Index ($ctx.Index + 1) -Errors $e
    }
}

function Invoke-IgwtGuiStartupDelete {
    <#
    .SYNOPSIS
        Delete (DECISIONS SA7): reads the plan in the worker, shows one confirmation with the entries,
        the refused ones and the anti-cheat warning, then deletes the allowed ones in one journaled
        step and offers Undo.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Asks for confirmation; Remove-IgwtStartupItem snapshots first.')]
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $ids = @($Rows | Where-Object { $_ } | ForEach-Object { "$($_.Scope)|$($_.Name)" })
    if (-not $ids.Count) { return }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtStartupRemovePlan' -Parameters @{ Item = [string[]]$ids } -Blocking -BusyText 'Checking the startup entries...' -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The entries could not be checked: $(@($errs)[0])" -Icon 'Error'; return }
        $plan = @($out | Where-Object { $_ -and $_.PSObject.Properties['Refused'] })
        $ok = @($plan | Where-Object { -not $_.Refused })
        $text = (@(Format-IgwtStartupRemovePlan -Plan $plan) -join "`n")
        if (-not $ok.Count) { $null = Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - Startup apps' -Icon 'Warning'; return }
        $ask = "Delete $($ok.Count) startup entr$(if ($ok.Count -eq 1) { 'y' } else { 'ies' })?`n`n$text"
        if ((Show-IgwtGuiMessage -Text $ask -Title 'iG Windows Tuner - Startup apps' -Buttons 'YesNo' -Icon $(if (@($ok | Where-Object { $_.Warning }).Count) { 'Warning' } else { 'Question' })) -ne 'Yes') { return }
        $null = Start-IgwtGuiJob -Command 'Remove-IgwtStartupItem' -Parameters @{ Item = [string[]]@($ok | ForEach-Object { $_.Id }); Confirm = $false } -Blocking -BusyText 'Backing up and deleting...' -Context $ok.Count -OnComplete {
            param($out2, $errs2, $count)
            $snap = [string](@($out2) | Where-Object { $_ -is [string] } | Select-Object -Last 1)
            if (@($errs2).Count -or -not $snap) { Show-IgwtGuiError -Message "The startup entries were not deleted: $(if (@($errs2).Count) { @($errs2)[0] } else { 'no snapshot was written' })" -Context 'Startup apps' }
            else {
                Show-IgwtGuiToast -Text "$count startup entr$(if ($count -eq 1) { 'y' } else { 'ies' }) deleted. A backup was made." -Tone Success -ActionText 'Undo' -Action { param($s) Invoke-IgwtGuiSnapshotUndo -Snapshot $s -Then { Start-IgwtGuiRefresh } } -ActionArgument $snap
            }
            Start-IgwtGuiRefresh
        }
    }
}

function Update-IgwtGuiStartupDetails {
    <# .SYNOPSIS The details line and the toolbar buttons of the Startup page for the selected rows. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $c = $script:Gui.C
    $grid = $script:Gui.Grids.StartupList
    $map = @{ on = 'StartupOnButton'; off = 'StartupOffButton'; delete = 'StartupDeleteButton'; open = 'StartupOpenButton'; copy = 'StartupCopyButton' }
    foreach ($a in @($grid.Actions)) {
        $b = $c[$map[[string]$a.Id]]
        if (-not $b) { continue }
        $why = Get-IgwtGridActionBlock -Action $a -Rows @($Rows)
        $b.IsEnabled = -not $why
        $b.ToolTip = $(if ($why) { $why } else { [string]$a.Tip })
        [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($b, $true)
    }
    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 1) {
        $r = $rows[0]
        $file = $(if ($r.Target) { "$($r.Target) ($(if ($r.TargetExists) { 'exists' } elseif ($r.FileMissing) { 'missing' } else { 'not checked' }))" } else { 'not found in the command' })
        $parts = @("File: $file")
        if ($r.Company) { $parts += "Company: $($r.Company)" }
        $parts += "Entry in: $($r.Source)"
        if ($r.ProtectionReason) { $parts += [string]$r.ProtectionReason }
        $c.StartupDetailText.Text = $parts -join '   |   '
    } elseif ($rows.Count -gt 1) {
        $c.StartupDetailText.Text = "$($rows.Count) entries selected."
    } else {
        $c.StartupDetailText.Text = 'Select an entry to see its file, company and where it is registered. Right-click for all actions.'
    }
}
