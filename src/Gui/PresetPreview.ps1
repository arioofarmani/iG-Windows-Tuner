# PresetPreview.ps1
# Preset preview (3.6, DECISIONS T16): before a preset's changes are staged, the window shows what
# applying it would do on this PC (will change, already set, not applicable, conflict, managed by
# policy) with a one-line summary. The preview runs in the worker over the states the window
# already has; nothing is staged until the user accepts it, and nothing changes until Apply.
# Handlers use $script:Gui state and the job context, never closures (DECISIONS U9).

function Format-IgwtGuiPresetPreview {
    <# .SYNOPSIS The preview text: summary, then the rows grouped by class. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Preview)
    $nl = [Environment]::NewLine
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($Preview.Name): $($Preview.Summary)")
    if ($Preview.Notes) { $lines.Add($Preview.Notes) }
    foreach ($f in @($Preview.FeatureConflicts)) { $lines.Add("Note: $f") }
    foreach ($cls in @(@('WillChange', 'Will change'), @('Conflict', 'Conflict'), @('ManagedByPolicy', 'Managed by policy'), @('NotApplicable', 'Not applicable'), @('AlreadySet', 'Already set'))) {
        $rows = @($Preview.Rows | Where-Object { $_.Class -eq $cls[0] })
        if (-not $rows.Count) { continue }
        $lines.Add(''); $lines.Add("$($cls[1]) ($($rows.Count))")
        foreach ($r in $rows) { $lines.Add(('  {0,-40} {1}{2}' -f $r.Id, $(if ($r.Desired -eq 'default') { '[reset to default] ' } else { '' }), $r.Reason).TrimEnd()) }
    }
    return ($lines -join $nl)
}

function Start-IgwtGuiPresetPreview {
    <# .SYNOPSIS Computes a preset's preview in the worker, then shows it (Show-IgwtGuiPresetPreview). Read-only. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only preview; staging follows only when the user accepts it.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset)
    $p = @{ Preset = [string]$Preset.id }
    if ($script:Gui.Data -and $script:Gui.Data.States) { $p.States = $script:Gui.Data.States }
    $started = Start-IgwtGuiJob -Command 'Get-IgwtPresetPreview' -Parameters $p -Channel 'presetpreview' -BusyText "Previewing the $($Preset.name) preset..." -Context @{ Preset = $Preset } -OnComplete {
        param($out, $errs, $ctx)
        $pv = @($out | Where-Object { $_ }) | Select-Object -Last 1
        if (-not $pv) { $null = Show-IgwtGuiMessage -Text "The preview failed: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })" -Icon 'Error'; return }
        Show-IgwtGuiPresetPreview -Preset $ctx.Preset -Preview $pv
    }
    # No worker (offscreen render): preview in place.
    if (-not $started -and -not $script:Gui.Runspace) { Show-IgwtGuiPresetPreview -Preset $Preset -Preview (Get-IgwtPresetPreview @p) }
}

function Show-IgwtGuiPresetPreview {
    <# .SYNOPSIS Shows the preview; on acceptance stages the items that will change (on, or reset to the Windows default). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Stages changes in the window only; Apply runs them after its own confirmation.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [Parameter(Mandatory = $true)]$Preview)
    $todo = @($Preview.Rows | Where-Object { $_.Class -eq 'WillChange' })
    $text = Format-IgwtGuiPresetPreview -Preview $Preview
    if ($Preview.Requirement -or -not $todo.Count) {
        $null = Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $($Preset.name) preview" -Text $text
        Set-IgwtGuiStatus $(if ($Preview.Requirement) { "$($Preset.name) does not apply to this PC: $($Preview.Requirement)" } else { "Nothing to change: $($Preset.name) is already applied." })
        return
    }
    if (-not (Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $($Preset.name) preview" -Text $text -AcceptText "Stage $(Format-IgwtCount -Count ($todo.Count) -Noun 'change')" -CancelText 'Cancel')) { return }
    # The staged list must not change under an Apply that is on its way (review 3.8.1 G-05).
    if (-not (Test-IgwtGuiCanRestage)) { return }
    if (-not (Confirm-IgwtGuiReplaceStaged -What "The $($Preset.name) preset")) { return }
    $script:Gui.Staged.Clear()
    foreach ($r in $todo) { Set-IgwtGuiStage -Id ([string]$r.Id) -Mode $(if ($r.Desired -eq 'default') { 'reset' } else { 'on' }) }
    Set-IgwtGuiPresetOperation -Name "Preset:$($Preset.id)"
    Update-IgwtGuiPending
    Set-IgwtGuiStatus "Staged $(Format-IgwtCount -Count ($todo.Count) -Noun 'change') from the $($Preset.name) preset ($($Preview.Summary)) Review them on the category pages (marked 'Pending'), then Preview or Apply."
}

function Get-IgwtGuiStagedKey {
    <# .SYNOPSIS The staged list as one sorted text (id=mode|...), to tell whether it changed. Pure over the window state. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (@($script:Gui.Staged.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $script:Gui.Staged[$_] }) -join '|')
}

function Set-IgwtGuiPresetOperation {
    <#
    .SYNOPSIS
        Names the session the staged list belongs to (a preset, a drift fix, the network test) and remembers that
        exact list: Apply uses the name only while the staged list is unchanged (review 3.8.1 HC-1).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $script:Gui.PresetOperation = $Name
    $script:Gui.PresetOperationKey = Get-IgwtGuiStagedKey
}

function Confirm-IgwtGuiReplaceStaged {
    <# .SYNOPSIS Asks before a preset or drift fix replaces changes the user staged by hand; true when nothing is staged or the user agrees (review 3.8.1 HC-1, PV-1). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$What)
    $n = @($script:Gui.Staged.Keys).Count
    if (-not $n) { return $true }
    $a = Show-IgwtGuiMessage -Text "$n staged change$(if ($n -ne 1) { 's are' } else { ' is' }) waiting to be applied. $What replaces $(if ($n -ne 1) { 'them' } else { 'it' }).`n`nOK: replace the staged changes.`nCancel: keep them and stop." -Buttons 'OKCancel' -Icon 'Question'
    return ($a -eq 'OK')
}