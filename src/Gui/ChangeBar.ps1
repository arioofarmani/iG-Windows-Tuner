# ChangeBar.ps1
# 4.0 section 2 (C3): the one apply path of the window. The bottom bar (ChangeBar style) shows what is
# staged, announces the count to screen readers, and offers Discard, Preview and Apply. These helpers
# hold the apply state so that a second Apply, a staging change or another change cannot run into an
# apply that is still on its way (review 3.8.1 G-04 to G-07). Nothing here changes the PC: the batch
# runs in the worker through the exported Invoke-IgwtGuiBatch.

function Test-IgwtGuiApplyBusy {
    <#
    .SYNOPSIS
        True while a foreground job runs or an Apply is on its way (from the user's Yes until its
        batch finishes, including the System Protection check and the restore point question).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ([bool]$script:Gui.Job -or [bool]$script:Gui.ApplyPending)
}

function Set-IgwtGuiApplyPending {
    <# .SYNOPSIS Marks an Apply as on its way (or done) and refreshes the buttons. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$Pending)
    $script:Gui.ApplyPending = $Pending
    if ($script:Gui.C -and $script:Gui.C.ApplyButton) { Update-IgwtGuiButtons }
}

function Remove-IgwtGuiStagedIds {
    <#
    .SYNOPSIS
        Removes from the staged list only the ids a finished batch handled (its Apply, Off and Reset
        sets). Changes staged while the batch ran stay staged (review 3.8.1 G-05). Returns how many
        stay.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)]$Sets)
    foreach ($k in @(@($Sets.Apply) + @($Sets.Off) + @($Sets.Reset) | Where-Object { $_ })) { $null = $script:Gui.Staged.Remove([string]$k) }
    return @($script:Gui.Staged.Keys).Count
}

function Show-IgwtGuiNotStarted {
    <#
    .SYNOPSIS
        Tells the user that a change they confirmed did not start because another change is still
        running (review 3.8.1 G-07): a dialog, not only the status line.
    #>
    [CmdletBinding()]
    param([string]$What = 'This change')
    $null = Show-IgwtGuiMessage -Text "$What did not start: another change is still running. Nothing was changed.`n`nTry again when it finishes." -Icon 'Warning'
}

function Test-IgwtGuiCanRestage {
    <#
    .SYNOPSIS
        False (with a status line) while an Apply is on its way: presets and the drift fix replace the
        staged list, which must not change under a running Apply.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (Test-IgwtGuiApplyBusy) { Set-IgwtGuiStatus 'Wait until the current change finishes, then try again.'; return $false }
    return $true
}

function Update-IgwtGuiChangeBarText {
    <#
    .SYNOPSIS
        The ChangeBar's count line, also its screen-reader name (a polite live region announces it):
        "3 changes ready" or "Nothing staged".
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window text only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Count, $Target, [string]$Text)
    $text = $(if ($Text) { $Text } elseif ($Count -eq 0) { 'Nothing staged' } elseif ($Count -eq 1) { '1 change ready' } else { "$Count changes ready" })
    if ($Target) {
        $Target.Text = $text
        [System.Windows.Automation.AutomationProperties]::SetName($Target, $text)
        $peer = [System.Windows.Automation.Peers.UIElementAutomationPeer]::FromElement($Target)
        if ($peer) { $peer.RaiseAutomationEvent([System.Windows.Automation.Peers.AutomationEvents]::LiveRegionChanged) }
    }
    return $text
}
