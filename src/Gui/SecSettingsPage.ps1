# SecSettingsPage.ps1
# Security > Security settings (DECISIONS SM33): every security setting in one SmartGrid with
# search, source chips and "Configured only"; a detail pane with an editor built for the setting's
# value kind (validated by Test-IgwtSecSettingValue on every edit); staged changes, a preview from
# the worker, a typed confirmation for high-risk changes, and Undo through the change journal.
# Reads and writes run in the worker; no scriptblock here is a closure (U9).

function New-IgwtGuiSecSettingRow {
    <# .SYNOPSIS SmartGrid row for one security setting (Get-IgwtSecSettings row). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Setting, [hashtable]$Staged = @{})
    $s = $Setting
    $r = [ordered]@{
        Key = [string]$s.Id; Id = [string]$s.Id; Setting = $s; Name = [string]$s.Name; CategoryText = (@($s.Category) -join ' > ')
        SourceKind = [string]$s.SourceKind; SourceText = $(switch ([string]$s.SourceKind) { 'admx' { 'Group Policy' } 'defender' { 'Defender' } 'asr' { 'ASR rule' } 'exclusionList' { 'Exclusions' } 'secpolicy' { 'Security option' } 'audit' { 'Audit' } 'deviceguardState' { 'Device Guard' } default { [string]$s.SourceKind } })
        CurrentText = [string]$s.CurrentText; OriginText = [string]$s.Origin; BaselineText = $(if ($null -ne $s.Baseline) { [string](@($s.Baseline) -join ', ') } else { [string]$s.BaselineSource })
        ConfiguredKey = $(if ($s.Configured) { 'Yes' } else { 'No' }); AccessKey = $(if ($s.ReadOnly) { 'ReadOnly' } else { 'Editable' }); RiskKey = [string]$s.Risk
        StagedKey = $(if ($Staged.ContainsKey([string]$s.Id)) { 'Yes' } else { 'No' })
        Tip = $(if ($s.ReadOnly) { [string]$s.ReadOnlyReason } else { [string]$s.Explain })
    }
    $tone = $(if ($s.ReadOnly) { 'Muted' } elseif ($s.Risk -eq 'high') { 'Warning' } elseif ($s.Configured) { 'Success' } else { 'Text' })
    Add-IgwtGuiStatusField -Row $r -Name 'StateCol' -Text $(if ($s.ReadOnly) { 'Read-only' } elseif ($Staged.ContainsKey([string]$s.Id)) { 'Staged' } elseif ($s.Risk -eq 'high') { 'High risk' } elseif ($s.Configured) { 'Configured' } else { 'Not configured' }) -Tone $tone -Locked:([bool]$s.ReadOnly)
    return [pscustomobject]$r
}

function Initialize-IgwtGuiSecSettingsPage {
    <# .SYNOPSIS Builds the Security settings page: the SmartGrid 'security.settings', its chips and the button handlers. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $script:Gui.SecStaged = [ordered]@{}
    $script:Gui.SecRows = @()
    $script:Gui.SecLoaded = $false
    $chips = @(
        @{ Id = 'configured'; Label = 'Configured only'; Group = 'conf'; Field = 'ConfiguredKey'; Values = @('Yes'); Tip = 'Settings that are set on this PC' }
        @{ Id = 'editable'; Label = 'Editable'; Group = 'access'; Field = 'AccessKey'; Values = @('Editable') }
        @{ Id = 'readonly'; Label = 'Read-only'; Group = 'access'; Field = 'AccessKey'; Values = @('ReadOnly'); Tip = 'Set by a domain, MDM or Tamper Protection, or not changed by iG (the reason is in the details)' }
        @{ Id = 'staged'; Label = 'Staged'; Group = 'staged'; Field = 'StagedKey'; Values = @('Yes') }
        @{ Id = 'high'; Label = 'High risk'; Group = 'risk'; Field = 'RiskKey'; Values = @('high'); More = $true }
    )
    foreach ($k in @(@('admx', 'Group Policy'), @('defender', 'Defender'), @('asr', 'ASR rules'), @('exclusionList', 'Exclusions'), @('secpolicy', 'Security options'), @('audit', 'Audit'), @('deviceguardState', 'Device Guard'))) {
        $chips += @{ Id = "src-$($k[0])"; Label = $k[1]; Group = 'src'; Field = 'SourceKind'; Values = @($k[0]); More = $true }
    }
    $g = New-IgwtSmartGrid -Id 'security.settings' -Noun 'settings' -RowKey 'Key' -SearchPlaceholder 'Search settings, categories and explanations' -SelectionMode Single `
        -EmptyTitle 'Loading security settings' -EmptyText 'The policy definitions are read in the background (read-only).' `
        -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiSecSettingsLoad } `
        -OnSelectionChanged { param($grid, $rows) $null = $grid; Show-IgwtGuiSecSettingDetail -Row (@($rows) | Select-Object -First 1) } -Columns @(
        @{ Key = 'Name'; Header = 'Setting'; Width = 320; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'StateCol'; Header = 'State'; Width = 130; Template = 'Status'; Search = $false }
        @{ Key = 'CurrentText'; Header = 'Current'; Width = 170 }
        @{ Key = 'OriginText'; Header = 'Origin'; Width = 120 }
        @{ Key = 'BaselineText'; Header = 'Baseline'; Width = 120 }
        @{ Key = 'SourceText'; Header = 'Source'; Width = 110 }
        @{ Key = 'CategoryText'; Header = 'Category'; MinWidth = 200 }
        @{ Key = 'Id'; Header = 'Id'; Width = 260; Template = 'Mono'; Visible = $false }
    ) -Chips $chips
    Add-IgwtGuiListGrid -Name 'SecSettingsList' -Grid $g -SortBy 'CategoryText', 'Name' -Empty
    $c = $script:Gui.C
    Register-IgwtGuiHandler -Control $c.SecRefreshButton -Event 'Click' -Handler { Start-IgwtGuiSecSettingsLoad }
    Register-IgwtGuiHandler -Control $c.SecPreviewButton -Event 'Click' -Handler { Invoke-IgwtGuiSecSettingsPreview }
    Register-IgwtGuiHandler -Control $c.SecApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiSecSettingsPreview -Apply }
    Register-IgwtGuiHandler -Control $c.SecClearButton -Event 'Click' -Handler { $script:Gui.SecStaged = [ordered]@{}; Update-IgwtGuiSecStaged; Set-IgwtGuiSecSettingsRows }
    Register-IgwtGuiHandler -Control $c.SecStageButton -Event 'Click' -Handler { Add-IgwtGuiSecStagedChange }
    Update-IgwtGuiSecStaged
}

function Start-IgwtGuiSecSettingsLoad {
    <# .SYNOPSIS Reads every security setting in the worker (read-only) and fills the grid. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only worker job.')]
    [CmdletBinding()]
    param()
    $g = $script:Gui.Grids.SecSettingsList
    if ($g) { Set-IgwtGridState -Grid $g -State 'Loading' }
    $script:Gui.C.SecStatusText.Text = 'Reading the policy definitions and current values (read-only)...'
    $null = Start-IgwtGuiJob -Command 'Get-IgwtSecSettings' -Channel 'secsettings' -BusyText 'Reading security settings (read-only)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Where-Object { $_ -and $_.PSObject.Properties['Rows'] } | Select-Object -Last 1
        if (@($errs).Count -or -not $res) { Set-IgwtGuiGridRows -Name 'SecSettingsList' -ErrorText "The security settings could not be read: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })"; return }
        Set-IgwtGuiSecSettingsData -Result $res
    }
}

function Set-IgwtGuiSecSettingsData {
    <# .SYNOPSIS Stores a Get-IgwtSecSettings result and shows it (also used by the offscreen render). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result)
    $script:Gui.SecRows = @($Result.Rows)
    $script:Gui.SecLoaded = $true
    $st = $Result.Status
    $ro = @($script:Gui.SecRows | Where-Object ReadOnly).Count
    $script:Gui.C.SecStatusText.Text = ("{0} settings, {1} read-only. Edition {2}; Tamper Protection {3}; domain policy {4}{5}." -f @($script:Gui.SecRows).Count, $ro, $(if ($st.EditionFamily) { $st.EditionFamily } else { 'not recognised' }), $st.Tamper, $st.DomainPolicyRead, $(if ($st.Managed) { '; managed PC' } else { '' }))
    Set-IgwtGuiSecSettingsRows
}

function Set-IgwtGuiSecSettingsRows {
    <# .SYNOPSIS Rebuilds the grid rows (after a load or when the staged changes change). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param()
    $staged = @{}; foreach ($k in @($script:Gui.SecStaged.Keys)) { $staged[[string]$k] = $true }
    Set-IgwtGuiGridRows -Name 'SecSettingsList' -Rows @($script:Gui.SecRows | ForEach-Object { New-IgwtGuiSecSettingRow -Setting $_ -Staged $staged })
}

function New-IgwtGuiSecSettingEditor {
    <#
    .SYNOPSIS
        The editor controls for one setting's value spec (DECISIONS SM4, SM33), added to a panel.
        Returns a reader scriptblock-free description: @{ Kind; Controls } that Read-IgwtGuiSecSettingEditor
        turns back into a value. Refused choices are shown disabled with their reason.
    .PARAMETER Setting
        A Get-IgwtSecSettings row.
    .PARAMETER Panel
        The panel the controls are added to.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Setting, [Parameter(Mandatory = $true)]$Panel)
    $spec = $Setting.ValueSpec
    $editor = @{ Mode = [string]$spec.Mode; State = $null; Elements = [ordered]@{} }
    $label = { param($t) $tb = New-Object System.Windows.Controls.TextBlock; $tb.Text = $t; $tb.Margin = '0,8,0,2'; $tb.TextWrapping = 'Wrap'; $null = $Panel.Children.Add($tb) }
    $current = $Setting.Current
    if ($editor.Mode -eq 'tristate') {
        & $label 'State'
        $cb = New-Object System.Windows.Controls.ComboBox
        foreach ($s in 'NotConfigured', 'Enabled', 'Disabled') { $i = New-Object System.Windows.Controls.ComboBoxItem; $i.Content = $(if ($s -eq 'NotConfigured') { 'Not configured' } else { $s }); $i.Tag = $s; $null = $cb.Items.Add($i) }
        $cb.SelectedIndex = $(switch ([string]$Setting.State) { 'Enabled' { 1 } 'Disabled' { 2 } default { 0 } })
        [System.Windows.Automation.AutomationProperties]::SetName($cb, "State of $($Setting.Name)")
        $null = $Panel.Children.Add($cb); $editor.State = $cb
    }
    foreach ($e in @($spec.Elements)) {
        & $label $(if ($e.Unit -and $e.Kind -in 'decimal', 'longDecimal') { "$($e.Label) ($($e.Min) to $($e.Max))" } else { [string]$e.Label })
        $now = $(if ($editor.Mode -eq 'tristate') { if ($current -is [System.Collections.IDictionary] -and $current.Contains([string]$e.Id)) { $current[[string]$e.Id] } else { $e.Default } } else { $current })
        switch ([string]$e.Kind) {
            { $_ -in 'enum', 'bool' } {
                $ctl = New-Object System.Windows.Controls.ComboBox
                foreach ($ch in @($e.Choices)) {
                    $i = New-Object System.Windows.Controls.ComboBoxItem
                    $i.Content = $(if ($ch.Refused) { "$($ch.Label) (not offered)" } else { [string]$ch.Label }); $i.Tag = $ch.Value
                    if ($ch.Refused) { $i.IsEnabled = $false; $i.ToolTip = [string]$ch.Refused; [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($i, $true) }
                    $null = $ctl.Items.Add($i)
                    if ($null -ne $now -and ([string]$ch.Value -eq [string]$now -or [string]$ch.Label -eq [string]$now)) { $ctl.SelectedItem = $i }
                }
            }
            'flags' {
                $ctl = New-Object System.Windows.Controls.StackPanel
                foreach ($b in @($e.Bits)) { $x = New-Object System.Windows.Controls.CheckBox; $x.Content = [string]$b.Label; $x.Tag = $b.Value; $x.IsChecked = ($null -ne $now -and ([uint32]$now -band [uint32]$b.Value) -ne 0); $null = $ctl.Children.Add($x) }
            }
            default {
                $ctl = New-Object System.Windows.Controls.TextBox
                $multi = ([string]$e.Kind -in 'multiText', 'list', 'keyValueList')
                if ($multi) { $ctl.AcceptsReturn = $true; $ctl.MinHeight = 70; $ctl.TextWrapping = 'Wrap'; $ctl.VerticalScrollBarVisibility = 'Auto' }
                $ctl.Text = $(if ($null -eq $now) { '' } elseif ($now -is [System.Collections.IDictionary]) { (@($now.Keys | ForEach-Object { "$_=$($now[$_])" }) -join "`r`n") } elseif ($multi) { (@($now) -join "`r`n") } else { [string]$now })
                if ([string]$e.Kind -eq 'time') { $ctl.ToolTip = 'HH:mm, for example 02:30' }
            }
        }
        [System.Windows.Automation.AutomationProperties]::SetName($ctl, "$($e.Label) of $($Setting.Name)")
        $null = $Panel.Children.Add($ctl)
        $editor.Elements[[string]$e.Id] = @{ Element = $e; Control = $ctl }
    }
    return $editor
}

function Read-IgwtGuiSecSettingEditor {
    <# .SYNOPSIS The value an editor holds, in the form Test-IgwtSecSettingValue takes. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Editor)
    $vals = @{}
    foreach ($k in @($Editor.Elements.Keys)) {
        $e = $Editor.Elements[$k].Element; $ctl = $Editor.Elements[$k].Control
        $v = switch ([string]$e.Kind) {
            { $_ -in 'enum', 'bool' } { if ($ctl.SelectedItem) { $ctl.SelectedItem.Tag } else { $null } }
            'flags' { @($ctl.Children | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Tag }) }
            { $_ -in 'multiText', 'list' } { @(([string]$ctl.Text -split "`r?`n") | Where-Object { $_.Trim() -ne '' }) }
            'keyValueList' { $h = [ordered]@{}; foreach ($line in @(([string]$ctl.Text -split "`r?`n") | Where-Object { $_ })) { $i = $line.IndexOf('='); if ($i -gt 0) { $h[$line.Substring(0, $i).Trim()] = $line.Substring($i + 1).Trim() } }; $h }
            default { [string]$ctl.Text }
        }
        $vals[$k] = $v
    }
    if ($Editor.Mode -eq 'tristate') { return @{ State = [string]$Editor.State.SelectedItem.Tag; Values = $vals } }
    return @($vals.Values)[0]
}

function Show-IgwtGuiSecSettingDetail {
    <# .SYNOPSIS The detail pane of the selected setting: facts, read-only reason or an editor, and the Stage button. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param($Row)
    $c = $script:Gui.C
    $host_ = $c.SecSettingsDetailHost
    $host_.Children.Clear()
    $script:Gui.SecEditor = $null; $script:Gui.SecEditorRow = $null
    $c.SecStageButton.IsEnabled = $false
    if (-not $Row) { $t = New-Object System.Windows.Controls.TextBlock; $t.Text = 'Select a setting to see what it does, where its value comes from and to change it.'; $t.TextWrapping = 'Wrap'; $null = $host_.Children.Add($t); return }
    $s = $Row.Setting
    $add = { param($text, [switch]$Bold, [switch]$Muted) $tb = New-Object System.Windows.Controls.TextBlock; $tb.Text = $text; $tb.TextWrapping = 'Wrap'; $tb.Margin = '0,0,0,6'; if ($Bold) { $tb.FontWeight = 'SemiBold' }; if ($Muted) { $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BrushTextMuted') }; $null = $host_.Children.Add($tb) }
    & $add ([string]$s.Name) -Bold
    & $add ("Current: $($s.CurrentText)  |  Origin: $($s.Origin)  |  Applies to: $($s.AppliesTo)")
    & $add ("Baseline: $(if ($null -ne $s.Baseline) { "$(@($s.Baseline) -join ', ') ($($s.BaselineSource))" } else { $s.BaselineSource })") -Muted
    if ($s.SupportedOn) { & $add ("Supported on: $($s.SupportedOn)") -Muted }
    if ($s.Risk -eq 'high') { & $add ("High risk. Restart: $($s.Restart). " + (@($s.SideEffects | ForEach-Object { $_.text }) -join ' ')) }
    if ($s.ReadOnly) { & $add ("Read-only: $($s.ReadOnlyReason)") }
    elseif ($s.ValueSpec.Mode -ne 'none') {
        $script:Gui.SecEditor = New-IgwtGuiSecSettingEditor -Setting $s -Panel $host_
        $script:Gui.SecEditorRow = $s
        $c.SecStageButton.IsEnabled = $true
    }
    if ($s.Explain) { & $add ([string]$s.Explain) -Muted }
}

function Add-IgwtGuiSecStagedChange {
    <# .SYNOPSIS Validates the editor's value (Test-IgwtSecSettingValue) and stages it, or shows why not. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Stages a change in memory only.')]
    [CmdletBinding()]
    param()
    $s = $script:Gui.SecEditorRow
    if (-not $s -or -not $script:Gui.SecEditor) { return }
    $value = Read-IgwtGuiSecSettingEditor -Editor $script:Gui.SecEditor
    $v = Test-IgwtSecSettingValue -ValueSpec $s.ValueSpec -Value $value -Current $s.Current
    if (-not $v.Ok) { $null = Show-IgwtGuiMessage -Text ("Not staged:`n" + (@($v.Errors) -join "`n")) -Title 'iG Windows Tuner - Security settings' -Icon 'Warning'; return }
    $script:Gui.SecStaged[[string]$s.Id] = @{ Id = [string]$s.Id; Value = $value; Name = [string]$s.Name }
    Update-IgwtGuiSecStaged
    Set-IgwtGuiSecSettingsRows
    Set-IgwtGuiStatus "Staged: $($s.Name). Preview or apply the staged changes below."
}

function Update-IgwtGuiSecStaged {
    <# .SYNOPSIS The staged changes line and the Preview, Apply and Clear buttons. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $n = @($script:Gui.SecStaged.Keys).Count
    $c.SecStagedText.Text = $(if ($n) { "$n staged: " + (@($script:Gui.SecStaged.Values | ForEach-Object { $_.Name }) -join '; ') } else { 'Nothing staged. Select a setting, choose a value and press Stage.' })
    foreach ($b in 'SecPreviewButton', 'SecApplyButton', 'SecClearButton') { $c[$b].IsEnabled = ($n -gt 0) }
    # 4.0 D6: the ChangeBar shows and applies these staged changes.
    if ($c.PendingText) { Update-IgwtGuiPending }
    if ($script:Gui.ReadOnly -or -not $script:Gui.IsAdmin) { $c.SecApplyButton.IsEnabled = $false; $c.SecApplyButton.ToolTip = (Get-IgwtGuiChangeBlockReason -What 'change security settings') }
}

function Invoke-IgwtGuiSecSettingsPreview {
    <#
    .SYNOPSIS
        Preview (and with -Apply, apply) the staged changes: the plan is made in the worker; the text
        is shown; for Apply, high-risk rows need the typed confirmation and managed rows the managed
        confirmation, then Invoke-IgwtSecSettingChange runs in the worker and the result offers Undo.
    .PARAMETER Apply
        Apply after the preview.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Asks for confirmation; the engine journals every change.')]
    [CmdletBinding()]
    param([switch]$Apply)
    $changes = @($script:Gui.SecStaged.Values | ForEach-Object { @{ Id = $_.Id; Value = $_.Value } })
    if (-not $changes.Count) { return }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtSecSettingChangePlan' -Parameters @{ Changes = $changes; AcknowledgeRisk = $true } -Channel 'secsettingsplan' -Blocking -BusyText 'Checking the staged changes (read-only)...' -Context @{ Apply = [bool]$Apply; Changes = $changes } -OnComplete {
        param($out, $errs, $ctx)
        $plan = @($out) | Where-Object { $_ -and $_.PSObject.Properties['Rows'] } | Select-Object -Last 1
        if (@($errs).Count -or -not $plan) { Show-IgwtGuiError -Message "The plan could not be made: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })" -Context 'Security settings'; return }
        $text = (@(Format-IgwtSecSettingPlan -Plan $plan) -join "`n")
        if (-not $ctx.Apply) { $null = Show-IgwtGuiTextDialog -Title 'Security settings - preview' -Text $text; return }
        # SS-1: managed rows are confirmed here, not acknowledged silently (the plan ran without AcknowledgeManaged).
        $managed = @($plan.Rows | Where-Object { $_.Status -eq 'NeedsManagedAck' })
        $blocking = @($plan.Rows | Where-Object { $_.Status -eq 'Refused' })
        if (-not $plan.CanApply -and (-not $managed.Count -or $blocking.Count)) { $null = Show-IgwtGuiTextDialog -Title 'Security settings - nothing to apply' -Text $text; return }
        if (-not (Show-IgwtGuiTextDialog -Title 'Security settings - apply these changes?' -Text $text -AcceptText 'Continue' -CancelText 'Cancel')) { return }
        $high = @($plan.Rows | Where-Object { $_.Status -in 'Change', 'NeedsManagedAck' -and $_.Risk -eq 'high' })
        if ($high.Count -and -not (Show-IgwtGuiSecSettingConfirm -Rows $high)) { return }
        if ($managed.Count) {
            $m = $script:Gui.Management
            $who = $(if ($m -and @($m.Authorities).Count) { " ($(@($m.Authorities) -join ', '))" } else { '' })
            $names = (@($managed | ForEach-Object { '- ' + [string]$_.Name }) -join [Environment]::NewLine)
            $msg = "This PC is managed by your organization$who. These settings are also set by its policy, which can override or conflict with a local change:`n`n$names`n`nChange them locally anyway?"
            if ((Show-IgwtGuiMessage -Title 'This PC is managed' -Buttons 'YesNo' -Icon 'Warning' -Text $msg) -ne 'Yes') { return }
        }
        $null = Start-IgwtGuiJob -Command 'Invoke-IgwtSecSettingChange' -Parameters @{ Changes = $ctx.Changes; AcknowledgeRisk = [bool]$high.Count; AcknowledgeManaged = [bool]$managed.Count; Confirm = $false } -Blocking -BusyText 'Applying security settings (journaled, with rollback)...' -OnComplete {
            param($out2, $errs2)
            $res = @($out2) | Where-Object { $_ -and $_.PSObject.Properties['SessionId'] } | Select-Object -Last 1
            if (@($errs2).Count -or -not $res) { Show-IgwtGuiError -Message "Nothing was changed: $(if (@($errs2).Count) { @($errs2)[0] } else { 'no result' })" -Context 'Security settings'; Start-IgwtGuiSecSettingsLoad; return }
            $script:Gui.SecStaged = [ordered]@{}; Update-IgwtGuiSecStaged
            $lines = @($res.Results | ForEach-Object { "[$($_.Result)] $($_.Name) $($_.Message)" })
            if ($res.Restart -eq 'reboot') { $lines += ''; $lines += 'Restart Windows to finish. Have your BitLocker recovery key ready if the system drive is encrypted.' }
            $ok = @($res.Results | Where-Object Result -EQ 'Committed').Count
            if ($ok) { Show-IgwtGuiToast -Text "$ok security setting(s) changed." -Tone Success -ActionText 'Undo' -Action { param($sid) Invoke-IgwtGuiSecSettingsUndo -SessionId $sid } -ActionArgument ([string]$res.SessionId) }
            $null = Show-IgwtGuiTextDialog -Title 'Security settings - result' -Text ($lines -join "`n")
            Start-IgwtGuiSecSettingsLoad
        }
    }
}

function Invoke-IgwtGuiSecSettingsUndo {
    <# .SYNOPSIS Undo of one apply: the revert plan of its session, shown first, then the journal revert in the worker. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Asks for confirmation; the engine journals the revert.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SessionId)
    $null = Start-IgwtGuiJob -Command 'Get-IgwtRevertPlan' -Parameters @{ SessionId = $SessionId } -Blocking -BusyText 'Reading what Undo would restore...' -Context $SessionId -OnComplete {
        param($out, $errs, $sid)
        $plan = @($out | Where-Object { $_ })
        if (@($errs).Count -or -not $plan.Count) { Show-IgwtGuiError -Message "Undo is not available: $(if (@($errs).Count) { @($errs)[0] } else { 'nothing to restore' })" -Context 'Security settings'; return }
        $text = (@($plan | ForEach-Object { "[$($_.Status)] $($_.Item)" }) -join "`n") + "`n`nSecurity options and audit policy are restored as whole steps; settings that needed a restart need another one."
        if (-not (Show-IgwtGuiTextDialog -Title 'Undo security settings' -Text $text -AcceptText 'Undo' -CancelText 'Cancel')) { return }
        $null = Start-IgwtGuiJob -Command 'Invoke-IgwtJournalRevert' -Parameters @{ Plan = $plan; Title = 'Undo security settings'; Confirm = $false } -Blocking -BusyText 'Undoing the security settings...' -OnComplete {
            param($o2, $e2)
            $null = $o2
            if (@($e2).Count) { Show-IgwtGuiError -Message "Undo failed: $(@($e2)[0])" -Context 'Security settings' } else { Show-IgwtGuiToast -Text 'The security settings change was undone.' -Tone Info }
            Start-IgwtGuiSecSettingsLoad
        }
    }
}

function Show-IgwtGuiSecSettingConfirm {
    <#
    .SYNOPSIS
        The high-risk confirmation (DECISIONS SM17, SM18): the rows with their prerequisite checks,
        side effects, the recovery-key and Windows Recovery notes, the restart notice and a typed word.
        Returns $true only when the word matches. Show-IgwtGuiRiskDialog (Risk Zone) is unchanged.
    .PARAMETER Rows
        High-risk plan rows.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Shows a dialog only.')]
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][object[]]$Rows)
    $word = $(if (@($Rows | Where-Object { $_.Id -like '*VolumeEncryption*' }).Count) { 'BITLOCKER' } elseif (@($Rows | Where-Object { $_.Id -like '*LocalSecurityAuthority*' }).Count) { 'LSA PROTECTION' } elseif (@($Rows | Where-Object { $_.Id -like '*DeviceGuard*' }).Count) { 'VBS' } else { 'CONFIRM' })
    $lines = foreach ($r in $Rows) {
        $r.Name
        foreach ($p in @($r.Prerequisites)) { "  $($p.Check): $($p.Result). $($p.Text)" }
        foreach ($s in @($r.SideEffects)) { "  Side effect: $($s.text)" }
    }
    $w = New-Object System.Windows.Window
    $w.Title = 'iG Windows Tuner - confirm a high-risk change'; $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'; $w.Width = 640; $w.SizeToContent = 'Height'; $w.ResizeMode = 'NoResize'; $w.ShowInTaskbar = $false
    $w.Background = $script:Gui.Window.FindResource('BrushBackground')
    $sp = New-Object System.Windows.Controls.StackPanel; $sp.Margin = '18'
    $t = New-Object System.Windows.Controls.TextBlock; $t.TextWrapping = 'Wrap'; $t.Margin = '0,0,0,10'
    $t.Text = ((@($lines) + @('', 'Windows restarts are needed for these changes. If Windows does not start, Microsoft documents how to turn memory integrity off from the Windows Recovery Environment. Have your BitLocker recovery key ready (aka.ms/myrecoverykey).', '', "Type $word to confirm.")) -join "`n")
    $t.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BrushText')
    $null = $sp.Children.Add($t)
    $box = New-Object System.Windows.Controls.TextBox; $box.Margin = '0,0,0,10'; [System.Windows.Automation.AutomationProperties]::SetName($box, "Type $word to confirm")
    $null = $sp.Children.Add($box)
    $dock = New-Object System.Windows.Controls.StackPanel; $dock.Orientation = 'Horizontal'; $dock.HorizontalAlignment = 'Right'
    $ok = New-Object System.Windows.Controls.Button; $ok.Content = 'Apply'; $ok.Margin = '0,0,8,0'; $ok.IsEnabled = $false; $ok.Tag = $word
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.IsCancel = $true
    $null = $dock.Children.Add($ok); $null = $dock.Children.Add($cancel); $null = $sp.Children.Add($dock)
    $box.Tag = $ok
    Register-IgwtGuiHandler -Control $box -Event 'TextChanged' -Handler { param($s, $e) $null = $e; $s.Tag.IsEnabled = ([string]$s.Text).Trim() -ceq [string]$s.Tag.Tag }
    Register-IgwtGuiHandler -Control $ok -Event 'Click' -Handler { param($s, $e) $null = $e; [System.Windows.Window]::GetWindow($s).DialogResult = $true }
    $w.Content = $sp
    return [bool]$w.ShowDialog()
}

function Get-IgwtGuiSecStagedCount {
    <# .SYNOPSIS How many Security Settings changes are staged (ChangeBar provider). #>
    [CmdletBinding()]
    [OutputType([int])]
    param()
    if (-not $script:Gui.SecStaged) { return 0 }
    return @($script:Gui.SecStaged.Keys).Count
}

function Invoke-IgwtGuiSecSettingsApply {
    <# .SYNOPSIS Applies the staged Security Settings changes after their preview (ChangeBar provider). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Shows the preview and confirmations before the engine changes anything.')]
    [CmdletBinding()]
    param()
    Invoke-IgwtGuiSecSettingsPreview -Apply
}

function Clear-IgwtGuiSecSettingsStage {
    <# .SYNOPSIS Unstages every Security Settings change (ChangeBar provider). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param()
    $script:Gui.SecStaged = [ordered]@{}; Update-IgwtGuiSecStaged; Set-IgwtGuiSecSettingsRows
    Set-IgwtGuiStatus 'Staged security setting changes discarded.'
}