# AsrPage.ps1
# Security > ASR Center: rules in a SmartGrid (rule, category, mode, supported modes, gamer impact,
# events and last event of the last 7 days, managed by), a details pane with a segmented mode
# control (unsupported modes disabled with the reason), bulk "set mode", the Audit-to-Block review,
# the events tab and the read-only Exploit protection tab. The mode shown is always read back from
# Defender after a change.

$script:IgwtAsrModeLabel = @{ NotConfigured = 'Off'; Off = 'Off (explicit)'; Audit = 'Audit'; Warn = 'Warn'; Block = 'Block' }

#region Rows

function New-IgwtGuiAsrGridRow {
    <# .SYNOPSIS SmartGrid row for one ASR rule, with its events from the audit view (when read). Never throws on unexpected values. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule, $AuditRule)
    $mode = [string]$Rule.Mode
    $modeTone = switch ($mode) { 'Block' { 'Pass' } 'Warn' { 'Pass' } 'Audit' { 'Info' } 'Off' { 'Warn' } default { 'Muted' } }
    $impact = [string]$Rule.GamerImpactLevel
    $impactTone = switch ($impact) { 'high' { 'Fail' } 'medium' { 'Warn' } 'low' { 'Info' } default { 'Pass' } }
    $events = 0; $last = $null
    if ($AuditRule) {
        $events = [int]$AuditRule.Total
        foreach ($p in @($AuditRule.Programs)) { if ($p.LastSeen) { $t = [datetime]$p.LastSeen; if (-not $last -or $t -gt $last) { $last = $t } } }
    }
    $row = [ordered]@{
        Key = [string]$Rule.Id; Id = [string]$Rule.Id; Rule = $Rule; Audit = $AuditRule; Name = [string]$Rule.Name; Hint = [string]$Rule.Hint
        Category = $(if ([string]$Rule.Category -eq 'standard') { 'Standard protection' } elseif ($Rule.MsCategory) { [string]$Rule.MsCategory } else { 'Other' })
        ModeKey = $mode; Supported = (@($Rule.AllowedModes | ForEach-Object { $script:IgwtAsrModeLabel[[string]$_] }) -join ', ')
        ImpactKey = $impact; ImpactRank = @{ none = 0; low = 1; medium = 2; high = 3 }[$impact]
        Events = $events; EventsText = $(if ($AuditRule) { [string]$events } else { '' }); LastEvent = $last; LastEventText = $(if ($last) { $last.ToString('g') } else { '' })
        ManagedBy = $(if ($Rule.ManagedByPolicy) { [string]$Rule.Source } elseif ([string]$Rule.Source -in '', 'NotSet') { 'Windows default' } else { 'Local' })
        Recommendation = $(if ($Rule.ServerOnly) { 'Not applicable (servers)' } elseif ($Rule.MeetsRecommendation) { 'Meets recommendation' } else { "Recommended: $($script:IgwtAsrModeLabel[[string]$Rule.Recommended])" })
        BelowRecommendation = $(if ($Rule.ServerOnly -or $Rule.MeetsRecommendation) { 'No' } else { 'Yes' })
    }
    $modeText = $script:IgwtAsrModeLabel[$mode]; if (-not $modeText) { $modeText = $mode }
    Add-IgwtGuiStatusField -Row $row -Name 'Mode' -Text $modeText -Tone $modeTone -Locked:([bool]$Rule.ManagedByPolicy)
    Add-IgwtGuiStatusField -Row $row -Name 'Impact' -Text $(if ($impact) { (Get-Culture).TextInfo.ToTitleCase($impact) } else { 'Unknown' }) -Tone $impactTone
    return [pscustomobject]$row
}

function New-IgwtGuiAsrEventRow {
    <# .SYNOPSIS SmartGrid rows for the events tab (programs per rule, controlled folder access, network protection). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds in-memory rows only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Audit)
    $i = 0
    foreach ($r in @($Audit.Rules)) {
        foreach ($p in @($r.Programs)) {
            $i++
            [pscustomobject]@{ Key = "e$i"; Program = $(if ($p.Path) { [string]$p.Path } else { '(no path)' }); Source = [string]$r.Name; Kind = 'ASR rule'; Count = [int]$p.Count
                LastSeen = $(if ($p.LastSeen) { [datetime]$p.LastSeen } else { $null }); LastSeenText = $(if ($p.LastSeen) { ([datetime]$p.LastSeen).ToString('g') } else { '' })
                Advice = "$($p.Suggestion): $($p.Reason)"; Detail = "Blocked $($p.Blocked), audited $($p.Audited), warn bypassed $($p.WarnBypassed)."; RuleId = [string]$r.Id; Exclusion = [string]$p.Exclusion }
        }
    }
    foreach ($c in @($Audit.ControlledFolderAccess)) {
        $i++
        [pscustomobject]@{ Key = "e$i"; Program = [string]$c.Process; Source = 'Controlled folder access'; Kind = 'Folder access'; Count = [int]$c.Count
            LastSeen = $(if ($c.LastSeen) { [datetime]$c.LastSeen } else { $null }); LastSeenText = $(if ($c.LastSeen) { ([datetime]$c.LastSeen).ToString('g') } else { '' })
            Advice = [string]$c.Advice; Detail = "Last file: $($c.LastPath). Blocked $($c.Blocked), audited $($c.Audited)."; RuleId = ''; Exclusion = '' }
    }
    foreach ($n in @($Audit.NetworkProtection)) {
        $i++
        [pscustomobject]@{ Key = "e$i"; Program = $(if ($n.Process) { [string]$n.Process } else { [string]$n.Destination }); Source = 'Network protection'; Kind = 'Network'; Count = [int]$n.Count
            LastSeen = $(if ($n.LastSeen) { [datetime]$n.LastSeen } else { $null }); LastSeenText = $(if ($n.LastSeen) { ([datetime]$n.LastSeen).ToString('g') } else { '' })
            Advice = [string]$n.Advice; Detail = [string]$n.Destination; RuleId = ''; Exclusion = '' }
    }
}

#endregion

#region Page

function Initialize-IgwtGuiAsrPage {
    <# .SYNOPSIS Builds the ASR, events and exploit protection grids and wires the page (called once at start). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $actions = @(
        @{ Id = 'block'; Label = 'Set to Block'; Bulk = $true; Changes = $true; Run = { param($rows) Invoke-IgwtGuiAsrBulkMode -Rows $rows -Mode 'Block' } }
        @{ Id = 'warn'; Label = 'Set to Warn'; Bulk = $true; Changes = $true; Run = { param($rows) Invoke-IgwtGuiAsrBulkMode -Rows $rows -Mode 'Warn' } }
        @{ Id = 'audit'; Label = 'Set to Audit'; Bulk = $true; Changes = $true; Run = { param($rows) Invoke-IgwtGuiAsrBulkMode -Rows $rows -Mode 'Audit' } }
        @{ Id = 'off'; Label = 'Set to Off'; Bulk = $true; Changes = $true; Run = { param($rows) Invoke-IgwtGuiAsrBulkMode -Rows $rows -Mode 'NotConfigured' } }
    )
    $g = New-IgwtSmartGrid -Id 'asr.rules' -Noun 'rules' -RowKey 'Key' -SearchPlaceholder 'Search rules' -Actions $actions `
        -Columns @(
        @{ Key = 'Name'; Header = 'Rule'; MinWidth = 220; Tip = 'Hint' }
        @{ Key = 'Category'; Header = 'Category'; Width = 170 }
        @{ Key = 'Mode'; Header = 'Mode'; Width = 120; Template = 'Status'; SortKey = 'ModeKey' }
        @{ Key = 'Supported'; Header = 'Supported modes'; Width = 170; Visible = $false }
        @{ Key = 'Impact'; Header = 'Gamer impact'; Width = 120; Template = 'Status'; Kind = 'Number'; SortKey = 'ImpactRank' }
        @{ Key = 'EventsText'; Header = 'Events (7 days)'; Width = 120; Kind = 'Number'; SortKey = 'Events' }
        @{ Key = 'LastEventText'; Header = 'Last event'; Width = 140; Kind = 'Date'; SortKey = 'LastEvent' }
        @{ Key = 'ManagedBy'; Header = 'Managed by'; Width = 140 }
        @{ Key = 'Recommendation'; Header = 'Recommendation'; Width = 190; Visible = $false }
    ) -Chips @(
        @{ Id = 'below'; Label = 'Below recommendation'; Group = 'rec'; Field = 'BelowRecommendation'; Values = @('Yes') }
        @{ Id = 'm-block'; Label = 'Block'; Group = 'mode'; Field = 'ModeKey'; Values = @('Block') }
        @{ Id = 'm-warn'; Label = 'Warn'; Group = 'mode'; Field = 'ModeKey'; Values = @('Warn') }
        @{ Id = 'm-audit'; Label = 'Audit'; Group = 'mode'; Field = 'ModeKey'; Values = @('Audit') }
        @{ Id = 'm-off'; Label = 'Off'; Group = 'mode'; Field = 'ModeKey'; Values = @('NotConfigured', 'Off') }
        @{ Id = 'events'; Label = 'Has events'; Group = 'events'; Test = { param($r) $r.Events -gt 0 } }
        @{ Id = 'i-high'; Label = 'High or medium gamer impact'; Group = 'impact'; Field = 'ImpactKey'; Values = @('high', 'medium'); More = $true }
        @{ Id = 'c-standard'; Label = 'Standard protection'; Group = 'cat'; Field = 'Category'; Values = @('Standard protection'); More = $true }
        @{ Id = 'managed'; Label = 'Managed by policy'; Group = 'managed'; Test = { param($r) [bool]$r.Rule.ManagedByPolicy }; More = $true }
    ) -OnSelectionChanged { param($grid, $sel) $null = $grid, $sel; Update-IgwtGuiAsrDetails } -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiAsrRefresh }
    $script:Gui.Grids.Asr = $g
    $c.AsrGridHost.Content = $g.Root
    $ev = New-IgwtSmartGrid -Id 'asr.events' -Noun 'events' -RowKey 'Key' -SearchPlaceholder 'Search programs and rules' -EmptyTitle 'No events in the last 7 days' -EmptyText 'Nothing was blocked or audited. Rules in Audit with no events can usually move to Block.' `
        -Columns @(
        @{ Key = 'Program'; Header = 'Program'; MinWidth = 220; Template = 'Mono'; Tip = 'Detail' }
        @{ Key = 'Source'; Header = 'Reported by'; Width = 230 }
        @{ Key = 'Count'; Header = 'Count'; Width = 80; Kind = 'Number' }
        @{ Key = 'LastSeenText'; Header = 'Last seen'; Width = 140; Kind = 'Date'; SortKey = 'LastSeen' }
        @{ Key = 'Advice'; Header = 'Advice'; Width = 320 }
    ) -Chips @(
        @{ Id = 'k-asr'; Label = 'ASR rules'; Group = 'kind'; Field = 'Kind'; Values = @('ASR rule') }
        @{ Id = 'k-cfa'; Label = 'Controlled folder access'; Group = 'kind'; Field = 'Kind'; Values = @('Folder access') }
        @{ Id = 'k-net'; Label = 'Network protection'; Group = 'kind'; Field = 'Kind'; Values = @('Network') }
    ) -OnSelectionChanged { param($grid, $sel) $null = $grid, $sel; Update-IgwtGuiAsrButtons }
    if (-not @($ev.Sort).Count) { Set-IgwtGridSort -Grid $ev -Key 'LastSeenText' -NoSave; Set-IgwtGridSort -Grid $ev -Key 'LastSeenText' -NoSave }
    $script:Gui.Grids.AsrEvents = $ev
    $c.AsrAuditGridHost.Content = $ev.Root
    $exp = New-IgwtSmartGrid -Id 'exploit.programs' -Noun 'programs' -RowKey 'Program' -SearchPlaceholder 'Search programs' -EmptyTitle 'No program has its own exploit protection settings' -EmptyText 'Every program uses the system-wide settings above.' `
        -Columns @(
        @{ Key = 'Program'; Header = 'Program'; MinWidth = 200; Template = 'Mono'; Tip = 'Note' }
        @{ Key = 'State'; Header = 'Status'; Width = 150; Template = 'Status'; SortKey = 'StateKey' }
        @{ Key = 'On'; Header = 'Turned on'; Width = 280 }
        @{ Key = 'Off'; Header = 'Turned off'; Width = 220 }
        @{ Key = 'Source'; Header = 'Source'; Width = 110; Visible = $false }
    ) -Chips @(
        @{ Id = 'anti'; Label = 'Anti-cheat (locked)'; Group = 'kind'; Field = 'StateKey'; Values = @('AntiCheat') }
        @{ Id = 'weak'; Label = 'Mitigations turned off'; Group = 'kind'; Field = 'StateKey'; Values = @('Weakened') }
    )
    $script:Gui.Grids.Exploit = $exp
    $c.ExpGridHost.Content = $exp.Root

    Register-IgwtGuiHandler -Control $c.AsrRefreshButton -Event 'Click' -Handler { Start-IgwtGuiAsrRefresh }
    Register-IgwtGuiHandler -Control $c.AsrPromoteButton -Event 'Click' -Handler { Show-IgwtGuiAsrPromote }
    Register-IgwtGuiHandler -Control $c.AsrRecommendButton -Event 'Click' -Handler {
        if (-not $script:Gui.AsrStatus) { return }
        $plan = @(Get-IgwtAsrRecommendationPlan -Status $script:Gui.AsrStatus)
        if ($plan.Count -eq 0) { Show-IgwtGuiToast -Text 'Every rule already meets its recommendation.' -Tone Info; return }
        $lines = @($plan | ForEach-Object { "- $($_.Name): $($_.From) -> $($_.To)" })
        Invoke-IgwtGuiAsrChange -Parameters @{ Recommended = $true } -Description ("Apply the recommended modes to $($plan.Count) rule(s)? No rule is lowered.`n`n" + ($lines -join "`n"))
    }
    foreach ($rb in 'AsrModeNotConfigured', 'AsrModeAudit', 'AsrModeWarn', 'AsrModeBlock') { Register-IgwtGuiHandler -Control $c[$rb] -Event 'Click' -Handler { Update-IgwtGuiAsrButtons } }
    Register-IgwtGuiHandler -Control $c.AsrSetModeButton -Event 'Click' -Handler { Invoke-IgwtGuiAsrSetMode }
    Register-IgwtGuiHandler -Control $c.AsrGlobalBox -Event 'Click' -Handler { Update-IgwtGuiAsrExclusionList }
    Register-IgwtGuiHandler -Control $c.AsrExclusionList -Event 'SelectionChanged' -Handler { Update-IgwtGuiAsrButtons }
    Register-IgwtGuiHandler -Control $c.AsrDetSources -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
        param($s, $e)
        $null = $s
        if ($e.OriginalSource -is [System.Windows.Controls.Button]) { Open-IgwtGuiPath -Target ([string]$e.OriginalSource.Tag) }
    }
    Register-IgwtGuiHandler -Control $c.AsrAddExclusionButton -Event 'Click' -Handler { Invoke-IgwtGuiAsrExclusion -Add }
    Register-IgwtGuiHandler -Control $c.AsrRemoveExclusionButton -Event 'Click' -Handler { Invoke-IgwtGuiAsrExclusion }
    Register-IgwtGuiHandler -Control $c.AsrAuditExcludeButton -Event 'Click' -Handler { Use-IgwtGuiAsrEventAsExclusion }
    Update-IgwtGuiAsrDetails
}

function Start-IgwtGuiAsrRefresh {
    <# .SYNOPSIS Reads the rules, the events of the last 7 days and the exploit protection settings in the background (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    Set-IgwtGridState -Grid $script:Gui.Grids.Asr -State Loading
    $null = Start-IgwtGuiJob -Command 'Get-IgwtAsrStatus' -Channel 'asr' -BusyText 'Reading ASR rules (read-only)...' -OnComplete {
        param($out, $errs)
        $st = @($out) | Select-Object -Last 1
        if (-not $st) { Set-IgwtGridState -Grid $script:Gui.Grids.Asr -State Error -Message $(if (@($errs).Count) { [string]@($errs)[0] } else { 'No data was returned.' }); return }
        Set-IgwtGuiAsrStatus -Status $st
    }
    Set-IgwtGridState -Grid $script:Gui.Grids.AsrEvents -State Loading
    $null = Start-IgwtGuiJob -Command 'Get-IgwtAsrAudit' -Channel 'asr-audit' -Parameters @{ Days = 7 } -BusyText 'Reading the Defender log (read-only)...' -OnComplete {
        param($out, $errs)
        $a = @($out) | Select-Object -Last 1
        if (-not $a) { Set-IgwtGridState -Grid $script:Gui.Grids.AsrEvents -State Error -Message $(if (@($errs).Count) { [string]@($errs)[0] } else { 'No data was returned.' }); return }
        Set-IgwtGuiAsrAudit -Audit $a
    }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtExploitProtectionInventory' -Channel 'exploit' -BusyText 'Reading exploit protection (read-only)...' -OnComplete {
        param($out, $errs)
        $x = @($out) | Select-Object -Last 1
        if ($x) { Set-IgwtGuiExploitProtection -Inventory $x } else { Set-IgwtGridState -Grid $script:Gui.Grids.Exploit -State Error -Message ([string]@($errs)[0]) }
    }
}

function Set-IgwtGuiAsrStatus {
    <# .SYNOPSIS Shows an ASR status (rules), merged with the events when they are already read. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Status)
    $c = $script:Gui.C
    $script:Gui.AsrStatus = $Status
    if (-not $Status) { Set-IgwtGridState -Grid $script:Gui.Grids.Asr -State Error -Message 'The ASR status could not be read; see the log.'; return }
    Update-IgwtGuiAsrRows
    $s = $Status.Summary
    $parts = New-Object System.Collections.Generic.List[string]
    if (-not $Status.DefenderActive) { $parts.Add('Microsoft Defender Antivirus is not the active antivirus, so ASR rules do not apply on this PC.') }
    $below = [int]$s.BelowRecommendation
    $parts.Add($(if ($below) { "$below rule(s) below the recommendation" } else { 'Every rule meets its recommendation' }) + (". {0} Block, {1} Warn, {2} Audit, {3} off." -f $s.Block, $s.Warn, $s.Audit, ($s.NotConfigured + $s.Off)))
    if ($Status.CloudProtection -eq $false) { $parts.Add('Cloud-delivered protection is off; three rules depend on it.') }
    if ($s.PolicyManaged) { $parts.Add("$($s.PolicyManaged) rule(s) are managed by Group Policy or MDM (locked).") }
    $c.AsrSummaryText.Text = $parts -join ' '
    $attention = ($below -gt 0 -or -not $Status.DefenderActive)
    $c.AsrSummaryIcon.Text = $(if ($attention) { [string][char]0xE7BA } else { [string][char]0xE73E })
    $c.AsrSummaryIcon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $(if ($attention) { 'BrushWarning' } else { 'BrushSuccess' }))
    Update-IgwtGuiAsrDetails
}

function Update-IgwtGuiAsrRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.AsrStatus) { return }
    $byId = @{}
    if ($script:Gui.AsrAudit -and $script:Gui.AsrAudit.Readable) { foreach ($r in @($script:Gui.AsrAudit.Rules)) { $byId[[string]$r.Id] = $r } }
    Set-IgwtGridRows -Grid $script:Gui.Grids.Asr -Rows @($script:Gui.AsrStatus.Rules | ForEach-Object { New-IgwtGuiAsrGridRow -Rule $_ -AuditRule $byId[[string]$_.Id] })
}

function Set-IgwtGuiAsrAudit {
    <# .SYNOPSIS Shows the events of the last 7 days and adds the counts to the rule list. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Audit)
    $c = $script:Gui.C
    $script:Gui.AsrAudit = $Audit
    if (-not $Audit -or -not $Audit.Readable) {
        $msg = $(if ($Audit) { [string]$Audit.Error } else { 'The Defender log could not be read; see the log.' })
        $c.AsrAuditSummaryText.Text = $msg
        Set-IgwtGridState -Grid $script:Gui.Grids.AsrEvents -State Error -Message $msg
        return
    }
    Set-IgwtGridRows -Grid $script:Gui.Grids.AsrEvents -Rows @(New-IgwtGuiAsrEventRow -Audit $Audit)
    $t = $Audit.Totals
    $c.AsrAuditSummaryText.Text = ("Last {0} day(s), the log covers {1}: {2} blocked, {3} audited, {4} controlled folder access, {5} network protection. {6} to review, {7} ready to move to Block." -f `
            $Audit.Days, $Audit.CoverageDays, $t.AsrBlocked, $t.AsrAudited, $t.Cfa, $t.Network, $t.ToReview, $t.ToPromote)
    Update-IgwtGuiAsrRows
    Update-IgwtGuiAsrButtons
}

function Set-IgwtGuiExploitProtection {
    <# .SYNOPSIS Fills the Exploit protection tab (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Inventory)
    $c = $script:Gui.C
    $script:Gui.Exploit = $Inventory
    $c.ExpSystemText.Text = $(if (@($Inventory.System).Count) { (@($Inventory.System | ForEach-Object { "$($_.Name): $($_.Value)" }) -join [Environment]::NewLine) } else { 'Not readable.' })
    $rows = @(foreach ($p in @($Inventory.Programs)) {
            $r = [ordered]@{ Program = $p.Program; On = $p.On; Off = $p.Off; Source = $p.Source; Note = $p.Note; StateKey = $(if ($p.AntiCheat) { 'AntiCheat' } elseif ($p.OffCount) { 'Weakened' } else { 'Hardened' }) }
            Add-IgwtGuiStatusField -Row $r -Name 'State' -Text $(if ($p.AntiCheat) { 'Anti-cheat (locked)' } elseif ($p.OffCount) { "$($p.OffCount) turned off" } else { 'Extra protection' }) -Tone $(if ($p.AntiCheat) { 'Muted' } elseif ($p.OffCount) { 'Warn' } else { 'Pass' }) -Locked:([bool]$p.AntiCheat)
            [pscustomobject]$r
        })
    Set-IgwtGridRows -Grid $script:Gui.Grids.Exploit -Rows $rows
    $notes = @($Inventory.Notes | Where-Object { $_ })
    if ($notes.Count) { $script:Gui.Grids.Exploit.EmptyText = $notes -join ' '; if (-not $rows.Count) { Set-IgwtGridState -Grid $script:Gui.Grids.Exploit -State Ready } }
}

function Update-IgwtGuiAsrDetails {
    <# .SYNOPSIS The details pane of the selected rule: impact, the segmented mode control (unsupported modes disabled with the reason) and exclusions. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if (-not $script:Gui.Grids.Asr) { return }
    $row = Get-IgwtGuiGridItem -Name Asr
    if (-not $row) {
        $c.AsrDetName.Text = 'Select a rule'; $c.AsrDetMeta.Text = ''
        $c.AsrDetDescription.Text = 'Pick a rule to see what it blocks, what it means for games, its events and its exclusions. Select several to change their mode together.'
        $c.AsrDetPanel.Visibility = 'Collapsed'; $c.AsrDetSources.ItemsSource = @()
        Update-IgwtGuiAsrButtons
        return
    }
    $r = $row.Rule
    $c.AsrDetPanel.Visibility = 'Visible'
    $c.AsrDetName.Text = [string]$r.Name
    $c.AsrDetMeta.Text = ("Mode: {0} ({1})  |  {2}  |  Events (7 days): {3}" -f $row.Mode, $row.ManagedBy, $row.Recommendation, $(if ($row.Audit) { $row.Events } else { 'not read' }))
    $desc = [string]$r.Description
    if ($r.Notes) { $desc += "  Note: $($r.Notes)" }
    if ($r.ManagedByPolicy) { $desc += "  Managed by $($r.Source): change it there." }
    $c.AsrDetDescription.Text = $desc
    $c.AsrDetImpactIcon.Text = $row.ImpactGlyph; $c.AsrDetImpactIcon.Foreground = $row.ImpactBrush
    $c.AsrDetImpactLevel.Text = $row.Impact; $c.AsrDetImpactLevel.Foreground = $row.ImpactBrush
    $c.AsrDetImpact.Text = [string]$r.GamerImpact
    $allowed = @($r.AllowedModes | ForEach-Object { [string]$_ })
    foreach ($pair in @(@('AsrModeNotConfigured', 'NotConfigured'), @('AsrModeAudit', 'Audit'), @('AsrModeWarn', 'Warn'), @('AsrModeBlock', 'Block'))) {
        $rb = $c[$pair[0]]
        $ok = ($allowed -contains $pair[1]) -and -not $r.ManagedByPolicy
        $rb.IsEnabled = $ok
        $rb.IsChecked = ([string]$r.Mode -eq $pair[1] -or ($pair[1] -eq 'NotConfigured' -and [string]$r.Mode -eq 'Off'))
        $rb.ToolTip = $(if ($r.ManagedByPolicy) { "Managed by $($r.Source); change it there." } elseif ($ok) { @{ NotConfigured = 'Off: the Windows default, the rule does nothing.'; Audit = 'Audit: only logs what the rule would block.'; Warn = 'Warn: blocks, but the user can unblock it for 24 hours.'; Block = 'Block: blocks the behaviour.' }[$pair[1]] } else { "This rule does not support $($script:IgwtAsrModeLabel[$pair[1]]) (Microsoft supports: $($row.Supported))." })
        [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($rb, $true)
    }
    $c.AsrDetSources.ItemsSource = @($r.Sources)
    Update-IgwtGuiAsrExclusionList
}

function Get-IgwtGuiAsrPickedMode {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $c = $script:Gui.C
    foreach ($pair in @(@('AsrModeNotConfigured', 'NotConfigured'), @('AsrModeAudit', 'Audit'), @('AsrModeWarn', 'Warn'), @('AsrModeBlock', 'Block'))) { if ($c[$pair[0]].IsChecked) { return $pair[1] } }
    return ''
}

function Update-IgwtGuiAsrButtons {
    <# .SYNOPSIS Enabled state of the ASR buttons, with the reason in the mode help line. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if (-not $script:Gui.Grids.Asr) { return }
    $busy = [bool]$script:Gui.Job
    $row = Get-IgwtGuiGridItem -Name Asr
    $active = [bool]$script:Gui.AsrStatus -and [bool]$script:Gui.AsrStatus.DefenderActive
    $canChange = (-not $busy) -and $script:Gui.IsAdmin -and -not (Test-IgwtReadOnly) -and $active
    $c.AsrRefreshButton.IsEnabled = -not $busy
    $c.AsrRecommendButton.IsEnabled = $canChange
    $c.AsrPromoteButton.IsEnabled = $canChange -and [bool]$script:Gui.AsrAudit -and [bool]$script:Gui.AsrAudit.Readable
    $picked = Get-IgwtGuiAsrPickedMode
    $why = ''
    if (-not $row) { $why = 'Select a rule.' }
    elseif ($row.Rule.ManagedByPolicy) { $why = "Managed by $($row.Rule.Source)." }
    elseif (-not $script:Gui.IsAdmin -or (Test-IgwtReadOnly)) { $why = 'Changes need administrator rights and are off in read-only mode.' }
    elseif (-not $active) { $why = 'Microsoft Defender Antivirus is not active.' }
    elseif ($picked -eq [string]$row.Rule.Mode -or ($picked -eq 'NotConfigured' -and [string]$row.Rule.Mode -eq 'Off')) { $why = 'Pick a different mode to change it.' }
    $c.AsrSetModeButton.IsEnabled = $canChange -and -not $why
    $c.AsrModeHelp.Text = $(if ($row -and $why -and $why -ne 'Pick a different mode to change it.') { $why } elseif ($row -and [string]$row.ImpactKey -in 'medium', 'high' -and $picked -in 'Block', 'Warn') { "Gamer impact is $($row.ImpactKey): check its events before blocking." } else { '' })
    $c.AsrAddExclusionButton.IsEnabled = $canChange -and ([bool]$row -or [bool]$c.AsrGlobalBox.IsChecked)
    $c.AsrRemoveExclusionButton.IsEnabled = $canChange -and [bool]$c.AsrExclusionList.SelectedItem
    $c.AsrAuditExcludeButton.IsEnabled = [bool](Get-IgwtGuiGridItem -Name AsrEvents)
}

function Update-IgwtGuiAsrExclusionList {
    <# .SYNOPSIS The selected rule's per-rule exclusions, or the global ASR exclusions when 'global' is ticked. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $items = @()
    if ([bool]$c.AsrGlobalBox.IsChecked) {
        if ($script:Gui.AsrStatus) {
            $g = $script:Gui.AsrStatus.GlobalExclusions
            if ($g.Readable) { $items = @($g.Paths) } else { $c.AsrExclusionList.ToolTip = [string]$g.Note }
        }
    } else { $row = Get-IgwtGuiGridItem -Name Asr; if ($row) { $items = @($row.Rule.Exclusions) } }
    $c.AsrExclusionList.ItemsSource = $items
    Update-IgwtGuiAsrButtons
}

#endregion

#region Changes

function Invoke-IgwtGuiAsrChange {
    <# .SYNOPSIS Confirms, runs one ASR change in the background (snapshot first), offers Undo and reads the real modes back. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Parameters, [Parameter(Mandatory = $true)][string]$Description)
    if (-not $script:Gui.IsAdmin -or (Test-IgwtReadOnly)) { Set-IgwtGuiStatus 'ASR changes need administrator rights and are off in read-only mode.'; return }
    if ((Show-IgwtGuiMessage -Text "$Description`n`nA snapshot is written first; Undo restores the earlier modes." -Title 'iG Windows Tuner - ASR Center' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtAsrChange' -Parameters $Parameters -Blocking -BusyText 'Changing ASR settings (snapshot first)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count -or -not $res) { Show-IgwtGuiError -Message "The change was not made: $(@($errs)[0])" -Context 'ASR' }
        else {
            $failed = @($res.Results | Where-Object Result -EQ 'Failed')
            if ($failed.Count) { Show-IgwtGuiError -Message "$($failed.Count) ASR change(s) failed: $($failed[0].Target): $($failed[0].Message)" -Context 'ASR' }
            if ($res.Changes -gt 0 -and $res.Snapshot) { Show-IgwtGuiToast -Text "$(@($res.Results | Where-Object Result -NE 'Failed').Count) ASR change(s) made." -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiAsrUndo -Snapshot $snap } -ActionArgument ([string]$res.Snapshot) }
            elseif ($res.Changes -eq 0) { Show-IgwtGuiToast -Text 'Nothing to change.' -Tone Info }
        }
        # Always show what Defender reports now, not what was asked for.
        Start-IgwtGuiAsrRefresh
    }
}

function Invoke-IgwtGuiAsrUndo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Snapshot)
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtRevert' -Parameters @{ SnapshotPath = $Snapshot } -Blocking -BusyText 'Undoing the ASR change...' -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { Show-IgwtGuiError -Message "Undo failed: $(@($errs)[0])" -Context 'ASR' } else { Show-IgwtGuiToast -Text 'The ASR change was undone.' -Tone Info }
        Start-IgwtGuiAsrRefresh
    }
}

function Invoke-IgwtGuiAsrSetMode {
    [CmdletBinding()]
    param()
    $row = Get-IgwtGuiGridItem -Name Asr
    $mode = Get-IgwtGuiAsrPickedMode
    if (-not $row -or -not $mode) { return }
    $extra = ''
    if ($mode -in 'Block', 'Warn' -and [string]$row.ImpactKey -in 'medium', 'high') { $extra = "`n`nGamer impact is $($row.ImpactKey): $($row.Rule.GamerImpact) Check its events first." }
    if ($mode -eq 'NotConfigured' -and [string]$row.Rule.Category -eq 'standard') { $extra = "`n`nThis is a standard protection rule that Microsoft recommends keeping in Block." }
    Invoke-IgwtGuiAsrChange -Parameters @{ RuleMode = @{ ([string]$row.Id) = $mode } } -Description "Set '$($row.Name)' from $($row.Mode) to $($script:IgwtAsrModeLabel[$mode])?$extra"
}

function Invoke-IgwtGuiAsrBulkMode {
    <# .SYNOPSIS Bulk "set mode": rules that do not support the mode or are managed by policy are listed and left alone. #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [Parameter(Mandatory = $true)][ValidateSet('NotConfigured', 'Audit', 'Warn', 'Block')][string]$Mode)
    $ok = New-Object System.Collections.Generic.List[object]; $skip = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows | Where-Object { $_ })) {
        if ($r.Rule.ManagedByPolicy) { $skip.Add("$($r.Name): managed by $($r.Rule.Source)"); continue }
        if (@($r.Rule.AllowedModes) -notcontains $Mode) { $skip.Add("$($r.Name): does not support $($script:IgwtAsrModeLabel[$Mode])"); continue }
        if ([string]$r.Rule.Mode -eq $Mode) { continue }
        $ok.Add($r)
    }
    if ($ok.Count -eq 0) { $null = Show-IgwtGuiMessage -Text ("Nothing to change." + $(if ($skip.Count) { "`n`n" + ($skip -join "`n") } else { '' })) -Title 'iG Windows Tuner - ASR Center' -Icon 'Information'; return }
    $map = @{}; foreach ($r in $ok) { $map[[string]$r.Id] = $Mode }
    $lines = @($ok | ForEach-Object { "- $($_.Name): $($_.Mode) -> $($script:IgwtAsrModeLabel[$Mode])" })
    if ($skip.Count) { $lines += ''; $lines += 'Left as they are:'; $lines += @($skip | ForEach-Object { "- $_" }) }
    Invoke-IgwtGuiAsrChange -Parameters @{ RuleMode = $map } -Description ("Set $($ok.Count) rule(s) to $($script:IgwtAsrModeLabel[$Mode])?`n`n" + ($lines -join "`n"))
}

function Invoke-IgwtGuiAsrExclusion {
    <# .SYNOPSIS Adds (-Add) or removes an exclusion for the selected rule or for every rule (global). #>
    [CmdletBinding()]
    param([switch]$Add)
    $c = $script:Gui.C
    $global = [bool]$c.AsrGlobalBox.IsChecked
    $row = Get-IgwtGuiGridItem -Name Asr
    if ($Add) {
        $path = ([string]$c.AsrExclusionBox.Text).Trim()
        if (-not $path) { Set-IgwtGuiStatus 'Type the full path of the program to exclude first.'; return }
        $check = Test-IgwtAsrExclusion -Path $path
        if (-not $check.Valid) { Show-IgwtGuiError -Message "This exclusion is refused: $($check.Reason)" -Context 'ASR'; return }
        if (-not $global -and -not $row) { Set-IgwtGuiStatus 'Select a rule (or tick global) first.'; return }
        $params = @{ AddExclusion = @($path) }
        $scope = 'every ASR rule (global exclusion)'
        if (-not $global) { $params.ExclusionRule = [string]$row.Id; $scope = "'$($row.Name)' only" }
        $notes = $(if (@($check.Warnings).Count) { "`n`n" + (@($check.Warnings) -join "`n") } else { '' })
        Invoke-IgwtGuiAsrChange -Parameters $params -Description "Exclude`n$path`nfrom ${scope}?$notes`n`nDefender applies exclusions when the program next starts."
        return
    }
    $path = [string]$c.AsrExclusionList.SelectedItem
    if (-not $path) { return }
    $params = @{ RemoveExclusion = @($path) }
    $scope = 'the global ASR exclusions'
    if (-not $global) { if (-not $row) { return }; $params.ExclusionRule = [string]$row.Id; $scope = "the exclusions of '$($row.Name)'" }
    Invoke-IgwtGuiAsrChange -Parameters $params -Description "Remove`n$path`nfrom ${scope}?"
}

function Use-IgwtGuiAsrEventAsExclusion {
    <# .SYNOPSIS Opens the rule of the selected event and copies its suggested file into the exclusion box (nothing is added yet). #>
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $sel = Get-IgwtGuiGridItem -Name AsrEvents
    if (-not $sel) { return }
    if ($sel.RuleId) {
        $g = $script:Gui.Grids.Asr
        $match = @($g.C.Grid.ItemsSource | Where-Object { $_.Id -eq $sel.RuleId }) | Select-Object -First 1
        if ($match) { $c.AsrTabs.SelectedIndex = 0; $g.C.Grid.SelectedItem = $match; $g.C.Grid.ScrollIntoView($match) }
    }
    if ($sel.Exclusion) {
        $c.AsrGlobalBox.IsChecked = $false
        $c.AsrExclusionBox.Text = [string]$sel.Exclusion
        Update-IgwtGuiAsrExclusionList
        Set-IgwtGuiStatus 'Suggested file copied. Review it, then press Add exclusion (only if you trust the program).'
    } else { Set-IgwtGuiStatus 'No exclusion is suggested for this event; see its advice.' }
}

function Get-IgwtAsrPromotionPlan {
    <#
    .SYNOPSIS
        Audit-to-Block review: every rule in Audit with its events of the period and a suggestion
        (Block when quiet, review the programs first, or keep auditing). Pure: reads the status and
        the audit view the page already has.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Status, $Audit)
    $byId = @{}
    if ($Audit -and $Audit.Readable) { foreach ($r in @($Audit.Rules)) { $byId[[string]$r.Id] = $r } }
    foreach ($r in @($Status.Rules | Where-Object { [string]$_.Mode -eq 'Audit' -and -not $_.ManagedByPolicy })) {
        $a = $byId[[string]$r.Id]
        $events = $(if ($a) { [int]$a.Total } else { 0 })
        $programs = @($(if ($a) { @($a.Programs) }))
        $canBlock = @($r.AllowedModes) -contains 'Block'
        $suggest = $(if (-not $canBlock) { 'Keep' } elseif ($events -eq 0) { 'Block' } elseif ([string]$r.GamerImpactLevel -in 'medium', 'high') { 'Review' } else { 'Review' })
        [pscustomobject]@{
            Id = [string]$r.Id; Name = [string]$r.Name; Events = $events; Impact = [string]$r.GamerImpactLevel; Suggestion = $suggest; Recommended = ($suggest -eq 'Block')
            Programs = @($programs | ForEach-Object { "$($_.Path) ($($_.Count)x): $($_.Suggestion)" })
            Why = $(switch ($suggest) { 'Block' { 'No events in the period: blocking it is unlikely to break anything.' } 'Review' { "$events event(s): check the programs it reported; exclude the ones you trust, then block." } default { 'This rule does not support Block.' } })
        }
    }
}

function Show-IgwtGuiAsrPromote {
    <# .SYNOPSIS The Audit-to-Block review: a preview of the rules to move, with their events; nothing changes until it is confirmed. #>
    [CmdletBinding()]
    param()
    if (-not $script:Gui.AsrStatus) { return }
    $plan = @(Get-IgwtAsrPromotionPlan -Status $script:Gui.AsrStatus -Audit $script:Gui.AsrAudit)
    if ($plan.Count -eq 0) { Show-IgwtGuiToast -Text 'No rule is in Audit; nothing to move to Block.' -Tone Info; return }
    $ready = @($plan | Where-Object Recommended)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Rules in Audit and their events of the last $($script:Gui.AsrAudit.Days) days:"); $lines.Add('')
    foreach ($p in $plan) {
        $lines.Add("[$($p.Suggestion)] $($p.Name): $($p.Events) event(s), gamer impact $($p.Impact)")
        $lines.Add("    $($p.Why)")
        foreach ($x in @($p.Programs | Select-Object -First 5)) { $lines.Add("    - $x") }
    }
    $lines.Add('')
    if ($ready.Count) { $lines.Add("Moving the $($ready.Count) quiet rule(s) to Block. The others stay in Audit; review their programs on the Events tab first.") }
    else { $lines.Add('No rule is quiet enough to block now. Review the programs on the Events tab, add exclusions for the ones you trust, then try again.') }
    $accept = $(if ($ready.Count) { "Move $($ready.Count) rule(s) to Block" } else { '' })
    if (-not (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - Audit to Block (preview, nothing changed yet)' -Text ($lines -join [Environment]::NewLine) -AcceptText $accept -CancelText 'Close')) { return }
    $map = @{}; foreach ($p in $ready) { $map[$p.Id] = 'Block' }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtAsrChange' -Parameters @{ RuleMode = $map } -Blocking -BusyText 'Moving rules to Block (snapshot first)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count -or -not $res) { Show-IgwtGuiError -Message "The change was not made: $(@($errs)[0])" -Context 'ASR' }
        elseif ($res.Snapshot) { Show-IgwtGuiToast -Text "$($res.Changes) rule(s) moved to Block." -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiAsrUndo -Snapshot $snap } -ActionArgument ([string]$res.Snapshot) }
        Start-IgwtGuiAsrRefresh
    }
}

#endregion
