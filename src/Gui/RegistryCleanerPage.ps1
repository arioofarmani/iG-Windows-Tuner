# RegistryCleanerPage.ps1
# Clean > Registry cleaner (DECISIONS RG20, RG21, RG23): a SmartGrid 'cleaner.registry' with the
# findings of Get-IgwtRegistryLeftovers, grouped by program and category, a tick box per removable
# row (nothing is ticked after a scan), the preview from Format-IgwtRegCleanPlan, the restore point
# question, the journaled removal (Invoke-IgwtRegistryCleanup) and the restore paths: Restore last
# cleanup, the row action Restore on the Removed view and the toast Undo. Each restore builds its own
# Get-IgwtRevertPlan (-SessionId or -EntryId) and calls Show-IgwtGuiJournalPlan directly; the Journal
# page and its grid are never read. The page holds no cleaner logic: every check runs in the engine.

$script:IgwtRegCleanGuiGlyph = @{ Safe = [string][char]0xE73E; Review = [string][char]0xE946; Protected = [string][char]0xEA18; Removed = [string][char]0xE81C }
$script:IgwtRegCleanGuiTone = @{ Safe = 'Pass'; Review = 'Info'; Protected = 'Warn'; Removed = 'Muted' }
$script:IgwtRegCleanGuiRank = @{ Safe = '1'; Review = '2'; Protected = '3'; Removed = '4' }
$script:IgwtRegCleanGuiDetailHint = 'Select an entry to see all of its evidence. Right-click an entry for Restore, Never show this again, Open removal tool or Open in Manage.'
$script:IgwtRegCleanGuiTips = @{
    RegRemoveButton  = 'Preview the ticked entries, then remove them after your confirmation. Every removal is backed up and journaled.'
    RegRestoreButton = 'Restore the entries of the last registry cleanup, after a preview.'
}

#region Rows

function Get-IgwtGuiRegCleanKeyText {
    <#
    .SYNOPSIS
        The Key column text of a finding: HIVE\path[\value], the task path or the firewall rule name,
        with "(32-bit view)" for the 32-bit registry view. Pure.
    .PARAMETER Finding
        A Get-IgwtRegistryLeftovers finding.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Finding)
    $f = $Finding
    if ([string]$f.Kind -eq 'firewallRule') { return "Firewall rule $([string]$f.RuleName)" }
    if (-not [string]$f.Hive) { return [string]$f.Path }
    $k = "$([string]$f.Hive)\$(([string]$f.Path).Trim('\'))"
    if ([string]$f.Kind -eq 'regValue') { $k = $k + '\' + $(if ([string]$f.ValueName) { [string]$f.ValueName } else { '(Default)' }) }
    if ([string]$f.View -eq '32') { $k = $k + ' (32-bit view)' }
    return $k
}

function New-IgwtGuiRegCleanRow {
    <#
    .SYNOPSIS
        SmartGrid row for one registry cleaner finding: tick box (only for removable Safe and Review
        rows), program, category, key, confidence (glyph and word) and the evidence. Never throws on
        sparse data.
    .PARAMETER Finding
        A Get-IgwtRegistryLeftovers finding (DECISIONS RG3).
    .PARAMETER Selected
        True when the finding is ticked.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [bool]$Selected)
    $f = $Finding
    $conf = [string]$f.Confidence
    if ($conf -notin 'Safe', 'Review', 'Protected') { $conf = 'Review' }
    $cat = [string]$f.Category
    $catText = $(if ($script:IgwtRegCleanCategoryLabels.ContainsKey($cat)) { $script:IgwtRegCleanCategoryLabels[$cat] } else { $cat })
    $removable = [bool]$f.Selectable -and $conf -in 'Safe', 'Review' -and [string]$f.Kind -in 'regKeyTree', 'regValue', 'firewallRule'
    $evidence = @($f.Evidence | Where-Object { $null -ne $_ } | ForEach-Object { '{0}: {1}{2}' -f [string]$_.Check, [string]$_.Result, $(if ([string]$_.Detail) { '  ' + [string]$_.Detail } else { '' }) })
    $first = @($f.Evidence | Where-Object { $null -ne $_ } | Select-Object -First 1)
    $program = $(if ([string]$f.Program) { [string]$f.Program } elseif ([string]$f.OwnerHint) { [string]$f.OwnerHint } else { '(unnamed)' })
    $why = $(if ([string]$f.Reason) { [string]$f.Reason } elseif ($conf -eq 'Protected') { 'Security software: use the vendor''s removal tool.' } else { 'This entry cannot be removed.' })
    $row = [ordered]@{
        Key = 'f|' + [string]$f.Id; Id = [string]$f.Id; View = 'Found'; Finding = $f; EntryId = ''; Kind = [string]$f.Kind; CategoryId = $cat
        On = ($removable -and $Selected); OnEnabled = $removable; OnName = "Remove $program"
        OnTip = $(if ($removable) { 'Tick to include this entry in Remove selected.' } else { $why })
        Program = $program; ProgramTip = $(if ([string]$f.OwnerHint) { "$program (from $([string]$f.OwnerHint))" } else { $program })
        CategoryText = $catText; KeyText = (Get-IgwtGuiRegCleanKeyText -Finding $f)
        ConfidenceKey = $conf; ConfidenceRank = $script:IgwtRegCleanGuiRank[$conf]
        Evidence = $(if ($first.Count) { '{0}: {1}' -f [string]$first[0].Check, $(if ([string]$first[0].Detail) { [string]$first[0].Detail } else { [string]$first[0].Result }) } else { '' })
        EvidenceTip = ($evidence -join [Environment]::NewLine); EvidenceAll = ($evidence -join ' ')
    }
    $label = $(if ($conf -eq 'Protected') { 'Protected' } else { $conf })
    Add-IgwtGuiStatusField -Row $row -Name 'Confidence' -Text $label -Tone $script:IgwtRegCleanGuiTone[$conf]
    $row.ConfidenceGlyph = $script:IgwtRegCleanGuiGlyph[$conf]
    return [pscustomobject]$row
}

function ConvertFrom-IgwtGuiRegCleanTargetKey {
    <#
    .SYNOPSIS
        Splits a regClean journal target key ('regclean|<kind>|<hive>|<sid or ->|<view>|<path>[|<name>]')
        into {Kind; Hive; View; Path; Name}. Pure; an unknown key gives empty fields.
    .PARAMETER Key
        The journal target key.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Key)
    $p = ([string]$Key).Split('|')
    $get = { param($i) if ($p.Count -gt $i) { [string]$p[$i] } else { '' } }
    $name = $(if ($p.Count -gt 6) { ($p[6..($p.Count - 1)]) -join '|' } else { '' })
    return [pscustomobject]@{ Kind = (& $get 1); Hive = (& $get 2); View = (& $get 4); Path = (& $get 5); Name = $name }
}

function New-IgwtGuiRegCleanRemovedRow {
    <#
    .SYNOPSIS
        SmartGrid row for one removed entry (a Get-IgwtJournalTimeline row of origin regClean that is
        still in effect), shown on the Removed view with the row action Restore.
    .PARAMETER Row
        The journal timeline row.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $t = ConvertFrom-IgwtGuiRegCleanTargetKey -Key ([string]$Row.Target)
    $cat = ([string]$Row.Item) -replace '^regclean:', ''
    $catText = $(if ($script:IgwtRegCleanCategoryLabels.ContainsKey($cat)) { $script:IgwtRegCleanCategoryLabels[$cat] } else { $cat })
    $when = ''
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Row.When, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) { $when = $dt.ToLocalTime().ToString('g') }
    $finding = [pscustomobject]@{ Kind = $t.Kind; Hive = $t.Hive; View = $t.View; Path = $t.Path; ValueName = $(if ($t.Kind -eq 'regValue') { $t.Name } else { '' }); RuleName = $(if ($t.Kind -eq 'firewallRule') { $t.Name } else { '' }) }
    $title = $(if ([string]$Row.SessionTitle) { [string]$Row.SessionTitle } else { 'Registry cleanup' })
    $r = [ordered]@{
        Key = 'r|' + [string]$Row.EntryId; Id = [string]$Row.EntryId; View = 'Removed'; Finding = $null; EntryId = [string]$Row.EntryId; Session = [string]$Row.Session; Kind = $t.Kind; CategoryId = $cat
        On = $false; OnEnabled = $false; OnName = 'Removed entry'; OnTip = 'Removed entries come back with Restore (right-click the entry).'
        Program = $(if ($when) { "$title, $when" } else { $title }); ProgramTip = $title
        CategoryText = $catText; KeyText = (Get-IgwtGuiRegCleanKeyText -Finding $finding)
        ConfidenceKey = 'Removed'; ConfidenceRank = $script:IgwtRegCleanGuiRank['Removed']
        Evidence = $(if ($when) { "Removed $when; a restore puts it back as it was." } else { 'Removed; a restore puts it back as it was.' })
        EvidenceTip = "Session $([string]$Row.Session), step $([string]$Row.Step). Restore creates only what is missing and refuses when the program wrote the key again."
        EvidenceAll = [string]$Row.Target
    }
    Add-IgwtGuiStatusField -Row $r -Name 'Confidence' -Text 'Removed' -Tone $script:IgwtRegCleanGuiTone['Removed']
    $r.ConfidenceGlyph = $script:IgwtRegCleanGuiGlyph['Removed']
    return [pscustomobject]$r
}

function Get-IgwtGuiRegCleanExclusionSpec {
    <#
    .SYNOPSIS
        The exclusion entry (DECISIONS RG13) that hides one finding: {Scope; Pattern; Why}. A key for
        key trees and services, a value for named values, the program path for a firewall rule. Scope
        is '' with the reason in Why when the row cannot be excluded on its own. Pure.
    .PARAMETER Finding
        A Get-IgwtRegistryLeftovers finding.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $f = $Finding
    $none = { param($why) [pscustomobject]@{ Scope = ''; Pattern = ''; Why = $why } }
    $esc = { param($s) [System.Management.Automation.WildcardPattern]::Escape([string]$s) }
    $scope = ''; $pattern = ''
    $hive = [string]$f.Hive
    $path = ([string]$f.Path).Trim('\')
    switch ([string]$f.Kind) {
        'regValue' {
            if (-not [string]$f.ValueName) { return (& $none 'The default value of a key cannot be excluded on its own.') }
            $scope = 'value'; $pattern = "$hive\" + (& $esc "$path\$([string]$f.ValueName)")
        }
        'firewallRule' {
            $prog = $(if ($f.PSObject.Properties['Facts'] -and $f.Facts -and $f.Facts.PSObject.Properties['Program']) { [string]$f.Facts.Program } else { '' })
            if ($prog -notmatch '^([A-Za-z]:\\|%[A-Za-z0-9_()]+%\\)') { return (& $none 'This firewall rule names no program path to exclude.') }
            $scope = 'path'; $pattern = (& $esc $prog)
        }
        default {
            if ($hive -notin 'HKLM', 'HKCU' -or -not $path) { return (& $none 'This entry has no registry key to exclude.') }
            $scope = 'key'; $pattern = "$hive\" + (& $esc $path)
        }
    }
    if ($pattern.Length -gt 512 -or $pattern -match '[^\x20-\x7E]') { return (& $none 'The exclusion list stores only printable ASCII patterns of up to 512 characters.') }
    return [pscustomobject]@{ Scope = $scope; Pattern = $pattern; Why = '' }
}

function Get-IgwtGuiRegCleanRemovalTool {
    <#
    .SYNOPSIS
        What "Open removal tool" does for a row: {Url (https only, else ''); Text}. Pure.
    .PARAMETER Finding
        A Protected finding with RemovalTool {Name; Url; Text}.
    #>
    [CmdletBinding()]
    param($Finding)
    $t = $(if ($Finding -and $Finding.PSObject.Properties['RemovalTool']) { $Finding.RemovalTool } else { $null })
    $url = $(if ($t -and [string]$t.Url -match '^https://[^\s]+$') { [string]$t.Url } else { '' })
    $text = $(if ($t -and [string]$t.Text) { [string]$t.Text } elseif ($t -and [string]$t.Name) { [string]$t.Name } else { 'No removal tool is known for this program; contact its vendor.' })
    return [pscustomobject]@{ Url = $url; Text = $text }
}

function ConvertTo-IgwtGuiRegCleanRestorePointChoice {
    <#
    .SYNOPSIS
        Maps the answer to the restore point question (DECISIONS RG21) to the cleanup switches:
        {Cancel; SkipRestorePoint; EnableSystemProtection}. Pure.
    .PARAMETER Answer
        Yes, No or Cancel.
    .PARAMETER SystemProtectionOn
        True when System Protection is on for the system drive.
    #>
    [CmdletBinding()]
    param([string]$Answer, [bool]$SystemProtectionOn)
    $cancel = $Answer -notin 'Yes', 'No'
    return [pscustomobject]@{
        Cancel                 = $cancel
        SkipRestorePoint       = (-not $cancel -and $Answer -eq 'No')
        EnableSystemProtection = (-not $cancel -and $Answer -eq 'Yes' -and -not $SystemProtectionOn)
    }
}

function Format-IgwtGuiRegCleanResult {
    <#
    .SYNOPSIS
        The text of the result dialog after a registry cleanup: one line per entry with its result
        and message, the backup folder, the restore point and how to restore. Pure.
    .PARAMETER Result
        An Invoke-IgwtRegistryCleanup result.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Result)
    $lines = New-Object System.Collections.Generic.List[string]
    if ([string]$Result.Message) { $lines.Add([string]$Result.Message); $lines.Add('') }
    foreach ($r in @($Result.Results | Where-Object { $null -ne $_ })) {
        $what = $(if ([string]$r.RuleName -and -not [string]$r.Path) { "Firewall rule $([string]$r.RuleName)" } else { "$(if ([string]$r.Hive) { [string]$r.Hive + '\' })$([string]$r.Path)$(if ([string]$r.ValueName) { '\' + [string]$r.ValueName })" })
        $lines.Add(('{0,-11} {1}{2}' -f [string]$r.Result, $what, $(if ([string]$r.Program) { "  ($([string]$r.Program))" } else { '' })))
        if ([string]$r.Message) { $lines.Add("            $([string]$r.Message)") }
    }
    $lines.Add('')
    if ([string]$Result.Backup) { $lines.Add("Backup folder: $([string]$Result.Backup)") }
    if ($Result.RestorePoint) { $lines.Add("Restore point: $(if ($Result.RestorePoint.Created) { 'created' } else { 'not created (' + [string]$Result.RestorePoint.Reason + ')' })") }
    if ([string]$Result.SessionId) { $lines.Add('Restore: Undo in the message, Restore last cleanup on this page, or Backups > Change journal.') }
    return ($lines.ToArray() -join [Environment]::NewLine)
}

#endregion

#region Page

function Initialize-IgwtGuiRegistryCleanerPage {
    <#
    .SYNOPSIS
        Builds the Registry cleaner page: the SmartGrid 'cleaner.registry' (grouped by program, then
        category), its chips and row actions, and the button handlers.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $script:Gui.RegClean = @{ Scan = $null; Selected = @{}; Timeline = @(); RemovedLoaded = $false; RemovedStale = $false; LastSessionId = ''; Notes = @() }
    $chips = @(
        @{ Id = 'safe'; Label = 'Safe'; Group = 'conf'; Field = 'ConfidenceKey'; Values = @('Safe'); Tip = 'Every reference is proven missing and nothing installed owns the entry' }
        @{ Id = 'review'; Label = 'Review'; Group = 'conf'; Field = 'ConfidenceKey'; Values = @('Review'); Tip = 'Probably left over; read the evidence before you tick it' }
        @{ Id = 'security'; Label = 'Security software'; Group = 'conf'; Field = 'ConfidenceKey'; Values = @('Protected'); Tip = 'Left by security software: never removed here; use the vendor''s removal tool' }
        @{ Id = 'selected'; Label = 'Selected'; Group = 'sel'; Test = { param($row) [bool]$script:Gui.RegClean.Selected[[string]$row.Id] }; Tip = 'Only the ticked entries (also ticks hidden by a search)' }
        @{ Id = 'removed'; Label = 'Removed'; Group = 'view'; Field = 'View'; Values = @('Removed'); Tip = 'Entries removed by earlier cleanups that can still be restored' }
    )
    foreach ($cat in $script:IgwtRegCleanScanOrder) {
        $chips += @{ Id = "cat-$cat"; Label = $script:IgwtRegCleanCategoryLabels[$cat]; Group = 'cat'; Field = 'CategoryId'; Values = @($cat); More = $true }
    }
    $actions = @(
        @{ Id = 'restore'; Label = 'Restore...'; Changes = $true; Tip = 'Preview and restore this removed entry'
            CanRun = { param($rows) if (@($rows | Where-Object { [string]$_.View -ne 'Removed' -or -not [string]$_.EntryId }).Count) { 'Restore is for entries on the Removed view.' } else { '' } }
            Run = { param($rows) $r = @($rows)[0]; $null = Start-IgwtGuiRegCleanRevert -EntryId ([string]$r.EntryId) -Title "Restore: $([string]$r.KeyText)" } }
        @{ Id = 'exclude'; Label = 'Never show this again'; Changes = $true; Tip = 'Add this entry to the exclusion list (asks for a reason); the PC is not changed'
            CanRun = { param($rows) $r = @($rows)[0]; if ([string]$r.View -ne 'Found' -or -not $r.Finding) { 'Only found entries can be excluded.' } else { [string](Get-IgwtGuiRegCleanExclusionSpec -Finding $r.Finding).Why } }
            Run = { param($rows) Invoke-IgwtGuiRegCleanExclude -Row (@($rows)[0]) } }
        @{ Id = 'tool'; Label = 'Open removal tool'; Tip = 'Open the vendor''s removal tool page (https only) or show the vendor''s advice'
            CanRun = { param($rows) if ([string]@($rows)[0].ConfidenceKey -ne 'Protected') { 'Only for security software entries.' } else { '' } }
            Run = { param($rows) Open-IgwtGuiRegCleanRemovalTool -Row (@($rows)[0]) } }
        @{ Id = 'manage'; Label = 'Open in Manage'; Tip = 'Show this service or scheduled task on the Manage page, where it can be disabled'
            CanRun = { param($rows) $r = @($rows)[0]; if ([string]$r.Kind -ne 'reportOnly' -or [string]$r.CategoryId -notin 'service', 'task') { 'Only for services and scheduled tasks.' } else { '' } }
            Run = { param($rows) Open-IgwtGuiRegCleanInManage -Row (@($rows)[0]) } }
    )
    $g = New-IgwtSmartGrid -Id 'cleaner.registry' -Noun 'entries' -RowKey 'Key' -SearchPlaceholder 'Search programs, keys and evidence' -SelectionMode Single `
        -EmptyTitle 'No scan yet' -EmptyText 'Press Scan to look for entries left behind by programs that are no longer installed. A scan changes nothing.' `
        -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiRegCleanScan } `
        -OnSelectionChanged { param($grid, $rows) Set-IgwtGuiRegCleanGrouping -Grid $grid; Update-IgwtGuiRegCleanDetail -Row (@($rows) | Select-Object -First 1) } `
        -OnBeforeQuery { param($grid) Set-IgwtGuiRegCleanScope -Grid $grid } -Columns @(
        @{ Key = 'On'; Header = 'Remove'; Width = 76; MinWidth = 56; Template = 'Toggle'; Search = $false }
        @{ Key = 'Program'; Header = 'Program'; Width = 210; MinWidth = 140; Tip = 'ProgramTip' }
        @{ Key = 'CategoryText'; Header = 'Category'; Width = 150; Search = $false }
        @{ Key = 'KeyText'; Header = 'Key'; MinWidth = 220; Template = 'Mono'; Tip = 'KeyText' }
        @{ Key = 'Confidence'; Header = 'Confidence'; Width = 130; Template = 'Status'; SortKey = 'ConfidenceRank'; Search = $false; Tip = 'OnTip' }
        @{ Key = 'Evidence'; Header = 'Evidence'; Width = 320; Tip = 'EvidenceTip' }
        @{ Key = 'EvidenceAll'; Header = 'All evidence'; Width = 320; Visible = $false }
        @{ Key = 'View'; Header = 'View'; Width = 90; Visible = $false; Search = $false }
    ) -Chips $chips -Actions $actions
    Add-IgwtGuiListGrid -Name 'RegList' -Grid $g -SortBy 'Program', 'CategoryText', 'KeyText' -Empty
    # Group headers (program, then category); the descriptions are set on every new default view.
    $dg = $g.C.Grid
    [System.Windows.Controls.VirtualizingPanel]::SetIsVirtualizingWhenGrouping($dg, $true)
    $gs = New-Object System.Windows.Controls.GroupStyle
    $gs.HeaderTemplate = [Windows.Markup.XamlReader]::Parse('<DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"><TextBlock Text="{Binding Name, Mode=OneWay}" FontWeight="SemiBold" Margin="6,8,0,2" Foreground="{DynamicResource BrushTextMuted}"/></DataTemplate>')
    $dg.GroupStyle.Add($gs)

    $c = $script:Gui.C
    $c.RegDetailText.Text = $script:IgwtRegCleanGuiDetailHint
    $c.RegNoteText.Text = 'No scan yet.'
    Register-IgwtGuiHandler -Control $c.RegScanButton -Event 'Click' -Handler { Start-IgwtGuiRegCleanScan }
    Register-IgwtGuiHandler -Control $c.RegCancelButton -Event 'Click' -Handler { if ($script:Gui.Cts) { $script:Gui.Cts.Cancel(); Set-IgwtGuiStatus 'Stopping the scan after the current entry...' } }
    Register-IgwtGuiHandler -Control $c.RegSelectSafeButton -Event 'Click' -Handler { Select-IgwtGuiRegCleanSafe }
    Register-IgwtGuiHandler -Control $c.RegClearButton -Event 'Click' -Handler { Clear-IgwtGuiRegCleanSelection }
    Register-IgwtGuiHandler -Control $c.RegRemoveButton -Event 'Click' -Handler { Invoke-IgwtGuiRegCleanRemove }
    Register-IgwtGuiHandler -Control $c.RegRestoreButton -Event 'Click' -Handler { Invoke-IgwtGuiRegCleanRestoreLast }
    Register-IgwtGuiHandler -Control $c.RegExclusionsButton -Event 'Click' -Handler { Start-IgwtGuiRegCleanExclusions }
    Register-IgwtGuiHandler -Control $g.Root -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
        param($eventSource, $e)
        $null = $eventSource
        $cb = $e.OriginalSource
        if (-not ($cb -is [System.Windows.Controls.CheckBox]) -or -not [string]$cb.Tag) { return }
        Set-IgwtGuiRegCleanTick -Key ([string]$cb.Tag) -On ([bool]$cb.IsChecked) -Row $cb.DataContext
    }
    Update-IgwtGuiRegCleanButtons
}

function Set-IgwtGuiRegCleanScope {
    <#
    .SYNOPSIS
        Before every query: the Removed chip switches the grid between found and removed entries (a
        scope, so it does not count as a user filter) and loads the removed entries when needed.
    .PARAMETER Grid
        The cleaner.registry grid.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $removed = $Grid.ActiveChips.Contains('removed')
    $Grid.Scope = @{ View = @($(if ($removed) { 'Removed' } else { 'Found' })) }
    $rc = $(if ($script:Gui) { $script:Gui.RegClean } else { $null })
    if ($removed -and $rc -and (-not $rc.RemovedLoaded -or $rc.RemovedStale) -and $script:Gui.Runspace) { $null = Start-IgwtGuiRegCleanRemovedLoad }
}

function Set-IgwtGuiRegCleanGrouping {
    <#
    .SYNOPSIS
        Groups the rows by program, then category, on the grid's current default CollectionView
        (CollectionViewSource.GetDefaultView). The SmartGrid sets a new item array on every query, so
        this runs after each one (from the selection callback). SmartGrid.ps1 is not changed.
    .PARAMETER Grid
        The cleaner.registry grid.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $src = $Grid.C.Grid.ItemsSource
    if ($null -eq $src) { return }
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($src)
    if ($null -eq $view -or -not $view.CanGroup -or $view.GroupDescriptions.Count -gt 0) { return }
    $view.GroupDescriptions.Add((New-Object System.Windows.Data.PropertyGroupDescription('Program')))
    $view.GroupDescriptions.Add((New-Object System.Windows.Data.PropertyGroupDescription('CategoryText')))
}

function Get-IgwtGuiRegCleanSelection {
    <# .SYNOPSIS The ticked findings of the current scan that can be removed (Safe or Review, selectable, a removable kind). #>
    [CmdletBinding()]
    param()
    $rc = $(if ($script:Gui) { $script:Gui.RegClean } else { $null })
    if (-not $rc -or -not $rc.Scan) { return @() }
    return @($rc.Scan.Findings | Where-Object { $null -ne $_ -and $rc.Selected[[string]$_.Id] -and [bool]$_.Selectable -and [string]$_.Confidence -in 'Safe', 'Review' -and [string]$_.Kind -in 'regKeyTree', 'regValue', 'firewallRule' })
}

function Update-IgwtGuiRegCleanList {
    <# .SYNOPSIS Rebuilds the rows (found entries of the last scan and removed entries), keeping search, chips and sort. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $rc = $script:Gui.RegClean
    if (-not $rc) { return }
    $rows = New-Object System.Collections.Generic.List[object]
    if ($rc.Scan) { foreach ($f in @($rc.Scan.Findings | Where-Object { $null -ne $_ })) { $rows.Add((New-IgwtGuiRegCleanRow -Finding $f -Selected ([bool]$rc.Selected[[string]$f.Id]))) } }
    foreach ($t in @($rc.Timeline | Where-Object { $null -ne $_ -and $_.InEffect -and [string]$_.EntryId })) { $rows.Add((New-IgwtGuiRegCleanRemovedRow -Row $t)) }
    Set-IgwtGuiGridRows -Name 'RegList' -Rows $rows.ToArray()
    $g = $script:Gui.Grids['RegList']
    if ($g) { Set-IgwtGuiRegCleanGrouping -Grid $g }
    Update-IgwtGuiRegCleanButtons
}

function Set-IgwtGuiRegCleanScan {
    <#
    .SYNOPSIS
        Shows a scan result. The selection is cleared on every scan: nothing is ticked until the user
        chooses it.
    .PARAMETER Scan
        A Get-IgwtRegistryLeftovers result (or $null).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Scan)
    if (-not $PSCmdlet.ShouldProcess('registry cleaner scan', 'Show')) { return }
    $rc = $script:Gui.RegClean
    $rc.Scan = $Scan
    $rc.Selected = @{}
    $notes = @($(if ($Scan) { @($Scan.Notes | Where-Object { $_ }) }))
    $rc.Notes = $notes
    $script:Gui.C.RegNoteText.Text = $(if (-not $Scan) { 'No scan yet.' } elseif ($notes.Count) { ($notes | ForEach-Object { [string]$_ + '.' }) -join ' ' } else { '' })
    $script:Gui.C.RegDetailText.Text = $script:IgwtRegCleanGuiDetailHint
    Update-IgwtGuiRegCleanList
}

function Set-IgwtGuiRegCleanTimeline {
    <#
    .SYNOPSIS
        Keeps the regClean rows of the change journal (for the Removed view and Restore last cleanup).
    .PARAMETER Timeline
        A Get-IgwtJournalTimeline result.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Timeline)
    if (-not $PSCmdlet.ShouldProcess('registry cleaner history', 'Show')) { return }
    $rc = $script:Gui.RegClean
    $rc.Timeline = @($(if ($Timeline) { @($Timeline.Rows | Where-Object { $null -ne $_ -and [string]$_.Origin -eq 'regClean' }) }))
    $rc.RemovedLoaded = $true
    $rc.RemovedStale = $false
    Update-IgwtGuiRegCleanList
}

function Set-IgwtGuiRegCleanTick {
    <#
    .SYNOPSIS
        A tick box changed: updates the selection, the row and the Selected chip, and shows "N selected".
    .PARAMETER Key
        The row key ('f|<finding id>').
    .PARAMETER On
        The new state.
    .PARAMETER Row
        The row object of the box (its On field follows the box; the binding is one-way).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Key, [bool]$On, $Row)
    if (-not $Key.StartsWith('f|') -or -not $PSCmdlet.ShouldProcess($Key, 'Tick')) { return }
    $rc = $script:Gui.RegClean
    $id = $Key.Substring(2)
    if ($On) { $rc.Selected[$id] = $true } else { $null = $rc.Selected.Remove($id) }
    if ($Row -and $Row.PSObject.Properties['On']) { $Row.On = $On }
    $g = $script:Gui.Grids['RegList']
    if ($g) { $null = $g.Index.Chips.Remove('selected') }
    Set-IgwtGuiStatus ('{0} selected' -f @(Get-IgwtGuiRegCleanSelection).Count)
    Update-IgwtGuiRegCleanButtons
}

function Select-IgwtGuiRegCleanSafe {
    <#
    .SYNOPSIS
        Ticks every removable Safe entry of the scan, also those hidden by a search or chip, and says
        "N selected" so hidden ticks are visible.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $rc = $script:Gui.RegClean
    if (-not $rc -or -not $rc.Scan -or -not $PSCmdlet.ShouldProcess('Safe entries', 'Tick')) { return }
    foreach ($f in @($rc.Scan.Findings | Where-Object { $null -ne $_ -and [string]$_.Confidence -eq 'Safe' -and [bool]$_.Selectable -and [string]$_.Kind -in 'regKeyTree', 'regValue', 'firewallRule' })) { $rc.Selected[[string]$f.Id] = $true }
    Update-IgwtGuiRegCleanList
    $n = @(Get-IgwtGuiRegCleanSelection).Count
    $g = $script:Gui.Grids['RegList']
    $shown = $(if ($g) { @(Get-IgwtGridViewRows -Grid $g | Where-Object { $_.On }).Count } else { $n })
    Set-IgwtGuiStatus $(if ($shown -lt $n) { "$n selected ($($n - $shown) hidden by the current filter)" } else { "$n selected" })
}

function Clear-IgwtGuiRegCleanSelection {
    <# .SYNOPSIS Unticks every entry. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $rc = $script:Gui.RegClean
    if (-not $rc -or -not $PSCmdlet.ShouldProcess('registry cleaner selection', 'Clear')) { return }
    $rc.Selected = @{}
    Update-IgwtGuiRegCleanList
    Set-IgwtGuiStatus '0 selected'
}

function Update-IgwtGuiRegCleanButtons {
    <# .SYNOPSIS Enables the page buttons for the current state; change buttons are off in read-only or non-admin windows. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui -or -not $script:Gui.C -or -not $script:Gui.C.RegScanButton) { return }
    $c = $script:Gui.C
    $busy = [bool]$script:Gui.Job
    $rc = $script:Gui.RegClean
    $n = @(Get-IgwtGuiRegCleanSelection).Count
    $block = Get-IgwtGuiChangeBlockReason -What 'remove or restore registry entries'
    $c.RegScanButton.IsEnabled = -not $busy
    $c.RegCancelButton.IsEnabled = $busy -and [bool]$script:Gui.Cts -and [string]$script:Gui.Job.Command -eq 'Get-IgwtRegistryLeftovers'
    $c.RegSelectSafeButton.IsEnabled = [bool]($rc -and $rc.Scan)
    $c.RegClearButton.IsEnabled = $n -gt 0
    $c.RegRemoveButton.IsEnabled = (-not $busy) -and $n -gt 0 -and -not $block
    $c.RegRemoveButton.ToolTip = $(if ($block) { $block } else { $script:IgwtRegCleanGuiTips['RegRemoveButton'] })
    $c.RegRestoreButton.IsEnabled = (-not $busy) -and -not $block
    $c.RegRestoreButton.ToolTip = $(if ($block) { $block } else { $script:IgwtRegCleanGuiTips['RegRestoreButton'] })
    $c.RegExclusionsButton.IsEnabled = -not $busy
}

function Update-IgwtGuiRegCleanDetail {
    <#
    .SYNOPSIS
        The detail line under the grid: the selected entry's full evidence, why it cannot be ticked
        and the removal tool advice.
    .PARAMETER Row
        The selected row ($null for the hint).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Row)
    $t = $script:Gui.C.RegDetailText
    if (-not $t) { return }
    if (-not $Row) { $t.Text = $script:IgwtRegCleanGuiDetailHint; return }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('{0}  |  {1}  |  {2}' -f [string]$Row.Program, [string]$Row.CategoryText, [string]$Row.KeyText))
    if ([string]$Row.EvidenceTip) { $lines.Add([string]$Row.EvidenceTip) }
    if ([string]$Row.View -eq 'Found' -and -not $Row.OnEnabled) { $lines.Add("Not removable here: $([string]$Row.OnTip)") }
    if ([string]$Row.ConfidenceKey -eq 'Protected') { $lines.Add('Removal tool: ' + [string](Get-IgwtGuiRegCleanRemovalTool -Finding $Row.Finding).Text) }
    $t.Text = ($lines.ToArray() -join [Environment]::NewLine)
}

#endregion

#region Scan, remove, restore

function Start-IgwtGuiRegCleanScan {
    <#
    .SYNOPSIS
        Runs Get-IgwtRegistryLeftovers as a foreground job with a cancel token; a cancelled scan
        shows the entries checked so far.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only scan.')]
    [CmdletBinding()]
    param()
    $cts = New-Object System.Threading.CancellationTokenSource
    $script:Gui.Cts = $cts
    $started = Start-IgwtGuiJob -Command 'Get-IgwtRegistryLeftovers' -Parameters @{ CancelToken = $cts.Token } -BusyText 'Scanning the registry (read-only, nothing is changed)...' -OnComplete {
        param($out, $errs)
        $script:Gui.Cts = $null
        $scan = @($out | Where-Object { $null -ne $_ }) | Select-Object -Last 1
        if ($scan) {
            Set-IgwtGuiRegCleanScan -Scan $scan
            Set-IgwtGuiStatus $(if ($scan.Cancelled) { 'Scan stopped. The entries checked so far are shown.' } else { 'Scan finished.' })
        } else {
            Set-IgwtGuiStatus 'The scan did not finish; see the log.'
            if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The registry scan stopped: $(@($errs)[0])" -Icon 'Error' }
        }
        Update-IgwtGuiButtons
    }
    if (-not $started) { $script:Gui.Cts = $null; $cts.Dispose(); return }
    $g = $script:Gui.Grids['RegList']
    if ($g) { Set-IgwtGridState -Grid $g -State 'Loading' }
}

function Start-IgwtGuiRegCleanRemovedLoad {
    <#
    .SYNOPSIS
        Reads the change journal in the background (channel 'regcleanremoved') for the Removed view.
    .PARAMETER Then
        'restoreLast' continues with Restore last cleanup once the journal is read.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Then)
    return (Start-IgwtGuiJob -Command 'Get-IgwtJournalTimeline' -Channel 'regcleanremoved' -BusyText 'Reading the change journal...' -Context @{ Then = $Then } -OnComplete {
            param($out, $errs, $ctx)
            $t = @($out | Where-Object { $null -ne $_ }) | Select-Object -Last 1
            if (-not $t) { if (@($errs).Count) { Set-IgwtGuiStatus "The change journal could not be read: $(@($errs)[0])" }; return }
            Set-IgwtGuiRegCleanTimeline -Timeline $t
            if ($ctx.Then -eq 'restoreLast') { Invoke-IgwtGuiRegCleanRestoreLast -NoLoad }
        })
}

function Invoke-IgwtGuiRegCleanRemove {
    <#
    .SYNOPSIS
        Remove selected...: builds the plan in the worker (channel 'regcleanplan'; every entry is
        checked again), then shows the preview (Show-IgwtGuiRegCleanPlan).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only plan; the change runs after the confirmed preview.')]
    [CmdletBinding()]
    param()
    $block = Get-IgwtGuiChangeBlockReason -What 'remove registry entries'
    if ($block) { $null = Show-IgwtGuiMessage -Text $block; return }
    $sel = @(Get-IgwtGuiRegCleanSelection)
    if (-not $sel.Count) { Set-IgwtGuiStatus 'Tick the entries to remove first.'; return }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtRegCleanPlan' -Parameters @{ Findings = $sel } -Channel 'regcleanplan' -BusyText 'Checking the ticked entries again (read-only)...' -OnComplete {
        param($out, $errs)
        $plan = @($out | Where-Object { $null -ne $_ }) | Select-Object -Last 1
        if (-not $plan) { $null = Show-IgwtGuiMessage -Text "The preview could not be built: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })" -Icon 'Error'; return }
        Show-IgwtGuiRegCleanPlan -Plan $plan
    }
}

function Show-IgwtGuiRegCleanPlan {
    <#
    .SYNOPSIS
        Shows the preview (Format-IgwtRegCleanPlan); on Remove... checks System Protection in the
        worker and continues with Complete-IgwtGuiRegCleanRemove.
    .PARAMETER Plan
        A Get-IgwtRegCleanPlan result.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The change runs only after the user confirms the preview.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Plan)
    $text = Format-IgwtRegCleanPlan -Plan $Plan
    $title = 'iG Windows Tuner - registry cleanup preview'
    if (-not @($Plan.Targets | Where-Object { $null -ne $_ }).Count) { $null = Show-IgwtGuiTextDialog -Title $title -Text $text; return }
    if (-not (Show-IgwtGuiTextDialog -Title $title -Text $text -AcceptText 'Remove...' -CancelText 'Cancel')) { Set-IgwtGuiStatus 'Nothing was changed.'; return }
    $null = Start-IgwtGuiJob -Command 'Test-IgwtSystemProtectionEnabled' -Channel 'precheck' -BusyText 'Checking System Protection...' -Context $Plan -OnComplete {
        param($out, $errs, $ctx)
        $null = $errs
        Complete-IgwtGuiRegCleanRemove -Plan $ctx -SystemProtectionOn ([bool](@($out) | Select-Object -Last 1))
    }
}

function Complete-IgwtGuiRegCleanRemove {
    <#
    .SYNOPSIS
        Asks the restore point question (DECISIONS RG21), then runs Invoke-IgwtRegistryCleanup as a
        blocking job (the preview was the confirmation) and shows the result with a toast Undo.
    .PARAMETER Plan
        The previewed Get-IgwtRegCleanPlan result.
    .PARAMETER SystemProtectionOn
        True when System Protection is on for the system drive.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs after the confirmed preview.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Plan, [bool]$SystemProtectionOn)
    $text = $(if ($SystemProtectionOn) {
            "Create a System Restore point before the removal?`n`nYes: create a restore point, then remove.`nNo: remove with the change journal and the backup folder only.`nCancel: do not remove anything."
        } else {
            "System Protection is off for $env:SystemDrive, so no restore point can be created.`n`nYes: turn System Protection on for $env:SystemDrive and create a restore point.`nNo: remove with the change journal and the backup folder only.`nCancel: do not remove anything."
        })
    $choice = ConvertTo-IgwtGuiRegCleanRestorePointChoice -Answer (Show-IgwtGuiMessage -Text $text -Buttons 'YesNoCancel' -Icon 'Question') -SystemProtectionOn $SystemProtectionOn
    if ($choice.Cancel) { Set-IgwtGuiStatus 'Nothing was changed.'; return }
    $params = @{ Plan = $Plan; SkipRestorePoint = [bool]$choice.SkipRestorePoint; EnableSystemProtection = [bool]$choice.EnableSystemProtection; Confirm = $false }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtRegistryCleanup' -Parameters $params -Blocking -BusyText 'Removing the ticked entries (backup first, every step journaled)...' -OnComplete {
        param($out, $errs)
        $r = @($out | Where-Object { $null -ne $_ }) | Select-Object -Last 1
        if (-not $r) {
            $null = Show-IgwtGuiMessage -Text "The registry cleanup did not run: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })`n`nNothing was removed." -Icon 'Error'
            return
        }
        Complete-IgwtGuiRegCleanResult -Result $r
    }
}

function Complete-IgwtGuiRegCleanResult {
    <#
    .SYNOPSIS
        After a cleanup: the result dialog, the removed entries leave the found list, the selection
        is cleared, the Removed view is read again and a toast offers Undo for this session.
    .PARAMETER Result
        An Invoke-IgwtRegistryCleanup result.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Result)
    if (-not $PSCmdlet.ShouldProcess('registry cleanup result', 'Show')) { return }
    $rc = $script:Gui.RegClean
    $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - registry cleanup result' -Text (Format-IgwtGuiRegCleanResult -Result $Result)
    if ([string]$Result.SessionId) { $rc.LastSessionId = [string]$Result.SessionId }
    $gone = @($Result.Results | Where-Object { $null -ne $_ -and [string]$_.Result -eq 'Removed' } | ForEach-Object { [string]$_.Id })
    if ($rc.Scan -and $gone.Count) {
        $rc.Scan = $rc.Scan | Select-Object *
        $rc.Scan.Findings = @($rc.Scan.Findings | Where-Object { $null -ne $_ -and $gone -notcontains [string]$_.Id })
    }
    $rc.Selected = @{}
    $rc.RemovedStale = $true
    Update-IgwtGuiRegCleanList
    if ($script:Gui.Runspace) { $null = Start-IgwtGuiRegCleanRemovedLoad }
    Set-IgwtGuiStatus 'Registry cleanup finished.'
    if ([string]$Result.SessionId -and $gone.Count) {
        Show-IgwtGuiToast -Text 'Registry cleanup finished. Every removed entry can be restored.' -Tone Success -ActionText 'Undo' -Action { param($sid) $null = Start-IgwtGuiRegCleanRevert -SessionId $sid -Title 'Undo registry cleanup' } -ActionArgument ([string]$Result.SessionId)
    }
    Update-IgwtGuiRegCleanButtons
}

function Start-IgwtGuiRegCleanRevert {
    <#
    .SYNOPSIS
        Builds the revert plan of one cleanup (-SessionId) or one removed entry (-EntryId) in the
        worker (channel 'regcleanrevert') and shows it with Show-IgwtGuiJournalPlan. The Journal
        page and its selection are never used (DECISIONS RG20).
    .PARAMETER SessionId
        The change session of a cleanup.
    .PARAMETER EntryId
        One journal entry of a cleanup.
    .PARAMETER Title
        The preview title.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query; the change runs after the confirmed preview.')]
    [CmdletBinding(DefaultParameterSetName = 'Session')]
    [OutputType([bool])]
    param([Parameter(ParameterSetName = 'Session', Mandatory = $true)][string]$SessionId,
        [Parameter(ParameterSetName = 'Entry', Mandatory = $true)][string]$EntryId, [string]$Title = 'Restore registry entries')
    $block = Get-IgwtGuiChangeBlockReason -What 'restore registry entries'
    if ($block) { $null = Show-IgwtGuiMessage -Text $block; return $false }
    $p = $(if ($PSCmdlet.ParameterSetName -eq 'Entry') { @{ EntryId = $EntryId } } else { @{ SessionId = $SessionId } })
    return (Start-IgwtGuiJob -Command 'Get-IgwtRevertPlan' -Parameters $p -Channel 'regcleanrevert' -BusyText 'Comparing the backup with the registry now...' -Context @{ Title = $Title } -OnComplete {
            param($out, $errs, $ctx)
            if (@($errs).Count -and -not @($out).Count) { $null = Show-IgwtGuiMessage -Text "The restore preview failed: $(@($errs)[0])" -Icon 'Error'; return }
            if ($script:Gui.RegClean) { $script:Gui.RegClean.RemovedStale = $true }
            Show-IgwtGuiJournalPlan -Plan @($out | Where-Object { $_ }) -Title $ctx.Title
        })
}

function Get-IgwtGuiRegCleanLastSessionId {
    <#
    .SYNOPSIS
        The session of the last cleanup: the one this window ran, otherwise the newest regClean
        session of the change journal ('' when none is known).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $rc = $script:Gui.RegClean
    if (-not $rc) { return '' }
    if ([string]$rc.LastSessionId) { return [string]$rc.LastSessionId }
    $newest = @($rc.Timeline | Where-Object { $null -ne $_ -and [string]$_.Session } | Sort-Object { [string]$_.When } -Descending | Select-Object -First 1)
    if ($newest.Count) { return [string]$newest[0].Session }
    return ''
}

function Invoke-IgwtGuiRegCleanRestoreLast {
    <#
    .SYNOPSIS
        Restore last cleanup...: the revert preview of the last cleanup session (the journal is read
        first when this window has not read it yet).
    .PARAMETER NoLoad
        Do not read the journal again (it was just read).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query; the change runs after the confirmed preview.')]
    [CmdletBinding()]
    param([switch]$NoLoad)
    $block = Get-IgwtGuiChangeBlockReason -What 'restore registry entries'
    if ($block) { $null = Show-IgwtGuiMessage -Text $block; return }
    $sid = Get-IgwtGuiRegCleanLastSessionId
    if ($sid) { $null = Start-IgwtGuiRegCleanRevert -SessionId $sid -Title 'Restore last registry cleanup'; return }
    if (-not $NoLoad -and -not $script:Gui.RegClean.RemovedLoaded) { $null = Start-IgwtGuiRegCleanRemovedLoad -Then 'restoreLast'; return }
    $null = Show-IgwtGuiMessage -Text 'The change journal holds no registry cleanup yet.'
}

#endregion

#region Exclusions and row actions

function Get-IgwtGuiRegCleanReasonText {
    <# .SYNOPSIS A reason the exclusion list accepts: printable ASCII only, at most 200 characters. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    $t = (([string]$Text) -replace '[^\x20-\x7E]', ' ' -replace '\s+', ' ').Trim()
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200).Trim() }
    return $t
}

function Invoke-IgwtGuiRegCleanExclude {
    <#
    .SYNOPSIS
        Never show this again: asks for a reason, reads the exclusion list (channel 'regcleanexcl'),
        adds the entry and saves the list (blocking job). The PC is not changed.
    .PARAMETER Row
        A found row.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Saves only after the user gives a reason.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $block = Get-IgwtGuiChangeBlockReason -What 'change the exclusion list'
    if ($block) { $null = Show-IgwtGuiMessage -Text $block; return }
    if (-not $Row.Finding) { return }
    $spec = Get-IgwtGuiRegCleanExclusionSpec -Finding $Row.Finding
    if (-not $spec.Scope) { $null = Show-IgwtGuiMessage -Text $spec.Why; return }
    $reason = Get-IgwtGuiRegCleanReasonText -Text (Read-IgwtGuiText -Title 'Never show this again' -Prompt "Why should iG never show this again? The reason is saved with the exclusion ($($spec.Scope) $($spec.Pattern)).")
    if (-not $reason) { Set-IgwtGuiStatus 'Not excluded: a reason is needed.'; return }
    $ctx = @{ Scope = $spec.Scope; Pattern = $spec.Pattern; Reason = $reason; Id = [string]$Row.Id }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtRegCleanExclusions' -Channel 'regcleanexcl' -BusyText 'Reading the exclusion list...' -Context $ctx -OnComplete {
        param($out, $errs, $ctx)
        $doc = @($out | Where-Object { $null -ne $_ }) | Select-Object -Last 1
        if (-not $doc) { $null = Show-IgwtGuiMessage -Text "The exclusion list could not be read: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })" -Icon 'Error'; return }
        $entries = @($doc.Entries | Where-Object { $null -ne $_ })
        if (@($entries | Where-Object { [string]$_.scope -eq $ctx.Scope -and [string]$_.pattern -eq $ctx.Pattern }).Count) { Set-IgwtGuiStatus 'This entry is already on the exclusion list.'; return }
        $entries += [pscustomobject]@{ pattern = $ctx.Pattern; scope = $ctx.Scope; reason = $ctx.Reason; addedUtc = '' }
        Save-IgwtGuiRegCleanExclusionList -Entries $entries -HideId $ctx.Id -Done "Excluded: $($ctx.Pattern). It is no longer shown."
    }
}

function Save-IgwtGuiRegCleanExclusionList {
    <#
    .SYNOPSIS
        Saves the whole exclusion list in the worker (Save-IgwtRegCleanExclusions, blocking job) and
        hides an excluded finding from the list.
    .PARAMETER Entries
        The complete new list.
    .PARAMETER HideId
        A finding id to take off the list once saved.
    .PARAMETER Done
        The toast text after the save.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [string]$HideId, [string]$Done = 'Exclusion list saved.')
    if (-not $PSCmdlet.ShouldProcess('registry cleaner exclusion list', 'Save in the background')) { return }
    $null = Start-IgwtGuiJob -Command 'Save-IgwtRegCleanExclusions' -Parameters @{ Entries = $Entries; Confirm = $false } -Blocking -BusyText 'Saving the exclusion list...' -Context @{ HideId = $HideId; Done = $Done } -OnComplete {
        param($out, $errs, $ctx)
        $null = $out
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The exclusion list was not saved: $(@($errs)[0])" -Icon 'Error'; return }
        $rc = $script:Gui.RegClean
        if ($ctx.HideId -and $rc.Scan) {
            $rc.Scan = $rc.Scan | Select-Object *
            $rc.Scan.Findings = @($rc.Scan.Findings | Where-Object { $null -ne $_ -and [string]$_.Id -ne $ctx.HideId })
            $null = $rc.Selected.Remove($ctx.HideId)
            Update-IgwtGuiRegCleanList
        }
        Show-IgwtGuiToast -Text $ctx.Done -Tone Success
    }
}

function Start-IgwtGuiRegCleanExclusions {
    <# .SYNOPSIS Exclusions...: reads the list in the worker (channel 'regcleanexcl'), shows it and saves the entries kept. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query; saving needs the dialog.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtRegCleanExclusions' -Channel 'regcleanexcl' -BusyText 'Reading the exclusion list...' -OnComplete {
        param($out, $errs)
        $doc = @($out | Where-Object { $null -ne $_ }) | Select-Object -Last 1
        if (-not $doc) { $null = Show-IgwtGuiMessage -Text "The exclusion list could not be read: $(if (@($errs).Count) { @($errs)[0] } else { 'no result' })" -Icon 'Error'; return }
        $kept = Show-IgwtGuiRegCleanExclusions -Entries @($doc.Entries | Where-Object { $null -ne $_ }) -Path ([string]$doc.Path)
        if ($null -ne $kept) { Save-IgwtGuiRegCleanExclusionList -Entries @($kept) -Done 'Exclusion list saved. Scan again to see the entries it no longer hides.' }
    }
}

function Format-IgwtGuiRegCleanExclusion {
    <# .SYNOPSIS One line of the exclusion dialog: scope, pattern, reason and date. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Entry)
    return ('{0,-5}  {1}   ({2}; added {3})' -f [string]$Entry.scope, [string]$Entry.pattern, [string]$Entry.reason, ([string]$Entry.addedUtc -replace 'T.*$', ''))
}

function Show-IgwtGuiRegCleanExclusions {
    <#
    .SYNOPSIS
        The exclusion list dialog: every entry with its reason, Remove for the selected entry, Save
        and Cancel. Returns the entries to keep, or $null when nothing changed.
    .PARAMETER Entries
        The current entries.
    .PARAMETER Path
        The file shown in the dialog.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Shows a dialog; the caller saves.')]
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Entries = @(), [string]$Path)
    $block = Get-IgwtGuiChangeBlockReason -What 'change the exclusion list'
    $w = New-Object System.Windows.Window
    $w.Title = 'iG Windows Tuner - registry cleaner exclusions'; $w.Width = 820; $w.Height = 480; $w.MinWidth = 560; $w.MinHeight = 320
    $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'; $w.ShowInTaskbar = $false
    Copy-IgwtGuiResources -Target $w
    $w.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'BrushSurface')
    $dock = New-Object System.Windows.Controls.DockPanel; $dock.Margin = '16'
    $head = New-Object System.Windows.Controls.TextBlock; $head.TextWrapping = 'Wrap'; $head.Margin = '0,0,0,10'
    $head.Text = "Entries on this list are never shown or removed by the registry cleaner. Removing an entry here shows it again at the next scan; the PC is not changed.`n$Path"
    [System.Windows.Controls.DockPanel]::SetDock($head, 'Top')
    $buttons = New-Object System.Windows.Controls.StackPanel; $buttons.Orientation = 'Horizontal'; $buttons.HorizontalAlignment = 'Right'; $buttons.Margin = '0,12,0,0'
    [System.Windows.Controls.DockPanel]::SetDock($buttons, 'Bottom')
    $list = New-Object System.Windows.Controls.ListBox
    $list.FontFamily = $script:Gui.Window.FindResource('FontMono')
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($list, 'RegExclusionList')
    [System.Windows.Automation.AutomationProperties]::SetName($list, 'Registry cleaner exclusions')
    $state = @{ Window = $w; List = $list; Entries = (New-Object System.Collections.Generic.List[object]); Changed = $false; Saved = $false }
    foreach ($e in $Entries) { $state.Entries.Add($e); $null = $list.Items.Add((Format-IgwtGuiRegCleanExclusion -Entry $e)) }
    if (-not $state.Entries.Count) { $null = $list.Items.Add('(no exclusions)'); $list.IsEnabled = $false }
    $script:Gui.RegClean.ExclusionDialog = $state
    $remove = New-Object System.Windows.Controls.Button; $remove.Content = 'Remove'; $remove.Margin = '0,0,8,0'
    $remove.ToolTip = $(if ($block) { $block } else { 'Take the selected entry off the list (saved with Save)' }); $remove.IsEnabled = (-not $block) -and $state.Entries.Count -gt 0
    [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($remove, $true)
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($remove, 'RegExclusionRemoveButton')
    $save = New-Object System.Windows.Controls.Button; $save.Content = 'Save'; $save.Margin = '0,0,8,0'; $save.IsEnabled = $false
    $save.ToolTip = 'Save the list without the removed entries'
    $save.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'AccentButton')
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($save, 'RegExclusionSaveButton')
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.IsCancel = $true; $cancel.ToolTip = 'Close without changing the list'
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($cancel, 'RegExclusionCancelButton')
    $state.Save = $save
    Register-IgwtGuiHandler -Control $remove -Event 'Click' -Handler {
        $s = $script:Gui.RegClean.ExclusionDialog
        $i = $s.List.SelectedIndex
        if ($i -lt 0 -or $i -ge $s.Entries.Count) { Set-IgwtGuiStatus 'Select an exclusion first.'; return }
        $s.Entries.RemoveAt($i); $s.List.Items.RemoveAt($i); $s.Changed = $true; $s.Save.IsEnabled = $true
    }
    Register-IgwtGuiHandler -Control $save -Event 'Click' -Handler { $s = $script:Gui.RegClean.ExclusionDialog; $s.Saved = $true; $s.Window.Close() }
    Register-IgwtGuiHandler -Control $cancel -Event 'Click' -Handler { $script:Gui.RegClean.ExclusionDialog.Window.Close() }
    $null = $buttons.Children.Add($remove); $null = $buttons.Children.Add($save); $null = $buttons.Children.Add($cancel)
    $null = $dock.Children.Add($head); $null = $dock.Children.Add($buttons); $null = $dock.Children.Add($list)
    $w.Content = $dock
    $null = $w.ShowDialog()
    $script:Gui.RegClean.ExclusionDialog = $null
    if ($state.Saved -and $state.Changed) { return , $state.Entries.ToArray() }
    return $null
}

function Open-IgwtGuiRegCleanRemovalTool {
    <#
    .SYNOPSIS
        Open removal tool: opens the vendor's https removal tool page, or shows the vendor's advice
        when there is no confirmed tool page (DECISIONS RG11).
    .PARAMETER Row
        A Protected row.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Opens a web page the user asked for.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $t = Get-IgwtGuiRegCleanRemovalTool -Finding $Row.Finding
    if ($t.Url) { Open-IgwtGuiPath -Target $t.Url; Set-IgwtGuiStatus "Opened $($t.Url)"; return }
    $null = Show-IgwtGuiMessage -Text $t.Text -Title 'Removal tool'
}

function Open-IgwtGuiRegCleanInManage {
    <#
    .SYNOPSIS
        Open in Manage: switches to the Manage page and its Services or Scheduled tasks tab, with the
        entry's name in the search box (services and tasks are report-only here, DECISIONS RG34).
    .PARAMETER Row
        A report-only service or task row.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window navigation only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $f = $Row.Finding
    $isTask = [string]$Row.CategoryId -eq 'task'
    $name = ''
    if ($f -and $f.PSObject.Properties['Facts'] -and $f.Facts -and $f.Facts.PSObject.Properties['Name']) { $name = [string]$f.Facts.Name }
    if (-not $name -and $f) { $name = $(if ($isTask) { [string]$f.Program } else { [string]$f.OwnerHint }) }
    Select-IgwtGuiNavPage -Tag 'Manage'
    $script:Gui.C.ManageTabs.SelectedIndex = $(if ($isTask) { 1 } else { 0 })
    $g = $script:Gui.Grids[$(if ($isTask) { 'Task' } else { 'Service' })]
    if ($g -and $name) { $g.C.SearchBox.Text = $name }
}

#endregion
