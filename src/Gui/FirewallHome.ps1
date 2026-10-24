# FirewallHome.ps1
# Firewall Manager 3.4 interface: Overview (home), group sidebar, 3.4 details pane, group actions with preview,
# quick wins and the smart fix wizard. Every change goes through Invoke-IgwtGuiFirewallChange (summary or preview,
# snapshot, Undo); read-only mode keeps every change button off.
$script:IgwtFwGroupGlyph = @{
    All = [string][char]0xE8FD; CoreServices = [string][char]0xE72E; WindowsConnections = [string][char]0xE7F8; UserInstalled = [string][char]0xE7B8; CustomRules = [string][char]0xE70F
    Inbound = [string][char]0xE896; Outbound = [string][char]0xE898; Blocked = [string][char]0xE733; Bloated = [string][char]0xE74D; SecurityRisks = [string][char]0xE7BA
}

function Get-IgwtGuiFirewallGroupItems {
    <# .SYNOPSIS The sidebar and tile items: All rules plus the nine groups with live counts, icon, tone and hint. #>
    [CmdletBinding()]
    param($Summary)
    $kb = Get-IgwtFirewallKnowledgeBase
    $items = New-Object System.Collections.Generic.List[object]
    $total = $(if ($Summary) { [int]$Summary.Total } else { 0 })
    $items.Add([pscustomobject]@{ Id = 'All'; Label = 'All rules'; Count = $total; CountText = $(if ($Summary) { '{0:N0}' -f $total } else { '' }); Glyph = $script:IgwtFwGroupGlyph.All; Brush = (Get-IgwtGuiToneBrush -Tone 'Text'); Tip = 'Every firewall rule, including the Windows Service Hardening rules.' })
    foreach ($c in @($kb.Categories | Sort-Object order)) {
        $n = $(if ($Summary) { [int]$Summary.Groups.([string]$c.id) } else { 0 })
        $tone = switch ([string]$c.id) { 'SecurityRisks' { $(if ($n) { 'Warn' } else { 'Pass' }) } 'Bloated' { $(if ($n) { 'Info' } else { 'Pass' }) } 'CoreServices' { 'Muted' } default { 'Text' } }
        $items.Add([pscustomobject]@{ Id = [string]$c.id; Label = [string]$c.name; Count = $n; CountText = $(if ($Summary) { '{0:N0}' -f $n } else { '' }); Glyph = $script:IgwtFwGroupGlyph[[string]$c.id]; Brush = (Get-IgwtGuiToneBrush -Tone $tone); Tip = "$($c.hint) $($c.handling)" })
    }
    return $items.ToArray()
}

function New-IgwtGuiFirewallTile {
    <# .SYNOPSIS One group tile (button): icon, count and name; Tag = group id. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Item)
    $b = New-Object System.Windows.Controls.Button
    $b.Tag = [string]$Item.Id
    $b.Width = 168; $b.Margin = '0,0,8,8'; $b.HorizontalContentAlignment = 'Left'; $b.Padding = '12,10'
    $b.ToolTip = [string]$Item.Tip
    [System.Windows.Automation.AutomationProperties]::SetName($b, "$($Item.Label): $($Item.CountText) rules")
    $sp = New-Object System.Windows.Controls.StackPanel
    $top = New-Object System.Windows.Controls.StackPanel; $top.Orientation = 'Horizontal'
    $g = New-Object System.Windows.Controls.TextBlock; $g.Text = [string]$Item.Glyph; $g.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'FontIcons'); $g.FontSize = 16; $g.Foreground = $Item.Brush; $g.Margin = '0,0,8,0'; $g.VerticalAlignment = 'Center'
    $n = New-Object System.Windows.Controls.TextBlock; $n.Text = [string]$Item.CountText; $n.FontWeight = 'SemiBold'; $n.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, 'FontSizeSubtitle'); $n.VerticalAlignment = 'Center'
    $null = $top.Children.Add($g); $null = $top.Children.Add($n)
    $l = New-Object System.Windows.Controls.TextBlock; $l.Text = [string]$Item.Label; $l.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'TextMuted'); $l.Margin = '0,4,0,0'
    $null = $sp.Children.Add($top); $null = $sp.Children.Add($l)
    $b.Content = $sp
    return $b
}

function Set-IgwtGuiFirewallChart {
    <#
    .SYNOPSIS
        A simple horizontal bar chart (no chart library): one row per value with label, bar and
        number; the text summary next to it carries the same numbers in words.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Panel, [object[]]$Bars = @())
    $Panel.Children.Clear()
    $max = [double](@($Bars | ForEach-Object { [double]$_.Value }) + 1 | Measure-Object -Maximum).Maximum
    foreach ($b in $Bars) {
        $row = New-Object System.Windows.Controls.Grid
        $row.Margin = '0,0,0,6'
        foreach ($w in @(140, -1, 56)) { $cd = New-Object System.Windows.Controls.ColumnDefinition; $cd.Width = $(if ($w -lt 0) { New-Object System.Windows.GridLength(1, 'Star') } else { New-Object System.Windows.GridLength($w) }); $row.ColumnDefinitions.Add($cd) }
        $lab = New-Object System.Windows.Controls.TextBlock; $lab.Text = [string]$b.Label; $lab.VerticalAlignment = 'Center'; $lab.TextTrimming = 'CharacterEllipsis'
        $track = New-Object System.Windows.Controls.Border; $track.Height = 12; $track.CornerRadius = 6; $track.VerticalAlignment = 'Center'; $track.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'BrushSurfaceAlt')
        $bar = New-Object System.Windows.Controls.Border; $bar.Height = 12; $bar.CornerRadius = 6; $bar.HorizontalAlignment = 'Left'; $bar.Background = $b.Brush
        $bar.Width = [Math]::Max([double]0, [double]220 * [double]$b.Value / [double]$max)
        $track.Child = $bar
        $num = New-Object System.Windows.Controls.TextBlock; $num.Text = '{0:N0}' -f [int]$b.Value; $num.HorizontalAlignment = 'Right'; $num.VerticalAlignment = 'Center'
        [System.Windows.Controls.Grid]::SetColumn($track, 1); [System.Windows.Controls.Grid]::SetColumn($num, 2)
        $null = $row.Children.Add($lab); $null = $row.Children.Add($track); $null = $row.Children.Add($num)
        [System.Windows.Automation.AutomationProperties]::SetName($row, "$($b.Label): $($b.Value)")
        $null = $Panel.Children.Add($row)
    }
}

function Update-IgwtGuiFirewallOverview {
    <# .SYNOPSIS Fills the Overview tab from the last audit and profile status. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $a = $script:Gui.Firewall
    $prof = $script:Gui.FirewallProfiles
    # Status line: firewall per profile, active network per adapter, default actions, logging.
    $lines = New-Object System.Collections.Generic.List[string]
    if ($prof) {
        $on = @($prof.Profiles | Where-Object { $_.Enabled })
        $lines.Add("Firewall: $(if ($on.Count -eq @($prof.Profiles).Count) { 'on for every profile' } else { "on for $(@($on | ForEach-Object { $_.Name }) -join ', '); OFF for $(@($prof.Profiles | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name }) -join ', ')" }).")
        $nets = @($prof.Networks | ForEach-Object { "$($_.InterfaceAlias) is on a $($_.Category) network" })
        if ($nets.Count) { $lines.Add(($nets -join '; ') + '.') }
        $lines.Add('Default: ' + (@($prof.Profiles | ForEach-Object { "$($_.Name) blocks inbound$(if ([string]$_.DefaultOutboundAction -eq 'Block') { ' and outbound' } else { ', allows outbound' })" }) -join '; ') + '.')
        $logging = @($prof.Profiles | Where-Object { $_.LogBlocked -or $_.LogAllowed } | ForEach-Object { $_.Name })
        $lines.Add("Logging: $(if ($logging.Count) { "dropped packets are logged for $($logging -join ', ')" } else { 'off' }).")
    } else { $lines.Add('Profiles not read yet.') }
    $c.FwOvStatusText.Text = $lines -join ' '
    if (-not $a) { $c.FwOvAttentionText.Text = 'Reading every firewall rule (read-only)...'; return }
    $s = $a.Summary
    $c.FwOvUpdatedText.Text = Format-IgwtGridAge -Time $a.Read
    # Needs attention: Critical and High risks, one primary action.
    $n = [int]$s.NeedsAttention
    $c.FwOvAttentionTitle.Text = $(if ($n) { "$n rule$(if ($n -ne 1) { 's' }) need$(if ($n -eq 1) { 's' }) attention" } else { 'Nothing needs attention' })
    $c.FwOvAttentionIcon.Text = $(if ($n) { [string][char]0xE7BA } else { [string][char]0xE73E })
    $c.FwOvAttentionIcon.Foreground = Get-IgwtGuiToneBrush -Tone $(if ($n) { 'Warn' } else { 'Pass' })
    $c.FwOvAttentionText.Text = $(if ($n) { "$($s.Severity.Critical) critical and $($s.Severity.High) high-severity finding(s)$(if ($s.Exposed) { "; $($s.Exposed) rule(s) match a port that is open right now" }). Lower findings: $([int]$s.Severity.Medium + [int]$s.Severity.Low)." } else { "No critical or high-severity findings. $([int]$s.Severity.Medium + [int]$s.Severity.Low) lower finding(s) are listed under Security Risks." })
    $open = @($a.Findings | Where-Object { -not $_.Ignored }).Count
    $c.FwOvReviewButton.Content = $(if ($open) { "Review $open finding$(if ($open -ne 1) { 's' })" } else { 'No findings to review' })
    $c.FwOvReviewButton.IsEnabled = [bool]$open
    # Quick wins: enabled bloated rules that can be disabled safely.
    $q = @($s.QuickWins).Count
    $c.FwOvQuickText.Text = $(if ($q) { "$q bloated rule$(if ($q -ne 1) { 's' }) can be disabled safely for a $($a.Role) PC. The preview shows what stops working; every change can be undone." } else { 'No bloated rules to disable for this role.' })
    $c.FwOvQuickButton.Content = $(if ($q) { "Preview $q change$(if ($q -ne 1) { 's' })" } else { 'Nothing to preview' })
    $c.FwOvQuickButton.IsEnabled = [bool]$q
    # Group tiles.
    $c.FwOvTiles.Children.Clear()
    foreach ($it in @(Get-IgwtGuiFirewallGroupItems -Summary $s | Where-Object { $_.Id -ne 'All' })) { $null = $c.FwOvTiles.Children.Add((New-IgwtGuiFirewallTile -Item $it)) }
    # Charts with text summaries.
    $g = $s.Groups
    Set-IgwtGuiFirewallChart -Panel $c.FwOvOriginChart -Bars @(
        [pscustomobject]@{ Label = 'Core Services'; Value = [int]$g.CoreServices; Brush = (Get-IgwtGuiToneBrush -Tone 'Muted') }
        [pscustomobject]@{ Label = 'Windows Connections'; Value = [int]$g.WindowsConnections; Brush = (Get-IgwtGuiToneBrush -Tone 'Info') }
        [pscustomobject]@{ Label = 'User Installed'; Value = [int]$g.UserInstalled; Brush = (Get-IgwtGuiToneBrush -Tone 'Accent') }
        [pscustomobject]@{ Label = 'Custom Rules'; Value = [int]$g.CustomRules; Brush = (Get-IgwtGuiToneBrush -Tone 'Pass') })
    $c.FwOvOriginText.Text = "$($s.Total) rules: $($g.CoreServices) Core Services, $($g.WindowsConnections) Windows Connections, $($g.UserInstalled) User Installed and $($g.CustomRules) Custom Rules. $($s.LowConfidence) classification(s) have low confidence."
    Set-IgwtGuiFirewallChart -Panel $c.FwOvDirChart -Bars @(
        [pscustomobject]@{ Label = 'Inbound allow'; Value = [int]$s.InboundAllow; Brush = (Get-IgwtGuiToneBrush -Tone 'Warn') }
        [pscustomobject]@{ Label = 'Inbound block'; Value = [int]$s.InboundBlock; Brush = (Get-IgwtGuiToneBrush -Tone 'Pass') }
        [pscustomobject]@{ Label = 'Outbound allow'; Value = [int]$s.OutboundAllow; Brush = (Get-IgwtGuiToneBrush -Tone 'Info') }
        [pscustomobject]@{ Label = 'Outbound block'; Value = [int]$s.OutboundBlock; Brush = (Get-IgwtGuiToneBrush -Tone 'Pass') })
    $c.FwOvDirText.Text = "$($s.Enabled) of $($s.Total) rules are enabled: $($s.InboundAllow) allow and $($s.InboundBlock) block inbound traffic, $($s.OutboundAllow) allow and $($s.OutboundBlock) block outbound traffic. Inbound traffic without an allow rule is blocked by default."
    # Exposure map.
    if ($script:Gui.Grids.FirewallExposure) { Set-IgwtGridRows -Grid $script:Gui.Grids.FirewallExposure -Rows @($a.Exposure | Where-Object { $_ } | ForEach-Object { New-IgwtGuiExposureRow -Entry $_ }) }
    $c.FwOvExposureText.Text = $(if ($a.Partial) { 'Programs listening for connections right now. Which rules let traffic reach them needs administrator rights (the port filters are not readable), so the status shows Unknown.' } else { 'Programs listening for connections right now, the rules that let traffic reach them, and whether they are reachable from the network.' })
    # Recent changes with Undo.
    $recent = @($a.RecentChanges | Where-Object { $_ })
    $c.FwOvRecentEmpty.Visibility = $(if ($recent.Count) { 'Collapsed' } else { 'Visible' })
    $c.FwOvRecentList.ItemsSource = @($recent | ForEach-Object { New-IgwtGuiRecentChangeRow -Snapshot $_ })
}

function New-IgwtGuiExposureRow {
    <# .SYNOPSIS SmartGrid row for one exposure map entry (status with icon). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)
    $e = $Entry
    $r = [ordered]@{ Key = [string]$e.Key; PortText = "$($e.Protocol) $($e.LocalPort)"; LocalPort = [int]$e.LocalPort; Protocol = [string]$e.Protocol; Process = [string]$e.Process; Path = [string]$e.Path; Services = [string]$e.Services
        Rules = $(if ($e.Rules) { [string]$e.Rules } else { '-' }); Profiles = $(if ($e.Profiles) { [string]$e.Profiles } else { '-' }); StatusKey = [string]$e.Status; Address = [string]$e.LocalAddress }
    $tone = switch ([string]$e.Status) { 'Exposed' { $(if ($e.Public) { 'Warn' } else { 'Info' }) } 'Blocked' { 'Pass' } 'Local only' { 'Pass' } default { 'Muted' } }
    $text = switch ([string]$e.Status) { 'Exposed' { $(if ($e.Public) { 'Reachable (also on public networks)' } else { 'Reachable' }) } 'Blocked' { 'Blocked by default' } 'Local only' { 'This PC only' } default { 'Unknown' } }
    Add-IgwtGuiStatusField -Row $r -Name 'StatusCol' -Text $text -Tone $tone
    [pscustomobject]$r
}

function New-IgwtGuiRecentChangeRow {
    <# .SYNOPSIS One recent firewall change (snapshot) with an Undo button (Tag = snapshot path). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Snapshot)
    $s = $Snapshot
    $dock = New-Object System.Windows.Controls.DockPanel
    $dock.Margin = '0,0,0,6'
    $b = New-Object System.Windows.Controls.Button
    $b.Content = 'Undo'; $b.Tag = [string]$s.Path; $b.Margin = '8,0,0,0'
    $b.ToolTip = 'Restore the rules exactly as they were before this change (from its snapshot).'
    [System.Windows.Controls.DockPanel]::SetDock($b, 'Right')
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = "$(Format-IgwtGuiTime -Value $s.Created)  $($s.Detail)"
    $t.TextWrapping = 'Wrap'; $t.VerticalAlignment = 'Center'
    $null = $dock.Children.Add($b); $null = $dock.Children.Add($t)
    return $dock
}

$script:IgwtFwActionLabel = @{ RestrictPrivate = 'Restrict to Private'; RestrictLocalSubnet = 'Restrict to local subnet'; Disable = 'Disable'; Delete = 'Delete...'; Keep = 'Keep'; Ignore = 'Ignore...' }

function New-IgwtGuiFirewallChip {
    <# .SYNOPSIS A small membership chip (Badge style) for the details pane. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([string]$Text, [string]$Tone = 'Text', [string]$Tip)
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Badge')
    $b.Margin = '0,0,6,6'
    if ($Tip) { $b.ToolTip = $Tip }
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text; $t.Foreground = Get-IgwtGuiToneBrush -Tone $Tone
    $t.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, 'FontSizeCaption')
    $b.Child = $t
    return $b
}

function New-IgwtGuiFindingCard {
    <#
    .SYNOPSIS
        One finding in the details pane: severity (icon + word), title, explanation, and buttons for
        the recommended action (accent) and the alternatives. Button Tag = "action|riskId".
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [bool]$ReadOnly, $Rule)
    $f = $Finding
    $tone = switch ([string]$f.Severity) { 'Critical' { 'Fail' } 'High' { 'Fail' } 'Medium' { 'Warn' } default { 'Info' } }
    $card = New-Object System.Windows.Controls.Border
    $card.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BrushBorder')
    $card.BorderThickness = 1; $card.CornerRadius = 6; $card.Padding = '10,8'; $card.Margin = '0,0,0,8'
    $sp = New-Object System.Windows.Controls.StackPanel
    $head = New-Object System.Windows.Controls.TextBlock
    $head.TextWrapping = 'Wrap'
    $g = New-Object System.Windows.Documents.Run ((Get-IgwtGuiToneGlyph -Tone $tone) + '  ')
    $g.SetResourceReference([System.Windows.Documents.TextElement]::FontFamilyProperty, 'FontIcons'); $g.Foreground = Get-IgwtGuiToneBrush -Tone $tone
    $sev = New-Object System.Windows.Documents.Run ("$($f.Severity)$(if ($f.ExposedNow) { ', exposed now' })$(if ($f.Ignored) { ', ignored' })  ")
    $sev.Foreground = Get-IgwtGuiToneBrush -Tone $tone; $sev.FontWeight = 'SemiBold'
    $title = New-Object System.Windows.Documents.Run ([string]$f.Title); $title.FontWeight = 'SemiBold'
    $head.Inlines.Add($g); $head.Inlines.Add($sev); $head.Inlines.Add($title)
    $null = $sp.Children.Add($head)
    $ex = New-Object System.Windows.Controls.TextBlock
    $ex.Text = [string]$f.Explanation + $(if ($f.Ignored) { " Ignored: $($f.IgnoreReason)" } else { '' })
    $ex.TextWrapping = 'Wrap'; $ex.Margin = '0,4,0,6'; $ex.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'TextMuted')
    $null = $sp.Children.Add($ex)
    $wrap = New-Object System.Windows.Controls.WrapPanel
    foreach ($act in @(@($f.Recommended) + @($f.Alternatives))) {
        if (-not $act) { continue }
        $b = New-Object System.Windows.Controls.Button
        $b.Content = $(if ($act -eq $f.Recommended) { "$($script:IgwtFwActionLabel[[string]$act]) (recommended)" } else { $script:IgwtFwActionLabel[[string]$act] })
        $b.Tag = "$act|$($f.RiskId)"; $b.Margin = '0,0,6,6'
        if ($act -eq $f.Recommended -and $act -ne 'Keep') { $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'AccentButton') }
        $changes = $act -in 'RestrictPrivate', 'RestrictLocalSubnet', 'Disable', 'Delete'
        $why = ''
        if ($changes -and $Rule) { $req = ConvertTo-IgwtFirewallChangeRequest -Action ([string]$act); $why = Get-IgwtFirewallChangeBlock -Operation $req.Operation -Rule $Rule -Settings $req.Settings }
        if ($changes -and $ReadOnly) { $b.IsEnabled = $false; $b.ToolTip = 'Read-only mode: nothing on this PC is changed.'; [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($b, $true) }
        elseif ($why) { $b.IsEnabled = $false; $b.ToolTip = $why; [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($b, $true) }
        elseif ($act -eq 'Keep') { $b.ToolTip = 'Leave the rule as it is (nothing is recorded).' }
        elseif ($act -eq 'Ignore') { $b.ToolTip = 'Hide this finding with a reason (remembered for this PC; can expire).' }
        else { $b.ToolTip = 'Shows a summary first, writes a snapshot and can be undone.' }
        [System.Windows.Automation.AutomationProperties]::SetName($b, "$($script:IgwtFwActionLabel[[string]$act]): $($f.Title)")
        $null = $wrap.Children.Add($b)
    }
    $null = $sp.Children.Add($wrap)
    $card.Child = $sp
    return $card
}

function Update-IgwtGuiFirewallDetail {
    <# .SYNOPSIS Details pane for the selected rule(s): plain summary, groups, findings with fixes, why it exists, classification, conflicts, actions, details and history. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $c = $script:Gui.C
    if (-not $script:Gui.Grids.Firewall) { return }
    $sel = @($Rows | Where-Object { $_ })
    $buttons = @{ FwEnableButton = 'enable'; FwDisableButton = 'disable'; FwAllowButton = 'allow'; FwBlockButton = 'block'; FwEditButton = 'edit'; FwDuplicateButton = 'duplicate'; FwDeleteButton = 'delete' }
    $why = @()
    foreach ($b in $buttons.Keys) {
        $a = @($script:Gui.Grids.Firewall.Actions | Where-Object { $_.Id -eq $buttons[$b] })[0]
        $block = Get-IgwtGridActionBlock -Action $a -Rows $sel
        if (-not $block -and $sel.Count) {
            $op = @{ enable = 'Enable'; disable = 'Disable'; allow = 'SetAction'; block = 'SetAction'; edit = 'Edit'; duplicate = 'Duplicate'; delete = 'Delete' }[$buttons[$b]]
            $settings = @{ Action = $(if ($buttons[$b] -eq 'allow') { 'Allow' } else { 'Block' }) }
            $refused = @($sel | ForEach-Object { Get-IgwtFirewallChangeBlock -Operation $op -Rule $_.Rule -Settings $settings -RemoteSession (Test-IgwtRemoteSession) } | Where-Object { $_ })
            if ($refused.Count -eq $sel.Count) { $block = $refused[0] }
        }
        $c[$b].IsEnabled = -not $block
        [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($c[$b], $true)
        if ($block -and $sel.Count -and $why -notcontains $block) { $why += $block }
    }
    $c.FwDetWhy.Text = ($why | Select-Object -First 2) -join ' '
    $c.FwDetChips.Children.Clear(); $c.FwDetFindings.Items.Clear()
    $clear = { foreach ($n in 'FwDetSummary', 'FwDetWhyExists', 'FwDetOrigin', 'FwDetPrecedence', 'FwDetText', 'FwDetHistory') { $c[$n].Text = '' }; $c.FwDetRiskBox.Visibility = 'Collapsed'; $c.FwDetFindingsTitle.Visibility = 'Collapsed'; $c.FwDetMoveButton.Visibility = 'Collapsed'; $c.FwDetNotBloatedButton.Visibility = 'Collapsed' }
    if ($sel.Count -eq 0) {
        & $clear
        $c.FwDetName.Text = 'Select a rule'
        $c.FwDetMeta.Text = 'Pick a rule to see what it does, why it exists, what looks risky and how to fix it. Select several (Ctrl or Shift) to change them together.'
        $c.FwDetWhy.Text = ''
        return
    }
    if ($sel.Count -gt 1) {
        & $clear
        $c.FwDetName.Text = "$($sel.Count) rules selected"
        $c.FwDetMeta.Text = 'The actions apply to every selected rule that allows them; the others are listed as refused in the summary.'
        return
    }
    $r = $sel[0].Rule
    $c.FwDetName.Text = [string]$r.DisplayName
    $c.FwDetMeta.Text = "$(if ($r.Enabled) { 'Enabled' } else { 'Disabled' }) | $($r.Direction) | $($r.Action)$(if ($r.Locked) { ' | locked' })"
    $c.FwDetSummary.Text = Format-IgwtFirewallRuleSummary -Row $r
    # Membership chips: origin, facets, assessments.
    $kbCats = @{}; foreach ($cat in (Get-IgwtFirewallKnowledgeBase).Categories) { $kbCats[[string]$cat.id] = $cat }
    foreach ($gid in @($r.Groups)) {
        $tone = switch ([string]$gid) { 'SecurityRisks' { 'Warn' } 'Bloated' { 'Info' } 'Blocked' { 'Pass' } default { 'Text' } }
        $null = $c.FwDetChips.Children.Add((New-IgwtGuiFirewallChip -Text ([string]$kbCats[[string]$gid].name) -Tone $tone -Tip ([string]$kbCats[[string]$gid].hint)))
    }
    if ($r.Confidence -eq 'Low') { $null = $c.FwDetChips.Children.Add((New-IgwtGuiFirewallChip -Text '? Low confidence' -Tone 'Warn' -Tip 'The category is a best guess. Is this right? Use Move to category if not.')) }
    # Lock and protection notices.
    $notes = @()
    if ($r.Locked) { $notes += [string]$r.LockReason }
    if ($r.Protected) { $notes += "Protected: $($r.ProtectedReason) It is never recommended for blocking." }
    if ($r.Protected -and [string]$r.Action -eq 'Block' -and [string]$r.Direction -eq 'Outbound') { $notes += 'This outbound block may break online play.' }
    $c.FwDetRisk.Text = $notes -join [Environment]::NewLine
    $c.FwDetRiskBox.Visibility = $(if ($notes.Count) { 'Visible' } else { 'Collapsed' })
    # Findings with fixes (open first).
    $fs = @($r.Findings | Sort-Object @{ Expression = { [int]$_.Ignored } }, @{ Expression = { @('Critical', 'High', 'Medium', 'Low').IndexOf([string]$_.Severity) } })
    $c.FwDetFindingsTitle.Visibility = $(if ($fs.Count) { 'Visible' } else { 'Collapsed' })
    foreach ($f in $fs) { $null = $c.FwDetFindings.Items.Add((New-IgwtGuiFindingCard -Finding $f -ReadOnly ([bool](Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) -Rule $r)) }
    # Why it exists, classification, conflicts.
    $c.FwDetWhyExists.Text = $(if ($r.KbMeaning) { "$($r.KbMeaning)$(if ($r.WhatStopsWorking) { " $($r.WhatStopsWorking)" })" } elseif ([string]$r.Description) { [string]$r.Description } else { 'No description. ' + [string]$r.OriginReason })
    $c.FwDetOrigin.Text = "$($r.OriginReason) Confidence: $($r.Confidence).$(if ($r.BloatReason) { " Bloated: $($r.BloatReason)" })"
    $c.FwDetMoveButton.Visibility = 'Visible'
    $c.FwDetNotBloatedButton.Visibility = $(if (@($r.Assessments) -contains 'Bloated') { 'Visible' } else { 'Collapsed' })
    $c.FwDetPrecedence.Text = $(if ($r.PrecedenceText) { [string]$r.PrecedenceText } elseif (-not $r.Enabled) { 'Turned off: it takes part in no conflicts.' } else { '' })
    $nl = [Environment]::NewLine
    $c.FwDetText.Text = (@(
            "Profiles: $($r.Profiles)", "Program: $($r.Program)$(if ($r.ProgramExists -eq 'No') { ' (not found)' })", "Service: $($r.Service)",
            $(if ($sel[0].Package) { "Package / AppContainer: $($sel[0].Package)" }), "Protocol: $(if ($r.Protocol) { $r.Protocol } else { 'unknown (needs administrator rights)' })",
            "Local port: $($r.LocalPort)", "Remote port: $($r.RemotePort)", "Local address: $($r.LocalAddress)", "Remote address: $($r.RemoteAddress)",
            "Interface type: $($r.InterfaceType)", "Edge traversal: $($r.EdgeTraversal)", "Group: $(if ($r.Group) { $r.Group } else { '(none)' })", "Store: $(if ($r.Store -and $r.Store -ne 'Active') { $r.Store } else { $r.StoreSource })",
            "Rule ID: $($r.Name)", $(if ($r.Description) { "${nl}$($r.Description)" })
        ) | Where-Object { $_ }) -join $nl
    $hist = @($script:Gui.Firewall.RecentChanges | Where-Object { @($_.Rules) -contains [string]$r.Name })
    $c.FwDetHistory.Text = $(if ($hist.Count) { (@($hist | ForEach-Object { "$(Format-IgwtGuiTime -Value $_.Created): $($_.Detail)" }) -join $nl) } else { 'No changes by iG Windows Tuner.' })
}

function Format-IgwtGuiFirewallPlanText {
    <#
    .SYNOPSIS
        Preview text for a planned group change: what changes (with what stops working for bloated
        rules) and what is skipped, with the reason. Example headline:
        "Disable all Bloated (12) - 2 skipped: locked Core Services."
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Plan, [string]$Label, [object[]]$Rows = @())
    $byId = @{}; foreach ($r in $Rows) { if ($r) { $byId[[string]$r.Name] = $r } }
    $ok = @($Plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp })
    $skip = @($Plan.Items | Where-Object { -not $_.Allowed })
    $same = @($Plan.Items | Where-Object { $_.Allowed -and $_.NoOp })
    $reasons = @($skip | Group-Object Reason | Sort-Object Count -Descending | Select-Object -First 2 | ForEach-Object { ($_.Name -split '[:.]')[0].Trim() })
    $nl = [Environment]::NewLine
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("$Label ($($ok.Count))$(if ($skip.Count) { " - $($skip.Count) skipped: $($reasons -join '; ')" })$(if ($same.Count) { ", $($same.Count) already set" }).$nl$nl")
    if ($ok.Count) {
        $null = $sb.Append("Will change:$nl")
        foreach ($i in $ok) {
            $r = $byId[[string]$i.Name]
            $stops = $(if ($r -and $r.WhatStopsWorking) { "   ($($r.WhatStopsWorking))" } else { '' })
            $null = $sb.Append("  - $(if ($i.DisplayName) { $i.DisplayName } else { $i.Name }): $($i.Change)$stops$nl")
        }
    }
    if ($skip.Count) {
        $null = $sb.Append("${nl}Skipped:$nl")
        foreach ($i in $skip) { $null = $sb.Append("  - $(if ($i.DisplayName) { $i.DisplayName } else { $i.Name }): $($i.Reason)$nl") }
    }
    foreach ($w in @($Plan.Warnings)) { $null = $sb.Append("${nl}Note: $w$nl") }
    $null = $sb.Append("${nl}A snapshot is written first; Undo restores every rule exactly.")
    if ($Plan.RemoteSession) { $null = $sb.Append(" A remote session is active: you will be asked to keep the change within 60 seconds, otherwise it is reverted automatically.") }
    return $sb.ToString()
}

function Initialize-IgwtGuiFirewallHome {
    <# .SYNOPSIS Wires the Overview tab, the group sidebar, the exposure grid and the 3.4 details pane (called once). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $script:Gui.FirewallGroup = 'All'
    $g = New-IgwtSmartGrid -Id 'firewall.exposure' -Noun 'open ports' -RowKey 'Key' -SearchPlaceholder 'Search ports and programs' -SelectionMode Single `
        -EmptyTitle 'Nothing is listening' -EmptyText 'No program waits for incoming connections right now.' -Columns @(
        @{ Key = 'PortText'; Header = 'Port'; Width = 90; Kind = 'Number'; SortKey = 'LocalPort' }
        @{ Key = 'Process'; Header = 'Program'; Width = 150; Tip = 'Path' }
        @{ Key = 'StatusCol'; Header = 'Reachable'; Width = 230; Template = 'Status'; SortKey = 'StatusKey' }
        @{ Key = 'Rules'; Header = 'Rules that allow it'; MinWidth = 200; Tip = 'Rules' }
        @{ Key = 'Profiles'; Header = 'Networks'; Width = 140 }
        @{ Key = 'Services'; Header = 'Services'; Width = 150; Visible = $false }
        @{ Key = 'Address'; Header = 'Address'; Width = 120; Visible = $false }
    ) -Chips @(
        @{ Id = 'exposed'; Label = 'Reachable'; Group = 'st'; Field = 'StatusKey'; Values = @('Exposed') }
        @{ Id = 'blocked'; Label = 'Blocked or this PC only'; Group = 'st'; Field = 'StatusKey'; Values = @('Blocked', 'Local only') }
    )
    $script:Gui.Grids.FirewallExposure = $g
    $c.FwOvExposureHost.Content = $g.Root
    if (-not @($g.Sort).Count) { Set-IgwtGridSort -Grid $g -Key 'StatusCol' -NoSave; Set-IgwtGridSort -Grid $g -Key 'PortText' -Add -NoSave }
    # Overview: tiles open the group, one primary action per card, Undo on recent changes.
    Register-IgwtGuiHandler -Control $c.FwOvTiles -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler { param($s, $e) $null = $s; $b = $e.OriginalSource; if ($b -is [System.Windows.Controls.Button] -and $b.Tag) { Select-IgwtGuiFirewallGroup -Id ([string]$b.Tag) -ShowRules } }
    Register-IgwtGuiHandler -Control $c.FwOvReviewButton -Event 'Click' -Handler { Show-IgwtGuiFirewallWizard }
    Register-IgwtGuiHandler -Control $c.FwOvQuickButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallQuickWins }
    Register-IgwtGuiHandler -Control $c.FwOvRecentList -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler { param($s, $e) $null = $s; $b = $e.OriginalSource; if ($b -is [System.Windows.Controls.Button] -and $b.Tag) { Invoke-IgwtGuiFirewallUndo -Snapshot ([string]$b.Tag) } }
    # Sidebar: groups with counts, saved views.
    Register-IgwtGuiHandler -Control $c.FwGroupList -Event 'SelectionChanged' -Handler { $it = $script:Gui.C.FwGroupList.SelectedItem; if ($it -and [string]$it.Id -ne [string]$script:Gui.FirewallGroup) { Select-IgwtGuiFirewallGroup -Id ([string]$it.Id) } }
    Register-IgwtGuiHandler -Control $c.FwViewList -Event 'SelectionChanged' -Handler { $v = [string]$script:Gui.C.FwViewList.SelectedItem; if ($v) { Use-IgwtGridSavedView -Grid $script:Gui.Grids.Firewall -Name $v } }
    Register-IgwtGuiHandler -Control $c.FwBulkButton -Event 'Click' -Handler { param($s, $e) $null = $e; Show-IgwtGuiFirewallGroupMenu -Target $s }
    Register-IgwtGuiHandler -Control $c.FwReportButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallReport }
    # Details pane: finding actions, move to category, not bloated.
    Register-IgwtGuiHandler -Control $c.FwDetFindings -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler { param($s, $e) $null = $s; $b = $e.OriginalSource; if ($b -is [System.Windows.Controls.Button] -and $b.Tag) { $parts = ([string]$b.Tag) -split '\|', 2; Invoke-IgwtGuiFirewallFindingAction -Action $parts[0] -RiskId $parts[1] } }
    Register-IgwtGuiHandler -Control $c.FwDetMoveButton -Event 'Click' -Handler { param($s, $e) $null = $e; Show-IgwtGuiFirewallMoveMenu -Target $s }
    Register-IgwtGuiHandler -Control $c.FwDetNotBloatedButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallNotBloated }
    Update-IgwtGuiFirewallGroups
    Select-IgwtGuiFirewallGroup -Id 'All'
}

function Update-IgwtGuiFirewallGroups {
    <# .SYNOPSIS Sidebar: All rules and the nine groups with live counts; saved views of the rule list. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $a = $script:Gui.Firewall
    $items = @(Get-IgwtGuiFirewallGroupItems -Summary $(if ($a -and $a.PSObject.Properties['Summary']) { $a.Summary } else { $null }))
    $script:Gui.FirewallGroupUpdating = $true
    try {
        $c.FwGroupList.ItemsSource = $items
        $c.FwGroupList.SelectedItem = @($items | Where-Object { $_.Id -eq [string]$script:Gui.FirewallGroup })[0]
    } finally { $script:Gui.FirewallGroupUpdating = $false }
    $views = @()
    if ($script:Gui.Grids.Firewall) { $views = @((Get-IgwtGridSavedViews -Grid $script:Gui.Grids.Firewall).Keys | Sort-Object) }
    $c.FwViewList.ItemsSource = $views
    $c.FwViewList.Visibility = $(if ($views.Count) { 'Visible' } else { 'Collapsed' })
    $c.FwViewEmpty.Visibility = $(if ($views.Count) { 'Collapsed' } else { 'Visible' })
}

function Select-IgwtGuiFirewallGroup {
    <# .SYNOPSIS Shows one group (or All rules) in the rule list; -ShowRules switches to the Rules tab. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [switch]$ShowRules)
    $c = $script:Gui.C
    $script:Gui.FirewallGroup = $Id
    if (-not $script:Gui.FirewallGroupUpdating) {
        $it = @($c.FwGroupList.ItemsSource | Where-Object { $_.Id -eq $Id })[0]
        if ($it -and -not [object]::ReferenceEquals($c.FwGroupList.SelectedItem, $it)) { $c.FwGroupList.SelectedItem = $it }
    }
    if ($script:Gui.Grids.Firewall) { Update-IgwtGridView -Grid $script:Gui.Grids.Firewall }
    $label = @($c.FwGroupList.ItemsSource | Where-Object { $_.Id -eq $Id } | ForEach-Object { $_.Label })[0]
    $c.FwBulkButton.Content = $(if ($Id -eq 'All') { 'Act on a group...' } else { "Act on $label..." })
    $c.FwBulkButton.IsEnabled = ($Id -ne 'All')
    if ($ShowRules) { $c.FwTabs.SelectedItem = $c.FwRulesTab }
}

function Get-IgwtGuiFirewallSelectedRule {
    <# .SYNOPSIS The engine row of the single selected rule ($null when none or several). #>
    [CmdletBinding()]
    param()
    $sel = @(Get-IgwtGridSelection -Grid $script:Gui.Grids.Firewall)
    if ($sel.Count -ne 1) { return $null }
    return $sel[0].Rule
}

function Invoke-IgwtGuiFirewallFindingAction {
    <# .SYNOPSIS Runs a finding's action for the selected rule: a change (summary, snapshot, Undo), Keep, or Ignore with a reason. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Action, [string]$RiskId)
    $r = Get-IgwtGuiFirewallSelectedRule
    if (-not $r) { return }
    switch ($Action) {
        'Keep' { Set-IgwtGuiStatus "Kept: $($r.DisplayName)."; return }
        'Ignore' {
            $reason = Read-IgwtGuiText -Title 'iG Windows Tuner - ignore finding' -Prompt "Why is this finding fine for '$($r.DisplayName)'? It stays hidden for 90 days (remembered for this PC)."
            if (-not $reason) { return }
            $null = Set-IgwtFirewallOverride -RuleId ([string]$r.Name) -IgnoreFinding $RiskId -Reason $reason -Until (Get-Date).AddDays(90)
            Set-IgwtGuiStatus 'Finding ignored for 90 days. It is still listed under the rule as ignored.'
            Start-IgwtGuiFirewallRefresh
            return
        }
    }
    $req = ConvertTo-IgwtFirewallChangeRequest -Action $Action
    if ($req) { Invoke-IgwtGuiFirewallChange -Operation $req.Operation -Rows @($r) -Settings $req.Settings }
}

function Show-IgwtGuiFirewallMoveMenu {
    <# .SYNOPSIS "Move to category": a menu of the four origin categories for the selected rule. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only; the choice is the user''s own override file.')]
    [CmdletBinding()]
    param($Target)
    $r = Get-IgwtGuiFirewallSelectedRule
    if (-not $r) { return }
    $menu = New-Object System.Windows.Controls.ContextMenu
    foreach ($cat in @((Get-IgwtFirewallKnowledgeBase).Categories | Where-Object layer -EQ 'origin' | Sort-Object order)) {
        $mi = New-Object System.Windows.Controls.MenuItem
        $mi.Header = [string]$cat.name; $mi.Tag = "$($cat.id)|$($r.Name)"; $mi.IsChecked = ([string]$r.Origin -eq [string]$cat.id); $mi.ToolTip = [string]$cat.hint
        Register-IgwtGuiHandler -Control $mi -Event 'Click' -Handler {
            param($s, $e)
            $null = $e
            $parts = ([string]$s.Tag) -split '\|', 2
            $null = Set-IgwtFirewallOverride -RuleId $parts[1] -Category $parts[0]
            Set-IgwtGuiStatus 'Category changed for this rule (remembered for this PC; export it from the Overview).'
            Start-IgwtGuiFirewallRefresh
        }
        $null = $menu.Items.Add($mi)
    }
    $menu.PlacementTarget = $Target; $menu.Placement = 'Bottom'; $menu.IsOpen = $true
}

function Invoke-IgwtGuiFirewallNotBloated {
    <# .SYNOPSIS "Not bloated for me": keeps the selected rule out of Bloated (the user's own override). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes only the user''s own override file.')]
    [CmdletBinding()]
    param()
    $r = Get-IgwtGuiFirewallSelectedRule
    if (-not $r) { return }
    $null = Set-IgwtFirewallOverride -RuleId ([string]$r.Name) -NotBloated
    Set-IgwtGuiStatus "'$($r.DisplayName)' is no longer counted as bloated on this PC."
    Start-IgwtGuiFirewallRefresh
}

function Show-IgwtGuiFirewallGroupMenu {
    <# .SYNOPSIS Group-level actions for the group in the sidebar: disable, enable, restrict; each opens a preview first. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Shows a menu; changes go through the preview.')]
    [CmdletBinding()]
    param($Target)
    $menu = New-Object System.Windows.Controls.ContextMenu
    foreach ($op in @(@('Disable', 'Disable all'), @('Enable', 'Enable all'), @('RestrictPrivate', 'Restrict all to Private networks'), @('RestrictLocalSubnet', 'Restrict all to the local subnet'))) {
        $mi = New-Object System.Windows.Controls.MenuItem
        $mi.Header = "$($op[1])..."; $mi.Tag = $op[0]
        Register-IgwtGuiHandler -Control $mi -Event 'Click' -Handler { param($s, $e) $null = $e; Invoke-IgwtGuiFirewallGroupAction -Action ([string]$s.Tag) }
        $null = $menu.Items.Add($mi)
    }
    $menu.PlacementTarget = $Target; $menu.Placement = 'Top'; $menu.IsOpen = $true
}

function Invoke-IgwtGuiFirewallGroupAction {
    <#
    .SYNOPSIS
        A change for every rule of the selected group, after a preview with the diff: what changes,
        what stops working, and what is skipped with the reason (locked, Core Services, Windows
        rules that cannot be edited ...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Disable', 'Enable', 'RestrictPrivate', 'RestrictLocalSubnet')][string]$Action)
    $id = [string]$script:Gui.FirewallGroup
    if (-not $id -or $id -eq 'All' -or -not $script:Gui.Firewall) { return }
    $rows = @($script:Gui.Firewall.Rules | Where-Object { @($_.Groups) -contains $id })
    $req = $(if ($Action -eq 'Enable') { @{ Operation = 'Enable'; Settings = @{} } } else { ConvertTo-IgwtFirewallChangeRequest -Action $Action })
    $plan = Get-IgwtFirewallChangePlan -Operation $req.Operation -Rules $rows -Settings $req.Settings
    $label = @{ Disable = 'Disable all'; Enable = 'Enable all'; RestrictPrivate = 'Restrict to Private'; RestrictLocalSubnet = 'Restrict to the local subnet' }[$Action]
    $groupName = @((Get-IgwtFirewallKnowledgeBase).Categories | Where-Object { $_.id -eq $id } | ForEach-Object { $_.name })[0]
    $text = Format-IgwtGuiFirewallPlanText -Plan $plan -Label "$label $groupName" -Rows $rows
    $canApply = (-not (Test-IgwtReadOnly)) -and $script:Gui.IsAdmin -and $plan.Count -gt 0
    $accept = $(if ($canApply) { "Apply $($plan.Count) change$(if ($plan.Count -ne 1) { 's' })" } else { '' })
    if (-not $canApply -and $plan.Count) { $text += [Environment]::NewLine + [Environment]::NewLine + 'Read-only: changes need administrator rights and are off in read-only mode.' }
    if (Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $label $groupName" -Text $text -AcceptText $accept) {
        $ids = @{}; foreach ($i in @($plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp })) { $ids[[string]$i.Name] = $true }
        Invoke-IgwtGuiFirewallChange -Operation $req.Operation -Rows @($rows | Where-Object { $ids.ContainsKey([string]$_.Name) }) -Settings $req.Settings -NoConfirm
    }
}

function Invoke-IgwtGuiFirewallQuickWins {
    <# .SYNOPSIS Quick wins: preview the bloated rules that can be disabled safely (what stops working), then disable them in one change. #>
    [CmdletBinding()]
    param()
    $a = $script:Gui.Firewall
    if (-not $a) { return }
    $ids = @{}; foreach ($n in @($a.Summary.QuickWins)) { $ids[[string]$n] = $true }
    $rows = @($a.Rules | Where-Object { $ids.ContainsKey([string]$_.Name) })
    $plan = Get-IgwtFirewallChangePlan -Operation Disable -Rules $rows
    $text = Format-IgwtGuiFirewallPlanText -Plan $plan -Label 'Disable bloated rules' -Rows $rows
    $canApply = (-not (Test-IgwtReadOnly)) -and $script:Gui.IsAdmin -and $plan.Count -gt 0
    if (-not $canApply -and $plan.Count) { $text += [Environment]::NewLine + [Environment]::NewLine + 'Read-only: changes need administrator rights and are off in read-only mode.' }
    if (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - quick wins' -Text $text -AcceptText $(if ($canApply) { "Disable $($plan.Count) rule$(if ($plan.Count -ne 1) { 's' })" } else { '' })) {
        Invoke-IgwtGuiFirewallChange -Operation Disable -Rows $rows -NoConfirm
    }
}

function Invoke-IgwtGuiFirewallReport {
    <# .SYNOPSIS Saves the firewall audit report (HTML, CSV or JSON) the user picks. #>
    [CmdletBinding()]
    param()
    if (-not $script:Gui.Firewall) { Set-IgwtGuiStatus 'Read the rules first.'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html|CSV (*.csv)|*.csv|JSON (*.json)|*.json'
    $dlg.FileName = "firewall-audit-$((Get-Date).ToString('yyyyMMdd')).html"
    if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
    try { $null = Export-IgwtFirewallAuditReport -Audit $script:Gui.Firewall -Path $dlg.FileName; Set-IgwtGuiStatus "Audit report saved: $($dlg.FileName)"; Open-IgwtGuiPath -Target $dlg.FileName }
    catch { Show-IgwtGuiError -Message "The report was not written: $($_.Exception.Message)" -Context 'Firewall' }
}

function Get-IgwtGuiFirewallWizardXaml {
    <# .SYNOPSIS The smart fix wizard window (themed through the copied resources). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="iG Windows Tuner - review findings" Width="640" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False" WindowStartupLocation="CenterOwner">
    <StackPanel Margin="22,18,22,18">
        <DockPanel>
            <TextBlock x:Name="StepText" DockPanel.Dock="Right" Style="{DynamicResource TextMuted}" VerticalAlignment="Center"/>
            <TextBlock x:Name="RuleName" FontSize="{DynamicResource FontSizeSubtitle}" FontWeight="SemiBold" TextWrapping="Wrap"/>
        </DockPanel>
        <TextBlock x:Name="RuleSummary" Style="{DynamicResource TextMuted}" TextWrapping="Wrap" Margin="0,4,0,10"/>
        <Border Style="{DynamicResource Card}" Margin="0,0,0,10">
            <StackPanel>
                <TextBlock x:Name="FindingTitle" FontWeight="SemiBold" TextWrapping="Wrap"/>
                <TextBlock x:Name="FindingText" TextWrapping="Wrap" Margin="0,6,0,0"/>
            </StackPanel>
        </Border>
        <TextBlock Style="{DynamicResource TextCaption}" Text="Fix with" Margin="0,0,0,4"/>
        <StackPanel x:Name="ActionPanel" Margin="0,0,0,10"/>
        <TextBlock x:Name="NoteText" Style="{DynamicResource TextCaption}" TextWrapping="Wrap" Margin="0,0,0,10"/>
        <DockPanel>
            <Button x:Name="CloseButton" DockPanel.Dock="Left" Content="Stop" IsCancel="True" Margin="0" ToolTip="Stop the review; the summary shows what you decided so far."/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="IgnoreButton" Content="Ignore..." ToolTip="Hide this finding with a reason (remembered for this PC for 90 days)."/>
                <Button x:Name="SkipButton" Content="Skip" ToolTip="Decide later; nothing is recorded."/>
                <Button x:Name="FixButton" Style="{DynamicResource AccentButton}" Content="Fix" Margin="0" ToolTip="Add the chosen fix to the summary. Nothing changes until you apply the summary."/>
            </StackPanel>
        </DockPanel>
    </StackPanel>
</Window>
'@
}

function Show-IgwtGuiFirewallWizard {
    <#
    .SYNOPSIS
        Smart fix wizard: walks through the open findings one at a time (most severe first) with
        Fix / Skip / Ignore and a step counter. Fixes are collected; the summary at the end previews
        every change (skipped rules with the reason) and applies them in one go per action, each with
        a snapshot and Undo. Ignore writes the user's own override. Works in read-only mode (Fix then
        only records what would be done).
    #>
    [CmdletBinding()]
    param()
    $a = $script:Gui.Firewall
    if (-not $a) { return }
    $steps = @(Get-IgwtFirewallWizardSteps -Rows $a.Rules)
    if (-not $steps.Count) { $null = Show-IgwtGuiMessage -Text 'No open findings: nothing to review.' -Title 'iG Windows Tuner - firewall'; return }
    $w = [Windows.Markup.XamlReader]::Parse((Get-IgwtGuiFirewallWizardXaml))
    $w.Owner = $script:Gui.Window
    Copy-IgwtGuiResources -Target $w
    $w.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'BrushSurface')
    $w.SetResourceReference([System.Windows.Window]::FontSizeProperty, 'FontSizeBody')
    $f = @{}; foreach ($n in 'StepText', 'RuleName', 'RuleSummary', 'FindingTitle', 'FindingText', 'ActionPanel', 'NoteText', 'CloseButton', 'IgnoreButton', 'SkipButton', 'FixButton') { $f[$n] = $w.FindName($n) }
    $script:IgwtFwWiz = @{ Window = $w; F = $f; Steps = $steps; Index = 0; Decisions = (New-Object System.Collections.Generic.List[object]); Ignored = 0; Skipped = 0 }
    Register-IgwtGuiHandler -Control $f.FixButton -Event 'Click' -Handler { Step-IgwtGuiFirewallWizard -Decision Fix }
    Register-IgwtGuiHandler -Control $f.SkipButton -Event 'Click' -Handler { Step-IgwtGuiFirewallWizard -Decision Skip }
    Register-IgwtGuiHandler -Control $f.IgnoreButton -Event 'Click' -Handler { Step-IgwtGuiFirewallWizard -Decision Ignore }
    Register-IgwtGuiHandler -Control $f.CloseButton -Event 'Click' -Handler { $script:IgwtFwWiz.Window.Close() }
    Show-IgwtGuiFirewallWizardStep
    $null = $w.ShowDialog()
    Complete-IgwtGuiFirewallWizard
}

function Show-IgwtGuiFirewallWizardStep {
    <# .SYNOPSIS Shows the current wizard step: rule, plain summary, finding and the fix choices (recommended first). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $z = $script:IgwtFwWiz; $f = $z.F
    $s = $z.Steps[$z.Index]
    $f.StepText.Text = "Step $($z.Index + 1) of $($z.Steps.Count)"
    $f.RuleName.Text = [string]$s.Rule.DisplayName
    $f.RuleSummary.Text = Format-IgwtFirewallRuleSummary -Row $s.Rule
    $f.FindingTitle.Text = "$($s.Finding.Severity)$(if ($s.Finding.ExposedNow) { ', exposed now' }): $($s.Finding.Title)"
    $f.FindingText.Text = [string]$s.Finding.Explanation
    $f.ActionPanel.Children.Clear()
    $first = $true
    foreach ($act in @(@($s.Finding.Recommended) + @($s.Finding.Alternatives) | Where-Object { $_ -and $_ -ne 'Ignore' })) {
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.GroupName = 'fix'; $rb.Tag = [string]$act; $rb.Margin = '0,0,0,4'
        $rb.Content = $(if ($act -eq $s.Finding.Recommended) { "$($script:IgwtFwActionLabel[[string]$act].TrimEnd('.')) (recommended)" } else { $script:IgwtFwActionLabel[[string]$act].TrimEnd('.') })
        $rb.IsChecked = $first; $first = $false
        $null = $f.ActionPanel.Children.Add($rb)
    }
    $ro = (Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin
    $f.NoteText.Text = $(if ($ro) { 'Read-only: Fix records what would be done; nothing on this PC changes.' } elseif ($s.Rule.Protected) { "Protected: $($s.Rule.ProtectedReason)" } else { 'Fixes are collected and shown in a summary before anything changes.' })
}

function Step-IgwtGuiFirewallWizard {
    <# .SYNOPSIS Records the decision for the current step and moves on (closes after the last step). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Ignore writes only the user''s own override file.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Fix', 'Skip', 'Ignore')][string]$Decision)
    $z = $script:IgwtFwWiz
    $s = $z.Steps[$z.Index]
    switch ($Decision) {
        'Fix' {
            $pick = @($z.F.ActionPanel.Children | Where-Object { $_.IsChecked })[0]
            $act = $(if ($pick) { [string]$pick.Tag } else { [string]$s.Finding.Recommended })
            if ($act -ne 'Keep') { $z.Decisions.Add([pscustomobject]@{ RuleId = $s.RuleId; Action = $act; Title = [string]$s.Finding.Title }) }
        }
        'Skip' { $z.Skipped++ }
        'Ignore' {
            $reason = Read-IgwtGuiText -Title 'iG Windows Tuner - ignore finding' -Prompt "Why is '$($s.Finding.Title)' fine for '$($s.Rule.DisplayName)'? Hidden for 90 days."
            if (-not $reason) { return }
            $null = Set-IgwtFirewallOverride -RuleId $s.RuleId -IgnoreFinding ([string]$s.Finding.RiskId) -Reason $reason -Until (Get-Date).AddDays(90)
            $z.Ignored++
        }
    }
    $z.Index++
    if ($z.Index -ge $z.Steps.Count) { $z.Window.Close(); return }
    Show-IgwtGuiFirewallWizardStep
}

function Complete-IgwtGuiFirewallWizard {
    <# .SYNOPSIS The wizard summary: every collected fix previewed (skipped rules with the reason), then applied per action after one confirmation. #>
    [CmdletBinding()]
    param()
    $z = $script:IgwtFwWiz
    if (-not $z) { return }
    $script:IgwtFwWiz = $null
    $nl = [Environment]::NewLine
    $head = "Reviewed $([Math]::Min($z.Index, $z.Steps.Count)) of $($z.Steps.Count) finding(s): $($z.Decisions.Count) fix(es), $($z.Skipped) skipped, $($z.Ignored) ignored."
    if ($z.Ignored) { Start-IgwtGuiFirewallRefresh }
    if (-not $z.Decisions.Count) { $null = Show-IgwtGuiMessage -Text $head -Title 'iG Windows Tuner - review summary'; return }
    $batches = @(Get-IgwtFirewallFixPlan -Decisions $z.Decisions.ToArray() -Rows $script:Gui.Firewall.Rules)
    $label = @{ Disable = 'Disable'; Delete = 'Delete'; RestrictPrivate = 'Restrict to Private'; RestrictLocalSubnet = 'Restrict to the local subnet' }
    $text = $head + $nl + $nl + (@($batches | ForEach-Object { Format-IgwtGuiFirewallPlanText -Plan $_.Plan -Label $label[[string]$_.Action] -Rows $_.Rules }) -join ($nl + $nl))
    $total = [int](@($batches | ForEach-Object { $_.Plan.Count }) | Measure-Object -Sum).Sum
    $canApply = (-not (Test-IgwtReadOnly)) -and $script:Gui.IsAdmin -and $total -gt 0
    if (-not $canApply -and $total) { $text += $nl + $nl + 'Read-only: this is what would change; nothing on this PC was changed.' }
    if (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - review summary' -Text $text -AcceptText $(if ($canApply) { "Apply $total change$(if ($total -ne 1) { 's' })" } else { '' })) {
        # Changes run one at a time: the next batch starts when the previous one completes.
        $queue = New-Object System.Collections.Generic.List[object]
        foreach ($b in $batches) {
            $ids = @{}; foreach ($i in @($b.Plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp })) { $ids[[string]$i.Name] = $true }
            $rows = @($b.Rules | Where-Object { $ids.ContainsKey([string]$_.Name) })
            if ($rows.Count) { $queue.Add([pscustomobject]@{ Operation = $b.Operation; Rows = $rows; Settings = $b.Settings }) }
        }
        Start-IgwtGuiFirewallQueue -Queue $queue
    }
}

function Start-IgwtGuiFirewallQueue {
    <# .SYNOPSIS Runs queued firewall changes one after another (Complete-IgwtGuiFirewallChange starts the next). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Each change goes through Invoke-IgwtGuiFirewallChange (plan, snapshot, engine guard).')]
    [CmdletBinding()]
    param([System.Collections.Generic.List[object]]$Queue)
    if (-not $Queue -or -not $Queue.Count) { return }
    $next = $Queue[0]; $Queue.RemoveAt(0)
    $script:Gui.FirewallQueue = $Queue
    Invoke-IgwtGuiFirewallChange -Operation $next.Operation -Rows $next.Rows -Settings $next.Settings -NoConfirm
}