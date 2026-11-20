# Components.ps1
# 4.0 components (Phase 3 design, section 4): small builders that return WPF elements styled with the
# 4.0 tokens in Theme.xaml. They hold no tweak logic and change nothing on the PC; pages (sections 3-7)
# fill them with data from exported engine functions. Every interactive part gets a screen-reader name
# that includes its object ("Undo Competitive preset"), and status is always a word plus a colour.

$script:IgwtUiToneGlyph = @{ Success = [string][char]0xE73E; Warning = [string][char]0xE7BA; Danger = [string][char]0xEA39; Info = [string][char]0xE946; Neutral = [string][char]0xE946 }

function Set-IgwtUiName {
    <# .SYNOPSIS Sets the screen-reader name (and optional help text) of an element and returns it. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Sets a property of an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Element, [Parameter(Mandatory = $true)][string]$Name, [string]$HelpText = '')
    [System.Windows.Automation.AutomationProperties]::SetName($Element, $Name)
    if ($HelpText) { [System.Windows.Automation.AutomationProperties]::SetHelpText($Element, $HelpText) }
    return $Element
}

function New-IgwtUiText {
    <# .SYNOPSIS A TextBlock with a 4.0 text style (TextBody when none is given). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text = '', [string]$Style = 'TextBody', [string]$Brush = '')
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text
    $t.TextWrapping = 'Wrap'
    $t.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, $Style)
    if ($Brush) { $t.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $Brush) }
    return $t
}

function New-IgwtUiButton {
    <#
    .SYNOPSIS
        A 4.0 button: Primary, Secondary, Subtle or Danger (outline). -ObjectName completes the
        screen-reader name, so repeated buttons are told apart ("Undo" + "Competitive preset").
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text, [ValidateSet('Primary', 'Secondary', 'Subtle', 'Danger')][string]$Kind = 'Secondary', [string]$ObjectName = '')
    $b = New-Object System.Windows.Controls.Button
    $b.Content = $Text
    $style = @{ Primary = 'PrimaryButton'; Secondary = 'SecondaryButton'; Subtle = 'SubtleButton'; Danger = 'DangerOutlineButton' }[$Kind]
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, $style)
    $null = Set-IgwtUiName -Element $b -Name $(if ($ObjectName) { "$Text $ObjectName" } else { $Text })
    return $b
}

function New-IgwtPill {
    <# .SYNOPSIS A status pill: icon plus word on the tone's soft fill (status is never colour alone). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text, [ValidateSet('Success', 'Warning', 'Danger', 'Info', 'Neutral')][string]$Tone = 'Neutral')
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Pill')
    $b.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, "Brush$($Tone)Soft")
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'
    $g = New-IgwtUiText -Text $script:IgwtUiToneGlyph[$Tone] -Style 'TextCaption' -Brush "Brush$Tone"
    $g.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'FontIcons')
    $g.Margin = [System.Windows.Thickness]::new(0, 0, 6, 0); $g.VerticalAlignment = 'Center'
    $t = New-IgwtUiText -Text $Text -Style 'TextCaption' -Brush $(if ($Tone -eq 'Neutral') { 'BrushTextMuted' } else { "Brush$Tone" })
    $t.FontWeight = [System.Windows.FontWeights]::SemiBold; $t.VerticalAlignment = 'Center'
    $null = $sp.Children.Add($g); $null = $sp.Children.Add($t)
    $b.Child = $sp
    return (Set-IgwtUiName -Element $b -Name $Text)
}

function New-IgwtInfoBar {
    <# .SYNOPSIS A Windows-style banner: tone icon, title, one line and an optional action. Announced politely. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title, [string]$Message = '', [ValidateSet('Success', 'Warning', 'Danger', 'Info')][string]$Tone = 'Info', [string]$ActionText = '')
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'InfoBar')
    $b.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, "Brush$($Tone)Soft")
    $b.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, "Brush$Tone")
    $dp = New-Object System.Windows.Controls.DockPanel
    $g = New-IgwtUiText -Text $script:IgwtUiToneGlyph[$Tone] -Style 'TextBody' -Brush "Brush$Tone"
    $g.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'FontIcons')
    $g.Margin = [System.Windows.Thickness]::new(0, 2, 10, 0)
    [System.Windows.Controls.DockPanel]::SetDock($g, 'Left'); $null = $dp.Children.Add($g)
    if ($ActionText) {
        $a = New-IgwtUiButton -Text $ActionText -Kind Secondary -ObjectName "($Title)"
        $a.Margin = [System.Windows.Thickness]::new(12, 0, 0, 0); $a.VerticalAlignment = 'Center'
        [System.Windows.Controls.DockPanel]::SetDock($a, 'Right'); $null = $dp.Children.Add($a)
    }
    $txt = New-Object System.Windows.Controls.StackPanel
    $null = $txt.Children.Add((New-IgwtUiText -Text $Title -Style 'TextBodyStrong'))
    if ($Message) { $null = $txt.Children.Add((New-IgwtUiText -Text $Message -Style 'TextBody')) }
    $null = $dp.Children.Add($txt)
    $b.Child = $dp
    [System.Windows.Automation.AutomationProperties]::SetLiveSetting($b, [System.Windows.Automation.AutomationLiveSetting]::Polite)
    return (Set-IgwtUiName -Element $b -Name "$Title. $Message".TrimEnd(' ', '.'))
}

function New-IgwtPageHeader {
    <# .SYNOPSIS Page title (Display), one muted line, and an optional element on the right (search or one action). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title, [string]$Subtitle = '', $Right = $null)
    $dp = New-Object System.Windows.Controls.DockPanel
    $dp.Margin = [System.Windows.Thickness]::new(0, 0, 0, 20)
    if ($Right) { [System.Windows.Controls.DockPanel]::SetDock($Right, 'Right'); $Right.VerticalAlignment = 'Center'; $null = $dp.Children.Add($Right) }
    $sp = New-Object System.Windows.Controls.StackPanel
    $h = New-IgwtUiText -Text $Title -Style 'TextDisplay'
    [System.Windows.Automation.AutomationProperties]::SetHeadingLevel($h, [System.Windows.Automation.AutomationHeadingLevel]::Level1)
    $null = $sp.Children.Add($h)
    if ($Subtitle) { $s = New-IgwtUiText -Text $Subtitle -Style 'TextBody' -Brush 'BrushTextMuted'; $s.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0); $null = $sp.Children.Add($s) }
    $null = $dp.Children.Add($sp)
    return $dp
}

function New-IgwtChipGroup {
    <#
    .SYNOPSIS
        Filter chips (toggle buttons whose state is announced). -Single makes them behave as one
        choice. Returns the WrapPanel; each chip's Tag is its value.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Labels, [string[]]$Selected = @(), [string]$GroupName = 'Filter', [switch]$Single)
    $wp = New-Object System.Windows.Controls.WrapPanel
    $null = Set-IgwtUiName -Element $wp -Name $GroupName
    foreach ($l in $Labels) {
        $c = New-Object System.Windows.Controls.Primitives.ToggleButton
        $c.Content = $l; $c.Tag = $l
        $c.IsChecked = ($Selected -contains $l)
        $c.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'FilterChip')
        $null = Set-IgwtUiName -Element $c -Name "$GroupName`: $l"
        if ($Single) {
            Register-IgwtGuiHandler -Control $c -Event 'Checked' -Handler { param($s, $e) foreach ($o in $s.Parent.Children) { if (-not [object]::ReferenceEquals($o, $s)) { $o.IsChecked = $false } } }
        }
        $null = $wp.Children.Add($c)
    }
    return $wp
}

function New-IgwtSettingRow {
    <#
    .SYNOPSIS
        One setting: name, plain hint, evidence label and a switch with a visible state word. The row
        is focusable (click selects it for the details panel); the switch toggles. Returns the row; the
        switch is in its Tag.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Hint = '', [string]$Evidence = '', [bool]$IsOn = $false, [switch]$Disabled, [string]$DisabledReason = '')
    $row = New-Object System.Windows.Controls.Border
    $row.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'SettingRow')
    $g = New-Object System.Windows.Controls.Grid
    foreach ($w in '*', 'Auto') { $cd = New-Object System.Windows.Controls.ColumnDefinition; $cd.Width = (New-Object System.Windows.GridLengthConverter).ConvertFromString($w); $g.ColumnDefinitions.Add($cd) }
    $left = New-Object System.Windows.Controls.StackPanel
    $null = $left.Children.Add((New-IgwtUiText -Text $Name -Style 'TextBodyStrong'))
    if ($Hint) { $null = $left.Children.Add((New-IgwtUiText -Text $Hint -Style 'TextBody' -Brush 'BrushTextMuted')) }
    if ($Evidence) { $e = New-IgwtUiText -Text $Evidence -Style 'TextCaption' -Brush 'BrushTextMuted'; $e.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0); $null = $left.Children.Add($e) }
    if ($Disabled -and $DisabledReason) { $null = $left.Children.Add((New-IgwtUiText -Text $DisabledReason -Style 'TextCaption' -Brush 'BrushWarning')) }
    $null = $g.Children.Add($left)
    $right = New-Object System.Windows.Controls.StackPanel
    $right.Orientation = 'Horizontal'; $right.VerticalAlignment = 'Center'; $right.Margin = [System.Windows.Thickness]::new(16, 0, 0, 0)
    [System.Windows.Controls.Grid]::SetColumn($right, 1)
    $state = New-IgwtUiText -Text $(if ($IsOn) { 'On' } else { 'Off' }) -Style 'TextBody' -Brush 'BrushTextMuted'
    $state.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0); $state.VerticalAlignment = 'Center'
    $sw = New-Object System.Windows.Controls.CheckBox
    $sw.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'ToggleSwitch')
    $sw.IsChecked = $IsOn; $sw.IsEnabled = -not $Disabled; $sw.VerticalAlignment = 'Center'
    $sw.Tag = $state
    Register-IgwtGuiHandler -Control $sw -Event 'Checked' -Handler { param($s, $e) $s.Tag.Text = 'On' }
    Register-IgwtGuiHandler -Control $sw -Event 'Unchecked' -Handler { param($s, $e) $s.Tag.Text = 'Off' }
    $null = Set-IgwtUiName -Element $sw -Name $Name -HelpText $Hint
    $null = $right.Children.Add($state); $null = $right.Children.Add($sw)
    $null = $g.Children.Add($right)
    $row.Child = $g
    $row.Tag = $sw
    return (Set-IgwtUiName -Element $row -Name "$Name, $(if ($IsOn) { 'on' } else { 'off' })")
}

function New-IgwtStatusTile {
    <# .SYNOPSIS Label, big value, one line, one link. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][string]$Value, [string]$Line = '', [string]$LinkText = '')
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'StatusTile')
    $sp = New-Object System.Windows.Controls.StackPanel
    $null = $sp.Children.Add((New-IgwtUiText -Text $Label -Style 'TextCaption' -Brush 'BrushTextMuted'))
    $v = New-IgwtUiText -Text $Value -Style 'TextDisplay'; $v.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4); $null = $sp.Children.Add($v)
    if ($Line) { $null = $sp.Children.Add((New-IgwtUiText -Text $Line -Style 'TextBody' -Brush 'BrushTextMuted')) }
    if ($LinkText) { $a = New-IgwtUiButton -Text $LinkText -Kind Subtle -ObjectName "($Label)"; $a.HorizontalAlignment = 'Left'; $a.Margin = [System.Windows.Thickness]::new(-18, 4, 0, 0); $null = $sp.Children.Add($a) }
    $b.Child = $sp
    return (Set-IgwtUiName -Element $b -Name "$Label`: $Value. $Line".TrimEnd(' ', '.'))
}

function New-IgwtNextStepCard {
    <# .SYNOPSIS The one next step: icon, small label, title, one sentence, a primary and a subtle action. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title, [string]$Text = '', [string]$Label = 'Next step', [string]$PrimaryText = '', [string]$SecondaryText = '', [string]$Glyph = [string][char]0xE7C1)
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'NextStepCard')
    $dp = New-Object System.Windows.Controls.DockPanel
    $ic = New-IgwtUiText -Text $Glyph -Style 'TextCardTitle' -Brush 'BrushAccent'
    $ic.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'FontIcons')
    $ic.Margin = [System.Windows.Thickness]::new(0, 2, 16, 0)
    [System.Windows.Controls.DockPanel]::SetDock($ic, 'Left'); $null = $dp.Children.Add($ic)
    $sp = New-Object System.Windows.Controls.StackPanel
    $null = $sp.Children.Add((New-IgwtUiText -Text $Label -Style 'TextCaption' -Brush 'BrushTextMuted'))
    $null = $sp.Children.Add((New-IgwtUiText -Text $Title -Style 'TextCardTitle'))
    if ($Text) { $t = New-IgwtUiText -Text $Text -Style 'TextBody'; $t.Margin = [System.Windows.Thickness]::new(0, 4, 0, 12); $null = $sp.Children.Add($t) }
    $acts = New-Object System.Windows.Controls.StackPanel; $acts.Orientation = 'Horizontal'
    if ($PrimaryText) { $null = $acts.Children.Add((New-IgwtUiButton -Text $PrimaryText -Kind Primary -ObjectName "($Title)")) }
    if ($SecondaryText) { $null = $acts.Children.Add((New-IgwtUiButton -Text $SecondaryText -Kind Subtle -ObjectName "($Title)")) }
    $null = $sp.Children.Add($acts)
    $null = $dp.Children.Add($sp)
    $b.Child = $dp
    return (Set-IgwtUiName -Element $b -Name "$Label`: $Title")
}

function New-IgwtEmptyState {
    <# .SYNOPSIS One line and one action. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text, [string]$ActionText = '')
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.HorizontalAlignment = 'Center'; $sp.Margin = [System.Windows.Thickness]::new(0, 24, 0, 24)
    $t = New-IgwtUiText -Text $Text -Style 'TextBody' -Brush 'BrushTextMuted'; $t.TextAlignment = 'Center'; $t.HorizontalAlignment = 'Center'
    $null = $sp.Children.Add($t)
    if ($ActionText) { $a = New-IgwtUiButton -Text $ActionText -Kind Secondary; $a.HorizontalAlignment = 'Center'; $a.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0); $null = $sp.Children.Add($a) }
    return (Set-IgwtUiName -Element $sp -Name $Text)
}

function New-IgwtSessionCard {
    <#
    .SYNOPSIS
        A change session for History: title, one metadata line, one Undo, and the steps (setting,
        before -> set, now). A step with a conflict shows its two choices inline, named with the
        setting. Steps: objects with Setting, Before, After, Now and Conflict (bool).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title, [string]$Meta = '', [object[]]$Steps = @(), [switch]$NoUndo, [switch]$Expanded)
    $b = New-Object System.Windows.Controls.Border
    $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'SessionCard')
    $sp = New-Object System.Windows.Controls.StackPanel
    $top = New-Object System.Windows.Controls.DockPanel
    if (-not $NoUndo) { $u = New-IgwtUiButton -Text 'Undo' -Kind Secondary -ObjectName $Title; [System.Windows.Controls.DockPanel]::SetDock($u, 'Right'); $u.VerticalAlignment = 'Center'; $null = $top.Children.Add($u) }
    $hd = New-Object System.Windows.Controls.StackPanel
    $null = $hd.Children.Add((New-IgwtUiText -Text $Title -Style 'TextSubtitle'))
    if ($Meta) { $null = $hd.Children.Add((New-IgwtUiText -Text $Meta -Style 'TextBody' -Brush 'BrushTextMuted')) }
    $null = $top.Children.Add($hd)
    $null = $sp.Children.Add($top)
    $steps = @($Steps | Where-Object { $_ })
    if ($steps.Count) {
        $ex = New-Object System.Windows.Controls.Expander
        $ex.Header = "$($steps.Count) setting$(if ($steps.Count -ne 1) { 's' })"
        $ex.IsExpanded = [bool]$Expanded; $ex.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
        $null = Set-IgwtUiName -Element $ex -Name "Settings in $Title"
        $list = New-Object System.Windows.Controls.StackPanel
        foreach ($s in $steps) {
            $r = New-Object System.Windows.Controls.StackPanel; $r.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)
            $null = $r.Children.Add((New-IgwtUiText -Text ([string]$s.Setting) -Style 'TextBodyStrong'))
            $vals = New-IgwtUiText -Text ("{0} -> {1}; now {2}" -f [string]$s.Before, [string]$s.After, [string]$s.Now) -Style 'TextValue' -Brush 'BrushTextMuted'
            $null = $r.Children.Add($vals)
            if ($s.Conflict) {
                $null = $r.Children.Add((New-IgwtPill -Text 'Changed since' -Tone Warning))
                $ch = New-Object System.Windows.Controls.StackPanel; $ch.Orientation = 'Horizontal'; $ch.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
                $null = $ch.Children.Add((New-IgwtUiButton -Text 'Keep the current value' -Kind Secondary -ObjectName "($([string]$s.Setting))"))
                $null = $ch.Children.Add((New-IgwtUiButton -Text "Restore $([string]$s.Before)" -Kind Subtle -ObjectName "($([string]$s.Setting))"))
                $null = $r.Children.Add($ch)
            }
            $null = $list.Children.Add($r)
        }
        $ex.Content = $list
        $null = $sp.Children.Add($ex)
    }
    $b.Child = $sp
    return (Set-IgwtUiName -Element $b -Name "$Title. $Meta".TrimEnd(' ', '.'))
}

function New-IgwtSplitView {
    <#
    .SYNOPSIS
        A list next to its DetailsPanel (DetailsWidth wide). Under 1100 px of available width the
        details move below the list as a bottom sheet (Phase 3: no fixed side column at 1100 x 720
        with 150 % text). Returns the Grid; the layout follows its width.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Main, [Parameter(Mandatory = $true)]$Details, [double]$Breakpoint = 1100)
    $g = New-Object System.Windows.Controls.Grid
    $panel = New-Object System.Windows.Controls.Border
    $panel.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'DetailsPanel')
    $panel.Child = $Details
    $null = Set-IgwtUiName -Element $panel -Name 'Details'
    $null = $g.Children.Add($Main); $null = $g.Children.Add($panel)
    $g.Tag = [pscustomobject]@{ Main = $Main; Panel = $panel; Breakpoint = $Breakpoint; Mode = '' }
    $null = Set-IgwtSplitLayout -Grid $g -Width $Breakpoint
    Register-IgwtGuiHandler -Control $g -Event 'SizeChanged' -Handler { param($s, $e) $null = Set-IgwtSplitLayout -Grid $s -Width $e.NewSize.Width }
    return $g
}

function Set-IgwtSplitLayout {
    <# .SYNOPSIS Side (details on the right) at or above the breakpoint, Sheet (details below) under it. Returns the mode. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes an in-memory layout only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Grid, [Parameter(Mandatory = $true)][double]$Width)
    $st = $Grid.Tag
    $mode = $(if ($Width -ge $st.Breakpoint) { 'Side' } else { 'Sheet' })
    if ($st.Mode -eq $mode) { return $mode }
    $Grid.ColumnDefinitions.Clear(); $Grid.RowDefinitions.Clear()
    $conv = New-Object System.Windows.GridLengthConverter
    if ($mode -eq 'Side') {
        $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = $conv.ConvertFromString('*')
        # DetailsWidth token (Theme.xaml): 320 px, inside the 280-340 px of the design.
        $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = [System.Windows.GridLength]::new(320)
        $Grid.ColumnDefinitions.Add($c1); $Grid.ColumnDefinitions.Add($c2)
        [System.Windows.Controls.Grid]::SetColumn($st.Main, 0); [System.Windows.Controls.Grid]::SetRow($st.Main, 0)
        [System.Windows.Controls.Grid]::SetColumn($st.Panel, 1); [System.Windows.Controls.Grid]::SetRow($st.Panel, 0)
        $st.Panel.Margin = [System.Windows.Thickness]::new(16, 0, 0, 0)
    } else {
        $r1 = New-Object System.Windows.Controls.RowDefinition; $r1.Height = $conv.ConvertFromString('*')
        $r2 = New-Object System.Windows.Controls.RowDefinition; $r2.Height = $conv.ConvertFromString('Auto')
        $Grid.RowDefinitions.Add($r1); $Grid.RowDefinitions.Add($r2)
        [System.Windows.Controls.Grid]::SetColumn($st.Main, 0); [System.Windows.Controls.Grid]::SetRow($st.Main, 0)
        [System.Windows.Controls.Grid]::SetColumn($st.Panel, 0); [System.Windows.Controls.Grid]::SetRow($st.Panel, 1)
        $st.Panel.Margin = [System.Windows.Thickness]::new(0, 16, 0, 0)
    }
    $st.Mode = $mode
    return $mode
}
