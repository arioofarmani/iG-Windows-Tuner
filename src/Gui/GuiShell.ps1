# GuiShell.ps1
# The window shell around the pages: the remembered view state (gui-state.json), the display
# settings (theme, text size, density, reduce motion), the custom title bar (WindowChrome),
# themed dialogs that replace MessageBox, and toasts with Undo. Nothing here changes the PC:
# the only file written is the per-user view state.

#region Event handlers (registered once)

# Control -> registration ids. Weak keys: closed dialogs and rebuilt rows are not kept alive.
$script:IgwtHandlerRegistry = New-Object 'System.Runtime.CompilerServices.ConditionalWeakTable[object,System.Collections.Generic.HashSet[string]]'
$script:IgwtHandlerDuplicates = 0

function Register-IgwtGuiHandler {
    <#
    .SYNOPSIS
        The one way the GUI subscribes to events. A registration is identified by control, event
        and the calling line (or -Key), so code that runs again (a page loaded twice, a list
        rebuilt) cannot attach the same handler twice and make an action fire several times.
    .PARAMETER Event
        CLR event name (Click, SelectionChanged, Tick, ...).
    .PARAMETER RoutedEvent
        A routed event handled for the whole subtree (AddHandler), for example ButtonBase.ClickEvent.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Subscribes a window event only.')]
    [CmdletBinding(DefaultParameterSetName = 'Clr')]
    param([Parameter(Mandatory = $true)]$Control,
        [Parameter(Mandatory = $true, ParameterSetName = 'Clr')][string]$Event,
        [Parameter(Mandatory = $true, ParameterSetName = 'Routed')][System.Windows.RoutedEvent]$RoutedEvent,
        [Parameter(Mandatory = $true)]$Handler, [string]$Key)
    if ($Handler -isnot [scriptblock] -and $Handler -isnot [System.Delegate]) { throw "Register-IgwtGuiHandler: -Handler must be a script block or a delegate." }
    $target = $Control.PSObject.BaseObject
    if (-not $Key) { $Key = '{0}:{1}' -f $MyInvocation.ScriptName, $MyInvocation.ScriptLineNumber }
    $name = $(if ($RoutedEvent) { "routed:$($RoutedEvent.OwnerType.Name).$($RoutedEvent.Name)" } else { $Event })
    $set = $script:IgwtHandlerRegistry.GetOrCreateValue($target)
    if (-not $set.Add("$name|$Key")) {
        $script:IgwtHandlerDuplicates++
        Write-Verbose "Handler for $name from $Key is already registered on this control; not added again."
        return
    }
    if ($RoutedEvent) { $target.AddHandler($RoutedEvent, $(if ($Handler -is [System.Delegate]) { $Handler } else { [System.Windows.RoutedEventHandler]$Handler })) }
    else { $target."Add_$Event"($Handler) }
}

#endregion

#region View state (gui-state.json)

function Get-IgwtGuiStatePath {
    <# .SYNOPSIS Path of the per-user view state: IGWT_GUI_STATE_DIR (test harness) or %LOCALAPPDATA%\iGWindowsTuner. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $dir = $env:IGWT_GUI_STATE_DIR
    if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'iGWindowsTuner' }
    return (Join-Path $dir 'gui-state.json')
}

function Read-IgwtGuiState {
    <# .SYNOPSIS The saved view state as a hashtable (empty when missing or unreadable). #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $out = @{}
    $path = Get-IgwtGuiStatePath
    if (-not (Test-Path -LiteralPath $path)) { return $out }
    try {
        $obj = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($p in $obj.PSObject.Properties) { $out[$p.Name] = $p.Value }
    } catch { Write-Verbose "View state not read: $($_.Exception.Message)" }
    return $out
}

function Save-IgwtGuiState {
    <# .SYNOPSIS Writes the view state (not while rendering screenshots). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state of the window only.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui -or $script:Gui.NoStateSave) { return }
    $path = Get-IgwtGuiStatePath
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        [pscustomobject]$script:Gui.ViewState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    } catch { Write-Verbose "View state not saved: $($_.Exception.Message)" }
}

function Set-IgwtGuiViewValue {
    <# .SYNOPSIS Stores one view-state value and saves the state. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state of the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, $Value)
    if (-not $script:Gui) { return }
    $script:Gui.ViewState[$Name] = $Value
    Save-IgwtGuiState
}

#endregion

#region Display settings

$script:IgwtThemeChoices = [ordered]@{ 'System' = 'System (follow Windows)'; 'Dark' = 'Dark'; 'Light' = 'Light'; 'HighContrast' = 'High contrast' }
$script:IgwtTextScaleChoices = @(100, 115, 130, 150)

function Initialize-IgwtGuiDisplay {
    <#
    .SYNOPSIS
        Applies the theme, text size and density at start (an explicit -Theme wins over the saved
        choice) and wires the Display popup and the Windows high-contrast switch.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([string]$Theme)
    $w = $script:Gui.Window
    $vs = $script:Gui.ViewState
    $themeName = $(if ($Theme) { $Theme } elseif ($vs.Theme -and [string]$vs.Theme -in $script:IgwtThemeChoices.Keys) { [string]$vs.Theme } else { 'System' })
    $scale = 100
    if ($vs.TextScale -and [int]$vs.TextScale -in $script:IgwtTextScaleChoices) { $scale = [int]$vs.TextScale }
    $density = $(if ([string]$vs.Density -eq 'Compact') { 'Compact' } else { 'Comfortable' })
    $reduce = $(if ($null -ne $vs.ReduceMotion) { [bool]$vs.ReduceMotion } else { -not [System.Windows.SystemParameters]::ClientAreaAnimation })
    $script:Gui.ThemeChoice = $themeName
    $script:Gui.ReduceMotion = $reduce
    $null = Set-IgwtGuiTheme -Target $w -Name $themeName
    Set-IgwtGuiTextScale -Target $w -Percent $scale
    Set-IgwtGuiDensity -Target $w -Mode $density

    $c = $script:Gui.C
    $c.ThemeBox.ItemsSource = @($script:IgwtThemeChoices.Values)
    $c.ThemeBox.SelectedItem = $script:IgwtThemeChoices[$themeName]
    $c.FontScaleBox.ItemsSource = @($script:IgwtTextScaleChoices | ForEach-Object { "$_ %" })
    $c.FontScaleBox.SelectedItem = "$scale %"
    $c.DensityBox.ItemsSource = @('Comfortable', 'Compact')
    $c.DensityBox.SelectedItem = $density
    $c.ReduceMotionBox.IsChecked = $reduce
    Register-IgwtGuiHandler -Control $c.DisplayButton -Event 'Click' -Handler { $script:Gui.C.DisplayPopup.IsOpen = -not $script:Gui.C.DisplayPopup.IsOpen }
    Register-IgwtGuiHandler -Control $c.ThemeBox -Event 'SelectionChanged' -Handler {
            $label = [string]$script:Gui.C.ThemeBox.SelectedItem
            $key = @($script:IgwtThemeChoices.Keys | Where-Object { $script:IgwtThemeChoices[$_] -eq $label }) | Select-Object -First 1
            if (-not $key -or $key -eq $script:Gui.ThemeChoice) { return }
            $script:Gui.ThemeChoice = $key
            $resolved = Set-IgwtGuiTheme -Target $script:Gui.Window -Name $key
            Update-IgwtGuiThemedRows
            Set-IgwtGuiViewValue -Name 'Theme' -Value $key
            Set-IgwtGuiStatus "Theme: $($script:IgwtThemeChoices[$resolved])."
        }
    Register-IgwtGuiHandler -Control $c.FontScaleBox -Event 'SelectionChanged' -Handler {
            $v = [int](([string]$script:Gui.C.FontScaleBox.SelectedItem) -replace '[^\d]', '')
            if (-not $v) { return }
            Set-IgwtGuiTextScale -Target $script:Gui.Window -Percent $v
            Set-IgwtGuiViewValue -Name 'TextScale' -Value $v
        }
    Register-IgwtGuiHandler -Control $c.DensityBox -Event 'SelectionChanged' -Handler {
            $v = [string]$script:Gui.C.DensityBox.SelectedItem
            if (-not $v) { return }
            Set-IgwtGuiDensity -Target $script:Gui.Window -Mode $v
            Set-IgwtGuiViewValue -Name 'Density' -Value $v
        }
    Register-IgwtGuiHandler -Control $c.ReduceMotionBox -Event 'Click' -Handler {
            $script:Gui.ReduceMotion = [bool]$script:Gui.C.ReduceMotionBox.IsChecked
            Set-IgwtGuiViewValue -Name 'ReduceMotion' -Value $script:Gui.ReduceMotion
        }
    # Windows high contrast switched on or off while the app runs: follow it when the theme is System.
    $script:Gui.HcHandler = [System.ComponentModel.PropertyChangedEventHandler] {
        param($s, $e)
        $null = $s
        if ($e.PropertyName -ne 'HighContrast' -or -not $script:Gui) { return }
        $null = $script:Gui.Window.Dispatcher.BeginInvoke([Action] {
                $choice = $(if ([System.Windows.SystemParameters]::HighContrast) { 'HighContrast' } else { $script:Gui.ThemeChoice })
                $null = Set-IgwtGuiTheme -Target $script:Gui.Window -Name $choice
                Update-IgwtGuiThemedRows
            })
    }
    [System.Windows.SystemParameters]::add_StaticPropertyChanged($script:Gui.HcHandler)
}

function Update-IgwtGuiThemedRows {
    <#
    .SYNOPSIS
        Row objects keep live theme brushes, so they follow a theme switch by themselves; lists only
        need a refresh for brushes that were set from code (dashboard tiles).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    if ($script:Gui -and $script:Gui.Data) { try { Update-IgwtGuiDashboard } catch { Write-Verbose "Dashboard not refreshed: $($_.Exception.Message)" } }
}

function Get-IgwtGuiBrush {
    <# .SYNOPSIS The live theme brush of a token (Success, WarningSoft, ...). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Token)
    $b = $script:IgwtThemeBrushes[$Token]
    if ($b) { return $b }
    if ($script:Gui -and $script:Gui.Window) { return $script:Gui.Window.FindResource("Brush$Token") }
    return $null
}

#endregion

#region Title bar

function Initialize-IgwtGuiChrome {
    <# .SYNOPSIS Wires the caption buttons and keeps the content on screen when the window is maximized. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    Register-IgwtGuiHandler -Control $c.CaptionMinButton -Event 'Click' -Handler { $script:Gui.Window.WindowState = 'Minimized' }
    Register-IgwtGuiHandler -Control $c.CaptionMaxButton -Event 'Click' -Handler { $w = $script:Gui.Window; $w.WindowState = $(if ($w.WindowState -eq 'Maximized') { 'Normal' } else { 'Maximized' }) }
    Register-IgwtGuiHandler -Control $c.CaptionCloseButton -Event 'Click' -Handler { $script:Gui.Window.Close() }
    Register-IgwtGuiHandler -Control $script:Gui.Window -Event 'StateChanged' -Handler { Update-IgwtGuiChromeState }
    Update-IgwtGuiChromeState
}

function Update-IgwtGuiChromeState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $w = $script:Gui.Window; $c = $script:Gui.C
    if ($w.WindowState -eq 'Maximized') {
        # A maximized WindowChrome window extends past the screen by the resize border.
        $t = [System.Windows.SystemParameters]::WindowResizeBorderThickness
        $c.RootGrid.Margin = New-Object System.Windows.Thickness(($t.Left + 1), ($t.Top + 1), ($t.Right + 1), ($t.Bottom + 1))
        $w.BorderThickness = 0
        $c.CaptionMaxButton.Content = [string][char]0xE923; $c.CaptionMaxButton.ToolTip = 'Restore'
        [System.Windows.Automation.AutomationProperties]::SetName($c.CaptionMaxButton, 'Restore')
    } else {
        $c.RootGrid.Margin = 0
        $w.BorderThickness = 1
        $c.CaptionMaxButton.Content = [string][char]0xE922; $c.CaptionMaxButton.ToolTip = 'Maximize'
        [System.Windows.Automation.AutomationProperties]::SetName($c.CaptionMaxButton, 'Maximize')
    }
}

#endregion

#region Dialogs

function Copy-IgwtGuiResources {
    <# .SYNOPSIS Shares the main window's theme (styles and live brushes) with a dialog window. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the dialog window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target)
    $src = $script:Gui.Window.Resources
    foreach ($k in @($src.Keys)) { $Target.Resources[$k] = $src[$k] }
}

function Show-IgwtGuiDialog {
    <#
    .SYNOPSIS
        Themed message dialog with the same contract as MessageBox: returns 'OK', 'Yes', 'No' or
        'Cancel'. Enter picks the primary button, Esc cancels (No for Yes/No).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Text, [string]$Title = 'iG Windows Tuner', [ValidateSet('OK', 'OKCancel', 'YesNo', 'YesNoCancel')][string]$Buttons = 'OK',
        [ValidateSet('Information', 'Warning', 'Error', 'Question', 'None')][string]$Icon = 'Information')
    $main = $script:Gui.Window
    $w = New-Object System.Windows.Window
    $w.Title = $Title
    $w.Owner = $main
    $w.WindowStartupLocation = 'CenterOwner'
    $w.SizeToContent = 'WidthAndHeight'
    $w.ResizeMode = 'NoResize'
    $w.ShowInTaskbar = $false
    $w.MinWidth = 420; $w.MaxWidth = 640
    Copy-IgwtGuiResources -Target $w
    $w.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'BrushSurface')
    $w.SetResourceReference([System.Windows.Window]::BorderBrushProperty, 'BrushBorderStrong')
    $w.BorderThickness = 1
    $w.SetResourceReference([System.Windows.Window]::FontFamilyProperty, 'FontUi')
    $w.SetResourceReference([System.Windows.Window]::FontSizeProperty, 'FontSizeBody')
    $chrome = New-Object System.Windows.Shell.WindowChrome
    $chrome.CaptionHeight = 40; $chrome.GlassFrameThickness = 0; $chrome.UseAeroCaptionButtons = $false; $chrome.ResizeBorderThickness = 0
    [System.Windows.Shell.WindowChrome]::SetWindowChrome($w, $chrome)

    $glyph = @{ Information = 0xE946; Warning = 0xE7BA; Error = 0xEA39; Question = 0xE9CE; None = 0xE946 }[$Icon]
    $tone = @{ Information = 'Info'; Warning = 'Warning'; Error = 'Danger'; Question = 'Accent'; None = 'TextMuted' }[$Icon]
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '24,20,24,18'
    foreach ($h in 'Auto', '*', 'Auto') { $rd = New-Object System.Windows.Controls.RowDefinition; $rd.Height = $h; $grid.RowDefinitions.Add($rd) }
    $head = New-Object System.Windows.Controls.StackPanel; $head.Orientation = 'Horizontal'; $head.Margin = '0,0,0,12'
    $ic = New-Object System.Windows.Controls.TextBlock
    $ic.Text = [string][char]$glyph; $ic.Style = $w.Resources['Icon']; $ic.FontSize = 20; $ic.Margin = '0,0,12,0'
    $ic.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "Brush$tone")
    $tt = New-Object System.Windows.Controls.TextBlock
    $tt.Text = ($Title -replace '^iG Windows Tuner( - )?', ''); if (-not $tt.Text) { $tt.Text = 'iG Windows Tuner' }
    $tt.FontWeight = 'SemiBold'; $tt.VerticalAlignment = 'Center'; $tt.TextWrapping = 'Wrap'
    $tt.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, 'FontSizeSubtitle')
    $null = $head.Children.Add($ic); $null = $head.Children.Add($tt)
    [System.Windows.Controls.Grid]::SetRow($head, 0)
    $sv = New-Object System.Windows.Controls.ScrollViewer; $sv.VerticalScrollBarVisibility = 'Auto'; $sv.MaxHeight = 460
    $body = New-Object System.Windows.Controls.TextBlock
    $body.Text = $Text; $body.TextWrapping = 'Wrap'; $body.LineHeight = 21
    $sv.Content = $body
    [System.Windows.Controls.Grid]::SetRow($sv, 1)
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,20,0,0'
    [System.Windows.Controls.Grid]::SetRow($panel, 2)
    $result = @{ Value = $(switch ($Buttons) { 'OK' { 'OK' } 'OKCancel' { 'Cancel' } 'YesNo' { 'No' } default { 'Cancel' } }) }
    $names = @{ OK = @('OK'); OKCancel = @('OK', 'Cancel'); YesNo = @('Yes', 'No'); YesNoCancel = @('Yes', 'No', 'Cancel') }[$Buttons]
    $last = $names[-1]
    foreach ($n in $names) {
        $b = New-Object System.Windows.Controls.Button
        $b.Content = $n; $b.MinWidth = 96; $b.Tag = $n
        $b.Style = $(if ($n -in 'OK', 'Yes') { $w.Resources['AccentButton'] } else { $w.Resources[[System.Windows.Controls.Button]] })
        if ($n -in 'OK', 'Yes') { $b.IsDefault = $true }
        if ($n -eq $result.Value) { $b.IsCancel = $true }
        if ($n -eq $last) { $b.Margin = '0' }
        Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { param($s, $e) $null = $e; $result.Value = [string]$s.Tag; $w.Close() }.GetNewClosure()
        $null = $panel.Children.Add($b)
    }
    $null = $grid.Children.Add($head); $null = $grid.Children.Add($sv); $null = $grid.Children.Add($panel)
    $w.Content = $grid
    Register-IgwtGuiHandler -Control $w -Event 'ContentRendered' -Handler { $first = @($panel.Children)[0]; if ($first) { $null = $first.Focus() } }.GetNewClosure()
    $null = $w.ShowDialog()
    return [string]$result.Value
}

function Read-IgwtGuiText {
    <# .SYNOPSIS Themed one-line text prompt. Returns the text, or '' when cancelled. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Title = 'iG Windows Tuner', [string]$Prompt = '', [string]$Default = '')
    $w = New-Object System.Windows.Window
    $w.Title = $Title; $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'
    $w.SizeToContent = 'Height'; $w.Width = 440; $w.ResizeMode = 'NoResize'; $w.ShowInTaskbar = $false
    Copy-IgwtGuiResources -Target $w
    $w.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'BrushSurface')
    $w.SetResourceReference([System.Windows.Window]::FontSizeProperty, 'FontSizeBody')
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Margin = '20,16,20,16'
    $label = New-Object System.Windows.Controls.TextBlock; $label.Text = $Prompt; $label.TextWrapping = 'Wrap'; $label.Margin = '0,0,0,8'
    $box = New-Object System.Windows.Controls.TextBox; $box.Text = $Default; $box.Style = $w.Resources[[System.Windows.Controls.TextBox]]
    [System.Windows.Automation.AutomationProperties]::SetName($box, $Prompt)
    $buttons = New-Object System.Windows.Controls.StackPanel; $buttons.Orientation = 'Horizontal'; $buttons.HorizontalAlignment = 'Right'; $buttons.Margin = '0,16,0,0'
    $result = @{ Text = '' }
    $ok = New-Object System.Windows.Controls.Button; $ok.Content = 'OK'; $ok.MinWidth = 90; $ok.IsDefault = $true; $ok.Style = $w.Resources['AccentButton']
    Register-IgwtGuiHandler -Control $ok -Event 'Click' -Handler { $result.Text = ([string]$box.Text).Trim(); $w.Close() }.GetNewClosure()
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.MinWidth = 90; $cancel.IsCancel = $true; $cancel.Margin = '0'
    $cancel.Style = $w.Resources[[System.Windows.Controls.Button]]
    Register-IgwtGuiHandler -Control $cancel -Event 'Click' -Handler { $w.Close() }.GetNewClosure()
    $null = $buttons.Children.Add($ok); $null = $buttons.Children.Add($cancel)
    $null = $panel.Children.Add($label); $null = $panel.Children.Add($box); $null = $panel.Children.Add($buttons)
    $w.Content = $panel
    Register-IgwtGuiHandler -Control $w -Event 'ContentRendered' -Handler { $null = $box.Focus(); $box.SelectAll() }.GetNewClosure()
    $null = $w.ShowDialog()
    return [string]$result.Text
}

#endregion

#region Toasts

function Show-IgwtGuiToast {
    <#
    .SYNOPSIS
        Shows a short result at the bottom right for about 10 seconds. -ActionText/-Action adds a
        button (for example Undo). Status is icon plus text, never colour only.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text, [ValidateSet('Info', 'Success', 'Warning', 'Danger')][string]$Tone = 'Success',
        [string]$ActionText, [scriptblock]$Action, [int]$Seconds = 10)
    $c = $script:Gui.C
    $glyph = @{ Info = 0xE946; Success = 0xE73E; Warning = 0xE7BA; Danger = 0xEA39 }[$Tone]
    $toast = New-Object System.Windows.Controls.Border
    $toast.Style = $script:Gui.Window.FindResource('Toast')
    [System.Windows.Automation.AutomationProperties]::SetName($toast, $Text)
    $dock = New-Object System.Windows.Controls.DockPanel
    $ic = New-Object System.Windows.Controls.TextBlock
    $ic.Text = [string][char]$glyph; $ic.Style = $script:Gui.Window.FindResource('Icon'); $ic.Margin = '0,0,10,0'
    $ic.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "Brush$Tone")
    [System.Windows.Controls.DockPanel]::SetDock($ic, 'Left')
    $close = New-Object System.Windows.Controls.Button
    $close.Style = $script:Gui.Window.FindResource('GhostButton'); $close.Content = [string][char]0xE711; $close.FontFamily = $script:Gui.Window.FindResource('FontIcons')
    $close.FontSize = 10; $close.Padding = '8,4'; $close.Margin = '6,0,0,0'; $close.MinHeight = 0; $close.ToolTip = 'Close'
    [System.Windows.Automation.AutomationProperties]::SetName($close, 'Close message')
    [System.Windows.Controls.DockPanel]::SetDock($close, 'Right')
    $null = $dock.Children.Add($ic); $null = $dock.Children.Add($close)
    $state = @{ Toast = $toast; Timer = $null }
    if ($ActionText -and $Action) {
        $act = New-Object System.Windows.Controls.Button
        $act.Content = $ActionText; $act.Style = $script:Gui.Window.FindResource('LinkButton'); $act.Margin = '12,0,0,0'; $act.VerticalAlignment = 'Center'
        [System.Windows.Controls.DockPanel]::SetDock($act, 'Right')
        Register-IgwtGuiHandler -Control $act -Event 'Click' -Handler { if ($state.Timer) { $state.Timer.Stop() }; $null = $script:Gui.C.ToastHost.Children.Remove($state.Toast); & $Action }.GetNewClosure()
        $null = $dock.Children.Add($act)
    }
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $Text; $tb.TextWrapping = 'Wrap'; $tb.VerticalAlignment = 'Center'
    $null = $dock.Children.Add($tb)
    $toast.Child = $dock
    Register-IgwtGuiHandler -Control $close -Event 'Click' -Handler { if ($state.Timer) { $state.Timer.Stop() }; $null = $script:Gui.C.ToastHost.Children.Remove($state.Toast) }.GetNewClosure()
    while ($c.ToastHost.Children.Count -ge 3) { $c.ToastHost.Children.RemoveAt(0) }
    $null = $c.ToastHost.Children.Add($toast)
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds([math]::Max(3, $Seconds))
    Register-IgwtGuiHandler -Control $timer -Event 'Tick' -Handler { $state.Timer.Stop(); $null = $script:Gui.C.ToastHost.Children.Remove($state.Toast) }.GetNewClosure()
    $state.Timer = $timer
    # Keep the toast while the pointer is over it, so it can be read and its button used.
    Register-IgwtGuiHandler -Control $toast -Event 'MouseEnter' -Handler { $state.Timer.Stop() }.GetNewClosure()
    Register-IgwtGuiHandler -Control $toast -Event 'MouseLeave' -Handler { $state.Timer.Start() }.GetNewClosure()
    $timer.Start()
    if ($script:Gui.DiagnosticsPath) { Write-IgwtGuiDiagnostic -Kind 'toast' -Text "$Tone $Text" }
}

#endregion
