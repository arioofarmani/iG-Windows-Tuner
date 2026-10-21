# Gui.ps1
# WPF front end. The window is loaded from MainWindow.xaml + Theme.xaml (no code-behind).
# All long operations run in one background runspace (worker) through fixed, exported module
# commands (AddCommand, no script text), so the UI thread never blocks. The GUI contains no
# tweak logic: it stages ids and hands them to the engine.

$script:Gui = $null

$script:IgwtGuiControlNames = @(
    'HeaderVersion', 'HeaderSummary', 'HeaderBuild', 'AcPill', 'AcPillDot', 'AcPillText', 'AdminBadge', 'AdminText', 'ElevateButton',
    'Banner', 'BannerText', 'NavList', 'DetailsColumn', 'DetailsPane',
    'PageDashboard', 'PagePresets', 'PageTweaks', 'PageStartup', 'PageBackups', 'PageRejected', 'PageAbout',
    'RefreshButton', 'ExportReportButton', 'AcReqList', 'AcMatrixList', 'HealthList', 'NvidiaList', 'RecommendList', 'HardwareTagList', 'HardwareOverlayList',
    'PresetCards', 'RevertLastButton', 'RevertSnapshotButton', 'ResetStagedButton',
    'TweakPageTitle', 'TweakPageSubtitle', 'SearchBox', 'FilterTierA', 'FilterTierB', 'FilterRiskLow', 'FilterRiskMedium', 'FilterRiskHigh',
    'FilterRestart', 'FilterChanged', 'TweakList',
    'StartupRefreshButton', 'StartupList', 'BackupRevertLastButton', 'BackupRevertSelectedButton', 'OpenBackupsButton', 'OpenLogsButton', 'SnapshotList',
    'RejectedList', 'AboutText',
    'PageCleaner', 'CleanScanButton', 'CleanRunButton', 'CleanCancelButton', 'CleanLevelBox', 'CleanOptInBox', 'CleanSummaryText', 'CleanerList',
    'PageDisk', 'DiskPathBox', 'DiskAnalyzeButton', 'DiskCancelButton', 'DiskOpenButton', 'DiskSummaryText', 'DiskFolderList', 'DiskFileList',
    'PageAsr', 'AsrRefreshButton', 'AsrAuditButton', 'AsrRecommendButton', 'AsrSummaryText', 'AsrList', 'AsrDetName', 'AsrDetMeta', 'AsrDetDescription', 'AsrDetImpact',
    'AsrModeBox', 'AsrSetModeButton', 'AsrExclusionList', 'AsrExclusionBox', 'AsrGlobalBox', 'AsrAddExclusionButton', 'AsrRemoveExclusionButton', 'AsrDetSources',
    'AsrAuditExcludeButton', 'AsrAuditSummaryText', 'AsrAuditList', 'SecurityScoreText', 'SecurityFixList',
    'PageInspect', 'InspectRefreshButton', 'InspectTabs', 'InspectPowerAllBox', 'InspectPowerSummary', 'InspectPowerList', 'InspectPowerDetailName', 'InspectPowerDetailText',
    'InspectPowerAcBox', 'InspectPowerDcBox', 'InspectPowerApplyButton', 'InspectPowerDefaultButton', 'InspectIrqSummary', 'InspectIrqList', 'InspectNicList',
    'InspectKernelChangedBox', 'InspectKernelSummary', 'InspectKernelList', 'InspectCrashText',
    'PageManage', 'ManageRefreshButton', 'ManageSearchBox', 'ManageTabs', 'ManageServiceSummary', 'ManageServiceList', 'ManageServiceDetail', 'ManageServiceStartBox', 'ManageServiceApplyButton',
    'ManageTaskSummary', 'ManageTaskList', 'ManageTaskDetail', 'ManageTaskDisableButton', 'ManageTaskEnableButton',
    'ManageAppSummary', 'ManageAppList', 'ManageAppDetail', 'ManageAppProvisionedBox', 'ManageAppRemoveButton',
    'ManagePersistSummary', 'ManagePersistList', 'ManagePersistDetail', 'ManagePersistDisableButton', 'ManagePersistExportButton',
    'ManageFirewallSummary', 'ManageFirewallList', 'ManageFirewallDetail', 'ManageFirewallToggleButton', 'ManageHostsText',
    'PageDiagnostics', 'DiagRefreshButton', 'DiagReportButton', 'DiagTabs', 'DiagOverviewText', 'DiagDriverSummary', 'DiagDriverList', 'DiagUpdateText',
    'DiagDnsButton', 'DiagLatencyBox', 'DiagLatencyButton', 'DiagNetText', 'DiagAdapterSummary', 'DiagAdapterList',
    'PageNetTest', 'NetDurationBox', 'NetTargetsBox', 'NetRunButton', 'NetLoadButton', 'NetExportButton', 'NetStatusText', 'NetGradeText', 'NetScoreText', 'NetLatencyText',
    'NetJitterText', 'NetLossText', 'NetStabilityText', 'NetConnectionText', 'NetEvidenceText', 'NetTargetList', 'NetApplyButton', 'NetRecoTitle', 'NetRecoList', 'NetGuidanceList', 'NetPathText',
    'DetName', 'DetMeta', 'DetWarning', 'DetWarningText', 'DetDescription', 'DetChanges', 'DetSources', 'DetEvidence', 'DetRevert', 'DetResetButton',
    'PendingText', 'StatusText', 'BusyBar', 'PreviewButton', 'ApplyButton', 'DiscardButton', 'LogExpander', 'LogBox'
)

#region XAML

function Get-IgwtGuiXaml {
    <# .SYNOPSIS MainWindow.xaml with Theme.xaml merged into Window.Resources (as an XmlDocument). #>
    [CmdletBinding()]
    param()
    $dir = Join-Path $script:IgwtModuleRoot 'Gui'
    $main = New-Object System.Xml.XmlDocument
    $main.PreserveWhitespace = $false
    $main.Load((Join-Path $dir 'MainWindow.xaml'))
    $theme = New-Object System.Xml.XmlDocument
    $theme.Load((Join-Path $dir 'Theme.xaml'))
    $ns = New-Object System.Xml.XmlNamespaceManager($main.NameTable)
    $ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
    $rd = $main.SelectSingleNode('/w:Window/w:Window.Resources/w:ResourceDictionary', $ns)
    if (-not $rd) { throw 'MainWindow.xaml: Window.Resources/ResourceDictionary not found.' }
    foreach ($child in @($theme.DocumentElement.ChildNodes)) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) { $null = $rd.AppendChild($main.ImportNode($child, $true)) }
    }
    return $main
}

function Import-IgwtWpf {
    [CmdletBinding()]
    param()
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
}

function New-IgwtMainWindow {
    <# .SYNOPSIS Parses the window (also used headlessly by the XAML test). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    Import-IgwtWpf
    $xml = Get-IgwtGuiXaml
    $reader = New-Object System.Xml.XmlNodeReader($xml)
    return [Windows.Markup.XamlReader]::Load($reader)
}

#endregion

#region Helpers

function Get-IgwtGuiControl {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    return $script:Gui.C[$Name]
}

function Set-IgwtGuiStatus {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Text)
    if ($PSCmdlet.ShouldProcess('status', 'Set')) { $script:Gui.C.StatusText.Text = $Text }
}

function Add-IgwtGuiLogLine {
    [CmdletBinding()]
    param([string]$Line)
    $box = $script:Gui.C.LogBox
    $box.AppendText($Line + [Environment]::NewLine)
    if ($box.Text.Length -gt 60000) { $box.Text = $box.Text.Substring($box.Text.Length - 40000) }
    $box.ScrollToEnd()
}

function Show-IgwtGuiMessage {
    [CmdletBinding()]
    param([string]$Text, [string]$Title = 'iG Windows Tuner', [string]$Buttons = 'OK', [string]$Icon = 'Information')
    return [System.Windows.MessageBox]::Show($script:Gui.Window, $Text, $Title, [System.Windows.MessageBoxButton]$Buttons, [System.Windows.MessageBoxImage]$Icon)
}

function Show-IgwtGuiTextDialog {
    <# .SYNOPSIS Read-only text dialog (preview / results). Returns $true when the user accepts. #>
    [CmdletBinding()]
    param([string]$Title, [string]$Text, [string]$AcceptText = '', [string]$CancelText = 'Close')
    $w = New-Object System.Windows.Window
    $w.Title = $Title
    $w.Width = 900; $w.Height = 620; $w.MinWidth = 600; $w.MinHeight = 400
    $w.Owner = $script:Gui.Window
    $w.WindowStartupLocation = 'CenterOwner'
    $w.Background = $script:Gui.Window.FindResource('BrushBackground')
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '14'
    $r1 = New-Object System.Windows.Controls.RowDefinition; $r1.Height = '*'
    $r2 = New-Object System.Windows.Controls.RowDefinition; $r2.Height = 'Auto'
    $grid.RowDefinitions.Add($r1); $grid.RowDefinitions.Add($r2)
    $tb = New-Object System.Windows.Controls.TextBox
    $tb.Text = $Text; $tb.IsReadOnly = $true; $tb.FontFamily = $script:Gui.Window.FindResource('FontMono'); $tb.FontSize = 12
    $tb.VerticalScrollBarVisibility = 'Auto'; $tb.HorizontalScrollBarVisibility = 'Auto'; $tb.TextWrapping = 'NoWrap'
    $tb.Style = $script:Gui.Window.FindResource([System.Windows.Controls.TextBox])
    [System.Windows.Controls.Grid]::SetRow($tb, 0)
    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,12,0,0'
    [System.Windows.Controls.Grid]::SetRow($panel, 1)
    $result = @{ Accepted = $false }
    if ($AcceptText) {
        $ok = New-Object System.Windows.Controls.Button
        $ok.Content = $AcceptText; $ok.Style = $script:Gui.Window.FindResource('AccentButton')
        $ok.Add_Click({ $result.Accepted = $true; $w.Close() }.GetNewClosure())
        $null = $panel.Children.Add($ok)
    }
    $cancel = New-Object System.Windows.Controls.Button
    $cancel.Content = $CancelText; $cancel.Style = $script:Gui.Window.FindResource([System.Windows.Controls.Button]); $cancel.IsCancel = $true
    $cancel.Add_Click({ $w.Close() }.GetNewClosure())
    $null = $panel.Children.Add($cancel)
    $null = $grid.Children.Add($tb); $null = $grid.Children.Add($panel)
    $w.Content = $grid
    $null = $w.ShowDialog()
    return [bool]$result.Accepted
}

function Show-IgwtGuiRiskDialog {
    <#
    .SYNOPSIS
        Risk Zone confirmation: shows the warning, what the item turns off and on, its risks and the
        reason it was rejected, and enables "Stage at my own risk" only after the user types
        I ACCEPT. Returns $true when the user accepts.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Tweak)
    $rz = $Tweak.riskZone
    $nl = [Environment]::NewLine
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($Tweak.name)  ($($Tweak.id))"); $lines.Add('')
    $lines.Add([string]$Tweak.warning); $lines.Add('')
    $off = @($rz.turnsOff | Where-Object { $_ }); $on = @($rz.turnsOn | Where-Object { $_ })
    if ($off.Count) { $lines.Add('It turns OFF:'); foreach ($x in $off) { $lines.Add("  - $x") } }
    if ($on.Count) { $lines.Add('It turns ON:'); foreach ($x in $on) { $lines.Add("  - $x") } }
    $lines.Add('Risks:'); foreach ($x in @($rz.risks | Where-Object { $_ })) { $lines.Add("  - $x") }
    $lines.Add(''); $lines.Add("Why it was rejected: $(([string]$Tweak.evidence.notes) -replace '^Rejected:\s*', '')")
    $lines.Add(''); $lines.Add("$(switch ($Tweak.requires) { 'reboot' { 'Needs a restart to take effect.' } 'logoff' { 'Needs a sign-out to take effect.' } default { 'Takes effect immediately.' } }) A snapshot is written first; revert it in Backups & Logs or by turning the toggle off.")
    $w = New-Object System.Windows.Window
    $w.Title = 'iG Windows Tuner - Risk Zone'
    $w.Width = 720; $w.Height = 560; $w.MinWidth = 520; $w.MinHeight = 420
    $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'
    $w.Background = $script:Gui.Window.FindResource('BrushBackground')
    $grid = New-Object System.Windows.Controls.Grid; $grid.Margin = '16'
    foreach ($h in 'Auto', '*', 'Auto', 'Auto') { $rd = New-Object System.Windows.Controls.RowDefinition; $rd.Height = $h; $grid.RowDefinitions.Add($rd) }
    $head = New-Object System.Windows.Controls.TextBlock
    $head.Text = 'You are about to stage a rejected tweak. iG Windows Tuner does not recommend it.'
    $head.Foreground = $script:Gui.Window.FindResource('BrushDanger'); $head.FontWeight = 'SemiBold'; $head.TextWrapping = 'Wrap'; $head.Margin = '0,0,0,8'
    [System.Windows.Controls.Grid]::SetRow($head, 0)
    $body = New-Object System.Windows.Controls.TextBox
    $body.Text = ($lines -join $nl); $body.IsReadOnly = $true; $body.TextWrapping = 'Wrap'; $body.VerticalScrollBarVisibility = 'Auto'
    $body.Style = $script:Gui.Window.FindResource([System.Windows.Controls.TextBox])
    [System.Windows.Controls.Grid]::SetRow($body, 1)
    $confirm = New-Object System.Windows.Controls.StackPanel; $confirm.Margin = '0,10,0,0'
    $label = New-Object System.Windows.Controls.TextBlock; $label.Text = 'Type I ACCEPT to confirm that you apply this at your own risk:'; $label.Foreground = $script:Gui.Window.FindResource('BrushText')
    $box = New-Object System.Windows.Controls.TextBox; $box.Margin = '0,4,0,0'; $box.Style = $script:Gui.Window.FindResource([System.Windows.Controls.TextBox]); $box.ToolTip = 'Type I ACCEPT (not case-sensitive).'
    $null = $confirm.Children.Add($label); $null = $confirm.Children.Add($box)
    [System.Windows.Controls.Grid]::SetRow($confirm, 2)
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,12,0,0'
    [System.Windows.Controls.Grid]::SetRow($panel, 3)
    $result = @{ Accepted = $false }
    $ok = New-Object System.Windows.Controls.Button; $ok.Content = 'Stage at my own risk'; $ok.Style = $script:Gui.Window.FindResource('AccentButton'); $ok.IsEnabled = $false; $ok.ToolTip = 'Enabled after you type I ACCEPT.'
    $ok.Add_Click({ $result.Accepted = $true; $w.Close() }.GetNewClosure())
    $box.Add_TextChanged({ $ok.IsEnabled = (([string]$box.Text).Trim() -ieq 'I ACCEPT') }.GetNewClosure())
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.Style = $script:Gui.Window.FindResource([System.Windows.Controls.Button]); $cancel.IsCancel = $true; $cancel.IsDefault = $true; $cancel.ToolTip = 'Do not stage this tweak.'
    $cancel.Add_Click({ $w.Close() }.GetNewClosure())
    $null = $panel.Children.Add($ok); $null = $panel.Children.Add($cancel)
    foreach ($el in $head, $body, $confirm, $panel) { $null = $grid.Children.Add($el) }
    $w.Content = $grid
    $null = $w.ShowDialog()
    return [bool]$result.Accepted
}

function Open-IgwtGuiPath {
    <# .SYNOPSIS Opens a folder, file or https URL with the shell (user-initiated only). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Target)
    if ($Target -match '^https://' -or (Test-Path -LiteralPath $Target)) {
        if ($PSCmdlet.ShouldProcess($Target, 'Open')) { Start-Process -FilePath $Target }
    }
}

#endregion

#region Background worker

function Initialize-IgwtGuiWorker {
    [CmdletBinding()]
    param()
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::MTA
    $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()
    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddCommand('Import-Module').AddParameter('Name', (Join-Path $script:IgwtModuleRoot 'iGWindowsTuner.psd1')).AddParameter('Force', $true)
    $null = $ps.AddStatement().AddCommand('Set-IgwtLogSink').AddParameter('Queue', $script:Gui.Queue)
    $null = $ps.Invoke()
    $ps.Dispose()
    $script:Gui.Runspace = $rs
}

function Start-IgwtGuiJob {
    <#
    .SYNOPSIS
        Runs one exported iG Windows Tuner command in the worker runspace. OnComplete receives the output
        and the error records on the UI thread.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Command, [hashtable]$Parameters = @{}, [scriptblock]$OnComplete, [string]$BusyText = 'Working...', [switch]$Blocking)
    if ($script:Gui.Job) { Set-IgwtGuiStatus 'Busy - please wait for the current operation to finish.'; return $false }
    if (-not $PSCmdlet.ShouldProcess($Command, 'Run in background')) { return $false }
    $ps = [PowerShell]::Create()
    $ps.Runspace = $script:Gui.Runspace
    $null = $ps.AddCommand($Command)
    foreach ($k in $Parameters.Keys) { $null = $ps.AddParameter($k, $Parameters[$k]) }
    $handle = $ps.BeginInvoke()
    $script:Gui.Job = @{ PS = $ps; Handle = $handle; OnComplete = $OnComplete; Command = $Command; Blocking = [bool]$Blocking }
    $script:Gui.C.BusyBar.Visibility = 'Visible'
    $script:Gui.C.BusyBar.IsIndeterminate = $true
    Set-IgwtGuiStatus $BusyText
    Update-IgwtGuiButtons
    return $true
}

function Invoke-IgwtGuiTick {
    <# .SYNOPSIS DispatcherTimer tick: drain log/progress queue and complete finished jobs. #>
    [CmdletBinding()]
    param()
    $item = $null
    $n = 0
    while ($n -lt 200 -and $script:Gui.Queue.TryDequeue([ref]$item)) {
        $n++
        if ($item.Kind -eq 'log') {
            $e = $item.Entry
            $t = ''
            try { $t = ([datetime]$e.time).ToString('HH:mm:ss') } catch { $t = '' }
            Add-IgwtGuiLogLine ("{0} [{1}] {2}{3}" -f $t, ([string]$e.level).ToUpperInvariant(), $(if ($e.PSObject.Properties['tweak'] -and $e.tweak) { "$($e.tweak) - " } else { '' }), $e.message)
            if ($e.level -in 'Warn', 'Error') { $script:Gui.C.LogExpander.IsExpanded = $true }
        } elseif ($item.Kind -eq 'progress') {
            if ([int]$item.Percent -ge 0) {
                $script:Gui.C.BusyBar.IsIndeterminate = $false
                $script:Gui.C.BusyBar.Value = [double]$item.Percent
            }
            Set-IgwtGuiStatus ([string]$item.Text)
        }
    }
    $job = $script:Gui.Job
    if ($job -and $job.Handle.IsCompleted) {
        $out = $null
        $errs = @()
        try {
            $out = $job.PS.EndInvoke($job.Handle)
            $errs = @($job.PS.Streams.Error)
        } catch {
            $errs = @($_)
        }
        $job.PS.Dispose()
        $script:Gui.Job = $null
        $script:Gui.C.BusyBar.Visibility = 'Hidden'
        $script:Gui.C.BusyBar.IsIndeterminate = $false
        foreach ($er in $errs) { Add-IgwtGuiLogLine "ERROR $($job.Command): $er" }
        if ($errs.Count -gt 0) { $script:Gui.C.LogExpander.IsExpanded = $true }
        Update-IgwtGuiButtons
        if ($job.OnComplete) {
            try { & $job.OnComplete $out $errs } catch { Add-IgwtGuiLogLine "UI error after $($job.Command): $($_.Exception.Message)" }
        }
    }
}

#endregion

#region Data binding

function Update-IgwtGuiFromData {
    <# .SYNOPSIS Applies a Get-IgwtGuiData result to every page. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Data)
    $c = $script:Gui.C
    $script:Gui.Data = $Data
    $script:Gui.IsAdmin = [bool]$Data.IsAdmin
    if ($Data.Summary) { $c.HeaderSummary.Text = [string]$Data.Summary.Text }
    $os = $Data.Preflight.Os
    $dg = $Data.AntiCheat.Requirements
    $c.HeaderBuild.Text = ("{0} {1} build {2}  |  Secure Boot {3}  |  VBS {4}  |  HVCI {5}" -f ($os.Caption -replace '^Microsoft ', ''), $os.DisplayVersion, $os.FullBuild,
        $(if ($dg.secureBoot.Pass) { 'on' } else { 'OFF' }), $(if ($dg.vbs.Pass) { 'running' } else { 'off' }), $(if ($dg.hvci.Pass) { 'running' } else { 'off' }))

    # Admin badge
    if ($script:Gui.IsAdmin) {
        $c.AdminText.Text = 'Administrator'
        $c.AdminBadge.BorderBrush = $script:Gui.Window.FindResource('BrushSuccess'); $c.AdminBadge.BorderThickness = '1'
        $c.ElevateButton.Visibility = 'Collapsed'
    } else {
        $c.AdminText.Text = 'Read-only (not elevated)'
        $c.AdminBadge.BorderBrush = $script:Gui.Window.FindResource('BrushWarning'); $c.AdminBadge.BorderThickness = '1'
        $c.ElevateButton.Visibility = 'Visible'
    }

    # Anti-cheat pill
    $overall = [string]$Data.AntiCheat.Overall
    switch ($overall) {
        'Green' { $c.AcPillDot.Fill = $script:Gui.Window.FindResource('BrushSuccess'); $c.AcPillText.Text = 'Anti-cheat: ready' }
        'Amber' { $c.AcPillDot.Fill = $script:Gui.Window.FindResource('BrushWarning'); $c.AcPillText.Text = 'Anti-cheat: partially ready' }
        default { $c.AcPillDot.Fill = $script:Gui.Window.FindResource('BrushDanger'); $c.AcPillText.Text = 'Anti-cheat: requirement missing' }
    }
    $c.AcReqList.ItemsSource = @($Data.AntiCheat.Requirements.PSObject.Properties | ForEach-Object { New-IgwtGuiRequirementRow -Requirement $_.Value })
    $c.AcMatrixList.ItemsSource = @($Data.AntiCheat.Matrix | ForEach-Object { New-IgwtGuiMatrixRow -Entry $_ })
    if ($Data.PSObject.Properties['Hardware'] -and $Data.Hardware) {
        $c.HardwareTagList.ItemsSource = @($Data.Hardware.Tags)
        $c.HardwareOverlayList.ItemsSource = @($Data.Hardware.Overlays)
    }
    if ($Data.Health -and $Data.Health.PSObject.Properties['Security'] -and $Data.Health.Security) {
        $sec = $Data.Health.Security
        $c.SecurityScoreText.Text = ("{0}/100  ({1}){2}" -f $sec.Score, $sec.Grade, $(if (@($sec.ToFix).Count -eq 0) { ' - nothing to fix' } else { '' }))
        $c.SecurityFixList.ItemsSource = @($sec.ToFix | ForEach-Object { New-IgwtGuiSecurityCheckRow -Check $_ })
    }
    if ($Data.Health) {
        $c.HealthList.ItemsSource = @($Data.Health.Checks | ForEach-Object { New-IgwtGuiCheckRow -Check $_ })
        $c.NvidiaList.ItemsSource = @($Data.Health.NvidiaGuidance)
        $c.RecommendList.ItemsSource = @($Data.Health.Recommendations)
    }

    # Banner
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Data.Pending) {
        $what = $(if ($Data.Pending.Requires -eq 'reboot') { 'Restart Windows' } else { 'Sign out and back in' })
        $lines.Add("$what to finish applying $(@($Data.Pending.Tweaks).Count) change(s): $(@($Data.Pending.Tweaks) -join ', ').")
    }
    if (-not $script:Gui.IsAdmin) { $lines.Add('Read-only mode: you can browse, preview, export reports and clean your own temp files and caches. Use "Restart as administrator" to apply tweaks or run system cleanup.') }
    foreach ($w in @($Data.Preflight.Warnings)) { if ($w -notlike 'Not elevated*') { $lines.Add([string]$w) } }
    if ($lines.Count -gt 0) { $c.BannerText.Text = ($lines -join '  '); $c.Banner.Visibility = 'Visible' } else { $c.Banner.Visibility = 'Collapsed' }

    # Startup and backups
    $c.StartupList.ItemsSource = @($Data.Startup | ForEach-Object {
            [pscustomobject]@{ Scope = $_.Scope; Name = $_.Name; Command = $_.Command; Enabled = [bool]$_.Enabled; CanToggle = $script:Gui.IsAdmin }
        })
    Update-IgwtGuiSnapshots -Snapshots $Data.Snapshots
    Update-IgwtGuiPresetCards
    Update-IgwtGuiTweakList
}

function Update-IgwtGuiSnapshots {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Snapshots)
    $script:Gui.C.SnapshotList.ItemsSource = @($Snapshots | ForEach-Object {
            $when = [string]$_.Created
            try { $when = ([datetime]::Parse([string]$_.Created, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch { Write-Verbose 'Unparsable snapshot time.' }
            [pscustomobject]@{ Path = $_.Path; File = $_.File; When = $when; Operation = $_.Operation
                Summary = "$(@($_.Applied).Count) applied/reverted entr(ies), $($_.Failed) failed. $($_.Detail)" }
        })
}

function Get-IgwtGuiFilter {
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    return @{
        TierA = [bool]$c.FilterTierA.IsChecked; TierB = [bool]$c.FilterTierB.IsChecked
        RiskLow = [bool]$c.FilterRiskLow.IsChecked; RiskMedium = [bool]$c.FilterRiskMedium.IsChecked; RiskHigh = [bool]$c.FilterRiskHigh.IsChecked
        Restart = [bool]$c.FilterRestart.IsChecked; Changed = [bool]$c.FilterChanged.IsChecked
    }
}

function Update-IgwtGuiTweakList {
    <# .SYNOPSIS Rebuilds rows (state + staging) and applies page/search/filters. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.Data) { return }
    $c = $script:Gui.C
    $selectedId = $null
    if ($c.TweakList.SelectedItem) { $selectedId = $c.TweakList.SelectedItem.Id }
    $filter = Get-IgwtGuiFilter
    $search = [string]$c.SearchBox.Text
    $rows = foreach ($t in $script:Gui.Catalog) {
        $row = New-IgwtGuiTweakRow -Tweak $t -State $script:Gui.Data.States[$t.id] -Changed ([bool]$script:Gui.Data.Changed[$t.id]) -Staged ([string]$script:Gui.Staged[$t.id]) -IsAdmin $script:Gui.IsAdmin
        if (Test-IgwtGuiRowVisible -Row $row -Category $script:Gui.Category -Search $search -Filter $filter) { $row }
    }
    $rows = @($rows)
    $c.TweakList.ItemsSource = $rows
    if ($selectedId) {
        $again = $rows | Where-Object { $_.Id -eq $selectedId } | Select-Object -First 1
        if ($again) { $c.TweakList.SelectedItem = $again }
    }
    if ($search) { $c.TweakPageTitle.Text = "Search: $search" }
    elseif ($script:Gui.Category -eq 'Storage') { $c.TweakPageTitle.Text = 'Storage Sense' }
    elseif ($script:Gui.Category -eq 'System') { $c.TweakPageTitle.Text = 'System and diagnostics' }
    elseif ($script:Gui.Category -eq 'Risk Zone') { $c.TweakPageTitle.Text = 'Risk Zone: rejected tweaks at your own risk' }
    elseif ($script:Gui.Category) { $c.TweakPageTitle.Text = $script:Gui.Category }
    $c.TweakPageSubtitle.Text = $(if ($script:Gui.Category -eq 'Risk Zone' -and -not $search) { "$($rows.Count) rejected tweak(s). iG Windows Tuner does not recommend these: each is placebo, obsolete or risky, and its details list what it turns off or on. Turning one on asks you to type a confirmation; every change is snapshot-backed and can be reverted." } else { "$($rows.Count) tweak(s). Toggles show the real current state; toggling stages a change. Nothing happens until you press Apply." })
    Update-IgwtGuiPending
}

function Update-IgwtGuiPending {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $n = @($script:Gui.Staged.Keys).Count
    $script:Gui.C.PendingText.Text = "$n pending"
    Update-IgwtGuiButtons
}

function Update-IgwtGuiButtons {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $busy = [bool]$script:Gui.Job
    $n = @($script:Gui.Staged.Keys).Count
    $c.PreviewButton.IsEnabled = (-not $busy) -and $n -gt 0
    $c.ApplyButton.IsEnabled = (-not $busy) -and $n -gt 0 -and $script:Gui.IsAdmin
    $c.DiscardButton.IsEnabled = (-not $busy) -and $n -gt 0
    $c.RefreshButton.IsEnabled = -not $busy
    foreach ($b in 'RevertLastButton', 'RevertSnapshotButton', 'BackupRevertLastButton', 'BackupRevertSelectedButton') { $c[$b].IsEnabled = (-not $busy) -and $script:Gui.IsAdmin }
    $jobCommand = ''
    if ($busy) { $jobCommand = [string]$script:Gui.Job.Command }
    $c.CleanScanButton.IsEnabled = -not $busy
    $c.CleanRunButton.IsEnabled = (-not $busy) -and [bool]$script:Gui.CleanScan -and @(Get-IgwtGuiCleanerSelection).Count -gt 0
    $c.CleanCancelButton.IsEnabled = $busy -and [bool]$script:Gui.Cts -and $jobCommand -like 'Invoke-IgwtCleaner*'
    $c.DiskAnalyzeButton.IsEnabled = -not $busy
    $c.DiskCancelButton.IsEnabled = $busy -and [bool]$script:Gui.Cts -and $jobCommand -eq 'Get-IgwtDiskUsage'
    $asrRow = $c.AsrList.SelectedItem
    $canChange = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$script:Gui.AsrStatus -and [bool]$script:Gui.AsrStatus.DefenderActive
    $c.AsrRefreshButton.IsEnabled = -not $busy
    $c.AsrAuditButton.IsEnabled = -not $busy
    $c.AsrRecommendButton.IsEnabled = $canChange
    $c.AsrSetModeButton.IsEnabled = $canChange -and [bool]$asrRow -and -not $asrRow.Rule.ManagedByPolicy -and @($asrRow.Rule.AllowedModes).Count -gt 0
    $c.AsrAddExclusionButton.IsEnabled = $canChange -and ([bool]$asrRow -or [bool]$c.AsrGlobalBox.IsChecked)
    $c.AsrRemoveExclusionButton.IsEnabled = $canChange -and [bool]$c.AsrExclusionList.SelectedItem
    $c.AsrAuditExcludeButton.IsEnabled = [bool]$c.AsrAuditList.SelectedItem
    $powerRow = $c.InspectPowerList.SelectedItem
    $canPower = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$powerRow -and [bool]$powerRow.Setting.Editable
    $c.InspectRefreshButton.IsEnabled = -not $busy
    $c.InspectPowerApplyButton.IsEnabled = $canPower
    $c.InspectPowerDefaultButton.IsEnabled = $canPower
    $canManage = (-not $busy) -and $script:Gui.IsAdmin
    $svc = $c.ManageServiceList.SelectedItem; $task = $c.ManageTaskList.SelectedItem; $app = $c.ManageAppList.SelectedItem
    $pe = $c.ManagePersistList.SelectedItem; $fw = $c.ManageFirewallList.SelectedItem
    $c.ManageRefreshButton.IsEnabled = -not $busy
    $c.ManageServiceApplyButton.IsEnabled = $canManage -and [bool]$svc -and [bool]$svc.Source.CanChange -and [bool]$c.ManageServiceStartBox.SelectedItem
    $c.ManageTaskDisableButton.IsEnabled = $canManage -and [bool]$task -and [bool]$task.Source.CanDisable
    $c.ManageTaskEnableButton.IsEnabled = $canManage -and [bool]$task -and -not $task.Source.Protected -and [string]$task.Source.State -eq 'Disabled'
    $c.ManageAppRemoveButton.IsEnabled = $canManage -and [bool]$app -and $app.Source.PSObject.Properties['CanRemove'] -and [bool]$app.Source.CanRemove
    $c.ManagePersistDisableButton.IsEnabled = $canManage -and [bool]$pe -and [string]$pe.Source.ActionKind -ne 'None' -and $pe.Source.Enabled -ne $false
    $c.ManagePersistExportButton.IsEnabled = [bool]$script:Gui.Manage -and $script:Gui.Manage.Persistence.PSObject.Properties['Entries']
    $c.ManageFirewallToggleButton.IsEnabled = $canManage -and [bool]$fw -and [bool]$fw.Source.CanChange
    $c.DiagRefreshButton.IsEnabled = -not $busy
    $c.DiagReportButton.IsEnabled = -not $busy
    $c.DiagDnsButton.IsEnabled = -not $busy
    $c.DiagLatencyButton.IsEnabled = -not $busy
    $c.NetRunButton.IsEnabled = -not $busy
    $c.NetLoadButton.IsEnabled = -not $busy
    $c.NetExportButton.IsEnabled = [bool]$script:Gui.NetResult -and -not [string]$script:Gui.NetResult.Error
    $c.NetApplyButton.IsEnabled = (-not $busy) -and [bool]$script:Gui.NetResult -and $script:Gui.NetResult.Recommendations -and @($script:Gui.NetResult.Recommendations.TweakIds).Count -gt 0
}

function Get-IgwtGuiPresetMembers {
    <# .SYNOPSIS A preset's items resolved through this PC's hardware overlays (falls back to the preset's own list before the first refresh). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset)
    $data = $script:Gui.Data
    if ($data -and $data.PSObject.Properties['PresetSelections'] -and $data.PresetSelections -and $data.PresetSelections.ContainsKey([string]$Preset.id)) {
        return @($data.PresetSelections[[string]$Preset.id].Ids)
    }
    return @($Preset.tweaks)
}

function Update-IgwtGuiPresetCards {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $cards = foreach ($p in $script:Gui.Presets) {
        $members = @(Get-IgwtGuiPresetMembers -Preset $p)
        $toChange = 0
        if ($script:Gui.Data) {
            foreach ($id in $members) { $s = $script:Gui.Data.States[$id]; if ($s -and $s.State -in 'Off', 'Partial') { $toChange++ } }
        }
        $overlayText = ''
        $data = $script:Gui.Data
        if ($data -and $data.PSObject.Properties['PresetSelections'] -and $data.PresetSelections -and $data.PresetSelections.ContainsKey([string]$p.id)) {
            $sel = $data.PresetSelections[[string]$p.id]
            $added = @($sel.Items | Where-Object { $_.Included -and $_.Origin -eq 'overlay' }).Count
            $blocked = @($sel.Blocked).Count
            if ($added -or $blocked) { $overlayText = " Hardware overlays on this PC: $added added, $blocked blocked." }
        }
        [pscustomobject]@{
            Id = [string]$p.id; Name = [string]$p.name; Tagline = [string]$p.tagline; Description = [string]$p.description
            Summary = "$($members.Count) tweaks in this preset; $toChange differ from your current state.$overlayText"
            ButtonText = $(if ($toChange -gt 0) { "Stage $toChange change(s)" } else { 'Nothing to change' })
        }
    }
    $script:Gui.C.PresetCards.ItemsSource = @($cards)
}

function Update-IgwtGuiDetails {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = $c.TweakList.SelectedItem
    if (-not $row) { return }
    $t = $script:Gui.Catalog | Where-Object { $_.id -eq $row.Id } | Select-Object -First 1
    $s = $script:Gui.Data.States[$row.Id]
    $c.DetName.Text = [string]$t.name
    $c.DetMeta.Text = ("{0}  |  {1}{2}  |  {3} level  |  Tier {4}  |  risk {5}  |  {6}  |  {7}  |  revert: {8}" -f $t.id, $t.category, $(if ($t.group) { " / $($t.group)" } else { '' }), $t.level, $t.evidence.tier, $t.risk,
        $(switch ($t.requires) { 'reboot' { 'reboot required' } 'logoff' { 'sign-out required' } default { 'applies immediately' } }),
        [string]$t.antiCheatText, [string]$t.reversible)
    if ([string]$t.evidence.tier -eq 'R') { $c.DetWarningText.Text = 'RISK ZONE (rejected tweak). ' + (Get-IgwtRiskZoneSummary -Tweak $t); $c.DetWarning.Visibility = 'Visible' }
    elseif ($t.warning) { $c.DetWarningText.Text = [string]$t.warning; $c.DetWarning.Visibility = 'Visible' } else { $c.DetWarning.Visibility = 'Collapsed' }
    $desc = [string]$t.description
    if ($s -and $s.Reason) { $desc += [Environment]::NewLine + [Environment]::NewLine + "Current state: $($row.StateText). $($s.Reason)" }
    $c.DetDescription.Text = $desc
    $items = @()
    if ($s) { $items = @($s.Items | ForEach-Object { [pscustomobject]@{ Target = [string]$_.Target; Current = [string]$_.Current; Desired = [string]$_.Desired; Note = [string]$_.Note } }) }
    $c.DetChanges.ItemsSource = $items
    $c.DetSources.ItemsSource = @($t.evidence.sources)
    $c.DetEvidence.Text = [string]$t.evidence.notes
    $c.DetRevert.Text = Get-IgwtTweakRevertDescription -Tweak $t
    $hasConfig = @($t.actions | Where-Object { $_.type -ne 'check' }).Count -gt 0
    $c.DetResetButton.IsEnabled = $script:Gui.IsAdmin -and $hasConfig -and $row.State -in 'On', 'Off', 'Partial' -and -not [bool]$script:Gui.Job
}

#endregion

#region Staging and actions

function Set-IgwtGuiStage {
    <# .SYNOPSIS Stages 'on', 'off' or 'reset' for a tweak, or clears staging ($null). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [AllowNull()][AllowEmptyString()][string]$Mode)
    if (-not $PSCmdlet.ShouldProcess($Id, "Stage $Mode")) { return }
    if (-not $Mode) { $null = $script:Gui.Staged.Remove($Id); return }
    $t = $script:Gui.Catalog | Where-Object { $_.id -eq $Id } | Select-Object -First 1
    if ($Mode -eq 'on') {
        foreach ($cf in @($t.conflictsWith)) {
            if ($script:Gui.Staged[[string]$cf] -eq 'on') { $null = $script:Gui.Staged.Remove([string]$cf); Set-IgwtGuiStatus "Unstaged '$cf' because it conflicts with '$Id'." }
        }
    }
    $script:Gui.Staged[$Id] = $Mode
}

function Invoke-IgwtGuiToggle {
    <# .SYNOPSIS Handles a toggle click on a tweak row. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$CheckBox)
    $id = [string]$CheckBox.Tag
    $row = @($script:Gui.C.TweakList.ItemsSource) | Where-Object { $_.Id -eq $id } | Select-Object -First 1
    if (-not $row) { return }
    $want = [bool]$CheckBox.IsChecked
    $isOn = ($row.State -eq 'On')
    $t = $script:Gui.Catalog | Where-Object { $_.id -eq $id } | Select-Object -First 1
    if ($want -eq $isOn) {
        Set-IgwtGuiStage -Id $id -Mode $null
    } elseif ($want) {
        if ([string]$t.evidence.tier -eq 'R') {
            if (-not (Show-IgwtGuiRiskDialog -Tweak $t)) { Update-IgwtGuiTweakList; return }
        } elseif ($t.expert) {
            $answer = Show-IgwtGuiMessage -Text ("EXPERT TOGGLE`n`n$($t.warning)`n`n$($t.description)`n`nStage this change anyway?") -Title 'iG Windows Tuner - expert toggle' -Buttons 'YesNo' -Icon 'Warning'
            if ($answer -ne 'Yes') { Update-IgwtGuiTweakList; return }
        }
        Set-IgwtGuiStage -Id $id -Mode 'on'
    } else {
        Set-IgwtGuiStage -Id $id -Mode 'off'
    }
    Update-IgwtGuiTweakList
    Update-IgwtGuiDetails
}

function Get-IgwtGuiStagedSets {
    [CmdletBinding()]
    param()
    $apply = @(); $off = @(); $reset = @()
    foreach ($k in @($script:Gui.Staged.Keys)) {
        switch ($script:Gui.Staged[$k]) { 'on' { $apply += $k } 'off' { $off += $k } 'reset' { $reset += $k } }
    }
    return [pscustomobject]@{ Apply = $apply; Off = $off; Reset = $reset }
}

function Start-IgwtGuiRefresh {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([switch]$IncludeHealth)
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiData' -Parameters @{ IncludeHealth = [bool]$IncludeHealth } -BusyText 'Reading the current system state (read-only)...' -OnComplete {
        param($out, $errs)
        $data = @($out) | Select-Object -Last 1
        if ($data) { Update-IgwtGuiFromData -Data $data; Set-IgwtGuiStatus "State refreshed at $((Get-Date).ToString('HH:mm:ss'))." }
        else { Set-IgwtGuiStatus 'Could not read the system state; see the log.' }
    }
}

function Invoke-IgwtGuiPreview {
    [CmdletBinding()]
    param()
    $sets = Get-IgwtGuiStagedSets
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiPreview' -Parameters @{ ApplyIds = $sets.Apply; OffIds = $sets.Off; ResetIds = $sets.Reset } -BusyText 'Building dry-run preview (no changes)...' -OnComplete {
        param($out, $errs)
        $text = (@($out) -join [Environment]::NewLine)
        Set-IgwtGuiStatus 'Preview ready.'
        $accept = ''
        if ($script:Gui.IsAdmin) { $accept = 'Apply these changes' }
        if (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - preview (dry run, nothing changed)' -Text $text -AcceptText $accept) { Invoke-IgwtGuiApply -SkipConfirm }
    }
}

function Invoke-IgwtGuiApply {
    [CmdletBinding()]
    param([switch]$SkipConfirm)
    if (-not $script:Gui.IsAdmin) {
        $a = Show-IgwtGuiMessage -Text 'Applying changes requires administrator rights. Restart iG Windows Tuner as administrator now? Your staged changes will need to be staged again.' -Buttons 'YesNo' -Icon 'Question'
        if ($a -eq 'Yes') { Invoke-IgwtGuiElevate }
        return
    }
    $sets = Get-IgwtGuiStagedSets
    $total = $sets.Apply.Count + $sets.Off.Count + $sets.Reset.Count
    if ($total -eq 0) { return }
    $expert = @($sets.Apply | Where-Object { $id = $_; ($script:Gui.Catalog | Where-Object { $_.id -eq $id }).expert })
    if (-not $SkipConfirm) {
        $msg = "Apply $total staged change(s)?`n`niG Windows Tuner first creates a System Restore point and a JSON snapshot of every value it changes, so you can revert."
        $risky = @($sets.Apply | Where-Object { $id = $_; [string]($script:Gui.Catalog | Where-Object { $_.id -eq $id }).evidence.tier -eq 'R' })
        if ($risky.Count) { $msg += "`n`nIncludes RISK ZONE (rejected) tweak(s), applied at your own risk: $($risky -join ', ')." }
        if ($expert.Count) { $msg += "`n`nIncludes EXPERT toggle(s): $($expert -join ', ')." }
        if ((Show-IgwtGuiMessage -Text $msg -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    }
    $skipRp = $false
    $enableSp = $false
    if (-not (Test-IgwtSystemProtectionEnabled)) {
        $a = Show-IgwtGuiMessage -Text "System Protection is off for $env:SystemDrive, so no restore point can be created.`n`nYes: turn System Protection on for $env:SystemDrive and create a restore point.`nNo: continue with the JSON snapshot only.`nCancel: do not apply." -Buttons 'YesNoCancel' -Icon 'Question'
        if ($a -eq 'Cancel') { return }
        if ($a -eq 'Yes') { $enableSp = $true } else { $skipRp = $true }
    }
    $operation = 'Apply'
    if ($script:Gui.PresetOperation -and $sets.Off.Count -eq 0 -and $sets.Reset.Count -eq 0) { $operation = $script:Gui.PresetOperation }
    $params = @{ ApplyIds = $sets.Apply; OffIds = $sets.Off; ResetIds = $sets.Reset; Operation = $operation
        SkipRestorePoint = $skipRp; EnableSystemProtection = $enableSp; AcknowledgeRisk = ($expert.Count -gt 0) }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtGuiBatch' -Parameters $params -Blocking -BusyText 'Creating restore point and snapshot, then applying...' -OnComplete {
        param($out, $errs)
        $r = @($out) | Select-Object -Last 1
        $script:Gui.Staged.Clear()
        $script:Gui.PresetOperation = $null
        if ($r) {
            $ok = @($r.Results | Where-Object { $_.Result -in 'Applied', 'Reverted' }).Count
            $failed = @($r.Results | Where-Object { $_.Result -eq 'Failed' })
            $lines = @("$ok change(s) applied or reverted, $($failed.Count) failed.")
            foreach ($f in $failed) { $lines += "FAILED $($f.Id): $($f.Message)" }
            foreach ($u in @($r.Results | Where-Object { $_.Result -in 'Applied' -and $_.PSObject.Properties['Verified'] -and -not $_.Verified })) { $lines += "Not verified $($u.Id): $($u.Message)" }
            if ($r.RestorePoint) { $lines += "Restore point: $(if ($r.RestorePoint.Created) { 'created' } else { "not created ($($r.RestorePoint.Reason))" })" }
            foreach ($s in @($r.Snapshots)) { $lines += "Snapshot: $s" }
            if ($r.Requires -eq 'reboot') { $lines += ''; $lines += 'Restart Windows to finish applying some changes.' }
            elseif ($r.Requires -eq 'logoff') { $lines += ''; $lines += 'Sign out and back in to finish applying some changes.' }
            $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - result' -Text ($lines -join [Environment]::NewLine)
        }
        Start-IgwtGuiRefresh
    }
}

function Invoke-IgwtGuiRevert {
    [CmdletBinding()]
    param([string]$SnapshotPath, [switch]$Last)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Reverting requires administrator rights. Use "Restart as administrator".'; return }
    $what = $(if ($Last) { 'every value changed by the most recent apply' } else { "the values in $(Split-Path $SnapshotPath -Leaf)" })
    if ((Show-IgwtGuiMessage -Text "Restore ${what}? A new snapshot of the current state is written first, so this can be undone too." -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $p = @{}
    if ($Last) { $p.Last = $true } else { $p.SnapshotPath = $SnapshotPath }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtRevert' -Parameters $p -Blocking -BusyText 'Reverting from snapshot...' -OnComplete {
        param($out, $errs)
        $r = @($out) | Select-Object -Last 1
        if ($r) {
            $lines = @($r.Results | ForEach-Object { "$($_.Result)  $($_.Id)  $($_.Message)" })
            if ($lines.Count -eq 0) { $lines = @('Nothing to revert.') }
            if ($r.Requires -eq 'reboot') { $lines += ''; $lines += 'Restart Windows to finish the revert.' }
            $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - revert result' -Text ($lines -join [Environment]::NewLine)
        } elseif (@($errs).Count) {
            $null = Show-IgwtGuiMessage -Text "Revert failed: $(@($errs)[0])" -Icon 'Error'
        }
        Start-IgwtGuiRefresh
    }
}

function Invoke-IgwtGuiElevate {
    [CmdletBinding()]
    param()
    $proc = Start-IgwtElevated -ScriptPath $script:Gui.ScriptPath
    if ($proc) { $script:Gui.AllowClose = $true; $script:Gui.Window.Close() }
    else { Set-IgwtGuiStatus 'Elevation was cancelled.' }
}

#region Cleaner and disk analyzer

function Get-IgwtGuiCleanerSelection {
    <# .SYNOPSIS Rule ids that are ticked and can be cleaned in the current scan. #>
    [CmdletBinding()]
    param()
    $scan = $script:Gui.CleanScan
    if (-not $scan) { return @() }
    return @($scan.Rules | Where-Object { $script:Gui.CleanSelected[[string]$_.RuleId] -and $_.Status -in 'Ready', 'RequiresClose' } | ForEach-Object { [string]$_.RuleId })
}

function Update-IgwtGuiCleanerSummary {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $scan = $script:Gui.CleanScan
    if (-not $scan) { Update-IgwtGuiButtons; return }
    $ids = @(Get-IgwtGuiCleanerSelection)
    $sel = @($scan.Rules | Where-Object { $ids -contains [string]$_.RuleId })
    $script:Gui.C.CleanSummaryText.Text = ("Found {0} in {1} item(s). Selected: {2} in {3} rule(s)." -f (Format-IgwtBytes $scan.TotalBytes), $scan.TotalCount,
        (Format-IgwtBytes (($sel | Measure-Object Bytes -Sum).Sum)), $sel.Count)
    Update-IgwtGuiButtons
}

function Update-IgwtGuiCleanerList {
    <# .SYNOPSIS Rebuilds the cleaner rows from the last scan. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $scan = $script:Gui.CleanScan
    if (-not $scan) {
        $c.CleanerList.ItemsSource = @()
        Update-IgwtGuiButtons
        return
    }
    $rules = @{}
    foreach ($r in $script:Gui.CleanRules) { $rules[[string]$r.id] = $r }
    $c.CleanerList.ItemsSource = @($scan.Rules | ForEach-Object { New-IgwtGuiCleanerRow -RuleScan $_ -Rule $rules[[string]$_.RuleId] -Selected ([bool]$script:Gui.CleanSelected[[string]$_.RuleId]) })
    Update-IgwtGuiCleanerSummary
}

function Set-IgwtGuiCleanerScan {
    <# .SYNOPSIS Stores a scan result and pre-selects the default rules that are ready. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Scan)
    if (-not $PSCmdlet.ShouldProcess('cleaner scan', 'Show')) { return }
    $script:Gui.CleanScan = $Scan
    $script:Gui.CleanSelected = @{}
    if ($Scan) { foreach ($r in $Scan.Rules) { if ($r.Status -eq 'Ready' -and $r.Default) { $script:Gui.CleanSelected[[string]$r.RuleId] = $true } } }
    Update-IgwtGuiCleanerList
}

function Start-IgwtGuiCleanerScan {
    <# .SYNOPSIS Runs a read-only cleaner scan in the worker. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only scan.')]
    [CmdletBinding()]
    param()
    $level = 'Standard'
    if ($script:Gui.C.CleanLevelBox.SelectedItem) { $level = [string]$script:Gui.C.CleanLevelBox.SelectedItem.Content }
    $cts = New-Object System.Threading.CancellationTokenSource
    $script:Gui.Cts = $cts
    $params = @{ Level = $level; IncludeOptIn = [bool]$script:Gui.C.CleanOptInBox.IsChecked; CancelToken = $cts.Token }
    $started = Start-IgwtGuiJob -Command 'Invoke-IgwtCleanerScan' -Parameters $params -BusyText 'Scanning (read-only, nothing is deleted)...' -OnComplete {
        param($out, $errs)
        $script:Gui.Cts = $null
        $scan = @($out) | Select-Object -Last 1
        if ($scan) {
            Set-IgwtGuiCleanerScan -Scan $scan
            Set-IgwtGuiStatus ("Scan finished: {0} found. Nothing was deleted." -f (Format-IgwtBytes $scan.TotalBytes))
        } else { Set-IgwtGuiStatus 'The scan failed; see the log.' }
        Update-IgwtGuiButtons
    }
    if (-not $started) { $script:Gui.Cts = $null; $cts.Dispose() }
}

function Invoke-IgwtGuiCleanerClean {
    <# .SYNOPSIS Confirms, then deletes only what the last scan found for the ticked rules. #>
    [CmdletBinding()]
    param()
    $scan = $script:Gui.CleanScan
    $ids = @(Get-IgwtGuiCleanerSelection)
    if (-not $scan -or $ids.Count -eq 0) { return }
    $sel = @($scan.Rules | Where-Object { $ids -contains [string]$_.RuleId })
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(("Clean {0} rule(s), {1} in {2} item(s)?" -f $sel.Count, (Format-IgwtBytes (($sel | Measure-Object Bytes -Sum).Sum)), (($sel | Measure-Object Count -Sum).Sum)))
    $lines.Add('')
    foreach ($r in $sel) {
        $line = "- $($r.Name): $(Format-IgwtBytes $r.Bytes)"
        if ($r.SideEffects) { $line += " ($($r.SideEffects))" }
        $lines.Add($line)
    }
    $lines.Add('')
    $lines.Add('Deleted files cannot be restored (the Downloads rule moves files to the Recycle Bin). Files in use, changed since the scan or in protected locations are skipped, and every deleted path is logged.')
    if ((Show-IgwtGuiMessage -Text ($lines -join "`n") -Title 'iG Windows Tuner - clean' -Buttons 'YesNo' -Icon 'Warning') -ne 'Yes') { return }
    $cts = New-Object System.Threading.CancellationTokenSource
    $script:Gui.Cts = $cts
    $started = Start-IgwtGuiJob -Command 'Invoke-IgwtCleanerClean' -Parameters @{ Scan = $scan; RuleId = $ids; CancelToken = $cts.Token } -Blocking -BusyText 'Cleaning (only files found by the scan)...' -OnComplete {
        param($out, $errs)
        $script:Gui.Cts = $null
        $r = @($out) | Select-Object -Last 1
        if ($r) {
            $text = New-Object System.Collections.Generic.List[string]
            $text.Add(("Freed {0}." -f (Format-IgwtBytes $r.FreedBytes)))
            $text.Add('')
            foreach ($x in $r.Rules) {
                $skipped = [int](($x.Skipped.Values | Measure-Object -Sum).Sum)
                $text.Add(("{0,-10} {1,10}  {2,6} file(s)  {3,5} skipped  {4}  {5}" -f "[$($x.Status)]", (Format-IgwtBytes $x.DeletedBytes), $x.DeletedCount, $skipped, $x.Name, $x.Reason))
                foreach ($k in @($x.Skipped.Keys | Select-Object -First 4)) { $text.Add(("           skipped {0}: {1}" -f $x.Skipped[$k], $k)) }
            }
            $text.Add('')
            $text.Add("Every deleted path is listed in $($r.LogFile)")
            $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - clean result' -Text ($text -join [Environment]::NewLine)
            Set-IgwtGuiCleanerScan -Scan $null
            $script:Gui.C.CleanSummaryText.Text = ("Freed {0}. Scan again to see what is left." -f (Format-IgwtBytes $r.FreedBytes))
            Set-IgwtGuiStatus ("Clean finished: {0} freed." -f (Format-IgwtBytes $r.FreedBytes))
        } else { Set-IgwtGuiStatus 'The clean failed; see the log.' }
        Update-IgwtGuiButtons
    }
    if (-not $started) { $script:Gui.Cts = $null; $cts.Dispose() }
}

function Update-IgwtGuiDiskLists {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Usage)
    $c = $script:Gui.C
    if (-not $Usage) { $c.DiskFolderList.ItemsSource = @(); $c.DiskFileList.ItemsSource = @(); return }
    $maxFolder = [long](($Usage.Folders | Measure-Object Bytes -Maximum).Maximum)
    $maxFile = [long](($Usage.LargestFiles | Measure-Object Bytes -Maximum).Maximum)
    $c.DiskFolderList.ItemsSource = @($Usage.Folders | ForEach-Object { New-IgwtGuiDiskRow -Path $_.Path -Bytes $_.Bytes -Largest $maxFolder -Extra ("{0:N0} file(s)" -f $_.Files) -IsFolder })
    $c.DiskFileList.ItemsSource = @($Usage.LargestFiles | ForEach-Object { New-IgwtGuiDiskRow -Path $_.Path -Bytes $_.Bytes -Largest $maxFile -Extra ([datetime]$_.LastWrite).ToString('yyyy-MM-dd') })
    $c.DiskSummaryText.Text = ("{0}: {1} in {2:N0} file(s){3}. {4} folder(s) not readable, {5} reparse point(s) not followed. Read-only." -f $Usage.Root, (Format-IgwtBytes $Usage.TotalBytes), $Usage.Files,
        $(if ($Usage.Cancelled) { ' (cancelled, partial result)' } else { '' }), $Usage.AccessDenied, $Usage.ReparseSkipped)
}

function Start-IgwtGuiDiskAnalyze {
    <# .SYNOPSIS Runs the read-only disk analyzer in the worker. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only analysis.')]
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) { $Path = ([string]$script:Gui.C.DiskPathBox.Text).Trim() }
    if (-not $Path) { $Path = "$env:SystemDrive\" }
    if ($Path -match '^[A-Za-z]:$') { $Path += '\' }
    if ($Path -notmatch '^[A-Za-z]:\\' -or -not (Test-Path -LiteralPath $Path -PathType Container)) { Set-IgwtGuiStatus "Folder not found: $Path (use a full path such as C:\ or D:\Games)."; return }
    $script:Gui.C.DiskPathBox.Text = $Path
    $cts = New-Object System.Threading.CancellationTokenSource
    $script:Gui.Cts = $cts
    $started = Start-IgwtGuiJob -Command 'Get-IgwtDiskUsage' -Parameters @{ Path = $Path; Top = 50; FolderDepth = 3; CancelToken = $cts.Token } -BusyText "Analyzing $Path (read-only)..." -OnComplete {
        param($out, $errs)
        $script:Gui.Cts = $null
        $u = @($out) | Select-Object -Last 1
        if ($u) { Update-IgwtGuiDiskLists -Usage $u; Set-IgwtGuiStatus "Analysis of $($u.Root) finished." }
        else { Set-IgwtGuiStatus 'The analysis failed; see the log.' }
        Update-IgwtGuiButtons
    }
    if (-not $started) { $script:Gui.Cts = $null; $cts.Dispose() }
}

function Show-IgwtGuiInExplorer {
    <# .SYNOPSIS Opens a folder in File Explorer, or selects a file in its folder (files are never opened). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Set-IgwtGuiStatus "No longer exists: $Path"; return }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Show in File Explorer')) { return }
    if (Test-Path -LiteralPath $Path -PathType Container) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $Path) }
    else { Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"{0}"' -f $Path) }
}

#endregion

#region Expert inspectors

function Update-IgwtGuiPowerList {
    <# .SYNOPSIS Rebuilds the power plan rows (editable and changed settings, or all), keeping the selection. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $p = $null
    if ($script:Gui.Inspection) { $p = $script:Gui.Inspection.Power }
    if (-not $p -or ($p.PSObject.Properties['Error'] -and $p.Error)) {
        $c.InspectPowerList.ItemsSource = @()
        $c.InspectPowerSummary.Text = $(if ($p) { "Power plan not readable: $($p.Error)" } else { 'Not read yet.' })
        return
    }
    $selected = $null
    if ($c.InspectPowerList.SelectedItem) { $selected = $c.InspectPowerList.SelectedItem.Setting.Guid }
    $all = [bool]$c.InspectPowerAllBox.IsChecked
    $rows = @($p.Settings | Where-Object { $all -or $_.Level -or $_.ChangedFromDefault } | Sort-Object @{ Expression = { if ($_.Level) { 0 } else { 1 } } }, Group, Alias | ForEach-Object { New-IgwtGuiPowerRow -Setting $_ })
    $c.InspectPowerList.ItemsSource = $rows
    if ($selected) { $again = $rows | Where-Object { $_.Setting.Guid -eq $selected } | Select-Object -First 1; if ($again) { $c.InspectPowerList.SelectedItem = $again } }
    $c.InspectPowerSummary.Text = ("Plan: {0}. {1} settings, {2} editable here, {3} differ from the defaults ({4}).{5}" -f $p.SchemeName, @($p.Settings).Count, $p.Editable, $p.Changed, $p.DefaultsFrom,
        $(if (-not $script:Gui.IsAdmin) { ' Read-only: restart as administrator to edit.' } else { '' }))
}

function Update-IgwtGuiPowerDetail {
    <# .SYNOPSIS Fills the editor card for the selected power setting. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = $c.InspectPowerList.SelectedItem
    if (-not $row) { $c.InspectPowerDetailName.Text = 'Select a setting'; $c.InspectPowerDetailText.Text = ''; $c.InspectPowerAcBox.Text = ''; $c.InspectPowerDcBox.Text = ''; Update-IgwtGuiButtons; return }
    $s = $row.Setting
    $c.InspectPowerDetailName.Text = "$($row.Alias) - $($s.Name)"
    $lines = New-Object System.Collections.Generic.List[string]
    if ($s.Description) { $lines.Add([string]$s.Description) } else { $lines.Add('Shown for information; iG Windows Tuner does not edit this setting.') }
    if (@($s.Options).Count) { $lines.Add('Values: ' + (@($s.Options | ForEach-Object { "$($_.Index) = $($_.Name)" }) -join ', ')) } elseif ($null -ne $s.Min) { $lines.Add("Range $($s.Min)-$($s.Max) $($s.Units)") }
    if ($null -ne $s.DefaultAC) { $lines.Add("Default ($($s.DefaultSource)): AC $($s.DefaultAC), DC $($s.DefaultDC)") }
    if ($s.BlockReason) { $lines.Add([string]$s.BlockReason) } elseif ($s.DcBlockReason) { $lines.Add("Battery value: $($s.DcBlockReason)") }
    $c.InspectPowerDetailText.Text = ($lines -join [Environment]::NewLine)
    $c.InspectPowerAcBox.Text = [string]$s.AC
    $c.InspectPowerDcBox.Text = [string]$s.DC
    Update-IgwtGuiButtons
}

function Update-IgwtGuiKernelList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $k = $null
    if ($script:Gui.Inspection) { $k = $script:Gui.Inspection.Kernel }
    if (-not $k -or ($k.PSObject.Properties['Error'] -and $k.Error)) { $c.InspectKernelList.ItemsSource = @(); $c.InspectKernelSummary.Text = $(if ($k) { "Not readable: $($k.Error)" } else { 'Not read yet.' }); return }
    $onlyChanged = [bool]$c.InspectKernelChangedBox.IsChecked
    $c.InspectKernelList.ItemsSource = @(foreach ($key in @($k.Keys)) { foreach ($v in @($key.Values)) { if (-not $onlyChanged -or $v.Status -ne 'Default') { New-IgwtGuiKernelRow -Value $v -Key ([string]$key.Name) } } })
    $c.InspectKernelSummary.Text = "$($k.Changed) documented value(s) differ from the Windows default. Undocumented values are listed so you can see what other tools changed."
}

function Set-IgwtGuiInspection {
    <# .SYNOPSIS Shows a Get-IgwtInspection result on every inspector tab. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Inspection)
    $c = $script:Gui.C
    $script:Gui.Inspection = $Inspection
    Update-IgwtGuiPowerList
    Update-IgwtGuiPowerDetail
    Update-IgwtGuiKernelList
    if (-not $Inspection) { return }
    $irq = $Inspection.Interrupts
    if ($irq -and -not ($irq.PSObject.Properties['Error'] -and $irq.Error)) {
        $c.InspectIrqList.ItemsSource = @($irq.Devices | ForEach-Object { New-IgwtGuiIrqRow -Device $_ })
        $c.InspectIrqSummary.Text = "$($irq.MessageSignaled) device(s) use message-signaled interrupts, $($irq.LineBased) line-based. $($irq.Note)"
    } elseif ($irq) { $c.InspectIrqSummary.Text = "Not readable: $($irq.Error)" }
    $nic = $Inspection.Network
    if ($nic -and -not ($nic.PSObject.Properties['Error'] -and $nic.Error)) { $c.InspectNicList.ItemsSource = @($nic.Adapters | ForEach-Object { New-IgwtGuiNicRow -Adapter $_ }) }
    $c.InspectCrashText.Text = Format-IgwtInspection -Inspection ([pscustomobject]@{ Elevated = $true; Timer = $Inspection.Timer; Crash = $Inspection.Crash })
}

function Start-IgwtGuiInspect {
    <# .SYNOPSIS Runs every inspector in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtInspection' -BusyText 'Reading power plan, interrupts, network queues and kernel settings (read-only)...' -OnComplete {
        param($out, $errs)
        Set-IgwtGuiInspection -Inspection (@($out) | Select-Object -Last 1)
        Set-IgwtGuiStatus 'Inspectors updated.'
    }
}

function Invoke-IgwtGuiPowerChange {
    <# .SYNOPSIS Validates a power setting change, asks for confirmation, then applies it in the worker (snapshot first). #>
    [CmdletBinding()]
    param([switch]$Default)
    $c = $script:Gui.C
    $row = $c.InspectPowerList.SelectedItem
    if (-not $row -or -not $row.Setting.Editable) { return }
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to change power settings.'; return }
    $params = @{ Setting = [string]$row.Setting.Guid; AcknowledgeRisk = $true }
    if ($Default) { $params.Default = $true }
    else {
        $n = 0L
        $acText = ([string]$c.InspectPowerAcBox.Text).Trim(); $dcText = ([string]$c.InspectPowerDcBox.Text).Trim()
        if ($acText) { if (-not [long]::TryParse($acText, [ref]$n)) { Set-IgwtGuiStatus 'The AC value must be a whole number.'; return }; $params.AC = $n }
        if ($dcText) { if (-not [long]::TryParse($dcText, [ref]$n)) { Set-IgwtGuiStatus 'The DC value must be a whole number.'; return }; $params.DC = $n }
    }
    $planParams = @{ Setting = $params.Setting }
    foreach ($k in 'AC', 'DC', 'Default') { if ($params.ContainsKey($k)) { $planParams[$k] = $params[$k] } }
    try { $plan = Get-IgwtPowerSettingChangePlan @planParams } catch { $null = Show-IgwtGuiMessage -Text "This change is refused:`n`n$($_.Exception.Message)" -Icon 'Warning'; return }
    if (-not $plan.HasChange) { Set-IgwtGuiStatus 'Already set; nothing to change.'; return }
    $text = "Change $($row.Alias) in the active plan?`n`n$($plan.Change)`n`n$($row.Setting.Description)`n`nExpert setting. A snapshot is written first, so you can revert it in Backups & Logs."
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - power plan' -Buttons 'YesNo' -Icon 'Warning') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtPowerSettingChange' -Parameters $params -Blocking -BusyText "Changing $($row.Alias) (snapshot first)..." -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The change was not made: $(@($errs)[0])" -Icon 'Error' }
        elseif ($res -and $res.Changes) { Set-IgwtGuiStatus ("{0}: {1}. Snapshot: {2}" -f @($res.Results)[0].Target, @($res.Results)[0].Result, $res.Snapshot) }
        Start-IgwtGuiInspect
    }
}

#endregion

#region Manage

function Test-IgwtGuiSearchMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Row, [string]$Text)
    if (-not $Text) { return $true }
    return ("$($Row.Title) $($Row.Subtitle) $($Row.Tip)".IndexOf($Text, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Update-IgwtGuiManageLists {
    <# .SYNOPSIS Fills the Manage lists from the cached data, filtered by the search box. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $m = $script:Gui.Manage
    if (-not $m) { return }
    $q = ([string]$c.ManageSearchBox.Text).Trim()
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] }
    $err = { param($o) if (& $has $o 'Error') { "Not readable: $($o.Error)" } else { 'Not readable.' } }
    $tone = @{ Protected = 'Muted'; Catalogued = 'Info'; Windows = 'Text'; ThirdParty = 'Warn' }
    if (& $has $m.Services 'Services') {
        $rows = @($m.Services.Services | ForEach-Object { New-IgwtGuiManageRow -Title $_.DisplayName -Subtitle "$($_.Name) - $($_.Description)" -Badge "$($_.State), $($_.StartupType)" -State $_.Rating -Tone $tone[[string]$_.Rating] -Tip "$($_.Advice)`n$($_.Path)" -Source $_ } | Where-Object { Test-IgwtGuiSearchMatch -Row $_ -Text $q })
        $c.ManageServiceList.ItemsSource = $rows
        $k = $m.Services.Counts
        $c.ManageServiceSummary.Text = "$($k.Total) services, $($k.Running) running, $($k.Protected) protected, $($k.ThirdParty) installed by apps. Catalogued services are managed by catalog items with documented reasons; prefer those."
    } else { $c.ManageServiceSummary.Text = & $err $m.Services }
    if (& $has $m.Tasks 'Tasks') {
        $c.ManageTaskList.ItemsSource = @($m.Tasks.Tasks | ForEach-Object {
                New-IgwtGuiManageRow -Title $_.Name -Subtitle $_.TaskPath -Badge $(if ($_.IsMicrosoft) { 'Microsoft' } else { 'third-party' }) -State $(if ($_.Protected) { 'Protected' } else { $_.State }) `
                    -Tone $(if ($_.Protected) { 'Muted' } elseif ($_.State -eq 'Disabled') { 'Muted' } elseif (-not $_.IsMicrosoft) { 'Warn' } else { 'Text' }) -Tip "$($_.Description)`n$($_.Action)" -Source $_
            } | Where-Object { Test-IgwtGuiSearchMatch -Row $_ -Text $q })
        $c.ManageTaskSummary.Text = "$($m.Tasks.Counts.Total) tasks, $($m.Tasks.Counts.Disabled) disabled, $($m.Tasks.Counts.ThirdParty) third-party. $($m.Tasks.Note)"
    } else { $c.ManageTaskSummary.Text = & $err $m.Tasks }
    if (& $has $m.Apps 'Appx') {
        $appx = @($m.Apps.Appx | ForEach-Object { New-IgwtGuiManageRow -Title $_.Name -Subtitle "Inbox / Store app $($_.Version)" -Badge 'Appx' -State $(if ($_.Protected) { 'Protected' } else { 'Removable' }) -Tone $(if ($_.Protected) { 'Muted' } else { 'Text' }) -Tip $_.Note -Source $_ })
        $win32 = @($m.Apps.Win32 | ForEach-Object { New-IgwtGuiManageRow -Title $_.Name -Subtitle "$($_.Publisher) $($_.Version)" -Badge 'Win32' -State $(if ($_.SizeMB) { "$($_.SizeMB) MB" } else { $_.Scope }) -Tone 'Muted' -Tip 'Uninstall Win32 apps with their own uninstaller (Settings > Apps > Installed apps).' -Source $_ })
        $c.ManageAppList.ItemsSource = @(@($appx) + @($win32) | Where-Object { Test-IgwtGuiSearchMatch -Row $_ -Text $q })
        $c.ManageAppSummary.Text = "$(@($m.Apps.Appx).Count) inbox/Store apps ($(@($m.Apps.Appx | Where-Object { $_.CanRemove }).Count) removable) and $(@($m.Apps.Win32).Count) Win32 apps. $($m.Apps.Note)"
    } else { $c.ManageAppSummary.Text = & $err $m.Apps }
    if (& $has $m.Persistence 'Entries') {
        $c.ManagePersistList.ItemsSource = @($m.Persistence.Entries | ForEach-Object {
                $sig = $(if ($_.Signature) { "$($_.Signature) $($_.Signer)".Trim() } else { '' })
                New-IgwtGuiManageRow -Title $_.Name -Subtitle $_.Command -Badge "$($_.Category)$(if ($_.Enabled -eq $false) { ', disabled' })" -State $_.Severity -Tone $(switch ($_.Severity) { 'Warn' { 'Fail' } 'Review' { 'Warn' } default { 'Pass' } }) -Tip "$($_.Location)`n$sig`n$($_.Note)" -Source $_
            } | Where-Object { Test-IgwtGuiSearchMatch -Row $_ -Text $q })
        $k = $m.Persistence.Counts
        $c.ManagePersistSummary.Text = "$($k.Total) entries (Microsoft-signed services, drivers and tasks hidden), $($k.Warn) warning(s), $($k.Review) to review. $($m.Persistence.Note)"
    } else { $c.ManagePersistSummary.Text = & $err $m.Persistence }
    if (& $has $m.Firewall 'Rules') {
        $c.ManageFirewallList.ItemsSource = @($m.Firewall.Rules | ForEach-Object {
                New-IgwtGuiManageRow -Title $_.DisplayName -Subtitle $(if ($_.Program) { $_.Program } else { $_.Group }) -Badge "$($_.Direction), $($_.Action)$(if ($_.IsWindowsRule) { ', Windows' })" -State $(if ($_.Enabled) { 'Enabled' } else { 'Disabled' }) `
                    -Tone $(if ($_.IsWindowsRule) { 'Muted' } elseif ($_.Enabled) { 'Pass' } else { 'Muted' }) -Tip "$($_.Name)`nProfile: $($_.Profile)" -Source $_
            } | Where-Object { Test-IgwtGuiSearchMatch -Row $_ -Text $q })
        $c.ManageFirewallSummary.Text = "$(@($m.Firewall.Rules).Count) rules, $($m.Firewall.AppRules) created by apps. $($m.Firewall.Note)"
    } else { $c.ManageFirewallSummary.Text = & $err $m.Firewall }
    if (& $has $m.Hosts 'Entries') {
        $h = $m.Hosts
        $lines = @($h.Entries | Where-Object { $_.Flag -ne 'Expected' } | Select-Object -First 8 | ForEach-Object { "[$($_.Flag)] $($_.Address) $($_.HostName)" })
        $c.ManageHostsText.Text = "Hosts file ($($h.Path)): $(@($h.Entries).Count) entr(ies), $($h.Unexpected) flagged. $($h.Note)$(if ($lines.Count) { [Environment]::NewLine + ($lines -join [Environment]::NewLine) })"
    }
    Update-IgwtGuiButtons
}

function Update-IgwtGuiManageDetail {
    <# .SYNOPSIS Detail texts under the Manage lists for the selected rows. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $nl = [Environment]::NewLine
    $s = $c.ManageServiceList.SelectedItem
    if ($s) {
        $x = $s.Source
        $items = @($x.CatalogItems | ForEach-Object { "$($_.Id)$(if (@($_.Presets).Count) { " (in $(@($_.Presets) -join ', '))" })" })
        $c.ManageServiceDetail.Text = "$($x.DisplayName) ($($x.Name)): $($x.State), $($x.StartupType), runs as $($x.Account).$nl$($x.Description)$nl$($x.Advice)" +
        $(if (@($x.DependsOn).Count) { "${nl}Depends on: $(@($x.DependsOn) -join ', ')" }) + $(if (@($x.Dependents).Count) { "${nl}Needed by: $(@($x.Dependents) -join ', ')" }) +
        $(if ($items.Count) { "${nl}Catalog items: $($items -join '; ')" })
        $c.ManageServiceStartBox.SelectedItem = $(if ($x.StartupType -in 'Automatic', 'AutomaticDelayed', 'Manual', 'Disabled') { $x.StartupType } else { $null })
    } else { $c.ManageServiceDetail.Text = 'Select a service.' }
    $t = $c.ManageTaskList.SelectedItem
    $c.ManageTaskDetail.Text = $(if ($t) { "$($t.Source.Path) ($($t.Source.State), author $($t.Source.Author))$nl$($t.Source.Description)${nl}Runs: $($t.Source.Action)$(if ($t.Source.Protected) { "${nl}Protected: security, update, recovery or anti-cheat task." })" } else { 'Select a task.' })
    $a = $c.ManageAppList.SelectedItem
    $c.ManageAppDetail.Text = $(if ($a) { "$($a.Title) $($a.Subtitle)$nl$($a.Tip)" } else { 'Select an app.' })
    $p = $c.ManagePersistList.SelectedItem
    if ($p) {
        $x = $p.Source
        $how = switch ([string]$x.ActionKind) { 'StartupEntry' { 'Disable turns the startup entry off (StartupApproved), like Task Manager.' } 'Service' { 'Disable sets the service startup type to Disabled.' } 'Task' { 'Disable disables the scheduled task.' } default { 'No documented disable mechanism here; investigate with Microsoft Defender or Autoruns.' } }
        $c.ManagePersistDetail.Text = "[$($x.Severity)] $($x.Category): $($x.Name)${nl}Location: $($x.Location)${nl}Command: $($x.Command)${nl}File: $($x.File)  Signature: $($x.Signature) $($x.Signer)$(if ($x.Note) { "$nl$($x.Note)" })$nl$how"
    } else { $c.ManagePersistDetail.Text = 'Select an entry.' }
    $f = $c.ManageFirewallList.SelectedItem
    $c.ManageFirewallDetail.Text = $(if ($f) { "$($f.Source.DisplayName) ($($f.Source.Name)): $($f.Source.Direction) $($f.Source.Action), $(if ($f.Source.Enabled) { 'enabled' } else { 'disabled' }), profile $($f.Source.Profile).${nl}Program: $($f.Source.Program)$(if ($f.Source.IsWindowsRule) { "${nl}Windows rule: shown for reference, never changed." })" } else { 'Select a rule.' })
    Update-IgwtGuiButtons
}

function Start-IgwtGuiManageRefresh {
    <# .SYNOPSIS Reads the Manage data in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiManageData' -BusyText 'Reading services, tasks, apps, persistence entries and firewall rules (read-only)...' -OnComplete {
        param($out, $errs)
        $script:Gui.Manage = @($out) | Select-Object -Last 1
        Update-IgwtGuiManageLists
        Update-IgwtGuiManageDetail
        Set-IgwtGuiStatus 'Manage data updated.'
    }
}

function Invoke-IgwtGuiManagedChange {
    <# .SYNOPSIS Validates a management change (protection rules), asks for confirmation, then applies it in the worker (snapshot first). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][string]$Value, [switch]$Provisioned)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to make changes.'; return }
    try { $plan = Get-IgwtManagedChangePlan -Kind $Kind -Target $Target -Value $Value -Provisioned:$Provisioned }
    catch { $null = Show-IgwtGuiMessage -Text "This change is refused:`n`n$($_.Exception.Message)" -Icon 'Warning'; return }
    if (-not $plan.HasChange) { Set-IgwtGuiStatus 'Already set; nothing to change.'; return }
    $text = "$($plan.Change)`n`nReversible: $($plan.Reversible). A snapshot is written first; revert it in Backups & Logs.`n`nContinue?"
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - manage' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $params = @{ Kind = $Kind; Target = $Target; Value = $Value }
    if ($Provisioned) { $params.Provisioned = $true }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtManagedChange' -Parameters $params -Blocking -BusyText "$Kind $Target -> $Value (snapshot first)..." -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The change was not made: $(@($errs)[0])" -Icon 'Error' }
        elseif ($res -and $res.Changes) {
            $r = @($res.Results)[0]
            $null = Show-IgwtGuiMessage -Text ("[{0}] {1}{2}`n`nSnapshot: {3}" -f $r.Result, $r.Change, $(if ($r.Message) { "`n$($r.Message)" }), $res.Snapshot) -Icon $(if ($r.Result -eq 'Failed') { 'Warning' } else { 'Information' })
        }
        $script:Gui.Manage = $null
        Start-IgwtGuiManageRefresh
    }
}

function Invoke-IgwtGuiPersistenceDisable {
    <# .SYNOPSIS Disables the selected persistence entry through its documented mechanism. #>
    [CmdletBinding()]
    param()
    $row = $script:Gui.C.ManagePersistList.SelectedItem
    if (-not $row) { return }
    $x = $row.Source
    switch ([string]$x.ActionKind) {
        'Service' { Invoke-IgwtGuiManagedChange -Kind service -Target ([string]$x.ActionTarget) -Value 'Disabled' }
        'Task' { Invoke-IgwtGuiManagedChange -Kind task -Target ([string]$x.ActionTarget) -Value 'Disabled' }
        'StartupEntry' {
            $parts = ([string]$x.ActionTarget) -split '\|', 2
            if ($parts.Count -ne 2) { return }
            if ((Show-IgwtGuiMessage -Text "Turn off the startup entry '$($parts[1])'?`n`nIt is disabled like in Task Manager (StartupApproved), not deleted. A snapshot is written first." -Title 'iG Windows Tuner - startup entry' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
            $null = Start-IgwtGuiJob -Command 'Set-IgwtStartupItemEnabled' -Parameters @{ Scope = $parts[0]; Name = $parts[1]; Enabled = $false } -Blocking -BusyText "Disabling startup entry $($parts[1])..." -OnComplete {
                param($out, $errs)
                if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The change was not made: $(@($errs)[0])" -Icon 'Error' } else { Set-IgwtGuiStatus 'Startup entry disabled (snapshot written).' }
                $script:Gui.Manage = $null
                Start-IgwtGuiManageRefresh
            }
        }
    }
}

function Export-IgwtGuiPersistence {
    <# .SYNOPSIS Saves the cached persistence inventory as HTML in the Reports folder and opens it. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $inv = $script:Gui.Manage.Persistence
    if (-not $inv -or -not $inv.PSObject.Properties['Entries']) { return }
    $dir = Get-IgwtDataPath -Kind Reports
    $path = Join-Path $dir ("iGWindowsTuner-persistence-{0}.html" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    if (-not $PSCmdlet.ShouldProcess($path, 'Write persistence report')) { return }
    $out = Export-IgwtPersistenceReport -Inventory $inv -Path $path -Format Html
    Set-IgwtGuiStatus "Persistence report saved: $out"
    Open-IgwtGuiPath -Target $out
}

#endregion

#region Diagnostics

function Set-IgwtGuiDiagData {
    <# .SYNOPSIS Shows a Get-IgwtGuiDiagnosticsData result on the Diagnostics tabs. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Data)
    $c = $script:Gui.C
    $script:Gui.Diag = $Data
    if (-not $Data) { return }
    $nl = [Environment]::NewLine
    $d = $Data.Diagnostics
    if ($d -and -not ($d.PSObject.Properties['Error'] -and $d.PSObject.Properties.Name.Count -eq 1)) {
        $c.DiagOverviewText.Text = Format-IgwtDiagnostics -Diagnostics ([pscustomobject]@{ DpcIsr = $d.DpcIsr; Reliability = $d.Reliability; Crashes = $d.Crashes; Boot = $d.Boot })
        $dr = $d.Drivers
        if ($dr -and $dr.PSObject.Properties['Drivers']) {
            $c.DiagDriverList.ItemsSource = @($dr.Drivers | ForEach-Object { New-IgwtGuiManageRow -Title $_.Device -Subtitle "$($_.Provider) $($_.Version), $($_.Date)" -Badge $_.Class -State $(if ($_.Flag) { $_.Flag } else { 'OK' }) -Tone $(switch ($_.Flag) { 'Unsigned' { 'Fail' } 'Old' { 'Warn' } default { 'Pass' } }) -Tip "Signer: $($_.Signer)${nl}INF: $($_.Inf)" -Source $_ })
            $c.DiagDriverSummary.Text = "$($dr.Counts.Total) non-Microsoft drivers, $($dr.Counts.Unsigned) unsigned, $($dr.Counts.Old) older than three years. $($dr.Note)"
        } elseif ($dr) { $c.DiagDriverSummary.Text = "Not readable: $($dr.Error)" }
    } elseif ($d) { $c.DiagOverviewText.Text = "Not readable: $($d.Error)" }
    $u = $Data.Updates
    if ($u -and $u.PSObject.Properties['Services']) {
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($s in $u.Services) { $lines.Add(('{0,-13} {1,-8} {2}' -f $s.Name, $s.Status, $s.StartType)) }
        $lines.Add("Pending restart: $(if (@($u.PendingRestart).Count) { $u.PendingRestart -join ', ' } else { 'no' })")
        $lines.Add("Policies: $(if (@($u.Policies).Count) { (@($u.Policies | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ') } else { 'none (Windows defaults)' })")
        $lines.Add("Last successful update (not counting Defender definitions): $(if ($u.LastSuccess) { $u.LastSuccess } else { 'unknown' })")
        if ($u.Error) { $lines.Add($u.Error) }
        foreach ($a in $u.Advice) { $lines.Add("-> $a") }
        $lines.Add('')
        foreach ($h in @($u.History | Select-Object -First 30)) { $lines.Add(('{0:yyyy-MM-dd} {1,-22} {2} {3}' -f $h.Date, $h.Result, $h.Title, $h.HResult)) }
        $lines.Add(''); $lines.Add($u.Note)
        $c.DiagUpdateText.Text = $lines.ToArray() -join $nl
    } elseif ($u) { $c.DiagUpdateText.Text = "Not readable: $($u.Error)" }
    $ad = $Data.Adapters
    if ($ad -and $ad.PSObject.Properties['Adapters']) {
        $c.DiagAdapterList.ItemsSource = @(foreach ($a in $ad.Adapters) { foreach ($p in @($a.Properties)) {
                    New-IgwtGuiManageRow -Title "$($p.DisplayName): $($p.Value)" -Subtitle $p.Description -Badge $a.Name -State $(if ($p.ChangedFromDefault) { 'Changed' } else { 'Default' }) -Tone $(if ($p.ChangedFromDefault) { 'Warn' } else { 'Muted' }) `
                        -Tip "$($p.Keyword) = $($p.RegistryValue) (default $($p.Default))$(if ($p.Allowed) { "${nl}Allowed: $($p.Allowed)" })$(if ($p.Range) { "${nl}Range: $($p.Range)" })${nl}$($p.Description)" -Source $p
                } })
        $c.DiagAdapterSummary.Text = "Adapter properties ($(@($ad.Adapters | ForEach-Object { "$($_.Name), $($_.LinkSpeed)" }) -join '; ')). $($ad.Note)"
    } elseif ($ad) { $c.DiagAdapterSummary.Text = "Adapter properties not readable: $($ad.Error)" }
}

function Start-IgwtGuiDiagRefresh {
    <# .SYNOPSIS Reads the Diagnostics data in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiDiagnosticsData' -BusyText 'Sampling DPC/ISR and reading reliability, crashes, boot, drivers and Windows Update (read-only)...' -OnComplete {
        param($out, $errs)
        Set-IgwtGuiDiagData -Data (@($out) | Select-Object -Last 1)
        Set-IgwtGuiStatus 'Diagnostics updated.'
    }
}

function Start-IgwtGuiNetworkTest {
    <# .SYNOPSIS Runs the user-initiated DNS benchmark or latency test in the worker. Sends network traffic, changes nothing. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only measurement.')]
    [CmdletBinding()]
    param([switch]$Dns)
    if ($Dns) {
        $null = Start-IgwtGuiJob -Command 'Invoke-IgwtDnsBenchmark' -BusyText 'Running the DNS benchmark (sends DNS queries)...' -OnComplete {
            param($out, $errs)
            $b = @($out) | Select-Object -Last 1
            if (-not $b) { $script:Gui.C.DiagNetText.Text = "DNS benchmark failed: $(@($errs)[0])"; return }
            $script:Gui.C.DiagNetText.Text = ((@($b.Results | ForEach-Object { '{0,-10} {1,-16} median {2,7} ms  worst {3,7} ms  failures {4}/{5}' -f $_.Name, $_.Server, $_.MedianMs, $_.WorstMs, $_.Failures, $_.Queries }) + @('', $b.Note)) -join [Environment]::NewLine)
            Set-IgwtGuiStatus 'DNS benchmark finished.'
        }
        return
    }
    $targets = @(([string]$script:Gui.C.DiagLatencyBox.Text) -split '[,;\s]+' | Where-Object { $_ } | Select-Object -First 5)
    if ($targets.Count -eq 0) { Set-IgwtGuiStatus 'Enter at least one host name or IP address.'; return }
    $null = Start-IgwtGuiJob -Command 'Test-IgwtNetworkLatency' -Parameters @{ Target = $targets } -BusyText "Measuring latency to $($targets -join ', ') (20 echo requests each)..." -OnComplete {
        param($out, $errs)
        $l = @($out) | Select-Object -Last 1
        if (-not $l) { $script:Gui.C.DiagNetText.Text = "Latency test failed: $(@($errs)[0])"; return }
        $script:Gui.C.DiagNetText.Text = ((@($l.Results | ForEach-Object { if ($_.Error) { '{0,-24} {1}' -f $_.Target, $_.Error } else { '{0,-24} avg {1,6} ms  min {2,5}  max {3,5}  jitter {4,5} ms  loss {5} %' -f $_.Target, $_.AvgMs, $_.MinMs, $_.MaxMs, $_.JitterMs, $_.LossPercent } }) + @('', $l.Note)) -join [Environment]::NewLine)
        Set-IgwtGuiStatus 'Latency test finished.'
    }
}

#endregion

#region Network test

function Get-IgwtGuiGradeTone {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Grade)
    switch ($Grade) { 'A+' { 'Pass' } 'A' { 'Pass' } 'B' { 'Info' } 'C' { 'Warn' } 'n/a' { 'Muted' } default { 'Fail' } }
}

function Set-IgwtGuiNetResult {
    <# .SYNOPSIS Shows a network quality test result on the Network Test page. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Result)
    $c = $script:Gui.C
    $script:Gui.NetResult = $Result
    if (-not $Result) { return }
    if ($Result.Error) { $c.NetStatusText.Text = "No result: $($Result.Error)"; Update-IgwtGuiButtons; return }
    $nl = [Environment]::NewLine
    $s = $Result.Score; $i = $Result.Internet
    $c.NetStatusText.Text = "Last test: $($Result.Duration) ($($Result.DurationSec) s) at $(([datetime]$Result.Generated).ToString('HH:mm:ss')). $(if ($s) { $s.Verdict })"
    $c.NetGradeText.Text = $(if ($s) { $s.Grade } else { '-' })
    $c.NetGradeText.Foreground = $script:IgwtColor[(Get-IgwtGuiGradeTone -Grade ([string]$s.Grade))]
    $c.NetScoreText.Text = $(if ($s) { "$($s.Score) / $($s.Mos)" } else { '-' })
    $c.NetLatencyText.Text = $(if ($i -and $null -ne $i.Stats.MedianMs) { "$($i.Stats.MedianMs) ms" } else { '-' })
    $c.NetJitterText.Text = $(if ($i -and $null -ne $i.Stats.JitterMs) { "$($i.Stats.JitterMs) ms" } else { '-' })
    $c.NetLossText.Text = $(if ($i -and $null -ne $i.Stats.LossPercent) { "$($i.Stats.LossPercent) %" } else { '-' })
    $c.NetStabilityText.Text = "$(if ($s) { $s.Stability } else { '-' }) / $(if ($Result.Bufferbloat) { $Result.Bufferbloat.Grade } else { '?' })"
    $g = $Result.TypeGuess; $conn = $Result.Connection
    $wifi = ''
    if ($conn.Wifi -and $conn.Wifi.Connected) { $wifi = " Wi-Fi: $($conn.Wifi.RadioType) $($conn.Wifi.Band), channel $($conn.Wifi.Channel), signal $($conn.Wifi.SignalPercent) %." }
    $c.NetConnectionText.Text = "$($g.Local), internet access: $($g.Access) (confidence $($g.Confidence)). Adapter $($conn.Description), gateway $($conn.Gateway), path MTU $(if ($Result.Mtu) { $Result.Mtu } else { 'n/a' }), IPv6 $(if ($conn.IPv6) { 'yes' } else { 'no' }).$wifi"
    $c.NetEvidenceText.Text = (@($g.Evidence | ForEach-Object { "- $_" }) -join $nl)
    $c.NetTargetList.ItemsSource = @($Result.Targets | ForEach-Object {
            $st = $_.Stats
            New-IgwtGuiManageRow -Title "$($_.Name)" -Subtitle "$($_.Address)  |  median $($st.MedianMs) ms, p95 $($st.P95Ms) ms, max $($st.MaxMs) ms  |  jitter $($st.JitterMs) ms  |  loss $($st.LossPercent) %  |  spikes $($st.Spikes)" `
                -Badge $_.Role -State "Grade $($_.Score.Grade)" -Tone (Get-IgwtGuiGradeTone -Grade ([string]$_.Score.Grade)) -Tip "Latency $($_.Score.Latency), jitter $($_.Score.Jitter), loss $($_.Score.Loss), stability $($_.Score.Stability). $($_.Score.Verdict)" -Source $_
        })
    $r = $Result.Recommendations
    if ($r) {
        $c.NetRecoTitle.Text = "Recommended Windows adjustments ($($r.Profile))"
        $reco = @($r.Tweaks | ForEach-Object { New-IgwtGuiManageRow -Title $_.Name -Subtitle $_.Why -Badge "$($_.Id) | $($_.Level), Tier $($_.Tier)" -State 'Recommended' -Tone 'Info' -Source $_ })
        $reco += @($r.Reverts | ForEach-Object { New-IgwtGuiManageRow -Title "Revert $($_.Name)" -Subtitle $_.Why -Badge $_.Id -State 'Risk Zone item on' -Tone 'Warn' -Tip "Turn this Risk Zone item off on the Risk Zone page. $($_.Why)" -Source $_ })
        if ($reco.Count -eq 0) { $reco = @(New-IgwtGuiManageRow -Title 'Nothing to change' -Subtitle 'Every recommended Windows network item is already applied or does not apply to this connection.' -State 'OK' -Tone 'Pass') }
        $c.NetRecoList.ItemsSource = $reco
        $c.NetGuidanceList.ItemsSource = @($r.Guidance | ForEach-Object { New-IgwtGuiManageRow -Title $_.Title -Subtitle $_.Text -State $_.Severity -Tone $(if ($_.Severity -eq 'Warn') { 'Warn' } else { 'Info' }) -Tip $_.Text -Source $_ })
    }
    $c.NetPathText.Text = (@($Result.Trace | ForEach-Object { '{0,2}  {1,-15} {2,9}  {3,-8} {4}' -f $_.Hop, $(if ($_.Address) { $_.Address } else { '*' }), $(if ($null -ne $_.RttMs) { "$($_.RttMs) ms" } else { '' }), $_.Class, $_.Name }) -join $nl)
    Update-IgwtGuiButtons
}

function Start-IgwtGuiNetTest {
    <# .SYNOPSIS Runs the network quality test in the worker (read-only: pings and DNS queries). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only measurement.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $duration = @('Quick', 'Standard', 'Extended')[[Math]::Max(0, $c.NetDurationBox.SelectedIndex)]
    $params = @{ Duration = $duration }
    $targets = @(([string]$c.NetTargetsBox.Text) -split '[,;\s]+' | Where-Object { $_ } | Select-Object -First 4)
    if ($targets.Count) { $params.Target = $targets }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtNetworkQualityTest' -Parameters $params -BusyText "Running the $($duration.ToLowerInvariant()) network test (pings and DNS queries only)..." -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (-not $res) { $script:Gui.C.NetStatusText.Text = "The test failed: $(@($errs)[0])"; return }
        Set-IgwtGuiNetResult -Result $res
        Set-IgwtGuiStatus 'Network test finished.'
    }
}

function Start-IgwtGuiNetLoad {
    <# .SYNOPSIS Measures latency under load (the user starts a speed test or download) and grades bufferbloat. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only measurement.')]
    [CmdletBinding()]
    param()
    $a = Show-IgwtGuiMessage -Text "Start a speed test in your browser (or a large download) now, so the line is busy.`n`nPress OK while it runs. iG Windows Tuner then measures latency for 20 seconds and grades bufferbloat. It does not generate any traffic itself apart from pings." -Title 'iG Windows Tuner - latency under load' -Buttons 'OKCancel' -Icon 'Information'
    if ($a -ne 'OK') { return }
    $params = @{ DurationSec = 20 }
    if ($script:Gui.NetResult -and -not $script:Gui.NetResult.Error) { $params.Baseline = $script:Gui.NetResult }
    $null = Start-IgwtGuiJob -Command 'Measure-IgwtLoadedLatency' -Parameters $params -BusyText 'Measuring latency under load for 20 seconds...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (-not $res) { $script:Gui.C.NetStatusText.Text = "The measurement failed: $(@($errs)[0])"; return }
        $msg = "Bufferbloat grade $($res.Grade): latency rose by $($res.IncreaseMs) ms under load (idle median $($res.IdleMedianMs) ms, loaded median $($res.Loaded.MedianMs) ms)."
        if ($script:Gui.NetResult -and -not $script:Gui.NetResult.Error) {
            $script:Gui.NetResult.Bufferbloat = [pscustomobject]@{ Grade = $res.Grade; IncreaseMs = $res.IncreaseMs }
            try { $script:Gui.NetResult.Recommendations = Get-IgwtNetworkRecommendations -Result $script:Gui.NetResult } catch { Write-Verbose "Recommendations not refreshed: $($_.Exception.Message)" }
            Set-IgwtGuiNetResult -Result $script:Gui.NetResult
        }
        $script:Gui.C.NetStatusText.Text = $msg
        Set-IgwtGuiStatus $msg
    }
}

function Invoke-IgwtGuiNetApply {
    <# .SYNOPSIS Stages the recommended network items and opens the dry-run preview (applied only after confirmation). #>
    [CmdletBinding()]
    param()
    $r = $script:Gui.NetResult
    if (-not $r -or -not $r.Recommendations) { return }
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart iG Windows Tuner as administrator to apply the recommended adjustments. You can still review them here.'; return }
    $count = 0
    foreach ($id in @($r.Recommendations.TweakIds)) { Set-IgwtGuiStage -Id $id -Mode 'on'; $count++ }
    $script:Gui.PresetOperation = 'Apply:NetworkTest'
    Update-IgwtGuiPending
    Set-IgwtGuiStatus "Staged $count recommended network adjustment(s). Review the preview, then apply."
    Invoke-IgwtGuiPreview
}

function Export-IgwtGuiNetReport {
    <# .SYNOPSIS Saves the last network test as HTML in the Reports folder and opens it. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $r = $script:Gui.NetResult
    if (-not $r -or $r.Error) { return }
    $path = Join-Path (Get-IgwtDataPath -Kind Reports) ("iGWindowsTuner-network-{0}.html" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    if (-not $PSCmdlet.ShouldProcess($path, 'Write network report')) { return }
    $out = Export-IgwtNetworkReport -Result $r -Path $path -Format Html
    Set-IgwtGuiStatus "Network report saved: $out"
    Open-IgwtGuiPath -Target $out
}

#endregion

#region ASR Center

function Set-IgwtGuiAsrStatus {
    <# .SYNOPSIS Stores an ASR status result and rebuilds the rule list, keeping the selection. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Status)
    $c = $script:Gui.C
    $script:Gui.AsrStatus = $Status
    $selected = $null
    if ($c.AsrList.SelectedItem) { $selected = $c.AsrList.SelectedItem.Id }
    if (-not $Status) { $c.AsrList.ItemsSource = @(); $c.AsrSummaryText.Text = 'The ASR status could not be read; see the log.'; Update-IgwtGuiAsrDetails; return }
    $rows = @($Status.Rules | ForEach-Object { New-IgwtGuiAsrRow -Rule $_ })
    $c.AsrList.ItemsSource = $rows
    if ($selected) {
        $again = $rows | Where-Object { $_.Id -eq $selected } | Select-Object -First 1
        if ($again) { $c.AsrList.SelectedItem = $again }
    }
    $s = $Status.Summary
    $text = "{0} Block, {1} Warn, {2} Audit, {3} not configured; {4} below the recommendation." -f $s.Block, $s.Warn, $s.Audit, ($s.NotConfigured + $s.Off), $s.BelowRecommendation
    if (-not $Status.DefenderActive) { $text = "Microsoft Defender Antivirus is not the active antivirus, so ASR rules do not apply on this PC. $text" }
    if ($Status.CloudProtection -eq $false) { $text += ' Cloud-delivered protection is off; three rules depend on it.' }
    if ($s.PolicyManaged) { $text += " $($s.PolicyManaged) rule(s) are managed by Group Policy or MDM and cannot be changed here." }
    if (-not $script:Gui.IsAdmin) { $text += ' Read-only: restart as administrator to change rules or exclusions.' }
    $c.AsrSummaryText.Text = $text
    Update-IgwtGuiAsrDetails
}

function Update-IgwtGuiAsrExclusionList {
    <# .SYNOPSIS Shows the selected rule's per-rule exclusions, or the global ASR exclusions when 'global' is ticked. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $items = @()
    if ([bool]$c.AsrGlobalBox.IsChecked) {
        if ($script:Gui.AsrStatus) {
            $g = $script:Gui.AsrStatus.GlobalExclusions
            if ($g.Readable) { $items = @($g.Paths) } else { $items = @(); $c.AsrExclusionList.ToolTip = [string]$g.Note }
        }
    } elseif ($c.AsrList.SelectedItem) { $items = @($c.AsrList.SelectedItem.Rule.Exclusions) }
    $c.AsrExclusionList.ItemsSource = $items
    Update-IgwtGuiButtons
}

function Update-IgwtGuiAsrDetails {
    <# .SYNOPSIS Fills the ASR details panel for the selected rule. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = $c.AsrList.SelectedItem
    if (-not $row) {
        $c.AsrDetName.Text = 'Select a rule'
        $c.AsrDetMeta.Text = ''; $c.AsrDetDescription.Text = 'Pick a rule on the left to see what it blocks, what it means for games and its exclusions.'; $c.AsrDetImpact.Text = ''
        $c.AsrModeBox.ItemsSource = @(); $c.AsrDetSources.ItemsSource = @()
        Update-IgwtGuiAsrExclusionList
        return
    }
    $r = $row.Rule
    $c.AsrDetName.Text = [string]$r.Name
    $c.AsrDetMeta.Text = ("Current: {0} ({1})  |  Recommended: {2}  |  {3}" -f $row.ModeText, $(if ($r.Source -eq 'NotSet') { 'Windows default' } else { $r.Source }), $r.Recommended, $r.Id)
    $desc = [string]$r.Description
    if ($r.Notes) { $desc += "  Note: $($r.Notes)" }
    if ($r.ManagedByPolicy) { $desc += "  This rule is managed by $($r.Source); change it there." }
    $c.AsrDetDescription.Text = $desc
    $c.AsrDetImpact.Text = [string]$r.GamerImpact
    $modes = @($r.AllowedModes)
    $c.AsrModeBox.ItemsSource = $modes
    if ($modes -contains [string]$r.Mode) { $c.AsrModeBox.SelectedItem = [string]$r.Mode }
    elseif ($modes -contains [string]$r.Recommended) { $c.AsrModeBox.SelectedItem = [string]$r.Recommended }
    $c.AsrDetSources.ItemsSource = @($r.Sources)
    Update-IgwtGuiAsrExclusionList
}

function Start-IgwtGuiAsrRefresh {
    <# .SYNOPSIS Reads the ASR status in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtAsrStatus' -BusyText 'Reading ASR rules (read-only)...' -OnComplete {
        param($out, $errs)
        $st = @($out) | Select-Object -Last 1
        Set-IgwtGuiAsrStatus -Status $st
        if ($st) { Set-IgwtGuiStatus 'ASR rules read.' } else { Set-IgwtGuiStatus 'The ASR status could not be read; see the log.' }
    }
}

function Set-IgwtGuiAsrAudit {
    <# .SYNOPSIS Shows an ASR audit view result. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Audit)
    $c = $script:Gui.C
    $script:Gui.AsrAudit = $Audit
    if (-not $Audit) { $c.AsrAuditList.ItemsSource = @(); $c.AsrAuditSummaryText.Text = 'The audit view could not be read; see the log.'; return }
    if (-not $Audit.Readable) { $c.AsrAuditList.ItemsSource = @(); $c.AsrAuditSummaryText.Text = [string]$Audit.Error; return }
    $c.AsrAuditList.ItemsSource = @(New-IgwtGuiAsrAuditRow -Audit $Audit)
    $t = $Audit.Totals
    $c.AsrAuditSummaryText.Text = ("Last {0} day(s), log covers {1}: {2} blocked, {3} audited, {4} controlled folder access, {5} network protection. {6} to review, {7} ready to promote." -f `
            $Audit.Days, $Audit.CoverageDays, $t.AsrBlocked, $t.AsrAudited, $t.Cfa, $t.Network, $t.ToReview, $t.ToPromote)
    Update-IgwtGuiButtons
}

function Start-IgwtGuiAsrAudit {
    <# .SYNOPSIS Reads the ASR audit view in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtAsrAudit' -Parameters @{ Days = 14 } -BusyText 'Reading the Defender log (read-only)...' -OnComplete {
        param($out, $errs)
        Set-IgwtGuiAsrAudit -Audit (@($out) | Select-Object -Last 1)
        Set-IgwtGuiStatus 'ASR audit view updated.'
    }
}

function Invoke-IgwtGuiAsrChange {
    <# .SYNOPSIS Confirms, then runs one ASR Center change in the worker (snapshot first) and refreshes. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Parameters, [Parameter(Mandatory = $true)][string]$Description)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to change ASR rules or exclusions.'; return }
    $text = "$Description`n`nA snapshot is written first, so you can revert this in Backups & Logs."
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - ASR Center' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtAsrChange' -Parameters $Parameters -Blocking -BusyText 'Changing ASR settings (snapshot first)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The change was not made: $(@($errs)[0])" -Icon 'Error' }
        elseif ($res -and $res.Changes -gt 0) {
            $lines = @($res.Results | ForEach-Object { "[$($_.Result)] $($_.Target): $($_.Change)$(if ($_.Message) { " - $($_.Message)" })" })
            $null = Show-IgwtGuiMessage -Text (($lines -join "`n") + "`n`nSnapshot: $($res.Snapshot)") -Icon $(if (@($res.Results | Where-Object { $_.Result -eq 'Failed' }).Count) { 'Warning' } else { 'Information' })
        } else { Set-IgwtGuiStatus 'Nothing to change.' }
        Start-IgwtGuiAsrRefresh
    }
}

#endregion

function Show-IgwtGuiPage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Page)
    $c = $script:Gui.C
    foreach ($p in 'PageDashboard', 'PagePresets', 'PageTweaks', 'PageInspect', 'PageManage', 'PageDiagnostics', 'PageNetTest', 'PageAsr', 'PageCleaner', 'PageDisk', 'PageStartup', 'PageBackups', 'PageRejected', 'PageAbout') { $c[$p].Visibility = 'Collapsed' }
    $isTweakPage = $script:IgwtCategories -contains $Page
    $c.DetailsColumn.Width = $(if ($isTweakPage) { New-Object System.Windows.GridLength(380) } else { New-Object System.Windows.GridLength(0) })
    $c.DetailsPane.Visibility = $(if ($isTweakPage) { 'Visible' } else { 'Collapsed' })
    if ($isTweakPage) {
        $script:Gui.Category = $Page
        $c.SearchBox.Text = ''
        $c.PageTweaks.Visibility = 'Visible'
        Update-IgwtGuiTweakList
        return
    }
    switch ($Page) {
        'Dashboard' { $c.PageDashboard.Visibility = 'Visible' }
        'Presets' { $c.PagePresets.Visibility = 'Visible'; Update-IgwtGuiPresetCards }
        'Asr' { $c.PageAsr.Visibility = 'Visible'; if (-not $script:Gui.AsrStatus -and $script:Gui.Runspace -and -not $script:Gui.Job) { Start-IgwtGuiAsrRefresh } }
        'Inspect' { $c.PageInspect.Visibility = 'Visible'; if (-not $script:Gui.Inspection -and $script:Gui.Runspace -and -not $script:Gui.Job) { Start-IgwtGuiInspect } }
        'Manage' { $c.PageManage.Visibility = 'Visible'; if (-not $script:Gui.Manage -and $script:Gui.Runspace -and -not $script:Gui.Job) { Start-IgwtGuiManageRefresh } }
        'NetTest' { $c.PageNetTest.Visibility = 'Visible' }
        'Diagnostics' { $c.PageDiagnostics.Visibility = 'Visible'; if (-not $script:Gui.Diag -and $script:Gui.Runspace -and -not $script:Gui.Job) { Start-IgwtGuiDiagRefresh } }
        'Cleaner' { $c.PageCleaner.Visibility = 'Visible' }
        'Disk' { $c.PageDisk.Visibility = 'Visible' }
        'Startup' { $c.PageStartup.Visibility = 'Visible' }
        'Backups' { $c.PageBackups.Visibility = 'Visible' }
        'Rejected' { $c.PageRejected.Visibility = 'Visible' }
        'About' { $c.PageAbout.Visibility = 'Visible' }
    }
}

function Save-IgwtGuiScreenshots {
    <#
    .SYNOPSIS
        Loads live data synchronously and renders each navigation page of the already-initialized
        window to PNG with RenderTargetBitmap (no window is shown). Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Folder, [double]$Scale = 1.0, [switch]$WithNetworkTest)
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder -Force }
    $data = Get-IgwtGuiData -IncludeHealth
    Update-IgwtGuiFromData -Data $data
    # Read-only data for the cleaner and disk analyzer pages (scan deletes nothing).
    Set-IgwtGuiCleanerScan -Scan (Invoke-IgwtCleanerScan -Level Standard)
    $script:Gui.C.DiskPathBox.Text = $script:IgwtProjectRoot
    Update-IgwtGuiDiskLists -Usage (Get-IgwtDiskUsage -Path $script:IgwtProjectRoot -Top 12)
    # Read-only data for the expert inspectors.
    try { Set-IgwtGuiInspection -Inspection (Get-IgwtInspection); if (@($script:Gui.C.InspectPowerList.ItemsSource).Count) { $script:Gui.C.InspectPowerList.SelectedIndex = 0 } }
    catch { Write-Verbose "Inspector data unavailable for screenshots: $($_.Exception.Message)" }
    # Read-only data for the Manage and Diagnostics pages (no network tests).
    try {
        $script:Gui.Manage = Get-IgwtGuiManageData; Update-IgwtGuiManageLists
        if (@($script:Gui.C.ManageServiceList.ItemsSource).Count) { $script:Gui.C.ManageServiceList.SelectedIndex = 0 }
        Update-IgwtGuiManageDetail
        Set-IgwtGuiDiagData -Data (Get-IgwtGuiDiagnosticsData)
    } catch { Write-Verbose "Manage/diagnostics data unavailable for screenshots: $($_.Exception.Message)" }
    # Optional: a quick network test (pings and DNS queries only) so the Network Test page shows data.
    if ($WithNetworkTest) { try { Set-IgwtGuiNetResult -Result (Invoke-IgwtNetworkQualityTest -Duration Quick) } catch { Write-Verbose "Network test unavailable for screenshots: $($_.Exception.Message)" } }
    # Read-only data for the ASR Center (status and the Defender event log).
    try {
        Set-IgwtGuiAsrStatus -Status (Get-IgwtAsrStatus)
        Set-IgwtGuiAsrAudit -Audit (Get-IgwtAsrAudit -Days 14)
        if (@($script:Gui.C.AsrList.ItemsSource).Count) { $script:Gui.C.AsrList.SelectedIndex = 0 }
    } catch { Write-Verbose "ASR data unavailable for screenshots: $($_.Exception.Message)" }
    $root = $script:Gui.Window.Content
    # Copy the window resources (theme) onto the root so implicit styles still resolve after detaching.
    $rd = New-Object System.Windows.ResourceDictionary
    foreach ($k in @($script:Gui.Window.Resources.Keys)) { $rd.Add($k, $script:Gui.Window.Resources[$k]) }
    $script:Gui.Window.Content = $null
    $root.Resources = $rd
    $root.Background = $script:Gui.Window.FindResource('BrushBackground')
    $root.LayoutTransform = New-Object System.Windows.Media.ScaleTransform($Scale, $Scale)
    $w = [int](1280 * $Scale); $h = [int](820 * $Scale)
    $saved = New-Object System.Collections.Generic.List[string]
    $index = 0
    foreach ($item in @($script:Gui.C.NavList.Items)) {
        $page = [string]$item.Tag
        $script:Gui.C.NavList.SelectedIndex = $index
        Show-IgwtGuiPage -Page $page
        if ($script:IgwtCategories -contains $page -and @($script:Gui.C.TweakList.ItemsSource).Count -gt 0) {
            $script:Gui.C.TweakList.SelectedIndex = 0
            Update-IgwtGuiDetails
        }
        $root.Measure((New-Object System.Windows.Size($w, $h)))
        $root.Arrange((New-Object System.Windows.Rect(0, 0, $w, $h)))
        $root.UpdateLayout()
        $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($w, $h, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
        $bmp.Render($root)
        $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
        $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bmp))
        $name = ('{0:D2}-{1}-{2}.png' -f $index, ($page -replace '[^A-Za-z]', ''), [int]($Scale * 100))
        $file = Join-Path $Folder $name
        $fs = [System.IO.File]::Create($file)
        try { $enc.Save($fs) } finally { $fs.Dispose() }
        $saved.Add($file)
        $index++
    }
    return $saved.ToArray()
}

#endregion

function Show-IgwtGui {
    <#
    .SYNOPSIS
        Opens the iG Windows Tuner WPF window. Runs read-only until elevated.
    .PARAMETER ScriptPath
        Path of iGWindowsTuner.ps1 (used for the "Restart as administrator" relaunch).
    .PARAMETER RenderTo
        Render every page offscreen to PNG files in this folder instead of showing the window
        (documentation screenshots and the GUI smoke test). Read-only.
    .PARAMETER Scale
        With -RenderTo: layout scale factor to emulate 125% / 150% display scaling.
    .PARAMETER WithNetworkTest
        With -RenderTo: run a quick network test (pings and DNS queries only) so the Network Test page shows data.
    #>
    [CmdletBinding()]
    param([string]$ScriptPath, [string]$RenderTo, [double]$Scale = 1.0, [switch]$WithNetworkTest)
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
        if (-not $ScriptPath) { throw 'WPF requires an STA thread. Start PowerShell with -STA.' }
        Start-Process -FilePath (Get-IgwtHostExecutable) -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', ('"{0}"' -f $ScriptPath))
        return
    }
    Import-IgwtWpf
    $window = New-IgwtMainWindow
    $script:Gui = @{
        Window = $window; C = @{}; Data = $null; Staged = @{}; Category = $null; Job = $null; PresetOperation = $null
        Queue = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'); Runspace = $null; IsAdmin = (Test-IgwtIsAdmin)
        Catalog = @(Get-IgwtCatalog); Presets = @(Get-IgwtPreset); ScriptPath = $ScriptPath; AllowClose = $false
        CleanRules = @(Get-IgwtCleanerRules); CleanScan = $null; CleanSelected = @{}; Cts = $null; DiskSelected = $null
        AsrStatus = $null; AsrAudit = $null; Inspection = $null; Manage = $null; Diag = $null; NetResult = $null
    }
    foreach ($n in $script:IgwtGuiControlNames) {
        $ctl = $window.FindName($n)
        if (-not $ctl) { throw "Control '$n' not found in MainWindow.xaml." }
        $script:Gui.C[$n] = $ctl
    }
    $c = $script:Gui.C
    $c.HeaderVersion.Text = "v$script:IgwtVersion  |  Gaming performance and security toolbox"
    $c.AboutText.Text = Get-IgwtAboutText
    $c.RejectedList.ItemsSource = @(Get-IgwtRejectedTweaks | ForEach-Object {
            [pscustomobject]@{ Name = $_.name; Category = $_.category; Claim = $_.claim; Reason = $_.reason
                SourcesText = $(if (@($_.sources).Count) { 'Sources: ' + (@($_.sources) -join '  ') } else { '' })
                Availability = $(if ($_.riskItem) { "Available in the Risk Zone at your own risk: $($_.riskItem)" } else { [string]$_.unavailable })
                AvailabilityBrush = $(if ($_.riskItem) { $script:IgwtColor.Warn } else { $script:IgwtColor.Muted }) }
        })
    $c.AdminText.Text = $(if ($script:Gui.IsAdmin) { 'Administrator' } else { 'Read-only (not elevated)' })
    $c.ElevateButton.Visibility = $(if ($script:Gui.IsAdmin) { 'Collapsed' } else { 'Visible' })
    Update-IgwtGuiPresetCards

    # Navigation and page wiring
    $c.NavList.Add_SelectionChanged({ $item = $script:Gui.C.NavList.SelectedItem; if ($item) { Show-IgwtGuiPage -Page ([string]$item.Tag) } })
    $c.NavList.SelectedIndex = 0
    $c.TweakList.Add_SelectionChanged({ Update-IgwtGuiDetails })
    $toggleHandler = [System.Windows.RoutedEventHandler] {
        param($eventSource, $e)
        $src = $e.OriginalSource
        if ($src -is [System.Windows.Controls.CheckBox]) { Invoke-IgwtGuiToggle -CheckBox $src }
    }
    $c.TweakList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, $toggleHandler)
    $c.SearchBox.Add_TextChanged({ Update-IgwtGuiTweakList })
    foreach ($f in 'FilterTierA', 'FilterTierB', 'FilterRiskLow', 'FilterRiskMedium', 'FilterRiskHigh', 'FilterRestart', 'FilterChanged') {
        $c[$f].Add_Click({ Update-IgwtGuiTweakList })
    }
    $c.DetSources.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($eventSource, $e)
            if ($e.OriginalSource -is [System.Windows.Controls.Button]) { Open-IgwtGuiPath -Target ([string]$e.OriginalSource.Tag) }
        })
    $c.DetResetButton.Add_Click({
            $row = $script:Gui.C.TweakList.SelectedItem
            if ($row) { Set-IgwtGuiStage -Id $row.Id -Mode 'reset'; Update-IgwtGuiTweakList; Set-IgwtGuiStatus "Staged: reset '$($row.Id)' to the Windows default." }
        })
    $c.PresetCards.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($eventSource, $e)
            $btn = $e.OriginalSource
            if (-not ($btn -is [System.Windows.Controls.Button])) { return }
            if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to stage and apply presets. You can still preview tweaks on the category pages.'; return }
            $preset = $script:Gui.Presets | Where-Object { $_.id -eq [string]$btn.Tag } | Select-Object -First 1
            if (-not $preset -or -not $script:Gui.Data) { return }
            $script:Gui.Staged.Clear()
            $count = 0
            foreach ($id in @(Get-IgwtGuiPresetMembers -Preset $preset)) {
                $s = $script:Gui.Data.States[$id]
                if ($s -and $s.State -in 'Off', 'Partial') { Set-IgwtGuiStage -Id $id -Mode 'on'; $count++ }
            }
            $script:Gui.PresetOperation = "Preset:$($preset.name)"
            Update-IgwtGuiPending
            Set-IgwtGuiStatus "Staged $count change(s) from the $($preset.name) preset. Review them on the category pages (marked 'Pending'), then Preview or Apply."
        })
    $c.PreviewButton.Add_Click({ Invoke-IgwtGuiPreview })
    $c.ApplyButton.Add_Click({ Invoke-IgwtGuiApply })
    $c.DiscardButton.Add_Click({ $script:Gui.Staged.Clear(); $script:Gui.PresetOperation = $null; Update-IgwtGuiTweakList; Set-IgwtGuiStatus 'All staged changes discarded.' })
    $c.RefreshButton.Add_Click({ Start-IgwtGuiRefresh -IncludeHealth })
    $c.ExportReportButton.Add_Click({
            $null = Start-IgwtGuiJob -Command 'Export-IgwtGuiReport' -BusyText 'Writing HTML report...' -OnComplete {
                param($out, $errs)
                $path = [string](@($out) | Select-Object -Last 1)
                if ($path -and (Test-Path -LiteralPath $path)) { Set-IgwtGuiStatus "Report saved: $path"; Open-IgwtGuiPath -Target $path }
            }
        })
    $c.ElevateButton.Add_Click({ Invoke-IgwtGuiElevate })
    $c.RevertLastButton.Add_Click({ Invoke-IgwtGuiRevert -Last })
    $c.BackupRevertLastButton.Add_Click({ Invoke-IgwtGuiRevert -Last })
    $c.BackupRevertSelectedButton.Add_Click({
            $sel = $script:Gui.C.SnapshotList.SelectedItem
            if ($sel) { Invoke-IgwtGuiRevert -SnapshotPath $sel.Path } else { Set-IgwtGuiStatus 'Select a snapshot first.' }
        })
    $c.RevertSnapshotButton.Add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Filter = 'iG Windows Tuner snapshot (snapshot-*.json)|snapshot-*.json'
            $dlg.InitialDirectory = Get-IgwtDataPath -Kind Backups
            if ($dlg.ShowDialog($script:Gui.Window)) { Invoke-IgwtGuiRevert -SnapshotPath $dlg.FileName }
        })
    $c.ResetStagedButton.Add_Click({
            $row = $script:Gui.C.TweakList.SelectedItem
            if ($row) { Set-IgwtGuiStage -Id $row.Id -Mode 'reset'; Update-IgwtGuiTweakList; Set-IgwtGuiStatus "Staged: reset '$($row.Id)' to the Windows default." }
            else { Set-IgwtGuiStatus 'Select a tweak on a category page first, then use this button (or the button in its details pane).' }
        })
    $c.OpenBackupsButton.Add_Click({ $p = Get-IgwtDataPath -Kind Backups; if (Test-Path -LiteralPath $p) { Open-IgwtGuiPath -Target $p } else { Set-IgwtGuiStatus 'No backups yet.' } })
    $c.OpenLogsButton.Add_Click({ $p = Get-IgwtDataPath -Kind Logs; if (Test-Path -LiteralPath $p) { Open-IgwtGuiPath -Target $p } else { Set-IgwtGuiStatus 'No logs yet.' } })
    # Cleaner and disk analyzer
    $c.DiskPathBox.Text = "$env:SystemDrive\"
    $c.CleanSummaryText.Text = 'No scan yet. Press Scan to see what can be cleaned (nothing is deleted).'
    $c.CleanScanButton.Add_Click({ Start-IgwtGuiCleanerScan })
    $c.CleanRunButton.Add_Click({ Invoke-IgwtGuiCleanerClean })
    $c.CleanCancelButton.Add_Click({ if ($script:Gui.Cts) { $script:Gui.Cts.Cancel(); Set-IgwtGuiStatus 'Cancelling after the current file...' } })
    $c.CleanerList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($eventSource, $e)
            $cb = $e.OriginalSource
            if (-not ($cb -is [System.Windows.Controls.CheckBox])) { return }
            $script:Gui.CleanSelected[[string]$cb.Tag] = [bool]$cb.IsChecked
            Update-IgwtGuiCleanerSummary
        })
    $c.DiskAnalyzeButton.Add_Click({ Start-IgwtGuiDiskAnalyze })
    $c.DiskCancelButton.Add_Click({ if ($script:Gui.Cts) { $script:Gui.Cts.Cancel(); Set-IgwtGuiStatus 'Cancelling the analysis...' } })
    $c.DiskPathBox.Add_KeyDown({ param($eventSource, $e) if ($e.Key -eq 'Return') { Start-IgwtGuiDiskAnalyze; $e.Handled = $true } })
    $c.DiskFolderList.Add_MouseDoubleClick({ $sel = $script:Gui.C.DiskFolderList.SelectedItem; if ($sel -and -not $script:Gui.Job) { Start-IgwtGuiDiskAnalyze -Path $sel.Path } })
    $c.DiskFolderList.Add_SelectionChanged({ if ($script:Gui.C.DiskFolderList.SelectedItem) { $script:Gui.DiskSelected = $script:Gui.C.DiskFolderList.SelectedItem.Path } })
    $c.DiskFileList.Add_SelectionChanged({ if ($script:Gui.C.DiskFileList.SelectedItem) { $script:Gui.DiskSelected = $script:Gui.C.DiskFileList.SelectedItem.Path } })
    $c.DiskOpenButton.Add_Click({ if ($script:Gui.DiskSelected) { Show-IgwtGuiInExplorer -Path $script:Gui.DiskSelected } else { Set-IgwtGuiStatus 'Select a folder or file first.' } })
    # Expert inspectors
    $c.InspectRefreshButton.Add_Click({ Start-IgwtGuiInspect })
    $c.InspectPowerAllBox.Add_Click({ Update-IgwtGuiPowerList })
    $c.InspectPowerList.Add_SelectionChanged({ Update-IgwtGuiPowerDetail })
    $c.InspectPowerApplyButton.Add_Click({ Invoke-IgwtGuiPowerChange })
    $c.InspectPowerDefaultButton.Add_Click({ Invoke-IgwtGuiPowerChange -Default })
    $c.InspectKernelChangedBox.Add_Click({ Update-IgwtGuiKernelList })
    # Manage
    $c.ManageServiceStartBox.ItemsSource = @('Automatic', 'AutomaticDelayed', 'Manual', 'Disabled')
    $c.ManageRefreshButton.Add_Click({ Start-IgwtGuiManageRefresh })
    $c.ManageSearchBox.Add_TextChanged({ Update-IgwtGuiManageLists })
    foreach ($l in 'ManageServiceList', 'ManageTaskList', 'ManageAppList', 'ManagePersistList', 'ManageFirewallList') { $c[$l].Add_SelectionChanged({ Update-IgwtGuiManageDetail }) }
    $c.ManageServiceStartBox.Add_SelectionChanged({ Update-IgwtGuiButtons })
    $c.ManageServiceApplyButton.Add_Click({
            $row = $script:Gui.C.ManageServiceList.SelectedItem; $v = [string]$script:Gui.C.ManageServiceStartBox.SelectedItem
            if ($row -and $v) { Invoke-IgwtGuiManagedChange -Kind service -Target ([string]$row.Source.Name) -Value $v }
        })
    $c.ManageTaskDisableButton.Add_Click({ $row = $script:Gui.C.ManageTaskList.SelectedItem; if ($row) { Invoke-IgwtGuiManagedChange -Kind task -Target ([string]$row.Source.Path) -Value 'Disabled' } })
    $c.ManageTaskEnableButton.Add_Click({ $row = $script:Gui.C.ManageTaskList.SelectedItem; if ($row) { Invoke-IgwtGuiManagedChange -Kind task -Target ([string]$row.Source.Path) -Value 'Enabled' } })
    $c.ManageAppRemoveButton.Add_Click({ $row = $script:Gui.C.ManageAppList.SelectedItem; if ($row) { Invoke-IgwtGuiManagedChange -Kind appx -Target ([string]$row.Source.Name) -Value 'Removed' -Provisioned:([bool]$script:Gui.C.ManageAppProvisionedBox.IsChecked) } })
    $c.ManagePersistDisableButton.Add_Click({ Invoke-IgwtGuiPersistenceDisable })
    $c.ManagePersistExportButton.Add_Click({ Export-IgwtGuiPersistence })
    $c.ManageFirewallToggleButton.Add_Click({
            $row = $script:Gui.C.ManageFirewallList.SelectedItem
            if ($row) { Invoke-IgwtGuiManagedChange -Kind firewallRule -Target ([string]$row.Source.Name) -Value $(if ($row.Source.Enabled) { 'Disabled' } else { 'Enabled' }) }
        })
    # Network test
    $c.NetDurationBox.ItemsSource = @('Quick (10 seconds)', 'Standard (30 seconds)', 'Extended (2 minutes)')
    $c.NetDurationBox.SelectedIndex = 1
    $c.NetRunButton.Add_Click({ Start-IgwtGuiNetTest })
    $c.NetLoadButton.Add_Click({ Start-IgwtGuiNetLoad })
    $c.NetApplyButton.Add_Click({ Invoke-IgwtGuiNetApply })
    $c.NetExportButton.Add_Click({ Export-IgwtGuiNetReport })
    # Diagnostics and network
    $c.DiagRefreshButton.Add_Click({ Start-IgwtGuiDiagRefresh })
    $c.DiagDnsButton.Add_Click({ Start-IgwtGuiNetworkTest -Dns })
    $c.DiagLatencyButton.Add_Click({ Start-IgwtGuiNetworkTest })
    $c.DiagReportButton.Add_Click({
            $null = Start-IgwtGuiJob -Command 'Export-IgwtGuiSystemReport' -BusyText 'Writing the full system report (read-only; about a minute)...' -OnComplete {
                param($out, $errs)
                $path = [string](@($out) | Select-Object -Last 1)
                if ($path -and (Test-Path -LiteralPath $path)) { Set-IgwtGuiStatus "System report saved: $path"; Open-IgwtGuiPath -Target $path }
                elseif (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The report was not written: $(@($errs)[0])" -Icon 'Error' }
            }
        })
    # ASR Center
    $c.AsrRefreshButton.Add_Click({ Start-IgwtGuiAsrRefresh })
    $c.AsrAuditButton.Add_Click({ Start-IgwtGuiAsrAudit })
    $c.AsrList.Add_SelectionChanged({ Update-IgwtGuiAsrDetails })
    $c.AsrGlobalBox.Add_Click({ Update-IgwtGuiAsrExclusionList })
    $c.AsrExclusionList.Add_SelectionChanged({ Update-IgwtGuiButtons })
    $c.AsrAuditList.Add_SelectionChanged({ Update-IgwtGuiButtons })
    $c.AsrDetSources.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($eventSource, $e)
            if ($e.OriginalSource -is [System.Windows.Controls.Button]) { Open-IgwtGuiPath -Target ([string]$e.OriginalSource.Tag) }
        })
    $c.AsrSetModeButton.Add_Click({
            $row = $script:Gui.C.AsrList.SelectedItem
            $mode = [string]$script:Gui.C.AsrModeBox.SelectedItem
            if (-not $row -or -not $mode) { Set-IgwtGuiStatus 'Select a rule and a mode first.'; return }
            if ($mode -eq [string]$row.Rule.Mode) { Set-IgwtGuiStatus "The rule is already in $mode."; return }
            $extra = ''
            if ($mode -in 'Block', 'Warn' -and [string]$row.Rule.GamerImpactLevel -in 'medium', 'high') { $extra = "`n`nGamer impact is $($row.Rule.GamerImpactLevel): $($row.Rule.GamerImpact) Check the audit view before blocking." }
            if ($mode -eq 'NotConfigured' -and [string]$row.Rule.Category -eq 'standard') { $extra = "`n`nThis is a standard protection rule that Microsoft recommends keeping in Block." }
            Invoke-IgwtGuiAsrChange -Parameters @{ RuleMode = @{ ([string]$row.Id) = $mode } } -Description "Set '$($row.Name)' from $($row.ModeText) to ${mode}?$extra"
        })
    $c.AsrRecommendButton.Add_Click({
            if (-not $script:Gui.AsrStatus) { return }
            $plan = @(Get-IgwtAsrRecommendationPlan -Status $script:Gui.AsrStatus)
            if ($plan.Count -eq 0) { Set-IgwtGuiStatus 'Every rule already meets its recommendation.'; return }
            $lines = @($plan | ForEach-Object { "- $($_.Name): $($_.From) -> $($_.To)" })
            Invoke-IgwtGuiAsrChange -Parameters @{ Recommended = $true } -Description ("Apply the recommended modes to $($plan.Count) rule(s)? No rule is lowered.`n`n" + ($lines -join "`n"))
        })
    $c.AsrAddExclusionButton.Add_Click({
            $path = ([string]$script:Gui.C.AsrExclusionBox.Text).Trim()
            if (-not $path) { Set-IgwtGuiStatus 'Type the full path of the program to exclude first.'; return }
            $check = Test-IgwtAsrExclusion -Path $path
            if (-not $check.Valid) { $null = Show-IgwtGuiMessage -Text "This exclusion is refused:`n`n$($check.Reason)" -Icon 'Warning'; return }
            $global = [bool]$script:Gui.C.AsrGlobalBox.IsChecked
            $row = $script:Gui.C.AsrList.SelectedItem
            if (-not $global -and -not $row) { Set-IgwtGuiStatus 'Select a rule (or tick global) first.'; return }
            $params = @{ AddExclusion = @($path) }
            $scope = 'every ASR rule (global exclusion)'
            if (-not $global) { $params.ExclusionRule = [string]$row.Id; $scope = "'$($row.Name)' only" }
            $notes = ''
            if (@($check.Warnings).Count) { $notes = "`n`n" + (@($check.Warnings) -join "`n") }
            Invoke-IgwtGuiAsrChange -Parameters $params -Description "Exclude`n$path`nfrom ${scope}?$notes`n`nDefender applies exclusions when the program next starts."
        })
    $c.AsrRemoveExclusionButton.Add_Click({
            $path = [string]$script:Gui.C.AsrExclusionList.SelectedItem
            if (-not $path) { return }
            $global = [bool]$script:Gui.C.AsrGlobalBox.IsChecked
            $row = $script:Gui.C.AsrList.SelectedItem
            $params = @{ RemoveExclusion = @($path) }
            $scope = 'the global ASR exclusions'
            if (-not $global) { if (-not $row) { return }; $params.ExclusionRule = [string]$row.Id; $scope = "the exclusions of '$($row.Name)'" }
            Invoke-IgwtGuiAsrChange -Parameters $params -Description "Remove`n$path`nfrom ${scope}?"
        })
    $c.AsrAuditExcludeButton.Add_Click({
            $sel = $script:Gui.C.AsrAuditList.SelectedItem
            if (-not $sel) { return }
            if ($sel.RuleId) {
                $match = @($script:Gui.C.AsrList.ItemsSource | Where-Object { $_.Id -eq $sel.RuleId }) | Select-Object -First 1
                if ($match) { $script:Gui.C.AsrList.SelectedItem = $match; $script:Gui.C.AsrList.ScrollIntoView($match) }
            }
            if ($sel.Exclusion) {
                $script:Gui.C.AsrGlobalBox.IsChecked = $false
                $script:Gui.C.AsrExclusionBox.Text = [string]$sel.Exclusion
                Update-IgwtGuiAsrExclusionList
                Set-IgwtGuiStatus 'Suggested file copied. Review it, then press Add exclusion (only if you trust the program).'
            } else { Set-IgwtGuiStatus 'No exclusion is suggested for this entry; see its advice.' }
        })

    $c.StartupRefreshButton.Add_Click({ Start-IgwtGuiRefresh })
    $c.StartupList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($eventSource, $e)
            $cb = $e.OriginalSource
            if (-not ($cb -is [System.Windows.Controls.CheckBox])) { return }
            $item = $cb.DataContext
            $enable = [bool]$cb.IsChecked
            $null = Start-IgwtGuiJob -Command 'Set-IgwtStartupItemEnabled' -Parameters @{ Scope = $item.Scope; Name = $item.Name; Enabled = $enable } -Blocking -BusyText "$(if ($enable) { 'Enabling' } else { 'Disabling' }) startup entry $($item.Name)..." -OnComplete {
                param($out, $errs)
                if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "Could not change the startup entry: $(@($errs)[0])" -Icon 'Error' }
                Start-IgwtGuiRefresh
            }
        })

    # Keyboard: Ctrl+F search, F5 refresh
    $window.Add_KeyDown({
            param($eventSource, $e)
            if ($e.Key -eq 'F5') { Start-IgwtGuiRefresh -IncludeHealth; $e.Handled = $true }
            elseif ($e.Key -eq 'F' -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
                if ($script:Gui.C.PageTweaks.Visibility -ne 'Visible') { $script:Gui.C.NavList.SelectedIndex = 2 }
                $null = $script:Gui.C.SearchBox.Focus(); $e.Handled = $true
            }
        })
    $window.Add_Closing({
            param($eventSource, $e)
            if ($script:Gui.Job -and $script:Gui.Job.Blocking -and -not $script:Gui.AllowClose) {
                $null = Show-IgwtGuiMessage -Text 'An apply, revert or clean is in progress. Please wait until it finishes.' -Icon 'Warning'
                $e.Cancel = $true
            }
        })

    if ($RenderTo) {
        Save-IgwtGuiScreenshots -Folder $RenderTo -Scale $Scale -WithNetworkTest:$WithNetworkTest
        return
    }

    # Worker + timer
    Initialize-IgwtGuiWorker
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({ Invoke-IgwtGuiTick })
    $timer.Start()
    $window.Add_ContentRendered({ Start-IgwtGuiRefresh -IncludeHealth })
    Update-IgwtGuiButtons

    try {
        $null = $window.ShowDialog()
    } finally {
        $timer.Stop()
        if ($script:Gui.Runspace) { try { $script:Gui.Runspace.Close(); $script:Gui.Runspace.Dispose() } catch { Write-Verbose 'Worker runspace already closed.' } }
    }
}
