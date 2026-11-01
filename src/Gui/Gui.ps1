# Gui.ps1
# WPF front end. The window is loaded from MainWindow.xaml + Theme.xaml (no code-behind).
# All long operations run in one background runspace (worker) through fixed, exported module
# commands (AddCommand, no script text), so the UI thread never blocks. The GUI contains no
# tweak logic: it stages ids and hands them to the engine.

$script:Gui = $null

$script:IgwtGuiControlNames = @(
    'HeaderVersion', 'HeaderSummary', 'HeaderBuild', 'PersonaBox', 'AcPill', 'AcPillDot', 'AcPillText', 'AdminBadge', 'AdminText', 'ElevateButton',
    'Banner', 'BannerText', 'NavList', 'FocusModeBox', 'FocusPill', 'DashDetails', 'Breadcrumb', 'DashRecentList', 'DashRecentEmpty', 'DashAllChangesButton', 'DashShortcuts', 'DashShortcutText', 'RootGrid', 'CaptionMinButton', 'CaptionMaxButton', 'CaptionCloseButton', 'DisplayButton', 'DisplayPopup', 'ThemeBox', 'FontScaleBox', 'DensityBox', 'ReduceMotionBox', 'ToastHost', 'DetailsColumn', 'DetailsPane', 'ReadOnlyBanner', 'ReadOnlyBannerText', 'ErrorBar', 'ErrorText', 'ErrorCopyButton', 'ErrorDismissButton',
    'PageDashboard', 'PagePresets', 'PageTweaks', 'PageStartup', 'PageBackups', 'PageRejected', 'PageAbout',
    'RefreshButton', 'ExportReportButton', 'AcReqList', 'AcMatrixList', 'HealthList', 'NvidiaList', 'RecommendList', 'HardwareTagList', 'HardwareOverlayList',
    'PresetCards', 'RevertLastButton', 'RevertSnapshotButton', 'ResetStagedButton', 'PresetDriftCard', 'PresetDriftText', 'PresetDriftReapplyButton', 'PresetDriftAdoptButton',
    'SessionCloseAppsBox', 'SessionStartButton', 'SessionStopButton', 'SessionStatusText', 'PresetPickBox', 'PresetCustomizeButton', 'PresetDuplicateButton', 'PresetExportButton', 'PresetImportButton', 'PresetDeleteButton',
    'TweakPageTitle', 'TweakPageSubtitle', 'TweakGridHost',
    'StartupRefreshButton', 'StartupListHost', 'BackupRevertLastButton', 'BackupRevertSelectedButton', 'OpenBackupsButton', 'OpenLogsButton', 'SnapshotListHost',
    'RejectedListHost', 'BackupSummaryText', 'RejectedSummaryText', 'PolTabs', 'PolComplianceTab', 'PolBaselineButton', 'PolBaselineText', 'PolComplianceHost', 'NetEmptyCard', 'NetResultPanel', 'NetHistoryHost', 'BackupTabs', 'HomeCard', 'HomeCardTitle', 'HomeCardText', 'HomeCardOverline', 'HomeCardDoButton', 'HomeCardSnoozeButton', 'HomeCardSnoozeWeekButton', 'HomeCardWhyButton', 'HomeCardPagesButton', 'BackupJournalTab', 'JournalStatusText', 'JournalRevertEntryButton', 'JournalRevertSessionButton', 'JournalRevertAllButton', 'JournalListHost', 'BackupLogTab', 'LogListHost', 'AboutText', 'AboutBuildText', 'AboutCopyButton', 'AboutChangelogExpander', 'AboutChangelogText', 'AboutNoticesExpander', 'AboutNoticesText',
    'PageCleaner', 'CleanScanButton', 'CleanRunButton', 'CleanCancelButton', 'CleanLevelBox', 'CleanOptInBox', 'CleanSummaryText', 'CleanerListHost',
    'PageDisk', 'DiskPathBox', 'DiskAnalyzeButton', 'DiskCancelButton', 'DiskOpenButton', 'DiskSummaryText', 'DiskFolderListHost', 'DiskFileListHost',
    'PageAsr', 'AsrRefreshButton', 'AsrPromoteButton', 'AsrRecommendButton', 'AsrSummaryIcon', 'AsrSummaryText', 'AsrTabs', 'AsrGridHost', 'AsrDetName', 'AsrDetMeta', 'AsrDetDescription', 'AsrDetPanel',
    'AsrDetImpactIcon', 'AsrDetImpactLevel', 'AsrDetImpact', 'AsrModeNotConfigured', 'AsrModeAudit', 'AsrModeWarn', 'AsrModeBlock', 'AsrModeHelp', 'AsrSetModeButton', 'AsrExclusionList', 'AsrExclusionBox', 'AsrGlobalBox',
    'AsrAddExclusionButton', 'AsrRemoveExclusionButton', 'AsrDetSources', 'AsrAuditExcludeButton', 'AsrAuditSummaryText', 'AsrAuditGridHost', 'ExpSystemText', 'ExpSummaryText', 'ExpGridHost', 'SecurityScoreText', 'SecurityFixList',
    'PageInspect', 'InspectRefreshButton', 'InspectTabs', 'InspectPowerAllBox', 'InspectPowerSummary', 'InspectPowerListHost', 'InspectPowerDetailName', 'InspectPowerDetailText',
    'InspectPowerAcBox', 'InspectPowerDcBox', 'InspectPowerApplyButton', 'InspectPowerDefaultButton', 'InspectIrqSummary', 'InspectIrqListHost', 'InspectNicList',
    'InspectKernelChangedBox', 'InspectKernelSummary', 'InspectKernelListHost', 'InspectCrashText',
    'PageManage', 'ManageRefreshButton', 'ManageTabs', 'ManageServiceSummary', 'ManageServiceGridHost', 'ManageServiceDetail', 'ManageServiceStartBox', 'ManageServiceApplyButton',
    'ManageTaskSummary', 'ManageTaskGridHost', 'ManageTaskDetail', 'ManageTaskDisableButton', 'ManageTaskEnableButton',
    'ManageAppSummary', 'ManageAppGridHost', 'ManageAppDetail', 'ManageAppProvisionedBox', 'ManageAppRemoveButton',
    'ManagePersistSummary', 'ManagePersistGridHost', 'ManagePersistDetail', 'ManagePersistDisableButton', 'ManagePersistExportButton',
    'ManageOpenFirewallButton', 'ManageHostsText', 'SecFirewallButton',
    'PageFirewall', 'FwNewRuleButton', 'FwRefreshButton', 'FwSummaryIcon', 'FwSummaryText', 'FwNoticeText', 'FwTabs', 'FwImportButton', 'FwExportButton', 'FwExportPolicyButton', 'FwGridHost',
    'FwOverviewTab', 'FwRulesTab', 'FwConnectionsTab', 'FwConnRefreshButton', 'FwConnText', 'FwConnHost', 'FwDefaultsTab', 'FwDefaultsText', 'FwDefaultsHost', 'FwOvScopeButton', 'FwOvExportOverridesButton', 'FwOvRoleBox', 'FwOvUpdatedText', 'FwOvStatusText', 'FwOvAttentionCard', 'FwOvAttentionIcon', 'FwOvAttentionTitle', 'FwOvAttentionText', 'FwOvReviewButton', 'FwOvQuickCard', 'FwOvQuickText', 'FwOvQuickButton', 'FwOvTiles', 'FwOvOriginChart', 'FwOvOriginText', 'FwOvDirChart', 'FwOvDirText', 'FwOvExposureText', 'FwOvExposureHost', 'FwOvRecentEmpty', 'FwOvRecentList', 'FwGroupList', 'FwViewList', 'FwViewEmpty', 'FwBulkButton', 'FwReportButton', 'FwDetSummary', 'FwDetChips', 'FwDetFindingsTitle', 'FwDetFindings', 'FwDetWhyExists', 'FwDetOrigin', 'FwDetMoveButton', 'FwDetNotBloatedButton', 'FwDetPrecedence', 'FwDetHistory',
    'FwDetName', 'FwDetMeta', 'FwDetRiskBox', 'FwDetRisk', 'FwEnableButton', 'FwDisableButton', 'FwAllowButton', 'FwBlockButton', 'FwEditButton', 'FwDuplicateButton', 'FwDeleteButton', 'FwDetWhy', 'FwDetText',
    'FwProfilesPanel', 'FwProfileList', 'FwNetworkList', 'FwProfileNote', 'FwLogButton',
    'FwLogTab', 'FwLogFollowButton', 'FwLogNoteButton', 'FwLogReadButton', 'FwLogStatusText', 'FwLogAddressBox', 'FwLogPortBox', 'FwLogProcessBox', 'FwLogFromBox', 'FwLogToBox', 'FwLogApplyButton', 'FwLogFilterError',
    'FwLogGridHost', 'FwLogOverviewPanel', 'FwLogSummaryText', 'FwLogHistogram', 'FwLogTopSources', 'FwLogTopPorts', 'FwLogTopProcesses', 'FwLogTopRemote', 'FwLogRulesButton',
    'FwForensicTab', 'FwForSources', 'FwForBasic', 'FwForFull', 'FwForCustom', 'FwForCustomPanel', 'FwForFwBlocked', 'FwForFwAllowed', 'FwForWfpConn', 'FwForWfpDrop', 'FwForDns', 'FwForSizeBox', 'FwForDurationBox',
    'FwForEstimateButton', 'FwForPreviewButton', 'FwForStartButton', 'FwForStopButton', 'FwForRefreshButton', 'FwForEstimateText', 'FwForStatusText', 'ForensicBanner', 'ForensicBannerText', 'ForensicBannerOpenButton', 'ForensicBannerStopButton',
    'FwExpFromBox', 'FwExpToBox', 'FwExpZipBox', 'FwExpEvidenceButton', 'FwExpFormatBox', 'FwExpRawBox', 'FwExpDatasetButton', 'FwExpStatusText',
    'PagePolicy', 'PolRefreshButton', 'PolSummaryIcon', 'PolSummaryText', 'PolTree', 'PolGridHost', 'PolDetName', 'PolDetMeta', 'PolDetState', 'PolEditPanel', 'PolStateBox', 'PolHelp', 'PolApplyButton', 'PolDetExplain',
    'PageToolkit', 'ToolkitRefreshButton', 'ToolkitTabs', 'ToolkitAppSummary', 'ToolkitAppListHost', 'ToolkitAppDetail', 'ToolkitAppStateButton', 'ToolkitInstallButton', 'ToolkitUpgradeButton',
    'ToolkitUninstallButton', 'ToolkitUpgradeAllButton', 'ToolkitImportButton', 'ToolkitExportButton', 'ToolkitTweakSummary', 'ToolkitTweakListHost', 'ToolkitTweakDetail', 'ToolkitTweakGoButton',
    'ToolkitFeatureSummary', 'ToolkitFeatureListHost', 'ToolkitFeatureDetail', 'ToolkitFeatureEnableButton', 'ToolkitFeatureDisableButton', 'ToolkitFixSummary', 'ToolkitFixListHost', 'ToolkitFixDetail', 'ToolkitFixRunButton',
    'ToolkitPanelListHost', 'ToolkitPanelDetail', 'ToolkitPanelOpenButton', 'ToolkitUpdateSummary', 'ToolkitUpdateListHost', 'ToolkitUpdateDetail', 'ToolkitUpdateGoButton', 'ToolkitUpdatePauseButton',
    'PageDiagnostics', 'DiagRefreshButton', 'DiagReportButton', 'DiagTabs', 'DiagEventListHost', 'DiagDpcCard', 'DiagDpcValue', 'DiagDpcNote', 'DiagStabilityCard', 'DiagStabilityValue', 'DiagStabilityNote', 'DiagCrashCard', 'DiagCrashValue', 'DiagCrashNote', 'DiagBootCard', 'DiagBootValue', 'DiagBootNote', 'DiagDriverSummary', 'DiagDriverListHost', 'DiagUpdateText', 'DiagUpdateListHost',
    'DiagDnsButton', 'DiagLatencyBox', 'DiagLatencyButton', 'DiagNetText', 'DiagAdapterSummary', 'DiagAdapterListHost',
    'PageNetTest', 'NetDurationBox', 'NetTargetsBox', 'NetRunButton', 'NetLoadButton', 'NetExportButton', 'NetStatusText', 'NetGradeText', 'NetScoreText', 'NetLatencyText',
    'NetJitterText', 'NetLossText', 'NetStabilityText', 'NetConnectionText', 'NetEvidenceText', 'NetTargetList', 'NetApplyButton', 'NetRecoTitle', 'NetRecoList', 'NetGuidanceList', 'NetPathText',
    'DetName', 'DetMeta', 'DetWarning', 'DetWarningText', 'DetDescription', 'DetChanges', 'DetSources', 'DetEvidence', 'DetRevert', 'DetResetButton',
    'PendingText', 'StatusText', 'BusyBar', 'BusyCancelButton', 'PreviewButton', 'ApplyButton', 'DiscardButton', 'LogExpander', 'LogBox',
    'SecuritySwitch', 'SecHardeningButton', 'SecAsrButton', 'AsrHardeningButton', 'AsrSelfButton', 'SecDefenderButton', 'AsrDefenderButton',
    'PageDefender', 'DefHardeningButton', 'DefAsrButton', 'DefSelfButton', 'DefPrefsViewButton', 'DefPolicyViewButton', 'DefRefreshButton', 'DefCategoryBox',
    'DefSummaryText', 'DefListHost', 'DefPolicyListHost', 'DefDetName', 'DefDetMeta', 'DefDetDescription', 'DefEditPanel', 'DefValueBox', 'DefValueText',
    'DefValueHelp', 'DefApplyButton', 'DefRecommendButton', 'DefPolicyPanel', 'DefPolicyStateBox', 'DefPolicyHelp', 'DefPolicyApplyButton', 'DefDocButton',
    'DashSubtitle', 'DashTileAc', 'DashAcDisc', 'DashAcIcon', 'DashAcValue', 'DashAcNote', 'DashTileSec', 'DashSecDisc', 'DashSecIcon', 'DashSecValue', 'DashSecNote',
    'DashTileHealth', 'DashHealthDisc', 'DashHealthIcon', 'DashHealthValue', 'DashHealthNote', 'DashTileChanges', 'DashChangesDisc', 'DashChangesIcon', 'DashChangesValue', 'DashChangesNote',
    'DashAllClear', 'DashActionList', 'DashMoreText', 'DashAcSummary', 'DashSecSummary', 'DashHealthSummary', 'DashHwSummary'
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
    if ($script:Gui -and $script:Gui.Window -and $script:Gui.Window.IsLoaded) { return (Show-IgwtGuiDialog -Text $Text -Title $Title -Buttons $Buttons -Icon $Icon) }
    return [string][System.Windows.MessageBox]::Show($Text, $Title, [System.Windows.MessageBoxButton]$Buttons, [System.Windows.MessageBoxImage]$Icon)
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
        Register-IgwtGuiHandler -Control $ok -Event 'Click' -Handler { $result.Accepted = $true; $w.Close() }.GetNewClosure()
        $null = $panel.Children.Add($ok)
    }
    $cancel = New-Object System.Windows.Controls.Button
    $cancel.Content = $CancelText; $cancel.Style = $script:Gui.Window.FindResource([System.Windows.Controls.Button]); $cancel.IsCancel = $true
    Register-IgwtGuiHandler -Control $cancel -Event 'Click' -Handler { $w.Close() }.GetNewClosure()
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
    Register-IgwtGuiHandler -Control $ok -Event 'Click' -Handler { $result.Accepted = $true; $w.Close() }.GetNewClosure()
    Register-IgwtGuiHandler -Control $box -Event 'TextChanged' -Handler { $ok.IsEnabled = (([string]$box.Text).Trim() -ieq 'I ACCEPT') }.GetNewClosure()
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.Style = $script:Gui.Window.FindResource([System.Windows.Controls.Button]); $cancel.IsCancel = $true; $cancel.IsDefault = $true; $cancel.ToolTip = 'Do not stage this tweak.'
    Register-IgwtGuiHandler -Control $cancel -Event 'Click' -Handler { $w.Close() }.GetNewClosure()
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

function Show-IgwtGuiError {
    <# .SYNOPSIS Error boundary: shows an error inline (with Copy details) instead of closing the window, and logs it. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Message, [string]$Details = '', [string]$Context = 'GUI')
    $script:Gui.LastErrorDetails = "$Context`r`n$Message`r`n$Details"
    try {
        $c = $script:Gui.C
        $c.ErrorText.Text = "Something went wrong ($Context): $Message The window stays open; copy the details if it happens again."
        $c.ErrorBar.Visibility = 'Visible'
    } catch { Write-Verbose "Error bar unavailable: $($_.Exception.Message)" }
    try { Write-IgwtLog -Level Error -Message "GUI error ($Context): $Message$(if ($Details) { ' | ' + (($Details -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 6) -join ' / ') })" } catch { Write-Verbose 'Logging failed.' }
    Write-IgwtGuiDiagnostic -Kind 'exception' -Text "$Context | $Message | $Details"
}

function Write-IgwtGuiDiagnostic {
    <# .SYNOPSIS Appends a line to the diagnostics folder (-DiagnosticsPath; the UI test harness reads it). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the diagnostics log the user asked for only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [string]$Text)
    if (-not $script:Gui -or -not $script:Gui.DiagnosticsPath) { return }
    try { [System.IO.File]::AppendAllText((Join-Path $script:Gui.DiagnosticsPath "$Kind.log"), ("{0:o}`t{1}`r`n" -f (Get-Date), $Text)) } catch { Write-Verbose "Diagnostics write failed: $($_.Exception.Message)" }
}

function Initialize-IgwtGuiDiagnostics {
    <#
    .SYNOPSIS
        Error boundary for the whole window, plus the diagnostics the UI test harness reads with
        -DiagnosticsPath: WPF binding errors, exceptions and UI-thread stalls longer than 200 ms.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Hooks window events and writes the diagnostics log the user asked for only.')]
    [CmdletBinding()]
    param([string]$Path)
    Register-IgwtGuiHandler -Control $script:Gui.Window.Dispatcher -Event 'UnhandledException' -Handler {
            param($eventSource, $e)
            $null = $eventSource
            $e.Handled = $true
            $ex = $e.Exception
            while ($ex.InnerException -and $ex -is [System.Management.Automation.MethodInvocationException]) { $ex = $ex.InnerException }
            # Where in the script it happened: a .NET stack alone does not name the PowerShell line.
            $where = ''
            if ($ex -is [System.Management.Automation.IContainsErrorRecord] -and $ex.ErrorRecord) {
                $er = $ex.ErrorRecord
                $where = "$(if ($er.InvocationInfo) { $er.InvocationInfo.PositionMessage })`r`n$($er.ScriptStackTrace)"
            }
            Show-IgwtGuiError -Message $ex.Message -Details ("$where`r`n$([string]$e.Exception)").Trim() -Context 'window'
        }
    Register-IgwtGuiHandler -Control ([System.AppDomain]::CurrentDomain) -Event 'UnhandledException' -Handler {
            param($eventSource, $e)
            $null = $eventSource
            Write-IgwtGuiDiagnostic -Kind 'exception' -Text "AppDomain | $([string]$e.ExceptionObject)"
        }
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Path $Path -Force }
    $script:Gui.DiagnosticsPath = (Resolve-Path -LiteralPath $Path).ProviderPath
    [System.Diagnostics.Trace]::AutoFlush = $true
    [System.Diagnostics.PresentationTraceSources]::Refresh()
    $listener = New-Object System.Diagnostics.TextWriterTraceListener((Join-Path $script:Gui.DiagnosticsPath 'binding.log'))
    $listener.TraceOutputOptions = [System.Diagnostics.TraceOptions]::DateTime   # when a binding error happens (to line it up with what the test was doing)
    $null = [System.Diagnostics.PresentationTraceSources]::DataBindingSource.Listeners.Add($listener)
    [System.Diagnostics.PresentationTraceSources]::DataBindingSource.Switch.Level = [System.Diagnostics.SourceLevels]::Warning
    $script:Gui.BindingListener = $listener
    # Stall monitor: a 100 ms timer on the UI thread; a late tick means the thread was blocked.
    $script:Gui.StallWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $stall = New-Object System.Windows.Threading.DispatcherTimer
    $stall.Interval = [TimeSpan]::FromMilliseconds(100)
    Register-IgwtGuiHandler -Control $stall -Event 'Tick' -Handler {
            $ms = $script:Gui.StallWatch.Elapsed.TotalMilliseconds
            $script:Gui.StallWatch.Restart()
            # Memory sampling for the automation suite: on request, collect garbage and report the managed heap,
            # so retained memory can be told from garbage that was not collected yet. Diagnostics mode only.
            $req = Join-Path $script:Gui.DiagnosticsPath 'gc.request'
            if (Test-Path -LiteralPath $req) {
                Remove-Item -LiteralPath $req -Force -ErrorAction SilentlyContinue
                [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
                [System.IO.File]::WriteAllText((Join-Path $script:Gui.DiagnosticsPath 'gc.done'), ('{0}|{1}' -f [math]::Round([GC]::GetTotalMemory($true) / 1MB, 1), [math]::Round([System.Diagnostics.Process]::GetCurrentProcess().PrivateMemorySize64 / 1MB, 1)))
                $script:Gui.StallWatch.Restart(); return
            }
            # Garbage collections since the last tick: a stall with a full (gen 2) collection is a GC pause.
            $gc = @([GC]::CollectionCount(0), [GC]::CollectionCount(1), [GC]::CollectionCount(2))
            $prev = $script:Gui.StallGc; $script:Gui.StallGc = $gc
            if ($ms -gt 300) { Write-IgwtGuiDiagnostic -Kind 'stall' -Text ("{0:n0} ms blocked (page {1}){2}" -f ($ms - 100), [string]$script:Gui.CurrentPage, $(if ($prev) { "; GC gen0 +{0}, gen1 +{1}, gen2 +{2}" -f ($gc[0] - $prev[0]), ($gc[1] - $prev[1]), ($gc[2] - $prev[2]) } else { '' })) }
        }
    $stall.Start()
    $script:Gui.StallTimer = $stall
    Register-IgwtGuiHandler -Control $script:Gui.Window -Event 'ContentRendered' -Handler { Write-IgwtGuiDiagnostic -Kind 'ready' -Text "pid $PID read-only $([bool]$script:Gui.ReadOnly)"; Write-IgwtGuiDiagnostic -Kind 'startup' -Text (($script:IgwtGuiStartupMarks.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join ' ') }
    # Who closed the window (the harness expects it to stay open until it closes it itself).
    Register-IgwtGuiHandler -Control $script:Gui.Window -Event 'Closing' -Handler { Write-IgwtGuiDiagnostic -Kind 'close' -Text ("page '$($script:Gui.CurrentPage)'`n" + (Get-PSCallStack | Out-String) + [Environment]::StackTrace) }
}

#endregion

#region Background worker

function Initialize-IgwtGuiWorker {
    <#
    .SYNOPSIS
        Opens the background runspace pool (up to 3 runspaces, each with the module loaded). Reads
        of different pages run side by side; the UI thread only receives the results.
    #>
    [CmdletBinding()]
    param([switch]$Async)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    # No host is attached: a prompt in a worker could never be answered and would hang the job.
    # The runspaces inherit the process execution policy of the launcher.
    # The Windows CIM modules load with the pool, not on first use: when parallel jobs auto-loaded
    # NetSecurity at the same moment, its type data was missing and firewall rules came back as raw
    # CIM objects (numbers instead of names, no rule name, every program "Any").
    $inbox = @('NetSecurity', 'NetAdapter', 'NetTCPIP', 'DnsClient', 'NetQos', 'NetConnection', 'ScheduledTasks', 'ConfigDefender', 'Defender') |
        Where-Object { Test-Path -LiteralPath (Join-Path $PSHOME "Modules\$_") }
    if (@($inbox).Count) { $iss.ImportPSModule([string[]]@($inbox)) }
    $iss.ImportPSModule(@((Join-Path $script:IgwtModuleRoot 'iGWindowsTuner.psd1')))
    # Log and progress entries reach the UI thread through this queue (set once per runspace here;
    # handing the queue to every job as a parameter blocked the job).
    $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('IgwtGuiLogQueue', $script:Gui.Queue, 'GUI log queue')))
    # One pool of up to 3 runspaces (synchronous callers: tests), or in the window (-Async) three pools of one
    # runspace each, all opened in the background: a pool that has to create another runspace blocks the caller
    # (BeginInvoke) for about a second.
    $count = $(if ($Async) { 3 } else { 1 })
    $pools = New-Object System.Collections.Generic.List[object]
    foreach ($n in 1..$count) {
        $p = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($iss)
        $null = $p.SetMinRunspaces(1)
        $null = $p.SetMaxRunspaces($(if ($Async) { 1 } else { 3 }))
        $p.ApartmentState = [System.Threading.ApartmentState]::MTA
        $p.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
        $pools.Add($p)
    }
    $pool = $pools[0]
    $script:Gui.Pools = $pools.ToArray()
    # Opening loads the Windows modules and this module into the first runspace (seconds): the window
    # opens the pool in the background (-Async) and starts its first reads when the pool is ready.
    if ($Async) { $script:Gui.PoolOpens = @($pools | ForEach-Object { , @($_, $_.BeginOpen($null, $null)) }) } else { $pool.Open() }
    $script:Gui.Runspace = $pool
    $script:Gui.Jobs = New-Object System.Collections.Generic.List[object]
    $script:Gui.WhenReady = New-Object System.Collections.Generic.List[scriptblock]
}

function Test-IgwtGuiWorkerReady {
    <# .SYNOPSIS True when the background pool has finished opening. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return [bool](@(Get-IgwtGuiOpenPools).Count)
}

function Get-IgwtGuiOpenPools {
    <# .SYNOPSIS The worker pools that have finished opening (only these accept jobs). #>
    [CmdletBinding()]
    param()
    $pools = @($(if ($script:Gui.Pools) { $script:Gui.Pools } elseif ($script:Gui.Runspace) { $script:Gui.Runspace }))
    return @($pools | Where-Object { [string]$_.RunspacePoolStateInfo.State -eq 'Opened' })
}

function Complete-IgwtGuiPoolOpens {
    <# .SYNOPSIS Calls EndOpen for pools that finished opening in the background (once each). #>
    [CmdletBinding()]
    param()
    if (-not $script:Gui.PoolOpens) { return }
    $left = New-Object System.Collections.Generic.List[object]
    foreach ($o in $script:Gui.PoolOpens) {
        if ([string]$o[0].RunspacePoolStateInfo.State -eq 'Opened') { try { $o[0].EndOpen($o[1]) } catch { Write-Verbose "Pool open: $($_.Exception.Message)" } } else { $left.Add($o) }
    }
    $script:Gui.PoolOpens = $left.ToArray()
}

function Wait-IgwtGuiWorkerReady {
    <# .SYNOPSIS Blocks until the pool is open (only when a read is started before the window's own startup reads: rare, and the same wait the old synchronous open had). #>
    [CmdletBinding()]
    param()
    if (-not $script:Gui.Runspace -or (Test-IgwtGuiWorkerReady)) { return }
    # Only the first pool is waited for; the others keep opening in the background.
    $first = @($script:Gui.PoolOpens | Where-Object { [object]::ReferenceEquals($_[0], $script:Gui.Runspace) })
    if ($first.Count) { $script:Gui.PoolOpens = @($script:Gui.PoolOpens | Where-Object { -not [object]::ReferenceEquals($_[0], $script:Gui.Runspace) }); $script:Gui.Runspace.EndOpen($first[0][1]) }
}

function Invoke-IgwtGuiWhenWorkerReady {
    <# .SYNOPSIS Runs an action now when the pool is open, else from the timer tick as soon as it is. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Defers a window action.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][scriptblock]$Action)
    # (An empty list is falsy: test for $null, not for "not set".)
    if ((Test-IgwtGuiWorkerReady) -or $null -eq $script:Gui.WhenReady) { & $Action; return }
    $script:Gui.WhenReady.Add($Action)
}

function Start-IgwtGuiJob {
    <#
    .SYNOPSIS
        Runs one exported iG Windows Tuner command in the background pool. OnComplete receives the
        output and the error records on the UI thread.
    .PARAMETER Channel
        Background read of one page (for example 'manage'): runs alongside other work, one per
        channel, and can be cancelled. Without a channel the job is a foreground job: one at a
        time, and -Blocking ones (changes) keep the window from closing.
    .PARAMETER Context
        Any object; OnComplete receives it as its third argument (instead of a closure).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Command, [hashtable]$Parameters = @{}, [scriptblock]$OnComplete, [string]$BusyText = 'Working...', [switch]$Blocking, [string]$Channel, $Context)
    # No worker (offscreen renders, tests): nothing can run in the background.
    if (-not $script:Gui.Runspace) { return $false }
    Wait-IgwtGuiWorkerReady
    if ($null -eq $script:Gui.Jobs) { $script:Gui.Jobs = New-Object System.Collections.Generic.List[object] }
    if ($Channel) {
        if (@($script:Gui.Jobs | Where-Object { $_.Channel -eq $Channel }).Count) { return $false }
    } elseif ($script:Gui.Job) { Set-IgwtGuiStatus 'Busy - please wait for the current operation to finish.'; return $false }
    if (-not $PSCmdlet.ShouldProcess($Command, 'Run in background')) { return $false }
    $ps = [PowerShell]::Create()
    # The idle open pool with the fewest running jobs (a busy one queues the job behind its own).
    $open = @(Get-IgwtGuiOpenPools)
    if (-not $open.Count) { $open = @($script:Gui.Runspace) }
    $pool = @($open | Sort-Object { $p = $_; @($script:Gui.Jobs | Where-Object { [object]::ReferenceEquals($_.Pool, $p) -and -not $_.Handle.IsCompleted }).Count })[0]
    $ps.RunspacePool = $pool
    $null = $ps.AddCommand($Command)
    foreach ($k in $Parameters.Keys) { $null = $ps.AddParameter($k, $Parameters[$k]) }
    $handle = $ps.BeginInvoke()
    $job = @{ Pool = $pool; PS = $ps; Handle = $handle; OnComplete = $OnComplete; Command = $Command; Blocking = [bool]$Blocking; Channel = $Channel; BusyText = $BusyText; Started = (Get-Date); Cancelled = $false; Context = $Context }
    $script:Gui.Jobs.Add($job)
    if (-not $Channel) { $script:Gui.Job = $job }
    Update-IgwtGuiBusy
    Set-IgwtGuiStatus $BusyText
    Update-IgwtGuiButtons
    return $true
}

function Stop-IgwtGuiReadJobs {
    <# .SYNOPSIS Cancels the background reads (changes are never interrupted). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    foreach ($job in @($script:Gui.Jobs | Where-Object { $_.Channel -and -not $_.Cancelled })) {
        if ($PSCmdlet.ShouldProcess($job.Command, 'Cancel')) { $job.Cancelled = $true; $null = $job.PS.BeginStop($null, $null) }
    }
    Set-IgwtGuiStatus 'Cancelling the background reads...'
}

function Update-IgwtGuiBusy {
    <# .SYNOPSIS Progress bar and Cancel button follow the running jobs. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $running = [object[]]$(if ($script:Gui.Jobs) { $script:Gui.Jobs.ToArray() } else { @() })
    if ($null -eq $running) { $running = @() }
    if ($running.Count) {
        if ($c.BusyBar.Visibility -ne 'Visible') { if ($script:Gui.ReduceMotion) { $c.BusyBar.IsIndeterminate = $false; $c.BusyBar.Value = 100 } else { $c.BusyBar.IsIndeterminate = $true } }
        $c.BusyBar.Visibility = 'Visible'
    } else {
        $c.BusyBar.Visibility = 'Hidden'
        $c.BusyBar.IsIndeterminate = $false
    }
    $reads = @($running | Where-Object { $_.Channel -and -not $_.Cancelled })
    $c.BusyCancelButton.Visibility = $(if ($reads.Count) { 'Visible' } else { 'Collapsed' })
    $c.BusyCancelButton.ToolTip = $(if ($reads.Count) { 'Cancel: ' + (@($reads | ForEach-Object { $_.BusyText }) -join '; ') } else { 'Cancel the background reads' })
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
    if ($script:Gui.PoolOpens -and $script:Gui.PoolOpens.Count) { Complete-IgwtGuiPoolOpens }
    # First reads wait for the pool to finish opening (started in the background).
    if ($script:Gui.WhenReady -and $script:Gui.WhenReady.Count -and (Test-IgwtGuiWorkerReady)) {
        Complete-IgwtGuiPoolOpens
        $pending = $script:Gui.WhenReady.ToArray(); $script:Gui.WhenReady.Clear()
        foreach ($a in $pending) { try { & $a } catch { Show-IgwtGuiError -Message "A startup read could not start: $($_.Exception.Message)" -Details ($_ | Out-String) } }
    }
    if ($null -eq $script:Gui.Jobs) { return }
    # One finished job per tick (150 ms): jobs that finish together do not apply their results in one block.
    $done = @($script:Gui.Jobs | Where-Object { $_.Handle.IsCompleted } | Select-Object -First 1)
    foreach ($job in $done) { Complete-IgwtGuiJob -Job $job }
}

function Get-IgwtGuiJobErrorText {
    <# .SYNOPSIS The message of an error thrown in a background job, without the EndInvoke and pipeline-stop wrappers around it. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)
    $ex = $Exception
    while ($ex.InnerException -and ($ex -is [System.Management.Automation.MethodInvocationException] -or $ex -is [System.Management.Automation.ActionPreferenceStopException])) { $ex = $ex.InnerException }
    return [string]$ex.Message
}

function Complete-IgwtGuiJob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Hands a finished job to the window.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Job)
    $out = $null
    $errs = @()
    try {
        $out = $Job.PS.EndInvoke($Job.Handle)
        $errs = @($Job.PS.Streams.Error)
    } catch {
        # A command that throws in the worker arrives wrapped ("Exception calling "EndInvoke" with "1"
        # argument(s): ..."): show its own message.
        if (-not $Job.Cancelled) {
            $errs = @(Get-IgwtGuiJobErrorText -Exception $_.Exception)
        }
    }
    $Job.PS.Dispose()
    $null = $script:Gui.Jobs.Remove($Job)
    if ([object]::ReferenceEquals($script:Gui.Job, $Job)) { $script:Gui.Job = $null }
    Update-IgwtGuiBusy
    if ($script:Gui.DiagnosticsPath) { Write-IgwtGuiDiagnostic -Kind 'job' -Text ("{0}`t{1}`t{2:N0} ms{3}" -f $Job.Command, $Job.Channel, ((Get-Date) - $Job.Started).TotalMilliseconds, $(if ($Job.Cancelled) { "`tcancelled" })) }
    if ($Job.Cancelled) {
        Set-IgwtGuiStatus "Cancelled: $($Job.BusyText)"
        Update-IgwtGuiButtons
        if ($Job.OnCancel) { try { & $Job.OnCancel } catch { Write-Verbose $_.Exception.Message } }
        return
    }
    foreach ($er in $errs) { Add-IgwtGuiLogLine "ERROR $($Job.Command): $er" }
    if ($errs.Count -gt 0) { $script:Gui.C.LogExpander.IsExpanded = $true }
    Update-IgwtGuiButtons
    if ($Job.OnComplete) {
        $applyWatch = [System.Diagnostics.Stopwatch]::StartNew()
        try { & $Job.OnComplete $out $errs $Job.Context } catch { Show-IgwtGuiError -Message "The result of $($Job.Command) could not be shown: $($_.Exception.Message)" -Details ($_ | Out-String) }
        if ($script:Gui.DiagnosticsPath) { Write-IgwtGuiDiagnostic -Kind 'apply' -Text ('{0}	{1:N0} ms' -f $Job.Command, $applyWatch.Elapsed.TotalMilliseconds) }
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
    $script:Gui.IsAdmin = ([bool]$Data.IsAdmin -and -not $script:Gui.ReadOnly)
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

    # The page updates run one per UI step (together they took about 400 ms, a visible freeze when the data
    # arrived). They read $script:Gui.Data, never a local of this function: the steps run later.
    Invoke-IgwtGuiChunked -Key 'data.pages' -Size 1 -Items @(
        { Set-IgwtGuiGridRows -Name 'StartupList' -Rows @($script:Gui.Data.Startup | ForEach-Object { New-IgwtGuiStartupRow -Entry $_ -CanToggle ([bool]$script:Gui.IsAdmin) }) }
        { Update-IgwtGuiSnapshots -Snapshots $script:Gui.Data.Snapshots }
        { if ($script:Gui.Journal -and $script:Gui.Runspace) { Start-IgwtGuiJournalLoad } }
        # The home card inputs (journal, unfinished changes, drift): at start and after every refresh.
        { if ($script:Gui.Runspace) { Start-IgwtGuiHomeCard } }
        { Update-IgwtGuiPresetCards }
        { Update-IgwtGuiTweakList }
        { Update-IgwtGuiDashboard -Data $script:Gui.Data }
    ) -Build { param($step) & $step; $null } -Done { param($rows) $null = $rows }
}

function Set-IgwtGuiTile {
    <# .SYNOPSIS Sets one dashboard tile: value, note and a calm tone (Pass, Warn, Fail, Info). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Value, [string]$Note, [ValidateSet('Pass', 'Warn', 'Fail', 'Info')][string]$Tone = 'Info')
    $c = $script:Gui.C
    $token = @{ Pass = 'Success'; Warn = 'Warning'; Fail = 'Danger'; Info = 'Info' }[$Tone]
    $c["Dash${Name}Value"].Text = $Value
    $c["Dash${Name}Note"].Text = $Note
    $c["Dash${Name}Disc"].Background = Get-IgwtGuiBrush -Token "${token}Soft"
    $c["Dash${Name}Icon"].Foreground = Get-IgwtGuiBrush -Token $token
    $tile = $c["DashTile$Name"]
    $tile.BorderBrush = $(if ($Tone -in 'Warn', 'Fail') { Get-IgwtGuiBrush -Token $token } else { Get-IgwtGuiBrush -Token 'Border' })
}

function Update-IgwtGuiDashboard {
    <#
    .SYNOPSIS
        The dashboard at a glance: four status tiles (anti-cheat, security, health, your changes),
        one short numbered "Do this next" list with the most important open items, and summaries
        for the folded detail sections. Display only.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Data)
    $c = $script:Gui.C
    $c.DashSubtitle.Text = "Read-only overview, updated $((Get-Date).ToString('HH:mm')). Open a section below for the details."
    $actions = New-Object System.Collections.Generic.List[object]
    $add = { param($level, $title, $action, $tip) if (-not @($actions | Where-Object { $_.Title -eq $title }).Count) { $actions.Add([pscustomobject]@{ Level = $level; Title = $title; Action = $action; Tip = $tip }) } }

    # Anti-cheat.
    $reqs = @($Data.AntiCheat.Requirements.PSObject.Properties | ForEach-Object { $_.Value })
    $passReq = @($reqs | Where-Object { $_.Pass }).Count
    $games = @($Data.AntiCheat.Matrix)
    $readyGames = @($games | Where-Object { [string]$_.Status -eq 'Pass' }).Count
    $acTone = switch ([string]$Data.AntiCheat.Overall) { 'Green' { 'Pass' } 'Amber' { 'Warn' } default { 'Fail' } }
    $acValue = switch ($acTone) { 'Pass' { 'Ready' } 'Warn' { 'Partly ready' } default { 'Not ready' } }
    Set-IgwtGuiTile -Name 'Ac' -Value $acValue -Note "$passReq of $($reqs.Count) requirements met, $readyGames of $($games.Count) games ready" -Tone $acTone
    $c.DashAcSummary.Text = "$passReq of $($reqs.Count) requirements, $readyGames of $($games.Count) games"
    foreach ($r in @($reqs | Where-Object { -not $_.Pass -and -not $_.Unknown })) { & $add 'Important' "Anti-cheat needs $($r.Name)" $(if ($r.Detail) { [string]$r.Detail } else { 'Turn it on in the firmware setup or Windows Security.' }) 'Kernel anti-cheat checks this before games start.' }

    # Security score.
    $sec = $null
    if ($Data.Health -and $Data.Health.PSObject.Properties['Security']) { $sec = $Data.Health.Security }
    if ($sec) {
        $open = @($sec.ToFix).Count
        $secTone = $(if ([int]$sec.Score -ge 90) { 'Pass' } elseif ([int]$sec.Score -ge 70) { 'Warn' } else { 'Fail' })
        Set-IgwtGuiTile -Name 'Sec' -Value "$($sec.Score)/100" -Note "$($sec.Grade). $(if ($open) { "$open thing(s) to fix" } else { 'Nothing to fix' })" -Tone $secTone
        $c.DashSecSummary.Text = "$($sec.Score)/100, $($sec.Grade)"
        foreach ($f in @($sec.ToFix)) {
            $route = (New-IgwtGuiSecurityCheckRow -Check $f).Route
            & $add $(if ([string]$f.Status -eq 'Fail') { 'Important' } else { 'Check' }) "$($f.Name): $($f.Value)" $(if ($route) { $route } else { [string]$f.Hint }) ([string]$f.Hint)
        }
    } else { Set-IgwtGuiTile -Name 'Sec' -Value '-' -Note 'Press Refresh to read the security score' -Tone 'Info' }

    # System health.
    if ($Data.Health) {
        $checks = @($Data.Health.Checks)
        $fail = @($checks | Where-Object { [string]$_.Status -eq 'Fail' }); $warn = @($checks | Where-Object { [string]$_.Status -in 'Warn', 'Unknown' })
        $pass = @($checks | Where-Object { [string]$_.Status -eq 'Pass' }).Count
        $issues = $fail.Count + $warn.Count
        Set-IgwtGuiTile -Name 'Health' -Value $(if ($issues) { "$issues to review" } else { 'All good' }) -Note "$($checks.Count) checks: $pass pass, $($warn.Count) to check, $($fail.Count) failed" -Tone $(if ($fail.Count) { 'Fail' } elseif ($warn.Count) { 'Warn' } else { 'Pass' })
        $c.DashHealthSummary.Text = "$($checks.Count) checks, $issues to review"
        foreach ($h in @($fail) + @($warn)) { if ($Data.Pending -and [string]$h.Name -like 'Pending reboot*') { continue }; & $add $(if ([string]$h.Status -eq 'Fail') { 'Important' } else { 'Check' }) "$($h.Name): $($h.Value)" $(if ($h.Advice) { [string]$h.Advice } else { [string]$h.Detail }) "$($h.Section). $($h.Detail)" }
        # Problems first in the detail list.
        $rank = @{ Fail = 0; Warn = 1; Unknown = 2; Info = 3; Pass = 4 }
        $c.HealthList.ItemsSource = @($checks | Sort-Object @{ Expression = { $k = [string]$_.Status; if ($rank.ContainsKey($k)) { $rank[$k] } else { 5 } } } | ForEach-Object { New-IgwtGuiCheckRow -Check $_ })
    } else { Set-IgwtGuiTile -Name 'Health' -Value '-' -Note 'Press Refresh to run the health checks' -Tone 'Info' }

    # Your changes.
    $snaps = @($Data.Snapshots | Where-Object { $_ }).Count
    if ($Data.Pending) {
        $what = $(if ($Data.Pending.Requires -eq 'reboot') { 'Restart Windows' } else { 'Sign out and back in' })
        Set-IgwtGuiTile -Name 'Changes' -Value $(if ($Data.Pending.Requires -eq 'reboot') { 'Restart needed' } else { 'Sign-out needed' }) -Note "To finish $(@($Data.Pending.Tweaks).Count) change(s)" -Tone 'Warn'
        & $add 'Important' "$what to finish your changes" "$(@($Data.Pending.Tweaks).Count) change(s) wait for it: $(@($Data.Pending.Tweaks) -join ', ')" ''
    } else {
        Set-IgwtGuiTile -Name 'Changes' -Value $(if ($snaps) { "$snaps snapshot(s)" } else { 'No changes yet' }) -Note 'Every change can be undone in Backups & Logs' -Tone 'Info'
    }
    Update-IgwtGuiDashRecent -Snapshots @($Data.Snapshots)
    if ($Data.PSObject.Properties['Hardware'] -and $Data.Hardware) { $c.DashHwSummary.Text = "$(@($Data.Hardware.Tags).Count) tags, $(@($Data.Hardware.Overlays).Count) overlay(s)" }

    # Do this next: important first, at most five, numbered.
    $ordered = @($actions | Sort-Object @{ Expression = { if ($_.Level -eq 'Important') { 0 } else { 1 } } })
    $top = @($ordered | Select-Object -First 5)
    $i = 0
    $c.DashActionList.ItemsSource = @(foreach ($a in $top) {
            $i++
            $tone = $(if ($a.Level -eq 'Important') { 'Fail' } else { 'Warn' })
            [pscustomobject]@{ Number = $i; Title = $a.Title; Action = $a.Action; Level = $a.Level; Tip = $(if ($a.Tip) { $a.Tip } else { $a.Action })
                Brush = $script:IgwtColor[$tone]; DiscBrush = $(if ($tone -eq 'Fail') { Get-IgwtGuiBrush -Token 'DangerSoft' } else { Get-IgwtGuiBrush -Token 'WarningSoft' }); RowBrush = 'Transparent' }
        })
    $c.DashAllClear.Visibility = $(if ($top.Count) { 'Collapsed' } else { 'Visible' })
    $more = $ordered.Count - $top.Count
    $c.DashMoreText.Text = "$more more item(s) in the sections below."
    $c.DashMoreText.Visibility = $(if ($more -gt 0) { 'Visible' } else { 'Collapsed' })
}

# Dashboard shortcuts per persona (3.3 D1): page tag and label.
$script:IgwtGuiDashShortcuts = @{
    Gamer     = @(@('Presets', 'Presets'), @('NetTest', 'Network test'), @('Graphics & Display', 'Graphics'), @('Firewall', 'Firewall'), @('Cleaner', 'Cleaner'))
    PowerUser = @(@('Presets', 'Presets'), @('Inspect', 'Expert inspectors'), @('Policy', 'Group Policy'), @('Manage', 'Manage'), @('Diagnostics', 'Diagnostics'))
    Sysadmin  = @(@('Security', 'Security'), @('Firewall', 'Firewall'), @('Policy', 'Group Policy'), @('Manage', 'Manage'), @('Diagnostics', 'Diagnostics'))
}

function Update-IgwtGuiDashRecent {
    <# .SYNOPSIS The dashboard's last three changes with Undo, and the persona shortcuts. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only; Undo asks first and runs through the engine.')]
    [CmdletBinding()]
    param([object[]]$Snapshots = @())
    $c = $script:Gui.C
    $canUndo = (-not (Test-IgwtReadOnly)) -and [bool]$script:Gui.IsAdmin
    $rows = @(@($Snapshots | Where-Object { $_ } | Select-Object -First 3) | ForEach-Object {
            $r = New-IgwtGuiSnapshotRow -Snapshot $_
            [pscustomobject]@{ Title = $(if ([string]$r.Detail) { [string]$r.Detail } else { [string]$r.Operation }); When = "$($r.When)  |  $($r.KindText)"; Tip = [string]$r.Path; Path = [string]$_.Path; CanUndo = $canUndo
                UndoTip = $(if ($canUndo) { 'Restore the values from before this change (asks first; the undo gets its own snapshot).' } elseif (Test-IgwtReadOnly) { 'Read-only mode: nothing can be undone here.' } else { 'Undo needs administrator rights.' }) }
        })
    $c.DashRecentList.ItemsSource = $rows
    $c.DashRecentEmpty.Visibility = $(if ($rows.Count) { 'Collapsed' } else { 'Visible' })
    $persona = $(if ($script:Gui.Persona) { [string]$script:Gui.Persona.Name } else { 'Gamer' })
    $list = $(if ($script:IgwtGuiDashShortcuts.ContainsKey($persona)) { $script:IgwtGuiDashShortcuts[$persona] } else { $script:IgwtGuiDashShortcuts.Gamer })
    $c.DashShortcuts.Children.Clear()
    foreach ($s in $list) {
        $b = New-Object System.Windows.Controls.Button
        $b.Content = $s[1]; $b.Tag = $s[0]; $b.Margin = '0,0,8,8'; $b.ToolTip = "Open $($s[1])"
        Register-IgwtGuiHandler -Control $b -Event 'Click' -Handler { param($x, $e) $null = $e; Select-IgwtGuiNavPage -Tag ([string]$x.Tag) }
        $null = $c.DashShortcuts.Children.Add($b)
    }
    $c.DashShortcutText.Text = "Pages a $($persona.ToLowerInvariant()) uses most (persona: header > persona)."
}

function Update-IgwtGuiSnapshots {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Snapshots)
    $list = @($Snapshots | Where-Object { $_ })
    Set-IgwtGuiGridRows -Name 'SnapshotList' -Rows @($list | ForEach-Object { New-IgwtGuiSnapshotRow -Snapshot $_ })
    # Status line (3.3 C1): how many snapshots, the last change and any failures.
    $c = $script:Gui.C
    if ($list.Count) {
        $last = New-IgwtGuiSnapshotRow -Snapshot $list[0]
        $failed = @($list | Where-Object { $_.PSObject.Properties['Failed'] -and [int]$_.Failed -gt 0 }).Count
        $c.BackupSummaryText.Text = "$($list.Count) snapshot$(if ($list.Count -ne 1) { 's' }); last change $($last.When): $(if ($last.Detail) { $last.Detail } else { $last.Operation }).$(if ($failed) { " $failed with failures." } else { '' }) Every one can be reverted."
    } else { $c.BackupSummaryText.Text = 'No changes yet. Every change you apply writes a snapshot here first.' }
}

function Update-IgwtGuiTweakList {
    <# .SYNOPSIS Rebuilds rows (state + staging) and applies page/search/filters. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.Data) { return }
    # Every tweak the persona shows goes into the grid; the category is a column filter that a
    # search lifts (Update-IgwtGuiTweakScope), so searching still covers every category.
    $rows = @(foreach ($t in $script:Gui.Catalog) {
            $st = $script:Gui.Data.States[$t.id]
            $personaOk = (-not $script:Gui.Persona) -or (Test-IgwtItemVisible -Tweak $t -Persona $script:Gui.Persona) -or $script:Gui.Staged.ContainsKey($t.id) -or ($st -and $st.State -in 'On', 'Partial' -and [string]$t.level -in 'Expert', 'Lab')
            if ($personaOk -and $script:Gui.FocusMode -and [string]$t.level -ne 'Standard' -and -not $script:Gui.Staged.ContainsKey($t.id)) { $personaOk = $false }
            if ($personaOk) { New-IgwtGuiTweakRow -Tweak $t -State $st -Changed ([bool]$script:Gui.Data.Changed[$t.id]) -Staged ([string]$script:Gui.Staged[$t.id]) -IsAdmin $script:Gui.IsAdmin -Confidence $(if ($script:Gui.Data.Confidence) { $script:Gui.Data.Confidence[[string]$t.id] }) }
        })
    $grid = $script:Gui.Grids.Tweaks
    Set-IgwtGridRows -Grid $grid -Rows $rows
    Update-IgwtGuiTweakHeader
    Update-IgwtGuiPending
}

function Update-IgwtGuiTweakScope {
    <# .SYNOPSIS Pre-query hook of the tweak grid: the page's category, unless a search is typed (then every category). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $Grid.Scope = $(if ($Grid.Search -or -not $script:Gui.Category) { @{} } else { @{ Category = @([string]$script:Gui.Category) } })
    if ($script:Gui.C) { Update-IgwtGuiTweakHeader }
}

function Update-IgwtGuiTweakHeader {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $grid = $script:Gui.Grids.Tweaks
    if (-not $grid) { return }
    $search = [string]$grid.Search
    $count = @($grid.Order).Count
    if ($search) { $c.TweakPageTitle.Text = "Search: $search" }
    elseif ($script:Gui.Category -eq 'Storage') { $c.TweakPageTitle.Text = 'Storage Sense' }
    elseif ($script:Gui.Category -eq 'System') { $c.TweakPageTitle.Text = 'System and diagnostics' }
    elseif ($script:Gui.Category -eq 'Risk Zone') { $c.TweakPageTitle.Text = 'Risk Zone: rejected tweaks at your own risk' }
    elseif ($script:Gui.Category) { $c.TweakPageTitle.Text = $script:Gui.Category }
    $c.TweakPageSubtitle.Text = $(if ($script:Gui.Category -eq 'Risk Zone' -and -not $search) { "$count rejected tweak(s). iG Windows Tuner does not recommend these: each is placebo, obsolete or risky, and its details list what it turns off or on. Turning one on asks you to type a confirmation; every change is snapshot-backed and can be reverted." } else { "$count tweak(s). Switches show the real current state; switching stages a change. Nothing happens until you press Apply." })
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
    Update-IgwtGuiJournalButtons
    $jobCommand = ''
    if ($busy) { $jobCommand = [string]$script:Gui.Job.Command }
    $c.CleanScanButton.IsEnabled = -not $busy
    $c.CleanRunButton.IsEnabled = (-not $busy) -and [bool]$script:Gui.CleanScan -and @(Get-IgwtGuiCleanerSelection).Count -gt 0 -and -not (Test-IgwtReadOnly)
    if (Test-IgwtReadOnly) { $c.CleanRunButton.ToolTip = Get-IgwtGuiChangeBlockReason -What 'delete files' }
    $c.CleanCancelButton.IsEnabled = $busy -and [bool]$script:Gui.Cts -and $jobCommand -like 'Invoke-IgwtCleaner*'
    $c.DiskAnalyzeButton.IsEnabled = -not $busy
    $c.DiskCancelButton.IsEnabled = $busy -and [bool]$script:Gui.Cts -and $jobCommand -eq 'Get-IgwtDiskUsage'
    Update-IgwtGuiAsrButtons
    $polRow = Get-IgwtGuiGridItem -Name DefPolicyList
    $c.DefPolicyApplyButton.IsEnabled = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$polRow -and [bool]$c.DefPolicyStateBox.SelectedItem -and [bool]$c.DefPolicyStateBox.SelectedItem.Allowed
    $c.DefDocButton.IsEnabled = [bool][string]$c.DefDocButton.Tag
    $powerRow = (Get-IgwtGuiGridItem -Name InspectPowerList)
    $canPower = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$powerRow -and [bool]$powerRow.Setting.Editable
    $c.InspectRefreshButton.IsEnabled = -not $busy
    $c.InspectPowerApplyButton.IsEnabled = $canPower
    $c.InspectPowerDefaultButton.IsEnabled = $canPower
    $canManage = (-not $busy) -and $script:Gui.IsAdmin
    $svc = Get-IgwtGuiGridItem -Name Service; $task = Get-IgwtGuiGridItem -Name Task; $app = Get-IgwtGuiGridItem -Name App
    $pe = Get-IgwtGuiGridItem -Name Persist
    $c.ManageRefreshButton.IsEnabled = -not $busy
    $c.ManageServiceApplyButton.IsEnabled = $canManage -and [bool]$svc -and [bool]$svc.Source.CanChange -and [bool]$c.ManageServiceStartBox.SelectedItem
    $c.ManageTaskDisableButton.IsEnabled = $canManage -and [bool]$task -and [bool]$task.Source.CanDisable
    $c.ManageTaskEnableButton.IsEnabled = $canManage -and [bool]$task -and -not $task.Source.Protected -and [string]$task.Source.State -eq 'Disabled'
    $c.ManageAppRemoveButton.IsEnabled = $canManage -and [bool]$app -and $app.Source.PSObject.Properties['CanRemove'] -and [bool]$app.Source.CanRemove
    $c.ManagePersistDisableButton.IsEnabled = $canManage -and [bool]$pe -and [string]$pe.Source.ActionKind -ne 'None' -and $pe.Source.Enabled -ne $false
    $c.ManagePersistExportButton.IsEnabled = [bool]$script:Gui.Manage -and $script:Gui.Manage.Persistence.PSObject.Properties['Entries']
    $pick = $c.PresetPickBox.SelectedItem
    $c.SessionStartButton.IsEnabled = (-not $busy) -and $script:Gui.IsAdmin -and -not $script:Gui.SessionActive
    $c.SessionStopButton.IsEnabled = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$script:Gui.SessionActive
    $c.PresetDriftReapplyButton.IsEnabled = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$script:Gui.Drift -and @($script:Gui.Drift.Drifted).Count -gt 0
    $c.PresetDriftAdoptButton.IsEnabled = (-not $busy) -and $script:Gui.IsAdmin -and [bool]$script:Gui.Drift -and @($script:Gui.Drift.Drifted).Count -gt 0
    foreach ($b in 'PresetCustomizeButton', 'PresetDuplicateButton', 'PresetExportButton') { $c[$b].IsEnabled = [bool]$pick }
    $c.PresetDeleteButton.IsEnabled = [bool]$pick -and $pick.PSObject.Properties['custom'] -and [bool]$pick.custom
    $tkApps = @(Get-IgwtGuiGridItems -Name ToolkitAppList).Count
    $tkFeature = (Get-IgwtGuiGridItem -Name ToolkitFeatureList)
    $c.ToolkitRefreshButton.IsEnabled = -not $busy
    $c.ToolkitAppStateButton.IsEnabled = (-not $busy) -and -not (Test-IgwtReadOnly)
    if (Test-IgwtReadOnly) { $c.ToolkitAppStateButton.ToolTip = 'Read-only mode: checking installed apps runs winget export (it writes a temporary file), so it is off here.' }
    foreach ($b in 'ToolkitInstallButton', 'ToolkitUpgradeButton', 'ToolkitUninstallButton') { $c[$b].IsEnabled = $canManage -and $tkApps -gt 0 }
    $c.ToolkitUpgradeAllButton.IsEnabled = $canManage
    $c.ToolkitExportButton.IsEnabled = $tkApps -gt 0
    $c.ToolkitImportButton.IsEnabled = [bool]$script:Gui.Toolkit
    $c.ToolkitFeatureEnableButton.IsEnabled = $canManage -and [bool]$tkFeature -and [bool]$tkFeature.Source.Supported -and [string]$tkFeature.Source.State -ne 'On'
    $c.ToolkitFeatureDisableButton.IsEnabled = $canManage -and [bool]$tkFeature -and [string]$tkFeature.Source.State -in 'On', 'Partial'
    $c.ToolkitFixRunButton.IsEnabled = (-not $busy) -and [bool](Get-IgwtGuiGridItem -Name ToolkitFixList) -and -not (Test-IgwtReadOnly)
    if (Test-IgwtReadOnly) { $c.ToolkitFixRunButton.ToolTip = Get-IgwtGuiChangeBlockReason -What 'run fixes' }
    $c.ToolkitPanelOpenButton.IsEnabled = [bool](Get-IgwtGuiGridItem -Name ToolkitPanelList)
    $c.ToolkitTweakGoButton.IsEnabled = [bool](Get-IgwtGuiGridItem -Name ToolkitTweakList)
    $c.ToolkitUpdateGoButton.IsEnabled = [bool](Get-IgwtGuiGridItem -Name ToolkitUpdateList)
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
    $cards = foreach ($p in @($script:Gui.Presets | Where-Object { -not ($_.PSObject.Properties['session'] -and $_.session) })) {
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
            Summary = "$($members.Count) tweaks in this preset; $toChange differ from your current state.$overlayText$(if ($toChange) { ' By category: ' + ((@(Get-IgwtGuiPresetDiff -Preset $p).ByCategory | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ') + '.' })"
            CompareTag = "compare:$($p.id)"
            ButtonText = $(if ($toChange -gt 0) { "Stage $toChange change(s)" } else { 'Nothing to change' })
        }
    }
    $script:Gui.C.PresetCards.ItemsSource = @($cards)
    Update-IgwtGuiPresetExtras
}

function Get-IgwtGuiPresetDiff {
    <#
    .SYNOPSIS
        What a preset would change on this PC (3.3 O3): every member that is Off or Partial now, with
        its category, current state, level and impact, and the counts per category.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [object[]]$Catalog = @($script:Gui.Catalog), [hashtable]$States = $(if ($script:Gui.Data) { $script:Gui.Data.States } else { @{} }))
    $byId = @{}; foreach ($t in $Catalog) { if ($t) { $byId[[string]$t.id] = $t } }
    $rank = @{ high = 0; medium = 1; low = 2 }
    $rows = @(foreach ($id in @(Get-IgwtGuiPresetMembers -Preset $Preset)) {
            $s = $States[$id]
            if (-not $s -or [string]$s.State -notin 'Off', 'Partial') { continue }
            $t = $byId[[string]$id]
            $impact = $(if ($t -and $t.impact) { @([string]$t.impact.performance, [string]$t.impact.latency) | Where-Object { $rank.ContainsKey($_) } | Sort-Object { $rank[$_] } | Select-Object -First 1 } else { '' })
            [pscustomobject]@{ Id = [string]$id; Name = $(if ($t) { [string]$t.name } else { [string]$id }); Category = $(if ($t) { [string]$t.category } else { 'Other' }); Now = [string]$s.State; After = 'On'
                Level = $(if ($t) { [string]$t.level } else { '' }); Impact = $(if ($impact) { [string]$impact } else { 'none' }); ImpactRank = $(if ($impact) { $rank[[string]$impact] } else { 3 }) }
        })
    $by = @($rows | Group-Object Category | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Count = [int]$_.Count } })
    [pscustomobject]@{ Rows = @($rows | Sort-Object Category, ImpactRank, Name); ByCategory = $by; Count = $rows.Count }
}

function Show-IgwtGuiPresetCompare {
    <# .SYNOPSIS The preset compared with the current state, by category; returns $true when the user chooses to stage it. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Preset)
    $d = Get-IgwtGuiPresetDiff -Preset $Preset
    $nl = [Environment]::NewLine
    if (-not $d.Count) { $null = Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $($Preset.name) compared with this PC" -Text "Nothing to change: every item of $($Preset.name) is already on."; return $false }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($Preset.name): $($d.Count) change(s) compared with this PC. Nothing changes until you stage, preview and apply.")
    $lines.Add('By category: ' + ((@($d.ByCategory) | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ') + '.')
    foreach ($grp in @($d.Rows | Group-Object Category)) {
        $lines.Add(''); $lines.Add("$($grp.Name) ($($grp.Count))")
        foreach ($r in $grp.Group) { $lines.Add(("  {0,-46} {1,-8} -> {2,-3}  impact {3}, {4}" -f $(if ($r.Name.Length -gt 46) { $r.Name.Substring(0, 45) + '~' } else { $r.Name }), $r.Now, $r.After, $r.Impact, $r.Level)) }
    }
    $accept = $(if ($script:Gui.IsAdmin -and -not (Test-IgwtReadOnly)) { "Stage $($d.Count) change(s)" } else { '' })
    return [bool](Show-IgwtGuiTextDialog -Title "iG Windows Tuner - $($Preset.name) compared with this PC" -Text ($lines -join $nl) -AcceptText $accept)
}

function Update-IgwtGuiPresetExtras {
    <# .SYNOPSIS Drift banner, Session Mode status and the custom-preset picker on the Presets page. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $script:Gui.Drift = $null
    $rec = $null
    try { $rec = Get-IgwtPresetRecord } catch { $rec = $null }
    if ($rec -and $script:Gui.Data) {
        $drifted = @(@($rec.ids) | Where-Object { $s = $script:Gui.Data.States[[string]$_]; $s -and $s.State -in 'Off', 'Partial' })
        $script:Gui.Drift = [pscustomobject]@{ Preset = [string]$rec.preset; Name = [string]$rec.name; Drifted = $drifted }
        $c.PresetDriftText.Text = $(if ($drifted.Count) { "$($drifted.Count) setting(s) changed since you applied $($rec.name) on $(([datetime]$rec.applied).ToString('g')): $($drifted -join ', '). Re-apply the preset, or adopt the current state as a custom preset." } else { "All items of $($rec.name) (applied $(([datetime]$rec.applied).ToString('g'))) are still in place." })
        $c.PresetDriftCard.Visibility = 'Visible'
    } else { $c.PresetDriftCard.Visibility = 'Collapsed' }
    $st = $null
    try { $st = Get-IgwtSessionState } catch { $st = $null }
    $sp = @($script:Gui.Presets | Where-Object { $_.PSObject.Properties['session'] -and $_.session }) | Select-Object -First 1
    $c.SessionStatusText.Text = $(if ($st -and $st.Active) { "Session active since $($st.Started.ToLocalTime().ToString('t')).$(if ($st.Stale) { " $($st.Reason) End it to restore your settings." } else { ' Ending it, or closing iG Windows Tuner, restores every setting.' })" }
        elseif ($sp) { "$($sp.hint) Apps it can close: $(@($sp.closeApps) -join ', ')." } else { '' })
    $script:Gui.SessionActive = [bool]($st -and $st.Active)
    $sel = $c.PresetPickBox.SelectedItem
    $c.PresetPickBox.ItemsSource = @($script:Gui.Presets | Where-Object { -not ($_.PSObject.Properties['session'] -and $_.session) })
    if ($sel) { $again = @($c.PresetPickBox.ItemsSource | Where-Object { $_.id -eq $sel.id }) | Select-Object -First 1; if ($again) { $c.PresetPickBox.SelectedItem = $again } }
    if (-not $c.PresetPickBox.SelectedItem) { $c.PresetPickBox.SelectedIndex = 0 }
    Update-IgwtGuiButtons
}

function Show-IgwtGuiInputDialog {
    <# .SYNOPSIS Small text input dialog; returns the text or $null. #>
    [CmdletBinding()]
    param([string]$Title, [string]$Prompt, [string]$Default = '')
    $w = New-Object System.Windows.Window
    $w.Title = $Title; $w.Width = 460; $w.SizeToContent = 'Height'; $w.ResizeMode = 'NoResize'
    $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'; $w.Background = $script:Gui.Window.FindResource('BrushBackground')
    $sp = New-Object System.Windows.Controls.StackPanel; $sp.Margin = '16'
    $lbl = New-Object System.Windows.Controls.TextBlock; $lbl.Text = $Prompt; $lbl.TextWrapping = 'Wrap'; $lbl.Margin = '0,0,0,8'; $lbl.Foreground = $script:Gui.Window.FindResource('BrushText')
    $tb = New-Object System.Windows.Controls.TextBox; $tb.Text = $Default; $tb.Style = $script:Gui.Window.FindResource([System.Windows.Controls.TextBox])
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,12,0,0'
    $result = @{ Text = $null }
    $ok = New-Object System.Windows.Controls.Button; $ok.Content = 'OK'; $ok.IsDefault = $true; $ok.Style = $script:Gui.Window.FindResource('AccentButton')
    Register-IgwtGuiHandler -Control $ok -Event 'Click' -Handler { $result.Text = $tb.Text; $w.Close() }.GetNewClosure()
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.IsCancel = $true; $cancel.Style = $script:Gui.Window.FindResource([System.Windows.Controls.Button])
    $null = $panel.Children.Add($ok); $null = $panel.Children.Add($cancel)
    $null = $sp.Children.Add($lbl); $null = $sp.Children.Add($tb); $null = $sp.Children.Add($panel)
    $w.Content = $sp
    $null = $tb.Focus()
    $null = $w.ShowDialog()
    if ($null -ne $result.Text) { return ([string]$result.Text).Trim() }
    return $null
}

function Show-IgwtGuiPresetBuilder {
    <#
    .SYNOPSIS
        Custom preset builder: every catalog item the base preset's rules allow, ticked when it is
        in the base preset. Returns Name, Add and Remove, or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Base)
    $members = @($Base.tweaks)
    $ceiling = Get-IgwtLevelRank -Level ([string]$Base.levelCeiling)
    $allowed = @($script:Gui.Catalog | Where-Object {
            [string]$_.level -ne 'Lab' -and [string]$_.evidence.tier -ne 'R' -and [string]$_.group -ne 'Session Mode' -and (Get-IgwtLevelRank -Level ([string]$_.level)) -le $ceiling -and
            ([string]$Base.antiCheatPolicy -ne 'safeOnly' -or $_.antiCheatSafe)
        })
    $w = New-Object System.Windows.Window
    $w.Title = "New custom preset based on $($Base.name)"; $w.Width = 760; $w.Height = 680
    $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'; $w.Background = $script:Gui.Window.FindResource('BrushBackground')
    $grid = New-Object System.Windows.Controls.Grid; $grid.Margin = '14'
    foreach ($h in 'Auto', '*', 'Auto') { $r = New-Object System.Windows.Controls.RowDefinition; $r.Height = $h; $grid.RowDefinitions.Add($r) }
    $top = New-Object System.Windows.Controls.StackPanel
    $lbl = New-Object System.Windows.Controls.TextBlock; $lbl.TextWrapping = 'Wrap'; $lbl.Foreground = $script:Gui.Window.FindResource('BrushText'); $lbl.Margin = '0,0,0,6'
    $lbl.Text = "Name of the new preset. Ticked items are in it; only items allowed by $($Base.name)'s rules (level up to $($Base.levelCeiling)$(if ([string]$Base.antiCheatPolicy -eq 'safeOnly') { ', anti-cheat safe' })) are listed. Hardware overlays still apply."
    $name = New-Object System.Windows.Controls.TextBox; $name.Text = "$($Base.name) (custom)"; $name.Style = $script:Gui.Window.FindResource([System.Windows.Controls.TextBox]); $name.Margin = '0,0,0,8'
    $null = $top.Children.Add($lbl); $null = $top.Children.Add($name)
    [System.Windows.Controls.Grid]::SetRow($top, 0)
    $list = New-Object System.Windows.Controls.StackPanel
    $boxes = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($allowed | Group-Object category)) {
        $hdr = New-Object System.Windows.Controls.TextBlock; $hdr.Text = $g.Name; $hdr.FontWeight = 'SemiBold'; $hdr.Margin = '0,8,0,2'; $hdr.Foreground = $script:Gui.Window.FindResource('BrushText')
        $null = $list.Children.Add($hdr)
        foreach ($i in $g.Group) {
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content = "$($i.name)  ($($i.id), $($i.level), Tier $($i.tier))"; $cb.Tag = [string]$i.id; $cb.IsChecked = ($members -contains [string]$i.id); $cb.ToolTip = [string]$i.hint
            $cb.Foreground = $script:Gui.Window.FindResource('BrushText'); $cb.Margin = '8,2,0,2'
            $null = $list.Children.Add($cb); $boxes.Add($cb)
        }
    }
    $sv = New-Object System.Windows.Controls.ScrollViewer; $sv.VerticalScrollBarVisibility = 'Auto'; $sv.Content = $list
    [System.Windows.Controls.Grid]::SetRow($sv, 1)
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,12,0,0'
    [System.Windows.Controls.Grid]::SetRow($panel, 2)
    $result = @{ Ok = $false }
    $ok = New-Object System.Windows.Controls.Button; $ok.Content = 'Save preset'; $ok.Style = $script:Gui.Window.FindResource('AccentButton')
    Register-IgwtGuiHandler -Control $ok -Event 'Click' -Handler { $result.Ok = $true; $w.Close() }.GetNewClosure()
    $cancel = New-Object System.Windows.Controls.Button; $cancel.Content = 'Cancel'; $cancel.IsCancel = $true; $cancel.Style = $script:Gui.Window.FindResource([System.Windows.Controls.Button])
    $null = $panel.Children.Add($ok); $null = $panel.Children.Add($cancel)
    $null = $grid.Children.Add($top); $null = $grid.Children.Add($sv); $null = $grid.Children.Add($panel)
    $w.Content = $grid
    $null = $w.ShowDialog()
    if (-not $result.Ok) { return $null }
    $checked = @($boxes | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Tag })
    [pscustomobject]@{ Name = ([string]$name.Text).Trim(); Add = @($checked | Where-Object { $members -notcontains $_ }); Remove = @($members | Where-Object { $checked -notcontains $_ }) }
}

function Update-IgwtGuiPresetList {
    <# .SYNOPSIS Reloads the presets (after a custom preset was saved, imported or deleted). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $script:Gui.Presets = @(Get-IgwtPreset)
    Update-IgwtGuiPresetCards
}

function Invoke-IgwtGuiPresetAction {
    <# .SYNOPSIS Customize, duplicate, export, import or delete presets from the Presets page. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Customize', 'Duplicate', 'Export', 'Import', 'Delete', 'Adopt')][string]$Action)
    $p = $script:Gui.C.PresetPickBox.SelectedItem
    try {
        switch ($Action) {
            'Export' {
                $dlg = New-Object Microsoft.Win32.SaveFileDialog
                $dlg.Filter = 'iG Windows Tuner preset (*.json)|*.json'; $dlg.FileName = "igwt-preset-$($p.id).json"
                if ($dlg.ShowDialog($script:Gui.Window)) { $null = Export-IgwtPreset -Name ([string]$p.id) -Path $dlg.FileName; Set-IgwtGuiStatus "Preset saved to $($dlg.FileName)." }
                return
            }
        }
        if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to save, import or delete custom presets (they are stored in the protected data folder).'; return }
        switch ($Action) {
            'Customize' {
                $r = Show-IgwtGuiPresetBuilder -Base $p
                if (-not $r) { return }
                $saved = Save-IgwtCustomPreset -Name $r.Name -BasedOn ([string]$p.id) -AddIds $r.Add -RemoveIds $r.Remove
                Set-IgwtGuiStatus "Saved custom preset '$($saved.name)' ($(@($saved.tweaks).Count) items)."
            }
            'Duplicate' {
                $n = Show-IgwtGuiInputDialog -Title 'Duplicate preset' -Prompt "Name of the copy of $($p.name):" -Default "$($p.name) copy"
                if (-not $n) { return }
                $saved = Copy-IgwtPreset -Name ([string]$p.id) -NewName $n
                Set-IgwtGuiStatus "Saved '$($saved.name)'."
            }
            'Import' {
                $dlg = New-Object Microsoft.Win32.OpenFileDialog
                $dlg.Filter = 'iG Windows Tuner preset (*.json)|*.json'
                if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
                $saved = Import-IgwtPreset -Path $dlg.FileName
                Set-IgwtGuiStatus "Imported '$($saved.name)' ($(@($saved.tweaks).Count) items)."
            }
            'Delete' {
                if (-not ($p.PSObject.Properties['custom'] -and $p.custom)) { $null = Show-IgwtGuiMessage -Text "'$($p.name)' is a built-in preset and cannot be deleted."; return }
                if ((Show-IgwtGuiMessage -Text "Delete the custom preset '$($p.name)'? Settings it applied stay as they are." -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
                Remove-IgwtCustomPreset -Name ([string]$p.id)
                Set-IgwtGuiStatus "Deleted '$($p.name)'."
            }
            'Adopt' {
                $d = $script:Gui.Drift
                if (-not $d) { return }
                $n = Show-IgwtGuiInputDialog -Title 'Adopt as custom preset' -Prompt "Save $($d.Name) without the $(@($d.Drifted).Count) item(s) you changed, as:" -Default "$($d.Name) (as is)"
                if (-not $n) { return }
                $saved = Save-IgwtDriftAsPreset -Name $n -Preset $d.Preset
                Set-IgwtGuiStatus "Saved '$($saved.name)'."
            }
        }
        Update-IgwtGuiPresetList
    } catch { $null = Show-IgwtGuiMessage -Text $_.Exception.Message -Icon 'Warning' }
}

function Start-IgwtGuiSession {
    <# .SYNOPSIS Starts Session Mode in the worker after confirmation (apps are closed only when ticked and confirmed). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Asks the user in a dialog, then runs Start-IgwtSession (which supports ShouldProcess) in the worker.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to start Session Mode.'; return }
    $sp = @($script:Gui.Presets | Where-Object { $_.PSObject.Properties['session'] -and $_.session }) | Select-Object -First 1
    $apps = @()
    if ($script:Gui.C.SessionCloseAppsBox.IsChecked) { $apps = @(Get-IgwtSessionApps -Name @($sp.closeApps) | ForEach-Object { $_.Name }) }
    $text = "Start Session Mode?`n`n- App notifications off`n- Windows Search indexing paused`n- The highest power plan your hardware allows`n$(if ($apps.Count) { "- Close: $($apps -join ', ')`n" })`nA snapshot is written first. Ending the session, or closing iG Windows Tuner, restores every setting."
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - Session Mode' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Start-IgwtSession' -Parameters @{ Owner = 'gui'; CloseApps = $apps } -Blocking -BusyText 'Starting Session Mode (snapshot first)...' -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "Session Mode did not start: $(@($errs)[0])" -Icon 'Warning' } else { Set-IgwtGuiStatus 'Session Mode started. End it on the Presets page or by closing iG Windows Tuner.' }
        Start-IgwtGuiRefresh
    }
}

function Stop-IgwtGuiSession {
    <# .SYNOPSIS Ends Session Mode in the worker (restores the session snapshot). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs Stop-IgwtSession (which supports ShouldProcess) in the worker.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to end Session Mode and restore your settings.'; return }
    $null = Start-IgwtGuiJob -Command 'Stop-IgwtSession' -Blocking -BusyText 'Ending Session Mode (restoring settings)...' -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "Session Mode could not be ended: $(@($errs)[0])" -Icon 'Warning' } else { Set-IgwtGuiStatus 'Session Mode ended; your settings are restored.' }
        Start-IgwtGuiRefresh
    }
}

function Update-IgwtGuiDetails {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = (Get-IgwtGuiGridItem -Name Tweaks)
    if (-not $row) { return }
    $t = $script:Gui.Catalog | Where-Object { $_.id -eq $row.Id } | Select-Object -First 1
    $s = $script:Gui.Data.States[$row.Id]
    $c.DetName.Text = [string]$t.name
    $badge = $(if ($script:Gui.Data -and $script:Gui.Data.Confidence -and $script:Gui.Data.Confidence[[string]$t.id]) { "  |  " + [string]$script:Gui.Data.Confidence[[string]$t.id].Label } else { '' })
    $c.DetMeta.Text = ("{0}  |  {1}{2}  |  {3} level  |  Tier {4}{9}  |  risk {5}  |  {6}  |  {7}  |  revert: {8}" -f $t.id, $t.category, $(if ($t.group) { " / $($t.group)" } else { '' }), $t.level, $t.evidence.tier, $t.risk,
        $(switch ($t.requires) { 'reboot' { 'reboot required' } 'logoff' { 'sign-out required' } default { 'applies immediately' } }),
        [string]$t.antiCheatText, [string]$t.reversible, $badge)
    if ([string]$t.evidence.tier -eq 'R') { $c.DetWarningText.Text = 'RISK ZONE (rejected tweak). ' + (Get-IgwtRiskZoneSummary -Tweak $t); $c.DetWarning.Visibility = 'Visible' }
    elseif ($t.warning) { $c.DetWarningText.Text = [string]$t.warning; $c.DetWarning.Visibility = 'Visible' } else { $c.DetWarning.Visibility = 'Collapsed' }
    $desc = [string]$t.description
    if ($s -and $s.Reason) { $desc += [Environment]::NewLine + [Environment]::NewLine + "Current state: $($row.StateText). $($s.Reason)" }
    $c.DetDescription.Text = $desc
    $items = @()
    if ($s) { $items = @($s.Items | ForEach-Object { [pscustomobject]@{ Target = (Format-IgwtGuiChangeTarget -Target ([string]$_.Target)); Current = [string]$_.Current; Desired = [string]$_.Desired; Note = [string]$_.Note } }) }
    $c.DetChanges.ItemsSource = $items
    $c.DetSources.ItemsSource = @($t.evidence.sources)
    # Confidence badge first (3.6), then the catalog's evidence notes.
    $conf = $(if ($script:Gui.Data -and $script:Gui.Data.Confidence) { $script:Gui.Data.Confidence[[string]$t.id] })
    $c.DetEvidence.Text = ((@($(if ($conf) { [string]$conf.Tip }), [string]$t.evidence.notes) | Where-Object { $_ }) -join [Environment]::NewLine)
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
    $row = @($script:Gui.Grids.Tweaks.Index.Rows) | Where-Object { $_.Id -eq $id } | Select-Object -First 1
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
        # Only items confirmed in their dialog may be applied with the risk acknowledgement.
        if ([string]$t.evidence.tier -eq 'R' -or $t.expert) { $script:Gui.Acked[$id] = $true }
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
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiData' -Channel 'state' -Parameters @{ IncludeHealth = [bool]$IncludeHealth } -BusyText 'Reading the current system state (read-only)...' -OnComplete {
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
    $unconfirmed = @($expert | Where-Object { -not $script:Gui.Acked.ContainsKey([string]$_) })
    if ($unconfirmed.Count) {
        $null = Show-IgwtGuiMessage -Text "These Expert, Lab or Risk Zone items were staged without their confirmation dialog: $($unconfirmed -join ', ').`n`nNothing was applied. Discard them, or turn each one on from its category page so its warning is shown." -Icon 'Warning'
        return
    }
    if (-not $SkipConfirm) {
        $msg = "Apply $total staged change(s)?`n`niG Windows Tuner first creates a System Restore point and a JSON snapshot of every value it changes, so you can revert."
        $risky = @($sets.Apply | Where-Object { $id = $_; [string]($script:Gui.Catalog | Where-Object { $_.id -eq $id }).evidence.tier -eq 'R' })
        if ($risky.Count) { $msg += "`n`nIncludes RISK ZONE (rejected) tweak(s), applied at your own risk: $($risky -join ', ')." }
        if ($expert.Count) { $msg += "`n`nIncludes EXPERT toggle(s): $($expert -join ', ')." }
        if ((Show-IgwtGuiMessage -Text $msg -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    }
    $null = Start-IgwtGuiJob -Command 'Test-IgwtSystemProtectionEnabled' -Channel 'precheck' -BusyText 'Checking System Protection...' -Context $sets -OnComplete {
        param($out, $errs, $ctx)
        $on = [bool](@($out) | Select-Object -Last 1)
        Complete-IgwtGuiApply -Sets $ctx -SystemProtectionOn $on
    }
}

function Complete-IgwtGuiApply {
    <# .SYNOPSIS The rest of Apply after the background System Protection check: restore point choice, managed items, then the batch. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Sets, [bool]$SystemProtectionOn)
    $sets = $Sets
    $expert = @($sets.Apply | Where-Object { $id = $_; ($script:Gui.Catalog | Where-Object { $_.id -eq $id }).expert })
    $skipRp = $false
    $enableSp = $false
    if (-not $SystemProtectionOn) {
        $a = Show-IgwtGuiMessage -Text "System Protection is off for $env:SystemDrive, so no restore point can be created.`n`nYes: turn System Protection on for $env:SystemDrive and create a restore point.`nNo: continue with the JSON snapshot only.`nCancel: do not apply." -Buttons 'YesNoCancel' -Icon 'Question'
        if ($a -eq 'Cancel') { return }
        if ($a -eq 'Yes') { $enableSp = $true } else { $skipRp = $true }
    }
    $operation = 'Apply'
    # A preset's resets belong to the preset's own session (3.6, DECISIONS T16); turn-offs do not.
    if ($script:Gui.PresetOperation -and $sets.Off.Count -eq 0 -and ($sets.Reset.Count -eq 0 -or [string]$script:Gui.PresetOperation -like 'Preset:*')) { $operation = $script:Gui.PresetOperation }
    $ackManaged = $false
    $authority = @($sets.Apply | Where-Object { $s = $script:Gui.Data.States[[string]$_]; $s -and $s.PSObject.Properties['Authority'] -and $s.Authority })
    if ($authority.Count) {
        $a = Show-IgwtGuiMessage -Text "This PC is managed by a domain or MDM. These policy items can be overridden by your organization: $($authority -join ', ').`n`nYes: change them locally anyway.`nNo: apply everything else and leave them (report-only)." -Buttons 'YesNoCancel' -Icon 'Warning'
        if ($a -eq 'Cancel') { return }
        $ackManaged = ($a -eq 'Yes')
    }
    $params = @{ ApplyIds = $sets.Apply; OffIds = $sets.Off; ResetIds = $sets.Reset; Operation = $operation
        SkipRestorePoint = $skipRp; EnableSystemProtection = $enableSp; AcknowledgeRisk = ($expert.Count -gt 0); AcknowledgeManaged = $ackManaged }
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
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text (Get-IgwtGuiChangeBlockReason -What 'revert changes'); return }
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
    $scan = $script:Gui.CleanScan
    if (-not $scan) {
        Set-IgwtGuiGridRows -Name 'CleanerList' -Rows @()
        Update-IgwtGuiButtons
        return
    }
    $rules = @{}
    # The cleaner rules are read the first time they are needed (faster start).
    if ($null -eq $script:Gui.CleanRules) { $script:Gui.CleanRules = @(Get-IgwtCleanerRules) }
    foreach ($r in $script:Gui.CleanRules) { $rules[[string]$r.id] = $r }
    Set-IgwtGuiGridRows -Name 'CleanerList' -Rows @($scan.Rules | ForEach-Object { New-IgwtGuiCleanerRow -RuleScan $_ -Rule $rules[[string]$_.RuleId] -Selected ([bool]$script:Gui.CleanSelected[[string]$_.RuleId]) })
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
    if (Test-IgwtReadOnly) { Set-IgwtGuiStatus (Get-IgwtGuiChangeBlockReason -What 'delete files'); return }
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
    if (-not $Usage) { Set-IgwtGuiGridRows -Name 'DiskFolderList' -Rows @(); Set-IgwtGuiGridRows -Name 'DiskFileList' -Rows @(); return }
    $maxFolder = [long](($Usage.Folders | Measure-Object Bytes -Maximum).Maximum)
    $maxFile = [long](($Usage.LargestFiles | Measure-Object Bytes -Maximum).Maximum)
    Set-IgwtGuiGridRows -Name 'DiskFolderList' -Rows @($Usage.Folders | ForEach-Object { New-IgwtGuiDiskRow -Path $_.Path -Bytes $_.Bytes -Largest $maxFolder -Extra ("{0:N0} file(s)" -f $_.Files) -IsFolder })
    Set-IgwtGuiGridRows -Name 'DiskFileList' -Rows @($Usage.LargestFiles | ForEach-Object { New-IgwtGuiDiskRow -Path $_.Path -Bytes $_.Bytes -Largest $maxFile -Extra ([datetime]$_.LastWrite).ToString('yyyy-MM-dd') })
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
        if ($p) { Set-IgwtGuiGridRows -Name 'InspectPowerList' -ErrorText "Power plan not readable: $($p.Error)" }
        $c.InspectPowerSummary.Text = $(if ($p) { "Power plan not readable: $($p.Error)" } else { 'Not read yet.' })
        return
    }
    # The grid keeps the selection by setting GUID.
    $all = [bool]$c.InspectPowerAllBox.IsChecked
    Set-IgwtGuiGridRows -Name 'InspectPowerList' -Rows @($p.Settings | Where-Object { $all -or $_.Level -or $_.ChangedFromDefault } | ForEach-Object { New-IgwtGuiPowerRow -Setting $_ })
    $c.InspectPowerSummary.Text = ("Plan: {0}. {1} settings, {2} editable here, {3} differ from the defaults ({4}).{5}" -f $p.SchemeName, @($p.Settings).Count, $p.Editable, $p.Changed, $p.DefaultsFrom,
        $(if (-not $script:Gui.IsAdmin) { ' Read-only: restart as administrator to edit.' } else { '' }))
}

function Update-IgwtGuiPowerDetail {
    <# .SYNOPSIS Fills the editor card for the selected power setting. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = (Get-IgwtGuiGridItem -Name InspectPowerList)
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
    if (-not $k -or ($k.PSObject.Properties['Error'] -and $k.Error)) {
        if ($k) { Set-IgwtGuiGridRows -Name 'InspectKernelList' -ErrorText "Not readable: $($k.Error)" }
        $c.InspectKernelSummary.Text = $(if ($k) { "Not readable: $($k.Error)" } else { 'Not read yet.' })
        return
    }
    $onlyChanged = [bool]$c.InspectKernelChangedBox.IsChecked
    Set-IgwtGuiGridRows -Name 'InspectKernelList' -Rows @(foreach ($key in @($k.Keys)) { foreach ($v in @($key.Values)) { if (-not $onlyChanged -or $v.Status -ne 'Default') { New-IgwtGuiKernelRow -Value $v -Key ([string]$key.Name) } } })
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
        Set-IgwtGuiGridRows -Name 'InspectIrqList' -Rows @($irq.Devices | ForEach-Object { New-IgwtGuiIrqRow -Device $_ })
        $c.InspectIrqSummary.Text = "$($irq.MessageSignaled) device(s) use message-signaled interrupts, $($irq.LineBased) line-based. $($irq.Note)"
    } elseif ($irq) { $c.InspectIrqSummary.Text = "Not readable: $($irq.Error)"; Set-IgwtGuiGridRows -Name 'InspectIrqList' -ErrorText "Not readable: $($irq.Error)" }
    $nic = $Inspection.Network
    if ($nic -and -not ($nic.PSObject.Properties['Error'] -and $nic.Error)) { $c.InspectNicList.ItemsSource = @($nic.Adapters | ForEach-Object { New-IgwtGuiNicRow -Adapter $_ }) }
    $c.InspectCrashText.Text = Format-IgwtInspection -Inspection ([pscustomobject]@{ Elevated = $true; Timer = $Inspection.Timer; Crash = $Inspection.Crash })
}

function Start-IgwtGuiInspect {
    <# .SYNOPSIS Runs every inspector in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtInspection' -Channel 'inspect' -BusyText 'Reading power plan, interrupts, network queues and kernel settings (read-only)...' -OnComplete {
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
    $row = (Get-IgwtGuiGridItem -Name InspectPowerList)
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
    # The dry run calls powercfg: it runs in the background, the confirmation follows (audit E2).
    $null = Start-IgwtGuiJob -Command 'Get-IgwtPowerSettingChangePlan' -Parameters $planParams -Channel 'plan' -BusyText 'Checking the change (dry run)...' -Context @{ Row = $row; Params = $params } -OnComplete {
        param($out, $errs, $ctx)
        $plan = @($out) | Select-Object -Last 1
        if (-not $plan) { Show-IgwtGuiError -Message "This change is refused: $(@($errs)[0])" -Context 'Power'; return }
        if (-not $plan.HasChange) { Set-IgwtGuiStatus 'Already set; nothing to change.'; return }
        $row = $ctx.Row
        $text = "Change $($row.Alias) in the active plan?`n`n$($plan.Change)`n`n$($row.Setting.Description)`n`nExpert setting. A snapshot is written first; Undo restores it."
        if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - power plan' -Buttons 'YesNo' -Icon 'Warning') -ne 'Yes') { return }
        $null = Start-IgwtGuiJob -Command 'Invoke-IgwtPowerSettingChange' -Parameters $ctx.Params -Blocking -BusyText "Changing $($row.Alias) (snapshot first)..." -OnComplete {
            param($o2, $e2)
            $res = @($o2) | Select-Object -Last 1
            if (@($e2).Count) { Show-IgwtGuiError -Message "The change was not made: $(@($e2)[0])" -Context 'Power' }
            elseif ($res -and $res.Changes -and $res.Snapshot) { Show-IgwtGuiToast -Text ("{0}: {1}." -f @($res.Results)[0].Target, @($res.Results)[0].Result) -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiSnapshotUndo -Snapshot $snap -Then { Start-IgwtGuiInspect } } -ActionArgument ([string]$res.Snapshot) }
            Start-IgwtGuiInspect
        }
    }
}

function Invoke-IgwtGuiSnapshotUndo {
    <# .SYNOPSIS Undo in a toast: reverts one snapshot in the background, then runs -Then (a refresh). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Snapshot, [scriptblock]$Then)
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtRevert' -Parameters @{ SnapshotPath = $Snapshot } -Blocking -BusyText 'Undoing the change...' -Context $Then -OnComplete {
        param($out, $errs, $then)
        $res = @($out) | Select-Object -Last 1
        $bad = @($(if ($res) { @($res.Results | Where-Object Result -EQ 'Failed') }))
        if (@($errs).Count -or $bad.Count) { Show-IgwtGuiError -Message "Undo failed: $(if (@($errs).Count) { @($errs)[0] } else { $bad[0].Message })" }
        else { Show-IgwtGuiToast -Text 'The change was undone.' -Tone Info }
        if ($then) { & $then }
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

function Get-IgwtGuiChangeBlockReason {
    <# .SYNOPSIS Why changes are off in this window ('' when they are allowed): read-only mode or no administrator rights. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$What = 'make changes')
    if ((Test-IgwtReadOnly) -or ($script:Gui -and $script:Gui.ReadOnly)) { return "Read-only mode: this window cannot $What. Start iG Windows Tuner without -ReadOnly to $What." }
    if ($script:Gui -and -not $script:Gui.IsAdmin) { return "Restart as administrator to $What." }
    return ''
}

function Get-IgwtGuiGridItem {
    <# .SYNOPSIS The first selected row of a page SmartGrid ($null when none). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $g = $script:Gui.Grids[$Name]
    if (-not $g) { return $null }
    return $g.C.Grid.SelectedItem
}

function Initialize-IgwtGuiManageGrids {
    <# .SYNOPSIS SmartGrids for the Services, Scheduled tasks, Apps and Persistence tabs. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $onSelect = { param($grid, $rows) $null = $grid, $rows; Update-IgwtGuiManageDetail }
    $refresh = { param($grid) $null = $grid; $script:Gui.Manage = $null; Start-IgwtGuiManageRefresh }
    $script:Gui.Grids.Service = New-IgwtSmartGrid -Id 'manage.services' -Noun 'services' -RowKey 'Key' -SearchPlaceholder 'Search services' -OnSelectionChanged $onSelect -OnRefresh $refresh `
        -Columns @(
        @{ Key = 'Title'; Header = 'Service'; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'Name'; Header = 'Name'; Width = 150; Template = 'Mono' }
        @{ Key = 'Status'; Header = 'Status'; Width = 100 }
        @{ Key = 'Startup'; Header = 'Startup type'; Width = 140 }
        @{ Key = 'Rating'; Header = 'Rating'; Width = 170; Template = 'Status'; SortKey = 'RatingKey' }
        @{ Key = 'Account'; Header = 'Runs as'; Width = 150; Visible = $false }
        @{ Key = 'Description'; Header = 'Description'; Width = 300; Visible = $false }
    ) -Chips @(
        @{ Id = 'running'; Label = 'Running'; Group = 'status'; Field = 'Status'; Values = @('Running') }
        @{ Id = 'stopped'; Label = 'Stopped'; Group = 'status'; Field = 'Status'; Values = @('Stopped') }
        @{ Id = 'auto'; Label = 'Automatic'; Group = 'startup'; Field = 'Startup'; Values = @('Automatic', 'AutomaticDelayed') }
        @{ Id = 'manual'; Label = 'Manual'; Group = 'startup'; Field = 'Startup'; Values = @('Manual') }
        @{ Id = 'disabled'; Label = 'Disabled'; Group = 'startup'; Field = 'Startup'; Values = @('Disabled') }
        @{ Id = 'thirdparty'; Label = 'Installed by apps'; Group = 'rating'; Field = 'RatingKey'; Values = @('ThirdParty'); Tip = 'Services that apps installed (not part of Windows)' }
        @{ Id = 'protected'; Label = 'Protected'; Group = 'rating'; Field = 'RatingKey'; Values = @('Protected'); Tip = 'Core Windows, security, update, audio, network, GPU and anti-cheat services: changes are refused' }
    )
    $script:Gui.Grids.Task = New-IgwtSmartGrid -Id 'manage.tasks' -Noun 'tasks' -RowKey 'Key' -SearchPlaceholder 'Search tasks' -OnSelectionChanged $onSelect -OnRefresh $refresh `
        -Columns @(
        @{ Key = 'Title'; Header = 'Task'; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'Path'; Header = 'Folder'; Width = 240 }
        @{ Key = 'Publisher'; Header = 'Publisher'; Width = 120 }
        @{ Key = 'State'; Header = 'State'; Width = 130; Template = 'Status' }
        @{ Key = 'Author'; Header = 'Author'; Width = 160; Visible = $false }
        @{ Key = 'Action'; Header = 'Runs'; Width = 300; Visible = $false; Template = 'Mono' }
    ) -Chips @(
        @{ Id = 'thirdparty'; Label = 'Third-party'; Group = 'pub'; Field = 'Publisher'; Values = @('Third-party') }
        @{ Id = 'microsoft'; Label = 'Microsoft'; Group = 'pub'; Field = 'Publisher'; Values = @('Microsoft') }
        @{ Id = 'disabled'; Label = 'Disabled'; Group = 'state'; Field = 'RawState'; Values = @('Disabled') }
        @{ Id = 'enabled'; Label = 'Ready or running'; Group = 'state'; Field = 'RawState'; Values = @('Ready', 'Running') }
    )
    $script:Gui.Grids.App = New-IgwtSmartGrid -Id 'manage.apps' -Noun 'apps' -RowKey 'Key' -SearchPlaceholder 'Search apps' -OnSelectionChanged $onSelect -OnRefresh $refresh `
        -Columns @(
        @{ Key = 'Title'; Header = 'App'; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'Type'; Header = 'Type'; Width = 80 }
        @{ Key = 'Publisher'; Header = 'Publisher'; Width = 180 }
        @{ Key = 'Version'; Header = 'Version'; Width = 120 }
        @{ Key = 'Size'; Header = 'Size'; Width = 90; Kind = 'Number'; SortKey = 'SizeMB' }
        @{ Key = 'Status'; Header = 'Status'; Width = 130; Template = 'Status' }
    ) -Chips @(
        @{ Id = 'appx'; Label = 'Inbox and Store'; Group = 'type'; Field = 'Type'; Values = @('Appx') }
        @{ Id = 'win32'; Label = 'Win32'; Group = 'type'; Field = 'Type'; Values = @('Win32') }
        @{ Id = 'removable'; Label = 'Removable'; Group = 'status'; Field = 'Status'; Values = @('Removable') }
    )
    $script:Gui.Grids.Persist = New-IgwtSmartGrid -Id 'manage.persistence' -Noun 'entries' -RowKey 'Key' -SearchPlaceholder 'Search autostart entries' -OnSelectionChanged $onSelect -OnRefresh $refresh `
        -Columns @(
        @{ Key = 'Title'; Header = 'Entry'; MinWidth = 160; Tip = 'Tip' }
        @{ Key = 'Category'; Header = 'Category'; Width = 130 }
        @{ Key = 'Severity'; Header = 'Severity'; Width = 110; Template = 'Status'; Kind = 'Number'; SortKey = 'SeverityKey' }
        @{ Key = 'Signature'; Header = 'Signature'; Width = 190 }
        @{ Key = 'Enabled'; Header = 'Enabled'; Width = 90 }
        @{ Key = 'Command'; Header = 'Command'; Width = 280; Template = 'Mono' }
        @{ Key = 'Location'; Header = 'Location'; Width = 260; Visible = $false; Template = 'Mono' }
    ) -Chips @(
        @{ Id = 'warn'; Label = 'Warnings'; Group = 'sev'; Field = 'Severity'; Values = @('Warning') }
        @{ Id = 'review'; Label = 'To review'; Group = 'sev'; Field = 'Severity'; Values = @('Review') }
        @{ Id = 'unsigned'; Label = 'Not signed'; Group = 'sig'; Field = 'Signature'; Values = @('Not signed') }
    )
    # Needs attention first by default.
    if (-not @($script:Gui.Grids.Persist.Sort).Count) { Set-IgwtGridSort -Grid $script:Gui.Grids.Persist -Key 'Severity' -NoSave }
    $c.ManageServiceGridHost.Content = $script:Gui.Grids.Service.Root
    $c.ManageTaskGridHost.Content = $script:Gui.Grids.Task.Root
    $c.ManageAppGridHost.Content = $script:Gui.Grids.App.Root
    $c.ManagePersistGridHost.Content = $script:Gui.Grids.Persist.Root
}

function Update-IgwtGuiManageLists {
    <# .SYNOPSIS Fills the Manage grids and the hosts viewer from the cached data. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $m = $script:Gui.Manage
    if (-not $m) { return }
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] }
    $err = { param($o) if (& $has $o 'Error') { "Not readable: $($o.Error)" } else { 'Not readable.' } }
    $grids = $script:Gui.Grids
    if (& $has $m.Services 'Services') {
        Set-IgwtGridRows -Grid $grids.Service -Rows @($m.Services.Services | ForEach-Object { New-IgwtGuiServiceRow -Service $_ })
        $k = $m.Services.Counts
        $c.ManageServiceSummary.Text = "$($k.Total) services, $($k.Running) running, $($k.Protected) protected, $($k.ThirdParty) installed by apps. Catalogued services are managed by catalog items with documented reasons; prefer those."
    } else { $c.ManageServiceSummary.Text = & $err $m.Services; Set-IgwtGridState -Grid $grids.Service -State Error -Message (& $err $m.Services) }
    if (& $has $m.Tasks 'Tasks') {
        Set-IgwtGridRows -Grid $grids.Task -Rows @($m.Tasks.Tasks | ForEach-Object { New-IgwtGuiTaskRow -Task $_ })
        $c.ManageTaskSummary.Text = "$($m.Tasks.Counts.Total) tasks, $($m.Tasks.Counts.Disabled) disabled, $($m.Tasks.Counts.ThirdParty) third-party. $($m.Tasks.Note)"
    } else { $c.ManageTaskSummary.Text = & $err $m.Tasks; Set-IgwtGridState -Grid $grids.Task -State Error -Message (& $err $m.Tasks) }
    if (& $has $m.Apps 'Appx') {
        Set-IgwtGridRows -Grid $grids.App -Rows @(@($m.Apps.Appx | ForEach-Object { New-IgwtGuiAppRow -App $_ -Kind Appx }) + @($m.Apps.Win32 | ForEach-Object { New-IgwtGuiAppRow -App $_ -Kind Win32 }))
        $c.ManageAppSummary.Text = "$(@($m.Apps.Appx).Count) inbox/Store apps ($(@($m.Apps.Appx | Where-Object { $_.CanRemove }).Count) removable) and $(@($m.Apps.Win32).Count) Win32 apps. $($m.Apps.Note)"
    } else { $c.ManageAppSummary.Text = & $err $m.Apps; Set-IgwtGridState -Grid $grids.App -State Error -Message (& $err $m.Apps) }
    if (& $has $m.Persistence 'Entries') {
        Set-IgwtGridRows -Grid $grids.Persist -Rows @($m.Persistence.Entries | ForEach-Object { New-IgwtGuiPersistenceRow -Entry $_ })
        $k = $m.Persistence.Counts
        $c.ManagePersistSummary.Text = "$($k.Total) entries (Microsoft-signed services, drivers and tasks hidden), $($k.Warn) warning(s), $($k.Review) to review. $($m.Persistence.Note)"
    } else { $c.ManagePersistSummary.Text = & $err $m.Persistence; Set-IgwtGridState -Grid $grids.Persist -State Error -Message (& $err $m.Persistence) }
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
    $s = Get-IgwtGuiGridItem -Name Service
    if ($s) {
        $x = $s.Source
        $items = @($x.CatalogItems | ForEach-Object { "$($_.Id)$(if (@($_.Presets).Count) { " (in $(@($_.Presets) -join ', '))" })" })
        $c.ManageServiceDetail.Text = "$($x.DisplayName) ($($x.Name)): $($x.State), $($x.StartupType), runs as $($x.Account).$nl$($x.Description)$nl$($x.Advice)" +
        $(if (@($x.DependsOn).Count) { "${nl}Depends on: $(@($x.DependsOn) -join ', ')" }) + $(if (@($x.Dependents).Count) { "${nl}Needed by: $(@($x.Dependents) -join ', ')" }) +
        $(if ($items.Count) { "${nl}Catalog items: $($items -join '; ')" })
        $c.ManageServiceStartBox.SelectedItem = $(if ($x.StartupType -in 'Automatic', 'AutomaticDelayed', 'Manual', 'Disabled') { $x.StartupType } else { $null })
    } else { $c.ManageServiceDetail.Text = 'Select a service.' }
    $t = Get-IgwtGuiGridItem -Name Task
    $c.ManageTaskDetail.Text = $(if ($t) { "$($t.Source.Path) ($($t.Source.State), author $($t.Source.Author))$nl$($t.Source.Description)${nl}Runs: $($t.Source.Action)$(if ($t.Source.Protected) { "${nl}Protected: security, update, recovery or anti-cheat task." })" } else { 'Select a task.' })
    $a = Get-IgwtGuiGridItem -Name App
    $c.ManageAppDetail.Text = $(if ($a) { "$($a.Title) $($a.Subtitle)$nl$($a.Tip)" } else { 'Select an app.' })
    $p = Get-IgwtGuiGridItem -Name Persist
    if ($p) {
        $x = $p.Source
        $how = switch ([string]$x.ActionKind) { 'StartupEntry' { 'Disable turns the startup entry off (StartupApproved), like Task Manager.' } 'Service' { 'Disable sets the service startup type to Disabled.' } 'Task' { 'Disable disables the scheduled task.' } default { 'No documented disable mechanism here; investigate with Microsoft Defender or Autoruns.' } }
        $c.ManagePersistDetail.Text = "[$($x.Severity)] $($x.Category): $($x.Name)${nl}Location: $($x.Location)${nl}Command: $($x.Command)${nl}File: $($x.File)  Signature: $($x.Signature) $($x.Signer)$(if ($x.Note) { "$nl$($x.Note)" })$nl$how"
    } else { $c.ManagePersistDetail.Text = 'Select an entry.' }
    Update-IgwtGuiButtons
}

function Start-IgwtGuiManageRefresh {
    <# .SYNOPSIS Reads the Manage data in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    foreach ($n in 'Service', 'Task', 'App', 'Persist') { if ($script:Gui.Grids[$n]) { Set-IgwtGridState -Grid $script:Gui.Grids[$n] -State Loading } }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiManageData' -Channel 'manage' -BusyText 'Reading services, tasks, apps, persistence entries and firewall rules (read-only)...' -OnComplete {
        param($out, $errs)
        $script:Gui.Manage = @($out) | Select-Object -Last 1
        if (-not $script:Gui.Manage) {
            $msg = $(if (@($errs).Count) { [string]@($errs)[0] } else { 'No data was returned.' })
            foreach ($n in 'Service', 'Task', 'App', 'Persist') { Set-IgwtGridState -Grid $script:Gui.Grids[$n] -State Error -Message $msg }
            return
        }
        Update-IgwtGuiManageLists
        Update-IgwtGuiManageDetail
        Set-IgwtGuiStatus 'Manage data updated.'
    }
}

function Invoke-IgwtGuiManagedChange {
    <# .SYNOPSIS Validates a management change (protection rules), asks for confirmation, then applies it in the worker (snapshot first). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][string]$Value, [switch]$Provisioned)
    if (-not $script:Gui.IsAdmin -or (Test-IgwtReadOnly)) { Set-IgwtGuiStatus 'Changes need administrator rights and are off in read-only mode.'; return }
    $params = @{ Kind = $Kind; Target = $Target; Value = $Value }
    if ($Provisioned) { $params.Provisioned = $true }
    # The plan queries services and packages: it runs in the background, the confirmation follows.
    $null = Start-IgwtGuiJob -Command 'Get-IgwtManagedChangePlan' -Parameters $params -Channel 'plan' -BusyText 'Checking the change...' -Context $params -OnComplete {
        param($out, $errs, $ctx)
        $plan = @($out) | Select-Object -Last 1
        if (-not $plan) { Show-IgwtGuiError -Message "This change is refused: $(@($errs)[0])" -Context 'Manage'; return }
        if (-not $plan.HasChange) { Set-IgwtGuiStatus 'Already set; nothing to change.'; return }
        $text = "$($plan.Change)`n`nReversible: $($plan.Reversible). A snapshot is written first; Undo restores it.`n`nContinue?"
        if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - manage' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
        $null = Start-IgwtGuiJob -Command 'Invoke-IgwtManagedChange' -Parameters $ctx -Blocking -BusyText "$($ctx.Kind) $($ctx.Target) -> $($ctx.Value) (snapshot first)..." -OnComplete {
            param($o2, $e2)
            $res = @($o2) | Select-Object -Last 1
            if (@($e2).Count) { Show-IgwtGuiError -Message "The change was not made: $(@($e2)[0])" -Context 'Manage' }
            elseif ($res -and $res.Changes) {
                $r = @($res.Results)[0]
                if ($r.Result -eq 'Failed') { Show-IgwtGuiError -Message "$($r.Change): $($r.Message)" -Context 'Manage' }
                else { Show-IgwtGuiToast -Text "$($r.Change)$(if ($r.Message) { ". $($r.Message)" })" -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiSnapshotUndo -Snapshot $snap -Then { $script:Gui.Manage = $null; Start-IgwtGuiManageRefresh } } -ActionArgument ([string]$res.Snapshot) }
            }
            $script:Gui.Manage = $null
            Start-IgwtGuiManageRefresh
        }
    }
}

function Invoke-IgwtGuiPersistenceDisable {
    <# .SYNOPSIS Disables the selected persistence entry through its documented mechanism. #>
    [CmdletBinding()]
    param()
    $row = Get-IgwtGuiGridItem -Name Persist
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
        Set-IgwtGuiDiagCards -Diagnostics $d
        Set-IgwtGuiGridRows -Name 'DiagEventList' -Rows (Get-IgwtGuiDiagEventRows -Diagnostics $d)
        $dr = $d.Drivers
        if ($dr -and $dr.PSObject.Properties['Drivers']) {
            Set-IgwtGuiGridRows -Name 'DiagDriverList' -Rows @($dr.Drivers | ForEach-Object {
                    New-IgwtGuiManageRow -Title $_.Device -Subtitle "$($_.Provider) $($_.Version), $($_.Date)" -Badge $_.Class -State $(if ($_.Flag) { $_.Flag } else { 'OK' }) -Tone $(switch ($_.Flag) { 'Unsigned' { 'Fail' } 'Old' { 'Warn' } default { 'Pass' } }) `
                        -Tip "Signer: $($_.Signer)${nl}INF: $($_.Inf)" -Source $_ -Key "$($_.Inf)|$($_.Device)" -Extra @{ Provider = [string]$_.Provider; Version = [string]$_.Version; DriverDate = [string]$_.Date; Signer = [string]$_.Signer }
                })
            $c.DiagDriverSummary.Text = "$($dr.Counts.Total) non-Microsoft drivers, $($dr.Counts.Unsigned) unsigned, $($dr.Counts.Old) older than three years. $($dr.Note)"
        } elseif ($dr) { $c.DiagDriverSummary.Text = "Not readable: $($dr.Error)"; Set-IgwtGuiGridRows -Name 'DiagDriverList' -ErrorText "Not readable: $($dr.Error)" }
    } elseif ($d) {
        Set-IgwtGuiDiagCards -Diagnostics $d
        foreach ($n in 'DiagEventList', 'DiagDriverList') { Set-IgwtGuiGridRows -Name $n -ErrorText "Not readable: $($d.Error)" }
    }
    $u = $Data.Updates
    if ($u -and $u.PSObject.Properties['Services']) {
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($s in $u.Services) { $lines.Add(('{0,-13} {1,-8} {2}' -f $s.Name, $s.Status, $s.StartType)) }
        $lines.Add("Pending restart: $(if (@($u.PendingRestart).Count) { $u.PendingRestart -join ', ' } else { 'no' })")
        $lines.Add("Policies: $(if (@($u.Policies).Count) { (@($u.Policies | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ') } else { 'none (Windows defaults)' })")
        $lines.Add("Last successful update (not counting Defender definitions): $(if ($u.LastSuccess) { Format-IgwtGuiTime -Value $u.LastSuccess } else { 'unknown' })")
        if ($u.Error) { $lines.Add($u.Error) }
        foreach ($a in $u.Advice) { $lines.Add("-> $a") }
        $lines.Add($u.Note)
        Set-IgwtGuiGridRows -Name 'DiagUpdateList' -Rows @($u.History | Where-Object { $_ } | ForEach-Object { New-IgwtGuiUpdateHistoryRow -Entry $_ })
        $c.DiagUpdateText.Text = $lines.ToArray() -join $nl
    } elseif ($u) { $c.DiagUpdateText.Text = "Not readable: $($u.Error)"; Set-IgwtGuiGridRows -Name 'DiagUpdateList' -ErrorText "Not readable: $($u.Error)" }
    $ad = $Data.Adapters
    if ($ad -and $ad.PSObject.Properties['Adapters']) {
        Set-IgwtGuiGridRows -Name 'DiagAdapterList' -Rows @(foreach ($a in $ad.Adapters) { foreach ($p in @($a.Properties)) {
                    New-IgwtGuiManageRow -Title "$($p.DisplayName): $($p.Value)" -Subtitle $p.Description -Badge $a.Name -State $(if ($p.ChangedFromDefault) { 'Changed' } else { 'Default' }) -Tone $(if ($p.ChangedFromDefault) { 'Warn' } else { 'Muted' }) `
                        -Tip "$($p.Keyword) = $($p.RegistryValue) (default $($p.Default))$(if ($p.Allowed) { "${nl}Allowed: $($p.Allowed)" })$(if ($p.Range) { "${nl}Range: $($p.Range)" })${nl}$($p.Description)" -Source $p `
                        -Key "$($a.Name)|$($p.Keyword)" -Extra @{ Property = [string]$p.DisplayName; Value = [string]$p.Value; DefaultValue = [string]$p.Default; Keyword = [string]$p.Keyword }
                } })
        $c.DiagAdapterSummary.Text = "Adapter properties ($(@($ad.Adapters | ForEach-Object { "$($_.Name), $($_.LinkSpeed)" }) -join '; ')). $($ad.Note)"
    } elseif ($ad) { $c.DiagAdapterSummary.Text = "Adapter properties not readable: $($ad.Error)"; Set-IgwtGuiGridRows -Name 'DiagAdapterList' -ErrorText "Not readable: $($ad.Error)" }
}

function Start-IgwtGuiDiagRefresh {
    <# .SYNOPSIS Reads the Diagnostics data in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiDiagnosticsData' -Channel 'diag' -BusyText 'Sampling DPC/ISR and reading reliability, crashes, boot, drivers and Windows Update (read-only)...' -OnComplete {
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
    $c.NetEmptyCard.Visibility = 'Collapsed'; $c.NetResultPanel.Visibility = 'Visible'
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

function Initialize-IgwtGuiCompliance {
    <# .SYNOPSIS The Group Policy > Compliance grid and its button (3.3 R1). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $grid = New-IgwtSmartGrid -Id 'policy.compliance' -Noun 'settings' -RowKey 'Key' -SearchPlaceholder 'Search settings' -SelectionMode Single `
        -EmptyTitle 'No baseline compared yet' -EmptyText 'Press "Compare a baseline..." and pick a baseline or GPO backup folder.' -Columns @(
        @{ Key = 'StatusCol'; Header = 'Status'; Width = 110; Template = 'Status'; SortKey = 'StatusRank' }
        @{ Key = 'Setting'; Header = 'Setting'; MinWidth = 260; Tip = 'Setting' }
        @{ Key = 'Area'; Header = 'Area'; Width = 170 }
        @{ Key = 'Baseline'; Header = 'Baseline'; Width = 150; Template = 'Mono' }
        @{ Key = 'Effective'; Header = 'This PC'; Width = 150; Template = 'Mono' }
        @{ Key = 'LocalGpo'; Header = 'Local GPO'; Width = 130; Template = 'Mono'; Visible = $false }
        @{ Key = 'Gpo'; Header = 'GPO'; Width = 220 }
    ) -Chips @(
        @{ Id = 'differs'; Label = 'Differs'; Group = 's'; Field = 'Status'; Values = @('Differs') }
        @{ Id = 'notset'; Label = 'Not set'; Group = 's'; Field = 'Status'; Values = @('NotSet') }
        @{ Id = 'match'; Label = 'Matches'; Group = 's'; Field = 'Status'; Values = @('Match') }
        @{ Id = 'other'; Label = 'Blocked, unsupported, unknown'; Group = 's'; Field = 'Status'; Values = @('Blocked', 'Unsupported', 'Unknown') }
    )
    $script:Gui.Grids.Compliance = $grid
    $script:Gui.C.PolComplianceHost.Content = $grid.Root
    if (-not @($grid.Sort).Count) { Set-IgwtGridSort -Grid $grid -Key 'StatusCol' -NoSave; Set-IgwtGridSort -Grid $grid -Key 'Setting' -Add -NoSave }
    Set-IgwtGridRows -Grid $grid -Rows @()
    Register-IgwtGuiHandler -Control $script:Gui.C.PolBaselineButton -Event 'Click' -Handler { Start-IgwtGuiCompliance }
}

function New-IgwtGuiComplianceRow {
    <# .SYNOPSIS SmartGrid row for one baseline comparison row (Compare-IgwtPolicyBaseline). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row, [int]$Index)
    $rank = @{ Differs = 0; NotSet = 1; Unknown = 2; Blocked = 3; Unsupported = 4; Match = 5 }
    $st = [string]$Row.Status
    $r = [ordered]@{ Key = "$Index|$($Row.Ref)"; Status = $st; StatusRank = $(if ($rank.ContainsKey($st)) { $rank[$st] } else { 9 }); Setting = [string]$Row.Setting; Area = [string]$Row.Area
        Baseline = [string]$Row.Baseline; Effective = [string]$Row.Effective; LocalGpo = [string]$Row.LocalGpo; Gpo = [string]$Row.Gpo }
    $text = switch ($st) { 'NotSet' { 'Not set' } default { $st } }
    Add-IgwtGuiStatusField -Row $r -Name 'StatusCol' -Text $text -Tone $(switch ($st) { 'Match' { 'Pass' } 'Differs' { 'Warn' } 'NotSet' { 'Warn' } 'Blocked' { 'Fail' } default { 'Text' } })
    [pscustomobject]$r
}

function Start-IgwtGuiCompliance {
    <# .SYNOPSIS Asks for a baseline folder and compares it with this PC in the background (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only comparison.')]
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) {
        Add-Type -AssemblyName System.Windows.Forms
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Pick a security baseline or GPO backup folder (for example the GPOs folder of a Microsoft Security Baseline).'
        if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $Path = $dlg.SelectedPath
    }
    $grid = $script:Gui.Grids.Compliance
    Set-IgwtGridState -Grid $grid -State Loading
    $script:Gui.C.PolBaselineText.Text = "Comparing $Path with this PC (read-only)..."
    $null = Start-IgwtGuiJob -Command 'Get-IgwtPolicyBaselineComparison' -Parameters @{ Path = $Path } -Channel 'compliance' -BusyText 'Comparing the baseline with this PC (read-only)...' -OnComplete {
        param($out, $errs)
        $rows = @($out | Where-Object { $_ })
        if (-not $rows.Count -and @($errs).Count) { Set-IgwtGridState -Grid $script:Gui.Grids.Compliance -State Error -Message ([string]@($errs)[0]); $script:Gui.C.PolBaselineText.Text = "Not compared: $(@($errs)[0])"; return }
        $i = 0
        Set-IgwtGridRows -Grid $script:Gui.Grids.Compliance -Rows @(foreach ($r in $rows) { $i++; New-IgwtGuiComplianceRow -Row $r -Index $i })
        $n = { param($s) @($rows | Where-Object { [string]$_.Status -eq $s }).Count }
        $script:Gui.C.PolBaselineText.Text = "$($rows.Count) settings: $(& $n 'Match') match, $(& $n 'Differs') differ, $(& $n 'NotSet') not set, $(& $n 'Unknown') unknown (some values need administrator rights). Read-only; nothing was changed."
    }
}

function Get-IgwtGuiNetHistoryPath {
    <# .SYNOPSIS The per-user network test history (the app's own file, next to the view state). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Split-Path -Parent (Get-IgwtGuiStatePath)) 'network-history.json')
}

function ConvertTo-IgwtGuiNetSummary {
    <# .SYNOPSIS The numbers of one network test result worth keeping (no addresses or adapter names). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result)
    $s = $Result.Score; $st = $(if ($Result.Internet) { $Result.Internet.Stats } else { $null })
    [pscustomobject]@{
        Time = ([datetime]$Result.Generated).ToUniversalTime().ToString('o'); Duration = [string]$Result.Duration; Grade = [string]$s.Grade; Score = $s.Score; Mos = $s.Mos
        PingMs = $(if ($st) { $st.MedianMs } else { $null }); JitterMs = $(if ($st) { $st.JitterMs } else { $null }); LossPercent = $(if ($st) { $st.LossPercent } else { $null })
        Stability = [string]$s.Stability; Bufferbloat = $(if ($Result.Bufferbloat) { [string]$Result.Bufferbloat.Grade } else { '' }); Access = [string]$Result.TypeGuess.Access
    }
}

function Add-IgwtGuiNetHistory {
    <# .SYNOPSIS Keeps the summary of a network test (the last 50) in the per-user history file. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the app''s own per-user history file only (like the view state).')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result, [string]$Path = (Get-IgwtGuiNetHistoryPath))
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($h in @(Get-IgwtGuiNetHistory -Path $Path)) { $list.Add($h) }
    $list.Insert(0, (ConvertTo-IgwtGuiNetSummary -Result $Result))
    while ($list.Count -gt 50) { $list.RemoveAt($list.Count - 1) }
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    [System.IO.File]::WriteAllText($Path, ([ordered]@{ schemaVersion = 1; kind = 'igwtNetworkHistory'; runs = $list.ToArray() } | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-IgwtGuiNetHistory {
    <# .SYNOPSIS The saved network test summaries, newest first (empty when there is no history). #>
    [CmdletBinding()]
    param([string]$Path = (Get-IgwtGuiNetHistoryPath))
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try { return @((Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json).runs | Where-Object { $_ }) } catch { Write-Verbose "Network history not readable: $($_.Exception.Message)"; return @() }
}

function New-IgwtGuiNetHistoryRows {
    <# .SYNOPSIS SmartGrid rows of the history with the change against the run before (lower ping and jitter are better). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds in-memory rows only.')]
    [CmdletBinding()]
    param([object[]]$Runs = @())
    $runs = @($Runs | Where-Object { $_ })
    $delta = { param($now, $prev, $unit) if ($null -eq $now -or $null -eq $prev -or "$now" -eq '' -or "$prev" -eq '') { '' } else { $d = [math]::Round([double]$now - [double]$prev, 1); if ($d -eq 0) { "same" } elseif ($d -gt 0) { "+$d $unit" } else { "$d $unit" } } }
    for ($i = 0; $i -lt $runs.Count; $i++) {
        $r = $runs[$i]; $p = $(if ($i + 1 -lt $runs.Count) { $runs[$i + 1] } else { $null })
        $t = $null; try { $t = [datetime]::Parse([string]$r.Time, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime() } catch { $t = $null }
        $row = [ordered]@{
            Key = "$i|$($r.Time)"; When = $(if ($t) { $t.ToString('yyyy-MM-dd HH:mm') } else { [string]$r.Time }); Duration = [string]$r.Duration; Grade = [string]$r.Grade; Score = $r.Score
            Ping = $(if ($null -ne $r.PingMs) { "$($r.PingMs) ms" } else { '' }); PingSort = $(if ($null -ne $r.PingMs) { [double]$r.PingMs } else { 99999 })
            Jitter = $(if ($null -ne $r.JitterMs) { "$($r.JitterMs) ms" } else { '' }); Loss = $(if ($null -ne $r.LossPercent) { "$($r.LossPercent) %" } else { '' })
            Stability = "$($r.Stability) / $(if ($r.Bufferbloat) { $r.Bufferbloat } else { '?' })"
            PingChange = $(if ($p) { & $delta $r.PingMs $p.PingMs 'ms' } else { 'first run' }); JitterChange = $(if ($p) { & $delta $r.JitterMs $p.JitterMs 'ms' } else { '' })
            Access = [string]$r.Access
        }
        Add-IgwtGuiStatusField -Row $row -Name 'GradeCol' -Text ([string]$r.Grade) -Tone (Get-IgwtGuiGradeTone -Grade ([string]$r.Grade))
        [pscustomobject]$row
    }
}

function Update-IgwtGuiNetHistory {
    <# .SYNOPSIS Fills the Earlier runs grid of the Network Test page. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $grid = $script:Gui.Grids.NetHistory
    if (-not $grid) {
        $grid = New-IgwtSmartGrid -Id 'nettest.history' -Noun 'runs' -RowKey 'Key' -SearchPlaceholder 'Search runs' -SelectionMode Single `
            -EmptyTitle 'No earlier runs' -EmptyText 'Each network test you run is kept here so you can compare before and after a change.' -Columns @(
            @{ Key = 'When'; Header = 'When'; Width = 140; Kind = 'Date' }
            @{ Key = 'GradeCol'; Header = 'Grade'; Width = 80; Template = 'Status'; SortKey = 'Score' }
            @{ Key = 'Ping'; Header = 'Ping'; Width = 90; SortKey = 'PingSort' }
            @{ Key = 'PingChange'; Header = 'Ping vs before'; Width = 120 }
            @{ Key = 'Jitter'; Header = 'Jitter'; Width = 90 }
            @{ Key = 'JitterChange'; Header = 'Jitter vs before'; Width = 120 }
            @{ Key = 'Loss'; Header = 'Loss'; Width = 80 }
            @{ Key = 'Stability'; Header = 'Stability / load'; Width = 130 }
            @{ Key = 'Duration'; Header = 'Duration'; Width = 100 }
            @{ Key = 'Access'; Header = 'Access'; Width = 140; Visible = $false }
        ) -Chips @(
            @{ Id = 'worse'; Label = 'Ping got worse'; Group = 'chg'; Test = { param($row) ([string]$row.PingChange).StartsWith('+') } }
            @{ Id = 'better'; Label = 'Ping got better'; Group = 'chg'; Test = { param($row) ([string]$row.PingChange).StartsWith('-') } }
        )
        $script:Gui.Grids.NetHistory = $grid
        $script:Gui.C.NetHistoryHost.Content = $grid.Root
        if (-not @($grid.Sort).Count) { Set-IgwtGridSort -Grid $grid -Key 'When' -NoSave; Set-IgwtGridSort -Grid $grid -Key 'When' -NoSave }
    }
    Set-IgwtGridRows -Grid $grid -Rows @(New-IgwtGuiNetHistoryRows -Runs @(Get-IgwtGuiNetHistory))
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
        if (-not $res.Error) { try { Add-IgwtGuiNetHistory -Result $res } catch { Write-IgwtLog -Level Warn -Message "Network history not saved: $($_.Exception.Message)" } }
        Update-IgwtGuiNetHistory
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
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text ((Get-IgwtGuiChangeBlockReason -What 'apply the recommended adjustments') + ' You can still review them here.'); return }
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

#region Defender settings

function Select-IgwtGuiNavPage {
    <# .SYNOPSIS Selects a navigation entry by its tag (the page then shows through the selection handler). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window navigation only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Tag)
    $it = @($script:Gui.C.NavList.Items | Where-Object { [string]$_.Tag -eq $Tag }) | Select-Object -First 1
    if ($it) { $script:Gui.C.NavList.SelectedItem = $it }
}

function Set-IgwtGuiDefenderView {
    <# .SYNOPSIS Switches the Defender page between the preference list and the Group Policy list (read the first time it is shown). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window layout only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Prefs', 'Policy')][string]$View)
    $c = $script:Gui.C
    $script:Gui.DefenderView = $View
    $isPolicy = ($View -eq 'Policy')
    $c.DefListHost.Visibility = $(if ($isPolicy) { 'Collapsed' } else { 'Visible' })
    $c.DefPolicyListHost.Visibility = $(if ($isPolicy) { 'Visible' } else { 'Collapsed' })
    $c.DefEditPanel.Visibility = $(if ($isPolicy) { 'Collapsed' } else { 'Visible' })
    $c.DefPolicyPanel.Visibility = $(if ($isPolicy) { 'Visible' } else { 'Collapsed' })
    $c.DefCategoryBox.IsEnabled = -not $isPolicy
    $accent = $script:Gui.Window.FindResource('AccentButton')
    if ($isPolicy) { $c.DefPrefsViewButton.ClearValue([System.Windows.FrameworkElement]::StyleProperty); $c.DefPolicyViewButton.Style = $accent }
    else { $c.DefPolicyViewButton.ClearValue([System.Windows.FrameworkElement]::StyleProperty); $c.DefPrefsViewButton.Style = $accent }
    Update-IgwtGuiDefenderLists
    if ($isPolicy -and $null -eq $script:Gui.DefenderPolicies -and $script:Gui.Runspace) { Start-IgwtGuiDefenderRefresh -Policies }
    elseif (-not $isPolicy -and ($null -eq $script:Gui.Defender -or $script:Gui.DefenderStale) -and $script:Gui.Runspace) { Start-IgwtGuiDefenderRefresh }
}

function Update-IgwtGuiDefenderLists {
    <# .SYNOPSIS Loads the Defender preference or Group Policy grid from the last read; the category box scopes the preferences (search and chips are the grid's). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if ($script:Gui.DefenderView -eq 'Policy') {
        $all = @($script:Gui.DefenderPolicies | Where-Object { $_ })
        if ($null -eq $script:Gui.DefenderPolicies) { $c.DefSummaryText.Text = 'Reading the Defender Group Policy settings (read-only)...' }
        else {
            Set-IgwtGuiGridRows -Name 'DefPolicyList' -Rows @($all | ForEach-Object { New-IgwtGuiDefenderPolicyRow -Policy $_ })
            $configured = @($all | Where-Object { [string]$_.State -ne 'NotConfigured' }).Count
            $c.DefSummaryText.Text = ("{0} Defender Group Policy settings, {1} configured in the Local Group Policy. Policies with extra values (numbers, lists) are set with -PolicySet and -PolicyValue; states that turn a protection off are refused." -f $all.Count, $configured)
        }
    } else {
        $g = $script:Gui.Grids['DefList']
        $cat = $c.DefCategoryBox.SelectedItem
        $catId = $(if ($cat) { [string]$cat.Id } else { '' })
        if ($g) { $g.Scope = $(if ($catId) { @{ CategoryId = @($catId) } } else { @{} }) }
        $all = @($script:Gui.Defender | Where-Object { $_ })
        if ($null -eq $script:Gui.Defender) { $c.DefSummaryText.Text = 'Not read yet.' }
        elseif (-not $all.Count) {
            $c.DefSummaryText.Text = 'The Defender settings could not be read (is Microsoft Defender Antivirus running?); see the log.'
            Set-IgwtGuiGridRows -Name 'DefList' -ErrorText 'The Defender settings could not be read (is Microsoft Defender Antivirus running?).'
        } else {
            Set-IgwtGuiGridRows -Name 'DefList' -Rows @($all | ForEach-Object { New-IgwtGuiDefenderRow -Setting $_ })
            $n = { param($s) @($all | Where-Object { [string]$_.Status -eq $s }).Count }
            $text = ("{0} settings: {1} on, {2} off, {3} below the recommended level, {4} optional hardening off, {5} options; {6} changeable here." -f $all.Count, (& $n 'On'), (& $n 'Off'), (& $n 'Below'), (& $n 'Optional'), (& $n 'Info'), @($all | Where-Object { $_.Editable }).Count)
            if (-not $script:Gui.IsAdmin) { $text += ' Read-only: restart as administrator to change settings.' }
            $c.DefSummaryText.Text = $text
        }
    }
    Update-IgwtGuiDefenderDetails
}

function Update-IgwtGuiDefenderDetails {
    <# .SYNOPSIS Fills the details and editor panel for the selected Defender setting or Group Policy setting. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    if ($script:Gui.DefenderView -eq 'Policy') {
        $row = (Get-IgwtGuiGridItem -Name DefPolicyList)
        $c.DefDocButton.Content = 'Defender policy documentation (Microsoft)'
        $c.DefDocButton.Tag = 'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender'
        if (-not $row) {
            $c.DefDetName.Text = 'Select a policy'; $c.DefDetMeta.Text = ''
            $c.DefDetDescription.Text = 'Pick a Defender Group Policy setting to see its explanation, its Local Group Policy state and the states iG Windows Tuner refuses.'
            $c.DefPolicyStateBox.ItemsSource = @(); $c.DefPolicyHelp.Text = ''
            Update-IgwtGuiButtons
            return
        }
        $p = $row.Policy
        $c.DefDetName.Text = [string]$p.Name
        $c.DefDetMeta.Text = "$($p.Id)  |  Local Group Policy: $($row.StateText)  |  Source: $($p.Source)"
        $explain = [string]$p.Explain
        if ($explain.Length -gt 1800) { $explain = $explain.Substring(0, 1800) + ' ...' }
        $c.DefDetDescription.Text = $explain.Trim()
        # One entry per state, and per option for single-option policies (for example "Enabled: Block").
        $items = @(foreach ($ch in @($p.Choices)) {
                [pscustomobject]@{ Value = [string]$ch.State; Values = $ch.Values; Label = $(if ($ch.Allowed) { [string]$ch.Label } elseif ($ch.Label -like '*needs values*') { [string]$ch.Label } else { "$($ch.Label) (not allowed)" }); Allowed = [bool]$ch.Allowed; Reason = [string]$ch.Reason }
            })
        $c.DefPolicyStateBox.ItemsSource = $items
        # Select the current state; for an Enabled policy with options the current option is not
        # known from the state alone, so nothing is preselected (the details line shows the state).
        $cur = @($items | Where-Object { $_.Value -eq [string]$p.State })
        if ($cur.Count -eq 1) { $c.DefPolicyStateBox.SelectedItem = $cur[0] }
        Update-IgwtGuiDefenderPolicyHelp
        return
    }
    $row = (Get-IgwtGuiGridItem -Name DefList)
    $c.DefDocButton.Content = 'Microsoft documentation'
    if (-not $row) {
        $c.DefDetName.Text = 'Select a setting'; $c.DefDetMeta.Text = ''
        $c.DefDetDescription.Text = 'Pick a setting to see what it does, its current and recommended value and how it can be changed.'
        $c.DefValueBox.ItemsSource = @(); $c.DefValueText.Text = ''; $c.DefValueHelp.Text = ''; $c.DefDocButton.Tag = ''
        $c.DefValueBox.Visibility = 'Visible'; $c.DefValueText.Visibility = 'Collapsed'
        Update-IgwtGuiButtons
        return
    }
    $s = $row.Setting
    $c.DefDetName.Text = [string]$s.Name
    $meta = "$($s.Property)  |  $($s.CategoryName)  |  Source: $($s.Source)"
    if ($s.Policy) { $meta += "  |  Policy: $($s.Policy)" }
    $c.DefDetMeta.Text = $meta
    $desc = "Current: $($s.Display)."
    if ($s.ProtectiveDisplay) { $desc += " Recommended: $($s.ProtectiveDisplay)." }
    $desc += "`n`n$($s.Hint)"
    if ($s.Note) { $desc += "`n`n$($s.Note)" }
    $how = [string]$s.Change
    if ($s.Editable -and [string]$s.Edit -eq 'set') { $how = 'pick a value below and press Apply value (a snapshot is written first; revert in Backups & Logs).' }
    elseif ($s.Editable) { $how = 'pick On below and press Apply value (parsers are only ever turned on).' }
    elseif ([string]$s.Edit -eq 'policy') { $how = "through Group Policy: open Group Policy above and select $($s.Policy)." }
    $desc += "`n`nHow to change: $how"
    $c.DefDetDescription.Text = $desc
    $def = Get-IgwtDefenderSettingDefinition -Name ([string]$s.Property)
    $choices = @($s.Choices | Where-Object { $_ })
    $typed = ([string]$s.Type -in 'uint', 'time', 'text')
    $c.DefValueBox.Visibility = $(if ($choices.Count) { 'Visible' } else { 'Collapsed' })
    $c.DefValueText.Visibility = $(if (-not $choices.Count -and $typed) { 'Visible' } else { 'Collapsed' })
    if ($choices.Count) {
        $items = @($choices | ForEach-Object { [pscustomobject]@{ Value = $_.Value; Label = $(if ($_.Allowed) { [string]$_.Label } else { "$($_.Label) (not allowed)" }); Allowed = [bool]$_.Allowed; Why = [string]$_.Why } })
        $c.DefValueBox.ItemsSource = $items
        $cur = @($items | Where-Object { Test-IgwtDefenderValueEqual -Definition $def -A $s.Current -B $_.Value }) | Select-Object -First 1
        if ($cur) { $c.DefValueBox.SelectedItem = $cur }
    } else {
        $c.DefValueBox.ItemsSource = @()
        $c.DefValueText.Text = $(if ([string]$s.Type -eq 'time' -and $null -ne $s.Current) { Format-IgwtDefenderSettingValue -Definition $def -Value $s.Current } elseif ($null -ne $s.Current) { [string](@($s.Current) -join '|') } else { '' })
    }
    $help = New-Object System.Collections.Generic.List[string]
    switch ([string]$s.Type) {
        'uint' { $help.Add(("A whole number from {0} to {1}{2}." -f $(if ($null -ne $s.Min) { $s.Min } else { 0 }), $(if ($null -ne $s.Max) { $s.Max } else { 4294967295 }), $(if ($s.Unit) { " ($($s.Unit))" } else { '' }))) }
        'time' { $help.Add('A time of day as HH:mm (24-hour clock).') }
        'text' { $help.Add('Text value; it is checked before anything changes.') }
        default { if ($choices.Count) { $help.Add("Values marked 'not allowed' turn a protection off or lower it, or are refused for the reason shown when you pick them.") } }
    }
    if (-not $s.Editable) { $help.Insert(0, "Locked: $(if ([string]$s.Source -match '(?i)policy|gpo|mdm') { "set by $($s.Source); change it there." } else { [string]$s.Change })") }
    elseif ([string]$s.Edit -eq 'parser') { $help.Add('Network Inspection parser: it is only ever turned on, so there is nothing to revert.') }
    $c.DefValueBox.IsEnabled = [bool]$s.Editable
    $c.DefValueText.IsReadOnly = -not [bool]$s.Editable
    $c.DefApplyButton.Visibility = $(if ($s.Editable) { 'Visible' } else { 'Collapsed' })
    $c.DefRecommendButton.Visibility = $(if ($s.Editable) { 'Visible' } else { 'Collapsed' })
    $script:Gui.DefValueBaseHelp = ($help -join "`n")
    $c.DefValueHelp.Text = $script:Gui.DefValueBaseHelp
    $c.DefDocButton.Tag = [string]$s.Doc
    Update-IgwtGuiButtons
}

function Set-IgwtGuiDefenderData {
    <# .SYNOPSIS Stores a Get-IgwtDefenderSettings result and rebuilds the list. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param($Settings)
    $script:Gui.Defender = @($Settings | Where-Object { $_ })
    $script:Gui.DefenderStale = $false
    Update-IgwtGuiDefenderLists
}

function Start-IgwtGuiDefenderRefresh {
    <# .SYNOPSIS Reads the Defender preferences, or with -Policies the Defender Group Policy settings, in the worker (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param([switch]$Policies)
    if ($Policies) {
        $null = Start-IgwtGuiJob -Command 'Get-IgwtDefenderPolicySettings' -Channel 'defender-policy' -BusyText 'Reading the Defender Group Policy settings (read-only)...' -OnComplete {
            param($out, $errs)
            $script:Gui.DefenderPolicies = @($out | Where-Object { $_ })
            Update-IgwtGuiDefenderLists
            if (@($errs).Count) { Set-IgwtGuiStatus "Defender Group Policy settings could not be read: $(@($errs)[0])" } else { Set-IgwtGuiStatus 'Defender Group Policy settings read.' }
        }
        return
    }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtDefenderSettings' -Channel 'defender' -BusyText 'Reading the Defender settings (read-only)...' -OnComplete {
        param($out, $errs)
        Set-IgwtGuiDefenderData -Settings @($out)
        if (@($out).Count) { Set-IgwtGuiStatus 'Defender settings read.' } else { Set-IgwtGuiStatus "Defender settings could not be read: $(@($errs)[0])" }
    }
}

function Select-IgwtGuiDefenderRecommended {
    <# .SYNOPSIS Picks the recommended value of the selected setting in the editor (nothing changes until Apply value). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the editor selection only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = (Get-IgwtGuiGridItem -Name DefList)
    if (-not $row -or $null -eq $row.Setting.Protective) { return }
    $def = Get-IgwtDefenderSettingDefinition -Name ([string]$row.Setting.Property)
    $on = ConvertTo-IgwtDefenderSettingValue -Definition $def -Value $row.Setting.Protective
    if (@($c.DefValueBox.ItemsSource).Count) {
        $hit = @($c.DefValueBox.ItemsSource | Where-Object { Test-IgwtDefenderValueEqual -Definition $def -A $_.Value -B $on }) | Select-Object -First 1
        if ($hit) { $c.DefValueBox.SelectedItem = $hit }
    } else { $c.DefValueText.Text = [string]$row.Setting.Protective }
    Set-IgwtGuiStatus "Recommended value picked: $($row.Setting.ProtectiveDisplay). Press Apply value to change it."
}

function Invoke-IgwtGuiDefenderChange {
    <# .SYNOPSIS Checks the new value of the selected Defender setting, confirms, then changes it in the worker (snapshot first) and reads the settings again. #>
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = (Get-IgwtGuiGridItem -Name DefList)
    if (-not $row) { Set-IgwtGuiStatus 'Select a setting first.'; return }
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text (Get-IgwtGuiChangeBlockReason -What 'change Defender settings'); return }
    $s = $row.Setting
    $def = Get-IgwtDefenderSettingDefinition -Name ([string]$s.Property)
    $raw = $null
    if ($c.DefValueBox.Visibility -eq 'Visible') {
        $pick = $c.DefValueBox.SelectedItem
        if (-not $pick) { Set-IgwtGuiStatus 'Pick a value first.'; return }
        if (-not $pick.Allowed) { Set-IgwtGuiStatus "Not allowed: $($pick.Why)"; return }
        $raw = $pick.Value
    } else {
        $raw = ([string]$c.DefValueText.Text).Trim()
        if (-not $raw) { Set-IgwtGuiStatus 'Type a value first.'; return }
    }
    try { $value = ConvertTo-IgwtDefenderSettingValue -Definition $def -Value $raw } catch { $null = Show-IgwtGuiMessage -Text "The value is not valid:`n`n$($_.Exception.Message)" -Icon 'Warning'; return }
    $why = Test-IgwtDefenderSettingValue -Definition $def -Value $value -Current $s.Current
    if ($why) { $script:Gui.C.DefValueHelp.Text = "Not allowed: $why"; Set-IgwtGuiStatus "Not allowed: $why"; return }
    if (Test-IgwtDefenderValueEqual -Definition $def -A $s.Current -B $value) { Set-IgwtGuiStatus "'$($s.Name)' is already $($s.Display)."; return }
    $newText = Format-IgwtDefenderSettingValue -Definition $def -Value $value
    $text = "Change '$($s.Name)' from $($s.Display) to ${newText}?"
    if ([string]$s.Edit -eq 'parser') { $text += "`n`nNetwork Inspection parsers are only ever turned on; there is nothing to revert." }
    else { $text += "`n`nA snapshot is written first, so you can revert this in Backups & Logs." }
    $params = @{ Setting = @{ ([string]$s.Property) = $value } }
    $m = $script:Gui.Management
    if ($m -and $m.Managed) { $text += "`n`nThis PC is managed ($(@($m.Authorities) -join ', ')): your organization's policy can override the local value."; $params.AcknowledgeManaged = $true }
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - Defender settings' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtDefenderSettingChange' -Parameters $params -Blocking -BusyText 'Changing the Defender setting (snapshot first)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The setting was not changed: $(@($errs)[0])" -Icon 'Error' }
        elseif ($res -and $res.Changes -gt 0) {
            $lines = @($res.Results | ForEach-Object { "[$($_.Result)] $($_.Target): $($_.Change)$(if ($_.Message) { " - $($_.Message)" })" })
            $tail = $(if ($res.Snapshot) { "`n`nSnapshot: $($res.Snapshot)" } else { '' })
            $null = Show-IgwtGuiMessage -Text (($lines -join "`n") + $tail) -Icon $(if (@($res.Results | Where-Object { $_.Result -ne 'Applied' }).Count) { 'Warning' } else { 'Information' })
        } else { Set-IgwtGuiStatus 'Nothing to change.' }
        Start-IgwtGuiDefenderRefresh
    }
}

function Update-IgwtGuiDefenderPolicyHelp {
    <# .SYNOPSIS The help under the policy state box: what the policy sets, and why the chosen option is not allowed (inline, no dialog). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = (Get-IgwtGuiGridItem -Name DefPolicyList)
    if (-not $row) { return }
    $p = $row.Policy
    $pick = $c.DefPolicyStateBox.SelectedItem
    $help = New-Object System.Collections.Generic.List[string]
    if ($pick -and -not $pick.Allowed) { $help.Add("Not allowed: $($pick.Reason)") }
    if ($p.Preference) { $help.Add("Sets the Defender preference $($p.Preference); a policy wins over the local value.") }
    $help.Add('A Local Group Policy backup is taken before every change (-PolicyRestore <backup> restores it).')
    $c.DefPolicyHelp.Text = ($help -join "`n")
    Update-IgwtGuiButtons
}

function Invoke-IgwtGuiDefenderPolicyChange {
    <# .SYNOPSIS Confirms, then sets the selected Defender Group Policy setting in the worker (Local GPO backup first, denylist checked) and reads the policies again. #>
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = (Get-IgwtGuiGridItem -Name DefPolicyList)
    $pick = $c.DefPolicyStateBox.SelectedItem
    if (-not $row -or -not $pick) { Set-IgwtGuiStatus 'Select a policy and a state first.'; return }
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to change Group Policy.'; return }
    if (-not $pick.Allowed) { Set-IgwtGuiStatus "Not allowed: $($pick.Reason)"; return }
    if ([string]$row.Policy.State -eq [string]$pick.Value -and -not @($pick.Values.Keys).Count) { Set-IgwtGuiStatus "The policy is already $($pick.Label)."; return }
    $text = "Set the Group Policy '$($row.Name)' to $($pick.Label)?`n`n$($row.Id)`n`nA backup of the Local Group Policy is taken first."
    $params = @{ Id = [string]$row.Id; State = [string]$pick.Value }
    if (@($pick.Values.Keys).Count) { $params.Values = $pick.Values }
    $m = $script:Gui.Management
    if ($m -and $m.Managed) { $text += "`n`nThis PC is managed ($(@($m.Authorities) -join ', ')): a domain or MDM policy can override it."; $params.AcknowledgeManaged = $true }
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - Defender Group Policy' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Set-IgwtLocalPolicy' -Parameters $params -Blocking -BusyText 'Setting the Group Policy (backup first)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The policy was not changed: $(@($errs)[0])" -Icon 'Error' }
        elseif ($res) {
            $v = $(if ($res.Verified -eq $true) { 'The resulting registry values were verified.' } elseif ($res.Verified -eq $false) { "Not every value was found after the refresh: $(@($res.Mismatch) -join ', ')." } else { '' })
            $null = Show-IgwtGuiMessage -Text "$($res.Id) -> $($res.State). $v`n`nBackup: $($res.Backup)" -Icon $(if ($res.Verified -eq $false) { 'Warning' } else { 'Information' })
        }
        $script:Gui.DefenderStale = $true
        Start-IgwtGuiDefenderRefresh -Policies
    }
}

#endregion

#region Persona

# Pages hidden in focus mode (3.3 C11): expert tools and reference lists.
$script:IgwtGuiFocusHidden = @('Inspect', 'Policy', 'Risk Zone', 'Rejected')

function Set-IgwtGuiFocusMode {
    <# .SYNOPSIS Focus mode on or off (display only): expert pages, dashboard details and items above Standard are hidden. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([bool]$On, [switch]$NoSave)
    $script:Gui.FocusMode = $On
    $c = $script:Gui.C
    $c.FocusModeBox.IsChecked = $On
    $c.FocusPill.Visibility = $(if ($On) { 'Visible' } else { 'Collapsed' })
    $c.DashDetails.Visibility = $(if ($On) { 'Collapsed' } else { 'Visible' })
    if (-not $NoSave) { Set-IgwtGuiViewValue -Name 'FocusMode' -Value $On }
    if ($script:Gui.Persona) { Set-IgwtGuiPersona -Name ([string]$script:Gui.Persona.Name) } elseif ($script:Gui.Data) { Update-IgwtGuiTweakList }
    if (-not $NoSave) { Set-IgwtGuiStatus $(if ($On) { 'Focus mode on: expert pages, details and advanced items are hidden. Nothing on the PC changed.' } else { 'Focus mode off: everything is shown again.' }) }
}

# Navigation groups (3.3 X11). Pages not listed fall into "More".
$script:IgwtGuiNavGroups = [ordered]@{
    'Start'    = @('Dashboard', 'Presets')
    'Optimize' = @('Power & CPU', 'Graphics & Display', 'Input', 'Network', 'Background & Privacy', 'System')
    'Secure'   = @('Security', 'Asr', 'Defender', 'Firewall', 'Policy', 'Risk Zone')
    'Clean'    = @('Cleaner', 'Storage', 'Disk', 'Startup')
    'Manage'   = @('Manage', 'Toolkit')
    'Diagnose' = @('Diagnostics', 'NetTest', 'Inspect')
    'History'  = @('Backups', 'Rejected', 'About')
}

function New-IgwtGuiNavHeader {
    <# .SYNOPSIS A group label for the navigation list (not selectable). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates a window object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)
    $h = New-Object System.Windows.Controls.ListBoxItem
    $h.Tag = "#group:$Text"
    $h.Style = $script:Gui.Window.FindResource('NavHeader')
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $Text.ToUpperInvariant(); $tb.FontSize = 11; $tb.FontWeight = 'SemiBold'
    $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BrushTextMuted')
    $h.Content = $tb
    [System.Windows.Automation.AutomationProperties]::SetName($h, "$Text group")
    return $h
}

function Get-IgwtGuiNavHeader {
    <# .SYNOPSIS The group label for the navigation list; one item per group, created once and reused. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)
    if ($null -eq $script:Gui.NavHeaders) { $script:Gui.NavHeaders = @{} }   # (not -not: an empty hashtable is falsy)
    if (-not $script:Gui.NavHeaders.ContainsKey($Text)) { $script:Gui.NavHeaders[$Text] = New-IgwtGuiNavHeader -Text $Text }
    return $script:Gui.NavHeaders[$Text]
}

function Test-IgwtGuiNavHeader {    <# .SYNOPSIS True for a navigation group label. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Item)
    return ([string]$Item.Tag).StartsWith('#group:')
}

function Set-IgwtGuiPersona {
    <# .SYNOPSIS Applies a persona to the window: navigation order, Risk Zone visibility and visible item levels. Display only. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window layout only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $c = $script:Gui.C
    $p = Get-IgwtPersonaProfile -Name $Name
    $script:Gui.Persona = $p
    $nav = $c.NavList
    $selected = $nav.SelectedItem
    $items = @($nav.Items | Where-Object { -not (Test-IgwtGuiNavHeader -Item $_) })
    if (-not $script:Gui.NavDefault) { $script:Gui.NavDefault = @($items | ForEach-Object { [string]$_.Tag }) }
    $order = @($p.NavOrder)
    if ($order.Count -eq 0) { $order = @($script:Gui.NavDefault) }
    $rank = @{}
    for ($i = 0; $i -lt $order.Count; $i++) { $rank[[string]$order[$i]] = $i }
    $sorted = @($items | Sort-Object @{ Expression = { $t = [string]$_.Tag; if ($rank.ContainsKey($t)) { $rank[$t] } else { 1000 + [array]::IndexOf($script:Gui.NavDefault, $t) } } })
    # The ASR Center and the Defender settings are part of Security: keep them directly under
    # Security in every persona.
    $subs = @(foreach ($tag in 'Asr', 'Defender', 'Firewall') { @($sorted | Where-Object { [string]$_.Tag -eq $tag }) | Select-Object -First 1 })
    $subs = @($subs | Where-Object { $_ })
    if ($subs.Count) {
        $rest = New-Object System.Collections.Generic.List[object]
        foreach ($it in $sorted) {
            if (@($subs | Where-Object { [object]::ReferenceEquals($_, $it) }).Count) { continue }
            $rest.Add($it)
            if ([string]$it.Tag -eq 'Security') { foreach ($s in $subs) { $rest.Add($s) } }
        }
        foreach ($s in $subs) { if (-not $rest.Contains($s)) { $rest.Add($s) } }
        $sorted = $rest.ToArray()
    }
    foreach ($it in $sorted) { $it.Visibility = $(if (([string]$it.Tag -eq 'Risk Zone' -and -not $p.ShowRiskZone) -or ($script:Gui.FocusMode -and $script:IgwtGuiFocusHidden -contains [string]$it.Tag)) { 'Collapsed' } else { 'Visible' }) }
    # Grouped navigation: groups follow the persona's order (the rank of their first page); a label
    # starts each group that has a visible page. The new order is planned first, the label items are reused,
    # and the list is only touched when the order changed (no needless detaching of its items).
    $groupOf = @{}; foreach ($k in $script:IgwtGuiNavGroups.Keys) { foreach ($tag in $script:IgwtGuiNavGroups[$k]) { $groupOf[$tag] = $k } }
    $groups = New-Object System.Collections.Generic.List[string]
    foreach ($it in $sorted) { $k = $(if ($groupOf.ContainsKey([string]$it.Tag)) { $groupOf[[string]$it.Tag] } else { 'More' }); if (-not $groups.Contains($k)) { $groups.Add($k) } }
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($k in $groups) {
        $members = @($sorted | Where-Object { $(if ($groupOf.ContainsKey([string]$_.Tag)) { $groupOf[[string]$_.Tag] } else { 'More' }) -eq $k })
        if (@($members | Where-Object { $_.Visibility -eq 'Visible' }).Count) { $plan.Add((Get-IgwtGuiNavHeader -Text $k)) }
        foreach ($it in $members) { $plan.Add($it) }
    }
    $same = ($plan.Count -eq $nav.Items.Count)
    for ($n = 0; $same -and $n -lt $plan.Count; $n++) { if (-not [object]::ReferenceEquals($plan[$n], $nav.Items[$n])) { $same = $false } }
    if (-not $same) {
        $nav.Items.Clear()
        foreach ($x in $plan) { $null = $nav.Items.Add($x) }
    }    if ($selected -and $selected.Visibility -eq 'Visible') { $nav.SelectedItem = $selected } else { $nav.SelectedItem = @($nav.Items | Where-Object { -not (Test-IgwtGuiNavHeader -Item $_) -and $_.Visibility -eq 'Visible' })[0] }
    if ($script:Gui.Data) { Update-IgwtGuiTweakList }
    Set-IgwtGuiStatus "Persona: $($p.Name). $($p.Hint)"
}

#endregion

#region Toolkit

function Update-IgwtGuiToolkitLists {
    <# .SYNOPSIS Fills the Toolkit grids from the cached Toolkit data and the tweak states (each grid has its own search and chips). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $t = $script:Gui.Toolkit
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] }
    $err = { param($o) if (& $has $o 'Error') { "Not readable: $($o.Error)" } else { '' } }
    if ($t) {
        $apps = @($t.Apps | Where-Object { $_ -and -not (& $has $_ 'Error') })
        Set-IgwtGuiGridRows -Name 'ToolkitAppList' -Rows @($apps | ForEach-Object {
                $st = $(if ($_.Installed -eq $true) { "Installed $($_.Version)".Trim() } elseif ($_.Installed -eq $false) { 'Not installed' } else { 'Not checked' })
                New-IgwtGuiManageRow -Title $_.Name -Subtitle "$($_.Id) - $($_.Hint)" -Badge $_.Category -State $st -Tone $(if ($_.Installed -eq $true) { 'Pass' } else { 'Muted' }) -Tip "$($_.Description)$(if ($_.Note) { "`n$($_.Note)" })" -Source $_ `
                    -Key ([string]$_.Id) -Extra @{ PackageId = [string]$_.Id; Hint = [string]$_.Hint; InstalledKey = $(if ($_.Installed -eq $true) { 'Yes' } elseif ($_.Installed -eq $false) { 'No' } else { '' }); FossKey = $(if ($_.Foss) { 'Yes' } else { 'No' }) }
            })
        $installed = @($apps | Where-Object { $_.Installed -eq $true }).Count
        $stateNote = @($apps | Where-Object { $_.StateNote } | Select-Object -First 1).StateNote
        $c.ToolkitAppSummary.Text = "$($apps.Count) curated winget packages in $(@($apps | Group-Object Category).Count) categories. " +
        $(if ($stateNote) { "Installed state unavailable: $stateNote" } elseif ($t.AppState) { "$installed installed." } else { 'Press Check installed to read installed versions (one winget export).' }) +
        $(if ($t.Consent) { ' winget agreements accepted.' } else { ' The first install shows winget''s agreements for you to accept.' })
        if (& $has $t.Features 'Error') { $c.ToolkitFeatureSummary.Text = & $err $t.Features; Set-IgwtGuiGridRows -Name 'ToolkitFeatureList' -ErrorText (& $err $t.Features) } else {
            Set-IgwtGuiGridRows -Name 'ToolkitFeatureList' -Rows @($t.Features | ForEach-Object {
                    $st = $(if (-not $_.Supported) { 'Not on this edition' } elseif ($_.State -eq 'On') { 'Enabled' } elseif ($_.State -eq 'Off') { 'Disabled' } elseif ($_.State -eq 'Partial') { 'Partly enabled' } else { 'Unknown' })
                    New-IgwtGuiManageRow -Title $_.Name -Subtitle $_.Hint -Badge "$($_.Kind)$(if (@($_.Editions).Count) { ', ' + (@($_.Editions) -join '/') })" -State $st `
                        -Tone $(if (-not $_.Supported) { 'Muted' } elseif ($_.State -eq 'On') { 'Pass' } elseif ($_.State -eq 'Unknown') { 'Muted' } else { 'Text' }) -Tip $_.Description -Source $_ -Key ([string]$_.Id)
                })
            $c.ToolkitFeatureSummary.Text = $(if (@($t.Features | Where-Object { $_.State -eq 'Unknown' }).Count -and -not $script:Gui.IsAdmin) { 'Feature states need administrator rights to read; restart as administrator to see and change them.' } else { 'Each change writes a snapshot first. Features that WSL, Docker and other tools depend on are never disabled.' })
        }
        if (& $has $t.Fixes 'Error') { Set-IgwtGuiGridRows -Name 'ToolkitFixList' -ErrorText (& $err $t.Fixes) } else {
            Set-IgwtGuiGridRows -Name 'ToolkitFixList' -Rows @($t.Fixes | ForEach-Object {
                    New-IgwtGuiManageRow -Title $_.Name -Subtitle $_.Hint -Badge "$(if ($_.Admin) { 'administrator' } else { 'no administrator' })$(if ($_.Reboot) { ', restart' })" -State "about $($_.Minutes) min" -Tone 'Text' -Tip $_.Description -Source $_ `
                        -Key ([string]$_.Id) -Extra @{ Minutes = [double]$_.Minutes; AdminKey = $(if ($_.Admin) { 'Yes' } else { 'No' }); RestartKey = $(if ($_.Reboot) { 'Yes' } else { 'No' }) }
                })
        }
        if (& $has $t.Panels 'Error') { Set-IgwtGuiGridRows -Name 'ToolkitPanelList' -ErrorText (& $err $t.Panels) } else {
            Set-IgwtGuiGridRows -Name 'ToolkitPanelList' -Rows @($t.Panels | ForEach-Object { New-IgwtGuiManageRow -Title $_.Name -Subtitle $_.Hint -Badge $_.Command -State 'Open' -Tone 'Info' -Tip $_.Description -Source $_ -Key ([string]$_.Id) })
        }
    }
    if ($script:Gui.Data -and $script:Gui.Catalog) {
        $mk = {
            param($items)
            @($items | ForEach-Object {
                    $s = $script:Gui.Data.States[$_.id]
                    $state = $(if ($s) { [string]$s.State } else { '' })
                    New-IgwtGuiManageRow -Title $_.name -Subtitle $_.hint -Badge "$($_.category) | $($_.level), Tier $($_.tier)" -State $state `
                        -Tone $(switch ($state) { 'On' { 'Pass' } 'Partial' { 'Warn' } 'ManagedByPolicy' { 'Info' } 'NotApplicable' { 'Muted' } default { 'Text' } }) -Tip "$($_.description)$(if ($_.attribution) { "`nCredit: $($_.attribution)" })" -Source $_ `
                        -Key ([string]$_.id) -Extra @{ Id = [string]$_.id; Category = [string]$_.category; Level = [string]$_.level }
                })
        }
        $tw = @($script:Gui.Catalog | Where-Object { [string]$_.source -eq 'winutil' })
        Set-IgwtGuiGridRows -Name 'ToolkitTweakList' -Rows (& $mk $tw)
        $c.ToolkitTweakSummary.Text = "$($tw.Count) items derived from WinUtil (mapping: docs\WINUTIL_MAPPING.md). They also appear in their categories; stage and apply them there like any other item."
        Set-IgwtGuiGridRows -Name 'ToolkitUpdateList' -Rows (& $mk @($script:Gui.Catalog | Where-Object { [string]$_.group -eq 'Windows Update' -or [string]$_.id -eq 'net.delivery-optimization-p2p-off' }))
    }
    Update-IgwtGuiButtons
}

function Update-IgwtGuiToolkitDetail {
    <# .SYNOPSIS Detail texts under the Toolkit lists for the selected rows. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $nl = [Environment]::NewLine
    $apps = @(Get-IgwtGuiGridItems -Name ToolkitAppList)
    $c.ToolkitAppDetail.Text = $(if ($apps.Count -eq 1) { $a = $apps[0].Source; "$($a.Name) ($($a.Id), $($a.Category)$(if ($a.Foss) { ', open source' })).$nl$($a.Description)$(if ($a.Note) { "${nl}Note: $($a.Note)" })" }
        elseif ($apps.Count -gt 1) { "$($apps.Count) apps selected: $(@($apps | ForEach-Object { $_.Source.Name }) -join ', ')." } else { 'Select one or more apps (Ctrl or Shift to select several).' })
    $f = (Get-IgwtGuiGridItem -Name ToolkitFeatureList)
    $c.ToolkitFeatureDetail.Text = $(if ($f) {
            $x = $f.Source
            "$($x.Name): $($x.Description)${nl}Targets: $(@($x.Targets) -join ', ')$(if (@($x.TargetStates).Count) { ' (' + (@($x.TargetStates | ForEach-Object { "$($_.Target) $($_.Current)" }) -join '; ') + ')' })" +
            $(if (@($x.Editions).Count) { "${nl}Editions: $(@($x.Editions) -join ', ')$(if (-not $x.Supported) { ' - not available on this edition' })" }) + $(if ($x.Reboot) { "${nl}Needs a restart." }) + $(if ($x.Warning) { "${nl}Warning: $($x.Warning)" })
        } else { 'Select a feature.' })
    $x = (Get-IgwtGuiGridItem -Name ToolkitFixList)
    $c.ToolkitFixDetail.Text = $(if ($x) { $p = $x.Source; "$($p.Name): $($p.Description)${nl}Steps:$nl$(@($p.Steps | ForEach-Object { "  - $_" }) -join $nl)$(if ($p.Warning) { "${nl}Warning: $($p.Warning)" })${nl}Source: $($p.Source)" } else { 'Select a fix to see its steps.' })
    $p = (Get-IgwtGuiGridItem -Name ToolkitPanelList)
    $c.ToolkitPanelDetail.Text = $(if ($p) { "$($p.Source.Name): $($p.Source.Description)${nl}Opens: $($p.Source.Command)" } else { 'Select a panel.' })
    foreach ($pair in @(@('ToolkitTweakListHost', 'ToolkitTweakDetail'), @('ToolkitUpdateListHost', 'ToolkitUpdateDetail'))) {
        $r = Get-IgwtGuiGridItem -Name $pair[0]
        $c[$pair[1]].Text = $(if ($r) { "$($r.Source.name) ($($r.Source.id)): $($r.Source.description)$(if ($r.Source.attribution) { "${nl}Credit: $($r.Source.attribution)" })" } else { 'Select an item.' })
    }
    Update-IgwtGuiButtons
}

function Start-IgwtGuiToolkitRefresh {
    <# .SYNOPSIS Reads the Toolkit data in the worker (read-only; -WithAppState runs one winget export). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param([switch]$WithAppState)
    $null = Start-IgwtGuiJob -Command 'Get-IgwtGuiToolkitData' -Channel 'toolkit' -Parameters @{ WithAppState = [bool]$WithAppState } -BusyText $(if ($WithAppState) { 'Reading installed packages with winget (read-only)...' } else { 'Reading the Toolkit lists (read-only)...' }) -OnComplete {
        param($out, $errs)
        $script:Gui.Toolkit = @($out) | Select-Object -Last 1
        Update-IgwtGuiToolkitLists
        Update-IgwtGuiToolkitDetail
        Set-IgwtGuiStatus 'Toolkit data updated.'
    }
}

function Confirm-IgwtGuiWingetAgreements {
    <# .SYNOPSIS Shows winget's agreements before the first install or upgrade; records the acceptance. Returns $true when accepted. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (Test-IgwtWingetConsent) { return $true }
    $a = Get-IgwtWingetAgreements
    $text = "Before the first install or upgrade, please read:`n`n$(@($a.Lines | ForEach-Object { "- $_" }) -join "`n`n")`n`nDo you accept these agreements?"
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - winget agreements' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return $false }
    try { Set-IgwtWingetConsent } catch { Write-Verbose "Acceptance not recorded: $($_.Exception.Message)" }
    return $true
}

function Invoke-IgwtGuiToolkitApps {
    <# .SYNOPSIS Installs, upgrades or uninstalls the selected apps with winget in the worker, after confirmation. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Install', 'Upgrade', 'Uninstall', 'UpgradeAll')][string]$Operation)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text 'Restart as administrator to install or remove apps.'; return }
    $ids = @(Get-IgwtGuiGridItems -Name ToolkitAppList | ForEach-Object { [string]$_.Source.Id })
    if ($Operation -ne 'UpgradeAll' -and $ids.Count -eq 0) { Set-IgwtGuiStatus 'Select one or more apps first.'; return }
    if ($Operation -ne 'Uninstall' -and -not (Confirm-IgwtGuiWingetAgreements)) { Set-IgwtGuiStatus 'Not installed: the winget agreements were not accepted.'; return }
    $what = $(if ($Operation -eq 'UpgradeAll') { 'Upgrade every package from the winget source' } else { "$Operation $($ids.Count) app(s):`n$(@(Get-IgwtGuiGridItems -Name ToolkitAppList | ForEach-Object { "  $($_.Source.Name) ($($_.Source.Id))" }) -join "`n")" })
    if ((Show-IgwtGuiMessage -Text "$what`n`nwinget runs each installer silently; progress is shown in the log. Continue?" -Title 'iG Windows Tuner - Toolkit' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $cmd = 'Invoke-IgwtToolkitApp'; $params = @{ Operation = $Operation; Id = $ids; AcceptAgreements = ($Operation -ne 'Uninstall') }
    if ($Operation -eq 'UpgradeAll') { $cmd = 'Invoke-IgwtWingetUpgradeAll'; $params = @{ AcceptAgreements = $true } }
    $null = Start-IgwtGuiJob -Command $cmd -Parameters $params -Blocking -BusyText "winget: $Operation..." -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "winget did not finish: $(@($errs)[0])" -Icon 'Error' }
        else {
            $lines = @(@($out) | Where-Object { $_ } | ForEach-Object { if ($_.PSObject.Properties['Id']) { "[$($_.Result)] $($_.Id) $($_.Message)" } else { "[$($_.Result)] winget upgrade --all (exit $($_.ExitCode))" } })
            $null = Show-IgwtGuiMessage -Text ($lines -join "`n") -Icon $(if (@(@($out) | Where-Object { $_.Result -eq 'Failed' }).Count) { 'Warning' } else { 'Information' })
        }
        Start-IgwtGuiToolkitRefresh -WithAppState
    }
}

function Export-IgwtGuiAppSelection {
    [CmdletBinding()]
    param()
    $ids = @(Get-IgwtGuiGridItems -Name ToolkitAppList | ForEach-Object { [string]$_.Source.Id })
    if ($ids.Count -eq 0) { Set-IgwtGuiStatus 'Select the apps to export first.'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'iG Windows Tuner app selection (*.json)|*.json'; $dlg.FileName = 'igwt-apps.json'
    if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
    try { $null = Export-IgwtAppSelection -Path $dlg.FileName -Id $ids; Set-IgwtGuiStatus "Saved $($ids.Count) app(s) to $($dlg.FileName)." }
    catch { $null = Show-IgwtGuiMessage -Text $_.Exception.Message -Icon 'Warning' }
}

function Import-IgwtGuiAppSelection {
    [CmdletBinding()]
    param()
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'iG Windows Tuner app selection (*.json)|*.json'
    if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
    try { $ids = @(Import-IgwtAppSelection -Path $dlg.FileName) } catch { $null = Show-IgwtGuiMessage -Text $_.Exception.Message -Icon 'Warning'; return }
    $g = $script:Gui.Grids.ToolkitAppList
    # Every app must be in the view to be selected: clear the search and chips first.
    Clear-IgwtGridFilters -Grid $g
    $list = $g.C.Grid
    $list.SelectedItems.Clear()
    foreach ($row in @($list.Items)) { if ($ids -contains [string]$row.Source.Id) { $null = $list.SelectedItems.Add($row) } }
    $missing = @($ids | Where-Object { $i = $_; -not @($g.Index.Rows | Where-Object { [string]$_.Source.Id -eq $i }).Count })
    Set-IgwtGuiStatus "Selected $(@($list.SelectedItems).Count) app(s) from the list.$(if ($missing.Count) { " Not in the curated list (install them with the CLI): $($missing -join ', ')." })"
}

function Invoke-IgwtGuiToolkitFeature {
    <# .SYNOPSIS Enables or disables the selected Toolkit feature in the worker after confirmation (snapshot first). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled')][string]$State)
    if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text (Get-IgwtGuiChangeBlockReason -What 'change Windows features'); return }
    $row = (Get-IgwtGuiGridItem -Name ToolkitFeatureList)
    if (-not $row) { return }
    $f = $row.Source
    $text = "$(if ($State -eq 'Enabled') { 'Enable' } else { 'Disable' }) $($f.Name)?`n`nTargets: $(@($f.Targets) -join ', ')$(if ($f.Warning) { "`n`nWarning: $($f.Warning)" })$(if ($f.Reboot) { "`n`nA restart is needed afterwards." })`n`nA snapshot is written first; revert it in Backups & Logs."
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - Windows feature' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtToolkitFeature' -Parameters @{ Id = [string]$f.Id; State = $State } -Blocking -BusyText "$($f.Name) -> $State (snapshot first)..." -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The change was not made: $(@($errs)[0])" -Icon 'Warning' }
        elseif ($res) { $null = Show-IgwtGuiMessage -Text ((@($res.Results | ForEach-Object { "[$($_.Result)] $($_.Change) $($_.Message)" }) -join "`n") + $(if ($res.RebootRequired) { "`n`nRestart Windows to finish." })) }
        Start-IgwtGuiToolkitRefresh
    }
}

function Invoke-IgwtGuiToolkitFix {
    <# .SYNOPSIS Shows the selected fix's steps for confirmation, then runs it in the worker and shows each step's result. #>
    [CmdletBinding()]
    param()
    $row = (Get-IgwtGuiGridItem -Name ToolkitFixList)
    if (-not $row) { return }
    $p = $row.Source
    if (Test-IgwtReadOnly) { Set-IgwtGuiStatus (Get-IgwtGuiChangeBlockReason -What 'run fixes'); return }
    if ($p.Admin -and -not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text "'$($p.Name)' needs administrator rights. Restart as administrator first."; return }
    $text = "$($p.Name)`n$($p.Description)`n`nSteps:`n$(@($p.Steps | ForEach-Object { "  - $_" }) -join "`n")$(if ($p.Warning) { "`n`nWarning: $($p.Warning)" })$(if ($p.Reboot) { "`n`nA restore point is created first; restart Windows afterwards." })`n`nSource: $($p.Source)"
    if (-not (Show-IgwtGuiTextDialog -Title "Run fix: $($p.Name)" -Text $text -AcceptText 'Run fix' -CancelText 'Cancel')) { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtToolkitFix' -Parameters @{ Id = [string]$p.Id } -Blocking -BusyText "$($p.Name): running (about $($p.Minutes) min)..." -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The fix did not run: $(@($errs)[0])" -Icon 'Warning'; return }
        if (-not $res) { return }
        $lines = @($res.Steps | ForEach-Object { "[$($_.Result)] $($_.Step)$(if ($_.Output) { "`n" + (([string]$_.Output) -replace '(?m)^', '      ') })" })
        $null = Show-IgwtGuiTextDialog -Title "$($res.Name): $($res.Result)" -Text (($lines -join "`n") + $(if ($res.RebootRequired) { "`n`nRestart Windows to finish this fix." }))
    }
}

function Show-IgwtGuiTweakInCategory {
    <# .SYNOPSIS Switches to the category page of a catalog item and selects it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $c = $script:Gui.C
    $t = @($script:Gui.Catalog | Where-Object { $_.id -eq $Id }) | Select-Object -First 1
    if (-not $t) { return }
    $nav = @($c.NavList.Items | Where-Object { [string]$_.Tag -eq [string]$t.category }) | Select-Object -First 1
    if ($nav) { $c.NavList.SelectedItem = $nav }
    # Show the item even when chips or a search would hide it.
    Clear-IgwtGridFilters -Grid $script:Gui.Grids.Tweaks
    $row = @($script:Gui.Grids.Tweaks.C.Grid.ItemsSource | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
    if ($row) { $script:Gui.Grids.Tweaks.C.Grid.SelectedItem = $row; $script:Gui.Grids.Tweaks.C.Grid.ScrollIntoView($row) }
}

#endregion

function Get-IgwtGuiBreadcrumb {
    <# .SYNOPSIS "Group > Page" for the breadcrumb (sub-pages of Security show their parent). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Page)
    $group = @($script:IgwtGuiNavGroups.Keys | Where-Object { $script:IgwtGuiNavGroups[$_] -contains $Page })[0]
    $item = @($script:Gui.C.NavList.Items | Where-Object { [string]$_.Tag -eq $Page })[0]
    $label = $Page
    if ($item -and $item.Content -is [System.Windows.Controls.Panel]) { $tb = @($item.Content.Children | Where-Object { $_ -is [System.Windows.Controls.TextBlock] -and $_.Style -ne $script:Gui.Window.TryFindResource('Icon') })[-1]; if ($tb) { $label = [string]$tb.Text } }
    $parts = @($group)
    if ($Page -in 'Asr', 'Defender', 'Firewall') { $parts += 'Security' }
    $parts += $label
    return (@($parts | Where-Object { $_ }) -join "  $([char]0x203A)  ")
}

function Show-IgwtGuiPage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Page)
    $c = $script:Gui.C
    $script:Gui.CurrentPage = $Page
    $c.Breadcrumb.Text = Get-IgwtGuiBreadcrumb -Page $Page
    # The Security sub-pages carry the breadcrumb in their title (Security > Firewall).
    $c.Breadcrumb.Visibility = $(if ($Page -in 'Asr', 'Defender', 'Firewall') { 'Collapsed' } else { 'Visible' })
    if ($script:Gui.Window -and $script:Gui.Window.IsLoaded) { Set-IgwtGuiViewValue -Name 'LastPage' -Value $Page }
    if ($script:Gui.DiagnosticsPath -and $script:Gui.Window) {
        # Page switch time: from the click to the next idle UI thread (the page is laid out and painted).
        $script:Gui.PageWatch = @{ Page = $Page; Watch = [System.Diagnostics.Stopwatch]::StartNew() }
        $null = $script:Gui.Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::ApplicationIdle, [Action] {
                $pw = $script:Gui.PageWatch
                if ($pw) { Write-IgwtGuiDiagnostic -Kind 'pageswitch' -Text ("{0}`t{1:n0}" -f $pw.Page, $pw.Watch.Elapsed.TotalMilliseconds); $script:Gui.PageWatch = $null }
            })
    }
    foreach ($p in 'PageDashboard', 'PagePresets', 'PageTweaks', 'PageInspect', 'PageManage', 'PageToolkit', 'PageDiagnostics', 'PageNetTest', 'PageAsr', 'PageDefender', 'PageFirewall', 'PagePolicy', 'PageCleaner', 'PageDisk', 'PageStartup', 'PageBackups', 'PageRejected', 'PageAbout') { $c[$p].Visibility = 'Collapsed' }
    $isTweakPage = $script:IgwtCategories -contains $Page
    $c.DetailsColumn.Width = $(if ($isTweakPage) { New-Object System.Windows.GridLength(380) } else { New-Object System.Windows.GridLength(0) })
    $c.DetailsPane.Visibility = $(if ($isTweakPage) { 'Visible' } else { 'Collapsed' })
    $c.SecuritySwitch.Visibility = $(if ($Page -eq 'Security') { 'Visible' } else { 'Collapsed' })
    if ($isTweakPage) {
        $script:Gui.Category = $Page
        $c.PageTweaks.Visibility = 'Visible'
        Set-IgwtGuiTweakPageChips
        if ($script:Gui.Data) { Update-IgwtGridView -Grid $script:Gui.Grids.Tweaks; Update-IgwtGuiTweakHeader }
        return
    }
    switch ($Page) {
        'Dashboard' { $c.PageDashboard.Visibility = 'Visible' }
        'Presets' { $c.PagePresets.Visibility = 'Visible'; Update-IgwtGuiPresetCards }
        'Asr' { $c.PageAsr.Visibility = 'Visible'; if (-not $script:Gui.AsrStatus -and $script:Gui.Runspace) { Start-IgwtGuiAsrRefresh } }
        'Defender' { $c.PageDefender.Visibility = 'Visible'; Set-IgwtGuiDefenderView -View $(if ($script:Gui.DefenderView) { $script:Gui.DefenderView } else { 'Prefs' }) }
        'Policy' { $c.PagePolicy.Visibility = 'Visible'; if (-not $script:Gui.Policy -and $script:Gui.Runspace) { Start-IgwtGuiPolicyRefresh } }
        'Firewall' { $c.PageFirewall.Visibility = 'Visible'; if (-not $script:Gui.Firewall -and $script:Gui.Runspace) { Start-IgwtGuiFirewallRefresh } }
        'Inspect' { $c.PageInspect.Visibility = 'Visible'; if (-not $script:Gui.Inspection -and $script:Gui.Runspace) { Start-IgwtGuiInspect } }
        'Manage' { $c.PageManage.Visibility = 'Visible'; if (-not $script:Gui.Manage -and $script:Gui.Runspace) { Start-IgwtGuiManageRefresh } }
        'Toolkit' { $c.PageToolkit.Visibility = 'Visible'; Update-IgwtGuiToolkitLists; if (-not $script:Gui.Toolkit -and $script:Gui.Runspace) { Start-IgwtGuiToolkitRefresh } }
        'NetTest' { $c.PageNetTest.Visibility = 'Visible' }
        'Diagnostics' { $c.PageDiagnostics.Visibility = 'Visible'; if (-not $script:Gui.Diag -and $script:Gui.Runspace) { Start-IgwtGuiDiagRefresh } }
        'Cleaner' { $c.PageCleaner.Visibility = 'Visible' }
        'Disk' { $c.PageDisk.Visibility = 'Visible' }
        'Startup' { $c.PageStartup.Visibility = 'Visible' }
        'Backups' { $c.PageBackups.Visibility = 'Visible'; if (-not $script:Gui.Journal -and $script:Gui.Runspace) { Start-IgwtGuiJournalLoad } }
        'Rejected' { $c.PageRejected.Visibility = 'Visible' }
        'About' { $c.PageAbout.Visibility = 'Visible' }
    }
}

function Add-IgwtGuiStartupMark {
    <# .SYNOPSIS Records how long the window took to reach a startup step (render suite diagnostics, 3.3 phase 7). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not $script:IgwtGuiStartWatch) { return }
    if (-not $script:IgwtGuiStartupMarks) { $script:IgwtGuiStartupMarks = [ordered]@{} }
    $script:IgwtGuiStartupMarks[$Name] = [math]::Round($script:IgwtGuiStartWatch.Elapsed.TotalMilliseconds)
}

function Save-IgwtGuiScreenshots {
    <#
    .SYNOPSIS
        Loads live data synchronously and renders each navigation page of the already-initialized
        window to PNG with RenderTargetBitmap (no window is shown). Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Folder, [double]$Scale = 1.0, [switch]$WithNetworkTest)
    # Offscreen cold-start proxy: module loaded, window and every page built, before the mocked data is set (3.3 phase 7).
    $windowBuiltMs = $(if ($script:IgwtGuiStartWatch) { [math]::Round($script:IgwtGuiStartWatch.Elapsed.TotalMilliseconds) } else { $null })
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder -Force }
    $data = Get-IgwtGuiData -IncludeHealth
    Update-IgwtGuiFromData -Data $data
    # Read-only data for the cleaner and disk analyzer pages (scan deletes nothing).
    Set-IgwtGuiCleanerScan -Scan (Invoke-IgwtCleanerScan -Level Standard)
    # The change journal (read-only).
    Set-IgwtGuiJournal -Timeline (Get-IgwtJournalTimeline)
    # The home card (read-only inputs).
    $script:Gui.HomeInput = Get-IgwtHomeCardInput
    Update-IgwtGuiHomeCard
    $script:Gui.C.DiskPathBox.Text = $script:IgwtProjectRoot
    Update-IgwtGuiDiskLists -Usage (Get-IgwtDiskUsage -Path $script:IgwtProjectRoot -Top 12)
    # Read-only data for the expert inspectors.
    try { Set-IgwtGuiInspection -Inspection (Get-IgwtInspection); if ($script:Gui.Grids.InspectPowerList.Index.Count) { $script:Gui.Grids.InspectPowerList.C.Grid.SelectedIndex = 0 } }
    catch { Write-Warning "Inspector data unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
    # Read-only data for the Manage and Diagnostics pages (no network tests).
    try {
        $script:Gui.Manage = Get-IgwtGuiManageData; Update-IgwtGuiManageLists
        if ($script:Gui.Grids.Service.Index.Count) { $script:Gui.Grids.Service.C.Grid.SelectedIndex = 0 }
        Update-IgwtGuiManageDetail
        Set-IgwtGuiDiagData -Data (Get-IgwtGuiDiagnosticsData)
        # Toolkit lists without the winget inventory (no winget export during screenshots).
        $script:Gui.Toolkit = Get-IgwtGuiToolkitData; Update-IgwtGuiToolkitLists
        if ($script:Gui.Grids.ToolkitAppList.Index.Count) { $script:Gui.Grids.ToolkitAppList.C.Grid.SelectedIndex = 0 }
        Update-IgwtGuiToolkitDetail
    } catch { Write-Warning "Manage/diagnostics data unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
    # Optional: a quick network test (pings and DNS queries only) so the Network Test page shows data.
    if ($WithNetworkTest) { try { Set-IgwtGuiNetResult -Result (Invoke-IgwtNetworkQualityTest -Duration Quick) } catch { Write-Warning "Network test unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" } }
    # Read-only data for the ASR Center (status and the Defender event log).
    try {
        Set-IgwtGuiAsrAudit -Audit (Get-IgwtAsrAudit -Days 7)
        Set-IgwtGuiAsrStatus -Status (Get-IgwtAsrStatus)
        Set-IgwtGuiExploitProtection -Inventory (Get-IgwtExploitProtectionInventory)
        if ($script:Gui.Grids.Asr.Index.Count) { $script:Gui.Grids.Asr.C.Grid.SelectedIndex = 0 }
    } catch { Write-Warning "ASR data unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
    # Read-only data for the Defender settings page.
    try {
        Set-IgwtGuiDefenderData -Settings @(Get-IgwtDefenderSettings)
        if ($script:Gui.Grids.DefList.Index.Count) { $script:Gui.Grids.DefList.C.Grid.SelectedIndex = 0 }
    } catch { Write-Warning "Defender settings unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
    # Read-only data for the Group Policy browser.
    try {
        Set-IgwtGuiPolicyData -Data (Get-IgwtPolicyBrowserData)
        if ($script:Gui.Grids.Policy.Index.Count) { $script:Gui.Grids.Policy.C.Grid.SelectedIndex = 0; Set-IgwtGuiPolicyDetail -Detail (Get-IgwtPolicyBrowserDetail -Id $script:Gui.Grids.Policy.C.Grid.SelectedItem.Id) }
    } catch { Write-Warning "Policy data unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
    # Read-only data for the Firewall Manager (rules and profiles).
    try {
        Set-IgwtGuiFirewallInventory -Inventory (Get-IgwtFirewallAudit)
        Set-IgwtGuiFirewallProfiles -Status (Get-IgwtFirewallProfileStatus)
        if ($script:Gui.Grids.Firewall.Index.Count) { $script:Gui.Grids.Firewall.C.Grid.SelectedIndex = 0 }
    } catch { Write-Warning "Firewall data unavailable for screenshots: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
    $root = $script:Gui.Window.Content
    # Copy the window resources (theme) onto the root so implicit styles still resolve after detaching.
    $rd = New-Object System.Windows.ResourceDictionary
    foreach ($k in @($script:Gui.Window.Resources.Keys)) { $rd.Add($k, $script:Gui.Window.Resources[$k]) }
    $script:Gui.Window.Content = $null
    $root.Resources = $rd
    $root.Background = $script:Gui.Window.FindResource('BrushBackground')
    $root.LayoutTransform = New-Object System.Windows.Media.ScaleTransform($Scale, $Scale)
    # Window size in device-independent pixels: 1280 x 820, or IGWT_RENDER_SIZE (render suite, for example 1100x720).
    $bw = 1280; $bh = 820
    if ([string]$env:IGWT_RENDER_SIZE -match '^(\d{3,4})x(\d{3,4})$') { $bw = [int]$Matches[1]; $bh = [int]$Matches[2] }
    $w = [int]($bw * $Scale); $h = [int]($bh * $Scale)
    $saved = New-Object System.Collections.Generic.List[string]
    $index = 0
    # Page switch time offscreen: from selecting the page to its first complete layout (no paint; 3.3 phase 7).
    $timings = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($script:Gui.C.NavList.Items | Where-Object { -not (Test-IgwtGuiNavHeader -Item $_) })) {
        $page = [string]$item.Tag
        $pageWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $script:Gui.C.NavList.SelectedItem = $item
        Show-IgwtGuiPage -Page $page
        if ($script:IgwtCategories -contains $page -and @($script:Gui.Grids.Tweaks.C.Grid.ItemsSource).Count -gt 0) {
            $script:Gui.Grids.Tweaks.C.Grid.SelectedIndex = 0
            Update-IgwtGuiDetails
        }
        $capture = {
            param($suffix)
            $root.Measure((New-Object System.Windows.Size($w, $h)))
            $root.Arrange((New-Object System.Windows.Rect(0, 0, $w, $h)))
            $root.UpdateLayout()
            if (-not $suffix -and $pageWatch.IsRunning) { $pageWatch.Stop(); $timings.Add([pscustomobject]@{ Page = $page; LayoutMs = [math]::Round($pageWatch.Elapsed.TotalMilliseconds, 1) }) }
            $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($w, $h, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
            $bmp.Render($root)
            $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
            $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bmp))
            $name = ('{0:D2}{3}-{1}-{2}.png' -f $index, ($page -replace '[^A-Za-z]', ''), [int]($Scale * 100), $suffix)
            $file = Join-Path $Folder $name
            $fs = [System.IO.File]::Create($file)
            try { $enc.Save($fs) } finally { $fs.Dispose() }
            $saved.Add($file)
        }
        & $capture ''
        # The dashboard continues below the fold: recent changes and shortcuts.
        if ($page -eq 'Dashboard') {
            $script:Gui.C.PageDashboard.ScrollToVerticalOffset(560)
            & $capture 'b'
            $script:Gui.C.PageDashboard.ScrollToVerticalOffset(0)
        }
        # The Firewall Manager has a second view worth checking: the Rules tab with a rule that has findings.
        if ($page -eq 'Firewall' -and $script:Gui.Grids.Firewall) {
            $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwRulesTab
            $fg = $script:Gui.Grids.Firewall.C.Grid
            $pick = @($fg.ItemsSource | Where-Object { $_.RiskLevel -in 'Critical', 'High' } | Select-Object -First 1)
            if ($pick.Count) { $fg.SelectedItem = $pick[0] } elseif (@($fg.ItemsSource).Count) { $fg.SelectedIndex = 0 }
            & $capture 'b'
            $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwDefaultsTab
            & $capture 'c'
            # The Log tab with a synthetic log (render mocks), newest first, one entry selected.
            $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwLogTab
            try {
                Show-IgwtGuiFirewallLogResult -Result (Read-IgwtFirewallLogSession) -Errors @()
                Update-IgwtGuiFirewallLogOverview
                if (@($script:Gui.Grids.FirewallLog.C.Grid.ItemsSource).Count) { $script:Gui.Grids.FirewallLog.C.Grid.SelectedIndex = 0 }
            } catch { Write-Verbose "Log demo not shown: $($_.Exception.Message)" }
            & $capture 'd'
            $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwForensicTab
            try { Set-IgwtGuiForensicState -State (Get-IgwtForensicLoggingState) } catch { Write-Verbose "Forensic demo not shown: $($_.Exception.Message)" }
            & $capture 'e'
            $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwOverviewTab
        }
        $index++
    }
    $timings.ToArray() | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $Folder 'page-timings.json') -Encoding UTF8
    if ($script:IgwtGuiStartWatch) { [ordered]@{ WindowBuiltMs = $windowBuiltMs; AllPagesMs = [math]::Round($script:IgwtGuiStartWatch.Elapsed.TotalMilliseconds); Steps = $script:IgwtGuiStartupMarks } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Folder 'startup-timing.json') -Encoding UTF8 }
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
    .PARAMETER ReadOnly
        Read-only mode: every apply, revert, clean, install, delete and change path is disabled in
        the engine (including the background worker) and a "Read-only mode" banner is shown.
    .PARAMETER DiagnosticsPath
        Folder for the UI test harness: binding errors, exceptions, UI-thread stalls and a ready marker.
    .PARAMETER Theme
        Dark, Light, HighContrast or System (follow Windows). Without it the saved choice is used.
    #>
    [CmdletBinding()]
    param([string]$ScriptPath, [string]$RenderTo, [double]$Scale = 1.0, [switch]$WithNetworkTest, [switch]$ReadOnly, [string]$DiagnosticsPath,
        [ValidateSet('System', 'Dark', 'Light', 'HighContrast')][string]$Theme)
    if ($ReadOnly) { Set-IgwtEnvironment -ReadOnly }
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
        if (-not $ScriptPath) { throw 'WPF requires an STA thread. Start PowerShell with -STA.' }
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', ('"{0}"' -f $ScriptPath))
        if (Test-IgwtReadOnly) { $relaunch += '-ReadOnly' }
        Start-Process -FilePath (Get-IgwtHostExecutable) -ArgumentList $relaunch
        return
    }
    $script:IgwtGuiStartWatch = [System.Diagnostics.Stopwatch]::StartNew(); $script:IgwtGuiStartupMarks = [ordered]@{}
    # With a window the process keeps a few hundred MB of data: blocking full collections froze the window for
    # 200-300 ms. Sustained low latency uses background collections (the setting is ignored where unsupported).
    if (-not $RenderTo) { try { [System.Runtime.GCSettings]::LatencyMode = [System.Runtime.GCLatencyMode]::SustainedLowLatency } catch { Write-Verbose "GC latency mode not set: $($_.Exception.Message)" } }
    $readOnlyMode = Test-IgwtReadOnly
    Import-IgwtWpf
    $window = New-IgwtMainWindow
    Add-IgwtGuiStartupMark -Name 'xaml'
    $script:Gui = @{
        Window = $window; C = @{}; Data = $null; Staged = @{}; Category = $null; Job = $null; PresetOperation = $null
        Queue = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'); Runspace = $null; IsAdmin = ((Test-IgwtIsAdmin) -and -not $readOnlyMode); ReadOnly = $readOnlyMode
        DiagnosticsPath = $null; LastErrorDetails = ''; CurrentPage = ''; NoStateSave = [bool]$RenderTo; ViewState = $(if ($RenderTo) { @{} } else { Read-IgwtGuiState }); ThemeChoice = 'System'; ReduceMotion = $false; FocusMode = $false; HcHandler = $null
        Catalog = @(Get-IgwtCatalog); Presets = @(Get-IgwtPreset); ScriptPath = $ScriptPath; AllowClose = $false
        CleanRules = $null; CleanScan = $null; CleanSelected = @{}; Cts = $null; DiskSelected = $null
        Defender = $null; DefenderPolicies = $null; DefenderView = 'Prefs'; DefenderStale = $false; AsrStatus = $null; AsrAudit = $null; Inspection = $null; Manage = $null; Toolkit = $null; Drift = $null; SessionActive = $false; Acked = @{}; Persona = $null; NavDefault = $null; Diag = $null; NetResult = $null; Grids = @{}; Jobs = $null; Firewall = $null; FirewallProfiles = $null; FirewallLastSnapshot = $null; Exploit = $null; Management = $null; Policy = $null; PolicyRows = @(); PolicyScope = ''; PolicyDetail = $null; PolicyDetailWanted = ''
    }
    Add-IgwtGuiStartupMark -Name 'catalog'
    foreach ($n in $script:IgwtGuiControlNames) {
        $ctl = $window.FindName($n)
        if (-not $ctl) { throw "Control '$n' not found in MainWindow.xaml." }
        $script:Gui.C[$n] = $ctl
    }
    Add-IgwtGuiStartupMark -Name 'controls'
    $c = $script:Gui.C
    Initialize-IgwtGuiDisplay -Theme $Theme
    Add-IgwtGuiStartupMark -Name 'display'
    Initialize-IgwtGuiChrome
    Initialize-IgwtGuiManageGrids
    Add-IgwtGuiStartupMark -Name 'manageGrids'
    Initialize-IgwtGuiListGrids
    Add-IgwtGuiStartupMark -Name 'listGrids'
    Initialize-IgwtGuiDiagGrids
    Initialize-IgwtGuiJournalGrid
    Add-IgwtGuiStartupMark -Name 'diagGrids'
    Initialize-IgwtGuiFirewallPage
    Add-IgwtGuiStartupMark -Name 'firewall'
    Initialize-IgwtGuiAsrPage
    Add-IgwtGuiStartupMark -Name 'asr'
    Initialize-IgwtGuiPolicyPage
    Add-IgwtGuiStartupMark -Name 'policy'
    $c.HeaderVersion.Text = "v$script:IgwtVersion  |  Gaming performance and security toolbox"
    $c.AboutText.Text = Get-IgwtAboutText
    $c.AboutBuildText.Text = Get-IgwtGuiBuildInfo
    Register-IgwtGuiHandler -Control $c.AboutCopyButton -Event 'Click' -Handler { [System.Windows.Clipboard]::SetText($script:Gui.C.AboutBuildText.Text); Set-IgwtGuiStatus 'Build information copied.' }
    # The changelog and notices are read when first opened (files of the installed copy).
    Register-IgwtGuiHandler -Control $c.AboutChangelogExpander -Event 'Expanded' -Handler { if (-not $script:Gui.C.AboutChangelogText.Text) { $script:Gui.C.AboutChangelogText.Text = Get-IgwtGuiDocText -Name 'docs\CHANGELOG.md' -MaxChars 60000 } }
    Register-IgwtGuiHandler -Control $c.AboutNoticesExpander -Event 'Expanded' -Handler { if (-not $script:Gui.C.AboutNoticesText.Text) { $script:Gui.C.AboutNoticesText.Text = (Get-IgwtGuiDocText -Name 'LICENSE') + [Environment]::NewLine + [Environment]::NewLine + (Get-IgwtGuiDocText -Name 'THIRD_PARTY_NOTICES.md') } }
    $rejected = @(Get-IgwtRejectedTweaks)
    Set-IgwtGuiGridRows -Name 'RejectedList' -Rows @($rejected | ForEach-Object { New-IgwtGuiRejectedRow -Entry $_ })
    $c.RejectedSummaryText.Text = "$($rejected.Count) popular tweaks are not offered; $(@($rejected | Where-Object { $_.riskItem }).Count) of them can be applied at your own risk from the Risk Zone."
    $c.AdminText.Text = $(if ($script:Gui.ReadOnly) { 'Read-only mode' } elseif ($script:Gui.IsAdmin) { 'Administrator' } else { 'Read-only (not elevated)' })
    $c.ElevateButton.Visibility = $(if ($script:Gui.IsAdmin -or $script:Gui.ReadOnly) { 'Collapsed' } else { 'Visible' })
    if ($script:Gui.ReadOnly) {
        $c.ReadOnlyBannerText.Text = 'Read-only mode: you can browse, sort, filter, preview and export. Apply, revert, clean, install, delete and every other change are turned off (started with -ReadOnly).'
        $c.ReadOnlyBanner.Visibility = 'Visible'
    } elseif (-not $script:Gui.IsAdmin) {
        $c.ReadOnlyBannerText.Text = 'Not running as administrator: you can browse, preview and export, and clean your own temp files. Use "Restart as administrator" to apply, revert or change settings.'
        $c.ReadOnlyBanner.Visibility = 'Visible'
    }
    Register-IgwtGuiHandler -Control $c.ErrorDismissButton -Event 'Click' -Handler { $script:Gui.C.ErrorBar.Visibility = 'Collapsed' }
    Register-IgwtGuiHandler -Control $c.ErrorCopyButton -Event 'Click' -Handler { try { [System.Windows.Clipboard]::SetText([string]$script:Gui.LastErrorDetails); Set-IgwtGuiStatus 'Error details copied.' } catch { Set-IgwtGuiStatus 'The clipboard is not available.' } }
    Initialize-IgwtGuiDiagnostics -Path $DiagnosticsPath
    Update-IgwtGuiPresetCards

    # Persona
    $c.PersonaBox.ItemsSource = @('Gamer', 'PowerUser', 'Sysadmin')
    $c.PersonaBox.SelectedItem = (Get-IgwtPersona)
    Set-IgwtGuiPersona -Name ([string]$c.PersonaBox.SelectedItem)
    Add-IgwtGuiStartupMark -Name 'persona'
    Register-IgwtGuiHandler -Control $c.PersonaBox -Event 'SelectionChanged' -Handler {
            $n = [string]$script:Gui.C.PersonaBox.SelectedItem
            if (-not $n -or ($script:Gui.Persona -and $script:Gui.Persona.Name -eq $n)) { return }
            if (Test-IgwtReadOnly) { Set-IgwtGuiStatus "Persona: $n for this window (read-only mode: not saved)." } else { try { Set-IgwtPersona -Name $n } catch { Write-Verbose "Persona not saved: $($_.Exception.Message)" } }
            Set-IgwtGuiPersona -Name $n
        }

    # Navigation and page wiring
    Register-IgwtGuiHandler -Control $c.NavList -Event 'SelectionChanged' -Handler { $item = $script:Gui.C.NavList.SelectedItem; if ($item -and -not (Test-IgwtGuiNavHeader -Item $item)) { Show-IgwtGuiPage -Page ([string]$item.Tag) } }
    Register-IgwtGuiHandler -Control $c.SecAsrButton -Event 'Click' -Handler { $it = @($script:Gui.C.NavList.Items | Where-Object { [string]$_.Tag -eq 'Asr' }) | Select-Object -First 1; if ($it) { $script:Gui.C.NavList.SelectedItem = $it } }
    Register-IgwtGuiHandler -Control $c.AsrHardeningButton -Event 'Click' -Handler { $it = @($script:Gui.C.NavList.Items | Where-Object { [string]$_.Tag -eq 'Security' }) | Select-Object -First 1; if ($it) { $script:Gui.C.NavList.SelectedItem = $it } }
    Register-IgwtGuiHandler -Control $c.SecDefenderButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Defender' }
    Register-IgwtGuiHandler -Control $c.AsrDefenderButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Defender' }
    Register-IgwtGuiHandler -Control $c.DefHardeningButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Security' }
    Register-IgwtGuiHandler -Control $c.DefAsrButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Asr' }
    # Focus mode from the previous session.
    Set-IgwtGuiFocusMode -On ([bool]$script:Gui.ViewState.FocusMode) -NoSave
    Register-IgwtGuiHandler -Control $c.FocusModeBox -Event 'Click' -Handler { Set-IgwtGuiFocusMode -On ([bool]$script:Gui.C.FocusModeBox.IsChecked) }
    Register-IgwtGuiHandler -Control $c.FocusPill -Event 'Click' -Handler { Set-IgwtGuiFocusMode -On $false }
    # 3.6 (DECISIONS T18): the Dashboard with the home card is the landing page; lists still remember their views.
    Select-IgwtGuiNavPage -Tag 'Dashboard'
    Initialize-IgwtGuiTweakGrid
    Add-IgwtGuiStartupMark -Name 'tweakGrid'
    Update-IgwtGuiNetHistory
    Initialize-IgwtGuiCompliance
    Add-IgwtGuiStartupMark -Name 'compliance'
    Register-IgwtGuiHandler -Control $c.DashRecentList -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($eventSource, $e)
            $null = $eventSource
            if ($e.OriginalSource -is [System.Windows.Controls.Button] -and [string]$e.OriginalSource.Tag) { Invoke-IgwtGuiRevert -SnapshotPath ([string]$e.OriginalSource.Tag) }
        }
    Register-IgwtGuiHandler -Control $c.DashAllChangesButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Backups' }
    # The log is read the first time its tab opens (and with the grid's Refresh).
    Register-IgwtGuiHandler -Control $c.BackupTabs -Event 'SelectionChanged' -Handler {
        param($s, $e)
        if (-not [object]::ReferenceEquals($e.OriginalSource, $s)) { return }
        if ($script:Gui.C.BackupTabs.SelectedItem -eq $script:Gui.C.BackupLogTab -and -not $script:Gui.LogLoaded) { $script:Gui.LogLoaded = $true; Start-IgwtGuiLogLoad }
    }
    Register-IgwtGuiHandler -Control $c.DetSources -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($eventSource, $e)
            if ($e.OriginalSource -is [System.Windows.Controls.Button]) { Open-IgwtGuiPath -Target ([string]$e.OriginalSource.Tag) }
        }
    Register-IgwtGuiHandler -Control $c.DetResetButton -Event 'Click' -Handler {
            $row = (Get-IgwtGuiGridItem -Name Tweaks)
            if ($row) { Set-IgwtGuiStage -Id $row.Id -Mode 'reset'; Update-IgwtGuiTweakList; Set-IgwtGuiStatus "Staged: reset '$($row.Id)' to the Windows default." }
        }
    Register-IgwtGuiHandler -Control $c.PresetCards -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($eventSource, $e)
            $btn = $e.OriginalSource
            if (-not ($btn -is [System.Windows.Controls.Button])) { return }
            $tag = [string]$btn.Tag
            if ($tag.StartsWith('compare:')) {
                $cmp = $script:Gui.Presets | Where-Object { $_.id -eq $tag.Substring(8) } | Select-Object -First 1
                if ($cmp -and $script:Gui.Data -and (Show-IgwtGuiPresetCompare -Preset $cmp) -and $script:Gui.IsAdmin) { $tag = [string]$cmp.id } else { return }
            }
            if (-not $script:Gui.IsAdmin) { $null = Show-IgwtGuiMessage -Text ((Get-IgwtGuiChangeBlockReason -What 'stage and apply presets') + ' You can still compare presets and preview tweaks.'); return }
            $preset = $script:Gui.Presets | Where-Object { $_.id -eq $tag } | Select-Object -First 1
            if (-not $preset -or -not $script:Gui.Data) { return }
            # 3.6: the preview first (will change, already set, not applicable, conflict, managed by policy).
            Start-IgwtGuiPresetPreview -Preset $preset
        }
    Register-IgwtGuiHandler -Control $c.PresetPickBox -Event 'SelectionChanged' -Handler { Update-IgwtGuiButtons }
    Register-IgwtGuiHandler -Control $c.PresetCustomizeButton -Event 'Click' -Handler { Invoke-IgwtGuiPresetAction -Action Customize }
    Register-IgwtGuiHandler -Control $c.PresetDuplicateButton -Event 'Click' -Handler { Invoke-IgwtGuiPresetAction -Action Duplicate }
    Register-IgwtGuiHandler -Control $c.PresetExportButton -Event 'Click' -Handler { Invoke-IgwtGuiPresetAction -Action Export }
    Register-IgwtGuiHandler -Control $c.PresetImportButton -Event 'Click' -Handler { Invoke-IgwtGuiPresetAction -Action Import }
    Register-IgwtGuiHandler -Control $c.PresetDeleteButton -Event 'Click' -Handler { Invoke-IgwtGuiPresetAction -Action Delete }
    Register-IgwtGuiHandler -Control $c.PresetDriftAdoptButton -Event 'Click' -Handler { Invoke-IgwtGuiPresetAction -Action Adopt }
    Register-IgwtGuiHandler -Control $c.PresetDriftReapplyButton -Event 'Click' -Handler {
            $d = $script:Gui.Drift
            if (-not $d) { return }
            $script:Gui.Staged.Clear()
            foreach ($id in @($d.Drifted)) {
                $dt = $script:Gui.Catalog | Where-Object { $_.id -eq [string]$id } | Select-Object -First 1
                if ($dt -and -not $dt.expert -and [string]$dt.evidence.tier -ne 'R') { Set-IgwtGuiStage -Id ([string]$id) -Mode 'on' }
            }
            $script:Gui.PresetOperation = "Preset:$($d.Preset)"
            Update-IgwtGuiPending
            Set-IgwtGuiStatus "Staged $(@($d.Drifted).Count) change(s) to re-apply $($d.Name). Preview or Apply."
        }
    Register-IgwtGuiHandler -Control $c.SessionStartButton -Event 'Click' -Handler { Start-IgwtGuiSession }
    Register-IgwtGuiHandler -Control $c.SessionStopButton -Event 'Click' -Handler { Stop-IgwtGuiSession }
    Register-IgwtGuiHandler -Control $c.PreviewButton -Event 'Click' -Handler { Invoke-IgwtGuiPreview }
    Register-IgwtGuiHandler -Control $c.ApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiApply }
    Register-IgwtGuiHandler -Control $c.DiscardButton -Event 'Click' -Handler { $script:Gui.Staged.Clear(); $script:Gui.PresetOperation = $null; Update-IgwtGuiTweakList; Set-IgwtGuiStatus 'All staged changes discarded.' }
    Register-IgwtGuiHandler -Control $c.RefreshButton -Event 'Click' -Handler { Start-IgwtGuiRefresh -IncludeHealth }
    Register-IgwtGuiHandler -Control $c.BusyCancelButton -Event 'Click' -Handler { Stop-IgwtGuiReadJobs }
    Register-IgwtGuiHandler -Control $c.ExportReportButton -Event 'Click' -Handler {
            $null = Start-IgwtGuiJob -Command 'Export-IgwtGuiReport' -BusyText 'Writing HTML report...' -OnComplete {
                param($out, $errs)
                $path = [string](@($out) | Select-Object -Last 1)
                if ($path -and (Test-Path -LiteralPath $path)) { Set-IgwtGuiStatus "Report saved: $path"; Open-IgwtGuiPath -Target $path }
            }
        }
    Register-IgwtGuiHandler -Control $c.ElevateButton -Event 'Click' -Handler { Invoke-IgwtGuiElevate }
    Register-IgwtGuiHandler -Control $c.RevertLastButton -Event 'Click' -Handler { Invoke-IgwtGuiRevert -Last }
    Register-IgwtGuiHandler -Control $c.BackupRevertLastButton -Event 'Click' -Handler { Invoke-IgwtGuiRevert -Last }
    Register-IgwtGuiHandler -Control $c.JournalRevertEntryButton -Event 'Click' -Handler { Start-IgwtGuiJournalRevert -Scope Entry }
    # Home card (3.6): Do it opens a preview or a page; Not now for 1 or 7 days; Why?; the list of every page.
    Register-IgwtGuiHandler -Control $c.HomeCardDoButton -Event 'Click' -Handler { Invoke-IgwtGuiHomeAction }
    Register-IgwtGuiHandler -Control $c.HomeCardSnoozeButton -Event 'Click' -Handler { Set-IgwtGuiHomeSnooze -Days 1 }
    Register-IgwtGuiHandler -Control $c.HomeCardSnoozeWeekButton -Event 'Click' -Handler { Set-IgwtGuiHomeSnooze -Days 7 }
    Register-IgwtGuiHandler -Control $c.HomeCardWhyButton -Event 'Click' -Handler { Show-IgwtGuiHomeWhy }
    Register-IgwtGuiHandler -Control $c.HomeCardPagesButton -Event 'Click' -Handler { Show-IgwtGuiAllPages }
    Register-IgwtGuiHandler -Control $c.JournalRevertSessionButton -Event 'Click' -Handler { Start-IgwtGuiJournalRevert -Scope Session }
    Register-IgwtGuiHandler -Control $c.JournalRevertAllButton -Event 'Click' -Handler { Start-IgwtGuiJournalRevert -Scope All }
    Register-IgwtGuiHandler -Control $c.BackupRevertSelectedButton -Event 'Click' -Handler {
            $sel = (Get-IgwtGuiGridItem -Name SnapshotList)
            if ($sel) { Invoke-IgwtGuiRevert -SnapshotPath $sel.Path } else { Set-IgwtGuiStatus 'Select a snapshot first.' }
        }
    Register-IgwtGuiHandler -Control $c.RevertSnapshotButton -Event 'Click' -Handler {
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Filter = 'iG Windows Tuner snapshot (snapshot-*.json)|snapshot-*.json'
            $dlg.InitialDirectory = Get-IgwtDataPath -Kind Backups
            if ($dlg.ShowDialog($script:Gui.Window)) { Invoke-IgwtGuiRevert -SnapshotPath $dlg.FileName }
        }
    Register-IgwtGuiHandler -Control $c.ResetStagedButton -Event 'Click' -Handler {
            $row = (Get-IgwtGuiGridItem -Name Tweaks)
            if ($row) { Set-IgwtGuiStage -Id $row.Id -Mode 'reset'; Update-IgwtGuiTweakList; Set-IgwtGuiStatus "Staged: reset '$($row.Id)' to the Windows default." }
            else { Set-IgwtGuiStatus 'Select a tweak on a category page first, then use this button (or the button in its details pane).' }
        }
    Register-IgwtGuiHandler -Control $c.OpenBackupsButton -Event 'Click' -Handler { $p = Get-IgwtDataPath -Kind Backups; if (Test-Path -LiteralPath $p) { Open-IgwtGuiPath -Target $p } else { Set-IgwtGuiStatus 'No backups yet.' } }
    Register-IgwtGuiHandler -Control $c.OpenLogsButton -Event 'Click' -Handler { $p = Get-IgwtDataPath -Kind Logs; if (Test-Path -LiteralPath $p) { Open-IgwtGuiPath -Target $p } else { Set-IgwtGuiStatus 'No logs yet.' } }
    # Cleaner and disk analyzer
    $c.DiskPathBox.Text = "$env:SystemDrive\"
    $c.CleanSummaryText.Text = 'No scan yet. Press Scan to see what can be cleaned (nothing is deleted).'
    Register-IgwtGuiHandler -Control $c.CleanScanButton -Event 'Click' -Handler { Start-IgwtGuiCleanerScan }
    Register-IgwtGuiHandler -Control $c.CleanRunButton -Event 'Click' -Handler { Invoke-IgwtGuiCleanerClean }
    Register-IgwtGuiHandler -Control $c.CleanCancelButton -Event 'Click' -Handler { if ($script:Gui.Cts) { $script:Gui.Cts.Cancel(); Set-IgwtGuiStatus 'Cancelling after the current file...' } }
    Register-IgwtGuiHandler -Control $script:Gui.Grids.CleanerList.Root -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($eventSource, $e)
            $cb = $e.OriginalSource
            if (-not ($cb -is [System.Windows.Controls.CheckBox]) -or -not $cb.Tag) { return }
            $script:Gui.CleanSelected[[string]$cb.Tag] = [bool]$cb.IsChecked
            # Keep the row and the "Ticked" chip in step with the box (the binding is one-way).
            if ($cb.DataContext -and $cb.DataContext.PSObject.Properties['On']) { $cb.DataContext.On = [bool]$cb.IsChecked; $cb.DataContext.Selected = [bool]$cb.IsChecked }
            $g = $script:Gui.Grids.CleanerList
            if ($g) { $null = $g.Index.Chips.Remove('ticked') }
            Update-IgwtGuiCleanerSummary
        }
    Register-IgwtGuiHandler -Control $c.DiskAnalyzeButton -Event 'Click' -Handler { Start-IgwtGuiDiskAnalyze }
    Register-IgwtGuiHandler -Control $c.DiskCancelButton -Event 'Click' -Handler { if ($script:Gui.Cts) { $script:Gui.Cts.Cancel(); Set-IgwtGuiStatus 'Cancelling the analysis...' } }
    Register-IgwtGuiHandler -Control $c.DiskPathBox -Event 'KeyDown' -Handler { param($eventSource, $e) if ($e.Key -eq 'Return') { Start-IgwtGuiDiskAnalyze; $e.Handled = $true } }
    Register-IgwtGuiHandler -Control $c.DiskOpenButton -Event 'Click' -Handler { if ($script:Gui.DiskSelected) { Show-IgwtGuiInExplorer -Path $script:Gui.DiskSelected } else { Set-IgwtGuiStatus 'Select a folder or file first.' } }
    # Expert inspectors
    Register-IgwtGuiHandler -Control $c.InspectRefreshButton -Event 'Click' -Handler { Start-IgwtGuiInspect }
    Register-IgwtGuiHandler -Control $c.InspectPowerAllBox -Event 'Click' -Handler { Update-IgwtGuiPowerList }
    Register-IgwtGuiHandler -Control $c.InspectPowerApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiPowerChange }
    Register-IgwtGuiHandler -Control $c.InspectPowerDefaultButton -Event 'Click' -Handler { Invoke-IgwtGuiPowerChange -Default }
    Register-IgwtGuiHandler -Control $c.InspectKernelChangedBox -Event 'Click' -Handler { Update-IgwtGuiKernelList }
    # Manage
    $c.ManageServiceStartBox.ItemsSource = @('Automatic', 'AutomaticDelayed', 'Manual', 'Disabled')
    Register-IgwtGuiHandler -Control $c.ManageRefreshButton -Event 'Click' -Handler { Start-IgwtGuiManageRefresh }
    Register-IgwtGuiHandler -Control $c.ManageOpenFirewallButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Firewall' }
    Register-IgwtGuiHandler -Control $c.SecFirewallButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Firewall' }
    # Toolkit
    Register-IgwtGuiHandler -Control $c.ToolkitRefreshButton -Event 'Click' -Handler { Start-IgwtGuiToolkitRefresh -WithAppState:([bool]($script:Gui.Toolkit -and $script:Gui.Toolkit.AppState)) }
    Register-IgwtGuiHandler -Control $c.ToolkitAppStateButton -Event 'Click' -Handler { if (Test-IgwtReadOnly) { return }; Start-IgwtGuiToolkitRefresh -WithAppState }
    Register-IgwtGuiHandler -Control $c.ToolkitInstallButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitApps -Operation Install }
    Register-IgwtGuiHandler -Control $c.ToolkitUpgradeButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitApps -Operation Upgrade }
    Register-IgwtGuiHandler -Control $c.ToolkitUninstallButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitApps -Operation Uninstall }
    Register-IgwtGuiHandler -Control $c.ToolkitUpgradeAllButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitApps -Operation UpgradeAll }
    Register-IgwtGuiHandler -Control $c.ToolkitExportButton -Event 'Click' -Handler { Export-IgwtGuiAppSelection }
    Register-IgwtGuiHandler -Control $c.ToolkitImportButton -Event 'Click' -Handler { Import-IgwtGuiAppSelection }
    Register-IgwtGuiHandler -Control $c.ToolkitFeatureEnableButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitFeature -State Enabled }
    Register-IgwtGuiHandler -Control $c.ToolkitFeatureDisableButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitFeature -State Disabled }
    Register-IgwtGuiHandler -Control $c.ToolkitFixRunButton -Event 'Click' -Handler { Invoke-IgwtGuiToolkitFix }
    Register-IgwtGuiHandler -Control $c.ToolkitPanelOpenButton -Event 'Click' -Handler {
            $row = (Get-IgwtGuiGridItem -Name ToolkitPanelList)
            if ($row) { try { Start-IgwtPanel -Id ([string]$row.Source.Id) } catch { $null = Show-IgwtGuiMessage -Text $_.Exception.Message -Icon 'Warning' } }
        }
    Register-IgwtGuiHandler -Control $c.ToolkitTweakGoButton -Event 'Click' -Handler { $row = (Get-IgwtGuiGridItem -Name ToolkitTweakList); if ($row) { Show-IgwtGuiTweakInCategory -Id ([string]$row.Source.id) } }
    Register-IgwtGuiHandler -Control $c.ToolkitUpdateGoButton -Event 'Click' -Handler { $row = (Get-IgwtGuiGridItem -Name ToolkitUpdateList); if ($row) { Show-IgwtGuiTweakInCategory -Id ([string]$row.Source.id) } }
    Register-IgwtGuiHandler -Control $c.ToolkitUpdatePauseButton -Event 'Click' -Handler { try { Start-IgwtPanel -Id 'panel.windows-update' } catch { $null = Show-IgwtGuiMessage -Text $_.Exception.Message -Icon 'Warning' } }
    Register-IgwtGuiHandler -Control $c.ManageServiceStartBox -Event 'SelectionChanged' -Handler { Update-IgwtGuiButtons }
    Register-IgwtGuiHandler -Control $c.ManageServiceApplyButton -Event 'Click' -Handler {
            $row = Get-IgwtGuiGridItem -Name Service; $v = [string]$script:Gui.C.ManageServiceStartBox.SelectedItem
            if ($row -and $v) { Invoke-IgwtGuiManagedChange -Kind service -Target ([string]$row.Source.Name) -Value $v }
        }
    Register-IgwtGuiHandler -Control $c.ManageTaskDisableButton -Event 'Click' -Handler { $row = Get-IgwtGuiGridItem -Name Task; if ($row) { Invoke-IgwtGuiManagedChange -Kind task -Target ([string]$row.Source.Path) -Value 'Disabled' } }
    Register-IgwtGuiHandler -Control $c.ManageTaskEnableButton -Event 'Click' -Handler { $row = Get-IgwtGuiGridItem -Name Task; if ($row) { Invoke-IgwtGuiManagedChange -Kind task -Target ([string]$row.Source.Path) -Value 'Enabled' } }
    Register-IgwtGuiHandler -Control $c.ManageAppRemoveButton -Event 'Click' -Handler { $row = Get-IgwtGuiGridItem -Name App; if ($row) { Invoke-IgwtGuiManagedChange -Kind appx -Target ([string]$row.Source.Name) -Value 'Removed' -Provisioned:([bool]$script:Gui.C.ManageAppProvisionedBox.IsChecked) } }
    Register-IgwtGuiHandler -Control $c.ManagePersistDisableButton -Event 'Click' -Handler { Invoke-IgwtGuiPersistenceDisable }
    Register-IgwtGuiHandler -Control $c.ManagePersistExportButton -Event 'Click' -Handler { Export-IgwtGuiPersistence }
    # Network test
    $c.NetDurationBox.ItemsSource = @('Quick (10 seconds)', 'Standard (30 seconds)', 'Extended (2 minutes)')
    $c.NetDurationBox.SelectedIndex = 1
    Register-IgwtGuiHandler -Control $c.NetRunButton -Event 'Click' -Handler { Start-IgwtGuiNetTest }
    Register-IgwtGuiHandler -Control $c.NetLoadButton -Event 'Click' -Handler { Start-IgwtGuiNetLoad }
    Register-IgwtGuiHandler -Control $c.NetApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiNetApply }
    Register-IgwtGuiHandler -Control $c.NetExportButton -Event 'Click' -Handler { Export-IgwtGuiNetReport }
    # Diagnostics and network
    Register-IgwtGuiHandler -Control $c.DiagRefreshButton -Event 'Click' -Handler { Start-IgwtGuiDiagRefresh }
    Register-IgwtGuiHandler -Control $c.DiagDnsButton -Event 'Click' -Handler { Start-IgwtGuiNetworkTest -Dns }
    Register-IgwtGuiHandler -Control $c.DiagLatencyButton -Event 'Click' -Handler { Start-IgwtGuiNetworkTest }
    Register-IgwtGuiHandler -Control $c.DiagReportButton -Event 'Click' -Handler {
            $null = Start-IgwtGuiJob -Command 'Export-IgwtGuiSystemReport' -BusyText 'Writing the full system report (read-only; about a minute)...' -OnComplete {
                param($out, $errs)
                $path = [string](@($out) | Select-Object -Last 1)
                if ($path -and (Test-Path -LiteralPath $path)) { Set-IgwtGuiStatus "System report saved: $path"; Open-IgwtGuiPath -Target $path }
                elseif (@($errs).Count) { $null = Show-IgwtGuiMessage -Text "The report was not written: $(@($errs)[0])" -Icon 'Error' }
            }
        }
    # Security > Defender settings
    $script:Gui.DefenderView = 'Prefs'
    $c.DefCategoryBox.DisplayMemberPath = 'Name'
    $c.DefCategoryBox.ItemsSource = @(@([pscustomobject]@{ Id = ''; Name = 'All categories' }) + @((Get-IgwtDefenderSettingCatalog).categories | ForEach-Object { [pscustomobject]@{ Id = [string]$_.id; Name = [string]$_.name } }))
    $c.DefCategoryBox.SelectedIndex = 0
    $c.DefPolicyStateBox.DisplayMemberPath = 'Label'
    Register-IgwtGuiHandler -Control $c.DefCategoryBox -Event 'SelectionChanged' -Handler { Update-IgwtGuiDefenderLists }
    Register-IgwtGuiHandler -Control $c.DefValueBox -Event 'SelectionChanged' -Handler {
        # A value that is not allowed shows its reason under the box (no dialog) and keeps Apply off.
        $pick = $script:Gui.C.DefValueBox.SelectedItem
        $script:Gui.C.DefValueHelp.Text = $(if ($pick -and -not $pick.Allowed) { "Not allowed: $($pick.Why)`n$($script:Gui.DefValueBaseHelp)" } else { [string]$script:Gui.DefValueBaseHelp })
        Update-IgwtGuiButtons
    }
    Register-IgwtGuiHandler -Control $c.DefPolicyStateBox -Event 'SelectionChanged' -Handler { Update-IgwtGuiDefenderPolicyHelp }
    Register-IgwtGuiHandler -Control $c.DefPrefsViewButton -Event 'Click' -Handler { Set-IgwtGuiDefenderView -View 'Prefs' }
    Register-IgwtGuiHandler -Control $c.DefPolicyViewButton -Event 'Click' -Handler { Set-IgwtGuiDefenderView -View 'Policy' }
    Register-IgwtGuiHandler -Control $c.DefRefreshButton -Event 'Click' -Handler { if ($script:Gui.DefenderView -eq 'Policy') { Start-IgwtGuiDefenderRefresh -Policies } else { Start-IgwtGuiDefenderRefresh } }
    Register-IgwtGuiHandler -Control $c.DefApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiDefenderChange }
    Register-IgwtGuiHandler -Control $c.DefRecommendButton -Event 'Click' -Handler { Select-IgwtGuiDefenderRecommended }
    Register-IgwtGuiHandler -Control $c.DefPolicyApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiDefenderPolicyChange }
    Register-IgwtGuiHandler -Control $c.DefDocButton -Event 'Click' -Handler { $u = [string]$script:Gui.C.DefDocButton.Tag; if ($u) { Open-IgwtGuiPath -Target $u } }
    Register-IgwtGuiHandler -Control $c.StartupRefreshButton -Event 'Click' -Handler { Start-IgwtGuiRefresh }
    Register-IgwtGuiHandler -Control $script:Gui.Grids.StartupList.Root -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
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
        }

    # Keyboard: Ctrl+F search, F5 refresh
    Register-IgwtGuiHandler -Control $window -Event 'KeyDown' -Handler {
            param($eventSource, $e)
            if ($e.Key -eq 'F5') { Start-IgwtGuiRefresh -IncludeHealth; $e.Handled = $true }
            elseif ($e.Key -eq 'F' -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
                if ($script:Gui.C.PageTweaks.Visibility -ne 'Visible') { Select-IgwtGuiNavPage -Tag 'Power & CPU' }
                $null = $script:Gui.Grids.Tweaks.C.SearchBox.Focus(); $e.Handled = $true
            }
        }
    Register-IgwtGuiHandler -Control $window -Event 'Closed' -Handler { try { Save-IgwtGridAllViews } catch { Write-Verbose "Views not saved: $($_.Exception.Message)" } }
    Register-IgwtGuiHandler -Control $window -Event 'Closing' -Handler {
            param($eventSource, $e)
            if ($script:Gui.Job -and $script:Gui.Job.Blocking -and -not $script:Gui.AllowClose) {
                $null = Show-IgwtGuiMessage -Text 'An apply, revert or clean is in progress. Please wait until it finishes.' -Icon 'Warning'
                $e.Cancel = $true
                return
            }
            if (-not $e.Cancel -and $script:Gui.IsAdmin) {
                try {
                    $st = Get-IgwtSessionState
                    if ($st.Active -and $st.Owner -eq 'gui' -and -not $st.Stale -and $st.OwnerPid -eq $PID) { $null = Stop-IgwtSession }
                } catch { $null = Show-IgwtGuiMessage -Text "Session Mode could not be ended: $($_.Exception.Message). Use -Session Stop." -Icon 'Warning' }
            }
        }

    if ($RenderTo) {
        try { Save-IgwtGuiScreenshots -Folder $RenderTo -Scale $Scale -WithNetworkTest:$WithNetworkTest }
        finally { if ($script:Gui.HcHandler) { [System.Windows.SystemParameters]::remove_StaticPropertyChanged($script:Gui.HcHandler) } }
        return
    }

    # Worker + timer
    Initialize-IgwtGuiWorker -Async
    # Domain/MDM management is read once in the background; the change dialogs use it.
    Invoke-IgwtGuiWhenWorkerReady -Action { $null = Start-IgwtGuiJob -Command 'Get-IgwtManagementState' -Channel 'mgmt' -BusyText 'Reading how this PC is managed (read-only)...' -OnComplete { param($out, $errs) $null = $errs; $script:Gui.Management = @($out) | Select-Object -Last 1 } }
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    Register-IgwtGuiHandler -Control $timer -Event 'Tick' -Handler { Invoke-IgwtGuiTick }
    $timer.Start()
    Register-IgwtGuiHandler -Control $window -Event 'ContentRendered' -Handler {
            try {
                $st = Get-IgwtSessionState
                if ($st.Stale) {
                    $msg = "A Session Mode session from $(if ($st.Started) { $st.Started.ToLocalTime().ToString('g') }) was not ended: $($st.Reason)`n`nRestore your settings from the session snapshot now?"
                    if ((Show-IgwtGuiMessage -Text $msg -Title 'iG Windows Tuner - Session Mode' -Buttons 'YesNo' -Icon 'Question') -eq 'Yes') {
                        if ($script:Gui.IsAdmin) { Stop-IgwtGuiSession; return } else { $null = Show-IgwtGuiMessage -Text 'Restart as administrator, then end the session on the Presets page.' }
                    }
                }
            } catch { Write-Verbose "Session check failed: $($_.Exception.Message)" }
            Invoke-IgwtGuiWhenWorkerReady -Action { Start-IgwtGuiRefresh -IncludeHealth }
        }
    Update-IgwtGuiButtons

    # Test harness: open without taking the keyboard focus from whoever uses the PC.
    if ($env:IGWT_GUI_NOACTIVATE -eq '1') { $window.ShowActivated = $false }
    try {
        $null = $window.ShowDialog()
    } finally {
        $timer.Stop()
        if ($script:Gui.HcHandler) { [System.Windows.SystemParameters]::remove_StaticPropertyChanged($script:Gui.HcHandler) }
        foreach ($j in $(if ($script:Gui.Jobs) { $script:Gui.Jobs.ToArray() } else { @() })) { try { $null = $j.PS.BeginStop($null, $null) } catch { Write-Verbose "Job not stopped: $($_.Exception.Message)" } }
        foreach ($wp in @($(if ($script:Gui.Pools) { $script:Gui.Pools } elseif ($script:Gui.Runspace) { $script:Gui.Runspace }))) { try { $wp.Close(); $wp.Dispose() } catch { Write-Verbose 'Worker runspace already closed.' } }
    }
}
