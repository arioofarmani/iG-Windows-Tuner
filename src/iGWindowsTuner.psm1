# iGWindowsTuner.psm1
# Loads the iG Windows Tuner engine. Plain, readable PowerShell: every source file below is
# dot-sourced from this folder; nothing is downloaded, decoded or generated at runtime.

$script:IgwtModuleRoot = $PSScriptRoot
$script:IgwtProjectRoot = Split-Path -Parent $PSScriptRoot

$folders = @('Core', 'Actions', 'Health', 'Hardware', 'Cleaner', 'Security', 'Inspectors', 'Manage', 'Network', 'Policy', 'Toolkit', 'Gui')
foreach ($folder in $folders) {
    $path = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path -LiteralPath $path)) { continue }
    foreach ($file in (Get-ChildItem -LiteralPath $path -Filter '*.ps1' -File | Sort-Object Name)) {
        . $file.FullName
    }
}

Export-ModuleMember -Function (
    'Get-IgwtCatalog', 'Get-IgwtTweak', 'Get-IgwtPreset', 'Get-IgwtGameDefinitions', 'Get-IgwtInstalledGames', 'Get-IgwtRejectedTweaks',
    'Test-IgwtCatalog', 'Get-IgwtTweakRevertDescription',
    'New-IgwtContext', 'Get-IgwtTweakState', 'Get-IgwtAllTweakStates', 'Get-IgwtPlan', 'Get-IgwtPresetPlan',
    'Invoke-IgwtApply', 'Invoke-IgwtRevert', 'Get-IgwtSnapshotList',
    'Get-IgwtHealthReport', 'Format-IgwtHealthReport', 'Export-IgwtHealthReport', 'Get-IgwtHardwareSummary', 'Get-IgwtAntiCheatReadiness',
    'Get-IgwtNvidiaGuidance', 'Get-IgwtOsInfo', 'Get-IgwtPreflight', 'Get-IgwtPendingRestartState',
    'Test-IgwtIsAdmin', 'Start-IgwtElevated', 'Test-IgwtSystemProtectionEnabled', 'New-IgwtRestorePoint',
    'Get-IgwtStartupItem', 'Set-IgwtStartupItemEnabled',
    'Write-IgwtLog', 'Get-IgwtLogBuffer', 'Set-IgwtLogSink',
    'Set-IgwtEnvironment', 'Get-IgwtEnvironment', 'Get-IgwtDataPath', 'Initialize-IgwtDataRoot',
    'Get-IgwtCleanerRules', 'Test-IgwtCleanerCatalog', 'Invoke-IgwtCleanerScan', 'Invoke-IgwtCleanerClean', 'Set-IgwtCleanerTestRoot',
    'Get-IgwtDiskUsage', 'Format-IgwtBytes',
    'Convert-IgwtDataToV2', 'Convert-IgwtSnapshotToV2', 'Get-IgwtHardwareTagDefinitions',
    'Get-IgwtHardwareFacts', 'Get-IgwtHardwareProfile', 'Get-IgwtHardwareOverlays', 'Resolve-IgwtPresetSelection', 'Test-IgwtHardwareCatalog',
    'Get-IgwtAsrCatalog', 'Get-IgwtAsrStatus', 'Get-IgwtAsrRecommendationPlan', 'Invoke-IgwtAsrChange', 'Test-IgwtAsrExclusion', 'Test-IgwtAsrCatalog',
    'Get-IgwtProtectionEvents', 'Get-IgwtAsrAudit', 'Format-IgwtAsrAudit',
    'Get-IgwtSecurityScore', 'ConvertTo-IgwtSecurityScore', 'Get-IgwtSecurityCheckDefinitions', 'Format-IgwtSecurityScore', 'Get-IgwtLocalAccountAudit', 'Get-IgwtNetworkSurface',
    'Get-IgwtInspection', 'Format-IgwtInspection', 'Get-IgwtPowerSettingsInspection', 'Get-IgwtPowerSettingCatalog', 'Invoke-IgwtPowerSettingChange', 'Get-IgwtPowerSettingChangePlan', 'Test-IgwtPowerSettingCatalog',
    'Get-IgwtInterruptInspection', 'Get-IgwtNicQueueInspection', 'Get-IgwtKernelInspection', 'Get-IgwtTimerInspection', 'Get-IgwtCrashInspection', 'Test-IgwtKernelInspectorCatalog',
    'Invoke-IgwtManagedChange', 'Get-IgwtManagedChangePlan', 'Get-IgwtServiceInventory', 'Get-IgwtTaskInventory', 'Get-IgwtAppInventory', 'Get-IgwtFeatureInventory', 'Test-IgwtManageCatalog',
    'Get-IgwtPersistenceInventory', 'Export-IgwtPersistenceReport', 'Get-IgwtUpdateStatus',
    'Get-IgwtAdapterPropertyInspection', 'Invoke-IgwtDnsBenchmark', 'Test-IgwtNetworkLatency', 'Get-IgwtFirewallRuleList', 'Get-IgwtHostsFile',
    'Get-IgwtDiagnostics', 'Format-IgwtDiagnostics', 'Get-IgwtDpcIsrSample', 'Get-IgwtReliabilityHistory', 'Get-IgwtCrashHistory', 'Get-IgwtBootPerformance', 'Get-IgwtDriverInventory',
    'Get-IgwtSystemReport', 'Export-IgwtSystemReport',
    'Invoke-IgwtNetworkQualityTest', 'Measure-IgwtLoadedLatency', 'Format-IgwtNetworkQuality', 'Export-IgwtNetworkReport', 'Get-IgwtActiveConnection', 'Invoke-IgwtRouteTrace', 'Find-IgwtPathMtu', 'Get-IgwtNetworkTypeGuess', 'Get-IgwtNetworkRecommendations', 'ConvertTo-IgwtLatencyStats', 'Get-IgwtNetworkScore', 'Get-IgwtBufferbloatGrade', 'Get-IgwtRiskZoneSummary',
    'Get-IgwtToolkitApps', 'Get-IgwtToolkitFeatures', 'Get-IgwtToolkitFixes', 'Get-IgwtToolkitFixPlan', 'Get-IgwtToolkitPanels', 'Get-IgwtToolkitTweaks', 'Get-IgwtToolkitUpdateItems', 'Test-IgwtToolkitCatalog',
    'Get-IgwtWingetAgreements', 'Test-IgwtWingetConsent', 'Set-IgwtWingetConsent', 'Get-IgwtWingetInventory', 'Invoke-IgwtToolkitApp', 'Invoke-IgwtWingetUpgradeAll', 'Export-IgwtAppSelection', 'Import-IgwtAppSelection',
    'Invoke-IgwtToolkitFeature', 'Invoke-IgwtToolkitFix', 'Start-IgwtPanel', 'Get-IgwtEditionFamily', 'Test-IgwtEditionSupported',
    'Save-IgwtCustomPreset', 'Copy-IgwtPreset', 'Remove-IgwtCustomPreset', 'Export-IgwtPreset', 'Import-IgwtPreset', 'Get-IgwtPresetDrift', 'Get-IgwtPresetRecord', 'Save-IgwtDriftAsPreset', 'Test-IgwtPresetDefinition',
    'Get-IgwtSessionState', 'Get-IgwtSessionPlan', 'Get-IgwtSessionApps', 'Start-IgwtSession', 'Stop-IgwtSession', 'Close-IgwtSessionApps',
    'Get-IgwtManagementState', 'Format-IgwtManagementState', 'Get-IgwtItemAuthority', 'Get-IgwtPersona', 'Set-IgwtPersona', 'Get-IgwtPersonaProfile',
    'Get-IgwtAdmxCatalog', 'Find-IgwtPolicy', 'Get-IgwtPolicyDefinition', 'Get-IgwtPolicyState', 'Get-IgwtPolicyChangePlan', 'Set-IgwtLocalPolicy', 'Get-IgwtTattooedPolicyValues', 'Read-IgwtRegistryPol', 'Write-IgwtRegistryPol',
    'Backup-IgwtLocalGpo', 'Restore-IgwtLocalGpo', 'Reset-IgwtLocalGpo', 'Get-IgwtLocalGpoResetPlan', 'Get-IgwtPolicyRegistryOps',
    'Get-IgwtTattooAdoptionPlan', 'Invoke-IgwtTattooAdoption', 'Restore-IgwtTattooRemoval', 'Test-IgwtPolicyBridgeEnabled',
    'Get-IgwtSecurityPolicy', 'Export-IgwtSecurityPolicy', 'Get-IgwtSecurityChangePlan', 'Set-IgwtSecurityPolicy', 'Restore-IgwtSecurityPolicy', 'ConvertFrom-IgwtSecurityChangeText', 'Get-IgwtAuditPolicy', 'Get-IgwtAuditChangePlan', 'Set-IgwtAuditPolicy', 'Restore-IgwtAuditPolicy', 'Import-IgwtAuditCsv', 'Export-IgwtAuditCsv',
    'Show-IgwtGui', 'Get-IgwtGuiData', 'Get-IgwtGuiPreview', 'Invoke-IgwtGuiBatch', 'Export-IgwtGuiReport', 'Get-IgwtGuiManageData', 'Get-IgwtGuiToolkitData', 'Get-IgwtGuiDiagnosticsData', 'Export-IgwtGuiSystemReport'
)
