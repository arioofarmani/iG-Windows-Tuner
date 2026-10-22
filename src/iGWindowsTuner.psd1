@{
    RootModule           = 'iGWindowsTuner.psm1'
    ModuleVersion        = '2.3.0'
    GUID                 = '220c64d8-0ab0-4ba8-afd9-1e09b4c9bb4d'
    Author               = 'iG Windows Tuner contributors'
    CompanyName          = 'iG Windows Tuner'
    Copyright            = '(c) iG Windows Tuner contributors. MIT License.'
    Description          = 'Auditable Windows 11 gaming performance and security toolbox: data-driven, reversible, anti-cheat compatible.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
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
        'Show-IgwtGui', 'Get-IgwtGuiData', 'Get-IgwtGuiPreview', 'Invoke-IgwtGuiBatch', 'Export-IgwtGuiReport', 'Get-IgwtGuiManageData', 'Get-IgwtGuiToolkitData', 'Get-IgwtGuiDiagnosticsData', 'Export-IgwtGuiSystemReport'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags = @('Windows11', 'Gaming', 'Performance', 'Security', 'Tuning')
        }
    }
}
