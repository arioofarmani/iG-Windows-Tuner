BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    . (Join-Path $PSScriptRoot 'OneEngineScan.ps1')
    $script:Src = (Resolve-Path (Join-Path $PSScriptRoot '..\src')).Path
    $script:Calls = @(Get-IgwtStateChangingCall -Root $script:Src)

    # Provider internals (DECISIONS T12): the only functions that may call a state-changing cmdlet or
    # tool. They are the State/Snapshot/Apply/Restore handlers and the module writers' bodies; each is
    # reached only through a change provider (Invoke-IgwtChangeStep) or a journaled module writer.
    $script:ProviderInternals = @(
        # src\Actions: catalog action handlers (provider "action")
        'Set-IgwtRegistryValue', 'Remove-IgwtRegistryValue', 'Remove-IgwtCreatedRegistryKey',
        'Set-IgwtServiceStartupType', 'Invoke-IgwtServiceApply', 'Restore-IgwtServiceSnapshot',
        'Set-IgwtTaskEnabled', 'Invoke-IgwtFirewallRuleApply', 'Restore-IgwtFirewallRuleSnapshot',
        'Invoke-IgwtNetQosApply', 'Restore-IgwtNetQosSnapshot', 'Invoke-IgwtDnsDohApply', 'Restore-IgwtDnsDohSnapshot',
        'Set-IgwtAdapterPropertyValue', 'Set-IgwtMitigationValue', 'Set-IgwtMpPreferenceValue',
        'Set-IgwtAsrRule', 'Invoke-IgwtAsrRuleApply', 'Restore-IgwtAsrRuleSnapshot',
        'Set-IgwtOptionalFeature', 'Set-IgwtCapability', 'Invoke-IgwtAppxApply', 'Restore-IgwtAppxSnapshot', 'Install-IgwtAppxPackage',
        'Install-IgwtWingetPackage', 'Uninstall-IgwtWingetPackage', 'Update-IgwtWingetPackage',
        'Invoke-IgwtPowerCfgSchemeApply', 'Restore-IgwtPowerCfgSchemeSnapshot', 'Set-IgwtPowerSettingIndex', 'Set-IgwtPowerAttributeVisible',
        'Stop-IgwtCleanerService', 'Restore-IgwtCleanerService',
        # module writers (provider "module", DECISIONS T14) and the restores they call
        'Import-IgwtFirewallRules', 'Invoke-IgwtFirewallChange', 'Restore-IgwtFirewallSnapshot', 'Set-IgwtFirewallProfileSetting', 'Set-IgwtNetworkCategory',
        'Invoke-IgwtManagedChange', 'Restore-IgwtManagedSnapshot',
        'Invoke-IgwtAsrChange', 'Set-IgwtAsrRuleMode', 'Restore-IgwtAsrSnapshot',
        'Invoke-IgwtMpPreferenceWrite', 'Set-IgwtDefenderParsersOn', 'Remove-IgwtDefenderExclusion', 'Remove-IgwtDefenderThreat', 'Start-IgwtDefenderScan',
        'Set-IgwtLocalPolicy', 'Reset-IgwtLocalGpo', 'Restore-IgwtLocalGpo', 'Invoke-IgwtPolicyBatch', 'Save-IgwtBridgePol',
        'Set-IgwtAuditPolicy', 'Restore-IgwtAuditPolicy', 'Set-IgwtSecurityPolicy', 'Restore-IgwtSecurityPolicy',
        'Invoke-IgwtFixStep', 'Invoke-IgwtWingetUpgradeAll',
        # forensic logging: providers forensicFirewall/forensicAudit/forensicEventLog and the 3.5 restore
        'Restore-IgwtForensicLogging', 'Restore-IgwtFirewallProfileSnapshot', 'Restore-IgwtDefenderSettingSnapshot'
    )
    # Script-level provider tables: catalog custom handlers and the forensic providers.
    $script:ProviderFiles = @('Actions\Custom.ps1', 'Defender\ForensicLogging.ps1')

    # Static call graph: function -> commands it calls; entries open a session or a journaled step.
    $script:Graph = @{}
    $tk = $null; $pe = $null
    foreach ($file in Get-ChildItem -Path $script:Src -Recurse -Filter *.ps1) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tk, [ref]$pe)
        foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            $names = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Select-Object -Unique)
            $script:Graph[$fn.Name] = [pscustomobject]@{ File = $file.FullName.Substring($script:Src.Length + 1); Calls = $names }
        }
    }
    $script:EntryCalls = 'Start-IgwtChangeSession', 'Invoke-IgwtModuleOperation', 'Invoke-IgwtChangeStep'
}

Describe 'One engine (DECISIONS T12)' {
    It 'finds the state-changing calls (the scanner works)' {
        $script:Calls.Count | Should -BeGreaterThan 50
        @($script:Calls | Where-Object Function -EQ 'Set-IgwtRegistryValue').Count | Should -BeGreaterThan 0
        @($script:Calls | Where-Object Command -Like 'Invoke-IgwtAuditpol*').Count | Should -BeGreaterThan 0
    }
    It 'calls state-changing cmdlets and tools only inside provider internals' {
        $bad = @($script:Calls | Where-Object { $_.Function -notin $script:ProviderInternals -and -not ($_.Function -eq '<script>' -and $_.File -in $script:ProviderFiles) })
        ($bad | ForEach-Object { "$($_.File):$($_.Line) $($_.Function) -> $($_.Command)" }) -join "`n" | Should -BeNullOrEmpty
    }
    It 'reaches provider internals from exported commands and the GUI only through the change engine' {
        $entries = @($script:Graph.Keys | Where-Object { $g = $script:Graph[$_]; @($g.Calls | Where-Object { $_ -in $script:EntryCalls }).Count -or $_ -in $script:EntryCalls -or (Get-Content -LiteralPath (Join-Path $script:Src $g.File) -Raw) -match "Invoke-IgwtModuleOperation -Command '$_'" })
        $writers = New-Object System.Collections.Generic.HashSet[string]
        # Journaled module writers are entries: their callers are not writers.
        foreach ($n in $script:ProviderInternals) { if ($n -notin $entries) { $null = $writers.Add($n) } }
        do {
            $added = 0
            foreach ($k in $script:Graph.Keys) {
                if ($writers.Contains($k) -or $k -in $entries) { continue }
                if (@($script:Graph[$k].Calls | Where-Object { $writers.Contains($_) }).Count) { $null = $writers.Add($k); $added++ }
            }
        } while ($added)
        $exported = @((Get-Module iGWindowsTuner).ExportedFunctions.Keys)
        $surface = @($script:Graph.Keys | Where-Object { $_ -in $exported -or $script:Graph[$_].File -like 'Gui\*' })
        $bad = @($surface | Where-Object { $writers.Contains($_) -and $_ -notin $entries -and $_ -notin $script:ProviderInternals } | Sort-Object)
        $bad -join ', ' | Should -BeNullOrEmpty
        $raw = @($surface | Where-Object { $_ -in $script:ProviderInternals -and $_ -notin $entries } | Sort-Object)
        $raw -join ', ' | Should -BeNullOrEmpty -Because 'an exported provider internal must be a journaled module writer'
    }
    It 'registers every journaled module writer with the module provider' {
        InModuleScope iGWindowsTuner {
            foreach ($op in $script:IgwtModuleOperations.Keys) {
                $def = (Get-Command $op).Definition
                $def | Should -Match ([regex]::Escape("Invoke-IgwtModuleOperation -Command '$op'")) -Because $op
            }
        }
    }
}
