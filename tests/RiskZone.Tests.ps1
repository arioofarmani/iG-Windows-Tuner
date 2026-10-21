# Risk Zone: rejected tweaks offered at the user's own risk. Catalog rules, gating and apply/revert
# round trips in TestRegistry; MMAgent, PnP and TCP settings are mocked. Nothing touches the real system.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Ctx = New-IgwtTestContext
    $script:Cat = @(Get-IgwtCatalog -Force)
    $script:Risk = @($script:Cat | Where-Object { $_.category -eq 'Risk Zone' })
    $script:Rejected = @(Get-IgwtRejectedTweaks)
    function Get-TestValue([string]$Path, [string]$Name) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Get-IgwtRegistryValue -Path $P -Name $N }
    }
    function Write-TestValue([string]$Path, [string]$Name, [string]$Kind, $Value) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name; K = $Kind; V = $Value } { param($P, $N, $K, $V) Set-IgwtRegistryValue -Path $P -Name $N -Kind $K -Value $V }
    }
}

Describe 'Risk Zone catalog' {
    It 'offers 19 rejected tweaks, every one Lab, tier R, with warnings and what it turns off or on' {
        $script:Risk.Count | Should -Be 19
        foreach ($t in $script:Risk) {
            $t.id | Should -Match '^risk\.' -Because $t.id
            $t.level | Should -Be 'Lab' -Because $t.id
            $t.evidence.tier | Should -Be 'R' -Because $t.id
            $t.expert | Should -BeTrue -Because $t.id
            ([string]$t.warning).Length | Should -BeGreaterThan 20 -Because $t.id
            ([string]$t.sideEffects).Length | Should -BeGreaterThan 10 -Because $t.id
            (@($t.riskZone.turnsOff).Count + @($t.riskZone.turnsOn).Count) | Should -BeGreaterThan 0 -Because $t.id
            @($t.riskZone.risks).Count | Should -BeGreaterThan 0 -Because $t.id
            @($t.evidence.sources).Count | Should -BeGreaterThan 0 -Because $t.id
        }
    }
    It 'links every rejected entry to a Risk Zone item or gives the reason it is not offered' {
        foreach ($r in $script:Rejected) {
            ([bool]$r.riskItem) | Should -Not -Be ([bool]$r.unavailable) -Because $r.id
            if ($r.riskItem) { @($script:Risk | Where-Object { $_.id -eq $r.riskItem -and $_.riskZone.rejected -eq $r.id }).Count | Should -Be 1 -Because $r.id }
        }
        @($script:Rejected | Where-Object { $_.riskItem }).Count | Should -Be 19
    }
    It 'does not offer tweaks that turn off security protections, edit the boot configuration or cannot be undone' {
        foreach ($id in 'rejected.spectre-mitigations-off', 'rejected.defender-game-exclusions', 'rejected.disable-security-features', 'rejected.test-signing', 'rejected.hypervisor-launch-off',
            'rejected.vbs-hvci-off-preset', 'rejected.svchost-split-threshold', 'rejected.hosts-telemetry-block', 'rejected.bcdedit-timers', 'rejected.winsxs-manual-delete', 'rejected.dism-component-removal') {
            $r = @($script:Rejected | Where-Object { $_.id -eq $id })[0]
            $r.riskItem | Should -BeNullOrEmpty -Because $id
            $r.unavailable | Should -Match '^Not offered' -Because $id
        }
        $text = Get-Content -LiteralPath (Join-Path $script:IgwtProjectRoot 'data\tweaks\riskzone.json') -Raw
        $text | Should -Not -Match '(?i)FeatureSettingsOverride|ExclusionPath|bcdedit|testsigning|HypervisorEnforcedCodeIntegrity|EnableVirtualizationBasedSecurity|\\\\Windows Defender'
        @($script:Risk | Where-Object { $_.impact.security -eq '-' } | ForEach-Object { $_.id }) | Should -Be @('risk.no-auto-reboot-logged-on')
    }
    It 'keeps Risk Zone items out of every preset' {
        foreach ($p in @(Get-IgwtPreset)) { foreach ($m in @($p.tweaks)) { $m | Should -Not -Match '^risk\.' -Because $p.id } }
    }
    It 'reports broken Risk Zone items in the validator' {
        $errors = New-Object System.Collections.Generic.List[string]
        $bad = [pscustomobject]@{ id = 'risk.bad'; category = 'Risk Zone'; level = 'Expert'; warning = ''; sideEffects = ''; evidence = [pscustomobject]@{ tier = 'R' }; riskZone = [pscustomobject]@{ rejected = 'x'; turnsOff = @(); turnsOn = @(); risks = @() } }
        InModuleScope iGWindowsTuner -Parameters @{ T = $bad; E = $errors } { param($T, $E) Test-IgwtRiskZoneItem -Tweak $T -Errors $E }
        ($errors -join ' ') | Should -Match 'level Lab'
        ($errors -join ' ') | Should -Match 'warning'
        ($errors -join ' ') | Should -Match 'turns off'
        ($errors -join ' ') | Should -Match 'risks'
        $errors.Clear()
        $mixed = [pscustomobject]@{ id = 'net.x'; category = 'Network'; level = 'Standard'; evidence = [pscustomobject]@{ tier = 'R' } }
        InModuleScope iGWindowsTuner -Parameters @{ T = $mixed; E = $errors } { param($T, $E) Test-IgwtRiskZoneItem -Tweak $T -Errors $E }
        ($errors -join ' ') | Should -Match 'go together'
    }
    It 'declares conflicts with the safe counterparts' {
        @($script:Risk | Where-Object { $_.id -eq 'risk.pagefile-off' })[0].conflictsWith | Should -Contain 'system.pagefile-auto'
        @($script:Risk | Where-Object { $_.id -eq 'risk.power-throttling-off' })[0].conflictsWith | Should -Contain 'power.power-throttling-on'
        @($script:Risk | Where-Object { $_.id -eq 'risk.tcp-autotuning-disabled' })[0].conflictsWith | Should -Contain 'net.tcp-autotuning-normal'
    }
}

Describe 'Risk Zone gating' {
    It 'refuses to apply without -AcknowledgeRisk and says what the item turns off and its risks' {
        Write-TestValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name 'Win32PrioritySeparation' -Kind 'DWord' -Value 2
        { Invoke-IgwtApply -Id 'risk.win32-priority-separation' -Context $script:Ctx } | Should -Throw '*Risk Zone*Turns off*Risks*-AcknowledgeRisk*'
        (Get-TestValue 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation').Value | Should -Be 2
    }
    It 'summarizes warning, turns off, turns on and risks' {
        $t = @($script:Risk | Where-Object { $_.id -eq 'risk.ipv6-disable' })[0]
        $s = Get-IgwtRiskZoneSummary -Tweak $t
        $s | Should -Match 'unsupported'; $s | Should -Match 'Turns off: IPv6'; $s | Should -Match 'Risks: Xbox'
    }
}

Describe 'Risk Zone apply and revert (TestRegistry)' {
    It 'applies and reverts registry items exactly, including an empty page file list' {
        $mm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        Write-TestValue -Path $mm -Name 'PagingFiles' -Kind 'MultiString' -Value @('?:\pagefile.sys')
        Write-TestValue -Path $mm -Name 'LargeSystemCache' -Kind 'DWord' -Value 0
        Write-TestValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name 'Win32PrioritySeparation' -Kind 'DWord' -Value 2
        $ids = 'risk.pagefile-off', 'risk.large-system-cache', 'risk.win32-priority-separation', 'risk.legacy-tcpip', 'risk.mmcss-games-task', 'risk.ipv6-disable'
        $r = Invoke-IgwtApply -Id $ids -Context $script:Ctx -AcknowledgeRisk
        @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 6
        @((Get-TestValue $mm 'PagingFiles').Value).Count | Should -Be 0
        (Get-TestValue $mm 'LargeSystemCache').Value | Should -Be 1
        (Get-TestValue 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation').Value | Should -Be 42
        (Get-TestValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DefaultTTL').Value | Should -Be 64
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' 'Scheduling Category').Value | Should -Be 'High'
        (Get-TestValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents').Value | Should -Be 255
        $doc = Get-Content $r.Snapshot -Raw | ConvertFrom-Json
        @($doc.entries | ForEach-Object { $_.level }) | Should -Not -Contain 'Standard'
        $rev = Invoke-IgwtRevert -SnapshotPath $r.Snapshot -Context $script:Ctx
        @($rev.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 6
        @((Get-TestValue $mm 'PagingFiles').Value) | Should -Be @('?:\pagefile.sys')
        (Get-TestValue $mm 'LargeSystemCache').Value | Should -Be 0
        (Get-TestValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DefaultTTL').Exists | Should -BeFalse
        (Get-TestValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents').Exists | Should -BeFalse
    }
    It 'turns memory compression off and back on (MMAgent mocked)' {
        $script:Mc = $true
        Mock -ModuleName iGWindowsTuner Get-MMAgent { [pscustomobject]@{ MemoryCompression = $script:Mc } }
        Mock -ModuleName iGWindowsTuner Disable-MMAgent { $script:Mc = $false }
        Mock -ModuleName iGWindowsTuner Enable-MMAgent { $script:Mc = $true }
        $r = Invoke-IgwtApply -Id 'risk.memory-compression-off' -Context $script:Ctx -AcknowledgeRisk
        @($r.Results)[0].Result | Should -Be 'Applied'
        $script:Mc | Should -BeFalse
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot -Context $script:Ctx
        $script:Mc | Should -BeTrue
    }
    It 'reports memory compression as Unknown when it cannot be read' {
        Mock -ModuleName iGWindowsTuner Get-MMAgent { throw 'Access denied' }
        (Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id 'risk.memory-compression-off') -Context $script:Ctx).State | Should -Be 'Unknown'
    }
    It 'disables and re-enables the HPET device (PnP mocked)' {
        $script:Hpet = [pscustomobject]@{ InstanceId = 'ACPI\PNP0103\0'; FriendlyName = 'High precision event timer'; Status = 'OK'; Problem = 'CM_PROB_NONE'; ConfigManagerErrorCode = 0 }
        Mock -ModuleName iGWindowsTuner Get-PnpDevice { @($script:Hpet) }
        Mock -ModuleName iGWindowsTuner Disable-PnpDevice { $script:Hpet.Status = 'Error'; $script:Hpet.Problem = 'CM_PROB_DISABLED'; $script:Hpet.ConfigManagerErrorCode = 22 }
        Mock -ModuleName iGWindowsTuner Enable-PnpDevice { $script:Hpet.Status = 'OK'; $script:Hpet.Problem = 'CM_PROB_NONE'; $script:Hpet.ConfigManagerErrorCode = 0 }
        $r = Invoke-IgwtApply -Id 'risk.hpet-disable' -Context $script:Ctx -AcknowledgeRisk
        @($r.Results)[0].Result | Should -Be 'Applied'
        $script:Hpet.ConfigManagerErrorCode | Should -Be 22
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot -Context $script:Ctx
        $script:Hpet.Status | Should -Be 'OK'
        Should -Invoke -ModuleName iGWindowsTuner Disable-PnpDevice -Times 1 -Exactly -ParameterFilter { $InstanceId -eq 'ACPI\PNP0103\0' }
    }
    It 'reports the HPET item as not applicable when no HPET device exists' {
        Mock -ModuleName iGWindowsTuner Get-PnpDevice { }
        (Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id 'risk.hpet-disable') -Context $script:Ctx).State | Should -Be 'NotApplicable'
    }
    It 'disables TCP auto-tuning and restores the previous level (NetTCPSetting mocked)' {
        $script:Atl = 'Normal'
        Mock -ModuleName iGWindowsTuner Get-NetTCPSetting { [pscustomobject]@{ SettingName = 'Internet'; AutoTuningLevelLocal = $script:Atl; AutoTuningLevelGroupPolicy = 'NotConfigured' } }
        Mock -ModuleName iGWindowsTuner Set-NetTCPSetting { $script:Atl = [string]$AutoTuningLevelLocal }
        $r = Invoke-IgwtApply -Id 'risk.tcp-autotuning-disabled' -Context $script:Ctx -AcknowledgeRisk
        $script:Atl | Should -Be 'Disabled'
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot -Context $script:Ctx
        $script:Atl | Should -Be 'Normal'
    }
    It 'refuses to apply a Risk Zone item together with its safe counterpart' {
        { Invoke-IgwtApply -Id 'risk.pagefile-off', 'system.pagefile-auto' -Context $script:Ctx -AcknowledgeRisk } | Should -Throw '*conflict*'
    }
}

Describe 'Risk Zone command line (argument checks only)' {
    It 'lists the Risk Zone as JSON and refuses Risk Zone items without -AcknowledgeRisk' {
        $script = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
        $json = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RiskZone -Json -NoGui | Out-String
        $LASTEXITCODE | Should -Be 0
        $rows = $json | ConvertFrom-Json
        @($rows | Where-Object { $_.Available }).Count | Should -Be 19
        @($rows | Where-Object { -not $_.Available -and $_.NotOffered }).Count | Should -Be 19
    }
}
