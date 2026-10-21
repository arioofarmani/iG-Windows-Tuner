# Round-trip tests (apply -> detect -> revert -> detect) for every non-registry action type.
# All system cmdlets are mocked with in-memory fakes; nothing reaches the real system.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    function Get-ActState($Action, $Context) {
        InModuleScope iGWindowsTuner -Parameters @{ A = $Action; C = $Context } { param($A, $C) @(Get-IgwtActionState -Action $A -Context $C) }
    }
    function Get-ActRollup($Action, $Context) {
        $items = Get-ActState $Action $Context
        InModuleScope iGWindowsTuner -Parameters @{ S = @($items | ForEach-Object { [string]$_.State }) } { param($S) Get-IgwtStateRollup -States $S }
    }
    function Get-ActSnapshot($Action, $Context) {
        $s = InModuleScope iGWindowsTuner -Parameters @{ A = $Action; C = $Context } { param($A, $C) Get-IgwtActionSnapshot -Action $A -Context $C }
        return ($s | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    }
    function Invoke-Act($Action, $Context, [string]$Mode = 'on') {
        InModuleScope iGWindowsTuner -Parameters @{ A = $Action; C = $Context; M = $Mode } { param($A, $C, $M) Invoke-IgwtActionApply -Action $A -Context $C -Mode $M }
    }
    function Restore-Act($Action, $Snapshot, $Context) {
        InModuleScope iGWindowsTuner -Parameters @{ A = $Action; S = $Snapshot; C = $Context } { param($A, $S, $C) Restore-IgwtActionSnapshot -Action $A -Snapshot $S -Context $C }
    }
    function Invoke-RoundTrip($Action, $Context) {
        $before = Get-ActRollup $Action $Context
        $snap = Get-ActSnapshot $Action $Context
        $applied = Invoke-Act $Action $Context
        if ($applied -is [System.Collections.IDictionary]) {
            $snap | Add-Member -NotePropertyName applied -NotePropertyValue ([pscustomobject]$applied) -Force
        }
        $after = Get-ActRollup $Action $Context
        Restore-Act -Action $Action -Snapshot $snap -Context $Context
        $restored = Get-ActRollup $Action $Context
        [pscustomobject]@{ Before = $before; After = $after; Restored = $restored }
    }
    $script:Adapter = [pscustomobject]@{ Name = 'Lan-Test'; InterfaceDescription = 'Fake 10GbE'; InterfaceGuid = '{11111111-2222-3333-4444-555555555555}'; ifIndex = 18; Status = 'Up'; Virtual = $false; PhysicalMediaType = '802.3'; NdisPhysicalMedium = 14 }
    $script:WiredCtx = New-IgwtTestContext -Extra @{ WiredAdapters = @($script:Adapter) }
}

Describe 'powercfgScheme, powercfgSetting, Ultimate plan and hibernation (powercfg mocked)' {
    BeforeEach {
        $script:Pc = @{
            Active  = '381b4222-f694-41f0-9685-ff5bb260df2e'
            Schemes = [ordered]@{ '381b4222-f694-41f0-9685-ff5bb260df2e' = @('Balanced', 15); '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = @('High performance', 13) }
            Values  = @{}
        }
        Mock Invoke-IgwtPowerCfg -ModuleName iGWindowsTuner {
            param($Arguments)
            $a = @($Arguments)
            switch ($a[0]) {
                '/getactivescheme' { return [pscustomobject]@{ ExitCode = 0; Output = "Power Scheme GUID: $($script:Pc.Active)  (x)" } }
                '/list' { return [pscustomobject]@{ ExitCode = 0; Output = (($script:Pc.Schemes.Keys | ForEach-Object { "Power Scheme GUID: $_  (n)" }) -join "`n") } }
                '/setactive' { $script:Pc.Active = $a[1].ToLowerInvariant(); return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                '/query' {
                    $k = "$($a[1])|$($a[2])|$($a[3])"
                    $v = $script:Pc.Values[$k]; if ($null -eq $v) { $v = @(1, 1) }
                    return [pscustomobject]@{ ExitCode = 0; Output = ("Possible 000`nCurrent AC Power Setting Index: 0x{0:x8}`nCurrent DC Power Setting Index: 0x{1:x8}" -f $v[0], $v[1]) }
                }
                '/setacvalueindex' { $k = "$($a[1])|$($a[2])|$($a[3])"; $v = $script:Pc.Values[$k]; if ($null -eq $v) { $v = @(1, 1) }; $script:Pc.Values[$k] = @([int]$a[4], $v[1]); return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                '/setdcvalueindex' { $k = "$($a[1])|$($a[2])|$($a[3])"; $v = $script:Pc.Values[$k]; if ($null -eq $v) { $v = @(1, 1) }; $script:Pc.Values[$k] = @($v[0], [int]$a[4]); return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                '/duplicatescheme' { $g = [guid]::NewGuid().ToString(); $script:Pc.Schemes[$g] = @('Ultimate Performance', 19); return [pscustomobject]@{ ExitCode = 0; Output = "Power Scheme GUID: $g  (Ultimate Performance)" } }
                '/delete' { $script:Pc.Schemes.Remove($a[1]); return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                '/hibernate' {
                    $val = 0; if ($a[1] -eq 'on') { $val = 1 }
                    New-Item -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power' -Force | Out-Null
                    Set-ItemProperty -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -Value $val -Type DWord
                    return [pscustomobject]@{ ExitCode = 0; Output = '' }
                }
                default { throw "unexpected powercfg call $($a -join ' ')" }
            }
        }
        Mock Get-IgwtPowerSchemes -ModuleName iGWindowsTuner {
            foreach ($g in @($script:Pc.Schemes.Keys)) { [pscustomobject]@{ Guid = $g; FriendlyName = "@powrprof.dll,-$($script:Pc.Schemes[$g][1]),$($script:Pc.Schemes[$g][0])"; Name = $script:Pc.Schemes[$g][0]; ResourceId = $script:Pc.Schemes[$g][1] } }
        }
    }

    It 'activates High performance and restores the previous scheme' {
        $a = [pscustomobject]@{ type = 'powercfgScheme'; scheme = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:Pc.Active | Should -Be '381b4222-f694-41f0-9685-ff5bb260df2e'
    }

    It 'creates an Ultimate copy, activates it and deletes only that copy on revert' {
        $a = [pscustomobject]@{ type = 'custom'; handler = 'UltimatePlan' }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        @($script:Pc.Schemes.Keys).Count | Should -Be 2
        $script:Pc.Active | Should -Be '381b4222-f694-41f0-9685-ff5bb260df2e'
    }

    It 'reuses an existing Ultimate copy and keeps it on revert' {
        $script:Pc.Schemes['98bdb6d0-a4b4-4553-9c5b-a1fd54831f74'] = @('Ultimate Performance', 19)
        $a = [pscustomobject]@{ type = 'custom'; handler = 'UltimatePlan' }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.After | Should -Be 'On'
        $script:Pc.Schemes.Contains('98bdb6d0-a4b4-4553-9c5b-a1fd54831f74') | Should -BeTrue
        @($script:Pc.Schemes.Keys).Count | Should -Be 3
    }

    It 'sets USB selective suspend (AC) and restores the previous index' {
        $a = [pscustomobject]@{ type = 'powercfgSetting'; label = 'USB'; subgroup = '2a737441-1930-4402-8d77-b2bebba308a3'; setting = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'; ac = 0; defaultAc = 1 }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
    }

    It 'turns hibernation off and back on' {
        New-Item -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power' -Force | Out-Null
        Set-ItemProperty -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -Value 1 -Type DWord
        $a = [pscustomobject]@{ type = 'custom'; handler = 'Hibernate' }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
    }
}

Describe 'Defender preferences and ASR rules (Defender cmdlets mocked)' {
    BeforeEach {
        $script:Mp = @{ PUAProtection = 0; MAPSReporting = 2; SubmitSamplesConsent = 1; EnableNetworkProtection = 0; EnableControlledFolderAccess = 0
            ScanOnlyIfIdleEnabled = $true; ScanAvgCPULoadFactor = 50; AttackSurfaceReductionRules_Ids = @(); AttackSurfaceReductionRules_Actions = @(); ControlledFolderAccessAllowedApplications = @() }
        $script:AsrMap = @{ Disabled = 0; Enabled = 1; AuditMode = 2; Warn = 6 }
        Mock Get-MpComputerStatus -ModuleName iGWindowsTuner { [pscustomobject]@{ AMServiceEnabled = $true; AMRunningMode = 'Normal'; RealTimeProtectionEnabled = $true; IsTamperProtected = $true } }
        Mock Get-MpPreference -ModuleName iGWindowsTuner { [pscustomobject]$script:Mp }
        Mock Set-MpPreference -ModuleName iGWindowsTuner { foreach ($k in $PesterBoundParameters.Keys) { if ($script:Mp.ContainsKey($k)) { $script:Mp[$k] = $PesterBoundParameters[$k] } } }
        Mock Add-MpPreference -ModuleName iGWindowsTuner {
            if ($PesterBoundParameters.ContainsKey('AttackSurfaceReductionRules_Ids')) {
                $id = [string]@($AttackSurfaceReductionRules_Ids)[0]
                $act = @($AttackSurfaceReductionRules_Actions)[0]
                $code = if ($act -is [string]) { $script:AsrMap[$act] } else { [int]$act }
                $ids = [System.Collections.ArrayList]@($script:Mp.AttackSurfaceReductionRules_Ids); $acts = [System.Collections.ArrayList]@($script:Mp.AttackSurfaceReductionRules_Actions)
                $i = $ids.IndexOf($id)
                if ($i -ge 0) { $acts[$i] = $code } else { $null = $ids.Add($id); $null = $acts.Add($code) }
                $script:Mp.AttackSurfaceReductionRules_Ids = @($ids); $script:Mp.AttackSurfaceReductionRules_Actions = @($acts)
            }
            if ($PesterBoundParameters.ContainsKey('ControlledFolderAccessAllowedApplications')) { $script:Mp.ControlledFolderAccessAllowedApplications = @($script:Mp.ControlledFolderAccessAllowedApplications) + @($ControlledFolderAccessAllowedApplications) }
        }
        Mock Remove-MpPreference -ModuleName iGWindowsTuner {
            if ($PesterBoundParameters.ContainsKey('AttackSurfaceReductionRules_Ids')) {
                $id = [string]@($AttackSurfaceReductionRules_Ids)[0]
                $ids = [System.Collections.ArrayList]@($script:Mp.AttackSurfaceReductionRules_Ids); $acts = [System.Collections.ArrayList]@($script:Mp.AttackSurfaceReductionRules_Actions)
                $i = $ids.IndexOf($id); if ($i -ge 0) { $ids.RemoveAt($i); $acts.RemoveAt($i) }
                $script:Mp.AttackSurfaceReductionRules_Ids = @($ids); $script:Mp.AttackSurfaceReductionRules_Actions = @($acts)
            }
            if ($PesterBoundParameters.ContainsKey('ControlledFolderAccessAllowedApplications')) { $rm = @($ControlledFolderAccessAllowedApplications); $script:Mp.ControlledFolderAccessAllowedApplications = @($script:Mp.ControlledFolderAccessAllowedApplications | Where-Object { $rm -notcontains $_ }) }
        }
    }

    It 'sets an allow-listed Defender preference and restores it' {
        $a = [pscustomobject]@{ type = 'mpPreference'; setting = 'EnableNetworkProtection'; on = 1; default = 0 }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        [int]$script:Mp.EnableNetworkProtection | Should -Be 0
    }

    It 'refuses Defender settings that are not on the allow-list' {
        $a = [pscustomobject]@{ type = 'mpPreference'; setting = 'DisableRealtimeMonitoring'; on = $true; default = $false }
        { Invoke-Act $a $script:WiredCtx } | Should -Throw '*allow-list*'
    }

    It 'adds an ASR rule in Block mode and removes it again when it was not configured' {
        $a = [pscustomobject]@{ type = 'asrRule'; label = 'LSASS'; id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; on = 'Block' }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        @($script:Mp.AttackSurfaceReductionRules_Ids).Count | Should -Be 0
    }

    It 'restores a previously configured ASR action instead of removing the rule' {
        $script:Mp.AttackSurfaceReductionRules_Ids = @('d4f940ab-401b-4efc-aadc-ad5f3c50688a'); $script:Mp.AttackSurfaceReductionRules_Actions = @(2)
        $a = [pscustomobject]@{ type = 'asrRule'; label = 'Office child'; id = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; on = 'Block' }
        $null = Invoke-RoundTrip $a $script:WiredCtx
        [int]@($script:Mp.AttackSurfaceReductionRules_Actions)[0] | Should -Be 2
    }

    It 'treats an existing Block rule as satisfying the Audit tweak (never weakens it)' {
        $script:Mp.AttackSurfaceReductionRules_Ids = @('3b576869-a4ec-4529-8536-b80a7769e899'); $script:Mp.AttackSurfaceReductionRules_Actions = @(1)
        $a = [pscustomobject]@{ type = 'asrRule'; label = 'Office exe'; id = '3b576869-a4ec-4529-8536-b80a7769e899'; on = 'Audit' }
        Get-ActRollup $a $script:WiredCtx | Should -Be 'On'
        $null = Invoke-Act $a $script:WiredCtx
        [int]@($script:Mp.AttackSurfaceReductionRules_Actions)[0] | Should -Be 1
    }

    It 'adds detected games to the CFA allow-list and removes only those on revert' {
        $script:Mp.ControlledFolderAccessAllowedApplications = @('C:\Tools\keep.exe')
        $ctx = New-IgwtTestContext -Extra @{ Games = @([pscustomobject]@{ Id = 'dota2'; Name = 'Dota 2'; ExePath = 'C:\Games\dota2.exe'; AntiCheat = 'VAC' }) }
        $a = [pscustomobject]@{ type = 'custom'; handler = 'CfaAllowGames' }
        $r = Invoke-RoundTrip $a $ctx
        $r.After | Should -Be 'On'
        @($script:Mp.ControlledFolderAccessAllowedApplications) | Should -Be @('C:\Tools\keep.exe')
    }

    It 'reports NotApplicable when Defender is not the active antivirus' {
        Mock Get-MpComputerStatus -ModuleName iGWindowsTuner { [pscustomobject]@{ AMServiceEnabled = $true; AMRunningMode = 'Passive Mode' } }
        $a = [pscustomobject]@{ type = 'mpPreference'; setting = 'PUAProtection'; on = 1; default = 0 }
        (Get-ActState $a $script:WiredCtx)[0].State | Should -Be 'NotApplicable'
    }
}

Describe 'Network adapter actions (NetAdapter cmdlets mocked)' {
    BeforeEach {
        $script:Props = @{ '*EEE' = '1'; '*InterruptModeration' = '1'; '*RSS' = '0' }
        Mock Get-NetAdapterAdvancedProperty -ModuleName iGWindowsTuner {
            foreach ($k in $script:Props.Keys) { [pscustomobject]@{ RegistryKeyword = $k; RegistryValue = @($script:Props[$k]); DisplayName = $k.Trim('*'); DisplayValue = $script:Props[$k] } }
        }
        Mock Set-NetAdapterAdvancedProperty -ModuleName iGWindowsTuner { $script:Props[[string]@($RegistryKeyword)[0]] = [string]@($RegistryValue)[0] }
        Mock Get-NetAdapter -ModuleName iGWindowsTuner { $script:Adapter }
        Mock Get-IgwtAdapterClassKey -ModuleName iGWindowsTuner { 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0010' }
    }

    It 'sets <Keyword> by standardized keyword and restores it' -ForEach @(
        @{ Keyword = '*EEE'; On = '0' }
        @{ Keyword = '*InterruptModeration'; On = '0' }
        @{ Keyword = '*RSS'; On = '1' }
    ) {
        $before = $script:Props[$Keyword]
        $a = [pscustomobject]@{ type = 'netAdapterAdvanced'; keyword = $Keyword; on = $On; default = '1' }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:Props[$Keyword] | Should -Be $before
    }

    It 'uses vendor display names only as a fallback' {
        $script:Props = @{}
        Mock Get-NetAdapterAdvancedProperty -ModuleName iGWindowsTuner { [pscustomobject]@{ RegistryKeyword = 'GreenEthernet'; RegistryValue = @('1'); DisplayName = 'Green Ethernet'; DisplayValue = $script:GreenValue } }
        Mock Set-NetAdapterAdvancedProperty -ModuleName iGWindowsTuner { $script:GreenValue = $DisplayValue }
        $script:GreenValue = 'Enabled'
        $a = [pscustomobject]@{ type = 'netAdapterAdvanced'; keyword = '*EEE'; on = '0'; default = '1'; fallback = @([pscustomobject]@{ displayName = 'Green Ethernet'; displayValue = 'Disabled' }) }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.After | Should -Be 'On'
        $script:GreenValue | Should -Be 'Enabled'
    }

    It 'is NotApplicable without an active wired adapter' {
        $a = [pscustomobject]@{ type = 'netAdapterAdvanced'; keyword = '*EEE'; on = '0'; default = '1' }
        (Get-ActState $a (New-IgwtTestContext))[0].State | Should -Be 'NotApplicable'
    }

    It 'writes PnPCapabilities (netAdapterPower) in the adapter driver key and restores it' {
        $a = [pscustomobject]@{ type = 'netAdapterPower'; allowTurnOff = $false }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        Test-Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0010' | Should -BeFalse
    }

    It 'expands {InterfaceGuid} for adapterRegistry actions' {
        $a = [pscustomobject]@{ type = 'adapterRegistry'; path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{InterfaceGuid}'; name = 'TcpAckFrequency'; valueType = 'DWord'; on = 1; default = '<absent>' }
        $snap = Get-ActSnapshot $a $script:WiredCtx
        $null = Invoke-Act $a $script:WiredCtx
        (Get-ItemProperty "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($script:Adapter.InterfaceGuid)").TcpAckFrequency | Should -Be 1
        Restore-Act -Action $a -Snapshot $snap -Context $script:WiredCtx
        Get-ActRollup $a $script:WiredCtx | Should -Be 'Off'
    }
}

Describe 'QoS policies (NetQos cmdlets mocked)' {
    BeforeEach {
        $script:Qos = @{}
        Mock Get-IgwtGameDefinitions -ModuleName iGWindowsTuner { @([pscustomobject]@{ id = 'dota2'; name = 'Dota 2'; exe = @('dota2.exe'); qos = $true }, [pscustomobject]@{ id = 'apex'; name = 'Apex'; exe = @('r5apex.exe'); qos = $false }) }
        Mock Get-NetQosPolicy -ModuleName iGWindowsTuner { $n = [string]@($Name)[0]; if ($script:Qos.ContainsKey($n)) { $script:Qos[$n] } else { throw 'not found' } }
        Mock New-NetQosPolicy -ModuleName iGWindowsTuner { $script:Qos[[string]@($Name)[0]] = [pscustomobject]@{ Name = $Name; AppPathName = $AppPathNameMatchCondition; IPProtocol = [string]$IPProtocolMatchCondition; DSCPValue = [int]$DSCPAction; NetworkProfile = 'All' } }
        Mock Set-NetQosPolicy -ModuleName iGWindowsTuner { $p = $script:Qos[[string]@($Name)[0]]; $p.AppPathName = $AppPathNameMatchCondition; $p.IPProtocol = [string]$IPProtocolMatchCondition; $p.DSCPValue = [int]$DSCPAction }
        Mock Remove-NetQosPolicy -ModuleName iGWindowsTuner { $script:Qos.Remove([string]@($Name)[0]) }
    }

    It 'creates one DSCP policy per qos game and removes it on revert' {
        $a = [pscustomobject]@{ type = 'netQosPolicy'; dscp = 46; protocol = 'UDP'; namePrefix = 'iGWindowsTuner-' }
        $snap = Get-ActSnapshot $a $script:WiredCtx
        $null = Invoke-Act $a $script:WiredCtx
        @($script:Qos.Keys) | Should -Be @('iGWindowsTuner-dota2')
        $script:Qos['iGWindowsTuner-dota2'].DSCPValue | Should -Be 46
        Get-ActRollup $a $script:WiredCtx | Should -Be 'On'
        Restore-Act -Action $a -Snapshot $snap -Context $script:WiredCtx
        @($script:Qos.Keys).Count | Should -Be 0
    }
    It 'keeps using a policy created by a preview build (AegisTune-<game>) and removes it on reset or revert' {
        $a = [pscustomobject]@{ type = 'netQosPolicy'; dscp = 46; protocol = 'UDP'; namePrefix = 'iGWindowsTuner-' }
        $script:Qos['AegisTune-dota2'] = [pscustomobject]@{ Name = 'AegisTune-dota2'; AppPathName = 'dota2.exe'; IPProtocol = 'UDP'; DSCPValue = 46; NetworkProfile = 'All' }
        Get-ActRollup $a $script:WiredCtx | Should -Be 'On'
        $null = Invoke-Act $a $script:WiredCtx
        @($script:Qos.Keys) | Should -Be @('AegisTune-dota2')
        # A preview-build snapshot that recorded the policy as absent removes it on revert.
        Restore-Act -Action $a -Snapshot @{ items = @(@{ name = 'AegisTune-dota2'; exists = $false }) } -Context $script:WiredCtx
        @($script:Qos.Keys).Count | Should -Be 0
        $script:Qos['AegisTune-dota2'] = [pscustomobject]@{ Name = 'AegisTune-dota2'; AppPathName = 'dota2.exe'; IPProtocol = 'UDP'; DSCPValue = 46; NetworkProfile = 'All' }
        InModuleScope iGWindowsTuner -Parameters @{ A = $a; C = $script:WiredCtx } { param($A, $C) Invoke-IgwtActionApply -Action $A -Context $C -Mode default }
        @($script:Qos.Keys).Count | Should -Be 0
    }
}

Describe 'DNS over HTTPS (DnsClient cmdlets mocked)' {
    BeforeEach {
        $script:Dns = @{ V4 = @('192.168.1.1'); Static = $false }
        $script:Doh = @{ '9.9.9.9' = @{ DohTemplate = 'https://dns.quad9.net/dns-query'; AutoUpgrade = $false; AllowFallbackToUdp = $false }; '149.112.112.112' = @{ DohTemplate = 'https://dns.quad9.net/dns-query'; AutoUpgrade = $false; AllowFallbackToUdp = $false } }
        Mock Get-DnsClientServerAddress -ModuleName iGWindowsTuner { if ($AddressFamily -eq 'IPv4') { [pscustomobject]@{ ServerAddresses = $script:Dns.V4 } } else { [pscustomobject]@{ ServerAddresses = @() } } }
        Mock Set-DnsClientServerAddress -ModuleName iGWindowsTuner {
            if ($ResetServerAddresses) { $script:Dns.V4 = @('192.168.1.1'); $script:Dns.Static = $false; Remove-ItemProperty -Path "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($script:Adapter.InterfaceGuid)" -Name NameServer -ErrorAction SilentlyContinue }
            else {
                $script:Dns.V4 = @($ServerAddresses); $script:Dns.Static = $true
                New-Item -Path "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($script:Adapter.InterfaceGuid)" -Force | Out-Null
                Set-ItemProperty -Path "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($script:Adapter.InterfaceGuid)" -Name NameServer -Value (@($ServerAddresses) -join ',')
            }
        }
        Mock Get-DnsClientDohServerAddress -ModuleName iGWindowsTuner { $sa = [string]@($ServerAddress)[0]; if ($script:Doh.ContainsKey($sa)) { $e = $script:Doh[$sa]; [pscustomobject]@{ ServerAddress = $sa; DohTemplate = $e.DohTemplate; AutoUpgrade = $e.AutoUpgrade; AllowFallbackToUdp = $e.AllowFallbackToUdp } } else { throw 'nf' } }
        Mock Set-DnsClientDohServerAddress -ModuleName iGWindowsTuner { $script:Doh[[string]@($ServerAddress)[0]] = @{ DohTemplate = $DohTemplate; AutoUpgrade = [bool]$AutoUpgrade; AllowFallbackToUdp = [bool]$AllowFallbackToUdp } }
        Mock Add-DnsClientDohServerAddress -ModuleName iGWindowsTuner { $script:Doh[[string]@($ServerAddress)[0]] = @{ DohTemplate = $DohTemplate; AutoUpgrade = [bool]$AutoUpgrade; AllowFallbackToUdp = [bool]$AllowFallbackToUdp } }
        Mock Remove-DnsClientDohServerAddress -ModuleName iGWindowsTuner { $script:Doh.Remove([string]@($ServerAddress)[0]) }
        Mock Get-NetIPAddress -ModuleName iGWindowsTuner { @() }
        Mock Get-NetAdapter -ModuleName iGWindowsTuner { $script:Adapter }
    }

    It 'switches to Quad9 with DoH and restores DHCP DNS and the previous DoH settings' {
        $a = [pscustomobject]@{ type = 'dnsDoh'; provider = 'quad9'; allowFallbackToUdp = $false }
        $state = Get-ActState $a $script:WiredCtx
        $state[0].Note | Should -Match 'router'
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:Dns.Static | Should -BeFalse
        $script:Doh['9.9.9.9'].AutoUpgrade | Should -BeFalse
        $script:Doh.ContainsKey('2620:fe::fe') | Should -BeFalse
    }
}

Describe 'Services (service cmdlets mocked)' {
    BeforeEach {
        New-Item -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\SysMain' -Force | Out-Null
        Set-ItemProperty -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\SysMain' -Name Start -Value 2 -Type DWord
        $script:SvcStatus = 'Running'
        Mock Get-Service -ModuleName iGWindowsTuner { [pscustomobject]@{ Name = $Name; Status = $script:SvcStatus } }
        Mock Set-Service -ModuleName iGWindowsTuner {
            $v = switch ([string]$StartupType) { 'Automatic' { 2 } 'Manual' { 3 } 'Disabled' { 4 } }
            Set-ItemProperty -Path "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value $v -Type DWord
        }
        Mock Stop-Service -ModuleName iGWindowsTuner { $script:SvcStatus = 'Stopped' }
        Mock Start-Service -ModuleName iGWindowsTuner { $script:SvcStatus = 'Running' }
    }

    It 'disables and stops a service, then restores startup type and running state' {
        $a = [pscustomobject]@{ type = 'service'; name = 'SysMain'; startupType = 'Disabled'; default = 'Automatic'; stop = $true }
        $r = Invoke-RoundTrip $a $script:WiredCtx
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:SvcStatus | Should -Be 'Running'
        (Get-ItemProperty 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\SysMain').Start | Should -Be 2
    }

    It 'refuses anti-cheat services' {
        $a = [pscustomobject]@{ type = 'service'; name = 'vgk'; startupType = 'Disabled'; default = 'Manual' }
        New-Item -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\vgk' -Force | Out-Null
        Set-ItemProperty -Path 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\vgk' -Name Start -Value 1 -Type DWord
        { Invoke-Act $a $script:WiredCtx } | Should -Throw '*protected*'
    }
}

Describe 'TCP auto-tuning, firewall, Wi-Fi and optional features (cmdlets mocked)' {
    It 'repairs TCP auto-tuning to Normal and restores the previous level' {
        $script:Tcp = 'Disabled'
        Mock Get-NetTCPSetting -ModuleName iGWindowsTuner { [pscustomobject]@{ SettingName = 'Internet'; AutoTuningLevelLocal = $script:Tcp; AutoTuningLevelGroupPolicy = 'NotConfigured' } }
        Mock Set-NetTCPSetting -ModuleName iGWindowsTuner { $script:Tcp = [string]$AutoTuningLevelLocal }
        $r = Invoke-RoundTrip ([pscustomobject]@{ type = 'custom'; handler = 'TcpAutoTuning' }) $script:WiredCtx
        $r.After | Should -Be 'On'; $script:Tcp | Should -Be 'Disabled'
    }

    It 'enables all firewall profiles with inbound Block and restores them' {
        $script:Fw = @{ Domain = @('True', 'NotConfigured'); Private = @('False', 'Allow'); Public = @('True', 'NotConfigured') }
        Mock Get-NetFirewallProfile -ModuleName iGWindowsTuner { foreach ($k in 'Domain', 'Private', 'Public') { [pscustomobject]@{ Name = $k; Enabled = $script:Fw[$k][0]; DefaultInboundAction = $script:Fw[$k][1] } } }
        Mock Set-NetFirewallProfile -ModuleName iGWindowsTuner { $names = $PesterBoundParameters['Name']; if (-not $names) { $names = $PesterBoundParameters['Profile'] }; foreach ($p in @($names)) { $script:Fw[[string]$p] = @([string]$PesterBoundParameters['Enabled'], [string]$PesterBoundParameters['DefaultInboundAction']) } }
        $r = Invoke-RoundTrip ([pscustomobject]@{ type = 'custom'; handler = 'FirewallProfiles' }) $script:WiredCtx
        $r.Before | Should -Be 'Partial'; $r.After | Should -Be 'On'
        $script:Fw.Private[0] | Should -Be 'False'; $script:Fw.Private[1] | Should -Be 'Allow'
    }

    It 'disables an unused Wi-Fi adapter, re-enables it on revert, and refuses when Wi-Fi is connected' {
        $script:Wifi = [pscustomobject]@{ Name = 'WiFi'; InterfaceDescription = 'Intel AX211'; InterfaceGuid = '{aaaa}'; Status = 'Disconnected'; PhysicalMediaType = 'Native 802.11'; NdisPhysicalMedium = 9; Virtual = $false }
        Mock Get-NetAdapter -ModuleName iGWindowsTuner { $script:Wifi }
        Mock Disable-NetAdapter -ModuleName iGWindowsTuner { $script:Wifi.Status = 'Disabled' }
        Mock Enable-NetAdapter -ModuleName iGWindowsTuner { $script:Wifi.Status = 'Disconnected' }
        $r = Invoke-RoundTrip ([pscustomobject]@{ type = 'custom'; handler = 'WifiAdapter' }) $script:WiredCtx
        $r.After | Should -Be 'On'; $script:Wifi.Status | Should -Be 'Disconnected'
        $script:Wifi.Status = 'Up'
        { Invoke-Act ([pscustomobject]@{ type = 'custom'; handler = 'WifiAdapter' }) $script:WiredCtx } | Should -Throw '*refusing*'
    }

    It 'disables SMB1 only through the optional-feature cmdlets and re-enables it on revert' {
        $script:Feat = 'Enabled'
        Mock Get-WindowsOptionalFeature -ModuleName iGWindowsTuner { [pscustomobject]@{ FeatureName = $FeatureName; State = $script:Feat } }
        Mock Disable-WindowsOptionalFeature -ModuleName iGWindowsTuner { $script:Feat = 'Disabled' }
        Mock Enable-WindowsOptionalFeature -ModuleName iGWindowsTuner { $script:Feat = 'Enabled' }
        $r = Invoke-RoundTrip ([pscustomobject]@{ type = 'optionalFeature'; feature = 'SMB1Protocol'; on = 'Disabled'; default = 'Disabled' }) $script:WiredCtx
        $r.After | Should -Be 'On'; $script:Feat | Should -Be 'Enabled'
    }
}

Describe 'Startup Apps (StartupApproved only, never deleted)' {
    It 'disables an HKCU Run entry via StartupApproved and restores it from the snapshot' {
        New-Item -Path 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Run' -Force | Out-Null
        Set-ItemProperty -Path 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Steam' -Value '"C:\Steam\steam.exe" -silent'
        $item = Get-IgwtStartupItem | Where-Object { $_.Name -eq 'Steam' }
        $item.Enabled | Should -BeTrue
        $snap = Set-IgwtStartupItemEnabled -Scope 'HKCU-Run' -Name 'Steam' -Enabled $false
        (Get-IgwtStartupItem | Where-Object { $_.Name -eq 'Steam' }).Enabled | Should -BeFalse
        (Get-ItemProperty 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Run').Steam | Should -Not -BeNullOrEmpty
        $r = Invoke-IgwtRevert -SnapshotPath $snap -Context (New-IgwtTestContext)
        $r.Results[0].Result | Should -Be 'Reverted'
        (Get-IgwtStartupItem | Where-Object { $_.Name -eq 'Steam' }).Enabled | Should -BeTrue
    }
}
