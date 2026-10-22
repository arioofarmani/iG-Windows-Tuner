# Expert inspectors and the power plan editor. powercfg, PnP, CIM and NetAdapter
# cmdlets are mocked; registry access stays in TestRegistry. Nothing touches the real system.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    $script:Sub = '54533251-82be-4824-96c1-47b60b740d00'
    $script:Plan = '98bdb6d0-a4b4-4553-9c5b-a1fd54831f74'
    $script:Balanced = '381b4222-f694-41f0-9685-ff5bb260df2e'
    $script:Defs = @{
        PERFEPP = @{ Guid = '36687f9e-e3a5-4dbf-b1dc-15eb381c6863'; Name = 'Processor energy performance preference policy'; Min = 0; Max = 100; Inc = 1; Units = '%' }
        PERFBOOSTMODE = @{ Guid = 'be337238-0d82-4146-a960-4f3749d470c7'; Name = 'Processor performance boost mode'; Options = @('Disabled', 'Enabled', 'Aggressive', 'Efficient Enabled', 'Efficient Aggressive') }
        CPMINCORES = @{ Guid = '0cc5b647-c1df-4637-891a-dec35c318583'; Name = 'Processor performance core parking min cores'; Min = 0; Max = 100; Inc = 1; Units = '%' }
        PROCTHROTTLEMIN = @{ Guid = '893dee8e-2bef-41e0-89c6-b55d0929964c'; Name = 'Minimum processor state'; Min = 0; Max = 100; Inc = 1; Units = '%' }
        IDLEDISABLE = @{ Guid = '5d76a2ca-e8c0-402f-a133-2158492d58ad'; Name = 'Processor idle disable'; Options = @('Enable idle', 'Disable idle') }
    }

    function ConvertTo-PowerCfgText {
        # Builds powercfg /qh style output for the settings in $script:PowerState (AC/DC or $null for UNKNOWN).
        param([string[]]$Aliases, [string]$Scheme = $script:Plan)
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.AppendLine("Power Scheme GUID: $Scheme  (Test plan)")
        $null = $sb.AppendLine("  Subgroup GUID: $script:Sub  (Processor power management)")
        $null = $sb.AppendLine('    GUID Alias: SUB_PROCESSOR')
        foreach ($a in $Aliases) {
            $d = $script:Defs[$a]; $st = $script:PowerState[$a]
            $null = $sb.AppendLine("    Power Setting GUID: $($d.Guid)  ($($d.Name))")
            $null = $sb.AppendLine("      GUID Alias: $a")
            if ($d.Options) {
                for ($i = 0; $i -lt $d.Options.Count; $i++) { $null = $sb.AppendLine(('      Possible Setting Index: {0:D3}' -f $i)); $null = $sb.AppendLine("      Possible Setting Friendly Name: $($d.Options[$i])") }
            } else {
                $null = $sb.AppendLine(('      Minimum Possible Setting: 0x{0:x8}' -f $d.Min)); $null = $sb.AppendLine(('      Maximum Possible Setting: 0x{0:x8}' -f $d.Max))
                $null = $sb.AppendLine(('      Possible Settings increment: 0x{0:x8}' -f $d.Inc)); $null = $sb.AppendLine("      Possible Settings units: $($d.Units)")
            }
            foreach ($k in 'AC', 'DC') {
                $v = $(if ($st) { $st[$k] } else { $null })
                $null = $sb.AppendLine("    Current $k Power Setting Index: $(if ($null -ne $v) { '0x{0:x8}' -f [int]$v } else { 'UNKNOWN' })")
            }
            $null = $sb.AppendLine('')
        }
        return $sb.ToString()
    }

    function Initialize-PowerMock {
        param([string[]]$Tags = @())
        $script:PowerState = @{ PERFEPP = @{ AC = 5; DC = 50 }; PERFBOOSTMODE = @{ AC = 2; DC = 2 }; CPMINCORES = @{ AC = 4; DC = 4 }; PROCTHROTTLEMIN = @{ AC = 100; DC = 5 }; IDLEDISABLE = @{ AC = 0; DC = 0 } }
        $script:PowerTags = $Tags
        Mock -ModuleName iGWindowsTuner Get-IgwtHardwareProfile { [pscustomobject]@{ Tags = @($script:PowerTags) } }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPowerCfg {
            $cmd = ([string]$Arguments[0]).ToLowerInvariant()
            switch ($cmd) {
                '/getactivescheme' { return [pscustomobject]@{ ExitCode = 0; Output = "Power Scheme GUID: $script:Plan  (Test plan)" } }
                '/list' { return [pscustomobject]@{ ExitCode = 0; Output = "Power Scheme GUID: $script:Plan  (Test plan) *`nPower Scheme GUID: $script:Balanced  (Balanced)" } }
                '/qh' {
                    $aliases = @($script:Defs.Keys | Sort-Object)
                    if ($Arguments.Count -ge 4) { $aliases = @($script:Defs.Keys | Where-Object { $script:Defs[$_].Guid -eq [string]$Arguments[3] }) }
                    return [pscustomobject]@{ ExitCode = 0; Output = (ConvertTo-PowerCfgText -Aliases $aliases) }
                }
                '/query' {
                    $alias = @($script:Defs.Keys | Where-Object { $script:Defs[$_].Guid -eq [string]$Arguments[3] })[0]
                    return [pscustomobject]@{ ExitCode = 0; Output = (ConvertTo-PowerCfgText -Aliases @($alias)) }
                }
                { $_ -in '/setacvalueindex', '/setdcvalueindex' } {
                    $alias = @($script:Defs.Keys | Where-Object { $script:Defs[$_].Guid -eq [string]$Arguments[3] })[0]
                    $script:PowerState[$alias][$(if ($cmd -eq '/setacvalueindex') { 'AC' } else { 'DC' })] = [int]$Arguments[4]
                    return [pscustomobject]@{ ExitCode = 0; Output = '' }
                }
                default { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
            }
        }
        $root = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power'
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($s in @(@{ G = $script:Plan; F = '@%SystemRoot%\system32\powrprof.dll,-19,Ultimate Performance' }, @{ G = $script:Balanced; F = '@%SystemRoot%\system32\powrprof.dll,-15,Balanced' }, @{ G = 'e9a42b02-d5df-448d-aa00-03f14749eb61'; F = '@%SystemRoot%\system32\powrprof.dll,-19,Ultimate Performance' })) {
            $null = New-Item -Path "$root\User\PowerSchemes\$($s.G)" -Force
            $null = New-ItemProperty -Path "$root\User\PowerSchemes\$($s.G)" -Name FriendlyName -Value $s.F -PropertyType String
        }
        foreach ($a in 'PERFEPP', 'PERFBOOSTMODE', 'CPMINCORES', 'PROCTHROTTLEMIN') {
            $k = "$root\PowerSettings\$script:Sub\$($script:Defs[$a].Guid)"
            $null = New-Item -Path "$k\DefaultPowerSchemeValues\$script:Balanced" -Force
            $null = New-ItemProperty -Path $k -Name Attributes -Value $(if ($a -eq 'PROCTHROTTLEMIN') { 2 } else { 1 }) -PropertyType DWord
            $def = @{ PERFEPP = @(33, 50); PERFBOOSTMODE = @(2, 2); CPMINCORES = @(100, 10); PROCTHROTTLEMIN = @(5, 5) }[$a]
            $null = New-ItemProperty -Path "$k\DefaultPowerSchemeValues\$script:Balanced" -Name ACSettingIndex -Value $def[0] -PropertyType DWord
            $null = New-ItemProperty -Path "$k\DefaultPowerSchemeValues\$script:Balanced" -Name DCSettingIndex -Value $def[1] -PropertyType DWord
        }
    }
}

Describe 'powercfg output parser' {
    It 'reads numeric and enumerated settings, ranges, units and AC/DC indexes' {
        $script:PowerState = @{ PERFEPP = @{ AC = 5; DC = 50 }; PERFBOOSTMODE = @{ AC = 2; DC = 1 } }
        $p = InModuleScope iGWindowsTuner -Parameters @{ T = (ConvertTo-PowerCfgText -Aliases @('PERFEPP', 'PERFBOOSTMODE')) } { param($T) ConvertFrom-IgwtPowerCfgQuery -Text $T }
        @($p).Count | Should -Be 2
        $epp = $p | Where-Object { $_.Alias -eq 'PERFEPP' }
        $epp.Guid | Should -Be '36687f9e-e3a5-4dbf-b1dc-15eb381c6863'
        $epp.Min | Should -Be 0; $epp.Max | Should -Be 100; $epp.Units | Should -Be '%'
        $epp.AC | Should -Be 5; $epp.DC | Should -Be 50
        $boost = $p | Where-Object { $_.Alias -eq 'PERFBOOSTMODE' }
        @($boost.Options).Count | Should -Be 5
        $boost.Options[2].Name | Should -Be 'Aggressive'
        $boost.AC | Should -Be 2; $boost.DC | Should -Be 1
    }
    It 'treats UNKNOWN indexes as unknown instead of shifting the range values' {
        $script:PowerState = @{ PERFEPP = @{ AC = $null; DC = $null } }
        $p = InModuleScope iGWindowsTuner -Parameters @{ T = (ConvertTo-PowerCfgText -Aliases @('PERFEPP')) } { param($T) ConvertFrom-IgwtPowerCfgQuery -Text $T }
        $p[0].AC | Should -BeNullOrEmpty; $p[0].Max | Should -Be 100
    }
    It 'does not depend on the localized labels' {
        $text = "Energieschema-GUID: $script:Plan  (Test)`n  GUID der Untergruppe: $script:Sub  (Prozessor)`n    GUID-Alias: SUB_PROCESSOR`n" +
        "    GUID der Energieeinstellung: 893dee8e-2bef-41e0-89c6-b55d0929964c  (Minimaler Leistungszustand des Prozessors)`n      GUID-Alias: PROCTHROTTLEMIN`n" +
        "      Minimale moegliche Einstellung: 0x00000000`n      Maximale moegliche Einstellung: 0x00000064`n      Schrittweite: 0x00000001`n      Einheiten: %`n" +
        "    Index der aktuellen Wechselstromeinstellung: 0x00000064`n    Index der aktuellen Gleichstromeinstellung: 0x00000005`n"
        $p = InModuleScope iGWindowsTuner -Parameters @{ T = $text } { param($T) ConvertFrom-IgwtPowerCfgQuery -Text $T }
        $p[0].Alias | Should -Be 'PROCTHROTTLEMIN'; $p[0].AC | Should -Be 100; $p[0].DC | Should -Be 5; $p[0].Units | Should -Be '%'
    }
}

Describe 'Power plan editor settings' {
    It 'validates and covers the settings named in the specification, never idle disable' {
        @(Test-IgwtPowerSettingCatalog) | Should -BeNullOrEmpty
        $aliases = @(Get-IgwtPowerSettingCatalog -Force | ForEach-Object { $_.alias })
        foreach ($a in 'PERFEPP', 'PERFBOOSTMODE', 'PERFBOOSTPOL', 'PROCTHROTTLEMIN', 'PROCTHROTTLEMAX', 'CPMINCORES', 'CPCONCURRENCY', 'IDLEPROMOTE', 'IDLEDEMOTE', 'HETEROPOLICY', 'SCHEDPOLICY', 'SHORTSCHEDPOLICY') { $aliases | Should -Contain $a }
        $aliases | Should -Not -Contain 'IDLEDISABLE'
        foreach ($s in Get-IgwtPowerSettingCatalog) { ([string]$s.hint).Length | Should -BeLessOrEqual 140 -Because $s.alias }
    }
}

Describe 'Power plan inspector and editor' {
    BeforeEach { Initialize-PowerMock }

    It 'lists settings with defaults, hidden state and editability (read-only)' {
        $i = Get-IgwtPowerSettingsInspection
        $i.Scheme | Should -Be $script:Plan
        $i.DefaultsFrom | Should -Be 'Balanced (reference)'
        $epp = $i.Settings | Where-Object { $_.Alias -eq 'PERFEPP' }
        $epp.Editable | Should -BeTrue; $epp.Hidden | Should -BeTrue
        $epp.DefaultAC | Should -Be 33; $epp.ChangedFromDefault | Should -BeTrue
        ($i.Settings | Where-Object { $_.Alias -eq 'PROCTHROTTLEMIN' }).Hidden | Should -BeFalse
        ($i.Settings | Where-Object { $_.Alias -eq 'IDLEDISABLE' }).Editable | Should -BeFalse
        Should -Invoke Invoke-IgwtPowerCfg -ModuleName iGWindowsTuner -ParameterFilter { $Arguments[0] -like '/set*' } -Times 0 -Exactly
    }
    It 'marks settings blocked by hardware overlays (Intel hybrid core parking, laptop battery values)' {
        Initialize-PowerMock -Tags @('intel.hybrid')
        $i = Get-IgwtPowerSettingsInspection
        ($i.Settings | Where-Object { $_.Alias -eq 'CPMINCORES' }).Blocked | Should -BeTrue
        ($i.Settings | Where-Object { $_.Alias -eq 'CPMINCORES' }).Editable | Should -BeFalse
        ($i.Settings | Where-Object { $_.Alias -eq 'PERFEPP' }).Blocked | Should -BeFalse
        { Invoke-IgwtPowerSettingChange -Setting CPMINCORES -AC 100 -AcknowledgeRisk } | Should -Throw '*Blocked on this hardware*'
        Initialize-PowerMock -Tags @('formfactor.laptop')
        ($i = Get-IgwtPowerSettingsInspection) | Out-Null
        ($i.Settings | Where-Object { $_.Alias -eq 'PERFEPP' }).DcBlocked | Should -BeTrue
        { Invoke-IgwtPowerSettingChange -Setting PERFEPP -DC 0 -AcknowledgeRisk } | Should -Throw '*Blocked on this hardware*'
        (Get-IgwtPowerSettingChangePlan -Setting PERFEPP -AC 0).HasChange | Should -BeTrue
    }
    It 'refuses values outside the reported range, unknown settings and missing acknowledgement' {
        { Invoke-IgwtPowerSettingChange -Setting PERFEPP -AC 101 -AcknowledgeRisk } | Should -Throw '*outside the allowed range*'
        { Invoke-IgwtPowerSettingChange -Setting PERFBOOSTMODE -AC 9 -AcknowledgeRisk } | Should -Throw '*not one of the allowed values*'
        { Invoke-IgwtPowerSettingChange -Setting IDLEDISABLE -AC 1 -AcknowledgeRisk } | Should -Throw '*not editable*'
        { Invoke-IgwtPowerSettingChange -Setting PERFEPP -AC 10 } | Should -Throw '*AcknowledgeRisk*'
        { Invoke-IgwtPowerSettingChange -Setting PERFEPP -AcknowledgeRisk } | Should -Throw '*-AC, -DC or -Default*'
        Should -Invoke Invoke-IgwtPowerCfg -ModuleName iGWindowsTuner -ParameterFilter { $Arguments[0] -like '/set*' } -Times 0 -Exactly
    }
    It 'changes a setting after a snapshot and reverts it exactly' {
        $r = Invoke-IgwtPowerSettingChange -Setting PERFEPP -AC 20 -AcknowledgeRisk
        $r.Changes | Should -Be 1
        $script:PowerState.PERFEPP.AC | Should -Be 20; $script:PowerState.PERFEPP.DC | Should -Be 50
        Should -Invoke Invoke-IgwtPowerCfg -ModuleName iGWindowsTuner -ParameterFilter { $Arguments[0] -eq '/setdcvalueindex' } -Times 0 -Exactly
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.operation | Should -Be 'Power'
        $doc.entries[0].actions[0].data.ac | Should -Be 5
        $rev = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        @($rev.Results)[0].Result | Should -Be 'Reverted'
        $script:PowerState.PERFEPP.AC | Should -Be 5; $script:PowerState.PERFEPP.DC | Should -Be 50
        Test-Path -LiteralPath $rev.Snapshot | Should -BeTrue
    }
    It 'returns a setting to the Windows default' {
        $null = Invoke-IgwtPowerSettingChange -Setting PROCTHROTTLEMIN -Default -AcknowledgeRisk
        $script:PowerState.PROCTHROTTLEMIN.AC | Should -Be 5; $script:PowerState.PROCTHROTTLEMIN.DC | Should -Be 5
    }
    It 'writes nothing for a no-op change' {
        $r = Invoke-IgwtPowerSettingChange -Setting PERFBOOSTMODE -AC 2 -AcknowledgeRisk
        $r.Changes | Should -Be 0; $r.Snapshot | Should -BeNullOrEmpty
    }
    It 'rejects snapshot entries for settings the editor does not cover' {
        $r = Invoke-IgwtPowerSettingChange -Setting PERFEPP -AC 20 -AcknowledgeRisk
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.entries[0].actions[0].data.setting = $script:Defs.IDLEDISABLE.Guid
        Set-Content -LiteralPath $r.Snapshot -Value ($doc | ConvertTo-Json -Depth 20) -Encoding UTF8
        @((Invoke-IgwtRevert -SnapshotPath $r.Snapshot).Results)[0].Result | Should -Be 'Failed'
        $script:PowerState.IDLEDISABLE.AC | Should -Be 0
    }
    It 'compares plan copies with the built-in plan they came from' {
        $hp = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'; $copy = '11111111-2222-3333-4444-555555555555'
        $root = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
        foreach ($g in $hp, $copy) { $null = New-Item -Path "$root\$g" -Force; $null = New-ItemProperty -Path "$root\$g" -Name FriendlyName -Value '@%SystemRoot%\system32\powrprof.dll,-13,High performance' -PropertyType String }
        (InModuleScope iGWindowsTuner -Parameters @{ C = $copy; S = $script:Sub } { param($C, $S) Get-IgwtPowerDefaults -Scheme $C -Subgroup $S }).Source | Should -Be 'High performance'
        (InModuleScope iGWindowsTuner -Parameters @{ C = $script:Balanced; S = $script:Sub } { param($C, $S) Get-IgwtPowerDefaults -Scheme $C -Subgroup $S }).Source | Should -Be 'plan'
    }
}

Describe 'Interrupt inspector (read-only)' {
    BeforeAll {
        $script:GpuId = 'PCI\VEN_10DE&DEV_2206&SUBSYS_00000000&REV_A1\4&1234&0&0008'
        $script:NicId = 'PCI\VEN_1D6A&DEV_04C0&SUBSYS_00000000&REV_02\4&5678&0&00E4'
        $script:HdaId = 'PCI\VEN_8086&DEV_7AD0&SUBSYS_00000000&REV_11\3&11583659&0&FB'
        $script:NvmeId = 'PCI\VEN_144D&DEV_A80A&SUBSYS_A801144D&REV_00\4&9999&0&0010'
    }
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-PnpDevice { @(
                [pscustomobject]@{ InstanceId = $script:GpuId; FriendlyName = 'Test GPU'; Class = 'Display'; Status = 'OK' }
                [pscustomobject]@{ InstanceId = $script:NicId; FriendlyName = 'Test NIC'; Class = 'Net'; Status = 'OK' }
                [pscustomobject]@{ InstanceId = $script:HdaId; FriendlyName = 'High Definition Audio Controller'; Class = 'System'; Status = 'OK' }
                [pscustomobject]@{ InstanceId = $script:NvmeId; FriendlyName = 'Standard NVM Express Controller'; Class = 'SCSIAdapter'; Status = 'OK' }
                [pscustomobject]@{ InstanceId = 'USB\ROOT_HUB30\1'; FriendlyName = 'Root hub'; Class = 'USB'; Status = 'OK' }
            ) }
        Mock -ModuleName iGWindowsTuner Get-PnpDeviceProperty {
            $sup = @{ $script:GpuId = 3; $script:NicId = 7; $script:HdaId = 3; $script:NvmeId = 7 }[[string]$InstanceId]
            $max = @{ $script:GpuId = 1; $script:NicId = 32; $script:HdaId = 1; $script:NvmeId = 130 }[[string]$InstanceId]
            @([pscustomobject]@{ InstanceId = $InstanceId; KeyName = 'DEVPKEY_PciDevice_InterruptSupport'; Data = $sup }, [pscustomobject]@{ InstanceId = $InstanceId; KeyName = 'DEVPKEY_PciDevice_InterruptMessageMaximum'; Data = $max })
        }
        $irq = { param($id, $n) [pscustomobject]@{ Antecedent = [pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'Win32_IRQResource' }; IRQNumber = $n }; Dependent = [pscustomobject]@{ DeviceID = $id } } }
        $script:Alloc = @((& $irq $script:GpuId 4294967291), (& $irq $script:NicId 4294967280), (& $irq $script:NicId 4294967279), (& $irq $script:HdaId 17))
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_PnPAllocatedResource' } { $script:Alloc }
        $base = "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Enum\$script:GpuId\Device Parameters\Interrupt Management"
        $null = New-Item -Path "$base\MessageSignaledInterruptProperties" -Force
        $null = New-ItemProperty -Path "$base\MessageSignaledInterruptProperties" -Name MSISupported -Value 1 -PropertyType DWord -Force
        $null = New-Item -Path "$base\Affinity Policy" -Force
        $null = New-ItemProperty -Path "$base\Affinity Policy" -Name DevicePolicy -Value 4 -PropertyType DWord -Force
        $null = New-ItemProperty -Path "$base\Affinity Policy" -Name DevicePriority -Value 3 -PropertyType DWord -Force
        $null = New-ItemProperty -Path "$base\Affinity Policy" -Name AssignmentSetOverride -Value ([byte[]](0x0C, 0, 0, 0, 0, 0, 0, 0)) -PropertyType Binary -Force
    }
    It 'reports supported and current interrupt modes, MSI configuration and affinity' {
        $r = Get-IgwtInterruptInspection
        $gpu = $r.Devices | Where-Object { $_.InstanceId -eq $script:GpuId }
        $gpu.CurrentMode | Should -Be 'Message-signaled'; $gpu.Messages | Should -Be 1
        @($gpu.Supports) | Should -Be @('Line', 'MSI')
        $gpu.MsiSupported | Should -Be 1
        $gpu.PolicyName | Should -Be 'Specified processors'; $gpu.PriorityName | Should -Be 'High'
        @($gpu.TargetCpus) | Should -Be @(2, 3)
        $gpu.CatalogClass | Should -Be 'Display'
        $nic = $r.Devices | Where-Object { $_.InstanceId -eq $script:NicId }
        $nic.Messages | Should -Be 2; @($nic.Supports) | Should -Contain 'MSI-X'
        $hda = $r.Devices | Where-Object { $_.InstanceId -eq $script:HdaId }
        $hda.CurrentMode | Should -Be 'Line-based'; @($hda.Irqs) | Should -Be @(17); $hda.CatalogClass | Should -BeNullOrEmpty
        ($r.Devices | Where-Object { $_.InstanceId -eq $script:NvmeId }).Note | Should -Match 'Storage controller'
        @($r.Devices | Where-Object { $_.InstanceId -like 'USB\*' }) | Should -BeNullOrEmpty
        $r.MessageSignaled | Should -Be 2; $r.LineBased | Should -Be 1
    }
    It 'converts affinity masks and interrupt resources' {
        InModuleScope iGWindowsTuner {
            @(ConvertFrom-IgwtAffinityMask -Value ([uint64]5)) | Should -Be @(0, 2)
            @(ConvertFrom-IgwtAffinityMask -Value ([byte[]](0, 1))) | Should -Be @(8)
            (Get-IgwtInterruptMode -Irqs @()).Mode | Should -Be 'Unknown'
            (Get-IgwtInterruptMode -Irqs @(16, 17)).Mode | Should -Be 'Line-based'
        }
    }
}

Describe 'NIC queue inspector (read-only)' {
    BeforeEach {
        $script:Rss = [pscustomobject]@{ Enabled = $true; Profile = 'NUMAStatic'; BaseProcessorNumber = 0; MaxProcessorNumber = 23; NumberOfReceiveQueues = 4 }
        $script:Discarded = 120
        Mock -ModuleName iGWindowsTuner Get-NetAdapter { @([pscustomobject]@{ Name = 'Ethernet'; InterfaceDescription = 'Test 2.5GbE'; Status = 'Up'; LinkSpeed = '2.5 Gbps' }) }
        Mock -ModuleName iGWindowsTuner Get-NetAdapterRss { $script:Rss }
        Mock -ModuleName iGWindowsTuner Get-NetAdapterAdvancedProperty { @(
                [pscustomobject]@{ RegistryKeyword = '*ReceiveBuffers'; DisplayName = 'Receive Buffers'; RegistryValue = @('512'); DisplayValue = '512'; DefaultRegistryValue = '512'; NumericParameterMinValue = 80; NumericParameterMaxValue = 4096; ValidRegistryValues = $null }
                [pscustomobject]@{ RegistryKeyword = '*TransmitBuffers'; DisplayName = 'Transmit Buffers'; RegistryValue = @('2048'); DisplayValue = '2048'; DefaultRegistryValue = '2048'; NumericParameterMinValue = 80; NumericParameterMaxValue = 4096; ValidRegistryValues = $null }
                [pscustomobject]@{ RegistryKeyword = '*RssBaseProcNumber'; DisplayName = 'RSS Base Processor Number'; RegistryValue = @('0'); DisplayValue = '0'; DefaultRegistryValue = '0'; NumericParameterMinValue = 0; NumericParameterMaxValue = 63; ValidRegistryValues = $null }
                [pscustomobject]@{ RegistryKeyword = '*JumboPacket'; DisplayName = 'Jumbo Packet'; RegistryValue = @('1514'); DisplayValue = 'Disabled'; DefaultRegistryValue = '1514' }
            ) }
        Mock -ModuleName iGWindowsTuner Get-NetAdapterStatistics { [pscustomobject]@{ ReceivedDiscardedPackets = $script:Discarded; ReceivedPacketErrors = 0 } }
    }
    It 'reports RSS placement, buffers and evidence-based advice' {
        $a = @((Get-IgwtNicQueueInspection).Adapters)[0]
        $a.RssEnabled | Should -BeTrue; $a.BaseProcessor | Should -Be 0; $a.ReceiveQueues | Should -Be 4
        $a.ReceiveBuffers.Max | Should -Be 4096; $a.DiscardedPackets | Should -Be 120
        ($a.Advice -join ' ') | Should -Match 'logical processor 0'
        ($a.Advice -join ' ') | Should -Match "Raising 'Receive Buffers'"
    }
    It 'recommends RSS when it is off and leaves buffers alone without discards' {
        $script:Rss = [pscustomobject]@{ Enabled = $false; Profile = ''; BaseProcessorNumber = 0; MaxProcessorNumber = 23; NumberOfReceiveQueues = 1 }
        $script:Discarded = 0
        $a = @((Get-IgwtNicQueueInspection).Adapters)[0]
        ($a.Advice -join ' ') | Should -Match 'net.rss-on'
        ($a.Advice -join ' ') | Should -Match 'large enough'
    }
}

Describe 'Kernel, timer and crash inspectors (read-only)' {
    BeforeEach {
        $mm = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        $null = New-Item -Path $mm -Force
        $null = New-ItemProperty -Path $mm -Name LargeSystemCache -Value 0 -PropertyType DWord -Force
        $null = New-ItemProperty -Path $mm -Name DisablePagingExecutive -Value 1 -PropertyType DWord -Force
        $null = New-ItemProperty -Path $mm -Name PagingFiles -Value @('?:\pagefile.sys') -PropertyType MultiString -Force
        $null = New-ItemProperty -Path $mm -Name PagefileUsage -Value ([byte[]](1, 2, 3)) -PropertyType Binary -Force
        $null = New-ItemProperty -Path $mm -Name MysteryValue -Value 7 -PropertyType DWord -Force
        $mp = 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
        $null = New-Item -Path $mp -Force
        $null = New-ItemProperty -Path $mp -Name NetworkThrottlingIndex -Value -1 -PropertyType DWord -Force
        $null = New-ItemProperty -Path $mp -Name SystemResponsiveness -Value 20 -PropertyType DWord -Force
        $cc = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\CrashControl'
        $null = New-Item -Path $cc -Force
        $null = New-ItemProperty -Path $cc -Name CrashDumpEnabled -Value 0 -PropertyType DWord -Force
        $mini = Join-Path $TestDrive 'Minidump'; $null = New-Item -ItemType Directory -Path $mini -Force
        Set-Content -LiteralPath (Join-Path $mini 'Mini1.dmp') -Value ('x' * 100)
        $null = New-ItemProperty -Path $cc -Name MinidumpDir -Value $mini -PropertyType ExpandString -Force
        $null = New-ItemProperty -Path $cc -Name DumpFile -Value (Join-Path $TestDrive 'MEMORY.DMP') -PropertyType ExpandString -Force
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_PageFileUsage' } { @([pscustomobject]@{ Name = 'C:\pagefile.sys'; AllocatedBaseSize = 2048; CurrentUsage = 10; PeakUsage = 40 }) }
    }
    It 'annotates values with defaults, status and the catalog or rejected entry' {
        $k = Get-IgwtKernelInspection
        $mem = $k.Keys | Where-Object { $_.Id -eq 'memory' }
        ($mem.Values | Where-Object { $_.Name -eq 'LargeSystemCache' }).Status | Should -Be 'Default'
        $dpe = $mem.Values | Where-Object { $_.Name -eq 'DisablePagingExecutive' }
        $dpe.Status | Should -Be 'Changed'; $dpe.Rejected | Should -Be 'rejected.disable-paging-executive'
        ($mem.Values | Where-Object { $_.Name -eq 'PagingFiles' }).Status | Should -Be 'Default'
        ($mem.Values | Where-Object { $_.Name -eq 'PagefileUsage' }).Current | Should -Be 'binary (3 bytes)'
        ($mem.Values | Where-Object { $_.Name -eq 'MysteryValue' }).Status | Should -Be 'Undocumented'
        ($mem.Values | Where-Object { $_.Name -eq 'ClearPageFileAtShutdown' }).Status | Should -Be 'Absent'
        $mm = $k.Keys | Where-Object { $_.Id -eq 'multimedia' }
        $nti = $mm.Values | Where-Object { $_.Name -eq 'NetworkThrottlingIndex' }
        $nti.Current | Should -Be '4294967295 (0xFFFFFFFF)'; $nti.Status | Should -Be 'Changed'; $nti.Item | Should -Be 'sched.network-throttling-off'
        ($mm.Values | Where-Object { $_.Name -eq 'SystemResponsiveness' }).Status | Should -Be 'Default'
        ($k.Keys | Where-Object { $_.Id -eq 'kernel' }).Values | Where-Object { $_.Name -eq 'GlobalTimerResolutionRequests' } | ForEach-Object { $_.Status | Should -Be 'Default' }
    }
    It 'validates the kernel inspector data' {
        @(Test-IgwtKernelInspectorCatalog) | Should -BeNullOrEmpty
    }
    It 'reports crash dumps, page files and advice' {
        $c = Get-IgwtCrashInspection
        $c.DumpTypeName | Should -Be 'None'
        $c.Minidumps | Should -Be 1
        $c.PageFileMode | Should -Be 'SystemManagedAllDrives'
        @($c.PageFiles)[0].PeakMB | Should -Be 40
        ($c.Advice -join ' ') | Should -Match 'Crash dumps are off'
        Set-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name PagingFiles -Value ([string[]]@())
        $c = Get-IgwtCrashInspection
        $c.PageFileMode | Should -Be 'None'
        ($c.Advice -join ' ') | Should -Match 'system.pagefile-auto'
    }
    It 'explains the timer behaviour' {
        $k = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        $null = New-Item -Path $k -Force
        (Get-IgwtTimerInspection).Behaviour | Should -Match 'Per process'
        $null = New-ItemProperty -Path $k -Name GlobalTimerResolutionRequests -Value 1 -PropertyType DWord -Force
        $t = Get-IgwtTimerInspection
        $t.Behaviour | Should -Match 'Global'; $t.CurrentResolution | Should -BeNullOrEmpty
    }
    It 'keeps going when one inspector fails' {
        Mock -ModuleName iGWindowsTuner Get-IgwtNicQueueInspection { throw 'adapter query failed' }
        $i = Get-IgwtInspection -Area Network, Timer
        $i.Network.Error | Should -Match 'adapter query failed'
        $i.Timer.Behaviour | Should -Not -BeNullOrEmpty
        Format-IgwtInspection -Inspection $i | Should -Match 'Error: adapter query failed'
    }
}

Describe 'Expert and System catalog items' {
    BeforeAll { $script:Cat = @(Get-IgwtCatalog -Force) }
    It 'adds the System items, the processor-settings visibility item and GPU MSI' {
        foreach ($id in 'system.pagefile-auto', 'system.dump-small', 'system.verbose-status', 'system.bsod-details', 'power.show-processor-settings', 'gfx.gpu-msi') {
            $t = @($script:Cat | Where-Object { $_.id -eq $id })[0]
            $t | Should -Not -BeNullOrEmpty -Because $id
            $t.antiCheat | Should -Be 'safe' -Because $id
            $t.reversible | Should -Be 'full' -Because $id
        }
        @($script:Cat | Where-Object { $_.category -eq 'System' }).Count | Should -Be 14   # 4 from 2.0, 8 WinUtil-derived and 2 Session Mode items (3.0 phase 1)
    }
    It 'never disables the page file and only unhides power settings' {
        $pf = @($script:Cat | Where-Object { $_.id -eq 'system.pagefile-auto' })[0]
        @($pf.actions[0].on) | Should -Be @('?:\pagefile.sys')
        $vis = @($script:Cat | Where-Object { $_.id -eq 'power.show-processor-settings' })[0]
        foreach ($a in $vis.actions) { $a.type | Should -Be 'powercfgAttribute'; $a.visible | Should -BeTrue; $a.setting | Should -Not -Be '5d76a2ca-e8c0-402f-a133-2158492d58ad' }
    }
    It 'keeps GPU MSI an Expert item that needs a reboot and only sets MSISupported' {
        $g = @($script:Cat | Where-Object { $_.id -eq 'gfx.gpu-msi' })[0]
        $g.level | Should -Be 'Expert'; $g.requires | Should -Be 'reboot'; $g.warning | Should -Not -BeNullOrEmpty
        $g.actions[0].type | Should -Be 'deviceInterrupt'; $g.actions[0].deviceClass | Should -Be 'Display'
        $g.actions[0].PSObject.Properties['devicePolicy'] | Should -BeNullOrEmpty
    }
}

Describe 'Inspector command line (argument checks only)' {
    It 'rejects power editor options without -PowerSetting and -PowerSetting without a value' {
        $script = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Ac 3 -NoGui
        $LASTEXITCODE | Should -Be 2
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -PowerSetting PERFEPP -NoGui
        $LASTEXITCODE | Should -Be 2
    }
}
