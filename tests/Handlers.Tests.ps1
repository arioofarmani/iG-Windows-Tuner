# Round-trip tests for the 2.0 action handlers: detect -> snapshot (serialized like a snapshot
# file) -> apply -> detect -> restore -> detect. Registry-backed handlers run in TestRegistry;
# cmdlet-backed handlers use stateful mocks. Nothing touches the real system.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    function Invoke-RoundTrip {
        [CmdletBinding()]
        param($Action, $Context)
        InModuleScope iGWindowsTuner -Parameters @{ A = $Action; C = $Context } {
            param($A, $C)
            if (-not $C) { $C = New-IgwtContext -Override @{ IsAdmin = $true; Build = 26300 } }
            $roll = { param($items) Get-IgwtStateRollup -States @($items | ForEach-Object { [string]$_.State }) }
            $before = @(Get-IgwtActionState -Action $A -Context $C)
            $snap = Get-IgwtActionSnapshot -Action $A -Context $C
            $json = ConvertTo-Json -InputObject $snap -Depth 20 | ConvertFrom-Json
            $null = Invoke-IgwtActionApply -Action $A -Context $C -Mode on
            $after = @(Get-IgwtActionState -Action $A -Context $C)
            Restore-IgwtActionSnapshot -Action $A -Snapshot $json -Context $C
            $restored = @(Get-IgwtActionState -Action $A -Context $C)
            [pscustomobject]@{ Before = (& $roll $before); After = (& $roll $after); Restored = (& $roll $restored); Items = $after; Snapshot = $json }
        }
    }
    function Get-Reg([string]$Path, [string]$Name) { InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Get-IgwtRegistryValue -Path $P -Name $N } }
    function Write-Reg([string]$Path, [string]$Name, [string]$Kind, $Value) { InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name; K = $Kind; V = $Value } { param($P, $N, $K, $V) Set-IgwtRegistryValue -Path $P -Name $N -Kind $K -Value $V } }
    function ConvertTo-Act([hashtable]$H) { [pscustomobject]$H }
}

Describe 'storageSense and wufbPolicy (registry composites)' {
    It 'round-trips a Storage Sense policy and removes what did not exist' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'storageSense'; setting = 'cadence'; value = 7 })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense' 'ConfigStorageSenseGlobalCadence').Exists | Should -BeFalse
    }
    It 'round-trips a feature update deferral (two policy values)' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'wufbPolicy'; setting = 'featureDeferralDays'; value = 90 })
        $r.After | Should -Be 'On'
        @($r.Items).Count | Should -Be 2
        $r.Restored | Should -Be 'Off'
        (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferFeatureUpdatesPeriodInDays').Exists | Should -BeFalse
    }
    It 'restores an existing quality deferral exactly' {
        Write-Reg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferQualityUpdates' -Kind 'DWord' -Value 1
        Write-Reg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferQualityUpdatesPeriodInDays' -Kind 'DWord' -Value 5
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'wufbPolicy'; setting = 'qualityDeferralDays'; value = 10 })
        $r.After | Should -Be 'On'
        (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferQualityUpdatesPeriodInDays').Value | Should -Be 5
    }
    It 'pins a target release with string values' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'wufbPolicy'; setting = 'targetRelease'; value = [pscustomobject]@{ product = 'Windows 11'; version = '25H2' } })
        $r.After | Should -Be 'On'
        @($r.Items | Where-Object { $_.Target -like '*TargetReleaseVersionInfo' }).Desired | Should -Match '25H2'
        $r.Restored | Should -Be 'Off'
    }
}

Describe 'deviceInterrupt' {
    BeforeAll {
        $script:GpuA = 'PCI\VEN_10DE&DEV_2216&SUBSYS_404B1458&REV_A1\4&8BD6E8D&0&0008'
        $script:GpuB = 'PCI\VEN_8086&DEV_A780&SUBSYS_00001458&REV_04\3&11583659&0&10'
        $script:BaseA = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($script:GpuA)\Device Parameters\Interrupt Management"
        $script:BaseB = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($script:GpuB)\Device Parameters\Interrupt Management"
    }
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-PnpDevice { @([pscustomobject]@{ InstanceId = $script:GpuA; FriendlyName = 'NVIDIA GeForce RTX 3080'; Status = 'OK' }, [pscustomobject]@{ InstanceId = $script:GpuB; FriendlyName = 'Intel UHD Graphics 770'; Status = 'OK' }) }
        Write-Reg -Path "$($script:BaseA)\MessageSignaledInterruptProperties" -Name 'MSISupported' -Kind 'DWord' -Value 0
        Write-Reg -Path "$($script:BaseB)" -Name 'Placeholder' -Kind 'DWord' -Value 1
    }
    It 'sets MSI mode only where the driver declares MSI support and restores exactly' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'deviceInterrupt'; deviceClass = 'Display'; msiSupported = 1; devicePolicy = 5 })
        @($r.Items | Where-Object { $_.State -eq 'NotApplicable' }).Note | Should -Match 'does not declare MSI support'
        $r.After | Should -Be 'On'
        (Get-Reg "$($script:BaseA)\MessageSignaledInterruptProperties" 'MSISupported').Value | Should -Be 0
        (Get-Reg "$($script:BaseA)\Affinity Policy" 'DevicePolicy').Exists | Should -BeFalse
        (Get-Reg "$($script:BaseB)\Affinity Policy" 'DevicePolicy').Exists | Should -BeFalse
        $r.Restored | Should -Be 'Off'
    }
    It 'has no Windows default to reset to' {
        { InModuleScope iGWindowsTuner { Invoke-IgwtActionApply -Action ([pscustomobject]@{ type = 'deviceInterrupt'; deviceClass = 'Display'; msiSupported = 1 }) -Context (New-IgwtContext -Override @{}) -Mode default } } | Should -Throw '*no documented Windows default*'
    }
    It 'refuses device classes other than Display, Net and USB' {
        { InModuleScope iGWindowsTuner { Get-IgwtCompositeParts -Action ([pscustomobject]@{ type = 'deviceInterrupt'; deviceClass = 'SCSIAdapter'; msiSupported = 1 }) } } | Should -Throw '*not allowed*'
    }
    It 'never touches USB host controllers when Windows runs from a USB disk' {
        $ctx = InModuleScope iGWindowsTuner { New-IgwtContext -Override @{ HardwareProfile = [pscustomobject]@{ Facts = [pscustomobject]@{ systemDisk = [pscustomobject]@{ bus = 'USB' } } } } }
        $items = @(InModuleScope iGWindowsTuner -Parameters @{ C = $ctx } { param($C) Get-IgwtActionState -Action ([pscustomobject]@{ type = 'deviceInterrupt'; deviceClass = 'USB'; msiSupported = 1 }) -Context $C })
        $items[0].State | Should -Be 'NotApplicable'
        $items[0].Note | Should -Match 'USB disk'
    }
}

Describe 'serviceSet' {
    BeforeEach {
        foreach ($n in 'IgwtTestSvcA', 'IgwtTestSvcB') { Write-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$n" -Name 'Start' -Kind 'DWord' -Value 3 }
        Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = $Name[0]; Status = 'Stopped' } }
        Mock -ModuleName iGWindowsTuner Set-Service {
            $v = switch ([string]$StartupType) { 'Automatic' { 2 } 'Manual' { 3 } 'Disabled' { 4 } }
            Set-ItemProperty -LiteralPath "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value $v
        }
    }
    It 'round-trips several services as one action' {
        $a = ConvertTo-Act @{ type = 'serviceSet'; services = @([pscustomobject]@{ name = 'IgwtTestSvcA'; startupType = 'Disabled'; default = 'Manual' }, [pscustomobject]@{ name = 'IgwtTestSvcB'; startupType = 'Disabled'; default = 'Manual' }) }
        $r = Invoke-RoundTrip -Action $a
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\IgwtTestSvcB' 'Start').Value | Should -Be 3
    }
    It 'refuses protected services inside a set' {
        Write-Reg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name 'Start' -Kind 'DWord' -Value 2
        $a = ConvertTo-Act @{ type = 'serviceSet'; services = @([pscustomobject]@{ name = 'WinDefend'; startupType = 'Disabled'; default = 'Automatic' }) }
        { InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Invoke-IgwtActionApply -Action $A -Context (New-IgwtContext -Override @{}) } } | Should -Throw '*protected*'
    }
}

Describe 'powercfgAttribute and powercfgSettingAcDc' {
    BeforeAll {
        $script:Sub = '54533251-82be-4824-96c1-47b60b740d00'
        $script:Set = '0cc5b647-c1df-4637-891a-dec35c318583'
        $script:Scheme = '381b4222-f694-41f0-9685-ff5bb260df2e'
    }
    It 'shows a hidden power setting and restores the exact Attributes value' {
        Write-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$($script:Sub)\$($script:Set)" -Name 'Attributes' -Kind 'DWord' -Value 1
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPowerCfg {
            if ($Arguments[0] -eq '-attributes') {
                $v = $(if ($Arguments[3] -eq '-ATTRIB_HIDE') { 2 } else { 1 })
                Set-ItemProperty -LiteralPath "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$($Arguments[1])\$($Arguments[2])" -Name Attributes -Value $v
            }
            [pscustomobject]@{ ExitCode = 0; Output = '' }
        }
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'powercfgAttribute'; label = 'Core parking min cores'; subgroup = $script:Sub; setting = $script:Set; visible = $true; default = 'hidden' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        (Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$($script:Sub)\$($script:Set)" 'Attributes').Value | Should -Be 1
        Should -Invoke Invoke-IgwtPowerCfg -ModuleName iGWindowsTuner -ParameterFilter { $Arguments[0] -eq '-attributes' -and $Arguments[3] -eq '-ATTRIB_HIDE' } -Times 1 -Exactly
    }
    It 'reports a power setting that does not exist as not applicable' {
        $items = @(InModuleScope iGWindowsTuner -Parameters @{ S = $script:Sub } { param($S) Get-IgwtActionState -Action ([pscustomobject]@{ type = 'powercfgAttribute'; label = 'x'; subgroup = $S; setting = '11111111-2222-3333-4444-555555555555'; visible = $true }) -Context $null })
        $items[0].State | Should -Be 'NotApplicable'
    }
    It 'round-trips separate AC and DC values' {
        $script:Pc = @{ AC = 0; DC = 2 }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPowerCfg {
            switch ($Arguments[0]) {
                '/getactivescheme' { [pscustomobject]@{ ExitCode = 0; Output = "Power Scheme GUID: $($script:Scheme)  (Balanced)" } }
                '/list' { [pscustomobject]@{ ExitCode = 0; Output = "Power Scheme GUID: $($script:Scheme)  (Balanced) *" } }
                '/query' { [pscustomobject]@{ ExitCode = 0; Output = ("Current AC Power Setting Index: 0x{0:x8}`r`nCurrent DC Power Setting Index: 0x{1:x8}" -f $script:Pc.AC, $script:Pc.DC) } }
                '/setacvalueindex' { $script:Pc.AC = [int]$Arguments[4]; [pscustomobject]@{ ExitCode = 0; Output = '' } }
                '/setdcvalueindex' { $script:Pc.DC = [int]$Arguments[4]; [pscustomobject]@{ ExitCode = 0; Output = '' } }
                default { [pscustomobject]@{ ExitCode = 0; Output = '' } }
            }
        }
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'powercfgSettingAcDc'; label = 'EPP'; subgroup = $script:Sub; setting = '36687f9e-e3a5-4dbf-b1dc-15eb381c6863'; ac = 0; dc = 50; defaultAc = 50; defaultDc = 50 })
        $r.After | Should -Be 'On'
        $r.Restored | Should -Be 'Off'
        $script:Pc.AC | Should -Be 0
        $script:Pc.DC | Should -Be 2
    }
}

Describe 'scheduledTask' {
    BeforeEach {
        $script:TaskState = 'Ready'
        Mock -ModuleName iGWindowsTuner Get-ScheduledTask { [pscustomobject]@{ TaskPath = $TaskPath; TaskName = $TaskName; State = $script:TaskState } }
        Mock -ModuleName iGWindowsTuner Disable-ScheduledTask { $script:TaskState = 'Disabled' }
        Mock -ModuleName iGWindowsTuner Enable-ScheduledTask { $script:TaskState = 'Ready' }
    }
    It 'round-trips disabling an existing task' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'scheduledTask'; path = '\Microsoft\Windows\Application Experience\'; name = 'ProgramDataUpdater'; on = 'Disabled'; default = 'Enabled' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:TaskState | Should -Be 'Ready'
    }
    It 'refuses to disable security and update tasks' {
        $a = ConvertTo-Act @{ type = 'scheduledTask'; path = '\Microsoft\Windows\Windows Defender\'; name = 'Windows Defender Scheduled Scan'; on = 'Disabled'; default = 'Enabled' }
        { InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Invoke-IgwtActionApply -Action $A -Context $null } } | Should -Throw '*protected*'
        Should -Invoke Disable-ScheduledTask -ModuleName iGWindowsTuner -Times 0 -Exactly
    }
    It 'treats a missing task as not applicable' {
        Mock -ModuleName iGWindowsTuner Get-ScheduledTask { }
        $items = @(InModuleScope iGWindowsTuner { Get-IgwtActionState -Action ([pscustomobject]@{ type = 'scheduledTask'; path = '\X\'; name = 'Gone'; on = 'Disabled'; default = 'Enabled' }) -Context $null })
        $items[0].State | Should -Be 'NotApplicable'
    }
    It 'reads every task with one query in the cached index outside TestMode, and invalidates it on writes' {
        Mock -ModuleName iGWindowsTuner Get-ScheduledTask {
            if ($TaskName) { [pscustomobject]@{ TaskPath = $TaskPath; TaskName = $TaskName; State = $script:TaskState } }
            else { @([pscustomobject]@{ TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'ProgramDataUpdater'; State = $script:TaskState }, [pscustomobject]@{ TaskPath = '\X\'; TaskName = 'Other'; State = 'Ready' }) }
        }
        $r = InModuleScope iGWindowsTuner {
            $saved = $script:IgwtSettings.TestMode
            $script:IgwtSettings.TestMode = $false
            try {
                Clear-IgwtCache -WhatIf:$false
                $a = [pscustomobject]@{ type = 'scheduledTask'; path = '\Microsoft\Windows\Application Experience\'; name = 'ProgramDataUpdater'; on = 'Disabled'; default = 'Enabled' }
                $missing = [pscustomobject]@{ type = 'scheduledTask'; path = '\X\'; name = 'Gone'; on = 'Disabled'; default = 'Enabled' }
                $first = (Get-IgwtScheduledTaskState -Action $a).State
                $gone = (Get-IgwtScheduledTaskState -Action $missing).State
                Set-IgwtTaskEnabled -Action $a -Enabled $false
                $second = (Get-IgwtScheduledTaskState -Action $a).State
                [pscustomobject]@{ First = $first; Gone = $gone; Second = $second }
            } finally { $script:IgwtSettings.TestMode = $saved; Clear-IgwtCache -WhatIf:$false }
        }
        $r.First | Should -Be 'Off'
        $r.Gone | Should -Be 'NotApplicable'
        $r.Second | Should -Be 'On'
        Should -Invoke Get-ScheduledTask -ModuleName iGWindowsTuner -Times 2 -Exactly -ParameterFilter { -not $TaskName }
    }
}

Describe 'firewallRule' {
    BeforeEach {
        $script:Fw = @{}
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule {
            if ($Name) { if ($script:Fw.ContainsKey($Name[0])) { $script:Fw[$Name[0]] } }
            else { @($script:Fw.Values | Where-Object { $_.DisplayGroup -eq $DisplayGroup[0] }) }
        }
        Mock -ModuleName iGWindowsTuner New-NetFirewallRule { $script:Fw[$Name] = [pscustomobject]@{ Name = $Name; DisplayGroup = 'iG Windows Tuner'; Enabled = 'True'; Action = [string]$Action; Direction = [string]$Direction } }
        Mock -ModuleName iGWindowsTuner Remove-NetFirewallRule { $null = $script:Fw.Remove($Name[0]) }
        Mock -ModuleName iGWindowsTuner Set-NetFirewallRule { $script:Fw[$Name[0]].Enabled = [string]$Enabled }
        Mock -ModuleName iGWindowsTuner Disable-NetFirewallRule { foreach ($n in $Name) { $script:Fw[$n].Enabled = 'False' } }
        Mock -ModuleName iGWindowsTuner Enable-NetFirewallRule { foreach ($n in $Name) { $script:Fw[$n].Enabled = 'True' } }
    }
    It 'creates an iG Windows Tuner block rule and removes it on revert' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'firewallRule'; rule = 'iGWindowsTuner-Block-LLMNR-In'; displayName = 'iG Windows Tuner: block LLMNR inbound'; direction = 'Inbound'; action = 'Block'; protocol = 'UDP'; localPort = '5355' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:Fw.ContainsKey('iGWindowsTuner-Block-LLMNR-In') | Should -BeFalse
        Should -Invoke New-NetFirewallRule -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Group -eq 'iG Windows Tuner' -and $LocalPort[0] -eq '5355' }
    }
    It 'disables a rule group and restores each rule''s exact state' {
        foreach ($x in @(@('RA-1', 'True'), @('RA-2', 'True'), @('RA-3', 'False'))) { $script:Fw[$x[0]] = [pscustomobject]@{ Name = $x[0]; DisplayGroup = 'Remote Assistance'; Enabled = $x[1]; Direction = 'Inbound'; Action = 'Allow' } }
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'firewallRule'; displayGroup = 'Remote Assistance'; on = 'Disabled'; default = 'Enabled' })
        $r.After | Should -Be 'On'
        $script:Fw['RA-1'].Enabled | Should -Be 'True'
        $script:Fw['RA-3'].Enabled | Should -Be 'False'
    }
    It 'reads all owned rules with one wildcard query outside TestMode, and invalidates it on writes' {
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule {
            if ($Name -and $Name[0] -eq 'iGWindowsTuner-*') { @($script:Fw.Values | Where-Object { $_.Name -like 'iGWindowsTuner-*' }) }
            elseif ($Name) { if ($script:Fw.ContainsKey($Name[0])) { $script:Fw[$Name[0]] } }
        }
        $r = InModuleScope iGWindowsTuner {
            $saved = $script:IgwtSettings.TestMode
            $script:IgwtSettings.TestMode = $false
            try {
                Clear-IgwtCache -WhatIf:$false
                $mk = { param($n) [pscustomobject]@{ type = 'firewallRule'; rule = $n; displayName = 'x'; direction = 'Outbound'; action = 'Block'; program = 'C:\x.exe' } }
                $a = & $mk 'iGWindowsTuner-A'
                $b = & $mk 'iGWindowsTuner-B'
                $s1 = (Get-IgwtFirewallRuleState -Action $a).State
                $s2 = (Get-IgwtFirewallRuleState -Action $b).State
                Invoke-IgwtFirewallRuleApply -Action $a -Mode on
                $s3 = (Get-IgwtFirewallRuleState -Action $a).State
                [pscustomobject]@{ S1 = $s1; S2 = $s2; S3 = $s3 }
            } finally { $script:IgwtSettings.TestMode = $saved; Clear-IgwtCache -WhatIf:$false }
        }
        $r.S1 | Should -Be 'Off'; $r.S2 | Should -Be 'Off'; $r.S3 | Should -Be 'On'
        Should -Invoke Get-NetFirewallRule -ModuleName iGWindowsTuner -Times 2 -Exactly -ParameterFilter { $Name -and $Name[0] -eq 'iGWindowsTuner-*' }
    }
    It 'refuses rules it does not own and allow rules' {
        { InModuleScope iGWindowsTuner { Invoke-IgwtActionApply -Action ([pscustomobject]@{ type = 'firewallRule'; rule = 'CoreNet-DHCP-In'; displayName = 'x'; direction = 'Inbound'; action = 'Block' }) -Context $null } } | Should -Throw "*own firewall rules*"
        { InModuleScope iGWindowsTuner { Invoke-IgwtActionApply -Action ([pscustomobject]@{ type = 'firewallRule'; rule = 'iGWindowsTuner-Open'; displayName = 'x'; direction = 'Inbound'; action = 'Allow' }) -Context $null } } | Should -Throw '*only creates Block rules*'
    }
}

Describe 'appx, winget and capability' {
    AfterEach { InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $null } }
    BeforeEach {
        $script:AppInstalled = $true
        $script:AppDir = Join-Path $TestDrive 'WindowsApps\Microsoft.BingWeather_4.53'
        $null = New-Item -ItemType Directory -Path $script:AppDir -Force
        Set-Content -LiteralPath (Join-Path $script:AppDir 'AppxManifest.xml') -Value '<Package/>'
        Mock -ModuleName iGWindowsTuner Get-AppxPackage { if ($script:AppInstalled) { [pscustomobject]@{ Name = $Name; PackageFullName = 'Microsoft.BingWeather_4.53_x64__8wekyb3d8bbwe'; InstallLocation = $script:AppDir } } }
        Mock -ModuleName iGWindowsTuner Remove-AppxPackage { $script:AppInstalled = $false }
        Mock -ModuleName iGWindowsTuner Add-AppxPackage { $script:AppInstalled = $true }
        Mock -ModuleName iGWindowsTuner Get-AppxProvisionedPackage { @([pscustomobject]@{ DisplayName = 'Microsoft.BingWeather'; PackageName = 'Microsoft.BingWeather_4.53_neutral_~_8wekyb3d8bbwe' }) }
        Mock -ModuleName iGWindowsTuner Remove-AppxProvisionedPackage { }
        $script:Winget = @{}
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $true }   # the user accepted winget's agreements
        Mock -ModuleName iGWindowsTuner Invoke-IgwtWinget {
            switch ($Arguments[0]) {
                'list' { [pscustomobject]@{ ExitCode = $(if ($script:Winget[$Arguments[2]]) { 0 } else { -1978335212 }); Output = '' } }
                'install' { $script:Winget[$Arguments[2]] = $true; [pscustomobject]@{ ExitCode = 0; Output = '' } }
                'uninstall' { $script:Winget[$Arguments[2]] = $false; [pscustomobject]@{ ExitCode = 0; Output = '' } }
            }
        }
    }
    It 'removes an inbox app and re-registers it on revert' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'appx'; package = 'Microsoft.BingWeather'; on = 'Removed'; default = 'Installed'; provisioned = $true })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        Should -Invoke Remove-AppxProvisionedPackage -ModuleName iGWindowsTuner -Times 1 -Exactly
        Should -Invoke Add-AppxPackage -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Register -and $Path -like '*AppxManifest.xml' }
    }
    It 'reinstalls from the Store when the app files are gone' {
        $a = ConvertTo-Act @{ type = 'appx'; package = 'Microsoft.BingWeather'; on = 'Removed'; default = 'Installed'; storeId = '9WZDNCRFJ3Q2' }
        InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Restore-IgwtActionSnapshot -Action $A -Snapshot ([pscustomobject]@{ installed = $true; installLocation = 'C:\Gone' }) -Context $null } -ErrorAction Stop 2>$null
        Should -Invoke Invoke-IgwtWinget -ModuleName iGWindowsTuner -Times 0 -Exactly
        $script:AppInstalled = $false
        InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Restore-IgwtActionSnapshot -Action $A -Snapshot ([pscustomobject]@{ installed = $true; installLocation = 'C:\Gone' }) -Context $null }
        Should -Invoke Invoke-IgwtWinget -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'install' -and ($Arguments -join ' ') -match '--source msstore' }
    }
    It 'never removes protected apps' {
        { InModuleScope iGWindowsTuner { Invoke-IgwtActionApply -Action ([pscustomobject]@{ type = 'appx'; package = 'Microsoft.DesktopAppInstaller'; on = 'Removed'; default = 'Installed' }) -Context $null } } | Should -Throw '*protected*'
        InModuleScope iGWindowsTuner { Test-IgwtAppxProtected -Package 'Microsoft.VCLibs.140.00' } | Should -BeTrue
    }
    It 'round-trips a winget install' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'winget'; id = 'Microsoft.PowerToys'; on = 'Installed'; default = 'NotInstalled' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        Should -Invoke Invoke-IgwtWinget -ModuleName iGWindowsTuner -ParameterFilter { $Arguments[0] -eq 'uninstall' } -Times 1 -Exactly
    }
    It 'round-trips removing a Windows capability' {
        $script:Cap = 'Installed'
        Mock -ModuleName iGWindowsTuner Get-WindowsCapability { [pscustomobject]@{ Name = 'Microsoft.Windows.WordPad~~~~0.0.1.0'; State = $script:Cap } }
        Mock -ModuleName iGWindowsTuner Remove-WindowsCapability { $script:Cap = 'NotPresent' }
        Mock -ModuleName iGWindowsTuner Add-WindowsCapability { $script:Cap = 'Installed' }
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'capability'; name = 'Microsoft.Windows.WordPad~~~~0.0.1.0'; on = 'NotPresent'; default = 'Installed' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
    }
}

Describe 'processMitigation and exploitSystem' {
    BeforeEach {
        $script:Mit = @{}
        Mock -ModuleName iGWindowsTuner Get-ProcessMitigation {
            $key = $(if ($System) { 'system' } else { $Name })
            $get = { param($m) if ($script:Mit.ContainsKey("$key|$m")) { $script:Mit["$key|$m"] } else { 'NOTSET' } }
            [pscustomobject]@{ DEP = [pscustomobject]@{ Enable = (& $get 'DEP') }; SEHOP = [pscustomobject]@{ Enable = (& $get 'SEHOP') }
                ASLR = [pscustomobject]@{ BottomUp = (& $get 'BottomUp'); HighEntropy = (& $get 'HighEntropy'); ForceRelocateImages = (& $get 'ForceRelocateImages') }
                CFG = [pscustomobject]@{ Enable = (& $get 'CFG') } }
        }
        Mock -ModuleName iGWindowsTuner Set-ProcessMitigation {
            $key = $(if ($System) { 'system' } else { $Name })
            foreach ($m in @($Enable)) { if ($m) { $script:Mit["$key|$m"] = 'ON' } }
            foreach ($m in @($Disable)) { if ($m) { if ($Remove) { $null = $script:Mit.Remove("$key|$m") } else { $script:Mit["$key|$m"] = 'OFF' } } }
        }
    }
    It 'round-trips a per-program mitigation from NOTSET (restored with -Remove)' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'processMitigation'; process = 'dota2.exe'; mitigation = 'BottomUp'; on = 'ON' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'; $r.Restored | Should -Be 'Off'
        $script:Mit.ContainsKey('dota2.exe|BottomUp') | Should -BeFalse
        Should -Invoke Set-ProcessMitigation -ModuleName iGWindowsTuner -ParameterFilter { $Remove -and $Disable -contains 'BottomUp' } -Times 1 -Exactly
    }
    It 'restores an explicit OFF exactly' {
        $script:Mit['system|SEHOP'] = 'OFF'
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'exploitSystem'; mitigation = 'SEHOP'; on = 'ON' })
        $r.After | Should -Be 'On'
        $script:Mit['system|SEHOP'] | Should -Be 'OFF'
    }
    It 'never turns system-wide exploit protection off' {
        { InModuleScope iGWindowsTuner { Invoke-IgwtActionApply -Action ([pscustomobject]@{ type = 'exploitSystem'; mitigation = 'DEP'; on = 'OFF' }) -Context $null } } | Should -Throw '*never turns system-wide*'
    }
    It 'treats "use default" as on for repair-only items and writes nothing' {
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'exploitSystem'; mitigation = 'CFG'; on = 'ON'; equivalentOn = @('NOTSET') })
        $r.Before | Should -Be 'On'; $r.After | Should -Be 'On'
        Should -Invoke Set-ProcessMitigation -ModuleName iGWindowsTuner -Times 0 -Exactly
    }
    It 'repairs an explicit OFF for repair-only items and restores it exactly' {
        $script:Mit['system|DEP'] = 'OFF'
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'exploitSystem'; mitigation = 'DEP'; on = 'ON'; equivalentOn = @('NOTSET') })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'
        $script:Mit['system|DEP'] | Should -Be 'OFF'
    }
}

Describe 'cleanerRule and the DefaultApp check' {
    It 'runs a cleaner rule and leaves nothing to revert' {
        $script:CleanStatus = 'Ready'
        Mock -ModuleName iGWindowsTuner Invoke-IgwtCleanerScan { [pscustomobject]@{ Rules = @([pscustomobject]@{ RuleId = 'clean.user.temp'; Name = 'User temporary files'; Status = $script:CleanStatus; Bytes = $(if ($script:CleanStatus -eq 'Ready') { 2048 } else { 0 }); Count = 3; Reason = '' }) } }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtCleanerClean { $script:CleanStatus = 'Empty'; [pscustomobject]@{ Rules = @([pscustomobject]@{ RuleId = 'clean.user.temp'; Status = 'Cleaned'; Reason = '' }) } }
        $r = Invoke-RoundTrip -Action (ConvertTo-Act @{ type = 'cleanerRule'; rule = 'clean.user.temp' })
        $r.Before | Should -Be 'Off'; $r.After | Should -Be 'On'
        $r.Restored | Should -Be 'On'
        $r.Snapshot.note | Should -Match 'cannot be restored'
    }
    It 'reads the default app without changing it' {
        Write-Reg -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -Name 'ProgId' -Kind 'String' -Value 'FirefoxURL-308046B0AF4A39CB'
        $items = @(InModuleScope iGWindowsTuner { Get-IgwtActionState -Action ([pscustomobject]@{ type = 'check'; checker = 'DefaultApp'; protocol = 'http'; progId = 'MSEdgeHTM' }) -Context $null })
        $items[0].State | Should -Be 'Off'
        $items[0].Current | Should -Be 'FirefoxURL-308046B0AF4A39CB'
        $items[0].Note | Should -Match 'Settings'
    }
}

Describe 'External tools never run unmocked in TestMode' {
    It 'refuses to start winget.exe' { { InModuleScope iGWindowsTuner { Invoke-IgwtWinget -Arguments @('list', '--id', 'x') } } | Should -Throw '*TestMode*' }
}

Describe '2.0 action validation' {
    It 'reports invalid 2.0 actions' {
        $base = (Get-Content -LiteralPath (Join-Path $script:IgwtProjectRoot 'data\tweaks\input.json') -Raw | ConvertFrom-Json).tweaks[0]
        $make = {
            param([string]$Id, $Action, [string]$Level = 'Standard', [string]$Reversible = 'full', [string]$Requires = 'none')
            $raw = $base | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $raw.id = $Id; $raw.level = $Level; $raw.reversible = $Reversible; $raw.requires = $Requires; $raw.sideEffects = 'test side effects'
            $raw.actions = @([pscustomobject]$Action)
            InModuleScope iGWindowsTuner -Parameters @{ R = $raw } { param($R) ConvertTo-IgwtNormalizedTweak -Tweak $R -SourceFile 'input.json' }
        }
        $bad = @(
            (& $make 'input.v2-cadence' @{ type = 'storageSense'; setting = 'cadence'; value = 5 })
            (& $make 'input.v2-quality' @{ type = 'wufbPolicy'; setting = 'qualityDeferralDays'; value = 45 })
            (& $make 'input.v2-irq' @{ type = 'deviceInterrupt'; deviceClass = 'Display'; msiSupported = 1 })
            (& $make 'input.v2-svc' @{ type = 'serviceSet'; services = @([pscustomobject]@{ name = 'WinDefend'; startupType = 'Disabled'; default = 'Automatic' }) })
            (& $make 'input.v2-task' @{ type = 'scheduledTask'; path = '\Microsoft\Windows\WindowsUpdate\'; name = 'Scheduled Start'; on = 'Disabled'; default = 'Enabled' })
            (& $make 'input.v2-fw' @{ type = 'firewallRule'; rule = 'iGWindowsTuner-Open'; displayName = 'x'; direction = 'Inbound'; action = 'Allow' })
            (& $make 'input.v2-fwgroup' @{ type = 'firewallRule'; displayGroup = 'Remote Desktop'; on = 'Enabled'; default = 'Enabled' })
            (& $make 'input.v2-appx' @{ type = 'appx'; package = 'Microsoft.WindowsStore'; on = 'Removed'; default = 'Installed' })
            (& $make 'input.v2-winget' @{ type = 'winget'; id = 'bad id;rm'; on = 'Installed'; default = 'NotInstalled' })
            (& $make 'input.v2-mit' @{ type = 'processMitigation'; process = 'game.exe'; mitigation = 'CFG'; on = 'OFF' })
            (& $make 'input.v2-sys' @{ type = 'exploitSystem'; mitigation = 'DEP'; on = 'OFF' })
            (& $make 'input.v2-syseq' @{ type = 'exploitSystem'; mitigation = 'DEP'; on = 'ON'; equivalentOn = @('OFF') })
            (& $make 'input.v2-clean' @{ type = 'cleanerRule'; rule = 'clean.user.temp' })
            (& $make 'input.v2-check' @{ type = 'check'; checker = 'DefaultApp'; extension = '.pdf' })
        )
        Mock -ModuleName iGWindowsTuner Get-IgwtCatalog { $bad }
        $errors = (@(Test-IgwtCatalog) -join "`n")
        $errors | Should -Match 'input.v2-cadence action\[0\]: cadence must be one of 0, 1, 7, 30'
        $errors | Should -Match 'input.v2-quality action\[0\]: quality update deferral must be 0-30 days'
        $errors | Should -Match 'input.v2-irq action\[0\]: interrupt changes need requires ''reboot'''
        $errors | Should -Match 'input.v2-irq action\[0\]: device interrupt items must be level Expert or Lab'
        $errors | Should -Match "input.v2-svc action\[0\]: service 'WinDefend' is protected"
        $errors | Should -Match 'input.v2-task action\[0\]: tasks under .* are protected'
        $errors | Should -Match 'input.v2-fw action\[0\]: iG Windows Tuner only creates Block rules'
        $errors | Should -Match 'input.v2-fwgroup action\[0\]: rule groups may only be disabled'
        $errors | Should -Match "input.v2-appx action\[0\]: app 'Microsoft.WindowsStore' is protected"
        $errors | Should -Match 'input.v2-appx action\[0\]: app removal is not fully reversible'
        $errors | Should -Match 'input.v2-winget action\[0\]: winget needs a package id'
        $errors | Should -Match 'input.v2-mit action\[0\]: turning a mitigation off needs level Expert or Lab'
        $errors | Should -Match 'input.v2-sys action\[0\]: system-wide exploit protection may only be turned ON'
        $errors | Should -Match 'input.v2-syseq action\[0\]: equivalentOn may only contain NOTSET'
        $errors | Should -Match "input.v2-clean action\[0\]: items that run a cleaner rule must be reversible 'none'"
        $errors | Should -Match 'input.v2-check action\[0\]: DefaultApp needs extension or protocol, and progId'
    }
    It 'gives every 2.0 action an identifying fingerprint without changing 1.0 fingerprints' {
        InModuleScope iGWindowsTuner {
            Get-IgwtActionFingerprint ([pscustomobject]@{ type = 'serviceSet'; services = @([pscustomobject]@{ name = 'A' }, [pscustomobject]@{ name = 'B' }) }) | Should -Be 'serviceSet|services=A,B'
            Get-IgwtActionFingerprint ([pscustomobject]@{ type = 'processMitigation'; process = 'x.exe'; mitigation = 'CFG'; on = 'ON' }) | Should -Be 'processMitigation|process=x.exe|mitigation=CFG'
            Get-IgwtActionFingerprint ([pscustomobject]@{ type = 'registry'; path = 'HKCU:\A'; name = 'B'; on = 1 }) | Should -Be 'registry|path=HKCU:\A|name=B'
        }
    }
}
