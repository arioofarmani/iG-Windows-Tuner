# 3.0 phase 7: Defender & Security Control Center. Every Defender, firewall and event log cmdlet is
# mocked; registry values live in TestRegistry and the GPO folder in TestDrive.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    function Get-TestPref([hashtable]$Over = @{}) {
        $h = [ordered]@{ DisableRealtimeMonitoring = $false; DisableBehaviorMonitoring = $false; DisableIOAVProtection = $false; DisableScriptScanning = $false; DisableEmailScanning = $true
            MAPSReporting = 2; DisableBlockAtFirstSeen = $false; CloudBlockLevel = 0; CloudExtendedTimeout = 0; PUAProtection = 1; EnableNetworkProtection = 0
            DisableDnsParsing = $false; DisableTlsParsing = $false; DisableQuicParsing = $true; EnableDnsSinkhole = $false; DisableInboundConnectionFiltering = $false
            AttackSurfaceReductionOnlyExclusions = @(); ControlledFolderAccessAllowedApplications = @() }
        $h['ExclusionPath'] = @(); $h['ExclusionProcess'] = @(); $h['ExclusionExtension'] = @(); $h['ExclusionIpAddress'] = @()
        foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }
        return [pscustomobject]$h
    }
    $script:Pref = Get-TestPref
}

Describe 'Defender & Security Control Center' {
    BeforeEach {
        $script:Pref = Get-TestPref
        Mock -ModuleName iGWindowsTuner Get-MpPreference { $script:Pref }
        Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { [pscustomobject]@{ AMServiceEnabled = $true; AntivirusEnabled = $true; AMRunningMode = 'Normal'; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 0; IsTamperProtected = $true; QuickScanAge = 1; FullScanAge = 10; AMEngineVersion = '1.1'; AMProductVersion = '4.18'; AntivirusSignatureVersion = '1.4'; SmartAppControlState = 'Off'; DeviceControlState = 'Disabled' } }
        Mock -ModuleName iGWindowsTuner Set-MpPreference { }
        Mock -ModuleName iGWindowsTuner Remove-MpPreference { }
        Mock -ModuleName iGWindowsTuner Add-MpPreference { throw 'Add-MpPreference must never be called.' }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $true } }
        $script:GpoRoot = Join-Path $TestDrive ('GPO-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $admx = Join-Path $TestDrive 'NoAdmx'; $null = New-Item -ItemType Directory -Path $admx -Force
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:GpoRoot; A = $admx } { param($R, $A) $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtAdmxCache = $null }
        Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager' -Recurse -Force -ErrorAction SilentlyContinue
    }
    AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

    Context 'Status and settings' {
        It 'reports versions, Tamper Protection and findings' {
            Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { [pscustomobject]@{ AMServiceEnabled = $true; AntivirusEnabled = $true; AMRunningMode = 'Passive Mode'; RealTimeProtectionEnabled = $false; AntivirusSignatureAge = 9; IsTamperProtected = $false; QuickScanAge = 20; FullScanAge = 30; AMEngineVersion = '1.1'; AMProductVersion = '4.18'; AntivirusSignatureVersion = '1.4'; SmartAppControlState = 'Off' } }
            $s = InModuleScope iGWindowsTuner { Get-IgwtDefenderStatus }
            $s.TamperProtected | Should -BeFalse
            $t = @($s.Findings | ForEach-Object { $_.Text }) -join ' '
            $t | Should -Match 'passive mode'; $t | Should -Match 'Real-time protection is off'; $t | Should -Match '9 days old'; $t | Should -Match 'never changes it'
        }
        It 'shows only settings this platform reports, with status and source' {
            $null = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Force
            $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Name 'PUAProtection' -Value 1 -PropertyType DWord
            $rows = @(InModuleScope iGWindowsTuner { Get-IgwtDefenderSettings })
            @($rows | ForEach-Object { $_.Property }) | Should -Not -Contain 'DisableArchiveScanning' -Because 'the mocked platform does not report it'
            ($rows | Where-Object Property -EQ 'DisableEmailScanning').Status | Should -Be 'Off'
            ($rows | Where-Object Property -EQ 'CloudBlockLevel').Status | Should -Be 'Off'
            ($rows | Where-Object Property -EQ 'MAPSReporting').Status | Should -Be 'On'
            ($rows | Where-Object Property -EQ 'DisableQuicParsing').Status | Should -Be 'Off'
            ($rows | Where-Object Property -EQ 'PUAProtection').Source | Should -Be 'MDM'
            ($rows | Where-Object Property -EQ 'DisableQuicParsing').Change | Should -Match 'never off'
        }
        It 'web protection, device control and detection logging are read-only views' {
            $null = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Edge' -Force
            $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled' -Value 0 -PropertyType DWord -Force
            (@(InModuleScope iGWindowsTuner { Get-IgwtWebProtectionStatus }) | Where-Object Name -EQ 'SmartScreen in Microsoft Edge (policy)').Status | Should -Be 'Off'
            Mock -ModuleName iGWindowsTuner Get-WinEvent { [pscustomobject]@{ IsEnabled = $true; MaximumSizeInBytes = 200MB; RecordCount = 5 } } -ParameterFilter { $ListLog }
            Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = 'Sysmon64'; Status = 'Running' } }
            $l = InModuleScope iGWindowsTuner { Get-IgwtDetectionLoggingStatus }
            $l.Sysmon.Installed | Should -BeTrue; $l.Sysmon.Note | Should -Match 'never installs'
            ($l.Checks | Where-Object Name -Like 'Security log*').On | Should -BeTrue
            Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Edge' -Recurse -Force
        }
    }

    Context 'Network Inspection parsers (one-way)' {
        It 'turns on only the parsers that are off, never off' {
            $r = InModuleScope iGWindowsTuner { Set-IgwtDefenderParsersOn }
            @($r.TurnedOn) | Should -Be @('DNS sinkhole', 'QUIC parser')
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 1 -Exactly -ParameterFilter { $DisableQuicParsing -eq $false }
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 1 -Exactly -ParameterFilter { $EnableDnsSinkhole -eq $true }
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 2 -Exactly
        }
        It 'refuses settings that are not parsers and managed PCs without acknowledgement' {
            { InModuleScope iGWindowsTuner { Set-IgwtDefenderParsersOn -Name 'DisableRealtimeMonitoring' } } | Should -Throw '*not a Network Inspection parser*'
            Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; Authorities = @('Intune'); LocalGroupPolicy = $true } }
            { InModuleScope iGWindowsTuner { Set-IgwtDefenderParsersOn } } | Should -Throw '*AcknowledgeManaged*'
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
        }
        It 'every catalog parser entry turns protection on' {
            foreach ($p in @((Get-Content (Join-Path $script:IgwtProjectRoot 'data\defender\settings.json') -Raw | ConvertFrom-Json).settings | Where-Object kind -EQ 'parser')) {
                if ($p.mp -like 'Disable*') { $p.on | Should -BeFalse -Because $p.mp } else { $p.on | Should -BeTrue -Because $p.mp }
            }
        }
        It 'the strict preset turns parsers on through the batch and its revert leaves them on' {
            $plan = InModuleScope iGWindowsTuner { $script:IgwtPolicyPresets = $null; $p = Get-IgwtPolicyPresets -Id 'defender-strict'; $only = $p | Select-Object * ; $only.settings = @($p.settings | Where-Object kind -EQ 'mppref'); $script:IgwtPolicyPresets = @($only); Get-IgwtPolicyPresetPlan -Id 'defender-strict' }
            $plan.Rows[0].Status | Should -Be 'Change'
            $plan.Rows[0].Note | Should -Match 'only ever turned on'
            $r = InModuleScope iGWindowsTuner -Parameters @{ P = $plan } { param($P) Invoke-IgwtPolicyBatch -Plan $P -NoRefresh }
            $rec = Get-Content $r.Record -Raw | ConvertFrom-Json
            @($rec.parsersTurnedOn) | Should -Contain 'QUIC parser'
            $undo = InModuleScope iGWindowsTuner -Parameters @{ R = $r.Record } { param($R) Restore-IgwtPolicyPreset -Record $R }
            @($undo.StillOn) | Should -Contain 'QUIC parser'
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 2 -Exactly
            InModuleScope iGWindowsTuner { $script:IgwtPolicyPresets = $null }
        }
    }

    Context 'Exclusions audit' {
        It 'rates risky exclusions' {
            $cases = @(
                @('Path', 'C:\', 'High'), @('Path', 'C:\*', 'High'), @('Path', '%TEMP%\x', 'High'), @('Path', 'C:\Users\ario\Downloads', 'High'), @('Path', 'C:\Users\ario\AppData\Local\Game', 'High'),
                @('Process', 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 'High'), @('Process', 'mshta.exe', 'High'), @('Extension', '.exe', 'High'), @('Extension', 'ps1', 'High'),
                @('IpAddress', '0.0.0.0/0', 'High'), @('IpAddress', '10.0.0.0/20', 'Medium'), @('Path', '\\nas\share', 'Medium'), @('Path', 'D:\Games\SteamLibrary\steamapps\common\Game\cache', 'Low'), @('Extension', 'vhdx', 'Low'))
            foreach ($c in $cases) { (InModuleScope iGWindowsTuner -Parameters @{ K = $c[0]; V = $c[1] } { param($K, $V) Test-IgwtExclusionRisk -Kind $K -Value $V }).Severity | Should -Be $c[2] -Because "$($c[0]) $($c[1])" }
        }
        It 'reports hidden exclusions for non-administrators' {
            $script:Pref = Get-TestPref @{ ExclusionPath = @('N/A: Must be an administrator to view exclusions'); AttackSurfaceReductionOnlyExclusions = @('N/A: Must be an administrator to view exclusions') }
            $a = InModuleScope iGWindowsTuner { Get-IgwtDefenderExclusionAudit }
            $a.Readable | Should -BeFalse
            $a.Note | Should -Match 'administrators only'
        }
        It 'lists exclusions with their source and removability' {
            $script:Pref = Get-TestPref @{ ExclusionPath = @('C:\Temp', 'D:\Build'); ExclusionProcess = @('mshta.exe') }
            $null = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Force
            $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -Name 'E:\FromDomain' -Value 0 -PropertyType DWord
            $a = InModuleScope iGWindowsTuner { Get-IgwtDefenderExclusionAudit }
            $a.Readable | Should -BeTrue
            ($a.Exclusions | Where-Object Value -EQ 'C:\Temp').Severity | Should -Be 'High'
            ($a.Exclusions | Where-Object Value -EQ 'E:\FromDomain').Removable | Should -BeFalse
            ($a.Exclusions | Where-Object Value -EQ 'D:\Build').Removable | Should -BeTrue
            $a.High | Should -Be 2
        }
        It 'removes a local exclusion with Remove-MpPreference and never adds one' {
            $script:Pref = Get-TestPref @{ ExclusionPath = @('C:\Temp') }
            $null = InModuleScope iGWindowsTuner { Remove-IgwtDefenderExclusion -Kind Path -Value 'c:\temp' -Confirm:$false }
            Should -Invoke -ModuleName iGWindowsTuner Remove-MpPreference -Times 1 -Exactly -ParameterFilter { @($ExclusionPath) -contains 'C:\Temp' }
            Should -Invoke -ModuleName iGWindowsTuner Add-MpPreference -Times 0
        }
        It 'removes a Local GPO exclusion from Registry.pol and refuses domain or unknown ones' {
            $script:Pref = Get-TestPref
            $key = 'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
            $e = InModuleScope iGWindowsTuner -Parameters @{ K = $key } { param($K) New-IgwtPolEntryObject -Key $K -ValueName 'C:\Old' -Type 1 -Data ([Text.Encoding]::Unicode.GetBytes("0`0")) }
            InModuleScope iGWindowsTuner -Parameters @{ E = @($e) } { param($E) Write-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine) -Entries $E }
            $null = New-Item -Path "TestRegistry:\HKLM\$key" -Force; $null = New-ItemProperty -LiteralPath "TestRegistry:\HKLM\$key" -Name 'C:\Old' -Value '0' -PropertyType String -Force
            $r = InModuleScope iGWindowsTuner { Remove-IgwtDefenderExclusion -Kind Path -Value 'C:\Old' -Confirm:$false }
            $r.Source | Should -Be 'Local GPO'
            @(InModuleScope iGWindowsTuner { (Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine)).Entries }).Count | Should -Be 0
            $null = New-ItemProperty -LiteralPath "TestRegistry:\HKLM\$key" -Name 'E:\Domain' -Value '0' -PropertyType String -Force
            { InModuleScope iGWindowsTuner { Remove-IgwtDefenderExclusion -Kind Path -Value 'E:\Domain' -Confirm:$false } } | Should -Throw '*remove it there*'
            { InModuleScope iGWindowsTuner { Remove-IgwtDefenderExclusion -Kind Path -Value 'Z:\None' -Confirm:$false } } | Should -Throw '*No Path exclusion*'
        }
    }

    Context 'Scans and quarantine' {
        It 'starts scans only as asked and guards the offline scan' {
            Mock -ModuleName iGWindowsTuner Start-MpScan { }
            Mock -ModuleName iGWindowsTuner Start-MpWDOScan { }
            $null = InModuleScope iGWindowsTuner { Start-IgwtDefenderScan -Type Quick -Confirm:$false }
            Should -Invoke -ModuleName iGWindowsTuner Start-MpScan -Times 1 -ParameterFilter { $ScanType -eq 'QuickScan' }
            { InModuleScope iGWindowsTuner { Start-IgwtDefenderScan -Type Custom -Confirm:$false } } | Should -Throw '*needs -Path*'
            { InModuleScope iGWindowsTuner { Start-IgwtDefenderScan -Type Offline -Confirm:$false } } | Should -Throw '*ConfirmRestart*'
            Should -Invoke -ModuleName iGWindowsTuner Start-MpWDOScan -Times 0
            $null = InModuleScope iGWindowsTuner -Parameters @{ P = $TestDrive } { param($P) Start-IgwtDefenderScan -Type Custom -Path $P -Confirm:$false }
            Should -Invoke -ModuleName iGWindowsTuner Start-MpScan -Times 1 -ParameterFilter { $ScanType -eq 'CustomScan' -and $ScanPath -eq $TestDrive }
        }
        It 'restores from quarantine only with the risk acknowledgement and never in TestMode' {
            { InModuleScope iGWindowsTuner { Restore-IgwtQuarantineItem -ThreatName 'Trojan:Win32/Test' -Confirm:$false } } | Should -Throw '*IUnderstandTheRisk*'
            { InModuleScope iGWindowsTuner { Restore-IgwtQuarantineItem -ThreatName 'Trojan:Win32/Test' -IUnderstandTheRisk -Confirm:$false } } | Should -Throw '*TestMode safety*'
            { InModuleScope iGWindowsTuner { Restore-IgwtQuarantineItem -ThreatName 'x; Remove-Item C:\' -IUnderstandTheRisk -Confirm:$false } } | Should -Throw '*Unexpected threat name*'
        }
        It 'joins detections with threats, newest first' {
            Mock -ModuleName iGWindowsTuner Get-MpThreat { @([pscustomobject]@{ ThreatID = 7; ThreatName = 'PUA:Win32/Test'; SeverityID = 1; IsActive = $false }) }
            Mock -ModuleName iGWindowsTuner Get-MpThreatDetection { @([pscustomobject]@{ ThreatID = 7; InitialDetectionTime = (Get-Date).AddDays(-1); Resources = @('file:_C:\x.exe'); ProcessName = 'explorer.exe'; DomainUser = 'PC\ario'; ThreatStatusID = 3; ActionSuccess = $true }, [pscustomobject]@{ ThreatID = 7; InitialDetectionTime = (Get-Date).AddDays(-40); Resources = @(); ProcessName = ''; DomainUser = ''; ThreatStatusID = 3; ActionSuccess = $true }) }
            $t = @(InModuleScope iGWindowsTuner { Get-IgwtDefenderThreats })
            $t.Count | Should -Be 2; $t[0].Threat | Should -Be 'PUA:Win32/Test'; $t[0].Severity | Should -Be 'Low'
            @(InModuleScope iGWindowsTuner { Get-IgwtDefenderThreats -Days 30 }).Count | Should -Be 1
        }
    }

    Context 'Firewall as a detection source' {
        BeforeAll {
            $script:Log = @'
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
2026-10-22 10:00:01 DROP TCP 203.0.113.5 192.168.1.10 51000 3389 52 S 1 0 64240 - - - RECEIVE 4
2026-10-22 10:00:05 DROP TCP 203.0.113.5 192.168.1.10 51001 445 52 S 1 0 64240 - - - RECEIVE 4
2026-10-22 10:30:00 DROP UDP 198.51.100.7 192.168.1.10 5353 5353 120 - - - - - - - RECEIVE 0
2026-10-22 11:15:00 ALLOW TCP 192.168.1.10 13.107.4.50 50123 443 0 - - - - - - - SEND 999999
garbage line
'@
            $script:LogFile = Join-Path $TestDrive 'pfirewall.log'
            [IO.File]::WriteAllText($script:LogFile, $script:Log)
        }
        It 'parses the W3C log and analyzes it' {
            $e = @(InModuleScope iGWindowsTuner -Parameters @{ P = $script:LogFile } { param($P) Read-IgwtFirewallLog -Path $P -MaxLines 3 })
            $e.Count | Should -Be 2 -Because 'only the last 3 lines are read (one is garbage), and the #Fields header is kept'
            $all = @(InModuleScope iGWindowsTuner -Parameters @{ P = $script:LogFile } { param($P) Read-IgwtFirewallLog -Path $P })
            $all.Count | Should -Be 4
            $all[0].DestinationPort | Should -Be '3389'; $all[3].ProcessId | Should -Be '999999'
            $a = InModuleScope iGWindowsTuner -Parameters @{ E = $all } { param($E) Get-IgwtFirewallLogAnalysis -Entries $E }
            $a.Dropped | Should -Be 3; $a.Allowed | Should -Be 1
            $a.TopBlockedSources[0].Value | Should -Be '203.0.113.5'; $a.TopBlockedSources[0].Count | Should -Be 2
            @($a.TopBlockedPorts | ForEach-Object { $_.Value }) | Should -Contain 'TCP/3389'
            @($a.Timeline).Count | Should -Be 2
            $j = Join-Path $TestDrive 'fw.json'; $c = Join-Path $TestDrive 'fw.csv'
            InModuleScope iGWindowsTuner -Parameters @{ A = $a; E = $all; J = $j; C = $c } { param($A, $E, $J, $C) Export-IgwtFirewallLogAnalysis -Analysis $A -Path $J; Export-IgwtFirewallLogAnalysis -Analysis $A -Entries $E -Path $C }
            (Get-Content $j -Raw | ConvertFrom-Json).Dropped | Should -Be 3
            @(Import-Csv $c).Count | Should -Be 4
        }
        It 'reports logging per profile' {
            Mock -ModuleName iGWindowsTuner Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; Enabled = 'True'; LogBlocked = 'False'; LogAllowed = 'False'; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxSizeKilobytes = 4096; DefaultOutboundAction = 'NotConfigured' }) }
            $s = @(InModuleScope iGWindowsTuner { Get-IgwtFirewallLoggingStatus })
            $s[0].Finding | Should -Match 'not logged'
            $s[0].LogFile | Should -Not -Match '%systemroot%'
        }
        It 'plans an outbound allow-list without creating rules or changing profiles' {
            Mock -ModuleName iGWindowsTuner New-NetFirewallRule { throw 'must not be called' }
            Mock -ModuleName iGWindowsTuner Set-NetFirewallProfile { throw 'must not be called' }
            $all = @(InModuleScope iGWindowsTuner -Parameters @{ P = $script:LogFile } { param($P) Read-IgwtFirewallLog -Path $P })
            $p = InModuleScope iGWindowsTuner -Parameters @{ E = $all } { param($E) Get-IgwtOutboundAllowListPlan -Entries $E }
            @($p.Observed).Count | Should -Be 1
            $p.Observed[0].Program | Should -Match 'ended'
            @($p.Essential | Where-Object Service -EQ 'wuauserv').Count | Should -Be 1
            ($p.Steps -join ' ') | Should -Match 'does not do these steps'
            Should -Invoke -ModuleName iGWindowsTuner New-NetFirewallRule -Times 0
            Should -Invoke -ModuleName iGWindowsTuner Set-NetFirewallProfile -Times 0
        }
    }
}
