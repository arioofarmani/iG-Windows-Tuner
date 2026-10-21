# Management and diagnostic modules. CIM, service, task, Appx, firewall, event log,
# DNS and ping access is mocked; registry access stays in TestRegistry and files in TestDrive.
# Nothing touches the real system.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    function Write-TestReg {
        param([string]$Path, [string]$Name, $Value, [string]$Kind = 'DWord')
        $p = $Path -replace '^HKLM:\\', 'TestRegistry:\HKLM\' -replace '^HKCU:\\', 'TestRegistry:\HKCU\'
        if (-not (Test-Path -LiteralPath $p)) { $null = New-Item -Path $p -Force }
        $null = New-ItemProperty -LiteralPath $p -Name $Name -Value $Value -PropertyType $Kind -Force
    }
    function Get-TestRegValue {
        param([string]$Path, [string]$Name)
        $p = $Path -replace '^HKLM:\\', 'TestRegistry:\HKLM\'
        return (Get-ItemProperty -LiteralPath $p -Name $Name -ErrorAction SilentlyContinue).$Name
    }
    function Initialize-ServiceMock {
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            $all = @(
                [pscustomobject]@{ Name = 'IgwtTestSvc'; DisplayName = 'Igwt test service'; Description = 'Test'; State = 'Running'; StartMode = 'Manual'; DelayedAutoStart = $false; StartName = 'LocalSystem'; PathName = 'C:\Program Files\Test\svc.exe'; ServiceType = 'Own Process' }
                [pscustomobject]@{ Name = 'IgwtTestDrv'; DisplayName = 'Igwt test driver'; Description = ''; State = 'Running'; StartMode = 'System'; DelayedAutoStart = $false; StartName = ''; PathName = 'C:\Windows\system32\drivers\t.sys'; ServiceType = 'Kernel Driver' }
                [pscustomobject]@{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service'; Description = ''; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; PathName = "$env:SystemRoot\x\MsMpEng.exe"; ServiceType = 'Own Process' }
                [pscustomobject]@{ Name = 'DiagTrack'; DisplayName = 'Connected User Experiences and Telemetry'; Description = ''; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; PathName = "$env:SystemRoot\System32\svchost.exe -k utcsvc -p"; ServiceType = 'Share Process' }
                [pscustomobject]@{ Name = 'Fax'; DisplayName = 'Fax'; Description = ''; State = 'Stopped'; StartMode = 'Manual'; DelayedAutoStart = $false; StartName = 'NetworkService'; PathName = "$env:SystemRoot\system32\fxssvc.exe"; ServiceType = 'Own Process' }
            )
            if ($Filter -match "Name='([^']+)'") { $n = $Matches[1]; return @($all | Where-Object { $_.Name -eq $n }) }
            return $all
        }
        Mock -ModuleName iGWindowsTuner Get-Service { if ($Name) { [pscustomobject]@{ Name = $Name[0]; Status = 'Running'; StartType = 'Manual'; ServicesDependedOn = @(); DependentServices = @() } } else { @([pscustomobject]@{ Name = 'Fax'; ServicesDependedOn = @([pscustomobject]@{ Name = 'RpcSs' }); DependentServices = @() }) } }
        Mock -ModuleName iGWindowsTuner Set-Service {
            $v = switch ([string]$StartupType) { 'Automatic' { 2 } 'Manual' { 3 } 'Disabled' { 4 } }
            Set-ItemProperty -LiteralPath "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value $v
        }
        foreach ($n in 'IgwtTestSvc', 'WinDefend', 'Fax') { Write-TestReg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$n" -Name 'Start' -Value 3 }
    }
}

Describe 'Management protection data' {
    It 'validates data\manage (protected services and NIC keyword descriptions)' {
        @(Test-IgwtManageCatalog) | Should -BeNullOrEmpty
    }
    It 'protects core, security, audio, network, GPU and anti-cheat services' {
        InModuleScope iGWindowsTuner {
            foreach ($n in 'RpcSs', 'WinDefend', 'mpssvc', 'EventLog', 'Audiosrv', 'Dhcp', 'Dnscache', 'TrustedInstaller', 'vgc', 'BEService', 'EasyAntiCheat_EOS') { Get-IgwtServiceProtection -Name $n | Should -Not -BeNullOrEmpty -Because $n }
            Get-IgwtServiceProtection -Name 'NVDisplay.ContainerLocalSystem' | Should -Not -BeNullOrEmpty
            Get-IgwtServiceProtection -Name 'XblGameSave' | Should -BeNullOrEmpty
            Get-IgwtServiceProtection -Name 'Fax' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Managed changes (snapshot, apply, revert)' {
    BeforeEach { Initialize-ServiceMock }

    It 'changes a service startup type with a Manage snapshot and reverts it' {
        $r = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Disabled'
        @($r.Results)[0].Result | Should -Be 'Applied'
        Get-TestRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Fax' 'Start' | Should -Be 4
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.operation | Should -Be 'Manage'
        $doc.entries[0].actions[0].managed.kind | Should -Be 'service'
        $rev = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        @($rev.Results)[0].Result | Should -Be 'Reverted'
        Get-TestRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Fax' 'Start' | Should -Be 3
        Test-Path -LiteralPath $rev.Snapshot | Should -BeTrue
    }
    It 'does nothing when the value is already set' {
        $r = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Manual'
        $r.Changes | Should -Be 0
        (Get-IgwtManagedChangePlan -Kind service -Target 'Fax' -Value 'Manual').HasChange | Should -BeFalse
        (Get-IgwtManagedChangePlan -Kind service -Target 'Fax' -Value 'Disabled').HasChange | Should -BeTrue
    }
    It 'refuses protected services, drivers, unknown services and invalid values' {
        { Invoke-IgwtManagedChange -Kind service -Target 'WinDefend' -Value 'Disabled' } | Should -Throw '*protected*'
        { Invoke-IgwtManagedChange -Kind service -Target 'IgwtTestDrv' -Value 'Disabled' } | Should -Throw '*driver*'
        { Invoke-IgwtManagedChange -Kind service -Target 'NoSuchSvc' -Value 'Disabled' } | Should -Throw '*does not exist*'
        { Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Boot' } | Should -Throw '*not allowed*'
        Get-TestRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' 'Start' | Should -Be 3
    }
    It 'refuses a tampered snapshot that points at a protected service' {
        $r = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Disabled'
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.entries[0].actions[0].managed.target = 'WinDefend'
        Set-Content -LiteralPath $r.Snapshot -Value ($doc | ConvertTo-Json -Depth 20) -Encoding UTF8
        $res = @((Invoke-IgwtRevert -SnapshotPath $r.Snapshot).Results)
        $res[0].Result | Should -Be 'Failed'
        Get-TestRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' 'Start' | Should -Be 3
    }
    It 'disables and re-enables a scheduled task but refuses security and anti-cheat tasks' {
        $script:TaskState = 'Ready'
        Mock -ModuleName iGWindowsTuner Get-ScheduledTask { [pscustomobject]@{ TaskPath = $TaskPath; TaskName = $TaskName; State = $script:TaskState } }
        Mock -ModuleName iGWindowsTuner Disable-ScheduledTask { $script:TaskState = 'Disabled' }
        Mock -ModuleName iGWindowsTuner Enable-ScheduledTask { $script:TaskState = 'Ready' }
        $r = Invoke-IgwtManagedChange -Kind task -Target '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator' -Value 'Disabled'
        @($r.Results)[0].Result | Should -Be 'Applied'
        $script:TaskState | Should -Be 'Disabled'
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        $script:TaskState | Should -Be 'Ready'
        { Invoke-IgwtManagedChange -Kind task -Target '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan' -Value 'Disabled' } | Should -Throw '*protected*'
        { Invoke-IgwtManagedChange -Kind task -Target '\Riot Vanguard\vgc update' -Value 'Disabled' } | Should -Throw '*anti-cheat*'
        { Invoke-IgwtManagedChange -Kind task -Target 'Consolidator' -Value 'Disabled' } | Should -Throw '*full task path*'
    }
    It 'refuses protected apps, features and capabilities' {
        Mock -ModuleName iGWindowsTuner Get-AppxPackage { }
        foreach ($p in 'Microsoft.WindowsStore', 'Microsoft.DesktopAppInstaller', 'Microsoft.XboxIdentityProvider', 'Microsoft.GamingServices', 'Microsoft.SecHealthUI') {
            { Invoke-IgwtManagedChange -Kind appx -Target $p -Value 'Removed' } | Should -Throw '*protected*' -Because $p
        }
        { Invoke-IgwtManagedChange -Kind feature -Target 'Windows-Defender-Default-Definitions' -Value 'Disabled' } | Should -Throw '*protected*'
        { Invoke-IgwtManagedChange -Kind feature -Target 'NetFx4-AdvSrvs' -Value 'Disabled' } | Should -Throw '*protected*'
        { Invoke-IgwtManagedChange -Kind capability -Target 'Language.Basic~~~en-US~0.0.1.0' -Value 'NotPresent' } | Should -Throw '*protected*'
        { Invoke-IgwtManagedChange -Kind appx -Target 'bad name;x' -Value 'Removed' } | Should -Throw '*valid*'
    }
    It 'refuses system and framework packages even when not on the protected list' {
        Mock -ModuleName iGWindowsTuner Get-AppxPackage { [pscustomobject]@{ Name = 'Contoso.Shell'; IsFramework = $false; SignatureKind = 'System' } }
        { Invoke-IgwtManagedChange -Kind appx -Target 'Contoso.Shell' -Value 'Removed' } | Should -Throw '*system component*'
    }
    It 'switches an app firewall rule with a snapshot and never changes Windows rules' {
        $script:Rules = @{
            AppRule = [pscustomobject]@{ Name = 'AppRule'; DisplayName = 'Contoso Game'; Enabled = 'True'; Group = ''; DisplayGroup = '' }
            CoreNet = [pscustomobject]@{ Name = 'CoreNet-DHCP-In'; DisplayName = 'Core Networking - DHCP'; Enabled = 'True'; Group = '@FirewallAPI.dll,-25000'; DisplayGroup = 'Core Networking' }
        }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule { $n = @($Name)[0]; $r = @($script:Rules.Values | Where-Object { $_.Name -eq $n }); if ($r.Count) { $r[0] } }
        Mock -ModuleName iGWindowsTuner Set-NetFirewallRule { $n = @($Name)[0]; $script:Rules[$(if ($n -eq 'AppRule') { 'AppRule' } else { 'CoreNet' })].Enabled = [string]$Enabled }
        $r = Invoke-IgwtManagedChange -Kind firewallRule -Target 'AppRule' -Value 'Disabled'
        @($r.Results)[0].Result | Should -Be 'Applied'
        $script:Rules.AppRule.Enabled | Should -Be 'False'
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        $script:Rules.AppRule.Enabled | Should -Be 'True'
        { Invoke-IgwtManagedChange -Kind firewallRule -Target 'CoreNet-DHCP-In' -Value 'Disabled' } | Should -Throw '*Windows*'
        $script:Rules.CoreNet.Enabled | Should -Be 'True'
    }
}

Describe 'Inventories (read-only)' {
    BeforeEach { Initialize-ServiceMock }

    It 'rates services as Protected, Catalogued, Windows or ThirdParty' {
        $inv = Get-IgwtServiceInventory
        $by = @{}; foreach ($s in $inv.Services) { $by[$s.Name] = $s }
        $by.WinDefend.Rating | Should -Be 'Protected'; $by.WinDefend.CanChange | Should -BeFalse
        $by.DiagTrack.Rating | Should -Be 'Catalogued'; @($by.DiagTrack.CatalogItems)[0].Id | Should -Be 'privacy.diagtrack-disabled'
        $by.Fax.Rating | Should -Be 'Windows'; @($by.Fax.DependsOn) | Should -Contain 'RpcSs'
        $by.IgwtTestSvc.Rating | Should -Be 'ThirdParty'
        $by.WinDefend.StartupType | Should -Be 'Automatic'
    }
    It 'marks security and anti-cheat tasks as protected' {
        Mock -ModuleName iGWindowsTuner Get-ScheduledTask {
            @(
                [pscustomobject]@{ TaskPath = '\Microsoft\Windows\Windows Defender\'; TaskName = 'Windows Defender Scheduled Scan'; State = 'Ready'; Author = 'Microsoft'; Description = ''; Actions = @() }
                [pscustomobject]@{ TaskPath = '\'; TaskName = 'FACEIT Updater'; State = 'Ready'; Author = 'FACEIT'; Description = ''; Actions = @([pscustomobject]@{ Execute = 'C:\faceit\upd.exe'; Arguments = '' }) }
                [pscustomobject]@{ TaskPath = '\Microsoft\Windows\Autochk\'; TaskName = 'Proxy'; State = 'Ready'; Author = 'Microsoft'; Description = ''; Actions = @() }
            )
        }
        $t = Get-IgwtTaskInventory
        @($t.Tasks | Where-Object { $_.Protected }).Count | Should -Be 2
        @($t.Tasks | Where-Object { $_.Name -eq 'Proxy' })[0].CanDisable | Should -BeTrue
        $t.Counts.ThirdParty | Should -Be 1
    }
    It 'lists Win32 apps from the uninstall keys and marks protected Appx packages' {
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Contoso' -Name 'DisplayName' -Value 'Contoso Launcher' -Kind String
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Contoso' -Name 'EstimatedSize' -Value 2048
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Hidden' -Name 'DisplayName' -Value 'Hidden part' -Kind String
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Hidden' -Name 'SystemComponent' -Value 1
        Mock -ModuleName iGWindowsTuner Get-AppxPackage {
            @(
                [pscustomobject]@{ Name = 'Microsoft.WindowsStore'; Version = '1'; PublisherId = '8wekyb3d8bbwe'; Publisher = 'CN=Microsoft Corporation'; SignatureKind = 'Store'; IsFramework = $false }
                [pscustomobject]@{ Name = 'Microsoft.BingWeather'; Version = '1'; PublisherId = '8wekyb3d8bbwe'; Publisher = 'CN=Microsoft Corporation'; SignatureKind = 'Store'; IsFramework = $false }
                [pscustomobject]@{ Name = 'Microsoft.VCLibs.140.00'; Version = '1'; PublisherId = '8wekyb3d8bbwe'; Publisher = 'CN=Microsoft Corporation'; SignatureKind = 'Store'; IsFramework = $true }
            )
        }
        $a = Get-IgwtAppInventory
        @($a.Win32 | ForEach-Object { $_.Name }) | Should -Contain 'Contoso Launcher'
        @($a.Win32 | ForEach-Object { $_.Name }) | Should -Not -Contain 'Hidden part'
        @($a.Win32 | Where-Object { $_.Name -eq 'Contoso Launcher' })[0].SizeMB | Should -Be 2
        @($a.Appx).Count | Should -Be 2
        @($a.Appx | Where-Object { $_.Name -eq 'Microsoft.WindowsStore' })[0].CanRemove | Should -BeFalse
        @($a.Appx | Where-Object { $_.Name -eq 'Microsoft.BingWeather' })[0].CanRemove | Should -BeTrue
    }
}

Describe 'Persistence Inspector (read-only)' {
    BeforeAll {
        $script:SavedEnv = @{ APPDATA = $env:APPDATA; ProgramData = $env:ProgramData; LOCALAPPDATA = $env:LOCALAPPDATA }
        $env:APPDATA = Join-Path $TestDrive 'Roaming'; $env:ProgramData = Join-Path $TestDrive 'ProgramData'; $env:LOCALAPPDATA = Join-Path $TestDrive 'Local'
        $ext = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0'
        $null = New-Item -ItemType Directory -Path $ext -Force
        Set-Content -LiteralPath (Join-Path $ext 'manifest.json') -Value '{ "name": "Test Extension", "version": "1.0" }' -Encoding ASCII
    }
    AfterAll { foreach ($k in $script:SavedEnv.Keys) { Set-Item -Path "env:$k" -Value $script:SavedEnv[$k] } }
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-CimInstance { }
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq '__EventConsumer' } {
            @(
                [pscustomobject]@{ Name = 'SCM Event Log Consumer'; CimClass = [pscustomobject]@{ CimClassName = 'NTEventLogEventConsumer' } }
                [pscustomobject]@{ Name = 'Updater'; CimClass = [pscustomobject]@{ CimClassName = 'CommandLineEventConsumer' }; CommandLineTemplate = 'C:\Users\Public\x.exe' }
            )
        }
        Mock -ModuleName iGWindowsTuner Get-ScheduledTask { }
    }
    It 'resolves command lines to files' {
        InModuleScope iGWindowsTuner {
            Resolve-IgwtCommandPath -Command '"C:\Program Files\App\app.exe" --background' | Should -Be 'C:\Program Files\App\app.exe'
            Resolve-IgwtCommandPath -Command 'C:\Tools\tool.exe /min' | Should -Be 'C:\Tools\tool.exe'
            Resolve-IgwtCommandPath -Command 'rundll32.exe C:\x\y.dll,Entry' | Should -Match 'rundll32\.exe$'
            Resolve-IgwtCommandPath -Command '' | Should -Be ''
        }
    }
    It 'flags unsigned Run entries, IFEO debuggers, changed Winlogon values and WMI command consumers' {
        Write-TestReg -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Updater' -Value '"C:\Nope\updater.exe" -silent' -Kind String
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name 'Debugger' -Value 'cmd.exe' -Kind String
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell' -Value 'explorer.exe, evil.exe' -Kind String
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value 'C:\Windows\system32\userinit.exe,' -Kind String
        $inv = Get-IgwtPersistenceInventory
        $run = @($inv.Entries | Where-Object { $_.Category -eq 'Run keys' -and $_.Name -eq 'Updater' })[0]
        $run.Severity | Should -Be 'Review'; $run.ActionKind | Should -Be 'StartupEntry'; $run.ActionTarget | Should -Be 'HKCU-Run|Updater'
        @($inv.Entries | Where-Object { $_.Category -eq 'IFEO Debugger' })[0].Severity | Should -Be 'Warn'
        @($inv.Entries | Where-Object { $_.Category -eq 'Winlogon' -and $_.Name -eq 'Shell' })[0].Severity | Should -Be 'Warn'
        @($inv.Entries | Where-Object { $_.Category -eq 'Winlogon' -and $_.Name -eq 'Userinit' })[0].Severity | Should -Be 'Info'
        $wmi = @($inv.Entries | Where-Object { $_.Category -eq 'WMI subscriptions' })
        @($wmi | Where-Object { $_.Name -like 'Updater*' })[0].Severity | Should -Be 'Warn'
        @($wmi | Where-Object { $_.Name -like 'SCM*' })[0].Severity | Should -Be 'Info'
        @($inv.Entries | Where-Object { $_.Category -eq 'Browser extensions' })[0].Name | Should -Be 'Test Extension 1.0'
        $inv.Counts.Warn | Should -BeGreaterOrEqual 3
    }
    It 'exports a self-contained HTML report without scripts and with encoded text' {
        $inv = [pscustomobject]@{ Generated = 'now'; Counts = [pscustomobject]@{ Total = 1; Warn = 1; Review = 0 }
            Entries = @([pscustomobject]@{ Category = 'Run keys'; Location = 'HKCU'; Name = '<script>alert(1)</script>'; Command = 'x'; Signature = 'NotSigned'; Signer = ''; Severity = 'Warn'; Note = '' }) }
        $path = Export-IgwtPersistenceReport -Inventory $inv -Path (Join-Path $TestDrive 'p.html')
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Not -Match '<script'
        $html | Should -Match '&lt;script&gt;'
        $json = Export-IgwtPersistenceReport -Inventory $inv -Path (Join-Path $TestDrive 'p.json') -Format Json
        (Get-Content -LiteralPath $json -Raw | ConvertFrom-Json).Counts.Warn | Should -Be 1
    }
}

Describe 'Windows Update status (read-only)' {
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = $Name[0]; Status = 'Running'; StartType = $(if ($Name[0] -eq 'wuauserv') { 'Disabled' } else { 'Manual' }) } }
    }
    It 'reads policies, ignores Defender definitions for the last update and gives advice' {
        Write-TestReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferFeatureUpdatesPeriodInDays' -Value 90
        Write-TestReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -Name 'x' -Value 1
        Mock -ModuleName iGWindowsTuner Get-IgwtUpdateHistoryRaw {
            @(
                [pscustomobject]@{ Date = (Get-Date); Title = 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'; ResultCode = 2; HResult = 0; Operation = 1 }
                [pscustomobject]@{ Date = (Get-Date).AddDays(-60); Title = '2026-08 Cumulative Update'; ResultCode = 2; HResult = 0; Operation = 1 }
                [pscustomobject]@{ Date = (Get-Date).AddDays(-2); Title = '2026-10 Cumulative Update'; ResultCode = 4; HResult = -2145124329; Operation = 1 }
            )
        }
        $u = Get-IgwtUpdateStatus
        @($u.Policies | Where-Object { $_.Name -eq 'DeferFeatureUpdatesPeriodInDays' })[0].Value | Should -Be '90'
        @($u.PendingRestart) | Should -Contain 'Windows Update'
        ([datetime]$u.LastSuccess) | Should -BeLessThan (Get-Date).AddDays(-59)
        $u.Failed | Should -Be 1
        @($u.History | Where-Object { $_.Result -eq 'Failed' })[0].HResult | Should -Be '0x80240017'
        ($u.Advice -join ' ') | Should -Match 'disabled'
        ($u.Advice -join ' ') | Should -Match '45 days'
    }
    It 'reports an unavailable history instead of failing' {
        $u = Get-IgwtUpdateStatus
        $u.Error | Should -Match 'unavailable'
        @($u.History).Count | Should -Be 0
    }
}

Describe 'Network toolkit' {
    It 'flags unexpected hosts-file entries and blocks of Microsoft endpoints' {
        $f = Join-Path $TestDrive 'hosts'
        Set-Content -LiteralPath $f -Encoding ASCII -Value @('# comment', '127.0.0.1 localhost', '::1 localhost', '0.0.0.0 vortex.data.microsoft.com  # telemetry', '10.0.0.5 nas.home')
        $h = Get-IgwtHostsFile -Path $f
        @($h.Entries).Count | Should -Be 4
        @($h.Entries | Where-Object { $_.HostName -eq 'vortex.data.microsoft.com' })[0].Flag | Should -Be 'BlocksMicrosoft'
        @($h.Entries | Where-Object { $_.HostName -eq 'nas.home' })[0].Flag | Should -Be 'Unexpected'
        $h.Unexpected | Should -Be 2
        (Get-IgwtHostsFile -Path (Join-Path $TestDrive 'missing')).Exists | Should -BeFalse
    }
    It 'benchmarks DNS servers and sorts them by median latency' {
        Mock -ModuleName iGWindowsTuner Get-DnsClientServerAddress { @([pscustomobject]@{ ServerAddresses = @('192.168.1.1') }) }
        Mock -ModuleName iGWindowsTuner Measure-IgwtDnsQuery { switch ($Server) { '192.168.1.1' { 30 } '1.1.1.1' { 8 } '9.9.9.9' { $null } default { 15 } } }
        $b = Invoke-IgwtDnsBenchmark -Rounds 2 -Names @('a.example', 'b.example')
        @($b.Results)[0].Server | Should -Be '1.1.1.1'
        @($b.Results)[0].MedianMs | Should -Be 8
        @($b.Results | Where-Object { $_.Server -eq '9.9.9.9' })[0].Failures | Should -Be 4
        @($b.Results)[-1].Server | Should -Be '9.9.9.9'
        @($b.Results | Where-Object { $_.Name -eq 'Current' }).Count | Should -Be 1
    }
    It 'computes latency, jitter and loss and rejects invalid targets' {
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPingProbe { @(10, 12, $null, 14) }
        $l = Test-IgwtNetworkLatency -Target 'game.example', 'bad target!' -Count 4
        $ok = @($l.Results | Where-Object { $_.Target -eq 'game.example' })[0]
        $ok.LossPercent | Should -Be 25; $ok.AvgMs | Should -Be 12; $ok.JitterMs | Should -Be 2; $ok.MinMs | Should -Be 10; $ok.MaxMs | Should -Be 14
        @($l.Results | Where-Object { $_.Target -eq 'bad target!' })[0].Error | Should -Match 'valid'
        Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtPingProbe -Times 1 -Exactly
    }
    It 'browses firewall rules and separates Windows rules from app rules' {
        Mock -ModuleName iGWindowsTuner Get-NetFirewallRule {
            @(
                [pscustomobject]@{ Name = 'AppRule'; DisplayName = 'Contoso Game'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Private'; Group = ''; DisplayGroup = '' }
                [pscustomobject]@{ Name = 'CoreNet-DHCP-In'; DisplayName = 'Core Networking - DHCP'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Group = '@FirewallAPI.dll,-25000'; DisplayGroup = 'Core Networking' }
            )
        }
        Mock -ModuleName iGWindowsTuner Get-NetFirewallApplicationFilter { @([pscustomobject]@{ InstanceID = 'AppRule'; Program = 'D:\Games\Contoso\game.exe' }) }
        $all = Get-IgwtFirewallRuleList
        @($all.Rules).Count | Should -Be 2; $all.AppRules | Should -Be 1
        @($all.Rules | Where-Object { $_.Name -eq 'AppRule' })[0].Program | Should -Be 'D:\Games\Contoso\game.exe'
        @($all.Rules | Where-Object { $_.Name -eq 'CoreNet-DHCP-In' })[0].CanChange | Should -BeFalse
        @((Get-IgwtFirewallRuleList -AppRulesOnly).Rules).Count | Should -Be 1
        @((Get-IgwtFirewallRuleList -Search 'contoso').Rules).Count | Should -Be 1
    }
    It 'describes every advanced adapter property and marks changed values' {
        Mock -ModuleName iGWindowsTuner Get-NetAdapter { @([pscustomobject]@{ Name = 'Ethernet'; InterfaceDescription = 'Intel(R) Ethernet Controller I226-V'; Status = 'Up'; LinkSpeed = '2.5 Gbps' }) }
        Mock -ModuleName iGWindowsTuner Get-NetAdapterAdvancedProperty {
            @(
                [pscustomobject]@{ RegistryKeyword = '*InterruptModeration'; DisplayName = 'Interrupt Moderation'; DisplayValue = 'Disabled'; RegistryValue = @('0'); DefaultRegistryValue = '1'; ValidDisplayValues = @('Disabled', 'Enabled'); NumericParameterMaxValue = $null }
                [pscustomobject]@{ RegistryKeyword = '*FlowControl'; DisplayName = 'Flow Control'; DisplayValue = 'Rx & Tx Enabled'; RegistryValue = @('3'); DefaultRegistryValue = '3'; ValidDisplayValues = @(); NumericParameterMaxValue = $null }
                [pscustomobject]@{ RegistryKeyword = 'VendorThing'; DisplayName = 'Vendor thing'; DisplayValue = 'On'; RegistryValue = @('1'); DefaultRegistryValue = '1'; ValidDisplayValues = @(); NumericParameterMaxValue = $null }
            )
        }
        $p = @((Get-IgwtAdapterPropertyInspection).Adapters[0].Properties)
        $im = @($p | Where-Object { $_.Keyword -eq '*InterruptModeration' })[0]
        $im.ChangedFromDefault | Should -BeTrue
        $im.Description | Should -Not -Match 'see the Microsoft documentation'
        @($p | Where-Object { $_.Keyword -eq '*FlowControl' })[0].ChangedFromDefault | Should -BeFalse
        @($p | Where-Object { $_.Keyword -eq 'VendorThing' })[0].Description | Should -Match 'Vendor-specific'
    }
}

Describe 'Diagnostics (read-only)' {
    It 'computes DPC and ISR percentages from raw counter deltas' {
        InModuleScope iGWindowsTuner {
            $a = [pscustomobject]@{ Dpc = 0; Isr = 0; Idle = 0; Interrupts = 0; Dpcs = 0; Time100ns = 0; PerfTime = 0; PerfFreq = 1000 }
            $b = [pscustomobject]@{ Dpc = 200000; Isr = 100000; Idle = 9000000; Interrupts = 5000; Dpcs = 500; Time100ns = 10000000; PerfTime = 1000; PerfFreq = 1000 }
            $r = ConvertFrom-IgwtProcessorRawPair -First $a -Second $b
            $r.Dpc | Should -Be 2; $r.Isr | Should -Be 1; $r.Cpu | Should -Be 10; $r.InterruptsPerSec | Should -Be 5000; $r.DpcRate | Should -Be 500
            ConvertFrom-IgwtProcessorRawPair -First $b -Second $b | Should -BeNullOrEmpty
        }
    }
    It 'samples DPC/ISR, lists top processes and advises when DPC time is high' {
        $script:Tick = 0
        Mock -ModuleName iGWindowsTuner Start-Sleep { }
        Mock -ModuleName iGWindowsTuner Get-IgwtProcessorRawSample {
            $script:Tick++
            [pscustomobject]@{ Dpc = 300000 * $script:Tick; Isr = 50000 * $script:Tick; Idle = 9000000 * $script:Tick; Interrupts = 4000 * $script:Tick; Dpcs = 100 * $script:Tick; Time100ns = 10000000 * $script:Tick; PerfTime = 1000 * $script:Tick; PerfFreq = 1000 }
        }
        Mock -ModuleName iGWindowsTuner Get-Process { @([pscustomobject]@{ Id = 42; ProcessName = 'game'; TotalProcessorTime = [timespan]::FromSeconds($script:Tick); WorkingSet64 = 1GB }) }
        $d = Get-IgwtDpcIsrSample -Samples 3
        @($d.Samples).Count | Should -Be 3
        $d.Dpc.Average | Should -Be 3
        $d.Isr.Average | Should -Be 0.5
        @($d.TopProcesses)[0].Name | Should -Be 'game'
        ($d.Advice -join ' ') | Should -Match 'LatencyMon'
    }
    It 'collects BugCheck, Kernel-Power and app crashes with the minidump list' {
        $mini = Join-Path $TestDrive 'Minidump'; $null = New-Item -ItemType Directory -Path $mini -Force
        Set-Content -LiteralPath (Join-Path $mini '101726-1.dmp') -Value 'x'
        Mock -ModuleName iGWindowsTuner Get-IgwtCrashInspection { [pscustomobject]@{ MinidumpFolder = $mini; DumpTypeName = 'Automatic memory dump (Windows default)' } }
        Mock -ModuleName iGWindowsTuner Get-WinEvent {
            switch ([int]$FilterHashtable.Id) {
                1001 { [pscustomobject]@{ TimeCreated = (Get-Date).AddDays(-1); Id = 1001; Message = 'The computer has rebooted from a bugcheck. The bugcheck was: 0x0000009f (0x3, 0x1, 0x2, 0x3).'; Properties = @() } }
                41 { 1..2 | ForEach-Object { [pscustomobject]@{ TimeCreated = (Get-Date).AddDays(-$_); Id = 41; Message = 'The system has rebooted without cleanly shutting down first.'; Properties = @() } } }
                1000 { [pscustomobject]@{ TimeCreated = (Get-Date).AddDays(-3); Id = 1000; Message = 'Faulting application'; Properties = @([pscustomobject]@{ Value = 'game.exe' }, [pscustomobject]@{ Value = '1.0' }, [pscustomobject]@{ Value = '0' }, [pscustomobject]@{ Value = 'gfx.dll' }) } }
                default { throw 'No events were found that match the specified selection criteria.' }
            }
        }
        $c = Get-IgwtCrashHistory -Days 30
        $c.Counts.BugCheck | Should -Be 1; $c.Counts.KernelPower41 | Should -Be 2; $c.Counts.UnexpectedShutdown | Should -Be 0; $c.Counts.AppCrash | Should -Be 1
        @($c.Events | Where-Object { $_.Kind -eq 'BugCheck' })[0].Detail | Should -Match '^Stop code 0x0000009f'
        @($c.Events | Where-Object { $_.Kind -eq 'AppCrash' })[0].Detail | Should -Be 'game.exe crashed in gfx.dll'
        @($c.Minidumps).Count | Should -Be 1
        ($c.Advice -join ' ') | Should -Match 'Kernel-Power 41'
    }
    It 'reads boot durations from Diagnostics-Performance event 100' {
        Mock -ModuleName iGWindowsTuner Get-WinEvent {
            $e = [pscustomobject]@{ TimeCreated = (Get-Date); LevelDisplayName = 'Warning' }
            $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="BootTime">24000</Data><Data Name="MainPathBootTime">12000</Data><Data Name="BootPostBootTime">12000</Data></EventData></Event>' }
            $e
        }
        $b = Get-IgwtBootPerformance
        @($b.Boots)[0].BootMs | Should -Be 24000; @($b.Boots)[0].Degraded | Should -BeTrue
        $b.AverageBootSeconds | Should -Be 24
    }
    It 'flags unsigned and old drivers but not the Intel placeholder date' {
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_PnPSignedDriver' } {
            @(
                [pscustomobject]@{ DeviceName = 'Old NIC'; DriverVersion = '1.0'; DriverDate = (Get-Date).AddYears(-8); DriverProviderName = 'Contoso'; IsSigned = $true; Signer = 'Microsoft Windows Hardware Compatibility Publisher'; DeviceClass = 'NET'; InfName = 'oem1.inf' }
                [pscustomobject]@{ DeviceName = 'Unsigned thing'; DriverVersion = '1.0'; DriverDate = (Get-Date); DriverProviderName = 'Contoso'; IsSigned = $false; Signer = ''; DeviceClass = 'SYSTEM'; InfName = 'oem2.inf' }
                [pscustomobject]@{ DeviceName = 'Intel PCIe Root Port'; DriverVersion = '10.1'; DriverDate = [datetime]'1968-07-18'; DriverProviderName = 'INTEL'; IsSigned = $true; Signer = 'Microsoft Windows'; DeviceClass = 'SYSTEM'; InfName = 'oem3.inf' }
                [pscustomobject]@{ DeviceName = 'Inbox'; DriverVersion = '10.0'; DriverDate = [datetime]'2006-06-21'; DriverProviderName = 'Microsoft'; IsSigned = $true; Signer = 'Microsoft Windows'; DeviceClass = 'SYSTEM'; InfName = 'machine.inf' }
            )
        }
        $d = Get-IgwtDriverInventory
        $d.Counts.Total | Should -Be 3; $d.Counts.Unsigned | Should -Be 1; $d.Counts.Old | Should -Be 1
        @($d.Drivers | Where-Object { $_.Device -eq 'Intel PCIe Root Port' })[0].Flag | Should -Be ''
        (Get-IgwtDriverInventory -IncludeMicrosoft).Counts.Total | Should -Be 4
    }
    It 'reports a failing area instead of throwing' {
        Mock -ModuleName iGWindowsTuner Get-IgwtDriverInventory { throw 'WMI broken' }
        Mock -ModuleName iGWindowsTuner Get-IgwtBootPerformance { [pscustomobject]@{ Boots = @(); AverageBootSeconds = $null; Error = 'none'; Note = '' } }
        $d = Get-IgwtDiagnostics -Area Drivers, Boot
        $d.Drivers.Error | Should -Be 'WMI broken'
        (Format-IgwtDiagnostics -Diagnostics $d) | Should -Match 'WMI broken'
    }
}

Describe 'Full system report' {
    It 'exports HTML without scripts and JSON, and records failing sections' {
        Mock -ModuleName iGWindowsTuner Get-IgwtHealthReport { throw 'health down' }
        Mock -ModuleName iGWindowsTuner Get-IgwtDiagnostics { [pscustomobject]@{ Generated = 'now'; Drivers = [pscustomobject]@{ Drivers = @([pscustomobject]@{ Device = '<b>NIC</b>'; Class = 'NET'; Version = '1'; Date = '2020-01-01'; Provider = 'C'; Signer = 'S'; Flag = 'Old' }); Counts = [pscustomobject]@{ Total = 1; Unsigned = 0; Old = 1 }; Note = '' } } }
        Mock -ModuleName iGWindowsTuner Get-IgwtUpdateStatus { [pscustomobject]@{ Services = @(); Policies = @(); History = @(); Advice = @('Restart'); Error = '' } }
        Mock -ModuleName iGWindowsTuner Get-IgwtServiceInventory { [pscustomobject]@{ Counts = [pscustomobject]@{ Total = 1; Running = 1; Protected = 0; ThirdParty = 1 }; Services = @() } }
        Mock -ModuleName iGWindowsTuner Get-IgwtAllTweakStates { @([pscustomobject]@{ Id = 'gfx.game-mode'; State = 'On' }) }
        $r = Get-IgwtSystemReport -Quick
        $r.Health.Error | Should -Match 'health down'
        $r.Persistence | Should -BeNullOrEmpty
        $html = Get-Content -LiteralPath (Export-IgwtSystemReport -Report $r -Path (Join-Path $TestDrive 'sys.html')) -Raw
        $html | Should -Not -Match '<script'
        $html | Should -Match '&lt;b&gt;NIC&lt;/b&gt;'
        $html | Should -Match 'gfx\.game-mode'
        $json = Export-IgwtSystemReport -Report $r -Path (Join-Path $TestDrive 'sys.json') -Format Json
        (Get-Content -LiteralPath $json -Raw | ConvertFrom-Json).ActiveItems[0].Id | Should -Be 'gfx.game-mode'
    }
}

Describe 'Management catalog items' {
    BeforeAll { $script:Cat = @(Get-IgwtCatalog -Force) }
    It 'disables only Microsoft telemetry/CEIP tasks, none of them protected' {
        $t = @($script:Cat | Where-Object { $_.id -eq 'privacy.telemetry-tasks-off' })[0]
        $t.evidence.tier | Should -Be 'B'
        foreach ($a in @($t.actions)) {
            $a.type | Should -Be 'scheduledTask'; $a.on | Should -Be 'Disabled'; $a.default | Should -Be 'Enabled'
            [string]$a.path | Should -BeLike '\Microsoft\Windows\*'
            { InModuleScope iGWindowsTuner -Parameters @{ P = [string]$a.path } { param($P) Assert-IgwtTaskAllowed -Path $P } } | Should -Not -Throw
        }
    }
    It 'defers feature updates only, never quality updates' {
        $t = @($script:Cat | Where-Object { $_.id -eq 'privacy.defer-feature-90' })[0]
        @($t.actions).Count | Should -Be 1
        $t.actions[0].type | Should -Be 'wufbPolicy'; $t.actions[0].setting | Should -Be 'featureDeferralDays'; [int]$t.actions[0].value | Should -Be 90
        @($script:Cat | ForEach-Object { $_.actions } | Where-Object { $_.type -eq 'wufbPolicy' -and $_.setting -eq 'qualityDeferralDays' }).Count | Should -Be 0
    }
}

Describe 'Management command line (argument checks only)' {
    It 'rejects options that belong to other modes' {
        $script = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Search x -NoGui
        $LASTEXITCODE | Should -Be 2
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Change service -Target Fax -NoGui
        $LASTEXITCODE | Should -Be 2
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -SystemReport -NoGui
        $LASTEXITCODE | Should -Be 2
    }
}
