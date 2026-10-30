BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

# Forensic logging (3.5 phase 3): every system call is mocked. The fake system below keeps the
# firewall profiles, the audit subcategories and the event log settings in memory, so snapshot,
# apply and restore round trips can be checked exactly. Real enable/disable round trips run in
# Windows Sandbox (tools\iGWindowsTuner.wsb), not on a development PC.
Describe 'Forensic logging' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            $script:FakeFw = @{}
            foreach ($n in 'Domain', 'Private', 'Public') { $script:FakeFw[$n] = @{ LogBlocked = 'False'; LogAllowed = 'False'; LogMaxSizeKilobytes = [uint64]4096; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' } }
            $script:FakeFw['Public'].LogBlocked = 'NotConfigured'
            $script:FakeAudit = @{ '0CCE9226-69AE-11D9-BED3-505054503030' = 'Failure'; '0CCE9225-69AE-11D9-BED3-505054503030' = 'None' }
            $script:FakeAuditBackup = $null
            $script:FakeLogs = @{ 'Security' = @{ enabled = 'true'; retention = 'false'; autoBackup = 'false'; maxSize = '20971520' }; 'Microsoft-Windows-DNS-Client/Operational' = @{ enabled = 'false'; retention = 'false'; autoBackup = 'false'; maxSize = '1052672' } }
            $script:WevtCalls = New-Object System.Collections.Generic.List[string]
            $script:FailOn = ''
            Mock Test-IgwtIsAdmin { $true }
            Mock Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; Authorities = @() } }
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = $false; Value = $null } }
            Mock Get-NetFirewallProfile {
                $names = $(if ($Name) { @($Name) } else { @('Domain', 'Private', 'Public') })
                foreach ($n in $names) { $f = $script:FakeFw[$n]; [pscustomobject]@{ Name = $n; LogBlocked = $f.LogBlocked; LogAllowed = $f.LogAllowed; LogMaxSizeKilobytes = $f.LogMaxSizeKilobytes; LogFileName = $f.LogFileName } }
            }
            Mock Set-NetFirewallProfile {
                if ($script:FailOn -eq 'firewall') { $script:FailOn = ''; throw 'simulated firewall failure' }   # fails the first call (the change), not the restore
                $f = $script:FakeFw[[string]$Name]
                if ($PesterBoundParameters.ContainsKey('LogBlocked')) { $f.LogBlocked = [string]$LogBlocked }
                if ($PesterBoundParameters.ContainsKey('LogAllowed')) { $f.LogAllowed = [string]$LogAllowed }
                if ($PesterBoundParameters.ContainsKey('LogMaxSizeKilobytes')) { $f.LogMaxSizeKilobytes = [uint64]$LogMaxSizeKilobytes }
            }
            Mock Invoke-IgwtAuditpol {
                $text = @{ None = 'No Auditing'; Success = 'Success'; Failure = 'Failure'; SuccessAndFailure = 'Success and Failure' }
                switch ($Arguments[0]) {
                    '/get' {
                        $csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`r`n"
                        $csv += "PC,System,Filtering Platform Connection,{0CCE9226-69AE-11D9-BED3-505054503030},$($text[$script:FakeAudit['0CCE9226-69AE-11D9-BED3-505054503030']]),`r`n"
                        $csv += "PC,System,Filtering Platform Packet Drop,{0CCE9225-69AE-11D9-BED3-505054503030},$($text[$script:FakeAudit['0CCE9225-69AE-11D9-BED3-505054503030']]),`r`n"
                        return [pscustomobject]@{ ExitCode = 0; Output = $csv }
                    }
                    '/backup' { $f = $Arguments[1].Substring(6); [IO.File]::WriteAllText($f, 'backup'); $script:FakeAuditBackup = $script:FakeAudit.Clone(); return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                    '/restore' { $script:FakeAudit = $script:FakeAuditBackup.Clone(); return [pscustomobject]@{ ExitCode = 0; Output = '' } }
                    '/set' {
                        $g = ($Arguments[1] -replace '^/subcategory:\{|\}$', '').ToUpperInvariant()
                        if ($script:FailOn -eq 'audit' -and $g -eq '0CCE9225-69AE-11D9-BED3-505054503030') { return [pscustomobject]@{ ExitCode = 1; Output = 'simulated audit failure' } }
                        $s = $Arguments[2] -eq '/success:enable'; $f = $Arguments[3] -eq '/failure:enable'
                        $script:FakeAudit[$g] = $(if ($s -and $f) { 'SuccessAndFailure' } elseif ($s) { 'Success' } elseif ($f) { 'Failure' } else { 'None' })
                        return [pscustomobject]@{ ExitCode = 0; Output = '' }
                    }
                }
            }
            Mock Invoke-IgwtWevtutil {
                $script:WevtCalls.Add(($Arguments -join ' '))
                $log = $script:FakeLogs[$Arguments[1]]
                if ($Arguments[0] -eq 'gl') { return [pscustomobject]@{ ExitCode = 0; Output = "name: $($Arguments[1])`r`nenabled: $($log.enabled)`r`ntype: Admin`r`nlogging:`r`n  logFileName: x.evtx`r`n  retention: $($log.retention)`r`n  autoBackup: $($log.autoBackup)`r`n  maxSize: $($log.maxSize)" } }
                if ($script:FailOn -eq 'wevtutil') { return [pscustomobject]@{ ExitCode = 5; Output = 'Access is denied.' } }
                foreach ($a in $Arguments[2..($Arguments.Count - 1)]) {
                    if ($a -like '/ms:*') { $log.maxSize = $a.Substring(4) }
                    if ($a -like '/e:*') { $log.enabled = $a.Substring(3) }
                }
                return [pscustomobject]@{ ExitCode = 0; Output = '' }
            }
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $p = Get-IgwtForensicSessionPath; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } } }

    It 'reads the state of every source (Security log without elevation through wevtutil gl)' {
        InModuleScope iGWindowsTuner {
            $s = Get-IgwtForensicLoggingState
            @($s.Firewall).Count | Should -Be 3
            $s.Firewall[0].LogFile | Should -Not -Match '%systemroot%'
            $s.Wfp.Connection | Should -Be 'Failure'
            $s.SecurityLog.MaxSizeBytes | Should -Be 20971520
            $s.Dns.Enabled | Should -BeFalse
            $s.Session | Should -BeNullOrEmpty
        }
    }
    It 'plans Basic as blocked packets only and Full as every source, only ever raising settings' {
        InModuleScope iGWindowsTuner {
            $b = Get-IgwtForensicLoggingPlan -LoggingProfile Basic
            @($b.Ops | Where-Object Source -NE 'Firewall').Count | Should -Be 0
            @($b.Ops | Where-Object { $_.Setting -eq 'LogBlocked' -and $_.Changes }).Count | Should -Be 3
            $f = Get-IgwtForensicLoggingPlan -LoggingProfile Full -SecurityLogMB 1024
            ($f.Ops | Where-Object Target -EQ 'Filtering Platform Connection').New | Should -Be 'SuccessAndFailure'
            ($f.Ops | Where-Object Target -EQ 'Filtering Platform Packet Drop').New | Should -Be 'Failure'
            ($f.Ops | Where-Object Source -EQ 'SecurityLog').New | Should -Be (1024MB)
            ($f.Ops | Where-Object Source -EQ 'Dns').New | Should -BeTrue
            ($f.Notes -join ' ') | Should -Match 'time-boxed'
            $script:FakeLogs.Security.maxSize = [string](2GB)
            $f2 = Get-IgwtForensicLoggingPlan -LoggingProfile Full -SecurityLogMB 256
            ($f2.Ops | Where-Object Source -EQ 'SecurityLog').Changes | Should -BeFalse -Because 'a larger Security log is never made smaller'
        }
    }
    It 'treats settings set by a policy as read-only, and refuses network-share log paths' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = ($Path -like '*DomainProfile\Logging' -or $Path -like '*EventLog\Security'); Value = 1 } }
            $script:FakeFw['Public'].LogFileName = '\\server\share\pfirewall.log'
            $p = Get-IgwtForensicLoggingPlan -LoggingProfile Full
            @($p.Ops | Where-Object { $_.Target -eq 'Domain' -and $_.Changes }).Count | Should -Be 0
            ($p.Ops | Where-Object { $_.Target -eq 'Domain' } | Select-Object -First 1).Refused | Should -Match 'policy'
            ($p.Ops | Where-Object { $_.Target -eq 'Public' } | Select-Object -First 1).Refused | Should -Match 'network share'
            ($p.Ops | Where-Object Source -EQ 'SecurityLog').Refused | Should -Match 'policy'
            Mock Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; Authorities = @('Domain') } }
            $m = Get-IgwtForensicLoggingPlan -LoggingProfile Full
            @($m.Ops | Where-Object { $_.Source -eq 'Wfp' -and $_.Changes }).Count | Should -Be 0
        }
    }
    It 'snapshots, applies and restores every setting exactly (including NotConfigured)' {
        InModuleScope iGWindowsTuner {
            $before = @{ fw = ($script:FakeFw | ConvertTo-Json -Depth 3); audit = ($script:FakeAudit | ConvertTo-Json); logs = ($script:FakeLogs | ConvertTo-Json -Depth 3) }
            $s = Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Full -SecurityLogMB 512) -Minutes 30 -Confirm:$false
            $s.Profile | Should -Be 'Full'
            $s.Until | Should -BeGreaterThan $s.Started
            $script:FakeFw['Public'].LogBlocked | Should -Be 'True'
            $script:FakeFw['Domain'].LogAllowed | Should -Be 'True'
            $script:FakeFw['Domain'].LogMaxSizeKilobytes | Should -Be 32767
            $script:FakeAudit['0CCE9226-69AE-11D9-BED3-505054503030'] | Should -Be 'SuccessAndFailure'
            $script:FakeLogs.Security.maxSize | Should -Be ([string](512MB))
            $script:FakeLogs['Microsoft-Windows-DNS-Client/Operational'].enabled | Should -Be 'true'
            $order = @($script:WevtCalls | Where-Object { $_ -like 'sl*' })
            $order[0] | Should -Match '^sl Security' -Because 'the Security log grows before auditing starts'
            $r = Stop-IgwtForensicLoggingSession -Confirm:$false
            $r.Stopped | Should -BeTrue
            ($script:FakeFw | ConvertTo-Json -Depth 3) | Should -Be $before.fw
            ($script:FakeAudit | ConvertTo-Json) | Should -Be $before.audit
            ($script:FakeLogs | ConvertTo-Json -Depth 3) | Should -Be $before.logs
            Get-IgwtForensicSession | Should -BeNullOrEmpty
        }
    }
    It 'restores everything applied so far when a step fails' {
        InModuleScope iGWindowsTuner {
            $before = @{ audit = ($script:FakeAudit | ConvertTo-Json); logs = ($script:FakeLogs | ConvertTo-Json -Depth 3) }
            $script:FailOn = 'firewall'
            { Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Full) -Confirm:$false } | Should -Throw '*simulated firewall failure*'
            $script:FailOn = ''
            ($script:FakeAudit | ConvertTo-Json) | Should -Be $before.audit
            ($script:FakeLogs | ConvertTo-Json -Depth 3) | Should -Be $before.logs
            Get-IgwtForensicSession | Should -BeNullOrEmpty
        }
    }
    It 'notices a session that expired while the app was closed, and refuses a second session' {
        InModuleScope iGWindowsTuner {
            $s = Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Basic) -Minutes 30 -Confirm:$false
            (Get-IgwtForensicSession -Now $s.Started.AddMinutes(10)).Expired | Should -BeFalse
            (Get-IgwtForensicSession -Now $s.Started.AddMinutes(31)).Expired | Should -BeTrue
            { Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Basic) -Confirm:$false } | Should -Throw '*already*'
            (Stop-IgwtForensicLoggingSession -Confirm:$false).Stopped | Should -BeTrue
            $u = Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Basic) -Minutes 0 -Confirm:$false
            $u.Until | Should -BeNullOrEmpty -Because '0 minutes means until stopped'
            $u.Expired | Should -BeFalse
        }
    }
    It 'keeps the session when a restore step fails, so it can be retried' {
        InModuleScope iGWindowsTuner {
            $null = Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Full) -Confirm:$false
            $script:FailOn = 'wevtutil'
            $r = Stop-IgwtForensicLoggingSession -Confirm:$false
            $r.Stopped | Should -BeFalse
            $r.Message | Should -Match 'try again'
            Get-IgwtForensicSession | Should -Not -BeNullOrEmpty
            $script:FailOn = ''
            (Stop-IgwtForensicLoggingSession -Confirm:$false).Stopped | Should -BeTrue
        }
    }
    It 'refuses changes in read-only mode and never clears or exports with the wrong verbs' {
        InModuleScope iGWindowsTuner {
            $plan = Get-IgwtForensicLoggingPlan -LoggingProfile Basic
            Set-IgwtEnvironment -ReadOnly
            try { { Start-IgwtForensicLoggingSession -Plan $plan -Confirm:$false } | Should -Throw 'Read-only mode:*' } finally { Set-IgwtEnvironment -ReadOnly:$false }
        }
        $src = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Defender\ForensicLogging.ps1') -Raw
        $src | Should -Not -Match "(?i)'cl'|clear-log|Clear-EventLog|Remove-EventLog|Limit-EventLog|Register-ScheduledTask|New-Service"
        { InModuleScope iGWindowsTuner { & ${function:Invoke-IgwtWevtutil} -Arguments @('cl', 'Security') } } | Should -Throw '*not used*' -Because 'the real function, not the mock, refuses to clear a log'
    }
    It 'review 3.5 #1: restores the audit policy when the second auditpol /set fails' {
        InModuleScope iGWindowsTuner {
            $before = ($script:FakeAudit | ConvertTo-Json)
            $script:FailOn = 'audit'
            { Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Full) -Confirm:$false } | Should -Throw '*simulated audit failure*'
            $script:FailOn = ''
            ($script:FakeAudit | ConvertTo-Json) | Should -Be $before -Because 'the backup was taken before any change and restored'
            Get-IgwtForensicSession | Should -BeNullOrEmpty
        }
    }
    It 'review 3.5 #2/#3: an incomplete rollback keeps the record (rollback-incomplete) so it can be retried' {
        InModuleScope iGWindowsTuner {
            Mock Set-NetFirewallProfile { throw 'simulated firewall failure' }
            { Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Basic) -Confirm:$false } | Should -Throw '*could not be restored*'
            $s = Get-IgwtForensicSession
            $s.Status | Should -Be 'rollback-incomplete'
            $s.Expired | Should -BeTrue -Because 'it needs restoring'
        }
    }
    It 'review 3.5 #4: a damaged session record is reported and restored from the newest forensic snapshot' {
        InModuleScope iGWindowsTuner {
            $null = Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Basic) -Confirm:$false
            [IO.File]::WriteAllText((Get-IgwtForensicSessionPath), '{ "kind": "igwt-forensic-session", "started": "not a date" }')
            $s = Get-IgwtForensicSession
            $s.Corrupt | Should -BeTrue
            { Get-IgwtForensicLoggingState } | Should -Not -Throw
            (Stop-IgwtForensicLoggingSession -Confirm:$false).Stopped | Should -BeTrue
            $script:FakeFw['Domain'].LogBlocked | Should -Be 'False'
            Get-IgwtForensicSession | Should -BeNullOrEmpty
            { Stop-IgwtForensicLoggingSession -SnapshotPath 'C:\Windows' -Confirm:$false } | Should -Not -Throw -Because 'with no session there is nothing to stop'
        }
    }
    It 'review 3.5 #5: Start makes the plan again (a policy that appeared after the preview is respected)' {
        InModuleScope iGWindowsTuner {
            $plan = Get-IgwtForensicLoggingPlan -LoggingProfile Basic
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = ($Path -like '*DomainProfile\Logging'); Value = 1 } }
            $null = Start-IgwtForensicLoggingSession -Plan $plan -Confirm:$false
            $script:FakeFw['Domain'].LogBlocked | Should -Be 'False' -Because 'Domain is now set by a policy'
            $script:FakeFw['Private'].LogBlocked | Should -Be 'True'
            (Stop-IgwtForensicLoggingSession -Confirm:$false).Stopped | Should -BeTrue
        }
    }
    It 'estimates the volume from the connection rate' {
        InModuleScope iGWindowsTuner {
            $e = Get-IgwtForensicVolumeEstimate -ConnectionsPerHour 3600
            $e.EventsPerHour | Should -Be 3600
            ($e.Retention | Where-Object SizeMB -EQ 512).Hours | Should -Be ([Math]::Round(512MB / (3600 * 1024.0), 1))
            $e.Assumption | Should -Match 'UNVERIFIED'
            Mock Get-NetTCPConnection { [pscustomobject]@{ LocalAddress = '1.1.1.1'; LocalPort = 1; RemoteAddress = '2.2.2.2'; RemotePort = (Get-Random); OwningProcess = 4 } }
            Mock Get-NetUDPEndpoint { @() }
            Mock Start-Sleep { }
            (Measure-IgwtConnectionRate -Seconds 10).New | Should -Be 1
        }
    }
}

Describe 'Forensic logging window (Ario 2026-10-30: second Start while a session runs)' {
    It 'shows the job''s own message, not the EndInvoke wrapper' {
        $ps = [powershell]::Create().AddScript('throw "A forensic logging session is already recorded. Stop and restore it first."')
        try { $null = $ps.Invoke(); $msg = 'no error' } catch { $msg = InModuleScope iGWindowsTuner -Parameters @{ E = $_.Exception } { param($E) Get-IgwtGuiJobErrorText -Exception $E } } finally { $ps.Dispose() }
        $msg | Should -Be 'A forensic logging session is already recorded. Stop and restore it first.'
    }
    It 'offers Start only without a session and Stop and restore only with one' {
        InModuleScope iGWindowsTuner {
            $old = $script:Gui
            $btn = { [pscustomobject]@{ IsEnabled = $null; ToolTip = $null } }
            $script:Gui = @{ IsAdmin = $true; C = @{ FwForStartButton = (& $btn); FwForStopButton = (& $btn); ForensicBannerStopButton = (& $btn) } }
            try {
                Update-IgwtGuiForensicButtons -Session $null
                $script:Gui.C.FwForStartButton.IsEnabled | Should -BeTrue
                $script:Gui.C.FwForStopButton.IsEnabled | Should -BeFalse
                Update-IgwtGuiForensicButtons -Session ([pscustomobject]@{ Status = 'active' })
                $script:Gui.C.FwForStartButton.IsEnabled | Should -BeFalse
                $script:Gui.C.FwForStartButton.ToolTip | Should -Match 'running'
                $script:Gui.C.FwForStopButton.IsEnabled | Should -BeTrue
                Set-IgwtEnvironment -ReadOnly
                try { Update-IgwtGuiForensicButtons -Session $null; $script:Gui.C.FwForStartButton.IsEnabled | Should -BeFalse; $script:Gui.C.FwForStartButton.ToolTip | Should -Match 'read-only' } finally { Set-IgwtEnvironment -ReadOnly:$false }
            } finally { $script:Gui = $old }
        }
    }
}
