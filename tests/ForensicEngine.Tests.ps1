BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

# Forensic logging on the change engine (3.6, DECISIONS T7): the session's changes are journaled
# steps (origin forensic) and Stop reverts them through the journal. tests\ForensicLogging.Tests.ps1
# keeps checking the unchanged 3.5 behaviour.
Describe 'Forensic logging on the change engine' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
            $script:IgwtJournal = $null
            $p = Get-IgwtForensicSessionPath; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
            $script:FakeFw = @{}
            foreach ($n in 'Domain', 'Private', 'Public') { $script:FakeFw[$n] = @{ LogBlocked = 'False'; LogAllowed = 'False'; LogMaxSizeKilobytes = [uint64]4096; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' } }
            Mock Test-IgwtIsAdmin { $true }
            Mock Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; Authorities = @() } }
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = $false; Value = $null } } -ParameterFilter { $Path -like '*Policies*' }
            Mock Invoke-IgwtAuditpol { [pscustomobject]@{ ExitCode = 5; Output = 'Error 0x00000522 occurred: A required privilege is not held by the client.' } }
            Mock Invoke-IgwtWevtutil { [pscustomobject]@{ ExitCode = 0; Output = "name: $($Arguments[1])`r`nenabled: false`r`n  maxSize: 1052672" } }
            Mock Get-NetFirewallProfile {
                $names = $(if ($Name) { @($Name) } else { @('Domain', 'Private', 'Public') })
                foreach ($n in $names) { $f = $script:FakeFw[$n]; [pscustomobject]@{ Name = $n; LogBlocked = $f.LogBlocked; LogAllowed = $f.LogAllowed; LogMaxSizeKilobytes = $f.LogMaxSizeKilobytes; LogFileName = $f.LogFileName } }
            }
            Mock Set-NetFirewallProfile {
                $f = $script:FakeFw[[string]$Name]
                if ($PesterBoundParameters.ContainsKey('LogBlocked')) { $f.LogBlocked = [string]$LogBlocked }
                if ($PesterBoundParameters.ContainsKey('LogAllowed')) { $f.LogAllowed = [string]$LogAllowed }
                if ($PesterBoundParameters.ContainsKey('LogMaxSizeKilobytes')) { $f.LogMaxSizeKilobytes = [uint64]$LogMaxSizeKilobytes }
            }
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $p = Get-IgwtForensicSessionPath; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } } }

    It 'journals the forensic changes as one session and reverts them through the journal' {
        InModuleScope iGWindowsTuner {
            $s = Start-IgwtForensicLoggingSession -Plan (Get-IgwtForensicLoggingPlan -LoggingProfile Basic) -Minutes 30 -Confirm:$false
            $s.EngineSession | Should -Not -BeNullOrEmpty
            $script:IgwtJournal = $null
            $j = Read-IgwtJournal
            $start = @($j.Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['session'] -eq $s.EngineSession })[0]
            $start['origin']['type'] | Should -Be 'forensic'
            $committed = @($j.Entries | Where-Object { $_['kind'] -eq 'committed' -and $_['session'] -eq $s.EngineSession })
            $committed.Count | Should -Be 3 -Because 'one step per firewall profile'
            foreach ($c in $committed) { $c['target']['provider'] | Should -Be 'forensicFirewall'; $c['readBack']['ok'] | Should -BeTrue }
            $script:FakeFw['Public'].LogBlocked | Should -Be 'True'
            (Stop-IgwtForensicLoggingSession -Confirm:$false).Stopped | Should -BeTrue
            foreach ($n in 'Domain', 'Private', 'Public') { $script:FakeFw[$n].LogBlocked | Should -Be 'False' -Because $n; $script:FakeFw[$n].LogMaxSizeKilobytes | Should -Be 4096 }
            $script:IgwtJournal = $null
            $rev = @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin']['type'] -eq 'revert' })
            $rev.Count | Should -Be 1 -Because 'Stop is a journaled revert session'
            @(Get-IgwtIncompleteChangeSession).Count | Should -Be 0
        }
    }
    It 'refuses a forensic target the session does not own' {
        InModuleScope iGWindowsTuner {
            { Resolve-IgwtChangeTarget -Target ([ordered]@{ provider = 'forensicFirewall'; key = 'forensic|firewall|Other'; profile = 'Other' }) } | Should -Throw '*not a forensic logging target*'
            { Resolve-IgwtChangeTarget -Target ([ordered]@{ provider = 'forensicEventLog'; key = 'forensic|eventlog|Application'; log = 'Application' }) } | Should -Throw '*not a forensic logging target*'
            { Resolve-IgwtChangeTarget -Target ([ordered]@{ provider = 'forensicAudit'; key = 'forensic|audit|0CCE9210-69AE-11D9-BED3-505054503030'; guid = '0CCE9210-69AE-11D9-BED3-505054503030' }) } | Should -Throw '*not a forensic logging target*'
        }
    }
}
