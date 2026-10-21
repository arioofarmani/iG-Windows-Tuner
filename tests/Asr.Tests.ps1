# ASR Center, ASR audit view and security modules. Defender, event log, accounts and
# network cmdlets are mocked; registry access stays in TestRegistry. Nothing touches the real system.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    $script:AsrKey = 'TestRegistry:\HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    $script:Verified = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'e6db77e5-3df2-4cf1-b95a-636979351e5b',
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
        '01443614-cd74-433a-b99e-2ecdc07bfc25', '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'd3e037e1-3eb8-44c8-a917-57927947596d',
        '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', '26190899-1602-49e8-8b27-eb1d0a1ce869',
        'd1e49aac-8f56-4280-b9ba-993a6d77406c', '33ddedf1-c6e0-47cb-833e-de6133960387', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb', 'a8f5898e-1dc8-49a9-9878-85004b8a61e6', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
        'c1db55ab-c21a-4637-bb3f-a12568109d35')

    # Stateful Defender mocks: rules, global ASR-only exclusions and status.
    function Initialize-MpMock {
        $script:Mp = @{ MAPSReporting = 2; AttackSurfaceReductionRules_Ids = @(); AttackSurfaceReductionRules_Actions = @(); AttackSurfaceReductionOnlyExclusions = @() }
        $script:MpActive = $true
        $script:AsrMap = @{ Disabled = 0; Enabled = 1; AuditMode = 2; Warn = 6 }
        Mock Get-MpComputerStatus -ModuleName iGWindowsTuner { [pscustomobject]@{ AMServiceEnabled = $script:MpActive; AMRunningMode = 'Normal'; RealTimeProtectionEnabled = $true; IsTamperProtected = $true } }
        Mock Get-MpPreference -ModuleName iGWindowsTuner { [pscustomobject]$script:Mp }
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
            if ($PesterBoundParameters.ContainsKey('AttackSurfaceReductionOnlyExclusions')) { $script:Mp.AttackSurfaceReductionOnlyExclusions = @($script:Mp.AttackSurfaceReductionOnlyExclusions) + @($AttackSurfaceReductionOnlyExclusions) }
        }
        Mock Remove-MpPreference -ModuleName iGWindowsTuner {
            if ($PesterBoundParameters.ContainsKey('AttackSurfaceReductionRules_Ids')) {
                $id = [string]@($AttackSurfaceReductionRules_Ids)[0]
                $ids = [System.Collections.ArrayList]@($script:Mp.AttackSurfaceReductionRules_Ids); $acts = [System.Collections.ArrayList]@($script:Mp.AttackSurfaceReductionRules_Actions)
                $i = $ids.IndexOf($id); if ($i -ge 0) { $ids.RemoveAt($i); $acts.RemoveAt($i) }
                $script:Mp.AttackSurfaceReductionRules_Ids = @($ids); $script:Mp.AttackSurfaceReductionRules_Actions = @($acts)
            }
            if ($PesterBoundParameters.ContainsKey('AttackSurfaceReductionOnlyExclusions')) { $rm = @($AttackSurfaceReductionOnlyExclusions); $script:Mp.AttackSurfaceReductionOnlyExclusions = @($script:Mp.AttackSurfaceReductionOnlyExclusions | Where-Object { $rm -notcontains $_ }) }
        }
    }
    function Add-MpRuleFixture([string]$Id, [int]$Code) {
        $script:Mp.AttackSurfaceReductionRules_Ids = @($script:Mp.AttackSurfaceReductionRules_Ids) + $Id
        $script:Mp.AttackSurfaceReductionRules_Actions = @($script:Mp.AttackSurfaceReductionRules_Actions) + $Code
    }
    function Get-MpRuleCode([string]$Id) {
        $ids = @($script:Mp.AttackSurfaceReductionRules_Ids)
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i] -eq $Id) { return [int]@($script:Mp.AttackSurfaceReductionRules_Actions)[$i] } }
        return $null
    }
    function Clear-AsrPolicy { Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Policies' -Recurse -Force -ErrorAction SilentlyContinue }
    function Get-AsrRule([string]$Key) { @((Get-IgwtAsrStatus).Rules | Where-Object { $_.Key -eq $Key })[0] }
}

Describe 'ASR rule catalog' {
    BeforeAll { $script:Rules = @(Get-IgwtAsrCatalog -Force) }

    It 'lists all 19 rules from the Microsoft reference, each once' {
        $script:Rules.Count | Should -Be 19
        @($script:Rules | ForEach-Object { ([string]$_.id).ToLowerInvariant() } | Sort-Object) | Should -Be @($script:Verified | Sort-Object)
    }
    It 'passes validation (hint <= 140, description, gamer impact, modes, sources)' {
        @(Test-IgwtAsrCatalog) | Should -BeNullOrEmpty
    }
    It 'gives every rule a hint, a description and a gamer-impact note' {
        foreach ($r in $script:Rules) {
            ([string]$r.hint).Length | Should -BeLessOrEqual 140 -Because $r.key
            ([string]$r.description).Length | Should -BeGreaterOrEqual 40 -Because $r.key
            ([string]$r.gamerImpact).Length | Should -BeGreaterOrEqual 20 -Because $r.key
        }
    }
    It 'marks the documented Warn, cloud and server-only limitations' {
        @($script:Rules | Where-Object { -not $_.supportsWarn } | ForEach-Object { $_.key } | Sort-Object) | Should -Be @('lsass', 'office-injection')
        @($script:Rules | Where-Object { $_.requiresCloud } | ForEach-Object { $_.key } | Sort-Object) | Should -Be @('obfuscated-scripts', 'prevalence-age', 'ransomware')
        @($script:Rules | Where-Object { $_.serverOnly } | ForEach-Object { $_.key }) | Should -Be @('webshell-servers')
    }
    It 'recommends Block for the three standard protection rules and never Block for medium or high gamer impact' {
        @($script:Rules | Where-Object { $_.category -eq 'standard' } | ForEach-Object { $_.recommendedMode } | Select-Object -Unique) | Should -Be @('Block')
        @($script:Rules | Where-Object { $_.category -eq 'standard' }).Count | Should -Be 3
        @($script:Rules | Where-Object { $_.gamerImpactLevel -in 'medium', 'high' -and $_.recommendedMode -eq 'Block' }) | Should -BeNullOrEmpty
    }
    It 'reports a broken rule catalog' {
        $copy = Join-Path $TestDrive 'data-asr'
        Copy-Item -Path (Join-Path $script:IgwtProjectRoot 'data') -Destination $copy -Recurse
        $file = Join-Path $copy 'asr\rules.json'
        $doc = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        $doc.rules[1].recommendedMode = 'Warn'                      # LSASS does not support Warn
        $doc.rules[0].hint = ('x' * 150)
        $doc.rules[9].recommendedMode = 'Block'                      # high gamer impact
        Set-Content -LiteralPath $file -Value ($doc | ConvertTo-Json -Depth 10) -Encoding UTF8
        try {
            Set-IgwtEnvironment -DataFolder $copy
            $errs = @(Test-IgwtAsrCatalog)
        } finally { Set-IgwtEnvironment -DataFolder '' }
        ($errs -join "`n") | Should -Match "lsass': recommends Warn, which the rule does not support"
        ($errs -join "`n") | Should -Match 'hint is 150'
        ($errs -join "`n") | Should -Match 'medium or high gamer impact'
    }
    It 'every asrRule action in the tweak catalog uses a rule from the ASR catalog' {
        $ids = @($script:Rules | ForEach-Object { ([string]$_.id).ToLowerInvariant() })
        foreach ($a in (Get-IgwtCatalog).actions | Where-Object { $_.type -eq 'asrRule' }) { ([string]$a.id).ToLowerInvariant() | Should -BeIn $ids }
    }
}

Describe 'ASR status (read-only)' {
    BeforeEach { Initialize-MpMock; Clear-AsrPolicy }

    It 'reports local modes, the Windows default and the recommendation gap' {
        Add-MpRuleFixture '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' 1
        Add-MpRuleFixture 'd1e49aac-8f56-4280-b9ba-993a6d77406c' 2
        $s = Get-IgwtAsrStatus
        $lsass = @($s.Rules | Where-Object { $_.Key -eq 'lsass' })[0]
        $lsass.Mode | Should -Be 'Block'; $lsass.Source | Should -Be 'Local'; $lsass.MeetsRecommendation | Should -BeTrue
        $lsass.AllowedModes | Should -Not -Contain 'Warn'
        $ps = @($s.Rules | Where-Object { $_.Key -eq 'psexec-wmi' })[0]
        $ps.Mode | Should -Be 'Audit'; $ps.MeetsRecommendation | Should -BeTrue
        $drv = @($s.Rules | Where-Object { $_.Key -eq 'vulnerable-drivers' })[0]
        $drv.Mode | Should -Be 'NotConfigured'; $drv.Source | Should -Be 'NotSet'; $drv.MeetsRecommendation | Should -BeFalse
        @($s.Rules | Where-Object { $_.Key -eq 'webshell-servers' })[0].AllowedModes | Should -BeNullOrEmpty
        $s.Summary.StandardInBlock | Should -Be 1
    }
    It 'shows Group Policy and MDM modes as managed' {
        $null = New-Item -Path "$script:AsrKey\Rules" -Force
        $null = New-ItemProperty -Path "$script:AsrKey\Rules" -Name '56a863a9-875e-4185-98a7-b882c64b5ce5' -Value '1' -PropertyType String
        $mdm = 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender'
        $null = New-Item -Path $mdm -Force
        $null = New-ItemProperty -Path $mdm -Name 'AttackSurfaceReductionRules' -Value 'e6db77e5-3df2-4cf1-b95a-636979351e5b=2|56a863a9-875e-4185-98a7-b882c64b5ce5=0' -PropertyType String
        $s = Get-IgwtAsrStatus
        $drv = @($s.Rules | Where-Object { $_.Key -eq 'vulnerable-drivers' })[0]
        $drv.Source | Should -Be 'GroupPolicy'; $drv.Mode | Should -Be 'Block'; $drv.ManagedByPolicy | Should -BeTrue
        $wmi = @($s.Rules | Where-Object { $_.Key -eq 'wmi-persistence' })[0]
        $wmi.Source | Should -Be 'MDM'; $wmi.Mode | Should -Be 'Audit'
        $s.Summary.PolicyManaged | Should -Be 2
        Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft' -Recurse -Force
    }
    It 'flags rules that need cloud protection when it is off' {
        $script:Mp.MAPSReporting = 0
        (Get-AsrRule 'ransomware').CloudMissing | Should -BeTrue
        (Get-AsrRule 'lsass').CloudMissing | Should -BeFalse
    }
    It 'reads per-rule exclusions and confirms them only when Defender reports them' {
        $null = New-Item -Path "$script:AsrKey\ASROnlyPerRuleExclusions" -Force
        $null = New-ItemProperty -Path "$script:AsrKey\ASROnlyPerRuleExclusions" -Name 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' -Value 'D:\Games\A\a.exe>D:\Games\B\b.exe' -PropertyType String
        $script:Mp.AttackSurfaceReductionRules_RuleSpecificExclusions_Id = @('N/A: Must be an administrator to view exclusions')
        $script:Mp.AttackSurfaceReductionRules_RuleSpecificExclusions = @('N/A: Must be an administrator to view exclusions')
        $r = Get-AsrRule 'copied-system-tools'
        @($r.Exclusions) | Should -Be @('D:\Games\A\a.exe', 'D:\Games\B\b.exe')
        $r.ExclusionsVerified | Should -Be 'Unknown'
        $script:Mp.AttackSurfaceReductionRules_RuleSpecificExclusions_Id = @('c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb')
        $script:Mp.AttackSurfaceReductionRules_RuleSpecificExclusions = @('D:\Games\A\a.exe>D:\Games\B\b.exe')
        (Get-AsrRule 'copied-system-tools').ExclusionsVerified | Should -Be 'Yes'
        $script:Mp.AttackSurfaceReductionRules_RuleSpecificExclusions = @('D:\Games\A\a.exe')
        (Get-AsrRule 'copied-system-tools').ExclusionsVerified | Should -Be 'No'
    }
    It 'reports global exclusions as unreadable without administrator rights' {
        $script:Mp.AttackSurfaceReductionOnlyExclusions = @('N/A: Must be an administrator to view exclusions')
        (Get-IgwtAsrStatus).GlobalExclusions.Readable | Should -BeFalse
    }
    It 'plans recommendations that only raise rules' {
        Add-MpRuleFixture '01443614-cd74-433a-b99e-2ecdc07bfc25' 1   # prevalence rule already in Block (recommended Audit)
        $plan = @(Get-IgwtAsrRecommendationPlan)
        @($plan | Where-Object { $_.Key -eq 'prevalence-age' }) | Should -BeNullOrEmpty
        @($plan | Where-Object { $_.Key -eq 'webshell-servers' }) | Should -BeNullOrEmpty
        @($plan | Where-Object { $_.Key -eq 'lsass' })[0].To | Should -Be 'Block'
        foreach ($p in $plan) { $p.To | Should -BeIn @('Audit', 'Block') }
    }
}

Describe 'ASR exclusion path validation' {
    It 'accepts specific program files and deep folders' -TestCases @(
        @{ P = 'D:\Games\MyGame\MyGame.exe' }
        @{ P = '%ProgramFiles%\Vendor\Tool.exe' }
        @{ P = '%ProgramFiles(x86)%\Steam\steamapps\common\Game\game.exe' }
        @{ P = 'D:\Games\MyGame' }
        @{ P = 'D:\Games\*\launcher.exe' }
    ) {
        param($P)
        $r = Test-IgwtAsrExclusion -Path $P
        $r.Valid | Should -BeTrue -Because $r.Reason
    }
    It 'accepts one program file inside a user profile' {
        (Test-IgwtAsrExclusion -Path (Join-Path $env:USERPROFILE 'AppData\Local\Programs\Tool\tool.exe')).Valid | Should -BeTrue
    }
    It 'warns about folder exclusions' {
        @((Test-IgwtAsrExclusion -Path 'D:\Games\MyGame').Warnings) -join ' ' | Should -Match 'folder exclusion'
    }
    It 'refuses broad, writable or malformed paths' -TestCases @(
        @{ P = '' }, @{ P = ' D:\Games\A\a.exe' }, @{ P = 'D:\Games\A\a.exe ' }, @{ P = 'C:\' }, @{ P = 'C:\*' }, @{ P = 'C:\*\*' }, @{ P = 'D:\*.exe' }
        @{ P = '*:\Games\a.exe' }, @{ P = 'Games\a.exe' }, @{ P = 'C:\Windows\System32\cmd.exe' }, @{ P = 'C:\Windows' }
        @{ P = '%SystemRoot%\System32\mshta.exe' }, @{ P = '%USERPROFILE%\a.exe' }, @{ P = '%TEMP%\a.exe' }, @{ P = '%LOCALAPPDATA%\Tool\a.exe' }
        @{ P = 'C:\Program Files' }, @{ P = 'C:\Program Files\' }, @{ P = 'D:\Games' }, @{ P = 'D:\Games\A\a">b.exe' }, @{ P = 'D:\Games\A|B\a.exe' }
        @{ P = 'D:\Games\..\Windows\a.exe' }, @{ P = 'D:\*\launcher.exe' }, @{ P = 'D:\Games\*' }
    ) {
        param($P)
        (Test-IgwtAsrExclusion -Path $P).Valid | Should -BeFalse
    }
    It 'refuses Downloads, Desktop, temp folders and folders in profiles or ProgramData' {
        foreach ($p in @((Join-Path $env:USERPROFILE 'Downloads\tool.exe'), (Join-Path $env:USERPROFILE 'Desktop\tool.exe'), (Join-Path $env:USERPROFILE 'AppData\Local\Temp\x.exe'),
                (Join-Path $env:USERPROFILE 'Documents'), (Join-Path $env:USERPROFILE 'Games\*.exe'), (Join-Path $env:ProgramData 'Vendor'), (Join-Path $env:ProgramData 'Vendor\*.exe'))) {
            (Test-IgwtAsrExclusion -Path $p).Valid | Should -BeFalse -Because $p
        }
    }
}

Describe 'ASR Center changes (snapshot first, revertible)' {
    BeforeEach { Initialize-MpMock; Clear-AsrPolicy }

    It 'sets a rule mode, records a snapshot and reverts to Not configured' {
        $r = Invoke-IgwtAsrChange -RuleMode @{ 'psexec-wmi' = 'Audit' }
        $r.Changes | Should -Be 1
        @($r.Results)[0].Result | Should -Be 'Applied'
        Get-MpRuleCode 'd1e49aac-8f56-4280-b9ba-993a6d77406c' | Should -Be 2
        Test-Path -LiteralPath $r.Snapshot | Should -BeTrue
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.operation | Should -Be 'ASR'
        $doc.entries[0].actions[0].type | Should -Be 'asrRuleMode'
        $doc.entries[0].actions[0].data.configured | Should -BeFalse
        $rev = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        @($rev.Results)[0].Result | Should -Be 'Reverted'
        Get-MpRuleCode 'd1e49aac-8f56-4280-b9ba-993a6d77406c' | Should -BeNullOrEmpty
        Test-Path -LiteralPath $rev.Snapshot | Should -BeTrue    # the revert itself can be undone
    }
    It 'restores a previous mode exactly' {
        Add-MpRuleFixture 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' 2
        $r = Invoke-IgwtAsrChange -RuleMode @{ 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Warn' }
        Get-MpRuleCode 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' | Should -Be 6
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        Get-MpRuleCode 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' | Should -Be 2
    }
    It 'refuses Warn where unsupported, explicit Off, server-only rules and policy-managed rules' {
        $backups = Get-IgwtDataPath -Kind Backups
        $before = @(Get-ChildItem -LiteralPath $backups -Filter 'snapshot-*' -ErrorAction SilentlyContinue).Count
        { Invoke-IgwtAsrChange -RuleMode @{ lsass = 'Warn' } } | Should -Throw '*does not support Warn*'
        { Invoke-IgwtAsrChange -RuleMode @{ lsass = 'Off' } } | Should -Throw '*explicit Off*'
        { Invoke-IgwtAsrChange -RuleMode @{ 'webshell-servers' = 'Audit' } } | Should -Throw '*Exchange servers only*'
        $null = New-Item -Path "$script:AsrKey\Rules" -Force
        $null = New-ItemProperty -Path "$script:AsrKey\Rules" -Name '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' -Value '1' -PropertyType String
        { Invoke-IgwtAsrChange -RuleMode @{ lsass = 'Audit' } } | Should -Throw '*managed by GroupPolicy*'
        Should -Invoke Add-MpPreference -ModuleName iGWindowsTuner -Times 0 -Exactly
        @(Get-ChildItem -LiteralPath $backups -Filter 'snapshot-*' -ErrorAction SilentlyContinue).Count | Should -Be $before   # nothing was written
    }
    It 'refuses unknown rules and does nothing when Defender is not active' {
        { Invoke-IgwtAsrChange -RuleMode @{ 'no-such-rule' = 'Block' } } | Should -Throw '*Unknown ASR rule*'
        $script:MpActive = $false
        { Invoke-IgwtAsrChange -Recommended } | Should -Throw '*not the active antivirus*'
    }
    It 'applies recommendations without lowering any rule' {
        Add-MpRuleFixture '01443614-cd74-433a-b99e-2ecdc07bfc25' 1
        $r = Invoke-IgwtAsrChange -Recommended
        $r.Changes | Should -Be 17   # 19 rules minus the server-only rule and the one already above its recommendation
        Get-MpRuleCode '01443614-cd74-433a-b99e-2ecdc07bfc25' | Should -Be 1
        Get-MpRuleCode '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' | Should -Be 1
        Get-MpRuleCode 'd1e49aac-8f56-4280-b9ba-993a6d77406c' | Should -Be 2
        Get-MpRuleCode 'a8f5898e-1dc8-49a9-9878-85004b8a61e6' | Should -BeNullOrEmpty
        (Invoke-IgwtAsrChange -Recommended).Changes | Should -Be 0
    }
    It 'writes per-rule exclusions to the Group Policy registry settings and reverts them completely' {
        $r = Invoke-IgwtAsrChange -ExclusionRule 'copied-system-tools' -AddExclusion 'D:\Games\A\a.exe', '%ProgramFiles%\Vendor\tool.exe'
        $r.Changes | Should -Be 1
        (Get-ItemProperty -LiteralPath "$script:AsrKey\ASROnlyPerRuleExclusions").'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' | Should -Be 'D:\Games\A\a.exe>%ProgramFiles%\Vendor\tool.exe'
        (Get-ItemProperty -LiteralPath $script:AsrKey).ExploitGuard_ASR_ASROnlyPerRuleExclusions | Should -Be 1
        $r2 = Invoke-IgwtAsrChange -ExclusionRule 'copied-system-tools' -RemoveExclusion 'D:\Games\A\a.exe'
        (Get-ItemProperty -LiteralPath "$script:AsrKey\ASROnlyPerRuleExclusions").'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' | Should -Be '%ProgramFiles%\Vendor\tool.exe'
        $null = Invoke-IgwtRevert -SnapshotPath $r2.Snapshot
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        Test-Path -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Policies' | Should -BeFalse   # keys created by iG Windows Tuner are removed again
    }
    It 'keeps the policy switch while another rule still has per-rule exclusions' {
        $a = Invoke-IgwtAsrChange -ExclusionRule 'copied-system-tools' -AddExclusion 'D:\Games\A\a.exe'
        $null = Invoke-IgwtAsrChange -ExclusionRule 'ransomware' -AddExclusion 'D:\Games\B\b.exe'
        $null = Invoke-IgwtRevert -SnapshotPath $a.Snapshot
        (Get-ItemProperty -LiteralPath $script:AsrKey).ExploitGuard_ASR_ASROnlyPerRuleExclusions | Should -Be 1
        (Get-ItemProperty -LiteralPath "$script:AsrKey\ASROnlyPerRuleExclusions").'c1db55ab-c21a-4637-bb3f-a12568109d35' | Should -Be 'D:\Games\B\b.exe'
    }
    It 'adds and reverts global ASR-only exclusions through Defender' {
        $script:Mp.AttackSurfaceReductionOnlyExclusions = @('D:\Keep\keep.exe')
        $r = Invoke-IgwtAsrChange -AddExclusion 'D:\Games\A\a.exe'
        @($script:Mp.AttackSurfaceReductionOnlyExclusions) | Should -Be @('D:\Keep\keep.exe', 'D:\Games\A\a.exe')
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        @($script:Mp.AttackSurfaceReductionOnlyExclusions) | Should -Be @('D:\Keep\keep.exe')
    }
    It 'refuses an invalid exclusion before changing anything' {
        { Invoke-IgwtAsrChange -RuleMode @{ 'psexec-wmi' = 'Audit' } -AddExclusion 'C:\Windows\System32\cmd.exe' } | Should -Throw '*refused*'
        Should -Invoke Add-MpPreference -ModuleName iGWindowsTuner -Times 0 -Exactly
        Get-MpRuleCode 'd1e49aac-8f56-4280-b9ba-993a6d77406c' | Should -BeNullOrEmpty
    }
    It 'refuses to remove global exclusions it cannot read' {
        $script:Mp.AttackSurfaceReductionOnlyExclusions = @('N/A: Must be an administrator to view exclusions')
        { Invoke-IgwtAsrChange -RemoveExclusion 'D:\Games\A\a.exe' } | Should -Throw '*cannot be read*'
    }
    It 'validates snapshot entries on revert (unknown rule GUIDs are not applied)' {
        $r = Invoke-IgwtAsrChange -RuleMode @{ 'psexec-wmi' = 'Audit' }
        $doc = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $doc.entries[0].actions[0].data.id = '00000000-0000-0000-0000-000000000000'
        Set-Content -LiteralPath $r.Snapshot -Value ($doc | ConvertTo-Json -Depth 20) -Encoding UTF8
        $rev = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        @($rev.Results)[0].Result | Should -Be 'Failed'
        Get-MpRuleCode 'd1e49aac-8f56-4280-b9ba-993a6d77406c' | Should -Be 2
    }
    It 'does nothing for a no-op request' {
        Add-MpRuleFixture 'd1e49aac-8f56-4280-b9ba-993a6d77406c' 2
        $r = Invoke-IgwtAsrChange -RuleMode @{ 'psexec-wmi' = 'Audit' }
        $r.Changes | Should -Be 0; $r.Snapshot | Should -BeNullOrEmpty
    }
}

Describe 'ASR audit view (read-only)' {
    BeforeAll {
        function Get-TestEvent([object[]]$Spec) {
            # Spec: event id, action, feature, rule GUID, path, process, hours ago
            [pscustomobject]@{ Time = (Get-Date).AddHours(-[int]$Spec[6]); EventId = [int]$Spec[0]; Feature = $Spec[2]; Action = $Spec[1]; RuleId = $Spec[3]; Path = $Spec[4]; Process = $Spec[5]; User = 'PC\me'; OldValue = ''; NewValue = ''; Detail = '' }
        }
        function Get-TestStatus([hashtable]$Modes) {
            [pscustomobject]@{ Rules = @(Get-IgwtAsrCatalog | ForEach-Object {
                        $m = 'NotConfigured'; if ($Modes.ContainsKey([string]$_.key)) { $m = $Modes[[string]$_.key] }
                        [pscustomobject]@{ Id = ([string]$_.id).ToLowerInvariant(); Key = [string]$_.key; Mode = $m }
                    }) }
        }
    }

    It 'parses Defender event XML into fields' {
        $xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1121</EventID></System><EventData>" +
        "<Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='ID'>C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB</Data><Data Name='Path'>D:\Games\A\a.exe</Data>" +
        "<Data Name='Process Name'>C:\Windows\explorer.exe</Data><Data Name='User'>PC\me</Data><Data Name='Target Commandline'>secret</Data><Data Name='RuleType'>x</Data></EventData></Event>"
        $ev = [pscustomobject]@{ Id = 1121; TimeCreated = (Get-Date); XmlText = $xml }
        $ev | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.XmlText }
        $p = InModuleScope iGWindowsTuner -Parameters @{ E = $ev } { param($E) ConvertFrom-IgwtProtectionEvent -WinEvent $E }
        $p.Feature | Should -Be 'ASR'; $p.Action | Should -Be 'Blocked'
        $p.RuleId | Should -Be 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'
        $p.Path | Should -Be 'D:\Games\A\a.exe'; $p.Process | Should -Be 'C:\Windows\explorer.exe'
        $p.Detail | Should -Not -Match 'secret'
    }
    It 'treats an empty log as readable and an access error as not readable' {
        Mock Get-WinEvent -ModuleName iGWindowsTuner {
            $er = New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception 'No events were found that match the specified selection criteria.'), 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null)
            throw $er
        }
        $e = Get-IgwtProtectionEvents -Days 7
        $e.Readable | Should -BeTrue; @($e.Events).Count | Should -Be 0
        Mock Get-WinEvent -ModuleName iGWindowsTuner { throw (New-Object System.UnauthorizedAccessException 'Attempted to perform an unauthorized operation.') }
        $e = Get-IgwtProtectionEvents -Days 7
        $e.Readable | Should -BeFalse; $e.Error | Should -Match 'administrator'
    }
    It 'groups events by rule and program and suggests the next step' {
        $events = [pscustomobject]@{ Readable = $true; Error = ''; Days = 14; LogStart = (Get-Date).AddDays(-20); Truncated = $false; Events = @(
                Get-TestEvent -Spec @(1121, 'Blocked', 'ASR', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'C:\Windows\System32\svchost.exe', 'C:\Windows\System32\lsass.exe', 1)
                Get-TestEvent -Spec @(1121, 'Blocked', 'ASR', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'C:\Windows\System32\svchost.exe', 'C:\Windows\System32\lsass.exe', 2)
                Get-TestEvent -Spec @(1122, 'Audited', 'ASR', 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb', 'D:\Games\A\a.exe', 'C:\Windows\explorer.exe', 1)
                Get-TestEvent -Spec @(1122, 'Audited', 'ASR', 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb', (Join-Path $env:USERPROFILE 'Downloads\tool.exe'), 'C:\Windows\explorer.exe', 1)
                Get-TestEvent -Spec @(1121, 'Blocked', 'ASR', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', 'C:\Windows\System32\rundll32.exe', 'C:\Windows\explorer.exe', 1)
                Get-TestEvent -Spec @(1123, 'Blocked', 'ControlledFolderAccess', '', 'C:\Users\me\Documents\save.dat', 'D:\Games\A\a.exe', 1)
                Get-TestEvent -Spec @(1126, 'Blocked', 'NetworkProtection', '', '', 'C:\Program Files\App\app.exe', 1)
            )
        }
        $status = Get-TestStatus @{ lsass = 'Block'; 'copied-system-tools' = 'Audit'; 'usb-untrusted' = 'Block'; 'office-child-processes' = 'Audit'; 'prevalence-age' = 'Audit' }
        $a = Get-IgwtAsrAudit -Events $events -Status $status
        $a.Readable | Should -BeTrue
        $a.CoverageDays | Should -Be 14
        $lsass = @($a.Rules | Where-Object { $_.Key -eq 'lsass' })[0]
        $lsass.Blocked | Should -Be 2; @($lsass.Programs).Count | Should -Be 1
        @($lsass.Programs)[0].Suggestion | Should -Be 'Ignore'
        $lsass.Recommendation | Should -Be 'None'
        $cst = @($a.Rules | Where-Object { $_.Key -eq 'copied-system-tools' })[0]
        $cst.Recommendation | Should -Be 'ReviewPrograms'
        $game = @($cst.Programs | Where-Object { $_.Path -eq 'D:\Games\A\a.exe' })[0]
        $game.Suggestion | Should -Be 'ExcludeIfTrusted'; $game.Exclusion | Should -Be 'D:\Games\A\a.exe'
        @($cst.Programs | Where-Object { $_.Path -like '*Downloads*' })[0].Suggestion | Should -Be 'Review'
        $usb = @($a.Rules | Where-Object { $_.Key -eq 'usb-untrusted' })[0]
        $usb.Recommendation | Should -Be 'ReviewBlocks'
        @($usb.Programs)[0].Exclusion | Should -BeNullOrEmpty          # Windows paths are never suggested
        (@($a.Rules | Where-Object { $_.Key -eq 'office-child-processes' })[0]).Recommendation | Should -Be 'PromoteToBlock'
        (@($a.Rules | Where-Object { $_.Key -eq 'prevalence-age' })[0]).Recommendation | Should -Be 'PromoteToWarn'
        (@($a.Rules | Where-Object { $_.Key -eq 'psexec-wmi' })[0]).Recommendation | Should -Be 'EnableAudit'
        (@($a.Rules | Where-Object { $_.Key -eq 'webshell-servers' })[0]).Recommendation | Should -Be 'None'
        @($a.ControlledFolderAccess)[0].Process | Should -Be 'D:\Games\A\a.exe'
        @($a.NetworkProtection).Count | Should -Be 1
        $a.Totals.AsrBlocked | Should -Be 3; $a.Totals.AsrAudited | Should -Be 2
    }
    It 'keeps auditing while the log covers less than a week' {
        $events = [pscustomobject]@{ Readable = $true; Error = ''; Days = 14; LogStart = (Get-Date).AddDays(-3); Truncated = $false; Events = @() }
        $a = Get-IgwtAsrAudit -Events $events -Status (Get-TestStatus @{ 'office-child-processes' = 'Audit' })
        (@($a.Rules | Where-Object { $_.Key -eq 'office-child-processes' })[0]).Recommendation | Should -Be 'KeepAuditing'
    }
    It 'renders the audit view as text' {
        $events = [pscustomobject]@{ Readable = $false; Error = 'Reading the Defender log needs administrator rights on this PC.'; Days = 14; LogStart = $null; Truncated = $false; Events = @() }
        Format-IgwtAsrAudit -Audit (Get-IgwtAsrAudit -Events $events -Status (Get-TestStatus @{})) | Should -Match 'administrator'
    }
}

Describe 'Security score' {
    BeforeAll {
        function Get-TestFacts {
            $states = @{}
            foreach ($c in (Get-IgwtSecurityCheckDefinitions | Where-Object { $_.Fix -eq 'Tweak' })) { $states[[string]$c.Target] = 'On' }
            [pscustomobject]@{
                Defender = [pscustomobject]@{ Active = $true; RealTime = $true; Tamper = $true; SignatureAge = 0; Mode = 'Normal' }
                TweakStates = $states; SecureBoot = $true
                Tpm = [pscustomobject]@{ Present = $true; Ready = $true; Version20 = $true; Detail = 'TPM 2.0' }
                DeviceGuard = [pscustomobject]@{ Available = $true; CredentialGuardRunning = $false }
                Asr = [pscustomobject]@{ StandardInBlock = 3; StandardTotal = 3; BelowRecommendation = 0 }
                BitLocker = [pscustomobject]@{ On = $true; Text = 'On' }
                Accounts = [pscustomobject]@{ Readable = $true; Findings = @() }
                SmartAppControl = 1; Edition = 'Professional'
            }
        }
    }
    It 'gives every check a hint (140 characters or fewer), a description and a known fix route' {
        $ids = @((Get-IgwtCatalog) | ForEach-Object { $_.id })
        foreach ($c in Get-IgwtSecurityCheckDefinitions) {
            ([string]$c.Hint).Length | Should -BeLessOrEqual 140 -Because $c.Id
            ([string]$c.Hint).Trim().Length | Should -BeGreaterThan 0 -Because $c.Id
            ([string]$c.Description).Length | Should -BeGreaterOrEqual 40 -Because $c.Id
            $c.Fix | Should -BeIn @('Tweak', 'AsrCenter', 'WindowsSecurity', 'Firmware', 'Settings', 'None')
            if ($c.Fix -eq 'Tweak') { $c.Target | Should -BeIn $ids }
        }
    }
    It 'scores a fully protected PC 100 (Strong)' {
        $s = ConvertTo-IgwtSecurityScore -Facts (Get-TestFacts)
        $s.Score | Should -Be 100; $s.Grade | Should -Be 'Strong'; @($s.ToFix) | Should -BeNullOrEmpty
        @($s.Checks | Where-Object { $_.Id -eq 'smartAppControl' })[0].Counted | Should -BeFalse
    }
    It 'weights failures, halves warnings and routes each one to its fix' {
        $f = Get-TestFacts
        $f.Defender.RealTime = $false
        $f.TweakStates['sec.smb-hardening'] = 'Partial'
        $f.Asr.BelowRecommendation = 6
        $s = ConvertTo-IgwtSecurityScore -Facts $f
        $s.Score | Should -BeLessThan 90
        @($s.ToFix)[0].Id | Should -Be 'defender'
        (@($s.Checks | Where-Object { $_.Id -eq 'smb' })[0]).Earned | Should -Be 1.5
        (@($s.ToFix | Where-Object { $_.Id -eq 'asrCoverage' })[0]).Fix | Should -Be 'AsrCenter'
        Format-IgwtSecurityScore -Score $s | Should -Match 'fix: catalog item sec.smb-hardening'
    }
    It 'leaves not-applicable, managed and unreadable checks out of the score' {
        $f = Get-TestFacts
        $f.TweakStates['sec.firewall-on'] = 'ManagedByPolicy'
        $f.TweakStates['sec.remote-access-off'] = 'NotApplicable'
        $f.SecureBoot = $null
        $s = ConvertTo-IgwtSecurityScore -Facts $f
        $s.Score | Should -Be 100
        (@($s.Checks | Where-Object { $_.Id -eq 'firewall' })[0]).Status | Should -Be 'Managed'
        (@($s.Checks | Where-Object { $_.Id -eq 'secureBoot' })[0]).Counted | Should -BeFalse
    }
    It 'treats ASR checks as not applicable when Defender is not the active antivirus' {
        $f = Get-TestFacts
        $f.Defender.Active = $false
        $s = ConvertTo-IgwtSecurityScore -Facts $f
        (@($s.Checks | Where-Object { $_.Id -eq 'asrStandard' })[0]).Status | Should -Be 'NotApplicable'
        (@($s.Checks | Where-Object { $_.Id -eq 'defender' })[0]).Status | Should -Be 'Fail'
    }
}

Describe 'Local accounts audit (read-only)' {
    It 'reports Guest, the built-in Administrator, missing password requirements and extra administrators' {
        Mock Get-LocalUser -ModuleName iGWindowsTuner {
            @(
                [pscustomobject]@{ Name = 'Administrator'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' }; PasswordRequired = $true; PrincipalSource = 'Local' }
                [pscustomobject]@{ Name = 'Guest'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-501' }; PasswordRequired = $false; PrincipalSource = 'Local' }
                [pscustomobject]@{ Name = 'gamer'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' }; PasswordRequired = $true; PrincipalSource = 'MicrosoftAccount' }
                [pscustomobject]@{ Name = 'kid'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1002' }; PasswordRequired = $false; PrincipalSource = 'Local' }
            )
        }
        Mock Get-LocalGroupMember -ModuleName iGWindowsTuner { @([pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' } }, [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' } }) }
        $a = Get-IgwtLocalAccountAudit
        $a.Readable | Should -BeTrue; $a.AdminsKnown | Should -BeTrue
        @($a.Findings | ForEach-Object { $_.Id } | Sort-Object) | Should -Be @('adminEnabled', 'guestEnabled', 'manyAdmins', 'noPasswordRequired')
        @($a.Findings | Where-Object { $_.Id -eq 'noPasswordRequired' })[0].Account | Should -Be 'kid'
    }
    It 'still works when the Administrators group cannot be listed' {
        Mock Get-LocalUser -ModuleName iGWindowsTuner { @([pscustomobject]@{ Name = 'gamer'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' }; PasswordRequired = $true; PrincipalSource = 'Local' }) }
        Mock Get-LocalGroupMember -ModuleName iGWindowsTuner { throw 'Failed to compare two elements in the array.' }
        $a = Get-IgwtLocalAccountAudit
        $a.Readable | Should -BeTrue; $a.AdminsKnown | Should -BeFalse
        @($a.Accounts)[0].IsAdmin | Should -BeNullOrEmpty
    }
}

Describe 'Network surface (read-only)' {
    It 'merges IPv4/IPv6 listeners, classifies scope and names well-known ports' {
        Mock Get-NetTCPConnection -ModuleName iGWindowsTuner {
            @(
                [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 445; OwningProcess = 4 }
                [pscustomobject]@{ LocalAddress = '::'; LocalPort = 445; OwningProcess = 4 }
                [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 9000; OwningProcess = 200 }
                [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 49668; OwningProcess = 300 }
            )
        }
        Mock Get-NetUDPEndpoint -ModuleName iGWindowsTuner { @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5355; OwningProcess = 100 }, [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 60000; OwningProcess = 100 }) }
        Mock Get-Process -ModuleName iGWindowsTuner { @([pscustomobject]@{ Id = 100; ProcessName = 'svchost'; Path = 'C:\Windows\System32\svchost.exe' }, [pscustomobject]@{ Id = 200; ProcessName = 'tool'; Path = 'D:\Tool\tool.exe' }, [pscustomobject]@{ Id = 300; ProcessName = 'spoolsv'; Path = 'C:\Windows\System32\spoolsv.exe' }) }
        Mock Get-CimInstance -ModuleName iGWindowsTuner -ParameterFilter { $ClassName -eq 'Win32_Service' } { @([pscustomobject]@{ Name = 'Dnscache'; ProcessId = 100 }) }
        $n = Get-IgwtNetworkSurface
        $smb = @($n.Entries | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq 445 })
        $smb.Count | Should -Be 1
        $smb[0].Scope | Should -Be 'AllInterfaces'; $smb[0].Process | Should -Be 'System'; $smb[0].Fix | Should -Be 'sec.smb-hardening'
        @($n.Entries | Where-Object { $_.Port -eq 9000 })[0].Scope | Should -Be 'Loopback'
        @($n.Entries | Where-Object { $_.Port -eq 5355 })[0].Fix | Should -Be 'sec.llmnr-off'
        @($n.Entries | Where-Object { $_.Port -eq 5355 })[0].Services | Should -Be @('Dnscache')
        @($n.Entries | Where-Object { $_.Port -eq 49668 })[0].Fix | Should -Be 'sec.print-spooler-no-inbound'
        @($n.Entries | Where-Object { $_.Port -eq 60000 }) | Should -BeNullOrEmpty     # ephemeral UDP client sockets are left out
        $n.LoopbackCount | Should -Be 1
    }
}

Describe 'Security catalog items' {
    BeforeAll { $script:Cat = @(Get-IgwtCatalog) }
    It 'adds the security module items with sources and no security-reducing effect' {
        foreach ($id in 'sec.exploit-protection-defaults', 'sec.wdigest-off', 'sec.restrict-anonymous', 'sec.ntlmv2-only', 'sec.wsh-off', 'sec.lolbin-outbound-block', 'sec.print-spooler-no-inbound', 'sec.print-spooler-off') {
            $t = @($script:Cat | Where-Object { $_.id -eq $id })[0]
            $t | Should -Not -BeNullOrEmpty -Because $id
            $t.impact.security | Should -Be '+' -Because $id
            $t.antiCheat | Should -Be 'safe' -Because $id
            @($t.evidence.sources).Count | Should -BeGreaterThan 0 -Because $id
        }
    }
    It 'only creates owned outbound Block rules for Windows script and download tools' {
        $t = @($script:Cat | Where-Object { $_.id -eq 'sec.lolbin-outbound-block' })[0]
        @($t.actions).Count | Should -Be 10
        foreach ($a in $t.actions) {
            $a.type | Should -Be 'firewallRule'; $a.action | Should -Be 'Block'; $a.direction | Should -Be 'Outbound'
            $a.rule | Should -Match '^iGWindowsTuner-Block-Out-'
            $a.program | Should -Match '^%SystemRoot%\\(System32|SysWOW64)\\(mshta|wscript|cscript|regsvr32|certutil)\.exe$'
        }
    }
    It 'keeps exploit protection items repair-only (use default counts as on, never OFF)' {
        $t = @($script:Cat | Where-Object { $_.id -eq 'sec.exploit-protection-defaults' })[0]
        foreach ($a in $t.actions) { $a.type | Should -Be 'exploitSystem'; $a.on | Should -Be 'ON'; @($a.equivalentOn) | Should -Be @('NOTSET') }
        @($t.actions | ForEach-Object { $_.mitigation }) | Should -Not -Contain 'ForceRelocateImages'
    }
}

Describe 'ASR command line (argument checks only)' {
    It 'rejects ASR options without -Asr and -Days without -AsrAudit' {
        $script = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -AsrMode Block -NoGui
        $LASTEXITCODE | Should -Be 2
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Days 3 -NoGui
        $LASTEXITCODE | Should -Be 2
    }
}
