# Security Settings Manager, B7 (DECISIONS SM20, SM21, SM26): the 'localPolicy' provider and the
# module step helper. Registry.pol and gpt.ini live in TestDrive; gpupdate is mocked.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Admx = Join-Path $PSScriptRoot 'fixtures\secsettings\admx'
    $script:GpoRoot = Join-Path $TestDrive 'GroupPolicy'
    InModuleScope iGWindowsTuner -Parameters @{ A = $script:Admx; R = $script:GpoRoot } { param($A, $R) $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtAdmxCache = $null; $script:IgwtSecSettingsData = $null }
    Mock -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate { }
    function Invoke-PolStep([string]$Policy, [string]$State, [hashtable]$Values = @{}, [string]$Class = 'Machine') {
        InModuleScope iGWindowsTuner -Parameters @{ N = $Policy; S = $State; V = $Values; K = $Class } {
            param($N, $S, $V, $K)
            $p = @((Get-IgwtAdmxCatalog -NoCache).Policies | Where-Object { $_.Name -eq $N })[0]
            $target = New-IgwtSecSettingPolTarget -Policy $p -Class $K
            $r = Resolve-IgwtSecSettingPolTarget -Target $target
            $cur = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $K)).Entries)
            $desired = ConvertTo-IgwtSecSettingPolDesired -Resolved $r -CurrentEntries $cur -Ops @(Get-IgwtPolicyRegistryOps -Policy $p -State $S -Values $V)
            $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'secSettings' }) -Title "test $N" -Confirm:$false
            try { $step = Invoke-IgwtChangeStep -Session $session -Target $target -Desired $desired -Group 'secsettings' -Confirm:$false }
            finally { Complete-IgwtChangeSession -Session $session }
            [pscustomobject]@{ Step = $step; Session = $session; Target = $target }
        }
    }
    function Get-PolEntries([string]$Class = 'Machine') { @(InModuleScope iGWindowsTuner -Parameters @{ K = $Class } { param($K) (Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $K)).Entries }) }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.AdmxFolders = $null; $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtAdmxCache = $null } }

Describe 'Writing local policy through the journal (SM20, SM21)' {
    BeforeEach { Remove-Item -Path $script:GpoRoot -Recurse -Force -ErrorAction SilentlyContinue }
    It 'writes the owned entries, reads them back, and updates gpt.ini like gpedit' {
        $s = Invoke-PolStep 'LoggingSwitch' 'Enabled'
        $s.Step.Result | Should -Be 'Committed'
        @(Get-PolEntries | ForEach-Object { "$($_.ValueName)=$($_.Value)" }) | Should -Be @('EnableAuditLogging=1')
        $gpt = Get-Content -LiteralPath (Join-Path $script:GpoRoot 'gpt.ini') -Raw
        $gpt | Should -Match 'Version=1\b'
        $gpt | Should -Match 'gPCMachineExtensionNames=\[\{35378EAC-683F-11D2-A89A-00C04FBBCFA2\}\{D02B1F72-3407-48AE-BA88-E8213C6761F1\}\]'
    }
    It 'keeps entries of other policies, and adds the client extension pair' {
        $null = Invoke-PolStep 'LoggingSwitch' 'Enabled'
        $null = Invoke-PolStep 'AllKinds' 'Disabled'
        @(Get-PolEntries | Where-Object ValueName -EQ 'EnableAuditLogging') | Should -Not -BeNullOrEmpty
        (Get-Content -LiteralPath (Join-Path $script:GpoRoot 'gpt.ini') -Raw) | Should -Match '\{827D319E-6EAC-11D2-A4EA-00C04F79F83A\}\{D02B1F72-3407-48AE-BA88-E8213C6761F1\}'
    }
    It 'uses the user tool GUID and the user version half for a User-class policy' {
        InModuleScope iGWindowsTuner {
            $p = [pscustomobject]@{ Id = 'X:UserPol'; Name = 'UserPol'; Class = 'User'; Key = 'Software\Policies\Contoso\UserSide'; ValueName = 'On'; EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @(); Elements = @(); ClientExtension = '' }
            $target = New-IgwtSecSettingPolTarget -Policy $p -Class User
            $r = Resolve-IgwtSecSettingPolTarget -Target $target
            $d = ConvertTo-IgwtSecSettingPolDesired -Resolved $r -Ops @(Get-IgwtPolicyRegistryOps -Policy $p -State Enabled)
            $null = Set-IgwtSecSettingPolEntries -Resolved $r -Desired $d -Confirm:$false
        }
        $gpt = Get-Content -LiteralPath (Join-Path $script:GpoRoot 'gpt.ini') -Raw
        $gpt | Should -Match 'Version=65536\b'
        $gpt | Should -Match 'gPCUserExtensionNames=\[\{35378EAC-683F-11D2-A89A-00C04FBBCFA2\}\{D02B1F73-3407-48AE-BA88-E8213C6761F1\}\]'
    }
    It 'undoes a change exactly through the revert plan of its session' {
        $null = Invoke-PolStep 'LoggingSwitch' 'Disabled'
        $s = Invoke-PolStep 'LoggingSwitch' 'Enabled'
        @(Get-PolEntries | ForEach-Object Value) | Should -Be @(1)
        InModuleScope iGWindowsTuner -Parameters @{ S = $s.Session.Id } { param($S) $plan = @(Get-IgwtRevertPlan -SessionId $S); $plan[0].Status | Should -Be 'Ready'; $null = Invoke-IgwtJournalRevert -Plan $plan -Confirm:$false }
        @(Get-PolEntries | ForEach-Object Value) | Should -Be @(0)
    }
}

Describe 'The provider guards itself (SM20)' {
    BeforeEach { Remove-Item -Path $script:GpoRoot -Recurse -Force -ErrorAction SilentlyContinue }
    It 'refuses an entry outside the owned set, a hard-blocked key and a UEFI-lock value, and writes nothing' {
        InModuleScope iGWindowsTuner {
            $p = @((Get-IgwtAdmxCatalog -NoCache).Policies | Where-Object { $_.Name -eq 'LoggingSwitch' })[0]
            $r = Resolve-IgwtSecSettingPolTarget -Target (New-IgwtSecSettingPolTarget -Policy $p -Class Machine)
            $other = [ordered]@{ entries = @([ordered]@{ key = 'Software\Policies\Contoso\Other'; valueName = 'Other'; type = 4; dataHex = '01000000' }) }
            { Set-IgwtSecSettingPolEntries -Resolved $r -Desired $other -Confirm:$false } | Should -Throw '*is not part of*'
            $ex = [pscustomobject]@{ Id = 'X:Ex'; Class = 'Machine'; Key = 'Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'; ValueName = 'C:\Games'; EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @(); Elements = @(); ClientExtension = '' }
            $rx = Resolve-IgwtSecSettingPolTarget -Target (New-IgwtSecSettingPolTarget -Policy $ex -Class Machine)
            { Set-IgwtSecSettingPolEntries -Resolved $rx -Desired ([ordered]@{ entries = @([ordered]@{ key = $ex.Key; valueName = 'C:\Games'; type = 1; dataHex = '3000' + '0000' }) }) -Confirm:$false } | Should -Throw '*never written*'
            $vbs = @((Get-IgwtAdmxCatalog -NoCache).Policies | Where-Object { $_.Name -eq 'VbsShaped' })[0]
            $rv = Resolve-IgwtSecSettingPolTarget -Target (New-IgwtSecSettingPolTarget -Policy $vbs -Class Machine)
            $lock = ConvertTo-IgwtSecSettingPolDesired -Resolved $rv -Ops @(Get-IgwtPolicyRegistryOps -Policy $vbs -State Enabled -Values @{ HvciDrop = 1; FakeDrop = 0 })
            { Set-IgwtSecSettingPolEntries -Resolved $rv -Desired $lock -Confirm:$false } | Should -Throw '*UEFI lock*'
        }
        Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
    }
    It 'resolves only targets whose key matches the owned set and whose keys are below Policies' {
        InModuleScope iGWindowsTuner {
            $p = @((Get-IgwtAdmxCatalog -NoCache).Policies | Where-Object { $_.Name -eq 'LoggingSwitch' })[0]
            $t = New-IgwtSecSettingPolTarget -Policy $p -Class Machine
            $t.owned = @('pair:software\policies\contoso\log|enableauditlogging', 'pair:software\policies\contoso\log|extra')
            { Resolve-IgwtSecSettingPolTarget -Target $t } | Should -Throw '*does not match*'
            $bad = [ordered]@{ provider = 'localPolicy'; class = 'Machine'; policyId = 'X:Bad'; owned = @('pair:system\currentcontrolset\control\lsa|runasppl'); cse = '' }
            $bad.key = "localPolicy|Machine|X:Bad|$((Get-IgwtJournalHash -Line 'pair:system\currentcontrolset\control\lsa|runasppl').Substring(0, 16))"
            { Resolve-IgwtSecSettingPolTarget -Target $bad } | Should -Throw '*outside the Policies keys*'
        }
    }
}

Describe 'Module step helper (SM26)' {
    It 'keeps the existing key format, and -Detail gives different keys for different batches' {
        InModuleScope iGWindowsTuner {
            $script:IgwtModuleOperations['Test-SecDummyWriter'] = ''
            $keys = New-Object System.Collections.Generic.List[string]
            Mock Invoke-IgwtChangeStep { $keys.Add([string]$Target['key']); [pscustomobject]@{ Result = 'Committed' } }
            $s = [pscustomobject]@{ Id = 's1'; Step = 0 }
            $null = Invoke-IgwtModuleOperationStep -Session $s -Command 'Test-SecDummyWriter' -Parameters @{ A = 1 } -Group g
            $expect = 'module|Test-SecDummyWriter|' + (Get-IgwtJournalHash -Line (ConvertTo-IgwtCanonicalJson (ConvertTo-IgwtJournalParameters -Parameters @{ A = 1 }))).Substring(0, 16)
            $keys[0] | Should -Be $expect
            $null = Invoke-IgwtModuleOperationStep -Session $s -Command 'Test-SecDummyWriter' -Parameters @{ A = 1 } -Group g -Detail 'Registry Values\NoLMHash=4,1'
            $null = Invoke-IgwtModuleOperationStep -Session $s -Command 'Test-SecDummyWriter' -Parameters @{ A = 1 } -Group g -Detail 'Registry Values\NoLMHash=4,0'
            $keys[1] | Should -Not -Be $keys[2]
            $script:IgwtModuleOperations.Remove('Test-SecDummyWriter')
        }
    }
}
