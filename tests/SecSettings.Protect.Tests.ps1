# Security Settings Manager, B3 (DECISIONS SM13, SM14, SM15, SM18, SM30): pure validation and the
# protected set. Synthetic VBS-shaped fixture, in-memory Registry.pol entries, mocked identities.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Admx = Join-Path $PSScriptRoot 'fixtures\secsettings\admx'
    InModuleScope iGWindowsTuner -Parameters @{ A = $script:Admx } { param($A) $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtAdmxCache = $null; $script:IgwtSecSettingsData = $null }
    $script:Cat = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force -NoCache }
    $script:Vbs = @($script:Cat.Policies | Where-Object { $_.Name -eq 'VbsShaped' })[0]
    function Get-Ops($Policy, [string]$State, [hashtable]$Values = @{}) { InModuleScope iGWindowsTuner -Parameters @{ P = $Policy; S = $State; V = $Values } { param($P, $S, $V) @(Get-IgwtPolicyRegistryOps -Policy $P -State $S -Values $V) } }
    function Get-Entries($Ops) { InModuleScope iGWindowsTuner -Parameters @{ O = $Ops } { param($O) @(Update-IgwtPolEntries -Entries @() -Ops $O) } }
    function Test-Lower($Ops, $Current) { @(InModuleScope iGWindowsTuner -Parameters @{ O = $Ops; C = $Current } { param($O, $C) Test-IgwtSecSettingOpsLowerProtection -Class Machine -Ops $O -CurrentEntries $C }) }
    function Get-Spec($Policy) { InModuleScope iGWindowsTuner -Parameters @{ P = $Policy } { param($P) ConvertTo-IgwtSecSettingValueSpec -SourceKind admx -Definition $P } }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

Describe 'Lowering protection by removing a value (SM13)' {
    BeforeAll { $script:OnNow = Get-Entries (Get-Ops $script:Vbs 'Enabled' @{ HvciDrop = 2; FakeDrop = 0 }) }
    It 'refuses Disabled and Not configured while VBS is on by local policy' {
        Test-Lower (Get-Ops $script:Vbs 'Disabled') $script:OnNow | Should -Not -BeNullOrEmpty
        Test-Lower (Get-Ops $script:Vbs 'NotConfigured') $script:OnNow | Should -Not -BeNullOrEmpty
    }
    It 'allows the same change when nothing protective is set, and an unchanged value' {
        Test-Lower (Get-Ops $script:Vbs 'NotConfigured') @() | Should -BeNullOrEmpty
        Test-Lower (Get-Ops $script:Vbs 'Enabled' @{ HvciDrop = 2; FakeDrop = 0 }) $script:OnNow | Should -BeNullOrEmpty
    }
    It 'refuses the UEFI-lock choice as a new value' {
        Test-Lower (Get-Ops $script:Vbs 'Enabled' @{ HvciDrop = 1; FakeDrop = 0 }) $script:OnNow | Should -Match 'UEFI lock'
    }
}

Describe 'UEFI-lock tuples (SM18)' {
    It 'refuses RunAsPPL=1 by key and value name, allows RunAsPPL=2 and the unlocked memory integrity route' {
        InModuleScope iGWindowsTuner {
            Get-IgwtSecSettingOpRefusal -Class Machine -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\Microsoft\Windows\System'; ValueName = 'RunAsPPL'; Value = 1 }) | Should -Match 'UEFI lock'
            Get-IgwtSecSettingOpRefusal -Class Machine -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\Microsoft\Windows\System'; ValueName = 'RunAsPPL'; Value = 2 }) | Should -BeNullOrEmpty
            Get-IgwtSecSettingOpRefusal -Class Machine -Op ([pscustomobject]@{ Op = 'Set'; Key = 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'; ValueName = 'Enabled'; Value = 1 }) | Should -BeNullOrEmpty
            Get-IgwtSecSettingOpRefusal -Class Machine -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Contoso'; ValueName = 'HypervisorEnforcedCodeIntegrity'; Value = 1 }) | Should -BeNullOrEmpty
        }
    }
    It 'marks the lock choice refused in the editor spec, and the validator refuses it' {
        $spec = Get-Spec $script:Vbs
        $hvci = $spec.Elements | Where-Object Id -EQ 'HvciDrop'
        ($hvci.Choices | Where-Object Label -EQ 'Enabled with UEFI lock').Refused | Should -Match 'UEFI lock'
        ($hvci.Choices | Where-Object Label -EQ 'Enabled without lock').Refused | Should -BeNullOrEmpty
        $bad = Test-IgwtSecSettingValue -ValueSpec $spec -Value @{ State = 'Enabled'; Values = @{ HvciDrop = 'Enabled with UEFI lock'; FakeDrop = 'Disabled' } }
        $bad.Ok | Should -BeFalse; ($bad.Errors -join ' ') | Should -Match 'UEFI lock'
        $ok = Test-IgwtSecSettingValue -ValueSpec $spec -Value @{ State = 'Enabled'; Values = @{ HvciDrop = 'Enabled without lock'; FakeDrop = 'Disabled' } }
        $ok.Ok | Should -BeTrue; $ok.Value.Values.HvciDrop | Should -Be 2
    }
}

Describe 'Weakening list (SM14)' {
    It 'refuses AlwaysInstallElevated=1 for both classes and the logging switch being removed' {
        InModuleScope iGWindowsTuner {
            Get-IgwtSecSettingOpRefusal -Class User -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\Microsoft\Windows\Installer'; ValueName = 'AlwaysInstallElevated'; Value = 1 }) | Should -Match 'system rights'
            Get-IgwtSecSettingOpRefusal -Class Machine -Op ([pscustomobject]@{ Op = 'Delete'; Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging' }) | Should -Match 'logging'
            Get-IgwtSecSettingOpRefusal -Class Machine -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging'; Value = 1 }) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Pure validation (SM30 part 1)' {
    It 'never reads secedit, the ADMX catalog or the account audit' {
        Mock -ModuleName iGWindowsTuner Invoke-IgwtSecedit { throw 'secedit must not run' }
        Mock -ModuleName iGWindowsTuner Get-IgwtAdmxCatalog { throw 'no ADMX parse' }
        Mock -ModuleName iGWindowsTuner Get-IgwtLocalAccountAudit { throw 'no account read' }
        $spec = Get-Spec $script:Vbs
        (Test-IgwtSecSettingValue -ValueSpec $spec -Value @{ State = 'Disabled' }).Ok | Should -BeTrue
        Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtSecedit -Times 0
        Should -Invoke -ModuleName iGWindowsTuner Get-IgwtAdmxCatalog -Times 0
    }
    It 'checks numbers, text, lists, pairs, time and flags' {
        InModuleScope iGWindowsTuner {
            $el = { param($kind, $more) @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id 'v' -Kind $kind -Label 'Value' -More $more) } }
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'decimal' @{ Min = 1; Max = 10 }) -Value '11').Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'decimal' @{ Min = 1; Max = 10 }) -Value '-3').Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'decimal' @{ Min = 1; Max = 10 }) -Value '7').Value | Should -Be 7
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'text' @{ PathKind = 'localFolder' }) -Value '\\server\share').Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'multiText' @{ SecpolText = $true }) -Value @('Welcome; all', 'ok')).Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'multiText' @{ SecpolText = $true }) -Value @('Welcome, all')).Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'multiText' @{ SecpolText = $true }) -Value @('Authorized use only')).Ok | Should -BeTrue
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'list' @{}) -Value @('a', 'A')).Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'keyValueList' @{}) -Value @{ '**del.x' = '1' }).Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'time' @{}) -Value '02:30').Value | Should -Be 150
            (Test-IgwtSecSettingValue -ValueSpec (& $el 'time' @{}) -Value '25:00').Ok | Should -BeFalse
            $flags = & $el 'flags' @{ Bits = @([pscustomobject]@{ Value = 524288; Label = 'NTLMv2' }, [pscustomobject]@{ Value = 536870912; Label = '128-bit' }) }
            (Test-IgwtSecSettingValue -ValueSpec $flags -Value @('NTLMv2', '128-bit')).Value | Should -Be 537395200
            (Test-IgwtSecSettingValue -ValueSpec $flags -Value @('8')).Ok | Should -BeFalse
            $enum = & $el 'enum' @{ Choices = @([pscustomobject]@{ Value = 0; Label = 'Off'; Index = 0 }, [pscustomobject]@{ Value = 2; Label = 'Block'; Index = 1 }) }
            (Test-IgwtSecSettingValue -ValueSpec $enum -Value 'Block').Value | Should -Be 2
            (Test-IgwtSecSettingValue -ValueSpec $enum -Value '1').Ok | Should -BeFalse
        }
    }
    It 'refuses adding to a remove-only list (exclusions) and allows removing' {
        InModuleScope iGWindowsTuner {
            $spec = @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id 'Path' -Kind 'list' -Label 'Excluded paths' -More @{ RemoveOnly = $true }) }
            (Test-IgwtSecSettingValue -ValueSpec $spec -Value @('C:\Games', 'C:\New') -Current @('C:\Games', 'C:\Old')).Ok | Should -BeFalse
            (Test-IgwtSecSettingValue -ValueSpec $spec -Value @('C:\Games') -Current @('C:\Games', 'C:\Old')).Ok | Should -BeTrue
        }
    }
}

Describe 'Audit is add-only (SM13 item 6)' {
    It 'refuses removing success or failure auditing and allows adding' {
        InModuleScope iGWindowsTuner {
            Test-IgwtSecSettingAuditAddOnly -Before 'SuccessAndFailure' -After 'Success' | Should -Match 'failure'
            Test-IgwtSecSettingAuditAddOnly -Before 'Success' -After 'None' | Should -Match 'success'
            Test-IgwtSecSettingAuditAddOnly -Before 'Success' -After 'SuccessAndFailure' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Lockout checks (SM15)' {
    It 'refuses what cannot be proven, and passes what can' {
        InModuleScope iGWindowsTuner {
            $user = [pscustomobject]@{ Name = 'PC\Player'; Sid = 'S-1-5-21-1-2-3-1001'; GroupSids = @('S-1-5-32-545'); IsRemote = $false }
            $admin = [pscustomobject]@{ Name = 'PC\Admin'; Sid = 'S-1-5-21-1-2-3-500'; GroupSids = @('S-1-5-32-544'); IsRemote = $false }
            $remote = [pscustomobject]@{ Name = 'PC\Admin'; Sid = 'S-1-5-21-1-2-3-500'; GroupSids = @('S-1-5-32-544'); IsRemote = $true }
            (Get-IgwtSecSettingLockoutChecks -ValueName 'ScForceOption' -Value 1 -Identity $admin).Result | Should -Be 'NotChecked'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'NoConnectedUser' -Value 3 -Identity $admin).Result | Should -Be 'NotChecked'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'ConsentPromptBehaviorUser' -Value 0 -Identity $user).Result | Should -Be 'Fail'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'ConsentPromptBehaviorUser' -Value 0 -Identity $admin).Result | Should -Be 'Pass'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'CrashOnAuditFail' -Value 1 -Identity $admin).Result | Should -Be 'Fail'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'MaxDevicePasswordFailedAttempts' -Value 10 -Identity $admin).Result | Should -Be 'NotChecked'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'MaxDevicePasswordFailedAttempts' -Value 10 -Identity $admin -RecoveryCheck Pass).Result | Should -Be 'Pass'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'fDenyTSConnections' -Value 1 -Identity $remote).Result | Should -Be 'Fail'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'EnableFirewall' -Value 1 -Identity $admin).Result | Should -Be 'Pass'
            (Get-IgwtSecSettingLockoutChecks -ValueName 'EnableFirewall' -Value 1 -Identity $null).Result | Should -Be 'NotChecked'
            @(Get-IgwtSecSettingLockoutChecks -ValueName 'NoLMHash' -Value 1 -Identity $admin) | Should -BeNullOrEmpty
        }
    }
}
