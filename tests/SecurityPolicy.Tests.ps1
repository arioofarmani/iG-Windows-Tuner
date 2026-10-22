# 3.0 security policy and auditing: secedit INF parse/serialize, audit CSV parse/serialize, the
# lockout safeguards (one test each), and the write/verify/restore paths with simulated secedit and
# auditpol (Invoke-IgwtSecedit and Invoke-IgwtAuditpol are mocked; nothing real runs).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    $script:MeSid = 'S-1-5-21-1000-2000-3000-1001'
    $script:OtherAdminSid = 'S-1-5-21-1000-2000-3000-1002'
    $script:BuiltinSid = 'S-1-5-21-1000-2000-3000-500'
    $script:BaseInf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 42
MinimumPasswordLength = 0
PasswordComplexity = 0
PasswordHistorySize = 0
LockoutBadCount = 10
ResetLockoutCount = 10
LockoutDuration = 10
AllowAdministratorLockout = 1
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
NewAdministratorName = "Administrator"
NewGuestName = "Guest"
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
EnableAdminAccount = 0
EnableGuestAccount = 0
[Event Audit]
AuditSystemEvents = 0
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyNetworkLogonRight = Guest
SeDenyInteractiveLogonRight = Guest
SeDebugPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $script:AuditR = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
PC,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},No Auditing,
PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,
PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success,
'@
}

Describe 'Security policy and auditing' {
    BeforeEach {
        # Simulated local security database: secedit /export writes it, /configure merges a template into it.
        $script:SecDb = InModuleScope iGWindowsTuner -Parameters @{ T = $script:BaseInf } { param($T) ConvertFrom-IgwtSecurityInf -Text $T }
        $script:Configured = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName iGWindowsTuner Invoke-IgwtSecedit {
            $cfg = $Arguments[[array]::IndexOf($Arguments, '/cfg') + 1]
            if ($Arguments[0] -eq '/export') {
                InModuleScope iGWindowsTuner -Parameters @{ P = $cfg; S = $script:SecDb } { param($P, $S) Write-IgwtSecurityInfFile -Path $P -Sections $S -WhatIf:$false }
                return [pscustomobject]@{ ExitCode = 0; Output = '' }
            }
            $tpl = InModuleScope iGWindowsTuner -Parameters @{ P = $cfg } { param($P) Read-IgwtSecurityInfFile -Path $P }
            foreach ($s in @($tpl.Keys)) { if ($s -in 'Unicode', 'Version') { continue }; foreach ($k in @($tpl[$s].Keys)) { $script:SecDb[$s][$k] = $tpl[$s][$k]; $script:Configured.Add("$s\$k=$($tpl[$s][$k])") } }
            return [pscustomobject]@{ ExitCode = 0; Output = '' }
        }
        $script:Remote = $false
        Mock -ModuleName iGWindowsTuner Get-IgwtCurrentIdentity { [pscustomobject]@{ Name = 'PC\ario'; Sid = $script:MeSid; GroupSids = @('S-1-1-0', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4'); IsRemote = $script:Remote } }
        $script:Accounts = @(
            [pscustomobject]@{ Name = 'Administrator'; Sid = $script:BuiltinSid; Enabled = $false; Role = 'BuiltinAdministrator'; IsAdmin = $true; PasswordLastSet = $null },
            [pscustomobject]@{ Name = 'ario'; Sid = $script:MeSid; Enabled = $true; Role = 'User'; IsAdmin = $true; PasswordLastSet = (Get-Date).AddDays(-30) },
            [pscustomobject]@{ Name = 'admin2'; Sid = $script:OtherAdminSid; Enabled = $true; Role = 'User'; IsAdmin = $true; PasswordLastSet = (Get-Date).AddDays(-5) }
        )
        $script:AdminsKnown = $true
        Mock -ModuleName iGWindowsTuner Get-IgwtLocalAccountAudit { [pscustomobject]@{ Readable = $true; AdminsKnown = $script:AdminsKnown; Accounts = $script:Accounts } }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; Authorities = @(); LocalGroupPolicy = $true } }
    }

    Context 'INF format' {
        It 'parses sections case-insensitively and keeps order and raw values' {
            InModuleScope iGWindowsTuner -Parameters @{ T = $script:BaseInf } {
                param($T)
                $s = ConvertFrom-IgwtSecurityInf -Text $T
                @($s.Keys) | Should -Be @('Unicode', 'System Access', 'Event Audit', 'Registry Values', 'Privilege Rights', 'Version')
                $s['system access']['maximumpasswordage'] | Should -Be '42'
                $s['System Access']['NewGuestName'] | Should -Be '"Guest"'
                $s['Registry Values']['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'] | Should -Be '4,1'
            }
        }
        It 'round-trips through text and a UTF-16 file' {
            InModuleScope iGWindowsTuner -Parameters @{ T = $script:BaseInf; P = (Join-Path $TestDrive 'rt.inf') } {
                param($T, $P)
                $s = ConvertFrom-IgwtSecurityInf -Text $T
                Write-IgwtSecurityInfFile -Path $P -Sections $s
                $b = [IO.File]::ReadAllBytes($P); "$($b[0]) $($b[1])" | Should -Be '255 254'
                $again = Read-IgwtSecurityInfFile -Path $P
                (ConvertTo-IgwtSecurityInfText -Sections $again) | Should -Be (ConvertTo-IgwtSecurityInfText -Sections $s)
                (ConvertTo-IgwtSecurityInfText -Sections $s) | Should -Match '(?m)^\[Unicode\]\r\nUnicode=yes'
                (ConvertTo-IgwtSecurityInfText -Sections $s) | Should -Match 'EnableLUA=4,1'
                (ConvertTo-IgwtSecurityInfText -Sections $s) | Should -Match 'LockoutBadCount = 10'
            }
        }
        It 'refuses malformed templates' {
            { InModuleScope iGWindowsTuner { ConvertFrom-IgwtSecurityInf -Text "Key = 1" } } | Should -Throw '*outside a section*'
            { InModuleScope iGWindowsTuner { ConvertFrom-IgwtSecurityInf -Text "[System Access]`nNoEquals" } } | Should -Throw "*without '='*"
        }
        It 'parses change text with section aliases and account names' {
            $c = @(InModuleScope iGWindowsTuner { ConvertFrom-IgwtSecurityChangeText -Text 'SystemAccess\LockoutBadCount=5;PrivilegeRights\SeShutdownPrivilege=*S-1-5-32-544|S-1-5-32-551' })
            $c.Count | Should -Be 2
            $c[0].Section | Should -Be 'System Access'
            $c[1].Value | Should -Be '*S-1-5-32-544,*S-1-5-32-551'
            { InModuleScope iGWindowsTuner { ConvertFrom-IgwtSecurityChangeText -Text 'Bogus\X=1' } } | Should -Throw '*Unknown section*'
        }
        It 'shows the policy with names and resolved accounts' {
            $rows = @(InModuleScope iGWindowsTuner { Get-IgwtSecurityPolicy })
            ($rows | Where-Object Key -EQ 'LockoutBadCount').Name | Should -Be 'Account lockout threshold'
            @(($rows | Where-Object Key -EQ 'SeDebugPrivilege').Accounts) | Should -Be @('Administrators')
            ($rows | Where-Object Key -EQ 'SeNetworkLogonRight').Accounts | Should -Contain 'Everyone'
        }
    }

    Context 'Lockout safeguards' {
        It 'refuses removing Administrators from local logon' {
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeInteractiveLogonRight'; Value = '*S-1-5-32-551' }) }
            @($p.Refusals) -join ' ' | Should -Match 'Administrators would lose the right to sign in'
        }
        It 'refuses removing the current user from local logon' {
            $script:Accounts[1].IsAdmin = $false
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeInteractiveLogonRight'; Value = '*S-1-5-32-551' }) }
            @($p.Refusals) -join ' ' | Should -Match 'you \(PC\\ario\) would lose'
        }
        It 'allows local logon for Administrators only (the current user is an administrator)' {
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeInteractiveLogonRight'; Value = '*S-1-5-32-544' }) }
            @($p.Refusals).Count | Should -Be 0
        }
        It 'refuses removing Remote Desktop or network logon while in a Remote Desktop session' {
            $script:Remote = $true
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeRemoteInteractiveLogonRight'; Value = '*S-1-5-32-555' }) }
            @($p.Refusals) -join ' ' | Should -Match 'Remote Desktop'
            $p2 = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeNetworkLogonRight'; Value = '*S-1-5-32-551' }) }
            @($p2.Refusals) -join ' ' | Should -Match 'Network Level Authentication'
            $script:Remote = $false
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeRemoteInteractiveLogonRight'; Value = '*S-1-5-32-555' }) }).Refusals.Count | Should -Be 0
        }
        It 'refuses deny rights that match the current user or Administrators' {
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeDenyInteractiveLogonRight'; Value = '*S-1-5-32-545' }) }
            @($p.Refusals) -join ' ' | Should -Match 'deny you .* through Users'
            $script:Remote = $true
            $p2 = InModuleScope iGWindowsTuner -Parameters @{ S = $script:MeSid } { param($S) Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeDenyRemoteInteractiveLogonRight'; Value = "*$S" }) }
            @($p2.Refusals).Count | Should -Be 1
            $script:Remote = $false
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeDenyNetworkLogonRight'; Value = 'Guest,*S-1-5-113' }) }).Refusals.Count | Should -Be 0
        }
        It 'refuses a maximum password age that expires the current password now' {
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MaximumPasswordAge'; Value = '20' }) }
            @($p.Refusals) -join ' ' | Should -Match 'would expire immediately'
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MaximumPasswordAge'; Value = '60' }) }).Refusals.Count | Should -Be 0
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MaximumPasswordAge'; Value = '-1' }) }).Refusals.Count | Should -Be 0
        }
        It 'refuses invalid or immediate lockout settings' {
            (@((InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'LockoutBadCount'; Value = '1' }) }).Refusals) -join ' ') | Should -Match 'Use 3 or more'
            (@((InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'ResetLockoutCount'; Value = '30' }) }).Refusals) -join ' ') | Should -Match 'must be at least ResetLockoutCount'
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'LockoutBadCount'; Value = '5' }) }).Refusals.Count | Should -Be 0
        }
        It 'refuses lockout without automatic unlock when only one administrator is enabled' {
            $script:Accounts[2].Enabled = $false
            (@((InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'LockoutDuration'; Value = '0' }) }).Refusals) -join ' ') | Should -Match 'only one enabled administrator'
            $script:Accounts[2].Enabled = $true
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'LockoutDuration'; Value = '0' }) }).Refusals.Count | Should -Be 0
        }
        It 'refuses disabling the last enabled administrator' {
            $script:Accounts[0].Enabled = $true; $script:Accounts[1].IsAdmin = $false; $script:Accounts[2].Enabled = $false
            (@((InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'EnableAdminAccount'; Value = '0' }) }).Refusals) -join ' ') | Should -Match 'last enabled administrator'
            $script:Accounts[2].Enabled = $true
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'EnableAdminAccount'; Value = '0' }) }).Refusals.Count | Should -Be 0
            $script:AdminsKnown = $false
            (@((InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'EnableAdminAccount'; Value = '0' }) }).Refusals) -join ' ') | Should -Match 'could not be read'
        }
        It 'refuses weakening settings, sensitive privileges for broad groups and denylisted registry values' {
            $p = InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @(
                    [pscustomobject]@{ Section = 'System Access'; Key = 'EnableGuestAccount'; Value = '1' },
                    [pscustomobject]@{ Section = 'System Access'; Key = 'ClearTextPassword'; Value = '1' },
                    [pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeDebugPrivilege'; Value = '*S-1-5-32-544,*S-1-5-32-545' },
                    [pscustomobject]@{ Section = 'Registry Values'; Key = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'; Value = '4,0' }) }
            @($p.Refusals).Count | Should -Be 4
            (@($p.Refusals) -join ' ') | Should -Match 'Guest'
            (@($p.Refusals) -join ' ') | Should -Match 'reversible'
            (@($p.Refusals) -join ' ') | Should -Match 'SeDebugPrivilege .* Users'
            (@($p.Refusals) -join ' ') | Should -Match 'User Account Control'
        }
        It 'does not refuse unchanged pre-existing broad grants' {
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MinimumPasswordLength'; Value = '12' }) }).Refusals.Count | Should -Be 0
        }
        It 'validates value formats' {
            { InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'LockoutBadCount'; Value = 'ten' }) } } | Should -Throw '*numbers*'
            { InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Registry Values'; Key = 'MACHINE\X\Y'; Value = '1' }) } } | Should -Throw '*type,value*'
            { InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'Event Audit'; Key = 'AuditSystemEvents'; Value = '1' }) } } | Should -Throw '*cannot be changed*'
        }
    }

    Context 'secedit write path' {
        It 'snapshots, configures only the changed settings, verifies and restores' {
            $r = InModuleScope iGWindowsTuner { Set-IgwtSecurityPolicy -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MinimumPasswordLength'; Value = '14' }, [pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeShutdownPrivilege'; Value = '*S-1-5-32-544' }) }
            $r.Verified | Should -BeTrue
            @($script:Configured) | Should -Be @('System Access\MinimumPasswordLength=14', 'Privilege Rights\SeShutdownPrivilege=*S-1-5-32-544')
            Test-Path -LiteralPath (Join-Path $r.Backup 'before.inf') | Should -BeTrue
            (Get-Content -LiteralPath (Join-Path $r.Backup 'manifest.json') -Raw | ConvertFrom-Json).changes[0].before | Should -Be '0'
            $script:SecDb['System Access']['MinimumPasswordLength'] | Should -Be '14'
            $x = InModuleScope iGWindowsTuner -Parameters @{ B = $r.Backup } { param($B) Restore-IgwtSecurityPolicy -BackupPath $B }
            $x.Settings | Should -Be 2
            $script:SecDb['System Access']['MinimumPasswordLength'] | Should -Be '0'
            $script:SecDb['Privilege Rights']['SeShutdownPrivilege'] | Should -Be '*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551'
        }
        It 'refuses before writing anything' {
            { InModuleScope iGWindowsTuner { Set-IgwtSecurityPolicy -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'EnableGuestAccount'; Value = '1' }) } } | Should -Throw '*Refused*'
            $script:Configured.Count | Should -Be 0
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtSecedit -Times 0 -ParameterFilter { $Arguments[0] -eq '/configure' }
        }
        It 'needs the acknowledgement on a managed PC' {
            Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; DomainJoined = $true; Authorities = @('Domain'); LocalGroupPolicy = $true } }
            { InModuleScope iGWindowsTuner { Set-IgwtSecurityPolicy -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MinimumPasswordLength'; Value = '14' }) } } | Should -Throw '*AcknowledgeManaged*'
            (InModuleScope iGWindowsTuner { Get-IgwtSecurityChangePlan -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MinimumPasswordLength'; Value = '14' }) }).Notes | Should -Match 'Domain-joined'
        }
        It 'reports a failed verification' {
            Mock -ModuleName iGWindowsTuner Invoke-IgwtSecedit {
                if ($Arguments[0] -eq '/export') { InModuleScope iGWindowsTuner -Parameters @{ P = $Arguments[2]; S = $script:SecDb } { param($P, $S) Write-IgwtSecurityInfFile -Path $P -Sections $S -WhatIf:$false } }
                [pscustomobject]@{ ExitCode = 0; Output = '' }
            }
            $r = InModuleScope iGWindowsTuner { Set-IgwtSecurityPolicy -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MinimumPasswordLength'; Value = '14' }) }
            $r.Verified | Should -BeFalse
            @($r.Mismatch) | Should -Be @('System Access\MinimumPasswordLength')
        }
        It 'refuses a tampered snapshot' {
            $r = InModuleScope iGWindowsTuner { Set-IgwtSecurityPolicy -Changes @([pscustomobject]@{ Section = 'System Access'; Key = 'MinimumPasswordLength'; Value = '14' }) }
            Add-Content -LiteralPath (Join-Path $r.Backup 'before.inf') -Value 'x'
            { InModuleScope iGWindowsTuner -Parameters @{ B = $r.Backup } { param($B) Restore-IgwtSecurityPolicy -BackupPath $B } } | Should -Throw '*was changed*'
        }
        It 'needs administrator rights to read (exit 740) and never runs secedit in TestMode' {
            Mock -ModuleName iGWindowsTuner Invoke-IgwtSecedit { [pscustomobject]@{ ExitCode = 740; Output = '' } }
            { InModuleScope iGWindowsTuner { Export-IgwtSecurityPolicy } } | Should -Throw '*administrator rights*'
            { InModuleScope iGWindowsTuner { & (Get-Command Invoke-IgwtSecedit -CommandType Function).ScriptBlock -Arguments @('/export') } } | Should -Throw '*TestMode safety*'
        }
    }

    Context 'Audit policy' {
        BeforeEach {
            $script:Audit = @{}
            foreach ($r in @(InModuleScope iGWindowsTuner -Parameters @{ T = $script:AuditR } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })) { $script:Audit[$r.Guid] = [pscustomobject]@{ Name = $r.Subcategory; Setting = $r.Setting } }
            $script:AuditCalls = New-Object System.Collections.Generic.List[string]
            Mock -ModuleName iGWindowsTuner Invoke-IgwtAuditpol {
                $script:AuditCalls.Add($Arguments -join ' ')
                switch ($Arguments[0]) {
                    '/get' {
                        $text = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`r`n"
                        $map = @{ None = 'No Auditing'; Success = 'Success'; Failure = 'Failure'; SuccessAndFailure = 'Success and Failure' }
                        foreach ($g in @($script:Audit.Keys | Sort-Object)) { $text += "PC,System,$($script:Audit[$g].Name),$g,$($map[$script:Audit[$g].Setting]),`r`n" }
                        return [pscustomobject]@{ ExitCode = 0; Output = $text }
                    }
                    '/set' {
                        $g = ($Arguments[1] -replace '^/subcategory:', '').ToUpperInvariant()
                        $s = $Arguments[2] -eq '/success:enable'; $f = $Arguments[3] -eq '/failure:enable'
                        $script:Audit[$g].Setting = $(if ($s -and $f) { 'SuccessAndFailure' } elseif ($s) { 'Success' } elseif ($f) { 'Failure' } else { 'None' })
                    }
                    '/backup' {
                        $rows = foreach ($g in $script:Audit.Keys) { [pscustomobject]@{ Subcategory = $script:Audit[$g].Name; Guid = $g; Setting = $script:Audit[$g].Setting; Option = $false } }
                        $csv = InModuleScope iGWindowsTuner -Parameters @{ R = @($rows) } { param($R) ConvertTo-IgwtAuditCsv -Rows $R }
                        [IO.File]::WriteAllText(($Arguments[1] -replace '^/file:', ''), $csv)
                    }
                    '/restore' {
                        foreach ($r in @(InModuleScope iGWindowsTuner -Parameters @{ T = [IO.File]::ReadAllText(($Arguments[1] -replace '^/file:', '')) } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })) { $script:Audit[$r.Guid].Setting = $r.Setting }
                    }
                }
                [pscustomobject]@{ ExitCode = 0; Output = '' }
            }
        }
        It 'parses auditpol /r output and audit.csv backups' {
            $rows = @(InModuleScope iGWindowsTuner -Parameters @{ T = $script:AuditR } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })
            $rows.Count | Should -Be 4
            ($rows | Where-Object Subcategory -EQ 'Logon').Setting | Should -Be 'SuccessAndFailure'
            ($rows | Where-Object Subcategory -EQ 'Credential Validation').Setting | Should -Be 'Success'
            $bak = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`nPC,System,Audit Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,,1`r`nPC,System,Option:CrashOnAuditFail,,Disabled,,0"
            $b = @(InModuleScope iGWindowsTuner -Parameters @{ T = $bak } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })
            $b[0].Setting | Should -Be 'Success'
            $b[1].Option | Should -BeTrue
            { InModuleScope iGWindowsTuner { ConvertFrom-IgwtAuditCsv -Text "a,b`r`n1,2" } } | Should -Throw '*Subcategory*'
        }
        It 'serializes the audit.csv format and parses it back' {
            $rows = @(InModuleScope iGWindowsTuner -Parameters @{ T = $script:AuditR } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })
            $csv = InModuleScope iGWindowsTuner -Parameters @{ R = $rows } { param($R) ConvertTo-IgwtAuditCsv -Rows $R -MachineName 'PC' }
            ($csv -split "`r`n")[0] | Should -Be 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
            $csv | Should -Match 'PC,System,"Logon",\{0CCE9215-69AE-11D9-BED3-505054503030\},Success and Failure,,3'
            $back = @(InModuleScope iGWindowsTuner -Parameters @{ T = $csv } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })
            @($back | ForEach-Object { $_.Setting }) | Should -Be @($rows | ForEach-Object { $_.Setting })
        }
        It 'plans by name or GUID and warns when auditing is reduced' {
            $p = InModuleScope iGWindowsTuner { Get-IgwtAuditChangePlan -Changes @{ 'process creation' = 'Success'; '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Success' } }
            @($p.Ops).Count | Should -Be 2
            @($p.Warnings) | Should -Be @('Logon: stops auditing failure events.')
            @($p.Notes).Count | Should -Be 1
            { InModuleScope iGWindowsTuner { Get-IgwtAuditChangePlan -Changes @{ 'Nope' = 'Success' } } } | Should -Throw '*Unknown audit subcategory*'
            { InModuleScope iGWindowsTuner { Get-IgwtAuditChangePlan -Changes @{ 'Logon' = 'Sometimes' } } } | Should -Throw '*not an audit setting*'
        }
        It 'backs up, sets, verifies and restores' {
            $r = InModuleScope iGWindowsTuner { Set-IgwtAuditPolicy -Changes @{ 'Process Creation' = 'SuccessAndFailure'; 'Logon' = 'SuccessAndFailure' } }
            $r.Verified | Should -BeTrue
            @($r.Ops).Count | Should -Be 1 -Because 'Logon is already set'
            $script:AuditCalls[1] | Should -Match '^/backup /file:'
            @($script:AuditCalls | Where-Object { $_ -like '/set *' }) | Should -Be @('/set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable')
            $script:Audit['{0CCE922B-69AE-11D9-BED3-505054503030}'].Setting | Should -Be 'SuccessAndFailure'
            $null = InModuleScope iGWindowsTuner -Parameters @{ B = $r.Backup } { param($B) Restore-IgwtAuditPolicy -BackupPath $B }
            $script:Audit['{0CCE922B-69AE-11D9-BED3-505054503030}'].Setting | Should -Be 'None'
        }
        It 'imports an audit.csv as the differing changes and exports the current policy' {
            $file = Join-Path $TestDrive 'baseline-audit.csv'
            [IO.File]::WriteAllText($file, "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n,System,Audit Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,,1`r`n,System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3")
            $c = InModuleScope iGWindowsTuner -Parameters @{ F = $file } { param($F) Import-IgwtAuditCsv -Path $F }
            @($c.Keys) | Should -Be @('0CCE922B-69AE-11D9-BED3-505054503030')
            $c['0CCE922B-69AE-11D9-BED3-505054503030'] | Should -Be 'Success'
            $out = Join-Path $TestDrive 'export.csv'
            InModuleScope iGWindowsTuner -Parameters @{ F = $out } { param($F) Export-IgwtAuditCsv -Path $F }
            @(InModuleScope iGWindowsTuner -Parameters @{ T = [IO.File]::ReadAllText($out) } { param($T) ConvertFrom-IgwtAuditCsv -Text $T }).Count | Should -Be 4
        }
        It 'never runs auditpol in TestMode and only allows get, set, backup and restore' {
            { InModuleScope iGWindowsTuner { & (Get-Command Invoke-IgwtAuditpol -CommandType Function).ScriptBlock -Arguments @('/get') } } | Should -Throw '*TestMode safety*'
            InModuleScope iGWindowsTuner {
                $saved = $script:IgwtSettings.TestMode
                try { $script:IgwtSettings.TestMode = $false; { & (Get-Command Invoke-IgwtAuditpol -CommandType Function).ScriptBlock -Arguments @('/clear') } | Should -Throw '*not used*' }
                finally { $script:IgwtSettings.TestMode = $saved }
            }
        }
    }
}
