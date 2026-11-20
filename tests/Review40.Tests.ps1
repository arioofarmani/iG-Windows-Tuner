# Regression tests for the 3.8.1 review Mediums fixed in 4.0 (findings in the Phase 1 report).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Review 4.0 CLI-05: no elevation from a program folder that other accounts can change' {
    It 'lists other writers but not SYSTEM, Administrators, TrustedInstaller or allowed accounts (real ACL objects)' {
        InModuleScope iGWindowsTuner {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)
            $sid = { param($s) New-Object System.Security.Principal.SecurityIdentifier($s) }
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((& $sid 'S-1-5-32-544'), 'FullControl', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((& $sid 'S-1-5-21-1-2-3-1001'), 'Modify', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((& $sid 'S-1-5-32-545'), 'ReadAndExecute, Synchronize', 'Allow')))
            @(Get-IgwtAclOtherWriters -Acl $acl -Allowed $script:IgwtTrustedPrincipals) | Should -Be @('S-1-5-21-1-2-3-1001')
            @(Get-IgwtAclOtherWriters -Acl $acl -Allowed (@($script:IgwtTrustedPrincipals) + 'S-1-5-21-1-2-3-1001')).Count | Should -Be 0
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((& $sid 'S-1-5-11'), 'Modify', 'Allow')))
            @(Get-IgwtAclOtherWriters -Acl $acl -Allowed (@($script:IgwtTrustedPrincipals) + 'S-1-5-21-1-2-3-1001')) | Should -Be @('S-1-5-11')
        }
    }
    It 'refuses to elevate and starts nothing when another account can change the program files' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtProgramFolderWriters { [pscustomobject]@{ Path = 'D:\Tools\iG\src'; Sid = 'S-1-5-11'; Account = 'NT AUTHORITY\Authenticated Users' } }
            Mock Start-Process { throw 'must not start' }
            { Start-IgwtElevated -ScriptPath 'D:\Tools\iG\iGWindowsTuner.ps1' -Confirm:$false } | Should -Throw '*Authenticated Users can change*Program Files*Nothing was changed*'
            Should -Invoke Start-Process -Times 0
        }
    }
    It 'elevates when only trusted accounts and the current user can change the program files' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtProgramFolderWriters { }
            Mock Start-Process { [pscustomobject]@{ Id = 1 } }
            Start-IgwtElevated -ScriptPath 'C:\Program Files\iG\iGWindowsTuner.ps1' -Confirm:$false | Should -Not -BeNullOrEmpty
            Should -Invoke Start-Process -Times 1
        }
    }
    It 'reads the real program folder without error' {
        $root = Split-Path -Parent $PSScriptRoot
        { InModuleScope iGWindowsTuner -Parameters @{ R = $root } { param($R) $null = @(Get-IgwtProgramFolderWriters -Root $R) } } | Should -Not -Throw
    }
}

Describe 'Review 4.0 TW-LSA: Reset to Windows default keeps LSA protection on' {
    It 'resets RunAsPPL to 2 instead of deleting it' {
        $item = @(Get-IgwtCatalog -Force | Where-Object { $_.id -eq 'sec.lsa-protection' })[0]
        $a = @($item.actions | Where-Object { $_.name -eq 'RunAsPPL' })[0]
        [string]$a.default | Should -Be '2'
        [string]$a.default | Should -Not -Be '<absent>'
    }
}
