# Regression tests for the 3.8.1 review (artifacts are local; findings S1, E1, ... in the Phase 1 report).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Review 3.8.1 S1: only SYSTEM, Administrators and TrustedInstaller are trusted' {
    BeforeAll {
        InModuleScope iGWindowsTuner {
            function script:New-R381Acl {
                param([string]$OwnerSid, [object[]]$Rules = @(), [switch]$Directory)
                $a = $(if ($Directory) { New-Object System.Security.AccessControl.DirectorySecurity } else { New-Object System.Security.AccessControl.FileSecurity })
                $a.SetAccessRuleProtection($true, $false)
                $a.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)))
                $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')), 'FullControl', 'Allow')))
                foreach ($r in $Rules) { $a.AddAccessRule($r) }
                $a
            }
            function script:New-R381Rule {
                param([string]$Sid, [string]$Rights, [string]$Inherit = 'None', [string]$Propagate = 'None')
                New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($Sid)), $Rights, $Inherit, $Propagate, 'Allow')
            }
        }
    }

    It 'refuses a file owned by the current user (UAC: the non-elevated token has the same SID)' {
        InModuleScope iGWindowsTuner {
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            Test-IgwtSecurityDescriptorTrusted -Acl (New-R381Acl -OwnerSid $me) | Should -BeFalse
        }
    }
    It 'refuses an Administrators-owned file that grants write to one user' {
        InModuleScope iGWindowsTuner {
            $acl = New-R381Acl -OwnerSid 'S-1-5-32-544' -Rules @(New-R381Rule -Sid 'S-1-5-21-1-2-3-1001' -Rights 'Write')
            Test-IgwtSecurityDescriptorTrusted -Acl $acl | Should -BeFalse
        }
    }
    It 'accepts the protected data-root ACL (SYSTEM and Administrators full, Users read) and a private folder (one user read)' {
        InModuleScope iGWindowsTuner {
            $root = New-R381Acl -OwnerSid 'S-1-5-32-544' -Directory -Rules @((New-R381Rule -Sid 'S-1-5-18' -Rights 'FullControl'), (New-R381Rule -Sid 'S-1-5-32-545' -Rights 'ReadAndExecute'))
            Test-IgwtSecurityDescriptorTrusted -Acl $root | Should -BeTrue
            $private = New-R381Acl -OwnerSid 'S-1-5-18' -Directory -Rules @(New-R381Rule -Sid 'S-1-5-21-1-2-3-1001' -Rights 'ReadAndExecute')
            Test-IgwtSecurityDescriptorTrusted -Acl $private | Should -BeTrue
        }
    }
    It 'accepts TrustedInstaller as owner and writer' {
        InModuleScope iGWindowsTuner {
            $ti = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
            Test-IgwtSecurityDescriptorTrusted -Acl (New-R381Acl -OwnerSid $ti -Rules @(New-R381Rule -Sid $ti -Rights 'FullControl')) | Should -BeTrue
        }
    }
    It 'ignores an inherit-only entry (CREATOR OWNER on a folder does not apply to the folder itself)' {
        InModuleScope iGWindowsTuner {
            $acl = New-R381Acl -OwnerSid 'S-1-5-32-544' -Directory -Rules @(New-R381Rule -Sid 'S-1-3-0' -Rights 'FullControl' -Inherit 'ContainerInherit, ObjectInherit' -Propagate 'InheritOnly')
            Test-IgwtSecurityDescriptorTrusted -Acl $acl | Should -BeTrue
        }
    }
    It 'still refuses an entry that applies to the object and grants write to CREATOR OWNER' {
        InModuleScope iGWindowsTuner {
            $acl = New-R381Acl -OwnerSid 'S-1-5-32-544' -Directory -Rules @(New-R381Rule -Sid 'S-1-3-0' -Rights 'Modify' -Inherit 'ContainerInherit, ObjectInherit')
            Test-IgwtSecurityDescriptorTrusted -Acl $acl | Should -BeFalse
        }
    }
}

Describe 'Review 3.8.1 S1: Test-IgwtPathTrustedChain checks every level up to the root' {
    It 'accepts when the file and every folder up to the root are trusted' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtTrustedFile { $true }
            Test-IgwtPathTrustedChain -Path 'C:\ProgramData\iGWindowsTuner\Backups\snapshot-x.json' -Root 'C:\ProgramData\iGWindowsTuner' | Should -BeTrue
            Should -Invoke Test-IgwtTrustedFile -Times 3 -Exactly
        }
    }
    It 'refuses when one folder in between is not trusted' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtTrustedFile { $Path -notlike '*\Backups' }
            Test-IgwtPathTrustedChain -Path 'C:\ProgramData\iGWindowsTuner\Backups\snapshot-x.json' -Root 'C:\ProgramData\iGWindowsTuner' | Should -BeFalse
        }
    }
    It 'refuses when the root itself is not trusted' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtTrustedFile { $Path -notlike '*\iGWindowsTuner' }
            Test-IgwtPathTrustedChain -Path 'C:\ProgramData\iGWindowsTuner\Backups\snapshot-x.json' -Root 'C:\ProgramData\iGWindowsTuner' | Should -BeFalse
        }
    }
    It 'refuses a file outside the root, including a look-alike folder name and ..' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtTrustedFile { $true }
            Test-IgwtPathTrustedChain -Path 'C:\ProgramData\AegisTune\Backups\snapshot-x.json' -Root 'C:\ProgramData\iGWindowsTuner' | Should -BeFalse
            Test-IgwtPathTrustedChain -Path 'C:\ProgramData\iGWindowsTuner2\snapshot-x.json' -Root 'C:\ProgramData\iGWindowsTuner' | Should -BeFalse
            Test-IgwtPathTrustedChain -Path 'C:\ProgramData\iGWindowsTuner\..\AegisTune\snapshot-x.json' -Root 'C:\ProgramData\iGWindowsTuner' | Should -BeFalse
            Should -Invoke Test-IgwtTrustedFile -Times 0 -Exactly
        }
    }
}

Describe 'Review 3.8.1 S1: Set-IgwtAdminOwner' {
    It 'changes nothing in test mode or when not elevated' {
        InModuleScope iGWindowsTuner {
            $f = Join-Path $TestDrive 'owner.txt'
            Set-Content -LiteralPath $f -Value 'x'
            $before = (Get-Acl -LiteralPath $f).Owner
            { Set-IgwtAdminOwner -Path $f } | Should -Not -Throw
            (Get-Acl -LiteralPath $f).Owner | Should -Be $before
        }
    }
}
