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

Describe 'Review 3.8.1 S1: snapshots are restored only from the protected Backups folder' {
    BeforeAll {
        $script:R381Doc = { param($Op) [ordered]@{ schema = 2; tool = 'iG Windows Tuner'; version = '3.8.1'; id = [guid]::NewGuid().ToString(); created = '2026-11-19T10:00:00Z'; operation = $Op; detail = ''; catalogSchema = 3; hardwareTags = @(); entries = @() } }
    }
    AfterEach { Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'IgwtData') }

    It 'refuses a snapshot file outside the Backups folder, even a trusted one' {
        $out = Join-Path $TestDrive 'Downloads'
        $null = New-Item -ItemType Directory -Path $out -Force
        $f = Join-Path $out 'snapshot-20991231-000000-000-Apply-aaaaaa.json'
        Set-Content -LiteralPath $f -Value ((& $script:R381Doc 'Apply') | ConvertTo-Json -Depth 5) -Encoding UTF8
        { InModuleScope iGWindowsTuner -Parameters @{ F = $f } { param($F) Read-IgwtSnapshot -Path $F } } | Should -Throw "*not in iG's protected Backups folder*"
        { Invoke-IgwtRevert -SnapshotPath $f } | Should -Throw "*not in iG's protected Backups folder*"
    }
    It 'refuses a snapshot in Backups when a folder above it is not protected' {
        InModuleScope iGWindowsTuner -Parameters @{ D = $script:R381Doc } {
            param($D)
            $b = Get-IgwtDataPath -Kind Backups
            $null = New-Item -ItemType Directory -Path $b -Force
            $f = Join-Path $b 'snapshot-20991231-000000-000-Apply-bbbbbb.json'
            Set-Content -LiteralPath $f -Value ((& $D 'Apply') | ConvertTo-Json -Depth 5) -Encoding UTF8
            try {
                Mock Test-IgwtTrustedFile { $Path -notlike '*\Backups' }
                { Read-IgwtSnapshot -Path $f } | Should -Throw "*not in iG's protected Backups folder*"
                Mock Test-IgwtTrustedFile { $true }
                (Read-IgwtSnapshot -Path $f).operation | Should -Be 'Apply'
            } finally { Remove-Item -LiteralPath $f -Force }
        }
    }
    It 'lists and restores from the legacy AegisTune folder only when it is protected' {
        $legacy = Join-Path $TestDrive 'LegacyR381'
        $null = New-Item -ItemType Directory -Path (Join-Path $legacy 'Backups') -Force
        $f = Join-Path $legacy 'Backups\snapshot-20991231-000000-000-Apply-cccccc.json'
        $doc = & $script:R381Doc 'Apply'; $doc.tool = 'AegisTune'
        Set-Content -LiteralPath $f -Value ($doc | ConvertTo-Json -Depth 5) -Encoding UTF8
        Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'R381Root') -LegacyDataRoot $legacy
        InModuleScope iGWindowsTuner -Parameters @{ F = $f; L = $legacy } {
            param($F, $L)
            Mock Test-IgwtTrustedFile { $Path -ne $L }
            Test-IgwtLegacyRootTrusted | Should -BeFalse
            @(Get-IgwtSnapshotList | ForEach-Object { $_.Path }) | Should -Not -Contain $F
            { Read-IgwtSnapshot -Path $F } | Should -Throw "*not in iG's protected Backups folder*"
            Mock Test-IgwtTrustedFile { $true }
            Test-IgwtLegacyRootTrusted | Should -BeTrue
            @(Get-IgwtSnapshotList | ForEach-Object { $_.Path }) | Should -Contain $F
        }
    }
    It 'Revert -Last never picks a planted legacy file' {
        $legacy = Join-Path $TestDrive 'LegacyR381b'
        $null = New-Item -ItemType Directory -Path (Join-Path $legacy 'Backups') -Force
        $doc = & $script:R381Doc 'Apply'; $doc.tool = 'AegisTune'
        $doc.entries = @([ordered]@{ tweakId = 'gfx.game-mode'; result = 'Applied'; message = ''; time = '2026-11-19T10:00:00Z'; actions = @() })
        Set-Content -LiteralPath (Join-Path $legacy 'Backups\snapshot-20991231-000000-000-Apply-dddddd.json') -Value ($doc | ConvertTo-Json -Depth 6) -Encoding UTF8
        Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'R381Root2') -LegacyDataRoot $legacy
        InModuleScope iGWindowsTuner -Parameters @{ L = $legacy } {
            param($L)
            Mock Test-IgwtTrustedFile { $Path -ne $L }
            { Invoke-IgwtRevert -Last } | Should -Throw '*No apply snapshot found*'
        }
    }
}

Describe 'Review 3.8.1 S1: firewall restores validate the saved rule definition' {
    BeforeAll {
        $script:R381Def = { [ordered]@{ name = '{11111111-2222-3333-4444-555555555555}'; displayName = 'Test rule'; description = ''; group = ''; enabled = $true; direction = 'Inbound'; action = 'Allow'; profile = 'Private, Public'; program = '%SystemRoot%\system32\svchost.exe'; service = 'RpcSs'; package = ''; protocol = 'TCP'; localPort = @('RPC'); remotePort = @(); localAddress = @(); remoteAddress = @('LocalSubnet'); edgeTraversal = 'Block'; owner = ''; interfaceType = 'Any' } }
    }
    It 'accepts a real-looking built-in definition with keyword ports and addresses' {
        InModuleScope iGWindowsTuner -Parameters @{ D = (& $script:R381Def) } { param($D) @(Test-IgwtFirewallRuleDefinition -Definition $D).Count | Should -Be 0 }
    }
    It 'refuses values outside the fixed sets, a relative program, a bad SID and control characters' {
        InModuleScope iGWindowsTuner -Parameters @{ Mk = $script:R381Def } {
            param($Mk)
            $cases = @(
                @{ k = 'edgeTraversal'; v = 'Everything' }, @{ k = 'direction'; v = 'Both' }, @{ k = 'action'; v = 'Permit' },
                @{ k = 'profile'; v = 'Home' }, @{ k = 'protocol'; v = 'GRE' }, @{ k = 'protocol'; v = '300' },
                @{ k = 'program'; v = 'evil.exe' }, @{ k = 'owner'; v = 'Administrators' }, @{ k = 'package'; v = 'S-1-5-18' },
                @{ k = 'interfaceType'; v = 'Bluetooth' }, @{ k = 'displayName'; v = "a`nb" }, @{ k = 'name'; v = '' }
            )
            foreach ($c in $cases) {
                $d = & $Mk; $d[$c.k] = $c.v
                @(Test-IgwtFirewallRuleDefinition -Definition $d).Count | Should -BeGreaterThan 0 -Because "$($c.k) = $($c.v)"
            }
            $ok = & $Mk; $ok.protocol = '47'; $ok.localPort = @(); @(Test-IgwtFirewallRuleDefinition -Definition $ok).Count | Should -Be 0 -Because 'a protocol number is valid'
        }
    }
    It 'a revert with an invalid saved definition changes nothing and reports Failed' {
        InModuleScope iGWindowsTuner -Parameters @{ Mk = $script:R381Def } {
            param($Mk)
            $bad = & $Mk; $bad.edgeTraversal = 'Everything'
            $doc = [pscustomobject]@{ operation = 'Firewall'; entries = @([pscustomobject]@{ tweakId = 'firewall:1'; result = 'Applied'; actions = @([pscustomobject]@{ type = 'firewallManager'; op = 'deleted'; name = $bad.name; definition = $bad }) }) }
            Mock Read-IgwtSnapshot { $doc }
            Mock Get-NetFirewallRule { @() }
            Mock New-NetFirewallRule { }
            Mock Set-NetFirewallRule { }
            $r = Restore-IgwtFirewallSnapshot -SnapshotPath 'C:\x\snapshot-x.json' -Confirm:$false
            @($r.Results)[0].Result | Should -Be 'Failed'
            @($r.Results)[0].Message | Should -BeLike '*not valid*'
            Should -Invoke New-NetFirewallRule -Times 0 -Exactly
        }
    }
}

Describe 'Review 3.8.1 E1: a module writer that fails after its backup can be rolled back with it' {
    It 'keeps the recorded backup reference on the failed step and gives it to the rollback' {
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null
            function script:Invoke-IgwtR381Writer {
                [CmdletBinding()] param([string]$Target)
                $snap = New-IgwtSnapshot -Operation 'Manage' -Detail $Target
                Save-IgwtSnapshot -Snapshot $snap
                $script:R381Snap = $snap.Path
                throw 'gpupdate failed after the write'
            }
            $script:IgwtModuleOperations['Invoke-IgwtR381Writer'] = 'snapshot'
            $orig = $script:IgwtChangeProviders['module'].Restore
            $script:R381Restored = @()
            $script:IgwtChangeProviders['module'].Restore = { param($r, $data, $ctx) $null = $r; $null = $ctx; $script:R381Restored += [string]$data['applied']['ref'] }
            try {
                $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test'; ref = 'E1' }) -Title 'E1 test' -Confirm:$false
                try {
                    $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Invoke-IgwtR381Writer' -Parameters @{ Target = 'x' } -Group 'g1' -Confirm:$false
                    $s.Step.Result | Should -Be 'Failed'
                    $s.Step.Applied['ref'] | Should -Be $script:R381Snap -Because 'the backup recorded before the failure is the undo reference'
                    $errs = @(Undo-IgwtChangeGroup -Session $session -Group 'g1' -Confirm:$false)
                    $errs.Count | Should -Be 0
                    $script:R381Restored | Should -Be @($script:R381Snap)
                } finally { Complete-IgwtChangeSession -Session $session }
            } finally {
                $script:IgwtChangeProviders['module'].Restore = $orig
                $script:IgwtModuleOperations.Remove('Invoke-IgwtR381Writer')
            }
        }
    }
    It 'a writer that fails before any backup still has no reference (nothing to restore)' {
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null
            function script:Invoke-IgwtR381Early { [CmdletBinding()] param([string]$Target) throw 'refused before any change' }
            $script:IgwtModuleOperations['Invoke-IgwtR381Early'] = 'snapshot'
            try {
                $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test'; ref = 'E1b' }) -Title 'E1 test b' -Confirm:$false
                try {
                    $s = Invoke-IgwtModuleOperationStep -Session $session -Command 'Invoke-IgwtR381Early' -Parameters @{ Target = 'x' } -Group 'g2' -Confirm:$false
                    $s.Step.Result | Should -Be 'Failed'
                    $s.Step.Applied | Should -BeNullOrEmpty
                } finally { Complete-IgwtChangeSession -Session $session }
            } finally { $script:IgwtModuleOperations.Remove('Invoke-IgwtR381Early') }
        }
    }
}

Describe 'Review 3.8.1 P-01/P-08: strict true/false parsing for policy values' {
    It 'reads bools, 0/1 and the usual words, and refuses anything else' {
        InModuleScope iGWindowsTuner {
            foreach ($t in @($true, 1, '1', 'true', 'TRUE', 'yes', 'On', ' true ')) { ConvertTo-IgwtStrictBool -Value $t | Should -BeTrue -Because "$t" }
            foreach ($f in @($false, 0, '0', 'false', 'False', 'no', 'OFF')) { ConvertTo-IgwtStrictBool -Value $f | Should -BeFalse -Because "$f" }
            foreach ($x in @('maybe', '', '2', 5, $null)) { { ConvertTo-IgwtStrictBool -Value $x -Label 'Test' } | Should -Throw "*not true or false for 'Test'*" -Because "$x" }
        }
    }
}

Describe 'Review 3.8.1 P-26/P-28: one write guard for every policy path' {
    It 'refuses UEFI-lock values in the general guard, with or without a class' {
        InModuleScope iGWindowsTuner {
            Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\Microsoft\Windows\System'; ValueName = 'RunAsPPL'; Type = 'DWord'; Value = 1 }) | Should -BeLike '*UEFI lock*'
            Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; ValueName = 'LsaCfgFlags'; Type = 'DWord'; Value = 1 }) -Class Machine | Should -BeLike '*UEFI lock*'
            Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\Microsoft\Windows\System'; ValueName = 'RunAsPPL'; Type = 'DWord'; Value = 2 }) | Should -BeNullOrEmpty -Because 'value 2 has no UEFI lock'
        }
    }
    It 'refuses a secpol Registry Values entry that sets RunAsPPL=1 on the Lsa key' {
        InModuleScope iGWindowsTuner {
            $k = 'MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL'
            $prop = New-IgwtInfSectionTable; $prop['Registry Values'] = New-IgwtInfSectionTable
            $prop['Registry Values'][$k] = '4,1'
            $id = [pscustomobject]@{ Name = 'PC\a'; Sid = 'S-1-5-21-1-2-3-1001'; GroupSids = @('S-1-5-32-544'); IsRemote = $false }
            $acc = [pscustomobject]@{ Readable = $true; AdminsKnown = $true; Accounts = @() }
            $why = @(Test-IgwtSecurityPolicySafeguards -Proposed $prop -Changed @("Registry Values\$k") -Identity $id -Accounts $acc)
            ($why -join ' ') | Should -BeLike '*UEFI lock*'
        }
    }
}

Describe 'Review 3.8.1 R-1/CP-1/P-1: a restore that cannot reach its target fails instead of reporting success' {
    It 'adapter registry: restores the present adapter, then fails naming the missing one' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtRegistryTargets { @([pscustomobject]@{ Scope = 'nic-present'; Path = 'HKLM:\SOFTWARE\R381\Nic'; Name = 'Value' }) }
            Mock Restore-IgwtRegistryItem { }
            Mock Get-IgwtRegistryBridgeTarget { $null }
            $action = [pscustomobject]@{ type = 'adapterRegistry'; name = 'Value' }
            $snap = [pscustomobject]@{ items = @([pscustomobject]@{ scope = 'nic-present'; exists = $true }, [pscustomobject]@{ scope = 'nic-gone'; exists = $true }) }
            { Restore-IgwtRegistrySnapshot -Action $action -Snapshot $snap -Confirm:$false } | Should -Throw '*nic-gone*not present*'
            Should -Invoke Restore-IgwtRegistryItem -Times 1 -Exactly
        }
    }
    It 'power plan: fails when the plan that was active before no longer exists' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtPowerSchemeExists { $false }
            Mock Invoke-IgwtPowerCfg { [pscustomobject]@{ ExitCode = 0; Output = '' } }
            $snap = [pscustomobject]@{ previousActive = '381b0d2a-0000-4000-8000-000000000001' }
            { Restore-IgwtPowerCfgSchemeSnapshot -Action ([pscustomobject]@{ type = 'powercfgScheme' }) -Snapshot $snap -Confirm:$false } | Should -Throw '*no longer exists*'
            Should -Invoke Invoke-IgwtPowerCfg -Times 0 -Exactly
        }
    }
    It 'interrupt devices: a restore also reaches a device that stopped working' {
        InModuleScope iGWindowsTuner {
            Mock Get-PnpDevice { @([pscustomobject]@{ InstanceId = 'PCI\VEN_10DE&DEV_0001\1'; Status = 'Error'; FriendlyName = 'GPU' }, [pscustomobject]@{ InstanceId = 'PCI\VEN_8086&DEV_0002\2'; Status = 'OK'; FriendlyName = 'iGPU' }) }
            @(Get-IgwtInterruptDevices -Class Display).Count | Should -Be 1 -Because 'apply only targets working devices'
            @(Get-IgwtInterruptDevices -Class Display -IncludeFailed).Count | Should -Be 2 -Because 'restore must reach the failing GPU'
        }
    }
}

Describe 'Review 3.8.1 G-02/PP-1/FOR-1: GUI changes do exactly what was shown and confirmed' {
    It 'G-02: staged sets compare by ids, order ignored' {
        InModuleScope iGWindowsTuner {
            $a = [pscustomobject]@{ Apply = @('a', 'b'); Off = @(); Reset = @('r') }
            Test-IgwtGuiStagedSetsEqual -A $a -B ([pscustomobject]@{ Apply = @('b', 'a'); Off = @(); Reset = @('r') }) | Should -BeTrue
            Test-IgwtGuiStagedSetsEqual -A $a -B ([pscustomobject]@{ Apply = @('a', 'b', 'c'); Off = @(); Reset = @('r') }) | Should -BeFalse
            Test-IgwtGuiStagedSetsEqual -A $a -B ([pscustomobject]@{ Apply = @('a', 'b'); Off = @('x'); Reset = @('r') }) | Should -BeFalse
        }
    }
    It 'PP-1: the policy toast Undo refuses when a newer GPO backup exists and asks before restoring' {
        $b = Join-Path $TestDrive 'PolBackups'
        $null = New-Item -ItemType Directory -Path (Join-Path $b 'gpo-20261119-100000-000') -Force
        InModuleScope iGWindowsTuner -Parameters @{ B = $b } {
            param($B)
            Mock Start-IgwtGuiJob { $true }
            Mock Show-IgwtGuiMessage { 'No' }
            Invoke-IgwtGuiPolicyUndo -Backup (Join-Path $B 'gpo-20261119-100000-000')
            Should -Invoke Start-IgwtGuiJob -Times 0 -Exactly -Because 'the user said No'
            Mock Show-IgwtGuiMessage { 'Yes' }
            Invoke-IgwtGuiPolicyUndo -Backup (Join-Path $B 'gpo-20261119-100000-000')
            Should -Invoke Start-IgwtGuiJob -Times 1 -Exactly
            $null = New-Item -ItemType Directory -Path (Join-Path $B 'gpo-20261119-110000-000') -Force
            Invoke-IgwtGuiPolicyUndo -Backup (Join-Path $B 'gpo-20261119-100000-000')
            Should -Invoke Start-IgwtGuiJob -Times 1 -Exactly -Because 'a later policy change exists; the journal keeps it'
        }
    }
    It 'FOR-1: a refused automatic forensic stop clears the flag and is retried by the session clock' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ IsAdmin = $true; Forensic = @{ State = $null; Stopping = $false; RetryStop = $false; Running = $false; Timer = $null } }
                Mock Test-IgwtReadOnly { $false }
                Mock Get-IgwtForensicSession { [pscustomobject]@{ Expired = $true; Corrupt = $false } }
                Mock Start-IgwtGuiJob { $false }
                Mock Set-IgwtGuiStatus { }
                Mock Update-IgwtGuiForensicBanner { }
                Invoke-IgwtGuiForensicStop -Automatic
                $script:Gui.Forensic.Stopping | Should -BeFalse
                $script:Gui.Forensic.RetryStop | Should -BeTrue
                Update-IgwtGuiForensicSession
                Should -Invoke Start-IgwtGuiJob -Times 2 -Exactly -Because 'the clock retries the restore'
            } finally { $script:Gui = $saved }
        }
    }
}

Describe 'Review 3.8.1 CU-1: every inline C# block compiles and declares the type the code uses' {
    It 'the native helper compiles to iGWindowsTuner.NativeMethods' {
        InModuleScope iGWindowsTuner {
            $script:IgwtNativeSource | Should -Match 'namespace iGWindowsTuner\s'
            { Initialize-IgwtNative } | Should -Not -Throw
            ('iGWindowsTuner.NativeMethods' -as [type]) | Should -Not -BeNullOrEmpty -Because 'the mouse and keyboard handlers call [iGWindowsTuner.NativeMethods]'
        }
    }
    It 'every type the PowerShell code calls in square brackets is declared by an inline or engine C# source' {
        $root = Join-Path $PSScriptRoot '..\src'
        $cs = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.cs' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw })
        $ps = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw })
        $declared = @(foreach ($t in @($cs) + @($ps)) { foreach ($m in [regex]::Matches($t, 'namespace\s+([A-Za-z_][\w\.]*)')) { $m.Groups[1].Value } })
        $declared | Should -Not -Contain 'iG' -Because 'a namespace with spaces does not compile'
        foreach ($ns in 'iGWindowsTuner', 'IgwtJournal') { $declared | Should -Contain $ns }
    }
}

Describe 'Review 3.8.1 E2/E3: unfinished recoveries and failed rollbacks stay offered' {
    It 'offers an incomplete recovery again, an ended session with a failed rollback, and not a finished recovery' {
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null
            $tg = [ordered]@{ provider = 'action'; key = 'action|x|0|fp'; item = 'x'; index = 0; type = 'registry'; fingerprint = 'fp' }
            $add = { param($e) $null = Add-IgwtJournalEntry -Entry $e }
            foreach ($sid in 'S-incomplete', 'S-rbfail', 'S-done') {
                & $add ([ordered]@{ kind = 'sessionStart'; session = $sid; origin = @{ type = 'tweak' }; title = $sid })
                & $add ([ordered]@{ kind = 'intent'; session = $sid; step = 1; group = 'g'; op = 'change'; item = 'x'; target = $tg; before = @{ v = 1 } })
                & $add ([ordered]@{ kind = 'committed'; session = $sid; step = 1; group = 'g'; op = 'change'; item = 'x'; target = $tg; before = @{ v = 1 }; after = @{ v = 2 } })
            }
            & $add ([ordered]@{ kind = 'sessionEnd'; session = 'S-incomplete'; outcome = 'recovery-incomplete'; by = 'R1' })
            & $add ([ordered]@{ kind = 'rollbackFailed'; session = 'S-rbfail'; step = 1; group = 'g'; item = 'x'; target = $tg; error = 'locked' })
            & $add ([ordered]@{ kind = 'sessionEnd'; session = 'S-rbfail'; outcome = 'partial'; steps = 1; failed = 1 })
            & $add ([ordered]@{ kind = 'sessionEnd'; session = 'S-done'; outcome = 'recovered'; by = 'R2' })
            $script:IgwtJournal = $null
            $inc = @(Get-IgwtIncompleteChangeSession -Journal (Read-IgwtJournal))
            $ids = @($inc | ForEach-Object { $_.Id })
            $ids | Should -Contain 'S-incomplete' -Because 'a recovery that did not finish is offered again (E2)'
            @(($inc | Where-Object Id -EQ 'S-incomplete').Steps).Count | Should -Be 1 -Because 'its committed step may still be changed'
            $ids | Should -Contain 'S-rbfail' -Because 'a failed rollback leaves a change in place (E3)'
            $ids | Should -Not -Contain 'S-done'
        }
    }
}

Describe 'Review 3.8.1 CLI-01: the elevated relaunch passes every argument exactly' {
    It 'quotes by the Windows rules' {
        InModuleScope iGWindowsTuner {
            ConvertTo-IgwtCommandLineArgument -Value 'plain' | Should -Be 'plain'
            ConvertTo-IgwtCommandLineArgument -Value '' | Should -Be '""'
            ConvertTo-IgwtCommandLineArgument -Value 'C:\My Reports\' | Should -Be '"C:\My Reports\\"'
            ConvertTo-IgwtCommandLineArgument -Value 'a"b c' | Should -Be '"a\"b c"'
        }
    }
    It 'a powershell.exe -File child reads the arguments back unchanged (no argument is split or added)' {
        $script = Join-Path $TestDrive 'echo-args.ps1'
        Set-Content -LiteralPath $script -Value '$args | ForEach-Object { "<$_>" }' -Encoding ASCII
        $values = @('C:\My Reports\', '-ReportPath', 'x" -AcknowledgeRisk "y', 'two words')
        $line = InModuleScope iGWindowsTuner -Parameters @{ V = $values } { param($V) (@($V | ForEach-Object { ConvertTo-IgwtCommandLineArgument -Value $_ }) -join ' ') }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Join-Path $PSHOME 'powershell.exe')
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" $line"
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi); $out = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
        @($out -split "`r?`n" | Where-Object { $_ }) | Should -Be @($values | ForEach-Object { "<$_>" })
    }
}
