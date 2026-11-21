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

Describe 'Review 4.0 TW-3 to TW-12: catalog claims match what the items do' {
    BeforeAll { $script:Cat = @(Get-IgwtCatalog -Force) }
    It 'marks the Storage Sense deletion items as partly reversible, with the side effect stated' {
        foreach ($id in 'storage.downloads-60-days', 'storage.recycle-bin-30-days') {
            $t = @($script:Cat | Where-Object { $_.id -eq $id })[0]
            $t.reversible | Should -Be 'partial' -Because "$id deletes files"
            [string]$t.sideEffects | Should -Match 'gone for good'
        }
    }
    It 'says that the network throttling sources do not describe the value, and keeps it Measure it' {
        $t = @($script:Cat | Where-Object { $_.id -eq 'sched.network-throttling-off' })[0]
        $t.evidence.tier | Should -Be 'B'
        [string]$t.evidence.notes | Should -Match 'do not describe NetworkThrottlingIndex'
    }
    It 'blocks the processor idle Risk Zone item on laptops, like the other battery-draining items' {
        $o = @((Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'data\hardware\overlays.json') -Raw | ConvertFrom-Json).overlays | Where-Object { @($_.tags) -contains 'formfactor.laptop' -and @($_.block) -contains 'net.wifi-disable' })[0]
        # By setting, not by id: a Risk Zone id in 'block' fails the overlay check on data folders without riskzone.json.
        @($o.block) | Should -Not -Contain 'risk.processor-idle-disable'
        $setting = [string](@((Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'data\tweaks\riskzone.json') -Raw | ConvertFrom-Json).tweaks | Where-Object { $_.id -eq 'risk.processor-idle-disable' })[0].actions[0].setting)
        $setting | Should -Not -BeNullOrEmpty
        @($o.blockMatching | Where-Object { $_.type -eq 'powercfgSetting' } | ForEach-Object { @($_.setting) }) | Should -Contain $setting
    }
    It 'keeps the edition limits, anti-cheat flag and laptop blocks fixed in 3.8.2' {
        foreach ($id in 'sec.network-protection', 'privacy.keep-drivers', 'privacy.update-active-hours', 'privacy.defer-feature-90', 'privacy.defer-feature-365') {
            @((@($script:Cat | Where-Object { $_.id -eq $id })[0]).editions) | Should -Not -Contain 'Core' -Because "$id is ignored on Home"
            @((@($script:Cat | Where-Object { $_.id -eq $id })[0]).editions).Count | Should -BeGreaterThan 0
        }
        (@($script:Cat | Where-Object { $_.id -eq 'sec.kernel-shadow-stacks' })[0]).antiCheat | Should -Not -Be 'safe'
    }
}
