# 4.0 section 6: Network page (D7), Clean tabs, and NET-1, R-2, CLN-3, CLN-4, RC-1, RC-2, AP-2, OF-2, DF-1, DF-2.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:Root = Split-Path -Parent $PSScriptRoot
}

Describe 'Clean and Network tabs' {
    It 'shows Files (temporary files and Storage Sense), Startup apps, Registry leftovers and Disk' {
        InModuleScope iGWindowsTuner {
            $sec = @($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Clean' })[0]
            $tabs = @(Get-IgwtGuiSectionTabList -Section $sec -Pages @($sec.Pages))
            @($tabs.Label) | Should -Be @('Files', 'Startup apps', 'Registry leftovers', 'Disk')
            @($tabs[0].Pages) | Should -Be @('Cleaner', 'Storage')
        }
    }
    It 'names blocked programs that share a file name by their folder' {
        InModuleScope iGWindowsTuner {
            $b = @([pscustomobject]@{ Name = 'certutil.exe'; Folder = 'System32'; Rules = 1; Directions = 'Outbound' }, [pscustomobject]@{ Name = 'certutil.exe'; Folder = 'SysWOW64'; Rules = 1; Directions = 'Outbound' }, [pscustomobject]@{ Name = 'game.exe'; Folder = 'Game'; Rules = 2; Directions = 'Inbound' })
            $l = @(Get-IgwtGuiBlockedProgramLines -Blocked $b)
            $l[0] | Should -Be 'certutil.exe (System32) - 1 rule, outbound'
            $l[2] | Should -Be 'game.exe - 2 rules, inbound'
            @(Get-IgwtGuiBlockedProgramLines -Blocked @($b + $b + $b) -Max 8)[-1] | Should -Be 'and 1 more'
        }
    }
    It 'draws the DNS, network profile and blocked programs cards' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $w = New-IgwtMainWindow
                $script:Gui = @{ Window = $w; IsAdmin = $true; C = @{ NetCardsHost = $w.FindName('NetCardsHost') }
                    NetOverview = [pscustomobject]@{ Profiles = @([pscustomobject]@{ Name = 'Home'; Interface = 'Ethernet'; InterfaceIndex = 5; Category = 'Public' }); ProfileError = ''
                        Dns = @([pscustomobject]@{ Interface = 'Ethernet'; Servers = @('1.1.1.1'); Encrypted = @('1.1.1.1') }); DnsError = ''; Blocked = @(); BlockedError = '' } }
                Mock Test-IgwtReadOnly { $false }
                Update-IgwtGuiNetCards
                $texts = @(Get-IgwtUiDescendant -Root $script:Gui.C.NetCardsHost | Where-Object { $_ -is [System.Windows.Controls.TextBlock] } | ForEach-Object { $_.Text })
                foreach ($h in 'DNS', 'Network profile', 'Blocked programs', 'Encrypted (DNS over HTTPS)', 'No program is blocked by a firewall rule.') { $texts | Should -Contain $h }
                $sw = @(Get-IgwtUiDescendant -Root $script:Gui.C.NetCardsHost | Where-Object { $_ -is [System.Windows.Controls.Button] -and [string]$_.Tag -like 'net|*' })[0]
                [string]$sw.Tag | Should -Be 'net|5|Private'
            } finally { $script:Gui = $saved }
        }
    }
}

Describe 'Network engine (NET-1, R-2)' {
    It 'never says "reverted" when the automatic revert failed (NET-1)' {
        $src = Get-Content (Join-Path $script:Root 'src\Network\GamingOptimizer.ps1') -Raw
        $src | Should -Match 'the automatic revert did not finish'
        $src | Should -Match '\$out\.RevertedAutomatically = \(-not \$why\)'
        $src | Should -Not -Match '\$null = Invoke-IgwtRevert -SnapshotPath \$applied\.Snapshot'
    }
    It 'counts a wired adapter that reports medium 0 but MediaType 802.3, never a Wi-Fi one (R-2)' {
        InModuleScope iGWindowsTuner {
            Clear-IgwtCache -Prefix 'net:' -WhatIf:$false
            Mock Get-NetAdapter { @(
                    [pscustomobject]@{ Name = 'USB LAN'; Status = 'Up'; Virtual = $false; InterfaceDescription = 'USB Ethernet'; PhysicalMediaType = 'Unspecified'; NdisPhysicalMedium = 0; MediaType = '802.3' }
                    [pscustomobject]@{ Name = 'Wi-Fi'; Status = 'Up'; Virtual = $false; InterfaceDescription = 'Wireless'; PhysicalMediaType = 'Native 802.11'; NdisPhysicalMedium = 9; MediaType = '802.3' }
                ) }
            @(Get-IgwtActiveWiredAdapter | ForEach-Object { $_.Name }) | Should -Be @('USB LAN')
            Clear-IgwtCache -Prefix 'net:' -WhatIf:$false
        }
    }
}

Describe 'Cleaner (CLN-3, CLN-4)' {
    It 'refuses per-user rules at scan time under another administrator''s account (CLN-3)' {
        InModuleScope iGWindowsTuner {
            $rule = [pscustomobject]@{ id = 'clean.t'; name = 'Temp'; method = 'files'; roots = @('%TEMP%'); recycle = $false; allowDownloads = $false }
            Test-IgwtCleanerRulePerUser -Rule $rule | Should -BeTrue
            Test-IgwtCleanerRulePerUser -Rule ([pscustomobject]@{ method = 'files'; roots = @('%SystemRoot%\Temp') }) | Should -BeFalse
            Mock Get-IgwtOtherAdminElevation { 'S-1-5-21-9-9-9-1001' }
            $r = Invoke-IgwtCleanerRuleScan -Rule $rule
            $r.Status | Should -Be 'Refused'
            $r.Reason | Should -Match "another administrator's account"
        }
    }
    It 'expands {SteamInstall} to the Steam install folder only (CLN-4)' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtSteamLibraryPaths { @('C:\Steam', 'D:\Games') }
            @(Expand-IgwtCleanerRootTemplate -Template '{SteamInstall}\logs') | Should -Be @('C:\Steam\logs')
            @(Expand-IgwtCleanerRootTemplate -Template '{SteamLibrary}\steamapps\shadercache').Count | Should -Be 2
            (Get-Content (Join-Path $script:IgwtProjectRoot 'data\cleaner\gaming.json') -Raw) | Should -Match '\{SteamInstall\}\\\\logs'
        }
    }
}

Describe 'Registry cleaner (RC-1, RC-2)' {
    It 'protects vendor and product key names and matches providers both ways (RC-1)' {
        $src = Get-Content (Join-Path $script:Root 'src\Cleaner\RegistryCleanerProtection.ps1') -Raw
        $src | Should -Match "Category -eq 'softwareKey'\) \{ \`$after = \`$false"
        $src | Should -Match "\`$pn -like \(\[string\]\`$n \+ '\*'\)"
    }
    It 'tests the vendor folder, skips recently-used values and never offers AppDataLow (RC-2)' {
        (Get-Content (Join-Path $script:Root 'src\Cleaner\RegistryCleanerOwners.ps1') -Raw) | Should -Match '(?m)^\s*if \(\$Candidate\.Vendor\) \{ \$names\.Add'
        (Get-Content (Join-Path $script:Root 'src\Cleaner\RegistryCleanerScan.ps1') -Raw) | Should -Match '\(MRU\|Last\|Recent\)'
        ((Get-Content (Join-Path $script:Root 'data\registry\categories.json') -Raw | ConvertFrom-Json).denyList.vendorNames) | Should -Contain 'AppDataLow'
    }
}

Describe 'Restore exactness (AP-2, OF-2, DF-1, DF-2)' {
    It 'does not try to reinstall removed apps on a rollback and says they stay removed (AP-2)' {
        $eng = Get-Content (Join-Path $script:Root 'src\Core\Engine.ps1') -Raw
        $eng | Should -Match "type -in 'appx', 'winget', 'capability', 'cleanerRule'\) \{ if \(\`$j -lt \`$done\)"
        (Get-Content (Join-Path $script:Root 'src\Core\Transaction.ps1') -Raw) | Should -Match 'reinstall removed apps from the Microsoft Store'
    }
    It 'keeps and restores the child features of an optional feature (OF-2)' {
        InModuleScope iGWindowsTuner {
            Mock Get-WindowsOptionalFeature { if ($FeatureName) { [pscustomobject]@{ FeatureName = $FeatureName; State = 'Disabled' } } else { @([pscustomobject]@{ FeatureName = 'SMB1Protocol-Client'; State = 'Disabled' }, [pscustomobject]@{ FeatureName = 'SMB1Protocol-Server'; State = 'Disabled' }, [pscustomobject]@{ FeatureName = 'Other'; State = 'Enabled' }) } }
            $kids = Get-IgwtOptionalFeatureChildStates -Feature 'SMB1Protocol'
            @($kids.Keys | Sort-Object) | Should -Be @('SMB1Protocol-Client', 'SMB1Protocol-Server')
            $script:Set = New-Object System.Collections.Generic.List[string]
            Mock Set-IgwtOptionalFeature { $script:Set.Add("$Feature=$State") }
            Restore-IgwtOptionalFeatureSnapshot -Action ([pscustomobject]@{ feature = 'SMB1Protocol' }) -Snapshot @{ feature = 'SMB1Protocol'; state = 'Enabled'; children = @{ 'SMB1Protocol-Client' = 'Enabled'; 'SMB1Protocol-Server' = 'Disabled' } }
            @($script:Set) | Should -Be @('SMB1Protocol=Enabled', 'SMB1Protocol-Client=Enabled')
        }
    }
    It 'fails a Defender write that Tamper Protection or a policy ignored (DF-1)' {
        InModuleScope iGWindowsTuner {
            Mock Set-MpPreference { }
            Mock Get-IgwtMpPreferenceValue { 0 }
            { Set-IgwtMpPreferenceValue -Setting 'PUAProtection' -Value 1 -Confirm:$false } | Should -Throw '*Defender kept PUAProtection at 0*'
            Mock Get-IgwtMpPreferenceValue { 1 }
            { Set-IgwtMpPreferenceValue -Setting 'PUAProtection' -Value 1 -Confirm:$false } | Should -Not -Throw
        }
    }
    It 'leaves PUA protection as it is on reset to default (DF-2)' {
        InModuleScope iGWindowsTuner {
            Mock Set-IgwtMpPreferenceValue { $script:Wrote = $true }
            Mock Get-IgwtMpPreferenceValue { 1 }
            $script:Wrote = $false
            Invoke-IgwtMpPreferenceApply -Action ([pscustomobject]@{ setting = 'PUAProtection'; on = 1; default = 0; keepOnReset = $true }) -Mode default
            $script:Wrote | Should -BeFalse
            $a = @((Get-Content (Join-Path $script:IgwtProjectRoot 'data\tweaks\security.json') -Raw | ConvertFrom-Json).tweaks | Where-Object { $_.id -eq 'sec.defender-hardening' })[0].actions | Where-Object { $_.setting -eq 'PUAProtection' }
            $a.keepOnReset | Should -BeTrue
        }
    }
}
