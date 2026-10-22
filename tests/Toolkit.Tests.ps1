# Toolkit (WinUtil-derived section): catalog rules, winget agreement gating, app selection files,
# fixes, panels, features, edition gating and the registry handler extensions the derived items
# need (bitSet, default value, HKU:\.DEFAULT). Every system call is mocked.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Toolkit catalog' {
    It 'validates without errors' {
        @(Test-IgwtToolkitCatalog) | Should -BeNullOrEmpty
    }
    It 'has every section with real texts' {
        @(Get-IgwtToolkitApps).Count | Should -BeGreaterThan 50
        @(Get-IgwtToolkitFeatures).Count | Should -BeGreaterOrEqual 8
        @(Get-IgwtToolkitFixes).Count | Should -BeGreaterOrEqual 10
        @(Get-IgwtToolkitPanels).Count | Should -BeGreaterOrEqual 20
        foreach ($a in @(Get-IgwtToolkitApps)) { $a.Hint.Length | Should -BeLessOrEqual 140 }
    }
    It 'never offers Sysmon, Chocolatey or a "disable updates" item' {
        @(Get-IgwtToolkitApps | Where-Object { $_.Id -in 'Microsoft.Sysinternals.Sysmon', 'Chocolatey.Chocolatey' }) | Should -BeNullOrEmpty
        foreach ($t in @(Get-IgwtToolkitUpdateItems)) { $t.hint | Should -Not -Match '(?i)disable (all )?(windows )?updates' }
    }
    It 'lists the WinUtil-derived items with an attribution' {
        $w = @(Get-IgwtToolkitTweaks)
        $w.Count | Should -BeGreaterOrEqual 15
        foreach ($t in $w) { [string]$t.attribution | Should -Match 'WinUtil' }
    }
    It 'refuses fix steps and panels outside the allow-lists' {
        InModuleScope iGWindowsTuner {
            { Resolve-IgwtFixExecutable -Name 'powershell.exe' } | Should -Throw '*not an allowed*'
            { Resolve-IgwtPanelCommand -Panel ([pscustomobject]@{ launch = 'exe'; target = 'cmd.exe'; name = 'x' }) } | Should -Throw '*not an allowed*'
            { Resolve-IgwtPanelCommand -Panel ([pscustomobject]@{ launch = 'uri'; target = 'https://example.com'; name = 'x' }) } | Should -Throw '*ms-settings*'
            { Resolve-IgwtPanelCommand -Panel ([pscustomobject]@{ launch = 'msc'; target = '..\evil.msc'; name = 'x' }) -NoFileCheck } | Should -Throw '*management console*'
        }
    }
}

Describe 'Toolkit install (winget)' {
    BeforeEach {
        $script:WingetCalls = New-Object System.Collections.Generic.List[string]
        $script:Installed = @{ 'Valve.Steam' = $false; 'VideoLAN.VLC' = $true }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtWinget {
            $script:WingetCalls.Add(($Arguments -join ' '))
            $id = $Arguments[2]
            switch ($Arguments[0]) {
                'list' { if ($script:Installed[$id]) { [pscustomobject]@{ ExitCode = 0; Output = '' } } else { [pscustomobject]@{ ExitCode = -1978335212; Output = '' } } }
                'install' { $script:Installed[$id] = $true; [pscustomobject]@{ ExitCode = 0; Output = '' } }
                'uninstall' { $script:Installed[$id] = $false; [pscustomobject]@{ ExitCode = 0; Output = '' } }
                'upgrade' { [pscustomobject]@{ ExitCode = -1978335189; Output = '' } }
                'export' { [System.IO.File]::WriteAllText($Arguments[2], '{"Sources":[{"Packages":[{"PackageIdentifier":"VideoLAN.VLC","Version":"3.0.24"}]}]}'); [pscustomobject]@{ ExitCode = 0; Output = '' } }
            }
        }
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $null; Clear-IgwtCache -WhatIf:$false }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $null } }
    It 'refuses to install before the agreements are accepted' {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $false }
        { Invoke-IgwtToolkitApp -Operation Install -Id 'Valve.Steam' } | Should -Throw '*agreements*'
        @($script:WingetCalls | Where-Object { $_ -like 'install*' }) | Should -BeNullOrEmpty
    }
    It 'installs with the accept flags only after acceptance, and skips installed packages' {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $false }
        $r = @(Invoke-IgwtToolkitApp -Operation Install -Id 'Valve.Steam', 'VideoLAN.VLC' -AcceptAgreements)
        ($r | Where-Object Id -eq 'Valve.Steam').Result | Should -Be 'Installed'
        ($r | Where-Object Id -eq 'VideoLAN.VLC').Result | Should -Be 'AlreadyInstalled'
        $inst = @($script:WingetCalls | Where-Object { $_ -like 'install*' })
        $inst.Count | Should -Be 1
        $inst[0] | Should -Match '--accept-package-agreements'
        $inst[0] | Should -Match '--source winget'
    }
    It 'uninstalls without needing the agreements' {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $false }
        (@(Invoke-IgwtToolkitApp -Operation Uninstall -Id 'VideoLAN.VLC'))[0].Result | Should -Be 'Uninstalled'
    }
    It 'reports an upgrade that is not applicable as up to date' {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $true }
        (@(Invoke-IgwtToolkitApp -Operation Upgrade -Id 'VideoLAN.VLC'))[0].Result | Should -Be 'UpToDate'
    }
    It 'refuses Sysmon and malformed ids' {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.WingetConsent = $true }
        { Invoke-IgwtToolkitApp -Operation Install -Id 'Microsoft.Sysinternals.Sysmon' } | Should -Throw '*never installed*'
        { Invoke-IgwtToolkitApp -Operation Install -Id 'bad id; rm' } | Should -Throw '*not a valid winget*'
    }
    It 'reads the installed inventory from one winget export' {
        $apps = @(Get-IgwtToolkitApps -WithState)
        ($apps | Where-Object Id -eq 'VideoLAN.VLC').Installed | Should -BeTrue
        ($apps | Where-Object Id -eq 'VideoLAN.VLC').Version | Should -Be '3.0.24'
        ($apps | Where-Object Id -eq 'Valve.Steam').Installed | Should -BeFalse
        @($script:WingetCalls | Where-Object { $_ -like 'export*' }).Count | Should -Be 1
    }
    It 'round-trips an app selection file and detects changes' {
        $p = Join-Path $TestDrive 'apps.json'
        Export-IgwtAppSelection -Path $p -Id 'Valve.Steam', 'VideoLAN.VLC' | Should -Be $p
        Import-IgwtAppSelection -Path $p | Should -Be @('Valve.Steam', 'VideoLAN.VLC')
        (Get-Content -LiteralPath $p -Raw).Replace('VideoLAN.VLC', 'Evil.Tool') | Set-Content -LiteralPath $p -Encoding UTF8
        { Import-IgwtAppSelection -Path $p } | Should -Throw '*SHA256*'
    }
}

Describe 'Toolkit fixes' {
    BeforeEach {
        $script:Ops = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName iGWindowsTuner Stop-Service { $script:Ops.Add("stop $Name") }
        Mock -ModuleName iGWindowsTuner Start-Service { $script:Ops.Add("start $Name") }
        Mock -ModuleName iGWindowsTuner Restart-Service { $script:Ops.Add("restart $Name") }
        Mock -ModuleName iGWindowsTuner Test-Path { $true } -ParameterFilter { $LiteralPath -like '*SoftwareDistribution*' -or $LiteralPath -like '*catroot2*' }
        Mock -ModuleName iGWindowsTuner Rename-Item { $script:Ops.Add("rename $LiteralPath -> $NewName") }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtFixProcess { $script:Ops.Add("run $FilePath $($Arguments -join ' ')"); [pscustomobject]@{ ExitCode = 0; Output = 'ok' } }
        Mock -ModuleName iGWindowsTuner Test-IgwtRdpSession { $false }
    }
    It 'previews every step without running anything' {
        $p = Get-IgwtToolkitFixPlan -Id 'fix.windows-update-reset'
        $p.Steps.Count | Should -Be 9
        $p.Steps[3] | Should -Match 'DataStore'
        $script:Ops.Count | Should -Be 0
    }
    It 'runs the Windows Update reset in order and keeps the renamed folders' {
        $r = Invoke-IgwtToolkitFix -Id 'fix.windows-update-reset'
        $r.Result | Should -Be 'Completed'
        $r.RebootRequired | Should -BeTrue
        $script:Ops[0] | Should -Be 'stop bits'
        @($script:Ops | Where-Object { $_ -like 'rename*' }).Count | Should -Be 3
        @($script:Ops | Where-Object { $_ -like 'rename*' })[0] | Should -Match 'DataStore\.igwt-\d{8}-\d{6}$'
        $script:Ops[-1] | Should -Be 'start wuauserv'
    }
    It 'after a failed step still starts the services again but skips the rest' {
        Mock -ModuleName iGWindowsTuner Rename-Item { throw 'Access denied' } -ParameterFilter { $LiteralPath -like '*DataStore' }
        $r = Invoke-IgwtToolkitFix -Id 'fix.windows-update-reset'
        $r.Result | Should -Be 'Failed'
        $r.RebootRequired | Should -BeFalse
        @($r.Steps | Where-Object { $_.Result -eq 'NotRun' }).Count | Should -Be 2
        @($script:Ops | Where-Object { $_ -like 'start *' }).Count | Should -Be 3
    }
    It 'runs only allow-listed System32 programs with fixed arguments' {
        $r = Invoke-IgwtToolkitFix -Id 'fix.chkdsk-scan'
        $r.Result | Should -Be 'Completed'
        $script:Ops[0] | Should -Match ([regex]::Escape((Join-Path $env:SystemRoot 'System32\chkdsk.exe')) + ' ' + [regex]::Escape($env:SystemDrive) + ' /scan$')
    }
    It 'refuses the network reset in a Remote Desktop session' {
        Mock -ModuleName iGWindowsTuner Test-IgwtRdpSession { $true }
        { Invoke-IgwtToolkitFix -Id 'fix.network-reset' } | Should -Throw '*Remote Desktop*'
        $script:Ops.Count | Should -Be 0
    }
    It 'reports a non-zero exit code as a warning, not a failure' {
        Mock -ModuleName iGWindowsTuner Invoke-IgwtFixProcess { [pscustomobject]@{ ExitCode = 1; Output = 'inconsistent' } }
        (Invoke-IgwtToolkitFix -Id 'fix.wmi-verify').Result | Should -Be 'CompletedWithWarnings'
    }
}

Describe 'CLI help' {
    It 'documents every CLI parameter in valid comment-based help (docs\CLI.md is generated from it)' {
        $file = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
        $help = $ast.GetHelpContent()
        $help | Should -Not -BeNullOrEmpty
        $documented = @($help.Parameters.Keys | ForEach-Object { $_.ToUpperInvariant() })
        foreach ($p in @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } | Where-Object { $_ -ne 'ElevatedRelaunch' })) { $documented | Should -Contain $p.ToUpperInvariant() -Because $p }
    }
}

Describe 'Toolkit TestMode guards' {
    It 'never runs fix programs or opens panels for real in TestMode' {
        InModuleScope iGWindowsTuner {
            { Invoke-IgwtFixProcess -FilePath 'C:\Windows\System32\sfc.exe' -Arguments @('/scannow') } | Should -Throw '*TestMode*'
            { Invoke-IgwtPanelProcess -FilePath 'C:\Windows\System32\control.exe' } | Should -Throw '*TestMode*'
        }
    }
}

Describe 'Toolkit panels' {
    It 'opens consoles through mmc.exe and Control Panel items through control.exe' {
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPanelProcess { }
        Mock -ModuleName iGWindowsTuner Test-Path { $true } -ParameterFilter { $LiteralPath -like '*.msc' -or $LiteralPath -like '*.cpl' }
        Start-IgwtPanel -Id 'panel.device-manager'
        Should -Invoke Invoke-IgwtPanelProcess -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $FilePath -like '*\System32\mmc.exe' -and $Arguments[0] -like '*\devmgmt.msc' }
        Start-IgwtPanel -Id 'panel.sound'
        Should -Invoke Invoke-IgwtPanelProcess -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $FilePath -like '*\System32\control.exe' -and $Arguments[0] -eq 'mmsys.cpl' }
    }
    It 'reports gpedit as unavailable when the console is missing (Home)' {
        Mock -ModuleName iGWindowsTuner Test-Path { $false } -ParameterFilter { $LiteralPath -like '*gpedit.msc' }
        { Start-IgwtPanel -Id 'panel.gpedit' } | Should -Throw '*not available on this edition*'
    }
}

Describe 'Toolkit features and edition gating' {
    It 'maps EditionID values to edition families' {
        Get-IgwtEditionFamily -EditionId 'Professional' | Should -Be 'Professional'
        Get-IgwtEditionFamily -EditionId 'ProfessionalWorkstation' | Should -Be 'Professional'
        Get-IgwtEditionFamily -EditionId 'ProfessionalEducation' | Should -Be 'Education'
        Get-IgwtEditionFamily -EditionId 'Core' | Should -Be 'Home'
        Get-IgwtEditionFamily -EditionId 'CoreSingleLanguage' | Should -Be 'Home'
        Get-IgwtEditionFamily -EditionId 'EnterpriseS' | Should -Be 'Enterprise'
        Get-IgwtEditionFamily -EditionId 'ServerDatacenter' | Should -Be 'Server'
        Test-IgwtEditionSupported -Editions @('Enterprise', 'Education') -EditionId 'Professional' | Should -BeFalse
        Test-IgwtEditionSupported -Editions @() -EditionId 'Core' | Should -BeTrue
        Test-IgwtEditionSupported -Editions @('Enterprise') -EditionId '' | Should -BeTrue
    }
    It 'shows an Enterprise-only policy as not effective on Pro' {
        $t = Get-IgwtTweak -Id 'privacy.consumer-features-off'
        $s = Get-IgwtTweakState -Tweak $t -Context (New-IgwtTestContext)
        $s.State | Should -Be 'NotApplicable'
        $s.Reason | Should -Match 'Not effective on this edition'
        (Get-IgwtTweakState -Tweak $t -Context (New-IgwtTestContext -Extra @{ EditionId = 'Enterprise' })).State | Should -Be 'Off'
    }
    It 'refuses Hyper-V on Home and enables each WSL target through the managed path' {
        Mock -ModuleName iGWindowsTuner Get-IgwtOsInfo { [pscustomobject]@{ EditionId = 'Core'; Build = 26300 } }
        { Invoke-IgwtToolkitFeature -Id 'feature.hyperv' -State Enabled } | Should -Throw '*not available on this edition*'
        Mock -ModuleName iGWindowsTuner Invoke-IgwtManagedChange { [pscustomobject]@{ Snapshot = 'x'; Changes = 1; Results = @([pscustomobject]@{ Target = $Target; Change = "$Kind $Target -> $Value"; Result = 'Applied'; Message = '' }) } }
        $r = Invoke-IgwtToolkitFeature -Id 'feature.wsl' -State Enabled
        @($r.Results).Count | Should -Be 2
        $r.RebootRequired | Should -BeTrue
        Should -Invoke Invoke-IgwtManagedChange -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Kind -eq 'feature' -and $Target -eq 'VirtualMachinePlatform' -and $Value -eq 'Enabled' }
    }
    It 'allows enabling protected features but never disabling them' {
        Mock -ModuleName iGWindowsTuner Get-WindowsOptionalFeature { [pscustomobject]@{ FeatureName = 'Microsoft-Windows-Subsystem-Linux'; State = 'Disabled' } }
        { Get-IgwtManagedChangePlan -Kind feature -Target 'Microsoft-Windows-Subsystem-Linux' -Value Disabled } | Should -Throw '*never disabled*'
        (Get-IgwtManagedChangePlan -Kind feature -Target 'Microsoft-Windows-Subsystem-Linux' -Value Enabled).HasChange | Should -BeTrue
        { Get-IgwtManagedChangePlan -Kind capability -Target 'OpenSSH.Client~~~~0.0.1.0' -Value NotPresent } | Should -Throw '*never removed*'
    }
}

Describe 'Registry handler extensions for the derived items' {
    It 'bitSet sets one flag, keeps the other bits and restores the exact old value' {
        InModuleScope iGWindowsTuner {
            $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            Set-IgwtRegistryValue -Path $p -Name 'DisabledComponents' -Kind DWord -Value 1
            $a = (Get-IgwtTweak -Id 'net.prefer-ipv4').actions[0]
            (Get-IgwtActionState -Action $a -Context $null)[0].State | Should -Be 'Off'
            $snap = Get-IgwtActionSnapshot -Action $a -Context $null
            $null = Invoke-IgwtActionApply -Action $a -Context $null -Mode on
            (Get-IgwtRegistryValue -Path $p -Name 'DisabledComponents').Value | Should -Be 33
            (Get-IgwtActionState -Action $a -Context $null)[0].State | Should -Be 'On'
            Restore-IgwtActionSnapshot -Action $a -Snapshot ($snap | ConvertTo-Json -Depth 10 | ConvertFrom-Json) -Context $null
            (Get-IgwtRegistryValue -Path $p -Name 'DisabledComponents').Value | Should -Be 1
        }
    }
    It 'counts an existing 0xFF as already preferring IPv4' {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Kind DWord -Value 255
            (Get-IgwtActionState -Action (Get-IgwtTweak -Id 'net.prefer-ipv4').actions[0] -Context $null)[0].State | Should -Be 'On'
        }
    }
    It 'writes and removes a key default value (classic context menu)' {
        InModuleScope iGWindowsTuner {
            $a = (Get-IgwtTweak -Id 'system.classic-context-menu').actions[0]
            $snap = Get-IgwtActionSnapshot -Action $a -Context $null
            $null = Invoke-IgwtActionApply -Action $a -Context $null -Mode on
            (Get-IgwtRegistryValue -Path $a.path -Name '').Exists | Should -BeTrue
            (Get-IgwtActionState -Action $a -Context $null)[0].State | Should -Be 'On'
            Restore-IgwtActionSnapshot -Action $a -Snapshot ($snap | ConvertTo-Json -Depth 10 | ConvertFrom-Json) -Context $null
            Test-IgwtRegistryKey -Path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' | Should -BeFalse
        }
    }
    It 'resolves HKU:\.DEFAULT (sign-in screen) into the test registry' {
        InModuleScope iGWindowsTuner {
            Resolve-IgwtRegistryPath -Path 'HKU:\.DEFAULT\Control Panel\Keyboard' | Should -BeLike 'TestRegistry:*'
            $a = (Get-IgwtTweak -Id 'system.numlock-on-boot').actions[0]
            Set-IgwtRegistryValue -Path $a.path -Name $a.name -Kind String -Value '2147483650'
            (Get-IgwtActionState -Action $a -Context $null)[0].State | Should -Be 'On'
        }
    }
    It 'rejects registry paths outside HKLM, HKCU and HKU:\.DEFAULT, and bitSet with bitClear' {
        $good = Get-IgwtTweak -Id 'system.numlock-on-boot'
        $bad = $good | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $bad.id = 'system.bad-hku'
        $bad.actions[0].path = 'HKU:\S-1-5-18\Control Panel\Keyboard'
        $bits = (Get-IgwtTweak -Id 'net.prefer-ipv4') | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $bits.id = 'net.bad-bits'
        $bits.actions[0] | Add-Member -NotePropertyName bitClear -NotePropertyValue 1 -Force
        $all = @(Get-IgwtCatalog) + @($bad, $bits)
        Mock -ModuleName iGWindowsTuner Get-IgwtCatalog { $all }
        $errors = (@(Test-IgwtCatalog) -join "`n")
        $errors | Should -Match 'system.bad-hku action\[0\]: path must start with'
        $errors | Should -Match 'net.bad-bits action\[0\]: use either bitSet or bitClear'
        $errors | Should -Not -Match 'system.numlock-on-boot action'
    }
}
