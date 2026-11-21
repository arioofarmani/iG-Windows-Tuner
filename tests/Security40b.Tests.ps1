# 4.0 section 5b: Security screens (D6: tabs, ChangeBar providers, toolbar limits) and the GUI findings
# ASR-1, ASR-2, FWH-x, FWP-x, FOR-2, SS-1, plus the 5a leftovers F-15 (b, c) and F-25 (svchost).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:Root = Split-Path -Parent $PSScriptRoot
}

Describe 'Security tabs (D6)' {
    It 'shows four tabs: Overview, Protection (Defender and ASR), Firewall and Policies' {
        InModuleScope iGWindowsTuner {
            $sec = @($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Security' })[0]
            $tabs = @(Get-IgwtGuiSectionTabList -Section $sec -Pages @($sec.Pages))
            @($tabs.Label) | Should -Be @('Overview', 'Protection', 'Firewall', 'Policies')
            $prot = $tabs[1]
            @($prot.Pages) | Should -Be @('Defender', 'Asr')
            $prot.Target | Should -Be 'Defender'
            (@(Get-IgwtGuiSectionTabList -Section $sec -Pages @($sec.Pages) -LastInGroup @{ Protection = 'Asr' })[1]).Target | Should -Be 'Asr' -Because 'the tab reopens the last page of its group'
        }
    }
    It 'hides the old cross-page buttons that the tabs replace' {
        $x = Get-Content (Join-Path $script:Root 'src\Gui\MainWindow.xaml') -Raw
        foreach ($b in 'AsrHardeningButton', 'AsrSelfButton', 'AsrDefenderButton', 'DefHardeningButton', 'DefAsrButton', 'DefSelfButton') { $x | Should -Match "x:Name=`"$b`" Visibility=`"Collapsed`"" }
    }
}

Describe 'ChangeBar providers (D6: every change through the bar)' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            $script:SavedGui = $script:Gui
            $script:Gui = @{ Staged = @{}; DefStaged = [ordered]@{}; AsrStaged = [ordered]@{}; SecStaged = [ordered]@{}; C = @{}; IsAdmin = $true; CurrentPage = 'Asr' }
            Initialize-IgwtGuiChangeProviders
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:Gui = $script:SavedGui } }
    It 'acts on the page''s own changes, else the tweaks, and counts the rest as elsewhere' {
        InModuleScope iGWindowsTuner {
            (Get-IgwtGuiChangeProviderState -Page 'Asr').Text | Should -Be 'Nothing staged'
            $script:Gui.Staged['a'] = 'on'; $script:Gui.Staged['b'] = 'off'
            $script:Gui.AsrStaged['r1'] = [pscustomobject]@{ Id = 'r1'; Name = 'R1'; From = 'Audit'; Mode = 'Block'; Note = '' }
            $st = Get-IgwtGuiChangeProviderState -Page 'Asr'
            $st.Active.Id | Should -Be 'asr'
            $st.Text | Should -Be '1 ASR change ready (+2 elsewhere)'
            (Get-IgwtGuiChangeProviderState -Page 'Home').Active.Id | Should -Be 'tweaks'
            (Get-IgwtGuiChangeProviderState -Page 'Home').Text | Should -Be '2 changes ready (+1 elsewhere)'
        }
    }
    It 'routes Apply to the provider the bar acts on' {
        InModuleScope iGWindowsTuner {
            $script:Gui.AsrStaged['r1'] = [pscustomobject]@{ Id = 'r1'; Name = 'R1'; From = 'Audit'; Mode = 'Block'; Note = '' }
            Mock Invoke-IgwtGuiAsrChange { $script:Called = @{ Map = $Parameters.RuleMode; Staged = [bool]$Staged } }
            Invoke-IgwtGuiChangeBarAction -Action Apply
            $script:Called.Map['r1'] | Should -Be 'Block'
            $script:Called.Staged | Should -BeTrue
        }
    }
    It 'stages ASR modes, and a rule set back to its mode is unstaged' {
        InModuleScope iGWindowsTuner {
            Mock Update-IgwtGuiPending { }; Mock Set-IgwtGuiStatus { }
            $row = [pscustomobject]@{ Id = 'r2'; Name = 'R2'; Mode = 'Audit'; Rule = [pscustomobject]@{ Mode = 'Audit' } }
            Add-IgwtGuiAsrStaged -Rows @($row) -Mode 'Block'
            $script:Gui.AsrStaged['r2'].Mode | Should -Be 'Block'
            Add-IgwtGuiAsrStaged -Rows @($row) -Mode 'Audit'
            $script:Gui.AsrStaged.Contains('r2') | Should -BeFalse
        }
    }
    It 'applies every staged Defender value in one engine call' {
        InModuleScope iGWindowsTuner {
            $script:Gui.DefStaged['CloudBlockLevel'] = [pscustomobject]@{ Property = 'CloudBlockLevel'; Name = 'Cloud block level'; From = 'High'; To = 'High+'; Value = 4; Parser = $false }
            $script:Gui.DefStaged['PUAProtection'] = [pscustomobject]@{ Property = 'PUAProtection'; Name = 'PUA'; From = 'Audit'; To = 'Block'; Value = 1; Parser = $false }
            Mock Show-IgwtGuiMessage { 'Yes' }
            Mock Start-IgwtGuiJob { $script:Job = @{ Command = $Command; Parameters = $Parameters }; $true }
            Invoke-IgwtGuiDefenderStagedApply
            $script:Job.Command | Should -Be 'Invoke-IgwtDefenderSettingChange'
            $script:Job.Parameters.Setting['CloudBlockLevel'] | Should -Be 4
            $script:Job.Parameters.Setting['PUAProtection'] | Should -Be 1
        }
    }
}

Describe 'ASR results (ASR-1, ASR-2) and Security Settings managed rows (SS-1)' {
    It 'names failed rules after a change and after an undo' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ C = @{} }
                Mock Show-IgwtGuiError { $script:Err = $Message }
                Mock Show-IgwtGuiToast { }
                $res = [pscustomobject]@{ Changes = 1; Snapshot = 's'; Results = @([pscustomobject]@{ Target = 'Rule A'; Result = 'Failed'; Message = 'managed by policy' }, [pscustomobject]@{ Target = 'Rule B'; Result = 'Applied'; Message = '' }) }
                Complete-IgwtGuiAsrChange -Out @($res) -Errors @() | Should -BeTrue
                $script:Err | Should -Match '1 ASR change failed: Rule A: managed by policy'
                $script:Err = $null
                Mock Start-IgwtGuiJob { & $OnComplete @([pscustomobject]@{ Results = @([pscustomobject]@{ Id = 'rule-x'; Result = 'Failed'; Message = 'still Block.' }) }) @() $null; $true }
                Mock Start-IgwtGuiAsrRefresh { }
                Invoke-IgwtGuiAsrUndo -Snapshot 's'
                $script:Err | Should -Match '1 ASR rule was not restored: rule-x'
            } finally { $script:Gui = $saved }
        }
    }
    It 'plans Security Settings without the managed acknowledgement, so managed rows are asked about (SS-1)' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ SecStaged = [ordered]@{ a = [pscustomobject]@{ Id = 'a'; Value = 1; Name = 'A' } }; C = @{} }
                Mock Start-IgwtGuiJob { $script:Plan = $Parameters; $true }
                Invoke-IgwtGuiSecSettingsPreview
                $script:Plan.ContainsKey('AcknowledgeManaged') | Should -BeFalse
                $src = (Get-Command Invoke-IgwtGuiSecSettingsPreview).ScriptBlock.ToString()
                $src | Should -Match "AcknowledgeManaged = \[bool\]\`$managed\.Count"
                $src | Should -Match "Title 'This PC is managed'"
            } finally { $script:Gui = $saved }
        }
    }
}

Describe 'Toolbars within six buttons (D6)' {
    It 'moves actions into a More menu that clicks the original button' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $panel = New-Object System.Windows.Controls.WrapPanel
            $btns = foreach ($n in 1..5) { $b = New-Object System.Windows.Controls.Button; $b.Content = "B$n"; $null = $panel.Children.Add($b); $b }
            $script:Clicked = ''
            Register-IgwtGuiHandler -Control $btns[3] -Event 'Click' -Handler { $script:Clicked = 'B4' }
            $more = Set-IgwtGuiToolbarOverflow -Buttons @($btns[3], $btns[4]) -ObjectName 'test'
            @($panel.Children | Where-Object { $_.Visibility -eq 'Visible' }).Count | Should -Be 4
            [string]$more.Content | Should -Match '^More'
            $panel.Children.IndexOf($more) | Should -Be 3 -Because 'More sits after the last button that stays'
            $mi = @($more.ContextMenu.Items)[0]
            $mi.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent)))
            $script:Clicked | Should -Be 'B4'
            $btns[4].IsEnabled = $false
            Update-IgwtGuiOverflowMenu -Menu $more.ContextMenu
            @($more.ContextMenu.Items)[1].IsEnabled | Should -BeFalse
        }
    }
    It 'keeps every Firewall toolbar and the selected-rule actions within six visible buttons' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $w = New-IgwtMainWindow
                $c = @{}; foreach ($n in 'FwImportButton', 'FwExportButton', 'FwReportButton', 'FwExportPolicyButton', 'FwAllowButton', 'FwBlockButton', 'FwDuplicateButton', 'FwDeleteButton', 'FwForEstimateButton', 'FwForRefreshButton', 'FwBulkButton', 'FwEnableButton', 'FwForStartButton') { $c[$n] = $w.FindName($n) }
                $script:Gui = @{ Window = $w; C = $c }
                Initialize-IgwtGuiSecurityToolbars
                foreach ($anchor in 'FwBulkButton', 'FwEnableButton', 'FwForStartButton') {
                    $panel = $c[$anchor].Parent
                    @($panel.Children | Where-Object { $_ -is [System.Windows.Controls.Button] -and $_.Visibility -eq 'Visible' }).Count | Should -BeLessOrEqual 6 -Because "the toolbar of $anchor"
                }
                @($c.FwBulkButton.Parent.Children | Where-Object { $_ -is [System.Windows.Controls.Button] -and $_.Visibility -eq 'Visible' }).Count | Should -Be 2
            } finally { $script:Gui = $saved }
        }
    }
}

Describe 'Firewall screens (FWH-2, FWH-3, FWH-4, FWP-3, FWP-5) and forensic logging (FOR-2)' {
    It 'reads the remote session once per selection and stops at the first allowed rule (FWH-2)' {
        $src = Get-Content (Join-Path $script:Root 'src\Gui\FirewallHome.ps1') -Raw
        $src | Should -Match '\$remote = Test-IgwtRemoteSession'
        $src | Should -Not -Match '-RemoteSession \(Test-IgwtRemoteSession\)'
        $src | Should -Match 'if \(-not \$why\) \{ \$allowed = \$true; break \}'
    }
    It 'catches a failed override write with a clear message (FWH-3)' {
        $src = Get-Content (Join-Path $script:Root 'src\Gui\FirewallHome.ps1') -Raw
        @([regex]::Matches($src, '(?m)^\s*\$null = Set-IgwtFirewallOverride')).Count | Should -Be 0
        @([regex]::Matches($src, 'try \{ \$null = Set-IgwtFirewallOverride')).Count | Should -Be 5
    }
    It 'shows one summary for a run of several batches, and the Undo toast only after Keep (FWH-4, FWP-3)' {
        $src = Get-Content (Join-Path $script:Root 'src\Gui\FirewallPage.ps1') -Raw
        $src | Should -Match 'firewall batches applied\. Each can be undone in History'
        $keep = $src.IndexOf('Show-IgwtGuiKeepChangesDialog -Seconds 60'); $toast = $src.IndexOf("-Noun 'firewall rule') changed.")
        $keep | Should -BeLessThan $toast
    }
    It 'names rules that were not imported (FWP-5)' {
        (Get-Content (Join-Path $script:Root 'src\Gui\FirewallPage.ps1') -Raw) | Should -Match ([regex]::Escape("-Noun 'rule' -Verb 'were') not imported"))
    }
    It 'says when the automatic forensic restore failed instead of "ended while closed" (FOR-2)' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $w = New-IgwtMainWindow
                $script:Gui = @{ Window = $w; IsAdmin = $true; C = @{ ForensicBanner = $w.FindName('ForensicBanner'); ForensicBannerText = $w.FindName('ForensicBannerText') }; Forensic = @{ Running = $false; StopFailed = 'Access denied.' } }
                Mock Update-IgwtGuiForensicButtons { }
                Update-IgwtGuiForensicBanner -Session ([pscustomobject]@{ Corrupt = $false; Status = 'active'; Expired = $true; Started = (Get-Date).AddHours(-2); Until = (Get-Date).AddHours(-1) })
                $script:Gui.C.ForensicBannerText.Text | Should -Match 'Restoring the logging settings failed: Access denied\.'
            } finally { $script:Gui = $saved }
        }
    }
}

Describe 'Persistence: svchost services and bare DLL names (F-25)' {
    It 'judges a svchost service by its ServiceDll' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = $true; Value = 'C:\Tools\evil.dll' } }
            Mock Get-IgwtFileSignature { [pscustomobject]@{ Status = 'NotSigned'; Signer = ''; IsMicrosoft = $false } }
            $e = [pscustomobject]@{ File = 'C:\Windows\System32\svchost.exe'; IsMicrosoft = $true; Severity = 'Info'; Note = '' }
            Set-IgwtPersistenceServiceDll -Entry $e -ServiceName 'X'
            $e.Severity | Should -Be 'Review'; $e.IsMicrosoft | Should -BeFalse; $e.Note | Should -Match 'evil\.dll'
            $ok = [pscustomobject]@{ File = 'C:\Windows\System32\svchost.exe'; IsMicrosoft = $true; Severity = 'Info'; Note = '' }
            Mock Get-IgwtFileSignature { [pscustomobject]@{ Status = 'Valid'; Signer = 'Microsoft Windows'; IsMicrosoft = $true } }
            Set-IgwtPersistenceServiceDll -Entry $ok -ServiceName 'Y'
            $ok.Severity | Should -Be 'Info'
        }
    }
    It 'resolves a bare DLL name in System32 and does not flag one Windows would find (real-PC false positive)' {
        InModuleScope iGWindowsTuner {
            Mock Resolve-IgwtCommandPath { 'C:\Windows\System32\rundll32.exe' }
            Mock Get-IgwtFileSignature { if ($Path -like '*\System32\Startupscan.dll' -or $Path -like '*rundll32*') { [pscustomobject]@{ Status = 'Valid'; Signer = 'Microsoft Windows'; IsMicrosoft = $true } } else { [pscustomobject]@{ Status = 'NotFound'; Signer = ''; IsMicrosoft = $false } } }
            (New-IgwtPersistenceEntry -Category 'Tasks' -Location '\Microsoft\Windows\X' -Name 'StartupAppTask' -Command 'rundll32.exe Startupscan.dll,SusRunTask').Severity | Should -Be 'Info'
        }
    }
}

Describe 'Firewall precedence: packages (F-15 c)' {
    It 'lets a block rule without a package cover app-container traffic, but not the other way' {
        InModuleScope iGWindowsTuner {
            $mk = { param($pkg) Get-IgwtFirewallRuleScope -Row ([pscustomobject]@{ Program = 'Any'; Service = 'Any'; Package = $pkg; Owner = ''; Protocol = 'TCP'; LocalPort = 'Any'; RemotePort = 'Any'; RemoteAddress = 'Any'; LocalAddress = 'Any'; IcmpType = ''; ProfileList = @('Any'); InterfaceType = 'Any' }) }
            Test-IgwtFirewallScopeRelation -A (& $mk '') -B (& $mk 'S-1-15-2-1') | Should -Be 'Covers'
            Test-IgwtFirewallScopeRelation -A (& $mk 'S-1-15-2-1') -B (& $mk '') | Should -Be 'Overlaps'
            Test-IgwtFirewallScopeRelation -A (& $mk 'S-1-15-2-1') -B (& $mk 'S-1-15-2-2') | Should -Be ''
        }
    }
}
