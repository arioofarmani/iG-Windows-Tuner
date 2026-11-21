# 4.0 section 5a: Security engine findings (Policy P-xx, Defender F-xx, Firewall and Manage FW F-xx).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Local GPO restore (P-03, P-04, P-23, P-31)' {
    BeforeEach {
        InModuleScope iGWindowsTuner -Parameters @{ D = $TestDrive } {
            param($D)
            $script:SavedRoots = @($script:IgwtSettings.GpoRoot, $script:IgwtSettings.GpoUsersRoot)
            $script:IgwtSettings.GpoRoot = Join-Path $D 'gp\GroupPolicy'; $script:IgwtSettings.GpoUsersRoot = Join-Path $D 'gp\GroupPolicyUsers'
            $null = New-Item -ItemType Directory -Force -Path (Join-Path $script:IgwtSettings.GpoRoot 'Machine'), $script:IgwtSettings.GpoUsersRoot
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $script:SavedRoots[0]; $script:IgwtSettings.GpoUsersRoot = $script:SavedRoots[1] } }
    It 'uses Sysnative from a 32-bit PowerShell on 64-bit Windows' {
        InModuleScope iGWindowsTuner {
            Get-IgwtSystemFolderName -Is64BitProcess $false -Is64BitOs $true | Should -Be 'Sysnative'
            Get-IgwtSystemFolderName -Is64BitProcess $true -Is64BitOs $true | Should -Be 'System32'
            Get-IgwtSystemFolderName -Is64BitProcess $false -Is64BitOs $false | Should -Be 'System32'
        }
    }
    It 'refuses manifest paths that leave their folder or name another folder' {
        InModuleScope iGWindowsTuner -Parameters @{ D = $TestDrive } {
            param($D)
            { Resolve-IgwtGpoBackupFile -BackupPath (Join-Path $D 'b') -File ([pscustomobject]@{ folder = 'GroupPolicy'; path = '..\..\Tasks\x' }) } | Should -Throw '*leaves its folder*'
            { Resolve-IgwtGpoBackupFile -BackupPath (Join-Path $D 'b') -File ([pscustomobject]@{ folder = 'Tasks'; path = 'x' }) } | Should -Throw '*only GroupPolicy and GroupPolicyUsers*'
            (Resolve-IgwtGpoBackupFile -BackupPath (Join-Path $D 'b') -File ([pscustomobject]@{ folder = 'GroupPolicy'; path = 'Machine\Registry.pol' })).To | Should -BeLike '*gp\GroupPolicy\Machine\Registry.pol'
        }
    }
    It 'refuses to undo an older change while a later one is in place, and allows it once that one is undone' {
        InModuleScope iGWindowsTuner {
            $pol = Join-Path $script:IgwtSettings.GpoRoot 'Machine\Registry.pol'
            [System.IO.File]::WriteAllText($pol, 'v1')
            $b1 = Backup-IgwtLocalGpo -Reason 'before change 1' -Confirm:$false
            Start-Sleep -Milliseconds 20
            [System.IO.File]::WriteAllText($pol, 'v2')
            $b2 = Backup-IgwtLocalGpo -Reason 'before change 2' -Confirm:$false
            [System.IO.File]::WriteAllText($pol, 'v3')
            $m1 = Read-IgwtJsonFile -Path (Join-Path $b1 'manifest.json')
            Get-IgwtGpoRestoreConflict -BackupPath $b1 -Manifest $m1 | Should -Match 'changed after this change'
            { Restore-IgwtLocalGpo -BackupPath $b1 -NoRefresh -Confirm:$false } | Should -Throw '*Nothing was restored*'
            [System.IO.File]::ReadAllText($pol) | Should -Be 'v3'
            # Undo change 2 first (newest first), then change 1 is allowed.
            $null = Restore-IgwtLocalGpo -BackupPath $b2 -NoRefresh -Confirm:$false
            [System.IO.File]::ReadAllText($pol) | Should -Be 'v2'
            Get-IgwtGpoRestoreConflict -BackupPath $b1 -Manifest $m1 | Should -BeNullOrEmpty
            $null = Restore-IgwtLocalGpo -BackupPath $b1 -NoRefresh -Confirm:$false
            [System.IO.File]::ReadAllText($pol) | Should -Be 'v1'
        }
    }
    It 'refuses when a Security Settings change made after the backup is still in place' {
        InModuleScope iGWindowsTuner {
            $b = Backup-IgwtLocalGpo -Reason 'before x' -Confirm:$false
            $later = (Get-Date).ToUniversalTime().AddMinutes(1).ToString('o')
            Mock Read-IgwtJournal { [pscustomobject]@{ Last = @{ k = @{ kind = 'committed'; op = 'change'; item = 'sec.x'; tsUtc = $later; target = @{ provider = 'localPolicy' } } } } }.GetNewClosure()
            Get-IgwtGpoRestoreConflict -BackupPath $b -Manifest (Read-IgwtJsonFile -Path (Join-Path $b 'manifest.json')) | Should -Match "Security Settings change.*'sec.x'"
        }
    }
    It 'puts the folders back when the restore fails part-way' {
        InModuleScope iGWindowsTuner {
            $pol = Join-Path $script:IgwtSettings.GpoRoot 'Machine\Registry.pol'
            [System.IO.File]::WriteAllText($pol, 'old')
            $b = Backup-IgwtLocalGpo -Reason 'before y' -Confirm:$false
            [System.IO.File]::WriteAllText($pol, 'current')
            # The restore itself is the only change since $b, and it fails on the first copy.
            Remove-Item -LiteralPath $b -Recurse -Force -ErrorAction SilentlyContinue
            $b = Backup-IgwtLocalGpo -Reason 'before y2' -Confirm:$false
            $script:Calls = 0
            Mock Copy-IgwtGpoBackupFiles { $script:Calls++; if ($script:Calls -eq 1) { throw 'disk full' }; foreach ($f in @($Manifest.files)) { $x = Resolve-IgwtGpoBackupFile -BackupPath $BackupPath -File $f; Copy-Item -LiteralPath $x.From -Destination $x.To -Force } }
            { Restore-IgwtLocalGpo -BackupPath $b -NoRefresh -Confirm:$false } | Should -Throw '*disk full*put back as it was*'
            [System.IO.File]::ReadAllText($pol) | Should -Be 'current'
        }
    }
}

Describe 'Security template and audit (P-13, P-16, P-20, P-30)' {
    It 'refuses an account that does not exist instead of writing an error text (P-16)' {
        InModuleScope iGWindowsTuner {
            { New-IgwtSecurityChange -Section 'PrivilegeRights' -Key 'SeBackupPrivilege' -Value 'NoSuchAccount_igwt_9f2' } | Should -Throw '*was not found on this PC*'
            (New-IgwtSecurityChange -Section 'PrivilegeRights' -Key 'SeBackupPrivilege' -Value '*S-1-5-32-544').Value | Should -Be '*S-1-5-32-544'
        }
    }
    It 'keeps an SDDL value with semicolons whole (P-20)' {
        InModuleScope iGWindowsTuner {
            $c = New-IgwtSecurityChange -Section 'Registry Values' -Key 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM' -Value '1,"O:BAG:BAD:(A;;RC;;;BA)"'
            $c.Section | Should -Be 'Registry Values'
            $c.Value | Should -Be '1,"O:BAG:BAD:(A;;RC;;;BA)"'
        }
    }
    It 'reads auditpol output with localized headers by column position (P-13)' {
        InModuleScope iGWindowsTuner {
            $csv = "Computername,Richtlinienziel,Unterkategorie,Unterkategorie-GUID,Einschlusseinstellung,Ausschlusseinstellung`r`nPC,System,Anmelden,{0CCE9215-69AE-11D9-BED3-505054503030},Erfolg und Fehler,"
            $rows = @(ConvertFrom-IgwtAuditCsv -Text $csv)
            $rows.Count | Should -Be 1
            $rows[0].Guid | Should -Be '{0CCE9215-69AE-11D9-BED3-505054503030}'
            $rows[0].Subcategory | Should -Be 'Anmelden'
        }
    }
    It 'never treats an audit setting it could not read as None (P-30)' {
        InModuleScope iGWindowsTuner {
            Test-IgwtSecSettingAuditAddOnly -Before 'Unknown' -After 'Success' | Should -Match 'could not be read'
            Test-IgwtSecSettingAuditAddOnly -Before 'None' -After 'Success' | Should -BeNullOrEmpty
            Test-IgwtSecSettingAuditAddOnly -Before 'SuccessAndFailure' -After 'Success' | Should -Match 'stop auditing failure'
        }
    }
}

Describe 'Protections are never lowered (P-25, P-27, F-02, F-03)' {
    It 'refuses Network protection block -> audit, allows off -> audit (P-27)' {
        InModuleScope iGWindowsTuner {
            $k = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            $cur = @([pscustomobject]@{ Key = $k; ValueName = 'EnableNetworkProtection'; Type = 'DWord'; Value = 1 })
            $why = @(Test-IgwtSecSettingOpsLowerProtection -Class Machine -CurrentEntries $cur -Ops @([pscustomobject]@{ Op = 'Set'; Key = $k; ValueName = 'EnableNetworkProtection'; Type = 'DWord'; Value = 2 }))
            ($why -join ' ') | Should -Match 'would lower this protection'
            $cur[0].Value = 0
            @(Test-IgwtSecSettingOpsLowerProtection -Class Machine -CurrentEntries $cur -Ops @([pscustomobject]@{ Op = 'Set'; Key = $k; ValueName = 'EnableNetworkProtection'; Type = 'DWord'; Value = 2 })).Count | Should -Be 0
        }
    }
    It 'refuses removing a tattooed value that keeps a protection on (P-25)' {
        InModuleScope iGWindowsTuner {
            Get-IgwtProtectiveValueReason -Key 'SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Value '1' | Should -Not -BeNullOrEmpty
            Get-IgwtProtectiveValueReason -Key 'SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Value '0' | Should -BeNullOrEmpty
            Get-IgwtProtectiveValueReason -Key 'SOFTWARE\Policies\Contoso\Game' -ValueName 'Fps' -Value '144' | Should -BeNullOrEmpty
        }
    }
    It 'refuses a weaker Defender level even between two "on" values (F-02)' {
        InModuleScope iGWindowsTuner {
            $cat = Get-IgwtDefenderSettingCatalog
            $cbl = @($cat.settings | Where-Object { $_.mp -eq 'CloudBlockLevel' })[0]
            Test-IgwtDefenderSettingValue -Definition $cbl -Value 2 -Current 6 | Should -Match 'never lowers'
            Test-IgwtDefenderSettingValue -Definition $cbl -Value 6 -Current 2 | Should -BeNullOrEmpty
            $ai = @($cat.settings | Where-Object { $_.mp -eq 'AiAgentProtection' })[0]
            Test-IgwtDefenderSettingValue -Definition $ai -Value 2 -Current 1 | Should -Match 'never lowers'
            Test-IgwtDefenderSettingValue -Definition $ai -Value 1 -Current 2 | Should -BeNullOrEmpty
        }
    }
    It 'refuses option values that weaken scanning or updates (F-03)' {
        InModuleScope iGWindowsTuner {
            $cat = Get-IgwtDefenderSettingCatalog
            $day = @($cat.settings | Where-Object { $_.mp -eq 'ScanScheduleDay' })[0]
            Test-IgwtDefenderSettingValue -Definition $day -Value 8 | Should -Match 'refused'
            Test-IgwtDefenderSettingValue -Definition $day -Value 1 | Should -BeNullOrEmpty
            $cu = @($cat.settings | Where-Object { $_.mp -eq 'SignatureUpdateCatchupInterval' })[0]
            Test-IgwtDefenderSettingValue -Definition $cu -Value 30 | Should -Match 'outside'
            $ch = @($cat.settings | Where-Object { $_.mp -eq 'EngineUpdatesChannel' })[0]
            Test-IgwtDefenderSettingValue -Definition $ch -Value 6 | Should -Match 'refused'
        }
    }
}

Describe 'Policy effect, preset revert and list prefixes (P-09, P-22, P-32)' {
    It 'reports a local-policy value that did not take effect (P-32)' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = $true; Value = 0 } }
            $e = Get-IgwtSecSettingEffect -Class Machine -Ops @([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\X'; ValueName = 'V'; Value = 1 })
            $e.Effect | Should -Be 'NotYetInEffect'
            $e.Message | Should -Match "reads '0' instead of '1'"
            Mock Get-IgwtRegistryValue { [pscustomobject]@{ Exists = $true; Value = 1 } }
            (Get-IgwtSecSettingEffect -Class Machine -Ops @([pscustomobject]@{ Op = 'Set'; Key = 'Software\Policies\X'; ValueName = 'V'; Value = 1 })).Effect | Should -Be 'InEffect'
        }
    }
    It 'restores every part of a policy preset and names the part that failed (P-22)' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtModuleOperationDirect { $true }
            Mock Test-IgwtPathUnder { $true }
            Mock Test-IgwtPathTrustedChain { $true }
            Mock Read-IgwtJsonFile { [pscustomobject]@{ kind = 'igwt-policy-preset'; preset = 'p'; secpolBackup = 's'; auditBackup = 'a'; gpoBackup = 'g' } }
            Mock Restore-IgwtSecurityPolicy { throw 'secedit failed' }
            Mock Restore-IgwtAuditPolicy { }
            Mock Restore-IgwtLocalGpo { }
            Mock Clear-IgwtCache { }
            { Restore-IgwtPolicyPreset -Record 'r.json' -NoRefresh -Confirm:$false } | Should -Throw '*Restored: audit policy, Local GPO. Failed: security policy: secedit failed*'
            Should -Invoke Restore-IgwtLocalGpo -Times 1 -Exactly
        }
    }
    It 'tells valuePrefix="" (names 1..n) from no valuePrefix (P-09)' {
        $src = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Policy\AdmxCatalog.ps1') -Raw
        $src | Should -Match "HasPrefix = \`$Node\.HasAttribute\('valuePrefix'\)"
        $src | Should -Match 'IgwtAdmxCacheVersion = 3'
        (Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Policy\PolicyEngine.ps1') -Raw) | Should -Match '\$hasPrefix = '
    }
}

Describe 'Defender audit and forensic logging (F-04, F-10, F-11)' {
    It 'counts audit coverage from the rule''s last mode change (F-11)' {
        InModuleScope iGWindowsTuner {
            $rule = @(Get-IgwtAsrCatalog | Where-Object { -not $_.serverOnly -and [string]$_.gamerImpactLevel -in 'none', 'low' })[0]
            $id = ([string]$rule.id).ToLowerInvariant()
            $events = [pscustomobject]@{ Readable = $true; Error = ''; Days = 30; LogStart = (Get-Date).AddDays(-30); Truncated = $false
                Events = @([pscustomobject]@{ Time = (Get-Date).AddDays(-2); EventId = 5007; Feature = 'Configuration'; Action = 'Changed'; RuleId = ''; Path = ''; Process = ''; User = ''; OldValue = ''; NewValue = "HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\$id = 0x2"; Detail = '' }) }
            $status = [pscustomobject]@{ Rules = @([pscustomobject]@{ Id = $id; Mode = 'Audit' }) }
            $r = @((Get-IgwtAsrAudit -Events $events -Status $status).Rules | Where-Object { ([string]$_.Id).ToLowerInvariant() -eq $id })[0]
            $r.Recommendation | Should -Be 'KeepAuditing'
            $r.RecommendationText | Should -Match 'in Audit for 2 day'
        }
    }
    It 'restores an expired forensic session once at the first elevated check, and says why WFP is refused on other languages (F-04, F-10)' {
        $page = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui\ForensicPage.ps1') -Raw
        $page | Should -Match '\$script:Gui\.Forensic\.RetryStop -or \$first'
        $page | Should -Match "Status -notin 'starting', 'rollback-incomplete'"
        (Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Defender\ForensicLogging.ps1') -Raw) | Should -Match 'could not be read in this Windows language'
    }
}

Describe 'Firewall and Manage engine (FW F-04 to F-25)' {
    It 'clears ports when an undo goes back to a protocol without ports (F-07), and reads enabled strictly (F-08)' {
        InModuleScope iGWindowsTuner {
            $p = ConvertTo-IgwtFirewallRuleParameters -Definition @{ displayName = 'x'; protocol = 'Any'; localPort = @('27015'); enabled = 'false' } -ForSet
            $p.LocalPort | Should -Be 'Any'
            $p.RemotePort | Should -Be 'Any'
            $p.Enabled | Should -Be 'False'
            (ConvertTo-IgwtFirewallRuleParameters -Definition @{ name = 'n'; displayName = 'x'; direction = 'Inbound'; protocol = 'TCP'; localPort = @('27015'); enabled = $true }).LocalPort | Should -Be @('27015')
        }
    }
    It 'never says a block rule for one port covers an allow rule for every port (F-15)' {
        InModuleScope iGWindowsTuner {
            $mk = { param($rp, $la) Get-IgwtFirewallRuleScope -Row ([pscustomobject]@{ Program = 'C:\g.exe'; Service = 'Any'; Package = ''; Owner = ''; Protocol = 'TCP'; LocalPort = 'Any'; RemotePort = $rp; RemoteAddress = 'Any'; LocalAddress = $la; IcmpType = ''; ProfileList = @('Any'); InterfaceType = 'Any' }) }
            Test-IgwtFirewallScopeRelation -A (& $mk '80' 'Any') -B (& $mk 'Any' 'Any') | Should -Be 'Overlaps'
            Test-IgwtFirewallScopeRelation -A (& $mk 'Any' '10.0.0.5') -B (& $mk 'Any' 'Any') | Should -Be 'Overlaps'
            Test-IgwtFirewallScopeRelation -A (& $mk 'Any' 'Any') -B (& $mk '80' 'Any') | Should -Be 'Covers'
            # Different spellings of a subnet are a possible overlap, not "no conflict".
            Test-IgwtFirewallScopeRelation -A (& $mk 'Any' '10.0.0.0/8') -B (& $mk 'Any' '10.1.2.3') | Should -Be 'Overlaps'
            Test-IgwtFirewallScopeRelation -A (& $mk 'Any' '10.0.0.1') -B (& $mk 'Any' '10.0.0.2') | Should -Be ''
        }
    }
    It 'matches System rules to the System process listeners (F-16)' {
        InModuleScope iGWindowsTuner {
            $row = [pscustomobject]@{ Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = '445'; Program = 'System'; Service = 'Any' }
            Test-IgwtFirewallListenerMatch -Row $row -Listener ([pscustomobject]@{ Local = $false; Protocol = 'TCP'; LocalPort = 445; Path = ''; ProcessId = 4; Services = @() }) | Should -BeTrue
            Test-IgwtFirewallListenerMatch -Row $row -Listener ([pscustomobject]@{ Local = $false; Protocol = 'TCP'; LocalPort = 445; Path = 'C:\x.exe'; ProcessId = 900; Services = @() }) | Should -BeFalse
        }
    }
    It 'does not judge installed apps from another administrator''s account (F-17)' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtOtherAdminElevation { 'S-1-5-21-1-1001' }
            Get-IgwtFirewallInstalledPackages | Should -BeNullOrEmpty
        }
    }
    It 'protects servicing, Store updates, defrag (SSD TRIM), certificates, activation and remediation tasks (F-22)' {
        InModuleScope iGWindowsTuner {
            foreach ($t in '\Microsoft\Windows\Defrag\ScheduledDefrag', '\Microsoft\Windows\Servicing\StartComponentCleanup', '\Microsoft\Windows\InstallService\ScanForUpdates', '\Microsoft\Windows\rempl\shell') {
                { Assert-IgwtTaskAllowed -Path $t } | Should -Throw
            }
        }
    }
    It 'marks an inbox app removal one-way in the journal (F-24)' {
        InModuleScope iGWindowsTuner {
            $def = $script:IgwtChangeProviders['module']
            $r = & $def.Resolve ([ordered]@{ provider = 'module'; key = 'module|Invoke-IgwtManagedChange|abc'; op = 'Invoke-IgwtManagedChange'; oneWay = $true }) $null
            & $def.Reversible $r | Should -Be 'oneWay'
            $r = & $def.Resolve ([ordered]@{ provider = 'module'; key = 'module|Invoke-IgwtManagedChange|abc'; op = 'Invoke-IgwtManagedChange' }) $null
            & $def.Reversible $r | Should -Be 'exact'
            (Get-Content (Join-Path $script:IgwtProjectRoot 'src\Core\Transaction.ps1') -Raw) | Should -Match "Parameters\['Kind'\] -eq 'appx'\) \{ \`$target\['oneWay'\] = \`$true \}"
        }
    }
    It 'flags persistence that hides behind a Microsoft-signed host (F-25)' {
        InModuleScope iGWindowsTuner {
            Mock Resolve-IgwtCommandPath { 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
            Mock Get-IgwtFileSignature { [pscustomobject]@{ Status = 'Valid'; Signer = 'Microsoft Windows'; IsMicrosoft = $true } }
            $e = New-IgwtPersistenceEntry -Category 'Tasks' -Location '\Microsoft\Windows\X' -Name 'x' -Command 'powershell.exe -nop -enc SQBFAFgA'
            $e.Severity | Should -Be 'Warn'
            $e.IsMicrosoft | Should -BeFalse
            $ok = New-IgwtPersistenceEntry -Category 'Tasks' -Location '\Microsoft\Windows\X' -Name 'y' -Command 'powershell.exe -NoProfile -File C:\Windows\System32\x.ps1'
            $ok.Severity | Should -Be 'Info'
            Mock Resolve-IgwtCommandPath { 'C:\Windows\System32\rundll32.exe' }
            Mock Get-IgwtFileSignature { if ($Path -like '*rundll32*') { [pscustomobject]@{ Status = 'Valid'; Signer = 'Microsoft Windows'; IsMicrosoft = $true } } else { [pscustomobject]@{ Status = 'NotSigned'; Signer = ''; IsMicrosoft = $false } } }
            $d = New-IgwtPersistenceEntry -Category 'Run' -Location 'HKCU Run' -Name 'z' -Command 'rundll32.exe C:\Tools\helper.dll,Start'
            $d.Severity | Should -Be 'Review'
            $d.Note | Should -Match 'Loads C:\\Tools\\helper.dll'
        }
    }
    It 'reads the firewall profile back from the active store (F-04)' {
        InModuleScope iGWindowsTuner {
            Mock Test-IgwtModuleOperationDirect { $true }
            Mock Test-IgwtRemoteSession { $false }
            Mock Initialize-IgwtDataRoot { }
            Mock Get-NetFirewallProfile { [pscustomobject]@{ LogBlocked = 'False' } }
            Mock Set-NetFirewallProfile { }
            $r = Set-IgwtFirewallProfileSetting -Profile Public -Setting LogBlocked -Value 'True' -Confirm:$false
            $r.InEffect | Should -BeFalse
            $r.Message | Should -Match "still 'False'"
            Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { $LogBlocked -eq 'True' }
        }
    }
}
