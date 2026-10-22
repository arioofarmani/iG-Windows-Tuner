# 3.0 phase 6: category policy presets, deployment exports and baseline import/compare. The ADMX
# files the presets reference are copied from this PC's PolicyDefinitions into TestDrive (read
# only); the GPO folder is temporary, gpupdate is simulated into TestRegistry, and secedit and
# auditpol are simulated in memory.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Presets = @((Get-Content (Join-Path $script:IgwtProjectRoot 'data\policy\presets.json') -Raw | ConvertFrom-Json).presets)
    $sys = Join-Path $env:SystemRoot 'PolicyDefinitions'
    $script:HaveAdmx = Test-Path -LiteralPath $sys
    $script:AdmxDir = Join-Path $TestDrive 'Admx'
    $null = New-Item -ItemType Directory -Path (Join-Path $script:AdmxDir 'en-US') -Force
    $files = @($script:Presets | ForEach-Object { $_.settings } | Where-Object { $_.kind -eq 'admx' } | ForEach-Object { ([string]$_.policy).Split(':')[0] } | Sort-Object -Unique)
    foreach ($n in $files) {
        $a = Join-Path $sys "$n.admx"; $l = Join-Path $sys "en-US\$n.adml"
        if (Test-Path -LiteralPath $a) { Copy-Item -LiteralPath $a -Destination $script:AdmxDir }
        if (Test-Path -LiteralPath $l) { Copy-Item -LiteralPath $l -Destination (Join-Path $script:AdmxDir 'en-US') }
    }
    $script:BaseInf = "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nLockoutBadCount = 0`r`nResetLockoutCount = 10`r`nLockoutDuration = 10`r`n[Registry Values]`r`nMACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1`r`n[Privilege Rights]`r`nSeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n"
    $script:AuditGuids = @($script:Presets | ForEach-Object { $_.settings } | Where-Object { $_.kind -eq 'audit' } | ForEach-Object { [string]$_.guid } | Sort-Object -Unique)

    function Get-TestPolEntries([string]$Class = 'Machine') { @(InModuleScope iGWindowsTuner -Parameters @{ C = $Class } { param($C) (Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $C)).Entries }) }
}

Describe 'Policy presets' {
    BeforeEach {
        $script:GpoRoot = Join-Path $TestDrive ('GPO-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:GpoRoot; A = $script:AdmxDir } { param($R, $A) $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtPolicyPresets = $null }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $true } }
        Mock -ModuleName iGWindowsTuner Get-MpPreference { [pscustomobject]@{ DisableDnsParsing = $false; DisableQuicParsing = $true; EnableDnsSinkhole = $true } }
        Mock -ModuleName iGWindowsTuner Set-MpPreference { }
        Mock -ModuleName iGWindowsTuner Get-IgwtOsInfo { [pscustomobject]@{ EditionId = 'Professional'; Build = 26300 } }
        Mock -ModuleName iGWindowsTuner Get-IgwtCurrentIdentity { [pscustomobject]@{ Name = 'PC\ario'; Sid = 'S-1-5-21-1-2-3-1001'; GroupSids = @('S-1-5-32-544', 'S-1-5-32-545'); IsRemote = $false } }
        Mock -ModuleName iGWindowsTuner Get-IgwtLocalAccountAudit { [pscustomobject]@{ Readable = $true; AdminsKnown = $true; Accounts = @([pscustomobject]@{ Name = 'ario'; Sid = 'S-1-5-21-1-2-3-1001'; Enabled = $true; Role = 'User'; IsAdmin = $true; PasswordLastSet = (Get-Date).AddDays(-3) }, [pscustomobject]@{ Name = 'admin2'; Sid = 'S-1-5-21-1-2-3-1002'; Enabled = $true; Role = 'User'; IsAdmin = $true; PasswordLastSet = (Get-Date) }) } }
        # Simulated secedit and auditpol.
        $script:SecDb = InModuleScope iGWindowsTuner -Parameters @{ T = $script:BaseInf } { param($T) ConvertFrom-IgwtSecurityInf -Text $T }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtSecedit {
            $cfg = $Arguments[[array]::IndexOf($Arguments, '/cfg') + 1]
            if ($Arguments[0] -eq '/export') { InModuleScope iGWindowsTuner -Parameters @{ P = $cfg; S = $script:SecDb } { param($P, $S) Write-IgwtSecurityInfFile -Path $P -Sections $S -WhatIf:$false } }
            else { $tpl = InModuleScope iGWindowsTuner -Parameters @{ P = $cfg } { param($P) Read-IgwtSecurityInfFile -Path $P }; foreach ($s in @($tpl.Keys)) { if ($s -in 'Unicode', 'Version') { continue }; if (-not $script:SecDb.Contains($s)) { $script:SecDb[$s] = InModuleScope iGWindowsTuner { New-IgwtInfSectionTable } }; foreach ($k in @($tpl[$s].Keys)) { $script:SecDb[$s][$k] = $tpl[$s][$k] } } }
            [pscustomobject]@{ ExitCode = 0; Output = '' }
        }
        $script:Audit = @{}; foreach ($g in $script:AuditGuids) { $script:Audit["{$g}"] = 'None' }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtAuditpol {
            $map = @{ None = 'No Auditing'; Success = 'Success'; Failure = 'Failure'; SuccessAndFailure = 'Success and Failure' }
            switch ($Arguments[0]) {
                '/get' { $t = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`r`n"; foreach ($g in @($script:Audit.Keys | Sort-Object)) { $t += "PC,System,Sub $g,$g,$($map[$script:Audit[$g]]),`r`n" }; return [pscustomobject]@{ ExitCode = 0; Output = $t } }
                '/set' { $g = ($Arguments[1] -replace '^/subcategory:', '').ToUpperInvariant(); $s = $Arguments[2] -eq '/success:enable'; $f = $Arguments[3] -eq '/failure:enable'; $script:Audit[$g] = $(if ($s -and $f) { 'SuccessAndFailure' } elseif ($s) { 'Success' } elseif ($f) { 'Failure' } else { 'None' }) }
                '/backup' { $rows = foreach ($g in $script:Audit.Keys) { [pscustomobject]@{ Subcategory = "Sub $g"; Guid = $g; Setting = $script:Audit[$g]; Option = $false } }; [IO.File]::WriteAllText(($Arguments[1] -replace '^/file:', ''), (InModuleScope iGWindowsTuner -Parameters @{ R = @($rows) } { param($R) ConvertTo-IgwtAuditCsv -Rows $R })) }
                '/restore' { foreach ($r in @(InModuleScope iGWindowsTuner -Parameters @{ T = [IO.File]::ReadAllText(($Arguments[1] -replace '^/file:', '')) } { param($T) ConvertFrom-IgwtAuditCsv -Text $T })) { $script:Audit[$r.Guid] = $r.Setting } }
            }
            [pscustomobject]@{ ExitCode = 0; Output = '' }
        }
        # Simulated registry client-side extension for the verification after gpupdate.
        Mock -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate {
            foreach ($e in @(InModuleScope iGWindowsTuner { (Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine)).Entries })) {
                $k = 'TestRegistry:\HKLM\' + $e.Key
                if ($e.ValueName.StartsWith('**del.')) { Remove-ItemProperty -LiteralPath $k -Name ($e.ValueName.Substring(6)) -ErrorAction SilentlyContinue; continue }
                if (-not $e.ValueName -or $e.ValueName.StartsWith('**')) { continue }
                if (-not (Test-Path -LiteralPath $k)) { $null = New-Item -Path $k -Force }
                $null = New-ItemProperty -LiteralPath $k -Name $e.ValueName -Value $e.Value -PropertyType $e.TypeName -Force
            }
        }
    }
    AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

    Context 'Catalog' {
        It 'ships at least the 12 categories of SPEC-v3 3.6 and passes validation' {
            $script:Presets.Count | Should -BeGreaterOrEqual 12
            @(InModuleScope iGWindowsTuner { Test-IgwtPolicyPresetCatalog }) | Should -BeNullOrEmpty
            foreach ($id in 'privacy-telemetry', 'wufb-pilot', 'wufb-broad', 'wufb-gaming', 'defender-recommended', 'defender-gaming', 'defender-strict', 'defender-audit', 'firewall-logging', 'attack-surface', 'edge-security', 'credentials-hardening', 'remote-access-lockdown', 'removable-media', 'audit-logging', 'kiosk-shared', 'developer-workstation', 'secure-gaming') { @($script:Presets | Where-Object id -EQ "policy.$id").Count | Should -Be 1 -Because $id }
        }
        It 'refuses invalid presets' {
            $bad = @([pscustomobject]@{ id = 'policy.bad'; name = 'B'; scope = 'Privacy'; hint = 'h'; description = 'd'; antiCheat = 'safe'; sources = @('https://learn.microsoft.com/'); settings = @(
                        [pscustomobject]@{ kind = 'admx'; policy = 'WindowsUpdate:DeferQualityUpdates'; state = 'Enabled' },
                        [pscustomobject]@{ kind = 'registry'; key = 'SYSTEM\CurrentControlSet\Services\X'; valueName = 'Start'; type = 'DWord'; value = 4; source = 'https://x.example' },
                        [pscustomobject]@{ kind = 'registry'; key = 'SOFTWARE\Policies\Microsoft\Windows Defender'; valueName = 'DisableAntiSpyware'; type = 'DWord'; value = 1; source = 'https://x.example' },
                        [pscustomobject]@{ kind = 'audit'; guid = '{bad}'; setting = 'Success' },
                        [pscustomobject]@{ kind = 'secpol'; key = 'Bogus\X'; value = '1' },
                        [pscustomobject]@{ kind = 'magic' }) })
            $e = @(InModuleScope iGWindowsTuner -Parameters @{ P = $bad } { param($P) Test-IgwtPolicyPresetCatalog -Presets $P }) -join "`n"
            $e | Should -Match 'quality updates are never deferred'
            $e | Should -Match 'machine Policies key'
            $e | Should -Match 'denylist'
            $e | Should -Match 'subcategory GUID'
            $e | Should -Match 'Unknown section'
            $e | Should -Match "unknown kind 'magic'"
        }
        It 'resolves every setting of every preset on this PC (Windows Pro)' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions on this PC'; return }
            foreach ($p in $script:Presets) {
                $plan = InModuleScope iGWindowsTuner -Parameters @{ I = $p.id } { param($I) Get-IgwtPolicyPresetPlan -Id $I }
                @($plan.Rows | Where-Object { $_.Status -in 'Unavailable', 'Refused', 'Unknown' } | ForEach-Object { "$($_.Name): $($_.Reason)" }) | Should -BeNullOrEmpty -Because $p.id
                @($plan.Refusals) | Should -BeNullOrEmpty -Because $p.id
            }
        }
        It 'writes one value when an element shares the policy value name (Join Microsoft MAPS)' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $ops = @(InModuleScope iGWindowsTuner { Get-IgwtPolicyRegistryOps -Policy (Get-IgwtPolicyDefinition -Id 'WindowsDefender:SpynetReporting') -State Enabled -Values @{ SpynetReporting = 'Advanced MAPS' } })
            $ops.Count | Should -Be 1
            $ops[0].Value | Should -Be 2
            $off = @(InModuleScope iGWindowsTuner { Get-IgwtPolicyRegistryOps -Policy (Get-IgwtPolicyDefinition -Id 'WindowsDefender:SpynetReporting') -State Disabled })
            @($off | Where-Object Op -EQ 'Delete').Count | Should -Be 0
        }
        It 'notes settings that this edition does not enforce' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $plan = InModuleScope iGWindowsTuner { Get-IgwtPolicyPresetPlan -Id 'kiosk-shared' }
            ($plan.Rows | Where-Object { $_.Setting.policy -eq 'WindowsStore:RemoveWindowsStore_2' }).Note | Should -Match 'Not effective on Professional'
        }
    }

    Context 'Batch apply and revert' {
        It 'applies a preset with one backup, one Registry.pol write and one gpupdate, verifies and reverts' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $r = InModuleScope iGWindowsTuner { Invoke-IgwtPolicyPreset -Id 'secure-gaming' }
            $r.Changed | Should -Be 8
            $r.Verified | Should -BeTrue -Because (@($r.Mismatch) -join ', ')
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate -Times 1 -Exactly
            $names = @(Get-TestPolEntries | ForEach-Object { $_.ValueName })
            $names | Should -Contain 'PUAProtection'
            $names | Should -Contain 'SmartScreenPuaEnabled'
            $names | Should -Contain 'EnableMulticast'
            $rec = Get-Content $r.Record -Raw | ConvertFrom-Json
            $rec.gpoBackup | Should -Not -BeNullOrEmpty
            $again = InModuleScope iGWindowsTuner { Get-IgwtPolicyPresetPlan -Id 'secure-gaming' }
            $again.Changes | Should -Be 0
            $null = InModuleScope iGWindowsTuner -Parameters @{ R = $r.Record } { param($R) Restore-IgwtPolicyPreset -Record $R }
            Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
        }
        It 'applies audit and security settings through their engines and reverts them' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $r = InModuleScope iGWindowsTuner { Invoke-IgwtPolicyPreset -Id 'audit-logging' -NoRefresh }
            $script:Audit['{0CCE922B-69AE-11D9-BED3-505054503030}'] | Should -Be 'Success'
            $script:Audit['{0CCE9215-69AE-11D9-BED3-505054503030}'] | Should -Be 'SuccessAndFailure'
            $script:SecDb['Registry Values']['MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'] | Should -Be '4,1'
            $rec = Get-Content $r.Record -Raw | ConvertFrom-Json
            $rec.auditBackup | Should -Not -BeNullOrEmpty; $rec.secpolBackup | Should -Not -BeNullOrEmpty
            $null = InModuleScope iGWindowsTuner -Parameters @{ R = $r.Record } { param($R) Restore-IgwtPolicyPreset -Record $R -NoRefresh }
            $script:Audit['{0CCE922B-69AE-11D9-BED3-505054503030}'] | Should -Be 'None'
        }
        It 'refuses the whole preset when a lockout safeguard fires and writes nothing' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            Mock -ModuleName iGWindowsTuner Get-IgwtLocalAccountAudit { [pscustomobject]@{ Readable = $true; AdminsKnown = $true; Accounts = @([pscustomobject]@{ Name = 'ario'; Sid = 'S-1-5-21-1-2-3-1001'; Enabled = $true; Role = 'User'; IsAdmin = $true; PasswordLastSet = (Get-Date) }) } }
            $script:SecDb['System Access']['LockoutDuration'] = '0'
            $null = InModuleScope iGWindowsTuner { $script:IgwtPolicyPresets = $null }
            # credentials-hardening sets duration 10, so it passes; a preset copy with duration 0 must be refused.
            $p = (Get-Content (Join-Path $script:IgwtProjectRoot 'data\policy\presets.json') -Raw | ConvertFrom-Json).presets | Where-Object id -EQ 'policy.credentials-hardening'
            ($p.settings | Where-Object { $_.key -eq 'SystemAccess\LockoutDuration' }).value = '0'
            InModuleScope iGWindowsTuner -Parameters @{ P = $p } { param($P) $script:IgwtPolicyPresets = @($P) }
            { InModuleScope iGWindowsTuner { Invoke-IgwtPolicyPreset -Id 'credentials-hardening' } } | Should -Throw '*only one enabled administrator*'
            Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
            InModuleScope iGWindowsTuner { $script:IgwtPolicyPresets = $null }
        }
        It 'needs the acknowledgement on a managed PC' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; DomainJoined = $false; DomainName = ''; Authorities = @('Intune'); LocalGroupPolicy = $true } }
            { InModuleScope iGWindowsTuner { Invoke-IgwtPolicyPreset -Id 'secure-gaming' -NoRefresh } } | Should -Throw '*AcknowledgeManaged*'
        }
    }

    Context 'Exports' {
        It 'writes an LGPO-style GPO backup folder that round-trips' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $out = Join-Path $TestDrive 'exp-gpo'
            $r = InModuleScope iGWindowsTuner -Parameters @{ O = $out } { param($O) Export-IgwtPolicyPreset -Id 'audit-logging' -Format GpoBackup -Path $O }
            $pol = @($r.Files | Where-Object { $_ -like '*\Machine\registry.pol' })[0]
            $inf = @($r.Files | Where-Object { $_ -like '*\SecEdit\GptTmpl.inf' })[0]
            $csv = @($r.Files | Where-Object { $_ -like '*\Audit\audit.csv' })[0]
            @(InModuleScope iGWindowsTuner -Parameters @{ P = $pol } { param($P) (Read-IgwtRegistryPol -Path $P).Entries }).Count | Should -BeGreaterThan 5
            (InModuleScope iGWindowsTuner -Parameters @{ P = $inf } { param($P) Read-IgwtSecurityInfFile -Path $P })['Registry Values'].Count | Should -Be 1
            @(InModuleScope iGWindowsTuner -Parameters @{ T = [IO.File]::ReadAllText($csv) } { param($T) ConvertFrom-IgwtAuditCsv -Text $T }).Count | Should -Be $script:AuditGuids.Count
            Get-Content (Join-Path $out 'README.txt') -Raw | Should -Match 'LGPO\.exe /m'
        }
        It 'writes .reg, script and JSON exports' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $out = Join-Path $TestDrive 'exp-other'
            $reg = InModuleScope iGWindowsTuner -Parameters @{ O = $out } { param($O) Export-IgwtPolicyPreset -Id 'edge-security' -Format Reg -Path $O }
            $text = [IO.File]::ReadAllText($reg.Files[0])
            $text | Should -Match '^Windows Registry Editor Version 5\.00'
            $text | Should -Match '"SmartScreenEnabled"=dword:00000001'
            $text | Should -Match '"BasicAuthOverHttpEnabled"=dword:00000000'
            $ps = InModuleScope iGWindowsTuner -Parameters @{ O = $out } { param($O) Export-IgwtPolicyPreset -Id 'audit-logging' -Format Script -Path $O }
            $script = @($ps.Files | Where-Object { $_ -like '*.ps1' })[0]
            $errs = $null; $null = [System.Management.Automation.PSParser]::Tokenize([IO.File]::ReadAllText($script), [ref]$errs)
            @($errs).Count | Should -Be 0
            [IO.File]::ReadAllText($script) | Should -Match 'SupportsShouldProcess'
            [IO.File]::ReadAllText($script) | Should -Match "auditpol /set /subcategory:'\{0CCE922B-69AE-11D9-BED3-505054503030\}' /success:enable /failure:disable"
            @($ps.Files | Where-Object { $_ -like '*.inf' }).Count | Should -Be 1
            $js = InModuleScope iGWindowsTuner -Parameters @{ O = $out } { param($O) Export-IgwtPolicyPreset -Id 'wufb-gaming' -Format Json -Path $O }
            $doc = Get-Content $js.Files[0] -Raw | ConvertFrom-Json
            $doc.kind | Should -Be 'igwt-policy-preset-export'
            @($doc.machineOps | Where-Object ValueName -EQ 'DeferFeatureUpdatesPeriodInDays')[0].Value | Should -Be 90
        }
        It 'converts every operation kind to .reg' {
            $t = InModuleScope iGWindowsTuner { ConvertTo-IgwtRegText -Machine @([pscustomobject]@{ Op = 'Set'; Key = 'SOFTWARE\Policies\A'; ValueName = 'S'; Type = 'String'; Value = 'a"b\c' }, [pscustomobject]@{ Op = 'Set'; Key = 'SOFTWARE\Policies\A'; ValueName = 'M'; Type = 'MultiString'; Value = @('x') }, [pscustomobject]@{ Op = 'Delete'; Key = 'SOFTWARE\Policies\A'; ValueName = 'D'; Type = ''; Value = $null }, [pscustomobject]@{ Op = 'Set'; Key = 'SOFTWARE\Policies\A'; ValueName = 'Q'; Type = 'QWord'; Value = [uint64]1 }) }
            $t | Should -Match '"S"="a\\"b\\\\c"'
            $t | Should -Match '"M"=hex\(7\):78,00,00,00,00,00'
            $t | Should -Match '"D"=-'
            $t | Should -Match '"Q"=hex\(b\):01,00,00,00,00,00,00,00'
        }
    }

    Context 'Baseline import and compare' {
        It 'imports an exported GPO folder, compares, applies the differences and then matches' {
            if (-not $script:HaveAdmx) { Set-ItResult -Skipped -Because 'no PolicyDefinitions'; return }
            $out = Join-Path $TestDrive 'baseline1'
            $null = InModuleScope iGWindowsTuner -Parameters @{ O = $out } { param($O) Export-IgwtPolicyPreset -Id 'audit-logging' -Format GpoBackup -Path $O }
            $guid = (Get-ChildItem -LiteralPath $out -Directory)[0].FullName
            [IO.File]::WriteAllText((Join-Path $guid 'bkupInfo.xml'), '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest"><GPODisplayName><![CDATA[Test Baseline - Computer]]></GPODisplayName></BackupInst>')
            $b = InModuleScope iGWindowsTuner -Parameters @{ O = $out } { param($O) Import-IgwtPolicyBaseline -Path $O }
            $b.Gpos.Count | Should -Be 1
            $b.Gpos[0].Name | Should -Be 'Test Baseline - Computer'
            $rows = @(InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Compare-IgwtPolicyBaseline -Baseline $B })
            @($rows | Where-Object Area -Like 'Registry*').Count | Should -BeGreaterThan 5
            @($rows | Where-Object { $_.Status -eq 'Match' }).Count | Should -Be 0
            ($rows | Where-Object Area -EQ 'Audit')[0].Status | Should -Be 'Differs'
            $csv = Join-Path $TestDrive 'compare.csv'
            InModuleScope iGWindowsTuner -Parameters @{ R = $rows; P = $csv } { param($R, $P) Export-IgwtPolicyComparison -Rows $R -Path $P }
            @(Import-Csv $csv).Count | Should -Be $rows.Count
            $plan = InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Get-IgwtPolicyBaselinePlan -Baseline $B -Select @('differs') }
            $plan.Changes | Should -Be $rows.Count
            $res = InModuleScope iGWindowsTuner -Parameters @{ P = $plan } { param($P) Invoke-IgwtPolicyBatch -Plan $P }
            $res.Verified | Should -BeTrue -Because (@($res.Mismatch) -join ', ')
            $after = @(InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Compare-IgwtPolicyBaseline -Baseline $B })
            @($after | Where-Object Status -NE 'Match' | ForEach-Object { "$($_.Area) $($_.Setting) $($_.Status) $($_.Effective)" }) | Should -BeNullOrEmpty
        }
        It 'marks denylisted baseline values as Blocked and never selects them with differs' {
            $dir = Join-Path $TestDrive 'baseline2\Machine'
            $null = New-Item -ItemType Directory -Path $dir -Force
            $e = @(InModuleScope iGWindowsTuner { New-IgwtPolEntryObject -Key 'SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'DisableAntiSpyware' -Type 4 -Data ([BitConverter]::GetBytes([uint32]1)); New-IgwtPolEntryObject -Key 'SOFTWARE\Policies\IgwtBaseline' -ValueName 'Ok' -Type 4 -Data ([BitConverter]::GetBytes([uint32]1)) })
            [IO.File]::WriteAllBytes((Join-Path $dir 'registry.pol'), (InModuleScope iGWindowsTuner -Parameters @{ E = $e } { param($E) ConvertTo-IgwtRegistryPolBytes -Entries $E }))
            $b = InModuleScope iGWindowsTuner -Parameters @{ P = (Join-Path $TestDrive 'baseline2') } { param($P) Import-IgwtPolicyBaseline -Path $P }
            $rows = @(InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Compare-IgwtPolicyBaseline -Baseline $B })
            ($rows | Where-Object Setting -Like '*DisableAntiSpyware').Status | Should -Be 'Blocked'
            $plan = InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Get-IgwtPolicyBaselinePlan -Baseline $B -Select @('differs') }
            @($plan.Rows | ForEach-Object { $_.Name }) | Should -Not -Match 'DisableAntiSpyware'
            $explicit = InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Get-IgwtPolicyBaselinePlan -Baseline $B -Select @('Registry|Machine|SOFTWARE\Policies\Microsoft\Windows Defender|DisableAntiSpyware') }
            $explicit.Rows[0].Status | Should -Be 'Refused'
            { InModuleScope iGWindowsTuner -Parameters @{ P = $explicit } { param($P) Invoke-IgwtPolicyBatch -Plan $P -NoRefresh } } | Should -Throw '*Refused*'
        }
        It 'refuses a folder without policy files' {
            $d = Join-Path $TestDrive 'empty-baseline'; $null = New-Item -ItemType Directory -Path $d -Force
            { InModuleScope iGWindowsTuner -Parameters @{ P = $d } { param($P) Import-IgwtPolicyBaseline -Path $P } } | Should -Throw '*No registry.pol*'
        }
    }
}
