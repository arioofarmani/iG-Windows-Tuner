# Defender settings editor: the catalog covers every Get-MpPreference property, values parse and
# format by type, the rules never turn a protection off or lower it, changes write a 'Defender'
# snapshot and revert exactly, and the Defender Group Policy list. Defender cmdlets are mocked;
# registry values live in TestRegistry and the GPO and ADMX folders in TestDrive.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Catalog = Get-Content (Join-Path $script:IgwtProjectRoot 'data\defender\settings.json') -Raw | ConvertFrom-Json
    function Get-TestPref {
        return [pscustomobject][ordered]@{
            DisableRealtimeMonitoring = $false; DisableEmailScanning = $true; MAPSReporting = [byte]2; CloudBlockLevel = [byte]0; CloudExtendedTimeout = [uint32]0
            SubmitSamplesConsent = [byte]1; PUAProtection = [byte]1; EnableNetworkProtection = [byte]1; ScanAvgCPULoadFactor = [byte]50
            ScanScheduleTime = [timespan]'02:00:00'; ScanScheduleDay = [byte]0; SignatureFallbackOrder = 'MicrosoftUpdateServer|MMPC'
            DisableQuicParsing = $true; DisableTamperProtection = $false; AiAgentProtection = [byte]0; LowThreatDefaultAction = [byte]0
        }
    }
    function Invoke-InModule([scriptblock]$Script, [hashtable]$Parameters = @{}) { $m = Get-Module iGWindowsTuner; & $m $Script @Parameters }
}

Describe 'Defender settings catalog' {
    It 'covers every Get-MpPreference property of the fixture exactly once' {
        $fixture = Get-Content (Join-Path $PSScriptRoot 'fixtures\defender\mppreference-properties.json') -Raw | ConvertFrom-Json
        $known = @(@($script:Catalog.settings | ForEach-Object { [string]$_.mp }) + @($script:Catalog.coveredElsewhere | ForEach-Object { [string]$_.mp }))
        foreach ($p in @($fixture.properties)) { $known | Should -Contain $p -Because "Get-MpPreference reports $p" }
        @($known | Group-Object | Where-Object Count -GT 1 | ForEach-Object Name) | Should -BeNullOrEmpty
        @($script:Catalog.settings).Count | Should -BeGreaterOrEqual 123
    }
    It 'has valid kinds, types, edit routes, categories, enum values and sources' {
        $cats = @($script:Catalog.categories | ForEach-Object { [string]$_.id })
        $docs = @($script:Catalog.docs.PSObject.Properties | ForEach-Object Name)
        foreach ($s in @($script:Catalog.settings)) {
            $s.kind | Should -BeIn @('protection', 'hardening', 'level', 'option', 'parser', 'info') -Because $s.mp
            $s.type | Should -BeIn @('bool', 'enum', 'uint', 'time', 'text', 'list') -Because $s.mp
            $s.edit | Should -BeIn @('set', 'parser', 'policy', 'readonly') -Because $s.mp
            $cats | Should -Contain ([string]$s.category) -Because $s.mp
            ([string]$s.name).Length | Should -BeGreaterThan 0
            ([string]$s.hint).Length | Should -BeLessOrEqual 160 -Because $s.mp
            if ($s.doc) { $docs | Should -Contain ([string]$s.doc) -Because $s.mp }
            if ($s.policy) { [string]$s.policy | Should -Match '^WindowsDefender:\w+$' -Because $s.mp }
            if ($s.kind -in 'protection', 'hardening', 'level', 'parser') { $null -eq $s.on | Should -BeFalse -Because "$($s.mp) needs its protective value" }
            if (($s.kind -eq 'parser') -or ($s.edit -eq 'parser')) { $s.kind | Should -Be 'parser'; $s.edit | Should -Be 'parser' }
            if ($s.edit -eq 'readonly') { [string]$s.note | Should -Not -BeNullOrEmpty -Because "$($s.mp) must say why it is shown only" }
            if ($s.edit -eq 'policy') { [string]$s.policy | Should -Not -BeNullOrEmpty -Because $s.mp }
            if ($s.type -eq 'list') { $s.edit | Should -Not -Be 'set' -Because $s.mp }
            if ($s.type -eq 'enum') {
                $vals = Invoke-InModule { param($D) @(Get-IgwtDefenderEnumValues -Definition $D) } @{ D = $s }
                @($vals).Count | Should -BeGreaterThan 1 -Because $s.mp
                foreach ($v in $vals) { $null -eq $v.v | Should -BeFalse; [string]$v.label | Should -Not -BeNullOrEmpty }
            }
            if ($null -ne $s.on) { { Invoke-InModule { param($D) $null = ConvertTo-IgwtDefenderSettingValue -Definition $D -Value $D.on } @{ D = $s } } | Should -Not -Throw -Because $s.mp }
        }
    }
    It 'never makes exclusions, Tamper Protection or undocumented settings editable, and refuses every off value' {
        foreach ($s in @($script:Catalog.settings)) {
            if (($s.type -eq 'list' -and [string]$s.mp -match 'Exclusion') -or [string]$s.mp -match 'Tamper') { $s.edit | Should -Be 'readonly' -Because $s.mp }
            if ([string]$s.note -match 'Not documented') { $s.edit | Should -Be 'readonly' -Because $s.mp }
            if ($s.kind -eq 'protection' -and $s.type -eq 'bool') { if ([string]$s.mp -like 'Disable*') { $s.on | Should -BeFalse -Because $s.mp } else { $s.on | Should -BeTrue -Because $s.mp } }
        }
        $enumLists = @(@($script:Catalog.settings | Where-Object { $_.values -and $_.values -isnot [string] } | ForEach-Object { @($_.values) }) + @($script:Catalog.enums.PSObject.Properties | ForEach-Object { @($_.Value) }))
        foreach ($v in $enumLists) { if ([string]$v.label -in 'Off', 'Never send', 'Allow', 'No action', 'None') { $v.refused | Should -BeTrue -Because "'$($v.label)' turns a protection off" } }
    }
}

Describe 'Defender setting values and rules' {
    It 'parses on/off, labels, numbers and times and formats them back' {
        InModuleScope iGWindowsTuner {
            $d = { param($n) Get-IgwtDefenderSettingDefinition -Name $n }
            ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'DisableRealtimeMonitoring') -Value 'on' | Should -BeFalse
            ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'DisableRealtimeMonitoring') -Value 'off' | Should -BeTrue
            ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'cloudblocklevel') -Value 'High' | Should -Be 2
            ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'CloudBlockLevel') -Value '4' | Should -Be 4
            { ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'CloudBlockLevel') -Value 'Ultra' } | Should -Throw '*not a valid value*'
            ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'ScanScheduleTime') -Value '03:30' | Should -Be 210
            { ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'ScanScheduleTime') -Value '25:00' } | Should -Throw '*not a valid time*'
            { ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'ScanAvgCPULoadFactor') -Value '-1' } | Should -Throw '*whole number*'
            ConvertTo-IgwtDefenderSettingValue -Definition (& $d 'ScanScheduleDay') -Value 'Friday' | Should -Be 6
            Format-IgwtDefenderSettingValue -Definition (& $d 'ScanScheduleTime') -Value 210 | Should -Be '03:30'
            Format-IgwtDefenderSettingValue -Definition (& $d 'CloudBlockLevel') -Value 2 | Should -Be 'High'
            Format-IgwtDefenderSettingValue -Definition (& $d 'DisableRealtimeMonitoring') -Value $false | Should -Be 'On'
            Format-IgwtDefenderSettingValue -Definition (& $d 'ScanOnlyIfIdleEnabled') -Value $true | Should -Be 'Yes'
            ConvertFrom-IgwtMpRawValue -Definition (& $d 'ScanScheduleTime') -Raw ([timespan]'01:45:00') | Should -Be 105
            { Get-IgwtDefenderSettingDefinition -Name 'NoSuchSetting' } | Should -Throw '*not a Defender setting*'
        }
    }
    It 'refuses values that turn a protection off or lower it, and allows raising and options' {
        InModuleScope iGWindowsTuner {
            $t = { param($n, $v, $cur) $d = Get-IgwtDefenderSettingDefinition -Name $n; $x = ConvertTo-IgwtDefenderSettingValue -Definition $d -Value $v; if ($null -ne $cur) { Test-IgwtDefenderSettingValue -Definition $d -Value $x -Current (ConvertTo-IgwtDefenderSettingValue -Definition $d -Value $cur) } else { Test-IgwtDefenderSettingValue -Definition $d -Value $x } }
            & $t 'DisableRealtimeMonitoring' $true $null | Should -Match 'never turns a protection off'
            & $t 'DisableRealtimeMonitoring' $false $null | Should -BeNullOrEmpty
            & $t 'MAPSReporting' 0 $null | Should -Match 'refused'
            & $t 'SubmitSamplesConsent' 2 $null | Should -Match 'Block at First Sight'
            & $t 'PUAProtection' 2 1 | Should -Match 'never lowers'
            & $t 'PUAProtection' 1 2 | Should -BeNullOrEmpty
            & $t 'CloudBlockLevel' 2 0 | Should -BeNullOrEmpty
            & $t 'CloudBlockLevel' 0 4 | Should -Match 'never lowers'
            & $t 'CloudBlockLevel' 2 6 | Should -BeNullOrEmpty
            & $t 'DisableTamperProtection' $true $null | Should -Match 'never changes it'
            & $t 'LowThreatDefaultAction' 2 $null | Should -Match 'Group Policy'
            & $t 'DisableQuicParsing' $true $null | Should -Match 'only ever turned on'
            & $t 'ScanAvgCPULoadFactor' 0 $null | Should -BeNullOrEmpty
            & $t 'ScanAvgCPULoadFactor' 30 $null | Should -BeNullOrEmpty
            & $t 'ScanAvgCPULoadFactor' 3 $null | Should -Match 'outside'
            & $t 'ScanAvgCPULoadFactor' 101 $null | Should -Match 'outside'
            & $t 'SignatureFallbackOrder' 'FileShares' $null | Should -Match 'Microsoft Update'
            & $t 'SignatureFallbackOrder' 'MMPC|FileShares' $null | Should -BeNullOrEmpty
            & $t 'SignatureFallbackOrder' 'Evil|MMPC' $null | Should -Match 'expected format'
            & $t 'AiAgentProtection' 'Audit' $null | Should -BeNullOrEmpty
            & $t 'AiAgentProtection' 0 $null | Should -Match 'never turns a protection off'
            & $t 'BruteForceProtectionConfiguredState' 'Off' $null | Should -Match 'refused'
            & $t 'ScanScheduleDay' 'Never' $null | Should -BeNullOrEmpty
        }
    }
    It 'reports On, Off, Below, Optional and Info' {
        InModuleScope iGWindowsTuner {
            $s = { param($n, $v) $d = Get-IgwtDefenderSettingDefinition -Name $n; Get-IgwtDefenderSettingStatus -Definition $d -Value (ConvertTo-IgwtDefenderSettingValue -Definition $d -Value $v) }
            & $s 'DisableRealtimeMonitoring' $false | Should -Be 'On'
            & $s 'DisableRealtimeMonitoring' $true | Should -Be 'Off'
            & $s 'CloudBlockLevel' 0 | Should -Be 'Below'
            & $s 'CloudBlockLevel' 6 | Should -Be 'On'
            & $s 'MAPSReporting' 0 | Should -Be 'Off'
            & $s 'DisableEmailScanning' $true | Should -Be 'Optional'
            & $s 'ScanScheduleDay' 0 | Should -Be 'Info'
            & $s 'CloudExtendedTimeout' 50 | Should -Be 'On'
            & $s 'CloudExtendedTimeout' 10 | Should -Be 'Below'
        }
    }
}

Describe 'Defender settings editor (Defender cmdlets mocked)' {
    BeforeEach {
        $script:Pref = Get-TestPref
        Mock -ModuleName iGWindowsTuner Get-MpPreference { $script:Pref }
        Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { [pscustomobject]@{ AMServiceEnabled = $true; AntivirusEnabled = $true; AMRunningMode = 'Normal'; RealTimeProtectionEnabled = $true; IsTamperProtected = $true } }
        Mock -ModuleName iGWindowsTuner Set-MpPreference {
            foreach ($k in @($PesterBoundParameters.Keys)) {
                if ($k -in 'ErrorAction', 'WarningAction', 'Verbose', 'Debug') { continue }
                $v = $PesterBoundParameters[$k]
                if ($v -is [datetime]) { $v = $v.TimeOfDay }
                $script:Pref.$k = $v
            }
        }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $true } }
        # These tests are about the rules, so every catalog setting is writable whatever Windows this runs on.
        $script:AllNames = @($script:Catalog.settings | ForEach-Object { [string]$_.mp })
        Mock -ModuleName iGWindowsTuner Get-IgwtMpWriteParameterInfo { [pscustomobject]@{ Available = $true; Names = $script:AllNames } }
        $script:GpoRoot = Join-Path $TestDrive ('GPO-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $admx = Join-Path $TestDrive 'NoAdmx'; $null = New-Item -ItemType Directory -Path $admx -Force
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:GpoRoot; A = $admx } { param($R, $A) $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtAdmxCache = $null }
        Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager' -Recurse -Force -ErrorAction SilentlyContinue
    }
    AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

    It 'lists reported settings with display values, choices and how to change them' {
        $rows = @(InModuleScope iGWindowsTuner { Get-IgwtDefenderSettings })
        $rows.Count | Should -Be 16
        $time = $rows | Where-Object Property -EQ 'ScanScheduleTime'
        $time.Display | Should -Be '02:00'; $time.Editable | Should -BeTrue; $time.Status | Should -Be 'Info'
        $rtp = $rows | Where-Object Property -EQ 'DisableRealtimeMonitoring'
        @($rtp.Choices | Where-Object { -not $_.Allowed } | ForEach-Object Label) | Should -Be @('Off')
        $pua = $rows | Where-Object Property -EQ 'PUAProtection'
        @($pua.Choices | Where-Object { $_.Allowed } | ForEach-Object Label) | Should -Be @('Block')
        ($rows | Where-Object Property -EQ 'DisableTamperProtection').Editable | Should -BeFalse
        ($rows | Where-Object Property -EQ 'LowThreatDefaultAction').Change | Should -Match 'Group Policy only'
        ($rows | Where-Object Property -EQ 'DisableEmailScanning').Status | Should -Be 'Optional'
        ($rows | Where-Object Property -EQ 'CloudBlockLevel').ProtectiveDisplay | Should -Be 'High'
        $script:Pref | Add-Member -NotePropertyName 'FutureDefenderSetting' -NotePropertyValue 3
        $new = @(InModuleScope iGWindowsTuner { Get-IgwtDefenderSettings }) | Where-Object Property -EQ 'FutureDefenderSetting'
        $new.Edit | Should -Be 'readonly'; $new.Display | Should -Be '3'; $new.Note | Should -Match 'not in the catalog yet'
    }
    It 'reverts option values exactly and keeps a protection on when the earlier value was off' {
        $script:Pref.DisableRealtimeMonitoring = $true
        $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting ([ordered]@{ DisableRealtimeMonitoring = 'on'; ScanScheduleDay = 'Friday' }) }
        $script:Pref.DisableRealtimeMonitoring | Should -BeFalse
        $rev = InModuleScope iGWindowsTuner -Parameters @{ P = $r.Snapshot } { param($P) Invoke-IgwtRevert -SnapshotPath $P }
        $script:Pref.DisableRealtimeMonitoring | Should -BeFalse -Because 'a revert never turns real-time protection off'
        [int]$script:Pref.ScanScheduleDay | Should -Be 0
        @($rev.Results | ForEach-Object Result | Sort-Object) | Should -Be @('Kept', 'Reverted')
    }
    It 'plans changes and refuses what may not change (off values, MDM, Defender not active)' {
        $plan = InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting ([ordered]@{ CloudBlockLevel = 'High'; ScanScheduleTime = '02:00'; MAPSReporting = 0 }) }
        ($plan.Rows | Where-Object Property -EQ 'CloudBlockLevel').HasChange | Should -BeTrue
        ($plan.Rows | Where-Object Property -EQ 'ScanScheduleTime').HasChange | Should -BeFalse
        ($plan.Rows | Where-Object Property -EQ 'MAPSReporting').Refused | Should -Match 'refused'
        $plan.Refused | Should -Be 1
        $null = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Force
        $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Name 'CloudBlockLevel' -Value 2 -PropertyType DWord
        (InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ CloudBlockLevel = 'High' } }).Rows[0].Refused | Should -Match 'Set by MDM'
        Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { [pscustomobject]@{ AMServiceEnabled = $true; AMRunningMode = 'Passive Mode' } }
        (InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ ScanAvgCPULoadFactor = 30 } }).Rows[0].Refused | Should -Match 'not the active antivirus'
        { InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ NoSuchSetting = 1 } } } | Should -Throw '*not a Defender setting*'
    }
    It 'changes settings after a Defender snapshot and reverts them exactly' {
        $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting ([ordered]@{ CloudBlockLevel = 'High'; ScanScheduleTime = '03:30'; ScanAvgCPULoadFactor = 30 }) }
        $r.Changes | Should -Be 3
        @($r.Results | Where-Object Result -NE 'Applied') | Should -BeNullOrEmpty
        $doc = Get-Content $r.Snapshot -Raw | ConvertFrom-Json
        $doc.operation | Should -Be 'Defender'
        @($doc.entries).Count | Should -Be 3
        Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 1 -Exactly -ParameterFilter { $null -ne $ScanScheduleTime -and $ScanScheduleTime.TimeOfDay -eq [timespan]'03:30:00' }
        Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 1 -Exactly -ParameterFilter { $null -ne $CloudBlockLevel -and [int]$CloudBlockLevel -eq 2 }
        [int]$script:Pref.CloudBlockLevel | Should -Be 2
        $rev = InModuleScope iGWindowsTuner -Parameters @{ P = $r.Snapshot } { param($P) Invoke-IgwtRevert -SnapshotPath $P }
        @($rev.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 2
        ($rev.Results | Where-Object Result -EQ 'Kept').Message | Should -Match 'never turns a protection off or lowers it'
        [int]$script:Pref.CloudBlockLevel | Should -Be 2 -Because 'a revert never lowers a protection level'
        [int]$script:Pref.ScanAvgCPULoadFactor | Should -Be 50
        $script:Pref.ScanScheduleTime | Should -Be ([timespan]'02:00:00')
        (Get-Content $rev.Snapshot -Raw | ConvertFrom-Json).operation | Should -Be 'Defender'
    }
    It 'changes nothing when one setting is refused, and reports a value Defender kept' {
        { InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High'; DisableRealtimeMonitoring = $true } } } | Should -Throw '*Refused*'
        Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
        Mock -ModuleName iGWindowsTuner Set-MpPreference { }
        $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High' } }
        $r.Results[0].Result | Should -Be 'NotApplied'
        $r.Results[0].Message | Should -Match 'Tamper Protection or a policy'
    }
    It 'turns a parser on without a snapshot and refuses managed PCs without acknowledgement' {
        $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ DisableQuicParsing = 'on' } }
        $r.Snapshot | Should -BeNullOrEmpty
        $r.Results[0].Message | Should -Match 'only ever turned on'
        Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 1 -Exactly -ParameterFilter { $DisableQuicParsing -eq $false }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; DomainJoined = $false; Authorities = @('Intune'); LocalGroupPolicy = $true } }
        { InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High' } } } | Should -Throw '*AcknowledgeManaged*'
        $ok = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High' } -AcknowledgeManaged }
        $ok.Results[0].Result | Should -Be 'Applied'
    }
    It 'refuses to revert snapshot entries for settings the editor never changes' {
        $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High' } }
        $text = (Get-Content $r.Snapshot -Raw).Replace('"CloudBlockLevel"', '"DisableTamperProtection"').Replace('"value":  0', '"value":  true')
        [IO.File]::WriteAllText($r.Snapshot, $text)
        $rev = InModuleScope iGWindowsTuner -Parameters @{ P = $r.Snapshot } { param($P) Restore-IgwtDefenderSettingSnapshot -SnapshotPath $P }
        $rev.Results[0].Result | Should -Be 'Failed'
        $rev.Results[0].Message | Should -Match 'not changed by the Defender settings editor'
        $script:Pref.DisableTamperProtection | Should -BeFalse
    }

    Context 'a setting this PC cannot write' {
        BeforeEach {
            $script:Without = @($script:AllNames | Where-Object { $_ -notin 'CloudBlockLevel', 'DisableQuicParsing' })
            Mock -ModuleName iGWindowsTuner Get-IgwtMpWriteParameterInfo { [pscustomobject]@{ Available = $true; Names = $script:Without } }
        }
        It 'refuses it in the plan and in the change, in plain words, before anything is written' {
            $plan = InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ CloudBlockLevel = 'High' } }
            $plan.Rows[0].Refused | Should -Be 'Windows on this PC does not support changing this setting yet.'
            $before = @(InModuleScope iGWindowsTuner { Get-IgwtSnapshotList }).Count
            { InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High'; ScanAvgCPULoadFactor = 30 } } } | Should -Throw '*does not support changing this setting yet*'
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
            @(InModuleScope iGWindowsTuner { Get-IgwtSnapshotList }).Count | Should -Be $before -Because 'a refused change writes no snapshot'
        }
        It 'still explains the rules first, and refuses at the write point too' {
            (InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ CloudBlockLevel = 'Default'; MAPSReporting = 0 } }).Rows[1].Refused | Should -Match 'refused'
            { InModuleScope iGWindowsTuner { Invoke-IgwtMpPreferenceWrite -Definition (Get-IgwtDefenderSettingDefinition -Name 'CloudBlockLevel') -Value 2 -Confirm:$false } } | Should -Throw '*does not support*'
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
        }
        It 'lists it as not changeable here instead of offering it' {
            $rows = @(InModuleScope iGWindowsTuner { Get-IgwtDefenderSettings })
            $s = $rows | Where-Object Property -EQ 'CloudBlockLevel'
            $s.Supported | Should -BeFalse; $s.Editable | Should -BeFalse
            $s.Display | Should -Be 'Default' -Because 'the current value is still shown'
            $s.Status | Should -Be 'Info' -Because 'a value nobody can change here is not listed under Needs attention'
            $s.Change | Should -Match 'does not support changing'
            @($s.Choices | Where-Object Allowed) | Should -BeNullOrEmpty
            @($s.Choices | ForEach-Object Why | Select-Object -Unique) | Should -Match 'does not support changing'
            ($rows | Where-Object Property -EQ 'ScanAvgCPULoadFactor').Supported | Should -BeTrue
            $row = InModuleScope iGWindowsTuner -Parameters @{ S = $s } { param($S) New-IgwtGuiDefenderRow -Setting $S }
            $row.EditText | Should -Be 'Not changeable here'; $row.EditableKey | Should -Be 'No'; $row.RecommendText | Should -Match 'does not support changing'
        }
        It 'skips an unsupported parser and names it, on both parser routes' {
            (InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ DisableQuicParsing = 'on' } }).Rows[0].Refused | Should -Match 'does not support'
            $r = InModuleScope iGWindowsTuner { Set-IgwtDefenderParsersOn -Name 'DisableQuicParsing' }
            @($r.TurnedOn) | Should -BeNullOrEmpty
            @($r.Unsupported) | Should -Be @('QUIC parser')
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
        }
    }

    Context 'without the Defender commands (another antivirus)' {
        BeforeEach {
            Mock -ModuleName iGWindowsTuner Get-IgwtMpWriteParameterInfo { [pscustomobject]@{ Available = $false; Names = @() } }
            Mock -ModuleName iGWindowsTuner Get-MpPreference { throw "The term 'Get-MpPreference' is not recognized" }
            Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { throw "The term 'Get-MpComputerStatus' is not recognized" }
        }
        It 'answers without throwing and refuses the change' {
            $plan = InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChangePlan -Setting @{ ScanAvgCPULoadFactor = 30 } }
            $plan.Rows[0].Refused | Should -Match 'commands are not available'
            InModuleScope iGWindowsTuner { Test-IgwtMpPreferenceWritable -Name 'ScanAvgCPULoadFactor' } | Should -BeFalse
            InModuleScope iGWindowsTuner { Get-IgwtDefenderSettingChoices -Definition (Get-IgwtDefenderSettingDefinition -Name 'CloudBlockLevel') | Where-Object Allowed } | Should -BeNullOrEmpty
            { InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ ScanAvgCPULoadFactor = 30 } } } | Should -Throw '*commands are not available*'
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
        }
    }

    Context 'a write that changed nothing' {
        It 'records a failed write as nothing changed: no recent change, nothing to undo, the file stays' {
            Mock -ModuleName iGWindowsTuner Set-MpPreference { throw "A parameter cannot be found that matches parameter name 'CloudBlockLevel'." }
            $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High' } }
            $r.Results[0].Result | Should -Be 'Failed'; $r.Changes | Should -Be 0
            $r.Snapshot | Should -Exist
            $row = InModuleScope iGWindowsTuner -Parameters @{ P = $r.Snapshot } { param($P) Get-IgwtSnapshotList | Where-Object Path -EQ $P }
            $row.HasChange | Should -BeFalse
            @($row.Applied) | Should -BeNullOrEmpty
        }
        It 'records a value that did not read back as nothing changed, and a mixed change only by what applied' {
            Mock -ModuleName iGWindowsTuner Set-MpPreference { }
            $r = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ CloudBlockLevel = 'High' } }
            $r.Results[0].Result | Should -Be 'NotApplied'; $r.Changes | Should -Be 0
            $doc = Get-Content $r.Snapshot -Raw | ConvertFrom-Json
            $doc.entries[0].result | Should -Be 'NotApplied'
            $doc.entries[0].message | Should -Match 'Tamper Protection or a policy'
            (InModuleScope iGWindowsTuner -Parameters @{ P = $r.Snapshot } { param($P) Get-IgwtSnapshotList | Where-Object Path -EQ $P }).HasChange | Should -BeFalse
            InModuleScope iGWindowsTuner -Parameters @{ R = $r } { param($R) Test-IgwtModuleOperationFailed -Result $R } | Should -BeTrue -Because 'the journal must not commit a change that did not read back'

            Mock -ModuleName iGWindowsTuner Set-MpPreference { if ($PesterBoundParameters.ContainsKey('CloudBlockLevel')) { throw 'no' } else { $script:Pref.ScanAvgCPULoadFactor = $PesterBoundParameters['ScanAvgCPULoadFactor'] } }
            $m = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting ([ordered]@{ CloudBlockLevel = 'High'; ScanAvgCPULoadFactor = 30 }) }
            $m.Changes | Should -Be 1
            (InModuleScope iGWindowsTuner -Parameters @{ P = $m.Snapshot } { param($P) Get-IgwtSnapshotList | Where-Object Path -EQ $P }).HasChange | Should -BeTrue
        }
        It 'never writes the earlier value of a failed or unconfirmed entry back (it could overwrite a later change)' {
            Mock -ModuleName iGWindowsTuner Set-MpPreference { throw 'blocked' }
            $f = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ ScanAvgCPULoadFactor = 30 } }
            Mock -ModuleName iGWindowsTuner Set-MpPreference { }
            $n = InModuleScope iGWindowsTuner { Invoke-IgwtDefenderSettingChange -Setting @{ ScanScheduleDay = 'Friday' } }
            $script:Pref.ScanAvgCPULoadFactor = [byte]40
            foreach ($p in $f.Snapshot, $n.Snapshot) {
                $rev = InModuleScope iGWindowsTuner -Parameters @{ P = $p } { param($P) Invoke-IgwtRevert -SnapshotPath $P }
                @($rev.Results) | Should -BeNullOrEmpty
                $rev.Snapshot | Should -BeNullOrEmpty -Because 'nothing to restore writes no new snapshot'
            }
            [int]$script:Pref.ScanAvgCPULoadFactor | Should -Be 40
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 2 -Exactly -Because 'the two attempts wrote; the reverts wrote nothing'
        }
        It 'a revert of an entry whose value is already right records no change' {
            Mock -ModuleName iGWindowsTuner Set-MpPreference { }
            $s = InModuleScope iGWindowsTuner { $x = New-IgwtSnapshot -Operation 'Defender' -Detail 'ScanAvgCPULoadFactor=30'; Save-IgwtSnapshot -Snapshot $x; Add-IgwtSnapshotEntry -Snapshot $x -TweakId 'defender:ScanAvgCPULoadFactor' -Actions @([ordered]@{ index = 0; type = 'defenderSetting'; fingerprint = 'defenderSetting|ScanAvgCPULoadFactor'; data = [ordered]@{ mp = 'ScanAvgCPULoadFactor'; value = 50 } }) -Result 'Applied' -Message '50 -> 30'; $x.Path }
            $rev = InModuleScope iGWindowsTuner -Parameters @{ P = $s } { param($P) Invoke-IgwtRevert -SnapshotPath $P }
            @($rev.Results | ForEach-Object Result) | Should -Be @('Reverted')
            (InModuleScope iGWindowsTuner -Parameters @{ P = $rev.Snapshot } { param($P) Get-IgwtSnapshotList | Where-Object Path -EQ $P }).HasChange | Should -BeFalse
            Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
        }
        It 'recognizes a snapshot written by 3.6.5 for a failed write, without changing or removing it' {
            $dir = InModuleScope iGWindowsTuner { Get-IgwtDataPath -Kind Backups }
            $null = New-Item -ItemType Directory -Path $dir -Force
            $file = Join-Path $dir 'snapshot-20261105-233501-989-Defender-old365.json'
            $json = @'
{ "schema": 2, "catalogSchema": 3, "tool": "iG Windows Tuner", "version": "3.6.5", "hardwareTags": [], "id": "00000000-0000-0000-0000-000000000365", "created": "2026-11-05T23:35:01.9894831Z",
  "operation": "Defender", "detail": "CloudBlockLevel=High", "computer": "TEST", "build": "26300.1", "userSid": "S-1-5-18", "userHiveSid": "S-1-5-18",
  "entries": [ { "tweakId": "defender:CloudBlockLevel", "result": "Failed", "message": "A parameter cannot be found that matches parameter name 'CloudBlockLevel'.", "time": "2026-11-05T23:35:02.0000000Z",
    "actions": [ { "index": 0, "type": "defenderSetting", "fingerprint": "defenderSetting|CloudBlockLevel", "data": { "mp": "CloudBlockLevel", "value": 0 } } ] } ] }
'@
            [IO.File]::WriteAllText($file, $json)
            try {
                $row = InModuleScope iGWindowsTuner -Parameters @{ F = $file } { param($F) Get-IgwtSnapshotList | Where-Object Path -EQ $F }
                $row.HasChange | Should -BeFalse
                [IO.File]::ReadAllText($file) | Should -BeExactly $json
            } finally { Remove-Item -LiteralPath $file -Force }
        }
    }
}

Describe 'What counts as a change in a snapshot' {
    It 'decides per entry result, and keeps the restore of writers that can stop halfway' -ForEach @(
        @{ Result = 'Applied'; Type = 'defenderSetting'; Expected = $true }
        @{ Result = 'Pending'; Type = 'registry'; Expected = $true }
        @{ Result = 'Reverted'; Type = 'registry'; Expected = $true }
        @{ Result = 'Failed'; Type = 'defenderSetting'; Expected = $false }
        @{ Result = 'NotApplied'; Type = 'defenderSetting'; Expected = $false }
        @{ Result = 'RolledBack'; Type = 'registry'; Expected = $false }
        @{ Result = 'Failed'; Type = 'firewallManager'; Expected = $true }
        @{ Result = 'Failed'; Type = 'powerSettingValue'; Expected = $true }
        @{ Result = 'SomethingNew'; Type = 'registry'; Expected = $true }
    ) {
        InModuleScope iGWindowsTuner -Parameters @{ R = $Result; T = $Type; E = $Expected } {
            param($R, $T, $E)
            Test-IgwtSnapshotEntryChanged -Entry ([pscustomobject]@{ result = $R; actions = @([pscustomobject]@{ type = $T }) }) | Should -Be $E
        }
    }
    It 'reads a list row, an empty snapshot, a failed entry without actions and an older row shape' {
        InModuleScope iGWindowsTuner {
            Test-IgwtSnapshotHasChange -Snapshot ([pscustomobject]@{ Entries = @() }) | Should -BeFalse
            Test-IgwtSnapshotHasChange -Snapshot ([pscustomobject]@{ Entries = @([pscustomobject]@{ result = 'Failed'; actions = @() }) }) | Should -BeFalse
            Test-IgwtSnapshotHasChange -Snapshot ([pscustomobject]@{ HasChange = $false; Entries = @([pscustomobject]@{ result = 'Applied' }) }) | Should -BeFalse
            Test-IgwtSnapshotHasChange -Snapshot ([pscustomobject]@{ Entries = @([pscustomobject]@{ result = 'Failed'; actions = @([pscustomobject]@{ type = 'defenderSetting' }) }, [pscustomobject]@{ result = 'Applied'; actions = @() }) }) | Should -BeTrue
            Test-IgwtSnapshotHasChange -Snapshot ([pscustomobject]@{ Path = 'p'; Operation = 'Apply' }) | Should -BeTrue
        }
    }
    It 'shows a snapshot in which nothing changed as such in Backups & Logs' {
        InModuleScope iGWindowsTuner {
            $r = New-IgwtGuiSnapshotRow -Snapshot ([pscustomobject]@{ Path = 'p'; File = 'f'; Created = '2026-11-05T23:35:01Z'; Operation = 'Defender'; Detail = 'X=Block'; Applied = @(); Failed = 1; HasChange = $false })
            $r.HasChange | Should -BeFalse; $r.FailedCol | Should -Be 'Nothing changed'; $r.Summary | Should -Match 'nothing to revert'
        }
    }
    It 'leaves it out of the Dashboard recent changes and the Backups summary, and offers no Undo for it' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
        InModuleScope iGWindowsTuner {
            $snap = { param($n, $changed, $failed) [pscustomobject]@{ Path = "C:\b\$n.json"; File = "$n.json"; Created = '2026-11-05T23:35:01Z'; Operation = 'Defender'; Detail = "$n=Block"; Applied = @(); Failed = $failed; HasChange = $changed } }
            $list = @((& $snap 'Failed1' $false 1), (& $snap 'Failed2' $false 1), (& $snap 'Good1' $true 0), (& $snap 'Mixed' $true 1))
            $script:Gui = @{ IsAdmin = $true; Persona = $null; Grids = @{}; C = @{
                    DashRecentList = (New-Object System.Windows.Controls.ItemsControl); DashRecentEmpty = (New-Object System.Windows.Controls.TextBlock)
                    DashShortcuts = (New-Object System.Windows.Controls.WrapPanel); DashShortcutText = (New-Object System.Windows.Controls.TextBlock)
                    BackupSummaryText = (New-Object System.Windows.Controls.TextBlock) } }
            try {
                Update-IgwtGuiDashRecent -Snapshots $list
                $rows = @($script:Gui.C.DashRecentList.ItemsSource)
                @($rows | ForEach-Object Title) | Should -Be @('Good1=Block', 'Mixed=Block (1 did not apply)')
                @($rows | ForEach-Object Path) | Should -Not -Contain 'C:\b\Failed1.json'
                Update-IgwtGuiDashRecent -Snapshots @($list[0], $list[1])
                @($script:Gui.C.DashRecentList.ItemsSource).Count | Should -Be 0
                $script:Gui.C.DashRecentEmpty.Visibility | Should -Be 'Visible'
                Mock Set-IgwtGuiGridRows { }
                Update-IgwtGuiSnapshots -Snapshots $list
                Should -Invoke Set-IgwtGuiGridRows -Times 1 -Exactly -ParameterFilter { @($Rows).Count -eq 4 }
                $script:Gui.C.BackupSummaryText.Text | Should -Match 'Good1=Block'
                $script:Gui.C.BackupSummaryText.Text | Should -Match '2 attempts changed nothing'
                Update-IgwtGuiSnapshots -Snapshots @($list[0])
                $script:Gui.C.BackupSummaryText.Text | Should -Match '^No changes yet\..*1 attempt changed nothing'
            } finally { $script:Gui = $null }
        }
    }
    It 'leaves it out of the Firewall recent changes' {
        (Get-Content (Join-Path $script:IgwtProjectRoot 'src\Manage\FirewallAudit.ps1') -Raw) | Should -Match "Operation -like 'Firewall\*' -and \(Test-IgwtSnapshotHasChange"
    }
}

# Runs on the real PC and only reads: Get-Command, never Set-MpPreference. It is the gate for the bug where
# the app called a Set-MpPreference that had no parameter for a catalog setting.
Describe 'Set-MpPreference contract on this PC (read-only)' {
    BeforeAll {
        $script:RealSet = Get-Command -Name 'Set-MpPreference' -ErrorAction SilentlyContinue | Select-Object -First 1
        $script:Writable = @($script:Catalog.settings | Where-Object { $_.edit -in 'set', 'parser' })
    }
    It 'maps every setting the editor writes to a real parameter, or reports it as unsupported without error' {
        $script:Writable.Count | Should -BeGreaterThan 50
        $unsupported = New-Object System.Collections.Generic.List[string]
        foreach ($s in $script:Writable) {
            $answer = InModuleScope iGWindowsTuner -Parameters @{ S = $s } { param($S) [pscustomobject]@{ Ok = (Test-IgwtMpPreferenceWritable -Name ([string]$S.mp)); Block = (Get-IgwtDefenderSettingWriteBlock -Definition $S) } }
            $real = ($null -ne $script:RealSet -and $script:RealSet.Parameters.ContainsKey([string]$s.mp))
            $answer.Ok | Should -Be $real -Because "$($s.mp) must follow what the command really has"
            if ($real) { $answer.Block | Should -BeNullOrEmpty -Because $s.mp } else { $unsupported.Add([string]$s.mp); [string]$answer.Block | Should -Not -BeNullOrEmpty -Because $s.mp }
        }
        if ($unsupported.Count) { Write-Information "Not writable on this PC: $($unsupported.ToArray() -join ', ')" -InformationAction Continue }
    }
    It 'offers only enum values the real parameter accepts' {
        if (-not $script:RealSet) { Set-ItResult -Skipped -Because 'this PC has no Set-MpPreference.'; return }
        foreach ($s in @($script:Writable | Where-Object { $_.type -eq 'enum' -and $script:RealSet.Parameters.ContainsKey([string]$_.mp) })) {
            $t = $script:RealSet.Parameters[[string]$s.mp].ParameterType
            if ($t.IsArray) { $t = $t.GetElementType() }
            $u = [Nullable]::GetUnderlyingType($t); if ($u) { $t = $u }
            if (-not $t.IsEnum) { continue }
            $vals = InModuleScope iGWindowsTuner -Parameters @{ S = $s } { param($S) @(Get-IgwtDefenderEnumValues -Definition $S) }
            foreach ($v in @($vals | Where-Object { -not $_.refused -and -not $_.noSet })) {
                [enum]::IsDefined($t, [System.Convert]::ChangeType($v.v, [enum]::GetUnderlyingType($t))) | Should -BeTrue -Because "$($s.mp) offers $($v.v) ($($v.label))"
            }
        }
    }
    It 'gives the GUI worker the same Set-MpPreference as a normal session' {
        $mods = @(InModuleScope iGWindowsTuner { Get-IgwtGuiWorkerInboxModule })
        @($mods | Where-Object { $_ -in 'ConfigDefender', 'Defender' }).Count | Should -BeLessOrEqual 1 -Because 'the Defender module loaded last wins, and Defender is a frozen copy'
        if (-not $script:RealSet) { Set-ItResult -Skipped -Because 'this PC has no Set-MpPreference.'; return }
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $iss.ImportPSModule([string[]]@($mods | Where-Object { $_ -in 'ConfigDefender', 'Defender' }))
        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
        $ps = [powershell]::Create()
        try {
            $rs.Open(); $ps.Runspace = $rs
            $null = $ps.AddScript('@((Get-Command -Name Set-MpPreference).Parameters.Keys)')
            $names = @($ps.Invoke() | ForEach-Object { [string]$_ })
        } finally { $ps.Dispose(); $rs.Dispose() }
        foreach ($s in $script:Writable) {
            if ($script:RealSet.Parameters.ContainsKey([string]$s.mp)) { $names | Should -Contain ([string]$s.mp) -Because 'the app must be able to write what this PC supports' }
        }
    }
    It 'has the catalog-independent helper read the real command and cache nothing wrong for a missing one' {
        $info = InModuleScope iGWindowsTuner { Get-IgwtMpWriteParameterInfo }
        $info.Available | Should -Be ($null -ne $script:RealSet)
        InModuleScope iGWindowsTuner { Test-IgwtMpPreferenceWritable -Name 'NoSuchPreferenceAtAll' } | Should -BeFalse
        InModuleScope iGWindowsTuner {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Set-MpPreference' }
            $none = Get-IgwtMpWriteParameterInfo
            $none.Available | Should -BeFalse; @($none.Names).Count | Should -Be 0
            Get-IgwtDefenderSettingWriteBlock -Definition (Get-IgwtDefenderSettingDefinition -Name 'CloudBlockLevel') | Should -Match 'commands are not available'
            Mock Get-Command { throw 'broken module' } -ParameterFilter { $Name -eq 'Set-MpPreference' }
            (Get-IgwtMpWriteParameterInfo).Available | Should -BeFalse
        }
    }
}

Describe 'Defender Group Policy settings' {
    BeforeAll {
        $script:DefAdmx = Join-Path $TestDrive 'DefenderAdmx'
        $null = New-Item -ItemType Directory -Path (Join-Path $script:DefAdmx 'en-US') -Force
        # A small ADMX written for these tests in the shape of WindowsDefender.admx (not a Microsoft file).
        [IO.File]::WriteAllText((Join-Path $script:DefAdmx 'WindowsDefender.admx'), @'
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0">
  <policyNamespaces><target prefix="windowsdefender" namespace="Microsoft.Policies.WindowsDefender" /></policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <categories><category name="AntiSpyware" displayName="$(string.Root)" /><category name="Scan" displayName="$(string.Scan)"><parentCategory ref="AntiSpyware" /></category></categories>
  <policies>
    <policy name="Scan_DisableHeuristics" class="Machine" displayName="$(string.Heur)" explainText="$(string.Help)" key="Software\Policies\Microsoft\Windows Defender\Scan" valueName="DisableHeuristics">
      <parentCategory ref="Scan" /><enabledValue><decimal value="0" /></enabledValue><disabledValue><decimal value="1" /></disabledValue>
    </policy>
    <policy name="Scan_ArchiveMaxDepth" class="Machine" displayName="$(string.Depth)" explainText="$(string.Help)" key="Software\Policies\Microsoft\Windows Defender\Scan" valueName="ArchiveMaxDepth">
      <parentCategory ref="Scan" /><elements><decimal id="ArchiveMaxDepth" valueName="ArchiveMaxDepth" /></elements>
    </policy>
    <policy name="Scan_ScanParameters" class="Machine" displayName="$(string.Params)" explainText="$(string.Help)" key="Software\Policies\Microsoft\Windows Defender\Scan" valueName="ScanParameters">
      <parentCategory ref="Scan" /><elements><enum id="ScanParameters" valueName="ScanParameters"><item displayName="$(string.Quick)"><value><decimal value="1" /></value></item></enum></elements>
    </policy>
    <policy name="Exclusions_Paths" class="Machine" displayName="$(string.Excl)" explainText="$(string.Help)" key="Software\Policies\Microsoft\Windows Defender\Exclusions" valueName="Exclusions_Paths">
      <parentCategory ref="AntiSpyware" /><enabledValue><decimal value="1" /></enabledValue><disabledValue><decimal value="0" /></disabledValue>
    </policy>
  </policies>
</policyDefinitions>
'@)
        [IO.File]::WriteAllText((Join-Path $script:DefAdmx 'en-US\WindowsDefender.adml'), @'
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources revision="1.0" schemaVersion="1.0">
  <displayName>t</displayName><description>t</description>
  <resources><stringTable>
    <string id="Root">Microsoft Defender Antivirus</string><string id="Scan">Scan</string><string id="Heur">Turn on heuristics</string>
    <string id="Depth">Specify the maximum depth to scan archive files</string><string id="Params">Specify the scan type to use for a scheduled scan</string>
    <string id="Quick">Quick scan</string><string id="Excl">Path exclusions</string><string id="Help">Test explain text.</string>
  </stringTable></resources>
</policyDefinitionResources>
'@)
    }
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; Authorities = @(); LocalGroupPolicy = $true } }
        $root = Join-Path $TestDrive ('GPO-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        InModuleScope iGWindowsTuner -Parameters @{ R = $root; A = $script:DefAdmx } { param($R, $A) $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtAdmxCache = $null }
    }
    AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

    It 'lists Defender policies with state, linked preference and refused states, leaving exclusions out' {
        $rows = @(InModuleScope iGWindowsTuner { Get-IgwtDefenderPolicySettings })
        @($rows | ForEach-Object Id) | Should -Not -Contain 'WindowsDefender:Exclusions_Paths'
        $heur = $rows | Where-Object Id -EQ 'WindowsDefender:Scan_DisableHeuristics'
        $heur.State | Should -Be 'NotConfigured'; $heur.Simple | Should -BeTrue
        @($heur.Refused) -join ' ' | Should -Match '^Disabled: '
        ($rows | Where-Object Id -EQ 'WindowsDefender:Scan_ArchiveMaxDepth').Simple | Should -BeFalse
        ($rows | Where-Object Id -EQ 'WindowsDefender:Scan_ScanParameters').Preference | Should -Be 'ScanParameters'
        @(InModuleScope iGWindowsTuner { Get-IgwtDefenderPolicySettings -Search 'heuristics' }).Count | Should -Be 1
    }
    It 'the denylist refuses the hidden Defender switches that turn protection off' {
        InModuleScope iGWindowsTuner {
            $t = { param($k, $n, $v) Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = $k; ValueName = $n; Type = 'DWord'; Value = $v }) }
            & $t 'Software\Policies\Microsoft\Windows Defender\Scan' 'DisableHeuristics' 1 | Should -Match 'scanning component'
            & $t 'Software\Policies\Microsoft\Windows Defender\Scan' 'DisableHeuristics' 0 | Should -BeNullOrEmpty
            & $t 'Software\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' 2 | Should -Match 'Block at First Sight'
            & $t 'Software\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' 1 | Should -BeNullOrEmpty
            & $t 'Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction' '4' '6' | Should -Match 'Allows detected threats'
            & $t 'Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction' '4' '2' | Should -BeNullOrEmpty
            & $t 'Software\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection' 'BruteForceProtectionConfiguredState' 4 | Should -Match 'brute-force'
            & $t 'Software\Policies\Microsoft\Windows Defender\NIS' 'DisableProtocolRecognition' 1 | Should -Match 'Network Inspection'
            & $t 'Software\Policies\Microsoft\Windows Defender\Real-Time Protection' 'RealtimeScanDirection' 1 | Should -Match 'one direction'
            & $t 'Software\Policies\Microsoft\Windows Defender' 'PUAProtection' 0 | Should -Match 'potentially unwanted'
        }
    }
}
