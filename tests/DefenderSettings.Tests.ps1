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
