# Security Settings Manager, B6 (DECISIONS SM17, SM26, SM29, SM30 part 2): the read-only change plan
# and its preview. Rows come from Get-IgwtSecSettings over synthetic fixtures and mocked readers.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Admx = Join-Path $PSScriptRoot 'fixtures\secsettings\admx'
    $script:GpoRoot = Join-Path $TestDrive 'GroupPolicy'
    $script:DgFixture = Join-Path $PSScriptRoot 'fixtures\secsettings\deviceguard-none.json'
    InModuleScope iGWindowsTuner -Parameters @{ A = $script:Admx; R = $script:GpoRoot } { param($A, $R) $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtAdmxCache = $null; $script:IgwtSecSettingsData = $null }
    function Initialize-PlanMocks {
        param([bool]$Admin = $true, [bool]$Mdm = $false)
        $script:MockAdmin = $Admin; $script:MockMdm = $Mdm
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ EditionFamily = 'Professional'; DomainJoined = $false; MdmEnrolled = $script:MockMdm; LocalGroupPolicy = $true } }
        Mock -ModuleName iGWindowsTuner Test-IgwtIsAdmin { $script:MockAdmin }
        Mock -ModuleName iGWindowsTuner Get-IgwtInteractiveUserSid { $null }
        Mock -ModuleName iGWindowsTuner Get-IgwtCurrentIdentity { [pscustomobject]@{ Name = 'PC\Admin'; Sid = 'S-1-5-21-1-2-3-500'; GroupSids = @('S-1-5-32-544'); IsRemote = $false } }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecSettingRegistryNames { , (New-Object 'System.Collections.Generic.HashSet[string]') }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecSettingMdmIndex { , (New-Object 'System.Collections.Generic.HashSet[string]') }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecDeviceGuardRegistry { @{} }
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' } { Get-Content -LiteralPath $script:DgFixture -Raw | ConvertFrom-Json }
        Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { [pscustomobject]@{ IsTamperProtected = $false } }
        Mock -ModuleName iGWindowsTuner Get-IgwtDefenderSettings { @() }
        Mock -ModuleName iGWindowsTuner Get-IgwtMpPreferenceSafe { [pscustomobject]@{} }
        Mock -ModuleName iGWindowsTuner Get-IgwtAsrStatus { [pscustomobject]@{ Rules = @([pscustomobject]@{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Name = 'Block abuse of exploited vulnerable signed drivers'; Mode = 'Audit'; Source = 'Local'; ManagedByPolicy = $false; SupportsWarn = $true }) } }
        Mock -ModuleName iGWindowsTuner Get-IgwtDefenderExclusionAudit { [pscustomobject]@{ Readable = $true; Exclusions = @([pscustomobject]@{ Kind = 'Path'; Value = 'C:\Games'; Source = 'Local preference'; Removable = $true }, [pscustomobject]@{ Kind = 'Path'; Value = 'C:\Old'; Source = 'Local preference'; Removable = $true }) } }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecurityPolicy { @([pscustomobject]@{ Section = 'Registry Values'; Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'; Value = '4,1'; Name = 'Do not store LAN Manager hash' }, [pscustomobject]@{ Section = 'Registry Values'; Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail'; Value = '4,0'; Name = 'Shut down if unable to log audits' }, [pscustomobject]@{ Section = 'Registry Values'; Key = 'MACHINE\Software\Contoso\NewOption'; Value = ''; Name = 'Contoso option' }) }
        Mock -ModuleName iGWindowsTuner Read-IgwtSceRegVlInf { foreach ($n in 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash', 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail', 'MACHINE\Software\Contoso\NewOption') { [pscustomobject]@{ Key = $n; RegType = 4; Name = $n; DisplayType = 0; Choices = @(); Unit = '' } } }
        Mock -ModuleName iGWindowsTuner Get-IgwtAuditPolicy { [pscustomobject]@{ Subcategories = @([pscustomobject]@{ Subcategory = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Setting = 'Success and Failure'; Option = $false }) } }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecSettingPrerequisites { @([pscustomobject]@{ Check = 'Virtualization support'; Result = 'Pass'; Text = 'ok' }) }
    }
    function Write-MachinePol([string]$Policy, [string]$State, [hashtable]$Values = @{}) {
        InModuleScope iGWindowsTuner -Parameters @{ N = $Policy; S = $State; V = $Values } {
            param($N, $S, $V)
            $p = @((Get-IgwtAdmxCatalog -NoCache).Policies | Where-Object { $_.Name -eq $N })[0]
            Write-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine) -Entries @(Update-IgwtPolEntries -Entries @() -Ops @(Get-IgwtPolicyRegistryOps -Policy $p -State $S -Values $V)) -Confirm:$false
        }
    }
    function Get-Plan([object[]]$Changes, [hashtable]$Options = @{}, [scriptblock]$EditRows) {
        InModuleScope iGWindowsTuner -Parameters @{ C = $Changes; O = $Options; E = $EditRows } {
            param($C, $O, $E)
            $rows = @((Get-IgwtSecSettings -NoCache).Rows)
            if ($E) { $rows = @($rows | ForEach-Object { & $E $_ }) }
            Get-IgwtSecSettingChangePlan -Changes $C -Rows $rows @O
        }
    }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.AdmxFolders = $null; $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtAdmxCache = $null } }

Describe 'ADMX changes through local policy (SM29)' {
    BeforeEach { Remove-Item -Path $script:GpoRoot -Recurse -Force -ErrorAction SilentlyContinue; Initialize-PlanMocks }
    It 'plans a change with its Registry.pol operations, and an unchanged value as already set' {
        $p = Get-Plan @(@{ Id = 'admx:SecFixture:LoggingSwitch:Machine'; Value = @{ State = 'Enabled' } })
        $r = $p.Rows[0]
        $r.Status | Should -Be 'Change'; $r.Writer | Should -Be 'localPolicy'
        @($r.Ops | ForEach-Object { "$($_.Op) $($_.ValueName)=$($_.Value)" }) | Should -Be @('Set EnableAuditLogging=1')
        $p.CanApply | Should -BeTrue
        Write-MachinePol 'LoggingSwitch' 'Enabled'
        (Get-Plan @(@{ Id = 'admx:SecFixture:LoggingSwitch:Machine'; Value = @{ State = 'Enabled' } })).Rows[0].Status | Should -Be 'InPlace'
    }
    It 'passes enum values as their index to the encoder' {
        $r = (Get-Plan @(@{ Id = 'admx:SecFixture:AllKinds:Machine'; Value = @{ State = 'Enabled'; Values = @{ EnumEl = 'High'; DecEl = '20' } } })).Rows[0]
        $r.Status | Should -Be 'Change'
        ($r.Ops | Where-Object ValueName -EQ 'EnumValue').Value | Should -Be 20
        $r.Input.Values.EnumEl | Should -Be 1
    }
    It 'refuses turning VBS off while local policy has it on, and a UEFI-lock choice' {
        Write-MachinePol 'VbsShaped' 'Enabled' @{ HvciDrop = 2; FakeDrop = 0 }
        $r = (Get-Plan @(@{ Id = 'admx:DgFixture:VbsShaped:Machine'; Value = @{ State = 'Disabled' } })).Rows[0]
        $r.Status | Should -Be 'Refused'; $r.Reason | Should -Match 'protection'
        $r = (Get-Plan @(@{ Id = 'admx:DgFixture:VbsShaped:Machine'; Value = @{ State = 'Enabled'; Values = @{ HvciDrop = 'Enabled with UEFI lock'; FakeDrop = 'Disabled' } } })).Rows[0]
        $r.Status | Should -Be 'Refused'; $r.Reason | Should -Match 'UEFI lock'
    }
    It 'asks for confirmation of a high-risk change, and refuses it when a prerequisite fails' {
        $high = { param($r) if ($r.Id -eq 'admx:DgFixture:VbsShaped:Machine') { $r.Risk = 'high'; $r.Restart = 'reboot' }; $r }
        $chg = @(@{ Id = 'admx:DgFixture:VbsShaped:Machine'; Value = @{ State = 'Enabled'; Values = @{ HvciDrop = 'Enabled without lock'; FakeDrop = 'Disabled' } } })
        $p = Get-Plan $chg -EditRows $high
        $p.Rows[0].Status | Should -Be 'NeedsConfirmation'; $p.CanApply | Should -BeFalse
        $p = Get-Plan $chg -Options @{ AcknowledgeRisk = $true } -EditRows $high
        $p.Rows[0].Status | Should -Be 'Change'; $p.Restart | Should -Be 'reboot'
        (@(InModuleScope iGWindowsTuner -Parameters @{ P = $p } { param($P) Format-IgwtSecSettingPlan -Plan $P }) -join "`n") | Should -Match 'Restart Windows after applying'
        Mock -ModuleName iGWindowsTuner Get-IgwtSecSettingPrerequisites { @([pscustomobject]@{ Check = 'Virtualization support'; Result = 'Fail'; Text = 'no hypervisor' }) }
        (Get-Plan $chg -Options @{ AcknowledgeRisk = $true } -EditRows $high).Rows[0].Status | Should -Be 'Refused'
    }
}

Describe 'Defender, ASR, exclusions, secpol and audit (SM22, SM24, SM26)' {
    BeforeEach { Initialize-PlanMocks }
    It 'plans an ASR mode change and refuses turning a rule off' {
        $r = (Get-Plan @(@{ Id = 'asr:56a863a9-875e-4185-98a7-b882c64b5ce5'; Value = 'Block' })).Rows[0]
        $r.Status | Should -Be 'Change'; $r.Input.Mode | Should -Be 'Block'
        (Get-Plan @(@{ Id = 'asr:56a863a9-875e-4185-98a7-b882c64b5ce5'; Value = 'Off' })).Rows[0].Status | Should -Be 'Refused'
    }
    It 'makes an exclusion removal one-way and never mixes it with another change' {
        $r = (Get-Plan @(@{ Id = 'exclusion:Path'; Value = @('C:\Games') })).Rows[0]
        $r.Status | Should -Be 'OneWay'; @($r.Removed) | Should -Be @('C:\Old')
        (Get-Plan @(@{ Id = 'exclusion:Path'; Value = @('C:\Games', 'C:\New') })).Rows[0].Status | Should -Be 'Refused'
        $p = Get-Plan @(@{ Id = 'exclusion:Path'; Value = @('C:\Games') }, @{ Id = 'asr:56a863a9-875e-4185-98a7-b882c64b5ce5'; Value = 'Block' })
        $p.Mixed | Should -BeTrue; @($p.Rows | ForEach-Object Status | Select-Object -Unique) | Should -Be @('Refused')
    }
    It 'builds one secpol change object, refuses lockout and weakening values, and marks an undefined option one-way' {
        $r = (Get-Plan @(@{ Id = 'secpol:Registry Values:MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'; Value = 'off' })).Rows[0]
        $r.Status | Should -Be 'Refused'; $r.Reason | Should -Match 'LAN Manager hash'
        $r = (Get-Plan @(@{ Id = 'secpol:Registry Values:MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail'; Value = 'on' })).Rows[0]
        $r.Status | Should -Be 'Refused'; $r.Reason | Should -Match 'Shut down when the audit log is full'
        $r = (Get-Plan @(@{ Id = 'secpol:Registry Values:MACHINE\Software\Contoso\NewOption'; Value = 'on' })).Rows[0]
        $r.Status | Should -Be 'OneWay'; $r.Input.Value | Should -Be '4,1'; $r.Input.Section | Should -Be 'Registry Values'
    }
    It 'refuses removing audit success or failure' {
        (Get-Plan @(@{ Id = 'audit:{0CCE9215-69AE-11D9-BED3-505054503030}'; Value = 'Success' })).Rows[0].Status | Should -Be 'Refused'
        (Get-Plan @(@{ Id = 'audit:{0CCE9215-69AE-11D9-BED3-505054503030}'; Value = 'SuccessAndFailure' })).Rows[0].Status | Should -Be 'InPlace'
    }
    It 'refuses an unknown id and a read-only row' {
        (Get-Plan @(@{ Id = 'admx:Nope:Nope:Machine'; Value = @{ State = 'Enabled' } })).Rows[0].Reason | Should -Match 'does not know'
        (Get-Plan @(@{ Id = 'admx:SecFixture:OverlapA:Machine'; Value = @{ State = 'Enabled' } })).Rows[0].Reason | Should -Match 'Shares registry values'
    }
}

Describe 'Managed PCs (SM11, SM29)' {
    It 'asks for the managed confirmation, and plans the change with it' {
        Initialize-PlanMocks -Mdm $true
        $chg = @(@{ Id = 'asr:56a863a9-875e-4185-98a7-b882c64b5ce5'; Value = 'Block' })
        (Get-Plan $chg).Rows[0].Status | Should -Be 'NeedsManagedAck'
        (Get-Plan $chg -Options @{ AcknowledgeManaged = $true }).Rows[0].Status | Should -Be 'Change'
    }
}
