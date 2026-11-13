# Security Settings Manager, B4 (DECISIONS SM9, SM11, SM12, SM22-SM24, SM32): current state, origin,
# read-only reasons and filters. Every system reader is mocked; Registry.pol lives in TestDrive.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Admx = Join-Path $PSScriptRoot 'fixtures\secsettings\admx'
    $script:GpoRoot = Join-Path $TestDrive 'GroupPolicy'
    $script:DgDir = Join-Path $PSScriptRoot 'fixtures\secsettings'
    $script:DgFixture = Join-Path $script:DgDir 'deviceguard-none.json'
    InModuleScope iGWindowsTuner -Parameters @{ A = $script:Admx; R = $script:GpoRoot } { param($A, $R) $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtAdmxCache = $null; $script:IgwtSecSettingsData = $null }
    function Initialize-StateMocks {
        param([string]$Family = 'Professional', [bool]$Admin = $false, [bool]$Domain = $false, [bool]$Mdm = $false, $Tamper = $false, [string[]]$MdmNames = @(), [string[]]$PolicyNames = @())
        $script:MockFamily = $Family; $script:MockAdmin = $Admin; $script:MockDomain = $Domain; $script:MockMdm = $Mdm; $script:MockTamper = $Tamper
        $script:MockMdmNames = $MdmNames; $script:MockPolicyNames = $PolicyNames
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ EditionFamily = $script:MockFamily; DomainJoined = $script:MockDomain; DomainName = 'contoso.test'; MdmEnrolled = $script:MockMdm; LocalGroupPolicy = $true } }
        Mock -ModuleName iGWindowsTuner Test-IgwtIsAdmin { $script:MockAdmin }
        Mock -ModuleName iGWindowsTuner Get-IgwtInteractiveUserSid { $null }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecSettingRegistryNames { $s = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($n in $script:MockPolicyNames) { $null = $s.Add($n) }; , $s }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecSettingMdmIndex { $s = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($n in $script:MockMdmNames) { $null = $s.Add($n) }; , $s }
        Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { if ($null -eq $script:MockTamper) { throw 'not available' }; [pscustomobject]@{ IsTamperProtected = $script:MockTamper } }
        Mock -ModuleName iGWindowsTuner Get-IgwtDomainPolicyResult { @() }
        Mock -ModuleName iGWindowsTuner Get-IgwtDefenderSettings { @() }
        Mock -ModuleName iGWindowsTuner Get-IgwtMpPreferenceSafe { [pscustomobject]@{} }
        Mock -ModuleName iGWindowsTuner Get-IgwtAsrStatus { [pscustomobject]@{ Rules = @([pscustomobject]@{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Name = 'Block abuse of exploited vulnerable signed drivers'; Mode = 'Block'; Source = 'Local'; ManagedByPolicy = $false; SupportsWarn = $true }) } }
        Mock -ModuleName iGWindowsTuner Get-IgwtDefenderExclusionAudit { [pscustomobject]@{ Readable = $true; Exclusions = @([pscustomobject]@{ Kind = 'Path'; Value = 'C:\Games'; Source = 'Local preference'; Removable = $true }, [pscustomobject]@{ Kind = 'AsrOnly'; Value = 'C:\Tools'; Source = 'ASR Center'; Removable = $false }) } }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtSecedit { throw 'secedit must not run' }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtAuditpol { throw 'auditpol must not run' }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecurityPolicy { @([pscustomobject]@{ Section = 'Registry Values'; Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'; Value = '4,1'; Name = 'Do not store LAN Manager hash' }, [pscustomobject]@{ Section = 'Privilege Rights'; Key = 'SeDebugPrivilege'; Value = '*S-1-5-32-544'; Name = 'Debug programs' }) }
        Mock -ModuleName iGWindowsTuner Get-IgwtAuditPolicy { [pscustomobject]@{ Subcategories = @([pscustomobject]@{ Subcategory = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Setting = 'Success and Failure'; Option = $false }) } }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecDeviceGuardRegistry { @{} }
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' } { Get-Content -LiteralPath $script:DgFixture -Raw | ConvertFrom-Json }
        Mock -ModuleName iGWindowsTuner Read-IgwtSceRegVlInf { [pscustomobject]@{ Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'; RegType = 4; Name = 'NoLMHash'; DisplayType = 0; Choices = @(); Unit = '' } }
    }
    function Write-MachinePol([string]$Policy, [string]$State, [hashtable]$Values = @{}) {
        InModuleScope iGWindowsTuner -Parameters @{ N = $Policy; S = $State; V = $Values } {
            param($N, $S, $V)
            $p = @((Get-IgwtAdmxCatalog -NoCache).Policies | Where-Object { $_.Name -eq $N })[0]
            $e = @(Update-IgwtPolEntries -Entries @() -Ops @(Get-IgwtPolicyRegistryOps -Policy $p -State $S -Values $V))
            Write-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine) -Entries $e -Confirm:$false
        }
    }
    function Get-Rows { param([hashtable]$Arguments = @{}) $a = $Arguments; InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Get-IgwtSecSettings @A -NoCache } }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.AdmxFolders = $null; $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtAdmxCache = $null } }

Describe 'ADMX rows: state and origin (SM9-SM11)' {
    BeforeEach { Remove-Item -Path $script:GpoRoot -Recurse -Force -ErrorAction SilentlyContinue }
    It 'decodes a local policy, keeps it writable and reports Not configured otherwise' {
        Initialize-StateMocks
        Write-MachinePol 'AllKinds' 'Enabled' @{ DecEl = 30; EnumEl = 0; BoolEl = $true }
        $r = Get-Rows
        $all = $r.Rows | Where-Object Id -EQ 'admx:SecFixture:AllKinds:Machine'
        $all.Origin | Should -Be 'LocalPolicy'; $all.State | Should -Be 'Enabled'; $all.ReadOnly | Should -BeFalse
        $all.Current.DecEl | Should -Be 30; $all.Configured | Should -BeTrue
        $log = $r.Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine'
        $log.Origin | Should -Be 'NotConfigured'; $log.Configured | Should -BeFalse
        @($r.Rows | Where-Object Id -Like '*NotInScope*') | Should -BeNullOrEmpty
    }
    It 'makes overlapping policies read-only' {
        Initialize-StateMocks
        $r = Get-Rows
        ($r.Rows | Where-Object Id -EQ 'admx:SecFixture:OverlapA:Machine').ReadOnlyReason | Should -Match 'Shares registry values'
    }
    It 'reads a failed domain result as Unknown and read-only' {
        Initialize-StateMocks -Domain $true
        $r = Get-Rows
        $r.Status.DomainPolicyRead | Should -Be 'Failed'
        $row = $r.Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine'
        $row.Origin | Should -Be 'Unknown'; $row.ReadOnly | Should -BeTrue
    }
    It 'reads a domain value by key and value name' {
        Initialize-StateMocks -Domain $true
        Mock -ModuleName iGWindowsTuner Get-IgwtDomainPolicyResult { @([pscustomobject]@{ Scope = 'Machine'; Key = 'Software\Policies\Contoso\Log'; ValueName = 'EnableAuditLogging'; Value = '1'; Gpo = 'Contoso baseline' }) }
        $r = Get-Rows
        $r.Status.DomainPolicyRead | Should -Be 'Ok'
        ($r.Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine').Origin | Should -Be 'DomainGpo'
    }
    It 'reports MDM and registry-only values as read-only' {
        Initialize-StateMocks -MdmNames @('enableauditlogging') -PolicyNames @('software\policies\contoso\log|enableauditlogging')
        $r = Get-Rows
        ($r.Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine').Origin | Should -Be 'Mdm'
        Initialize-StateMocks -PolicyNames @('software\policies\contoso\log|enableauditlogging')
        $c = (Get-Rows).Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine'
        $c.Origin | Should -Be 'RegistryOnly'; $c.ReadOnlyReason | Should -Match 'Adopt'
    }
    It 'makes every ADMX row read-only on Home and on an unknown edition' {
        Initialize-StateMocks -Family 'Home'
        ($(Get-Rows).Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine').ReadOnlyReason | Should -Match 'does not have'
        Initialize-StateMocks -Family ''
        ($(Get-Rows).Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine').ReadOnlyReason | Should -Match 'not recognised'
    }
    It 'makes every ADMX, Defender and ASR row read-only on a managed PC' {
        Initialize-StateMocks -Mdm $true
        $r = Get-Rows
        ($r.Rows | Where-Object Id -EQ 'admx:SecFixture:LoggingSwitch:Machine').ReadOnly | Should -BeTrue
        ($r.Rows | Where-Object SourceKind -EQ 'asr').ReadOnly | Should -BeTrue
    }
}

Describe 'Defender, ASR and exclusion rows (SM12, SM24)' {
    It 'shows ASR modes with Off and Not configured refused, and exclusions as remove-only lists' {
        Initialize-StateMocks
        $r = Get-Rows
        $asr = $r.Rows | Where-Object SourceKind -EQ 'asr'
        $asr.Origin | Should -Be 'DefenderLocal'
        @($asr.ValueSpec.Elements[0].Choices | Where-Object { $_.Refused } | ForEach-Object Value) | Should -Be @('Off', 'NotConfigured')
        $path = $r.Rows | Where-Object Id -EQ 'exclusion:Path'
        @($path.Current) | Should -Be @('C:\Games'); $path.ReadOnly | Should -BeFalse; $path.ValueSpec.Elements[0].RemoveOnly | Should -BeTrue
        ($r.Rows | Where-Object Id -EQ 'exclusion:AsrOnly').ReadOnly | Should -BeTrue
        ($r.Rows | Where-Object Id -EQ 'exclusion:Process').Configured | Should -BeFalse
    }
    It 'locks Tamper-protected rows when Tamper Protection is on or unknown' {
        Mock -ModuleName iGWindowsTuner Get-IgwtDefenderSettings { @([pscustomobject]@{ Property = 'DisableRealtimeMonitoring'; Name = 'Real-time protection'; CategoryName = 'Real-time'; Source = 'Local'; Supported = $true; Edit = 'set'; Current = $false; Display = 'On'; Policy = 'WindowsDefender:DisableRealtimeMonitoring'; Hint = '' }) }
        foreach ($t in @($true, $null)) {
            Initialize-StateMocks -Tamper $t
            Mock -ModuleName iGWindowsTuner Get-IgwtDefenderSettings { @([pscustomobject]@{ Property = 'DisableRealtimeMonitoring'; Name = 'Real-time protection'; CategoryName = 'Real-time'; Source = 'Local'; Supported = $true; Edit = 'set'; Current = $false; Display = 'On'; Policy = 'WindowsDefender:DisableRealtimeMonitoring'; Hint = '' }) }
            $row = (Get-Rows).Rows | Where-Object Id -EQ 'defender:DisableRealtimeMonitoring'
            $row.Origin | Should -Be 'TamperProtection'; $row.ReadOnly | Should -BeTrue
        }
        Initialize-StateMocks -Tamper $false
        Mock -ModuleName iGWindowsTuner Get-IgwtDefenderSettings { @([pscustomobject]@{ Property = 'DisableRealtimeMonitoring'; Name = 'Real-time protection'; CategoryName = 'Real-time'; Source = 'Local'; Supported = $true; Edit = 'set'; Current = $false; Display = 'On'; Policy = 'WindowsDefender:DisableRealtimeMonitoring'; Hint = '' }) }
        ((Get-Rows).Rows | Where-Object Id -EQ 'defender:DisableRealtimeMonitoring').ReadOnly | Should -BeFalse
    }
}

Describe 'Local security policy and audit (SM22)' {
    It 'never runs secedit or auditpol when not elevated' {
        Initialize-StateMocks -Admin $false
        $r = Get-Rows
        ($r.Rows | Where-Object Id -EQ 'secpolicy:unavailable').ReadOnlyReason | Should -Match 'administrator'
        Should -Invoke -ModuleName iGWindowsTuner Get-IgwtSecurityPolicy -Times 0
        Should -Invoke -ModuleName iGWindowsTuner Get-IgwtAuditPolicy -Times 0
    }
    It 'shows security options with their spec and audit rows when elevated, never user rights' {
        Initialize-StateMocks -Admin $true
        $r = Get-Rows
        $nolm = $r.Rows | Where-Object Id -EQ 'secpol:Registry Values:MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
        $nolm.ValueSpec.Elements[0].Kind | Should -Be 'bool'; $nolm.Current | Should -Be '1'
        @($r.Rows | Where-Object { $_.Id -like 'secpol:Privilege Rights*' }) | Should -BeNullOrEmpty
        ($r.Rows | Where-Object SourceKind -EQ 'audit').Current | Should -Be 'SuccessAndFailure'
    }
}

Describe 'Filters and status' {
    It 'filters by search, source kind and Configured only, and reports the status' {
        Initialize-StateMocks
        Write-MachinePol 'AllKinds' 'Disabled'
        $r = Get-Rows -Arguments @{ ConfiguredOnly = $true; SourceKind = @('admx') }
        @($r.Rows | ForEach-Object Id) | Should -Be @('admx:SecFixture:AllKinds:Machine')
        @((Get-Rows -Arguments @{ Search = 'audit logging' }).Rows | ForEach-Object Id) | Should -Contain 'admx:SecFixture:LoggingSwitch:Machine'
        $r.Status.EditionFamily | Should -Be 'Professional'; $r.Status.Tamper | Should -Be 'Off'; $r.Status.Elevated | Should -BeFalse
    }
}

Describe 'Device Guard state (SM31) and high-risk prerequisites (SM17)' {
    BeforeEach { Initialize-StateMocks }
    It 'shows configured versus running, and Unknown (never Off) when Windows does not answer' {
        $script:DgFixture = Join-Path $script:DgDir 'deviceguard-running.json'
        $rows = @(InModuleScope iGWindowsTuner { Get-IgwtSecDeviceGuardRows })
        ($rows | Where-Object Id -EQ 'deviceguard:2').CurrentText | Should -Be 'Running'
        ($rows | Where-Object Id -EQ 'deviceguard:vbs').Current.Running | Should -BeTrue
        ($rows | Where-Object Id -EQ 'deviceguard:1').CurrentText | Should -Be 'Off'
        $script:DgFixture = Join-Path $script:DgDir 'deviceguard-configured-not-running.json'
        $rows = @(InModuleScope iGWindowsTuner { Get-IgwtSecDeviceGuardRows })
        ($rows | Where-Object Id -EQ 'deviceguard:1').CurrentText | Should -Match '^Configured, not running'
        ($rows | Where-Object Id -EQ 'deviceguard:1').Configured | Should -BeTrue
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' } { throw 'Invalid namespace' }
        $rows = @(InModuleScope iGWindowsTuner { Get-IgwtSecDeviceGuardRows })
        @($rows | ForEach-Object State | Select-Object -Unique) | Should -Be @('Unknown')
        $script:DgFixture = Join-Path $script:DgDir 'deviceguard-none.json'
    }
    It 'adds the UEFI-lock warning when a value is already locked' {
        $script:DgFixture = Join-Path $script:DgDir 'deviceguard-running.json'
        Mock -ModuleName iGWindowsTuner Get-IgwtSecDeviceGuardRegistry { @{ 'system\currentcontrolset\control\lsa|lsacfgflags' = 1 } }
        (@(InModuleScope iGWindowsTuner { Get-IgwtSecDeviceGuardRows }) | Where-Object Id -EQ 'deviceguard:2').CurrentText | Should -Match 'cannot be removed by software'
        $script:DgFixture = Join-Path $script:DgDir 'deviceguard-none.json'
    }
    It 'fails VBS without hypervisor support and never passes without evidence' {
        Mock -ModuleName iGWindowsTuner Get-IgwtDeviceGuardInfo { [pscustomobject]@{ Available = $true; HypervisorAvailable = $false; DmaProtectionAvailable = $false } }
        Mock -ModuleName iGWindowsTuner Get-IgwtSecureBootInfo { [pscustomobject]@{ Enabled = $null } }
        Mock -ModuleName iGWindowsTuner Get-IgwtTpmInfo { throw 'no tpm read' }
        Mock -ModuleName iGWindowsTuner Get-IgwtBitLockerStatus { [pscustomobject]@{ On = $false; Text = 'Unknown' } }
        $c = @(InModuleScope iGWindowsTuner { Get-IgwtSecSettingPrerequisites -Id 'admx:DeviceGuard:VirtualizationBasedSecurity:Machine' -EditionFamily 'Professional' })
        ($c | Where-Object Check -EQ 'Virtualization support').Result | Should -Be 'Fail'
        ($c | Where-Object Check -EQ 'Secure Boot').Result | Should -Be 'NotChecked'
        ($c | Where-Object Check -EQ 'TPM').Result | Should -Be 'NotChecked'
        ($c | Where-Object Check -EQ 'Driver compatibility').Result | Should -Be 'NotChecked'
        ($c | Where-Object Check -EQ 'BitLocker recovery key').Result | Should -Be 'NotChecked'
        ($c | Where-Object Check -EQ 'If Windows does not start').Text | Should -Match 'learn.microsoft.com'
    }
    It 'checks the BitLocker recovery password by protector type only' {
        Mock -ModuleName iGWindowsTuner Get-IgwtBitLockerStatus { [pscustomobject]@{ On = $true; Text = 'Protection On'; ProtectorTypes = @('Tpm', 'RecoveryPassword') } }
        (@(InModuleScope iGWindowsTuner { Get-IgwtSecSettingPrerequisites -Id 'admx:VolumeEncryption:OSRecoveryUsage:Machine' }) | Where-Object Check -EQ 'BitLocker recovery key').Result | Should -Be 'Pass'
        Mock -ModuleName iGWindowsTuner Get-IgwtBitLockerStatus { [pscustomobject]@{ On = $true; Text = 'Protection On'; ProtectorTypes = @('Tpm') } }
        (@(InModuleScope iGWindowsTuner { Get-IgwtSecSettingPrerequisites -Id 'admx:VolumeEncryption:OSRecoveryUsage:Machine' }) | Where-Object Check -EQ 'BitLocker recovery key').Result | Should -Be 'Fail'
        Mock -ModuleName iGWindowsTuner Get-IgwtBitLockerStatus { [pscustomobject]@{ On = $true; Text = 'On (non-elevated reading)' } }
        (@(InModuleScope iGWindowsTuner { Get-IgwtSecSettingPrerequisites -Id 'admx:VolumeEncryption:OSRecoveryUsage:Machine' }) | Where-Object Check -EQ 'BitLocker recovery key').Result | Should -Be 'NotChecked'
        Mock -ModuleName iGWindowsTuner Get-IgwtBitLockerStatus { [pscustomobject]@{ On = $false; Text = 'Protection Off' } }
        (@(InModuleScope iGWindowsTuner { Get-IgwtSecSettingPrerequisites -Id 'admx:VolumeEncryption:OSRecoveryUsage:Machine' }) | Where-Object Check -EQ 'BitLocker recovery key').Result | Should -Be 'Pass'
        @(InModuleScope iGWindowsTuner { Get-IgwtSecSettingPrerequisites -Id 'admx:SecFixture:LoggingSwitch:Machine' }) | Should -BeNullOrEmpty
    }
}