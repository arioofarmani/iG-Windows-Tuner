# 3.0 platform: schema v3 fields and migration, management detection (domain, Entra ID, MDM,
# Defender for Endpoint), report-only policy items on managed PCs, edition gating and personas.
# Runs in TestRegistry with mocks.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Schema v3' {
    It 'ships every tweak file as schema v3 with valid v3 fields' {
        foreach ($f in Get-ChildItem (Join-Path $script:IgwtProjectRoot 'data\tweaks') -Filter *.json) {
            (Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json).schemaVersion | Should -Be 3 -Because $f.Name
        }
        foreach ($t in @(Get-IgwtCatalog)) {
            $t.scope | Should -BeIn @('Performance', 'Network', 'Privacy', 'Updates', 'Defender', 'AttackSurface', 'AuditLogging', 'System') -Because $t.id
            @($t.managedBy) | Should -Contain 'local' -Because $t.id
        }
    }
    It 'marks every item that writes a Group Policy location with its gpoPath' {
        $t = Get-IgwtTweak -Id 'privacy.activity-history-off'
        $t.gpoPath | Should -Be 'machine'
        @($t.managedBy) | Should -Be @('local', 'gpo', 'mdm')
        (Get-IgwtTweak -Id 'privacy.bing-search-off').gpoPath | Should -Be ''
        (Get-IgwtTweak -Id 'privacy.office-privacy-policies').gpoPath | Should -Be 'user'
    }
    It 'migrates a v2 entry: scope, gpoPath, managedBy and editions moved out of appliesTo' {
        $v2 = [pscustomobject]@{ id = 'privacy.test'; name = 'T'; category = 'Background & Privacy'; group = 'Windows Update'; level = 'Standard'; hint = 'h'; description = 'd'
            evidence = [pscustomobject]@{ tier = 'A'; sources = @('https://learn.microsoft.com/') }; impact = [pscustomobject]@{ performance = 'none'; latency = 'none'; security = '0' }
            risk = 'low'; antiCheat = 'safe'; reversible = 'full'; sideEffects = ''; requires = 'none'; appliesTo = [pscustomobject]@{ minBuild = 26100; editions = @('Enterprise') }
            hardware = [pscustomobject]@{ tags = @(); excludeTags = @() }; source = 'igwt'
            actions = @([pscustomobject]@{ type = 'registry'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; name = 'X'; valueType = 'DWord'; on = 1; default = '<absent>' }) }
        $v3 = InModuleScope iGWindowsTuner -Parameters @{ T = $v2 } { param($T) ConvertTo-IgwtV3Tweak -Tweak $T }
        $v3.scope | Should -Be 'Updates'
        $v3.gpoPath | Should -Be 'machine'
        @($v3.managedBy) | Should -Be @('local', 'gpo', 'mdm')
        @($v3.editions) | Should -Be @('Enterprise')
        $v3.appliesTo.Contains('editions') | Should -BeFalse
        ($v3.actions[0] | ConvertTo-Json -Compress) | Should -Be ($v2.actions[0] | ConvertTo-Json -Compress)
    }
    It 'refuses a policy item without gpoPath' {
        $bad = (Get-IgwtTweak -Id 'privacy.activity-history-off') | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $bad.id = 'privacy.bad-gpo'; $bad.gpoPath = ''
        $all = @(Get-IgwtCatalog) + @($bad)
        Mock -ModuleName iGWindowsTuner Get-IgwtCatalog { $all }
        (@(Test-IgwtCatalog) -join "`n") | Should -Match "privacy.bad-gpo: writes a Group Policy location; set gpoPath to 'machine'"
    }
}

Describe 'Management detection' {
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-IgwtOsInfo { [pscustomobject]@{ EditionId = 'Professional'; Build = 26300 } }
        Mock -ModuleName iGWindowsTuner Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = 'Normal' } }
        Mock -ModuleName iGWindowsTuner Get-CimInstance { [pscustomobject]@{ PartOfDomain = $script:Domain; Domain = 'corp.example' } } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        Mock -ModuleName iGWindowsTuner Get-CimInstance { @([pscustomobject]@{ displayName = 'Microsoft Defender Antivirus' }) } -ParameterFilter { $ClassName -eq 'AntivirusProduct' }
        $script:Domain = $false
        Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Enrollments' -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'reports an unmanaged PC and ignores the built-in enrollment authorities' {
        $k = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Enrollments\8345CBE6' -Force
        $null = New-ItemProperty -Path $k.PSPath -Name ProviderID -Value 'Deploy Authority'; $null = New-ItemProperty -Path $k.PSPath -Name EnrollmentState -Value 1 -PropertyType DWord; $null = New-ItemProperty -Path $k.PSPath -Name EnrollmentType -Value 30 -PropertyType DWord
        $s = Get-IgwtManagementState
        $s.Managed | Should -BeFalse
        $s.MdmEnrolled | Should -BeFalse
        $s.LocalGroupPolicy | Should -BeTrue
    }
    It 'detects a domain join and an Intune enrollment' {
        $script:Domain = $true
        $k = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Enrollments\ABC' -Force
        $null = New-ItemProperty -Path $k.PSPath -Name ProviderID -Value 'MS DM Server'; $null = New-ItemProperty -Path $k.PSPath -Name EnrollmentState -Value 1 -PropertyType DWord; $null = New-ItemProperty -Path $k.PSPath -Name EnrollmentType -Value 6 -PropertyType DWord
        $s = Get-IgwtManagementState
        $s.DomainJoined | Should -BeTrue
        $s.MdmEnrolled | Should -BeTrue
        @($s.MdmProviders) | Should -Be @('MS DM Server')
        $s.Managed | Should -BeTrue
        (@($s.Authorities) -join ' ') | Should -Match 'corp.example'
    }
    It 'marks Home as having no Local Group Policy' {
        Mock -ModuleName iGWindowsTuner Get-IgwtOsInfo { [pscustomobject]@{ EditionId = 'Core'; Build = 26300 } }
        (Get-IgwtManagementState).LocalGroupPolicy | Should -BeFalse
    }
}

Describe 'Report-only policy items on managed PCs' {
    BeforeAll {
        $script:Managed = [pscustomobject]@{ Managed = $true; Authorities = @('MDM (MS DM Server)') }
    }
    It 'refuses a policy item unless the local change is acknowledged, and leaves non-policy items alone' {
        $ctx = New-IgwtTestContext -Extra @{ Management = $script:Managed }
        $s = Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id 'privacy.activity-history-off') -Context $ctx
        $s.Authority | Should -Match 'managed'
        (Get-IgwtPlan -Id 'privacy.activity-history-off' -Context $ctx).Plan | Should -Be 'ReportOnly'
        $r = Invoke-IgwtApply -Id 'privacy.activity-history-off', 'input.pointer-precision-off' -Context $ctx
        ($r.Results | Where-Object Id -EQ 'privacy.activity-history-off').Result | Should -Be 'ReportOnly'
        ($r.Results | Where-Object Id -EQ 'input.pointer-precision-off').Result | Should -Be 'Applied'
        $r2 = Invoke-IgwtApply -Id 'privacy.activity-history-off' -AcknowledgeManaged -Context $ctx
        @($r2.Results)[0].Result | Should -Be 'Applied'
    }
    It 'applies policy items normally on an unmanaged PC' {
        $ctx = New-IgwtTestContext -Extra @{ Management = [pscustomobject]@{ Managed = $false; Authorities = @() } }
        (Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id 'privacy.location-off') -Context $ctx).Authority | Should -BeNullOrEmpty
    }
}

Describe 'Hardware detection failure' {
    It 'blocks items a hardware overlay guards when the hardware is unknown (fail closed)' {
        $ctx = New-IgwtTestContext -Extra @{ HardwareTags = @(); HardwareUnknown = $true }
        $s = Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id 'risk.processor-idle-disable') -Context $ctx
        $s.State | Should -Be 'NotApplicable'
        $s.Reason | Should -Match 'Hardware detection failed'
        (Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id 'gfx.game-mode') -Context $ctx).Applicable | Should -BeTrue
    }
}

Describe 'Personas' {
    AfterEach { InModuleScope iGWindowsTuner { $script:IgwtSettings.Persona = $null } }
    It 'defines three personas that change only what is shown' {
        foreach ($n in 'Gamer', 'PowerUser', 'Sysadmin') { (Get-IgwtPersonaProfile -Name $n).Name | Should -Be $n }
        $g = Get-IgwtPersonaProfile -Name Gamer
        InModuleScope iGWindowsTuner -Parameters @{ P = $g } { param($P) Test-IgwtItemVisible -Tweak (Get-IgwtTweak -Id 'gfx.gpu-msi') -Persona $P } | Should -BeFalse
        $s = Get-IgwtPersonaProfile -Name Sysadmin
        InModuleScope iGWindowsTuner -Parameters @{ P = $s } { param($P) Test-IgwtItemVisible -Tweak (Get-IgwtTweak -Id 'risk.hpet-disable') -Persona $P } | Should -BeFalse
        @($s.NavOrder)[1] | Should -Be 'Security'
    }
    It 'stores the persona per user' {
        Get-IgwtPersona | Should -Be 'Gamer'
        Set-IgwtPersona -Name Sysadmin
        Get-IgwtPersona | Should -Be 'Sysadmin'
    }
    It 'does not change a safety gate: Expert items still need the acknowledgement for every persona' {
        Set-IgwtPersona -Name PowerUser
        { Invoke-IgwtApply -Id 'gfx.gpu-msi' -Context (New-IgwtTestContext) } | Should -Throw '*AcknowledgeRisk*'
    }
}
