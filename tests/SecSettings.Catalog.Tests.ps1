# Security Settings Manager, B1 (DECISIONS SM2, SM5-SM8, SM14, SM25): data files, ADMX parser
# fields added for 3.8, -NoCache, policy selection, overlap index and the maintainer tool.
# Synthetic ADMX fixtures only; nothing reads or writes the real policy store.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Admx = Join-Path $PSScriptRoot 'fixtures\secsettings\admx'
    $script:Documented = Join-Path $PSScriptRoot 'fixtures\secsettings\set-mppreference-documented.json'
    InModuleScope iGWindowsTuner -Parameters @{ A = $script:Admx } { param($A) $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtAdmxCache = $null; $script:IgwtSecSettingsData = $null }
    $script:Cat = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force -NoCache }
    function Get-FixturePolicy([string]$Name) { @($script:Cat.Policies | Where-Object { $_.Name -eq $Name })[0] }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

Describe 'data\security files (SM2, SM14, SM25)' {
    It 'pass their validator, including Set-MpPreference coverage of every documented name' {
        @(InModuleScope iGWindowsTuner -Parameters @{ D = $script:Documented } { param($D) Test-IgwtSecSettingsCatalog -DocumentedPath $D }) | Should -BeNullOrEmpty
    }
    It 'are part of Test-IgwtCatalog' {
        @(InModuleScope iGWindowsTuner { Test-IgwtCatalog } | Where-Object { $_ -like 'security\*' }) | Should -BeNullOrEmpty
    }
    It 'report a documented parameter that is missing from mpCoverage' {
        $doc = Join-Path $TestDrive 'documented.json'
        '{ "parameters": [ { "name": "ContosoNewSetting", "type": "Boolean" } ] }' | Set-Content -LiteralPath $doc -Encoding ascii
        @(InModuleScope iGWindowsTuner -Parameters @{ D = $doc } { param($D) Test-IgwtSecSettingsCatalog -DocumentedPath $D }) | Should -Contain "security\settings-meta.json: the documented Defender preference parameter 'ContosoNewSetting' is not in mpCoverage."
    }
    It 'list the three UEFI-lock tuples, each with a Learn source' {
        $t = @(InModuleScope iGWindowsTuner { (Get-IgwtSecSettingsData).Meta.uefiLockValues })
        @($t | ForEach-Object { "$($_.valueName)=$($_.value)" }) | Should -Be @('HypervisorEnforcedCodeIntegrity=1', 'LsaCfgFlags=1', 'RunAsPPL=1')
        @($t | Where-Object { $_.source -notlike 'https://learn.microsoft.com/*' }) | Should -BeNullOrEmpty
    }
    It 'match settings-meta keys exactly first, then by the longest prefix' {
        InModuleScope iGWindowsTuner {
            (Get-IgwtSecSettingMeta -Id 'admx:VolumeEncryption:AnyPolicy:Machine').risk | Should -Be 'high'
            (Get-IgwtSecSettingMeta -Id 'admx:DeviceGuard:VirtualizationBasedSecurity:Machine').restart | Should -Be 'reboot'
            Get-IgwtSecSettingMeta -Id 'admx:Contoso:Nothing:Machine' | Should -BeNullOrEmpty
        }
    }
}

Describe 'ADMX parser fields added for 3.8 (SM7)' {
    It 'reads clientExtension, spin, spinStep, maxStrings, suggestions and presentation kinds' {
        $p = Get-FixturePolicy 'AllKinds'
        $p.ClientExtension | Should -Be '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
        $dec = $p.Elements | Where-Object Id -EQ 'DecEl'
        $dec.Presentation | Should -Be 'decimalTextBox'; $dec.Spin | Should -BeTrue; $dec.SpinStep | Should -Be 5
        ($p.Elements | Where-Object Id -EQ 'LongEl').Spin | Should -BeFalse
        ($p.Elements | Where-Object Id -EQ 'MultiEl').MaxStrings | Should -Be 5
        ($p.Elements | Where-Object Id -EQ 'TextEl').Label | Should -Be 'Server name'
        @((Get-FixturePolicy 'ListOwner').Elements[0].Suggestions) | Should -Be @('alpha', 'beta')
    }
    It 'keeps the existing fields unchanged' {
        $p = Get-FixturePolicy 'AllKinds'
        $p.Key | Should -Be 'Software\Policies\Contoso\Sec'; $p.ValueName | Should -Be 'AllKindsOn'
        $p.CategoryPath | Should -Be 'Lanman Workstation > Contoso child category'
        $p.SupportedOn | Should -Be 'At least Windows 11'
        ($p.Elements | Where-Object Id -EQ 'DecEl').Max | Should -Be 99
        ($p.Elements | Where-Object Id -EQ 'PairEl').ExplicitValue | Should -BeTrue
    }
    It 'with -NoCache writes no disk cache but keeps the catalog in memory for later readers' {
        InModuleScope iGWindowsTuner { $script:IgwtAdmxCache = $null; $null = Get-IgwtAdmxCatalog -Force -NoCache }
        @(Get-ChildItem -Path $TestDrive -Recurse -Filter 'admx-*.xml' -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
        InModuleScope iGWindowsTuner { $script:IgwtAdmxCache | Should -Not -BeNullOrEmpty; (Get-IgwtAdmxCatalog).Hash | Should -Be $script:IgwtAdmxCache.Hash }
        @(Get-ChildItem -Path $TestDrive -Recurse -Filter 'admx-*.xml' -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
    }
}

Describe 'Policies in scope (SM5)' {
    It 'takes namespace-wide entries, listed categories and their child categories, and nothing else' {
        $ids = @(InModuleScope iGWindowsTuner -Parameters @{ C = $script:Cat } { param($C) Get-IgwtSecSettingDefinitions -Catalog $C } | ForEach-Object { $_.Policy.Name })
        $ids | Should -Contain 'AllKinds'
        $ids | Should -Contain 'VbsShaped'
        $ids | Should -Not -Contain 'NotInScope'
    }
}

Describe 'Overlap index (SM8 condition 6)' {
    It 'finds shared value names and a list key that owns another policy''s key, and nothing for a lone policy' {
        $ix = InModuleScope iGWindowsTuner -Parameters @{ C = $script:Cat } { param($C) Get-IgwtSecSettingOverlapIndex -Catalog $C }
        @($ix['SecFixture:OverlapA']) | Should -Be @('SecFixture:OverlapB')
        @($ix['SecFixture:ListOwner']) | Should -Be @('SecFixture:ChildWriter')
        @($ix['SecFixture:ChildWriter']) | Should -Be @('SecFixture:ListOwner')
        $ix.ContainsKey('SecFixture:AllKinds') | Should -BeFalse
    }
}

Describe 'Maintainer review tool (SM6)' {
    It 'reports the unlisted keyword category, the unlisted lock choice, the logging switch and the overlaps, and writes no file' {
        $before = @(Get-ChildItem -Path $script:Admx -Recurse -File).Count
        # A child process: the tool imports the module with -Force, which would reset this test session.
        $tool = Join-Path $script:IgwtProjectRoot 'tools\Find-IgwtSecurityCategories.ps1'
        $cmd = "& '$tool' -AdmxFolder '$($script:Admx)' | ForEach-Object { `$_.Check + ' ' + `$_.Item + ' ' + `$_.Detail }"
        $text = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd)
        $text | Where-Object { $_ -like 'Category *Cat_Unlisted*' } | Should -Not -BeNullOrEmpty
        $text | Where-Object { $_ -like 'UefiLock *FakeIsolation=1*' } | Should -Not -BeNullOrEmpty
        $text | Where-Object { $_ -like 'UefiLock *HypervisorEnforcedCodeIntegrity=1*' } | Should -BeNullOrEmpty
        $text | Where-Object { $_ -like 'Weakening SecFixture:LoggingSwitch*' } | Should -Not -BeNullOrEmpty
        $text | Where-Object { $_ -like 'Overlap SecFixture:OverlapA*' } | Should -Not -BeNullOrEmpty
        @(Get-ChildItem -Path $script:Admx -Recurse -File).Count | Should -Be $before
    }
}
