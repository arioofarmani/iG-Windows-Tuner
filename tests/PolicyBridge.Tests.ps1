# 3.0 phase 5: catalog items that write a machine Policies key go through the Local GPO
# (Registry.pol + gpt.ini) as well as the registry; snapshots capture the Registry.pol entries;
# v1/v2 snapshots still revert correctly; tattooed values can be adopted or removed. The GPO folder
# is a temporary copy in TestDrive and registry values live in TestRegistry.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Ctx = New-IgwtTestContext
    $script:Explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $script:PolKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

    function Get-TestValue([string]$Path, [string]$Name) { InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Get-IgwtRegistryValue -Path $P -Name $N } }
    function Clear-TestValue([string]$Path, [string]$Name) { InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Remove-IgwtRegistryValue -Path $P -Name $N } }
    function Write-TestValue([string]$Path, [string]$Name, [string]$Kind, $Value) { InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name; K = $Kind; V = $Value } { param($P, $N, $K, $V) Set-IgwtRegistryValue -Path $P -Name $N -Kind $K -Value $V } }
    function Get-TestPol { @(InModuleScope iGWindowsTuner { (Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine)).Entries }) }
    function Get-TestPolValue([string]$Name) { @(Get-TestPol | Where-Object { $_.Key -eq $script:PolKey -and $_.ValueName -eq $Name }) }
    function Get-TestGptVersion { $f = Join-Path $script:GpoRoot 'gpt.ini'; if (-not (Test-Path $f)) { return 0 }; (InModuleScope iGWindowsTuner -Parameters @{ T = [IO.File]::ReadAllText($f) } { param($T) Read-IgwtGptIni -Text $T }).MachineVersion }
}

Describe 'Policy items through the Local GPO' {
    BeforeEach {
        $script:GpoRoot = Join-Path $TestDrive ('GPO-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:GpoRoot } { param($R) $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = "$R-Users"; $script:IgwtSettings.PolicyBridge = $null }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $true } }
        Clear-TestValue $script:Explorer 'NoAutorun'; Clear-TestValue $script:Explorer 'NoDriveTypeAutoRun'
    }
    AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null } }

    It 'writes the registry and Registry.pol, bumps gpt.ini and reverts both' {
        $r = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 1
        (Get-TestValue $script:Explorer 'NoAutorun').Value | Should -Be 1
        (Get-TestPolValue 'NoAutorun')[0].Value | Should -Be 1
        (Get-TestPolValue 'NoDriveTypeAutoRun')[0].Value | Should -Be 255
        Get-TestGptVersion | Should -BeGreaterThan 0
        $doc = Get-Content $r.Snapshot -Raw | ConvertFrom-Json
        @(@($doc.entries[0].actions | ForEach-Object { $_.data.items[0] } | Where-Object { $_.pol })).Count | Should -Be 2; @($doc.entries[0].actions[0].data.items[0].pol.entries).Count | Should -Be 0 -Because 'the value was not in the Local GPO before'
        $null = Invoke-IgwtRevert -Id 'sec.autorun-off' -Context $script:Ctx
        (Get-TestValue $script:Explorer 'NoAutorun').Exists | Should -BeFalse
        @(Get-TestPolValue 'NoAutorun').Count | Should -Be 0
        @(Get-TestPolValue 'NoDriveTypeAutoRun').Count | Should -Be 0
    }
    It 'restores a pre-existing Local GPO entry byte for byte' {
        $other = InModuleScope iGWindowsTuner { New-IgwtPolEntryObject -Key 'SOFTWARE\Policies\Other' -ValueName 'Keep' -Type 4 -Data ([BitConverter]::GetBytes([uint32]7)) }
        $pre = InModuleScope iGWindowsTuner -Parameters @{ K = $script:PolKey } { param($K) New-IgwtPolEntryObject -Key $K -ValueName 'NoAutorun' -Type 4 -Data ([BitConverter]::GetBytes([uint32]0)) }
        InModuleScope iGWindowsTuner -Parameters @{ E = @($other, $pre) } { param($E) Write-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine) -Entries $E }
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol')))
        Write-TestValue $script:Explorer 'NoAutorun' 'DWord' 0
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        (Get-TestPolValue 'NoAutorun')[0].Value | Should -Be 1
        $null = Invoke-IgwtRevert -Id 'sec.autorun-off' -Context $script:Ctx
        (Get-TestValue $script:Explorer 'NoAutorun').Value | Should -Be 0
        $entries = @(Get-TestPol)
        @($entries | ForEach-Object { $_.ValueName }) | Should -Be @('Keep', 'NoAutorun')
        (Get-TestPolValue 'NoAutorun')[0].Value | Should -Be 0
        ($entries | Where-Object ValueName -EQ 'Keep').Value | Should -Be 7
        [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol'))) | Should -Be $before
    }
    It 'makes the value not configured when reset to the Windows default' {
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        $null = InModuleScope iGWindowsTuner -Parameters @{ C = $script:Ctx } { param($C) foreach ($a in @((Get-IgwtTweak -Id 'sec.autorun-off').actions)) { Invoke-IgwtActionApply -Action $a -Context $C -Mode default } }
        (Get-TestValue $script:Explorer 'NoAutorun').Exists | Should -BeFalse
        @(Get-TestPolValue 'NoAutorun').Count | Should -Be 0
    }
    It 'reverts a v2 snapshot (no Registry.pol data) and keeps the Local GPO in step' {
        # A 2.x apply wrote only the registry; later the value was adopted into the Local GPO.
        $snap = InModuleScope iGWindowsTuner { $script:IgwtSettings.PolicyBridge = $false; try { $a = (Get-IgwtTweak -Id 'sec.autorun-off').actions | Where-Object name -EQ 'NoAutorun'; $s = Get-IgwtActionSnapshot -Action $a; Invoke-IgwtActionApply -Action $a; $s } finally { $script:IgwtSettings.PolicyBridge = $null } }
        $snap.items[0].Contains('pol') | Should -BeFalse
        $null = InModuleScope iGWindowsTuner { Invoke-IgwtTattooAdoption -Action Adopt -Select @('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun') }
        (Get-TestPolValue 'NoAutorun')[0].Value | Should -Be 1
        InModuleScope iGWindowsTuner -Parameters @{ S = $snap } { param($S) Restore-IgwtActionSnapshot -Action ((Get-IgwtTweak -Id 'sec.autorun-off').actions | Where-Object name -EQ 'NoAutorun') -Snapshot $S }
        (Get-TestValue $script:Explorer 'NoAutorun').Exists | Should -BeFalse
        @(Get-TestPolValue 'NoAutorun').Count | Should -Be 0
    }
    It 'reverts a v2 snapshot without touching Registry.pol when the value was never in it' {
        $snap = InModuleScope iGWindowsTuner { $script:IgwtSettings.PolicyBridge = $false; try { $a = (Get-IgwtTweak -Id 'sec.autorun-off').actions | Where-Object name -EQ 'NoAutorun'; $s = Get-IgwtActionSnapshot -Action $a; Invoke-IgwtActionApply -Action $a; $s } finally { $script:IgwtSettings.PolicyBridge = $null } }
        InModuleScope iGWindowsTuner -Parameters @{ S = $snap } { param($S) Restore-IgwtActionSnapshot -Action ((Get-IgwtTweak -Id 'sec.autorun-off').actions | Where-Object name -EQ 'NoAutorun') -Snapshot $S }
        Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
    }
    It 'refuses a snapshot whose Registry.pol entry belongs to another value' {
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        $bad = InModuleScope iGWindowsTuner { ConvertTo-IgwtHexString -Value ((ConvertTo-IgwtPolEntryBytes -Entry (New-IgwtPolEntryObject -Key 'SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'DisableAntiSpyware' -Type 4 -Data ([BitConverter]::GetBytes([uint32]1))))) }
        $snap = @{ items = @([ordered]@{ scope = ''; path = $script:Explorer; name = 'NoAutorun'; exists = $false; kind = $null; value = $null; missingDepth = 0; pol = [ordered]@{ class = 'Machine'; entries = @($bad) } }) }
        { InModuleScope iGWindowsTuner -Parameters @{ S = $snap } { param($S) Restore-IgwtActionSnapshot -Action ((Get-IgwtTweak -Id 'sec.autorun-off').actions | Where-Object name -EQ 'NoAutorun') -Snapshot $S } } | Should -Throw '*does not belong*'
        @(Get-TestPol | Where-Object ValueName -EQ 'DisableAntiSpyware').Count | Should -Be 0
    }
    It 'leaves HKCU items as per-user registry writes' {
        InModuleScope iGWindowsTuner { $a = [pscustomobject]@{ type = 'registry'; path = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'; name = 'IgwtTestValue'; valueType = 'DWord'; on = 1; default = '<absent>'; absentValue = $null; equivalentOn = $null; bitClear = $null; bitSet = $null; onlyIfAbsent = $false }; Invoke-IgwtActionApply -Action $a; (Get-IgwtActionSnapshot -Action $a).items[0].Contains('pol') | Should -BeFalse }
        Test-Path -LiteralPath (Join-Path $script:GpoRoot 'User\Registry.pol') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
    }
    It 'is off on editions without Local Group Policy, when turned off, and in TestMode without a temporary GPO folder' {
        (InModuleScope iGWindowsTuner { Test-IgwtPolicyBridgeEnabled }) | Should -BeTrue
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; LocalGroupPolicy = $false } }
        (InModuleScope iGWindowsTuner { Test-IgwtPolicyBridgeEnabled }) | Should -BeFalse
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        (Get-TestValue $script:Explorer 'NoAutorun').Value | Should -Be 1
        Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
        InModuleScope iGWindowsTuner { $saved = $script:IgwtSettings.GpoRoot; try { $script:IgwtSettings.GpoRoot = $null; Test-IgwtPolicyBridgeEnabled | Should -BeFalse } finally { $script:IgwtSettings.GpoRoot = $saved } }
        InModuleScope iGWindowsTuner { $script:IgwtSettings.PolicyBridge = $false; try { Test-IgwtPolicyBridgeEnabled | Should -BeFalse } finally { $script:IgwtSettings.PolicyBridge = $null } }
    }
    It 'maps only machine Policies paths' {
        InModuleScope iGWindowsTuner {
            (Get-IgwtPolicyBridgeTarget -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'X').Key | Should -Be 'SOFTWARE\Policies\Microsoft\Windows\System'
            (Get-IgwtPolicyBridgeTarget -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun').Class | Should -Be 'Machine'
            Get-IgwtPolicyBridgeTarget -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'X' | Should -BeNullOrEmpty
            Get-IgwtPolicyBridgeTarget -Path 'HKCU:\Software\Policies\Microsoft\X' -Name 'X' | Should -BeNullOrEmpty
            Get-IgwtPolicyBridgeTarget -Path 'HKLM:\SOFTWARE\Policies\X' -Name '' | Should -BeNullOrEmpty
        }
    }
    It 'notes values that are on but only in the registry' {
        Write-TestValue $script:Explorer 'NoAutorun' 'DWord' 1
        $st = @(InModuleScope iGWindowsTuner { Get-IgwtRegistryState -Action ((Get-IgwtTweak -Id 'sec.autorun-off').actions | Where-Object name -EQ 'NoAutorun') })
        $st[0].Note | Should -Match 'tattooed'
    }

    Context 'Tattooed values' {
        It 'adopts selected values into the Local GPO after a backup and refuses denylisted values' {
            Write-TestValue $script:Explorer 'NoAutorun' 'DWord' 1
            Write-TestValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 'DWord' 1
            $plan = InModuleScope iGWindowsTuner { Get-IgwtTattooAdoptionPlan -Action Adopt -Select @('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun', 'SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware', 'SOFTWARE\Policies\Nope\X') }
            ($plan.Ops | Where-Object ValueName -EQ 'DisableAntiSpyware').Refusal | Should -Match 'Remove it instead'
            @($plan.NotFound) | Should -Be @('SOFTWARE\Policies\Nope\X')
            $r = InModuleScope iGWindowsTuner { Invoke-IgwtTattooAdoption -Action Adopt -Select @('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun', 'SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware') }
            $r.Count | Should -Be 1
            Test-Path -LiteralPath (Join-Path $r.Backup 'manifest.json') | Should -BeTrue
            (Get-TestPolValue 'NoAutorun')[0].Value | Should -Be 1
            @(Get-TestPol | Where-Object ValueName -EQ 'DisableAntiSpyware').Count | Should -Be 0
            Clear-TestValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware'
        }
        It 'selects every value an iG Windows Tuner item wrote with igwt' {
            Write-TestValue $script:Explorer 'NoAutorun' 'DWord' 1
            Write-TestValue 'HKLM:\SOFTWARE\Policies\IgwtUnknownVendor' 'Foo' 'DWord' 1
            $plan = InModuleScope iGWindowsTuner { Get-IgwtTattooAdoptionPlan -Action Adopt -Select @('igwt') }
            @($plan.Ops | ForEach-Object { $_.ValueName }) | Should -Contain 'NoAutorun'
            @($plan.Ops | ForEach-Object { $_.ValueName }) | Should -Not -Contain 'Foo'
            Clear-TestValue 'HKLM:\SOFTWARE\Policies\IgwtUnknownVendor' 'Foo'
        }
        It 'removes tattooed values with a restore file and writes them back' {
            Write-TestValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 'DWord' 1
            $r = InModuleScope iGWindowsTuner { Invoke-IgwtTattooAdoption -Action Remove -Select @('SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware') }
            (Get-TestValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware').Exists | Should -BeFalse
            $n = InModuleScope iGWindowsTuner -Parameters @{ F = $r.Backup } { param($F) Restore-IgwtTattooRemoval -Path $F }
            $n.Restored | Should -Be 1
            (Get-TestValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware').Value | Should -Be 1
            Clear-TestValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware'
        }
        It 'refuses a restore file that points outside the machine Policies keys' {
            $f = Join-Path $TestDrive 'evil.json'
            [IO.File]::WriteAllText($f, '{"kind":"igwt-tattoo-removal","values":[{"key":"SYSTEM\\CurrentControlSet\\Services\\WinDefend","name":"Start","kind":"DWord","value":4}]}')
            { InModuleScope iGWindowsTuner -Parameters @{ F = $f } { param($F) Restore-IgwtTattooRemoval -Path $F } } | Should -Throw '*not under a machine Policies key*'
        }
        It 'ignores Windows-owned values under CurrentVersion\Policies' {
            Write-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'IgwtWindowsOwned' 'DWord' 1
            @(InModuleScope iGWindowsTuner { Get-IgwtTattooedPolicyValues } | Where-Object ValueName -EQ 'IgwtWindowsOwned').Count | Should -Be 0
            Clear-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'IgwtWindowsOwned'
        }
    }
}
