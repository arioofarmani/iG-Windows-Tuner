BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Ctx = New-IgwtTestContext

    function Get-TestValue([string]$Path, [string]$Name) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Get-IgwtRegistryValue -Path $P -Name $N }
    }
    function Write-TestValue([string]$Path, [string]$Name, [string]$Kind, $Value) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name; K = $Kind; V = $Value } { param($P, $N, $K, $V) Set-IgwtRegistryValue -Path $P -Name $N -Kind $K -Value $V }
    }
    function Clear-TestValue([string]$Path, [string]$Name) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Remove-IgwtRegistryValue -Path $P -Name $N }
    }
    function Initialize-TestSeed {
        # Machine state similar to a typical gaming PC: mouse values written as DWORD by an old tool,
        # DirectX string with only the VRR item, Game Mode value absent, AutoRun values absent.
        Write-TestValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Kind 'DWord' -Value 0
        Write-TestValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Kind 'DWord' -Value 0
        Write-TestValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Kind 'DWord' -Value 0
        Write-TestValue -Path 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' -Name 'DirectXUserGlobalSettings' -Kind 'String' -Value 'VRROptimizeEnable=1;'
        Clear-TestValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled'
        Write-TestValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
        Clear-TestValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
        Clear-TestValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun'
    }
    $script:Ids = @('gfx.game-mode', 'gfx.windowed-optimizations', 'input.pointer-precision-off', 'sec.autorun-off')
}

Describe 'Apply and revert real catalog tweaks (TestRegistry)' {
    BeforeAll { Initialize-TestSeed }

    It 'starts Off for the seeded state' {
        $states = Get-IgwtAllTweakStates -Id $script:Ids -Context $script:Ctx
        foreach ($s in $states) { $s.State | Should -Not -Be 'On' -Because $s.Id }
    }

    It 'dry run changes nothing' {
        $plan = Get-IgwtPlan -Id $script:Ids -Context $script:Ctx
        @($plan | Where-Object Plan -EQ 'Change').Count | Should -Be 4
        (Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseSpeed').Kind | Should -Be 'DWord'
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun').Exists | Should -BeFalse
    }

    It 'applies, verifies and writes a snapshot' {
        $r = Invoke-IgwtApply -Id $script:Ids -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 4
        @($r.Results | Where-Object { $_.Result -eq 'Applied' -and -not $_.Verified }).Count | Should -Be 0
        $r.Snapshot | Should -Exist
        $doc = Get-Content $r.Snapshot -Raw | ConvertFrom-Json
        $doc.schema | Should -Be 2
        $doc.catalogSchema | Should -Be 2
        @($doc.entries).Count | Should -Be 4
        foreach ($e in $doc.entries) { $e.result | Should -Be 'Applied'; $e.actions[0].fingerprint | Should -Not -BeNullOrEmpty; $e.level | Should -Be 'Standard' -Because $e.tweakId }
        foreach ($s in (Get-IgwtAllTweakStates -Id $script:Ids -Context $script:Ctx)) { $s.State | Should -Be 'On' -Because $s.Id }
        (Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseSpeed').Kind | Should -Be 'String'
        (Get-TestValue 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;'
    }

    It 'is idempotent (second apply changes nothing and writes no snapshot)' {
        $r = Invoke-IgwtApply -Id $script:Ids -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Unchanged').Count | Should -Be 4
        $r.Snapshot | Should -BeNullOrEmpty
    }

    It 'reverts by id to the exact previous values (types and absent values)' {
        $r = Invoke-IgwtRevert -Id $script:Ids -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 4
        $m = Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseSpeed'
        $m.Kind | Should -Be 'DWord'; $m.Value | Should -Be 0
        (Get-TestValue 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;'
        (Get-TestValue 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled').Value | Should -Be 0
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun').Exists | Should -BeFalse
    }

    It 'does not revert twice' {
        $r = Invoke-IgwtRevert -Id $script:Ids -Context $script:Ctx
        @($r.Results).Count | Should -Be 0
    }

    It 'reverts everything from the last apply with -Last' {
        $null = Invoke-IgwtApply -Id 'sec.autorun-off' -Context $script:Ctx
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun').Value | Should -Be 1
        $r = Invoke-IgwtRevert -Last -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Reverted').Id | Should -Be 'sec.autorun-off'
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun').Exists | Should -BeFalse
    }

    It 'resets to documented Windows defaults' {
        $null = Invoke-IgwtApply -Id 'input.pointer-precision-off' -Context $script:Ctx
        $r = Invoke-IgwtApply -Id 'input.pointer-precision-off' -Mode default -Operation ResetDefault -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 1
        (Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseSpeed').Value | Should -Be '1'
        (Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseThreshold1').Value | Should -Be '6'
        (Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseThreshold2').Value | Should -Be '10'
    }
}

Describe 'Atomic per-tweak rollback and safety checks' {
    BeforeAll {
        $good = @{ type = 'registry'; path = 'HKLM:\SOFTWARE\IgwtTest\Atomic'; name = 'First'; valueType = 'DWord'; on = 1; default = '<absent>' }
        $bad = @{ type = 'registry'; path = 'HKLM:\SOFTWARE\IgwtTest\Atomic'; name = 'Second'; valueType = 'DWord'; on = 'not-a-number'; default = '<absent>' }
        $script:TestCatalog = @(
            (New-IgwtTestTweak -Id 'test.atomic' -Actions @($good, $bad))
            (New-IgwtTestTweak -Id 'test.fine' -Actions @(@{ type = 'registry'; path = 'HKLM:\SOFTWARE\IgwtTest\Fine'; name = 'V'; valueType = 'DWord'; on = 5; default = '<absent>' }))
            (New-IgwtTestTweak -Id 'test.expert' -Expert -Actions @(@{ type = 'registry'; path = 'HKLM:\SOFTWARE\IgwtTest\Expert'; name = 'V'; valueType = 'DWord'; on = 1; default = '<absent>' }))
            (New-IgwtTestTweak -Id 'test.a' -ConflictsWith @('test.b') -Actions @(@{ type = 'registry'; path = 'HKLM:\SOFTWARE\IgwtTest\C'; name = 'A'; valueType = 'DWord'; on = 1; default = '<absent>' }))
            (New-IgwtTestTweak -Id 'test.b' -ConflictsWith @('test.a') -Actions @(@{ type = 'registry'; path = 'HKLM:\SOFTWARE\IgwtTest\C'; name = 'B'; valueType = 'DWord'; on = 1; default = '<absent>' }))
        )
        Mock Get-IgwtCatalog -ModuleName iGWindowsTuner { $script:TestCatalog }
        Write-TestValue -Path 'HKLM:\SOFTWARE\IgwtTest\Atomic' -Name 'First' -Kind 'DWord' -Value 7
    }

    It 'rolls back the already-applied actions of a failing tweak and continues with the rest' {
        $r = Invoke-IgwtApply -Id 'test.atomic', 'test.fine' -Context $script:Ctx
        ($r.Results | Where-Object Id -EQ 'test.atomic').Result | Should -Be 'Failed'
        ($r.Results | Where-Object Id -EQ 'test.fine').Result | Should -Be 'Applied'
        (Get-TestValue 'HKLM:\SOFTWARE\IgwtTest\Atomic' 'First').Value | Should -Be 7
        (Get-TestValue 'HKLM:\SOFTWARE\IgwtTest\Atomic' 'Second').Exists | Should -BeFalse
        (Get-TestValue 'HKLM:\SOFTWARE\IgwtTest\Fine' 'V').Value | Should -Be 5
        $doc = Get-Content $r.Snapshot -Raw | ConvertFrom-Json
        ($doc.entries | Where-Object tweakId -EQ 'test.atomic').result | Should -Be 'RolledBack'
    }

    It 'requires -AcknowledgeRisk for expert toggles' {
        { Invoke-IgwtApply -Id 'test.expert' -Context $script:Ctx } | Should -Throw '*expert*'
        $r = Invoke-IgwtApply -Id 'test.expert' -AcknowledgeRisk -Context $script:Ctx
        $r.Results[0].Result | Should -Be 'Applied'
    }

    It 'refuses conflicting selections' {
        { Invoke-IgwtApply -Id 'test.a', 'test.b' -Context $script:Ctx } | Should -Throw '*conflict*'
    }

    It 'refuses unknown ids' {
        { Invoke-IgwtApply -Id 'test.nope' -Context $script:Ctx } | Should -Throw '*Unknown tweak id*'
    }

    It 'does not restore onto a catalog definition that changed since the snapshot' {
        $null = Invoke-IgwtApply -Id 'test.fine' -Mode default -Operation ResetDefault -Context $script:Ctx
        $r1 = Invoke-IgwtApply -Id 'test.fine' -Context $script:Ctx
        $r1.Results[0].Result | Should -Be 'Applied'
        $script:TestCatalog[1].actions[0].path = 'HKLM:\SOFTWARE\IgwtTest\Moved'
        $r = Invoke-IgwtRevert -Id 'test.fine' -Context $script:Ctx
        $r.Results[0].Result | Should -Be 'Failed'
        $r.Results[0].Message | Should -Match 'changed'
        $script:TestCatalog[1].actions[0].path = 'HKLM:\SOFTWARE\IgwtTest\Fine'
    }
}

Describe 'State roll-up' {
    It 'rolls item states up correctly' -ForEach @(
        @{ In = @('On', 'On'); Out = 'On' }
        @{ In = @('Off', 'Off'); Out = 'Off' }
        @{ In = @('On', 'Off'); Out = 'Partial' }
        @{ In = @('On', 'NotApplicable'); Out = 'On' }
        @{ In = @('NotApplicable'); Out = 'NotApplicable' }
        @{ In = @('On', 'ManagedByPolicy'); Out = 'ManagedByPolicy' }
        @{ In = @('Unknown'); Out = 'Unknown' }
        @{ In = @('Off', 'Unknown'); Out = 'Off' }
    ) {
        $in = $In
        InModuleScope iGWindowsTuner -Parameters @{ S = $in } { param($S) Get-IgwtStateRollup -States $S } | Should -Be $Out
    }

    It 'reports ManagedByPolicy when a policy value controls the tweak' {
        $t = New-IgwtTestTweak -Id 'test.policy' -Actions @(@{ type = 'registry'; path = 'HKCU:\Software\IgwtTest\P'; name = 'V'; valueType = 'DWord'; on = 1; default = '<absent>' })
        $t.policyKeys = @([pscustomobject]@{ path = 'HKLM:\SOFTWARE\Policies\IgwtTest'; name = 'Enforced' })
        Write-TestValue -Path 'HKLM:\SOFTWARE\Policies\IgwtTest' -Name 'Enforced' -Kind 'DWord' -Value 0
        (Get-IgwtTweakState -Tweak $t -Context $script:Ctx).State | Should -Be 'ManagedByPolicy'
    }

    It 'reports NotApplicable for runtime conditions and RDP blocks' {
        $t = New-IgwtTestTweak -Id 'test.hw' -Actions @(@{ type = 'registry'; path = 'HKCU:\Software\IgwtTest\H'; name = 'V'; valueType = 'DWord'; on = 1; default = '<absent>' })
        $t.appliesTo.conditions = @('multipleGpus')
        (Get-IgwtTweakState -Tweak $t -Context $script:Ctx).State | Should -Be 'NotApplicable'
        $t.appliesTo.conditions = @('notRdp')
        (Get-IgwtTweakState -Tweak $t -Context (New-IgwtTestContext -Extra @{ IsRdp = $true })).State | Should -Be 'NotApplicable'
        (Get-IgwtTweakState -Tweak $t -Context $script:Ctx).State | Should -Not -Be 'NotApplicable'
    }
}

Describe 'Backups from pre-release preview builds' {
    AfterAll { Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'IgwtData') }
    It 'lists and reads snapshots in the legacy data root that say tool AegisTune, and never writes there' {
        $legacy = Join-Path $TestDrive 'LegacyRoot'
        $null = New-Item -ItemType Directory -Path (Join-Path $legacy 'Backups') -Force
        $doc = [ordered]@{ schema = 2; tool = 'AegisTune'; version = '1.0.0'; id = 'x1'; created = '2026-10-16T18:17:47Z'; operation = 'Apply'; detail = ''; catalogSchema = 2; hardwareTags = @(); entries = @() }
        $file = Join-Path $legacy 'Backups\snapshot-20261016-181747-907-Apply-abcdef.json'
        Set-Content -LiteralPath $file -Value ($doc | ConvertTo-Json -Depth 5) -Encoding UTF8
        Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'NewRoot') -LegacyDataRoot $legacy
        @(Get-IgwtSnapshotList | ForEach-Object { $_.Path }) | Should -Contain $file
        (InModuleScope iGWindowsTuner -Parameters @{ F = $file } { param($F) Read-IgwtSnapshot -Path $F }).tool | Should -Be 'AegisTune'
        (Get-IgwtDataPath -Kind Backups) | Should -Be (Join-Path (Join-Path $TestDrive 'NewRoot') 'Backups')
        Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'NewRoot')
        @(Get-IgwtSnapshotList | ForEach-Object { $_.Path }) | Should -Not -Contain $file
    }
}
