# Schema v2 and v1 migration tests. The v1 data and the v1 snapshot come from tests\fixtures\v1
# (frozen iG Windows Tuner 1.0 files). Migration runs only on TestDrive copies; registry work uses
# TestRegistry through the normal test redirection.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Fixture = Join-Path $PSScriptRoot 'fixtures\v1'
    $script:RepoData = Join-Path $script:IgwtProjectRoot 'data'

    function New-V1DataCopy {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates TestDrive fixtures only.')]
        [CmdletBinding()]
        param()
        $dest = Join-Path $TestDrive ('v1data-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        Copy-Item -LiteralPath (Join-Path $script:Fixture 'data') -Destination $dest -Recurse
        Copy-Item -LiteralPath (Join-Path $script:RepoData 'hardware') -Destination $dest -Recurse
        Copy-Item -LiteralPath (Join-Path $script:RepoData 'asr') -Destination $dest -Recurse   # 2.0 ASR rule catalog (no v1 equivalent)
        Copy-Item -LiteralPath (Join-Path $script:RepoData 'power') -Destination $dest -Recurse # 2.0 power plan editor settings (no v1 equivalent)
        Copy-Item -LiteralPath (Join-Path $script:RepoData 'migration') -Destination $dest -Recurse
        return $dest
    }
    function Get-RawTweaks([string]$Folder) {
        foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $Folder 'tweaks') -Filter *.json)) { @((Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json).tweaks) }
    }
    function Get-Fingerprints($Tweak) {
        @($Tweak.actions | ForEach-Object { $a = $_; InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Get-IgwtActionFingerprint $A } })
    }
}

AfterAll { Set-IgwtEnvironment -DataFolder '' }

Describe 'Schema v2: every shipped item' {
    BeforeAll {
        $script:Tweaks = @(Get-IgwtCatalog -Force)
        $script:Rules = @(Get-IgwtCleanerRules -Force)
        $script:Presets = @(Get-IgwtPreset)
        $script:Tags = @(Get-IgwtHardwareTagDefinitions -Force)
    }
    It 'declares schemaVersion 2 in every data file' {
        $files = @(Get-ChildItem -LiteralPath $script:RepoData -Recurse -Filter *.json | Where-Object { $_.Directory.Name -in 'tweaks', 'presets', 'cleaner', 'hardware', 'migration' })
        $files.Count | Should -BeGreaterThan 15
        foreach ($f in $files) { (Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json).schemaVersion | Should -Be 2 -Because $f.Name }
    }
    It 'contains no v1 fields in the data files' {
        foreach ($t in (Get-RawTweaks $script:RepoData)) {
            $t.PSObject.Properties['antiCheatSafe'] | Should -BeNullOrEmpty -Because $t.id
            $t.PSObject.Properties['expert'] | Should -BeNullOrEmpty -Because $t.id
            $t.appliesTo.PSObject.Properties['hardware'] | Should -BeNullOrEmpty -Because $t.id
        }
        foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $script:RepoData 'presets') -Filter *.json)) { (Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json).PSObject.Properties['tweaks'] | Should -BeNullOrEmpty -Because $f.Name }
    }
    It 'validates without errors' {
        @(Test-IgwtCatalog) | Should -BeNullOrEmpty
        @(Test-IgwtCleanerCatalog) | Should -BeNullOrEmpty
    }
    It 'gives every tweak, cleaner rule, preset and hardware tag a hint of 140 characters or fewer and a description' {
        $items = @($script:Tweaks | ForEach-Object { [pscustomobject]@{ Label = "tweak $($_.id)"; Hint = [string]$_.hint; Description = [string]$_.description } }) +
            @($script:Rules | ForEach-Object { [pscustomobject]@{ Label = "rule $($_.id)"; Hint = [string]$_.hint; Description = [string]$_.description } }) +
            @($script:Presets | ForEach-Object { [pscustomobject]@{ Label = "preset $($_.id)"; Hint = [string]$_.hint; Description = [string]$_.description } }) +
            @($script:Tags | ForEach-Object { [pscustomobject]@{ Label = "tag $($_.id)"; Hint = [string]$_.hint; Description = [string]$_.description } })
        $items.Count | Should -BeGreaterThan 130
        foreach ($i in $items) {
            $i.Hint.Trim() | Should -Not -BeNullOrEmpty -Because $i.Label
            $i.Hint.Length | Should -BeLessOrEqual 140 -Because $i.Label
            $i.Description.Length | Should -BeGreaterOrEqual 40 -Because $i.Label
        }
    }
    It 'gives every tweak and cleaner rule a valid level, tier, antiCheat, reversible, source and known hardware tags' {
        $known = @($script:Tags.id)
        foreach ($i in @($script:Tweaks) + @($script:Rules)) {
            $i.level | Should -BeIn @('Standard', 'Advanced', 'Expert', 'Lab') -Because $i.id
            (InModuleScope iGWindowsTuner -Parameters @{ I = $i } { param($I) Get-IgwtItemTier -Item $I }) | Should -BeIn @('A', 'B', 'R') -Because $i.id
            (InModuleScope iGWindowsTuner -Parameters @{ V = $i.antiCheat } { param($V) ConvertTo-IgwtAntiCheatInfo -Value $V }).Valid | Should -BeTrue -Because $i.id
            $i.reversible | Should -BeIn @('full', 'partial', 'none') -Because $i.id
            $i.source | Should -BeIn @('igwt', 'winutil', 'microsoft') -Because $i.id
            if ($i.source -eq 'winutil') { [string]$i.attribution | Should -Not -BeNullOrEmpty -Because $i.id }
            $i.PSObject.Properties['sideEffects'] | Should -Not -BeNullOrEmpty -Because $i.id
            foreach ($t in @($i.hardware.tags) + @($i.hardware.excludeTags)) { if ($t) { $t | Should -BeIn $known -Because $i.id } }
        }
    }
    It 'keeps Lab, rejected and non-safe items out of every gaming preset' {
        $rejected = @(Get-IgwtRejectedTweaks | ForEach-Object { $_.id })
        foreach ($p in $script:Presets) {
            foreach ($id in $p.tweaks) {
                $t = $script:Tweaks | Where-Object { $_.id -eq $id }
                $t.level | Should -Not -Be 'Lab' -Because "$($p.id): $id"
                $id | Should -Not -BeIn $rejected
                if ($p.gaming) { $t.antiCheat | Should -Be 'safe' -Because "$($p.id): $id" }
            }
        }
    }
    It 'marks the item that breaks anti-cheat as Lab and names the anti-cheats' {
        $t = $script:Tweaks | Where-Object { $_.id -eq 'sec.vbs-hvci-off-expert' }
        $t.level | Should -Be 'Lab'
        @($t.antiCheat.breaks) | Should -Contain 'FACEIT'
        @($t.antiCheat.breaks) | Should -Contain 'Riot Vanguard'
        $t.expert | Should -BeTrue
        $t.antiCheatSafe | Should -BeFalse
    }
    It 'reports every broken v2 field' {
        $base = (Get-Content -LiteralPath (Join-Path $script:RepoData 'tweaks\input.json') -Raw | ConvertFrom-Json).tweaks[0]
        $make = {
            param([string]$Id, [scriptblock]$Change)
            $raw = $base | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $raw.id = $Id
            & $Change $raw
            InModuleScope iGWindowsTuner -Parameters @{ R = $raw } { param($R) ConvertTo-IgwtNormalizedTweak -Tweak $R -SourceFile 'input.json' }
        }
        $bad = @(
            (& $make 'input.bad-hint' { param($r) $r.hint = 'x' * 141 })
            (& $make 'input.bad-desc' { param($r) $r.description = '' })
            (& $make 'input.bad-level' { param($r) $r.level = 'Ultra' })
            (& $make 'input.bad-ac' { param($r) $r.antiCheat = 'maybe' })
            (& $make 'input.bad-breaks' { param($r) $r.antiCheat = [pscustomobject]@{ breaks = @('FACEIT') }; $r.level = 'Advanced' })
            (& $make 'input.bad-rev' { param($r) $r.reversible = 'sometimes' })
            (& $make 'input.bad-partial' { param($r) $r.reversible = 'partial'; $r.sideEffects = '' })
            (& $make 'input.bad-winutil' { param($r) $r.source = 'winutil' })
            (& $make 'input.bad-tag' { param($r) $r.hardware.tags = @('gpu.voodoo') })
            (& $make 'input.bad-cond' { param($r) $r.appliesTo | Add-Member -NotePropertyName conditions -NotePropertyValue @('moonPhase') -Force })
            (& $make 'input.bad-legacy' { param($r) $r | Add-Member -NotePropertyName antiCheatSafe -NotePropertyValue $true })
            (& $make 'input.bad-expert' { param($r) $r.level = 'Expert' })
        )
        Mock -ModuleName iGWindowsTuner Get-IgwtCatalog { $bad }
        $errors = (@(Test-IgwtCatalog) -join "`n")
        $errors | Should -Match 'input.bad-hint: hint is 141 characters'
        $errors | Should -Match "input.bad-desc: missing 'description'"
        $errors | Should -Match 'input.bad-level: level must be Standard, Advanced, Expert or Lab'
        $errors | Should -Match 'input.bad-ac: antiCheat must be'
        $errors | Should -Match 'input.bad-breaks: an item that breaks anti-cheat must be level Lab'
        $errors | Should -Match 'input.bad-rev: reversible must be full, partial or none'
        $errors | Should -Match 'input.bad-partial: items that are not fully reversible must describe it in sideEffects'
        $errors | Should -Match "input.bad-winutil: WinUtil-derived items need an 'attribution'"
        $errors | Should -Match "input.bad-tag: unknown hardware tag 'gpu.voodoo'"
        $errors | Should -Match "input.bad-cond: unknown appliesTo condition 'moonPhase'"
        $errors | Should -Match "input.bad-legacy: v1 field 'antiCheatSafe' is not used in schema v2"
        $errors | Should -Match 'input.bad-expert: Expert and Lab items need a warning text'
    }
}

Describe 'v1 to v2 data migration' {
    BeforeAll {
        $script:V1 = New-V1DataCopy
        $script:RawV1 = @(Get-RawTweaks $script:V1)
        $script:Report = @(Convert-IgwtDataToV2 -DataFolder $script:V1)
        $script:RawV2 = @(Get-RawTweaks $script:V1)
    }
    AfterEach { Set-IgwtEnvironment -DataFolder '' }

    It 'converts every v1 tweak and preset file' {
        $script:Report.Count | Should -Be 10
        foreach ($r in $script:Report) { $r.FromSchema | Should -Be 1 -Because $r.File; $r.Changed | Should -BeTrue -Because $r.File }
        @($script:Report | Where-Object { $_.Kind -eq 'preset' }).Count | Should -Be 3
    }
    It 'is idempotent' {
        $again = @(Convert-IgwtDataToV2 -DataFolder $script:V1)
        @($again | Where-Object { $_.Changed }) | Should -BeNullOrEmpty
        foreach ($r in $again) { $r.FromSchema | Should -Be 2 }
    }
    It 'keeps every id and every action unchanged, so snapshot fingerprints stay valid' {
        $script:RawV2.Count | Should -Be $script:RawV1.Count
        foreach ($old in $script:RawV1) {
            $new = $script:RawV2 | Where-Object { $_.id -eq $old.id }
            $new | Should -Not -BeNullOrEmpty -Because $old.id
            ($new.actions | ConvertTo-Json -Depth 20 -Compress) | Should -Be ($old.actions | ConvertTo-Json -Depth 20 -Compress) -Because $old.id
            (Get-Fingerprints $new) | Should -Be (Get-Fingerprints $old) -Because $old.id
            foreach ($k in 'name', 'category', 'hint', 'description', 'risk', 'requires') { $new.$k | Should -Be $old.$k -Because "$($old.id).$k" }
        }
    }
    It 'maps the v1 fields to v2 fields' {
        foreach ($t in $script:RawV2) {
            $t.PSObject.Properties['antiCheatSafe'] | Should -BeNullOrEmpty
            $t.PSObject.Properties['expert'] | Should -BeNullOrEmpty
            $t.reversible | Should -Be 'full'
            $t.source | Should -Be 'igwt'
            $t.sideEffects | Should -Be ''
            @($t.hardware.tags).Count | Should -Be 0
            $t.appliesTo.minBuild | Should -Be 26100
        }
        $get = { param($id) $script:RawV2 | Where-Object { $_.id -eq $id } }
        $lab = & $get 'sec.vbs-hvci-off-expert'
        $lab.level | Should -Be 'Lab'
        @($lab.antiCheat.breaks) | Should -Be @('FACEIT', 'Riot Vanguard')
        (& $get 'sched.global-timer-resolution').level | Should -Be 'Expert'
        (& $get 'sched.global-timer-resolution').antiCheat | Should -Be 'safe'
        foreach ($t in $script:RawV2 | Where-Object { $_.level -eq 'Standard' }) { $t.evidence.tier | Should -Be 'A'; $t.risk | Should -Be 'low' }
        foreach ($t in $script:RawV1 | Where-Object { -not $_.expert -and $_.evidence.tier -eq 'B' }) { (& $get $t.id).level | Should -Be 'Advanced' -Because $t.id }
    }
    It 'moves appliesTo.hardware checks to appliesTo.conditions' {
        foreach ($old in $script:RawV1 | Where-Object { $_.appliesTo.hardware }) {
            $new = $script:RawV2 | Where-Object { $_.id -eq $old.id }
            foreach ($p in $old.appliesTo.hardware.PSObject.Properties) {
                $expected = $p.Name
                if ($expected -eq 'defender') { $expected = 'defenderActive' }
                @($new.appliesTo.conditions) | Should -Contain $expected -Because $old.id
            }
        }
        @(($script:RawV2 | Where-Object { $_.id -eq 'net.eee-off' }).appliesTo.conditions) | Should -Contain 'wiredAdapter'
    }
    It 'turns v1 presets into intent presets with the same members' {
        foreach ($name in 'competitive', 'balanced', 'hardened') {
            $old = Get-Content -LiteralPath (Join-Path $script:Fixture "data\presets\$name.json") -Raw | ConvertFrom-Json
            $new = Get-Content -LiteralPath (Join-Path $script:V1 "presets\$name.json") -Raw | ConvertFrom-Json
            $new.schemaVersion | Should -Be 2
            @($new.include) | Should -Be @($old.tweaks)
            @($new.exclude).Count | Should -Be 0
            $new.levelCeiling | Should -Be 'Advanced'
            $new.antiCheatPolicy | Should -Be 'safeOnly'
            $new.gaming | Should -BeTrue
            $new.hint.Length | Should -BeLessOrEqual 140
            $new.hint | Should -Not -BeNullOrEmpty
        }
    }
    It 'passes v2 validation after migration' {
        Set-IgwtEnvironment -DataFolder $script:V1
        # The kernel inspector data links to 2.0 catalog items, so a v1 folder ships without it.
        @(Test-IgwtCatalog | Where-Object { $_ -notlike 'inspectors\kernel.json: missing*' -and $_ -notlike 'manage\*.json: missing.' -and $_ -notlike 'rejected.json: * needs exactly one of riskItem or unavailable.' }) | Should -BeNullOrEmpty
        (Get-IgwtPreset -Name 'balanced').tweaks.Count | Should -Be 35
    }
    It 'still loads unmigrated v1 files by upgrading them in memory' {
        $raw = New-V1DataCopy
        Set-IgwtEnvironment -DataFolder $raw
        $cat = @(Get-IgwtCatalog -Force)
        $cat.Count | Should -Be 65
        $vbs = $cat | Where-Object { $_.id -eq 'sec.vbs-hvci-off-expert' }
        $vbs.level | Should -Be 'Lab'
        $vbs.expert | Should -BeTrue
        $vbs.antiCheatSafe | Should -BeFalse
        ($cat | Where-Object { $_.id -eq 'net.eee-off' }).appliesTo.conditions | Should -Contain 'wiredAdapter'
        (Get-IgwtPreset -Name 'competitive').tweaks.Count | Should -Be 44
        $errors = (@(Test-IgwtCatalog) -join "`n")
        $errors | Should -Match 'schemaVersion 1; run tools\\Convert-IgwtV1Data.ps1'
        $errors | Should -Not -Match 'hint is|antiCheat must be|level must be'
    }
    It 'applies renamed ids from the id map to presets' {
        $copy = New-V1DataCopy
        $map = Join-Path $copy 'migration\id-map.json'
        '{ "schemaVersion": 2, "renamed": { "gfx.game-mode": "gfx.game-mode-renamed" } }' | Set-Content -LiteralPath $map -Encoding ASCII
        $null = Convert-IgwtDataToV2 -DataFolder $copy
        $p = Get-Content -LiteralPath (Join-Path $copy 'presets\balanced.json') -Raw | ConvertFrom-Json
        @($p.include) | Should -Contain 'gfx.game-mode-renamed'
        @($p.include) | Should -Not -Contain 'gfx.game-mode'
    }
    It 'upgrades pre-v2 cleaner rules with conservative values' {
        $rules = InModuleScope iGWindowsTuner {
            @(
                ConvertTo-IgwtV2CleanerRule -Rule ([pscustomobject]@{ id = 'clean.a'; method = 'files'; roots = @('%TEMP%') })
                ConvertTo-IgwtV2CleanerRule -Rule ([pscustomobject]@{ id = 'clean.b'; method = 'files'; recycle = $true; sources = @('https://learn.microsoft.com/x') })
                ConvertTo-IgwtV2CleanerRule -Rule ([pscustomobject]@{ id = 'clean.c'; method = 'guidance' })
                ConvertTo-IgwtV2CleanerRule -Rule ([pscustomobject]@{ id = 'clean.d'; method = 'files'; reversible = 'none'; tier = 'A'; level = 'Expert' })
            )
        }
        $rules[0].tier | Should -Be 'B'; $rules[0].reversible | Should -Be 'none'; $rules[0].antiCheat | Should -Be 'safe'; $rules[0].level | Should -Be 'Standard'
        $rules[1].tier | Should -Be 'A'; $rules[1].reversible | Should -Be 'partial'
        $rules[2].reversible | Should -Be 'full'
        $rules[3].tier | Should -Be 'A'; $rules[3].level | Should -Be 'Expert'
        foreach ($r in $rules) { $r.source | Should -Be 'igwt'; @($r.hardware.tags).Count | Should -Be 0 }
    }
}

Describe 'Data file JSON writer' {
    It 'round-trips every migrated data file and keeps it ASCII' {
        foreach ($f in (Get-ChildItem -LiteralPath $script:RepoData -Recurse -Filter *.json | Where-Object { $_.Directory.Name -in 'tweaks', 'presets', 'cleaner', 'asr' })) {
            $text = [System.IO.File]::ReadAllText($f.FullName)
            $doc = $text | ConvertFrom-Json
            $again = InModuleScope iGWindowsTuner -Parameters @{ D = $doc } { param($D) ConvertTo-IgwtJson -InputObject $D }
            $again | Should -Be $text -Because $f.Name
            $text | Should -Not -Match '[^\x00-\x7F]' -Because $f.Name
            $text | Should -Not -Match '\\u003c' -Because "$($f.Name) keeps <absent> readable"
        }
    }
    It 'escapes quotes, backslashes, control and non-ASCII characters' {
        $value = [pscustomobject]@{ s = ('a"b\c' + "`n`t" + [char]0xE9 + [char]0x1F + '<absent>'); n = 42; d = 1.5; b = $false; z = $null; e = @(); o = [pscustomobject]@{} }
        $json = InModuleScope iGWindowsTuner -Parameters @{ V = $value } { param($V) ConvertTo-IgwtJson -InputObject $V }
        $json | Should -Match '\\u00e9'
        $json | Should -Match '<absent>'
        $back = $json | ConvertFrom-Json
        $back.s | Should -BeExactly $value.s
        $back.n | Should -Be 42
        $back.d | Should -Be 1.5
        $back.b | Should -BeFalse
        $back.z | Should -BeNullOrEmpty
        @($back.e).Count | Should -Be 0
    }
}

Describe 'v1 snapshots after migration' {
    BeforeAll {
        $script:SnapName = 'snapshot-20261017-010119-000-Apply-v1fix.json'
        $script:Backups = Get-IgwtDataPath -Kind Backups
        $null = New-Item -ItemType Directory -Path $script:Backups -Force
        $script:SnapPath = Join-Path $script:Backups $script:SnapName
        Copy-Item -LiteralPath (Join-Path $script:Fixture $script:SnapName) -Destination $script:SnapPath -Force
        $script:SnapHash = (Get-FileHash -LiteralPath $script:SnapPath -Algorithm SHA256).Hash
        $script:Ctx = New-IgwtTestContext

        function Write-TestValue([string]$Path, [string]$Name, [string]$Kind, $Value) {
            InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name; K = $Kind; V = $Value } { param($P, $N, $K, $V) Set-IgwtRegistryValue -Path $P -Name $N -Kind $K -Value $V }
        }
        function Get-TestValue([string]$Path, [string]$Name) {
            InModuleScope iGWindowsTuner -Parameters @{ P = $Path; N = $Name } { param($P, $N) Get-IgwtRegistryValue -Path $P -Name $N }
        }
        # The state right after the 1.0 apply that wrote the fixture snapshot.
        function Write-AfterApplyState {
            Write-TestValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Kind 'String' -Value '0'
            Write-TestValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Kind 'String' -Value '0'
            Write-TestValue -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Kind 'String' -Value '0'
            Write-TestValue -Path 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' -Name 'DirectXUserGlobalSettings' -Kind 'String' -Value 'VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;'
            Write-TestValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 1
            Write-TestValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Kind 'DWord' -Value 255
            Write-TestValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Kind 'DWord' -Value 1
        }
    }

    It 'reads the schema 1 file as schema 2 in memory and leaves the file unchanged' {
        $doc = InModuleScope iGWindowsTuner -Parameters @{ P = $script:SnapPath } { param($P) Read-IgwtSnapshot -Path $P }
        $doc.schema | Should -Be 2
        $doc.migratedFrom | Should -Be 1
        $doc.catalogSchema | Should -Be 1
        @($doc.entries).Count | Should -Be 4
        foreach ($e in $doc.entries) { $e.level | Should -Be 'Standard' -Because $e.tweakId }
        (Get-FileHash -LiteralPath $script:SnapPath -Algorithm SHA256).Hash | Should -Be $script:SnapHash
        $listed = @(Get-IgwtSnapshotList | Where-Object { $_.File -eq $script:SnapName })
        @($listed[0].Applied | Sort-Object) | Should -Be @('gfx.game-mode', 'gfx.windowed-optimizations', 'input.pointer-precision-off', 'sec.autorun-off')
    }
    It 'refuses snapshot schemas it does not know' {
        $bad = Join-Path $TestDrive 'snapshot-bad-schema.json'
        (Get-Content -LiteralPath $script:SnapPath -Raw).Replace('"schema":  1', '"schema":  3') | Set-Content -LiteralPath $bad -Encoding UTF8
        { InModuleScope iGWindowsTuner -Parameters @{ P = $bad } { param($P) Read-IgwtSnapshot -Path $P } } | Should -Throw '*unsupported format*'
    }
    It 'reverts one tweak from the v1 snapshot by id' {
        Write-AfterApplyState
        $r = Invoke-IgwtRevert -Id 'gfx.game-mode' -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Reverted').Id | Should -Be 'gfx.game-mode'
        $v = Get-TestValue 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled'
        $v.Kind | Should -Be 'DWord'; $v.Value | Should -Be 0
    }
    It 'reverts every entry of the v1 snapshot to the exact captured values' {
        Write-AfterApplyState
        $r = Invoke-IgwtRevert -SnapshotPath $script:SnapPath -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 4
        @($r.Results | Where-Object Result -EQ 'Failed') | Should -BeNullOrEmpty
        foreach ($m in @(@('MouseSpeed', '1'), @('MouseThreshold1', '6'), @('MouseThreshold2', '10'))) {
            $v = Get-TestValue 'HKCU:\Control Panel\Mouse' $m[0]
            $v.Kind | Should -Be 'String'; $v.Value | Should -Be $m[1]
        }
        (Get-TestValue 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;'
        (Get-TestValue 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled').Value | Should -Be 0
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun').Exists | Should -BeFalse
        (Get-TestValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun').Exists | Should -BeFalse
        $revert = Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json
        $revert.schema | Should -Be 2
        foreach ($e in $revert.entries) { $e.level | Should -Not -BeNullOrEmpty }
    }
    It 'writes schema 2 copies elsewhere that keep the captured data and revert the same way' {
        $out = Join-Path $TestDrive 'snapcopies'
        $copy = Convert-IgwtSnapshotToV2 -Path $script:SnapPath -Destination $out
        { Convert-IgwtSnapshotToV2 -Path $script:SnapPath -Destination $script:Backups } | Should -Throw '*Refusing to overwrite*'
        $old = Get-Content -LiteralPath $script:SnapPath -Raw | ConvertFrom-Json
        $new = Get-Content -LiteralPath $copy -Raw | ConvertFrom-Json
        $new.schema | Should -Be 2
        $new.migratedFrom | Should -Be 1
        foreach ($e in $old.entries) {
            $n = $new.entries | Where-Object { $_.tweakId -eq $e.tweakId }
            ($n.actions | ConvertTo-Json -Depth 20 -Compress) | Should -Be ($e.actions | ConvertTo-Json -Depth 20 -Compress) -Because $e.tweakId
        }
        Write-AfterApplyState
        $r = Invoke-IgwtRevert -SnapshotPath $copy -Context $script:Ctx
        @($r.Results | Where-Object Result -EQ 'Reverted').Count | Should -Be 4
        (Get-TestValue 'HKCU:\Control Panel\Mouse' 'MouseSpeed').Value | Should -Be '1'
    }
    It 'maps renamed ids when it upgrades a v1 snapshot' {
        $doc = Get-Content -LiteralPath $script:SnapPath -Raw | ConvertFrom-Json
        $up = InModuleScope iGWindowsTuner -Parameters @{ D = $doc } { param($D) ConvertTo-IgwtV2Snapshot -Document $D -Catalog @() -IdMap @{ 'gfx.game-mode' = 'gfx.game-mode-renamed' } }
        $e = $up.entries | Where-Object { $_.originalTweakId -eq 'gfx.game-mode' }
        $e.tweakId | Should -Be 'gfx.game-mode-renamed'
        $e.actions[0].fingerprint | Should -Be 'registry|path=HKCU:\Software\Microsoft\GameBar|name=AutoGameModeEnabled'
    }
}
