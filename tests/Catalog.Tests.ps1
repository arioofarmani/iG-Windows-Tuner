BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Catalog = @(Get-IgwtCatalog -Force)
    $script:Presets = @(Get-IgwtPreset)
    $script:Rejected = @(Get-IgwtRejectedTweaks)
}

Describe 'Tweak catalog' {
    It 'validates without errors (Test-IgwtCatalog)' {
        $errors = Test-IgwtCatalog
        $errors | Should -BeNullOrEmpty
    }

    It 'has unique ids' {
        $dupes = $script:Catalog | Group-Object id | Where-Object Count -GT 1
        $dupes | Should -BeNullOrEmpty
    }

    It 'has every required field on every tweak' {
        foreach ($t in $script:Catalog) {
            foreach ($f in 'id', 'name', 'category', 'hint', 'description', 'risk', 'requires') { [string]$t.$f | Should -Not -BeNullOrEmpty -Because "$($t.id).$f" }
            $t.evidence | Should -Not -BeNullOrEmpty -Because $t.id
            $t.impact | Should -Not -BeNullOrEmpty -Because $t.id
            @($t.actions).Count | Should -BeGreaterThan 0 -Because $t.id
        }
    }

    It 'keeps every hint at 140 characters or less' {
        foreach ($t in $script:Catalog) { ([string]$t.hint).Length | Should -BeLessOrEqual 140 -Because $t.id }
    }

    It 'gives every tweak (Tier A, B and Risk Zone R) at least one https source' {
        foreach ($t in $script:Catalog) {
            $t.evidence.tier | Should -BeIn @('A', 'B', 'R') -Because $t.id
            @($t.evidence.sources).Count | Should -BeGreaterThan 0 -Because $t.id
            foreach ($s in $t.evidence.sources) { $s | Should -Match '^https://' -Because $t.id }
        }
    }

    It 'tells the user to measure for every Tier B tweak' {
        foreach ($t in ($script:Catalog | Where-Object { $_.evidence.tier -eq 'B' })) {
            ([string]$t.hint + ' ' + [string]$t.description) | Should -Match '(?i)measure' -Because $t.id
        }
    }

    It 'has a revert path for every action' {
        $handlers = InModuleScope iGWindowsTuner { $script:IgwtCustomHandlers }
        foreach ($t in $script:Catalog) {
            foreach ($a in $t.actions) {
                switch ($a.type) {
                    { $_ -in 'registry', 'adapterRegistry' } { $a.PSObject.Properties['default'] | Should -Not -BeNullOrEmpty -Because "$($t.id) needs a Windows default" }
                    'registryListMerge' { $a.PSObject.Properties['default'] | Should -Not -BeNullOrEmpty -Because $t.id }
                    'service' { $a.default | Should -Not -BeNullOrEmpty -Because $t.id }
                    'mpPreference' { $a.PSObject.Properties['default'] | Should -Not -BeNullOrEmpty -Because $t.id }
                    'custom' { $handlers[$a.handler].Restore | Should -Not -BeNullOrEmpty -Because $t.id }
                }
            }
        }
    }

    It 'never lists an anti-cheat-unsafe tweak unless it is an expert toggle with a warning' {
        foreach ($t in ($script:Catalog | Where-Object { -not $_.antiCheatSafe -and $_.evidence.tier -ne 'R' })) {
            $t.expert | Should -BeTrue -Because $t.id
            $t.warning | Should -Match 'FACEIT' -Because "$($t.id) must name FACEIT"
            $t.warning | Should -Match 'Vanguard' -Because "$($t.id) must name Vanguard"
        }
    }

    It 'contains the warned VBS/HVCI expert toggle and no other security-reducing tweak' {
        $minus = @($script:Catalog | Where-Object { $_.impact.security -eq '-' -and $_.evidence.tier -ne 'R' } | ForEach-Object { $_.id })   # Risk Zone: tests\RiskZone.Tests.ps1
        $minus | Should -Be @('sec.vbs-hvci-off-expert')
    }

    It 'uses the verified ASR rule GUIDs only' {
        $verified = @('56a863a9-875e-4185-98a7-b882c64b5ce5', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
            'd3e037e1-3eb8-44c8-a917-57927947596d', '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'e6db77e5-3df2-4cf1-b95a-636979351e5b',
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', '3b576869-a4ec-4529-8536-b80a7769e899',
            '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', '33ddedf1-c6e0-47cb-833e-de6133960387')
        foreach ($a in ($script:Catalog.actions | Where-Object { $_.type -eq 'asrRule' })) { $a.id | Should -BeIn $verified }
    }

    It 'never targets anti-cheat or core security services' {
        $protected = InModuleScope iGWindowsTuner { $script:IgwtProtectedServices }
        foreach ($a in ($script:Catalog.actions | Where-Object { $_.type -eq 'service' })) { $a.name | Should -Not -BeIn $protected }
        $text = (Get-ChildItem (Join-Path $script:IgwtProjectRoot 'data\tweaks') -Filter *.json | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        foreach ($svc in 'vgc', 'vgk', 'EasyAntiCheat', 'BEService', 'FACEIT') { $text | Should -Not -Match ('"name"\s*:\s*"' + $svc + '"') }
    }

    It 'never writes to BCD, Secure Boot, TPM or DEP settings' {
        $text = (Get-ChildItem (Join-Path $script:IgwtProjectRoot 'data\tweaks') -Filter *.json | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        $text | Should -Not -Match '(?i)bcdedit'
        $text | Should -Not -Match '(?i)Control\\\\SecureBoot'
        $text | Should -Not -Match '(?i)FeatureSettingsOverride'
    }
}

Describe 'Presets' {
    It 'defines the ten v2 presets in order' {
        $script:Presets.id | Should -Be @('competitive', 'balanced', 'hardened', 'streamer', 'engineer', 'laptop', 'privacy-max', 'debloat', 'fortress', 'session')
    }

    It 'references only existing tweak ids' {
        $ids = $script:Catalog.id
        foreach ($p in $script:Presets) { foreach ($m in $p.tweaks) { $m | Should -BeIn $ids -Because "preset $($p.id)" } }
    }

    It 'contains no rejected item, no expert toggle and no conflicting pair' {
        $rejectedIds = $script:Rejected.id
        foreach ($p in $script:Presets) {
            foreach ($m in $p.tweaks) {
                $m | Should -Not -BeIn $rejectedIds
                $t = $script:Catalog | Where-Object id -EQ $m
                $t.expert | Should -BeFalse -Because "$m in $($p.id)"
                foreach ($c in $t.conflictsWith) { $c | Should -Not -BeIn $p.tweaks -Because "$m conflicts with $c in $($p.id)" }
            }
        }
    }

    It 'keeps Balanced Tier A only' {
        $b = $script:Presets | Where-Object id -EQ 'balanced'
        foreach ($m in $b.tweaks) { ($script:Catalog | Where-Object id -EQ $m).evidence.tier | Should -Be 'A' -Because $m }
    }

    It 'keeps the security baseline in Competitive' {
        $c = ($script:Presets | Where-Object id -EQ 'competitive').tweaks
        foreach ($m in 'sec.hvci-on', 'sec.lsa-protection', 'sec.asr-baseline', 'sec.defender-hardening', 'sec.firewall-on') { $m | Should -BeIn $c }
    }

    It 'makes Hardened a superset of Balanced (Office ASR Block replaces Audit)' {
        $b = ($script:Presets | Where-Object id -EQ 'balanced').tweaks
        $h = ($script:Presets | Where-Object id -EQ 'hardened').tweaks
        foreach ($m in $b) { if ($m -eq 'sec.asr-office-audit') { 'sec.asr-office-block' | Should -BeIn $h } else { $m | Should -BeIn $h } }
    }
}

Describe 'Rejected list' {
    It 'documents a reason for every entry and implements none of them' {
        $ids = $script:Catalog.id
        foreach ($r in $script:Rejected) {
            $r.reason | Should -Not -BeNullOrEmpty
            $r.id | Should -Not -BeIn $ids
        }
    }

    It 'covers the rejected items required by the specification' {
        $all = ($script:Rejected | ForEach-Object { "$($_.id) $($_.name)" }) -join "`n"
        foreach ($needle in 'bcdedit', 'HPET', 'Spectre', 'Win32PrioritySeparation', 'page file', 'LargeSystemCache', 'DisablePagingExecutive', 'Fullscreen Optimizations',
            'MouseDataQueueSize', 'IRQ', 'SvcHostSplitThreshold', 'Power Throttling off', 'E-core', 'TcpWindowSize', 'auto-tuning disabled', 'Mandatory ASLR',
            'exclusions', 'Windows Update', 'ViVeTool', 'DISM', 'Standby-list',
            'Hypervisor launch type', 'idle disable', 'Test signing', 'nointegritychecks', 'kernel debugging', 'Image File Execution Options', 'Registry cleaners',
            'hosts file', 'Prefetch', 'WinSxS', 'Installer', 'IPv6', 'Pinning device interrupts') {
            $all | Should -Match ([regex]::Escape($needle)) -Because "rejected list should mention $needle"
        }
    }
}
