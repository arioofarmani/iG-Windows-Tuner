# Declarative presets, schema v3 (3.6, DECISIONS T9 and T16): converted presets, the equivalence
# with the v2 originals on every hardware fixture, strict checks of untrusted user presets, the
# preview classes, one session per preset, and the preview budget.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:FixtureDir = Join-Path $PSScriptRoot 'fixtures\hardware'
    $script:V2Dir = Join-Path $PSScriptRoot 'fixtures\presets-v2'
    function Get-FixtureTags([string]$Name) { @((Get-IgwtHardwareProfile -Facts (Get-Content -LiteralPath (Join-Path $script:FixtureDir "$Name.json") -Raw | ConvertFrom-Json)).Tags) }
    function Get-V3Errors($Document) {
        InModuleScope iGWindowsTuner -Parameters @{ D = $Document } {
            param($D)
            $errs = New-Object System.Collections.Generic.List[string]
            Test-IgwtPresetV3Document -Document $D -CatalogIndex (Get-IgwtPresetCatalogIndex) -Errors $errs
            $errs.ToArray()
        }
    }
    function Get-GoodDocument {
        [pscustomobject]@{ schemaVersion = 3; id = 'my-preset'; name = 'My preset'; version = '1.0.0'; description = 'A preset of mine for testing the strict checks of user presets.'
            requires = [pscustomobject]@{ minBuild = 26100 }; changes = @([pscustomobject]@{ item = 'gfx.game-mode'; desired = 'on' }, [pscustomobject]@{ item = 'sec.autorun-off'; desired = 'default' }); conflicts = @(); notes = '' }
    }
}

Describe 'Preset schema v3' {
    It 'stores every built-in preset as schema v3 with item ids and desired values only' {
        foreach ($f in Get-ChildItem (Join-Path $PSScriptRoot '..\data\presets') -Filter *.json) {
            $d = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
            $d.schemaVersion | Should -Be 3 -Because $f.Name
            $d.PSObject.Properties['include'] | Should -BeNullOrEmpty -Because $f.Name
            @(Get-V3Errors $d) -join "`n" | Should -BeNullOrEmpty -Because $f.Name
        }
    }
    It 'plans the same change set as the v2 original on every hardware fixture (<_>)' -ForEach @('amd-laptop', 'amd-x3d-dualccd-desktop', 'intel-arc-desktop', 'intel-laptop', 'intel-raptorlake-desktop', 'vm') {
        $tags = Get-FixtureTags $_
        foreach ($f in Get-ChildItem $script:V2Dir -Filter *.json) {
            $v2 = InModuleScope iGWindowsTuner -Parameters @{ P = $f.FullName } { param($P) ConvertTo-IgwtNormalizedPreset -Preset (Read-IgwtJsonFile -Path $P) -SourceFile 'v2' -SourceSchema 2 }
            $v3 = Get-IgwtPreset -Name ([string]$v2.id)
            $a = Resolve-IgwtPresetSelection -Preset $v2 -Tags $tags
            $b = Resolve-IgwtPresetSelection -Preset $v3 -Tags $tags
            @($b.Ids | Sort-Object) | Should -Be @($a.Ids | Sort-Object) -Because "$($f.Name) on $_"
            @($b.Blocked | Sort-Object) | Should -Be @($a.Blocked | Sort-Object) -Because "$($f.Name) on $_"
            @($v3.tweaks | Sort-Object) | Should -Be @($v2.tweaks | Sort-Object) -Because $f.Name
        }
    }
    It 'accepts a valid user preset' {
        @(Get-V3Errors (Get-GoodDocument)) -join "`n" | Should -BeNullOrEmpty
    }
    It 'rejects untrusted user presets with readable messages' {
        $cases = @(
            @{ Edit = { param($d) $d.changes[0].item = 'gfx.no-such-item' }; Expect = "*unknown item 'gfx.no-such-item'*" }
            @{ Edit = { param($d) $d.changes[0].desired = 'max' }; Expect = '*use on, default or unchanged*' }
            @{ Edit = { param($d) $d.changes[0] | Add-Member -NotePropertyName path -NotePropertyValue 'HKLM:\SOFTWARE\X' }; Expect = "*unknown field 'path'*" }
            @{ Edit = { param($d) $d | Add-Member -NotePropertyName script -NotePropertyValue 'x' }; Expect = "*unknown field 'script'*" }
            @{ Edit = { param($d) $d.changes = @($d.changes[0], $d.changes[0]) }; Expect = '*listed twice*' }
            @{ Edit = { param($d) $d.changes = @() }; Expect = '*at least one item*' }
            @{ Edit = { param($d) $d.requires = [pscustomobject]@{ minBuild = 'latest' } }; Expect = '*must be a Windows build number*' }
            @{ Edit = { param($d) $d.requires = [pscustomobject]@{ hardware = [pscustomobject]@{ tags = @('cpu.quantum') } } }; Expect = "*unknown hardware tag 'cpu.quantum'*" }
            @{ Edit = { param($d) $d.conflicts = @([pscustomobject]@{ feature = 'run C:\\tools\\x.ps1 first'; reason = 'x' }) }; Expect = '*path or command*' }
            @{ Edit = { param($d) $d.id = 'Bad Id!' }; Expect = '*id must be*' }
            @{ Edit = { param($d) $d.conflicts = @([pscustomobject]@{ item = 'gfx.hags' }) }; Expect = '*needs a reason*' }
        )
        foreach ($c in $cases) {
            $d = Get-GoodDocument
            & $c.Edit $d
            (@(Get-V3Errors $d) -join "`n") | Should -BeLike $c.Expect
        }
    }
    It 'imports a user v3 preset only after the strict check' {
        $p = Join-Path $TestDrive 'mine.json'
        $d = Get-GoodDocument; $d.changes = @([pscustomobject]@{ item = 'gfx.game-mode'; desired = 'on' }, [pscustomobject]@{ item = 'gfx.hags'; desired = 'unchanged' })
        ConvertTo-Json -InputObject $d -Depth 6 | Set-Content -LiteralPath $p -Encoding UTF8
        $r = Import-IgwtPreset -Path $p -Name 'Mine from v3' -Confirm:$false
        $r.id | Should -Be 'custom-mine-from-v3'
        @($r.tweaks) | Should -Be @('gfx.game-mode')
        @($r.exclude) | Should -Contain 'gfx.hags'
        $d.changes[0].item = 'gfx.no-such-item'
        ConvertTo-Json -InputObject $d -Depth 6 | Set-Content -LiteralPath $p -Encoding UTF8
        { Import-IgwtPreset -Path $p -Name 'Bad' -Confirm:$false } | Should -Throw "*unknown item 'gfx.no-such-item'*"
        Remove-IgwtCustomPreset -Name 'custom-mine-from-v3' -Confirm:$false
    }
}

Describe 'Preset preview and apply' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            Remove-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null
        }
    }
    It 'classifies each item and sums it up in one line' {
        InModuleScope iGWindowsTuner {
            $p = ConvertFrom-IgwtPresetV3 -Preset ([pscustomobject]@{ schemaVersion = 3; id = 'pv'; name = 'Preview'; levelCeiling = 'Expert'; antiCheatPolicy = 'any'
                    changes = @([pscustomobject]@{ item = 'gfx.game-mode'; desired = 'on' }, [pscustomobject]@{ item = 'sec.autorun-off'; desired = 'on' }) })
            Mock Get-IgwtTweakState -ParameterFilter { $Tweak.id -eq 'sec.autorun-off' } { [pscustomobject]@{ Id = 'sec.autorun-off'; State = 'On'; Items = @(); Reason = '' } }
            $pv = Get-IgwtPresetPreview -Preset $p -Tags @('formfactor.desktop')
            @($pv.Rows | Where-Object Id -EQ 'gfx.game-mode')[0].Class | Should -Be 'WillChange'
            @($pv.Rows | Where-Object Id -EQ 'sec.autorun-off')[0].Class | Should -Be 'AlreadySet'
            $pv.Summary | Should -Be '1 will change, 1 already set, 0 not applicable, 0 conflict(s), 0 managed by policy.'
        }
    }
    It 'shows managed-by-policy, not-applicable and conflicting items' {
        InModuleScope iGWindowsTuner {
            $p = ConvertFrom-IgwtPresetV3 -Preset ([pscustomobject]@{ schemaVersion = 3; id = 'pv'; name = 'Preview'; levelCeiling = 'Expert'; antiCheatPolicy = 'any'
                    changes = @([pscustomobject]@{ item = 'gfx.game-mode'; desired = 'on' }, [pscustomobject]@{ item = 'sec.autorun-off'; desired = 'on' }, [pscustomobject]@{ item = 'gfx.hags'; desired = 'on' })
                    conflicts = @([pscustomobject]@{ item = 'gfx.background-recording-off'; reason = 'Test conflict.' }) })
            Mock Get-IgwtTweakState -ParameterFilter { $Tweak.id -eq 'sec.autorun-off' } { [pscustomobject]@{ Id = 'sec.autorun-off'; State = 'ManagedByPolicy'; Items = @(); Reason = 'Set by a domain policy.' } }
            Mock Get-IgwtTweakState -ParameterFilter { $Tweak.id -eq 'gfx.hags' } { [pscustomobject]@{ Id = 'gfx.hags'; State = 'NotApplicable'; Items = @(); Reason = 'Needs a GPU that supports it.' } }
            Mock Get-IgwtTweakState -ParameterFilter { $Tweak.id -eq 'gfx.background-recording-off' } { [pscustomobject]@{ Id = 'gfx.background-recording-off'; State = 'On'; Items = @(); Reason = '' } }
            $pv = Get-IgwtPresetPreview -Preset $p -Tags @('formfactor.desktop')
            @($pv.Rows | Where-Object Id -EQ 'sec.autorun-off')[0].Class | Should -Be 'ManagedByPolicy'
            @($pv.Rows | Where-Object Id -EQ 'gfx.hags')[0].Class | Should -Be 'NotApplicable'
            @($pv.Rows | Where-Object Id -EQ 'gfx.background-recording-off')[0].Class | Should -Be 'Conflict'
            $pv.Summary | Should -BeLike '*1 conflict(s), 1 managed by policy.'
        }
    }
    It 'refuses nothing silently: a preset whose requirements are not met is not applicable as a whole' {
        InModuleScope iGWindowsTuner {
            $p = ConvertFrom-IgwtPresetV3 -Preset ([pscustomobject]@{ schemaVersion = 3; id = 'pv'; name = 'Preview'; requires = [pscustomobject]@{ minBuild = 99999 }; changes = @([pscustomobject]@{ item = 'gfx.game-mode'; desired = 'on' }) })
            $pv = Get-IgwtPresetPreview -Preset $p -Tags @()
            $pv.Requirement | Should -BeLike 'Needs Windows build 99999 or later*'
            @($pv.Rows)[0].Class | Should -Be 'NotApplicable'
        }
    }
    It 'applies a preset with on and default changes as one journaled session' {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Kind 'DWord' -Value 255
            $r = Invoke-IgwtApply -Id @('gfx.game-mode') -ResetId @('sec.autorun-off') -Operation 'Preset:pv' -Context (New-IgwtContext)
            @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 2
            (Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun').Exists | Should -BeFalse -Because 'the Windows default is absent'
            $script:IgwtJournal = $null
            $j = Read-IgwtJournal
            @($j.Entries | Where-Object { $_['kind'] -eq 'sessionStart' }).Count | Should -Be 1
            @($j.Entries | Where-Object { $_['kind'] -eq 'intent' -and $_['item'] -eq 'sec.autorun-off' })[0]['desired'] | Should -Be 'default'
        }
    }
    It 'previews a 100-change preset in under 500 ms' {
        InModuleScope iGWindowsTuner {
            $ids = @(Get-IgwtCatalog | Where-Object { $_.level -ne 'Lab' -and [string]$_.evidence.tier -ne 'R' } | Select-Object -First 100 | ForEach-Object { [string]$_.id })
            $p = ConvertFrom-IgwtPresetV3 -Preset ([pscustomobject]@{ schemaVersion = 3; id = 'big'; name = 'Big'; levelCeiling = 'Expert'; antiCheatPolicy = 'any'; changes = @($ids | ForEach-Object { [pscustomobject]@{ item = $_; desired = 'on' } }) })
            # The budget is the preview over states already read (as in the GUI); detection is the engine's.
            $st = @{}; foreach ($i in @(Get-IgwtCatalog | ForEach-Object { [string]$_.id })) { $st[$i] = [pscustomobject]@{ Id = $i; State = 'Off'; Items = @(); Reason = '' } }
            $ctx = New-IgwtContext
            $null = Get-IgwtPresetPreview -Preset $p -Tags @('formfactor.desktop') -Context $ctx -States $st
            $best = [double]::MaxValue
            foreach ($i in 1..3) { $sw = [Diagnostics.Stopwatch]::StartNew(); $pv = Get-IgwtPresetPreview -Preset $p -Tags @('formfactor.desktop') -Context $ctx -States $st; $best = [Math]::Min([double]$best, [double]$sw.Elapsed.TotalMilliseconds) }
            @($pv.Rows).Count | Should -BeGreaterOrEqual 90
            Write-Information -InformationAction Continue -MessageData ("    preset preview: {0} items in {1:N0} ms" -f @($pv.Rows).Count, $best)
            $best | Should -BeLessThan 500
        }
    }
}
