# Hardware profile engine tests. Facts come from tests\fixtures\hardware (this PC is the primary
# fixture, captured read-only with -Hardware -Json); no detection runs against the real machine.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:FixtureDir = Join-Path $PSScriptRoot 'fixtures\hardware'
    function Get-Fixture([string]$Name) { Get-Content -LiteralPath (Join-Path $script:FixtureDir "$Name.json") -Raw | ConvertFrom-Json }
    function Get-FixtureTags([string]$Name) { @((Get-IgwtHardwareProfile -Facts (Get-Fixture $Name)).Tags) }
    function Get-TestPreset([string[]]$Include, [string[]]$Exclude = @(), [string]$Ceiling = 'Advanced') {
        [pscustomobject]@{ id = 'test'; name = 'Test'; include = $Include; exclude = $Exclude; levelCeiling = $Ceiling; antiCheatPolicy = 'safeOnly'; gaming = $true; tweaks = $Include }
    }
}

Describe 'Hardware fixtures' {
    It 'provides the six fixtures from the spec' {
        $names = @(Get-ChildItem -LiteralPath $script:FixtureDir -Filter *.json | ForEach-Object { $_.BaseName } | Sort-Object)
        $names | Should -Be @('amd-laptop', 'amd-x3d-dualccd-desktop', 'intel-arc-desktop', 'intel-laptop', 'intel-raptorlake-desktop', 'vm')
    }
    It 'keeps fixtures free of serial numbers and other identifiers (<_>)' -ForEach @('amd-laptop', 'amd-x3d-dualccd-desktop', 'intel-arc-desktop', 'intel-laptop', 'intel-raptorlake-desktop', 'vm') {
        $f = Get-Fixture $_
        $f.schemaVersion | Should -Be 2
        @($f.PSObject.Properties.Name | Sort-Object) | Should -Be @('battery', 'cpu', 'gpus', 'memoryGB', 'modernStandby', 'name', 'nics', 'os', 'portableChassis', 'schemaVersion', 'system', 'systemDisk')
        foreach ($n in @($f.gpus) + @($f.nics)) { [string]$n.pnp | Should -Match '^(VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4})?$' }
    }
}

Describe 'Hardware tag detection' {
    It 'detects <Name>' -ForEach @(
        @{ Name = 'intel-raptorlake-desktop'; Tags = @('formfactor.desktop', 'gpu.nvidia', 'intel.hybrid', 'intel.raptorlake.desktop', 'nic.marvell', 'ram.32', 'storage.nvme') }
        @{ Name = 'amd-x3d-dualccd-desktop'; Tags = @('amd.x3d.dualccd', 'amd.zen', 'formfactor.desktop', 'gpu.amd', 'nic.realtek', 'ram.64plus', 'storage.nvme') }
        @{ Name = 'intel-laptop'; Tags = @('formfactor.laptop', 'gpu.intel', 'gpu.nvidia', 'intel.hybrid', 'nic.realtek', 'power.modernstandby', 'ram.16', 'storage.nvme') }
        @{ Name = 'amd-laptop'; Tags = @('amd.zen', 'formfactor.laptop', 'gpu.amd', 'nic.killer', 'power.modernstandby', 'ram.lt16', 'storage.nvme') }
        @{ Name = 'intel-arc-desktop'; Tags = @('formfactor.desktop', 'gpu.intel', 'gpu.intel.arc', 'nic.intel.i226', 'ram.16', 'storage.hdd') }
        @{ Name = 'vm'; Tags = @('ram.lt16', 'vm') }
    ) {
        Get-FixtureTags $Name | Should -Be $Tags
    }
    It 'explains every tag with the rule that produced it' {
        $hp = Get-IgwtHardwareProfile -Facts (Get-Fixture 'intel-raptorlake-desktop')
        foreach ($d in $hp.TagDetails) { $d.Basis | Should -Not -BeNullOrEmpty -Because $d.Id; $d.Name | Should -Not -Be $d.Id -Because $d.Id }
    }
    It 'does not mark mobile Raptor Lake chips as affected desktop parts' {
        $f = Get-Fixture 'intel-raptorlake-desktop'
        $f.cpu.name = '13th Gen Intel(R) Core(TM) i9-13980HX'
        (Get-IgwtHardwareProfile -Facts $f).Tags | Should -Not -Contain 'intel.raptorlake.desktop'
    }
    It 'needs E-cores for intel.hybrid (12th gen without E-cores is not hybrid)' {
        (Get-FixtureTags 'intel-arc-desktop') | Should -Not -Contain 'intel.hybrid'
    }
    It 'does not treat integrated Arc Graphics as an Arc discrete card' {
        $f = Get-Fixture 'intel-arc-desktop'
        $f.gpus[0].name = 'Intel(R) Arc(TM) Graphics'
        $tags = (Get-IgwtHardwareProfile -Facts $f).Tags
        $tags | Should -Contain 'gpu.intel'
        $tags | Should -Not -Contain 'gpu.intel.arc'
    }
    It 'ignores disabled GPUs and keeps CPU-derived tags out of virtual machines' {
        (Get-FixtureTags 'amd-x3d-dualccd-desktop') | Should -Not -Contain 'gpu.intel'
        $vm = Get-FixtureTags 'vm'
        $vm | Should -Not -Contain 'intel.hybrid'
        $vm | Should -Not -Contain 'intel.raptorlake.desktop'
        $vm | Should -Not -Contain 'formfactor.desktop'
    }
    It 'detects a Hyper-V guest by manufacturer and model, not by HypervisorPresent' {
        $f = Get-Fixture 'intel-raptorlake-desktop'
        (Get-IgwtHardwareProfile -Facts $f).Derived.Vm | Should -BeFalse
        $f.system.model = 'VMware20,1'
        (Get-IgwtHardwareProfile -Facts $f).Derived.Vm | Should -BeTrue
    }
    It 'reads Modern Standby from powercfg /a' {
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPowerCfg { [pscustomobject]@{ ExitCode = 0; Output = "The following sleep states are available on this system:`r`n    Standby (S3)`r`n    Hibernate`r`n`r`nThe following sleep states are not available on this system:`r`n    Standby (S0 Low Power Idle)`r`n        The system firmware does not support this standby state.`r`n" } }
        InModuleScope iGWindowsTuner { Test-IgwtModernStandby } | Should -BeFalse
        Mock -ModuleName iGWindowsTuner Invoke-IgwtPowerCfg { [pscustomobject]@{ ExitCode = 0; Output = "The following sleep states are available on this system:`r`n    Standby (S0 Low Power Idle) Network Connected`r`n    Hibernate`r`n`r`nThe following sleep states are not available on this system:`r`n    Standby (S3)`r`n" } }
        InModuleScope iGWindowsTuner { Test-IgwtModernStandby } | Should -BeTrue
    }
    It 'strips instance data from PCI ids' {
        InModuleScope iGWindowsTuner { ConvertTo-IgwtPciId 'PCI\VEN_10DE&DEV_2216&SUBSYS_404B1458&REV_A1\4&8BD6E8D&0&0008' } | Should -Be 'VEN_10DE&DEV_2216'
        InModuleScope iGWindowsTuner { ConvertTo-IgwtPciId 'VMBUS\{f8615163}' } | Should -Be ''
    }
}

Describe 'Hardware overlays: presets per fixture' {
    It 'changes nothing harmful on this PC and confirms Power Throttling' {
        $tags = Get-FixtureTags 'intel-raptorlake-desktop'
        foreach ($p in @(Get-IgwtPreset)) {
            $s = Resolve-IgwtPresetSelection -Preset $p -Tags $tags
            @($s.Blocked) | Should -BeNullOrEmpty -Because $p.id
            @($s.Ids) | Should -Be @($p.tweaks) -Because $p.id
            @($s.Items | Where-Object { $_.Id -eq 'power.power-throttling-on' }).Notes | Should -Match 'Intel hybrid CPU'
            @($s.Overlays.Id) | Should -Contain 'overlay.raptorlake-voltage'
        }
    }
    It 'blocks High and Ultimate Performance plans on an X3D dual-CCD desktop' {
        $tags = Get-FixtureTags 'amd-x3d-dualccd-desktop'
        $c = Resolve-IgwtPresetSelection -Preset 'competitive' -Tags $tags
        $c.Blocked | Should -Contain 'power.ultimate-plan'
        $c.Ids | Should -Not -Contain 'power.ultimate-plan'
        ($c.Items | Where-Object { $_.Id -eq 'power.ultimate-plan' }).Notes[0] | Should -Match 'AMD X3D dual-CCD'
        (Resolve-IgwtPresetSelection -Preset 'balanced' -Tags $tags).Blocked | Should -Contain 'power.high-performance-plan'
        ($c.Items | Where-Object { $_.Id -eq 'gfx.game-mode' }).Notes | Should -Match 'Also required by'
        @($c.Guidance) -join ' ' | Should -Match '3D V-Cache Performance Optimizer'
    }
    It 'blocks plan switches on laptops and Modern Standby PCs' -ForEach @('intel-laptop', 'amd-laptop') {
        $tags = Get-FixtureTags $_
        foreach ($p in @(Get-IgwtPreset)) {
            $s = Resolve-IgwtPresetSelection -Preset $p -Tags $tags
            $s.Ids | Should -Not -Contain 'power.high-performance-plan' -Because $p.id
            $s.Ids | Should -Not -Contain 'power.ultimate-plan' -Because $p.id
        }
    }
    It 'keeps SysMain on with a hard disk or less than 16 GB, even as your add-on' -ForEach @('intel-arc-desktop', 'amd-laptop', 'vm') {
        $tags = Get-FixtureTags $_
        $s = Resolve-IgwtPresetSelection -Preset 'balanced' -Tags $tags -AddIds @('privacy.sysmain-off')
        $it = $s.Items | Where-Object { $_.Id -eq 'privacy.sysmain-off' }
        $it.Included | Should -BeFalse
        $it.Blocked | Should -BeTrue
        $it.Notes -join ' ' | Should -Match 'keep SysMain'
        (Resolve-IgwtPresetSelection -Preset 'balanced' -Tags (Get-FixtureTags 'intel-raptorlake-desktop') -AddIds @('privacy.sysmain-off')).Ids | Should -Contain 'privacy.sysmain-off'
    }
    It 'adds Intel''s EEE mitigation for I226 controllers' {
        $tags = Get-FixtureTags 'intel-arc-desktop'
        $s = Resolve-IgwtPresetSelection -Preset (Get-TestPreset -Include @('gfx.game-mode')) -Tags $tags
        $it = $s.Items | Where-Object { $_.Id -eq 'net.eee-off' }
        $it.Origin | Should -Be 'overlay'
        $it.Included | Should -BeTrue
        $it.Notes[0] | Should -Match 'Intel I226'
        @($s.Guidance) -join ' ' | Should -Match 'Resizable BAR'
    }
    It 'blocks hardware-level items in a virtual machine but keeps TCP/IP settings' {
        $tags = Get-FixtureTags 'vm'
        $s = Resolve-IgwtPresetSelection -Preset 'hardened' -Tags $tags
        foreach ($id in 'power.usb-selective-suspend-off', 'power.pcie-aspm-off', 'net.eee-off', 'net.rss-on', 'net.wifi-disable') { $s.Blocked | Should -Contain $id }
        $s.Ids | Should -Contain 'sec.netbios-off'
        $s.Ids | Should -Contain 'privacy.diagnostic-data-required'
    }
}

Describe 'Preset resolution order' {
    BeforeAll {
        $script:Tags = Get-FixtureTags 'intel-arc-desktop'
    }
    It 'lets a preset exclude an item an overlay would add' {
        $s = Resolve-IgwtPresetSelection -Preset (Get-TestPreset -Include @('gfx.game-mode') -Exclude @('net.eee-off')) -Tags $script:Tags
        $it = $s.Items | Where-Object { $_.Id -eq 'net.eee-off' }
        $it.Included | Should -BeFalse
        $it.Notes[0] | Should -Match 'excluded by the preset'
    }
    It 'never lets an overlay add items above the level ceiling, Lab items or non-safe items' {
        $fake = @([pscustomobject]@{ id = 'overlay.test'; name = 'Test overlay'; tags = @('vm'); hint = 'test'; add = @('power.hibernation-off', 'sec.vbs-hvci-off-expert', 'gfx.game-mode'); block = @(); blockMatching = @(); guidance = @() })
        Mock -ModuleName iGWindowsTuner Get-IgwtHardwareOverlays { $fake }
        $s = Resolve-IgwtPresetSelection -Preset (Get-TestPreset -Include @('sec.autorun-off') -Ceiling 'Standard') -Tags @('vm')
        ($s.Items | Where-Object { $_.Id -eq 'power.hibernation-off' }).Included | Should -BeFalse
        ($s.Items | Where-Object { $_.Id -eq 'power.hibernation-off' }).Notes[0] | Should -Match 'level ceiling'
        ($s.Items | Where-Object { $_.Id -eq 'sec.vbs-hvci-off-expert' }).Included | Should -BeFalse
        ($s.Items | Where-Object { $_.Id -eq 'gfx.game-mode' }).Included | Should -BeTrue
        ($s.Items | Where-Object { $_.Id -eq 'gfx.game-mode' }).Origin | Should -Be 'overlay'
    }
    It 'applies your add-ons and removals last, but never past a hardware block' {
        $s = Resolve-IgwtPresetSelection -Preset (Get-TestPreset -Include @('gfx.game-mode', 'sec.autorun-off')) -Tags (Get-FixtureTags 'vm') -AddIds @('privacy.ads-suggestions-off', 'net.eee-off') -RemoveIds @('sec.autorun-off')
        $s.Ids | Should -Contain 'privacy.ads-suggestions-off'
        ($s.Items | Where-Object { $_.Id -eq 'privacy.ads-suggestions-off' }).Origin | Should -Be 'user'
        $s.Ids | Should -Not -Contain 'sec.autorun-off'
        $s.Ids | Should -Not -Contain 'net.eee-off'
        $s.Blocked | Should -Contain 'net.eee-off'
    }
}

Describe 'Hardware blocks in state detection and apply' {
    BeforeAll {
        $script:Tweak = New-IgwtTestTweak -Id 'test.hwblock' -Actions @(@{ type = 'registry'; path = 'HKCU:\Software\IgwtTest\HwBlock'; name = 'V'; valueType = 'DWord'; on = 1; default = '<absent>' })
        $fake = @([pscustomobject]@{ id = 'overlay.test-block'; name = 'Test block'; tags = @('vm'); hint = 'Test hint.'; add = @(); block = @('test.hwblock'); blockMatching = @(); guidance = @() })
        Mock -ModuleName iGWindowsTuner Get-IgwtHardwareOverlays { $fake }
        Mock -ModuleName iGWindowsTuner Get-IgwtTweak { $script:Tweak } -ParameterFilter { @($Id) -contains 'test.hwblock' }
        $script:VmCtx = New-IgwtTestContext -Extra @{ HardwareTags = @('vm') }
        $script:PcCtx = New-IgwtTestContext -Extra @{ HardwareTags = @('formfactor.desktop') }
        function Get-Value { InModuleScope iGWindowsTuner { Get-IgwtRegistryValue -Path 'HKCU:\Software\IgwtTest\HwBlock' -Name 'V' } }
    }
    It 'reports a blocked item as Not applicable with the overlay reason' {
        $s = Get-IgwtTweakState -Tweak $script:Tweak -Context $script:VmCtx
        $s.State | Should -Be 'NotApplicable'
        $s.Blocked | Should -BeTrue
        $s.Reason | Should -Match "Blocked on this hardware by 'Test block' \(vm\): Test hint"
        (Get-IgwtTweakState -Tweak $script:Tweak -Context $script:PcCtx).State | Should -Be 'Off'
    }
    It 'refuses to apply a blocked item' {
        $r = Invoke-IgwtApply -Id 'test.hwblock' -Context $script:VmCtx
        $r.Results[0].Result | Should -Be 'NotApplicable'
        (Get-Value).Exists | Should -BeFalse
    }
    It 'still shows an already-applied blocked item as On so it can be turned off' {
        InModuleScope iGWindowsTuner { Set-IgwtRegistryValue -Path 'HKCU:\Software\IgwtTest\HwBlock' -Name 'V' -Kind DWord -Value 1 }
        $s = Get-IgwtTweakState -Tweak $script:Tweak -Context $script:VmCtx
        $s.State | Should -Be 'On'
        $s.Blocked | Should -BeTrue
        $s.Reason | Should -Match 'turning it off is recommended'
        $r = Invoke-IgwtApply -Id 'test.hwblock' -Mode default -Operation ResetDefault -Context $script:VmCtx
        $r.Results[0].Result | Should -Be 'Applied'
        (Get-Value).Exists | Should -BeFalse
    }
    It 'requires the hardware tags an item declares' {
        $t = New-IgwtTestTweak -Id 'test.needsnvidia' -Actions @(@{ type = 'registry'; path = 'HKCU:\Software\IgwtTest\Nv'; name = 'V'; valueType = 'DWord'; on = 1; default = '<absent>' })
        $t.hardware.tags = @('gpu.nvidia')
        (Get-IgwtTweakState -Tweak $t -Context $script:PcCtx).Reason | Should -Match 'Needs hardware tag\(s\) gpu.nvidia'
        $t.hardware.tags = @(); $t.hardware.excludeTags = @('formfactor.desktop')
        (Get-IgwtTweakState -Tweak $t -Context $script:PcCtx).State | Should -Be 'NotApplicable'
    }
}

Describe 'Hardware knowledge base validation' {
    It 'validates without errors' { @(Test-IgwtHardwareCatalog) | Should -BeNullOrEmpty }
    It 'gives every overlay https sources, a basis and at least one effect' {
        foreach ($o in @(Get-IgwtHardwareOverlays -Force)) {
            @($o.sources).Count | Should -BeGreaterThan 0 -Because $o.id
            foreach ($s in $o.sources) { $s | Should -Match '^https://' }
            $o.basis | Should -BeIn @('vendor', 'reviewer', 'igwt')
        }
    }
    It 'reports broken overlays and detection rules' {
        $badOverlays = @(
            [pscustomobject]@{ id = 'bad id'; name = 'x'; tags = @('gpu.voodoo'); hint = ('x' * 141); description = 'short'; basis = 'rumour'; sources = @('http://example.com'); block = @('no.such-item'); add = @('no.such-item'); blockMatching = @([pscustomobject]@{ colour = 'red' }) }
            [pscustomobject]@{ id = 'overlay.empty'; name = 'Empty'; tags = @('vm'); hint = 'Does nothing.'; description = 'An overlay without any effect, which the validator must reject.'; basis = 'igwt'; sources = @('https://learn.microsoft.com/') }
        )
        $badRules = @([pscustomobject]@{ tag = 'gpu.voodoo'; when = [pscustomobject]@{ moonPhase = 'full'; cpuName = '(' } })
        Mock -ModuleName iGWindowsTuner Get-IgwtHardwareOverlays { $badOverlays }
        Mock -ModuleName iGWindowsTuner Get-IgwtDetectionRules { $badRules }
        $errors = (@(Test-IgwtHardwareCatalog) -join "`n")
        $errors | Should -Match "overlay 'bad id': id must look like 'overlay.name'"
        $errors | Should -Match "unknown tag 'gpu.voodoo'"
        $errors | Should -Match 'hint is 141 characters'
        $errors | Should -Match 'basis must be vendor, reviewer or igwt'
        $errors | Should -Match "source 'http://example.com' must be https"
        $errors | Should -Match "unknown item 'no.such-item'"
        $errors | Should -Match "'no.such-item' is both added and blocked"
        $errors | Should -Match "every blockMatching entry needs 'type'"
        $errors | Should -Match "unknown blockMatching field 'colour'"
        $errors | Should -Match "overlay 'overlay.empty': needs block, blockMatching, add or guidance"
        $errors | Should -Match "detection rule for 'gpu.voodoo': unknown tag"
        $errors | Should -Match "unknown condition 'moonPhase'"
        $errors | Should -Match "invalid regex in 'cpuName'"
        $errors | Should -Match "hardware tag 'vm': no detection rule"
    }
}
