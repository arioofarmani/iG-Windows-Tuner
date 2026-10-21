BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Semicolon list parsing' {
    It 'adds an item without touching unrelated items' {
        InModuleScope iGWindowsTuner { Set-IgwtListItem -Text 'VRROptimizeEnable=1;' -Key 'SwapEffectUpgradeEnable' -Value '1' | Should -Be 'VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;' }
    }
    It 'replaces an existing item in place (case-insensitive key)' {
        InModuleScope iGWindowsTuner { Set-IgwtListItem -Text 'A=1;swapeffectupgradeenable=0;B=2;' -Key 'SwapEffectUpgradeEnable' -Value '1' | Should -Be 'A=1;swapeffectupgradeenable=1;B=2;' }
    }
    It 'removes only the requested item' {
        InModuleScope iGWindowsTuner { Remove-IgwtListItem -Text 'A=1;VRROptimizeEnable=1;B=2;' -Key 'VRROptimizeEnable' | Should -Be 'A=1;B=2;' }
    }
    It 'preserves raw items without an equals sign' {
        InModuleScope iGWindowsTuner { Set-IgwtListItem -Text 'Legacy;A=1;' -Key 'B' -Value '2' | Should -Be 'Legacy;A=1;B=2;' }
    }
    It 'handles empty and missing strings' {
        InModuleScope iGWindowsTuner {
            Set-IgwtListItem -Text '' -Key 'A' -Value '1' | Should -Be 'A=1;'
            Remove-IgwtListItem -Text $null -Key 'A' | Should -Be ''
        }
    }
}

Describe 'registryListMerge action' {
    BeforeAll {
        $script:Path = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
    }

    It 'merges into an existing string and reverts to the exact original' {
        $path = $script:Path
        InModuleScope iGWindowsTuner -Parameters @{ P = $path } {
            param($P)
            Set-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings' -Kind String -Value 'VRROptimizeEnable=1;Custom=7;'
            $a = [pscustomobject]@{ type = 'registryListMerge'; path = $P; name = 'DirectXUserGlobalSettings'; item = 'SwapEffectUpgradeEnable'; on = '1'; off = '<remove>'; default = '<remove>' }
            (Get-IgwtListMergeState -Action $a).State | Should -Be 'Off'
            $snap = (Get-IgwtRegistrySnapshot -Action $a) | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            Invoke-IgwtListMergeApply -Action $a
            (Get-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;Custom=7;SwapEffectUpgradeEnable=1;'
            (Get-IgwtListMergeState -Action $a).State | Should -Be 'On'
            Invoke-IgwtListMergeApply -Action $a
            (Get-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;Custom=7;SwapEffectUpgradeEnable=1;'
            Restore-IgwtRegistrySnapshot -Action $a -Snapshot $snap
            (Get-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;Custom=7;'
        }
    }

    It 'creates the value when absent and the default removes it again' {
        $path = $script:Path
        InModuleScope iGWindowsTuner -Parameters @{ P = $path } {
            param($P)
            Remove-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings'
            $a = [pscustomobject]@{ type = 'registryListMerge'; path = $P; name = 'DirectXUserGlobalSettings'; item = 'VRROptimizeEnable'; on = '1'; off = '<remove>'; default = '<remove>' }
            Invoke-IgwtListMergeApply -Action $a
            (Get-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;'
            Invoke-IgwtListMergeApply -Action $a -Mode default
            (Get-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings').Exists | Should -BeFalse
        }
    }

    It 'removing one item keeps the others' {
        $path = $script:Path
        InModuleScope iGWindowsTuner -Parameters @{ P = $path } {
            param($P)
            Set-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings' -Kind String -Value 'SwapEffectUpgradeEnable=1;VRROptimizeEnable=1;'
            $a = [pscustomobject]@{ type = 'registryListMerge'; path = $P; name = 'DirectXUserGlobalSettings'; item = 'SwapEffectUpgradeEnable'; on = '1'; off = '<remove>'; default = '<remove>' }
            Invoke-IgwtListMergeApply -Action $a -Mode off
            (Get-IgwtRegistryValue -Path $P -Name 'DirectXUserGlobalSettings').Value | Should -Be 'VRROptimizeEnable=1;'
        }
    }
}
