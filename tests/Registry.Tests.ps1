BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Registry redirection safety' {
    It 'refuses paths that are not redirected into TestRegistry in TestMode' {
        InModuleScope iGWindowsTuner { { Resolve-IgwtRegistryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\X' } | Should -Throw '*TestMode safety*' }
    }
    It 'redirects HKLM and HKCU into TestRegistry' {
        InModuleScope iGWindowsTuner {
            Resolve-IgwtRegistryPath 'HKLM:\SOFTWARE\Test' | Should -Be 'TestRegistry:\HKLM\SOFTWARE\Test'
            Resolve-IgwtRegistryPath 'HKCU:\Software\Test' | Should -Be 'TestRegistry:\HKCU\Software\Test'
        }
    }
}

Describe 'Snapshot fidelity for every REG type' {
    BeforeEach {
        $script:Key = "HKLM:\SOFTWARE\IgwtTest\Fidelity$([guid]::NewGuid().ToString('N').Substring(0,6))"
    }

    It 'round-trips <Kind> exactly through snapshot JSON' -ForEach @(
        @{ Kind = 'DWord'; Value = 0 }
        @{ Kind = 'DWord'; Value = '0xFFFFFFFF' }
        @{ Kind = 'QWord'; Value = '18446744073709551615' }
        @{ Kind = 'String'; Value = 'VRROptimizeEnable=1;' }
        @{ Kind = 'ExpandString'; Value = '%SystemRoot%\System32\x.dll' }
        @{ Kind = 'MultiString'; Value = @('one', 'two', '') }
        @{ Kind = 'Binary'; Value = '0001FF7F80' }
    ) {
        $k = $script:Key; $kind = $Kind; $val = $Value
        InModuleScope iGWindowsTuner -Parameters @{ Key = $k; Kind = $kind; Val = $val } {
            param($Key, $Kind, $Val)
            Set-IgwtRegistryValue -Path $Key -Name 'V' -Kind $Kind -Value (ConvertFrom-IgwtSerializableValue -Data $Val -Kind $Kind)
            $action = [pscustomobject]@{ type = 'registry'; path = $Key; name = 'V'; valueType = $Kind; on = $null; default = '<absent>' }
            $snap = Get-IgwtRegistrySnapshot -Action $action
            $json = $snap | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            Remove-IgwtRegistryValue -Path $Key -Name 'V'
            (Get-IgwtRegistryValue -Path $Key -Name 'V').Exists | Should -BeFalse
            Restore-IgwtRegistrySnapshot -Action $action -Snapshot $json
            $after = Get-IgwtRegistryValue -Path $Key -Name 'V'
            $after.Exists | Should -BeTrue
            $after.Kind | Should -Be $Kind
            Test-IgwtRegistryValueEqual $after.Value (ConvertFrom-IgwtSerializableValue -Data $Val -Kind $Kind) $Kind | Should -BeTrue
        }
    }

    It 'keeps REG_EXPAND_SZ unexpanded' {
        $k = $script:Key
        InModuleScope iGWindowsTuner -Parameters @{ Key = $k } {
            param($Key)
            Set-IgwtRegistryValue -Path $Key -Name 'E' -Kind ExpandString -Value '%windir%\foo'
            (Get-IgwtRegistryValue -Path $Key -Name 'E').Value | Should -Be '%windir%\foo'
        }
    }

    It 'restores "value did not exist" and removes keys iG Windows Tuner created' {
        $k = "$script:Key\Deep\Er"
        InModuleScope iGWindowsTuner -Parameters @{ Key = $k } {
            param($Key)
            $action = [pscustomobject]@{ type = 'registry'; path = $Key; name = 'N'; valueType = 'DWord'; on = 1; default = '<absent>' }
            $snap = (Get-IgwtRegistrySnapshot -Action $action) | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            $snap.items[0].exists | Should -BeFalse
            $snap.items[0].missingDepth | Should -BeGreaterOrEqual 3
            Invoke-IgwtRegistryApply -Action $action
            (Get-IgwtRegistryValue -Path $Key -Name 'N').Value | Should -Be 1
            Restore-IgwtRegistrySnapshot -Action $action -Snapshot $snap
            (Get-IgwtRegistryValue -Path $Key -Name 'N').Exists | Should -BeFalse
            Test-IgwtRegistryKey -Path $Key | Should -BeFalse
            Test-IgwtRegistryKey -Path ($Key -replace '\\Deep\\Er$', '') | Should -BeFalse
        }
    }

    It 'never deletes a pre-existing key that still holds other values' {
        $k = $script:Key
        InModuleScope iGWindowsTuner -Parameters @{ Key = $k } {
            param($Key)
            Set-IgwtRegistryValue -Path "$Key\Sub" -Name 'Other' -Kind String -Value 'keep'
            $action = [pscustomobject]@{ type = 'registry'; path = "$Key\Sub\New"; name = 'N'; valueType = 'DWord'; on = 1; default = '<absent>' }
            $snap = (Get-IgwtRegistrySnapshot -Action $action) | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            Invoke-IgwtRegistryApply -Action $action
            Restore-IgwtRegistrySnapshot -Action $action -Snapshot $snap
            Test-IgwtRegistryKey -Path "$Key\Sub\New" | Should -BeFalse
            (Get-IgwtRegistryValue -Path "$Key\Sub" -Name 'Other').Value | Should -Be 'keep'
        }
    }
}

Describe 'Registry action semantics' {
    It 'rewrites a wrongly typed value (DWORD 0 -> REG_SZ "0") and reverts to the original DWORD' {
        InModuleScope iGWindowsTuner {
            $p = 'HKCU:\Control Panel\MouseTypeTest'
            Set-IgwtRegistryValue -Path $p -Name 'MouseSpeed' -Kind DWord -Value 0
            $a = [pscustomobject]@{ type = 'registry'; path = $p; name = 'MouseSpeed'; valueType = 'String'; on = '0'; default = '1' }
            (Get-IgwtRegistryState -Action $a).State | Should -Be 'Off'
            $snap = (Get-IgwtRegistrySnapshot -Action $a) | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            Invoke-IgwtRegistryApply -Action $a
            $v = Get-IgwtRegistryValue -Path $p -Name 'MouseSpeed'
            $v.Kind | Should -Be 'String'; $v.Value | Should -Be '0'
            (Get-IgwtRegistryState -Action $a).State | Should -Be 'On'
            Restore-IgwtRegistrySnapshot -Action $a -Snapshot $snap
            $r = Get-IgwtRegistryValue -Path $p -Name 'MouseSpeed'
            $r.Kind | Should -Be 'DWord'; $r.Value | Should -Be 0
        }
    }

    It 'clears only the hotkey bit with bitClear and preserves other flags' {
        InModuleScope iGWindowsTuner {
            $p = 'HKCU:\Control Panel\Accessibility\StickyKeysTest'
            Set-IgwtRegistryValue -Path $p -Name 'Flags' -Kind String -Value '511'
            $a = [pscustomobject]@{ type = 'registry'; path = $p; name = 'Flags'; valueType = 'String'; on = '506'; bitClear = 4; default = '510'; absentValue = '510' }
            (Get-IgwtRegistryState -Action $a).State | Should -Be 'Off'
            Invoke-IgwtRegistryApply -Action $a
            (Get-IgwtRegistryValue -Path $p -Name 'Flags').Value | Should -Be '507'
            (Get-IgwtRegistryState -Action $a).State | Should -Be 'On'
        }
    }

    It 'treats absent values using absentValue and equivalentOn values as on' {
        InModuleScope iGWindowsTuner {
            $p = 'HKLM:\SOFTWARE\IgwtTest\Semantics'
            $a = [pscustomobject]@{ type = 'registry'; path = $p; name = 'A'; valueType = 'DWord'; on = 1; default = '<absent>'; absentValue = 1 }
            (Get-IgwtRegistryState -Action $a).State | Should -Be 'On'
            $b = [pscustomobject]@{ type = 'registry'; path = $p; name = 'B'; valueType = 'DWord'; on = 2; default = '<absent>'; equivalentOn = @(1) }
            Set-IgwtRegistryValue -Path $p -Name 'B' -Kind DWord -Value 1
            (Get-IgwtRegistryState -Action $b).State | Should -Be 'On'
            $c = [pscustomobject]@{ type = 'registry'; path = $p; name = 'C'; valueType = 'DWord'; on = '<absent>'; default = '<absent>'; equivalentOn = @(0) }
            Set-IgwtRegistryValue -Path $p -Name 'C' -Kind DWord -Value 1
            (Get-IgwtRegistryState -Action $c).State | Should -Be 'Off'
            Invoke-IgwtRegistryApply -Action $c
            (Get-IgwtRegistryValue -Path $p -Name 'C').Exists | Should -BeFalse
        }
    }

    It 'writes onlyIfAbsent values only when missing' {
        InModuleScope iGWindowsTuner {
            $p = 'HKLM:\SOFTWARE\IgwtTest\OnlyIfAbsent'
            Set-IgwtRegistryValue -Path $p -Name 'W' -Kind DWord -Value 1
            $a = [pscustomobject]@{ type = 'registry'; path = $p; name = 'W'; valueType = 'DWord'; on = 2; onlyIfAbsent = $true; default = '<absent>' }
            Invoke-IgwtRegistryApply -Action $a
            (Get-IgwtRegistryValue -Path $p -Name 'W').Value | Should -Be 1
        }
    }

    It 'resets to the documented Windows default' {
        InModuleScope iGWindowsTuner {
            $p = 'HKLM:\SOFTWARE\IgwtTest\Default'
            $a = [pscustomobject]@{ type = 'registry'; path = $p; name = 'D'; valueType = 'DWord'; on = 10; default = 20 }
            Invoke-IgwtRegistryApply -Action $a
            Invoke-IgwtRegistryApply -Action $a -Mode default
            (Get-IgwtRegistryValue -Path $p -Name 'D').Value | Should -Be 20
        }
    }

    It 'parses microcode-style hex and negative DWORD inputs' {
        InModuleScope iGWindowsTuner {
            ConvertTo-IgwtUInt64 '0xFFFFFFFF' | Should -Be 4294967295
            ConvertTo-IgwtUInt64 (-1) | Should -Be 4294967295
            ConvertTo-IgwtUInt64 10 | Should -Be 10
        }
    }
}
