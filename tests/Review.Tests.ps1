# Regression tests for the findings of the independent review (docs\REVIEW.md, 3.0 phase 1).
# Everything runs in TestRegistry, a TestDrive data root and mocks.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Review H1/M4: Recycle Bin rules' {
    It 'runs Recycle Bin rules before every other rule in one clean' {
        $scan = [pscustomobject]@{ Id = 'x'; AllUsers = $false; Rules = @(
                [pscustomobject]@{ RuleId = 'clean.downloads.old'; Method = 'files'; Status = 'Ready' },
                [pscustomobject]@{ RuleId = 'clean.recycle-bin'; Method = 'recycleBin'; Status = 'Ready' }) }
        $script:Order = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName iGWindowsTuner Invoke-IgwtCleanerRuleClean { $script:Order.Add([string]$RuleScan.RuleId); [pscustomobject]@{ RuleId = $RuleScan.RuleId; Status = 'Done'; Reason = ''; DeletedBytes = 0L; DeletedCount = 0; Skipped = @{} } }
        $null = Invoke-IgwtCleanerClean -Scan $scan
        @($script:Order) | Should -Be @('clean.recycle-bin', 'clean.downloads.old')
    }
}

Describe 'Review H2: Recycle Bin refusals' {
    It 'skips a file that cannot be recycled instead of deleting it permanently' {
        $dir = Join-Path $TestDrive 'dl'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $file = Join-Path $dir 'big.iso'
        Set-Content -LiteralPath $file -Value 'x'
        InModuleScope iGWindowsTuner -Parameters @{ F = $file; D = $dir } {
            param($F, $D)
            Set-IgwtCleanerTestRoot -Path $D
            Mock Get-IgwtRecycleRefusal { 'the file is larger than this drive''s Recycle Bin' }
            Mock Send-IgwtToRecycleBin { }
            $fi = New-Object System.IO.FileInfo($F)
            $entry = [pscustomobject]@{ Path = $F; Root = $D; Size = $fi.Length; LastWriteTicks = $fi.LastWriteTimeUtc.Ticks }
            $rule = [pscustomobject]@{ id = 'clean.test'; recycle = $true; allowDownloads = $true; allowSystemFiles = $false; minAgeHours = 0; ResolvedRoots = @($D) }
            $o = Remove-IgwtCleanerFile -Entry $entry -Rule $rule
            $o.Result | Should -Be 'Skipped'
            $o.Reason | Should -Match 'larger than'
            Should -Invoke Send-IgwtToRecycleBin -Times 0 -Exactly
            Set-IgwtCleanerTestRoot -Path ''
        }
        Test-Path -LiteralPath $file | Should -BeTrue
    }
}

Describe 'Review H3: VBS/HVCI is never turned off' {
    It 'keeps the retired item only for reverting' {
        $t = Get-IgwtTweak -Id 'sec.vbs-hvci-off-expert'
        $t.status | Should -Be 'NotApplicable'
        $s = Get-IgwtTweakState -Tweak $t -Context (New-IgwtTestContext)
        $s.State | Should -Be 'NotApplicable'
        $r = Invoke-IgwtApply -Id 'sec.vbs-hvci-off-expert' -AcknowledgeRisk -Context (New-IgwtTestContext)
        @($r.Results)[0].Result | Should -Be 'NotApplicable'
    }
}

Describe 'Review M1/M2: presets never carry Lab or Risk Zone items' {
    BeforeEach {
        $folder = InModuleScope iGWindowsTuner { Get-IgwtDataPath -Kind Presets }
        if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
    }
    It 'drops Lab and Risk Zone items from a preset selection' {
        $p = [pscustomobject]@{ id = 'x'; name = 'X'; include = @('gfx.game-mode', 'risk.hpet-disable'); exclude = @(); levelCeiling = 'Advanced'; antiCheatPolicy = 'safeOnly'; tweaks = @('gfx.game-mode', 'risk.hpet-disable') }
        $s = Resolve-IgwtPresetSelection -Preset $p -Tags @()
        $s.Ids | Should -Not -Contain 'risk.hpet-disable'
    }
    It 'skips a custom preset that breaks the rules even with a valid SHA256 field' {
        $saved = Save-IgwtCustomPreset -Name 'Valid' -BasedOn balanced
        $doc = Get-Content -LiteralPath $saved.sourceFile -Raw | ConvertFrom-Json
        $doc.include = @(@($doc.include) + 'risk.hpet-disable')
        $doc.sha256 = InModuleScope iGWindowsTuner -Parameters @{ D = $doc } { param($D) Get-IgwtPresetHash -Preset $D }
        [System.IO.File]::WriteAllText($saved.sourceFile, ($doc | ConvertTo-Json -Depth 6))
        @(Get-IgwtPreset | Where-Object { $_.id -eq 'custom-valid' }) | Should -BeNullOrEmpty
    }
    It 'refuses a custom preset with a built-in name' {
        { Save-IgwtCustomPreset -Name 'Balanced' -BasedOn balanced } | Should -Throw '*built-in*'
    }
    It 'records only the preset''s own selection for the drift report' {
        InModuleScope iGWindowsTuner { Save-IgwtPresetRecord -Preset balanced -Id @('gfx.game-mode', 'risk.pagefile-off') }
        $r = InModuleScope iGWindowsTuner { Get-IgwtPresetRecord }
        @($r.ids) | Should -Not -Contain 'risk.pagefile-off'
        @($r.ids) | Should -Contain 'sec.uac-on'
    }
}

Describe 'Review M3/L5: Session Mode crash safety' {
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-IgwtBootTime { [datetime]::UtcNow.AddHours(-3) }
        Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = 'WSearch'; Status = 'Running' } } -ParameterFilter { $Name -eq 'WSearch' }
        Mock -ModuleName iGWindowsTuner Stop-Service { } -ParameterFilter { $Name -eq 'WSearch' }
        $f = InModuleScope iGWindowsTuner { Get-IgwtSessionFile }
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    }
    It 'writes the session record before anything changes' {
        Mock -ModuleName iGWindowsTuner Invoke-IgwtApply { $script:SeenRecord = Test-Path -LiteralPath (InModuleScope iGWindowsTuner { Get-IgwtSessionFile }); throw 'power lost' }
        { Start-IgwtSession -Context (New-IgwtTestContext -Extra @{ HardwareTags = @('formfactor.laptop') }) } | Should -Throw '*power lost*'
        $script:SeenRecord | Should -BeTrue
        $f = InModuleScope iGWindowsTuner { Get-IgwtSessionFile }
        $m = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        $m.state | Should -Be 'starting'
        $m.pid = 999999
        [System.IO.File]::WriteAllText($f, ($m | ConvertTo-Json))
        $st = Get-IgwtSessionState
        $st.Stale | Should -BeTrue
        $st.Reason | Should -Match 'did not finish starting'
        Remove-Item -LiteralPath $f -Force
    }
}

Describe 'Review M6: management changes never lower security' {
    It 'refuses to enable SMBv1, PowerShell 2.0 or Telnet' {
        foreach ($f in 'SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root', 'TelnetClient') {
            { Get-IgwtManagedChangePlan -Kind feature -Target $f -Value Enabled } | Should -Throw '*lowers security*' -Because $f
        }
    }
    It 'protects the Defender core, SmartScreen, BITS and Delivery Optimization services' {
        foreach ($s in 'MDCoreSvc', 'webthreatdefsvc', 'BITS', 'DoSvc', 'AppIDSvc') {
            InModuleScope iGWindowsTuner -Parameters @{ S = $s } { param($S) Get-IgwtServiceProtection -Name $S } | Should -Not -BeNullOrEmpty -Because $s
        }
    }
}

Describe 'Review L2/L4' {
    It 'checks fix steps against the allow-lists when they run' {
        InModuleScope iGWindowsTuner {
            { Invoke-IgwtFixStep -Step ([pscustomobject]@{ kind = 'renameFolder'; path = 'C:\Users' }) -Stamp 'x' } | Should -Throw '*not allowed*'
            { Invoke-IgwtFixStep -Step ([pscustomobject]@{ kind = 'service'; name = 'WinDefend'; operation = 'stop' }) -Stamp 'x' } | Should -Throw '*not allowed*'
        }
    }
    It 'resetting a bitSet item clears only its own bit' {
        InModuleScope iGWindowsTuner {
            $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            Set-IgwtRegistryValue -Path $p -Name 'DisabledComponents' -Kind DWord -Value 33
            $a = (Get-IgwtTweak -Id 'net.prefer-ipv4').actions[0]
            $null = Invoke-IgwtActionApply -Action $a -Context $null -Mode default
            (Get-IgwtRegistryValue -Path $p -Name 'DisabledComponents').Value | Should -Be 1
            $null = Invoke-IgwtActionApply -Action $a -Context $null -Mode on
            Set-IgwtRegistryValue -Path $p -Name 'DisabledComponents' -Kind DWord -Value 32
            $null = Invoke-IgwtActionApply -Action $a -Context $null -Mode default
            (Get-IgwtRegistryValue -Path $p -Name 'DisabledComponents').Exists | Should -BeFalse
        }
    }
}
