# Presets 2.0: the ten built-in presets and their rules, custom presets (save, duplicate, import,
# export with SHA256), the drift report and Session Mode (snapshot-backed, crash-safe). Runs in
# TestRegistry with a TestDrive data root; every system call is mocked.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Presets = @(Get-IgwtPreset -Builtin)
    function Get-P([string]$Id) { @($script:Presets | Where-Object { $_.id -eq $Id })[0] }
}

Describe 'Built-in presets' {
    It 'ships the ten v2 presets' {
        @($script:Presets | ForEach-Object { $_.id } | Sort-Object) | Should -Be @('balanced', 'competitive', 'debloat', 'engineer', 'fortress', 'hardened', 'laptop', 'privacy-max', 'session', 'streamer')
        foreach ($p in $script:Presets) { [string]$p.code | Should -Match '^[A-Z]$' -Because $p.id }
        @($script:Presets | ForEach-Object { $_.code } | Select-Object -Unique).Count | Should -Be 10
    }
    It 'passes the preset rules (texts, ceiling, no Lab or Risk Zone, gaming presets anti-cheat safe)' {
        $ids = InModuleScope iGWindowsTuner { Get-IgwtPresetCatalogIndex }
        foreach ($p in $script:Presets) {
            $e = New-Object System.Collections.Generic.List[string]
            Test-IgwtPresetDefinition -Preset $p -CatalogIndex $ids -Errors $e
            @($e) | Should -BeNullOrEmpty -Because $p.id
        }
    }
    It 'keeps capture and background apps for the streamer preset' {
        $p = Get-P 'streamer'
        @($p.exclude) | Should -Contain 'gfx.background-recording-off'
        @($p.exclude) | Should -Contain 'privacy.background-apps-off'
        @($p.tweaks) | Should -Contain 'net.qos-dscp-games'
    }
    It 'keeps Windows power management on the laptop preset' {
        $p = Get-P 'laptop'
        foreach ($x in 'power.ultimate-plan', 'power.high-performance-plan', 'power.pcie-aspm-off', 'power.usb-selective-suspend-off') { @($p.tweaks) | Should -Not -Contain $x; @($p.exclude) | Should -Contain $x }
        @($p.tweaks) | Should -Contain 'power.power-throttling-on'
    }
    It 'changes no services and nothing virtualization-related on the engineer preset' {
        $p = Get-P 'engineer'
        @($p.tweaks) | Should -Contain 'system.long-paths'
        foreach ($x in 'privacy.diagtrack-disabled', 'privacy.sysmain-off', 'privacy.search-indexing-off', 'sec.vbs-hvci-off-expert') { @($p.tweaks) | Should -Not -Contain $x }
        (@($p.guidance) -join ' ') | Should -Match 'Dev Drive'
        (@($p.guidance) -join ' ') | Should -Match 'Developer Mode'
    }
    It 'covers the privacy items and never turns security features off in Privacy Max' {
        $p = Get-P 'privacy-max'
        foreach ($x in 'privacy.ai-features-off', 'privacy.activity-history-off', 'privacy.location-off', 'privacy.edge-privacy-policies', 'privacy.office-privacy-policies', 'privacy.diagnostic-data-required') { @($p.tweaks) | Should -Contain $x }
        @($p.tweaks) | Should -Contain 'sec.smartscreen-on'
    }
    It 'removes only unprotected inbox apps in the debloat preset' {
        @((Get-P 'debloat').tweaks) | Should -Contain 'privacy.inbox-apps-consumer-off'
        foreach ($a in @((Get-IgwtTweak -Id 'privacy.inbox-apps-consumer-off').actions)) {
            InModuleScope iGWindowsTuner -Parameters @{ P = [string]$a.package } { param($P) Test-IgwtAppxProtected -Package $P } | Should -BeFalse -Because $a.package
            [string]$a.storeId | Should -Match '^[0-9A-Z]{12}$'
        }
    }
    It 'makes Fortress a superset of the Hardened security items' {
        $f = @((Get-P 'fortress').tweaks)
        foreach ($x in @((Get-P 'hardened').tweaks | Where-Object { $_ -like 'sec.*' })) { $f | Should -Contain $x }
        $f | Should -Contain 'sec.asr-safe-mode-block'
        $f | Should -Contain 'sec.wsh-off'
    }
    It 'keeps the Session Mode items out of every other preset' {
        foreach ($p in @($script:Presets | Where-Object { $_.id -ne 'session' })) { @($p.tweaks | Where-Object { $_ -like 'system.session-*' }) | Should -BeNullOrEmpty -Because $p.id }
        (Get-P 'session').session | Should -BeTrue
    }
}

Describe 'Custom presets' {
    BeforeEach {
        $folder = InModuleScope iGWindowsTuner { Get-IgwtDataPath -Kind Presets }
        if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
    }
    It 'saves a preset with additions, removals and a SHA256 field' {
        $p = Save-IgwtCustomPreset -Name 'My Balanced' -BasedOn balanced -AddIds 'system.long-paths' -RemoveIds 'sec.llmnr-off'
        $p.id | Should -Be 'custom-my-balanced'
        $p.custom | Should -BeTrue
        @($p.tweaks) | Should -Contain 'system.long-paths'
        @($p.tweaks) | Should -Not -Contain 'sec.llmnr-off'
        @($p.exclude) | Should -Contain 'sec.llmnr-off'
        $doc = Get-Content -LiteralPath $p.sourceFile -Raw | ConvertFrom-Json
        [string]$doc.sha256 | Should -Match '^[0-9a-f]{64}$'
        @(Get-IgwtPreset | Where-Object { $_.id -eq 'custom-my-balanced' }).Count | Should -Be 1
        (Resolve-IgwtPresetSelection -Preset 'custom-my-balanced' -Tags @()).Ids | Should -Contain 'system.long-paths'
    }
    It 'refuses Lab items, Session Mode as a base and duplicate names' {
        { Save-IgwtCustomPreset -Name 'Bad' -BasedOn competitive -AddIds 'sec.vbs-hvci-off-expert' } | Should -Throw '*Lab item*'
        { Save-IgwtCustomPreset -Name 'Bad' -BasedOn session } | Should -Throw '*Session Mode*'
        $null = Save-IgwtCustomPreset -Name 'Twice' -BasedOn balanced
        { Save-IgwtCustomPreset -Name 'Twice' -BasedOn balanced } | Should -Throw '*already exists*'
    }
    It 'skips a custom preset whose file was changed' {
        $p = Save-IgwtCustomPreset -Name 'Tamper' -BasedOn balanced
        $raw = (Get-Content -LiteralPath $p.sourceFile -Raw).Replace('"sec.uac-on"', '"sec.vbs-hvci-off-expert"')
        [System.IO.File]::WriteAllText($p.sourceFile, $raw)
        @(Get-IgwtPreset | Where-Object { $_.id -eq 'custom-tamper' }) | Should -BeNullOrEmpty
    }
    It 'duplicates, exports, imports and removes' {
        $dup = Copy-IgwtPreset -Name hardened -NewName 'Hardened copy'
        @($dup.tweaks).Count | Should -Be @((Get-P 'hardened').tweaks).Count
        $file = Join-Path $TestDrive 'export.json'
        Export-IgwtPreset -Name 'custom-hardened-copy' -Path $file | Should -Be $file
        Remove-IgwtCustomPreset -Name 'custom-hardened-copy'
        @(Get-IgwtPreset | Where-Object { $_.id -eq 'custom-hardened-copy' }) | Should -BeNullOrEmpty
        $imp = Import-IgwtPreset -Path $file
        $imp.id | Should -Be 'custom-hardened-copy'
        @($imp.tweaks) | Should -Be @($dup.tweaks)
        { Remove-IgwtCustomPreset -Name balanced } | Should -Throw '*built-in*'
    }
    It 'refuses an import whose SHA256 field does not match' {
        $file = Join-Path $TestDrive 'bad-export.json'
        $null = Export-IgwtPreset -Name competitive -Path $file
        $raw = (Get-Content -LiteralPath $file -Raw).Replace('"sec.uac-on"', '"sec.wsh-off"')
        [System.IO.File]::WriteAllText($file, $raw)
        { Import-IgwtPreset -Path $file } | Should -Throw '*SHA256*'
    }
}

Describe 'Drift report' {
    BeforeEach {
        $state = InModuleScope iGWindowsTuner { Get-IgwtDataPath -Kind State }
        if (Test-Path -LiteralPath (Join-Path $state 'last-preset.json')) { Remove-Item -LiteralPath (Join-Path $state 'last-preset.json') -Force }
        $folder = InModuleScope iGWindowsTuner { Get-IgwtDataPath -Kind Presets }
        if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
    }
    It 'reports no preset before one was applied' {
        (Get-IgwtPresetDrift -Context (New-IgwtTestContext)).HasPreset | Should -BeFalse
    }
    It 'lists the items that changed since the recorded apply and adopts the rest as a custom preset' {
        InModuleScope iGWindowsTuner { Save-IgwtPresetRecord -Preset balanced -Id @('input.pointer-precision-off', 'gfx.game-mode', 'sec.uac-on') }
        Mock -ModuleName iGWindowsTuner Get-IgwtAllTweakStates { foreach ($i in $Id) { [pscustomobject]@{ Id = $i; State = $(if ($i -eq 'gfx.game-mode') { 'Off' } else { 'On' }) } } }
        Mock -ModuleName iGWindowsTuner New-IgwtContext { New-IgwtTestContext }
        $d = Get-IgwtPresetDrift
        $d.HasPreset | Should -BeTrue
        $d.FromRecord | Should -BeTrue
        @($d.Drifted).Count | Should -Be 1
        $d.Drifted[0].Id | Should -Be 'gfx.game-mode'
        $d.Message | Should -Match '1 setting\(s\) changed since you applied Balanced'
        $adopted = Save-IgwtDriftAsPreset -Name 'Balanced as is'
        @($adopted.tweaks) | Should -Not -Contain 'gfx.game-mode'
        @($adopted.exclude) | Should -Contain 'gfx.game-mode'
    }
    It 'records the preset after a preset apply' {
        $null = Invoke-IgwtApply -Id 'input.accessibility-hotkeys-off' -Operation 'Preset:balanced' -Context (New-IgwtTestContext)
        $r = InModuleScope iGWindowsTuner { Get-IgwtPresetRecord }
        $r.preset | Should -Be 'balanced'
        @($r.ids) | Should -Contain 'input.accessibility-hotkeys-off'
    }
}

Describe 'Session Mode' {
    BeforeEach {
        $script:Search = 'Running'
        Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = 'WSearch'; Status = $script:Search } } -ParameterFilter { $Name -eq 'WSearch' }
        Mock -ModuleName iGWindowsTuner Stop-Service { $script:Search = 'Stopped' } -ParameterFilter { $Name -eq 'WSearch' }
        Mock -ModuleName iGWindowsTuner Start-Service { $script:Search = 'Running' } -ParameterFilter { $Name -eq 'WSearch' }
        Mock -ModuleName iGWindowsTuner Get-IgwtBootTime { [datetime]::UtcNow.AddHours(-3) }
        $f = InModuleScope iGWindowsTuner { Get-IgwtSessionFile }
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
        $script:Laptop = New-IgwtTestContext -Extra @{ HardwareTags = @('formfactor.laptop') }
        $script:Desktop = New-IgwtTestContext -Extra @{ HardwareTags = @('cpu.intel.hybrid') }
    }
    It 'uses the highest power plan the hardware allows' {
        (Get-IgwtSessionPlan -Context $script:Desktop).PowerPlan | Should -Be 'power.ultimate-plan'
        $l = Get-IgwtSessionPlan -Context $script:Laptop
        $l.PowerPlan | Should -Be ''
        @($l.Ids) | Should -Be @('system.session-notifications-off', 'system.session-search-paused')
    }
    It 'applies the session items with a snapshot and restores them when it ends' {
        $r = Start-IgwtSession -Context $script:Laptop -Owner cli
        $r.Snapshot | Should -Not -BeNullOrEmpty
        $script:Search | Should -Be 'Stopped'
        InModuleScope iGWindowsTuner { (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled').Value } | Should -Be 0
        $st = Get-IgwtSessionState
        $st.Active | Should -BeTrue
        $st.Stale | Should -BeFalse
        { Start-IgwtSession -Context $script:Laptop } | Should -Throw '*already active*'
        $null = Stop-IgwtSession
        $script:Search | Should -Be 'Running'
        InModuleScope iGWindowsTuner { (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled').Exists } | Should -BeFalse
        (Get-IgwtSessionState).Active | Should -BeFalse
    }
    It 'flags a session as stale after a restart or when its app is gone' {
        $null = Start-IgwtSession -Context $script:Laptop -Owner cli
        Mock -ModuleName iGWindowsTuner Get-IgwtBootTime { [datetime]::UtcNow.AddMinutes(5) }
        $st = Get-IgwtSessionState
        $st.Stale | Should -BeTrue
        $st.Reason | Should -Match 'restarted'
        $null = Stop-IgwtSession
        Mock -ModuleName iGWindowsTuner Get-IgwtBootTime { [datetime]::UtcNow.AddHours(-3) }
        $null = Start-IgwtSession -Context $script:Laptop -Owner gui
        $f = InModuleScope iGWindowsTuner { Get-IgwtSessionFile }
        $m = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        $m.pid = 999999
        [System.IO.File]::WriteAllText($f, ($m | ConvertTo-Json))
        (Get-IgwtSessionState).Reason | Should -Match 'closed without ending'
        $null = Stop-IgwtSession
    }
    It 'closes only apps from the session list' {
        Mock -ModuleName iGWindowsTuner Get-Process { @([pscustomobject]@{ Id = 4242; ProcessName = 'OneDrive'; MainWindowHandle = [IntPtr]::Zero }) } -ParameterFilter { $Name -eq 'OneDrive' }
        Mock -ModuleName iGWindowsTuner Stop-Process { }
        $r = @(Close-IgwtSessionApps -Name 'OneDrive', 'explorer')
        ($r | Where-Object Name -eq 'explorer').Result | Should -Be 'Refused'
        ($r | Where-Object Name -eq 'OneDrive').Result | Should -Be 'Closed'
        Should -Invoke Stop-Process -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Id -eq 4242 }
    }
}
