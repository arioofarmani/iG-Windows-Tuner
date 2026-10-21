# Custom.ps1
# 'custom' actions (named Detect / Snapshot / Apply / Restore handlers for settings that need
# more than one primitive), 'check' actions (read-only runtime conditions that contribute to a
# tweak's state, e.g. "memory integrity is actually running"), post-apply hooks, and the single
# P/Invoke used by iG Windows Tuner.

#region Native: the only Add-Type in iG Windows Tuner

$script:IgwtNativeSource = @'
using System;
using System.Runtime.InteropServices;

namespace iG Windows Tuner
{
    // SystemParametersInfo applies mouse, keyboard-repeat and accessibility-hotkey settings to
    // the running session and broadcasts WM_SETTINGCHANGE (SPIF_SENDCHANGE), so the user does
    // not have to sign out after iG Windows Tuner has written the documented registry values.
    public static class NativeMethods
    {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, int[] pvParam, uint fWinIni);
    }
}
'@

$script:SPI_GETMOUSE = 0x0003
$script:SPI_SETMOUSE = 0x0004
$script:SPI_SETKEYBOARDSPEED = 0x000B
$script:SPI_SETKEYBOARDDELAY = 0x0017
$script:SPI_GETFILTERKEYS = 0x0032
$script:SPI_SETFILTERKEYS = 0x0033
$script:SPI_GETTOGGLEKEYS = 0x0034
$script:SPI_SETTOGGLEKEYS = 0x0035
$script:SPI_GETSTICKYKEYS = 0x003A
$script:SPI_SETSTICKYKEYS = 0x003B
$script:SPIF_SENDCHANGE = 0x0002

function Initialize-IgwtNative {
    [CmdletBinding()]
    param()
    if (-not ('iGWindowsTuner.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition $script:IgwtNativeSource -Language CSharp
    }
}

function Invoke-IgwtSystemParametersInfo {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([uint32]$Action, [uint32]$UiParam = 0, [int[]]$Buffer = $null)
    if ($script:IgwtSettings.TestMode) { return $true }
    if (-not $PSCmdlet.ShouldProcess("SystemParametersInfo 0x$('{0:X}' -f $Action)", 'Apply to current session')) { return $true }
    Initialize-IgwtNative
    return [iGWindowsTuner.NativeMethods]::SystemParametersInfo($Action, $UiParam, $Buffer, $script:SPIF_SENDCHANGE)
}

function ConvertTo-IgwtIntOrDefault {
    [CmdletBinding()]
    param($Read, [int]$Default)
    if (-not $Read.Exists) { return $Default }
    $n = 0
    if ([int]::TryParse([string]$Read.Value, [ref]$n)) { return $n }
    return $Default
}

#endregion

#region Post-apply hooks (live refresh after registry changes)

function Invoke-IgwtPostApplyHook {
    <# .SYNOPSIS Applies just-written per-user settings to the running session. Never throws. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Hook)
    try {
        switch ($Hook) {
            'MouseParameters' {
                $m = 'HKCU:\Control Panel\Mouse'
                $t1 = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path $m -Name 'MouseThreshold1') 6
                $t2 = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path $m -Name 'MouseThreshold2') 10
                $sp = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path $m -Name 'MouseSpeed') 1
                $null = Invoke-IgwtSystemParametersInfo -Action $script:SPI_SETMOUSE -Buffer @($t1, $t2, $sp)
            }
            'KeyboardRepeat' {
                $k = 'HKCU:\Control Panel\Keyboard'
                $delay = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path $k -Name 'KeyboardDelay') 1
                $speed = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path $k -Name 'KeyboardSpeed') 31
                $null = Invoke-IgwtSystemParametersInfo -Action $script:SPI_SETKEYBOARDDELAY -UiParam ([uint32]$delay)
                $null = Invoke-IgwtSystemParametersInfo -Action $script:SPI_SETKEYBOARDSPEED -UiParam ([uint32]$speed)
            }
            'AccessibilityFlags' {
                $a = 'HKCU:\Control Panel\Accessibility'
                $sticky = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path "$a\StickyKeys" -Name 'Flags') 510
                $toggle = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path "$a\ToggleKeys" -Name 'Flags') 62
                $filter = ConvertTo-IgwtIntOrDefault (Get-IgwtRegistryValue -Path "$a\Keyboard Response" -Name 'Flags') 126
                # STICKYKEYS / TOGGLEKEYS = { cbSize, dwFlags }; FILTERKEYS = 6 DWORDs (flags at index 1).
                $null = Invoke-IgwtSystemParametersInfo -Action $script:SPI_SETSTICKYKEYS -UiParam 8 -Buffer @(8, $sticky)
                $null = Invoke-IgwtSystemParametersInfo -Action $script:SPI_SETTOGGLEKEYS -UiParam 8 -Buffer @(8, $toggle)
                if (-not $script:IgwtSettings.TestMode) {
                    Initialize-IgwtNative
                    $fk = [int[]]@(24, 0, 0, 0, 0, 0)
                    if ([iGWindowsTuner.NativeMethods]::SystemParametersInfo($script:SPI_GETFILTERKEYS, 24, $fk, 0)) {
                        $fk[1] = $filter
                        $null = Invoke-IgwtSystemParametersInfo -Action $script:SPI_SETFILTERKEYS -UiParam 24 -Buffer $fk
                    }
                }
            }
            default { Write-IgwtLog -Level Warn -Message "Unknown post-apply hook '$Hook'." }
        }
    } catch {
        Write-IgwtLog -Level Warn -Message "Live refresh '$Hook' failed (a sign-out applies the change): $($_.Exception.Message)"
    }
}

#endregion

#region Check actions (read-only conditions)

function Get-IgwtCheckState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $checker = [string]$Action.checker
    switch ($checker) {
        'HvciRunning' {
            $dg = Get-IgwtDeviceGuardInfo
            if (-not $dg.Available) { return [pscustomobject]@{ Target = 'Memory integrity running'; Current = 'unknown'; Desired = 'running'; State = 'Unknown'; Note = 'Win32_DeviceGuard not available.' } }
            return [pscustomobject]@{ Target = 'Memory integrity (HVCI) running'; Current = $(if ($dg.HvciRunning) { 'running' } else { 'not running' }); Desired = 'running';
                State = $(if ($dg.HvciRunning) { 'On' } else { 'Off' }); Note = 'Becomes active after a reboot.' }
        }
        'HvciNotRunning' {
            $dg = Get-IgwtDeviceGuardInfo
            if (-not $dg.Available) { return [pscustomobject]@{ Target = 'Memory integrity running'; Current = 'unknown'; Desired = 'not running'; State = 'Unknown'; Note = '' } }
            return [pscustomobject]@{ Target = 'Memory integrity (HVCI) running'; Current = $(if ($dg.HvciRunning) { 'running' } else { 'not running' }); Desired = 'not running';
                State = $(if (-not $dg.HvciRunning) { 'On' } else { 'Off' }); Note = 'Becomes inactive after a reboot.' }
        }
        'KernelShadowStacksRunning' {
            $dg = Get-IgwtDeviceGuardInfo
            if (-not $dg.Available) { return [pscustomobject]@{ Target = 'Kernel stack protection running'; Current = 'unknown'; Desired = 'running'; State = 'Unknown'; Note = '' } }
            return [pscustomobject]@{ Target = 'Kernel-mode hardware-enforced stack protection running'; Current = $(if ($dg.KernelShadowStacksRunning) { 'running' } else { 'not running' }); Desired = 'running';
                State = $(if ($dg.KernelShadowStacksRunning) { 'On' } else { 'Off' }); Note = 'Requires memory integrity and a CET-capable CPU; becomes active after a reboot.' }
        }
        'DefaultApp' {
            # Read-only: Windows protects per-user default apps with a hash, so they are changed in Settings.
            $what = $(if ($Action.extension) { [string]$Action.extension } else { [string]$Action.protocol })
            $path = $(if ($Action.extension) { "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Action.extension)\UserChoice" } else { "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($Action.protocol)\UserChoice" })
            $v = Get-IgwtRegistryValue -Path $path -Name 'ProgId'
            $cur = $(if ($v.Exists) { [string]$v.Value } else { '(Windows default)' })
            return [pscustomobject]@{ Target = "Default app for $what"; Current = $cur; Desired = [string]$Action.progId
                State = $(if ($v.Exists -and [string]$v.Value -eq [string]$Action.progId) { 'On' } else { 'Off' }); Note = 'Change it in Settings > Apps > Default apps; Windows does not allow programs to set it.' }
        }
        default { throw "Unknown checker '$checker'." }
    }
}

#endregion

#region Custom handlers

function Get-IgwtDiscoveredGameExes {
    [CmdletBinding()]
    param($Context)
    $games = $null
    if ($Context -and $null -ne $Context.Games) { $games = @($Context.Games) } else { $games = @(Get-IgwtInstalledGames) }
    return @($games | ForEach-Object { $_.ExePath } | Where-Object { $_ } | Select-Object -Unique)
}

$script:IgwtGpuPrefKey = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'

$script:IgwtCustomHandlers = @{

    # Ultimate Performance: duplicate the hidden e9a42b02 scheme once (or reuse an existing copy),
    # activate it, and on revert re-activate the previous scheme and delete only a copy we created.
    UltimatePlan = @{
        Detect = {
            param($Action, $Context)
            $active = Get-IgwtActivePowerScheme
            $schemes = @(Get-IgwtPowerSchemes)
            $cur = $schemes | Where-Object { $_.Guid -eq $active } | Select-Object -First 1
            $isUltimate = ($active -eq $script:IgwtSchemeUltimateBase) -or ($cur -and $cur.ResourceId -eq 19)
            $existing = $schemes | Where-Object { $_.ResourceId -eq 19 -or $_.Guid -eq $script:IgwtSchemeUltimateBase } | Select-Object -First 1
            [pscustomobject]@{
                Target  = 'Active power scheme'
                Current = "$($cur.Name) ($active)"
                Desired = $(if ($existing) { "Ultimate Performance ($($existing.Guid), existing copy reused)" } else { 'Ultimate Performance (new copy of e9a42b02-...)' })
                State   = $(if ($isUltimate) { 'On' } else { 'Off' })
                Note    = 'C-states and turbo stay under BIOS control; idle power use rises.'
            }
        }
        Snapshot = {
            param($Action, $Context)
            @{ previousActive = (Get-IgwtActivePowerScheme) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            if ($Mode -eq 'default') {
                $null = Invoke-IgwtPowerCfg -Arguments @('/setactive', $script:IgwtSchemeBalanced)
                return $null
            }
            $existing = @(Get-IgwtPowerSchemes) | Where-Object { $_.ResourceId -eq 19 } | Select-Object -First 1
            $created = $null
            $target = $null
            if ($existing) { $target = $existing.Guid }
            else {
                $r = Invoke-IgwtPowerCfg -Arguments @('/duplicatescheme', $script:IgwtSchemeUltimateBase)
                $m = [regex]::Matches($r.Output, $script:IgwtGuidPattern) | Where-Object { $_.Value.ToLowerInvariant() -ne $script:IgwtSchemeUltimateBase } | Select-Object -First 1
                if ($r.ExitCode -ne 0 -or -not $m) { throw "powercfg /duplicatescheme failed: $($r.Output)" }
                $target = $m.Value.ToLowerInvariant()
                $created = $target
            }
            $r2 = Invoke-IgwtPowerCfg -Arguments @('/setactive', $target)
            if ($r2.ExitCode -ne 0) { throw "powercfg /setactive failed: $($r2.Output)" }
            return @{ activated = $target; createdGuid = $created }
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            $prev = ([string]$Snapshot.previousActive).ToLowerInvariant()
            if ($prev -match "^$script:IgwtGuidPattern$" -and (Test-IgwtPowerSchemeExists -Guid $prev)) {
                $r = Invoke-IgwtPowerCfg -Arguments @('/setactive', $prev)
                if ($r.ExitCode -ne 0) { throw "powercfg /setactive failed: $($r.Output)" }
            }
            $created = [string]$Snapshot.applied.createdGuid
            if ($created -match "^$script:IgwtGuidPattern$" -and $created -ne $script:IgwtSchemeUltimateBase) {
                if ((Get-IgwtActivePowerScheme) -ne $created.ToLowerInvariant()) {
                    $null = Invoke-IgwtPowerCfg -Arguments @('/delete', $created)
                }
            }
        }
    }

    # Hibernation: powercfg /hibernate off|on. Disabling hibernation also disables Fast Startup.
    Hibernate = @{
        Detect = {
            param($Action, $Context)
            $v = Get-IgwtRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
            $enabled = $v.Exists -and [int]$v.Value -ne 0
            [pscustomobject]@{ Target = 'Hibernation (hiberfil.sys)'; Current = $(if ($enabled) { 'enabled' } else { 'disabled' }); Desired = 'disabled';
                State = $(if ($enabled) { 'Off' } else { 'On' }); Note = 'Turning hibernation off also turns Fast Startup off and deletes hiberfil.sys.' }
        }
        Snapshot = {
            param($Action, $Context)
            $v = Get-IgwtRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
            @{ enabled = ($v.Exists -and [int]$v.Value -ne 0) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            $arg = 'off'
            if ($Mode -eq 'default') { $arg = 'on' }
            $r = Invoke-IgwtPowerCfg -Arguments @('/hibernate', $arg)
            if ($r.ExitCode -ne 0) { throw "powercfg /hibernate $arg failed: $($r.Output)" }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            if ($Snapshot.enabled) {
                $r = Invoke-IgwtPowerCfg -Arguments @('/hibernate', 'on')
                if ($r.ExitCode -ne 0) { throw "powercfg /hibernate on failed: $($r.Output)" }
            }
        }
    }

    # TCP receive window auto-tuning: repair to Normal if another tool disabled it.
    TcpAutoTuning = @{
        Detect = {
            param($Action, $Context)
            $s = Get-NetTCPSetting -SettingName Internet -ErrorAction Stop
            $state = 'Off'
            if ([string]$s.AutoTuningLevelLocal -eq 'Normal') { $state = 'On' }
            if ($s.AutoTuningLevelGroupPolicy -and [string]$s.AutoTuningLevelGroupPolicy -ne 'NotConfigured') { $state = 'ManagedByPolicy' }
            [pscustomobject]@{ Target = 'TCP auto-tuning (Internet template)'; Current = [string]$s.AutoTuningLevelLocal; Desired = 'Normal'; State = $state; Note = 'Normal is the Windows default.' }
        }
        Snapshot = {
            param($Action, $Context)
            @{ level = [string](Get-NetTCPSetting -SettingName Internet -ErrorAction Stop).AutoTuningLevelLocal }
        }
        Apply = {
            param($Action, $Context, $Mode)
            if ([string](Get-NetTCPSetting -SettingName Internet -ErrorAction Stop).AutoTuningLevelLocal -ne 'Normal') {
                Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal -ErrorAction Stop
            }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            $allowed = @('Disabled', 'HighlyRestricted', 'Restricted', 'Normal', 'Experimental')
            $lvl = [string]$Snapshot.level
            if ($allowed -contains $lvl) { Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal $lvl -ErrorAction Stop }
        }
    }

    # Windows Firewall: all profiles on with default inbound Block.
    FirewallProfiles = @{
        Detect = {
            param($Action, $Context)
            foreach ($p in @(Get-NetFirewallProfile -Profile Domain, Private, Public -ErrorAction Stop)) {
                $inboundOk = [string]$p.DefaultInboundAction -in 'Block', 'NotConfigured'
                [pscustomobject]@{ Target = "Firewall profile $($p.Name)"; Current = "enabled=$($p.Enabled) inbound=$($p.DefaultInboundAction)";
                    Desired = 'enabled=True inbound=Block'; State = $(if ([string]$p.Enabled -eq 'True' -and $inboundOk) { 'On' } else { 'Off' });
                    Note = 'NotConfigured inbound means Block (Windows default).' }
            }
        }
        Snapshot = {
            param($Action, $Context)
            $items = foreach ($p in @(Get-NetFirewallProfile -Profile Domain, Private, Public -ErrorAction Stop)) {
                [ordered]@{ name = [string]$p.Name; enabled = [string]$p.Enabled; inbound = [string]$p.DefaultInboundAction }
            }
            @{ profiles = @($items) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            if ($Mode -eq 'default') { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction NotConfigured -ErrorAction Stop }
            else { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -ErrorAction Stop }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            foreach ($p in @($Snapshot.profiles)) {
                if ([string]$p.name -notin 'Domain', 'Private', 'Public') { continue }
                if ([string]$p.enabled -notin 'True', 'False', 'NotConfigured') { continue }
                if ([string]$p.inbound -notin 'Block', 'Allow', 'NotConfigured') { continue }
                Set-NetFirewallProfile -Profile ([string]$p.name) -Enabled ([string]$p.enabled) -DefaultInboundAction ([string]$p.inbound) -ErrorAction Stop
            }
        }
    }

    # Unused Wi-Fi adapter: disable it (never when it carries the active connection).
    WifiAdapter = @{
        Detect = {
            param($Action, $Context)
            $wifi = @(Get-IgwtWifiAdapter)
            if ($wifi.Count -eq 0) {
                return [pscustomobject]@{ Target = 'Wi-Fi adapter'; Current = 'none present'; Desired = 'disabled'; State = 'NotApplicable'; Note = 'No Wi-Fi adapter is present (or it is disabled in firmware).' }
            }
            foreach ($w in $wifi) {
                $note = ''
                if ($w.Status -eq 'Up') { $note = 'This adapter is connected and in use; iG Windows Tuner will not disable it.' }
                [pscustomobject]@{ Target = "Wi-Fi adapter $($w.Name)"; Current = [string]$w.Status; Desired = 'Disabled';
                    State = $(if ($w.Status -eq 'Disabled') { 'On' } else { 'Off' }); Note = $note }
            }
        }
        Snapshot = {
            param($Action, $Context)
            $items = foreach ($w in @(Get-IgwtWifiAdapter)) { [ordered]@{ scope = [string]$w.InterfaceGuid; name = [string]$w.Name; status = [string]$w.Status } }
            @{ adapters = @($items) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            foreach ($w in @(Get-IgwtWifiAdapter)) {
                if ($Mode -eq 'default') { if ($w.Status -eq 'Disabled') { Enable-NetAdapter -Name $w.Name -Confirm:$false -ErrorAction Stop }; continue }
                if ($w.Status -eq 'Up') { throw "Wi-Fi adapter $($w.Name) is connected; refusing to disable the network connection in use." }
                if ($w.Status -ne 'Disabled') { Disable-NetAdapter -Name $w.Name -Confirm:$false -ErrorAction Stop }
            }
            Clear-IgwtCache -Prefix 'net:' -WhatIf:$false
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            $now = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)
            foreach ($i in @($Snapshot.adapters)) {
                $a = $now | Where-Object { [string]$_.InterfaceGuid -eq [string]$i.scope } | Select-Object -First 1
                if (-not $a) { continue }
                if ([string]$i.status -ne 'Disabled' -and $a.Status -eq 'Disabled') { Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop }
            }
        }
    }

    # Per-game GPU preference (High performance) for discovered game executables.
    GameGpuPreference = @{
        Detect = {
            param($Action, $Context)
            $exes = @(Get-IgwtDiscoveredGameExes -Context $Context)
            if ($exes.Count -eq 0) {
                return [pscustomobject]@{ Target = 'Per-game GPU preference'; Current = 'no supported games found'; Desired = 'GpuPreference=2'; State = 'NotApplicable'; Note = '' }
            }
            foreach ($exe in $exes) {
                $cur = Get-IgwtRegistryValue -Path $script:IgwtGpuPrefKey -Name $exe
                $text = $null
                if ($cur.Exists) { $text = [string]$cur.Value }
                $val = Get-IgwtListItemValue -Text $text -Key 'GpuPreference'
                [pscustomobject]@{ Target = "$script:IgwtGpuPrefKey\$exe"; Current = $(if ($cur.Exists) { '"{0}"' -f $text } else { $script:IgwtAbsent });
                    Desired = 'GpuPreference=2 (High performance)'; State = $(if ([string]$val -eq '2') { 'On' } else { 'Off' }); Note = '' }
            }
        }
        Snapshot = {
            param($Action, $Context)
            $items = foreach ($exe in @(Get-IgwtDiscoveredGameExes -Context $Context)) {
                $cur = Get-IgwtRegistryValue -Path $script:IgwtGpuPrefKey -Name $exe
                [ordered]@{ name = $exe; exists = [bool]$cur.Exists; kind = $cur.Kind; value = (ConvertTo-IgwtSerializableValue -Value $cur.Value -Kind $cur.Kind);
                    missingDepth = (Get-IgwtRegistryMissingDepth -Path $script:IgwtGpuPrefKey) }
            }
            @{ items = @($items) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            foreach ($exe in @(Get-IgwtDiscoveredGameExes -Context $Context)) {
                $cur = Get-IgwtRegistryValue -Path $script:IgwtGpuPrefKey -Name $exe
                $text = $null
                if ($cur.Exists) { $text = [string]$cur.Value }
                if ($Mode -eq 'default') { $new = Remove-IgwtListItem -Text $text -Key 'GpuPreference' -WhatIf:$false }
                else { $new = Set-IgwtListItem -Text $text -Key 'GpuPreference' -Value '2' -WhatIf:$false }
                if ($cur.Exists -and $new -eq $text) { continue }
                if ([string]::IsNullOrEmpty($new)) { if ($cur.Exists) { Remove-IgwtRegistryValue -Path $script:IgwtGpuPrefKey -Name $exe } }
                else { Set-IgwtRegistryValue -Path $script:IgwtGpuPrefKey -Name $exe -Kind String -Value $new }
            }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            foreach ($i in @($Snapshot.items)) {
                $name = [string]$i.name
                if ($name -notmatch '^[A-Za-z]:\\.+\.exe$') { Write-IgwtLog -Level Warn -Message "Skipping unexpected GPU preference entry '$name'."; continue }
                Restore-IgwtRegistryItem -Path $script:IgwtGpuPrefKey -Name $name -Item $i
            }
        }
    }

    # Controlled Folder Access allow-list for discovered game executables (helper for Block mode).
    CfaAllowGames = @{
        Detect = {
            param($Action, $Context)
            $exes = @(Get-IgwtDiscoveredGameExes -Context $Context)
            if ($exes.Count -eq 0) {
                return [pscustomobject]@{ Target = 'Controlled Folder Access allowed apps'; Current = 'no supported games found'; Desired = ''; State = 'NotApplicable'; Note = '' }
            }
            $allowed = @((Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }).ControlledFolderAccessAllowedApplications)
            foreach ($exe in $exes) {
                $present = @($allowed | Where-Object { [string]::Equals([string]$_, $exe, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
                [pscustomobject]@{ Target = "CFA allowed app $exe"; Current = $(if ($present) { 'allowed' } else { 'not listed' }); Desired = 'allowed';
                    State = $(if ($present) { 'On' } else { 'Off' }); Note = 'Allow-listing is not an antivirus exclusion; files are still scanned.' }
            }
        }
        Snapshot = {
            param($Action, $Context)
            $allowed = @((Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }).ControlledFolderAccessAllowedApplications)
            $pre = foreach ($exe in @(Get-IgwtDiscoveredGameExes -Context $Context)) {
                if (@($allowed | Where-Object { [string]::Equals([string]$_, $exe, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) { $exe }
            }
            @{ alreadyAllowed = @($pre) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            $allowed = @((Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }).ControlledFolderAccessAllowedApplications)
            $added = New-Object System.Collections.Generic.List[string]
            foreach ($exe in @(Get-IgwtDiscoveredGameExes -Context $Context)) {
                $present = @($allowed | Where-Object { [string]::Equals([string]$_, $exe, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
                if ($Mode -eq 'default') { if ($present) { Remove-MpPreference -ControlledFolderAccessAllowedApplications $exe -ErrorAction Stop }; continue }
                if (-not $present) { Add-MpPreference -ControlledFolderAccessAllowedApplications $exe -ErrorAction Stop; $added.Add($exe) }
            }
            Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false
            return @{ added = @($added) }
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            foreach ($exe in @($Snapshot.applied.added)) {
                if ([string]$exe -notmatch '^[A-Za-z]:\\.+\.exe$') { continue }
                Remove-MpPreference -ControlledFolderAccessAllowedApplications ([string]$exe) -ErrorAction Stop
            }
        }
    }

    # Risk Zone: High Precision Event Timer device (ACPI\PNP0103) disabled.
    HpetDevice = @{
        Detect = {
            param($Action, $Context)
            $d = Get-IgwtHpetDevice
            if (-not $d) { return [pscustomobject]@{ Target = 'High precision event timer device'; Current = 'not present'; Desired = 'Disabled'; State = 'NotApplicable'; Note = 'No HPET device is present (it may be off in firmware).' } }
            $off = Test-IgwtPnpDeviceDisabled -Device $d
            [pscustomobject]@{ Target = "Device $($d.FriendlyName)"; Current = $(if ($off) { 'Disabled' } else { [string]$d.Status }); Desired = 'Disabled'; State = $(if ($off) { 'On' } else { 'Off' }); Note = 'Windows already prefers the invariant TSC.' }
        }
        Snapshot = {
            param($Action, $Context)
            $d = Get-IgwtHpetDevice
            if (-not $d) { return @{ present = $false } }
            @{ present = $true; instanceId = [string]$d.InstanceId; disabled = (Test-IgwtPnpDeviceDisabled -Device $d) }
        }
        Apply = {
            param($Action, $Context, $Mode)
            $d = Get-IgwtHpetDevice
            if (-not $d) { return $null }
            $off = Test-IgwtPnpDeviceDisabled -Device $d
            if ($Mode -eq 'default') { if ($off) { Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop } }
            elseif (-not $off) { Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            if (-not $Snapshot.present) { return }
            $d = Get-IgwtHpetDevice
            if (-not $d -or [string]$d.InstanceId -ne [string]$Snapshot.instanceId) { throw 'The HPET device in the snapshot is not present any more.' }
            $off = Test-IgwtPnpDeviceDisabled -Device $d
            if ([bool]$Snapshot.disabled -and -not $off) { Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop }
            elseif (-not [bool]$Snapshot.disabled -and $off) { Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop }
        }
    }

    # Risk Zone: memory compression off (Memory Management Agent).
    MemoryCompression = @{
        Detect = {
            param($Action, $Context)
            try { $on = [bool](Get-MMAgent -ErrorAction Stop).MemoryCompression }
            catch { return [pscustomobject]@{ Target = 'Memory compression'; Current = 'not readable'; Desired = 'Disabled'; State = 'Unknown'; Note = 'Reading memory compression needs administrator rights.' } }
            [pscustomobject]@{ Target = 'Memory compression'; Current = $(if ($on) { 'Enabled' } else { 'Disabled' }); Desired = 'Disabled'; State = $(if ($on) { 'Off' } else { 'On' }); Note = 'Takes effect after a restart.' }
        }
        Snapshot = {
            param($Action, $Context)
            @{ enabled = [bool](Get-MMAgent -ErrorAction Stop).MemoryCompression }
        }
        Apply = {
            param($Action, $Context, $Mode)
            $on = [bool](Get-MMAgent -ErrorAction Stop).MemoryCompression
            if ($Mode -eq 'default') { if (-not $on) { Enable-MMAgent -MemoryCompression -ErrorAction Stop } }
            elseif ($on) { Disable-MMAgent -MemoryCompression -ErrorAction Stop }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            $on = [bool](Get-MMAgent -ErrorAction Stop).MemoryCompression
            if ([bool]$Snapshot.enabled -and -not $on) { Enable-MMAgent -MemoryCompression -ErrorAction Stop }
            elseif (-not [bool]$Snapshot.enabled -and $on) { Disable-MMAgent -MemoryCompression -ErrorAction Stop }
        }
    }

    # Risk Zone: TCP receive-window auto-tuning disabled (the counterpart of TcpAutoTuning).
    TcpAutoTuningDisabled = @{
        Detect = {
            param($Action, $Context)
            $s = Get-NetTCPSetting -SettingName Internet -ErrorAction Stop
            $state = $(if ([string]$s.AutoTuningLevelLocal -eq 'Disabled') { 'On' } else { 'Off' })
            if ($s.AutoTuningLevelGroupPolicy -and [string]$s.AutoTuningLevelGroupPolicy -ne 'NotConfigured') { $state = 'ManagedByPolicy' }
            [pscustomobject]@{ Target = 'TCP auto-tuning (Internet template)'; Current = [string]$s.AutoTuningLevelLocal; Desired = 'Disabled'; State = $state; Note = 'Normal is the Windows default.' }
        }
        Snapshot = {
            param($Action, $Context)
            @{ level = [string](Get-NetTCPSetting -SettingName Internet -ErrorAction Stop).AutoTuningLevelLocal }
        }
        Apply = {
            param($Action, $Context, $Mode)
            $target = $(if ($Mode -eq 'default') { 'Normal' } else { 'Disabled' })
            if ([string](Get-NetTCPSetting -SettingName Internet -ErrorAction Stop).AutoTuningLevelLocal -ne $target) {
                Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal $target -ErrorAction Stop
            }
            return $null
        }
        Restore = {
            param($Action, $Snapshot, $Context)
            $allowed = @('Disabled', 'HighlyRestricted', 'Restricted', 'Normal', 'Experimental')
            $lvl = [string]$Snapshot.level
            if ($allowed -contains $lvl) { Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal $lvl -ErrorAction Stop }
        }
    }
}

function Get-IgwtHpetDevice {
    <# .SYNOPSIS The High Precision Event Timer device (ACPI\PNP0103), or $null. #>
    [CmdletBinding()]
    param()
    @(Get-PnpDevice -Class System -ErrorAction SilentlyContinue | Where-Object { [string]$_.InstanceId -like 'ACPI\PNP0103*' }) | Select-Object -First 1
}

function Test-IgwtPnpDeviceDisabled {
    <# .SYNOPSIS True when a PnP device is disabled (problem code 22 / CM_PROB_DISABLED). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Device)
    return ([string]$Device.Problem -match 'DISABLED' -or [int]$Device.ConfigManagerErrorCode -eq 22)
}

function Get-IgwtCustomHandler {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $h = $script:IgwtCustomHandlers[$Name]
    if (-not $h) { throw "Unknown custom handler '$Name'." }
    return $h
}

#endregion
