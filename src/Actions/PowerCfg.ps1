# PowerCfg.ps1
# 'powercfgScheme' and 'powercfgSetting' actions through the inbox powercfg.exe.
# Output is parsed only for GUIDs and 0x values, which are not localized.

$script:IgwtSchemeBalanced = '381b4222-f694-41f0-9685-ff5bb260df2e'
$script:IgwtSchemeHighPerformance = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
$script:IgwtSchemeUltimateBase = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
$script:IgwtGuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

function Invoke-IgwtPowerCfg {
    <#
    .SYNOPSIS
        Runs %SystemRoot%\System32\powercfg.exe with the given arguments and returns exit code and output.
        Refuses to run in TestMode (tests must mock this function).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: powercfg.exe must be mocked in tests.' }
    $readOnly = @('/getactivescheme', '/list', '/query', '/q', '/qh', '/l', '/availablesleepstates', '/a')
    $isRead = $readOnly -contains $Arguments[0].ToLowerInvariant()
    if (-not $isRead -and -not $PSCmdlet.ShouldProcess("powercfg.exe $($Arguments -join ' ')", 'Run')) {
        return [pscustomobject]@{ ExitCode = 0; Output = '' }
    }
    $exe = Join-Path $env:SystemRoot 'System32\powercfg.exe'
    if ($isRead) {
        return (Get-IgwtCached -Key ("pc:" + ($Arguments -join ' ')) -ScriptBlock {
                $o = & $exe @Arguments 2>&1 | Out-String
                [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $o }
            })
    }
    $output = & $exe @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    Clear-IgwtCache -Prefix 'pc:' -WhatIf:$false
    return [pscustomobject]@{ ExitCode = $code; Output = $output }
}

function Get-IgwtActivePowerScheme {
    <# .SYNOPSIS GUID (lower case) of the active power scheme. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $r = Invoke-IgwtPowerCfg -Arguments @('/getactivescheme')
    $m = [regex]::Match($r.Output, $script:IgwtGuidPattern)
    if (-not $m.Success) { throw "Could not read the active power scheme: $($r.Output)" }
    return $m.Value.ToLowerInvariant()
}

function Get-IgwtPowerSchemes {
    <# .SYNOPSIS Installed power schemes from the registry, with the powrprof resource id of their name. #>
    [CmdletBinding()]
    param()
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
    $r = Invoke-IgwtPowerCfg -Arguments @('/list')
    $listed = @([regex]::Matches($r.Output, $script:IgwtGuidPattern) | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
    foreach ($g in $listed) {
        $fn = $null
        try { $fn = [string](Get-IgwtRegistryValue -Path "$root\$g" -Name 'FriendlyName').Value } catch { $fn = $null }
        $resId = $null
        if ($fn -match 'powrprof\.dll,-(\d+)') { $resId = [int]$Matches[1] }
        $display = $fn
        if ($fn -and $fn.Contains(',')) { $display = $fn.Substring($fn.LastIndexOf(',') + 1) }
        [pscustomobject]@{ Guid = $g; FriendlyName = $fn; Name = $display; ResourceId = $resId }
    }
}

function Test-IgwtPowerSchemeExists {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Guid)
    return (@(Get-IgwtPowerSchemes | Where-Object { $_.Guid -eq $Guid.ToLowerInvariant() }).Count -gt 0)
}

function Get-IgwtPowerSettingValue {
    <# .SYNOPSIS Current AC/DC index of a setting in a scheme (last two 0x values of powercfg /query). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$Subgroup, [Parameter(Mandatory = $true)][string]$Setting)
    $r = Invoke-IgwtPowerCfg -Arguments @('/query', $Scheme, $Subgroup, $Setting)
    $hex = @([regex]::Matches($r.Output, '0x([0-9a-fA-F]{8})') | ForEach-Object { [Convert]::ToUInt32($_.Groups[1].Value, 16) })
    if ($hex.Count -lt 2) { return $null }
    return [pscustomobject]@{ AC = [int]$hex[$hex.Count - 2]; DC = [int]$hex[$hex.Count - 1] }
}

function Get-IgwtPowerSettingDefault {
    <#
    .SYNOPSIS
        Windows default AC/DC index for a setting in a scheme, from
        HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\<sub>\<setting>\DefaultPowerSchemeValues\<scheme>.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$Subgroup, [Parameter(Mandatory = $true)][string]$Setting)
    $p = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$Subgroup\$Setting\DefaultPowerSchemeValues\$Scheme"
    try {
        $ac = Get-IgwtRegistryValue -Path $p -Name 'ACSettingIndex'
        $dc = Get-IgwtRegistryValue -Path $p -Name 'DCSettingIndex'
        if ($ac.Exists) { return [pscustomobject]@{ AC = [int]$ac.Value; DC = $(if ($dc.Exists) { [int]$dc.Value } else { $null }) } }
    } catch { Write-Verbose "No default power values for $Scheme." }
    return $null
}

#region powercfgScheme

function Get-IgwtPowerCfgSchemeState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $target = ([string]$Action.scheme).ToLowerInvariant()
    $active = Get-IgwtActivePowerScheme
    $schemes = @(Get-IgwtPowerSchemes)
    $activeName = ($schemes | Where-Object { $_.Guid -eq $active } | Select-Object -First 1).Name
    $targetScheme = $schemes | Where-Object { $_.Guid -eq $target } | Select-Object -First 1
    if (-not $targetScheme) {
        return [pscustomobject]@{ Target = 'Active power scheme'; Current = "$activeName ($active)"; Desired = $target; State = 'NotApplicable'; Note = 'This power scheme is not installed on this PC.' }
    }
    [pscustomobject]@{
        Target  = 'Active power scheme'
        Current = "$activeName ($active)"
        Desired = "$($targetScheme.Name) ($target)"
        State   = $(if ($active -eq $target) { 'On' } else { 'Off' })
        Note    = ''
    }
}

function Get-IgwtPowerCfgSchemeSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    return @{ previousActive = (Get-IgwtActivePowerScheme) }
}

function Invoke-IgwtPowerCfgSchemeApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $target = ([string]$Action.scheme).ToLowerInvariant()
    if ($Mode -eq 'default') { $target = $script:IgwtSchemeBalanced }
    if ((Get-IgwtActivePowerScheme) -eq $target) { return }
    if ($PSCmdlet.ShouldProcess($target, 'Activate power scheme')) {
        $r = Invoke-IgwtPowerCfg -Arguments @('/setactive', $target)
        if ($r.ExitCode -ne 0) { throw "powercfg /setactive failed: $($r.Output)" }
    }
}

function Restore-IgwtPowerCfgSchemeSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $prev = ([string]$Snapshot.previousActive).ToLowerInvariant()
    if ($prev -notmatch "^$script:IgwtGuidPattern$") { throw 'Snapshot does not contain a valid scheme GUID.' }
    if (-not (Test-IgwtPowerSchemeExists -Guid $prev)) { Write-IgwtLog -Level Warn -Message "Previous power scheme $prev no longer exists; leaving the current scheme active."; return }
    if ($PSCmdlet.ShouldProcess($prev, 'Re-activate previous power scheme')) {
        $r = Invoke-IgwtPowerCfg -Arguments @('/setactive', $prev)
        if ($r.ExitCode -ne 0) { throw "powercfg /setactive failed: $($r.Output)" }
    }
}

#endregion

#region powercfgSetting

function Get-IgwtPowerCfgSettingState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $scheme = Get-IgwtActivePowerScheme
    $v = Get-IgwtPowerSettingValue -Scheme $scheme -Subgroup $Action.subgroup -Setting $Action.setting
    if (-not $v) {
        return [pscustomobject]@{ Target = "Power setting $($Action.label)"; Current = 'not available'; Desired = ''; State = 'NotApplicable'; Note = 'Setting not exposed by this power scheme or hardware.' }
    }
    $isOn = ($v.AC -eq [int]$Action.ac)
    if ($null -ne $Action.dc) { $isOn = $isOn -and ($v.DC -eq [int]$Action.dc) }
    $desired = "AC=$($Action.ac)"
    if ($null -ne $Action.dc) { $desired += " DC=$($Action.dc)" }
    [pscustomobject]@{
        Target  = "Power setting $($Action.label) (active plan $scheme)"
        Current = "AC=$($v.AC) DC=$($v.DC)"
        Desired = $desired
        State   = $(if ($isOn) { 'On' } else { 'Off' })
        Note    = 'Applies to the plan that is active at apply time.'
    }
}

function Get-IgwtPowerCfgSettingSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $scheme = Get-IgwtActivePowerScheme
    $v = Get-IgwtPowerSettingValue -Scheme $scheme -Subgroup $Action.subgroup -Setting $Action.setting
    $ac = $null; $dc = $null
    if ($v) { $ac = $v.AC; $dc = $v.DC }
    return @{ scheme = $scheme; ac = $ac; dc = $dc }
}

function Set-IgwtPowerSettingIndex {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$Subgroup, [Parameter(Mandatory = $true)][string]$Setting, $AC, $DC)
    if (-not $PSCmdlet.ShouldProcess("$Scheme $Subgroup $Setting", "Set AC=$AC DC=$DC")) { return }
    if ($null -ne $AC) {
        $r = Invoke-IgwtPowerCfg -Arguments @('/setacvalueindex', $Scheme, $Subgroup, $Setting, ([string][int]$AC))
        if ($r.ExitCode -ne 0) { throw "powercfg /setacvalueindex failed: $($r.Output)" }
    }
    if ($null -ne $DC) {
        $r = Invoke-IgwtPowerCfg -Arguments @('/setdcvalueindex', $Scheme, $Subgroup, $Setting, ([string][int]$DC))
        if ($r.ExitCode -ne 0) { throw "powercfg /setdcvalueindex failed: $($r.Output)" }
    }
    if ((Get-IgwtActivePowerScheme) -eq $Scheme) {
        # Re-activating the scheme makes the new index effective immediately.
        $null = Invoke-IgwtPowerCfg -Arguments @('/setactive', $Scheme)
    }
}

function Invoke-IgwtPowerCfgSettingApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $scheme = Get-IgwtActivePowerScheme
    if ($Mode -eq 'default') {
        $def = Get-IgwtPowerSettingDefault -Scheme $scheme -Subgroup $Action.subgroup -Setting $Action.setting
        if (-not $def -and $Action.defaultFromScheme) {
            $def = Get-IgwtPowerSettingDefault -Scheme ([string]$Action.defaultFromScheme) -Subgroup $Action.subgroup -Setting $Action.setting
        }
        if (-not $def) { $def = [pscustomobject]@{ AC = $Action.defaultAc; DC = $Action.defaultDc } }
        if ($null -eq $def.AC) { throw "No documented default for power setting $($Action.label)." }
        Set-IgwtPowerSettingIndex -Scheme $scheme -Subgroup $Action.subgroup -Setting $Action.setting -AC $def.AC -DC $def.DC
        return
    }
    $dc = $null
    if ($null -ne $Action.dc) { $dc = $Action.dc }
    Set-IgwtPowerSettingIndex -Scheme $scheme -Subgroup $Action.subgroup -Setting $Action.setting -AC $Action.ac -DC $dc
}

function Restore-IgwtPowerCfgSettingSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $scheme = ([string]$Snapshot.scheme).ToLowerInvariant()
    if ($scheme -notmatch "^$script:IgwtGuidPattern$") { throw 'Snapshot does not contain a valid scheme GUID.' }
    if ($null -eq $Snapshot.ac) { return }
    if (-not (Test-IgwtPowerSchemeExists -Guid $scheme)) { Write-IgwtLog -Level Warn -Message "Power scheme $scheme no longer exists; $($Action.label) not restored."; return }
    Set-IgwtPowerSettingIndex -Scheme $scheme -Subgroup $Action.subgroup -Setting $Action.setting -AC $Snapshot.ac -DC $Snapshot.dc
}

#endregion
