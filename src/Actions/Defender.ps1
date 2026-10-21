# Defender.ps1
# 'mpPreference' action: Microsoft Defender Antivirus preferences through Set-MpPreference.
# Only an explicit allow-list of settings can be changed, and none of them lowers protection.
# iG Windows Tuner never touches real-time protection, Tamper Protection, AMSI or exclusions.

$script:IgwtMpAllowed = @{
    PUAProtection                 = 'int'
    MAPSReporting                 = 'int'
    SubmitSamplesConsent          = 'int'
    EnableNetworkProtection       = 'int'
    EnableControlledFolderAccess  = 'int'
    ScanOnlyIfIdleEnabled         = 'bool'
    ScanAvgCPULoadFactor          = 'int'
}

function Test-IgwtDefenderActive {
    <# .SYNOPSIS True when Microsoft Defender Antivirus is the active antivirus (not passive or off). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $s = Get-IgwtCached -Key 'mp:status' -TtlSeconds 10 -ScriptBlock { Get-MpComputerStatus -ErrorAction Stop }
        return ([bool]$s.AMServiceEnabled -and ([string]$s.AMRunningMode -eq 'Normal' -or [string]::IsNullOrEmpty([string]$s.AMRunningMode)))
    } catch { return $false }
}

function ConvertTo-IgwtMpValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Setting, $Value)
    $t = $script:IgwtMpAllowed[$Setting]
    if (-not $t) { throw "Defender setting '$Setting' is not on iG Windows Tuner's allow-list." }
    if ($t -eq 'bool') {
        if ($Value -is [string]) { return [bool]::Parse($Value) }
        return [bool]$Value
    }
    return [int]$Value
}

function Get-IgwtMpPreferenceValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Setting)
    $null = ConvertTo-IgwtMpValue -Setting $Setting -Value 0
    $pref = Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }
    $raw = $pref.$Setting
    if ($null -eq $raw) { return $null }
    if ($script:IgwtMpAllowed[$Setting] -eq 'bool') { return [bool]$raw }
    return [int]$raw
}

function Get-IgwtMpPreferenceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $setting = [string]$Action.setting
    if (-not (Test-IgwtDefenderActive)) {
        return [pscustomobject]@{ Target = "Defender $setting"; Current = 'Defender not active'; Desired = [string]$Action.on; State = 'NotApplicable'; Note = 'Microsoft Defender Antivirus is not the active antivirus.' }
    }
    try { $cur = Get-IgwtMpPreferenceValue -Setting $setting } catch {
        return [pscustomobject]@{ Target = "Defender $setting"; Current = 'unreadable'; Desired = [string]$Action.on; State = 'Unknown'; Note = $_.Exception.Message }
    }
    $desired = ConvertTo-IgwtMpValue -Setting $setting -Value $Action.on
    $isOn = ($null -ne $cur -and $cur -eq $desired)
    if (-not $isOn -and $null -ne $cur -and $null -ne $Action.equivalentOn) {
        foreach ($eq in @($Action.equivalentOn)) { if ($cur -eq (ConvertTo-IgwtMpValue -Setting $setting -Value $eq)) { $isOn = $true } }
    }
    [pscustomobject]@{
        Target  = "Defender preference $setting"
        Current = [string]$cur
        Desired = [string]$desired
        State   = $(if ($isOn) { 'On' } else { 'Off' })
        Note    = ''
    }
}

function Get-IgwtMpPreferenceSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    return @{ setting = [string]$Action.setting; value = (Get-IgwtMpPreferenceValue -Setting ([string]$Action.setting)) }
}

function Set-IgwtMpPreferenceValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Setting, [Parameter(Mandatory = $true)]$Value)
    $v = ConvertTo-IgwtMpValue -Setting $Setting -Value $Value
    if (-not $PSCmdlet.ShouldProcess("Defender $Setting", "Set to $v")) { return }
    $params = @{ ErrorAction = 'Stop' }
    $params[$Setting] = $v
    try { Set-MpPreference @params } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
}

function Invoke-IgwtMpPreferenceApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $target = $Action.on
    if ($Mode -eq 'default') { $target = $Action.default }
    if ($null -eq $target) { throw "No default defined for Defender $($Action.setting)." }
    $cur = Get-IgwtMpPreferenceValue -Setting ([string]$Action.setting)
    if ($null -ne $cur -and $cur -eq (ConvertTo-IgwtMpValue -Setting ([string]$Action.setting) -Value $target)) { return }
    Set-IgwtMpPreferenceValue -Setting ([string]$Action.setting) -Value $target
}

function Restore-IgwtMpPreferenceSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if ($null -eq $Snapshot.value) { return }
    Set-IgwtMpPreferenceValue -Setting ([string]$Action.setting) -Value $Snapshot.value
}
