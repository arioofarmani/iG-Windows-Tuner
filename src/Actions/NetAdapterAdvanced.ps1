# NetAdapterAdvanced.ps1
# 'netAdapterAdvanced' action: driver advanced properties addressed by their standardized
# RegistryKeyword (*EEE, *InterruptModeration, *RSS, ...). Display names are localized and
# vendor-specific, so they are only used as a fallback when the keyword is not exposed.
# Changes are written with -NoRestart; the new value takes effect after the adapter restarts
# (or after a reboot), so an active connection or Remote Desktop session is never dropped.

function Get-IgwtAdapterAdvancedProperty {
    <#
    .SYNOPSIS
        Finds the advanced property on one adapter: by RegistryKeyword first, then by fallback
        display names. Returns $null when the adapter does not expose it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Adapter, [Parameter(Mandatory = $true)]$Action)
    $props = @()
    try { $props = @(Get-IgwtCached -Key "na:$($Adapter.Name)" -ScriptBlock { @(Get-NetAdapterAdvancedProperty -Name $Adapter.Name -AllProperties -ErrorAction Stop) }) } catch { return $null }
    $byKeyword = $props | Where-Object { $_.RegistryKeyword -eq [string]$Action.keyword } | Select-Object -First 1
    if ($byKeyword) { return [pscustomobject]@{ Property = $byKeyword; Mode = 'keyword'; OnValue = [string]$Action.on } }
    foreach ($fb in @($Action.fallback)) {
        if (-not $fb) { continue }
        $p = $props | Where-Object { $_.DisplayName -eq [string]$fb.displayName } | Select-Object -First 1
        if ($p) { return [pscustomobject]@{ Property = $p; Mode = 'displayName'; OnValue = [string]$fb.displayValue } }
    }
    return $null
}

function Get-IgwtAdapterPropertyCurrent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Found)
    if ($Found.Mode -eq 'keyword') { return [string](@($Found.Property.RegistryValue)[0]) }
    return [string]$Found.Property.DisplayValue
}

function Get-IgwtNetAdapterAdvancedState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $adapters = @()
    if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
    if ($adapters.Count -eq 0) {
        return @([pscustomobject]@{ Target = "Adapter property $($Action.keyword)"; Current = 'no active wired adapter'; Desired = ''; State = 'NotApplicable'; Note = '' })
    }
    foreach ($a in $adapters) {
        $found = Get-IgwtAdapterAdvancedProperty -Adapter $a -Action $Action
        if (-not $found) {
            [pscustomobject]@{ Target = "[$($a.Name)] $($Action.keyword)"; Current = 'not exposed by driver'; Desired = [string]$Action.on; State = 'NotApplicable'; Note = 'The driver does not offer this property.' }
            continue
        }
        $cur = Get-IgwtAdapterPropertyCurrent -Found $found
        $label = $found.Property.RegistryKeyword
        if ($found.Mode -eq 'displayName') { $label = "$($found.Property.DisplayName) (vendor name)" }
        [pscustomobject]@{
            Target  = "[$($a.Name)] $label"
            Current = "$cur ($($found.Property.DisplayValue))"
            Desired = $found.OnValue
            State   = $(if ($cur -eq $found.OnValue) { 'On' } else { 'Off' })
            Note    = 'Takes effect after the adapter restarts or after a reboot.'
        }
    }
}

function Get-IgwtNetAdapterAdvancedSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $adapters = @()
    if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
    $items = foreach ($a in $adapters) {
        $found = Get-IgwtAdapterAdvancedProperty -Adapter $a -Action $Action
        if (-not $found) { continue }
        [ordered]@{
            scope       = [string]$a.InterfaceGuid
            adapter     = [string]$a.Name
            mode        = $found.Mode
            keyword     = [string]$found.Property.RegistryKeyword
            displayName = [string]$found.Property.DisplayName
            value       = (Get-IgwtAdapterPropertyCurrent -Found $found)
        }
    }
    return @{ items = @($items) }
}

function Set-IgwtAdapterPropertyValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$AdapterName, [string]$Keyword, [string]$DisplayName, [Parameter(Mandatory = $true)][string]$Mode, [Parameter(Mandatory = $true)][string]$Value)
    if (-not $PSCmdlet.ShouldProcess("$AdapterName $Keyword$DisplayName", "Set advanced property to $Value (no adapter restart)")) { return }
    try {
        if ($Mode -eq 'keyword') {
            Set-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $Keyword -RegistryValue $Value -NoRestart -ErrorAction Stop
        } else {
            Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -DisplayValue $Value -NoRestart -ErrorAction Stop
        }
    } finally { Clear-IgwtCache -Prefix 'na:' -WhatIf:$false }
}

function Invoke-IgwtNetAdapterAdvancedApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $adapters = @()
    if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
    foreach ($a in $adapters) {
        $found = Get-IgwtAdapterAdvancedProperty -Adapter $a -Action $Action
        if (-not $found) { continue }
        $target = $found.OnValue
        if ($Mode -eq 'default') {
            if ($found.Mode -ne 'keyword' -or $null -eq $Action.default) { continue }
            $target = [string]$Action.default
        }
        if ((Get-IgwtAdapterPropertyCurrent -Found $found) -eq $target) { continue }
        Set-IgwtAdapterPropertyValue -AdapterName $a.Name -Keyword $found.Property.RegistryKeyword -DisplayName $found.Property.DisplayName -Mode $found.Mode -Value $target
    }
}

function Restore-IgwtNetAdapterAdvancedSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop) } catch { $adapters = @() }
    foreach ($item in @($Snapshot.items)) {
        $a = $adapters | Where-Object { [string]$_.InterfaceGuid -eq [string]$item.scope } | Select-Object -First 1
        if (-not $a) { Write-IgwtLog -Level Warn -Message "Adapter $($item.adapter) is no longer present; $($item.keyword) not restored."; continue }
        $keyword = [string]$item.keyword
        if ([string]$item.mode -ne 'keyword') { $keyword = '' }
        Set-IgwtAdapterPropertyValue -AdapterName $a.Name -Keyword $keyword -DisplayName ([string]$item.displayName) -Mode ([string]$item.mode) -Value ([string]$item.value)
    }
}
