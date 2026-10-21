# RestorePoint.ps1
# System Restore point before every apply (in addition to the JSON snapshot).
# Uses the documented WMI class root\default:SystemRestore so it works in Windows PowerShell 5.1
# and PowerShell 7. The 24-hour creation limit is lifted only for the duration of the call by
# setting SystemRestorePointCreationFrequency to 0, then the exact previous value is restored.

$script:IgwtSystemRestoreKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'

function Test-IgwtSystemProtectionEnabled {
    <# .SYNOPSIS True when System Protection is on for the system drive. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $v = Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -Name '{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}'
        if (-not $v.Exists) { return $false }
        $drive = ($env:SystemDrive).TrimEnd(':')
        foreach ($line in @($v.Value)) { if ([string]$line -match "\($drive%3A\)") { return $true } }
        return $false
    } catch { return $false }
}

function Enable-IgwtSystemProtection {
    <# .SYNOPSIS Turns on System Protection for the system drive (only called after explicit consent). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not $PSCmdlet.ShouldProcess("$env:SystemDrive\", 'Enable System Protection')) { return $false }
    $r = Invoke-CimMethod -Namespace 'root/default' -ClassName SystemRestore -MethodName Enable -Arguments @{ Drive = "$env:SystemDrive\" } -ErrorAction Stop
    if ([int]$r.ReturnValue -ne 0) { throw "Enabling System Protection failed (code $($r.ReturnValue))." }
    Write-IgwtLog -Message "System Protection enabled on $env:SystemDrive (user consent)."
    return $true
}

function New-IgwtRestorePoint {
    <#
    .SYNOPSIS
        Creates a restore point. Returns an object with Created (bool) and Reason.
    .PARAMETER Description
        Restore point description.
    .PARAMETER EnableSystemProtection
        Consent to turn on System Protection for the system drive if it is off.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Description = 'iG Windows Tuner: before applying changes', [switch]$EnableSystemProtection)
    if (-not (Test-IgwtSystemProtectionEnabled)) {
        if (-not $EnableSystemProtection) {
            return [pscustomobject]@{ Created = $false; Reason = 'SystemProtectionDisabled' }
        }
        try { $null = Enable-IgwtSystemProtection } catch { return [pscustomobject]@{ Created = $false; Reason = "EnableFailed: $($_.Exception.Message)" } }
    }
    if (-not $PSCmdlet.ShouldProcess($Description, 'Create System Restore point')) { return [pscustomobject]@{ Created = $false; Reason = 'WhatIf' } }

    $before = Get-IgwtRegistryValue -Path $script:IgwtSystemRestoreKey -Name 'SystemRestorePointCreationFrequency'
    $missing = Get-IgwtRegistryMissingDepth -Path $script:IgwtSystemRestoreKey
    $item = @{ exists = $before.Exists; kind = $before.Kind; value = (ConvertTo-IgwtSerializableValue -Value $before.Value -Kind $before.Kind); missingDepth = $missing }
    try {
        Set-IgwtRegistryValue -Path $script:IgwtSystemRestoreKey -Name 'SystemRestorePointCreationFrequency' -Kind DWord -Value 0
        # RestorePointType 12 = MODIFY_SETTINGS, EventType 100 = BEGIN_SYSTEM_CHANGE
        $r = Invoke-CimMethod -Namespace 'root/default' -ClassName SystemRestore -MethodName CreateRestorePoint -Arguments @{
            Description = $Description; RestorePointType = [uint32]12; EventType = [uint32]100 } -ErrorAction Stop
        if ([int]$r.ReturnValue -ne 0) { return [pscustomobject]@{ Created = $false; Reason = "CreateRestorePoint returned $($r.ReturnValue)" } }
        Write-IgwtLog -Message "System Restore point created: $Description"
        return [pscustomobject]@{ Created = $true; Reason = '' }
    } catch {
        return [pscustomobject]@{ Created = $false; Reason = $_.Exception.Message }
    } finally {
        try { Restore-IgwtRegistryItem -Path $script:IgwtSystemRestoreKey -Name 'SystemRestorePointCreationFrequency' -Item $item }
        catch { Write-IgwtLog -Level Warn -Message "Could not restore SystemRestorePointCreationFrequency: $($_.Exception.Message)" }
    }
}
