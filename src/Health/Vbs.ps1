# Vbs.ps1
# Virtualization-based security, memory integrity (HVCI), kernel stack protection and DMA
# protection from Win32_DeviceGuard (documented values, see learn.microsoft.com
# "Enable memory integrity" > "Validate enabled VBS and memory integrity features").

function Get-IgwtDeviceGuardInfo {
    <# .SYNOPSIS Parsed Win32_DeviceGuard. Available = $false when the class cannot be queried. #>
    [CmdletBinding()]
    param()
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Available = $false; VbsStatus = $null; HvciRunning = $false; HvciConfigured = $false; CredentialGuardRunning = $false;
            KernelShadowStacksRunning = $false; DmaProtectionAvailable = $false; SecureBootAvailable = $false; HypervisorAvailable = $false; MbecAvailable = $false; Error = $_.Exception.Message }
    }
    $avail = @($dg.AvailableSecurityProperties | ForEach-Object { [int]$_ })
    $running = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
    $configured = @($dg.SecurityServicesConfigured | ForEach-Object { [int]$_ })
    [pscustomobject]@{
        Available                 = $true
        VbsStatus                 = [int]$dg.VirtualizationBasedSecurityStatus   # 0 off, 1 enabled not running, 2 running
        HvciRunning               = ($running -contains 2)
        HvciConfigured            = ($configured -contains 2)
        CredentialGuardRunning    = ($running -contains 1)
        KernelShadowStacksRunning = ($running -contains 5)
        HvptRunning               = ($running -contains 7)
        DmaProtectionAvailable    = ($avail -contains 3)
        SecureBootAvailable       = ($avail -contains 2)
        HypervisorAvailable       = ($avail -contains 1)
        MbecAvailable             = ($avail -contains 7)
        CodeIntegrityPolicy       = [int]$dg.CodeIntegrityPolicyEnforcementStatus
        Error                     = $null
    }
}

function Get-IgwtBootFlags {
    <#
    .SYNOPSIS
        Read-only view of the boot options Windows started with (HKLM\SYSTEM\CurrentControlSet\Control
        SystemStartOptions). Detects test signing, kernel debugging and disabled integrity checks
        without ever touching BCD.
    #>
    [CmdletBinding()]
    param([string]$StartOptions)
    if (-not $PSBoundParameters.ContainsKey('StartOptions')) {
        try { $StartOptions = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SystemStartOptions -ErrorAction Stop).SystemStartOptions } catch { $StartOptions = '' }
    }
    $tokens = @($StartOptions.Trim() -split '\s+' | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() })
    [pscustomobject]@{
        Raw              = $StartOptions
        TestSigning      = ($tokens -contains 'TESTSIGNING')
        KernelDebug      = (@($tokens | Where-Object { $_ -eq 'DEBUG' -or $_ -like 'DEBUGPORT=*' -or $_ -like 'DEBUG=*' }).Count -gt 0)
        NoIntegrityCheck = ($tokens -contains 'DISABLE_INTEGRITY_CHECKS')
    }
}

function Get-IgwtVbsChecks {
    [CmdletBinding()]
    param()
    $dg = Get-IgwtDeviceGuardInfo
    $src = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
    if (-not $dg.Available) {
        return @([pscustomobject]@{ Section = 'Security'; Id = 'vbs'; Name = 'Virtualization-based security'; Status = 'Unknown'; Value = 'unavailable'; Detail = $dg.Error; Advice = ''; Source = $src })
    }
    $vbsText = switch ($dg.VbsStatus) { 0 { 'Off' } 1 { 'Enabled, not running' } 2 { 'Running' } default { "Status $($dg.VbsStatus)" } }
    @(
        [pscustomobject]@{ Section = 'Security'; Id = 'vbs'; Name = 'Virtualization-based security (VBS)'; Status = $(if ($dg.VbsStatus -eq 2) { 'Pass' } else { 'Fail' }); Value = $vbsText
            Detail = 'Required by FACEIT AC (for IOMMU) and Vanguard On-Demand.'; Advice = $(if ($dg.VbsStatus -ne 2) { 'Enable virtualization (Intel VT-x/VT-d) in BIOS and turn on Memory integrity in Windows Security.' } else { '' }); Source = $src }
        [pscustomobject]@{ Section = 'Security'; Id = 'hvci'; Name = 'Memory integrity (HVCI)'; Status = $(if ($dg.HvciRunning) { 'Pass' } elseif ($dg.HvciConfigured) { 'Warn' } else { 'Fail' })
            Value = $(if ($dg.HvciRunning) { 'Running' } elseif ($dg.HvciConfigured) { 'Configured, not running (reboot?)' } else { 'Off' }); Detail = 'Required by Vanguard On-Demand; keep it on.'; Advice = ''; Source = $src }
        [pscustomobject]@{ Section = 'Security'; Id = 'iommu'; Name = 'IOMMU / DMA protection available'; Status = $(if ($dg.DmaProtectionAvailable) { 'Pass' } else { 'Warn' })
            Value = $(if ($dg.DmaProtectionAvailable) { 'Available' } else { 'Not reported' }); Detail = 'Win32_DeviceGuard AvailableSecurityProperties contains 3 (DMA protection). msinfo32 shows "Kernel DMA Protection" for confirmation.'
            Advice = $(if (-not $dg.DmaProtectionAvailable) { 'Enable Intel VT-d in BIOS (Gigabyte: Settings > Miscellaneous > Intel VT-d Technology).' } else { '' }); Source = $src }
        [pscustomobject]@{ Section = 'Security'; Id = 'kss'; Name = 'Kernel-mode hardware-enforced stack protection'; Status = 'Info'; Value = $(if ($dg.KernelShadowStacksRunning) { 'Running' } else { 'Off' })
            Detail = 'Optional extra protection; some older anti-cheat drivers were incompatible.'; Advice = ''; Source = 'https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection' }
    )
}
