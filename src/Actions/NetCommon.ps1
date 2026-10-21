# NetCommon.ps1
# Adapter discovery shared by the network actions. Only the active physical wired adapter is
# ever targeted; virtual, VPN, tunnel and hypervisor adapters are skipped.

$script:IgwtVirtualAdapterPattern = 'VPN|Virtual|TAP-|TAP |Hyper-V|VMware|VirtualBox|WireGuard|Wintun|Npcap|Loopback|Bluetooth|Tailscale|ZeroTier|Kernel Debug|WAN Miniport|Teredo|IP-HTTPS|6to4'
$script:IgwtNetClassGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}'

function Get-IgwtActiveWiredAdapter {
    <# .SYNOPSIS Physical Ethernet adapters that are Up, excluding virtual/VPN adapters. #>
    [CmdletBinding()]
    param()
    $all = @()
    try { $all = @(Get-IgwtCached -Key 'net:physical' -ScriptBlock { @(Get-NetAdapter -Physical -ErrorAction Stop) }) } catch { return @() }
    $result = foreach ($a in $all) {
        if ($a.Status -ne 'Up') { continue }
        if ($a.Virtual) { continue }
        if ($a.InterfaceDescription -match $script:IgwtVirtualAdapterPattern) { continue }
        $isEthernet = ([string]$a.PhysicalMediaType -eq '802.3') -or ([int]$a.NdisPhysicalMedium -eq 14)
        if (-not $isEthernet) { continue }
        $a
    }
    return @($result)
}

function Get-IgwtWifiAdapter {
    <# .SYNOPSIS Physical Wi-Fi adapters (any status except Not Present). #>
    [CmdletBinding()]
    param()
    $all = @()
    try { $all = @(Get-NetAdapter -Physical -ErrorAction Stop) } catch { return @() }
    $result = foreach ($a in $all) {
        $isWifi = ([string]$a.PhysicalMediaType -match '802\.11') -or ([int]$a.NdisPhysicalMedium -eq 9)
        if ($isWifi -and $a.Status -ne 'Not Present') { $a }
    }
    return @($result)
}

function Get-IgwtAdapterClassKey {
    <#
    .SYNOPSIS
        Registry path of the adapter's driver key under the network class
        (HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}\NNNN), matched by NetCfgInstanceId.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$InterfaceGuid)
    $classPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$script:IgwtNetClassGuid"
    $keys = Get-ChildItem -LiteralPath $classPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
    foreach ($k in $keys) {
        try {
            $id = $k.GetValue('NetCfgInstanceId')
            if ($id -and [string]::Equals([string]$id, $InterfaceGuid, [System.StringComparison]::OrdinalIgnoreCase)) {
                return "$classPath\$($k.PSChildName)"
            }
        } catch { Write-Verbose "Skipping unreadable class key $($k.PSChildName)." }
    }
    return $null
}

function Get-IgwtAdapterIdentity {
    <# .SYNOPSIS Short label for logs and diffs. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Adapter)
    return "$($Adapter.Name) ($($Adapter.InterfaceDescription))"
}
