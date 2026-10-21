# Dns.ps1
# 'dnsDoh' action: points the active wired adapter at a public resolver that is on Windows'
# built-in DNS-over-HTTPS list and turns on DoH auto-upgrade for those addresses with the
# supported DnsClient cmdlets. Revert restores the previous DHCP or static DNS servers and the
# previous DoH entry settings exactly.

$script:IgwtDohProviders = @{
    cloudflare = @{ Name = 'Cloudflare'; V4 = @('1.1.1.1', '1.0.0.1'); V6 = @('2606:4700:4700::1111', '2606:4700:4700::1001'); Template = 'https://cloudflare-dns.com/dns-query' }
    quad9      = @{ Name = 'Quad9'; V4 = @('9.9.9.9', '149.112.112.112'); V6 = @('2620:fe::fe', '2620:fe::9'); Template = 'https://dns.quad9.net/dns-query' }
}

function Get-IgwtDohProvider {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Provider)
    $p = $script:IgwtDohProviders[$Provider.ToLowerInvariant()]
    if (-not $p) { throw "Unknown DoH provider '$Provider'." }
    return $p
}

function Test-IgwtAdapterHasGlobalIPv6 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)
    try {
        $v6 = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object { $_.PrefixOrigin -in 'RouterAdvertisement', 'Dhcp', 'Manual' -and $_.IPAddress -notlike 'fe80*' })
        return ($v6.Count -gt 0)
    } catch { return $false }
}

function Get-IgwtDnsInterfaceConfig {
    <# .SYNOPSIS Current DNS servers of one interface and whether they are static or from DHCP. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Adapter)
    $v4 = @(); $v6 = @()
    try { $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses) } catch { $v4 = @() }
    try { $v6 = @((Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv6 -ErrorAction Stop).ServerAddresses) } catch { $v6 = @() }
    $static4 = $null
    $static6 = $null
    try { $static4 = (Get-IgwtRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($Adapter.InterfaceGuid)" -Name 'NameServer').Value } catch { $static4 = $null }
    try { $static6 = (Get-IgwtRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($Adapter.InterfaceGuid)" -Name 'NameServer').Value } catch { $static6 = $null }
    [pscustomobject]@{
        V4       = @($v4 | Where-Object { $_ })
        V6       = @($v6 | Where-Object { $_ })
        Static4  = -not [string]::IsNullOrWhiteSpace([string]$static4)
        Static6  = -not [string]::IsNullOrWhiteSpace([string]$static6)
    }
}

function Get-IgwtDohEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Address)
    try { return (Get-DnsClientDohServerAddress -ServerAddress $Address -ErrorAction Stop | Select-Object -First 1) } catch { return $null }
}

function Get-IgwtDnsDohState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $prov = Get-IgwtDohProvider -Provider $Action.provider
    $adapters = @()
    if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
    if ($adapters.Count -eq 0) {
        return @([pscustomobject]@{ Target = 'DNS servers'; Current = 'no active wired adapter'; Desired = ''; State = 'NotApplicable'; Note = '' })
    }
    $fallback = [bool]$Action.allowFallbackToUdp
    foreach ($a in $adapters) {
        $cfg = Get-IgwtDnsInterfaceConfig -Adapter $a
        $serversOk = ((@($cfg.V4) -join ',') -eq (@($prov.V4) -join ','))
        $dohOk = $true
        foreach ($ip in $prov.V4) {
            $e = Get-IgwtDohEntry -Address $ip
            if (-not $e -or -not $e.AutoUpgrade -or ([bool]$e.AllowFallbackToUdp -ne $fallback)) { $dohOk = $false }
        }
        $note = ''
        $private = @($cfg.V4 | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' })
        if ($private.Count -gt 0) { $note = 'Your current DNS server is on your local network (router). DoH bypasses router DNS, local host names and router-side filtering.' }
        [pscustomobject]@{
            Target  = "[$($a.Name)] DNS servers + DoH"
            Current = "$(if ($cfg.Static4) { 'static' } else { 'DHCP' }): $(@($cfg.V4) -join ', ')"
            Desired = "$($prov.Name): $($prov.V4 -join ', ') (DoH auto-upgrade, fallback to plain DNS: $fallback)"
            State   = $(if ($serversOk -and $dohOk) { 'On' } else { 'Off' })
            Note    = $note
        }
    }
}

function Get-IgwtDnsDohSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $prov = Get-IgwtDohProvider -Provider $Action.provider
    $adapters = @()
    if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
    $ifaces = foreach ($a in $adapters) {
        $cfg = Get-IgwtDnsInterfaceConfig -Adapter $a
        [ordered]@{ scope = [string]$a.InterfaceGuid; adapter = [string]$a.Name; static4 = $cfg.Static4; v4 = @($cfg.V4); static6 = $cfg.Static6; v6 = @($cfg.V6) }
    }
    $doh = foreach ($ip in @($prov.V4 + $prov.V6)) {
        $e = Get-IgwtDohEntry -Address $ip
        if ($e) { [ordered]@{ address = $ip; exists = $true; template = [string]$e.DohTemplate; autoUpgrade = [bool]$e.AutoUpgrade; fallback = [bool]$e.AllowFallbackToUdp } }
        else { [ordered]@{ address = $ip; exists = $false } }
    }
    return @{ interfaces = @($ifaces); doh = @($doh) }
}

function Invoke-IgwtDnsDohApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $prov = Get-IgwtDohProvider -Provider $Action.provider
    $adapters = @()
    if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
    if ($Mode -eq 'default') {
        foreach ($a in $adapters) {
            if ($PSCmdlet.ShouldProcess($a.Name, 'Reset DNS servers to DHCP')) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop }
        }
        return
    }
    $fallback = [bool]$Action.allowFallbackToUdp
    foreach ($ip in @($prov.V4 + $prov.V6)) {
        $e = Get-IgwtDohEntry -Address $ip
        if ($e) {
            if (-not $e.AutoUpgrade -or [bool]$e.AllowFallbackToUdp -ne $fallback) {
                if ($PSCmdlet.ShouldProcess($ip, 'Enable DoH auto-upgrade')) {
                    $null = Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $e.DohTemplate -AutoUpgrade $true -AllowFallbackToUdp $fallback -ErrorAction Stop
                }
            }
        } elseif ($PSCmdlet.ShouldProcess($ip, 'Add DoH server entry')) {
            $null = Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $prov.Template -AutoUpgrade $true -AllowFallbackToUdp $fallback -ErrorAction Stop
        }
    }
    foreach ($a in $adapters) {
        $servers = @($prov.V4)
        if (Test-IgwtAdapterHasGlobalIPv6 -InterfaceIndex $a.ifIndex) { $servers += $prov.V6 }
        if ($PSCmdlet.ShouldProcess($a.Name, "Set DNS servers to $($servers -join ', ')")) {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
        }
    }
}

function Restore-IgwtDnsDohSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $prov = Get-IgwtDohProvider -Provider $Action.provider
    $known = @($prov.V4 + $prov.V6)
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop) } catch { $adapters = @() }
    foreach ($i in @($Snapshot.interfaces)) {
        $a = $adapters | Where-Object { [string]$_.InterfaceGuid -eq [string]$i.scope } | Select-Object -First 1
        if (-not $a) { Write-IgwtLog -Level Warn -Message "Adapter $($i.adapter) is no longer present; DNS not restored."; continue }
        if (-not $i.static4 -and -not $i.static6) {
            if ($PSCmdlet.ShouldProcess($a.Name, 'Restore DNS servers from DHCP')) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop }
        } else {
            $servers = @()
            if ($i.static4) { $servers += @($i.v4) }
            if ($i.static6) { $servers += @($i.v6) }
            if ($PSCmdlet.ShouldProcess($a.Name, "Restore static DNS servers $($servers -join ', ')")) {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
            }
        }
    }
    foreach ($d in @($Snapshot.doh)) {
        $ip = [string]$d.address
        if ($known -notcontains $ip) { continue }
        $e = Get-IgwtDohEntry -Address $ip
        if ($d.exists) {
            if ($PSCmdlet.ShouldProcess($ip, 'Restore DoH entry')) {
                if ($e) { $null = Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate ([string]$d.template) -AutoUpgrade ([bool]$d.autoUpgrade) -AllowFallbackToUdp ([bool]$d.fallback) -ErrorAction Stop }
                else { $null = Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate ([string]$d.template) -AutoUpgrade ([bool]$d.autoUpgrade) -AllowFallbackToUdp ([bool]$d.fallback) -ErrorAction Stop }
            }
        } elseif ($e -and $PSCmdlet.ShouldProcess($ip, 'Remove DoH entry added by iG Windows Tuner')) {
            Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction Stop
        }
    }
}
