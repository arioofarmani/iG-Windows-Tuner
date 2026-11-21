# NetworkOverview.ps1
# 4.0 section 6 (D7): what the Network page shows next to the test: the network profile of each
# connected network, the DNS servers and whether they are encrypted (DNS over HTTPS), and the
# programs that enabled firewall rules block. Read-only.

function Get-IgwtNetworkOverview {
    <#
    .SYNOPSIS
        Network page cards (read-only): Profiles (connected networks with their category), Dns (per
        connected adapter: servers and, for each, whether Windows knows an encrypted DNS template for
        it) and Blocked (programs blocked by enabled firewall rules, with the rule count). Each part
        reads on its own; a part that cannot be read has an error text instead.
    #>
    [CmdletBinding()]
    param()
    $profiles = @(); $profileError = ''
    try {
        $profiles = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; Interface = [string]$_.InterfaceAlias; InterfaceIndex = [int]$_.InterfaceIndex; Category = [string]$_.NetworkCategory; IPv4 = [string]$_.IPv4Connectivity }
            })
    } catch { $profileError = "Network profiles not readable: $($_.Exception.Message)" }
    $dns = @(); $dnsError = ''
    try {
        $doh = @{}
        try { foreach ($d in @(Get-DnsClientDohServerAddress -ErrorAction Stop)) { $doh[[string]$d.ServerAddress] = [string]$d.DohTemplate } } catch { Write-Verbose "DoH templates not readable: $($_.Exception.Message)" }
        $up = @{}; foreach ($p in $profiles) { $up[$p.InterfaceIndex] = $true }
        $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { @($_.ServerAddresses).Count -and ($up.Count -eq 0 -or $up.ContainsKey([int]$_.InterfaceIndex)) } | ForEach-Object {
                $servers = @($_.ServerAddresses | ForEach-Object { [string]$_ })
                [pscustomobject]@{ Interface = [string]$_.InterfaceAlias; InterfaceIndex = [int]$_.InterfaceIndex; Servers = $servers; Encrypted = @($servers | Where-Object { $doh.ContainsKey($_) }); Templates = @($servers | Where-Object { $doh.ContainsKey($_) } | ForEach-Object { $doh[$_] }) }
            })
    } catch { $dnsError = "DNS settings not readable: $($_.Exception.Message)" }
    $blocked = @(); $blockedError = ''
    try {
        $rules = @(Get-NetFirewallRule -Action Block -Enabled True -ErrorAction Stop)
        $byProgram = @{}
        foreach ($r in $rules) {
            $app = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            $prog = $(if ($app -and [string]$app.Program -and [string]$app.Program -ne 'Any') { [string]$app.Program } elseif ($app -and $app.PSObject.Properties['AppPath'] -and [string]$app.AppPath) { [string]$app.AppPath } else { '' })
            if (-not $prog) { continue }
            $k = $prog.ToLowerInvariant()
            if (-not $byProgram.ContainsKey($k)) { $full = [Environment]::ExpandEnvironmentVariables($prog); $byProgram[$k] = [pscustomobject]@{ Program = $prog; Name = [System.IO.Path]::GetFileName($full); Folder = [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($full)); Rules = 0; Directions = (New-Object System.Collections.Generic.List[string]) } }
            $byProgram[$k].Rules++
            $dir = (ConvertFrom-IgwtFirewallCimValue -Kind Direction -Value $r.Direction)
            if (-not $byProgram[$k].Directions.Contains($dir)) { $byProgram[$k].Directions.Add($dir) }
        }
        $blocked = @($byProgram.Values | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Program = $_.Program; Name = $_.Name; Folder = $_.Folder; Rules = $_.Rules; Directions = ($_.Directions.ToArray() -join ', ') } })
    } catch { $blockedError = "Firewall rules not readable: $($_.Exception.Message)" }
    [pscustomobject]@{
        Profiles = $profiles; ProfileError = $profileError
        Dns = $dns; DnsError = $dnsError
        Blocked = $blocked; BlockedError = $blockedError
        Read = (Get-Date)
    }
}
