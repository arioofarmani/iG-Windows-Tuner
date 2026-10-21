# NetworkToolkit.ps1
# Network toolkit: adapter inspector (every advanced property with a description), user-initiated
# DNS benchmark and latency/jitter/loss monitor, firewall rule browser (app rules can be enabled or
# disabled through Invoke-IgwtManagedChange; Windows rules are never changed or deleted) and a
# read-only hosts-file viewer. Listening ports: Get-IgwtNetworkSurface.

$script:IgwtDnsBenchmarkServers = @(
    [pscustomobject]@{ Name = 'Cloudflare'; Address = '1.1.1.1' }
    [pscustomobject]@{ Name = 'Quad9'; Address = '9.9.9.9' }
    [pscustomobject]@{ Name = 'Google'; Address = '8.8.8.8' }
)
$script:IgwtDnsBenchmarkNames = @('www.microsoft.com', 'store.steampowered.com', 'www.riotgames.com', 'www.ea.com', 'www.epicgames.com')
$script:IgwtHostTargetPattern = '^(?=.{1,253}$)(([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*|\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]+)$'

function Get-IgwtNicKeywordDescriptions {
    [CmdletBinding()]
    param()
    if ($script:IgwtNicKeywordCache) { return $script:IgwtNicKeywordCache }
    $map = @{}
    $file = Join-Path (Get-IgwtDataFolder) 'manage\nic-keywords.json'
    if (Test-Path -LiteralPath $file) { foreach ($k in @((Read-IgwtJsonFile -Path $file).keywords | Where-Object { $_ })) { $map[([string]$k.keyword).ToLowerInvariant()] = [string]$k.description } }
    $script:IgwtNicKeywordCache = $map
    return $map
}

function Get-IgwtAdapterPropertyInspection {
    <# .SYNOPSIS Every advanced property of the physical network adapters with value, allowed values, default and a description (read-only). #>
    [CmdletBinding()]
    param()
    $desc = Get-IgwtNicKeywordDescriptions
    $adapters = foreach ($a in @(Get-NetAdapter -Physical -ErrorAction Stop)) {
        $props = foreach ($p in @(Get-NetAdapterAdvancedProperty -Name ([string]$a.Name) -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })) {
            $kw = [string]$p.RegistryKeyword
            [pscustomobject]@{
                Keyword = $kw; DisplayName = [string]$p.DisplayName; Value = [string]$p.DisplayValue; RegistryValue = (@($p.RegistryValue) -join ',')
                Default = [string]$p.DefaultRegistryValue; Allowed = (@($p.ValidDisplayValues | Where-Object { $_ }) -join ', ')
                Range = $(if ($null -ne $p.NumericParameterMaxValue) { "$($p.NumericParameterMinValue)-$($p.NumericParameterMaxValue)" } else { '' })
                Standardized = $kw.StartsWith('*')
                Description = $(if ($desc.ContainsKey($kw.ToLowerInvariant())) { $desc[$kw.ToLowerInvariant()] } elseif ($kw.StartsWith('*')) { 'Standardized NDIS keyword; see the Microsoft documentation.' } else { 'Vendor-specific setting; see the adapter vendor documentation.' })
                ChangedFromDefault = ([string]$p.DefaultRegistryValue -and (@($p.RegistryValue) -join ',') -ne [string]$p.DefaultRegistryValue)
            }
        }
        [pscustomobject]@{ Name = [string]$a.Name; Description = [string]$a.InterfaceDescription; Status = [string]$a.Status; LinkSpeed = [string]$a.LinkSpeed; Properties = @($props | Sort-Object DisplayName) }
    }
    [pscustomobject]@{ Adapters = @($adapters); Note = 'Read-only. Adapter settings change only through catalog items (Network category) or Device Manager.' }
}

function Measure-IgwtDnsQuery {
    <# .SYNOPSIS Time of one DNS query in milliseconds against a server ($null on failure). Mock this in tests. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Server, [Parameter(Mandatory = $true)][string]$Name)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { $null = Resolve-DnsName -Name $Name -Server $Server -DnsOnly -NoHostsFile -QuickTimeout -Type A -ErrorAction Stop } catch { return $null }
    $sw.Stop()
    return [Math]::Round($sw.Elapsed.TotalMilliseconds, 1)
}

function Invoke-IgwtDnsBenchmark {
    <#
    .SYNOPSIS
        User-initiated DNS benchmark: resolves gaming-related names against the current DNS servers
        and a few public resolvers, several rounds each, and reports median and worst latency and
        failures. Uses the network; changes nothing.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 10)][int]$Rounds = 3, [string[]]$Servers, [string[]]$Names = $script:IgwtDnsBenchmarkNames)
    $targets = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($d in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)) {
            $targets.Add([pscustomobject]@{ Name = 'Current'; Address = [string]$d })
        }
    } catch { Write-Verbose 'Current DNS servers unavailable.' }
    foreach ($s in $script:IgwtDnsBenchmarkServers) { if (@($targets | Where-Object { $_.Address -eq $s.Address }).Count -eq 0) { $targets.Add($s) } }
    if ($Servers) { $targets = New-Object System.Collections.Generic.List[object]; foreach ($s in $Servers) { if ($s -match $script:IgwtHostTargetPattern) { $targets.Add([pscustomobject]@{ Name = 'Custom'; Address = $s }) } } }
    $rows = foreach ($t in $targets) {
        $times = New-Object System.Collections.Generic.List[double]; $fail = 0
        for ($r = 0; $r -lt $Rounds; $r++) {
            foreach ($n in $Names) { $ms = Measure-IgwtDnsQuery -Server $t.Address -Name $n; if ($null -eq $ms) { $fail++ } else { $times.Add([double]$ms) } }
        }
        $sorted = @($times.ToArray() | Sort-Object)
        [pscustomobject]@{
            Name = $t.Name; Server = $t.Address; Queries = ($Rounds * @($Names).Count); Failures = $fail
            MedianMs = $(if ($sorted.Count) { $sorted[[int][Math]::Floor(($sorted.Count - 1) / 2)] } else { $null })
            WorstMs = $(if ($sorted.Count) { $sorted[$sorted.Count - 1] } else { $null })
        }
    }
    $rows = @($rows | Sort-Object @{ Expression = { if ($null -eq $_.MedianMs) { [double]::MaxValue } else { $_.MedianMs } } })
    [pscustomobject]@{ Results = $rows; Note = 'Lower median latency means faster name lookups (mostly noticeable when launchers and browsers start). It does not change in-game ping. iG Windows Tuner offers DNS over HTTPS items in the Network category.' }
}

function Invoke-IgwtPingProbe {
    <# .SYNOPSIS Round-trip times in ms for Count echo requests ($null entries for lost replies). Mock this in tests. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Target, [int]$Count = 20)
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            $r = $null
            try { $r = $ping.Send($Target, 1000) } catch { $r = $null }
            if ($r -and [string]$r.Status -eq 'Success') { [double]$r.RoundtripTime } else { $null }
            Start-Sleep -Milliseconds 200
        }
    } finally { $ping.Dispose() }
}

function Test-IgwtNetworkLatency {
    <#
    .SYNOPSIS
        User-initiated latency, jitter and packet-loss monitor for targets you choose (host names or
        IP addresses): Count echo requests per target. Jitter is the mean difference between
        consecutive replies. Uses the network; changes nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Target, [ValidateRange(4, 200)][int]$Count = 20)
    $rows = foreach ($t in $Target) {
        $name = $t.Trim()
        if ($name -notmatch $script:IgwtHostTargetPattern) { [pscustomobject]@{ Target = $name; Error = 'Not a valid host name or IP address.' }; continue }
        $samples = @(Invoke-IgwtPingProbe -Target $name -Count $Count)
        $ok = @($samples | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
        $jitter = $null
        if ($ok.Count -ge 2) { $d = for ($i = 1; $i -lt $ok.Count; $i++) { [Math]::Abs($ok[$i] - $ok[$i - 1]) }; $jitter = [Math]::Round((@($d) | Measure-Object -Average).Average, 1) }
        [pscustomobject]@{
            Target = $name; Sent = $samples.Count; Received = $ok.Count
            LossPercent = $(if ($samples.Count) { [Math]::Round(100 * ($samples.Count - $ok.Count) / $samples.Count, 1) } else { $null })
            AvgMs = $(if ($ok.Count) { [Math]::Round(($ok | Measure-Object -Average).Average, 1) } else { $null })
            MinMs = $(if ($ok.Count) { ($ok | Measure-Object -Minimum).Minimum } else { $null })
            MaxMs = $(if ($ok.Count) { ($ok | Measure-Object -Maximum).Maximum } else { $null })
            JitterMs = $jitter; Error = ''
        }
    }
    [pscustomobject]@{ Results = @($rows); Note = 'Some servers ignore ping (ICMP); 100 % loss then says nothing about game traffic. Run a bufferbloat test for latency under load.' }
}

function Get-IgwtFirewallRuleList {
    <#
    .SYNOPSIS
        Firewall rule browser (read-only): name, display name, direction, action, enabled, profile,
        group, program, and whether it is a Windows rule. Only rules created by apps can be enabled
        or disabled (Invoke-IgwtManagedChange -Kind firewallRule); nothing is ever deleted.
    #>
    [CmdletBinding()]
    param([string]$Search, [switch]$AppRulesOnly)
    $programs = @{}
    try { foreach ($f in @(Get-NetFirewallApplicationFilter -ErrorAction Stop)) { $programs[[string]$f.InstanceID] = [string]$f.Program } } catch { Write-Verbose 'Application filters unavailable.' }
    $rows = foreach ($r in @(Get-NetFirewallRule -ErrorAction Stop)) {
        $win = Test-IgwtWindowsFirewallRule -Rule $r
        if ($AppRulesOnly -and $win) { continue }
        $prog = [string]$programs[[string]$r.Name]
        $row = [pscustomobject]@{
            Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; Direction = [string]$r.Direction; Action = [string]$r.Action; Enabled = ([string]$r.Enabled -eq 'True')
            Profile = [string]$r.Profile; Group = [string]$r.DisplayGroup; Program = $prog; IsWindowsRule = $win; CanChange = -not $win
        }
        if ($Search) {
            $s = $Search.Trim()
            if ("$($row.DisplayName) $($row.Name) $($row.Program) $($row.Group)".IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        $row
    }
    $rows = @($rows | Sort-Object DisplayName)
    [pscustomobject]@{ Rules = $rows; AppRules = @($rows | Where-Object { -not $_.IsWindowsRule }).Count; Note = 'Windows rules are shown but never changed or deleted. App rules can be enabled or disabled with a snapshot.' }
}

function Get-IgwtHostsFile {
    <# .SYNOPSIS Read-only hosts-file viewer that flags entries other than localhost, and blocks of Microsoft endpoints. #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'))
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Path = $Path; Exists = $false; Entries = @(); Unexpected = 0; Note = 'No hosts file.' } }
    $rows = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $n++
        $text = ($line -replace '#.*$', '').Trim()
        if (-not $text) { continue }
        $parts = @($text -split '\s+')
        if ($parts.Count -lt 2) { continue }
        $ip = $parts[0]
        foreach ($h in $parts[1..($parts.Count - 1)]) {
            $flag = 'Expected'; $note = ''
            if ($h -in 'localhost', 'localhost.localdomain' -and $ip -in '127.0.0.1', '::1') { $flag = 'Expected' }
            elseif ($h -match '(?i)(microsoft|windows|msft|live|bing|office|azure|xbox|msn)\.(com|net)$' -and $ip -in '0.0.0.0', '127.0.0.1', '::', '::1') { $flag = 'BlocksMicrosoft'; $note = 'Blocks a Microsoft endpoint. Microsoft Defender flags this (HostsFileHijack) and it can break Windows Update, activation or Xbox services.' }
            else { $flag = 'Unexpected'; $note = 'Not a default entry. Make sure you added it on purpose; malware uses the hosts file to redirect sites.' }
            $rows.Add([pscustomobject]@{ Line = $n; Address = $ip; HostName = $h; Flag = $flag; Note = $note })
        }
    }
    [pscustomobject]@{ Path = $Path; Exists = $true; Entries = $rows.ToArray(); Unexpected = @($rows | Where-Object { $_.Flag -ne 'Expected' }).Count; Note = 'Read-only. iG Windows Tuner never edits the hosts file.' }
}
