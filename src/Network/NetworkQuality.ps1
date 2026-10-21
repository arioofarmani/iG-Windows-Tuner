# NetworkQuality.ps1
# Network quality analyzer: measures latency, jitter, packet loss and stability to the router, the
# ISP and internet anchors, traces the path, finds the path MTU, guesses the connection type
# (local link and internet access technology) and recommends catalog items and router/Wi-Fi
# guidance that lower latency and jitter. Read-only: it sends ICMP echo requests and DNS queries
# and changes nothing; recommended items are applied only through the normal engine.

$script:IgwtNetAnchors = @(
    [pscustomobject]@{ Name = 'Cloudflare DNS'; Address = '1.1.1.1' }
    [pscustomobject]@{ Name = 'Google DNS'; Address = '8.8.8.8' }
    [pscustomobject]@{ Name = 'Quad9 DNS'; Address = '9.9.9.9' }
)
$script:IgwtNetDurations = @{ Quick = 10; Standard = 30; Extended = 120 }
$script:IgwtNetHostPattern = '^(?=.{1,253}$)(([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*|\d{1,3}(\.\d{1,3}){3})$'

#region Probes (mocked in tests)

function Send-IgwtPingProbe {
    <#
    .SYNOPSIS
        One ICMP echo request. Returns Status (Success, TimedOut, TtlExpired, PacketTooBig or the
        raw status), the replying Address and RttMs (stopwatch time, also for TTL-expired replies).
        Read-only; refuses to run in TestMode (tests mock it).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Target, [ValidateRange(1, 255)][int]$Ttl = 128, [ValidateRange(100, 5000)][int]$TimeoutMs = 1000,
        [ValidateRange(0, 65500)][int]$Size = 32, [switch]$DontFragment)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: ICMP probes must be mocked in tests.' }
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $opt = New-Object System.Net.NetworkInformation.PingOptions($Ttl, [bool]$DontFragment)
        $buf = New-Object byte[] $Size
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $reply = $null
        try { $reply = $ping.Send($Target, $TimeoutMs, $buf, $opt) } catch { return [pscustomobject]@{ Status = 'Error'; Address = ''; RttMs = $null } }
        $sw.Stop()
        $status = [string]$reply.Status
        $rtt = $null
        # The ICMP API reports whole milliseconds; the stopwatch gives sub-millisecond resolution for jitter.
        if ($status -eq 'Success') { $rtt = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2) }
        elseif ($status -eq 'TtlExpired') { $rtt = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2) }
        [pscustomobject]@{ Status = $status; Address = $(if ($reply.Address) { [string]$reply.Address } else { '' }); RttMs = $rtt }
    } finally { $ping.Dispose() }
}

function Resolve-IgwtHostName {
    <# .SYNOPSIS Reverse DNS name of an IP address within a short timeout, or ''. Mocked in tests. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Address, [int]$TimeoutMs = 1500)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: reverse DNS must be mocked in tests.' }
    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($Address)
        if ($task.Wait($TimeoutMs) -and $task.Result -and [string]$task.Result.HostName -ne $Address) { return [string]$task.Result.HostName }
    } catch { Write-Verbose "No reverse DNS for $Address" }
    return ''
}

function Invoke-IgwtNetshWlanInterfaces {
    <# .SYNOPSIS Output of 'netsh wlan show interfaces' (fixed, read-only arguments). Mocked in tests. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: netsh.exe must be mocked in tests.' }
    $exe = Join-Path $env:SystemRoot 'System32\netsh.exe'
    return (& $exe 'wlan' 'show' 'interfaces' 2>$null | Out-String)
}

#endregion

#region Connection profile

function Get-IgwtIpClass {
    <# .SYNOPSIS Private, CGNAT (100.64.0.0/10), Loopback, LinkLocal or Public for an IPv4 address. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Address)
    if ($Address -notmatch '^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$') { return 'Unknown' }
    $a = [int]$Matches[1]; $b = [int]$Matches[2]
    if ($a -eq 10 -or ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or ($a -eq 192 -and $b -eq 168)) { return 'Private' }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return 'CGNAT' }
    if ($a -eq 127) { return 'Loopback' }
    if ($a -eq 169 -and $b -eq 254) { return 'LinkLocal' }
    return 'Public'
}

function ConvertFrom-IgwtWlanInterfaces {
    <#
    .SYNOPSIS
        Parses 'netsh wlan show interfaces' without relying on the (localized) labels where the
        values are self-describing: radio type (802.11xx), signal (NN%), band (N GHz); channel,
        rates and RSSI are read by label in English, German, French and Spanish.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $r = [ordered]@{ Connected = $false; Ssid = ''; RadioType = ''; Generation = ''; Band = ''; Channel = $null; SignalPercent = $null; Rssi = $null; ReceiveMbps = $null; TransmitMbps = $null }
    if (-not $Text) { return [pscustomobject]$r }
    $rates = New-Object System.Collections.Generic.List[double]
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -notmatch '^\s*([^:]+?)\s*:\s*(.+?)\s*$') { continue }
        $label = $Matches[1]; $value = $Matches[2]
        if ($value -match '^(802\.11[a-z]+)$') { $r.RadioType = $Matches[1]; continue }
        if ($value -match '^(\d{1,3})\s?%$') { $r.SignalPercent = [int]$Matches[1]; continue }
        if ($value -match '^(\d(?:[\.,]\d)?)\s*GHz$') { $r.Band = ($Matches[1] -replace ',', '.') + ' GHz'; continue }
        if ($label -match '^(?i)rssi$' -and $value -match '^-?\d+$') { $r.Rssi = [int]$value; continue }
        if ($label -match '^(?i)ssid$') { $r.Ssid = $value; continue }
        if ($label -match '(?i)^(channel|kanal|canal|canale)$' -and $value -match '^\d+$') { $r.Channel = [int]$value; continue }
        if ($label -match '(?i)(mbps|mbit|rate)' -and $value -match '^\d+([\.,]\d+)?$') { $rates.Add([double]($value -replace ',', '.')); continue }
        if ($label -match '(?i)^(state|status|.tat|estado|zustand)$' -and $value -match '(?i)^(connected|verbunden|connect|conectado)') { $r.Connected = $true }
    }
    if ($rates.Count -ge 1) { $r.ReceiveMbps = $rates[0] }
    if ($rates.Count -ge 2) { $r.TransmitMbps = $rates[1] }
    if (($null -ne $r.SignalPercent) -and -not $r.Connected) { $r.Connected = $true }
    if (-not $r.Band -and $r.Channel) { $r.Band = $(if ($r.Channel -le 14) { '2.4 GHz' } else { '5 GHz' }) }
    $r.Generation = switch -Regex ($r.RadioType) { '^802\.11be$' { 'Wi-Fi 7'; break } '^802\.11ax$' { $(if ($r.Band -eq '6 GHz') { 'Wi-Fi 6E' } else { 'Wi-Fi 6' }); break } '^802\.11ac$' { 'Wi-Fi 5'; break } '^802\.11n$' { 'Wi-Fi 4'; break } '^802\.11[abg]$' { 'Legacy Wi-Fi'; break } default { '' } }
    return [pscustomobject]$r
}

function Get-IgwtActiveConnection {
    <#
    .SYNOPSIS
        The interface that carries the default route, with its kind (Ethernet, WiFi, Cellular,
        Tethering, VPN, Virtual), link speed, gateway, addresses, DNS servers, MTU and Wi-Fi details.
    #>
    [CmdletBinding()]
    param()
    $route = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric }) | Select-Object -First 1
    if (-not $route) { return [pscustomobject]@{ Connected = $false; Kind = 'None'; Note = 'No default route: the PC has no internet connection.' } }
    $idx = [int]$route.ifIndex
    $adapter = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
    $cfg = Get-NetIPConfiguration -InterfaceIndex $idx -ErrorAction SilentlyContinue
    $ipIf = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $desc = [string]$(if ($adapter) { $adapter.InterfaceDescription } else { $cfg.InterfaceDescription })
    $media = [string]$(if ($adapter) { $adapter.PhysicalMediaType } else { '' })
    $mediaType = [string]$(if ($adapter) { $adapter.MediaType } else { '' })
    $virtual = ($adapter -and (($adapter.PSObject.Properties['Virtual'] -and $adapter.Virtual) -or ($adapter.PSObject.Properties['HardwareInterface'] -and -not $adapter.HardwareInterface)))
    $kind = 'Unknown'
    if ($desc -match '(?i)wireguard|wintun|tap-windows|openvpn|tailscale|zerotier|nordlynx|anyconnect|fortinet|globalprotect|proton|mullvad|expressvpn|\bvpn\b') { $kind = 'VPN' }
    elseif ($desc -match '(?i)remote ndis|rndis|apple mobile device ethernet') { $kind = 'Tethering' }
    elseif ($media -match '(?i)wireless wan|wwan' -or $mediaType -match '(?i)wireless wan' -or $desc -match '(?i)mobile broadband|wwan|\blte\b|\b5g\b') { $kind = 'Cellular' }
    elseif ($media -match '802\.11' -or $mediaType -match '802\.11' -or $desc -match '(?i)wi-?fi|wireless|802\.11|wlan') { $kind = 'WiFi' }
    elseif ($desc -match '(?i)hyper-v virtual|vethernet') { $kind = 'Virtual' }
    elseif ($media -match '802\.3' -or $mediaType -match '802\.3' -or $desc -match '(?i)ethernet|gbe|lan|aqtion|realtek|killer') { $kind = $(if ($virtual) { 'Virtual' } else { 'Ethernet' }) }
    elseif ($virtual) { $kind = 'Virtual' }
    $gw = [string]$route.NextHop
    $v4 = @($cfg.IPv4Address | ForEach-Object { [string]$_.IPAddress }) | Select-Object -First 1
    $v6 = @($cfg.IPv6Address | Where-Object { $_ -and [string]$_.PrefixOrigin -ne 'WellKnown' } | ForEach-Object { [string]$_.IPAddress } | Where-Object { $_ -and $_ -notmatch '^fe80' })
    $wifi = $null
    if ($kind -eq 'WiFi') { try { $wifi = ConvertFrom-IgwtWlanInterfaces -Text (Invoke-IgwtNetshWlanInterfaces) } catch { Write-Verbose 'Wi-Fi details unavailable.' } }
    $hotspot = ($kind -eq 'WiFi' -and $gw -in '192.168.43.1', '172.20.10.1')
    [pscustomobject]@{
        Connected = $true; Kind = $kind; Alias = [string]$route.InterfaceAlias; Description = $desc; InterfaceIndex = $idx
        LinkSpeed = [string]$(if ($adapter) { $adapter.LinkSpeed } else { '' }); Gateway = $gw; GatewayClass = (Get-IgwtIpClass -Address $gw)
        LocalIPv4 = [string]$v4; LocalClass = (Get-IgwtIpClass -Address ([string]$v4)); IPv6 = ($v6.Count -gt 0)
        DnsServers = @($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
        Mtu = $(if ($ipIf) { [int]$ipIf.NlMtu } else { $null }); Wifi = $wifi; PhoneHotspot = $hotspot
        Note = $(if ($kind -eq 'VPN') { 'Traffic goes through a VPN; latency includes the VPN server.' } elseif ($hotspot) { 'The gateway address is typical of a phone hotspot.' } else { '' })
    }
}

#endregion

#region Path

function Invoke-IgwtRouteTrace {
    <# .SYNOPSIS Traceroute with ICMP and increasing TTL (two probes per hop, best RTT), with reverse DNS and address class per hop. #>
    [CmdletBinding()]
    param([string]$Target = '1.1.1.1', [ValidateRange(1, 30)][int]$MaxHops = 18, [int]$TimeoutMs = 1000, [switch]$NoNames)
    $hops = New-Object System.Collections.Generic.List[object]
    for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
        $best = $null; $addr = ''; $reached = $false
        for ($p = 0; $p -lt 2; $p++) {
            $r = Send-IgwtPingProbe -Target $Target -Ttl $ttl -TimeoutMs $TimeoutMs
            if ($r.Status -in 'Success', 'TtlExpired' -and $r.Address) {
                $addr = [string]$r.Address
                if ($null -ne $r.RttMs -and ($null -eq $best -or [double]$r.RttMs -lt $best)) { $best = [double]$r.RttMs }
                if ($r.Status -eq 'Success') { $reached = $true }
            }
        }
        $name = ''
        if ($addr -and -not $NoNames) { $name = Resolve-IgwtHostName -Address $addr }
        $hops.Add([pscustomobject]@{ Hop = $ttl; Address = $addr; Name = $name; RttMs = $best; Class = $(if ($addr) { Get-IgwtIpClass -Address $addr } else { 'NoReply' }) })
        if ($reached) { break }
    }
    return $hops.ToArray()
}

function Find-IgwtPathMtu {
    <# .SYNOPSIS Largest IPv4 packet that reaches Target without fragmentation (binary search with Don't Fragment), or $null. #>
    [CmdletBinding()]
    param([string]$Target = '1.1.1.1')
    $lo = 1172; $hi = 1472   # ICMP payload; MTU = payload + 28 (IPv4 + ICMP headers)
    $ok = Send-IgwtPingProbe -Target $Target -Size $lo -DontFragment -TimeoutMs 1500
    if ($ok.Status -ne 'Success') { return $null }
    while ($lo -lt $hi) {
        $mid = [int][Math]::Ceiling(($lo + $hi) / 2)
        $r = Send-IgwtPingProbe -Target $Target -Size $mid -DontFragment -TimeoutMs 1500
        if ($r.Status -eq 'Success') { $lo = $mid } else { $hi = $mid - 1 }
    }
    return ($lo + 28)
}

#endregion

#region Statistics and scores

function ConvertTo-IgwtLatencyStats {
    <#
    .SYNOPSIS
        Statistics for a sample series ($null = lost): loss, min/avg/median/p95/p99/max, standard
        deviation, jitter (mean difference between consecutive replies, as used by game and VoIP
        tools), RFC 3550 smoothed jitter, spikes and the longest loss burst.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Samples, [double]$DurationSec = 0)
    $all = @($Samples)
    $ok = @($all | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
    $sent = $all.Count; $recv = $ok.Count
    $burst = 0; $run = 0
    foreach ($s in $all) { if ($null -eq $s) { $run++; if ($run -gt $burst) { $burst = $run } } else { $run = 0 } }
    $res = [ordered]@{ Sent = $sent; Received = $recv; LossPercent = $(if ($sent) { [Math]::Round(100.0 * ($sent - $recv) / $sent, 2) } else { $null })
        MinMs = $null; AvgMs = $null; MedianMs = $null; P95Ms = $null; P99Ms = $null; MaxMs = $null; StdDevMs = $null; JitterMs = $null; JitterRfc3550Ms = $null; Spikes = 0; SpikesPerMinute = $null; MaxLossBurst = $burst }
    if ($recv -eq 0) { return [pscustomobject]$res }
    $sorted = @($ok | Sort-Object)
    $pct = { param($p) $sorted[[Math]::Max(0, [int][Math]::Ceiling($p / 100.0 * $sorted.Count) - 1)] }
    $avg = ($ok | Measure-Object -Average).Average
    $res.MinMs = [Math]::Round($sorted[0], 2); $res.MaxMs = [Math]::Round($sorted[$sorted.Count - 1], 2); $res.AvgMs = [Math]::Round([double]$avg, 2)
    $res.MedianMs = [Math]::Round([double](& $pct 50), 2); $res.P95Ms = [Math]::Round([double](& $pct 95), 2); $res.P99Ms = [Math]::Round([double](& $pct 99), 2)
    $var = 0.0; foreach ($x in $ok) { $var += ($x - $avg) * ($x - $avg) }
    $res.StdDevMs = [Math]::Round([Math]::Sqrt($var / $recv), 2)
    if ($recv -ge 2) {
        $sum = 0.0; $j = 0.0
        for ($i = 1; $i -lt $recv; $i++) { $d = [Math]::Abs($ok[$i] - $ok[$i - 1]); $sum += $d; $j += ($d - $j) / 16.0 }
        $res.JitterMs = [Math]::Round($sum / ($recv - 1), 2); $res.JitterRfc3550Ms = [Math]::Round($j, 2)
    } else { $res.JitterMs = 0.0; $res.JitterRfc3550Ms = 0.0 }
    # Spike threshold from the median absolute deviation, which (unlike jitter) is not inflated by the spikes themselves.
    $med = [double]$res.MedianMs
    $dev = @($ok | ForEach-Object { [Math]::Abs($_ - $med) } | Sort-Object)
    $mad = [double]$dev[[Math]::Max(0, [int][Math]::Ceiling($dev.Count / 2.0) - 1)]
    $limit = [Math]::Max($med * 1.5, $med + [Math]::Max(10.0, 3 * $mad))
    $res.Spikes = @($ok | Where-Object { $_ -gt $limit }).Count
    # Short tests would over-extrapolate a single spike, so the rate uses at least a one-minute window.
    if ($DurationSec -gt 0) { $res.SpikesPerMinute = [Math]::Round($res.Spikes * 60.0 / [Math]::Max([double]60, [double]$DurationSec), 2) }
    return [pscustomobject]$res
}

function Get-IgwtGradeFromScale {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value, [double[]]$Limits)
    if ($null -eq $Value) { return 'n/a' }
    $grades = @('A+', 'A', 'B', 'C', 'D')
    for ($i = 0; $i -lt $Limits.Count; $i++) { if ([double]$Value -le $Limits[$i]) { return $grades[$i] } }
    return 'F'
}

function Get-IgwtNetworkScore {
    <#
    .SYNOPSIS
        Quality score for a statistics object: a gaming grade per metric (latency, jitter, loss,
        stability) and overall (the weakest metric), a 0-100 score and an estimated MOS from the
        simplified ITU-T G.107 E-model used by VoIP monitoring tools.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Stats)
    if (-not $Stats.Received) { return [pscustomobject]@{ Grade = 'F'; Score = 0; Mos = 1.0; Latency = 'F'; Jitter = 'F'; Loss = 'F'; Stability = 'F'; Limiting = 'No replies'; Verdict = 'No replies: the target is unreachable or blocks ping.' } }
    $lat = [double]$Stats.AvgMs; $jit = [double]$Stats.JitterMs; $loss = [double]$Stats.LossPercent
    $g = [ordered]@{
        Latency = (Get-IgwtGradeFromScale -Value $lat -Limits 20, 40, 60, 100, 150)
        Jitter = (Get-IgwtGradeFromScale -Value $jit -Limits 2, 5, 10, 20, 40)
        Loss = (Get-IgwtGradeFromScale -Value $loss -Limits 0, 0.5, 1, 2.5, 5)
        Stability = (Get-IgwtGradeFromScale -Value $(if ($null -ne $Stats.SpikesPerMinute) { [double]$Stats.SpikesPerMinute + 2 * [double]$Stats.MaxLossBurst } else { [double]$Stats.Spikes }) -Limits 0, 1, 3, 6, 12)
    }
    $rank = @{ 'A+' = 0; 'A' = 1; 'B' = 2; 'C' = 3; 'D' = 4; 'F' = 5 }
    $worst = 'Latency'; foreach ($k in $g.Keys) { if ($rank[$g[$k]] -gt $rank[$g[$worst]]) { $worst = $k } }
    $score = 100.0 - [Math]::Max([double]0, $lat - 20) * 0.35 - [Math]::Max([double]0, $jit - 2) * 1.2 - $loss * 8 - [Math]::Min([double]20, 3 * [double]$Stats.Spikes)
    $score = [Math]::Round([Math]::Max([double]0, [Math]::Min([double]100, $score)))
    $eff = $lat + 2 * $jit + 10.0
    $r = $(if ($eff -lt 160) { 93.2 - $eff / 40.0 } else { 93.2 - ($eff - 120.0) / 10.0 }) - 2.5 * $loss
    $r = [Math]::Max([double]0, [Math]::Min([double]100, $r))
    $mos = [Math]::Round([Math]::Max(1.0, [Math]::Min(4.5, 1 + 0.035 * $r + 0.000007 * $r * ($r - 60) * (100 - $r))), 2)
    $overall = $g[$worst]
    $verdict = switch ($overall) { 'A+' { 'Excellent for competitive gaming.' } 'A' { 'Very good for online gaming and calls.' } 'B' { 'Good; occasional hiccups are possible in fast games.' } 'C' { 'Fair; expect noticeable lag or rubber-banding at times.' } 'D' { 'Poor for real-time games; calls may break up.' } default { 'Bad; real-time games will be unreliable.' } }
    [pscustomobject]@{ Grade = $overall; Score = $score; Mos = $mos; Latency = $g.Latency; Jitter = $g.Jitter; Loss = $g.Loss; Stability = $g.Stability; Limiting = $worst; Verdict = $verdict }
}

function Get-IgwtBufferbloatGrade {
    <# .SYNOPSIS Bufferbloat grade from the median latency increase under load (same scale as common bufferbloat tests). #>
    [CmdletBinding()]
    param([AllowNull()]$IdleMedianMs, [AllowNull()]$LoadedMedianMs)
    if ($null -eq $IdleMedianMs -or $null -eq $LoadedMedianMs) { return [pscustomobject]@{ Grade = 'n/a'; IncreaseMs = $null } }
    $inc = [Math]::Round([Math]::Max([double]0, [double]$LoadedMedianMs - [double]$IdleMedianMs), 1)
    [pscustomobject]@{ Grade = (Get-IgwtGradeFromScale -Value $inc -Limits 5, 30, 60, 200, 400); IncreaseMs = $inc }
}

#endregion

#region Connection type guess

function Get-IgwtNetworkTypeGuess {
    <#
    .SYNOPSIS
        Guesses the local link and the internet access technology (fiber, cable, DSL, cellular,
        Starlink, geostationary satellite, fixed wireless) from the adapter, reverse DNS of the
        ISP hops, carrier-grade NAT, the latency to the first ISP hop, idle jitter and the path
        MTU. Returns the guess, a confidence and the evidence used.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Connection, [object[]]$Trace = @(), $Mtu, $GatewayStats, $InternetStats)
    $ev = New-Object System.Collections.Generic.List[string]
    $local = switch ($Connection.Kind) {
        'WiFi' { $w = $Connection.Wifi; $t = 'Wi-Fi'; if ($w -and $w.Generation) { $t = "$($w.Generation)" }; if ($w -and $w.Band) { $t += " ($($w.Band))" }; $t }
        'Ethernet' { "Ethernet$(if ($Connection.LinkSpeed) { " ($($Connection.LinkSpeed))" })" }
        'Cellular' { 'Mobile broadband adapter' }
        'Tethering' { 'Phone tethering (USB)' }
        'VPN' { 'VPN tunnel' }
        'Virtual' { 'Virtual adapter (VM switch)' }
        default { 'Unknown' }
    }
    $score = [ordered]@{ 'Fiber (FTTH)' = 0; 'Cable (DOCSIS)' = 0; 'DSL (VDSL/ADSL)' = 0; 'Cellular (4G/5G)' = 0; 'Satellite (Starlink, LEO)' = 0; 'Satellite (geostationary)' = 0; 'Fixed wireless' = 0 }
    $add = { param($k, $n, $why) $score[$k] += $n; if ($why) { $ev.Add($why) } }
    if ($Connection.Kind -eq 'VPN') { $ev.Add('A VPN carries the traffic, so the path and latency describe the VPN, not your ISP line.'); return [pscustomobject]@{ Local = $local; Access = 'Unknown (behind a VPN)'; Confidence = 'Low'; Evidence = $ev.ToArray(); IspHopRttMs = $null } }
    if ($Connection.Kind -eq 'Cellular') { return [pscustomobject]@{ Local = $local; Access = 'Cellular (4G/5G)'; Confidence = 'High'; Evidence = @('The active adapter is a mobile broadband (WWAN) adapter.'); IspHopRttMs = $null } }
    if ($Connection.Kind -eq 'Tethering') { & $add 'Cellular (4G/5G)' 6 'The connection is shared from a phone over USB (RNDIS), which usually means mobile data.' }
    if ($Connection.PhoneHotspot) { & $add 'Cellular (4G/5G)' 5 "The gateway $($Connection.Gateway) is the default address of a phone hotspot." }
    $hops = @($Trace | Where-Object { $_ -and $_.Address })
    $lanRtt = $null; if ($GatewayStats -and $null -ne $GatewayStats.MedianMs) { $lanRtt = [double]$GatewayStats.MedianMs }
    $isp = @($hops | Where-Object { $_.Class -in 'Public', 'CGNAT' }) | Select-Object -First 1
    $ispRtt = $null
    if ($isp -and $null -ne $isp.RttMs) { $ispRtt = [Math]::Round([Math]::Max([double]0, [double]$isp.RttMs - $(if ($null -ne $lanRtt) { $lanRtt } else { 0 })), 1) }
    $names = (@($hops | Where-Object { $_.Class -in 'Public', 'CGNAT' } | Select-Object -First 6 | ForEach-Object { [string]$_.Name }) -join ' ').ToLowerInvariant()
    $kw = [ordered]@{
        'Satellite (Starlink, LEO)' = 'starlink'
        'Fiber (FTTH)' = '(ftth|fttp|fttb|fiber|fibre|gpon|xgspon|xgs-pon|\bpon\b|glasfaser|fibra)'
        'DSL (VDSL/ADSL)' = '(vdsl|adsl|\bdsl|bras|dslam|xdsl)'
        'Cable (DOCSIS)' = '(docsis|cmts|\bcable|\bhfc|kabel|\.cm\.|cpe\.cable)'
        'Cellular (4G/5G)' = '(\blte|\b4g|\b5g|mobile|wwan|gprs|\bpgw|\bepc|cellular|mobil)'
        'Satellite (geostationary)' = '(vsat|hughes|viasat|satellite)'
        'Fixed wireless' = '(wisp|fixedwireless|fixed-wireless|\bfwa\b)'
    }
    foreach ($k in $kw.Keys) { if ($names -match $kw[$k]) { & $add $k 5 "An ISP router name on the path contains '$($Matches[0])'." } }
    $cgnat = (@($hops | Where-Object { $_.Class -eq 'CGNAT' }).Count -gt 0) -or $Connection.LocalClass -eq 'CGNAT'
    if ($cgnat) { & $add 'Cellular (4G/5G)' 2 'Carrier-grade NAT (100.64.0.0/10) on the path, common on mobile, Starlink and some fiber ISPs.'; $score['Satellite (Starlink, LEO)'] += 2; $score['Fiber (FTTH)'] += 1; $score['Fixed wireless'] += 1 }
    if (@($hops | Where-Object { $_.Address -eq '100.64.0.1' }).Count -and $null -ne $ispRtt -and $ispRtt -ge 15 -and $ispRtt -le 60) { & $add 'Satellite (Starlink, LEO)' 3 'The first ISP hop is 100.64.0.1 at satellite-like latency, typical of Starlink.' }
    if ($null -ne $ispRtt) {
        if ($ispRtt -gt 450) { & $add 'Satellite (geostationary)' 6 "The first ISP hop answers after $ispRtt ms, which only geostationary satellite links do." }
        elseif ($ispRtt -le 3) { & $add 'Fiber (FTTH)' 3 "The first ISP hop answers in $ispRtt ms, typical of fiber."; $score['Cable (DOCSIS)'] += 1 }
        elseif ($ispRtt -le 8) { & $add 'Cable (DOCSIS)' 2 "The first ISP hop answers in $ispRtt ms, typical of cable or VDSL."; $score['DSL (VDSL/ADSL)'] += 1; $score['Fiber (FTTH)'] += 1 }
        elseif ($ispRtt -le 20) { & $add 'DSL (VDSL/ADSL)' 2 "The first ISP hop answers in $ispRtt ms, typical of DSL (interleaving) or busy cable."; $score['Cable (DOCSIS)'] += 1; $score['Fixed wireless'] += 1 }
        else { & $add 'Cellular (4G/5G)' 2 "The first ISP hop answers in $ispRtt ms, typical of radio links (mobile, satellite or fixed wireless)."; $score['Satellite (Starlink, LEO)'] += 2; $score['Fixed wireless'] += 1 }
    }
    if ($InternetStats -and $null -ne $InternetStats.JitterMs -and [double]$InternetStats.JitterMs -gt 8 -and $Connection.Kind -ne 'WiFi') {
        & $add 'Cellular (4G/5G)' 1 "Idle jitter of $($InternetStats.JitterMs) ms on a wired link points to a radio access network."; $score['Satellite (Starlink, LEO)'] += 1; $score['Fixed wireless'] += 1
    }
    if ($Mtu) {
        if ($Mtu -eq 1492) { & $add 'DSL (VDSL/ADSL)' 1 'Path MTU 1492 means PPPoE, used by most DSL and many fiber ISPs.'; $score['Fiber (FTTH)'] += 1 }
        elseif ($Mtu -eq 1500) { & $add 'Cable (DOCSIS)' 1 'Path MTU 1500 (no PPPoE), as on cable and many fiber lines.'; $score['Fiber (FTTH)'] += 1 }
        elseif ($Mtu -lt 1460) { & $add 'Cellular (4G/5G)' 1 "Path MTU $Mtu points to a tunnel (mobile networks, DS-Lite or a VPN on the router)." }
    }
    $ranked = @($score.GetEnumerator() | Sort-Object Value -Descending)
    $top = $ranked[0]; $second = $ranked[1]
    if ($top.Value -le 0) { return [pscustomobject]@{ Local = $local; Access = 'Unknown'; Confidence = 'Low'; Evidence = $(if ($ev.Count) { $ev.ToArray() } else { @('Not enough evidence: the path did not answer and the ISP routers have no telling names.') }); IspHopRttMs = $ispRtt } }
    $margin = $top.Value - $second.Value
    $conf = $(if ($top.Value -ge 6 -and $margin -ge 3) { 'High' } elseif ($margin -ge 2) { 'Medium' } else { 'Low' })
    [pscustomobject]@{ Local = $local; Access = [string]$top.Key; Confidence = $conf; Evidence = $ev.ToArray(); IspHopRttMs = $ispRtt; Alternatives = @($ranked | Select-Object -Skip 1 -First 2 | Where-Object { $_.Value -gt 0 } | ForEach-Object { [string]$_.Key }) }
}

#endregion

#region Recommendations

function Get-IgwtNetworkRecommendations {
    <#
    .SYNOPSIS
        Recommended catalog items (only Windows networking items that help latency or jitter on
        this kind of connection and are not applied yet) and router, Wi-Fi and ISP guidance from
        the measurements. Risk Zone items are never recommended; applied Risk Zone network items
        are flagged for revert.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result, $Context)
    $conn = $Result.Connection; $kind = [string]$conn.Kind
    $gw = $Result.Targets | Where-Object { $_.Role -eq 'Gateway' } | Select-Object -First 1
    $net = $Result.Internet
    $why = [ordered]@{
        'net.adapter-power-saving-off'      = 'Stops the adapter from saving power between packets, which adds wake-up latency.'
        'net.eee-off'                       = 'Energy Efficient Ethernet sleeps the link between packets and can add latency spikes.'
        'net.interrupt-moderation-off'      = 'Delivers each packet immediately instead of batching interrupts (measure before and after).'
        'net.rss-on'                        = 'Spreads network processing over several cores.'
        'net.qos-dscp-games'                = 'Marks game traffic so routers with QoS or SQM can prioritize it.'
        'sched.network-throttling-off'      = 'Stops Windows from throttling network processing while multimedia apps run.'
        'sched.system-responsiveness'       = 'Gives games and multimedia more CPU time relative to background work.'
        'net.tcp-autotuning-normal'         = 'Repairs TCP auto-tuning so downloads and streaming use the full line.'
        'net.delivery-optimization-p2p-off' = 'Stops Windows from uploading updates to other PCs, which can saturate the upload.'
        'net.wifi-power-max-performance'    = 'Keeps the Wi-Fi adapter out of power saving, which causes latency spikes.'
        'power.pcie-aspm-off'               = 'Stops PCI Express link power saving for the network card.'
    }
    $ids = switch ($kind) {
        'Ethernet' { 'net.adapter-power-saving-off', 'net.eee-off', 'net.interrupt-moderation-off', 'net.rss-on', 'net.qos-dscp-games', 'sched.network-throttling-off', 'sched.system-responsiveness', 'net.tcp-autotuning-normal', 'net.delivery-optimization-p2p-off', 'power.pcie-aspm-off' }
        'WiFi' { 'net.wifi-power-max-performance', 'net.qos-dscp-games', 'sched.network-throttling-off', 'sched.system-responsiveness', 'net.tcp-autotuning-normal', 'net.delivery-optimization-p2p-off', 'power.pcie-aspm-off' }
        default { 'sched.network-throttling-off', 'sched.system-responsiveness', 'net.tcp-autotuning-normal', 'net.delivery-optimization-p2p-off' }
    }
    if (-not $Context) { $Context = New-IgwtContext }
    $tweaks = New-Object System.Collections.Generic.List[object]
    $reverts = New-Object System.Collections.Generic.List[object]
    $catalog = @(Get-IgwtCatalog)
    foreach ($id in $ids) {
        $t = $catalog | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if (-not $t) { continue }
        $s = $null; try { $s = Get-IgwtTweakState -Tweak $t -Context $Context } catch { $s = $null }
        $state = $(if ($s) { [string]$s.State } else { 'Unknown' })
        if ($state -in 'On', 'NotApplicable', 'ManagedByPolicy') { continue }
        $tweaks.Add([pscustomobject]@{ Id = $id; Name = [string]$t.name; Level = [string]$t.level; Tier = [string]$t.evidence.tier; State = $state; Why = [string]$why[$id] })
    }
    foreach ($t in @($catalog | Where-Object { [string]$_.evidence.tier -eq 'R' -and [string]$_.group -eq 'Network' })) {
        $s = $null; try { $s = Get-IgwtTweakState -Tweak $t -Context $Context } catch { $s = $null }
        if ($s -and [string]$s.State -in 'On', 'Partial') { $reverts.Add([pscustomobject]@{ Id = [string]$t.id; Name = [string]$t.name; Why = [string]$t.warning }) }
    }
    $g = New-Object System.Collections.Generic.List[object]
    $addG = { param($sev, $title, $text) $g.Add([pscustomobject]@{ Severity = $sev; Title = $title; Text = $text }) }
    if ($kind -eq 'WiFi') {
        $w = $conn.Wifi
        & $addG 'Info' 'Use a cable for competitive play' 'Ethernet removes Wi-Fi interference, retries and roaming scans, the main causes of jitter on wireless links.'
        if ($w -and $null -ne $w.SignalPercent -and $w.SignalPercent -lt 60) { & $addG 'Warn' 'Weak Wi-Fi signal' "Signal is $($w.SignalPercent) %. Move closer to the router, remove obstacles, or add a mesh node or access point near the PC." }
        if ($w -and $w.Band -eq '2.4 GHz') { & $addG 'Warn' 'Connected on 2.4 GHz' 'The 2.4 GHz band is crowded and slower. Connect to the 5 GHz or 6 GHz network of your router (give it a separate name if needed).' }
        if ($w -and $w.Generation -in 'Wi-Fi 4', 'Legacy Wi-Fi') { & $addG 'Info' 'Old Wi-Fi standard' "The link uses $($w.RadioType). A Wi-Fi 6 or newer router and adapter reduce latency under load." }
        & $addG 'Info' 'Wi-Fi adapter settings' 'In Device Manager > network adapter > Advanced, set Roaming Aggressiveness to Lowest and Preferred Band to 5 GHz (or 6 GHz) if your driver offers them. Names differ by vendor.'
    }
    # Routers answer pings to themselves with low priority: router-only loss or spikes are normal when the internet targets are clean.
    $netLoss = $(if ($net -and $net.Stats.Received) { [double]$net.Stats.LossPercent } else { 0 }); $netJit = $(if ($net -and $net.Stats.Received) { [double]$net.Stats.JitterMs } else { 0 })
    if ($gw -and $gw.Stats.Received) {
        if ([double]$gw.Stats.LossPercent -gt 0.5 -and $netLoss -gt 0.5) { & $addG 'Warn' 'Packet loss inside your home network' "$($gw.Stats.LossPercent) % of pings to your router were lost. Check the cable, the Wi-Fi signal and interference before blaming the ISP." }
        if ([double]$gw.Stats.JitterMs -gt 5 -and $netJit -gt 5) { & $addG 'Warn' 'Jitter inside your home network' "Jitter to the router is $($gw.Stats.JitterMs) ms. On Wi-Fi this means interference or a busy channel; on a cable, a faulty cable, switch or powerline adapter." }
    }
    if ($net -and $net.Stats.Received -and $gw -and $gw.Stats.Received -and [double]$net.Stats.LossPercent -gt ([double]$gw.Stats.LossPercent + 1)) {
        & $addG 'Warn' 'Packet loss beyond your router' "Loss to the internet ($($net.Stats.LossPercent) %) is higher than to the router. The problem is likely at the ISP or on the route; run an Extended test at different times and contact your ISP with the results."
    }
    if ($Result.Bufferbloat -and $Result.Bufferbloat.Grade -in 'C', 'D', 'F') { & $addG 'Warn' "Bufferbloat grade $($Result.Bufferbloat.Grade)" "Latency rises by $($Result.Bufferbloat.IncreaseMs) ms when the line is busy. Enable Smart Queue Management (SQM, CAKE or fq_codel) on your router and set it to about 90 % of your line speed." }
    elseif (-not $Result.Bufferbloat) { & $addG 'Info' 'Test latency under load' 'Run "Measure under load" while a speed test or large download runs. High latency under load (bufferbloat) is the most common cause of lag spikes and is fixed in the router (SQM).' }
    $cg = @($Result.Trace | Where-Object { $_.Class -eq 'CGNAT' }).Count -gt 0
    $priv = @($Result.Trace | Where-Object { $_.Class -eq 'Private' }).Count
    if ($cg) { & $addG 'Info' 'Carrier-grade NAT' 'Your ISP shares one public IPv4 address between customers. Some games report a strict or moderate NAT type and peer-to-peer features may fail; ask the ISP for a public IPv4 address or use IPv6.' }
    if ($priv -ge 2) { & $addG 'Info' 'Double NAT' 'There are two routers doing NAT in your home (for example an ISP modem-router plus your own router). Put the ISP device in bridge mode or use only one router to avoid NAT problems and extra latency.' }
    if ($kind -eq 'VPN') { & $addG 'Warn' 'VPN active' 'A VPN adds the distance to the VPN server to every packet. Turn it off for gaming unless you need it.' }
    if ($conn.Kind -ne 'VPN' -and -not $conn.IPv6) { & $addG 'Info' 'No IPv6' 'This connection has no global IPv6 address. That is fine for most games; if IPv6 was disabled on purpose with a tweak, Xbox networking and some services may not work.' }
    $access = [string]$Result.TypeGuess.Access
    if ($access -like 'Satellite (geostationary)*') { & $addG 'Info' 'Geostationary satellite' 'Latency of 500 ms or more is physical and cannot be tuned away. Prefer turn-based games and the closest servers.' }
    if ($access -like 'Satellite (Starlink*') { & $addG 'Info' 'Starlink' 'Short latency spikes every 15 seconds come from satellite handovers. Keep the dish free of obstructions and use a cable from the router to the PC.' }
    if ($access -like 'Cellular*') { & $addG 'Info' 'Mobile data' 'Mobile networks have higher jitter. Place the router or phone near a window, prefer 5G standalone or a less loaded cell, and avoid large downloads while gaming.' }
    if ($Result.Dns -and $null -ne $Result.Dns.MedianMs -and [double]$Result.Dns.MedianMs -gt 60) { & $addG 'Info' 'Slow DNS' "Name lookups take $($Result.Dns.MedianMs) ms. Run the DNS benchmark and pick a faster resolver; this speeds up launchers and browsing, not in-game ping." }
    $profileName = switch ($kind) { 'Ethernet' { 'Ethernet gaming profile' } 'WiFi' { 'Wi-Fi gaming profile' } 'Cellular' { 'Mobile data profile' } 'Tethering' { 'Mobile data profile' } default { 'General network profile' } }
    [pscustomobject]@{ Profile = $profileName; Tweaks = $tweaks.ToArray(); Reverts = $reverts.ToArray(); Guidance = $g.ToArray(); TweakIds = @($tweaks | ForEach-Object { $_.Id }) }
}

#endregion

#region Test runner

function Measure-IgwtLatencySeries {
    <# .SYNOPSIS Round-robin echo requests to several targets for DurationSec at IntervalMs; returns the sample list per target. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Targets, [ValidateRange(2, 600)][int]$DurationSec = 30, [ValidateRange(100, 2000)][int]$IntervalMs = 250, [string]$Label = 'Measuring')
    $samples = @{}; foreach ($t in $Targets) { $samples[[string]$t.Address] = New-Object System.Collections.Generic.List[object] }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $rounds = [Math]::Max(1, [int]($DurationSec * 1000 / $IntervalMs))
    for ($i = 0; $i -lt $rounds; $i++) {
        $start = $clock.Elapsed.TotalMilliseconds
        foreach ($t in $Targets) {
            $r = Send-IgwtPingProbe -Target ([string]$t.Address) -TimeoutMs 1000
            $samples[[string]$t.Address].Add($(if ($r.Status -eq 'Success') { [double]$r.RttMs } else { $null }))
        }
        if ($i % 8 -eq 0) { Send-IgwtProgress -Text "$Label ($([int]($i * 100 / $rounds)) %)" -Percent ([int]($i * 100 / $rounds)) }
        $wait = $IntervalMs - ($clock.Elapsed.TotalMilliseconds - $start)
        if ($wait -gt 1) { Start-Sleep -Milliseconds ([int]$wait) }
    }
    $out = @{}; foreach ($k in $samples.Keys) { $out[$k] = $samples[$k].ToArray() }
    return [pscustomobject]@{ Samples = $out; DurationSec = [Math]::Round($clock.Elapsed.TotalSeconds, 1) }
}

function Invoke-IgwtNetworkQualityTest {
    <#
    .SYNOPSIS
        Full network quality test: connection profile, path trace, path MTU, latency/jitter/loss
        series to the router, the first ISP hop, internet anchors and your own targets (for
        example a game server), DNS lookup time, scores, connection type guess and
        recommendations. Read-only; sends ICMP echo requests and DNS queries only.
    .PARAMETER Duration
        Quick (10 s), Standard (30 s) or Extended (2 minutes) of measurement.
    .PARAMETER Target
        Extra host names or IP addresses to measure (up to 4), such as a game server.
    #>
    [CmdletBinding()]
    param([ValidateSet('Quick', 'Standard', 'Extended')][string]$Duration = 'Standard', [string[]]$Target, [switch]$SkipTrace, [switch]$SkipMtu)
    Send-IgwtProgress -Text 'Reading the active connection...' -Percent 0
    $conn = Get-IgwtActiveConnection
    if (-not $conn.Connected) { return [pscustomobject]@{ Generated = (Get-Date).ToString('o'); Connection = $conn; Error = $conn.Note } }
    $trace = @()
    if (-not $SkipTrace) { Send-IgwtProgress -Text 'Tracing the path to the internet...' -Percent 5; $trace = @(Invoke-IgwtRouteTrace -Target '1.1.1.1') }
    $mtu = $null
    if (-not $SkipMtu) { Send-IgwtProgress -Text 'Finding the path MTU...' -Percent 15; try { $mtu = Find-IgwtPathMtu -Target '1.1.1.1' } catch { $mtu = $null } }
    $targets = New-Object System.Collections.Generic.List[object]
    if ($conn.Gateway -and $conn.Gateway -ne '0.0.0.0') { $targets.Add([pscustomobject]@{ Name = 'Your router'; Address = $conn.Gateway; Role = 'Gateway' }) }
    $isp = @($trace | Where-Object { $_.Address -and $_.Class -in 'Public', 'CGNAT' }) | Select-Object -First 1
    if ($isp -and $isp.Address -ne '1.1.1.1') { $targets.Add([pscustomobject]@{ Name = "ISP first hop$(if ($isp.Name) { " ($($isp.Name))" })"; Address = [string]$isp.Address; Role = 'ISP' }) }
    foreach ($a in $script:IgwtNetAnchors | Select-Object -First 2) { $targets.Add([pscustomobject]@{ Name = $a.Name; Address = $a.Address; Role = 'Internet' }) }
    foreach ($t in @($Target | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Select-Object -First 4)) {
        if ($t -match $script:IgwtNetHostPattern) { $targets.Add([pscustomobject]@{ Name = $t; Address = $t; Role = 'Custom' }) }
    }
    $sec = $script:IgwtNetDurations[$Duration]
    $series = Measure-IgwtLatencySeries -Targets $targets.ToArray() -DurationSec $sec -Label 'Measuring latency, jitter and loss'
    $rows = foreach ($t in $targets) {
        $st = ConvertTo-IgwtLatencyStats -Samples $series.Samples[[string]$t.Address] -DurationSec $series.DurationSec
        [pscustomobject]@{ Name = $t.Name; Address = $t.Address; Role = $t.Role; Stats = $st; Score = (Get-IgwtNetworkScore -Stats $st) }
    }
    $rows = @($rows)
    $inet = @($rows | Where-Object { $_.Role -eq 'Internet' -and $_.Stats.Received } | Sort-Object { [double]$_.Stats.MedianMs }) | Select-Object -First 1
    if (-not $inet) { $inet = @($rows | Where-Object { $_.Role -eq 'Internet' }) | Select-Object -First 1 }
    $dns = $null
    try {
        $server = @($conn.DnsServers) | Select-Object -First 1
        if ($server) {
            $times = @(foreach ($n in 'www.microsoft.com', 'store.steampowered.com', 'www.cloudflare.com') { Measure-IgwtDnsQuery -Server $server -Name $n })
            $okT = @($times | Where-Object { $null -ne $_ } | Sort-Object)
            $dns = [pscustomobject]@{ Server = $server; MedianMs = $(if ($okT.Count) { $okT[[int][Math]::Floor(($okT.Count - 1) / 2)] } else { $null }); Failures = @($times | Where-Object { $null -eq $_ }).Count }
        }
    } catch { $dns = $null }
    $gwRow = $rows | Where-Object { $_.Role -eq 'Gateway' } | Select-Object -First 1
    $guess = Get-IgwtNetworkTypeGuess -Connection $conn -Trace $trace -Mtu $mtu -GatewayStats $(if ($gwRow) { $gwRow.Stats }) -InternetStats $(if ($inet) { $inet.Stats })
    $result = [pscustomobject]@{
        Generated = (Get-Date).ToString('o'); Duration = $Duration; DurationSec = $series.DurationSec; Connection = $conn; Trace = $trace; Mtu = $mtu
        Targets = $rows; Internet = $inet; Score = $(if ($inet) { $inet.Score } else { $null }); Dns = $dns; TypeGuess = $guess; Bufferbloat = $null; Recommendations = $null; Error = ''
        Note = 'Read-only: only ICMP echo requests and DNS queries were sent. Some servers ignore ping; game traffic can still work when ping is blocked.'
    }
    Send-IgwtProgress -Text 'Building recommendations...' -Percent 98
    $result.Recommendations = Get-IgwtNetworkRecommendations -Result $result
    return $result
}

function Measure-IgwtLoadedLatency {
    <#
    .SYNOPSIS
        Latency under load: measures while you run a speed test or large download, and grades
        bufferbloat against the idle median of an earlier test (or a short idle measurement).
        iG Windows Tuner does not generate the load itself.
    #>
    [CmdletBinding()]
    param($Baseline, [string]$Target = '1.1.1.1', [ValidateRange(5, 120)][int]$DurationSec = 20)
    $idle = $null
    if ($Baseline -and $Baseline.Targets) { $b = @($Baseline.Targets | Where-Object { $_.Address -eq $Target }) | Select-Object -First 1; if ($b) { $idle = $b.Stats.MedianMs } }
    if ($null -eq $idle) {
        $pre = Measure-IgwtLatencySeries -Targets @([pscustomobject]@{ Address = $Target }) -DurationSec 5 -Label 'Measuring idle latency'
        $idle = (ConvertTo-IgwtLatencyStats -Samples $pre.Samples[$Target]).MedianMs
    }
    $loaded = Measure-IgwtLatencySeries -Targets @([pscustomobject]@{ Address = $Target }) -DurationSec $DurationSec -Label 'Measuring latency under load'
    $st = ConvertTo-IgwtLatencyStats -Samples $loaded.Samples[$Target] -DurationSec $loaded.DurationSec
    $bb = Get-IgwtBufferbloatGrade -IdleMedianMs $idle -LoadedMedianMs $st.MedianMs
    [pscustomobject]@{ Target = $Target; IdleMedianMs = $idle; Loaded = $st; Grade = $bb.Grade; IncreaseMs = $bb.IncreaseMs
        Note = 'Run this while a speed test or large download uses the full line. A or A+ means no bufferbloat; C or worse is fixed with SQM on the router.' }
}

#endregion

#region Output

function Format-IgwtNetworkQuality {
    <# .SYNOPSIS Plain-text report of a network quality test. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Result)
    $sb = New-Object System.Text.StringBuilder
    $c = $Result.Connection
    if ($Result.Error) { return "Network test: $($Result.Error)" }
    $null = $sb.AppendLine("Connection: $($Result.TypeGuess.Local) | internet access: $($Result.TypeGuess.Access) (confidence $($Result.TypeGuess.Confidence))")
    $null = $sb.AppendLine("  Adapter: $($c.Description) | gateway $($c.Gateway) | local $($c.LocalIPv4) ($($c.LocalClass)) | IPv6 $(if ($c.IPv6) { 'yes' } else { 'no' }) | path MTU $(if ($Result.Mtu) { $Result.Mtu } else { 'n/a' })")
    if ($c.Wifi -and $c.Wifi.Connected) { $null = $sb.AppendLine("  Wi-Fi: $($c.Wifi.RadioType) $($c.Wifi.Band) channel $($c.Wifi.Channel), signal $($c.Wifi.SignalPercent) %, $($c.Wifi.ReceiveMbps)/$($c.Wifi.TransmitMbps) Mbps") }
    foreach ($e in @($Result.TypeGuess.Evidence)) { $null = $sb.AppendLine("    - $e") }
    if ($Result.Score) { $null = $sb.AppendLine(("Quality: grade {0}, score {1}/100, estimated MOS {2}. {3} (limited by {4})" -f $Result.Score.Grade, $Result.Score.Score, $Result.Score.Mos, $Result.Score.Verdict, $Result.Score.Limiting.ToLowerInvariant())) }
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine(('{0,-34} {1,7} {2,7} {3,7} {4,7} {5,7} {6,7} {7,6} {8,5}' -f 'Target', 'min', 'median', 'avg', 'p95', 'max', 'jitter', 'loss%', 'grade'))
    foreach ($t in $Result.Targets) {
        $s = $t.Stats
        $null = $sb.AppendLine(('{0,-34} {1,7} {2,7} {3,7} {4,7} {5,7} {6,7} {7,6} {8,5}' -f ($t.Name.Substring(0, [Math]::Min(34, $t.Name.Length))), $s.MinMs, $s.MedianMs, $s.AvgMs, $s.P95Ms, $s.MaxMs, $s.JitterMs, $s.LossPercent, $t.Score.Grade))
    }
    if ($Result.Dns) { $null = $sb.AppendLine("DNS lookups via $($Result.Dns.Server): median $($Result.Dns.MedianMs) ms, $($Result.Dns.Failures) failure(s)") }
    if ($Result.Bufferbloat) { $null = $sb.AppendLine("Bufferbloat: grade $($Result.Bufferbloat.Grade) (+$($Result.Bufferbloat.IncreaseMs) ms under load)") }
    if (@($Result.Trace).Count) {
        $null = $sb.AppendLine(''); $null = $sb.AppendLine('Path to 1.1.1.1:')
        foreach ($h in $Result.Trace) { $null = $sb.AppendLine(('  {0,2}  {1,-15} {2,8}  {3,-8} {4}' -f $h.Hop, $(if ($h.Address) { $h.Address } else { '*' }), $(if ($null -ne $h.RttMs) { "$($h.RttMs) ms" } else { '' }), $h.Class, $h.Name)) }
    }
    $r = $Result.Recommendations
    if ($r) {
        $null = $sb.AppendLine(''); $null = $sb.AppendLine("Recommended Windows adjustments ($($r.Profile)):")
        if (@($r.Tweaks).Count -eq 0) { $null = $sb.AppendLine('  None: every recommended item is already applied or does not apply here.') }
        foreach ($t in $r.Tweaks) { $null = $sb.AppendLine(("  {0,-34} {1} [{2}, Tier {3}]" -f $t.Id, $t.Why, $t.Level, $t.Tier)) }
        if (@($r.TweakIds).Count) { $null = $sb.AppendLine("  Preview: .\iGWindowsTuner.ps1 -Apply $($r.TweakIds -join ',') -DryRun") }
        foreach ($v in $r.Reverts) { $null = $sb.AppendLine("  Revert Risk Zone item $($v.Id): $($v.Why)") }
        $null = $sb.AppendLine(''); $null = $sb.AppendLine('Router, Wi-Fi and ISP:')
        foreach ($g in $r.Guidance) { $null = $sb.AppendLine("  [$($g.Severity)] $($g.Title): $($g.Text)") }
    }
    $null = $sb.AppendLine(''); $null = $sb.AppendLine($Result.Note)
    return $sb.ToString()
}

function Export-IgwtNetworkReport {
    <# .SYNOPSIS Writes a network quality test as a self-contained HTML file (no scripts) or JSON. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][string]$Path, [ValidateSet('Html', 'Json')][string]$Format = 'Html')
    if (-not $PSCmdlet.ShouldProcess($Path, "Write $Format network report")) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    if ($Format -eq 'Json') { [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Result -Depth 8), $utf8); return $Path }
    $e = { param($t) ConvertTo-IgwtHtmlText $t }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>iG Windows Tuner network report</title><style>')
    $null = $sb.Append(':root{--bg:#f7f7f8;--fg:#1b1b1f;--card:#fff;--muted:#5d5d66;--line:#e2e2e6;--warn:#9d5d00}@media (prefers-color-scheme:dark){:root{--bg:#1c1c1c;--fg:#f3f3f3;--card:#2b2b2b;--muted:#b0b0b8;--line:#3a3a3a;--warn:#fce100}}body{font-family:"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}main{max-width:1100px;margin:0 auto}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:8px 0;overflow-x:auto}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:5px 7px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}.muted{color:var(--muted)}.big{font-size:2rem;font-weight:600}.warn{color:var(--warn)}')
    $null = $sb.Append('</style></head><body><main>')
    $null = $sb.Append("<h1>Network quality report</h1><p class='muted'>$(& $e $Result.Generated) &middot; $(& $e $Result.Duration) test ($($Result.DurationSec) s)</p>")
    if ($Result.Score) { $null = $sb.Append("<div class='card'><span class='big'>$(& $e $Result.Score.Grade)</span> &nbsp; score $($Result.Score.Score)/100 &middot; MOS $($Result.Score.Mos) &middot; $(& $e $Result.Score.Verdict)</div>") }
    $g = $Result.TypeGuess
    $null = $sb.Append("<h2>Connection</h2><div class='card'><p><b>$(& $e $g.Local)</b>, internet access <b>$(& $e $g.Access)</b> (confidence $(& $e $g.Confidence))</p><ul>")
    foreach ($x in @($g.Evidence)) { $null = $sb.Append("<li>$(& $e $x)</li>") }
    $null = $sb.Append("</ul><p class='muted'>Adapter $(& $e $Result.Connection.Description), gateway $(& $e $Result.Connection.Gateway), path MTU $(& $e ([string]$Result.Mtu))</p></div>")
    $null = $sb.Append("<h2>Measurements</h2><div class='card'><table><tr><th>Target</th><th>min</th><th>median</th><th>avg</th><th>p95</th><th>p99</th><th>max</th><th>jitter</th><th>loss %</th><th>spikes</th><th>grade</th></tr>")
    foreach ($t in $Result.Targets) { $s = $t.Stats; $null = $sb.Append("<tr><td>$(& $e $t.Name)<br><span class='muted'>$(& $e $t.Address)</span></td><td>$($s.MinMs)</td><td>$($s.MedianMs)</td><td>$($s.AvgMs)</td><td>$($s.P95Ms)</td><td>$($s.P99Ms)</td><td>$($s.MaxMs)</td><td>$($s.JitterMs)</td><td>$($s.LossPercent)</td><td>$($s.Spikes)</td><td>$(& $e $t.Score.Grade)</td></tr>") }
    $null = $sb.Append('</table></div>')
    if (@($Result.Trace).Count) {
        $null = $sb.Append("<h2>Path</h2><div class='card'>" + (ConvertTo-IgwtHtmlTable -Rows $Result.Trace -Property Hop, Address, RttMs, Class, Name) + '</div>')
    }
    $r = $Result.Recommendations
    if ($r) {
        $null = $sb.Append("<h2>Recommended Windows adjustments ($(& $e $r.Profile))</h2><div class='card'>" + (ConvertTo-IgwtHtmlTable -Rows $r.Tweaks -Property Id, Name, Why, Level, Tier) + '</div>')
        $null = $sb.Append("<h2>Router, Wi-Fi and ISP</h2><div class='card'>" + (ConvertTo-IgwtHtmlTable -Rows $r.Guidance -Property Severity, Title, Text) + '</div>')
    }
    $null = $sb.Append("<p class='muted'>$(& $e $Result.Note)</p></main></body></html>")
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $utf8)
    return $Path
}

#endregion
