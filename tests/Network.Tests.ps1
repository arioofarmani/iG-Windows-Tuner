# Network quality analyzer. ICMP probes, reverse DNS, netsh, NetTCPIP/NetAdapter cmdlets and DNS
# queries are mocked; nothing is sent on the network and nothing is changed.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    function Get-TestConnection {
        param([string]$Kind = 'Ethernet', [string]$Gateway = '192.168.1.1', [string]$LocalClass = 'Private', [bool]$IPv6 = $true, $Wifi = $null, [bool]$Hotspot = $false)
        [pscustomobject]@{ Connected = $true; Kind = $Kind; Description = 'Test adapter'; LinkSpeed = '1 Gbps'; Gateway = $Gateway; GatewayClass = 'Private'; LocalIPv4 = '192.168.1.20'; LocalClass = $LocalClass
            IPv6 = $IPv6; DnsServers = @('192.168.1.1'); Mtu = 1500; Wifi = $Wifi; PhoneHotspot = $Hotspot; Note = '' }
    }
    function Get-TestHop([int]$Hop, [string]$Address, $Rtt, [string]$Name = '') {
        [pscustomobject]@{ Hop = $Hop; Address = $Address; Name = $Name; RttMs = $Rtt; Class = (InModuleScope iGWindowsTuner -Parameters @{ A = $Address } { param($A) Get-IgwtIpClass -Address $A }) }
    }
    function Get-TestStats([double[]]$Values) { ConvertTo-IgwtLatencyStats -Samples $Values -DurationSec 60 }
}

Describe 'Latency statistics and scores' {
    It 'computes loss, percentiles, jitter, spikes and loss bursts' {
        $s = ConvertTo-IgwtLatencyStats -Samples @(10, 12, $null, 14, 10, $null, $null, 50, 12, 10) -DurationSec 60
        $s.Sent | Should -Be 10; $s.Received | Should -Be 7; $s.LossPercent | Should -Be 30
        $s.MinMs | Should -Be 10; $s.MaxMs | Should -Be 50; $s.MedianMs | Should -Be 12
        $s.MaxLossBurst | Should -Be 2
        $s.JitterMs | Should -Be ([Math]::Round((2 + 2 + 4 + 40 + 38 + 2) / 6.0, 2))
        $s.Spikes | Should -Be 1
        $s.SpikesPerMinute | Should -Be 1
    }
    It 'does not extrapolate one spike in a short test to a high rate' {
        (ConvertTo-IgwtLatencyStats -Samples @(1, 1, 1, 15, 1, 1) -DurationSec 10).SpikesPerMinute | Should -Be 1
    }
    It 'handles a series without replies' {
        $s = ConvertTo-IgwtLatencyStats -Samples @($null, $null)
        $s.LossPercent | Should -Be 100; $s.MedianMs | Should -BeNullOrEmpty
        (Get-IgwtNetworkScore -Stats $s).Grade | Should -Be 'F'
    }
    It 'grades a clean fiber line A+ with a high MOS and a congested line poorly' {
        $good = Get-IgwtNetworkScore -Stats (Get-TestStats @(8, 8.2, 8.1, 8.3, 8, 8.1))
        $good.Grade | Should -Be 'A+'; $good.Mos | Should -BeGreaterThan 4.3; $good.Score | Should -BeGreaterThan 95
        $bad = Get-IgwtNetworkScore -Stats (ConvertTo-IgwtLatencyStats -Samples @(80, 140, $null, 95, 160, 70, $null, 130) -DurationSec 60)
        $bad.Grade | Should -BeIn @('D', 'F'); $bad.Mos | Should -BeLessThan 4; $bad.Limiting | Should -Not -BeNullOrEmpty
    }
    It 'grades bufferbloat from the latency increase under load' {
        (Get-IgwtBufferbloatGrade -IdleMedianMs 10 -LoadedMedianMs 12).Grade | Should -Be 'A+'
        (Get-IgwtBufferbloatGrade -IdleMedianMs 10 -LoadedMedianMs 35).Grade | Should -Be 'A'
        (Get-IgwtBufferbloatGrade -IdleMedianMs 10 -LoadedMedianMs 150).Grade | Should -Be 'C'
        (Get-IgwtBufferbloatGrade -IdleMedianMs 10 -LoadedMedianMs 900).Grade | Should -Be 'F'
        (Get-IgwtBufferbloatGrade -IdleMedianMs 10 -LoadedMedianMs 9).IncreaseMs | Should -Be 0
    }
}

Describe 'Connection profile' {
    It 'classifies IPv4 addresses' {
        InModuleScope iGWindowsTuner {
            Get-IgwtIpClass -Address '10.1.2.3' | Should -Be 'Private'
            Get-IgwtIpClass -Address '172.20.10.1' | Should -Be 'Private'
            Get-IgwtIpClass -Address '100.64.0.1' | Should -Be 'CGNAT'
            Get-IgwtIpClass -Address '100.128.0.1' | Should -Be 'Public'
            Get-IgwtIpClass -Address '1.1.1.1' | Should -Be 'Public'
            Get-IgwtIpClass -Address 'nope' | Should -Be 'Unknown'
        }
    }
    It 'parses English netsh Wi-Fi output' {
        $txt = @"
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Home
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ax
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960
    Signal                 : 88%
    Rssi                   : -52
"@
        $w = InModuleScope iGWindowsTuner -Parameters @{ T = $txt } { param($T) ConvertFrom-IgwtWlanInterfaces -Text $T }
        $w.Connected | Should -BeTrue; $w.RadioType | Should -Be '802.11ax'; $w.Generation | Should -Be 'Wi-Fi 6'; $w.Band | Should -Be '5 GHz'
        $w.Channel | Should -Be 36; $w.SignalPercent | Should -Be 88; $w.Rssi | Should -Be -52; $w.ReceiveMbps | Should -Be 1201; $w.TransmitMbps | Should -Be 960; $w.Ssid | Should -Be 'Home'
    }
    It 'parses localized netsh output from self-describing values and derives the band from the channel' {
        $txt = "    Name                   : WLAN`r`n    Status                 : Verbunden`r`n    Funktyp                : 802.11n`r`n    Kanal                  : 6`r`n    Empfangsrate (MBit/s)  : 144`r`n    Senderate (MBit/s)     : 130`r`n    Signal                 : 41 %"
        $w = InModuleScope iGWindowsTuner -Parameters @{ T = $txt } { param($T) ConvertFrom-IgwtWlanInterfaces -Text $T }
        $w.RadioType | Should -Be '802.11n'; $w.Generation | Should -Be 'Wi-Fi 4'; $w.Channel | Should -Be 6; $w.Band | Should -Be '2.4 GHz'
        $w.SignalPercent | Should -Be 41; $w.ReceiveMbps | Should -Be 144; $w.Connected | Should -BeTrue
    }
    It 'detects the default-route adapter and its kind' {
        Mock -ModuleName iGWindowsTuner Get-NetRoute { @([pscustomobject]@{ ifIndex = 7; RouteMetric = 0; InterfaceMetric = 25; NextHop = '192.168.1.1'; InterfaceAlias = 'Wi-Fi' }, [pscustomobject]@{ ifIndex = 3; RouteMetric = 0; InterfaceMetric = 75; NextHop = '10.0.0.1'; InterfaceAlias = 'Ethernet' }) }
        Mock -ModuleName iGWindowsTuner Get-NetAdapter { [pscustomobject]@{ InterfaceDescription = 'Intel(R) Wi-Fi 6E AX211 160MHz'; PhysicalMediaType = 'Native 802.11'; MediaType = 'Native 802.11'; LinkSpeed = '1.2 Gbps'; Virtual = $false; HardwareInterface = $true } }
        Mock -ModuleName iGWindowsTuner Get-NetIPConfiguration { [pscustomobject]@{ IPv4Address = @([pscustomobject]@{ IPAddress = '192.168.1.20' }); IPv6Address = @(); DNSServer = @([pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('192.168.1.1') }) } }
        Mock -ModuleName iGWindowsTuner Get-NetIPInterface { [pscustomobject]@{ NlMtu = 1500 } }
        Mock -ModuleName iGWindowsTuner Invoke-IgwtNetshWlanInterfaces { "    State : connected`n    Radio type : 802.11ac`n    Channel : 44`n    Signal : 70%" }
        $c = Get-IgwtActiveConnection
        $c.Kind | Should -Be 'WiFi'; $c.InterfaceIndex | Should -Be 7; $c.Gateway | Should -Be '192.168.1.1'; $c.Mtu | Should -Be 1500
        $c.Wifi.Generation | Should -Be 'Wi-Fi 5'; $c.IPv6 | Should -BeFalse; @($c.DnsServers) | Should -Contain '192.168.1.1'
    }
    It 'recognizes VPN, tethering and mobile broadband adapters and a missing default route' {
        Mock -ModuleName iGWindowsTuner Get-NetRoute { @([pscustomobject]@{ ifIndex = 9; RouteMetric = 0; InterfaceMetric = 5; NextHop = '10.2.0.1'; InterfaceAlias = 'wg0' }) }
        Mock -ModuleName iGWindowsTuner Get-NetIPConfiguration { [pscustomobject]@{ IPv4Address = @(); IPv6Address = @(); DNSServer = @() } }
        Mock -ModuleName iGWindowsTuner Get-NetIPInterface { }
        foreach ($case in @(@{ D = 'WireGuard Tunnel'; M = ''; K = 'VPN' }, @{ D = 'Remote NDIS based Internet Sharing Device'; M = '802.3'; K = 'Tethering' }, @{ D = 'Generic Mobile Broadband Adapter'; M = 'Wireless WAN'; K = 'Cellular' })) {
            $script:Desc = $case.D; $script:Media = $case.M
            Mock -ModuleName iGWindowsTuner Get-NetAdapter { [pscustomobject]@{ InterfaceDescription = $script:Desc; PhysicalMediaType = $script:Media; MediaType = $script:Media; LinkSpeed = ''; Virtual = $false; HardwareInterface = $true } }
            (Get-IgwtActiveConnection).Kind | Should -Be $case.K -Because $case.D
        }
        Mock -ModuleName iGWindowsTuner Get-NetRoute { }
        (Get-IgwtActiveConnection).Connected | Should -BeFalse
    }
}

Describe 'Path trace and MTU' {
    It 'traces hops with TTL-expired replies until the target answers' {
        Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe {
            switch ($Ttl) { 1 { [pscustomobject]@{ Status = 'TtlExpired'; Address = '192.168.1.1'; RttMs = 0.5 } } 2 { [pscustomobject]@{ Status = 'TimedOut'; Address = ''; RttMs = $null } } 3 { [pscustomobject]@{ Status = 'TtlExpired'; Address = '100.64.0.1'; RttMs = 30 } } default { [pscustomobject]@{ Status = 'Success'; Address = '1.1.1.1'; RttMs = 35 } } }
        }
        Mock -ModuleName iGWindowsTuner Resolve-IgwtHostName { if ($Address -eq '100.64.0.1') { 'customer.starlinkisp.net' } else { '' } }
        $h = @(Invoke-IgwtRouteTrace -Target '1.1.1.1')
        $h.Count | Should -Be 4
        $h[0].Class | Should -Be 'Private'; $h[1].Class | Should -Be 'NoReply'; $h[2].Class | Should -Be 'CGNAT'; $h[2].Name | Should -Be 'customer.starlinkisp.net'; $h[3].Address | Should -Be '1.1.1.1'
    }
    It 'finds the path MTU with Do not Fragment probes (PPPoE 1492)' {
        Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe { if ($Size -le 1464) { [pscustomobject]@{ Status = 'Success'; Address = '1.1.1.1'; RttMs = 5 } } else { [pscustomobject]@{ Status = 'PacketTooBig'; Address = ''; RttMs = $null } } }
        Find-IgwtPathMtu -Target '1.1.1.1' | Should -Be 1492
        Should -Invoke -ModuleName iGWindowsTuner Send-IgwtPingProbe -ParameterFilter { $DontFragment } -Times 3
    }
    It 'returns no MTU when even small Do not Fragment probes fail' {
        Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe { [pscustomobject]@{ Status = 'TimedOut'; Address = ''; RttMs = $null } }
        Find-IgwtPathMtu | Should -BeNullOrEmpty
    }
}

Describe 'Connection type guess' {
    It 'guesses fiber from a 1 ms first ISP hop and router names' {
        $trace = @((Get-TestHop -Hop 1 -Address '192.168.1.1' -Rtt 0.4), (Get-TestHop -Hop 2 -Address '88.10.20.1' -Rtt 1.2 -Name 'gpon-olt1.isp.net'))
        $g = Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection) -Trace $trace -Mtu 1500 -GatewayStats (Get-TestStats @(0.4, 0.4)) -InternetStats (Get-TestStats @(3, 3))
        $g.Access | Should -Be 'Fiber (FTTH)'; $g.Confidence | Should -Be 'High'; $g.Local | Should -Match 'Ethernet'
        ($g.Evidence -join ' ') | Should -Match 'gpon'
    }
    It 'guesses DSL from interleaving latency, PPPoE MTU and a BRAS name' {
        $trace = @((Get-TestHop -Hop 1 -Address '192.168.178.1' -Rtt 0.5), (Get-TestHop -Hop 2 -Address '62.1.2.3' -Rtt 14 -Name 'bras2.dsl.example.net'))
        $g = Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Gateway '192.168.178.1') -Trace $trace -Mtu 1492 -GatewayStats (Get-TestStats @(0.5)) -InternetStats (Get-TestStats @(20, 21))
        $g.Access | Should -Be 'DSL (VDSL/ADSL)'
    }
    It 'guesses cable from a CMTS name and MTU 1500' {
        $trace = @((Get-TestHop -Hop 1 -Address '192.168.0.1' -Rtt 0.5), (Get-TestHop -Hop 2 -Address '24.1.2.3' -Rtt 9 -Name 'cmts01.city.cable.example.com'))
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Gateway '192.168.0.1') -Trace $trace -Mtu 1500 -GatewayStats (Get-TestStats @(0.5))).Access | Should -Be 'Cable (DOCSIS)'
    }
    It 'guesses Starlink from 100.64.0.1 at satellite latency and its router name' {
        $trace = @((Get-TestHop -Hop 1 -Address '192.168.1.1' -Rtt 0.5), (Get-TestHop -Hop 2 -Address '100.64.0.1' -Rtt 28 -Name 'customer.starlinkisp.net'))
        $g = Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection) -Trace $trace -Mtu 1500 -GatewayStats (Get-TestStats @(0.5)) -InternetStats (Get-TestStats @(30, 45, 28))
        $g.Access | Should -Be 'Satellite (Starlink, LEO)'; $g.Confidence | Should -Be 'High'
    }
    It 'guesses geostationary satellite from a 600 ms first hop' {
        $trace = @((Get-TestHop -Hop 1 -Address '192.168.1.1' -Rtt 1), (Get-TestHop -Hop 2 -Address '5.6.7.8' -Rtt 610))
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection) -Trace $trace -GatewayStats (Get-TestStats @(1))).Access | Should -Be 'Satellite (geostationary)'
    }
    It 'recognizes mobile broadband, phone tethering and phone hotspots' {
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Kind 'Cellular')).Access | Should -Be 'Cellular (4G/5G)'
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Kind 'Tethering') -Trace @((Get-TestHop -Hop 1 -Address '192.168.42.129' -Rtt 1))).Access | Should -Be 'Cellular (4G/5G)'
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Kind 'WiFi' -Gateway '172.20.10.1' -Hotspot $true) -Trace @((Get-TestHop -Hop 1 -Address '172.20.10.1' -Rtt 3), (Get-TestHop -Hop 2 -Address '100.70.1.1' -Rtt 35))).Access | Should -Be 'Cellular (4G/5G)'
    }
    It 'does not guess the line behind a VPN and admits when evidence is missing' {
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Kind 'VPN')).Access | Should -Match 'VPN'
        $g = Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection) -Trace @((Get-TestHop -Hop 1 -Address '192.168.1.1' -Rtt 0.5))
        $g.Access | Should -Be 'Unknown'; $g.Confidence | Should -Be 'Low'
    }
    It 'describes the Wi-Fi link in the local part' {
        $w = [pscustomobject]@{ Connected = $true; Generation = 'Wi-Fi 6E'; Band = '6 GHz'; SignalPercent = 90 }
        (Get-IgwtNetworkTypeGuess -Connection (Get-TestConnection -Kind 'WiFi' -Wifi $w)).Local | Should -Be 'Wi-Fi 6E (6 GHz)'
    }
}

Describe 'Recommendations' {
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-IgwtTweakState { [pscustomobject]@{ Id = $Tweak.id; State = $(if ($Tweak.id -eq 'net.rss-on') { 'On' } elseif ($Tweak.id -eq 'risk.tcp-autotuning-disabled') { 'On' } elseif ($Tweak.id -like 'risk.*') { 'Off' } else { 'Off' }) } }
    }
    It 'recommends the Ethernet profile without items that are already on and flags applied Risk Zone network items' {
        $res = [pscustomobject]@{ Connection = (Get-TestConnection); Targets = @(); Internet = $null; Trace = @(); Bufferbloat = $null; TypeGuess = [pscustomobject]@{ Access = 'Fiber (FTTH)' }; Dns = $null }
        $r = Get-IgwtNetworkRecommendations -Result $res -Context (New-IgwtTestContext)
        $r.Profile | Should -Be 'Ethernet gaming profile'
        $r.TweakIds | Should -Contain 'net.eee-off'; $r.TweakIds | Should -Contain 'net.adapter-power-saving-off'; $r.TweakIds | Should -Not -Contain 'net.rss-on'
        $r.TweakIds | Should -Not -Contain 'net.wifi-power-max-performance'
        @($r.TweakIds | Where-Object { $_ -like 'risk.*' }).Count | Should -Be 0
        @($r.Reverts | ForEach-Object { $_.Id }) | Should -Contain 'risk.tcp-autotuning-disabled'
        ($r.Guidance | ForEach-Object { $_.Title }) | Should -Contain 'Test latency under load'
    }
    It 'recommends the Wi-Fi profile and Wi-Fi guidance for a weak 2.4 GHz link' {
        $w = [pscustomobject]@{ Connected = $true; Generation = 'Wi-Fi 4'; RadioType = '802.11n'; Band = '2.4 GHz'; SignalPercent = 35 }
        $res = [pscustomobject]@{ Connection = (Get-TestConnection -Kind 'WiFi' -Wifi $w); Targets = @(); Internet = $null; Trace = @(); Bufferbloat = [pscustomobject]@{ Grade = 'D'; IncreaseMs = 250 }; TypeGuess = [pscustomobject]@{ Access = 'Cable (DOCSIS)' }; Dns = $null }
        $r = Get-IgwtNetworkRecommendations -Result $res -Context (New-IgwtTestContext)
        $r.Profile | Should -Be 'Wi-Fi gaming profile'
        $r.TweakIds | Should -Contain 'net.wifi-power-max-performance'; $r.TweakIds | Should -Not -Contain 'net.eee-off'
        $titles = @($r.Guidance | ForEach-Object { $_.Title })
        $titles | Should -Contain 'Weak Wi-Fi signal'; $titles | Should -Contain 'Connected on 2.4 GHz'; $titles | Should -Contain 'Old Wi-Fi standard'; $titles | Should -Contain 'Bufferbloat grade D'
    }
    It 'separates home-network problems from ISP problems and ignores router-only ping noise' {
        $gwBad = [pscustomobject]@{ Role = 'Gateway'; Stats = (ConvertTo-IgwtLatencyStats -Samples @(1, 30, 1, $null, 40, 1, $null, 2) -DurationSec 60) }
        $netBad = [pscustomobject]@{ Role = 'Internet'; Stats = (ConvertTo-IgwtLatencyStats -Samples @(10, 40, $null, 12, 50, $null, 11, 45) -DurationSec 60) }
        $netGood = [pscustomobject]@{ Role = 'Internet'; Stats = (ConvertTo-IgwtLatencyStats -Samples @(10, 10, 10, 10, 10, 10, 10, 10) -DurationSec 60) }
        $mk = { param($n) [pscustomobject]@{ Connection = (Get-TestConnection); Targets = @($gwBad, $n); Internet = $n; Trace = @((Get-TestHop -Hop 1 -Address '192.168.1.1' -Rtt 1), (Get-TestHop -Hop 2 -Address '192.168.0.1' -Rtt 2), (Get-TestHop -Hop 3 -Address '100.64.1.1' -Rtt 5)); Bufferbloat = $null; TypeGuess = [pscustomobject]@{ Access = 'Unknown' }; Dns = $null } }
        $t1 = @((Get-IgwtNetworkRecommendations -Result (& $mk $netBad) -Context (New-IgwtTestContext)).Guidance | ForEach-Object { $_.Title })
        $t1 | Should -Contain 'Packet loss inside your home network'; $t1 | Should -Contain 'Double NAT'; $t1 | Should -Contain 'Carrier-grade NAT'
        $t2 = @((Get-IgwtNetworkRecommendations -Result (& $mk $netGood) -Context (New-IgwtTestContext)).Guidance | ForEach-Object { $_.Title })
        $t2 | Should -Not -Contain 'Packet loss inside your home network'; $t2 | Should -Not -Contain 'Jitter inside your home network'
    }
}

Describe 'Full network test (all probes mocked)' {
    BeforeAll {
        Mock -ModuleName iGWindowsTuner Get-IgwtActiveConnection { Get-TestConnection }
        Mock -ModuleName iGWindowsTuner Start-Sleep { }
        Mock -ModuleName iGWindowsTuner Resolve-IgwtHostName { '' }
        Mock -ModuleName iGWindowsTuner Measure-IgwtDnsQuery { 12 }
        Mock -ModuleName iGWindowsTuner Get-IgwtTweakState { [pscustomobject]@{ Id = $Tweak.id; State = 'Off' } }
        Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe {
            if ($DontFragment) { if ($Size -le 1472) { return [pscustomobject]@{ Status = 'Success'; Address = $Target; RttMs = 3 } } else { return [pscustomobject]@{ Status = 'PacketTooBig'; Address = ''; RttMs = $null } } }
            if ($Ttl -eq 1) { return [pscustomobject]@{ Status = 'TtlExpired'; Address = '192.168.1.1'; RttMs = 0.5 } }
            if ($Ttl -eq 2) { return [pscustomobject]@{ Status = 'TtlExpired'; Address = '85.1.2.3'; RttMs = 1.5 } }
            switch ($Target) { '192.168.1.1' { [pscustomobject]@{ Status = 'Success'; Address = $Target; RttMs = 0.5 } } '85.1.2.3' { [pscustomobject]@{ Status = 'Success'; Address = $Target; RttMs = 1.5 } } 'game.example' { [pscustomobject]@{ Status = 'TimedOut'; Address = ''; RttMs = $null } } default { [pscustomobject]@{ Status = 'Success'; Address = $Target; RttMs = 9 } } }
        }
    }
    It 'measures router, ISP hop, anchors and custom targets and builds the result' {
        $r = Invoke-IgwtNetworkQualityTest -Duration Quick -Target 'game.example', 'not a host!'
        @($r.Targets | ForEach-Object { $_.Role }) | Should -Be @('Gateway', 'ISP', 'Internet', 'Internet', 'Custom')
        $r.Mtu | Should -Be 1500
        $r.Internet.Stats.MedianMs | Should -Be 9
        $r.Score.Grade | Should -Be 'A+'
        @($r.Targets | Where-Object { $_.Role -eq 'Custom' })[0].Stats.LossPercent | Should -Be 100
        $r.TypeGuess.Access | Should -Be 'Fiber (FTTH)'
        $r.Dns.MedianMs | Should -Be 12
        $r.Recommendations.Profile | Should -Be 'Ethernet gaming profile'
        $text = Format-IgwtNetworkQuality -Result $r
        $text | Should -Match 'Quality: grade A\+'; $text | Should -Match '-Apply net\.'
    }
    It 'grades bufferbloat under load against the idle baseline' {
        $base = Invoke-IgwtNetworkQualityTest -Duration Quick -SkipTrace -SkipMtu
        Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe { [pscustomobject]@{ Status = 'Success'; Address = $Target; RttMs = 95 } }
        $l = Measure-IgwtLoadedLatency -Baseline $base -DurationSec 5
        $l.IdleMedianMs | Should -Be 9; $l.Grade | Should -Be 'C'; $l.IncreaseMs | Should -Be 86
    }
    It 'exports a self-contained HTML report without scripts and a JSON report' {
        $r = Invoke-IgwtNetworkQualityTest -Duration Quick -SkipTrace -SkipMtu
        $r.Connection.Description = '<b>adapter</b>'
        $html = Get-Content -LiteralPath (Export-IgwtNetworkReport -Result $r -Path (Join-Path $TestDrive 'n.html')) -Raw
        $html | Should -Not -Match '<script'; $html | Should -Match '&lt;b&gt;adapter&lt;/b&gt;'
        (Get-Content -LiteralPath (Export-IgwtNetworkReport -Result $r -Path (Join-Path $TestDrive 'n.json') -Format Json) -Raw | ConvertFrom-Json).Score.Grade | Should -Be 'A+'
    }
    It 'reports a missing connection instead of failing' {
        Mock -ModuleName iGWindowsTuner Get-IgwtActiveConnection { [pscustomobject]@{ Connected = $false; Kind = 'None'; Note = 'No default route.' } }
        (Invoke-IgwtNetworkQualityTest -Duration Quick).Error | Should -Match 'No default route'
    }
}

Describe 'Network probes refuse to run unmocked in tests' {
    It 'throws in TestMode' {
        { InModuleScope iGWindowsTuner { Send-IgwtPingProbe -Target '127.0.0.1' } } | Should -Throw '*TestMode*'
        { InModuleScope iGWindowsTuner { Invoke-IgwtNetshWlanInterfaces } } | Should -Throw '*TestMode*'
        { InModuleScope iGWindowsTuner { Resolve-IgwtHostName -Address '1.1.1.1' } } | Should -Throw '*TestMode*'
    }
}

Describe 'Network test command line (argument checks only)' {
    It 'rejects network test options without -NetworkTest' {
        $script = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -UnderLoad -NoGui
        $LASTEXITCODE | Should -Be 2
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -NetTarget x -NoGui
        $LASTEXITCODE | Should -Be 2
    }
}
