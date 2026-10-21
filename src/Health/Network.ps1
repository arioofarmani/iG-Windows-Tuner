# Network.ps1
# Active wired adapter, link speed, EEE/interrupt moderation/RSS state, DNS and DoH. Read-only.

function Get-IgwtNetworkChecks {
    [CmdletBinding()]
    param()
    $checks = New-Object System.Collections.Generic.List[object]
    $wired = @(Get-IgwtActiveWiredAdapter)
    if ($wired.Count -eq 0) {
        $checks.Add([pscustomobject]@{ Section = 'Network'; Id = 'nic'; Name = 'Wired adapter'; Status = 'Warn'; Value = 'No active wired adapter'; Detail = 'Competitive play is best on a wired connection.'; Advice = 'Use Ethernet (Cat5e or better).'; Source = '' })
    }
    foreach ($a in $wired) {
        $bps = [double]$a.ReceiveLinkSpeed
        $speedText = [string]$a.LinkSpeed
        $status = 'Pass'
        $advice = ''
        if ($bps -gt 0 -and $bps -le 100000000) {
            $status = 'Warn'
            $advice = 'Link negotiated at 100 Mbps or less: usually a damaged cable, a 2-pair cable, or a bad port. Try another Cat5e/Cat6 cable and router port.'
        }
        $drvDate = ''
        if ($a.DriverDate) { $drvDate = ([datetime]$a.DriverDate).ToString('yyyy-MM-dd') }
        $checks.Add([pscustomobject]@{ Section = 'Network'; Id = "nic-$($a.ifIndex)"; Name = 'Wired adapter'; Status = $status; Value = "$($a.InterfaceDescription) at $speedText"
                Detail = "Name '$($a.Name)', driver $($a.DriverVersionString) ($drvDate)"; Advice = $advice; Source = '' })
        $props = @()
        try { $props = @(Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -ErrorAction Stop) } catch { $props = @() }
        foreach ($kw in @(@{ K = '*EEE'; N = 'Energy Efficient Ethernet'; Want = '0' }, @{ K = '*InterruptModeration'; N = 'Interrupt moderation'; Want = $null }, @{ K = '*RSS'; N = 'Receive Side Scaling'; Want = '1' })) {
            $p = $props | Where-Object { $_.RegistryKeyword -eq $kw.K } | Select-Object -First 1
            if (-not $p) { continue }
            $val = [string](@($p.RegistryValue)[0])
            $st = 'Info'
            if ($kw.Want) { $st = $(if ($val -eq $kw.Want) { 'Pass' } else { 'Warn' }) }
            $checks.Add([pscustomobject]@{ Section = 'Network'; Id = "nic-$($a.ifIndex)-$($kw.K)"; Name = $kw.N; Status = $st; Value = "$($p.DisplayValue) ($($kw.K)=$val)"; Detail = $a.Name; Advice = ''; Source = '' })
        }
        $cfg = Get-IgwtDnsInterfaceConfig -Adapter $a
        $private = @($cfg.V4 | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' })
        $dnsDetail = $(if ($cfg.Static4) { 'Static' } else { 'From DHCP' })
        if ($private.Count -gt 0) { $dnsDetail += '; the resolver is your router (local DNS). Encrypted DNS would bypass router-side filtering and local host names.' }
        $checks.Add([pscustomobject]@{ Section = 'Network'; Id = "dns-$($a.ifIndex)"; Name = 'DNS servers'; Status = 'Info'; Value = (@($cfg.V4 + $cfg.V6) -join ', '); Detail = $dnsDetail; Advice = ''; Source = '' })
    }
    try {
        $tcp = Get-NetTCPSetting -SettingName Internet -ErrorAction Stop
        $ok = [string]$tcp.AutoTuningLevelLocal -eq 'Normal'
        $checks.Add([pscustomobject]@{ Section = 'Network'; Id = 'autotuning'; Name = 'TCP receive window auto-tuning'; Status = $(if ($ok) { 'Pass' } else { 'Warn' }); Value = [string]$tcp.AutoTuningLevelLocal
                Detail = 'Normal is the Windows default; "Disabled" (an old tweak) caps download throughput.'; Advice = $(if (-not $ok) { 'Apply "TCP auto-tuning normal" in iG Windows Tuner (Network).' } else { '' }); Source = 'https://learn.microsoft.com/en-us/powershell/module/nettcpip/set-nettcpsetting' })
    } catch { Write-Verbose 'Get-NetTCPSetting failed.' }
    $wifi = @(Get-IgwtWifiAdapter)
    foreach ($w in $wifi) {
        $checks.Add([pscustomobject]@{ Section = 'Network'; Id = "wifi-$($w.ifIndex)"; Name = 'Wi-Fi adapter'; Status = 'Info'; Value = "$($w.InterfaceDescription): $($w.Status)"; Detail = 'Unused radios can be disabled (Network > Disable unused Wi-Fi adapter).'; Advice = ''; Source = '' })
    }
    return $checks.ToArray()
}
