# NetworkInspector.ps1
# NIC queue inspector (read-only): receive side scaling (enabled, profile, base and max processor,
# queues), receive and transmit buffers with the driver's allowed range, and discarded-packet
# counters, so recommendations rest on evidence. iG Windows Tuner changes RSS only through the catalog
# item net.rss-on; queue and buffer values are shown with guidance, not edited.

$script:IgwtNicQueueKeywords = @('*RSS', '*RSSProfile', '*NumRssQueues', '*RssBaseProcNumber', '*MaxRssProcessors', '*RssMaxProcNumber', '*ReceiveBuffers', '*TransmitBuffers')

function Get-IgwtNicQueueInspection {
    <#
    .SYNOPSIS
        Read-only RSS, queue and buffer view of the physical network adapters, with
        recommendations: RSS on, RSS off logical processor 0 when the driver allows it, and larger
        receive buffers only when the adapter actually discards received packets.
    #>
    [CmdletBinding()]
    param()
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { [string]$_.Status -ne 'Not Present' }) } catch { Write-Verbose 'Network adapters unavailable.' }
    $rows = foreach ($a in $adapters) {
        $name = [string]$a.Name
        $rss = $null
        try { $rss = Get-NetAdapterRss -Name $name -ErrorAction Stop } catch { $rss = $null }
        $props = @{}
        try {
            foreach ($p in @(Get-NetAdapterAdvancedProperty -Name $name -AllProperties -ErrorAction Stop)) {
                if ($script:IgwtNicQueueKeywords -contains [string]$p.RegistryKeyword) { $props[[string]$p.RegistryKeyword] = $p }
            }
        } catch { Write-Verbose "Advanced properties of $name unavailable." }
        $stats = $null
        try { $stats = Get-NetAdapterStatistics -Name $name -ErrorAction Stop } catch { $stats = $null }
        $prop = {
            param($kw)
            $p = $props[$kw]
            if (-not $p) { return $null }
            [pscustomobject]@{
                Keyword = $kw; DisplayName = [string]$p.DisplayName; Value = (@($p.RegistryValue) -join ','); DisplayValue = [string]$p.DisplayValue
                Default = [string]$p.DefaultRegistryValue; Min = $p.NumericParameterMinValue; Max = $p.NumericParameterMaxValue
                Allowed = @($p.ValidRegistryValues | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
            }
        }
        $rssEnabled = $null; $base = $null; $maxProc = $null; $queues = $null; $rssProfile = ''
        if ($rss) {
            $rssEnabled = [bool]$rss.Enabled
            if ([string]$rss.BaseProcessorNumber -ne '') { $base = [int]$rss.BaseProcessorNumber }
            if ([string]$rss.MaxProcessorNumber -ne '') { $maxProc = [int]$rss.MaxProcessorNumber }
            if ([string]$rss.NumberOfReceiveQueues -ne '') { $queues = [int]$rss.NumberOfReceiveQueues }
            $rssProfile = [string]$rss.Profile
        }
        $baseProp = & $prop '*RssBaseProcNumber'
        if ($null -eq $base -and $baseProp -and $baseProp.Value -ne '') { $base = [int]$baseProp.Value }
        $rx = & $prop '*ReceiveBuffers'
        $tx = & $prop '*TransmitBuffers'
        $discarded = $null; $rxErrors = $null
        if ($stats) { $discarded = [long]$stats.ReceivedDiscardedPackets; $rxErrors = [long]$stats.ReceivedPacketErrors }
        $advice = New-Object System.Collections.Generic.List[string]
        if ($rssEnabled -eq $false) { $advice.Add('RSS is off: turn it on (catalog item net.rss-on) so receive processing is spread across cores.') }
        if ($rssEnabled -and $base -eq 0) {
            if ($baseProp) { $advice.Add("RSS starts on logical processor 0, which also services many system interrupts. The driver offers '$($baseProp.DisplayName)': a base of 2 keeps RSS off core 0. Change it in Device Manager > adapter > Advanced if you measure DPC latency problems.") }
            else { $advice.Add('RSS starts on logical processor 0. This driver does not expose the RSS base processor, so Windows keeps its default placement.') }
        }
        if ($rx -and $null -ne $discarded) {
            if ($discarded -gt 0 -and $rx.Max -and [long]$rx.Value -lt [long]$rx.Max) { $advice.Add("$discarded received packet(s) were discarded. Raising '$($rx.DisplayName)' from $($rx.Value) toward $($rx.Max) can help; it uses a little more memory.") }
            elseif ($discarded -eq 0) { $advice.Add('No received packets were discarded since the adapter started: the receive buffers are large enough.') }
        }
        [pscustomobject]@{
            Name              = $name
            Description       = [string]$a.InterfaceDescription
            Status            = [string]$a.Status
            LinkSpeed         = [string]$a.LinkSpeed
            RssEnabled        = $rssEnabled
            RssProfile        = $rssProfile
            BaseProcessor     = $base
            MaxProcessor      = $maxProc
            ReceiveQueues     = $queues
            Queues            = (& $prop '*NumRssQueues')
            BaseProcessorProp = $baseProp
            ReceiveBuffers    = $rx
            TransmitBuffers   = $tx
            DiscardedPackets  = $discarded
            ReceiveErrors     = $rxErrors
            Advice            = $advice.ToArray()
        }
    }
    [pscustomobject]@{
        Adapters = @($rows)
        Note     = 'Read-only. Some RSS values are only visible to administrators. Queue and buffer changes are made in Device Manager > adapter > Advanced; iG Windows Tuner shows the allowed range and evidence (discarded packets).'
    }
}
