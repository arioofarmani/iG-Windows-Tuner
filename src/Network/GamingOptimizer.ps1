# GamingOptimizer.ps1
# Gaming network optimization for the PC this runs on: measures the connection (latency, jitter,
# loss to the router, the ISP and internet anchors, plus optional game servers), picks the Windows
# network items that lower latency and jitter on this kind of connection, applies them through the
# normal engine (restore point, snapshot, per-item rollback), checks that the network still works
# (and reverts automatically when it does not), then measures again and shows before and after.
# Measurement rules: interrupt moderation is turned off only on links up to 2.5 Gbit/s; game
# traffic is DSCP-marked only when the user confirms the router honors DSCP; items that are
# already on, not applicable or managed by policy are skipped.

function ConvertTo-IgwtLinkSpeedMbps {
    <# .SYNOPSIS Link speed text ("2.5 Gbps", "1 Gbps", "866.7 Mbps") in Mbit/s, or $null. Pure. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$LinkSpeed)
    if ($LinkSpeed -notmatch '^\s*([\d.,]+)\s*([KMG])bps\s*$') { return $null }
    $n = [double]($Matches[1] -replace ',', '.')
    switch ($Matches[2]) { 'G' { return $n * 1000 } 'M' { return $n } 'K' { return $n / 1000 } }
}

function Get-IgwtGamingNetworkPlan {
    <#
    .SYNOPSIS
        The gaming network plan for a measured connection: catalog items to apply (with the reason
        and the measurement behind it), items left out and why, and router or Wi-Fi guidance.
        Read-only.
    .PARAMETER RouterHonorsDscp
        Include DSCP marking of game traffic (only useful when the router prioritizes by DSCP).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result, [switch]$RouterHonorsDscp, $Context)
    if (-not $Context) { $Context = New-IgwtContext }
    $rec = Get-IgwtNetworkRecommendations -Result $Result -Context $Context
    $conn = $Result.Connection
    $mbps = ConvertTo-IgwtLinkSpeedMbps -LinkSpeed ([string]$conn.LinkSpeed)
    $inet = $Result.Internet
    $evidence = @()
    if ($inet -and $inet.Stats.Received) { $evidence += ("Internet: median {0} ms, jitter {1} ms, loss {2} %" -f $inet.Stats.MedianMs, $inet.Stats.JitterMs, $inet.Stats.LossPercent) }
    $gw = @($Result.Targets | Where-Object { $_.Role -eq 'Gateway' }) | Select-Object -First 1
    if ($gw -and $gw.Stats.Received) { $evidence += ("Router: median {0} ms, jitter {1} ms, loss {2} %" -f $gw.Stats.MedianMs, $gw.Stats.JitterMs, $gw.Stats.LossPercent) }
    $items = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($rec.Tweaks)) {
        $reason = ''
        if ($t.Id -eq 'net.qos-dscp-games' -and -not $RouterHonorsDscp) { $reason = 'DSCP marking only helps when the router prioritizes by DSCP; confirm with -RouterHonorsDscp.' }
        if ($t.Id -eq 'net.interrupt-moderation-off') {
            if ($null -eq $mbps) { $reason = 'The link speed is unknown; interrupt moderation stays on.' }
            elseif ($mbps -gt 2500) { $reason = "At $($conn.LinkSpeed) interrupt moderation off costs a lot of CPU; it stays at the driver default." }
        }
        if ($reason) { $skipped.Add([pscustomobject]@{ Id = $t.Id; Name = $t.Name; Reason = $reason }); continue }
        $items.Add([pscustomobject]@{ Id = $t.Id; Name = $t.Name; Level = $t.Level; Tier = $t.Tier; Why = $t.Why })
    }
    [pscustomobject]@{
        Profile = $rec.Profile; Connection = [string]$conn.Kind; LinkSpeed = [string]$conn.LinkSpeed; Evidence = $evidence
        Items = $items.ToArray(); Ids = @($items | ForEach-Object { $_.Id }); Skipped = $skipped.ToArray()
        Reverts = @($rec.Reverts); Guidance = @($rec.Guidance)
    }
}

function Test-IgwtNetworkConnectivity {
    <#
    .SYNOPSIS
        Waits until the router answers, an internet anchor answers and a DNS lookup works (adapter
        changes restart the link for a few seconds). Returns Ok and the details. Read-only.
    #>
    [CmdletBinding()]
    param([string]$Gateway, [string]$DnsServer, [ValidateRange(5, 120)][int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $gwOk = -not $Gateway; $netOk = $false; $dnsOk = -not $DnsServer
    do {
        if (-not $gwOk) { $gwOk = (Send-IgwtPingProbe -Target $Gateway -TimeoutMs 1000).Status -eq 'Success' }
        if (-not $netOk) { $netOk = ((Send-IgwtPingProbe -Target '1.1.1.1' -TimeoutMs 1000).Status -eq 'Success') -or ((Send-IgwtPingProbe -Target '8.8.8.8' -TimeoutMs 1000).Status -eq 'Success') }
        if (-not $dnsOk) { $dnsOk = $null -ne (Measure-IgwtDnsQuery -Server $DnsServer -Name 'www.microsoft.com') }
        if ($gwOk -and $netOk -and $dnsOk) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    [pscustomobject]@{ Ok = ($gwOk -and $netOk -and $dnsOk); Gateway = $gwOk; Internet = $netOk; Dns = $dnsOk }
}

function Compare-IgwtNetworkQuality {
    <#
    .SYNOPSIS
        Before/after comparison of two network quality tests per target: median, jitter, loss and
        grade, with the change and a verdict (Better, Same, Worse). Small differences are measurement
        noise and count as Same. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Before, [Parameter(Mandatory = $true)]$After)
    foreach ($b in @($Before.Targets)) {
        $a = @($After.Targets | Where-Object { $_.Address -eq $b.Address }) | Select-Object -First 1
        if (-not $a) { continue }
        $d = { param($x, $y) if ($null -eq $x -or $null -eq $y) { $null } else { [Math]::Round([double]$y - [double]$x, 2) } }
        $dMed = & $d $b.Stats.MedianMs $a.Stats.MedianMs; $dJit = & $d $b.Stats.JitterMs $a.Stats.JitterMs; $dLoss = & $d $b.Stats.LossPercent $a.Stats.LossPercent
        $score = 0
        if ($null -ne $dJit) { if ($dJit -le -0.5 -and $dJit -le -0.15 * [double]$b.Stats.JitterMs) { $score++ } elseif ($dJit -ge 0.5 -and $dJit -ge 0.15 * [double]$b.Stats.JitterMs) { $score-- } }
        if ($null -ne $dMed) { if ($dMed -le -1) { $score++ } elseif ($dMed -ge 2) { $score-- } }
        if ($null -ne $dLoss) { if ($dLoss -le -0.5) { $score++ } elseif ($dLoss -ge 0.5) { $score-- } }
        [pscustomobject]@{
            Name = $b.Name; Role = $b.Role; Address = $b.Address
            MedianBefore = $b.Stats.MedianMs; MedianAfter = $a.Stats.MedianMs; MedianChange = $dMed
            JitterBefore = $b.Stats.JitterMs; JitterAfter = $a.Stats.JitterMs; JitterChange = $dJit
            LossBefore = $b.Stats.LossPercent; LossAfter = $a.Stats.LossPercent; LossChange = $dLoss
            GradeBefore = $b.Score.Grade; GradeAfter = $a.Score.Grade
            Verdict = $(if ($score -gt 0) { 'Better' } elseif ($score -lt 0) { 'Worse' } else { 'Same' })
        }
    }
}

function Invoke-IgwtGamingNetworkOptimization {
    <#
    .SYNOPSIS
        Measures the connection, builds the gaming network plan and (unless -PlanOnly) applies it
        through the engine, checks connectivity (reverting automatically when the network does not
        come back within 60 seconds), measures again and compares before and after.
    .PARAMETER PlanOnly
        Measure and plan only; change nothing.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([ValidateSet('Quick', 'Standard', 'Extended')][string]$Duration = 'Standard', [string[]]$Target, [switch]$RouterHonorsDscp, [switch]$PlanOnly,
        [switch]$SkipRestorePoint, [switch]$AcknowledgeManaged, [ValidateRange(5, 120)][int]$ConnectivityTimeoutSec = 60, $Context)
    if (-not $Context) { $Context = New-IgwtContext }
    Send-IgwtProgress -Text 'Measuring the connection before changes...' -Percent 0
    $before = Invoke-IgwtNetworkQualityTest -Duration $Duration -Target $Target
    if ($before.Error) { return [pscustomobject]@{ Before = $before; Plan = $null; Applied = $null; Connectivity = $null; After = $null; Comparison = @(); RevertedAutomatically = $false; Error = $before.Error } }
    $plan = Get-IgwtGamingNetworkPlan -Result $before -RouterHonorsDscp:$RouterHonorsDscp -Context $Context
    $out = [ordered]@{ Before = $before; Plan = $plan; Applied = $null; Connectivity = $null; After = $null; Comparison = @(); RevertedAutomatically = $false; Error = '' }
    if ($PlanOnly -or -not $plan.Ids.Count) { return [pscustomobject]$out }
    if ($Context.IsRdp) { $out.Error = 'This is a Remote Desktop session: adapter changes restart the network link and would drop the session. Run it at the PC.'; return [pscustomobject]$out }
    if (-not $PSCmdlet.ShouldProcess("$($plan.Ids.Count) network item(s)", 'Apply gaming network settings')) { return [pscustomobject]$out }
    $applied = Invoke-IgwtApply -Id $plan.Ids -Operation 'Preset:NetworkGaming' -SkipRestorePoint:$SkipRestorePoint -AcknowledgeManaged:$AcknowledgeManaged -Context $Context
    $out.Applied = $applied
    $conn = $before.Connection
    $dns = @($conn.DnsServers) | Select-Object -First 1
    Send-IgwtProgress -Text 'Checking that the network still works...' -Percent 60
    $check = Test-IgwtNetworkConnectivity -Gateway ([string]$conn.Gateway) -DnsServer ([string]$dns) -TimeoutSec $ConnectivityTimeoutSec
    $out.Connectivity = $check
    if (-not $check.Ok) {
        if ($applied.Snapshot) { $null = Invoke-IgwtRevert -SnapshotPath $applied.Snapshot -Context $Context; $out.RevertedAutomatically = $true }
        Write-IgwtLog -Level Warn -Message "Gaming network settings reverted automatically: router $($check.Gateway), internet $($check.Internet), DNS $($check.Dns) after the change."
        $out.Error = "The network did not come back within $ConnectivityTimeoutSec seconds, so the changes were reverted automatically."
        return [pscustomobject]$out
    }
    Send-IgwtProgress -Text 'Measuring the connection after changes...' -Percent 70
    $after = Invoke-IgwtNetworkQualityTest -Duration $Duration -Target $Target -SkipMtu
    $out.After = $after
    if (-not $after.Error) { $out.Comparison = @(Compare-IgwtNetworkQuality -Before $before -After $after) }
    return [pscustomobject]$out
}
