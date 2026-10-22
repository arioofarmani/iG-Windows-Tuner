# FirewallLog.ps1
# Windows Firewall as a detection source: per-profile logging status, a parser and analyzer for
# the W3C firewall log (pfirewall.log: top blocked sources, ports and apps, an hourly timeline,
# export), and an outbound allow-list builder that produces a reviewable plan only. Logging is
# turned on through the Local GPO (policy preset policy.firewall-logging). iG Windows Tuner never
# creates allow rules or switches outbound traffic to default-block itself (DECISIONS D3).

function Get-IgwtFirewallLoggingStatus {
    <# .SYNOPSIS Logging per firewall profile: dropped and allowed packets, log file and size, with a finding. Read-only. #>
    [CmdletBinding()]
    param()
    foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
        $file = [Environment]::ExpandEnvironmentVariables([string]$p.LogFileName)
        $dropped = [string]$p.LogBlocked -eq 'True'
        [pscustomobject]@{
            Profile = [string]$p.Name; Enabled = [string]$p.Enabled -eq 'True'
            LogBlocked = [string]$p.LogBlocked; LogAllowed = [string]$p.LogAllowed; LogFile = $file; MaxSizeKB = [int]$p.LogMaxSizeKilobytes
            DefaultOutbound = [string]$p.DefaultOutboundAction
            Finding = $(if (-not $dropped) { 'Dropped packets are not logged; turn it on with the Firewall Logging policy preset to see what the firewall blocks.' } elseif ([int]$p.LogMaxSizeKilobytes -lt 16384) { 'The log is under 16 MB and fills quickly; the preset sets 32 MB.' } else { '' })
        }
    }
}

function ConvertFrom-IgwtFirewallLog {
    <#
    .SYNOPSIS
        Parses W3C firewall log lines (the #Fields header names the columns: date time action
        protocol src-ip dst-ip src-port dst-port size tcpflags ... info path pid). Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)
    $fields = @('date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'size', 'tcpflags', 'tcpsyn', 'tcpack', 'tcpwin', 'icmptype', 'icmpcode', 'info', 'path', 'pid')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($l in $Lines) {
        if (-not $l) { continue }
        if ($l.StartsWith('#')) { if ($l -match '^#Fields:\s*(.+)$') { $fields = @($Matches[1].Trim() -split '\s+') }; continue }
        $parts = @($l.Trim() -split '\s+')
        if ($parts.Count -lt 8) { continue }
        $h = [ordered]@{}
        for ($i = 0; $i -lt $fields.Count -and $i -lt $parts.Count; $i++) { $h[$fields[$i]] = $(if ($parts[$i] -eq '-') { '' } else { $parts[$i] }) }
        $t = $null
        try { $t = [datetime]::ParseExact("$($h['date']) $($h['time'])", 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) } catch { $t = $null }
        $out.Add([pscustomobject]@{ Time = $t; Action = [string]$h['action']; Protocol = [string]$h['protocol']; Source = [string]$h['src-ip']; Destination = [string]$h['dst-ip']; SourcePort = [string]$h['src-port']; DestinationPort = [string]$h['dst-port']; Direction = [string]$h['path']; ProcessId = [string]$h['pid'] })
    }
    return $out.ToArray()
}

function Read-IgwtFirewallLog {
    <#
    .SYNOPSIS
        Reads the last lines of a firewall log (default: the log file of the active profiles) and
        parses them. Reading the default log needs administrator rights. Read-only.
    #>
    [CmdletBinding()]
    param([string]$Path, [int]$MaxLines = 200000)
    if (-not $Path) { $Path = @(Get-IgwtFirewallLoggingStatus | Where-Object { $_.LogFile } | ForEach-Object { $_.LogFile } | Select-Object -Unique)[0] }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Firewall log '$Path' not found. Turn on logging first (policy preset policy.firewall-logging)." }
    $lines = @()
    try { $lines = @(Get-Content -LiteralPath $Path -Tail $MaxLines -ErrorAction Stop) } catch { throw "The firewall log could not be read (administrator rights are needed for the default log): $($_.Exception.Message)" }
    # Keep the #Fields header, which -Tail may have cut off.
    $header = @(Get-Content -LiteralPath $Path -TotalCount 6 -ErrorAction SilentlyContinue | Where-Object { $_ -like '#Fields:*' })
    return (ConvertFrom-IgwtFirewallLog -Lines @(@($header) + $lines))
}

function Get-IgwtFirewallLogAnalysis {
    <#
    .SYNOPSIS
        Analysis of firewall log entries: counts by action, top blocked sources, top blocked
        destination ports (with protocol), top processes (by process id, named when the process
        still runs), and an hourly timeline of blocked and allowed packets. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [int]$Top = 10)
    $drop = @($Entries | Where-Object { $_.Action -eq 'DROP' })
    $allow = @($Entries | Where-Object { $_.Action -eq 'ALLOW' })
    $proc = @{}
    foreach ($id in @($Entries | Where-Object { $_.ProcessId } | ForEach-Object { $_.ProcessId } | Select-Object -Unique)) { $p = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue; $proc[$id] = $(if ($p) { $p.ProcessName } else { "pid $id (ended)" }) }
    $topOf = { param($set, $sb) @($set | Group-Object -Property $sb | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Value = $_.Name; Count = $_.Count } }) }
    [pscustomobject]@{
        Entries = $Entries.Count; Dropped = $drop.Count; Allowed = $allow.Count
        From = @($Entries | Where-Object Time | Sort-Object Time | Select-Object -First 1).Time; To = @($Entries | Where-Object Time | Sort-Object Time -Descending | Select-Object -First 1).Time
        TopBlockedSources = (& $topOf $drop { $_.Source })
        TopBlockedPorts = (& $topOf $drop { "$($_.Protocol)/$($_.DestinationPort)" })
        TopBlockedProcesses = (& $topOf @($drop | Where-Object ProcessId) { $proc[$_.ProcessId] })
        TopAllowedProcesses = (& $topOf @($allow | Where-Object ProcessId) { $proc[$_.ProcessId] })
        Timeline = @($Entries | Where-Object Time | Group-Object { $_.Time.ToString('yyyy-MM-dd HH:00') } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Hour = $_.Name; Dropped = @($_.Group | Where-Object Action -EQ 'DROP').Count; Allowed = @($_.Group | Where-Object Action -EQ 'ALLOW').Count } })
    }
}

function Export-IgwtFirewallLogAnalysis {
    <# .SYNOPSIS Writes a firewall log analysis as JSON, or the parsed entries as CSV (by file extension). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Analysis, [AllowEmptyCollection()][object[]]$Entries = @(), [Parameter(Mandatory = $true)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export firewall log analysis')) { return }
    $utf = New-Object System.Text.UTF8Encoding($false)
    if ($Path -match '\.csv$') { [System.IO.File]::WriteAllText($Path, ((@($Entries | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"), $utf) }
    else { [System.IO.File]::WriteAllText($Path, ($Analysis | ConvertTo-Json -Depth 5), $utf) }
}

function Get-IgwtOutboundAllowListPlan {
    <#
    .SYNOPSIS
        Expert planning aid for default-block outbound: the programs that made allowed outbound
        connections (from the firewall log, with logging of allowed packets on) and the Windows
        components that always need outbound access. It returns a plan only; iG Windows Tuner does
        not create allow rules or switch outbound traffic to block (an incomplete list cuts off
        Windows Update, Defender updates, activation, time sync and DNS).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Entries = @())
    $warnings = @(
        'Default-block outbound breaks everything that is not on the allow-list, including Windows Update, Defender security intelligence updates, Microsoft Store, activation, time sync, game launchers, anti-cheat services and voice chat.',
        'Programs that update themselves change their path; allow rules by path then silently stop matching.',
        'svchost.exe hosts many services: allow it per service, never as a whole.',
        'Test on a PC you can reach locally; keep a way back (Windows Security > Firewall > Restore defaults).'
    )
    $essential = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'defender\outbound-essentials.json')).essential | ForEach-Object { [pscustomobject]@{ Program = [string]$_.program; Service = [string]$_.service; Why = [string]$_.why } })
    $proc = @{}
    foreach ($e in @($Entries | Where-Object { $_.Action -eq 'ALLOW' -and $_.Direction -eq 'SEND' -and $_.ProcessId })) {
        if ($proc.ContainsKey($e.ProcessId)) { $proc[$e.ProcessId].Connections++; continue }
        $p = Get-Process -Id ([int]$e.ProcessId) -ErrorAction SilentlyContinue
        $path = $(if ($p) { try { $p.Path } catch { '' } } else { '' })
        $proc[$e.ProcessId] = [pscustomobject]@{ Program = $(if ($path) { $path } else { "pid $($e.ProcessId) (ended; path unknown)" }); Process = $(if ($p) { $p.ProcessName } else { '' }); Connections = 1 }
    }
    $observed = @($proc.Values | Group-Object Program | ForEach-Object { [pscustomobject]@{ Program = $_.Name; Process = $_.Group[0].Process; Connections = ($_.Group | Measure-Object Connections -Sum).Sum } } | Sort-Object Connections -Descending)
    [pscustomobject]@{ Warnings = $warnings; Essential = $essential; Observed = $observed
        Steps = @('Review the list and remove anything you do not recognize.', 'Create allow rules for each program (Windows Defender Firewall with Advanced Security > Outbound Rules), per service for svchost.exe.', 'Only then set the outbound default to Block per profile, and watch the firewall log for drops.', 'iG Windows Tuner does not do these steps for you.') }
}
