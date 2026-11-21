# NetworkCards.ps1
# 4.0 section 6 (D7): the Network page next to the test: a DNS card (servers, encrypted or not, and a
# DNS benchmark), a network profile card (Public or Private, with the confirmed category change of the
# Firewall Profiles tab) and the programs that firewall rules block. Reads with the exported
# Get-IgwtNetworkOverview in the worker; changes only through Set-IgwtNetworkCategory (after a
# confirmation, Invoke-IgwtGuiFirewallProfileTag). Handlers use Tags, never closures (DECISIONS U9).

function Start-IgwtGuiNetOverviewLoad {
    <# .SYNOPSIS Reads the network profiles, DNS servers and blocked programs in the background (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Get-IgwtNetworkOverview' -Channel 'netoverview' -BusyText 'Reading the network settings...' -OnComplete {
        param($out, $errs)
        $o = @($out | Where-Object { $_ }) | Select-Object -Last 1
        $script:Gui.NetOverview = $(if ($o) { $o } else { [pscustomobject]@{ Profiles = @(); ProfileError = "Not read: $(@($errs)[0])"; Dns = @(); DnsError = ''; Blocked = @(); BlockedError = '' } })
        Update-IgwtGuiNetCards
    }
}

function Get-IgwtGuiBlockedProgramLines {
    <# .SYNOPSIS The blocked programs as lines; a name that two folders share gets its folder (System32, SysWOW64). Pure. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([object[]]$Blocked = @(), [int]$Max = 8)
    $dup = @{}; foreach ($b in @($Blocked)) { $k = ([string]$b.Name).ToLowerInvariant(); $dup[$k] = 1 + [int]$dup[$k] }
    $lines = @(@($Blocked) | Select-Object -First $Max | ForEach-Object {
            $label = $(if ($dup[([string]$_.Name).ToLowerInvariant()] -gt 1 -and $_.Folder) { "$($_.Name) ($($_.Folder))" } else { [string]$_.Name })
            "$label - $($_.Rules) rule$(if ($_.Rules -ne 1) { 's' }), $(([string]$_.Directions).ToLowerInvariant())"
        })
    if (@($Blocked).Count -gt $Max) { $lines += "and $(@($Blocked).Count - $Max) more" }
    return $lines
}

function Update-IgwtGuiNetCards {
    <# .SYNOPSIS Draws the DNS, network profile and blocked programs cards into NetCardsHost. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $h = $script:Gui.C.NetCardsHost
    if (-not $h) { return }
    $h.Children.Clear()
    $o = $script:Gui.NetOverview
    if (-not $o) { $null = $h.Children.Add((New-IgwtUiText -Text 'Reading the network settings (read-only)...' -Style 'TextBody' -Brush 'BrushTextMuted')); return }
    $mkCard = {
        param($title)
        $b = New-Object System.Windows.Controls.Border; $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Card4')
        $sp = New-Object System.Windows.Controls.StackPanel
        $t = New-IgwtUiText -Text $title -Style 'TextSubtitle'
        [System.Windows.Automation.AutomationProperties]::SetHeadingLevel($t, [System.Windows.Automation.AutomationHeadingLevel]::Level2)
        $null = $sp.Children.Add($t); $b.Child = $sp
        return $b
    }
    $row = New-Object System.Windows.Controls.Grid
    foreach ($w in '1*', '1*') { $cd = New-Object System.Windows.Controls.ColumnDefinition; $cd.Width = (New-Object System.Windows.GridLengthConverter).ConvertFromString($w); $row.ColumnDefinitions.Add($cd) }
    $row.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)

    # DNS
    $dns = & $mkCard 'DNS'; $dns.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
    $ds = $dns.Child
    if ($o.DnsError) { $null = $ds.Children.Add((New-IgwtUiText -Text $o.DnsError -Style 'TextBody' -Brush 'BrushTextMuted')) }
    foreach ($d in @($o.Dns)) {
        $line = New-Object System.Windows.Controls.StackPanel; $line.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)
        $null = $line.Children.Add((New-IgwtUiText -Text "$($d.Interface): $(@($d.Servers) -join ', ')" -Style 'TextBodyStrong'))
        $enc = @($d.Encrypted).Count
        $pill = $(if ($enc -and $enc -eq @($d.Servers).Count) { New-IgwtPill -Text 'Encrypted (DNS over HTTPS)' -Tone Success } elseif ($enc) { New-IgwtPill -Text 'Partly encrypted' -Tone Warning } else { New-IgwtPill -Text 'Not encrypted' -Tone Neutral })
        $pill.HorizontalAlignment = 'Left'; $pill.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0)
        $null = $line.Children.Add($pill)
        $null = $ds.Children.Add($line)
    }
    if (-not @($o.Dns).Count -and -not $o.DnsError) { $null = $ds.Children.Add((New-IgwtUiText -Text 'No connected network adapter with DNS servers.' -Style 'TextBody' -Brush 'BrushTextMuted')) }
    $btns = New-Object System.Windows.Controls.WrapPanel; $btns.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
    $bench = New-IgwtUiButton -Text 'Benchmark DNS' -Kind Secondary
    $bench.ToolTip = 'Measures how fast your DNS servers and a few public ones answer (DNS queries only; nothing changes).'
    Register-IgwtGuiHandler -Control $bench -Event 'Click' -Handler { Invoke-IgwtGuiDnsBenchmark }
    $doh = New-IgwtUiButton -Text 'Encrypted DNS settings' -Kind Subtle
    $doh.ToolTip = 'The DNS over HTTPS items (Cloudflare, Quad9) are in Optimize > Network settings.'
    Register-IgwtGuiHandler -Control $doh -Event 'Click' -Handler { Open-IgwtGuiPage -Page 'Network' }
    $null = $btns.Children.Add($bench); $null = $btns.Children.Add($doh); $null = $ds.Children.Add($btns)
    $null = $row.Children.Add($dns)

    # Network profile
    $pc = & $mkCard 'Network profile'; $pc.Margin = [System.Windows.Thickness]::new(8, 0, 0, 0)
    [System.Windows.Controls.Grid]::SetColumn($pc, 1)
    $ps = $pc.Child
    if ($o.ProfileError) { $null = $ps.Children.Add((New-IgwtUiText -Text $o.ProfileError -Style 'TextBody' -Brush 'BrushTextMuted')) }
    foreach ($p in @($o.Profiles)) {
        $line = New-Object System.Windows.Controls.DockPanel; $line.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)
        $other = $(if ($p.Category -eq 'Private') { 'Public' } else { 'Private' })
        if ($p.Category -in 'Public', 'Private') {
            $sw = New-IgwtUiButton -Text "Set to $other" -Kind Secondary -ObjectName "($($p.Name))"
            $sw.Tag = "net|$($p.InterfaceIndex)|$other"; $sw.VerticalAlignment = 'Center'
            $sw.IsEnabled = [bool]$script:Gui.IsAdmin -and -not (Test-IgwtReadOnly)
            $sw.ToolTip = $(if ($other -eq 'Private') { 'Only for your own home network: Private allows discovery and file sharing.' } else { 'Public is the safer choice for networks you do not control.' })
            Register-IgwtGuiHandler -Control $sw -Event 'Click' -Handler { param($s, $e) $null = $e; Invoke-IgwtGuiFirewallProfileTag -Tag ([string]$s.Tag) }
            [System.Windows.Controls.DockPanel]::SetDock($sw, 'Right'); $null = $line.Children.Add($sw)
        }
        $txt = New-Object System.Windows.Controls.StackPanel
        $null = $txt.Children.Add((New-IgwtUiText -Text "$($p.Name) ($($p.Interface))" -Style 'TextBodyStrong'))
        $cat = New-IgwtPill -Text $p.Category -Tone $(if ($p.Category -eq 'Public') { 'Success' } elseif ($p.Category -eq 'Private') { 'Info' } else { 'Neutral' })
        $cat.HorizontalAlignment = 'Left'; $cat.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0)
        $null = $txt.Children.Add($cat)
        $null = $line.Children.Add($txt)
        $null = $ps.Children.Add($line)
    }
    if (-not @($o.Profiles).Count -and -not $o.ProfileError) { $null = $ps.Children.Add((New-IgwtUiText -Text 'No connected network.' -Style 'TextBody' -Brush 'BrushTextMuted')) }
    $note = New-IgwtUiText -Text 'Public is the safer choice; use Private only for your own home network.' -Style 'TextCaption' -Brush 'BrushTextMuted'
    $note.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0); $null = $ps.Children.Add($note)
    $null = $row.Children.Add($pc)
    $null = $h.Children.Add($row)

    # Blocked programs
    $bc = & $mkCard 'Blocked programs'
    $bs = $bc.Child
    if ($o.BlockedError) { $null = $bs.Children.Add((New-IgwtUiText -Text $o.BlockedError -Style 'TextBody' -Brush 'BrushTextMuted')) }
    elseif (-not @($o.Blocked).Count) { $null = $bs.Children.Add((New-IgwtUiText -Text 'No program is blocked by a firewall rule.' -Style 'TextBody' -Brush 'BrushTextMuted')) }
    else {
        $sub = New-IgwtUiText -Text "$(@($o.Blocked).Count) program$(if (@($o.Blocked).Count -ne 1) { 's' }) blocked by enabled firewall rules. A game or launcher in this list cannot connect." -Style 'TextBody' -Brush 'BrushTextMuted'
        $sub.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4); $null = $bs.Children.Add($sub)
        foreach ($l in @(Get-IgwtGuiBlockedProgramLines -Blocked @($o.Blocked))) { $t = New-IgwtUiText -Text $l -Style 'TextBody'; $t.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0); $null = $bs.Children.Add($t) }
    }
    $fw = New-IgwtUiButton -Text 'Open firewall rules' -Kind Subtle; $fw.HorizontalAlignment = 'Left'; $fw.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
    Register-IgwtGuiHandler -Control $fw -Event 'Click' -Handler { Open-IgwtGuiPage -Page 'Firewall' }
    $null = $bs.Children.Add($fw)
    $null = $h.Children.Add($bc)
}

function Invoke-IgwtGuiDnsBenchmark {
    <# .SYNOPSIS Runs the DNS benchmark in the background (DNS queries only) and shows the result. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only measurement.')]
    [CmdletBinding()]
    param()
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtDnsBenchmark' -Channel 'dnsbench' -BusyText 'Measuring DNS servers (DNS queries only)...' -OnComplete {
        param($out, $errs)
        $r = @($out | Where-Object { $_ }) | Select-Object -Last 1
        if (-not $r) { Show-IgwtGuiError -Message "The DNS benchmark did not run: $(@($errs)[0])" -Context 'Network'; return }
        $lines = @(@($r.Results) | ForEach-Object { '{0,-24} {1,-16} median {2} ms, worst {3} ms{4}' -f $_.Name, $_.Server, $_.MedianMs, $_.WorstMs, $(if ($_.Failures) { ", $($_.Failures) failed" } else { '' }) })
        $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - DNS benchmark' -Text (($lines + @('', [string]$r.Note)) -join [Environment]::NewLine)
    }
}
