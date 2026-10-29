# FirewallLogPage.ps1
# Security > Firewall > Log: the firewall log in a SmartGrid backed by the compiled engine
# (src\Defender\FirewallLogEngine.cs, DECISIONS F11). Reads run in the background worker; the
# newest part of the log shows first, then the whole log (with the rotated .old file). Quick
# filters, address (CIDR), port, process and time filters, an overview with drill-down, live
# follow and notes. Read-only: nothing here changes the PC. Every value comes from the network
# and is shown as plain text only.

#region Definitions

function Get-IgwtGuiFirewallLogColumns {
    <# .SYNOPSIS Columns of the log grid (keys are engine field names). #>
    [CmdletBinding()]
    param()
    @(
        @{ Key = 'TimeText'; Header = 'Time'; Kind = 'Date'; Width = 165; Tip = 'TimeUtcText' }
        @{ Key = 'Action'; Header = 'Action'; Width = 70 }
        @{ Key = 'Direction'; Header = 'Direction'; Width = 80 }
        @{ Key = 'Protocol'; Header = 'Protocol'; Width = 70 }
        @{ Key = 'Source'; Header = 'Source'; Template = 'Mono'; Width = 140 }
        @{ Key = 'SourcePort'; Header = 'Src port'; Kind = 'Number'; Width = 70 }
        @{ Key = 'Destination'; Header = 'Destination'; Template = 'Mono'; Width = 140 }
        @{ Key = 'DestinationPort'; Header = 'Dst port'; Kind = 'Number'; Width = 70 }
        @{ Key = 'Size'; Header = 'Size'; Kind = 'Number'; Width = 60 }
        @{ Key = 'TcpFlags'; Header = 'TCP flags'; Width = 70 }
        @{ Key = 'Process'; Header = 'Process'; Width = 120 }
        @{ Key = 'ProcessId'; Header = 'PID'; Kind = 'Number'; Width = 60 }
        @{ Key = 'Note'; Header = 'Note'; Width = 160 }
        @{ Key = 'Rule'; Header = 'Rule'; Width = 140; Visible = $false }
        @{ Key = 'Info'; Header = 'Info'; Width = 60; Visible = $false }
        @{ Key = 'File'; Header = 'File'; Width = 200; Visible = $false }
    )
}

function Get-IgwtGuiFirewallLogChips {
    <#
    .SYNOPSIS
        Quick filters. Field names starting with @ are handled by the engine callback, not by row
        properties. Direction uses the log's own path values (SEND, RECEIVE) as written.
    #>
    [CmdletBinding()]
    param()
    @(
        @{ Id = 'drop'; Label = 'Blocked'; Group = 'action'; Field = 'Action'; Values = @('DROP'); Tip = 'Packets the firewall dropped' }
        @{ Id = 'allow'; Label = 'Allowed'; Group = 'action'; Field = 'Action'; Values = @('ALLOW'); Tip = 'Packets the firewall allowed (logged only when "Log allowed connections" is on)' }
        @{ Id = 'in'; Label = 'Inbound'; Group = 'dir'; Field = 'Direction'; Values = @('RECEIVE'); Tip = 'Entries the log marks RECEIVE' }
        @{ Id = 'out'; Label = 'Outbound'; Group = 'dir'; Field = 'Direction'; Values = @('SEND'); Tip = 'Entries the log marks SEND' }
        @{ Id = 'tcp'; Label = 'TCP'; Group = 'proto'; Field = 'Protocol'; Values = @('TCP') }
        @{ Id = 'udp'; Label = 'UDP'; Group = 'proto'; Field = 'Protocol'; Values = @('UDP') }
        @{ Id = 'icmp'; Label = 'ICMP'; Group = 'proto'; Field = 'Protocol'; Values = @('ICMP', 'ICMPv6'); More = $true }
        @{ Id = 't15'; Label = 'Last 15 min'; Group = 'time'; Field = '@Since'; Values = @('15') }
        @{ Id = 't60'; Label = 'Last hour'; Group = 'time'; Field = '@Since'; Values = @('60') }
        @{ Id = 't1440'; Label = 'Last 24 h'; Group = 'time'; Field = '@Since'; Values = @('1440') }
        @{ Id = 'notes'; Label = 'With a note'; Group = 'notes'; Field = '@Notes'; Values = @('1'); More = $true }
    )
}

#endregion

#region Engine callback (filters, sort, overview)

function ConvertTo-IgwtGuiFirewallLogQuery {
    <#
    .SYNOPSIS
        The engine query for a grid state: search, chips, column filters (row fields and the @Address,
        @Port, @Process, @From, @To filters of the filter row) and sort. Throws on an invalid filter.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [datetime]$Now = (Get-Date))
    $q = New-Object IgwtFirewallLog.Query
    $q.Search = [string]$Grid.Search
    $byField = @{}
    foreach ($ch in @($Grid.Chips | Where-Object { $Grid.ActiveChips.Contains([string]$_.Id) })) {
        $f = [string]$ch.Field
        if (-not $byField.ContainsKey($f)) { $byField[$f] = New-Object System.Collections.Generic.List[string] }
        foreach ($v in @($ch.Values)) { $byField[$f].Add([string]$v) }
    }
    if ($byField.Action) { $q.Actions = [string[]]$byField.Action.ToArray() }
    if ($byField.Direction) { $q.Directions = [string[]]$byField.Direction.ToArray() }
    if ($byField.Protocol) { $q.Protocols = [string[]]$byField.Protocol.ToArray() }
    if ($byField['@Since']) { $q.From = $Now.AddMinutes(- [double](@($byField['@Since'] | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum)) }
    if ($byField['@Notes']) { $q.NotesOnly = $true }
    $cols = New-Object 'System.Collections.Generic.Dictionary[string,string[]]'
    foreach ($k in @($Grid.ColumnFilters.Keys)) {
        $vals = @($Grid.ColumnFilters[$k] | Where-Object { "$_" } | ForEach-Object { [string]$_ })
        if (-not $vals.Count) { continue }
        switch ([string]$k) {
            '@Address' { $q.Address = $vals[0] }
            '@Port' { $q.Ports = [int[]]@($vals | ForEach-Object { [int]$_ }) }
            '@Process' { $q.Process = $vals[0] }
            '@From' { $from = [datetime]::ParseExact($vals[0], 'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture); if (-not $q.From -or $from -gt $q.From) { $q.From = $from } }
            '@To' { $q.To = [datetime]::ParseExact($vals[0], 'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture).AddSeconds(59) }
            default { $cols[[string]$k] = [string[]]$vals }
        }
    }
    $q.Columns = $cols
    $levels = @($Grid.Sort | Where-Object { $_ })
    if ($levels.Count) {
        $q.SortKeys = [string[]]@($levels | ForEach-Object { [string]$_.Key })
        $q.SortDescending = [bool[]]@($levels | ForEach-Object { [bool]$_.Descending })
    } else {
        # Newest first by default.
        $q.SortKeys = [string[]]@('TimeText'); $q.SortDescending = [bool[]]@($true)
    }
    return $q
}

function Invoke-IgwtGuiFirewallLogQuery {
    <# .SYNOPSIS SmartGrid engine callback: runs the query on the loaded entries and schedules the overview. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $log = $script:Gui.FwLog
    # Not $( ): it would unroll the typed list into object[] (and copy every entry).
    $all = $null; if ($log) { $all = $log.All }
    if ($null -eq $all) { return @{ Items = [object[]]@(); Total = 0 } }
    $c = $script:Gui.C
    Sync-IgwtGuiFirewallLogFilterBoxes -Grid $Grid
    $q = $null
    try { $q = ConvertTo-IgwtGuiFirewallLogQuery -Grid $Grid; $c.FwLogFilterError.Text = '' }
    catch { $c.FwLogFilterError.Text = "A filter is not valid and was ignored: $($_.Exception.Message)"; $q = New-Object IgwtFirewallLog.Query }
    $items = [IgwtFirewallLog.Engine]::Run($all, $q)
    $log.View = $items
    # The overview follows in a later UI step, so the rows show first.
    $null = $script:Gui.Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [Action] { Update-IgwtGuiFirewallLogOverview })
    return @{ Items = $items; Total = $all.Count }
}

function Update-IgwtGuiFirewallLogOverview {
    <# .SYNOPSIS Summary, histogram and top lists of the current view. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $log = $script:Gui.FwLog
    if (-not $log -or $null -eq $log.View) { return }
    $c = $script:Gui.C
    $rows = $log.View
    $s = [IgwtFirewallLog.Engine]::Summarize($rows)
    $span = $(if ($s.From -and $s.To) { ' from {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}' -f $s.From, $s.To } else { '' })
    $c.FwLogSummaryText.Text = ('{0:N0} entries{1}: {2:N0} blocked, {3:N0} allowed.' -f $s.Entries, $span, $s.Dropped, $s.Allowed)
    # Histogram: about 40 bars over the time range of the view.
    $minutes = 60
    if ($s.From -and $s.To) { $minutes = [int][Math]::Max([double]1, [Math]::Ceiling(([datetime]$s.To - [datetime]$s.From).TotalMinutes / 40)) }
    $buckets = [IgwtFirewallLog.Engine]::Histogram($rows, $minutes)
    $max = 1; foreach ($b in $buckets) { $max = [Math]::Max($max, $b.Dropped + $b.Allowed) }
    $c.FwLogHistogram.ItemsSource = @(foreach ($b in $buckets) {
            [pscustomobject]@{ DroppedHeight = [double](64 * $b.Dropped / $max); AllowedHeight = [double](64 * $b.Allowed / $max); Tip = ('{0:yyyy-MM-dd HH:mm}: {1:N0} blocked, {2:N0} allowed' -f $b.Start, $b.Dropped, $b.Allowed) }
        })
    $ports = $log.PortInfo
    $fill = {
        param($list, $counts, $kind)
        $list.ItemsSource = @(foreach ($x in $counts) {
                $meaning = $(if ($kind -eq 'Port' -and $ports -and $ports.ContainsKey([string]$x.Value)) { " - $($ports[[string]$x.Value])" } else { '' })
                [pscustomobject]@{ Kind = $kind; Value = [string]$x.Value; Text = ('{0,7:N0}  {1}{2}' -f $x.Hits, $x.Value, $meaning) }
            })
        $list.DisplayMemberPath = 'Text'
    }
    & $fill $c.FwLogTopSources ([IgwtFirewallLog.Engine]::Top($rows, 'Source', 'DROP', 8)) 'Source'
    & $fill $c.FwLogTopPorts ([IgwtFirewallLog.Engine]::Top($rows, 'Port', 'DROP', 8)) 'Port'
    & $fill $c.FwLogTopProcesses ([IgwtFirewallLog.Engine]::Top($rows, 'Process', '', 8)) 'Process'
    & $fill $c.FwLogTopRemote ([IgwtFirewallLog.Engine]::Top($rows, 'Remote', '', 8)) 'Remote'
}

function Sync-IgwtGuiFirewallLogFilterBoxes {
    <# .SYNOPSIS Shows the filter-row values of the grid state in the boxes (after Clear filters or a saved view). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $c = $script:Gui.C
    foreach ($pair in @(@('@Address', 'FwLogAddressBox'), @('@Port', 'FwLogPortBox'), @('@Process', 'FwLogProcessBox'), @('@From', 'FwLogFromBox'), @('@To', 'FwLogToBox'))) {
        $v = $(if ($Grid.ColumnFilters.ContainsKey($pair[0])) { (@($Grid.ColumnFilters[$pair[0]]) -join ', ') } else { '' })
        if ([string]$c[$pair[1]].Text -ne $v) { $c[$pair[1]].Text = $v }
    }
}

function Test-IgwtGuiFirewallLogFilter {
    <#
    .SYNOPSIS
        Validates the filter-row input and returns the column filters to set (@Address, @Port,
        @Process, @From, @To) or an Error. Pure.
    #>
    [CmdletBinding()]
    param([string]$Address, [string]$Port, [string]$Process, [string]$From, [string]$To)
    $out = @{}
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Address.Trim()) {
        $net = $null; $prefix = 0
        if (-not [IgwtFirewallLog.Engine]::TryParseNetwork($Address.Trim(), [ref]$net, [ref]$prefix)) { return @{ Error = "Address: '$($Address.Trim())' is not an IP address or a network such as 192.168.1.0/24." } }
        $out['@Address'] = @($Address.Trim())
    }
    if ($Port.Trim()) {
        $ports = @()
        foreach ($p in ($Port -split '[,\s]+' | Where-Object { $_ })) {
            $n = 0
            if (-not [int]::TryParse($p, [ref]$n) -or $n -lt 0 -or $n -gt 65535) { return @{ Error = "Port: '$p' is not a port number (0 to 65535)." } }
            $ports += [string]$n
        }
        $out['@Port'] = $ports
    }
    if ($Process.Trim()) { $out['@Process'] = @($Process.Trim()) }
    foreach ($pair in @(@('@From', $From, 'From'), @('@To', $To, 'To'))) {
        $v = ([string]$pair[1]).Trim()
        if (-not $v) { continue }
        $dt = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($v, 'yyyy-MM-dd HH:mm', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) { return @{ Error = "$($pair[2]): write the time as yyyy-MM-dd HH:mm (for example $((Get-Date).ToString('yyyy-MM-dd HH:mm', $inv)))." } }
        $out[$pair[0]] = @($v)
    }
    if ($out.ContainsKey('@From') -and $out.ContainsKey('@To') -and ([datetime]::ParseExact($out['@From'][0], 'yyyy-MM-dd HH:mm', $inv) -gt [datetime]::ParseExact($out['@To'][0], 'yyyy-MM-dd HH:mm', $inv))) { return @{ Error = 'From is after To.' } }
    return @{ Filters = $out }
}

#endregion

#region Page

function Initialize-IgwtGuiFirewallLogPage {
    <# .SYNOPSIS Builds the log grid and wires the Log tab (called once by the Firewall page). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $script:Gui.FwLog = @{ All = $null; View = $null; Files = @(); Tails = @(); Notes = (Read-IgwtGuiFirewallLogNotes); PortInfo = @{}; FullApplied = $false; Timer = $null }
    try {
        foreach ($p in @((Get-IgwtFirewallKnowledgeBase).Ports)) { $script:Gui.FwLog.PortInfo["$($p.protocol)/$($p.port)"] = [string]$p.name }
    } catch { Write-Verbose "Port names not loaded: $($_.Exception.Message)" }
    $g = New-IgwtSmartGrid -Id 'firewall.log' -Noun 'entries' -SearchPlaceholder 'Search address, port, process, flags or note' -Columns (Get-IgwtGuiFirewallLogColumns) -Chips (Get-IgwtGuiFirewallLogChips) `
        -EmptyTitle 'The log has not been read' -EmptyText 'Press Read the log. Reading the default log needs administrator rights.' -SaveFilters `
        -Engine { param($grid) Invoke-IgwtGuiFirewallLogQuery -Grid $grid } -Exporter { param($grid, $rows, $path) Export-IgwtGuiFirewallLogView -Grid $grid -Rows $rows -Path $path } `
        -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiFirewallLogRead }
    $script:Gui.Grids.FirewallLog = $g
    $c.FwLogGridHost.Content = $g.Root
    Register-IgwtGuiHandler -Control $c.FwLogReadButton -Event 'Click' -Handler { Start-IgwtGuiFirewallLogRead }
    Register-IgwtGuiHandler -Control $c.FwLogApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallLogApplyFilters }
    foreach ($n in 'FwLogAddressBox', 'FwLogPortBox', 'FwLogProcessBox', 'FwLogFromBox', 'FwLogToBox') {
        Register-IgwtGuiHandler -Control $c[$n] -Event 'KeyDown' -Handler { param($s, $e) $null = $s; if ($e.Key -eq 'Return') { $e.Handled = $true; Invoke-IgwtGuiFirewallLogApplyFilters } }
    }
    Register-IgwtGuiHandler -Control $c.FwLogFollowButton -Event 'Click' -Handler { Set-IgwtGuiFirewallLogFollow -On ([bool]$script:Gui.C.FwLogFollowButton.IsChecked) }
    Register-IgwtGuiHandler -Control $c.FwLogNoteButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallLogNote }
    Register-IgwtGuiHandler -Control $c.FwLogRulesButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallLogRules }
    foreach ($n in 'FwLogTopSources', 'FwLogTopPorts', 'FwLogTopProcesses', 'FwLogTopRemote') {
        Register-IgwtGuiHandler -Control $c[$n] -Event 'SelectionChanged' -Handler { param($s, $e) $null = $e; if ($s.SelectedItem) { $item = $s.SelectedItem; $s.SelectedItem = $null; Invoke-IgwtGuiFirewallLogDrillDown -Kind $item.Kind -Value $item.Value } }
    }
}

function Start-IgwtGuiFirewallLogRead {
    <# .SYNOPSIS Reads the log in the background: the newest part first (rows at once), then everything. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $log = $script:Gui.FwLog
    $g = $script:Gui.Grids.FirewallLog
    Set-IgwtGuiFirewallLogFollow -On $false
    $log.FullApplied = $false
    Set-IgwtGridState -Grid $g -State Loading
    $script:Gui.C.FwLogStatusText.Text = 'Reading the newest entries...'
    $null = Start-IgwtGuiJob -Command 'Read-IgwtFirewallLogSession' -Parameters @{ Quick = $true; Notes = $log.Notes } -Channel 'firewall-log-quick' -BusyText 'Reading the newest firewall log entries (read-only)...' -OnComplete {
        param($out, $errs)
        $r = @($out) | Select-Object -Last 1
        if ($script:Gui.FwLog.FullApplied -or -not $r) { return }
        if ($r.Entries.Count) {
            $script:Gui.FwLog.All = $r.Entries
            Set-IgwtGridEngineReady -Grid $script:Gui.Grids.FirewallLog -Count $r.Entries.Count
            $script:Gui.C.FwLogStatusText.Text = ('Showing the newest {0:N0} entries while the whole log is read...' -f $r.Entries.Count)
        } elseif (@($r.Messages).Count -or @($errs).Count) { Show-IgwtGuiFirewallLogResult -Result $r -Errors $errs }
    }
    $null = Start-IgwtGuiJob -Command 'Read-IgwtFirewallLogSession' -Parameters @{ Notes = $log.Notes } -Channel 'firewall-log' -BusyText 'Reading the whole firewall log (read-only)...' -OnComplete {
        param($out, $errs)
        Show-IgwtGuiFirewallLogResult -Result (@($out) | Select-Object -Last 1) -Errors $errs
    }
}

function Show-IgwtGuiFirewallLogResult {
    <# .SYNOPSIS Shows a full read: rows, and a status line with the files, counts, skipped lines and problems. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Result, $Errors)
    $log = $script:Gui.FwLog
    $g = $script:Gui.Grids.FirewallLog
    $c = $script:Gui.C
    if (-not $Result) {
        Set-IgwtGridState -Grid $g -State Error -Message "The firewall log could not be read: $(@($Errors)[0])"
        $c.FwLogStatusText.Text = "The firewall log could not be read: $(@($Errors)[0])"
        return
    }
    if (-not $Result.Quick) { $log.FullApplied = $true; $log.Files = @($Result.Files) }
    $log.All = $Result.Entries
    $parts = New-Object System.Collections.Generic.List[string]
    $label = @{ NoHeader = 'before the #Fields header'; FieldCount = 'wrong number of fields'; Partial = 'partial last line' }
    foreach ($f in @($Result.Files)) {
        $skip = @($f.Skipped.Keys | Where-Object { $label.ContainsKey([string]$_) -and $f.Skipped[$_] } | ForEach-Object { "$($f.Skipped[$_]) $($label[[string]$_])" })
        $parts.Add(('{0}: {1:N0} entries ({2:N1} MB){3}' -f [IO.Path]::GetFileName($f.Path), $f.Entries, ($f.Bytes / 1MB), $(if ($skip.Count) { "; skipped $($skip -join ', ')" } else { '' })))
    }
    $text = $(if ($parts.Count) { 'Read in {0:N1} s: {1}.' -f ($Result.ReadMs / 1000), ($parts -join '; ') } else { '' })
    if (@($Result.Messages).Count) { $text = (@($text) + @($Result.Messages) | Where-Object { $_ }) -join ' ' }
    $c.FwLogStatusText.Text = $text
    if ($Result.Entries.Count -or @($Result.Files).Count) { Set-IgwtGridEngineReady -Grid $g -Count $Result.Entries.Count }
    else { Set-IgwtGridState -Grid $g -State Error -Message $(if (@($Result.Messages).Count) { @($Result.Messages)[0] } else { 'Nothing was read.' }) }
}

function Invoke-IgwtGuiFirewallLogApplyFilters {
    <# .SYNOPSIS Validates the filter row and applies it to the grid. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $g = $script:Gui.Grids.FirewallLog
    Initialize-IgwtFirewallLogEngine
    $r = Test-IgwtGuiFirewallLogFilter -Address $c.FwLogAddressBox.Text -Port $c.FwLogPortBox.Text -Process $c.FwLogProcessBox.Text -From $c.FwLogFromBox.Text -To $c.FwLogToBox.Text
    if ($r.Error) { $c.FwLogFilterError.Text = $r.Error; return }
    $c.FwLogFilterError.Text = ''
    foreach ($k in '@Address', '@Port', '@Process', '@From', '@To') { $null = $g.ColumnFilters.Remove($k) }
    foreach ($k in $r.Filters.Keys) { $g.ColumnFilters[$k] = $r.Filters[$k] }
    Update-IgwtGridView -Grid $g
    Request-IgwtGridSave -Grid $g
}

function Invoke-IgwtGuiFirewallLogDrillDown {
    <# .SYNOPSIS A click in the overview: show only the entries with that value. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][string]$Value)
    $g = $script:Gui.Grids.FirewallLog
    switch ($Kind) {
        'Port' { $parts = $Value.Split('/'); $g.ColumnFilters['Protocol'] = @($parts[0]); $g.ColumnFilters['DestinationPort'] = @($parts[-1]) }
        'Process' { $g.ColumnFilters['Process'] = @($Value) }
        default { $g.ColumnFilters[$Kind] = @($Value) }
    }
    Update-IgwtGridView -Grid $g
}

function Invoke-IgwtGuiFirewallLogRules {
    <# .SYNOPSIS Opens the Rules tab searching for the destination port of the selected entry. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param()
    $sel = @(Get-IgwtGridSelection -Grid $script:Gui.Grids.FirewallLog)
    if (-not $sel.Count -or -not $sel[0].DestinationPort) { Set-IgwtGuiStatus 'Select a log entry with a destination port first.'; return }
    $rules = $script:Gui.Grids.Firewall
    $rules.Search = [string]$sel[0].DestinationPort
    $rules.C.SearchBox.Text = $rules.Search
    $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwRulesTab
    Update-IgwtGridView -Grid $rules
}

#endregion

#region Follow live

function Set-IgwtGuiFirewallLogFollow {
    <# .SYNOPSIS Starts or stops following the current log files (new entries every 2 seconds). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([bool]$On)
    $log = $script:Gui.FwLog
    $c = $script:Gui.C
    if ($log.Timer) { $log.Timer.Stop() }
    if (-not $On) { $c.FwLogFollowButton.IsChecked = $false; return }
    $current = @($log.Files | Where-Object { $_.Current })
    if (-not $log.FullApplied -or -not $current.Count) { $c.FwLogFollowButton.IsChecked = $false; Set-IgwtGuiStatus 'Read the whole log first, then follow it.'; return }
    $log.Tails = @(foreach ($f in $current) { New-IgwtFirewallLogTail -Path $f.Path -Offset $f.EndOffset -Fields ([string[]]$f.Fields) -TimeIsUtc ([bool]$f.TimeIsUtc) })
    if (-not $log.Timer) {
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromSeconds(2)
        Register-IgwtGuiHandler -Control $t -Event 'Tick' -Handler { Invoke-IgwtGuiFirewallLogPoll }
        $log.Timer = $t
    }
    $c.FwLogFollowButton.IsChecked = $true
    $log.Timer.Start()
}

function Invoke-IgwtGuiFirewallLogPoll {
    <# .SYNOPSIS One follow step: reads the appended bytes in the background and adds the new entries. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $log = $script:Gui.FwLog
    if (-not @($log.Tails).Count) { return }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtFirewallLogTail' -Parameters @{ Tail = @($log.Tails) } -Channel 'firewall-log-tail' -BusyText 'Following the firewall log...' -OnComplete {
        param($out, $errs)
        $r = @($out) | Select-Object -Last 1
        $c = $script:Gui.C
        if (-not $r) { if (@($errs).Count) { $c.FwLogStatusText.Text = "Following stopped: $(@($errs)[0])"; Set-IgwtGuiFirewallLogFollow -On $false }; return }
        if (@($r.Messages).Count) { $c.FwLogStatusText.Text = "Following stopped: $(@($r.Messages)[0])"; Set-IgwtGuiFirewallLogFollow -On $false; return }
        if ($r.Rotated) { $c.FwLogStatusText.Text = 'The log was rotated by Windows; following the new file. Read the log again to include the older entries.' }
        if ($r.Entries.Count) {
            $script:Gui.FwLog.All.AddRange($r.Entries)
            Set-IgwtGridEngineReady -Grid $script:Gui.Grids.FirewallLog -Count $script:Gui.FwLog.All.Count
            Set-IgwtGuiStatus ('Following the firewall log: {0:N0} new entries at {1:HH:mm:ss}.' -f $r.Entries.Count, (Get-Date))
        }
    }
}

#endregion

#region Notes and export

function Get-IgwtGuiFirewallLogNotesPath {
    <# .SYNOPSIS Where the user's log notes are kept (next to the view state; IGWT_GUI_STATE_DIR in tests). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Split-Path -Parent (Get-IgwtGuiStatePath)) 'firewall-log-notes.json')
}

function Read-IgwtGuiFirewallLogNotes {
    <# .SYNOPSIS The saved notes (entry key -> text); empty when there are none. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $out = @{}
    $path = Get-IgwtGuiFirewallLogNotesPath
    if (-not (Test-Path -LiteralPath $path)) { return $out }
    try {
        $obj = [IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
        foreach ($p in $obj.PSObject.Properties) { $out[[string]$p.Name] = [string]$p.Value }
    } catch { Write-Verbose "Notes not read: $($_.Exception.Message)" }
    return $out
}

function Save-IgwtGuiFirewallLogNotes {
    <# .SYNOPSIS Writes the notes file (the user's own notes; not system state). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user notes file only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Notes)
    $path = Get-IgwtGuiFirewallLogNotesPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $o = [ordered]@{}
    foreach ($k in @($Notes.Keys | Sort-Object)) { $o[$k] = $Notes[$k] }
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject ([pscustomobject]$o) -Depth 2), (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-IgwtGuiFirewallLogNote {
    <# .SYNOPSIS Adds, changes or (empty text) removes the note of the selected entries. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the per-user notes only.')]
    [CmdletBinding()]
    param()
    $g = $script:Gui.Grids.FirewallLog
    $sel = @(Get-IgwtGridSelection -Grid $g)
    if (-not $sel.Count) { Set-IgwtGuiStatus 'Select one or more log entries first.'; return }
    $text = Show-IgwtGuiInputDialog -Title 'iG Windows Tuner - note' -Prompt "Note for $($sel.Count) selected entr$(if ($sel.Count -eq 1) { 'y' } else { 'ies' }) (empty removes the note):" -Default ([string]$sel[0].Note)
    if ($null -eq $text) { return }
    $notes = $script:Gui.FwLog.Notes
    foreach ($e in $sel) {
        $key = [IgwtFirewallLog.Engine]::NoteKey($e)
        if ([string]$text) { $notes[$key] = [string]$text } else { $null = $notes.Remove($key) }
        $e.Note = [string]$text
    }
    try { Save-IgwtGuiFirewallLogNotes -Notes $notes } catch { Show-IgwtGuiError -Message "The note was not saved: $($_.Exception.Message)" -Context 'Firewall' }
    $g.C.Grid.Items.Refresh()
}

function Export-IgwtGuiFirewallLogView {
    <# .SYNOPSIS SmartGrid exporter: the visible columns of the rows to CSV (formula-safe) or JSON, written by the engine. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the export file the user chose.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, $Rows, [Parameter(Mandatory = $true)][string]$Path)
    $cols = @($Grid.Columns | Where-Object { $Grid.DataColumns[$_.Key].Visibility -eq 'Visible' } | Sort-Object { $Grid.DataColumns[$_.Key].DisplayIndex })
    $list = New-Object 'System.Collections.Generic.List[IgwtFirewallLog.Entry]'
    if ($Rows -is [IgwtFirewallLog.Entry[]]) { $list.AddRange($Rows) } else { foreach ($r in @($Rows)) { if ($r -is [IgwtFirewallLog.Entry]) { $list.Add($r) } } }
    $keys = [string[]]@($cols | ForEach-Object { $_.Key }); $headers = [string[]]@($cols | ForEach-Object { $_.Header })
    if ($Path -like '*.json') { [IO.File]::WriteAllLines($Path, [IgwtFirewallLog.Engine]::JsonArrayLines($list, $keys, $headers), (New-Object System.Text.UTF8Encoding($false))) }
    else { [IO.File]::WriteAllLines($Path, [IgwtFirewallLog.Engine]::CsvLines($list, $keys, $headers), (New-Object System.Text.UTF8Encoding($true))) }
    return $list.Count
}

#endregion
