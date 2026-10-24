# DiagPage.ps1
# Diagnostics page: summary cards (DPC/ISR, stability, crashes, boot) instead of a text dump, and
# the reliability records, crashes, boots and Windows Update history as sortable, filterable,
# exportable tables (dates as yyyy-MM-dd HH:mm). Read-only.

function Format-IgwtGuiTime {
    <# .SYNOPSIS A date as yyyy-MM-dd HH:mm (local time); text that is not a date is returned as is. #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)
    if ($null -eq $Value) { return '' }
    $dt = [datetime]::MinValue
    if ($Value -is [datetime]) { $dt = $Value }
    elseif (-not [datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt) -and
        -not [datetime]::TryParse([string]$Value, [ref]$dt)) { return [string]$Value }
    if ($dt.Kind -eq [System.DateTimeKind]::Utc) { $dt = $dt.ToLocalTime() }
    return $dt.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
}

function New-IgwtGuiDiagEventRow {
    <# .SYNOPSIS SmartGrid row for one diagnostics event (reliability record, crash, boot). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([string]$Area, $Time, [string]$Kind, [string]$Detail, [string]$Tone = 'Text', [string]$Tip)
    $when = Format-IgwtGuiTime -Value $Time
    $r = [ordered]@{ Key = "$Area|$when|$Kind|$($Detail.GetHashCode())"; Area = $Area; When = $when; Detail = $Detail; Tip = $(if ($Tip) { $Tip } else { $Detail }) }
    Add-IgwtGuiStatusField -Row $r -Name 'KindCol' -Text $Kind -Tone $Tone
    [pscustomobject]$r
}

function Get-IgwtGuiDiagEventRows {
    <# .SYNOPSIS Event rows from a Get-IgwtDiagnostics result (never throws on missing parts). #>
    [CmdletBinding()]
    param($Diagnostics)
    $d = $Diagnostics
    if (-not $d) { return @() }
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] }
    $rows = New-Object System.Collections.Generic.List[object]
    if ((& $has $d 'Reliability') -and (& $has $d.Reliability 'Records')) {
        foreach ($x in @($d.Reliability.Records)) {
            if (-not $x) { continue }
            $detail = (@([string]$x.Product, [string]$x.Message) | Where-Object { $_ }) -join ': '
            $rows.Add((New-IgwtGuiDiagEventRow -Area 'Reliability' -Time $x.Time -Kind ([string]$x.Source) -Detail $detail -Tone 'Warn'))
        }
    }
    if ((& $has $d 'Crashes') -and (& $has $d.Crashes 'Events')) {
        foreach ($x in @($d.Crashes.Events)) {
            if (-not $x) { continue }
            $tone = $(if ([string]$x.Kind -in 'BugCheck', 'KernelPower41') { 'Fail' } else { 'Warn' })
            $rows.Add((New-IgwtGuiDiagEventRow -Area 'Crashes' -Time $x.Time -Kind ([string]$x.Kind) -Detail ([string]$x.Detail) -Tone $tone))
        }
    }
    if ((& $has $d 'Boot') -and (& $has $d.Boot 'Boots')) {
        foreach ($x in @($d.Boot.Boots)) {
            if (-not $x) { continue }
            $sec = { param($ms) if ($null -eq $ms -or "$ms" -eq '') { '?' } else { '{0:N1} s' -f ([double]$ms / 1000) } }
            $rows.Add((New-IgwtGuiDiagEventRow -Area 'Boot' -Time $x.Time -Kind $(if ($x.Degraded) { 'Slow boot' } else { 'Boot' }) -Tone $(if ($x.Degraded) { 'Warn' } else { 'Pass' }) `
                        -Detail "Total $(& $sec $x.BootMs), main path $(& $sec $x.MainPathMs), after sign-in $(& $sec $x.PostBootMs)"))
        }
    }
    return $rows.ToArray()
}

function New-IgwtGuiUpdateHistoryRow {
    <# .SYNOPSIS SmartGrid row for one Windows Update history entry. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param($Entry)
    $h = $Entry
    $result = [string]$h.Result
    $when = Format-IgwtGuiTime -Value $h.Date
    $hr = ''
    if ($null -ne $h.HResult -and "$($h.HResult)" -ne '' -and [long]$h.HResult -ne 0) { $hr = '0x{0:X8}' -f ([long]$h.HResult -band 0xFFFFFFFFL) }
    $r = [ordered]@{ Key = "$when|$($h.Title)"; When = $when; Title = [string]$h.Title; HResultText = $hr; ResultKey = $result }
    $tone = switch -Regex ($result) { '^Succeeded$' { 'Pass' } 'Fail|Abort' { 'Fail' } 'Errors' { 'Warn' } default { 'Muted' } }
    Add-IgwtGuiStatusField -Row $r -Name 'ResultCol' -Text $(if ($result) { $result } else { 'Unknown' }) -Tone $tone
    [pscustomobject]$r
}

function Initialize-IgwtGuiDiagGrids {
    <# .SYNOPSIS Builds the Diagnostics event and update history grids. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $diag = { param($grid) $null = $grid; Start-IgwtGuiDiagRefresh }
    $g = New-IgwtSmartGrid -Id 'diag.events' -Noun 'events' -RowKey 'Key' -SearchPlaceholder 'Search events' -SelectionMode Single -OnRefresh $diag `
        -EmptyTitle 'No events' -EmptyText 'No reliability records, crashes or boot records in the last 30 days.' -Columns @(
        @{ Key = 'When'; Header = 'When'; Width = 140; Kind = 'Date' }
        @{ Key = 'Area'; Header = 'Area'; Width = 110 }
        @{ Key = 'KindCol'; Header = 'Event'; Width = 170; Template = 'Status' }
        @{ Key = 'Detail'; Header = 'Detail'; MinWidth = 240; Tip = 'Tip' }
    ) -Chips @(
        @{ Id = 'reliability'; Label = 'Reliability'; Group = 'area'; Field = 'Area'; Values = @('Reliability') }
        @{ Id = 'crashes'; Label = 'Crashes'; Group = 'area'; Field = 'Area'; Values = @('Crashes') }
        @{ Id = 'boot'; Label = 'Boot'; Group = 'area'; Field = 'Area'; Values = @('Boot') }
        @{ Id = 'week'; Label = 'Last 7 days'; Group = 'age'; Test = { param($row) $dt = [datetime]::MinValue; [datetime]::TryParse([string]$row.When, [ref]$dt) -and $dt -ge (Get-Date).AddDays(-7) } }
    )
    Add-IgwtGuiListGrid -Name 'DiagEventList' -Grid $g -SortBy 'When' -Descending
    $g = New-IgwtSmartGrid -Id 'diag.updates' -Noun 'updates' -RowKey 'Key' -SearchPlaceholder 'Search update history' -SelectionMode Single -OnRefresh $diag `
        -EmptyTitle 'No update history' -EmptyText 'Windows Update has no history on this PC yet.' -Columns @(
        @{ Key = 'When'; Header = 'When'; Width = 140; Kind = 'Date' }
        @{ Key = 'ResultCol'; Header = 'Result'; Width = 160; Template = 'Status' }
        @{ Key = 'Title'; Header = 'Update'; MinWidth = 260; Tip = 'Title' }
        @{ Key = 'HResultText'; Header = 'Error code'; Width = 110; Template = 'Mono' }
    ) -Chips @(
        @{ Id = 'failed'; Label = 'Failed'; Group = 'result'; Test = { param($row) [string]$row.ResultKey -match 'Fail|Abort|Errors' } }
        @{ Id = 'ok'; Label = 'Succeeded'; Group = 'result'; Field = 'ResultKey'; Values = @('Succeeded') }
    )
    Add-IgwtGuiListGrid -Name 'DiagUpdateList' -Grid $g -SortBy 'When' -Descending
}

function Set-IgwtGuiDiagCards {
    <# .SYNOPSIS Fills the four Diagnostics summary cards (DPC/ISR, stability, crashes, boot) from a Get-IgwtDiagnostics result. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Diagnostics)
    $c = $script:Gui.C
    $d = $Diagnostics
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] }
    $err = { param($o) if (& $has $o 'Error') { "Not readable: $($o.Error)" } else { 'Not read yet.' } }
    $set = { param($name, $value, $note, $tip) $c["Diag${name}Value"].Text = $value; $c["Diag${name}Note"].Text = $note; $c["Diag${name}Card"].ToolTip = $(if ($tip) { $tip } else { $null }) }
    $x = $(if (& $has $d 'DpcIsr') { $d.DpcIsr } else { $null })
    if ((& $has $x 'Dpc') -and -not (& $has $x 'Error')) {
        $top = @($x.TopProcesses | Select-Object -First 1)
        & $set 'Dpc' ("DPC {0} %  |  ISR {1} %" -f $x.Dpc.Average, $x.Isr.Average) $(if (@($x.Advice).Count) { [string]@($x.Advice)[0] } elseif ($top) { "Busiest: $($top[0].Name) ($($top[0].CpuPercent) % CPU)" } else { 'Interrupt time is low.' }) `
        ((@("Peak DPC $($x.Dpc.Max) %, peak ISR $($x.Isr.Max) %, $([Math]::Round([double]$x.Interrupts.Average)) interrupts/s") + @($x.TopProcesses | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.CpuPercent) % CPU, $($_.WorkingSetMB) MB" }) + @($x.Advice)) -join [Environment]::NewLine)
    } else { & $set 'Dpc' '-' (& $err $x) $null }
    $x = $(if (& $has $d 'Reliability') { $d.Reliability } else { $null })
    if (& $has $x 'Records') { & $set 'Stability' $(if ($null -ne $x.Current) { "$($x.Current) / 10" } else { 'n/a' }) "$(@($x.Records).Count) record(s) in $($x.Days) days" $null }
    else { & $set 'Stability' '-' (& $err $x) $null }
    $x = $(if (& $has $d 'Crashes') { $d.Crashes } else { $null })
    if (& $has $x 'Counts') {
        $k = $x.Counts
        $system = [int]$k.BugCheck + [int]$k.KernelPower41 + [int]$k.UnexpectedShutdown
        & $set 'Crash' $(if ($system) { "$system system crash(es)" } else { 'No system crashes' }) "Blue screens $($k.BugCheck), power loss $($k.KernelPower41), app crashes $($k.AppCrash) ($($x.Days) days)" (@($x.Advice) -join [Environment]::NewLine)
    } else { & $set 'Crash' '-' (& $err $x) $null }
    $x = $(if (& $has $d 'Boot') { $d.Boot } else { $null })
    if ((& $has $x 'Boots') -and -not $x.Error) { & $set 'Boot' "$($x.AverageBootSeconds) s" "Average of $(@($x.Boots).Count) boot(s)" $null }
    elseif (& $has $x 'Boots') { & $set 'Boot' '-' ([string]$x.Error) $null }
    else { & $set 'Boot' '-' (& $err $x) $null }
}
