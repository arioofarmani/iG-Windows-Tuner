# Inspection.ps1
# One entry point for the read-only expert inspectors (CLI -Inspect, GUI Inspectors page) and their
# plain-text rendering.

$script:IgwtInspectionAreas = @('Power', 'Interrupts', 'Network', 'Kernel', 'Timer', 'Crash')

function Get-IgwtInspection {
    <#
    .SYNOPSIS
        Runs one or all read-only inspectors: Power (processor power settings of the active plan),
        Interrupts (PCI interrupt modes and affinity), Network (RSS, queues, buffers), Kernel
        (kernel and memory registry values), Timer and Crash (dumps and page file). Each area fails
        on its own and reports the error instead of stopping the others.
    #>
    [CmdletBinding()]
    param([ValidateSet('All', 'Power', 'Interrupts', 'Network', 'Kernel', 'Timer', 'Crash')][string[]]$Area = @('All'))
    $areas = $(if ($Area -contains 'All') { $script:IgwtInspectionAreas } else { @($Area) })
    $result = [ordered]@{ Generated = (Get-Date).ToString('o'); Elevated = (Test-IgwtIsAdmin) }
    foreach ($a in $areas) {
        try {
            $result[$a] = switch ($a) {
                'Power' { Get-IgwtPowerSettingsInspection }
                'Interrupts' { Get-IgwtInterruptInspection }
                'Network' { Get-IgwtNicQueueInspection }
                'Kernel' { Get-IgwtKernelInspection }
                'Timer' { Get-IgwtTimerInspection }
                'Crash' { Get-IgwtCrashInspection }
            }
        } catch { $result[$a] = [pscustomobject]@{ Error = $_.Exception.Message } }
    }
    return [pscustomobject]$result
}

function Format-IgwtInspection {
    <# .SYNOPSIS Plain-text rendering of Get-IgwtInspection for the console. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Inspection)
    $sb = New-Object System.Text.StringBuilder
    $line = '-' * 78
    $err = { param($o) if ($o -and $o.PSObject.Properties['Error'] -and $o.Error) { $null = $sb.AppendLine("  Error: $($o.Error)"); return $true }; return $false }
    if (-not $Inspection.Elevated) { $null = $sb.AppendLine('Note: not elevated - some RSS values and allocated resources may be incomplete.') }
    if ($Inspection.PSObject.Properties['Power']) {
        $p = $Inspection.Power
        $null = $sb.AppendLine($line); $null = $sb.AppendLine("[Power plan] $($p.SchemeName) ($($p.Scheme))")
        if (-not (& $err $p)) {
            $null = $sb.AppendLine("  $(@($p.Settings).Count) processor settings, $($p.Editable) editable here, $($p.Changed) differ from the Windows default.")
            foreach ($s in @($p.Settings | Where-Object { $_.Level -or $_.ChangedFromDefault })) {
                $flag = $(if ($s.Blocked) { ' [blocked on this hardware]' } elseif ($s.Level) { " [editable: $($s.Level)]" } else { '' })
                $def = $(if ($null -ne $s.DefaultAC) { "  default AC $($s.DefaultAC)/DC $($s.DefaultDC)$(if ($s.DefaultSource -and $s.DefaultSource -ne 'plan') { " ($($s.DefaultSource))" })" } else { '' })
                $null = $sb.AppendLine(('  {0,-20} AC {1,-26} DC {2,-26}{3}{4}{5}' -f $s.Alias, $s.AcText, $s.DcText, $def, $(if ($s.Hidden) { ' hidden' } else { '' }), $flag))
            }
        }
    }
    if ($Inspection.PSObject.Properties['Interrupts']) {
        $i = $Inspection.Interrupts
        $null = $sb.AppendLine($line); $null = $sb.AppendLine('[Interrupts]')
        if (-not (& $err $i)) {
            foreach ($d in @($i.Devices | Where-Object { $_.CatalogClass -or $_.CurrentMode -eq 'Line-based' })) {
                $mode = $(if ($d.CurrentMode -eq 'Message-signaled') { "MSI ($($d.Messages) message(s))" } elseif ($d.CurrentMode -eq 'Line-based') { "line-based (IRQ $(@($d.Irqs) -join ','))" } else { 'unknown' })
                $null = $sb.AppendLine(('  {0,-12} {1,-26} supports {2,-14} policy: {3}{4}' -f $d.Class, $mode, (@($d.Supports) -join '/'), $d.PolicyName, $(if (@($d.TargetCpus).Count) { " CPUs $(@($d.TargetCpus) -join ',')" } else { '' })))
                $null = $sb.AppendLine("               $($d.Name)$(if ($d.Note) { " - $($d.Note)" })")
            }
            $null = $sb.AppendLine("  $($i.MessageSignaled) device(s) use message-signaled interrupts, $($i.LineBased) line-based.")
        }
    }
    if ($Inspection.PSObject.Properties['Network']) {
        $n = $Inspection.Network
        $null = $sb.AppendLine($line); $null = $sb.AppendLine('[Network queues]')
        if (-not (& $err $n)) {
            foreach ($a in @($n.Adapters)) {
                $null = $sb.AppendLine("  $($a.Name) ($($a.Description), $($a.LinkSpeed))")
                $null = $sb.AppendLine(("    RSS {0}, base processor {1}, max processor {2}, receive queues {3}" -f $(if ($null -eq $a.RssEnabled) { 'unknown' } elseif ($a.RssEnabled) { 'on' } else { 'off' }), $(if ($null -ne $a.BaseProcessor) { $a.BaseProcessor } else { '?' }), $(if ($null -ne $a.MaxProcessor) { $a.MaxProcessor } else { '?' }), $(if ($null -ne $a.ReceiveQueues) { $a.ReceiveQueues } else { '?' })))
                if ($a.ReceiveBuffers) { $null = $sb.AppendLine("    receive buffers $($a.ReceiveBuffers.Value) (range $($a.ReceiveBuffers.Min)-$($a.ReceiveBuffers.Max)), transmit buffers $(if ($a.TransmitBuffers) { $a.TransmitBuffers.Value } else { '?' }); discarded received packets: $(if ($null -ne $a.DiscardedPackets) { $a.DiscardedPackets } else { '?' })") }
                foreach ($x in @($a.Advice)) { $null = $sb.AppendLine("    -> $x") }
            }
        }
    }
    if ($Inspection.PSObject.Properties['Kernel']) {
        $k = $Inspection.Kernel
        $null = $sb.AppendLine($line); $null = $sb.AppendLine("[Kernel and memory] $($k.Changed) documented value(s) differ from the Windows default")
        if (-not (& $err $k)) {
            foreach ($key in @($k.Keys)) {
                $null = $sb.AppendLine("  $($key.Name)")
                foreach ($v in @($key.Values | Where-Object { $_.Status -ne 'Default' })) {
                    $link = $(if ($v.Item) { " (catalog: $($v.Item))" } elseif ($v.Rejected) { " (see $($v.Rejected))" } else { '' })
                    $null = $sb.AppendLine(('    [{0,-12}] {1} = {2}{3}{4}' -f $v.Status, $v.Name, $v.Current, $(if ($v.Default) { " (default $($v.Default))" } else { '' }), $link))
                }
            }
        }
    }
    if ($Inspection.PSObject.Properties['Timer']) {
        $t = $Inspection.Timer
        $null = $sb.AppendLine($line); $null = $sb.AppendLine('[Timer]')
        if (-not (& $err $t)) { $null = $sb.AppendLine("  $($t.Behaviour)"); $null = $sb.AppendLine("  $($t.Note)") }
    }
    if ($Inspection.PSObject.Properties['Crash']) {
        $c = $Inspection.Crash
        $null = $sb.AppendLine($line); $null = $sb.AppendLine('[Crash dumps and page file]')
        if (-not (& $err $c)) {
            $null = $sb.AppendLine("  Dump type: $($c.DumpTypeName); restart after a stop error: $(if ($c.AutoReboot -eq 0) { 'no' } else { 'yes' }); stop code details: $(if ($c.DisplayParameters -eq 1) { 'shown' } else { 'default' }); verbose status messages: $(if ($c.VerboseStatus -eq 1) { 'on' } else { 'off' })")
            $null = $sb.AppendLine("  Minidumps: $($c.Minidumps) in $($c.MinidumpFolder)$(if ($c.LatestMinidump) { ", latest $($c.LatestMinidump)" })$(if ($null -ne $c.DumpFileBytes) { "; memory dump on disk: $([Math]::Round($c.DumpFileBytes / 1MB)) MB" })")
            $null = $sb.AppendLine("  Page file: $($c.PageFileMode) ($(@($c.PagingFiles) -join '; '))$(@($c.PageFiles | ForEach-Object { "; $($_.Path) $($_.AllocatedMB) MB allocated, peak $($_.PeakMB) MB" }) -join '')")
            foreach ($x in @($c.Advice)) { $null = $sb.AppendLine("  -> $x") }
        }
    }
    return $sb.ToString()
}
