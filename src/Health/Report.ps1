# Report.ps1
# Aggregates every read-only health check into one report; console, HTML and JSON output.

function Get-IgwtHardwareSummary {
    <# .SYNOPSIS One-line hardware summary for the GUI header and the report title. #>
    [CmdletBinding()]
    param()
    $cpu = Get-IgwtCpuInfo
    $mem = Get-IgwtMemoryInfo
    $os = Get-IgwtOsInfo
    $gpu = ''
    try { $gpu = (@(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.PNPDeviceID -like 'PCI\*' } | ForEach-Object { $_.Name }) -join ' + ') } catch { $gpu = '' }
    $cpuShort = ($cpu.Name -replace '\(R\)|\(TM\)|CPU|Processor|\d+th Gen ', '' -replace '\s+', ' ').Trim()
    [pscustomobject]@{
        Cpu   = $cpuShort
        Gpu   = $gpu
        Memory = "$($mem.TotalGB) GB $($mem.Type)-$($mem.ConfiguredMTs)"
        Os    = "$($os.Caption -replace 'Microsoft ', '') $($os.DisplayVersion) ($($os.FullBuild))"
        Text  = "$cpuShort | $gpu | $($mem.TotalGB) GB $($mem.Type)-$($mem.ConfiguredMTs) | $($os.Caption -replace 'Microsoft ', '') $($os.DisplayVersion) ($($os.FullBuild))"
    }
}

function Get-IgwtRecommendations {
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{ Title = 'Test bufferbloat on your router'; Text = 'Run a bufferbloat test (for example the Waveform bufferbloat test) while the line is loaded. If latency rises a lot under load, enable SQM / Smart Queue (CAKE or fq_codel) on the router. This usually matters more for online play than any Windows setting.'; Source = 'https://www.waveform.com/tools/bufferbloat' }
        [pscustomobject]@{ Title = 'Keep the BIOS current'; Text = 'BIOS updates carry CPU microcode (13th/14th-gen Vmin Shift fix 0x12F+), Secure Boot key updates and memory compatibility fixes.'; Source = '' }
        [pscustomobject]@{ Title = 'Use the Intel Default Settings profile'; Text = 'On 13th/14th-gen Intel CPUs, load the "Intel Default Settings" profile in BIOS for safe power limits and current limits.'; Source = 'https://www.intel.com/content/www/us/en/support/articles/000102331/processors.html' }
        [pscustomobject]@{ Title = 'Turn on NVIDIA Reflex in game'; Text = 'Reflex lowers render latency more than any OS tweak. Dota 2, CS2 and VALORANT support it.'; Source = 'https://www.nvidia.com/en-us/geforce/technologies/reflex/' }
        [pscustomobject]@{ Title = 'Measure, do not guess'; Text = 'Capture frametimes (PresentMon or CapFrameX), DPC latency (LatencyMon) and ping/jitter before and after changes. See docs\TESTING.md.'; Source = 'https://github.com/GameTechDev/PresentMon' }
    )
}

function Get-IgwtHealthReport {
    <#
    .SYNOPSIS
        Runs every read-only health check. Never changes anything.
    #>
    [CmdletBinding()]
    param()
    $checks = New-Object System.Collections.Generic.List[object]
    $sections = @(
        @{ Name = 'Hardware'; Block = { Get-IgwtHardwareChecks } }
        @{ Name = 'Firmware'; Block = { Get-IgwtFirmwareChecks } }
        @{ Name = 'SecureBoot'; Block = { Get-IgwtSecureBootChecks } }
        @{ Name = 'Vbs'; Block = { Get-IgwtVbsChecks } }
        @{ Name = 'Gpu'; Block = { Get-IgwtGpuChecks } }
        @{ Name = 'Network'; Block = { Get-IgwtNetworkChecks } }
        @{ Name = 'Storage'; Block = { Get-IgwtStorageChecks } }
        @{ Name = 'Security'; Block = { Get-IgwtSecurityPostureChecks } }
    )
    foreach ($s in $sections) {
        try { foreach ($c in @(& $s.Block)) { if ($c) { $checks.Add($c) } } }
        catch { $checks.Add([pscustomobject]@{ Section = $s.Name; Id = "error-$($s.Name)"; Name = "$($s.Name) checks"; Status = 'Unknown'; Value = 'Error'; Detail = $_.Exception.Message; Advice = ''; Source = '' }) }
    }
    $ac = Get-IgwtAntiCheatReadiness
    $games = @()
    try { $games = @(Get-IgwtInstalledGames) } catch { $games = @() }
    $hardware = $null
    try {
        $hp = Get-IgwtHardwareProfile
        $hardware = [pscustomobject]@{
            Tags     = @($hp.TagDetails)
            Overlays = @(Get-IgwtActiveOverlays -Tags @($hp.Tags) | ForEach-Object { [pscustomobject]@{ Id = [string]$_.id; Name = [string]$_.name; Tags = @($_.MatchedTags); Hint = [string]$_.hint; Guidance = @($_.guidance | Where-Object { $_ }); Sources = @($_.sources) } })
        }
    } catch { Write-Verbose "Hardware profile unavailable: $($_.Exception.Message)" }
    $security = $null
    try { $security = Get-IgwtSecurityScore } catch { Write-Verbose "Security score unavailable: $($_.Exception.Message)" }
    [pscustomobject]@{
        Generated       = (Get-Date).ToString('o')
        Tool            = "iG Windows Tuner $script:IgwtVersion"
        Computer        = $env:COMPUTERNAME
        Elevated        = (Test-IgwtIsAdmin)
        Summary         = (Get-IgwtHardwareSummary)
        Hardware        = $hardware
        Checks          = $checks.ToArray()
        AntiCheat       = $ac
        Security        = $security
        Games           = $games
        NvidiaGuidance  = @(Get-IgwtNvidiaGuidance)
        Recommendations = @(Get-IgwtRecommendations)
    }
}

function Format-IgwtHealthReport {
    <# .SYNOPSIS Plain-text rendering of the health report for the console. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Report)
    $sb = New-Object System.Text.StringBuilder
    $line = '-' * 78
    $null = $sb.AppendLine("iG Windows Tuner health report  ($($Report.Tool), $($Report.Generated))")
    $null = $sb.AppendLine($Report.Summary.Text)
    if (-not $Report.Elevated) { $null = $sb.AppendLine('Note: not elevated - TPM readiness, Secure Boot databases, disk counters and BitLocker details are limited.') }
    $null = $sb.AppendLine($line)
    if ($Report.Hardware) {
        $null = $sb.AppendLine('[Hardware profile]')
        $null = $sb.AppendLine('  Tags: ' + (@($Report.Hardware.Tags | ForEach-Object { $_.Id }) -join ', '))
        foreach ($t in $Report.Hardware.Tags) { $null = $sb.AppendLine(('    {0,-26} {1}' -f $t.Id, $t.Name)) }
        if (@($Report.Hardware.Overlays).Count) { $null = $sb.AppendLine('  Hardware overlays (adjust presets on this PC):') }
        foreach ($o in $Report.Hardware.Overlays) {
            $null = $sb.AppendLine("    - $($o.Name): $($o.Hint)")
            foreach ($g in $o.Guidance) { $null = $sb.AppendLine("        -> $g") }
        }
        $null = $sb.AppendLine($line)
    }
    foreach ($group in ($Report.Checks | Group-Object Section)) {
        $null = $sb.AppendLine("[$($group.Name)]")
        foreach ($c in $group.Group) {
            $null = $sb.AppendLine(('  {0,-8} {1}: {2}' -f "[$($c.Status.ToUpperInvariant())]", $c.Name, $c.Value))
            if ($c.Detail) { $null = $sb.AppendLine("           $($c.Detail)") }
            if ($c.Advice) { $null = $sb.AppendLine("           -> $($c.Advice)") }
        }
    }
    $null = $sb.AppendLine($line)
    $null = $sb.AppendLine("Anti-cheat readiness: $($Report.AntiCheat.Overall.ToUpperInvariant())")
    foreach ($k in $Report.AntiCheat.Requirements.PSObject.Properties) {
        $r = $k.Value
        $st = $(if ($r.Unknown) { 'UNKNOWN' } elseif ($r.Pass) { 'PASS' } else { 'FAIL' })
        $null = $sb.AppendLine(('  {0,-9} {1}{2}' -f "[$st]", $r.Name, $(if ($r.Detail) { " ($($r.Detail))" } else { '' })))
    }
    foreach ($m in $Report.AntiCheat.Matrix) {
        $extra = ''
        if ($m.Missing.Count) { $extra = " - missing: $($m.Missing -join ', ')" } elseif ($m.Unknown.Count) { $extra = " - unverified: $($m.Unknown -join ', ')" }
        $null = $sb.AppendLine(('  {0,-9} {1}{2}' -f "[$($m.Status.ToUpperInvariant())]", $m.Name, $extra))
    }
    $null = $sb.AppendLine($line)
    if ($Report.Security) {
        $null = $sb.AppendLine("Security score: $($Report.Security.Score)/100 ($($Report.Security.Grade))")
        if (@($Report.Security.ToFix).Count -eq 0) { $null = $sb.AppendLine('  Nothing to fix.') }
        foreach ($c in @($Report.Security.ToFix)) {
            $route = switch ($c.Fix) { 'Tweak' { "catalog item $($c.Target)" } 'AsrCenter' { 'ASR Center (-Asr)' } default { $c.Target } }
            $null = $sb.AppendLine(('  {0,-9} {1}: {2} -> {3}' -f "[$($c.Status.ToUpperInvariant())]", $c.Name, $c.Value, $route))
        }
        $null = $sb.AppendLine($line)
    }
    $null = $sb.AppendLine('Detected games: ' + $(if ($Report.Games.Count) { (@($Report.Games | ForEach-Object { "$($_.Name) [$($_.AntiCheat)]" }) -join ', ') } else { 'none' }))
    $null = $sb.AppendLine('NVIDIA checklist (read-only):')
    foreach ($n in $Report.NvidiaGuidance) { $null = $sb.AppendLine("  - $($n.Item): $($n.Advice)") }
    $null = $sb.AppendLine('Outside Windows:')
    foreach ($r in $Report.Recommendations) { $null = $sb.AppendLine("  - $($r.Title): $($r.Text)") }
    return $sb.ToString()
}

function ConvertTo-IgwtHtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Export-IgwtHealthReport {
    <#
    .SYNOPSIS
        Writes the health report as a self-contained HTML file (inline CSS, no scripts) or JSON.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Report, [Parameter(Mandatory = $true)][string]$Path, [ValidateSet('Html', 'Json')][string]$Format = 'Html')
    if (-not $PSCmdlet.ShouldProcess($Path, "Write $Format report")) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    if ($Format -eq 'Json') {
        [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Report -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
        return $Path
    }
    $e = { param($t) ConvertTo-IgwtHtmlText $t }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append(@'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>iG Windows Tuner health report</title>
<style>
:root{--bg:#f7f7f8;--fg:#1b1b1f;--card:#fff;--muted:#5d5d66;--line:#e2e2e6;--pass:#107c10;--warn:#9d5d00;--fail:#c42b1c;--info:#005fb8}
@media (prefers-color-scheme:dark){:root{--bg:#1c1c1c;--fg:#f3f3f3;--card:#2b2b2b;--muted:#b0b0b8;--line:#3a3a3a;--pass:#6ccb5f;--warn:#fce100;--fail:#ff99a4;--info:#60cdff}}
body{font-family:"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}
main{max-width:1100px;margin:0 auto}h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.1rem;margin:1.4rem 0 .5rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:8px 0}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.s{font-weight:600;white-space:nowrap}.Pass{color:var(--pass)}.Warn,.Amber,.Unknown{color:var(--warn)}.Fail,.Red{color:var(--fail)}.Info{color:var(--info)}.Green{color:var(--pass)}
.muted{color:var(--muted);font-size:.9em}.adv{font-size:.92em}
</style></head><body><main>
'@)
    $null = $sb.Append("<h1>iG Windows Tuner health report</h1><p class='muted'>$(& $e $Report.Tool) &middot; $(& $e $Report.Generated) &middot; $(& $e $Report.Computer)$(if (-not $Report.Elevated) { ' &middot; not elevated (some checks limited)' })</p>")
    $null = $sb.Append("<div class='card'>$(& $e $Report.Summary.Text)</div>")
    if ($Report.Hardware) {
        $null = $sb.Append("<h2>Hardware profile</h2><div class='card'><table><tr><th>Tag</th><th>Meaning</th></tr>")
        foreach ($t in $Report.Hardware.Tags) { $null = $sb.Append("<tr><td class='s Info'>$(& $e $t.Id)</td><td><b>$(& $e $t.Name)</b><div class='muted'>$(& $e $t.Hint)</div></td></tr>") }
        $null = $sb.Append('</table></div>')
        if (@($Report.Hardware.Overlays).Count) {
            $null = $sb.Append("<div class='card'><table><tr><th>Hardware overlay</th><th>Effect</th></tr>")
            foreach ($o in $Report.Hardware.Overlays) {
                $g = (@($o.Guidance | ForEach-Object { "<div class='adv'>&rarr; $(& $e $_)</div>" }) -join '')
                $src = (@($o.Sources | ForEach-Object { " <a href='$(& $e $_)'>source</a>" }) -join '')
                $null = $sb.Append("<tr><td><b>$(& $e $o.Name)</b><div class='muted'>$(& $e (@($o.Tags) -join ', '))</div></td><td>$(& $e $o.Hint)$src$g</td></tr>")
            }
            $null = $sb.Append('</table></div>')
        }
    }
    $null = $sb.Append("<h2>Anti-cheat readiness: <span class='$($Report.AntiCheat.Overall)'>$($Report.AntiCheat.Overall)</span></h2><div class='card'><table><tr><th>Requirement</th><th>Result</th><th>Detail</th></tr>")
    foreach ($k in $Report.AntiCheat.Requirements.PSObject.Properties) {
        $r = $k.Value
        $st = $(if ($r.Unknown) { 'Unknown' } elseif ($r.Pass) { 'Pass' } else { 'Fail' })
        $null = $sb.Append("<tr><td>$(& $e $r.Name)</td><td class='s $st'>$st</td><td class='muted'>$(& $e $r.Detail)</td></tr>")
    }
    $null = $sb.Append('</table></div><div class="card"><table><tr><th>Anti-cheat</th><th>Result</th><th>Notes</th></tr>')
    foreach ($m in $Report.AntiCheat.Matrix) {
        $note = $m.Note
        if ($m.Missing.Count) { $note = "Missing: $($m.Missing -join ', '). $note" }
        $null = $sb.Append("<tr><td>$(& $e $m.Name)</td><td class='s $($m.Status)'>$($m.Status)</td><td class='muted'>$(& $e $note)</td></tr>")
    }
    $null = $sb.Append('</table></div>')
    if ($Report.Security) {
        $sc = $Report.Security
        $cls = $(if ($sc.Score -ge 90) { 'Pass' } elseif ($sc.Score -ge 75) { 'Info' } elseif ($sc.Score -ge 50) { 'Warn' } else { 'Fail' })
        $null = $sb.Append("<h2>Security score: <span class='$cls'>$($sc.Score)/100 ($(& $e $sc.Grade))</span></h2><div class='card'><table><tr><th>Result</th><th>Check</th><th>Fix</th></tr>")
        foreach ($c in @($sc.Checks)) {
            $route = switch ($c.Fix) { 'Tweak' { "Catalog item $($c.Target)" } 'AsrCenter' { 'ASR Center' } 'None' { '' } default { $c.Target } }
            $null = $sb.Append("<tr><td class='s $($c.Status)'>$(& $e $c.Status)</td><td><b>$(& $e $c.Name)</b>: $(& $e $c.Value)<div class='muted'>$(& $e $c.Hint)</div></td><td class='muted'>$(if ($c.Status -in 'Fail', 'Warn') { & $e $route })</td></tr>")
        }
        $null = $sb.Append('</table></div>')
    }
    foreach ($group in ($Report.Checks | Group-Object Section)) {
        $null = $sb.Append("<h2>$(& $e $group.Name)</h2><div class='card'><table>")
        foreach ($c in $group.Group) {
            $adv = ''
            if ($c.Advice) { $adv = "<div class='adv'>&rarr; $(& $e $c.Advice)</div>" }
            $src = ''
            if ($c.Source) { $src = " <a href='$(& $e $c.Source)'>source</a>" }
            $null = $sb.Append("<tr><td class='s $($c.Status)'>$($c.Status)</td><td><b>$(& $e $c.Name)</b>: $(& $e $c.Value)<div class='muted'>$(& $e $c.Detail)$src</div>$adv</td></tr>")
        }
        $null = $sb.Append('</table></div>')
    }
    $null = $sb.Append("<h2>NVIDIA checklist (read-only)</h2><div class='card'><ul>")
    foreach ($n in $Report.NvidiaGuidance) { $null = $sb.Append("<li><b>$(& $e $n.Item)</b>: $(& $e $n.Advice)</li>") }
    $null = $sb.Append("</ul></div><h2>Outside Windows</h2><div class='card'><ul>")
    foreach ($r in $Report.Recommendations) {
        $src = ''
        if ($r.Source) { $src = " <a href='$(& $e $r.Source)'>link</a>" }
        $null = $sb.Append("<li><b>$(& $e $r.Title)</b>: $(& $e $r.Text)$src</li>")
    }
    $null = $sb.Append('</ul></div></main></body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}
