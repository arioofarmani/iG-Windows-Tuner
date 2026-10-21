# SystemReport.ps1
# Full system report: the health report plus diagnostics, Windows Update status, services and
# persistence summaries, the driver inventory and iG Windows Tuner item states, exported as one
# self-contained HTML file (inline CSS, no scripts) or JSON. Read-only.

function Get-IgwtSystemReport {
    <#
    .SYNOPSIS
        Collects the full read-only system report. Each section that fails is recorded with its
        error instead of stopping the report.
    .PARAMETER Quick
        Skips the slow sections (persistence signatures, DPC sampling).
    #>
    [CmdletBinding()]
    param([switch]$Quick, [int]$Days = 30)
    $section = { param($name, $block) try { & $block } catch { [pscustomobject]@{ Error = "${name}: $($_.Exception.Message)" } } }
    $health = & $section 'Health' { Get-IgwtHealthReport }
    $areas = @('Reliability', 'Crashes', 'Boot', 'Drivers'); if (-not $Quick) { $areas = @('DpcIsr') + $areas }
    $diag = & $section 'Diagnostics' { Get-IgwtDiagnostics -Area $areas -Days $Days -Samples 3 }
    $updates = & $section 'Updates' { Get-IgwtUpdateStatus -Count 20 }
    $services = & $section 'Services' { $s = Get-IgwtServiceInventory; [pscustomobject]@{ Counts = $s.Counts; ThirdPartyRunning = @($s.Services | Where-Object { $_.Rating -eq 'ThirdParty' -and $_.State -eq 'Running' } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; StartupType = $_.StartupType } }) } }
    $persistence = $null
    if (-not $Quick) { $persistence = & $section 'Persistence' { $p = Get-IgwtPersistenceInventory; [pscustomobject]@{ Counts = $p.Counts; Flagged = @($p.Entries | Where-Object { $_.Severity -ne 'Info' } | Select-Object Category, Name, Command, Signature, Severity, Note) } } }
    $items = & $section 'Items' { @(Get-IgwtAllTweakStates | Where-Object { $_.State -in 'On', 'Partial', 'ManagedByPolicy' } | ForEach-Object { [pscustomobject]@{ Id = [string]$_.Id; State = [string]$_.State } }) }
    [pscustomobject]@{
        Generated   = (Get-Date).ToString('o')
        Tool        = "iG Windows Tuner $script:IgwtVersion"
        Computer    = $env:COMPUTERNAME
        Health      = $health
        Diagnostics = $diag
        Updates     = $updates
        Services    = $services
        Persistence = $persistence
        ActiveItems = $items
        Note        = 'Read-only report. It contains the computer name and installed software; review it before sharing.'
    }
}

function ConvertTo-IgwtHtmlTable {
    <# .SYNOPSIS HTML table (encoded) of the given rows and properties. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object[]]$Rows, [Parameter(Mandatory = $true)][string[]]$Property, [int]$Max = 200)
    $list = @($Rows | Where-Object { $null -ne $_ } | Select-Object -First $Max)
    if ($list.Count -eq 0) { return "<p class='muted'>None.</p>" }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<table><tr>')
    foreach ($p in $Property) { $null = $sb.Append("<th>$(ConvertTo-IgwtHtmlText $p)</th>") }
    $null = $sb.Append('</tr>')
    foreach ($r in $list) {
        $null = $sb.Append('<tr>')
        foreach ($p in $Property) { $v = $(if ($r.PSObject.Properties[$p]) { $r.$p } else { '' }); $null = $sb.Append("<td>$(ConvertTo-IgwtHtmlText (@($v) -join ', '))</td>") }
        $null = $sb.Append('</tr>')
    }
    $null = $sb.Append('</table>')
    return $sb.ToString()
}

function Export-IgwtSystemReport {
    <# .SYNOPSIS Writes the full system report as self-contained HTML (no scripts) or JSON. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Report, [Parameter(Mandatory = $true)][string]$Path, [ValidateSet('Html', 'Json')][string]$Format = 'Html')
    if (-not $PSCmdlet.ShouldProcess($Path, "Write $Format system report")) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    if ($Format -eq 'Json') { [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Report -Depth 8), $utf8); return $Path }
    $e = { param($t) ConvertTo-IgwtHtmlText $t }
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>iG Windows Tuner system report</title><style>')
    $null = $sb.Append(':root{--bg:#f7f7f8;--fg:#1b1b1f;--card:#fff;--muted:#5d5d66;--line:#e2e2e6;--warn:#9d5d00;--fail:#c42b1c}@media (prefers-color-scheme:dark){:root{--bg:#1c1c1c;--fg:#f3f3f3;--card:#2b2b2b;--muted:#b0b0b8;--line:#3a3a3a;--warn:#fce100;--fail:#ff99a4}}')
    $null = $sb.Append('body{font-family:"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}main{max-width:1100px;margin:0 auto}h2{font-size:1.1rem;margin:1.4rem 0 .5rem}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:8px 0;overflow-x:auto}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:5px 7px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}.muted{color:var(--muted)}.adv{color:var(--warn)}.err{color:var(--fail)}')
    $null = $sb.Append('</style></head><body><main>')
    $null = $sb.Append("<h1>iG Windows Tuner system report</h1><p class='muted'>$(& $e $Report.Tool) &middot; $(& $e $Report.Generated) &middot; $(& $e $Report.Computer)</p><p class='muted'>$(& $e $Report.Note)</p>")
    $card = { param($title, $body) $null = $sb.Append("<h2>$(& $e $title)</h2><div class='card'>$body</div>") }
    $advice = { param($list) (@($list | Where-Object { $_ } | ForEach-Object { "<p class='adv'>&rarr; $(& $e $_)</p>" }) -join '') }
    $err = { param($o) if (& $has $o 'Error' -and $o.Error) { "<p class='err'>$(& $e $o.Error)</p>" } else { '' } }
    $h = $Report.Health
    if (& $has $h 'Summary') {
        & $card 'System' "<p>$(& $e $h.Summary.Text)</p>$(ConvertTo-IgwtHtmlTable -Rows $h.Checks -Property Section, Name, Status, Value, Advice)"
        if ($h.Security) { & $card "Security score $($h.Security.Score)/100 ($($h.Security.Grade))" (ConvertTo-IgwtHtmlTable -Rows $h.Security.Checks -Property Name, Status, Value) }
    } else { & $card 'System' (& $err $h) }
    $d = $Report.Diagnostics
    if (& $has $d 'DpcIsr') {
        $x = $d.DpcIsr
        if (& $has $x 'Dpc') { & $card 'DPC and ISR' ("<p>DPC average $($x.Dpc.Average) % (max $($x.Dpc.Max) %), ISR average $($x.Isr.Average) % (max $($x.Isr.Max) %).</p>" + (& $advice $x.Advice) + (ConvertTo-IgwtHtmlTable -Rows $x.TopProcesses -Property Name, CpuPercent, WorkingSetMB)) }
        else { & $card 'DPC and ISR' (& $err $x) }
    }
    if (& $has $d 'Reliability') { $x = $d.Reliability; & $card "Reliability (index $(if (& $has $x 'Current') { $x.Current } else { 'n/a' }))" ((& $err $x) + $(if (& $has $x 'Records') { ConvertTo-IgwtHtmlTable -Rows $x.Records -Property Time, Source, Product, Message -Max 50 } else { '' })) }
    if (& $has $d 'Crashes') { $x = $d.Crashes; & $card 'Crashes' ((& $err $x) + $(if (& $has $x 'Events') { (& $advice $x.Advice) + (ConvertTo-IgwtHtmlTable -Rows $x.Events -Property Time, Kind, Detail -Max 60) + '<h3>Minidumps</h3>' + (ConvertTo-IgwtHtmlTable -Rows $x.Minidumps -Property Name, Time, SizeKB) } else { '' })) }
    if (& $has $d 'Boot') { $x = $d.Boot; & $card 'Boot performance' ((& $err $x) + $(if (& $has $x 'Boots') { ConvertTo-IgwtHtmlTable -Rows $x.Boots -Property Time, BootMs, MainPathMs, PostBootMs } else { '' })) }
    if (& $has $d 'Drivers') { $x = $d.Drivers; & $card 'Drivers (non-Microsoft)' ((& $err $x) + $(if (& $has $x 'Drivers') { ConvertTo-IgwtHtmlTable -Rows $x.Drivers -Property Device, Class, Version, Date, Provider, Signer, Flag -Max 400 } else { '' })) }
    $u = $Report.Updates
    if (& $has $u 'Services') { & $card 'Windows Update' ((& $err $u) + (& $advice $u.Advice) + (ConvertTo-IgwtHtmlTable -Rows $u.Services -Property Name, Status, StartType) + (ConvertTo-IgwtHtmlTable -Rows $u.Policies -Property Name, Value) + (ConvertTo-IgwtHtmlTable -Rows $u.History -Property Date, Title, Result, HResult -Max 20)) }
    else { & $card 'Windows Update' (& $err $u) }
    $s = $Report.Services
    if (& $has $s 'Counts') { & $card "Services ($($s.Counts.Total), $($s.Counts.Running) running)" ("<p>Running third-party services:</p>" + (ConvertTo-IgwtHtmlTable -Rows $s.ThirdPartyRunning -Property Name, DisplayName, StartupType)) }
    $p = $Report.Persistence
    if (& $has $p 'Counts') { & $card "Persistence ($($p.Counts.Warn) warnings, $($p.Counts.Review) to review)" (ConvertTo-IgwtHtmlTable -Rows $p.Flagged -Property Severity, Category, Name, Command, Signature, Note -Max 300) }
    elseif ($p) { & $card 'Persistence' (& $err $p) }
    & $card 'iG Windows Tuner items in effect' (ConvertTo-IgwtHtmlTable -Rows @($Report.ActiveItems) -Property Id, State -Max 500)
    $null = $sb.Append('</main></body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $utf8)
    return $Path
}
