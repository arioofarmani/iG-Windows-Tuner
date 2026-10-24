# FirewallReport.ps1
# Firewall audit report (HTML, CSV, JSON) for sysadmins. Writes only the path the user picks.

function Export-IgwtFirewallAuditReport {
    <#
    .SYNOPSIS
        Writes a firewall audit report for sysadmins: HTML (self-contained, no scripts or external
        files), CSV (one line per rule) or JSON (everything), chosen by the file extension. Contains
        the categories, findings, conflicts, exposure and recommendations. Writes only -Path.
    .PARAMETER Audit
        A Get-IgwtFirewallAudit result (read one when omitted).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Audit, [Parameter(Mandatory = $true)][string]$Path)
    if (-not $Audit) { $Audit = Get-IgwtFirewallAudit }
    $ext = ([System.IO.Path]::GetExtension($Path)).ToLowerInvariant()
    if ($ext -notin '.html', '.htm', '.csv', '.json') { throw 'The report path must end in .html, .csv or .json.' }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write firewall audit report')) { return }
    $rows = @($Audit.Rules)
    $line = {
        param($r)
        $open = @($r.Findings | Where-Object { $_ -and -not $_.Ignored })
        [ordered]@{
            RuleId = [string]$r.Name; Name = [string]$r.DisplayName; Enabled = [bool]$r.Enabled; Direction = [string]$r.Direction; Action = [string]$r.Action
            Category = [string]$r.OriginName; Confidence = [string]$r.Confidence; Reason = [string]$r.OriginReason; Groups = (@($r.Groups) -join ', ')
            Profiles = [string]$r.Profiles; Program = [string]$r.Program; Service = [string]$r.Service; Protocol = [string]$r.Protocol; LocalPort = [string]$r.LocalPort; RemoteAddress = [string]$r.RemoteAddress
            Locked = [bool]$r.Locked; RiskLevel = [string]$r.RiskLevel; Findings = (@($open | ForEach-Object { "$($_.Severity): $($_.Title) -> $($_.Recommended)" }) -join '; ')
            Bloated = [string]$r.BloatReason; Conflicts = [string]$r.PrecedenceText; ExposedNow = [bool]$r.Exposed
        }
    }
    switch ($ext) {
        '.csv' {
            # Cells that a spreadsheet would run as a formula (rule names come from other programs) start with a quote.
            $safe = { param($h) $o = [ordered]@{}; foreach ($k in @($h.Keys)) { $v = [string]$h[$k]; $o[$k] = $(if ($v -match '^[=+\-@\t\r]') { "'$v" } else { $v }) }; [pscustomobject]$o }
            @($rows | ForEach-Object { & $safe (& $line $_) }) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        }
        '.json' {
            $out = [ordered]@{
                schemaVersion = 1; kind = 'igwtFirewallAudit'; generated = (Get-Date).ToString('o'); tool = "iG Windows Tuner $script:IgwtVersion"; role = [string]$Audit.Role; partial = [bool]$Audit.Partial
                summary = $Audit.Summary; rules = @($rows | ForEach-Object { & $line $_ }); exposure = @($Audit.Exposure); relations = @($Audit.Relations)
            }
            [System.IO.File]::WriteAllText($Path, ($out | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        }
        default { [System.IO.File]::WriteAllText($Path, (ConvertTo-IgwtFirewallReportHtml -Audit $Audit), (New-Object System.Text.UTF8Encoding($false))) }
    }
    return $Path
}

function ConvertTo-IgwtFirewallReportHtml {
    <# .SYNOPSIS The HTML audit report (self-contained; every value HTML-encoded). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Audit)
    $e = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $s = $Audit.Summary
    $rows = @($Audit.Rules)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Firewall audit</title><style>')
    $null = $sb.Append('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24;max-width:1200px}h1{font-size:22px}h2{font-size:17px;margin-top:28px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #d0d7de;padding:5px 7px;text-align:left;vertical-align:top}th{background:#f3f5f7}.Critical,.High{color:#b42318;font-weight:600}.Medium{color:#9a6700;font-weight:600}.Low{color:#0b6bcb}.muted{color:#57606a}.grid{display:flex;flex-wrap:wrap;gap:10px}.tile{border:1px solid #d0d7de;border-radius:6px;padding:8px 12px;min-width:150px}.tile b{font-size:18px;display:block}')
    $null = $sb.Append('</style></head><body>')
    $null = $sb.Append("<h1>Firewall audit</h1><p class=""muted"">$(& $e "iG Windows Tuner $script:IgwtVersion, $((Get-Date).ToString('yyyy-MM-dd HH:mm')), role: $($Audit.Role)")$(if ($Audit.Partial) { ' - not elevated: ports and addresses were not readable, so port-based findings and exposure are incomplete.' })</p>")
    $null = $sb.Append("<h2>Summary</h2><div class=""grid"">")
    foreach ($p in @(@('Rules', $s.Total), @('Enabled', $s.Enabled), @('Need attention', $s.NeedsAttention), @('Quick wins', @($s.QuickWins).Count), @('Exposed now', $s.Exposed), @('Locked', $s.Locked))) { $null = $sb.Append("<div class=""tile""><b>$(& $e $p[1])</b>$(& $e $p[0])</div>") }
    $null = $sb.Append('</div><h2>Groups</h2><div class="grid">')
    foreach ($c in @((Get-IgwtFirewallKnowledgeBase).Categories | Sort-Object order)) { $null = $sb.Append("<div class=""tile""><b>$(& $e $s.Groups.([string]$c.id))</b>$(& $e $c.name)</div>") }
    $null = $sb.Append('</div>')
    $findings = @($rows | ForEach-Object { $r = $_; @($r.Findings | Where-Object { $_ -and -not $_.Ignored } | ForEach-Object { [pscustomobject]@{ Rule = $r; F = $_ } }) })
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $null = $sb.Append("<h2>Findings ($($findings.Count))</h2><table><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Finding</th><th>Recommended</th><th>Why</th></tr>")
    foreach ($x in @($findings | Sort-Object @{ Expression = { $rank[[string]$_.F.Severity] } }, @{ Expression = { [string]$_.Rule.DisplayName } })) {
        $null = $sb.Append("<tr><td class=""$(& $e $x.F.Severity)"">$(& $e $x.F.Severity)$(if ($x.F.ExposedNow) { ' (exposed now)' })</td><td>$(& $e $x.Rule.DisplayName)<br><span class=""muted"">$(& $e (Format-IgwtFirewallRuleSummary -Row $x.Rule))</span></td><td>$(& $e $x.Rule.OriginName)</td><td>$(& $e $x.F.Title)</td><td>$(& $e $x.F.Recommended)</td><td>$(& $e $x.F.Explanation)</td></tr>")
    }
    $null = $sb.Append('</table>')
    $quick = @($rows | Where-Object { @($s.QuickWins) -contains [string]$_.Name })
    $null = $sb.Append("<h2>Quick wins ($($quick.Count))</h2><table><tr><th>Rule</th><th>Why it can go</th><th>What stops working</th></tr>")
    foreach ($r in $quick) { $null = $sb.Append("<tr><td>$(& $e $r.DisplayName)</td><td>$(& $e $r.BloatReason)</td><td>$(& $e $r.WhatStopsWorking)</td></tr>") }
    $null = $sb.Append("</table><h2>Open ports</h2><table><tr><th>Port</th><th>Program</th><th>Status</th><th>Rules that allow it</th><th>Networks</th></tr>")
    foreach ($x in @($Audit.Exposure)) { $null = $sb.Append("<tr><td>$(& $e "$($x.Protocol) $($x.LocalPort)")</td><td>$(& $e $x.Process)</td><td>$(& $e $x.Status)</td><td>$(& $e $x.Rules)</td><td>$(& $e $x.Profiles)</td></tr>") }
    $conf = @($rows | Where-Object { $_.Shadowed -or $_.Redundant -or @($_.Conflicts).Count })
    $null = $sb.Append("</table><h2>Conflicts ($($conf.Count))</h2><table><tr><th>Rule</th><th>Result</th></tr>")
    foreach ($r in $conf) { $null = $sb.Append("<tr><td>$(& $e $r.DisplayName)</td><td>$(& $e $r.PrecedenceText)</td></tr>") }
    $null = $sb.Append('</table><p class="muted">Read-only report: nothing was changed. Categories, risk rules and sources: docs\FIREWALL_CATEGORIES.md.</p></body></html>')
    return $sb.ToString()
}
