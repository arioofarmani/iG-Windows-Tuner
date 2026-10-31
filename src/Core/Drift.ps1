# Drift.ps1
# Update drift guardian (3.6, DECISIONS T10 and T17): compares every value iG set, as the change
# journal records it, with the value now. Strictly read-only: it calls only the providers' Get (a
# test fails if any Set or Restore is called) and reads the System event log. Windows updates
# installed in between are reported as "installed in between", never as the cause.
#   Still applied  the value now is the value iG set.
#   Drifted        the value is there but different.
#   Missing        the value iG set is gone (a registry value or key that iG created no longer exists).
#   Can't read     the value could not be read (most often: needs administrator rights).

function Get-IgwtUpdateHistorySince {
    <#
    .SYNOPSIS
        Windows updates installed since a time: System log, provider Microsoft-Windows-WindowsUpdateClient,
        event 19 "Installation Successful" (documented on Microsoft Learn; the field names are read
        by Data Name, verified on this PC: updateTitle, updateGuid). Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][datetime]$Since)
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19; StartTime = $Since } -ErrorAction Stop) }
    catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-Verbose "Update history not read: $($_.Exception.Message)" }; return @() }
    foreach ($e in $events) {
        $title = ''
        try {
            [xml]$x = $e.ToXml()
            foreach ($d in @($x.Event.EventData.Data)) { if ([string]$d.Name -ieq 'updateTitle') { $title = [string]$d.'#text' } }
        } catch { $title = '' }
        [pscustomobject]@{ Time = $e.TimeCreated; Title = $(if ($title) { $title } else { 'A Windows update' }) }
    }
}

function Get-IgwtDriftReport {
    <#
    .SYNOPSIS
        Every value iG set that is still tracked (the last journal state of its target is a change
        by iG), checked against the value now: Status StillApplied, Drifted, Missing or CantRead,
        the value iG set and the value now, the build when it was set and now, and the updates
        installed in between. Module steps (their values are in their own snapshots) are not
        compared. Strictly read-only.
    #>
    [CmdletBinding()]
    param($Journal, [switch]$NoUpdateHistory, $Context)
    if (-not $Journal) { $Journal = Read-IgwtJournal -NoEntries }
    $bi = Get-IgwtWindowsBuildInfo
    $rows = New-Object System.Collections.Generic.List[object]
    if ($Journal.Status -ne 'Ok') {
        return [pscustomobject]@{ Status = [string]$Journal.Status; Reason = [string]$Journal.Reason; Build = $bi.Build; Ubr = $bi.Ubr; Rows = @(); Updates = @(); Summary = $(if ($Journal.Status -eq 'Empty') { 'Nothing to check: iG has not changed anything yet.' } else { "The journal cannot be checked: $($Journal.Reason)" }) }
    }
    # The context (hardware, user hive) is built once, and only when a target needs it.
    $ctx = $Context
    $catalog = $null
    $oldest = $null
    foreach ($key in @($Journal.Last.Keys)) {
        $e = $Journal.Last[$key]
        if ([string]$e['kind'] -ne 'committed' -or [string]$e['op'] -ne 'change') { continue }
        $target = $e['target']
        $def = $script:IgwtChangeProviders[[string]$target['provider']]
        if (-not $def -or $def.NoCompare) { continue }
        $row = [ordered]@{ Key = $key; Item = [string]$e['item']; Target = $target; Session = [string]$e['session']; EntryId = [string]$e['id']; WeSet = $e['after']; Now = $null
            Status = ''; Message = ''; SetUtc = [string]$e['tsUtc']; SetBuild = [string]$e['build']; SetUbr = [string]$e['ubr'] }
        try {
            if (-not $catalog) { $catalog = Get-IgwtCatalog }
            $r = Resolve-IgwtChangeTarget -Target $target -Catalog $catalog
            if (-not $ctx -and [string]$target['provider'] -eq 'action') { $ctx = New-IgwtContext }
            $now = & $def.Get $r $ctx
            $row.Now = $now
            $nowJ = ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $now)
            $setJ = ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $e['after'])
            if ($nowJ -eq $setJ) { $row.Status = 'StillApplied' }
            elseif ($setJ -match '"exists":true' -and $nowJ -match '"exists":false') { $row.Status = 'Missing'; $row.Message = 'The value iG set is gone.' }
            else { $row.Status = 'Drifted'; $row.Message = 'The value is different from the one iG set.' }
        } catch {
            $row.Status = 'CantRead'
            $row.Message = $(if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)access|denied|administrator|privilege') { 'Cannot be read without administrator rights.' } else { "Cannot be read: $($_.Exception.Message)" })
        }
        if ($row.Status -in 'Drifted', 'Missing') {
            $t = [datetime]::MinValue
            if ([datetime]::TryParse($row.SetUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$t)) { if (-not $oldest -or $t -lt $oldest) { $oldest = $t } }
            if ($row.SetBuild -and ($row.SetBuild -ne [string]$bi.Build -or $row.SetUbr -ne [string]$bi.Ubr)) { $row.Message += " Windows was updated in between (set on $($row.SetBuild).$($row.SetUbr), now $($bi.Build).$($bi.Ubr))." }
        }
        $rows.Add([pscustomobject]$row)
    }
    $updates = @()
    if ($oldest -and -not $NoUpdateHistory) { $updates = @(Get-IgwtUpdateHistorySince -Since $oldest.ToLocalTime()) }
    $n = { param($s) @($rows | Where-Object { $_.Status -eq $s }).Count }
    $summary = '{0} still applied, {1} drifted, {2} missing, {3} cannot be read.' -f (& $n 'StillApplied'), (& $n 'Drifted'), (& $n 'Missing'), (& $n 'CantRead')
    if ($updates.Count) { $summary += " $($updates.Count) Windows update(s) were installed in between (they may or may not be related)." }
    return [pscustomobject]@{ Status = 'Ok'; Reason = ''; Build = $bi.Build; Ubr = $bi.Ubr; Rows = $rows.ToArray(); Updates = $updates; Summary = $summary }
}

function Invoke-IgwtDriftAccept {
    <#
    .SYNOPSIS
        Accepts the value Windows (or something else) set for drifted targets: journaled as
        "retired" in a session with origin driftAccept, so iG stops tracking the value it set. The
        system is not changed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][object[]]$Rows)
    Assert-IgwtWritable -Operation 'Invoke-IgwtDriftAccept'
    $todo = @($Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' })
    if (-not $todo.Count) { return [pscustomobject]@{ Accepted = 0 } }
    if (-not $PSCmdlet.ShouldProcess("$($todo.Count) value(s)", "Accept the current value")) { return $null }
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'driftAccept'; ref = 'drift' }) -Title "Accepted the current value of $($todo.Count) item(s)" -Confirm:$false
    try {
        foreach ($r in $todo) { $null = Add-IgwtJournalEntry -Entry ([ordered]@{ kind = 'retired'; session = $session.Id; item = $r.Item; target = $r.Target; now = $r.Now; note = 'Accepted the current value after drift; iG no longer tracks the value it set.' }) }
    } finally { Complete-IgwtChangeSession -Session $session }
    return [pscustomobject]@{ Accepted = $todo.Count; Session = $session.Id }
}

function Get-IgwtDriftReapplyIds {
    <# .SYNOPSIS The catalog items to re-apply for drifted or missing rows (preview with Get-IgwtPlan, apply with Invoke-IgwtApply). Pure. #>
    [CmdletBinding()]
    param([object[]]$Rows)
    return @($Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' -and [string]$_.Target['provider'] -eq 'action' } | ForEach-Object { [string]$_.Item } | Select-Object -Unique)
}
