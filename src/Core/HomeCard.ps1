# HomeCard.ps1
# Home card, "next best action" (3.6, DECISIONS T11 and T18): one card on the Dashboard, chosen by
# priority: 1 an unfinished change or a journal problem, 2 drift, 3 an expired forensic logging
# session, 4 Unverified items in the active preset, 5 a suggestion; otherwise All clear. Reading
# the inputs and choosing the card never write anything; "Not now" is remembered by the window.

function Get-IgwtHomeCardInput {
    <#
    .SYNOPSIS
        (worker) What the home card is chosen from, read-only: the journal check, unfinished
        sessions, the drift report, the forensic session, the active preset and its Unverified
        items. A read that fails leaves its part empty (the card never blocks the window).
    #>
    [CmdletBinding()]
    param($Context)
    $journal = $null; $incomplete = @(); $drift = $null; $forensic = $null; $preset = $null; $unverified = @()
    try { $journal = Read-IgwtJournal } catch { Write-Verbose "Journal not read: $($_.Exception.Message)" }
    if ($journal -and $journal.Status -eq 'Ok') {
        try { $incomplete = @(Get-IgwtIncompleteChangeSession -Journal $journal | Where-Object { @($_.Steps).Count }) } catch { $incomplete = @() }
        try { $drift = Get-IgwtDriftReport -Journal $journal -Context $Context } catch { Write-Verbose "Drift not checked: $($_.Exception.Message)" }
    }
    try { $forensic = Get-IgwtForensicSession } catch { $forensic = $null }
    try {
        $rec = Get-IgwtPresetRecord
        if ($rec -and $rec.preset) {
            $preset = [pscustomobject]@{ Id = [string]$rec.preset; Name = [string]$rec.name }
            $map = Get-IgwtConfidenceMap -Context (Get-IgwtConfidenceContext -Journal $journal)
            $unverified = @(@($rec.ids) | Where-Object { $map[[string]$_] -and $map[[string]$_].Level -eq 'Unverified' } | ForEach-Object { [string]$_ })
        }
    } catch { Write-Verbose "Active preset not read: $($_.Exception.Message)" }
    return [pscustomobject]@{ Journal = $(if ($journal) { [pscustomobject]@{ Status = [string]$journal.Status; Reason = [string]$journal.Reason; Count = $journal.Count } } else { $null })
        Incomplete = $incomplete; Drift = $drift; Forensic = $forensic; Preset = $preset; Unverified = $unverified }
}

function Select-IgwtHomeCard {
    <#
    .SYNOPSIS
        Chooses the one home card from the inputs, skipping cards snoozed until a later time
        (card key -> until, local time). Returns Key (stable per situation, for "Not now"),
        Priority, Kind, Title, Text, Action (what "Do it" opens) and Why (the details). Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$InputData, [hashtable]$Snoozed = @{}, [datetime]$Now = (Get-Date))
    $cards = New-Object System.Collections.Generic.List[object]
    $j = $InputData.Journal
    if ($j -and $j.Status -eq 'Broken') {
        $cards.Add([pscustomobject]@{ Key = 'journal:broken'; Priority = 1; Kind = 'journal'; Title = 'The change journal needs attention'
                Text = 'Its integrity check failed, so iG makes no change until this is resolved.'; Action = 'openJournal'
                Why = "The journal records every change iG makes and protects itself with a hash chain. $($j.Reason) Changes are blocked so nothing is restored from a journal that may have been edited." })
    }
    foreach ($s in @($InputData.Incomplete)) {
        $cards.Add([pscustomobject]@{ Key = "incomplete:$($s.Id)"; Priority = 1; Kind = 'incomplete'; Title = 'A change did not finish'
                Text = "'$($s.Title)' stopped part-way ($(@($s.Steps).Count) step(s) may have changed something). Roll it back?"; Action = 'recover'; SessionId = [string]$s.Id
                Why = "The app or the PC stopped while this change was running. Do it shows the steps and restores each one to the value recorded before it, as a new journaled change. Nothing happens until you confirm." })
    }
    $d = $InputData.Drift
    if ($d -and $d.Status -eq 'Ok') {
        $bad = @($d.Rows | Where-Object { $_.Status -in 'Drifted', 'Missing' })
        if ($bad.Count) {
            $ids = @($bad | ForEach-Object { [string]$_.Item } | Select-Object -Unique)
            $names = @($bad | ForEach-Object { if ($_.PSObject.Properties['Name'] -and $_.Name) { [string]$_.Name } else { [string]$_.Item } } | Select-Object -Unique)
            $cards.Add([pscustomobject]@{ Key = "drift:$((Get-IgwtJournalHash -Line ((@($bad | ForEach-Object { [string]$_.Key } | Sort-Object)) -join '|')).Substring(0, 16))"; Priority = 2; Kind = 'drift'
                    Title = "$($ids.Count) setting(s) changed since iG set them"; Text = "$(($names | Select-Object -First 3) -join '; ')$(if ($names.Count -gt 3) { '; and more' }). Re-apply them or accept the current values?"; Action = 'drift'
                    Why = "$($d.Summary) Something else changed these values after iG set them: you, an app, a policy or Windows. $(if (@($d.Updates).Count) { "Windows updates installed in between: $((@($d.Updates) | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; '). They may or may not be related." } else { '' })".Trim() })
        }
    }
    $f = $InputData.Forensic
    if ($f -and $f.PSObject.Properties['Expired'] -and $f.Expired) {
        $cards.Add([pscustomobject]@{ Key = 'forensic:expired'; Priority = 3; Kind = 'forensic'; Title = 'Forensic logging has ended'
                Text = 'Its time is up; restore the firewall, audit and event log settings it changed.'; Action = 'forensic'
                Why = 'A forensic logging session records connections for a limited time and then restores every setting exactly. This one ended while the app was closed, so the settings are still the logging ones.' })
    }
    if ($InputData.Preset -and @($InputData.Unverified).Count) {
        $u = @($InputData.Unverified)
        $cards.Add([pscustomobject]@{ Key = "unverified:$($InputData.Preset.Id):$((Get-IgwtJournalHash -Line ($u -join '|')).Substring(0, 16))"; Priority = 4; Kind = 'unverified'; Title = "$($u.Count) Unverified item(s) in $($InputData.Preset.Name)"
                Text = "$($u -join ', '): no Microsoft or hardware-vendor documentation backs them."; Action = 'unverified'; Items = $u
                Why = 'Unverified means the item has no Microsoft or hardware-vendor documentation as a source. It still applies and reverts like any item; you may prefer to leave it out (customize the preset) until it is documented.' })
    }
    if (-not $InputData.Preset -and ($null -eq $j -or $j.Status -eq 'Empty')) {
        $cards.Add([pscustomobject]@{ Key = 'suggest:preset'; Priority = 5; Kind = 'suggestion'; Title = 'Start with a preset'
                Text = 'A preset previews what it would change on this PC; nothing changes until you apply it.'; Action = 'presets'
                Why = 'Presets group documented items for a goal (competitive gaming, balanced, privacy, security). The preview shows what is already set and what would change; every change is journaled and can be reverted.' })
    }
    # Sort-Object is not stable in Windows PowerShell 5.1: equal priorities keep the order they were added in.
    $n = 0; foreach ($x in $cards) { $x | Add-Member -NotePropertyName Order -NotePropertyValue ($n++) -Force }
    $card = @($cards | Where-Object { -not ($Snoozed.ContainsKey($_.Key) -and [datetime]$Snoozed[$_.Key] -gt $Now) } | Sort-Object Priority, Order) | Select-Object -First 1
    if ($card) { return $card }
    return [pscustomobject]@{ Key = 'clear'; Priority = 6; Kind = 'clear'; Title = 'All clear'; Text = 'Every change iG made is still in place, and nothing needs your attention.'; Action = ''
        Why = 'The home card checks, read-only, for an unfinished change, the journal''s integrity, settings that changed since iG set them, an ended forensic logging session and Unverified items in your preset.' }
}
