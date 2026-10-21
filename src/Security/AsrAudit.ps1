# AsrAudit.ps1
# ASR audit view (read-only): reads the Microsoft Defender Operational log for attack surface
# reduction, controlled folder access, network protection and configuration events, groups them by
# rule, program and path, and recommends the next step (promote a quiet Audit rule, exclude a
# trusted program, or ignore expected noise). Nothing here changes the system.
# Event IDs: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events

$script:IgwtDefenderOperationalLog = 'Microsoft-Windows-Windows Defender/Operational'
$script:IgwtProtectionEvents = @{
    1121 = @{ Feature = 'ASR'; Action = 'Blocked' }
    1122 = @{ Feature = 'ASR'; Action = 'Audited' }
    1129 = @{ Feature = 'ASR'; Action = 'WarnBypassed' }
    1123 = @{ Feature = 'ControlledFolderAccess'; Action = 'Blocked' }
    1124 = @{ Feature = 'ControlledFolderAccess'; Action = 'Audited' }
    1127 = @{ Feature = 'ControlledFolderAccess'; Action = 'Blocked' }
    1128 = @{ Feature = 'ControlledFolderAccess'; Action = 'Audited' }
    1125 = @{ Feature = 'NetworkProtection'; Action = 'Audited' }
    1126 = @{ Feature = 'NetworkProtection'; Action = 'Blocked' }
    5007 = @{ Feature = 'Configuration'; Action = 'Changed' }
}
# Event fields that are not shown in the Detail column (versions, and command lines that can hold secrets).
$script:IgwtProtectionHiddenFields = @('Product Name', 'Product Version', 'Unused', 'Unused2', 'Unused3', 'Unused4', 'Unused5', 'Unused6', 'Detection Time',
    'Security intelligence Version', 'Engine Version', 'Target Commandline', 'Parent Commandline', 'Inhertiance Flags', 'Inheritance Flags', 'ID', 'Path', 'Process Name', 'User', 'Old Value', 'New Value')
$script:IgwtAsrMinimumAuditDays = 7

function ConvertFrom-IgwtProtectionEvent {
    <# .SYNOPSIS One Defender event -> Time, EventId, Feature, Action, RuleId, Path, Process, User, Detail. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$WinEvent)
    $data = @{}
    try {
        $xml = [xml]$WinEvent.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $data[[string]$d.Name] = [string]$d.'#text' } }
    } catch { Write-Verbose "Event $($WinEvent.Id) could not be parsed." }
    $meta = $script:IgwtProtectionEvents[[int]$WinEvent.Id]
    if (-not $meta) { $meta = @{ Feature = 'Other'; Action = 'Other' } }
    $get = { param($n) if ($data.ContainsKey($n)) { [string]$data[$n] } else { '' } }
    $detail = @(foreach ($k in ($data.Keys | Sort-Object)) {
            if ($script:IgwtProtectionHiddenFields -notcontains $k -and [string]$data[$k]) { "${k}: $($data[$k])" }
        }) -join '; '
    if ($detail.Length -gt 240) { $detail = $detail.Substring(0, 237) + '...' }
    [pscustomobject]@{
        Time     = $WinEvent.TimeCreated
        EventId  = [int]$WinEvent.Id
        Feature  = [string]$meta.Feature
        Action   = [string]$meta.Action
        RuleId   = (& $get 'ID').ToLowerInvariant()
        Path     = (& $get 'Path')
        Process  = (& $get 'Process Name')
        User     = (& $get 'User')
        OldValue = (& $get 'Old Value')
        NewValue = (& $get 'New Value')
        Detail   = $detail
    }
}

function Get-IgwtProtectionEvents {
    <#
    .SYNOPSIS
        Reads ASR (1121/1122/1129), controlled folder access (1123/1124/1127/1128), network protection
        (1125/1126) and configuration (5007) events from the Defender Operational log. Read-only.
        Readable is false (with a reason) when the log cannot be read.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 90)][int]$Days = 14, [ValidateRange(1, 50000)][int]$MaxEvents = 5000)
    $filter = @{ LogName = $script:IgwtDefenderOperationalLog; Id = [int[]]@($script:IgwtProtectionEvents.Keys); StartTime = (Get-Date).AddDays(-$Days) }
    $raw = @(); $readable = $true; $err = ''
    try { $raw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch {
        if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $raw = @() }
        elseif ($_.Exception -is [System.UnauthorizedAccessException] -or [string]$_.Exception.Message -match '(?i)unauthorized|access is denied') {
            $readable = $false; $err = 'Reading the Defender log needs administrator rights on this PC. Run iG Windows Tuner as administrator to see the audit view.'
        } else { $readable = $false; $err = "The Defender log could not be read: $($_.Exception.Message)" }
    }
    $logStart = $null
    if ($readable) {
        try { $oldest = @(Get-WinEvent -LogName $script:IgwtDefenderOperationalLog -MaxEvents 1 -Oldest -ErrorAction Stop); if ($oldest.Count) { $logStart = $oldest[0].TimeCreated } }
        catch { Write-Verbose 'Oldest Defender event not readable.' }
    }
    $items = foreach ($e in $raw) { if ($e) { ConvertFrom-IgwtProtectionEvent -WinEvent $e } }
    [pscustomobject]@{ Readable = $readable; Error = $err; Days = $Days; LogStart = $logStart; Truncated = ($raw.Count -ge $MaxEvents); Events = @($items) }
}

function Get-IgwtAsrProgramSuggestion {
    <# .SYNOPSIS Next step for one program a rule reported: Ignore, Review or ExcludeIfTrusted (with the exact file to exclude). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [AllowEmptyString()][string]$Path)
    if ([string]$Definition.key -eq 'lsass') {
        return [pscustomobject]@{ Suggestion = 'Ignore'; Exclusion = ''; Reason = 'Programs that open LSASS are only denied memory access, not stopped; Microsoft says these events can be ignored unless something actually breaks.' }
    }
    if (-not $Path) { return [pscustomobject]@{ Suggestion = 'Review'; Exclusion = ''; Reason = 'The event has no file path.' } }
    if ($env:SystemRoot -and (Test-IgwtPathUnder -Path $Path -Parent ([string]$env:SystemRoot))) {
        return [pscustomobject]@{ Suggestion = 'Review'; Exclusion = ''; Reason = 'A Windows component triggered this rule. Investigate the parent program instead; Windows paths cannot be excluded.' }
    }
    $check = Test-IgwtAsrExclusion -Path $Path
    if ($check.Valid) {
        return [pscustomobject]@{ Suggestion = 'ExcludeIfTrusted'; Exclusion = $Path; Reason = 'If you trust this program, add a per-rule exclusion for this exact file (not its folder).' }
    }
    return [pscustomobject]@{ Suggestion = 'Review'; Exclusion = ''; Reason = "Not excludable: $($check.Reason)" }
}

function Get-IgwtAsrAudit {
    <#
    .SYNOPSIS
        ASR audit view (read-only). Groups events by rule and by program/path and recommends:
        PromoteToBlock / PromoteToWarn (quiet Audit rule), ReviewPrograms (Audit rule with hits),
        ReviewBlocks (blocking rule with hits), KeepAuditing (log covers fewer than 7 days),
        EnableAudit (rule not configured) or None.
    .PARAMETER Events
        Output of Get-IgwtProtectionEvents (read from the log when omitted).
    .PARAMETER Status
        Output of Get-IgwtAsrStatus (read when omitted).
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 90)][int]$Days = 14, $Events, $Status)
    if (-not $Events) { $Events = Get-IgwtProtectionEvents -Days $Days }
    if (-not $Status) { try { $Status = Get-IgwtAsrStatus } catch { $Status = $null } }
    $all = @($Events.Events | Where-Object { $_ })
    $asr = @($all | Where-Object { $_.Feature -eq 'ASR' })
    $coverage = 0.0
    if ($Events.LogStart) { $coverage = [Math]::Round([Math]::Min([double]$Events.Days, ((Get-Date) - [datetime]$Events.LogStart).TotalDays), 1) }
    $statusById = @{}
    if ($Status) { foreach ($r in @($Status.Rules)) { $statusById[[string]$r.Id] = $r } }

    $rules = foreach ($def in @(Get-IgwtAsrCatalog)) {
        $id = ([string]$def.id).ToLowerInvariant()
        $evs = @($asr | Where-Object { $_.RuleId -eq $id })
        $mode = 'Unknown'
        if ($statusById.ContainsKey($id)) { $mode = [string]$statusById[$id].Mode }
        $programs = @($evs | Group-Object { "$($_.Path)|$($_.Process)" } | ForEach-Object {
                $g = @($_.Group | Sort-Object Time -Descending)
                $s = Get-IgwtAsrProgramSuggestion -Definition $def -Path ([string]$g[0].Path)
                [pscustomobject]@{
                    Path         = [string]$g[0].Path
                    Process      = [string]$g[0].Process
                    Count        = $g.Count
                    Blocked      = @($g | Where-Object { $_.Action -eq 'Blocked' }).Count
                    Audited      = @($g | Where-Object { $_.Action -eq 'Audited' }).Count
                    WarnBypassed = @($g | Where-Object { $_.Action -eq 'WarnBypassed' }).Count
                    LastSeen     = $g[0].Time
                    Suggestion   = $s.Suggestion
                    Exclusion    = $s.Exclusion
                    Reason       = $s.Reason
                }
            } | Sort-Object Count -Descending)
        $blocked = @($evs | Where-Object { $_.Action -eq 'Blocked' }).Count
        $audited = @($evs | Where-Object { $_.Action -eq 'Audited' }).Count
        $bypassed = @($evs | Where-Object { $_.Action -eq 'WarnBypassed' }).Count
        $actionable = @($programs | Where-Object { $_.Suggestion -ne 'Ignore' })
        $rec = 'None'; $text = ''
        if ($def.serverOnly) { $text = 'Exchange servers only; nothing to do on Windows 11.' }
        elseif ($mode -in 'NotConfigured', 'Off') {
            if ([string]$def.recommendedMode -ne 'NotConfigured') { $rec = 'EnableAudit'; $text = "Not active. Recommended: $($def.recommendedMode). Start in Audit to see what it would block." }
        } elseif ($mode -eq 'Audit') {
            if ($actionable.Count -gt 0) { $rec = 'ReviewPrograms'; $text = "$($actionable.Count) program(s) would have been blocked. Exclude the ones you trust (exact file), then promote the rule." }
            elseif ($coverage -lt $script:IgwtAsrMinimumAuditDays) { $rec = 'KeepAuditing'; $text = "The Defender log only covers $coverage day(s); keep auditing for at least $($script:IgwtAsrMinimumAuditDays) days before promoting." }
            elseif ([string]$def.gamerImpactLevel -in 'medium', 'high' -and $def.supportsWarn) { $rec = 'PromoteToWarn'; $text = "No audit hits in $coverage day(s). Warn is the safer next step for this rule: a block can be bypassed for 24 hours (administrator approval needed)." }
            else { $rec = 'PromoteToBlock'; $text = "No audit hits in $coverage day(s): switching to Block should not affect this PC." }
        } elseif ($mode -in 'Block', 'Warn') {
            if ($actionable.Count -gt 0) { $rec = 'ReviewBlocks'; $text = "$($actionable.Count) program(s) were blocked. If a trusted program stopped working, add a per-rule exclusion for its exact file." }
            elseif ($programs.Count -gt 0) { $text = 'Only expected events (see the program list).' }
            else { $text = 'Active, no events.' }
        }
        [pscustomobject]@{
            Id                 = $id
            Key                = [string]$def.key
            Name               = [string]$def.name
            Mode               = $mode
            Blocked            = $blocked
            Audited            = $audited
            WarnBypassed       = $bypassed
            Total              = $evs.Count
            LastSeen           = $(if ($evs.Count) { ($evs | Sort-Object Time -Descending | Select-Object -First 1).Time } else { $null })
            Programs           = $programs
            Recommendation     = $rec
            RecommendationText = $text
        }
    }
    $knownIds = @(Get-IgwtAsrCatalog | ForEach-Object { ([string]$_.id).ToLowerInvariant() })
    $unknown = @($asr | Where-Object { $_.RuleId -and $knownIds -notcontains $_.RuleId } | Group-Object RuleId | ForEach-Object { [pscustomobject]@{ RuleId = $_.Name; Count = $_.Count } })
    $cfa = @($all | Where-Object { $_.Feature -eq 'ControlledFolderAccess' } | Group-Object Process | ForEach-Object {
            $g = @($_.Group | Sort-Object Time -Descending)
            [pscustomobject]@{ Process = [string]$_.Name; Count = $g.Count; Blocked = @($g | Where-Object { $_.Action -eq 'Blocked' }).Count; Audited = @($g | Where-Object { $_.Action -eq 'Audited' }).Count
                LastPath = [string]$g[0].Path; LastSeen = $g[0].Time
                Advice = 'If this is a trusted program (for example a game saving to Documents), allow it in Windows Security > Ransomware protection > Allow an app.' }
        } | Sort-Object Count -Descending)
    $np = @($all | Where-Object { $_.Feature -eq 'NetworkProtection' } | Group-Object Process | ForEach-Object {
            $g = @($_.Group | Sort-Object Time -Descending)
            [pscustomobject]@{ Process = [string]$_.Name; Count = $g.Count; Blocked = @($g | Where-Object { $_.Action -eq 'Blocked' }).Count; Audited = @($g | Where-Object { $_.Action -eq 'Audited' }).Count
                LastDetail = [string]$g[0].Detail; LastSeen = $g[0].Time }
        } | Sort-Object Count -Descending)
    $config = @($all | Where-Object { $_.Feature -eq 'Configuration' -and ("$($_.OldValue) $($_.NewValue)" -match '(?i)Exploit Guard|AttackSurfaceReduction|ASR') } |
            Sort-Object Time -Descending | Select-Object -First 15 | ForEach-Object { [pscustomobject]@{ Time = $_.Time; OldValue = $_.OldValue; NewValue = $_.NewValue } })
    $rules = @($rules)
    [pscustomobject]@{
        Generated              = (Get-Date).ToString('o')
        Readable               = [bool]$Events.Readable
        Error                  = [string]$Events.Error
        Days                   = [int]$Events.Days
        CoverageDays           = $coverage
        Truncated              = [bool]$Events.Truncated
        Rules                  = $rules
        UnknownRules           = $unknown
        ControlledFolderAccess = $cfa
        NetworkProtection      = $np
        ConfigChanges          = $config
        Totals                 = [pscustomobject]@{
            AsrBlocked   = @($asr | Where-Object { $_.Action -eq 'Blocked' }).Count
            AsrAudited   = @($asr | Where-Object { $_.Action -eq 'Audited' }).Count
            WarnBypassed = @($asr | Where-Object { $_.Action -eq 'WarnBypassed' }).Count
            Cfa          = @($all | Where-Object { $_.Feature -eq 'ControlledFolderAccess' }).Count
            Network      = @($all | Where-Object { $_.Feature -eq 'NetworkProtection' }).Count
            ToReview     = @($rules | Where-Object { $_.Recommendation -in 'ReviewPrograms', 'ReviewBlocks' }).Count
            ToPromote    = @($rules | Where-Object { $_.Recommendation -in 'PromoteToBlock', 'PromoteToWarn' }).Count
        }
    }
}

function Format-IgwtAsrAudit {
    <# .SYNOPSIS Plain-text rendering of the ASR audit view for the console. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Audit)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("ASR audit view: last $($Audit.Days) day(s); the Defender log covers $($Audit.CoverageDays) day(s).")
    if (-not $Audit.Readable) { $null = $sb.AppendLine("  $($Audit.Error)"); return $sb.ToString() }
    $t = $Audit.Totals
    $null = $sb.AppendLine("  ASR blocks $($t.AsrBlocked), audits $($t.AsrAudited), warn bypasses $($t.WarnBypassed); controlled folder access $($t.Cfa); network protection $($t.Network).")
    if ($Audit.Truncated) { $null = $sb.AppendLine('  Note: the event limit was reached; older events are not included.') }
    $null = $sb.AppendLine(('-' * 78))
    foreach ($r in $Audit.Rules) {
        if ($r.Total -eq 0 -and $r.Recommendation -eq 'None') { continue }
        $null = $sb.AppendLine(('[{0,-13}] {1}' -f $r.Mode, $r.Name))
        if ($r.Total) { $null = $sb.AppendLine("    events: $($r.Blocked) blocked, $($r.Audited) audited, $($r.WarnBypassed) bypassed; last $($r.LastSeen)") }
        foreach ($p in @($r.Programs | Select-Object -First 5)) {
            $null = $sb.AppendLine("    - $($p.Count)x $($p.Path)$(if ($p.Process) { " (process: $($p.Process))" })")
            $null = $sb.AppendLine("      $($p.Suggestion): $($p.Reason)")
        }
        if ($r.RecommendationText) { $null = $sb.AppendLine("    -> $($r.Recommendation): $($r.RecommendationText)") }
    }
    if (@($Audit.ControlledFolderAccess).Count) {
        $null = $sb.AppendLine('Controlled folder access:')
        foreach ($c in @($Audit.ControlledFolderAccess | Select-Object -First 10)) { $null = $sb.AppendLine("  - $($c.Count)x $($c.Process) (blocked $($c.Blocked), audited $($c.Audited))") }
    }
    if (@($Audit.NetworkProtection).Count) {
        $null = $sb.AppendLine('Network protection:')
        foreach ($n in @($Audit.NetworkProtection | Select-Object -First 10)) { $null = $sb.AppendLine("  - $($n.Count)x $($n.Process) (blocked $($n.Blocked), audited $($n.Audited))") }
    }
    if (@($Audit.ConfigChanges).Count) { $null = $sb.AppendLine("ASR configuration changes: $(@($Audit.ConfigChanges).Count) (latest $($Audit.ConfigChanges[0].Time))") }
    return $sb.ToString()
}
