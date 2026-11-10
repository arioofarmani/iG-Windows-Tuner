# RegistryCleanerPlan.ps1
# The registry cleaner's preview and its one writer (DECISIONS RG14, RG18, RG19, RG21):
# Get-IgwtRegCleanPlan re-reads every selected finding (RG14 point 2), collapses nested selections
# and lists refusals and the backup that will be written; Invoke-IgwtRegistryCleanup runs a fresh
# plan as one change session: restore point, private backup folder (selected.reg,
# firewall-rules.json, manifest.json), then one journaled step per target through the 'regClean'
# provider. The plan is read-only; the writer changes the PC only through Invoke-IgwtChangeStep.

$script:IgwtRegCleanPlanMaxAgeMinutes = 10
$script:IgwtRegCleanFirewallNote = 'Firewall rules are saved in firewall-rules.json, not in selected.reg: their store is a protected system key.'

#region Plan

function Test-IgwtRegCleanNestedTarget {
    <#
    .SYNOPSIS
        True when one finding lies inside a key tree finding (same hive, SID and view; a key below
        the tree's key, or a value of the tree's key or below it). Pure.
    .PARAMETER Ancestor
        The candidate key tree finding.
    .PARAMETER Descendant
        The other finding.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Ancestor, [Parameter(Mandatory = $true)]$Descendant)
    if ([string]$Ancestor.Kind -ne 'regKeyTree' -or [string]$Descendant.Kind -notin 'regKeyTree', 'regValue') { return $false }
    if ([string]$Ancestor.Hive -ne [string]$Descendant.Hive -or [string]$Ancestor.Sid -ne [string]$Descendant.Sid -or [string]$Ancestor.View -ne [string]$Descendant.View) { return $false }
    $a = ([string]$Ancestor.Path).Trim('\')
    $d = ([string]$Descendant.Path).Trim('\')
    if ([string]$Descendant.Kind -eq 'regValue' -and [string]::Equals($a, $d, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $d.StartsWith($a + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-IgwtRegCleanPlan {
    <#
    .SYNOPSIS
        The preview of a registry cleanup (DECISIONS RG14, RG18, RG19): every selected finding is
        evaluated again on a fresh read with the scan's rules and Test-IgwtRegCleanProtected (check
        point 2), nested selections are collapsed into the outermost key, and refusals are listed
        with their reasons. Read-only: changes nothing and writes no file.
    .DESCRIPTION
        Result: {Generated (ISO 8601); ScanId; Sid; Targets (the re-read findings that would be
        removed, each with Includes: the ids it absorbs); Included ({Id; Path; ValueName;
        IncludedIn}); Refused ({Id; Category; Program; Path; ValueName; RuleName; Reason});
        Backup {Folder; Files; Note}; Summary}. A selected key that lies inside another selected key
        of the same hive, user and view is removed (and restored) with it. Report-only rows
        (services, tasks), Protected rows and rows that cannot be backed up exactly are refused.
        Invoke-IgwtRegistryCleanup accepts the plan for 10 minutes.
    .PARAMETER Findings
        The selected findings of one Get-IgwtRegistryLeftovers result.
    .PARAMETER Context
        A scan context to re-read with (default: a new one, which reads the owners index and the
        protection lists again).
    .EXAMPLE
        $scan = Get-IgwtRegistryLeftovers; $plan = Get-IgwtRegCleanPlan -Findings @($scan.Findings | Where-Object Confidence -EQ 'Safe')
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Findings, $Context)
    $selected = @($Findings | Where-Object { $null -ne $_ })
    $scanIds = @($selected | ForEach-Object { [string]$_.ScanId } | Select-Object -Unique)
    if ($scanIds.Count -gt 1) { throw 'The selected entries come from different scans; scan again and select them from one result.' }
    $scanId = $(if ($scanIds.Count) { $scanIds[0] } else { '' })
    if ($null -eq $Context) { $Context = Get-IgwtRegCleanScanContext }
    $refused = New-Object System.Collections.Generic.List[object]
    $accepted = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $refuse = { param($f, $why) $refused.Add([pscustomobject]@{ Id = [string]$f.Id; Category = [string]$f.Category; Program = [string]$f.Program; Path = [string]$f.Path; ValueName = [string]$f.ValueName; RuleName = [string]$f.RuleName; Reason = [string]$why }) }
    foreach ($f in $selected) {
        if (-not $seen.Add([string]$f.Id)) { continue }
        if ([string]$f.Kind -notin 'regKeyTree', 'regValue', 'firewallRule') { & $refuse $f $(if ($f.Reason) { [string]$f.Reason } else { 'This entry is shown for information only.' }); continue }
        if ([string]$f.Confidence -notin 'Safe', 'Review') { & $refuse $f $(if ($f.Reason) { [string]$f.Reason } else { 'Protected: use the vendor''s removal tool.' }); continue }
        if (-not $f.Selectable) { & $refuse $f $(if ($f.Reason) { [string]$f.Reason } else { 'Not removable.' }); continue }
        # RG14 point 2: the scan's own evaluation, Test-IgwtRegCleanProtected included, on a fresh read.
        $ev = $null
        try { $ev = Get-IgwtRegCleanEvaluation -Target $f -Context $Context } catch { & $refuse $f "Cannot be checked again: $($_.Exception.Message)"; continue }
        $fresh = $ev.Finding
        if ($null -eq $fresh) { & $refuse $f "No longer a provable leftover ($($ev.Skip): $($ev.Detail))."; continue }
        if ([string]$fresh.Confidence -notin 'Safe', 'Review') { & $refuse $f $(if ($fresh.Reason) { [string]$fresh.Reason } else { 'Protected.' }); continue }
        if (-not $fresh.Selectable) { & $refuse $f $(if ($fresh.Reason) { [string]$fresh.Reason } else { 'Not removable.' }); continue }
        $t = $fresh | Select-Object *
        $t.ScanId = $scanId
        $t.Includes = @()
        $accepted.Add($t)
    }
    # Nested selections (RG19): the outermost key absorbs what lies inside it.
    $list = $accepted.ToArray()
    $parentOf = @{}
    foreach ($d in $list) {
        $best = $null
        foreach ($a in $list) {
            if ([object]::ReferenceEquals($a, $d)) { continue }
            if (Test-IgwtRegCleanNestedTarget -Ancestor $a -Descendant $d) { if ($null -eq $best -or ([string]$a.Path).Length -lt ([string]$best.Path).Length) { $best = $a } }
        }
        if ($best) { $parentOf[[string]$d.Id] = $best }
    }
    $targets = New-Object System.Collections.Generic.List[object]
    $included = New-Object System.Collections.Generic.List[object]
    foreach ($t in $list) {
        if ($parentOf.ContainsKey([string]$t.Id)) {
            $p = $parentOf[[string]$t.Id]
            $p.Includes = @(@($p.Includes) + [string]$t.Id)
            $included.Add([pscustomobject]@{ Id = [string]$t.Id; Path = [string]$t.Path; ValueName = [string]$t.ValueName; IncludedIn = [string]$p.Id; Note = "included in $([string]$p.Hive)\$([string]$p.Path)" })
        } else { $targets.Add($t) }
    }
    $regTargets = @($targets | Where-Object { $_.Kind -in 'regKeyTree', 'regValue' })
    $fwTargets = @($targets | Where-Object { $_.Kind -eq 'firewallRule' })
    $values = 0; foreach ($t in $regTargets) { $values += [int]$t.Size }
    $files = @(
        "selected.reg ($($regTargets.Count) key(s) or value(s), $values value(s))"
        "firewall-rules.json ($($fwTargets.Count) rule(s))"
        'manifest.json (ids, targets, SHA256 of each file, permissions of each key)'
    )
    $backup = [pscustomobject]@{
        Folder = (Join-Path (Get-IgwtDataPath -Kind Backups) 'regclean-<time>-<id>')
        Files  = $files
        Note   = $(if ($fwTargets.Count) { $script:IgwtRegCleanFirewallNote } else { '' })
    }
    $summary = '{0} entr{1} will be removed ({2} included in a selected key), {3} refused. A private backup folder and the change journal keep everything for a restore.' -f $targets.Count, $(if ($targets.Count -eq 1) { 'y' } else { 'ies' }), $included.Count, $refused.Count
    return [pscustomobject]@{
        Generated = (Get-Date).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        ScanId    = $scanId
        Sid       = [string]$Context.Sid
        Targets   = $targets.ToArray()
        Included  = $included.ToArray()
        Refused   = $refused.ToArray()
        Backup    = $backup
        Summary   = $summary
    }
}

#endregion

#region Writer

function Write-IgwtRegCleanBackupFile {
    <#
    .SYNOPSIS
        Writes one file of the cleanup's backup folder (selected.reg as UTF-16LE with a BOM, JSON as
        UTF-8 without a BOM) and returns its SHA256. Only into a folder directly under the data
        root's Backups folder.
    .PARAMETER Folder
        The backup folder.
    .PARAMETER Name
        The file name.
    .PARAMETER Text
        The content.
    .PARAMETER Unicode
        Write UTF-16LE with a BOM (selected.reg).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Folder, [Parameter(Mandatory = $true)][string]$Name, [AllowEmptyString()][string]$Text = '', [switch]$Unicode)
    Assert-IgwtWritable -Operation 'Write-IgwtRegCleanBackupFile'
    $backups = [System.IO.Path]::GetFullPath((Get-IgwtDataPath -Kind Backups)).TrimEnd('\')
    if (-not [string]::Equals((Split-Path -Parent ([System.IO.Path]::GetFullPath($Folder).TrimEnd('\'))), $backups, [StringComparison]::OrdinalIgnoreCase)) { throw "Backup failed: '$Folder' is not a backup folder of the tool; nothing changed." }
    if ($Name -notmatch '^[A-Za-z0-9._-]+$') { throw "Backup failed: '$Name' is not a backup file name; nothing changed." }
    $path = Join-Path $Folder $Name
    if (-not $PSCmdlet.ShouldProcess($path, 'Write backup file')) { return '' }
    $enc = $(if ($Unicode) { New-Object System.Text.UnicodeEncoding($false, $true) } else { New-Object System.Text.UTF8Encoding($false) })
    [System.IO.File]::WriteAllText($path, $Text, $enc)
    return [string](Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Invoke-IgwtRegistryCleanup {
    <#
    .SYNOPSIS
        Removes the targets of a registry cleaner plan as one journaled change session (DECISIONS
        RG16-RG21). Every removal can be restored from the change journal and from the private
        backup folder.
    .DESCRIPTION
        Needs administrator rights and a fresh Get-IgwtRegCleanPlan result (at most 10 minutes old,
        one scan id, no nested targets). One confirmation for the whole plan; then a System Restore
        point (New-IgwtRestorePoint, unless -SkipRestorePoint; with System Protection off it stops
        before anything changes unless -EnableSystemProtection is given), the change session
        (origin regClean, the backup folder as its reference), the private backup folder with
        selected.reg, firewall-rules.json and manifest.json, and one Invoke-IgwtChangeStep per
        target. The provider checks every entry once more just before it is removed (protection,
        evidence, unchanged since the preview, permissions). A refusal ('Refused:') skips that entry
        and the cleanup continues; any other failure rolls that entry back and stops (the rest is
        NotStarted). Result: {SessionId; Backup; RestorePoint; Results (per finding: Removed,
        Refused, Failed or NotStarted with the message); Removed; Refused; Failed; NotStarted;
        Message}.
    .PARAMETER Plan
        A Get-IgwtRegCleanPlan result.
    .PARAMETER SkipRestorePoint
        Do not create a System Restore point (the journal and the backup folder still keep
        everything).
    .PARAMETER EnableSystemProtection
        Turn System Protection on for the system drive when it is off, to create the restore point.
    .EXAMPLE
        Invoke-IgwtRegistryCleanup -Plan (Get-IgwtRegCleanPlan -Findings $selected)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)]$Plan, [switch]$SkipRestorePoint, [switch]$EnableSystemProtection)
    Assert-IgwtWritable -Operation 'Invoke-IgwtRegistryCleanup'
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'The registry cleaner needs administrator rights: restart iG Windows Tuner as administrator.' }
    foreach ($n in 'Generated', 'ScanId', 'Targets') { if (-not $Plan.PSObject.Properties[$n]) { throw 'This is not a registry cleaner plan: build it with Get-IgwtRegCleanPlan.' } }
    $generated = [datetime]::MinValue
    if (-not [datetime]::TryParse([string]$Plan.Generated, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$generated)) { throw 'The plan has no valid time stamp: build it again with Get-IgwtRegCleanPlan.' }
    $age = ((Get-Date).ToUniversalTime() - $generated.ToUniversalTime()).TotalMinutes
    if ($age -gt $script:IgwtRegCleanPlanMaxAgeMinutes -or $age -lt -1) { throw 'The plan is older than 10 minutes: build it again with Get-IgwtRegCleanPlan, so every entry is checked again.' }
    $scanId = [string]$Plan.ScanId
    $targets = @($Plan.Targets | Where-Object { $null -ne $_ })
    foreach ($t in $targets) { if ([string]$t.ScanId -ne $scanId) { throw 'The plan mixes entries of different scans: build it again with Get-IgwtRegCleanPlan.' } }
    # Nested targets would record an empty "before" for the inner one and break its restore (RG19).
    foreach ($a in $targets) { foreach ($d in $targets) { if (-not [object]::ReferenceEquals($a, $d) -and (Test-IgwtRegCleanNestedTarget -Ancestor $a -Descendant $d)) { throw "Refused: $([string]$d.Path) lies inside $([string]$a.Path); build the plan again with Get-IgwtRegCleanPlan." } } }
    $results = [ordered]@{}
    $row = { param($f, $res, $msg) [pscustomobject]@{ Id = [string]$f.Id; Category = [string]$f.Category; Kind = [string]$f.Kind; Program = [string]$f.Program; Hive = [string]$f.Hive; Path = [string]$f.Path; ValueName = [string]$f.ValueName; RuleName = [string]$f.RuleName; Result = $res; Message = [string]$msg } }
    $todo = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        if ($results.Contains([string]$t.Id)) { continue }
        if ([string]$t.Kind -notin 'regKeyTree', 'regValue', 'firewallRule' -or [string]$t.Confidence -notin 'Safe', 'Review' -or -not $t.Selectable) { $results[[string]$t.Id] = & $row $t 'Refused' 'This entry is not removable.'; continue }
        $results[[string]$t.Id] = & $row $t 'NotStarted' ''
        $todo.Add($t)
    }
    $sids = @($todo | Where-Object { $_.Hive -eq 'HKCU' } | ForEach-Object { [string]$_.Sid } | Select-Object -Unique)
    if ($sids.Count -gt 1) { throw 'The plan holds entries of more than one user: build it again with Get-IgwtRegCleanPlan.' }
    $userSid = $(if ($sids.Count) { $sids[0] } else { '' })
    $out = { param($sessionId, $folder, $rp, $msg)
        $all = @($results.Values)
        foreach ($inc in @($(if ($Plan.PSObject.Properties['Included']) { $Plan.Included }))) {
            if ($null -eq $inc) { continue }
            $p = $results[[string]$inc.IncludedIn]
            $all += [pscustomobject]@{ Id = [string]$inc.Id; Category = $(if ($p) { $p.Category } else { '' }); Kind = 'included'; Program = $(if ($p) { $p.Program } else { '' }); Hive = $(if ($p) { $p.Hive } else { '' }); Path = [string]$inc.Path; ValueName = [string]$inc.ValueName; RuleName = ''; Result = $(if ($p) { $p.Result } else { 'NotStarted' }); Message = [string]$inc.Note }
        }
        $n = { param($r) @($all | Where-Object { $_.Result -eq $r }).Count }
        [pscustomobject]@{ SessionId = $sessionId; Backup = $folder; RestorePoint = $rp; Results = $all; Removed = (& $n 'Removed'); Refused = (& $n 'Refused'); Failed = (& $n 'Failed'); NotStarted = (& $n 'NotStarted'); Message = $msg }
    }
    if ($todo.Count -eq 0) { return (& $out '' '' $null 'Nothing to remove.') }
    if (-not $PSCmdlet.ShouldProcess("$($todo.Count) registry cleaner entr$(if ($todo.Count -eq 1) { 'y' } else { 'ies' })", 'Remove (journaled, with a backup)')) { return $null }

    # RG21: the restore point is its own one-way journaled session, before ours.
    $rp = $null
    if (-not $SkipRestorePoint) {
        $rp = New-IgwtRestorePoint -Description 'iG Windows Tuner: before registry cleanup' -EnableSystemProtection:$EnableSystemProtection -Confirm:$false
        if ($rp -and -not $rp.Created -and [string]$rp.Reason -eq 'SystemProtectionDisabled') {
            throw 'System Protection is off, so no restore point can be created: run the cleanup again with -EnableSystemProtection or -SkipRestorePoint. Nothing changed.'
        }
        if ($rp -and -not $rp.Created) { Write-IgwtLog -Level Warn -Message "Registry cleanup: no restore point was created ($([string]$rp.Reason)); the change journal and the backup folder keep everything." }
    }
    Initialize-IgwtDataRoot -Confirm:$false
    $backups = Get-IgwtDataPath -Kind Backups
    $folder = Join-Path $backups (Get-IgwtRegCleanBackupFolderName)
    $title = "Registry cleanup ($($todo.Count) entr$(if ($todo.Count -eq 1) { 'y' } else { 'ies' }))"
    $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'regClean'; ref = $folder; version = [string]$script:IgwtVersion }) -Title $title -Confirm:$false
    # The provider needs neither the tweak catalog nor the hardware context.
    $session.Context = [pscustomobject]@{ Provider = 'regClean' }
    $session.Catalog = [pscustomobject]@{ Provider = 'regClean' }
    $message = ''
    $folderMade = $false
    $manifestArgs = $null
    try {
        try {
            $ctx = Get-IgwtRegCleanScanContext
            $findings = @{}
            foreach ($t in $todo) { $findings[[string](Get-IgwtRegCleanTarget -Finding $t)['key']] = $t }
            $script:IgwtRegCleanStep = [pscustomobject]@{
                SessionId = $session.Id; Lock = $script:IgwtChangeLock; Context = $ctx; Findings = $findings; Before = @{}
                Backup = $folder; FirewallSnapshots = [ordered]@{}
            }
            # The backup (RG18): exact snapshots, firewall definitions and key permissions.
            $snaps = New-Object System.Collections.Generic.List[object]
            $fwDefs = New-Object System.Collections.Generic.List[object]
            $security = @{}
            $steps = New-Object System.Collections.Generic.List[object]
            foreach ($t in $todo) {
                try {
                    switch ([string]$t.Kind) {
                        'regKeyTree' {
                            $s = Get-IgwtRegCleanKeySnapshot -Hive $t.Hive -Sid $t.Sid -View $t.View -Path $t.Path
                            if (-not $s.exists) { throw 'the key no longer exists' }
                            # The function returns its rows as one array (no @(), which would nest it).
                            $security[[string]$t.Id] = Get-IgwtRegCleanTreeSecurity -Snapshot $s
                            $snaps.Add($s)
                        }
                        'regValue' {
                            $s = Get-IgwtRegCleanValueSnapshot -Hive $t.Hive -Sid $t.Sid -View $t.View -Path $t.Path -Name ([string]$t.ValueName)
                            if (-not $s.exists) { throw 'the value no longer exists' }
                            $snaps.Add($s)
                        }
                        'firewallRule' { $fwDefs.Add((Get-IgwtFirewallRuleDefinition -Name ([string]$t.RuleName))) }
                    }
                    $steps.Add($t)
                } catch {
                    # Not in the backup, so it is not removed: nothing changed for it.
                    $results[[string]$t.Id] = & $row $t 'Failed' "Nothing changed: $($_.Exception.Message)"
                }
            }
            $regText = ConvertTo-IgwtRegFileText -Snapshots $snaps.ToArray()
            $fwText = ConvertTo-IgwtRegCleanFirewallRulesJson -Definitions $fwDefs.ToArray()
            $null = New-IgwtPrivateBackupFolder -Path $folder -UserSid $userSid -Confirm:$false
            $folderMade = $true
            $hashes = [ordered]@{}
            $hashes['selected.reg'] = Write-IgwtRegCleanBackupFile -Folder $folder -Name 'selected.reg' -Text $regText -Unicode -Confirm:$false
            $hashes['firewall-rules.json'] = Write-IgwtRegCleanBackupFile -Folder $folder -Name 'firewall-rules.json' -Text $fwText -Confirm:$false
            $manifestArgs = @{ Folder = (Split-Path -Leaf $folder); ScanId = $scanId; Generated = (Get-Date).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture); Targets = $steps.ToArray(); Files = $hashes; Security = $security; FirewallSnapshots = $script:IgwtRegCleanStep.FirewallSnapshots }
            $null = Write-IgwtRegCleanBackupFile -Folder $folder -Name 'manifest.json' -Text (ConvertTo-IgwtRegCleanManifest @manifestArgs) -Confirm:$false
        } catch {
            $message = $(if ($_.Exception.Message -like 'Backup failed*') { $_.Exception.Message } elseif ($folderMade) { "Backup failed: $($_.Exception.Message); nothing changed." } else { "Stopped before any change: $($_.Exception.Message); nothing changed." })
            foreach ($k in @($results.Keys)) { if ($results[$k].Result -eq 'NotStarted') { $results[$k].Message = $message } }
            Write-IgwtLog -Level Warn -Message "Registry cleanup stopped before any change: $message"
            return (& $out $session.Id $(if ($folderMade) { $folder } else { '' }) $rp $message)
        }
        foreach ($t in $steps) {
            $target = Get-IgwtRegCleanTarget -Finding $t
            $desired = [ordered]@{ action = 'remove'; finding = [string]$t.Id; session = $session.Id }
            $r = Invoke-IgwtChangeStep -Session $session -Target $target -Desired $desired -Group ([string]$t.Id) -Confirm:$false
            if ($r -and $r.Result -eq 'Committed') { $results[[string]$t.Id] = & $row $t 'Removed' ''; continue }
            $msg = $(if ($r) { [string]$r.Message } else { 'The step did not run.' })
            $plain = $msg -replace '^Nothing changed:\s*', ''
            if ($plain -like 'Refused:*') { $results[[string]$t.Id] = & $row $t 'Refused' ($plain -replace '^Refused:\s*', ''); continue }
            # Any other failure: roll this entry back and stop (RG19).
            $errors = @(Undo-IgwtChangeGroup -Session $session -Group ([string]$t.Id) -Confirm:$false)
            if ($errors.Count) { $msg = $msg + ' Rollback: ' + ($errors -join '; ') }
            $results[[string]$t.Id] = & $row $t 'Failed' $msg
            $message = 'The cleanup stopped after a failure; the remaining entries were not started.'
            break
        }
        foreach ($k in @($results.Keys)) { if ($results[$k].Result -eq 'NotStarted' -and -not $results[$k].Message) { $results[$k].Message = 'Not started: the cleanup stopped earlier.' } }
    } finally {
        try {
            if ($folderMade -and $manifestArgs -and @($script:IgwtRegCleanStep.FirewallSnapshots.Keys).Count) {
                $null = Write-IgwtRegCleanBackupFile -Folder $folder -Name 'manifest.json' -Text (ConvertTo-IgwtRegCleanManifest @manifestArgs) -Confirm:$false
            }
        } catch { Write-IgwtLog -Level Warn -Message "manifest.json was not updated with the firewall snapshots: $($_.Exception.Message)" }
        $script:IgwtRegCleanStep = $null
        Complete-IgwtChangeSession -Session $session
    }
    $res = & $out $session.Id $folder $rp $message
    Write-IgwtLog -Message "Registry cleanup: $($res.Removed) removed, $($res.Refused) refused, $($res.Failed) failed, $($res.NotStarted) not started. Backup: $folder"
    return $res
}

#endregion
