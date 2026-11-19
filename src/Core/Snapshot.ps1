# Snapshot.ps1
# JSON snapshots of every value about to change, written to %ProgramData%\iGWindowsTuner\Backups
# before anything is modified and updated after each tweak, so an interrupted run can still be
# reverted. Snapshot files are plain JSON and can be inspected with any text editor.

$script:IgwtSnapshotSchema = 2
$script:IgwtSupportedSnapshotSchemas = @(1, 2)   # schema 1 (iG Windows Tuner 1.x) is upgraded in memory when read
# Snapshots record the tool name; pre-release preview builds wrote 'AegisTune'.
$script:IgwtSnapshotToolNames = @('iG Windows Tuner', 'AegisTune')
$script:IgwtApplyOperations =@('Apply', 'Preset', 'ResetDefault', 'Startup')
# Action types whose write is one call of one setting: when it fails, nothing changed.
$script:IgwtSingleWriteActions = @('defenderSetting')

function Get-IgwtActionFingerprint {
    <# .SYNOPSIS Identifies an action so a snapshot is only restored onto the same catalog action. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Action)
    $parts = @([string]$Action.type)
    # 1.0 keys first (unchanged, so 1.0 snapshots keep matching); 2.0 keys only exist on 2.0 action types.
    foreach ($p in 'path', 'name', 'item', 'subgroup', 'setting', 'scheme', 'keyword', 'setting', 'id', 'feature', 'handler', 'checker', 'provider',
        'deviceClass', 'package', 'process', 'mitigation', 'rule', 'displayGroup', 'direction', 'extension', 'protocol') {
        if ($null -ne $Action.PSObject.Properties[$p] -and $null -ne $Action.$p) { $parts += "$p=$($Action.$p)" }
    }
    if ($null -ne $Action.PSObject.Properties['services'] -and $null -ne $Action.services) { $parts += 'services=' + (@($Action.services | ForEach-Object { [string]$_.name }) -join ',') }
    return ($parts -join '|')
}

function New-IgwtSnapshot {
    <# .SYNOPSIS Creates a new snapshot document (in memory) and its file path. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Operation, [string]$Detail = '')
    $dir = Get-IgwtDataPath -Kind Backups
    if (-not (Test-Path -LiteralPath $dir)) {
        if ($PSCmdlet.ShouldProcess($dir, 'Create backups folder')) { $null = New-Item -ItemType Directory -Path $dir -Force }
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    $safeOp = ($Operation -replace '[^A-Za-z0-9\-]', '')
    $path = Join-Path $dir ("snapshot-{0}-{1}-{2}.json" -f $stamp, $safeOp, [guid]::NewGuid().ToString('N').Substring(0, 6))
    # Inside a journaled module writer: record the snapshot's path before anything changes (DECISIONS T14).
    Set-IgwtModuleOperationRef -Path $path
    $os = Get-IgwtOsInfo
    $doc = [ordered]@{
        schema        = $script:IgwtSnapshotSchema
        catalogSchema = $script:IgwtSchemaVersion
        tool          = 'iG Windows Tuner'
        version       = $script:IgwtVersion
        hardwareTags  = @()
        id          = [guid]::NewGuid().ToString()
        created     = (Get-Date).ToUniversalTime().ToString('o')
        operation   = $Operation
        detail      = $Detail
        computer    = $env:COMPUTERNAME
        build       = $os.FullBuild
        userSid     = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        userHiveSid = $script:IgwtSettings.UserHiveSid
        entries     = New-Object System.Collections.Generic.List[object]
    }
    return [pscustomobject]@{ Path = $path; Document = $doc }
}

function Save-IgwtSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Snapshot)
    Assert-IgwtWritable -Operation 'Save-IgwtSnapshot'
    if (-not $PSCmdlet.ShouldProcess($Snapshot.Path, 'Write snapshot')) { return }
    $json = ConvertTo-Json -InputObject $Snapshot.Document -Depth 25
    $tmp = "$($Snapshot.Path).tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Set-IgwtAdminOwner -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $Snapshot.Path -Force
}

function Add-IgwtSnapshotEntry {
    <# .SYNOPSIS Adds (or replaces) the entry for one tweak and writes the file immediately. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$TweakId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Actions,
        [Parameter(Mandatory = $true)][string]$Result,
        [string]$Message = '',
        [string]$Level
    )
    $entries = $Snapshot.Document.entries
    for ($i = $entries.Count - 1; $i -ge 0; $i--) { if ($entries[$i].tweakId -eq $TweakId) { $entries.RemoveAt($i) } }
    $entry = [ordered]@{ tweakId = $TweakId }
    if ($Level) { $entry['level'] = $Level }
    $entry['result'] = $Result; $entry['message'] = $Message; $entry['time'] = (Get-Date).ToUniversalTime().ToString('o'); $entry['actions'] = @($Actions)
    $entries.Add($entry)
    if ($PSCmdlet.ShouldProcess($Snapshot.Path, "Record $TweakId ($Result)")) { Save-IgwtSnapshot -Snapshot $Snapshot }
}

function Test-IgwtSnapshotEntryChanged {
    <#
    .SYNOPSIS
        Whether a snapshot entry can stand for a change on this PC. Applied, Pending and Reverted can
        (an entry is written before its write, so a crash stays revertable); NotApplied, RolledBack,
        Kept and Skipped cannot. Failed cannot when the entry's actions are one single write
        ($script:IgwtSingleWriteActions) or there are none; other failed writers can stop halfway, so
        their restore stays available. An unknown result counts as a change. Pure.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Entry)
    $result = [string]$Entry.result
    if ($result -in 'NotApplied', 'RolledBack', 'Kept', 'Skipped') { return $false }
    if ($result -ne 'Failed') { return $true }
    return (@(@($Entry.actions) | Where-Object { $_ -and $script:IgwtSingleWriteActions -notcontains [string]$_.type }).Count -gt 0)
}

function Test-IgwtSnapshotHasChange {
    <#
    .SYNOPSIS
        False for a snapshot in which nothing changed (no entries, or only entries such as a failed
        Defender write): the file stays, but it is no recent change and has nothing to undo. Takes a
        Get-IgwtSnapshotList row; a row that holds neither HasChange nor Entries counts as a change. Pure.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Snapshot)
    if ($Snapshot.PSObject.Properties['HasChange'] -and $null -ne $Snapshot.HasChange) { return [bool]$Snapshot.HasChange }
    if (-not $Snapshot.PSObject.Properties['Entries']) { return $true }
    foreach ($e in @($Snapshot.Entries | Where-Object { $_ })) { if (Test-IgwtSnapshotEntryChanged -Entry $e) { return $true } }
    return $false
}

function Get-IgwtSnapshotList {
    <# .SYNOPSIS Snapshot files, newest first, with their operation and entries. #>
    [CmdletBinding()]
    param()
    # Backups written by pre-release preview builds stay in their data root and are listed too.
    $dirs = @(Get-IgwtDataPath -Kind Backups; Get-IgwtDataPath -Kind LegacyBackups) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if ($dirs.Count -eq 0) { return @() }
    $files = @($dirs | ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter 'snapshot-*.json' -File }) | Sort-Object Name -Descending
    $catalog = @()
    $idMap = @{}
    try { $catalog = @(Get-IgwtCatalog); $idMap = Get-IgwtIdMap } catch { Write-Verbose "Catalog unavailable for snapshot upgrade: $($_.Exception.Message)" }
    foreach ($f in $files) {
        try {
            $doc = Read-IgwtJsonFile -Path $f.FullName
            if ([int]$doc.schema -lt $script:IgwtSnapshotSchema) { $doc = ConvertTo-IgwtV2Snapshot -Document $doc -Catalog $catalog -IdMap $idMap }
            $entries = @($doc.entries | Where-Object { $_ })
            [pscustomobject]@{
                Path      = $f.FullName
                File      = $f.Name
                Created   = $doc.created
                Operation = [string]$doc.operation
                Detail    = [string]$doc.detail
                Entries   = $entries
                Applied   = @($doc.entries | Where-Object { $_ -and $_.result -eq 'Applied' } | ForEach-Object { $_.tweakId })
                HasChange = (Test-IgwtSnapshotHasChange -Snapshot ([pscustomobject]@{ Entries = $entries }))
                Document  = $doc
            }
        } catch {
            Write-IgwtLog -Level Warn -Message "Unreadable snapshot $($f.Name): $($_.Exception.Message)"
        }
    }
}

function Read-IgwtSnapshot {
    <#
    .SYNOPSIS
        Loads a snapshot for restore. Refuses files that are not owned by an administrator or that
        low-privilege users could have modified, and files with an unknown schema. Schema 1 files
        (iG Windows Tuner 1.x) are upgraded to schema 2 in memory; the file itself is not changed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Snapshot not found: $Path" }
    if (-not (Test-IgwtTrustedFile -Path $Path)) {
        throw "Snapshot '$Path' is not trusted (it must be owned by Administrators/SYSTEM and not writable by standard users). Refusing to restore from it."
    }
    $doc = Read-IgwtJsonFile -Path $Path
    if ($script:IgwtSupportedSnapshotSchemas -notcontains [int]$doc.schema -or $script:IgwtSnapshotToolNames -notcontains [string]$doc.tool) { throw "Snapshot '$Path' has an unsupported format." }
    if ([int]$doc.schema -lt $script:IgwtSnapshotSchema) { $doc = ConvertTo-IgwtV2Snapshot -Document $doc -Catalog @(Get-IgwtCatalog) -IdMap (Get-IgwtIdMap) }
    return $doc
}

function Find-IgwtLatestSnapshotEntry {
    <#
    .SYNOPSIS
        Newest applied entry for a tweak that has not been reverted since. Returns
        (Path, Document, Entry) or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TweakId)
    foreach ($s in @(Get-IgwtSnapshotList)) {
        $entry = @($s.Entries | Where-Object { $_.tweakId -eq $TweakId -and $_.result -in 'Applied', 'Reverted' }) | Select-Object -First 1
        if (-not $entry) { continue }
        if ($s.Operation -eq 'Revert') { return $null }   # most recent event for this tweak was a revert
        if ($script:IgwtApplyOperations -contains (($s.Operation -split ':')[0])) {
            return [pscustomobject]@{ Path = $s.Path; Document = $s.Document; Entry = $entry }
        }
    }
    return $null
}
