# AuditPolicy.ps1
# Advanced audit policy: read with `auditpol /get /category:* /r`, change per subcategory with
# `auditpol /set /subcategory:{GUID}`, back up and restore with `auditpol /backup` and `/restore`,
# and import or export the audit.csv format that Group Policy backups use. Every change is
# preceded by a backup and followed by a verification. auditpol throws in TestMode unless
# Invoke-IgwtAuditpol is mocked.

$script:IgwtAuditSettings = @('None', 'Success', 'Failure', 'SuccessAndFailure')
$script:IgwtAuditSettingText = @{ None = 'No Auditing'; Success = 'Success'; Failure = 'Failure'; SuccessAndFailure = 'Success and Failure' }

function Invoke-IgwtAuditpol {
    <# .SYNOPSIS Runs auditpol.exe (get, set, backup, restore only); returns the exit code and output. Refuses to run in TestMode (tests mock it). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: auditpol must be mocked in tests.' }
    if ($Arguments[0] -notin '/get', '/set', '/backup', '/restore') { throw "auditpol $($Arguments[0]) is not used by iG Windows Tuner." }
    if ($Arguments[0] -in '/set', '/restore' -and -not $PSCmdlet.ShouldProcess('Audit policy', "auditpol $($Arguments -join ' ')")) { return [pscustomobject]@{ ExitCode = 0; Output = 'WhatIf' } }
    $exe = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    $out = & $exe @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
}

function ConvertTo-IgwtAuditSetting {
    <# .SYNOPSIS Normalizes an audit setting (number 0-3, "Success and Failure", "SuccessAndFailure", ...) to None, Success, Failure or SuccessAndFailure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Value)
    $v = ([string]$Value).Trim()
    switch -Regex ($v) {
        '^0$|^(?i)(none|no auditing|off|disabled?)$' { return 'None' }
        '^1$|^(?i)success$' { return 'Success' }
        '^2$|^(?i)failure$' { return 'Failure' }
        '^3$|^(?i)(success\s*and\s*failure|successandfailure|both|all)$' { return 'SuccessAndFailure' }
    }
    return ''
}

function ConvertFrom-IgwtAuditCsv {
    <#
    .SYNOPSIS
        Parses audit CSV: the output of `auditpol /get /r` or the audit.csv of a Group Policy
        backup (with "Setting Value"). Returns Subcategory, Guid, Setting (None, Success, Failure,
        SuccessAndFailure; from Setting Value when present, otherwise from the English inclusion
        text) and raw columns. Option rows (CrashOnAuditFail and others) are returned with Option set.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $lines = @(([string]$Text) -split "`r?`n" | Where-Object { $_.Trim() })
    if (-not $lines.Count) { return @() }
    if ($lines[0] -notmatch '(?i)Subcategory') { throw 'Not an audit policy CSV: the header has no Subcategory column.' }
    foreach ($r in @($lines | ConvertFrom-Csv)) {
        $guid = ([string]$r.'Subcategory GUID').Trim()
        $sub = ([string]$r.Subcategory).Trim()
        $isOption = (-not $guid) -or $sub -like 'Option:*' -or $sub -like 'Global*'
        $setting = ''
        if ($r.PSObject.Properties['Setting Value'] -and ([string]$r.'Setting Value').Trim() -ne '') { $setting = ConvertTo-IgwtAuditSetting -Value ([string]$r.'Setting Value') }
        if (-not $setting) { $setting = ConvertTo-IgwtAuditSetting -Value ([string]$r.'Inclusion Setting') }
        [pscustomobject]@{
            Subcategory = $sub; Guid = $(if ($guid) { $guid.ToUpperInvariant() } else { '' }); Setting = $setting
            Inclusion = [string]$r.'Inclusion Setting'; Exclusion = [string]$r.'Exclusion Setting'
            Option = $isOption; RawValue = $(if ($r.PSObject.Properties['Setting Value']) { [string]$r.'Setting Value' } else { '' }); Target = [string]$r.'Policy Target'
        }
    }
}

function ConvertTo-IgwtAuditCsv {
    <# .SYNOPSIS Serializes audit rows in the audit.csv format of Group Policy backups (and auditpol /restore). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows, [string]$MachineName = $env:COMPUTERNAME)
    $q = { param($s) '"' + ([string]$s).Replace('"', '""') + '"' }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n")
    foreach ($r in $Rows) {
        if ($r.Option) {
            $null = $sb.Append(("{0},{1},{2},,{3},{4},{5}`r`n" -f $MachineName, $(if ($r.Target) { $r.Target } else { 'System' }), (& $q $r.Subcategory), (& $q $r.Inclusion), (& $q $r.Exclusion), $r.RawValue))
            continue
        }
        $s = ConvertTo-IgwtAuditSetting -Value ([string]$r.Setting)
        if (-not $s) { throw "Audit row '$($r.Subcategory)' has an invalid setting '$($r.Setting)'." }
        $guid = ([string]$r.Guid).Trim('{}').ToUpperInvariant()
        $null = $sb.Append(("{0},System,{1},{{{2}}},{3},,{4}`r`n" -f $MachineName, (& $q $r.Subcategory), $guid, $script:IgwtAuditSettingText[$s], [array]::IndexOf($script:IgwtAuditSettings, $s)))
    }
    return $sb.ToString()
}

function Get-IgwtAuditPolicy {
    <#
    .SYNOPSIS
        The advanced audit policy per subcategory (`auditpol /get /category:* /r`) and whether
        advanced audit policy overrides the legacy categories (SCENoApplyLegacyAuditPolicy).
        Read-only; needs administrator rights.
    #>
    [CmdletBinding()]
    param()
    $r = Invoke-IgwtAuditpol -Arguments @('/get', '/category:*', '/r')
    if ($r.ExitCode -ne 0) {
        if ($r.Output -match '0x00000522|privilege') { throw 'Reading the audit policy needs administrator rights (auditpol /get).' }
        throw "auditpol /get failed (exit $($r.ExitCode)): $($r.Output)"
    }
    $rows = @(ConvertFrom-IgwtAuditCsv -Text $r.Output | Where-Object { -not $_.Option })
    $force = Get-IgwtRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
    [pscustomobject]@{ Subcategories = $rows; AdvancedOverridesLegacy = ([bool]$force.Exists -and [string]$force.Value -eq '1'); Unparsed = @($rows | Where-Object { -not $_.Setting }).Count }
}

function Resolve-IgwtAuditSubcategory {
    <# .SYNOPSIS A subcategory row by GUID (with or without braces) or by name (case-insensitive). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows)
    $g = $Name.Trim().Trim('{}').ToUpperInvariant()
    $hit = @($Rows | Where-Object { ([string]$_.Guid).Trim('{}') -eq $g -or [string]::Equals([string]$_.Subcategory, $Name.Trim(), [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $hit) { throw "Unknown audit subcategory '$Name'. List them with -AuditPolicy." }
    return $hit
}

function Get-IgwtAuditChangePlan {
    <#
    .SYNOPSIS
        Dry run of Set-IgwtAuditPolicy: per subcategory the current and new setting, and warnings
        for settings that reduce auditing. Read-only.
    .PARAMETER Changes
        Hashtable of subcategory name or GUID to None, Success, Failure or SuccessAndFailure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Changes, $Current)
    if (-not $Current) { $Current = Get-IgwtAuditPolicy }
    $ops = foreach ($k in @($Changes.Keys)) {
        $row = Resolve-IgwtAuditSubcategory -Name ([string]$k) -Rows @($Current.Subcategories)
        $new = ConvertTo-IgwtAuditSetting -Value ([string]$Changes[$k])
        if (-not $new) { throw "'$($Changes[$k])' is not an audit setting (use None, Success, Failure or SuccessAndFailure)." }
        [pscustomobject]@{ Subcategory = $row.Subcategory; Guid = ([string]$row.Guid).Trim('{}'); Current = $row.Setting; New = $new; Changes = ($row.Setting -ne $new) }
    }
    $ops = @($ops)
    $warnings = @(foreach ($o in $ops) {
            $had = @{ Success = ($o.Current -in 'Success', 'SuccessAndFailure'); Failure = ($o.Current -in 'Failure', 'SuccessAndFailure') }
            $will = @{ Success = ($o.New -in 'Success', 'SuccessAndFailure'); Failure = ($o.New -in 'Failure', 'SuccessAndFailure') }
            foreach ($kind in 'Success', 'Failure') { if ($had[$kind] -and -not $will[$kind]) { "$($o.Subcategory): stops auditing $($kind.ToLowerInvariant()) events." } }
        })
    $notes = @()
    if (-not $Current.AdvancedOverridesLegacy) { $notes += 'SCENoApplyLegacyAuditPolicy is not set: a legacy audit category policy can override these subcategory settings.' }
    [pscustomobject]@{ Ops = $ops; Warnings = $warnings; Notes = $notes }
}

function Set-IgwtAuditPolicy {
    <#
    .SYNOPSIS
        Changes audit subcategories: `auditpol /backup` to a backup folder, `auditpol /set` per
        subcategory, then verification. Revert with Restore-IgwtAuditPolicy -BackupPath <Backup>.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][hashtable]$Changes, [switch]$AcknowledgeManaged)
    $current = Get-IgwtAuditPolicy
    $plan = Get-IgwtAuditChangePlan -Changes $Changes -Current $current
    $m = Get-IgwtManagementState
    if ($m.Managed -and -not $AcknowledgeManaged) { throw "This PC is managed ($(@($m.Authorities) -join ', ')); a domain or MDM audit policy can override local settings. Pass -AcknowledgeManaged to change it locally." }
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Changing the audit policy needs administrator rights.' }
    $todo = @($plan.Ops | Where-Object { $_.Changes })
    if (-not $PSCmdlet.ShouldProcess('Audit policy', "Set $($todo.Count) subcategory setting(s)")) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $dir = Join-Path (Get-IgwtDataPath -Kind Backups) ("audit-{0}" -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    $null = New-Item -ItemType Directory -Path $dir -Force
    $file = Join-Path $dir 'audit-before.csv'
    $b = Invoke-IgwtAuditpol -Arguments @('/backup', "/file:$file")
    if ($b.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "auditpol /backup failed (exit $($b.ExitCode)): $($b.Output). Nothing was changed." }
    $manifest = [ordered]@{ kind = 'igwt-audit-backup'; created = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME; sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        changes = @($todo | ForEach-Object { [ordered]@{ subcategory = $_.Subcategory; guid = $_.Guid; before = $_.Current; after = $_.New } }) }
    [System.IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), (ConvertTo-IgwtJson -InputObject $manifest), (New-Object System.Text.UTF8Encoding($false)))
    foreach ($o in $todo) {
        $s = $(if ($o.New -in 'Success', 'SuccessAndFailure') { 'enable' } else { 'disable' })
        $f = $(if ($o.New -in 'Failure', 'SuccessAndFailure') { 'enable' } else { 'disable' })
        $r = Invoke-IgwtAuditpol -Arguments @('/set', "/subcategory:{$($o.Guid)}", "/success:$s", "/failure:$f")
        if ($r.ExitCode -ne 0) { throw "auditpol /set for $($o.Subcategory) failed (exit $($r.ExitCode)): $($r.Output). Restore with -AuditRestore `"$dir`"." }
    }
    Write-IgwtLog -Message "Audit policy: $(@($todo | ForEach-Object { "$($_.Subcategory)=$($_.New)" }) -join '; '). Backup: $dir"
    $after = Get-IgwtAuditPolicy
    $mismatch = @(foreach ($o in $todo) { $now = @($after.Subcategories | Where-Object { ([string]$_.Guid).Trim('{}') -eq $o.Guid }) | Select-Object -First 1; if (-not $now -or $now.Setting -ne $o.New) { $o.Subcategory } })
    return [pscustomobject]@{ Backup = $dir; Ops = $todo; Warnings = $plan.Warnings; Verified = ($mismatch.Count -eq 0); Mismatch = $mismatch }
}

function Restore-IgwtAuditPolicy {
    <# .SYNOPSIS Restores the audit policy from a Set-IgwtAuditPolicy backup (`auditpol /restore`), after checking its hash. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$BackupPath)
    $mf = Join-Path $BackupPath 'manifest.json'
    if (-not (Test-Path -LiteralPath $mf)) { throw "'$BackupPath' is not an audit policy backup (manifest.json missing)." }
    $m = Read-IgwtJsonFile -Path $mf
    if ([string]$m.kind -ne 'igwt-audit-backup') { throw "'$BackupPath' is not an iG Windows Tuner audit policy backup." }
    $file = Join-Path $BackupPath 'audit-before.csv'
    if (-not (Test-Path -LiteralPath $file) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne [string]$m.sha256) { throw 'The audit backup is missing or was changed; nothing was restored.' }
    if (-not $PSCmdlet.ShouldProcess('Audit policy', "Restore from $BackupPath")) { return $null }
    $r = Invoke-IgwtAuditpol -Arguments @('/restore', "/file:$file")
    if ($r.ExitCode -ne 0) { throw "auditpol /restore failed (exit $($r.ExitCode)): $($r.Output)" }
    Write-IgwtLog -Message "Audit policy restored from $BackupPath"
    return [pscustomobject]@{ Restored = $BackupPath; Subcategories = @($m.changes).Count }
}

function Import-IgwtAuditCsv {
    <#
    .SYNOPSIS
        Reads an audit.csv (from a Group Policy backup, a security baseline or Export-IgwtAuditCsv)
        and returns the change hashtable for the subcategories that differ from the current policy.
        Read-only; pass the result to Get-IgwtAuditChangePlan or Set-IgwtAuditPolicy.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, $Current)
    $rows = @(ConvertFrom-IgwtAuditCsv -Text ([System.IO.File]::ReadAllText($Path)) | Where-Object { -not $_.Option })
    if (-not $Current) { $Current = Get-IgwtAuditPolicy }
    $changes = @{}
    foreach ($r in $rows) {
        if (-not $r.Setting) { throw "Row '$($r.Subcategory)' in $Path has no valid setting." }
        $cur = @($Current.Subcategories | Where-Object { ([string]$_.Guid).Trim('{}') -eq ([string]$r.Guid).Trim('{}') }) | Select-Object -First 1
        if (-not $cur) { throw "Subcategory $($r.Subcategory) $($r.Guid) does not exist on this PC." }
        if ($cur.Setting -ne $r.Setting) { $changes[([string]$r.Guid).Trim('{}')] = $r.Setting }
    }
    return $changes
}

function Export-IgwtAuditCsv {
    <# .SYNOPSIS Writes the current audit policy as audit.csv (Group Policy backup format). Reads the policy; writes only the given file. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, $Current)
    if (-not $Current) { $Current = Get-IgwtAuditPolicy }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export audit policy')) { return }
    [System.IO.File]::WriteAllText($Path, (ConvertTo-IgwtAuditCsv -Rows @($Current.Subcategories)), (New-Object System.Text.UTF8Encoding($false)))
}
