# PolicyPresets.ps1
# Category-scoped policy presets (data\policy\presets.json): ADMX policies, documented registry
# policy values, advanced audit subcategories and security template settings. A preset is applied
# as one batch: one Local GPO backup, one Registry.pol write per class, one gpt.ini update, one
# targeted gpupdate and a verification; audit and security settings go through their own engines
# (with backups and the lockout safeguards). A record file lists every backup so the whole preset
# can be reverted. Presets also export as an LGPO-style GPO backup folder, a .reg file, a
# standalone PowerShell script or JSON.

$script:IgwtPolicyPresets = $null

function Get-IgwtPolicyPresets {
    <# .SYNOPSIS The policy presets from data\policy\presets.json. #>
    [CmdletBinding()]
    param([string]$Id)
    if (-not $script:IgwtPolicyPresets) { $script:IgwtPolicyPresets = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'policy\presets.json')).presets) }
    if ($Id) {
        $p = @($script:IgwtPolicyPresets | Where-Object { $_.id -eq $Id -or $_.id -eq "policy.$Id" }) | Select-Object -First 1
        if (-not $p) { throw "Unknown policy preset '$Id'. List them with -PolicyPreset list." }
        return $p
    }
    return $script:IgwtPolicyPresets
}

function Test-IgwtPolicyPresetCatalog {
    <#
    .SYNOPSIS
        Validates the policy presets: unique ids, texts, https sources, known setting kinds,
        registry values only under machine Policies keys and never on the denylist, audit GUIDs,
        security template keys, and no quality update deferral. Returns error texts.
    #>
    [CmdletBinding()]
    param([object[]]$Presets)
    if (-not $Presets) { $Presets = @(Get-IgwtPolicyPresets) }
    $errors = New-Object System.Collections.Generic.List[string]
    $ids = @{}
    foreach ($p in $Presets) {
        $id = [string]$p.id
        if ($id -notmatch '^policy\.[a-z0-9-]+$') { $errors.Add("${id}: id must be policy.<name>.") }
        if ($ids.ContainsKey($id)) { $errors.Add("${id}: duplicate id.") }; $ids[$id] = $true
        foreach ($f in 'name', 'scope', 'hint', 'description', 'antiCheat') { if (-not [string]$p.$f) { $errors.Add("${id}: missing $f.") } }
        if (([string]$p.hint).Length -gt 140) { $errors.Add("${id}: hint is longer than 140 characters.") }
        if (-not @($p.sources).Count -or @($p.sources | Where-Object { [string]$_ -notmatch '^https://' }).Count) { $errors.Add("${id}: needs https sources.") }
        if (-not @($p.settings).Count) { $errors.Add("${id}: has no settings.") }
        $n = 0
        foreach ($s in @($p.settings)) {
            $n++; $where = "${id} setting ${n}"
            switch ([string]$s.kind) {
                'admx' {
                    if ([string]$s.policy -notmatch '^[^:]+:[^:]+$') { $errors.Add("${where}: policy must be file:name.") }
                    if ([string]$s.state -notin 'Enabled', 'Disabled', 'NotConfigured') { $errors.Add("${where}: state must be Enabled, Disabled or NotConfigured.") }
                    if ([string]$s.policy -match '^WindowsUpdate:DeferQualityUpdates') { $errors.Add("${where}: quality updates are never deferred.") }
                }
                'registry' {
                    if (-not (Get-IgwtPolicyBridgeTarget -Path ('HKLM:\' + [string]$s.key) -Name ([string]$s.valueName))) { $errors.Add("${where}: registry settings must be under a machine Policies key.") }
                    if ([string]$s.type -notin 'String', 'ExpandString', 'DWord', 'QWord', 'MultiString') { $errors.Add("${where}: unsupported type $($s.type).") }
                    if ([string]$s.source -notmatch '^https://') { $errors.Add("${where}: registry settings need an https source.") }
                    $why = Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = [string]$s.key; ValueName = [string]$s.valueName; Type = [string]$s.type; Value = $s.value })
                    if ($why) { $errors.Add("${where}: refused by the denylist: $why") }
                    if ([string]$s.valueName -match '^DeferQualityUpdates') { $errors.Add("${where}: quality updates are never deferred.") }
                }
                'audit' {
                    if ([string]$s.guid -notmatch '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') { $errors.Add("${where}: guid must be a subcategory GUID without braces.") }
                    if (-not (ConvertTo-IgwtAuditSetting -Value ([string]$s.setting))) { $errors.Add("${where}: invalid audit setting $($s.setting).") }
                }
                'secpol' {
                    try { $c = @(ConvertFrom-IgwtSecurityChangeText -Text ("{0}={1}" -f $s.key, $s.value)); if ($c.Count -ne 1) { $errors.Add("${where}: one security setting per entry.") } }
                    catch { $errors.Add("${where}: $($_.Exception.Message)") }
                }
                default { $errors.Add("${where}: unknown kind '$($s.kind)'.") }
            }
        }
    }
    return $errors.ToArray()
}

function ConvertTo-IgwtPolicyPresetValues {
    [CmdletBinding()]
    param($Values)
    $h = @{}
    if ($Values) { foreach ($pr in $Values.PSObject.Properties) { $v = $pr.Value; if ($v -is [object[]]) { $v = @($v | ForEach-Object { [string]$_ }) }; $h[$pr.Name] = $v } }
    return $h
}

function Get-IgwtPolicyPresetPlan {
    <#
    .SYNOPSIS
        Dry run of a policy preset: per setting the Registry.pol operations or audit and security
        changes, the current state, whether it already matches, and why a setting is unavailable
        (ADMX not installed, edition, denylist). Read-only; audit and security rows show
        "needs administrator rights" when the session cannot read them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $p = Get-IgwtPolicyPresets -Id $Id
    $family = Get-IgwtEditionFamily -EditionId ([string](Get-IgwtOsInfo).EditionId)
    $m = Get-IgwtManagementState
    $rows = New-Object System.Collections.Generic.List[object]
    $audit = $null; $auditErr = ''; $sec = $null; $secErr = ''
    if (@($p.settings | Where-Object { $_.kind -eq 'audit' }).Count) { try { $audit = Get-IgwtAuditPolicy } catch { $auditErr = $_.Exception.Message } }
    if (@($p.settings | Where-Object { $_.kind -eq 'secpol' }).Count) { try { $sec = Export-IgwtSecurityPolicy } catch { $secErr = $_.Exception.Message } }
    foreach ($s in @($p.settings)) {
        $row = [ordered]@{ Kind = [string]$s.kind; Name = ''; Class = 'Machine'; Ops = @(); Status = 'Change'; Reason = ''; Note = [string]$s.note; Setting = $s }
        if ($s.editions -and @($s.editions).Count -and @($s.editions) -notcontains $family) { $row.Note = (@("Not effective on $family (Windows applies it on $(@($s.editions) -join ', ')).", $row.Note) | Where-Object { $_ }) -join ' ' }
        switch ([string]$s.kind) {
            'admx' {
                $cls = $(if ($s.class) { [string]$s.class } else { $null })
                try {
                    $classArg = @{}; if ($cls) { $classArg.Class = $cls }
                    $cp = Get-IgwtPolicyChangePlan -Id ([string]$s.policy) -State ([string]$s.state) -Values (ConvertTo-IgwtPolicyPresetValues -Values $s.values) @classArg
                    $row.Name = "$($cp.Policy.DisplayName) = $($s.state)"; $row.Class = $cp.Class; $row.Ops = @($cp.Ops)
                    if ($cp.Refusals.Count) { $row.Status = 'Refused'; $row.Reason = ($cp.Refusals -join ' ') }
                    else {
                        $entries = @(Get-IgwtLocalPolicyEntries -Class $cp.Class)
                        if (Test-IgwtPolOpsSatisfied -Entries $entries -Ops $row.Ops) { $row.Status = 'InPlace' }
                    }
                } catch { $row.Name = [string]$s.policy; $row.Status = 'Unavailable'; $row.Reason = $(if ($_.Exception.Message -like 'Unknown policy*') { "The ADMX template for $($s.policy) is not installed (add its folder with -AdmxFolder)." } else { $_.Exception.Message }) }
            }
            'registry' {
                $row.Name = $(if ($s.label) { [string]$s.label } else { "$($s.key)\$($s.valueName)" })
                $row.Ops = @([pscustomobject]@{ Op = 'Set'; Key = [string]$s.key; ValueName = [string]$s.valueName; Type = [string]$s.type; Value = $s.value })
                $why = Test-IgwtPolicyOpAllowed -Op $row.Ops[0]
                if ($why) { $row.Status = 'Refused'; $row.Reason = $why }
                elseif (Test-IgwtPolOpsSatisfied -Entries @(Get-IgwtLocalPolicyEntries -Class Machine) -Ops $row.Ops) { $row.Status = 'InPlace' }
            }
            'audit' {
                $row.Name = "Audit $($s.name) = $($s.setting)"
                if (-not $audit) { $row.Status = 'Unknown'; $row.Reason = $auditErr }
                else {
                    $cur = @($audit.Subcategories | Where-Object { ([string]$_.Guid).Trim('{}') -eq ([string]$s.guid).ToUpperInvariant() }) | Select-Object -First 1
                    if (-not $cur) { $row.Status = 'Unavailable'; $row.Reason = "Audit subcategory $($s.guid) does not exist on this PC." }
                    elseif ($cur.Setting -eq (ConvertTo-IgwtAuditSetting -Value ([string]$s.setting))) { $row.Status = 'InPlace' }
                }
            }
            'secpol' {
                $c = @(ConvertFrom-IgwtSecurityChangeText -Text ("{0}={1}" -f $s.key, $s.value))[0]
                $row.Name = $(if ($s.label) { [string]$s.label } else { "$($c.Section)\$($c.Key) = $($c.Value)" })
                if (-not $sec) { $row.Status = 'Unknown'; $row.Reason = $secErr }
                elseif ($sec.Contains($c.Section) -and $sec[$c.Section].Contains($c.Key) -and [string]$sec[$c.Section][$c.Key] -eq [string]$c.Value) { $row.Status = 'InPlace' }
            }
        }
        $rows.Add([pscustomobject]$row)
    }
    $refusals = @()
    $secRows = @($rows | Where-Object { $_.Kind -eq 'secpol' -and $_.Status -ne 'InPlace' })
    if ($secRows.Count -and $sec) {
        try { $sp = Get-IgwtSecurityChangePlan -Current $sec -Changes @($secRows | ForEach-Object { ConvertFrom-IgwtSecurityChangeText -Text ("{0}={1}" -f $_.Setting.key, $_.Setting.value) }); $refusals += @($sp.Refusals) } catch { $refusals += $_.Exception.Message }
    }
    if (-not $m.LocalGroupPolicy) { $refusals += 'Windows Home has no Local Group Policy: policy presets are report-only on this edition.' }
    [pscustomobject]@{ Preset = $p; Rows = $rows.ToArray(); Refusals = $refusals; Managed = [bool]$m.Managed; Authorities = @($m.Authorities)
        Changes = @($rows | Where-Object { $_.Status -eq 'Change' }).Count; Unavailable = @($rows | Where-Object { $_.Status -in 'Unavailable', 'Refused' }).Count }
}

function Test-IgwtPolOpsSatisfied {
    <# .SYNOPSIS True when applying the operations would not change the Registry.pol entries. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Ops)
    $after = @(Update-IgwtPolEntries -Entries $Entries -Ops $Ops)
    $key = { param($e) "$(([string]$e.Key).ToLowerInvariant())|$(([string]$e.ValueName).ToLowerInvariant())|$($e.Type)|$([BitConverter]::ToString([byte[]]@($e.Data)))" }
    $a = @($Entries | ForEach-Object { & $key $_ } | Sort-Object)
    $b = @($after | ForEach-Object { & $key $_ } | Sort-Object)
    return (($a -join "`n") -eq ($b -join "`n"))
}

function Invoke-IgwtPolicyPreset {
    <#
    .SYNOPSIS
        Applies a policy preset as one batch (see the file header) and writes a record of every
        backup to State\policy-preset-<timestamp>.json; revert with Restore-IgwtPolicyPreset.
        Unavailable settings are skipped and reported; any refusal stops the whole preset.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [switch]$AcknowledgeManaged, [switch]$NoRefresh)
    $plan = Get-IgwtPolicyPresetPlan -Id $Id
    return (Invoke-IgwtPolicyBatch -Plan $plan -AcknowledgeManaged:$AcknowledgeManaged -NoRefresh:$NoRefresh)
}

function Invoke-IgwtPolicyBatch {
    <#
    .SYNOPSIS
        Applies a policy plan (from a preset or a baseline) as one batch: Local GPO backup, one
        Registry.pol write per class, gpt.ini, audit and security changes through their engines,
        a record file, one targeted gpupdate and a verification.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Plan, [switch]$AcknowledgeManaged, [switch]$NoRefresh)
    $plan = $Plan
    $refused = @($plan.Rows | Where-Object { $_.Status -eq 'Refused' })
    if ($plan.Refusals.Count -or $refused.Count) { throw "Refused: $(@($plan.Refusals) + @($refused | ForEach-Object { "$($_.Name): $($_.Reason)" }) -join ' ')" }
    if ($plan.Managed -and -not $AcknowledgeManaged) { throw "This PC is managed ($($plan.Authorities -join ', ')); a domain or MDM policy can override local policies. Pass -AcknowledgeManaged to apply the preset locally." }
    if (@($plan.Rows | Where-Object { $_.Kind -in 'audit', 'secpol' -and $_.Status -eq 'Unknown' }).Count) { throw 'This preset changes audit or security settings, which need administrator rights to read and change.' }
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Applying a policy preset needs administrator rights.' }
    $todo = @($plan.Rows | Where-Object { $_.Status -eq 'Change' })
    if (-not $todo.Count) { return [pscustomobject]@{ Id = $plan.Preset.id; Changed = 0; Record = $null; Verified = $true; Mismatch = @(); Skipped = @($plan.Rows | Where-Object { $_.Status -eq 'Unavailable' }) } }
    if (-not $PSCmdlet.ShouldProcess($plan.Preset.name, "Apply $($todo.Count) policy setting(s)")) { return $null }
    $record = [ordered]@{ kind = 'igwt-policy-preset'; preset = [string]$plan.Preset.id; created = (Get-Date).ToString('o'); gpoBackup = $null; auditBackup = $null; secpolBackup = $null; settings = @($todo | ForEach-Object { $_.Name }) }
    $polRows = @($todo | Where-Object { $_.Kind -in 'admx', 'registry' })
    $classes = @($polRows | ForEach-Object { $_.Class } | Select-Object -Unique)
    if ($polRows.Count) {
        $record.gpoBackup = Backup-IgwtLocalGpo -Reason "before policy preset $($plan.Preset.id)"
        foreach ($cls in $classes) {
            $before = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $cls)).Entries)
            $after = @(Update-IgwtPolEntries -Entries $before -Ops @($polRows | Where-Object { $_.Class -eq $cls } | ForEach-Object { $_.Ops }))
            $null = Save-IgwtBridgePol -Class $cls -Before $before -After $after
        }
    }
    if (@($todo | Where-Object Kind -EQ 'audit').Count) {
        $changes = @{}; foreach ($r in @($todo | Where-Object Kind -EQ 'audit')) { $changes[[string]$r.Setting.guid] = [string]$r.Setting.setting }
        $record.auditBackup = (Set-IgwtAuditPolicy -Changes $changes -AcknowledgeManaged:$AcknowledgeManaged).Backup
    }
    if (@($todo | Where-Object Kind -EQ 'secpol').Count) {
        $changes = @($todo | Where-Object Kind -EQ 'secpol' | ForEach-Object { ConvertFrom-IgwtSecurityChangeText -Text ("{0}={1}" -f $_.Setting.key, $_.Setting.value) })
        $record.secpolBackup = (Set-IgwtSecurityPolicy -Changes $changes -AcknowledgeManaged:$AcknowledgeManaged).Backup
    }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $stateDir = Get-IgwtDataPath -Kind State
    if (-not (Test-Path -LiteralPath $stateDir)) { $null = New-Item -ItemType Directory -Path $stateDir -Force }
    $recFile = Join-Path $stateDir ("policy-preset-{0}.json" -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    [System.IO.File]::WriteAllText($recFile, (ConvertTo-IgwtJson -InputObject $record), (New-Object System.Text.UTF8Encoding($false)))
    Write-IgwtLog -Message "Policy preset $($plan.Preset.id): $($todo.Count) setting(s). Record: $recFile"
    $mismatch = @()
    if ($polRows.Count -and -not $NoRefresh) {
        Invoke-IgwtGpUpdate -Target $(if ($classes.Count -gt 1) { 'Both' } else { [string]$classes[0] })
        foreach ($r in $polRows) {
            $root = Get-IgwtPolicyRoot -Class $r.Class
            foreach ($o in @($r.Ops | Where-Object { $_.Op -in 'Set', 'Delete' })) {
                $v = Get-IgwtRegistryValue -Path ($root + $o.Key) -Name $o.ValueName
                $ok = $(if ($o.Op -eq 'Delete') { -not $v.Exists } else { $v.Exists -and ((@($v.Value) -join ',') -eq (@($o.Value) -join ',')) })
                if (-not $ok) { $mismatch += "$($o.Key)\$($o.ValueName)" }
            }
        }
    }
    return [pscustomobject]@{ Id = $plan.Preset.id; Changed = $todo.Count; Record = $recFile; Verified = ($mismatch.Count -eq 0); Mismatch = $mismatch; Skipped = @($plan.Rows | Where-Object { $_.Status -eq 'Unavailable' }) }
}

function Restore-IgwtPolicyPreset {
    <# .SYNOPSIS Reverts a policy preset from its record: Local GPO, audit and security backups, in reverse order. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Record, [switch]$NoRefresh)
    $r = Read-IgwtJsonFile -Path $Record
    if ([string]$r.kind -ne 'igwt-policy-preset') { throw "'$Record' is not a policy preset record." }
    if (-not $PSCmdlet.ShouldProcess([string]$r.preset, 'Revert policy preset')) { return $null }
    $done = @()
    if ($r.secpolBackup) { $null = Restore-IgwtSecurityPolicy -BackupPath ([string]$r.secpolBackup); $done += 'security policy' }
    if ($r.auditBackup) { $null = Restore-IgwtAuditPolicy -BackupPath ([string]$r.auditBackup); $done += 'audit policy' }
    if ($r.gpoBackup) { $null = Restore-IgwtLocalGpo -BackupPath ([string]$r.gpoBackup) -NoRefresh:$NoRefresh; Clear-IgwtCache -Prefix 'pol:' -WhatIf:$false; $done += 'Local GPO' }
    Write-IgwtLog -Message "Policy preset $($r.preset) reverted ($($done -join ', '))."
    return [pscustomobject]@{ Preset = [string]$r.preset; Restored = $done }
}

#region Exports

function Get-IgwtPolicyExportContent {
    <#
    .SYNOPSIS
        Resolved content of a preset (or a plan) for export: Registry.pol operations per class,
        audit rows and security template sections. Settings that are unavailable on this PC are left out.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Plan)
    $ok = @($Plan.Rows | Where-Object { $_.Status -notin 'Unavailable', 'Refused' })
    $sec = New-IgwtInfSectionTable
    foreach ($r in @($ok | Where-Object Kind -EQ 'secpol')) {
        $c = @(ConvertFrom-IgwtSecurityChangeText -Text ("{0}={1}" -f $r.Setting.key, $r.Setting.value))[0]
        if (-not $sec.Contains($c.Section)) { $sec[$c.Section] = New-IgwtInfSectionTable }
        $sec[$c.Section][$c.Key] = $c.Value
    }
    [pscustomobject]@{
        Machine = @($ok | Where-Object { $_.Kind -in 'admx', 'registry' -and $_.Class -eq 'Machine' } | ForEach-Object { $_.Ops })
        User    = @($ok | Where-Object { $_.Kind -in 'admx', 'registry' -and $_.Class -eq 'User' } | ForEach-Object { $_.Ops })
        Audit   = @($ok | Where-Object Kind -EQ 'audit' | ForEach-Object { [pscustomobject]@{ Subcategory = [string]$_.Setting.name; Guid = ([string]$_.Setting.guid).ToUpperInvariant(); Setting = (ConvertTo-IgwtAuditSetting -Value ([string]$_.Setting.setting)); Option = $false } })
        Security = $sec
        Skipped = @($Plan.Rows | Where-Object { $_.Status -in 'Unavailable', 'Refused' } | ForEach-Object { "$($_.Name): $($_.Reason)" })
    }
}

function ConvertTo-IgwtRegText {
    <# .SYNOPSIS Registry.pol operations as a .reg file (Windows Registry Editor Version 5.00). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Machine = @(), [AllowEmptyCollection()][object[]]$User = @())
    $esc = { param($s) ([string]$s).Replace('\', '\\').Replace('"', '\"') }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("Windows Registry Editor Version 5.00`r`n")
    foreach ($pair in @(@('HKEY_LOCAL_MACHINE', $Machine), @('HKEY_CURRENT_USER', $User))) {
        foreach ($g in @($pair[1] | Group-Object { $_.Key })) {
            $null = $sb.Append("`r`n[$($pair[0])\$($g.Name)]`r`n")
            foreach ($o in $g.Group) {
                switch ($o.Op) {
                    'Set' {
                        $line = switch ([string]$o.Type) {
                            'DWord' { 'dword:{0:x8}' -f [uint32]$o.Value }
                            'QWord' { 'hex(b):' + ((([BitConverter]::GetBytes([uint64]$o.Value)) | ForEach-Object { '{0:x2}' -f $_ }) -join ',') }
                            'String' { '"' + (& $esc $o.Value) + '"' }
                            'ExpandString' { 'hex(2):' + (([System.Text.Encoding]::Unicode.GetBytes([string]$o.Value + [char]0) | ForEach-Object { '{0:x2}' -f $_ }) -join ',') }
                            'MultiString' { 'hex(7):' + (([System.Text.Encoding]::Unicode.GetBytes(((@($o.Value) -join [string][char]0) + [char]0 + [char]0)) | ForEach-Object { '{0:x2}' -f $_ }) -join ',') }
                            default { throw "Type $($o.Type) cannot be exported to .reg." }
                        }
                        $null = $sb.Append("`"$(& $esc $o.ValueName)`"=$line`r`n")
                    }
                    'Delete' { $null = $sb.Append("`"$(& $esc $o.ValueName)`"=-`r`n") }
                    'Remove' { $null = $sb.Append("`"$(& $esc $o.ValueName)`"=-`r`n") }
                    { $_ -in 'DeleteValues', 'RemoveKeyValues' } { $null = $sb.Append("; all values of this key are removed first (non-additive list); .reg cannot express it, delete them by hand`r`n") }
                }
            }
        }
    }
    return $sb.ToString()
}

function ConvertTo-IgwtPolicyScriptText {
    <#
    .SYNOPSIS
        A standalone PowerShell script that writes the registry policy values and audit settings
        (run it elevated; -WhatIf previews). Security template settings are written as an INF next
        to it and applied with secedit by the script. It changes only the listed settings.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Content, [Parameter(Mandatory = $true)][string]$Name, [string]$InfName = '')
    $q = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("# $Name`r`n# Generated by iG Windows Tuner $script:IgwtVersion on $((Get-Date).ToString('yyyy-MM-dd')). Run elevated in Windows PowerShell; -WhatIf previews.`r`n")
    $null = $sb.Append("# These are direct registry writes: they do not appear in gpedit and a policy refresh does not keep them. Prefer the GPO backup export with LGPO.exe.`r`n")
    $null = $sb.Append("[CmdletBinding(SupportsShouldProcess = `$true)]`r`nparam()`r`n`$ErrorActionPreference = 'Stop'`r`n")
    $null = $sb.Append("function Set-PolicyValue([string]`$Path, [string]`$Name, [string]`$Type, `$Value) { if (`$PSCmdlet.ShouldProcess(`"`$Path\`$Name`", `"Set `$Type`")) { if (-not (Test-Path -LiteralPath `$Path)) { `$null = New-Item -Path `$Path -Force }; `$null = New-ItemProperty -LiteralPath `$Path -Name `$Name -PropertyType `$Type -Value `$Value -Force } }`r`n")
    $null = $sb.Append("function Remove-PolicyValue([string]`$Path, [string]`$Name) { if (`$PSCmdlet.ShouldProcess(`"`$Path\`$Name`", 'Delete')) { Remove-ItemProperty -LiteralPath `$Path -Name `$Name -ErrorAction SilentlyContinue } }`r`n")
    foreach ($pair in @(@('HKLM:\', $Content.Machine), @('HKCU:\', $Content.User))) {
        foreach ($o in @($pair[1])) {
            $path = & $q ($pair[0] + $o.Key)
            switch ($o.Op) {
                'Set' {
                    $val = switch ([string]$o.Type) { 'DWord' { [string][uint32]$o.Value } 'QWord' { [string][uint64]$o.Value } 'MultiString' { '@(' + ((@($o.Value) | ForEach-Object { & $q $_ }) -join ', ') + ')' } default { & $q $o.Value } }
                    $null = $sb.Append("Set-PolicyValue $path $(& $q $o.ValueName) $(& $q $o.Type) $val`r`n")
                }
                { $_ -in 'Delete', 'Remove' } { $null = $sb.Append("Remove-PolicyValue $path $(& $q $o.ValueName)`r`n") }
                { $_ -in 'DeleteValues', 'RemoveKeyValues' } { $null = $sb.Append("if (`$PSCmdlet.ShouldProcess($path, 'Remove all values')) { Remove-ItemProperty -LiteralPath $path -Name * -ErrorAction SilentlyContinue }`r`n") }
            }
        }
    }
    foreach ($a in @($Content.Audit)) {
        $s = $(if ($a.Setting -in 'Success', 'SuccessAndFailure') { 'enable' } else { 'disable' }); $f = $(if ($a.Setting -in 'Failure', 'SuccessAndFailure') { 'enable' } else { 'disable' })
        $null = $sb.Append("if (`$PSCmdlet.ShouldProcess($(& $q "Audit $($a.Subcategory)"), $(& $q $a.Setting))) { auditpol /set /subcategory:'{$($a.Guid)}' /success:$s /failure:$f }`r`n")
    }
    if ($InfName) {
        $null = $sb.Append("`$inf = Join-Path `$PSScriptRoot $(& $q $InfName)`r`n")
        $null = $sb.Append("if (`$PSCmdlet.ShouldProcess(`$inf, 'Apply security template')) { secedit /configure /db (Join-Path `$env:TEMP 'policy-export.sdb') /cfg `$inf /areas SECURITYPOLICY USER_RIGHTS /quiet }`r`n")
    }
    return $sb.ToString()
}

function Export-IgwtPolicyPreset {
    <#
    .SYNOPSIS
        Exports a policy preset for deployment:
        GpoBackup  an LGPO-style folder ({GUID}\DomainSysvol\GPO\Machine|User\registry.pol,
                   Machine\microsoft\windows nt\SecEdit\GptTmpl.inf and ...\Audit\audit.csv) with a README of the
                   LGPO.exe commands. A full GPMC backup (Backup.xml, bkupInfo.xml) is not generated.
        Reg        a .reg file with the registry policy values.
        Script     a standalone PowerShell script (plus an INF for security settings).
        Json       the preset definition with its resolved Registry.pol operations.
        Writes only into -Path; resolving the preset reads the policy catalog.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][ValidateSet('GpoBackup', 'Reg', 'Script', 'Json')][string]$Format, [Parameter(Mandatory = $true)][string]$Path)
    $plan = Get-IgwtPolicyPresetPlan -Id $Id
    $c = Get-IgwtPolicyExportContent -Plan $plan
    $name = [string]$plan.Preset.id
    if (-not $PSCmdlet.ShouldProcess($Path, "Export $name as $Format")) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Path $Path -Force }
    $utf = New-Object System.Text.UTF8Encoding($false)
    $files = New-Object System.Collections.Generic.List[string]
    switch ($Format) {
        'GpoBackup' {
            $guid = '{' + ([guid]::NewGuid().ToString().ToUpperInvariant()) + '}'
            $gpo = Join-Path $Path "$guid\DomainSysvol\GPO"
            foreach ($cls in 'Machine', 'User') {
                $ops = @($c.$cls); if (-not $ops.Count) { continue }
                $dir = Join-Path $gpo $cls; $null = New-Item -ItemType Directory -Path $dir -Force
                $f = Join-Path $dir 'registry.pol'
                [System.IO.File]::WriteAllBytes($f, (ConvertTo-IgwtRegistryPolBytes -Entries @(Update-IgwtPolEntries -Entries @() -Ops $ops))); $files.Add($f)
            }
            if ($c.Security.Count) {
                $dir = Join-Path $gpo 'Machine\microsoft\windows nt\SecEdit'; $null = New-Item -ItemType Directory -Path $dir -Force
                $f = Join-Path $dir 'GptTmpl.inf'; Write-IgwtSecurityInfFile -Path $f -Sections $c.Security -WhatIf:$false; $files.Add($f)
            }
            if (@($c.Audit).Count) {
                $dir = Join-Path $gpo 'Machine\microsoft\windows nt\Audit'; $null = New-Item -ItemType Directory -Path $dir -Force
                $f = Join-Path $dir 'audit.csv'; [System.IO.File]::WriteAllText($f, (ConvertTo-IgwtAuditCsv -Rows @($c.Audit) -MachineName ''), $utf); $files.Add($f)
            }
            $readme = Join-Path $Path 'README.txt'
            $lines = New-Object System.Collections.Generic.List[string]
            $lines.Add("$($plan.Preset.name) ($name), exported by iG Windows Tuner $script:IgwtVersion.")
            $lines.Add('')
            $lines.Add('Apply on another PC from an elevated prompt with LGPO.exe (Microsoft Security Compliance Toolkit), one file at a time:')
            foreach ($cls in 'Machine', 'User') { if (@($c.$cls).Count) { $lines.Add("  LGPO.exe /$(if ($cls -eq 'Machine') { 'm' } else { 'u' }) `"$guid\DomainSysvol\GPO\$cls\registry.pol`"") } }
            if ($c.Security.Count) { $lines.Add("  LGPO.exe /s `"$guid\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf`"") }
            if (@($c.Audit).Count) { $lines.Add("  LGPO.exe /a `"$guid\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv`"") }
            $lines.Add('Check the switches with LGPO.exe /? for your LGPO version. The folder uses the layout of a GPO backup but has no Backup.xml or bkupInfo.xml, so it is not a GPMC backup and GPMC cannot import it; in a domain, create a GPO and import these files into it.')
            if ($c.Skipped.Count) { $lines.Add(''); $lines.Add('Not included (unavailable on the exporting PC):'); foreach ($k in $c.Skipped) { $lines.Add("  - $k") } }
            [System.IO.File]::WriteAllText($readme, (($lines -join "`r`n") + "`r`n"), $utf);            $files.Add($readme)
        }
        'Reg' {
            $f = Join-Path $Path "$name.reg"
            [System.IO.File]::WriteAllText($f, (ConvertTo-IgwtRegText -Machine @($c.Machine) -User @($c.User)), [System.Text.Encoding]::Unicode); $files.Add($f)
        }
        'Script' {
            $inf = ''
            if ($c.Security.Count) { $inf = "$name.inf"; $f = Join-Path $Path $inf; Write-IgwtSecurityInfFile -Path $f -Sections $c.Security -WhatIf:$false; $files.Add($f) }
            $f = Join-Path $Path "$name.ps1"
            [System.IO.File]::WriteAllText($f, (ConvertTo-IgwtPolicyScriptText -Content $c -Name "$($plan.Preset.name) ($name)" -InfName $inf), $utf); $files.Add($f)
        }
        'Json' {
            $f = Join-Path $Path "$name.json"
            $doc = [ordered]@{ kind = 'igwt-policy-preset-export'; exported = (Get-Date).ToString('o'); preset = $plan.Preset; machineOps = @($c.Machine); userOps = @($c.User); skipped = @($c.Skipped) }
            [System.IO.File]::WriteAllText($f, (ConvertTo-IgwtJson -InputObject $doc), $utf); $files.Add($f)
        }
    }
    return [pscustomobject]@{ Format = $Format; Files = $files.ToArray(); Skipped = @($c.Skipped) }
}

#endregion
