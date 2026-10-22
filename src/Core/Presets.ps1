# Presets.ps1
# Presets 2.0 beyond the built-in intent presets: the shared preset rules, custom presets (save,
# duplicate, import and export with a SHA256 integrity field), the drift report against the last
# applied preset, and Session Mode (temporary, snapshot-backed, crash-safe).

$script:IgwtPresetHashKeys = @('id', 'name', 'basedOn', 'tagline', 'hint', 'description', 'gaming', 'levelCeiling', 'antiCheatPolicy', 'include', 'exclude', 'guidance')
$script:IgwtSessionPowerPlans = @('power.ultimate-plan', 'power.high-performance-plan')

#region Preset rules

function Test-IgwtPresetDefinition {
    <#
    .SYNOPSIS
        The preset rules (texts, level ceiling, never Lab or Risk Zone, gaming presets anti-cheat
        safe only, Balanced Tier A only, no conflicting pairs). Adds error strings to Errors.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [Parameter(Mandatory = $true)][hashtable]$CatalogIndex, [string[]]$RejectedIds = @(),
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    $p = $Preset
    $presetId = [string]$p.id
    $label = "preset ${presetId}"
    $ids = $CatalogIndex
    Test-IgwtItemText -Item $p -Label $label -Errors $Errors
    $ceiling = Get-IgwtLevelRank -Level ([string]$p.levelCeiling)
    if ($ceiling -lt 0 -or [string]$p.levelCeiling -eq 'Lab') { $Errors.Add("${label}: levelCeiling must be Standard, Advanced or Expert (Lab items are never in presets).") }
    if ($script:IgwtAntiCheatPolicies -notcontains [string]$p.antiCheatPolicy) { $Errors.Add("${label}: antiCheatPolicy must be safeOnly or any.") }
    if ($p.gaming -and [string]$p.antiCheatPolicy -ne 'safeOnly') { $Errors.Add("${label}: gaming presets must use antiCheatPolicy safeOnly.") }
    foreach ($x in @($p.exclude | Where-Object { $_ })) {
        if (-not $ids.ContainsKey([string]$x)) { $Errors.Add("${label}: exclude lists unknown tweak '$x'.") }
        if (@($p.include) -contains $x) { $Errors.Add("${label}: '$x' is both included and excluded.") }
    }
    $members = @($p.include | Where-Object { $_ })
    foreach ($m in $members) {
        if (-not $ids.ContainsKey([string]$m)) { $Errors.Add("${label}: unknown tweak '$m'."); continue }
        $t = $ids[[string]$m]
        if ($RejectedIds -contains [string]$m) { $Errors.Add("${label}: contains rejected item '$m'.") }
        if ([string]$t.evidence.tier -eq 'R') { $Errors.Add("${label}: contains Risk Zone item '$m' (rejected tweaks are never in presets).") }
        if ([string]$t.level -eq 'Lab') { $Errors.Add("${label}: contains Lab item '$m' (Lab items are never in presets).") }
        elseif ($ceiling -ge 0 -and (Get-IgwtLevelRank -Level ([string]$t.level)) -gt $ceiling) { $Errors.Add("${label}: contains $($t.level) item '$m' above its level ceiling $($p.levelCeiling).") }
        if ([string]$p.antiCheatPolicy -eq 'safeOnly' -and -not $t.antiCheatSafe) { $Errors.Add("${label}: contains '$m', which is not anti-cheat safe.") }
        foreach ($c in @($t.conflictsWith)) { if ($members -contains [string]$c) { $Errors.Add("${label}: contains conflicting '$m' and '$c'.") } }
        if ($presetId -eq 'balanced' -and [string]$t.evidence.tier -ne 'A') { $Errors.Add("preset balanced: contains Tier B item '$m' (Balanced is Tier A only).") }
        if ([string]$t.group -eq 'Session Mode' -and -not $p.session) { $Errors.Add("${label}: '$m' is a Session Mode item; it belongs only to the session preset.") }
    }
    if (@($members | Select-Object -Unique).Count -ne $members.Count) { $Errors.Add("${label}: duplicate entries.") }
    if ($p.session) {
        if ([string]$p.sessionPowerPlan -notin 'highestAllowed', 'none') { $Errors.Add("${label}: sessionPowerPlan must be highestAllowed or none.") }
        foreach ($n in @($p.closeApps | Where-Object { $_ })) { if ([string]$n -notmatch '^[\w\. \-]+$') { $Errors.Add("${label}: closeApps entry '$n' is not a process name.") } }
    }
    if ($p.custom -and $p.session) { $Errors.Add("${label}: Session Mode cannot be a custom preset.") }
}

function Get-IgwtPresetCatalogIndex {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $ids = @{}
    foreach ($t in @(Get-IgwtCatalog)) { $ids[[string]$t.id] = $t }
    return $ids
}

#endregion

#region Custom presets

function Get-IgwtPresetHash {
    <# .SYNOPSIS SHA256 over the preset's defining fields (stable order), used as the integrity field of custom and exported presets. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Preset)
    $o = [ordered]@{}
    foreach ($k in $script:IgwtPresetHashKeys) {
        $v = $null
        if ($Preset -is [System.Collections.IDictionary]) { if ($Preset.Contains($k)) { $v = $Preset[$k] } }
        elseif ($null -ne $Preset.PSObject.Properties[$k]) { $v = $Preset.$k }
        if ($k -in 'include', 'exclude', 'guidance') { $v = @(@($v) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }
        elseif ($k -eq 'gaming') { $v = [bool]$v }
        else { $v = [string]$v }
        $o[$k] = $v
    }
    $text = ConvertTo-Json -InputObject $o -Depth 5 -Compress
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function ConvertTo-IgwtPresetSlug {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Name)
    $s = ($Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if (-not $s) { throw "'$Name' is not a usable preset name (use letters or digits)." }
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40).Trim('-') }
    return $s
}

function Get-IgwtCustomPresets {
    <#
    .SYNOPSIS
        Custom presets from the Presets data folder. Files whose SHA256 field does not match are
        skipped (and logged), so a changed file is never applied.
    #>
    [CmdletBinding()]
    param()
    $folder = Get-IgwtDataPath -Kind Presets
    if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { return @() }
    $index = $null; $rej = @()
    foreach ($f in (Get-ChildItem -LiteralPath $folder -Filter 'custom-*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $doc = Read-IgwtJsonFile -Path $f.FullName
            if ($null -eq $doc.PSObject.Properties['include'] -or $null -ne $doc.PSObject.Properties['tweaks']) { throw 'it has no include list (or a legacy tweaks list)' }
            if ((Get-IgwtPresetHash -Preset $doc) -ne [string]$doc.sha256) { throw 'its SHA256 field does not match the content' }
            if ([string]$doc.id -notlike 'custom-*') { throw 'its id does not start with custom-' }
            $p = ConvertTo-IgwtNormalizedPreset -Preset $doc -SourceFile $f.FullName -SourceSchema (Get-IgwtFileSchemaVersion -Document $doc)
            $p | Add-Member -NotePropertyName custom -NotePropertyValue $true -Force
            if (-not $index) { $index = Get-IgwtPresetCatalogIndex; $rej = @(Get-IgwtRejectedTweaks | ForEach-Object { [string]$_.id }) }
            $errs = New-Object System.Collections.Generic.List[string]
            Test-IgwtPresetDefinition -Preset $p -CatalogIndex $index -RejectedIds $rej -Errors $errs
            if ($errs.Count) { throw "it breaks the preset rules: $($errs -join ' ')" }
            $p
        } catch { Write-IgwtLog -Level Warn -Message "Custom preset $($f.Name) skipped: $($_.Exception.Message)" }
    }
}

function New-IgwtCustomPresetDocument {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory document only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)]$Base, [string[]]$Include, [string[]]$Exclude, [string]$Description)
    $slug = ConvertTo-IgwtPresetSlug -Name $Name
    $n = @($Include).Count
    $doc = [ordered]@{
        schemaVersion = 2; id = "custom-$slug"; name = $Name; order = 100; tagline = "Custom, based on $($Base.name)"
        hint = $(if ("Custom preset based on $($Base.name): $n item(s), resolved through the hardware overlays like every preset.".Length -le 140) { "Custom preset based on $($Base.name): $n item(s), resolved through the hardware overlays like every preset." } else { "Custom preset: $n item(s), resolved through the hardware overlays." })
        description = $(if ($Description -and $Description.Length -ge 40) { $Description } else { "Your preset, based on $($Base.name) ($($Base.id)) with your additions and removals. It follows the same rules as the built-in presets: level ceiling $($Base.levelCeiling), $(if ($Base.gaming) { 'anti-cheat safe items only' } else { 'no Lab or Risk Zone items' }), and hardware overlays still apply. $Description".Trim() })
        gaming = [bool]$Base.gaming; levelCeiling = [string]$Base.levelCeiling; antiCheatPolicy = [string]$Base.antiCheatPolicy
        include = @($Include); exclude = @($Exclude); guidance = @($Base.guidance | Where-Object { $_ })
        custom = $true; basedOn = [string]$(if ($Base.PSObject.Properties['basedOn'] -and $Base.basedOn) { $Base.basedOn } else { $Base.id }); created = (Get-Date).ToString('o')
    }
    $doc.sha256 = Get-IgwtPresetHash -Preset $doc
    return $doc
}

function Write-IgwtCustomPresetFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Document, [switch]$Force)
    $errors = New-Object System.Collections.Generic.List[string]
    $rejected = @(Get-IgwtRejectedTweaks | ForEach-Object { [string]$_.id })
    Test-IgwtPresetDefinition -Preset ([pscustomobject]$Document) -CatalogIndex (Get-IgwtPresetCatalogIndex) -RejectedIds $rejected -Errors $errors
    if ($errors.Count) { throw "The preset was not saved: $($errors -join ' ')" }
    if (@(Get-IgwtPreset -Builtin | Where-Object { $_.id -eq $Document.id -or [string]$_.name -eq [string]$Document.name }).Count) { throw "'$($Document.name)' is the name of a built-in preset; choose another name." }
    $folder = Get-IgwtDataPath -Kind Presets
    $file = Join-Path $folder ("{0}.json" -f $Document.id)
    if ((Test-Path -LiteralPath $file) -and -not $Force) { throw "A custom preset '$($Document.name)' already exists. Use another name or -Force to replace it." }
    if (-not $PSCmdlet.ShouldProcess($file, 'Save custom preset')) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    if (-not (Test-Path -LiteralPath $folder)) { $null = New-Item -ItemType Directory -Path $folder -Force }
    [System.IO.File]::WriteAllText($file, (ConvertTo-IgwtJson -InputObject $Document), (New-Object System.Text.UTF8Encoding($false)))
    Write-IgwtLog -Message "Custom preset saved: $($Document.id) ($(@($Document.include).Count) items) -> $file"
    return (Get-IgwtPreset -Name ([string]$Document.id))
}

function Save-IgwtCustomPreset {
    <#
    .SYNOPSIS
        Saves a custom preset: a built-in or custom preset plus your additions and removals. The
        preset rules are checked before anything is written.
    .PARAMETER BasedOn
        The preset to start from (id or name).
    .PARAMETER AddIds
        Items to add.
    .PARAMETER RemoveIds
        Items to leave out (also kept out when a hardware overlay would add them).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [string]$BasedOn = 'balanced', [string[]]$AddIds = @(), [string[]]$RemoveIds = @(), [string]$Description, [switch]$Force)
    $base = Get-IgwtPreset -Name $BasedOn
    if ($base.PSObject.Properties['session'] -and $base.session) { throw 'Session Mode is temporary and cannot be the base of a custom preset.' }
    $add = @($AddIds | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $remove = @($RemoveIds | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $include = @(@($base.tweaks) + $add | Where-Object { $remove -notcontains $_ } | Select-Object -Unique)
    $exclude = @(@($base.exclude) + $remove | Where-Object { $_ -and $add -notcontains $_ } | Select-Object -Unique)
    $doc = New-IgwtCustomPresetDocument -Name $Name -Base $base -Include $include -Exclude $exclude -Description $Description
    return (Write-IgwtCustomPresetFile -Document $doc -Force:$Force -WhatIf:$WhatIfPreference)
}

function Copy-IgwtPreset {
    <# .SYNOPSIS Duplicates a preset (built-in or custom) as a new custom preset. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$NewName)
    return (Save-IgwtCustomPreset -Name $NewName -BasedOn $Name -WhatIf:$WhatIfPreference)
}

function Remove-IgwtCustomPreset {
    <# .SYNOPSIS Deletes a custom preset file (built-in presets cannot be removed). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name)
    $p = Get-IgwtPreset -Name $Name
    if (-not ($p.PSObject.Properties['custom'] -and $p.custom)) { throw "'$($p.name)' is a built-in preset and cannot be removed." }
    if ($PSCmdlet.ShouldProcess([string]$p.sourceFile, 'Delete custom preset')) {
        Remove-Item -LiteralPath ([string]$p.sourceFile) -Force
        Write-IgwtLog -Message "Custom preset removed: $($p.id)"
    }
}

function Export-IgwtPreset {
    <# .SYNOPSIS Writes a preset (built-in or custom) to a JSON file with a SHA256 integrity field. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Path)
    $p = Get-IgwtPreset -Name $Name
    if ($p.PSObject.Properties['session'] -and $p.session) { throw 'Session Mode is part of iG Windows Tuner and is not exported.' }
    $doc = [ordered]@{ schemaVersion = 2; format = 'igwt-preset' }
    foreach ($k in $script:IgwtPresetHashKeys) {
        if ($k -eq 'include') { $doc[$k] = @($p.tweaks) }
        elseif ($null -ne $p.PSObject.Properties[$k]) { $doc[$k] = $p.$k }
    }
    if (-not $doc.Contains('basedOn') -or -not $doc.basedOn) { $doc.basedOn = [string]$p.id }
    $doc.exported = (Get-Date).ToString('o')
    $doc.sha256 = Get-IgwtPresetHash -Preset $doc
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export preset')) { return $null }
    [System.IO.File]::WriteAllText($Path, (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

function Import-IgwtPreset {
    <#
    .SYNOPSIS
        Imports a preset file as a custom preset after checking its SHA256 field and the preset
        rules. The imported preset gets a custom- id, so it never replaces a built-in preset.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [string]$Name, [switch]$Force)
    $doc = Read-IgwtJsonFile -Path $Path
    if (-not $doc.PSObject.Properties['sha256'] -or -not $doc.sha256) { throw "'$Path' has no SHA256 integrity field; only presets exported by iG Windows Tuner can be imported." }
    if ((Get-IgwtPresetHash -Preset $doc) -ne [string]$doc.sha256) { throw "The preset in '$Path' does not match its SHA256 field; the file was changed or damaged." }
    if (@($doc.include).Count -eq 0) { throw "'$Path' contains no items." }
    $label = $(if ($Name) { $Name } else { [string]$doc.name })
    $base = $null
    try { $base = Get-IgwtPreset -Name ([string]$doc.basedOn) } catch { $base = $null }
    if (-not $base) { $base = [pscustomobject]@{ id = [string]$doc.basedOn; name = [string]$doc.basedOn; gaming = [bool]$doc.gaming; levelCeiling = [string]$doc.levelCeiling; antiCheatPolicy = [string]$doc.antiCheatPolicy; guidance = @($doc.guidance) } }
    $base = [pscustomobject]@{ id = [string]$base.id; name = [string]$base.name; gaming = [bool]$doc.gaming; levelCeiling = [string]$doc.levelCeiling; antiCheatPolicy = [string]$doc.antiCheatPolicy; guidance = @($doc.guidance | Where-Object { $_ }); basedOn = [string]$doc.basedOn }
    $new = New-IgwtCustomPresetDocument -Name $label -Base $base -Include @($doc.include) -Exclude @($doc.exclude) -Description ([string]$doc.description)
    return (Write-IgwtCustomPresetFile -Document $new -Force:$Force -WhatIf:$WhatIfPreference)
}

#endregion

#region Drift

function Save-IgwtPresetRecord {
    <# .SYNOPSIS Records the last applied preset (id, item ids, time, snapshot) for the drift report. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Preset, [Parameter(Mandatory = $true)][string[]]$Id, [string]$Snapshot)
    $p = $null
    try { $p = Get-IgwtPreset -Name $Preset } catch { return }
    if ($p.PSObject.Properties['session'] -and $p.session) { return }
    $state = Get-IgwtDataPath -Kind State
    if (-not (Test-Path -LiteralPath $state)) { $null = New-Item -ItemType Directory -Path $state -Force -WhatIf:$false }
    # Record only items of the preset's own selection (never extra staged or Expert/Lab/Risk Zone items).
    $selection = @()
    try { $selection = @((Resolve-IgwtPresetSelection -Preset $p).Ids) } catch { $selection = @($p.tweaks) }
    $cat = Get-IgwtPresetCatalogIndex
    $ids = @($selection | Where-Object { $t = $cat[[string]$_]; $t -and -not $t.expert -and [string]$t.evidence.tier -ne 'R' })
    $doc = [ordered]@{ preset = [string]$p.id; name = [string]$p.name; ids = $ids; applied = (Get-Date).ToString('o'); snapshot = $Snapshot }
    if ($PSCmdlet.ShouldProcess('last applied preset', 'Record')) {
        [System.IO.File]::WriteAllText((Join-Path $state 'last-preset.json'), (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
    }
}

function Get-IgwtPresetRecord {
    <# .SYNOPSIS The last applied preset record, or $null. #>
    [CmdletBinding()]
    param()
    $file = Join-Path (Get-IgwtDataPath -Kind State) 'last-preset.json'
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    try { return (Read-IgwtJsonFile -Path $file) } catch { return $null }
}

function Get-IgwtPresetDrift {
    <#
    .SYNOPSIS
        Drift report: which items of the last applied preset (or of -Preset, resolved for this
        hardware) are no longer in their preset state. Read-only.
    #>
    [CmdletBinding()]
    param([string]$Preset, $Context)
    $record = $null
    if (-not $Preset) {
        $record = Get-IgwtPresetRecord
        if (-not $record) { return [pscustomobject]@{ HasPreset = $false; Message = 'No preset has been applied with iG Windows Tuner yet.' } }
        $Preset = [string]$record.preset
    }
    $p = Get-IgwtPreset -Name $Preset
    if (-not $Context) { $Context = New-IgwtContext }
    $ids = $(if ($record) { @($record.ids) } else { @((Resolve-IgwtPresetSelection -Preset $p -Tags @($Context.HardwareTags)).Ids) })
    $states = @(Get-IgwtAllTweakStates -Id $ids -Context $Context)
    $drifted = @($states | Where-Object { $_.State -in 'Off', 'Partial' } | ForEach-Object { $s = $_; $t = Get-IgwtTweak -Id $s.Id; [pscustomobject]@{ Id = $s.Id; Name = [string]$t.name; State = $s.State } })
    $inPlace = @($states | Where-Object { $_.State -eq 'On' }).Count
    $msg = $(if ($drifted.Count -eq 0) { "All $inPlace applicable item(s) of $($p.name) are in place." }
        elseif ($record) { "$($drifted.Count) setting(s) changed since you applied $($p.name): re-apply the preset, or adopt the current state as a custom preset." }
        else { "$($drifted.Count) setting(s) differ from $($p.name): apply the preset, or save the current state as a custom preset." })
    [pscustomobject]@{
        HasPreset = $true; Preset = [string]$p.id; Name = [string]$p.name; Applied = $(if ($record) { [string]$record.applied } else { '' }); FromRecord = [bool]$record
        Total = $ids.Count; InPlace = $inPlace; Drifted = $drifted; NotApplicable = @($states | Where-Object { $_.State -in 'NotApplicable', 'ManagedByPolicy', 'Unknown' } | ForEach-Object { $_.Id }); Message = $msg
    }
}

function Save-IgwtDriftAsPreset {
    <# .SYNOPSIS "Adopt as custom": saves the preset minus its drifted items as a custom preset. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Preset, [switch]$Force)
    $d = Get-IgwtPresetDrift -Preset $Preset
    if (-not $d.HasPreset) { throw $d.Message }
    return (Save-IgwtCustomPreset -Name $Name -BasedOn $d.Preset -RemoveIds @($d.Drifted | ForEach-Object { $_.Id }) -Description "Adopted from $($d.Name) on $((Get-Date).ToString('yyyy-MM-dd')): the $($d.Drifted.Count) item(s) you changed afterwards are left out." -Force:$Force -WhatIf:$WhatIfPreference)
}

#endregion

#region Session Mode

function Get-IgwtSessionFile {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Get-IgwtDataPath -Kind State) 'session.json')
}

function Get-IgwtBootTime {
    <# .SYNOPSIS Last boot time (UTC), or $null when unreadable. #>
    [CmdletBinding()]
    param()
    try { return ([datetime](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime).ToUniversalTime() } catch { return $null }
}

function Get-IgwtSessionState {
    <#
    .SYNOPSIS
        Whether a Session Mode session is active, and whether it is stale: the app that started it
        is gone or Windows restarted since, so its settings should be restored. Read-only.
    #>
    [CmdletBinding()]
    param()
    $file = Get-IgwtSessionFile
    if (-not (Test-Path -LiteralPath $file)) { return [pscustomobject]@{ Active = $false; Stale = $false; Started = $null; Owner = ''; Snapshot = ''; Reason = '' } }
    $m = $null
    try { $m = Read-IgwtJsonFile -Path $file } catch { return [pscustomobject]@{ Active = $true; Stale = $true; Started = $null; Owner = ''; Snapshot = ''; Reason = 'The session record is unreadable.' } }
    $reason = ''
    $started = [datetime]::Parse([string]$m.started, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $boot = Get-IgwtBootTime
    if ($boot -and $boot -gt $started) { $reason = 'Windows restarted after the session started.' }
    elseif ([string]$m.state -eq 'starting' -and [int]$m.pid -ne $PID) { $reason = 'The session did not finish starting (the app or PC stopped).' }
    elseif ([string]$m.owner -eq 'gui') {
        $proc = Get-Process -Id ([int]$m.pid) -ErrorAction SilentlyContinue
        $alive = $false
        if ($proc) { try { $alive = ($proc.StartTime.ToUniversalTime().ToString('o') -eq [string]$m.processStart) } catch { $alive = $true } }
        if (-not $alive) { $reason = 'iG Windows Tuner was closed without ending the session.' }
    }
    [pscustomobject]@{ Active = $true; Stale = [bool]$reason; Started = $started; Owner = [string]$m.owner; Snapshot = [string]$m.snapshot; Reason = $reason; PowerPlan = [string]$m.powerPlan; OwnerPid = [int]$m.pid }
}

function Get-IgwtSessionPlan {
    <#
    .SYNOPSIS
        The items a session would change on this PC: the session preset items plus the highest
        power plan the hardware overlays allow, and the listed background apps that are running. Read-only.
    #>
    [CmdletBinding()]
    param($Context)
    if (-not $Context) { $Context = New-IgwtContext }
    $p = @(Get-IgwtPreset -Builtin | Where-Object { $_.PSObject.Properties['session'] -and $_.session }) | Select-Object -First 1
    if (-not $p) { throw 'The Session Mode preset is missing.' }
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($p.tweaks)) { $ids.Add([string]$i) }
    $plan = ''
    if ([string]$p.sessionPowerPlan -eq 'highestAllowed') {
        foreach ($c in $script:IgwtSessionPowerPlans) {
            $t = Get-IgwtTweak -Id $c
            if (-not (Get-IgwtHardwareBlock -Tweak $t -Tags @($Context.HardwareTags))) { $ids.Add($c); $plan = $c; break }
        }
    }
    [pscustomobject]@{ Preset = $p; Ids = $ids.ToArray(); PowerPlan = $plan; Apps = @(Get-IgwtSessionApps -Name @($p.closeApps)); AllowedApps = @($p.closeApps) }
}

function Get-IgwtSessionApps {
    <# .SYNOPSIS Running processes from the Session Mode close list (name, count, whether they have a window). Read-only. #>
    [CmdletBinding()]
    param([string[]]$Name = @())
    $want = @($Name | Where-Object { $_ })
    if ($want.Count -eq 0) { return @() }
    foreach ($g in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $want -contains $_.ProcessName } | Group-Object ProcessName)) {
        [pscustomobject]@{ Name = [string]$g.Name; Count = $g.Count; HasWindow = (@($g.Group | Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero }).Count -gt 0) }
    }
}

function Close-IgwtSessionApps {
    <#
    .SYNOPSIS
        Closes running apps from the Session Mode list after the user confirmed: windows get a
        normal close request; background apps without a window are stopped. Apps not on the list are refused.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string[]]$Name)
    $p = @(Get-IgwtPreset -Builtin | Where-Object { $_.PSObject.Properties['session'] -and $_.session }) | Select-Object -First 1
    $allowed = @($p.closeApps)
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($Name | Where-Object { $_ } | Select-Object -Unique)) {
        if ($allowed -notcontains $n) { $results.Add([pscustomobject]@{ Name = $n; Result = 'Refused'; Message = 'Not on the Session Mode close list.' }); continue }
        foreach ($proc in @(Get-Process -Name $n -ErrorAction SilentlyContinue)) {
            if (-not $PSCmdlet.ShouldProcess("$n ($($proc.Id))", 'Close')) { continue }
            try {
                if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $null = $proc.CloseMainWindow(); $how = 'close request sent' }
                else { Stop-Process -Id $proc.Id -ErrorAction Stop; $how = 'stopped' }
                $results.Add([pscustomobject]@{ Name = $n; Result = 'Closed'; Message = $how })
            } catch { $results.Add([pscustomobject]@{ Name = $n; Result = 'Failed'; Message = $_.Exception.Message }) }
        }
    }
    foreach ($r in $results) { Write-IgwtLog -Message "Session Mode: $($r.Name) $($r.Result) $($r.Message)" }
    return $results.ToArray()
}

function Start-IgwtSession {
    <#
    .SYNOPSIS
        Starts Session Mode: applies the session items with a snapshot (operation 'Session'),
        records the session so it can be restored after a crash, and optionally closes listed apps.
    .PARAMETER CloseApps
        Names from the Session Mode list to close (only after the user confirmed them).
    .PARAMETER Owner
        gui (the session ends when the app closes) or cli (it lasts until Stop-IgwtSession or a restart).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]]$CloseApps = @(), [ValidateSet('gui', 'cli')][string]$Owner = 'cli', $Context, [scriptblock]$OnProgress)
    $st = Get-IgwtSessionState
    if ($st.Active) { throw "A session is already active (started $($st.Started.ToLocalTime().ToString('g'))). End it first$(if ($st.Stale) { "; $($st.Reason)" })." }
    if (-not $Context) { $Context = New-IgwtContext }
    $plan = Get-IgwtSessionPlan -Context $Context
    if (-not $PSCmdlet.ShouldProcess('Session Mode', "Start ($($plan.Ids -join ', '))")) { return $null }
    $proc = Get-Process -Id $PID
    $marker = [ordered]@{ state = 'starting'; started = (Get-Date).ToUniversalTime().ToString('o'); owner = $Owner; pid = $PID; processStart = $(try { $proc.StartTime.ToUniversalTime().ToString('o') } catch { '' }); snapshot = ''; powerPlan = $plan.PowerPlan; ids = @($plan.Ids) }
    $state = Get-IgwtDataPath -Kind State
    if (-not (Test-Path -LiteralPath $state)) { $null = New-Item -ItemType Directory -Path $state -Force -WhatIf:$false }
    [System.IO.File]::WriteAllText((Get-IgwtSessionFile), (ConvertTo-IgwtJson -InputObject $marker), (New-Object System.Text.UTF8Encoding($false)))
    $res = Invoke-IgwtApply -Id $plan.Ids -Operation 'Session' -SkipRestorePoint -Context $Context -OnProgress $OnProgress
    $marker.state = 'active'
    $marker.snapshot = [string]$res.Snapshot
    [System.IO.File]::WriteAllText((Get-IgwtSessionFile), (ConvertTo-IgwtJson -InputObject $marker), (New-Object System.Text.UTF8Encoding($false)))
    $closed = @()
    if (@($CloseApps).Count) { $closed = @(Close-IgwtSessionApps -Name $CloseApps) }
    Write-IgwtLog -Message "Session Mode started ($Owner): $(@($res.Results | Where-Object { $_.Result -eq 'Applied' }).Count) change(s). Snapshot: $($res.Snapshot)"
    return [pscustomobject]@{ Operation = 'Session'; Snapshot = $res.Snapshot; Results = $res.Results; PowerPlan = $plan.PowerPlan; Closed = $closed; Requires = $res.Requires }
}

function Stop-IgwtSession {
    <# .SYNOPSIS Ends Session Mode: restores every setting from the session snapshot and removes the session record. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([scriptblock]$OnProgress)
    $st = Get-IgwtSessionState
    if (-not $st.Active) { return [pscustomobject]@{ Operation = 'Revert'; Snapshot = $null; Results = @(); Requires = 'none'; Message = 'No session is active.' } }
    if (-not $PSCmdlet.ShouldProcess('Session Mode', 'End and restore settings')) { return $null }
    $res = [pscustomobject]@{ Operation = 'Revert'; Snapshot = $null; Results = @(); Requires = 'none' }
    $snapPath = $st.Snapshot
    if (-not $snapPath -and $st.Started) {
        # A start that was interrupted: use the newest Session snapshot written after it began.
        $cand = @(Get-IgwtSnapshotList | Where-Object { $_.Operation -eq 'Session' -and $_.Created -and ([datetime]$_.Created).ToUniversalTime() -ge $st.Started.AddSeconds(-5) }) | Select-Object -First 1
        if ($cand) { $snapPath = $cand.Path }
    }
    if ($snapPath -and (Test-Path -LiteralPath $snapPath)) { $res = Invoke-IgwtRevert -SnapshotPath $snapPath -OnProgress $OnProgress }
    # L5: keep the record when a restore failed, so it can be retried.
    if (@($res.Results | Where-Object { $_.Result -eq 'Failed' }).Count) {
        Write-IgwtLog -Level Warn -Message 'Session Mode: some settings could not be restored; the session record is kept so -Session Stop can retry.'
        return $res
    }
    Remove-Item -LiteralPath (Get-IgwtSessionFile) -Force -ErrorAction SilentlyContinue
    Write-IgwtLog -Message "Session Mode ended: $(@($res.Results | Where-Object { $_.Result -eq 'Reverted' }).Count) setting(s) restored."
    return $res
}

#endregion
