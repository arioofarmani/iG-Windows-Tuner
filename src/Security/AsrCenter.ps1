# AsrCenter.ps1
# ASR Center: every Microsoft Defender attack surface reduction rule (data\asr\rules.json) with its
# current mode, gamer-impact note, recommendation and exclusions, plus snapshot-backed changes:
#   - rule modes Not configured / Audit / Warn / Block (Add-/Remove-MpPreference). An explicit Off
#     (code 0) is never written: Not configured is the Windows default and cannot conflict with
#     policies. Warn is refused for rules that do not support it; server-only rules are not changed.
#   - global ASR-only exclusions (Add-/Remove-MpPreference -AttackSurfaceReductionOnlyExclusions)
#   - per-rule exclusions through the documented Group Policy registry settings
#     (...\Windows Defender Exploit Guard\ASR\ASROnlyPerRuleExclusions: value name = rule GUID,
#     data = paths separated by '>'), the only local method Microsoft documents for them.
# Antivirus scan exclusions are never read or written here. Every change writes a snapshot
# (operation 'ASR') first, so it can be reverted from Backups & Logs or with -Revert -Snapshot.

$script:IgwtAsrModeRank = @{ NotConfigured = 0; Off = 0; Audit = 1; Warn = 2; Block = 3 }
$script:IgwtAsrSettableCodes = @{ Audit = 2; Warn = 6; Block = 1 }
$script:IgwtAsrGuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$script:IgwtAsrPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
$script:IgwtAsrPerRuleKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyPerRuleExclusions'
$script:IgwtAsrPerRuleFlag = 'ExploitGuard_ASR_ASROnlyPerRuleExclusions'
$script:IgwtAsrMdmKey = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender'
# System environment variables Microsoft allows in ASR exclusions (user variables are not supported).
$script:IgwtAsrExclusionVariables = @('SystemDrive', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'ProgramData', 'CommonProgramFiles', 'CommonProgramFiles(x86)')
# Leaf extensions that make an exclusion a single program or script file rather than a folder.
$script:IgwtAsrFileExtensions = @('exe', 'dll', 'com', 'scr', 'sys', 'cpl', 'ocx', 'msi', 'ps1', 'psm1', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta', 'jar')

function Get-IgwtAsrCatalog {
    <# .SYNOPSIS Every ASR rule from data\asr\rules.json (cached), in display order. #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtAsrCatalogCache -and -not $Force) { return $script:IgwtAsrCatalogCache }
    $file = Join-Path (Get-IgwtDataFolder) 'asr\rules.json'
    $rules = @()
    if (Test-Path -LiteralPath $file) { $rules = @((Read-IgwtJsonFile -Path $file).rules | Where-Object { $_ } | Sort-Object { [int]$_.order }) }
    $script:IgwtAsrCatalogCache = $rules
    return $rules
}

function Get-IgwtAsrRuleDefinition {
    <# .SYNOPSIS One rule by GUID or key; throws for unknown rules. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Rule)
    $r = @(Get-IgwtAsrCatalog | Where-Object {
            [string]::Equals([string]$_.id, $Rule.Trim(), [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals([string]$_.key, $Rule.Trim(), [System.StringComparison]::OrdinalIgnoreCase)
        }) | Select-Object -First 1
    if (-not $r) { throw "Unknown ASR rule '$Rule'. Use a GUID or key from data\asr\rules.json (see -AsrStatus)." }
    return $r
}

function Get-IgwtAsrModeRank {
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$Mode)
    if ($Mode -and $script:IgwtAsrModeRank.ContainsKey($Mode)) { return [int]$script:IgwtAsrModeRank[$Mode] }
    return 0
}

function ConvertTo-IgwtAsrModeName {
    <# .SYNOPSIS Defender rule action code -> NotConfigured, Off, Block, Audit or Warn. #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Code)
    if ($null -eq $Code -or [string]$Code -eq '') { return 'NotConfigured' }
    switch ([int]$Code) { 0 { 'Off' } 1 { 'Block' } 2 { 'Audit' } 5 { 'NotConfigured' } 6 { 'Warn' } default { "Code $Code" } }
}

function Get-IgwtAsrAllowedModes {
    <# .SYNOPSIS Modes iG Windows Tuner may set for a rule: server-only rules none, no Warn where unsupported. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition)
    if ($Definition.serverOnly) { return @() }
    if (-not $Definition.supportsWarn) { return @('NotConfigured', 'Audit', 'Block') }
    return @('NotConfigured', 'Audit', 'Warn', 'Block')
}

function Test-IgwtAsrCatalog {
    <# .SYNOPSIS Validates data\asr\rules.json and the asrRule actions of the tweak catalog. Returns error strings. #>
    [CmdletBinding()]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $file = Join-Path (Get-IgwtDataFolder) 'asr\rules.json'
    if (-not (Test-Path -LiteralPath $file)) { $errors.Add('asr\rules.json: missing (ASR Center rule catalog).'); return $errors.ToArray() }
    $doc = Read-IgwtJsonFile -Path $file
    if ((Get-IgwtFileSchemaVersion -Document $doc) -lt $script:IgwtSchemaVersion) { $errors.Add('asr\rules.json: schemaVersion must be 2.') }
    $seenIds = @{}; $seenKeys = @{}
    foreach ($r in @(Get-IgwtAsrCatalog -Force)) {
        $label = "ASR rule '$($r.key)'"
        $id = ([string]$r.id).ToLowerInvariant()
        if ($id -notmatch $script:IgwtAsrGuidPattern) { $errors.Add("${label}: id must be the rule GUID.") }
        if ($seenIds.ContainsKey($id)) { $errors.Add("${label}: duplicate GUID $id.") } else { $seenIds[$id] = $true }
        if ([string]$r.key -notmatch '^[a-z0-9]+(-[a-z0-9]+)*$') { $errors.Add("${label}: key must be lower-case words joined by hyphens.") }
        if ($seenKeys.ContainsKey([string]$r.key)) { $errors.Add("${label}: duplicate key.") } else { $seenKeys[[string]$r.key] = $true }
        if (-not $r.name) { $errors.Add("${label}: missing 'name'.") }
        Test-IgwtItemText -Item $r -Label $label -Errors $errors
        $gi = ([string]$r.gamerImpact).Trim()
        if ($gi.Length -lt 20) { $errors.Add("${label}: needs a gamerImpact note (what it means for games, launchers and mods).") }
        elseif ($gi.Length -gt 200) { $errors.Add("${label}: gamerImpact is $($gi.Length) characters (max 200).") }
        if ([string]$r.gamerImpactLevel -notin 'none', 'low', 'medium', 'high') { $errors.Add("${label}: gamerImpactLevel must be none, low, medium or high.") }
        if ([string]$r.category -notin 'standard', 'other') { $errors.Add("${label}: category must be standard or other.") }
        foreach ($b in 'supportsWarn', 'requiresCloud', 'serverOnly') {
            if ($null -eq $r.PSObject.Properties[$b] -or $r.$b -isnot [bool]) { $errors.Add("${label}: '$b' must be true or false.") }
        }
        $rec = [string]$r.recommendedMode
        if ($rec -notin 'NotConfigured', 'Audit', 'Warn', 'Block') { $errors.Add("${label}: recommendedMode must be NotConfigured, Audit, Warn or Block.") }
        if ($rec -eq 'Warn' -and -not $r.supportsWarn) { $errors.Add("${label}: recommends Warn, which the rule does not support.") }
        if ($r.serverOnly -and $rec -ne 'NotConfigured') { $errors.Add("${label}: server-only rules must recommend NotConfigured.") }
        if ([string]$r.category -eq 'standard' -and $rec -ne 'Block') { $errors.Add("${label}: standard protection rules are recommended in Block (Microsoft guidance).") }
        if ([string]$r.gamerImpactLevel -in 'medium', 'high' -and $rec -eq 'Block') { $errors.Add("${label}: rules with medium or high gamer impact may not be recommended in Block (audit first).") }
        $sources = @($r.sources | Where-Object { $_ })
        if ($sources.Count -eq 0) { $errors.Add("${label}: needs at least one source.") }
        foreach ($s in $sources) { if ([string]$s -notmatch '^https://') { $errors.Add("${label}: source '$s' must be an https URL.") } }
    }
    foreach ($t in @(Get-IgwtCatalog)) {
        foreach ($a in @($t.actions | Where-Object { $_ -and [string]$_.type -eq 'asrRule' })) {
            $def = @(Get-IgwtAsrCatalog | Where-Object { [string]::Equals([string]$_.id, [string]$a.id, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
            if (-not $def) { $errors.Add("$($t.id): ASR rule $($a.id) is not in asr\rules.json."); continue }
            if ([string]$a.on -eq 'Warn' -and -not $def.supportsWarn) { $errors.Add("$($t.id): ASR rule '$($def.key)' does not support Warn.") }
            if ($def.serverOnly) { $errors.Add("$($t.id): ASR rule '$($def.key)' is server-only and may not be set by a tweak.") }
        }
    }
    return $errors.ToArray()
}

function ConvertFrom-IgwtAsrExclusionList {
    <# .SYNOPSIS Per-rule exclusion data ('path1>path2') -> paths. #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if (-not $Value) { return @() }
    return @($Value.Split([char]'>') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-IgwtAsrRegistryValueMap {
    <# .SYNOPSIS Values of one registry key as name -> data (empty when the key is missing or unreadable). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $map = @{}
    try {
        $key = Get-Item -LiteralPath (Resolve-IgwtRegistryPath $Path) -ErrorAction Stop
        foreach ($n in $key.GetValueNames()) { if ($n) { $map[$n] = $key.GetValue($n) } }
    } catch { Write-Verbose "Registry key not readable: $Path" }
    return $map
}

function Get-IgwtAsrPolicyModes {
    <#
    .SYNOPSIS
        Rule modes set by Group Policy (ASR\Rules) or MDM (Policy CSP). Both override local settings
        at startup, so the ASR Center shows them and does not change those rules. Read-only.
    #>
    [CmdletBinding()]
    param()
    $map = @{}
    $gp = Get-IgwtAsrRegistryValueMap -Path "$script:IgwtAsrPolicyKey\Rules"
    foreach ($n in $gp.Keys) {
        $code = 0
        if ($n -match $script:IgwtAsrGuidPattern -and [int]::TryParse(([string]$gp[$n]).Trim(), [ref]$code)) { $map[$n.ToLowerInvariant()] = [pscustomobject]@{ Source = 'GroupPolicy'; Code = $code } }
    }
    try {
        $mdm = Get-IgwtRegistryValue -Path $script:IgwtAsrMdmKey -Name 'AttackSurfaceReductionRules'
        if ($mdm.Exists -and $mdm.Value) {
            foreach ($pair in ([string]$mdm.Value -split '\|')) {
                $kv = $pair.Split([char]'=')
                $code = 0
                if ($kv.Count -eq 2 -and $kv[0].Trim() -match $script:IgwtAsrGuidPattern -and [int]::TryParse($kv[1].Trim(), [ref]$code)) {
                    $id = $kv[0].Trim().ToLowerInvariant()
                    if (-not $map.ContainsKey($id)) { $map[$id] = [pscustomobject]@{ Source = 'MDM'; Code = $code } }   # Group Policy wins by default
                }
            }
        }
    } catch { Write-Verbose 'MDM ASR policy not readable.' }
    return $map
}

function Get-IgwtAsrLocalModes {
    <# .SYNOPSIS Rule GUID (lower case) -> action code, as Get-MpPreference reports it. #>
    [CmdletBinding()]
    param()
    $pref = Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }
    $map = @{}
    $ids = @($pref.AttackSurfaceReductionRules_Ids)
    $acts = @($pref.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ([string]$ids[$i] -match $script:IgwtAsrGuidPattern -and $i -lt $acts.Count) { $map[([string]$ids[$i]).ToLowerInvariant()] = [int]$acts[$i] }
    }
    return $map
}

function Get-IgwtAsrRuleExclusionMap {
    <# .SYNOPSIS Per-rule exclusions from the Group Policy registry settings: rule GUID (lower case) -> paths. #>
    [CmdletBinding()]
    param()
    $map = @{}
    $values = Get-IgwtAsrRegistryValueMap -Path $script:IgwtAsrPerRuleKey
    foreach ($n in $values.Keys) {
        if ($n -match $script:IgwtAsrGuidPattern) { $map[$n.ToLowerInvariant()] = @(ConvertFrom-IgwtAsrExclusionList -Value ([string]$values[$n])) }
    }
    return $map
}

function Test-IgwtMpListReadable {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Value)
    $items = @($Value | Where-Object { $null -ne $_ })
    return -not ($items.Count -ge 1 -and [string]$items[0] -like 'N/A*')
}

function Get-IgwtAsrGlobalExclusions {
    <# .SYNOPSIS Global ASR-only exclusions as Defender reports them (reading them needs administrator rights). #>
    [CmdletBinding()]
    param()
    $pref = Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }
    $raw = $pref.AttackSurfaceReductionOnlyExclusions
    if (-not (Test-IgwtMpListReadable -Value $raw)) { return [pscustomobject]@{ Readable = $false; Paths = @(); Note = 'Administrator rights are needed to read exclusions.' } }
    return [pscustomobject]@{ Readable = $true; Paths = @($raw | Where-Object { $_ } | ForEach-Object { [string]$_ }); Note = '' }
}

function Get-IgwtAsrEffectiveRuleExclusions {
    <#
    .SYNOPSIS
        Per-rule exclusions as Defender itself reports them (Get-MpPreference, administrator only),
        used to confirm that the policy values were picked up. $null when not readable.
    #>
    [CmdletBinding()]
    param()
    $pref = Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }
    if ($null -eq $pref.PSObject.Properties['AttackSurfaceReductionRules_RuleSpecificExclusions_Id']) { return $null }
    $ids = $pref.AttackSurfaceReductionRules_RuleSpecificExclusions_Id
    $values = $pref.AttackSurfaceReductionRules_RuleSpecificExclusions
    if (-not (Test-IgwtMpListReadable -Value $ids) -or -not (Test-IgwtMpListReadable -Value $values)) { return $null }
    $map = @{}
    $idList = @($ids | Where-Object { $null -ne $_ }); $valueList = @($values | Where-Object { $null -ne $_ })
    for ($i = 0; $i -lt $idList.Count; $i++) {
        $id = ([string]$idList[$i]).ToLowerInvariant()
        $text = $(if ($i -lt $valueList.Count) { [string]$valueList[$i] } else { '' })
        if ($map.ContainsKey($id)) { $map[$id] = "$($map[$id])>$text" } else { $map[$id] = $text }
    }
    return $map
}

function Get-IgwtAsrStatus {
    <#
    .SYNOPSIS
        ASR Center view (read-only): every rule with its mode, where the mode comes from (local,
        Group Policy or MDM), the recommendation, gamer impact and exclusions.
    #>
    [CmdletBinding()]
    param()
    $err = ''
    $local = @{}; $cloud = $null; $tamper = $null
    try {
        $local = Get-IgwtAsrLocalModes
        $pref = Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop }
        $cloud = ([int]$pref.MAPSReporting -gt 0)
    } catch { $err = "Defender preferences unavailable: $($_.Exception.Message)" }
    try { $st = Get-IgwtCached -Key 'mp:status' -TtlSeconds 10 -ScriptBlock { Get-MpComputerStatus -ErrorAction Stop }; $tamper = [bool]$st.IsTamperProtected } catch { Write-Verbose 'Defender status unavailable.' }
    $policy = Get-IgwtAsrPolicyModes
    $perRule = Get-IgwtAsrRuleExclusionMap
    $global = [pscustomobject]@{ Readable = $false; Paths = @(); Note = 'Unavailable.' }
    try { $global = Get-IgwtAsrGlobalExclusions } catch { Write-Verbose 'Global ASR exclusions unavailable.' }
    $effective = $null
    try { $effective = Get-IgwtAsrEffectiveRuleExclusions } catch { $effective = $null }

    $rules = foreach ($def in @(Get-IgwtAsrCatalog)) {
        $id = ([string]$def.id).ToLowerInvariant()
        $code = $null; $source = 'NotSet'
        if ($policy.ContainsKey($id)) { $code = $policy[$id].Code; $source = $policy[$id].Source }
        elseif ($local.ContainsKey($id)) { $code = $local[$id]; $source = 'Local' }
        $mode = ConvertTo-IgwtAsrModeName -Code $code
        $excl = @(); if ($perRule.ContainsKey($id)) { $excl = @($perRule[$id]) }
        $verified = 'Unknown'
        if ($excl.Count -eq 0) { $verified = 'None' }
        elseif ($null -ne $effective) {
            $text = $(if ($effective.ContainsKey($id)) { [string]$effective[$id] } else { '' })
            $missing = @($excl | Where-Object { $text.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 })
            $verified = $(if ($missing.Count -eq 0) { 'Yes' } else { 'No' })
        }
        $rec = [string]$def.recommendedMode
        [pscustomobject]@{
            Id                  = $id
            Key                 = [string]$def.key
            Name                = [string]$def.name
            Category            = [string]$def.category
            MsCategory          = [string]$def.msCategory
            Mode                = $mode
            Code                = $code
            Source              = $source
            ManagedByPolicy     = ($source -in 'GroupPolicy', 'MDM')
            Recommended         = $rec
            MeetsRecommendation = ((Get-IgwtAsrModeRank $mode) -ge (Get-IgwtAsrModeRank $rec))
            AllowedModes        = @(Get-IgwtAsrAllowedModes -Definition $def)
            SupportsWarn        = [bool]$def.supportsWarn
            RequiresCloud       = [bool]$def.requiresCloud
            CloudMissing        = ([bool]$def.requiresCloud -and $cloud -eq $false)
            ServerOnly          = [bool]$def.serverOnly
            AppliesTo           = [string]$def.appliesTo
            Hint                = [string]$def.hint
            Description         = [string]$def.description
            GamerImpact         = [string]$def.gamerImpact
            GamerImpactLevel    = [string]$def.gamerImpactLevel
            Notes               = [string]$def.notes
            Exclusions          = $excl
            ExclusionsVerified  = $verified
            Sources             = @($def.sources)
        }
    }
    $rules = @($rules)
    $known = @{}; foreach ($r in $rules) { $known[$r.Id] = $true }
    $unknown = @(foreach ($id in @($local.Keys) + @($policy.Keys)) { if (-not $known.ContainsKey($id)) { $id } }) | Select-Object -Unique
    $summary = [pscustomobject]@{
        Block                = @($rules | Where-Object { $_.Mode -eq 'Block' }).Count
        Warn                 = @($rules | Where-Object { $_.Mode -eq 'Warn' }).Count
        Audit                = @($rules | Where-Object { $_.Mode -eq 'Audit' }).Count
        Off                  = @($rules | Where-Object { $_.Mode -eq 'Off' }).Count
        NotConfigured        = @($rules | Where-Object { $_.Mode -eq 'NotConfigured' }).Count
        BelowRecommendation  = @($rules | Where-Object { -not $_.MeetsRecommendation -and -not $_.ServerOnly }).Count
        StandardInBlock      = @($rules | Where-Object { $_.Category -eq 'standard' -and $_.Mode -eq 'Block' }).Count
        StandardTotal        = @($rules | Where-Object { $_.Category -eq 'standard' }).Count
        PolicyManaged        = @($rules | Where-Object { $_.ManagedByPolicy }).Count
        RulesWithExclusions  = @($rules | Where-Object { @($_.Exclusions).Count -gt 0 }).Count
    }
    [pscustomobject]@{
        DefenderActive   = (Test-IgwtDefenderActive)
        CloudProtection  = $cloud
        TamperProtected  = $tamper
        Elevated         = (Test-IgwtIsAdmin)
        Error            = $err
        Rules            = $rules
        UnknownRules     = @($unknown)
        GlobalExclusions = $global
        Summary          = $summary
    }
}

function Get-IgwtAsrRecommendationPlan {
    <# .SYNOPSIS Rules below their recommended mode (never lowers a rule; skips policy-managed and server-only rules). #>
    [CmdletBinding()]
    param($Status)
    if (-not $Status) { $Status = Get-IgwtAsrStatus }
    foreach ($r in @($Status.Rules)) {
        if ($r.ServerOnly -or $r.ManagedByPolicy -or $r.Recommended -eq 'NotConfigured') { continue }
        if ((Get-IgwtAsrModeRank $r.Mode) -lt (Get-IgwtAsrModeRank $r.Recommended)) {
            [pscustomobject]@{ Id = $r.Id; Key = $r.Key; Name = $r.Name; From = $r.Mode; To = $r.Recommended }
        }
    }
}

function Test-IgwtAsrExclusion {
    <#
    .SYNOPSIS
        Checks a proposed ASR exclusion so it cannot quietly switch ASR off. Refuses: drive roots,
        the Windows folder, the whole Program Files folders, folders or wildcards in user profiles and
        ProgramData, Downloads/Desktop/temp folders, user environment variables, relative segments,
        quotes and the '>' separator. Folder exclusions must be at least two levels deep.
        Microsoft recommends excluding the specific program file whenever possible.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)
    $warnings = New-Object System.Collections.Generic.List[string]
    $result = { param($ok, $reason, $expanded, $kind) [pscustomobject]@{ Valid = $ok; Path = $Path; Expanded = $expanded; Kind = $kind; Reason = $reason; Warnings = $warnings.ToArray() } }
    if (-not $Path.Trim()) { return (& $result $false 'The path is empty.' '' '') }
    if ($Path -ne $Path.Trim()) { return (& $result $false 'Leading or trailing spaces are not supported in ASR exclusions.' '' '') }
    if ($Path.Length -gt 260) { return (& $result $false 'The path is longer than 260 characters.' '' '') }
    if ($Path -match '["''<>|\r\n\t]') { return (& $result $false 'Quotes and the characters < > | are not allowed (Defender does not support them in exclusions).' '' '') }
    foreach ($m in [regex]::Matches($Path, '%([^%]*)%')) {
        if ($script:IgwtAsrExclusionVariables -notcontains $m.Groups[1].Value) {
            return (& $result $false "Only system environment variables such as %ProgramFiles% or %ProgramData% are allowed; '%$($m.Groups[1].Value)%' is not (Microsoft does not support user variables in exclusions)." '' '')
        }
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded.Contains('%')) { return (& $result $false 'The path contains an environment variable that is not set on this PC.' '' '') }
    if ($expanded -notmatch '^[A-Za-z]:\\') { return (& $result $false 'Use a full path that starts with a drive letter (C:\...) or a system variable such as %ProgramFiles% (wildcards cannot stand for the drive).' $expanded '') }
    if ($expanded -match '\\\.{1,2}(\\|$)') { return (& $result $false 'Relative segments (. or ..) are not allowed.' $expanded '') }
    $trimmed = $expanded.TrimEnd('\')
    $segments = @($expanded.Substring(3).Split([char]'\') | Where-Object { $_ })
    if ($segments.Count -eq 0) { return (& $result $false 'A whole drive cannot be excluded.' $expanded '') }
    $leaf = $segments[$segments.Count - 1]
    $ext = ''
    if ($leaf -match '\.([A-Za-z0-9]{1,5})$') { $ext = $Matches[1].ToLowerInvariant() }
    $kind = $(if (-not $expanded.EndsWith('\') -and $script:IgwtAsrFileExtensions -contains $ext) { 'File' } else { 'Folder' })
    $hasWildcard = ($expanded -match '[\*\?]')
    # A wildcard may stand for one folder level below a named folder (D:\Games\*\game.exe), never for
    # the first level or for the folder that is being excluded.
    $folderSegments = @($segments)
    if ($kind -eq 'File') { $folderSegments = @($segments | Select-Object -First ($segments.Count - 1)) }
    for ($i = 0; $i -lt $folderSegments.Count; $i++) {
        $s = [string]$folderSegments[$i]
        if ($s -match '^[\*\?]+$' -and ($i -eq 0 -or ($kind -eq 'Folder' -and $i -le 1))) { return (& $result $false 'Wildcards cannot replace the first folder levels; that would cover almost everything on the drive.' $expanded $kind) }
    }
    if ($segments.Count -eq 1 -and $hasWildcard) { return (& $result $false 'Wildcard names directly in a drive root are too broad.' $expanded $kind) }

    $windir = [string]$env:SystemRoot
    if ($windir -and (Test-IgwtPathUnder -Path $trimmed -Parent $windir)) {
        return (& $result $false 'Paths in the Windows folder are refused: attackers abuse built-in Windows tools, so they must stay covered by ASR.' $expanded $kind)
    }
    foreach ($pf in @(@([string]$env:ProgramFiles, [string]${env:ProgramFiles(x86)}) | Where-Object { $_ })) {
        if ([string]::Equals($trimmed, $pf.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            return (& $result $false 'The whole Program Files folder cannot be excluded; pick the program''s own folder or, better, its .exe file.' $expanded $kind)
        }
    }
    $usersRoot = ''
    if ($env:USERPROFILE) { $usersRoot = Split-Path -Parent $env:USERPROFILE }
    if ($usersRoot -and (Test-IgwtPathUnder -Path $trimmed -Parent $usersRoot)) {
        if ($kind -ne 'File' -or $hasWildcard) {
            return (& $result $false 'In user profiles only single program files can be excluded (no folders or wildcards): any program you run can write there.' $expanded $kind)
        }
        foreach ($bad in '\Downloads\', '\Desktop\', '\AppData\Local\Temp\', '\Temp\', '\INetCache\') {
            if ($trimmed.IndexOf($bad, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return (& $result $false 'Downloads, Desktop, browser cache and temp folders are where malware lands first; exclusions there are refused.' $expanded $kind)
            }
        }
    }
    $programData = [string]$env:ProgramData
    if ($programData -and (Test-IgwtPathUnder -Path $trimmed -Parent $programData) -and ($kind -ne 'File' -or $hasWildcard)) {
        return (& $result $false 'In ProgramData only single program files can be excluded: many of its folders are writable by standard users.' $expanded $kind)
    }
    if ($kind -eq 'Folder') {
        if ($segments.Count -lt 2) { return (& $result $false 'Folder exclusions must be at least two levels deep (for example D:\Games\MyGame); a top-level folder is too broad.' $expanded $kind) }
        $warnings.Add('A folder exclusion covers everything inside it, including files written later. Microsoft recommends excluding the program file itself when possible.')
    }
    if ($hasWildcard) { $warnings.Add('Wildcards widen the exclusion; make sure the pattern only matches the program you trust.') }
    elseif (-not (Test-Path -LiteralPath $expanded)) { $warnings.Add('The path does not exist on this PC (yet).') }
    return (& $result $true '' $expanded $kind)
}

function Get-IgwtAsrRuleModeData {
    <# .SYNOPSIS Snapshot data of one rule's local mode: id, configured, action code. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RuleId)
    $code = Get-IgwtAsrRuleAction -RuleId $RuleId
    return [ordered]@{ id = $RuleId.ToLowerInvariant(); configured = ($null -ne $code); action = $code }
}

function Get-IgwtAsrRuleExclusionData {
    <# .SYNOPSIS Snapshot data of one rule's per-rule exclusion value and the policy switch value. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RuleId)
    $item = { param($p, $n)
        $cur = Get-IgwtRegistryValue -Path $p -Name $n
        [ordered]@{ exists = [bool]$cur.Exists; kind = $cur.Kind; value = (ConvertTo-IgwtSerializableValue -Value $cur.Value -Kind $cur.Kind); missingDepth = (Get-IgwtRegistryMissingDepth -Path $p) }
    }
    return [ordered]@{ id = $RuleId.ToLowerInvariant(); value = (& $item $script:IgwtAsrPerRuleKey $RuleId.ToLowerInvariant()); flag = (& $item $script:IgwtAsrPolicyKey $script:IgwtAsrPerRuleFlag) }
}

function Set-IgwtAsrRuleMode {
    <# .SYNOPSIS Sets one rule's local mode (NotConfigured removes it). Internal: use Invoke-IgwtAsrChange. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$RuleId, [Parameter(Mandatory = $true)][ValidateSet('NotConfigured', 'Audit', 'Warn', 'Block')][string]$Mode)
    if ($Mode -eq 'NotConfigured') {
        if ($null -ne (Get-IgwtAsrRuleAction -RuleId $RuleId) -and $PSCmdlet.ShouldProcess("ASR rule $RuleId", 'Remove (Not configured)')) {
            try { Remove-MpPreference -AttackSurfaceReductionRules_Ids $RuleId -ErrorAction Stop } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
        }
        return
    }
    Set-IgwtAsrRule -RuleId $RuleId -Code $script:IgwtAsrSettableCodes[$Mode]
}

function Set-IgwtAsrRuleExclusionValue {
    <# .SYNOPSIS Writes (or removes) one rule's per-rule exclusion list and turns the policy switch on. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$RuleId, [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Paths)
    $name = $RuleId.ToLowerInvariant()
    if (@($Paths).Count -eq 0) {
        if ($PSCmdlet.ShouldProcess("$script:IgwtAsrPerRuleKey\$name", 'Remove per-rule ASR exclusions')) { Remove-IgwtRegistryValue -Path $script:IgwtAsrPerRuleKey -Name $name }
        return
    }
    if (-not $PSCmdlet.ShouldProcess("$script:IgwtAsrPerRuleKey\$name", 'Set per-rule ASR exclusions')) { return }
    $flag = Get-IgwtRegistryValue -Path $script:IgwtAsrPolicyKey -Name $script:IgwtAsrPerRuleFlag
    if (-not $flag.Exists -or [int]$flag.Value -ne 1) { Set-IgwtRegistryValue -Path $script:IgwtAsrPolicyKey -Name $script:IgwtAsrPerRuleFlag -Kind DWord -Value 1 }
    Set-IgwtRegistryValue -Path $script:IgwtAsrPerRuleKey -Name $name -Kind String -Value (@($Paths) -join '>')
}

function Invoke-IgwtAsrChange {
    <#
    .SYNOPSIS
        Applies ASR Center changes after writing one snapshot (operation 'ASR'). Everything is
        validated before anything changes. Antivirus exclusions are never touched.
    .PARAMETER RuleMode
        Hashtable: rule GUID or key -> NotConfigured, Audit, Warn or Block.
    .PARAMETER Recommended
        Raise every rule that is below its recommended mode. Never lowers a rule.
    .PARAMETER AddExclusion
        Paths to exclude. With -ExclusionRule they apply to that rule only (per-rule exclusion,
        Group Policy registry setting); without it to every ASR rule (global ASR-only exclusion).
    .PARAMETER RemoveExclusion
        Paths to remove from the same list.
    .PARAMETER ExclusionRule
        Rule GUID or key for per-rule exclusions.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([hashtable]$RuleMode, [switch]$Recommended, [string[]]$AddExclusion, [string[]]$RemoveExclusion, [string]$ExclusionRule)
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'ASR changes need administrator rights.' }
        Initialize-IgwtDataRoot
    }
    if (-not (Test-IgwtDefenderActive)) { throw 'Microsoft Defender Antivirus is not the active antivirus, so ASR rules do not apply on this PC.' }
    $status = Get-IgwtAsrStatus
    $byId = @{}; foreach ($r in $status.Rules) { $byId[$r.Id] = $r }

    # 1. Rule modes (explicit choices win over recommendations).
    $targets = [ordered]@{}
    if ($Recommended) { foreach ($p in @(Get-IgwtAsrRecommendationPlan -Status $status)) { $targets[$p.Id] = $p.To } }
    if ($RuleMode) {
        foreach ($k in $RuleMode.Keys) {
            $def = Get-IgwtAsrRuleDefinition -Rule ([string]$k)
            $targets[([string]$def.id).ToLowerInvariant()] = [string]$RuleMode[$k]
        }
    }
    $modeOps = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($targets.Keys)) {
        $r = $byId[$id]; $mode = [string]$targets[$id]
        if ($r.ServerOnly) { throw "ASR rule '$($r.Key)' applies to Exchange servers only; iG Windows Tuner leaves it Not configured." }
        if ($r.AllowedModes -notcontains $mode) {
            if ($mode -eq 'Warn') { throw "ASR rule '$($r.Key)' does not support Warn mode (Microsoft). Use Audit or Block." }
            if ($mode -eq 'Off') { throw "iG Windows Tuner does not set rules to an explicit Off; use NotConfigured (the Windows default)." }
            throw "Mode '$mode' is not valid for ASR rule '$($r.Key)'. Use $($r.AllowedModes -join ', ')."
        }
        if ($r.ManagedByPolicy) { throw "ASR rule '$($r.Key)' is managed by $($r.Source); change it there (local changes would be overwritten at the next restart)." }
        $current = $(if ($r.Source -eq 'Local') { $r.Mode } else { 'NotConfigured' })
        if ($current -eq $mode) { continue }
        $modeOps.Add([pscustomobject]@{ Rule = $r; From = $current; To = $mode })
    }

    # 2. Exclusions.
    $adds = @($AddExclusion | Where-Object { $_ })
    $removes = @($RemoveExclusion | Where-Object { $_ })
    foreach ($p in $adds) {
        $check = Test-IgwtAsrExclusion -Path $p
        if (-not $check.Valid) { throw "ASR exclusion '$p' refused: $($check.Reason)" }
    }
    foreach ($p in $removes) { if ($p -match '[">|\r\n]') { throw "ASR exclusion '$p' contains characters that cannot be part of an exclusion." } }
    $exclOp = $null
    if ($adds.Count -or $removes.Count) {
        if ($ExclusionRule) {
            $def = Get-IgwtAsrRuleDefinition -Rule $ExclusionRule
            if ($def.serverOnly) { throw "ASR rule '$($def.key)' applies to Exchange servers only." }
            $rid = ([string]$def.id).ToLowerInvariant()
            if ($byId[$rid].ManagedByPolicy -and $byId[$rid].Source -eq 'MDM') { Write-IgwtLog -Level Warn -Message "ASR rule '$($def.key)' is managed by MDM; MDM per-rule exclusions may replace local ones." }
            $existing = @($byId[$rid].Exclusions)
            $new = New-Object System.Collections.Generic.List[string]
            foreach ($e in $existing) { if (-not (@($removes) | Where-Object { [string]::Equals($_, $e, [System.StringComparison]::OrdinalIgnoreCase) })) { $new.Add($e) } }
            foreach ($a in $adds) { if (-not (@($new) | Where-Object { [string]::Equals($_, $a, [System.StringComparison]::OrdinalIgnoreCase) })) { $new.Add($a) } }
            if ((@($new) -join '>') -ne (@($existing) -join '>')) { $exclOp = [pscustomobject]@{ Scope = 'Rule'; Rule = $byId[$rid]; Paths = $new.ToArray(); From = $existing } }
        } else {
            $known = @(); $readable = $status.GlobalExclusions.Readable
            if ($readable) { $known = @($status.GlobalExclusions.Paths) }
            elseif ($removes.Count) { throw 'The current global ASR exclusions cannot be read (administrator rights needed), so nothing can be removed safely.' }
            $toAdd = @($adds | Where-Object { $p = $_; -not ($known | Where-Object { [string]::Equals($_, $p, [System.StringComparison]::OrdinalIgnoreCase) }) })
            $toRemove = @($removes | Where-Object { $p = $_; (-not $readable) -or ($known | Where-Object { [string]::Equals($_, $p, [System.StringComparison]::OrdinalIgnoreCase) }) })
            if ($toAdd.Count -or $toRemove.Count) { $exclOp = [pscustomobject]@{ Scope = 'Global'; Added = $toAdd; Removed = $toRemove } }
        }
    }

    $count = $modeOps.Count + $(if ($exclOp) { 1 } else { 0 })
    $results = New-Object System.Collections.Generic.List[object]
    if ($count -eq 0) { return [pscustomobject]@{ Snapshot = $null; Results = @(); Changes = 0 } }
    if (-not $PSCmdlet.ShouldProcess("$count ASR change(s)", 'Apply')) { return [pscustomobject]@{ Snapshot = $null; Results = @(); Changes = 0 } }

    $snap = New-IgwtSnapshot -Operation 'ASR' -Detail "$count ASR change(s)"
    Save-IgwtSnapshot -Snapshot $snap
    foreach ($op in $modeOps) {
        $rid = $op.Rule.Id
        $tid = "asr:$($op.Rule.Key)"
        $data = Get-IgwtAsrRuleModeData -RuleId $rid
        $actions = @([ordered]@{ index = 0; type = 'asrRuleMode'; fingerprint = "asrRuleMode|$rid"; data = $data })
        Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions $actions -Result 'Applied' -Message "$($op.From) -> $($op.To)"
        try {
            Set-IgwtAsrRuleMode -RuleId $rid -Mode $op.To
            $results.Add([pscustomobject]@{ Target = $op.Rule.Name; Change = "$($op.From) -> $($op.To)"; Result = 'Applied'; Message = '' })
            Write-IgwtLog -Message "ASR rule $($op.Rule.Key) ($rid): $($op.From) -> $($op.To). Snapshot: $($snap.Path)"
        } catch {
            Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions $actions -Result 'Failed' -Message $_.Exception.Message
            $results.Add([pscustomobject]@{ Target = $op.Rule.Name; Change = "$($op.From) -> $($op.To)"; Result = 'Failed'; Message = $_.Exception.Message })
            Write-IgwtLog -Level Error -Message "ASR rule $($op.Rule.Key): $($_.Exception.Message)"
        }
    }
    if ($exclOp -and $exclOp.Scope -eq 'Rule') {
        $rid = $exclOp.Rule.Id
        $tid = "asr:exclusions:$($exclOp.Rule.Key)"
        $actions = @([ordered]@{ index = 0; type = 'asrRuleExclusions'; fingerprint = "asrRuleExclusions|$rid"; data = (Get-IgwtAsrRuleExclusionData -RuleId $rid) })
        $change = "per-rule exclusions: $(@($exclOp.From).Count) -> $(@($exclOp.Paths).Count)"
        Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions $actions -Result 'Applied' -Message $change
        try {
            Set-IgwtAsrRuleExclusionValue -RuleId $rid -Paths $exclOp.Paths
            $results.Add([pscustomobject]@{ Target = $exclOp.Rule.Name; Change = $change; Result = 'Applied'; Message = 'Defender applies exclusions when a program starts; restart the affected program.' })
            Write-IgwtLog -Message "ASR per-rule exclusions for $($exclOp.Rule.Key): $(@($exclOp.Paths) -join '; '). Snapshot: $($snap.Path)"
        } catch {
            Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions $actions -Result 'Failed' -Message $_.Exception.Message
            $results.Add([pscustomobject]@{ Target = $exclOp.Rule.Name; Change = $change; Result = 'Failed'; Message = $_.Exception.Message })
        }
    } elseif ($exclOp) {
        $data = [ordered]@{ added = @($exclOp.Added); removed = @($exclOp.Removed) }
        $actions = @([ordered]@{ index = 0; type = 'asrGlobalExclusions'; fingerprint = 'asrGlobalExclusions'; data = $data })
        $change = "global exclusions: +$(@($exclOp.Added).Count) / -$(@($exclOp.Removed).Count)"
        Add-IgwtSnapshotEntry -Snapshot $snap -TweakId 'asr:exclusions' -Actions $actions -Result 'Applied' -Message $change
        try {
            if (@($exclOp.Added).Count) { Add-MpPreference -AttackSurfaceReductionOnlyExclusions @($exclOp.Added) -ErrorAction Stop }
            if (@($exclOp.Removed).Count) { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions @($exclOp.Removed) -ErrorAction Stop }
            $results.Add([pscustomobject]@{ Target = 'All ASR rules'; Change = $change; Result = 'Applied'; Message = 'Defender applies exclusions when a program starts; restart the affected program.' })
            Write-IgwtLog -Message "ASR global exclusions: added $(@($exclOp.Added) -join '; '); removed $(@($exclOp.Removed) -join '; '). Snapshot: $($snap.Path)"
        } catch {
            Add-IgwtSnapshotEntry -Snapshot $snap -TweakId 'asr:exclusions' -Actions $actions -Result 'Failed' -Message $_.Exception.Message
            $results.Add([pscustomobject]@{ Target = 'All ASR rules'; Change = $change; Result = 'Failed'; Message = $_.Exception.Message })
        } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
    }
    return [pscustomobject]@{ Snapshot = $snap.Path; Results = $results.ToArray(); Changes = $count }
}

function Restore-IgwtAsrSnapshot {
    <#
    .SYNOPSIS
        Reverts an ASR Center snapshot. Rule GUIDs are validated against the ASR catalog and
        registry paths come from code, never from the file. The current state is captured in a new
        'ASR' snapshot first, so the revert itself can be undone.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    if ([string]$doc.operation -ne 'ASR') { throw 'This is not an ASR Center snapshot.' }
    $entries = @($doc.entries | Where-Object { $_ -and [string]$_.result -in 'Applied', 'Failed' })
    [array]::Reverse($entries)
    $results = New-Object System.Collections.Generic.List[object]
    if ($entries.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($entries.Count) ASR change(s) from $(Split-Path $SnapshotPath -Leaf)", 'Revert')) {
        return [pscustomobject]@{ Snapshot = $null; Results = @() }
    }
    $undo = New-IgwtSnapshot -Operation 'ASR' -Detail "revert of $(Split-Path $SnapshotPath -Leaf)"
    Save-IgwtSnapshot -Snapshot $undo
    foreach ($e in $entries) {
        $tid = [string]$e.tweakId
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            try {
                switch ([string]$a.type) {
                    'asrRuleMode' {
                        $def = Get-IgwtAsrRuleDefinition -Rule ([string]$a.data.id)
                        $rid = ([string]$def.id).ToLowerInvariant()
                        Add-IgwtSnapshotEntry -Snapshot $undo -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'asrRuleMode'; fingerprint = "asrRuleMode|$rid"; data = (Get-IgwtAsrRuleModeData -RuleId $rid) }) -Result 'Applied' -Message 'before revert'
                        if (-not $a.data.configured) { Set-IgwtAsrRuleMode -RuleId $rid -Mode NotConfigured }
                        else {
                            $code = [int]$a.data.action
                            if ($code -notin 0, 1, 2, 6) { throw "Snapshot action code $code is not a valid ASR mode." }
                            if ((Get-IgwtAsrRuleAction -RuleId $rid) -ne $code) { Set-IgwtAsrRule -RuleId $rid -Code $code }
                        }
                    }
                    'asrRuleExclusions' {
                        $def = Get-IgwtAsrRuleDefinition -Rule ([string]$a.data.id)
                        $rid = ([string]$def.id).ToLowerInvariant()
                        Add-IgwtSnapshotEntry -Snapshot $undo -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'asrRuleExclusions'; fingerprint = "asrRuleExclusions|$rid"; data = (Get-IgwtAsrRuleExclusionData -RuleId $rid) }) -Result 'Applied' -Message 'before revert'
                        Restore-IgwtRegistryItem -Path $script:IgwtAsrPerRuleKey -Name $rid -Item $a.data.value
                        # Keep the policy switch while other rules still have per-rule exclusions.
                        if ($a.data.flag.exists -or (Get-IgwtAsrRuleExclusionMap).Count -eq 0) { Restore-IgwtRegistryItem -Path $script:IgwtAsrPolicyKey -Name $script:IgwtAsrPerRuleFlag -Item $a.data.flag }
                    }
                    'asrGlobalExclusions' {
                        $added = @($a.data.added | Where-Object { $_ } | ForEach-Object { [string]$_ })
                        $removed = @($a.data.removed | Where-Object { $_ } | ForEach-Object { [string]$_ })
                        foreach ($p in $added + $removed) { if ($p -match '[">|\r\n]') { throw "Snapshot exclusion '$p' is not a valid path." } }
                        Add-IgwtSnapshotEntry -Snapshot $undo -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'asrGlobalExclusions'; fingerprint = 'asrGlobalExclusions'; data = [ordered]@{ added = $removed; removed = $added } }) -Result 'Applied' -Message 'before revert'
                        try {
                            if ($added.Count) { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $added -ErrorAction Stop }
                            if ($removed.Count) { Add-MpPreference -AttackSurfaceReductionOnlyExclusions $removed -ErrorAction Stop }
                        } finally { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false }
                    }
                    default { throw "Unknown ASR snapshot action '$($a.type)'." }
                }
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Reverted'; Message = '' })
            } catch {
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = $_.Exception.Message })
                Write-IgwtLog -Level Error -Message "ASR revert of ${tid}: $($_.Exception.Message)"
            }
        }
    }
    Write-IgwtLog -Message "ASR snapshot $(Split-Path $SnapshotPath -Leaf) reverted. Undo snapshot: $($undo.Path)"
    return [pscustomobject]@{ Snapshot = $undo.Path; Results = $results.ToArray() }
}
