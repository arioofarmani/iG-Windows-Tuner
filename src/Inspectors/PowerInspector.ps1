# PowerInspector.ps1
# Power plan engineer (Expert):
#   - read-only view of every setting in a power subgroup of the active plan, hidden ones included
#     (powercfg /qh), with the Windows default for the plan, the hidden flag and hardware blocks
#   - a snapshot-backed editor for the processor settings listed in data\power\processor.json
#     (operation 'Power', reverted through Invoke-IgwtRevert)
# Hardware overlays apply: a setting an active overlay blocks cannot be edited (for example core
# parking and hybrid scheduling on Intel hybrid CPUs). powercfg output is parsed for GUIDs, aliases
# and 0x values, which are not localized; setting names stay in the system language.

$script:IgwtSubProcessor = '54533251-82be-4824-96c1-47b60b740d00'
$script:IgwtPowerHexLine = '^\s+[^:]+:\s*0x([0-9a-fA-F]{8})\s*$'
$script:IgwtPowerIndexLine = '^\s+[^:]+:\s*(\d{3})\s*$'

function ConvertFrom-IgwtPowerCfgQuery {
    <#
    .SYNOPSIS
        Parses powercfg /q or /qh output into settings: Guid, Alias, Name, Min, Max, Increment,
        Units, Options (Index, Name), AC and DC indexes. Works on localized output because it
        relies on indentation, GUIDs, upper-case aliases and hex values only.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $lines = @($Text -split "`r?`n")
    $current = $null
    $settings = New-Object System.Collections.Generic.List[object]
    $finish = {
        if ($current) {
            # Numeric settings list min, max and increment before the AC and DC indexes; enumerated
            # settings list only AC and DC. Plans can report UNKNOWN instead of an index.
            $hex = $current.Hex.ToArray()
            $current.Setting.Options = $current.Setting.Options.ToArray()
            $s = $current.Setting
            if ($s.Options.Count -gt 0) {
                if ($hex.Count -ge 2) { $s.AC = [long]$hex[0]; $s.DC = [long]$hex[1] }
            } elseif ($hex.Count -ge 3) {
                $s.Min = [long]$hex[0]; $s.Max = [long]$hex[1]; $s.Increment = [long]$hex[2]
                if ($hex.Count -ge 5) { $s.AC = [long]$hex[3]; $s.DC = [long]$hex[4] }
            } elseif ($hex.Count -eq 2) { $s.AC = [long]$hex[0]; $s.DC = [long]$hex[1] }
            $settings.Add($s)
        }
    }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $m = [regex]::Match($line, "^\s{4}\S.*?\b($script:IgwtGuidPattern)\b\s*(?:\((.*)\))?\s*$")
        if ($m.Success -and $line -notmatch '^\s{5}') {
            & $finish
            $current = @{
                Hex = New-Object System.Collections.Generic.List[long]; AfterThirdHex = $false
                Setting = [pscustomobject]@{ Guid = $m.Groups[1].Value.ToLowerInvariant(); Alias = ''; Name = $m.Groups[2].Value.Trim(); Min = $null; Max = $null; Increment = $null; Units = ''
                    Options = (New-Object System.Collections.Generic.List[object]); AC = $null; DC = $null }
            }
            continue
        }
        if (-not $current) { continue }
        $hm = [regex]::Match($line, $script:IgwtPowerHexLine)
        if ($hm.Success) { $current.Hex.Add([Convert]::ToInt64($hm.Groups[1].Value, 16)); continue }
        $im = [regex]::Match($line, $script:IgwtPowerIndexLine)
        if ($im.Success) {
            $name = ''
            if ($i + 1 -lt $lines.Count -and $lines[$i + 1] -match '^\s+[^:]+:\s*(.*)$') { $name = $Matches[1].Trim(); $i++ }
            $current.Setting.Options.Add([pscustomobject]@{ Index = [int]$im.Groups[1].Value; Name = $name })
            continue
        }
        if (-not $current.Setting.Alias -and $current.Hex.Count -eq 0 -and $line -match '^\s{6}[^:]+:\s*([A-Z][A-Z0-9_]*)\s*$') { $current.Setting.Alias = $Matches[1]; continue }
        if ($current.Hex.Count -eq 3 -and -not $current.Setting.Units -and $line -match '^\s{6}[^:]+:\s*(\S.*)$') { $current.Setting.Units = $Matches[1].Trim() }
    }
    & $finish
    return $settings.ToArray()
}

function Get-IgwtPowerSettingCatalog {
    <# .SYNOPSIS Editable processor settings from data\power\processor.json (cached). #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtPowerSettingCache -and -not $Force) { return $script:IgwtPowerSettingCache }
    $file = Join-Path (Get-IgwtDataFolder) 'power\processor.json'
    $list = @()
    if (Test-Path -LiteralPath $file) { $list = @((Read-IgwtJsonFile -Path $file).settings | Where-Object { $_ }) }
    $script:IgwtPowerSettingCache = $list
    return $list
}

function Get-IgwtPowerSettingDefinition {
    <# .SYNOPSIS One editable setting by alias or GUID; throws for settings that are not editable. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Setting)
    $s = $Setting.Trim()
    $def = @(Get-IgwtPowerSettingCatalog | Where-Object { [string]::Equals([string]$_.alias, $s, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals([string]$_.guid, $s, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $def) { throw "Power setting '$Setting' is not editable in iG Windows Tuner. Editable: $(@(Get-IgwtPowerSettingCatalog | ForEach-Object { $_.alias }) -join ', ')." }
    return $def
}

function Test-IgwtPowerSettingCatalog {
    <# .SYNOPSIS Validates data\power\processor.json. Returns error strings. #>
    [CmdletBinding()]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $file = Join-Path (Get-IgwtDataFolder) 'power\processor.json'
    if (-not (Test-Path -LiteralPath $file)) { $errors.Add('power\processor.json: missing (power plan editor settings).'); return $errors.ToArray() }
    if ((Get-IgwtFileSchemaVersion -Document (Read-IgwtJsonFile -Path $file)) -lt $script:IgwtSchemaVersion) { $errors.Add('power\processor.json: schemaVersion must be 2.') }
    $seen = @{}
    foreach ($s in @(Get-IgwtPowerSettingCatalog -Force)) {
        $label = "power setting '$($s.alias)'"
        if ([string]$s.alias -notmatch '^[A-Z][A-Z0-9_]*$') { $errors.Add("${label}: alias must be the powercfg alias in upper case.") }
        if ([string]$s.guid -notmatch "^$script:IgwtGuidPattern$") { $errors.Add("${label}: guid invalid.") }
        foreach ($k in 'alias', 'guid') { $v = ([string]$s.$k).ToLowerInvariant(); if ($seen.ContainsKey($v)) { $errors.Add("${label}: duplicate $k.") } else { $seen[$v] = $true } }
        if ([string]$s.level -notin 'Advanced', 'Expert') { $errors.Add("${label}: level must be Advanced or Expert.") }
        if (-not $s.group) { $errors.Add("${label}: missing 'group'.") }
        if ([string]$s.guid -eq '5d76a2ca-e8c0-402f-a133-2158492d58ad') { $errors.Add("${label}: processor idle disable is not editable (Lab, rejected).") }
        Test-IgwtItemText -Item $s -Label $label -Errors $errors
        $sources = @($s.sources | Where-Object { $_ })
        if ($sources.Count -eq 0) { $errors.Add("${label}: needs at least one source.") }
        foreach ($u in $sources) { if ([string]$u -notmatch '^https://') { $errors.Add("${label}: source '$u' must be https.") } }
    }
    return $errors.ToArray()
}

function Get-IgwtPowerSettingBlock {
    <# .SYNOPSIS Reason an active hardware overlay blocks editing a power setting (AC, or DC with -Dc), or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Guid, [AllowEmptyCollection()][string[]]$Tags = @(), [switch]$Dc)
    $probe = [pscustomobject]@{ type = 'powercfgSetting'; subgroup = $script:IgwtSubProcessor; setting = $Guid.ToLowerInvariant(); ac = 0 }
    if ($Dc) { $probe | Add-Member -NotePropertyName dc -NotePropertyValue 0 }
    foreach ($o in @(Get-IgwtActiveOverlays -Tags $Tags)) {
        foreach ($m in @($o.blockMatching | Where-Object { $_ })) {
            if (Test-IgwtOverlayActionMatch -Action $probe -Matcher $m) { return "Blocked on this hardware by '$($o.name)': $($o.hint)" }
        }
    }
    return $null
}

function Get-IgwtPowerDefaults {
    <#
    .SYNOPSIS
        Where the "Windows default" of a plan's settings comes from: Windows' stored defaults for a
        built-in plan; for a copy, the built-in plan it was made from (same name resource); Balanced
        as a labelled reference for Ultimate Performance (Windows stores no defaults for it) and for
        unknown custom plans. Returns Source (label) and Scheme.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$Subgroup)
    $builtIn = @($script:IgwtSchemeBalanced, $script:IgwtSchemeHighPerformance, 'a1841308-3541-4fab-bc81-f71556f20b4a', $script:IgwtSchemeUltimateBase)
    $base = $Scheme.ToLowerInvariant()
    if ($builtIn -notcontains $base) {
        # The name resource id ('powrprof.dll,-19') identifies the built-in plan a copy was made from;
        # built-in plans such as Ultimate Performance can be hidden from 'powercfg /list'.
        $resId = {
            param($g)
            try { $fn = [string](Get-IgwtRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$g" -Name 'FriendlyName').Value } catch { $fn = '' }
            if ($fn -match 'powrprof\.dll,-(\d+)') { return [int]$Matches[1] }
            return $null
        }
        $mine = & $resId $base
        $match = $null
        if ($null -ne $mine) { $match = @($builtIn | Where-Object { (& $resId $_) -eq $mine }) | Select-Object -First 1 }
        if ($match) { $base = [string]$match } else { return [pscustomobject]@{ Source = 'Balanced (reference)'; Scheme = $script:IgwtSchemeBalanced } }
    }
    if ($base -eq $script:IgwtSchemeUltimateBase) {
        # Windows stores no defaults for Ultimate Performance and its hidden base plan reports UNKNOWN,
        # so Balanced is shown as a labelled reference.
        return [pscustomobject]@{ Source = 'Balanced (reference)'; Scheme = $script:IgwtSchemeBalanced }
    }
    $names = @{ $script:IgwtSchemeBalanced = 'Balanced'; $script:IgwtSchemeHighPerformance = 'High performance'; 'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver' }
    $label = $(if ($base -eq $Scheme.ToLowerInvariant()) { 'plan' } else { [string]$names[$base] })
    return [pscustomobject]@{ Source = $label; Scheme = $base }
}

function Get-IgwtPowerDefaultValue {
    <# .SYNOPSIS AC/DC default of one setting from Get-IgwtPowerDefaults (falls back to Balanced), with its source. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Defaults, [Parameter(Mandatory = $true)][string]$Subgroup, [Parameter(Mandatory = $true)][string]$Setting)
    $g = $Setting.ToLowerInvariant()
    $d = Get-IgwtPowerSettingDefault -Scheme $Defaults.Scheme -Subgroup $Subgroup -Setting $g
    if ($d) { return [pscustomobject]@{ AC = $d.AC; DC = $d.DC; Source = $Defaults.Source } }
    $b = Get-IgwtPowerSettingDefault -Scheme $script:IgwtSchemeBalanced -Subgroup $Subgroup -Setting $g
    if ($b) { return [pscustomobject]@{ AC = $b.AC; DC = $b.DC; Source = 'Balanced' } }
    return $null
}

function Get-IgwtPowerHardwareTags {
    [CmdletBinding()]
    param()
    try { return @((Get-IgwtHardwareProfile).Tags) } catch { return @() }
}

function Format-IgwtPowerValue {
    [CmdletBinding()]
    [OutputType([string])]
    param($Setting, $Value)
    if ($null -eq $Value) { return '' }
    $opt = @($Setting.Options | Where-Object { $_.Index -eq [int]$Value }) | Select-Object -First 1
    if ($opt) { return "$Value ($($opt.Name))" }
    if ($Setting.Units) { return "$Value $($Setting.Units)" }
    return [string]$Value
}

function Get-IgwtPowerSettingsInspection {
    <#
    .SYNOPSIS
        Read-only power plan view: every setting of a subgroup in the active plan (hidden ones
        included) with AC/DC values, the Windows default for that plan (Balanced's when the plan
        is a custom copy), hidden flag, whether iG Windows Tuner can edit it and hardware blocks.
    .PARAMETER Subgroup
        Subgroup alias or GUID (default SUB_PROCESSOR).
    #>
    [CmdletBinding()]
    param([ValidatePattern('^([A-Z_]+|[0-9a-fA-F\-]{36})$')][string]$Subgroup = 'SUB_PROCESSOR')
    $scheme = Get-IgwtActivePowerScheme
    $schemeName = (@(Get-IgwtPowerSchemes | Where-Object { $_.Guid -eq $scheme }) | Select-Object -First 1).Name
    $r = Invoke-IgwtPowerCfg -Arguments @('/qh', $scheme, $Subgroup)
    if ($r.ExitCode -ne 0) { throw "powercfg /qh failed: $($r.Output)" }
    $subGuid = $Subgroup
    if ($Subgroup -eq 'SUB_PROCESSOR') { $subGuid = $script:IgwtSubProcessor }
    elseif ($Subgroup -notmatch "^$script:IgwtGuidPattern$") {
        $sm = [regex]::Match($r.Output, "(?m)^\s{2}\S.*?\b($script:IgwtGuidPattern)\b")
        if ($sm.Success) { $subGuid = $sm.Groups[1].Value.ToLowerInvariant() }
    }
    $tags = @(Get-IgwtPowerHardwareTags)
    $catalog = @{}
    foreach ($d in @(Get-IgwtPowerSettingCatalog)) { $catalog[([string]$d.guid).ToLowerInvariant()] = $d }
    $defaults = Get-IgwtPowerDefaults -Scheme $scheme -Subgroup $subGuid
    $rows = foreach ($s in @(ConvertFrom-IgwtPowerCfgQuery -Text $r.Output)) {
        $def = Get-IgwtPowerDefaultValue -Defaults $defaults -Subgroup $subGuid -Setting $s.Guid
        $defSource = $(if ($def) { [string]$def.Source } else { '' })
        $visible = Get-IgwtPowerAttributeVisible -Action ([pscustomobject]@{ subgroup = $subGuid; setting = $s.Guid })
        $meta = $catalog[$s.Guid]
        $blockAc = $null; $blockDc = $null
        if ($meta) { $blockAc = Get-IgwtPowerSettingBlock -Guid $s.Guid -Tags $tags; $blockDc = Get-IgwtPowerSettingBlock -Guid $s.Guid -Tags $tags -Dc }
        $changed = $false
        if ($def -and $null -ne $def.AC) { $changed = ($s.AC -ne $def.AC) -or ($null -ne $def.DC -and $s.DC -ne $def.DC) }
        [pscustomobject]@{
            Guid               = $s.Guid
            Alias              = $s.Alias
            Name               = $s.Name
            Group              = $(if ($meta) { [string]$meta.group } else { '' })
            AC                 = $s.AC
            DC                 = $s.DC
            AcText             = (Format-IgwtPowerValue -Setting $s -Value $s.AC)
            DcText             = (Format-IgwtPowerValue -Setting $s -Value $s.DC)
            DefaultAC          = $(if ($def) { $def.AC } else { $null })
            DefaultDC          = $(if ($def) { $def.DC } else { $null })
            DefaultSource      = $defSource
            ChangedFromDefault = $changed
            Min                = $s.Min
            Max                = $s.Max
            Increment          = $s.Increment
            Units              = $s.Units
            Options            = @($s.Options)
            Hidden             = ($visible -eq $false)
            Editable           = [bool]$meta -and -not $blockAc
            Level              = $(if ($meta) { [string]$meta.level } else { '' })
            Hint               = $(if ($meta) { [string]$meta.hint } else { '' })
            Description        = $(if ($meta) { [string]$meta.description } else { '' })
            Blocked            = [bool]$blockAc
            BlockReason        = [string]$blockAc
            DcBlocked          = [bool]$blockDc -and -not $blockAc
            DcBlockReason      = $(if ($blockDc -and -not $blockAc) { [string]$blockDc } else { '' })
            Sources            = $(if ($meta) { @($meta.sources) } else { @() })
        }
    }
    $rows = @($rows)
    [pscustomobject]@{
        Scheme      = $scheme
        SchemeName  = $schemeName
        Subgroup    = $subGuid
        Tags        = $tags
        Settings    = $rows
        Editable    = @($rows | Where-Object { $_.Editable }).Count
        Changed     = @($rows | Where-Object { $_.ChangedFromDefault }).Count
        DefaultsFrom = [string]$defaults.Source
        Note        = 'Values apply to the active power plan. Defaults come from Windows (stored plan defaults); a plan copy is compared with the built-in plan it came from, and Ultimate Performance with the built-in Ultimate plan.'
    }
}

function Test-IgwtPowerSettingValue {
    <# .SYNOPSIS Reason a value is invalid for a parsed setting, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Setting, [Parameter(Mandatory = $true)][long]$Value)
    if (@($Setting.Options).Count -gt 0) {
        if (@($Setting.Options | Where-Object { $_.Index -eq $Value }).Count -eq 0) { return "$Value is not one of the allowed values ($(@($Setting.Options | ForEach-Object { "$($_.Index) $($_.Name)" }) -join ', '))." }
        return $null
    }
    if ($null -ne $Setting.Min -and ($Value -lt $Setting.Min -or $Value -gt $Setting.Max)) { return "$Value is outside the allowed range $($Setting.Min)-$($Setting.Max)$(if ($Setting.Units) { " $($Setting.Units)" })." }
    if ($Setting.Increment -and [long]$Setting.Increment -gt 1 -and (($Value - [long]$Setting.Min) % [long]$Setting.Increment) -ne 0) { return "$Value is not a multiple of the step $($Setting.Increment)." }
    return $null
}

function Get-IgwtPowerSettingChangePlan {
    <#
    .SYNOPSIS
        Validates a power setting change without changing anything (used by -DryRun and by
        Invoke-IgwtPowerSettingChange): editable setting, available in the active plan, values in
        the range powercfg reports, not blocked by a hardware overlay. Throws with the reason when
        the change is not allowed; returns Definition, Scheme, Parsed, NewAC, NewDC, Change and
        HasChange otherwise.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Setting, [Nullable[long]]$AC, [Nullable[long]]$DC, [switch]$Default)
    $def = Get-IgwtPowerSettingDefinition -Setting $Setting
    $guid = ([string]$def.guid).ToLowerInvariant()
    $scheme = Get-IgwtActivePowerScheme
    $r = Invoke-IgwtPowerCfg -Arguments @('/qh', $scheme, $script:IgwtSubProcessor, $guid)
    $parsed = @(ConvertFrom-IgwtPowerCfgQuery -Text $r.Output | Where-Object { $_.Guid -eq $guid }) | Select-Object -First 1
    if (-not $parsed -or $null -eq $parsed.AC) { throw "Power setting $($def.alias) is not available in the active plan on this PC." }
    if ($Default) {
        $d = Get-IgwtPowerDefaultValue -Defaults (Get-IgwtPowerDefaults -Scheme $scheme -Subgroup $script:IgwtSubProcessor) -Subgroup $script:IgwtSubProcessor -Setting $guid
        if (-not $d -or $null -eq $d.AC) { throw "Windows has no stored default for $($def.alias)." }
        $AC = [long]$d.AC
        if ($null -ne $d.DC) { $DC = [long]$d.DC }
    }
    if ($null -eq $AC -and $null -eq $DC) { throw 'Give -AC, -DC or -Default.' }
    foreach ($pair in @(@{ Name = 'AC'; Value = $AC }, @{ Name = 'DC'; Value = $DC })) {
        if ($null -eq $pair.Value) { continue }
        $bad = Test-IgwtPowerSettingValue -Setting $parsed -Value ([long]$pair.Value)
        if ($bad) { throw "$($def.alias) $($pair.Name): $bad" }
    }
    $tags = @(Get-IgwtPowerHardwareTags)
    $block = Get-IgwtPowerSettingBlock -Guid $guid -Tags $tags -Dc:($null -ne $DC)
    if ($block) { throw "$($def.alias): $block" }
    $newAc = $(if ($null -ne $AC) { [long]$AC } else { [long]$parsed.AC })
    $newDc = $(if ($null -ne $DC) { [long]$DC } else { [long]$parsed.DC })
    $change = "AC $(Format-IgwtPowerValue -Setting $parsed -Value $parsed.AC) -> $(Format-IgwtPowerValue -Setting $parsed -Value $newAc); DC $(Format-IgwtPowerValue -Setting $parsed -Value $parsed.DC) -> $(Format-IgwtPowerValue -Setting $parsed -Value $newDc)"
    [pscustomobject]@{
        Definition = $def; Scheme = $scheme; Guid = $guid; Parsed = $parsed; NewAC = $newAc; NewDC = $newDc
        HasChange = -not ($newAc -eq $parsed.AC -and $newDc -eq $parsed.DC); Change = $change
    }
}

function Invoke-IgwtPowerSettingChange {
    <#
    .SYNOPSIS
        Changes one editable processor setting of the active power plan after writing a snapshot
        (operation 'Power'). Values are checked against the range powercfg reports; settings
        blocked by a hardware overlay are refused. Expert settings need -AcknowledgeRisk.
    .PARAMETER Setting
        Alias (for example PERFEPP) or GUID from data\power\processor.json.
    .PARAMETER AC
        New plugged-in value. Omit to leave it unchanged.
    .PARAMETER DC
        New battery value. Omit to leave it unchanged.
    .PARAMETER Default
        Set AC and DC to the Windows default of the plan (Balanced as reference for Ultimate copies).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Setting, [Nullable[long]]$AC, [Nullable[long]]$DC, [switch]$Default, [switch]$AcknowledgeRisk)
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Power plan changes need administrator rights.' }
        Initialize-IgwtDataRoot
    }
    $def = Get-IgwtPowerSettingDefinition -Setting $Setting
    if ([string]$def.level -eq 'Expert' -and -not $AcknowledgeRisk) { throw "'$($def.alias)' is an Expert setting. Review its description, then confirm with -AcknowledgeRisk." }
    $plan = Get-IgwtPowerSettingChangePlan -Setting $Setting -AC $AC -DC $DC -Default:$Default
    if (-not $plan.HasChange) { return [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @() } }
    $scheme = $plan.Scheme; $guid = $plan.Guid; $parsed = $plan.Parsed; $newAc = $plan.NewAC; $newDc = $plan.NewDC; $change = $plan.Change
    if (-not $PSCmdlet.ShouldProcess("$($def.alias) in plan $scheme", $change)) { return [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @() } }
    $snap = New-IgwtSnapshot -Operation 'Power' -Detail "$($def.alias): $change"
    Save-IgwtSnapshot -Snapshot $snap
    $data = [ordered]@{ scheme = $scheme; subgroup = $script:IgwtSubProcessor; setting = $guid; ac = [long]$parsed.AC; dc = [long]$parsed.DC }
    $actions = @([ordered]@{ index = 0; type = 'powerSettingValue'; fingerprint = "powerSettingValue|$guid"; data = $data })
    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "power:$($def.alias)" -Actions $actions -Result 'Applied' -Message $change -Level ([string]$def.level)
    try {
        Set-IgwtPowerSettingIndex -Scheme $scheme -Subgroup $script:IgwtSubProcessor -Setting $guid -AC $(if ($newAc -ne $parsed.AC) { $newAc } else { $null }) -DC $(if ($newDc -ne $parsed.DC) { $newDc } else { $null })
        Write-IgwtLog -Message "Power setting $($def.alias): $change. Snapshot: $($snap.Path)"
        return [pscustomobject]@{ Snapshot = $snap.Path; Changes = 1; Results = @([pscustomobject]@{ Target = [string]$def.alias; Change = $change; Result = 'Applied'; Message = '' }) }
    } catch {
        Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "power:$($def.alias)" -Actions $actions -Result 'Failed' -Message $_.Exception.Message -Level ([string]$def.level)
        Write-IgwtLog -Level Error -Message "Power setting $($def.alias): $($_.Exception.Message)"
        return [pscustomobject]@{ Snapshot = $snap.Path; Changes = 1; Results = @([pscustomobject]@{ Target = [string]$def.alias; Change = $change; Result = 'Failed'; Message = $_.Exception.Message }) }
    }
}

function Restore-IgwtPowerSettingSnapshot {
    <#
    .SYNOPSIS
        Reverts a 'Power' snapshot. Setting GUIDs are validated against data\power\processor.json
        and the plan must still exist. The current values are captured in a new snapshot first.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    if ([string]$doc.operation -ne 'Power') { throw 'This is not a power plan snapshot.' }
    $entries = @($doc.entries | Where-Object { $_ -and [string]$_.result -in 'Applied', 'Failed' })
    [array]::Reverse($entries)
    $results = New-Object System.Collections.Generic.List[object]
    if ($entries.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($entries.Count) power setting(s) from $(Split-Path $SnapshotPath -Leaf)", 'Revert')) { return [pscustomobject]@{ Snapshot = $null; Results = @() } }
    $undo = New-IgwtSnapshot -Operation 'Power' -Detail "revert of $(Split-Path $SnapshotPath -Leaf)"
    Save-IgwtSnapshot -Snapshot $undo
    foreach ($e in $entries) {
        $tid = [string]$e.tweakId
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            try {
                if ([string]$a.type -ne 'powerSettingValue') { throw "Unknown power snapshot action '$($a.type)'." }
                $def = Get-IgwtPowerSettingDefinition -Setting ([string]$a.data.setting)
                $guid = ([string]$def.guid).ToLowerInvariant()
                $scheme = ([string]$a.data.scheme).ToLowerInvariant()
                if ($scheme -notmatch "^$script:IgwtGuidPattern$") { throw 'Snapshot does not contain a valid plan GUID.' }
                if (-not (Test-IgwtPowerSchemeExists -Guid $scheme)) { throw "Power plan $scheme no longer exists." }
                $cur = Get-IgwtPowerSettingValue -Scheme $scheme -Subgroup $script:IgwtSubProcessor -Setting $guid
                if ($cur) {
                    Add-IgwtSnapshotEntry -Snapshot $undo -TweakId $tid -Actions @([ordered]@{ index = 0; type = 'powerSettingValue'; fingerprint = "powerSettingValue|$guid"; data = [ordered]@{ scheme = $scheme; subgroup = $script:IgwtSubProcessor; setting = $guid; ac = [long]$cur.AC; dc = [long]$cur.DC } }) -Result 'Applied' -Message 'before revert'
                }
                Set-IgwtPowerSettingIndex -Scheme $scheme -Subgroup $script:IgwtSubProcessor -Setting $guid -AC ([long]$a.data.ac) -DC ([long]$a.data.dc)
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Reverted'; Message = '' })
            } catch {
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = $_.Exception.Message })
                Write-IgwtLog -Level Error -Message "Power revert of ${tid}: $($_.Exception.Message)"
            }
        }
    }
    Write-IgwtLog -Message "Power snapshot $(Split-Path $SnapshotPath -Leaf) reverted. Undo snapshot: $($undo.Path)"
    return [pscustomobject]@{ Snapshot = $undo.Path; Results = $results.ToArray() }
}
