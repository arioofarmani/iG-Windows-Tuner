# Catalog.ps1
# Loads the data-driven tweak catalog (data\tweaks\*.json), presets, games and the rejected list,
# and validates them. No tweak logic lives here or in the GUI; it is all declared in JSON.

$script:IgwtCatalogCache = $null
$script:IgwtCategories = @('Power & CPU', 'Graphics & Display', 'Input', 'Network', 'Background & Privacy', 'Storage', 'Security', 'System', 'Risk Zone')
$script:IgwtLegacyTweakFields = @('antiCheatSafe', 'expert')
$script:IgwtActionTypes = @('registry', 'registryListMerge', 'adapterRegistry', 'netAdapterPower', 'powercfgScheme', 'powercfgSetting', 'service',
    'netAdapterAdvanced', 'netQosPolicy', 'dnsDoh', 'mpPreference', 'asrRule', 'optionalFeature', 'custom', 'check',
    'storageSense', 'wufbPolicy', 'deviceInterrupt', 'serviceSet', 'powercfgAttribute', 'powercfgSettingAcDc', 'scheduledTask', 'firewallRule',
    'appx', 'winget', 'capability', 'processMitigation', 'exploitSystem', 'cleanerRule')
$script:IgwtV2ActionTypes = @('storageSense', 'wufbPolicy', 'deviceInterrupt', 'serviceSet', 'powercfgAttribute', 'powercfgSettingAcDc', 'scheduledTask',
    'firewallRule', 'appx', 'winget', 'capability', 'processMitigation', 'exploitSystem', 'cleanerRule')
$script:IgwtRegistryKinds = @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')

function Get-IgwtDataFolder {
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.DataFolder) { return [string]$script:IgwtSettings.DataFolder }
    return (Join-Path $script:IgwtProjectRoot 'data')
}

function Get-IgwtFileSchemaVersion {
    <# .SYNOPSIS schemaVersion of a parsed data file (1 when the field is missing). #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)]$Document)
    if ($null -ne $Document.PSObject.Properties['schemaVersion']) { return [int]$Document.schemaVersion }
    return 1
}

function Read-IgwtJsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    try { return ($text | ConvertFrom-Json) } catch { throw "Invalid JSON in ${Path}: $($_.Exception.Message)" }
}

function Set-IgwtDefaultProperty {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Object, [Parameter(Mandatory = $true)][string]$Name, $Value)
    if ($null -eq $Object.PSObject.Properties[$Name]) {
        if ($PSCmdlet.ShouldProcess($Name, 'Add default property')) { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
    }
}

function ConvertTo-IgwtNormalizedTweak {
    <#
    .SYNOPSIS
        Fills optional fields with defaults so the engine and GUI can rely on them. v1 entries
        (no level/antiCheat) are upgraded to schema v2 in memory first. Adds the computed
        compatibility properties expert, antiCheatSafe and tier.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, [string]$SourceFile, [int]$SourceSchema = 2)
    $legacy = @($script:IgwtLegacyTweakFields | Where-Object { $null -ne $Tweak.PSObject.Properties[$_] })
    if ($null -eq $Tweak.PSObject.Properties['level'] -or $null -eq $Tweak.PSObject.Properties['antiCheat']) {
        $Tweak = ConvertTo-IgwtPSObject -InputObject (ConvertTo-IgwtV2Tweak -Tweak $Tweak)
    } else {
        foreach ($f in $legacy) { $Tweak.PSObject.Properties.Remove($f) }
    }
    Set-IgwtDefaultProperty -Object $Tweak -Name 'order' -Value 50 -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'group' -Value '' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'expert' -Value $false -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'warning' -Value '' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'conflictsWith' -Value @() -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'status' -Value 'Active' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'statusReason' -Value '' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'policyKeys' -Value @() -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'postApply' -Value $null -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'requires' -Value 'none' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'appliesTo' -Value ([pscustomobject]@{ minBuild = 26100 }) -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'revertNote' -Value '' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'sourceFile' -Value $SourceFile -WhatIf:$false
    if ($null -eq $Tweak.appliesTo.PSObject.Properties['conditions']) { $Tweak.appliesTo | Add-Member -NotePropertyName conditions -NotePropertyValue @() }
    if ($null -eq $Tweak.appliesTo.PSObject.Properties['minBuild']) { $Tweak.appliesTo | Add-Member -NotePropertyName minBuild -NotePropertyValue 26100 }
    Set-IgwtDefaultProperty -Object $Tweak -Name 'sideEffects' -Value '' -WhatIf:$false
    Set-IgwtDefaultProperty -Object $Tweak -Name 'attribution' -Value '' -WhatIf:$false
    # Computed (never written to files): the engine, GUI and docs read these.
    $ac = ConvertTo-IgwtAntiCheatInfo -Value $Tweak.antiCheat
    $Tweak | Add-Member -NotePropertyName expert -NotePropertyValue ([string]$Tweak.level -in 'Expert', 'Lab') -Force
    $Tweak | Add-Member -NotePropertyName antiCheatSafe -NotePropertyValue ([bool]$ac.Safe) -Force
    $Tweak | Add-Member -NotePropertyName antiCheatText -NotePropertyValue ([string]$ac.Text) -Force
    $Tweak | Add-Member -NotePropertyName tier -NotePropertyValue ([string]$Tweak.evidence.tier) -Force
    $Tweak | Add-Member -NotePropertyName sourceSchema -NotePropertyValue $SourceSchema -Force
    $Tweak | Add-Member -NotePropertyName legacyFields -NotePropertyValue $legacy -Force
    return $Tweak
}

function Get-IgwtCatalog {
    <#
    .SYNOPSIS
        Returns all tweaks from data\tweaks\*.json (normalized, sorted by category and order).
    .PARAMETER Force
        Reload from disk instead of using the cache.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtCatalogCache -and -not $Force) { return $script:IgwtCatalogCache }
    $folder = Join-Path (Get-IgwtDataFolder) 'tweaks'
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($file in (Get-ChildItem -LiteralPath $folder -Filter '*.json' | Sort-Object Name)) {
        $doc = Read-IgwtJsonFile -Path $file.FullName
        $schema = Get-IgwtFileSchemaVersion -Document $doc
        foreach ($t in @($doc.tweaks)) {
            if ($null -eq $t) { continue }
            $all.Add((ConvertTo-IgwtNormalizedTweak -Tweak $t -SourceFile $file.Name -SourceSchema $schema))
        }
    }
    $script:IgwtCatalogCache = @($all | Sort-Object @{ Expression = { [array]::IndexOf($script:IgwtCategories, $_.category) } }, order, id)
    return $script:IgwtCatalogCache
}

function Get-IgwtTweak {
    <# .SYNOPSIS Returns tweaks by id (throws on unknown ids). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Id)
    $catalog = Get-IgwtCatalog
    foreach ($i in $Id) {
        $t = $catalog | Where-Object { $_.id -eq $i } | Select-Object -First 1
        if (-not $t) { throw "Unknown tweak id '$i'. Use -ListTweaks to see valid ids." }
        $t
    }
}

function ConvertTo-IgwtNormalizedPreset {
    <#
    .SYNOPSIS
        Upgrades a v1 preset in memory and adds the computed member list 'tweaks' (include minus
        exclude), which the engine, CLI and GUI use.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preset, [string]$SourceFile, [int]$SourceSchema = 2)
    $p = ConvertTo-IgwtPSObject -InputObject (ConvertTo-IgwtV2Preset -Preset $Preset -IdMap (Get-IgwtIdMap))
    $excluded = @($p.exclude | Where-Object { $_ })
    $p | Add-Member -NotePropertyName tweaks -NotePropertyValue @(@($p.include) | Where-Object { $_ -and $excluded -notcontains $_ }) -Force
    $p | Add-Member -NotePropertyName sourceFile -NotePropertyValue $SourceFile -Force
    $p | Add-Member -NotePropertyName sourceSchema -NotePropertyValue $SourceSchema -Force
    return $p
}

function Get-IgwtPreset {
    <#
    .SYNOPSIS Returns one preset (built-in or custom, by id or name) or all presets.
    .PARAMETER Builtin
        Only the built-in presets from data\presets (no custom presets).
    #>
    [CmdletBinding()]
    param([string]$Name, [switch]$Builtin)
    $folder = Join-Path (Get-IgwtDataFolder) 'presets'
    $presets = foreach ($file in (Get-ChildItem -LiteralPath $folder -Filter '*.json' | Sort-Object Name)) {
        $doc = Read-IgwtJsonFile -Path $file.FullName
        ConvertTo-IgwtNormalizedPreset -Preset $doc -SourceFile $file.Name -SourceSchema (Get-IgwtFileSchemaVersion -Document $doc)
    }
    if (-not $Builtin) { $presets = @($presets) + @(Get-IgwtCustomPresets) }
    $presets = @($presets | Where-Object { $_ } | Sort-Object order, name)
    if ($Name) {
        $p = $presets | Where-Object { $_.id -eq $Name -or $_.name -eq $Name } | Select-Object -First 1
        if (-not $p) { throw "Unknown preset '$Name'." }
        return $p
    }
    return $presets
}

function Get-IgwtGameDefinitions {
    <# .SYNOPSIS Game definitions from data\games.json (Dota 2 first). #>
    [CmdletBinding()]
    param()
    return @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'games.json')).games)
}

function Get-IgwtRejectedTweaks {
    <# .SYNOPSIS Documented-but-not-implemented tweaks with the reason they were rejected. #>
    [CmdletBinding()]
    param()
    return @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'rejected.json')).rejected)
}

function Get-IgwtTweakRevertDescription {
    <# .SYNOPSIS Plain-language description of how a tweak is reverted. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Revert restores the exact values captured in the JSON snapshot taken right before apply (including values that did not exist).')
    foreach ($a in @($Tweak.actions)) {
        switch ($a.type) {
            'registry' { $lines.Add("Windows default for $($a.path)\$($a.name): $(if ($null -ne $a.default) { $a.default } else { 'not documented' }).") }
            'registryListMerge' { $lines.Add("Windows default for item $($a.item) in $($a.name): $(if ($a.default) { $a.default } else { '<remove>' }).") }
            'service' { $lines.Add("Windows default startup type for $($a.name): $($a.default).") }
            'mpPreference' { $lines.Add("Windows default for Defender $($a.setting): $($a.default).") }
            'asrRule' { $lines.Add("Windows default for ASR rule $($a.label): not configured.") }
            'powercfgScheme' { $lines.Add('Windows default power scheme: Balanced.') }
            'powercfgSetting' { $lines.Add("Windows default for $($a.label): the plan's built-in default value.") }
            'powercfgSettingAcDc' { $lines.Add("Windows default for $($a.label): the plan's built-in AC and DC default values.") }
            { $_ -in 'storageSense', 'wufbPolicy' } { $lines.Add("Windows default for the $($a.setting) policy: not configured (value absent).") }
            'scheduledTask' { $lines.Add("Windows default for task $($a.path)$($a.name): $($a.default).") }
            'firewallRule' { $lines.Add($(if ($a.rule) { "Revert removes the iG Windows Tuner rule $($a.rule) if iG Windows Tuner created it." } else { "Revert re-enables exactly the rules in '$($a.displayGroup)' that were enabled before." })) }
            'appx' { $lines.Add("Revert re-registers $($a.package) from its install folder or reinstalls it from the Microsoft Store; a removed provisioned copy is not restored for new user profiles.") }
            { $_ -in 'processMitigation', 'exploitSystem' } { $lines.Add("Windows default for exploit protection $($a.mitigation): not set (system default).") }
            'deviceInterrupt' { $lines.Add('Revert restores the exact interrupt values the driver had; there is no separate Windows default.') }
            'cleanerRule' { $lines.Add('Deleted files cannot be restored.') }
            default { }
        }
    }
    if ($Tweak.revertNote) { $lines.Add([string]$Tweak.revertNote) }
    return ($lines -join ' ')
}

function Test-IgwtV2Action {
    <# .SYNOPSIS Validation of the 2.0 action types (fields, ranges, safety limits). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)][string]$Where,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    $a = $Action
    $guid = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $expertPlus = ([string]$Tweak.level -in 'Expert', 'Lab')
    switch ([string]$a.type) {
        'storageSense' {
            $def = $script:IgwtStorageSenseSettings[[string]$a.setting]
            if (-not $def) { $Errors.Add("${Where}: unknown Storage Sense setting '$($a.setting)'.") }
            elseif ($def.ContainsKey('Allowed') -and @($def.Allowed) -notcontains [int]$a.value) { $Errors.Add("${Where}: $($a.setting) must be one of $(@($def.Allowed) -join ', ').") }
            elseif ($def.ContainsKey('Min') -and ([int]$a.value -lt $def.Min -or [int]$a.value -gt $def.Max)) { $Errors.Add("${Where}: $($a.setting) must be $($def.Min)-$($def.Max).") }
        }
        'wufbPolicy' {
            switch ([string]$a.setting) {
                'featureDeferralDays' { if ([int]$a.value -lt 0 -or [int]$a.value -gt 365) { $Errors.Add("${Where}: feature update deferral must be 0-365 days.") } }
                'qualityDeferralDays' { if ([int]$a.value -lt 0 -or [int]$a.value -gt 30) { $Errors.Add("${Where}: quality update deferral must be 0-30 days.") } }
                'targetRelease' { if ([string]$a.value.product -ne 'Windows 11' -or [string]$a.value.version -notmatch '^\d{2}H[12]$') { $Errors.Add("${Where}: targetRelease needs product 'Windows 11' and a version such as 24H2.") } }
                default { $Errors.Add("${Where}: unknown Windows Update policy setting '$($a.setting)'.") }
            }
        }
        'deviceInterrupt' {
            if ($script:IgwtInterruptClasses -notcontains [string]$a.deviceClass) { $Errors.Add("${Where}: deviceClass must be Display, Net or USB.") }
            $set = @($script:IgwtInterruptFields.Keys | Where-Object { $null -ne $a.PSObject.Properties[$_] -and $null -ne $a.$_ })
            if ($set.Count -eq 0) { $Errors.Add("${Where}: set at least one of $(@($script:IgwtInterruptFields.Keys) -join ', ').") }
            foreach ($f in $set) { $spec = $script:IgwtInterruptFields[$f]; if ([int]$a.$f -lt $spec.Min -or [int]$a.$f -gt $spec.Max) { $Errors.Add("${Where}: $f must be $($spec.Min)-$($spec.Max).") } }
            if ([string]$Tweak.requires -ne 'reboot') { $Errors.Add("${Where}: interrupt changes need requires 'reboot'.") }
            if (-not $expertPlus) { $Errors.Add("${Where}: device interrupt items must be level Expert or Lab.") }
        }
        'serviceSet' {
            if (@($a.services).Count -eq 0) { $Errors.Add("${Where}: serviceSet needs services.") }
            foreach ($s in @($a.services)) {
                if (-not $s.name -or -not $s.startupType -or -not $s.default) { $Errors.Add("${Where}: every service needs name, startupType and default.") }
                if ($script:IgwtProtectedServices -contains [string]$s.name) { $Errors.Add("${Where}: service '$($s.name)' is protected and may not be changed.") }
            }
        }
        'powercfgAttribute' {
            if ([string]$a.subgroup -notmatch $guid -or [string]$a.setting -notmatch $guid) { $Errors.Add("${Where}: powercfgAttribute needs subgroup and setting GUIDs.") }
            if ($null -eq $a.PSObject.Properties['visible']) { $Errors.Add("${Where}: powercfgAttribute needs 'visible'.") }
            if ([string]$a.default -notin 'hidden', 'visible') { $Errors.Add("${Where}: powercfgAttribute default must be hidden or visible.") }
        }
        'powercfgSettingAcDc' {
            if ([string]$a.subgroup -notmatch $guid -or [string]$a.setting -notmatch $guid) { $Errors.Add("${Where}: powercfgSettingAcDc needs subgroup and setting GUIDs.") }
            if ($null -eq $a.ac -or $null -eq $a.dc) { $Errors.Add("${Where}: powercfgSettingAcDc needs both ac and dc.") }
            if (-not $a.defaultFromScheme -and ($null -eq $a.defaultAc -or $null -eq $a.defaultDc)) { $Errors.Add("${Where}: powercfgSettingAcDc needs defaultFromScheme or defaultAc and defaultDc.") }
        }
        'scheduledTask' {
            if ([string]$a.path -notmatch '^\\.*\\$' -or -not $a.name) { $Errors.Add("${Where}: scheduledTask needs a path like '\Microsoft\Windows\...\' and a name.") }
            if ([string]$a.on -notin 'Enabled', 'Disabled' -or [string]$a.default -notin 'Enabled', 'Disabled') { $Errors.Add("${Where}: scheduledTask on and default must be Enabled or Disabled.") }
            if ([string]$a.on -eq 'Disabled') { foreach ($pp in $script:IgwtProtectedTaskPaths) { if (([string]$a.path).StartsWith($pp, [System.StringComparison]::OrdinalIgnoreCase)) { $Errors.Add("${Where}: tasks under '$pp' are protected.") } } }
        }
        'firewallRule' {
            if ($a.rule) {
                if (-not ([string]$a.rule).StartsWith('iGWindowsTuner-')) { $Errors.Add("${Where}: owned firewall rules must be named 'iGWindowsTuner-...'.") }
                if ([string]$a.action -ne 'Block') { $Errors.Add("${Where}: iG Windows Tuner only creates Block rules.") }
                if ([string]$a.direction -notin 'Inbound', 'Outbound') { $Errors.Add("${Where}: direction must be Inbound or Outbound.") }
                if (-not $a.displayName) { $Errors.Add("${Where}: owned firewall rules need a displayName.") }
            } elseif ($a.displayGroup) {
                if ([string]$a.on -ne 'Disabled') { $Errors.Add("${Where}: rule groups may only be disabled (iG Windows Tuner only reduces exposure).") }
                if ([string]$a.default -notin 'Enabled', 'Disabled') { $Errors.Add("${Where}: rule group default must be Enabled or Disabled.") }
            } else { $Errors.Add("${Where}: firewallRule needs 'rule' (owned block rule) or 'displayGroup'.") }
        }
        'appx' {
            if (-not $a.package) { $Errors.Add("${Where}: appx needs package.") }
            elseif (Test-IgwtAppxProtected -Package ([string]$a.package)) { $Errors.Add("${Where}: app '$($a.package)' is protected.") }
            if ([string]$a.on -ne 'Removed' -or [string]$a.default -ne 'Installed') { $Errors.Add("${Where}: appx on must be Removed and default Installed.") }
            if ([string]$Tweak.reversible -eq 'full') { $Errors.Add("${Where}: app removal is not fully reversible (use reversible partial).") }
        }
        'winget' {
            if ([string]$a.id -notmatch '^[A-Za-z0-9][A-Za-z0-9\.\-_+]*$') { $Errors.Add("${Where}: winget needs a package id.") }
            if ($a.source -and [string]$a.source -notin 'winget', 'msstore') { $Errors.Add("${Where}: winget source must be winget or msstore.") }
            if ([string]$a.on -notin 'Installed', 'NotInstalled' -or [string]$a.default -notin 'Installed', 'NotInstalled') { $Errors.Add("${Where}: winget on and default must be Installed or NotInstalled.") }
        }
        'capability' {
            if (-not $a.name) { $Errors.Add("${Where}: capability needs name.") }
            if ([string]$a.on -notin 'Installed', 'NotPresent' -or [string]$a.default -notin 'Installed', 'NotPresent') { $Errors.Add("${Where}: capability on and default must be Installed or NotPresent.") }
        }
        'processMitigation' {
            if ([string]$a.process -notmatch '^[\w\.\- ]+\.exe$') { $Errors.Add("${Where}: processMitigation needs a program name like game.exe.") }
            if (-not $script:IgwtMitigationMap.Contains([string]$a.mitigation)) { $Errors.Add("${Where}: unsupported mitigation '$($a.mitigation)'.") }
            if ([string]$a.on -notin 'ON', 'OFF') { $Errors.Add("${Where}: processMitigation on must be ON or OFF.") }
            if ([string]$a.on -eq 'OFF' -and -not $expertPlus) { $Errors.Add("${Where}: turning a mitigation off needs level Expert or Lab.") }
            foreach ($eq in @($a.equivalentOn | Where-Object { $_ })) { if ([string]$eq -ne 'NOTSET' -or [string]$a.on -ne 'ON') { $Errors.Add("${Where}: equivalentOn may only contain NOTSET, for ON items.") } }
        }
        'exploitSystem' {
            if (-not $script:IgwtMitigationMap.Contains([string]$a.mitigation)) { $Errors.Add("${Where}: unsupported mitigation '$($a.mitigation)'.") }
            if ([string]$a.on -ne 'ON') { $Errors.Add("${Where}: system-wide exploit protection may only be turned ON.") }
            foreach ($eq in @($a.equivalentOn | Where-Object { $_ })) { if ([string]$eq -ne 'NOTSET') { $Errors.Add("${Where}: equivalentOn may only contain NOTSET (use default).") } }
        }
        'cleanerRule' {
            if (@(Get-IgwtCleanerRules | Where-Object { $_.id -eq [string]$a.rule }).Count -eq 0) { $Errors.Add("${Where}: unknown cleaner rule '$($a.rule)'.") }
            if ([string]$Tweak.reversible -ne 'none') { $Errors.Add("${Where}: items that run a cleaner rule must be reversible 'none'.") }
        }
    }
}

function Test-IgwtRiskZoneItem {
    <#
    .SYNOPSIS
        Rules for rejected tweaks offered at the user's own risk: evidence tier R only in the Risk
        Zone category and vice versa, level Lab, a warning, side effects, and a riskZone block that
        names the rejected entry, what the item turns off or on, and its risks.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    $tid = [string]$Tweak.id
    $isR = ([string]$Tweak.evidence.tier -eq 'R')
    $inZone = ([string]$Tweak.category -eq 'Risk Zone')
    if ($isR -ne $inZone) { $Errors.Add("${tid}: evidence tier R and the Risk Zone category go together."); return }
    if (-not $isR) { if ($Tweak.PSObject.Properties['riskZone'] -and $Tweak.riskZone) { $Errors.Add("${tid}: only Risk Zone items may have a riskZone block.") }; return }
    if ($tid -notmatch '^risk\.') { $Errors.Add("${tid}: Risk Zone ids start with 'risk.'.") }
    if ([string]$Tweak.level -ne 'Lab') { $Errors.Add("${tid}: Risk Zone items must be level Lab.") }
    if (-not ([string]$Tweak.warning).Trim()) { $Errors.Add("${tid}: Risk Zone items need a warning.") }
    if (-not ([string]$Tweak.sideEffects).Trim()) { $Errors.Add("${tid}: Risk Zone items must describe what they switch off or on in sideEffects.") }
    $rz = $Tweak.riskZone
    if (-not $rz) { $Errors.Add("${tid}: Risk Zone items need a riskZone block (rejected, turnsOff, turnsOn, risks)."); return }
    if ([string]$rz.rejected -notmatch '^rejected\.') { $Errors.Add("${tid}: riskZone.rejected must name the rejected.json entry.") }
    if ((@($rz.turnsOff | Where-Object { $_ }).Count + @($rz.turnsOn | Where-Object { $_ }).Count) -eq 0) { $Errors.Add("${tid}: riskZone must list what the item turns off and/or on.") }
    if (@($rz.risks | Where-Object { $_ }).Count -eq 0) { $Errors.Add("${tid}: riskZone.risks must list at least one risk.") }
}

function Test-IgwtCatalog {
    <#
    .SYNOPSIS
        Validates the catalog, presets and rejected list. Returns a list of error strings (empty = valid).
    #>
    [CmdletBinding()]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $catalog = @(Get-IgwtCatalog -Force)
    $ids = @{}
    $validRisk = @('low', 'medium', 'high')
    $validImpact = @('none', 'low', 'medium', 'high')
    $validSec = @('+', '0', '-')
    $validRequires = @('none', 'logoff', 'reboot')
    $handlers = @($script:IgwtCustomHandlers.Keys)
    $checkers = @('HvciRunning', 'HvciNotRunning', 'KernelShadowStacksRunning', 'DefaultApp')
    $hooks = @('MouseParameters', 'KeyboardRepeat', 'AccessibilityFlags')

    $files = @{}
    foreach ($t in $catalog) {
        $tid = [string]$t.id
        foreach ($field in 'id', 'name', 'category', 'risk', 'requires') {
            if ($null -eq $t.$field -or ([string]$t.$field).Length -eq 0) { $errors.Add("${tid}: missing '$field'.") }
        }
        foreach ($field in 'evidence', 'impact', 'actions') {
            if ($null -eq $t.$field) { $errors.Add("${tid}: missing '$field'.") }
        }
        Test-IgwtItemText -Item $t -Label $tid -Errors $errors
        Test-IgwtItemMetadata -Item $t -Label $tid -Errors $errors
        if ([int]$t.sourceSchema -lt $script:IgwtSchemaVersion -and -not $files.ContainsKey([string]$t.sourceFile)) {
            $files[[string]$t.sourceFile] = $true
            $errors.Add("tweaks\$($t.sourceFile): schemaVersion $($t.sourceSchema); run tools\Convert-IgwtV1Data.ps1 to migrate it to schema v$($script:IgwtSchemaVersion).")
        }
        foreach ($lf in @($t.legacyFields)) { $errors.Add("${tid}: v1 field '$lf' is not used in schema v2 (use level and antiCheat).") }
        foreach ($cond in @($t.appliesTo.conditions | Where-Object { $_ })) { if ($script:IgwtConditions -notcontains [string]$cond) { $errors.Add("${tid}: unknown appliesTo condition '$cond'.") } }
        if ($tid -notmatch '^[a-z]+\.[a-z0-9\-]+$') { $errors.Add("${tid}: id must look like 'category.name' in lower case.") }
        if ($ids.ContainsKey($tid)) { $errors.Add("${tid}: duplicate id.") } else { $ids[$tid] = $t }
        if ($script:IgwtCategories -notcontains [string]$t.category) { $errors.Add("${tid}: unknown category '$($t.category)'.") }
        if ($t.evidence) {
            $sources = @($t.evidence.sources | Where-Object { $_ })
            if ($sources.Count -lt 1) { $errors.Add("${tid}: Tier $($t.evidence.tier) needs at least one source URL.") }
            foreach ($s in $sources) { if ([string]$s -notmatch '^https://') { $errors.Add("${tid}: source '$s' must be an https URL.") } }
            if ([string]$t.evidence.tier -eq 'B' -and ([string]$t.hint + ' ' + [string]$t.description) -notmatch '(?i)measure') {
                $errors.Add("${tid}: Tier B hint/description must tell the user to measure before/after.")
            }
        }
        if ($t.impact) {
            if ($validImpact -notcontains [string]$t.impact.performance) { $errors.Add("${tid}: impact.performance invalid.") }
            if ($validImpact -notcontains [string]$t.impact.latency) { $errors.Add("${tid}: impact.latency invalid.") }
            if ($validSec -notcontains [string]$t.impact.security) { $errors.Add("${tid}: impact.security must be +, 0 or -.") }
        }
        if ($validRisk -notcontains [string]$t.risk) { $errors.Add("${tid}: risk must be low, medium or high.") }
        if ($validRequires -notcontains [string]$t.requires) { $errors.Add("${tid}: requires must be none, logoff or reboot.") }
        $ac = ConvertTo-IgwtAntiCheatInfo -Value $t.antiCheat
        if (@($ac.Breaks).Count -gt 0 -and [string]$t.level -ne 'Lab') { $errors.Add("${tid}: an item that breaks anti-cheat must be level Lab.") }
        if ($ac.Unknown -and [string]$t.level -notin 'Expert', 'Lab') { $errors.Add("${tid}: an item with unknown anti-cheat impact must be level Expert or Lab.") }
        if ([string]$t.level -in 'Expert', 'Lab' -and -not $t.warning) { $errors.Add("${tid}: Expert and Lab items need a warning text.") }
        if ([string]$t.reversible -ne 'full' -and -not ([string]$t.sideEffects).Trim()) { $errors.Add("${tid}: items that are not fully reversible must describe it in sideEffects.") }
        if ([string]$t.status -notin 'Active', 'NotApplicable') { $errors.Add("${tid}: status must be Active or NotApplicable.") }
        if ($t.postApply -and $hooks -notcontains [string]$t.postApply) { $errors.Add("${tid}: unknown postApply hook '$($t.postApply)'.") }
        Test-IgwtRiskZoneItem -Tweak $t -Errors $errors

        $actions = @($t.actions)
        if ($actions.Count -eq 0) { $errors.Add("${tid}: needs at least one action.") }
        $i = 0
        foreach ($a in $actions) {
            $where = "${tid} action[$i]"
            if ($script:IgwtActionTypes -notcontains [string]$a.type) { $errors.Add("${where}: unknown type '$($a.type)'.") }
            switch ([string]$a.type) {
                { $_ -in 'registry', 'adapterRegistry' } {
                    if (-not $a.path -or -not $a.name) { $errors.Add("${where}: registry actions need path and name.") }
                    if ($a.type -eq 'registry' -and [string]$a.path -notmatch '^(HKLM|HKCU):\\' -and [string]$a.path -notmatch '^HKU:\\\.DEFAULT\\') { $errors.Add("${where}: path must start with HKLM:\, HKCU:\ or HKU:\.DEFAULT\.") }
                    if ($null -ne $a.bitSet -and $null -ne $a.bitClear) { $errors.Add("${where}: use either bitSet or bitClear, not both.") }
                    if ([string]$a.on -ne '<absent>' -and $script:IgwtRegistryKinds -notcontains [string]$a.valueType) { $errors.Add("${where}: valueType '$($a.valueType)' invalid.") }
                    if ($null -eq $a.PSObject.Properties['default']) { $errors.Add("${where}: missing 'default' (Windows default or <absent>), needed for Reset to default.") }
                    if ($null -eq $a.PSObject.Properties['on']) { $errors.Add("${where}: missing 'on'.") }
                }
                'registryListMerge' {
                    if (-not $a.path -or -not $a.name -or -not $a.item -or $null -eq $a.on) { $errors.Add("${where}: registryListMerge needs path, name, item and on.") }
                    if ($null -eq $a.PSObject.Properties['default']) { $errors.Add("${where}: missing 'default'.") }
                }
                'powercfgScheme' { if ([string]$a.scheme -notmatch '^[0-9a-f\-]{36}$') { $errors.Add("${where}: scheme GUID invalid.") } }
                'powercfgSetting' { if (-not $a.subgroup -or -not $a.setting -or $null -eq $a.ac) { $errors.Add("${where}: powercfgSetting needs subgroup, setting and ac.") } }
                'service' {
                    if (-not $a.name -or -not $a.startupType -or -not $a.default) { $errors.Add("${where}: service needs name, startupType and default.") }
                    if ($script:IgwtProtectedServices -contains [string]$a.name) { $errors.Add("${where}: service '$($a.name)' is protected and may not be changed.") }
                }
                'netAdapterAdvanced' { if (-not $a.keyword -or $null -eq $a.on) { $errors.Add("${where}: netAdapterAdvanced needs keyword and on.") } }
                'netQosPolicy' { if ($null -eq $a.dscp -or -not $a.protocol) { $errors.Add("${where}: netQosPolicy needs dscp and protocol.") } }
                'dnsDoh' { if (-not $script:IgwtDohProviders.ContainsKey(([string]$a.provider).ToLowerInvariant())) { $errors.Add("${where}: unknown DoH provider '$($a.provider)'.") } }
                'mpPreference' {
                    if (-not $script:IgwtMpAllowed.ContainsKey([string]$a.setting)) { $errors.Add("${where}: Defender setting '$($a.setting)' is not on the allow-list.") }
                    if ($null -eq $a.PSObject.Properties['default']) { $errors.Add("${where}: missing 'default'.") }
                }
                'asrRule' {
                    if ([string]$a.id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $errors.Add("${where}: ASR GUID invalid.") }
                    if (@('Block', 'Audit', 'Warn') -notcontains [string]$a.on) { $errors.Add("${where}: ASR on must be Block, Audit or Warn.") }
                }
                'optionalFeature' { if (-not $a.feature -or -not $a.on -or -not $a.default) { $errors.Add("${where}: optionalFeature needs feature, on and default.") } }
                'custom' {
                    if ($handlers -notcontains [string]$a.handler) { $errors.Add("${where}: unknown custom handler '$($a.handler)'.") }
                    else {
                        $h = $script:IgwtCustomHandlers[[string]$a.handler]
                        foreach ($k in 'Detect', 'Snapshot', 'Apply', 'Restore') { if (-not $h[$k]) { $errors.Add("${where}: handler '$($a.handler)' lacks $k (no revert path).") } }
                    }
                }
                'check' {
                    if ($checkers -notcontains [string]$a.checker) { $errors.Add("${where}: unknown checker '$($a.checker)'.") }
                    if ([string]$a.checker -eq 'DefaultApp' -and ((-not $a.extension -and -not $a.protocol) -or -not $a.progId)) { $errors.Add("${where}: DefaultApp needs extension or protocol, and progId.") }
                }
                { $script:IgwtV2ActionTypes -contains $_ } { Test-IgwtV2Action -Action $a -Tweak $t -Where $where -Errors $errors }
            }
            $i++
        }
    }
    foreach ($t in $catalog) {
        foreach ($c in @($t.conflictsWith)) { if ($c -and -not $ids.ContainsKey([string]$c)) { $errors.Add("$($t.id): conflictsWith unknown id '$c'.") } }
    }

    $rejected = @()
    try { $rejected = @(Get-IgwtRejectedTweaks) } catch { $errors.Add("rejected.json: $($_.Exception.Message)") }
    foreach ($r in $rejected) {
        if (-not $r.id -or -not $r.name -or -not $r.reason) { $errors.Add("rejected.json: entry '$($r.id)' needs id, name and reason.") }
        if ($ids.ContainsKey([string]$r.id)) { $errors.Add("rejected.json: '$($r.id)' is rejected but also implemented in the catalog.") }
        # Every rejected tweak is either offered in the Risk Zone (riskItem) or not offered, with the reason (unavailable).
        $hasItem = [bool]([string]$r.riskItem); $hasReason = [bool](([string]$r.unavailable).Trim())
        if ($hasItem -eq $hasReason) { $errors.Add("rejected.json: '$($r.id)' needs exactly one of riskItem or unavailable.") }
        if ($hasItem) {
            $ri = $ids[[string]$r.riskItem]
            if (-not $ri) { $errors.Add("rejected.json: '$($r.id)' riskItem '$($r.riskItem)' is not in the catalog.") }
            elseif ([string]$ri.riskZone.rejected -ne [string]$r.id) { $errors.Add("rejected.json: '$($r.id)' riskItem '$($r.riskItem)' points back to '$($ri.riskZone.rejected)'.") }
        }
    }
    foreach ($t in @($catalog | Where-Object { [string]$_.evidence.tier -eq 'R' })) {
        if (-not @($rejected | Where-Object { [string]$_.riskItem -eq [string]$t.id }).Count) { $errors.Add("$($t.id): Risk Zone item is not linked from rejected.json (riskItem).") }
    }
    $rejectedIds = @($rejected | ForEach-Object { [string]$_.id })

    foreach ($p in @(Get-IgwtPreset -Builtin)) {
        if ([int]$p.sourceSchema -lt $script:IgwtSchemaVersion) { $errors.Add("presets\$($p.sourceFile): schemaVersion $($p.sourceSchema); run tools\Convert-IgwtV1Data.ps1 to migrate it.") }
        Test-IgwtPresetDefinition -Preset $p -CatalogIndex $ids -RejectedIds $rejectedIds -Errors $errors
    }
    $sessionPresets = @(Get-IgwtPreset -Builtin | Where-Object { $_.PSObject.Properties['session'] -and $_.session })
    if ($sessionPresets.Count -gt 1) { $errors.Add('presets: only one Session Mode preset (session: true) is allowed.') }
    if ($sessionPresets.Count -eq 0 -and @($catalog | Where-Object { [string]$_.group -eq 'Session Mode' }).Count) { $errors.Add('presets: the Session Mode items need the session preset (session: true).') }

    $tagIds = @{}
    $tagFile = Join-Path (Get-IgwtDataFolder) 'hardware\tags.json'
    if (-not (Test-Path -LiteralPath $tagFile)) { $errors.Add('hardware\tags.json: missing (hardware tag vocabulary).') }
    else {
        $tagDoc = Read-IgwtJsonFile -Path $tagFile
        if ((Get-IgwtFileSchemaVersion -Document $tagDoc) -lt $script:IgwtSchemaVersion) { $errors.Add('hardware\tags.json: schemaVersion must be 2.') }
        foreach ($tag in @(Get-IgwtHardwareTagDefinitions -Force)) {
            $tagId = [string]$tag.id
            if ($tagId -notmatch '^[a-z0-9]+(\.[a-z0-9]+)*$') { $errors.Add("hardware tag '$tagId': id must be lower-case words separated by dots.") }
            if ($tagIds.ContainsKey($tagId)) { $errors.Add("hardware tag '$tagId': duplicate id.") } else { $tagIds[$tagId] = $true }
            if (-not $tag.name) { $errors.Add("hardware tag '$tagId': missing 'name'.") }
            Test-IgwtItemText -Item $tag -Label "hardware tag '$tagId'" -Errors $errors
        }
    }
    foreach ($e in @(Test-IgwtHardwareCatalog)) { $errors.Add([string]$e) }
    foreach ($e in @(Test-IgwtAsrCatalog)) { $errors.Add([string]$e) }
    foreach ($e in @(Test-IgwtPowerSettingCatalog)) { $errors.Add([string]$e) }
    foreach ($e in @(Test-IgwtKernelInspectorCatalog)) { $errors.Add([string]$e) }
    foreach ($e in @(Test-IgwtManageCatalog)) { $errors.Add([string]$e) }
    foreach ($e in @(Test-IgwtToolkitCatalog)) { $errors.Add([string]$e) }
    return $errors.ToArray()
}
