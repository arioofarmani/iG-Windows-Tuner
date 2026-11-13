# SecSettingsState.ps1
# Security Settings Manager (3.8): current values, origins and read-only reasons for every source
# (DECISIONS SM3, SM9, SM11, SM12, SM22-SM24, SM32, SM35). Read-only: registry reads, Registry.pol
# reads and the existing readers; secedit and auditpol only when elevated; gpresult only on
# domain-joined PCs. Each slow source is read once per call.

$script:IgwtSecSettingsLast = $null

function Get-IgwtSecSettingDomainResult {
    <#
    .SYNOPSIS
        Domain policy for the manager (DECISIONS SM11): @{ Status = NotNeeded | Ok | Failed; Rows }.
        Get-IgwtDomainPolicyResult returns an empty list both for "no domain settings" and for a
        gpresult failure, so on a domain-joined PC an empty or failed result counts as Failed (all
        ADMX rows then read-only). Read-only.
    .PARAMETER Management
        Get-IgwtManagementState.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Management)
    if (-not $Management.DomainJoined) { return @{ Status = 'NotNeeded'; Rows = @() } }
    $rows = @()
    try { $rows = @(Get-IgwtDomainPolicyResult) } catch { return @{ Status = 'Failed'; Rows = @() } }
    if (-not $rows.Count) { return @{ Status = 'Failed'; Rows = @() } }
    return @{ Status = 'Ok'; Rows = $rows }
}

function Get-IgwtSecSettingRegistryNames {
    <#
    .SYNOPSIS
        Every 'key|valueName' (lower case, key relative to the hive) below one registry key, read once
        with the 64-bit view (DECISIONS SM11). Read-only; unreadable keys are skipped.
    .PARAMETER Hive
        LocalMachine or Users.
    .PARAMETER Path
        The key below the hive.
    .PARAMETER Strip
        A prefix removed from the reported key (for HKEY_USERS\<sid>\).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryHive]$Hive, [Parameter(Mandatory = $true)][string]$Path, [string]$Strip = '')
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtSecSettingRegistryNames reads the real registry and must be mocked in tests.' }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $base = Open-IgwtRegistryBaseKey -Hive $Hive
    try {
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($Path)
        $guard = 0
        while ($stack.Count -and $guard -lt 20000) {
            $guard++
            $p = $stack.Pop()
            $k = $null
            try { $k = $base.OpenSubKey($p, $false) } catch { $k = $null }
            if (-not $k) { continue }
            try {
                $rel = $(if ($Strip -and $p.StartsWith($Strip, [System.StringComparison]::OrdinalIgnoreCase)) { $p.Substring($Strip.Length) } else { $p })
                foreach ($n in $k.GetValueNames()) { $null = $set.Add(("$rel|$n").ToLowerInvariant()) }
                foreach ($s in $k.GetSubKeyNames()) { $stack.Push("$p\$s") }
            } finally { $k.Dispose() }
        }
    } finally { $base.Dispose() }
    return , $set
}

function Get-IgwtSecSettingMdmIndex {
    <#
    .SYNOPSIS
        The MDM policy index (DECISIONS SM11, location UNVERIFIED SM39c): every value name under
        HKLM\SOFTWARE\Microsoft\PolicyManager\current\device, as 'area|name' and 'name' (lower case).
        A hit only makes a row read-only. Read-only.
    #>
    [CmdletBinding()]
    param()
    $names = New-Object 'System.Collections.Generic.HashSet[string]'
    $root = 'SOFTWARE\Microsoft\PolicyManager\current\device'
    foreach ($e in (Get-IgwtSecSettingRegistryNames -Hive LocalMachine -Path $root -Strip "$root\")) {
        $null = $names.Add($e)
        $n = $e.Substring($e.LastIndexOf('|') + 1)
        if ($n -and $n -notmatch '_(ProviderSet|WinningProvider|LastWrite)$') { $null = $names.Add($n) }
    }
    return , $names
}

function Get-IgwtSecSettingContext {
    <#
    .SYNOPSIS
        The read-once facts of one refresh (DECISIONS SM11): management, edition, elevation,
        Registry.pol entries per class, the Policies and MDM indexes, domain policy, Tamper state.
        Read-only.
    #>
    [CmdletBinding()]
    param()
    $m = Get-IgwtManagementState
    # The family Get-IgwtManagementState mapped from the EditionID ('' = not recognised, SM23).
    $family = [string]$m.EditionFamily
    $elevated = [bool](Test-IgwtIsAdmin)
    $pol = @{}
    foreach ($class in 'Machine', 'User') {
        $pol[$class] = @()
        try { $pol[$class] = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $class)).Entries) } catch { $pol[$class] = @() }
    }
    $policies = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in 'SOFTWARE\Policies', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies') {
        foreach ($e in (Get-IgwtSecSettingRegistryNames -Hive LocalMachine -Path $p)) { $null = $policies.Add("machine|$e") }
    }
    $sid = $null
    try { $sid = Get-IgwtInteractiveUserSid } catch { $sid = $null }
    if ($sid) {
        foreach ($p in 'Software\Policies', 'Software\Microsoft\Windows\CurrentVersion\Policies') {
            foreach ($e in (Get-IgwtSecSettingRegistryNames -Hive Users -Path "$sid\$p" -Strip "$sid\")) { $null = $policies.Add("user|$e") }
        }
    }
    $mdm = New-Object 'System.Collections.Generic.HashSet[string]'
    try { $mdm = Get-IgwtSecSettingMdmIndex } catch { Write-Verbose 'MDM index unavailable.' }
    $tamper = $null
    try { $st = Get-MpComputerStatus -ErrorAction Stop; $tamper = [bool]$st.IsTamperProtected } catch { $tamper = $null }
    return [pscustomobject]@{
        Management = $m; EditionFamily = $family; IsHome = ($family -in 'Home', ''); Elevated = $elevated; Is64BitProcess = [Environment]::Is64BitProcess
        Pol = $pol; PoliciesIndex = $policies; MdmIndex = $mdm; Domain = (Get-IgwtSecSettingDomainResult -Management $m)
        TamperOn = $tamper; Managed = [bool]($m.MdmEnrolled -or ($m.PSObject.Properties['DefenderForEndpoint'] -and $m.DefenderForEndpoint))
    }
}

function Test-IgwtSecSettingTamperLocked {
    <# .SYNOPSIS True when a Defender preference name or ADMX policy id is in settings-meta.json tamperLocked (DECISIONS SM12). Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Preference, [string]$PolicyId)
    $t = (Get-IgwtSecSettingsData).Meta.tamperLocked
    if (-not $t) { return $false }
    if ($Preference -and @($t.preferences) -contains $Preference) { return $true }
    if ($PolicyId) {
        if (@($t.policies) -contains $PolicyId) { return $true }
        foreach ($p in @($t.prefixes)) { if ($PolicyId.StartsWith([string]$p, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    }
    return $false
}

function Get-IgwtSecSettingBaselineValue {
    <#
    .SYNOPSIS
        The bundled baseline value of a setting id (DECISIONS SM32) or the imported one, with its
        source text: @{ Value; Source }. 'Not bundled' when neither has it. Read-only.
    .PARAMETER Id
        The setting id.
    .PARAMETER Imported
        Imported baseline values: id -> @{ Values = list of @{ Value; Gpo } }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [hashtable]$Imported = @{})
    if ($Imported.ContainsKey($Id)) {
        $vals = @($Imported[$Id])
        $distinct = @($vals | ForEach-Object { ConvertTo-IgwtCanonicalJson $_.Value } | Select-Object -Unique)
        if ($distinct.Count -gt 1) { return @{ Value = $null; Source = "Conflicting baselines: $(@($vals | ForEach-Object { $_.Gpo }) -join ', ')" } }
        return @{ Value = $vals[0].Value; Source = "Imported: $($vals[0].Gpo)" }
    }
    $b = (Get-IgwtSecSettingsData).Baseline
    $hit = @($b.entries | Where-Object { $_ -and [string]$_.id -eq $Id }) | Select-Object -First 1
    if ($hit) { return @{ Value = $hit.value; Source = "$($b.baseline.name) $($b.baseline.version)" } }
    return @{ Value = $null; Source = 'Not bundled' }
}

function Get-IgwtSecSettingAdmxRows {
    <#
    .SYNOPSIS
        The ADMX rows (DECISIONS SM5, SM8-SM11, SM12, SM23): one per policy in scope and class, with
        decoded state, origin and read-only reason. Policies merged into Defender rows are skipped.
        Read-only.
    .PARAMETER Catalog
        Get-IgwtAdmxCatalog.
    .PARAMETER Context
        Get-IgwtSecSettingContext.
    .PARAMETER MergedPolicies
        ADMX policy ids shown as Defender rows instead.
    .PARAMETER Imported
        Imported baseline values.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Catalog, [Parameter(Mandatory = $true)]$Context, [hashtable]$MergedPolicies = @{}, [hashtable]$Imported = @{})
    $overlap = Get-IgwtSecSettingOverlapIndex -Catalog $Catalog
    $domainIdx = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in @($Context.Domain.Rows)) { $null = $domainIdx.Add(("$($r.Scope)|$($r.Key)|$($r.ValueName)").ToLowerInvariant()) }
    foreach ($d in @(Get-IgwtSecSettingDefinitions -Catalog $Catalog)) {
        $p = $d.Policy
        if ($MergedPolicies.ContainsKey([string]$p.Id)) { continue }
        $classes = $(if ([string]$p.Class -eq 'Both') { @('Machine', 'User') } else { @([string]$p.Class) })
        foreach ($class in $classes) {
            $id = "admx:$($p.Id):$class"
            $entries = @($Context.Pol[$class])
            $mine = @(Get-IgwtSecSettingPolicyEntries -Policy $p -Entries $entries)
            $owned = Get-IgwtSecSettingOwnedSet -Policy $p
            $pairs = @($owned.Pairs)
            $origin = 'NotConfigured'; $state = 'NotConfigured'; $current = $null; $text = 'Not configured'
            if ($Context.Domain.Status -eq 'Failed') { $origin = 'Unknown'; $state = 'Unknown'; $text = 'Unknown' }
            elseif ($mine.Count) {
                $dec = ConvertFrom-IgwtPolicyEntries -Policy $p -Entries $mine
                $origin = 'LocalPolicy'; $state = [string]$dec.State; $current = $dec.Values
                $text = $(if ($state -eq 'Enabled' -and $dec.Values.Count) { 'Enabled: ' + (@($dec.Values.Keys | Sort-Object | ForEach-Object { "$_=$(@($dec.Values[$_]) -join ',')" }) -join '; ') } else { $state })
            } elseif (@($pairs | Where-Object { $domainIdx.Contains(("$class|$_").ToLowerInvariant()) }).Count) { $origin = 'DomainGpo'; $state = 'Configured'; $text = 'Set by a domain policy' }
            elseif ($Context.MdmIndex.Contains(([string]$p.Name).ToLowerInvariant()) -or ($p.ValueName -and $Context.MdmIndex.Contains(([string]$p.ValueName).ToLowerInvariant()))) { $origin = 'Mdm'; $state = 'Configured'; $text = 'Set by MDM' }
            elseif (@($pairs | Where-Object { $Context.PoliciesIndex.Contains(("$($class.ToLowerInvariant())|$_")) }).Count) { $origin = 'RegistryOnly'; $state = 'Configured'; $text = 'Set in the registry without local policy' }
            $meta = Get-IgwtSecSettingMeta -Id $id
            $reason = ''
            switch ($origin) {
                'DomainGpo' { $reason = 'Set by a domain Group Policy; change it there.' }
                'Mdm' { $reason = 'Set by MDM (for example Intune); change it there.' }
                'RegistryOnly' { $reason = 'Set directly in the registry; use Adopt on the Group Policy page to manage it.' }
                'Unknown' { $reason = 'Domain policy could not be read, so iG does not change policies on this PC.' }
            }
            if (-not $reason -and $Context.IsHome) { $reason = $(if ($Context.EditionFamily -eq 'Home') { 'Needs Group Policy, which this edition does not have.' } else { 'Edition not recognised, so iG does not write Group Policy.' }) }
            if (-not $reason -and $Context.Managed) { $reason = 'This PC is managed (MDM or Defender for Endpoint); MDM may set this under another name.' }
            if (-not $reason -and $Context.TamperOn -ne $false -and (Test-IgwtSecSettingTamperLocked -PolicyId ([string]$p.Id))) { $origin = $(if ($origin -eq 'NotConfigured') { 'TamperProtection' } else { $origin }); $reason = 'Tamper Protection is on; Windows blocks this change. Turn it off in Windows Security first if you really need to.' }
            if (-not $reason -and [string]$p.Name -eq 'EnableScripts') { $reason = 'Script execution stays as it is: iG keeps the PowerShell execution policy unchanged (docs\SECURITY.md).' }
            if (-not $reason) { $g = Test-IgwtSecSettingWritable -Policy $p -Entries $entries -OverlapIndex $overlap -Class $class; if (-not $g.Writable) { $reason = $g.Reason } }
            $base = Get-IgwtSecSettingBaselineValue -Id $id -Imported $Imported
            New-IgwtSecSettingRow -Fields @{
                Id = $id; SourceKind = 'admx'; Category = @($d.CategoryLabel) + @(@(([string]$p.CategoryPath) -split ' > ') | Where-Object { $_ }); Name = [string]$p.DisplayName
                Explain = [string]$p.Explain; SupportedOn = [string]$p.SupportedOn; Class = $class
                ValueSpec = (ConvertTo-IgwtSecSettingValueSpec -SourceKind admx -Definition $p); Current = $current; CurrentText = $text; State = $state; Origin = $origin
                ReadOnly = [bool]$reason; ReadOnlyReason = $reason; Writer = 'localPolicy'; PolicyId = [string]$p.Id
                Baseline = $base.Value; BaselineSource = $base.Source
                Risk = $(if ($meta) { [string]$meta.risk } else { 'normal' }); RiskClass = $(if ($meta) { @($meta.riskClass) } else { @() })
                Restart = $(if ($meta -and $meta.restart) { [string]$meta.restart } else { 'unknown' }); SideEffects = $(if ($meta) { @($meta.sideEffects) } else { @() })
            }
        }
    }
}

function ConvertTo-IgwtSecSettingOrigin {
    <# .SYNOPSIS Maps a Defender or ASR source label to an SM9 origin. Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Source)
    switch -Regex ($Source) {
        'MDM' { return 'Mdm' }
        'Domain' { return 'DomainGpo' }
        'Local GPO|^GroupPolicy$' { return 'LocalPolicy' }
        'registry only' { return 'RegistryOnly' }
        '^Local$' { return 'DefenderLocal' }
        '^NotSet$' { return 'NotConfigured' }
    }
    return 'Unknown'
}

function Get-IgwtSecSettingDefenderRows {
    <#
    .SYNOPSIS
        Defender preference rows (DECISIONS SM12, SM24, SM25), ASR rule rows and exclusion list rows,
        from the existing readers. Returns @{ Rows; Merged = ADMX policy ids shown here }. Read-only.
    .PARAMETER Context
        Get-IgwtSecSettingContext.
    .PARAMETER Imported
        Imported baseline values.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [hashtable]$Imported = @{})
    $rows = New-Object System.Collections.Generic.List[object]
    $merged = @{}
    $cat = Get-IgwtDefenderSettingCatalog
    $defs = @{}; foreach ($s in @($cat.settings)) { $defs[[string]$s.mp] = $s }
    $settings = @()
    try { $settings = @(Get-IgwtDefenderSettings) } catch { $rows.Add((New-IgwtSecSettingRow -Fields @{ Id = 'defender:unavailable'; SourceKind = 'defender'; Category = @('Microsoft Defender Antivirus'); Name = 'Microsoft Defender preferences'; ReadOnly = $true; ReadOnlyReason = $_.Exception.Message; State = 'Unknown'; Origin = 'Unknown' })) }
    foreach ($s in $settings) {
        $def = $defs[[string]$s.Property]
        $id = "defender:$($s.Property)"
        $origin = ConvertTo-IgwtSecSettingOrigin -Source ([string]$s.Source)
        $policyId = [string]$s.Policy
        if ($policyId) { $merged[$policyId] = $true }
        $writer = $(if ($origin -eq 'LocalPolicy' -and $policyId) { 'localPolicy' } else { 'defender' })
        $reason = ''
        if ($origin -in 'DomainGpo', 'Mdm', 'RegistryOnly', 'Unknown') { $reason = "Set by $($s.Source); change it there." }
        elseif (-not $s.Supported -or [string]$s.Edit -notin 'set', 'parser') { $reason = $(if ($s.Change) { [string]$s.Change } else { 'Shown only.' }) }
        elseif ($Context.Managed) { $reason = 'This PC is managed (MDM or Defender for Endpoint); MDM may set this under another name.' }
        elseif ($Context.TamperOn -ne $false -and (Test-IgwtSecSettingTamperLocked -Preference ([string]$s.Property))) { $origin = 'TamperProtection'; $reason = 'Tamper Protection is on; Windows blocks this change. Turn it off in Windows Security first if you really need to.' }
        $default = $(if ($def -and $null -ne $def.PSObject.Properties['default']) { $def.default } else { $null })
        $base = Get-IgwtSecSettingBaselineValue -Id $id -Imported $Imported
        $rows.Add((New-IgwtSecSettingRow -Fields @{
                    Id = $id; SourceKind = 'defender'; Category = @('Microsoft Defender Antivirus', [string]$s.CategoryName); Name = [string]$s.Name; Explain = [string]$s.Hint
                    ValueSpec = $(if ($def) { ConvertTo-IgwtSecSettingValueSpec -SourceKind defender -Definition $def } else { @{ Mode = 'none'; Elements = @() } })
                    Current = $s.Current; CurrentText = [string]$s.Display; State = 'Configured'; Origin = $origin
                    Configured = [bool]($origin -in 'DefenderLocal', 'LocalPolicy', 'DomainGpo', 'Mdm' -and ($null -eq $default -or (ConvertTo-IgwtCanonicalJson $s.Current) -ne (ConvertTo-IgwtCanonicalJson $default)))
                    ReadOnly = [bool]$reason; ReadOnlyReason = $reason; Writer = $writer; PolicyId = $policyId; Restart = 'none'
                    Baseline = $base.Value; BaselineSource = $base.Source
                }))
    }
    # Documented preferences with no catalog entry: read-only rows (SM25).
    $pref = $null
    try { $pref = Get-IgwtMpPreferenceSafe } catch { $pref = $null }
    $cov = (Get-IgwtSecSettingsData).Meta.mpCoverage
    foreach ($p in @($cov.PSObject.Properties)) {
        $kind = [string]$p.Value
        $show = ($kind -eq 'readOnly') -or ($kind -eq 'coveredElsewhere:cfa' -and $p.Name -like '*Folders')
        if (-not $show) { continue }
        $v = $(if ($pref -and $pref.PSObject.Properties[$p.Name]) { $pref.($p.Name) } else { $null })
        $rows.Add((New-IgwtSecSettingRow -Fields @{ Id = "defender:$($p.Name)"; SourceKind = 'defender'; Category = @('Microsoft Defender Antivirus', 'Other preferences'); Name = $p.Name
                    Current = $v; CurrentText = $(if ($null -eq $v) { 'Unknown' } else { [string](@($v) -join ', ') }); State = 'Configured'; Origin = 'DefenderLocal'
                    ReadOnly = $true; ReadOnlyReason = $(if ($kind -eq 'readOnly') { 'Documented by Microsoft, not editable in 3.8.' } else { 'Protected folders are managed in the ASR Center.' }) }))
    }
    # ASR rules (SM24): Block, Audit and Warn; Off and Not configured are refused (SM41 answer 2).
    $asr = $null
    try { $asr = Get-IgwtAsrStatus } catch { $asr = $null }
    foreach ($r in @($(if ($asr) { $asr.Rules }))) {
        if (-not $r) { continue }
        $origin = ConvertTo-IgwtSecSettingOrigin -Source ([string]$r.Source)
        $choices = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($m in @('Block', 'Audit', 'Warn', 'Off', 'NotConfigured')) {
            if ($m -eq 'Warn' -and $r.PSObject.Properties['SupportsWarn'] -and -not $r.SupportsWarn) { continue }
            $choices.Add([pscustomobject]@{ Value = $m; Label = $(if ($m -eq 'NotConfigured') { 'Not configured' } else { $m }); Index = $i; Refused = $(if ($m -in 'Off', 'NotConfigured') { 'Turning an ASR rule off is refused; use Audit to watch it instead.' } else { '' }) }); $i++
        }
        $reason = $(if ([bool]$r.ManagedByPolicy) { "Set by $($r.Source); change it there." } elseif ($Context.Managed) { 'This PC is managed (MDM or Defender for Endpoint); MDM may set this under another name.' } else { '' })
        $rows.Add((New-IgwtSecSettingRow -Fields @{
                    Id = "asr:$($r.Id)"; SourceKind = 'asr'; Category = @('Microsoft Defender Antivirus', 'Attack surface reduction'); Name = [string]$r.Name
                    ValueSpec = @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id 'mode' -Kind 'enum' -Label 'Mode' -More @{ Choices = $choices.ToArray() }) }
                    Current = [string]$r.Mode; CurrentText = [string]$r.Mode; State = $(if ([string]$r.Mode -eq 'NotConfigured') { 'NotConfigured' } else { 'Configured' }); Origin = $origin
                    ReadOnly = [bool]$reason; ReadOnlyReason = $reason; Writer = 'asr'; Restart = 'none'
                }))
    }
    # Exclusion lists (SM24): remove only; AsrOnly and CfaApp are read-only here.
    $ex = $null
    try { $ex = Get-IgwtDefenderExclusionAudit } catch { $ex = $null }
    $kinds = @('Path', 'Process', 'Extension', 'IpAddress', 'AsrOnly', 'CfaApp')
    foreach ($k in $kinds) {
        $items = @($(if ($ex) { @($ex.Exclusions | Where-Object { $_ -and [string]$_.Kind -eq $k }) }))
        $removable = @($items | Where-Object { $_.Removable })
        $reason = $(if (-not $ex -or -not $ex.Readable) { 'Defender shows exclusions to administrators only; run elevated to see them.' } elseif ($k -in 'AsrOnly', 'CfaApp') { 'Managed in the ASR Center.' } elseif ($items.Count -and -not $removable.Count) { 'These exclusions are not set locally; change them where they are set.' } else { '' })
        $rows.Add((New-IgwtSecSettingRow -Fields @{
                    Id = "exclusion:$k"; SourceKind = 'exclusionList'; Category = @('Microsoft Defender Antivirus', 'Exclusions'); Name = "Excluded $(switch ($k) { 'Path' { 'files and folders' } 'Process' { 'processes' } 'Extension' { 'file types' } 'IpAddress' { 'IP addresses' } 'AsrOnly' { 'paths (ASR only)' } 'CfaApp' { 'apps (Controlled folder access)' } })"
                    ValueSpec = @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id $k -Kind 'list' -Label 'Entries' -More @{ RemoveOnly = $true }) }
                    Current = @($items | ForEach-Object { [string]$_.Value }); CurrentText = $(if ($items.Count) { "$($items.Count) entr$(if ($items.Count -eq 1) { 'y' } else { 'ies' })" } else { 'None' })
                    State = $(if ($items.Count) { 'Configured' } else { 'NotConfigured' }); Origin = $(if ($items.Count) { 'DefenderLocal' } else { 'NotConfigured' })
                    ReadOnly = [bool]$reason; ReadOnlyReason = $reason; Writer = 'exclusion'; Restart = 'none'; RiskClass = @('oneWay')
                    Explain = 'iG never adds exclusions. Removing one cannot be undone by iG (DECISIONS D5).'
                }))
    }
    return @{ Rows = $rows.ToArray(); Merged = $merged }
}

function Get-IgwtSecSettingPolicyRows {
    <#
    .SYNOPSIS
        Local security policy (password, lockout, security options) and advanced audit rows
        (DECISIONS SM22). Only when elevated and not on Home or a domain-joined PC; otherwise one
        read-only row per source says why. Never runs secedit or auditpol when not elevated.
        Read-only.
    .PARAMETER Context
        Get-IgwtSecSettingContext.
    .PARAMETER Imported
        Imported baseline values.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [hashtable]$Imported = @{})
    $why = ''
    if (-not $Context.Elevated) { $why = 'Run iG as administrator to read the local security policy and audit policy.' }
    elseif ($Context.IsHome) { $why = 'Local security policy is not changed on this edition.' }
    if ($why) {
        foreach ($k in 'secpolicy', 'audit') { New-IgwtSecSettingRow -Fields @{ Id = "$k`:unavailable"; SourceKind = $k; Category = @($(if ($k -eq 'audit') { 'Audit policy' } else { 'Local security policy' })); Name = $(if ($k -eq 'audit') { 'Advanced audit policy' } else { 'Local security policy' }); State = 'Unknown'; Origin = 'Unknown'; ReadOnly = $true; ReadOnlyReason = $why } }
        return
    }
    $domain = [bool]$Context.Management.DomainJoined
    $sce = @{}
    foreach ($s in @(Read-IgwtSceRegVlInf)) { $sce[([string]$s.Key).ToLowerInvariant()] = $s }
    foreach ($r in @(Get-IgwtSecurityPolicy)) {
        if ([string]$r.Section -notin 'System Access', 'Registry Values') { continue }
        $id = "secpol:$($r.Section):$($r.Key)"
        $spec = @{ Mode = 'none'; Elements = @(); Reason = 'iG has no definition for this option.' }
        $current = [string]$r.Value
        if ([string]$r.Section -eq 'Registry Values') {
            $d = $sce[([string]$r.Key).ToLowerInvariant()]
            if ($d) { $spec = ConvertTo-IgwtSecSettingValueSpec -SourceKind secpol -Definition $d; if ($current -match '^\d+,(.*)$') { $current = $Matches[1] } }
        } elseif ($current -match '^-?\d+$') {
            $spec = @{ Mode = 'value'; Elements = @(New-IgwtSecSettingElement -Id 'value' -Kind 'decimal' -Label ([string]$r.Name) -More @{ Min = [uint64]0; Max = [uint64][uint32]::MaxValue; Step = [uint64]1; SecpolText = $true }) }
        }
        $reason = $(if ($domain) { 'iG cannot tell local from domain values on a domain-joined PC.' } elseif ($spec.Mode -eq 'none') { [string]$spec.Reason } else { '' })
        $meta = Get-IgwtSecSettingMeta -Id $id
        $base = Get-IgwtSecSettingBaselineValue -Id $id -Imported $Imported
        New-IgwtSecSettingRow -Fields @{
            Id = $id; SourceKind = 'secpolicy'; Category = @('Local security policy', $(if ([string]$r.Section -eq 'System Access') { 'Account policies' } else { 'Security options' })); Name = [string]$r.Name
            Explain = $(if ($r.PSObject.Properties['Hint']) { [string]$r.Hint } else { '' }); ValueSpec = $spec; Current = $current; CurrentText = $current; State = 'Configured'; Origin = 'SystemValue'
            Configured = $(if ($meta -and $null -ne $meta.PSObject.Properties['documentedDefault']) { [string]$meta.documentedDefault -ne $current } else { $true })
            ReadOnly = [bool]$reason; ReadOnlyReason = $reason; Writer = 'secpol'; Section = [string]$r.Section; Key = [string]$r.Key; Restart = 'none'
            Risk = $(if ($meta) { [string]$meta.risk } else { 'normal' }); RiskClass = $(if ($meta) { @($meta.riskClass) } else { @() })
            Baseline = $base.Value; BaselineSource = $base.Source
        }
    }
    $audit = $null
    try { $audit = Get-IgwtAuditPolicy } catch { $audit = $null }
    foreach ($a in @($(if ($audit) { $audit.Subcategories }))) {
        if (-not $a -or $a.Option -or -not $a.Guid) { continue }
        $id = "audit:$($a.Guid)"
        $cur = switch -Regex ([string]$a.Setting) { 'Success.*Failure|SuccessAndFailure' { 'SuccessAndFailure'; break } '^Success' { 'Success'; break } '^Failure' { 'Failure'; break } default { 'None' } }
        $base = Get-IgwtSecSettingBaselineValue -Id $id -Imported $Imported
        New-IgwtSecSettingRow -Fields @{
            Id = $id; SourceKind = 'audit'; Category = @('Audit policy'); Name = [string]$a.Subcategory; ValueSpec = (ConvertTo-IgwtSecSettingValueSpec -SourceKind audit)
            Current = $cur; CurrentText = [string]$a.Setting; State = 'Configured'; Origin = 'SystemValue'
            ReadOnly = $domain; ReadOnlyReason = $(if ($domain) { 'iG cannot tell local from domain values on a domain-joined PC.' } else { '' }); Writer = 'audit'; Restart = 'none'
            Explain = 'System audit policy (auditpol), not Local Group Policy. iG only adds auditing.'
            Baseline = $base.Value; BaselineSource = $base.Source
        }
    }
}

function Get-IgwtSecSettings {
    <#
    .SYNOPSIS
        Every security setting the manager shows (DECISIONS SM1, SM3): ADMX policies in scope,
        Defender preferences, ASR rules, exclusion lists, local security policy, audit policy and
        Device Guard state, with current value, origin and read-only reason. Returns
        @{ Rows; Status = @{ EditionFamily; DomainPolicyRead; Managed; Elevated; Is64BitProcess; Tamper } }.
        Read-only.
    .PARAMETER Category
        Only rows whose category path contains this text.
    .PARAMETER Search
        Only rows whose name, category, explain text or id contains this text.
    .PARAMETER ConfiguredOnly
        Only rows that are configured (SM3 rule per source).
    .PARAMETER SourceKind
        Only rows of these source kinds.
    .PARAMETER NoCache
        Do not write the ADMX disk cache (read-only runs on the dev PC).
    .PARAMETER Imported
        Imported baseline values (Import-IgwtSecSettingBaseline).
    #>
    [CmdletBinding()]
    param([string]$Category, [string]$Search, [switch]$ConfiguredOnly, [string[]]$SourceKind, [switch]$NoCache, [hashtable]$Imported = @{})
    $catalog = Get-IgwtAdmxCatalog -NoCache:$NoCache
    $ctx = Get-IgwtSecSettingContext
    $all = New-Object System.Collections.Generic.List[object]
    $def = Get-IgwtSecSettingDefenderRows -Context $ctx -Imported $Imported
    foreach ($r in @(Get-IgwtSecSettingAdmxRows -Catalog $catalog -Context $ctx -MergedPolicies $def.Merged -Imported $Imported)) { $all.Add($r) }
    foreach ($r in @($def.Rows)) { $all.Add($r) }
    foreach ($r in @(Get-IgwtSecSettingPolicyRows -Context $ctx -Imported $Imported)) { $all.Add($r) }
    if (Get-Command -Name Get-IgwtSecDeviceGuardRows -ErrorAction SilentlyContinue) { foreach ($r in @(Get-IgwtSecDeviceGuardRows)) { $all.Add($r) } }
    $rows = @($all.ToArray() | Where-Object {
            $_ -and (-not $SourceKind -or @($SourceKind) -contains [string]$_.SourceKind) -and
            (-not $ConfiguredOnly -or [bool]$_.Configured) -and
            (-not $Category -or (@($_.Category) -join ' > ').IndexOf($Category, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -and
            (-not $Search -or $_.Search.IndexOf($Search.ToLowerInvariant(), [System.StringComparison]::Ordinal) -ge 0)
        })
    $status = [pscustomobject]@{
        EditionFamily = $ctx.EditionFamily; DomainPolicyRead = [string]$ctx.Domain.Status; Managed = $ctx.Managed; Elevated = $ctx.Elevated
        Is64BitProcess = $ctx.Is64BitProcess; Tamper = $(if ($null -eq $ctx.TamperOn) { 'Unknown' } elseif ($ctx.TamperOn) { 'On' } else { 'Off' })
    }
    $script:IgwtSecSettingsLast = [pscustomobject]@{ Rows = @($all.ToArray()); Status = $status }
    return [pscustomobject]@{ Rows = $rows; Status = $status }
}

function Get-IgwtSecSettingDetail {
    <#
    .SYNOPSIS
        One row by id, from the last Get-IgwtSecSettings call or a new one. Read-only.
    .PARAMETER Id
        The setting id.
    .PARAMETER NoCache
        Do not write the ADMX disk cache.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [switch]$NoCache)
    $src = $script:IgwtSecSettingsLast
    if (-not $src) { $null = Get-IgwtSecSettings -NoCache:$NoCache; $src = $script:IgwtSecSettingsLast }
    return (@($src.Rows | Where-Object { [string]::Equals([string]$_.Id, $Id, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1)
}
