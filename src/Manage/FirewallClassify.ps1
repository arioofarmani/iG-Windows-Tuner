# FirewallClassify.ps1
# Firewall Manager 3.4 classification: every rule gets exactly one origin category (Core Services,
# Windows Connections, User Installed, Custom Rules), its facets (Inbound, Outbound, Blocked) and the
# Bloated assessment, each with a reason and a confidence level. Deterministic and locale-independent:
# it matches rule IDs, raw group resource strings, stores, package publisher IDs and program paths
# from the knowledge base (data\firewall), never display names. Pure functions over inventory rows;
# the user's overrides (role, category, "not bloated for me") come from Get-IgwtFirewallOverrides.

function Get-IgwtFirewallClassificationContext {
    <#
    .SYNOPSIS
        Lookup tables for classifying many rules quickly: group strings, rule ID patterns, stores,
        Microsoft publishers, protected programs, script hosts, user-writable paths, the owned tag,
        the role, installed packages, signatures and overrides.
    .PARAMETER Role
        Gamer, PowerUser, Sysadmin or Workstation (default: the override, else the persona).
    .PARAMETER InstalledPackages
        Package names (for example Microsoft.GamingApp) used by bloatWhen conditions; $null means
        unknown, and conditional bloat is then not applied.
    .PARAMETER Signatures
        Path -> signature info (Status, Signer) from Get-IgwtFirewallSignatures; optional.
    #>
    [CmdletBinding()]
    param([string]$Role, [string[]]$InstalledPackages, [hashtable]$Signatures = @{}, $Overrides)
    $kb = Get-IgwtFirewallKnowledgeBase
    if (-not $Overrides) { $Overrides = Get-IgwtFirewallOverrides }
    if ($null -eq $Signatures) { $Signatures = @{} }
    if (-not $Role) { $Role = [string]$Overrides.Role }
    if (-not $Role) { $Role = Get-IgwtFirewallDefaultRole }
    $groupIndex = @{}; $storeIndex = @{}; $patterns = New-Object System.Collections.Generic.List[object]; $publisherEntry = $null
    foreach ($g in $kb.Groups) {
        foreach ($s in @($g.match.groups | Where-Object { $_ })) { $groupIndex[([string]$s).ToLowerInvariant()] = $g }
        foreach ($s in @($g.match.stores | Where-Object { $_ })) { $storeIndex[[string]$s] = $g }
        $rx = ConvertTo-IgwtFirewallWildcardRegex -Pattern @($g.match.namePatterns)
        if ($rx) { $patterns.Add(@{ Regex = $rx; Entry = $g }) }
        if (@($g.match.packagePublishers | Where-Object { $_ }).Count) { $publisherEntry = $g }
    }
    $services = @{}
    foreach ($s in $kb.Services) { $services[([string]$s.name).ToLowerInvariant()] = $s }
    $expand = { param($p) [Environment]::ExpandEnvironmentVariables([string]$p) }
    $writable = @($kb.Apps.userWritable | ForEach-Object { & $expand $_ })
    $writableExceptions = @($kb.Apps.userWritableExceptions | ForEach-Object { & $expand $_ })
    $protected = @(foreach ($p in @($kb.Apps.protected)) { foreach ($pat in @($p.programPatterns)) { @{ Pattern = [string]$pat; Entry = $p } } })
    $games = @()
    try { $games = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'games.json')).games | ForEach-Object { @($_.exe) } | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() }) } catch { Write-Verbose "games.json not readable: $($_.Exception.Message)" }
    $packages = $null
    if ($null -ne $InstalledPackages) { $packages = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase); foreach ($n in $InstalledPackages) { $null = $packages.Add([string]$n) } }
    $windir = [Environment]::GetFolderPath('Windows')
    $categories = @{}
    foreach ($cat in $kb.Categories) { $categories[[string]$cat.id] = $cat }
    [pscustomobject]@{
        Kb = $kb; Role = $Role; GroupIndex = $groupIndex; StoreIndex = $storeIndex; Patterns = $patterns.ToArray(); PublisherEntry = $publisherEntry
        Publishers = @($kb.Apps.microsoftPublishers); MicrosoftSigners = @($kb.Apps.microsoftSigners); Services = $services
        Writable = $writable; WritableExceptions = $writableExceptions; Protected = $protected; Games = $games
        ScriptHosts = @($kb.Apps.scriptHosts | ForEach-Object { ([string]$_).ToLowerInvariant() }); Owned = $kb.Apps.owned
        Packages = $packages; Signatures = $Signatures; Overrides = $Overrides; WindowsDir = $windir
        Categories = $categories
    }
}

function Get-IgwtFirewallDefaultRole {
    <# .SYNOPSIS The firewall role that matches the current persona (Gamer when unknown). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $persona = ''
    try { $persona = [string](Get-IgwtPersona) } catch { Write-Verbose "Persona not readable: $($_.Exception.Message)" }
    foreach ($r in @((Get-IgwtFirewallKnowledgeBase).Roles)) { if (@($r.personas) -contains $persona) { return [string]$r.id } }
    return 'Gamer'
}

function Get-IgwtFirewallPackagePublisher {
    <#
    .SYNOPSIS
        The package publisher ID of an AppContainer rule (the 13-character hash after the last '_'
        of the package family name in the rule ID or group), or '' for other rules.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Name, [string]$Group)
    foreach ($t in @($Group, $Name)) {
        if (-not $t) { continue }
        # Group form: @{Package_Version_Arch__publisher?ms-resource://...}; rule ID form: Family_publisherS-1-5-...
        $m = [regex]::Match([string]$t, '_([a-z0-9]{13})(?:\?|S-1-|$|-)')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return ''
}

function Test-IgwtFirewallPathPattern {
    <# .SYNOPSIS True when a path matches any wildcard pattern (case-insensitive). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Path, [string[]]$Pattern)
    if (-not $Path) { return $false }
    foreach ($p in $Pattern) { if ($p -and $Path -like $p) { return $true } }
    return $false
}

function Resolve-IgwtFirewallOrigin {
    <#
    .SYNOPSIS
        The origin category of one inventory row: Category, Confidence (High, Medium, Low), Reason
        (one plain sentence) and KbId (the knowledge-base entry, if any). First match wins:
        iG Windows Tuner tag, service-hardening store, Windows group string, rule ID pattern,
        AppContainer package publisher, service filter, unknown Windows resource group, program
        path and signer, firewall-prompt pattern, then manual (Custom) rules.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)]$Context)
    $r = $Row; $c = $Context
    $name = [string]$r.Name; $group = [string]$r.RawGroup; if (-not $group) { $group = [string]$r.Group }
    $result = { param($cat, $conf, $reason, $kb) @{ Category = $cat; Confidence = $conf; Reason = $reason; KbId = $(if ($kb) { [string]$kb.id } else { '' }) } }
    $o = $c.Owned
    if (($o.namePrefix -and $name -like "$($o.namePrefix)*") -or ($o.group -and $group -eq [string]$o.group) -or ($o.descriptionMarker -and ([string]$r.Description).Contains([string]$o.descriptionMarker))) {
        return (& $result 'CustomRules' 'High' "Custom Rules: created by iG Windows Tuner (rule ID prefix $($o.namePrefix))." $null)
    }
    $store = [string]$r.Store
    if ($store -and $c.StoreIndex.ContainsKey($store)) { $e = $c.StoreIndex[$store]; return (& $result $e.category 'High' "$($c.Categories[[string]$e.category].name): $($e.name) rule from the $store policy store." $e) }
    if ($group -and $c.GroupIndex.ContainsKey($group.ToLowerInvariant())) {
        $e = $c.GroupIndex[$group.ToLowerInvariant()]
        # programUnder: the group counts only for programs in these folders (shared groups such as the packaged-app group).
        $under = @($e.match.programUnder | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_) })
        if (-not $under.Count -or (Test-IgwtFirewallPathPattern -Path ([Environment]::ExpandEnvironmentVariables([string]$r.Program)) -Pattern $under)) {
            return (& $result $e.category 'High' "$($c.Categories[[string]$e.category].name): Windows group '$($e.name)' (group ID $group)." $e)
        }
    }
    foreach ($p in $c.Patterns) {
        if ($p.Regex.IsMatch($name)) { $e = $p.Entry; return (& $result $e.category 'High' "$($c.Categories[[string]$e.category].name): rule ID $name belongs to '$($e.name)'." $e) }
    }
    $publisher = Get-IgwtFirewallPackagePublisher -Name $name -Group $group
    if ([string]$r.Owner -or $publisher -or $group -like '@{*') {
        if ($publisher -and $c.Publishers -contains $publisher) {
            return (& $result 'WindowsConnections' 'High' "Windows Connections: app rule of a Microsoft package (publisher ID $publisher)." $c.PublisherEntry)
        }
        $who = $(if ($publisher) { "publisher ID $publisher" } else { 'an unknown publisher' })
        return (& $result 'UserInstalled' $(if ($publisher) { 'High' } else { 'Medium' }) "User Installed: app rule of a Store package from $who (not Microsoft)." $null)
    }
    $service = ([string]$r.Service).ToLowerInvariant()
    if ($service -and $service -ne 'any' -and $c.Services.ContainsKey($service)) {
        $s = $c.Services[$service]
        return (& $result $s.category 'Medium' "$($c.Categories[[string]$s.category].name): restricted to the Windows service $($s.displayName) ($($s.name))." $null)
    }
    if ($group -like '@*') { return (& $result 'WindowsConnections' 'Medium' "Windows Connections: Windows group resource string $group that the knowledge base does not list yet." $null) }
    $program = [string]$r.Program
    $guidName = $name -match '^\{[0-9A-Fa-f-]{36}\}$'
    if ($program -and $program -notin 'Any', 'System') {
        $path = [Environment]::ExpandEnvironmentVariables($program)
        $sig = $c.Signatures[$path.ToLowerInvariant()]
        $signer = $(if ($sig -and [string]$sig.Status -eq 'Valid') { [string]$sig.Signer } else { '' })
        $folder = Split-Path -Path $path -Parent
        if ($path -like "$($c.WindowsDir)\*") {
            return (& $result 'CustomRules' 'Medium' "Custom Rules: a rule for the Windows program $(Split-Path $path -Leaf) that no Windows group created; probably made by hand or by a script." $null)
        }
        if ($signer -and @($c.MicrosoftSigners | Where-Object { $signer -like "*$_*" }).Count) {
            return (& $result 'WindowsConnections' 'Medium' "Windows Connections: Microsoft app $(Split-Path $path -Leaf), signed by $signer." $null)
        }
        if ($guidName -and ([string]$r.DisplayName) -and -not $group) {
            $why = $(if ($signer) { "signed by $signer, " } else { '' })
            return (& $result 'UserInstalled' 'Medium' "User Installed: created when a Windows firewall prompt was answered for $(Split-Path $path -Leaf) ($why$folder)." $null)
        }
        if ($signer) { return (& $result 'UserInstalled' 'High' "User Installed: program signed by $signer and located in $folder." $null) }
        return (& $result 'UserInstalled' 'Medium' "User Installed: program $(Split-Path $path -Leaf) in $folder (signature not checked or not valid)." $null)
    }
    if (-not $group) {
        return (& $result 'CustomRules' 'Low' 'Custom Rules: a port or address rule without a program or group; probably created by hand. Is this right?' $null)
    }
    return (& $result 'CustomRules' 'Low' "Custom Rules: group '$group' is not a Windows group and the rule names no program. Is this right?" $null)
}

function ConvertTo-IgwtFirewallWildcardRegex {
    <# .SYNOPSIS One case-insensitive regex for a list of wildcard patterns (* and ?), $null for an empty list. #>
    [CmdletBinding()]
    param([string[]]$Pattern)
    $parts = @($Pattern | Where-Object { $_ } | ForEach-Object { '^' + ([regex]::Escape([string]$_) -replace '\\\*', '.*' -replace '\\\?', '.') + '$' })
    if (-not $parts.Count) { return $null }
    return New-Object System.Text.RegularExpressions.Regex (($parts -join '|'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Invoke-IgwtFirewallClassification {
    <#
    .SYNOPSIS
        Adds the classification to inventory rows (in place; no output): Origin, OriginName,
        Confidence, OriginReason, KbId, KbName, KbMeaning, Facets, Assessments, BloatReason,
        WhatStopsWorking, Protected, ProtectedReason, IsWindows, Groups (the membership chips).
        Overrides apply: a moved category keeps the engine's reason as "was: ..."; "not bloated for
        me" clears Bloated.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [Parameter(Mandatory = $true)]$Context)
    $c = $Context
    $list = @($Rows | Where-Object { $_ })
    if (-not $list.Count) { return }
    # Rows from Join-IgwtFirewallData declare these fields; other rows get them once here.
    $fields = @('Origin', 'EngineOrigin', 'OriginName', 'Confidence', 'OriginReason', 'KbId', 'KbName', 'KbMeaning', 'Facets', 'Assessments', 'BloatReason', 'WhatStopsWorking', 'Protected', 'ProtectedReason', 'IsWindows', 'Groups')
    foreach ($r in $list) { foreach ($f in $fields) { if (-not $r.PSObject.Properties[$f]) { $r | Add-Member -NotePropertyName $f -NotePropertyValue $null } } ; break }
    if (-not $list[-1].PSObject.Properties['Groups']) { foreach ($r in $list) { foreach ($f in $fields) { if (-not $r.PSObject.Properties[$f]) { $r | Add-Member -NotePropertyName $f -NotePropertyValue $null } } } }
    $ov = $c.Overrides
    $catOverride = @{}; if ($ov -and $ov.Categories) { foreach ($p in $ov.Categories.PSObject.Properties) { $catOverride[[string]$p.Name] = [string]$p.Value } }
    $notBloated = @{}; if ($ov -and $ov.NotBloated) { foreach ($n in @($ov.NotBloated)) { $notBloated[[string]$n] = $true } }
    $kbById = @{}; foreach ($g in $c.Kb.Groups) { $kbById[[string]$g.id] = $g }
    $roleName = ([string]@($c.Kb.Roles | Where-Object { $_.id -eq $c.Role } | ForEach-Object { $_.name })[0]).ToLowerInvariant()
    $protRegex = @{}; foreach ($p in @($c.Kb.Apps.protected)) { $protRegex[[string]$p.reason] = ConvertTo-IgwtFirewallWildcardRegex -Pattern @($p.programPatterns) }
    $games = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase); foreach ($gx in $c.Games) { $null = $games.Add([string]$gx) }
    $bloatText = @{}
    foreach ($r in $list) {
        $o = Resolve-IgwtFirewallOrigin -Row $r -Context $c
        $category = $o.Category; $confidence = $o.Confidence; $reason = $o.Reason
        $name = [string]$r.Name
        # A user's move never takes a rule out of Core Services (they stay locked); the locks use EngineOrigin.
        if ($catOverride.ContainsKey($name) -and $catOverride[$name] -in $script:IgwtFirewallOrigins -and $o.Category -ne 'CoreServices') {
            $category = $catOverride[$name]; $confidence = 'High'
            $reason = "$($c.Categories[$category].name): moved here by you (was: $($o.Reason))"
        }
        $kb = $(if ($o.KbId) { $kbById[$o.KbId] } else { $null })
        $facets = @()
        if ([string]$r.Direction -eq 'Inbound') { $facets += 'Inbound' } elseif ([string]$r.Direction -eq 'Outbound') { $facets += 'Outbound' }
        if ([string]$r.Action -eq 'Block') { $facets += 'Blocked' }
        # Bloated: an enabled rule the role does not need (knowledge base), or an orphaned app rule.
        $bloat = ''; $stops = ''
        if ($kb -and $r.Enabled -and [string]$kb.roles.($c.Role) -eq 'bloat') {
            $cond = $true
            if ($kb.bloatWhen -and $kb.bloatWhen.packagesMissing) {
                $cond = $false
                if ($null -ne $c.Packages) { $cond = -not @($kb.bloatWhen.packagesMissing | Where-Object { $c.Packages.Contains([string]$_) }).Count }
            }
            if ($cond) {
                if (-not $bloatText.ContainsKey($kb.id)) {
                    $bloatText[$kb.id] = @("Not needed on a ${roleName}: $($kb.name)$(if ($kb.bloatWhen -and $kb.bloatWhen.packagesMissing) { " (the $(@($kb.bloatWhen.packagesMissing) -join ' / ') app is not installed)" }).", "Stops working: $(@($kb.neededFor) -join '; ').")
                }
                $bloat = $bloatText[$kb.id][0]; $stops = $bloatText[$kb.id][1]
            }
        }
        $windowsRule = $category -in 'CoreServices', 'WindowsConnections'
        if (-not $bloat -and [string]$r.ProgramExists -eq 'No' -and -not $windowsRule) { $bloat = 'Orphaned: the program no longer exists.'; $stops = 'Nothing: the program is gone.' }
        if ($bloat -and $notBloated.ContainsKey($name)) { $bloat = ''; $stops = '' }
        # Protected programs (anti-cheat, launchers, games): never recommended for blocking.
        $prot = ''
        $program = [string]$r.Program
        if ($program -and $program -notin 'Any', 'System') {
            $path = [Environment]::ExpandEnvironmentVariables($program)
            foreach ($k in $protRegex.Keys) { $rx = $protRegex[$k]; if ($rx -and $rx.IsMatch($path)) { $prot = $k; break } }
            if (-not $prot -and $games.Contains([System.IO.Path]::GetFileName($path))) { $prot = 'Game executable (data\games.json): blocking it may break online play.' }
        }
        $r.Origin = $category; $r.EngineOrigin = [string]$o.Category; $r.OriginName = [string]$c.Categories[$category].name; $r.Confidence = $confidence; $r.OriginReason = $reason; $r.KbId = [string]$o.KbId
        $r.KbName = $(if ($kb) { [string]$kb.name } else { '' }); $r.KbMeaning = $(if ($kb) { [string]$kb.meaning } else { '' }); $r.Facets = $facets
        $r.Assessments = $(if ($bloat) { @('Bloated') } else { @() }); $r.BloatReason = $bloat; $r.WhatStopsWorking = $stops
        $r.Protected = [bool]$prot; $r.ProtectedReason = $prot; $r.IsWindows = $windowsRule
        $r.Groups = @(@($category) + $facets + @($r.Assessments))
    }
}
function Get-IgwtFirewallOverridesPath {
    <# .SYNOPSIS The per-user file with the Firewall Manager overrides (role, categories, not bloated, ignored findings). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $dir = $(if ($env:IGWT_GUI_STATE_DIR) { $env:IGWT_GUI_STATE_DIR } else { Join-Path $env:LOCALAPPDATA 'iGWindowsTuner' })
    return (Join-Path $dir 'firewall-overrides.json')
}

function Get-IgwtFirewallOverrides {
    <#
    .SYNOPSIS
        The user's Firewall Manager overrides: Role, Categories (rule ID -> origin), NotBloated
        (rule IDs) and Ignored (finding key -> reason, until). Missing or unreadable file: empty.
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) { $Path = Get-IgwtFirewallOverridesPath }
    $o = $null
    if (Test-Path -LiteralPath $Path) { try { $o = Read-IgwtJsonFile -Path $Path } catch { Write-Verbose "Overrides not readable: $($_.Exception.Message)" } }
    [pscustomobject]@{
        Role       = $(if ($o -and $o.PSObject.Properties['Role']) { [string]$o.Role } else { '' })
        Categories = $(if ($o -and $o.Categories) { $o.Categories } else { [pscustomobject]@{} })
        NotBloated = @($(if ($o -and $o.NotBloated) { @($o.NotBloated) }))
        Ignored    = $(if ($o -and $o.Ignored) { $o.Ignored } else { [pscustomobject]@{} })
    }
}

function Set-IgwtFirewallOverride {
    <#
    .SYNOPSIS
        Changes the user's Firewall Manager overrides (the app's own per-user file, not a PC setting;
        allowed in read-only mode like the view state, DECISIONS F6): the role, a rule's category
        ("move to category"), "not bloated for me", or an ignored finding with a reason and an
        optional expiry. -Clear removes the rule's category, not-bloated or ignore entry.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Gamer', 'PowerUser', 'Sysadmin', 'Workstation')][string]$Role,
        [string]$RuleId,
        [ValidateSet('CoreServices', 'WindowsConnections', 'UserInstalled', 'CustomRules')][string]$Category,
        [switch]$NotBloated,
        [string]$IgnoreFinding, [string]$Reason, [datetime]$Until,
        [switch]$Clear, [string]$Path
    )
    if (-not $Path) { $Path = Get-IgwtFirewallOverridesPath }
    $o = Get-IgwtFirewallOverrides -Path $Path
    $cats = [ordered]@{}; foreach ($p in $o.Categories.PSObject.Properties) { $cats[$p.Name] = [string]$p.Value }
    $nb = New-Object System.Collections.Generic.List[string]; foreach ($n in @($o.NotBloated)) { if ($n -and -not $nb.Contains([string]$n)) { $nb.Add([string]$n) } }
    $ign = [ordered]@{}; foreach ($p in $o.Ignored.PSObject.Properties) { $ign[$p.Name] = $p.Value }
    $newRole = [string]$o.Role
    if ($Role) { $newRole = $Role }
    if ($RuleId -and $Category) { if ($Clear) { $cats.Remove($RuleId) } else { $cats[$RuleId] = $Category } }
    if ($RuleId -and $NotBloated) { if ($Clear) { $null = $nb.Remove($RuleId) } elseif (-not $nb.Contains($RuleId)) { $nb.Add($RuleId) } }
    if ($IgnoreFinding) {
        $key = $(if ($RuleId) { "$RuleId|$IgnoreFinding" } else { $IgnoreFinding })
        if ($Clear) { $ign.Remove($key) }
        else {
            if (-not $Reason) { throw 'Ignoring a finding needs a reason.' }
            $ign[$key] = [ordered]@{ Reason = $Reason; Until = $(if ($PSBoundParameters.ContainsKey('Until')) { $Until.ToString('o') } else { '' }); Set = (Get-Date).ToString('o') }
        }
    }
    $out = [ordered]@{ schemaVersion = 1; Role = $newRole; Categories = $cats; NotBloated = $nb.ToArray(); Ignored = $ign }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Save Firewall Manager overrides')) { return }
    $dir = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    [System.IO.File]::WriteAllText($Path, ($out | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    return (Get-IgwtFirewallOverrides -Path $Path)
}

function Test-IgwtFirewallIgnored {
    <# .SYNOPSIS True when a finding (rule ID + risk ID) is ignored and the ignore has not expired. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Overrides, [string]$RuleId, [Parameter(Mandatory = $true)][string]$RiskId, [datetime]$Now = (Get-Date))
    if (-not $Overrides.Ignored) { return $false }
    foreach ($key in @("$RuleId|$RiskId", $RiskId)) {
        $p = $Overrides.Ignored.PSObject.Properties[$key]
        if (-not $p) { continue }
        $until = [string]$p.Value.Until
        if (-not $until) { return $true }
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse($until, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt) -and $dt -gt $Now) { return $true }
    }
    return $false
}

function Export-IgwtFirewallOverrides {
    <# .SYNOPSIS Copies the Firewall Manager overrides to a file the user picks (JSON). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    $o = Get-IgwtFirewallOverrides
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export Firewall Manager overrides')) { return }
    [System.IO.File]::WriteAllText($Path, ([ordered]@{ schemaVersion = 1; kind = 'igwtFirewallOverrides'; Role = $o.Role; Categories = $o.Categories; NotBloated = @($o.NotBloated); Ignored = $o.Ignored } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

function Import-IgwtFirewallOverrides {
    <# .SYNOPSIS Replaces the Firewall Manager overrides with an exported file (validated: known role and categories only). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    $in = Read-IgwtJsonFile -Path $Path
    if ([string]$in.kind -ne 'igwtFirewallOverrides') { throw "$Path is not a Firewall Manager overrides export." }
    if ($in.Role -and [string]$in.Role -notin $script:IgwtFirewallRoleIds) { throw "Unknown role '$($in.Role)'." }
    foreach ($p in @($in.Categories.PSObject.Properties)) { if ([string]$p.Value -notin $script:IgwtFirewallOrigins) { throw "Unknown category '$($p.Value)' for $($p.Name)." } }
    $target = Get-IgwtFirewallOverridesPath
    if (-not $PSCmdlet.ShouldProcess($target, 'Import Firewall Manager overrides')) { return }
    $dir = Split-Path -Path $target -Parent
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    [System.IO.File]::WriteAllText($target, ([ordered]@{ schemaVersion = 1; Role = [string]$in.Role; Categories = $in.Categories; NotBloated = @($in.NotBloated); Ignored = $in.Ignored } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    return (Get-IgwtFirewallOverrides)
}

function Invoke-IgwtFirewallEngineClassification {
    <#
    .SYNOPSIS
        Classifies inventory rows for the change engine (in place): the origin category the locks depend
        on, with cached Authenticode results for their programs. Read-only. Throws when the knowledge
        base cannot be read, so a change is never planned without its locks.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $list = @($Rows | Where-Object { $_ })
    if (-not $list.Count) { return }
    $sig = @{}
    try { $sig = Get-IgwtFirewallSignatures -Path @($list | ForEach-Object { [string]$_.Program }) } catch { Write-Verbose "Signatures not read: $($_.Exception.Message)" }
    $ctx = Get-IgwtFirewallClassificationContext -InstalledPackages @() -Signatures $sig
    Invoke-IgwtFirewallClassification -Rows $list -Context $ctx
}

function Test-IgwtFirewallProtectedProgram {
    <# .SYNOPSIS The reason (for example 'anti-cheat') when a program path is a protected game, launcher or anti-cheat program; '' otherwise. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Program)
    if (-not $Program -or $Program -in 'Any', 'System') { return '' }
    $full = [Environment]::ExpandEnvironmentVariables($Program)
    foreach ($p in @((Get-IgwtFirewallKnowledgeBase).Apps.protected)) {
        if ((ConvertTo-IgwtFirewallWildcardRegex -Pattern @($p.programPatterns)).IsMatch($full)) { return [string]$p.reason }
    }
    return ''
}
