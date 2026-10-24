# FirewallKB.ps1
# The Firewall Manager knowledge base (data\firewall\*.json): groups and rule IDs, services, ports,
# risk rules, program knowledge, roles and the nine categories. Code only evaluates this data
# (DECISIONS F4), so a later C# version can reuse it unchanged. Read-only.

$script:IgwtFirewallKbCache = $null
$script:IgwtFirewallOrigins = @('CoreServices', 'WindowsConnections', 'UserInstalled', 'CustomRules')
$script:IgwtFirewallRoleIds = @('Gamer', 'PowerUser', 'Sysadmin', 'Workstation')
$script:IgwtFirewallSeverities = @('Critical', 'High', 'Medium', 'Low')
$script:IgwtFirewallActions = @('RestrictPrivate', 'RestrictLocalSubnet', 'Disable', 'Delete', 'Keep', 'Ignore')
# The closed set of checks a risk rule may use (evaluated by Test-IgwtFirewallRiskCheck).
$script:IgwtFirewallRiskChecks = @('enabled', 'inbound', 'outbound', 'allow', 'block', 'programAny', 'serviceAny', 'packageAny', 'portAny', 'remoteAny', 'profilePublic',
    'userWritablePath', 'unsigned', 'orphaned', 'nonWindows', 'scriptHost', 'edgeTraversal', 'localServiceRemoteAny', 'disabledSecurityRelevant', 'duplicate', 'broadPortRange', 'noDescription')

function Get-IgwtFirewallKnowledgeBase {
    <#
    .SYNOPSIS
        The firewall knowledge base (cached): Categories, Groups, Risks, PortSets, Ports, Services,
        Apps and Roles from data\firewall. -Force reads the files again.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtFirewallKbCache -and -not $Force) { return $script:IgwtFirewallKbCache }
    $dir = Join-Path (Get-IgwtDataFolder) 'firewall'
    $read = { param($name) Read-IgwtJsonFile -Path (Join-Path $dir $name) }
    $risks = & $read 'risks.json'
    $kb = [pscustomobject]@{
        Categories = @((& $read 'categories.json').categories)
        Groups     = @((& $read 'groups.json').groups)
        Risks      = @($risks.risks)
        PortSets   = $risks.portSets
        Ports      = @((& $read 'ports.json').ports)
        Services   = @((& $read 'services.json').services)
        Apps       = (& $read 'apps.json')
        Roles      = @((& $read 'roles.json').roles)
    }
    $script:IgwtFirewallKbCache = $kb
    return $kb
}

function Test-IgwtFirewallKnowledgeBase {
    <#
    .SYNOPSIS
        Validates data\firewall\*.json: required fields, valid categories, roles, severities, actions
        and risk checks, https sources, hint length (140), no duplicate ids, group strings, rule ID
        patterns or ports. Returns error strings (empty = valid).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    try { $kb = Get-IgwtFirewallKnowledgeBase -Force } catch { return @("firewall knowledge base: $($_.Exception.Message)") }
    $hasText = { param($o, $n) $o -and $o.PSObject.Properties[$n] -and ([string]$o.$n).Trim().Length -gt 0 }
    $checkSources = {
        param($label, $sources, [bool]$required)
        $list = @($sources | Where-Object { $_ })
        if ($required -and $list.Count -eq 0) { $errors.Add("${label}: no sources.") }
        foreach ($s in $list) { if ([string]$s -notmatch '^https://') { $errors.Add("${label}: source '$s' is not an https URL.") } }
    }
    $checkHint = { param($label, $o) if (-not (& $hasText $o 'hint')) { $errors.Add("${label}: missing 'hint'.") } elseif (([string]$o.hint).Length -gt 140) { $errors.Add("${label}: hint longer than 140 characters.") } }

    # Categories: the nine groups, each with its layer and texts.
    $catIds = @{}
    foreach ($c in $kb.Categories) {
        $label = "category $($c.id)"
        if ($catIds.ContainsKey([string]$c.id)) { $errors.Add("${label}: duplicate id.") } else { $catIds[[string]$c.id] = $c }
        if ([string]$c.layer -notin 'origin', 'facet', 'assessment') { $errors.Add("${label}: layer must be origin, facet or assessment.") }
        foreach ($f in 'name', 'description', 'criteria', 'handling') { if (-not (& $hasText $c $f)) { $errors.Add("${label}: missing '$f'.") } }
        & $checkHint $label $c
        & $checkSources $label $c.sources $false
    }
    foreach ($need in @($script:IgwtFirewallOrigins) + @('Inbound', 'Outbound', 'Blocked', 'Bloated', 'SecurityRisks')) { if (-not $catIds.ContainsKey($need)) { $errors.Add("categories: '$need' is missing.") } }

    # Groups: category, match, texts, roles, action, sources; no group string or rule pattern twice.
    $gIds = @{}; $gStrings = @{}; $gPatterns = @{}
    foreach ($g in $kb.Groups) {
        $label = "group $($g.id)"
        if (-not (& $hasText $g 'id')) { $errors.Add('group: missing id.'); continue }
        if ($gIds.ContainsKey([string]$g.id)) { $errors.Add("${label}: duplicate id.") } else { $gIds[[string]$g.id] = $true }
        if ([string]$g.category -notin 'CoreServices', 'WindowsConnections') { $errors.Add("${label}: category must be CoreServices or WindowsConnections (built-in groups).") }
        foreach ($f in 'name', 'meaning', 'riskNote') { if (-not (& $hasText $g $f)) { $errors.Add("${label}: missing '$f'.") } }
        & $checkHint $label $g
        if (@($g.neededFor | Where-Object { $_ }).Count -eq 0) { $errors.Add("${label}: 'neededFor' is empty.") }
        if ([string]$g.severityHint -notin 'none', 'low', 'medium', 'high') { $errors.Add("${label}: severityHint must be none, low, medium or high.") }
        if ([string]$g.recommendedAction -notin 'Keep', 'Disable', 'Restrict to Private', 'Restrict to Local Subnet') { $errors.Add("${label}: recommendedAction '$($g.recommendedAction)' is not valid.") }
        if ([string]$g.basis -notin 'microsoft', 'igwt') { $errors.Add("${label}: basis must be microsoft or igwt.") }
        foreach ($r in $script:IgwtFirewallRoleIds) {
            $v = $(if ($g.roles -and $g.roles.PSObject.Properties[$r]) { [string]$g.roles.$r } else { '' })
            if ($v -notin 'needed', 'optional', 'bloat') { $errors.Add("${label}: role '$r' must be needed, optional or bloat.") }
        }
        if ($g.category -eq 'CoreServices' -and @($script:IgwtFirewallRoleIds | Where-Object { [string]$g.roles.$_ -ne 'needed' }).Count) { $errors.Add("${label}: Core Services must be 'needed' for every role.") }
        $m = $g.match
        $count = @($m.groups | Where-Object { $_ }).Count + @($m.namePatterns | Where-Object { $_ }).Count + @($m.stores | Where-Object { $_ }).Count + @($m.packagePublishers | Where-Object { $_ }).Count
        if (-not $m -or $count -eq 0) { $errors.Add("${label}: 'match' needs groups, namePatterns, stores or packagePublishers.") }
        foreach ($s in @($m.groups | Where-Object { $_ })) { $k = ([string]$s).ToLowerInvariant(); if ($gStrings.ContainsKey($k)) { $errors.Add("${label}: group '$s' is also in $($gStrings[$k]).") } else { $gStrings[$k] = $g.id } }
        foreach ($p in @($m.namePatterns | Where-Object { $_ })) { $k = ([string]$p).ToLowerInvariant(); if ($gPatterns.ContainsKey($k)) { $errors.Add("${label}: rule pattern '$p' is also in $($gPatterns[$k]).") } else { $gPatterns[$k] = $g.id } }
        & $checkSources $label $g.sources $true
    }

    # Risk rules: severity, checks from the closed set, port sets, actions, texts, sources.
    $rIds = @{}
    $portSetNames = @(if ($kb.PortSets) { $kb.PortSets.PSObject.Properties.Name })
    foreach ($r in $kb.Risks) {
        $label = "risk $($r.id)"
        if ($rIds.ContainsKey([string]$r.id)) { $errors.Add("${label}: duplicate id.") } else { $rIds[[string]$r.id] = $true }
        if ([string]$r.severity -notin $script:IgwtFirewallSeverities) { $errors.Add("${label}: severity must be Critical, High, Medium or Low.") }
        foreach ($f in 'title', 'explanation') { if (-not (& $hasText $r $f)) { $errors.Add("${label}: missing '$f'.") } }
        & $checkHint $label $r
        if (@($r.when).Count -eq 0) { $errors.Add("${label}: 'when' is empty.") }
        foreach ($w in @($r.when)) {
            if ([string]$w -like 'ports:*') { $set = ([string]$w).Substring(6); if ($portSetNames -notcontains $set) { $errors.Add("${label}: unknown port set '$set'.") } }
            elseif ([string]$w -notin $script:IgwtFirewallRiskChecks) { $errors.Add("${label}: unknown check '$w'.") }
        }
        if ([string]$r.recommended -notin $script:IgwtFirewallActions) { $errors.Add("${label}: recommended action '$($r.recommended)' is not valid.") }
        foreach ($a in @($r.alternatives)) { if ([string]$a -notin $script:IgwtFirewallActions) { $errors.Add("${label}: alternative '$a' is not valid.") } }
        if (@($r.alternatives) -contains [string]$r.recommended) { $errors.Add("${label}: the recommended action is also listed as an alternative.") }
        if ([string]$r.recommended -eq 'Delete' -and @($r.when) -notcontains 'orphaned' -and @($r.when) -notcontains 'duplicate') { $errors.Add("${label}: Delete may only be recommended for orphaned or duplicate rules.") }
        & $checkSources $label $r.sources $true
    }

    # Ports and services.
    $pKeys = @{}
    foreach ($p in $kb.Ports) {
        $label = "port $($p.protocol) $($p.port)"
        if ([string]$p.protocol -notin 'TCP', 'UDP') { $errors.Add("${label}: protocol must be TCP or UDP.") }
        $n = 0; if (-not [int]::TryParse([string]$p.port, [ref]$n) -or $n -lt 1 -or $n -gt 65535) { $errors.Add("${label}: port must be 1-65535.") }
        $k = "$($p.protocol)/$($p.port)"; if ($pKeys.ContainsKey($k)) { $errors.Add("${label}: duplicate port.") } else { $pKeys[$k] = $true }
        foreach ($f in 'name', 'meaning') { if (-not (& $hasText $p $f)) { $errors.Add("${label}: missing '$f'.") } }
        if ([string]$p.risk -notin 'none', 'low', 'medium', 'high') { $errors.Add("${label}: risk must be none, low, medium or high.") }
        & $checkSources $label $p.sources $true
    }
    $sKeys = @{}
    foreach ($s in $kb.Services) {
        $label = "service $($s.name)"
        if ($sKeys.ContainsKey(([string]$s.name).ToLowerInvariant())) { $errors.Add("${label}: duplicate service.") } else { $sKeys[([string]$s.name).ToLowerInvariant()] = $true }
        if ([string]$s.category -notin 'CoreServices', 'WindowsConnections') { $errors.Add("${label}: category must be CoreServices or WindowsConnections.") }
        foreach ($f in 'displayName', 'meaning') { if (-not (& $hasText $s $f)) { $errors.Add("${label}: missing '$f'.") } }
        & $checkSources $label $s.sources $true
    }

    # Program knowledge and roles.
    $a = $kb.Apps
    foreach ($f in 'protected', 'scriptHosts', 'userWritable', 'microsoftPublishers', 'owned') { if (-not $a -or -not $a.PSObject.Properties[$f]) { $errors.Add("apps: missing '$f'.") } }
    foreach ($p in @($a.protected)) { if (-not (& $hasText $p 'id') -or -not (& $hasText $p 'reason') -or @($p.programPatterns).Count -eq 0) { $errors.Add("apps: protected entry '$($p.id)' needs id, programPatterns and reason.") } }
    if ($a -and $a.owned -and [string]$a.owned.namePrefix -ne $script:IgwtFirewallOwnedPrefix) { $errors.Add("apps: owned.namePrefix must be '$script:IgwtFirewallOwnedPrefix' (the prefix the Firewall Manager gives its rules).") }
    & $checkSources 'apps' $a.sources $true
    $roleIds = @($kb.Roles | ForEach-Object { [string]$_.id })
    foreach ($r in $script:IgwtFirewallRoleIds) { if ($roleIds -notcontains $r) { $errors.Add("roles: '$r' is missing.") } }
    foreach ($r in $kb.Roles) { & $checkHint "role $($r.id)" $r; if (-not (& $hasText $r 'description')) { $errors.Add("role $($r.id): missing 'description'.") } }
    # Plain output (unrolled): callers collect it with @() like the other catalog validators.
    return $errors.ToArray()
}
