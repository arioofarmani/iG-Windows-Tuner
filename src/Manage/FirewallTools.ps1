# FirewallTools.ps1
# Firewall Manager 3.4 tools: risk warnings for a rule before it is created, the comparison with the
# Windows default rules of this build, and the live connections view. Read-only.

function Get-IgwtFirewallNewRuleWarnings {
    <#
    .SYNOPSIS
        What the risk rules would say about a rule before it is created or after an edit, for
        example "Critical: Inbound allow for any program, any port, from anywhere". Evaluates the
        settings as a Custom rule with the knowledge-base risk rules. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory = $true)][hashtable]$Settings, $Rule)
    $get = { param($k, $default) if ($Settings.ContainsKey($k) -and $null -ne $Settings[$k] -and "$($Settings[$k])" -ne '') { $Settings[$k] } elseif ($Rule -and $Rule.PSObject.Properties[$k]) { $Rule.$k } else { $default } }
    $profiles = @(& $get 'Profiles' @('Any'))
    if ($Rule -and -not $Settings.ContainsKey('Profiles')) { $profiles = @($Rule.ProfileList) }
    $row = [pscustomobject]@{
        Name = '(new rule)'; DisplayName = [string](& $get 'DisplayName' 'New rule'); Enabled = $true; Direction = [string](& $get 'Direction' 'Inbound'); Action = [string](& $get 'Action' 'Allow')
        Program = [string](& $get 'Program' 'Any'); Service = [string](& $get 'Service' 'Any'); Package = ''; Owner = ''; Protocol = [string](& $get 'Protocol' 'Any')
        LocalPort = [string](& $get 'LocalPort' 'Any'); RemotePort = [string](& $get 'RemotePort' 'Any'); RemoteAddress = [string](& $get 'RemoteAddress' 'Any'); LocalAddress = [string](& $get 'LocalAddress' 'Any')
        ProfileList = $profiles; Profiles = ($profiles -join ', '); EdgeTraversal = 'Block'; Description = 'new'; RawGroup = $script:IgwtFirewallOwnedGroup; Store = 'Active'
        ProgramExists = ''; Origin = 'CustomRules'; IsWindows = $false; Protected = $false; Locked = $false; Assessments = @(); Groups = @(); Findings = @(); RiskLevel = ''; Exposed = $false; ExposedBy = @()
    }
    if ($row.Program -notin 'Any', 'System', '') { $row.ProgramExists = $(if (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($row.Program)) -PathType Leaf) { 'Yes' } else { 'No' }) }
    $none = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
    $ctx = Get-IgwtFirewallClassificationContext -Role Gamer -InstalledPackages @() -Overrides $none
    $found = @(Get-IgwtFirewallFindings -Rows @($row) -Context $ctx | Where-Object { $_.RiskId -notin 'no-description', 'duplicate', 'orphaned-program' })
    return @($found | Sort-Object @{ Expression = { @('Critical', 'High', 'Medium', 'Low').IndexOf([string]$_.Severity) } } | ForEach-Object { "$($_.Severity): $($_.Title). $($_.Hint)" })
}

function Get-IgwtFirewallBaselinePath {
    <# .SYNOPSIS Where a default-rule baseline exported in Windows Sandbox for this build is looked for. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Build)
    if (-not $Build) { $Build = [string][Environment]::OSVersion.Version.Build }
    return (Join-Path (Get-IgwtDataPath -Kind State) "firewall-baseline-$Build.json")
}

function Get-IgwtFirewallDefaultRuleSet {
    <#
    .SYNOPSIS
        The Windows default rule set of this build: rule ID -> Enabled, Direction, Action, Profile,
        Name. From the read-only SystemDefaults store (DECISIONS F2), else from a baseline exported in
        Windows Sandbox (tools\Invoke-SandboxTest.ps1 writes firewall-baseline-<build>.json to its results; copy it to the State folder). $null when neither exists.
    #>
    [CmdletBinding()]
    param([string]$BaselinePath)
    $h = @{}
    try {
        foreach ($r in @(Get-NetFirewallRule -PolicyStore SystemDefaults -ErrorAction Stop)) {
            $id = $(if ([string]$r.Name) { [string]$r.Name } else { [string]$r.InstanceID })
            $prof = $(if ($null -ne $r.Profile -and [string]$r.Profile -ne '') { $r.Profile } elseif ($r.PSObject.Properties['Profiles']) { $r.Profiles } else { $null })
            $h[$id] = [pscustomobject]@{ Name = $id; DisplayName = [string]$r.DisplayName; Enabled = ((ConvertFrom-IgwtFirewallCimValue -Kind Enabled -Value $r.Enabled) -eq 'True'); Direction = (ConvertFrom-IgwtFirewallCimValue -Kind Direction -Value $r.Direction); Action = (ConvertFrom-IgwtFirewallCimValue -Kind Action -Value $r.Action); Profile = (ConvertFrom-IgwtFirewallCimValue -Kind Profile -Value $prof); Source = 'SystemDefaults' }
        }
    } catch { Write-Verbose "SystemDefaults store not readable: $($_.Exception.Message)" }
    if ($h.Count) { return $h }
    if (-not $BaselinePath) { $BaselinePath = Get-IgwtFirewallBaselinePath }
    if (Test-Path -LiteralPath $BaselinePath) {
        try { foreach ($r in @((Read-IgwtJsonFile -Path $BaselinePath).rules)) { $h[[string]$r.Name] = [pscustomobject]@{ Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; Enabled = [bool]$r.Enabled; Direction = [string]$r.Direction; Action = [string]$r.Action; Profile = [string]$r.Profile; Source = 'Sandbox baseline' } } } catch { Write-Verbose "Baseline not readable: $($_.Exception.Message)" }
    }
    if ($h.Count) { return $h }
    return $null
}

function Compare-IgwtFirewallDefaults {
    <#
    .SYNOPSIS
        Compares the rules with the Windows default rule set: Added (not a default rule), Removed
        (a default rule that is gone) and Modified (enabled, direction, action or profiles differ).
        App and Store rules and the service hardening stores are listed as Added only when -All.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [hashtable]$Defaults, [switch]$All)
    if (-not $Defaults) { return $null }
    $byId = @{}; foreach ($r in $Rows) { if ($r) { $byId[[string]$r.Name] = $r } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $Defaults.Keys) {
        $d = $Defaults[$id]; $r = $byId[$id]
        if (-not $r) { $out.Add([pscustomobject]@{ Key = $id; Change = 'Removed'; Name = $(if ($d.DisplayName) { $d.DisplayName } else { $id }); RuleId = $id; Detail = "Windows ships this rule ($(if ($d.Enabled) { 'enabled' } else { 'disabled' }), $($d.Direction) $($d.Action)); it is not on this PC."; Rule = $null }); continue }
        $diff = @()
        if ([bool]$r.Enabled -ne [bool]$d.Enabled) { $diff += "$(if ($d.Enabled) { 'enabled' } else { 'disabled' }) by default, now $(if ($r.Enabled) { 'enabled' } else { 'disabled' })" }
        if ([string]$r.Action -ne [string]$d.Action) { $diff += "action $($d.Action) by default, now $($r.Action)" }
        if ([string]$r.Direction -ne [string]$d.Direction) { $diff += "direction $($d.Direction) by default, now $($r.Direction)" }
        if ($d.Profile -and [string]$r.Profiles -ne [string]$d.Profile) { $diff += "profiles $($d.Profile) by default, now $($r.Profiles)" }
        if ($diff.Count) { $out.Add([pscustomobject]@{ Key = $id; Change = 'Modified'; Name = [string]$r.DisplayName; RuleId = $id; Detail = ($diff -join '; ') + '.'; Rule = $r }) }
    }
    foreach ($r in $Rows) {
        if (-not $r -or $Defaults.ContainsKey([string]$r.Name)) { continue }
        if (-not $All -and ([string]$r.Store -in 'StaticServiceStore', 'ConfigurableServiceStore' -or [string]$r.Owner)) { continue }
        $out.Add([pscustomobject]@{ Key = [string]$r.Name; Change = 'Added'; Name = [string]$r.DisplayName; RuleId = [string]$r.Name; Detail = "Not a Windows default rule ($($r.OriginName))."; Rule = $r })
    }
    return $out.ToArray()
}

function Get-IgwtFirewallConnections {
    <#
    .SYNOPSIS
        Current TCP connections and UDP endpoints (read-only) with the process, its services, the
        remote address and port, and the best-matching enabled rule (the most specific rule for the
        direction, program, protocol and port; a block wins over an allow).
    .PARAMETER Rows
        Classified rules (Get-IgwtFirewallAudit) to match against; without them no rule is shown.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [object[]]$Connections, [int[]]$ListenPorts)
    $procs = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $path = ''; try { $path = [string]$p.Path } catch { $path = '' }; $procs[[int]$p.Id] = [pscustomobject]@{ Name = $p.ProcessName; Path = $path } }
    $svc = @{}
    try { foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter 'State = "Running"' -ErrorAction Stop)) { $k = [int]$s.ProcessId; if (-not $svc.ContainsKey($k)) { $svc[$k] = New-Object System.Collections.Generic.List[string] }; $svc[$k].Add([string]$s.Name) } } catch { Write-Verbose "Services not readable: $($_.Exception.Message)" }
    if ($null -eq $Connections) {
        $list = New-Object System.Collections.Generic.List[object]
        $all = @(); try { $all = @(Get-NetTCPConnection -ErrorAction Stop) } catch { Write-Verbose "TCP connections not readable: $($_.Exception.Message)" }
        if ($null -eq $ListenPorts) { $ListenPorts = @($all | Where-Object { [string]$_.State -eq 'Listen' } | ForEach-Object { [int]$_.LocalPort } | Select-Object -Unique) }
        try { foreach ($c in @($all | Where-Object { [string]$_.State -ne 'Listen' })) { $list.Add([pscustomobject]@{ Protocol = 'TCP'; LocalAddress = [string]$c.LocalAddress; LocalPort = [int]$c.LocalPort; RemoteAddress = [string]$c.RemoteAddress; RemotePort = [int]$c.RemotePort; State = [string]$c.State; ProcessId = [int]$c.OwningProcess }) } } catch { Write-Verbose "TCP connections not readable: $($_.Exception.Message)" }
        try { foreach ($u in @(Get-NetUDPEndpoint -ErrorAction Stop)) { $list.Add([pscustomobject]@{ Protocol = 'UDP'; LocalAddress = [string]$u.LocalAddress; LocalPort = [int]$u.LocalPort; RemoteAddress = ''; RemotePort = 0; State = 'Endpoint'; ProcessId = [int]$u.OwningProcess }) } } catch { Write-Verbose "UDP endpoints not readable: $($_.Exception.Message)" }
        $Connections = $list.ToArray()
    }
    $enabled = @($Rows | Where-Object { $_ -and $_.Enabled })
    # Index the rules once: by direction, then by program path (rules for any program in their own list),
    # with the port ranges parsed up front, so each connection only looks at its candidates.
    $index = @{ Inbound = @{ Any = New-Object System.Collections.Generic.List[object]; ByPath = @{} }; Outbound = @{ Any = New-Object System.Collections.Generic.List[object]; ByPath = @{} } }
    foreach ($r in $enabled) {
        $dir = [string]$r.Direction
        if (-not $index.ContainsKey($dir)) { continue }
        $port = $(if ($dir -eq 'Outbound') { [string]$r.RemotePort } else { [string]$r.LocalPort })
        $prog = [string]$r.Program
        $e = [pscustomobject]@{
            Rule = $r; Protocol = [string]$r.Protocol; Service = [string]$r.Service; Block = ([string]$r.Action -eq 'Block')
            Ranges = $(if ($port -and $port -ne 'Any') { @(ConvertTo-IgwtFirewallPortRanges -Port $port) } else { $null })
        }
        if ($prog -in 'Any', '', 'System') { $index[$dir].Any.Add($e) }
        else {
            $k = [Environment]::ExpandEnvironmentVariables($prog).ToLowerInvariant()
            if (-not $index[$dir].ByPath.ContainsKey($k)) { $index[$dir].ByPath[$k] = New-Object System.Collections.Generic.List[object] }
            $index[$dir].ByPath[$k].Add($e)
        }
    }
    foreach ($c in $Connections) {
        $pr = $procs[[int]$c.ProcessId]
        $path = $(if ($pr) { [string]$pr.Path } else { '' })
        $services = @($(if ($svc.ContainsKey([int]$c.ProcessId)) { $svc[[int]$c.ProcessId].ToArray() }))
        $loopback = ([string]$c.RemoteAddress -in '127.0.0.1', '::1') -or ([string]$c.LocalAddress -in '127.0.0.1', '::1' -and [string]$c.Protocol -eq 'UDP')
        # A connection to a local listening port was accepted (inbound); others were started here (outbound).
        $direction = $(if ([string]$c.Protocol -eq 'UDP' -or @($ListenPorts) -contains [int]$c.LocalPort) { 'Inbound' } else { 'Outbound' })
        $best = $null; $bestScore = -1
        if (-not $loopback) {
            $want = $(if ($direction -eq 'Outbound') { [int]$c.RemotePort } else { [int]$c.LocalPort })
            $byPath = $(if ($path) { $index[$direction].ByPath[$path.ToLowerInvariant()] } else { $null })
            foreach ($set in @(@{ List = $byPath; Score = 4 }, @{ List = $index[$direction].Any; Score = 0 })) {
                if (-not $set.List) { continue }
                foreach ($e in $set.List) {
                    if ($e.Protocol -notin 'Any', '' -and $e.Protocol -ne [string]$c.Protocol) { continue }
                    $score = $set.Score
                    if ($e.Service -notin 'Any', '') { if ($services -notcontains $e.Service) { continue }; $score += 2 }
                    if ($null -ne $e.Ranges) {
                        $hit = $false; foreach ($x in $e.Ranges) { if ($x.Low -ge 0 -and $want -ge $x.Low -and $want -le $x.High) { $hit = $true; break } }
                        if (-not $hit) { continue }; $score += 2
                    }
                    if ($e.Block) { $score += 10 }
                    if ($score -gt $bestScore) { $best = $e.Rule; $bestScore = $score }
                }
            }
        }
        [pscustomobject]@{
            Key = "$($c.Protocol)|$($c.LocalAddress)|$($c.LocalPort)|$($c.RemoteAddress)|$($c.RemotePort)|$($c.ProcessId)"
            Protocol = [string]$c.Protocol; Local = "$($c.LocalAddress):$($c.LocalPort)"; Remote = $(if ($c.RemoteAddress) { "$($c.RemoteAddress):$($c.RemotePort)" } else { '' }); State = [string]$c.State
            Process = $(if ($pr) { [string]$pr.Name } else { "PID $($c.ProcessId)" }); Path = $path; Services = ($services -join ', ')
            Direction = $(if ($loopback) { 'This PC' } else { $direction })
            Rule = $(if ($best) { [string]$best.DisplayName } elseif ($loopback) { 'Not filtered (loopback)' } elseif ($direction -eq 'Outbound') { 'No rule: outbound is allowed by default' } else { 'No rule: inbound is blocked by default' })
            RuleId = $(if ($best) { [string]$best.Name } else { '' }); RuleAction = $(if ($best) { [string]$best.Action } else { '' })
        }
    }
}

# Firewall-scope presets (data\firewall\scopes.json).

function Get-IgwtFirewallScopes {
    <# .SYNOPSIS The firewall-scope presets (data\firewall\scopes.json). #>
    [CmdletBinding()]
    param()
    return @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'firewall\scopes.json')).scopes)
}

function Get-IgwtFirewallScopePlan {
    <#
    .SYNOPSIS
        What a firewall scope would change on this PC (read-only): the rules are classified for the
        scope's role on copies (the audit shown on screen is not changed), then the Bloated quick wins
        and the scope's risk recommendations become change batches with Get-IgwtFirewallFixPlan
        (skipped rules listed with the reason).
    .PARAMETER Rows
        Inventory or audit rows (Get-IgwtFirewallAudit). Read from the PC when omitted.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scope, [object[]]$Rows, [object[]]$Listeners = @(), [hashtable]$Signatures = @{}, [Nullable[bool]]$RemoteSession)
    $s = @(Get-IgwtFirewallScopes | Where-Object { [string]$_.id -eq $Scope })[0]
    if (-not $s) { throw "Unknown firewall scope '$Scope'. Known: $(@(Get-IgwtFirewallScopes | ForEach-Object { $_.id }) -join ', ')." }
    if (-not $Rows) { $Rows = @((Get-IgwtFirewallInventory).Rules) }
    $copies = @($Rows | Where-Object { $_ } | ForEach-Object { $_.PSObject.Copy() })
    $ctx = Get-IgwtFirewallClassificationContext -Role ([string]$s.role) -InstalledPackages (Get-IgwtFirewallInstalledPackages) -Signatures $Signatures
    Invoke-IgwtFirewallClassification -Rows $copies -Context $ctx
    $null = Get-IgwtFirewallFindings -Rows $copies -Context $ctx -Listeners $Listeners
    $decisions = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if ($s.applyBloat) {
        foreach ($r in @(Get-IgwtFirewallAuditSummary -Rows $copies).QuickWins) { $decisions.Add([pscustomobject]@{ RuleId = [string]$r; Action = 'Disable' }); $seen["$r|Disable"] = $true }
    }
    $wanted = @($s.risks)
    foreach ($r in $copies) {
        foreach ($f in @($r.Findings | Where-Object { $_ -and -not $_.Ignored -and $wanted -contains [string]$_.RiskId -and [string]$_.Recommended -notin 'Keep', 'Ignore' })) {
            $k = "$($r.Name)|$($f.Recommended)"
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            $decisions.Add([pscustomobject]@{ RuleId = [string]$r.Name; Action = [string]$f.Recommended })
        }
    }
    # One action per rule: Delete beats Disable beats a restriction (the stronger fix makes the others moot).
    $rank = @{ Delete = 0; Disable = 1; RestrictPrivate = 2; RestrictLocalSubnet = 3 }
    $final = @($decisions | Group-Object RuleId | ForEach-Object { @($_.Group | Sort-Object { $rank[[string]$_.Action] })[0] })
    $batches = @(Get-IgwtFirewallFixPlan -Decisions $final -Rows $copies -RemoteSession $RemoteSession)
    [pscustomobject]@{ Scope = $s; Batches = $batches; Count = [int](@($batches | ForEach-Object { $_.Plan.Count }) | Measure-Object -Sum).Sum; Rows = $copies }
}
