# FirewallAudit.ps1
# Firewall Manager 3.4: one read-only call that reads every rule (active policy plus the Windows
# Service Hardening stores), classifies it, evaluates the risk rules and live exposure, analyses
# precedence and summarises the result for the overview dashboard. Runs in the GUI's background
# pool; every step is timed.

function Get-IgwtFirewallInstalledPackages {
    <# .SYNOPSIS Names of the AppX packages installed for the current user (read-only), for bloatWhen conditions; $null when unreadable. #>
    [CmdletBinding()]
    param()
    try { return @(Get-AppxPackage -ErrorAction Stop | ForEach-Object { [string]$_.Name } | Select-Object -Unique) } catch { Write-Verbose "Packages not readable: $($_.Exception.Message)"; return $null }
}

function Get-IgwtFirewallDefaultRuleState {
    <#
    .SYNOPSIS
        The Windows default rule set of this build from the read-only SystemDefaults store
        (DECISIONS F2): rule ID -> enabled. $null when the store cannot be read.
    #>
    [CmdletBinding()]
    param()
    try {
        $h = @{}
        foreach ($r in @(Get-NetFirewallRule -PolicyStore SystemDefaults -ErrorAction Stop)) {
            $id = $(if ([string]$r.Name) { [string]$r.Name } else { [string]$r.InstanceID })
            $h[$id] = ((ConvertFrom-IgwtFirewallCimValue -Kind Enabled -Value $r.Enabled) -eq 'True')
        }
        return $h
    } catch { Write-Verbose "SystemDefaults store not readable: $($_.Exception.Message)"; return $null }
}

function Get-IgwtFirewallAuditSummary {
    <#
    .SYNOPSIS
        Counts for the overview: per origin category, facet and assessment, findings per severity
        (open, exposed), locked rules and the quick wins (enabled Bloated rules that can be disabled
        safely: not Core Services, not locked, not protected).
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $count = { param($test) @($Rows | Where-Object $test).Count }
    $groups = [ordered]@{}
    foreach ($g in 'CoreServices', 'WindowsConnections', 'UserInstalled', 'CustomRules', 'Inbound', 'Outbound', 'Blocked', 'Bloated', 'SecurityRisks') { $groups[$g] = 0 }
    foreach ($r in $Rows) { foreach ($g in @($r.Groups)) { if ($groups.Contains([string]$g)) { $groups[[string]$g]++ } } }
    $open = @($Rows | ForEach-Object { @($_.Findings) } | Where-Object { $_ -and -not $_.Ignored })
    $sev = [ordered]@{}; foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $sev[$s] = @($open | Where-Object Severity -EQ $s).Count }
    $quick = @($Rows | Where-Object { $_.Enabled -and @($_.Assessments) -contains 'Bloated' -and $_.Origin -ne 'CoreServices' -and -not $_.Locked -and -not $_.Protected })
    [pscustomobject]@{
        Total = @($Rows).Count; Enabled = & $count { $_.Enabled }; Groups = [pscustomobject]$groups; Severity = [pscustomobject]$sev
        NeedsAttention = [int]$sev.Critical + [int]$sev.High; Exposed = & $count { $_.Exposed }; Locked = & $count { $_.Locked }
        Shadowed = & $count { $_.Shadowed }; Redundant = & $count { $_.Redundant }; Conflicting = & $count { @($_.Conflicts).Count -gt 0 }
        LowConfidence = & $count { $_.Confidence -eq 'Low' }; QuickWins = @($quick | ForEach-Object { [string]$_.Name })
        InboundAllow = & $count { $_.Enabled -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }; InboundBlock = & $count { $_.Enabled -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }
        OutboundAllow = & $count { $_.Enabled -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow' }; OutboundBlock = & $count { $_.Enabled -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }
    }
}

function Get-IgwtFirewallAudit {
    <#
    .SYNOPSIS
        Reads, classifies and audits every firewall rule (read-only): origin category, facets,
        Bloated, risk findings with live exposure, shadowed/redundant/conflicting rules and the
        overview counts. Every step is timed.
    .PARAMETER Role
        Gamer, PowerUser, Sysadmin or Workstation (default: the override, else the persona).
    .PARAMETER Inventory
        A Get-IgwtFirewallInventory result to audit instead of reading the PC (tests, refresh of a
        few rules).
    .PARAMETER NoListeners
        Skip the exposure check (listening ports).
    .PARAMETER NoSignatures
        Skip the Authenticode checks (faster; unsigned programs are not flagged).
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Gamer', 'PowerUser', 'Sysadmin', 'Workstation')][string]$Role,
        $Inventory, [switch]$NoListeners, [switch]$NoSignatures,
        [object[]]$Listeners, [string[]]$InstalledPackages, [hashtable]$DefaultRules, [hashtable]$Signatures
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timing = [ordered]@{}
    $step = { param($name, $block) $t0 = $sw.ElapsedMilliseconds; $v = & $block; $timing[$name] = $sw.ElapsedMilliseconds - $t0; if ($null -eq $v) { return $null }; , $v }
    $inv = $(if ($Inventory) { $Inventory } else { & $step 'Inventory' { Get-IgwtFirewallInventory } })
    $rows = @($inv.Rules)
    if (-not $PSBoundParameters.ContainsKey('InstalledPackages')) { $InstalledPackages = & $step 'Packages' { Get-IgwtFirewallInstalledPackages } }
    if (-not $PSBoundParameters.ContainsKey('DefaultRules')) { $DefaultRules = & $step 'Defaults' { Get-IgwtFirewallDefaultRuleState } }
    if (-not $Signatures) {
        $Signatures = @{}
        if (-not $NoSignatures) {
            # Programs outside the Windows folder only: Windows binaries are catalog-signed and slow to check.
            $windir = [Environment]::GetFolderPath('Windows')
            $paths = @($rows | Where-Object { [string]$_.Program -notin 'Any', 'System', '' } | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_.Program) } | Where-Object { $_ -notlike "$windir\*" } | Select-Object -Unique)
            $Signatures = & $step 'Signatures' { Get-IgwtFirewallSignatures -Path $paths }
        }
    }
    if (-not $PSBoundParameters.ContainsKey('Listeners')) { $Listeners = $(if ($NoListeners) { $null } else { & $step 'Listeners' { Get-IgwtFirewallListeners } }) }
    $ctx = & $step 'Context' { Get-IgwtFirewallClassificationContext -Role $Role -InstalledPackages $InstalledPackages -Signatures $Signatures }
    $null = & $step 'Classify' { Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx }
    $defaultEnabled = $(if ($DefaultRules) { @($DefaultRules.Keys | Where-Object { $DefaultRules[$_] }) } else { $null })
    $findings = & $step 'Findings' { Get-IgwtFirewallFindings -Rows $rows -Context $ctx -Listeners $Listeners -DefaultEnabled $defaultEnabled }
    $relations = & $step 'Precedence' { Get-IgwtFirewallConflicts -Rows $rows }
    $exposure = & $step 'Exposure' { @(Get-IgwtFirewallExposureMap -Rows $rows -Listeners @($Listeners | Where-Object { $_ })) }
    $recent = & $step 'History' { @(Get-IgwtSnapshotList | Where-Object { [string]$_.Operation -like 'Firewall*' } | Select-Object -First 8 | ForEach-Object { [pscustomobject]@{ Path = [string]$_.Path; Created = $_.Created; Operation = [string]$_.Operation; Detail = $(if ($_.Detail) { [string]$_.Detail } else { [string]$_.Operation }); Rules = @($_.Entries | ForEach-Object { [string]$_.Name }) } }) }
    $summary = & $step 'Summary' { Get-IgwtFirewallAuditSummary -Rows $rows }
    $total = $sw.ElapsedMilliseconds
    Write-IgwtLog -Message ("Firewall audit: {0} rules in {1} ms ({2})" -f $rows.Count, $total, (@($timing.Keys | ForEach-Object { "$_ $($timing[$_]) ms" }) -join ', '))
    [pscustomobject]@{
        Rules = $rows; Count = $rows.Count; Summary = $summary; Findings = @($findings); Relations = @($relations); Listeners = @($Listeners | Where-Object { $_ })
        Exposure = @($exposure); RecentChanges = @($recent); Context = $ctx
        Role = $ctx.Role; Partial = [bool]$inv.Partial; Notes = @($inv.Notes); HasDefaults = ($null -ne $DefaultRules); DefaultRules = $DefaultRules
        Timing = [pscustomobject]$timing; LoadMs = $total; InventoryMs = [int]$inv.LoadMs; Read = (Get-Date)
    }
}

function Get-IgwtFirewallWizardSteps {
    <#
    .SYNOPSIS
        The smart fix wizard's steps: every open finding, most severe first (exposed before not
        exposed), one step per rule and finding.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $steps = foreach ($r in @($Rows | Where-Object { $_ })) {
        foreach ($f in @($r.Findings | Where-Object { $_ -and -not $_.Ignored })) { [pscustomobject]@{ RuleId = [string]$r.Name; Rule = $r; Finding = $f; Rank = [int]$order[[string]$f.Severity]; Exposed = [bool]$f.ExposedNow } }
    }
    return @($steps | Sort-Object Rank, @{ Expression = { -not $_.Exposed } }, @{ Expression = { [string]$_.Rule.DisplayName } })
}

function ConvertTo-IgwtFirewallChangeRequest {
    <#
    .SYNOPSIS
        A finding action as a Firewall Manager change: Disable, Delete, or Edit with Profiles
        (Restrict to Private) or RemoteAddress (Restrict to local subnet). Keep and Ignore change
        nothing ($null).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('RestrictPrivate', 'RestrictLocalSubnet', 'Disable', 'Delete', 'Keep', 'Ignore')][string]$Action)
    switch ($Action) {
        'Disable' { return @{ Operation = 'Disable'; Settings = @{} } }
        'Delete' { return @{ Operation = 'Delete'; Settings = @{} } }
        'RestrictPrivate' { return @{ Operation = 'Edit'; Settings = @{ Profiles = @('Private') } } }
        'RestrictLocalSubnet' { return @{ Operation = 'Edit'; Settings = @{ RemoteAddress = 'LocalSubnet' } } }
    }
    return $null
}

function Get-IgwtFirewallFixPlan {
    <#
    .SYNOPSIS
        Groups the wizard's Fix decisions into change batches (one per action) and plans each with
        Get-IgwtFirewallChangePlan, so the summary lists what will change and what is refused
        (locked, Core Services, Windows rules that cannot be deleted ...). Read-only.
    .PARAMETER Decisions
        @{ RuleId; Action } for each Fix decision.
    #>
    [CmdletBinding()]
    param([object[]]$Decisions = @(), [object[]]$Rows = @(), [Nullable[bool]]$RemoteSession)
    $byId = @{}; foreach ($r in $Rows) { if ($r) { $byId[[string]$r.Name] = $r } }
    $batches = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Decisions | Where-Object { $_ -and $_.Action -notin 'Keep', 'Ignore' } | Group-Object { [string]$_.Action })) {
        $req = ConvertTo-IgwtFirewallChangeRequest -Action $g.Name
        $rules = @($g.Group | ForEach-Object { $byId[[string]$_.RuleId] } | Where-Object { $_ } | Sort-Object Name -Unique)
        $plan = Get-IgwtFirewallChangePlan -Operation $req.Operation -Rules $rules -Settings $req.Settings -RemoteSession $RemoteSession
        $batches.Add([pscustomobject]@{ Action = $g.Name; Operation = $req.Operation; Settings = $req.Settings; Plan = $plan; Rules = $rules })
    }
    return $batches.ToArray()
}

function Get-IgwtFirewallExposureMap {
    <#
    .SYNOPSIS
        One row per listening port: protocol, port, address, process, path, services, the enabled
        inbound allow rules that let traffic reach it, their profiles, and the status: Exposed (a
        rule allows it), Blocked (no allow rule: the default inbound block applies), Local only
        (loopback), or Unknown (the rule filters need administrator rights to read).
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [object[]]$Listeners = @())
    $allow = @($Rows | Where-Object { $_ -and $_.Enabled -and [string]$_.Direction -eq 'Inbound' -and [string]$_.Action -eq 'Allow' })
    $readable = @($allow | Where-Object { [string]$_.Protocol }).Count -gt 0 -or $allow.Count -eq 0
    foreach ($l in @($Listeners | Where-Object { $_ } | Sort-Object Protocol, LocalPort -Unique)) {
        $match = @()
        if (-not $l.Local) { $match = @(foreach ($r in $allow) { if (Test-IgwtFirewallListenerMatch -Row $r -Listener $l) { $r } }) }
        $status = $(if ($l.Local) { 'Local only' } elseif ($match.Count) { 'Exposed' } elseif (-not $readable) { 'Unknown' } else { 'Blocked' })
        $profiles = @($match | ForEach-Object { @($_.ProfileList) } | Where-Object { $_ } | Select-Object -Unique)
        [pscustomobject]@{
            Key = "$($l.Protocol)|$($l.LocalPort)|$($l.LocalAddress)"; Protocol = [string]$l.Protocol; LocalPort = [int]$l.LocalPort; LocalAddress = [string]$l.LocalAddress
            Process = [string]$l.ProcessName; Path = [string]$l.Path; Services = (@($l.Services) -join ', ')
            Rules = (@($match | ForEach-Object { [string]$_.DisplayName }) -join '; '); RuleIds = @($match | ForEach-Object { [string]$_.Name }); RuleCount = $match.Count
            Profiles = $(if ($profiles -contains 'Any') { 'All networks' } else { $profiles -join ', ' }); Status = $status
            Public = ($profiles -contains 'Any' -or $profiles -contains 'Public')
        }
    }
}

function Format-IgwtFirewallRuleSummary {
    <#
    .SYNOPSIS
        One plain sentence that says what a rule does, generated from its fields, for example
        "Allows incoming UDP on port 27015 to steam.exe from any address, on Private and Public
        networks." Unreadable filters (not elevated) are named instead of guessed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Row)
    $r = $Row
    $inbound = [string]$r.Direction -ne 'Outbound'
    $verb = $(if ([string]$r.Action -eq 'Block') { 'Blocks' } else { 'Allows' })
    $dir = $(if ($inbound) { 'incoming' } else { 'outgoing' })
    $proto = [string]$r.Protocol
    $what = $(if (-not $proto) { 'traffic' } elseif ($proto -eq 'Any') { 'traffic of any protocol' } else { $proto })
    $portText = ''
    $lp = [string]$r.LocalPort; $rp = [string]$r.RemotePort
    $port = $(if ($inbound) { $lp } else { $(if ($rp -and $rp -ne 'Any') { $rp } else { $lp }) })
    if ($proto -in 'TCP', 'UDP') {
        if (-not $port) { $portText = '' }
        elseif ($port -eq 'Any') { $portText = ' on any port' }
        elseif ($port -match '[,-]') { $portText = " on ports $port" }
        else { $portText = " on port $port" }
    }
    $program = [string]$r.Program
    $target = $(if ($program -and $program -notin 'Any', 'System') { [System.IO.Path]::GetFileName([Environment]::ExpandEnvironmentVariables($program)) } elseif ($program -eq 'System') { 'the System process' } else { '' })
    $service = [string]$r.Service
    $who = ''
    if ($target -and $service -and $service -ne 'Any') { $who = "$target (service $service)" }
    elseif ($target) { $who = $target }
    elseif ($service -and $service -ne 'Any') { $who = "the $service service" }
    elseif ([string]$r.Package -or [string]$r.Owner) { $who = 'a Store app' }
    else { $who = 'any program' }
    $whoText = $(if ($inbound) { " to $who" } else { " from $who" })
    $remote = [string]$r.RemoteAddress
    $remoteText = $(if (-not $remote) { '' } elseif ($remote -eq 'Any') { ' any address' } elseif ($remote -eq 'LocalSubnet') { ' your local subnet' } else { " $remote" })
    if ($remoteText) { $remoteText = $(if ($inbound) { " from$remoteText" } else { " to$remoteText" }) }
    $profiles = @($r.ProfileList | Where-Object { $_ })
    $netText = $(if (-not $profiles.Count -or $profiles -contains 'Any') { 'on all networks' } elseif ($profiles.Count -eq 1) { "on $($profiles[0]) networks" } else { "on $(@($profiles[0..($profiles.Count - 2)]) -join ', ') and $($profiles[-1]) networks" })
    $s = "$verb $dir $what$portText$whoText$remoteText, $netText."
    if (-not $proto) { $s += ' Ports and addresses can only be read with administrator rights.' }
    if (-not $r.Enabled) { $s = "Turned off. When on, it: $($s.Substring(0, 1).ToLowerInvariant())$($s.Substring(1))" }
    return $s
}
