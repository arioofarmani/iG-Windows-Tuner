# FirewallPrecedence.ps1
# Firewall Manager 3.4 conflict and precedence analysis (DECISIONS F3). Windows Defender Firewall
# applies authenticated bypass, then block, then allow, then the profile default; there is no
# administrator-assigned order. From that model, for enabled rules of the same direction:
#   Shadowed     an allow rule whose traffic is entirely covered by a block rule (it never applies)
#   Redundant    an app or custom rule entirely covered by a broader rule with the same action
#   Conflicting  an allow and a block that overlap partly (the block wins on the overlap)
# Pairs of two Windows rules are not compared: they differ in settings the inventory does not read
# (user and computer restrictions, dynamic targets), and Windows rules are never deleted anyway.
# Authenticated-bypass (IPsec "override block rules") settings are not read by the inventory; rules
# are marked as not evaluated for it rather than guessed.

function Test-IgwtFirewallSetCovers {
    <#
    .SYNOPSIS
        Coverage and overlap of one rule dimension. Mode Covers: every value of B is allowed by A.
        Mode Overlaps: A and B share at least one value. 'Any' (or empty) means everything; values
        compare case-insensitively; Ports compares numeric ranges.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$A, [string]$B, [ValidateSet('Covers', 'Overlaps')][string]$Mode = 'Covers', [switch]$Ports)
    $anyA = ($A -in '', 'Any'); $anyB = ($B -in '', 'Any')
    if ($anyA) { return $true }
    if ($anyB) { return ($Mode -eq 'Overlaps') }
    if ($Ports) {
        $ra = @(ConvertTo-IgwtFirewallPortRanges -Port $A); $rb = @(ConvertTo-IgwtFirewallPortRanges -Port $B)
        # Keywords (RPC, IPHTTPS ...) only match the same keyword text.
        if (@($ra + $rb | Where-Object { $_.Low -lt 0 }).Count) { $ka = @($A -split ',\s*'); $kb = @($B -split ',\s*'); if ($Mode -eq 'Covers') { return -not @($kb | Where-Object { $ka -notcontains $_ }).Count } else { return [bool]@($kb | Where-Object { $ka -contains $_ }).Count } }
        if ($Mode -eq 'Overlaps') { foreach ($x in $ra) { foreach ($y in $rb) { if ($x.Low -le $y.High -and $y.Low -le $x.High) { return $true } } }; return $false }
        foreach ($y in $rb) { $inside = $false; foreach ($x in $ra) { if ($y.Low -ge $x.Low -and $y.High -le $x.High) { $inside = $true; break } }; if (-not $inside) { return $false } }
        return $true
    }
    $sa = @($A -split ',\s*' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }); $sb = @($B -split ',\s*' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    if ($Mode -eq 'Covers') { return -not @($sb | Where-Object { $sa -notcontains $_ }).Count }
    return [bool]@($sb | Where-Object { $sa -contains $_ }).Count
}

function Get-IgwtFirewallRuleScope {
    <#
    .SYNOPSIS
        The dimensions the precedence engine compares, parsed once per rule: program and service
        (lower case), package, protocol, port ranges and keywords, remote address, ICMP type,
        profile and interface sets. 'Any' (or empty) is stored as Any = $true.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $r = $Row
    $program = [string]$r.Program
    if ($program -and $program -notin 'Any', 'System') { $program = ([Environment]::ExpandEnvironmentVariables($program)).ToLowerInvariant() } elseif (-not $program) { $program = 'Any' }
    $set = {
        param($text)
        $t = [string]$text
        if ($t -in '', 'Any') { return @{ Any = $true; Items = $null } }
        $h = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($i in ($t -split ',\s*')) { if ($i) { $null = $h.Add($i.Trim()) } }
        return @{ Any = $false; Items = $h }
    }
    $lp = [string]$r.LocalPort
    $ports = @{ Any = ($lp -in '', 'Any'); Ranges = @(); Keywords = $null }
    if (-not $ports.Any) {
        $kw = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $ports.Ranges = @(foreach ($part in ($lp -split ',\s*')) { $m = [regex]::Match($part.Trim(), '^(\d+)(?:-(\d+))?$'); if ($m.Success) { , @([int]$m.Groups[1].Value, $(if ($m.Groups[2].Success) { [int]$m.Groups[2].Value } else { [int]$m.Groups[1].Value })) } elseif ($part) { $null = $kw.Add($part.Trim()) } })
        $ports.Keywords = $kw
    }
    $profiles = @($r.ProfileList | Where-Object { $_ })
    [pscustomobject]@{
        Program = $program; Service = $(if ([string]$r.Service -and [string]$r.Service -ne 'Any') { ([string]$r.Service).ToLowerInvariant() } else { 'any' })
        Package = (([string]$r.Package) + '|' + ([string]$r.Owner)).ToLowerInvariant()
        Protocol = $(if ([string]$r.Protocol) { [string]$r.Protocol } else { '?' }); Ports = $ports
        Remote = (& $set $r.RemoteAddress); Icmp = (& $set $r.IcmpType)
        Profiles = $(if (-not $profiles.Count -or $profiles -contains 'Any') { & $set 'Any' } else { & $set ($profiles -join ',') })
        Interface = (& $set $r.InterfaceType)
    }
}
function Test-IgwtFirewallScopeRelation {
    <#
    .SYNOPSIS
        'Covers' when scope A includes all traffic of scope B, 'Overlaps' when they share some
        traffic, '' when they are disjoint. Scopes come from Get-IgwtFirewallRuleScope. Rules whose
        port or address filters were not readable (protocol unknown) are never compared.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$A, [Parameter(Mandatory = $true)]$B)
    if ($A.Protocol -eq '?' -or $B.Protocol -eq '?' -or $A.Package -ne $B.Package) { return '' }
    $covers = $true
    # Single-value dimensions: Any covers everything; otherwise equal values only. (Loop variables
    # are $va/$vb: PowerShell names are case-insensitive, so $a would overwrite the parameter $A.)
    foreach ($pair in @(@($A.Program, $B.Program), @($A.Service, $B.Service), @($A.Protocol, $B.Protocol))) {
        $va = $pair[0]; $vb = $pair[1]
        if ($va -eq 'any') { continue }
        if ($vb -eq 'any') { $covers = $false; continue }
        if ($va -ne $vb) { return '' }
    }
    # Set dimensions (remote address, ICMP type, profiles, interface types).
    foreach ($pair in @(@($A.Remote, $B.Remote), @($A.Icmp, $B.Icmp), @($A.Profiles, $B.Profiles), @($A.Interface, $B.Interface))) {
        $va = $pair[0]; $vb = $pair[1]
        if ($va.Any) { continue }
        if ($vb.Any) { $covers = $false; continue }
        $shared = $false; $all = $true
        foreach ($i in $vb.Items) { if ($va.Items.Contains($i)) { $shared = $true } else { $all = $false } }
        if (-not $shared) { return '' }
        if (-not $all) { $covers = $false }
    }
    # Local ports: numeric ranges; keywords (RPC, IPHTTPS ...) only match the same keyword.
    $pa = $A.Ports; $pb = $B.Ports
    if (-not $pa.Any) {
        if ($pb.Any) { $covers = $false }
        else {
            $shared = $false; $all = $true
            foreach ($y in $pb.Ranges) {
                $inside = $false
                foreach ($q in $pa.Ranges) { if ($y[0] -le $q[1] -and $q[0] -le $y[1]) { $shared = $true }; if ($y[0] -ge $q[0] -and $y[1] -le $q[1]) { $inside = $true } }
                if (-not $inside) { $all = $false }
            }
            foreach ($k in $pb.Keywords) { if ($pa.Keywords.Contains($k)) { $shared = $true } else { $all = $false } }
            if (-not $shared) { return '' }
            if (-not $all) { $covers = $false }
        }
    }
    if ($covers) { return 'Covers' }
    return 'Overlaps'
}
function Get-IgwtFirewallConflicts {
    <#
    .SYNOPSIS
        Shadowed, redundant and conflicting rules among the enabled rules (in place) and the list of
        relations. Each row gets Shadowed, ShadowedBy, Redundant, RedundantWith, Conflicts and a plain
        PrecedenceText. Rules are compared only within the same direction and where the programs
        match (or one is any program), which keeps 1,000 rules fast.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @())
    $active = @($Rows | Where-Object { $_ -and $_.Enabled -and [string]$_.Action -in 'Allow', 'Block' })
    $scope = @{}; foreach ($r in $active) { $scope[[string]$r.Name] = Get-IgwtFirewallRuleScope -Row $r }
    $info = @{}; foreach ($r in @($Rows | Where-Object { $_ })) { $info[[string]$r.Name] = [pscustomobject]@{ ShadowedBy = New-Object System.Collections.Generic.List[string]; RedundantWith = New-Object System.Collections.Generic.List[string]; Conflicts = New-Object System.Collections.Generic.List[string] } }
    $relations = New-Object System.Collections.Generic.List[object]
    $label = @{}; foreach ($r in @($Rows | Where-Object { $_ })) { $label[[string]$r.Name] = $(if ([string]$r.DisplayName) { [string]$r.DisplayName } else { [string]$r.Name }) }
    foreach ($dir in 'Inbound', 'Outbound') {
        $set = @($active | Where-Object { [string]$_.Direction -eq $dir })
        # Buckets by program and protocol: a rule can only relate to rules of the same program and
        # protocol, or to any-program / any-protocol rules.
        $bucket = @{}
        foreach ($r in $set) {
            $sc = $scope[[string]$r.Name]
            if ($sc.Protocol -eq '?') { continue }
            $k = "$($sc.Program)|$($sc.Protocol)"
            if (-not $bucket.ContainsKey($k)) { $bucket[$k] = New-Object System.Collections.Generic.List[object] }
            $bucket[$k].Add($r)
        }
        foreach ($a in $set) {
            $sa = $scope[[string]$a.Name]
            if ($sa.Protocol -eq '?') { continue }
            $keys = @("$($sa.Program)|$($sa.Protocol)", "$($sa.Program)|Any", "any|$($sa.Protocol)", 'any|Any') | Select-Object -Unique
            if ($sa.Protocol -eq 'Any') { $keys = @($bucket.Keys | Where-Object { $_ -like "$($sa.Program)|*" -or $_ -like 'any|*' }) }
            if ($sa.Program -eq 'any') { $keys = @($bucket.Keys | Where-Object { $sa.Protocol -eq 'Any' -or $_ -like "*|$($sa.Protocol)" -or $_ -like '*|Any' }) }
            $candidates = foreach ($k in $keys) { if ($bucket.ContainsKey($k)) { $bucket[$k] } }
            foreach ($b in $candidates) {
                if ([object]::ReferenceEquals($a, $b)) { continue }
                # Windows rules differ in settings the inventory does not read (user and computer
                # restrictions, dynamic targets); compare only pairs that include an app or custom rule.
                if ($a.IsWindows -and $b.IsWindows) { continue }
                # Service hardening rules are read-only restrictions Windows layers over broad rules by design.
                if ([string]$a.Store -in 'StaticServiceStore', 'ConfigurableServiceStore' -or [string]$b.Store -in 'StaticServiceStore', 'ConfigurableServiceStore') { continue }
                # An allow/block pair is examined from the block's side; redundancy is reported for app
                # and custom rules only (a Windows rule is never deleted, so it is not actionable).
                if ([string]$a.Action -eq 'Allow' -and [string]$b.Action -eq 'Block') { continue }
                if ([string]$a.Action -eq [string]$b.Action -and $b.IsWindows) { continue }
                $sb = $scope[[string]$b.Name]
                if ($sa.Package -ne $sb.Package) { continue }
                $rel = Test-IgwtFirewallScopeRelation -A $sa -B $sb
                if (-not $rel) { continue }
                $an = [string]$a.Name; $bn = [string]$b.Name
                if ([string]$a.Action -eq 'Block' -and [string]$b.Action -eq 'Allow') {
                    if ($rel -eq 'Covers') { $info[$bn].ShadowedBy.Add($an); $relations.Add([pscustomobject]@{ Kind = 'Shadowed'; Rule = $bn; By = $an }) }
                    elseif (-not $info[$bn].Conflicts.Contains($an)) { $info[$bn].Conflicts.Add($an); $info[$an].Conflicts.Add($bn); $relations.Add([pscustomobject]@{ Kind = 'Conflicting'; Rule = $bn; By = $an }) }
                } elseif ([string]$a.Action -eq [string]$b.Action -and $rel -eq 'Covers') {
                    # Two rules that cover each other are identical: report the second one only (by name order).
                    $mutual = (Test-IgwtFirewallScopeRelation -A $scope[$bn] -B $sa) -eq 'Covers'
                    if ($mutual -and [string]::CompareOrdinal($an, $bn) -gt 0) { continue }
                    $info[$bn].RedundantWith.Add($an); $relations.Add([pscustomobject]@{ Kind = 'Redundant'; Rule = $bn; By = $an })
                }
            }
        }
    }
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $i = $info[[string]$r.Name]
        $text = ''
        if ($i.ShadowedBy.Count) { $text = "This allow rule never applies: block rule '$($label[$i.ShadowedBy[0]])' covers the same traffic, and a block always wins.$(if ($i.ShadowedBy.Count -gt 1) { " ($($i.ShadowedBy.Count) block rules do.)" })" }
        elseif ($i.Conflicts.Count -and [string]$r.Action -eq 'Allow') { $text = "Partly blocked: block rule '$($label[$i.Conflicts[0]])' overlaps this rule; on the shared traffic the block wins, the rest is allowed." }
        elseif ($i.Conflicts.Count) { $text = "Overlaps allow rule '$($label[$i.Conflicts[0]])'; on the shared traffic this block wins." }
        elseif ($i.RedundantWith.Count) { $text = "Redundant: rule '$($label[$i.RedundantWith[0]])' already covers all of this rule's traffic with the same action." }
        elseif ($r.Enabled) { $text = 'No conflicts found with other enabled rules (IPsec authenticated bypass is not evaluated).' }
        foreach ($pair in @(@('Shadowed', [bool]$i.ShadowedBy.Count), @('ShadowedBy', $i.ShadowedBy.ToArray()), @('Redundant', [bool]$i.RedundantWith.Count), @('RedundantWith', $i.RedundantWith.ToArray()), @('Conflicts', $i.Conflicts.ToArray()), @('PrecedenceText', $text))) {
            if ($r.PSObject.Properties[$pair[0]]) { $r.($pair[0]) = $pair[1] } else { $r | Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1] }
        }
    }
    return $relations.ToArray()
}
