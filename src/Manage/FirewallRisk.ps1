# FirewallRisk.ps1
# Firewall Manager 3.4 risk findings and active exposure. The risk rules are data
# (data\firewall\risks.json); each 'when' check is evaluated here from inventory rows, so the
# findings stay explainable. Signatures are cached by path + size + last-write time; listeners come
# from Get-NetTCPConnection / Get-NetUDPEndpoint (read-only) and raise a matching finding one level.

function Get-IgwtFirewallSignatureCachePath {
    <# .SYNOPSIS The per-user Authenticode cache of the Firewall Manager. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $dir = $(if ($env:IGWT_GUI_STATE_DIR) { $env:IGWT_GUI_STATE_DIR } else { Join-Path $env:LOCALAPPDATA 'iGWindowsTuner' })
    return (Join-Path $dir 'firewall-signatures.json')
}

function Get-IgwtFirewallSignatures {
    <#
    .SYNOPSIS
        Authenticode status and signer of each program path (lower-case path -> Status, Signer),
        read with Get-AuthenticodeSignature and cached by path, size and last-write time (signature
        checks are slow). Missing files are skipped. The cache is the app's own per-user file.
    .PARAMETER Path
        Program paths (environment variables are expanded).
    #>
    [CmdletBinding()]
    param([string[]]$Path = @(), [string]$CachePath, [switch]$NoCache)
    if (-not $CachePath) { $CachePath = Get-IgwtFirewallSignatureCachePath }
    $cache = @{}
    if (-not $NoCache -and (Test-Path -LiteralPath $CachePath)) {
        try { foreach ($p in (Read-IgwtJsonFile -Path $CachePath).entries.PSObject.Properties) { $cache[$p.Name] = $p.Value } } catch { Write-Verbose "Signature cache not readable: $($_.Exception.Message)" }
    }
    $result = @{}; $changed = $false; $checked = 0
    foreach ($raw in @($Path | Where-Object { $_ -and $_ -notin 'Any', 'System' } | Select-Object -Unique)) {
        $full = [Environment]::ExpandEnvironmentVariables([string]$raw)
        $key = $full.ToLowerInvariant()
        if ($result.ContainsKey($key)) { continue }
        $fi = $null
        try { $fi = Get-Item -LiteralPath $full -ErrorAction Stop } catch { continue }
        if ($fi.PSIsContainer) { continue }
        $stamp = "$($fi.Length)|$($fi.LastWriteTimeUtc.Ticks)"
        $hit = $cache[$key]
        if ($hit -and [string]$hit.Stamp -eq $stamp) { $result[$key] = [pscustomobject]@{ Status = [string]$hit.Status; Signer = [string]$hit.Signer }; continue }
        $status = 'UnknownError'; $signer = ''
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop
            $status = [string]$s.Status
            if ($s.SignerCertificate) { $signer = ([regex]::Match([string]$s.SignerCertificate.Subject, 'CN=("?)([^,"]+)\1')).Groups[2].Value }
        } catch { Write-Verbose "Signature of $full not readable: $($_.Exception.Message)" }
        $checked++
        $result[$key] = [pscustomobject]@{ Status = $status; Signer = $signer }
        $cache[$key] = [pscustomobject]@{ Stamp = $stamp; Status = $status; Signer = $signer }
        $changed = $true
    }
    if ($changed -and -not $NoCache) {
        try {
            $dir = Split-Path -Path $CachePath -Parent
            if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
            $entries = [ordered]@{}; foreach ($k in @($cache.Keys | Sort-Object)) { $entries[$k] = $cache[$k] }
            [System.IO.File]::WriteAllText($CachePath, ([ordered]@{ schemaVersion = 1; entries = $entries } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
        } catch { Write-Verbose "Signature cache not written: $($_.Exception.Message)" }
    }
    Write-Verbose "Signatures: $checked checked, $($result.Count - $checked) from cache."
    return $result
}

function ConvertTo-IgwtFirewallPortRanges {
    <#
    .SYNOPSIS
        A local or remote port text ('Any', '80, 443', '1000-2000', keywords such as RPC) as ranges
        (Low, High). Keywords count as one port with Low = High = -1. 'Any' and '' return nothing.
    #>
    [CmdletBinding()]
    param([string]$Port)
    foreach ($part in @(([string]$Port) -split ',\s*' | Where-Object { $_ -and $_ -ne 'Any' })) {
        $m = [regex]::Match($part.Trim(), '^(\d+)(?:-(\d+))?$')
        if ($m.Success) { $lo = [int]$m.Groups[1].Value; $hi = $(if ($m.Groups[2].Success) { [int]$m.Groups[2].Value } else { $lo }); [pscustomobject]@{ Low = $lo; High = $hi } }
        else { [pscustomobject]@{ Low = -1; High = -1 } }
    }
}

function Test-IgwtFirewallPortInSet {
    <# .SYNOPSIS True when an explicit local port list (not Any) of the rule's protocol hits a port of the set (TCP/UDP lists). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Protocol, [string]$LocalPort, $Set)
    $lists = @()
    if ($Protocol -in 'TCP', 'Any', '') { $lists += @($Set.tcp) }
    if ($Protocol -in 'UDP', 'Any', '') { $lists += @($Set.udp) }
    $ranges = @(ConvertTo-IgwtFirewallPortRanges -Port $LocalPort)
    foreach ($p in $lists) { $n = [int]$p; foreach ($r in $ranges) { if ($r.Low -ge 0 -and $n -ge $r.Low -and $n -le $r.High) { return $true } } }
    return $false
}

function Get-IgwtFirewallRiskState {
    <# .SYNOPSIS Data the risk checks need for all rows: duplicate counts, local-only ports and the Windows default enabled set. #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [Parameter(Mandatory = $true)]$Context, [string[]]$DefaultEnabled)
    $dupKey = { param($r) ('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}' -f $r.Direction, $r.Action, ([string]$r.Program).ToLowerInvariant(), $r.Service, $r.Package, $r.Protocol, $r.LocalPort, $r.RemotePort, $r.RemoteAddress, $r.Profiles) }
    $dupCandidate = { param($r) [string]$r.Origin -in 'UserInstalled', 'CustomRules' -and -not [string]$r.Owner -and -not [string]$r.Package -and [string]$r.Protocol -ne '' -and -not $r.Locked }
    $counts = @{}
    foreach ($r in $Rows) { if (& $dupCandidate $r) { $k = & $dupKey $r; if ($counts.ContainsKey($k)) { $counts[$k]++ } else { $counts[$k] = 1 } } }
    $local = @{ TCP = @(); UDP = @() }
    foreach ($p in $Context.Kb.Ports) { if ($p.localOnly) { $local[[string]$p.protocol] += [string]$p.port } }
    $defaults = $null
    if ($null -ne $DefaultEnabled) { $defaults = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase); foreach ($n in $DefaultEnabled) { $null = $defaults.Add([string]$n) } }
    # Port sets as integer lookups per protocol (the local-only ports of ports.json too).
    $toSet = { param($list) $h = New-Object 'System.Collections.Generic.HashSet[int]'; foreach ($n in @($list)) { $null = $h.Add([int]$n) }; , $h }
    $sets = @{ '__local' = @{ TCP = (& $toSet $local.TCP); UDP = (& $toSet $local.UDP) } }
    if ($Context.Kb.PortSets) { foreach ($p in $Context.Kb.PortSets.PSObject.Properties) { $sets[$p.Name] = @{ TCP = (& $toSet $p.Value.tcp); UDP = (& $toSet $p.Value.udp) } } }
    [pscustomobject]@{ DupCounts = $counts; DupKey = $dupKey; DupCandidate = $dupCandidate; LocalPorts = [pscustomobject]@{ tcp = $local.TCP; udp = $local.UDP }; DefaultEnabled = $defaults
        PortSets = $sets; Writable = (ConvertTo-IgwtFirewallWildcardRegex -Pattern $Context.Writable); WritableExceptions = (ConvertTo-IgwtFirewallWildcardRegex -Pattern $Context.WritableExceptions) }
}

function Get-IgwtFirewallRowFacts {
    <#
    .SYNOPSIS
        Every named risk check for one row at once (hashtable check -> bool), so the risk rules are
        evaluated as lookups. ports:<set> checks are added for the port sets the rules use. Unreadable
        filters (not elevated: ports and addresses '') never count as 'Any'.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)]$State, [string[]]$PortSets = @())
    $r = $Row
    $program = [string]$r.Program
    $path = $(if ($program -and $program -notin 'Any', 'System') { [Environment]::ExpandEnvironmentVariables($program) } else { '' })
    $lp = [string]$r.LocalPort; $proto = [string]$r.Protocol
    $profiles = @($r.ProfileList)
    $exists = [string]$r.ProgramExists -ne 'No'
    $sig = $(if ($path) { $Context.Signatures[$path.ToLowerInvariant()] } else { $null })
    $o = $Context.Owned
    $owned = (($o.namePrefix -and [string]$r.Name -like "$($o.namePrefix)*") -or ($o.group -and [string]$r.RawGroup -eq [string]$o.group))
    $ranges = @(ConvertTo-IgwtFirewallPortRanges -Port $lp)
    $ports = 0; foreach ($x in $ranges) { $ports += [Math]::Max(1, $x.High - $x.Low + 1) }
    # An explicit port list of the rule's protocol hits a port of a set (Any never counts).
    $inSet = {
        param($set)
        foreach ($pr in @($(if ($proto -in 'TCP', 'Any') { 'TCP' }), $(if ($proto -in 'UDP', 'Any') { 'UDP' }))) {
            if (-not $pr) { continue }
            foreach ($n in $set[$pr]) { foreach ($x in $ranges) { if ($x.Low -ge 0 -and $n -ge $x.Low -and $n -le $x.High) { return $true } } }
        }
        return $false
    }
    $writable = ($path -and $State.Writable -and $State.Writable.IsMatch($path) -and -not ($State.WritableExceptions -and $State.WritableExceptions.IsMatch($path)))
    $f = @{
        enabled = [bool]$r.Enabled; inbound = ([string]$r.Direction -eq 'Inbound'); outbound = ([string]$r.Direction -eq 'Outbound')
        allow = ([string]$r.Action -eq 'Allow'); block = ([string]$r.Action -eq 'Block')
        programAny = ($program -in 'Any', ''); serviceAny = ([string]$r.Service -in 'Any', ''); packageAny = (-not [string]$r.Package -and -not [string]$r.Owner)
        portAny = ($lp -eq 'Any'); remoteAny = ([string]$r.RemoteAddress -eq 'Any'); profilePublic = ($profiles -contains 'Public' -or $profiles -contains 'Any')
        userWritablePath = [bool]$writable
        unsigned = [bool]($path -and $exists -and $sig -and [string]$sig.Status -in 'NotSigned', 'HashMismatch', 'NotTrusted', 'Incompatible')
        orphaned = (-not $exists); nonWindows = ([string]$r.Origin -in 'UserInstalled', 'CustomRules')
        scriptHost = [bool]($path -and $Context.ScriptHosts -contains ([System.IO.Path]::GetFileName($path)).ToLowerInvariant())
        edgeTraversal = ([string]$r.EdgeTraversal -in 'Allow', 'DeferToUser', 'DeferToApp')
        localServiceRemoteAny = ([string]$r.RemoteAddress -eq 'Any' -and $ranges.Count -and (& $inSet $State.PortSets['__local']))
        disabledSecurityRelevant = $false
        duplicate = ((& $State.DupCandidate $r) -and $State.DupCounts[(& $State.DupKey $r)] -gt 1)
        broadPortRange = ($ports -gt 1000); noDescription = (-not $owned -and -not ([string]$r.Description).Trim())
    }
    if (-not $r.Enabled -and [string]$r.Origin -eq 'CoreServices' -and [string]$r.Store -notin 'StaticServiceStore', 'ConfigurableServiceStore') {
        $f.disabledSecurityRelevant = $(if ($State.DefaultEnabled) { $State.DefaultEnabled.Contains([string]$r.Name) } else { $true })
    }
    foreach ($set in $PortSets) { $f["ports:$set"] = ($ranges.Count -gt 0 -and $State.PortSets.ContainsKey($set) -and (& $inSet $State.PortSets[$set])) }
    return $f
}
function Get-IgwtFirewallListeners {
    <#
    .SYNOPSIS
        What is listening right now (read-only): TCP listeners and UDP endpoints with the owning
        process, its path and the services it hosts. Loopback-only listeners are marked Local.
    #>
    [CmdletBinding()]
    param()
    $procs = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $path = ''; try { $path = [string]$p.Path } catch { $path = '' }; $procs[[int]$p.Id] = [pscustomobject]@{ Name = $p.ProcessName; Path = $path } }
    $svcByPid = @{}
    try { foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter 'State = "Running"' -ErrorAction Stop)) { $k = [int]$s.ProcessId; if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = New-Object System.Collections.Generic.List[string] }; $svcByPid[$k].Add([string]$s.Name) } } catch { Write-Verbose "Services not readable: $($_.Exception.Message)" }
    $make = {
        param($proto, $address, $port, $procId)
        $pr = $procs[[int]$procId]
        [pscustomobject]@{
            Protocol = $proto; LocalAddress = [string]$address; LocalPort = [int]$port; ProcessId = [int]$procId
            ProcessName = $(if ($pr) { $pr.Name } else { '' }); Path = $(if ($pr) { $pr.Path } else { '' })
            Services = @($(if ($svcByPid.ContainsKey([int]$procId)) { $svcByPid[[int]$procId].ToArray() }))
            Local = ([string]$address -in '127.0.0.1', '::1')
        }
    }
    $out = New-Object System.Collections.Generic.List[object]
    try { foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) { $out.Add((& $make 'TCP' $c.LocalAddress $c.LocalPort $c.OwningProcess)) } } catch { Write-Verbose "TCP listeners not readable: $($_.Exception.Message)" }
    try { foreach ($u in @(Get-NetUDPEndpoint -ErrorAction Stop)) { $out.Add((& $make 'UDP' $u.LocalAddress $u.LocalPort $u.OwningProcess)) } } catch { Write-Verbose "UDP endpoints not readable: $($_.Exception.Message)" }
    return $out.ToArray()
}

function Test-IgwtFirewallListenerMatch {
    <# .SYNOPSIS True when an enabled inbound allow rule admits traffic to a (non-loopback) listener: protocol, port, program and service all match. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)]$Listener)
    $r = $Row; $l = $Listener
    if ($l.Local -or -not $r.Enabled -or [string]$r.Direction -ne 'Inbound' -or [string]$r.Action -ne 'Allow') { return $false }
    if ([string]$r.Protocol -notin 'Any', '' -and [string]$r.Protocol -ne [string]$l.Protocol) { return $false }
    if ([string]$r.Protocol -eq '' -and [string]$r.LocalPort -eq '') { return $false }   # filters not readable: no claim
    if ([string]$r.LocalPort -ne 'Any') {
        $hit = $false
        foreach ($x in @(ConvertTo-IgwtFirewallPortRanges -Port ([string]$r.LocalPort))) { if ($x.Low -ge 0 -and $l.LocalPort -ge $x.Low -and $l.LocalPort -le $x.High) { $hit = $true; break } }
        if (-not $hit) { return $false }
    }
    if ([string]$r.Program -notin 'Any', '' -and [Environment]::ExpandEnvironmentVariables([string]$r.Program) -ne [string]$l.Path) { return $false }
    if ([string]$r.Service -notin 'Any', '' -and @($l.Services) -notcontains [string]$r.Service) { return $false }
    return $true
}

function Get-IgwtFirewallFindings {
    <#
    .SYNOPSIS
        Evaluates the risk rules for every row (in place) and returns the findings. Each row gets
        Findings (RiskId, Severity, BaseSeverity, Title, Hint, Explanation, Recommended,
        Alternatives, ExposedNow, Ignored, IgnoreReason), RiskLevel (highest open severity), Exposed,
        ExposedBy, and SecurityRisks in Assessments and Groups when an open finding exists.
    .PARAMETER Listeners
        From Get-IgwtFirewallListeners; $null skips the exposure check.
    .PARAMETER DefaultEnabled
        Rule IDs enabled in the Windows default rule set (SystemDefaults store); $null = unknown.
    #>
    [CmdletBinding()]
    param([object[]]$Rows = @(), [Parameter(Mandatory = $true)]$Context, [object[]]$Listeners, [string[]]$DefaultEnabled, [datetime]$Now = (Get-Date))
    $state = Get-IgwtFirewallRiskState -Rows $Rows -Context $Context -DefaultEnabled $DefaultEnabled
    $order = @('Low', 'Medium', 'High', 'Critical')
    $all = New-Object System.Collections.Generic.List[object]
    $when = @{}; foreach ($risk in $Context.Kb.Risks) { $when[[string]$risk.id] = @($risk.when | ForEach-Object { [string]$_ }) }
    # Listeners reachable from the network (loopback-only ones are not exposed).
    $reachable = $(if ($null -ne $Listeners) { @($Listeners | Where-Object { $_ -and -not $_.Local }) } else { $null })
    $portSets = @($Context.Kb.Risks | ForEach-Object { @($_.when) } | Where-Object { [string]$_ -like 'ports:*' } | ForEach-Object { ([string]$_).Substring(6) } | Select-Object -Unique)
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $exposedBy = @()
        # Only enabled inbound allow rules with readable filters can admit traffic to a listener.
        if ($null -ne $reachable -and $r.Enabled -and [string]$r.Direction -eq 'Inbound' -and [string]$r.Action -eq 'Allow' -and [string]$r.Protocol) {
            $exposedBy = @(foreach ($l in $reachable) { if (Test-IgwtFirewallListenerMatch -Row $r -Listener $l) { $l } })
        }
        $list = New-Object System.Collections.Generic.List[object]
        $facts = Get-IgwtFirewallRowFacts -Row $r -Context $Context -State $state -PortSets $portSets
        foreach ($risk in $Context.Kb.Risks) {
            $ok = $true
            foreach ($w in $when[[string]$risk.id]) { if (-not $facts[$w]) { $ok = $false; break } }
            if (-not $ok) { continue }
            $sev = [string]$risk.severity
            $exposed = ($exposedBy.Count -gt 0 -and [string]$r.Action -eq 'Allow')
            if ($exposed -and $sev -ne 'Critical') { $sev = $order[$order.IndexOf($sev) + 1] }
            $ignored = Test-IgwtFirewallIgnored -Overrides $Context.Overrides -RuleId ([string]$r.Name) -RiskId ([string]$risk.id) -Now $Now
            $why = ''
            if ($ignored) { foreach ($k in @("$($r.Name)|$($risk.id)", [string]$risk.id)) { $p = $Context.Overrides.Ignored.PSObject.Properties[$k]; if ($p) { $why = [string]$p.Value.Reason; break } } }
            # Never recommend blocking or disabling a protected game, launcher or anti-cheat rule.
            $rec = [string]$risk.recommended; $alts = @($risk.alternatives)
            if ($r.Protected -and $rec -in 'Disable', 'Delete') { $alts = @(@($rec) + @($alts | Where-Object { $_ -ne 'Keep' })); $rec = 'Keep' }
            # Windows rules are never deleted and, like in 3.3 (DECISIONS U13), only enabled or disabled:
            # a restrict recommendation becomes Disable (the feature turns its rules back on when used).
            if ($r.IsWindows) {
                $alts = @($alts | Where-Object { $_ -notin 'Delete', 'RestrictPrivate', 'RestrictLocalSubnet' })
                if ($rec -in 'Delete', 'RestrictPrivate', 'RestrictLocalSubnet') { $rec = 'Disable'; $alts = @($alts | Where-Object { $_ -ne 'Disable' }) }
            }
            if ([string]$r.Origin -eq 'CoreServices') { $alts = @($alts | Where-Object { $_ -in 'Keep', 'Ignore' }); if ($rec -notin 'Keep', 'Ignore') { $rec = 'Keep' } }
            $f = [pscustomobject]@{
                RuleId = [string]$r.Name; RiskId = [string]$risk.id; Severity = $sev; BaseSeverity = [string]$risk.severity; Title = [string]$risk.title; Hint = [string]$risk.hint
                Explanation = [string]$risk.explanation; Recommended = $rec; Alternatives = $alts; ExposedNow = $exposed; Ignored = $ignored; IgnoreReason = $why; Sources = @($risk.sources)
            }
            $list.Add($f); $all.Add($f)
        }
        $open = @($list | Where-Object { -not $_.Ignored })
        $level = ''
        foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($open | Where-Object { $_.Severity -eq $s }).Count) { $level = $s; break } }
        $assess = @(@($r.Assessments | Where-Object { $_ -and $_ -ne 'SecurityRisks' }) + @($(if ($open.Count) { 'SecurityRisks' })))
        $groups = @(@($r.Groups | Where-Object { $_ -and $_ -ne 'SecurityRisks' }) + @($(if ($open.Count) { 'SecurityRisks' })))
        if (-not $r.PSObject.Properties['ExposedBy']) { foreach ($n in 'Findings', 'RiskLevel', 'Exposed', 'ExposedBy', 'Assessments', 'Groups') { if (-not $r.PSObject.Properties[$n]) { $r | Add-Member -NotePropertyName $n -NotePropertyValue $null } } }
        $r.Findings = $list.ToArray(); $r.RiskLevel = $level; $r.Exposed = ($exposedBy.Count -gt 0)
        $r.ExposedBy = @($exposedBy | ForEach-Object { "$($_.Protocol) $($_.LocalPort) $($_.ProcessName)" }); $r.Assessments = $assess; $r.Groups = $groups
    }
    return $all.ToArray()
}
