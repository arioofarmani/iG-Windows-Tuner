# ForensicLogging.ps1
# Forensic connection logging (3.5): three sources that can be switched on for a time-boxed
# session and are restored exactly afterwards.
#   Firewall packet log  Set-NetFirewallProfile LogBlocked/LogAllowed/LogMaxSizeKilobytes (1-32767 KB).
#   WFP auditing         audit subcategories Filtering Platform Connection {0CCE9226-...} and Packet
#                        Drop {0CCE9225-...} (by GUID, locale independent), through Set-IgwtAuditPolicy
#                        (auditpol /backup first, /restore to revert); events 5156/5157 and 5152.
#                        The Security log is enlarged first (wevtutil sl Security /ms:).
#   DNS client log       Microsoft-Windows-DNS-Client/Operational (off by default), wevtutil sl /e:.
# Sources and verification: DECISIONS F12. Every setting is snapshot before a change; settings set
# by a policy are read-only. No event log is ever cleared, no scheduled task or service is created
# (an expired session is noticed at the next start), and nothing logs to a network share.

$script:IgwtWfpConnectionGuid = '0CCE9226-69AE-11D9-BED3-505054503030'
$script:IgwtWfpPacketDropGuid = '0CCE9225-69AE-11D9-BED3-505054503030'
$script:IgwtDnsClientLog = 'Microsoft-Windows-DNS-Client/Operational'
$script:IgwtFirewallProfiles = @('Domain', 'Private', 'Public')

#region Change providers (3.6, DECISIONS T7): forensic targets on the change engine

# The forensic targets are a fixed set (DECISIONS T4: a restore only touches targets a catalog owns).
$script:IgwtChangeProviders['forensicFirewall'] = @{
    Reversible = { param($r) $null = $r; 'exact' }
    Resolve    = {
        param($t, $catalog)
        $null = $catalog
        $name = [string]$t['profile']
        if ($name -notin $script:IgwtFirewallProfiles -or [string]$t['key'] -ne "forensic|firewall|$name") { throw "'$($t['key'])' is not a forensic logging target." }
        return [pscustomobject]@{ Profile = $name }
    }
    Get        = { param($r, $ctx) $null = $ctx; $p = Get-NetFirewallProfile -Name $r.Profile -PolicyStore PersistentStore -ErrorAction Stop; [ordered]@{ logBlocked = [string]$p.LogBlocked; logAllowed = [string]$p.LogAllowed; logMaxKB = [long]$p.LogMaxSizeKilobytes } }
    Set        = {
        param($r, $desired, $ctx)
        $null = $ctx
        $arg = @{ Name = $r.Profile; ErrorAction = 'Stop' }
        if ($desired['logBlocked']) { $arg.LogBlocked = [string]$desired['logBlocked'] }
        if ($desired['logAllowed']) { $arg.LogAllowed = [string]$desired['logAllowed'] }
        if ($desired['logMaxKB']) { $arg.LogMaxSizeKilobytes = [uint64]$desired['logMaxKB'] }
        Set-NetFirewallProfile @arg
    }
    Restore    = { param($r, $data, $ctx) $null = $ctx; Set-NetFirewallProfile -Name $r.Profile -LogBlocked ([string]$data['logBlocked']) -LogAllowed ([string]$data['logAllowed']) -LogMaxSizeKilobytes ([uint64]$data['logMaxKB']) -ErrorAction Stop }
    TestSet    = {
        param($r, $desired, $ctx)
        $now = & $script:IgwtChangeProviders['forensicFirewall'].Get $r $ctx
        foreach ($k in 'logBlocked', 'logAllowed', 'logMaxKB') { if ($desired[$k] -and [string]$now[$k] -ne [string]$desired[$k]) { return [pscustomobject]@{ Ok = $false; State = "$k=$($now[$k])"; Note = "Read back $($r.Profile) $k = $($now[$k]) after setting $($desired[$k])." } } }
        return [pscustomobject]@{ Ok = $true; State = 'set'; Note = '' }
    }
}

$script:IgwtChangeProviders['forensicAudit'] = @{
    Reversible = { param($r) $null = $r; 'exact' }
    Resolve    = {
        param($t, $catalog)
        $null = $catalog
        $g = ([string]$t['guid']).ToUpperInvariant()
        if ($g -notin $script:IgwtWfpConnectionGuid, $script:IgwtWfpPacketDropGuid -or [string]$t['key'] -ne "forensic|audit|$g") { throw "'$($t['key'])' is not a forensic logging target." }
        return [pscustomobject]@{ Guid = $g; Backup = [string]$t['backup'] }
    }
    Get        = {
        param($r, $ctx)
        $null = $ctx
        $row = @((Get-IgwtAuditPolicy).Subcategories | Where-Object { ([string]$_.Guid).Trim('{}') -eq $r.Guid }) | Select-Object -First 1
        [ordered]@{ setting = $(if ($row) { [string]$row.Setting } else { 'Unknown' }) }
    }
    Set        = {
        param($r, $desired, $ctx)
        $null = $ctx
        $new = [string]$desired['setting']
        $s = $(if ($new -in 'Success', 'SuccessAndFailure') { 'enable' } else { 'disable' })
        $f = $(if ($new -in 'Failure', 'SuccessAndFailure') { 'enable' } else { 'disable' })
        $res = Invoke-IgwtAuditpol -Arguments @('/set', "/subcategory:{$($r.Guid)}", "/success:$s", "/failure:$f")
        if ($res.ExitCode -ne 0) { throw "auditpol /set failed (exit $($res.ExitCode)): $($res.Output)" }
    }
    # As in 3.5: the audit policy comes back from the backup taken before the session's first change.
    Restore    = {
        param($r, $data, $ctx)
        $null = $data; $null = $ctx
        if (-not $r.Backup) { throw 'No audit policy backup was recorded for this session.' }
        $null = Restore-IgwtAuditPolicy -BackupPath $r.Backup -Confirm:$false
    }
    TestSet    = {
        param($r, $desired, $ctx)
        $now = & $script:IgwtChangeProviders['forensicAudit'].Get $r $ctx
        $ok = ([string]$now['setting'] -eq [string]$desired['setting'])
        return [pscustomobject]@{ Ok = $ok; State = [string]$now['setting']; Note = $(if ($ok) { '' } else { "The audit policy did not take effect for $($r.Guid) (reads $($now['setting']))." }) }
    }
}

$script:IgwtChangeProviders['forensicEventLog'] = @{
    Reversible = { param($r) $null = $r; 'exact' }
    Resolve    = {
        param($t, $catalog)
        $null = $catalog
        $ln = [string]$t['log']
        if ($ln -notin 'Security', $script:IgwtDnsClientLog -or [string]$t['key'] -ne "forensic|eventlog|$ln") { throw "'$($t['key'])' is not a forensic logging target." }
        return [pscustomobject]@{ Log = $ln }
    }
    Get        = { param($r, $ctx) $null = $ctx; $c = Get-IgwtEventLogConfig -LogName $r.Log; [ordered]@{ enabled = [bool]$c.Enabled; maxSizeBytes = [long]$c.MaxSizeBytes } }
    Set        = {
        param($r, $desired, $ctx)
        $null = $ctx
        $a = @('sl', $r.Log)
        if ($desired.Contains('maxSizeBytes')) { $a += "/ms:$([long]$desired['maxSizeBytes'])" }
        if ($desired.Contains('enabled')) { $a += "/e:$(([string][bool]$desired['enabled']).ToLowerInvariant())" }
        $res = Invoke-IgwtWevtutil -Arguments $a
        if ($res.ExitCode -ne 0) { throw "wevtutil sl $($r.Log) failed (exit $($res.ExitCode)): $($res.Output)" }
    }
    Restore    = {
        param($r, $data, $ctx)
        $null = $ctx
        $res = Invoke-IgwtWevtutil -Arguments @('sl', $r.Log, "/ms:$([long]$data['maxSizeBytes'])", "/e:$(([string][bool]$data['enabled']).ToLowerInvariant())")
        if ($res.ExitCode -ne 0) { throw "wevtutil sl $($r.Log) failed (exit $($res.ExitCode)): $($res.Output)" }
    }
    TestSet    = {
        param($r, $desired, $ctx)
        $now = & $script:IgwtChangeProviders['forensicEventLog'].Get $r $ctx
        foreach ($k in 'maxSizeBytes', 'enabled') { if ($desired.Contains($k) -and [string]$now[$k] -ne [string]$desired[$k]) { return [pscustomobject]@{ Ok = $false; State = "$k=$($now[$k])"; Note = "Read back $($r.Log) $k = $($now[$k]) after setting $($desired[$k])." } } }
        return [pscustomobject]@{ Ok = $true; State = 'set'; Note = '' }
    }
}

#endregion

function Invoke-IgwtWevtutil {
    <#
    .SYNOPSIS
        Runs wevtutil.exe for gl (get-log), sl (set-log) and epl (export-log) only; clearing a log is
        never possible here. Returns the exit code and output. Refuses to run in TestMode (tests mock it).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if ($Arguments[0] -notin 'gl', 'sl', 'epl') { throw "wevtutil $($Arguments[0]) is not used by iG Windows Tuner." }
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: wevtutil must be mocked in tests.' }
    if ($Arguments[0] -in 'sl', 'epl' -and -not $PSCmdlet.ShouldProcess($Arguments[1], "wevtutil $($Arguments -join ' ')")) { return [pscustomobject]@{ ExitCode = 0; Output = 'WhatIf' } }
    $exe = Join-Path $env:SystemRoot 'System32\wevtutil.exe'
    $out = & $exe @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
}

function Get-IgwtEventLogConfig {
    <#
    .SYNOPSIS
        Configuration of an event log from `wevtutil gl` (enabled, retention, autoBackup, maxSize in
        bytes, log file). Works without administrator rights for the Security log. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LogName)
    $r = Invoke-IgwtWevtutil -Arguments @('gl', $LogName)
    if ($r.ExitCode -ne 0) { throw "wevtutil gl $LogName failed (exit $($r.ExitCode)): $($r.Output)" }
    $v = @{}
    foreach ($line in ($r.Output -split "`r?`n")) { if ($line -match '^\s*(\w+):\s*(.*)$') { if (-not $v.ContainsKey($Matches[1])) { $v[$Matches[1]] = $Matches[2].Trim() } } }
    [pscustomobject]@{
        LogName = $LogName; Enabled = ([string]$v.enabled -eq 'true'); Retention = ([string]$v.retention -eq 'true'); AutoBackup = ([string]$v.autoBackup -eq 'true')
        MaxSizeBytes = [long]$(if ($v.maxSize) { $v.maxSize } else { 0 }); LogFile = [string]$v.logFileName
    }
}

function Get-IgwtForensicPolicyState {
    <#
    .SYNOPSIS
        Which forensic settings a policy sets (then they are read-only here): firewall logging under
        SOFTWARE\Policies\Microsoft\WindowsFirewall\<profile>\Logging (WindowsFirewall.admx), the
        Security log size and retention under Software\Policies\Microsoft\Windows\EventLog\Security
        (EventLog.admx), and the audit policy of a domain- or MDM-managed PC. Read-only.
    #>
    [CmdletBinding()]
    param()
    $fw = @{}
    $keys = @{ Domain = @('DomainProfile'); Private = @('StandardProfile', 'PrivateProfile'); Public = @('StandardProfile', 'PublicProfile') }
    foreach ($p in $script:IgwtFirewallProfiles) {
        $set = @()
        foreach ($k in $keys[$p]) {
            $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$k\Logging"
            foreach ($n in 'LogDroppedPackets', 'LogSuccessfulConnections', 'LogFileSize', 'LogFilePath') { if ((Get-IgwtRegistryValue -Path $path -Name $n).Exists) { $set += $n } }
        }
        $fw[$p] = @($set | Select-Object -Unique)
    }
    $ev = @()
    foreach ($n in 'MaxSize', 'Retention', 'AutoBackupLogFiles') { if ((Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name $n).Exists) { $ev += $n } }
    $managed = $false; $authorities = @()
    try { $m = Get-IgwtManagementState; $managed = [bool]$m.Managed; $authorities = @($m.Authorities) } catch { Write-Verbose "Management state unknown: $($_.Exception.Message)" }
    [pscustomobject]@{ Firewall = $fw; SecurityLog = $ev; AuditManaged = $managed; Authorities = $authorities }
}

function Get-IgwtForensicLoggingState {
    <#
    .SYNOPSIS
        The current state of the three forensic sources and the Security log, with who manages each
        setting (Local or Policy) and the session, if one runs. Values that need administrator rights
        to read (the audit policy) are Unknown without them. Read-only.
    #>
    [CmdletBinding()]
    param()
    $policy = Get-IgwtForensicPolicyState
    $notes = New-Object System.Collections.Generic.List[string]
    $profiles = @(foreach ($p in @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)) {
            $name = [string]$p.Name
            [pscustomobject]@{
                Profile = $name; LogBlocked = ([string]$p.LogBlocked -eq 'True'); LogAllowed = ([string]$p.LogAllowed -eq 'True'); LogMaxKB = [int]$p.LogMaxSizeKilobytes
                LogFile = [Environment]::ExpandEnvironmentVariables([string]$p.LogFileName); RawLogBlocked = [string]$p.LogBlocked; RawLogAllowed = [string]$p.LogAllowed
                ManagedBy = $(if (@($policy.Firewall[$name]).Count) { 'Policy' } else { 'Local' }); PolicyValues = @($policy.Firewall[$name])
                OnNetworkShare = (Test-IgwtNetworkPath -Path ([Environment]::ExpandEnvironmentVariables([string]$p.LogFileName)))
            }
        })
    $audit = $null
    try {
        $a = Get-IgwtAuditPolicy
        $find = { param($g) @($a.Subcategories | Where-Object { ([string]$_.Guid).Trim('{}') -eq $g }) | Select-Object -First 1 }
        $c = & $find $script:IgwtWfpConnectionGuid; $d = & $find $script:IgwtWfpPacketDropGuid
        $audit = [pscustomobject]@{ Connection = $(if ($c) { $c.Setting } else { 'Unknown' }); PacketDrop = $(if ($d) { $d.Setting } else { 'Unknown' }); Readable = $true; AdvancedOverridesLegacy = $a.AdvancedOverridesLegacy }
    } catch {
        $audit = [pscustomobject]@{ Connection = 'Unknown'; PacketDrop = 'Unknown'; Readable = $false; AdvancedOverridesLegacy = $false }
        $notes.Add("The audit policy could not be read: $($_.Exception.Message)")
    }
    $sec = $null; $dns = $null
    try { $sec = Get-IgwtEventLogConfig -LogName 'Security' } catch { $notes.Add("The Security log settings could not be read: $($_.Exception.Message)") }
    try { $dns = Get-IgwtEventLogConfig -LogName $script:IgwtDnsClientLog } catch { $notes.Add("The DNS client log settings could not be read: $($_.Exception.Message)") }
    [pscustomobject]@{
        Firewall = $profiles
        Wfp = [pscustomobject]@{ Connection = $audit.Connection; PacketDrop = $audit.PacketDrop; Readable = $audit.Readable; ManagedBy = $(if ($policy.AuditManaged) { 'Policy' } else { 'Local' }); Authorities = $policy.Authorities }
        SecurityLog = $(if ($sec) { [pscustomobject]@{ MaxSizeBytes = $sec.MaxSizeBytes; Retention = $sec.Retention; AutoBackup = $sec.AutoBackup; ManagedBy = $(if (@($policy.SecurityLog).Count) { 'Policy' } else { 'Local' }) } } else { $null })
        Dns = $(if ($dns) { [pscustomobject]@{ Enabled = $dns.Enabled; MaxSizeBytes = $dns.MaxSizeBytes; ManagedBy = 'Local' } } else { $null })
        Session = (Get-IgwtForensicSession)
        Notes = $notes.ToArray()
    }
}

function Get-IgwtForensicLoggingPlan {
    <#
    .SYNOPSIS
        What a forensic logging profile would change, from the current state: per setting the current
        and new value, or why it is not changed (set by a policy, a network-share log path, already
        set). Basic: blocked packets in the firewall log of every profile. Full: also allowed packets,
        WFP connection auditing (success and failure), WFP packet drops (failure), the DNS client log,
        and a Security log of the chosen size. Custom: pick the sources. Settings only ever go up
        (logging on, logs larger); the session restores them. Read-only.
    .PARAMETER SecurityLogMB
        Security log size for WFP auditing: 256, 512 or 1024 MB. A larger current size is kept.
    #>
    [CmdletBinding()]
    param([ValidateSet('Basic', 'Full', 'Custom')][string]$LoggingProfile = 'Basic', [hashtable]$Options = @{},
        [ValidateSet(256, 512, 1024)][int]$SecurityLogMB = 512, $State)
    if (-not $State) { $State = Get-IgwtForensicLoggingState }
    $o = @{ FirewallBlocked = $true; FirewallAllowed = $false; WfpConnection = $false; WfpPacketDrop = $false; DnsClient = $false }
    if ($LoggingProfile -eq 'Full') { foreach ($k in @($o.Keys)) { $o[$k] = $true } }
    if ($LoggingProfile -eq 'Custom') { foreach ($k in @($o.Keys)) { $o[$k] = [bool]$Options[$k] } }
    $ops = New-Object System.Collections.Generic.List[object]
    $add = { param($source, $target, $setting, $current, $new, $why) $ops.Add([pscustomobject]@{ Source = $source; Target = $target; Setting = $setting; Current = $current; New = $new; Changes = (-not $why -and [string]$current -ne [string]$new); Refused = [string]$why }) }
    foreach ($p in @($State.Firewall)) {
        $why = $(if ($p.ManagedBy -eq 'Policy') { "Set by a policy ($(@($p.PolicyValues) -join ', ')): change it there." } elseif ($p.OnNetworkShare) { 'The log file is on a network share; forensic logging only writes to local disks.' } else { '' })
        if ($o.FirewallBlocked -or $o.FirewallAllowed) { & $add 'Firewall' $p.Profile 'LogMaxKB' $p.LogMaxKB ([Math]::Max([int]$p.LogMaxKB, 32767)) $why }
        if ($o.FirewallBlocked) { & $add 'Firewall' $p.Profile 'LogBlocked' $p.LogBlocked $true $why }
        if ($o.FirewallAllowed) { & $add 'Firewall' $p.Profile 'LogAllowed' $p.LogAllowed $true $why }
    }
    $wfpWhy = $(if ($State.Wfp.ManagedBy -eq 'Policy') { "This PC is managed ($(@($State.Wfp.Authorities) -join ', ')): its audit policy comes from there." } elseif (-not $State.Wfp.Readable) { 'The audit policy can only be read and changed as administrator.' } else { '' })
    $merge = { param($cur, [bool]$success, [bool]$failure) $s = $success -or $cur -in 'Success', 'SuccessAndFailure'; $f = $failure -or $cur -in 'Failure', 'SuccessAndFailure'; if ($s -and $f) { 'SuccessAndFailure' } elseif ($s) { 'Success' } elseif ($f) { 'Failure' } else { 'None' } }
    if ($o.WfpConnection) { & $add 'Wfp' 'Filtering Platform Connection' 'Audit' $State.Wfp.Connection (& $merge $State.Wfp.Connection $true $true) $wfpWhy }
    if ($o.WfpPacketDrop) { & $add 'Wfp' 'Filtering Platform Packet Drop' 'Audit' $State.Wfp.PacketDrop (& $merge $State.Wfp.PacketDrop $false $true) $wfpWhy }
    if ($o.WfpConnection -or $o.WfpPacketDrop) {
        $sec = $State.SecurityLog
        $why = $(if (-not $sec) { 'The Security log settings could not be read.' } elseif ($sec.ManagedBy -eq 'Policy') { 'The Security log size is set by a policy: change it there.' } else { '' })
        $cur = $(if ($sec) { [long]$sec.MaxSizeBytes } else { 0 })
        & $add 'SecurityLog' 'Security' 'MaxSizeBytes' $cur ([Math]::Max($cur, [long]$SecurityLogMB * 1MB)) $why
    }
    if ($o.DnsClient) {
        $dns = $State.Dns
        & $add 'Dns' $script:IgwtDnsClientLog 'Enabled' $(if ($dns) { $dns.Enabled } else { 'Unknown' }) $true $(if (-not $dns) { 'The DNS client log settings could not be read.' } else { '' })
    }
    $notes = @()
    if (($o.WfpConnection -or $o.WfpPacketDrop)) { $notes += 'WFP auditing writes one Security event for every connection (5156/5157) and, for packet drops, every dropped packet (5152): use it for a limited time.' }
    if ($o.WfpPacketDrop) { $notes += 'Microsoft does not recommend packet drop auditing permanently (very high volume; for troubleshooting). Blocked connections are also in event 5157.' }
    $notes += 'Gaming: run a time-boxed session rather than leaving forensic logging on during competitive play.'
    [pscustomobject]@{ Profile = $LoggingProfile; Options = $o; SecurityLogMB = $SecurityLogMB; Ops = $ops.ToArray(); Changes = @($ops | Where-Object Changes).Count; Refused = @($ops | Where-Object Refused); Notes = $notes }
}

function Get-IgwtForensicSessionPath {
    <# .SYNOPSIS The session record (ProgramData State folder). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Get-IgwtDataPath -Kind State) 'forensic-session.json')
}

function Get-IgwtForensicSession {
    <#
    .SYNOPSIS
        The recorded forensic logging session (or $null): status (starting, active, rollback-incomplete),
        when it started and ends, its snapshot, and Expired when it needs restoring (the end has passed,
        for example while iG Windows Tuner was closed, or a start or rollback did not finish). A damaged
        record comes back with Corrupt (Stop-IgwtForensicLoggingSession can then restore the newest
        snapshot). There is no scheduled task: the next start of the app checks this. Read-only.
    #>
    [CmdletBinding()]
    param([datetime]$Now = (Get-Date))
    $path = Get-IgwtForensicSessionPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $s = Read-IgwtJsonFile -Path $path
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $rt = [System.Globalization.DateTimeStyles]::RoundtripKind
        if ([string]$s.kind -ne 'igwt-forensic-session' -or -not [string]$s.started -or -not [string]$s.snapshot) { throw 'required fields are missing' }
        $started = [datetime]::Parse([string]$s.started, $inv, $rt).ToLocalTime()
        $until = $(if ([string]$s.until) { [datetime]::Parse([string]$s.until, $inv, $rt).ToLocalTime() } else { $null })
        $status = $(if ([string]$s.status) { [string]$s.status } else { 'active' })
        return [pscustomobject]@{
            Corrupt = $false; Path = $path; Status = $status; Profile = [string]$s.profile; Snapshot = [string]$s.snapshot
            Started = $started; Until = $until; Expired = ($status -ne 'active' -or ($null -ne $until -and $Now -ge $until)); Changes = @($s.changes); Message = [string]$s.message
            EngineSession = [string]$s.engineSession
        }
    } catch {
        return [pscustomobject]@{ Corrupt = $true; Path = $path; Status = 'corrupt'; Expired = $true; Snapshot = ''; Message = "The forensic session record is damaged ($($_.Exception.Message)). Stop and restore uses the newest forensic snapshot." }
    }
}

function Save-IgwtForensicSessionRecord {
    <# .SYNOPSIS Writes the session record (ProgramData State folder). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the tool''s own session record; called by the session functions after their ShouldProcess.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Record)
    $file = Get-IgwtForensicSessionPath
    $dir = Split-Path -Parent $file
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    [System.IO.File]::WriteAllText($file, (ConvertTo-IgwtJson -InputObject $Record), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-IgwtForensicSnapshotFolders {
    <# .SYNOPSIS The forensic snapshot folders in the Backups folder, newest first. Read-only. #>
    [CmdletBinding()]
    param()
    $root = Get-IgwtDataPath -Kind Backups
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    @(Get-ChildItem -LiteralPath $root -Directory -Filter 'forensic-*' | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'snapshot.json') } | Sort-Object Name -Descending | ForEach-Object { $_.FullName })
}

function Start-IgwtForensicLoggingSession {
    <#
    .SYNOPSIS
        Starts forensic logging. The plan is made again from the current state (a policy that appeared
        after the preview is respected, and settings only ever go up). Then: snapshot of every setting
        it touches (firewall profile logging, the audit subcategories through auditpol /backup, Security
        log size, DNS client log), a session record (status starting), the changes, and status active
        with the end time (-Minutes; 0 = until stopped). When a step fails, everything applied so far is
        restored; if that restore is incomplete the record stays (rollback-incomplete) so it can be retried.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Plan, [ValidateSet(0, 30, 120, 480)][int]$Minutes = 120)
    Assert-IgwtWritable -Operation 'Start-IgwtForensicLoggingSession'
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Forensic logging needs administrator rights.' }
    $existing = Get-IgwtForensicSession
    if ($existing) { throw 'A forensic logging session is already recorded. Stop and restore it first.' }
    $options = @{}
    if ($Plan.Options) { foreach ($k in @($Plan.Options.Keys)) { $options[$k] = $Plan.Options[$k] } }
    $sizeMB = $(if ([int]$Plan.SecurityLogMB -in 256, 512, 1024) { [int]$Plan.SecurityLogMB } else { 512 })
    $fresh = Get-IgwtForensicLoggingPlan -LoggingProfile ([string]$Plan.Profile) -Options $options -SecurityLogMB $sizeMB
    $todo = @($fresh.Ops | Where-Object { $_.Changes })
    if (-not $todo.Count) { throw 'Nothing to change: every setting of this profile is already on (or set by a policy).' }
    if (-not $PSCmdlet.ShouldProcess('Forensic logging', "$($todo.Count) change(s), $(if ($Minutes) { "$Minutes min" } else { 'until stopped' })")) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $dir = Join-Path (Get-IgwtDataPath -Kind Backups) ('forensic-{0}' -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    $null = New-Item -ItemType Directory -Path $dir -Force
    # 1. Snapshot first: exact previous values of everything this plan touches.
    $fw = @(foreach ($name in @($todo | Where-Object Source -EQ 'Firewall' | ForEach-Object { $_.Target } | Select-Object -Unique)) {
            $p = Get-NetFirewallProfile -Name $name -PolicyStore PersistentStore -ErrorAction Stop
            [ordered]@{ profile = $name; logBlocked = [string]$p.LogBlocked; logAllowed = [string]$p.LogAllowed; logMaxKB = [long]$p.LogMaxSizeKilobytes }
        })
    $events = @(foreach ($ln in @($todo | Where-Object { $_.Source -in 'SecurityLog', 'Dns' } | ForEach-Object { $_.Target } | Select-Object -Unique)) {
            $cfg = Get-IgwtEventLogConfig -LogName $ln
            [ordered]@{ log = $ln; enabled = $cfg.Enabled; maxSizeBytes = $cfg.MaxSizeBytes; retention = $cfg.Retention; autoBackup = $cfg.AutoBackup }
        })
    $auditDir = ''
    if (@($todo | Where-Object Source -EQ 'Wfp').Count) {
        # The audit policy backup is taken here, before any change, in the format Restore-IgwtAuditPolicy reads.
        $auditDir = Join-Path $dir 'audit'
        $null = New-Item -ItemType Directory -Path $auditDir -Force
        $csv = Join-Path $auditDir 'audit-before.csv'
        $b = Invoke-IgwtAuditpol -Arguments @('/backup', "/file:$csv")
        if ($b.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $csv)) { throw "auditpol /backup failed (exit $($b.ExitCode)): $($b.Output). Nothing was changed." }
        $am = [ordered]@{ kind = 'igwt-audit-backup'; created = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME; sha256 = (Get-FileHash -LiteralPath $csv -Algorithm SHA256).Hash; changes = @() }
        [System.IO.File]::WriteAllText((Join-Path $auditDir 'manifest.json'), (ConvertTo-IgwtJson -InputObject $am), (New-Object System.Text.UTF8Encoding($false)))
    }
    $snapshot = [ordered]@{ kind = 'igwt-forensic-snapshot'; created = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME; profile = $fresh.Profile; firewall = $fw; eventLogs = $events; auditBackup = $auditDir
        changes = @($todo | ForEach-Object { [ordered]@{ source = $_.Source; target = $_.Target; setting = $_.Setting; before = [string]$_.Current; after = [string]$_.New } }) }
    [System.IO.File]::WriteAllText((Join-Path $dir 'snapshot.json'), (ConvertTo-IgwtJson -InputObject $snapshot), (New-Object System.Text.UTF8Encoding($false)))
    # 2. The session record before the first change: a crash from here on still leaves something to restore.
    $now = Get-Date
    $record = [ordered]@{ kind = 'igwt-forensic-session'; status = 'starting'; profile = $fresh.Profile; started = $now.ToUniversalTime().ToString('o')
        until = $(if ($Minutes) { $now.AddMinutes($Minutes).ToUniversalTime().ToString('o') } else { '' }); snapshot = $dir; message = ''
        changes = @($todo | ForEach-Object { "$($_.Source) $($_.Target) $($_.Setting) -> $($_.New)" }) }
    Save-IgwtForensicSessionRecord -Record $record
    # 3. The changes: journaled steps of one change session (3.6, DECISIONS T7), in the 3.5 order.
    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($op in @($todo | Where-Object Source -EQ 'SecurityLog')) {
        # The Security log grows before auditing starts, so the new events do not push old ones out.
        if ([long]$op.New -le [long]$op.Current) { continue }
        $steps.Add(@{ Target = [ordered]@{ provider = 'forensicEventLog'; key = 'forensic|eventlog|Security'; log = 'Security' }; Desired = [ordered]@{ maxSizeBytes = [long]$op.New } })
    }
    foreach ($op in @($todo | Where-Object Source -EQ 'Dns')) {
        $steps.Add(@{ Target = [ordered]@{ provider = 'forensicEventLog'; key = "forensic|eventlog|$($script:IgwtDnsClientLog)"; log = $script:IgwtDnsClientLog }; Desired = [ordered]@{ enabled = $true } })
    }
    foreach ($op in @($todo | Where-Object Source -EQ 'Wfp')) {
        $g = $(if ($op.Target -like '*Connection') { $script:IgwtWfpConnectionGuid } else { $script:IgwtWfpPacketDropGuid })
        $steps.Add(@{ Target = [ordered]@{ provider = 'forensicAudit'; key = "forensic|audit|$g"; guid = $g; backup = $auditDir }; Desired = [ordered]@{ setting = [string]$op.New } })
    }
    foreach ($name in @($todo | Where-Object Source -EQ 'Firewall' | ForEach-Object { $_.Target } | Select-Object -Unique)) {
        $d = [ordered]@{}
        foreach ($op in @($todo | Where-Object { $_.Source -eq 'Firewall' -and $_.Target -eq $name })) {
            switch ($op.Setting) {
                'LogBlocked' { $d.logBlocked = 'True' }
                'LogAllowed' { $d.logAllowed = 'True' }
                'LogMaxKB' { if ([long]$op.New -gt [long]$op.Current) { $d.logMaxKB = [long]$op.New } }
            }
        }
        if ($d.Count) { $steps.Add(@{ Target = [ordered]@{ provider = 'forensicFirewall'; key = "forensic|firewall|$name"; profile = $name }; Desired = $d }) }
    }
    # If no change can start (another change runs, a read-only journal), nothing was changed: the record goes (review 3.6 R15).
    try { $session = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'forensic'; ref = $dir; profile = $fresh.Profile }) -Title "Forensic logging ($($fresh.Profile))" -Confirm:$false }
    catch { Remove-Item -LiteralPath (Get-IgwtForensicSessionPath) -Force -ErrorAction SilentlyContinue; throw }
    $record.engineSession = $session.Id
    Save-IgwtForensicSessionRecord -Record $record
    $failure = $null; $rollbackErrors = @()
    try {
        foreach ($s in $steps) {
            $sr = Invoke-IgwtChangeStep -Session $session -Target $s.Target -Desired $s.Desired -Group 'forensic' -Confirm:$false
            if ($sr.Result -ne 'Committed') { $failure = $sr.Message; break }
        }
        # Everything applied so far goes back (reverse order, read back); the record stays when that is incomplete.
        if ($failure) { $rollbackErrors = @(Undo-IgwtChangeGroup -Session $session -Group 'forensic' -Confirm:$false) }
    } finally { Complete-IgwtChangeSession -Session $session }
    if ($failure) {
        if (-not $rollbackErrors.Count) {
            Remove-Item -LiteralPath (Get-IgwtForensicSessionPath) -Force -ErrorAction SilentlyContinue
            throw "Forensic logging was not started: $failure Every setting was restored."
        }
        $record.status = 'rollback-incomplete'; $record.message = "Start failed ($failure); not restored: $($rollbackErrors -join '; ')"
        Save-IgwtForensicSessionRecord -Record $record
        Write-IgwtLog -Level Error -Message "Forensic logging: $($record.message). Snapshot: $dir"
        throw "Forensic logging was not started: $failure Some settings could not be restored ($($rollbackErrors -join '; ')); use Stop and restore to try again."
    }
    $record.status = 'active'
    Save-IgwtForensicSessionRecord -Record $record
    Write-IgwtLog -Message "Forensic logging started ($($fresh.Profile), $(if ($Minutes) { "$Minutes min" } else { 'until stopped' })): $($todo.Count) change(s). Snapshot: $dir"
    return (Get-IgwtForensicSession)
}

function Restore-IgwtForensicLogging {
    <#
    .SYNOPSIS
        Restores every setting in a forensic snapshot exactly: firewall profile logging values, the
        audit policy (auditpol /restore of the backup), and the event log settings it changed. Event
        logs are never cleared: a Security log that was enlarged keeps its events; the configured
        maximum is set back.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    Assert-IgwtWritable -Operation 'Restore-IgwtForensicLogging'
    if (-not (Test-IgwtModuleOperationDirect -BoundParameters $PSBoundParameters)) { return (Invoke-IgwtModuleOperation -Command 'Restore-IgwtForensicLogging' -Parameters $PSBoundParameters) }
    $file = Join-Path $SnapshotPath 'snapshot.json'
    if (-not (Test-Path -LiteralPath $file)) { throw "'$SnapshotPath' is not a forensic logging snapshot (snapshot.json missing)." }
    $s = Read-IgwtJsonFile -Path $file
    if ([string]$s.kind -ne 'igwt-forensic-snapshot') { throw "'$SnapshotPath' is not an iG Windows Tuner forensic logging snapshot." }
    if (-not $PSCmdlet.ShouldProcess('Forensic logging', "Restore from $SnapshotPath")) { return $null }
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($s.firewall)) {
        try { Set-NetFirewallProfile -Name ([string]$p.profile) -LogBlocked ([string]$p.logBlocked) -LogAllowed ([string]$p.logAllowed) -LogMaxSizeKilobytes ([uint64]$p.logMaxKB) -ErrorAction Stop }
        catch { $errors.Add("Firewall $($p.profile): $($_.Exception.Message)") }
    }
    if ([string]$s.auditBackup) {
        try { $null = Restore-IgwtAuditPolicy -BackupPath ([string]$s.auditBackup) -Confirm:$false } catch { $errors.Add("Audit policy: $($_.Exception.Message)") }
    }
    foreach ($e in @($s.eventLogs)) {
        $ln = [string]$e.log
        $changed = @($s.changes | Where-Object { [string]$_.target -eq $ln })
        $args2 = @('sl', $ln)
        if (@($changed | Where-Object { [string]$_.setting -eq 'MaxSizeBytes' }).Count) { $args2 += "/ms:$([long]$e.maxSizeBytes)" }
        if (@($changed | Where-Object { [string]$_.setting -eq 'Enabled' }).Count) { $args2 += "/e:$(([string][bool]$e.enabled).ToLowerInvariant())" }
        if ($args2.Count -le 2) { continue }
        try { $r = Invoke-IgwtWevtutil -Arguments $args2; if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.Output)" } } catch { $errors.Add("${ln}: $($_.Exception.Message)") }
    }
    if ($errors.Count) { Write-IgwtLog -Level Error -Message "Forensic logging restore from ${SnapshotPath}: $($errors -join '; ')" }
    else { Write-IgwtLog -Message "Forensic logging restored from $SnapshotPath" }
    return [pscustomobject]@{ Restored = $SnapshotPath; Errors = $errors.ToArray(); Complete = ($errors.Count -eq 0) }
}

function Stop-IgwtForensicLoggingSession {
    <#
    .SYNOPSIS
        Ends the forensic logging session (also an expired, unfinished or damaged one): restores its
        snapshot and removes the session record when everything was restored. A damaged record uses the
        newest forensic snapshot folder (or -SnapshotPath, which must be one of them). Collected logs and
        events stay.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$SnapshotPath)
    Assert-IgwtWritable -Operation 'Stop-IgwtForensicLoggingSession'
    $s = Get-IgwtForensicSession
    if (-not $s) { return [pscustomobject]@{ Stopped = $false; Errors = @(); Snapshot = ''; Message = 'No forensic logging session is running.' } }
    $folders = @(Get-IgwtForensicSnapshotFolders)
    $snap = $(if ($SnapshotPath) { $SnapshotPath } elseif ($s.Corrupt) { @($folders)[0] } else { $s.Snapshot })
    if (-not $snap) { throw "$($s.Message) No forensic snapshot folder was found in the Backups folder." }
    # Only the tool's own snapshot folders are accepted (a session record or an argument cannot point elsewhere).
    $full = [System.IO.Path]::GetFullPath($snap).TrimEnd('\')
    if (-not @($folders | Where-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') -eq $full }).Count) { throw "'$snap' is not a forensic snapshot folder of iG Windows Tuner (Backups\forensic-*)." }
    if (-not $PSCmdlet.ShouldProcess('Forensic logging session', "Stop and restore the previous settings from $snap")) { return $null }
    if (-not $s.Corrupt -and -not $SnapshotPath -and $s.EngineSession) {
        # 3.6: revert the session's journaled steps (each read back). Forensic logging restores its own
        # values unconditionally, as in 3.5, so a value changed since is restored too.
        $plan = @(Get-IgwtRevertPlan -SessionId $s.EngineSession)
        $decisions = @{}; foreach ($p in $plan) { $decisions[$p.Key] = 'Restore' }
        $rv = Invoke-IgwtJournalRevert -Plan $plan -Decisions $decisions -Title "Stop forensic logging ($($s.Profile))" -Confirm:$false
        $bad = @($rv.Results | Where-Object { $_.Result -notin 'Reverted', 'Already' })
        $r = [pscustomobject]@{ Complete = ($bad.Count -eq 0); Errors = @($bad | ForEach-Object { "$($_.Key): $($_.Message)" }) }
    } else {
        # A 3.5 session, or a damaged record: the snapshot-based restore.
        $r = Restore-IgwtForensicLogging -SnapshotPath $snap -Confirm:$false
    }
    if ($r.Complete) { Remove-Item -LiteralPath $s.Path -Force }
    return [pscustomobject]@{ Stopped = $r.Complete; Errors = $r.Errors; Snapshot = $snap; Message = $(if ($r.Complete) { 'Forensic logging stopped; the previous settings are back.' } else { "Some settings were not restored: $($r.Errors -join '; '). The session stays recorded so you can try again." }) }
}

function Measure-IgwtConnectionRate {
    <#
    .SYNOPSIS
        Samples the connection table twice (TCP connections and UDP endpoints) and counts the ones
        that appeared in between: new connections per hour at the current use of the PC. Read-only.
    #>
    [CmdletBinding()]
    param([ValidateRange(2, 60)][int]$Seconds = 10)
    $take = {
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) { $null = $set.Add("T|$($c.LocalAddress)|$($c.LocalPort)|$($c.RemoteAddress)|$($c.RemotePort)|$($c.OwningProcess)") }
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) { $null = $set.Add("U|$($u.LocalAddress)|$($u.LocalPort)|$($u.OwningProcess)") }
        , $set
    }
    $a = & $take
    Start-Sleep -Seconds $Seconds
    $b = & $take
    $new = 0; foreach ($k in $b) { if (-not $a.Contains($k)) { $new++ } }
    [pscustomobject]@{ Seconds = $Seconds; Before = $a.Count; After = $b.Count; New = $new; PerHour = [long][Math]::Round($new * 3600.0 / $Seconds) }
}

function Get-IgwtForensicVolumeEstimate {
    <#
    .SYNOPSIS
        Rough expected volume of WFP connection auditing: events per hour from the sampled connection
        rate (at least one 5156 or 5157 event per new connection) and how many hours each Security log
        size holds. The bytes per event are an assumption (UNVERIFIED, about 1 KB); the real retention
        shows after a session. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][long]$ConnectionsPerHour, [int[]]$SizesMB = @(256, 512, 1024), [int]$BytesPerEvent = 1024)
    $eventsPerHour = [Math]::Max([long]1, $ConnectionsPerHour)
    [pscustomobject]@{
        EventsPerHour = $eventsPerHour; BytesPerEvent = $BytesPerEvent; Assumption = 'At least one event per new connection; about 1 KB per event (UNVERIFIED estimate).'
        Retention = @(foreach ($mb in $SizesMB) { [pscustomobject]@{ SizeMB = $mb; Hours = [Math]::Round(($mb * 1MB) / ($eventsPerHour * [double]$BytesPerEvent), 1) } })
    }
}
