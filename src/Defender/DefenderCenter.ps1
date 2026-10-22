# DefenderCenter.ps1
# Defender & Security Control Center (SPEC-v3 section 4): status and health, every Defender setting
# with its current value, the recommended value and who manages it, threat history, quarantine,
# on-demand scans, web and phishing protection, device control and detection logging. Reading is
# done with Get-Mp*, the registry and event log metadata. Changes go through the policy presets
# (Local GPO); the only direct Defender writes are turning Network Inspection parsers ON, starting
# scans the user asked for, and quarantine actions the user confirms. Nothing here turns a
# protection off. Controlled folder access, ASR and exploit protection live in the ASR Center.

$script:IgwtDefenderSettings = $null
$script:IgwtDefenderPolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'

function Get-IgwtDefenderSettingCatalog {
    <# .SYNOPSIS The Defender settings catalog (data\defender\settings.json). #>
    [CmdletBinding()]
    param()
    if (-not $script:IgwtDefenderSettings) { $script:IgwtDefenderSettings = Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'defender\settings.json') }
    return $script:IgwtDefenderSettings
}

function Get-IgwtMpPreferenceSafe {
    [CmdletBinding()]
    param()
    return (Get-IgwtCached -Key 'mp:pref' -ScriptBlock { Get-MpPreference -ErrorAction Stop })
}

function Get-IgwtMpStatusSafe {
    [CmdletBinding()]
    param()
    return (Get-IgwtCached -Key 'mp:status' -TtlSeconds 10 -ScriptBlock { Get-MpComputerStatus -ErrorAction Stop })
}

function Get-IgwtDefenderEndpointState {
    <# .SYNOPSIS Whether the PC is onboarded to Microsoft Defender for Endpoint (OnboardingState = 1). Read-only. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $v = Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'
    return ([bool]$v.Exists -and [string]$v.Value -eq '1')
}

function Get-IgwtDefenderStatus {
    <#
    .SYNOPSIS
        Defender status and health: engine, platform and security intelligence versions and age,
        running mode (Normal, Passive, EDR block mode), real-time protection, Tamper Protection
        (read-only), Smart App Control, last scans, Defender for Endpoint onboarding and who
        manages the PC. Read-only.
    #>
    [CmdletBinding()]
    param()
    $s = $null; $err = ''
    try { $s = Get-IgwtMpStatusSafe } catch { $err = "Defender status unavailable: $($_.Exception.Message)" }
    $m = Get-IgwtManagementState
    $findings = New-Object System.Collections.Generic.List[object]
    if ($s) {
        if (-not $s.AMServiceEnabled -or -not $s.AntivirusEnabled) { $findings.Add([pscustomobject]@{ Severity = 'Fail'; Text = 'Microsoft Defender Antivirus is not running. Check whether another antivirus product replaced it.' }) }
        if ([string]$s.AMRunningMode -match 'Passive') { $findings.Add([pscustomobject]@{ Severity = 'Warn'; Text = 'Defender runs in passive mode: another antivirus product is the primary one; real-time protection is off in Defender.' }) }
        if (-not $s.RealTimeProtectionEnabled) { $findings.Add([pscustomobject]@{ Severity = 'Fail'; Text = 'Real-time protection is off.' }) }
        if ([int]$s.AntivirusSignatureAge -gt 3) { $findings.Add([pscustomobject]@{ Severity = 'Warn'; Text = "Security intelligence is $($s.AntivirusSignatureAge) days old." }) }
        if (-not $s.IsTamperProtected) { $findings.Add([pscustomobject]@{ Severity = 'Warn'; Text = 'Tamper Protection is off. Turn it on in Windows Security > Virus & threat protection settings (iG Windows Tuner never changes it).' }) }
        if ([int]$s.QuickScanAge -gt 7 -and [int]$s.FullScanAge -gt 7) { $findings.Add([pscustomobject]@{ Severity = 'Info'; Text = "No scan for $($s.QuickScanAge) days." }) }
    }
    [pscustomobject]@{
        Available          = [bool]$s
        Error              = $err
        RunningMode        = $(if ($s) { [string]$s.AMRunningMode } else { '' })
        EngineVersion      = $(if ($s) { [string]$s.AMEngineVersion } else { '' })
        PlatformVersion    = $(if ($s) { [string]$s.AMProductVersion } else { '' })
        SignatureVersion   = $(if ($s) { [string]$s.AntivirusSignatureVersion } else { '' })
        SignatureAgeDays   = $(if ($s) { [int]$s.AntivirusSignatureAge } else { $null })
        SignatureUpdated   = $(if ($s) { $s.AntivirusSignatureLastUpdated } else { $null })
        RealTimeProtection = $(if ($s) { [bool]$s.RealTimeProtectionEnabled } else { $null })
        TamperProtected    = $(if ($s) { [bool]$s.IsTamperProtected } else { $null })
        TamperSource       = $(if ($s) { [string]$s.TamperProtectionSource } else { '' })
        SmartAppControl    = $(if ($s) { [string]$s.SmartAppControlState } else { '' })
        QuickScanAgeDays   = $(if ($s) { [int]$s.QuickScanAge } else { $null })
        FullScanAgeDays    = $(if ($s) { [int]$s.FullScanAge } else { $null })
        DefenderForEndpoint = (Get-IgwtDefenderEndpointState)
        Managed            = [bool]$m.Managed
        Authorities        = @($m.Authorities)
        Findings           = $findings.ToArray()
    }
}

function Get-IgwtDefenderSettingSource {
    <#
    .SYNOPSIS
        Who sets one Defender setting: Domain GPO, Local GPO, Policy (registry only), MDM, or Local
        (Defender's own preference). Defender for Endpoint security settings management writes MDM
        policy. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Setting, $PolicyDefinition)
    if ($PolicyDefinition) {
        $names = @(@($PolicyDefinition.ValueName) + @($PolicyDefinition.Elements | ForEach-Object { $_.ValueName }) | Where-Object { $_ })
        $key = [string]$PolicyDefinition.Key
        foreach ($n in $names) {
            $v = Get-IgwtRegistryValue -Path ('HKLM:\' + $key) -Name $n
            if (-not $v.Exists) { continue }
            try { if (@(Get-IgwtDomainPolicyResult | Where-Object { $_.Scope -eq 'Machine' -and [string]::Equals($_.Key, $key, [System.StringComparison]::OrdinalIgnoreCase) -and $_.ValueName -eq $n }).Count) { return 'Domain GPO' } } catch { Write-Verbose 'No domain results.' }
            if (@(Get-IgwtLocalPolicyEntries -Class Machine | Where-Object { [string]::Equals([string]$_.Key, $key, [System.StringComparison]::OrdinalIgnoreCase) -and $_.ValueName -eq $n }).Count) { return 'Local GPO' }
            return 'Policy (registry only)'
        }
    }
    $mdm = Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Name ([string]$Setting.mp)
    if ($mdm.Exists) { return 'MDM' }
    return 'Local'
}

function Get-IgwtDefenderSettings {
    <#
    .SYNOPSIS
        Every catalog Defender setting that exists on this platform version: category, current
        value, the protective value, status (On, Off, Below, Info), who manages it, and the ADMX
        policy that changes it. Settings that Get-MpPreference does not report are left out. Read-only.
    #>
    [CmdletBinding()]
    param([string]$Category)
    $cat = Get-IgwtDefenderSettingCatalog
    $pref = $null; $err = ''
    try { $pref = Get-IgwtMpPreferenceSafe } catch { $err = $_.Exception.Message }
    if (-not $pref) { throw "Defender preferences are unavailable: $err" }
    $admx = $null
    try { $admx = Get-IgwtAdmxCatalog } catch { Write-Verbose "ADMX catalog unavailable: $($_.Exception.Message)" }
    foreach ($s in @($cat.settings)) {
        if ($Category -and $s.category -ne $Category) { continue }
        if (-not $pref.PSObject.Properties[[string]$s.mp]) { continue }
        $cur = $pref.([string]$s.mp)
        $pd = $null
        if ($s.policy -and $admx) { $pd = @($admx.Policies | Where-Object { $_.Id -eq [string]$s.policy }) | Select-Object -First 1 }
        $status = 'Info'
        if ($null -ne $s.on -and $s.kind -in 'protection', 'parser') { $status = $(if ([string]$cur -eq [string]$s.on) { 'On' } else { 'Off' }) }
        elseif ($null -ne $s.on -and $s.kind -eq 'level') { $status = $(if ([double]$cur -ge [double]$s.on) { 'On' } elseif ([double]$cur -eq 0) { 'Off' } else { 'Below' }) }
        [pscustomobject]@{
            Category = [string]$s.category; Name = [string]$s.name; Property = [string]$s.mp; Kind = [string]$s.kind
            Current = $cur; Protective = $s.on; Status = $status; Hint = [string]$s.hint
            Source = (Get-IgwtDefenderSettingSource -Setting $s -PolicyDefinition $pd)
            Policy = $(if ($pd) { $pd.Id } else { '' })
            Change = $(if ($s.kind -eq 'parser') { 'Network Inspection parser: -DefenderParsersOn turns it on (never off).' } elseif ($pd) { "Policy $($pd.Id) (policy presets, -PolicySet)" } else { 'Shown only.' })
        }
    }
}

#region Network Inspection parsers

function Set-IgwtDefenderParsersOn {
    <#
    .SYNOPSIS
        Turns ON Network Inspection parsers, inbound connection filtering, datagram processing and
        the DNS sinkhole that are off (catalog kind 'parser'), with Set-MpPreference. One-way by
        design: iG Windows Tuner never turns an inspection parser off, so there is no revert.
    .PARAMETER Name
        Limit to these Get-MpPreference properties (default: every parser that is off).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]]$Name, [switch]$AcknowledgeManaged)
    $m = Get-IgwtManagementState
    if ($m.Managed -and -not $AcknowledgeManaged) { throw "This PC is managed ($(@($m.Authorities) -join ', ')); Defender settings may come from your organization. Pass -AcknowledgeManaged to change them locally." }
    $pref = Get-IgwtMpPreferenceSafe
    $parsers = @((Get-IgwtDefenderSettingCatalog).settings | Where-Object { $_.kind -eq 'parser' -and $pref.PSObject.Properties[[string]$_.mp] })
    if ($Name) {
        $unknown = @($Name | Where-Object { $n = $_; -not @($parsers | Where-Object { $_.mp -eq $n }).Count })
        if ($unknown.Count) { throw "Not a Network Inspection parser setting: $($unknown -join ', ')." }
        $parsers = @($parsers | Where-Object { $Name -contains $_.mp })
    }
    $todo = @($parsers | Where-Object { [string]$pref.([string]$_.mp) -ne [string]$_.on })
    $done = New-Object System.Collections.Generic.List[string]
    foreach ($p in $todo) {
        if ($p.on -isnot [bool]) { throw "Parser setting $($p.mp) has no on/off value; refused." }
        if (-not $PSCmdlet.ShouldProcess([string]$p.name, 'Turn on')) { continue }
        $arg = @{ ([string]$p.mp) = [bool]$p.on; ErrorAction = 'Stop' }
        Set-MpPreference @arg
        $done.Add([string]$p.name)
    }
    if ($done.Count) { Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false; Write-IgwtLog -Message "Network Inspection turned on: $($done -join ', ')" }
    return [pscustomobject]@{ TurnedOn = $done.ToArray(); AlreadyOn = @($parsers | Where-Object { $todo -notcontains $_ } | ForEach-Object { [string]$_.name }) }
}

#endregion

#region Threats, quarantine and scans

function Get-IgwtDefenderThreats {
    <#
    .SYNOPSIS
        Threat history: every detection (Get-MpThreatDetection) joined with its threat (name,
        severity, category, status), newest first. Read-only.
    #>
    [CmdletBinding()]
    param([int]$Days = 0)
    $threats = @{}
    foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $threats[[string]$t.ThreatID] = $t }
    $sev = @{ 0 = 'Unknown'; 1 = 'Low'; 2 = 'Moderate'; 4 = 'High'; 5 = 'Severe' }
    $rows = foreach ($d in @(Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
        if ($Days -gt 0 -and $d.InitialDetectionTime -and ([datetime]$d.InitialDetectionTime) -lt (Get-Date).AddDays(-$Days)) { continue }
        $t = $threats[[string]$d.ThreatID]
        [pscustomobject]@{
            Time = $d.InitialDetectionTime; Threat = $(if ($t) { [string]$t.ThreatName } else { "ThreatID $($d.ThreatID)" }); ThreatId = [string]$d.ThreatID
            Severity = $(if ($t -and $sev.ContainsKey([int]$t.SeverityID)) { $sev[[int]$t.SeverityID] } else { '' })
            Resources = @($d.Resources); Process = [string]$d.ProcessName; User = [string]$d.DomainUser
            Action = [string]$d.ThreatStatusID; Success = [bool]$d.ActionSuccess; Active = $(if ($t) { [bool]$t.IsActive } else { $false })
        }
    }
    return @($rows | Sort-Object Time -Descending)
}

function Get-IgwtMpCmdRunPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $s = Get-IgwtMpStatusSafe
    $platform = Join-Path $env:ProgramData "Microsoft\Windows Defender\Platform\$([string]$s.AMProductVersion)\MpCmdRun.exe"
    if (Test-Path -LiteralPath $platform) { return $platform }
    return (Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe')
}

function Restore-IgwtQuarantineItem {
    <#
    .SYNOPSIS
        Restores a quarantined threat by name (MpCmdRun -Restore -Name). Only on the user's explicit
        request: the file comes back to its original location, so it can run again.
    .PARAMETER IUnderstandTheRisk
        Required: restoring a quarantined file can reintroduce malware.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][string]$ThreatName, [switch]$IUnderstandTheRisk)
    if (-not $IUnderstandTheRisk) { throw 'Restoring a quarantined file can reintroduce malware. Pass -IUnderstandTheRisk to confirm.' }
    if ($ThreatName -notmatch '^[\w.:/!\-]+$') { throw "Unexpected threat name '$ThreatName'." }
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: MpCmdRun must not run in tests.' }
    if (-not $PSCmdlet.ShouldProcess($ThreatName, 'Restore from quarantine')) { return $null }
    $exe = Get-IgwtMpCmdRunPath
    $out = & $exe '-Restore' '-Name' $ThreatName 2>&1 | Out-String
    Write-IgwtLog -Level Warn -Message "Quarantine restore of $ThreatName (exit $LASTEXITCODE): $($out.Trim())"
    return [pscustomobject]@{ Threat = $ThreatName; ExitCode = $LASTEXITCODE; Output = $out.Trim() }
}

function Remove-IgwtDefenderThreat {
    <# .SYNOPSIS Removes active threats (Remove-MpThreat): deletes the detected files Defender has not cleaned yet. User-initiated only. #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not $PSCmdlet.ShouldProcess('Active threats', 'Remove')) { return $null }
    Remove-MpThreat -ErrorAction Stop
    Write-IgwtLog -Message 'Active threats removed (Remove-MpThreat).'
    return $true
}

function Start-IgwtDefenderScan {
    <#
    .SYNOPSIS
        Starts a Defender scan: Quick, Full or Custom (-Path). Offline starts Microsoft Defender
        Offline, which restarts the PC immediately and needs -ConfirmRestart. User-initiated only.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][ValidateSet('Quick', 'Full', 'Custom', 'Offline')][string]$Type, [string]$Path, [switch]$ConfirmRestart, [switch]$AsJob)
    if ($Type -eq 'Custom' -and -not $Path) { throw 'A custom scan needs -Path.' }
    if ($Type -eq 'Custom' -and -not (Test-Path -LiteralPath $Path)) { throw "Path '$Path' not found." }
    if ($Type -eq 'Offline') {
        if (-not $ConfirmRestart) { throw 'Microsoft Defender Offline restarts the PC right away and scans for about 15 minutes. Save your work and pass -ConfirmRestart.' }
        if (-not $PSCmdlet.ShouldProcess('This PC', 'Restart into Microsoft Defender Offline scan')) { return $null }
        Write-IgwtLog -Level Warn -Message 'Starting Microsoft Defender Offline scan (restart).'
        Start-MpWDOScan -ErrorAction Stop
        return [pscustomobject]@{ Type = 'Offline'; Started = $true }
    }
    if (-not $PSCmdlet.ShouldProcess($(if ($Path) { $Path } else { 'This PC' }), "$Type scan")) { return $null }
    $arg = @{ ScanType = "${Type}Scan"; ErrorAction = 'Stop' }
    if ($Type -eq 'Custom') { $arg.ScanPath = $Path }
    if ($AsJob) { $arg.AsJob = $true }
    Write-IgwtLog -Message "Defender $Type scan started$(if ($Path) { " on $Path" })."
    $r = Start-MpScan @arg
    return [pscustomobject]@{ Type = $Type; Started = $true; Job = $r }
}

#endregion

#region Web, device control and detection logging

function Get-IgwtWebProtectionStatus {
    <#
    .SYNOPSIS
        SmartScreen for apps and files (Windows), Microsoft Edge and Store apps, Edge PUA blocking,
        and Enhanced Phishing Protection policies: current value and whether a policy sets it. Read-only.
    #>
    [CmdletBinding()]
    param()
    $rows = @(
        @{ Name = 'SmartScreen for apps and files (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Value = 'EnableSmartScreen'; On = '1'; Absent = 'Not configured (Windows default: warn)' },
        @{ Name = 'SmartScreen for apps and files'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; Value = 'SmartScreenEnabled'; On = 'Warn|RequireAdmin'; Absent = 'Windows default (warn)' },
        @{ Name = 'SmartScreen in Microsoft Edge (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Value = 'SmartScreenEnabled'; On = '1'; Absent = 'Not configured (Edge default: on)' },
        @{ Name = 'Edge blocks potentially unwanted apps (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Value = 'SmartScreenPuaEnabled'; On = '1'; Absent = 'Not configured (user choice)' },
        @{ Name = 'SmartScreen for Store apps (this user)'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost'; Value = 'EnableWebContentEvaluation'; On = '1'; Absent = 'Windows default (on)' },
        @{ Name = 'Enhanced Phishing Protection service (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Value = 'ServiceEnabled'; On = '1'; Absent = 'Not configured' },
        @{ Name = 'Warn on phishing sites (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Value = 'NotifyMalicious'; On = '1'; Absent = 'Not configured' },
        @{ Name = 'Warn on password reuse (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Value = 'NotifyPasswordReuse'; On = '1'; Absent = 'Not configured' },
        @{ Name = 'Warn on unsafe password storage (policy)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Value = 'NotifyUnsafeApp'; On = '1'; Absent = 'Not configured' }
    )
    foreach ($r in $rows) {
        $v = Get-IgwtRegistryValue -Path $r.Path -Name $r.Value
        [pscustomobject]@{ Name = $r.Name; Value = $(if ($v.Exists) { [string]$v.Value } else { $r.Absent }); Status = $(if (-not $v.Exists) { 'Default' } elseif ([string]$v.Value -match "^(?:$($r.On))$") { 'On' } else { 'Off' }); Key = "$($r.Path)\$($r.Value)" }
    }
}

function Get-IgwtDeviceControlStatus {
    <# .SYNOPSIS Device installation restrictions, removable storage access policies and Defender device control state. Read-only. #>
    [CmdletBinding()]
    param()
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Area = 'Device installation' }, @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'; Area = 'Removable storage' })) {
        if (-not (Test-IgwtRegistryKey -Path $p.Path)) { continue }
        $key = Get-Item -LiteralPath (Resolve-IgwtRegistryPath -Path $p.Path) -ErrorAction SilentlyContinue
        foreach ($k in @(@($key) + @(Get-ChildItem -LiteralPath (Resolve-IgwtRegistryPath -Path $p.Path) -Recurse -ErrorAction SilentlyContinue))) {
            if (-not $k) { continue }
            foreach ($n in @($k.GetValueNames())) { $out.Add([pscustomobject]@{ Area = $p.Area; Setting = "$($k.PSChildName)\$n"; Value = [string]$k.GetValue($n) }) }
        }
    }
    $state = ''
    try { $state = [string](Get-IgwtMpStatusSafe).DeviceControlState } catch { $state = '' }
    [pscustomobject]@{ Policies = $out.ToArray(); DefenderDeviceControl = $state; Note = 'Change these with the Removable Media & Device Installation policy preset or -PolicySet.' }
}

function Get-IgwtDetectionLoggingStatus {
    <#
    .SYNOPSIS
        SOC readiness: Defender operational log, Security log size, process creation auditing with
        command line (event 4688), PowerShell script block, module and transcription logging,
        and Sysmon (detected and used, never installed). Read-only.
    #>
    [CmdletBinding()]
    param()
    $logs = foreach ($n in 'Microsoft-Windows-Windows Defender/Operational', 'Security', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational') {
        $l = $null
        try { $l = Get-WinEvent -ListLog $n -ErrorAction Stop } catch { $l = $null }
        [pscustomobject]@{ Log = $n; Exists = [bool]$l; Enabled = $(if ($l) { [bool]$l.IsEnabled } else { $false }); MaxSizeMB = $(if ($l) { [math]::Round($l.MaximumSizeInBytes / 1MB, 1) } else { $null }); Records = $(if ($l) { $l.RecordCount } else { $null }) }
    }
    $logs = @($logs)
    $val = { param($p, $n) $v = Get-IgwtRegistryValue -Path $p -Name $n; if ($v.Exists) { [string]$v.Value } else { '' } }
    $sysmon = @(Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object -First 1)
    $checks = @(
        [pscustomobject]@{ Name = 'Command line in process creation events (4688)'; On = ((& $val 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq '1'); Note = 'Also needs Audit Process Creation (Success) in the audit policy.' },
        [pscustomobject]@{ Name = 'PowerShell script block logging'; On = ((& $val 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq '1'); Note = '' },
        [pscustomobject]@{ Name = 'PowerShell module logging'; On = ((& $val 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq '1'); Note = '' },
        [pscustomobject]@{ Name = 'PowerShell transcription'; On = ((& $val 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting') -eq '1'); Note = 'Transcripts can contain secrets; protect their folder.' },
        [pscustomobject]@{ Name = 'Advanced audit policy overrides legacy categories'; On = ((& $val 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy') -eq '1'); Note = '' },
        [pscustomobject]@{ Name = 'Security log at least 192 MB'; On = (@($logs | Where-Object { $_.Log -eq 'Security' -and $_.MaxSizeMB -ge 192 }).Count -gt 0); Note = 'Reading the Security log size needs administrator rights.' }
    )
    [pscustomobject]@{
        Logs = $logs; Checks = $checks
        Sysmon = [pscustomobject]@{ Installed = [bool]$sysmon.Count; Service = $(if ($sysmon.Count) { [string]$sysmon[0].Name } else { '' }); Running = $(if ($sysmon.Count) { [string]$sysmon[0].Status -eq 'Running' } else { $false }); Note = 'Sysmon is detected and its events are used when present; iG Windows Tuner never installs it.' }
        Preset = 'policy.audit-logging'
    }
}

function Get-IgwtSysmonEventSummary {
    <# .SYNOPSIS Counts of recent Sysmon events per event id (process create, network connect, ...), when Sysmon is installed. Read-only. #>
    [CmdletBinding()]
    param([int]$Hours = 24, [int]$Max = 5000)
    $names = @{ 1 = 'Process create'; 3 = 'Network connection'; 7 = 'Image loaded'; 8 = 'CreateRemoteThread'; 10 = 'Process access'; 11 = 'File create'; 12 = 'Registry object'; 13 = 'Registry value set'; 22 = 'DNS query'; 23 = 'File delete' }
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = (Get-Date).AddHours(-$Hours) } -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
    foreach ($g in @($ev | Group-Object Id | Sort-Object Count -Descending)) { [pscustomobject]@{ EventId = [int]$g.Name; Name = $(if ($names.ContainsKey([int]$g.Name)) { $names[[int]$g.Name] } else { '' }); Count = $g.Count } }
}

#endregion

function Get-IgwtDefenderCenter {
    <#
    .SYNOPSIS
        The whole Defender & Security Control Center as one object: status, settings by category,
        exclusions audit, firewall logging, web protection, device control and detection logging.
        Read-only; sections that need administrator rights say so.
    #>
    [CmdletBinding()]
    param([ValidateSet('All', 'Status', 'Settings', 'Exclusions', 'Firewall', 'Web', 'DeviceControl', 'Logging')][string]$Section = 'All')
    $o = [ordered]@{}
    $try = { param($n, $sb) try { $o[$n] = & $sb } catch { $o[$n] = [pscustomobject]@{ Error = $_.Exception.Message } } }
    if ($Section -in 'All', 'Status') { & $try 'Status' { Get-IgwtDefenderStatus } }
    if ($Section -in 'All', 'Settings') { & $try 'Settings' { @(Get-IgwtDefenderSettings) } }
    if ($Section -in 'All', 'Exclusions') { & $try 'Exclusions' { Get-IgwtDefenderExclusionAudit } }
    if ($Section -in 'All', 'Firewall') { & $try 'Firewall' { @(Get-IgwtFirewallLoggingStatus) } }
    if ($Section -in 'All', 'Web') { & $try 'Web' { @(Get-IgwtWebProtectionStatus) } }
    if ($Section -in 'All', 'DeviceControl') { & $try 'DeviceControl' { Get-IgwtDeviceControlStatus } }
    if ($Section -in 'All', 'Logging') { & $try 'Logging' { Get-IgwtDetectionLoggingStatus } }
    $o['AsrCenter'] = 'Controlled folder access, attack surface reduction and exploit protection: -Asr (the ASR Center is the single source of truth).'
    return [pscustomobject]$o
}
