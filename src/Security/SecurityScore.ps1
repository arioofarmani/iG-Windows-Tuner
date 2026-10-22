# SecurityScore.ps1
# Read-only security overview:
#   - a weighted security score in which every check routes to its fix (a catalog item, the ASR
#     Center, Windows Security, firmware or Settings guidance)
#   - a local accounts audit (Guest, built-in Administrator, administrators, password requirement)
#   - a listening-ports report (which programs accept connections, on which interfaces)
# Nothing here changes the system. Facts are collected once (Get-IgwtSecurityFacts) and scored by
# a pure function (ConvertTo-IgwtSecurityScore), so the scoring is testable without a live PC.

# Every check has a hint (140 characters or fewer) and a description, like every catalog item.
$script:IgwtSecurityChecks = @(
    [pscustomobject]@{ Id = 'defender'; Name = 'Microsoft Defender real-time protection'; Weight = 15; Fix = 'WindowsSecurity'; Target = 'Virus & threat protection'
        Hint = 'Defender Antivirus is active with real-time protection on.'
        Description = 'Real-time protection scans files and processes as they run. ASR rules, network protection and controlled folder access all depend on it. iG Windows Tuner never turns it off.' }
    [pscustomobject]@{ Id = 'tamper'; Name = 'Tamper Protection'; Weight = 8; Fix = 'WindowsSecurity'; Target = 'Virus & threat protection settings'
        Hint = 'Stops malware and tools from switching Defender protection off. Turn it on in Windows Security; iG Windows Tuner only reads it.'
        Description = 'Tamper Protection locks key Defender settings so that malware (or a careless tweak tool) cannot disable them. iG Windows Tuner reads it and never changes it.' }
    [pscustomobject]@{ Id = 'signatures'; Name = 'Security intelligence up to date'; Weight = 4; Fix = 'WindowsSecurity'; Target = 'Protection updates'
        Hint = 'Defender definitions are at most 3 days old.'
        Description = 'Old security intelligence misses new threats. Windows Update normally refreshes it several times a day; check Protection updates if it is older than three days.' }
    [pscustomobject]@{ Id = 'cloud'; Name = 'Cloud protection and PUA blocking'; Weight = 5; Fix = 'Tweak'; Target = 'sec.defender-hardening'
        Hint = 'Cloud-delivered protection, safe sample submission and potentially unwanted app blocking are on.'
        Description = 'Cloud protection gives Defender verdicts on new files within seconds and several ASR rules need it. PUA blocking stops bundled adware and coin miners.' }
    [pscustomobject]@{ Id = 'networkProtection'; Name = 'Network protection'; Weight = 4; Fix = 'Tweak'; Target = 'sec.network-protection'
        Hint = 'Blocks connections to known malicious domains from every app.'
        Description = 'Network protection extends SmartScreen-style reputation checks to all programs. It inspects connection setup only, so game traffic is not affected.' }
    [pscustomobject]@{ Id = 'asrStandard'; Name = 'ASR standard protection rules in Block'; Weight = 8; Fix = 'AsrCenter'; Target = 'standard'
        Hint = 'The three ASR rules Microsoft recommends enabling in Block without testing are active.'
        Description = 'Vulnerable signed drivers, LSASS credential theft and WMI persistence. Microsoft calls them standard protection rules with minimal impact on users.' }
    [pscustomobject]@{ Id = 'asrCoverage'; Name = 'ASR rules at their recommended mode'; Weight = 4; Fix = 'AsrCenter'; Target = 'recommended'
        Hint = 'Every ASR rule is at least at the mode iG Windows Tuner recommends for a gaming PC (Block or Audit).'
        Description = 'Rules with no gamer impact are recommended in Block; the others in Audit, so you can review what they would block in the ASR audit view before promoting them.' }
    [pscustomobject]@{ Id = 'firewall'; Name = 'Windows Firewall on'; Weight = 10; Fix = 'Tweak'; Target = 'sec.firewall-on'
        Hint = 'All firewall profiles are on and block unsolicited inbound traffic.'
        Description = 'The firewall decides whether the listening programs in the network surface report can be reached from other devices. Keep all three profiles on.' }
    [pscustomobject]@{ Id = 'uac'; Name = 'User Account Control'; Weight = 10; Fix = 'Tweak'; Target = 'sec.uac-on'
        Hint = 'UAC is on and prompts on the secure desktop before programs get administrator rights.'
        Description = 'UAC keeps programs, including game mods and downloaded tools, from silently gaining administrator rights. Turning it off also breaks Store apps.' }
    [pscustomobject]@{ Id = 'secureBoot'; Name = 'Secure Boot'; Weight = 8; Fix = 'Firmware'; Target = 'Enable Secure Boot in the BIOS/UEFI setup'
        Hint = 'Secure Boot is on, which blocks boot-level malware and is required by several kernel anti-cheats.'
        Description = 'Secure Boot only lets signed boot loaders start. FACEIT, Riot Vanguard, Call of Duty and Battlefield 6 require it. It is switched on in the firmware setup.' }
    [pscustomobject]@{ Id = 'tpm'; Name = 'TPM 2.0'; Weight = 4; Fix = 'Firmware'; Target = 'Enable Intel PTT / AMD fTPM in the BIOS/UEFI setup'
        Hint = 'A ready TPM 2.0 protects keys for BitLocker and Windows Hello and is required by several anti-cheats.'
        Description = 'The TPM stores keys in hardware. Windows 11, BitLocker, Windows Hello and kernel anti-cheats rely on it. On desktops it is enabled in the firmware setup.' }
    [pscustomobject]@{ Id = 'hvci'; Name = 'Memory integrity (VBS/HVCI)'; Weight = 8; Fix = 'Tweak'; Target = 'sec.hvci-on'
        Hint = 'Virtualization-based security and memory integrity are running and keep unsigned code out of the kernel.'
        Description = 'Memory integrity stops vulnerable or malicious drivers from running unsigned kernel code. FACEIT and Vanguard On-Demand require it. The cost on modern CPUs is small.' }
    [pscustomobject]@{ Id = 'lsa'; Name = 'LSA protection'; Weight = 5; Fix = 'Tweak'; Target = 'sec.lsa-protection'
        Hint = 'LSASS runs as a protected process, so credential dumpers cannot read it.'
        Description = 'LSA protection keeps non-protected code from reading LSASS memory, where Windows keeps sign-in secrets.' }
    [pscustomobject]@{ Id = 'driverBlocklist'; Name = 'Vulnerable driver blocklist'; Weight = 4; Fix = 'Tweak'; Target = 'sec.vulnerable-driver-blocklist'
        Hint = 'Windows refuses to load drivers on Microsoft''s vulnerable driver blocklist.'
        Description = 'Known-vulnerable signed drivers are a favorite way for malware and some cheats to reach the kernel. The blocklist is on by default in Windows 11.' }
    [pscustomobject]@{ Id = 'smartscreen'; Name = 'SmartScreen'; Weight = 4; Fix = 'Tweak'; Target = 'sec.smartscreen-on'
        Hint = 'SmartScreen warns before unknown or malicious downloads and apps run.'
        Description = 'SmartScreen checks the reputation of downloaded files, apps and websites and warns before running something unknown.' }
    [pscustomobject]@{ Id = 'exploitProtection'; Name = 'Exploit protection system defaults'; Weight = 4; Fix = 'Tweak'; Target = 'sec.exploit-protection-defaults'
        Hint = 'DEP, SEHOP, CFG and ASLR are at their Windows defaults (on).'
        Description = 'These system-wide mitigations make memory-corruption exploits much harder. Windows turns them on by default; a tweak tool should never switch them off.' }
    [pscustomobject]@{ Id = 'wdigest'; Name = 'WDigest credential caching off'; Weight = 3; Fix = 'Tweak'; Target = 'sec.wdigest-off'
        Hint = 'Windows does not keep sign-in passwords in clear text for the legacy WDigest protocol.'
        Description = 'When WDigest caching is turned on, LSASS holds your password in clear text. It is off by default and should stay off.' }
    [pscustomobject]@{ Id = 'smb'; Name = 'SMB signing required, SMBv1 off'; Weight = 3; Fix = 'Tweak'; Target = 'sec.smb-hardening'
        Hint = 'File sharing traffic is signed and the obsolete SMBv1 protocol is not installed.'
        Description = 'SMB signing prevents relay and tampering attacks; SMBv1 is the protocol WannaCry spread through. Both are Windows 11 defaults.' }
    [pscustomobject]@{ Id = 'remoteAccess'; Name = 'Remote Desktop and Remote Assistance off'; Weight = 2; Fix = 'Tweak'; Target = 'sec.remote-access-off'
        Hint = 'No incoming Remote Desktop or Remote Assistance connections are accepted.'
        Description = 'Remote Desktop is a common target for password guessing. A gaming PC rarely needs it; it is off by default on Windows 11 Pro.' }
    [pscustomobject]@{ Id = 'llmnr'; Name = 'LLMNR off'; Weight = 2; Fix = 'Tweak'; Target = 'sec.llmnr-off'
        Hint = 'Windows does not answer link-local multicast name queries that attackers spoof to capture hashes.'
        Description = 'LLMNR poisoning on shared networks (dorms, LAN parties, cafes) captures NTLM hashes. DNS and mDNS keep working without it.' }
    [pscustomobject]@{ Id = 'autorun'; Name = 'AutoRun off'; Weight = 2; Fix = 'Tweak'; Target = 'sec.autorun-off'
        Hint = 'USB drives and discs cannot start programs automatically.'
        Description = 'AutoRun used to spread USB worms. With it off, removable media only opens when you open it.' }
    [pscustomobject]@{ Id = 'bitlocker'; Name = 'BitLocker on the system drive'; Weight = 4; Fix = 'Settings'; Target = 'Settings > Privacy & security > Device encryption / BitLocker'
        Hint = 'The system drive is encrypted, so a stolen PC or drive does not expose your data. Back up the recovery key first.'
        Description = 'BitLocker protects data at rest. Back up the recovery key (Microsoft account or printed) before turning it on, because BIOS updates may ask for it. iG Windows Tuner never changes it.' }
    [pscustomobject]@{ Id = 'accounts'; Name = 'Guest and built-in Administrator disabled'; Weight = 3; Fix = 'Settings'; Target = 'Computer Management > Local Users and Groups'
        Hint = 'The Guest account and the built-in Administrator (which runs without UAC prompts) are disabled.'
        Description = 'The built-in Administrator runs everything elevated without UAC prompts, and Guest allows sign-in without a password. Both are disabled on a clean install.' }
    [pscustomobject]@{ Id = 'smartAppControl'; Name = 'Smart App Control'; Weight = 0; Fix = 'WindowsSecurity'; Target = 'App & browser control > Smart App Control'
        Hint = 'Shown for information: blocks untrusted apps. It can only be turned on again with a clean install, so it is not scored.'
        Description = 'Smart App Control blocks apps that are not known to be safe. Once turned off it can only be turned on again by resetting Windows, so iG Windows Tuner reports it without scoring it.' }
    [pscustomobject]@{ Id = 'credentialGuard'; Name = 'Credential Guard'; Weight = 0; Fix = 'None'; Target = 'Enterprise and Education editions'
        Hint = 'Shown for information: isolates credentials with VBS. Available on Enterprise and Education, not Windows 11 Pro.'
        Description = 'Credential Guard stores secrets in a VBS-isolated process. Windows 11 Pro does not include it; LSA protection gives Pro users similar protection against credential dumping.' }
)

function Get-IgwtSecurityCheckDefinitions {
    <# .SYNOPSIS The security score checks (id, name, weight, fix route, hint, description). #>
    [CmdletBinding()]
    param()
    return $script:IgwtSecurityChecks
}

function Get-IgwtSecurityFacts {
    <# .SYNOPSIS Collects everything the security score needs (read-only). Each source fails independently. #>
    [CmdletBinding()]
    param($Context)
    $facts = [ordered]@{ Defender = $null; TweakStates = @{}; SecureBoot = $null; Tpm = $null; DeviceGuard = $null; Asr = $null; BitLocker = $null; Accounts = $null; SmartAppControl = $null; Edition = '' }
    try {
        $mp = Get-IgwtCached -Key 'mp:status' -TtlSeconds 10 -ScriptBlock { Get-MpComputerStatus -ErrorAction Stop }
        $facts.Defender = [pscustomobject]@{ Active = (Test-IgwtDefenderActive); RealTime = [bool]$mp.RealTimeProtectionEnabled; Tamper = [bool]$mp.IsTamperProtected; SignatureAge = [int]$mp.AntivirusSignatureAge; Mode = [string]$mp.AMRunningMode }
    } catch { Write-Verbose "Defender status unavailable: $($_.Exception.Message)" }
    if (-not $Context) { $Context = New-IgwtContext }
    $facts.Edition = [string]$Context.EditionId
    foreach ($c in @($script:IgwtSecurityChecks | Where-Object { $_.Fix -eq 'Tweak' })) {
        try { $facts.TweakStates[[string]$c.Target] = [string](Get-IgwtTweakState -Tweak (Get-IgwtTweak -Id ([string]$c.Target)) -Context $Context).State }
        catch { $facts.TweakStates[[string]$c.Target] = 'Unknown' }
    }
    try { $facts.SecureBoot = (Get-IgwtSecureBootInfo).Enabled } catch { Write-Verbose 'Secure Boot state unavailable.' }
    try { $facts.Tpm = Get-IgwtTpmInfo } catch { Write-Verbose 'TPM state unavailable.' }
    try { $facts.DeviceGuard = Get-IgwtDeviceGuardInfo } catch { Write-Verbose 'Device Guard state unavailable.' }
    try { $facts.Asr = (Get-IgwtAsrStatus).Summary } catch { Write-Verbose 'ASR status unavailable.' }
    try { $facts.BitLocker = Get-IgwtBitLockerStatus } catch { Write-Verbose 'BitLocker state unavailable.' }
    try { $facts.Accounts = Get-IgwtLocalAccountAudit } catch { Write-Verbose 'Local accounts unavailable.' }
    try {
        $sac = Get-IgwtRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState'
        if ($sac.Exists) { $facts.SmartAppControl = [int]$sac.Value }
    } catch { Write-Verbose 'Smart App Control state unavailable.' }
    return [pscustomobject]$facts
}

function ConvertTo-IgwtSecurityCheckResult {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition, [Parameter(Mandatory = $true)][string]$Status, [string]$Value = '')
    $earned = 0.0
    $counted = ($Status -in 'Pass', 'Warn', 'Fail' -and [int]$Definition.Weight -gt 0)
    if ($Status -eq 'Pass') { $earned = [double]$Definition.Weight } elseif ($Status -eq 'Warn') { $earned = [double]$Definition.Weight / 2 }
    [pscustomobject]@{
        Id          = [string]$Definition.Id
        Name        = [string]$Definition.Name
        Status      = $Status
        Value       = $Value
        Weight      = [int]$Definition.Weight
        Earned      = $(if ($counted) { $earned } else { 0.0 })
        Counted     = $counted
        Fix         = [string]$Definition.Fix
        Target      = [string]$Definition.Target
        Hint        = [string]$Definition.Hint
        Description = [string]$Definition.Description
    }
}

function ConvertTo-IgwtSecurityScore {
    <#
    .SYNOPSIS
        Scores the facts: Pass earns the full weight, Warn half, Fail nothing; NotApplicable,
        Unknown, Managed (Group Policy/MDM) and Info checks are not counted. Score = earned /
        possible, 0-100. Grade: Strong (90+), Good (75+), Fair (50+), Weak.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Facts)
    $results = foreach ($d in $script:IgwtSecurityChecks) {
        $status = 'Unknown'; $value = ''
        switch ([string]$d.Id) {
            'defender' {
                if ($Facts.Defender) {
                    $ok = ($Facts.Defender.Active -and $Facts.Defender.RealTime)
                    $status = $(if ($ok) { 'Pass' } else { 'Fail' }); $value = "Real-time protection $(if ($Facts.Defender.RealTime) { 'on' } else { 'off' }), mode $($Facts.Defender.Mode)"
                }
            }
            'tamper' { if ($Facts.Defender) { $status = $(if ($Facts.Defender.Tamper) { 'Pass' } else { 'Fail' }); $value = $(if ($Facts.Defender.Tamper) { 'On' } else { 'Off' }) } }
            'signatures' {
                if ($Facts.Defender) {
                    $age = [int]$Facts.Defender.SignatureAge
                    $status = $(if ($age -le 3) { 'Pass' } elseif ($age -le 7) { 'Warn' } else { 'Fail' }); $value = "$age day(s) old"
                }
            }
            'asrStandard' {
                if ($Facts.Asr -and [int]$Facts.Asr.StandardTotal -gt 0) {
                    $n = [int]$Facts.Asr.StandardInBlock; $total = [int]$Facts.Asr.StandardTotal
                    $status = $(if ($n -ge $total) { 'Pass' } elseif ($n -gt 0) { 'Warn' } else { 'Fail' }); $value = "$n of $total in Block"
                }
                if ($Facts.Defender -and -not $Facts.Defender.Active) { $status = 'NotApplicable'; $value = 'Defender is not the active antivirus' }
            }
            'asrCoverage' {
                if ($Facts.Asr) {
                    $below = [int]$Facts.Asr.BelowRecommendation
                    $status = $(if ($below -eq 0) { 'Pass' } elseif ($below -le 4) { 'Warn' } else { 'Fail' }); $value = $(if ($below) { "$below rule(s) below the recommendation" } else { 'All rules at or above the recommendation' })
                }
                if ($Facts.Defender -and -not $Facts.Defender.Active) { $status = 'NotApplicable'; $value = 'Defender is not the active antivirus' }
            }
            'secureBoot' { if ($null -ne $Facts.SecureBoot) { $status = $(if ($Facts.SecureBoot) { 'Pass' } else { 'Fail' }); $value = $(if ($Facts.SecureBoot) { 'On' } else { 'Off' }) } }
            'tpm' {
                if ($Facts.Tpm) {
                    $status = $(if ($Facts.Tpm.Present -and $Facts.Tpm.Ready -and $Facts.Tpm.Version20) { 'Pass' } elseif ($Facts.Tpm.Present) { 'Warn' } else { 'Fail' })
                    $value = [string]$Facts.Tpm.Detail
                }
            }
            'bitlocker' { if ($Facts.BitLocker) { $status = $(if ($Facts.BitLocker.On) { 'Pass' } else { 'Fail' }); $value = [string]$Facts.BitLocker.Text } }
            'accounts' {
                if ($Facts.Accounts -and $Facts.Accounts.Readable) {
                    $bad = @($Facts.Accounts.Findings | Where-Object { $_.Id -in 'guestEnabled', 'adminEnabled' })
                    $status = $(if ($bad.Count -eq 0) { 'Pass' } elseif (@($bad | Where-Object { $_.Id -eq 'guestEnabled' }).Count) { 'Fail' } else { 'Warn' })
                    $value = $(if ($bad.Count) { (@($bad | ForEach-Object { $_.Text }) -join ' ') } else { 'Both disabled' })
                }
            }
            'smartAppControl' {
                $status = 'Info'
                $value = switch ($Facts.SmartAppControl) { 0 { 'Off' } 1 { 'On' } 2 { 'Evaluation' } default { 'Unknown' } }
            }
            'credentialGuard' {
                $status = 'Info'
                $value = $(if ($Facts.DeviceGuard -and $Facts.DeviceGuard.CredentialGuardRunning) { 'Running' } elseif ([string]$Facts.Edition -match '^(Enterprise|Education)') { 'Not running' } else { "Not available on this edition ($($Facts.Edition))" })
            }
            default {
                if ([string]$d.Fix -eq 'Tweak') {
                    $state = 'Unknown'
                    if ($Facts.TweakStates -and $Facts.TweakStates.ContainsKey([string]$d.Target)) { $state = [string]$Facts.TweakStates[[string]$d.Target] }
                    switch ($state) {
                        'On' { $status = 'Pass'; $value = 'On' }
                        'Partial' { $status = 'Warn'; $value = 'Partly applied' }
                        'Off' { $status = 'Fail'; $value = 'Off' }
                        'ManagedByPolicy' { $status = 'Managed'; $value = 'Set by Group Policy or MDM' }
                        'NotApplicable' { $status = 'NotApplicable'; $value = 'Not applicable on this PC' }
                        default { $status = 'Unknown'; $value = 'Could not be read' }
                    }
                }
            }
        }
        ConvertTo-IgwtSecurityCheckResult -Definition $d -Status $status -Value $value
    }
    $results = @($results)
    $possible = [double](($results | Where-Object { $_.Counted } | Measure-Object -Property Weight -Sum).Sum)
    $earned = [double](($results | Where-Object { $_.Counted } | Measure-Object -Property Earned -Sum).Sum)
    $score = 0
    if ($possible -gt 0) { $score = [int][Math]::Round(100 * $earned / $possible) }
    $grade = $(if ($score -ge 90) { 'Strong' } elseif ($score -ge 75) { 'Good' } elseif ($score -ge 50) { 'Fair' } else { 'Weak' })
    [pscustomobject]@{
        Generated = (Get-Date).ToString('o')
        Score     = $score
        Grade     = $grade
        Earned    = $earned
        Possible  = $possible
        Checks    = $results
        ToFix     = @($results | Where-Object { $_.Status -in 'Fail', 'Warn' } | Sort-Object Weight -Descending)
    }
}

function Get-IgwtSecurityScore {
    <# .SYNOPSIS Security score with a fix route for every failed check (read-only). #>
    [CmdletBinding()]
    param($Context)
    return (ConvertTo-IgwtSecurityScore -Facts (Get-IgwtSecurityFacts -Context $Context))
}

function Get-IgwtLocalAccountAudit {
    <#
    .SYNOPSIS
        Local accounts (read-only): enabled accounts, administrators, and the state of the built-in
        Administrator and Guest accounts, with findings.
    #>
    [CmdletBinding()]
    param()
    $users = @(); $err = ''
    try { $users = @(Get-LocalUser -ErrorAction Stop) } catch { $err = "Local accounts could not be read: $($_.Exception.Message)" }
    $adminSids = $null
    try { $adminSids = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.SID.Value }) }
    catch { Write-Verbose "Administrators group not readable: $($_.Exception.Message)" }   # known to fail with orphaned or cloud members
    $accounts = foreach ($u in $users) {
        $sid = [string]$u.SID.Value
        $role = 'User'
        if ($sid -match '-500$') { $role = 'BuiltinAdministrator' } elseif ($sid -match '-501$') { $role = 'Guest' } elseif ($sid -match '-503$') { $role = 'DefaultAccount' } elseif ($sid -match '-504$') { $role = 'WDAGUtilityAccount' }
        [pscustomobject]@{
            Name             = [string]$u.Name
            Sid              = $sid
            Enabled          = [bool]$u.Enabled
            Role             = $role
            IsAdmin          = $(if ($null -eq $adminSids) { $null } else { $adminSids -contains $sid })
            PasswordRequired = [bool]$u.PasswordRequired
            PasswordLastSet  = $u.PasswordLastSet
            LastLogon        = $u.LastLogon
            Source           = [string]$u.PrincipalSource
        }
    }
    $accounts = @($accounts)
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($a in $accounts) {
        if ($a.Role -eq 'Guest' -and $a.Enabled) { $findings.Add([pscustomobject]@{ Id = 'guestEnabled'; Severity = 'Fail'; Account = $a.Name; Text = 'The Guest account is enabled.'; Advice = 'Disable it in Computer Management > Local Users and Groups > Users.' }) }
        if ($a.Role -eq 'BuiltinAdministrator' -and $a.Enabled) { $findings.Add([pscustomobject]@{ Id = 'adminEnabled'; Severity = 'Warn'; Account = $a.Name; Text = 'The built-in Administrator account is enabled.'; Advice = 'It runs everything elevated without UAC prompts. Use your own administrator account and disable this one.' }) }
        if ($a.Enabled -and $a.Role -eq 'User' -and $a.Source -eq 'Local' -and -not $a.PasswordRequired) { $findings.Add([pscustomobject]@{ Id = 'noPasswordRequired'; Severity = 'Warn'; Account = $a.Name; Text = "Account '$($a.Name)' is allowed to have an empty password."; Advice = 'Give every local account a password (or use a Microsoft account with Windows Hello).' }) }
    }
    $enabledAdmins = @($accounts | Where-Object { $_.Enabled -and $_.IsAdmin -eq $true })
    if ($enabledAdmins.Count -gt 1) { $findings.Add([pscustomobject]@{ Id = 'manyAdmins'; Severity = 'Info'; Account = (@($enabledAdmins | ForEach-Object { $_.Name }) -join ', '); Text = "$($enabledAdmins.Count) enabled administrator accounts."; Advice = 'Remove administrator rights from accounts that do not need them.' }) }
    [pscustomobject]@{
        Readable       = (-not $err)
        Error          = $err
        AdminsKnown    = ($null -ne $adminSids)
        Accounts       = $accounts
        EnabledCount   = @($accounts | Where-Object { $_.Enabled }).Count
        AdminCount     = $enabledAdmins.Count
        Findings       = $findings.ToArray()
    }
}

# Well-known listening ports: what they are and which catalog item reduces the exposure.
$script:IgwtKnownListeners = @{
    'TCP:135'  = @{ Name = 'RPC endpoint mapper'; Fix = ''; Note = 'Core Windows service; the firewall blocks it from other devices by default.' }
    'TCP:139'  = @{ Name = 'NetBIOS session service'; Fix = 'sec.netbios-off'; Note = 'Legacy file sharing transport.' }
    'TCP:445'  = @{ Name = 'SMB file and printer sharing'; Fix = 'sec.smb-hardening'; Note = 'Needed only when this PC shares folders or printers.' }
    'TCP:3389' = @{ Name = 'Remote Desktop'; Fix = 'sec.remote-access-off'; Note = 'A common target for password guessing.' }
    'TCP:5985' = @{ Name = 'WinRM (HTTP)'; Fix = ''; Note = 'PowerShell remoting listener; not enabled by default on Windows 11.' }
    'TCP:5986' = @{ Name = 'WinRM (HTTPS)'; Fix = ''; Note = 'PowerShell remoting listener; not enabled by default on Windows 11.' }
    'TCP:5357' = @{ Name = 'Web Services for Devices'; Fix = ''; Note = 'Network discovery of printers and PCs on private networks.' }
    'UDP:137'  = @{ Name = 'NetBIOS name service'; Fix = 'sec.netbios-off'; Note = 'Legacy, spoofable name service.' }
    'UDP:138'  = @{ Name = 'NetBIOS datagram service'; Fix = 'sec.netbios-off'; Note = 'Legacy browsing protocol.' }
    'UDP:1900' = @{ Name = 'SSDP / UPnP discovery'; Fix = ''; Note = 'Device discovery; also used by some games and media apps.' }
    'UDP:3702' = @{ Name = 'WS-Discovery'; Fix = ''; Note = 'Network discovery on private networks.' }
    'UDP:5353' = @{ Name = 'mDNS'; Fix = ''; Note = 'Local name resolution and casting.' }
    'UDP:5355' = @{ Name = 'LLMNR'; Fix = 'sec.llmnr-off'; Note = 'Spoofable name resolution used in hash-capture attacks.' }
}
# Listeners recognized by their program when the port is dynamic.
$script:IgwtKnownListenerProcesses = @{
    'spoolsv' = @{ Name = 'Print Spooler (remote clients)'; Fix = 'sec.print-spooler-no-inbound'; Note = 'Accepts print clients from other PCs; only needed when you share a printer.' }
}

function Get-IgwtListenerScope {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Address)
    if ($Address -in '0.0.0.0', '::') { return 'AllInterfaces' }
    if ($Address -like '127.*' -or $Address -eq '::1') { return 'Loopback' }
    return 'Specific'
}

function Get-IgwtNetworkSurface {
    <#
    .SYNOPSIS
        Listening-ports report (read-only): TCP listeners and non-ephemeral UDP endpoints with the
        owning program and services, the interfaces they listen on, and what well-known ports are.
        Listening is not the same as reachable: Windows Firewall blocks unsolicited inbound traffic
        unless an allow rule exists.
    #>
    [CmdletBinding()]
    param()
    $err = ''
    $tcp = @(); $udp = @()
    try { $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch { $err = "TCP listeners unavailable: $($_.Exception.Message)" }
    try { $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [int]$_.LocalPort -lt 49152 }) } catch { Write-Verbose 'UDP endpoints unavailable.' }
    $procs = @{}
    try { foreach ($p in @(Get-Process -ErrorAction Stop)) { $procs[[int]$p.Id] = $p } } catch { Write-Verbose 'Process list unavailable.' }
    $services = @{}
    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter "State='Running'" -ErrorAction Stop)) {
            $id = [int]$s.ProcessId
            if ($id -le 0) { continue }
            if (-not $services.ContainsKey($id)) { $services[$id] = New-Object System.Collections.Generic.List[string] }
            $services[$id].Add([string]$s.Name)
        }
    } catch { Write-Verbose 'Service list unavailable.' }
    $rows = foreach ($e in @(@($tcp | ForEach-Object { [pscustomobject]@{ Protocol = 'TCP'; Address = [string]$_.LocalAddress; Port = [int]$_.LocalPort; ProcessId = [int]$_.OwningProcess } }) +
            @($udp | ForEach-Object { [pscustomobject]@{ Protocol = 'UDP'; Address = [string]$_.LocalAddress; Port = [int]$_.LocalPort; ProcessId = [int]$_.OwningProcess } }))) {
        $e
    }
    $entries = @($rows | Group-Object { "$($_.Protocol)|$($_.Port)|$($_.ProcessId)" } | ForEach-Object {
            $g = @($_.Group)
            $first = $g[0]
            $scopes = @($g | ForEach-Object { Get-IgwtListenerScope -Address $_.Address } | Select-Object -Unique)
            $scope = $(if ($scopes -contains 'AllInterfaces') { 'AllInterfaces' } elseif ($scopes -contains 'Specific') { 'Specific' } else { 'Loopback' })
            $proc = $procs[[int]$first.ProcessId]
            $path = ''
            if ($proc) { try { $path = [string]$proc.Path } catch { $path = '' } }
            $known = $script:IgwtKnownListeners["$($first.Protocol):$($first.Port)"]
            if (-not $known -and $proc) { $known = $script:IgwtKnownListenerProcesses[([string]$proc.ProcessName).ToLowerInvariant()] }
            [pscustomobject]@{
                Protocol  = $first.Protocol
                Port      = $first.Port
                Addresses = @($g | ForEach-Object { $_.Address } | Select-Object -Unique)
                Scope     = $scope
                ProcessId = $first.ProcessId
                Process   = $(if ($proc) { [string]$proc.ProcessName } elseif ($first.ProcessId -eq 4) { 'System' } else { "PID $($first.ProcessId)" })
                Path      = $path
                Services  = $(if ($services.ContainsKey([int]$first.ProcessId)) { @($services[[int]$first.ProcessId]) } else { @() })
                Known     = $(if ($known) { [string]$known.Name } else { '' })
                Note      = $(if ($known) { [string]$known.Note } else { '' })
                Fix       = $(if ($known) { [string]$known.Fix } else { '' })
            }
        } | Sort-Object Protocol, Port)
    $exposed = @($entries | Where-Object { $_.Scope -ne 'Loopback' })
    [pscustomobject]@{
        Generated      = (Get-Date).ToString('o')
        Error          = $err
        Entries        = $entries
        ExposedCount   = $exposed.Count
        LoopbackCount  = @($entries | Where-Object { $_.Scope -eq 'Loopback' }).Count
        KnownExposed   = @($exposed | Where-Object { $_.Known })
        Note           = 'Listening is not the same as reachable: Windows Firewall blocks unsolicited inbound traffic unless an allow rule exists.'
    }
}

function Format-IgwtSecurityScore {
    <# .SYNOPSIS Plain-text rendering of the security score for the console and -Report. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Score)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("Security score: $($Score.Score)/100 ($($Score.Grade))")
    foreach ($c in $Score.Checks) {
        $fix = ''
        if ($c.Status -in 'Fail', 'Warn') {
            $fix = switch ($c.Fix) { 'Tweak' { " -> fix: catalog item $($c.Target)" } 'AsrCenter' { ' -> fix: ASR Center (-Asr, then -Asr -AsrRecommended)' } 'None' { '' } default { " -> fix: $($c.Target)" } }
        }
        $null = $sb.AppendLine(('  {0,-15} {1}: {2}{3}' -f "[$($c.Status.ToUpperInvariant())]", $c.Name, $c.Value, $fix))
    }
    return $sb.ToString()
}
