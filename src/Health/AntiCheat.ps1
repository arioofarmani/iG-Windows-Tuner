# AntiCheat.ps1
# Anti-cheat readiness: which platform requirements pass, per anti-cheat. Read-only.
# Requirements are documented in docs\ANTICHEAT.md with sources.

$script:IgwtAntiCheatProfiles = @(
    [pscustomobject]@{ Id = 'faceit'; Name = 'FACEIT Anti-Cheat (CS2)'; Requires = @('tpm', 'secureBoot', 'vbs', 'iommu', 'win11', 'noTestSign')
        Note = 'TPM 2.0 + Secure Boot mandatory since 25 Nov 2025; VBS + IOMMU enforced in waves; Windows 10 unsupported from 14 Oct 2026.' }
    [pscustomobject]@{ Id = 'vanguard'; Name = 'Riot Vanguard (VALORANT, LoL)'; Requires = @('tpm', 'secureBoot', 'noTestSign')
        Note = 'On Windows 11, Vanguard requires TPM 2.0 and Secure Boot.' }
    [pscustomobject]@{ Id = 'vanguardOnDemand'; Name = 'Riot Vanguard On-Demand mode'; Requires = @('win1125h2', 'secureBoot', 'tpm', 'vbs', 'hvci', 'iommu', 'noTestSign')
        Note = 'Optional mode: Windows 11 25H2+, Secure Boot, TPM 2.0, VBS, HVCI and IOMMU.' }
    [pscustomobject]@{ Id = 'ricochet'; Name = 'Call of Duty (RICOCHET)'; Requires = @('tpm', 'secureBoot', 'noTestSign')
        Note = 'TPM 2.0 and Secure Boot required from Black Ops 7.' }
    [pscustomobject]@{ Id = 'javelin'; Name = 'Battlefield 6 (Javelin)'; Requires = @('secureBoot', 'tpm', 'noTestSign')
        Note = 'Secure Boot required; TPM 2.0 required.' }
    [pscustomobject]@{ Id = 'eacbe'; Name = 'Easy Anti-Cheat / BattlEye'; Requires = @('noTestSign')
        Note = 'No platform-wide requirement; individual games may require Secure Boot. Test signing and kernel debugging are refused.' }
    [pscustomobject]@{ Id = 'vac'; Name = 'Valve Anti-Cheat (Dota 2, CS2)'; Requires = @()
        Note = 'User-mode anti-cheat with no platform requirements.' }
)

function Get-IgwtAntiCheatRequirements {
    <# .SYNOPSIS Evaluates each platform requirement once (Pass/Fail/Unknown with detail). #>
    [CmdletBinding()]
    param()
    $os = Get-IgwtOsInfo
    $tpm = Get-IgwtTpmInfo
    $sb = Get-IgwtSecureBootInfo
    $dg = Get-IgwtDeviceGuardInfo
    $boot = Get-IgwtBootFlags
    $r = [ordered]@{}
    $r.tpm = [pscustomobject]@{ Name = 'TPM 2.0 ready'; Pass = ($tpm.Present -and $tpm.Ready -and $tpm.Version20); Unknown = $false; Detail = $tpm.Detail }
    $r.secureBoot = [pscustomobject]@{ Name = 'Secure Boot on'; Pass = ($sb.Enabled -eq $true); Unknown = ($null -eq $sb.Enabled); Detail = '' }
    $r.secureBoot2023 = [pscustomobject]@{ Name = 'Secure Boot 2023 certificates'; Pass = ($sb.CA2023Status -eq 'Updated' -or ($sb.DbHas2023 -and $sb.KekHas2023)); Unknown = (-not $sb.CA2023Status -and -not $sb.DatabaseChecked); Detail = $sb.CA2023Status }
    $r.vbs = [pscustomobject]@{ Name = 'VBS running'; Pass = ($dg.Available -and $dg.VbsStatus -eq 2); Unknown = (-not $dg.Available); Detail = '' }
    $r.hvci = [pscustomobject]@{ Name = 'Memory integrity (HVCI) running'; Pass = ($dg.Available -and $dg.HvciRunning); Unknown = (-not $dg.Available); Detail = '' }
    $r.iommu = [pscustomobject]@{ Name = 'IOMMU / Kernel DMA protection'; Pass = ($dg.Available -and $dg.DmaProtectionAvailable); Unknown = (-not $dg.Available); Detail = 'Win32_DeviceGuard reports DMA protection available' }
    $r.win11 = [pscustomobject]@{ Name = 'Windows 11'; Pass = ($os.Build -ge 22000); Unknown = $false; Detail = "build $($os.FullBuild)" }
    $r.win1125h2 = [pscustomobject]@{ Name = 'Windows 11 25H2 or newer'; Pass = ($os.Build -ge 26200); Unknown = $false; Detail = "$($os.DisplayVersion), build $($os.FullBuild)" }
    $flags = @()
    if ($boot.TestSigning) { $flags += 'test signing' }
    if ($boot.KernelDebug) { $flags += 'kernel debugging' }
    if ($boot.NoIntegrityCheck) { $flags += 'integrity checks disabled' }
    $r.noTestSign = [pscustomobject]@{ Name = 'No test signing / kernel debugging'; Pass = ($flags.Count -eq 0); Unknown = $false; Detail = $(if ($flags.Count) { "Active: $($flags -join ', ')" } else { 'Boot options clean' }) }
    return [pscustomobject]$r
}

function Get-IgwtAntiCheatReadiness {
    <#
    .SYNOPSIS
        Requirement results plus a per-anti-cheat matrix and an overall color:
        Green = everything including Vanguard On-Demand passes; Amber = kernel anti-cheats work but
        an optional mode or the 2023 certificates are missing; Red = a hard requirement fails.
    #>
    [CmdletBinding()]
    param($Requirements)
    if (-not $Requirements) { $Requirements = Get-IgwtAntiCheatRequirements }
    $matrix = foreach ($p in $script:IgwtAntiCheatProfiles) {
        $missing = @(); $unknown = @()
        foreach ($req in $p.Requires) {
            $r = $Requirements.$req
            if ($r.Unknown) { $unknown += $r.Name } elseif (-not $r.Pass) { $missing += $r.Name }
        }
        $status = $(if ($missing.Count) { 'Fail' } elseif ($unknown.Count) { 'Unknown' } else { 'Pass' })
        [pscustomobject]@{ Id = $p.Id; Name = $p.Name; Status = $status; Missing = $missing; Unknown = $unknown; Note = $p.Note }
    }
    $hardFail = @($matrix | Where-Object { $_.Id -in 'faceit', 'vanguard', 'ricochet', 'javelin', 'eacbe' -and $_.Status -eq 'Fail' }).Count -gt 0
    $optionalMiss = @($matrix | Where-Object { $_.Status -ne 'Pass' -and $_.Id -notin 'vac' }).Count -gt 0 -or -not $Requirements.secureBoot2023.Pass
    $overall = $(if ($hardFail) { 'Red' } elseif ($optionalMiss) { 'Amber' } else { 'Green' })
    return [pscustomobject]@{ Overall = $overall; Requirements = $Requirements; Matrix = @($matrix) }
}

function Get-IgwtSecurityPostureChecks {
    <# .SYNOPSIS Defender, firewall, UAC, LSA protection, SmartScreen and BitLocker (read-only). #>
    [CmdletBinding()]
    param()
    $checks = New-Object System.Collections.Generic.List[object]
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $ok = $mp.AMServiceEnabled -and $mp.RealTimeProtectionEnabled
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'defender'; Name = 'Microsoft Defender Antivirus'; Status = $(if ($ok) { 'Pass' } else { 'Fail' })
                Value = "Real-time protection $(if ($mp.RealTimeProtectionEnabled) { 'on' } else { 'off' }), mode $($mp.AMRunningMode)"; Detail = "Engine $($mp.AMEngineVersion)"; Advice = ''; Source = '' })
        $age = [int]$mp.AntivirusSignatureAge
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'signatures'; Name = 'Security intelligence age'; Status = $(if ($age -le 3) { 'Pass' } else { 'Warn' }); Value = "$age day(s)"; Detail = "Version $($mp.AntivirusSignatureVersion)"; Advice = ''; Source = '' })
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'tamper'; Name = 'Tamper Protection'; Status = $(if ($mp.IsTamperProtected) { 'Pass' } else { 'Warn' }); Value = $(if ($mp.IsTamperProtected) { 'On' } else { 'Off' })
                Detail = 'Read-only. iG Windows Tuner never changes Tamper Protection.'; Advice = $(if (-not $mp.IsTamperProtected) { 'Turn it on in Windows Security > Virus & threat protection settings.' } else { '' }); Source = 'https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection' })
    } catch {
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'defender'; Name = 'Microsoft Defender Antivirus'; Status = 'Unknown'; Value = 'Status unavailable'; Detail = $_.Exception.Message; Advice = ''; Source = '' })
    }
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'firewall'; Name = 'Windows Firewall'; Status = $(if ($off.Count -eq 0) { 'Pass' } else { 'Fail' })
                Value = $(if ($off.Count -eq 0) { 'All profiles on' } else { "Off: $($off -join ', ')" }); Detail = (@($profiles | ForEach-Object { "$($_.Name): inbound $($_.DefaultInboundAction)" }) -join '; '); Advice = ''; Source = '' })
        $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop | Where-Object { -not $_.Group -or ([string]$_.Group) -notlike '@*' })
        $names = @($rules | Select-Object -ExpandProperty DisplayName -Unique)
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'fwrules'; Name = 'App-created inbound allow rules'; Status = 'Info'; Value = "$($names.Count) rule(s)"
                Detail = (($names | Select-Object -First 15) -join '; ') + $(if ($names.Count -gt 15) { '; ...' } else { '' }); Advice = 'Review these in Windows Defender Firewall > Inbound Rules and remove rules for apps you no longer use.'; Source = '' })
    } catch { Write-Verbose 'Firewall query failed.' }
    $uac = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    if ($uac) {
        $level = switch ([int]$uac.ConsentPromptBehaviorAdmin) { 2 { 'Always notify' } 5 { 'Default (notify for apps)' } 0 { 'Never notify' } default { "ConsentPromptBehaviorAdmin=$($uac.ConsentPromptBehaviorAdmin)" } }
        $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'uac'; Name = 'User Account Control'; Status = $(if ([int]$uac.EnableLUA -eq 1 -and [int]$uac.ConsentPromptBehaviorAdmin -ne 0) { 'Pass' } else { 'Fail' })
                Value = "$(if ([int]$uac.EnableLUA -eq 1) { 'On' } else { 'OFF' }), $level"; Detail = ''; Advice = ''; Source = '' })
    }
    $lsa = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
    $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'lsa'; Name = 'LSA protection'; Status = $(if ($lsa -and [int]$lsa.RunAsPPL -in 1, 2) { 'Pass' } else { 'Warn' })
            Value = $(if ($lsa) { "RunAsPPL=$($lsa.RunAsPPL)" } else { 'Not configured' }); Detail = '1 = with UEFI lock, 2 = without UEFI lock.'; Advice = ''; Source = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' })
    $bl = Get-IgwtBitLockerStatus
    $checks.Add([pscustomobject]@{ Section = 'Defender'; Id = 'bitlocker'; Name = "BitLocker ($env:SystemDrive)"; Status = $(if ($bl.On) { 'Pass' } else { 'Info' }); Value = $bl.Text
            Detail = 'Report only; iG Windows Tuner never enables or suspends BitLocker.'
            Advice = $(if ($bl.On) { 'Make sure the recovery key is backed up (Microsoft account or printed). BIOS updates may ask for it.' } else { 'Optional: turn on BitLocker (Settings > Privacy & security > Device encryption / BitLocker) and back up the recovery key first.' })
            Source = 'https://support.microsoft.com/en-us/windows/back-up-your-bitlocker-recovery-key-e63607b4-77fb-4ad3-8022-d6dc428fbd0d' })
    return $checks.ToArray()
}

function Get-IgwtBitLockerStatus {
    <# .SYNOPSIS BitLocker state of the system drive (Get-BitLockerVolume when elevated, Shell property otherwise). #>
    [CmdletBinding()]
    param()
    if (Test-IgwtIsAdmin) {
        try {
            $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            return [pscustomobject]@{ On = ([string]$v.ProtectionStatus -eq 'On'); Text = "Protection $($v.ProtectionStatus), $($v.VolumeStatus), $($v.EncryptionPercentage)%" }
        } catch { Write-Verbose 'Get-BitLockerVolume failed.' }
    }
    try {
        $shell = New-Object -ComObject Shell.Application
        $p = $shell.NameSpace("$env:SystemDrive\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
        $text = switch ([int]$p) { 1 { 'On' } 2 { 'Off' } 3 { 'Encrypting' } 4 { 'Decrypting' } 5 { 'Suspended' } 6 { 'On (locked)' } default { "Unknown ($p)" } }
        return [pscustomobject]@{ On = ([int]$p -in 1, 3, 6); Text = "$text (non-elevated reading)" }
    } catch { return [pscustomobject]@{ On = $false; Text = 'Unknown' } }
}
