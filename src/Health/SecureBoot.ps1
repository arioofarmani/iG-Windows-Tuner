# SecureBoot.ps1
# Secure Boot state and the 2023 certificate rollout (Microsoft Windows Production PCA 2011 expires
# 19 Oct 2026). Read-only: iG Windows Tuner never triggers certificate deployment (AvailableUpdates).

$script:IgwtPca2011Expiry = [datetime]'2026-10-19'

function Get-IgwtSecureBootInfo {
    [CmdletBinding()]
    param()
    $state = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
    $svc = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -ErrorAction SilentlyContinue
    $enabled = $null
    if ($state -and $null -ne $state.UEFISecureBootEnabled) { $enabled = ([int]$state.UEFISecureBootEnabled -eq 1) }
    $dbHas2023 = $null; $kekHas2023 = $null; $verified = $false
    if (Test-IgwtIsAdmin) {
        try { if ($null -eq $enabled) { $enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } } catch { Write-Verbose 'Confirm-SecureBootUEFI failed.' }
        try {
            $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
            $dbHas2023 = ([System.Text.Encoding]::ASCII.GetString($db.Bytes) -match 'Windows UEFI CA 2023')
            $kek = Get-SecureBootUEFI -Name KEK -ErrorAction Stop
            $kekHas2023 = ([System.Text.Encoding]::ASCII.GetString($kek.Bytes) -match 'KEK 2K CA 2023')
            $verified = $true
        } catch { Write-Verbose "Get-SecureBootUEFI failed: $($_.Exception.Message)" }
    }
    [pscustomobject]@{
        Enabled         = $enabled
        CA2023Status    = $(if ($svc) { [string]$svc.UEFICA2023Status } else { '' })
        CA2023Capable   = $(if ($svc -and $null -ne $svc.WindowsUEFICA2023Capable) { [int]$svc.WindowsUEFICA2023Capable } else { $null })
        CA2023Error     = $(if ($svc -and $null -ne $svc.UEFICA2023Error) { [int]$svc.UEFICA2023Error } else { $null })
        DbHas2023       = $dbHas2023
        KekHas2023      = $kekHas2023
        DatabaseChecked = $verified
    }
}

function Get-IgwtSecureBootChecks {
    [CmdletBinding()]
    param()
    $sb = Get-IgwtSecureBootInfo
    $daysLeft = [int][math]::Ceiling(($script:IgwtPca2011Expiry - (Get-Date)).TotalDays)
    $certOk = ($sb.CA2023Status -eq 'Updated') -or ($sb.DbHas2023 -and $sb.KekHas2023)
    $detail = "Servicing status: $(if ($sb.CA2023Status) { $sb.CA2023Status } else { 'not reported' })"
    if ($null -ne $sb.CA2023Capable) { $detail += "; WindowsUEFICA2023Capable=$($sb.CA2023Capable) (2 = booting the 2023-signed boot manager)" }
    if ($sb.DatabaseChecked) { $detail += "; db has 'Windows UEFI CA 2023': $($sb.DbHas2023); KEK has 'KEK 2K CA 2023': $($sb.KekHas2023)" }
    else { $detail += '; db/KEK contents need an elevated run to read' }
    if ($sb.CA2023Error) { $detail += "; UEFICA2023Error=$($sb.CA2023Error)" }
    $expiryText = $(if ($daysLeft -gt 0) { "Microsoft Windows Production PCA 2011 expires 19 Oct 2026 ($daysLeft day(s) left)." } else { 'Microsoft Windows Production PCA 2011 expired on 19 Oct 2026.' })
    @(
        [pscustomobject]@{ Section = 'Security'; Id = 'secureBoot'; Name = 'Secure Boot'; Status = $(if ($sb.Enabled -eq $true) { 'Pass' } elseif ($null -eq $sb.Enabled) { 'Unknown' } else { 'Fail' })
            Value = $(if ($sb.Enabled -eq $true) { 'On' } elseif ($null -eq $sb.Enabled) { 'Unknown' } else { 'Off' }); Detail = 'Required by FACEIT AC, Riot Vanguard (Windows 11), Call of Duty and Battlefield 6.'
            Advice = $(if ($sb.Enabled -ne $true) { 'Enable Secure Boot in BIOS (requires UEFI boot mode, CSM off, and a GPT system disk).' } else { '' })
            Source = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot' }
        [pscustomobject]@{ Section = 'Security'; Id = 'secureBoot2023'; Name = 'Secure Boot 2023 certificates'; Status = $(if ($certOk) { 'Pass' } elseif ($sb.CA2023Status -eq 'InProgress') { 'Warn' } else { 'Fail' })
            Value = $(if ($certOk) { 'Applied' } elseif ($sb.CA2023Status) { $sb.CA2023Status } else { 'Not applied' }); Detail = "$detail. $expiryText"
            Advice = $(if ($certOk) { '' } else { 'Open Windows Security > Device security > Secure Boot and follow the update prompt; install the latest cumulative update and BIOS. iG Windows Tuner does not deploy certificates itself.' })
            Source = 'https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d' }
    )
}
