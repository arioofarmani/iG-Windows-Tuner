# Firmware.ps1
# BIOS/board information and TPM status. Read-only; iG Windows Tuner never touches firmware settings.

function Get-IgwtFirmwareInfo {
    [CmdletBinding()]
    param()
    $bios = $null; $board = $null
    try { $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop } catch { Write-Verbose 'Win32_BIOS unavailable.' }
    try { $board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop } catch { Write-Verbose 'Win32_BaseBoard unavailable.' }
    [pscustomobject]@{
        BiosVendor    = $(if ($bios) { $bios.Manufacturer } else { '' })
        BiosVersion   = $(if ($bios) { $bios.SMBIOSBIOSVersion } else { '' })
        BiosDate      = $(if ($bios) { $bios.ReleaseDate } else { $null })
        BoardVendor   = $(if ($board) { $board.Manufacturer } else { '' })
        BoardProduct  = $(if ($board) { $board.Product } else { '' })
    }
}

function Get-IgwtTpmInfo {
    <#
    .SYNOPSIS
        TPM status. Elevated: Get-Tpm (present/ready) plus the spec version from Win32_Tpm.
        Not elevated: presence of the "Trusted Platform Module 2.0" device only.
    #>
    [CmdletBinding()]
    param()
    if (Test-IgwtIsAdmin) {
        try {
            $t = Get-Tpm -ErrorAction Stop
            $spec = $null
            try { $spec = (Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop).SpecVersion } catch { $spec = $null }
            $is20 = $false
            if ($spec) { $is20 = ([string]$spec).Split(',')[0].Trim() -like '2.*' }
            return [pscustomobject]@{ Present = [bool]$t.TpmPresent; Ready = [bool]$t.TpmReady; Version20 = $is20; Verified = $true; Detail = "Spec $spec" }
        } catch { Write-Verbose "Get-Tpm failed: $($_.Exception.Message)" }
    }
    try {
        $dev = @(Get-PnpDevice -Class SecurityDevices -PresentOnly -ErrorAction Stop | Where-Object { $_.FriendlyName -like 'Trusted Platform Module*' })
        if ($dev.Count -gt 0) {
            $d = $dev[0]
            return [pscustomobject]@{ Present = $true; Ready = ($d.Status -eq 'OK'); Version20 = ($d.FriendlyName -match '2\.0'); Verified = $false
                Detail = "$($d.FriendlyName), device status $($d.Status) (run elevated for full readiness)" }
        }
    } catch { Write-Verbose 'PnP TPM query failed.' }
    return [pscustomobject]@{ Present = $false; Ready = $false; Version20 = $false; Verified = $false; Detail = 'No TPM device found.' }
}

function Get-IgwtFirmwareChecks {
    [CmdletBinding()]
    param()
    $fw = Get-IgwtFirmwareInfo
    $tpm = Get-IgwtTpmInfo
    $date = ''
    if ($fw.BiosDate) { $date = $fw.BiosDate.ToString('yyyy-MM-dd') }
    $ageWarn = $fw.BiosDate -and (((Get-Date) - $fw.BiosDate).TotalDays -gt 540)
    @(
        [pscustomobject]@{ Section = 'Firmware'; Id = 'bios'; Name = 'BIOS / motherboard'; Status = $(if ($ageWarn) { 'Warn' } else { 'Info' })
            Value = "$($fw.BoardVendor) $($fw.BoardProduct), BIOS $($fw.BiosVersion) ($date)"; Detail = $fw.BiosVendor
            Advice = $(if ($ageWarn) { 'BIOS is older than 18 months; check the board vendor for updates (microcode, Secure Boot keys, stability).' } else { '' }); Source = '' }
        [pscustomobject]@{ Section = 'Security'; Id = 'tpm'; Name = 'TPM 2.0'; Status = $(if ($tpm.Present -and $tpm.Ready -and $tpm.Version20) { 'Pass' } elseif ($tpm.Present) { 'Warn' } else { 'Fail' })
            Value = $(if ($tpm.Present) { $(if ($tpm.Ready) { 'Present and ready' } else { 'Present, not ready' }) } else { 'Not found' }); Detail = $tpm.Detail
            Advice = $(if (-not $tpm.Present) { 'Enable Intel PTT (Platform Trust Technology) in BIOS.' } else { '' }); Source = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview' }
    )
}
