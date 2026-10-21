# Preflight.ps1
# Checks that run before any change: admin, edition, build, pending reboot, laptop/battery, RDP.

$script:IgwtMinimumBuild = 26100

function Get-IgwtOsInfo {
    <# .SYNOPSIS Windows edition, version, build and UBR from the registry (read-only). #>
    [CmdletBinding()]
    param()
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $build = 0
    if ($cv -and $cv.CurrentBuildNumber) { $build = [int]$cv.CurrentBuildNumber }
    elseif ($cv -and $cv.CurrentBuild) { $build = [int]$cv.CurrentBuild }
    $ubr = 0
    if ($cv -and $null -ne $cv.UBR) { $ubr = [int]$cv.UBR }
    $caption = $null
    $lastBoot = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = $os.Caption
        $lastBoot = $os.LastBootUpTime
    } catch { Write-Verbose "Win32_OperatingSystem unavailable: $($_.Exception.Message)" }
    [pscustomobject]@{
        Caption        = $(if ($caption) { $caption } else { $cv.ProductName })
        EditionId      = $cv.EditionID
        DisplayVersion = $cv.DisplayVersion
        Build          = $build
        Ubr            = $ubr
        FullBuild      = "$build.$ubr"
        LastBootUpTime = $lastBoot
        Uptime         = $(if ($lastBoot) { (Get-Date) - $lastBoot } else { $null })
    }
}

function Get-IgwtPendingReboot {
    <# .SYNOPSIS Returns the reasons a reboot is pending (Windows servicing and iG Windows Tuner itself). #>
    [CmdletBinding()]
    param()
    $reasons = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('Component Based Servicing') }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('Windows Update') }
    try {
        $sm = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
        if ($sm.PendingFileRenameOperations) { $reasons.Add('Pending file rename operations') }
    } catch { Write-Verbose 'No pending file rename operations.' }
    $own = Get-IgwtPendingRestartState
    if ($own -and $own.Requires -ne 'none') { $reasons.Add("iG Windows Tuner changes ($($own.Requires))") }
    return , $reasons.ToArray()
}

function Test-IgwtRdpSession {
    <# .SYNOPSIS Returns $true when the current session is a Remote Desktop session. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    # SESSIONNAME is "Console" locally and "RDP-Tcp#N" in a Remote Desktop session.
    if ($env:SESSIONNAME -and $env:SESSIONNAME -like 'RDP-*') { return $true }
    try {
        $null = [System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
        if ([System.Windows.Forms.SystemInformation]::TerminalServerSession) { return $true }
    } catch { Write-Verbose 'System.Windows.Forms not available for RDP detection.' }
    return $false
}

function Get-IgwtPowerSource {
    <# .SYNOPSIS Laptop/battery detection (desktop PCs report no battery). #>
    [CmdletBinding()]
    param()
    $isPortable = $false
    $hasBattery = $false
    $onBattery = $false
    try {
        $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
        $portable = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
        foreach ($t in @($enclosure.ChassisTypes)) { if ($portable -contains [int]$t) { $isPortable = $true } }
    } catch { Write-Verbose 'Win32_SystemEnclosure unavailable.' }
    try {
        $battery = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop)
        if ($battery.Count -gt 0) {
            $hasBattery = $true
            # BatteryStatus 1 = discharging (on battery)
            if (@($battery | Where-Object { $_.BatteryStatus -eq 1 }).Count -gt 0) { $onBattery = $true }
        }
    } catch { Write-Verbose 'Win32_Battery unavailable.' }
    [pscustomobject]@{ IsPortable = $isPortable; HasBattery = $hasBattery; OnBattery = $onBattery }
}

function Get-IgwtPreflight {
    <#
    .SYNOPSIS
        Collects preflight facts and returns warnings/errors. Read-only.
    .PARAMETER ForApply
        Evaluate as if changes are about to be made (admin becomes an error, not a warning).
    #>
    [CmdletBinding()]
    param([switch]$ForApply)
    $os = Get-IgwtOsInfo
    $isAdmin = Test-IgwtIsAdmin
    $pending = Get-IgwtPendingReboot
    $power = Get-IgwtPowerSource
    $rdp = Test-IgwtRdpSession
    $warnings = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]

    if ($os.Build -lt $script:IgwtMinimumBuild) {
        $errors.Add("Windows build $($os.Build) is older than $script:IgwtMinimumBuild (Windows 11 24H2). iG Windows Tuner refuses to change older builds.")
    }
    if ($os.EditionId -ne 'Professional') {
        $warnings.Add("Edition is '$($os.EditionId)'. iG Windows Tuner is designed and tested for Windows 11 Pro; some policies may behave differently.")
    }
    if (-not $isAdmin) {
        if ($ForApply) { $errors.Add('Administrator rights are required to apply or revert changes.') }
        else { $warnings.Add('Not elevated: some health checks (TPM, Secure Boot databases, BitLocker, disk counters) are limited.') }
    }
    if ($pending.Count -gt 0) { $warnings.Add("A reboot is already pending: $($pending -join ', ').") }
    if ($power.IsPortable -or $power.HasBattery) {
        $warnings.Add('Portable device or battery detected. Performance power settings raise power use and heat.')
    }
    if ($power.OnBattery) { $warnings.Add('Running on battery.') }
    if ($rdp) { $warnings.Add('This is a Remote Desktop session. Tweaks that could interrupt networking or Remote Desktop are blocked.') }

    [pscustomobject]@{
        IsAdmin       = $isAdmin
        Os            = $os
        Build         = $os.Build
        EditionId     = $os.EditionId
        IsPro         = ($os.EditionId -eq 'Professional')
        SupportedBuild = ($os.Build -ge $script:IgwtMinimumBuild)
        PendingReboot = $pending
        Power         = $power
        IsRdpSession  = $rdp
        Warnings      = $warnings.ToArray()
        Errors        = $errors.ToArray()
        CanApply      = ($errors.Count -eq 0)
    }
}

function Get-IgwtPendingRestartState {
    <# .SYNOPSIS Returns iG Windows Tuner's own logoff/reboot requirement that has not been satisfied yet. #>
    [CmdletBinding()]
    param()
    $file = Join-Path (Get-IgwtDataPath -Kind State) 'pending-restart.json'
    if (-not (Test-Path -LiteralPath $file)) {
        # A requirement recorded by a pre-release preview build.
        $legacy = Get-IgwtDataPath -Kind LegacyState
        if ($legacy) { $file = Join-Path $legacy 'pending-restart.json' }
        if (-not $legacy -or -not (Test-Path -LiteralPath $file)) { return $null }
    }
    try {
        $state = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch { return $null }
    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { Write-Verbose 'OS query failed.' }
    if ($os -and $state.bootTime) {
        $recordedBoot = [datetime]::Parse($state.bootTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        if ([math]::Abs(($os.LastBootUpTime - $recordedBoot).TotalSeconds) -gt 120) { return $null }   # rebooted since
    }
    $requires = [string]$state.requires
    if ($requires -eq 'logoff' -and $state.recordedAt) {
        $explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
        $recordedAt = [datetime]::Parse($state.recordedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        if ($explorer -and $explorer.StartTime -gt $recordedAt) { return $null }  # signed out and back in since
    }
    [pscustomobject]@{ Requires = $requires; Tweaks = @($state.tweaks); RecordedAt = $state.recordedAt }
}

function Set-IgwtPendingRestartState {
    <# .SYNOPSIS Records that applied tweaks need a logoff or reboot (persistent banner). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('logoff', 'reboot')][string]$Requires,
        [string[]]$TweakId
    )
    if (-not $PSCmdlet.ShouldProcess('pending-restart.json', 'Record restart requirement')) { return }
    $dir = Get-IgwtDataPath -Kind State
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $file = Join-Path $dir 'pending-restart.json'
    $existing = Get-IgwtPendingRestartState
    $all = @($TweakId)
    if ($existing) {
        $all = @($existing.Tweaks) + @($TweakId) | Select-Object -Unique
        if ($existing.Requires -eq 'reboot') { $Requires = 'reboot' }
    }
    $boot = $null
    try { $boot = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToString('o') } catch { Write-Verbose 'OS query failed.' }
    $obj = [ordered]@{ requires = $Requires; tweaks = @($all); bootTime = $boot; recordedAt = (Get-Date).ToString('o') }
    Set-Content -LiteralPath $file -Value (ConvertTo-Json -InputObject $obj -Depth 4) -Encoding UTF8
}
