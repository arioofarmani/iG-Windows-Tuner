# Gpu.ps1
# GPU driver, Resizable BAR (nvidia-smi BAR1 size, read-only), HAGS state and refresh rate.
# iG Windows Tuner never writes NVIDIA driver profiles.

function Invoke-IgwtNvidiaSmi {
    <# .SYNOPSIS Runs nvidia-smi.exe read-only queries. Returns $null when it is not installed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: nvidia-smi.exe must be mocked in tests.' }
    # Only the read-only query modes (-q and --query-gpu) are permitted.
    if (@($Arguments | Where-Object { $_ -like '--query-gpu*' -or $_ -eq '-q' }).Count -eq 0) { throw 'Only read-only nvidia-smi queries are allowed.' }
    $exe = Join-Path $env:SystemRoot 'System32\nvidia-smi.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
        $alt = Join-Path ${env:ProgramFiles} 'NVIDIA Corporation\NVSMI\nvidia-smi.exe'
        if (Test-Path -LiteralPath $alt) { $exe = $alt } else { return $null }
    }
    try { return (& $exe @Arguments 2>$null | Out-String) } catch { return $null }
}

function ConvertFrom-IgwtNvidiaBar1 {
    <# .SYNOPSIS Parses "BAR1 Memory Usage ... Total : 16384 MiB" from nvidia-smi -q -d MEMORY. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $m = [regex]::Match($Text, 'BAR1 Memory Usage\s*[\r\n]+\s*Total\s*:\s*(\d+)\s*MiB')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Test-IgwtRefreshRateOk {
    <# .SYNOPSIS True when the current refresh rate is within 2 Hz of the maximum (239.76 Hz reports as 239). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([int]$Current, [int]$Maximum)
    if ($Current -le 0 -or $Maximum -le 0) { return $true }
    return ($Current -ge ($Maximum - 2))
}

function Get-IgwtGpuChecks {
    [CmdletBinding()]
    param()
    $checks = New-Object System.Collections.Generic.List[object]
    $gpus = @()
    try { $gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.PNPDeviceID -like 'PCI\*' }) } catch { $gpus = @() }
    foreach ($g in $gpus) {
        $date = ''
        if ($g.DriverDate) { $date = $g.DriverDate.ToString('yyyy-MM-dd') }
        $checks.Add([pscustomobject]@{ Section = 'GPU'; Id = "gpu-$($g.DeviceID)"; Name = 'Graphics adapter'; Status = 'Info'; Value = $g.Name
                Detail = "Driver $($g.DriverVersion) ($date)"; Advice = ''; Source = '' })
        if ($g.CurrentRefreshRate -and $g.MaxRefreshRate) {
            $ok = Test-IgwtRefreshRateOk -Current ([int]$g.CurrentRefreshRate) -Maximum ([int]$g.MaxRefreshRate)
            $checks.Add([pscustomobject]@{ Section = 'GPU'; Id = "refresh-$($g.DeviceID)"; Name = 'Refresh rate'; Status = $(if ($ok) { 'Pass' } else { 'Warn' })
                    Value = "$($g.CurrentRefreshRate) Hz (max $($g.MaxRefreshRate) Hz)"; Detail = $g.VideoModeDescription
                    Advice = $(if (-not $ok) { 'Your display runs below its maximum refresh rate. Settings > System > Display > Advanced display > Choose a refresh rate.' } else { '' })
                    Source = 'https://support.microsoft.com/en-us/windows/change-the-refresh-rate-on-your-monitor-in-windows-c8ea729e-0678-015c-c415-f806f04aae5a' })
        }
    }
    $nv = @($gpus | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_10DE*' })
    if ($nv.Count -gt 0) {
        $q = Invoke-IgwtNvidiaSmi -Arguments @('--query-gpu=name,driver_version,pcie.link.gen.max,pcie.link.width.max', '--format=csv,noheader')
        if ($q) {
            $checks.Add([pscustomobject]@{ Section = 'GPU'; Id = 'nvsmi'; Name = 'NVIDIA driver (nvidia-smi)'; Status = 'Info'; Value = $q.Trim(); Detail = 'name, driver, max PCIe gen, max PCIe width'; Advice = ''; Source = '' })
        }
        $mem = Invoke-IgwtNvidiaSmi -Arguments @('-q', '-d', 'MEMORY')
        $bar1 = $null
        if ($mem) { $bar1 = ConvertFrom-IgwtNvidiaBar1 -Text $mem }
        if ($null -ne $bar1) {
            $on = $bar1 -gt 256
            $checks.Add([pscustomobject]@{ Section = 'GPU'; Id = 'rebar'; Name = 'Resizable BAR'; Status = $(if ($on) { 'Pass' } else { 'Info' }); Value = $(if ($on) { "Enabled (BAR1 $bar1 MiB)" } else { "Disabled (BAR1 $bar1 MiB)" })
                    Detail = 'BAR1 of about the VRAM size means Resizable BAR is active; 256 MiB means it is off.'
                    Advice = $(if (-not $on) { 'Optional: enable "Above 4G Decoding" and "Re-Size BAR Support" in BIOS (Gigabyte: Settings > IO Ports). Gains are game-dependent.' } else { '' })
                    Source = 'https://www.nvidia.com/en-us/geforce/news/geforce-rtx-30-series-resizable-bar-support/' })
        }
    }
    $hags = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name HwSchMode -ErrorAction SilentlyContinue
    $hagsText = 'Driver default (not set)'
    if ($hags) { $hagsText = $(switch ([int]$hags.HwSchMode) { 2 { 'On (HwSchMode=2)' } 1 { 'Off (HwSchMode=1)' } default { "HwSchMode=$($hags.HwSchMode)" } }) }
    $checks.Add([pscustomobject]@{ Section = 'GPU'; Id = 'hags'; Name = 'Hardware-accelerated GPU scheduling'; Status = 'Info'; Value = $hagsText
            Detail = 'Benefit varies by game and GPU; measure frametimes before and after changing it.'; Advice = ''; Source = 'https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/' })
    return $checks.ToArray()
}

function Get-IgwtNvidiaGuidance {
    <# .SYNOPSIS Read-only NVIDIA Control Panel / in-game checklist (iG Windows Tuner never writes driver profiles). #>
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{ Item = 'NVIDIA Reflex'; Advice = 'Turn on Reflex (On + Boost optional) in each game that supports it. Dota 2, CS2 and VALORANT support Reflex.' }
        [pscustomobject]@{ Item = 'Low Latency Mode'; Advice = 'Use Low Latency Mode On (or Ultra) only for games without Reflex; Reflex overrides it where available.' }
        [pscustomobject]@{ Item = 'Power management mode'; Advice = 'Optional: "Prefer maximum performance" per game profile if clocks drop in light scenes. Costs idle power when set globally.' }
        [pscustomobject]@{ Item = 'Instant Replay / ShadowPlay'; Advice = 'Turn off Instant Replay in the NVIDIA App if you do not use it; it keeps the encoder busy.' }
        [pscustomobject]@{ Item = 'G-SYNC / VRR'; Advice = 'With G-SYNC: cap FPS a few frames below refresh (Reflex does this automatically) and keep V-Sync per your preference.' }
        [pscustomobject]@{ Item = 'DLSS Frame Generation'; Advice = 'Not available on RTX 30-series (requires RTX 40/50).' }
    )
}
