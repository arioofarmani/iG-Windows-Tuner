# Storage.ps1
# Disk model/bus/health, reliability counters (elevated), TRIM state and free space. Read-only.

function Get-IgwtStorageChecks {
    [CmdletBinding()]
    param()
    $checks = New-Object System.Collections.Generic.List[object]
    $disks = @()
    try { $disks = @(Get-PhysicalDisk -ErrorAction Stop) } catch { $disks = @() }
    foreach ($d in $disks) {
        $rel = $null
        if (Test-IgwtIsAdmin) { try { $rel = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { $rel = $null } }
        $detail = "$($d.BusType) $($d.MediaType), $([math]::Round($d.Size / 1GB)) GB"
        $status = $(if ([string]$d.HealthStatus -eq 'Healthy') { 'Pass' } else { 'Warn' })
        if ($rel) {
            if ($null -ne $rel.Wear) { $detail += ", wear $($rel.Wear)%" ; if ([int]$rel.Wear -ge 80) { $status = 'Warn' } }
            if ($null -ne $rel.Temperature -and [int]$rel.Temperature -gt 0) { $detail += ", $($rel.Temperature) C" }
            if ($rel.ReadErrorsUncorrected) { $detail += ", uncorrected read errors $($rel.ReadErrorsUncorrected)"; $status = 'Warn' }
        } else { $detail += ' (reliability counters need an elevated run)' }
        $checks.Add([pscustomobject]@{ Section = 'Storage'; Id = "disk-$($d.DeviceId)"; Name = 'Disk'; Status = $status; Value = "$($d.FriendlyName): $($d.HealthStatus)"; Detail = $detail; Advice = ''; Source = '' })
    }
    $trim = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name DisableDeleteNotification -ErrorAction SilentlyContinue
    $trimOn = (-not $trim) -or ([int]$trim.DisableDeleteNotification -eq 0)
    $checks.Add([pscustomobject]@{ Section = 'Storage'; Id = 'trim'; Name = 'TRIM'; Status = $(if ($trimOn) { 'Pass' } else { 'Warn' }); Value = $(if ($trimOn) { 'Enabled' } else { 'Disabled' })
            Detail = 'DisableDeleteNotification = 0 means TRIM is sent to SSDs.'; Advice = $(if (-not $trimOn) { 'Re-enable TRIM (fsutil behavior set DisableDeleteNotify 0) from an elevated prompt.' } else { '' }); Source = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior' })
    try {
        foreach ($v in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
            if (-not $v.Size) { continue }
            $pct = [math]::Round(100 * $v.FreeSpace / $v.Size)
            $checks.Add([pscustomobject]@{ Section = 'Storage'; Id = "vol-$($v.DeviceID)"; Name = "Free space ($($v.DeviceID))"; Status = $(if ($pct -lt 10) { 'Warn' } else { 'Pass' })
                    Value = "$([math]::Round($v.FreeSpace / 1GB)) GB free of $([math]::Round($v.Size / 1GB)) GB ($pct%)"; Detail = ''; Advice = $(if ($pct -lt 10) { 'Keep at least 10-15% free on SSDs for consistent write performance.' } else { '' }); Source = '' })
        }
    } catch { Write-Verbose 'Win32_LogicalDisk failed.' }
    return $checks.ToArray()
}
