# StartupApps.ps1
# Startup Apps page: lists Run keys and Startup folders and toggles them through the
# StartupApproved keys (the same mechanism as Task Manager / Settings). Entries are never deleted.
# Every toggle writes a JSON snapshot first, so it can be reverted from Backups & Logs.

$script:IgwtStartupSources = @(
    [pscustomobject]@{ Scope = 'HKCU-Run'; Location = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Kind = 'Registry' }
    [pscustomobject]@{ Scope = 'HKLM-Run'; Location = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Kind = 'Registry' }
    [pscustomobject]@{ Scope = 'HKLM-Run32'; Location = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Kind = 'Registry' }
    [pscustomobject]@{ Scope = 'User-Folder'; Location = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'; Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Kind = 'Folder' }
    [pscustomobject]@{ Scope = 'Common-Folder'; Location = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp'; Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Kind = 'Folder' }
)

function Get-IgwtStartupSource {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scope)
    $s = $script:IgwtStartupSources | Where-Object { $_.Scope -eq $Scope } | Select-Object -First 1
    if (-not $s) { throw "Unknown startup scope '$Scope'." }
    return $s
}

function Test-IgwtStartupApprovedEnabled {
    <# .SYNOPSIS StartupApproved data: first byte even (02/06) = enabled, odd (03/07) = disabled, missing = enabled. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Read)
    if (-not $Read -or -not $Read.Exists) { return $true }
    $bytes = ConvertTo-IgwtByteArray $Read.Value
    if ($bytes.Count -lt 1) { return $true }
    return (($bytes[0] -band 1) -eq 0)
}

function Get-IgwtStartupItem {
    <# .SYNOPSIS Lists startup entries with their enabled state. Read-only. #>
    [CmdletBinding()]
    param()
    foreach ($src in $script:IgwtStartupSources) {
        $entries = @()
        if ($src.Kind -eq 'Registry') {
            try {
                $key = Get-Item -LiteralPath (Resolve-IgwtRegistryPath $src.Location) -ErrorAction Stop
                $entries = foreach ($n in $key.GetValueNames()) { if ($n) { [pscustomobject]@{ Name = $n; Command = [string]$key.GetValue($n) } } }
            } catch { $entries = @() }
        } else {
            $folder = [Environment]::ExpandEnvironmentVariables($src.Location)
            if (Test-Path -LiteralPath $folder) {
                $entries = foreach ($f in (Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                    [pscustomobject]@{ Name = $f.Name; Command = $f.FullName }
                }
            }
        }
        foreach ($e in @($entries)) {
            if ($null -eq $e) { continue }
            $approved = $null
            try { $approved = Get-IgwtRegistryValue -Path $src.Approved -Name $e.Name } catch { $approved = $null }
            [pscustomobject]@{
                Scope    = $src.Scope
                Name     = $e.Name
                Command  = $e.Command
                Enabled  = (Test-IgwtStartupApprovedEnabled -Read $approved)
                Machine  = $src.Approved.StartsWith('HKLM')
                Location = $src.Location
            }
        }
    }
}

function Set-IgwtStartupItemEnabled {
    <#
    .SYNOPSIS
        Enables or disables one startup entry via StartupApproved. Writes a snapshot first.
        Machine-wide entries require elevation.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Scope, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][bool]$Enabled)
    $src = Get-IgwtStartupSource -Scope $Scope
    if ($src.Approved.StartsWith('HKLM') -and -not (Test-IgwtIsAdmin) -and -not $script:IgwtSettings.TestMode) { throw 'Machine-wide startup entries require administrator rights.' }
    if (-not $PSCmdlet.ShouldProcess("$Scope\$Name", $(if ($Enabled) { 'Enable startup entry' } else { 'Disable startup entry' }))) { return }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $cur = Get-IgwtRegistryValue -Path $src.Approved -Name $Name
    $item = [ordered]@{ scope = $Scope; name = $Name; exists = [bool]$cur.Exists; kind = $cur.Kind; value = (ConvertTo-IgwtSerializableValue -Value $cur.Value -Kind $cur.Kind); missingDepth = (Get-IgwtRegistryMissingDepth -Path $src.Approved) }
    $snap = New-IgwtSnapshot -Operation 'Startup' -Detail "$Scope\$Name"
    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "startup:$Scope" -Actions @([ordered]@{ index = 0; type = 'startupApproved'; fingerprint = "startupApproved|$Scope"; data = $item }) -Result 'Applied'
    $bytes = New-Object byte[] 12
    if ($Enabled) { $bytes[0] = 2 }
    else {
        $bytes[0] = 3
        $ft = [BitConverter]::GetBytes((Get-Date).ToFileTimeUtc())
        [Array]::Copy($ft, 0, $bytes, 4, 8)
    }
    Set-IgwtRegistryValue -Path $src.Approved -Name $Name -Kind Binary -Value $bytes
    Write-IgwtLog -Message "Startup entry $Scope\$Name $(if ($Enabled) { 'enabled' } else { 'disabled' }). Snapshot: $($snap.Path)"
    return $snap.Path
}

function Restore-IgwtStartupSnapshot {
    <# .SYNOPSIS Reverts a Startup snapshot (only StartupApproved values, validated against the allow-list). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    foreach ($e in @($doc.entries | Where-Object { $_ })) {
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            if ([string]$a.type -ne 'startupApproved') { continue }
            $src = Get-IgwtStartupSource -Scope ([string]$a.data.scope)
            if ($PSCmdlet.ShouldProcess("$($src.Scope)\$($a.data.name)", 'Restore startup entry state')) {
                Restore-IgwtRegistryItem -Path $src.Approved -Name ([string]$a.data.name) -Item $a.data
            }
        }
    }
}
