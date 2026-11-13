# StartupApps.ps1
# Startup Apps page: lists Run keys and Startup folders, toggles them through the StartupApproved
# keys (the same mechanism as Task Manager / Settings) and, since 3.8.1, deletes them with a
# backup (DECISIONS SA1-SA10). Every change writes a JSON snapshot first, so it can be reverted from
# Backups & Logs or the change journal. New entries and edited commands are never written: that
# would be persistence (SA1). The only code that recreates an entry is Restore-IgwtStartupEntry,
# and only from iG's own backup (SA4).

$script:IgwtStartupSources = @(
    [pscustomobject]@{ Scope = 'HKCU-Run'; Location = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Kind = 'Registry' }
    [pscustomobject]@{ Scope = 'HKLM-Run'; Location = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; Kind = 'Registry' }
    [pscustomobject]@{ Scope = 'HKLM-Run32'; Location = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Kind = 'Registry' }
    [pscustomobject]@{ Scope = 'User-Folder'; Location = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'; Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Kind = 'Folder' }
    [pscustomobject]@{ Scope = 'Common-Folder'; Location = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp'; Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Kind = 'Folder' }
)

# A startup folder file larger than this is not backed up or deleted (SA3; a shortcut is a few KB).
$script:IgwtStartupFileMaxBytes = 10MB
# TestMode only: scope -> folder path, so tests never touch the real Startup folders.
$script:IgwtStartupFolderOverride = @{}

function Get-IgwtStartupSource {
    <# .SYNOPSIS The allow-listed source (Run key or Startup folder) of a scope; throws for any other scope. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scope)
    $s = $script:IgwtStartupSources | Where-Object { $_.Scope -eq $Scope } | Select-Object -First 1
    if (-not $s) { throw "Unknown startup scope '$Scope'." }
    return $s
}

function Get-IgwtStartupFolderPath {
    <#
    .SYNOPSIS
        The expanded folder of a folder scope. In TestMode only an override set by the tests is
        returned, so a test can never read or change the real Startup folders. Read-only.
    .PARAMETER Scope
        User-Folder or Common-Folder.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Scope)
    $src = Get-IgwtStartupSource -Scope $Scope
    if ($src.Kind -ne 'Folder') { throw "'$Scope' is not a Startup folder scope." }
    if ($script:IgwtSettings.TestMode) {
        if ($script:IgwtStartupFolderOverride.ContainsKey($Scope)) { return [string]$script:IgwtStartupFolderOverride[$Scope] }
        return ''
    }
    return [Environment]::ExpandEnvironmentVariables($src.Location)
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

function Get-IgwtStartupProtection {
    <#
    .SYNOPSIS
        Why a startup entry must not be deleted, or should be deleted with care (DECISIONS SA5):
        {Kind = 'Windows' | 'Security' | 'AntiCheat' | ''; Reason; Vendor}. Windows: the target lies
        under %SystemRoot%. Security: a security vendor of data\registry\protected.json matches the
        entry name (displayNamePatterns) or target (pathPatterns). AntiCheat: the antiCheat group
        matches. Windows and Security refuse a delete; AntiCheat only warns. Read-only.
    .PARAMETER Name
        The entry name (Run value name or file name).
    .PARAMETER Target
        The resolved target file, or ''.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Name = '', [AllowEmptyString()][string]$Target = '')
    $none = [pscustomobject]@{ Kind = ''; Reason = ''; Vendor = '' }
    $root = [string]$env:SystemRoot
    if ($Target -and $root -and (Test-IgwtPathUnder -Path $Target -Parent $root)) {
        return [pscustomobject]@{ Kind = 'Windows'; Reason = 'This is part of Windows. You can turn it off, but iG does not delete it.'; Vendor = '' }
    }
    $catalog = $null
    try { $catalog = Get-IgwtRegCleanProtectedCatalog } catch { $catalog = $null }
    if ($null -eq $catalog) { return $none }
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    $match = {
        param($item)
        foreach ($p in @($item.displayNamePatterns)) { if ($p -and ($Name -like $p -or $baseName -like $p)) { return $true } }
        if ($Target) { foreach ($p in @($item.pathPatterns)) { if ($p -and $Target -like $p) { return $true } } }
        return $false
    }
    $security = @($catalog.groups | Where-Object { $_ -and [string]$_.id -eq 'securityVendors' }) | Select-Object -First 1
    foreach ($v in @($security.vendors)) {
        if ($null -eq $v) { continue }
        if (& $match $v) {
            $tool = $(if ($v.removalTool -and $v.removalTool.text) { ' ' + [string]$v.removalTool.text } else { '' })
            return [pscustomobject]@{ Kind = 'Security'; Reason = "This belongs to $($v.name), a security product. Turn it off here, or use $($v.name)'s own settings or removal tool.$tool"; Vendor = [string]$v.name }
        }
    }
    $anti = @($catalog.groups | Where-Object { $_ -and [string]$_.id -eq 'antiCheat' }) | Select-Object -First 1
    if ($anti -and (& $match $anti)) {
        return [pscustomobject]@{ Kind = 'AntiCheat'; Reason = 'This belongs to an anti-cheat. Removing it can stop the anti-cheat from updating or starting, and games that need it may refuse to run.'; Vendor = '' }
    }
    return $none
}

function Get-IgwtStartupItem {
    <#
    .SYNOPSIS
        Lists startup entries with their enabled state, target file, company and protection
        (DECISIONS SA6). Read-only.
    #>
    [CmdletBinding()]
    param()
    foreach ($src in $script:IgwtStartupSources) {
        $entries = @()
        $sourceText = $src.Location
        if ($src.Kind -eq 'Registry') {
            try {
                $key = Get-Item -LiteralPath (Resolve-IgwtRegistryPath $src.Location) -ErrorAction Stop
                $entries = foreach ($n in $key.GetValueNames()) { if ($n) { [pscustomobject]@{ Name = $n; Command = [string]$key.GetValue($n); Target = '' } } }
            } catch { $entries = @() }
        } else {
            $folder = Get-IgwtStartupFolderPath -Scope $src.Scope
            $sourceText = $folder
            if ($folder -and (Test-Path -LiteralPath $folder)) {
                $entries = foreach ($f in (Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                    [pscustomobject]@{ Name = $f.Name; Command = $f.FullName; Target = $f.FullName }
                }
            }
        }
        foreach ($e in @($entries)) {
            if ($null -eq $e) { continue }
            $approved = $null
            try { $approved = Get-IgwtRegistryValue -Path $src.Approved -Name $e.Name } catch { $approved = $null }
            $target = [string]$e.Target
            if (-not $target) { try { $target = Resolve-IgwtCommandPath -Command $e.Command } catch { $target = '' } }
            $rooted = [bool]($target -match '^[A-Za-z]:\\')
            $exists = $false
            $company = ''
            if ($rooted) {
                try { $exists = [System.IO.File]::Exists($target) } catch { $exists = $false }
                if ($exists) { try { $company = [string]([System.Diagnostics.FileVersionInfo]::GetVersionInfo($target).CompanyName) } catch { $company = '' } }
            }
            $prot = Get-IgwtStartupProtection -Name $e.Name -Target $target
            [pscustomobject]@{
                Scope        = $src.Scope
                Name         = $e.Name
                Command      = $e.Command
                Enabled      = (Test-IgwtStartupApprovedEnabled -Read $approved)
                Machine      = $src.Approved.StartsWith('HKLM')
                Location     = $src.Location
                Source       = $sourceText
                Target       = $target
                TargetExists = $exists
                FileMissing  = [bool]($rooted -and -not $exists -and $src.Kind -eq 'Registry')
                Company      = $company
                Protection   = $prot.Kind
                ProtectionReason = $prot.Reason
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
    Assert-IgwtWritable -Operation 'Set-IgwtStartupItemEnabled'
    if (-not (Test-IgwtModuleOperationDirect -BoundParameters $PSBoundParameters)) { return (Invoke-IgwtModuleOperation -Command 'Set-IgwtStartupItemEnabled' -Parameters $PSBoundParameters) }
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

#region Delete (DECISIONS SA2-SA5)

function ConvertFrom-IgwtStartupItemId {
    <#
    .SYNOPSIS
        Splits '<Scope>|<Name>' into {Scope; Name} and validates both: an allow-listed scope, a
        non-empty name, and for a folder scope a plain file name (no path separator, no '..',
        not desktop.ini). Throws otherwise. Pure.
    .PARAMETER Id
        The item id as shown by -Startup and used by the GUI rows.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $cut = $Id.IndexOf('|')
    if ($cut -lt 1 -or $cut -ge $Id.Length - 1) { throw "'$Id' is not a startup entry id ('<Scope>|<Name>')." }
    $scope = $Id.Substring(0, $cut)
    $name = $Id.Substring($cut + 1)
    $src = Get-IgwtStartupSource -Scope $scope
    if ($src.Kind -eq 'Folder') {
        if ($name -match '[\\/:*?"<>|]' -or $name -in '.', '..' -or $name -eq 'desktop.ini' -or $name.Trim() -ne $name) { throw "'$name' is not a file name in the Startup folder." }
    }
    return [pscustomobject]@{ Scope = $scope; Name = $name; Source = $src }
}

function Get-IgwtStartupRemovePlan {
    <#
    .SYNOPSIS
        The plan for deleting startup entries (DECISIONS SA5, SA8): one row per id with Scope, Name,
        Command, Target, Exists (the entry is there now), Refused (reason or ''), Warning (anti-cheat
        or '') and NeedsAdmin. Read-only.
    .PARAMETER Item
        Item ids '<Scope>|<Name>'.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Item)
    $current = @(Get-IgwtStartupItem)
    $admin = [bool]($script:IgwtSettings.TestMode -or (Test-IgwtIsAdmin))
    foreach ($id in @($Item | Where-Object { $_ } | Select-Object -Unique)) {
        $p = $null
        $refused = ''
        try { $p = ConvertFrom-IgwtStartupItemId -Id $id } catch { $refused = $_.Exception.Message }
        if (-not $p) {
            [pscustomobject]@{ Id = $id; Scope = ''; Name = ''; Command = ''; Target = ''; Exists = $false; Refused = $refused; Warning = ''; NeedsAdmin = $false }
            continue
        }
        $e = @($current | Where-Object { $_.Scope -eq $p.Scope -and [string]::Equals([string]$_.Name, $p.Name, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
        $needsAdmin = [bool]$p.Source.Approved.StartsWith('HKLM')
        $warning = ''
        if (-not $e) { $refused = 'The entry no longer exists.' }
        elseif ([string]$e.Protection -in 'Windows', 'Security') { $refused = [string]$e.ProtectionReason }
        elseif ([string]$e.Protection -eq 'AntiCheat') { $warning = [string]$e.ProtectionReason }
        if (-not $refused -and $needsAdmin -and -not $admin) { $refused = 'Entries that start for all users need administrator rights.' }
        [pscustomobject]@{
            Id = "$($p.Scope)|$($p.Name)"; Scope = $p.Scope; Name = $p.Name
            Command = $(if ($e) { [string]$e.Command } else { '' }); Target = $(if ($e) { [string]$e.Target } else { '' })
            Exists = [bool]$e; Refused = $refused; Warning = $warning; NeedsAdmin = $needsAdmin
        }
    }
}

function Format-IgwtStartupRemovePlan {
    <# .SYNOPSIS Text lines describing a startup remove plan (CLI and confirmation dialog). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Plan = @())
    $ok = @($Plan | Where-Object { $_ -and -not $_.Refused })
    $no = @($Plan | Where-Object { $_ -and $_.Refused })
    if ($ok.Count) {
        'Will be deleted (a backup is made first; restore it from Backups & Logs or with Undo):'
        foreach ($r in $ok) { "  - $($r.Name) ($($r.Scope)): $($r.Command)"; if ($r.Warning) { "    Warning: $($r.Warning)" } }
    }
    if ($no.Count) {
        'Not deleted:'
        foreach ($r in $no) { "  - $(if ($r.Name) { $r.Name } else { $r.Id }): $($r.Refused)" }
    }
    if (-not $ok.Count -and -not $no.Count) { 'Nothing to delete.' }
}

function Get-IgwtStartupEntryData {
    <#
    .SYNOPSIS
        The exact data of one startup entry for the snapshot (DECISIONS SA2, SA3): scope, name, kind
        (registry or folder), for a Run value its kind and raw data (variables not expanded), for
        a folder file its size and SHA256, and the StartupApproved item. Throws when the entry
        cannot be captured exactly. Read-only.
    .PARAMETER Scope
        The scope.
    .PARAMETER Name
        The entry name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Scope, [Parameter(Mandatory = $true)][string]$Name)
    $src = Get-IgwtStartupSource -Scope $Scope
    $ap = Get-IgwtRegistryValue -Path $src.Approved -Name $Name
    $approved = [ordered]@{ exists = [bool]$ap.Exists; kind = $ap.Kind; value = (ConvertTo-IgwtSerializableValue -Value $ap.Value -Kind $ap.Kind) }
    if ($src.Kind -eq 'Registry') {
        $v = Get-IgwtRegistryValue -Path $src.Location -Name $Name
        if (-not $v.Exists) { throw "The startup entry '$Name' no longer exists." }
        if ([string]$v.Kind -notin 'String', 'ExpandString', 'MultiString', 'Binary', 'DWord', 'QWord', 'None') { throw "The startup entry '$Name' has a value kind iG cannot back up exactly ($($v.Kind))." }
        return [ordered]@{ scope = $Scope; name = $Name; kind = 'registry'; valueKind = [string]$v.Kind; value = (ConvertTo-IgwtSerializableValue -Value $v.Value -Kind ([string]$v.Kind)); approved = $approved }
    }
    $folder = Get-IgwtStartupFolderPath -Scope $Scope
    if (-not $folder) { throw "The Startup folder of '$Scope' is not available." }
    $file = Join-Path $folder $Name
    if (-not [System.IO.File]::Exists($file)) { throw "The startup file '$Name' no longer exists." }
    $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "The startup file '$Name' is a link; iG does not delete links." }
    if (-not [string]::Equals((Split-Path -Parent $info.FullName).TrimEnd('\'), $folder.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) { throw "The startup file '$Name' is not directly in the Startup folder." }
    if ($info.Length -gt $script:IgwtStartupFileMaxBytes) { throw "The startup file '$Name' is larger than 10 MB; iG does not delete it." }
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    return [ordered]@{ scope = $Scope; name = $Name; kind = 'folder'; size = [int64]$info.Length; sha256 = $hash; backupFolder = ''; approved = $approved }
}

function Remove-IgwtStartupEntry {
    <#
    .SYNOPSIS
        Deletes one captured startup entry and its StartupApproved value, then reads both back
        (DECISIONS SA2, SA3). Provider internal: called only by Remove-IgwtStartupItem, after the
        entry's data is in the snapshot and, for a folder file, after its backup copy is verified.
    .PARAMETER Data
        The entry data from Get-IgwtStartupEntryData.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Data)
    Assert-IgwtWritable -Operation 'Remove-IgwtStartupEntry'
    $src = Get-IgwtStartupSource -Scope ([string]$Data['scope'])
    $name = [string]$Data['name']
    if (-not $PSCmdlet.ShouldProcess("$($src.Scope)\$name", 'Delete startup entry')) { return }
    if ($src.Kind -eq 'Registry') {
        Remove-IgwtRegistryValue -Path $src.Location -Name $name
        if ((Get-IgwtRegistryValue -Path $src.Location -Name $name).Exists) { throw "The startup entry '$name' is still there after the delete." }
    } else {
        $file = Join-Path (Get-IgwtStartupFolderPath -Scope $src.Scope) $name
        Remove-Item -LiteralPath $file -Force -ErrorAction Stop
        if ([System.IO.File]::Exists($file)) { throw "The startup file '$name' is still there after the delete." }
    }
    Remove-IgwtRegistryValue -Path $src.Approved -Name $name
    if ((Get-IgwtRegistryValue -Path $src.Approved -Name $name).Exists) { throw "The on/off state of '$name' is still there after the delete." }
}

function Restore-IgwtStartupEntry {
    <#
    .SYNOPSIS
        Recreates one deleted startup entry from iG's own backup, additively (DECISIONS SA4):
        returns 'Restored', 'AlreadyPresent' or throws "Refused: ..." with nothing changed when an
        entry of that name exists again with other data or the backup file does not match its
        hash. This is the only function that writes a Run value or creates a Startup folder file,
        and it writes only what the snapshot recorded (tests\Safety.Tests.ps1 checks this).
    .PARAMETER Data
        The 'startupEntry' action data from the snapshot.
    .PARAMETER SnapshotPath
        The snapshot file (a folder entry's backup lies next to it in the Backups folder).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Data, [AllowEmptyString()][string]$SnapshotPath = '')
    Assert-IgwtWritable -Operation 'Restore-IgwtStartupEntry'
    $field = { param($n) if ($Data -is [System.Collections.IDictionary]) { $Data[$n] } elseif ($Data.PSObject.Properties[$n]) { $Data.$n } else { $null } }
    $src = Get-IgwtStartupSource -Scope ([string](& $field 'scope'))
    $null = ConvertFrom-IgwtStartupItemId -Id "$($src.Scope)|$([string](& $field 'name'))"
    $name = [string](& $field 'name')
    $kind = [string](& $field 'kind')
    $approved = & $field 'approved'
    $result = 'Restored'
    if ($kind -eq 'registry' -and $src.Kind -eq 'Registry') {
        $vk = [string](& $field 'valueKind')
        $want = ConvertFrom-IgwtSerializableValue -Data (& $field 'value') -Kind $vk
        $now = Get-IgwtRegistryValue -Path $src.Location -Name $name
        if ($now.Exists) {
            $same = ([string]$now.Kind -eq $vk) -and ((ConvertTo-IgwtCanonicalJson (ConvertTo-IgwtSerializableValue -Value $now.Value -Kind $vk)) -eq (ConvertTo-IgwtCanonicalJson (& $field 'value')))
            if (-not $same) { throw "Refused: the startup entry '$name' exists again with other data; nothing changed." }
            $result = 'AlreadyPresent'
        } elseif ($PSCmdlet.ShouldProcess("$($src.Scope)\$name", 'Restore startup entry')) {
            Set-IgwtRegistryValue -Path $src.Location -Name $name -Kind $vk -Value $want
        }
    } elseif ($kind -eq 'folder' -and $src.Kind -eq 'Folder') {
        $folder = Get-IgwtStartupFolderPath -Scope $src.Scope
        if (-not $folder) { throw "Refused: the Startup folder of '$($src.Scope)' is not available; nothing changed." }
        $backupLeaf = [string](& $field 'backupFolder')
        if ($backupLeaf -notmatch '^startup-[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$') { throw "Refused: the backup folder name '$backupLeaf' is not one iG creates; nothing changed." }
        $backup = Join-Path (Join-Path (Get-IgwtDataPath -Kind Backups) $backupLeaf) $name
        if (-not [System.IO.File]::Exists($backup)) { throw "Refused: the backup copy of '$name' is missing; nothing changed." }
        if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne [string](& $field 'sha256')) { throw "Refused: the backup copy of '$name' does not match its recorded hash; nothing changed." }
        $file = Join-Path $folder $name
        if ([System.IO.File]::Exists($file)) {
            if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne [string](& $field 'sha256')) { throw "Refused: a different file '$name' is in the Startup folder again; nothing changed." }
            $result = 'AlreadyPresent'
        } elseif ($PSCmdlet.ShouldProcess($file, 'Restore startup file')) {
            Copy-Item -LiteralPath $backup -Destination $file -ErrorAction Stop
        }
    } else {
        throw "Refused: '$kind' does not match the scope '$($src.Scope)'; nothing changed."
    }
    if ($approved -and $approved.exists) {
        $cur = Get-IgwtRegistryValue -Path $src.Approved -Name $name
        if (-not $cur.Exists -and $PSCmdlet.ShouldProcess("$($src.Scope)\$name", 'Restore startup on/off state')) {
            Set-IgwtRegistryValue -Path $src.Approved -Name $name -Kind ([string]$approved.kind) -Value (ConvertFrom-IgwtSerializableValue -Data $approved.value -Kind ([string]$approved.kind))
        }
    }
    return $result
}

function Remove-IgwtStartupItem {
    <#
    .SYNOPSIS
        Deletes startup entries with a backup (DECISIONS SA2-SA5): refuses the whole call when any
        id is refused by Get-IgwtStartupRemovePlan, writes one 'Startup' snapshot with the exact data
        of every entry (folder files are first copied into a private backup folder and verified),
        deletes each entry and reads it back. A failure rolls back the entries already deleted in
        this call. Revert with Invoke-IgwtRevert -SnapshotPath or from Backups & Logs. Returns the
        snapshot path.
    .PARAMETER Item
        Item ids '<Scope>|<Name>'.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string[]]$Item)
    Assert-IgwtWritable -Operation 'Remove-IgwtStartupItem'
    if (-not (Test-IgwtModuleOperationDirect -BoundParameters $PSBoundParameters)) { return (Invoke-IgwtModuleOperation -Command 'Remove-IgwtStartupItem' -Parameters $PSBoundParameters) }
    $plan = @(Get-IgwtStartupRemovePlan -Item $Item)
    $refused = @($plan | Where-Object { $_.Refused })
    if ($refused.Count) { throw "Refused, nothing changed: $(@($refused | ForEach-Object { "$(if ($_.Name) { $_.Name } else { $_.Id }): $($_.Refused)" }) -join ' ')" }
    if (-not $plan.Count) { throw 'Nothing to delete.' }
    if (-not $PSCmdlet.ShouldProcess("$($plan.Count) startup entr(ies)", 'Delete with backup')) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $datas = @(foreach ($r in $plan) { Get-IgwtStartupEntryData -Scope $r.Scope -Name $r.Name })
    $backupFolder = ''
    if (@($datas | Where-Object { $_['kind'] -eq 'folder' }).Count) {
        $leaf = 'startup-{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 6)
        $backupFolder = New-IgwtPrivateBackupFolder -Path (Join-Path (Get-IgwtDataPath -Kind Backups) $leaf) -Confirm:$false
        foreach ($d in @($datas | Where-Object { $_['kind'] -eq 'folder' })) {
            $file = Join-Path (Get-IgwtStartupFolderPath -Scope $d['scope']) $d['name']
            $copy = Join-Path $backupFolder $d['name']
            Copy-Item -LiteralPath $file -Destination $copy -ErrorAction Stop
            if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne $d['sha256']) { throw "Backup failed: the copy of '$($d['name'])' does not match the file; nothing changed." }
            $d['backupFolder'] = $leaf
        }
    }
    $snap = New-IgwtSnapshot -Operation 'Startup' -Detail ('Delete ' + (@($plan | ForEach-Object { "$($_.Scope)\$($_.Name)" }) -join '; '))
    for ($i = 0; $i -lt $datas.Count; $i++) {
        $d = $datas[$i]
        Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "startup-delete:$($d['scope'])|$($d['name'])" -Actions @([ordered]@{ index = 0; type = 'startupEntry'; fingerprint = "startupEntry|$($d['scope'])|$($d['name'])"; data = $d }) -Result 'Applied' -Message 'Deleted'
    }
    $done = New-Object System.Collections.Generic.List[object]
    foreach ($d in $datas) {
        try {
            Remove-IgwtStartupEntry -Data $d -Confirm:$false
            $done.Add($d)
        } catch {
            $why = $_.Exception.Message
            $rollback = @()
            for ($j = $done.Count - 1; $j -ge 0; $j--) {
                try { $null = Restore-IgwtStartupEntry -Data $done[$j] -SnapshotPath $snap.Path -Confirm:$false }
                catch { $rollback += "$($done[$j]['name']): $($_.Exception.Message)" }
            }
            foreach ($x in $datas) {
                $msg = $(if ([object]::ReferenceEquals($x, $d)) { $why } else { 'Rolled back' })
                if ($rollback.Count -and -not [object]::ReferenceEquals($x, $d)) { $msg = 'Rollback incomplete: ' + ($rollback -join '; ') }
                Add-IgwtSnapshotEntry -Snapshot $snap -TweakId "startup-delete:$($x['scope'])|$($x['name'])" -Actions @([ordered]@{ index = 0; type = 'startupEntry'; fingerprint = "startupEntry|$($x['scope'])|$($x['name'])"; data = $x }) -Result 'Failed' -Message $msg
            }
            Write-IgwtLog -Level Error -Message "Startup delete failed at $($d['name']): $why$(if ($rollback.Count) { " Rollback incomplete: $($rollback -join '; ')" })"
            throw "The delete of '$($d['name'])' failed ($why); $(if ($rollback.Count) { 'the rollback was incomplete, see the log' } else { 'nothing changed' })."
        }
    }
    Write-IgwtLog -Message "Startup entries deleted: $(@($datas | ForEach-Object { "$($_['scope'])\$($_['name'])" }) -join ', '). Snapshot: $($snap.Path)"
    return $snap.Path
}

#endregion

function Restore-IgwtStartupSnapshot {
    <#
    .SYNOPSIS
        Reverts a Startup snapshot: StartupApproved values (on/off changes) and deleted entries
        (DECISIONS SA4, additive only), validated against the allow-listed scopes.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    foreach ($e in @($doc.entries | Where-Object { $_ })) {
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            if ([string]$a.type -eq 'startupApproved') {
                $src = Get-IgwtStartupSource -Scope ([string]$a.data.scope)
                if ($PSCmdlet.ShouldProcess("$($src.Scope)\$($a.data.name)", 'Restore startup entry state')) {
                    Restore-IgwtRegistryItem -Path $src.Approved -Name ([string]$a.data.name) -Item $a.data
                }
            } elseif ([string]$a.type -eq 'startupEntry') {
                if ([string]$e.result -ne 'Applied') { continue }
                if ($PSCmdlet.ShouldProcess("$($a.data.scope)\$($a.data.name)", 'Restore deleted startup entry')) {
                    $null = Restore-IgwtStartupEntry -Data $a.data -SnapshotPath $SnapshotPath -Confirm:$false
                }
            }
        }
    }
}
