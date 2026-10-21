# CleanerSafety.ps1
# Safety core of the cleaning engine. Every deletion goes through Remove-IgwtCleanerFile, and
# the protections live HERE, in the primitive, not only in the rule files:
#   - allow-list only: a path is deleted only if it resolves under one of the rule's roots
#   - canonical paths: GetFullPath + 8.3 short-name expansion; device, UNC and relative paths refused
#   - hard denylist (system, program, profile and user-document locations, OneDrive, Defender, ...)
#   - reparse points (junctions, symlinks, mount points) are never followed and never deleted
#   - cloud placeholders / offline files are skipped so cleaning never triggers downloads
#   - files are re-validated right before deletion (unchanged since the scan, still old enough)
#   - only single files and EMPTY directories are deleted; there is no recursive delete anywhere

$script:IgwtCleanerTestRoot = $null   # TestMode: deletions are refused outside this folder

# File attribute bits used by the safety checks.
$script:IgwtAttrReparse = 0x400          # FILE_ATTRIBUTE_REPARSE_POINT
$script:IgwtAttrOffline = 0x1000         # FILE_ATTRIBUTE_OFFLINE
$script:IgwtAttrRecallOnOpen = 0x40000   # FILE_ATTRIBUTE_RECALL_ON_OPEN
$script:IgwtAttrRecallOnData = 0x400000  # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
$script:IgwtAttrSystem = 0x4
$script:IgwtAttrReadOnly = 0x1

# Cache folder names that may be deleted inside browser profile data.
$script:IgwtBrowserCacheNames = @('Cache', 'Code Cache', 'GPUCache', 'ShaderCache', 'GrShaderCache', 'GraphiteDawnCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache', 'cache2', 'startupCache', 'jumpListCache', 'thumbnails')

function Set-IgwtCleanerTestRoot {
    <# .SYNOPSIS TestMode only: deletions outside this folder are refused (second safety net for the test suite). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess('cleaner test root', 'Set')) {
        if ($Path) { $script:IgwtCleanerTestRoot = (ConvertTo-IgwtCanonicalPath -Path $Path) } else { $script:IgwtCleanerTestRoot = $null }
    }
}

function Resolve-IgwtLongPathName {
    <#
    .SYNOPSIS
        Expands 8.3 short-name components (for example PROGRA~1) to their long names by asking the
        file system for the matching directory entry. Components that do not exist are kept as-is.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -notmatch '~') { return $Path }
    $root = [System.IO.Path]::GetPathRoot($Path)
    $parts = $Path.Substring($root.Length).Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)
    $current = $root
    foreach ($p in $parts) {
        $next = Join-Path $current $p
        if ($p -match '~') {
            try {
                $match = @((New-Object System.IO.DirectoryInfo($current)).GetFileSystemInfos($p))
                if ($match.Count -eq 1) { $next = Join-Path $current $match[0].Name }
            } catch { Write-Verbose "Cannot expand short name '$p' under $current." }
        }
        $current = $next
    }
    return $current
}

function ConvertTo-IgwtCanonicalPath {
    <#
    .SYNOPSIS
        Canonical, absolute, local path without trailing separator. Refuses empty, relative, UNC,
        device (\\?\, \\.\) and invalid paths. Resolves "." and ".." and 8.3 short names.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Empty path.' }
    if ($Path.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) { throw "Invalid characters in path '$Path'." }
    if ($Path.StartsWith('\\')) { throw "UNC and device paths are not allowed: '$Path'." }
    if ($Path -notmatch '^[A-Za-z]:\\') { throw "Only absolute local paths are allowed: '$Path'." }
    $full = [System.IO.Path]::GetFullPath($Path)
    $full = Resolve-IgwtLongPathName -Path $full
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    return $full
}

function Test-IgwtPathUnder {
    <# .SYNOPSIS True when Path equals Parent or lies inside it (case-insensitive, separator-aware). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Parent, [switch]$Strict)
    $p = $Path.TrimEnd('\'); $q = $Parent.TrimEnd('\')
    if ([string]::Equals($p, $q, [System.StringComparison]::OrdinalIgnoreCase)) { return (-not $Strict) }
    return $p.StartsWith($q + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-IgwtKnownFolderPath {
    <# .SYNOPSIS Current user's shell folder from the registry (Shell Folders, expanded), or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $key = Resolve-IgwtRegistryPath -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        $v = (Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction Stop).$Name
        if ($v) { return [Environment]::ExpandEnvironmentVariables([string]$v) }
    } catch { Write-Verbose "Shell folder $Name not found." }
    return $null
}

function Get-IgwtCleanerProtection {
    <#
    .SYNOPSIS
        Builds the protection lists (canonical paths) used by the deletion primitive:
        ExactDeny (these exact paths are never deleted), PrefixDeny (never delete at or below),
        SystemAllow (the only %SystemRoot% subfolders that may be cleaned), ProfileAllow (the only
        user-profile subfolders that may be cleaned), Exceptions (code-level allowed subfolders inside
        protected program folders, e.g. the Steam shader cache).
    #>
    [CmdletBinding()]
    param()
    $sys = $env:SystemRoot
    $pf = $env:ProgramFiles; $pf86 = ${env:ProgramFiles(x86)}; $pfw = $env:ProgramW6432
    $pd = $env:ProgramData
    $profilesRoot = Split-Path -Parent $env:USERPROFILE
    $canon = { param($x) if ($x) { try { ConvertTo-IgwtCanonicalPath -Path ([string]$x) } catch { $null } } }

    $exact = New-Object System.Collections.Generic.List[string]
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) { $exact.Add($d.RootDirectory.FullName) }
    foreach ($x in @($sys, $pd, $profilesRoot, $env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, (Join-Path $env:USERPROFILE 'AppData'), (Join-Path $env:USERPROFILE 'AppData\LocalLow'), $env:PUBLIC)) {
        $c = & $canon $x; if ($c) { $exact.Add($c) }
    }

    $prefix = New-Object System.Collections.Generic.List[string]
    foreach ($x in @((Join-Path $sys 'System32'), (Join-Path $sys 'SysWOW64'), (Join-Path $sys 'WinSxS'), (Join-Path $sys 'Installer'),
            (Join-Path $sys 'servicing'), (Join-Path $sys 'assembly'), (Join-Path $sys 'Prefetch'), (Join-Path $sys 'Boot'), (Join-Path $sys 'Fonts'),
            $pf, $pf86, $pfw, (Join-Path $pd 'Microsoft\Windows Defender'), (Join-Path $pd 'Microsoft\Windows Defender Advanced Threat Protection'),
            (Join-Path $pd 'Microsoft\Windows\Start Menu'), (Join-Path $pd 'Packages'))) {
        $c = & $canon $x; if ($c) { $prefix.Add($c) }
    }
    # User document folders (current user; resolved from Shell Folders so redirected folders count too)
    foreach ($n in 'Desktop', 'Personal', 'My Pictures', 'My Music', 'My Video', '{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}', 'Favorites', 'Start Menu', 'Startup') {
        $c = & $canon (Get-IgwtKnownFolderPath -Name $n); if ($c) { $prefix.Add($c) }
    }
    foreach ($x in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial)) { $c = & $canon $x; if ($c) { $prefix.Add($c) } }
    foreach ($n in 'Desktop', 'Documents', 'Pictures', 'Music', 'Videos', 'Saved Games', 'Favorites', 'Contacts', 'Links', 'Searches', 'OneDrive') {
        $c = & $canon (Join-Path $env:USERPROFILE $n); if ($c) { $prefix.Add($c) }
    }
    # Roaming browser profile data (cookies, history, passwords) and Defender per-user data
    foreach ($x in @((Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'), (Join-Path $env:APPDATA 'Opera Software'))) { $c = & $canon $x; if ($c) { $prefix.Add($c) } }

    $downloads = & $canon (Get-IgwtKnownFolderPath -Name '{374DE290-123F-4565-9164-39C4925E467B}')
    if (-not $downloads) { $downloads = & $canon (Join-Path $env:USERPROFILE 'Downloads') }

    $systemAllow = @()
    foreach ($x in @('Temp', 'SoftwareDistribution\Download', 'Logs\CBS', 'Logs\DISM', 'Minidump', 'LiveKernelReports')) { $c = & $canon (Join-Path $sys $x); if ($c) { $systemAllow += $c } }
    $memoryDmp = & $canon (Join-Path $sys 'MEMORY.DMP')

    $exceptions = @()
    foreach ($base in @($pf86, $pf)) {
        if (-not $base) { continue }
        foreach ($x in @('Steam\logs', 'Steam\steamapps\shadercache', 'Steam\appcache\httpcache', 'Steam\dumps')) { $c = & $canon (Join-Path $base $x); if ($c) { $exceptions += $c } }
    }

    [pscustomobject]@{
        ExactDeny    = @($exact | Select-Object -Unique)
        PrefixDeny   = @($prefix | Select-Object -Unique)
        SystemRoot   = (& $canon $sys)
        SystemAllow  = $systemAllow
        MemoryDmp    = $memoryDmp
        ProfilesRoot = (& $canon $profilesRoot)
        Downloads    = $downloads
        Exceptions   = $exceptions
    }
}

function Get-IgwtCleanerProtectionCached {
    [CmdletBinding()]
    param()
    if (-not $script:IgwtCleanerProtection) { $script:IgwtCleanerProtection = Get-IgwtCleanerProtection }
    return $script:IgwtCleanerProtection
}

function Test-IgwtCleanerPathProtected {
    <#
    .SYNOPSIS
        Returns a refusal reason when a canonical path must never be deleted (or used as a root),
        otherwise $null. Enforced for every root and every single deletion.
    .PARAMETER AllowDownloads
        Only the explicit opt-in Downloads rule may target the Downloads folder.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$AllowDownloads)
    $prot = Get-IgwtCleanerProtectionCached
    foreach ($e in $prot.ExactDeny) { if ([string]::Equals($Path.TrimEnd('\'), $e.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) { return "protected location ($e)" } }

    $isException = $false
    foreach ($x in $prot.Exceptions) { if (Test-IgwtPathUnder -Path $Path -Parent $x) { $isException = $true } }
    if (-not $isException) {
        foreach ($d in $prot.PrefixDeny) { if (Test-IgwtPathUnder -Path $Path -Parent $d) { return "protected folder ($d)" } }
    }

    # Under %SystemRoot%: only the declared subfolders (and MEMORY.DMP) may be cleaned.
    if ($prot.SystemRoot -and (Test-IgwtPathUnder -Path $Path -Parent $prot.SystemRoot)) {
        $ok = $false
        foreach ($a in $prot.SystemAllow) { if (Test-IgwtPathUnder -Path $Path -Parent $a) { $ok = $true } }
        if ($prot.MemoryDmp -and [string]::Equals($Path, $prot.MemoryDmp, [System.StringComparison]::OrdinalIgnoreCase)) { $ok = $true }
        if (-not $ok) { return 'Windows folder outside the allowed cleanup subfolders' }
    }

    # Under a user profile: only AppData, the Gradle/Maven caches and (opt-in) Downloads.
    if ($prot.ProfilesRoot -and (Test-IgwtPathUnder -Path $Path -Parent $prot.ProfilesRoot -Strict)) {
        $rel = $Path.Substring($prot.ProfilesRoot.Length).TrimStart('\')
        $segs = $rel.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($segs.Count -lt 2) { return 'user profile root' }
        $second = $segs[1]
        $allowed = $false
        if ($second -eq 'AppData' -and $segs.Count -ge 4) { $allowed = $true }
        elseif ($second -eq '.gradle' -and $segs.Count -ge 3 -and $segs[2] -eq 'caches') { $allowed = $true }
        elseif ($second -eq '.m2' -and $segs.Count -ge 3 -and $segs[2] -eq 'repository') { $allowed = $true }
        elseif ($second -eq 'Downloads' -and $AllowDownloads) { $allowed = $true }
        if (-not $allowed) { return 'user profile folder outside AppData and the declared developer caches' }
    }
    if ($prot.Downloads -and -not $AllowDownloads -and (Test-IgwtPathUnder -Path $Path -Parent $prot.Downloads)) { return 'Downloads folder (only the opt-in Downloads rule may clean it)' }

    # Never touch the Recycle Bin or System Volume Information through the file method.
    if ($Path -match '\\\$Recycle\.Bin(\\|$)' -or $Path -match '\\System Volume Information(\\|$)') { return 'Recycle Bin / System Volume Information' }

    # Browser profile data: only cache folders below a Chromium "User Data" or Firefox profile root.
    if ($Path -match '\\User Data\\' -or $Path -match '\\Mozilla\\Firefox\\Profiles\\') {
        $segs = $Path.Split([char[]]@('\'))
        $hasCache = @($segs | Where-Object { $script:IgwtBrowserCacheNames -contains $_ }).Count -gt 0
        if (-not $hasCache) { return 'browser profile data (only cache folders may be cleaned)' }
    }
    return $null
}

function Test-IgwtCleanerRootAllowed {
    <#
    .SYNOPSIS
        Refusal reason for a rule root, or $null. A root may be a temp folder (only its contents are
        ever deleted), but never a drive root, the Windows/ProgramData/profile roots, or anything the
        denylist protects. Roots that are reparse points are refused as well.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root, [switch]$AllowDownloads)
    if ($Root -match '^[A-Za-z]:\\?$') { return 'drive root' }
    $reason = Test-IgwtCleanerPathProtected -Path $Root -AllowDownloads:$AllowDownloads
    if ($reason) { return $reason }
    try {
        $di = New-Object System.IO.DirectoryInfo($Root)
        if ($di.Exists -and ((([long]$di.Attributes) -band $script:IgwtAttrReparse) -ne 0)) { return 'root is a reparse point (not followed)' }
    } catch { return 'root is not accessible' }
    return $null
}

function Test-IgwtCleanerAttributesSkippable {
    <#
    .SYNOPSIS
        Skip reason for a file's attributes: reparse point, cloud placeholder / offline file,
        or System+ReadOnly (unless the rule allows system files). $null when the file may be deleted.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][long]$Attributes, [switch]$AllowSystemFiles)
    if (($Attributes -band $script:IgwtAttrReparse) -ne 0) { return 'reparse point (not followed)' }
    if (($Attributes -band ($script:IgwtAttrOffline -bor $script:IgwtAttrRecallOnOpen -bor $script:IgwtAttrRecallOnData)) -ne 0) { return 'cloud placeholder or offline file (would trigger a download)' }
    if (-not $AllowSystemFiles -and ($Attributes -band $script:IgwtAttrSystem) -ne 0 -and ($Attributes -band $script:IgwtAttrReadOnly) -ne 0) { return 'system + read-only file' }
    return $null
}

function Test-IgwtCleanerAncestry {
    <#
    .SYNOPSIS
        True when no directory between Root (exclusive) and the file is a reparse point. Run right
        before each deletion so a junction swapped in after the scan cannot redirect the delete.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Root)
    try {
        $rootInfo = New-Object System.IO.DirectoryInfo($Root)
        if (-not $rootInfo.Exists -or (([long]$rootInfo.Attributes) -band $script:IgwtAttrReparse) -ne 0) { return $false }
        $dir = [System.IO.Path]::GetDirectoryName($Path)
        while ($dir -and (Test-IgwtPathUnder -Path $dir -Parent $Root -Strict)) {
            $di = New-Object System.IO.DirectoryInfo($dir)
            if (-not $di.Exists) { return $false }
            if ((([long]$di.Attributes) -band $script:IgwtAttrReparse) -ne 0) { return $false }
            $dir = [System.IO.Path]::GetDirectoryName($dir)
        }
        return $true
    } catch { return $false }
}

function Get-IgwtCleanerFileAge {
    <# .SYNOPSIS Age in hours from the NEWER of creation and last-write time (extracted files keep old write times). #>
    [CmdletBinding()]
    [OutputType([double])]
    param([Parameter(Mandatory = $true)][System.IO.FileSystemInfo]$Item)
    $newest = $Item.LastWriteTimeUtc
    if ($Item.CreationTimeUtc -gt $newest) { $newest = $Item.CreationTimeUtc }
    return ([DateTime]::UtcNow - $newest).TotalHours
}

function Send-IgwtToRecycleBin {
    <# .SYNOPSIS Moves one file to the Recycle Bin (used by the opt-in Downloads rule). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Move to Recycle Bin')) { return }
    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($Path, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
}

function Remove-IgwtCleanerFile {
    <#
    .SYNOPSIS
        THE deletion primitive. Deletes one scanned file only after every safety check passes again.
        Returns an object with Result (Deleted / Skipped / Refused) and Reason.
    .PARAMETER Entry
        The scan entry (Path, Size, LastWriteUtc, Root) captured during the scan.
    .PARAMETER Rule
        The cleaner rule (minAgeHours, recycle, allowSystemFiles, allowDownloads).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Entry, [Parameter(Mandatory = $true)]$Rule)
    $out = { param($r, $why) [pscustomobject]@{ Path = [string]$Entry.Path; Bytes = [long]$Entry.Size; Result = $r; Reason = $why } }
    try { $path = ConvertTo-IgwtCanonicalPath -Path ([string]$Entry.Path) } catch { return (& $out 'Refused' $_.Exception.Message) }
    if (-not [string]::Equals($path, [string]$Entry.Path, [System.StringComparison]::OrdinalIgnoreCase)) { return (& $out 'Refused' 'path changed after canonicalization') }
    if ($script:IgwtSettings.TestMode) {
        if (-not $script:IgwtCleanerTestRoot -or -not (Test-IgwtPathUnder -Path $path -Parent $script:IgwtCleanerTestRoot -Strict)) { return (& $out 'Refused' 'TestMode: outside the test root') }
    }
    $root = [string]$Entry.Root
    try { $root = ConvertTo-IgwtCanonicalPath -Path $root } catch { return (& $out 'Refused' 'invalid root') }
    if (-not (Test-IgwtPathUnder -Path $path -Parent $root -Strict)) { return (& $out 'Refused' 'outside the rule root') }
    $declared = @($Rule.ResolvedRoots | Where-Object { [string]::Equals([string]$_, $root, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($declared.Count -eq 0) { return (& $out 'Refused' 'root is not one of the rule roots') }
    $prot = Test-IgwtCleanerPathProtected -Path $path -AllowDownloads:([bool]$Rule.allowDownloads)
    if ($prot) { return (& $out 'Refused' $prot) }
    if (-not (Test-IgwtCleanerAncestry -Path $path -Root $root)) { return (& $out 'Skipped' 'a parent folder is (or became) a reparse point') }
    $fi = New-Object System.IO.FileInfo($path)
    if (-not $fi.Exists) { return (& $out 'Skipped' 'no longer exists') }
    $attrSkip = Test-IgwtCleanerAttributesSkippable -Attributes ([long]$fi.Attributes) -AllowSystemFiles:([bool]$Rule.allowSystemFiles)
    if ($attrSkip) { return (& $out 'Skipped' $attrSkip) }
    if ($fi.Length -ne [long]$Entry.Size -or $fi.LastWriteTimeUtc.Ticks -ne [long]$Entry.LastWriteTicks) { return (& $out 'Skipped' 'changed since the scan') }
    if ((Get-IgwtCleanerFileAge -Item $fi) -lt [double]$Rule.minAgeHours) { return (& $out 'Skipped' 'younger than the minimum age') }
    if (-not $PSCmdlet.ShouldProcess($path, 'Delete file')) { return (& $out 'Skipped' 'WhatIf') }
    try {
        if ($Rule.recycle) {
            Send-IgwtToRecycleBin -Path $path
        } else {
            if (($fi.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
                if (-not $Rule.allowSystemFiles) { return (& $out 'Skipped' 'read-only file') }
                $fi.Attributes = ($fi.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly))
            }
            [System.IO.File]::Delete($path)
        }
        return (& $out 'Deleted' '')
    } catch [System.UnauthorizedAccessException] {
        return (& $out 'Skipped' 'access denied')
    } catch [System.IO.IOException] {
        return (& $out 'Skipped' 'in use')
    } catch {
        return (& $out 'Skipped' $_.Exception.Message)
    }
}

function Remove-IgwtCleanerEmptyDirectory {
    <# .SYNOPSIS Deletes one directory only if it is empty, not a reparse point, inside the root and not protected. Never recursive. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Root, $Rule)
    try { $p = ConvertTo-IgwtCanonicalPath -Path $Path; $r = ConvertTo-IgwtCanonicalPath -Path $Root } catch { return $false }
    if (-not (Test-IgwtPathUnder -Path $p -Parent $r -Strict)) { return $false }
    if ($script:IgwtSettings.TestMode -and (-not $script:IgwtCleanerTestRoot -or -not (Test-IgwtPathUnder -Path $p -Parent $script:IgwtCleanerTestRoot -Strict))) { return $false }
    if (Test-IgwtCleanerPathProtected -Path $p -AllowDownloads:([bool]$Rule.allowDownloads)) { return $false }
    $di = New-Object System.IO.DirectoryInfo($p)
    if (-not $di.Exists -or ((([long]$di.Attributes) -band $script:IgwtAttrReparse) -ne 0)) { return $false }
    if (-not (Test-IgwtCleanerAncestry -Path (Join-Path $p 'x') -Root $r)) { return $false }
    try {
        if (@($di.EnumerateFileSystemInfos()).Count -gt 0) { return $false }
        if (-not $PSCmdlet.ShouldProcess($p, 'Delete empty folder')) { return $false }
        [System.IO.Directory]::Delete($p, $false)
        return $true
    } catch { return $false }
}
