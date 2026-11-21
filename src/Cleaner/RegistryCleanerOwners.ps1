# RegistryCleanerOwners.ps1
# The registry cleaner's owners index (DECISIONS RG4), the ownership test (RG5) and the scanned user
# (RG33). Read-only: registry keys are opened through Resolve-IgwtRegistryPath and OpenSubKey with
# writable $false; the MSI, Store app and service lists come from wrappers that throw in TestMode
# unless a test mocks them. Display names never make anything deletable; only identifiers and
# folders decide ownership.

$script:IgwtRegCleanGuidPattern = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
$script:IgwtRegCleanPerUserNote = 'Per-user entries were not checked'
$script:IgwtRegCleanServicesKey = 'SYSTEM\CurrentControlSet\Services'

#region Registry reads

function Get-IgwtRegCleanKeyLocation {
    <#
    .SYNOPSIS
        Where a cleaner key is opened: {Hive (RegistryHive); SubKey; View (RegistryView)}. Read-only.
    .DESCRIPTION
        HKLM keys are opened with OpenBaseKey in the requested view (RG8). HKCU keys always belong to
        a recorded SID and are opened as HKU:\<sid> (RG33), so a different process user never changes
        the hive. Every path goes through Resolve-IgwtRegistryPath (TestMode redirection). In TestMode
        the 32-bit view is the literal SOFTWARE\WOW6432Node path, because TestRegistry has no
        registry redirector.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER View
        64 or 32 (HKCU: 64).
    .PARAMETER Path
        Key path below the hive, without a drive prefix.
    .PARAMETER Sid
        The user SID for HKCU keys.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [ValidateSet('64', '32')][string]$View = '64',
        [AllowEmptyString()][string]$Path = '',
        [AllowEmptyString()][AllowNull()][string]$Sid = ''
    )
    $p = ([string]$Path).Trim('\')
    $regView = [Microsoft.Win32.RegistryView]::Registry64
    if ($Hive -eq 'HKCU') {
        if ($Sid -notmatch '^S-1-[0-9-]+$') { throw 'An HKCU entry needs the SID of the user whose hive was read.' }
        $ps = 'HKU:\' + $Sid
    } else {
        if ($View -eq '32') {
            if ($script:IgwtSettings.TestMode) {
                if ($p -match '^(?i)SOFTWARE(\\|$)') { $p = 'SOFTWARE\WOW6432Node' + $p.Substring(8) }
            } else { $regView = [Microsoft.Win32.RegistryView]::Registry32 }
        }
        $ps = 'HKLM:'
    }
    if ($p) { $ps = $ps + '\' + $p } else { $ps = $ps + '\' }
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath -Path $ps)
    return [pscustomobject]@{ Hive = $loc.Hive; SubKey = $loc.SubKey; View = $regView }
}

function Read-IgwtRegCleanKey {
    <#
    .SYNOPSIS
        One key's subkey names and values: {SubKeys; Values (name -> raw data, strings never
        expanded); Kinds (name -> RegistryValueKind)}, or $null when the key does not exist. Read-only.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Sid
        The user SID for HKCU keys.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [ValidateSet('64', '32')][string]$View = '64',
        [AllowEmptyString()][string]$Path = '',
        [AllowEmptyString()][AllowNull()][string]$Sid = ''
    )
    $loc = Get-IgwtRegCleanKeyLocation -Hive $Hive -View $View -Path $Path -Sid $Sid
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($loc.Hive, $loc.View)
    try {
        $key = $base.OpenSubKey($loc.SubKey, $false)
        if (-not $key) { return $null }
        try {
            $values = @{}
            $kinds = @{}
            foreach ($n in $key.GetValueNames()) {
                $values[$n] = $key.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $kinds[$n] = [string]$key.GetValueKind($n)
            }
            return [pscustomobject]@{ SubKeys = @($key.GetSubKeyNames()); Values = $values; Kinds = $kinds }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Get-IgwtRegCleanValuePaths {
    <#
    .SYNOPSIS
        The absolute local paths a registry value names, after the RG6 parsing steps, without
        touching the disk.
    .DESCRIPTION
        Strips a leading '@' and (File) a trailing ',<index>', the shell placeholders, \??\ and
        \SystemRoot\; expands variables from the owner's table; takes the quoted program, the
        CreateProcess try-in-order candidates of an unquoted line, or the payload of a host program
        (no path for msiexec product codes or unprovable host forms). Paths that the resolver would
        call Unprovable or Unknown (bare, relative, UNC, 8.3, unexpanded variables) are left out.
        Used to build the owners index and the protection facts; existence is decided only by
        Resolve-IgwtRegCleanPath.
    .PARAMETER Value
        The raw registry data.
    .PARAMETER Kind
        Command, File or Folder.
    .PARAMETER Variables
        The owner's variable table (RG7).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyString()][AllowNull()][string]$Value, [ValidateSet('Command', 'File', 'Folder')][string]$Kind = 'Command', [hashtable]$Variables = @{})
    $v = $(if ($Value) { $Value.Trim() } else { '' })
    if (-not $v) { return @() }
    if ($v.StartsWith('@')) { $v = $v.Substring(1).Trim() }
    if ($Kind -eq 'File') { $v = $v -replace ',\s*-?\d+\s*$', '' }
    $v = ([regex]::Replace($v, $script:IgwtRegCleanPlaceholderPattern, '')).Trim()
    if ($v.StartsWith('"\??\')) { $v = '"' + $v.Substring(5) }
    elseif ($v.StartsWith('\??\')) { $v = $v.Substring(4) }
    if ($v -match '^(?i)"?\\SystemRoot\\') { $v = $v -replace '^(?i)("?)\\SystemRoot\\', '$1%SystemRoot%\' }
    $v = (Expand-IgwtRegCleanVariables -Text $v -Variables $Variables).Text
    if (-not $v) { return @() }
    $paths = @()
    if ($Kind -eq 'Command') {
        $split = Split-IgwtRegCleanCommandLine -Text $v -ProgramOnly
        $hostInfo = Get-IgwtRegCleanHostPayload -Split $split
        if ($hostInfo.IsHost) {
            if ($hostInfo.Kind -eq 'Path') { $paths = @(([string]$hostInfo.Path).Trim().Trim('"')) }
        } elseif ($split.Quoted) { $paths = @([string]$split.Program) }
        else { $paths = @(Get-IgwtRegCleanTryOrder -Text $v) }
    } else {
        $p = $v
        if ($p.Length -ge 2 -and $p.StartsWith('"') -and $p.EndsWith('"')) { $p = $p.Substring(1, $p.Length - 2) }
        if ($Kind -eq 'Folder' -and $p.Length -gt 3) { $p = $p.TrimEnd('\') }
        $paths = @($p)
    }
    return @($paths | Where-Object { $_ -and -not (Get-IgwtRegCleanPathShape -Path $_) })
}

function Get-IgwtRegCleanUninstallEntries {
    <#
    .SYNOPSIS
        Every subkey of one Uninstall root (RG4a), including SystemComponent, ParentKeyName and
        entries without a DisplayName. Read-only.
    .DESCRIPTION
        Returns {Hive, View, Sid, KeyName, Path, DisplayName, Publisher, InstallLocation,
        UninstallString, QuietUninstallString, DisplayIcon, SystemComponent, ParentKeyName,
        WindowsInstaller, BundleProviderKey, ProductCode, Readable}. ProductCode is the key name when
        it is GUID-shaped, otherwise the {GUID} of an MsiExec /X or /I uninstall string. A subkey that
        cannot be read is still returned (Readable $false): its name proves something is installed.
        Throws when the root itself cannot be read.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        The Uninstall root path below the hive.
    .PARAMETER Sid
        The user SID for HKCU.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][AllowNull()][string]$Sid = ''
    )
    $root = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path $Path -Sid $Sid
    if ($null -eq $root) { return @() }
    $text = { param($h, $n) if ($h -and $h.ContainsKey($n) -and $null -ne $h[$n]) { [string]$h[$n] } else { '' } }
    foreach ($name in @($root.SubKeys)) {
        $sub = $null
        $readable = $true
        try { $sub = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path ($Path + '\' + $name) -Sid $Sid } catch { $readable = $false }
        $vals = $(if ($sub) { $sub.Values } else { @{} })
        $un = & $text $vals 'UninstallString'
        $code = ''
        if ($name -match $script:IgwtRegCleanGuidPattern) { $code = $name.ToUpperInvariant() }
        else {
            $m = [regex]::Match($un, '(?i)msiexec(\.exe)?"?\s.*?[/-][xi]\s*"?(\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\})')
            if ($m.Success) { $code = $m.Groups[2].Value.ToUpperInvariant() }
        }
        $sc = 0
        [void][int]::TryParse((& $text $vals 'SystemComponent'), [ref]$sc)
        $wi = 0
        [void][int]::TryParse((& $text $vals 'WindowsInstaller'), [ref]$wi)
        [pscustomobject]@{
            Hive = $Hive; View = $View; Sid = $(if ($Hive -eq 'HKCU') { $Sid } else { '' }); KeyName = $name; Path = ($Path + '\' + $name)
            DisplayName = (& $text $vals 'DisplayName'); Publisher = (& $text $vals 'Publisher')
            InstallLocation = (& $text $vals 'InstallLocation'); UninstallString = $un; QuietUninstallString = (& $text $vals 'QuietUninstallString')
            DisplayIcon = (& $text $vals 'DisplayIcon'); SystemComponent = ($sc -eq 1); ParentKeyName = (& $text $vals 'ParentKeyName')
            WindowsInstaller = ($wi -eq 1); BundleProviderKey = (& $text $vals 'BundleProviderKey'); ProductCode = $code; Readable = $readable
        }
    }
}

#endregion

#region System lists (mockable wrappers)

function Get-IgwtMsiProductState {
    <#
    .SYNOPSIS
        The Windows Installer ProductState of one product code (RG4b). Read-only and side-effect free.
    .DESCRIPTION
        Uses the documented Installer.ProductState property of the WindowsInstaller.Installer COM
        object (https://learn.microsoft.com/en-us/windows/win32/msi/installer-productstate-property).
        Only -1 (msiInstallStateUnknown) means "not installed"; Absent (another user), Advertised,
        Default and BadConfig count as installed. the WMI product class is never queried (it reconfigures
        products). Throws in TestMode unless mocked.
    .PARAMETER ProductCode
        A {GUID} product code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$ProductCode)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtMsiProductState must be mocked.' }
    if ($ProductCode -notmatch $script:IgwtRegCleanGuidPattern) { throw "Not a product code: '$ProductCode'." }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try { return [int]$installer.ProductState($ProductCode) }
    finally { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
}

function Get-IgwtRegCleanAppxPackages {
    <#
    .SYNOPSIS
        Installed Store packages, frameworks included (RG4c): {Name, PackageFamilyName, PublisherId,
        InstallLocation}. Read-only.
    .DESCRIPTION
        Get-AppxPackage -AllUsers when elevated, the current user's packages otherwise (the cmdlet's
        default package types are main and framework packages). Throws in TestMode unless mocked.
    #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtRegCleanAppxPackages must be mocked.' }
    $pk = $(if (Test-IgwtIsAdmin) { @(Get-AppxPackage -AllUsers -ErrorAction Stop) } else { @(Get-AppxPackage -ErrorAction Stop) })
    foreach ($p in $pk) {
        if ($null -eq $p) { continue }
        [pscustomobject]@{ Name = [string]$p.Name; PackageFamilyName = [string]$p.PackageFamilyName; PublisherId = [string]$p.PublisherId; InstallLocation = [string]$p.InstallLocation }
    }
}

function Get-IgwtRegCleanServiceList {
    <#
    .SYNOPSIS
        Services and drivers (RG4d): {Name, DisplayName, ImagePath, Type, Start, Group, LaunchProtected,
        State}. Read-only.
    .DESCRIPTION
        Win32_Service and Win32_SystemDriver names plus every HKLM\SYSTEM\CurrentControlSet\Services
        subkey (ImagePath unexpanded, Type, Start, Group, LaunchProtected from the key). Throws in
        TestMode unless mocked.
    #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtRegCleanServiceList must be mocked.' }
    $rows = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $add = {
        param($name, $display, $state)
        if (-not $name) { return }
        if (-not $rows.ContainsKey($name)) {
            $rows[$name] = [pscustomobject]@{ Name = [string]$name; DisplayName = [string]$display; ImagePath = ''; Type = $null; Start = $null; Group = ''; LaunchProtected = $null; State = [string]$state }
        }
    }
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) { if ($s) { & $add $s.Name $s.DisplayName $s.State } }
    foreach ($s in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)) { if ($s) { & $add $s.Name $s.DisplayName $s.State } }
    $root = Read-IgwtRegCleanKey -Hive HKLM -View 64 -Path $script:IgwtRegCleanServicesKey
    foreach ($n in @($root.SubKeys)) {
        & $add $n '' ''
        $k = $null
        try { $k = Read-IgwtRegCleanKey -Hive HKLM -View 64 -Path ($script:IgwtRegCleanServicesKey + '\' + $n) } catch { $k = $null }
        if (-not $k) { continue }
        $r = $rows[$n]
        if ($k.Values.ContainsKey('ImagePath')) { $r.ImagePath = [string]$k.Values['ImagePath'] }
        if ($k.Values.ContainsKey('Type')) { $r.Type = $k.Values['Type'] }
        if ($k.Values.ContainsKey('Start')) { $r.Start = $k.Values['Start'] }
        if ($k.Values.ContainsKey('Group')) { $r.Group = [string]$k.Values['Group'] }
        if ($k.Values.ContainsKey('LaunchProtected')) { $r.LaunchProtected = $k.Values['LaunchProtected'] }
        if (-not $r.DisplayName -and $k.Values.ContainsKey('DisplayName')) { $r.DisplayName = [string]$k.Values['DisplayName'] }
    }
    return @($rows.Values)
}

#endregion

#region Scanned user (RG33)

function Get-IgwtRegCleanScanUser {
    <#
    .SYNOPSIS
        The user whose HKCU the scan reads (RG33): {Sid; Source interactive|process|none; Note}.
    .DESCRIPTION
        The interactive user (Get-IgwtInteractiveUserSid, the owner of explorer.exe in this session);
        when there is none and the process is not elevated, the process user; when there is none and
        the process is elevated (no explorer: SSH, a crash, a scheduled run), $null with the note
        'Per-user entries were not checked', and the HKCU categories are skipped.
    #>
    [CmdletBinding()]
    param()
    $sid = Get-IgwtInteractiveUserSid
    if ($sid) { return [pscustomobject]@{ Sid = [string]$sid; Source = 'interactive'; Note = '' } }
    if (-not (Test-IgwtIsAdmin)) {
        return [pscustomobject]@{ Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; Source = 'process'; Note = '' }
    }
    return [pscustomobject]@{ Sid = $null; Source = 'none'; Note = $script:IgwtRegCleanPerUserNote }
}

function Get-IgwtRegCleanVariableSet {
    <#
    .SYNOPSIS
        The variable tables a scan needs (RG7): @{ '64'; '32'; 'user' } ('user' only with a SID).
    .PARAMETER Sid
        The scanned user's SID, or empty.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Sid = '')
    $set = @{ '64' = (Get-IgwtRegCleanVariableTable -View '64'); '32' = (Get-IgwtRegCleanVariableTable -View '32') }
    if ($Sid) { $set['user'] = Get-IgwtRegCleanVariableTable -View '64' -User $Sid }
    return $set
}

#endregion

#region Owners index (RG4)

function Get-IgwtRegCleanBroadFolders {
    <#
    .SYNOPSIS
        Folders that are never stored as an owned folder (lower case): drive roots are refused
        separately; these are the shared parents (Windows, Program Files, Common Files, ProgramData,
        Users, the profile and its AppData folders) that would otherwise "own" every leftover.
    .PARAMETER Variables
        The variable set of Get-IgwtRegCleanVariableSet.
    #>
    [CmdletBinding()]
    param([hashtable]$Variables = @{})
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($Variables['64'], $Variables['32'], $Variables['user'])) {
        if (-not $t) { continue }
        foreach ($n in 'SystemRoot', 'windir', 'ProgramData', 'ALLUSERSPROFILE', 'ProgramFiles', 'ProgramW6432', 'ProgramFiles(x86)', 'CommonProgramFiles', 'CommonProgramW6432', 'CommonProgramFiles(x86)', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PUBLIC', 'TEMP', 'TMP') {
            $v = [string]$t[$n]
            if ($v -and $v -match '^[A-Za-z]:\\') {
                $f = $v.TrimEnd('\')
                $null = $set.Add($f)
                if ($n -in 'USERPROFILE', 'PUBLIC') { $null = $set.Add((Split-Path -Parent $f)); $null = $set.Add($f + '\AppData'); $null = $set.Add($f + '\AppData\LocalLow') }
                if ($n -in 'SystemRoot', 'windir') { $null = $set.Add($f + '\System32'); $null = $set.Add($f + '\SysWOW64') }
                if ($n -in 'ProgramData', 'ALLUSERSPROFILE') { $null = $set.Add($f + '\Package Cache') }
            }
        }
    }
    return , $set
}

function Add-IgwtRegCleanOwnerFolder {
    <#
    .SYNOPSIS
        Adds one folder (lower case, canonical) with its source to an owners index; refuses drive
        roots, shared parents, folders under Windows and 8.3 paths. Returns $true when added.
    .PARAMETER Index
        The owners index.
    .PARAMETER Folder
        Absolute folder path.
    .PARAMETER Source
        Where the folder came from (for the self-exclusion of RG5).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Index, [AllowEmptyString()][string]$Folder, [string]$Source)
    if (-not $Folder -or (Get-IgwtRegCleanPathShape -Path $Folder)) { return $false }
    $f = $Folder.TrimEnd('\')
    try { $f = [IO.Path]::GetFullPath($f).TrimEnd('\') } catch { return $false }
    if ($f.Length -le 3 -or $Index.Broad.Contains($f)) { return $false }
    foreach ($w in @($Index.Windows)) { if ($w -and (Test-IgwtPathUnder -Path $f -Parent $w)) { return $false } }
    $key = $f.ToLowerInvariant()
    if (-not $Index.Folders.ContainsKey($key)) { $Index.Folders[$key] = New-Object System.Collections.Generic.List[string] }
    if (-not $Index.Folders[$key].Contains($Source)) { $Index.Folders[$key].Add($Source) }
    $rel = $key.Substring(2)
    if (-not $Index.RelativeFolders.ContainsKey($rel)) { $Index.RelativeFolders[$rel] = New-Object System.Collections.Generic.List[string] }
    if (-not $Index.RelativeFolders[$rel].Contains($Source)) { $Index.RelativeFolders[$rel].Add($Source) }
    return $true
}

function Add-IgwtRegCleanOwnerId {
    <#
    .SYNOPSIS
        Adds one identifier (key name, product code, service or package name) with its source to an
        owners index.
    .PARAMETER Index
        The owners index.
    .PARAMETER Id
        The identifier.
    .PARAMETER Source
        Where it came from.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Index, [AllowEmptyString()][string]$Id, [string]$Source)
    if (-not $Id) { return }
    if (-not $Index.Identifiers.ContainsKey($Id)) { $Index.Identifiers[$Id] = New-Object System.Collections.Generic.List[string] }
    if (-not $Index.Identifiers[$Id].Contains($Source)) { $Index.Identifiers[$Id].Add($Source) }
}

function Get-IgwtRegCleanOwnerIndex {
    <#
    .SYNOPSIS
        The owners index of one scan (RG4): identifiers and folders of everything that is installed.
        Read-only.
    .DESCRIPTION
        (a) every Uninstall subkey in HKLM 64, HKLM 32 (RegistryView.Registry32) and the scanned
        user's HKCU, SystemComponent, ParentKeyName and nameless entries included: key names, product
        codes, and the InstallLocation, uninstaller and DisplayIcon folders that are not provably
        missing; (b) MSI products are checked per product code with Get-IgwtMsiProductState when a
        candidate is tested; (c) Store packages (Get-IgwtRegCleanAppxPackages): names, family names,
        publisher IDs and install folders; (d) services and drivers (Get-IgwtRegCleanServiceList):
        names and existing ImagePath folders; (e) games and Steam libraries (Get-IgwtInstalledGames,
        Get-IgwtSteamLibraryPaths). Folders are stored lower case and canonical; shared parents (drive
        roots, Program Files, AppData, Windows) are never stored. A part that fails is listed in
        Failed, and Test-IgwtRegCleanOwned then answers Unknown (not reported). Display names are
        never indexed.
    .PARAMETER Sid
        The scanned user's SID (Get-IgwtRegCleanScanUser); empty = HKCU is not read.
    .PARAMETER DriveTable
        Get-IgwtRegCleanDriveTable result (built when omitted).
    .PARAMETER Probe
        The path probe scriptblock (default Test-IgwtRegCleanPathProbe).
    .PARAMETER Variables
        Variable set of Get-IgwtRegCleanVariableSet (built when omitted).
    .EXAMPLE
        $i = Get-IgwtRegCleanOwnerIndex -Sid (Get-IgwtRegCleanScanUser).Sid
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Sid = '', [hashtable]$DriveTable, [scriptblock]$Probe, [hashtable]$Variables)
    if (-not $Probe) { $Probe = { param($p, $m) Test-IgwtRegCleanPathProbe -Path $p -Mode $m } }
    if ($null -eq $DriveTable) { $DriveTable = Get-IgwtRegCleanDriveTable -Probe $Probe }
    if ($null -eq $Variables) { $Variables = Get-IgwtRegCleanVariableSet -Sid $Sid }
    $cmp = [StringComparer]::OrdinalIgnoreCase
    $windows = New-Object System.Collections.Generic.List[string]
    foreach ($t in @($Variables['64'])) { if ($t -and $t['SystemRoot']) { $windows.Add(([string]$t['SystemRoot']).TrimEnd('\')) } }
    $msiCache = @{}
    $index = [pscustomobject]@{
        Sid             = [string]$Sid
        Identifiers     = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ($cmp))
        Folders         = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ($cmp))
        RelativeFolders = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ($cmp))
        PublisherIds    = (New-Object 'System.Collections.Generic.HashSet[string]' ($cmp))
        Uninstall       = (New-Object System.Collections.Generic.List[object])
        Services        = (New-Object System.Collections.Generic.List[object])
        Packages        = (New-Object System.Collections.Generic.List[object])
        Failed          = (New-Object System.Collections.Generic.List[string])
        Notes           = (New-Object System.Collections.Generic.List[string])
        Broad           = (Get-IgwtRegCleanBroadFolders -Variables $Variables)
        Windows         = $windows.ToArray()
        Variables       = $Variables
        DriveTable      = $DriveTable
        Probe           = $Probe
        MsiCache        = $msiCache
    }
    $folderOf = { param($p) $i = $p.LastIndexOf('\'); if ($i -gt 2) { $p.Substring(0, $i) } else { '' } }
    # A folder is stored when the resolver does not prove it missing (Exists or Unknown).
    $addIfPresent = {
        param($folder, $source, $table)
        if (-not $folder -or (Get-IgwtRegCleanPathShape -Path $folder)) { return }
        $st = (Resolve-IgwtRegCleanPath -Value $folder -Kind Folder -View '64' -DriveTable $DriveTable -Probe $Probe -Variables $table).Status
        if ($st -eq 'Exists' -or $st -eq 'Unknown') { $null = Add-IgwtRegCleanOwnerFolder -Index $index -Folder $folder -Source $source }
    }

    # (a) Uninstall entries.
    foreach ($r in @(Get-IgwtRegCleanCategoryRoots | Where-Object { $_.Category -eq 'uninstall' })) {
        if ($r.Hive -eq 'HKCU' -and -not $Sid) {
            if (-not $index.Notes.Contains($script:IgwtRegCleanPerUserNote)) { $index.Notes.Add($script:IgwtRegCleanPerUserNote) }
            continue
        }
        $table = $(if ($r.Hive -eq 'HKCU') { $Variables['user'] } else { $Variables[$r.View] })
        if ($null -eq $table) { $table = @{} }
        $entries = @()
        try { $entries = @(Get-IgwtRegCleanUninstallEntries -Hive $r.Hive -View $r.View -Path $r.Path -Sid $Sid) }
        catch { $index.Failed.Add("uninstall $($r.Hive) $($r.View): $($_.Exception.Message)"); continue }
        foreach ($e in $entries) {
            $index.Uninstall.Add($e)
            $source = 'uninstall|' + $e.Hive + '|' + $e.View + '|' + $e.KeyName
            Add-IgwtRegCleanOwnerId -Index $index -Id $e.KeyName -Source $source
            Add-IgwtRegCleanOwnerId -Index $index -Id $e.ProductCode -Source $source
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $e.InstallLocation -Kind Folder -Variables $table)) { & $addIfPresent $p $source $table }
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $e.UninstallString -Kind Command -Variables $table)) { & $addIfPresent (& $folderOf $p) $source $table }
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $e.DisplayIcon -Kind File -Variables $table)) { & $addIfPresent (& $folderOf $p) $source $table }
        }
    }

    # (c) Store packages.
    try {
        foreach ($p in @(Get-IgwtRegCleanAppxPackages)) {
            if ($null -eq $p) { continue }
            $index.Packages.Add($p)
            $source = 'package|' + [string]$p.PackageFamilyName
            Add-IgwtRegCleanOwnerId -Index $index -Id ([string]$p.Name) -Source $source
            Add-IgwtRegCleanOwnerId -Index $index -Id ([string]$p.PackageFamilyName) -Source $source
            if ($p.PublisherId) { $null = $index.PublisherIds.Add([string]$p.PublisherId) }
            if ($p.InstallLocation) { $null = Add-IgwtRegCleanOwnerFolder -Index $index -Folder ([string]$p.InstallLocation) -Source $source }
        }
    } catch { $index.Failed.Add("Store apps: $($_.Exception.Message)") }

    # (d) Services and drivers.
    try {
        $sysTable = $Variables['64']
        if ($null -eq $sysTable) { $sysTable = @{} }
        foreach ($s in @(Get-IgwtRegCleanServiceList)) {
            if ($null -eq $s) { continue }
            $index.Services.Add($s)
            $source = 'service|' + [string]$s.Name
            Add-IgwtRegCleanOwnerId -Index $index -Id ([string]$s.Name) -Source $source
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value ([string]$s.ImagePath) -Kind Command -Variables $sysTable)) {
                $folder = & $folderOf $p
                if (-not $folder -or (Get-IgwtRegCleanPathShape -Path $folder)) { continue }
                $st = (Resolve-IgwtRegCleanPath -Value $folder -Kind Folder -View '64' -DriveTable $DriveTable -Probe $Probe -Variables $sysTable).Status
                if ($st -eq 'Exists') { $null = Add-IgwtRegCleanOwnerFolder -Index $index -Folder $folder -Source $source }
            }
        }
    } catch { $index.Failed.Add("services: $($_.Exception.Message)") }

    # (e) Games and Steam libraries.
    try {
        foreach ($g in @(Get-IgwtInstalledGames)) {
            if ($g -and $g.ExePath) { $null = Add-IgwtRegCleanOwnerFolder -Index $index -Folder (& $folderOf ([string]$g.ExePath)) -Source ('game|' + [string]$g.Id) }
        }
        foreach ($l in @(Get-IgwtSteamLibraryPaths)) { if ($l) { $null = Add-IgwtRegCleanOwnerFolder -Index $index -Folder ([string]$l) -Source 'game|steamLibrary' } }
    } catch { $index.Failed.Add("games: $($_.Exception.Message)") }
    return $index
}

function Get-IgwtRegCleanIndexProductState {
    <#
    .SYNOPSIS
        The MSI ProductState of a product code through the owners index cache (one
        Get-IgwtMsiProductState call per code and scan).
    .PARAMETER Index
        The owners index.
    .PARAMETER ProductCode
        A {GUID} product code.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Index, [Parameter(Mandatory = $true)][string]$ProductCode)
    $c = $ProductCode.ToUpperInvariant()
    if (-not $Index.MsiCache.ContainsKey($c)) { $Index.MsiCache[$c] = Get-IgwtMsiProductState -ProductCode $c }
    return $Index.MsiCache[$c]
}

function Test-IgwtRegCleanOwned {
    <#
    .SYNOPSIS
        RG5: whether a candidate belongs to something that is installed: {State Owned|NotOwned|Unknown;
        Reason}. Identifiers and folders only; names never make anything deletable.
    .DESCRIPTION
        Owned when: the key name (or its product code) equals an Uninstall key name, a product code,
        a service name, a package name or a package family name from another source than the
        candidate itself; a GUID-shaped key name has an MSI ProductState other than -1; any of its
        absolute paths lies under an owned folder, or under a folder of the same relative path on
        another drive; or, for Software\<Vendor>\<Product> keys and Uninstall entries, a folder named
        <Product> (or the Uninstall key name) exists under <Vendor> or directly in Program Files,
        Program Files (x86), ProgramData or the scanned user's AppData\Roaming, AppData\Local or
        AppData\LocalLow (exact folder name, a path test). Unknown when the index is incomplete, a
        product state or folder cannot be checked, or the user's folders are not known.
    .PARAMETER Index
        Get-IgwtRegCleanOwnerIndex result.
    .PARAMETER Candidate
        {Category; Hive; View; KeyName; ProductCode (optional); Vendor and Product (softwareKey);
        Paths (absolute, expanded: Get-IgwtRegCleanValuePaths); Self (the index source string of
        the candidate itself, for example 'uninstall|HKLM|64|<key name>')}.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Index, [Parameter(Mandatory = $true)]$Candidate)
    $res = { param($s, $r) [pscustomobject]@{ State = $s; Reason = $r } }
    if ($Index.Failed.Count -gt 0) { return (& $res 'Unknown' ('the list of installed programs is incomplete (' + ($Index.Failed -join '; ') + ')')) }
    $self = [string]$Candidate.Self
    $foreign = { param($list) @($list | Where-Object { $_ -ne $self }).Count -gt 0 }

    # Identifiers.
    $ids = @([string]$Candidate.KeyName, [string]$Candidate.ProductCode) | Where-Object { $_ } | Select-Object -Unique
    foreach ($id in $ids) {
        if ($Index.Identifiers.ContainsKey($id) -and (& $foreign $Index.Identifiers[$id])) {
            return (& $res 'Owned' ("'$id' is the name of an installed program, service or package (" + ($Index.Identifiers[$id] | Where-Object { $_ -ne $self } | Select-Object -First 1) + ')'))
        }
        if ($id -match $script:IgwtRegCleanGuidPattern) {
            $state = $null
            try { $state = Get-IgwtRegCleanIndexProductState -Index $Index -ProductCode $id } catch { return (& $res 'Unknown' "the Windows Installer state of $id could not be read") }
            $n = 0
            if (-not [int]::TryParse([string](@($state) | Select-Object -Last 1), [ref]$n)) { return (& $res 'Unknown' "the Windows Installer state of $id could not be read") }
            if ($n -ne -1) { return (& $res 'Owned' "Windows Installer reports $id as installed (state $n)") }
        }
    }

    # Paths under an owned folder (or the same relative folder on another drive).
    foreach ($p in @($Candidate.Paths | Where-Object { $_ })) {
        $full = [string]$p
        try { $full = [IO.Path]::GetFullPath($full) } catch { continue }
        $cur = $full.TrimEnd('\').ToLowerInvariant()
        while ($cur.Length -gt 3) {
            if ($Index.Folders.ContainsKey($cur) -and (& $foreign $Index.Folders[$cur])) { return (& $res 'Owned' "$p lies in the folder of an installed program") }
            $rel = $cur.Substring(2)
            if ($Index.RelativeFolders.ContainsKey($rel) -and (& $foreign $Index.RelativeFolders[$rel])) { return (& $res 'Owned' "$p lies in a folder of an installed program on another drive") }
            $i = $cur.LastIndexOf('\')
            if ($i -lt 3) { break }
            $cur = $cur.Substring(0, $i)
        }
    }

    # Folder-name test for Software\<Vendor>\<Product> keys and Uninstall entries.
    $cat = [string]$Candidate.Category
    if ($cat -eq 'softwareKey' -or $cat -eq 'uninstall') {
        $user = $Index.Variables['user']
        if ($null -eq $user) { return (& $res 'Unknown' 'the per-user program folders were not checked') }
        $machine = $Index.Variables['64']
        if ($null -eq $machine) { $machine = @{} }
        $names = New-Object System.Collections.Generic.List[string]
        if ($cat -eq 'softwareKey') {
            if ($Candidate.Vendor -and $Candidate.Product) { $names.Add([string]$Candidate.Vendor + '\' + [string]$Candidate.Product) }
            # The vendor folder counts too (7-Zip\FM belongs to C:\Program Files\7-Zip), review RC-2.
            if ($Candidate.Product) { $names.Add([string]$Candidate.Product) }
            if ($Candidate.Vendor) { $names.Add([string]$Candidate.Vendor) }
        } elseif ($Candidate.KeyName) { $names.Add([string]$Candidate.KeyName) }
        $bases = @(
            @('%ProgramW6432%', $machine), @('%ProgramFiles(x86)%', $machine), @('%ProgramData%', $machine),
            @('%APPDATA%', $user), @('%LOCALAPPDATA%', $user), @('%USERPROFILE%\AppData\LocalLow', $user)
        )
        foreach ($n in $names) {
            if ($n.IndexOfAny([char[]]@('/', ':', '*', '?', '"', '<', '>', '|')) -ge 0) { continue }
            foreach ($b in $bases) {
                $r = Resolve-IgwtRegCleanPath -Value ($b[0] + '\' + $n) -Kind Folder -View '64' -DriveTable $Index.DriveTable -Probe $Index.Probe -Variables $b[1]
                if ($r.Status -eq 'Exists') { return (& $res 'Owned' "the program folder $($r.Reason)") }
                if ($r.Status -eq 'Unknown') { return (& $res 'Unknown' "the program folder $($b[0])\$n could not be checked ($($r.Reason))") }
            }
        }
    }
    return (& $res 'NotOwned' 'no installed program, service, package or program folder claims it')
}

#endregion
