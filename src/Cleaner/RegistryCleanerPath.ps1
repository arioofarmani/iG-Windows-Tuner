# RegistryCleanerPath.ps1
# The registry cleaner's single path resolver (DECISIONS RG6-RG9): drive table, variable table,
# command-line parsing and the one disk-touching probe. Read-only. Scan, preview and removal use
# the same rules; anything that cannot be proven is Unprovable or Unknown and is never reported.
# Resolve-IgwtCommandPath (Persistence.ps1) is a different, older helper and is not used here.

# Host programs whose evidence is their payload, not the host file (RG6 step 6).
$script:IgwtRegCleanHostPrograms = @('rundll32', 'regsvr32', 'msiexec', 'cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'explorer')
# Shell verb placeholders removed before parsing (RG6 step 5).
# A placeholder must not be the start of a variable name (%LOCALAPPDATA% begins with %L).
$script:IgwtRegCleanPlaceholderPattern = '"%[1LlVv0*]"|%[1LlVv0*](?![A-Za-z0-9_(%])'
# MSFT_Disk BusType numbers (class page; RG28 item 14 UNVERIFIED) and the allowlist of fixed buses (RG9).
$script:IgwtRegCleanBusTypeNames = @{
    0 = 'Unknown'; 1 = 'SCSI'; 2 = 'ATAPI'; 3 = 'ATA'; 4 = '1394'; 5 = 'SSA'; 6 = 'Fibre Channel'; 7 = 'USB'; 8 = 'RAID'; 9 = 'iSCSI'
    10 = 'SAS'; 11 = 'SATA'; 12 = 'SD'; 13 = 'MMC'; 14 = 'Virtual'; 15 = 'File Backed Virtual'; 16 = 'Storage Spaces'; 17 = 'NVMe'
}
$script:IgwtRegCleanFixedBusTypes = @('SATA', 'NVMe', 'SAS', 'ATA', 'SCSI', 'RAID')
$script:IgwtRegCleanDriveNote = 'Other drives were not checked'

#region Process, volumes and drive table

function Test-IgwtRegCleanProcess64 {
    <#
    .SYNOPSIS
        True when PowerShell runs as a 64-bit process (the registry cleaner refuses otherwise, RG8).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return [Environment]::Is64BitProcess
}

function Get-IgwtRegCleanVolumeList {
    <#
    .SYNOPSIS
        Drive letters with their DriveType and IsReady state ([IO.DriveInfo]::GetDrives()). Read-only.
    .DESCRIPTION
        Wrapped so tests can mock it; in TestMode it throws unless mocked.
    #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtRegCleanVolumeList must be mocked.' }
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        $ready = $false
        try { $ready = [bool]$d.IsReady } catch { $ready = $false }
        [pscustomobject]@{ Letter = $d.Name.Substring(0, 1).ToUpperInvariant(); DriveType = [string]$d.DriveType; IsReady = $ready }
    }
}

function Get-IgwtRegCleanSystemDrive {
    <#
    .SYNOPSIS
        The letter of the Windows drive (for example 'C').
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $win = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ($win -match '^([A-Za-z]):') { return $Matches[1].ToUpperInvariant() }
    if ($env:SystemDrive -match '^([A-Za-z]):') { return $Matches[1].ToUpperInvariant() }
    return 'C'
}

function Get-IgwtRegCleanBusTypeName {
    <#
    .SYNOPSIS
        The bus type name of an MSFT_Disk BusType value (number or name); 'Unknown' for anything else.
    .PARAMETER BusType
        The BusType property.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$BusType)
    if ($null -eq $BusType) { return 'Unknown' }
    $n = 0
    if ([int]::TryParse([string]$BusType, [ref]$n)) {
        if ($script:IgwtRegCleanBusTypeNames.ContainsKey($n)) { return $script:IgwtRegCleanBusTypeNames[$n] }
        return 'Unknown'
    }
    $s = ([string]$BusType).Trim()
    if ($s) { return $s }
    return 'Unknown'
}

function Get-IgwtRegCleanDriveTable {
    <#
    .SYNOPSIS
        The drives a scan may use as proof (RG9): SystemDrive, Online letters, Skipped letters with
        the reason, and Notes.
    .DESCRIPTION
        A drive is online when it is the system drive, or when DriveInfo reports Fixed and IsReady,
        its root can be listed, and its disk bus type (MSFT_Partition and MSFT_Disk in
        root/Microsoft/Windows/Storage) is SATA, NVMe, SAS, ATA, SCSI or RAID. Any other drive, an
        unknown bus type or a failed lookup is skipped and the note 'Other drives were not checked'
        is added. Get-BitLockerVolume and Get-Disk are not used. Read once per scan.
    .PARAMETER Probe
        The path probe (default Test-IgwtRegCleanPathProbe); called with the root and Mode 'List'.
    #>
    [CmdletBinding()]
    param([scriptblock]$Probe)
    if (-not $Probe) { $Probe = { param($p, $m) Test-IgwtRegCleanPathProbe -Path $p -Mode $m } }
    $system = Get-IgwtRegCleanSystemDrive
    $online = New-Object System.Collections.Generic.List[string]
    $online.Add($system)
    $skipped = [ordered]@{}
    $pending = New-Object System.Collections.Generic.List[string]
    foreach ($v in @(Get-IgwtRegCleanVolumeList)) {
        $letter = ([string]$v.Letter).Substring(0, 1).ToUpperInvariant()
        if ($letter -eq $system -or $skipped.Contains($letter) -or $pending.Contains($letter)) { continue }
        if ([string]$v.DriveType -ne 'Fixed') { $skipped[$letter] = 'drive type ' + [string]$v.DriveType; continue }
        if (-not $v.IsReady) { $skipped[$letter] = 'not ready (offline or locked)'; continue }
        $state = ConvertTo-IgwtRegCleanProbeState (& $Probe ($letter + ':\') 'List')
        if ($state -ne 'Exists') { $skipped[$letter] = 'root cannot be listed'; continue }
        $pending.Add($letter)
    }
    if ($pending.Count -gt 0) {
        $bus = @{}
        $failed = ''
        try {
            $ns = 'root/Microsoft/Windows/Storage'
            $parts = @(Get-CimInstance -Namespace $ns -ClassName MSFT_Partition -ErrorAction Stop)
            $disks = @(Get-CimInstance -Namespace $ns -ClassName MSFT_Disk -ErrorAction Stop)
            $diskBus = @{}
            foreach ($d in $disks) { if ($null -ne $d -and $null -ne $d.Number) { $diskBus[[string]$d.Number] = Get-IgwtRegCleanBusTypeName $d.BusType } }
            foreach ($p in $parts) {
                if ($null -eq $p -or $null -eq $p.DriveLetter) { continue }
                $l = ([string]$p.DriveLetter).Trim()
                if ($l.Length -lt 1 -or $l -notmatch '^[A-Za-z]') { continue }
                $l = $l.Substring(0, 1).ToUpperInvariant()
                if ($diskBus.ContainsKey([string]$p.DiskNumber)) { $bus[$l] = $diskBus[[string]$p.DiskNumber] }
            }
        } catch { $failed = 'bus type lookup failed' }
        foreach ($l in $pending) {
            if ($failed) { $skipped[$l] = $failed; continue }
            if (-not $bus.ContainsKey($l)) { $skipped[$l] = 'no partition found (subst or virtual drive)'; continue }
            if ($script:IgwtRegCleanFixedBusTypes -contains $bus[$l]) { $online.Add($l) }
            else { $skipped[$l] = 'bus type ' + $bus[$l] }
        }
    }
    $notes = @()
    if ($skipped.Count -gt 0) { $notes = @($script:IgwtRegCleanDriveNote) }
    return @{ SystemDrive = $system; Online = $online.ToArray(); Skipped = $skipped; Notes = $notes }
}

#endregion

#region Probe (the only function that touches the disk)

function Get-IgwtRegCleanProbeErrorState {
    <#
    .SYNOPSIS
        Maps an exception from a file-system read to Missing (FileNotFound, DirectoryNotFound) or
        Unknown (access denied, any other IO error, anything else).
    .PARAMETER Exception
        The caught exception; PowerShell wrapper exceptions are unwrapped.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Exception)
    $e = $Exception
    while ($e -and ($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.Management.Automation.ActionPreferenceStopException]) -and $e.InnerException) { $e = $e.InnerException }
    if ($e -is [System.IO.FileNotFoundException] -or $e -is [System.IO.DirectoryNotFoundException]) { return 'Missing' }
    return 'Unknown'
}

function ConvertTo-IgwtRegCleanProbeState {
    <#
    .SYNOPSIS
        The State string of a probe result (a probe may return a string or an object with State).
    .PARAMETER Result
        The probe result.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Result)
    $r = @($Result | Where-Object { $null -ne $_ } | Select-Object -Last 1)
    if ($r.Count -eq 0) { return 'Unknown' }
    $s = $(if ($r[0] -is [string]) { $r[0] } else { [string]$r[0].State })
    if ($s -in 'Exists', 'Missing') { return $s }
    return 'Unknown'
}

function Test-IgwtRegCleanPathProbe {
    <#
    .SYNOPSIS
        Existence of one local path: {State Exists|Missing|Unknown; Reason}. Read-only.
    .DESCRIPTION
        Mode Path walks from the drive root down with [IO.File]::GetAttributes on each segment.
        FileNotFound/DirectoryNotFound = Missing, but only when the nearest existing parent folder
        can be listed (proof we could have seen the entry); access denied or any other IO error =
        Unknown; a reparse point below the root (mounted folder, junction, symbolic link) =
        Unknown. Mode List returns Exists when the folder can be listed, Unknown otherwise. This is
        the only registry cleaner function that touches the disk; the resolver takes it as a
        scriptblock so tests can replace it.
    .PARAMETER Path
        An absolute local path (X:\...).
    .PARAMETER Mode
        Path (default) or List.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path, [ValidateSet('Path', 'List')][string]$Mode = 'Path')
    if ($Path -notmatch '^[A-Za-z]:\\') { return [pscustomobject]@{ State = 'Unknown'; Reason = 'not a local absolute path' } }
    if ($Mode -eq 'List') {
        $en = $null
        try {
            $en = [IO.Directory]::EnumerateFileSystemEntries($Path).GetEnumerator()
            $null = $en.MoveNext()
            return [pscustomobject]@{ State = 'Exists'; Reason = 'listable' }
        } catch {
            return [pscustomobject]@{ State = 'Unknown'; Reason = 'folder cannot be listed' }
        } finally { if ($en) { $en.Dispose() } }
    }
    $root = $Path.Substring(0, 3)
    $segments = @($Path.Substring(3).Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries))
    $current = $root
    for ($i = 0; $i -lt $segments.Count; $i++) {
        $next = $(if ($current.EndsWith('\')) { $current + $segments[$i] } else { $current + '\' + $segments[$i] })
        $attr = $null
        try {
            $attr = [IO.File]::GetAttributes($next)
        } catch {
            $st = Get-IgwtRegCleanProbeErrorState $_.Exception
            if ($st -ne 'Missing') { return [pscustomobject]@{ State = 'Unknown'; Reason = "cannot read $next" } }
            $listed = Test-IgwtRegCleanPathProbe -Path $current -Mode List
            if ($listed.State -ne 'Exists') { return [pscustomobject]@{ State = 'Unknown'; Reason = "parent folder $current cannot be listed" } }
            return [pscustomobject]@{ State = 'Missing'; Reason = "$next not found" }
        }
        if (($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return [pscustomobject]@{ State = 'Unknown'; Reason = "reparse point at $next" } }
        if ($i -lt ($segments.Count - 1) -and ($attr -band [IO.FileAttributes]::Directory) -eq 0) { return [pscustomobject]@{ State = 'Unknown'; Reason = "$next is a file, not a folder" } }
        $current = $next
    }
    return [pscustomobject]@{ State = 'Exists'; Reason = "$current exists" }
}

#endregion

#region Variable table

function Get-IgwtRegCleanKeyStrings {
    <#
    .SYNOPSIS
        The string values (REG_SZ, REG_EXPAND_SZ, unexpanded) of one key as a hashtable; empty when the
        key does not exist. Read-only, through Resolve-IgwtRegistryPath.
    .PARAMETER Path
        Registry path (HKLM:\..., HKU:\<sid>\...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $h = @{}
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        $key = $base.OpenSubKey($loc.SubKey, $false)
        if (-not $key) { return $h }
        try {
            foreach ($n in $key.GetValueNames()) {
                if (-not $n) { continue }
                $kind = $key.GetValueKind($n)
                if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String -and $kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) { continue }
                $h[$n] = [string]$key.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
    return $h
}

function Expand-IgwtRegCleanVariables {
    <#
    .SYNOPSIS
        Replaces every %NAME% found in the table; returns {Text; Unresolved (bool)}.
    .PARAMETER Text
        The text to expand.
    .PARAMETER Variables
        Variable table (Get-IgwtRegCleanVariableTable).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text, [hashtable]$Variables = @{})
    if (-not $Text -or $Text.IndexOf('%') -lt 0) { return [pscustomobject]@{ Text = $Text; Unresolved = $false } }
    $sb = New-Object System.Text.StringBuilder
    $unresolved = $false
    $pos = 0
    foreach ($m in [regex]::Matches($Text, '%([^%\\"\s]+)%')) {
        $null = $sb.Append($Text.Substring($pos, $m.Index - $pos))
        $name = $m.Groups[1].Value
        if ($Variables.ContainsKey($name) -and $null -ne $Variables[$name]) { $null = $sb.Append([string]$Variables[$name]) }
        else { $null = $sb.Append($m.Value); $unresolved = $true }
        $pos = $m.Index + $m.Length
    }
    $null = $sb.Append($Text.Substring($pos))
    return [pscustomobject]@{ Text = $sb.ToString(); Unresolved = $unresolved }
}

function Get-IgwtRegCleanVariableTable {
    <#
    .SYNOPSIS
        Environment variables of the owner of an entry (RG7): the system table for HKLM entries, or the
        system table plus the given user's variables for HKCU entries.
    .DESCRIPTION
        System: values of HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment, plus
        SystemRoot, windir, SystemDrive, ProgramData, ALLUSERSPROFILE, ProgramFiles,
        ProgramFiles(x86), ProgramW6432, CommonProgramFiles, CommonProgramFiles(x86) and
        CommonProgramW6432 from the machine-wide known folders; ProgramFiles and CommonProgramFiles
        are the x86 folders for View 32 (RG8). User: USERPROFILE from ProfileList
        (Get-IgwtUserProfileFolders), APPDATA and LOCALAPPDATA from the user's User Shell Folders,
        and the values of HKU\<sid>\Environment (UNVERIFIED location, RG28 item 2). The elevated
        process's own environment is never used. A variable that is not found is left out, so a
        path that uses it stays Unknown.
    .PARAMETER View
        64, 32 or '' (unsure; treated as 64).
    .PARAMETER User
        The user SID for HKCU entries; '' for HKLM entries.
    #>
    [CmdletBinding()]
    param([ValidateSet('64', '32', '')][AllowEmptyString()][string]$View = '64', [AllowEmptyString()][string]$User = '')
    $t = @{}
    foreach ($kv in (Get-IgwtRegCleanKeyStrings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').GetEnumerator()) { $t[$kv.Key] = $kv.Value }
    $sf = [Environment+SpecialFolder]
    $win = [Environment]::GetFolderPath($sf::Windows)
    $pf64 = [Environment]::GetFolderPath($sf::ProgramFiles)
    $pf86 = [Environment]::GetFolderPath($sf::ProgramFilesX86)
    $cf64 = [Environment]::GetFolderPath($sf::CommonProgramFiles)
    $cf86 = [Environment]::GetFolderPath($sf::CommonProgramFilesX86)
    $pd = [Environment]::GetFolderPath($sf::CommonApplicationData)
    $computed = [ordered]@{
        'SystemRoot' = $win; 'windir' = $win; 'SystemDrive' = $(if ($win.Length -ge 2) { $win.Substring(0, 2) } else { '' })
        'ProgramData' = $pd; 'ALLUSERSPROFILE' = $pd
        'ProgramW6432' = $pf64; 'ProgramFiles(x86)' = $pf86; 'CommonProgramW6432' = $cf64; 'CommonProgramFiles(x86)' = $cf86
        'ProgramFiles' = $(if ($View -eq '32') { $pf86 } else { $pf64 }); 'CommonProgramFiles' = $(if ($View -eq '32') { $cf86 } else { $cf64 })
    }
    foreach ($k in $computed.Keys) { if ($computed[$k]) { $t[$k] = $computed[$k] } else { $t.Remove($k) } }
    if ($User) {
        if ($User -notmatch '^S-1-[0-9-]+$') { throw "Invalid user SID '$User'." }
        $prof = @(Get-IgwtUserProfileFolders | Where-Object { $_.Sid -eq $User } | Select-Object -First 1)
        if ($prof.Count -and $prof[0].Path) { $t['USERPROFILE'] = [string]$prof[0].Path } else { $t.Remove('USERPROFILE') }
        $shell = Get-IgwtRegCleanKeyStrings -Path ('HKU:\' + $User + '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
        if ($shell.ContainsKey('AppData')) { $t['APPDATA'] = $shell['AppData'] }
        if ($shell.ContainsKey('Local AppData')) { $t['LOCALAPPDATA'] = $shell['Local AppData'] }
        foreach ($kv in (Get-IgwtRegCleanKeyStrings -Path ('HKU:\' + $User + '\Environment')).GetEnumerator()) { $t[$kv.Key] = $kv.Value }
    }
    # Values may refer to other variables (TEMP=%USERPROFILE%\AppData\Local\Temp): expand a few rounds.
    for ($round = 0; $round -lt 4; $round++) {
        $changed = $false
        foreach ($k in @($t.Keys)) {
            $v = [string]$t[$k]
            if ($v.IndexOf('%') -lt 0) { continue }
            $e = (Expand-IgwtRegCleanVariables -Text $v -Variables $t).Text
            if ($e -ne $v) { $t[$k] = $e; $changed = $true }
        }
        if (-not $changed) { break }
    }
    return $t
}

#endregion

#region Parsing

function Split-IgwtRegCleanCommandLine {
    <#
    .SYNOPSIS
        Splits a command line by the CommandLineToArgvW rules: {Program; Quoted; Rest; Arguments}.
    .DESCRIPTION
        The program is the text between the first pair of quotes when the line starts with a quote,
        otherwise everything up to the first space or tab. Rest is the raw text after the program;
        Arguments are parsed with the backslash and quote rules (2n backslashes + quote = n
        backslashes and a quote toggle; 2n+1 = n backslashes and a literal quote).
    .PARAMETER Text
        The command line.
    .PARAMETER ProgramOnly
        Skips the argument parsing (Arguments is empty); the resolver uses it for non-host programs.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text, [switch]$ProgramOnly)
    $s = $(if ($Text) { $Text.TrimStart() } else { '' })
    $program = ''
    $quoted = $false
    $restStart = $s.Length
    if ($s.StartsWith('"')) {
        $quoted = $true
        $end = $s.IndexOf('"', 1)
        if ($end -lt 0) { $program = $s.Substring(1); $restStart = $s.Length }
        else {
            $program = $s.Substring(1, $end - 1)
            $restStart = $end + 1
            while ($restStart -lt $s.Length -and $s[$restStart] -ne ' ' -and $s[$restStart] -ne "`t") { $restStart++ }
        }
    } else {
        $i = 0
        while ($i -lt $s.Length -and $s[$i] -ne ' ' -and $s[$i] -ne "`t") { $i++ }
        $program = $s.Substring(0, $i)
        $restStart = $i
    }
    $rest = $(if ($restStart -lt $s.Length) { $s.Substring($restStart) } else { '' })
    if ($ProgramOnly) { return [pscustomobject]@{ Program = $program; Quoted = $quoted; Rest = $rest; Arguments = @() } }
    $out = New-Object System.Collections.Generic.List[string]
    $cur = New-Object System.Text.StringBuilder
    $inQuote = $false
    $have = $false
    $i = 0
    while ($i -lt $rest.Length) {
        $c = $rest[$i]
        if (($c -eq ' ' -or $c -eq "`t") -and -not $inQuote) {
            if ($have) { $out.Add($cur.ToString()); $null = $cur.Clear(); $have = $false }
            $i++; continue
        }
        if ($c -eq '\') {
            $n = 0
            while ($i -lt $rest.Length -and $rest[$i] -eq '\') { $n++; $i++ }
            if ($i -lt $rest.Length -and $rest[$i] -eq '"') {
                $null = $cur.Append('\' * [int][Math]::Floor($n / 2))
                if ($n % 2 -eq 1) { $null = $cur.Append('"'); $i++ }
            } else { $null = $cur.Append('\' * $n) }
            $have = $true
            continue
        }
        if ($c -eq '"') {
            if ($inQuote -and ($i + 1) -lt $rest.Length -and $rest[$i + 1] -eq '"') { $null = $cur.Append('"'); $i += 2; $have = $true; continue }
            $inQuote = -not $inQuote; $have = $true; $i++; continue
        }
        $null = $cur.Append($c); $have = $true; $i++
    }
    if ($have) { $out.Add($cur.ToString()) }
    return [pscustomobject]@{ Program = $program; Quoted = $quoted; Rest = $rest; Arguments = $out.ToArray() }
}

function Get-IgwtRegCleanTryOrder {
    <#
    .SYNOPSIS
        The CreateProcess try-in-order candidates of an unquoted command line: every prefix that
        ends before a space, then the whole line; ".exe" is appended when the last segment has no
        extension.
    .PARAMETER Text
        The unquoted command line (variables already expanded).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $s = $(if ($Text) { $Text.Trim() } else { '' })
    $list = New-Object System.Collections.Generic.List[string]
    if (-not $s) { return $list.ToArray() }
    $ends = New-Object System.Collections.Generic.List[int]
    for ($i = 1; $i -lt $s.Length; $i++) { if ($s[$i] -eq ' ' -and $s[$i - 1] -ne ' ') { $ends.Add($i) } }
    $ends.Add($s.Length)
    foreach ($e in $ends) {
        $p = $s.Substring(0, $e).TrimEnd()
        $leaf = $p.Substring($p.LastIndexOf('\') + 1)
        if ($leaf.IndexOf('.') -lt 0) { $p = "${p}.exe" }
        if (-not $list.Contains($p)) { $list.Add($p) }
    }
    return $list.ToArray()
}

function Get-IgwtRegCleanPathShape {
    <#
    .SYNOPSIS
        '' when a path can be probed, otherwise 'Unprovable: <why>' or 'Unknown: <why>' (RG6).
    .DESCRIPTION
        Unprovable: empty, URL or protocol target (shell:, ms-, http:), UNC, bare names, relative
        paths, invalid characters, '.' or '..' segments, empty segments, and 8.3 short-name segments
        ('~' followed by a digit). Unknown: a variable left unexpanded.
    .PARAMETER Path
        The path after expansion.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Path)
    if (-not $Path) { return 'Unprovable: empty path' }
    if ($Path.StartsWith('\\') -or $Path.StartsWith('//')) { return 'Unprovable: network path' }
    if ($Path -match '%[^%\\"\s]+%') { return 'Unknown: variable not expanded' }
    if ($Path -match '^[A-Za-z][A-Za-z0-9+.\-]+:') { return 'Unprovable: URL or protocol target' }
    if ($Path -notmatch '^[A-Za-z]:\\') { return 'Unprovable: bare or relative path' }
    $rest = $Path.Substring(3)
    if ($rest.IndexOfAny([char[]]@('/', ':', '*', '?', '"', '<', '>', '|')) -ge 0 -or $rest.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) { return 'Unprovable: invalid characters' }
    $trim = $rest.TrimEnd('\')
    if (-not $trim) { return 'Unprovable: drive root' }
    foreach ($seg in $trim.Split('\')) {
        if (-not $seg) { return 'Unprovable: empty path segment' }
        if ($seg -eq '.' -or $seg -eq '..') { return 'Unprovable: relative segment' }
        if ($seg -match '~\d') { return 'Unprovable: 8.3 short name' }
        if ($seg.EndsWith(' ') -or $seg.EndsWith('.')) { return 'Unprovable: segment ends with a space or dot' }
    }
    return ''
}

function Get-IgwtRegCleanHostPayload {
    <#
    .SYNOPSIS
        For a host program (rundll32, regsvr32, msiexec, cmd, powershell, pwsh, wscript, cscript,
        mshta, explorer): {IsHost; Kind Path|Msi|Unprovable; Path; ProductCode; Reason} (RG6 step 6).
    .DESCRIPTION
        rundll32: the DLL before the first comma of the first argument (UNVERIFIED syntax, RG28
        item 1; without a comma = Unprovable). regsvr32, wscript, cscript, mshta, explorer: the
        first argument that is not a switch. powershell and pwsh: the argument after -File (any
        other form = Unprovable). msiexec: /X or /I followed by a {GUID} = the product code. cmd
        and every other host form = Unprovable.
    .PARAMETER Split
        Result of Split-IgwtRegCleanCommandLine.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Split)
    $leaf = ([string]$Split.Program).TrimEnd('\')
    $leaf = $leaf.Substring($leaf.LastIndexOf('\') + 1) -replace '(?i)\.exe$', ''
    $r = [pscustomobject]@{ IsHost = $false; Kind = ''; Path = ''; ProductCode = ''; Reason = '' }
    if ($script:IgwtRegCleanHostPrograms -notcontains $leaf.ToLowerInvariant()) { return $r }
    $r.IsHost = $true
    $r.Kind = 'Unprovable'
    $args0 = @($Split.Arguments)
    # A -ProgramOnly split has no arguments yet: parse them now (Rest starts with a space or is empty).
    if ($args0.Count -eq 0 -and $Split.Rest) { $args0 = @((Split-IgwtRegCleanCommandLine -Text ('x' + [string]$Split.Rest)).Arguments) }
    switch ($leaf.ToLowerInvariant()) {
        'rundll32' {
            if ($args0.Count -ge 1 -and $args0[0].IndexOf(',') -gt 0) { $r.Kind = 'Path'; $r.Path = $args0[0].Substring(0, $args0[0].IndexOf(',')).Trim() }
            else { $r.Reason = 'rundll32 form without DLL,entry' }
        }
        'msiexec' {
            $m = [regex]::Match([string]$Split.Rest, '(?i)(^|\s)[/-](x|i|uninstall|package)\s*"?(\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\})')
            if ($m.Success) { $r.Kind = 'Msi'; $r.ProductCode = $m.Groups[3].Value.ToUpperInvariant() }
            else { $r.Reason = 'msiexec form without a product code' }
        }
        { $_ -in 'powershell', 'pwsh' } {
            $hasCommand = @($args0 | Where-Object { $_ -match '^(?i)-(c|command|e|ec|enc\w*)$' }).Count -gt 0
            for ($i = 0; $i -lt $args0.Count - 1; $i++) {
                if ($args0[$i] -match '^(?i)-(f|file)$') { $r.Kind = 'Path'; $r.Path = $args0[$i + 1]; break }
            }
            if ($hasCommand) { $r.Kind = 'Unprovable'; $r.Path = '' }
            if ($r.Kind -ne 'Path') { $r.Reason = 'PowerShell form without -File' }
        }
        { $_ -in 'regsvr32', 'wscript', 'cscript', 'mshta', 'explorer' } {
            $first = @($args0 | Where-Object { $_ -and $_ -notmatch '^[/-]' } | Select-Object -First 1)
            if ($first.Count) { $r.Kind = 'Path'; $r.Path = $first[0] } else { $r.Reason = "$leaf form without a file argument" }
        }
        default { $r.Reason = "$leaf command" }
    }
    return $r
}

function Get-IgwtRegCleanWowCandidates {
    <#
    .SYNOPSIS
        The WOW64 file-system candidates of a path (RG8): for View 32 or '' (unsure), Program Files and
        Program Files (x86), Common Files both ways, and System32 and SysWOW64. View 64 = the path only.
    .PARAMETER Path
        An absolute path.
    .PARAMETER View
        64, 32 or ''.
    .PARAMETER Variables
        The variable table (ProgramW6432, ProgramFiles(x86), CommonProgramW6432,
        CommonProgramFiles(x86), SystemRoot).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [AllowEmptyString()][string]$View = '64', [hashtable]$Variables = @{})
    $list = New-Object System.Collections.Generic.List[string]
    $list.Add($Path)
    if ($View -eq '64') { return $list.ToArray() }
    $pairs = New-Object System.Collections.Generic.List[object]
    # Common Files first: it lies inside Program Files, so the longer prefix must win.
    if ($Variables['CommonProgramW6432'] -and $Variables['CommonProgramFiles(x86)']) { $pairs.Add(@([string]$Variables['CommonProgramW6432'], [string]$Variables['CommonProgramFiles(x86)'])) }
    if ($Variables['ProgramW6432'] -and $Variables['ProgramFiles(x86)']) { $pairs.Add(@([string]$Variables['ProgramW6432'], [string]$Variables['ProgramFiles(x86)'])) }
    if ($Variables['SystemRoot']) {
        $sr = ([string]$Variables['SystemRoot']).TrimEnd('\')
        $pairs.Add(@(($sr + '\System32'), ($sr + '\SysWOW64')))
    }
    foreach ($pair in $pairs) {
        foreach ($dir in 0, 1) {
            $from = ([string]$pair[$dir]).TrimEnd('\')
            $to = ([string]$pair[1 - $dir]).TrimEnd('\')
            if ($Path.Length -gt $from.Length -and $Path.StartsWith($from + '\', [StringComparison]::OrdinalIgnoreCase)) {
                $alt = $to + $Path.Substring($from.Length)
                if (-not $list.Contains($alt)) { $list.Add($alt) }
                return $list.ToArray()
            }
        }
    }
    return $list.ToArray()
}

#endregion

#region Resolver

function Resolve-IgwtRegCleanPath {
    <#
    .SYNOPSIS
        The single registry cleaner path resolver (RG6): {Status Exists|Missing|Unknown|Unprovable;
        Candidates; Reason}.
    .DESCRIPTION
        Steps in order: raw string; strip a leading '@' and (File kind) a trailing ',<index>';
        strip \??\ and map \SystemRoot\; remove the %1, %L, %V, %*, %0 placeholders; expand
        variables from the owner's table (RG7, unexpanded = Unknown); split the command line by the
        CommandLineToArgvW rules with CreateProcess try-in-order for unquoted programs; evaluate
        the payload of host programs (msiexec /X {GUID} = the ProductState scriptblock); add the
        WOW64 candidates (RG8) and the same relative path on every other online fixed drive (RG9).
        UNC and network paths (Test-IgwtNetworkPath) are Unprovable before any probe; a path on a
        skipped drive is Unknown. Exists when any candidate exists; Missing only when every
        candidate is provably missing. Refuses in a 32-bit process.
    .PARAMETER Value
        The raw registry data (not expanded).
    .PARAMETER Kind
        Command (a command line), File (one file path, may carry ',index') or Folder.
    .PARAMETER View
        Registry view the value came from: 64, 32 or '' (unsure or shared key).
    .PARAMETER User
        The SID whose hive the value came from; '' for HKLM.
    .PARAMETER DriveTable
        Get-IgwtRegCleanDriveTable result (built when omitted).
    .PARAMETER Probe
        Path probe scriptblock (param($Path, $Mode)) returning a state string or an object with State;
        default Test-IgwtRegCleanPathProbe.
    .PARAMETER Variables
        Variable table (default Get-IgwtRegCleanVariableTable -View -User).
    .PARAMETER ProductState
        Scriptblock (param($ProductCode)) returning the MSI ProductState integer; -1 = not installed.
        Without it an msiexec product code is Unknown.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][AllowNull()][string]$Value,
        [ValidateSet('Command', 'File', 'Folder')][string]$Kind = 'Command',
        [ValidateSet('64', '32', '')][AllowEmptyString()][string]$View = '64',
        [AllowEmptyString()][string]$User = '',
        [hashtable]$DriveTable,
        [scriptblock]$Probe,
        [hashtable]$Variables,
        [scriptblock]$ProductState
    )
    if (-not (Test-IgwtRegCleanProcess64)) { throw 'The registry cleaner needs 64-bit PowerShell; start iG Windows Tuner from the 64-bit Windows PowerShell.' }
    $result = { param($s, $c, $r) [pscustomobject]@{ Status = $s; Candidates = @($c); Reason = $r } }
    $v = $(if ($Value) { $Value.Trim() } else { '' })
    if (-not $v) { return (& $result 'Unprovable' @() 'empty value') }
    # (2) indirect string and resource index.
    if ($v.StartsWith('@')) { $v = $v.Substring(1).Trim() }
    if ($Kind -eq 'File') { $v = $v -replace ',\s*-?\d+\s*$', '' }
    # (5) shell verb placeholders.
    $v = ([regex]::Replace($v, $script:IgwtRegCleanPlaceholderPattern, '')).Trim()
    # (3) native forms.
    if ($v.StartsWith('"\??\')) { $v = '"' + $v.Substring(5) }
    elseif ($v.StartsWith('\??\')) { $v = $v.Substring(4) }
    if ($v -match '^(?i)"?\\SystemRoot\\') { $v = $v -replace '^(?i)("?)\\SystemRoot\\', '$1%SystemRoot%\' }
    if (-not $v) { return (& $result 'Unprovable' @() 'empty value') }
    if ($null -eq $Variables) { $Variables = Get-IgwtRegCleanVariableTable -View $View -User $User }
    # (7) variables: expanded before splitting, as the shell does before CreateProcess.
    $v = (Expand-IgwtRegCleanVariables -Text $v -Variables $Variables).Text
    # (4, 6) the paths to test.
    $paths = @()
    if ($Kind -eq 'Command') {
        $split = Split-IgwtRegCleanCommandLine -Text $v -ProgramOnly
        $leaf = ([string]$split.Program).TrimEnd('\')
        $leaf = ($leaf.Substring($leaf.LastIndexOf('\') + 1) -replace '(?i)\.exe$', '').ToLowerInvariant()
        $hostInfo = $null
        if ($script:IgwtRegCleanHostPrograms -contains $leaf) { $hostInfo = Get-IgwtRegCleanHostPayload -Split $split }
        if ($hostInfo -and $hostInfo.IsHost) {
            if ($hostInfo.Kind -eq 'Unprovable') { return (& $result 'Unprovable' @() $hostInfo.Reason) }
            if ($hostInfo.Kind -eq 'Msi') {
                $code = $hostInfo.ProductCode
                if (-not $ProductState) { return (& $result 'Unknown' @($code) 'msiexec product code; product state not checked') }
                $state = $null
                try { $state = & $ProductState $code } catch { return (& $result 'Unknown' @($code) 'msiexec product code; product state lookup failed') }
                $n = 0
                if (-not [int]::TryParse([string](@($state) | Select-Object -Last 1), [ref]$n)) { return (& $result 'Unknown' @($code) 'msiexec product code; product state unreadable') }
                if ($n -eq -1) { return (& $result 'Missing' @($code) "product $code is not installed") }
                return (& $result 'Exists' @($code) "product $code is installed (state $n)")
            }
            $paths = @(([string]$hostInfo.Path).Trim().Trim('"'))
        } elseif ($split.Quoted) {
            $paths = @($split.Program)
        } else {
            $paths = @(Get-IgwtRegCleanTryOrder -Text $v)
        }
    } else {
        $p = $v
        if ($p.Length -ge 2 -and $p.StartsWith('"') -and $p.EndsWith('"')) { $p = $p.Substring(1, $p.Length - 2) }
        if ($Kind -eq 'Folder' -and $p.Length -gt 3) { $p = $p.TrimEnd('\') }
        $paths = @($p)
    }
    # Shape checks before any probe; network paths never reach the probe.
    $probeable = New-Object System.Collections.Generic.List[string]
    $unknownReason = ''
    $firstReason = ''
    $netMemo = @{}
    foreach ($p in $paths) {
        $shape = Get-IgwtRegCleanPathShape -Path $p
        if (-not $shape) {
            $drive = $p.Substring(0, 2).ToUpperInvariant()
            if (-not $netMemo.ContainsKey($drive)) { $netMemo[$drive] = [bool](Test-IgwtNetworkPath -Path $p) }
            if ($netMemo[$drive]) { $shape = 'Unprovable: network path' }
        }
        if (-not $shape) { $probeable.Add($p); continue }
        if ($shape.StartsWith('Unknown') -and -not $unknownReason) { $unknownReason = $shape.Substring(9) }
        if (-not $firstReason) { $firstReason = $shape.Substring($shape.IndexOf(':') + 2) }
    }
    if ($probeable.Count -eq 0) {
        if ($unknownReason) { return (& $result 'Unknown' @() $unknownReason) }
        return (& $result 'Unprovable' @() $firstReason)
    }
    if ($null -eq $DriveTable) { $DriveTable = Get-IgwtRegCleanDriveTable -Probe $Probe }
    if (-not $Probe) { $Probe = { param($p, $m) Test-IgwtRegCleanPathProbe -Path $p -Mode $m } }
    $online = New-Object System.Collections.Generic.List[string]
    foreach ($o in @($DriveTable.Online)) { $online.Add(([string]$o).ToUpperInvariant()) }
    # (8, 9) WOW64 candidates, then the same relative path on every other online fixed drive.
    $candidates = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($p in $probeable) {
        foreach ($w in @(Get-IgwtRegCleanWowCandidates -Path $p -View $View -Variables $Variables)) {
            $letter = $w.Substring(0, 1).ToUpperInvariant()
            $rel = $w.Substring(1)
            $drives = New-Object System.Collections.Generic.List[string]
            $drives.Add($letter)
            foreach ($o in $online) { if ($o -ne $letter) { $drives.Add($o) } }
            foreach ($d in $drives) {
                $c = $d + $rel
                if ($seen.ContainsKey($c)) { continue }
                $seen[$c] = $true
                $candidates.Add($c)
            }
        }
    }
    $unknown = $unknownReason
    foreach ($c in $candidates) {
        $letter = $c.Substring(0, 1).ToUpperInvariant()
        if (-not $online.Contains($letter)) {
            if (-not $unknown) { $unknown = "drive ${letter}: is not checked" }
            continue
        }
        $raw = & $Probe $c 'Path'
        $state = $(if ($raw -is [string]) { $(if ($raw -eq 'Exists' -or $raw -eq 'Missing') { $raw } else { 'Unknown' }) } else { ConvertTo-IgwtRegCleanProbeState $raw })
        if ($state -eq 'Exists') { return (& $result 'Exists' $candidates.ToArray() "$c exists") }
        if ($state -ne 'Missing' -and -not $unknown) { $unknown = "$c could not be checked" }
    }
    if ($unknown) { return (& $result 'Unknown' $candidates.ToArray() $unknown) }
    $drivesText = (@($candidates | ForEach-Object { $_.Substring(0, 2) } | Select-Object -Unique) -join ', ')
    return (& $result 'Missing' $candidates.ToArray() "missing on $drivesText")
}

#endregion
