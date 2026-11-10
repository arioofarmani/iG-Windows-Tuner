# RegistryCleanerSnapshot.ps1
# The registry cleaner's exact snapshots and backup text (DECISIONS RG17, RG18): the compared
# key-tree and value snapshots the journal keeps, the key permissions recorded for information,
# and the pure builders of selected.reg, firewall-rules.json and manifest.json. Read-only: keys are
# opened through Get-IgwtRegCleanKeyLocation (Resolve-IgwtRegistryPath) and OpenSubKey with writable
# $false; nothing in this file writes the registry or a file.

$script:IgwtRegFileHeader = 'Windows Registry Editor Version 5.00'
# Wine's regedit export starts a new line once a hex line is this long (UNVERIFIED that Windows
# regedit wraps at the same column; the import accepts any wrapping, RG28).
$script:IgwtRegFileHexWidth = 77

#region Snapshots (the compared data, RG17)

function Get-IgwtRegCleanSnapshotData {
    <#
    .SYNOPSIS
        One value in snapshot form: {Kind; Data; Bytes}. Data is ConvertTo-IgwtSerializableValue of
        the normalized value (strings never expanded, REG_NONE and binary as hex, QWORD as decimal
        text). Throws for a kind .NET cannot write back (Unknown: REG_LINK, REG_RESOURCE_LIST and
        similar). Pure.
    .PARAMETER Raw
        The raw value from RegistryKey.GetValue with DoNotExpandEnvironmentNames.
    .PARAMETER Kind
        The RegistryValueKind name.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Raw, [Parameter(Mandatory = $true)][string]$Kind)
    $bytes = 0
    switch ($Kind) {
        { $_ -in 'String', 'ExpandString' } { $bytes = 2 * (([string]$Raw).Length + 1) }
        'MultiString' { foreach ($s in @($Raw)) { $bytes += 2 * (([string]$s).Length + 1) } }
        'DWord' { $bytes = 4 }
        'QWord' { $bytes = 8 }
        { $_ -in 'Binary', 'None' } { if ($Raw -is [byte[]]) { $bytes = $Raw.Length } }
        default { throw "Cannot be backed up exactly: a value of kind '$Kind' cannot be restored." }
    }
    $norm = ConvertFrom-IgwtRawRegistryValue -Raw $Raw -Kind $Kind
    $data = ConvertTo-IgwtSerializableValue -Value $norm -Kind $Kind
    if ($Kind -eq 'MultiString') { $data = [string[]]@($norm) }
    elseif ($Kind -in 'Binary', 'None' -and $null -eq $data) { $data = '' }
    return [pscustomobject]@{ Kind = $Kind; Data = $data; Bytes = $bytes }
}

function Get-IgwtRegCleanKeySnapshot {
    <#
    .SYNOPSIS
        The exact snapshot of one key tree (RG17), the data the journal compares:
        [ordered]{exists; kind 'keyTree'; value '<n> keys, <m> values'; hive; sid; view; path;
        keyList (relative paths, sorted ordinally, '' = the root); valueList ({key; name; kind;
        data}, by key and then name, ordinally); valueCount}. Read-only.
    .DESCRIPTION
        The members are keyList, valueList and valueCount rather than RG17's keys, values and count:
        on a PowerShell dictionary $d.Keys, $d.Values and $d.Count return such members instead of
        the dictionary's own, which breaks the journal helpers that copy and serialize snapshots.
        Strings are read with DoNotExpandEnvironmentNames and kept raw; MultiString keeps order and
        empty strings; DWORD is a number, QWORD decimal text, binary and REG_NONE hex
        (ConvertTo-IgwtSerializableValue). Owner and SDDL are not part of it (see
        Get-IgwtRegCleanTreeSecurity). A tree that cannot be backed up exactly THROWS (it never
        returns a reason object): a value of an Unknown kind, more than 2,000 values, 2,000 keys or
        512 KB of data, a subkey that cannot be opened, or a subkey name on the RG32 deny list
        (data\registry\categories.json segmentNames). A missing root gives exists $false and empty
        lists.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER Sid
        The user SID for HKCU keys ('' for HKLM).
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive, without a drive prefix.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [AllowEmptyString()][AllowNull()][string]$Sid = '',
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path
    )
    $p = ([string]$Path).Trim('\')
    if (-not $p) { throw 'A key tree snapshot needs a key path below the hive.' }
    if ($Hive -eq 'HKLM') { $Sid = '' }
    $exact = 'Cannot be backed up exactly'
    $deny = @(@((Get-IgwtRegCleanCategories).denyList.segmentNames) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $snap = [ordered]@{
        exists = $false; kind = 'keyTree'; value = '0 keys, 0 values'; hive = $Hive; sid = [string]$Sid; view = $View; path = $p
        keyList = @(); valueList = @(); valueCount = 0
    }
    $root = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path $p -Sid $Sid
    if ($null -eq $root) { return $snap }
    $keys = New-Object System.Collections.Generic.List[string]
    $rows = @{}
    $valueCount = 0
    $bytes = 0
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@('', $root))
    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $rel = [string]$item[0]
        $k = $item[1]
        if ($null -eq $k) {
            $full = $p + '\' + $rel
            try { $k = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path $full -Sid $Sid } catch { throw "${exact}: the subkey '$rel' cannot be opened ($($_.Exception.Message))." }
            if ($null -eq $k) { throw "${exact}: the subkey '$rel' cannot be opened (it disappeared while it was read)." }
        }
        $keys.Add($rel)
        if ($keys.Count -gt $script:IgwtRegCleanMaxTreeKeys) { throw "${exact}: the tree has more than 2,000 keys." }
        $names = [string[]]@($k.Values.Keys)
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($vn in $names) {
            $d = Get-IgwtRegCleanSnapshotData -Raw $k.Values[$vn] -Kind ([string]$k.Kinds[$vn])
            $valueCount++
            $bytes += $d.Bytes
            if ($valueCount -gt $script:IgwtRegCleanMaxTreeValues -or $bytes -gt $script:IgwtRegCleanMaxTreeBytes) { throw "${exact}: the tree has more than 2,000 values or 512 KB of data." }
            $list.Add([ordered]@{ key = $rel; name = $vn; kind = $d.Kind; data = $d.Data })
        }
        $rows[$rel] = $list
        foreach ($sk in @($k.SubKeys)) {
            if ($deny -contains [string]$sk) { throw "Contains a shared or linked key ($sk); it cannot be backed up or removed." }
            $queue.Enqueue(@($(if ($rel) { $rel + '\' + $sk } else { [string]$sk }), $null))
        }
    }
    $arr = $keys.ToArray()
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    $values = New-Object System.Collections.Generic.List[object]
    foreach ($rel in $arr) { foreach ($row in $rows[$rel]) { $values.Add($row) } }
    $snap.exists = $true
    $snap.keyList = [string[]]$arr
    $snap.valueList = $values.ToArray()
    $snap.valueCount = $valueCount
    $snap.value = '{0} keys, {1} values' -f $arr.Count, $valueCount
    return $snap
}

function Get-IgwtRegCleanTreeSecurity {
    <#
    .SYNOPSIS
        The permissions of every key of a snapshot, for the offer rule, Set's applied.security and
        manifest.json (information only, never compared): a list of [ordered]{key; owner; sddl;
        aclProtected; explicitAceCount}. Throws when a key's permissions cannot be read. Read-only.
    .PARAMETER Snapshot
        A Get-IgwtRegCleanKeySnapshot result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Snapshot)
    $get = { param($n) if ($Snapshot -is [System.Collections.IDictionary]) { $Snapshot[$n] } else { $Snapshot.$n } }
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (& $get 'exists')) { return , $out.ToArray() }
    $base = [string](& $get 'path')
    foreach ($rel in @(& $get 'keyList')) {
        $full = $(if ([string]$rel) { $base + '\' + $rel } else { $base })
        $sec = Get-IgwtRegCleanKeySecurity -Hive ([string](& $get 'hive')) -View ([string](& $get 'view')) -Path $full -Sid ([string](& $get 'sid'))
        if ($null -eq $sec) { throw "The permissions of '$full' cannot be read: the key no longer exists." }
        $out.Add([ordered]@{ key = [string]$rel; owner = [string]$sec.Owner; sddl = [string]$sec.Sddl; aclProtected = [bool]$sec.AclProtected; explicitAceCount = [int]$sec.ExplicitAceCount })
    }
    return , $out.ToArray()
}

function Get-IgwtRegCleanValueSnapshot {
    <#
    .SYNOPSIS
        The exact snapshot of one value (RG17): the Get-IgwtRegistryValue shape in journal form
        [ordered]{exists; kind; value} plus view and sid, and hive, path and name for the .reg
        writer. The value is ConvertTo-IgwtSerializableValue of the raw data (never expanded). The
        name matches case-insensitively, like Get-IgwtRegistryValue. Throws for a kind that cannot
        be restored. Read-only.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER Sid
        The user SID for HKCU keys ('' for HKLM).
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Name
        The value name ('' = the default value).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [AllowEmptyString()][AllowNull()][string]$Sid = '',
        [ValidateSet('64', '32')][string]$View = '64',
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name
    )
    $p = ([string]$Path).Trim('\')
    if ($Hive -eq 'HKLM') { $Sid = '' }
    $snap = [ordered]@{ exists = $false; kind = $null; value = $null; view = $View; sid = [string]$Sid; hive = $Hive; path = $p; name = $Name }
    $k = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path $p -Sid $Sid
    if ($null -eq $k) { return $snap }
    foreach ($n in @($k.Values.Keys)) {
        if (-not [string]::Equals([string]$n, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $d = Get-IgwtRegCleanSnapshotData -Raw $k.Values[$n] -Kind ([string]$k.Kinds[$n])
        $snap.exists = $true
        $snap.kind = $d.Kind
        $snap.value = $d.Data
        $snap.name = [string]$n
        break
    }
    return $snap
}

#endregion

#region .reg text (RG18, pure)

function ConvertTo-IgwtRegFileKeyName {
    <#
    .SYNOPSIS
        The [key] name a .reg file uses for a cleaner key: HKEY_LOCAL_MACHINE\..., with the physical
        SOFTWARE\WOW6432Node path for a 32-bit view key, or HKEY_USERS\<sid>\... for HKCU, so an
        import can never land in another user's hive. Throws for a name a .reg file cannot hold.
        Pure.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER Sid
        The user SID (HKCU).
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Hive, [AllowEmptyString()][AllowNull()][string]$Sid = '', [AllowEmptyString()][string]$View = '64', [Parameter(Mandatory = $true)][string]$Path)
    $p = ([string]$Path).Trim('\')
    if ($p -match '[\x00-\x1F]') { throw "The key '$p' has a name that a .reg file cannot hold." }
    switch ($Hive) {
        'HKLM' {
            if ($View -eq '32' -and $p -match '^(?i)SOFTWARE(\\|$)' -and $p -notmatch '^(?i)SOFTWARE\\WOW6432Node(\\|$)') { $p = 'SOFTWARE\WOW6432Node' + $p.Substring(8) }
            return ('HKEY_LOCAL_MACHINE\' + $p)
        }
        'HKCU' {
            if ([string]$Sid -notmatch '^S-1-[0-9-]+$') { throw 'An HKCU key needs the SID of the user whose hive was read.' }
            return ('HKEY_USERS\' + $Sid + '\' + $p)
        }
        default { throw "Unknown hive '$Hive'." }
    }
}

function ConvertTo-IgwtRegFileString {
    <#
    .SYNOPSIS
        A quoted .reg string: backslash and double quote escaped. Pure.
    .PARAMETER Text
        The text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Text)
    return ('"' + ([string]$Text).Replace('\', '\\').Replace('"', '\"') + '"')
}

function ConvertTo-IgwtRegFileHex {
    <#
    .SYNOPSIS
        '<prefix>xx,xx,...' with regedit-style continuation lines (',\' and two spaces) once a line
        reaches 77 characters. Pure.
    .PARAMETER Prefix
        The '"name"=hex(n):' part.
    .PARAMETER Bytes
        The data.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Prefix, [AllowNull()][byte[]]$Bytes)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append($Prefix)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $sb.ToString() }
    $lineLen = $Prefix.Length
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        $null = $sb.Append($Bytes[$i].ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture))
        if ($i -eq $Bytes.Length - 1) { break }
        $null = $sb.Append(',')
        $lineLen += 3
        if ($lineLen -ge $script:IgwtRegFileHexWidth) { $null = $sb.Append("\`r`n  "); $lineLen = 2 }
    }
    return $sb.ToString()
}

function ConvertTo-IgwtRegFileValueLine {
    <#
    .SYNOPSIS
        One '"name"=data' line of a .reg file from snapshot data: string, dword:, hex: (binary),
        hex(2): (ExpandString), hex(7): (MultiString), hex(b): (QWORD), hex(0): (REG_NONE). A string
        with a control character is written as hex(1): so the line stays one value. '' is '@'.
        Pure.
    .PARAMETER Name
        The value name.
    .PARAMETER Kind
        The RegistryValueKind name.
    .PARAMETER Data
        The snapshot data (ConvertTo-IgwtSerializableValue form).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Name, [Parameter(Mandatory = $true)][string]$Kind, [AllowNull()]$Data)
    if ($Name -match '[\x00-\x1F]') { throw "The value name '$Name' cannot be written to a .reg file." }
    $lead = $(if ($Name -eq '') { '@=' } else { (ConvertTo-IgwtRegFileString -Text $Name) + '=' })
    $utf16 = { param($s) [System.Text.Encoding]::Unicode.GetBytes([string]$s + [char]0) }
    switch ($Kind) {
        'String' {
            $s = [string]$Data
            if ($s -match '[\x00-\x1F]') { return (ConvertTo-IgwtRegFileHex -Prefix ($lead + 'hex(1):') -Bytes (& $utf16 $s)) }
            return ($lead + (ConvertTo-IgwtRegFileString -Text $s))
        }
        'ExpandString' { return (ConvertTo-IgwtRegFileHex -Prefix ($lead + 'hex(2):') -Bytes (& $utf16 $Data)) }
        'MultiString' {
            $ms = New-Object System.Collections.Generic.List[byte]
            foreach ($s in @($Data)) { $ms.AddRange([byte[]](& $utf16 $s)) }
            $ms.AddRange([byte[]]@(0, 0))
            return (ConvertTo-IgwtRegFileHex -Prefix ($lead + 'hex(7):') -Bytes $ms.ToArray())
        }
        'DWord' { return ($lead + 'dword:' + ([uint32](ConvertTo-IgwtUInt64 $Data)).ToString('x8', [System.Globalization.CultureInfo]::InvariantCulture)) }
        'QWord' { return (ConvertTo-IgwtRegFileHex -Prefix ($lead + 'hex(b):') -Bytes ([BitConverter]::GetBytes([uint64](ConvertTo-IgwtUInt64 ([string]$Data))))) }
        'Binary' { return (ConvertTo-IgwtRegFileHex -Prefix ($lead + 'hex:') -Bytes (ConvertTo-IgwtByteArray ([string]$Data))) }
        'None' { return (ConvertTo-IgwtRegFileHex -Prefix ($lead + 'hex(0):') -Bytes (ConvertTo-IgwtByteArray ([string]$Data))) }
        default { throw "A value of kind '$Kind' cannot be written to a .reg file." }
    }
}

function ConvertTo-IgwtRegFileText {
    <#
    .SYNOPSIS
        The text of selected.reg from cleaner snapshots (RG18): the header 'Windows Registry Editor
        Version 5.00', then one [key] block per key with its '"name"=value' lines, CRLF line ends.
        Pure; the caller writes it as UTF-16LE with a BOM.
    .DESCRIPTION
        Key-tree snapshots (kind 'keyTree') give one block per key in their ordinal key order;
        value snapshots give a block with the one value. Snapshots with exists $false are skipped.
        HKLM 32-bit keys use the physical WOW6432Node path, HKCU keys HKEY_USERS\<sid>. The format
        follows https://support.microsoft.com/en-us/help/310516 (not on Learn; UNVERIFIED, RG28).
    .PARAMETER Snapshots
        Get-IgwtRegCleanKeySnapshot and Get-IgwtRegCleanValueSnapshot results (dictionaries or the
        same data read back from JSON).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Snapshots = @())
    $nl = "`r`n"
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append($script:IgwtRegFileHeader).Append($nl).Append($nl)
    foreach ($s in @($Snapshots)) {
        if ($null -eq $s) { continue }
        $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $o.$n } }
        if (-not (& $get $s 'exists')) { continue }
        $hive = [string](& $get $s 'hive'); $sid = [string](& $get $s 'sid'); $view = [string](& $get $s 'view'); $path = [string](& $get $s 'path')
        if ([string](& $get $s 'kind') -eq 'keyTree') {
            $byKey = @{}
            foreach ($v in @(& $get $s 'valueList')) {
                $kk = [string](& $get $v 'key')
                if (-not $byKey.ContainsKey($kk)) { $byKey[$kk] = New-Object System.Collections.Generic.List[object] }
                $byKey[$kk].Add($v)
            }
            foreach ($rel in @(& $get $s 'keyList')) {
                $full = $(if ([string]$rel) { $path + '\' + $rel } else { $path })
                $null = $sb.Append('[').Append((ConvertTo-IgwtRegFileKeyName -Hive $hive -Sid $sid -View $view -Path $full)).Append(']').Append($nl)
                if ($byKey.ContainsKey([string]$rel)) {
                    foreach ($v in $byKey[[string]$rel]) { $null = $sb.Append((ConvertTo-IgwtRegFileValueLine -Name ([string](& $get $v 'name')) -Kind ([string](& $get $v 'kind')) -Data (& $get $v 'data'))).Append($nl) }
                }
                $null = $sb.Append($nl)
            }
        } else {
            $null = $sb.Append('[').Append((ConvertTo-IgwtRegFileKeyName -Hive $hive -Sid $sid -View $view -Path $path)).Append(']').Append($nl)
            $null = $sb.Append((ConvertTo-IgwtRegFileValueLine -Name ([string](& $get $s 'name')) -Kind ([string](& $get $s 'kind')) -Data (& $get $s 'value'))).Append($nl).Append($nl)
        }
    }
    return $sb.ToString()
}

#endregion

#region Backup folder files (RG18, pure)

function Get-IgwtRegCleanBackupFolderName {
    <#
    .SYNOPSIS
        The name of a cleanup's backup folder: regclean-<yyyyMMdd-HHmmss>-<6 hex>. Pure apart from
        the random suffix.
    .PARAMETER Now
        The time to use (default: now).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([datetime]$Now = (Get-Date))
    return ('regclean-{0}-{1}' -f $Now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture), [guid]::NewGuid().ToString('N').Substring(0, 6))
}

function ConvertTo-IgwtRegCleanFirewallRulesJson {
    <#
    .SYNOPSIS
        The text of firewall-rules.json (RG18): {schemaVersion 1; rules: the
        Get-IgwtFirewallRuleDefinition rows of the selected rules, in the given order}. Throws for a
        row without a rule name. Pure.
    .PARAMETER Definitions
        Get-IgwtFirewallRuleDefinition results.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Definitions = @())
    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Definitions)) {
        if ($null -eq $d) { continue }
        $n = $(if ($d -is [System.Collections.IDictionary]) { [string]$d['name'] } else { [string]$d.name })
        if (-not $n) { throw 'A firewall rule definition without a rule name cannot be backed up.' }
        $rules.Add($d)
    }
    return (ConvertTo-IgwtJson -InputObject ([ordered]@{ schemaVersion = 1; rules = $rules.ToArray() }))
}

function ConvertTo-IgwtRegCleanManifest {
    <#
    .SYNOPSIS
        The text of manifest.json (RG18): {schemaVersion 1; tool; version; generated; scanId;
        folder; files [{name; sha256}] by name; targets [{id; category; kind; hive; sid; view; path;
        valueName; ruleName; includes; firewallSnapshot; security}]}. Owner and SDDL per key are
        information only. Pure.
    .PARAMETER Folder
        The backup folder name.
    .PARAMETER ScanId
        The scan id of the plan.
    .PARAMETER Generated
        The time stamp text (ISO 8601).
    .PARAMETER Targets
        The plan targets (findings: Id, Category, Kind, Hive, Sid, View, Path, ValueName, RuleName,
        Includes).
    .PARAMETER Files
        File name -> SHA256 hex.
    .PARAMETER Security
        Target id -> Get-IgwtRegCleanTreeSecurity rows.
    .PARAMETER FirewallSnapshots
        Rule name -> the path of the firewall snapshot (filled after its step).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Folder,
        [AllowEmptyString()][string]$ScanId = '',
        [AllowEmptyString()][string]$Generated = '',
        [AllowEmptyCollection()][object[]]$Targets = @(),
        [System.Collections.IDictionary]$Files = @{},
        [System.Collections.IDictionary]$Security = @{},
        [System.Collections.IDictionary]$FirewallSnapshots = @{}
    )
    $names = [string[]]@($Files.Keys | ForEach-Object { [string]$_ })
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $fileRows = @(foreach ($n in $names) { [ordered]@{ name = $n; sha256 = ([string]$Files[$n]).ToUpperInvariant() } })
    $str = { param($o, $n) if ($null -ne $o -and $o.PSObject.Properties[$n]) { [string]$o.$n } else { '' } }
    $targetRows = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Targets)) {
        if ($null -eq $t) { continue }
        $id = & $str $t 'Id'
        if (-not $id) { throw 'A manifest target needs its finding id.' }
        $rule = & $str $t 'RuleName'
        $inc = @()
        if ($t.PSObject.Properties['Includes'] -and $null -ne $t.Includes) { $inc = [string[]]@($t.Includes | ForEach-Object { [string]$_ }) }
        $targetRows.Add([ordered]@{
                id = $id; category = (& $str $t 'Category'); kind = (& $str $t 'Kind'); hive = (& $str $t 'Hive'); sid = (& $str $t 'Sid'); view = (& $str $t 'View')
                path = (& $str $t 'Path'); valueName = (& $str $t 'ValueName'); ruleName = $rule; includes = $inc
                firewallSnapshot = $(if ($rule -and $FirewallSnapshots.Contains($rule)) { [string]$FirewallSnapshots[$rule] } else { '' })
                security = @($(if ($Security.Contains($id)) { $Security[$id] }))
            })
    }
    $doc = [ordered]@{
        schemaVersion = 1; tool = 'iG Windows Tuner'; version = [string]$script:IgwtVersion; generated = $Generated; scanId = $ScanId; folder = $Folder
        files = $fileRows; targets = $targetRows.ToArray()
    }
    return (ConvertTo-IgwtJson -InputObject $doc)
}

#endregion
