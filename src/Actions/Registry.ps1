# Registry.ps1
# Type-exact registry primitives (.NET Microsoft.Win32 API, no reg.exe) and the 'registry' action.
#
# Snapshot fidelity: every captured value records whether it existed, its exact REG type and
# data, whether its key existed and how many parent keys were missing, so a revert can put
# back "value did not exist" and remove keys that iG Windows Tuner created.

$script:IgwtAbsent = '<absent>'

#region Path resolution

function Resolve-IgwtRegistryPath {
    <#
    .SYNOPSIS
        Applies the interactive-user hive mapping and the test redirection to a registry path.
        In TestMode every path must end up inside the Pester TestRegistry: drive.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $p = $Path
    if ($script:IgwtSettings.UserHiveSid -and $p -match '^(HKCU:|HKEY_CURRENT_USER)(\\|$)') {
        $rest = $p -replace '^(HKCU:|HKEY_CURRENT_USER)\\?', ''
        $p = "Registry::HKEY_USERS\$($script:IgwtSettings.UserHiveSid)\$rest"
    }
    $redirect = $script:IgwtSettings.RegistryRedirect
    if ($redirect) {
        foreach ($prefix in $redirect.Keys) {
            if ($p.StartsWith([string]$prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $p = [string]$redirect[$prefix] + $p.Substring(([string]$prefix).Length)
                break
            }
        }
    }
    if ($script:IgwtSettings.TestMode -and -not $p.StartsWith('TestRegistry:', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "TestMode safety: registry path '$Path' does not resolve into TestRegistry:."
    }
    return $p
}

function ConvertTo-IgwtRegistryLocation {
    <# .SYNOPSIS Converts a resolved PowerShell registry path into hive + subkey for the .NET API. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ResolvedPath)
    $native = $null
    if ($ResolvedPath -match '^Registry::(.+)$') {
        $native = $Matches[1]
    } elseif ($ResolvedPath -match '^(HKEY_[A-Z_]+)(\\.*)?$') {
        $native = $ResolvedPath
    } elseif ($ResolvedPath -match '^([A-Za-z][A-Za-z0-9_]*):\\?(.*)$') {
        $driveName = $Matches[1]
        $rest = $Matches[2]
        $drive = Get-PSDrive -Name $driveName -PSProvider Registry -ErrorAction Stop
        $root = $drive.Root.TrimEnd('\')
        if ($rest) { $native = "$root\$rest" } else { $native = $root }
    } else {
        throw "Unsupported registry path '$ResolvedPath'."
    }
    $native = $native.TrimEnd('\')
    $parts = $native.Split([char[]]@('\'), 2)
    switch ($parts[0].ToUpperInvariant()) {
        'HKEY_LOCAL_MACHINE' { $hive = [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKEY_CURRENT_USER'  { $hive = [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKEY_USERS'         { $hive = [Microsoft.Win32.RegistryHive]::Users }
        'HKEY_CLASSES_ROOT'  { $hive = [Microsoft.Win32.RegistryHive]::ClassesRoot }
        default { throw "Unsupported registry hive '$($parts[0])'." }
    }
    $sub = ''
    if ($parts.Count -gt 1) { $sub = $parts[1] }
    [pscustomobject]@{ Hive = $hive; SubKey = $sub; Native = $native }
}

function Open-IgwtRegistryBaseKey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryHive]$Hive)
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, [Microsoft.Win32.RegistryView]::Registry64)
}

#endregion

#region Value conversion

function ConvertTo-IgwtUInt64 {
    <# .SYNOPSIS Converts JSON numbers, hex strings ("0xFFFFFFFF") and negative Int32 values to UInt64. #>
    [CmdletBinding()]
    [OutputType([uint64])]
    param([Parameter(Mandatory = $true)]$Value)
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if ($s -match '^0x([0-9a-fA-F]+)$') { return [Convert]::ToUInt64($Matches[1], 16) }
        if ($s -match '^-\d+$') { $Value = [int64]$s }
        else { return [uint64]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture) }
    }
    if ($Value -is [uint64] -or $Value -is [uint32]) { return [uint64]$Value }
    if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return [uint64]$Value }
    $i = [int64]$Value
    if ($i -lt 0) {
        if ($i -ge [int32]::MinValue) { return [uint64][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$i), 0) }
        return [BitConverter]::ToUInt64([BitConverter]::GetBytes($i), 0)
    }
    return [uint64]$i
}

function ConvertTo-IgwtByteArray {
    <# .SYNOPSIS Bytes from a byte array, an integer list or a hex string ("0A1BFF", spaces allowed). #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return , ([byte[]]@()) }
    if ($Value -is [byte[]]) { return , $Value }
    if ($Value -is [string]) {
        $hex = ($Value -replace '\s', '')
        if ($hex.Length % 2 -ne 0 -or $hex -notmatch '^[0-9a-fA-F]*$') { throw "Invalid hex data '$Value'." }
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        return , $bytes
    }
    return , ([byte[]]@($Value | ForEach-Object { [byte]$_ }))
}

function ConvertTo-IgwtHexString {
    <# .SYNOPSIS Hex text for binary registry data in snapshots (readable, no encoding of code). #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)
    return ((ConvertTo-IgwtByteArray $Value) | ForEach-Object { '{0:X2}' -f $_ }) -join ''
}

function ConvertFrom-IgwtRawRegistryValue {
    <# .SYNOPSIS Normalizes a raw .NET registry value (DWORD -> UInt32, QWORD -> UInt64). #>
    [CmdletBinding()]
    param($Raw, [Parameter(Mandatory = $true)][string]$Kind)
    switch ($Kind) {
        'DWord'       { return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$Raw), 0) }
        'QWord'       { return [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$Raw), 0) }
        'MultiString' { return , ([string[]]@($Raw)) }
        'Binary'      { return , (ConvertTo-IgwtByteArray $Raw) }
        'None'        { return , (ConvertTo-IgwtByteArray $Raw) }
        'Unknown'     { return , (ConvertTo-IgwtByteArray $Raw) }
        default       { return [string]$Raw }
    }
}

function ConvertTo-IgwtRawRegistryValue {
    <# .SYNOPSIS Converts a normalized or JSON value into what RegistryKey.SetValue expects for the kind. #>
    [CmdletBinding()]
    param($Value, [Parameter(Mandatory = $true)][string]$Kind)
    switch ($Kind) {
        'DWord' {
            $u = ConvertTo-IgwtUInt64 $Value
            if ($u -gt [uint32]::MaxValue) { throw "Value $u does not fit in a DWORD." }
            return [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$u), 0)
        }
        'QWord' {
            $u = ConvertTo-IgwtUInt64 $Value
            return [BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]$u), 0)
        }
        'MultiString' { return , ([string[]]@($Value | ForEach-Object { [string]$_ })) }
        'Binary'      { return , (ConvertTo-IgwtByteArray $Value) }
        'None'        { return , (ConvertTo-IgwtByteArray $Value) }
        'String'      { return [string]$Value }
        'ExpandString' { return [string]$Value }
        default { throw "Unsupported registry value kind '$Kind'." }
    }
}

function ConvertTo-IgwtSerializableValue {
    <# .SYNOPSIS JSON-safe form: QWORD as decimal string, binary as hex text. #>
    [CmdletBinding()]
    param($Value, [string]$Kind)
    if ($null -eq $Value) { return $null }
    switch ($Kind) {
        'DWord'       { return [int64](ConvertTo-IgwtUInt64 $Value) }
        'QWord'       { return ([uint64](ConvertTo-IgwtUInt64 $Value)).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        'Binary'      { return (ConvertTo-IgwtHexString $Value) }
        'None'        { return (ConvertTo-IgwtHexString $Value) }
        'Unknown'     { return (ConvertTo-IgwtHexString $Value) }
        'MultiString' { return , ([string[]]@($Value)) }
        default       { return [string]$Value }
    }
}

function ConvertFrom-IgwtSerializableValue {
    [CmdletBinding()]
    param($Data, [string]$Kind)
    if ($null -eq $Data) { return $null }
    switch ($Kind) {
        'DWord'       { return [uint32](ConvertTo-IgwtUInt64 $Data) }
        'QWord'       { return [uint64](ConvertTo-IgwtUInt64 ([string]$Data)) }
        'Binary'      { return , (ConvertTo-IgwtByteArray ([string]$Data)) }
        'None'        { return , (ConvertTo-IgwtByteArray ([string]$Data)) }
        'Unknown'     { return , (ConvertTo-IgwtByteArray ([string]$Data)) }
        'MultiString' { return , ([string[]]@($Data)) }
        default       { return [string]$Data }
    }
}

function Test-IgwtRegistryValueEqual {
    <# .SYNOPSIS Compares two values of the same kind (numbers numerically, strings case-insensitively). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Left, $Right, [Parameter(Mandatory = $true)][string]$Kind)
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    switch ($Kind) {
        { $_ -in 'DWord', 'QWord' } {
            try { return ((ConvertTo-IgwtUInt64 $Left) -eq (ConvertTo-IgwtUInt64 $Right)) } catch { return $false }
        }
        'MultiString' {
            $l = @($Left); $r = @($Right)
            if ($l.Count -ne $r.Count) { return $false }
            for ($i = 0; $i -lt $l.Count; $i++) { if ([string]$l[$i] -ne [string]$r[$i]) { return $false } }
            return $true
        }
        { $_ -in 'Binary', 'None', 'Unknown' } {
            return ((ConvertTo-IgwtHexString $Left) -eq (ConvertTo-IgwtHexString $Right))
        }
        default { return ([string]$Left -eq [string]$Right) }
    }
}

function Format-IgwtRegistryValue {
    <# .SYNOPSIS Short display form, e.g. 0 (DWORD), "Warn" (REG_SZ), <absent>. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([bool]$Exists = $true, $Value, [string]$Kind)
    if (-not $Exists) { return $script:IgwtAbsent }
    switch ($Kind) {
        'DWord' {
            $u = ConvertTo-IgwtUInt64 $Value
            if ($u -gt 9) { return ('{0} (0x{0:X}) DWORD' -f $u) }
            return "$u DWORD"
        }
        'QWord' { return "$(ConvertTo-IgwtUInt64 $Value) QWORD" }
        'String' { return ('"{0}" SZ' -f $Value) }
        'ExpandString' { return ('"{0}" EXPAND_SZ' -f $Value) }
        'MultiString' { return ('[{0}] MULTI_SZ' -f (@($Value) -join ', ')) }
        default {
            $bytes = ConvertTo-IgwtByteArray $Value
            $hex = ($bytes | Select-Object -First 12 | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
            if ($bytes.Count -gt 12) { $hex += ' ...' }
            return "$hex $($Kind.ToUpperInvariant())"
        }
    }
}

#endregion

#region Primitive operations

function Test-IgwtRegistryKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        $key = $base.OpenSubKey($loc.SubKey, $false)
        if ($key) { $key.Dispose(); return $true }
        return $false
    } finally { $base.Dispose() }
}

function Get-IgwtRegistryValue {
    <#
    .SYNOPSIS
        Reads one value. Returns Exists, KeyExists, Kind and the normalized Value.
        Environment variables in REG_EXPAND_SZ are not expanded (exact data is preserved).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name
    )
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        $key = $base.OpenSubKey($loc.SubKey, $false)
        if (-not $key) { return [pscustomobject]@{ Exists = $false; KeyExists = $false; Kind = $null; Value = $null } }
        try {
            $names = $key.GetValueNames()
            $found = $false
            foreach ($n in $names) { if ([string]::Equals($n, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { $found = $true; break } }
            if (-not $found) { return [pscustomobject]@{ Exists = $false; KeyExists = $true; Kind = $null; Value = $null } }
            $kind = $key.GetValueKind($Name).ToString()
            $raw = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $value = ConvertFrom-IgwtRawRegistryValue -Raw $raw -Kind $kind
            return [pscustomobject]@{ Exists = $true; KeyExists = $true; Kind = $kind; Value = $value }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Set-IgwtRegistryValue {
    <# .SYNOPSIS Creates the key if needed and writes the value with the exact kind. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)][string]$Kind,
        [AllowNull()]$Value
    )
    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set $Kind")) { return }
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $raw = ConvertTo-IgwtRawRegistryValue -Value $Value -Kind $Kind
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        $key = $base.CreateSubKey($loc.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        if (-not $key) { throw "Could not open or create registry key '$Path'." }
        try { $key.SetValue($Name, $raw, [Microsoft.Win32.RegistryValueKind]$Kind) } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Remove-IgwtRegistryValue {
    <# .SYNOPSIS Deletes a value if present (missing key or value is not an error). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name
    )
    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", 'Delete value')) { return }
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        $key = $base.OpenSubKey($loc.SubKey, $true)
        if ($key) { try { $key.DeleteValue($Name, $false) } finally { $key.Dispose() } }
    } finally { $base.Dispose() }
}

function Get-IgwtRegistryMissingDepth {
    <#
    .SYNOPSIS
        Number of trailing key segments of Path that do not exist yet (0 = key exists).
        Recorded in snapshots so a revert can remove keys created by iG Windows Tuner.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $segments = @($loc.SubKey.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries))
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        for ($i = $segments.Count; $i -ge 1; $i--) {
            $sub = ($segments[0..($i - 1)] -join '\')
            $key = $base.OpenSubKey($sub, $false)
            if ($key) { $key.Dispose(); return ($segments.Count - $i) }
        }
        return $segments.Count
    } finally { $base.Dispose() }
}

function Test-IgwtRegistryTreeEmpty {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$Key)
    if ($Key.ValueCount -gt 0) { return $false }
    foreach ($name in $Key.GetSubKeyNames()) {
        $child = $Key.OpenSubKey($name, $false)
        if ($child) {
            try { if (-not (Test-IgwtRegistryTreeEmpty -Key $child)) { return $false } } finally { $child.Dispose() }
        }
    }
    return $true
}

function Remove-IgwtCreatedRegistryKey {
    <#
    .SYNOPSIS
        Removes the top-most key that iG Windows Tuner created for Path (MissingDepth segments up),
        but only when that whole tree holds no values. Pre-existing keys are never removed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$MissingDepth
    )
    if ($MissingDepth -le 0) { return }
    $loc = ConvertTo-IgwtRegistryLocation (Resolve-IgwtRegistryPath $Path)
    $segments = @($loc.SubKey.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($MissingDepth -ge $segments.Count) { return }   # never delete a hive-level key
    $createdTop = ($segments[0..($segments.Count - $MissingDepth)] -join '\')
    $parent = ''
    if ($segments.Count - $MissingDepth - 1 -ge 0) { $parent = ($segments[0..($segments.Count - $MissingDepth - 1)] -join '\') }
    $leafName = $segments[$segments.Count - $MissingDepth]
    $base = Open-IgwtRegistryBaseKey $loc.Hive
    try {
        $top = $base.OpenSubKey($createdTop, $false)
        if (-not $top) { return }
        $empty = $false
        try { $empty = Test-IgwtRegistryTreeEmpty -Key $top } finally { $top.Dispose() }
        if (-not $empty) { return }
        if (-not $PSCmdlet.ShouldProcess($createdTop, 'Delete empty key created by iG Windows Tuner')) { return }
        if ($parent) {
            $pk = $base.OpenSubKey($parent, $true)
            if ($pk) { try { $pk.DeleteSubKeyTree($leafName, $false) } finally { $pk.Dispose() } }
        } else {
            $base.DeleteSubKeyTree($leafName, $false)
        }
    } finally { $base.Dispose() }
}

#endregion

#region 'registry' action

function Get-IgwtRegistryDesired {
    <#
    .SYNOPSIS
        Computes the target value for a registry action given the current value.
        Supports "<absent>" targets and "bitClear" (clear flag bits in a numeric string or DWORD).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Current, [string]$Mode = 'on')
    $target = $Action.on
    if ($Mode -eq 'default') { $target = $Action.default }
    if ([string]$target -eq $script:IgwtAbsent) {
        return [pscustomobject]@{ Absent = $true; Kind = $null; Value = $null }
    }
    $kind = [string]$Action.valueType
    if ($Mode -eq 'on' -and $null -ne $Action.bitClear) {
        $base = $null
        if ($Current.Exists) { $base = $Current.Value }
        elseif ($null -ne $Action.default -and [string]$Action.default -ne $script:IgwtAbsent) { $base = $Action.default }
        else { $base = 0 }
        $num = ConvertTo-IgwtUInt64 ([string]$base)
        $mask = ConvertTo-IgwtUInt64 $Action.bitClear
        $newNum = $num -band (-bnot $mask)
        if ($kind -eq 'String') { $target = [string]$newNum } else { $target = $newNum }
    }
    return [pscustomobject]@{ Absent = $false; Kind = $kind; Value = (ConvertFrom-IgwtSerializableValue -Data $target -Kind $kind) }
}

function Test-IgwtRegistryOn {
    <# .SYNOPSIS True when the current value satisfies the action's target. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Current)
    if ($Action.onlyIfAbsent -and $Current.Exists) { return $true }
    if ($null -ne $Action.bitClear -and $Current.Exists) {
        try {
            $num = ConvertTo-IgwtUInt64 ([string]$Current.Value)
            return (($num -band (ConvertTo-IgwtUInt64 $Action.bitClear)) -eq 0)
        } catch { return $false }
    }
    $desired = Get-IgwtRegistryDesired -Action $Action -Current $Current
    if ($desired.Absent) {
        if (-not $Current.Exists) { return $true }
    } elseif ($Current.Exists) {
        if ($Current.Kind -eq $desired.Kind -and (Test-IgwtRegistryValueEqual -Left $Current.Value -Right $desired.Value -Kind $desired.Kind)) { return $true }
    } elseif ($null -ne $Action.absentValue) {
        # Windows treats a missing value as absentValue.
        if ($null -ne $Action.bitClear) {
            return (((ConvertTo-IgwtUInt64 ([string]$Action.absentValue)) -band (ConvertTo-IgwtUInt64 $Action.bitClear)) -eq 0)
        }
        if (Test-IgwtRegistryValueEqual -Left (ConvertFrom-IgwtSerializableValue -Data $Action.absentValue -Kind $desired.Kind) -Right $desired.Value -Kind $desired.Kind) { return $true }
    }
    if ($Current.Exists -and $null -ne $Action.equivalentOn) {
        foreach ($eq in @($Action.equivalentOn)) {
            if (Test-IgwtRegistryValueEqual -Left $Current.Value -Right (ConvertFrom-IgwtSerializableValue -Data $eq -Kind $Current.Kind) -Kind $Current.Kind) { return $true }
        }
    }
    return $false
}

function Get-IgwtRegistryTargets {
    <#
    .SYNOPSIS
        Concrete (path, name) targets of a registry-like action. Plain registry actions have one;
        adapter-scoped actions get one per active wired adapter with {InterfaceGuid} and
        {AdapterClassKey} tokens expanded.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    if ($Action.type -in 'adapterRegistry', 'netAdapterPower') {
        $path = [string]$Action.path
        $name = [string]$Action.name
        if ($Action.type -eq 'netAdapterPower') { $path = '{AdapterClassKey}'; $name = 'PnPCapabilities' }
        $adapters = @()
        if ($Context -and $null -ne $Context.WiredAdapters) { $adapters = @($Context.WiredAdapters) } else { $adapters = @(Get-IgwtActiveWiredAdapter) }
        $targets = foreach ($a in $adapters) {
            $p = $path.Replace('{InterfaceGuid}', [string]$a.InterfaceGuid)
            if ($p.Contains('{AdapterClassKey}')) {
                $classKey = Get-IgwtAdapterClassKey -InterfaceGuid $a.InterfaceGuid
                if (-not $classKey) { continue }
                $p = $p.Replace('{AdapterClassKey}', $classKey)
            }
            [pscustomobject]@{ Path = $p; Name = $name; Scope = [string]$a.InterfaceGuid; Label = [string]$a.Name }
        }
        return @($targets)
    }
    return @([pscustomobject]@{ Path = [string]$Action.path; Name = [string]$Action.name; Scope = ''; Label = '' })
}

function Get-IgwtRegistryActionEffective {
    <# .SYNOPSIS Returns the action with netAdapterPower translated to its registry form. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action)
    if ($Action.type -ne 'netAdapterPower') { return $Action }
    # PnPCapabilities 24 (0x18) clears "Allow the computer to turn off this device to save power";
    # 0 restores the default (documented by Microsoft, see catalog sources).
    $on = 24
    if ($Action.allowTurnOff) { $on = 0 }
    return [pscustomobject]@{ type = 'netAdapterPower'; valueType = 'DWord'; on = $on; default = 0; absentValue = 0;
        bitClear = $null; onlyIfAbsent = $false; equivalentOn = $null }
}

function Get-IgwtRegistryState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $eff = Get-IgwtRegistryActionEffective $Action
    $targets = @(Get-IgwtRegistryTargets -Action $Action -Context $Context)
    if ($targets.Count -eq 0) {
        return @([pscustomobject]@{ Target = 'Active wired network adapter'; Current = 'none found'; Desired = ''; State = 'NotApplicable'; Note = 'No active physical wired adapter.' })
    }
    foreach ($t in $targets) {
        $cur = Get-IgwtRegistryValue -Path $t.Path -Name $t.Name
        $desired = Get-IgwtRegistryDesired -Action $eff -Current $cur
        $isOn = Test-IgwtRegistryOn -Action $eff -Current $cur
        $note = ''
        if ($cur.Exists -and -not $desired.Absent -and $cur.Kind -ne $desired.Kind -and -not $isOn) {
            $note = "Current type is $($cur.Kind); Windows expects $($desired.Kind). It will be rewritten with the correct type."
        }
        if (-not $cur.Exists -and $null -ne $eff.absentValue) { $note = "Not set; Windows uses $($eff.absentValue) when absent." }
        $label = "$($t.Path)\$($t.Name)"
        if ($t.Label) { $label = "[$($t.Label)] $label" }
        [pscustomobject]@{
            Target  = $label
            Current = (Format-IgwtRegistryValue -Exists $cur.Exists -Value $cur.Value -Kind $cur.Kind)
            Desired = $(if ($desired.Absent) { $script:IgwtAbsent } else { Format-IgwtRegistryValue -Exists $true -Value $desired.Value -Kind $desired.Kind })
            State   = $(if ($isOn) { 'On' } else { 'Off' })
            Note    = $note
        }
    }
}

function Get-IgwtRegistrySnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $targets = @(Get-IgwtRegistryTargets -Action $Action -Context $Context)
    $items = foreach ($t in $targets) {
        $cur = Get-IgwtRegistryValue -Path $t.Path -Name $t.Name
        [ordered]@{
            scope        = $t.Scope
            path         = $t.Path
            name         = $t.Name
            exists       = [bool]$cur.Exists
            kind         = $cur.Kind
            value        = (ConvertTo-IgwtSerializableValue -Value $cur.Value -Kind $cur.Kind)
            missingDepth = (Get-IgwtRegistryMissingDepth -Path $t.Path)
        }
    }
    return @{ items = @($items) }
}

function Invoke-IgwtRegistryApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $eff = Get-IgwtRegistryActionEffective $Action
    if ($Mode -eq 'default' -and $null -eq $eff.default) { throw "No documented Windows default for $($Action.path)\$($Action.name)." }
    foreach ($t in @(Get-IgwtRegistryTargets -Action $Action -Context $Context)) {
        $cur = Get-IgwtRegistryValue -Path $t.Path -Name $t.Name
        if ($Mode -eq 'on' -and (Test-IgwtRegistryOn -Action $eff -Current $cur)) { continue }
        $desired = Get-IgwtRegistryDesired -Action $eff -Current $cur -Mode $Mode
        if ($desired.Absent) {
            if ($PSCmdlet.ShouldProcess("$($t.Path)\$($t.Name)", 'Delete value')) { Remove-IgwtRegistryValue -Path $t.Path -Name $t.Name }
        } else {
            if ($PSCmdlet.ShouldProcess("$($t.Path)\$($t.Name)", "Set $($desired.Kind)")) {
                Set-IgwtRegistryValue -Path $t.Path -Name $t.Name -Kind $desired.Kind -Value $desired.Value
            }
        }
    }
}

function Restore-IgwtRegistryItem {
    <# .SYNOPSIS Restores one captured value exactly, including "did not exist" and created keys. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)]$Item)
    if ($Item.exists) {
        $value = ConvertFrom-IgwtSerializableValue -Data $Item.value -Kind ([string]$Item.kind)
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Restore $($Item.kind)")) {
            Set-IgwtRegistryValue -Path $Path -Name $Name -Kind ([string]$Item.kind) -Value $value
        }
    } else {
        if ($PSCmdlet.ShouldProcess("$Path\$Name", 'Restore (delete value that did not exist)')) {
            Remove-IgwtRegistryValue -Path $Path -Name $Name
            if ($null -ne $Item.missingDepth -and [int]$Item.missingDepth -gt 0) {
                Remove-IgwtCreatedRegistryKey -Path $Path -MissingDepth ([int]$Item.missingDepth)
            }
        }
    }
}

function Restore-IgwtRegistrySnapshot {
    <#
    .SYNOPSIS
        Restores captured values. Paths come from the catalog action (expanded per adapter scope),
        never from the snapshot file, so a modified snapshot cannot redirect writes elsewhere.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $targets = @(Get-IgwtRegistryTargets -Action $Action -Context $Context)
    foreach ($item in @($Snapshot.items)) {
        $target = $targets | Where-Object { $_.Scope -eq [string]$item.scope } | Select-Object -First 1
        if (-not $target) {
            if ($Action.type -in 'adapterRegistry', 'netAdapterPower') {
                Write-IgwtLog -Level Warn -Message "Adapter $($item.scope) is no longer present; its value was not restored."
                continue
            }
            $target = $targets[0]
        }
        if ($PSCmdlet.ShouldProcess("$($target.Path)\$($target.Name)", 'Restore')) {
            Restore-IgwtRegistryItem -Path $target.Path -Name $target.Name -Item $item
        }
    }
}

#endregion
