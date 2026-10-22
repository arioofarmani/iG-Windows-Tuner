# RegistryPol.ps1
# Registry.pol (PReg) reader and writer per [MS-GPREG] section 2.1: a 4-byte signature "PReg"
# (0x67655250), a 4-byte version (1) and a sequence of entries
#   [key;valuename;type;size;data]
# where the brackets and semicolons are UTF-16LE characters, key and value name are UTF-16LE
# strings with a terminating null, type and size are little-endian 32-bit integers and data is
# 'size' raw bytes. Every entry keeps its original bytes, so a file that is read and written
# without changes is identical byte for byte, and unknown entries are preserved exactly.
# Special value names (**del.<name>, **delvals., **DeleteValues, **DeleteKeys, **SecureKey,
# **soft.<name> and a key-only entry with an empty value name) are kept and understood.

$script:IgwtPolSignature = [uint32]0x67655250
$script:IgwtPolVersion = [uint32]1
$script:IgwtRegTypes = @{ 0 = 'None'; 1 = 'String'; 2 = 'ExpandString'; 3 = 'Binary'; 4 = 'DWord'; 5 = 'DWordBigEndian'; 7 = 'MultiString'; 11 = 'QWord' }

function Read-IgwtRegistryPol {
    <#
    .SYNOPSIS
        Parses a Registry.pol file (or bytes) into entries: Key, ValueName, Type, TypeName, Data
        (bytes), Value (decoded) and Raw (the entry's exact bytes). Throws with the offset when the
        file is not a valid PReg file.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param([Parameter(Mandatory = $true, ParameterSetName = 'Path')][string]$Path, [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')][AllowEmptyCollection()][byte[]]$Bytes)
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Exists = $false; Path = $Path; Entries = @() } }
        $Bytes = [System.IO.File]::ReadAllBytes($Path)
    }
    if ($Bytes.Length -lt 8) { throw "Registry.pol is corrupted: $($Bytes.Length) bytes is shorter than the 8-byte header." }
    if ([BitConverter]::ToUInt32($Bytes, 0) -ne $script:IgwtPolSignature) { throw 'Registry.pol is corrupted: the PReg signature is missing.' }
    $ver = [BitConverter]::ToUInt32($Bytes, 4)
    if ($ver -ne $script:IgwtPolVersion) { throw "Registry.pol has unsupported version $ver." }
    $entries = New-Object System.Collections.Generic.List[object]
    $i = 8
    $n = $Bytes.Length
    while ($i -lt $n) {
        $start = $i
        if ($i + 1 -ge $n -or $Bytes[$i] -ne 0x5B -or $Bytes[$i + 1] -ne 0) { throw "Registry.pol is corrupted at offset ${i}: expected '['." }
        $i += 2
        # key: UTF-16LE up to the ';' separator (each field ends with a null character before ';').
        $fields = @()
        for ($f = 0; $f -lt 2; $f++) {
            # The field ends at the first aligned ';' (3B 00) after a null character. The search
            # stays inline: passing the whole byte array to a function copies it on every call.
            $fs = $i
            $p = $fs; $i = -1
            while ($p -lt $n) {
                $p = [Array]::IndexOf($Bytes, [byte]0x3B, $p)
                if ($p -lt 0 -or $p + 1 -ge $n) { break }
                if ((($p - $fs) % 2) -eq 0 -and $Bytes[$p + 1] -eq 0 -and $p -ge $fs + 2 -and $Bytes[$p - 2] -eq 0 -and $Bytes[$p - 1] -eq 0) { $i = $p; break }
                $p++
            }
            if ($i -lt 0) { throw "Registry.pol is corrupted at offset ${fs}: unterminated string." }
            $fields += , ([System.Text.Encoding]::Unicode.GetString($Bytes, $fs, $i - $fs).TrimEnd([char]0))
            $i += 2
        }
        if ($i + 10 -gt $n) { throw "Registry.pol is corrupted at offset ${i}: truncated type or size." }
        $type = [BitConverter]::ToUInt32($Bytes, $i); $i += 4
        if ($Bytes[$i] -ne 0x3B -or $Bytes[$i + 1] -ne 0) { throw "Registry.pol is corrupted at offset ${i}: expected ';' after the type." }
        $i += 2
        $size = [BitConverter]::ToUInt32($Bytes, $i); $i += 4
        if ($Bytes[$i] -ne 0x3B -or $Bytes[$i + 1] -ne 0) { throw "Registry.pol is corrupted at offset ${i}: expected ';' after the size." }
        $i += 2
        if ($i + $size + 2 -gt $n) { throw "Registry.pol is corrupted at offset ${i}: data of $size bytes runs past the end of the file." }
        $data = New-Object byte[] $size
        if ($size -gt 0) { [Array]::Copy($Bytes, $i, $data, 0, $size) }
        $i += [int]$size
        if ($Bytes[$i] -ne 0x5D -or $Bytes[$i + 1] -ne 0) { throw "Registry.pol is corrupted at offset ${i}: expected ']'." }
        $i += 2
        $raw = New-Object byte[] ($i - $start)
        [Array]::Copy($Bytes, $start, $raw, 0, $i - $start)
        $entries.Add((New-IgwtPolEntryObject -Key $fields[0] -ValueName $fields[1] -Type ([int]$type) -Data $data -Raw $raw))
    }
    return [pscustomobject]@{ Exists = $true; Path = $(if ($PSCmdlet.ParameterSetName -eq 'Path') { $Path } else { '' }); Entries = $entries.ToArray() }
}

function ConvertFrom-IgwtPolData {
    <# .SYNOPSIS Decodes entry data by registry type (string, multi-string, DWORD, QWORD, binary). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Type, [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Data)
    switch ($Type) {
        { $_ -in 1, 2 } { return ([System.Text.Encoding]::Unicode.GetString($Data)).TrimEnd([char]0) }
        7 { return @(([System.Text.Encoding]::Unicode.GetString($Data)).TrimEnd([char]0).Split([char]0) | Where-Object { $_ -ne '' }) }
        4 { if ($Data.Length -ge 4) { return [BitConverter]::ToUInt32($Data, 0) } else { return $null } }
        5 { if ($Data.Length -ge 4) { $b = [byte[]]$Data[0..3]; [Array]::Reverse($b); return [BitConverter]::ToUInt32($b, 0) } else { return $null } }
        11 { if ($Data.Length -ge 8) { return [BitConverter]::ToUInt64($Data, 0) } else { return $null } }
        default { return , $Data }
    }
}

function ConvertTo-IgwtPolData {
    <# .SYNOPSIS Encodes a value for a registry type as Registry.pol data bytes. #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory = $true)][int]$Type, [AllowNull()]$Value)
    switch ($Type) {
        # The comma keeps the byte array whole (an empty array would otherwise become $null).
        { $_ -in 1, 2 } { return , [System.Text.Encoding]::Unicode.GetBytes(([string]$Value) + [char]0) }
        7 { $s = ((@($Value) | ForEach-Object { [string]$_ }) -join [string][char]0) + [char]0 + [char]0; return , [System.Text.Encoding]::Unicode.GetBytes($s) }
        4 { return , [BitConverter]::GetBytes([uint32]$Value) }
        11 { return , [BitConverter]::GetBytes([uint64]$Value) }
        3 { return , [byte[]]@($Value) }
        0 { return , [byte[]]@() }
    }
    throw "Registry type $Type is not supported in Registry.pol entries."
}

function New-IgwtPolEntryObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Key, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ValueName, [Parameter(Mandatory = $true)][int]$Type,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Data, [byte[]]$Raw)
    $special = ''
    if ($ValueName -match '^\*\*(del\.|delvals\.|DeleteValues|DeleteKeys|SecureKey|soft\.)') { $special = $Matches[1].TrimEnd('.') }
    $typeName = 'Unknown'; if ($script:IgwtRegTypes.ContainsKey($Type)) { $typeName = $script:IgwtRegTypes[$Type] }
    [pscustomobject]@{ Key = $Key; ValueName = $ValueName; Type = $Type; TypeName = $typeName; Data = $Data; Value = (ConvertFrom-IgwtPolData -Type $Type -Data $Data); Special = $special; Raw = $Raw }
}

function ConvertTo-IgwtPolEntryBytes {
    <# .SYNOPSIS The exact bytes of one entry (its original bytes when it was read and not changed). #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory = $true)]$Entry)
    if ($Entry.Raw) { return [byte[]]$Entry.Raw }
    $ms = New-Object System.IO.MemoryStream
    $w = New-Object System.IO.BinaryWriter($ms)
    try {
        $sep = [System.Text.Encoding]::Unicode.GetBytes(';')
        $w.Write([System.Text.Encoding]::Unicode.GetBytes('['))
        $w.Write([System.Text.Encoding]::Unicode.GetBytes(([string]$Entry.Key) + [char]0)); $w.Write($sep)
        $w.Write([System.Text.Encoding]::Unicode.GetBytes(([string]$Entry.ValueName) + [char]0)); $w.Write($sep)
        $w.Write([uint32]$Entry.Type); $w.Write($sep)
        $data = [byte[]]@($Entry.Data)
        $w.Write([uint32]$data.Length); $w.Write($sep)
        if ($data.Length) { $w.Write($data) }
        $w.Write([System.Text.Encoding]::Unicode.GetBytes(']'))
        $w.Flush()
        return $ms.ToArray()
    } finally { $w.Dispose() }
}

function ConvertTo-IgwtRegistryPolBytes {
    <# .SYNOPSIS Serializes entries to Registry.pol bytes (header plus entries in order). #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
    $ms = New-Object System.IO.MemoryStream
    try {
        $hdr = [BitConverter]::GetBytes($script:IgwtPolSignature) + [BitConverter]::GetBytes($script:IgwtPolVersion)
        $ms.Write($hdr, 0, $hdr.Length)
        foreach ($e in $Entries) { $b = ConvertTo-IgwtPolEntryBytes -Entry $e; $ms.Write($b, 0, $b.Length) }
        return $ms.ToArray()
    } finally { $ms.Dispose() }
}

function Write-IgwtRegistryPol {
    <# .SYNOPSIS Writes entries to a Registry.pol file (atomically: temp file, then replace). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
    Assert-IgwtGpoPathAllowed -Path $Path
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write Registry.pol')) { return }
    $bytes = ConvertTo-IgwtRegistryPolBytes -Entries $Entries
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $tmp = "$Path.igwt-tmp"
    [System.IO.File]::WriteAllBytes($tmp, $bytes)
    # [NullString]::Value: PowerShell would pass $null to a string parameter as '' (an invalid backup path).
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [System.IO.File]::Move($tmp, $Path) }
}

function Set-IgwtPolEntry {
    <#
    .SYNOPSIS
        Returns entries with one value set (an existing entry for the same key and value name is
        replaced in place; matching **del. markers are removed). Pure: changes nothing on disk.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure function over an in-memory list.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ValueName,
        [Parameter(Mandatory = $true)][int]$Type, [AllowNull()]$Value)
    $new = New-IgwtPolEntryObject -Key $Key -ValueName $ValueName -Type $Type -Data (ConvertTo-IgwtPolData -Type $Type -Value $Value)
    $out = New-Object System.Collections.Generic.List[object]
    $placed = $false
    foreach ($e in $Entries) {
        $sameKey = [string]::Equals([string]$e.Key, $Key, [System.StringComparison]::OrdinalIgnoreCase)
        if ($sameKey -and [string]::Equals([string]$e.ValueName, $ValueName, [System.StringComparison]::OrdinalIgnoreCase)) { if (-not $placed) { $out.Add($new); $placed = $true }; continue }
        if ($sameKey -and [string]::Equals([string]$e.ValueName, "**del.$ValueName", [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $out.Add($e)
    }
    if (-not $placed) { $out.Add($new) }
    return $out.ToArray()
}

function Remove-IgwtPolEntry {
    <# .SYNOPSIS Returns entries without the value (and its **del. marker): the policy value becomes "not configured". Pure. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure function over an in-memory list.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ValueName)
    return @($Entries | Where-Object {
            -not ([string]::Equals([string]$_.Key, $Key, [System.StringComparison]::OrdinalIgnoreCase) -and
                ([string]::Equals([string]$_.ValueName, $ValueName, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals([string]$_.ValueName, "**del.$ValueName", [System.StringComparison]::OrdinalIgnoreCase)))
        })
}

function Add-IgwtPolDeleteMarker {
    <# .SYNOPSIS Returns entries with a **del.<name> marker (the value is deleted when policy applies), replacing a value entry of that name. Pure. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure function over an in-memory list.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries, [Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][string]$ValueName)
    $rest = @(Remove-IgwtPolEntry -Entries $Entries -Key $Key -ValueName $ValueName)
    $marker = New-IgwtPolEntryObject -Key $Key -ValueName "**del.$ValueName" -Type 1 -Data ([System.Text.Encoding]::Unicode.GetBytes(' ' + [char]0))
    return @($rest + $marker)
}
