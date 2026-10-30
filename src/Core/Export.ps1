# Export.ps1
# Shared helpers for files the user exports. Exported values can come from untrusted sources
# (firewall log fields come from the network): a spreadsheet would run a cell that starts with
# = + - @ (or a tab or carriage return) as a formula, so CSV cells get a leading apostrophe.

function Protect-IgwtCsvValue {
    <#
    .SYNOPSIS
        One CSV cell made safe against formula injection: a value that starts with = + - @, a tab or
        a carriage return gets a leading apostrophe (the spreadsheet then shows it as text). Pure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()]$Value)
    if ($null -eq $Value) { return '' }
    $s = $(if ($Value -is [datetime]) { $Value.ToString('o') } else { [string]$Value })
    if ($s.Length -gt 0 -and '=+-@'.IndexOf($s[0]) -ge 0) { return "'" + $s }
    if ($s.Length -gt 0 -and ($s[0] -eq "`t" -or $s[0] -eq "`r")) { return "'" + $s }
    return $s
}

function ConvertTo-IgwtSafeCsv {
    <#
    .SYNOPSIS
        CSV lines (header first) for rows, with every cell protected by Protect-IgwtCsvValue and
        quoted. -Properties picks and orders the columns (default: the first row's properties). Pure.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyCollection()][object[]]$Rows = @(), [string[]]$Properties)
    if (-not $Properties) { $first = @($Rows | Where-Object { $null -ne $_ } | Select-Object -First 1); $Properties = $(if ($first.Count) { @($first[0].PSObject.Properties | ForEach-Object { $_.Name }) } else { @() }) }
    $q = { param($v) '"' + ([string]$v).Replace('"', '""') + '"' }
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add((@($Properties | ForEach-Object { & $q (Protect-IgwtCsvValue $_) }) -join ','))
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $out.Add((@(foreach ($p in $Properties) { & $q (Protect-IgwtCsvValue $r.$p) }) -join ','))
    }
    return $out.ToArray()
}

function Test-IgwtNetworkPath {
    <#
    .SYNOPSIS
        True for a path on a network share: \\server\share, //server/share, or a drive letter mapped
        to a network drive. Forensic logs and exports are only written to local disks. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Path)
    if (-not $Path) { return $false }
    $p = $Path.Trim().Replace('/', '\')
    if ($p.StartsWith('\\')) { return $true }
    if ($p -match '^([A-Za-z]):') {
        try { return ((New-Object System.IO.DriveInfo($Matches[1])).DriveType -eq [System.IO.DriveType]::Network) } catch { return $false }
    }
    return $false
}
