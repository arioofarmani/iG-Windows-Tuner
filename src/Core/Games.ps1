# Games.ps1
# Read-only game discovery from data\games.json: Steam libraries (libraryfolders.vdf),
# Riot install manifest, and known install paths. Nothing is ever written to game folders.

function Get-IgwtSteamLibraryPaths {
    <# .SYNOPSIS Steam library roots from the Steam install path and steamapps\libraryfolders.vdf. #>
    [CmdletBinding()]
    param()
    $roots = New-Object System.Collections.Generic.List[string]
    $steam = $null
    try { $steam = (Get-ItemProperty -LiteralPath (Resolve-IgwtRegistryPath -Path 'HKCU:\Software\Valve\Steam') -Name SteamPath -ErrorAction Stop).SteamPath } catch { $steam = $null }
    if (-not $steam) {
        try { $steam = (Get-ItemProperty -LiteralPath (Resolve-IgwtRegistryPath -Path 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam') -Name InstallPath -ErrorAction Stop).InstallPath } catch { $steam = $null }
    }
    if (-not $steam) { return @() }
    $steam = $steam -replace '/', '\'
    $roots.Add($steam)
    $vdf = Join-Path $steam 'steamapps\libraryfolders.vdf'
    if (Test-Path -LiteralPath $vdf) {
        foreach ($p in (ConvertFrom-IgwtSteamLibraryVdf -Text ([System.IO.File]::ReadAllText($vdf)))) { if ($roots -notcontains $p) { $roots.Add($p) } }
    }
    return @($roots | Where-Object { Test-Path -LiteralPath $_ })
}

function ConvertFrom-IgwtSteamLibraryVdf {
    <# .SYNOPSIS Extracts "path" values from libraryfolders.vdf text. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $result = foreach ($m in [regex]::Matches($Text, '"path"\s+"([^"]+)"')) {
        ($m.Groups[1].Value -replace '\\\\', '\') -replace '/', '\'
    }
    return @($result)
}

function Get-IgwtRiotInstallPaths {
    <# .SYNOPSIS Product install folders from %ProgramData%\Riot Games\RiotClientInstalls.json (if present). #>
    [CmdletBinding()]
    param()
    $file = Join-Path $env:ProgramData 'Riot Games\RiotClientInstalls.json'
    if (-not (Test-Path -LiteralPath $file)) { return @() }
    try {
        $doc = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        $paths = foreach ($p in $doc.PSObject.Properties) {
            if ($p.Value -is [string] -and $p.Value -match '\.exe$') { Split-Path -Parent ($p.Value -replace '/', '\') }
            elseif ($p.Value -is [psobject]) { foreach ($q in $p.Value.PSObject.Properties) { if ($q.Value -is [string] -and $q.Value -match '\.exe$') { Split-Path -Parent ($q.Value -replace '/', '\') } } }
        }
        return @($paths | Select-Object -Unique)
    } catch { return @() }
}

function Get-IgwtInstalledGames {
    <#
    .SYNOPSIS
        Detects installed games listed in data\games.json. Returns Id, Name, ExePath, AntiCheat.
    #>
    [CmdletBinding()]
    param()
    $defs = Get-IgwtGameDefinitions
    $steamLibs = @(Get-IgwtSteamLibraryPaths)
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($g in $defs) {
        $candidates = New-Object System.Collections.Generic.List[string]
        if ($g.steamDir -and $g.relativeExe) {
            foreach ($lib in $steamLibs) { $candidates.Add((Join-Path $lib "steamapps\common\$($g.steamDir)\$($g.relativeExe)")) }
        }
        foreach ($kp in @($g.knownPaths)) {
            if ($kp) { $candidates.Add([Environment]::ExpandEnvironmentVariables([string]$kp)) }
        }
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -PathType Leaf) {
                $found.Add([pscustomobject]@{ Id = $g.id; Name = $g.name; ExePath = $c; AntiCheat = $g.antiCheat })
                break
            }
        }
    }
    return $found.ToArray()
}
