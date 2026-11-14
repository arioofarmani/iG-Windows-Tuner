# RegistryCleanerExclusions.ps1
# The registry cleaner's user exclusion list (DECISIONS RG13):
# %ProgramData%\iGWindowsTuner\State\regclean-exclusions.json. It changes only what the tool shows and
# removes, never the PC, so it is not journaled. An unreadable or invalid file is an error, never
# "no exclusions". Kept apart from RegistryCleanerProtection.ps1 so that file holds no write member.

$script:IgwtRegCleanExclusionMax = 1000
$script:IgwtRegCleanExclusionScopes = @('key', 'value', 'path')
$script:IgwtRegCleanExclusionFields = @('pattern', 'scope', 'reason', 'addedUtc')

function Get-IgwtRegCleanExclusionsPath {
    <#
    .SYNOPSIS
        Full path of the exclusion file: <data root>\State\regclean-exclusions.json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Get-IgwtDataPath -Kind State) 'regclean-exclusions.json')
}

function Test-IgwtRegCleanExclusionData {
    <#
    .SYNOPSIS
        Validates an exclusion document against the strict schema. Returns error strings (empty = valid).
    .DESCRIPTION
        {schemaVersion: 1, entries: [{pattern, scope, reason, addedUtc}]}: no other properties, at
        most 1,000 entries, scope key, value or path; key and value patterns start with HKLM\ or
        HKCU\, path patterns with a drive or a %Variable%\; pattern up to 512 and reason up to 200
        printable ASCII characters; addedUtc an ISO 8601 UTC time; no duplicate pattern and scope.
    .PARAMETER Document
        The parsed document.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()]$Document)
    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Document -or $Document -is [string] -or $Document -is [array] -or $Document -is [ValueType]) { $errors.Add('the file is not a JSON object.'); return $errors.ToArray() }
    $props = @($Document.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($p in $props) { if ($p -notin 'schemaVersion', 'entries') { $errors.Add("unknown property '$p'.") } }
    if (-not ($props -contains 'schemaVersion') -or [string]$Document.schemaVersion -ne '1') { $errors.Add('schemaVersion must be 1.') }
    if (-not ($props -contains 'entries')) { $errors.Add('entries is missing.'); return $errors.ToArray() }
    $entries = @($Document.entries | Where-Object { $null -ne $_ })
    if ($entries.Count -gt $script:IgwtRegCleanExclusionMax) { $errors.Add("at most $($script:IgwtRegCleanExclusionMax) entries are allowed ($($entries.Count)).") }
    $seen = @{}
    $i = 0
    foreach ($e in $entries) {
        $i++
        $l = "entry $i"
        if ($e -is [string] -or $e -is [ValueType]) { $errors.Add("${l}: not an object."); continue }
        foreach ($p in @($e.PSObject.Properties | ForEach-Object { $_.Name })) { if ($p -notin $script:IgwtRegCleanExclusionFields) { $errors.Add("${l}: unknown property '$p'.") } }
        $pattern = [string]$e.pattern
        $scope = [string]$e.scope
        $reason = [string]$e.reason
        if ($scope -cnotin $script:IgwtRegCleanExclusionScopes) { $errors.Add("${l}: scope must be key, value or path.") }
        if (-not $pattern -or $pattern.Length -gt 512 -or $pattern -match '[^\x20-\x7E]') { $errors.Add("${l}: pattern must be 1 to 512 printable ASCII characters.") }
        elseif ($scope -in 'key', 'value' -and $pattern -cnotmatch '^(HKLM|HKCU)\\[^\\]') { $errors.Add("${l}: a $scope pattern starts with HKLM\ or HKCU\.") }
        elseif ($scope -eq 'path' -and $pattern -notmatch '^([A-Za-z]:\\|%[A-Za-z0-9_()]+%\\)') { $errors.Add("${l}: a path pattern starts with a drive or a %Variable%\.") }
        if (-not $reason.Trim() -or $reason.Length -gt 200 -or $reason -match '[^\x20-\x7E]') { $errors.Add("${l}: reason must be 1 to 200 printable ASCII characters.") }
        $added = $e.addedUtc
        $ok = $false
        if ($added -is [datetime]) { $ok = $true }
        elseif ($added -is [string] -and $added -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$') {
            $dt = [datetime]::MinValue
            $ok = [datetime]::TryParse($added, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)
        }
        if (-not $ok) { $errors.Add("${l}: addedUtc must be an ISO 8601 UTC time (yyyy-MM-ddTHH:mm:ssZ).") }
        $k = $scope.ToLowerInvariant() + '|' + $pattern.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $errors.Add("${l}: duplicate of entry $($seen[$k]).") } else { $seen[$k] = $i }
    }
    return $errors.ToArray()
}

function Get-IgwtRegCleanExclusions {
    <#
    .SYNOPSIS
        The registry cleaner's exclusion list (RG13): {SchemaVersion; Entries; Path}. Read-only.
    .DESCRIPTION
        Reads %ProgramData%\iGWindowsTuner\State\regclean-exclusions.json. A missing file means no
        exclusions; an unreadable or invalid file throws, so a scan refuses instead of showing entries
        the user excluded.
    .EXAMPLE
        (Get-IgwtRegCleanExclusions).Entries
    #>
    [CmdletBinding()]
    param()
    $path = Get-IgwtRegCleanExclusionsPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return [pscustomobject]@{ SchemaVersion = 1; Entries = @(); Path = $path } }
    $doc = $null
    try { $doc = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "The registry cleaner exclusion list $path cannot be read ($($_.Exception.Message)); fix or delete the file." }
    $errors = @(Test-IgwtRegCleanExclusionData -Document $doc)
    if ($errors.Count -gt 0) { throw "The registry cleaner exclusion list $path is invalid: $($errors -join ' ') Fix or delete the file." }
    $entries = @($doc.entries | Where-Object { $null -ne $_ } | ForEach-Object {
            $a = $_.addedUtc
            if ($a -is [datetime]) { $a = $a.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
            [pscustomobject]@{ pattern = [string]$_.pattern; scope = [string]$_.scope; reason = [string]$_.reason; addedUtc = [string]$a }
        })
    return [pscustomobject]@{ SchemaVersion = 1; Entries = $entries; Path = $path }
}

function Save-IgwtRegCleanExclusions {
    <#
    .SYNOPSIS
        Replaces the registry cleaner's exclusion list (RG13). Changes only what the tool shows and
        removes, never the PC.
    .DESCRIPTION
        Refuses in read-only mode and, outside TestMode, without administrator rights (the file lives
        in the admin-only data root). Every entry must pass the strict schema (an entry without
        addedUtc gets the current UTC time). Writes a temporary file next to the target and moves it
        into place, only under the data root. Returns the saved list.
    .PARAMETER Entries
        The complete new list: objects or hashtables with pattern, scope (key, value, path), reason
        and optional addedUtc. An empty list clears the exclusions.
    .EXAMPLE
        Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'HKCU\Software\Contoso'; scope = 'key'; reason = 'still used' })
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
    Assert-IgwtWritable -Operation 'Save-IgwtRegCleanExclusions'
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'Saving the registry cleaner exclusions needs administrator rights.' }
    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Entries | Where-Object { $null -ne $_ })) {
        $h = [ordered]@{}
        $names = $(if ($e -is [System.Collections.IDictionary]) { @($e.Keys | ForEach-Object { [string]$_ }) } else { @($e.PSObject.Properties | ForEach-Object { $_.Name }) })
        foreach ($n in $names) { if ($n -notin $script:IgwtRegCleanExclusionFields) { throw "Exclusion entry has an unknown property '$n'." } }
        foreach ($n in $script:IgwtRegCleanExclusionFields) { $h[$n] = $(if ($e -is [System.Collections.IDictionary]) { $e[$n] } else { $e.$n }) }
        if (-not $h['addedUtc']) { $h['addedUtc'] = $now }
        if ($h['addedUtc'] -is [datetime]) { $h['addedUtc'] = ([datetime]$h['addedUtc']).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
        foreach ($n in 'pattern', 'scope', 'reason', 'addedUtc') { $h[$n] = [string]$h[$n] }
        $list.Add([pscustomobject]$h)
    }
    $doc = [ordered]@{ schemaVersion = 1; entries = $list.ToArray() }
    $errors = @(Test-IgwtRegCleanExclusionData -Document ([pscustomobject]$doc))
    if ($errors.Count -gt 0) { throw "The exclusion list was not saved: $($errors -join ' ')" }
    $path = Get-IgwtRegCleanExclusionsPath
    $root = Get-IgwtDataPath -Kind Root
    if (-not $root -or -not (Test-IgwtPathUnder -Path $path -Parent $root -Strict)) { throw "Refused: the exclusion list must be saved under the data root ($root)." }
    if (-not $PSCmdlet.ShouldProcess($path, 'Save registry cleaner exclusions')) { return }
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $tmp = $path + '.tmp'
    [IO.File]::WriteAllText($tmp, (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return (Get-IgwtRegCleanExclusions)
}
