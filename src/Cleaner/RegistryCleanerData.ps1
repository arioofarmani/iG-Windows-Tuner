# RegistryCleanerData.ps1
# Loads and validates the registry cleaner data: data\registry\categories.json (categories, their
# roots per hive and view, the RG32 deny list) and data\registry\protected.json (the protected set,
# DECISIONS RG11). Read-only. Vendor, anti-cheat and service names live only in the JSON (RG30).

$script:IgwtRegCleanProtectedCache = $null
$script:IgwtRegCleanCategoryCache = $null
$script:IgwtRegCleanCategoryIds = @('uninstall', 'appPath', 'progId', 'application', 'openWith', 'run', 'softwareKey', 'firewallRule', 'service', 'task')
$script:IgwtRegCleanCategoryKinds = @('regKeyTree', 'regValue', 'firewallRule', 'reportOnly')
$script:IgwtRegCleanProtectedGroupIds = @('microsoft', 'securityVendors', 'hardware', 'antiCheat', 'runtimes', 'launchers')
$script:IgwtRegCleanVendorTypes = @('consumer', 'edr', 'windows')
# Invented child key names used to test whether a keyPattern reaches the entries below a category root.
$script:IgwtRegCleanRootProbeNames = @('Contoso', 'Contoso App 1.0', 'contoso.app', '.contoso', 'Fabrikam_is1', '{01234567-89AB-CDEF-0123-456789ABCDEF}')

function Get-IgwtRegCleanDataFile {
    <#
    .SYNOPSIS
        Full path of a registry cleaner data file (data\registry\<Name>.json).
    .PARAMETER Name
        File base name: categories or protected.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('categories', 'protected')][string]$Name)
    return (Join-Path (Join-Path (Get-IgwtDataFolder) 'registry') ($Name + '.json'))
}

function Get-IgwtRegCleanProtectedCatalog {
    <#
    .SYNOPSIS
        The parsed data\registry\protected.json (cached; Clear-IgwtCatalogCaches resets it).
    .PARAMETER Force
        Reads the file again instead of returning the cached copy.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtRegCleanProtectedCache -and -not $Force) { return $script:IgwtRegCleanProtectedCache }
    $script:IgwtRegCleanProtectedCache = Read-IgwtJsonFile -Path (Get-IgwtRegCleanDataFile -Name 'protected')
    return $script:IgwtRegCleanProtectedCache
}

function Get-IgwtRegCleanCategories {
    <#
    .SYNOPSIS
        The parsed data\registry\categories.json (cached; Clear-IgwtCatalogCaches resets it).
    .PARAMETER Force
        Reads the file again instead of returning the cached copy.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtRegCleanCategoryCache -and -not $Force) { return $script:IgwtRegCleanCategoryCache }
    $script:IgwtRegCleanCategoryCache = Read-IgwtJsonFile -Path (Get-IgwtRegCleanDataFile -Name 'categories')
    return $script:IgwtRegCleanCategoryCache
}

function Get-IgwtRegCleanCategoryRoots {
    <#
    .SYNOPSIS
        Flat list of category roots: {Category, Kind, Hive, View, Path, Full ('HIVE\path')}.
    .PARAMETER Categories
        A parsed categories.json document (default: the shipped file).
    #>
    [CmdletBinding()]
    param($Categories)
    if ($null -eq $Categories) { $Categories = Get-IgwtRegCleanCategories }
    foreach ($c in @($Categories.categories | Where-Object { $_ })) {
        foreach ($r in @($c.roots | Where-Object { $_ })) {
            [pscustomobject]@{
                Category = [string]$c.id; Kind = [string]$c.kind; Hive = [string]$r.hive; View = [string]$r.view
                Path = [string]$r.path; Full = ([string]$r.hive + '\' + [string]$r.path)
            }
        }
    }
}

function Test-IgwtRegCleanPatternAnchor {
    <#
    .SYNOPSIS
        Error text when a protected-set pattern is not anchored, $null when it is.
    .DESCRIPTION
        key: starts with HKLM\, HKCU\ or HK*\, or with *\ followed by a key name of 4+ characters.
        path: starts with a drive (C:\), a %Variable%\ or *\ followed by a folder of 4+ characters.
        signer: starts with CN= or O=. name (publisher, display name, service, value name, package):
        does not start with a wildcard. A leading '*\' must be followed by a segment of at least 4
        characters without wildcards (RG11).
    .PARAMETER Pattern
        The wildcard pattern.
    .PARAMETER Kind
        key, path, signer or name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Pattern, [Parameter(Mandatory = $true)][ValidateSet('key', 'path', 'signer', 'name')][string]$Kind)
    if ([string]::IsNullOrWhiteSpace($Pattern)) { return 'empty pattern' }
    if ($Pattern.StartsWith('*\')) {
        if ($Kind -eq 'key' -or $Kind -eq 'path') {
            if ($Pattern -match '^\*\\[^\\*?\[\]]{4,}(\\|$)') { return $null }
            return "leading '*\' must be followed by a segment of at least 4 characters"
        }
    }
    switch ($Kind) {
        'key' { if ($Pattern -match '^(?i)(HKLM|HKCU|HK\*)\\[^\\]') { return $null } }
        'path' { if ($Pattern -match '^([A-Za-z]:\\|%[A-Za-z0-9_()]+%\\)') { return $null } }
        'signer' { if ($Pattern -match '^(?i)(CN|O)=\S') { return $null } }
        'name' { if ($Pattern -notmatch '^[*?\[]') { return $null } }
    }
    return 'unanchored pattern'
}

function Test-IgwtRegCleanKeyPatternCoversRoot {
    <#
    .SYNOPSIS
        True when a keyPattern matches a category root or the entries directly below it.
    .DESCRIPTION
        Probes the root itself and invented child names (one and two levels below) against the
        pattern, so 'HK*\SOFTWARE\Microsoft\*' covers the Uninstall root while
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\*' does not.
    .PARAMETER Pattern
        The keyPattern (HIVE\path wildcard).
    .PARAMETER Root
        The root as 'HIVE\path'.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Pattern, [Parameter(Mandatory = $true)][string]$Root)
    if ($Root -like $Pattern) { return $true }
    foreach ($n in $script:IgwtRegCleanRootProbeNames) {
        if (($Root + '\' + $n) -like $Pattern) { return $true }
        if (($Root + '\' + $n + '\' + $n) -like $Pattern) { return $true }
    }
    return $false
}

function Test-IgwtRegCleanHttpsList {
    <#
    .SYNOPSIS
        Adds an error for every source that is not an https URL.
    .PARAMETER Values
        The sources to check.
    .PARAMETER Label
        Prefix for the error text.
    .PARAMETER Errors
        The error list to add to.
    #>
    [CmdletBinding()]
    param($Values, [string]$Label, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    foreach ($s in @($Values | Where-Object { $null -ne $_ })) {
        if (-not ([string]$s -match '^https://[^\s/]+\.[^\s]+$')) { $Errors.Add("${Label}: source '$s' is not an https URL.") }
    }
}

function Test-IgwtRegCleanCategoryData {
    <#
    .SYNOPSIS
        Validates a parsed categories.json document. Returns error strings (empty = valid).
    .PARAMETER Categories
        The parsed document.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory = $true)]$Categories)
    $errors = New-Object System.Collections.Generic.List[string]
    $label = 'registry\categories.json'
    if ((Get-IgwtFileSchemaVersion -Document $Categories) -ne 1) { $errors.Add("${label}: schemaVersion must be 1.") }
    $seen = @{}
    foreach ($c in @($Categories.categories | Where-Object { $_ })) {
        $id = [string]$c.id
        $l = "$label category '$id'"
        if ($id -notin $script:IgwtRegCleanCategoryIds) { $errors.Add("${l}: unknown category id.") }
        if ($seen.ContainsKey($id)) { $errors.Add("${l}: duplicate id.") } else { $seen[$id] = $true }
        if ([string]$c.kind -notin $script:IgwtRegCleanCategoryKinds) { $errors.Add("${l}: kind must be one of $($script:IgwtRegCleanCategoryKinds -join ', ').") }
        if ([string]$c.maxConfidence -notin @('Safe', 'Review')) { $errors.Add("${l}: maxConfidence must be Safe or Review.") }
        if ([string]$c.kind -eq 'reportOnly' -and [string]$c.maxConfidence -ne 'Review') { $errors.Add("${l}: report-only categories are Review at most.") }
        $roots = @($c.roots | Where-Object { $_ })
        if ([string]$c.kind -in @('regKeyTree', 'regValue') -and $roots.Count -eq 0) { $errors.Add("${l}: a registry category needs at least one root.") }
        if ([string]$c.kind -notin @('regKeyTree', 'regValue') -and $roots.Count -gt 0) { $errors.Add("${l}: only registry categories have roots.") }
        foreach ($r in $roots) {
            $p = [string]$r.path
            if ([string]$r.hive -notin @('HKLM', 'HKCU')) { $errors.Add("${l}: root '$p' hive must be HKLM or HKCU.") }
            if ([string]$r.view -notin @('64', '32')) { $errors.Add("${l}: root '$p' view must be 64 or 32.") }
            if ([string]$r.hive -eq 'HKCU' -and [string]$r.view -ne '64') { $errors.Add("${l}: root '$p' HKCU is read in view 64 only.") }
            if ([string]::IsNullOrWhiteSpace($p) -or $p.StartsWith('\') -or $p.EndsWith('\') -or $p -match '[*?\[\]]') { $errors.Add("${l}: root '$p' must be a plain key path without wildcards or leading/trailing backslash.") }
            if ($p -match '(?i)(^|\\)wow6432node(\\|$)') { $errors.Add("${l}: root '$p' must use the logical path; the 32-bit view is chosen by 'view'.") }
        }
        Test-IgwtRegCleanHttpsList -Values $c.sources -Label $l -Errors $errors
        if (@($c.sources | Where-Object { $_ }).Count -eq 0) { $errors.Add("${l}: needs at least one https source.") }
    }
    foreach ($must in $script:IgwtRegCleanCategoryIds) { if (-not $seen.ContainsKey($must)) { $errors.Add("${label}: category '$must' is missing.") } }
    $deny = $Categories.denyList
    if ($null -eq $deny) { $errors.Add("${label}: denyList is missing.") }
    else {
        $rootNames = @{}
        foreach ($r in @(Get-IgwtRegCleanCategoryRoots -Categories $Categories)) { $rootNames[$r.Path.ToLowerInvariant()] = $true; $rootNames[$r.Full.ToLowerInvariant()] = $true }
        foreach ($list in 'vendorNames', 'segmentNames') {
            $names = @($deny.$list | Where-Object { $null -ne $_ })
            if ($names.Count -eq 0) { $errors.Add("${label}: denyList.$list is empty.") }
            foreach ($n in $names) {
                $s = [string]$n
                if ([string]::IsNullOrWhiteSpace($s) -or $s -match '[\\*?\[\]]') { $errors.Add("${label}: denyList.$list '$s' must be one key name without wildcards.") }
                elseif ($rootNames.ContainsKey($s.ToLowerInvariant())) { $errors.Add("${label}: denyList.$list '$s' is also a category root.") }
            }
        }
        Test-IgwtRegCleanHttpsList -Values $deny.sources -Label "$label denyList" -Errors $errors
    }
    return $errors.ToArray()
}

function Test-IgwtRegCleanPatternList {
    <#
    .SYNOPSIS
        Adds an error for every pattern of one field that is not anchored (Test-IgwtRegCleanPatternAnchor).
    .PARAMETER Owner
        The group or vendor object holding the field.
    .PARAMETER Field
        The field name (keyPatterns, pathPatterns, ...).
    .PARAMETER Kind
        key, path, signer or name.
    .PARAMETER Label
        Prefix for the error text.
    .PARAMETER Errors
        The error list to add to.
    #>
    [CmdletBinding()]
    param($Owner, [string]$Field, [string]$Kind, [string]$Label, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    if ($null -eq $Owner.PSObject.Properties[$Field]) { return }
    foreach ($p in @($Owner.$Field | Where-Object { $null -ne $_ })) {
        $why = Test-IgwtRegCleanPatternAnchor -Pattern ([string]$p) -Kind $Kind
        if ($why) { $Errors.Add("${Label}: $Field '$p': $why.") }
    }
}

function Test-IgwtRegCleanProtectedCatalog {
    <#
    .SYNOPSIS
        Validates data\registry\protected.json and categories.json. Returns error strings (empty = valid).
    .DESCRIPTION
        Fails for: unanchored patterns, a leading '*\' not followed by a segment of 4+ characters,
        non-https sources or removal tool urls, a non-EDR security vendor without a removal tool url
        or the "publishes no removal tool that iG could confirm" text, an EDR vendor without the
        "Ask your administrator" text, a keyPattern that covers a categories.json root without a
        carve-out (categoryRootsAllowed), a carve-out that is not a category root, and a deny-list
        name that is also a category root (DECISIONS RG11, RG32). Called by Test-IgwtCatalog.
    .PARAMETER Protected
        A parsed protected.json document (default: the shipped file).
    .PARAMETER Categories
        A parsed categories.json document (default: the shipped file).
    .EXAMPLE
        Test-IgwtRegCleanProtectedCatalog
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param($Protected, $Categories)
    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Categories) {
        $file = Get-IgwtRegCleanDataFile -Name 'categories'
        if (-not (Test-Path -LiteralPath $file)) { $errors.Add('registry\categories.json: missing.') }
        else { try { $Categories = Read-IgwtJsonFile -Path $file } catch { $errors.Add("registry\categories.json: $($_.Exception.Message)") } }
    }
    if ($null -eq $Protected) {
        $file = Get-IgwtRegCleanDataFile -Name 'protected'
        if (-not (Test-Path -LiteralPath $file)) { $errors.Add('registry\protected.json: missing.') }
        else { try { $Protected = Read-IgwtJsonFile -Path $file } catch { $errors.Add("registry\protected.json: $($_.Exception.Message)") } }
    }
    if ($null -eq $Categories -or $null -eq $Protected) { return $errors.ToArray() }
    foreach ($e in @(Test-IgwtRegCleanCategoryData -Categories $Categories)) { $errors.Add([string]$e) }
    $roots = @(Get-IgwtRegCleanCategoryRoots -Categories $Categories)
    $rootSet = @{}
    # Both views of a root share one 'HIVE\path'; coverage is checked once per distinct root.
    $distinctRoots = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roots) {
        if (-not $rootSet.ContainsKey($r.Full.ToLowerInvariant())) { $distinctRoots.Add($r) }
        $rootSet[$r.Full.ToLowerInvariant()] = $true
    }

    $label = 'registry\protected.json'
    if ((Get-IgwtFileSchemaVersion -Document $Protected) -ne 2) { $errors.Add("${label}: schemaVersion must be 2.") }
    foreach ($f in @($Protected.alsoRead | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Get-IgwtDataFolder)) ([string]$f)))) { $errors.Add("${label}: alsoRead file '$f' does not exist.") }
    }
    $groups = @($Protected.groups | Where-Object { $_ })
    $seen = @{}
    foreach ($g in $groups) {
        $id = [string]$g.id
        $l = "$label group '$id'"
        if ([string]::IsNullOrWhiteSpace($id)) { $errors.Add("${label}: a group has no id."); continue }
        if ($seen.ContainsKey($id)) { $errors.Add("${l}: duplicate id.") } else { $seen[$id] = $true }
        if ([string]::IsNullOrWhiteSpace([string]$g.reason) -or ([string]$g.reason).Length -gt 200) { $errors.Add("${l}: needs a reason of 200 characters or fewer.") }
        if ([string]$g.basis -notin @('microsoft', 'vendor', 'igwt')) { $errors.Add("${l}: basis must be microsoft, vendor or igwt.") }
        Test-IgwtRegCleanHttpsList -Values $g.sources -Label $l -Errors $errors
        if ([string]$g.basis -ne 'igwt' -and @($g.sources | Where-Object { $_ }).Count -eq 0) { $errors.Add("${l}: a $($g.basis) group needs at least one https source.") }

        # Carve-outs must name exact category roots.
        $allowed = @{}
        foreach ($a in @($g.categoryRootsAllowed | Where-Object { $null -ne $_ })) {
            if (-not $rootSet.ContainsKey(([string]$a).ToLowerInvariant())) { $errors.Add("${l}: categoryRootsAllowed '$a' is not a root in categories.json.") }
            $allowed[([string]$a).ToLowerInvariant()] = $true
        }
        $owners = New-Object System.Collections.Generic.List[object]
        $owners.Add(@{ Object = $g; Label = $l })
        foreach ($v in @($g.vendors | Where-Object { $_ })) { $owners.Add(@{ Object = $v; Label = "$l vendor '$($v.id)'"; Vendor = $true }) }
        foreach ($o in $owners) {
            $obj = $o.Object
            Test-IgwtRegCleanPatternList -Owner $obj -Field 'keyPatterns' -Kind 'key' -Label $o.Label -Errors $errors
            Test-IgwtRegCleanPatternList -Owner $obj -Field 'pathPatterns' -Kind 'path' -Label $o.Label -Errors $errors
            Test-IgwtRegCleanPatternList -Owner $obj -Field 'signerPatterns' -Kind 'signer' -Label $o.Label -Errors $errors
            foreach ($nf in 'publisherPatterns', 'displayNamePatterns', 'servicePatterns', 'valueNamePatterns', 'packageNamePatterns', 'packagePublisherIds') {
                Test-IgwtRegCleanPatternList -Owner $obj -Field $nf -Kind 'name' -Label $o.Label -Errors $errors
            }
            foreach ($kp in @($obj.keyPatterns | Where-Object { $null -ne $_ })) {
                foreach ($r in $distinctRoots) {
                    if ((Test-IgwtRegCleanKeyPatternCoversRoot -Pattern ([string]$kp) -Root $r.Full) -and -not $allowed.ContainsKey($r.Full.ToLowerInvariant())) {
                        $errors.Add("$($o.Label): keyPattern '$kp' covers the $($r.Category) root '$($r.Full)' without a carve-out in categoryRootsAllowed.")
                    }
                }
            }
            if ($o.Vendor) {
                $v = $obj
                $vl = $o.Label
                if ([string]::IsNullOrWhiteSpace([string]$v.id) -or [string]::IsNullOrWhiteSpace([string]$v.name)) { $errors.Add("${vl}: needs an id and a name.") }
                if ([string]$v.type -notin $script:IgwtRegCleanVendorTypes) { $errors.Add("${vl}: type must be one of $($script:IgwtRegCleanVendorTypes -join ', ').") }
                if (@($v.publisherPatterns | Where-Object { $_ }).Count + @($v.displayNamePatterns | Where-Object { $_ }).Count -eq 0) { $errors.Add("${vl}: needs publisherPatterns or displayNamePatterns.") }
                $tool = $v.removalTool
                if ($null -eq $tool) { $errors.Add("${vl}: removalTool {name, url, text} is required."); continue }
                $url = [string]$tool.url
                $text = [string]$tool.text
                if ($url -and $url -notmatch '^https://[^\s/]+\.[^\s]+$') { $errors.Add("${vl}: removalTool url '$url' is not an https URL.") }
                if ($url -and [string]::IsNullOrWhiteSpace([string]$tool.name)) { $errors.Add("${vl}: a removalTool with a url needs a name.") }
                if ([string]::IsNullOrWhiteSpace($text)) { $errors.Add("${vl}: removalTool text is required.") }
                switch ([string]$v.type) {
                    'edr' { if (-not $text.StartsWith('Ask your administrator')) { $errors.Add("${vl}: an EDR vendor's removalTool text starts with 'Ask your administrator'.") } }
                    'consumer' {
                        if (-not $url -and $text -notmatch '^.+ publishes no removal tool that iG could confirm; contact .+ support\.?$') {
                            $errors.Add("${vl}: a vendor without a removal tool url needs the text '<vendor> publishes no removal tool that iG could confirm; contact <vendor> support'.")
                        }
                    }
                }
            }
        }
    }
    foreach ($must in $script:IgwtRegCleanProtectedGroupIds) { if (-not $seen.ContainsKey($must)) { $errors.Add("${label}: group '$must' is missing.") } }
    $sec = @($groups | Where-Object { [string]$_.id -eq 'securityVendors' })
    if ($sec.Count -gt 0 -and @($sec[0].vendors | Where-Object { $_ }).Count -eq 0) { $errors.Add("${label}: group 'securityVendors' has no vendors.") }
    return $errors.ToArray()
}
