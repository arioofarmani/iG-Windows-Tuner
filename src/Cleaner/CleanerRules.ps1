# CleanerRules.ps1
# Loads and validates the cleaner rules (data\cleaner\*.json) and expands their roots:
# environment variables, the {SteamLibrary} token, Chromium/Firefox profile discovery and
# (opt-in, admin) all user profiles. Every resolved root is canonicalized and checked against the
# denylist before it is used.

$script:IgwtCleanerRuleCache = $null
$script:IgwtCleanerCategories = @('System', 'Gaming', 'Browsers', 'Apps', 'Developer', 'Downloads')
$script:IgwtCleanerMethods = @('files', 'browserCache', 'recycleBin', 'deliveryOptimization', 'dism', 'driverStore', 'guidance')
$script:IgwtLevels = @('Standard', 'Advanced', 'Expert')

function ConvertTo-IgwtNormalizedCleanerRule {
    <# .SYNOPSIS Upgrades pre-v2 rules in memory (tier, antiCheat, reversible, source, hardware) and fills defaults. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule, [string]$SourceFile, [int]$SourceSchema = 2)
    $missing = @('tier', 'antiCheat', 'reversible', 'source', 'hardware') | Where-Object { $null -eq $Rule.PSObject.Properties[$_] }
    if ($missing) { $Rule = ConvertTo-IgwtPSObject -InputObject (ConvertTo-IgwtV2CleanerRule -Rule $Rule) }
    $defaults = [ordered]@{
        level = 'Standard'; sideEffects = ''; include = @('*'); exclude = @(); recurse = $true; minAgeHours = 0; requiresClosed = @()
        services = @(); allUsers = $false; recycle = $false; default = $false; requiresAdmin = $false; allowSystemFiles = $false; allowDownloads = $false
        removeEmptyDirs = $true; keepNewest = 0; roots = @(); browser = ''; userDataRoots = @(); profileCacheDirs = @(); rootCacheDirs = @()
        sources = @(); notes = ''; resetBase = $false; source = 'igwt'
    }
    foreach ($k in $defaults.Keys) {
        if ($null -eq $Rule.PSObject.Properties[$k]) { $Rule | Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k] }
    }
    $Rule | Add-Member -NotePropertyName sourceFile -NotePropertyValue $SourceFile -Force
    $Rule | Add-Member -NotePropertyName sourceSchema -NotePropertyValue $SourceSchema -Force
    return $Rule
}

function Get-IgwtCleanerRules {
    <# .SYNOPSIS All cleaner rules from data\cleaner\*.json (normalized). #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtCleanerRuleCache -and -not $Force) { return $script:IgwtCleanerRuleCache }
    $folder = Join-Path (Get-IgwtDataFolder) 'cleaner'
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($file in (Get-ChildItem -LiteralPath $folder -Filter '*.json' | Sort-Object Name)) {
        $doc = Read-IgwtJsonFile -Path $file.FullName
        $schema = Get-IgwtFileSchemaVersion -Document $doc
        foreach ($r in @($doc.rules)) { if ($r) { $all.Add((ConvertTo-IgwtNormalizedCleanerRule -Rule $r -SourceFile $file.Name -SourceSchema $schema)) } }
    }
    $script:IgwtCleanerRuleCache = @($all | Sort-Object @{ Expression = { [array]::IndexOf($script:IgwtCleanerCategories, $_.category) } }, id)
    return $script:IgwtCleanerRuleCache
}

function Get-IgwtCleanerRule {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Id)
    $rules = Get-IgwtCleanerRules
    foreach ($i in $Id) {
        $r = $rules | Where-Object { $_.id -eq $i } | Select-Object -First 1
        if (-not $r) { throw "Unknown cleaner rule '$i'." }
        $r
    }
}

function Get-IgwtUserProfileFolders {
    <#
    .SYNOPSIS
        Local user profiles from HKLM\...\ProfileList (real user SIDs only; no Default/Public/system profiles).
    #>
    [CmdletBinding()]
    param()
    $list = Resolve-IgwtRegistryPath -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($k in (Get-ChildItem -LiteralPath $list -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -notmatch '^S-1-5-21-') { continue }
        $p = [string]$k.GetValue('ProfileImagePath')
        if (-not $p) { continue }
        $p = [Environment]::ExpandEnvironmentVariables($p)
        if (Test-Path -LiteralPath $p) { [pscustomobject]@{ Sid = $k.PSChildName; Path = $p } }
    }
}

function Expand-IgwtCleanerRootTemplate {
    <#
    .SYNOPSIS
        Expands one root template for one user profile (or the current user) into concrete paths.
        Unresolved environment variables make the root invalid (it is skipped, never guessed).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Template, [string]$ProfilePath)
    $t = $Template
    if ($ProfilePath) {
        $t = $t.Replace('%LOCALAPPDATA%', (Join-Path $ProfilePath 'AppData\Local')).Replace('%APPDATA%', (Join-Path $ProfilePath 'AppData\Roaming'))
        $t = $t.Replace('%TEMP%', (Join-Path $ProfilePath 'AppData\Local\Temp')).Replace('%TMP%', (Join-Path $ProfilePath 'AppData\Local\Temp')).Replace('%USERPROFILE%', $ProfilePath)
    }
    if ($t.Contains('{SteamLibrary}')) {
        $libs = @()
        try { $libs = @(Get-IgwtSteamLibraryPaths) } catch { $libs = @() }
        return @($libs | ForEach-Object { [Environment]::ExpandEnvironmentVariables($t.Replace('{SteamLibrary}', $_)) })
    }
    $e = [Environment]::ExpandEnvironmentVariables($t)
    if ($e -match '%[^%]+%') { return @() }
    return @($e)
}

function Get-IgwtBrowserCacheRoots {
    <#
    .SYNOPSIS
        Cache folders of every Chromium profile (Default, Profile N, Guest Profile) or Firefox profile
        under the rule's user-data roots. Only folder names listed in the rule are returned.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule)
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($tpl in @($Rule.userDataRoots)) {
        foreach ($udr in @(Expand-IgwtCleanerRootTemplate -Template ([string]$tpl))) {
            if (-not (Test-Path -LiteralPath $udr -PathType Container)) { continue }
            foreach ($rc in @($Rule.rootCacheDirs)) { $roots.Add((Join-Path $udr $rc)) }
            $profiles = @()
            if ($Rule.browser -eq 'firefox') {
                $profiles = @(Get-ChildItem -LiteralPath $udr -Directory -ErrorAction SilentlyContinue)
            } else {
                $profiles = @(Get-ChildItem -LiteralPath $udr -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -eq 'Guest Profile' })
            }
            foreach ($p in $profiles) {
                if ((([long]$p.Attributes) -band 0x400) -ne 0) { continue }
                foreach ($pc in @($Rule.profileCacheDirs)) { $roots.Add((Join-Path $p.FullName $pc)) }
            }
        }
    }
    return @($roots)
}

function Resolve-IgwtCleanerRoots {
    <#
    .SYNOPSIS
        Concrete, validated roots of a rule. Returns objects with Path, Status (Ok, Missing, Refused)
        and Reason. Only Ok roots are ever enumerated or used by the deletion primitive.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule, [switch]$AllUsers)
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Rule.method -eq 'browserCache') {
        foreach ($r in (Get-IgwtBrowserCacheRoots -Rule $Rule)) { $candidates.Add($r) }
    } else {
        $profiles = @($null)
        if ($AllUsers -and $Rule.allUsers) { $profiles = @(Get-IgwtUserProfileFolders | ForEach-Object { $_.Path }) }
        foreach ($tpl in @($Rule.roots)) {
            foreach ($prof in $profiles) {
                foreach ($x in @(Expand-IgwtCleanerRootTemplate -Template ([string]$tpl) -ProfilePath $prof)) { $candidates.Add($x) }
            }
        }
    }
    $seen = @{}
    foreach ($c in $candidates) {
        $canon = $null
        try { $canon = ConvertTo-IgwtCanonicalPath -Path $c } catch {
            [pscustomobject]@{ Path = $c; Status = 'Refused'; Reason = $_.Exception.Message }
            continue
        }
        if ($seen.ContainsKey($canon.ToLowerInvariant())) { continue }
        $seen[$canon.ToLowerInvariant()] = $true
        $reason = Test-IgwtCleanerRootAllowed -Root $canon -AllowDownloads:([bool]$Rule.allowDownloads)
        if ($reason) { [pscustomobject]@{ Path = $canon; Status = 'Refused'; Reason = $reason }; continue }
        if (-not (Test-Path -LiteralPath $canon)) { [pscustomobject]@{ Path = $canon; Status = 'Missing'; Reason = 'not present' }; continue }
        [pscustomobject]@{ Path = $canon; Status = 'Ok'; Reason = '' }
    }
}

function Test-IgwtCleanerCatalog {
    <# .SYNOPSIS Validates data\cleaner\*.json. Returns error strings (none = valid). #>
    [CmdletBinding()]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $rules = @(Get-IgwtCleanerRules -Force)
    $ids = @{}
    $files = @{}
    foreach ($r in $rules) {
        $rid = [string]$r.id
        foreach ($f in 'id', 'name', 'category', 'level', 'method') { if (-not [string]$r.$f) { $errors.Add("${rid}: missing '$f'.") } }
        if ($rid -notmatch '^clean\.[a-z0-9\.\-]+$') { $errors.Add("${rid}: id must start with 'clean.' (lower case).") }
        if ($ids.ContainsKey($rid)) { $errors.Add("${rid}: duplicate id.") } else { $ids[$rid] = $true }
        Test-IgwtItemText -Item $r -Label $rid -Errors $errors
        Test-IgwtItemMetadata -Item $r -Label $rid -Errors $errors
        if ([int]$r.sourceSchema -lt $script:IgwtSchemaVersion -and -not $files.ContainsKey([string]$r.sourceFile)) {
            $files[[string]$r.sourceFile] = $true
            $errors.Add("cleaner\$($r.sourceFile): schemaVersion $($r.sourceSchema); run tools\Convert-IgwtV1Data.ps1 to migrate it.")
        }
        if ([string]$r.method -in 'files', 'browserCache', 'recycleBin', 'deliveryOptimization', 'dism', 'driverStore' -and -not $r.recycle -and [string]$r.reversible -eq 'full') { $errors.Add("${rid}: rules that delete files cannot be reversible 'full'.") }
        if (-not (ConvertTo-IgwtAntiCheatInfo -Value $r.antiCheat).Safe) { $errors.Add("${rid}: cleaner rules must be anti-cheat safe.") }
        if ($script:IgwtCleanerCategories -notcontains [string]$r.category) { $errors.Add("${rid}: unknown category '$($r.category)'.") }
        if ($script:IgwtLevels -notcontains [string]$r.level) { $errors.Add("${rid}: level must be Standard, Advanced or Expert.") }
        if ($script:IgwtCleanerMethods -notcontains [string]$r.method) { $errors.Add("${rid}: unknown method '$($r.method)'.") }
        if ($r.method -in 'files', 'guidance' -and @($r.roots).Count -eq 0) { $errors.Add("${rid}: '$($r.method)' rules need roots.") }
        if ($r.method -eq 'browserCache' -and (@($r.userDataRoots).Count -eq 0 -or (@($r.profileCacheDirs).Count + @($r.rootCacheDirs).Count) -eq 0)) { $errors.Add("${rid}: browserCache rules need userDataRoots and cache folders.") }
        foreach ($d in @($r.profileCacheDirs) + @($r.rootCacheDirs)) { if ($script:IgwtBrowserCacheNames -notcontains [string]$d) { $errors.Add("${rid}: '$d' is not an allowed browser cache folder name.") } }
        if ($r.default -and $r.level -ne 'Standard') { $errors.Add("${rid}: only Standard rules may be on by default.") }
        if ($r.allowDownloads -and -not $r.recycle) { $errors.Add("${rid}: rules that clean Downloads must send files to the Recycle Bin.") }
        if ($r.allowDownloads -and $r.default) { $errors.Add("${rid}: the Downloads rule must be opt-in (default false).") }
        if ($r.category -eq 'Browsers' -and @($r.requiresClosed).Count -eq 0) { $errors.Add("${rid}: browser rules must list the browser process in requiresClosed.") }
        foreach ($s in @($r.sources)) { if ([string]$s -notmatch '^https://') { $errors.Add("${rid}: source '$s' must be https.") } }
        foreach ($tpl in @($r.roots)) {
            foreach ($x in @(Expand-IgwtCleanerRootTemplate -Template ([string]$tpl))) {
                try {
                    $c = ConvertTo-IgwtCanonicalPath -Path $x
                    $why = Test-IgwtCleanerRootAllowed -Root $c -AllowDownloads:([bool]$r.allowDownloads)
                    if ($why -and $why -notlike 'root is*') { $errors.Add("${rid}: root '$tpl' resolves to a protected location ($why).") }
                } catch { $errors.Add("${rid}: root '$tpl' is invalid ($($_.Exception.Message)).") }
            }
        }
    }
    return $errors.ToArray()
}
