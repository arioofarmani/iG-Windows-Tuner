# RegistryCleanerProtection.ps1
# The registry cleaner's one protection function (DECISIONS RG11-RG15): Test-IgwtRegCleanProtected
# answers the same question at the scan, the preview and the engine, from a context built by
# Get-IgwtRegCleanProtectionContext (data lists, live facts, exclusions). Read-only: this file holds
# no write member. The Windows Security Center query, the LaunchProtected and Early-Launch checks and
# the signature checks live only here (RG30). Vendor names live only in data\registry\protected.json.

$script:IgwtRegCleanWindowsSecurityClasses = @('AntiVirusProduct', 'FirewallProduct', 'AntiSpywareProduct')
# Registry rights that let an account change a key: SetValue, CreateSubKey, Delete, WriteDac,
# WriteOwner, GENERIC_WRITE and GENERIC_ALL.
$script:IgwtRegCleanWriteRightsMask = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
$script:IgwtRegCleanSystemSid = 'S-1-5-18'

#region Live facts (mockable wrappers)

function Get-IgwtRegCleanTrustedInstallerSid {
    <#
    .SYNOPSIS
        The SID of 'NT SERVICE\TrustedInstaller', translated at run time with NTAccount.Translate (no
        hard-coded SID; RG12, UNVERIFIED account name RG28 item 15); $null when the translation fails.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    try {
        $acct = New-Object System.Security.Principal.NTAccount('NT SERVICE', 'TrustedInstaller')
        return [string]$acct.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Get-IgwtRegCleanSecurityProducts {
    <#
    .SYNOPSIS
        Products registered with Windows Security Center (root\SecurityCenter2 AntiVirusProduct,
        FirewallProduct, AntiSpywareProduct): {Class, DisplayName, ProductPath, ReportingPath}.
    .DESCRIPTION
        Read-only. SecurityCenter2 is not documented on Learn (UNVERIFIED, RG28 item 4): it is used
        only to add protection, and a failed read makes every entry protected (RG12). Throws in
        TestMode unless mocked.
    #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtRegCleanSecurityProducts must be mocked.' }
    foreach ($c in $script:IgwtRegCleanWindowsSecurityClasses) {
        foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $c -ErrorAction Stop)) {
            if ($null -eq $p) { continue }
            [pscustomobject]@{ Class = $c; DisplayName = [string]$p.displayName; ProductPath = [string]$p.pathToSignedProductExe; ReportingPath = [string]$p.pathToSignedReportingExe }
        }
    }
}

function Get-IgwtRegCleanPnpProviders {
    <#
    .SYNOPSIS
        Driver package providers of present devices (Win32_PnPSignedDriver DriverProviderName),
        unique. Read-only; throws in TestMode unless mocked.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: Get-IgwtRegCleanPnpProviders must be mocked.' }
    $names = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -Property DriverProviderName -ErrorAction Stop | ForEach-Object { [string]$_.DriverProviderName })
    return @($names | Where-Object { $_ -and -not $_.StartsWith('(') } | Sort-Object -Unique)
}

function Get-IgwtRegCleanKeySecurity {
    <#
    .SYNOPSIS
        Owner and write access of one key (RegistryKey.GetAccessControl; Get-Acl -LiteralPath fails on
        HKLM here): {Owner (SID); Writers (SIDs with an Allow write right that applies to this key);
        AclProtected; HasExplicitAce; ExplicitAceCount; Sddl}. $null when the key does not exist. Read-only.
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
        $key = $base.OpenSubKey($loc.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if (-not $key) { return $null }
        try {
            $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access
            $acl = $key.GetAccessControl($sections)
            $sidType = [System.Security.Principal.SecurityIdentifier]
            $writers = New-Object System.Collections.Generic.List[string]
            $explicit = $false
            $explicitCount = 0
            foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
                if (-not $rule.IsInherited) { $explicit = $true; $explicitCount++ }
                if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
                if (([int64][int]$rule.RegistryRights -band $script:IgwtRegCleanWriteRightsMask) -eq 0) { continue }
                $v = [string]$rule.IdentityReference.Value
                if (-not $writers.Contains($v)) { $writers.Add($v) }
            }
            return [pscustomobject]@{
                Owner = [string]$acl.GetOwner($sidType).Value; Writers = $writers.ToArray(); AclProtected = [bool]$acl.AreAccessRulesProtected
                HasExplicitAce = $explicit; ExplicitAceCount = $explicitCount; Sddl = [string]$acl.GetSecurityDescriptorSddlForm($sections)
            }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Get-IgwtRegCleanFileSigner {
    <#
    .SYNOPSIS
        Signature of an existing file through the per-scan in-memory cache: {Status; Subject}. Uses
        Get-AuthenticodeSignature (catalog signatures included). Throws when the signature cannot be
        read. Never writes a cache file (RG22).
    .PARAMETER Path
        The file.
    .PARAMETER Cache
        The scan's signature cache (hashtable).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][hashtable]$Cache)
    $k = $Path.ToLowerInvariant()
    if ($Cache.ContainsKey($k)) { return $Cache[$k] }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($null -eq $sig) { throw "No signature information for $Path." }
    $status = [string]$sig.Status
    if ($status -eq 'UnknownError') { throw "The signature of $Path could not be checked." }
    $subject = ''
    if ($sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject }
    $r = [pscustomobject]@{ Status = $status; Subject = $subject }
    $Cache[$k] = $r
    return $r
}

#endregion

#region Context

function Get-IgwtRegCleanProtectionContext {
    <#
    .SYNOPSIS
        Everything Test-IgwtRegCleanProtected needs (RG14): the protected set and categories, the
        lists that are read rather than copied, the user's exclusions and the live facts.
    .DESCRIPTION
        Data: data\registry\protected.json and categories.json, data\manage\services.json and
        $script:IgwtProtectedServices (Get-IgwtServiceProtection), $script:IgwtProtectedTaskPaths,
        $script:IgwtAntiCheatTaskPattern and the protected programs of data\firewall\apps.json.
        Exclusions: Get-IgwtRegCleanExclusions (an invalid file throws, so the scan refuses).
        Live facts: the TrustedInstaller SID (NTAccount.Translate), the Windows Security Center
        products, the driver providers of present devices; signatures and key security are read per
        entry with in-memory caches. A live list that cannot be read is recorded in LiveFailed, and
        every entry is then protected (RG12).
    .PARAMETER Sid
        The scanned user's SID (for HKCU variables), or empty.
    .PARAMETER Variables
        Variable set of Get-IgwtRegCleanVariableSet (built when omitted).
    .PARAMETER Probe
        The path probe scriptblock (default Test-IgwtRegCleanPathProbe).
    .PARAMETER Exclusions
        A Get-IgwtRegCleanExclusions result (read when omitted).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Sid = '', [hashtable]$Variables, [scriptblock]$Probe, $Exclusions)
    if (-not $Probe) { $Probe = { param($p, $m) Test-IgwtRegCleanPathProbe -Path $p -Mode $m } }
    if ($null -eq $Variables) { $Variables = Get-IgwtRegCleanVariableSet -Sid $Sid }
    if ($null -eq $Exclusions) { $Exclusions = Get-IgwtRegCleanExclusions }
    $protected = Get-IgwtRegCleanProtectedCatalog
    $categories = Get-IgwtRegCleanCategories
    $failed = [ordered]@{}
    $firewallPatterns = @()
    try { $firewallPatterns = @((Get-IgwtFirewallKnowledgeBase).Apps.protected | ForEach-Object { @($_.programPatterns) } | Where-Object { $_ }) }
    catch { $failed['firewallApps'] = $_.Exception.Message }
    $ti = $null
    try { $ti = Get-IgwtRegCleanTrustedInstallerSid } catch { $ti = $null }
    if (-not $ti) { $failed['trustedInstaller'] = 'the TrustedInstaller account could not be identified' }
    $products = @()
    try { $products = @(Get-IgwtRegCleanSecurityProducts | Where-Object { $_ }) } catch { $failed['securityCenter'] = $_.Exception.Message }
    $providers = @()
    try { $providers = @(Get-IgwtRegCleanPnpProviders | Where-Object { $_ }) } catch { $failed['drivers'] = $_.Exception.Message }
    $windir = ''
    if ($Variables['64'] -and $Variables['64']['SystemRoot']) { $windir = ([string]$Variables['64']['SystemRoot']).TrimEnd('\') }
    return [pscustomobject]@{
        Sid               = [string]$Sid
        Protected         = $protected
        Groups            = @($protected.groups | Where-Object { $_ })
        Roots             = @(Get-IgwtRegCleanCategoryRoots -Categories $categories)
        VendorDeny        = @($categories.denyList.vendorNames | Where-Object { $_ } | ForEach-Object { [string]$_ })
        SegmentDeny       = @($categories.denyList.segmentNames | Where-Object { $_ } | ForEach-Object { [string]$_ })
        TaskPaths         = @($script:IgwtProtectedTaskPaths)
        AntiCheatTask     = [string]$script:IgwtAntiCheatTaskPattern
        FirewallPrograms  = $firewallPatterns
        Exclusions        = @($Exclusions.Entries | Where-Object { $_ })
        TrustedInstaller  = $ti
        SecurityProducts  = $products
        DriverProviders   = $providers
        LiveFailed        = $failed
        Variables         = $Variables
        Windows           = $windir
        Probe             = $Probe
        SignatureCache    = @{}
        KeySecurityCache  = @{}
        ProbeCache        = @{}
    }
}

function Get-IgwtRegCleanProtectionFacts {
    <#
    .SYNOPSIS
        The names, value names, paths and service facts of one finding that the protection rules
        look at: {Exists; Names; ValueNames; Strings; Paths; Service; ReadError}. Read-only.
    .DESCRIPTION
        Registry kinds are read live (the key tree up to 2,000 values and 16 levels, deny-listed
        subkeys not entered; or the one value): DisplayName and Publisher of the key, the App Paths
        or Applications exe name, the Run value name, and every string value as expanded paths.
        Firewall, service and task rows use Finding.Facts (DisplayName, Group, Program, Service,
        TaskPath, Actions). Names only ever add protection (RG5).
    .PARAMETER Finding
        The finding (RG3 shape; optional Facts).
    .PARAMETER Context
        Get-IgwtRegCleanProtectionContext result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [Parameter(Mandatory = $true)]$Context)
    $facts = [pscustomobject]@{
        Exists = $false; Names = (New-Object System.Collections.Generic.List[string]); ValueNames = (New-Object System.Collections.Generic.List[string])
        Strings = (New-Object System.Collections.Generic.List[string]); Paths = (New-Object System.Collections.Generic.List[string]); Service = $null; ReadError = ''
    }
    $hive = [string]$Finding.Hive
    $view = $(if ([string]$Finding.View -eq '32') { '32' } else { '64' })
    $table = $(if ($hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables[$view] })
    if ($null -eq $table) { $table = @{} }
    $addString = {
        param($s)
        if ($null -eq $s) { return }
        foreach ($one in @($s)) {
            $t = [string]$one
            if (-not $t) { continue }
            $facts.Strings.Add($t)
            foreach ($k in 'Command', 'Folder') {
                foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $t -Kind $k -Variables $table)) { if (-not $facts.Paths.Contains($p)) { $facts.Paths.Add($p) } }
            }
        }
    }
    $addName = { param($n) if ($n -and -not $facts.Names.Contains([string]$n)) { $facts.Names.Add([string]$n) } }
    $path = ([string]$Finding.Path).Trim('\')
    $leaf = $path.Substring($path.LastIndexOf('\') + 1)
    $f = $null
    if ($Finding.PSObject.Properties['Facts']) { $f = $Finding.Facts }
    switch ([string]$Finding.Kind) {
        'regKeyTree' {
            try {
                $root = Read-IgwtRegCleanKey -Hive $hive -View $view -Path $path -Sid ([string]$Finding.Sid)
                if ($null -eq $root) { break }
                $facts.Exists = $true
                foreach ($n in 'DisplayName', 'Publisher') { if ($root.Values.ContainsKey($n)) { & $addName ([string]$root.Values[$n]) } }
                if ([string]$Finding.Category -in 'appPath', 'application') { & $addName $leaf }
                # Settings keys rarely hold DisplayName or Publisher: the vendor and product key names count too, so a
                # hardware vendor or the driver provider of a present device protects HKLM\SOFTWARE\Realtek\Audio (review RC-1).
                if ([string]$Finding.Category -eq 'softwareKey') { $after = $false; foreach ($seg in @($path -split '\\')) { if ($after -and $seg -and $seg -ne 'WOW6432Node') { & $addName $seg }; if ($seg -eq 'SOFTWARE') { $after = $true } } }
                $deny = @($Context.SegmentDeny)
                $queue = New-Object System.Collections.Generic.Queue[object]
                $queue.Enqueue(@($path, $root, 0))
                $count = 0
                while ($queue.Count -gt 0) {
                    $item = $queue.Dequeue()
                    $k = $item[1]
                    if ($null -eq $k) { $k = Read-IgwtRegCleanKey -Hive $hive -View $view -Path $item[0] -Sid ([string]$Finding.Sid) }
                    if ($null -eq $k) { continue }
                    foreach ($vn in @($k.Values.Keys)) {
                        $count++
                        if ($count -gt 2000) { break }
                        $kind = [string]$k.Kinds[$vn]
                        if ($kind -in 'String', 'ExpandString', 'MultiString') { & $addString $k.Values[$vn] }
                    }
                    if ($count -gt 2000 -or $item[2] -ge 16) { continue }
                    foreach ($sk in @($k.SubKeys)) {
                        if ($deny -contains $sk) { continue }
                        $queue.Enqueue(@(($item[0] + '\' + $sk), $null, ($item[2] + 1)))
                    }
                }
            } catch { $facts.ReadError = $_.Exception.Message }
        }
        'regValue' {
            $vn = [string]$Finding.ValueName
            if ($vn) { $facts.ValueNames.Add($vn) }
            if ([string]$Finding.Category -eq 'run') { & $addName $vn }
            try {
                $k = Read-IgwtRegCleanKey -Hive $hive -View $view -Path $path -Sid ([string]$Finding.Sid)
                if ($k -and $k.Values.ContainsKey($vn)) { $facts.Exists = $true; & $addString $k.Values[$vn] }
            } catch { $facts.ReadError = $_.Exception.Message }
        }
        default {
            $facts.Exists = $true
            if ($f) {
                foreach ($n in 'DisplayName', 'Group', 'Name') { if ($f.PSObject.Properties[$n]) { & $addName ([string]$f.$n) } }
                foreach ($n in 'Program', 'ImagePath') { if ($f.PSObject.Properties[$n]) { & $addString ([string]$f.$n) } }
                if ($f.PSObject.Properties['Actions']) { foreach ($a in @($f.Actions)) { & $addString ([string]$a) } }
                if ($f.PSObject.Properties['Service']) { $facts.Service = $f.Service }
            }
            if ($facts.Service) {
                & $addName ([string]$facts.Service.Name)
                & $addName ([string]$facts.Service.DisplayName)
                & $addString ([string]$facts.Service.ImagePath)
            }
        }
    }
    return $facts
}

#endregion

#region Protection

function Test-IgwtRegCleanNameMatch {
    <#
    .SYNOPSIS
        The first pattern that matches any of the names (case-insensitive -like), or $null.
    .PARAMETER Names
        The names to test.
    .PARAMETER Patterns
        Wildcard patterns.
    #>
    [CmdletBinding()]
    param($Names, $Patterns)
    foreach ($p in @($Patterns | Where-Object { $_ })) {
        foreach ($n in @($Names | Where-Object { $_ })) { if ([string]$n -like [string]$p) { return [string]$p } }
    }
    return $null
}

function Test-IgwtRegCleanExcluded {
    <#
    .SYNOPSIS
        The user exclusion (RG13) that covers a finding, or $null.
    .DESCRIPTION
        key: the target key or one of its parents matches the pattern; value: 'HIVE\path\name'
        matches; path: a referenced path matches the pattern or lies in the folder it names.
    .PARAMETER KeyFull
        'HIVE\path' of the finding's key ('' for rows without a key).
    .PARAMETER ValueName
        The value name (regValue findings).
    .PARAMETER Paths
        The finding's referenced paths.
    .PARAMETER Context
        The protection context.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$KeyFull, [AllowEmptyString()][string]$ValueName, $Paths, [Parameter(Mandatory = $true)]$Context)
    foreach ($e in @($Context.Exclusions)) {
        $pat = [string]$e.pattern
        switch ([string]$e.scope) {
            'key' {
                if ($KeyFull -and ($KeyFull -like $pat -or $KeyFull -like ($pat.TrimEnd('\') + '\*'))) { return $e }
            }
            'value' {
                if ($KeyFull -and $ValueName -and (($KeyFull + '\' + $ValueName) -like $pat)) { return $e }
            }
            'path' {
                $table = $Context.Variables['user']
                if ($null -eq $table) { $table = $Context.Variables['64'] }
                if ($null -eq $table) { $table = @{} }
                $x = Expand-IgwtRegCleanVariables -Text $pat -Variables $table
                if ($x.Unresolved) { continue }
                $folder = $x.Text.TrimEnd('\')
                foreach ($p in @($Paths | Where-Object { $_ })) {
                    if ([string]$p -like $x.Text) { return $e }
                    if ($folder.IndexOfAny([char[]]@('*', '?', '[')) -lt 0 -and (Test-IgwtPathUnder -Path ([string]$p) -Parent $folder)) { return $e }
                }
            }
        }
    }
    return $null
}

function Test-IgwtRegCleanProtected {
    <#
    .SYNOPSIS
        The one protection test (RG14): $null when nothing protects the finding, otherwise {Reason;
        RemovalTool; SecurityProduct; Group; Excluded}. Called at the scan, the preview and the engine.
    .DESCRIPTION
        In order: the category roots and the RG32 deny list (a key equal to a root, outside the roots,
        a deny-listed segment or Vendor); the user's exclusions (Excluded $true); security vendors
        (key, path, signer, publisher, display or service name; RemovalTool and SecurityProduct
        set); products registered with Windows Security Center; protected services (LaunchProtected
        1 or more, Early-Launch group, driver and file system types, boot and system start, image
        under Windows); the other groups of protected.json (keyPatterns with the microsoft
        categoryRootsAllowed carve-out, pathPatterns, signer, publisher, display, value, service and
        package patterns); the lists that are read, not copied (protected services, protected and
        anti-cheat task paths, data\firewall\apps.json programs); the key owner and write access
        (TrustedInstaller, or writable only by SYSTEM and TrustedInstaller); existing referenced
        files under Windows or with a matching signer; driver providers of present devices. Names
        (DisplayName, Publisher, Run value names, App Paths exe names, firewall DisplayName and
        Group) only add protection. A live check that cannot run protects the entry.
    .PARAMETER Finding
        The finding (RG3 shape; firewall, service and task rows carry Facts).
    .PARAMETER Context
        Get-IgwtRegCleanProtectionContext result.
    .EXAMPLE
        Test-IgwtRegCleanProtected -Finding $f -Context $ctx
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [Parameter(Mandatory = $true)]$Context)
    $out = {
        param($reason, $group, $vendor, $product, $excluded)
        $tool = $null
        if ($vendor -and $vendor.removalTool) { $tool = [pscustomobject]@{ Name = [string]$vendor.removalTool.name; Url = [string]$vendor.removalTool.url; Text = [string]$vendor.removalTool.text } }
        [pscustomobject]@{ Reason = [string]$reason; RemovalTool = $tool; SecurityProduct = [string]$product; Group = [string]$group; Excluded = [bool]$excluded }
    }
    $kind = [string]$Finding.Kind
    $cat = [string]$Finding.Category
    $hive = [string]$Finding.Hive
    $isReg = $kind -in 'regKeyTree', 'regValue'
    $path = ([string]$Finding.Path).Trim('\')
    $keyFull = $(if ($isReg) { $hive + '\' + $path } else { '' })

    # 1. Category roots and the RG32 deny list.
    if ($isReg) {
        if ($hive -notin 'HKLM', 'HKCU') { return (& $out 'not a registry hive the cleaner reads' 'structure' $null '' $false) }
        $view = $(if ($hive -eq 'HKCU') { '64' } else { [string]$Finding.View })
        $roots = @($Context.Roots | Where-Object { $_.Category -eq $cat -and $_.Hive -eq $hive -and $_.View -eq $view })
        $root = $null
        foreach ($r in $roots) {
            if ([string]::Equals($path, $r.Path, [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith($r.Path + '\', [StringComparison]::OrdinalIgnoreCase)) {
                if ($null -eq $root -or $r.Path.Length -gt $root.Path.Length) { $root = $r }
            }
        }
        if ($null -eq $root) { return (& $out 'outside the keys this category may remove' 'structure' $null '' $false) }
        $below = $(if ($path.Length -gt $root.Path.Length) { $path.Substring($root.Path.Length + 1) } else { '' })
        if ($kind -eq 'regKeyTree' -and -not $below) { return (& $out 'a category root is never removed' 'structure' $null '' $false) }
        $segments = @($below.Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries))
        foreach ($s in $segments) { if ($Context.SegmentDeny -contains $s) { return (& $out "contains a shared or linked key ($s)" 'denyList' $null '' $false) } }
        if ($cat -eq 'softwareKey' -and $segments.Count -gt 0 -and $Context.VendorDeny -contains $segments[0]) { return (& $out "'$($segments[0])' is never removed as a vendor key" 'denyList' $null '' $false) }
    }

    $facts = Get-IgwtRegCleanProtectionFacts -Finding $Finding -Context $Context
    $names = @($facts.Names)
    $paths = @($facts.Paths)
    $strings = @($facts.Strings)

    # 2. The user's exclusions.
    $ex = Test-IgwtRegCleanExcluded -KeyFull $keyFull -ValueName ([string]$Finding.ValueName) -Paths $paths -Context $Context
    if ($ex) { return (& $out ('Excluded by you: ' + [string]$ex.reason) 'exclusions' $null '' $true) }
    if ($facts.ReadError) { return (& $out "the entry could not be read ($($facts.ReadError))" 'live' $null '' $false) }

    $serviceNames = New-Object System.Collections.Generic.List[string]
    if ($facts.Service -and $facts.Service.Name) { $serviceNames.Add([string]$facts.Service.Name) }
    if ($cat -eq 'service' -and $Finding.PSObject.Properties['Facts'] -and $Finding.Facts -and $Finding.Facts.PSObject.Properties['Name']) { $serviceNames.Add([string]$Finding.Facts.Name) }
    $table = $(if ($hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables[$(if ([string]$Finding.View -eq '32') { '32' } else { '64' })] })
    if ($null -eq $table) { $table = @{} }
    $pathMatch = {
        param($patterns)
        foreach ($pp in @($patterns | Where-Object { $_ })) {
            $x = Expand-IgwtRegCleanVariables -Text ([string]$pp) -Variables $table
            if ($x.Unresolved) { continue }
            foreach ($p in $paths) { if ([string]$p -like $x.Text) { return [string]$pp } }
        }
        return $null
    }
    $keyMatch = {
        param($owner, $patterns)
        if (-not $isReg -or $cat -eq 'service') { return $null }
        foreach ($a in @($owner.categoryRootsAllowed | Where-Object { $_ })) {
            $al = [string]$a
            if ([string]::Equals($keyFull, $al, [StringComparison]::OrdinalIgnoreCase) -or $keyFull.StartsWith($al + '\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
        }
        foreach ($kp in @($patterns | Where-Object { $_ })) { if ($keyFull -like [string]$kp) { return [string]$kp } }
        return $null
    }

    # 3. Security vendors (RG15).
    foreach ($g in @($Context.Groups | Where-Object { $_.vendors })) {
        foreach ($v in @($g.vendors | Where-Object { $_ })) {
            $hit = & $keyMatch $v $v.keyPatterns
            if (-not $hit) { $hit = & $pathMatch $v.pathPatterns }
            if (-not $hit) { $hit = Test-IgwtRegCleanNameMatch -Names $names -Patterns (@($v.publisherPatterns) + @($v.displayNamePatterns)) }
            if (-not $hit) { $hit = Test-IgwtRegCleanNameMatch -Names $serviceNames -Patterns $v.servicePatterns }
            if ($hit) {
                $reason = $(if ([string]$v.type -eq 'consumer' -and $v.removalTool -and $v.removalTool.url) { "Use $($v.name)'s removal tool" } else { [string]$v.removalTool.text })
                return (& $out $reason ([string]$g.id) $v ([string]$v.name) $false)
            }
        }
    }

    # 4. Products registered with Windows Security Center.
    if ($Context.LiveFailed.Contains('securityCenter')) { return (& $out 'the security products registered with Windows could not be read' 'live' $null '' $false) }
    foreach ($sp in @($Context.SecurityProducts)) {
        $dn = [string]$sp.DisplayName
        $hit = $false
        if ($dn) { foreach ($n in $names) { if ([string]$n -like ($dn + '*') -or $dn -like ([string]$n + '*')) { $hit = $true; break } } }
        if (-not $hit) {
            foreach ($exe in @($sp.ProductPath, $sp.ReportingPath)) {
                foreach ($ep in @(Get-IgwtRegCleanValuePaths -Value ([string]$exe) -Kind File -Variables $Context.Variables['64'])) {
                    $dir = $ep.Substring(0, [Math]::Max(3, $ep.LastIndexOf('\')))
                    if ($dir.Length -le 3) { continue }
                    foreach ($p in $paths) { if (Test-IgwtPathUnder -Path ([string]$p) -Parent $dir) { $hit = $true } }
                }
            }
        }
        if ($hit) {
            $vendor = $null
            foreach ($g in @($Context.Groups | Where-Object { $_.vendors })) {
                foreach ($v in @($g.vendors)) { if (-not $vendor -and (Test-IgwtRegCleanNameMatch -Names @($dn) -Patterns (@($v.publisherPatterns) + @($v.displayNamePatterns)))) { $vendor = $v } }
            }
            $reason = $(if ($vendor -and $vendor.removalTool.url) { "Use $($vendor.name)'s removal tool" } elseif ($vendor) { [string]$vendor.removalTool.text } else { "Registered with Windows Security as $dn; use its vendor's removal tool" })
            return (& $out $reason 'windowsSecurity' $vendor $dn $false)
        }
    }

    # 5. Services: protected anti-malware, early-launch, drivers, boot and system start, Windows images.
    if ($facts.Service) {
        $s = $facts.Service
        $num = { param($x) $n = -1; if ($null -ne $x) { [void][int64]::TryParse([string]$x, [ref]$n) }; $n }
        $lp = & $num $s.LaunchProtected
        if ($lp -ge 1) { return (& $out 'a protected anti-malware service (LaunchProtected)' 'live' $null ([string]$s.Name) $false) }
        if ([string]$s.Group -eq 'Early-Launch') { return (& $out 'an early-launch anti-malware driver' 'live' $null ([string]$s.Name) $false) }
        $type = & $num $s.Type
        $start = & $num $s.Start
        if ($type -lt 0 -or $start -lt 0) { return (& $out 'the service type or start mode could not be read' 'live' $null '' $false) }
        if ($type -in 1, 2, 4, 8) { return (& $out 'a driver or file system service' 'live' $null '' $false) }
        if ($start -in 0, 1) { return (& $out 'starts with Windows at boot or system start' 'live' $null '' $false) }
        foreach ($p in $paths) { if ($Context.Windows -and (Test-IgwtPathUnder -Path ([string]$p) -Parent $Context.Windows)) { return (& $out 'a Windows service' 'live' $null '' $false) } }
    } elseif ($cat -eq 'service') { return (& $out 'the service facts could not be read' 'live' $null '' $false) }

    # 6. The other groups of protected.json.
    foreach ($g in @($Context.Groups | Where-Object { -not $_.vendors })) {
        $hit = & $keyMatch $g $g.keyPatterns
        if (-not $hit) { $hit = & $pathMatch $g.pathPatterns }
        if (-not $hit) { $hit = Test-IgwtRegCleanNameMatch -Names $names -Patterns (@($g.publisherPatterns) + @($g.displayNamePatterns) + @($g.packageNamePatterns)) }
        if (-not $hit) { $hit = Test-IgwtRegCleanNameMatch -Names @($facts.ValueNames) -Patterns $g.valueNamePatterns }
        if (-not $hit) { $hit = Test-IgwtRegCleanNameMatch -Names $serviceNames -Patterns $g.servicePatterns }
        if (-not $hit) {
            foreach ($id in @($g.packagePublisherIds | Where-Object { $_ })) {
                foreach ($s in $strings) { if ($s.IndexOf('_' + [string]$id, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = [string]$id } }
            }
        }
        if ($hit) { return (& $out "protected: $([string]$g.reason)" ([string]$g.id) $null '' $false) }
    }

    # 7. Lists that are read, not copied.
    foreach ($sn in $serviceNames) {
        $why = Get-IgwtServiceProtection -Name $sn
        if ($why) { return (& $out "protected service: $why" 'services' $null '' $false) }
    }
    if ($cat -eq 'task') {
        $tp = ''
        if ($Finding.PSObject.Properties['Facts'] -and $Finding.Facts -and $Finding.Facts.PSObject.Properties['TaskPath']) { $tp = [string]$Finding.Facts.TaskPath }
        if (-not $tp) { $tp = $path }
        if ($tp -like '\Microsoft\*') { return (& $out 'a Windows task' 'tasks' $null '' $false) }
        foreach ($t in @($Context.TaskPaths)) { if ($tp -like ([string]$t + '*')) { return (& $out 'a protected task' 'tasks' $null '' $false) } }
        if ($Context.AntiCheatTask -and ($tp -match $Context.AntiCheatTask -or (@($names) -join '|') -match $Context.AntiCheatTask)) { return (& $out 'an anti-cheat task' 'tasks' $null '' $false) }
    }
    if ($Context.LiveFailed.Contains('firewallApps')) { return (& $out 'the protected program list could not be read' 'live' $null '' $false) }
    foreach ($fp in @($Context.FirewallPrograms)) {
        foreach ($p in $paths) { if ([string]$p -like [string]$fp) { return (& $out 'a protected game or launcher program' 'launchers' $null '' $false) } }
    }

    # 8. Key owner and write access (registry kinds).
    if ($isReg -and $facts.Exists) {
        if (-not $Context.TrustedInstaller) { return (& $out 'the TrustedInstaller account could not be identified' 'live' $null '' $false) }
        $sid = [string]$Finding.Sid
        $ck = $keyFull + '|' + [string]$Finding.View + '|' + $sid
        $sec = $null
        if ($Context.KeySecurityCache.ContainsKey($ck)) { $sec = $Context.KeySecurityCache[$ck] }
        else {
            try { $sec = Get-IgwtRegCleanKeySecurity -Hive $hive -View $(if ([string]$Finding.View -eq '32') { '32' } else { '64' }) -Path $path -Sid $sid }
            catch { return (& $out "the key's permissions could not be read" 'live' $null '' $false) }
            $Context.KeySecurityCache[$ck] = $sec
        }
        if ($sec) {
            if ([string]$sec.Owner -eq $Context.TrustedInstaller) { return (& $out 'owned by TrustedInstaller (Windows)' 'live' $null '' $false) }
            $others = @($sec.Writers | Where-Object { $_ -and $_ -ne $script:IgwtRegCleanSystemSid -and $_ -ne $Context.TrustedInstaller })
            if ($others.Count -eq 0) { return (& $out 'only SYSTEM or TrustedInstaller may change this key' 'live' $null '' $false) }
        }
    }

    # 9. Referenced files that still exist: Windows files and signers.
    $signers = @($Context.Groups | ForEach-Object { @($_.signerPatterns) + @($_.vendors | ForEach-Object { @($_.signerPatterns) }) } | Where-Object { $_ })
    foreach ($p in $paths) {
        $pk = ([string]$p).ToLowerInvariant()
        if (-not $Context.ProbeCache.ContainsKey($pk)) {
            $raw = & $Context.Probe ([string]$p) 'Path'
            $Context.ProbeCache[$pk] = $(if ($raw -is [string]) { $raw } else { ConvertTo-IgwtRegCleanProbeState $raw })
        }
        $state = [string]$Context.ProbeCache[$pk]
        if ($state -eq 'Missing') { continue }
        if ($state -ne 'Exists') { return (& $out "$p could not be checked" 'live' $null '' $false) }
        if ($Context.Windows -and (Test-IgwtPathUnder -Path ([string]$p) -Parent $Context.Windows)) { return (& $out 'refers to a Windows file' 'microsoft' $null '' $false) }
        # A last segment without a dot is taken for a folder: folders carry no signature.
        $leafName = ([string]$p).Substring(([string]$p).LastIndexOf('\') + 1)
        if ($leafName.IndexOf('.') -lt 0) { continue }
        $sig = $null
        try { $sig = Get-IgwtRegCleanFileSigner -Path ([string]$p) -Cache $Context.SignatureCache }
        catch { return (& $out "the signature of $p could not be checked" 'live' $null '' $false) }
        if ($sig.Subject) {
            $parts = @([regex]::Split([string]$sig.Subject, ',\s*(?=[A-Za-z]+=)') | ForEach-Object { $_.Trim() })
            $hit = Test-IgwtRegCleanNameMatch -Names $parts -Patterns $signers
            if ($hit) { return (& $out "signed by a protected publisher ($hit)" 'signer' $null '' $false) }
        }
    }

    # 10. Driver providers of present devices.
    if ($Context.LiveFailed.Contains('drivers')) { return (& $out 'the drivers of present devices could not be read' 'live' $null '' $false) }
    foreach ($pv in @($Context.DriverProviders)) {
        $pn = ([string]$pv).Trim()
        if ($pn.Length -lt 3) { continue }
        foreach ($n in $names) { if ([string]$n -like ($pn + '*') -or (([string]$n).Length -ge 3 -and $pn -like ([string]$n + '*'))) { return (& $out "made by the driver provider of a present device ($pn)" 'drivers' $null '' $false) } }
    }
    return $null
}

#endregion
