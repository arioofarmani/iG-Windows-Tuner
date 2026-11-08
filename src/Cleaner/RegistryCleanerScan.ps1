# RegistryCleanerScan.ps1
# The registry cleaner's scanner (DECISIONS RG2, RG3, RG10, RG15, RG17, RG22, RG32, RG33):
# Get-IgwtRegistryLeftovers enumerates the candidates of every category read-only and
# Get-IgwtRegCleanFinding evaluates one target with the same rules at the scan, the preview and the
# engine. Every referenced path goes through Resolve-IgwtRegCleanPath, ownership through
# Test-IgwtRegCleanOwned and protection through Test-IgwtRegCleanProtected. A step that answers
# Unknown drops the entry; only Safe, Review and Protected (security software) are ever returned.
# Read-only: registry keys are opened with writable $false, firewall rules are read from the
# persistent store, services and tasks are only reported. Nothing here writes a file or a cache.

$script:IgwtRegCleanScanOrder = @('uninstall', 'appPath', 'progId', 'application', 'openWith', 'run', 'softwareKey', 'firewallRule', 'service', 'task')
$script:IgwtRegCleanCategoryLabels = @{
    uninstall = 'Uninstall entries'; appPath = 'App Paths'; progId = 'File type handlers'; application = 'Open with applications'
    openWith = 'Open with lists'; run = 'Run and RunOnce'; softwareKey = 'Software keys'; firewallRule = 'Firewall rules'
    service = 'Services'; task = 'Scheduled tasks'
}
$script:IgwtRegCleanMaxTreeValues = 2000
$script:IgwtRegCleanMaxTreeBytes = 524288
$script:IgwtRegCleanMaxTreeKeys = 2000
$script:IgwtRegCleanOwnerSids = @('S-1-5-18', 'S-1-5-32-544')
$script:IgwtRegCleanNotAdminNote = 'Some entries cannot be checked without administrator rights and are not shown'
$script:IgwtRegCleanServiceReason = 'iG does not remove services; you can disable it in Manage.'
$script:IgwtRegCleanTaskReason = 'iG does not remove scheduled tasks; you can disable it in Manage.'
$script:IgwtRegCleanInstallerProducts = 'SOFTWARE\Classes\Installer\Products'
# Per-user Windows Installer product registrations (UNVERIFIED location, DECISIONS RG10).
$script:IgwtRegCleanUserInstallerProducts = 'Software\Microsoft\Installer\Products'

#region Helpers

function Get-IgwtRegCleanTargetKey {
    <#
    .SYNOPSIS
        The target key of one finding (RG16): 'regclean|<kind>|<hive>|<sid or ->|<view>|<path>' plus
        '|<value name or rule name>' for values and firewall rules.
    .PARAMETER Kind
        regKeyTree, regValue, firewallRule or reportOnly.
    .PARAMETER Hive
        HKLM, HKCU or '' (firewall rules and tasks).
    .PARAMETER Sid
        The user SID for HKCU, otherwise ''.
    .PARAMETER View
        64, 32 or ''.
    .PARAMETER Path
        Key path below the hive (task path for tasks).
    .PARAMETER Name
        The value name or the firewall rule name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Kind, [AllowEmptyString()][string]$Hive = '', [AllowEmptyString()][string]$Sid = '', [AllowEmptyString()][string]$View = '',
        [AllowEmptyString()][string]$Path = '', [AllowEmptyString()][string]$Name = '')
    $s = $(if ($Sid) { $Sid } else { '-' })
    $k = 'regclean|' + $Kind + '|' + $Hive + '|' + $s + '|' + $View + '|' + $Path
    if ($Kind -in 'regValue', 'firewallRule') { $k = $k + '|' + $Name }
    return $k
}

function Get-IgwtRegCleanFindingId {
    <#
    .SYNOPSIS
        A finding id: the first 16 hex characters (lower case) of the SHA256 of the target key (RG3).
    .PARAMETER TargetKey
        Get-IgwtRegCleanTargetKey result.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$TargetKey)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($TargetKey.ToLowerInvariant()))
        return ((-join ($bytes | ForEach-Object { $_.ToString('x2') })).Substring(0, 16))
    } finally { $sha.Dispose() }
}

function ConvertTo-IgwtRegCleanEvidence {
    <#
    .SYNOPSIS
        One evidence row {Check; Result; Detail} (RG3).
    .PARAMETER Check
        What was checked, for example PathMissing.
    .PARAMETER Result
        Pass, Review or Protected.
    .PARAMETER Detail
        Plain text proof.
    #>
    [CmdletBinding()]
    param([string]$Check, [string]$Result = 'Pass', [AllowEmptyString()][string]$Detail = '')
    return [pscustomobject]@{ Check = $Check; Result = $Result; Detail = $Detail }
}

function Resolve-IgwtRegCleanPointer {
    <#
    .SYNOPSIS
        Resolves one registry pointer with the scan's drive table, probe and the owner's variables
        (RG6, RG7): the Resolve-IgwtRegCleanPath result. HKCU pointers use the scanned user's table;
        without it the answer is Unknown. MSI product codes use the owners index cache.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Value
        The raw registry data.
    .PARAMETER Kind
        Command, File or Folder.
    .PARAMETER Hive
        HKLM, HKCU or '' (firewall rules, services, tasks: the machine table).
    .PARAMETER View
        64, 32 or '' (shared key or unsure: every WOW64 candidate).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [AllowEmptyString()][AllowNull()][string]$Value, [ValidateSet('Command', 'File', 'Folder')][string]$Kind = 'Command',
        [AllowEmptyString()][string]$Hive = '', [ValidateSet('64', '32', '')][AllowEmptyString()][string]$View = '')
    $table = $(if ($Hive -eq 'HKCU') { $Context.Variables['user'] } elseif ($View -eq '32') { $Context.Variables['32'] } else { $Context.Variables['64'] })
    if ($null -eq $table) { return [pscustomobject]@{ Status = 'Unknown'; Candidates = @(); Reason = 'the per-user folders of this entry are not known' } }
    $regCleanMsiIndex = $Context.Index
    $productState = { param($code) Get-IgwtRegCleanIndexProductState -Index $regCleanMsiIndex -ProductCode $code }
    $user = $(if ($Hive -eq 'HKCU') { [string]$Context.Sid } else { '' })
    return (Resolve-IgwtRegCleanPath -Value $Value -Kind $Kind -View $View -User $user -DriveTable $Context.DriveTable -Probe $Context.Probe -Variables $table -ProductState $productState)
}

function Add-IgwtRegCleanPointerEvidence {
    <#
    .SYNOPSIS
        Adds the evidence of one Missing pointer and returns ''; returns the skip code instead when
        the pointer exists ('exists'), cannot be checked ('unknown') or cannot be proven
        ('unprovable').
    .PARAMETER Evidence
        The finding's evidence list.
    .PARAMETER Result
        Resolve-IgwtRegCleanPointer result.
    .PARAMETER Check
        The evidence check name.
    .PARAMETER Value
        The raw value (shown in the evidence).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence, [Parameter(Mandatory = $true)]$Result,
        [string]$Check, [AllowEmptyString()][string]$Value)
    switch ([string]$Result.Status) {
        'Missing' { $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check $Check -Detail ($Value.Trim() + ' - ' + [string]$Result.Reason))); return '' }
        'Exists' { return 'exists' }
        'Unknown' { return 'unknown' }
    }
    return 'unprovable'
}

function Test-IgwtRegCleanHostCommand {
    <#
    .SYNOPSIS
        True when a command line runs a host program (rundll32, msiexec, script hosts; RG6 step 6), so
        the evidence is a payload and the entry is Review at most.
    .PARAMETER Value
        The raw command line.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if (-not $Value) { return $false }
    $split = Split-IgwtRegCleanCommandLine -Text $Value.Trim() -ProgramOnly
    $leaf = ([string]$split.Program).TrimEnd('\')
    $leaf = ($leaf.Substring($leaf.LastIndexOf('\') + 1) -replace '(?i)\.exe$', '').ToLowerInvariant()
    return ($script:IgwtRegCleanHostPrograms -contains $leaf)
}

function Get-IgwtRegCleanDataPathKind {
    <#
    .SYNOPSIS
        How a data value of a Software key is resolved: 'Command' (quoted program, or a file name
        followed by arguments), 'File' (a path with a ',<index>' resource part), 'Folder' (any other
        absolute path), or '' when the value is not an absolute path.
    .PARAMETER Text
        The raw value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $t = $(if ($Text) { $Text.Trim() } else { '' })
    if (-not $t) { return '' }
    $abs = '^(%[^%\\]+%|[A-Za-z]:)\\'
    if ($t.StartsWith('"')) { if ($t.Substring(1) -match $abs) { return 'Command' }; return '' }
    if ($t -notmatch $abs) { return '' }
    if ($t -match ',\s*-?\d+$') { return 'File' }
    if ($t -match '\.[A-Za-z0-9]{1,4}\s+\S') { return 'Command' }
    return 'Folder'
}

function ConvertTo-IgwtRegCleanPackedGuid {
    <#
    .SYNOPSIS
        The packed form of an MSI product code used as the key name under Installer\Products (the
        first three groups reversed, every byte of the last two groups swapped; UNVERIFIED, not on
        Learn, RG10). '' for a value that is not a {GUID}.
    .PARAMETER ProductCode
        A {GUID} product code.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$ProductCode)
    if ($ProductCode -notmatch $script:IgwtRegCleanGuidPattern) { return '' }
    $g = $ProductCode.Trim('{', '}').ToUpperInvariant().Split('-')
    $rev = { param($s) -join ($s.ToCharArray()[($s.Length - 1)..0]) }
    $swap = { param($s) $sb = New-Object System.Text.StringBuilder; for ($i = 0; $i -lt $s.Length; $i += 2) { $null = $sb.Append($s[$i + 1]).Append($s[$i]) }; $sb.ToString() }
    return ((& $rev $g[0]) + (& $rev $g[1]) + (& $rev $g[2]) + (& $swap $g[3]) + (& $swap $g[4]))
}

function Get-IgwtRegCleanTreeInfo {
    <#
    .SYNOPSIS
        One key tree as the cleaner would back it up (RG17): {Exists; Keys (relative, sorted
        ordinally, '' = root); SubKeys; ValueCount; Bytes; Strings ({Key; Name; Data}); Selectable;
        Reason}. Read-only.
    .DESCRIPTION
        Not selectable ('cannot be backed up exactly') when a value has a kind .NET cannot write back,
        the tree holds more than 2,000 values, 2,000 keys or 512 KB of data, or a subkey cannot be
        opened; not selectable ('contains a shared or linked key') when a subkey name is on the RG32
        deny list (it is not entered); not selectable when a key has its own permissions (protected
        ACL or an explicit ACE) or an owner other than SYSTEM, Administrators or the scanned user, or
        when its permissions cannot be read. Throws when the root cannot be read.
    .PARAMETER Hive
        HKLM or HKCU.
    .PARAMETER View
        64 or 32.
    .PARAMETER Path
        Key path below the hive.
    .PARAMETER Sid
        The user SID for HKCU keys.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result (deny list).
    .PARAMETER SkipSecurity
        Do not read the permissions (an evidence pass that only needs the values; the finding reads
        the tree again with its permissions).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Hive, [string]$View = '64', [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$Sid = '', [Parameter(Mandatory = $true)]$Context, [switch]$SkipSecurity)
    $info = [pscustomobject]@{
        Exists = $false; Keys = @(); SubKeys = @(); ValueCount = 0; Bytes = 0
        Strings = (New-Object System.Collections.Generic.List[object]); Selectable = $true; Reason = ''
    }
    $fail = { param($why) if ($info.Selectable) { $info.Selectable = $false; $info.Reason = $why } }
    $exact = 'cannot be backed up exactly'
    $root = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path $Path -Sid $Sid
    if ($null -eq $root) { return $info }
    $info.Exists = $true
    $info.SubKeys = @($root.SubKeys)
    $keys = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@('', $root))
    $owners = @($script:IgwtRegCleanOwnerSids) + @($(if ($Sid) { $Sid }))
    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $rel = [string]$item[0]
        $full = $(if ($rel) { $Path + '\' + $rel } else { $Path })
        $k = $item[1]
        if ($null -eq $k) {
            try { $k = Read-IgwtRegCleanKey -Hive $Hive -View $View -Path $full -Sid $Sid } catch { & $fail "$exact (a subkey cannot be opened)"; continue }
            if ($null -eq $k) { continue }
        }
        $keys.Add($rel)
        if ($keys.Count -gt $script:IgwtRegCleanMaxTreeKeys) { & $fail "$exact (more than 2,000 keys)"; break }
        foreach ($vn in @($k.Values.Keys)) {
            $info.ValueCount++
            $data = $k.Values[$vn]
            switch ([string]$k.Kinds[$vn]) {
                { $_ -in 'String', 'ExpandString' } { $info.Bytes += 2 * (([string]$data).Length + 1); $info.Strings.Add([pscustomobject]@{ Key = $rel; Name = [string]$vn; Data = [string]$data }) }
                'MultiString' { foreach ($s in @($data)) { $info.Bytes += 2 * (([string]$s).Length + 1); $info.Strings.Add([pscustomobject]@{ Key = $rel; Name = [string]$vn; Data = [string]$s }) } }
                'DWord' { $info.Bytes += 4 }
                'QWord' { $info.Bytes += 8 }
                { $_ -in 'Binary', 'None' } { if ($data -is [byte[]]) { $info.Bytes += $data.Length } }
                default { & $fail "$exact (a value of a kind that cannot be restored)" }
            }
        }
        if ($info.ValueCount -gt $script:IgwtRegCleanMaxTreeValues -or $info.Bytes -gt $script:IgwtRegCleanMaxTreeBytes) { & $fail "$exact (more than 2,000 values or 512 KB)"; break }
        $sec = $null
        if (-not $SkipSecurity) { try { $sec = Get-IgwtRegCleanKeySecurity -Hive $Hive -View $View -Path $full -Sid $Sid } catch { & $fail "the permissions of a key cannot be read" } }
        if ($sec) {
            if ($sec.AclProtected -or $sec.HasExplicitAce) { & $fail 'a key has its own permissions' }
            elseif ($owners -notcontains [string]$sec.Owner) { & $fail 'a key is owned by another account' }
        }
        foreach ($sk in @($k.SubKeys)) {
            if ($Context.SegmentDeny -contains $sk) { & $fail "contains a shared or linked key ($sk)"; continue }
            $queue.Enqueue(@($(if ($rel) { $rel + '\' + $sk } else { [string]$sk }), $null))
        }
    }
    $arr = $keys.ToArray()
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    $info.Keys = $arr
    return $info
}

#endregion

#region Scan context and shared lists

function Get-IgwtRegCleanScanContext {
    <#
    .SYNOPSIS
        Everything one scan (or one re-check) needs, built once: the scanned user (RG33), variable
        tables (RG7), drive table (RG9), owners index (RG4), protection context with exclusions
        (RG14), category roots, deny lists and per-scan caches. Read-only.
    .DESCRIPTION
        Refuses (throws) in a 32-bit process and when the exclusion list is invalid. The scan id is
        new for every context.
    #>
    [CmdletBinding()]
    param()
    if (-not (Test-IgwtRegCleanProcess64)) { throw 'The registry cleaner needs 64-bit PowerShell; start iG Windows Tuner from the 64-bit Windows PowerShell.' }
    $user = Get-IgwtRegCleanScanUser
    $sid = $(if ($user.Sid) { [string]$user.Sid } else { '' })
    $vars = Get-IgwtRegCleanVariableSet -Sid $sid
    $probe = { param($p, $m) Test-IgwtRegCleanPathProbe -Path $p -Mode $m }
    $protection = Get-IgwtRegCleanProtectionContext -Sid $sid -Variables $vars -Probe $probe
    $drives = Get-IgwtRegCleanDriveTable -Probe $probe
    $index = Get-IgwtRegCleanOwnerIndex -Sid $sid -DriveTable $drives -Probe $probe -Variables $vars
    $categories = Get-IgwtRegCleanCategories
    $kinds = @{}
    foreach ($c in @($categories.categories | Where-Object { $_ })) { $kinds[[string]$c.id] = [string]$c.kind }
    $notes = New-Object System.Collections.Generic.List[string]
    $noteList = New-Object System.Collections.Generic.List[string]
    $noteList.Add([string]$user.Note)
    foreach ($n in $index.Notes) { $noteList.Add([string]$n) }
    foreach ($n in @($drives.Notes)) { $noteList.Add([string]$n) }
    foreach ($n in $noteList) { if ($n -and -not $notes.Contains([string]$n)) { $notes.Add([string]$n) } }
    $elevated = [bool](Test-IgwtIsAdmin)
    if (-not $elevated -and -not $notes.Contains($script:IgwtRegCleanNotAdminNote)) { $notes.Add($script:IgwtRegCleanNotAdminNote) }
    return [pscustomobject]@{
        ScanId             = [guid]::NewGuid().ToString('N')
        Sid                = $sid
        User               = $user
        Elevated           = $elevated
        Variables          = $vars
        Probe              = $probe
        DriveTable         = $drives
        Index              = $index
        Protection         = $protection
        Roots              = @(Get-IgwtRegCleanCategoryRoots -Categories $categories)
        Kinds              = $kinds
        SegmentDeny        = @($protection.SegmentDeny)
        VendorDeny         = @($protection.VendorDeny)
        Notes              = $notes
        EvalCache          = @{}
        EntryPoints        = $null
        ClassNames         = $null
        ExtRefs            = $null
        FirewallSignatures = @{}
        FirewallContext    = $null
    }
}

function Get-IgwtRegCleanEntryPoints {
    <#
    .SYNOPSIS
        The files that App Paths, Run and RunOnce values and services point to (expanded paths),
        read once per scan for the Uninstall vendor-folder test (RG10): {Path; Hive; View; Source}.
        Throws when a list cannot be read, so the dependent entries are not shown.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)
    if ($null -ne $Context.EntryPoints) { return $Context.EntryPoints }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Context.Roots | Where-Object { $_.Category -in 'appPath', 'run' })) {
        if ($r.Hive -eq 'HKCU' -and -not $Context.Sid) { continue }
        $table = $(if ($r.Hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables[$r.View] })
        if ($null -eq $table) { $table = @{} }
        $sid = $(if ($r.Hive -eq 'HKCU') { $Context.Sid } else { '' })
        $key = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path $r.Path -Sid $sid
        if ($null -eq $key) { continue }
        $add = { param($p, $src) $list.Add([pscustomobject]@{ Path = $p; Hive = $r.Hive; View = $r.View; Source = $src }) }
        if ($r.Category -eq 'run') {
            foreach ($vn in @($key.Values.Keys)) {
                if ([string]$key.Kinds[$vn] -notin 'String', 'ExpandString') { continue }
                foreach ($p in @(Get-IgwtRegCleanValuePaths -Value ([string]$key.Values[$vn]) -Kind Command -Variables $table)) { & $add $p ($r.Full + '\' + $vn) }
            }
        } else {
            foreach ($sk in @($key.SubKeys)) {
                $k = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path ($r.Path + '\' + $sk) -Sid $sid
                if ($null -eq $k) { continue }
                if ($k.Values.ContainsKey('')) { foreach ($p in @(Get-IgwtRegCleanValuePaths -Value ([string]$k.Values['']) -Kind File -Variables $table)) { & $add $p ($r.Full + '\' + $sk) } }
                if ($k.Values.ContainsKey('Path')) {
                    foreach ($part in @(([string]$k.Values['Path']).Split(';'))) {
                        foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $part -Kind Folder -Variables $table)) { & $add $p ($r.Full + '\' + $sk) }
                    }
                }
            }
        }
    }
    $sys = $Context.Variables['64']
    if ($null -eq $sys) { $sys = @{} }
    foreach ($s in $Context.Index.Services) {
        if ($null -eq $s -or -not $s.ImagePath) { continue }
        foreach ($p in @(Get-IgwtRegCleanValuePaths -Value ([string]$s.ImagePath) -Kind Command -Variables $sys)) {
            $list.Add([pscustomobject]@{ Path = $p; Hive = 'HKLM'; View = '64'; Source = 'service ' + [string]$s.Name })
        }
    }
    $Context.EntryPoints = $list.ToArray()
    return $Context.EntryPoints
}

function Get-IgwtRegCleanClassNames {
    <#
    .SYNOPSIS
        The subkey names of HKLM\SOFTWARE\Classes and the scanned user's Software\Classes, read once
        per scan: @{ HKLM = HashSet; HKCU = HashSet or $null when per-user entries are not read }.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)
    if ($null -ne $Context.ClassNames) { return $Context.ClassNames }
    $names = @{ HKLM = $null; HKCU = $null }
    foreach ($r in @($Context.Roots | Where-Object { $_.Category -eq 'progId' })) {
        if ($r.Hive -eq 'HKCU' -and -not $Context.Sid) { continue }
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $key = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path $r.Path -Sid $(if ($r.Hive -eq 'HKCU') { $Context.Sid } else { '' })
        if ($key) { foreach ($n in @($key.SubKeys)) { $null = $set.Add([string]$n) } }
        $names[$r.Hive] = $set
    }
    $Context.ClassNames = $names
    return $names
}

function Get-IgwtRegCleanClassesIndex {
    <#
    .SYNOPSIS
        For every ProgID that a file extension names (its (Default) value or an OpenWithProgids value
        name), the other ProgIDs the same extension names: progid (lower case) -> list of
        {Hive; Ext; Others}. Read once per scan, only when a ProgID candidate needs it.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)
    if ($null -ne $Context.ExtRefs) { return $Context.ExtRefs }
    $refs = @{}
    $names = Get-IgwtRegCleanClassNames -Context $Context
    foreach ($r in @($Context.Roots | Where-Object { $_.Category -eq 'progId' })) {
        $set = $names[$r.Hive]
        if ($null -eq $set) { continue }
        $sid = $(if ($r.Hive -eq 'HKCU') { $Context.Sid } else { '' })
        foreach ($ext in @($set | Where-Object { $_.StartsWith('.') })) {
            $k = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path ($r.Path + '\' + $ext) -Sid $sid
            if ($null -eq $k) { continue }
            $named = New-Object System.Collections.Generic.List[string]
            if ($k.Values.ContainsKey('') -and [string]$k.Values['']) { $named.Add([string]$k.Values['']) }
            $ow = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path ($r.Path + '\' + $ext + '\OpenWithProgids') -Sid $sid
            if ($ow) { foreach ($vn in @($ow.Values.Keys)) { if ($vn -and -not $named.Contains([string]$vn)) { $named.Add([string]$vn) } } }
            foreach ($n in $named) {
                $lk = $n.ToLowerInvariant()
                if (-not $refs.ContainsKey($lk)) { $refs[$lk] = New-Object System.Collections.Generic.List[object] }
                $refs[$lk].Add([pscustomobject]@{ Hive = $r.Hive; Ext = $ext; Others = @($named | Where-Object { $_ -ne $n }) })
            }
        }
    }
    $Context.ExtRefs = $refs
    return $refs
}

function Get-IgwtRegCleanFirewallRows {
    <#
    .SYNOPSIS
        Firewall rules of the persistent store that name a program on an online fixed drive, joined
        with Join-IgwtFirewallData -PathExists { $true } (RG22): {Rows; Dropped (counts)}. Read-only.
    .DESCRIPTION
        Reads Get-NetFirewallRule and Get-NetFirewallApplicationFilter (-PolicyStore PersistentStore).
        UNC and network programs, programs with a variable that cannot be expanded, relative names
        and programs on a drive that is not an online fixed drive are dropped before anything else,
        so no file or share is ever touched for them. Get-IgwtFirewallInventory is not used: its own
        probe would test every program path. The program is evaluated later only by the resolver.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Name
        One rule name (re-check of a single finding); all rules when empty.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [AllowEmptyString()][string]$Name = '')
    $drop = [ordered]@{}
    $count = { param($k) if ($drop.Contains($k)) { $drop[$k]++ } else { $drop[$k] = 1 } }
    $rules = @()
    if ($Name) {
        try { $rules = @(Get-NetFirewallRule -Name $Name -PolicyStore PersistentStore -ErrorAction Stop) }
        catch { if ([string]$_.CategoryInfo.Category -eq 'ObjectNotFound') { $rules = @() } else { throw } }
    } else { $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop) }
    $rules = @($rules | Where-Object { $_ })
    if ($rules.Count -eq 0) { return [pscustomobject]@{ Rows = @(); Dropped = $drop } }
    $idOf = { param($x) $(if ([string]$x.InstanceID) { [string]$x.InstanceID } else { [string]$x.Name }) }
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $rules) { $null = $ids.Add((& $idOf $r)) }
    $machine = $Context.Variables['64']
    if ($null -eq $machine) { $machine = @{} }
    $online = @($Context.DriveTable.Online | ForEach-Object { ([string]$_).ToUpperInvariant() })
    $keptFilters = New-Object System.Collections.Generic.List[object]
    $keptIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @(Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -ErrorAction Stop)) {
        if ($null -eq $f) { continue }
        $id = [string]$f.InstanceID
        if (-not $ids.Contains($id)) { continue }
        $prog = $(if ([string]$f.Program) { [string]$f.Program } elseif ($f.PSObject.Properties['AppPath']) { [string]$f.AppPath } else { '' })
        $prog = $prog.Trim().Trim('"')
        if (-not $prog -or $prog -in 'Any', 'System') { continue }
        if ($prog.StartsWith('\\') -or $prog.StartsWith('//')) { & $count 'network'; continue }
        $x = Expand-IgwtRegCleanVariables -Text $prog -Variables $machine
        if ($x.Unresolved) { & $count 'unknown'; continue }
        if ($x.Text -notmatch '^[A-Za-z]:\\') { & $count 'unprovable'; continue }
        if (Test-IgwtNetworkPath -Path $x.Text) { & $count 'network'; continue }
        if ($online -notcontains $x.Text.Substring(0, 1).ToUpperInvariant()) { & $count 'drive'; continue }
        $keptFilters.Add($f)
        $null = $keptIds.Add($id)
    }
    $keptRules = @($rules | Where-Object { $keptIds.Contains((& $idOf $_)) })
    if ($keptRules.Count -eq 0) { return [pscustomobject]@{ Rows = @(); Dropped = $drop } }
    $rows = Join-IgwtFirewallData -Rules $keptRules -ApplicationFilters $keptFilters.ToArray() -PathExists { $true }
    $rows = @($rows | Where-Object { $_ })
    return [pscustomobject]@{ Rows = $rows; Dropped = $drop }
}

function Get-IgwtRegCleanTaskList {
    <#
    .SYNOPSIS
        Scheduled tasks with their actions (Get-ScheduledTask): {TaskPath; TaskName; Path; State;
        Actions ({Kind Exec|ComHandler|Other; Execute; Arguments})}. Read-only.
    .PARAMETER Path
        One task path (folder plus name) to return; all tasks when empty.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path = '')
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        if ($null -eq $t) { continue }
        $full = [string]$t.TaskPath + [string]$t.TaskName
        if ($Path -and -not [string]::Equals($full, $Path, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $actions = @(foreach ($a in @($t.Actions)) {
                if ($null -eq $a) { continue }
                if ($a.PSObject.Properties['Execute'] -and [string]$a.Execute) {
                    $arg = $(if ($a.PSObject.Properties['Arguments']) { [string]$a.Arguments } else { '' })
                    [pscustomobject]@{ Kind = 'Exec'; Execute = [string]$a.Execute; Arguments = $arg }
                } elseif ($a.PSObject.Properties['ClassId'] -and [string]$a.ClassId) {
                    [pscustomobject]@{ Kind = 'ComHandler'; Execute = ''; Arguments = '' }
                } else { [pscustomobject]@{ Kind = 'Other'; Execute = ''; Arguments = '' } }
            })
        [pscustomobject]@{ TaskPath = [string]$t.TaskPath; TaskName = [string]$t.TaskName; Path = $full; State = [string]$t.State; Actions = $actions }
    }
}

#endregion

#region Per-category evidence (RG10)

function Get-IgwtRegCleanUninstallEvidence {
    <#
    .SYNOPSIS
        RG10 Uninstall entry: Safe only for a non-MSI, non-hidden entry whose uninstaller is Missing
        AND a second independent pointer (InstallLocation, or a DisplayIcon outside the uninstaller's
        folder) is Missing, with no program folder and no App Paths, Run or service entry in the
        vendor's folder; Review otherwise. Returns a draft hashtable (Skip or the finding fields).
    .PARAMETER Target
        The normalized target.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    $k = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path $t.Path -Sid $t.Sid
    if ($null -eq $k) { return @{ Skip = 'gone'; Detail = 'the key no longer exists' } }
    if ($t.Below.Count -ne 1) { return @{ Skip = 'notApplicable'; Detail = 'not an Uninstall entry' } }
    $name = $t.Leaf
    $text = { param($n) if ($k.Values.ContainsKey($n) -and $null -ne $k.Values[$n]) { [string]$k.Values[$n] } else { '' } }
    $un = & $text 'UninstallString'
    if (-not $un.Trim()) { return @{ Skip = 'unprovable'; Detail = 'no uninstall command' } }
    $rv = $(if ($t.Hive -eq 'HKLM') { [string]$t.View } else { '' })
    $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $un -Kind Command -Hive $t.Hive -View $rv) -Check 'UninstallerMissing' -Value $un
    if ($s) { return @{ Skip = $s; Detail = 'uninstall command' } }
    $quiet = & $text 'QuietUninstallString'
    if ($quiet.Trim()) {
        $q = Resolve-IgwtRegCleanPointer -Context $Context -Value $quiet -Kind Command -Hive $t.Hive -View $rv
        if ($q.Status -eq 'Exists') { return @{ Skip = 'exists'; Detail = 'quiet uninstall command' } }
        if ($q.Status -eq 'Unknown') { return @{ Skip = 'unknown'; Detail = 'quiet uninstall command' } }
    }
    $num = { param($n) $v = 0; [void][int]::TryParse((& $text $n), [ref]$v); $v }
    $isGuid = $name -match $script:IgwtRegCleanGuidPattern
    $wi = (& $num 'WindowsInstaller') -eq 1
    $sc = (& $num 'SystemComponent') -eq 1
    $parent = & $text 'ParentKeyName'
    $bundle = & $text 'BundleProviderKey'
    $hostCmd = Test-IgwtRegCleanHostCommand -Value $un
    $code = ''
    if ($isGuid) { $code = $name.ToUpperInvariant() }
    else {
        $m = [regex]::Match($un, '(?i)msiexec(\.exe)?"?\s.*?[/-][xi]\s*"?(\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\})')
        if ($m.Success) { $code = $m.Groups[2].Value.ToUpperInvariant() }
    }
    $review = New-Object System.Collections.Generic.List[string]
    if ($code) {
        $state = $null
        try { $state = Get-IgwtRegCleanIndexProductState -Index $Context.Index -ProductCode $code } catch { return @{ Skip = 'unknown'; Detail = 'Windows Installer state' } }
        $n = 0
        if (-not [int]::TryParse([string](@($state) | Select-Object -Last 1), [ref]$n)) { return @{ Skip = 'unknown'; Detail = 'Windows Installer state' } }
        if ($n -ne -1) { return @{ Skip = 'exists'; Detail = "Windows Installer reports $code as installed" } }
        $packed = ConvertTo-IgwtRegCleanPackedGuid -ProductCode $code
        try {
            if (Read-IgwtRegCleanKey -Hive HKLM -View 64 -Path ($script:IgwtRegCleanInstallerProducts + '\' + $packed)) { return @{ Skip = 'exists'; Detail = 'Windows Installer product registration' } }
            if ($Context.Sid -and (Read-IgwtRegCleanKey -Hive HKCU -Path ($script:IgwtRegCleanUserInstallerProducts + '\' + $packed) -Sid $Context.Sid)) { return @{ Skip = 'exists'; Detail = 'Windows Installer product registration' } }
        } catch { return @{ Skip = 'unknown'; Detail = 'Windows Installer product registration' } }
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'MsiNotInstalled' -Detail "Windows Installer does not know product $code and has no product registration for it"))
        $review.Add('a Windows Installer entry')
    }
    $table = $(if ($t.Hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables[$t.View] })
    if ($null -eq $table) { $table = @{} }
    $folderOf = { param($p) $i = $p.LastIndexOf('\'); if ($i -gt 2) { $p.Substring(0, $i) } else { '' } }
    $unPaths = @(Get-IgwtRegCleanValuePaths -Value $un -Kind Command -Variables $table)
    $unFolder = $(if ($unPaths.Count) { & $folderOf ([string]$unPaths[0]) } else { '' })
    $second = $false
    $il = & $text 'InstallLocation'
    $ilPaths = @()
    if ($il.Trim()) {
        $r = Resolve-IgwtRegCleanPointer -Context $Context -Value $il -Kind Folder -Hive $t.Hive -View $rv
        $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result $r -Check 'InstallFolderMissing' -Value $il
        if ($s -and $s -ne 'unprovable') { return @{ Skip = $s; Detail = 'install folder' } }
        if (-not $s) { $second = $true; $ilPaths = @(Get-IgwtRegCleanValuePaths -Value $il -Kind Folder -Variables $table) }
    }
    $icon = & $text 'DisplayIcon'
    $iconPaths = @()
    if ($icon.Trim()) {
        $r = Resolve-IgwtRegCleanPointer -Context $Context -Value $icon -Kind File -Hive $t.Hive -View $rv
        if ($r.Status -eq 'Exists') { return @{ Skip = 'exists'; Detail = 'display icon' } }
        if ($r.Status -eq 'Unknown') { return @{ Skip = 'unknown'; Detail = 'display icon' } }
        if ($r.Status -eq 'Missing') {
            $iconPaths = @(Get-IgwtRegCleanValuePaths -Value $icon -Kind File -Variables $table)
            $outside = $iconPaths.Count -gt 0 -and -not ($unFolder -and (Test-IgwtPathUnder -Path ([string]$iconPaths[0]) -Parent $unFolder))
            if ($outside) { $null = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result $r -Check 'IconMissing' -Value $icon; $second = $true }
        }
    }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{
            Category = 'uninstall'; Hive = $t.Hive; View = $t.View; KeyName = $name; ProductCode = $code
            Paths = @(@($unPaths) + @($ilPaths) + @($iconPaths) + @(Get-IgwtRegCleanValuePaths -Value $quiet -Kind Command -Variables $table))
            Self = ('uninstall|' + $t.Hive + '|' + $t.View + '|' + $name)
        })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    # Vendor folders: the folders of the entry and their parents, never a shared parent.
    $vendor = New-Object System.Collections.Generic.List[string]
    foreach ($f in @(@($ilPaths) + @($unFolder))) {
        if (-not $f) { continue }
        foreach ($c in @(([string]$f).TrimEnd('\'), (& $folderOf (([string]$f).TrimEnd('\'))))) {
            if ($c -and $c.Length -gt 3 -and -not $Context.Index.Broad.Contains($c) -and -not $vendor.Contains($c)) { $vendor.Add($c) }
        }
    }
    if ($vendor.Count -gt 0) {
        $eps = $null
        try { $eps = @(Get-IgwtRegCleanEntryPoints -Context $Context) } catch { return @{ Skip = 'unknown'; Detail = 'App Paths, Run or service list' } }
        foreach ($ep in $eps) {
            if (-not @($vendor | Where-Object { Test-IgwtPathUnder -Path ([string]$ep.Path) -Parent $_ }).Count) { continue }
            $r = Resolve-IgwtRegCleanPointer -Context $Context -Value ([string]$ep.Path) -Kind File -Hive $ep.Hive -View ''
            if ($r.Status -eq 'Exists') { return @{ Skip = 'vendorFolder'; Detail = "$($ep.Source) points to an existing file of the same vendor" } }
            if ($r.Status -ne 'Missing') { return @{ Skip = 'unknown'; Detail = "$($ep.Source) could not be checked" } }
        }
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoVendorEntryPoint' -Detail ('no App Paths, Run or service entry points to an existing file in ' + ($vendor -join ', '))))
    }
    if ($isGuid -and -not $code) { $review.Add('a product-code entry') }
    if ($wi) { $review.Add('a Windows Installer entry') }
    if ($sc) { $review.Add('hidden from Apps (SystemComponent)') }
    if ($parent) { $review.Add('part of another entry (ParentKeyName)') }
    if ($bundle) { $review.Add('part of an installer bundle (BundleProviderKey)') }
    if ($hostCmd) { $review.Add('the uninstall command runs through a host program') }
    if (-not $second) { $review.Add('only the uninstaller is missing (it may be a cached copy)') }
    $conf = 'Safe'
    if ($review.Count -gt 0) {
        $conf = 'Review'
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail (($review | Select-Object -Unique) -join '; ')))
    }
    $dn = & $text 'DisplayName'
    return @{ Skip = ''; Confidence = $conf; Program = $(if ($dn) { $dn } else { $name }); OwnerHint = $name; Tree = $true }
}

function Get-IgwtRegCleanAppPathEvidence {
    <#
    .SYNOPSIS
        RG10 App Paths\<exe>: Safe when (Default) is an absolute path that is Missing and every folder
        of the Path value is Missing, and nothing installed owns it. Returns a draft hashtable.
    .PARAMETER Target
        The normalized target.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    if ($t.Below.Count -ne 1) { return @{ Skip = 'notApplicable'; Detail = 'not an App Paths entry' } }
    $k = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path $t.Path -Sid $t.Sid
    if ($null -eq $k) { return @{ Skip = 'gone'; Detail = 'the key no longer exists' } }
    $def = $(if ($k.Values.ContainsKey('')) { [string]$k.Values[''] } else { '' })
    if (-not $def.Trim()) { return @{ Skip = 'unprovable'; Detail = 'no program path' } }
    $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $def -Kind File -Hive $t.Hive -View '') -Check 'ProgramMissing' -Value $def
    if ($s) { return @{ Skip = $s; Detail = 'program path' } }
    $table = $(if ($t.Hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables['64'] })
    if ($null -eq $table) { $table = @{} }
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $def -Kind File -Variables $table)) { $paths.Add($p) }
    if ($k.Values.ContainsKey('Path')) {
        foreach ($part in @(([string]$k.Values['Path']).Split(';') | Where-Object { $_.Trim() })) {
            $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $part -Kind Folder -Hive $t.Hive -View '') -Check 'PathFolderMissing' -Value $part
            if ($s) { return @{ Skip = $s; Detail = 'Path folder' } }
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $part -Kind Folder -Variables $table)) { $paths.Add($p) }
        }
    }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{ Category = 'appPath'; Hive = $t.Hive; View = $t.View; KeyName = $t.Leaf; Paths = $paths.ToArray(); Self = '' })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    return @{ Skip = ''; Confidence = 'Safe'; Program = $t.Leaf; OwnerHint = $t.Leaf; Tree = $true }
}

function Get-IgwtRegCleanClassEvidence {
    <#
    .SYNOPSIS
        RG10 ProgID and Applications\<exe> keys (Review only): every shell\<verb>\command (Default)
        and, for a ProgID, the DefaultIcon is Missing; a verb without a command line is unprovable. A
        ProgID that a file extension names together with another registered ProgID is not shown.
        Returns a draft hashtable.
    .PARAMETER Target
        The normalized target.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    $isProgId = $t.Category -eq 'progId'
    if ($t.Below.Count -ne 1) { return @{ Skip = 'notApplicable'; Detail = 'not a class key' } }
    $name = $t.Leaf
    if ($isProgId -and ($name.StartsWith('.') -or $name.IndexOfAny([char[]]@('*', '?')) -ge 0 -or $name -eq 'Applications')) { return @{ Skip = 'notApplicable'; Detail = 'not a ProgID' } }
    $k = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path $t.Path -Sid $t.Sid
    if ($null -eq $k) { return @{ Skip = 'gone'; Detail = 'the key no longer exists' } }
    $hasShell = @($k.SubKeys) -contains 'shell'
    $hasIcon = $isProgId -and (@($k.SubKeys) -contains 'DefaultIcon')
    if (-not $hasShell -and -not $hasIcon) { return @{ Skip = 'notApplicable'; Detail = 'no command or icon' } }
    $table = $(if ($t.Hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables['64'] })
    if ($null -eq $table) { $table = @{} }
    $paths = New-Object System.Collections.Generic.List[string]
    $pointers = 0
    if ($hasShell) {
        $shell = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path ($t.Path + '\shell') -Sid $t.Sid
        foreach ($verb in @($shell.SubKeys)) {
            $cmd = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path ($t.Path + '\shell\' + $verb + '\command') -Sid $t.Sid
            $line = $(if ($cmd -and $cmd.Values.ContainsKey('')) { [string]$cmd.Values[''] } else { '' })
            if (-not $line.Trim()) { return @{ Skip = 'unprovable'; Detail = "verb $verb has no command line" } }
            $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $line -Kind Command -Hive $t.Hive -View '') -Check 'VerbProgramMissing' -Value $line
            if ($s) { return @{ Skip = $s; Detail = "verb $verb" } }
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $line -Kind Command -Variables $table)) { $paths.Add($p) }
            $pointers++
        }
    }
    if ($hasIcon) {
        $ic = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path ($t.Path + '\DefaultIcon') -Sid $t.Sid
        $icon = $(if ($ic -and $ic.Values.ContainsKey('')) { [string]$ic.Values[''] } else { '' })
        if ($icon.Trim()) {
            $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $icon -Kind File -Hive $t.Hive -View '') -Check 'IconMissing' -Value $icon
            if ($s) { return @{ Skip = $s; Detail = 'default icon' } }
            foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $icon -Kind File -Variables $table)) { $paths.Add($p) }
            $pointers++
        }
    }
    if ($pointers -eq 0) { return @{ Skip = 'unprovable'; Detail = 'no command line or icon path' } }
    if ($isProgId) {
        $refs = Get-IgwtRegCleanClassesIndex -Context $Context
        $names = Get-IgwtRegCleanClassNames -Context $Context
        $lk = $name.ToLowerInvariant()
        if ($refs.ContainsKey($lk)) {
            foreach ($ref in $refs[$lk]) {
                foreach ($o in @($ref.Others)) {
                    foreach ($h in 'HKLM', 'HKCU') {
                        if ($names[$h] -and $names[$h].Contains([string]$o)) { return @{ Skip = 'sharedExtension'; Detail = "$($ref.Ext) also names the registered handler $o" } }
                    }
                }
            }
        }
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOtherHandler' -Detail 'no file extension names it together with another registered handler'))
    }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{ Category = $t.Category; Hive = $t.Hive; View = $t.View; KeyName = $name; Paths = $paths.ToArray(); Self = '' })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail $(if ($isProgId) { 'a file type handler can carry settings that are still used' } else { 'an Open with entry; check that the program is really gone' })))
    return @{ Skip = ''; Confidence = 'Review'; Program = $name; OwnerHint = $name; Tree = $true }
}

function Get-IgwtRegCleanOpenWithEvidence {
    <#
    .SYNOPSIS
        RG10 OpenWithProgids value naming a ProgID that exists in neither Classes root (HKLM and the
        scanned user's): Review. Without the scanned user's Classes the answer is Unknown. Returns a
        draft hashtable.
    .PARAMETER Target
        The normalized target.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    if ($t.Below.Count -ne 2 -or -not $t.Below[0].StartsWith('.') -or $t.Below[1] -ne 'OpenWithProgids' -or -not $t.ValueName) { return @{ Skip = 'notApplicable'; Detail = 'not an OpenWithProgids value' } }
    $k = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path $t.Path -Sid $t.Sid
    if ($null -eq $k -or -not $k.Values.ContainsKey($t.ValueName)) { return @{ Skip = 'gone'; Detail = 'the value no longer exists' } }
    $names = Get-IgwtRegCleanClassNames -Context $Context
    if ($null -eq $names['HKLM'] -or $null -eq $names['HKCU']) { return @{ Skip = 'unknown'; Detail = 'the per-user file types were not read' } }
    foreach ($h in 'HKLM', 'HKCU') { if ($names[$h].Contains($t.ValueName)) { return @{ Skip = 'exists'; Detail = "$($t.ValueName) is registered" } } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ProgIdMissing' -Detail "$($t.ValueName) is registered in neither HKLM\SOFTWARE\Classes nor the user's Software\Classes"))
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail 'an Open with list entry'))
    return @{ Skip = ''; Confidence = 'Review'; Program = $t.ValueName; OwnerHint = $t.Below[0]; Tree = $false }
}

function Get-IgwtRegCleanRunEvidence {
    <#
    .SYNOPSIS
        RG10 Run and RunOnce value: Safe when a plain program path is Missing; Review when the
        evidence is the payload of a host program. Returns a draft hashtable.
    .PARAMETER Target
        The normalized target.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    if ($t.Below.Count -ne 0 -or -not $t.ValueName) { return @{ Skip = 'notApplicable'; Detail = 'not a Run value' } }
    $k = Read-IgwtRegCleanKey -Hive $t.Hive -View $t.View -Path $t.Path -Sid $t.Sid
    if ($null -eq $k -or -not $k.Values.ContainsKey($t.ValueName)) { return @{ Skip = 'gone'; Detail = 'the value no longer exists' } }
    if ([string]$k.Kinds[$t.ValueName] -notin 'String', 'ExpandString') { return @{ Skip = 'unprovable'; Detail = 'not a command line' } }
    $line = [string]$k.Values[$t.ValueName]
    $rv = $(if ($t.Hive -eq 'HKLM') { [string]$t.View } else { '' })
    $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $line -Kind Command -Hive $t.Hive -View $rv) -Check 'ProgramMissing' -Value $line
    if ($s) { return @{ Skip = $s; Detail = 'command line' } }
    $table = $(if ($t.Hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables[$t.View] })
    if ($null -eq $table) { $table = @{} }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{ Category = 'run'; Hive = $t.Hive; View = $t.View; KeyName = ''; Paths = @(Get-IgwtRegCleanValuePaths -Value $line -Kind Command -Variables $table); Self = '' })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    $conf = 'Safe'
    if (Test-IgwtRegCleanHostCommand -Value $line) {
        $conf = 'Review'
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail 'the command runs through a host program; the missing file is its argument'))
    }
    return @{ Skip = ''; Confidence = $conf; Program = $t.ValueName; OwnerHint = $t.ValueName; Tree = $false }
}

function Get-IgwtRegCleanSoftwareEvidence {
    <#
    .SYNOPSIS
        RG10 Software\<Vendor>\<Product> (Review only): the tree holds at least one absolute path
        value, every such path is Missing and no program folder exists. A Vendor key is offered only
        when every subkey is such a finding, its own path values are Missing and the Vendor name is
        not on the RG32 deny list. Returns a draft hashtable.
    .PARAMETER Target
        The normalized target.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    $depth = $t.Below.Count
    if ($depth -lt 1 -or $depth -gt 2) { return @{ Skip = 'notApplicable'; Detail = 'not a vendor or product key' } }
    $vendorName = [string]$t.Below[0]
    if ($Context.VendorDeny -contains $vendorName) { return @{ Skip = 'notApplicable'; Detail = "$vendorName is never a vendor key" } }
    $tree = Get-IgwtRegCleanTreeInfo -Hive $t.Hive -View $t.View -Path $t.Path -Sid $t.Sid -Context $Context -SkipSecurity
    if (-not $tree.Exists) { return @{ Skip = 'gone'; Detail = 'the key no longer exists' } }
    $rv = $(if ($t.Hive -eq 'HKLM') { [string]$t.View } else { '' })
    $table = $(if ($t.Hive -eq 'HKCU') { $Context.Variables['user'] } else { $Context.Variables[$t.View] })
    if ($null -eq $table) { $table = @{} }
    $paths = New-Object System.Collections.Generic.List[string]
    $found = 0
    $strings = $tree.Strings.ToArray()
    if ($depth -eq 1) { $strings = @($strings | Where-Object { -not $_.Key }) }
    foreach ($s in $strings) {
        $kind = Get-IgwtRegCleanDataPathKind -Text ([string]$s.Data)
        if (-not $kind) { continue }
        $label = $(if ($s.Key) { $s.Key + '\' + $s.Name } elseif ($s.Name) { $s.Name } else { '(Default)' })
        $code = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value ([string]$s.Data) -Kind $kind -Hive $t.Hive -View $rv) -Check 'PathMissing' -Value ($label + ' = ' + [string]$s.Data)
        if ($code) { return @{ Skip = $code; Detail = "value $label" } }
        foreach ($p in @(Get-IgwtRegCleanValuePaths -Value ([string]$s.Data) -Kind $kind -Variables $table)) { $paths.Add($p) }
        $found++
    }
    $product = ''
    if ($depth -eq 2) {
        if ($found -eq 0) { return @{ Skip = 'unprovable'; Detail = 'no path value' } }
        $product = [string]$t.Below[1]
    } else {
        $subs = @($tree.SubKeys)
        if ($subs.Count -eq 0) { return @{ Skip = 'unprovable'; Detail = 'no product keys' } }
        foreach ($sk in $subs) {
            if ($Context.SegmentDeny -contains $sk) { return @{ Skip = 'notAllProducts'; Detail = "contains a shared or linked key ($sk)" } }
            $sub = Get-IgwtRegCleanEvaluation -Target ([pscustomobject]@{ Category = 'softwareKey'; Kind = 'regKeyTree'; Hive = $t.Hive; Sid = $t.Sid; View = $t.View; Path = ($t.Path + '\' + $sk) }) -Context $Context
            if ($null -eq $sub.Finding -or $sub.Finding.Confidence -ne 'Review') { return @{ Skip = 'notAllProducts'; Detail = "$sk is not a leftover" } }
        }
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'AllProductsLeftover' -Detail ('every product key is a leftover: ' + ($subs -join ', '))))
    }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{
            Category = 'softwareKey'; Hive = $t.Hive; View = $t.View; KeyName = $(if ($product) { $product } else { $vendorName }); Vendor = $vendorName; Product = $product
            Paths = $paths.ToArray(); Self = ''
        })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail 'a program settings key; it may hold settings you want to keep'))
    return @{ Skip = ''; Confidence = 'Review'; Program = $(if ($product) { $vendorName + ' ' + $product } else { $vendorName }); OwnerHint = $vendorName; Tree = $true }
}

function Get-IgwtRegCleanFirewallEvidence {
    <#
    .SYNOPSIS
        RG10 firewall rule: the program is Missing per the resolver, the rule comes from a user or an
        app (not Windows, Group Policy, MDM or a Store app), data\firewall\apps.json does not protect
        the program and Get-IgwtFirewallChangeBlock allows Delete. Allow rules may be Safe, Block
        rules are Review at most. Returns a draft hashtable.
    .PARAMETER Target
        The normalized target (Row: a Join-IgwtFirewallData row from the scan).
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    $row = $t.Row
    if ($null -eq $row) {
        if (-not $t.RuleName) { return @{ Skip = 'notApplicable'; Detail = 'no rule name' } }
        $read = Get-IgwtRegCleanFirewallRows -Context $Context -Name $t.RuleName
        $row = @($read.Rows | Where-Object { [string]$_.Name -eq $t.RuleName }) | Select-Object -First 1
        if ($null -eq $row) {
            if ($read.Dropped.Count -gt 0) { return @{ Skip = @($read.Dropped.Keys)[0]; Detail = 'program location' } }
            return @{ Skip = 'gone'; Detail = 'the rule no longer exists or names no program' }
        }
    }
    $prog = [string]$row.Program
    if (-not $prog -or $prog -in 'Any', 'System') { return @{ Skip = 'notApplicable'; Detail = 'no program' } }
    $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $prog -Kind File -Hive '' -View '') -Check 'ProgramMissing' -Value $prog
    if ($s) { return @{ Skip = $s; Detail = 'program' } }
    $row.ProgramExists = 'No'
    if ($null -eq $Context.FirewallContext) {
        $none = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
        $Context.FirewallContext = Get-IgwtFirewallClassificationContext -Role 'PowerUser' -InstalledPackages @() -Signatures $Context.FirewallSignatures -Overrides $none
    }
    Invoke-IgwtFirewallClassification -Rows @($row) -Context $Context.FirewallContext
    if ([string]$row.Source -notin 'ThirdParty', 'Owned') { return @{ Skip = 'source'; Detail = "a $([string]$row.Source) rule" } }
    if ($row.Protected) { return @{ Skip = 'protected'; Detail = [string]$row.ProtectedReason } }
    $block = Get-IgwtFirewallChangeBlock -Operation Delete -Rule $row
    if ($block) { return @{ Skip = 'blocked'; Detail = $block } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'UserRule' -Detail ("a rule added by a program or a user ($([string]$row.OriginReason))")))
    $table = $Context.Variables['64']
    if ($null -eq $table) { $table = @{} }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{ Category = 'firewallRule'; Hive = ''; View = ''; KeyName = ''; Paths = @(Get-IgwtRegCleanValuePaths -Value $prog -Kind File -Variables $table); Self = '' })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    $conf = 'Safe'
    if ([string]$row.Action -ne 'Allow') {
        $conf = 'Review'
        $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail 'Block rule: removing it lets this path use the network if the program comes back'))
    }
    $facts = [pscustomobject]@{ DisplayName = [string]$row.DisplayName; Group = [string]$row.Group; Program = $prog; Action = [string]$row.Action; Direction = [string]$row.Direction; Source = [string]$row.Source }
    return @{ Skip = ''; Confidence = $conf; Program = [string]$row.DisplayName; OwnerHint = [string]$row.Group; Tree = $false; Facts = $facts; RuleName = [string]$row.Name }
}

function Get-IgwtRegCleanServiceEvidence {
    <#
    .SYNOPSIS
        RG10 service (report only, Review): an own-process or shared-process service (Type 0x10 or
        0x20), Start 2-4, stopped, whose ImagePath is Missing. Returns a draft hashtable.
    .PARAMETER Target
        The normalized target (Facts.Service from the scan, otherwise the owners index list).
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    $svc = $null
    if ($t.Facts -and $t.Facts.PSObject.Properties['Service']) { $svc = $t.Facts.Service }
    if ($null -eq $svc) { $svc = @($Context.Index.Services | Where-Object { [string]$_.Name -eq $t.Leaf }) | Select-Object -First 1 }
    if ($null -eq $svc) { return @{ Skip = 'gone'; Detail = 'the service no longer exists' } }
    $num = { param($x) $n = -1; if ($null -ne $x) { [void][int64]::TryParse([string]$x, [ref]$n) }; $n }
    $type = & $num $svc.Type
    $start = & $num $svc.Start
    if ($type -notin 16, 32) { return @{ Skip = 'notApplicable'; Detail = 'not an own-process or shared-process service' } }
    if ($start -lt 2 -or $start -gt 4) { return @{ Skip = 'notApplicable'; Detail = 'start mode' } }
    if ([string]$svc.State -ne 'Stopped') { return @{ Skip = 'notApplicable'; Detail = 'the service is not stopped' } }
    $image = [string]$svc.ImagePath
    if (-not $image.Trim()) { return @{ Skip = 'unprovable'; Detail = 'no image path' } }
    $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $image -Kind Command -Hive '' -View '') -Check 'ImageMissing' -Value $image
    if ($s) { return @{ Skip = $s; Detail = 'image path' } }
    $table = $Context.Variables['64']
    if ($null -eq $table) { $table = @{} }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{ Category = 'service'; Hive = 'HKLM'; View = ''; KeyName = [string]$svc.Name; Paths = @(Get-IgwtRegCleanValuePaths -Value $image -Kind Command -Variables $table); Self = ('service|' + [string]$svc.Name) })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail $script:IgwtRegCleanServiceReason))
    $service = [pscustomobject]@{ Name = [string]$svc.Name; DisplayName = [string]$svc.DisplayName; ImagePath = $image; Type = $type; Start = $start; Group = [string]$svc.Group; LaunchProtected = $svc.LaunchProtected; State = [string]$svc.State }
    $facts = [pscustomobject]@{ Name = [string]$svc.Name; DisplayName = [string]$svc.DisplayName; ImagePath = $image; Service = $service }
    return @{ Skip = ''; Confidence = 'Review'; Program = $(if ([string]$svc.DisplayName) { [string]$svc.DisplayName } else { [string]$svc.Name }); OwnerHint = [string]$svc.Name; Tree = $false; Facts = $facts; Reason = $script:IgwtRegCleanServiceReason }
}

function Get-IgwtRegCleanTaskEvidence {
    <#
    .SYNOPSIS
        RG10 scheduled task (report only, Review): not under \Microsoft\, no COM handler action, and
        every Exec action's program is Missing. Returns a draft hashtable.
    .PARAMETER Target
        The normalized target (Row from the scan, otherwise read with Get-IgwtRegCleanTaskList).
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    .PARAMETER Evidence
        The evidence list to fill.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Evidence)
    $t = $Target
    $task = $t.Row
    if ($null -eq $task) { $task = @(Get-IgwtRegCleanTaskList -Path $t.Path) | Select-Object -First 1 }
    if ($null -eq $task) { return @{ Skip = 'gone'; Detail = 'the task no longer exists' } }
    if ([string]$task.TaskPath -like '\Microsoft\*') { return @{ Skip = 'notApplicable'; Detail = 'a Windows task' } }
    $actions = @($task.Actions | Where-Object { $_ })
    if ($actions.Count -eq 0 -or @($actions | Where-Object { $_.Kind -ne 'Exec' }).Count -gt 0) { return @{ Skip = 'notApplicable'; Detail = 'a task with a COM handler or no program' } }
    $table = $Context.Variables['64']
    if ($null -eq $table) { $table = @{} }
    $lines = New-Object System.Collections.Generic.List[string]
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($a in $actions) {
        $line = '"' + ([string]$a.Execute).Trim().Trim('"') + '"'
        if ([string]$a.Arguments) { $line = $line + ' ' + [string]$a.Arguments }
        $s = Add-IgwtRegCleanPointerEvidence -Evidence $Evidence -Result (Resolve-IgwtRegCleanPointer -Context $Context -Value $line -Kind Command -Hive '' -View '') -Check 'ProgramMissing' -Value $line
        if ($s) { return @{ Skip = $s; Detail = 'task action' } }
        $lines.Add($line)
        foreach ($p in @(Get-IgwtRegCleanValuePaths -Value $line -Kind Command -Variables $table)) { $paths.Add($p) }
    }
    $owned = Test-IgwtRegCleanOwned -Index $Context.Index -Candidate ([pscustomobject]@{ Category = 'task'; Hive = ''; View = ''; KeyName = ''; Paths = $paths.ToArray(); Self = '' })
    if ($owned.State -eq 'Owned') { return @{ Skip = 'owned'; Detail = $owned.Reason } }
    if ($owned.State -ne 'NotOwned') { return @{ Skip = 'unknown'; Detail = $owned.Reason } }
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NoOwner' -Detail $owned.Reason))
    $Evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'ReviewReason' -Result 'Review' -Detail $script:IgwtRegCleanTaskReason))
    $facts = [pscustomobject]@{ TaskPath = [string]$task.Path; Name = [string]$task.TaskName; Actions = $lines.ToArray() }
    return @{ Skip = ''; Confidence = 'Review'; Program = [string]$task.TaskName; OwnerHint = [string]$task.TaskPath; Tree = $false; Facts = $facts; Reason = $script:IgwtRegCleanTaskReason }
}

#endregion

#region Evaluation (one engine for scan, preview and engine)

function Get-IgwtRegCleanEvaluation {
    <#
    .SYNOPSIS
        Evaluates one target with the RG10 rules: {Finding (RG3 shape) or $null; Skip (reason code);
        Detail}. Read-only; results are cached per context.
    .DESCRIPTION
        Normalizes the target, checks that a registry target lies below a root of its category (never
        the root itself), that an HKCU target belongs to the scanned user, runs the category's
        evidence rules (every path through the resolver, ownership through Test-IgwtRegCleanOwned),
        reads the key tree for regKeyTree findings (RG17: Selectable and Size), and then runs
        Test-IgwtRegCleanProtected: a security-software match becomes Confidence Protected with the
        removal tool (RG15); any other protection or exclusion drops the entry. Any Unknown step
        drops it (RG2).
    .PARAMETER Target
        {Category; Kind (optional); Hive; Sid; View; Path; ValueName; RuleName; Facts; Row}.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Context)
    $prop = { param($n) if ($Target.PSObject.Properties[$n] -and $null -ne $Target.$n) { $Target.$n } else { $null } }
    $cat = [string](& $prop 'Category')
    $kind = [string](& $prop 'Kind')
    if (-not $kind -and $Context.Kinds.ContainsKey($cat)) { $kind = [string]$Context.Kinds[$cat] }
    $hive = [string](& $prop 'Hive')
    $isReg = $kind -in 'regKeyTree', 'regValue'
    $view = [string](& $prop 'View')
    if ($isReg -and ($hive -eq 'HKCU' -or $view -ne '32')) { $view = '64' }
    $sid = $(if ($hive -eq 'HKCU') { [string](& $prop 'Sid') } else { '' })
    # A task path keeps its leading backslash (\Folder\Name); key paths have none.
    $path = $(if ($cat -eq 'task') { [string](& $prop 'Path') } else { ([string](& $prop 'Path')).Trim('\') })
    $valueName =$(if ($kind -eq 'regValue') { [string](& $prop 'ValueName') } else { '' })
    $ruleName = $(if ($kind -eq 'firewallRule') { [string](& $prop 'RuleName') } else { '' })
    $tkey = Get-IgwtRegCleanTargetKey -Kind $kind -Hive $hive -Sid $sid -View $view -Path $path -Name $(if ($kind -eq 'regValue') { $valueName } else { $ruleName })
    if ($Context.EvalCache.ContainsKey($tkey)) { return $Context.EvalCache[$tkey] }
    $result = { param($f, $code, $detail) $r = [pscustomobject]@{ Finding = $f; Skip = [string]$code; Detail = [string]$detail }; $Context.EvalCache[$tkey] = $r; $r }
    if (-not $Context.Kinds.ContainsKey($cat) -or $Context.Kinds[$cat] -ne $kind) { return (& $result $null 'notApplicable' 'unknown category or kind') }

    # Structure: below a root of the category, the scanned user's hive.
    $below = @()
    if ($isReg) {
        if ($hive -notin 'HKLM', 'HKCU') { return (& $result $null 'notApplicable' 'not a hive the cleaner reads') }
        if ($hive -eq 'HKCU' -and (-not $Context.Sid -or $sid -ne $Context.Sid)) { return (& $result $null 'otherUser' 'per-user entries of this user were not checked') }
        $root = $null
        foreach ($r in @($Context.Roots | Where-Object { $_.Category -eq $cat -and $_.Hive -eq $hive -and $_.View -eq $view })) {
            if ([string]::Equals($path, $r.Path, [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith($r.Path + '\', [StringComparison]::OrdinalIgnoreCase)) {
                if ($null -eq $root -or $r.Path.Length -gt $root.Path.Length) { $root = $r }
            }
        }
        if ($null -eq $root) { return (& $result $null 'notApplicable' 'outside the keys this category may remove') }
        if ($path.Length -gt $root.Path.Length) { $below = @($path.Substring($root.Path.Length + 1).Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries)) }
        if ($kind -eq 'regKeyTree' -and $below.Count -eq 0) { return (& $result $null 'notApplicable' 'a category root is never removed') }
        foreach ($seg in $below) { if ($Context.SegmentDeny -contains $seg) { return (& $result $null 'denyList' "contains a shared or linked key ($seg)") } }
    }
    $t = [pscustomobject]@{
        Category = $cat; Kind = $kind; Hive = $hive; Sid = $sid; View = $view; Path = $path; ValueName = $valueName; RuleName = $ruleName
        Facts = (& $prop 'Facts'); Row = (& $prop 'Row'); Below = $below; Leaf = $path.Substring($path.LastIndexOf('\') + 1)
    }
    $evidence = New-Object System.Collections.Generic.List[object]
    $draft = $null
    try {
        switch ($cat) {
            'uninstall' { $draft = Get-IgwtRegCleanUninstallEvidence -Target $t -Context $Context -Evidence $evidence }
            'appPath' { $draft = Get-IgwtRegCleanAppPathEvidence -Target $t -Context $Context -Evidence $evidence }
            { $_ -in 'progId', 'application' } { $draft = Get-IgwtRegCleanClassEvidence -Target $t -Context $Context -Evidence $evidence }
            'openWith' { $draft = Get-IgwtRegCleanOpenWithEvidence -Target $t -Context $Context -Evidence $evidence }
            'run' { $draft = Get-IgwtRegCleanRunEvidence -Target $t -Context $Context -Evidence $evidence }
            'softwareKey' { $draft = Get-IgwtRegCleanSoftwareEvidence -Target $t -Context $Context -Evidence $evidence }
            'firewallRule' { $draft = Get-IgwtRegCleanFirewallEvidence -Target $t -Context $Context -Evidence $evidence }
            'service' { $draft = Get-IgwtRegCleanServiceEvidence -Target $t -Context $Context -Evidence $evidence }
            'task' { $draft = Get-IgwtRegCleanTaskEvidence -Target $t -Context $Context -Evidence $evidence }
        }
    } catch { return (& $result $null 'unknown' $_.Exception.Message) }
    if ($null -eq $draft) { return (& $result $null 'notApplicable' 'no rule for this category') }
    if ($draft.Skip) { return (& $result $null $draft.Skip $draft.Detail) }

    # The key tree as it would be backed up (RG17).
    $size = 1
    $selectable = $true
    $reason = ''
    if ($kind -eq 'regKeyTree') {
        $tree = $null
        try { $tree = Get-IgwtRegCleanTreeInfo -Hive $hive -View $view -Path $path -Sid $sid -Context $Context } catch { return (& $result $null 'unknown' $_.Exception.Message) }
        if (-not $tree.Exists) { return (& $result $null 'gone' 'the key no longer exists') }
        $size = [int]$tree.ValueCount
        $selectable = [bool]$tree.Selectable
        $reason = [string]$tree.Reason
    } elseif ($kind -eq 'reportOnly') {
        $selectable = $false
        $reason = [string]$draft['Reason']
    }
    if ($kind -eq 'firewallRule' -and $draft['RuleName']) { $ruleName = [string]$draft['RuleName'] }
    $facts = $draft['Facts']
    $finding = [pscustomobject]@{
        Id = (Get-IgwtRegCleanFindingId -TargetKey $tkey); Category = $cat; Kind = $kind; Hive = $hive; Sid = $sid; View = $(if ($isReg) { $view } else { '' })
        Path = $path; ValueName = $valueName; RuleName = $ruleName; Program = [string]$draft['Program']; OwnerHint = [string]$draft['OwnerHint']
        Confidence = [string]$draft['Confidence']; Evidence = @(); RemovalTool = $null; Size = $size; Includes = @(); Selectable = $selectable; Reason = $reason
        ScanId = [string]$Context.ScanId
    }
    if ($null -ne $facts) { $finding | Add-Member -NotePropertyName Facts -NotePropertyValue $facts }

    # Protection (RG14 point 1, RG15).
    $prot = $null
    try { $prot = Test-IgwtRegCleanProtected -Finding $finding -Context $Context.Protection } catch { return (& $result $null 'unknown' $_.Exception.Message) }
    if ($prot) {
        if ($prot.Excluded) { return (& $result $null 'excluded' $prot.Reason) }
        if (-not $prot.SecurityProduct) { return (& $result $null 'protected' $prot.Reason) }
        $finding.Confidence = 'Protected'
        $finding.Selectable = $false
        $finding.Reason = [string]$prot.Reason
        $finding.RemovalTool = $(if ($prot.RemovalTool) { $prot.RemovalTool } else { [pscustomobject]@{ Name = ''; Url = ''; Text = [string]$prot.Reason } })
        $evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'SecuritySoftware' -Result 'Protected' -Detail ([string]$prot.SecurityProduct + ': ' + [string]$prot.Reason)))
    } else {
        $evidence.Add((ConvertTo-IgwtRegCleanEvidence -Check 'NotProtected' -Detail 'no protected group, exclusion or live check matches'))
    }
    if ($finding.Confidence -notin 'Safe', 'Review', 'Protected') { return (& $result $null 'unknown' 'no confidence') }
    $finding.Evidence = $evidence.ToArray()
    return (& $result $finding '' '')
}

function Get-IgwtRegCleanFinding {
    <#
    .SYNOPSIS
        Re-evaluates one registry cleaner target with the scan's rules and returns the finding (RG3
        shape), or $null when it is gone, no longer provably a leftover, protected or excluded.
        Read-only.
    .DESCRIPTION
        The evidence re-check of the preview and the engine (RG14 points 2 and 3): the same
        Get-IgwtRegCleanEvaluation the scan uses, on a live re-read. A firewall rule is read again
        by name from the persistent store; a service or task from its facts or a fresh list.
    .PARAMETER Target
        A finding or target: {Category; Kind; Hive; Sid; View; Path; ValueName; RuleName; Facts}.
    .PARAMETER Context
        A Get-IgwtRegistryLeftovers scan context (built when omitted, which reads the owners index and
        the protection lists again).
    .EXAMPLE
        Get-IgwtRegCleanFinding -Target $finding
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, $Context)
    if ($null -eq $Context) { $Context = Get-IgwtRegCleanScanContext }
    return (Get-IgwtRegCleanEvaluation -Target $Target -Context $Context).Finding
}

#endregion

#region Scan

function Get-IgwtRegCleanTargets {
    <#
    .SYNOPSIS
        The candidate targets of one category, enumerated read-only (RG1, RG8, RG33): Uninstall, App
        Paths, ProgID, Applications and Run keys and values below their roots (both views where the
        key is not shared, HKCU as HKEY_USERS\<sid>), Software\<Vendor>\<Product> keys followed by
        their Vendor key, firewall rules with a local program, services and non-Windows tasks.
    .PARAMETER Category
        A category id.
    .PARAMETER Context
        Get-IgwtRegCleanScanContext result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)]$Context)
    $kind = [string]$Context.Kinds[$Category]
    $roots = @($Context.Roots | Where-Object { $_.Category -eq $Category })
    $target = { param($r, $p, $vn) [pscustomobject]@{ Category = $Category; Kind = $kind; Hive = $r.Hive; Sid = $(if ($r.Hive -eq 'HKCU') { $Context.Sid } else { '' }); View = $r.View; Path = $p; ValueName = $vn } }
    switch ($Category) {
        'firewallRule' {
            $read = Get-IgwtRegCleanFirewallRows -Context $Context
            foreach ($k in @($read.Dropped.Keys)) { $Context.Notes.Add('firewall:' + $k + '=' + $read.Dropped[$k]) }
            foreach ($row in @($read.Rows)) { [pscustomobject]@{ Category = $Category; Kind = $kind; Hive = ''; Sid = ''; View = ''; Path = ''; RuleName = [string]$row.Name; Row = $row } }
            return
        }
        'service' {
            foreach ($s in $Context.Index.Services) {
                if ($null -eq $s -or -not $s.Name) { continue }
                [pscustomobject]@{ Category = $Category; Kind = $kind; Hive = 'HKLM'; Sid = ''; View = ''; Path = ($script:IgwtRegCleanServicesKey + '\' + [string]$s.Name); Facts = [pscustomobject]@{ Name = [string]$s.Name; Service = $s } }
            }
            return
        }
        'task' {
            foreach ($task in @(Get-IgwtRegCleanTaskList)) {
                if ($null -eq $task -or [string]$task.TaskPath -like '\Microsoft\*') { continue }
                [pscustomobject]@{ Category = $Category; Kind = $kind; Hive = ''; Sid = ''; View = ''; Path = [string]$task.Path; Row = $task }
            }
            return
        }
    }
    foreach ($r in $roots) {
        if ($r.Hive -eq 'HKCU' -and -not $Context.Sid) {
            if (-not $Context.Notes.Contains($script:IgwtRegCleanPerUserNote)) { $Context.Notes.Add($script:IgwtRegCleanPerUserNote) }
            continue
        }
        $sid = $(if ($r.Hive -eq 'HKCU') { $Context.Sid } else { '' })
        $key = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path $r.Path -Sid $sid
        if ($null -eq $key) { continue }
        switch ($Category) {
            'run' { foreach ($vn in @($key.Values.Keys | Sort-Object)) { if ($vn) { & $target $r $r.Path ([string]$vn) } } }
            'openWith' {
                foreach ($ext in @($key.SubKeys | Where-Object { $_.StartsWith('.') })) {
                    $ow = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path ($r.Path + '\' + $ext + '\OpenWithProgids') -Sid $sid
                    if ($null -eq $ow) { continue }
                    foreach ($vn in @($ow.Values.Keys | Sort-Object)) { if ($vn) { & $target $r ($r.Path + '\' + $ext + '\OpenWithProgids') ([string]$vn) } }
                }
            }
            'softwareKey' {
                foreach ($vendor in @($key.SubKeys)) {
                    if ($Context.VendorDeny -contains $vendor) { continue }
                    $vk = $null
                    try { $vk = Read-IgwtRegCleanKey -Hive $r.Hive -View $r.View -Path ($r.Path + '\' + $vendor) -Sid $sid } catch { $vk = $null }
                    if ($null -eq $vk -or @($vk.SubKeys).Count -eq 0) { continue }
                    foreach ($product in @($vk.SubKeys)) { & $target $r ($r.Path + '\' + $vendor + '\' + $product) '' }
                    & $target $r ($r.Path + '\' + $vendor) ''
                }
            }
            'progId' { foreach ($n in @($key.SubKeys)) { if (-not $n.StartsWith('.') -and $n -ne 'Applications' -and $Context.SegmentDeny -notcontains $n) { & $target $r ($r.Path + '\' + $n) '' } } }
            default { foreach ($n in @($key.SubKeys)) { & $target $r ($r.Path + '\' + $n) '' } }
        }
    }
}

function Get-IgwtRegistryLeftovers {
    <#
    .SYNOPSIS
        Scans for registry entries left behind by programs that are no longer installed (DECISIONS
        RG1-RG3, RG10, RG22). Read-only: changes nothing, writes no file and no cache.
    .DESCRIPTION
        For every category (Uninstall entries, App Paths, ProgIDs, Open with applications and lists,
        Run and RunOnce, Software\<Vendor>\<Product> keys, firewall rules, and report-only services
        and scheduled tasks) the candidates are enumerated read-only and evaluated with
        Get-IgwtRegCleanFinding's rules: every referenced path is resolved by the single resolver,
        nothing installed may own it, the protected set, the live checks and the user's exclusions
        apply. Only Safe, Review and Protected (security software, with its removal tool) are
        returned; anything with an Unknown step is left out. Progress is reported per category and
        every 200 entries; the cancel token is checked before every entry and a cancelled scan
        returns its partial result with Cancelled $true. HKCU is the scanned user's hive (RG33);
        when elevated without a signed-in user the per-user categories are skipped with a note.
        Result: {Generated; ScanId; Findings; Skipped (counts per reason, for the log only);
        Cancelled; Elapsed (seconds); Notes; User {Sid; Source}}.
    .PARAMETER CancelToken
        A System.Threading.CancellationToken (the GUI worker's Cancel button).
    .PARAMETER Category
        Limit the scan to these categories.
    .EXAMPLE
        (Get-IgwtRegistryLeftovers).Findings | Format-Table Confidence, Category, Program, Path
    .EXAMPLE
        Get-IgwtRegistryLeftovers -Category uninstall, run
    #>
    [CmdletBinding()]
    param($CancelToken, [ValidateSet('uninstall', 'appPath', 'progId', 'application', 'openWith', 'run', 'softwareKey', 'firewallRule', 'service', 'task')][string[]]$Category)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $cats = @($script:IgwtRegCleanScanOrder | Where-Object { -not $Category -or $Category -contains $_ })
    Send-IgwtProgress -Text 'Registry cleaner: preparing the scan (read-only)...' -Percent 0
    $ctx = Get-IgwtRegCleanScanContext
    $findings = New-Object System.Collections.Generic.List[object]
    $ids = New-Object 'System.Collections.Generic.HashSet[string]'
    $skipped = [ordered]@{}
    $tally = { param($k) if (-not $k) { $k = 'unknown' }; if ($skipped.Contains($k)) { $skipped[$k]++ } else { $skipped[$k] = 1 } }
    $cancelled = $false
    $count = 0
    for ($i = 0; $i -lt $cats.Count; $i++) {
        if ($CancelToken -and $CancelToken.IsCancellationRequested) { $cancelled = $true; break }
        $c = $cats[$i]
        $label = $script:IgwtRegCleanCategoryLabels[$c]
        Send-IgwtProgress -Text "Registry cleaner: checking $label..." -Percent ([int](100 * $i / [Math]::Max(1, $cats.Count)))
        $targets = @()
        try { $targets = @(Get-IgwtRegCleanTargets -Category $c -Context $ctx) }
        catch {
            & $tally 'unreadable'
            $note = "$label were not checked"
            if (-not $ctx.Notes.Contains($note)) { $ctx.Notes.Add($note) }
            continue
        }
        foreach ($t in $targets) {
            if ($CancelToken -and $CancelToken.IsCancellationRequested) { $cancelled = $true; break }
            $count++
            if ($count % 200 -eq 0) { Send-IgwtProgress -Text "Registry cleaner: checking $label ($count entries so far)..." -Percent -1 }
            $ev = $null
            try { $ev = Get-IgwtRegCleanEvaluation -Target $t -Context $ctx } catch { & $tally 'unknown'; continue }
            if ($ev.Finding) {
                if ($ids.Add([string]$ev.Finding.Id)) { $findings.Add($ev.Finding) }
            } else { & $tally $ev.Skip }
        }
        if ($cancelled) { break }
    }
    $sw.Stop()
    Send-IgwtProgress -Text $(if ($cancelled) { 'Scan stopped, partial result.' } else { 'Scan finished.' }) -Percent 100
    $notes = @($ctx.Notes | Where-Object { $_ -and -not $_.StartsWith('firewall:') } | Select-Object -Unique)
    foreach ($n in @($ctx.Notes | Where-Object { $_ -and $_.StartsWith('firewall:') })) {
        $pair = $n.Substring(9).Split('=')
        $k = 'firewall ' + $pair[0]
        if ($skipped.Contains($k)) { $skipped[$k] += [int]$pair[1] } else { $skipped[$k] = [int]$pair[1] }
    }
    return [pscustomobject]@{
        Generated = (Get-Date).ToString('o')
        ScanId    = [string]$ctx.ScanId
        Findings  = $findings.ToArray()
        Skipped   = $skipped
        Cancelled = $cancelled
        Elapsed   = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        Notes     = $notes
        User      = [pscustomobject]@{ Sid = [string]$ctx.Sid; Source = [string]$ctx.User.Source }
    }
}

#endregion
