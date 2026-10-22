# AdmxCatalog.ps1
# Policy catalog built from the ADMX/ADML files of this PC (C:\Windows\PolicyDefinitions), the
# domain Central Store when the PC is domain-joined, and extra folders the user adds (Edge,
# Chrome, Office templates). Microsoft's files are read at runtime and never copied into the
# project. The parsed catalog is cached per user, keyed by a hash of the definition files.

$script:IgwtAdmxCache = $null
$script:IgwtAdmxCacheVersion = 1

function Get-IgwtAdmxFolders {
    <#
    .SYNOPSIS
        Definition folders in priority order: the domain Central Store (domain-joined PCs), the
        local PolicyDefinitions folder, then extra folders from -Extra or the user settings.
    #>
    [CmdletBinding()]
    param([string[]]$Extra = @())
    $list = New-Object System.Collections.Generic.List[string]
    if ($script:IgwtSettings.AdmxFolders) { foreach ($f in @($script:IgwtSettings.AdmxFolders)) { $list.Add([string]$f) }; return $list.ToArray() }
    try {
        $m = Get-IgwtManagementState
        if ($m.DomainJoined -and $m.DomainName) {
            $central = "\\$($m.DomainName)\SYSVOL\$($m.DomainName)\Policies\PolicyDefinitions"
            if (Test-Path -LiteralPath $central) { $list.Add($central) }
        }
    } catch { Write-Verbose 'Central Store check skipped.' }
    $list.Add((Join-Path $env:SystemRoot 'PolicyDefinitions'))
    foreach ($f in @($Extra | Where-Object { $_ })) { if (Test-Path -LiteralPath $f) { $list.Add([string]$f) } }
    return @($list | Select-Object -Unique)
}

function Get-IgwtAdmlPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Folder, [Parameter(Mandatory = $true)][string]$AdmxName)
    $base = [System.IO.Path]::ChangeExtension($AdmxName, '.adml')
    foreach ($lang in @([System.Globalization.CultureInfo]::CurrentUICulture.Name, 'en-US')) {
        $p = Join-Path (Join-Path $Folder $lang) $base
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return ''
}

function Get-IgwtAdmxFolderHash {
    <# .SYNOPSIS SHA256 over the names, sizes and write times of every ADMX/ADML file: the cache key. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string[]]$Folders)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("v$script:IgwtAdmxCacheVersion|")
    foreach ($d in $Folders) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Include '*.admx', '*.adml' -ErrorAction SilentlyContinue | Sort-Object FullName)) {
            $null = $sb.Append($f.FullName).Append('|').Append($f.Length).Append('|').Append($f.LastWriteTimeUtc.Ticks).Append(';')
        }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Resolve-IgwtAdmlString {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Ref, [hashtable]$Strings)
    if ($Ref -match '^\$\(string\.(.+)\)$') { $k = $Matches[1]; if ($Strings.ContainsKey($k)) { return [string]$Strings[$k] }; return $k }
    return $Ref
}

function ConvertFrom-IgwtAdmxValue {
    <# .SYNOPSIS An ADMX value element (decimal, longDecimal, string, delete) as Type + Value. #>
    [CmdletBinding()]
    param($Node)
    if (-not $Node) { return $null }
    foreach ($c in $Node.ChildNodes) {
        if ($c.NodeType -ne 'Element') { continue }
        switch ($c.LocalName) {
            'decimal' { return [pscustomobject]@{ Type = 'DWord'; Value = [uint32]$c.GetAttribute('value') } }
            'longDecimal' { return [pscustomobject]@{ Type = 'QWord'; Value = [uint64]$c.GetAttribute('value') } }
            'string' { return [pscustomobject]@{ Type = 'String'; Value = [string]$c.InnerText } }
            'delete' { return [pscustomobject]@{ Type = 'Delete'; Value = $null } }
        }
    }
    return $null
}

function ConvertFrom-IgwtAdmxValueList {
    [CmdletBinding()]
    param($Node, [string]$DefaultKey)
    if (-not $Node) { return @() }
    $key = $Node.GetAttribute('defaultKey'); if (-not $key) { $key = $DefaultKey }
    @(foreach ($item in $Node.ChildNodes) {
            if ($item.NodeType -ne 'Element' -or $item.LocalName -ne 'item') { continue }
            $k = $item.GetAttribute('key'); if (-not $k) { $k = $key }
            [pscustomobject]@{ Key = $k; ValueName = $item.GetAttribute('valueName'); Value = (ConvertFrom-IgwtAdmxValue -Node $item['value']) }
        })
}

function Get-IgwtAdmxPresentation {
    <# .SYNOPSIS Labels and defaults of a policy's presentation, keyed by element id. #>
    [CmdletBinding()]
    param($Presentations, [string]$Ref)
    $map = @{}
    if (-not $Presentations -or $Ref -notmatch '^\$\(presentation\.(.+)\)$') { return $map }
    $node = $Presentations[$Matches[1]]
    if (-not $node) { return $map }
    foreach ($c in $node.ChildNodes) {
        if ($c.NodeType -ne 'Element') { continue }
        $rid = $c.GetAttribute('refId')
        if (-not $rid) { continue }
        $label = $(if ($c['label']) { $c['label'].InnerText } else { $c.InnerText })
        $map[$rid] = [pscustomobject]@{ Kind = $c.LocalName; Label = ([string]$label).Trim(); Default = $(if ($c.HasAttribute('defaultValue')) { $c.GetAttribute('defaultValue') } elseif ($c.HasAttribute('defaultChecked')) { $c.GetAttribute('defaultChecked') } elseif ($c.HasAttribute('defaultItem')) { $c.GetAttribute('defaultItem') } else { $null }) }
    }
    return $map
}

function ConvertFrom-IgwtAdmxElement {
    [CmdletBinding()]
    param($Node, [string]$PolicyKey, [hashtable]$Strings, [hashtable]$Labels)
    $id = $Node.GetAttribute('id')
    $key = $Node.GetAttribute('key'); if (-not $key) { $key = $PolicyKey }
    $e = [ordered]@{ Type = $Node.LocalName; Id = $id; Key = $key; ValueName = $Node.GetAttribute('valueName'); Required = ($Node.GetAttribute('required') -eq 'true')
        Label = $(if ($Labels.ContainsKey($id)) { $Labels[$id].Label } else { $id }); Default = $(if ($Labels.ContainsKey($id)) { $Labels[$id].Default } else { $null }) }
    switch ($Node.LocalName) {
        { $_ -in 'decimal', 'longDecimal' } {
            $e.Min = $(if ($Node.HasAttribute('minValue')) { [uint64]$Node.GetAttribute('minValue') } else { [uint64]0 })
            $e.Max = $(if ($Node.HasAttribute('maxValue')) { [uint64]$Node.GetAttribute('maxValue') } elseif ($_ -eq 'decimal') { [uint64][uint32]::MaxValue } else { [uint64]::MaxValue })
            $e.StoreAsText = ($Node.GetAttribute('storeAsText') -eq 'true')
        }
        { $_ -in 'text', 'multiText' } {
            $e.MaxLength = $(if ($Node.HasAttribute('maxLength')) { [int]$Node.GetAttribute('maxLength') } else { 1023 })
            $e.Expandable = ($Node.GetAttribute('expandable') -eq 'true')
        }
        'boolean' {
            $e.TrueValue = ConvertFrom-IgwtAdmxValue -Node $Node['trueValue']
            $e.FalseValue = ConvertFrom-IgwtAdmxValue -Node $Node['falseValue']
            $e.TrueList = @(ConvertFrom-IgwtAdmxValueList -Node $Node['trueList'] -DefaultKey $key)
            $e.FalseList = @(ConvertFrom-IgwtAdmxValueList -Node $Node['falseList'] -DefaultKey $key)
        }
        'enum' {
            $e.Items = @(foreach ($it in $Node.ChildNodes) {
                    if ($it.NodeType -ne 'Element' -or $it.LocalName -ne 'item') { continue }
                    [pscustomobject]@{ DisplayName = (Resolve-IgwtAdmlString -Ref $it.GetAttribute('displayName') -Strings $Strings); Value = (ConvertFrom-IgwtAdmxValue -Node $it['value']); ValueList = @(ConvertFrom-IgwtAdmxValueList -Node $it['valueList'] -DefaultKey $key) }
                })
        }
        'list' {
            $e.ValuePrefix = $Node.GetAttribute('valuePrefix'); $e.Additive = ($Node.GetAttribute('additive') -eq 'true')
            $e.ExplicitValue = ($Node.GetAttribute('explicitValue') -eq 'true'); $e.Expandable = ($Node.GetAttribute('expandable') -eq 'true')
        }
    }
    return [pscustomobject]$e
}

function Read-IgwtAdmxFolder {
    <# .SYNOPSIS Parses every ADMX file of one folder (with its ADML) into raw namespaces, categories, supportedOn definitions and policies. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Folder)
    $result = [pscustomobject]@{ Folder = $Folder; Files = New-Object System.Collections.Generic.List[object]; Errors = New-Object System.Collections.Generic.List[string] }
    foreach ($f in @(Get-ChildItem -LiteralPath $Folder -Filter '*.admx' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $x = New-Object System.Xml.XmlDocument
            $x.XmlResolver = $null
            $x.Load($f.FullName)
            $root = $x.DocumentElement
            $strings = @{}; $presentations = @{}
            $adml = Get-IgwtAdmlPath -Folder $Folder -AdmxName $f.Name
            if ($adml) {
                $y = New-Object System.Xml.XmlDocument; $y.XmlResolver = $null; $y.Load($adml)
                $res = $y.DocumentElement['resources']
                if ($res -and $res['stringTable']) { foreach ($s in $res['stringTable'].ChildNodes) { if ($s.NodeType -eq 'Element') { $strings[$s.GetAttribute('id')] = $s.InnerText } } }
                if ($res -and $res['presentationTable']) { foreach ($p in $res['presentationTable'].ChildNodes) { if ($p.NodeType -eq 'Element') { $presentations[$p.GetAttribute('id')] = $p } } }
            }
            $ns = $root['policyNamespaces']
            $target = $ns['target']
            $using = @{}
            foreach ($u in $ns.ChildNodes) { if ($u.NodeType -eq 'Element' -and $u.LocalName -eq 'using') { $using[$u.GetAttribute('prefix')] = $u.GetAttribute('namespace') } }
            $self = $target.GetAttribute('namespace'); $using[$target.GetAttribute('prefix')] = $self
            $resolve = { param($ref) if (-not $ref) { return '' }; if ($ref -match '^([^:]+):(.+)$') { $n = $using[$Matches[1]]; if (-not $n) { $n = $Matches[1] }; return "${n}:$($Matches[2])" }; return "${self}:$ref" }.GetNewClosure()
            $file = [pscustomobject]@{ Name = $f.Name; Namespace = $self; Categories = @(); Supported = @(); Policies = @() }
            if ($root['categories']) {
                $file.Categories = @(foreach ($c in $root['categories'].ChildNodes) {
                        if ($c.NodeType -ne 'Element') { continue }
                        [pscustomobject]@{ Id = "${self}:$($c.GetAttribute('name'))"; DisplayName = (Resolve-IgwtAdmlString -Ref $c.GetAttribute('displayName') -Strings $strings); Parent = $(if ($c['parentCategory']) { & $resolve $c['parentCategory'].GetAttribute('ref') } else { '' }) }
                    })
            }
            if ($root['supportedOn'] -and $root['supportedOn']['definitions']) {
                $file.Supported = @(foreach ($d in $root['supportedOn']['definitions'].ChildNodes) {
                        if ($d.NodeType -ne 'Element') { continue }
                        [pscustomobject]@{ Id = "${self}:$($d.GetAttribute('name'))"; DisplayName = (Resolve-IgwtAdmlString -Ref $d.GetAttribute('displayName') -Strings $strings) }
                    })
            }
            if ($root['policies']) {
                $file.Policies = @(foreach ($p in $root['policies'].ChildNodes) {
                        if ($p.NodeType -ne 'Element' -or $p.LocalName -ne 'policy') { continue }
                        $key = $p.GetAttribute('key')
                        $labels = Get-IgwtAdmxPresentation -Presentations $presentations -Ref $p.GetAttribute('presentation')
                        $elements = @()
                        if ($p['elements']) { $elements = @(foreach ($el in $p['elements'].ChildNodes) { if ($el.NodeType -eq 'Element') { ConvertFrom-IgwtAdmxElement -Node $el -PolicyKey $key -Strings $strings -Labels $labels } }) }
                        [pscustomobject]@{
                            Id = "$([System.IO.Path]::GetFileNameWithoutExtension($f.Name)):$($p.GetAttribute('name'))"; Name = $p.GetAttribute('name'); File = $f.Name; Namespace = $self
                            Class = $p.GetAttribute('class'); DisplayName = (Resolve-IgwtAdmlString -Ref $p.GetAttribute('displayName') -Strings $strings)
                            Explain = (Resolve-IgwtAdmlString -Ref $p.GetAttribute('explainText') -Strings $strings)
                            Key = $key; ValueName = $p.GetAttribute('valueName')
                            Category = $(if ($p['parentCategory']) { & $resolve $p['parentCategory'].GetAttribute('ref') } else { '' })
                            SupportedOnId = $(if ($p['supportedOn']) { & $resolve $p['supportedOn'].GetAttribute('ref') } else { '' })
                            EnabledValue = (ConvertFrom-IgwtAdmxValue -Node $p['enabledValue']); DisabledValue = (ConvertFrom-IgwtAdmxValue -Node $p['disabledValue'])
                            EnabledList = @(ConvertFrom-IgwtAdmxValueList -Node $p['enabledList'] -DefaultKey $key); DisabledList = @(ConvertFrom-IgwtAdmxValueList -Node $p['disabledList'] -DefaultKey $key)
                            Elements = $elements
                        }
                    })
            }
            $result.Files.Add($file)
        } catch { $result.Errors.Add("$($f.Name): $($_.Exception.Message)") }
    }
    return $result
}

function Get-IgwtAdmxCatalogPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Hash)
    $base = $(if ($script:IgwtSettings.TestMode) { Join-Path ([string]$script:IgwtSettings.DataRoot) 'Cache' } else { Join-Path ([string]$script:IgwtSettings.UserLogRoot) 'Cache' })
    return (Join-Path $base "admx-$($Hash.Substring(0, 16)).xml")
}

function Get-IgwtAdmxCatalog {
    <#
    .SYNOPSIS
        The policy catalog: every ADMX policy with its category path, class, supportedOn text,
        registry mapping, elements and explain text (which becomes the hint and description).
        Cached in memory and on disk per user, keyed by a hash of the definition files. Read-only.
    .PARAMETER Force
        Parse again even when a cache exists.
    .PARAMETER ExtraFolder
        Additional ADMX folders (for example Edge, Chrome or Office templates).
    #>
    [CmdletBinding()]
    param([switch]$Force, [string[]]$ExtraFolder = @(), [scriptblock]$OnProgress)
    $folders = @(Get-IgwtAdmxFolders -Extra $ExtraFolder)
    $hash = Get-IgwtAdmxFolderHash -Folders $folders
    if (-not $Force -and $script:IgwtAdmxCache -and $script:IgwtAdmxCache.Hash -eq $hash) { return $script:IgwtAdmxCache }
    $cacheFile = Get-IgwtAdmxCatalogPath -Hash $hash
    if (-not $Force -and (Test-Path -LiteralPath $cacheFile)) {
        try {
            $cat = Import-Clixml -LiteralPath $cacheFile
            if ($cat.Hash -eq $hash) { $script:IgwtAdmxCache = $cat; return $cat }
        } catch { Write-Verbose "ADMX cache unreadable; parsing again: $($_.Exception.Message)" }
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $categories = @{}; $supported = @{}; $byId = [ordered]@{}; $errors = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($d in $folders) {
        $i++
        Send-IgwtProgress -Text "Reading policy definitions in $d" -Percent ([int](100 * ($i - 1) / [Math]::Max(1, $folders.Count))) -Callback $OnProgress
        $r = Read-IgwtAdmxFolder -Folder $d
        foreach ($e in $r.Errors) { $errors.Add("${d}: $e") }
        foreach ($f in $r.Files) {
            foreach ($c in $f.Categories) { if (-not $categories.ContainsKey($c.Id)) { $categories[$c.Id] = $c } }
            foreach ($s in $f.Supported) { if (-not $supported.ContainsKey($s.Id)) { $supported[$s.Id] = $s.DisplayName } }
            # The first folder wins (the Central Store overrides local definitions).
            foreach ($p in $f.Policies) { if (-not $byId.Contains($p.Id)) { $byId[$p.Id] = $p } }
        }
    }
    $pathCache = @{}
    $catPath = {
        param($id)
        if (-not $id) { return '' }
        if ($pathCache.ContainsKey($id)) { return $pathCache[$id] }
        $parts = New-Object System.Collections.Generic.List[string]; $cur = $id; $guard = 0
        while ($cur -and $categories.ContainsKey($cur) -and $guard -lt 20) { $parts.Insert(0, [string]$categories[$cur].DisplayName); $cur = $categories[$cur].Parent; $guard++ }
        $text = ($parts -join ' > '); $pathCache[$id] = $text; return $text
    }
    $policies = New-Object System.Collections.Generic.List[object]
    foreach ($p in $byId.Values) {
        $p | Add-Member -NotePropertyName CategoryPath -NotePropertyValue (& $catPath $p.Category) -Force
        $p | Add-Member -NotePropertyName SupportedOn -NotePropertyValue $(if ($supported.ContainsKey($p.SupportedOnId)) { $supported[$p.SupportedOnId] } else { ($p.SupportedOnId -replace '^.*:', '') }) -Force
        $p | Add-Member -NotePropertyName Search -NotePropertyValue ("$($p.DisplayName)`n$($p.Explain)`n$($p.Key)\$($p.ValueName)`n$($p.Name)`n$(@($p.Elements | ForEach-Object { "$($_.Key)\$($_.ValueName)" }) -join "`n")".ToLowerInvariant()) -Force
        $policies.Add($p)
    }
    $cat = [pscustomobject]@{ Hash = $hash; Folders = $folders; Parsed = (Get-Date).ToString('o'); ParseMs = $sw.ElapsedMilliseconds; Policies = $policies.ToArray(); Categories = @($categories.Values); Errors = $errors.ToArray() }
    try {
        $dir = Split-Path -Parent $cacheFile
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        Export-Clixml -LiteralPath $cacheFile -InputObject $cat -Depth 8
    } catch { Write-Verbose "ADMX cache not written: $($_.Exception.Message)" }
    $script:IgwtAdmxCache = $cat
    Send-IgwtProgress -Text 'Policy definitions read' -Percent 100 -Callback $OnProgress
    return $cat
}

function Find-IgwtPolicy {
    <#
    .SYNOPSIS
        Searches the policy catalog by name, explain text or registry path, with filters for class
        and category. Read-only.
    #>
    [CmdletBinding()]
    param([string]$Search, [ValidateSet('Machine', 'User', 'Both', '')][string]$Class = '', [string]$Category, [int]$First = 0)
    $all = @((Get-IgwtAdmxCatalog).Policies)
    $q = ([string]$Search).Trim().ToLowerInvariant()
    $words = @($q -split '\s+' | Where-Object { $_ })
    $hits = foreach ($p in $all) {
        if ($Class -and [string]$p.Class -ne $Class -and [string]$p.Class -ne 'Both') { continue }
        if ($Category -and ([string]$p.CategoryPath).IndexOf($Category, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $ok = $true
        foreach ($w in $words) { if ($p.Search.IndexOf($w, [System.StringComparison]::Ordinal) -lt 0) { $ok = $false; break } }
        if ($ok) { $p }
    }
    $hits = @($hits | Sort-Object CategoryPath, DisplayName)
    if ($First -gt 0) { return @($hits | Select-Object -First $First) }
    return $hits
}

function Get-IgwtPolicyDefinition {
    <# .SYNOPSIS One policy by id (file:name, for example WindowsUpdate:AutoUpdateCfg) or by exact name. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $all = @((Get-IgwtAdmxCatalog).Policies)
    $p = @($all | Where-Object { [string]::Equals($_.Id, $Id, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $p) { $p = @($all | Where-Object { [string]::Equals($_.Name, $Id, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1 }
    if (-not $p) { throw "Unknown policy '$Id'. Search with -PolicySearch." }
    return $p
}
