# Inventory.ps1
# Read-only inventories for the management modules: services (with a "safe to change" rating and
# the catalog items and presets that touch them), scheduled tasks, installed Win32 and Appx apps,
# and optional features and capabilities. Changes go through Invoke-IgwtManagedChange.

function Get-IgwtCatalogServiceMap {
    <# .SYNOPSIS Service name (lower case) -> catalog items (and the presets that include them) that change it. #>
    [CmdletBinding()]
    param()
    $map = @{}
    $presets = @(); try { $presets = @(Get-IgwtPreset) } catch { $presets = @() }
    foreach ($t in @(Get-IgwtCatalog)) {
        $names = @()
        foreach ($a in @($t.actions)) {
            if ([string]$a.type -eq 'service') { $names += [string]$a.name }
            elseif ([string]$a.type -eq 'serviceSet') { $names += @($a.services | ForEach-Object { [string]$_.name }) }
        }
        foreach ($n in $names) {
            $k = $n.ToLowerInvariant()
            if (-not $map.ContainsKey($k)) { $map[$k] = New-Object System.Collections.Generic.List[object] }
            $in = @($presets | Where-Object { @($_.tweaks) -contains $t.id } | ForEach-Object { [string]$_.name })
            $map[$k].Add([pscustomobject]@{ Id = [string]$t.id; Name = [string]$t.name; Presets = $in })
        }
    }
    return $map
}

function Get-IgwtServiceInventory {
    <#
    .SYNOPSIS
        Every Win32 service with display name, description, status, startup type, dependencies and
        a rating: Protected (never changed), Catalogued (a catalog item manages it), Windows (part
        of Windows: change only when you know what depends on it) or ThirdParty.
    #>
    [CmdletBinding()]
    param()
    $cat = Get-IgwtCatalogServiceMap
    $deps = @{}
    try {
        foreach ($s in @(Get-Service -ErrorAction Stop)) {
            $deps[([string]$s.Name).ToLowerInvariant()] = [pscustomobject]@{ DependsOn = @($s.ServicesDependedOn | ForEach-Object { [string]$_.Name }); Dependents = @($s.DependentServices | ForEach-Object { [string]$_.Name }) }
        }
    } catch { Write-Verbose 'Service dependencies unavailable.' }
    $windir = [string]$env:SystemRoot
    $rows = foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $name = [string]$s.Name
        $lower = $name.ToLowerInvariant()
        $start = [string]$s.StartMode
        if ($start -eq 'Auto') { $start = $(if ($s.DelayedAutoStart) { 'AutomaticDelayed' } else { 'Automatic' }) }
        $protect = Get-IgwtServiceProtection -Name $name
        $path = [string]$s.PathName
        $inWindowsDir = ($windir -and $path.TrimStart('"').StartsWith($windir, [System.StringComparison]::OrdinalIgnoreCase))
        $items = @(); if ($cat.ContainsKey($lower)) { $items = $cat[$lower].ToArray() }
        $rating = $(if ($protect) { 'Protected' } elseif ($items.Count) { 'Catalogued' } elseif ($inWindowsDir) { 'Windows' } else { 'ThirdParty' })
        $advice = switch ($rating) {
            'Protected' { $protect }
            'Catalogued' { "Managed by catalog item(s) $(@($items | ForEach-Object { $_.Id }) -join ', '); prefer those, they include the documented reasons." }
            'Windows' { 'Part of Windows. Change it only when you know which feature needs it; Manual is safer than Disabled.' }
            default { 'Installed by an application. Manual or Disabled is fine when you do not use that application.' }
        }
        $d = $deps[$lower]
        [pscustomobject]@{
            Name = $name; DisplayName = [string]$s.DisplayName; Description = [string]$s.Description; State = [string]$s.State; StartupType = $start
            Account = [string]$s.StartName; Path = $path; Rating = $rating; Advice = $advice; CatalogItems = $items
            DependsOn = $(if ($d) { @($d.DependsOn) } else { @() }); Dependents = $(if ($d) { @($d.Dependents) } else { @() })
            CanChange = ($rating -ne 'Protected')
        }
    }
    $rows = @($rows | Sort-Object DisplayName)
    [pscustomobject]@{
        Services = $rows
        Counts   = [pscustomobject]@{ Total = $rows.Count; Running = @($rows | Where-Object { $_.State -eq 'Running' }).Count; Protected = @($rows | Where-Object { $_.Rating -eq 'Protected' }).Count; ThirdParty = @($rows | Where-Object { $_.Rating -eq 'ThirdParty' }).Count }
        Note     = 'Read-only. Changes are snapshot-backed (Invoke-IgwtManagedChange -Kind service) and protected services are refused.'
    }
}

function Get-IgwtTaskInventory {
    <# .SYNOPSIS Every scheduled task with state, author, action, last result and whether iG Windows Tuner may disable it. #>
    [CmdletBinding()]
    param()
    $rows = foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $full = "$($t.TaskPath)$($t.TaskName)"
        $protected = $false
        try { Assert-IgwtTaskAllowed -Path ([string]$t.TaskPath) } catch { $protected = $true }
        if ($full -match $script:IgwtAntiCheatTaskPattern) { $protected = $true }
        $exec = @($t.Actions | ForEach-Object { if ($_.PSObject.Properties['Execute'] -and $_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } elseif ($_.PSObject.Properties['ClassId'] -and $_.ClassId) { "COM handler $($_.ClassId)" } }) -join '; '
        [pscustomobject]@{
            Path = $full; TaskPath = [string]$t.TaskPath; Name = [string]$t.TaskName; State = [string]$t.State; Author = [string]$t.Author; Description = [string]$t.Description
            Action = $exec; IsMicrosoft = ([string]$t.TaskPath -like '\Microsoft\*'); Protected = $protected; CanDisable = (-not $protected -and [string]$t.State -ne 'Disabled')
        }
    }
    $rows = @($rows | Sort-Object Path)
    [pscustomobject]@{
        Tasks  = $rows
        Counts = [pscustomobject]@{ Total = $rows.Count; Disabled = @($rows | Where-Object { $_.State -eq 'Disabled' }).Count; ThirdParty = @($rows | Where-Object { -not $_.IsMicrosoft }).Count }
        Note   = 'Tasks are only enabled or disabled, never created or deleted. Windows Defender, Windows Update, TPM, BitLocker, restore, time and anti-cheat tasks are protected. The curated telemetry set is catalog item privacy.telemetry-tasks-off.'
    }
}

function Get-IgwtAppInventory {
    <# .SYNOPSIS Installed Win32 apps (uninstall entries) and Appx packages, with protection and removal notes. #>
    [CmdletBinding()]
    param()
    $win32 = New-Object System.Collections.Generic.List[object]
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        try {
            foreach ($k in @(Get-ChildItem -LiteralPath (Resolve-IgwtRegistryPath $root) -ErrorAction Stop)) {
                $name = [string]$k.GetValue('DisplayName')
                if (-not $name -or [int]$k.GetValue('SystemComponent', 0) -eq 1 -or [string]$k.GetValue('ParentKeyName')) { continue }
                $win32.Add([pscustomobject]@{ Name = $name; Version = [string]$k.GetValue('DisplayVersion'); Publisher = [string]$k.GetValue('Publisher'); InstallDate = [string]$k.GetValue('InstallDate')
                        SizeMB = $(if ($k.GetValue('EstimatedSize')) { [Math]::Round([double]$k.GetValue('EstimatedSize') / 1024, 1) } else { $null }); Scope = $(if ($root -like 'HKCU*') { 'User' } else { 'Machine' }) })
            }
        } catch { Write-Verbose "Uninstall key not readable: $root" }
    }
    $appx = @()
    try {
        $appx = @(Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework } | ForEach-Object {
                $prot = Test-IgwtAppxProtected -Package ([string]$_.Name)
                $system = ([string]$_.SignatureKind -eq 'System')
                [pscustomobject]@{ Name = [string]$_.Name; Version = [string]$_.Version; Publisher = [string]$_.PublisherId; Inbox = ([string]$_.SignatureKind -in 'System', 'Store' -and [string]$_.Publisher -like '*Microsoft*')
                    Protected = ($prot -or $system); CanRemove = -not ($prot -or $system)
                    Note = $(if ($prot) { 'Protected: needed by the Store, gaming services, security or the shell.' } elseif ($system) { 'System component: cannot be removed.' } else { 'Removal is reversible only partially: iG Windows Tuner re-registers the app or reinstalls it from the Microsoft Store.' }) }
            })
    } catch { Write-Verbose 'Appx packages unavailable.' }
    $unique = @($win32 | Sort-Object Name, Version -Unique)
    [pscustomobject]@{ Win32 = $unique; Appx = @($appx | Sort-Object Name); Note = 'Win32 apps are uninstalled with their own uninstaller (Settings > Apps); iG Windows Tuner only removes inbox Appx apps, with a snapshot.' }
}

function Get-IgwtFeatureInventory {
    <# .SYNOPSIS Optional features and capabilities with their state (administrator rights needed to read them). #>
    [CmdletBinding()]
    param()
    $features = @(); $caps = @(); $err = ''
    try {
        $features = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.FeatureName; State = [string]$_.State; Protected = (Test-IgwtNamePattern -Name ([string]$_.FeatureName) -Patterns $script:IgwtProtectedFeatures) }
            } | Sort-Object Name)
    } catch { $err = 'Optional features need administrator rights to read.' }
    try {
        $caps = @(Get-WindowsCapability -Online -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; State = [string]$_.State; Protected = (Test-IgwtNamePattern -Name ([string]$_.Name) -Patterns $script:IgwtProtectedCapabilities) }
            } | Sort-Object Name)
    } catch { if (-not $err) { $err = 'Capabilities need administrator rights to read.' } }
    [pscustomobject]@{ Features = $features; Capabilities = $caps; Error = $err; Note = 'Changes are snapshot-backed (Invoke-IgwtManagedChange -Kind feature/capability); protected entries are refused.' }
}
