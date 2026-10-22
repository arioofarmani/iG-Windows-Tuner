# Toolkit.ps1
# Toolkit section, inspired by Chris Titus Tech's WinUtil (see docs\WINUTIL_MAPPING.md): curated
# winget installs, Windows features and capabilities, previewed fixes, launchers for inbox panels,
# and views over the WinUtil-derived and Windows Update catalog items. Data: data\toolkit\*.json.
# Every write goes through an existing audited path (winget with fixed arguments,
# Invoke-IgwtManagedChange, the cleaner, allow-listed fix steps). Nothing is fetched at runtime
# except the winget packages the user picks.

$script:IgwtToolkitData = @{}
$script:IgwtToolkitAppCategories = @('Browsers', 'Communication', 'Gaming', 'Streaming & Media', 'Development', 'Utilities', 'System tools', 'Sysadmin', 'Security & Privacy')
# Never installed from the Toolkit: Sysmon (detected and used when present, never installed) and
# Chocolatey (its bootstrap is download-and-execute).
$script:IgwtToolkitRefusedApps = @('Microsoft.Sysinternals.Sysmon', 'Chocolatey.Chocolatey')
$script:IgwtWingetIdPattern = '^[A-Za-z0-9][A-Za-z0-9\.\-_+]*$'
$script:IgwtWingetUpdateNotApplicable = -1978335189   # 0x8A15002B APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE
$script:IgwtFixStepKinds = @('run', 'service', 'renameFolder', 'appxRegisterFamily', 'appxRegisterInstalled', 'explorer', 'cleanerRule')
$script:IgwtFixExecutables = @('sfc.exe', 'dism.exe', 'chkdsk.exe', 'netsh.exe', 'ipconfig.exe', 'winmgmt.exe', 'wsreset.exe')
$script:IgwtFixServices = @('bits', 'wuauserv', 'cryptsvc', 'WSearch')
$script:IgwtFixFolders = @('{SystemRoot}\SoftwareDistribution\DataStore', '{SystemRoot}\SoftwareDistribution\Download', '{SystemRoot}\System32\catroot2')
$script:IgwtFixAppxFamilies = @('Microsoft.DesktopAppInstaller_8wekyb3d8bbwe')
$script:IgwtFixAppxPackages = @('Microsoft.Windows.StartMenuExperienceHost')
$script:IgwtPanelExecutables = @('control.exe', 'netplwiz.exe', 'resmon.exe', 'perfmon.exe', 'msinfo32.exe', 'rstrui.exe')

#region Data

function Get-IgwtToolkitData {
    <# .SYNOPSIS Entries of one Toolkit data file (apps, features, fixes or panels), cached per data folder. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Apps', 'Features', 'Fixes', 'Panels')][string]$Section)
    $key = "$Section|$(Get-IgwtDataFolder)"
    if (-not $script:IgwtToolkitData.ContainsKey($key)) {
        $name = $Section.ToLowerInvariant()
        $doc = Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) "toolkit\$name.json")
        $script:IgwtToolkitData[$key] = @($doc.$name | Where-Object { $_ })
    }
    return $script:IgwtToolkitData[$key]
}

function Get-IgwtToolkitEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Apps', 'Features', 'Fixes', 'Panels')][string]$Section, [Parameter(Mandatory = $true)][string]$Id)
    $e = @(Get-IgwtToolkitData -Section $Section | Where-Object { [string]$_.id -eq $Id }) | Select-Object -First 1
    if (-not $e) { throw "Unknown Toolkit $($Section.ToLowerInvariant().TrimEnd('s')) '$Id'. Use -Toolkit $Section to list them." }
    return $e
}

function Expand-IgwtToolkitToken {
    <# .SYNOPSIS Replaces {SystemRoot} and {SystemDrive} in a fix argument or path. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    return ([string]$Text).Replace('{SystemRoot}', $env:SystemRoot).Replace('{SystemDrive}', $env:SystemDrive)
}

function Test-IgwtToolkitCatalog {
    <# .SYNOPSIS Validates data\toolkit (texts, ids, allow-listed fix steps and panel targets). Returns error strings. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($n in 'apps', 'features', 'fixes', 'panels') {
        if (-not (Test-Path -LiteralPath (Join-Path (Get-IgwtDataFolder) "toolkit\$n.json"))) { $errors.Add("toolkit\$n.json: missing.") }
    }
    if ($errors.Count) { return $errors.ToArray() }
    $seen = @{}
    foreach ($a in @(Get-IgwtToolkitData -Section Apps)) {
        $label = "toolkit app '$($a.id)'"
        if ([string]$a.id -notmatch $script:IgwtWingetIdPattern) { $errors.Add("${label}: id must be a winget package id.") }
        if ($seen.ContainsKey("app:$($a.id)")) { $errors.Add("${label}: duplicate id.") } else { $seen["app:$($a.id)"] = $true }
        if ($script:IgwtToolkitRefusedApps -contains [string]$a.id) { $errors.Add("${label}: this package is never installed by the Toolkit.") }
        if (-not $a.name) { $errors.Add("${label}: missing name.") }
        if ($script:IgwtToolkitAppCategories -notcontains [string]$a.category) { $errors.Add("${label}: unknown category '$($a.category)'.") }
        Test-IgwtItemText -Item $a -Label $label -Errors $errors
    }
    foreach ($f in @(Get-IgwtToolkitData -Section Features)) {
        $label = "toolkit feature '$($f.id)'"
        if ([string]$f.id -notmatch '^(feature|capability)\.[a-z0-9\-]+$') { $errors.Add("${label}: id must be feature.* or capability.*.") }
        if ([string]$f.kind -notin 'feature', 'capability') { $errors.Add("${label}: kind must be feature or capability.") }
        if (@($f.targets | Where-Object { $_ }).Count -eq 0) { $errors.Add("${label}: needs targets.") }
        foreach ($e in @($f.editions | Where-Object { $_ })) { if ($script:IgwtEditionFamilies -notcontains [string]$e) { $errors.Add("${label}: unknown edition '$e'.") } }
        Test-IgwtItemText -Item $f -Label $label -Errors $errors
    }
    $cleanerIds = @(Get-IgwtCleanerRules | ForEach-Object { [string]$_.id })
    foreach ($x in @(Get-IgwtToolkitData -Section Fixes)) {
        $label = "toolkit fix '$($x.id)'"
        if ([string]$x.id -notmatch '^fix\.[a-z0-9\-]+$') { $errors.Add("${label}: id must be fix.*.") }
        if ([string]$x.source -notmatch '^https://') { $errors.Add("${label}: needs an https source.") }
        Test-IgwtItemText -Item $x -Label $label -Errors $errors
        $steps = @($x.steps | Where-Object { $_ })
        if ($steps.Count -eq 0) { $errors.Add("${label}: needs steps.") }
        foreach ($s in $steps) {
            switch ([string]$s.kind) {
                'run' { if ($script:IgwtFixExecutables -notcontains [string]$s.exe) { $errors.Add("${label}: '$($s.exe)' is not an allowed fix program.") } }
                'service' {
                    if ($script:IgwtFixServices -notcontains [string]$s.name) { $errors.Add("${label}: service '$($s.name)' is not allowed in fixes.") }
                    if ([string]$s.operation -notin 'stop', 'start', 'restart') { $errors.Add("${label}: service operation must be stop, start or restart.") }
                }
                'renameFolder' { if ($script:IgwtFixFolders -notcontains [string]$s.path) { $errors.Add("${label}: folder '$($s.path)' is not allowed in fixes.") } }
                'appxRegisterFamily' { if ($script:IgwtFixAppxFamilies -notcontains [string]$s.family) { $errors.Add("${label}: package family '$($s.family)' is not allowed.") } }
                'appxRegisterInstalled' { if ($script:IgwtFixAppxPackages -notcontains [string]$s.package) { $errors.Add("${label}: package '$($s.package)' is not allowed.") } }
                'explorer' { if ([string]$s.operation -notin 'stop', 'start') { $errors.Add("${label}: explorer operation must be stop or start.") } }
                'cleanerRule' { if ($cleanerIds -notcontains [string]$s.rule) { $errors.Add("${label}: unknown cleaner rule '$($s.rule)'.") } }
                default { $errors.Add("${label}: unknown step kind '$($s.kind)'.") }
            }
        }
    }
    foreach ($p in @(Get-IgwtToolkitData -Section Panels)) {
        $label = "toolkit panel '$($p.id)'"
        Test-IgwtItemText -Item $p -Label $label -Errors $errors
        try { $null = Resolve-IgwtPanelCommand -Panel $p -NoFileCheck } catch { $errors.Add("${label}: $($_.Exception.Message)") }
    }
    return $errors.ToArray()
}

#endregion

#region Install (winget)

function Get-IgwtWingetConsentPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Get-IgwtDataPath -Kind State) 'winget-consent.json')
}

function Get-IgwtWingetAgreements {
    <# .SYNOPSIS The agreements shown before the first winget install or upgrade, and whether they were accepted. #>
    [CmdletBinding()]
    param()
    [pscustomobject]@{
        Accepted = (Test-IgwtWingetConsent)
        Lines    = @(
            'Packages come from the winget community repository (source "winget", https://github.com/microsoft/winget-pkgs) and are installed by winget, the Windows Package Manager.'
            'Each package is licensed to you by its owner, not by Microsoft or iG Windows Tuner. "winget show --id <package>" shows its license and publisher.'
            'Installing or upgrading passes --accept-package-agreements and --accept-source-agreements to winget: you accept each chosen package''s license and the source''s terms (https://aka.ms/winget-command-help).'
            'winget sends the package identifiers you install to the source in order to download them; installers then run with their own silent options.'
        )
    }
}

function Test-IgwtWingetConsent {
    <# .SYNOPSIS True after the user accepted the winget agreements (Set-IgwtWingetConsent). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($null -ne $script:IgwtSettings.WingetConsent) { return [bool]$script:IgwtSettings.WingetConsent }
    $path = Get-IgwtWingetConsentPath
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try { return ([bool](Read-IgwtJsonFile -Path $path).accepted) } catch { return $false }
}

function Set-IgwtWingetConsent {
    <# .SYNOPSIS Records (or withdraws) the user's acceptance of the winget agreements. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$Revoke)
    if ($script:IgwtSettings.TestMode) { $script:IgwtSettings.WingetConsent = -not $Revoke; return }
    if (-not $PSCmdlet.ShouldProcess('winget agreements', $(if ($Revoke) { 'Withdraw acceptance' } else { 'Record acceptance' }))) { return }
    Initialize-IgwtDataRoot
    $doc = [ordered]@{ accepted = (-not $Revoke); date = (Get-Date).ToString('o'); user = [Environment]::UserName }
    [System.IO.File]::WriteAllText((Get-IgwtWingetConsentPath), (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
    Write-IgwtLog -Message "winget agreements $(if ($Revoke) { 'withdrawn' } else { 'accepted' }) by $([Environment]::UserName)."
}

function ConvertFrom-IgwtWingetExport {
    <# .SYNOPSIS Parses 'winget export' JSON into a hashtable of package id -> version. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)][string]$Json)
    $map = @{}
    $doc = $Json | ConvertFrom-Json
    foreach ($src in @($doc.Sources | Where-Object { $_ })) {
        foreach ($p in @($src.Packages | Where-Object { $_ })) {
            if ($p.PackageIdentifier) { $map[[string]$p.PackageIdentifier] = [string]$p.Version }
        }
    }
    return $map
}

function Get-IgwtWingetInventory {
    <#
    .SYNOPSIS
        Installed packages that map to the winget source (id -> version), from one 'winget export'
        to a temporary file. Read-only; cached for 2 minutes and cleared by every install.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return (Get-IgwtCached -Key 'winget:inventory' -TtlSeconds 120 -ScriptBlock {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-winget-{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                $wArgs = @('export', '--output', $tmp, '--source', 'winget', '--include-versions', '--disable-interactivity')
                if (Test-IgwtWingetConsent) { $wArgs += '--accept-source-agreements' }
                $r = Invoke-IgwtWinget -Arguments $wArgs
                if (-not (Test-Path -LiteralPath $tmp)) { throw "winget export wrote no file (exit $($r.ExitCode))." }
                ConvertFrom-IgwtWingetExport -Json ([System.IO.File]::ReadAllText($tmp))
            } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue -WhatIf:$false } }
        })
}

function Get-IgwtToolkitApps {
    <#
    .SYNOPSIS
        The curated winget catalog (data\toolkit\apps.json). -WithState adds Installed and Version
        from one winget export.
    #>
    [CmdletBinding()]
    param([string]$Category, [string]$Search, [switch]$WithState)
    $apps = @(Get-IgwtToolkitData -Section Apps)
    if ($Category) { $apps = @($apps | Where-Object { [string]$_.category -eq $Category }) }
    if ($Search) {
        $s = $Search.Trim()
        $apps = @($apps | Where-Object { ([string]$_.name).IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or ([string]$_.id).IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or ([string]$_.hint).IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
    }
    $inv = $null; $invError = ''
    if ($WithState) { try { $inv = Get-IgwtWingetInventory } catch { $invError = $_.Exception.Message } }
    foreach ($a in $apps) {
        $installed = $null; $version = ''
        if ($inv) { $installed = $inv.ContainsKey([string]$a.id); if ($installed) { $version = [string]$inv[[string]$a.id] } }
        [pscustomobject]@{ Id = [string]$a.id; Name = [string]$a.name; Category = [string]$a.category; Foss = [bool]$a.foss; Hint = [string]$a.hint
            Description = [string]$a.description; Note = [string]$a.note; Installed = $installed; Version = $version; StateNote = $invError }
    }
}

function Test-IgwtToolkitAppId {
    <# .SYNOPSIS Throws when an id is not a valid winget id or is refused. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    if ($Id -notmatch $script:IgwtWingetIdPattern) { throw "'$Id' is not a valid winget package id." }
    if ($script:IgwtToolkitRefusedApps -contains $Id) { throw "'$Id' is never installed by iG Windows Tuner (Sysmon is only detected; Chocolatey's bootstrap is download-and-execute)." }
}

function Update-IgwtWingetPackage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Id, [switch]$AcceptAgreements)
    if (-not $AcceptAgreements) { throw 'Accept the winget agreements first.' }
    if (-not $PSCmdlet.ShouldProcess($Id, 'winget upgrade')) { return 'Skipped' }
    $r = Invoke-IgwtWinget -Arguments @('upgrade', '--id', $Id, '--exact', '--source', 'winget', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    if ($r.ExitCode -eq $script:IgwtWingetUpdateNotApplicable) { return 'UpToDate' }
    if ($r.ExitCode -eq $script:IgwtWingetNotFound) { return 'NotInstalled' }
    if ($r.ExitCode -ne 0) { throw "winget upgrade $Id failed (exit $($r.ExitCode))." }
    return 'Upgraded'
}

function Invoke-IgwtToolkitApp {
    <#
    .SYNOPSIS
        Installs, upgrades or uninstalls winget packages, one at a time, with progress and logging.
    .PARAMETER Operation
        Install, Upgrade or Uninstall.
    .PARAMETER Id
        winget package ids (from the curated list or any valid id).
    .PARAMETER AcceptAgreements
        The user accepted the winget agreements (Get-IgwtWingetAgreements). Install and Upgrade
        refuse to run without it or a recorded acceptance.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Install', 'Upgrade', 'Uninstall')][string]$Operation,
        [Parameter(Mandatory = $true)][string[]]$Id, [switch]$AcceptAgreements, [scriptblock]$OnProgress)
    $ids = @($Id | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($i in $ids) { Test-IgwtToolkitAppId -Id $i }
    $accepted = ([bool]$AcceptAgreements -or (Test-IgwtWingetConsent))
    if ($Operation -ne 'Uninstall' -and -not $accepted) { throw "winget's package and source agreements have not been accepted. Review them (Get-IgwtWingetAgreements or the Toolkit > Install page) and pass -AcceptAgreements." }
    $results = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($i in $ids) {
        $n++
        Send-IgwtProgress -Text "$Operation $i ($n of $($ids.Count))" -Percent ([int](100 * ($n - 1) / $ids.Count)) -Callback $OnProgress
        $result = 'Skipped'; $msg = ''
        try {
            switch ($Operation) {
                'Install' {
                    if (Test-IgwtWingetInstalled -Id $i) { $result = 'AlreadyInstalled' }
                    elseif ($PSCmdlet.ShouldProcess($i, 'winget install')) { Install-IgwtWingetPackage -Id $i -AcceptAgreements; $result = 'Installed' }
                }
                'Upgrade' { $result = Update-IgwtWingetPackage -Id $i -AcceptAgreements -WhatIf:$WhatIfPreference }
                'Uninstall' {
                    if (-not (Test-IgwtWingetInstalled -Id $i)) { $result = 'NotInstalled' }
                    elseif ($PSCmdlet.ShouldProcess($i, 'winget uninstall')) { Uninstall-IgwtWingetPackage -Id $i; $result = 'Uninstalled' }
                }
            }
        } catch { $result = 'Failed'; $msg = $_.Exception.Message }
        if ($result -notin 'Skipped') { Write-IgwtLog -Level $(if ($result -eq 'Failed') { 'Error' } else { 'Info' }) -Message "Toolkit ${Operation} ${i}: $result $msg" }
        $results.Add([pscustomobject]@{ Id = $i; Operation = $Operation; Result = $result; Message = $msg })
    }
    Clear-IgwtCache -Prefix 'winget:' -WhatIf:$false
    Send-IgwtProgress -Text 'Done' -Percent 100 -Callback $OnProgress
    return $results.ToArray()
}

function Invoke-IgwtWingetUpgradeAll {
    <# .SYNOPSIS Runs 'winget upgrade --all' for packages from the winget source (needs the accepted agreements). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$AcceptAgreements)
    if (-not ([bool]$AcceptAgreements -or (Test-IgwtWingetConsent))) { throw "winget's package and source agreements have not been accepted; pass -AcceptAgreements after reviewing them." }
    if (-not $PSCmdlet.ShouldProcess('all winget packages', 'winget upgrade --all')) { return $null }
    $r = Invoke-IgwtWinget -Arguments @('upgrade', '--all', '--source', 'winget', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    Clear-IgwtCache -Prefix 'winget:' -WhatIf:$false
    Write-IgwtLog -Message "Toolkit: winget upgrade --all finished (exit $($r.ExitCode))."
    return [pscustomobject]@{ ExitCode = $r.ExitCode; Output = [string]$r.Output; Result = $(if ($r.ExitCode -eq 0) { 'Completed' } else { 'Failed' }) }
}

function Get-IgwtAppSelectionHash {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][string[]]$Id)
    $text = (@($Id) -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Export-IgwtAppSelection {
    <# .SYNOPSIS Writes a list of winget ids to a JSON file with a SHA256 integrity field. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string[]]$Id)
    $ids = @($Id | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($i in $ids) { Test-IgwtToolkitAppId -Id $i }
    $doc = [ordered]@{ format = 'igwt-app-selection'; version = 1; created = (Get-Date).ToString('o'); apps = $ids; sha256 = (Get-IgwtAppSelectionHash -Id $ids) }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write app selection')) { return }
    [System.IO.File]::WriteAllText($Path, (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

function Import-IgwtAppSelection {
    <# .SYNOPSIS Reads an app selection file and checks its format, ids and SHA256 field. Returns the ids. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $doc = Read-IgwtJsonFile -Path $Path
    if ([string]$doc.format -ne 'igwt-app-selection') { throw "'$Path' is not an iG Windows Tuner app selection file." }
    $ids = @($doc.apps | ForEach-Object { [string]$_ })
    if ((Get-IgwtAppSelectionHash -Id $ids) -ne [string]$doc.sha256) { throw "The app list in '$Path' does not match its SHA256 field; the file was changed or damaged." }
    foreach ($i in $ids) { Test-IgwtToolkitAppId -Id $i }
    return $ids
}

#endregion

#region Features

function Get-IgwtToolkitFeatures {
    <#
    .SYNOPSIS
        Windows features and capabilities offered in the Toolkit; -WithState adds the current state
        of each target and whether this edition has the feature. Read-only.
    #>
    [CmdletBinding()]
    param([switch]$WithState, [string]$EditionId)
    if ($WithState -and -not $EditionId) { $EditionId = [string](Get-IgwtOsInfo).EditionId }
    foreach ($f in @(Get-IgwtToolkitData -Section Features)) {
        $state = $null; $targets = @()
        $editions = @($f.editions | Where-Object { $_ })
        $supported = Test-IgwtEditionSupported -Editions $editions -EditionId $EditionId
        if ($WithState) {
            $targets = @(foreach ($t in @($f.targets)) {
                    $a = New-IgwtToolkitFeatureAction -Kind ([string]$f.kind) -Target ([string]$t) -Enable $true
                    $cur = 'Unknown'
                    try { $it = @(Get-IgwtActionState -Action $a -Context $null) | Select-Object -First 1; $cur = [string]$it.Current; $st = [string]$it.State } catch { $st = 'Unknown'; $cur = $_.Exception.Message }
                    [pscustomobject]@{ Target = [string]$t; Current = $cur; State = $st }
                })
            $state = Get-IgwtStateRollup -States @($targets | ForEach-Object { $_.State })
        }
        [pscustomobject]@{ Id = [string]$f.id; Name = [string]$f.name; Kind = [string]$f.kind; Targets = @($f.targets); Hint = [string]$f.hint; Description = [string]$f.description
            Warning = [string]$f.warning; Reboot = [bool]$f.reboot; Editions = $editions; Supported = $supported; State = $state; TargetStates = $targets }
    }
}

function New-IgwtToolkitFeatureAction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory action only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][bool]$Enable)
    if ($Kind -eq 'capability') { return [pscustomobject]@{ type = 'capability'; name = $Target; on = $(if ($Enable) { 'Installed' } else { 'NotPresent' }); default = $(if ($Enable) { 'NotPresent' } else { 'Installed' }) } }
    return [pscustomobject]@{ type = 'optionalFeature'; feature = $Target; on = $(if ($Enable) { 'Enabled' } else { 'Disabled' }); default = $(if ($Enable) { 'Disabled' } else { 'Enabled' }) }
}

function Invoke-IgwtToolkitFeature {
    <#
    .SYNOPSIS
        Enables or disables a Toolkit feature through the managed-change path (one snapshot per
        target, revert with -RevertAll or the snapshot list). Protected features are never disabled.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled')][string]$State)
    $f = Get-IgwtToolkitEntry -Section Features -Id $Id
    $edition = [string](Get-IgwtOsInfo).EditionId
    $editions = @($f.editions | Where-Object { $_ })
    if ($State -eq 'Enabled' -and -not (Test-IgwtEditionSupported -Editions $editions -EditionId $edition)) {
        throw "'$($f.name)' is not available on this edition ($(Get-IgwtEditionFamily -EditionId $edition)); it needs $($editions -join ', ')."
    }
    $kind = [string]$f.kind
    $value = $State
    if ($kind -eq 'capability') { $value = $(if ($State -eq 'Enabled') { 'Installed' } else { 'NotPresent' }) }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($f.targets)) {
        if (-not $PSCmdlet.ShouldProcess([string]$t, "$kind -> $value")) { continue }
        $r = Invoke-IgwtManagedChange -Kind $kind -Target ([string]$t) -Value $value
        foreach ($x in @($r.Results)) { $results.Add($x) }
        if ($r.Changes -eq 0) { $results.Add([pscustomobject]@{ Target = [string]$t; Change = "$kind $t -> $value"; Result = 'AlreadySet'; Message = '' }) }
    }
    return [pscustomobject]@{ Id = $Id; State = $State; Results = $results.ToArray(); RebootRequired = ([bool]$f.reboot -and @($results | Where-Object { $_.Result -eq 'Applied' }).Count -gt 0) }
}

#endregion

#region Fixes

function Format-IgwtFixStep {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Step, [string]$Stamp = '<time>')
    switch ([string]$Step.kind) {
        'run' { return ('Run {0} {1}' -f (Resolve-IgwtFixExecutable -Name ([string]$Step.exe)), ((@($Step.arguments) | ForEach-Object { Expand-IgwtToolkitToken ([string]$_) }) -join ' ')).Trim() }
        'service' { return ('{0} the {1} service' -f (Get-Culture).TextInfo.ToTitleCase([string]$Step.operation), [string]$Step.name) }
        'renameFolder' { $p = Expand-IgwtToolkitToken ([string]$Step.path); return ('Rename {0} to {1}.igwt-{2} (kept, not deleted)' -f $p, (Split-Path -Leaf $p), $Stamp) }
        'appxRegisterFamily' { return ('Re-register the app package {0} for your account' -f [string]$Step.family) }
        'appxRegisterInstalled' { return ('Re-register {0} from its install folder' -f [string]$Step.package) }
        'explorer' { return $(if ([string]$Step.operation -eq 'stop') { 'Close Explorer (taskbar and open folders)' } else { 'Start Explorer again' }) }
        'cleanerRule' { return ('Scan and clean with cleaner rule {0}' -f [string]$Step.rule) }
    }
    return [string]$Step.kind
}

function Resolve-IgwtFixExecutable {
    <# .SYNOPSIS Full path of an allow-listed System32 program (Sysnative from a 32-bit process). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:IgwtFixExecutables -notcontains $Name) { throw "'$Name' is not an allowed fix program." }
    $dir = 'System32'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $dir = 'Sysnative' }
    return (Join-Path (Join-Path $env:SystemRoot $dir) $Name)
}

function Get-IgwtToolkitFixes {
    <# .SYNOPSIS The Toolkit fixes with their steps as text. Read-only. #>
    [CmdletBinding()]
    param()
    foreach ($x in @(Get-IgwtToolkitData -Section Fixes)) { Get-IgwtToolkitFixPlan -Id ([string]$x.id) }
}

function Get-IgwtToolkitFixPlan {
    <# .SYNOPSIS Preview of a fix: every step it would run, its warning, and whether it needs admin rights or a reboot. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $x = Get-IgwtToolkitEntry -Section Fixes -Id $Id
    [pscustomobject]@{
        Id = [string]$x.id; Name = [string]$x.name; Hint = [string]$x.hint; Description = [string]$x.description; Warning = [string]$x.warning
        Admin = [bool]$x.admin; Reboot = [bool]$x.reboot; Minutes = [int]$x.minutes; Source = [string]$x.source; RefuseInRdp = [bool]$x.refuseInRdp
        Steps = @(@($x.steps) | ForEach-Object { Format-IgwtFixStep -Step $_ })
    }
}

function Invoke-IgwtFixProcess {
    <# .SYNOPSIS Runs an allow-listed program and returns ExitCode and Output. Refuses to run in TestMode (tests mock it). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$FilePath, [AllowEmptyCollection()][string[]]$Arguments = @(), [switch]$UnicodeOutput)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: fix programs must be mocked in tests.' }
    if (-not $PSCmdlet.ShouldProcess("$FilePath $($Arguments -join ' ')", 'Run')) { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
    $old = $null
    # sfc writes UTF-16 to a redirected stdout (step flag unicodeOutput).
    try { $old = [Console]::OutputEncoding; if ($UnicodeOutput) { [Console]::OutputEncoding = [System.Text.Encoding]::Unicode } } catch { $old = $null }
    try {
        $out = & $FilePath @Arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { if ($old) { try { [Console]::OutputEncoding = $old } catch { Write-Verbose 'Console encoding not restored.' } } }
    return [pscustomobject]@{ ExitCode = $code; Output = ($out -replace "`0", '').Trim() }
}

function Invoke-IgwtFixStep {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Step, [Parameter(Mandatory = $true)][string]$Stamp)
    $text = Format-IgwtFixStep -Step $Step -Stamp $Stamp
    switch ([string]$Step.kind) {
        'service' { if ($script:IgwtFixServices -notcontains [string]$Step.name -or [string]$Step.operation -notin 'stop', 'start', 'restart') { throw "Service step '$($Step.name)' is not allowed." } }
        'renameFolder' { if ($script:IgwtFixFolders -notcontains [string]$Step.path) { throw "Folder '$($Step.path)' is not allowed in fixes." } }
        'appxRegisterFamily' { if ($script:IgwtFixAppxFamilies -notcontains [string]$Step.family) { throw "Package family '$($Step.family)' is not allowed." } }
        'appxRegisterInstalled' { if ($script:IgwtFixAppxPackages -notcontains [string]$Step.package) { throw "Package '$($Step.package)' is not allowed." } }
        'cleanerRule' { if (@(Get-IgwtCleanerRules | Where-Object { [string]$_.id -eq [string]$Step.rule }).Count -eq 0) { throw "Unknown cleaner rule '$($Step.rule)'." } }
        'explorer' { if ([string]$Step.operation -notin 'stop', 'start') { throw 'Explorer step must be stop or start.' } }
        'run' { $null = Resolve-IgwtFixExecutable -Name ([string]$Step.exe) }
        default { throw "Unknown fix step kind '$($Step.kind)'." }
    }
    if (-not $PSCmdlet.ShouldProcess($text, 'Fix step')) { return [pscustomobject]@{ Step = $text; Result = 'Skipped'; Output = '' } }
    switch ([string]$Step.kind) {
        'run' {
            $exe = Resolve-IgwtFixExecutable -Name ([string]$Step.exe)
            $r = Invoke-IgwtFixProcess -FilePath $exe -Arguments @(@($Step.arguments) | ForEach-Object { Expand-IgwtToolkitToken ([string]$_) }) -UnicodeOutput:([bool]$Step.unicodeOutput)
            return [pscustomobject]@{ Step = $text; Result = $(if ($r.ExitCode -eq 0) { 'Done' } else { "ExitCode $($r.ExitCode)" }); Output = [string]$r.Output }
        }
        'service' {
            $n = [string]$Step.name
            switch ([string]$Step.operation) {
                'stop' { Stop-Service -Name $n -Force -ErrorAction Stop }
                'start' { Start-Service -Name $n -ErrorAction Stop }
                'restart' { Restart-Service -Name $n -Force -ErrorAction Stop }
            }
            return [pscustomobject]@{ Step = $text; Result = 'Done'; Output = '' }
        }
        'renameFolder' {
            $p = Expand-IgwtToolkitToken ([string]$Step.path)
            if (-not (Test-Path -LiteralPath $p)) { return [pscustomobject]@{ Step = $text; Result = 'NotPresent'; Output = '' } }
            $new = '{0}.igwt-{1}' -f (Split-Path -Leaf $p), $Stamp
            Rename-Item -LiteralPath $p -NewName $new -ErrorAction Stop
            return [pscustomobject]@{ Step = $text; Result = 'Done'; Output = "Renamed to $new" }
        }
        'appxRegisterFamily' {
            Add-AppxPackage -RegisterByFamilyName -MainPackage ([string]$Step.family) -ErrorAction Stop
            return [pscustomobject]@{ Step = $text; Result = 'Done'; Output = '' }
        }
        'appxRegisterInstalled' {
            $pkgs = @(Get-AppxPackage -Name ([string]$Step.package) -ErrorAction Stop | Where-Object { $_ })
            if ($pkgs.Count -eq 0) { throw "$($Step.package) is not installed; Microsoft supports no reinstall of this inbox package (reset Windows or restore a backup)." }
            foreach ($p in $pkgs) { Add-AppxPackage -DisableDevelopmentMode -Register (Join-Path ([string]$p.InstallLocation) 'AppXManifest.xml') -ErrorAction Stop }
            return [pscustomobject]@{ Step = $text; Result = 'Done'; Output = '' }
        }
        'explorer' {
            if ([string]$Step.operation -eq 'stop') {
                Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 1500
            } elseif (@(Get-Process -Name 'explorer' -ErrorAction SilentlyContinue).Count -eq 0) {
                Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe')
            }
            return [pscustomobject]@{ Step = $text; Result = 'Done'; Output = '' }
        }
        'cleanerRule' {
            $rule = [string]$Step.rule
            $scan = Invoke-IgwtCleanerScan -RuleId $rule
            $c = Invoke-IgwtCleanerClean -Scan $scan -RuleId $rule
            return [pscustomobject]@{ Step = $text; Result = 'Done'; Output = ('{0:N1} MB freed' -f ($c.FreedBytes / 1MB)) }
        }
    }
    throw "Unknown fix step kind '$($Step.kind)'."
}

function Invoke-IgwtToolkitFix {
    <#
    .SYNOPSIS
        Runs a Toolkit fix after its preview (Get-IgwtToolkitFixPlan). Steps run in order; after a
        failed step only the recovery steps (starting services and Explorer) still run. A restore
        point is created first for fixes that need a reboot. Everything is logged.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [scriptblock]$OnProgress)
    $x = Get-IgwtToolkitEntry -Section Fixes -Id $Id
    if ([bool]$x.admin -and -not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw "'$($x.name)' needs administrator rights." }
    if ([bool]$x.refuseInRdp -and (Test-IgwtRdpSession)) { throw "'$($x.name)' is refused in a Remote Desktop session because it can cut the connection." }
    if (-not $PSCmdlet.ShouldProcess([string]$x.name, 'Run fix')) { return $null }
    if ([bool]$x.reboot -and -not $script:IgwtSettings.TestMode) {
        try { $null = New-IgwtRestorePoint -Description "iG Windows Tuner: before $($x.name)" } catch { Write-IgwtLog -Level Warn -Message "Restore point before $($x.id) failed: $($_.Exception.Message)" }
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $steps = @($x.steps)
    $results = New-Object System.Collections.Generic.List[object]
    $failed = $false
    for ($i = 0; $i -lt $steps.Count; $i++) {
        $s = $steps[$i]
        $recovery = (([string]$s.kind -eq 'service' -and [string]$s.operation -in 'start', 'restart') -or ([string]$s.kind -eq 'explorer' -and [string]$s.operation -eq 'start'))
        if ($failed -and -not $recovery) { $results.Add([pscustomobject]@{ Step = (Format-IgwtFixStep -Step $s -Stamp $stamp); Result = 'NotRun'; Output = '' }); continue }
        Send-IgwtProgress -Text "$($x.name): step $($i + 1) of $($steps.Count)" -Percent ([int](100 * $i / $steps.Count)) -Callback $OnProgress
        try { $r = Invoke-IgwtFixStep -Step $s -Stamp $stamp }
        catch { $r = [pscustomobject]@{ Step = (Format-IgwtFixStep -Step $s -Stamp $stamp); Result = 'Failed'; Output = $_.Exception.Message }; $failed = $true }
        $results.Add($r)
        Write-IgwtLog -Level $(if ($r.Result -eq 'Failed') { 'Error' } else { 'Info' }) -Message "Fix $($x.id): $($r.Step): $($r.Result)"
    }
    Send-IgwtProgress -Text 'Done' -Percent 100 -Callback $OnProgress
    $overall = 'Completed'
    if ($failed) { $overall = 'Failed' } elseif (@($results | Where-Object { $_.Result -like 'ExitCode*' }).Count) { $overall = 'CompletedWithWarnings' }
    return [pscustomobject]@{ Id = [string]$x.id; Name = [string]$x.name; Result = $overall; Steps = $results.ToArray(); RebootRequired = ([bool]$x.reboot -and -not $failed) }
}

#endregion

#region Panels, tweaks and updates

function Resolve-IgwtPanelCommand {
    <# .SYNOPSIS FilePath and Arguments that open a panel; only inbox tools and ms-settings: links. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Panel, [switch]$NoFileCheck)
    $target = [string]$Panel.target
    $sys = Join-Path $env:SystemRoot 'System32'
    switch ([string]$Panel.launch) {
        'exe' {
            $parts = $target.Split([char[]]@(' '), 2)
            if ($script:IgwtPanelExecutables -notcontains $parts[0]) { throw "'$($parts[0])' is not an allowed panel program." }
            $argList = @(); if ($parts.Count -gt 1) { $argList = @($parts[1].Split(' ')) }
            return [pscustomobject]@{ FilePath = (Join-Path $sys $parts[0]); Arguments = $argList }
        }
        'cpl' {
            if ($target -notmatch '^[a-z0-9]+\.cpl$') { throw "'$target' is not a Control Panel item." }
            if (-not $NoFileCheck -and -not (Test-Path -LiteralPath (Join-Path $sys $target))) { throw "'$($Panel.name)' is not available on this PC." }
            return [pscustomobject]@{ FilePath = (Join-Path $sys 'control.exe'); Arguments = @($target) }
        }
        'msc' {
            if ($target -notmatch '^[a-z0-9]+\.msc$') { throw "'$target' is not a management console." }
            if (-not $NoFileCheck -and -not (Test-Path -LiteralPath (Join-Path $sys $target))) { throw "'$($Panel.name)' is not available on this edition (for example gpedit.msc is missing on Windows Home)." }
            return [pscustomobject]@{ FilePath = (Join-Path $sys 'mmc.exe'); Arguments = @((Join-Path $sys $target)) }
        }
        'uri' {
            if ($target -notmatch '^ms-settings:[a-z0-9\-]+$') { throw "'$target' is not an ms-settings: link." }
            return [pscustomobject]@{ FilePath = $target; Arguments = @() }
        }
    }
    throw "Unknown panel launch type '$($Panel.launch)'."
}

function Get-IgwtToolkitPanels {
    <# .SYNOPSIS The Toolkit panel launchers. Read-only. #>
    [CmdletBinding()]
    param()
    foreach ($p in @(Get-IgwtToolkitData -Section Panels)) {
        [pscustomobject]@{ Id = [string]$p.id; Name = [string]$p.name; Hint = [string]$p.hint; Description = [string]$p.description; Command = (([string]$p.launch) + ': ' + [string]$p.target) }
    }
}

function Invoke-IgwtPanelProcess {
    <# .SYNOPSIS Starts a panel. Refuses to run in TestMode (tests mock it). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$FilePath, [AllowEmptyCollection()][string[]]$Arguments = @())
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: panel launches must be mocked in tests.' }
    if (-not $PSCmdlet.ShouldProcess($FilePath, 'Open')) { return }
    if (@($Arguments).Count) { Start-Process -FilePath $FilePath -ArgumentList $Arguments } else { Start-Process -FilePath $FilePath }
}

function Start-IgwtPanel {
    <# .SYNOPSIS Opens an inbox Windows tool or Settings page from the Toolkit list (changes nothing by itself). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id)
    $p = Get-IgwtToolkitEntry -Section Panels -Id $Id
    $cmd = Resolve-IgwtPanelCommand -Panel $p
    if (-not $PSCmdlet.ShouldProcess([string]$p.name, 'Open')) { return }
    Invoke-IgwtPanelProcess -FilePath $cmd.FilePath -Arguments $cmd.Arguments
}

function Get-IgwtToolkitTweaks {
    <# .SYNOPSIS Catalog items derived from WinUtil (source 'winutil'); they also appear in their normal categories. #>
    [CmdletBinding()]
    param()
    return @(Get-IgwtCatalog | Where-Object { [string]$_.source -eq 'winutil' })
}

function Get-IgwtToolkitUpdateItems {
    <#
    .SYNOPSIS
        The Windows Update items of the catalog (deferrals, driver exclusion, active hours,
        Delivery Optimization). There is no 'disable updates' item; pausing is done in Settings.
    #>
    [CmdletBinding()]
    param()
    return @(Get-IgwtCatalog | Where-Object { [string]$_.group -eq 'Windows Update' -or [string]$_.id -eq 'net.delivery-optimization-p2p-off' })
}

#endregion
