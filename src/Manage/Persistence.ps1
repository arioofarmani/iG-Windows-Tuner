# Persistence.ps1
# Persistence Inspector (read-only, Autoruns-style): Run/RunOnce keys (including WOW6432Node),
# Startup folders, non-Microsoft services and drivers, non-Microsoft scheduled tasks, WMI event
# subscriptions, Winlogon Shell/Userinit, IFEO Debugger values, AppInit_DLLs and browser extensions,
# with the Authenticode signature of each file. The only actions offered are documented disable
# mechanisms that already exist elsewhere: startup entries (StartupApproved), services (startup
# type) and scheduled tasks (disable), each snapshot-backed. Everything else is reported for review.

$script:IgwtSignatureCache = @{}

function Resolve-IgwtCommandPath {
    <# .SYNOPSIS The executable or DLL path inside a command line, image path or registry value. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Command)
    if (-not $Command) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    if ($c -match '^(?i)system32\\') { $c = Join-Path $env:SystemRoot $c }
    $path = ''
    if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 1) { $path = $c.Substring(1, $end - 1) } }
    else {
        $m = [regex]::Match($c, '^(?i)(.+?\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|scr|cpl|ocx))(\s|,|$)')
        $path = $(if ($m.Success) { $m.Groups[1].Value } else { ($c -split '\s+')[0] })
    }
    if ($path -and $path -notmatch '^[A-Za-z]:\\' -and $path -notmatch '^\\\\') {
        $candidate = Join-Path (Join-Path $env:SystemRoot 'System32') $path
        if (Test-Path -LiteralPath $candidate) { $path = $candidate }
    }
    return $path
}

function Get-IgwtFileSignature {
    <# .SYNOPSIS Authenticode status and signer of a file (cached). Status NotFound when the file is missing. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path)
    if (-not $Path) { return [pscustomobject]@{ Status = 'NoFile'; Signer = ''; IsMicrosoft = $false } }
    $k = $Path.ToLowerInvariant()
    if ($script:IgwtSignatureCache.ContainsKey($k)) { return $script:IgwtSignatureCache[$k] }
    $r = [pscustomobject]@{ Status = 'NotFound'; Signer = ''; IsMicrosoft = $false }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $subject = $(if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' })
            $cn = $(if ($subject -match '^CN=(?:"([^"]+)"|([^,]+))') { $(if ($Matches[1]) { $Matches[1] } else { $Matches[2] }) } else { $subject })
            # WHQL-signed third-party drivers carry a Microsoft signature; the file's company name tells them apart.
            $company = ''
            try { $company = [string](Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName } catch { $company = '' }
            $r = [pscustomobject]@{ Status = [string]$s.Status; Signer = $cn; IsMicrosoft = ([string]$s.Status -eq 'Valid' -and $subject -match 'O=Microsoft Corporation' -and (-not $company -or $company -match 'Microsoft')) }
        } catch { $r = [pscustomobject]@{ Status = 'Unknown'; Signer = ''; IsMicrosoft = $false } }
    }
    $script:IgwtSignatureCache[$k] = $r
    return $r
}

function New-IgwtPersistenceEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param([string]$Category, [string]$Location, [string]$Name, [string]$Command, [string]$Severity = 'Info', [string]$Note = '', [string]$ActionKind = 'None', [string]$ActionTarget = '', $Enabled = $null, [switch]$NoSignature)
    $file = Resolve-IgwtCommandPath -Command $Command
    $sig = $(if ($NoSignature) { [pscustomobject]@{ Status = ''; Signer = ''; IsMicrosoft = $false } } else { Get-IgwtFileSignature -Path $file })
    if ($Severity -eq 'Info' -and -not $NoSignature -and $sig.Status -notin 'Valid', '') { $Severity = 'Review' }
    [pscustomobject]@{
        Category = $Category; Location = $Location; Name = $Name; Command = $Command; File = $file; Signature = $sig.Status; Signer = $sig.Signer; IsMicrosoft = $sig.IsMicrosoft
        Enabled = $Enabled; Severity = $Severity; Note = $Note; ActionKind = $ActionKind; ActionTarget = $ActionTarget
    }
}

function Get-IgwtRunKeyEntries {
    [CmdletBinding()]
    param()
    $keys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Scope = 'HKLM-Run' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = '' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Scope = 'HKLM-Run32' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = '' }
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'HKCU-Run' }
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = '' }
    )
    $startup = @{}
    try { foreach ($s in @(Get-IgwtStartupItem)) { $startup["$($s.Scope)|$($s.Name)"] = $s } } catch { Write-Verbose 'Startup items unavailable.' }
    foreach ($k in $keys) {
        try {
            $item = Get-Item -LiteralPath (Resolve-IgwtRegistryPath $k.Path) -ErrorAction Stop
            foreach ($n in $item.GetValueNames()) {
                if (-not $n) { continue }
                $cmd = [string]$item.GetValue($n)
                $st = $startup["$($k.Scope)|$n"]
                New-IgwtPersistenceEntry -Category 'Run keys' -Location $k.Path -Name $n -Command $cmd -Enabled $(if ($st) { [bool]$st.Enabled } else { $true }) `
                    -ActionKind $(if ($k.Scope) { 'StartupEntry' } else { 'None' }) -ActionTarget $(if ($k.Scope) { "$($k.Scope)|$n" } else { '' }) -Note $(if (-not $k.Scope) { 'RunOnce entries run once at the next sign-in and then delete themselves.' } else { '' })
            }
        } catch { Write-Verbose "Key not readable: $($k.Path)" }
    }
    foreach ($f in @(@{ Path = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'; Scope = 'User-Folder' }, @{ Path = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp'; Scope = 'Common-Folder' })) {
        $dir = [Environment]::ExpandEnvironmentVariables($f.Path)
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $target = $file.FullName
            if ($file.Extension -eq '.lnk') {
                try { $sh = New-Object -ComObject WScript.Shell; $target = [string]$sh.CreateShortcut($file.FullName).TargetPath } catch { $target = $file.FullName }
            }
            $st = $startup["$($f.Scope)|$($file.Name)"]
            New-IgwtPersistenceEntry -Category 'Startup folders' -Location $dir -Name $file.Name -Command $target -Enabled $(if ($st) { [bool]$st.Enabled } else { $true }) -ActionKind 'StartupEntry' -ActionTarget "$($f.Scope)|$($file.Name)"
        }
    }
}

function Get-IgwtPersistenceInventory {
    <#
    .SYNOPSIS
        Read-only persistence view (Autoruns-style) with signature status. Severity: Info (signed,
        expected), Review (unsigned, unknown signer or missing file) or Warn (a location malware
        typically uses: IFEO Debugger, AppInit_DLLs, changed Winlogon values, WMI command or script
        consumers). ActionKind tells which documented disable mechanism applies (StartupEntry,
        Service, Task) or None.
    .PARAMETER IncludeMicrosoft
        Also list Microsoft-signed services, drivers and tasks (slow: every file is checked).
    #>
    [CmdletBinding()]
    param([switch]$IncludeMicrosoft)
    $entries = New-Object System.Collections.Generic.List[object]
    $add = { param($e) foreach ($x in @($e)) { if ($x) { $entries.Add($x) } } }
    & $add (Get-IgwtRunKeyEntries)
    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            # Without administrator rights Windows hides the image path of a few protected services.
            if (-not [string]$s.PathName) { if ($IncludeMicrosoft) { $entries.Add((New-IgwtPersistenceEntry -Category 'Services' -Location 'Services' -Name "$($s.DisplayName) ($($s.Name))" -Command '' -NoSignature -Enabled ([string]$s.StartMode -ne 'Disabled') -Note 'Image path not readable without administrator rights.')) }; continue }
            $e = New-IgwtPersistenceEntry -Category 'Services' -Location 'Services' -Name "$($s.DisplayName) ($($s.Name))" -Command ([string]$s.PathName) -Enabled ([string]$s.StartMode -ne 'Disabled') `
                -ActionKind $(if (Get-IgwtServiceProtection -Name ([string]$s.Name)) { 'None' } else { 'Service' }) -ActionTarget ([string]$s.Name) -Note "Startup: $($s.StartMode), state: $($s.State)"
            if ($IncludeMicrosoft -or -not $e.IsMicrosoft) { $entries.Add($e) }
        }
    } catch { Write-Verbose 'Services unavailable.' }
    try {
        foreach ($d in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Where-Object { [string]$_.StartMode -in 'Boot', 'System', 'Auto' })) {
            $e = New-IgwtPersistenceEntry -Category 'Drivers' -Location 'Drivers' -Name "$($d.DisplayName) ($($d.Name))" -Command ([string]$d.PathName) -Enabled $true -Note "Startup: $($d.StartMode), state: $($d.State)"
            if ($IncludeMicrosoft -or -not $e.IsMicrosoft) { $entries.Add($e) }
        }
    } catch { Write-Verbose 'Drivers unavailable.' }
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            $full = "$($t.TaskPath)$($t.TaskName)"
            foreach ($a in @($t.Actions | Where-Object { $_.PSObject.Properties['Execute'] -and $_.Execute })) {
                $e = New-IgwtPersistenceEntry -Category 'Scheduled tasks' -Location ([string]$t.TaskPath) -Name ([string]$t.TaskName) -Command "$($a.Execute) $($a.Arguments)" -Enabled ([string]$t.State -ne 'Disabled') `
                    -ActionKind 'Task' -ActionTarget $full -Note "Author: $($t.Author)"
                if ($IncludeMicrosoft -or -not ($e.IsMicrosoft -and [string]$t.TaskPath -like '\Microsoft\*')) { $entries.Add($e) }
            }
        }
    } catch { Write-Verbose 'Scheduled tasks unavailable.' }
    try {
        $binds = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)
        foreach ($c in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)) {
            $cls = [string]$c.CimClass.CimClassName
            $cmd = $(if ($c.PSObject.Properties['CommandLineTemplate'] -and $c.CommandLineTemplate) { [string]$c.CommandLineTemplate } elseif ($c.PSObject.Properties['ScriptText'] -and $c.ScriptText) { 'script: ' + ([string]$c.ScriptText).Substring(0, [Math]::Min(80, ([string]$c.ScriptText).Length)) } else { '' })
            $bound = @($binds | Where-Object { [string]$_.Consumer -match [regex]::Escape([string]$c.Name) }).Count -gt 0
            $known = ([string]$c.Name -eq 'SCM Event Log Consumer' -and $cls -eq 'NTEventLogEventConsumer')
            $sev = $(if ($known) { 'Info' } elseif ($cls -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { 'Warn' } else { 'Review' })
            $entries.Add((New-IgwtPersistenceEntry -Category 'WMI subscriptions' -Location 'root\subscription' -Name "$($c.Name) [$cls]" -Command $cmd -Severity $sev -Enabled $bound -NoSignature `
                        -Note $(if ($known) { 'Windows default consumer.' } else { 'WMI event consumers run code when an event fires; investigate unknown ones (Defender scan, Autoruns).' })))
        }
    } catch { Write-Verbose 'WMI subscriptions unavailable.' }
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($v in @(@{ Name = 'Shell'; Expected = '^explorer\.exe$' }, @{ Name = 'Userinit'; Expected = '^(?i)[A-Z]:\\Windows\\system32\\userinit\.exe,?$' })) {
        try {
            $r = Get-IgwtRegistryValue -Path $wl -Name $v.Name
            if ($r.Exists) {
                $ok = ([string]$r.Value).Trim() -match $v.Expected
                $entries.Add((New-IgwtPersistenceEntry -Category 'Winlogon' -Location $wl -Name $v.Name -Command ([string]$r.Value) -Severity $(if ($ok) { 'Info' } else { 'Warn' }) -NoSignature -Note $(if ($ok) { 'Windows default.' } else { 'Changed from the Windows default; malware uses this value to start with every sign-in.' })))
            }
        } catch { Write-Verbose 'Winlogon not readable.' }
    }
    foreach ($ifeo in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        try {
            foreach ($k in @(Get-ChildItem -LiteralPath (Resolve-IgwtRegistryPath $ifeo) -ErrorAction Stop)) {
                $dbg = $k.GetValue('Debugger')
                if ($dbg) { $entries.Add((New-IgwtPersistenceEntry -Category 'IFEO Debugger' -Location $ifeo -Name ([string]$k.PSChildName) -Command ([string]$dbg) -Severity 'Warn' -Note 'A Debugger value starts another program instead of this one. Legitimate uses are rare (developer tools); malware uses it to hijack programs.')) }
            }
        } catch { Write-Verbose "IFEO not readable: $ifeo" }
    }
    foreach ($w in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        try {
            $dlls = Get-IgwtRegistryValue -Path $w -Name 'AppInit_DLLs'
            $load = Get-IgwtRegistryValue -Path $w -Name 'LoadAppInit_DLLs'
            if ($dlls.Exists -and ([string]$dlls.Value).Trim()) {
                $entries.Add((New-IgwtPersistenceEntry -Category 'AppInit_DLLs' -Location $w -Name 'AppInit_DLLs' -Command ([string]$dlls.Value) -Severity 'Warn' -Enabled ($load.Exists -and [int]$load.Value -eq 1) -Note 'DLLs loaded into every process that loads user32.dll. Deprecated; on Secure Boot systems Windows ignores them.'))
            }
        } catch { Write-Verbose "AppInit not readable: $w" }
    }
    foreach ($b in @(Get-IgwtBrowserExtensions)) { $entries.Add($b) }
    $list = $entries.ToArray()
    [pscustomobject]@{
        Generated = (Get-Date).ToString('o')
        Entries   = $list
        Counts    = [pscustomobject]@{ Total = $list.Count; Warn = @($list | Where-Object { $_.Severity -eq 'Warn' }).Count; Review = @($list | Where-Object { $_.Severity -eq 'Review' }).Count }
        Note      = 'Read-only. Startup entries, services and tasks can be disabled through their documented mechanisms with a snapshot; other locations are reported for review (use Microsoft Defender or Autoruns to investigate).'
    }
}

function Get-IgwtBrowserExtensions {
    <# .SYNOPSIS Installed Chromium (Chrome, Edge, Brave) and Firefox extensions of the current user (read-only). #>
    [CmdletBinding()]
    param()
    $browsers = @(
        @{ Name = 'Chrome'; Root = '%LOCALAPPDATA%\Google\Chrome\User Data' }
        @{ Name = 'Edge'; Root = '%LOCALAPPDATA%\Microsoft\Edge\User Data' }
        @{ Name = 'Brave'; Root = '%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data' }
    )
    foreach ($b in $browsers) {
        $root = [Environment]::ExpandEnvironmentVariables($b.Root)
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($profileDir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
            $ext = Join-Path $profileDir.FullName 'Extensions'
            if (-not (Test-Path -LiteralPath $ext)) { continue }
            foreach ($idDir in @(Get-ChildItem -LiteralPath $ext -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[a-p]{32}$' })) {
                $manifest = @(Get-ChildItem -LiteralPath $idDir.FullName -Filter 'manifest.json' -Recurse -File -ErrorAction SilentlyContinue) | Select-Object -First 1
                $name = $idDir.Name; $version = ''
                if ($manifest) {
                    try { $m = Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop | ConvertFrom-Json; if ($m.name -and [string]$m.name -notlike '__MSG_*') { $name = [string]$m.name }; $version = [string]$m.version } catch { Write-Verbose "Manifest unreadable: $($manifest.FullName)" }
                }
                New-IgwtPersistenceEntry -Category 'Browser extensions' -Location "$($b.Name) / $($profileDir.Name)" -Name "$name $version".Trim() -Command $idDir.Name -NoSignature -Note 'Review extensions you did not install; they can read the pages you visit.'
            }
        }
    }
    $ff = [Environment]::ExpandEnvironmentVariables('%APPDATA%\Mozilla\Firefox\Profiles')
    if (Test-Path -LiteralPath $ff) {
        foreach ($p in @(Get-ChildItem -LiteralPath $ff -Directory -ErrorAction SilentlyContinue)) {
            $json = Join-Path $p.FullName 'extensions.json'
            if (-not (Test-Path -LiteralPath $json)) { continue }
            try {
                $doc = Get-Content -LiteralPath $json -Raw -ErrorAction Stop | ConvertFrom-Json
                foreach ($a in @($doc.addons | Where-Object { $_ -and [string]$_.type -eq 'extension' -and [string]$_.location -eq 'app-profile' })) {
                    New-IgwtPersistenceEntry -Category 'Browser extensions' -Location "Firefox / $($p.Name)" -Name "$($a.defaultLocale.name) $($a.version)".Trim() -Command ([string]$a.id) -NoSignature -Enabled ([bool]$a.active) -Note 'Review extensions you did not install; they can read the pages you visit.'
                }
            } catch { Write-Verbose "Firefox extensions unreadable: $json" }
        }
    }
}

function Export-IgwtPersistenceReport {
    <# .SYNOPSIS Writes the persistence inventory as a self-contained HTML file (no scripts) or JSON. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Inventory, [Parameter(Mandatory = $true)][string]$Path, [ValidateSet('Html', 'Json')][string]$Format = 'Html')
    if (-not $PSCmdlet.ShouldProcess($Path, "Write $Format persistence report")) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    if ($Format -eq 'Json') { [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Inventory -Depth 6), (New-Object System.Text.UTF8Encoding($false))); return $Path }
    $e = { param($t) ConvertTo-IgwtHtmlText $t }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>iG Windows Tuner persistence report</title><style>body{font-family:"Segoe UI",sans-serif;margin:16px;color:#1b1b1f;background:#fff}@media (prefers-color-scheme:dark){body{color:#f3f3f3;background:#1c1c1c}}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #8884;padding:4px 6px;text-align:left;vertical-align:top;font-size:13px}.Warn{color:#c42b1c;font-weight:600}.Review{color:#9d5d00;font-weight:600}</style></head><body>')
    $null = $sb.Append("<h1>iG Windows Tuner persistence report</h1><p>$(& $e $Inventory.Generated) - $($Inventory.Counts.Total) entries, $($Inventory.Counts.Warn) warnings, $($Inventory.Counts.Review) to review. Read-only report.</p>")
    foreach ($g in ($Inventory.Entries | Group-Object Category)) {
        $null = $sb.Append("<h2>$(& $e $g.Name)</h2><table><tr><th>Severity</th><th>Name</th><th>Command / file</th><th>Signature</th><th>Note</th></tr>")
        foreach ($x in $g.Group) { $null = $sb.Append("<tr><td class='$($x.Severity)'>$($x.Severity)</td><td>$(& $e $x.Name)<br><small>$(& $e $x.Location)</small></td><td>$(& $e $x.Command)</td><td>$(& $e $x.Signature) $(& $e $x.Signer)</td><td>$(& $e $x.Note)</td></tr>") }
        $null = $sb.Append('</table>')
    }
    $null = $sb.Append('</body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}
