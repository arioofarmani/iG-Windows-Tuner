<#
.SYNOPSIS
    Registry cleaner round trip INSIDE Windows Sandbox: fake leftovers -> scan -> plan -> removal ->
    restore per entry and per session -> compare (DECISIONS RG27).
.DESCRIPTION
    Not for a real PC: it really removes and restores registry keys, values and firewall rules. It
    refuses to run unless it is sure it runs in Windows Sandbox: the process user must be the
    Sandbox account WDAGUtilityAccount (observed only, RG28 item 16) and the process must be
    elevated. Nothing is downloaded or installed. Windows Sandbox has no System Restore (RG28 item
    17), so the cleanup always runs with -SkipRestorePoint.

    Steps:
      1. Fake leftovers of the invented program 'SbxContoso' whose folder is deleted again: an
         Uninstall entry in the 64-bit view with a value of every kind, an Uninstall entry in the
         32-bit view (RegistryView.Registry32), App Paths, a ProgID, Run values (64-bit, 32-bit and
         HKCU), an HKCU Software key, and a firewall Allow and Block rule for the deleted program.
      2. reg export of every fake key (before), owner and SDDL of every fake key (observation).
      3. Get-IgwtRegistryLeftovers, Get-IgwtRegCleanPlan for the fake findings,
         Invoke-IgwtRegistryCleanup -SkipRestorePoint; every fake key must be gone and the rules
         deleted.
      4. Restore one entry (Get-IgwtRevertPlan -EntryId), then the rest of the session
         (-SessionId); reg export again and compare with step 2; firewall rules compared field by
         field; owner and SDDL recorded again (observation, not a pass criterion).
      5. reg import of the backup's selected.reg into a copy key (HKCU\Software\iGSandboxCopy) and a
         value-by-value comparison with the restored originals.
      6. Observations: MSI ProductState of an installed product (when one exists) and of an
         invented product code, Get-AppxPackage -AllUsers elevated, and that no finding lies below a
         deny-list (link) key.
    Results in -ResultsPath: registry-cleaner-sandbox.json (criteria, observations, timings in
    seconds) and the reg export files.
.PARAMETER ResultsPath
    Writable results folder (default C:\SandboxResults, as for tools\Invoke-SandboxTest.ps1).
.EXAMPLE
    # In an elevated Windows PowerShell inside Windows Sandbox:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\iGWindowsTuner\tools\RegistryCleaner.Sandbox.ps1
#>
[CmdletBinding()]
param([string]$ResultsPath = 'C:\SandboxResults')
$ErrorActionPreference = 'Stop'

# Safety stop first, before anything is read or written.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$userName = [string]$identity.Name
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $userName -notlike '*\WDAGUtilityAccount') {
    throw 'Safety stop: this script removes and restores registry keys and firewall rules for real and only runs inside Windows Sandbox (user WDAGUtilityAccount).'
}
if (-not $isAdmin) { throw 'Run this script from an elevated Windows PowerShell inside Windows Sandbox.' }
if (-not [Environment]::Is64BitProcess) { throw 'Run this script from the 64-bit Windows PowerShell.' }

if (-not (Test-Path -LiteralPath $ResultsPath)) { $null = New-Item -ItemType Directory -Path $ResultsPath -Force }
$projectRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $projectRoot 'src\iGWindowsTuner.psd1') -Force
$module = Get-Module iGWindowsTuner

$report = [ordered]@{ Started = (Get-Date).ToString('o'); User = $userName; Criteria = [ordered]@{}; Observations = [ordered]@{}; Timings = [ordered]@{}; Errors = @() }
$pass = { param([string]$Name, [bool]$Ok, [string]$Detail) $report.Criteria[$Name] = [ordered]@{ Pass = $Ok; Detail = $Detail }; Write-Output ('{0,-5} {1} {2}' -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail) }
$observe = { param([string]$Name, $Value) $report.Observations[$Name] = $Value; Write-Output "NOTE  $Name" }
$time = { param([string]$Name, [scriptblock]$Block) $sw = [Diagnostics.Stopwatch]::StartNew(); $r = & $Block; $report.Timings[$Name] = [Math]::Round($sw.Elapsed.TotalSeconds, 2); return $r }

function Get-SbxBaseKey {
    <# .SYNOPSIS Opens HKLM in a view or HKCU (Sandbox script only). #>
    param([string]$Hive, [string]$View)
    $v = $(if ($View -eq '32') { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 })
    $h = $(if ($Hive -eq 'HKCU') { [Microsoft.Win32.RegistryHive]::CurrentUser } else { [Microsoft.Win32.RegistryHive]::LocalMachine })
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, $v)
}

function Write-SbxFakeKey {
    <# .SYNOPSIS Creates a key and writes values {name -> @(kind, data)} (Sandbox script only). #>
    param([string]$Hive, [string]$View, [string]$Path, [hashtable]$Values)
    $base = Get-SbxBaseKey -Hive $Hive -View $View
    try {
        $k = $base.CreateSubKey($Path)
        try { foreach ($n in $Values.Keys) { $k.SetValue($n, $Values[$n][1], [Microsoft.Win32.RegistryValueKind]$Values[$n][0]) } } finally { $k.Dispose() }
    } finally { $base.Dispose() }
}

function Get-SbxKeyDump {
    <# .SYNOPSIS Every subkey and value of a tree as sorted text lines (Sandbox script only); $null when absent. #>
    param([string]$Hive, [string]$View, [string]$Path, [string]$ValueName)
    $base = Get-SbxBaseKey -Hive $Hive -View $View
    try {
        $root = $base.OpenSubKey($Path, $false)
        if (-not $root) { return $null }
        $lines = New-Object System.Collections.Generic.List[string]
        $queue = New-Object System.Collections.Generic.Queue[object]
        $queue.Enqueue(@('', $root))
        while ($queue.Count) {
            $item = $queue.Dequeue(); $rel = [string]$item[0]; $k = $item[1]
            try {
                $lines.Add("[$rel]")
                foreach ($n in @($k.GetValueNames() | Sort-Object)) {
                    if ($ValueName -and $n -ne $ValueName) { continue }
                    $raw = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $data = $(if ($raw -is [byte[]]) { [BitConverter]::ToString($raw) } elseif ($raw -is [string[]]) { ($raw | ForEach-Object { '<' + $_ + '>' }) -join '' } else { [string]$raw })
                    $lines.Add(('{0}={1}:{2}' -f $n, $k.GetValueKind($n), $data))
                }
                if (-not $ValueName) { foreach ($s in @($k.GetSubKeyNames() | Sort-Object)) { $queue.Enqueue(@($(if ($rel) { "$rel\$s" } else { $s }), $k.OpenSubKey($s, $false))) } }
            } finally { $k.Dispose() }
        }
        if ($ValueName -and $lines.Count -lt 2) { return $null }
        return ($lines -join "`n")
    } finally { $base.Dispose() }
}

function Get-SbxNativePath {
    <# .SYNOPSIS The physical path of a fake key for reg.exe and Get-Acl (Sandbox script only). #>
    param([string]$Hive, [string]$View, [string]$Path)
    if ($Hive -eq 'HKCU') { return 'HKEY_CURRENT_USER\' + $Path }
    if ($View -eq '32' -and $Path -match '^(?i)SOFTWARE\\') { return 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\' + $Path.Substring(9) }
    return 'HKEY_LOCAL_MACHINE\' + $Path
}

function Get-SbxSecurity {
    <# .SYNOPSIS Owner and SDDL of a fake key, or the error text (Sandbox script only). #>
    param([string]$Hive, [string]$View, [string]$Path)
    try { $a = Get-Acl -LiteralPath ('Registry::' + (Get-SbxNativePath -Hive $Hive -View $View -Path $Path)); return [ordered]@{ Owner = [string]$a.Owner; Sddl = [string]$a.Sddl } }
    catch { return [ordered]@{ Error = $_.Exception.Message } }
}

function Invoke-SbxReg {
    <# .SYNOPSIS Runs reg.exe and returns its exit code; its messages go to stderr, which must not stop the script (Sandbox script only). #>
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $null = & reg.exe @Arguments 2>&1
    return $LASTEXITCODE
}

function Export-SbxKey {
    <# .SYNOPSIS reg export of a fake key into the results folder; returns the text or $null (Sandbox script only). #>
    param($Fake, [string]$Stage)
    $file = Join-Path $ResultsPath ('regclean-{0}-{1}.reg' -f $Fake.Id, $Stage)
    $native = Get-SbxNativePath -Hive $Fake.Hive -View $Fake.View -Path $Fake.Path
    if ((Invoke-SbxReg -Arguments @('export', $native, $file, '/y', '/reg:64')) -ne 0 -or -not (Test-Path -LiteralPath $file)) { return $null }
    return [IO.File]::ReadAllText($file)
}

$fakes = @()
$sid = [string]$identity.User.Value
try {
    # 1. Fake leftovers of a program whose folder no longer exists.
    $folder = 'C:\SbxContoso\App'
    $null = New-Item -ItemType Directory -Path $folder -Force
    [IO.File]::WriteAllText("$folder\app.exe", 'placeholder')
    $exe = "$folder\app.exe"
    $un = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $run = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $fakes = @(
        [pscustomobject]@{ Id = 'uninstall64'; Category = 'uninstall'; Hive = 'HKLM'; View = '64'; Path = "$un\SbxContosoApp"; ValueName = ''; Values = @{
                DisplayName = @('String', 'SbxContoso App'); Publisher = @('String', 'SbxContoso Ltd'); InstallLocation = @('String', $folder)
                UninstallString = @('String', """$folder\unins000.exe"""); DisplayIcon = @('ExpandString', '%SystemDrive%\SbxContoso\App\app.exe,0')
                Languages = @('MultiString', [string[]]@('en-US', '', 'de-DE')); EstimatedSize = @('DWord', 4096); InstallStamp = @('QWord', [long]5000000000)
                Blob = @('Binary', [byte[]](0, 1, 2, 254, 255)); NoneValue = @('None', [byte[]](9, 8, 7)); 'Quote "and" back\slash' = @('String', "line with ""quotes"" and \")
            }
        }
        [pscustomobject]@{ Id = 'uninstall32'; Category = 'uninstall'; Hive = 'HKLM'; View = '32'; Path = "$un\SbxContoso32"; ValueName = ''; Values = @{ DisplayName = @('String', 'SbxContoso 32'); InstallLocation = @('String', 'C:\SbxContoso\App32'); UninstallString = @('String', '"C:\SbxContoso\App32\unins000.exe"') } }
        [pscustomobject]@{ Id = 'appPath'; Category = 'appPath'; Hive = 'HKLM'; View = '64'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\sbxcontoso.exe'; ValueName = ''; Values = @{ '' = @('String', $exe); Path = @('String', $folder) } }
        [pscustomobject]@{ Id = 'progId'; Category = 'progId'; Hive = 'HKLM'; View = '64'; Path = 'SOFTWARE\Classes\SbxContoso.Document'; ValueName = ''; Values = @{ '' = @('String', 'SbxContoso Document') } }
        [pscustomobject]@{ Id = 'run64'; Category = 'run'; Hive = 'HKLM'; View = '64'; Path = $run; ValueName = 'SbxContosoTray'; Values = @{ SbxContosoTray = @('String', """$exe"" /tray") } }
        [pscustomobject]@{ Id = 'run32'; Category = 'run'; Hive = 'HKLM'; View = '32'; Path = $run; ValueName = 'SbxContosoTray32'; Values = @{ SbxContosoTray32 = @('String', '"C:\SbxContoso\App32\tray.exe"') } }
        [pscustomobject]@{ Id = 'runUser'; Category = 'run'; Hive = 'HKCU'; View = '64'; Path = 'Software\Microsoft\Windows\CurrentVersion\Run'; ValueName = 'SbxContosoUser'; Values = @{ SbxContosoUser = @('ExpandString', '%SystemDrive%\SbxContoso\App\app.exe --user') } }
        [pscustomobject]@{ Id = 'softwareUser'; Category = 'softwareKey'; Hive = 'HKCU'; View = '64'; Path = 'Software\SbxContoso\App'; ValueName = ''; Values = @{ InstallPath = @('String', $folder); Settings = @('Binary', [byte[]](1, 2, 3)) } }
    )
    foreach ($f in $fakes) { Write-SbxFakeKey -Hive $f.Hive -View $f.View -Path $f.Path -Values $f.Values }
    # The ProgID's open verb (the finding is the whole SbxContoso.Document tree).
    Write-SbxFakeKey -Hive HKLM -View 64 -Path 'SOFTWARE\Classes\SbxContoso.Document\shell\open\command' -Values @{ '' = @('String', """$exe"" ""%1""") }
    $rules = @(
        New-NetFirewallRule -Name 'SbxContoso-Allow' -DisplayName 'SbxContoso Allow' -Direction Inbound -Action Allow -Program $exe -Profile Any
        New-NetFirewallRule -Name 'SbxContoso-Block' -DisplayName 'SbxContoso Block' -Direction Outbound -Action Block -Program $exe -Profile Any
    )
    $ruleFields = { param($n) $r = Get-NetFirewallRule -Name $n -PolicyStore PersistentStore -ErrorAction SilentlyContinue; if (-not $r) { return $null }; $a = $r | Get-NetFirewallApplicationFilter; '{0}|{1}|{2}|{3}|{4}|{5}' -f $r.DisplayName, $r.Direction, $r.Action, $r.Enabled, $r.Profile, $a.Program }
    $rulesBefore = @{}; foreach ($r in $rules) { $rulesBefore[$r.Name] = & $ruleFields $r.Name }
    Remove-Item -LiteralPath 'C:\SbxContoso' -Recurse -Force
    & $pass 'fake program folder deleted' (-not (Test-Path -LiteralPath 'C:\SbxContoso')) 'C:\SbxContoso'

    # 2. Before: reg exports, dumps, owner and SDDL.
    $before = @{}; $dumpBefore = @{}; $secBefore = @{}
    foreach ($f in $fakes) {
        $before[$f.Id] = Export-SbxKey -Fake $f -Stage 'before'
        $dumpBefore[$f.Id] = Get-SbxKeyDump -Hive $f.Hive -View $f.View -Path $f.Path -ValueName $f.ValueName
        $secBefore[$f.Id] = Get-SbxSecurity -Hive $f.Hive -View $f.View -Path $f.Path
    }
    & $pass 'Registry32 view writes land in WOW6432Node' ($null -ne (Get-SbxKeyDump -Hive HKLM -View 64 -Path "SOFTWARE\WOW6432Node\$un\SbxContoso32")) 'the 32-bit Uninstall entry is visible at its physical path'
    & $pass 'Registry64 view does not see the 32-bit entry at the logical path' ($null -eq (Get-SbxKeyDump -Hive HKLM -View 64 -Path "$un\SbxContoso32")) 'WOW64 redirection of HKLM\SOFTWARE'

    # 3. Scan, plan, removal.
    $scan = & $time 'scanSeconds' { Get-IgwtRegistryLeftovers }
    $report.Observations['scanFindings'] = @($scan.Findings).Count
    $report.Observations['scanSkipped'] = $scan.Skipped
    $report.Observations['scanNotes'] = @($scan.Notes)
    $ours = @($scan.Findings | Where-Object { ([string]$_.Path + '|' + [string]$_.ValueName + '|' + [string]$_.RuleName) -like '*SbxContoso*' })
    foreach ($f in $fakes) {
        $hit = @($ours | Where-Object { $_.Hive -eq $f.Hive -and [string]$_.Path -eq $f.Path -and [string]$_.ValueName -eq $f.ValueName -and ($f.Hive -eq 'HKCU' -or [string]$_.View -eq $f.View) })
        & $pass "scan finds $($f.Id)" ($hit.Count -eq 1) $(if ($hit.Count) { "$($hit[0].Confidence), selectable $($hit[0].Selectable)" } else { 'not found' })
    }
    foreach ($r in $rules) { & $pass "scan finds firewall rule $($r.Name)" (@($ours | Where-Object { $_.RuleName -eq $r.Name }).Count -eq 1) '' }
    $denySegments = @((Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'data\registry\categories.json') | ConvertFrom-Json).denyList.segmentNames)
    # Microsoft and Wow6432Node are part of category roots; the other deny-list names are link or shared keys.
    $linkNames = @($denySegments | Where-Object { $_ -notin 'Microsoft', 'Wow6432Node' })
    $linked = @($scan.Findings | Where-Object { $p = [string]$_.Path; @($linkNames | Where-Object { $p -match ('(?i)(^|\\)' + [regex]::Escape($_) + '(\\|$)') }).Count -gt 0 })
    & $observe 'findingsBelowDenyListKeys' @($linked | ForEach-Object { "$($_.Hive)\$($_.Path)" })

    $selected = @($ours | Where-Object { $_.Selectable -and $_.Confidence -in 'Safe', 'Review' })
    $plan = & $time 'planSeconds' { Get-IgwtRegCleanPlan -Findings $selected }
    & $observe 'planRefused' @($plan.Refused | ForEach-Object { "$($_.Path) $($_.ValueName) $($_.RuleName): $($_.Reason)" })
    $res = & $time 'cleanupSeconds' { Invoke-IgwtRegistryCleanup -Plan $plan -SkipRestorePoint -Confirm:$false }
    & $pass 'cleanup removed every planned entry' ($res.Removed -ge @($plan.Targets).Count -and $res.Failed -eq 0) $res.Message
    $report.Observations['cleanupResults'] = @($res.Results | ForEach-Object { "$($_.Result) $($_.Hive)\$($_.Path) $($_.ValueName) $($_.RuleName) $($_.Message)" })
    foreach ($f in $fakes) {
        $gone = $null -eq (Get-SbxKeyDump -Hive $f.Hive -View $f.View -Path $f.Path -ValueName $f.ValueName)
        $planned = @($plan.Targets | Where-Object { [string]$_.Path -eq $f.Path -and [string]$_.ValueName -eq $f.ValueName }).Count -gt 0
        if ($planned) { & $pass "removed $($f.Id) (bottom-up)" $gone '' }
    }
    foreach ($r in $rules) { if (@($plan.Targets | Where-Object { $_.RuleName -eq $r.Name }).Count) { & $pass "firewall rule $($r.Name) deleted" ($null -eq (& $ruleFields $r.Name)) '' } }

    # 4. Restore: one entry, then the rest of the session.
    $rows = @((Get-IgwtJournalTimeline).Rows | Where-Object { [string]$_.Session -eq [string]$res.SessionId -and $_.EntryId -and [string]$_.Result -eq 'Committed' })
    if ($rows.Count) {
        $one = $rows[0]
        $entryPlan = @(Get-IgwtRevertPlan -EntryId ([string]$one.EntryId))
        $r1 = & $time 'restoreEntrySeconds' { Invoke-IgwtJournalRevert -Plan $entryPlan -Title 'Sandbox: restore one entry' -Confirm:$false }
        & $pass 'restore of one entry' ($null -ne $r1 -and @($r1.Results | Where-Object { [string]$_.Result -eq 'Failed' }).Count -eq 0) ([string]$one.Target)
    } else { & $pass 'restore of one entry' $false 'no journal entry for the session' }
    $sessionPlan = @(Get-IgwtRevertPlan -SessionId ([string]$res.SessionId))
    $r2 = & $time 'restoreSessionSeconds' { Invoke-IgwtJournalRevert -Plan $sessionPlan -Title 'Sandbox: restore the session' -Confirm:$false }
    & $pass 'restore of the session' (@($r2.Results | Where-Object { [string]$_.Result -eq 'Failed' }).Count -eq 0) ''
    $secAfter = @{}
    foreach ($f in $fakes) {
        $after = Export-SbxKey -Fake $f -Stage 'after'
        $planned = @($plan.Targets | Where-Object { [string]$_.Path -eq $f.Path -and [string]$_.ValueName -eq $f.ValueName }).Count -gt 0
        if (-not $planned) { continue }
        & $pass "reg export equal after restore: $($f.Id)" ($null -ne $after -and $after -eq $before[$f.Id]) ''
        & $pass "data equal after restore: $($f.Id)" ((Get-SbxKeyDump -Hive $f.Hive -View $f.View -Path $f.Path -ValueName $f.ValueName) -eq $dumpBefore[$f.Id]) ''
        $secAfter[$f.Id] = Get-SbxSecurity -Hive $f.Hive -View $f.View -Path $f.Path
    }
    foreach ($r in $rules) { if (@($plan.Targets | Where-Object { $_.RuleName -eq $r.Name }).Count) { & $pass "firewall rule $($r.Name) recreated" ((& $ruleFields $r.Name) -eq $rulesBefore[$r.Name]) ([string](& $ruleFields $r.Name)) } }
    & $observe 'securityBefore' $secBefore
    & $observe 'securityAfter' $secAfter

    # 5. reg import of selected.reg into a copy key.
    $selectedReg = Join-Path ([string]$res.Backup) 'selected.reg'
    if (Test-Path -LiteralPath $selectedReg) {
        $text = [IO.File]::ReadAllText($selectedReg)
        $copyRoot = 'Software\iGSandboxCopy'
        $copy = [regex]::Replace($text, '(?m)^\[HKEY_(LOCAL_MACHINE|USERS)\\', { param($m) '[HKEY_CURRENT_USER\' + $copyRoot + $(if ($m.Groups[1].Value -eq 'USERS') { '\HKU\' } else { '\HKLM\' }) })
        $copyFile = Join-Path $ResultsPath 'regclean-selected-copy.reg'
        [IO.File]::WriteAllText($copyFile, $copy, [Text.Encoding]::Unicode)
        $code = & $time 'regImportSeconds' { Invoke-SbxReg -Arguments @('import', $copyFile) }
        & $pass 'reg import of selected.reg' ($code -eq 0) "$copyFile (exit $code)"
        foreach ($f in $fakes) {
            if (-not @($plan.Targets | Where-Object { [string]$_.Path -eq $f.Path -and [string]$_.ValueName -eq $f.ValueName }).Count) { continue }
            $phys = Get-SbxNativePath -Hive $f.Hive -View $f.View -Path $f.Path
            $copyPath = $(if ($f.Hive -eq 'HKCU') { "$copyRoot\HKU\$sid\" + $f.Path } else { "$copyRoot\HKLM\" + $phys.Substring(19) })
            & $pass "reg import recreates the data: $($f.Id)" ((Get-SbxKeyDump -Hive HKCU -View 64 -Path $copyPath -ValueName $f.ValueName) -eq $dumpBefore[$f.Id]) $copyPath
        }
    } else { & $pass 'reg import of selected.reg' $false "no selected.reg in '$($res.Backup)'" }

    # 6. Observations.
    $installedMsi = @(Get-ChildItem -LiteralPath "Registry::HKEY_LOCAL_MACHINE\$un" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$' -and $_.GetValue('WindowsInstaller') -eq 1 } | Select-Object -First 1)
    & $observe 'msiProductState' ([ordered]@{
            Installed = $(if ($installedMsi.Count) { [ordered]@{ Code = $installedMsi[0].PSChildName; State = (& $module { param($c) Get-IgwtMsiProductState -ProductCode $c } $installedMsi[0].PSChildName) } } else { 'no MSI product installed in this Sandbox' })
            Invented  = (& $module { Get-IgwtMsiProductState -ProductCode '{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}' })
        })
    & $observe 'appxPackagesAllUsersElevated' (& $module { @(Get-IgwtRegCleanAppxPackages).Count })
} catch {
    $report.Errors += ($_.Exception.Message + ' ' + $_.ScriptStackTrace)
    Write-Output "ERROR $($_.Exception.Message)"
} finally {
    $report.Finished = (Get-Date).ToString('o')
    $report.Passed = @($report.Criteria.Values | Where-Object { $_.Pass }).Count
    $report.Failed = @($report.Criteria.Values | Where-Object { -not $_.Pass }).Count
    [IO.File]::WriteAllText((Join-Path $ResultsPath 'registry-cleaner-sandbox.json'), ($report | ConvertTo-Json -Depth 6))
    Write-Output ("Registry cleaner Sandbox run: {0} passed, {1} failed, {2} error(s). Report: {3}" -f $report.Passed, $report.Failed, @($report.Errors).Count, (Join-Path $ResultsPath 'registry-cleaner-sandbox.json'))
}
