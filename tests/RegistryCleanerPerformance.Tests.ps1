# Registry cleaner performance budgets (DECISIONS RG25, step RG-B9).
# Every measurement runs in a clean child powershell.exe (the T19 lesson: Pester mocks and a long-lived
# test session make PowerShell several times slower), with a plain scriptblock probe, hashtable drive
# and variable tables, and plain stub functions in module scope for the live reads (no Pester mocks).
# The child only reads: the synthetic candidates live in Pester's TestRegistry, which the child maps
# as its own TestRegistry: drive, and the module runs in TestMode, so any registry path outside it
# throws. Set IGWT_PERF_REPORT to a .json path to keep the measured values.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Sid = 'S-1-5-21-1-2-3-1001'
    $regRoot = (Get-PSDrive -Name TestRegistry).Root
    if ($regRoot -notmatch '^(?i)HKEY_CURRENT_USER\\(Software\\Pester\\.+)$') { throw "Unexpected TestRegistry root '$regRoot'." }
    $rootSub = $Matches[1].TrimEnd('\')
    $script:Existing = New-Object System.Collections.Generic.List[string]
    $hkcu = [Microsoft.Win32.Registry]::CurrentUser
    $add = {
        param([string]$Path, [hashtable]$Values, [hashtable]$Kinds)
        $k = $hkcu.CreateSubKey($rootSub + '\' + $Path)
        try {
            foreach ($n in @($Values.Keys)) {
                $kind = $(if ($Kinds -and $Kinds.ContainsKey($n)) { $Kinds[$n] } elseif ($Values[$n] -is [int]) { [Microsoft.Win32.RegistryValueKind]::DWord } else { [Microsoft.Win32.RegistryValueKind]::String })
                $k.SetValue($n, $Values[$n], $kind)
            }
        } finally { $k.Dispose() }
    }
    $un64 = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $un32 = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    # 5,000 synthetic candidates: 2,000 Uninstall entries (both views), 1,000 App Paths, 1,000 Run values
    # (HKLM and the scanned user's HKCU) and 1,000 Software keys (500 vendors with one product each).
    # Every third program is installed (its folder exists); the others are gone.
    for ($i = 0; $i -lt 2000; $i++) {
        $pf = $(if ($i -lt 1500) { 'C:\Program Files' } else { 'C:\Program Files (x86)' })
        $state = $(if ($i % 3 -eq 0) { 'Installed' } else { 'Gone' })
        $dir = '{0}\PerfContoso{1}{2:D4}' -f $pf, $state, $i
        if ($state -eq 'Installed') { $script:Existing.Add($dir); $script:Existing.Add("$dir\unins000.exe") }
        $key = $(if ($i -lt 1500) { $un64 } else { $un32 }) + ('\PerfContoso{0:D4}' -f $i)
        & $add $key @{ DisplayName = "Perf Contoso $i"; Publisher = 'Perf Contoso Ltd'; InstallLocation = $dir; UninstallString = "`"$dir\unins000.exe`""; EstimatedSize = 1024 } $null
    }
    for ($i = 0; $i -lt 1000; $i++) {
        $dir = 'C:\Program Files\PerfFabrikam{0:D4}' -f $i
        if ($i % 3 -eq 0) { $script:Existing.Add("$dir\perftool$i.exe") }
        & $add ('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\perftool{0}.exe' -f $i) @{ '' = "$dir\perftool$i.exe"; Path = $dir } $null
    }
    $runM = @{}; $runU = @{}; $runUKinds = @{}
    for ($i = 0; $i -lt 500; $i++) {
        $dir = 'C:\Program Files\PerfRun{0:D4}' -f $i
        if ($i % 3 -eq 0) { $script:Existing.Add("$dir\tray.exe") }
        $runM["PerfRun$i"] = "`"$dir\tray.exe`" /min"
        $udir = 'C:\Users\contoso\AppData\Local\PerfRunUser{0:D4}' -f $i
        if ($i % 3 -eq 0) { $script:Existing.Add("$udir\tray.exe") }
        $runU["PerfRunUser$i"] = ('%LOCALAPPDATA%\PerfRunUser{0:D4}\tray.exe --background' -f $i)
        $runUKinds["PerfRunUser$i"] = [Microsoft.Win32.RegistryValueKind]::ExpandString
    }
    & $add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' $runM $null
    & $add "HKU\$($script:Sid)\Software\Microsoft\Windows\CurrentVersion\Run" $runU $runUKinds
    for ($i = 0; $i -lt 500; $i++) {
        $dir = 'C:\Program Files\PerfVendor{0:D4}\Product' -f $i
        if ($i % 3 -eq 0) { $script:Existing.Add($dir) }
        & $add ('HKLM\SOFTWARE\PerfVendor{0:D4}\Product' -f $i) @{ InstallPath = $dir; Version = '1.0' } $null
    }
    # The 2,000-value tree for the snapshot and .reg text (20 keys of 100 values, every kind the .reg
    # writer handles), outside every category root so the scan does not read it.
    $kinds = @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString, [Microsoft.Win32.RegistryValueKind]::MultiString, [Microsoft.Win32.RegistryValueKind]::DWord, [Microsoft.Win32.RegistryValueKind]::QWord, [Microsoft.Win32.RegistryValueKind]::Binary, [Microsoft.Win32.RegistryValueKind]::None)
    for ($k = 0; $k -lt 20; $k++) {
        $vals = @{}; $vk = @{}
        for ($v = 0; $v -lt 100; $v++) {
            $kind = $kinds[($k * 100 + $v) % $kinds.Count]
            $name = 'Value{0:D3}' -f $v
            # Assigned per kind, not through switch output, which would unroll the arrays.
            if ($kind -eq 'String') { $vals[$name] = "Perf text $k-$v with ""quotes"" and \backslash" }
            elseif ($kind -eq 'ExpandString') { $vals[$name] = "%ProgramFiles%\PerfSnapshot\$k\$v" }
            elseif ($kind -eq 'MultiString') { $vals[$name] = [string[]]@("first $v", '', "third $k") }
            elseif ($kind -eq 'DWord') { $vals[$name] = [int]($k * 1000 + $v) }
            elseif ($kind -eq 'QWord') { $vals[$name] = [long](4294967296 + $v) }
            else {
                $bytes = New-Object byte[] (($v % 40) + 2)
                for ($b = 0; $b -lt $bytes.Length; $b++) { $bytes[$b] = [byte](($b * 7 + $v) % 256) }
                $vals[$name] = $bytes
            }
            $vk[$name] = $kind
        }
        & $add ('HKLM\SYSTEM\PerfSnapshot\Tree\Part{0:D2}' -f $k) $vals $vk
    }

    # The child: one clean powershell.exe that measures all four budgets and writes them as JSON.
    $child = {
        param([string]$ProjectRoot, [string]$RegRoot, [string]$DataRoot, [string]$OutFile, [string]$ExistingFile, [string]$Sid)
        $ErrorActionPreference = 'Stop'
        Import-Module (Join-Path $ProjectRoot 'src\iGWindowsTuner.psd1') -Force
        $null = New-PSDrive -Name TestRegistry -PSProvider Registry -Root $RegRoot -Scope Global
        Set-IgwtEnvironment -TestMode -DataRoot $DataRoot -RegistryRedirect ([ordered]@{ 'HKLM:\' = 'TestRegistry:\HKLM\'; 'HKCU:\' = 'TestRegistry:\HKCU\'; 'HKU:\' = 'TestRegistry:\HKU\' })
        $existing = @(Get-Content -LiteralPath $ExistingFile)
        $out = & (Get-Module iGWindowsTuner) {
            param($Existing, $Sid)
            $m64 = @{
                SystemRoot = 'C:\Windows'; windir = 'C:\Windows'; SystemDrive = 'C:'; ProgramData = 'C:\ProgramData'; ALLUSERSPROFILE = 'C:\ProgramData'
                ProgramFiles = 'C:\Program Files'; ProgramW6432 = 'C:\Program Files'; 'ProgramFiles(x86)' = 'C:\Program Files (x86)'
                CommonProgramFiles = 'C:\Program Files\Common Files'; CommonProgramW6432 = 'C:\Program Files\Common Files'; 'CommonProgramFiles(x86)' = 'C:\Program Files (x86)\Common Files'
            }
            $m32 = @{}; foreach ($k in $m64.Keys) { $m32[$k] = $m64[$k] }
            $m32['ProgramFiles'] = 'C:\Program Files (x86)'; $m32['CommonProgramFiles'] = 'C:\Program Files (x86)\Common Files'
            $user = @{}; foreach ($k in $m64.Keys) { $user[$k] = $m64[$k] }
            $user['USERPROFILE'] = 'C:\Users\contoso'; $user['APPDATA'] = 'C:\Users\contoso\AppData\Roaming'; $user['LOCALAPPDATA'] = 'C:\Users\contoso\AppData\Local'
            $script:PerfVars = @{ '64' = $m64; '32' = $m32; 'user' = $user }
            $script:PerfDrives = @{ SystemDrive = 'C'; Online = @('C', 'D'); Skipped = @{}; Notes = @() }
            $script:PerfExisting = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($p in $Existing) { $null = $script:PerfExisting.Add([string]$p) }
            $script:PerfSid = $Sid
            # Plain stubs for the live reads (the same set the scan tests mock): no disk, WMI, Appx or
            # service access, and the scanned user is the synthetic SID.
            function script:Test-IgwtRegCleanPathProbe { param([string]$Path, [string]$Mode) if ($Mode -eq 'List') { return 'Exists' }; if ($script:PerfExisting.Contains($Path)) { return 'Exists' }; return 'Missing' }
            function script:Get-IgwtRegCleanVariableSet { $script:PerfVars }
            function script:Get-IgwtRegCleanDriveTable { $script:PerfDrives }
            function script:Get-IgwtInteractiveUserSid { $script:PerfSid }
            function script:Test-IgwtIsAdmin { $true }
            function script:Test-IgwtNetworkPath { param([string]$Path) ([string]$Path).StartsWith('\\') }
            function script:Get-IgwtRegCleanAppxPackages { }
            function script:Get-IgwtRegCleanServiceList { }
            function script:Get-IgwtInstalledGames { }
            function script:Get-IgwtSteamLibraryPaths { }
            function script:Get-IgwtMsiProductState { -1 }
            function script:Get-IgwtRegCleanTrustedInstallerSid { 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
            function script:Get-IgwtRegCleanSecurityProducts { }
            function script:Get-IgwtRegCleanPnpProviders { }
            function script:Get-IgwtRegCleanKeySecurity { [pscustomobject]@{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-32-544', 'S-1-5-18'); AclProtected = $false; HasExplicitAce = $false; ExplicitAceCount = 0; Sddl = '' } }
            function script:Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }

            # (1) Resolver: 2,000 command lines of ten forms, two passes (the second pass is the slower one).
            $probe = { param($p, $m) if ($m -eq 'List') { return 'Exists' }; if ($script:PerfExisting.Contains($p)) { return 'Exists' }; return 'Missing' }
            $templates = @(
                @{ V = '"C:\Program Files\Contoso{0}\app.exe" --minimized "%1"'; K = 'Command'; W = '64' }
                @{ V = 'C:\Program Files\Fabrikam{0}\tool.exe -tray -x'; K = 'Command'; W = '64' }
                @{ V = '"%ProgramFiles%\Fabrikam{0}\svc.exe"'; K = 'Command'; W = '32' }
                @{ V = 'rundll32.exe "C:\Program Files\Fabrikam{0}\helper.dll",Run'; K = 'Command'; W = '64' }
                @{ V = 'MsiExec.exe /X{{0F1E2D3C-4B5A-6978-8796-A5B4C3D2{0:D4}}}'; K = 'Command'; W = '32' }
                @{ V = '%LOCALAPPDATA%\Fabrikam{0}\Update.exe --processStart app.exe'; K = 'Command'; W = '64' }
                @{ V = '"C:\Program Files (x86)\Contoso{0}\app.exe",0'; K = 'File'; W = '32' }
                @{ V = 'C:\Program Files\Contoso{0}\'; K = 'Folder'; W = '' }
                @{ V = 'notepad.exe %1'; K = 'Command'; W = '64' }
                @{ V = '\SystemRoot\System32\drivers\fabrikam{0}.sys'; K = 'Command'; W = '64' }
            )
            $lines = New-Object System.Collections.Generic.List[object]
            for ($i = 0; $i -lt 2000; $i++) { $t = $templates[$i % $templates.Count]; $lines.Add(@{ V = ($t.V -f $i); K = $t.K; W = $t.W }) }
            $rv = @{}; foreach ($k in $user.Keys) { $rv[$k] = $user[$k] }
            $ps = { param($code) -1 }
            $resolver = @()
            $statuses = @{}
            foreach ($pass in 1..2) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                foreach ($l in $lines) {
                    $r = Resolve-IgwtRegCleanPath -Value $l.V -Kind $l.K -View $l.W -DriveTable $script:PerfDrives -Probe $probe -Variables $rv -ProductState $ps
                    if ($pass -eq 1) { $statuses[[string]$r.Status] = 1 + [int]$statuses[[string]$r.Status] }
                }
                $resolver += [Math]::Round($sw.Elapsed.TotalSeconds, 2)
            }

            # (2) Scan of the 5,000 synthetic candidates: context (owners index, protection), rule
            # evaluation, owner matching and the key tree of every finding.
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $scan = Get-IgwtRegistryLeftovers -Category uninstall, appPath, run, softwareKey
            $scanSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
            $evaluated = @($scan.Findings).Count
            foreach ($k in @($scan.Skipped.Keys)) { $evaluated += [int]$scan.Skipped[$k] }
            $conf = @{}; foreach ($f in @($scan.Findings)) { $conf[[string]$f.Confidence] = 1 + [int]$conf[[string]$f.Confidence] }

            # (3) Plan for 200 findings (a new context, as the GUI and the CLI build it).
            $sel = @($scan.Findings | Where-Object { $_.Selectable -and [string]$_.Confidence -in 'Safe', 'Review' -and [string]$_.Kind -in 'regKeyTree', 'regValue' } | Select-Object -First 200)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $plan = Get-IgwtRegCleanPlan -Findings $sel
            $planSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)

            # (4) Snapshot plus .reg text of the 2,000-value tree.
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $snap = Get-IgwtRegCleanKeySnapshot -Hive HKLM -View 64 -Path 'SYSTEM\PerfSnapshot\Tree'
            $text = ConvertTo-IgwtRegFileText -Snapshots @($snap)
            $snapSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)

            [pscustomobject]@{
                ResolverSeconds = $resolver; ResolverLines = $lines.Count; ResolverStatuses = $statuses
                ScanSeconds = $scanSeconds; Evaluated = $evaluated; Findings = @($scan.Findings).Count; Confidence = $conf; Skipped = $scan.Skipped; Notes = @($scan.Notes)
                PlanSeconds = $planSeconds; PlanSelected = $sel.Count; PlanTargets = @($plan.Targets).Count; PlanRefused = @($plan.Refused).Count
                SnapshotSeconds = $snapSeconds; SnapshotValues = [int]$snap.valueCount; SnapshotKeys = @($snap.keyList).Count; RegTextLength = $text.Length
            }
        } $existing $Sid
        $out | Add-Member -NotePropertyName PowerShell -NotePropertyValue ([string]$PSVersionTable.PSVersion)
        $out | Add-Member -NotePropertyName Is64Bit -NotePropertyValue ([Environment]::Is64BitProcess)
        [IO.File]::WriteAllText($OutFile, ($out | ConvertTo-Json -Depth 5))
    }
    $childFile = Join-Path $TestDrive 'perf-child.ps1'
    [IO.File]::WriteAllText($childFile, $child.ToString())
    $existingFile = Join-Path $TestDrive 'perf-existing.txt'
    [IO.File]::WriteAllLines($existingFile, [string[]]$script:Existing.ToArray())
    $outFile = Join-Path $TestDrive 'perf.json'
    $childData = Join-Path $TestDrive 'childdata'
    $script:ChildOutput = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $childFile -ProjectRoot $script:IgwtProjectRoot -RegRoot $regRoot -DataRoot $childData -OutFile $outFile -ExistingFile $existingFile -Sid $script:Sid 2>&1 | Out-String
    $script:Perf = $null
    if (Test-Path -LiteralPath $outFile) {
        $script:Perf = Get-Content -Raw -LiteralPath $outFile | ConvertFrom-Json
        if ($env:IGWT_PERF_REPORT) { Copy-Item -LiteralPath $outFile -Destination $env:IGWT_PERF_REPORT -Force }
    }
}

Describe 'Entry points below the vendor folders (RG10 index, RG25)' {
    It 'returns the same entry points, in list order, as Test-IgwtPathUnder for every pair' {
        InModuleScope iGWindowsTuner {
            $paths = @('C:\Program Files\Contoso\App\app.exe', 'C:\Program Files\Contoso', 'C:\Program Files\ContosoX\b.exe', 'c:\program files\contoso\APP\sub\c.dll', 'C:\Program Files\Fabrikam\..\Contoso\d.exe', 'D:\Tools\e.exe', '\\server\share\Contoso\f.exe', 'relative\Contoso\g.exe', 'C:\Program Files\Contoso\App\')
            $eps = @(for ($i = 0; $i -lt $paths.Count; $i++) { [pscustomobject]@{ Path = $paths[$i]; Hive = 'HKLM'; View = '64'; Source = "ep$i" } })
            $ctx = [pscustomobject]@{ EntryPoints = $eps; EntryPointIndex = $null }
            $folderSets = @(@('C:\Program Files\Contoso'), @('C:\Program Files\Contoso\App\'), @('C:\PROGRAM FILES\CONTOSO\App', 'D:\Tools'), @('\\server\share\Contoso'), @('relative\Contoso'), @('C:\Program Files\Fabrikam'), @('C:\Program Files\Cont'), @())
            foreach ($set in $folderSets) {
                $expected = @($eps | Where-Object { $p = [string]$_.Path; @($set | Where-Object { Test-IgwtPathUnder -Path $p -Parent $_ }).Count -gt 0 } | ForEach-Object { $_.Source })
                $actual = @(Get-IgwtRegCleanEntryPointsUnder -Context $ctx -Folder $set | ForEach-Object { $_.Source })
                ($actual -join ',') | Should -Be ($expected -join ',') -Because ($set -join ';')
            }
            $ctx.EntryPointIndex | Should -Not -BeNullOrEmpty
            # A context without the cache property still works (built on every call).
            @(Get-IgwtRegCleanEntryPointsUnder -Context ([pscustomobject]@{ EntryPoints = $eps }) -Folder @('D:\Tools')).Count | Should -Be 1
        }
    }
}

# Budgets: the measured values in DECISIONS RG25 with about 2x headroom.
Describe 'Registry cleaner performance (RG25)' {
    It 'runs the measurements in a clean 64-bit child powershell.exe 5.1' {
        $script:Perf | Should -Not -BeNullOrEmpty -Because $script:ChildOutput
        $script:Perf.Is64Bit | Should -BeTrue
        $script:Perf.PowerShell | Should -BeLike '5.1*'
    }

    It 'resolves 2,000 command lines in under 14 s (slower of two passes)' {
        $script:Perf.ResolverLines | Should -Be 2000
        ($script:Perf.ResolverSeconds | Measure-Object -Maximum).Maximum | Should -BeLessThan 14 -Because "passes took $($script:Perf.ResolverSeconds -join ', ') s"
    }

    It 'evaluates 5,000 synthetic candidates (rules, owners, protection, key trees) in under 1,050 s' {
        $script:Perf.Evaluated | Should -BeGreaterOrEqual 5000
        $script:Perf.Findings | Should -BeGreaterOrEqual 200
        $script:Perf.ScanSeconds | Should -BeLessThan 1050 -Because "the scan took $($script:Perf.ScanSeconds) s"
    }

    It 'builds the plan for 200 findings in under 125 s' {
        $script:Perf.PlanSelected | Should -Be 200
        ($script:Perf.PlanTargets + $script:Perf.PlanRefused) | Should -Be 200
        $script:Perf.PlanSeconds | Should -BeLessThan 125 -Because "the plan took $($script:Perf.PlanSeconds) s"
    }

    It 'reads the snapshot of a 2,000-value tree and writes its .reg text in under 5 s' {
        $script:Perf.SnapshotValues | Should -Be 2000
        $script:Perf.SnapshotKeys | Should -Be 21
        $script:Perf.RegTextLength | Should -BeGreaterThan 0
        $script:Perf.SnapshotSeconds | Should -BeLessThan 5 -Because "snapshot and .reg text took $($script:Perf.SnapshotSeconds) s"
    }
}
