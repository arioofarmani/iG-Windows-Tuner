# Registry Analyzer & Cleaner (3.8): the single path resolver, the drive table, the variable table
# and the probe (DECISIONS RG6-RG9, RG26). Headless and read-only: synthetic command lines from
# tests\fixtures\registry\commandlines.json, a stubbed probe and drive table, mocked Get-CimInstance
# and volume list, TestRegistry for the variable table and TestDrive for the probe itself.

BeforeDiscovery {
    $fixturePath = Join-Path $PSScriptRoot 'fixtures\registry\commandlines.json'
    $script:ResolverCases = @((Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json).cases | ForEach-Object {
            @{ Name = $_.name; Value = $_.value; Kind = $_.kind; View = $_.view; User = $_.user; Status = $_.status; Candidates = $_.candidates; ProductState = $_.productState }
        })
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Fixture = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\registry\commandlines.json') -Raw | ConvertFrom-Json
    $script:Sid = [string]$script:Fixture.sid
    function ConvertTo-TestTable($Object) {
        $h = @{}
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = [string]$p.Value }
        return $h
    }
    function Get-TestProbe([string[]]$Existing, [string[]]$Unknown, $Log) {
        # A plain scriptblock probe (no disk): Exists, Unknown or Missing by list; folders are listable.
        return {
            param($p, $m)
            if ($null -ne $Log) { $Log.Add([string]$p) }
            if ($m -eq 'List') { return 'Exists' }
            if ($Unknown -contains $p) { return 'Unknown' }
            if ($Existing -contains $p) { return [pscustomobject]@{ State = 'Exists'; Reason = 'stub' } }
            return 'Missing'
        }.GetNewClosure()
    }
    function Invoke-TestResolve([hashtable]$Arguments) {
        return (& (Get-Module iGWindowsTuner) { param($a) Resolve-IgwtRegCleanPath @a } $Arguments)
    }
    function Get-TestVariables([string]$View, [string]$User) {
        $t = ConvertTo-TestTable $(if ($View -eq '32') { $script:Fixture.variables.machine32 } else { $script:Fixture.variables.machine64 })
        if ($User) { foreach ($kv in (ConvertTo-TestTable $script:Fixture.variables.user).GetEnumerator()) { $t[$kv.Key] = $kv.Value } }
        return $t
    }
    $script:DriveTable = @{ SystemDrive = 'C'; Online = @('C', 'D'); Skipped = @{ 'E' = 'bus type USB' }; Notes = @('Other drives were not checked') }
    $script:Probe = Get-TestProbe -Existing @($script:Fixture.existing) -Unknown @($script:Fixture.unknown) -Log $null
}

Describe 'Resolve-IgwtRegCleanPath (RG6-RG9)' {
    BeforeAll {
        # Only a \\ path counts as network here, so the result never depends on this PC's mapped drives.
        Mock Test-IgwtNetworkPath -ModuleName iGWindowsTuner { ([string]$Path).StartsWith('\\') }
        Mock Test-IgwtRegCleanProcess64 -ModuleName iGWindowsTuner { $true }
    }

    It '<Name>' -TestCases $script:ResolverCases {
        $a = @{ Value = $Value; Kind = $Kind; View = $View; User = $User; DriveTable = $script:DriveTable; Probe = $script:Probe; Variables = (Get-TestVariables $View $User) }
        if ($null -ne $ProductState) { $state = [int]$ProductState; $a.ProductState = { param($code) $state }.GetNewClosure() }
        $r = Invoke-TestResolve $a
        $r.Status | Should -Be $Status -Because $r.Reason
        $r.Reason | Should -Not -BeNullOrEmpty
        if ($null -ne $Candidates) { @($r.Candidates) | Should -Be @($Candidates) }
        foreach ($c in @($r.Candidates)) { $c | Should -Not -Match '%' }
    }

    It 'never probes a UNC or network-mapped path' {
        Mock Test-IgwtNetworkPath -ModuleName iGWindowsTuner { ([string]$Path).StartsWith('\\') -or ([string]$Path).StartsWith('N:') }
        $log = New-Object System.Collections.Generic.List[string]
        $probe = Get-TestProbe -Existing @() -Unknown @() -Log $log
        $table = @{ SystemDrive = 'C'; Online = @('C', 'N'); Skipped = @{}; Notes = @() }
        foreach ($v in '\\fileserver\share\Fabrikam\app.exe', '"\\fileserver\share\Fabrikam\app.exe" /x', 'N:\Fabrikam\app.exe', 'rundll32.exe \\fileserver\share\f.dll,Run') {
            $r = Invoke-TestResolve @{ Value = $v; DriveTable = $table; Probe = $probe; Variables = (Get-TestVariables '64' '') }
            $r.Status | Should -Be 'Unprovable' -Because $v
        }
        $log.Count | Should -Be 0
    }

    It 'refuses in a 32-bit process' {
        Mock Test-IgwtRegCleanProcess64 -ModuleName iGWindowsTuner { $false }
        { Invoke-TestResolve @{ Value = 'C:\Fabrikam\app.exe'; DriveTable = $script:DriveTable; Probe = $script:Probe; Variables = @{} } } | Should -Throw '*64-bit*'
    }

    It 'leaves an msiexec product code Unknown without a ProductState lookup or when it fails' {
        $v = 'MsiExec.exe /X{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}'
        (Invoke-TestResolve @{ Value = $v; DriveTable = $script:DriveTable; Probe = $script:Probe; Variables = @{} }).Status | Should -Be 'Unknown'
        (Invoke-TestResolve @{ Value = $v; DriveTable = $script:DriveTable; Probe = $script:Probe; Variables = @{}; ProductState = { throw 'COM failure' } }).Status | Should -Be 'Unknown'
    }

    It 'is Unknown when the probe returns nothing or an unexpected state' {
        foreach ($p in @({ param($a, $b) }, { param($a, $b) 'Weird' }, { param($a, $b) throw 'probe failure' })) {
            $r = $null
            try { $r = Invoke-TestResolve @{ Value = 'C:\Fabrikam\app.exe'; Kind = 'File'; DriveTable = $script:DriveTable; Probe = $p; Variables = @{} } } catch { $r = [pscustomobject]@{ Status = 'Threw' } }
            $r.Status | Should -BeIn @('Unknown', 'Threw')
            $r.Status | Should -Not -Be 'Missing'
        }
    }

    It 'builds the owner''s variable table when none is passed' {
        Mock Get-IgwtRegCleanVariableTable -ModuleName iGWindowsTuner { @{ LOCALAPPDATA = 'C:\Users\contoso\AppData\Local' } }
        $r = Invoke-TestResolve @{ Value = '%LOCALAPPDATA%\Fabrikam\gone.exe'; User = $script:Sid; DriveTable = $script:DriveTable; Probe = $script:Probe }
        $r.Status | Should -Be 'Missing'
        Should -Invoke Get-IgwtRegCleanVariableTable -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $User -eq $script:Sid -and $View -eq '64' }
    }

    It 'leaves Resolve-IgwtCommandPath to the Manage pages (separate function, not used by the resolver)' {
        $src = Get-Content -LiteralPath (Join-Path $script:IgwtProjectRoot 'src\Cleaner\RegistryCleanerPath.ps1') -Raw
        $src | Should -Not -Match '(?m)^[^#\r\n]*Resolve-IgwtCommandPath\s+-'
        @(& (Get-Module iGWindowsTuner) { Resolve-IgwtCommandPath -Command 'rundll32.exe C:\Fabrikam\helper.dll,Run' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Command-line parsing helpers' {
    It 'splits by the CommandLineToArgvW rules' {
        $s = & (Get-Module iGWindowsTuner) { Split-IgwtRegCleanCommandLine -Text '"C:\Program Files\Contoso\app.exe" -a "b c" d\"e "f\\" g' }
        $s.Program | Should -Be 'C:\Program Files\Contoso\app.exe'
        $s.Quoted | Should -BeTrue
        @($s.Arguments) | Should -Be @('-a', 'b c', 'd"e', 'f\', 'g')
        $u = & (Get-Module iGWindowsTuner) { Split-IgwtRegCleanCommandLine -Text 'C:\Contoso\app.exe /x' }
        $u.Program | Should -Be 'C:\Contoso\app.exe'
        $u.Quoted | Should -BeFalse
    }

    It 'lists the CreateProcess try-in-order candidates' {
        $t = & (Get-Module iGWindowsTuner) { Get-IgwtRegCleanTryOrder -Text 'C:\Program Files\Contoso App\app.exe -x' }
        # 'app.exe -x' already has an extension ('.exe -x'), so nothing is appended to the last candidate.
        @($t) | Should -Be @('C:\Program.exe', 'C:\Program Files\Contoso.exe', 'C:\Program Files\Contoso App\app.exe', 'C:\Program Files\Contoso App\app.exe -x')
    }

    It 'keeps %LOCALAPPDATA% while removing the %L placeholder' {
        $r = & (Get-Module iGWindowsTuner) { [regex]::Replace('"%LOCALAPPDATA%\Fabrikam\v.exe" "%L" %L', $script:IgwtRegCleanPlaceholderPattern, '').Trim() }
        $r | Should -Be '"%LOCALAPPDATA%\Fabrikam\v.exe"'
    }
}

Describe 'Get-IgwtRegCleanVariableTable (RG7)' {
    BeforeAll {
        $env1 = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        $null = New-Item -Path $env1 -Force
        $null = New-ItemProperty -Path $env1 -Name 'FABRIKAM_HOME' -Value '%SystemRoot%\Fabrikam' -PropertyType ExpandString -Force
        $null = New-ItemProperty -Path $env1 -Name 'NUMBER_OF_THINGS' -Value 4 -PropertyType DWord -Force
        $shell = "TestRegistry:\HKU\$($script:Sid)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $null = New-Item -Path $shell -Force
        $null = New-ItemProperty -Path $shell -Name 'AppData' -Value '%USERPROFILE%\AppData\Roaming' -PropertyType ExpandString -Force
        $null = New-ItemProperty -Path $shell -Name 'Local AppData' -Value '%USERPROFILE%\AppData\Local' -PropertyType ExpandString -Force
        $uenv = "TestRegistry:\HKU\$($script:Sid)\Environment"
        $null = New-Item -Path $uenv -Force
        $null = New-ItemProperty -Path $uenv -Name 'TEMP' -Value '%USERPROFILE%\AppData\Local\Temp' -PropertyType ExpandString -Force
        $null = New-ItemProperty -Path $uenv -Name 'CONTOSO_DATA' -Value '%LOCALAPPDATA%\Contoso' -PropertyType ExpandString -Force
        Mock Get-IgwtUserProfileFolders -ModuleName iGWindowsTuner { [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001'; Path = 'C:\Users\contoso' } }
    }

    It 'reads the system table from Session Manager\Environment and the machine folders' {
        $t = & (Get-Module iGWindowsTuner) { Get-IgwtRegCleanVariableTable -View '64' }
        $win = [Environment]::GetFolderPath('Windows')
        $t['FABRIKAM_HOME'] | Should -Be ($win + '\Fabrikam')
        $t.ContainsKey('NUMBER_OF_THINGS') | Should -BeFalse
        $t['ProgramFiles'] | Should -Be ([Environment]::GetFolderPath('ProgramFiles'))
        $t['ProgramW6432'] | Should -Be ([Environment]::GetFolderPath('ProgramFiles'))
        $t['ProgramFiles(x86)'] | Should -Be ([Environment]::GetFolderPath('ProgramFilesX86'))
        foreach ($n in 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP') { $t.ContainsKey($n) | Should -BeFalse -Because "$n is per user, never the process's own" }
    }

    It 'uses the x86 Program Files for the 32-bit view' {
        $t = & (Get-Module iGWindowsTuner) { Get-IgwtRegCleanVariableTable -View '32' }
        $t['ProgramFiles'] | Should -Be ([Environment]::GetFolderPath('ProgramFilesX86'))
        $t['CommonProgramFiles'] | Should -Be ([Environment]::GetFolderPath('CommonProgramFilesX86'))
    }

    It 'adds the scanned user''s profile, shell folders and environment' {
        $t = & (Get-Module iGWindowsTuner) { param($s) Get-IgwtRegCleanVariableTable -View '64' -User $s } $script:Sid
        $t['USERPROFILE'] | Should -Be 'C:\Users\contoso'
        $t['APPDATA'] | Should -Be 'C:\Users\contoso\AppData\Roaming'
        $t['LOCALAPPDATA'] | Should -Be 'C:\Users\contoso\AppData\Local'
        $t['TEMP'] | Should -Be 'C:\Users\contoso\AppData\Local\Temp'
        $t['CONTOSO_DATA'] | Should -Be 'C:\Users\contoso\AppData\Local\Contoso'
    }

    It 'leaves user variables out when the user has no profile or loaded hive' {
        $t = & (Get-Module iGWindowsTuner) { Get-IgwtRegCleanVariableTable -View '64' -User 'S-1-5-21-1-2-3-1002' }
        foreach ($n in 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP') { $t.ContainsKey($n) | Should -BeFalse }
    }

    It 'rejects a user value that is not a SID' {
        { & (Get-Module iGWindowsTuner) { Get-IgwtRegCleanVariableTable -User '..\Contoso' } } | Should -Throw '*Invalid user SID*'
    }
}

Describe 'Get-IgwtRegCleanDriveTable (RG9)' {
    BeforeAll {
        Mock Get-IgwtRegCleanSystemDrive -ModuleName iGWindowsTuner { 'C' }
        $script:ListableProbe = { param($p, $m) 'Exists' }
        function Initialize-TestStorage([object[]]$Disks, [object[]]$Partitions) {
            $script:TestDisks = $Disks
            $script:TestPartitions = $Partitions
            Mock Get-CimInstance -ModuleName iGWindowsTuner -ParameterFilter { $ClassName -eq 'MSFT_Disk' } { $script:TestDisks }
            Mock Get-CimInstance -ModuleName iGWindowsTuner -ParameterFilter { $ClassName -eq 'MSFT_Partition' } { $script:TestPartitions }
        }
        function Get-TestDriveTable([scriptblock]$Probe = $script:ListableProbe) { return (& (Get-Module iGWindowsTuner) { param($p) Get-IgwtRegCleanDriveTable -Probe $p } $Probe) }
        $script:FourDrives = @(
            [pscustomobject]@{ Letter = 'C'; DriveType = 'Fixed'; IsReady = $true }
            [pscustomobject]@{ Letter = 'D'; DriveType = 'Fixed'; IsReady = $true }
            [pscustomobject]@{ Letter = 'F'; DriveType = 'Fixed'; IsReady = $true }
            [pscustomobject]@{ Letter = 'G'; DriveType = 'Fixed'; IsReady = $true }
        )
        $script:FourParts = @(
            [pscustomobject]@{ DriveLetter = [char]'C'; DiskNumber = 0 }
            [pscustomobject]@{ DriveLetter = [char]'D'; DiskNumber = 1 }
            [pscustomobject]@{ DriveLetter = [char]'F'; DiskNumber = 2 }
            [pscustomobject]@{ DriveLetter = [char]'G'; DiskNumber = 3 }
            [pscustomobject]@{ DriveLetter = [char]0; DiskNumber = 0 }
        )
    }

    It 'keeps NVMe, SATA, SAS, ATA, SCSI and RAID drives online' {
        $vols = @([pscustomobject]@{ Letter = 'C'; DriveType = 'Fixed'; IsReady = $true })
        $parts = @()
        $disks = @()
        $n = 0
        foreach ($bus in 17, 11, 10, 3, 1, 8) {
            $n++
            $l = [string][char](67 + $n)
            $vols += [pscustomobject]@{ Letter = $l; DriveType = 'Fixed'; IsReady = $true }
            $parts += [pscustomobject]@{ DriveLetter = [char]$l; DiskNumber = $n }
            $disks += [pscustomobject]@{ Number = $n; BusType = [uint16]$bus }
        }
        $script:Vols = $vols
        Mock Get-IgwtRegCleanVolumeList -ModuleName iGWindowsTuner { $script:Vols }
        Initialize-TestStorage -Disks $disks -Partitions $parts
        $t = Get-TestDriveTable
        @($t.Online) | Should -Be @('C', 'D', 'E', 'F', 'G', 'H', 'I')
        $t.Skipped.Count | Should -Be 0
        @($t.Notes).Count | Should -Be 0
    }

    It 'skips USB, SD, File Backed Virtual and Unknown bus types with the note' {
        Mock Get-IgwtRegCleanVolumeList -ModuleName iGWindowsTuner { $script:FourDrives }
        Initialize-TestStorage -Disks @(
            [pscustomobject]@{ Number = 0; BusType = [uint16]17 }
            [pscustomobject]@{ Number = 1; BusType = [uint16]7 }
            [pscustomobject]@{ Number = 2; BusType = [uint16]12 }
            [pscustomobject]@{ Number = 3; BusType = [uint16]15 }
        ) -Partitions $script:FourParts
        $t = Get-TestDriveTable
        @($t.Online) | Should -Be @('C')
        $t.Skipped['D'] | Should -Be 'bus type USB'
        $t.Skipped['F'] | Should -Be 'bus type SD'
        $t.Skipped['G'] | Should -Be 'bus type File Backed Virtual'
        @($t.Notes) | Should -Be @('Other drives were not checked')
        Initialize-TestStorage -Disks @([pscustomobject]@{ Number = 1; BusType = [uint16]0 }, [pscustomobject]@{ Number = 2; BusType = [uint16]99 }, [pscustomobject]@{ Number = 3; BusType = $null }) -Partitions $script:FourParts
        $t = Get-TestDriveTable
        @($t.Online) | Should -Be @('C')
        foreach ($l in 'D', 'F', 'G') { $t.Skipped[$l] | Should -Be 'bus type Unknown' }
    }

    It 'keeps only the system drive online with a note when the CIM lookup fails' {
        Mock Get-IgwtRegCleanVolumeList -ModuleName iGWindowsTuner { $script:FourDrives }
        Mock Get-CimInstance -ModuleName iGWindowsTuner { throw 'Invalid namespace' }
        $t = Get-TestDriveTable
        @($t.Online) | Should -Be @('C')
        foreach ($l in 'D', 'F', 'G') { $t.Skipped[$l] | Should -Be 'bus type lookup failed' }
        @($t.Notes) | Should -Be @('Other drives were not checked')
    }

    It 'skips a locked or offline volume (IsReady false), removable, network and CD drives without asking CIM' {
        Mock Get-IgwtRegCleanVolumeList -ModuleName iGWindowsTuner {
            [pscustomobject]@{ Letter = 'C'; DriveType = 'Fixed'; IsReady = $true }
            [pscustomobject]@{ Letter = 'D'; DriveType = 'Fixed'; IsReady = $false }
            [pscustomobject]@{ Letter = 'E'; DriveType = 'Removable'; IsReady = $true }
            [pscustomobject]@{ Letter = 'N'; DriveType = 'Network'; IsReady = $true }
            [pscustomobject]@{ Letter = 'R'; DriveType = 'CDRom'; IsReady = $false }
        }
        Mock Get-CimInstance -ModuleName iGWindowsTuner { throw 'must not be called' }
        $t = Get-TestDriveTable
        @($t.Online) | Should -Be @('C')
        $t.Skipped['D'] | Should -Match 'not ready'
        $t.Skipped['E'] | Should -Be 'drive type Removable'
        $t.Skipped['N'] | Should -Be 'drive type Network'
        $t.Skipped['R'] | Should -Be 'drive type CDRom'
        Should -Invoke Get-CimInstance -ModuleName iGWindowsTuner -Times 0 -Exactly
    }

    It 'skips a subst drive (no partition) and a drive whose root cannot be listed' {
        Mock Get-IgwtRegCleanVolumeList -ModuleName iGWindowsTuner { $script:FourDrives }
        Initialize-TestStorage -Disks @([pscustomobject]@{ Number = 0; BusType = [uint16]17 }, [pscustomobject]@{ Number = 1; BusType = [uint16]11 }) -Partitions @(
            [pscustomobject]@{ DriveLetter = [char]'C'; DiskNumber = 0 }
            [pscustomobject]@{ DriveLetter = [char]'D'; DiskNumber = 1 }
        )
        $t = Get-TestDriveTable -Probe { param($p, $m) if ($p -eq 'F:\') { 'Unknown' } else { 'Exists' } }
        @($t.Online) | Should -Be @('C', 'D')
        $t.Skipped['F'] | Should -Be 'root cannot be listed'
        $t.Skipped['G'] | Should -Match 'no partition'
    }

    It 'keeps the system drive online without any lookup and adds no note when there is no other drive' {
        Mock Get-IgwtRegCleanVolumeList -ModuleName iGWindowsTuner { [pscustomobject]@{ Letter = 'C'; DriveType = 'Fixed'; IsReady = $true } }
        Mock Get-CimInstance -ModuleName iGWindowsTuner { throw 'must not be called' }
        $t = Get-TestDriveTable -Probe { param($p, $m) 'Unknown' }
        @($t.Online) | Should -Be @('C')
        $t.SystemDrive | Should -Be 'C'
        @($t.Notes).Count | Should -Be 0
    }

    It 'throws in TestMode when the volume list is not mocked' {
        { & (Get-Module iGWindowsTuner) { Get-IgwtRegCleanVolumeList } } | Should -Throw '*must be mocked*'
    }
}

Describe 'Test-IgwtRegCleanPathProbe (the only disk-touching function)' {
    BeforeAll {
        $script:Root = Join-Path $TestDrive 'probe'
        $null = New-Item -ItemType Directory -Path (Join-Path $script:Root 'Contoso\bin') -Force
        [IO.File]::WriteAllText((Join-Path $script:Root 'Contoso\bin\app.exe'), 'x')
        function Invoke-TestProbe([string]$Path, [string]$Mode = 'Path') { return (& (Get-Module iGWindowsTuner) { param($p, $m) Test-IgwtRegCleanPathProbe -Path $p -Mode $m } $Path $Mode) }
    }

    It 'finds an existing file and folder' {
        (Invoke-TestProbe (Join-Path $script:Root 'Contoso\bin\app.exe')).State | Should -Be 'Exists'
        (Invoke-TestProbe (Join-Path $script:Root 'Contoso\bin')).State | Should -Be 'Exists'
        (Invoke-TestProbe (Join-Path $script:Root 'Contoso') 'List').State | Should -Be 'Exists'
    }

    It 'reports Missing when the nearest existing parent can be listed' {
        (Invoke-TestProbe (Join-Path $script:Root 'Contoso\bin\gone.exe')).State | Should -Be 'Missing'
        (Invoke-TestProbe (Join-Path $script:Root 'Fabrikam\deep\gone.exe')).State | Should -Be 'Missing'
    }

    It 'reports Unknown when the parent folder cannot be listed' {
        # The real probe runs for Mode Path; its own List call for the parent folder hits the mock.
        Mock Test-IgwtRegCleanPathProbe -ModuleName iGWindowsTuner {
            if ($Mode -eq 'List') { return [pscustomobject]@{ State = 'Unknown'; Reason = 'access denied (mock)' } }
            # The function itself (Pester's alias shadows its name), so only the List call is mocked.
            & (Get-Module iGWindowsTuner) { param($p, $m) & (Get-Command -Name Test-IgwtRegCleanPathProbe -CommandType Function) -Path $p -Mode $m } $Path $Mode
        }
        $r = Invoke-TestProbe (Join-Path $script:Root 'Contoso\bin\gone.exe')
        $r.State | Should -Be 'Unknown'
        $r.Reason | Should -Match 'cannot be listed'
        Should -Invoke Test-IgwtRegCleanPathProbe -ModuleName iGWindowsTuner -ParameterFilter { $Mode -eq 'List' } -Times 1
    }

    It 'reports Unknown for a reparse point below the root' {
        $target = Join-Path $script:Root 'Contoso'
        $link = Join-Path $script:Root 'Link'
        $null = New-Item -ItemType Junction -Path $link -Target $target
        try {
            $r = Invoke-TestProbe (Join-Path $link 'bin\app.exe')
            $r.State | Should -Be 'Unknown'
            $r.Reason | Should -Match 'reparse'
        } finally { [IO.Directory]::Delete($link) }
    }

    It 'reports Unknown for a file used as a folder, a relative path and an unlistable folder' {
        (Invoke-TestProbe (Join-Path $script:Root 'Contoso\bin\app.exe\more.exe')).State | Should -Be 'Unknown'
        (Invoke-TestProbe 'Contoso\app.exe').State | Should -Be 'Unknown'
        (Invoke-TestProbe (Join-Path $script:Root 'Fabrikam') 'List').State | Should -Be 'Unknown'
    }

    It 'maps not found to Missing and access denied or any IO error to Unknown' {
        $map = { param($e) & (Get-Module iGWindowsTuner) { param($x) Get-IgwtRegCleanProbeErrorState -Exception $x } $e }
        & $map (New-Object System.IO.FileNotFoundException 'x') | Should -Be 'Missing'
        & $map (New-Object System.IO.DirectoryNotFoundException 'x') | Should -Be 'Missing'
        & $map (New-Object System.UnauthorizedAccessException 'x') | Should -Be 'Unknown'
        & $map (New-Object System.IO.IOException 'x') | Should -Be 'Unknown'
        & $map (New-Object System.IO.PathTooLongException 'x') | Should -Be 'Unknown'
        & $map (New-Object System.Management.Automation.MethodInvocationException 'wrapped', (New-Object System.IO.FileNotFoundException 'x')) | Should -Be 'Missing'
        & $map (New-Object System.Management.Automation.MethodInvocationException 'wrapped', (New-Object System.UnauthorizedAccessException 'x')) | Should -Be 'Unknown'
        & $map $null | Should -Be 'Unknown'
    }

    It 'is the only registry cleaner function that reads the file system, and no BitLocker or Get-Disk call exists' {
        $file = Join-Path $script:IgwtProjectRoot 'src\Cleaner\RegistryCleanerPath.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
        $pattern = '(?i)(GetAttributes|EnumerateFileSystemEntries|Test-Path|Get-Item\b|Get-ChildItem|\[IO\.File\]::|\[IO\.Directory\]::)'
        foreach ($fd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            if ($fd.Name -eq 'Test-IgwtRegCleanPathProbe') { continue }
            $fd.Body.Extent.Text | Should -Not -Match $pattern -Because $fd.Name
        }
        $tokens = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$null)
        $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
        $code | Should -Not -Match '(?i)Get-BitLockerVolume|Get-Disk\b|Win32_Product'
    }
}
