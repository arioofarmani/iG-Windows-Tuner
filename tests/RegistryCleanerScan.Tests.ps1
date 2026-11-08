# Registry Analyzer & Cleaner (3.8): data, protected set, owners index, protection, exclusions and
# (later steps) scan rules. Headless and read-only: data\registry\*.json and synthetic copies,
# TestRegistry fixtures (Contoso, Fabrikam, fake SID), a stubbed probe and mocked system lists.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:RegDataDir = Join-Path $script:IgwtProjectRoot 'data\registry'
    function Get-RegCleanTestDoc([string]$Name) {
        # A fresh, independent copy of a shipped data file for each synthetic variant.
        return (Get-Content -LiteralPath (Join-Path $script:RegDataDir ($Name + '.json')) -Raw | ConvertFrom-Json)
    }
    function Get-RegCleanTestGroup($Doc, [string]$Id) { return @($Doc.groups | Where-Object { $_.id -eq $Id })[0] }
    function Get-RegCleanTestVendor($Doc, [string]$Type) { return @((Get-RegCleanTestGroup $Doc 'securityVendors').vendors | Where-Object { $_.type -eq $Type })[0] }
    function Test-RegCleanCatalog($Protected, $Categories) {
        if ($null -eq $Protected) { $Protected = Get-RegCleanTestDoc 'protected' }
        if ($null -eq $Categories) { $Categories = Get-RegCleanTestDoc 'categories' }
        return @(& (Get-Module iGWindowsTuner) { param($p, $c) Test-IgwtRegCleanProtectedCatalog -Protected $p -Categories $c } $Protected $Categories)
    }
}

Describe 'Registry cleaner catalog (RG11, RG32)' {
    Context 'shipped data' {
        It 'passes Test-IgwtRegCleanProtectedCatalog' {
            @(& (Get-Module iGWindowsTuner) { Test-IgwtRegCleanProtectedCatalog }) | Should -BeNullOrEmpty
        }

        It 'is part of Test-IgwtCatalog' {
            Mock Test-IgwtRegCleanProtectedCatalog -ModuleName iGWindowsTuner { 'synthetic regclean error' }
            @(Test-IgwtCatalog) | Should -Contain 'synthetic regclean error'
        }

        It 'is ASCII, CRLF and written in ConvertTo-IgwtJson style' {
            foreach ($n in 'categories', 'protected') {
                $path = Join-Path $script:RegDataDir ($n + '.json')
                $text = [IO.File]::ReadAllText($path)
                $text | Should -Not -Match '[^\x00-\x7F]' -Because $n
                $text | Should -Not -Match '(?<!\r)\n' -Because $n
                $doc = $text | ConvertFrom-Json
                (& (Get-Module iGWindowsTuner) { param($d) ConvertTo-IgwtJson -InputObject $d } $doc) | Should -BeExactly $text -Because $n
            }
        }

        It 'has every category with its kind, maximum confidence and roots' {
            $c = Get-RegCleanTestDoc 'categories'
            @($c.categories.id) | Should -Be @('uninstall', 'appPath', 'progId', 'application', 'openWith', 'run', 'softwareKey', 'firewallRule', 'service', 'task')
            @($c.categories | Where-Object { $_.kind -eq 'reportOnly' }).id | Should -Be @('service', 'task')
            @($c.categories | Where-Object { $_.maxConfidence -eq 'Safe' }).id | Should -Be @('uninstall', 'appPath', 'run', 'firewallRule')
            $un = @($c.categories | Where-Object { $_.id -eq 'uninstall' })[0]
            @($un.roots | ForEach-Object { "$($_.hive)|$($_.view)" }) | Should -Be @('HKLM|64', 'HKLM|32', 'HKCU|64')
        }

        It 'lists exactly the Uninstall, App Paths, Run and RunOnce roots as microsoft carve-outs' {
            $c = Get-RegCleanTestDoc 'categories'
            $expected = @($c.categories | Where-Object { $_.id -in 'uninstall', 'appPath', 'run' } | ForEach-Object { $_.roots } | ForEach-Object { "$($_.hive)\$($_.path)" } | Sort-Object -Unique)
            $ms = Get-RegCleanTestGroup (Get-RegCleanTestDoc 'protected') 'microsoft'
            @($ms.categoryRootsAllowed | Sort-Object) | Should -Be $expected
            @($ms.publisherPatterns) | Should -Contain 'Microsoft Corporation'
        }

        It 'gives every security vendor a removal tool, https url or the confirmed-no-tool text, and EDR the administrator text' {
            foreach ($v in @((Get-RegCleanTestGroup (Get-RegCleanTestDoc 'protected') 'securityVendors').vendors)) {
                $v.removalTool | Should -Not -BeNullOrEmpty -Because $v.id
                if ($v.removalTool.url) { $v.removalTool.url | Should -Match '^https://' -Because $v.id }
                if ($v.type -eq 'edr') { $v.removalTool.text | Should -Match '^Ask your administrator' -Because $v.id }
                if ($v.type -eq 'consumer' -and -not $v.removalTool.url) { $v.removalTool.text | Should -Match 'publishes no removal tool that iG could confirm; contact .+ support' -Because $v.id }
            }
        }

        It 'keeps vendor names out of the registry cleaner code (RG30)' {
            $code = (Get-ChildItem -Path (Join-Path $script:IgwtProjectRoot 'src\Cleaner') -Filter 'RegistryCleaner*.ps1' | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
            foreach ($v in @((Get-RegCleanTestGroup (Get-RegCleanTestDoc 'protected') 'securityVendors').vendors)) {
                foreach ($p in @($v.publisherPatterns)) {
                    $word = ([string]$p).TrimEnd('*')
                    $code | Should -Not -Match ('(?i)\b' + [regex]::Escape($word) + '\b') -Because "$($v.id) publisher '$p'"
                }
            }
        }

        It 'loads both files through cached loaders that Clear-IgwtCatalogCaches resets' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtRegCleanProtectedCatalog -Force
                $c = Get-IgwtRegCleanCategories -Force
                $p.schemaVersion | Should -Be 2
                [object]::ReferenceEquals($p, (Get-IgwtRegCleanProtectedCatalog)) | Should -BeTrue
                [object]::ReferenceEquals($c, (Get-IgwtRegCleanCategories)) | Should -BeTrue
                Clear-IgwtCatalogCaches -Confirm:$false
                $script:IgwtRegCleanProtectedCache | Should -BeNullOrEmpty
                $script:IgwtRegCleanCategoryCache | Should -BeNullOrEmpty
            }
        }
    }

    Context 'synthetic catalogs that must fail' {
        It 'rejects an unanchored name pattern' {
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestGroup $p 'hardware').publisherPatterns += '*Contoso*'
            (Test-RegCleanCatalog $p) -join "`n" | Should -Match "publisherPatterns '\*Contoso\*': unanchored pattern"
        }

        It 'rejects an unanchored key pattern and an unanchored path pattern' {
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestGroup $p 'launchers').keyPatterns += 'SOFTWARE\Contoso\*'
            (Get-RegCleanTestGroup $p 'launchers').pathPatterns += 'Program Files\Contoso\*'
            $e = (Test-RegCleanCatalog $p) -join "`n"
            $e | Should -Match "keyPatterns 'SOFTWARE\\Contoso\\\*': unanchored pattern"
            $e | Should -Match "pathPatterns 'Program Files\\Contoso\\\*': unanchored pattern"
        }

        It 'rejects a leading *\ that is not followed by a segment of 4 or more characters' {
            foreach ($bad in '*\Abc\*', '*\*\Contoso\*', '*\Co?t\*') {
                $p = Get-RegCleanTestDoc 'protected'
                (Get-RegCleanTestGroup $p 'antiCheat').pathPatterns += $bad
                (Test-RegCleanCatalog $p) -join "`n" | Should -Match "at least 4 characters" -Because $bad
            }
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestGroup $p 'antiCheat').pathPatterns += '*\Contoso\*'
            Test-RegCleanCatalog $p | Should -BeNullOrEmpty
        }

        It 'rejects non-https sources and removal tool urls' {
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestGroup $p 'microsoft').sources += 'http://learn.example.com/page'
            (Get-RegCleanTestVendor $p 'consumer').removalTool.url = 'http://support.example.com/tool'
            $c = Get-RegCleanTestDoc 'categories'
            $c.categories[0].sources += 'ftp://example.com/x'
            $e = (Test-RegCleanCatalog $p $c) -join "`n"
            $e | Should -Match "group 'microsoft': source 'http://learn.example.com/page' is not an https URL"
            $e | Should -Match "removalTool url 'http://support.example.com/tool' is not an https URL"
            $e | Should -Match "category 'uninstall': source 'ftp://example.com/x' is not an https URL"
        }

        It 'rejects a non-EDR vendor without a tool url or the confirmed-no-tool text' {
            $p = Get-RegCleanTestDoc 'protected'
            $v = Get-RegCleanTestVendor $p 'consumer'
            $v.removalTool.url = ''
            $v.removalTool.text = 'See the vendor home page.'
            (Test-RegCleanCatalog $p) -join "`n" | Should -Match 'publishes no removal tool that iG could confirm'
            $v.removalTool.text = 'Contoso publishes no removal tool that iG could confirm; contact Contoso support.'
            Test-RegCleanCatalog $p | Should -BeNullOrEmpty
            $v.removalTool.text = ''
            (Test-RegCleanCatalog $p) -join "`n" | Should -Match 'removalTool text is required'
            $v.PSObject.Properties.Remove('removalTool')
            (Test-RegCleanCatalog $p) -join "`n" | Should -Match 'removalTool \{name, url, text\} is required'
        }

        It 'rejects an EDR vendor whose text does not send the user to the administrator' {
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestVendor $p 'edr').removalTool.text = 'Run the cleanup tool.'
            (Test-RegCleanCatalog $p) -join "`n" | Should -Match "EDR vendor's removalTool text starts with 'Ask your administrator'"
        }

        It 'rejects a keyPattern that covers a category root without a carve-out' {
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestGroup $p 'hardware').keyPatterns += 'HK*\SOFTWARE\*'
            $e = (Test-RegCleanCatalog $p) -join "`n"
            $e | Should -Match "group 'hardware': keyPattern 'HK\*\\SOFTWARE\\\*' covers the softwareKey root 'HKLM\\SOFTWARE'"
            $e | Should -Match "covers the uninstall root"
        }

        It 'rejects the microsoft group keyPattern once its carve-out is removed' {
            $p = Get-RegCleanTestDoc 'protected'
            $ms = Get-RegCleanTestGroup $p 'microsoft'
            $ms.categoryRootsAllowed = @($ms.categoryRootsAllowed | Where-Object { $_ -notlike '*\Uninstall' })
            $e = @(Test-RegCleanCatalog $p)
            @($e | Where-Object { $_ -match "keyPattern 'HK\*\\SOFTWARE\\Microsoft\\\*' covers the uninstall root" }).Count | Should -Be 2
            @($e | Where-Object { $_ -match 'App Paths|\\Run' }) | Should -BeNullOrEmpty
        }

        It 'does not count a narrower pattern below a root, or an unrelated key, as covering it' {
            InModuleScope iGWindowsTuner {
                $root = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                Test-IgwtRegCleanKeyPatternCoversRoot -Pattern 'HK*\SOFTWARE\Microsoft\*' -Root $root | Should -BeTrue
                Test-IgwtRegCleanKeyPatternCoversRoot -Pattern 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*' -Root 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' | Should -BeTrue
                Test-IgwtRegCleanKeyPatternCoversRoot -Pattern 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\*' -Root $root | Should -BeFalse
                Test-IgwtRegCleanKeyPatternCoversRoot -Pattern "$root\Fabrikam Tools*" -Root $root | Should -BeFalse
                Test-IgwtRegCleanKeyPatternCoversRoot -Pattern '*\Policies\*' -Root $root | Should -BeFalse
                Test-IgwtRegCleanKeyPatternCoversRoot -Pattern 'HK*\SOFTWARE\Classes\CLSID\*' -Root 'HKCU\Software\Classes' | Should -BeFalse
            }
        }

        It 'rejects a carve-out that is not a category root' {
            $p = Get-RegCleanTestDoc 'protected'
            (Get-RegCleanTestGroup $p 'microsoft').categoryRootsAllowed += 'HKLM\SOFTWARE\Contoso'
            (Test-RegCleanCatalog $p) -join "`n" | Should -Match "categoryRootsAllowed 'HKLM\\SOFTWARE\\Contoso' is not a root in categories.json"
        }

        It 'rejects a deny-list name that is also a category root, or that is not a single key name' {
            $c = Get-RegCleanTestDoc 'categories'
            $c.denyList.vendorNames += 'SOFTWARE'
            $c.denyList.segmentNames += 'Classes\Contoso'
            $e = (Test-RegCleanCatalog $null $c) -join "`n"
            $e | Should -Match "denyList.vendorNames 'SOFTWARE' is also a category root"
            $e | Should -Match "denyList.segmentNames 'Classes\\Contoso' must be one key name"
        }

        It 'rejects a missing group, a wrong schema version and a bad category' {
            $p = Get-RegCleanTestDoc 'protected'
            $p.schemaVersion = 1
            $p.groups = @($p.groups | Where-Object { $_.id -ne 'runtimes' })
            $c = Get-RegCleanTestDoc 'categories'
            $c.categories[0].kind = 'delete'
            $c.categories[1].roots[0].view = '16'
            $e = (Test-RegCleanCatalog $p $c) -join "`n"
            $e | Should -Match "protected.json: schemaVersion must be 2"
            $e | Should -Match "group 'runtimes' is missing"
            $e | Should -Match "category 'uninstall': kind must be one of"
            $e | Should -Match "view must be 64 or 32"
        }
    }
}

Describe 'Registry cleaner owners, protection and exclusions (RG4, RG5, RG11-RG15, RG33)' {
    BeforeAll {
        $script:Sid = 'S-1-5-21-1-2-3-1001'
        $script:TiSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        $m64 = @{
            SystemRoot = 'C:\Windows'; windir = 'C:\Windows'; SystemDrive = 'C:'; ProgramData = 'C:\ProgramData'; ALLUSERSPROFILE = 'C:\ProgramData'
            ProgramFiles = 'C:\Program Files'; ProgramW6432 = 'C:\Program Files'; 'ProgramFiles(x86)' = 'C:\Program Files (x86)'
            CommonProgramFiles = 'C:\Program Files\Common Files'; CommonProgramW6432 = 'C:\Program Files\Common Files'; 'CommonProgramFiles(x86)' = 'C:\Program Files (x86)\Common Files'
        }
        $m32 = @{}; foreach ($k in $m64.Keys) { $m32[$k] = $m64[$k] }
        $m32['ProgramFiles'] = 'C:\Program Files (x86)'; $m32['CommonProgramFiles'] = 'C:\Program Files (x86)\Common Files'
        $user = @{}; foreach ($k in $m64.Keys) { $user[$k] = $m64[$k] }
        $user['USERPROFILE'] = 'C:\Users\contoso'; $user['APPDATA'] = 'C:\Users\contoso\AppData\Roaming'; $user['LOCALAPPDATA'] = 'C:\Users\contoso\AppData\Local'
        $script:Vars = @{ '64' = $m64; '32' = $m32; 'user' = $user }
        $script:VarsNoUser = @{ '64' = $m64; '32' = $m32 }
        $script:Drives = @{ SystemDrive = 'C'; Online = @('C', 'D'); Skipped = @{}; Notes = @() }
        $script:Existing = New-Object System.Collections.Generic.List[string]
        $script:UnknownPaths = New-Object System.Collections.Generic.List[string]
        $script:Probe = {
            param($p, $m)
            if ($m -eq 'List') { return 'Exists' }
            if ($script:UnknownPaths -contains $p) { return 'Unknown' }
            if ($script:Existing -contains $p) { return 'Exists' }
            return 'Missing'
        }
        $script:NoExclusions = [pscustomobject]@{ SchemaVersion = 1; Entries = @(); Path = '' }
        $script:UnPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

        $un = 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $un32 = 'TestRegistry:\HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        $unU = "TestRegistry:\HKU\$($script:Sid)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        function Add-RegTestKey([string]$Path, [hashtable]$Values = @{}, [hashtable]$Types = @{}) {
            $null = New-Item -Path $Path -Force
            foreach ($k in $Values.Keys) {
                $t = $(if ($Types.ContainsKey($k)) { $Types[$k] } elseif ($Values[$k] -is [int]) { 'DWord' } else { 'String' })
                $null = New-ItemProperty -LiteralPath $Path -Name $k -Value $Values[$k] -PropertyType $t -Force
            }
        }
        Add-RegTestKey -Path "$un\Contoso_is1" -Values @{ DisplayName = 'Contoso App'; Publisher = 'Contoso Ltd'; InstallLocation = 'C:\Program Files\Contoso\App'; UninstallString = '"C:\Program Files\Contoso\App\unins000.exe"' }
        Add-RegTestKey -Path "$un\FabrikamHidden" -Values @{ SystemComponent = 1; InstallLocation = 'C:\Program Files\Fabrikam\Gone' }
        Add-RegTestKey -Path "$un\FabrikamChild" -Values @{ ParentKeyName = 'FabrikamHidden'; DisplayName = 'Fabrikam Child' }
        Add-RegTestKey -Path "$un\{11111111-2222-3333-4444-555555555555}" -Values @{ WindowsInstaller = 1; UninstallString = 'MsiExec.exe /X{11111111-2222-3333-4444-555555555555}' }
        Add-RegTestKey -Path "$un\ContosoMsiWrapper" -Values @{ UninstallString = 'MsiExec.exe /I{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' }
        Add-RegTestKey -Path "$un\ContosoBroad" -Values @{ UninstallString = 'C:\Program Files\uninst.exe' }
        Add-RegTestKey -Path "$un32\Fabrikam32" -Values @{ InstallLocation = 'C:\Program Files (x86)\Fabrikam32' }
        Add-RegTestKey -Path "$unU\ContosoUser" -Values @{ InstallLocation = '%LOCALAPPDATA%\ContosoUser' } -Types @{ InstallLocation = 'ExpandString' }
        Add-RegTestKey -Path "$un\ContosoClean" -Values @{ DisplayName = 'Contoso Clean'; Publisher = 'Contoso Ltd'; UninstallString = '"C:\Program Files\ContosoClean\unins.exe"' }
        Add-RegTestKey -Path "$un\MsPart" -Values @{ DisplayName = 'Fabrikam Part'; Publisher = 'Microsoft Corporation'; UninstallString = '"C:\Program Files\FabrikamPart\unins.exe"' }
        Add-RegTestKey -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\contosoapp.exe' -Values @{ '(default)' = 'C:\Program Files\ContosoClean\contosoapp.exe' }
        Add-RegTestKey -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Values @{ ContosoTray = '"C:\Program Files\ContosoClean\tray.exe" /min'; WinPart = 'C:\Windows\System32\contoso.dll' }
        Add-RegTestKey -Path 'TestRegistry:\HKLM\SOFTWARE\Contoso\Leftover' -Values @{ Path = 'C:\Program Files\ContosoGone\x.dat' }

        Mock Test-IgwtNetworkPath -ModuleName iGWindowsTuner { ([string]$Path).StartsWith('\\') }
        Mock Test-IgwtRegCleanProcess64 -ModuleName iGWindowsTuner { $true }
        Mock Get-IgwtRegCleanAppxPackages -ModuleName iGWindowsTuner {
            [pscustomobject]@{ Name = 'Contoso.Notes'; PackageFamilyName = 'Contoso.Notes_abcdef123'; PublisherId = 'abcdef123'; InstallLocation = 'C:\Program Files\WindowsApps\Contoso.Notes_1.0_x64__abcdef123' }
        }
        Mock Get-IgwtRegCleanServiceList -ModuleName iGWindowsTuner {
            [pscustomobject]@{ Name = 'ContosoSvc'; DisplayName = 'Contoso Service'; ImagePath = '"C:\Program Files\Contoso\Svc\svc.exe" -k'; Type = 16; Start = 2; Group = ''; LaunchProtected = $null; State = 'Running' }
        }
        Mock Get-IgwtInstalledGames -ModuleName iGWindowsTuner { [pscustomobject]@{ Id = 'contosogame'; Name = 'Contoso Game'; ExePath = 'D:\Games\ContosoGame\game.exe'; AntiCheat = '' } }
        Mock Get-IgwtSteamLibraryPaths -ModuleName iGWindowsTuner { 'E:\SteamLibrary' }
        Mock Get-IgwtMsiProductState -ModuleName iGWindowsTuner { -1 }
        Mock Get-IgwtRegCleanTrustedInstallerSid -ModuleName iGWindowsTuner { 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
        Mock Get-IgwtRegCleanSecurityProducts -ModuleName iGWindowsTuner { }
        Mock Get-IgwtRegCleanPnpProviders -ModuleName iGWindowsTuner { }
        Mock Get-IgwtRegCleanKeySecurity -ModuleName iGWindowsTuner { [pscustomobject]@{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-32-544', 'S-1-5-18'); AclProtected = $false; HasExplicitAce = $false; Sddl = '' } }
        Mock Get-AuthenticodeSignature -ModuleName iGWindowsTuner { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }

        function Get-TestIndex([hashtable]$Variables = $script:Vars, [string]$Sid = $script:Sid) {
            InModuleScope iGWindowsTuner -Parameters @{ V = $Variables; S = $Sid; D = $script:Drives; P = $script:Probe } {
                param($V, $S, $D, $P) Get-IgwtRegCleanOwnerIndex -Sid $S -DriveTable $D -Probe $P -Variables $V
            }
        }
        function Test-TestOwned($Index, [hashtable]$Candidate) {
            InModuleScope iGWindowsTuner -Parameters @{ I = $Index; C = [pscustomobject]$Candidate } { param($I, $C) Test-IgwtRegCleanOwned -Index $I -Candidate $C }
        }
        function Get-TestContext([hashtable]$Variables = $script:Vars, $Exclusions = $script:NoExclusions) {
            InModuleScope iGWindowsTuner -Parameters @{ V = $Variables; P = $script:Probe; E = $Exclusions; S = $script:Sid } {
                param($V, $P, $E, $S) Get-IgwtRegCleanProtectionContext -Sid $S -Variables $V -Probe $P -Exclusions $E
            }
        }
        function Get-RegTestFinding([string]$Category, [string]$Kind, [string]$Path, [string]$Hive = 'HKLM', [string]$View = '64', [string]$ValueName = '', $Facts = $null) {
            $f = [pscustomobject]@{
                Id = 'test'; Category = $Category; Kind = $Kind; Hive = $Hive; Sid = $(if ($Hive -eq 'HKCU') { $script:Sid } else { '' }); View = $View; Path = $Path
                ValueName = $ValueName; RuleName = ''; Program = ''; OwnerHint = ''; Confidence = 'Review'; Evidence = @(); RemovalTool = $null; Size = 0; Includes = @(); Selectable = $true; Reason = ''
            }
            if ($null -ne $Facts) { $f | Add-Member -NotePropertyName Facts -NotePropertyValue $Facts }
            return $f
        }
        function Test-TestProtected($Finding, $Context) {
            if ($null -eq $Context) { $Context = Get-TestContext }
            InModuleScope iGWindowsTuner -Parameters @{ F = $Finding; C = $Context } { param($F, $C) Test-IgwtRegCleanProtected -Finding $F -Context $C }
        }
        function ConvertTo-TestJson($Object) { if ($null -eq $Object) { return '' }; return ($Object | ConvertTo-Json -Depth 4 -Compress) }
    }
    BeforeEach {
        $script:Existing.Clear()
        $script:UnknownPaths.Clear()
        foreach ($p in 'C:\Program Files\Contoso\App', 'C:\Program Files (x86)\Fabrikam32', 'C:\Users\contoso\AppData\Local\ContosoUser', 'C:\Program Files\Contoso\Svc') { $script:Existing.Add($p) }
    }

    Context 'owners index (RG4)' {
        It 'indexes every Uninstall key name in HKLM 64, HKLM 32 and the scanned user''s HKCU, hidden entries included' {
            $i = Get-TestIndex
            $i.Failed.Count | Should -Be 0
            foreach ($n in 'Contoso_is1', 'FabrikamHidden', 'FabrikamChild', '{11111111-2222-3333-4444-555555555555}', 'Fabrikam32', 'ContosoUser') { $i.Identifiers.ContainsKey($n) | Should -BeTrue -Because $n }
            @($i.Identifiers['Fabrikam32'])[0] | Should -Be 'uninstall|HKLM|32|Fabrikam32'
            @($i.Identifiers['ContosoUser'])[0] | Should -Be 'uninstall|HKCU|64|ContosoUser'
            @($i.Uninstall | Where-Object { $_.KeyName -eq 'FabrikamHidden' })[0].SystemComponent | Should -BeTrue
            @($i.Uninstall | Where-Object { $_.KeyName -eq 'ContosoUser' })[0].Sid | Should -Be $script:Sid
        }
        It 'takes product codes from GUID key names and MsiExec uninstall strings' {
            $i = Get-TestIndex
            $i.Identifiers.ContainsKey('{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}') | Should -BeTrue
            @($i.Uninstall | Where-Object { $_.KeyName -eq 'ContosoMsiWrapper' })[0].ProductCode | Should -Be '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
        }
        It 'stores existing install folders lower case, never missing or shared parent folders' {
            $i = Get-TestIndex
            $i.Folders.ContainsKey('c:\program files\contoso\app') | Should -BeTrue
            $i.Folders.ContainsKey('c:\program files (x86)\fabrikam32') | Should -BeTrue
            $i.Folders.ContainsKey('c:\users\contoso\appdata\local\contosouser') | Should -BeTrue
            $i.Folders.ContainsKey('c:\program files\fabrikam\gone') | Should -BeFalse
            $i.Folders.ContainsKey('c:\program files') | Should -BeFalse
            @($i.Folders.Keys | Where-Object { $_ -cne $_.ToLowerInvariant() -or $_.Length -le 3 }).Count | Should -Be 0
        }
        It 'adds Store packages, services, games and Steam libraries' {
            $i = Get-TestIndex
            foreach ($n in 'Contoso.Notes', 'Contoso.Notes_abcdef123', 'ContosoSvc') { $i.Identifiers.ContainsKey($n) | Should -BeTrue -Because $n }
            $i.PublisherIds.Contains('abcdef123') | Should -BeTrue
            $i.Folders.ContainsKey('c:\program files\contoso\svc') | Should -BeTrue
            $i.Folders.ContainsKey('d:\games\contosogame') | Should -BeTrue
            $i.Folders.ContainsKey('e:\steamlibrary') | Should -BeTrue
        }
        It 'skips HKCU with a note when there is no scanned user' {
            $i = Get-TestIndex -Variables $script:VarsNoUser -Sid ''
            $i.Identifiers.ContainsKey('ContosoUser') | Should -BeFalse
            @($i.Notes) | Should -Contain 'Per-user entries were not checked'
        }
        It 'records a failed part, and ownership is then Unknown' {
            Mock Get-IgwtRegCleanAppxPackages -ModuleName iGWindowsTuner { throw 'appx failed' }
            $i = Get-TestIndex
            @($i.Failed)[0] | Should -BeLike 'Store apps:*'
            (Test-TestOwned $i @{ Category = 'appPath'; KeyName = 'nothing' }).State | Should -Be 'Unknown'
        }
        It 'never calls Win32_Product and has no registry write member in the new files' {
            foreach ($n in 'RegistryCleanerOwners.ps1', 'RegistryCleanerProtection.ps1', 'RegistryCleanerExclusions.ps1') {
                $code = [IO.File]::ReadAllText((Join-Path $script:IgwtProjectRoot "src\Cleaner\$n"))
                $code | Should -Not -Match 'Win32_Product' -Because $n
                $code | Should -Not -Match '(?i)\.(SetValue|DeleteValue|DeleteSubKey|DeleteSubKeyTree|CreateSubKey|SetAccessControl)\(' -Because $n
                $code | Should -Not -Match '(?i)OpenSubKey\([^)]*\$true' -Because $n
            }
            [IO.File]::ReadAllText((Join-Path $script:IgwtProjectRoot 'src\Cleaner\RegistryCleanerProtection.ps1')) | Should -Not -Match '(?i)WriteAllText|Move-Item|New-Item|Set-Content|Out-File'
        }
    }

    Context 'ownership (RG5)' {
        It 'owns a key named like an installed Uninstall entry, service or package, but not itself' {
            $i = Get-TestIndex
            (Test-TestOwned $i @{ Category = 'softwareKey'; KeyName = 'Contoso_is1'; Vendor = 'Contoso'; Product = 'Contoso_is1' }).State | Should -Be 'Owned'
            (Test-TestOwned $i @{ Category = 'appPath'; KeyName = 'ContosoSvc' }).State | Should -Be 'Owned'
            (Test-TestOwned $i @{ Category = 'progId'; KeyName = 'Contoso.Notes_abcdef123' }).State | Should -Be 'Owned'
            $self = Test-TestOwned $i @{ Category = 'uninstall'; KeyName = 'FabrikamHidden'; Self = 'uninstall|HKLM|64|FabrikamHidden' }
            $self.State | Should -Be 'NotOwned' -Because $self.Reason
        }
        It 'counts every MSI ProductState except -1 as installed (Absent = another user)' {
            $c = @{ Category = 'uninstall'; KeyName = '{11111111-2222-3333-4444-555555555555}'; Self = 'uninstall|HKLM|64|{11111111-2222-3333-4444-555555555555}' }
            foreach ($state in 2, 1, 5, -6) {
                $script:MsiState = $state
                Mock Get-IgwtMsiProductState -ModuleName iGWindowsTuner { $script:MsiState }
                (Test-TestOwned (Get-TestIndex) $c).State | Should -Be 'Owned' -Because "state $state"
            }
            Mock Get-IgwtMsiProductState -ModuleName iGWindowsTuner { -1 }
            (Test-TestOwned (Get-TestIndex) $c).State | Should -Be 'NotOwned'
            Mock Get-IgwtMsiProductState -ModuleName iGWindowsTuner { throw 'COM failed' }
            (Test-TestOwned (Get-TestIndex) $c).State | Should -Be 'Unknown'
        }
        It 'owns a path inside an installed program folder, also on another drive' {
            $i = Get-TestIndex
            (Test-TestOwned $i @{ Category = 'run'; KeyName = 'x'; Paths = @('C:\Program Files\Contoso\App\tray.exe') }).State | Should -Be 'Owned'
            (Test-TestOwned $i @{ Category = 'run'; KeyName = 'x'; Paths = @('D:\Program Files\Contoso\App\tray.exe') }).State | Should -Be 'Owned'
            (Test-TestOwned $i @{ Category = 'run'; KeyName = 'x'; Paths = @('C:\Program Files\ContosoGone\tray.exe') }).State | Should -Be 'NotOwned'
        }
        It 'never decides by display name' {
            $r = Test-TestOwned (Get-TestIndex) @{ Category = 'appPath'; KeyName = 'Contoso App'; Paths = @('C:\Program Files\ContosoGone\a.dat') }
            $r.State | Should -Be 'NotOwned'
        }
        It 'owns a Software\<Vendor>\<Product> key whose program folder exists, and is Unknown when it cannot be checked' {
            $i = Get-TestIndex
            $c = @{ Category = 'softwareKey'; KeyName = 'Leftover'; Vendor = 'Contoso'; Product = 'Leftover' }
            (Test-TestOwned $i $c).State | Should -Be 'NotOwned'
            $script:Existing.Add('C:\Users\contoso\AppData\Roaming\Contoso\Leftover')
            (Test-TestOwned $i $c).State | Should -Be 'Owned'
            $null = $script:Existing.Remove('C:\Users\contoso\AppData\Roaming\Contoso\Leftover')
            $script:UnknownPaths.Add('C:\Program Files (x86)\Leftover')
            (Test-TestOwned $i $c).State | Should -Be 'Unknown'
            $script:UnknownPaths.Clear()
            (Test-TestOwned (Get-TestIndex -Variables $script:VarsNoUser -Sid '') $c).State | Should -Be 'Unknown'
        }
        It 'uses the Uninstall key name as the folder name for Uninstall entries' {
            $script:Existing.Add('C:\ProgramData\ContosoClean')
            $r = Test-TestOwned (Get-TestIndex) @{ Category = 'uninstall'; KeyName = 'ContosoClean'; Self = 'uninstall|HKLM|64|ContosoClean' }
            $r.State | Should -Be 'Owned'
        }
    }

    Context 'scanned user (RG33)' {
        It 'uses the interactive user, else the process user when not elevated, else nobody with a note' {
            Mock Get-IgwtInteractiveUserSid -ModuleName iGWindowsTuner { 'S-1-5-21-1-2-3-1001' }
            $u = InModuleScope iGWindowsTuner { Get-IgwtRegCleanScanUser }
            $u.Sid | Should -Be 'S-1-5-21-1-2-3-1001'
            $u.Source | Should -Be 'interactive'
            Mock Get-IgwtInteractiveUserSid -ModuleName iGWindowsTuner { $null }
            Mock Test-IgwtIsAdmin -ModuleName iGWindowsTuner { $false }
            $u = InModuleScope iGWindowsTuner { Get-IgwtRegCleanScanUser }
            $u.Sid | Should -Be ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
            $u.Source | Should -Be 'process'
            Mock Test-IgwtIsAdmin -ModuleName iGWindowsTuner { $true }
            $u = InModuleScope iGWindowsTuner { Get-IgwtRegCleanScanUser }
            $u.Sid | Should -BeNullOrEmpty
            $u.Note | Should -Be 'Per-user entries were not checked'
        }
    }

    Context 'protection (RG11-RG15)' {
        It 'does not protect a Contoso Uninstall entry, App Paths key or Run value through the microsoft group' {
            Test-TestProtected (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\ContosoClean") | Should -BeNullOrEmpty
            Test-TestProtected (Get-RegTestFinding -Category 'appPath' -Kind 'regKeyTree' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\contosoapp.exe') | Should -BeNullOrEmpty
            Test-TestProtected (Get-RegTestFinding -Category 'run' -Kind 'regValue' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName 'ContosoTray') | Should -BeNullOrEmpty
            Test-TestProtected (Get-RegTestFinding -Category 'run' -Kind 'regValue' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -View '32' -ValueName 'Gone') | Should -BeNullOrEmpty
        }
        It 'protects an entry with the Microsoft publisher, a Windows path, Installer and Policies keys' {
            (Test-TestProtected (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\MsPart")).Group | Should -Be 'microsoft'
            Test-TestProtected (Get-RegTestFinding -Category 'run' -Kind 'regValue' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName 'WinPart') | Should -Not -BeNullOrEmpty
            (Test-TestProtected (Get-RegTestFinding -Category 'progId' -Kind 'regKeyTree' -Path 'SOFTWARE\Classes\Installer\Products\0123')).Group | Should -Be 'microsoft'
            Test-TestProtected (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path 'SOFTWARE\Policies\Contoso') | Should -Not -BeNullOrEmpty
            Test-TestProtected (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path 'Software\Contoso\Policies\X' -Hive 'HKCU') | Should -Not -BeNullOrEmpty
        }
        It 'shows a GUID Uninstall key with a security vendor publisher as Protected with the removal tool' {
            $doc = Get-RegCleanTestDoc 'protected'
            $v = @((Get-RegCleanTestGroup $doc 'securityVendors').vendors | Where-Object { $_.type -eq 'consumer' -and $_.removalTool.url -and @($_.publisherPatterns).Count })[0]
            $key = "TestRegistry:\HKLM\$($script:UnPath)\{22222222-2222-3333-4444-555555555555}"
            $null = New-Item -Path $key -Force
            $null = New-ItemProperty -LiteralPath $key -Name Publisher -Value ((@($v.publisherPatterns)[0]) -replace '\*', ' Inc.') -Force
            $null = New-ItemProperty -LiteralPath $key -Name UninstallString -Value 'C:\Program Files\Gone\unins.exe' -Force
            $r = Test-TestProtected (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\{22222222-2222-3333-4444-555555555555}")
            $r.Group | Should -Be 'securityVendors'
            $r.SecurityProduct | Should -Be $v.name
            $r.RemovalTool.Url | Should -Be $v.removalTool.url
            $r.Reason | Should -Be "Use $($v.name)'s removal tool"
            $e = @((Get-RegCleanTestGroup $doc 'securityVendors').vendors | Where-Object { $_.type -eq 'edr' })[0]
            $fw = Get-RegTestFinding -Category 'firewallRule' -Kind 'firewallRule' -Path '' -Hive '' -View '' -Facts ([pscustomobject]@{ DisplayName = ((@($e.displayNamePatterns)[0]) -replace '\*', ' Agent'); Group = ''; Program = 'C:\Program Files\Gone\agent.exe' })
            $r = Test-TestProtected $fw
            $r.Reason | Should -BeLike 'Ask your administrator*'
            $r.SecurityProduct | Should -Be $e.name
        }
        It 'protects through every group of protected.json' {
            $doc = Get-RegCleanTestDoc 'protected'
            $i = 0
            foreach ($g in @($doc.groups)) {
                foreach ($o in (@($g) + @($g.vendors | Where-Object { $_ }))) {
                    $pat = @(@($o.publisherPatterns) + @($o.displayNamePatterns) | Where-Object { $_ })
                    if ($pat.Count -eq 0) { continue }
                    $i++
                    $key = "TestRegistry:\HKLM\$($script:UnPath)\GroupProbe$i"
                    $null = New-Item -Path $key -Force
                    $null = New-ItemProperty -LiteralPath $key -Name DisplayName -Value (([string]$pat[0]) -replace '\*', 'X') -Force
                    $r = Test-TestProtected (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\GroupProbe$i")
                    $r | Should -Not -BeNullOrEmpty -Because "$($g.id) $($o.id) $($pat[0])"
                }
            }
            $i | Should -BeGreaterThan 30
            foreach ($g in @($doc.groups | Where-Object { @($_.keyPatterns).Count -and $_.id -ne 'microsoft' })) {
                $kp = ([string]@($g.keyPatterns)[0]) -replace '^HK\*\\', '' -replace '^HKLM\\', '' -replace '\*', 'X'
                Test-TestProtected (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path $kp) | Should -Not -BeNullOrEmpty -Because "$($g.id) key $kp"
            }
        }
        It 'applies the RG32 deny list and the category roots' {
            foreach ($p in 'SOFTWARE\Contoso\Wow6432Node\X', 'SOFTWARE\Microsoft\Contoso', 'SOFTWARE\Classes', 'SOFTWARE\Contoso\Clients') {
                Test-TestProtected (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path $p) | Should -Not -BeNullOrEmpty -Because $p
            }
            (Test-TestProtected (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path $script:UnPath)).Reason | Should -Be 'a category root is never removed'
            (Test-TestProtected (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path 'SOFTWARE\Contoso\Leftover')).Reason | Should -Be 'outside the keys this category may remove'
            Test-TestProtected (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path 'SOFTWARE\Contoso\Leftover') | Should -BeNullOrEmpty
        }
        It 'protects keys owned by TrustedInstaller or writable only by SYSTEM and TrustedInstaller, and when that cannot be read' {
            $f = Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path 'SOFTWARE\Contoso\Leftover'
            Mock Get-IgwtRegCleanKeySecurity -ModuleName iGWindowsTuner { [pscustomobject]@{ Owner = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; Writers = @('S-1-5-32-544'); AclProtected = $false; HasExplicitAce = $false; Sddl = '' } }
            (Test-TestProtected $f).Reason | Should -BeLike '*TrustedInstaller*'
            Mock Get-IgwtRegCleanKeySecurity -ModuleName iGWindowsTuner { [pscustomobject]@{ Owner = 'S-1-5-18'; Writers = @('S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); AclProtected = $false; HasExplicitAce = $false; Sddl = '' } }
            (Test-TestProtected $f).Reason | Should -Be 'only SYSTEM or TrustedInstaller may change this key'
            Mock Get-IgwtRegCleanKeySecurity -ModuleName iGWindowsTuner { throw 'access denied' }
            (Test-TestProtected $f).Group | Should -Be 'live'
            Mock Get-IgwtRegCleanTrustedInstallerSid -ModuleName iGWindowsTuner { $null }
            (Test-TestProtected $f).Reason | Should -Be 'the TrustedInstaller account could not be identified'
        }
        It 'protects an entry whose existing file is Microsoft-signed, and when the signature or the file cannot be checked' {
            $f = Get-RegTestFinding -Category 'run' -Kind 'regValue' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName 'ContosoTray'
            $script:Existing.Add('C:\Program Files\ContosoClean\tray.exe')
            Mock Get-AuthenticodeSignature -ModuleName iGWindowsTuner { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, C=US' } } }
            (Test-TestProtected $f).Group | Should -Be 'signer'
            Mock Get-AuthenticodeSignature -ModuleName iGWindowsTuner { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Contoso Ltd, O=Contoso Ltd' } } }
            Test-TestProtected $f | Should -BeNullOrEmpty
            Mock Get-AuthenticodeSignature -ModuleName iGWindowsTuner { throw 'signature error' }
            (Test-TestProtected $f).Group | Should -Be 'live'
            $null = $script:Existing.Remove('C:\Program Files\ContosoClean\tray.exe')
            $script:UnknownPaths.Add('C:\Program Files\ContosoClean\tray.exe')
            (Test-TestProtected $f).Group | Should -Be 'live'
        }
        It 'protects products registered with Windows Security, and everything when that list cannot be read' {
            $f = Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\ContosoClean"
            Mock Get-IgwtRegCleanSecurityProducts -ModuleName iGWindowsTuner { [pscustomobject]@{ Class = 'AntiVirusProduct'; DisplayName = 'Contoso Clean'; ProductPath = 'C:\Program Files\ContosoAV\av.exe'; ReportingPath = '' } }
            $r = Test-TestProtected $f
            $r.Group | Should -Be 'windowsSecurity'
            $r.SecurityProduct | Should -Be 'Contoso Clean'
            Mock Get-IgwtRegCleanSecurityProducts -ModuleName iGWindowsTuner { [pscustomobject]@{ Class = 'AntiVirusProduct'; DisplayName = 'Fabrikam Shield'; ProductPath = '%ProgramFiles%\ContosoClean\shield.exe'; ReportingPath = '' } }
            (Test-TestProtected $f).SecurityProduct | Should -Be 'Fabrikam Shield'
            Mock Get-IgwtRegCleanSecurityProducts -ModuleName iGWindowsTuner { throw 'Invalid namespace' }
            (Test-TestProtected $f).Reason | Should -Be 'the security products registered with Windows could not be read'
        }
        It 'protects entries of a present device''s driver provider, and everything when drivers cannot be read' {
            $f = Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\ContosoClean"
            Mock Get-IgwtRegCleanPnpProviders -ModuleName iGWindowsTuner { 'Contoso' }
            (Test-TestProtected $f).Group | Should -Be 'drivers'
            Mock Get-IgwtRegCleanPnpProviders -ModuleName iGWindowsTuner { throw 'WMI error' }
            (Test-TestProtected $f).Group | Should -Be 'live'
        }
        It 'checks services: LaunchProtected, Early-Launch, drivers, boot start, Windows images and protected names' {
            $svc = {
                param($h)
                $b = @{ Name = 'ContosoSvc2'; DisplayName = 'Contoso Updater'; ImagePath = '"C:\Program Files\ContosoClean\upd.exe"'; Type = 16; Start = 3; Group = ''; LaunchProtected = $null }
                foreach ($k in $h.Keys) { $b[$k] = $h[$k] }
                Get-RegTestFinding -Category 'service' -Kind 'reportOnly' -Path ('SYSTEM\CurrentControlSet\Services\' + $b.Name) -Facts ([pscustomobject]@{ Name = $b.Name; Service = [pscustomobject]$b })
            }
            Test-TestProtected (& $svc @{}) | Should -BeNullOrEmpty
            (Test-TestProtected (& $svc @{ LaunchProtected = 1 })).SecurityProduct | Should -Be 'ContosoSvc2'
            (Test-TestProtected (& $svc @{ Group = 'Early-Launch' })).Reason | Should -Be 'an early-launch anti-malware driver'
            (Test-TestProtected (& $svc @{ Type = 1 })).Reason | Should -Be 'a driver or file system service'
            (Test-TestProtected (& $svc @{ Start = 0 })).Reason | Should -Be 'starts with Windows at boot or system start'
            Test-TestProtected (& $svc @{ ImagePath = '%SystemRoot%\System32\contososvc.dll' }) | Should -Not -BeNullOrEmpty
            (Test-TestProtected (& $svc @{ Name = 'vgc' })).Group | Should -Be 'antiCheat'
            Test-TestProtected (& $svc @{ Name = 'WinDefend' }) | Should -Not -BeNullOrEmpty
            (Test-TestProtected (Get-RegTestFinding -Category 'service' -Kind 'reportOnly' -Path 'SYSTEM\CurrentControlSet\Services\X' -Facts ([pscustomobject]@{ Name = 'X' }))).Reason | Should -Be 'the service facts could not be read'
        }
        It 'checks firewall rows by name and program, and tasks by path' {
            $fw = { param($dn, $prog) Get-RegTestFinding -Category 'firewallRule' -Kind 'firewallRule' -Path '' -Hive '' -View '' -Facts ([pscustomobject]@{ DisplayName = $dn; Group = ''; Program = $prog }) }
            Test-TestProtected (& $fw 'Contoso Sync' 'C:\Program Files\ContosoClean\sync.exe') | Should -BeNullOrEmpty
            Test-TestProtected (& $fw 'Contoso Sync' 'C:\Games\Steam\steam.exe') | Should -Not -BeNullOrEmpty
            (Test-TestProtected (& $fw 'Steam' 'C:\Gone\x.exe')).Group | Should -Be 'launchers'
            $task = { param($tp) Get-RegTestFinding -Category 'task' -Kind 'reportOnly' -Path $tp -Hive '' -View '' -Facts ([pscustomobject]@{ TaskPath = $tp; Actions = @('C:\Gone\t.exe') }) }
            Test-TestProtected (& $task '\ContosoUpdate') | Should -BeNullOrEmpty
            Test-TestProtected (& $task '\Microsoft\Windows\Contoso') | Should -Not -BeNullOrEmpty
            Test-TestProtected (& $task '\FACEIT\Updater') | Should -Not -BeNullOrEmpty
        }
        It 'gives the same answer at the scan, the preview and the engine (fresh context, JSON round trip)' {
            $cases = @(
                (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\ContosoClean"),
                (Get-RegTestFinding -Category 'uninstall' -Kind 'regKeyTree' -Path "$($script:UnPath)\MsPart"),
                (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path 'SOFTWARE\Contoso\Wow6432Node\X')
            )
            foreach ($f in $cases) {
                $scan = ConvertTo-TestJson (Test-TestProtected $f (Get-TestContext))
                $plan = ConvertTo-TestJson (Test-TestProtected ($f | ConvertTo-Json -Depth 6 | ConvertFrom-Json) (Get-TestContext))
                $engine = ConvertTo-TestJson (Test-TestProtected ($f | ConvertTo-Json -Depth 6 | ConvertFrom-Json) (Get-TestContext))
                $plan | Should -Be $scan
                $engine | Should -Be $scan
            }
        }
    }

    Context 'exclusions (RG13)' {
        BeforeEach {
            $script:ExPath = InModuleScope iGWindowsTuner { Get-IgwtRegCleanExclusionsPath }
            if (Test-Path -LiteralPath $script:ExPath) { Remove-Item -LiteralPath $script:ExPath -Force }
        }
        It 'is empty without a file and lives in the data root State folder' {
            $script:ExPath | Should -Be (Join-Path $TestDrive 'IgwtData\State\regclean-exclusions.json')
            @((Get-IgwtRegCleanExclusions).Entries).Count | Should -Be 0
        }
        It 'saves and reads back a strict, ASCII, CRLF file through a temporary file' {
            $r = Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'HKCU\Software\Contoso\*'; scope = 'key'; reason = 'still used' }, [pscustomobject]@{ pattern = 'C:\Tools\Contoso'; scope = 'path'; reason = 'portable app'; addedUtc = '2026-11-08T10:00:00Z' }) -Confirm:$false
            @($r.Entries).Count | Should -Be 2
            @($r.Entries)[0].addedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
            @($r.Entries)[1].addedUtc | Should -Be '2026-11-08T10:00:00Z'
            $text = [IO.File]::ReadAllText($script:ExPath)
            $text | Should -Not -Match '[^\x00-\x7F]'
            $text | Should -Not -Match '(?<!\r)\n'
            Test-Path -LiteralPath ($script:ExPath + '.tmp') | Should -BeFalse
            @((Get-IgwtRegCleanExclusions).Entries | ForEach-Object { $_.pattern }) | Should -Be @('HKCU\Software\Contoso\*', 'C:\Tools\Contoso')
        }
        It 'refuses invalid entries and writes nothing' {
            { Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'Software\Contoso'; scope = 'key'; reason = 'x' }) -Confirm:$false } | Should -Throw '*not saved*'
            { Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'HKLM\SOFTWARE\Contoso'; scope = 'tree'; reason = 'x' }) -Confirm:$false } | Should -Throw '*not saved*'
            { Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'HKLM\SOFTWARE\Contoso'; scope = 'key'; reason = '' }) -Confirm:$false } | Should -Throw '*not saved*'
            { Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'HKLM\SOFTWARE\Contoso'; scope = 'key'; reason = 'x'; extra = 1 }) -Confirm:$false } | Should -Throw '*unknown property*'
            $many = @(1..1001 | ForEach-Object { @{ pattern = "HKLM\SOFTWARE\Contoso$_"; scope = 'key'; reason = 'x' } })
            { Save-IgwtRegCleanExclusions -Entries $many -Confirm:$false } | Should -Throw '*at most 1000*'
            Test-Path -LiteralPath $script:ExPath | Should -BeFalse
        }
        It 'writes nothing with -WhatIf and refuses in read-only mode' {
            Save-IgwtRegCleanExclusions -Entries @(@{ pattern = 'HKLM\SOFTWARE\Contoso'; scope = 'key'; reason = 'x' }) -WhatIf
            Test-Path -LiteralPath $script:ExPath | Should -BeFalse
            try {
                Set-IgwtEnvironment -ReadOnly
                { Save-IgwtRegCleanExclusions -Entries @() -Confirm:$false } | Should -Throw 'Read-only mode:*'
            } finally { Set-IgwtEnvironment -ReadOnly:$false }
            Test-Path -LiteralPath $script:ExPath | Should -BeFalse
        }
        It 'needs administrator rights outside TestMode' {
            Mock Test-IgwtIsAdmin -ModuleName iGWindowsTuner { $false }
            InModuleScope iGWindowsTuner {
                $script:IgwtSettings.TestMode = $false
                try { { Save-IgwtRegCleanExclusions -Entries @() -Confirm:$false } | Should -Throw '*administrator*' }
                finally { $script:IgwtSettings.TestMode = $true }
            }
            Test-Path -LiteralPath $script:ExPath | Should -BeFalse
        }
        It 'refuses to read an invalid file, so a scan cannot run with a lost list' {
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $script:ExPath) -Force
            foreach ($bad in '{ not json', '{"schemaVersion":2,"entries":[]}', '{"schemaVersion":1,"entries":[],"extra":1}', '{"schemaVersion":1,"entries":[{"pattern":"HKLM\\SOFTWARE\\X","scope":"key","reason":"x","addedUtc":"yesterday"}]}') {
                [IO.File]::WriteAllText($script:ExPath, $bad)
                { Get-IgwtRegCleanExclusions } | Should -Throw '*exclusion list*' -Because $bad
                { InModuleScope iGWindowsTuner -Parameters @{ V = $script:Vars; P = $script:Probe } { param($V, $P) Get-IgwtRegCleanProtectionContext -Variables $V -Probe $P } } | Should -Throw '*exclusion list*'
            }
            Remove-Item -LiteralPath $script:ExPath -Force
        }
        It 'excludes by key, value and path in the protection test' {
            $ex = { param($p, $s) [pscustomobject]@{ SchemaVersion = 1; Entries = @([pscustomobject]@{ pattern = $p; scope = $s; reason = 'mine'; addedUtc = '2026-11-08T10:00:00Z' }); Path = '' } }
            $r = Test-TestProtected (Get-RegTestFinding -Category 'softwareKey' -Kind 'regKeyTree' -Path 'SOFTWARE\Contoso\Leftover') (Get-TestContext -Exclusions (& $ex 'HKLM\SOFTWARE\Contoso' 'key'))
            $r.Excluded | Should -BeTrue
            $r.Reason | Should -Be 'Excluded by you: mine'
            $run = Get-RegTestFinding -Category 'run' -Kind 'regValue' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName 'ContosoTray'
            (Test-TestProtected $run (Get-TestContext -Exclusions (& $ex 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Contoso*' 'value'))).Excluded | Should -BeTrue
            (Test-TestProtected $run (Get-TestContext -Exclusions (& $ex '%ProgramFiles%\ContosoClean' 'path'))).Excluded | Should -BeTrue
            Test-TestProtected $run (Get-TestContext -Exclusions (& $ex 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Contoso*' 'value')) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Registry cleaner wrapped system calls (RG4, RG12)' {
    It 'throw in TestMode unless mocked' {
        InModuleScope iGWindowsTuner {
            foreach ($n in 'Get-IgwtRegCleanSecurityProducts', 'Get-IgwtRegCleanPnpProviders', 'Get-IgwtRegCleanAppxPackages', 'Get-IgwtRegCleanServiceList') {
                { & $n } | Should -Throw '*TestMode safety*' -Because $n
            }
            { Get-IgwtMsiProductState -ProductCode '{11111111-2222-3333-4444-555555555555}' } | Should -Throw '*TestMode safety*'
        }
    }
}
