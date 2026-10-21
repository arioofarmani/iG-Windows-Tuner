# Cleaning engine tests. Every file operation happens inside $TestDrive fixtures, and the engine
# refuses deletions outside the test root in TestMode (Set-IgwtCleanerTestRoot). Service, process,
# Recycle Bin, Delivery Optimization, DISM and pnputil calls are mocked.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Set-IgwtCleanerTestRoot -Path $TestDrive

    function New-TestFolder {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates TestDrive fixtures only.')]
        [CmdletBinding()]
        param()
        $p = Join-Path $TestDrive ('t' + [guid]::NewGuid().ToString('N').Substring(0, 10))
        $null = New-Item -ItemType Directory -Path $p -Force
        return $p
    }
    function New-Fixture {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates TestDrive fixtures only.')]
        [CmdletBinding()]
        param([string]$Path, [int]$Bytes = 16, [double]$AgeHours = 0)
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] $Bytes))
        if ($AgeHours -gt 0) {
            $t = [DateTime]::UtcNow.AddHours(-$AgeHours)
            [System.IO.File]::SetCreationTimeUtc($Path, $t)
            [System.IO.File]::SetLastWriteTimeUtc($Path, $t)
        }
        return $Path
    }
    function New-TestRule {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory rule object only.')]
        [CmdletBinding()]
        param([hashtable]$Props)
        $base = [ordered]@{ id = 'clean.test.fixture'; name = 'Fixture'; category = 'System'; level = 'Standard'; method = 'files'
            hint = 'Fixture rule.'; description = 'Fixture rule used by the Pester suite to exercise the cleaning engine.'; sideEffects = ''; roots = @() }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        $o = [pscustomobject]$base
        return (InModuleScope iGWindowsTuner -Parameters @{ R = $o } { param($R) ConvertTo-IgwtNormalizedCleanerRule -Rule $R })
    }
    function Use-TestRules([object[]]$Rules) {
        InModuleScope iGWindowsTuner -Parameters @{ R = $Rules } { param($R) $script:IgwtCleanerRuleCache = @($R); $script:IgwtCleanerProtection = $null }
    }
    function Invoke-TestScan($Rule) {
        Use-TestRules @($Rule)
        return (Invoke-IgwtCleanerScan -RuleId $Rule.id)
    }
    function Invoke-TestClean($Rule) {
        $scan = Invoke-TestScan $Rule
        $clean = Invoke-IgwtCleanerClean -Scan $scan
        return [pscustomobject]@{ Scan = $scan.Rules[0]; Clean = $clean.Rules[0]; LogFile = $clean.LogFile }
    }
    function Set-TestShellFolder {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes to the Pester TestRegistry: drive only.')]
        [CmdletBinding()]
        param([string]$Name, [string]$Value)
        $key = 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        if (-not (Test-Path -LiteralPath $key)) { $null = New-Item -Path $key -Force }
        $null = New-ItemProperty -LiteralPath $key -Name $Name -Value $Value -PropertyType String -Force
        InModuleScope iGWindowsTuner { $script:IgwtCleanerProtection = $null }
    }
}

AfterAll {
    InModuleScope iGWindowsTuner { $script:IgwtCleanerRuleCache = $null; $script:IgwtCleanerProtection = $null; $script:IgwtLastCleanerScan = $null }
    Set-IgwtCleanerTestRoot -Path ''
}

Describe 'Cleaner rule catalog' {
    BeforeAll {
        Mock -ModuleName iGWindowsTuner Get-IgwtSteamLibraryPaths { @((Join-Path $TestDrive 'SteamFixture')) }
        InModuleScope iGWindowsTuner { $script:IgwtCleanerRuleCache = $null }
        $script:Rules = @(Get-IgwtCleanerRules -Force)
    }
    AfterAll { InModuleScope iGWindowsTuner { $script:IgwtCleanerRuleCache = $null } }

    It 'validates without errors' { @(Test-IgwtCleanerCatalog) | Should -BeNullOrEmpty }
    It 'ships rules in every category' {
        foreach ($c in 'System', 'Gaming', 'Browsers', 'Apps', 'Developer', 'Downloads') { @($script:Rules | Where-Object { $_.category -eq $c }).Count | Should -BeGreaterThan 0 -Because $c }
    }
    It 'gives every rule a hint of 140 characters or less and a description' {
        foreach ($r in $script:Rules) {
            ([string]$r.hint).Length | Should -BeLessOrEqual 140 -Because $r.id
            ([string]$r.hint).Length | Should -BeGreaterThan 10 -Because $r.id
            ([string]$r.description).Length | Should -BeGreaterOrEqual 40 -Because $r.id
        }
    }
    It 'keeps Advanced and Expert rules opt-in' {
        foreach ($r in ($script:Rules | Where-Object { $_.level -ne 'Standard' })) { $r.default | Should -BeFalse -Because $r.id }
    }
    It 'requires the Downloads rule to be opt-in and to use the Recycle Bin' {
        $d = @($script:Rules | Where-Object { $_.allowDownloads })
        $d.Count | Should -Be 1
        $d[0].recycle | Should -BeTrue
        $d[0].default | Should -BeFalse
    }
    It 'lists the browser process for every browser rule' {
        foreach ($r in ($script:Rules | Where-Object { $_.category -eq 'Browsers' })) { @($r.requiresClosed).Count | Should -BeGreaterThan 0 -Because $r.id }
    }
    It 'cleans browsers only through allowed cache folder names' {
        $allowed = InModuleScope iGWindowsTuner { $script:IgwtBrowserCacheNames }
        foreach ($r in ($script:Rules | Where-Object { $_.method -eq 'browserCache' })) {
            foreach ($d in @($r.profileCacheDirs) + @($r.rootCacheDirs)) { $d | Should -BeIn $allowed -Because $r.id }
        }
    }
    It 'never deletes Windows.old or Docker data directly (guidance only)' {
        (Get-IgwtCleanerRules | Where-Object { $_.id -eq 'clean.windows-old' }).method | Should -Be 'guidance'
        (Get-IgwtCleanerRules | Where-Object { $_.id -eq 'clean.dev.docker' }).method | Should -Be 'guidance'
    }
    It 'reports every broken rule property' {
        $bad = @(
            (New-TestRule @{ id = 'Bad Id' })
            (New-TestRule @{ id = 'clean.bad.hint'; hint = ('x' * 141); roots = @('%TEMP%\IgwtFixture') })
            (New-TestRule @{ id = 'clean.bad.desc'; description = 'short'; roots = @('%TEMP%\IgwtFixture') })
            (New-TestRule @{ id = 'clean.bad.category'; category = 'Nope'; roots = @('%TEMP%\IgwtFixture') })
            (New-TestRule @{ id = 'clean.bad.default'; level = 'Expert'; default = $true; roots = @('%TEMP%\IgwtFixture') })
            (New-TestRule @{ id = 'clean.bad.downloads'; allowDownloads = $true; roots = @('%USERPROFILE%\Downloads') })
            (New-TestRule @{ id = 'clean.bad.browser'; category = 'Browsers'; roots = @('%TEMP%\IgwtFixture') })
            (New-TestRule @{ id = 'clean.bad.source'; sources = @('http://example.com'); roots = @('%TEMP%\IgwtFixture') })
            (New-TestRule @{ id = 'clean.bad.root'; roots = @('%SystemRoot%\System32') })
            (New-TestRule @{ id = 'clean.bad.cookies'; method = 'browserCache'; userDataRoots = @('%LOCALAPPDATA%\X\User Data'); profileCacheDirs = @('Cookies'); requiresClosed = @('x') })
            (New-TestRule @{ id = 'clean.bad.noroots' })
        )
        Mock -ModuleName iGWindowsTuner Get-IgwtCleanerRules { $bad }
        $errors = (@(Test-IgwtCleanerCatalog) -join "`n")
        $errors | Should -Match "Bad Id: id must start with 'clean.'"
        $errors | Should -Match 'clean.bad.hint: hint is 141 characters'
        $errors | Should -Match 'clean.bad.desc: description is too short'
        $errors | Should -Match "clean.bad.category: unknown category 'Nope'"
        $errors | Should -Match 'clean.bad.default: only Standard rules may be on by default'
        $errors | Should -Match 'clean.bad.downloads: rules that clean Downloads must send files to the Recycle Bin'
        $errors | Should -Match 'clean.bad.browser: browser rules must list the browser process'
        $errors | Should -Match "clean.bad.source: source 'http://example.com' must be https"
        $errors | Should -Match 'clean.bad.root: root .* resolves to a protected location'
        $errors | Should -Match "clean.bad.cookies: 'Cookies' is not an allowed browser cache folder name"
        $errors | Should -Match "clean.bad.noroots: 'files' rules need roots"
    }
}

Describe 'Path canonicalization and the denylist' {
    It 'refuses empty, relative, UNC and device paths' -ForEach @(
        @{ P = '' }, @{ P = 'relative\path' }, @{ P = '\\server\share\x' }, @{ P = '\\?\C:\Windows' }, @{ P = '\\.\C:\x' }, @{ P = 'C:relative' }
    ) {
        $path = $P
        { InModuleScope iGWindowsTuner -Parameters @{ X = $path } { param($X) ConvertTo-IgwtCanonicalPath -Path $X } } | Should -Throw
    }
    It 'resolves ".." segments before any check' {
        $c = InModuleScope iGWindowsTuner -Parameters @{ X = "$env:SystemRoot\Temp\..\System32" } { param($X) ConvertTo-IgwtCanonicalPath -Path $X }
        $c | Should -Be (Join-Path $env:SystemRoot 'System32')
    }
    It 'expands 8.3 short names so they cannot bypass the denylist' {
        $short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($env:ProgramFiles).ShortPath
        if ($short -eq $env:ProgramFiles) { Set-ItResult -Skipped -Because '8.3 names are disabled on this volume' ; return }
        $c = InModuleScope iGWindowsTuner -Parameters @{ X = "$short\IgwtNotThere" } { param($X) ConvertTo-IgwtCanonicalPath -Path $X }
        $c | Should -Be (Join-Path $env:ProgramFiles 'IgwtNotThere')
        InModuleScope iGWindowsTuner -Parameters @{ X = $c } { param($X) Test-IgwtCleanerPathProtected -Path $X } | Should -Not -BeNullOrEmpty
    }
    It 'protects <P>' -ForEach @(
        @{ P = "$env:SystemDrive\" }
        @{ P = "$env:SystemRoot" }
        @{ P = "$env:SystemRoot\explorer.exe" }
        @{ P = "$env:SystemRoot\System32\kernel32.dll" }
        @{ P = "$env:SystemRoot\WinSxS\x.manifest" }
        @{ P = "$env:SystemRoot\Installer\x.msi" }
        @{ P = "$env:ProgramFiles\App\app.exe" }
        @{ P = "${env:ProgramFiles(x86)}\Steam\steamapps\common\Game\game.exe" }
        @{ P = "$env:ProgramData" }
        @{ P = "$env:ProgramData\Microsoft\Windows Defender\Scans\x.bin" }
        @{ P = "$env:USERPROFILE" }
        @{ P = "$env:USERPROFILE\notes.txt" }
        @{ P = "$env:USERPROFILE\Documents\thesis.docx" }
        @{ P = "$env:USERPROFILE\Desktop\x.lnk" }
        @{ P = "$env:USERPROFILE\Saved Games\save.dat" }
        @{ P = "$env:USERPROFILE\Downloads\setup.exe" }
        @{ P = "$env:LOCALAPPDATA" }
        @{ P = "$env:APPDATA" }
        @{ P = "$env:USERPROFILE\AppData\LocalLow" }
        @{ P = "$env:APPDATA\Mozilla\Firefox\Profiles\a.default\places.sqlite" }
        @{ P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" }
        @{ P = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies" }
        @{ P = "$env:SystemDrive\`$Recycle.Bin\S-1-5-21-1\x" }
    ) {
        $path = $P
        InModuleScope iGWindowsTuner -Parameters @{ X = $path } { param($X) $script:IgwtCleanerProtection = $null; Test-IgwtCleanerPathProtected -Path (ConvertTo-IgwtCanonicalPath -Path $X) } | Should -Not -BeNullOrEmpty
    }
    It 'allows <P>' -ForEach @(
        @{ P = "$env:TEMP\x.tmp" }
        @{ P = "$env:SystemRoot\Temp\x.tmp" }
        @{ P = "$env:SystemRoot\SoftwareDistribution\Download\abc\x.cab" }
        @{ P = "$env:SystemRoot\Logs\CBS\CbsPersist_1.log" }
        @{ P = "$env:SystemRoot\Minidump\a.dmp" }
        @{ P = "$env:LOCALAPPDATA\D3DSCache\x\y.idx" }
        @{ P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\Cache_Data\f_000001" }
        @{ P = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\a.default\cache2\entries\x" }
        @{ P = "${env:ProgramFiles(x86)}\Steam\steamapps\shadercache\730\x.bin" }
        @{ P = "$env:USERPROFILE\.gradle\caches\modules-2\x.jar" }
    ) {
        $path = $P
        InModuleScope iGWindowsTuner -Parameters @{ X = $path } { param($X) $script:IgwtCleanerProtection = $null; Test-IgwtCleanerPathProtected -Path (ConvertTo-IgwtCanonicalPath -Path $X) } | Should -BeNullOrEmpty
    }
    It 'allows Downloads only for the opt-in rule' {
        $p = InModuleScope iGWindowsTuner { ConvertTo-IgwtCanonicalPath -Path "$env:USERPROFILE\Downloads\old.zip" }
        InModuleScope iGWindowsTuner -Parameters @{ X = $p } { param($X) Test-IgwtCleanerPathProtected -Path $X -AllowDownloads } | Should -BeNullOrEmpty
    }
    It 'protects a redirected Documents folder read from Shell Folders' {
        $docs = New-TestFolder
        Set-TestShellFolder -Name 'Personal' -Value $docs
        try {
            InModuleScope iGWindowsTuner -Parameters @{ X = (Join-Path $docs 'report.docx') } { param($X) Test-IgwtCleanerPathProtected -Path $X } | Should -Match 'protected folder'
        } finally { Remove-ItemProperty -LiteralPath 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name 'Personal'; InModuleScope iGWindowsTuner { $script:IgwtCleanerProtection = $null } }
    }
    It 'flags reparse points, cloud placeholders and offline files by attribute' -ForEach @(
        @{ A = 0x400; Skip = $true }, @{ A = 0x1000; Skip = $true }, @{ A = 0x40000; Skip = $true }, @{ A = 0x400000; Skip = $true }
        @{ A = 0x400020; Skip = $true }, @{ A = 0x5; Skip = $true }, @{ A = 0x20; Skip = $false }, @{ A = 0x1; Skip = $false }, @{ A = 0x80; Skip = $false }
    ) {
        $a = [long]$A
        $r = InModuleScope iGWindowsTuner -Parameters @{ X = $a } { param($X) Test-IgwtCleanerAttributesSkippable -Attributes $X }
        if ($Skip) { $r | Should -Not -BeNullOrEmpty } else { $r | Should -BeNullOrEmpty }
    }
    It 'lets system files through only when the rule allows them' {
        InModuleScope iGWindowsTuner { Test-IgwtCleanerAttributesSkippable -Attributes 0x5 -AllowSystemFiles } | Should -BeNullOrEmpty
    }
}

Describe 'Root resolution refuses malicious roots' {
    AfterEach { Remove-Item Env:\IGWT_TEST_EVIL -ErrorAction SilentlyContinue }
    It 'refuses <T>' -ForEach @(
        @{ T = 'C:\' }
        @{ T = '%SystemDrive%\' }
        @{ T = '%USERPROFILE%' }
        @{ T = '%USERPROFILE%\Documents' }
        @{ T = '%SystemRoot%' }
        @{ T = '%SystemRoot%\System32' }
        @{ T = '%ProgramFiles%' }
        @{ T = '%ProgramData%' }
        @{ T = '%LOCALAPPDATA%' }
        @{ T = '%TEMP%\..\..' }
        @{ T = '%TEMP%\..\..\..\Documents' }
        @{ T = '\\server\share\cache' }
        @{ T = '\\?\C:\Windows\Temp' }
    ) {
        $rule = New-TestRule @{ roots = @($T) }
        $res = @(InModuleScope iGWindowsTuner -Parameters @{ R = $rule } { param($R) $script:IgwtCleanerProtection = $null; Resolve-IgwtCleanerRoots -Rule $R })
        $res.Count | Should -BeGreaterThan 0
        foreach ($x in $res) { $x.Status | Should -Be 'Refused' }
    }
    It 'refuses a root injected through an environment variable' {
        $env:IGWT_TEST_EVIL = "$env:SystemRoot\System32"
        $rule = New-TestRule @{ roots = @('%IGWT_TEST_EVIL%') }
        $res = @(InModuleScope iGWindowsTuner -Parameters @{ R = $rule } { param($R) Resolve-IgwtCleanerRoots -Rule $R })
        $res[0].Status | Should -Be 'Refused'
    }
    It 'skips roots with unresolved environment variables instead of guessing' {
        $rule = New-TestRule @{ roots = @('%IGWT_TEST_UNSET_VAR%\cache') }
        @(InModuleScope iGWindowsTuner -Parameters @{ R = $rule } { param($R) Resolve-IgwtCleanerRoots -Rule $R }) | Should -BeNullOrEmpty
    }
    It 'refuses a root that is itself a junction' {
        $base = New-TestFolder
        $target = Join-Path $base 'target'; $null = New-Item -ItemType Directory -Path $target
        $link = Join-Path $base 'link'; $null = New-Item -ItemType Junction -Path $link -Value $target
        $rule = New-TestRule @{ roots = @($link) }
        $res = @(InModuleScope iGWindowsTuner -Parameters @{ R = $rule } { param($R) Resolve-IgwtCleanerRoots -Rule $R })
        $res[0].Status | Should -Be 'Refused'
        $res[0].Reason | Should -Match 'reparse point'
    }
    It 'expands allUsers roots from the profile list (real user SIDs only)' {
        $users = New-TestFolder
        $a = Join-Path $users 'alice'; $b = Join-Path $users 'bob'
        $null = New-Item -ItemType Directory -Path (Join-Path $a 'AppData\Local\IgwtFixtureCache') -Force
        $null = New-Item -ItemType Directory -Path (Join-Path $b 'AppData\Local\IgwtFixtureCache') -Force
        $list = 'TestRegistry:\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($e in @(@{ S = 'S-1-5-21-1-2-3-1001'; P = $a }, @{ S = 'S-1-5-21-1-2-3-1002'; P = $b }, @{ S = 'S-1-5-18'; P = $a })) {
            $k = Join-Path $list $e.S
            $null = New-Item -Path $k -Force
            $null = New-ItemProperty -LiteralPath $k -Name ProfileImagePath -Value $e.P -PropertyType ExpandString -Force
        }
        $rule = New-TestRule @{ roots = @('%LOCALAPPDATA%\IgwtFixtureCache'); allUsers = $true }
        $res = @(InModuleScope iGWindowsTuner -Parameters @{ R = $rule } { param($R) Resolve-IgwtCleanerRoots -Rule $R -AllUsers } | Where-Object { $_.Status -eq 'Ok' })
        @($res.Path) | Should -Contain (Join-Path $a 'AppData\Local\IgwtFixtureCache')
        @($res.Path) | Should -Contain (Join-Path $b 'AppData\Local\IgwtFixtureCache')
        Remove-Item -LiteralPath $list -Recurse -Force
    }
}

Describe 'Scan then clean on fixtures' {
    It 'deletes the scanned files, removes emptied subfolders and keeps the root' {
        $root = New-TestFolder
        $f1 = New-Fixture (Join-Path $root 'a.tmp') 100
        $f2 = New-Fixture (Join-Path $root 'sub\deeper\b.tmp') 200
        $rule = New-TestRule @{ roots = @($root) }
        $r = Invoke-TestClean $rule
        $r.Scan.Status | Should -Be 'Ready'
        $r.Scan.Count | Should -Be 2
        $r.Scan.Bytes | Should -Be 300
        $r.Clean.DeletedCount | Should -Be 2
        $r.Clean.DeletedBytes | Should -Be 300
        Test-Path -LiteralPath $f1 | Should -BeFalse
        Test-Path -LiteralPath $f2 | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $root 'sub') | Should -BeFalse
        Test-Path -LiteralPath $root | Should -BeTrue
    }
    It 'writes every deleted path to the JSONL deletion log' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'logged.tmp') 10
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root) })
        $lines = @(Get-Content -LiteralPath $r.LogFile | ForEach-Object { $_ | ConvertFrom-Json })
        @($lines.path) | Should -Contain $f
        ($lines | Where-Object { $_.path -eq $f }).rule | Should -Be 'clean.test.fixture'
    }
    It 'never deletes files that appeared after the scan' {
        $root = New-TestFolder
        $null = New-Fixture (Join-Path $root 'old.tmp')
        $rule = New-TestRule @{ roots = @($root) }
        $scan = Invoke-TestScan $rule
        $new = New-Fixture (Join-Path $root 'new.tmp')
        $null = Invoke-IgwtCleanerClean -Scan $scan
        Test-Path -LiteralPath $new | Should -BeTrue
    }
    It 'skips files that changed after the scan' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'changing.log') 10
        $rule = New-TestRule @{ roots = @($root) }
        $scan = Invoke-TestScan $rule
        [System.IO.File]::AppendAllText($f, 'more')
        $c = (Invoke-IgwtCleanerClean -Scan $scan).Rules[0]
        Test-Path -LiteralPath $f | Should -BeTrue
        $c.Skipped.Keys | Should -Contain 'changed since the scan'
    }
    It 'skips files that are locked by another process' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'locked.tmp') 10
        $rule = New-TestRule @{ roots = @($root) }
        $scan = Invoke-TestScan $rule
        $fs = [System.IO.File]::Open($f, 'Open', 'ReadWrite', 'None')
        try { $c = (Invoke-IgwtCleanerClean -Scan $scan).Rules[0] } finally { $fs.Dispose() }
        Test-Path -LiteralPath $f | Should -BeTrue
        $c.Skipped.Keys | Should -Contain 'in use'
        $c.Status | Should -Be 'Cleaned'
    }
    It 'applies the minimum age using the newer of creation and write time' {
        $root = New-TestFolder
        $old = New-Fixture -Path (Join-Path $root 'old.tmp') -Bytes 10 -AgeHours 72
        $young = New-Fixture (Join-Path $root 'young.tmp') 10
        $extracted = New-Fixture (Join-Path $root 'extracted.tmp') 10
        [System.IO.File]::SetLastWriteTimeUtc($extracted, [DateTime]::UtcNow.AddDays(-30))
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root); minAgeHours = 24 })
        Test-Path -LiteralPath $old | Should -BeFalse
        Test-Path -LiteralPath $young | Should -BeTrue
        Test-Path -LiteralPath $extracted | Should -BeTrue
        $r.Scan.Count | Should -Be 1
    }
    It 'honours include and exclude patterns' {
        $root = New-TestFolder
        $thumb = New-Fixture (Join-Path $root 'thumbcache_256.db')
        $icon = New-Fixture (Join-Path $root 'iconcache_256.db')
        $other = New-Fixture (Join-Path $root 'notes.txt')
        $null = Invoke-TestClean (New-TestRule @{ roots = @($root); include = @('thumbcache_*.db', 'iconcache*'); exclude = @('iconcache*'); recurse = $false })
        Test-Path -LiteralPath $thumb | Should -BeFalse
        Test-Path -LiteralPath $icon | Should -BeTrue
        Test-Path -LiteralPath $other | Should -BeTrue
    }
    It 'keeps the newest files when keepNewest is set' {
        $root = New-TestFolder
        $files = foreach ($i in 1..5) { New-Fixture -Path (Join-Path $root "dump$i.dmp") -Bytes 10 -AgeHours (10 * $i) }
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root); keepNewest = 2 })
        $r.Scan.Count | Should -Be 3
        Test-Path -LiteralPath $files[0] | Should -BeTrue
        Test-Path -LiteralPath $files[1] | Should -BeTrue
        foreach ($f in $files[2..4]) { Test-Path -LiteralPath $f | Should -BeFalse }
    }
    It 'skips offline (cloud placeholder) files so cleaning never triggers a download' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'placeholder.bin')
        [System.IO.File]::SetAttributes($f, [System.IO.FileAttributes]::Offline)
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root) })
        Test-Path -LiteralPath $f | Should -BeTrue
        $r.Scan.Skipped.Keys | Should -Contain 'cloud placeholder or offline file (would trigger a download)'
    }
    It 'skips read-only files unless the rule allows system files' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'readonly.tmp')
        [System.IO.File]::SetAttributes($f, [System.IO.FileAttributes]::ReadOnly)
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root) })
        Test-Path -LiteralPath $f | Should -BeTrue
        $r.Clean.Skipped.Keys | Should -Contain 'read-only file'
        [System.IO.File]::SetAttributes($f, [System.IO.FileAttributes]::Normal)
    }
    It 'reports NotPresent when no root exists and GuidanceOnly for guidance rules' {
        $missing = Join-Path (New-TestFolder) 'nothing-here'
        (Invoke-TestScan (New-TestRule @{ roots = @($missing) })).Rules[0].Status | Should -Be 'NotPresent'
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'big.vhdx') 1000
        $r = Invoke-TestClean (New-TestRule @{ method = 'guidance'; roots = @($root); notes = 'Use the app.' })
        $r.Scan.Status | Should -Be 'GuidanceOnly'
        $r.Scan.Bytes | Should -Be 1000
        $r.Clean.Status | Should -Be 'Skipped'
        Test-Path -LiteralPath $f | Should -BeTrue
    }
    It 'reports RequiresAdmin for admin rules when not elevated' {
        Mock -ModuleName iGWindowsTuner Test-IgwtIsAdmin { $false }
        $root = New-TestFolder
        $null = New-Fixture (Join-Path $root 'x.tmp')
        (Invoke-TestScan (New-TestRule @{ roots = @($root); requiresAdmin = $true })).Rules[0].Status | Should -Be 'RequiresAdmin'
    }
    It 'never closes apps: a running blocker skips the rule' {
        Mock -ModuleName iGWindowsTuner Get-Process { [pscustomobject]@{ Name = 'igwtfixtureapp' } } -ParameterFilter { @($Name) -contains 'igwtfixtureapp' }
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'x.tmp')
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root); requiresClosed = @('igwtfixtureapp') })
        $r.Scan.Status | Should -Be 'RequiresClose'
        $r.Clean.Status | Should -Be 'Skipped'
        Test-Path -LiteralPath $f | Should -BeTrue
    }
    It 'refuses to clean without a scan' {
        InModuleScope iGWindowsTuner { $script:IgwtLastCleanerScan = $null }
        { Invoke-IgwtCleanerClean } | Should -Throw '*Run a scan first*'
    }
    It 'deletes nothing with -WhatIf' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'x.tmp')
        $scan = Invoke-TestScan (New-TestRule @{ roots = @($root) })
        $null = Invoke-IgwtCleanerClean -Scan $scan -WhatIf
        Test-Path -LiteralPath $f | Should -BeTrue
    }
    It 'stops between files when cancelled' {
        $root = New-TestFolder
        $f = New-Fixture (Join-Path $root 'x.tmp')
        $scan = Invoke-TestScan (New-TestRule @{ roots = @($root) })
        $cts = New-Object System.Threading.CancellationTokenSource
        $cts.Cancel()
        $null = Invoke-IgwtCleanerClean -Scan $scan -CancelToken $cts.Token
        Test-Path -LiteralPath $f | Should -BeTrue
        (Invoke-IgwtCleanerScan -RuleId 'clean.test.fixture' -CancelToken $cts.Token).Rules[0].Status | Should -Be 'Cancelled'
    }
}

Describe 'Reparse points and tampering' {
    It 'never follows a junction inside a root and never deletes the junction' {
        $base = New-TestFolder
        $root = Join-Path $base 'root'
        $outside = Join-Path $base 'outside'
        $precious = New-Fixture (Join-Path $outside 'precious.txt')
        $null = New-Fixture (Join-Path $root 'junk.tmp')
        $link = Join-Path $root 'link'
        $null = New-Item -ItemType Junction -Path $link -Value $outside
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root) })
        @($r.Scan.Items | Where-Object { $_.Path -like "$link*" }) | Should -BeNullOrEmpty
        $r.Scan.Count | Should -Be 1
        $r.Scan.Skipped.Keys | Should -Contain 'reparse point (not followed)'
        Test-Path -LiteralPath $precious | Should -BeTrue
        Test-Path -LiteralPath $link | Should -BeTrue
    }
    It 'never follows a directory symbolic link' {
        $base = New-TestFolder
        $root = Join-Path $base 'root'; $null = New-Item -ItemType Directory -Path $root
        $outside = Join-Path $base 'outside'
        $precious = New-Fixture (Join-Path $outside 'precious.txt')
        try { $null = New-Item -ItemType SymbolicLink -Path (Join-Path $root 'sym') -Value $outside -ErrorAction Stop }
        catch { Set-ItResult -Skipped -Because 'creating symbolic links needs Developer Mode or elevation'; return }
        $null = Invoke-TestClean (New-TestRule @{ roots = @($root) })
        Test-Path -LiteralPath $precious | Should -BeTrue
    }
    It 'refuses a delete when a folder was swapped for a junction after the scan' {
        $base = New-TestFolder
        $root = Join-Path $base 'root'
        $victim = New-Fixture (Join-Path $root 'sub\file.txt') 10
        $scan = Invoke-TestScan (New-TestRule @{ roots = @($root) })
        $ticks = $scan.Rules[0].Items[0].LastWriteTicks
        Remove-Item -LiteralPath (Join-Path $root 'sub') -Recurse -Force
        $outside = Join-Path $base 'outside'
        $precious = New-Fixture (Join-Path $outside 'file.txt') 10
        [System.IO.File]::SetLastWriteTimeUtc($precious, (New-Object DateTime($ticks, [DateTimeKind]::Utc)))
        $null = New-Item -ItemType Junction -Path (Join-Path $root 'sub') -Value $outside
        $c = (Invoke-IgwtCleanerClean -Scan $scan).Rules[0]
        Test-Path -LiteralPath $precious | Should -BeTrue
        $c.Skipped.Keys | Should -Contain 'a parent folder is (or became) a reparse point'
        Test-Path -LiteralPath $victim | Should -BeTrue
    }
    It 'refuses scan entries that were edited to point outside the rule' {
        $base = New-TestFolder
        $root = Join-Path $base 'root'
        $null = New-Fixture (Join-Path $root 'a.tmp')
        $precious = New-Fixture (Join-Path $base 'outside\precious.txt')
        $scan = Invoke-TestScan (New-TestRule @{ roots = @($root) })
        $item = $scan.Rules[0].Items[0]
        $item.Path = $precious; $item.Size = 16; $item.LastWriteTicks = (Get-Item -LiteralPath $precious).LastWriteTimeUtc.Ticks
        $c = (Invoke-IgwtCleanerClean -Scan $scan).Rules[0]
        Test-Path -LiteralPath $precious | Should -BeTrue
        $c.Skipped.Keys | Should -Contain 'outside the rule root'
        # Also widen the root and the scan's root list: the clean phase re-resolves the rule's roots.
        $item.Root = Join-Path $base 'outside'
        $scan.Rules[0].ResolvedRoots = @($item.Root)
        $c = (Invoke-IgwtCleanerClean -Scan $scan).Rules[0]
        Test-Path -LiteralPath $precious | Should -BeTrue
        $c.Skipped.Keys | Should -Contain 'root is not one of the rule roots'
    }
    It 'refuses paths that change under canonicalization (.. segments)' {
        $base = New-TestFolder
        $root = Join-Path $base 'root'; $null = New-Item -ItemType Directory -Path $root
        $precious = New-Fixture (Join-Path $base 'outside\precious.txt')
        $entry = [pscustomobject]@{ Path = "$root\..\outside\precious.txt"; Size = 16; LastWriteTicks = (Get-Item -LiteralPath $precious).LastWriteTimeUtc.Ticks; Root = $root }
        $rule = New-TestRule @{ roots = @($root) }
        $rule | Add-Member -NotePropertyName ResolvedRoots -NotePropertyValue @($root) -Force
        $o = InModuleScope iGWindowsTuner -Parameters @{ E = $entry; R = $rule } { param($E, $R) Remove-IgwtCleanerFile -Entry $E -Rule $R }
        $o.Result | Should -Be 'Refused'
        Test-Path -LiteralPath $precious | Should -BeTrue
    }
    It 'refuses anything outside the test root in TestMode' {
        $entry = [pscustomobject]@{ Path = "$env:SystemRoot\Temp\igwt-not-there.tmp"; Size = 0; LastWriteTicks = 0; Root = "$env:SystemRoot\Temp" }
        $rule = New-TestRule @{ roots = @("$env:SystemRoot\Temp") }
        $rule | Add-Member -NotePropertyName ResolvedRoots -NotePropertyValue @("$env:SystemRoot\Temp") -Force
        $o = InModuleScope iGWindowsTuner -Parameters @{ E = $entry; R = $rule } { param($E, $R) Remove-IgwtCleanerFile -Entry $E -Rule $R }
        $o.Result | Should -Be 'Refused'
        $o.Reason | Should -Match 'TestMode'
    }
    It 'refuses browser profile data that is not a cache folder' {
        $base = New-TestFolder
        $prof = Join-Path $base 'User Data\Default'
        $cookies = New-Fixture (Join-Path $prof 'Cookies')
        $cache = New-Fixture (Join-Path $prof 'Cache\Cache_Data\f_000001')
        $rule = New-TestRule @{ roots = @($prof) }
        $rule | Add-Member -NotePropertyName ResolvedRoots -NotePropertyValue @($prof) -Force
        foreach ($p in $cookies, $cache) {
            $fi = Get-Item -LiteralPath $p
            $e = [pscustomobject]@{ Path = $p; Size = $fi.Length; LastWriteTicks = $fi.LastWriteTimeUtc.Ticks; Root = $prof }
            $o = InModuleScope iGWindowsTuner -Parameters @{ E = $e; R = $rule } { param($E, $R) Remove-IgwtCleanerFile -Entry $E -Rule $R }
            if ($p -eq $cookies) { $o.Result | Should -Be 'Refused' } else { $o.Result | Should -Be 'Deleted' }
        }
        Test-Path -LiteralPath $cookies | Should -BeTrue
    }
    It 'cleans only cache folders of every Chromium profile' {
        $base = New-TestFolder
        $udr = Join-Path $base 'User Data'
        $keep = @((New-Fixture (Join-Path $udr 'Default\Cookies')), (New-Fixture (Join-Path $udr 'Default\History')), (New-Fixture (Join-Path $udr 'Local State')), (New-Fixture (Join-Path $udr 'Profile 2\Login Data')))
        $gone = @((New-Fixture (Join-Path $udr 'Default\Cache\Cache_Data\f_1')), (New-Fixture (Join-Path $udr 'Profile 2\Code Cache\js\a')), (New-Fixture (Join-Path $udr 'ShaderCache\data_0')))
        $notProfile = New-Fixture (Join-Path $udr 'Crashpad\Cache\x')
        $rule = New-TestRule @{ category = 'Browsers'; method = 'browserCache'; browser = 'chromium'; userDataRoots = @($udr); profileCacheDirs = @('Cache', 'Code Cache'); rootCacheDirs = @('ShaderCache'); requiresClosed = @('igwtfixturebrowser') }
        $null = Invoke-TestClean $rule
        foreach ($k in $keep) { Test-Path -LiteralPath $k | Should -BeTrue -Because $k }
        foreach ($g in $gone) { Test-Path -LiteralPath $g | Should -BeFalse -Because $g }
        Test-Path -LiteralPath $notProfile | Should -BeTrue
    }
    It 'refuses a rule root inside a redirected Downloads folder unless the rule is the opt-in Downloads rule' {
        $dl = New-TestFolder
        Set-TestShellFolder -Name '{374DE290-123F-4565-9164-39C4925E467B}' -Value $dl
        try {
            $f = New-Fixture -Path (Join-Path $dl 'setup.exe') -Bytes 10 -AgeHours 2000
            $r = Invoke-TestClean (New-TestRule @{ roots = @($dl) })
            $r.Scan.Status | Should -Be 'Refused'
            $r.Clean.Status | Should -Be 'Skipped'
            Test-Path -LiteralPath $f | Should -BeTrue
            Mock -ModuleName iGWindowsTuner Send-IgwtToRecycleBin { }
            $r = Invoke-TestClean (New-TestRule @{ category = 'Downloads'; roots = @($dl); allowDownloads = $true; recycle = $true; minAgeHours = 1440 })
            $r.Clean.DeletedCount | Should -Be 1
            Should -Invoke Send-IgwtToRecycleBin -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Path -eq $f }
            Test-Path -LiteralPath $f | Should -BeTrue -Because 'the Recycle Bin call is mocked, so a permanent delete would have removed it'
        } finally {
            Remove-ItemProperty -LiteralPath 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}'
            InModuleScope iGWindowsTuner { $script:IgwtCleanerProtection = $null }
        }
    }
}

Describe 'Services and special methods' {
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = $Name[0]; Status = 'Running' } }
        Mock -ModuleName iGWindowsTuner Stop-Service { }
        Mock -ModuleName iGWindowsTuner Start-Service { }
    }
    It 'restarts stopped services even when cleaning throws' {
        $root = New-TestFolder
        $null = New-Fixture (Join-Path $root 'x.tmp')
        Mock -ModuleName iGWindowsTuner Remove-IgwtCleanerFile { throw 'simulated failure' }
        $r = Invoke-TestClean (New-TestRule @{ roots = @($root); services = @('igwtfixturesvc') })
        $r.Clean.Status | Should -Be 'Error'
        Should -Invoke Stop-Service -ModuleName iGWindowsTuner -Times 1 -Exactly
        Should -Invoke Start-Service -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $Name[0] -eq 'igwtfixturesvc' }
    }
    It 'does not start services that were not running before' {
        Mock -ModuleName iGWindowsTuner Get-Service { [pscustomobject]@{ Name = $Name[0]; Status = 'Stopped' } }
        $root = New-TestFolder
        $null = New-Fixture (Join-Path $root 'x.tmp')
        $null = Invoke-TestClean (New-TestRule @{ roots = @($root); services = @('igwtfixturesvc') })
        Should -Invoke Stop-Service -ModuleName iGWindowsTuner -Times 0 -Exactly
        Should -Invoke Start-Service -ModuleName iGWindowsTuner -Times 0 -Exactly
    }
    It 'empties only Recycle Bins that hold data' {
        Mock -ModuleName iGWindowsTuner Get-IgwtRecycleBinUsage { @([pscustomobject]@{ Drive = 'C'; Bytes = 500; Items = 2 }, [pscustomobject]@{ Drive = 'D'; Bytes = 0; Items = 0 }) }
        Mock -ModuleName iGWindowsTuner Clear-RecycleBin { }
        $r = Invoke-TestClean (New-TestRule @{ method = 'recycleBin' })
        $r.Scan.Bytes | Should -Be 500
        $r.Clean.DeletedBytes | Should -Be 500
        Should -Invoke Clear-RecycleBin -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $DriveLetter[0] -eq 'C' }
    }
    It 'uses the Delivery Optimization cmdlets' {
        Mock -ModuleName iGWindowsTuner Get-DeliveryOptimizationPerfSnap { [pscustomobject]@{ CacheSizeBytes = 4096 } }
        Mock -ModuleName iGWindowsTuner Delete-DeliveryOptimizationCache { }
        $r = Invoke-TestClean (New-TestRule @{ method = 'deliveryOptimization'; requiresAdmin = $true })
        $r.Scan.Bytes | Should -Be 4096
        Should -Invoke Delete-DeliveryOptimizationCache -ModuleName iGWindowsTuner -Times 1 -Exactly
    }
    It 'runs DISM component cleanup through Repair-WindowsImage (ResetBase only for the Expert rule)' {
        Mock -ModuleName iGWindowsTuner Test-IgwtIsAdmin { $true }
        Mock -ModuleName iGWindowsTuner Get-IgwtComponentStoreAnalysis { [pscustomobject]@{ Bytes = 1GB; Recommended = $true; Packages = 3 } }
        Mock -ModuleName iGWindowsTuner Repair-WindowsImage { }
        $r = Invoke-TestClean (New-TestRule @{ method = 'dism'; requiresAdmin = $true })
        $r.Scan.Bytes | Should -Be 1GB
        Should -Invoke Repair-WindowsImage -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $StartComponentCleanup -and -not $ResetBase }
        $null = Invoke-TestClean (New-TestRule @{ id = 'clean.test.resetbase'; method = 'dism'; requiresAdmin = $true; resetBase = $true; level = 'Expert' })
        Should -Invoke Repair-WindowsImage -ModuleName iGWindowsTuner -Times 1 -Exactly -ParameterFilter { $ResetBase }
    }
    It 'parses the DISM component store report' {
        $text = "Component Store (WinSxS) information:`r`n`r`nWindows Explorer Reported Size of Component Store : 7.12 GB`r`n`r`nBackups and Disabled Features : 1.50 GB`r`n`r`nNumber of Reclaimable Packages : 4`r`nComponent Store Cleanup Recommended : Yes"
        $r = InModuleScope iGWindowsTuner -Parameters @{ T = $text } { param($T) ConvertFrom-IgwtComponentStoreReport -Text $T }
        $r.Bytes | Should -Be ([long](1.5 * 1GB))
        $r.Packages | Should -Be 4
        $r.Recommended | Should -BeTrue
        InModuleScope iGWindowsTuner { ConvertFrom-IgwtSizeText '512.00 MB' } | Should -Be 512MB
    }
    It 'never runs dism.exe or pnputil.exe unmocked in TestMode' {
        { InModuleScope iGWindowsTuner { Get-IgwtComponentStoreAnalysis } } | Should -Throw '*TestMode*'
        { InModuleScope iGWindowsTuner { Invoke-IgwtPnpUtilDelete -Inf 'oem12.inf' } } | Should -Throw '*TestMode*'
        { InModuleScope iGWindowsTuner { Invoke-IgwtPnpUtilDelete -Inf 'oem12.inf /force' } } | Should -Throw '*Refusing*'
    }
    It 'offers only older, unused third-party driver packages' {
        $ds = New-TestFolder
        foreach ($d in 'a1', 'a2', 'b1', 'b2', 'c1') { $null = New-Fixture (Join-Path $ds "$d\pkg.cat") 100 }
        Mock -ModuleName iGWindowsTuner Get-WindowsDriver {
            @(
                [pscustomobject]@{ Driver = 'oem10.inf'; OriginalFileName = "$ds\a1\gpu.inf"; ProviderName = 'Vendor'; ClassName = 'Display'; Version = '1.0.0.0'; Date = [datetime]'2024-01-01'; Inbox = $false }
                [pscustomobject]@{ Driver = 'oem11.inf'; OriginalFileName = "$ds\a2\gpu.inf"; ProviderName = 'Vendor'; ClassName = 'Display'; Version = '2.0.0.0'; Date = [datetime]'2025-01-01'; Inbox = $false }
                [pscustomobject]@{ Driver = 'oem12.inf'; OriginalFileName = "$ds\b1\net.inf"; ProviderName = 'Vendor'; ClassName = 'Net'; Version = '1.0.0.0'; Date = [datetime]'2024-01-01'; Inbox = $false }
                [pscustomobject]@{ Driver = 'oem13.inf'; OriginalFileName = "$ds\b2\net.inf"; ProviderName = 'Vendor'; ClassName = 'Net'; Version = '2.0.0.0'; Date = [datetime]'2025-01-01'; Inbox = $false }
                [pscustomobject]@{ Driver = 'oem14.inf'; OriginalFileName = "$ds\c1\solo.inf"; ProviderName = 'Vendor'; ClassName = 'USB'; Version = '1.0.0.0'; Date = [datetime]'2024-01-01'; Inbox = $false }
            )
        }
        Mock -ModuleName iGWindowsTuner Get-PnpDevice { @([pscustomobject]@{ InstanceId = 'PCI\NET1' }, [pscustomobject]@{ InstanceId = 'PCI\GPU1' }) }
        Mock -ModuleName iGWindowsTuner Get-PnpDeviceProperty {
            if ($InstanceId[0] -eq 'PCI\NET1') { [pscustomobject]@{ Data = 'oem12.inf' } } else { [pscustomobject]@{ Data = 'oem11.inf' } }
        }
        $c = @(InModuleScope iGWindowsTuner { Get-IgwtDriverStoreCandidates })
        @($c.Inf) | Should -Be @('oem10.inf')
        $c[0].Newer | Should -Be '2.0.0.0'
        $c[0].Bytes | Should -Be 100
    }
}

Describe 'Deletion log rotation' {
    It 'keeps the ten newest logs and archives the rest' {
        $dir = New-TestFolder
        foreach ($i in 1..12) { Set-Content -LiteralPath (Join-Path $dir ('Cleaner-202601{0:D2}-000000-000.jsonl' -f $i)) -Value '{}' }
        InModuleScope iGWindowsTuner -Parameters @{ D = $dir } { param($D) Invoke-IgwtCleanerLogRotation -Folder $D }
        @(Get-ChildItem -LiteralPath $dir -Filter 'Cleaner-*.jsonl').Count | Should -Be 10
        @(Get-ChildItem -LiteralPath $dir -Filter 'Cleaner-archive-*.zip').Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $dir 'Cleaner-20260101-000000-000.jsonl') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $dir 'Cleaner-20260102-000000-000.jsonl') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $dir 'Cleaner-20260112-000000-000.jsonl') | Should -BeTrue
    }
}

Describe 'Storage Sense tweaks' {
    BeforeAll {
        $script:StorageTweaks = @(Get-IgwtCatalog -Force | Where-Object { $_.category -eq 'Storage' })
        $script:SsKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense'
    }
    It 'ships the Storage Sense items in the Storage category' {
        @($script:StorageTweaks.id) | Should -Be @('storage.storage-sense-weekly', 'storage.recycle-bin-30-days', 'storage.downloads-60-days')
    }
    It 'uses only the documented Storage Sense policy values with Windows default absent' {
        $allowed = @('AllowStorageSenseGlobal', 'ConfigStorageSenseGlobalCadence', 'AllowStorageSenseTemporaryFilesCleanup', 'ConfigStorageSenseRecycleBinCleanupThreshold', 'ConfigStorageSenseDownloadsCleanupThreshold')
        foreach ($t in $script:StorageTweaks) {
            foreach ($a in @($t.actions)) {
                $a.type | Should -Be 'storageSense'
                foreach ($part in @(InModuleScope iGWindowsTuner -Parameters @{ A = $a } { param($A) Get-IgwtCompositeParts -Action $A })) {
                    $part.Action.path | Should -Be $script:SsKey
                    $part.Action.name | Should -BeIn $allowed
                    $part.Action.default | Should -Be '<absent>'
                }
            }
        }
    }
    It 'keeps the Downloads threshold an expert toggle outside every preset' {
        $d = $script:StorageTweaks | Where-Object { $_.id -eq 'storage.downloads-60-days' }
        $d.expert | Should -BeTrue
        $d.warning | Should -Not -BeNullOrEmpty
        foreach ($p in @(Get-IgwtPreset)) { @($p.tweaks) | Should -Not -Contain 'storage.downloads-60-days' }
    }
    It 'applies and reverts Storage Sense in TestRegistry' {
        $ctx = New-IgwtTestContext
        $r = Invoke-IgwtApply -Id 'storage.storage-sense-weekly' -Context $ctx
        @($r.Results | Where-Object Result -EQ 'Applied').Count | Should -Be 1
        $v = InModuleScope iGWindowsTuner -Parameters @{ P = $script:SsKey } { param($P) Get-IgwtRegistryValue -Path $P -Name 'ConfigStorageSenseGlobalCadence' }
        $v.Value | Should -Be 7
        (Get-IgwtAllTweakStates -Id 'storage.storage-sense-weekly' -Context $ctx).State | Should -Be 'On'
        $null = Invoke-IgwtRevert -Id 'storage.storage-sense-weekly' -Context $ctx
        $v = InModuleScope iGWindowsTuner -Parameters @{ P = $script:SsKey } { param($P) Get-IgwtRegistryValue -Path $P -Name 'AllowStorageSenseGlobal' }
        $v.Exists | Should -BeFalse
    }
}

Describe 'Disk analyzer' {
    It 'finds the largest folders and files without following junctions' {
        $root = New-TestFolder
        $null = New-Fixture (Join-Path $root 'big\one.bin') 1000
        $null = New-Fixture (Join-Path $root 'big\sub\two.bin') 2000
        $null = New-Fixture (Join-Path $root 'small\three.bin') 10
        $null = New-Fixture (Join-Path $root 'top.bin') 5
        $outside = New-TestFolder
        $null = New-Fixture (Join-Path $outside 'huge.bin') 50000
        $null = New-Item -ItemType Junction -Path (Join-Path $root 'link') -Value $outside
        $u = Get-IgwtDiskUsage -Path $root -Top 10 -FolderDepth 2
        $u.TotalBytes | Should -Be 3015
        $u.Files | Should -Be 4
        $u.ReparseSkipped | Should -Be 1
        $u.Folders[0].Path | Should -Be (Join-Path $root 'big')
        $u.Folders[0].Bytes | Should -Be 3000
        ($u.Folders | Where-Object { $_.Path -eq (Join-Path $root 'big\sub') }).Bytes | Should -Be 2000
        $u.LargestFiles[0].Path | Should -Be (Join-Path $root 'big\sub\two.bin')
        Test-Path -LiteralPath (Join-Path $outside 'huge.bin') | Should -BeTrue
    }
    It 'formats sizes' {
        Format-IgwtBytes 512 | Should -Be '512 B'
        Format-IgwtBytes 2048 | Should -Be '2 KB'
        Format-IgwtBytes (5GB) | Should -Match '^5[\.,]00 GB$'
    }
}
