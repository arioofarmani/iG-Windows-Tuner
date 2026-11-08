# Registry Analyzer & Cleaner (3.8): data, protected set and (later steps) scan rules.
# Headless and read-only: the catalog context only reads data\registry\*.json and synthetic copies.

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
