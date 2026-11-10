# Registry Analyzer & Cleaner (3.8): exact snapshots, the .reg / firewall-rules.json / manifest.json
# builders and the private backup folder (DECISIONS RG17, RG18). Headless and non-elevated:
# TestRegistry keys under a fake SID, mocks for failures, and TestDrive for the backup folder. Later
# steps add the provider (Get/Set/Restore) contexts to this file.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Sid = 'S-1-5-21-1-2-3-1001'
    $script:Fixture = Join-Path $PSScriptRoot 'fixtures\registry\selected.reg.txt'
    function Invoke-InIgwt([scriptblock]$Block, [object[]]$ArgumentList = @()) { return (& (Get-Module iGWindowsTuner) $Block @ArgumentList) }
    function Get-RawTestKey([string]$TestRegistryPath) {
        # A writable .NET handle on a TestRegistry key (the test builds its fixture with it; src never writes here).
        $name = (Get-Item -LiteralPath $TestRegistryPath).Name
        $sub = $name.Substring($name.IndexOf('\') + 1)
        return [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub, $true)
    }
    function New-ContosoTree {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixture in TestRegistry/TestDrive only.')]
        param()
        $root = "TestRegistry:\HKU\$($script:Sid)\Software\Contoso\App"
        foreach ($k in 'a', 'a\c', 'b', 'a b') { $null = New-Item -Path (Join-Path $root $k) -Force }
        $key = Get-RawTestKey $root
        try {
            $key.SetValue('', 'Contoso App', [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('Path', '%ProgramFiles%\Contoso\app.app', [Microsoft.Win32.RegistryValueKind]::ExpandString)
            $key.SetValue('List', [string[]]@('one', '', 'three'), [Microsoft.Win32.RegistryValueKind]::MultiString)
            $key.SetValue('Flags', [int32]-1, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.SetValue('Big', [int64]::MaxValue, [Microsoft.Win32.RegistryValueKind]::QWord)
            $key.SetValue('Blob', [byte[]]@(0, 1, 254, 255), [Microsoft.Win32.RegistryValueKind]::Binary)
            $key.SetValue('Marker', [byte[]]@(7, 8), [Microsoft.Win32.RegistryValueKind]::None)
            $key.SetValue('Empty', [byte[]]@(), [Microsoft.Win32.RegistryValueKind]::Binary)
        } finally { $key.Dispose() }
        $c = Get-RawTestKey (Join-Path $root 'a\c')
        try { $c.SetValue('Note', 'Say "hi" \ bye', [Microsoft.Win32.RegistryValueKind]::String) } finally { $c.Dispose() }
        return $root
    }
}

Describe 'Registry cleaner snapshots (RG17)' {
    BeforeEach {
        Remove-Item -LiteralPath "TestRegistry:\HKU\$($script:Sid)" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE' -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context 'key tree snapshot' {
        It 'returns the compared shape with every kind, ordinal key order and the value text' {
            $null = New-ContosoTree
            $s = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -View 64 -Path 'Software\Contoso\App' } $script:Sid
            $s | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
            @($s.PSBase.Keys) | Should -Be @('exists', 'kind', 'value', 'hive', 'sid', 'view', 'path', 'keyList', 'valueList', 'valueCount')
            $s.exists | Should -BeTrue
            $s.kind | Should -Be 'keyTree'
            $s.hive | Should -Be 'HKCU'
            $s.sid | Should -Be $script:Sid
            $s.path | Should -Be 'Software\Contoso\App'
            @($s.keyList) | Should -Be @('', 'a', 'a b', 'a\c', 'b')
            $s.valueCount | Should -Be 9
            $s.value | Should -Be '5 keys, 9 values'
            $byName = @{}; foreach ($v in $s.valueList) { $byName[$v.name] = $v }
            @($s.valueList | ForEach-Object { $_.name }) | Should -Be @('', 'Big', 'Blob', 'Empty', 'Flags', 'List', 'Marker', 'Path', 'Note')
            @($s.valueList[0].Keys) | Should -Be @('key', 'name', 'kind', 'data')
            $byName[''].data | Should -Be 'Contoso App'
            $byName['Path'].kind | Should -Be 'ExpandString'
            $byName['Path'].data | Should -Be '%ProgramFiles%\Contoso\app.app'
            $byName['List'].kind | Should -Be 'MultiString'
            , $byName['List'].data | Should -BeOfType [string[]]
            $byName['List'].data | Should -Be @('one', '', 'three')
            $byName['Flags'].data | Should -Be 4294967295
            $byName['Big'].data | Should -Be '9223372036854775807'
            $byName['Blob'].data | Should -Be '0001FEFF'
            $byName['Marker'].kind | Should -Be 'None'
            $byName['Marker'].data | Should -Be '0708'
            $byName['Empty'].data | Should -Be ''
            $byName['Note'].key | Should -Be 'a\c'
            $s.Contains('owner') | Should -BeFalse
            $s.Contains('sddl') | Should -BeFalse
        }

        It 'is deterministic and survives a JSON round trip unchanged' {
            $null = New-ContosoTree
            $a = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $b = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $ja = Invoke-InIgwt { param($x) ConvertTo-IgwtCanonicalJson $x } $a
            $jb = Invoke-InIgwt { param($x) ConvertTo-IgwtCanonicalJson $x } $b
            $jb | Should -BeExactly $ja
            $text = Invoke-InIgwt { param($x) ConvertTo-IgwtJson -InputObject $x } $a
            $back = $text | ConvertFrom-Json
            (Invoke-InIgwt { param($x) ConvertTo-IgwtJson -InputObject $x } $back) | Should -BeExactly $text
            @($back.valueList | Where-Object { $_.name -eq 'List' })[0].data | Should -Be @('one', '', 'three')
        }

        It 'gives exists false and empty lists for a missing key' {
            $s = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Nobody' } $script:Sid
            $s.exists | Should -BeFalse
            @($s.keyList).Count | Should -Be 0
            @($s.valueList).Count | Should -Be 0
            $s.valueCount | Should -Be 0
        }

        It 'reads the 32-bit view of HKLM from WOW6432Node (TestMode) and keeps the logical path' {
            $null = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\WOW6432Node\Fabrikam\Tool' -Force
            $null = New-ItemProperty -Path 'TestRegistry:\HKLM\SOFTWARE\WOW6432Node\Fabrikam\Tool' -Name 'Version' -Value '1.0' -PropertyType String
            $s = Invoke-InIgwt { Get-IgwtRegCleanKeySnapshot -Hive HKLM -Sid 'S-1-5-21-9' -View 32 -Path 'SOFTWARE\Fabrikam\Tool' }
            $s.exists | Should -BeTrue
            $s.path | Should -Be 'SOFTWARE\Fabrikam\Tool'
            $s.view | Should -Be '32'
            $s.sid | Should -Be ''
            $s.valueList[0].data | Should -Be '1.0'
        }

        It 'throws on a deny-listed subkey name (RG32)' {
            $root = New-ContosoTree
            $deny = @((Get-Content -Raw (Join-Path $script:IgwtProjectRoot 'data\registry\categories.json') | ConvertFrom-Json).denyList.segmentNames)[0]
            $null = New-Item -Path (Join-Path $root "b\$deny") -Force
            { Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid } | Should -Throw '*shared or linked key*'
        }

        It 'throws for more than 2,000 values' {
            $null = New-Item -Path "TestRegistry:\HKU\$($script:Sid)\Software\Contoso\Many" -Force
            $key = Get-RawTestKey "TestRegistry:\HKU\$($script:Sid)\Software\Contoso\Many"
            try { for ($i = 0; $i -le 2000; $i++) { $key.SetValue("v$i", $i, [Microsoft.Win32.RegistryValueKind]::DWord) } } finally { $key.Dispose() }
            { Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\Many' } $script:Sid } | Should -Throw '*more than 2,000 values or 512 KB*'
        }

        It 'throws for more than 512 KB of data' {
            $null = New-Item -Path "TestRegistry:\HKU\$($script:Sid)\Software\Contoso\Large" -Force
            $key = Get-RawTestKey "TestRegistry:\HKU\$($script:Sid)\Software\Contoso\Large"
            try { $key.SetValue('blob', (New-Object byte[] 524289), [Microsoft.Win32.RegistryValueKind]::Binary) } finally { $key.Dispose() }
            { Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\Large' } $script:Sid } | Should -Throw '*more than 2,000 values or 512 KB*'
        }

        It 'throws for a value of an Unknown kind' {
            Mock Read-IgwtRegCleanKey -ModuleName iGWindowsTuner { [pscustomobject]@{ SubKeys = @(); Values = @{ link = [byte[]]@(1) }; Kinds = @{ link = 'Unknown' } } }
            { Invoke-InIgwt { Get-IgwtRegCleanKeySnapshot -Hive HKLM -Path 'SOFTWARE\Contoso' } } | Should -Throw "*kind 'Unknown' cannot be restored*"
        }

        It 'throws when a subkey cannot be opened, and when it disappears while read' {
            Mock Read-IgwtRegCleanKey -ModuleName iGWindowsTuner {
                if ($Path -eq 'SOFTWARE\Contoso') { return [pscustomobject]@{ SubKeys = @('locked'); Values = @{}; Kinds = @{} } }
                throw 'Requested registry access is not allowed.'
            }
            { Invoke-InIgwt { Get-IgwtRegCleanKeySnapshot -Hive HKLM -Path 'SOFTWARE\Contoso' } } | Should -Throw "*subkey 'locked' cannot be opened*"
            Mock Read-IgwtRegCleanKey -ModuleName iGWindowsTuner {
                if ($Path -eq 'SOFTWARE\Contoso') { return [pscustomobject]@{ SubKeys = @('gone'); Values = @{}; Kinds = @{} } }
                return $null
            }
            { Invoke-InIgwt { Get-IgwtRegCleanKeySnapshot -Hive HKLM -Path 'SOFTWARE\Contoso' } } | Should -Throw "*subkey 'gone' cannot be opened*"
        }

        It 'throws for more than 2,000 keys' {
            Mock Read-IgwtRegCleanKey -ModuleName iGWindowsTuner {
                if ($Path -eq 'SOFTWARE\Contoso') { return [pscustomobject]@{ SubKeys = @(1..2001 | ForEach-Object { "k$_" }); Values = @{}; Kinds = @{} } }
                return [pscustomobject]@{ SubKeys = @(); Values = @{}; Kinds = @{} }
            }
            { Invoke-InIgwt { Get-IgwtRegCleanKeySnapshot -Hive HKLM -Path 'SOFTWARE\Contoso' } } | Should -Throw '*more than 2,000 keys*'
        }

        It 'needs the SID for HKCU' {
            { Invoke-InIgwt { Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid '' -Path 'Software\Contoso' } } | Should -Throw '*SID*'
        }
    }

    Context 'key permissions (information only)' {
        It 'returns owner, SDDL, aclProtected and explicitAceCount per key of the snapshot' {
            $null = New-ContosoTree
            $s = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $rows = @(Invoke-InIgwt { param($x) Get-IgwtRegCleanTreeSecurity -Snapshot $x } $s)
            $rows.Count | Should -Be 5
            @($rows | ForEach-Object { $_.key }) | Should -Be @('', 'a', 'a b', 'a\c', 'b')
            @($rows[0].Keys) | Should -Be @('key', 'owner', 'sddl', 'aclProtected', 'explicitAceCount')
            $rows[0].owner | Should -Match '^S-1-'
            $rows[0].sddl | Should -Match '^O:'
            $rows[0].explicitAceCount | Should -BeOfType [int]
        }

        It 'counts explicit ACEs and throws when a key vanished' {
            Mock Get-IgwtRegCleanKeySecurity -ModuleName iGWindowsTuner {
                if ($Path -like '*\gone') { return $null }
                [pscustomobject]@{ Owner = 'S-1-5-18'; Writers = @(); AclProtected = $false; HasExplicitAce = $true; ExplicitAceCount = 2; Sddl = 'O:SYD:' }
            }
            $snap = [ordered]@{ exists = $true; kind = 'keyTree'; hive = 'HKLM'; sid = ''; view = '64'; path = 'SOFTWARE\Contoso'; keyList = @('') }
            $rows = @(Invoke-InIgwt { param($x) Get-IgwtRegCleanTreeSecurity -Snapshot $x } $snap)
            $rows[0].explicitAceCount | Should -Be 2
            $rows[0].owner | Should -Be 'S-1-5-18'
            $snap.keyList = @('', 'gone')
            { Invoke-InIgwt { param($x) Get-IgwtRegCleanTreeSecurity -Snapshot $x } $snap } | Should -Throw '*no longer exists*'
            $snap.exists = $false
            @(Invoke-InIgwt { param($x) Get-IgwtRegCleanTreeSecurity -Snapshot $x } $snap).Count | Should -Be 0
        }

        It 'reports the explicit ACE count from Get-IgwtRegCleanKeySecurity' {
            $null = New-ContosoTree
            $sec = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySecurity -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $sec.PSObject.Properties.Name | Should -Contain 'ExplicitAceCount'
            ($sec.ExplicitAceCount -gt 0) | Should -Be ([bool]$sec.HasExplicitAce)
        }
    }

    Context 'value snapshot' {
        It 'is the Get-IgwtRegistryValue shape plus view and sid' {
            $null = New-ContosoTree
            $v = Invoke-InIgwt { param($sid) Get-IgwtRegCleanValueSnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Name 'path' } $script:Sid
            @($v.Keys) | Should -Be @('exists', 'kind', 'value', 'view', 'sid', 'hive', 'path', 'name')
            $v.exists | Should -BeTrue
            $v.kind | Should -Be 'ExpandString'
            $v.value | Should -Be '%ProgramFiles%\Contoso\app.app'
            $v.name | Should -Be 'Path'
            $v.sid | Should -Be $script:Sid
            $m = Invoke-InIgwt { param($sid) Get-IgwtRegCleanValueSnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Name 'Nope' } $script:Sid
            $m.exists | Should -BeFalse
            $m.kind | Should -BeNullOrEmpty
            $k = Invoke-InIgwt { Get-IgwtRegCleanValueSnapshot -Hive HKLM -Path 'SOFTWARE\Nobody' -Name 'x' }
            $k.exists | Should -BeFalse
            $k.sid | Should -Be ''
        }

        It 'throws for a value of an Unknown kind' {
            Mock Read-IgwtRegCleanKey -ModuleName iGWindowsTuner { [pscustomobject]@{ SubKeys = @(); Values = @{ link = [byte[]]@(1) }; Kinds = @{ link = 'Unknown' } } }
            { Invoke-InIgwt { Get-IgwtRegCleanValueSnapshot -Hive HKLM -Path 'SOFTWARE\Contoso' -Name 'link' } } | Should -Throw '*cannot be restored*'
        }
    }
}

Describe 'Registry cleaner .reg writer (RG18)' {
    BeforeAll {
        $script:GoldenSnapshots = @(
            [ordered]@{
                exists = $true; kind = 'keyTree'; value = '3 keys, 9 values'; hive = 'HKCU'; sid = $script:Sid; view = '64'; path = 'Software\Contoso\App'
                keyList = @('', 'Sub', 'Sub\Deep')
                valueList = @(
                    [ordered]@{ key = ''; name = ''; kind = 'String'; data = 'Contoso App' }
                    [ordered]@{ key = ''; name = 'Quote"Name'; kind = 'String'; data = 'C:\Program Files\Contoso\app.app "%1"' }
                    [ordered]@{ key = ''; name = 'Flags'; kind = 'DWord'; data = 4294967295 }
                    [ordered]@{ key = ''; name = 'Big'; kind = 'QWord'; data = '81985529216486895' }
                    [ordered]@{ key = ''; name = 'Blob'; kind = 'Binary'; data = '0001FEFF' }
                    [ordered]@{ key = ''; name = 'Marker'; kind = 'None'; data = '0708' }
                    [ordered]@{ key = 'Sub'; name = 'Path'; kind = 'ExpandString'; data = '%ProgramFiles%\C' }
                    [ordered]@{ key = 'Sub'; name = 'List'; kind = 'MultiString'; data = @('a', '', 'b') }
                    [ordered]@{ key = 'Sub\Deep'; name = 'Long'; kind = 'Binary'; data = ('00' * 40) }
                )
                valueCount = 9
            }
            [ordered]@{ exists = $true; kind = 'String'; value = 'C:\Fabrikam\tool.app'; view = '32'; sid = ''; hive = 'HKLM'; path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\tool.app'; name = '' }
            [ordered]@{ exists = $false; kind = $null; value = $null; view = '64'; sid = ''; hive = 'HKLM'; path = 'SOFTWARE\Gone'; name = 'x' }
            [ordered]@{ exists = $true; kind = 'DWord'; value = 1; view = '64'; sid = ''; hive = 'HKLM'; path = 'SYSTEM\CurrentControlSet\Services\contoso'; name = 'Start' }
        )
    }

    It 'matches the golden selected.reg text (HKEY_USERS form, WOW6432Node, every kind, wrapping)' {
        $text = Invoke-InIgwt { param($s) ConvertTo-IgwtRegFileText -Snapshots $s } (, $script:GoldenSnapshots)
        $text | Should -BeExactly ([IO.File]::ReadAllText($script:Fixture))
        $text | Should -Not -Match '(?<!\r)\n'
        $text | Should -Not -Match 'HKEY_CURRENT_USER'
        $text | Should -Not -Match 'SOFTWARE\\Gone'
    }

    It 'gives the same text for snapshots read back from JSON' {
        $json = Invoke-InIgwt { param($s) ConvertTo-IgwtJson -InputObject $s } (, $script:GoldenSnapshots)
        $back = @($json | ConvertFrom-Json | ForEach-Object { $_ })
        $text = Invoke-InIgwt { param($s) ConvertTo-IgwtRegFileText -Snapshots $s } (, $back)
        $text | Should -BeExactly ([IO.File]::ReadAllText($script:Fixture))
    }

    It 'writes every kind in the documented form' {
        $line = { param($n, $k, $d) Invoke-InIgwt { param($a, $b, $c) ConvertTo-IgwtRegFileValueLine -Name $a -Kind $b -Data $c } @($n, $k, $d) }
        & $line 'a' 'String' 'x\y"z' | Should -BeExactly '"a"="x\\y\"z"'
        & $line '' 'String' '' | Should -BeExactly '@=""'
        & $line 'd' 'DWord' 10 | Should -BeExactly '"d"=dword:0000000a'
        & $line 'q' 'QWord' '1' | Should -BeExactly '"q"=hex(b):01,00,00,00,00,00,00,00'
        & $line 'b' 'Binary' '' | Should -BeExactly '"b"=hex:'
        & $line 'n' 'None' '' | Should -BeExactly '"n"=hex(0):'
        & $line 'e' 'ExpandString' 'A' | Should -BeExactly '"e"=hex(2):41,00,00,00'
        & $line 'm' 'MultiString' @() | Should -BeExactly '"m"=hex(7):00,00'
        & $line 'm' 'MultiString' @('A') | Should -BeExactly '"m"=hex(7):41,00,00,00,00,00'
        & $line 's' 'String' "a`r`nb" | Should -BeExactly '"s"=hex(1):61,00,0d,00,0a,00,62,00,00,00'
        & $line 'u' 'String' ([string][char]0x00E9) | Should -BeExactly ('"u"="' + [char]0x00E9 + '"')
        { & $line "bad`nname" 'String' 'x' } | Should -Throw '*cannot be written*'
        { & $line 'x' 'Unknown' '00' } | Should -Throw '*cannot be written*'
    }

    It 'names keys by hive, view and SID' {
        $kn = { param($h, $s, $v, $p) Invoke-InIgwt { param($a, $b, $c, $d) ConvertTo-IgwtRegFileKeyName -Hive $a -Sid $b -View $c -Path $d } @($h, $s, $v, $p) }
        & $kn 'HKLM' '' '32' 'SOFTWARE\Contoso' | Should -Be 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Contoso'
        & $kn 'HKLM' '' '32' 'SOFTWARE\WOW6432Node\Contoso' | Should -Be 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Contoso'
        & $kn 'HKLM' '' '64' 'SOFTWARE\Contoso' | Should -Be 'HKEY_LOCAL_MACHINE\SOFTWARE\Contoso'
        & $kn 'HKLM' '' '32' 'SYSTEM\Contoso' | Should -Be 'HKEY_LOCAL_MACHINE\SYSTEM\Contoso'
        & $kn 'HKCU' $script:Sid '64' 'Software\Contoso' | Should -Be "HKEY_USERS\$($script:Sid)\Software\Contoso"
        { & $kn 'HKCU' '' '64' 'Software\Contoso' } | Should -Throw '*SID*'
    }

    It 'writes a live snapshot that the header and blocks describe completely' {
        Remove-Item -LiteralPath "TestRegistry:\HKU\$($script:Sid)" -Recurse -Force -ErrorAction SilentlyContinue
        $null = New-ContosoTree
        $s = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
        $text = Invoke-InIgwt { param($x) ConvertTo-IgwtRegFileText -Snapshots @($x) } $s
        $text | Should -BeLike 'Windows Registry Editor Version 5.00*'
        ([regex]::Matches($text, '(?m)^\[HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Contoso\\App')).Count | Should -Be 5
        $text | Should -Match '"Flags"=dword:ffffffff'
        $text | Should -Match '"Note"="Say \\"hi\\" \\\\ bye"'
    }
}

Describe 'Registry cleaner backup files (RG18)' {
    It 'builds firewall-rules.json from Get-IgwtFirewallRuleDefinition rows' {
        $d = [ordered]@{ name = '{AAAA}'; displayName = 'Contoso'; program = 'C:\Contoso\app.app'; localPort = @() }
        $text = Invoke-InIgwt { param($x) ConvertTo-IgwtRegCleanFirewallRulesJson -Definitions @($x) } $d
        $doc = $text | ConvertFrom-Json
        $doc.schemaVersion | Should -Be 1
        $doc.rules[0].name | Should -Be '{AAAA}'
        $doc.rules[0].program | Should -Be 'C:\Contoso\app.app'
        $text | Should -Not -Match '(?<!\r)\n'
        { Invoke-InIgwt { ConvertTo-IgwtRegCleanFirewallRulesJson -Definitions @([ordered]@{ name = '' }) } } | Should -Throw '*rule name*'
        (Invoke-InIgwt { ConvertTo-IgwtRegCleanFirewallRulesJson -Definitions @() } | ConvertFrom-Json).rules.Count | Should -Be 0
    }

    It 'builds manifest.json with files, targets, includes, firewall snapshot paths and key security' {
        $t = @(
            [pscustomobject]@{ Id = 'aaaa'; Category = 'uninstall'; Kind = 'regKeyTree'; Hive = 'HKCU'; Sid = $script:Sid; View = '64'; Path = 'Software\X'; ValueName = ''; RuleName = ''; Includes = @('bbbb') }
            [pscustomobject]@{ Id = 'cccc'; Category = 'firewallRule'; Kind = 'firewallRule'; Hive = ''; Sid = ''; View = ''; Path = ''; RuleName = '{R1}' }
        )
        $sec = @{ aaaa = @([ordered]@{ key = ''; owner = 'S-1-5-18'; sddl = 'O:SYD:'; aclProtected = $false; explicitAceCount = 0 }) }
        $text = Invoke-InIgwt { param($a, $b) ConvertTo-IgwtRegCleanManifest -Folder 'regclean-20261110-120000-abc123' -ScanId 's1' -Generated '2026-11-10T12:00:00' -Targets $a -Files ([ordered]@{ 'selected.reg' = 'ab'; 'firewall-rules.json' = 'cd' }) -Security $b -FirewallSnapshots @{ '{R1}' = 'C:\x\fw.json' } } @($t, $sec)
        $doc = $text | ConvertFrom-Json
        $doc.schemaVersion | Should -Be 1
        $doc.folder | Should -Be 'regclean-20261110-120000-abc123'
        @($doc.files | ForEach-Object { $_.name }) | Should -Be @('firewall-rules.json', 'selected.reg')
        $doc.files[1].sha256 | Should -Be 'AB'
        $doc.targets[0].includes | Should -Be @('bbbb')
        $doc.targets[0].security[0].owner | Should -Be 'S-1-5-18'
        $doc.targets[1].firewallSnapshot | Should -Be 'C:\x\fw.json'
        $doc.targets[1].valueName | Should -Be ''
        @($doc.targets[1].security).Count | Should -Be 0
        $text2 = Invoke-InIgwt { param($a, $b) ConvertTo-IgwtRegCleanManifest -Folder 'regclean-20261110-120000-abc123' -ScanId 's1' -Generated '2026-11-10T12:00:00' -Targets $a -Files ([ordered]@{ 'firewall-rules.json' = 'cd'; 'selected.reg' = 'ab' }) -Security $b -FirewallSnapshots @{ '{R1}' = 'C:\x\fw.json' } } @($t, $sec)
        $text2 | Should -BeExactly $text
        { Invoke-InIgwt { ConvertTo-IgwtRegCleanManifest -Folder 'f' -Targets @([pscustomobject]@{ Kind = 'regValue' }) } } | Should -Throw '*finding id*'
    }

    It 'names the backup folder regclean-time-6hex' {
        $n = Invoke-InIgwt { Get-IgwtRegCleanBackupFolderName -Now ([datetime]'2026-11-10T08:09:10') }
        $n | Should -Match '^regclean-20261110-080910-[0-9a-f]{6}$'
    }
}

Describe 'Private backup folder (RG18)' {
    BeforeAll {
        $script:Backups = Invoke-InIgwt { Get-IgwtDataPath -Kind Backups }
        $null = New-Item -ItemType Directory -Path $script:Backups -Force
        $script:Me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        function Reset-TestFolderAcl {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixture in TestRegistry/TestDrive only.')]
            param([string]$Path)
            # The test user owns the folder, so it may rewrite the ACL to clean up TestDrive.
            if (-not [IO.Directory]::Exists($Path)) { return }
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($false, $false)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($script:Me)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
            [IO.Directory]::SetAccessControl($Path, $acl)
            [IO.Directory]::Delete($Path)
        }
    }
    AfterEach { Set-IgwtEnvironment -ReadOnly:$false }

    It 'creates the folder with the protected ACL before anything is written' {
        $p = Join-Path $script:Backups 'regclean-20261110-000000-aaaaaa'
        try {
            $r = Invoke-InIgwt { param($a, $b) New-IgwtPrivateBackupFolder -Path $a -UserSid $b -Confirm:$false } @($p, $script:Me)
            $r | Should -Be $p
            [IO.Directory]::Exists($p) | Should -BeTrue
            $acl = [IO.Directory]::GetAccessControl($p, 'Access')
            $acl.AreAccessRulesProtected | Should -BeTrue
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            @($rules | Where-Object { $_.IsInherited }).Count | Should -Be 0
            @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique) | Should -Be (@('S-1-5-18', 'S-1-5-32-544', $script:Me) | Sort-Object)
            (Invoke-InIgwt { param($a, $b) Test-IgwtPrivateFolderSecurity -Security $a -UserSid $b } @($acl, $script:Me)) | Should -BeTrue
        } finally { Reset-TestFolderAcl $p }
    }

    It 'refuses paths that are not a new folder directly under Backups' {
        $outside = Join-Path $TestDrive 'elsewhere'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } $outside } | Should -Throw 'Backup failed:*not a folder directly under*'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } (Join-Path $script:Backups 'a\b') } | Should -Throw 'Backup failed:*not a folder directly under*'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } (Join-Path $script:Backups '..\x') } | Should -Throw 'Backup failed:*not a folder directly under*'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } $script:Backups } | Should -Throw 'Backup failed:*'
        { Invoke-InIgwt { New-IgwtPrivateBackupFolder -Path 'regclean-x' -Confirm:$false } } | Should -Throw 'Backup failed:*absolute*'
        $existing = Join-Path $script:Backups 'regclean-existing'
        $null = New-Item -ItemType Directory -Path $existing -Force
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } $existing } | Should -Throw 'Backup failed:*already exists*'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -UserSid 'nobody' -Confirm:$false } (Join-Path $script:Backups 'regclean-y') } | Should -Throw 'Backup failed:*not a user SID*'
    }

    It 'throws when the ACL cannot be applied (mocked) and creates nothing' {
        Mock New-IgwtDirectoryWithSecurity -ModuleName iGWindowsTuner { throw 'Attempted to perform an unauthorized operation.' }
        $p = Join-Path $script:Backups 'regclean-20261110-000000-bbbbbb'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } $p } | Should -Throw 'Backup failed: the private folder could not be created*nothing changed*'
        [IO.Directory]::Exists($p) | Should -BeFalse
    }

    It 'throws and removes the empty folder when the ACL read back is not the private one' {
        Mock New-IgwtDirectoryWithSecurity -ModuleName iGWindowsTuner { $null = [IO.Directory]::CreateDirectory($Path) }
        Mock Get-IgwtDirectorySecurity -ModuleName iGWindowsTuner { New-Object System.Security.AccessControl.DirectorySecurity }
        $p = Join-Path $script:Backups 'regclean-20261110-000000-cccccc'
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } $p } | Should -Throw 'Backup failed:*not the private ones*'
        [IO.Directory]::Exists($p) | Should -BeFalse
        Mock Get-IgwtDirectorySecurity -ModuleName iGWindowsTuner { throw 'Access denied.' }
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } $p } | Should -Throw 'Backup failed:*cannot be read*'
        [IO.Directory]::Exists($p) | Should -BeFalse
    }

    It 'checks the private ACL exactly' {
        $test = { param($acl, $sid) Invoke-InIgwt { param($a, $b) Test-IgwtPrivateFolderSecurity -Security $a -UserSid $b } @($acl, $sid) }
        $good = Invoke-InIgwt { param($s) New-IgwtPrivateFolderSecurity -UserSid $s } $script:Sid
        & $test $good $script:Sid | Should -BeTrue
        & $test $good '' | Should -BeFalse
        $noUser = Invoke-InIgwt { New-IgwtPrivateFolderSecurity }
        & $test $noUser '' | Should -BeTrue
        $writer = Invoke-InIgwt { param($s) New-IgwtPrivateFolderSecurity -UserSid $s } $script:Sid
        $writer.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($script:Sid)), 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        & $test $writer $script:Sid | Should -BeFalse
        $users = Invoke-InIgwt { New-IgwtPrivateFolderSecurity }
        $users.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        & $test $users '' | Should -BeFalse
        $open = Invoke-InIgwt { New-IgwtPrivateFolderSecurity }
        $open.SetAccessRuleProtection($false, $false)
        & $test $open '' | Should -BeFalse
    }

    It 'refuses in read-only mode' {
        Set-IgwtEnvironment -ReadOnly
        { Invoke-InIgwt { param($a) New-IgwtPrivateBackupFolder -Path $a -Confirm:$false } (Join-Path $script:Backups 'regclean-ro') } | Should -Throw 'Read-only mode:*'
    }
}
