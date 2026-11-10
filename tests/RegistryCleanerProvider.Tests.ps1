# Registry Analyzer & Cleaner (3.8): exact snapshots, the .reg / firewall-rules.json / manifest.json
# builders, the private backup folder (DECISIONS RG17, RG18), the 'regClean' change provider, the
# plan and the journaled writer (RG14, RG16, RG19-RG21). Headless and non-elevated: TestRegistry
# keys under a fake SID, the synthetic leftovers fixture, mocks for every live system call and for
# failures, and TestDrive for the data root.

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

Describe 'Registry cleaner provider, plan and writer (RG14, RG16, RG19-RG21)' {
    BeforeAll {
        $script:Fx = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\registry\leftovers.json') -Raw | ConvertFrom-Json
        $script:FxSid = [string]$script:Fx.sid
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
        $script:Drives = @{ SystemDrive = 'C'; Online = @('C', 'D'); Skipped = @{}; Notes = @() }
        $script:Existing = New-Object System.Collections.Generic.List[string]
        $script:NoExclusions = [pscustomobject]@{ SchemaVersion = 1; Entries = @(); Path = '' }
        $script:Exclusions = $script:NoExclusions
        $vendors = @((Get-Content -LiteralPath (Join-Path $script:IgwtProjectRoot 'data\registry\protected.json') -Raw | ConvertFrom-Json).groups | Where-Object { $_.id -eq 'securityVendors' })[0].vendors
        $script:VendorPublisher = ([string]@(@($vendors | Where-Object { $_.type -eq 'consumer' -and @($_.publisherPatterns).Count -gt 0 -and $_.removalTool.url })[0].publisherPatterns)[0]).TrimEnd('*')
        $script:FwSnapshot = Join-Path (Invoke-InIgwt { Get-IgwtDataPath -Kind Backups }) 'snapshot-firewall-test.json'

        function Reset-RegCleanFixture {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixture in TestRegistry only.')]
            param()
            foreach ($p in 'TestRegistry:\HKLM\SOFTWARE', 'TestRegistry:\HKLM\SYSTEM', "TestRegistry:\HKU\$($script:FxSid)") { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }
            foreach ($k in @($script:Fx.keys)) {
                $p = 'TestRegistry:\' + ([string]$k.path).Replace('{sid}', $script:FxSid)
                $null = New-Item -Path $p -Force
                foreach ($v in @($k.values)) {
                    $data = $v.data
                    if ($data -is [string]) { $data = $data.Replace('{vendorPublisher}', $script:VendorPublisher).Replace('{vendorDisplay}', 'Fabrikam Shield') }
                    $null = New-ItemProperty -LiteralPath $p -Name ([string]$v.name) -Value $data -PropertyType ([string]$v.type) -Force
                }
            }
            $script:Existing.Clear(); foreach ($p in @($script:Fx.existingPaths)) { $script:Existing.Add([string]$p) }
            $script:Exclusions = $script:NoExclusions
            $script:FwRules = @(foreach ($r in @($script:Fx.firewallRules)) {
                    [pscustomobject]@{
                        Name = $r.Name; InstanceID = $r.Name; DisplayName = $r.DisplayName; Group = $r.Group; DisplayGroup = $r.Group; Enabled = 'True'
                        Direction = $r.Direction; Action = $r.Action; Profile = 'Any'; PolicyStoreSourceType = 'Local'; PolicyStoreSource = 'PersistentStore'
                        Owner = ''; Description = ''; EdgeTraversalPolicy = 'Block'
                    }
                })
            $script:FwFilters = @(foreach ($r in @($script:Fx.firewallRules)) { [pscustomobject]@{ InstanceID = $r.Name; Program = $r.Program; Package = '' } })
            $script:FwRemoved = New-Object System.Collections.Generic.List[object]
        }
        function Get-TestScan([string[]]$Category) { if ($Category) { Get-IgwtRegistryLeftovers -Category $Category } else { Get-IgwtRegistryLeftovers } }
        function Find-TestFinding($Scan, [string]$Category, [string]$Path = '', [string]$ValueName = '', [string]$Rule = '', [string]$Hive = '') {
            $hit = @($Scan.Findings | Where-Object { $_.Category -eq $Category -and $(if ($Rule) { $_.RuleName -eq $Rule } else { $_.Path -eq $Path -and [string]$_.ValueName -eq $ValueName -and (-not $Hive -or $_.Hive -eq $Hive) }) })
            if ($hit.Count -ne 1) { throw "Fixture finding not found: $Category $Path $ValueName $Rule" }
            return $hit[0]
        }
        function Invoke-TestCleanup([object[]]$Findings, [switch]$WithRestorePoint, [switch]$EnableSystemProtection) {
            $plan = Get-IgwtRegCleanPlan -Findings $Findings
            if ($WithRestorePoint) { return (Invoke-IgwtRegistryCleanup -Plan $plan -EnableSystemProtection:$EnableSystemProtection -Confirm:$false) }
            return (Invoke-IgwtRegistryCleanup -Plan $plan -SkipRestorePoint -Confirm:$false)
        }
        function Get-TestKeySnapshot([string]$Hive, [string]$Path, [string]$View = '64') {
            $sid = $(if ($Hive -eq 'HKCU') { $script:FxSid } else { '' })
            Invoke-InIgwt { param($h, $s, $v, $p) ConvertTo-IgwtCanonicalJson (Get-IgwtRegCleanKeySnapshot -Hive $h -Sid $s -View $v -Path $p) } @($Hive, $sid, $View, $Path)
        }
        function Get-TestSessionEntries([string]$SessionId) { @(Invoke-InIgwt { param($s) @((Read-IgwtJournal).Entries | Where-Object { [string]$_['session'] -eq $s }) } @($SessionId)) }
        function Get-TestRawKey([string]$TestRegistryPath, [System.Security.AccessControl.RegistryRights]$Rights) {
            $name = (Get-Item -LiteralPath $TestRegistryPath).Name
            return [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($name.Substring($name.IndexOf('\') + 1), [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $Rights)
        }

        Mock Test-IgwtRegCleanProcess64 -ModuleName iGWindowsTuner { $true }
        Mock Get-IgwtRegCleanVariableSet -ModuleName iGWindowsTuner { $script:Vars }
        Mock Get-IgwtRegCleanDriveTable -ModuleName iGWindowsTuner { $script:Drives }
        Mock Test-IgwtRegCleanPathProbe -ModuleName iGWindowsTuner { if ($Mode -eq 'List') { return 'Exists' }; if ($script:Existing -contains $Path) { return 'Exists' }; return 'Missing' }
        Mock Test-IgwtNetworkPath -ModuleName iGWindowsTuner { ([string]$Path).StartsWith('\\') }
        Mock Get-IgwtRegCleanAppxPackages -ModuleName iGWindowsTuner { }
        Mock Get-IgwtRegCleanServiceList -ModuleName iGWindowsTuner { @($script:Fx.services) }
        Mock Get-IgwtInstalledGames -ModuleName iGWindowsTuner { }
        Mock Get-IgwtSteamLibraryPaths -ModuleName iGWindowsTuner { }
        Mock Get-IgwtMsiProductState -ModuleName iGWindowsTuner { -1 }
        Mock Get-IgwtRegCleanTrustedInstallerSid -ModuleName iGWindowsTuner { 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
        Mock Get-IgwtRegCleanSecurityProducts -ModuleName iGWindowsTuner { }
        Mock Get-IgwtRegCleanPnpProviders -ModuleName iGWindowsTuner { }
        Mock Get-IgwtRegCleanKeySecurity -ModuleName iGWindowsTuner { [pscustomobject]@{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-32-544', 'S-1-5-18'); AclProtected = $false; HasExplicitAce = $false; ExplicitAceCount = 0; Sddl = 'O:BAG:SYD:AI' } }
        Mock Get-AuthenticodeSignature -ModuleName iGWindowsTuner { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
        Mock Get-IgwtRegCleanExclusions -ModuleName iGWindowsTuner { $script:Exclusions }
        Mock Get-IgwtInteractiveUserSid -ModuleName iGWindowsTuner { 'S-1-5-21-1-2-3-1001' }
        Mock Test-IgwtIsAdmin -ModuleName iGWindowsTuner { $true }
        Mock Get-NetFirewallRule -ModuleName iGWindowsTuner { if ($Name) { @($script:FwRules | Where-Object { $_.Name -eq @($Name)[0] }) } else { $script:FwRules } }
        Mock Get-NetFirewallApplicationFilter -ModuleName iGWindowsTuner { $script:FwFilters }
        Mock Get-ScheduledTask -ModuleName iGWindowsTuner { @(foreach ($t in @($script:Fx.tasks)) { [pscustomobject]@{ TaskPath = $t.TaskPath; TaskName = $t.TaskName; State = $t.State; Actions = @($t.Actions) } }) }
        Mock Get-IgwtFirewallInventory -ModuleName iGWindowsTuner { throw 'the cleaner must not use the firewall inventory' }
        Mock Get-IgwtFirewallSignatures -ModuleName iGWindowsTuner { throw 'the cleaner must not write the signature cache' }
        Mock Send-IgwtProgress -ModuleName iGWindowsTuner { }
        Mock Get-IgwtFirewallRuleDefinition -ModuleName iGWindowsTuner {
            $r = @($script:FwRules | Where-Object { $_.Name -eq $Name })[0]
            if (-not $r) { throw "No MSFT_NetFirewallRule objects found with property 'Name' equal to '$Name'." }
            $f = @($script:FwFilters | Where-Object { $_.InstanceID -eq $Name })[0]
            [ordered]@{ name = [string]$r.Name; displayName = [string]$r.DisplayName; group = [string]$r.Group; enabled = $true; direction = [string]$r.Direction; action = [string]$r.Action; program = [string]$f.Program }
        }
        Mock Invoke-IgwtFirewallChange -ModuleName iGWindowsTuner {
            foreach ($n in @($Name)) { $script:FwRemoved.Add(@($script:FwRules | Where-Object { $_.Name -eq $n })[0]) }
            $script:FwRules = @($script:FwRules | Where-Object { @($Name) -notcontains $_.Name })
            [pscustomobject]@{ Snapshot = $script:FwSnapshot; Changes = @($Name).Count; Results = @() }
        }
        Mock Invoke-IgwtRevert -ModuleName iGWindowsTuner {
            foreach ($r in $script:FwRemoved) { $script:FwRules += $r }
            $script:FwRemoved.Clear()
            [pscustomobject]@{ Operation = 'Revert'; Results = @([pscustomobject]@{ Id = 'firewall'; Result = 'Reverted'; Message = '' }) }
        }
        Mock New-IgwtRestorePoint -ModuleName iGWindowsTuner { throw 'the restore point is mocked per test' }
        # The real private folder gives the (non-elevated) test user read access only; its ACL is tested above.
        Mock New-IgwtPrivateBackupFolder -ModuleName iGWindowsTuner { $null = [IO.Directory]::CreateDirectory($Path); $Path }

        $script:UninstallGone = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ContosoGone_is1'
        $script:UserUninstall = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\ContosoUserGone'
        $script:RunKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        $script:RuleAllow = '{11111111-0000-0000-0000-000000000001}'
        $script:RuleBlock = '{11111111-0000-0000-0000-000000000002}'
    }
    BeforeEach {
        Reset-RegCleanFixture
        Invoke-InIgwt { $script:IgwtRegCleanStep = $null }
    }

    Context 'target and Resolve (structural, RG16)' {
        It 'builds the RG16 target from a finding and Resolve accepts it' {
            $scan = Get-TestScan -Category uninstall, run, firewallRule
            $f = Find-TestFinding -Scan $scan -Category 'uninstall' $script:UserUninstall
            $t = Invoke-InIgwt { param($x) Get-IgwtRegCleanTarget -Finding $x } @($f)
            @($t.Keys) | Should -Be @('provider', 'key', 'item', 'kind', 'hive', 'sid', 'view', 'path', 'valueName', 'ruleName', 'category')
            $t.key | Should -Be "regclean|regKeyTree|HKCU|$($script:FxSid)|64|$($script:UserUninstall)"
            $t.item | Should -Be 'regclean:uninstall'
            $r = Invoke-InIgwt { param($x) Resolve-IgwtChangeTarget -Target $x } @($t)
            $r.Kind | Should -Be 'regKeyTree'
            $r.Sid | Should -Be $script:FxSid
            $v = Invoke-InIgwt { param($x) Get-IgwtRegCleanTarget -Finding $x } @(Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray')
            $v.key | Should -Be "regclean|regValue|HKLM|-|64|$($script:RunKey)|ContosoTray"
            (Invoke-InIgwt { param($x) Resolve-IgwtChangeTarget -Target $x } @($v)).ValueName | Should -Be 'ContosoTray'
            $fw = Invoke-InIgwt { param($x) Get-IgwtRegCleanTarget -Finding $x } @(Find-TestFinding -Scan $scan -Category 'firewallRule' -Rule $script:RuleAllow)
            $fw.key | Should -Be "regclean|firewallRule||-|||$($script:RuleAllow)"
            (Invoke-InIgwt { param($x) Resolve-IgwtChangeTarget -Target $x } @($fw)).RuleName | Should -Be $script:RuleAllow
        }
        It 'refuses roots, other keys, deny-listed segments, mismatched keys, report-only rows and bad SIDs' {
            $mk = {
                param($kind, $hive, $sid, $view, $path, $name, $cat)
                Invoke-InIgwt { param($a) $f = [pscustomobject]@{ Kind = $a[0]; Hive = $a[1]; Sid = $a[2]; View = $a[3]; Path = $a[4]; ValueName = $a[5]; RuleName = $a[5]; Category = $a[6] }; Get-IgwtRegCleanTarget -Finding $f } @(, @($kind, $hive, $sid, $view, $path, $name, $cat))
            }
            $resolve = { param($t) Invoke-InIgwt { param($x) Resolve-IgwtChangeTarget -Target $x } @($t) }
            { & $resolve (& $mk 'regKeyTree' 'HKLM' '' '64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' '' 'uninstall') } | Should -Throw '*category root is never removed*'
            { & $resolve (& $mk 'regKeyTree' 'HKLM' '' '64' 'SOFTWARE\Contoso\App' '' 'uninstall') } | Should -Throw '*outside the keys*'
            { & $resolve (& $mk 'regKeyTree' 'HKLM' '' '64' 'SOFTWARE\Contoso\Policies' '' 'softwareKey') } | Should -Throw '*shared or linked key*'
            { & $resolve (& $mk 'reportOnly' 'HKLM' '' '' 'SYSTEM\CurrentControlSet\Services\x' '' 'service') } | Should -Throw '*kind*'
            { & $resolve (& $mk 'regKeyTree' 'HKCU' 'S-1-5-18' '64' 'Software\Contoso\App' '' 'softwareKey') } | Should -Throw '*user SID*'
            { & $resolve (& $mk 'regValue' 'HKLM' '' '64' $script:RunKey 'X' 'uninstall') } | Should -Throw '*category*'
            $t = & $mk 'regValue' 'HKLM' '' '64' $script:RunKey 'ContosoTray' 'run'
            $t.path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            { & $resolve $t } | Should -Throw '*does not match its fields*'
            $t = & $mk 'regValue' 'HKLM' '' '64' $script:RunKey 'ContosoTray' 'run'
            $t.provider = 'module'
            { Invoke-InIgwt { param($x) Resolve-IgwtRegCleanTarget -Target $x } @($t) } | Should -Throw '*not a registry cleaner entry*'
        }
        It 'refuses an HKCU target of a user whose hive is not loaded, with the sign-in message (RG33)' {
            $t = Invoke-InIgwt { Get-IgwtRegCleanTarget -Finding ([pscustomobject]@{ Kind = 'regKeyTree'; Hive = 'HKCU'; Sid = 'S-1-5-21-9-9-9-1002'; View = '64'; Path = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\ContosoUserGone'; Category = 'uninstall' }) }
            { Invoke-InIgwt { param($x) Resolve-IgwtChangeTarget -Target $x } @($t) } | Should -Throw '*belongs to a user who is not signed in; sign in as that user*'
            $r = Invoke-InIgwt {
                param($x)
                $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'other user' -Confirm:$false
                try { Invoke-IgwtChangeStep -Session $s -Target $x -Desired ([ordered]@{ action = 'remove' }) -Group 'g' -Confirm:$false } finally { Complete-IgwtChangeSession -Session $s }
            } @($t)
            $r.Result | Should -Be 'Failed'
            $r.Message | Should -BeLike 'Nothing changed: Refused: This entry belongs to a user who is not signed in*'
        }
    }

    Context 'additive restore and bottom-up removal (RG17, RG20)' {
        It 'removes and restores a tree with every kind exactly (remove-then-restore compare passes)' {
            $null = New-ContosoTree
            $before = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $json = Invoke-InIgwt { param($x) ConvertTo-IgwtCanonicalJson $x } @($before)
            Invoke-InIgwt { param($sid, $b) Remove-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Before $b -Confirm:$false } @($script:Sid, $before)
            Test-Path -LiteralPath "TestRegistry:\HKU\$($script:Sid)\Software\Contoso\App" | Should -BeFalse
            Test-Path -LiteralPath "TestRegistry:\HKU\$($script:Sid)\Software\Contoso" | Should -BeTrue
            # The journal keeps the snapshot as JSON: restore from the round-tripped copy.
            $back = (Invoke-InIgwt { param($x) ConvertTo-IgwtJson -InputObject $x } @($before)) | ConvertFrom-Json
            Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Snapshot $b -Confirm:$false } @($script:Sid, $back)
            $after = Invoke-InIgwt { param($sid) ConvertTo-IgwtCanonicalJson (Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App') } $script:Sid
            $after | Should -BeExactly $json
            # A second restore of an unchanged key changes nothing (idempotent).
            Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Snapshot $b -Confirm:$false } @($script:Sid, $before)
            (Invoke-InIgwt { param($sid) ConvertTo-IgwtCanonicalJson (Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App') } $script:Sid) | Should -BeExactly $json
        }
        It 'refuses to remove a tree that differs from the snapshot (a subkey added since)' {
            $root = New-ContosoTree
            $before = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $null = New-Item -Path (Join-Path $root 'b\added') -Force
            { Invoke-InIgwt { param($sid, $b) Remove-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Before $b -Confirm:$false } @($script:Sid, $before) } | Should -Throw 'Refused: changed since the preview*'
            Test-Path -LiteralPath (Join-Path $root 'b\added') | Should -BeTrue
            @((Get-Item -LiteralPath $root).Property).Count | Should -Be 8
        }
        It 'fills in a partly removed tree and refuses a key that exists again with other or extra data' {
            $root = New-ContosoTree
            $before = Invoke-InIgwt { param($sid) Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' } $script:Sid
            $json = Invoke-InIgwt { param($x) ConvertTo-IgwtCanonicalJson $x } @($before)
            Remove-Item -LiteralPath (Join-Path $root 'a') -Recurse -Force
            Remove-ItemProperty -LiteralPath $root -Name 'Flags'
            Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Snapshot $b -Confirm:$false } @($script:Sid, $before)
            (Invoke-InIgwt { param($sid) ConvertTo-IgwtCanonicalJson (Get-IgwtRegCleanKeySnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App') } $script:Sid) | Should -BeExactly $json
            Set-ItemProperty -LiteralPath $root -Name 'Path' -Value 'C:\Reinstalled'
            { Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Snapshot $b -Confirm:$false } @($script:Sid, $before) } | Should -Throw 'Refused: the key exists again with other data; nothing changed.'
            Remove-ItemProperty -LiteralPath $root -Name 'Path'
            $null = New-Item -Path (Join-Path $root 'new') -Force
            Remove-Item -LiteralPath (Join-Path $root 'b') -Force
            { Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanKeyTree -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Snapshot $b -Confirm:$false } @($script:Sid, $before) } | Should -Throw 'Refused: the key exists again*'
            Test-Path -LiteralPath (Join-Path $root 'b') | Should -BeFalse -Because 'a refused restore writes nothing'
        }
        It 'removes and restores one value additively' {
            $root = New-ContosoTree
            $before = Invoke-InIgwt { param($sid) Get-IgwtRegCleanValueSnapshot -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Name 'List' } $script:Sid
            Invoke-InIgwt { param($sid, $b) Remove-IgwtRegCleanValue -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Name 'List' -Before $b -Confirm:$false } @($script:Sid, $before)
            (Get-Item -LiteralPath $root).GetValue('List') | Should -BeNullOrEmpty
            Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanValue -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Name 'List' -Snapshot $b -Confirm:$false } @($script:Sid, $before)
            (Get-Item -LiteralPath $root).GetValue('List') | Should -Be @('one', '', 'three')
            (Get-Item -LiteralPath $root).GetValueKind('List') | Should -Be 'MultiString'
            Set-ItemProperty -LiteralPath $root -Name 'List' -Value @('x') -Type MultiString
            { Invoke-InIgwt { param($sid, $b) Restore-IgwtRegCleanValue -Hive HKCU -Sid $sid -Path 'Software\Contoso\App' -Name 'List' -Snapshot $b -Confirm:$false } @($script:Sid, $before) } | Should -Throw 'Refused: the key exists again*'
        }
    }

    Context 'the plan (RG14 point 2, RG19)' {
        It 're-reads every selection, collapses nested keys and lists refusals with reasons' {
            $scan = Get-TestScan
            $vendor = Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone'
            $product = Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone\App'
            $linked = Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\Fabrikam\Linked'
            $svc = @($scan.Findings | Where-Object { $_.Category -eq 'service' })[0]
            $prot = @($scan.Findings | Where-Object { $_.Confidence -eq 'Protected' })[0]
            $gone = Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone
            Remove-Item -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" -Recurse -Force
            $plan = Get-IgwtRegCleanPlan -Findings @($product, $vendor, $linked, $svc, $prot, $gone)
            $plan.ScanId | Should -Be $scan.ScanId
            @($plan.Targets).Count | Should -Be 1
            $plan.Targets[0].Path | Should -Be 'SOFTWARE\ContosoGone'
            $plan.Targets[0].ScanId | Should -Be $scan.ScanId
            @($plan.Targets[0].Includes) | Should -Be @($product.Id)
            $plan.Included[0].IncludedIn | Should -Be $vendor.Id
            $plan.Included[0].Note | Should -Be 'included in HKLM\SOFTWARE\ContosoGone'
            @($plan.Refused).Count | Should -Be 4
            ($plan.Refused | Where-Object Id -EQ $linked.Id).Reason | Should -BeLike '*shared or linked key*'
            ($plan.Refused | Where-Object Id -EQ $svc.Id).Reason | Should -BeLike 'iG does not remove*'
            ($plan.Refused | Where-Object Id -EQ $prot.Id).Reason | Should -Not -BeNullOrEmpty
            ($plan.Refused | Where-Object Id -EQ $gone.Id).Reason | Should -BeLike 'No longer a provable leftover*'
            @($plan.Backup.Files).Count | Should -Be 3
            Test-Path -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\ContosoGone\App' | Should -BeTrue
        }
        It 'notes that firewall rules are backed up in firewall-rules.json and refuses mixed scans' {
            $scan = Get-TestScan -Category firewallRule
            $plan = Get-IgwtRegCleanPlan -Findings @(Find-TestFinding -Scan $scan -Category 'firewallRule' -Rule $script:RuleAllow)
            @($plan.Targets).Count | Should -Be 1
            $plan.Backup.Note | Should -BeLike '*firewall-rules.json*'
            $a = Find-TestFinding -Scan $scan -Category 'firewallRule' -Rule $script:RuleAllow
            $b = (Find-TestFinding -Scan $scan -Category 'firewallRule' -Rule $script:RuleBlock) | Select-Object *
            $b.ScanId = 'other'
            { Get-IgwtRegCleanPlan -Findings @($a, $b) } | Should -Throw '*different scans*'
        }
    }

    Context 'the writer (RG16, RG18, RG19)' {
        It 'removes key trees, values and firewall rules in one session with a backup folder and the journal' {
            $scan = Get-TestScan -Category uninstall, run, firewallRule
            $sel = @((Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone), (Find-TestFinding -Scan $scan -Category 'uninstall' $script:UserUninstall), (Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray'), (Find-TestFinding -Scan $scan -Category 'firewallRule' -Rule $script:RuleAllow))
            $beforeHklm = Get-TestKeySnapshot HKLM $script:UninstallGone
            $beforeHkcu = Get-TestKeySnapshot HKCU $script:UserUninstall
            $res = Invoke-TestCleanup $sel
            $res.Removed | Should -Be 4 -Because (($res.Results | ForEach-Object { "$($_.Path)$($_.RuleName): $($_.Result) $($_.Message)" }) -join '; ')
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeFalse
            Test-Path -LiteralPath "TestRegistry:\HKU\$($script:FxSid)\$($script:UserUninstall)" | Should -BeFalse
            (Get-Item -LiteralPath "TestRegistry:\HKLM\$($script:RunKey)").GetValue('ContosoTray') | Should -BeNullOrEmpty
            @($script:FwRules | Where-Object Name -EQ $script:RuleAllow).Count | Should -Be 0
            Should -Invoke Invoke-IgwtFirewallChange -ModuleName iGWindowsTuner -Times 1 -Exactly -Scope It -ParameterFilter { $Operation -eq 'Delete' -and @($Name) -contains '{11111111-0000-0000-0000-000000000001}' }

            # Backup folder (RG18).
            $res.Backup | Should -Match '\\Backups\\regclean-\d{8}-\d{6}-[0-9a-f]{6}$'
            $reg = [IO.File]::ReadAllBytes((Join-Path $res.Backup 'selected.reg'))
            $reg[0] | Should -Be 0xFF
            $reg[1] | Should -Be 0xFE
            $text = [IO.File]::ReadAllText((Join-Path $res.Backup 'selected.reg'))
            $text | Should -BeLike 'Windows Registry Editor Version 5.00*'
            $text | Should -Match ([regex]::Escape("[HKEY_USERS\$($script:FxSid)\$($script:UserUninstall)]"))
            $text | Should -Match ([regex]::Escape("[HKEY_LOCAL_MACHINE\$($script:UninstallGone)]"))
            $text | Should -Match '"ContosoTray"='
            $fw = Get-Content -LiteralPath (Join-Path $res.Backup 'firewall-rules.json') -Raw | ConvertFrom-Json
            $fw.rules[0].name | Should -Be $script:RuleAllow
            $man = Get-Content -LiteralPath (Join-Path $res.Backup 'manifest.json') -Raw | ConvertFrom-Json
            @($man.targets).Count | Should -Be 4
            ($man.targets | Where-Object ruleName -EQ $script:RuleAllow).firewallSnapshot | Should -Be $script:FwSnapshot
            ($man.files | Where-Object name -EQ 'selected.reg').sha256 | Should -Be (Get-FileHash -LiteralPath (Join-Path $res.Backup 'selected.reg') -Algorithm SHA256).Hash
            @(($man.targets | Where-Object path -EQ $script:UninstallGone).security)[0].owner | Should -Be 'S-1-5-32-544'

            # Journal: one session, origin regClean with the folder, committed steps with the exact before data.
            $entries = Get-TestSessionEntries $res.SessionId
            $start = @($entries | Where-Object { $_['kind'] -eq 'sessionStart' })[0]
            $start['origin']['type'] | Should -Be 'regClean'
            $start['origin']['ref'] | Should -Be $res.Backup
            $start['title'] | Should -Be 'Registry cleanup (4 entries)'
            @($entries | Where-Object { $_['kind'] -eq 'committed' }).Count | Should -Be 4
            $c = @($entries | Where-Object { $_['kind'] -eq 'committed' -and [string]$_['target']['path'] -eq $script:UninstallGone })[0]
            (Invoke-InIgwt { param($x) ConvertTo-IgwtCanonicalJson (Remove-IgwtVolatileSnapshotKey $x) } @($c['before'])) | Should -BeExactly $beforeHklm
            $c['applied']['backup'] | Should -Be $res.Backup
            $c['after']['exists'] | Should -BeFalse
            @($entries | Where-Object { $_['kind'] -eq 'sessionEnd' })[0]['outcome'] | Should -Be 'ok'
            (Invoke-InIgwt { $script:IgwtRegCleanStep }) | Should -BeNullOrEmpty

            # Restore the whole session (revert plan + one-click revert, RG20).
            $plan = @(Get-IgwtRevertPlan -SessionId $res.SessionId)
            $plan.Count | Should -Be 4
            @($plan | Where-Object Status -NE 'Ready').Count | Should -Be 0
            $rev = Invoke-IgwtJournalRevert -Plan $plan -Title 'Restore last cleanup' -Confirm:$false
            @($rev.Results | Where-Object Result -NE 'Reverted').Count | Should -Be 0 -Because (($rev.Results | ForEach-Object { "$($_.Key): $($_.Result) $($_.Message)" }) -join '; ')
            Get-TestKeySnapshot HKLM $script:UninstallGone | Should -BeExactly $beforeHklm
            Get-TestKeySnapshot HKCU $script:UserUninstall | Should -BeExactly $beforeHkcu
            (Get-Item -LiteralPath "TestRegistry:\HKLM\$($script:RunKey)").GetValue('ContosoTray') | Should -Not -BeNullOrEmpty
            @($script:FwRules | Where-Object Name -EQ $script:RuleAllow).Count | Should -Be 1
            Should -Invoke Invoke-IgwtRevert -ModuleName iGWindowsTuner -Times 1 -Exactly -Scope It -ParameterFilter { $SnapshotPath -like '*snapshot-firewall-test.json' }
        }

        It 'restores one entry, also after an exclusion was added for it (RG14: exclusions never block a restore)' {
            $scan = Get-TestScan -Category uninstall, run
            $before = Get-TestKeySnapshot HKLM $script:UninstallGone
            $res = Invoke-TestCleanup @((Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone), (Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray'))
            $res.Removed | Should -Be 2
            $script:Exclusions = [pscustomobject]@{ SchemaVersion = 1; Path = ''; Entries = @([pscustomobject]@{ pattern = "HKLM\$($script:UninstallGone)"; scope = 'key'; reason = 'test'; addedUtc = '2026-11-10T00:00:00Z' }) }
            $row = @((Get-IgwtJournalTimeline).Rows | Where-Object { $_.Session -eq $res.SessionId -and $_.Target -like "*|$($script:UninstallGone)" })[0]
            $row.Origin | Should -Be 'regClean'
            $row.InEffect | Should -BeTrue
            $plan = @(Get-IgwtRevertPlan -EntryId $row.EntryId)
            $plan[0].Status | Should -Be 'Ready'
            $rev = Invoke-IgwtJournalRevert -Plan $plan -Confirm:$false
            $rev.Results[0].Result | Should -Be 'Reverted'
            Get-TestKeySnapshot HKLM $script:UninstallGone | Should -BeExactly $before
            (Get-Item -LiteralPath "TestRegistry:\HKLM\$($script:RunKey)").GetValue('ContosoTray') | Should -BeNullOrEmpty -Because 'only the chosen entry is restored'
        }

        It 'refuses to restore over a reinstalled program with other values (Conflict, then Refused, nothing changed)' {
            $scan = Get-TestScan -Category uninstall
            $res = Invoke-TestCleanup @(Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone)
            $res.Removed | Should -Be 1
            $p = "TestRegistry:\HKLM\$($script:UninstallGone)"
            $null = New-Item -Path $p -Force
            $null = New-ItemProperty -LiteralPath $p -Name 'DisplayName' -Value 'Contoso Gone 2' -PropertyType String
            $plan = @(Get-IgwtRevertPlan -SessionId $res.SessionId)
            $plan[0].Status | Should -Be 'Conflict'
            $rev = Invoke-IgwtJournalRevert -Plan $plan -Decisions @{ $plan[0].Key = 'Restore' } -Confirm:$false
            $rev.Results[0].Result | Should -Be 'Failed'
            $rev.Results[0].Message | Should -BeLike '*Refused: the key exists again with other data; nothing changed.*'
            @((Get-Item -LiteralPath $p).Property) | Should -Be @('DisplayName')
            (Get-Item -LiteralPath $p).GetValue('DisplayName') | Should -Be 'Contoso Gone 2'
        }

        It 'collapses a nested selection: the vendor key is removed and restored with its product key' {
            $scan = Get-TestScan -Category softwareKey
            $before = Get-TestKeySnapshot HKLM 'SOFTWARE\ContosoGone'
            $vendor = Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone'
            $product = Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone\App'
            $res = Invoke-TestCleanup @($product, $vendor)
            $res.Removed | Should -Be 2
            ($res.Results | Where-Object Id -EQ $product.Id).Message | Should -Be 'included in HKLM\SOFTWARE\ContosoGone'
            @(Get-TestSessionEntries $res.SessionId | Where-Object { $_['kind'] -eq 'committed' }).Count | Should -Be 1
            Test-Path -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\ContosoGone' | Should -BeFalse
            $null = Invoke-IgwtJournalRevert -Plan @(Get-IgwtRevertPlan -SessionId $res.SessionId) -Confirm:$false
            Get-TestKeySnapshot HKLM 'SOFTWARE\ContosoGone' | Should -BeExactly $before
        }

        It 'maps Refused to Refused and continues the session (an exclusion added after the preview, RG14 point 3)' {
            $scan = Get-TestScan -Category uninstall, run
            $plan = Get-IgwtRegCleanPlan -Findings @((Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone), (Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray'))
            $script:Exclusions = [pscustomobject]@{ SchemaVersion = 1; Path = ''; Entries = @([pscustomobject]@{ pattern = "HKLM\$($script:UninstallGone)"; scope = 'key'; reason = 'test'; addedUtc = '2026-11-10T00:00:00Z' }) }
            $res = Invoke-IgwtRegistryCleanup -Plan $plan -SkipRestorePoint -Confirm:$false
            $r1 = $res.Results | Where-Object Path -EQ $script:UninstallGone
            $r1.Result | Should -Be 'Refused'
            $r1.Message | Should -BeLike 'protected (*'
            ($res.Results | Where-Object ValueName -EQ 'ContosoTray').Result | Should -Be 'Removed'
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeTrue
            $entries = Get-TestSessionEntries $res.SessionId
            @($entries | Where-Object { $_['kind'] -in 'rolledBack', 'rollbackFailed' }).Count | Should -Be 0
            @($entries | Where-Object { $_['kind'] -eq 'sessionEnd' })[0]['outcome'] | Should -Be 'partial'
        }

        It 'refuses a key that changed between the step''s read and the removal (a subkey added)' {
            $scan = Get-TestScan -Category uninstall
            $plan = Get-IgwtRegCleanPlan -Findings @(Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone)
            Mock Get-IgwtRegCleanFinding -ModuleName iGWindowsTuner { $null = New-Item -Path "TestRegistry:\HKLM\$($script:UninstallGone)\Added" -Force; $Target }
            $res = Invoke-IgwtRegistryCleanup -Plan $plan -SkipRestorePoint -Confirm:$false
            $res.Results[0].Result | Should -Be 'Refused'
            $res.Results[0].Message | Should -Be 'changed since the preview; nothing changed.'
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)\Added" | Should -BeTrue
            @((Get-Item -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)").Property).Count | Should -Be 4
        }

        It 'gives Failed "Nothing changed" for a value of an Unknown kind added after the preview, with the key in place' {
            $scan = Get-TestScan -Category uninstall, run
            $plan = Get-IgwtRegCleanPlan -Findings @((Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone), (Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray'))
            Mock Get-IgwtRegCleanKeySnapshot -ModuleName iGWindowsTuner { throw "Cannot be backed up exactly: a value of kind 'Unknown' cannot be restored." }
            $res = Invoke-IgwtRegistryCleanup -Plan $plan -SkipRestorePoint -Confirm:$false
            $r1 = $res.Results | Where-Object Path -EQ $script:UninstallGone
            $r1.Result | Should -Be 'Failed'
            $r1.Message | Should -BeLike 'Nothing changed: Cannot be backed up exactly*'
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeTrue
            ($res.Results | Where-Object ValueName -EQ 'ContosoTray').Result | Should -Be 'Removed'
            # The engine path: a Get that throws ends the step before its intent.
            $t = Invoke-InIgwt { param($f) Get-IgwtRegCleanTarget -Finding $f } @($plan.Targets | Where-Object Kind -EQ 'regKeyTree')
            $r = Invoke-InIgwt {
                param($x)
                $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'unknown kind' -Confirm:$false
                try { Invoke-IgwtChangeStep -Session $s -Target $x -Desired ([ordered]@{ action = 'remove' }) -Group 'g' -Confirm:$false } finally { Complete-IgwtChangeSession -Session $s }
            } @($t)
            $r.Result | Should -Be 'Failed'
            $r.Message | Should -BeLike 'Nothing changed: Cannot be backed up exactly*'
        }

        It 'rolls back when the read-back fails and stops the session (the rest is NotStarted)' {
            $scan = Get-TestScan -Category uninstall, run
            $before = Get-TestKeySnapshot HKLM $script:UninstallGone
            Mock Remove-IgwtRegCleanKeyTree -ModuleName iGWindowsTuner { }
            $res = Invoke-TestCleanup @((Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone), (Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray'))
            $r1 = $res.Results | Where-Object Path -EQ $script:UninstallGone
            $r1.Result | Should -Be 'Failed'
            $r1.Message | Should -BeLike '*still there*'
            ($res.Results | Where-Object ValueName -EQ 'ContosoTray').Result | Should -Be 'NotStarted'
            (Get-Item -LiteralPath "TestRegistry:\HKLM\$($script:RunKey)").GetValue('ContosoTray') | Should -Not -BeNullOrEmpty
            Get-TestKeySnapshot HKLM $script:UninstallGone | Should -BeExactly $before
            @(Get-TestSessionEntries $res.SessionId | Where-Object { $_['kind'] -eq 'rolledBack' }).Count | Should -Be 1
        }

        It 'rolls a partial bottom-up removal back exactly (the root key cannot be deleted)' {
            $p = 'TestRegistry:\HKLM\SOFTWARE\ContosoGone\App'
            foreach ($s in 'Sub1', 'Sub2') { $null = New-Item -Path "$p\$s" -Force; $null = New-ItemProperty -LiteralPath "$p\$s" -Name 'Count' -Value 7 -PropertyType DWord }
            $scan = Get-TestScan -Category softwareKey
            $before = Get-TestKeySnapshot HKLM 'SOFTWARE\ContosoGone\App'
            $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $deny = New-Object System.Security.AccessControl.RegistryAccessRule($me, [System.Security.AccessControl.RegistryRights]::Delete, [System.Security.AccessControl.AccessControlType]::Deny)
            $k = Get-TestRawKey $p ([System.Security.AccessControl.RegistryRights]'ReadKey, ChangePermissions')
            try { $acl = $k.GetAccessControl(); $acl.AddAccessRule($deny); $k.SetAccessControl($acl) } finally { $k.Dispose() }
            try {
                $res = Invoke-TestCleanup @(Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone\App')
                $res.Results[0].Result | Should -Be 'Failed'
                $res.Results[0].Message | Should -Not -BeLike '*Rollback:*'
                Get-TestKeySnapshot HKLM 'SOFTWARE\ContosoGone\App' | Should -BeExactly $before
                @(Get-TestSessionEntries $res.SessionId | Where-Object { $_['kind'] -eq 'rolledBack' }).Count | Should -Be 1
            } finally {
                $k = Get-TestRawKey $p ([System.Security.AccessControl.RegistryRights]'ReadKey, ChangePermissions')
                try { $acl = $k.GetAccessControl(); $null = $acl.RemoveAccessRule($deny); $k.SetAccessControl($acl) } finally { $k.Dispose() }
            }
        }

        It 'maps a firewall delete the firewall refused (Changes 0) to Refused with no rollback' {
            $scan = Get-TestScan -Category firewallRule
            Mock Invoke-IgwtFirewallChange -ModuleName iGWindowsTuner { [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @([pscustomobject]@{ Target = 'x'; Change = 'Delete'; Result = 'Refused'; Message = 'Delete is locked for this rule' }) } }
            $res = Invoke-TestCleanup @(Find-TestFinding -Scan $scan -Category 'firewallRule' -Rule $script:RuleAllow)
            $res.Results[0].Result | Should -Be 'Refused'
            $res.Results[0].Message | Should -BeLike 'the firewall rule was not deleted (Delete is locked for this rule)*'
            @($script:FwRules | Where-Object Name -EQ $script:RuleAllow).Count | Should -Be 1
            @(Get-TestSessionEntries $res.SessionId | Where-Object { $_['kind'] -in 'rolledBack', 'rollbackFailed' }).Count | Should -Be 0
        }

        It 'ends with nothing changed when the private backup folder cannot be created' {
            $scan = Get-TestScan -Category uninstall
            Mock New-IgwtPrivateBackupFolder -ModuleName iGWindowsTuner { throw 'Backup failed: the private folder could not be created (Attempted to perform an unauthorized operation.); nothing changed.' }
            $res = Invoke-TestCleanup @(Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone)
            $res.Results[0].Result | Should -Be 'NotStarted'
            $res.Message | Should -BeLike 'Backup failed*nothing changed*'
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeTrue
            @(Get-TestSessionEntries $res.SessionId | Where-Object { $_['kind'] -eq 'intent' }).Count | Should -Be 0
            (Invoke-InIgwt { $script:IgwtRegCleanStep }) | Should -BeNullOrEmpty
        }

        It 'refuses a stale plan, a plan of mixed scans and a plan with nested targets' {
            $scan = Get-TestScan -Category softwareKey
            $plan = Get-IgwtRegCleanPlan -Findings @(Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone')
            $old = $plan | Select-Object *
            $old.Generated = (Get-Date).AddMinutes(-11).ToString('o')
            { Invoke-IgwtRegistryCleanup -Plan $old -SkipRestorePoint -Confirm:$false } | Should -Throw '*older than 10 minutes*'
            $mixed = $plan | Select-Object *
            $mixed.ScanId = 'other'
            { Invoke-IgwtRegistryCleanup -Plan $mixed -SkipRestorePoint -Confirm:$false } | Should -Throw '*different scans*'
            $nested = $plan | Select-Object *
            $nested.Targets = @($plan.Targets[0], (Find-TestFinding -Scan $scan -Category 'softwareKey' 'SOFTWARE\ContosoGone\App'))
            { Invoke-IgwtRegistryCleanup -Plan $nested -SkipRestorePoint -Confirm:$false } | Should -Throw 'Refused:*lies inside*'
            Test-Path -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\ContosoGone\App' | Should -BeTrue
        }
    }

    Context 'engine integration (RG14, RG16, RG21)' {
        It 'refuses Set without the cleanup context of this session (a change step outside the writer)' {
            $scan = Get-TestScan -Category uninstall
            $t = Invoke-InIgwt { param($f) Get-IgwtRegCleanTarget -Finding $f } @(Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone)
            $r = Invoke-InIgwt {
                param($x)
                $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'test' }) -Title 'outside the writer' -Confirm:$false
                try { Invoke-IgwtChangeStep -Session $s -Target $x -Desired ([ordered]@{ action = 'remove'; session = $s.Id }) -Group 'g' -Confirm:$false } finally { Complete-IgwtChangeSession -Session $s }
            } @($t)
            $r.Result | Should -Be 'Failed'
            $r.Message | Should -BeLike 'Refused: a registry cleaner entry is removed only by Invoke-IgwtRegistryCleanup*'
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeTrue
        }

        It 'shows regClean rows in the timeline, the drift report and revert plans without any live-context function' {
            $scan = Get-TestScan -Category uninstall, run
            $res = Invoke-TestCleanup @((Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone), (Find-TestFinding -Scan $scan -Category 'run' $script:RunKey 'ContosoTray'))
            $res.Removed | Should -Be 2
            foreach ($fn in 'Get-IgwtRegCleanScanContext', 'Get-IgwtRegCleanFinding', 'Get-IgwtRegCleanEvaluation', 'Test-IgwtRegCleanProtected', 'Get-IgwtRegCleanProtectionContext', 'Get-IgwtRegCleanOwnerIndex', 'Get-IgwtRegCleanExclusions', 'Get-IgwtRegCleanSecurityProducts') {
                Mock $fn -ModuleName iGWindowsTuner { throw 'a live-context function was called' }
            }
            $rows = @((Get-IgwtJournalTimeline).Rows | Where-Object { $_.Session -eq $res.SessionId })
            $rows.Count | Should -Be 2
            foreach ($r in $rows) {
                $r.Origin | Should -Be 'regClean'
                $r.Before | Should -Not -BeNullOrEmpty
                $r.After | Should -Be 'absent'
            }
            @($rows | Where-Object { $_.Target -like "*|$($script:UninstallGone)" })[0].Before | Should -Be 'keyTree 1 keys, 4 values'
            $keys = @($rows | ForEach-Object { $_.Target })
            $drift = @((Get-IgwtDriftReport -NoUpdateHistory).Rows | Where-Object { $keys -contains $_.Key })
            $drift.Count | Should -Be 2
            @($drift | Where-Object Status -NE 'StillApplied').Count | Should -Be 0
            @(Get-IgwtRevertPlan -SessionId $res.SessionId | Where-Object Status -NE 'Ready').Count | Should -Be 0
            $null = New-Item -Path "TestRegistry:\HKLM\$($script:UninstallGone)" -Force
            @((Get-IgwtDriftReport -NoUpdateHistory).Rows | Where-Object { $_.Key -like "*|$($script:UninstallGone)" -and $keys -contains $_.Key })[0].Status | Should -Be 'Drifted'
        }

        It 'recovers an interrupted cleanup session (the key comes back from the journal)' {
            $scan = Get-TestScan -Category uninstall
            $f = Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone
            $before = Get-TestKeySnapshot HKLM $script:UninstallGone
            $sid = Invoke-InIgwt {
                param($fd)
                $t = Get-IgwtRegCleanTarget -Finding $fd
                $s = Start-IgwtChangeSession -Origin ([ordered]@{ type = 'regClean'; ref = '' }) -Title 'Registry cleanup (1 entry)' -Confirm:$false
                $script:IgwtRegCleanStep = [pscustomobject]@{ SessionId = $s.Id; Lock = $script:IgwtChangeLock; Context = (Get-IgwtRegCleanScanContext); Findings = @{ ([string]$t['key']) = $fd }; Before = @{}; Backup = ''; FirewallSnapshots = [ordered]@{} }
                $r = Invoke-IgwtChangeStep -Session $s -Target $t -Desired ([ordered]@{ action = 'remove'; finding = $fd.Id; session = $s.Id }) -Group $fd.Id -Confirm:$false
                $script:IgwtRegCleanStep = $null
                if ($r.Result -ne 'Committed') { Complete-IgwtChangeSession -Session $s; throw $r.Message }
                # The process stops here: no sessionEnd, and the lock is gone with it.
                Exit-IgwtChangeLock
                $s.Id
            } @($f)
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeFalse
            @(Get-IgwtIncompleteChangeSession | Where-Object Id -EQ $sid).Count | Should -Be 1
            $rec = Invoke-IgwtChangeRecovery -SessionId $sid -Confirm:$false
            $rec.Complete | Should -BeTrue -Because (@($rec.Errors) -join '; ')
            Get-TestKeySnapshot HKLM $script:UninstallGone | Should -BeExactly $before
        }

        It 'stops before the session when System Protection is off (mocked restore point), and creates one otherwise' {
            $scan = Get-TestScan -Category uninstall
            $f = Find-TestFinding -Scan $scan -Category 'uninstall' $script:UninstallGone
            $count = { @(Invoke-InIgwt { @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' -and $_['origin'] -and [string]$_['origin']['type'] -eq 'regClean' }) }).Count }
            $n0 = & $count
            Mock New-IgwtRestorePoint -ModuleName iGWindowsTuner { [pscustomobject]@{ Created = $false; Reason = 'SystemProtectionDisabled' } }
            { Invoke-TestCleanup @($f) -WithRestorePoint } | Should -Throw '*System Protection is off*-EnableSystemProtection or -SkipRestorePoint*'
            (& $count) | Should -Be $n0
            Test-Path -LiteralPath "TestRegistry:\HKLM\$($script:UninstallGone)" | Should -BeTrue
            Mock New-IgwtRestorePoint -ModuleName iGWindowsTuner { [pscustomobject]@{ Created = $true; Reason = '' } }
            $res = Invoke-TestCleanup @($f) -WithRestorePoint -EnableSystemProtection
            $res.Removed | Should -Be 1
            $res.RestorePoint.Created | Should -BeTrue
            Should -Invoke New-IgwtRestorePoint -ModuleName iGWindowsTuner -Times 1 -Exactly -Scope It -ParameterFilter { $EnableSystemProtection }
            (& $count) | Should -Be ($n0 + 1)
        }
    }
}
