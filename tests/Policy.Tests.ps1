# 3.0 Group Policy engine: the Registry.pol (PReg) reader and writer, gpt.ini, Local GPO backup,
# restore and reset, the ADMX catalog, registry operations per element type, the denylist and the
# Set-IgwtLocalPolicy write path. The GPO folders are temporary copies in TestDrive, gpupdate and
# gpresult are mocked, and registry values live in TestRegistry.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    # A small ADMX/ADML pair written for these tests (not a Microsoft file).
    $script:AdmxDir = Join-Path $TestDrive 'PolicyDefinitions'
    $null = New-Item -ItemType Directory -Path (Join-Path $script:AdmxDir 'en-US') -Force
    $admx = @'
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="igtest" namespace="IGWT.Policies.Test" />
    <using prefix="windows" namespace="Microsoft.Policies.Windows" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <supportedOn><definitions><definition name="SUPPORTED_Test" displayName="$(string.SUPPORTED_Test)" /></definitions></supportedOn>
  <categories>
    <category name="Root" displayName="$(string.Root)" />
    <category name="Child" displayName="$(string.Child)"><parentCategory ref="Root" /></category>
  </categories>
  <policies>
    <policy name="Simple" class="Machine" displayName="$(string.Simple)" explainText="$(string.Simple_Help)" key="Software\Policies\IgwtTest" valueName="SimpleOn">
      <parentCategory ref="Child" /><supportedOn ref="SUPPORTED_Test" />
      <enabledValue><decimal value="1" /></enabledValue><disabledValue><decimal value="0" /></disabledValue>
    </policy>
    <policy name="Implicit" class="Both" displayName="$(string.Implicit)" explainText="$(string.Simple_Help)" key="Software\Policies\IgwtTest" valueName="ImplicitOn">
      <parentCategory ref="Child" /><supportedOn ref="SUPPORTED_Test" />
    </policy>
    <policy name="Elements" class="Machine" displayName="$(string.Elements)" explainText="$(string.Simple_Help)" key="Software\Policies\IgwtTest\Elements" presentation="$(presentation.Elements)">
      <parentCategory ref="Child" /><supportedOn ref="SUPPORTED_Test" />
      <elements>
        <decimal id="Days" valueName="Days" minValue="0" maxValue="365" />
        <decimal id="DaysText" valueName="DaysText" storeAsText="true" />
        <text id="Name" valueName="Name" maxLength="10" />
        <text id="PathX" valueName="PathX" expandable="true" />
        <multiText id="Lines" valueName="Lines" />
        <boolean id="Flag" valueName="Flag"><trueValue><decimal value="5" /></trueValue><falseValue><delete /></falseValue></boolean>
        <enum id="Mode" valueName="Mode">
          <item displayName="$(string.ModeA)"><value><decimal value="10" /></value></item>
          <item displayName="$(string.ModeB)"><value><string>bee</string></value><valueList><item valueName="ModeExtra"><value><decimal value="2" /></value></item></valueList></item>
        </enum>
        <list id="Hosts" key="Software\Policies\IgwtTest\Elements\Hosts" valuePrefix="Host" />
        <list id="Pairs" key="Software\Policies\IgwtTest\Elements\Pairs" explicitValue="true" additive="true" />
      </elements>
    </policy>
    <policy name="DefenderOff" class="Machine" displayName="$(string.DefenderOff)" explainText="$(string.Simple_Help)" key="Software\Policies\Microsoft\Windows Defender" valueName="DisableAntiSpyware">
      <parentCategory ref="Child" /><supportedOn ref="SUPPORTED_Test" />
      <enabledValue><decimal value="1" /></enabledValue><disabledValue><decimal value="0" /></disabledValue>
    </policy>
  </policies>
</policyDefinitions>
'@
    $adml = @'
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources revision="1.0" schemaVersion="1.0">
  <displayName>t</displayName><description>t</description>
  <resources>
    <stringTable>
      <string id="SUPPORTED_Test">Test systems</string>
      <string id="Root">Test Root</string>
      <string id="Child">Test Child</string>
      <string id="Simple">Turn on the simple setting</string>
      <string id="Simple_Help">Explain text with zebra word.</string>
      <string id="Implicit">Implicit value policy</string>
      <string id="Elements">Policy with elements</string>
      <string id="DefenderOff">Defender off test policy</string>
      <string id="ModeA">Mode A</string>
      <string id="ModeB">Mode B</string>
    </stringTable>
    <presentationTable>
      <presentation id="Elements">
        <decimalTextBox refId="Days" defaultValue="30">Days</decimalTextBox>
        <textBox refId="Name"><label>Name label</label></textBox>
        <checkBox refId="Flag" defaultChecked="true">Flag</checkBox>
        <dropdownList refId="Mode" defaultItem="0">Mode</dropdownList>
      </presentation>
    </presentationTable>
  </resources>
</policyDefinitionResources>
'@
    [IO.File]::WriteAllText((Join-Path $script:AdmxDir 'IgwtTest.admx'), $admx)
    [IO.File]::WriteAllText((Join-Path $script:AdmxDir 'en-US\IgwtTest.adml'), $adml)

    function ConvertTo-TestPolBytes([object[]]$Entries) { InModuleScope iGWindowsTuner -Parameters @{ E = $Entries } { param($E) ConvertTo-IgwtRegistryPolBytes -Entries $E } }
    function Get-TestPolEntry([string]$Key, [string]$Name, [int]$Type, $Value) {
        InModuleScope iGWindowsTuner -Parameters @{ K = $Key; N = $Name; T = $Type; V = $Value } { param($K, $N, $T, $V) New-IgwtPolEntryObject -Key $K -ValueName $N -Type $T -Data (ConvertTo-IgwtPolData -Type $T -Value $V) }
    }
}

Describe 'Group Policy engine' {
    BeforeEach {
        $script:GpoRoot = Join-Path $TestDrive ('GroupPolicy-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:GpoUsers = "$script:GpoRoot-Users"
        InModuleScope iGWindowsTuner -Parameters @{ R = $script:GpoRoot; U = $script:GpoUsers; A = $script:AdmxDir } {
            param($R, $U, $A)
            $script:IgwtSettings.GpoRoot = $R; $script:IgwtSettings.GpoUsersRoot = $U; $script:IgwtSettings.AdmxFolders = @($A)
            $script:IgwtAdmxCache = $null; $script:IgwtDomainRsop = $null
        }
        Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $true } }
    }

    AfterAll {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.GpoRoot = $null; $script:IgwtSettings.GpoUsersRoot = $null; $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null }
    }

    Describe 'Registry.pol reader and writer' {
        It 'round-trips entries of every type byte for byte' {
            $entries = @(
                (Get-TestPolEntry 'Software\Policies\A' 'Dw' 4 7),
                (Get-TestPolEntry 'Software\Policies\A' 'Qw' 11 ([uint64]5000000000)),
                (Get-TestPolEntry 'Software\Policies\A' 'Str' 1 'hello'),
                (Get-TestPolEntry 'Software\Policies\A' 'Exp' 2 '%SystemRoot%\x'),
                (Get-TestPolEntry 'Software\Policies\A' 'Multi' 7 @('one', 'two')),
                (Get-TestPolEntry 'Software\Policies\A' 'Bin' 3 ([byte[]](1, 2, 3, 0, 255))),
                (Get-TestPolEntry 'Software\Policies\A' '' 0 $null)
            )
            $bytes = ConvertTo-TestPolBytes $entries
            $read = InModuleScope iGWindowsTuner -Parameters @{ B = $bytes } { param($B) Read-IgwtRegistryPol -Bytes $B }
            @($read.Entries).Count | Should -Be 7
            $read.Entries[0].Value | Should -Be 7
            $read.Entries[1].Value | Should -Be ([uint64]5000000000)
            $read.Entries[2].Value | Should -Be 'hello'
            $read.Entries[3].TypeName | Should -Be 'ExpandString'
            @($read.Entries[4].Value) | Should -Be @('one', 'two')
            @($read.Entries[5].Value) | Should -Be @(1, 2, 3, 0, 255)
            $read.Entries[6].ValueName | Should -Be ''
            [Convert]::ToBase64String((ConvertTo-TestPolBytes $read.Entries)) | Should -Be ([Convert]::ToBase64String($bytes))
        }
        It 'starts with the PReg signature and version 1' {
            $bytes = ConvertTo-TestPolBytes @()
            $bytes.Length | Should -Be 8
            [Text.Encoding]::ASCII.GetString($bytes, 0, 4) | Should -Be 'PReg'
            [BitConverter]::ToUInt32($bytes, 4) | Should -Be 1
        }
        It 'keeps Unicode, semicolons and brackets in names and data' {
            $key = "Software\Policies\$([char]0xDC)n$([char]0xEF);[k]"; $data = "Daten; [$([char]0xFC)] $([char]0x20AC) $([char]0x65E5)"
            $e = @((Get-TestPolEntry $key 'Wert;]' 1 $data))
            $read = InModuleScope iGWindowsTuner -Parameters @{ B = (ConvertTo-TestPolBytes $e) } { param($B) Read-IgwtRegistryPol -Bytes $B }
            $read.Entries[0].Key | Should -Be $key
            $read.Entries[0].ValueName | Should -Be 'Wert;]'
            $read.Entries[0].Value | Should -Be $data
        }
        It 'recognizes the special value names' {
            $names = '**del.Foo', '**delvals.', '**DeleteValues', '**DeleteKeys', '**SecureKey', '**soft.Bar'
            $e = @($names | ForEach-Object { Get-TestPolEntry 'Software\Policies\S' $_ 1 ' ' })
            $read = InModuleScope iGWindowsTuner -Parameters @{ B = (ConvertTo-TestPolBytes $e) } { param($B) Read-IgwtRegistryPol -Bytes $B }
            @($read.Entries | ForEach-Object { $_.Special }) | Should -Be @('del', 'delvals', 'DeleteValues', 'DeleteKeys', 'SecureKey', 'soft')
        }
        It 'handles a large file' {
            $bytes = InModuleScope iGWindowsTuner { ConvertTo-IgwtRegistryPolBytes -Entries @(1..3000 | ForEach-Object { New-IgwtPolEntryObject -Key "Software\Policies\Big\K$($_ % 50)" -ValueName "V$_" -Type 4 -Data ([BitConverter]::GetBytes([uint32]$_)) }) }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $read = InModuleScope iGWindowsTuner -Parameters @{ B = $bytes } { param($B) Read-IgwtRegistryPol -Bytes $B }
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
            @($read.Entries).Count | Should -Be 3000
            $read.Entries[2999].Value | Should -Be 3000
        }
        It 'refuses corrupted files with the offset' {
            $good = ConvertTo-TestPolBytes @((Get-TestPolEntry 'Software\Policies\C' 'V' 4 1))
            $bad = [byte[]]$good.Clone(); $bad[0] = 0x41
            { InModuleScope iGWindowsTuner -Parameters @{ B = $bad } { param($B) Read-IgwtRegistryPol -Bytes $B } } | Should -Throw '*signature*'
            $v2 = [byte[]]$good.Clone(); $v2[4] = 2
            { InModuleScope iGWindowsTuner -Parameters @{ B = $v2 } { param($B) Read-IgwtRegistryPol -Bytes $B } } | Should -Throw '*version 2*'
            $trunc = [byte[]]$good[0..($good.Length - 4)]
            { InModuleScope iGWindowsTuner -Parameters @{ B = $trunc } { param($B) Read-IgwtRegistryPol -Bytes $B } } | Should -Throw '*corrupted at offset*'
            { InModuleScope iGWindowsTuner { Read-IgwtRegistryPol -Bytes ([byte[]](1, 2, 3)) } } | Should -Throw '*header*'
            $junk = [byte[]]($good + [byte[]](0x41, 0))
            { InModuleScope iGWindowsTuner -Parameters @{ B = $junk } { param($B) Read-IgwtRegistryPol -Bytes $B } } | Should -Throw '*corrupted at offset*expected*'
            $odd = [byte[]]($good[0..9] + [byte[]](0x41))
            { InModuleScope iGWindowsTuner -Parameters @{ B = $odd } { param($B) Read-IgwtRegistryPol -Bytes $B } } | Should -Throw '*unterminated string*'
        }
        It 'returns Exists false for a missing file' {
            $r = InModuleScope iGWindowsTuner -Parameters @{ P = (Join-Path $TestDrive 'none.pol') } { param($P) Read-IgwtRegistryPol -Path $P }
            $r.Exists | Should -BeFalse
            @($r.Entries).Count | Should -Be 0
        }
        It 'sets, removes and marks values without touching other entries' {
            $keep = Get-TestPolEntry 'Software\Policies\Other' 'Keep' 4 9
            InModuleScope iGWindowsTuner -Parameters @{ K = $keep } {
                param($K)
                $l = @(Set-IgwtPolEntry -Entries @($K) -Key 'Software\Policies\T' -ValueName 'V' -Type 4 -Value 1)
                $l = @(Set-IgwtPolEntry -Entries $l -Key 'software\policies\t' -ValueName 'v' -Type 4 -Value 2)
                $l.Count | Should -Be 2
                $l[1].Value | Should -Be 2
                [Convert]::ToBase64String((ConvertTo-IgwtPolEntryBytes -Entry $l[0])) | Should -Be ([Convert]::ToBase64String((ConvertTo-IgwtPolEntryBytes -Entry $K)))
                $l = @(Add-IgwtPolDeleteMarker -Entries $l -Key 'Software\Policies\T' -ValueName 'V')
                @($l | ForEach-Object { $_.ValueName }) | Should -Be @('Keep', '**del.V')
                $l = @(Set-IgwtPolEntry -Entries $l -Key 'Software\Policies\T' -ValueName 'V' -Type 4 -Value 3)
                @($l | ForEach-Object { $_.ValueName }) | Should -Be @('Keep', 'V')
                $l = @(Remove-IgwtPolEntry -Entries $l -Key 'Software\Policies\T' -ValueName 'V')
                @($l | ForEach-Object { $_.ValueName }) | Should -Be @('Keep')
            }
        }
        It 'writes atomically only inside the Local GPO folders' {
            $path = Join-Path $script:GpoRoot 'Machine\Registry.pol'
            InModuleScope iGWindowsTuner -Parameters @{ P = $path } {
                param($P)
                Write-IgwtRegistryPol -Path $P -Entries @(New-IgwtPolEntryObject -Key 'Software\Policies\W' -ValueName 'V' -Type 4 -Data ([BitConverter]::GetBytes([uint32]1)))
                Write-IgwtRegistryPol -Path $P -Entries @(New-IgwtPolEntryObject -Key 'Software\Policies\W' -ValueName 'V' -Type 4 -Data ([BitConverter]::GetBytes([uint32]2)))
                (Read-IgwtRegistryPol -Path $P).Entries[0].Value | Should -Be 2
                Test-Path -LiteralPath "$P.igwt-tmp" | Should -BeFalse
                { Write-IgwtRegistryPol -Path (Join-Path $TestDrive 'elsewhere\Registry.pol') -Entries @() } | Should -Throw '*outside the Local Group Policy folders*'
                { Write-IgwtRegistryPol -Path (Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Registry.pol') -Entries @() } | Should -Throw '*TestMode safety*'
            }
        }
        It 'refuses the real Group Policy store in TestMode even when it is configured as the root' {
            InModuleScope iGWindowsTuner {
                $saved = $script:IgwtSettings.GpoRoot
                try {
                    $script:IgwtSettings.GpoRoot = Join-Path $env:SystemRoot 'System32\GroupPolicy'
                    { Assert-IgwtGpoPathAllowed -Path (Join-Path $env:SystemRoot 'System32\GroupPolicy\gpt.ini') } | Should -Throw '*TestMode safety*'
                } finally { $script:IgwtSettings.GpoRoot = $saved }
            }
        }
    }

    Describe 'gpt.ini' {
        It 'increments the machine half and registers the registry extension' {
            InModuleScope iGWindowsTuner {
                $t = Update-IgwtGptIniText -Text '' -Class Machine
                $g = Read-IgwtGptIni -Text $t
                $g.Version | Should -Be 1
                $g.MachineExtensions | Should -Be '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
                $t | Should -Match '^\[General\]\r\n'
            }
        }
        It 'increments the user half (high 16 bits) and keeps other lines' {
            InModuleScope iGWindowsTuner {
                $src = "[General]`r`ngPCFunctionalityVersion=2`r`nVersion=65539`r`ngPCUserExtensionNames=[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]`r`n"
                $g = Read-IgwtGptIni -Text (Update-IgwtGptIniText -Text $src -Class User)
                $g.UserVersion | Should -Be 2
                $g.MachineVersion | Should -Be 3
                $g.Version | Should -Be (2 * 65536 + 3)
                (Update-IgwtGptIniText -Text $src -Class User) | Should -Match 'gPCFunctionalityVersion=2'
            }
        }
        It 'wraps the 16-bit version' {
            InModuleScope iGWindowsTuner { (Read-IgwtGptIni -Text (Update-IgwtGptIniText -Text "[General]`r`nVersion=65535" -Class Machine)).Version | Should -Be 0 }
        }
        It 'keeps extension lists sorted by CSE and merges tools' {
            InModuleScope iGWindowsTuner {
                $l = Add-IgwtCseToList -List '' -Cse $script:IgwtSecurityCse -Tool $script:IgwtSecurityTool
                $l = Add-IgwtCseToList -List $l -Cse $script:IgwtRegistryCse -Tool $script:IgwtRegistryTool
                $l = Add-IgwtCseToList -List $l -Cse $script:IgwtRegistryCse -Tool $script:IgwtRegistryTool
                $l | Should -Be '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
                $l2 = Add-IgwtCseToList -List '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957E-509E-11D1-A7CC-0000F87571E3}]' -Cse $script:IgwtRegistryCse -Tool $script:IgwtRegistryTool
                $l2 | Should -Be '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957E-509E-11D1-A7CC-0000F87571E3}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
            }
        }
    }

    Describe 'Local GPO backup, restore and reset' {
        BeforeEach {
            $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoRoot 'Machine') -Force
            $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoUsers 'S-1-5-32-545\User') -Force
            [IO.File]::WriteAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol'), (ConvertTo-TestPolBytes @((Get-TestPolEntry 'Software\Policies\B' 'V' 4 1))))
            [IO.File]::WriteAllText((Join-Path $script:GpoRoot 'gpt.ini'), "[General]`r`nVersion=1`r`n")
            [IO.File]::WriteAllText((Join-Path $script:GpoUsers 'S-1-5-32-545\User\Registry.pol'), 'x')
            Mock -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate { }
        }
        It 'backs up both folders with a SHA256 manifest and restores them exactly' {
            $b = InModuleScope iGWindowsTuner { Backup-IgwtLocalGpo -Reason 'test' }
            $m = Get-Content -LiteralPath (Join-Path $b 'manifest.json') -Raw | ConvertFrom-Json
            $m.kind | Should -Be 'igwt-gpo-backup'
            @($m.files).Count | Should -Be 3
            $orig = (Get-FileHash (Join-Path $script:GpoRoot 'Machine\Registry.pol')).Hash
            Remove-Item -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol')
            [IO.File]::WriteAllText((Join-Path $script:GpoRoot 'new.txt'), 'added after the backup')
            $r = InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Restore-IgwtLocalGpo -BackupPath $B }
            $r.Files | Should -Be 3
            (Get-FileHash (Join-Path $script:GpoRoot 'Machine\Registry.pol')).Hash | Should -Be $orig
            Test-Path -LiteralPath (Join-Path $script:GpoRoot 'new.txt') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $script:GpoUsers 'S-1-5-32-545\User\Registry.pol') | Should -BeTrue
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate -Times 1 -ParameterFilter { $Target -eq 'Both' }
        }
        It 'refuses a tampered backup and changes nothing' {
            $b = InModuleScope iGWindowsTuner { Backup-IgwtLocalGpo }
            [IO.File]::WriteAllText((Join-Path $b 'GroupPolicy\gpt.ini'), 'tampered')
            [IO.File]::WriteAllText((Join-Path $script:GpoRoot 'gpt.ini'), 'current')
            { InModuleScope iGWindowsTuner -Parameters @{ B = $b } { param($B) Restore-IgwtLocalGpo -BackupPath $B } } | Should -Throw '*was changed; nothing was restored*'
            Get-Content -LiteralPath (Join-Path $script:GpoRoot 'gpt.ini') -Raw | Should -Be 'current'
            { InModuleScope iGWindowsTuner -Parameters @{ B = $TestDrive } { param($B) Restore-IgwtLocalGpo -BackupPath $B } } | Should -Throw '*manifest.json missing*'
        }
        It 'previews and resets the Local GPO after a backup' {
            $plan = InModuleScope iGWindowsTuner { Get-IgwtLocalGpoResetPlan }
            @($plan.Files).Count | Should -Be 3
            $plan.Basis | Should -Match 'reversible'
            $r = InModuleScope iGWindowsTuner { Reset-IgwtLocalGpo }
            @(Get-ChildItem -LiteralPath $script:GpoRoot -Recurse -File).Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $script:GpoUsers -Recurse -File).Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $r.Backup 'GroupPolicy\Machine\Registry.pol') | Should -BeTrue
            InModuleScope iGWindowsTuner -Parameters @{ B = $r.Backup } { param($B) $null = Restore-IgwtLocalGpo -BackupPath $B -NoRefresh }
            Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeTrue
        }
        It 'never runs gpupdate in TestMode' {
            { InModuleScope iGWindowsTuner { & (Get-Command Invoke-IgwtGpUpdate -CommandType Function).ScriptBlock -Target Machine } } | Should -Throw '*TestMode safety*'
        }
    }

    Describe 'ADMX catalog' {
        It 'parses the test definitions: ids, category path, supportedOn, explain text and elements' {
            $c = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force }
            @($c.Errors).Count | Should -Be 0
            @($c.Policies).Count | Should -Be 4
            $p = InModuleScope iGWindowsTuner { Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple' }
            $p.CategoryPath | Should -Be 'Test Root > Test Child'
            $p.SupportedOn | Should -Be 'Test systems'
            $p.DisplayName | Should -Be 'Turn on the simple setting'
            $p.EnabledValue.Value | Should -Be 1
            $e = InModuleScope iGWindowsTuner { Get-IgwtPolicyDefinition -Id 'Elements' }
            @($e.Elements | ForEach-Object { $_.Type }) | Should -Be @('decimal', 'decimal', 'text', 'text', 'multiText', 'boolean', 'enum', 'list', 'list')
            ($e.Elements | Where-Object Id -EQ 'Days').Default | Should -Be '30'
            ($e.Elements | Where-Object Id -EQ 'Days').Max | Should -Be 365
            ($e.Elements | Where-Object Id -EQ 'Name').Label | Should -Be 'Name label'
            ($e.Elements | Where-Object Id -EQ 'Mode').Items[1].DisplayName | Should -Be 'Mode B'
        }
        It 'searches by name, explain text and registry path, with a class filter' {
            $null = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force }
            @(InModuleScope iGWindowsTuner { Find-IgwtPolicy -Search 'zebra' }).Count | Should -Be 4
            @(InModuleScope iGWindowsTuner { Find-IgwtPolicy -Search 'simpleon' }).Count | Should -Be 1
            @(InModuleScope iGWindowsTuner { Find-IgwtPolicy -Search 'elements hosts' }).Count | Should -Be 1
            @(InModuleScope iGWindowsTuner { Find-IgwtPolicy -Search 'policy' -Class User }).Id | Should -Be 'IgwtTest:Implicit'
            { InModuleScope iGWindowsTuner { Get-IgwtPolicyDefinition -Id 'IgwtTest:Nope' } } | Should -Throw '*Unknown policy*'
        }
        It 'caches the parsed catalog on disk and reloads it' {
            $null = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force }
            @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'IgwtData\Cache') -Filter 'admx-*.xml').Count | Should -BeGreaterThan 0
            $c = InModuleScope iGWindowsTuner { $script:IgwtAdmxCache = $null; Get-IgwtAdmxCatalog }
            @($c.Policies).Count | Should -Be 4
        }
        It 'records a broken ADMX file as an error and keeps the others' {
            $dir = Join-Path $TestDrive 'BrokenAdmx'
            $null = New-Item -ItemType Directory -Path $dir -Force
            Copy-Item -LiteralPath (Join-Path $script:AdmxDir 'IgwtTest.admx') -Destination $dir
            [IO.File]::WriteAllText((Join-Path $dir 'Broken.admx'), '<policyDefinitions><unclosed>')
            $r = InModuleScope iGWindowsTuner -Parameters @{ D = $dir } { param($D) Read-IgwtAdmxFolder -Folder $D }
            $r.Errors.Count | Should -Be 1
            $r.Files.Count | Should -Be 1
        }
        It 'parses a sample of the Windows definitions of this PC without errors' {
            $sys = Join-Path $env:SystemRoot 'PolicyDefinitions'
            $names = 'WindowsUpdate.admx', 'DataCollection.admx', 'WindowsDefender.admx', 'Sensors.admx'
            $present = @($names | Where-Object { Test-Path -LiteralPath (Join-Path $sys $_) })
            if ($present.Count -eq 0) { Set-ItResult -Skipped -Because 'no PolicyDefinitions on this PC'; return }
            $dir = Join-Path $TestDrive 'SysSample'
            $null = New-Item -ItemType Directory -Path (Join-Path $dir 'en-US') -Force
            foreach ($n in $present) {
                Copy-Item -LiteralPath (Join-Path $sys $n) -Destination $dir
                $l = Join-Path $sys ('en-US\' + [IO.Path]::ChangeExtension($n, '.adml'))
                if (Test-Path -LiteralPath $l) { Copy-Item -LiteralPath $l -Destination (Join-Path $dir 'en-US') }
            }
            $r = InModuleScope iGWindowsTuner -Parameters @{ D = $dir } { param($D) Read-IgwtAdmxFolder -Folder $D }
            @($r.Errors).Count | Should -Be 0 -Because (@($r.Errors) -join '; ')
            $all = @($r.Files | ForEach-Object { $_.Policies })
            $all.Count | Should -BeGreaterThan 20
            @($all | Where-Object { -not $_.Key }).Count | Should -Be 0
            if ($present -contains 'WindowsUpdate.admx') { @($all | Where-Object Id -EQ 'WindowsUpdate:DeferFeatureUpdates').Count | Should -Be 1 }
        }
    }

    Describe 'Registry operations per element type' {
        BeforeEach { $null = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force } }
        It 'writes enabledValue and disabledValue' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple'
                $on = @(Get-IgwtPolicyRegistryOps -Policy $p -State Enabled)
                $on.Count | Should -Be 1
                "$($on[0].Op) $($on[0].ValueName) $($on[0].Type) $($on[0].Value)" | Should -Be 'Set SimpleOn DWord 1'
                (@(Get-IgwtPolicyRegistryOps -Policy $p -State Disabled))[0].Value | Should -Be 0
                $nc = @(Get-IgwtPolicyRegistryOps -Policy $p -State NotConfigured)
                "$($nc[0].Op) $($nc[0].ValueName)" | Should -Be 'Remove SimpleOn'
            }
        }
        It 'uses 1 and 0 for a policy without explicit values' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Implicit'
                (@(Get-IgwtPolicyRegistryOps -Policy $p -State Enabled))[0].Value | Should -Be 1
                (@(Get-IgwtPolicyRegistryOps -Policy $p -State Disabled))[0].Value | Should -Be 0
            }
        }
        It 'maps every element type when enabled' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Elements'
                $ops = @(Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Days = 90; DaysText = 7; Name = 'abc'; PathX = '%TEMP%'; Lines = @('a', 'b'); Flag = $true; Mode = 'Mode B'; Hosts = @('h1', 'h2'); Pairs = @{ k1 = 'v1' } })
                $by = @{}; foreach ($o in $ops) { $by["$($o.Op)|$($o.ValueName)"] = $o }
                $by['Set|Days'].Type | Should -Be 'DWord'; $by['Set|Days'].Value | Should -Be 90
                $by['Set|DaysText'].Type | Should -Be 'String'; $by['Set|DaysText'].Value | Should -Be '7'
                $by['Set|Name'].Type | Should -Be 'String'
                $by['Set|PathX'].Type | Should -Be 'ExpandString'
                $by['Set|Lines'].Type | Should -Be 'MultiString'
                $by['Set|Flag'].Value | Should -Be 5
                $by['Set|Mode'].Value | Should -Be 'bee'; $by['Set|Mode'].Type | Should -Be 'String'
                $by['Set|ModeExtra'].Value | Should -Be 2
                $by['DeleteValues|'].Key | Should -Be 'Software\Policies\IgwtTest\Elements\Hosts'
                $by['Set|Host1'].Value | Should -Be 'h1'; $by['Set|Host2'].Value | Should -Be 'h2'
                $by['Set|k1'].Value | Should -Be 'v1'
                @($ops | Where-Object { $_.Op -eq 'DeleteValues' }).Count | Should -Be 1 -Because 'the additive list keeps its other values'
            }
        }
        It 'uses presentation defaults, enum indexes and the boolean false value' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Elements'
                $ops = @(Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Flag = $false; Mode = 0 })
                ($ops | Where-Object ValueName -EQ 'Days').Value | Should -Be 30
                ($ops | Where-Object ValueName -EQ 'Mode').Value | Should -Be 10
                ($ops | Where-Object ValueName -EQ 'Flag').Op | Should -Be 'Delete'
            }
        }
        It 'validates ranges, lengths and enum options' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Elements'
                { Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Days = 400 } } | Should -Throw '*between 0 and 365*'
                { Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Name = 'way too long name' } } | Should -Throw '*longer than 10*'
                { Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Mode = 'Mode Z' } } | Should -Throw '*not an option*'
                { Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Pairs = @('x') } } | Should -Throw '*name=value*'
            }
        }
        It 'writes delete markers when disabled and removes everything when not configured' {
            InModuleScope iGWindowsTuner {
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Elements'
                $d = @(Get-IgwtPolicyRegistryOps -Policy $p -State Disabled)
                @($d | Where-Object Op -EQ 'Delete').Count | Should -Be 7
                @($d | Where-Object Op -EQ 'DeleteValues').Count | Should -Be 2
                $nc = @(Get-IgwtPolicyRegistryOps -Policy $p -State NotConfigured)
                @($nc | Where-Object Op -EQ 'RemoveKeyValues').Count | Should -Be 2
                @($nc | Where-Object { $_.Op -eq 'Remove' -and $_.ValueName -eq 'ModeExtra' }).Count | Should -Be 1
            }
        }
        It 'applies operations to entries as the Group Policy editor does' {
            InModuleScope iGWindowsTuner {
                $keep = New-IgwtPolEntryObject -Key 'Software\Policies\Keep' -ValueName 'K' -Type 4 -Data ([BitConverter]::GetBytes([uint32]1))
                $old = New-IgwtPolEntryObject -Key 'Software\Policies\IgwtTest\Elements\Hosts' -ValueName 'Host9' -Type 1 -Data ([Text.Encoding]::Unicode.GetBytes("old`0"))
                $p = Get-IgwtPolicyDefinition -Id 'IgwtTest:Elements'
                $ops = @(Get-IgwtPolicyRegistryOps -Policy $p -State Enabled -Values @{ Hosts = @('n1') })
                $after = @(Update-IgwtPolEntries -Entries @($keep, $old) -Ops $ops)
                @($after | Where-Object ValueName -EQ 'Host9').Count | Should -Be 0
                @($after | Where-Object ValueName -EQ '**delvals.').Count | Should -Be 1
                @($after | Where-Object ValueName -EQ 'K').Count | Should -Be 1
                $nc = @(Update-IgwtPolEntries -Entries $after -Ops @(Get-IgwtPolicyRegistryOps -Policy $p -State NotConfigured))
                @($nc | ForEach-Object { $_.ValueName }) | Should -Be @('K')
            }
        }
    }

    Describe 'Denylist' {
        It 'refuses security-disabling values and allows the safe direction' {
            InModuleScope iGWindowsTuner {
                $t = { param($k, $n, $v) Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = $k; ValueName = $n; Type = 'DWord'; Value = $v }) }
                & $t 'Software\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1 | Should -Match 'Defender'
                & $t 'Software\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 0 | Should -BeNullOrEmpty
                & $t 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'EnableFirewall' 0 | Should -Match 'Firewall'
                & $t 'Software\Policies\Microsoft\Windows Defender\Exclusions\Paths' 'C:\Games' 0 | Should -Match 'exclusions'
                & $t 'Software\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 0 | Should -Match 'User Account Control'
                & $t 'Software\Policies\Microsoft\Windows\DeviceGuard' 'HypervisorEnforcedCodeIntegrity' 0 | Should -Match 'memory integrity'
                & $t 'Software\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 1 | Should -Match 'Windows Update'
                & $t 'Software\Policies\Microsoft\Windows\WindowsUpdate' 'DeferFeatureUpdatesPeriodInDays' 90 | Should -BeNullOrEmpty
                Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Delete'; Key = 'Software\Policies\Microsoft\Windows Defender'; ValueName = 'DisableAntiSpyware'; Value = $null }) | Should -BeNullOrEmpty
            }
        }
        It 'every entry has a key, a value name, values and a reason, and its patterns compile' {
            foreach ($d in @((Get-Content (Join-Path $script:IgwtProjectRoot 'data\policy\denylist.json') -Raw | ConvertFrom-Json).entries)) {
                $d.reason | Should -Not -BeNullOrEmpty
                @($d.values).Count | Should -BeGreaterThan 0
                { [regex]::new([string]$d.key) } | Should -Not -Throw
                { [regex]::new([string]$d.valueName) } | Should -Not -Throw
            }
        }
        It 'refuses a plan that turns Defender off' {
            $null = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force }
            $plan = InModuleScope iGWindowsTuner { Get-IgwtPolicyChangePlan -Id 'IgwtTest:DefenderOff' -State Enabled }
            @($plan.Refusals).Count | Should -Be 1
            { InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:DefenderOff' -State Enabled -NoRefresh } } | Should -Throw '*Refused*'
            Test-Path -LiteralPath (Join-Path $script:GpoRoot 'Machine\Registry.pol') | Should -BeFalse
            (InModuleScope iGWindowsTuner { Get-IgwtPolicyChangePlan -Id 'IgwtTest:DefenderOff' -State Disabled }).Refusals.Count | Should -Be 0
        }
    }

    Describe 'Set-IgwtLocalPolicy' {
        BeforeEach {
            $null = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force }
            $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoRoot 'Machine') -Force
            [IO.File]::WriteAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol'), (ConvertTo-TestPolBytes @((Get-TestPolEntry 'Software\Policies\Existing' 'Keep' 4 3))))
            Remove-Item -LiteralPath 'TestRegistry:\HKLM\Software\Policies\IgwtTest' -Recurse -Force -ErrorAction SilentlyContinue
            # Simulated registry client-side extension: applies Registry.pol to TestRegistry.
            Mock -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate {
                foreach ($e in @(InModuleScope iGWindowsTuner { (Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine)).Entries })) {
                    $k = 'TestRegistry:\HKLM\' + $e.Key
                    if ($e.ValueName.StartsWith('**del.')) { Remove-ItemProperty -LiteralPath $k -Name ($e.ValueName.Substring(6)) -ErrorAction SilentlyContinue; continue }
                    if (-not $e.ValueName -or $e.ValueName.StartsWith('**')) { continue }
                    if (-not (Test-Path -LiteralPath $k)) { $null = New-Item -Path $k -Force }
                    $null = New-ItemProperty -LiteralPath $k -Name $e.ValueName -Value $e.Value -PropertyType $e.TypeName -Force
                }
            }
        }
        It 'backs up, writes Registry.pol and gpt.ini, refreshes and verifies' {
            $r = InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Enabled }
            $r.Verified | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $r.Backup 'manifest.json') | Should -BeTrue
            $entries = @((InModuleScope iGWindowsTuner { Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine) }).Entries)
            @($entries | ForEach-Object { $_.ValueName }) | Should -Be @('Keep', 'SimpleOn')
            $g = InModuleScope iGWindowsTuner { Read-IgwtGptIni -Text ([IO.File]::ReadAllText((Join-Path (Get-IgwtGpoRoot) 'gpt.ini'))) }
            $g.MachineVersion | Should -Be 1
            $g.MachineExtensions | Should -Match '35378EAC'
            (Get-ItemProperty -LiteralPath 'TestRegistry:\HKLM\Software\Policies\IgwtTest').SimpleOn | Should -Be 1
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate -Times 1 -ParameterFilter { $Target -eq 'Machine' }
            $s = InModuleScope iGWindowsTuner { Get-IgwtPolicyState -Policy (Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple') }
            $s.LocalGpo | Should -Be 'Enabled'
            $s.Source | Should -Be 'Local GPO'
            $s.Tattooed | Should -BeFalse
        }
        It 'reports a failed verification when policy did not apply' {
            Mock -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate { }
            $r = InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Enabled }
            $r.Verified | Should -BeFalse
            @($r.Mismatch) | Should -Be @('Software\Policies\IgwtTest\SimpleOn')
        }
        It 'reverts through the backup' {
            $before = (Get-FileHash (Join-Path $script:GpoRoot 'Machine\Registry.pol')).Hash
            $r = InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Disabled -NoRefresh }
            $null = InModuleScope iGWindowsTuner -Parameters @{ B = $r.Backup } { param($B) Restore-IgwtLocalGpo -BackupPath $B }
            (Get-FileHash (Join-Path $script:GpoRoot 'Machine\Registry.pol')).Hash | Should -Be $before
        }
        It 'refuses managed PCs unless acknowledged, and Home editions always' {
            Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; DomainJoined = $false; DomainName = ''; Authorities = @('Intune'); LocalGroupPolicy = $true } }
            { InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Enabled -NoRefresh } } | Should -Throw '*AcknowledgeManaged*'
            (InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Enabled -NoRefresh -AcknowledgeManaged }).State | Should -Be 'Enabled'
            Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $false } }
            { InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Enabled -NoRefresh } } | Should -Throw '*Windows Home*'
        }
        It 'refuses the wrong class' {
            { InModuleScope iGWindowsTuner { Get-IgwtPolicyChangePlan -Id 'IgwtTest:Simple' -State Enabled -Class User } } | Should -Throw '*Machine policy*'
        }
        It 'changes nothing with -WhatIf' {
            $before = (Get-FileHash (Join-Path $script:GpoRoot 'Machine\Registry.pol')).Hash
            $null = InModuleScope iGWindowsTuner { Set-IgwtLocalPolicy -Id 'IgwtTest:Simple' -State Enabled -WhatIf }
            (Get-FileHash (Join-Path $script:GpoRoot 'Machine\Registry.pol')).Hash | Should -Be $before
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtGpUpdate -Times 0
        }
    }

    Describe 'Effective state, sources and tattoos' {
        BeforeEach {
            $null = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force }
            Remove-Item -LiteralPath 'TestRegistry:\HKLM\Software\Policies' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager' -Recurse -Force -ErrorAction SilentlyContinue
        }
        It 'flags a registry value that no Registry.pol sets as tattooed' {
            $null = New-Item -Path 'TestRegistry:\HKLM\Software\Policies\IgwtTest' -Force
            $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\Software\Policies\IgwtTest' -Name 'SimpleOn' -Value 1 -PropertyType DWord
            $s = InModuleScope iGWindowsTuner { Get-IgwtPolicyState -Policy (Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple') }
            $s.LocalGpo | Should -Be 'NotConfigured'
            $s.Tattooed | Should -BeTrue
            $s.Source | Should -Be 'Registry only (tattooed)'
            $t = @(InModuleScope iGWindowsTuner { Get-IgwtTattooedPolicyValues })
            @($t | Where-Object { $_.Class -eq 'Machine' -and $_.ValueName -eq 'SimpleOn' -and $_.Key -eq 'Software\Policies\IgwtTest' }).Count | Should -Be 1
        }
        It 'does not flag values that the Local GPO sets' {
            $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoRoot 'Machine') -Force
            [IO.File]::WriteAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol'), (ConvertTo-TestPolBytes @((Get-TestPolEntry 'Software\Policies\IgwtTest' 'SimpleOn' 4 0))))
            $null = New-Item -Path 'TestRegistry:\HKLM\Software\Policies\IgwtTest' -Force
            $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\Software\Policies\IgwtTest' -Name 'SimpleOn' -Value 0 -PropertyType DWord
            $s = InModuleScope iGWindowsTuner { Get-IgwtPolicyState -Policy (Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple') }
            $s.LocalGpo | Should -Be 'Disabled'
            $s.Tattooed | Should -BeFalse
            @(InModuleScope iGWindowsTuner { Get-IgwtTattooedPolicyValues } | Where-Object ValueName -EQ 'SimpleOn').Count | Should -Be 0
        }
        It 'reports a domain GPO as the winning source and the conflict' {
            $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoRoot 'Machine') -Force
            [IO.File]::WriteAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol'), (ConvertTo-TestPolBytes @((Get-TestPolEntry 'Software\Policies\IgwtTest' 'SimpleOn' 4 1))))
            Mock -ModuleName iGWindowsTuner Get-IgwtDomainPolicyResult { @([pscustomobject]@{ Scope = 'Machine'; Key = 'Software\Policies\IgwtTest'; ValueName = 'SimpleOn'; Value = '0'; Gpo = 'Corp Baseline' }) }
            $s = InModuleScope iGWindowsTuner { Get-IgwtPolicyState -Policy (Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple') }
            $s.Source | Should -Be 'Domain GPO'
            @($s.Conflicts).Count | Should -Be 1
        }
        It 'reports an MDM value' {
            $null = New-Item -Path 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\IgwtArea' -Force
            $null = New-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\IgwtArea' -Name 'Simple' -Value 1 -PropertyType DWord
            $s = InModuleScope iGWindowsTuner { Get-IgwtPolicyState -Policy (Get-IgwtPolicyDefinition -Id 'IgwtTest:Simple') }
            $s.Source | Should -Be 'MDM'
            $s.Mdm.Area | Should -Be 'IgwtArea'
        }
        It 'parses gpresult XML registry settings' {
            $xml = @'
    <Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop"><ComputerResults><ExtensionData><Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/Registry">
    <q1:RegistrySetting><GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{A}</Identifier></GPO>
    <q1:KeyPath>Software\Policies\IgwtTest</q1:KeyPath><q1:Value><q1:Name>SimpleOn</q1:Name><q1:Number>1</q1:Number></q1:Value></q1:RegistrySetting>
    </Extension></ExtensionData></ComputerResults></Rsop>
'@
            $r = @(InModuleScope iGWindowsTuner -Parameters @{ X = $xml } { param($X) ConvertFrom-IgwtRsopXml -Xml $X })
            $r.Count | Should -Be 1
            $r[0].Scope | Should -Be 'Machine'
            $r[0].Key | Should -Be 'Software\Policies\IgwtTest'
            $r[0].ValueName | Should -Be 'SimpleOn'
            $r[0].Value | Should -Be '1'
            $r[0].Gpo | Should -Be '{A}'
        }
        It 'never runs gpresult in TestMode on a domain-joined PC' {
            Mock -ModuleName iGWindowsTuner Get-IgwtManagementState { [pscustomobject]@{ Managed = $true; DomainJoined = $true; DomainName = 'corp.example'; Authorities = @('Domain'); LocalGroupPolicy = $true } }
            { InModuleScope iGWindowsTuner { Get-IgwtDomainPolicyResult -Force } } | Should -Throw '*TestMode safety*'
        }
    }
}
