# Security Settings Manager, B2 (DECISIONS SM3, SM4, SM8, SM10, SM22): value specs, decoding
# Registry.pol entries, the round-trip and writability gate, the sceregvl.inf reader and rows.
# Pure functions over synthetic ADMX fixtures and in-memory entries.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Admx = Join-Path $PSScriptRoot 'fixtures\secsettings\admx'
    InModuleScope iGWindowsTuner -Parameters @{ A = $script:Admx } { param($A) $script:IgwtSettings.AdmxFolders = @($A); $script:IgwtAdmxCache = $null; $script:IgwtSecSettingsData = $null }
    $script:Cat = InModuleScope iGWindowsTuner { Get-IgwtAdmxCatalog -Force -NoCache }
    $script:Index = InModuleScope iGWindowsTuner -Parameters @{ C = $script:Cat } { param($C) Get-IgwtSecSettingOverlapIndex -Catalog $C }
    function Get-FixturePolicy([string]$Name) { @($script:Cat.Policies | Where-Object { $_.Name -eq $Name })[0] }
    function Get-Entries($Policy, [string]$State, [hashtable]$Values = @{}) {
        InModuleScope iGWindowsTuner -Parameters @{ P = $Policy; S = $State; V = $Values } { param($P, $S, $V) @(Update-IgwtPolEntries -Entries @() -Ops @(Get-IgwtPolicyRegistryOps -Policy $P -State $S -Values $V)) }
    }
    function Invoke-Decode($Policy, $Entries) { InModuleScope iGWindowsTuner -Parameters @{ P = $Policy; E = $Entries } { param($P, $E) ConvertFrom-IgwtPolicyEntries -Policy $P -Entries $E } }
    function Invoke-Gate($Policy, $Entries, $Index = @{}) { InModuleScope iGWindowsTuner -Parameters @{ P = $Policy; E = $Entries; I = $Index } { param($P, $E, $I) Test-IgwtSecSettingWritable -Policy $P -Entries $E -OverlapIndex $I } }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtSettings.AdmxFolders = $null; $script:IgwtAdmxCache = $null } }

Describe 'Value specs (SM4)' {
    It 'maps every ADMX element kind, with spin step, max strings and enum indexes' {
        $spec = InModuleScope iGWindowsTuner -Parameters @{ P = (Get-FixturePolicy 'AllKinds') } { param($P) ConvertTo-IgwtSecSettingValueSpec -SourceKind admx -Definition $P }
        $spec.Mode | Should -Be 'tristate'
        @($spec.Elements | ForEach-Object Kind) | Should -Be @('bool', 'decimal', 'longDecimal', 'text', 'multiText', 'enum', 'list', 'keyValueList')
        $dec = $spec.Elements | Where-Object Id -EQ 'DecEl'
        $dec.Min | Should -Be 1; $dec.Max | Should -Be 99; $dec.Step | Should -Be 5; $dec.Unit | Should -Be 'Minutes'
        ($spec.Elements | Where-Object Id -EQ 'MultiEl').MaxStrings | Should -Be 5
        @(($spec.Elements | Where-Object Id -EQ 'EnumEl').Choices | ForEach-Object { "$($_.Label)=$($_.Index)" }) | Should -Be @('Low=0', 'High=1')
    }
    It 'maps Defender catalog types, secpol display types and audit' {
        InModuleScope iGWindowsTuner {
            (ConvertTo-IgwtSecSettingValueSpec -SourceKind defender -Definition ([pscustomobject]@{ mp = 'ScanScheduleTime'; type = 'time'; edit = 'set'; name = 'Time' })).Elements[0].Kind | Should -Be 'time'
            $u = (ConvertTo-IgwtSecSettingValueSpec -SourceKind defender -Definition ([pscustomobject]@{ mp = 'X'; type = 'uint'; min = 5; max = 100; unit = 'percent'; edit = 'set'; name = 'X' })).Elements[0]
            "$($u.Kind) $($u.Min) $($u.Max) $($u.Unit)" | Should -Be 'decimal 5 100 percent'
            (ConvertTo-IgwtSecSettingValueSpec -SourceKind defender -Definition ([pscustomobject]@{ mp = 'Y'; type = 'bool'; edit = 'none'; name = 'Y' })).Mode | Should -Be 'none'
            (ConvertTo-IgwtSecSettingValueSpec -SourceKind secpol -Definition ([pscustomobject]@{ RegType = 4; DisplayType = 5; Name = 'N'; Choices = @([pscustomobject]@{ Value = 524288; Label = 'A' }) })).Elements[0].Kind | Should -Be 'flags'
            (ConvertTo-IgwtSecSettingValueSpec -SourceKind secpol -Definition ([pscustomobject]@{ RegType = 3; DisplayType = 2; Name = 'B' })).Mode | Should -Be 'none'
            @((ConvertTo-IgwtSecSettingValueSpec -SourceKind audit).Elements[0].Choices | ForEach-Object Value) | Should -Be @('None', 'Success', 'Failure', 'SuccessAndFailure')
        }
    }
}

Describe 'Decoding Registry.pol entries (SM10) and the round trip (SM8)' {
    It 'decodes every element kind of an Enabled policy and writes the same entries again' {
        $p = Get-FixturePolicy 'AllKinds'
        $values = @{ BoolEl = $false; DecEl = 42; LongEl = 4000000000; TextEl = 'srv01'; MultiEl = @('a', 'b'); EnumEl = 1; ListEl = @('one', 'two'); PairEl = @{ alpha = '1'; beta = '2' } }
        $entries = Get-Entries $p 'Enabled' $values
        $d = Invoke-Decode $p $entries
        $d.State | Should -Be 'Enabled'
        $d.Values.BoolEl | Should -BeFalse; $d.Values.DecEl | Should -Be 42; $d.Values.LongEl | Should -Be 4000000000
        $d.Values.TextEl | Should -Be 'srv01'; @($d.Values.MultiEl) | Should -Be @('a', 'b')
        $d.Values.EnumEl | Should -Be 'High'; $d.Indexes.EnumEl | Should -Be 1
        @($d.Values.ListEl) | Should -Be @('one', 'two'); $d.Values.PairEl.beta | Should -Be '2'
        (Invoke-Gate $p $entries).Writable | Should -BeTrue
    }
    It 'decodes Disabled and NotConfigured' {
        $p = Get-FixturePolicy 'AllKinds'
        (Invoke-Decode $p (Get-Entries $p 'Disabled')).State | Should -Be 'Disabled'
        (Invoke-Decode $p @()).State | Should -Be 'NotConfigured'
        (Invoke-Gate $p (Get-Entries $p 'Disabled')).Writable | Should -BeTrue
    }
    It 'ignores entries of other policies' {
        $p = Get-FixturePolicy 'AllKinds'
        $other = Get-Entries (Get-FixturePolicy 'LoggingSwitch') 'Enabled'
        (Invoke-Decode $p $other).State | Should -Be 'NotConfigured'
    }
    It 'keeps an enum with number-like labels at the right item by passing the Index' {
        $p = [pscustomobject]@{ Id = 'X:NumEnum'; Name = 'NumEnum'; Class = 'Machine'; Key = 'Software\Policies\Contoso\Num'; ValueName = 'On'; EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @()
            Elements = @([pscustomobject]@{ Type = 'enum'; Id = 'E'; Key = 'Software\Policies\Contoso\Num'; ValueName = 'Level'; Required = $false; Label = 'Level'; Default = $null
                    Items = @([pscustomobject]@{ DisplayName = '2'; Value = [pscustomobject]@{ Type = 'DWord'; Value = 7 }; ValueList = @() }, [pscustomobject]@{ DisplayName = '0'; Value = [pscustomobject]@{ Type = 'DWord'; Value = 9 }; ValueList = @() }, [pscustomobject]@{ DisplayName = '1'; Value = [pscustomobject]@{ Type = 'DWord'; Value = 3 }; ValueList = @() }) }) }
        $entries = Get-Entries $p 'Enabled' @{ E = 0 }
        $d = Invoke-Decode $p $entries
        $d.Values.E | Should -Be '2'; $d.Indexes.E | Should -Be 0
        (Invoke-Gate $p $entries).Writable | Should -BeTrue
    }
    It 'makes a policy read-only when its entries match no rule' {
        $p = Get-FixturePolicy 'LoggingSwitch'
        $odd = @(InModuleScope iGWindowsTuner { New-IgwtPolEntryObject -Key 'Software\Policies\Contoso\Log' -ValueName 'EnableAuditLogging' -Type 4 -Data ([BitConverter]::GetBytes([uint32]7)) })
        (Invoke-Decode $p $odd).State | Should -Be 'Configured'
        $g = Invoke-Gate $p $odd
        $g.Writable | Should -BeFalse; $g.Reason | Should -Match 'do not match'
    }
}

Describe 'Writability gate (SM8)' {
    It 'refuses an overlapping policy, a key outside the Policies keys and an unsupported element' {
        $g = Invoke-Gate (Get-FixturePolicy 'OverlapA') @() $script:Index
        $g.Writable | Should -BeFalse; $g.Reason | Should -Match 'Shares registry values with SecFixture:OverlapB'
        $outside = [pscustomobject]@{ Id = 'X:Out'; Class = 'Machine'; Key = 'System\CurrentControlSet\Control\Contoso'; ValueName = 'On'; EnabledList = @(); DisabledList = @(); Elements = @() }
        (Invoke-Gate $outside @()).Reason | Should -Match 'outside the Policies keys'
        $odd = [pscustomobject]@{ Id = 'X:Odd'; Class = 'Machine'; Key = 'Software\Policies\Contoso'; ValueName = 'On'; EnabledList = @(); DisabledList = @(); Elements = @([pscustomobject]@{ Type = 'futureKind'; Id = 'F' }) }
        (Invoke-Gate $odd @()).Reason | Should -Match 'not supported'
        $both = [pscustomobject]@{ Id = 'X:Both'; Class = 'Both'; Key = 'Software\Policies\Contoso'; ValueName = 'On'; EnabledList = @(); DisabledList = @(); Elements = @() }
        (Invoke-Gate $both @()).Writable | Should -BeFalse
    }
}

Describe 'sceregvl.inf reader (SM22)' {
    It 'reads keys, types, names, choices and units, and skips unreadable lines' {
        $rows = @(InModuleScope iGWindowsTuner -Parameters @{ P = (Join-Path $PSScriptRoot 'fixtures\secsettings\sceregvl-sample.inf') } { param($P) Read-IgwtSceRegVlInf -Path $P })
        $rows.Count | Should -Be 6
        $lm = $rows | Where-Object { $_.Key -like '*LmCompatibilityLevel' }
        $lm.DisplayType | Should -Be 3; @($lm.Choices | ForEach-Object Value) | Should -Be @(0, 1, 5)
        $lm.Choices[2].Label | Should -Be 'Send NTLMv2 response only. Refuse LM and NTLM'
        ($rows | Where-Object { $_.Key -like '*CachedLogonsCount' }).Unit | Should -Be 'logons'
        ($rows | Where-Object { $_.Key -like '*NTLMMinClientSec' }).Name | Should -Be '@wsecedit.dll,-59066'
        ($rows | Where-Object { $_.Key -like '*BinaryOption' }).RegType | Should -Be 3
    }
}

Describe 'Rows (SM3)' {
    It 'applies the Configured rule per source kind and the User-class wording' {
        InModuleScope iGWindowsTuner {
            (New-IgwtSecSettingRow -Fields @{ Id = 'admx:F:P:Machine'; SourceKind = 'admx'; State = 'NotConfigured' }).Configured | Should -BeFalse
            (New-IgwtSecSettingRow -Fields @{ Id = 'admx:F:P:Machine'; SourceKind = 'admx'; State = 'Disabled' }).Configured | Should -BeTrue
            (New-IgwtSecSettingRow -Fields @{ Id = 'exclusion:Path'; SourceKind = 'exclusionList'; Current = @() }).Configured | Should -BeFalse
            (New-IgwtSecSettingRow -Fields @{ Id = 'secpol:x'; SourceKind = 'secpolicy' }).Configured | Should -BeTrue
            (New-IgwtSecSettingRow -Fields @{ Id = 'admx:F:P:User'; SourceKind = 'admx'; Class = 'User' }).AppliesTo | Should -Be 'every user of this PC'
            $r = New-IgwtSecSettingRow -Fields @{ Id = 'admx:F:P:Machine'; SourceKind = 'admx'; Name = 'Contoso Policy'; ReadOnly = $true; Writer = 'localPolicy' }
            $r.Writer | Should -Be 'none'; $r.Search | Should -Match 'contoso policy'
        }
    }
}
