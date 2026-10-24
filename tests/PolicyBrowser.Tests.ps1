BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Simple = [pscustomobject]@{ Id = 'T:Simple'; DisplayName = 'Simple'; Class = 'Machine'; Key = 'Software\Policies\Test'; ValueName = 'On'
        EnabledValue = [pscustomobject]@{ Type = 'DWord'; Value = [uint32]1 }; DisabledValue = [pscustomobject]@{ Type = 'DWord'; Value = [uint32]0 }; EnabledList = @(); DisabledList = @(); Elements = @() }
    $script:Elem = [pscustomobject]@{ Id = 'T:Elem'; DisplayName = 'Element'; Class = 'Machine'; Key = 'Software\Policies\Test'; ValueName = ''; EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @()
        Elements = @([pscustomobject]@{ Type = 'decimal'; Id = 'N'; Key = 'Software\Policies\Test\Sub'; ValueName = 'Count'; Label = 'Count'; Min = 0; Max = 9 }) }
}

Describe 'Group Policy browser (bulk state)' {
    It 'finds the policies that have Registry.pol entries without reading each one' {
        InModuleScope iGWindowsTuner -Parameters @{ S = $script:Simple; E = $script:Elem } {
            param($S, $E)
            $entries = @([pscustomobject]@{ Key = 'Software\Policies\Test'; ValueName = 'On'; Value = 1 }, [pscustomobject]@{ Key = 'Software\Policies\Other'; ValueName = 'X'; Value = 1 })
            $idx = Get-IgwtPolicyEntryIndex -Class Machine -Entries $entries
            Test-IgwtPolicyHasEntries -Policy $S -Index $idx | Should -BeTrue
            Test-IgwtPolicyHasEntries -Policy $E -Index $idx | Should -BeFalse
            $idx2 = Get-IgwtPolicyEntryIndex -Class Machine -Entries @([pscustomobject]@{ Key = 'SOFTWARE\Policies\Test\Sub'; ValueName = '**del.Count'; Value = '' })
            Test-IgwtPolicyHasEntries -Policy $E -Index $idx2 | Should -BeTrue -Because 'keys are compared case-insensitively and del. markers count'
        }
    }

    It 'works out Enabled, Disabled and Not configured from the entries only' {
        InModuleScope iGWindowsTuner -Parameters @{ S = $script:Simple } {
            param($S)
            Mock Get-IgwtLocalPolicyEntries { @([pscustomobject]@{ Key = 'Software\Policies\Test'; ValueName = 'On'; Value = 1; Special = '' }) }
            Get-IgwtPolicyLocalState -Policy $S -Class Machine | Should -Be 'Enabled'
            Mock Get-IgwtLocalPolicyEntries { @([pscustomobject]@{ Key = 'Software\Policies\Test'; ValueName = 'On'; Value = 0; Special = '' }) }
            Get-IgwtPolicyLocalState -Policy $S -Class Machine | Should -Be 'Disabled'
            Mock Get-IgwtLocalPolicyEntries { @() }
            Get-IgwtPolicyLocalState -Policy $S -Class Machine | Should -Be 'NotConfigured'
        }
    }

    It 'builds browser rows with status, configured flag and the settable hint' {
        InModuleScope iGWindowsTuner {
            $r = New-IgwtGuiPolicyRow -Policy ([pscustomobject]@{ Id = 'a:b'; Name = 'N'; Category = 'A > B'; Class = 'User'; SupportedOn = 'x'; State = 'Enabled'; Simple = $false; File = 'a.admx' })
            $r.State | Should -Be 'Enabled'
            $r.Configured | Should -Be 'Yes'
            $r.Settable | Should -Be 'Values'
            (New-IgwtGuiPolicyRow -Policy ([pscustomobject]@{ Id = 'c'; State = 'NotConfigured'; Simple = $true })).State | Should -Be 'Not configured'
        }
    }
}
