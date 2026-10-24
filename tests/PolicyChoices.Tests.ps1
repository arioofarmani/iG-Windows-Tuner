BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    # The Defender ADMX policy "Configure detection for potentially unwanted applications"
    # (WindowsDefender:Root_PUAProtection): one enum element, Off = 0, Block = 1, Audit = 2.
    $script:Pua = [pscustomobject]@{
        Id = 'WindowsDefender:Root_PUAProtection'; DisplayName = 'Configure detection for potentially unwanted applications'; Key = 'Software\Policies\Microsoft\Windows Defender'; ValueName = ''
        EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @()
        Elements = @([pscustomobject]@{
                Type = 'enum'; Id = 'Root_PUAProtection'; Key = 'Software\Policies\Microsoft\Windows Defender'; ValueName = 'PUAProtection'; Required = $true; Label = 'Options'; Default = $null
                Items = @(
                    [pscustomobject]@{ DisplayName = 'Off (default)'; Value = [pscustomobject]@{ Type = 'DWord'; Value = [uint32]0 }; ValueList = @() }
                    [pscustomobject]@{ DisplayName = 'Block'; Value = [pscustomobject]@{ Type = 'DWord'; Value = [uint32]1 }; ValueList = @() }
                    [pscustomobject]@{ DisplayName = 'Audit Mode'; Value = [pscustomobject]@{ Type = 'DWord'; Value = [uint32]2 }; ValueList = @() }
                )
            })
    }
}

Describe 'Policy choices (audit S1)' {
    It 'offers Enabled per option and refuses only the option that turns protection off' {
        InModuleScope iGWindowsTuner -Parameters @{ P = $script:Pua } {
            param($P)
            $ch = @(Get-IgwtPolicyChoices -Policy $P)
            ($ch | Where-Object Label -EQ 'Enabled: Block').Allowed | Should -BeTrue
            ($ch | Where-Object Label -EQ 'Enabled: Audit Mode').Allowed | Should -BeTrue
            $off = $ch | Where-Object Label -EQ 'Enabled: Off (default)'
            $off.Allowed | Should -BeFalse
            $off.Reason | Should -Match 'potentially unwanted'
            ($ch | Where-Object Label -EQ 'Enabled: Block').Values['Root_PUAProtection'] | Should -Be 'Block'
            ($ch | Where-Object State -EQ 'NotConfigured').Allowed | Should -BeTrue
        }
    }

    It 'only refuses the whole Enabled state when every option is refused' {
        InModuleScope iGWindowsTuner -Parameters @{ P = $script:Pua } {
            param($P)
            $ch = @(Get-IgwtPolicyChoices -Policy $P)
            $en = @($ch | Where-Object State -EQ 'Enabled')
            @($en | Where-Object Allowed).Count | Should -Be 2
            # The values chosen for Block are really allowed by the denylist when applied.
            $ops = @(Get-IgwtPolicyRegistryOps -Policy $P -State Enabled -Values @{ Root_PUAProtection = 'Block' })
            @($ops | Where-Object { Test-IgwtPolicyOpAllowed -Op $_ }).Count | Should -Be 0
        }
    }

    It 'sends policies with several elements to -PolicySet instead of guessing values' {
        InModuleScope iGWindowsTuner {
            $p = [pscustomobject]@{ Id = 'X:Multi'; DisplayName = 'Multi'; Key = 'Software\Policies\Test'; ValueName = ''; EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @()
                Elements = @([pscustomobject]@{ Type = 'decimal'; Id = 'A'; Key = 'Software\Policies\Test'; ValueName = 'A'; Label = 'A'; Min = 0; Max = 10 }, [pscustomobject]@{ Type = 'text'; Id = 'B'; Key = 'Software\Policies\Test'; ValueName = 'B'; Label = 'B'; MaxLength = 10 }) }
            $en = @(Get-IgwtPolicyChoices -Policy $p | Where-Object State -EQ 'Enabled')
            $en.Count | Should -Be 1
            $en[0].Allowed | Should -BeFalse
            $en[0].Reason | Should -Match '-PolicySet'
        }
    }

    It 'lists the PUA policy without refusing Enabled in the Defender Group Policy view' {
        $gui = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Defender\DefenderSettings.ps1') -Raw
        $gui | Should -Match 'Get-IgwtPolicyChoices -Policy \$p'
        $g = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\Gui.ps1') -Raw
        $g | Should -Not -Match 'This state cannot be set here'
        $g | Should -Match 'SelectedItem\.Allowed'
    }
}
