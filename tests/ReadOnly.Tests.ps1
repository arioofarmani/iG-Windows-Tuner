# 3.3: read-only mode (-ReadOnly) is enforced by the engine. Every exported function that changes
# the PC refuses in read-only mode before doing anything, the internal write primitives refuse too,
# and the mode is inherited by new runspaces (the GUI worker) through the process environment.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    # State-changing exports that are not changes to the PC: report and export files the user asks
    # for, module settings, the log sink, the cleaner test root, opening a Windows panel and the
    # elevation relaunch (which passes -ReadOnly on).
    # The Firewall Manager overrides are the app's own per-user preferences (DECISIONS F6).
    $script:Allowed = @('Set-IgwtEnvironment', 'Set-IgwtLogSink', 'Set-IgwtCleanerTestRoot', 'Start-IgwtPanel', 'Start-IgwtElevated', 'Set-IgwtFirewallOverride', 'Import-IgwtFirewallOverrides')
    $m = Get-Module iGWindowsTuner
    $script:Mutating = @(foreach ($n in @($m.ExportedFunctions.Keys)) {
            $f = $m.ExportedFunctions[$n]
            $pb = $f.ScriptBlock.Ast.Body.ParamBlock
            $ssp = $pb -and @($pb.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' -and $_.NamedArguments.ArgumentName -contains 'SupportsShouldProcess' }).Count
            if ($ssp -and $n -notlike 'Export-*' -and $script:Allowed -notcontains $n) { $n }
        })
    function Get-DummyArguments([System.Management.Automation.CommandInfo]$Command) {
        $set = @($Command.ParameterSets | Where-Object IsDefault) | Select-Object -First 1
        if (-not $set) { $set = $Command.ParameterSets[0] }
        $h = @{}
        foreach ($p in @($set.Parameters | Where-Object IsMandatory)) {
            $t = $p.ParameterType
            $vs = @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }) | Select-Object -First 1
            if ($vs) { $v = $vs.ValidValues[0]; if ($t.IsArray) { $v = @($v) } }
            elseif ($t -eq [System.Management.Automation.SwitchParameter]) { continue }
            elseif ($t -eq [string]) { $v = 'x' }
            elseif ($t -eq [string[]]) { $v = @('x') }
            elseif ($t -in [int], [long], [double], [uint32]) { $v = 1 }
            elseif ([System.Collections.IDictionary].IsAssignableFrom($t)) { $v = @{ x = 1 } }
            elseif ($t -eq [bool]) { $v = $true }
            elseif ($t -eq [scriptblock]) { $v = { } }
            else { $v = [pscustomobject]@{ id = 'x'; type = 'registry'; path = 'HKLM:\SOFTWARE\x'; name = 'x' } }
            $h[$p.Name] = $v
        }
        return $h
    }
}

AfterAll { Set-IgwtEnvironment -ReadOnly:$false }

Describe 'Read-only mode' {
    AfterEach { Set-IgwtEnvironment -ReadOnly:$false }

    It 'finds the state-changing exports (sanity check)' {
        $script:Mutating.Count | Should -BeGreaterThan 40
        $script:Mutating | Should -Contain 'Invoke-IgwtApply'
        $script:Mutating | Should -Contain 'Invoke-IgwtRevert'
        $script:Mutating | Should -Contain 'Invoke-IgwtCleanerClean'
    }
    It 'guards every state-changing export as its first statement' {
        $m = Get-Module iGWindowsTuner
        foreach ($n in $script:Mutating) {
            $body = $m.ExportedFunctions[$n].ScriptBlock.Ast.Body
            $first = @($body.EndBlock.Statements)[0]
            [string]$first.Extent.Text | Should -Be "Assert-IgwtWritable -Operation '$n'" -Because "$n changes the PC and must refuse in read-only mode"
        }
    }
    It 'every state-changing export refuses in read-only mode before doing anything' {
        Mock -ModuleName iGWindowsTuner Set-MpPreference { throw 'must not run' }
        Mock -ModuleName iGWindowsTuner Remove-MpPreference { throw 'must not run' }
        Set-IgwtEnvironment -ReadOnly
        foreach ($n in $script:Mutating) {
            $cmd = Get-Command -Name $n -Module iGWindowsTuner
            $a = Get-DummyArguments -Command $cmd
            $err = $null
            try { $null = & $cmd @a -Confirm:$false -ErrorAction Stop } catch { $err = $_.Exception.Message }
            $err | Should -BeLike 'Read-only mode:*' -Because "$n must refuse in read-only mode"
        }
        Should -Invoke -ModuleName iGWindowsTuner Set-MpPreference -Times 0
    }
    It 'the engine write primitives refuse too (defense in depth)' {
        Set-IgwtEnvironment -ReadOnly
        InModuleScope iGWindowsTuner {
            $a = [pscustomobject]@{ type = 'registry'; path = 'HKCU:\Software\IgwtTest'; name = 'X'; valueType = 'DWord'; on = 1; default = '<absent>' }
            { Invoke-IgwtActionApply -Action $a -Context $null -Mode on } | Should -Throw '*Read-only mode*'
            { Restore-IgwtActionSnapshot -Action $a -Snapshot @{} -Context $null } | Should -Throw '*Read-only mode*'
            { Save-IgwtSnapshot -Snapshot ([pscustomobject]@{ Path = 'TestDrive:\x.json'; Document = @{} }) } | Should -Throw '*Read-only mode*'
            { Invoke-IgwtMpPreferenceWrite -Definition ([pscustomobject]@{ mp = 'X'; edit = 'set'; type = 'bool' }) -Value $true } | Should -Throw '*Read-only mode*'
            { Initialize-IgwtDataRoot } | Should -Throw '*Read-only mode*'
        }
        Test-Path -LiteralPath 'TestRegistry:\HKCU\Software\IgwtTest' | Should -BeFalse
    }
    It 'is inherited by a new runspace through the process environment and survives -Reset' {
        Set-IgwtEnvironment -ReadOnly
        $env:IGWT_READONLY | Should -Be '1'
        $ps = [PowerShell]::Create()
        try {
            $null = $ps.AddCommand('Import-Module').AddParameter('Name', (Join-Path $script:IgwtProjectRoot 'src\iGWindowsTuner.psd1')).AddParameter('Force', $true)
            $null = $ps.AddStatement().AddCommand('Test-IgwtReadOnly')
            @($ps.Invoke())[-1] | Should -BeTrue
        } finally { $ps.Dispose() }
        InModuleScope iGWindowsTuner { $script:IgwtSettings.ReadOnly = $false; Set-IgwtEnvironment -Reset; Test-IgwtReadOnly | Should -BeTrue }
        Set-IgwtEnvironment -ReadOnly:$false
        Test-IgwtReadOnly | Should -BeFalse
        $env:IGWT_READONLY | Should -BeNullOrEmpty
        Initialize-IgwtTestEnvironment
    }
    It 'the CLI and the GUI wire -ReadOnly through the engine and stop before asking for elevation' {
        $cli = Get-Content (Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1') -Raw
        $cli | Should -Match 'if \(\$ReadOnly\) \{ Set-IgwtEnvironment -ReadOnly \}'
        $cli | Should -Match '(?s)function Request-IgwtCliElevation.{0,200}Test-IgwtReadOnly.{0,250}exit 7'
        $cli | Should -Match 'Show-IgwtGui -ScriptPath \$PSCommandPath -ReadOnly:\$ReadOnly'
        $gui = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\Gui.ps1') -Raw
        $gui | Should -Match 'if \(\$ReadOnly\) \{ Set-IgwtEnvironment -ReadOnly \}'
        $xaml = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw
        $xaml | Should -Match 'AutomationProperties.AutomationId="ReadOnlyBanner"'
    }
}
