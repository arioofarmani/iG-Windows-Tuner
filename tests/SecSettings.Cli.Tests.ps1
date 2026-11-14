# Security Settings Manager, B9 (DECISIONS SM29, SM33 CLI): -SecSettings, -SecSetting, -SecSettingSet,
# -SecSettingRemoveExclusion. Process runs only check argument errors and help; the change verb's
# functions are loaded from the script's source and run in-process with the module's functions mocked.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Cli = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Cli, [ref]$null, [ref]$null)
    $names = 'ConvertFrom-IgwtCliSecSettingValue', 'Invoke-IgwtCliSecSettingChange', 'Write-IgwtCliSecSettingDetail'
    foreach ($d in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | Where-Object { $names -contains $_.Name })) { . ([scriptblock]::Create($d.Extent.Text)) }
    $script:Log = New-Object System.Collections.Generic.List[string]
    function Write-IgwtCliLine { param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) $null = $Color; $script:Log.Add($Text) }
    function Invoke-CliProcess([string[]]$Arguments) {
        $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Cli @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    }
    $script:Rows = @(
        [pscustomobject]@{ Id = 'admx:Contoso:Pol:Machine'; Name = 'Contoso policy'; Current = $null; ValueSpec = @{ Mode = 'tristate'; Elements = @([pscustomobject]@{ Id = 'Level'; Kind = 'decimal'; Label = 'Level'; Min = 1; Max = 9; Required = $false; Choices = @() }, [pscustomobject]@{ Id = 'Names'; Kind = 'list'; Label = 'Names'; Required = $false; Choices = @() }) } }
        [pscustomobject]@{ Id = 'exclusion:Path'; Name = 'Excluded files and folders'; Current = @('C:\Games', 'C:\Old'); ValueSpec = @{ Mode = 'value'; Elements = @([pscustomobject]@{ Id = 'Path'; Kind = 'list'; Label = 'Entries'; RemoveOnly = $true; Required = $false; Choices = @() }) } }
    )
}

Describe 'Argument checks and help (process)' {
    It 'refuses options outside their verbs with exit code 2' {
        (Invoke-CliProcess @('-ConfiguredOnly')).Code | Should -Be 2
        (Invoke-CliProcess @('-NoCache', '-Report')).Code | Should -Be 2
    }
    It 'documents the verbs in the help' {
        $h = (Get-Help $script:Cli -Parameter SecSettingSet | Out-String)
        $h | Should -Match 'id=value'
        (Get-Help $script:Cli -Parameter SecSettingRemoveExclusion | Out-String) | Should -Match 'cannot be undone'
    }
}

Describe 'Value parsing' {
    It 'parses ADMX state with element values and lists, and plain values' {
        $v = ConvertFrom-IgwtCliSecSettingValue -Row $script:Rows[0] -Text 'Enabled;Level=4;Names=a|b'
        $v.State | Should -Be 'Enabled'; $v.Values.Level | Should -Be '4'; @($v.Values.Names) | Should -Be @('a', 'b')
        @(ConvertFrom-IgwtCliSecSettingValue -Row $script:Rows[1] -Text 'C:\Games|C:\Old') | Should -Be @('C:\Games', 'C:\Old')
    }
}

Describe 'Change verbs (in-process, module mocked)' {
    BeforeEach {
        $script:Log.Clear()
        Mock Get-IgwtSecSettings { [pscustomobject]@{ Rows = $script:Rows; Status = $null } }
        Mock Get-IgwtSecSettingChangePlan { [pscustomobject]@{ Rows = @([pscustomobject]@{ Id = $Changes[0].Id; Status = 'Change' }); CanApply = $true; Mixed = $false } }
        Mock Format-IgwtSecSettingPlan { 'PLAN TEXT' }
        Mock Invoke-IgwtSecSettingChange { throw 'must not apply in a dry run' }
    }
    It 'prints the plan and changes nothing with -DryRun' {
        $r = Invoke-IgwtCliSecSettingChange -Set @('admx:Contoso:Pol:Machine=Enabled;Level=4') -DryRun
        $r.Code | Should -Be 0
        $script:Log | Should -Contain 'PLAN TEXT'
        $script:Log | Should -Contain 'Dry run: nothing was changed.'
        Should -Invoke Invoke-IgwtSecSettingChange -Times 0
    }
    It 'refuses an unknown id and an invalid value with exit code 2 before planning' {
        (Invoke-IgwtCliSecSettingChange -Set @('admx:Nope:Nope:Machine=Enabled') -DryRun).Code | Should -Be 2
        (Invoke-IgwtCliSecSettingChange -Set @('admx:Contoso:Pol:Machine=Enabled;Level=12') -DryRun).Code | Should -Be 2
        Should -Invoke Get-IgwtSecSettingChangePlan -Times 0
    }
    It 'turns -SecSettingRemoveExclusion into the list without the removed entries, and splits a comma-joined list' {
        $null = Invoke-IgwtCliSecSettingChange -RemoveExclusion @('Path:C:\Old') -DryRun
        Should -Invoke Get-IgwtSecSettingChangePlan -Times 1 -ParameterFilter { $Changes[0].Id -eq 'exclusion:Path' -and @($Changes[0].Value) -join ';' -eq 'C:\Games' }
        $null = Invoke-IgwtCliSecSettingChange -Set @('admx:Contoso:Pol:Machine=Disabled,exclusion:Path=C:\Games') -DryRun
        Should -Invoke Get-IgwtSecSettingChangePlan -Times 1 -ParameterFilter { @($Changes).Count -eq 2 }
        (Invoke-IgwtCliSecSettingChange -RemoveExclusion @('Registry:HKLM') -DryRun).Code | Should -Be 2
    }
}
