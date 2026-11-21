# 4.0 section 7: Settings page, Advanced tools overview and expert info bar, plain words.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Xaml = Get-Content -LiteralPath (Join-Path $script:Root 'src\Gui\MainWindow.xaml') -Raw
}

Describe 'Settings page' {
    It 'holds the display settings (moved from the Display popup) and an Updates card' {
        $script:Xaml | Should -Not -Match 'x:Name="DisplayPopup"'
        $x = [xml]$script:Xaml
        $page = $x.SelectSingleNode("//*[@*[local-name()='Name' and .='PageSettings']]")
        $page | Should -Not -BeNullOrEmpty
        foreach ($n in 'ThemeBox', 'FontScaleBox', 'DensityBox', 'FocusModeBox', 'ShowAdvancedBox', 'ReduceMotionBox', 'SettingsUpdateText') {
            @($page.SelectNodes(".//*[@*[local-name()='Name' and .='$n']]")).Count | Should -Be 1 -Because "$n is on the Settings page"
        }
        $script:Xaml | Should -Match 'never checks the internet for updates by itself'
    }
    It 'opens Settings from the Display button, with Settings and About as tabs' {
        (Get-Content (Join-Path $script:Root 'src\Gui\GuiShell.ps1') -Raw) | Should -Match "DisplayButton -Event 'Click' -Handler \{ Open-IgwtGuiPage -Page 'Settings' \}"
        InModuleScope iGWindowsTuner {
            @(@($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Settings' })[0].Pages) | Should -Be @('Settings', 'About')
        }
    }
}

Describe 'Advanced tools' {
    It 'opens on an overview with one card per tool, each with an Open button' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $w = New-IgwtMainWindow
                $script:Gui = @{ Window = $w; C = @{ AdvancedHost = $w.FindName('AdvancedHost') }; Persona = [pscustomobject]@{ ShowRiskZone = $true } }
                Update-IgwtGuiAdvancedPage
                $btns = @(Get-IgwtUiDescendant -Root $script:Gui.C.AdvancedHost | Where-Object { $_ -is [System.Windows.Controls.Button] })
                @($btns | ForEach-Object { [string]$_.Tag }) | Should -Be @('Inspect', 'Policy', 'Manage', 'Toolkit', 'Risk Zone', 'Rejected')
                [System.Windows.Automation.AutomationProperties]::GetName($btns[0]) | Should -Be 'Open Expert inspectors'
                $script:Gui.Persona = [pscustomobject]@{ ShowRiskZone = $false }
                Update-IgwtGuiAdvancedPage
                @(Get-IgwtUiDescendant -Root $script:Gui.C.AdvancedHost | Where-Object { $_ -is [System.Windows.Controls.Button] -and [string]$_.Tag -eq 'Risk Zone' }).Count | Should -Be 0
            } finally { $script:Gui = $saved }
        }
    }
    It 'shows the expert info bar on the tool pages, not on the overview' {
        (Get-Content (Join-Path $script:Root 'src\Gui\Gui.ps1') -Raw) | Should -Match "ExpertInfoBar\.Visibility = \`$\(if \(\`$sec -and \`$sec\.Id -eq 'Advanced' -and \`$Page -ne 'Advanced'\)"
        InModuleScope iGWindowsTuner { @(@($script:IgwtGuiSections | Where-Object { $_.Id -eq 'Advanced' })[0].Pages)[0] | Should -Be 'Advanced' }
    }
}

Describe 'Plain words' {
    It 'names settings instead of their ids, at most five and "and N more"' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ Catalog = @([pscustomobject]@{ id = 'a.one'; name = 'Game Mode' }, [pscustomobject]@{ id = 'a.two'; name = 'HAGS' }) }
                Format-IgwtGuiNameList -Ids @('a.one', 'a.two', 'x.unknown') | Should -Be 'Game Mode, HAGS, x.unknown'
                Format-IgwtGuiNameList -Ids @(1..7 | ForEach-Object { 'a.one' }) -Max 5 | Should -Match ' and 2 more$'
            } finally { $script:Gui = $saved }
        }
        (Get-Content (Join-Path $script:Root 'src\Gui\Gui.ps1') -Raw) | Should -Match 'Format-IgwtGuiNameList -Ids \$drifted'
        InModuleScope iGWindowsTuner {
            Get-IgwtGuiHistoryTitle -Title 'Apply (1 item(s))' | Should -Be 'Changed 1 setting'
            Get-IgwtGuiHistoryTitle -Title 'Apply (3 item(s))' | Should -Be 'Changed 3 settings'
            Get-IgwtGuiHistoryTitle -Title 'Accepted the current value of 2 item(s)' | Should -Be 'Accepted the current value of 2 item(s)' -Because 'only the counted suffix is rewritten'
        }
    }
}

Describe 'Mandatory parameters' {
    It 'never calls a module function without its mandatory parameters (a missing one prompts on the console and freezes the window)' {
        $find = {
            param([System.Management.Automation.Language.Ast[]]$Asts)
            $defs = @{}
            foreach ($a in $Asts) {
                foreach ($fn in $a.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                    if (-not $fn.Body.ParamBlock) { continue }
                    $mand = @(foreach ($p in $fn.Body.ParamBlock.Parameters) {
                            foreach ($at in $p.Attributes) {
                                if ($at.TypeName.Name -ne 'Parameter') { continue }
                                $m = @($at.NamedArguments | Where-Object { $_.ArgumentName -eq 'Mandatory' })
                                $set = @($at.NamedArguments | Where-Object { $_.ArgumentName -eq 'ParameterSetName' })
                                if ($m.Count -and -not $set.Count -and ($m[0].ExpressionOmitted -or $m[0].Argument.Extent.Text -match 'true')) { $p.Name.VariablePath.UserPath }
                            }
                        })
                    if ($mand.Count) { $defs[$fn.Name] = $mand }
                }
            }
            foreach ($a in $Asts) {
                foreach ($c in $a.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                    $n = $c.GetCommandName()
                    if (-not $n -or -not $defs.ContainsKey($n)) { continue }
                    $el = @($c.CommandElements | Select-Object -Skip 1)
                    if (@($el | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted }).Count) { continue }
                    if ($c.Parent -is [System.Management.Automation.Language.PipelineAst] -and $c.Parent.PipelineElements[0] -ne $c) { continue }
                    $named = @($el | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
                    $values = @($el | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] }).Count - @($el | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and -not $_.Argument }).Count
                    foreach ($m in $defs[$n]) {
                        if (-not @($named | Where-Object { $m -like "$_*" }).Count -and $values -le 0) { '{0}:{1} {2} without -{3}' -f $c.Extent.File, $c.Extent.StartLineNumber, $n, $m }
                    }
                }
            }
        }
        $bad = [System.Management.Automation.Language.Parser]::ParseInput('function Update-X { param([Parameter(Mandatory = $true)]$Data) } function Get-Y { Update-X }', [ref]$null, [ref]$null)
        @(& $find @($bad)).Count | Should -Be 1 -Because 'the check finds a known missing parameter'
        $asts = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'src') -Recurse -Filter '*.ps1' | ForEach-Object { [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null) })
        @(& $find $asts) | Should -BeNullOrEmpty
    }
}