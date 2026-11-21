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

Describe 'Wording and focus (D9, D10)' {
    It 'shows no internal names (Invoke-Igwt, regClean, $script:) in visible texts' {
        $pat = 'Invoke-Igwt|Get-Igwt|Set-Igwt|\bregClean\b|\bIgwt[A-Z]|\$script:'
        $params = 'Text', 'Message', 'Title', 'Subtitle', 'Prompt', 'Header', 'ToolTip', 'Label', 'Meta', 'ActionText', 'Summary'
        $scan = {
            param([System.Management.Automation.Language.Ast]$Ast)
            foreach ($c in $Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $el = $c.CommandElements; $n = $c.GetCommandName()
                for ($i = 1; $i -lt $el.Count; $i++) {
                    $e = $el[$i]; $arg = $null
                    if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and $params -contains $e.ParameterName) { $arg = $(if ($e.Argument) { $e.Argument } elseif ($i + 1 -lt $el.Count) { $el[$i + 1] }) }
                    elseif ($i -eq 1 -and $n -eq 'Set-IgwtGuiStatus' -and $e -isnot [System.Management.Automation.Language.CommandParameterAst]) { $arg = $e }
                    if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $arg -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                        $lit = [string]$arg.Value -replace '\$\([^)]*\)', '' -replace '\$\w+(:\w+)?', ''
                        if ($lit -match $pat) { '{0}:{1} {2}' -f $c.Extent.File, $arg.Extent.StartLineNumber, $arg.Value }
                    }
                }
            }
        }
        $bad = [System.Management.Automation.Language.Parser]::ParseInput("Set-IgwtGuiStatus 'Invoke-IgwtApply failed'", [ref]$null, [ref]$null)
        @(& $scan $bad).Count | Should -Be 1 -Because 'the check finds a known internal name'
        $hits = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'src\Gui') -Filter '*.ps1' | ForEach-Object { & $scan ([System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)) })
        $hits | Should -BeNullOrEmpty
        @([regex]::Matches($script:Xaml, '(?:Text|Content|Header|ToolTip|AutomationProperties\.Name)="([^"]*)"') | Where-Object { $_.Groups[1].Value -match 'Igwt|regClean|Invoke-' }) | Should -BeNullOrEmpty
    }
    It 'counts with the right noun form and keeps "(s)" out of GUI texts' {
        InModuleScope iGWindowsTuner {
            Format-IgwtCount -Count 1 -Noun 'setting' | Should -Be '1 setting'
            Format-IgwtCount -Count 3 -Noun 'setting' | Should -Be '3 settings'
            Format-IgwtCount -Count 0 -Noun 'ASR change' | Should -Be '0 ASR changes'
            Format-IgwtCount -Count 1 -Noun 'entry' -Plural 'entries' | Should -Be '1 entry'
            Format-IgwtCount -Count 2 -Noun 'crash' -Plural 'crashes' | Should -Be '2 crashes'
            Format-IgwtCount -Count 1.5 -Noun 'hour' | Should -Be '1.5 hours'
            Format-IgwtCount -Count $null -Noun 'rule' | Should -Be '0 rules'
            Format-IgwtCount -Count 1 -Noun 'rule' -Verb 'are' | Should -Be '1 rule is'
            Format-IgwtCount -Count 2 -Noun 'rule' -Verb 'are' | Should -Be '2 rules are'
            Format-IgwtCount -Count 1 -Noun 'rule' -Verb 'match' | Should -Be '1 rule matches'
            Format-IgwtCount -Count 1 -Noun 'device' -Verb 'use' | Should -Be '1 device uses'
            Format-IgwtCount -Count 1 -Noun 'item' -Verb 'have' | Should -Be '1 item has'
        }
        $bad = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'src\Gui') -Filter '*.ps1' | ForEach-Object {
                $a = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
                $a.FindAll({ $args[0] -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true) | Where-Object { $_.Extent.Text -match '\$[\w(].{0,80}?\w\((s|es|ies)\)' } | ForEach-Object { "$($_.Extent.File):$($_.Extent.StartLineNumber)" }
            })
        $bad | Should -BeNullOrEmpty -Because 'use Format-IgwtCount for a counted noun'
    }
    It 'draws a focus ring in every style that hides the default focus visual' {
        $x = [xml](Get-Content -LiteralPath (Join-Path $script:Root 'src\Gui\Theme.xaml') -Raw)
        $ns = @{ w = 'http://schemas.microsoft.com/winfx/2006/xaml/presentation' }
        $styles = @(Select-Xml -Xml $x -XPath "//w:Style[w:Setter[@Property='FocusVisualStyle' and @Value='{x:Null}']]" -Namespace $ns | ForEach-Object { $_.Node })
        $styles.Count | Should -BeGreaterThan 10
        foreach ($s in $styles) {
            # Keyboard focus in a DataGrid lands on a cell; DataGridCell draws the ring for the grid and its rows.
            if ([string]$s.TargetType -in '{x:Type DataGrid}', '{x:Type DataGridRow}') { continue }
            $s.OuterXml | Should -Match 'IsKeyboardFocused|IsKeyboardFocusWithin|IsFocused' -Because "$($s.TargetType) $($s.GetAttribute('Key', 'http://schemas.microsoft.com/winfx/2006/xaml')) hides the default focus visual"
        }
    }
}

Describe 'Remaining Mediums (section 7)' {
    It 'relaunches elevated with -Confirm:$false and the working folder, and refuses -Json there (CLI-02, CLI-03, CLI-04)' {
        $cli = Get-Content -LiteralPath (Join-Path $script:Root 'iGWindowsTuner.ps1') -Raw
        foreach ($code in @(
                'if ($k -eq ''Confirm'' -and $v -is [switch] -and -not $v.IsPresent) { $pass.Add(''-ElevatedNoConfirm''); continue }'
                '$pass.Add(''-ElevatedWorkingDirectory'')'
                'if ($ElevatedRelaunch -and $ElevatedWorkingDirectory -and (Test-Path -LiteralPath $ElevatedWorkingDirectory -PathType Container)) { Set-Location -LiteralPath $ElevatedWorkingDirectory }'
                'if ($ElevatedRelaunch -and $ElevatedNoConfirm) { $ConfirmPreference = ''None'' }')) {
            $cli | Should -Match ([regex]::Escape($code))
        }
        $cli | Should -Match "(?s)function Request-IgwtCliElevation.{0,700}ContainsKey\('Json'\).{0,250}exit 2"
        # The registry cleaner and security settings build their -Confirm from bound parameters: the elevated copy must too (code review of 4.0).
        ([regex]::Matches($cli, [regex]::Escape('if ($ElevatedNoConfirm) { $confirmArgs.Confirm = $false }'))).Count | Should -Be 2
        $cli | Should -Match ([regex]::Escape("if (`$here -like '\\*' -or (`$loc.Drive -and [string]`$loc.Drive.DisplayRoot -like '\\*'))"))
    }
    It 'reads the whole Defender threat history unless -Days limits it (CLI-08)' {
        $cli = Get-Content -LiteralPath (Join-Path $script:Root 'iGWindowsTuner.ps1') -Raw
        $cli | Should -Match ([regex]::Escape('$SystemReport -or $DefenderThreats))'))
        $cli | Should -Match ([regex]::Escape('Get-IgwtDefenderThreats -Days $(if ($PSBoundParameters.ContainsKey(''Days'')) { $Days } else { 0 })'))
    }
    It 'keeps custom presets out of the docs, passes -WhatIf down and fails gates on every failure list (T-01, T-11, T-06, T-09)' {
        $t = { param($n) Get-Content -LiteralPath (Join-Path $script:Root "tools\$n") -Raw }
        (& $t 'Build-Docs.ps1') | Should -Match '\$presets = @\(Get-IgwtPreset -Builtin\)'
        (& $t 'Convert-IgwtV1Data.ps1') | Should -Match 'Convert-IgwtDataToV2 -DataFolder \$DataFolder -WhatIf:\$WhatIfPreference'
        (& $t 'Convert-IgwtV1Data.ps1') | Should -Match 'Convert-IgwtSnapshotToV2 .* -WhatIf:\$WhatIfPreference'
        (& $t 'Test-All.ps1') | Should -Match "'QualityGate', 'Render', 'Automation', 'AutomationClean'"
        (& $t 'Invoke-SandboxTest.ps1') | Should -Match '\$notVerified\.Count -eq 0 -and \$notOn\.Count -eq 0 .* \$stateDiff\.Count -eq 0'
    }
    It 'checks every data file before writing and leaves v3 presets alone (MIG-1)' {
        InModuleScope iGWindowsTuner {
            $d = Join-Path $TestDrive 'mig'
            foreach ($s in 'tweaks', 'presets') { $null = New-Item -ItemType Directory -Path (Join-Path $d $s) -Force }
            $tw = Join-Path $d 'tweaks\system.json'
            Set-Content -LiteralPath $tw -Value '{ "category": "System", "tweaks": [] }' -Encoding ASCII
            $v3 = '{ "schemaVersion": 3, "id": "x", "name": "X" }'
            Set-Content -LiteralPath (Join-Path $d 'presets\x.json') -Value $v3 -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $d 'presets\z.json') -Value '{ "schemaVersion": 9, "id": "z", "name": "Z" }' -Encoding ASCII
            $before = [IO.File]::ReadAllText($tw)
            { Convert-IgwtDataToV2 -DataFolder $d } | Should -Throw '*schemaVersion 9*Nothing was written*'
            [IO.File]::ReadAllText($tw) | Should -Be $before -Because 'nothing is written when a file cannot be converted'
            Remove-Item -LiteralPath (Join-Path $d 'presets\z.json')
            $r = @(Convert-IgwtDataToV2 -DataFolder $d)
            @($r | Where-Object { $_.File -eq 'presets\x.json' })[0].Changed | Should -BeFalse
            ([IO.File]::ReadAllText((Join-Path $d 'presets\x.json'))).Trim() | Should -Be $v3
        }
    }
    It 'treats a PC onboarded to Defender for Endpoint as managed (C3)' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtJoinInfo { [pscustomobject]@{ DomainJoined = $false; DomainName = ''; EntraJoined = $false; TenantId = '' } }
            Mock Get-IgwtMdmEnrollment { @() }
            Mock Get-IgwtSecurityManagement { [pscustomobject]@{ DefenderForEndpoint = $true; DefenderMode = 'Normal'; ThirdPartyAntivirus = @() } }
            $m = Get-IgwtManagementState -Force
            $m.Managed | Should -BeTrue
            $m.Authorities | Should -Contain 'Microsoft Defender for Endpoint'
            Mock Get-IgwtSecurityManagement { [pscustomobject]@{ DefenderForEndpoint = $false; DefenderMode = 'Normal'; ThirdPartyAntivirus = @() } }
            (Get-IgwtManagementState -Force).Managed | Should -BeFalse
        }
    }
    It 'asks before a preset or drift fix replaces staged changes, and names the session only for its own list (HC-1, PV-1)' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ Staged = @{}; PresetOperation = $null; PresetOperationKey = $null }
                Mock Show-IgwtGuiMessage { 'Cancel' }
                Confirm-IgwtGuiReplaceStaged -What 'X' | Should -BeTrue
                Should -Invoke Show-IgwtGuiMessage -Times 0 -Exactly -Because 'nothing staged, nothing to ask'
                $script:Gui.Staged['a.one'] = 'on'; $script:Gui.Staged['a.two'] = 'reset'
                Confirm-IgwtGuiReplaceStaged -What 'The Competitive preset' | Should -BeFalse
                Should -Invoke Show-IgwtGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -like '2 staged changes are waiting*The Competitive preset replaces them*' }
                Mock Show-IgwtGuiMessage { 'OK' }
                Confirm-IgwtGuiReplaceStaged -What 'X' | Should -BeTrue
                Set-IgwtGuiPresetOperation -Name 'DriftFix'
                $script:Gui.PresetOperationKey | Should -Be (Get-IgwtGuiStagedKey)
                $script:Gui.Staged['b.three'] = 'on'
                $script:Gui.PresetOperationKey | Should -Not -Be (Get-IgwtGuiStagedKey) -Because 'a changed list no longer carries the drift-fix name'
            } finally { $script:Gui = $saved }
        }
        $gui = Get-ChildItem -LiteralPath (Join-Path $script:Root 'src\Gui') -Filter '*.ps1' | ForEach-Object { @{ Name = $_.Name; Lines = [IO.File]::ReadAllLines($_.FullName) } }
        foreach ($g in $gui) {
            for ($i = 0; $i -lt $g.Lines.Count; $i++) {
                if ($g.Lines[$i] -notmatch '\$script:Gui\.Staged\.Clear\(\)' -or $g.Lines[$i] -match '-Discard') { continue }
                ($g.Lines[[Math]::Max(0, $i - 3)..$i] -join "`n") | Should -Match 'Confirm-IgwtGuiReplaceStaged' -Because "$($g.Name):$($i + 1) clears staged changes"
            }
        }
        (Get-Content -LiteralPath (Join-Path $script:Root 'src\Gui\Gui.ps1') -Raw) | Should -Match ([regex]::Escape('[string]$script:Gui.PresetOperationKey -eq (Get-IgwtGuiStagedKey)'))
        (Get-Content -LiteralPath (Join-Path $script:Root 'src\Gui\Gui.ps1') -Raw) | Should -Match ([regex]::Escape("if (`$alone) { Set-IgwtGuiPresetOperation -Name 'Apply:NetworkTest' }")) -Because 'recommendations staged on top of other changes are a normal apply'
    }
    It 'recognizes 13th- and 14th-gen desktop CPUs by model number, not by "Gen" text (HL-1)' {
        InModuleScope iGWindowsTuner {
            $case = { param($Name, $Model)
                Mock Get-CimInstance { [pscustomobject]@{ Name = $Name; NumberOfCores = 8; NumberOfLogicalProcessors = 16 } }.GetNewClosure()
                Mock Get-ItemProperty { [pscustomobject]@{ Identifier = "Intel64 Family 6 Model $Model Stepping 1"; VendorIdentifier = 'GenuineIntel'; ProcessorNameString = $Name } }.GetNewClosure()
                (Get-IgwtCpuInfo).IsVminAffected
            }
            & $case 'Intel(R) Core(TM) i9-14900K' 183 | Should -BeTrue
            & $case '13th Gen Intel(R) Core(TM) i7-13700K' 183 | Should -BeTrue
            & $case 'Intel(R) Core(TM) i7-14700KF' 191 | Should -BeTrue
            & $case '12th Gen Intel(R) Core(TM) i7-12700K' 151 | Should -BeFalse
            & $case 'AMD Ryzen 7 7800X3D 8-Core Processor' 183 | Should -BeFalse
        }
    }
}