# 4.0 section 2 (C3): the ChangeBar is the one apply path; review 3.8.1 G-04 to G-07.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'ChangeBar: one apply path' {
    It 'starts the batch (Invoke-IgwtGuiBatch) from one place only: Complete-IgwtGuiApply' {
        $gui = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui'
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in Get-ChildItem -LiteralPath $gui -Filter '*.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Start-IgwtGuiJob' }, $true)) {
                if ($c.Extent.Text -match "-Command\s+'Invoke-IgwtGuiBatch'") {
                    $fn = $c.Parent; while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                    $hits.Add("$($f.Name):$($fn.Name)")
                }
            }
        }
        @($hits) | Should -Be @('Gui.ps1:Complete-IgwtGuiApply')
    }
    It 'words the count for people and screen readers' {
        InModuleScope iGWindowsTuner {
            Update-IgwtGuiChangeBarText -Count 0 | Should -Be 'Nothing staged'
            Update-IgwtGuiChangeBarText -Count 1 | Should -Be '1 change ready'
            Update-IgwtGuiChangeBarText -Count 3 | Should -Be '3 changes ready'
        }
    }
}

Describe 'ChangeBar: re-entrancy (review 3.8.1 G-04 to G-07)' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            $script:SavedGui = $script:Gui
            $staged = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            $staged['gfx.game-mode'] = 'on'; $staged['input.mouse-accel-off'] = 'on'
            $script:Gui = @{ Runspace = $null; Window = $null; IsAdmin = $true; Job = $null; ApplyPending = $false; Staged = $staged; Catalog = @(); Acked = @{}; PresetOperation = $null; C = $null; Data = @{ States = @{} } }
            $script:Started = New-Object System.Collections.Generic.List[string]
            $script:Dialogs = New-Object System.Collections.Generic.List[string]
            Mock Show-IgwtGuiMessage { $script:Dialogs.Add([string]$Text); 'Yes' }
            Mock Set-IgwtGuiStatus { }
            Mock Get-IgwtGuiStagedSets { [pscustomobject]@{ Apply = @('gfx.game-mode', 'input.mouse-accel-off'); Off = @(); Reset = @() } }
        }
    }
    AfterEach { InModuleScope iGWindowsTuner { $script:Gui = $script:SavedGui } }

    It 'G-04: a second Apply while the first is on its way starts nothing' {
        InModuleScope iGWindowsTuner {
            Mock Start-IgwtGuiJob { $script:Started.Add($Command); $true }
            Invoke-IgwtGuiApply
            $script:Gui.ApplyPending | Should -BeTrue -Because 'the precheck runs; the batch has not started'
            (Test-IgwtGuiApplyBusy) | Should -BeTrue
            Invoke-IgwtGuiApply
            @($script:Started) | Should -Be @('Test-IgwtSystemProtectionEnabled')
            @($script:Dialogs | Where-Object { $_ -like 'Apply 2 staged*' }).Count | Should -Be 1 -Because 'the second click asks nothing'
        }
    }
    It 'G-04: Cancel at the restore point question and a precheck that cannot start both end the pending apply' {
        InModuleScope iGWindowsTuner {
            Mock Start-IgwtGuiJob { $false }
            Mock Show-IgwtGuiNotStarted { }
            Invoke-IgwtGuiApply
            $script:Gui.ApplyPending | Should -BeFalse
            Should -Invoke Show-IgwtGuiNotStarted -Times 1
            $script:Gui.ApplyPending = $true
            Mock Show-IgwtGuiMessage { 'Cancel' }
            Complete-IgwtGuiApply -Sets (Get-IgwtGuiStagedSets) -SystemProtectionOn $false
            $script:Gui.ApplyPending | Should -BeFalse
        }
    }
    It 'G-05: only what the batch handled leaves the staged list; changes staged meanwhile stay' {
        InModuleScope iGWindowsTuner {
            $script:Gui.Staged['sec.smb1-off'] = 'on'
            $left = Remove-IgwtGuiStagedIds -Sets ([pscustomobject]@{ Apply = @('gfx.game-mode', 'input.mouse-accel-off'); Off = @(); Reset = @() })
            $left | Should -Be 1
            @($script:Gui.Staged.Keys) | Should -Be @('sec.smb1-off')
        }
    }
    It 'G-05: presets and the drift fix cannot replace the staged list under a running Apply' {
        InModuleScope iGWindowsTuner {
            $script:Gui.ApplyPending = $true
            Test-IgwtGuiCanRestage | Should -BeFalse
            $script:Gui.ApplyPending = $false
            Test-IgwtGuiCanRestage | Should -BeTrue
        }
    }
    It 'G-07: a change refused because another one runs gets a dialog; a background read only a status line' {
        InModuleScope iGWindowsTuner {
            Mock Show-IgwtGuiNotStarted { }
            Mock Wait-IgwtGuiWorkerReady { }
            $script:Gui.Runspace = [pscustomobject]@{}
            $script:Gui.Job = [pscustomobject]@{ Command = 'Invoke-IgwtDefenderSettingChange' }
            Start-IgwtGuiJob -Command 'Invoke-IgwtRevert' -Blocking -BusyText 'Reverting...' | Should -BeFalse
            Should -Invoke Show-IgwtGuiNotStarted -Times 1 -ParameterFilter { $What -eq "'Reverting'" }
            Start-IgwtGuiJob -Command 'Get-IgwtGuiData' | Should -BeFalse
            Should -Invoke Show-IgwtGuiNotStarted -Times 1
        }
    }
    It 'G-06: a startup switch whose change cannot start goes back' {
        $gui = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui\Gui.ps1') -Raw
        $gui | Should -Match '(?s)\$ok = Start-IgwtGuiJob -Command ''Set-IgwtStartupItemEnabled''.{0,600}if \(-not \$ok\) \{ \$cb\.IsChecked = -not \$enable \}'
    }
    It 'G-07: a toast keeps its Undo while another change runs' {
        $shell = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui\GuiShell.ps1') -Raw
        $shell.Contains('if (& $state.Busy) { & $state.Blocked ([string]$state.Toast.Tag); return }; if ($state.Timer)') | Should -BeTrue
    }
}
