# Registry Analyzer & Cleaner (3.8): the CLI verbs (DECISIONS RG24) and the plan text
# (Format-IgwtRegCleanPlan, RG23). Process tests start iGWindowsTuner.ps1 with -NoGui and check
# only argument errors and the read-only refusal (nothing is scanned or changed). Logic tests load
# the script's registry cleaner functions from its source and call them in TestMode with every
# engine command mocked, except one call of the real writer with -WhatIf (it stops at
# ShouldProcess before anything happens).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Cli = Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'
    $script:CliAst = [System.Management.Automation.Language.Parser]::ParseFile($script:Cli, [ref]$null, [ref]$null)
    $names = @('Get-IgwtCliRegKeyText', 'Write-IgwtCliRegScan', 'Get-IgwtCliRegCleanSelection', 'Invoke-IgwtCliRegClean', 'Resolve-IgwtCliRegRestoreId', 'Invoke-IgwtCliRegRestore', 'Get-IgwtCliExclusionSpec', 'Invoke-IgwtCliRegExclusion')
    $defs = @($script:CliAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | Where-Object { $names -contains $_.Name })
    $script:CliFunctionCount = $defs.Count
    foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
    # The script's own Write-IgwtCliLine writes to the host; here every line goes to one ordered log.
    $script:Log = New-Object System.Collections.Generic.List[string]
    function Write-IgwtCliLine { param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) $script:Log.Add($Text) }
    function Invoke-CliProcess([string[]]$Arguments) {
        $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Cli @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    }
    function Get-TestFinding([string]$Id, [string]$Confidence, [bool]$Selectable = $true, [string]$Kind = 'regKeyTree', [string]$Path = 'SOFTWARE\Contoso\App') {
        [pscustomobject]@{
            Id = $Id; Category = 'softwareKey'; Kind = $Kind; Hive = 'HKLM'; Sid = ''; View = '64'; Path = $Path; ValueName = ''; RuleName = ''
            Program = 'Contoso App'; OwnerHint = 'Contoso'; Confidence = $Confidence
            Evidence = @([pscustomobject]@{ Check = 'PathMissing'; Result = 'Pass'; Detail = 'C:\Program Files\Contoso missing on C:' })
            RemovalTool = $null; Size = 2; Includes = @(); Selectable = $Selectable; Reason = $(if ($Selectable) { '' } else { 'Security software: use the vendor''s removal tool.' }); ScanId = 'scan1'
        }
    }
    function Get-TestScan {
        [pscustomobject]@{
            Generated = (Get-Date).ToString('o'); ScanId = 'scan1'; Cancelled = $false; Elapsed = 1; Notes = @(); User = [pscustomobject]@{ Sid = ''; Source = 'none' }; Skipped = @{}
            Findings = @((Get-TestFinding -Id 'aaaa000000000001' -Confidence 'Safe'), (Get-TestFinding -Id 'aaaa000000000002' -Confidence 'Review' -Selectable:$true -Kind 'regKeyTree' -Path 'SOFTWARE\Contoso\Other'), (Get-TestFinding -Id 'aaaa000000000003' -Confidence 'Protected' -Selectable:$false))
        }
    }
    function Get-TestPlan([object[]]$Targets) {
        [pscustomobject]@{
            Generated = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture); ScanId = 'scan1'; Sid = ''
            Targets = @($Targets); Included = @(); Refused = @()
            Backup = [pscustomobject]@{ Folder = 'C:\ProgramData\iGWindowsTuner\Backups\regclean-<time>-<id>'; Files = @('selected.reg (1 key(s) or value(s), 2 value(s))'); Note = '' }
            Summary = "$(@($Targets).Count) entries will be removed."
        }
    }
}

Describe 'Registry cleaner CLI parameters and help (RG24)' {
    It 'loads the script''s registry cleaner functions for the logic tests' {
        $script:CliFunctionCount | Should -Be 8
    }
    It 'declares the nine new parameters once, each with a .PARAMETER entry, and reuses the existing ones' {
        $params = @($script:CliAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $help = $script:CliAst.GetHelpContent()
        foreach ($p in 'RegScan', 'Category', 'RegClean', 'RegRestore', 'RegConflict', 'RegExclusions', 'RegExclude', 'Reason', 'RegUnexclude') {
            @($params | Where-Object { $_ -eq $p }).Count | Should -Be 1 -Because $p
            $text = [string]$help.Parameters[$p.ToUpperInvariant()]
            $text | Should -Not -BeNullOrEmpty -Because $p
            foreach ($l in ($text -split "`r?`n")) { $l.TrimStart() | Should -Not -Match '^\.' -Because "a help line of -$p starts with '.'" }
        }
        foreach ($p in 'DryRun', 'Json', 'ReportPath', 'SkipRestorePoint', 'EnableSystemProtection') { @($params | Where-Object { $_ -eq $p }).Count | Should -Be 1 }
        $conflict = @($script:CliAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RegConflict' })[0]
        $conflict.DefaultValue.Value | Should -Be 'Skip'
    }
    It 'gives the script -Confirm (SupportsShouldProcess) for the writers' {
        $cb = @($script:CliAst.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })[0]
        @($cb.NamedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' }).Count | Should -Be 1
    }
    It 'asks before removing: the writer has ConfirmImpact High' {
        $cmd = Get-Command Invoke-IgwtRegistryCleanup -Module iGWindowsTuner
        $cb = @($cmd.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] })[0]
        [string]$cb.ConfirmImpact | Should -Be 'High'
    }
}

Describe 'Registry cleaner CLI argument checks (process, -NoGui)' {
    It 'accepts -ReportPath with -RegScan and rejects -Category without -RegScan' {
        $r = Invoke-CliProcess @('-RegScan', '-ReportPath', 'x.json', '-Reason', 'y', '-NoGui')
        $r.Code | Should -Be 2
        $r.Out | Should -Match '-Reason is only valid with -RegExclude'
        $r.Out | Should -Not -Match '-ReportPath is only valid'
        (Invoke-CliProcess @('-Category', 'run', '-NoGui')).Code | Should -Be 2
        $r = Invoke-CliProcess @('-RegScan', '-Category', 'run,bogus', '-NoGui')
        $r.Code | Should -Be 2
        $r.Out | Should -Match "Unknown -Category 'bogus'"
    }
    It 'rejects options of other verbs, a non-JSON report, a missing reason, -WhatIf and a misplaced -Confirm' {
        $r = Invoke-CliProcess @('-RegScan', '-RegConflict', 'Keep', '-NoGui')
        $r.Code | Should -Be 2
        $r.Out | Should -Match '-RegConflict is only valid with -RegRestore'
        (Invoke-CliProcess @('-RegScan', '-ReportPath', 'x.html', '-NoGui')).Code | Should -Be 2
        (Invoke-CliProcess @('-RegExclude', 'HKCU\Software\Contoso', '-NoGui')).Code | Should -Be 2
        (Invoke-CliProcess @('-RegScan', '-WhatIf', '-NoGui')).Code | Should -Be 2
        (Invoke-CliProcess @('-RegScan', '-Confirm', '-NoGui')).Code | Should -Be 2
        (Invoke-CliProcess @('-RegScan', '-RegExclusions', '-NoGui')).Code | Should -Be 2
    }
    It 'refuses the changing verbs in read-only mode with exit code 7 before scanning' {
        $r = Invoke-CliProcess @('-RegClean', 'Safe', '-ReadOnly', '-NoGui')
        $r.Code | Should -Be 7
        $r.Out | Should -Match 'Read-only mode'
        (Invoke-CliProcess @('-RegRestore', 'Last', '-ReadOnly', '-NoGui')).Code | Should -Be 7
        (Invoke-CliProcess @('-RegExclude', 'HKCU\Software\Contoso', '-Reason', 'kept', '-ReadOnly', '-NoGui')).Code | Should -Be 7
        (Invoke-CliProcess @('-RegUnexclude', 'HKCU\Software\Contoso', '-ReadOnly', '-NoGui')).Code | Should -Be 7
    }
}

Describe 'Format-IgwtRegCleanPlan (RG23)' {
    It 'lists key, program, evidence, included entries, refusals, the backup and how to restore' {
        $t = Get-TestFinding -Id 'aaaa000000000001' -Confidence 'Safe'
        $plan = Get-TestPlan @($t)
        $plan.Included = @([pscustomobject]@{ Id = 'aaaa000000000009'; Path = 'SOFTWARE\Contoso\App\Sub'; ValueName = ''; IncludedIn = 'aaaa000000000001'; Note = 'included in HKLM\SOFTWARE\Contoso\App' })
        $plan.Refused = @([pscustomobject]@{ Id = 'aaaa000000000003'; Category = 'service'; Program = 'Contoso Service'; Path = 'SYSTEM\CurrentControlSet\Services\Contoso'; ValueName = ''; RuleName = ''; Reason = 'This entry is shown for information only.' })
        $plan.Backup.Note = 'Firewall rules are saved in firewall-rules.json, not in selected.reg: their store is a protected system key.'
        $text = Format-IgwtRegCleanPlan -Plan $plan
        $text | Should -BeOfType [string]
        $text | Should -Match 'nothing has changed yet'
        $text | Should -Match ([regex]::Escape('HKLM\SOFTWARE\Contoso\App  [Safe, Software keys]'))
        $text | Should -Match 'Program: Contoso App'
        $text | Should -Match 'PathMissing: Pass'
        $text | Should -Match ([regex]::Escape('Also removed with it: SOFTWARE\Contoso\App\Sub'))
        $text | Should -Match 'Not removed:'
        $text | Should -Match 'shown for information only'
        $text | Should -Match 'Backup folder: '
        $text | Should -Match 'firewall-rules.json, not in selected.reg'
        $text | Should -Match 'Change journal'
        ($text -split "`r?`n") | ForEach-Object { $_ | Should -Not -Match '[^\x20-\x7E]' }
    }
    It 'shows values, the 32-bit view and firewall rules by their own names, and says when nothing will be removed' {
        $v = Get-TestFinding -Id 'aaaa000000000004' -Confidence 'Review' -Selectable:$true -Kind 'regValue' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        $v.Category = 'run'; $v.ValueName = 'ContosoTray'; $v.View = '32'
        $fw = Get-TestFinding -Id 'aaaa000000000005' -Confidence 'Review' -Selectable:$true -Kind 'firewallRule' -Path ''
        $fw.Category = 'firewallRule'; $fw.Hive = ''; $fw.View = ''; $fw.RuleName = '{0000-contoso}'
        $text = Format-IgwtRegCleanPlan -Plan (Get-TestPlan @($v, $fw))
        $text | Should -Match ([regex]::Escape("CurrentVersion\Run value 'ContosoTray' (32-bit view)  [Review, Run and RunOnce]"))
        $text | Should -Match ([regex]::Escape('Firewall rule {0000-contoso}  [Review, Firewall rules]'))
        Format-IgwtRegCleanPlan -Plan (Get-TestPlan @()) | Should -Match 'Nothing will be removed.'
    }
    It 'is read-only: no SupportsShouldProcess and exported for the CLI' {
        $cmd = Get-Command Format-IgwtRegCleanPlan -Module iGWindowsTuner
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeFalse
    }
}

Describe 'Registry cleaner CLI: -RegScan output and -RegClean (TestMode)' {
    BeforeEach {
        $script:Log.Clear()
        Mock Get-IgwtRegistryLeftovers { Get-TestScan }
        Mock Get-IgwtRegCleanPlan { $script:Log.Add('PLAN-BUILT'); Get-TestPlan @($Findings) }
        Mock Invoke-IgwtRegistryCleanup {
            $script:Log.Add('WRITER')
            [pscustomobject]@{ SessionId = 'sess1'; Backup = 'C:\x'; RestorePoint = $null; Removed = @($Plan.Targets).Count; Refused = 0; Failed = 0; NotStarted = 0; Message = ''
                Results = @($Plan.Targets | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Kind = $_.Kind; Hive = $_.Hive; Path = $_.Path; ValueName = ''; RuleName = ''; Result = 'Removed'; Message = '' } })
            }
        }
    }
    It 'prints every finding with its id and confidence' {
        Write-IgwtCliRegScan -Scan (Get-TestScan)
        $all = $script:Log -join "`n"
        $all | Should -Match '\[Safe\] +aaaa000000000001'
        $all | Should -Match '\[Protected\] +aaaa000000000003'
        $all | Should -Match 'Scan finished'
        $all | Should -Not -Match '(?i)problem|error'
    }
    It "'Safe' selects exactly the selectable Safe findings of a fresh scan" {
        $sel = Get-IgwtCliRegCleanSelection -Scan (Get-TestScan) -Selection @('Safe')
        @($sel.Findings).Count | Should -Be 1
        $sel.Findings[0].Id | Should -Be 'aaaa000000000001'
        $sel = Get-IgwtCliRegCleanSelection -Scan (Get-TestScan) -Selection @('aaaa000000000002,aaaa000000000003', 'nope')
        @($sel.Findings | ForEach-Object { $_.Id }) | Should -Be @('aaaa000000000002', 'aaaa000000000003')
        @($sel.Unknown) | Should -Be @('nope')
    }
    It 'stops with exit code 2 on an unknown id, before any plan' {
        $r = Invoke-IgwtCliRegClean -Selection @('nope')
        $r.Code | Should -Be 2
        Should -Invoke Get-IgwtRegCleanPlan -Times 0
        Should -Invoke Invoke-IgwtRegistryCleanup -Times 0
    }
    It '-DryRun prints the plan and never calls the writer' {
        $r = Invoke-IgwtCliRegClean -Selection @('Safe') -DryRun
        $r.Code | Should -Be 0
        ($script:Log -join "`n") | Should -Match 'Registry cleanup preview'
        ($script:Log -join "`n") | Should -Match 'Dry run: nothing was changed'
        Should -Invoke Invoke-IgwtRegistryCleanup -Times 0
        $j = Invoke-IgwtCliRegClean -Selection @('Safe') -DryRun -Json
        ($j.Json | ConvertFrom-Json).ScanId | Should -Be 'scan1'
        Should -Invoke Invoke-IgwtRegistryCleanup -Times 0
    }
    It 'prints the plan before the writer and passes -Confirm through' {
        $r = Invoke-IgwtCliRegClean -Selection @('Safe') -SkipRestorePoint -ConfirmArgs @{ Confirm = $false }
        $r.Code | Should -Be 0
        $preview = $script:Log.IndexOf('Registry cleanup preview (nothing has changed yet)')
        $preview | Should -BeGreaterThan -1
        $preview | Should -BeLessThan $script:Log.IndexOf('WRITER')
        Should -Invoke Invoke-IgwtRegistryCleanup -Times 1 -ParameterFilter { $PesterBoundParameters.ContainsKey('Confirm') -and -not $Confirm -and $SkipRestorePoint }
        ($script:Log -join "`n") | Should -Match 'Restore with: -RegRestore sess1'
    }
    It 'leaves -Confirm to the writer when the caller does not pass it (ConfirmImpact High asks)' {
        $null = Invoke-IgwtCliRegClean -Selection @('Safe')
        Should -Invoke Invoke-IgwtRegistryCleanup -Times 1 -ParameterFilter { -not $PesterBoundParameters.ContainsKey('Confirm') }
    }
    It 'maps the writer result to exit codes 0, 1 and 7' {
        Mock Invoke-IgwtRegistryCleanup { [pscustomobject]@{ SessionId = 's'; Backup = ''; RestorePoint = $null; Removed = 0; Refused = 0; Failed = 1; NotStarted = 0; Message = 'stopped'; Results = @() } }
        (Invoke-IgwtCliRegClean -Selection @('Safe') -ConfirmArgs @{ Confirm = $false }).Code | Should -Be 1
        Mock Invoke-IgwtRegistryCleanup { throw 'Read-only mode: Invoke-IgwtRegistryCleanup is disabled.' }
        (Invoke-IgwtCliRegClean -Selection @('Safe') -ConfirmArgs @{ Confirm = $false }).Code | Should -Be 7
        Mock Invoke-IgwtRegistryCleanup { throw 'System Protection is off' }
        (Invoke-IgwtCliRegClean -Selection @('Safe') -ConfirmArgs @{ Confirm = $false }).Code | Should -Be 1
        Mock Invoke-IgwtRegistryCleanup { $null }
        (Invoke-IgwtCliRegClean -Selection @('Safe')).Code | Should -Be 0
        ($script:Log -join "`n") | Should -Match 'Cancelled; nothing was changed'
    }
}

Describe 'Registry cleaner CLI: the real writer honors a declined confirmation (TestMode)' {
    BeforeEach {
        $script:Log.Clear()
        Mock Get-IgwtRegistryLeftovers { Get-TestScan }
        Mock Get-IgwtRegCleanPlan { Get-TestPlan @($Findings) }
    }
    It 'stops at ShouldProcess: no restore point, session or backup folder' {
        Mock -ModuleName iGWindowsTuner Start-IgwtChangeSession { throw 'must not run' }
        Mock -ModuleName iGWindowsTuner New-IgwtRestorePoint { throw 'must not run' }
        Mock -ModuleName iGWindowsTuner New-IgwtPrivateBackupFolder { throw 'must not run' }
        $r = Invoke-IgwtCliRegClean -Selection @('Safe') -ConfirmArgs @{ WhatIf = $true }
        $r.Code | Should -Be 0
        ($script:Log -join "`n") | Should -Match 'Cancelled; nothing was changed'
        $script:Log.IndexOf('Registry cleanup preview (nothing has changed yet)') | Should -BeGreaterThan -1
        Should -Invoke -ModuleName iGWindowsTuner Start-IgwtChangeSession -Times 0
        Should -Invoke -ModuleName iGWindowsTuner New-IgwtRestorePoint -Times 0
        Should -Invoke -ModuleName iGWindowsTuner New-IgwtPrivateBackupFolder -Times 0
    }
}

Describe 'Registry cleaner CLI: -RegRestore (TestMode)' {
    BeforeEach {
        $script:Log.Clear()
        Mock Get-IgwtJournalSessions {
            $steps = [ordered]@{}
            $steps['1'] = [pscustomobject]@{ Step = 1; Result = 'Committed'; EntryId = 'entry1'; Target = @{ provider = 'regClean'; key = 'regclean|regKeyTree|HKLM|-|64|SOFTWARE\Contoso\App' } }
            $other = [ordered]@{}
            $other['1'] = [pscustomobject]@{ Step = 1; Result = 'Committed'; EntryId = 'entry2'; Target = @{ provider = 'registry'; key = 'x' } }
            @(
                [pscustomobject]@{ Id = 'sessReg'; Origin = @{ type = 'regClean'; ref = 'C:\b' }; Title = 'Registry cleanup (1 entry)'; Steps = $steps }
                [pscustomobject]@{ Id = 'sessApply'; Origin = @{ type = 'apply' }; Title = 'Apply'; Steps = $other }
            )
        }
        Mock Get-IgwtRevertPlan {
            $script:Log.Add('PLAN-READ')
            @(
                [pscustomobject]@{ Key = 'k1'; Item = 'regclean:softwareKey'; Status = 'Ready'; Message = '' }
                [pscustomobject]@{ Key = 'k2'; Item = 'regclean:run'; Status = 'Conflict'; Message = 'Changed since iG set it.' }
            )
        }
        Mock Invoke-IgwtJournalRevert { $script:Log.Add('REVERT'); [pscustomobject]@{ Session = 'r1'; Results = @([pscustomobject]@{ Key = 'k1'; Result = 'Reverted'; Message = '' }, [pscustomobject]@{ Key = 'k2'; Result = 'Skipped'; Message = '' }) } }
    }
    It 'resolves Last, a regClean session id and a removed entry id' {
        (Resolve-IgwtCliRegRestoreId -Id 'Last').SessionId | Should -Be 'sessReg'
        (Resolve-IgwtCliRegRestoreId -Id 'sessReg').SessionId | Should -Be 'sessReg'
        (Resolve-IgwtCliRegRestoreId -Id 'entry1').EntryId | Should -Be 'entry1'
        Resolve-IgwtCliRegRestoreId -Id 'sessApply' | Should -BeNullOrEmpty
        Resolve-IgwtCliRegRestoreId -Id 'entry2' | Should -BeNullOrEmpty
        Resolve-IgwtCliRegRestoreId -Id 'nope' | Should -BeNullOrEmpty
    }
    It 'refuses ids that are not a registry cleanup with exit code 2' {
        (Invoke-IgwtCliRegRestore -Id 'sessApply').Code | Should -Be 2
        Should -Invoke Get-IgwtRevertPlan -Times 0
    }
    It '-DryRun prints the restore plan and never reverts' {
        $r = Invoke-IgwtCliRegRestore -Id 'entry1' -DryRun
        $r.Code | Should -Be 0
        Should -Invoke Get-IgwtRevertPlan -Times 1 -ParameterFilter { $EntryId -eq 'entry1' }
        Should -Invoke Invoke-IgwtJournalRevert -Times 0
        ($script:Log -join "`n") | Should -Match '\[Conflict\] +k2'
    }
    It 'prints the plan first, then reverts with Skip (default) or Keep for every Conflict key' {
        $r = Invoke-IgwtCliRegRestore -Id 'sessReg' -ConfirmArgs @{ Confirm = $false }
        $r.Code | Should -Be 0
        $script:Log.IndexOf('PLAN-READ') | Should -BeLessThan $script:Log.IndexOf('REVERT')
        @($script:Log | Where-Object { $_ -like '*k2*' }).Count | Should -BeGreaterThan 0
        Should -Invoke Invoke-IgwtJournalRevert -Times 1 -ParameterFilter { $Decisions['k2'] -eq 'Skip' -and -not $Decisions.ContainsKey('k1') -and -not $Confirm }
        $null = Invoke-IgwtCliRegRestore -Id 'sessReg' -Conflict Keep
        Should -Invoke Invoke-IgwtJournalRevert -Times 1 -ParameterFilter { $Decisions['k2'] -eq 'Keep' -and -not $PesterBoundParameters.ContainsKey('Confirm') }
    }
    It 'returns exit code 1 when a restore failed' {
        Mock Invoke-IgwtJournalRevert { [pscustomobject]@{ Session = 'r1'; Results = @([pscustomobject]@{ Key = 'k1'; Result = 'Failed'; Message = 'Refused: the key exists again with other data; nothing changed' }) } }
        (Invoke-IgwtCliRegRestore -Id 'Last').Code | Should -Be 1
    }
}

Describe 'Registry cleaner CLI: exclusions (TestMode)' {
    BeforeEach {
        $script:Log.Clear()
        Mock Get-IgwtRegCleanExclusions { [pscustomobject]@{ SchemaVersion = 1; Path = 'C:\x\regclean-exclusions.json'; Entries = @([pscustomobject]@{ pattern = 'HKCU\Software\Kept'; scope = 'key'; reason = 'used'; addedUtc = '2026-11-01T10:00:00Z' }) } }
        Mock Save-IgwtRegCleanExclusions { [pscustomobject]@{ SchemaVersion = 1; Path = 'C:\x\regclean-exclusions.json'; Entries = @($Entries) } }
    }
    It 'infers the kind from the pattern or takes a key:, value: or path: prefix' {
        (Get-IgwtCliExclusionSpec -Text 'HKLM\SOFTWARE\Contoso').Scope | Should -Be 'key'
        (Get-IgwtCliExclusionSpec -Text 'C:\Games\Contoso').Scope | Should -Be 'path'
        (Get-IgwtCliExclusionSpec -Text '%ProgramFiles%\Contoso').Scope | Should -Be 'path'
        $v = Get-IgwtCliExclusionSpec -Text 'value:HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Contoso'
        $v.Scope | Should -Be 'value'
        $v.Pattern | Should -Be 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Contoso'
    }
    It 'lists the exclusions (text and JSON)' {
        (Invoke-IgwtCliRegExclusion -Action List).Code | Should -Be 0
        ($script:Log -join "`n") | Should -Match 'HKCU\\Software\\Kept'
        ((Invoke-IgwtCliRegExclusion -Action List -Json).Json | ConvertFrom-Json).Entries[0].scope | Should -Be 'key'
    }
    It 'adds an exclusion with its reason, keeps the others and previews with -DryRun' {
        (Invoke-IgwtCliRegExclusion -Action Add -Pattern 'HKLM\SOFTWARE\Contoso' -Reason 'still used' -DryRun).Code | Should -Be 0
        Should -Invoke Save-IgwtRegCleanExclusions -Times 0
        (Invoke-IgwtCliRegExclusion -Action Add -Pattern 'HKLM\SOFTWARE\Contoso' -Reason 'still used').Code | Should -Be 0
        Should -Invoke Save-IgwtRegCleanExclusions -Times 1 -ParameterFilter { @($Entries).Count -eq 2 -and $Entries[1].pattern -eq 'HKLM\SOFTWARE\Contoso' -and $Entries[1].scope -eq 'key' -and $Entries[1].reason -eq 'still used' -and -not $Confirm }
        (Invoke-IgwtCliRegExclusion -Action Add -Pattern 'hkcu\software\kept' -Reason 'again').Code | Should -Be 0
        Should -Invoke Save-IgwtRegCleanExclusions -Times 1
    }
    It 'removes an exclusion by pattern; an unknown pattern is exit code 2' {
        (Invoke-IgwtCliRegExclusion -Action Remove -Pattern 'HKCU\Software\Kept').Code | Should -Be 0
        Should -Invoke Save-IgwtRegCleanExclusions -Times 1 -ParameterFilter { @($Entries).Count -eq 0 }
        (Invoke-IgwtCliRegExclusion -Action Remove -Pattern 'HKCU\Software\Nope').Code | Should -Be 2
        (Invoke-IgwtCliRegExclusion -Action Remove -Pattern 'path:HKCU\Software\Kept').Code | Should -Be 2
    }
    It 'maps a schema refusal to 2 and read-only to 7' {
        Mock Save-IgwtRegCleanExclusions { throw 'The exclusion list was not saved: entry 2: a path pattern starts with a drive or a %Variable%\.' }
        (Invoke-IgwtCliRegExclusion -Action Add -Pattern 'relative\folder' -Reason 'x').Code | Should -Be 2
        Mock Save-IgwtRegCleanExclusions { throw 'Read-only mode: Save-IgwtRegCleanExclusions is disabled.' }
        (Invoke-IgwtCliRegExclusion -Action Add -Pattern 'HKLM\SOFTWARE\Contoso' -Reason 'x').Code | Should -Be 7
    }
}
