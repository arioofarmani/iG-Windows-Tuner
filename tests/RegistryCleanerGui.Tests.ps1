BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    # The demo scan of the render suite (fictional programs, the real result shape).
    $script:MockFile = Join-Path $PSScriptRoot 'gui\GuiMocks.ps1'
}

# Registry cleaner page (DECISIONS RG20, RG21, RG23): rows, grouping, selection, preview, restore paths.
Describe 'Registry cleaner page: rows and pure helpers' {
    It 'makes only removable Safe and Review rows tickable and shows confidence as glyph and word' {
        InModuleScope iGWindowsTuner {
            $ev = @([pscustomobject]@{ Check = 'PathMissing'; Result = 'Pass'; Detail = 'C:\x\a.app missing' }, [pscustomobject]@{ Check = 'NoOwner'; Result = 'Pass'; Detail = '' })
            $safe = [pscustomobject]@{ Id = 'a1'; Category = 'run'; Kind = 'regValue'; Hive = 'HKCU'; View = '64'; Path = 'Software\Microsoft\Windows\CurrentVersion\Run'; ValueName = 'Tool'; Program = 'Tool'; OwnerHint = 'Tool'; Confidence = 'Safe'; Evidence = $ev; Selectable = $true; Reason = '' }
            $r = New-IgwtGuiRegCleanRow -Finding $safe -Selected $false
            $r.Key | Should -Be 'f|a1'
            $r.On | Should -BeFalse
            $r.OnEnabled | Should -BeTrue
            $r.KeyText | Should -Be 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tool'
            $r.Confidence | Should -Be 'Safe'
            $r.ConfidenceGlyph | Should -Be ([string][char]0xE73E)
            $r.Evidence | Should -Be 'PathMissing: C:\x\a.app missing'
            $r.EvidenceTip | Should -Match 'NoOwner: Pass'
            $r.CategoryText | Should -Be 'Run and RunOnce'
            (New-IgwtGuiRegCleanRow -Finding $safe -Selected $true).On | Should -BeTrue
            $prot = $safe | Select-Object *; $prot.Confidence = 'Protected'; $prot.Selectable = $false; $prot.Reason = 'Security software'
            $p = New-IgwtGuiRegCleanRow -Finding $prot -Selected $true
            $p.OnEnabled | Should -BeFalse; $p.On | Should -BeFalse; $p.ConfidenceGlyph | Should -Be ([string][char]0xEA18); $p.OnTip | Should -Be 'Security software'
            $svc = [pscustomobject]@{ Id = 's1'; Category = 'service'; Kind = 'reportOnly'; Hive = 'HKLM'; View = ''; Path = 'SYSTEM\CurrentControlSet\Services\X'; Confidence = 'Review'; Selectable = $false; Reason = 'iG does not remove services.' }
            (New-IgwtGuiRegCleanRow -Finding $svc).OnEnabled | Should -BeFalse
            $k32 = [pscustomobject]@{ Kind = 'regKeyTree'; Hive = 'HKLM'; View = '32'; Path = 'SOFTWARE\Contoso' }
            Get-IgwtGuiRegCleanKeyText -Finding $k32 | Should -Be 'HKLM\SOFTWARE\Contoso (32-bit view)'
            Get-IgwtGuiRegCleanKeyText -Finding ([pscustomobject]@{ Kind = 'firewallRule'; RuleName = '{abc}' }) | Should -Be 'Firewall rule {abc}'
        }
    }

    It 'builds Removed rows from regClean journal rows' {
        InModuleScope iGWindowsTuner {
            $t = [pscustomobject]@{ Session = 's4'; SessionTitle = 'Registry cleanup (1 entry)'; Origin = 'regClean'; When = '2026-10-31T10:12:00.0000000Z'; Step = 1; Item = 'regclean:uninstall'; Target = 'regclean|regValue|HKCU|S-1-5-21-1|64|Software\Run|My|Tool'; EntryId = 'e5'; InEffect = $true }
            $r = New-IgwtGuiRegCleanRemovedRow -Row $t
            $r.Key | Should -Be 'r|e5'; $r.View | Should -Be 'Removed'; $r.EntryId | Should -Be 'e5'
            $r.KeyText | Should -Be 'HKCU\Software\Run\My|Tool'
            $r.CategoryText | Should -Be 'Uninstall entries'
            $r.OnEnabled | Should -BeFalse
            $r.Program | Should -Match '^Registry cleanup \(1 entry\), '
        }
    }

    It 'builds exclusion entries that match only the row (wildcards escaped) and refuses rows without a key or path' {
        InModuleScope iGWindowsTuner {
            $s = Get-IgwtGuiRegCleanExclusionSpec -Finding ([pscustomobject]@{ Kind = 'regKeyTree'; Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool [x64]' })
            $s.Scope | Should -Be 'key'
            $s.Pattern | Should -Be 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool `[x64`]'
            ('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool [x64]' -like $s.Pattern) | Should -BeTrue
            ('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool 6' -like $s.Pattern) | Should -BeFalse
            $v = Get-IgwtGuiRegCleanExclusionSpec -Finding ([pscustomobject]@{ Kind = 'regValue'; Hive = 'HKCU'; Path = 'Software\Run'; ValueName = 'Tool*' })
            $v.Scope | Should -Be 'value'; $v.Pattern | Should -Be 'HKCU\Software\Run\Tool`*'
            (Get-IgwtGuiRegCleanExclusionSpec -Finding ([pscustomobject]@{ Kind = 'regValue'; Hive = 'HKCU'; Path = 'Software\Run'; ValueName = '' })).Scope | Should -Be ''
            $fw = Get-IgwtGuiRegCleanExclusionSpec -Finding ([pscustomobject]@{ Kind = 'firewallRule'; Hive = ''; Path = ''; Facts = [pscustomobject]@{ Program = 'D:\Games\x.app' } })
            $fw.Scope | Should -Be 'path'; $fw.Pattern | Should -Be 'D:\Games\x.app'
            $task = Get-IgwtGuiRegCleanExclusionSpec -Finding ([pscustomobject]@{ Kind = 'reportOnly'; Category = 'task'; Hive = ''; Path = '\Vendor\Task' })
            $task.Scope | Should -Be ''; $task.Why | Should -Not -BeNullOrEmpty
            $errors = @(Test-IgwtRegCleanExclusionData -Document ([pscustomobject]@{ schemaVersion = 1; entries = @([pscustomobject]@{ pattern = $s.Pattern; scope = $s.Scope; reason = 'still used'; addedUtc = '2026-11-10T10:00:00Z' }) }))
            $errors | Should -BeNullOrEmpty -Because 'the GUI writes entries the strict schema accepts'
            Get-IgwtGuiRegCleanReasonText -Text ("  still`tused " + [char]0x00E9 + ('x' * 300)) | Should -Match '^still used x{189}$'
        }
    }

    It 'opens only https removal tool pages and otherwise shows the vendor text (RG11)' {
        InModuleScope iGWindowsTuner {
            (Get-IgwtGuiRegCleanRemovalTool -Finding ([pscustomobject]@{ RemovalTool = [pscustomobject]@{ Name = 'Tool'; Url = 'https://example.com/tool'; Text = '' } })).Url | Should -Be 'https://example.com/tool'
            $h = Get-IgwtGuiRegCleanRemovalTool -Finding ([pscustomobject]@{ RemovalTool = [pscustomobject]@{ Name = 'Tool'; Url = 'http://example.com/tool'; Text = 'Contact support.' } })
            $h.Url | Should -Be ''; $h.Text | Should -Be 'Contact support.'
            (Get-IgwtGuiRegCleanRemovalTool -Finding $null).Text | Should -Not -BeNullOrEmpty
        }
    }

    It 'maps the restore point answer like the apply flow (RG21)' {
        InModuleScope iGWindowsTuner {
            $a = ConvertTo-IgwtGuiRegCleanRestorePointChoice -Answer 'Yes' -SystemProtectionOn $true
            $a.Cancel | Should -BeFalse; $a.SkipRestorePoint | Should -BeFalse; $a.EnableSystemProtection | Should -BeFalse
            $b = ConvertTo-IgwtGuiRegCleanRestorePointChoice -Answer 'Yes' -SystemProtectionOn $false
            $b.EnableSystemProtection | Should -BeTrue; $b.SkipRestorePoint | Should -BeFalse
            $c = ConvertTo-IgwtGuiRegCleanRestorePointChoice -Answer 'No' -SystemProtectionOn $false
            $c.SkipRestorePoint | Should -BeTrue; $c.EnableSystemProtection | Should -BeFalse
            (ConvertTo-IgwtGuiRegCleanRestorePointChoice -Answer 'Cancel' -SystemProtectionOn $true).Cancel | Should -BeTrue
        }
    }

    It 'uses no headline totals, problem or speed wording on the page' {
        $text = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\RegistryCleanerPage.ps1') -Raw
        $text | Should -Not -Match '(?i)\b(speed|faster|boost|performance|problems?|errors found|issues found)\b'
        $xaml = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw
        $page = $xaml.Substring($xaml.IndexOf('x:Name="PageRegistryCleaner"'))
        $page = $page.Substring(0, $page.IndexOf('<!-- Disk analyzer -->'))
        $page | Should -Not -Match '(?i)\b(speed|faster|boost|performance|problems?)\b'
    }
}

Describe 'Registry cleaner page: grid, selection and restore paths' {
    BeforeAll {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { return }
        InModuleScope iGWindowsTuner -Parameters @{ MockFile = $script:MockFile } {
            param($MockFile)
            # Only the demo scan of the render mocks is used here.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($MockFile, [ref]$null, [ref]$null)
            $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'script:Get-IgwtRegistryLeftovers' }, $true)
            $body = $fn.Body.Extent.Text
            $script:IgwtTestRegScanBlock = [scriptblock]::Create($body.Substring(1, $body.Length - 2))
            $script:MockNow = [datetime]'2026-10-22T19:30:00'
        }
    }

    BeforeEach {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { return }
        InModuleScope iGWindowsTuner {
            $script:IgwtTestJobs = New-Object System.Collections.Generic.List[object]
            $w = New-IgwtMainWindow
            $null = Set-IgwtGuiTheme -Target $w -Name Dark
            $script:Gui = @{ Window = $w; C = @{}; Grids = @{}; ViewState = @{}; NoStateSave = $true; ReadOnly = $false; IsAdmin = $true; DiagnosticsPath = $null; Job = $null; Jobs = $null; Runspace = $null; Cts = $null }
            foreach ($n in $script:IgwtGuiControlNames) { $script:Gui.C[$n] = $w.FindName($n) }
            Initialize-IgwtGuiRegistryCleanerPage
        }
    }

    AfterEach {
        InModuleScope iGWindowsTuner {
            foreach ($k in @($script:IgwtGrids.Keys)) { $script:IgwtGrids.Remove($k) }
            $script:Gui = $null; $script:IgwtTestJobs = $null; $script:IgwtTestToast = $null
        }
    }

    It 'pre-selects nothing, groups by program then category, and keeps the grouping under a filter' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $scan = & $script:IgwtTestRegScanBlock
            Set-IgwtGuiRegCleanScan -Scan $scan
            $g = $script:Gui.Grids.RegList
            @($script:Gui.RegClean.Selected.Keys).Count | Should -Be 0
            @(Get-IgwtGridViewRows -Grid $g | Where-Object { $_.On }).Count | Should -Be 0 -Because 'nothing is ticked after a scan'
            $g.C.CountText.Text | Should -Be '8 entries'
            $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($g.C.Grid.ItemsSource)
            @($view.GroupDescriptions | ForEach-Object { $_.PropertyName }) | Should -Be @('Program', 'CategoryText')
            @($view.Groups | ForEach-Object { [string]$_.Name }) | Should -Contain 'Contoso Photo Studio 4'
            $contoso = @($view.Groups | Where-Object { [string]$_.Name -eq 'Contoso Photo Studio 4' })[0]
            @($contoso.Items | ForEach-Object { [string]$_.Name }) | Should -Be @('App Paths', 'Uninstall entries')
            # A chip sets a new item array: the grouping is applied to its view again.
            Set-IgwtGridChip -Grid $g -ChipId 'review'
            $view2 = [System.Windows.Data.CollectionViewSource]::GetDefaultView($g.C.Grid.ItemsSource)
            [object]::ReferenceEquals($view, $view2) | Should -BeFalse
            $view2.GroupDescriptions.Count | Should -Be 2 -Because 'grouping survives SmartGrid filtering'
            @($view2.Groups | ForEach-Object { [string]$_.Name }) | Should -Not -Contain 'Contoso Photo Studio 4'
        }
    }

    It 'ticks every Safe row with Select all Safe, also rows hidden by a filter, and says how many' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            $g = $script:Gui.Grids.RegList
            Set-IgwtGridChip -Grid $g -ChipId 'review'
            Select-IgwtGuiRegCleanSafe
            @(Get-IgwtGuiRegCleanSelection).Count | Should -Be 3
            @(Get-IgwtGuiRegCleanSelection | ForEach-Object { $_.Confidence } | Select-Object -Unique) | Should -Be @('Safe')
            $script:Gui.C.StatusText.Text | Should -Be '3 selected (3 hidden by the current filter)'
            $script:Gui.C.RegRemoveButton.IsEnabled | Should -BeTrue
            Set-IgwtGridChip -Grid $g -ChipId 'review' -On $false
            Set-IgwtGridChip -Grid $g -ChipId 'selected'
            $g.C.CountText.Text | Should -Be '3 of 8 shown'
            # A tick box click on a Review row.
            $review = @($g.Index.Rows | Where-Object { $_.ConfidenceKey -eq 'Review' -and $_.OnEnabled })[0]
            Set-IgwtGuiRegCleanTick -Key $review.Key -On $true -Row $review
            @(Get-IgwtGuiRegCleanSelection).Count | Should -Be 4
            $script:Gui.C.StatusText.Text | Should -Be '4 selected'
            # A protected or report-only row is never part of the selection, even when its id is ticked.
            $prot = @($g.Index.Rows | Where-Object { $_.ConfidenceKey -eq 'Protected' })[0]
            $script:Gui.RegClean.Selected[$prot.Id] = $true
            @(Get-IgwtGuiRegCleanSelection).Count | Should -Be 4
            # A new scan clears the selection.
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            @(Get-IgwtGuiRegCleanSelection).Count | Should -Be 0
            $script:Gui.C.RegRemoveButton.IsEnabled | Should -BeFalse
        }
    }

    It 'shows removed entries only on the Removed view' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            $rows = @(
                [pscustomobject]@{ Session = 's4'; SessionTitle = 'Registry cleanup (2 entries)'; Origin = 'regClean'; When = '2026-10-31T10:12:00Z'; Step = 1; Item = 'regclean:uninstall'; Target = 'regclean|regKeyTree|HKLM|-|64|SOFTWARE\X'; EntryId = 'e5'; InEffect = $true }
                [pscustomobject]@{ Session = 's4'; SessionTitle = 'Registry cleanup (2 entries)'; Origin = 'regClean'; When = '2026-10-31T10:12:00Z'; Step = 2; Item = 'regclean:run'; Target = 'regclean|regValue|HKLM|-|64|SOFTWARE\Run|Y'; EntryId = 'e6'; InEffect = $false }
                [pscustomobject]@{ Session = 's1'; SessionTitle = 'Preset'; Origin = 'preset'; When = '2026-10-30T10:12:00Z'; Step = 1; Item = 'gfx.x'; Target = 'action|gfx.x|0|registry'; EntryId = 'e1'; InEffect = $true }
            )
            Set-IgwtGuiRegCleanTimeline -Timeline ([pscustomobject]@{ Rows = $rows })
            $g = $script:Gui.Grids.RegList
            $g.C.CountText.Text | Should -Be '8 entries'
            Set-IgwtGridChip -Grid $g -ChipId 'removed'
            @(Get-IgwtGridViewRows -Grid $g | ForEach-Object { $_.Key }) | Should -Be @('r|e5') -Because 'only regClean entries still in effect'
            Get-IgwtGuiRegCleanLastSessionId | Should -Be 's4'
        }
    }

    It 'restores through its own Get-IgwtRevertPlan job with the cleanup ids and never reads the Journal page' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            Mock Start-IgwtGuiJob { $script:IgwtTestJobs.Add([pscustomobject]@{ Command = $Command; Parameters = $Parameters; Channel = $Channel; Blocking = [bool]$Blocking; OnComplete = $OnComplete; Context = $Context }); $true }
            Mock Get-IgwtGuiGridItem { throw 'the Journal page grid must not be read' }
            Mock Get-IgwtGuiGridItems { throw 'the Journal page grid must not be read' }
            Mock Start-IgwtGuiJournalRevert { }
            Mock Show-IgwtGuiTextDialog { $false }
            $script:IgwtTestToast = $null
            Mock Show-IgwtGuiToast { $script:IgwtTestToast = @{ Action = $Action; Arg = $ActionArgument; Text = $ActionText } }
            Mock Show-IgwtGuiJournalPlan { }

            # Restore last cleanup: the session of the cleanup this window ran.
            $script:Gui.RegClean.LastSessionId = 'sess-42'
            Invoke-IgwtGuiRegCleanRestoreLast
            $j = $script:IgwtTestJobs[$script:IgwtTestJobs.Count - 1]
            $j.Command | Should -Be 'Get-IgwtRevertPlan'; $j.Channel | Should -Be 'regcleanrevert'
            $j.Parameters.SessionId | Should -Be 'sess-42'; $j.Parameters.ContainsKey('EntryId') | Should -BeFalse

            # Row action Restore on the Removed view: the entry id.
            Set-IgwtGuiRegCleanTimeline -Timeline ([pscustomobject]@{ Rows = @([pscustomobject]@{ Session = 's4'; SessionTitle = 'Registry cleanup'; Origin = 'regClean'; When = '2026-10-31T10:12:00Z'; Step = 1; Item = 'regclean:uninstall'; Target = 'regclean|regKeyTree|HKLM|-|64|SOFTWARE\X'; EntryId = 'e5'; InEffect = $true }) })
            $g = $script:Gui.Grids.RegList
            $removedRow = @($g.Index.Rows | Where-Object { $_.View -eq 'Removed' })[0]
            $restore = @($g.Actions | Where-Object { $_.Id -eq 'restore' })[0]
            Get-IgwtGridActionBlock -Action $restore -Rows @($removedRow) | Should -Be ''
            & $restore.Run @($removedRow)
            $j = $script:IgwtTestJobs[$script:IgwtTestJobs.Count - 1]
            $j.Parameters.EntryId | Should -Be 'e5'; $j.Parameters.ContainsKey('SessionId') | Should -BeFalse

            # The result toast Undo: the session id of the cleanup just run.
            $res = [pscustomobject]@{ SessionId = 'sess-77'; Backup = 'C:\data\Backups\regclean-x'; RestorePoint = $null; Message = ''
                Results = @([pscustomobject]@{ Id = '00000000000003e9'; Hive = 'HKLM'; Path = 'SOFTWARE\Y'; ValueName = ''; RuleName = ''; Program = 'Contoso'; Result = 'Removed'; Message = '' }) }
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            Complete-IgwtGuiRegCleanResult -Result $res
            $script:Gui.RegClean.LastSessionId | Should -Be 'sess-77'
            @($script:Gui.RegClean.Scan.Findings | Where-Object { $_.Id -eq '00000000000003e9' }).Count | Should -Be 0 -Because 'removed entries leave the found list'
            $script:IgwtTestToast.Text | Should -Be 'Undo'
            $script:IgwtTestToast.Arg | Should -Be 'sess-77'
            & $script:IgwtTestToast.Action $script:IgwtTestToast.Arg
            $j = $script:IgwtTestJobs[$script:IgwtTestJobs.Count - 1]
            $j.Command | Should -Be 'Get-IgwtRevertPlan'; $j.Parameters.SessionId | Should -Be 'sess-77'

            # The plan result goes straight to the journal preview.
            & $j.OnComplete @([pscustomobject]@{ Key = 'k'; Status = 'Ready' }) @() $j.Context
            Should -Invoke Show-IgwtGuiJournalPlan -Times 1 -Exactly
            Should -Invoke Start-IgwtGuiJournalRevert -Times 0 -Exactly
            Should -Invoke Get-IgwtGuiGridItem -Times 0 -Exactly
            Should -Invoke Get-IgwtGuiGridItems -Times 0 -Exactly
        }
    }

    It 'previews, asks about the restore point and runs the cleanup as one blocking job; read-only windows cannot' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            Mock Start-IgwtGuiJob { $script:IgwtTestJobs.Add([pscustomobject]@{ Command = $Command; Parameters = $Parameters; Channel = $Channel; Blocking = [bool]$Blocking; OnComplete = $OnComplete; Context = $Context }); $true }
            Mock Show-IgwtGuiTextDialog { $true }
            Mock Show-IgwtGuiMessage { 'No' }
            Mock Format-IgwtRegCleanPlan { 'preview' }
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            Select-IgwtGuiRegCleanSafe
            Invoke-IgwtGuiRegCleanRemove
            $j = $script:IgwtTestJobs[0]
            $j.Command | Should -Be 'Get-IgwtRegCleanPlan'; $j.Channel | Should -Be 'regcleanplan'
            @($j.Parameters.Findings).Count | Should -Be 3
            $plan = [pscustomobject]@{ Targets = @($j.Parameters.Findings); Refused = @(); Included = @() }
            & $j.OnComplete @($plan) @() $null
            Should -Invoke Format-IgwtRegCleanPlan -Times 1 -Exactly
            $j = $script:IgwtTestJobs[1]
            $j.Command | Should -Be 'Test-IgwtSystemProtectionEnabled'
            & $j.OnComplete @($true) @() $j.Context
            $j = $script:IgwtTestJobs[2]
            $j.Command | Should -Be 'Invoke-IgwtRegistryCleanup'
            $j.Blocking | Should -BeTrue
            $j.Parameters.Confirm | Should -BeFalse
            $j.Parameters.SkipRestorePoint | Should -BeTrue -Because 'the user answered No'
            $j.Parameters.EnableSystemProtection | Should -BeFalse
            [object]::ReferenceEquals($j.Parameters.Plan, $plan) | Should -BeTrue

            # Cancel at the restore point question: nothing starts.
            Mock Show-IgwtGuiMessage { 'Cancel' }
            $before = $script:IgwtTestJobs.Count
            Complete-IgwtGuiRegCleanRemove -Plan $plan -SystemProtectionOn $true
            $script:IgwtTestJobs.Count | Should -Be $before

            # Read-only window: no plan job, the change buttons are off with the reason.
            $script:Gui.ReadOnly = $true
            Update-IgwtGuiRegCleanButtons
            $script:Gui.C.RegRemoveButton.IsEnabled | Should -BeFalse
            [string]$script:Gui.C.RegRemoveButton.ToolTip | Should -Match 'Read-only'
            $script:Gui.C.RegRestoreButton.IsEnabled | Should -BeFalse
            $script:Gui.C.RegScanButton.IsEnabled | Should -BeTrue -Because 'scanning is read-only'
            Invoke-IgwtGuiRegCleanRemove
            $script:IgwtTestJobs.Count | Should -Be $before
        }
    }

    It 'adds an exclusion with a reason through the exclusion jobs and hides the row' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            Mock Start-IgwtGuiJob { $script:IgwtTestJobs.Add([pscustomobject]@{ Command = $Command; Parameters = $Parameters; Channel = $Channel; Blocking = [bool]$Blocking; OnComplete = $OnComplete; Context = $Context }); $true }
            Mock Read-IgwtGuiText { 'I still use it' }
            Mock Show-IgwtGuiToast { }
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            $g = $script:Gui.Grids.RegList
            $row = @($g.Index.Rows | Where-Object { $_.Kind -eq 'regKeyTree' -and $_.ConfidenceKey -eq 'Review' })[0]
            $exclude = @($g.Actions | Where-Object { $_.Id -eq 'exclude' })[0]
            Get-IgwtGridActionBlock -Action $exclude -Rows @($row) | Should -Be ''
            & $exclude.Run @($row)
            $j = $script:IgwtTestJobs[0]
            $j.Command | Should -Be 'Get-IgwtRegCleanExclusions'; $j.Channel | Should -Be 'regcleanexcl'
            $old = [pscustomobject]@{ pattern = 'HKLM\SOFTWARE\Old'; scope = 'key'; reason = 'old'; addedUtc = '2026-01-01T00:00:00Z' }
            & $j.OnComplete @([pscustomobject]@{ SchemaVersion = 1; Entries = @($old); Path = 'x' }) @() $j.Context
            $s = $script:IgwtTestJobs[1]
            $s.Command | Should -Be 'Save-IgwtRegCleanExclusions'; $s.Blocking | Should -BeTrue; $s.Parameters.Confirm | Should -BeFalse
            @($s.Parameters.Entries).Count | Should -Be 2
            $new = @($s.Parameters.Entries)[1]
            $new.scope | Should -Be 'key'; $new.reason | Should -Be 'I still use it'
            $new.pattern | Should -Be ([string](Get-IgwtGuiRegCleanExclusionSpec -Finding $row.Finding).Pattern)
            & $s.OnComplete @() @() $s.Context
            @($script:Gui.RegClean.Scan.Findings | Where-Object { $_.Id -eq $row.Id }).Count | Should -Be 0
            # The task row cannot be excluded on its own; the action says why.
            $task = @($script:Gui.Grids.RegList.Index.Rows | Where-Object { $_.CategoryId -eq 'task' })[0]
            Get-IgwtGridActionBlock -Action $exclude -Rows @($task) | Should -Match 'no registry key'
        }
    }

    It 'sends report-only services and tasks to the Manage page and protected rows to the removal tool text' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF requires an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            Mock Select-IgwtGuiNavPage { }
            Mock Show-IgwtGuiMessage { 'OK' }
            Mock Open-IgwtGuiPath { }
            Set-IgwtGuiRegCleanScan -Scan (& $script:IgwtTestRegScanBlock)
            $g = $script:Gui.Grids.RegList
            $manage = @($g.Actions | Where-Object { $_.Id -eq 'manage' })[0]
            $task = @($g.Index.Rows | Where-Object { $_.CategoryId -eq 'task' })[0]
            Get-IgwtGridActionBlock -Action $manage -Rows @($task) | Should -Be ''
            & $manage.Run @($task)
            Should -Invoke Select-IgwtGuiNavPage -Times 1 -Exactly -ParameterFilter { $Tag -eq 'Manage' }
            $script:Gui.C.ManageTabs.SelectedIndex | Should -Be 1
            $safe = @($g.Index.Rows | Where-Object { $_.ConfidenceKey -eq 'Safe' })[0]
            Get-IgwtGridActionBlock -Action $manage -Rows @($safe) | Should -Not -Be ''
            $tool = @($g.Actions | Where-Object { $_.Id -eq 'tool' })[0]
            $prot = @($g.Index.Rows | Where-Object { $_.ConfidenceKey -eq 'Protected' })[0]
            & $tool.Run @($prot)
            Should -Invoke Open-IgwtGuiPath -Times 0 -Exactly
            Should -Invoke Show-IgwtGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'publishes no removal tool' }
        }
    }
}
