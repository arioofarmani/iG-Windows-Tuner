BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

# Stability work for the 3.3 budgets (no UI-thread block over 200 ms): big lists are built in slices
# between UI frames, the worker pools open in the background, and startup reads wait for a pool.
Describe 'Window stability helpers (headless)' {
    It 'builds all rows in order without a window, in one call' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $script:Gui = @{ Runspace = $null; Window = $null }
                $got = $null
                Invoke-IgwtGuiChunked -Key 'k' -Items @(1..10) -Build { param($i) $i * 2 } -Done { param($rows) $script:Got = $rows }
                @($script:Got) | Should -Be @(2, 4, 6, 8, 10, 12, 14, 16, 18, 20)
            } finally { $script:Gui = $saved; Remove-Variable -Name Got -Scope Script -ErrorAction SilentlyContinue }
        }
    }

    It 'builds in slices between UI frames, keeps the order and lets a newer call replace an unfinished one' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $dispatcher = [System.Windows.Threading.Dispatcher]::CurrentDispatcher
                $script:Gui = @{ Runspace = [pscustomobject]@{}; Window = [pscustomobject]@{ Dispatcher = $dispatcher } }
                $script:Slices = 0; $script:First = $null; $script:Second = $null
                Invoke-IgwtGuiChunked -Key 'list' -Items @(1..250) -Size 50 -Build { param($i) $script:Slices++; $i } -Done { param($rows) $script:First = $rows }
                $script:Gui.Chunks['list'].Items.Count | Should -Be 250
                # A newer call with the same key replaces the unfinished one: its Done never runs.
                Invoke-IgwtGuiChunked -Key 'list' -Items @(1..120) -Size 50 -Build { param($i) $i + 1000 } -Done { param($rows) $script:Second = $rows }
                for ($n = 0; $n -lt 20 -and $null -eq $script:Second; $n++) { $null = $dispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::SystemIdle) }
                $script:First | Should -BeNullOrEmpty -Because 'the replaced build never delivers'
                @($script:Second).Count | Should -Be 120
                $script:Second[0] | Should -Be 1001
                $script:Second[119] | Should -Be 1120
                # A single list builds in more than one slice, so the window can paint in between.
                $script:Slices = 0; $script:Third = $null
                Invoke-IgwtGuiChunked -Key 'big' -Items @(1..250) -Size 50 -Build { param($i) $script:Slices++; $i } -Done { param($rows) $script:Third = $rows }
                $dispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::Background)
                $script:Slices | Should -BeLessThan 250 -Because 'only the first slice ran before the next frame'
                for ($n = 0; $n -lt 20 -and $null -eq $script:Third; $n++) { $null = $dispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::SystemIdle) }
                @($script:Third).Count | Should -Be 250
                $script:Third[249] | Should -Be 250
            } finally { $script:Gui = $saved; foreach ($v in 'Slices', 'First', 'Second', 'Third') { Remove-Variable -Name $v -Scope Script -ErrorAction SilentlyContinue } }
        }
    }

    It 'only counts pools that finished opening, and defers startup reads until one is open' {
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $mk = { param($state) [pscustomobject]@{ RunspacePoolStateInfo = [pscustomobject]@{ State = $state } } }
                $a = & $mk 'Opening'; $b = & $mk 'Opening'
                $script:Gui = @{ Pools = @($a, $b); Runspace = $a; WhenReady = (New-Object System.Collections.Generic.List[scriptblock]) }
                Test-IgwtGuiWorkerReady | Should -BeFalse
                @(Get-IgwtGuiOpenPools).Count | Should -Be 0
                $script:Ran = 0
                Invoke-IgwtGuiWhenWorkerReady -Action { $script:Ran++ }
                $script:Ran | Should -Be 0 -Because 'no pool is open yet'
                $script:Gui.WhenReady.Count | Should -Be 1
                $b.RunspacePoolStateInfo.State = 'Opened'
                Test-IgwtGuiWorkerReady | Should -BeTrue
                @(Get-IgwtGuiOpenPools).Count | Should -Be 1
                Invoke-IgwtGuiWhenWorkerReady -Action { $script:Ran++ }
                $script:Ran | Should -Be 1 -Because 'a ready pool runs the action at once'
            } finally { $script:Gui = $saved; Remove-Variable -Name Ran -Scope Script -ErrorAction SilentlyContinue }
        }
    }

    It 'opens the worker as three single-runspace pools in the window and as one pool for plain callers' {
        $src = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\Gui.ps1') -Raw
        $src | Should -Match 'Initialize-IgwtGuiWorker -Async' -Because 'the window opens the pools in the background'
        $src | Should -Match '\$count = \$\(if \(\$Async\) \{ 3 \} else \{ 1 \}\)'
        $src | Should -Match 'SetMaxRunspaces\(\$\(if \(\$Async\) \{ 1 \} else \{ 3 \}\)\)' -Because 'a pool that has to grow blocks its caller for about a second'
    }

    It 'applies at most one finished job per tick' {
        $src = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\Gui.ps1') -Raw
        $src | Should -Match 'Select-Object -First 1\)\s*\r?\n\s*foreach \(\$job in \$done\)'
    }

    It 'creates each navigation group label once and reuses it, and rebuilds the list only when the order changed' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF needs an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $saved = $script:Gui
            try {
                $window = New-IgwtMainWindow
                $script:Gui = @{ Window = $window; C = @{ NavList = $window.FindName('NavList') }; NavHeaders = $null }
                $a = Get-IgwtGuiNavHeader -Text 'Start'
                [object]::ReferenceEquals((Get-IgwtGuiNavHeader -Text 'Start'), $a) | Should -BeTrue -Because 'a second call returns the same item'
                [object]::ReferenceEquals((Get-IgwtGuiNavHeader -Text 'Secure'), $a) | Should -BeFalse
                Test-IgwtGuiNavHeader -Item $a | Should -BeTrue
                # The persona code plans the order first and skips the rebuild when it is unchanged (the nav items are not detached).
                $src = (Get-Command Set-IgwtGuiPersona).ScriptBlock.ToString()
                $src | Should -Match '\$same = \(\$plan\.Count -eq \$nav\.Items\.Count\)'
                $src | Should -Match 'if \(-not \$same\) \{\s+\$nav\.Items\.Clear\(\)'
            } finally { $script:Gui = $saved }
        }
    }
}
