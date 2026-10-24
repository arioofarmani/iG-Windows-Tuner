BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

# The GUI's background worker, tested without a window (these bugs were only seen by the UI
# Automation suite before: jobs that never finished, and a crash with one running job).
Describe 'GUI background worker (headless)' {
    It 'runs pooled jobs to completion in parallel and delivers log entries to the UI queue' {
        InModuleScope iGWindowsTuner {
            $script:Gui = @{ Queue = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]') }
            try {
                Initialize-IgwtGuiWorker
                $jobs = foreach ($i in 1..3) {
                    $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:Gui.Runspace
                    $null = $ps.AddCommand('Get-IgwtPersona')
                    , @($ps, $ps.BeginInvoke())
                }
                foreach ($j in $jobs) {
                    $j[1].AsyncWaitHandle.WaitOne(60000) | Should -BeTrue -Because 'a pooled job must not hang'
                    @($j[0].EndInvoke($j[1])).Count | Should -Be 1
                    $j[0].Dispose()
                }
                # A command that logs: its entry reaches the queue through the runspace variable.
                $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:Gui.Runspace
                $null = $ps.AddScript("Get-Variable -Name IgwtGuiLogQueue -Scope Global -ValueOnly | ForEach-Object { `$_.GetType().Name }")
                $h = $ps.BeginInvoke()
                $h.AsyncWaitHandle.WaitOne(60000) | Should -BeTrue
                [string](@($ps.EndInvoke($h))[0]) | Should -Match 'ConcurrentQueue'
                $ps.Dispose()
            } finally { if ($script:Gui.Runspace) { $script:Gui.Runspace.Close(); $script:Gui.Runspace.Dispose() }; $script:Gui = $null }
        }
    }

    It 'never hands the queue to a job as a parameter (that blocked the job)' {
        $gui = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\Gui.ps1') -Raw
        $gui | Should -Not -Match "AddCommand\('Set-IgwtLogSink'\)"
        $gui | Should -Match "SessionStateVariableEntry\('IgwtGuiLogQueue'"
        $gui | Should -Not -Match 'CreateRunspacePool\([^)]*\$Host'
    }

    It 'shows the busy bar and Cancel with one, several or no running jobs (no @() on the job list)' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WPF controls need an STA thread.'; return }
        InModuleScope iGWindowsTuner {
            $c = @{ BusyBar = (New-Object System.Windows.Controls.ProgressBar); BusyCancelButton = (New-Object System.Windows.Controls.Button) }
            $jobs = New-Object System.Collections.Generic.List[object]
            $script:Gui = @{ C = $c; Jobs = $jobs }
            try {
                Update-IgwtGuiBusy
                $c.BusyBar.Visibility | Should -Be 'Hidden'
                $jobs.Add(@{ Channel = 'manage'; Cancelled = $false; BusyText = 'Reading' })
                { Update-IgwtGuiBusy } | Should -Not -Throw
                $c.BusyBar.Visibility | Should -Be 'Visible'
                $c.BusyCancelButton.Visibility | Should -Be 'Visible'
                $jobs.Add(@{ Channel = ''; Cancelled = $false; BusyText = 'Applying' })
                { Update-IgwtGuiBusy } | Should -Not -Throw
                $jobs.Clear(); $jobs.Add(@{ Channel = ''; Cancelled = $false; BusyText = 'Applying' })
                Update-IgwtGuiBusy
                $c.BusyCancelButton.Visibility | Should -Be 'Collapsed'
            } finally { $script:Gui = $null }
        }
    }

    It 'keeps slow engine queries off the UI thread (they run as background jobs)' {
        # Plans and checks that call powercfg, CIM, package or management queries (audit E2, X5).
        $found = New-Object System.Collections.Generic.List[string]
        $slow = @('Get-IgwtPowerSettingChangePlan', 'Get-IgwtManagedChangePlan', 'Test-IgwtSystemProtectionEnabled', 'Get-IgwtManagementState', 'Get-IgwtFirewallInventory', 'Get-IgwtPolicyBrowserData', 'Get-IgwtAsrAudit', 'Get-IgwtExploitProtectionInventory')
        foreach ($f in Get-ChildItem (Join-Path $script:IgwtProjectRoot 'src\Gui') -Filter *.ps1) {
            $tk = $null; $er = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tk, [ref]$er)
            foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $slow -contains $n.GetCommandName() }, $true)) {
                # The offscreen renderer loads its (mocked) data synchronously on purpose.
                $fn = $cmd.Parent; while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                if ($fn -and $fn.Name -eq 'Save-IgwtGuiScreenshots') { continue }
                $found.Add("$($f.Name):$($cmd.Extent.StartLineNumber) $($cmd.GetCommandName())")
            }
        }
        $found | Should -BeNullOrEmpty -Because 'these queries must run through Start-IgwtGuiJob -Command'
    }
}
