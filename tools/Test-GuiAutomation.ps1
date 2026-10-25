<#
.SYNOPSIS
    UI Automation smoke suite: drives the real GUI in read-only mode with System.Windows.Automation.
.DESCRIPTION
    Launches iG Windows Tuner itself with -ReadOnly and -DiagnosticsPath, refuses to continue unless
    the window shows the "Read-only mode" banner, then opens every page and tab, selects the first
    row of every list (details panes), types into every search box, toggles the view filters,
    invokes every sortable column header, resizes the window to the minimum size and back, switches
    themes when a theme selector exists, and navigates all pages 20 times to measure memory growth.
    It never presses an action button. Results: exceptions, WPF binding errors, UI-thread stalls
    over 200 ms, page switch times and memory, in <OutDir>\automation-report.json.
.PARAMETER OutDir
    Output folder (default artifacts\gui-automation).
.PARAMETER Cycles
    Navigation cycles for the memory check (default 20).
.PARAMETER StartTimeoutSec
    Seconds to wait for the window (default 90).
.PARAMETER Attempts
    Runs again (up to this many runs in all) when someone using the PC closes the test window.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\gui-automation'),
    [int]$Cycles = 20,
    [int]$StartTimeoutSec = 90,
    [int]$Attempts = 3
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, WindowsBase
$root = Split-Path -Parent $PSScriptRoot
$diag = Join-Path $OutDir 'diagnostics'
if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $diag -Force
$A = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$CT = [System.Windows.Automation.ControlType]
function Get-Cond([System.Windows.Automation.AutomationProperty]$Prop, $Value) { New-Object System.Windows.Automation.PropertyCondition($Prop, $Value) }
function Find-ById($Parent, [string]$Id) { $Parent.FindFirst($TS::Descendants, (Get-Cond $A::AutomationIdProperty $Id)) }
function Find-AllType($Parent, $Type) { @($Parent.FindAll($TS::Descendants, (Get-Cond $A::ControlTypeProperty $Type))) }
function Test-OnScreen($El) { try { -not $El.Current.IsOffscreen -and $El.Current.BoundingRectangle.Width -gt 0 } catch { $false } }
function Wait-Idle([int]$Ms = 250) { Start-Sleep -Milliseconds $Ms }
function Wait-AppIdle($Window, [int]$TimeoutSec = 90) {
    # The busy bar is visible while the worker loads data; wait until it is hidden.
    $t0 = Get-Date
    do {
        Start-Sleep -Milliseconds 300
        $bar = Find-ById $Window 'BusyBar'
        $busy = $bar -and (Test-OnScreen $bar)
    } while ($busy -and ((Get-Date) - $t0).TotalSeconds -lt $TimeoutSec)
    return (-not $busy)
}
$log = New-Object System.Collections.Generic.List[string]
function Note([string]$Text) { $log.Add(("{0:HH:mm:ss.fff} {1}" -f (Get-Date), $Text)); Write-Verbose $Text }

# 1. Launch the GUI read-only (the harness never targets an instance it did not start read-only).
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$stateDir = Join-Path $OutDir 'state'
$null = New-Item -ItemType Directory -Path $stateDir -Force
# IGWT_GUI_NOACTIVATE: the test window opens without taking the keyboard focus from whoever uses the PC.
$cmd = "`$env:IGWT_GUI_NOACTIVATE = '1'; `$env:IGWT_GUI_STATE_DIR = '$stateDir'; Import-Module '$root\src\iGWindowsTuner.psd1' -Force; Show-IgwtGui -ReadOnly -DiagnosticsPath '$diag' -ScriptPath '$root\iGWindowsTuner.ps1'"
$proc = Start-Process -FilePath $psExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-Command', $cmd) -PassThru
$report = [ordered]@{ Started = (Get-Date).ToString('o'); Pid = $proc.Id; ReadOnlyVerified = $false; Pages = @(); Tabs = 0; HeadersInvoked = 0; SearchBoxes = 0; Filters = 0; RowsSelected = 0; Resized = $false; Themes = @(); Errors = @() }
$win = $null
try {
    $deadline = (Get-Date).AddSeconds($StartTimeoutSec)
    while (-not $win -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if ($proc.HasExited) { throw "The GUI process exited early (code $($proc.ExitCode))." }
        $win = $A::RootElement.FindFirst($TS::Children, (New-Object System.Windows.Automation.AndCondition((Get-Cond $A::ProcessIdProperty $proc.Id), (Get-Cond $A::ControlTypeProperty $CT::Window))))
    }
    if (-not $win) { throw 'The GUI window did not appear.' }
    while (-not (Test-Path -LiteralPath (Join-Path $diag 'ready.log')) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    try { ([System.Windows.Automation.WindowPattern]$win.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)).SetWindowVisualState('Normal') } catch { Note 'window state not set' }
    Wait-Idle 800
    # A Border has no automation peer; the banner's text element carries the state.
    $banner = Find-ById $win 'ReadOnlyBannerText'
    if (-not $banner -or -not (Test-OnScreen $banner) -or -not ([string]$banner.Current.Name).StartsWith('Read-only mode:')) { throw 'Refusing to continue: the window does not show the Read-only mode banner.' }
    $report.ReadOnlyVerified = $true
    Note 'read-only banner verified'

    $nav = Find-ById $win 'NavList'
    $items = @($nav.FindAll($TS::Children, (Get-Cond $A::ControlTypeProperty $CT::ListItem)))
    # Navigation group labels (3.3 grouped navigation) are not pages.
    $items = @($items | Where-Object { -not ([string]$_.Current.Name).EndsWith(' group') })
    if (-not (Wait-AppIdle $win 120)) { Note 'start-up data still loading after 120 s' }
    Note "$($items.Count) navigation items"
    $sel = [System.Windows.Automation.SelectionItemPattern]::Pattern
    $memory = New-Object System.Collections.Generic.List[object]
    $safeChecks = '^(Filter[A-Za-z]+|InspectPowerAllBox|InspectKernelChangedBox|Chip_.+|Focus.+)$'

    # 2. Every page: tabs, rows, search, filters, headers.
    foreach ($it in $items) {
        $name = $it.Current.Name
        try { ($it.GetCurrentPattern($sel)).Select() } catch { $report.Errors += "select $name"; continue }
        Wait-Idle 500
        if (-not (Wait-AppIdle $win 90)) { Note "page $name still loading after 90 s" }
        $page = [ordered]@{ Name = $name; Tabs = 0; Rows = 0; Headers = 0 }
        $tabs = @(Find-AllType $win $CT::TabItem | Where-Object { Test-OnScreen $_ })
        $tabsToVisit = New-Object System.Collections.Generic.List[object]
        if ($tabs.Count) { foreach ($tb in $tabs) { $tabsToVisit.Add($tb) } } else { $tabsToVisit.Add('page') }
        foreach ($tab in $tabsToVisit) {
            if ($tab -isnot [string]) { try { ($tab.GetCurrentPattern($sel)).Select(); $page.Tabs++; $report.Tabs++; Wait-Idle 400 } catch { Note "tab select failed on $name" } }
            $lists = @(@(Find-AllType $win $CT::List) + @(Find-AllType $win $CT::DataGrid) | Where-Object { (Test-OnScreen $_) -and $_.Current.AutomationId -ne 'NavList' })
            Note ("{0}: lists {1}" -f $name, (@($lists | ForEach-Object { "$($_.Current.AutomationId)[$($_.Current.ControlType.ProgrammaticName)]" }) -join ', '))
            foreach ($list in $lists) {
                $first = $list.FindFirst($TS::Children, (New-Object System.Windows.Automation.OrCondition((Get-Cond $A::ControlTypeProperty $CT::ListItem), (Get-Cond $A::ControlTypeProperty $CT::DataItem))))
                if ($first) { try { ($first.GetCurrentPattern($sel)).Select(); $page.Rows++; $report.RowsSelected++; Wait-Idle 200 } catch { Note "row select failed on $name" } }
            }
            foreach ($h in @(Find-AllType $win $CT::HeaderItem | Where-Object { Test-OnScreen $_ })) {
                try { $ip = $h.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern); $ip.Invoke(); Wait-Idle 150; $ip.Invoke(); Wait-Idle 150; $page.Headers++; $report.HeadersInvoked++ } catch { Note "header not invokable on $name" }
            }
            foreach ($b in @(Find-AllType $win $CT::Button | Where-Object { (Test-OnScreen $_) -and $_.Current.AutomationId -like 'Sort*' })) {
                try { ($b.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke(); Wait-Idle 150; $page.Headers++; $report.HeadersInvoked++ } catch { Note "sort button failed on $name" }
            }
            foreach ($box in @(Find-AllType $win $CT::Edit | Where-Object { (Test-OnScreen $_) -and $_.Current.AutomationId -like '*SearchBox' })) {
                try { $vp = $box.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern); $vp.SetValue('a'); Wait-Idle 300; $vp.SetValue(''); Wait-Idle 200; $report.SearchBoxes++ } catch { Note "search failed on $name" }
            }
            foreach ($cb in @(@(Find-AllType $win $CT::CheckBox) + @(Find-AllType $win $CT::Button) | Where-Object { (Test-OnScreen $_) -and $_.Current.AutomationId -match $safeChecks })) {
                try { $tp = $cb.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern); $tp.Toggle(); Wait-Idle 200; $tp.Toggle(); Wait-Idle 150; $report.Filters++ } catch { Note "filter toggle failed on $name" }
            }
        }
        $report.Pages += [pscustomobject]$page
    }

    # 3. Resize to the minimum size and back.
    try {
        try { ($win.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)).SetWindowVisualState('Normal'); Wait-Idle 400 } catch { Note "window state: $($_.Exception.Message)" }
        $tp = $win.GetCurrentPattern([System.Windows.Automation.TransformPattern]::Pattern)
        if (-not $tp.Current.CanResize) { Note 'window reports CanResize = false' }
        $tp.Resize(1100, 720); Wait-Idle 800; $tp.Resize(1280, 820); Wait-Idle 600; $tp.Resize(1600, 960); Wait-Idle 600
        $report.Resized = $true
    } catch { $report.Errors += "resize: $($_.Exception.Message)" }

    # 4. Themes (when the selector exists).
    $themeBox = Find-ById $win 'ThemeBox'
    if ($themeBox) {
        try {
            $ec = $themeBox.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern); $ec.Expand(); Wait-Idle 300
            foreach ($opt in @($themeBox.FindAll($TS::Descendants, (Get-Cond $A::ControlTypeProperty $CT::ListItem)))) { ($opt.GetCurrentPattern($sel)).Select(); Wait-Idle 700; $report.Themes += $opt.Current.Name }
            try { $ec.Collapse() } catch { Note 'collapse' }
        } catch { $report.Errors += "theme: $($_.Exception.Message)" }
    }

    # 5. Navigation cycles and memory.
    $p0 = Get-Process -Id $proc.Id
    $memory.Add([pscustomobject]@{ Cycle = 0; PrivateMB = [math]::Round($p0.PrivateMemorySize64 / 1MB, 1); WorkingSetMB = [math]::Round($p0.WorkingSet64 / 1MB, 1) })
    for ($c = 1; $c -le $Cycles; $c++) {
        foreach ($it in $items) { try { ($it.GetCurrentPattern($sel)).Select(); Start-Sleep -Milliseconds 120 } catch { Note "cycle select failed $c" } }
        if ($c -eq 1 -or $c -eq $Cycles -or $c % 5 -eq 0) {
            Start-Sleep -Milliseconds 800
            $p = Get-Process -Id $proc.Id
            $memory.Add([pscustomobject]@{ Cycle = $c; PrivateMB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1); WorkingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1) })
        }
    }
    $report.Memory = $memory.ToArray()
    $arr = $memory.ToArray(); $base = @($arr | Where-Object Cycle -EQ 1)[0]; $last = $arr[$arr.Length - 1]
    $report.MemoryGrowthMB = [math]::Round($last.PrivateMB - $base.PrivateMB, 1)
    $report.StillRunning = -not $proc.HasExited
} catch {
    $report.Errors += "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
} finally {
    if ($win) { try { ($win.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)).Close() } catch { Note 'close failed' } }
    $t0 = Get-Date
    while (-not $proc.HasExited -and ((Get-Date) - $t0).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 300 }
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue; Note 'GUI killed after close timeout' }
}

# 6. Collect the app-side diagnostics.
$read = { param($n) $p = Join-Path $diag "$n.log"; if (Test-Path -LiteralPath $p) { @(Get-Content -LiteralPath $p | Where-Object { $_ }) } else { @() } }
$binding = @(& $read 'binding' | Where-Object { $_ -match 'System.Windows.Data (Error|Warning)' })
$exceptions = @(& $read 'exception')
$stalls = @(& $read 'stall' | ForEach-Object { $parts = $_ -split "`t", 2; [pscustomobject]@{ Time = $parts[0]; Text = $parts[1]; Ms = [double](($parts[1] -replace '[^0-9.,].*$', '') -replace ',', '') } })
$switches = @(& $read 'pageswitch' | ForEach-Object { $f = $_ -split "`t"; [pscustomobject]@{ Page = $f[1]; Ms = [double]($f[2] -replace ',', '') } })
$report.BindingErrors = $binding.Count
$report.BindingSamples = @($binding | Select-Object -Unique -First 15)
$report.Exceptions = $exceptions
$report.Stalls = @($stalls | Sort-Object Ms -Descending | Select-Object -First 25)
$report.StallsOver200 = @($stalls | Where-Object { $_.Ms -gt 200 }).Count
$report.PageSwitch = @($switches | Group-Object Page | ForEach-Object { [pscustomobject]@{ Page = $_.Name; Count = $_.Count; MaxMs = ($_.Group | Measure-Object Ms -Maximum).Maximum; MedianMs = @($_.Group | Sort-Object Ms)[[int][math]::Floor($_.Count / 2)].Ms } })
$report.Log = $log.ToArray()
$report.Finished = (Get-Date).ToString('o')
# Someone using the PC closed the test window (a real mouse click on a button, logged by the
# app in close.log): that is not an app failure, so run again.
$closeLog = Join-Path $diag 'close.log'
$report.ClosedByUser = (-not $report.StillRunning) -and (Test-Path -LiteralPath $closeLog) -and ((Get-Content -LiteralPath $closeLog -Raw) -match 'OnMouseLeftButtonUp')
if ($report.ClosedByUser -and $Attempts -gt 1) {
    Write-Output 'The test window was closed by a mouse click (someone is using this PC); running the suite again.'
    & $PSCommandPath -OutDir $OutDir -Cycles $Cycles -StartTimeoutSec $StartTimeoutSec -Attempts ($Attempts - 1)
    exit $LASTEXITCODE
}
$out = Join-Path $OutDir 'automation-report.json'
[pscustomobject]$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $out -Encoding UTF8
Write-Output ("Read-only verified: {0}; pages {1}; tabs {2}; headers {3}; rows {4}; search {5}; filters {6}; resized {7}; themes {8}" -f $report.ReadOnlyVerified, @($report.Pages).Count, $report.Tabs, $report.HeadersInvoked, $report.RowsSelected, $report.SearchBoxes, $report.Filters, $report.Resized, (@($report.Themes) -join ','))
Write-Output ("Exceptions {0}; binding errors {1}; stalls over 200 ms {2}; memory growth {3} MB after {4} cycles; errors {5}" -f @($exceptions).Count, $binding.Count, $report.StallsOver200, $report.MemoryGrowthMB, $Cycles, @($report.Errors).Count)
Write-Output "Report: $out"
if (-not $report.ReadOnlyVerified -or @($report.Errors).Count) { exit 1 }
exit 0
