# Updates.ps1
# Windows Update: read-only status (services, pending restart, Windows Update for Business policies)
# and update history from the Windows Update Agent (COM, query only). Policies are changed only
# through catalog items (wufbPolicy action type), never directly.

$script:IgwtWuResultNames = @{ 0 = 'Not started'; 1 = 'In progress'; 2 = 'Succeeded'; 3 = 'Succeeded with errors'; 4 = 'Failed'; 5 = 'Aborted' }

function Get-IgwtUpdateHistoryRaw {
    <# .SYNOPSIS Raw update history from the Windows Update Agent (IUpdateSearcher.QueryHistory, read-only). Mock this in tests. #>
    [CmdletBinding()]
    param([ValidateRange(1, 500)][int]$Count = 40)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: the Windows Update Agent must be mocked in tests.' }
    $session = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $total = $searcher.GetTotalHistoryCount()
    if ($total -le 0) { return @() }
    $items = $searcher.QueryHistory(0, [Math]::Min($Count, $total))
    foreach ($h in $items) { [pscustomobject]@{ Date = $h.Date; Title = [string]$h.Title; ResultCode = [int]$h.ResultCode; HResult = [int]$h.HResult; Operation = [int]$h.Operation } }
}

function Get-IgwtUpdateStatus {
    <#
    .SYNOPSIS
        Read-only Windows Update status: update services, pending restart, Windows Update for
        Business policy values, the last successful update and recent history with failures.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 500)][int]$Count = 100)
    $services = foreach ($n in 'wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'BITS') {
        try { $s = Get-Service -Name $n -ErrorAction Stop; [pscustomobject]@{ Name = $n; Status = [string]$s.Status; StartType = [string]$s.StartType } }
        catch { [pscustomobject]@{ Name = $n; Status = 'Missing'; StartType = '' } }
    }
    $pending = New-Object System.Collections.Generic.List[string]
    foreach ($k in @(@{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; T = 'Windows Update' }, @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; T = 'Component servicing' })) {
        try { if (Test-IgwtRegistryKey -Path $k.P) { $pending.Add($k.T) } } catch { Write-Verbose "Not readable: $($k.P)" }
    }
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $policies = foreach ($n in 'DeferFeatureUpdates', 'DeferFeatureUpdatesPeriodInDays', 'DeferQualityUpdates', 'DeferQualityUpdatesPeriodInDays', 'TargetReleaseVersion', 'ProductVersion', 'TargetReleaseVersionInfo') {
        try { $v = Get-IgwtRegistryValue -Path $pol -Name $n; if ($v.Exists) { [pscustomobject]@{ Name = $n; Value = [string]$v.Value } } } catch { Write-Verbose "Policy not readable: $n" }
    }
    $history = @(); $err = ''
    try {
        $history = @(Get-IgwtUpdateHistoryRaw -Count $Count | ForEach-Object {
                [pscustomobject]@{ Date = $_.Date; Title = $_.Title; Result = $(if ($script:IgwtWuResultNames.ContainsKey([int]$_.ResultCode)) { $script:IgwtWuResultNames[[int]$_.ResultCode] } else { "Code $($_.ResultCode)" })
                    HResult = $(if ([int]$_.HResult) { '0x{0:X8}' -f [int]$_.HResult } else { '' }) }
            })
    } catch { $err = "Update history unavailable: $($_.Exception.Message)" }
    # Defender definition updates arrive several times a day; they do not show that Windows itself is updated.
    $ok = @($history | Where-Object { $_.Result -like 'Succeeded*' -and $_.Title -notmatch 'Security Intelligence Update' } | Sort-Object Date -Descending)
    $failed = @($history | Where-Object { $_.Result -in 'Failed', 'Aborted' })
    $advice = New-Object System.Collections.Generic.List[string]
    if (@($services | Where-Object { $_.Name -eq 'wuauserv' -and $_.StartType -eq 'Disabled' }).Count) { $advice.Add('The Windows Update service is disabled; security updates are not installed. Set it back to Manual (iG Windows Tuner never disables it).') }
    if ($pending.Count) { $advice.Add("A restart is pending ($($pending -join ', ')). Restart to finish installing updates.") }
    if ($ok.Count -and ((Get-Date) - [datetime]$ok[0].Date).TotalDays -gt 45) { $advice.Add('No update was installed successfully in the last 45 days. Open Settings > Windows Update and check for updates.') }
    if ($failed.Count) { $advice.Add("$($failed.Count) update(s) failed recently; the error code (HResult) identifies the cause in Microsoft's documentation.") }
    [pscustomobject]@{
        Services        = @($services)
        PendingRestart  = $pending.ToArray()
        Policies        = @($policies)
        LastSuccess     = $(if ($ok.Count) { $ok[0].Date } else { $null })
        History         = $history
        Failed          = $failed.Count
        Error           = $err
        Advice          = $advice.ToArray()
        Note            = 'Read-only. Windows Update for Business policies are changed only through catalog items (for example update.defer-feature-90).'
    }
}
