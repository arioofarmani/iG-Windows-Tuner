<#
.SYNOPSIS
    Real round trips on this PC through iG's own engine (development tool; CHANGES THIS PC).
.DESCRIPTION
    4.0 section V. Each check changes one harmless setting through the engine (journal, snapshot or
    backup first), reads the value back, undoes it, and reads again. Every check restores its start
    state in a finally block. Needs an elevated session and -IUnderstandThisChangesThisPC; make a
    System Restore point first. Results go to the console and to -ReportPath (JSON).
.PARAMETER Only
    Run only these checks (names: Tweak, History, Policy, Firewall, Asr, Defender, SecSettings,
    Session, Startup, RegClean).
.PARAMETER IUnderstandThisChangesThisPC
    Required: these are real changes on this PC (each undone right after).
.PARAMETER ReportPath
    JSON report of the results.
#>
[CmdletBinding()]
param([string[]]$Only = @(), [switch]$IUnderstandThisChangesThisPC, [string]$ReportPath = (Join-Path $env:TEMP 'igwt-roundtrips.json'))
if (-not $IUnderstandThisChangesThisPC) { throw 'These checks change this PC (each change is undone right after). Run again with -IUnderstandThisChangesThisPC.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated session.' }
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\iGWindowsTuner.psd1') -Force
$results = New-Object System.Collections.Generic.List[object]
$want = { param($n) -not $Only.Count -or $Only -contains $n }
function Add-Result([string]$Check, [string]$Result, [string]$Detail) { $results.Add([pscustomobject]@{ Check = $Check; Result = $Result; Detail = $Detail }); Write-Information -MessageData ('{0,-12} {1,-5} {2}' -f $Check, $Result, $Detail) -InformationAction Continue }
$inv = { param($block) try { & $block } catch { "ERROR: $($_.Exception.Message)" } }
$pstate = { param($polId) $po = @((Get-IgwtAdmxCatalog).Policies | Where-Object { $_.Id -eq $polId })[0]; $cls = $(if ([string]$po.Class -eq 'User') { 'User' } else { 'Machine' }); $e = @((Read-IgwtRegistryPol -Path (Join-Path $env:SystemRoot "System32\GroupPolicy\$cls\Registry.pol")).Entries | Where-Object { [string]$_.Key -eq [string]$po.Key -and [string]$_.ValueName -eq [string]$po.ValueName }); $(if ($e.Count) { 'Set' } else { 'NotSet' }) }
$tstate = { param($tw) [string](Get-IgwtTweakState -Tweak $tw -Context (New-IgwtContext)).State }
function Get-IgwtRoundTripSecRows { $x = Get-IgwtSecSettings -SourceKind audit -NoCache; if ($x.PSObject.Properties['Rows']) { @($x.Rows) } else { @($x) } }

# 1. Tweak: undo and apply again through the engine.
if (& $want 'Tweak') {
    $id = 'system.end-task-taskbar'; $t = Get-IgwtTweak -Id $id
    $s0 = (& $tstate $t)
    try {
        if ($s0 -eq 'On') { $null = Invoke-IgwtRevert -Id $id; $s1 = (& $tstate $t); $null = Invoke-IgwtApply -Id $id -SkipRestorePoint; $s2 = (& $tstate $t); $ok = ($s1 -eq 'Off' -and $s2 -eq 'On') }
        else { $null = Invoke-IgwtApply -Id $id -SkipRestorePoint; $s1 = (& $tstate $t); $null = Invoke-IgwtRevert -Id $id; $s2 = (& $tstate $t); $ok = ($s1 -eq 'On' -and $s2 -eq $s0) }
        Add-Result -Check 'Tweak' -Result $(if ($ok) { 'Pass' } else { 'Fail' }) -Detail "$id $s0 -> $s1 -> $s2"
    } catch { Add-Result -Check 'Tweak' -Result 'Fail' -Detail $_.Exception.Message }
}

# 2. History: a value changed after iG set it is a Conflict; Keep leaves it; apply puts iG's value back.
if (& $want 'History') {
    $id = 'system.end-task-taskbar'; $t = Get-IgwtTweak -Id $id; $a = @($t.actions)[0]
    $path = [string]$a.path; $name = [string]$a.name
    $orig = (& $tstate $t)
    if (-not $orig) { Add-Result -Check 'History' -Result 'Fail' -Detail 'start state not readable'; $orig = 'On' }
    try {
        # A fresh, committed change by iG first (revert, then apply), so the journal's last entry is this change.
        $null = Invoke-IgwtRevert -Id $id
        $null = Invoke-IgwtApply -Id $id -SkipRestorePoint
        $set = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
        Set-ItemProperty -LiteralPath $path -Name $name -Value 2 -Type DWord   # "something else" sets a third value
        $j = Read-IgwtJournal
        $last = $j.Last.Keys | Where-Object { $j.Last[$_]['item'] -eq $id -and $j.Last[$_]['kind'] -eq 'committed' } | Select-Object -First 1
        $plan = @(Get-IgwtRevertPlan -EntryId ([string]$j.Last[$last]['id']))
        $st = @($plan | ForEach-Object { $_.Status }) -join ','
        $r = Invoke-IgwtJournalRevert -Plan $plan -Decisions @{ ([string]$plan[0].Key) = 'Keep' } -Title 'Round trip: keep' -Confirm:$false
        $after = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
        $ok = ($st -eq 'Conflict' -and [string]@($r.Results)[0].Result -eq 'Kept' -and [int]$after -eq 2)
        Add-Result -Check 'History' -Result $(if ($ok) { 'Pass' } else { 'Fail' }) -Detail "iG set $set; changed to 2; plan $st; choice Keep -> $(@($r.Results)[0].Result); value $after"
    } catch { Add-Result -Check 'History' -Result 'Fail' -Detail $_.Exception.Message }
    # After Keep, the test value would become the item's "before": reset to the Windows default first (journaled), so
    # a later undo by the user never writes the test value.
    finally { $null = & $inv { Invoke-IgwtApply -Id $id -Mode default -SkipRestorePoint }; if ($orig -eq 'On') { $null = & $inv { Invoke-IgwtApply -Id $id -SkipRestorePoint } } }
}

# 3. Group Policy: two sets, the older undo is refused while the newer is in place, then newest first.
if (& $want 'Policy') {
    $A = 'FeedbackNotifications:DoNotShowFeedbackNotifications'; $B = 'HelpAndSupport:HPExplicitFeedback'
    $a0 = (& $pstate $A); $b0 = (& $pstate $B)
    $ra = $null; $rb = $null
    try {
        $ra = Set-IgwtLocalPolicy -Id $A -State Enabled -Confirm:$false
        $rb = Set-IgwtLocalPolicy -Id $B -State Enabled -Confirm:$false
        $mid = "$((& $pstate $A))/$((& $pstate $B))"
        $refused = & $inv { $null = Restore-IgwtLocalGpo -BackupPath ([string]$ra.Backup) -Confirm:$false; 'restored' }
        $null = Restore-IgwtLocalGpo -BackupPath ([string]$rb.Backup) -Confirm:$false
        $null = Restore-IgwtLocalGpo -BackupPath ([string]$ra.Backup) -Confirm:$false
        $end = "$((& $pstate $A))/$((& $pstate $B))"
        $ok = ($refused -like 'ERROR:*later*' -and $end -eq "$a0/$b0")
        Add-Result -Check 'Policy' -Result $(if ($ok) { 'Pass' } else { 'Fail' }) -Detail "start $a0/$b0; set $mid; older undo first: $refused; newest first, end $end"
    } catch { Add-Result -Check 'Policy' -Result 'Fail' -Detail $_.Exception.Message
        foreach ($r in @($rb, $ra)) { if ($r -and $r.Backup) { $null = & $inv { Restore-IgwtLocalGpo -BackupPath ([string]$r.Backup) -Confirm:$false } } } }
}

# 4. Firewall: an iG test rule, an edit to TCP 27015, the undo back to Any (FW F-07), then removed.
if (& $want 'Firewall') {
    $name = $null
    try {
        $new = Invoke-IgwtFirewallChange -Operation New -Settings @{ DisplayName = 'iG round-trip test rule'; Direction = 'Inbound'; Action = 'Block'; Profiles = @('Any'); Protocol = 'Any'; Program = 'C:\iG-roundtrip\none.exe' } -Confirm:$false
        $name = @(Get-NetFirewallRule -DisplayName 'iG round-trip test rule' -ErrorAction Stop)[0].Name
        $edit = Invoke-IgwtFirewallChange -Operation Edit -Name @($name) -Settings @{ Protocol = 'TCP'; LocalPort = '27015' } -Confirm:$false
        $pf = Get-NetFirewallRule -Name $name | Get-NetFirewallPortFilter; $mid = "$($pf.Protocol) $($pf.LocalPort)"
        $null = Invoke-IgwtRevert -SnapshotPath ([string]$edit.Snapshot)
        $pf = Get-NetFirewallRule -Name $name | Get-NetFirewallPortFilter; $back = "$($pf.Protocol) $($pf.LocalPort)"
        $null = Invoke-IgwtRevert -SnapshotPath ([string]$new.Snapshot)
        $gone = -not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
        $pr = Set-IgwtFirewallProfileSetting -Profile Public -Setting LogBlocked -Value ([string](Get-NetFirewallProfile -Name Public -PolicyStore PersistentStore).LogBlocked -eq 'True') -Confirm:$false
        $ok = ($mid -eq 'TCP 27015' -and $back -eq 'Any Any' -and $gone -and $pr.InEffect)
        Add-Result -Check 'Firewall' -Result $(if ($ok) { 'Pass' } else { 'Fail' }) -Detail "edit $mid; undo $back; rule removed $gone; profile read-back in effect $($pr.InEffect)"
    } catch { Add-Result -Check 'Firewall' -Result 'Fail' -Detail $_.Exception.Message }
    finally { if ($name) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } }
}

# 5. ASR: a rule that is off goes to Audit and back.
if (& $want 'Asr') {
    try {
        $cat = @{}; foreach ($d in @(Get-IgwtAsrCatalog)) { $cat[([string]$d.id).ToLowerInvariant()] = $d }
        $usable = @((Get-IgwtAsrStatus).Rules | Where-Object { -not $_.ManagedByPolicy -and -not $cat[([string]$_.Id).ToLowerInvariant()].serverOnly })
        $rule = @($usable | Where-Object { [string]$_.Mode -in 'Off', 'NotConfigured' }) | Select-Object -First 1
        $to = 'Audit'
        if (-not $rule) { $rule = @($usable | Where-Object { [string]$_.Mode -eq 'Audit' }) | Select-Object -First 1; $to = 'NotConfigured' }
        if (-not $rule) { $rule = @($usable | Where-Object { [string]$_.Mode -eq 'Warn' }) | Select-Object -First 1; $to = 'Audit' }
        if (-not $rule) { Add-Result -Check 'Asr' -Result 'Skip' -Detail 'no usable rule (off or in Audit)' }
        else {
            $m0 = [string]$rule.Mode
            $res = Invoke-IgwtAsrChange -RuleMode @{ ([string]$rule.Id) = $to } -Confirm:$false
            $m1 = [string]@((Get-IgwtAsrStatus).Rules | Where-Object { $_.Id -eq $rule.Id })[0].Mode
            $null = Invoke-IgwtRevert -SnapshotPath ([string]$res.Snapshot)
            $m2 = [string]@((Get-IgwtAsrStatus).Rules | Where-Object { $_.Id -eq $rule.Id })[0].Mode
            Add-Result -Check 'Asr' -Result $(if ($m1 -in $to, $(if ($to -eq 'NotConfigured') { 'Off' }) -and $m2 -eq $m0) { 'Pass' } else { 'Fail' }) -Detail "$($rule.Name): $m0 -> $m1 -> $m2"
        }
    } catch { Add-Result -Check 'Asr' -Result 'Fail' -Detail $_.Exception.Message }
}

# 6. Defender: scan CPU load nudged by 5 and restored (read back, DF-1).
if (& $want 'Defender') {
    try {
        $v0 = [int](Get-MpPreference).ScanAvgCPULoadFactor
        $v1 = $(if ($v0 -ge 10) { $v0 - 5 } else { $v0 + 5 })
        $res = Invoke-IgwtDefenderSettingChange -Setting @{ ScanAvgCPULoadFactor = $v1 } -Confirm:$false
        $read1 = [int](Get-MpPreference).ScanAvgCPULoadFactor
        $null = Invoke-IgwtRevert -SnapshotPath ([string]$res.Snapshot)
        $read2 = [int](Get-MpPreference).ScanAvgCPULoadFactor
        Add-Result -Check 'Defender' -Result $(if ($read1 -eq $v1 -and $read2 -eq $v0) { 'Pass' } else { 'Fail' }) -Detail "ScanAvgCPULoadFactor $v0 -> $read1 -> $read2"
    } catch { Add-Result -Check 'Defender' -Result 'Fail' -Detail $_.Exception.Message }
}

# 7. Security Settings: success auditing added to a quiet subcategory, undone from the journal.
if (& $want 'SecSettings') {
    try {
        $row = @((Get-IgwtRoundTripSecRows) | Where-Object { [string]$_.SourceKind -eq 'audit' -and [string]$_.Current -eq 'None' -and [string]$_.Name -match 'Other' }) | Select-Object -First 1
        if (-not $row) { Add-Result -Check 'SecSettings' -Result 'Skip' -Detail 'no quiet audit subcategory' }
        else {
            $res = Invoke-IgwtSecSettingChange -Changes @(@{ Id = [string]$row.Id; Value = 'Success' }) -Confirm:$false
            $mid = [string]@((Get-IgwtRoundTripSecRows) | Where-Object { $_.Id -eq $row.Id })[0].Current
            $plan = @(Get-IgwtRevertPlan -SessionId ([string]$res.SessionId))
            $null = Invoke-IgwtJournalRevert -Plan $plan -Title 'Round trip: security setting' -Confirm:$false
            $end = [string]@((Get-IgwtRoundTripSecRows) | Where-Object { $_.Id -eq $row.Id })[0].Current
            Add-Result -Check 'SecSettings' -Result $(if ($mid -eq 'Success' -and $end -eq 'None') { 'Pass' } else { 'Fail' }) -Detail "$($row.Name): None -> $mid -> $end"
        }
    } catch { Add-Result -Check 'SecSettings' -Result 'Fail' -Detail $_.Exception.Message }
}

# 8. Session Mode: start and stop (PRE-1 path with a real backup).
if (& $want 'Session') {
    try {
        if ((Get-IgwtSessionState).Active) { Add-Result -Check 'Session' -Result 'Skip' -Detail 'a session is already active' }
        else {
            $r1 = Start-IgwtSession -Owner cli -Confirm:$false
            $act = (Get-IgwtSessionState).Active
            $r2 = Stop-IgwtSession -Confirm:$false
            $bad = @($r2.Results | Where-Object { $_.Result -eq 'Failed' })
            Add-Result -Check 'Session' -Result $(if ($act -and -not (Get-IgwtSessionState).Active -and -not $bad.Count) { 'Pass' } else { 'Fail' }) -Detail "applied $(@($r1.Results | Where-Object Result -EQ 'Applied').Count); restored $(@($r2.Results | Where-Object Result -EQ 'Reverted').Count); failed $($bad.Count)"
        }
    } catch { Add-Result -Check 'Session' -Result 'Fail' -Detail $_.Exception.Message }
}

# 9. Startup app: one user entry off and on again.
if (& $want 'Startup') {
    try {
        $it = @(Get-IgwtStartupItem | Where-Object { $_.Enabled -and -not [string]$_.Protection -and -not $_.FileMissing }) | Sort-Object { [string]$_.Scope -notlike 'HKCU*' } | Select-Object -First 1
        $flip = $false
        if (-not $it) { $it = @(Get-IgwtStartupItem | Where-Object { -not $_.Enabled -and -not [string]$_.Protection -and -not $_.FileMissing -and [string]$_.Scope -like 'HKCU*' }) | Select-Object -First 1; $flip = [bool]$it }
        if (-not $it) { Add-Result -Check 'Startup' -Result 'Skip' -Detail 'no unprotected startup entry' }
        elseif ($flip) {
            $null = Set-IgwtStartupItemEnabled -Scope ([string]$it.Scope) -Name ([string]$it.Name) -Enabled $true -Confirm:$false
            $mid = [bool]@(Get-IgwtStartupItem | Where-Object { $_.Scope -eq $it.Scope -and $_.Name -eq $it.Name })[0].Enabled
            $null = Set-IgwtStartupItemEnabled -Scope ([string]$it.Scope) -Name ([string]$it.Name) -Enabled $false -Confirm:$false
            $end = [bool]@(Get-IgwtStartupItem | Where-Object { $_.Scope -eq $it.Scope -and $_.Name -eq $it.Name })[0].Enabled
            Add-Result -Check 'Startup' -Result $(if ($mid -and -not $end) { 'Pass' } else { 'Fail' }) -Detail "$($it.Name): off -> $mid -> $end"
        }
        else {
            $null = Set-IgwtStartupItemEnabled -Scope ([string]$it.Scope) -Name ([string]$it.Name) -Enabled $false -Confirm:$false
            $mid = [bool]@(Get-IgwtStartupItem | Where-Object { $_.Scope -eq $it.Scope -and $_.Name -eq $it.Name })[0].Enabled
            $null = Set-IgwtStartupItemEnabled -Scope ([string]$it.Scope) -Name ([string]$it.Name) -Enabled $true -Confirm:$false
            $end = [bool]@(Get-IgwtStartupItem | Where-Object { $_.Scope -eq $it.Scope -and $_.Name -eq $it.Name })[0].Enabled
            Add-Result -Check 'Startup' -Result $(if (-not $mid -and $end) { 'Pass' } else { 'Fail' }) -Detail "$($it.Name): on -> $mid -> $end"
        }
    } catch { Add-Result -Check 'Startup' -Result 'Fail' -Detail $_.Exception.Message }
}

# 10. Registry cleaner: a planted leftover is found, removed and restored.
if (& $want 'RegClean') {
    $key = 'HKCU:\Software\IgwtRoundTripVendor\IgwtRoundTripProduct'
    try {
        $null = New-Item -Path $key -Force; New-ItemProperty -Path $key -Name 'Exe' -Value 'C:\Program Files\IgwtRoundTripGone\app.exe' -PropertyType String -Force | Out-Null
        $scan = Get-IgwtRegistryLeftovers
        $f = @($scan.Findings | Where-Object { [string]$_.Path -like '*IgwtRoundTripVendor\IgwtRoundTripProduct' }) | Select-Object -First 1
        if (-not $f) { Add-Result -Check 'RegClean' -Result 'Fail' -Detail 'the planted leftover was not found' }
        else {
            $plan = Get-IgwtRegCleanPlan -Findings @($f)
            $res = Invoke-IgwtRegistryCleanup -Plan $plan -SkipRestorePoint -Confirm:$false
            $gone = -not (Test-Path -LiteralPath $key)
            $rp = @(Get-IgwtRevertPlan -SessionId ([string]$res.SessionId))
            $null = Invoke-IgwtJournalRevert -Plan $rp -Title 'Round trip: registry leftover' -Confirm:$false
            $back = ((Get-ItemProperty -LiteralPath $key -Name Exe -ErrorAction SilentlyContinue).Exe -eq 'C:\Program Files\IgwtRoundTripGone\app.exe')
            Add-Result -Check 'RegClean' -Result $(if ($gone -and $back) { 'Pass' } else { 'Fail' }) -Detail "found [$($f.Confidence)]; removed $gone; restored $back"
        }
    } catch { Add-Result -Check 'RegClean' -Result 'Fail' -Detail $_.Exception.Message }
    finally { Remove-Item -LiteralPath 'HKCU:\Software\IgwtRoundTripVendor' -Recurse -Force -ErrorAction SilentlyContinue }
}

$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ReportPath -Encoding utf8
Write-Information -MessageData "Report: $ReportPath" -InformationAction Continue
$results
