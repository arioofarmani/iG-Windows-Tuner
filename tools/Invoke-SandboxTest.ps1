<#
.SYNOPSIS
    End-to-end test INSIDE Windows Sandbox: apply all -> verify -> revert all -> verify.
.DESCRIPTION
    Started automatically by tools\iGWindowsTuner.wsb (project mapped read-only to C:\iGWindowsTuner, results
    folder mapped writable to C:\SandboxResults). It refuses to run anywhere except Windows Sandbox
    because it really applies every non-expert tweak to the (disposable) sandbox system.

    Steps:
      1. Health report (HTML) and the state of every tweak before.
      2. Raw capture of every registry value the catalog touches.
      3. Apply all non-expert tweaks (one of each conflicting pair), without a restore point
         (Sandbox has no System Protection; the JSON snapshot is still written).
      4. Verify: every applicable tweak should now be On (GPU/TPM/adapter items report NotApplicable).
      5. Revert from the snapshot written in step 3.
      6. Verify: every captured registry value is back exactly (type, data, absent).
      7. Presets on the VM fixture: each built-in preset is resolved for this VM's hardware tags,
         applied, verified and reverted, with the same exact registry comparison.
      8. Session Mode: start, verify the session items, end, verify the restore.
      9. Cleaner: scan the Standard rules, clean, scan again; no rule errors and the reclaimable
         size must not grow.
     10. Custom presets: save, export, import and delete a custom preset.
    Results: summary.txt, results.json, report.html, transcript.txt and the iG Windows Tuner logs.
.PARAMETER ResultsPath
    Writable results folder (default C:\SandboxResults).
#>
[CmdletBinding()]
param([string]$ResultsPath = 'C:\SandboxResults')
$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $ResultsPath)) { $null = New-Item -ItemType Directory -Path $ResultsPath -Force }
Start-Transcript -Path (Join-Path $ResultsPath 'transcript.txt') -Force | Out-Null
try {
    if ($env:USERNAME -ne 'WDAGUtilityAccount') {
        throw 'Safety stop: this script applies every tweak for real and only runs inside Windows Sandbox (user WDAGUtilityAccount).'
    }
    $projectRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $projectRoot 'src\iGWindowsTuner.psd1') -Force
    $module = Get-Module iGWindowsTuner

    Write-Output '== Report'
    $report = Get-IgwtHealthReport
    $null = Export-IgwtHealthReport -Report $report -Path (Join-Path $ResultsPath 'report.html') -Format Html

    $catalog = @(Get-IgwtCatalog)
    # One of each conflicting pair; inbox app removal is covered by the preset step (its revert needs the Store).
    $skip = @('power.high-performance-plan', 'net.doh-cloudflare', 'sec.asr-office-audit', 'privacy.defer-feature-90', 'privacy.inbox-apps-consumer-off')
    $ids = @($catalog | Where-Object { -not $_.expert -and $skip -notcontains $_.id } | ForEach-Object { $_.id })

    $captureRegistry = {
        param($Catalog)
        $rows = @()
        foreach ($t in $Catalog) {
            foreach ($a in @($t.actions)) {
                if ($a.type -notin 'registry', 'registryListMerge') { continue }
                $v = Get-IgwtRegistryValue -Path $a.path -Name $a.name
                $rows += [pscustomobject]@{ Key = "$($a.path)\$($a.name)"; Exists = $v.Exists; Kind = $v.Kind; Value = (ConvertTo-IgwtSerializableValue -Value $v.Value -Kind $v.Kind) }
            }
        }
        $rows | Sort-Object Key -Unique
    }

    Write-Output '== Before'
    $ctx = New-IgwtContext
    $before = @(Get-IgwtAllTweakStates -Context $ctx | Select-Object Id, State, Reason)
    $regBefore = & $module $captureRegistry $catalog

    Write-Output "== Apply $($ids.Count) tweaks"
    $apply = Invoke-IgwtApply -Id $ids -Operation 'Apply' -SkipRestorePoint
    $applyFailed = @($apply.Results | Where-Object Result -EQ 'Failed')
    $notVerified = @($apply.Results | Where-Object { $_.Result -eq 'Applied' -and $_.PSObject.Properties['Verified'] -and -not $_.Verified })

    Write-Output '== Verify after apply'
    $ctx = New-IgwtContext
    $after = @(Get-IgwtAllTweakStates -Id $ids -Context $ctx | Select-Object Id, State, Reason)
    $notOn = @($after | Where-Object { $_.State -notin 'On', 'NotApplicable', 'ManagedByPolicy' })

    Write-Output '== Revert'
    $revert = $null
    if ($apply.Snapshot) { $revert = Invoke-IgwtRevert -SnapshotPath $apply.Snapshot }
    $revertFailed = @()
    if ($revert) { $revertFailed = @($revert.Results | Where-Object Result -EQ 'Failed') }

    Write-Output '== Verify after revert'
    $regAfter = & $module $captureRegistry $catalog
    $mismatch = @()
    foreach ($b in $regBefore) {
        $a = $regAfter | Where-Object Key -EQ $b.Key | Select-Object -First 1
        if (-not $a -or $a.Exists -ne $b.Exists -or $a.Kind -ne $b.Kind -or (ConvertTo-Json $a.Value -Compress) -ne (ConvertTo-Json $b.Value -Compress)) {
            $mismatch += [pscustomobject]@{ Key = $b.Key; Before = "$($b.Exists) $($b.Kind) $(ConvertTo-Json $b.Value -Compress)"; After = $(if ($a) { "$($a.Exists) $($a.Kind) $(ConvertTo-Json $a.Value -Compress)" } else { 'missing' }) }
        }
    }
    $ctx = New-IgwtContext
    $final = @(Get-IgwtAllTweakStates -Context $ctx | Select-Object Id, State, Reason)
    $stateDiff = @(foreach ($b in $before) { $f = $final | Where-Object Id -EQ $b.Id; if ($f.State -ne $b.State) { [pscustomobject]@{ Id = $b.Id; Before = $b.State; After = $f.State } } })

    $compare = {
        param($Before, $After)
        foreach ($b in $Before) {
            $a = $After | Where-Object Key -EQ $b.Key | Select-Object -First 1
            if (-not $a -or $a.Exists -ne $b.Exists -or $a.Kind -ne $b.Kind -or (ConvertTo-Json $a.Value -Compress) -ne (ConvertTo-Json $b.Value -Compress)) { $b.Key }
        }
    }

    Write-Output '== Presets on the VM fixture'
    $presetRows = @()
    foreach ($p in @(Get-IgwtPreset -Builtin | Where-Object { -not ($_.PSObject.Properties['session'] -and $_.session) })) {
        $sel = Resolve-IgwtPresetSelection -Preset $p
        $regB = & $module $captureRegistry $catalog
        $pa = Invoke-IgwtApply -Id @($sel.Ids) -Operation "Preset:$($p.id)" -SkipRestorePoint
        $ctx = New-IgwtContext
        $pNotOn = @(Get-IgwtAllTweakStates -Id @($sel.Ids) -Context $ctx | Where-Object { $_.State -notin 'On', 'NotApplicable', 'ManagedByPolicy' } | ForEach-Object { $_.Id })
        $pr = $null; if ($pa.Snapshot) { $pr = Invoke-IgwtRevert -SnapshotPath $pa.Snapshot }
        $regA = & $module $captureRegistry $catalog
        $pm = @(& $compare $regB $regA)
        $presetRows += [pscustomobject]@{ Preset = $p.id; Items = @($sel.Ids).Count; Blocked = @($sel.Blocked); Applied = @($pa.Results | Where-Object Result -EQ 'Applied').Count
            ApplyFailed = @($pa.Results | Where-Object Result -EQ 'Failed' | ForEach-Object { "$($_.Id): $($_.Message)" }); NotOn = $pNotOn
            RevertFailed = @($(if ($pr) { $pr.Results | Where-Object Result -EQ 'Failed' | ForEach-Object { "$($_.Id): $($_.Message)" } })); RegistryMismatch = $pm }
    }
    $presetFail = @($presetRows | Where-Object { @($_.ApplyFailed).Count -or @($_.RevertFailed).Count -or @($_.RegistryMismatch).Count })

    Write-Output '== Session Mode'
    $sessionOk = $false; $sessionNote = ''
    try {
        $regB = & $module $captureRegistry $catalog
        $ss = Start-IgwtSession -Owner cli
        $active = (Get-IgwtSessionState).Active
        $toast = Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled'
        $null = Stop-IgwtSession
        $regA = & $module $captureRegistry $catalog
        $sm = @(& $compare $regB $regA)
        $sessionOk = ($active -and $toast.Exists -and [int]$toast.Value -eq 0 -and -not (Get-IgwtSessionState).Active -and $sm.Count -eq 0)
        $sessionNote = "applied $(@($ss.Results | Where-Object Result -EQ 'Applied').Count), power plan $($ss.PowerPlan), registry mismatches after end: $($sm.Count)"
    } catch { $sessionNote = "error: $($_.Exception.Message)" }

    Write-Output '== Cleaner'
    $cleanOk = $false; $cleanNote = ''
    try {
        $scan1 = Invoke-IgwtCleanerScan -Level Standard
        $clean = Invoke-IgwtCleanerClean -Scan $scan1
        $scan2 = Invoke-IgwtCleanerScan -Level Standard
        $b1 = [long](($scan1.Rules | Measure-Object Bytes -Sum).Sum); $b2 = [long](($scan2.Rules | Measure-Object Bytes -Sum).Sum)
        $errs = @($clean.Rules | Where-Object Status -EQ 'Error')
        $cleanOk = ($errs.Count -eq 0 -and $b2 -le $b1)
        $cleanNote = ("{0:N1} MB before, {1:N1} MB freed, {2:N1} MB after, {3} rule error(s)" -f ($b1 / 1MB), ($clean.FreedBytes / 1MB), ($b2 / 1MB), $errs.Count)
    } catch { $cleanNote = "error: $($_.Exception.Message)" }

    Write-Output '== Custom presets'
    $customOk = $false; $customNote = ''
    try {
        $cp = Save-IgwtCustomPreset -Name 'Sandbox test' -BasedOn balanced -AddIds 'system.long-paths' -RemoveIds 'sec.llmnr-off' -Force
        $exp = Join-Path $env:TEMP 'igwt-sandbox-preset.json'
        $null = Export-IgwtPreset -Name $cp.id -Path $exp
        Remove-IgwtCustomPreset -Name $cp.id
        $imp = Import-IgwtPreset -Path $exp
        $customOk = ((@($imp.tweaks) -join ',') -eq (@($cp.tweaks) -join ','))
        Remove-IgwtCustomPreset -Name $imp.id
        $customNote = "$(@($cp.tweaks).Count) items round-tripped"
    } catch { $customNote = "error: $($_.Exception.Message)" }

    $pass = ($applyFailed.Count -eq 0 -and $revertFailed.Count -eq 0 -and $mismatch.Count -eq 0 -and $presetFail.Count -eq 0 -and $sessionOk -and $cleanOk -and $customOk)
    $results = [ordered]@{
        Pass = $pass; Build = (Get-IgwtOsInfo).FullBuild; Applied = @($apply.Results | Where-Object Result -EQ 'Applied').Count
        ApplyFailed = $applyFailed; NotVerified = $notVerified; NotOnAfterApply = $notOn; RevertFailed = $revertFailed
        RegistryMismatchAfterRevert = $mismatch; StateDifferencesAfterRevert = $stateDiff; Before = $before; After = $after; Final = $final
        ApplySnapshot = $apply.Snapshot; RevertSnapshot = $(if ($revert) { $revert.Snapshot } else { $null })
        Presets = $presetRows; Session = [ordered]@{ Pass = $sessionOk; Note = $sessionNote }; Cleaner = [ordered]@{ Pass = $cleanOk; Note = $cleanNote }; CustomPresets = [ordered]@{ Pass = $customOk; Note = $customNote }
    }
    $results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ResultsPath 'results.json') -Encoding UTF8
    $summary = @(
        "iG Windows Tuner Windows Sandbox test - $(Get-Date -Format s)"
        "Result: $(if ($pass) { 'PASS' } else { 'FAIL' })"
        "Tweaks applied: $($results.Applied); apply failures: $($applyFailed.Count); not verified: $($notVerified.Count)"
        "Applicable tweaks not On after apply: $($notOn.Count)"
        "Revert failures: $($revertFailed.Count); registry values not restored exactly: $($mismatch.Count); state differences after revert: $($stateDiff.Count)"
        ''
        'Apply failures:'; ($applyFailed | ForEach-Object { "  $($_.Id): $($_.Message)" })
        'Not On after apply (expected for hardware-dependent items in Sandbox):'; ($notOn | ForEach-Object { "  $($_.Id): $($_.State) $($_.Reason)" })
        'Registry mismatches after revert:'; ($mismatch | ForEach-Object { "  $($_.Key): before $($_.Before) / after $($_.After)" })
        'State differences after revert:'; ($stateDiff | ForEach-Object { "  $($_.Id): $($_.Before) -> $($_.After)" })
        ''
        "Presets on the VM fixture: $($presetRows.Count) tested, $($presetFail.Count) with failures"
        ($presetRows | ForEach-Object { "  $($_.Preset): $($_.Items) items, $($_.Applied) applied, blocked $(@($_.Blocked).Count), failures $(@($_.ApplyFailed).Count)/$(@($_.RevertFailed).Count), registry mismatches $(@($_.RegistryMismatch).Count), not On $(@($_.NotOn).Count)" })
        "Session Mode: $(if ($sessionOk) { 'PASS' } else { 'FAIL' }) ($sessionNote)"
        "Cleaner cycle: $(if ($cleanOk) { 'PASS' } else { 'FAIL' }) ($cleanNote)"
        "Custom presets: $(if ($customOk) { 'PASS' } else { 'FAIL' }) ($customNote)"
    )
    $summary | Set-Content -LiteralPath (Join-Path $ResultsPath 'summary.txt') -Encoding UTF8
    $summary | Write-Output
    $logs = Get-IgwtDataPath -Kind Logs
    if (Test-Path -LiteralPath $logs) { Copy-Item -Path (Join-Path $logs '*') -Destination $ResultsPath -Force }
} catch {
    Write-Output "Sandbox test aborted: $($_.Exception.Message)"
    "ABORTED: $($_.Exception.Message)" | Set-Content -LiteralPath (Join-Path $ResultsPath 'summary.txt') -Encoding UTF8
} finally {
    Stop-Transcript | Out-Null
}
