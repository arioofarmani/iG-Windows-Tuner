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
    $skip = @('power.high-performance-plan', 'net.doh-cloudflare', 'sec.asr-office-audit')
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

    $pass = ($applyFailed.Count -eq 0 -and $revertFailed.Count -eq 0 -and $mismatch.Count -eq 0)
    $results = [ordered]@{
        Pass = $pass; Build = (Get-IgwtOsInfo).FullBuild; Applied = @($apply.Results | Where-Object Result -EQ 'Applied').Count
        ApplyFailed = $applyFailed; NotVerified = $notVerified; NotOnAfterApply = $notOn; RevertFailed = $revertFailed
        RegistryMismatchAfterRevert = $mismatch; StateDifferencesAfterRevert = $stateDiff; Before = $before; After = $after; Final = $final
        ApplySnapshot = $apply.Snapshot; RevertSnapshot = $(if ($revert) { $revert.Snapshot } else { $null })
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
