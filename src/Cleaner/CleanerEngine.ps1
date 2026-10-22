# CleanerEngine.ps1
# Two-phase cleaner: Invoke-IgwtCleanerScan enumerates and sizes (deletes nothing);
# Invoke-IgwtCleanerClean deletes only the files in a scan result, re-validating each one through
# Remove-IgwtCleanerFile. Processes are never killed; services are stopped only for the rules that
# declare them and always restored in a finally block. Work runs at below-normal thread priority and
# can be cancelled between files.

$script:IgwtCleanerMaxItemsPerRule = 250000
$script:IgwtLastCleanerScan = $null

#region Enumeration

function Get-IgwtCleanerRunningBlockers {
    <# .SYNOPSIS Names of required-closed processes that are running (the rule is skipped while they run). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule)
    $running = @()
    foreach ($n in @($Rule.requiresClosed)) {
        if (-not $n) { continue }
        if (@(Get-Process -Name ([string]$n) -ErrorAction SilentlyContinue).Count -gt 0) { $running += [string]$n }
    }
    return $running
}

function Test-IgwtNameMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Name, [string[]]$Patterns)
    foreach ($p in @($Patterns)) { if ($p -and $Name -like $p) { return $true } }
    return $false
}

function Add-IgwtCleanerSkip {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][string]$Reason, [string]$Path)
    if (-not $Result.Skipped.ContainsKey($Reason)) { $Result.Skipped[$Reason] = 0; $Result.SkippedSamples[$Reason] = New-Object System.Collections.Generic.List[string] }
    $Result.Skipped[$Reason]++
    if ($Path -and $Result.SkippedSamples[$Reason].Count -lt 5) { $Result.SkippedSamples[$Reason].Add($Path) }
}

function Get-IgwtCleanerFolderItems {
    <#
    .SYNOPSIS
        Enumerates one validated root without following reparse points. Adds file entries to
        $Result.Items and directories to $Result.Directories; records skip reasons.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule, [Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)]$Result, $CancelToken)
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $stack.Push((New-Object System.IO.DirectoryInfo($Root)))
    $first = $true
    while ($stack.Count -gt 0) {
        if ($CancelToken -and $CancelToken.IsCancellationRequested) { $Result.Cancelled = $true; return }
        $dir = $stack.Pop()
        if (-not $first) { $Result.Directories.Add([pscustomobject]@{ Path = $dir.FullName; Root = $Root }) }
        $first = $false
        $entries = @()
        try { $entries = @($dir.EnumerateFileSystemInfos()) } catch { Add-IgwtCleanerSkip -Result $Result -Reason 'folder not readable (access denied)' -Path $dir.FullName; continue }
        foreach ($e in $entries) {
            $attr = [long]$e.Attributes
            if (($attr -band $script:IgwtAttrReparse) -ne 0) { Add-IgwtCleanerSkip -Result $Result -Reason 'reparse point (not followed)' -Path $e.FullName; continue }
            if ($e -is [System.IO.DirectoryInfo]) {
                if (Test-IgwtNameMatch -Name $e.Name -Patterns @($Rule.exclude)) { Add-IgwtCleanerSkip -Result $Result -Reason 'excluded by rule' -Path $e.FullName; continue }
                if ($Rule.recurse) { $stack.Push($e) }
                continue
            }
            if (-not (Test-IgwtNameMatch -Name $e.Name -Patterns @($Rule.include))) { continue }
            if (Test-IgwtNameMatch -Name $e.Name -Patterns @($Rule.exclude)) { Add-IgwtCleanerSkip -Result $Result -Reason 'excluded by rule' -Path $e.FullName; continue }
            $skip = Test-IgwtCleanerAttributesSkippable -Attributes $attr -AllowSystemFiles:([bool]$Rule.allowSystemFiles)
            if ($skip) { Add-IgwtCleanerSkip -Result $Result -Reason $skip -Path $e.FullName; continue }
            if ((Get-IgwtCleanerFileAge -Item $e) -lt [double]$Rule.minAgeHours) { Add-IgwtCleanerSkip -Result $Result -Reason "younger than $($Rule.minAgeHours) h" -Path $e.FullName; continue }
            $prot = Test-IgwtCleanerPathProtected -Path $e.FullName -AllowDownloads:([bool]$Rule.allowDownloads)
            if ($prot) { Add-IgwtCleanerSkip -Result $Result -Reason "protected: $prot" -Path $e.FullName; continue }
            if ($Result.Items.Count -ge $script:IgwtCleanerMaxItemsPerRule) { $Result.Truncated = $true; Add-IgwtCleanerSkip -Result $Result -Reason 'item limit reached (scan again after cleaning)' -Path $e.FullName; continue }
            $Result.Items.Add([pscustomobject]@{ Path = $e.FullName; Size = [long]$e.Length; LastWriteTicks = $e.LastWriteTimeUtc.Ticks; Root = $Root })
        }
    }
}

#endregion

#region Special methods (sizes and actions)

function Get-IgwtRecycleBinUsage {
    <# .SYNOPSIS Size of the current user's Recycle Bin per fixed drive (read from X:\$Recycle.Bin\<SID>). #>
    [CmdletBinding()]
    param()
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -ne 'Fixed' -or -not $d.IsReady) { continue }
        $bin = Join-Path $d.RootDirectory.FullName "`$Recycle.Bin\$sid"
        $bytes = 0L; $count = 0
        if (Test-Path -LiteralPath $bin) {
            try {
                foreach ($f in (New-Object System.IO.DirectoryInfo($bin)).EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
                    if ($f.Name -like '$R*' -or $f.DirectoryName -ne $bin) { $bytes += $f.Length; if ($f.DirectoryName -eq $bin) { $count++ } }
                }
            } catch { Write-Verbose "Recycle Bin on $($d.Name) not readable." }
        }
        [pscustomobject]@{ Drive = $d.Name.TrimEnd('\').TrimEnd(':'); Bytes = $bytes; Items = $count }
    }
}

function Get-IgwtDeliveryOptimizationCacheSize {
    [CmdletBinding()]
    param()
    try { return [long](Get-DeliveryOptimizationPerfSnap -ErrorAction Stop -WarningAction SilentlyContinue).CacheSizeBytes } catch { return $null }
}

function ConvertFrom-IgwtSizeText {
    <# .SYNOPSIS "1.23 GB" -> bytes (used for DISM output). #>
    [CmdletBinding()]
    [OutputType([long])]
    param([string]$Text)
    if ($Text -match '([\d\.,]+)\s*(KB|MB|GB|TB|bytes)') {
        $n = [double]::Parse(($Matches[1] -replace ',', '.'), [System.Globalization.CultureInfo]::InvariantCulture)
        switch ($Matches[2]) { 'KB' { return [long]($n * 1KB) } 'MB' { return [long]($n * 1MB) } 'GB' { return [long]($n * 1GB) } 'TB' { return [long]($n * 1TB) } default { return [long]$n } }
    }
    return 0
}

function ConvertFrom-IgwtComponentStoreReport {
    <# .SYNOPSIS Parses 'dism /AnalyzeComponentStore /English' output (reclaimable bytes, recommendation, packages). #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $reclaim = 0L
    if ($Text -match 'Backups and Disabled Features\s*:\s*([^\r\n]+)') { $reclaim += ConvertFrom-IgwtSizeText $Matches[1] }
    $recommended = ($Text -match 'Component Store Cleanup Recommended\s*:\s*Yes')
    $packages = 0
    if ($Text -match 'Number of Reclaimable Packages\s*:\s*(\d+)') { $packages = [int]$Matches[1] }
    [pscustomobject]@{ Bytes = $reclaim; Recommended = [bool]$recommended; Packages = $packages }
}

function Get-IgwtComponentStoreAnalysis {
    <# .SYNOPSIS Read-only DISM component store analysis (needs elevation). #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: dism.exe must be mocked in tests.' }
    $exe = Join-Path $env:SystemRoot 'System32\dism.exe'
    $out = & $exe /Online /Cleanup-Image /AnalyzeComponentStore /English 2>&1 | Out-String
    $r = ConvertFrom-IgwtComponentStoreReport -Text $out
    $r | Add-Member -NotePropertyName ExitCode -NotePropertyValue $LASTEXITCODE
    return $r
}

function Get-IgwtDriverStoreCandidates {
    <#
    .SYNOPSIS
        Older third-party driver packages that have a newer version of the same package installed and
        are not bound to any present device. Read-only (needs elevation).
    #>
    [CmdletBinding()]
    param()
    $drivers = @(Get-WindowsDriver -Online -ErrorAction Stop | Where-Object { -not $_.Inbox -and $_.Driver -like 'oem*.inf' })
    $inUse = @{}
    foreach ($p in @(Get-PnpDevice -ErrorAction SilentlyContinue)) {
        try {
            $inf = (Get-PnpDeviceProperty -InstanceId $p.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath' -ErrorAction Stop).Data
            if ($inf) { $inUse[([string]$inf).ToLowerInvariant()] = $true }
        } catch { Write-Verbose "No driver inf for $($p.InstanceId)." }
    }
    $groups = $drivers | Group-Object { "$((Split-Path ([string]$_.OriginalFileName) -Leaf).ToLowerInvariant())|$($_.ProviderName)|$($_.ClassName)" }
    foreach ($g in $groups) {
        if ($g.Count -lt 2) { continue }
        $sorted = @($g.Group | Sort-Object @{ Expression = { $v = $null; if ([version]::TryParse([string]$_.Version, [ref]$v)) { $v } else { [version]'0.0' } } }, Date -Descending)
        foreach ($old in ($sorted | Select-Object -Skip 1)) {
            $name = ([string]$old.Driver).ToLowerInvariant()
            if ($inUse.ContainsKey($name)) { continue }
            $folder = Split-Path -Parent ([string]$old.OriginalFileName)
            $bytes = 0L
            try { $bytes = (Get-ChildItem -LiteralPath $folder -Recurse -File -ErrorAction Stop | Measure-Object Length -Sum).Sum } catch { $bytes = 0 }
            [pscustomobject]@{ Inf = $name; Provider = $old.ProviderName; Class = $old.ClassName; Version = [string]$old.Version; Date = $old.Date; Bytes = [long]$bytes; Newer = [string]$sorted[0].Version }
        }
    }
}

#endregion

#region Services

function Stop-IgwtCleanerService {
    <# .SYNOPSIS Stops the rule's services and returns their original states (restored by Restore-IgwtCleanerService). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]]$Name)
    $states = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($Name)) {
        if (-not $n) { continue }
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $states.Add([pscustomobject]@{ Name = $n; WasRunning = ([string]$svc.Status -eq 'Running') })
        if ([string]$svc.Status -eq 'Running' -and $PSCmdlet.ShouldProcess($n, 'Stop service temporarily')) {
            try { Stop-Service -Name $n -Force -ErrorAction Stop }
            catch {
                # Restart what this call already stopped before reporting the failure.
                try { Restore-IgwtCleanerService -States $states.ToArray() } catch { Write-IgwtLog -Level Warn -Message "Cleaner: could not restart services: $($_.Exception.Message)" }
                throw
            }
        }
    }
    return $states.ToArray()
}

function Restore-IgwtCleanerService {
    <# .SYNOPSIS Starts every service that was running before the clean. Never throws. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($States)
    foreach ($s in @($States)) {
        if (-not $s -or -not $s.WasRunning) { continue }
        try { if ($PSCmdlet.ShouldProcess($s.Name, 'Restart service')) { Start-Service -Name $s.Name -ErrorAction Stop } }
        catch { Write-IgwtLog -Level Warn -Message "Cleaner could not restart service $($s.Name): $($_.Exception.Message)" }
    }
}

#endregion

#region Scan

function New-IgwtCleanerRuleResult {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory result object only.')]
    param([Parameter(Mandatory = $true)]$Rule)
    [pscustomobject]@{
        RuleId = [string]$Rule.id; Name = [string]$Rule.name; Category = [string]$Rule.category; Level = [string]$Rule.level; Method = [string]$Rule.method
        Default = [bool]$Rule.default; Hint = [string]$Rule.hint; SideEffects = [string]$Rule.sideEffects
        Status = 'Ready'; Reason = ''; Bytes = 0L; Count = 0; Roots = @(); Items = (New-Object System.Collections.Generic.List[object])
        Directories = (New-Object System.Collections.Generic.List[object]); Skipped = @{}; SkippedSamples = @{}; Samples = @(); Truncated = $false; Cancelled = $false
        Extra = $null; Blockers = @(); ResolvedRoots = @()
    }
}

function Invoke-IgwtCleanerRuleScan {
    <# .SYNOPSIS Scans one rule. Never deletes anything. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule, [switch]$AllUsers, $CancelToken)
    $res = New-IgwtCleanerRuleResult -Rule $Rule
    $isAdmin = Test-IgwtIsAdmin
    try {
        $res.Blockers = @(Get-IgwtCleanerRunningBlockers -Rule $Rule)
        switch ([string]$Rule.method) {
            { $_ -in 'files', 'browserCache', 'guidance' } {
                $roots = @(Resolve-IgwtCleanerRoots -Rule $Rule -AllUsers:$AllUsers)
                $res.Roots = $roots
                $res.ResolvedRoots = @($roots | Where-Object { $_.Status -eq 'Ok' } | ForEach-Object { $_.Path })
                foreach ($r in ($roots | Where-Object { $_.Status -eq 'Refused' })) { Add-IgwtCleanerSkip -Result $res -Reason "root refused: $($r.Reason)" -Path $r.Path }
                foreach ($root in $res.ResolvedRoots) { Get-IgwtCleanerFolderItems -Rule $Rule -Root $root -Result $res -CancelToken $CancelToken }
                if ([int]$Rule.keepNewest -gt 0 -and $res.Items.Count -gt 0) {
                    $keep = @($res.Items | Sort-Object LastWriteTicks -Descending | Select-Object -First ([int]$Rule.keepNewest))
                    foreach ($k in $keep) { [void]$res.Items.Remove($k); Add-IgwtCleanerSkip -Result $res -Reason "kept the newest $($Rule.keepNewest)" -Path $k.Path }
                }
                $res.Bytes = [long](($res.Items | Measure-Object Size -Sum).Sum)
                $res.Count = $res.Items.Count
                if ($Rule.method -eq 'guidance') { $res.Status = 'GuidanceOnly'; $res.Reason = [string]$Rule.notes }
                elseif ($res.ResolvedRoots.Count -eq 0 -and @($roots | Where-Object { $_.Status -eq 'Refused' }).Count -gt 0) { $res.Status = 'Refused'; $res.Reason = 'Every folder of this rule resolves to a protected location on this PC, so it is never cleaned.' }
                elseif ($res.ResolvedRoots.Count -eq 0) { $res.Status = 'NotPresent'; $res.Reason = 'Nothing to clean: the folders do not exist on this PC.' }
            }
            'recycleBin' {
                $usage = @(Get-IgwtRecycleBinUsage)
                $res.Extra = $usage
                $res.Bytes = [long](($usage | Measure-Object Bytes -Sum).Sum)
                $res.Count = [int](($usage | Measure-Object Items -Sum).Sum)
            }
            'deliveryOptimization' {
                $b = Get-IgwtDeliveryOptimizationCacheSize
                if ($null -eq $b) { $res.Status = 'Unknown'; $res.Reason = 'Delivery Optimization status is not available.' } else { $res.Bytes = $b; $res.Count = $(if ($b -gt 0) { 1 } else { 0 }) }
            }
            'dism' {
                if (-not $isAdmin) { $res.Status = 'RequiresAdmin'; $res.Reason = 'Component store analysis needs administrator rights.' }
                else {
                    $a = Get-IgwtComponentStoreAnalysis
                    $res.Extra = $a; $res.Bytes = $a.Bytes; $res.Count = $a.Packages
                    if (-not $a.Recommended -and -not $Rule.resetBase) { $res.Reason = 'DISM reports that component store cleanup is not recommended right now.' }
                }
            }
            'driverStore' {
                if (-not $isAdmin) { $res.Status = 'RequiresAdmin'; $res.Reason = 'Driver store analysis needs administrator rights.' }
                else {
                    $c = @(Get-IgwtDriverStoreCandidates)
                    $res.Extra = $c; $res.Bytes = [long](($c | Measure-Object Bytes -Sum).Sum); $res.Count = $c.Count
                }
            }
        }
        if ($res.Status -eq 'Ready' -and $Rule.requiresAdmin -and -not $isAdmin) { $res.Status = 'RequiresAdmin'; $res.Reason = 'Cleaning this needs administrator rights (sizes may be incomplete).' }
        if ($res.Status -eq 'Ready' -and $res.Blockers.Count -gt 0) { $res.Status = 'RequiresClose'; $res.Reason = "Close $($res.Blockers -join ', ') first; iG Windows Tuner never closes apps for you." }
        if ($res.Status -eq 'Ready' -and $res.Bytes -eq 0 -and $res.Count -eq 0) { $res.Status = 'Empty' }
        if ($res.Cancelled) { $res.Status = 'Cancelled' }
        $res.Samples = @($res.Items | Sort-Object Size -Descending | Select-Object -First 10 | ForEach-Object { $_.Path })
    } catch {
        $res.Status = 'Error'; $res.Reason = $_.Exception.Message
    }
    return $res
}

function Invoke-IgwtCleanerScan {
    <#
    .SYNOPSIS
        Phase 1: enumerates and sizes the selected rules. Deletes nothing.
    .PARAMETER RuleId
        Rules to scan (default: every rule up to -Level; default-off rules only with -IncludeOptIn).
    .PARAMETER Level
        Highest rule level to include (Standard, Advanced, Expert).
    .PARAMETER IncludeOptIn
        Include rules that are off by default.
    .PARAMETER AllUsers
        Expand allUsers rules to every local profile (requires admin).
    #>
    [CmdletBinding()]
    param([string[]]$RuleId, [ValidateSet('Standard', 'Advanced', 'Expert')][string]$Level = 'Standard', [switch]$IncludeOptIn, [switch]$AllUsers, $CancelToken)
    if ($AllUsers -and -not (Test-IgwtIsAdmin) -and -not $script:IgwtSettings.TestMode) { throw 'All-user-profiles mode requires administrator rights.' }
    $rules = @()
    if ($RuleId) { $rules = @(Get-IgwtCleanerRule -Id $RuleId) }
    else {
        $max = [array]::IndexOf($script:IgwtLevels, $Level)
        $rules = @(Get-IgwtCleanerRules | Where-Object { [array]::IndexOf($script:IgwtLevels, [string]$_.level) -le $max -and ($_.default -or $IncludeOptIn) })
    }
    $oldPriority = [System.Threading.Thread]::CurrentThread.Priority
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::BelowNormal
    $script:IgwtCleanerProtection = $null
    try {
        $results = New-Object System.Collections.Generic.List[object]
        $n = 0
        foreach ($r in $rules) {
            $n++
            Send-IgwtProgress -Text "Scanning: $($r.name)" -Percent ([int](100 * ($n - 1) / [Math]::Max(1, $rules.Count)))
            $results.Add((Invoke-IgwtCleanerRuleScan -Rule $r -AllUsers:$AllUsers -CancelToken $CancelToken))
            if ($CancelToken -and $CancelToken.IsCancellationRequested) { break }
        }
        Send-IgwtProgress -Text 'Scan finished' -Percent 100
        $scan = [pscustomobject]@{
            Id = [guid]::NewGuid().ToString(); Created = (Get-Date).ToString('o'); AllUsers = [bool]$AllUsers
            Rules = $results.ToArray(); TotalBytes = [long](($results | Measure-Object Bytes -Sum).Sum); TotalCount = [int](($results | Measure-Object Count -Sum).Sum)
        }
        $script:IgwtLastCleanerScan = $scan
        Write-IgwtLog -Message ("Cleaner scan: {0} rule(s), {1:N1} MB in {2} item(s). Nothing was deleted." -f $results.Count, ($scan.TotalBytes / 1MB), $scan.TotalCount)
        return $scan
    } finally {
        [System.Threading.Thread]::CurrentThread.Priority = $oldPriority
    }
}

#endregion

#region Clean

function Write-IgwtCleanerDeletionLog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Writer, [Parameter(Mandatory = $true)][string]$RuleId, [Parameter(Mandatory = $true)]$Outcome)
    $line = ConvertTo-Json -Compress -InputObject ([ordered]@{ time = (Get-Date).ToString('o'); rule = $RuleId; path = $Outcome.Path; bytes = $Outcome.Bytes })
    $Writer.WriteLine($line)
}

function Invoke-IgwtCleanerLogRotation {
    <# .SYNOPSIS Keeps the 10 newest cleaner deletion logs; older ones are compressed into one archive and removed. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Folder)
    $logs = @(Get-ChildItem -LiteralPath $Folder -Filter 'Cleaner-*.jsonl' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if ($logs.Count -le 10) { return }
    $old = $logs | Select-Object -Skip 10
    $zip = Join-Path $Folder ("Cleaner-archive-{0}.zip" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    if ($PSCmdlet.ShouldProcess($zip, 'Compress old cleaner logs')) {
        Compress-Archive -LiteralPath @($old.FullName) -DestinationPath $zip -CompressionLevel Optimal
        foreach ($o in $old) { Remove-Item -LiteralPath $o.FullName -Force }
    }
}

function Invoke-IgwtCleanerRuleClean {
    <#
    .SYNOPSIS
        Cleans one rule from a scan. The rule's roots are resolved again and intersected with the
        scan's roots, so a stale or modified scan object cannot widen what may be deleted.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Rule, [Parameter(Mandatory = $true)]$RuleScan, $Writer, $CancelToken, [switch]$AllUsers)
    $sum = [pscustomobject]@{ RuleId = $Rule.id; Name = $Rule.name; Status = 'Cleaned'; Reason = ''; DeletedBytes = 0L; DeletedCount = 0; Skipped = @{}; SkippedSamples = @{} }
    $isAdmin = (Test-IgwtIsAdmin) -or $script:IgwtSettings.TestMode
    if ($RuleScan.Status -in 'Error', 'NotPresent', 'Refused', 'GuidanceOnly', 'Empty', 'Cancelled', 'Unknown') { $sum.Status = 'Skipped'; $sum.Reason = "Scan status: $($RuleScan.Status)"; return $sum }
    if ($Rule.requiresAdmin -and -not $isAdmin) { $sum.Status = 'Skipped'; $sum.Reason = 'Requires administrator rights.'; return $sum }
    $blockers = @(Get-IgwtCleanerRunningBlockers -Rule $Rule)
    if ($blockers.Count -gt 0) { $sum.Status = 'Skipped'; $sum.Reason = "Close $($blockers -join ', ') first (iG Windows Tuner never closes apps)."; return $sum }
    if (-not $PSCmdlet.ShouldProcess($Rule.id, 'Clean')) { $sum.Status = 'Skipped'; $sum.Reason = 'WhatIf'; return $sum }

    $roots = @()
    if ($Rule.method -in 'files', 'browserCache') {
        $fresh = @(Resolve-IgwtCleanerRoots -Rule $Rule -AllUsers:$AllUsers | Where-Object { $_.Status -eq 'Ok' } | ForEach-Object { $_.Path })
        $roots = @($RuleScan.ResolvedRoots | Where-Object { $scanRoot = [string]$_; @($fresh | Where-Object { [string]::Equals($_, $scanRoot, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 })
    }
    $ruleForDelete = $Rule.PSObject.Copy()
    $ruleForDelete | Add-Member -NotePropertyName ResolvedRoots -NotePropertyValue $roots -Force
    $services = @()
    try {
        if (@($Rule.services).Count -gt 0) { $services = @(Stop-IgwtCleanerService -Name @($Rule.services)) }
        switch ([string]$Rule.method) {
            { $_ -in 'files', 'browserCache' } {
                foreach ($item in $RuleScan.Items) {
                    if ($CancelToken -and $CancelToken.IsCancellationRequested) { $sum.Status = 'Cancelled'; break }
                    $o = Remove-IgwtCleanerFile -Entry $item -Rule $ruleForDelete
                    if ($o.Result -eq 'Deleted') {
                        $sum.DeletedBytes += $o.Bytes; $sum.DeletedCount++
                        if ($Writer) { Write-IgwtCleanerDeletionLog -Writer $Writer -RuleId $Rule.id -Outcome $o }
                    } else { Add-IgwtCleanerSkip -Result $sum -Reason $o.Reason -Path $o.Path }
                }
                if ($Rule.removeEmptyDirs) {
                    foreach ($d in @($RuleScan.Directories | Sort-Object { $_.Path.Length } -Descending)) {
                        $null = Remove-IgwtCleanerEmptyDirectory -Path $d.Path -Root $d.Root -Rule $ruleForDelete
                    }
                }
            }
            'recycleBin' {
                # Empty a drive's bin only when it holds nothing the scan did not show.
                $now = @{}
                foreach ($x in @(Get-IgwtRecycleBinUsage)) { $now[[string]$x.Drive] = $x }
                foreach ($u in @($RuleScan.Extra | Where-Object { $_.Bytes -gt 0 })) {
                    $cur = $now[[string]$u.Drive]
                    if ($cur -and ([long]$cur.Bytes -gt [long]$u.Bytes -or [int]$cur.Items -gt [int]$u.Items)) {
                        Add-IgwtCleanerSkip -Result $sum -Reason 'the Recycle Bin changed since the scan; scan again' -Path "$($u.Drive):\"
                        continue
                    }
                    Clear-RecycleBin -DriveLetter $u.Drive -Force -ErrorAction Stop
                    $sum.DeletedBytes += $u.Bytes; $sum.DeletedCount += $u.Items
                }
            }
            'deliveryOptimization' {
                Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
                $sum.DeletedBytes = [long]$RuleScan.Bytes
            }
            'dism' {
                if ($Rule.resetBase) { $null = Repair-WindowsImage -Online -StartComponentCleanup -ResetBase -NoRestart -ErrorAction Stop }
                else { $null = Repair-WindowsImage -Online -StartComponentCleanup -NoRestart -ErrorAction Stop }
                $sum.DeletedBytes = [long]$RuleScan.Bytes
            }
            'driverStore' {
                $current = @(Get-IgwtDriverStoreCandidates | ForEach-Object { $_.Inf })
                foreach ($c in @($RuleScan.Extra)) {
                    if ($current -notcontains $c.Inf) { Add-IgwtCleanerSkip -Result $sum -Reason 'no longer a safe candidate (in use or newest)' -Path $c.Inf; continue }
                    $r = Invoke-IgwtPnpUtilDelete -Inf $c.Inf
                    if ($r -eq 0) { $sum.DeletedBytes += $c.Bytes; $sum.DeletedCount++ } else { Add-IgwtCleanerSkip -Result $sum -Reason "pnputil refused (exit $r)" -Path $c.Inf }
                }
            }
        }
    } catch {
        $sum.Status = 'Error'; $sum.Reason = $_.Exception.Message
    } finally {
        Restore-IgwtCleanerService -States $services
    }
    return $sum
}

function Invoke-IgwtPnpUtilDelete {
    <# .SYNOPSIS Deletes one third-party driver package WITHOUT /force (pnputil refuses packages that are in use). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Inf)
    if ($Inf -notmatch '^oem\d+\.inf$') { throw "Refusing unexpected driver package name '$Inf'." }
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: pnputil.exe must be mocked in tests.' }
    if (-not $PSCmdlet.ShouldProcess($Inf, 'pnputil /delete-driver (no /force)')) { return -1 }
    $exe = Join-Path $env:SystemRoot 'System32\pnputil.exe'
    $null = & $exe /delete-driver $Inf 2>&1
    return $LASTEXITCODE
}

function Invoke-IgwtCleanerClean {
    <#
    .SYNOPSIS
        Phase 2: deletes ONLY the items found by a scan (Invoke-IgwtCleanerScan), re-validating each
        file right before deletion. Writes a per-rule summary to the log and every deleted path to
        Logs\Cleaner-<time>.jsonl.
    .PARAMETER Scan
        The scan result (default: the last scan of this session).
    .PARAMETER RuleId
        Clean only these rules from the scan.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Scan, [string[]]$RuleId, $CancelToken)
    if (-not $Scan) { $Scan = $script:IgwtLastCleanerScan }
    if (-not $Scan) { throw 'Run a scan first (Invoke-IgwtCleanerScan); the cleaner only deletes what a scan found.' }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $logDir = Get-IgwtDataPath -Kind Logs
    if (-not (Test-Path -LiteralPath $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force -WhatIf:$false }
    $logFile = Join-Path $logDir ("Cleaner-{0}.jsonl" -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    $writer = New-Object System.IO.StreamWriter($logFile, $false, (New-Object System.Text.UTF8Encoding($false)))
    $oldPriority = [System.Threading.Thread]::CurrentThread.Priority
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::BelowNormal
    $script:IgwtCleanerProtection = $null
    $results = New-Object System.Collections.Generic.List[object]
    try {
        # Recycle Bin rules first: files that another rule (Downloads) moves to the bin in the same
        # run must never be purged a moment later.
        $todo = @(@($Scan.Rules | Where-Object { (-not $RuleId -or $RuleId -contains $_.RuleId) -and [string]$_.Method -eq 'recycleBin' }) +
            @($Scan.Rules | Where-Object { (-not $RuleId -or $RuleId -contains $_.RuleId) -and [string]$_.Method -ne 'recycleBin' }))
        $n = 0
        foreach ($rs in $todo) {
            $n++
            if ($CancelToken -and $CancelToken.IsCancellationRequested) { break }
            $rule = Get-IgwtCleanerRule -Id $rs.RuleId
            Send-IgwtProgress -Text "Cleaning: $($rule.name)" -Percent ([int](100 * ($n - 1) / [Math]::Max(1, $todo.Count)))
            $r = Invoke-IgwtCleanerRuleClean -Rule $rule -RuleScan $rs -Writer $writer -CancelToken $CancelToken -AllUsers:([bool]$Scan.AllUsers)
            $results.Add($r)
            $skippedTotal = [int](($r.Skipped.Values | Measure-Object -Sum).Sum)
            Write-IgwtLog -Message ("Cleaner {0}: {1} - {2:N1} MB in {3} file(s), {4} skipped. {5}" -f $r.RuleId, $r.Status, ($r.DeletedBytes / 1MB), $r.DeletedCount, $skippedTotal, $r.Reason)
        }
    } finally {
        $writer.Dispose()
        [System.Threading.Thread]::CurrentThread.Priority = $oldPriority
        try { Invoke-IgwtCleanerLogRotation -Folder $logDir } catch { Write-Verbose 'Log rotation failed.' }
    }
    Send-IgwtProgress -Text 'Clean finished' -Percent 100
    $total = [long](($results | Measure-Object DeletedBytes -Sum).Sum)
    Write-IgwtLog -Message ("Cleaner finished: {0:N1} MB freed. Deleted-path log: {1}" -f ($total / 1MB), $logFile)
    return [pscustomobject]@{ ScanId = $Scan.Id; Rules = $results.ToArray(); FreedBytes = $total; LogFile = $logFile }
}

#endregion
