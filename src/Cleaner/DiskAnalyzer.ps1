# DiskAnalyzer.ps1
# Read-only disk usage analyzer: largest folders and largest files under a path. Reparse points are
# never followed (so OneDrive placeholders, junctions and mount points are not double-counted or
# hydrated). Nothing is modified.

function Get-IgwtDiskUsage {
    <#
    .SYNOPSIS
        Largest folders (up to -FolderDepth below Path) and largest files under Path. Read-only.
    .PARAMETER Path
        Folder or drive to analyze (default: the system drive).
    .PARAMETER Top
        Number of folders and files to return.
    .PARAMETER FolderDepth
        Folders deeper than this (relative to Path) are aggregated into their ancestors.
    #>
    [CmdletBinding()]
    param([string]$Path = "$env:SystemDrive\", [int]$Top = 25, [int]$FolderDepth = 3, $CancelToken)
    $root = ConvertTo-IgwtCanonicalPath -Path $Path
    if ($root.Length -eq 2) { $root += '\' }
    $rootInfo = New-Object System.IO.DirectoryInfo($root)
    if (-not $rootInfo.Exists) { throw "Folder not found: $root" }
    $rootDepth = @($rootInfo.FullName.TrimEnd('\').Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)).Count
    $folderBytes = New-Object 'System.Collections.Generic.Dictionary[string,long]' ([System.StringComparer]::OrdinalIgnoreCase)
    $folderFiles = New-Object 'System.Collections.Generic.Dictionary[string,long]' ([System.StringComparer]::OrdinalIgnoreCase)
    $topFiles = New-Object System.Collections.Generic.List[object]
    $minTop = 0L
    $files = 0L; $total = 0L; $denied = 0; $reparse = 0; $dirs = 0
    $oldPriority = [System.Threading.Thread]::CurrentThread.Priority
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::BelowNormal
    try {
        $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
        $stack.Push($rootInfo)
        while ($stack.Count -gt 0) {
            if ($CancelToken -and $CancelToken.IsCancellationRequested) { break }
            $dir = $stack.Pop()
            $dirs++
            if ($dirs % 500 -eq 0) { Send-IgwtProgress -Text ("Analyzing {0}: {1:N0} file(s), {2} so far (read-only)..." -f $root, $files, (Format-IgwtBytes $total)) -Percent -1 }
            $entries = @()
            try { $entries = @($dir.EnumerateFileSystemInfos()) } catch { $denied++; continue }
            # The folder this directory's sizes are credited to (capped at FolderDepth below the root).
            $segs = @($dir.FullName.TrimEnd('\').Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries))
            $keep = [Math]::Min($segs.Count, $rootDepth + $FolderDepth)
            foreach ($e in $entries) {
                if ((([long]$e.Attributes) -band 0x400) -ne 0) { $reparse++; continue }
                if ($e -is [System.IO.DirectoryInfo]) { $stack.Push($e); continue }
                $len = [long]$e.Length
                $files++; $total += $len
                # Credit every ancestor from the root down to the capped depth.
                for ($d = $rootDepth + 1; $d -le $keep; $d++) {
                    $key = ($segs[0..($d - 1)] -join '\')
                    if ($key.Length -eq 2) { $key += '\' }
                    if ($folderBytes.ContainsKey($key)) { $folderBytes[$key] += $len; $folderFiles[$key]++ } else { $folderBytes[$key] = $len; $folderFiles[$key] = 1 }
                }
                if ($topFiles.Count -lt $Top -or $len -gt $minTop) {
                    $topFiles.Add([pscustomobject]@{ Path = $e.FullName; Bytes = $len; LastWrite = $e.LastWriteTime })
                    if ($topFiles.Count -gt $Top * 4) {
                        $trim = @($topFiles | Sort-Object Bytes -Descending | Select-Object -First $Top)
                        $topFiles.Clear(); foreach ($t in $trim) { $topFiles.Add($t) }
                        $minTop = $trim[-1].Bytes
                    }
                }
            }
        }
    } finally {
        [System.Threading.Thread]::CurrentThread.Priority = $oldPriority
    }
    $folders = foreach ($k in $folderBytes.Keys) {
        $depth = @($k.TrimEnd('\').Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)).Count - $rootDepth
        [pscustomobject]@{ Path = $k; Bytes = $folderBytes[$k]; Files = $folderFiles[$k]; Depth = $depth }
    }
    [pscustomobject]@{
        Root            = $root
        TotalBytes      = $total
        Files           = $files
        Folders         = @($folders | Sort-Object Bytes -Descending | Select-Object -First $Top)
        LargestFiles    = @($topFiles | Sort-Object Bytes -Descending | Select-Object -First $Top)
        AccessDenied    = $denied
        ReparseSkipped  = $reparse
        Cancelled       = [bool]($CancelToken -and $CancelToken.IsCancellationRequested)
    }
}

function Format-IgwtBytes {
    <# .SYNOPSIS Human-readable size (B, KB, MB, GB, TB). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}
