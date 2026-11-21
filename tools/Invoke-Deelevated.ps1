<#
.SYNOPSIS
    Runs a PowerShell command without administrator rights from an elevated session (development tool).
.DESCRIPTION
    The Pester suite refuses to run elevated (tests must never reach the real system). When the
    development session runs as administrator, this starts the command with a basic-user token
    (runas /trustlevel:0x20000), waits until it finishes, and returns its output and exit code.
    The command's output goes to -LogPath. Nothing here changes the system.
.PARAMETER Command
    The PowerShell command text to run (in the project folder).
.PARAMETER LogPath
    Where the output is written (default: a file in %TEMP%).
.PARAMETER TimeoutSec
    How long to wait before giving up (default 7200).
.EXAMPLE
    .\tools\Invoke-Deelevated.ps1 -Command "& .\tools\Test-All.ps1 -SkipAutomation" -LogPath $env:TEMP\gate.txt
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Command, [string]$LogPath, [ValidateRange(10, 86400)][int]$TimeoutSec = 7200)
$root = Split-Path -Parent $PSScriptRoot
if (-not $LogPath) { $LogPath = Join-Path $env:TEMP ("igwt-deelevated-{0}.txt" -f (Get-Date).ToString('yyyyMMdd-HHmmss')) }
$tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
$done = Join-Path $env:TEMP "igwt-deelevated-$tag.done"
$script = Join-Path $env:TEMP "igwt-deelevated-$tag.ps1"
$body = @"
Set-Location -LiteralPath '$($root -replace "'", "''")'
`$code = 0
try { & { $Command } *> '$($LogPath -replace "'", "''")'; if (`$LASTEXITCODE) { `$code = `$LASTEXITCODE } } catch { `$_ | Out-File -LiteralPath '$($LogPath -replace "'", "''")' -Append -Encoding utf8; `$code = 1 }
Set-Content -LiteralPath '$($done -replace "'", "''")' -Value `$code -Encoding ascii
"@
Set-Content -LiteralPath $script -Value $body -Encoding utf8
$psExe = Join-Path $PSHOME 'powershell.exe'
& runas.exe /trustlevel:0x20000 "`"$psExe`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path -LiteralPath $done)) {
    if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { Write-Warning "Timed out after $TimeoutSec s; output so far is in $LogPath."; exit 2 }
    Start-Sleep -Seconds 2
}
$exit = [int](Get-Content -LiteralPath $done -Raw).Trim()
Remove-Item -LiteralPath $done, $script -Force -ErrorAction SilentlyContinue
[pscustomobject]@{ ExitCode = $exit; LogPath = $LogPath; Seconds = [int]$sw.Elapsed.TotalSeconds }
