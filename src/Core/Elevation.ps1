# Elevation.ps1
# Admin detection and the standard, visible UAC relaunch. No UAC bypass of any kind.

function Test-IgwtIsAdmin {
    <# .SYNOPSIS Returns $true when the current process runs elevated as an administrator. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-IgwtHostExecutable {
    <# .SYNOPSIS Path of the running PowerShell host (powershell.exe or pwsh.exe). #>
    [CmdletBinding()]
    param()
    $path = (Get-Process -Id $PID).Path
    if (-not $path) {
        if ($PSVersionTable.PSEdition -eq 'Core') { $path = Join-Path $PSHOME 'pwsh.exe' }
        else { $path = Join-Path $PSHOME 'powershell.exe' }
    }
    return $path
}

function ConvertTo-IgwtCommandLineArgument {
    <#
    .SYNOPSIS
        One argument quoted for a Windows command line so the new process reads it back exactly
        (CommandLineToArgvW rules): backslashes before a quote and at the end are doubled, quotes
        are escaped. A path ending in "\" no longer swallows the next argument, and a value with
        quotes cannot add parameters (review 3.8.1 CLI-01). Pure.
    .PARAMETER Value
        The argument.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Value)
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('"')
    $slashes = 0
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq '\') { $slashes++; continue }
        if ($c -eq '"') { $null = $sb.Append('\', 2 * $slashes + 1); $null = $sb.Append('"') }
        else { if ($slashes) { $null = $sb.Append('\', $slashes) }; $null = $sb.Append($c) }
        $slashes = 0
    }
    if ($slashes) { $null = $sb.Append('\', 2 * $slashes) }
    $null = $sb.Append('"')
    return $sb.ToString()
}

function Start-IgwtElevated {
    <#
    .SYNOPSIS
        Relaunches iGWindowsTuner.ps1 elevated through the normal UAC consent prompt
        (Start-Process -Verb RunAs). The window is visible; the execution policy override
        applies to the new process only.
    .PARAMETER ScriptPath
        Full path of iGWindowsTuner.ps1.
    .PARAMETER ArgumentList
        Arguments to pass through unchanged.
    .PARAMETER Wait
        Wait for the elevated process and return its exit code.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$ArgumentList = @(),
        [switch]$Wait
    )
    $exe = Get-IgwtHostExecutable
    $quoted = foreach ($a in $ArgumentList) { ConvertTo-IgwtCommandLineArgument -Value ([string]$a) }
    $allArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $ScriptPath)) + @($quoted)
    if (-not $PSCmdlet.ShouldProcess("$exe $($allArgs -join ' ')", 'Start elevated (UAC prompt)')) { return $null }
    try {
        $proc = Start-Process -FilePath $exe -ArgumentList $allArgs -Verb RunAs -PassThru -ErrorAction Stop
    } catch {
        Write-IgwtLog -Level Warn -Message "Elevation was cancelled or failed: $($_.Exception.Message)"
        return $null
    }
    if ($Wait) {
        $proc.WaitForExit()
        return $proc.ExitCode
    }
    return $proc
}
