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
    $quoted = foreach ($a in $ArgumentList) {
        if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
    }
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
