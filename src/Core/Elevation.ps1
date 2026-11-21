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

function Get-IgwtProgramFolderWriters {
    <#
    .SYNOPSIS
        Folders and top-level files of the program that accounts other than SYSTEM, Administrators,
        TrustedInstaller and the current user can change. The elevated process runs every script
        under src, so such a folder lets another account run code as administrator (review CLI-05).
        Checks the program folder, its top-level files and every folder under src and data.
        Read-only.
    .PARAMETER Root
        The program folder (where iGWindowsTuner.ps1 is).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root)
    $allowed = @($script:IgwtTrustedPrincipals) + @([string][System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $items = New-Object System.Collections.Generic.List[string]
    $items.Add($Root)
    foreach ($f in @(Get-ChildItem -LiteralPath $Root -File -ErrorAction SilentlyContinue)) { $items.Add($f.FullName) }
    foreach ($sub in 'src', 'data') {
        $p = Join-Path $Root $sub
        if (Test-Path -LiteralPath $p) { $items.Add($p); foreach ($d in @(Get-ChildItem -LiteralPath $p -Directory -Recurse -ErrorAction SilentlyContinue)) { $items.Add($d.FullName) } }
    }
    foreach ($i in $items) {
        $writers = @()
        try { $writers = @(Get-IgwtAclOtherWriters -Acl (Get-Acl -LiteralPath $i -ErrorAction Stop) -Allowed $allowed) } catch { $writers = @('unreadable') }
        foreach ($w in $writers) {
            $name = $w
            try { if ($w -ne 'unreadable') { $name = (New-Object System.Security.Principal.SecurityIdentifier($w)).Translate([System.Security.Principal.NTAccount]).Value } } catch { $name = $w }
            [pscustomobject]@{ Path = $i; Sid = $w; Account = $name }
        }
    }
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
    $writers = @(Get-IgwtProgramFolderWriters -Root (Split-Path -Parent $ScriptPath))
    if ($writers.Count) {
        $w = $writers[0]
        throw ("Other accounts can change the program files ({0} can change '{1}'). Running them as administrator would let those accounts run code as administrator. Move iG Windows Tuner to a folder only administrators can change, for example C:\Program Files\iGWindowsTuner, then start it again. Nothing was changed." -f $w.Account, $w.Path)
    }
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
