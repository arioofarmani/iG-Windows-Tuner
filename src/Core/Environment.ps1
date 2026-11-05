# Environment.ps1
# Module-wide settings: data folders, registry redirection (used only by the test suite)
# and the interactive-user hive mapping used when elevation happens under a different account.

$script:IgwtVersion = '3.6.5'

$script:IgwtSettings = @{
    DataRoot         = (Join-Path $env:ProgramData 'iGWindowsTuner')
    UserLogRoot      = (Join-Path $env:LOCALAPPDATA 'iGWindowsTuner')
    LegacyDataRoot   = (Join-Path $env:ProgramData 'AegisTune')   # data root of pre-release preview builds; its backups stay readable
    RegistryRedirect = $null      # ordered map of path prefix -> replacement prefix (tests only)
    TestMode         = $false     # when true, every registry path must resolve into TestRegistry:
    UserHiveSid      = $null      # when set, HKCU:\ resolves to HKEY_USERS\<sid>\
    DataFolder       = $null      # catalog data folder override (tests and the migration tool); default <project>\data
    ReadOnly         = $false     # when true, every apply, revert, clean, install, delete and change path throws
}
# Read-only mode is inherited through the process environment, so the GUI's background runspaces
# and any relaunched process (elevation) stay read-only too; a module import cannot turn it off.
if ($env:IGWT_READONLY -eq '1') { $script:IgwtSettings.ReadOnly = $true }

function Set-IgwtEnvironment {
    <#
    .SYNOPSIS
        Overrides module settings. Used by the test suite and by the elevation logic.
    .PARAMETER DataRoot
        Folder for backups, logs and state (default %ProgramData%\iGWindowsTuner).
    .PARAMETER LegacyDataRoot
        With -DataRoot: data root used by pre-release preview builds (default
        %ProgramData%\AegisTune; empty when -DataRoot is given without it). Its backups stay
        listed and revertable; nothing is written there.
    .PARAMETER RegistryRedirect
        Ordered hashtable of path prefix to replacement prefix, e.g. @{ 'HKLM:\' = 'TestRegistry:\HKLM\' }.
    .PARAMETER TestMode
        Refuse any registry path that does not resolve into the Pester TestRegistry: drive and
        refuse to run external executables that have not been mocked.
    .PARAMETER UserHiveSid
        Resolve HKCU:\ to HKEY_USERS\<sid>\ (interactive user while running elevated as another admin).
    .PARAMETER DataFolder
        Read the catalog (tweaks, presets, cleaner rules, hardware tags) from this folder instead of
        the project's data folder. An empty string restores the default.
    .PARAMETER ReadOnly
        Read-only mode (-ReadOnly, for audits and the GUI test harness): every apply, revert, clean,
        install, delete and change path throws. Also sets IGWT_READONLY=1 for this process, so
        background runspaces and relaunched processes stay read-only. -ReadOnly:$false turns it off
        (tests only; the CLI and GUI never do).
    .PARAMETER Reset
        Restore all defaults (read-only mode is kept when the process environment requests it).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$DataRoot,
        [string]$LegacyDataRoot,
        [System.Collections.IDictionary]$RegistryRedirect,
        [switch]$TestMode,
        [string]$UserHiveSid,
        [AllowEmptyString()][string]$DataFolder,
        [switch]$ReadOnly,
        [switch]$Reset
    )
    if (-not $PSCmdlet.ShouldProcess('iG Windows Tuner module settings', 'Update')) { return }
    if ($Reset) {
        $script:IgwtSettings.DataRoot = (Join-Path $env:ProgramData 'iGWindowsTuner')
        $script:IgwtSettings.UserLogRoot = (Join-Path $env:LOCALAPPDATA 'iGWindowsTuner')
        $script:IgwtSettings.LegacyDataRoot = (Join-Path $env:ProgramData 'AegisTune')
        $script:IgwtSettings.RegistryRedirect = $null
        $script:IgwtSettings.TestMode = $false
        $script:IgwtSettings.UserHiveSid = $null
        $script:IgwtSettings.DataFolder = $null
        $script:IgwtSettings.ReadOnly = ($env:IGWT_READONLY -eq '1')
        Clear-IgwtCatalogCaches
        return
    }
    if ($PSBoundParameters.ContainsKey('ReadOnly')) {
        $script:IgwtSettings.ReadOnly = [bool]$ReadOnly
        if ($ReadOnly) { $env:IGWT_READONLY = '1' } else { Remove-Item -Path 'Env:\IGWT_READONLY' -ErrorAction SilentlyContinue }
    }
    if ($PSBoundParameters.ContainsKey('DataFolder')) {
        if ($DataFolder) { $script:IgwtSettings.DataFolder = $DataFolder } else { $script:IgwtSettings.DataFolder = $null }
        Clear-IgwtCatalogCaches
    }
    if ($PSBoundParameters.ContainsKey('DataRoot')) {
        $script:IgwtSettings.DataRoot = $DataRoot
        $script:IgwtSettings.UserLogRoot = $DataRoot
        $script:IgwtSettings.LegacyDataRoot = $LegacyDataRoot
    }
    if ($PSBoundParameters.ContainsKey('RegistryRedirect')) { $script:IgwtSettings.RegistryRedirect = $RegistryRedirect }
    if ($PSBoundParameters.ContainsKey('TestMode')) { $script:IgwtSettings.TestMode = [bool]$TestMode }
    if ($PSBoundParameters.ContainsKey('UserHiveSid')) { $script:IgwtSettings.UserHiveSid = $UserHiveSid }
}

function Test-IgwtReadOnly {
    <# .SYNOPSIS True in read-only mode (-ReadOnly): nothing on the PC may be changed. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return [bool]$script:IgwtSettings.ReadOnly
}

function Assert-IgwtWritable {
    <#
    .SYNOPSIS
        Throws in read-only mode. The first statement of every function that changes the PC (apply,
        revert, clean, install, delete, change), so read-only mode is enforced by the engine and not
        only by the user interface.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Operation)
    if ($script:IgwtSettings.ReadOnly) {
        throw (New-Object System.InvalidOperationException("Read-only mode: $Operation is disabled. Start iG Windows Tuner without -ReadOnly to change this PC."))
    }
}

function Clear-IgwtCatalogCaches {
    <# .SYNOPSIS Drops the cached catalog, cleaner rules and hardware tags (reloaded on next use). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not $PSCmdlet.ShouldProcess('catalog caches', 'Clear')) { return }
    $script:IgwtCatalogCache = $null
    $script:IgwtCleanerRuleCache = $null
    $script:IgwtHardwareTagCache = $null
    $script:IgwtDetectionCache = $null
    $script:IgwtOverlayCache = $null
    $script:IgwtAsrCatalogCache = $null
    $script:IgwtPowerSettingCache = $null
    $script:IgwtKernelInspectorCache = $null
    $script:IgwtServiceRuleCache = $null
    $script:IgwtNicKeywordCache = $null
}

function Get-IgwtEnvironment {
    <# .SYNOPSIS Returns a copy of the current module settings. #>
    [CmdletBinding()]
    param()
    [pscustomobject]@{
        Version          = $script:IgwtVersion
        DataRoot         = $script:IgwtSettings.DataRoot
        UserLogRoot      = $script:IgwtSettings.UserLogRoot
        TestMode         = $script:IgwtSettings.TestMode
        UserHiveSid      = $script:IgwtSettings.UserHiveSid
        RegistryRedirect = $script:IgwtSettings.RegistryRedirect
        ProjectRoot      = $script:IgwtProjectRoot
    }
}

function Get-IgwtDataPath {
    <#
    .SYNOPSIS
        Returns a data folder path. Backups and state always live under the admin-only data root.
        Logs fall back to %LOCALAPPDATA%\iGWindowsTuner\Logs when not elevated (read-only runs).
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Root', 'Backups', 'Logs', 'State', 'Reports', 'Presets', 'LegacyBackups', 'LegacyState')]
        [string]$Kind = 'Root'
    )
    $root = $script:IgwtSettings.DataRoot
    $legacy = [string]$script:IgwtSettings.LegacyDataRoot
    switch ($Kind) {
        'LegacyBackups' { if ($legacy) { return (Join-Path $legacy 'Backups') }; return $null }
        'LegacyState' { if ($legacy) { return (Join-Path $legacy 'State') }; return $null }
        'Root'    { return $root }
        'Backups' { return (Join-Path $root 'Backups') }
        'State'   { return (Join-Path $root 'State') }
        'Presets' { return (Join-Path $root 'Presets') }
        'Logs' {
            if ((Test-IgwtIsAdmin) -or $script:IgwtSettings.TestMode) { return (Join-Path $root 'Logs') }
            return (Join-Path $script:IgwtSettings.UserLogRoot 'Logs')
        }
        'Reports' {
            if ((Test-IgwtIsAdmin) -or $script:IgwtSettings.TestMode) { return (Join-Path $root 'Reports') }
            return (Join-Path $script:IgwtSettings.UserLogRoot 'Reports')
        }
    }
}

function Initialize-IgwtDataRoot {
    <#
    .SYNOPSIS
        Creates the data folders. When elevated, the root gets a protected ACL
        (SYSTEM and Administrators: full control, Users: read) so that a standard user
        cannot plant or edit snapshot files that an elevated revert would later trust.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Assert-IgwtWritable -Operation 'Initialize-IgwtDataRoot'
    $isAdmin = Test-IgwtIsAdmin
    $root = $script:IgwtSettings.DataRoot
    if ($isAdmin -or $script:IgwtSettings.TestMode) {
        foreach ($kind in 'Root', 'Backups', 'Logs', 'State', 'Reports', 'Presets') {
            $p = Get-IgwtDataPath -Kind $kind
            if (-not (Test-Path -LiteralPath $p)) {
                if ($PSCmdlet.ShouldProcess($p, 'Create folder')) { $null = New-Item -ItemType Directory -Path $p -Force }
            }
        }
        if ($isAdmin -and -not $script:IgwtSettings.TestMode) { Protect-IgwtDataRoot -Path $root }
    } else {
        foreach ($kind in 'Logs', 'Reports') {
            $p = Get-IgwtDataPath -Kind $kind
            if (-not (Test-Path -LiteralPath $p)) {
                if ($PSCmdlet.ShouldProcess($p, 'Create folder')) { $null = New-Item -ItemType Directory -Path $p -Force }
            }
        }
    }
}

function Protect-IgwtDataRoot {
    <# .SYNOPSIS Applies the protected ACL to the iG Windows Tuner data root (elevated only). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Set protected ACL (SYSTEM/Administrators full, Users read)')) { return }
    try {
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $prop, $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, 'FullControl', $inherit, $prop, $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', $inherit, $prop, $allow)))
        try { $acl.SetOwner($admins) } catch { Write-Verbose "Could not set owner on ${Path}: $($_.Exception.Message)" }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    } catch {
        Write-Warning "Could not protect ${Path}: $($_.Exception.Message)"
    }
}

function Test-IgwtSecurityDescriptorTrusted {
    <#
    .SYNOPSIS
        True when a file or folder security descriptor is owned by SYSTEM, Administrators,
        TrustedInstaller or the current user and gives low-privilege groups no write access. Reading
        is fine: only the exact write bits count (the composite Modify and FullControl also contain
        read bits, so a mask built from them takes "Users: read" for write access). Works on SIDs,
        so it does not depend on the Windows language. Pure.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$Acl)
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $owner = $Acl.GetOwner($sidType)
    if ($null -eq $owner) { return $false }
    $trustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($trustedOwners -notcontains $owner.Value) { return $false }
    # Everyone, Authenticated Users, Users, Interactive, Guests.
    $lowPriv = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-32-546')
    # WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes, Delete,
    # ChangePermissions, TakeOwnership, and the generic GENERIC_ALL and GENERIC_WRITE.
    [long]$writeBits = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    foreach ($rule in $Acl.GetAccessRules($true, $true, $sidType)) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($lowPriv -contains $rule.IdentityReference.Value -and (([long][int]$rule.FileSystemRights) -band $writeBits) -ne 0) { return $false }
    }
    return $true
}

function Test-IgwtTrustedFile {
    <#
    .SYNOPSIS
        Returns $true when a file or folder is owned by SYSTEM, Administrators, TrustedInstaller or
        the current (elevated) user and grants no write access to low-privilege groups. Snapshots
        and journal files that fail this check are not used.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($script:IgwtSettings.TestMode) { return $true }
    try { return (Test-IgwtSecurityDescriptorTrusted -Acl (Get-Acl -LiteralPath $Path -ErrorAction Stop)) }
    catch { return $false }
}
function Get-IgwtInteractiveUserSid {
    <#
    .SYNOPSIS
        Returns the SID of the user who owns explorer.exe in the current session, or $null.
        Used to detect over-the-shoulder elevation (UAC credentials of a different admin),
        in which case HKCU tweaks are redirected to the interactive user's hive.
    #>
    [CmdletBinding()]
    param()
    try {
        $sessionId = (Get-Process -Id $PID).SessionId
        $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop |
            Where-Object { $_.SessionId -eq $sessionId } | Select-Object -First 1
        if (-not $explorer) { return $null }
        $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwnerSid -ErrorAction Stop
        return $owner.Sid
    } catch {
        return $null
    }
}

function Initialize-IgwtUserHive {
    <#
    .SYNOPSIS
        When elevated as a different account than the signed-in user, map HKCU:\ to the
        signed-in user's hive so per-user tweaks land where the gamer actually logs on.
    #>
    [CmdletBinding()]
    param()
    if ($script:IgwtSettings.TestMode) { return }
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $interactive = Get-IgwtInteractiveUserSid
    if ($interactive -and ($interactive -ne $current)) {
        if (Test-Path -LiteralPath "Registry::HKEY_USERS\$interactive") {
            $script:IgwtSettings.UserHiveSid = $interactive
            Write-IgwtLog -Level Warn -Message "Elevated as a different account; per-user (HKCU) settings will target the signed-in user $interactive."
        }
    }
}
