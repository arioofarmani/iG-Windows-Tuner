# PrivateFolder.ps1
# Private backup folders under the data root (DECISIONS RG18): a new folder below Backups that is
# created with a protected ACL (SYSTEM and Administrators: full control; optionally one user: read)
# before any file is written into it, so per-user registry data never becomes readable by other
# local users and a standard user cannot edit a .reg file an administrator may later import. It
# lives in Core because it protects the app's own folders, not files being cleaned.

function New-IgwtPrivateFolderSecurity {
    <#
    .SYNOPSIS
        The DirectorySecurity of a private backup folder: inheritance from the parent removed,
        SYSTEM and Administrators full control, and the given user read and execute, all inherited
        by subfolders and files. Builds an object only. Pure.
    .PARAMETER UserSid
        The user SID that may read the folder, or empty.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory security object only.')]
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$UserSid = '')
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($s in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($s)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', $inherit, $prop, $allow)))
    }
    if ($UserSid) {
        $id = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'ReadAndExecute', $inherit, $prop, $allow)))
    }
    return $acl
}

function New-IgwtDirectoryWithSecurity {
    <#
    .SYNOPSIS
        Creates one folder with its security descriptor in the same call
        (Directory.CreateDirectory(String, DirectorySecurity)), so no file can be written into it
        under the inherited ACL first. A separate function so tests can make it fail.
    .PARAMETER Path
        The new folder.
    .PARAMETER Security
        The DirectorySecurity to apply.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][System.Security.AccessControl.DirectorySecurity]$Security)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create private folder')) { return }
    $null = [System.IO.Directory]::CreateDirectory($Path, $Security)
}

function Get-IgwtDirectorySecurity {
    <#
    .SYNOPSIS
        The access rules of a folder (Directory.GetAccessControl). Read-only; a separate function
        so tests can return a wrong ACL.
    .PARAMETER Path
        The folder.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Directory]::GetAccessControl($Path, [System.Security.AccessControl.AccessControlSections]::Access)
}

function Test-IgwtPrivateFolderSecurity {
    <#
    .SYNOPSIS
        True when a folder's ACL is exactly the private one: protected (nothing inherited), every
        rule Allow, and the set of SIDs SYSTEM, Administrators and the given user (read only). Pure.
    .PARAMETER Security
        The folder's DirectorySecurity.
    .PARAMETER UserSid
        The user SID that may read the folder, or empty.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Security, [AllowEmptyString()][AllowNull()][string]$UserSid = '')
    if (-not $Security.AreAccessRulesProtected) { return $false }
    $expected = @('S-1-5-18', 'S-1-5-32-544') + @($(if ($UserSid) { $UserSid }))
    $seen = @{}
    # WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes,
    # Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE.
    [long]$writeBits = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    foreach ($r in $Security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($r.IsInherited) { return $false }
        if ($r.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
        $sid = [string]$r.IdentityReference.Value
        if ($expected -notcontains $sid) { return $false }
        if ($UserSid -and $sid -eq $UserSid -and (([long][int]$r.FileSystemRights) -band $writeBits) -ne 0) { return $false }
        $seen[$sid] = $true
    }
    foreach ($s in $expected) { if (-not $seen.ContainsKey($s)) { return $false } }
    return $true
}

function New-IgwtPrivateBackupFolder {
    <#
    .SYNOPSIS
        Creates a new private backup folder under the data root's Backups folder (RG18) and returns
        its full path. Throws ("Backup failed: ...") when the path is not a new folder directly under
        Backups, the ACL cannot be applied, or the ACL read back is not the private one; nothing is
        written into the folder in that case and an empty folder that was created is removed.
    .PARAMETER Path
        The new folder (for example <Backups>\regclean-<yyyyMMdd-HHmmss>-<6hex>).
    .PARAMETER UserSid
        The user SID that may read the folder (the plan holds that user's HKCU entries), or empty.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path, [AllowEmptyString()][AllowNull()][string]$UserSid = '')
    Assert-IgwtWritable -Operation 'New-IgwtPrivateBackupFolder'
    if ($UserSid -and $UserSid -notmatch '^S-1-[0-9-]+$') { throw "Backup failed: '$UserSid' is not a user SID." }
    $backups = [System.IO.Path]::GetFullPath((Get-IgwtDataPath -Kind Backups)).TrimEnd('\')
    if ($Path -notmatch '^[A-Za-z]:\\') { throw "Backup failed: '$Path' is not an absolute local path." }
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not (Test-IgwtPathUnder -Path $full -Parent $backups -Strict) -or -not [string]::Equals((Split-Path -Parent $full), $backups, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Backup failed: '$Path' is not a folder directly under $backups."
    }
    if (-not [System.IO.Directory]::Exists($backups)) { throw "Backup failed: the Backups folder $backups does not exist." }
    if ([System.IO.Directory]::Exists($full) -or [System.IO.File]::Exists($full)) { throw "Backup failed: $full already exists." }
    if (-not $PSCmdlet.ShouldProcess($full, 'Create private backup folder')) { return $null }
    $security = New-IgwtPrivateFolderSecurity -UserSid $UserSid
    try {
        New-IgwtDirectoryWithSecurity -Path $full -Security $security -Confirm:$false
    } catch {
        throw "Backup failed: the private folder could not be created ($($_.Exception.Message)); nothing changed."
    }
    $ok = $false
    $why = 'its permissions are not the private ones'
    try { $ok = Test-IgwtPrivateFolderSecurity -Security (Get-IgwtDirectorySecurity -Path $full) -UserSid $UserSid } catch { $why = "its permissions cannot be read ($($_.Exception.Message))" }
    if (-not $ok) {
        # The folder is still empty: remove it (not recursive) so no unprotected folder stays behind.
        try { if ([System.IO.Directory]::Exists($full)) { [System.IO.Directory]::Delete($full) } } catch { Write-Verbose "Could not remove ${full}: $($_.Exception.Message)" }
        throw "Backup failed: the folder $full was not used because $why; nothing changed."
    }
    return $full
}
