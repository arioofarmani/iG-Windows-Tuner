# GpoStore.ps1
# The Local Group Policy Object on disk: %SystemRoot%\System32\GroupPolicy (Machine\Registry.pol,
# User\Registry.pol, gpt.ini) and GroupPolicyUsers. gpt.ini version and client-side extension
# lists, backup and restore of the folders, the "reset Local Group Policy" fix and the policy
# refresh. Every write is limited to these folders (tests use temporary copies), is preceded by a
# backup and is followed by a refresh and a verification by the caller.

$script:IgwtRegistryCse = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
$script:IgwtRegistryTool = '{D02B1F72-3407-48AE-BA88-E8213C6761F1}'
$script:IgwtSecurityCse = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
$script:IgwtSecurityTool = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
$script:IgwtAuditCse = '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}'
$script:IgwtAuditTool = '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'

function Get-IgwtGpoRoot {
    <# .SYNOPSIS The Local GPO folder (GroupPolicy) or the per-user folder (GroupPolicyUsers). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([switch]$Users)
    if ($Users) {
        if ($script:IgwtSettings.GpoUsersRoot) { return [string]$script:IgwtSettings.GpoUsersRoot }
        return (Join-Path $env:SystemRoot 'System32\GroupPolicyUsers')
    }
    if ($script:IgwtSettings.GpoRoot) { return [string]$script:IgwtSettings.GpoRoot }
    return (Join-Path $env:SystemRoot 'System32\GroupPolicy')
}

function Get-IgwtLocalPolPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class)
    return (Join-Path (Get-IgwtGpoRoot) "$Class\Registry.pol")
}

function Assert-IgwtGpoPathAllowed {
    <#
    .SYNOPSIS
        Throws unless a path is inside the Local GPO folders. In TestMode the folders must be
        overridden to a temporary location, so the real Group Policy store is never written by tests.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $roots = @((Get-IgwtGpoRoot), (Get-IgwtGpoRoot -Users)) | ForEach-Object { [System.IO.Path]::GetFullPath($_) }
    if ($script:IgwtSettings.TestMode) {
        $sys = [System.IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32'))
        if ($full.StartsWith($sys, [System.StringComparison]::OrdinalIgnoreCase)) { throw "TestMode safety: '$Path' is in the real Group Policy store." }
    }
    foreach ($r in $roots) { if ($full.StartsWith($r.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($full, $r, [System.StringComparison]::OrdinalIgnoreCase)) { return } }
    throw "'$Path' is outside the Local Group Policy folders."
}

#region gpt.ini

function Read-IgwtGptIni {
    <# .SYNOPSIS Parses gpt.ini text into Version (machine and user halves) and the extension-name lists. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $version = 0; $machineExt = ''; $userExt = ''
    foreach ($line in @(([string]$Text) -split "`r?`n")) {
        if ($line -match '^\s*Version\s*=\s*(\d+)\s*$') { $version = [uint32]$Matches[1] }
        elseif ($line -match '^\s*gPCMachineExtensionNames\s*=\s*(.*)$') { $machineExt = $Matches[1].Trim() }
        elseif ($line -match '^\s*gPCUserExtensionNames\s*=\s*(.*)$') { $userExt = $Matches[1].Trim() }
    }
    [pscustomobject]@{ Version = [uint32]$version; MachineVersion = [int]($version -band 0xFFFF); UserVersion = [int](($version -shr 16) -band 0xFFFF); MachineExtensions = $machineExt; UserExtensions = $userExt }
}

function Add-IgwtCseToList {
    <#
    .SYNOPSIS
        Adds a [{CSE}{tool}] pair to a gPC*ExtensionNames value, keeping the list sorted by CSE GUID
        (as the Group Policy editor writes it) and merging tools of the same CSE.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$List, [Parameter(Mandatory = $true)][string]$Cse, [Parameter(Mandatory = $true)][string]$Tool)
    $map = [ordered]@{}
    foreach ($m in [regex]::Matches([string]$List, '\[([^\]]*)\]')) {
        $guids = @([regex]::Matches($m.Groups[1].Value, '\{[0-9A-Fa-f\-]{36}\}') | ForEach-Object { $_.Value.ToUpperInvariant() })
        if ($guids.Count -eq 0) { continue }
        $map[$guids[0]] = New-Object System.Collections.Generic.List[string]
        foreach ($g in @($guids | Select-Object -Skip 1)) { $map[$guids[0]].Add($g) }
    }
    $c = $Cse.ToUpperInvariant(); $t = $Tool.ToUpperInvariant()
    if (-not $map.Contains($c)) { $map[$c] = New-Object System.Collections.Generic.List[string] }
    if (-not $map[$c].Contains($t)) { $map[$c].Add($t) }
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in @($map.Keys | Sort-Object)) { $null = $sb.Append('[').Append($k).Append((@($map[$k] | Sort-Object) -join '')).Append(']') }
    return $sb.ToString()
}

function Update-IgwtGptIniText {
    <#
    .SYNOPSIS
        Returns gpt.ini text with the machine or user version incremented (the high 16 bits are the
        user version, the low 16 bits the machine version) and the given client-side extension
        registered in the matching extension-name list. Other lines are kept. Pure.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure function over text.')]
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text, [Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class, [string]$Cse = $script:IgwtRegistryCse, [string]$Tool = $script:IgwtRegistryTool)
    $g = Read-IgwtGptIni -Text $Text
    $mv = $g.MachineVersion; $uv = $g.UserVersion
    if ($Class -eq 'Machine') { $mv = ($mv + 1) -band 0xFFFF } else { $uv = ($uv + 1) -band 0xFFFF }
    $ver = ([uint32]$uv -shl 16) -bor [uint32]$mv
    $extName = $(if ($Class -eq 'Machine') { 'gPCMachineExtensionNames' } else { 'gPCUserExtensionNames' })
    $ext = Add-IgwtCseToList -List $(if ($Class -eq 'Machine') { $g.MachineExtensions } else { $g.UserExtensions }) -Cse $Cse -Tool $Tool
    $lines = New-Object System.Collections.Generic.List[string]
    $seenGeneral = $false; $wroteVer = $false; $wroteExt = $false
    foreach ($line in @(([string]$Text) -split "`r?`n")) {
        if ($line -match '^\s*\[General\]\s*$') { $seenGeneral = $true; $lines.Add('[General]'); continue }
        if ($line -match '^\s*Version\s*=') { $lines.Add("Version=$ver"); $wroteVer = $true; continue }
        if ($line -match "^\s*$extName\s*=") { $lines.Add("$extName=$ext"); $wroteExt = $true; continue }
        if ($line -ne '' -or $lines.Count) { $lines.Add($line) }
    }
    while ($lines.Count -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
    if (-not $seenGeneral) { $lines.Insert(0, '[General]') }
    $gi = $lines.IndexOf('[General]')
    if (-not $wroteExt) { $lines.Insert($gi + 1, "$extName=$ext") }
    if (-not $wroteVer) { $lines.Add("Version=$ver") }
    return (($lines -join "`r`n") + "`r`n")
}

#endregion

#region Backup, restore, reset

function Backup-IgwtLocalGpo {
    <#
    .SYNOPSIS
        Copies the Local GPO folders (GroupPolicy and GroupPolicyUsers) to a backup folder in the
        data root, with a manifest of every file's SHA256. Returns the backup folder.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Reason = 'before a Group Policy change')
    $dest = Join-Path (Get-IgwtDataPath -Kind Backups) ("gpo-{0}" -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    if (-not $PSCmdlet.ShouldProcess($dest, 'Back up the Local Group Policy')) { return $null }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $null = New-Item -ItemType Directory -Path $dest -Force
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($pair in @(@('GroupPolicy', (Get-IgwtGpoRoot)), @('GroupPolicyUsers', (Get-IgwtGpoRoot -Users)))) {
        $src = $pair[1]
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $target = Join-Path $dest $pair[0]
        foreach ($f in @(Get-ChildItem -LiteralPath $src -Recurse -File -Force -ErrorAction Stop)) {
            $rel = $f.FullName.Substring($src.TrimEnd('\').Length + 1)
            $to = Join-Path $target $rel
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force
            Copy-Item -LiteralPath $f.FullName -Destination $to -Force
            $files.Add([ordered]@{ folder = $pair[0]; path = $rel; size = $f.Length; sha256 = (Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash })
        }
    }
    $manifest = [ordered]@{ kind = 'igwt-gpo-backup'; created = (Get-Date).ToString('o'); reason = $Reason; computer = $env:COMPUTERNAME; files = $files.ToArray() }
    [System.IO.File]::WriteAllText((Join-Path $dest 'manifest.json'), (ConvertTo-IgwtJson -InputObject $manifest), (New-Object System.Text.UTF8Encoding($false)))
    Write-IgwtLog -Message "Local Group Policy backed up ($($files.Count) file(s)) to $dest"
    return $dest
}

function Restore-IgwtLocalGpo {
    <#
    .SYNOPSIS
        Restores the Local GPO folders from a backup: the backup's files are checked against the
        manifest, the current folders are replaced, and the policy is refreshed (unless -NoRefresh).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$BackupPath, [switch]$NoRefresh)
    $mf = Join-Path $BackupPath 'manifest.json'
    if (-not (Test-Path -LiteralPath $mf)) { throw "'$BackupPath' is not a Group Policy backup (manifest.json missing)." }
    $m = Read-IgwtJsonFile -Path $mf
    if ([string]$m.kind -ne 'igwt-gpo-backup') { throw "'$BackupPath' is not an iG Windows Tuner Group Policy backup." }
    foreach ($f in @($m.files)) {
        $p = Join-Path (Join-Path $BackupPath ([string]$f.folder)) ([string]$f.path)
        if (-not (Test-Path -LiteralPath $p) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne [string]$f.sha256) { throw "Backup file $($f.folder)\$($f.path) is missing or was changed; nothing was restored." }
    }
    if (-not $PSCmdlet.ShouldProcess('Local Group Policy', "Restore from $BackupPath")) { return $null }
    foreach ($pair in @(@('GroupPolicy', (Get-IgwtGpoRoot)), @('GroupPolicyUsers', (Get-IgwtGpoRoot -Users)))) {
        $root = $pair[1]
        Assert-IgwtGpoPathAllowed -Path $root
        if (Test-Path -LiteralPath $root) { Get-ChildItem -LiteralPath $root -Force | Remove-Item -Recurse -Force }
        foreach ($f in @($m.files | Where-Object { [string]$_.folder -eq $pair[0] })) {
            $to = Join-Path $root ([string]$f.path)
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force
            Copy-Item -LiteralPath (Join-Path (Join-Path $BackupPath $pair[0]) ([string]$f.path)) -Destination $to -Force
        }
    }
    Write-IgwtLog -Message "Local Group Policy restored from $BackupPath"
    if (-not $NoRefresh) { Invoke-IgwtGpUpdate -Target Both }
    return [pscustomobject]@{ Restored = $BackupPath; Files = @($m.files).Count }
}

function Get-IgwtLocalGpoResetPlan {
    <# .SYNOPSIS Preview of "Reset Local Group Policy to default": the files that would be removed. Read-only. #>
    [CmdletBinding()]
    param()
    $files = @()
    foreach ($r in @((Get-IgwtGpoRoot), (Get-IgwtGpoRoot -Users))) {
        if (Test-Path -LiteralPath $r) { $files += @(Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
    }
    [pscustomobject]@{
        Files = $files
        Steps = @('Back up both Local Group Policy folders to the data root', 'Delete the contents of GroupPolicy and GroupPolicyUsers', 'Refresh policy (gpupdate /force)', 'Policies set by a domain or MDM are not affected; values that earlier policies wrote to the registry stay until something sets them again (tattooed values).')
        # No Microsoft article documents this reset (checked 2026-10-22); it is the long-standing
        # community practice, made reversible here by the backup. See docs\DECISIONS.md G4.
        Basis = 'Community practice (no Microsoft article); reversible through the backup.'
    }
}

function Reset-IgwtLocalGpo {
    <# .SYNOPSIS Resets Local Group Policy to its default (no local policies), after a backup; revert with Restore-IgwtLocalGpo. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$NoRefresh)
    if (-not $PSCmdlet.ShouldProcess('Local Group Policy', 'Reset to default (backup first)')) { return $null }
    $backup = Backup-IgwtLocalGpo -Reason 'before a reset of the Local Group Policy'
    foreach ($r in @((Get-IgwtGpoRoot), (Get-IgwtGpoRoot -Users))) {
        Assert-IgwtGpoPathAllowed -Path $r
        if (Test-Path -LiteralPath $r) { Get-ChildItem -LiteralPath $r -Force | Remove-Item -Recurse -Force }
    }
    Write-IgwtLog -Message "Local Group Policy reset to default. Backup: $backup"
    if (-not $NoRefresh) { Invoke-IgwtGpUpdate -Target Both }
    return [pscustomobject]@{ Backup = $backup }
}

function Invoke-IgwtGpUpdate {
    <# .SYNOPSIS Targeted policy refresh (gpupdate /target:computer|user /force). Refuses to run in TestMode (tests mock it). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User', 'Both')][string]$Target)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: gpupdate must be mocked in tests.' }
    $exe = Join-Path $env:SystemRoot 'System32\gpupdate.exe'
    $targets = $(if ($Target -eq 'Both') { @('Computer', 'User') } elseif ($Target -eq 'Machine') { @('Computer') } else { @('User') })
    foreach ($t in $targets) {
        if (-not $PSCmdlet.ShouldProcess("gpupdate /target:$t /force", 'Run')) { continue }
        $out = & $exe "/target:$t" '/force' 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "gpupdate /target:$t failed (exit $LASTEXITCODE): $($out.Trim())" }
    }
}

#endregion
