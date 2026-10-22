# Exclusions.ps1
# Defender exclusions audit: lists every antivirus exclusion (path, process, extension, IP address),
# ASR-only exclusions and Controlled folder access allowed apps, from Defender's own preference
# and from policy, and flags risky ones (whole drives, user-writable and temp folders, script
# hosts, risky extensions, wildcard abuse, broad IP ranges): unexpected exclusions are a classic
# malware persistence trick. This is the only file that names exclusion settings. Exclusions are
# only ever REMOVED here, after confirmation; adding one is manual only (Windows Security).

$script:IgwtExclusionRiskData = $null
$script:IgwtExclusionKinds = [ordered]@{
    Path      = @{ Pref = 'ExclusionPath'; PolicyKey = 'Paths'; Remove = 'ExclusionPath' }
    Process   = @{ Pref = 'ExclusionProcess'; PolicyKey = 'Processes'; Remove = 'ExclusionProcess' }
    Extension = @{ Pref = 'ExclusionExtension'; PolicyKey = 'Extensions'; Remove = 'ExclusionExtension' }
    IpAddress = @{ Pref = 'ExclusionIpAddress'; PolicyKey = 'IpAddresses'; Remove = 'ExclusionIpAddress' }
}

function Test-IgwtExclusionRisk {
    <#
    .SYNOPSIS
        Risk findings for one exclusion: Severity (High, Medium, Low) and reasons. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Path', 'Process', 'Extension', 'IpAddress', 'AsrOnly', 'CfaApp')][string]$Kind, [Parameter(Mandatory = $true)][string]$Value)
    $v = [Environment]::ExpandEnvironmentVariables($Value.Trim())
    $reasons = New-Object System.Collections.Generic.List[string]
    $high = $false
    if (-not $script:IgwtExclusionRiskData) { $script:IgwtExclusionRiskData = Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'defender\exclusion-risk.json') }
    $scriptHosts = @($script:IgwtExclusionRiskData.scriptHosts | ForEach-Object { ([string]$_).ToLowerInvariant() })
    switch ($Kind) {
        { $_ -in 'Path', 'AsrOnly', 'Process', 'CfaApp' } {
            $leaf = Split-Path -Leaf ($v.TrimEnd('\'))
            if ($v -match '^[A-Za-z]:\\?\*?$' -or $v -in '\', '*', '*.*', '\*') { $reasons.Add('Excludes a whole drive or everything.'); $high = $true }
            if ($v -match '^\*|\\\*\\|^[A-Za-z]:\\\*') { $reasons.Add('Starts with or contains a broad wildcard.'); $high = $true }
            if ($v -match '(?i)\\(Temp|Tmp)(\\|$)|\\AppData\\Local\\Temp|\\Windows\\Temp|\\Downloads(\\|$)|\\Users\\Public|\\ProgramData(\\|$)|\\AppData\\Roaming(\\|$)|\\Desktop(\\|$)|\\Recycle') { $reasons.Add('A user-writable or temporary folder: anything dropped there runs unscanned.'); $high = $true }
            elseif ($v -match '(?i)^[A-Za-z]:\\Users\\[^\\]+\\?$|\\AppData(\\|$)') { $reasons.Add('A user profile or AppData folder (user-writable).'); $high = $true }
            if ($v -match '(?i)^[A-Za-z]:\\Windows\\?$|^[A-Za-z]:\\Windows\\System32\\?$|^[A-Za-z]:\\Program Files( \(x86\))?\\?$') { $reasons.Add('An entire system or program folder.'); $high = $true }
            if ($scriptHosts -contains $leaf.ToLowerInvariant()) { $reasons.Add("$leaf is a script host or living-off-the-land binary; excluding it hides whatever it runs."); $high = $true }
            if ($v -match '(?i)\.(exe|dll|ps1|bat|cmd|js|vbs|hta|scr)$' -and $Kind -eq 'Path' -and $v -match '\*') { $reasons.Add('Wildcard over executable files.'); $high = $true }
            if ($v -match '^\\\\') { $reasons.Add('A network path: files from the share are not scanned.') }
        }
        'Extension' {
            $e = $v.TrimStart('*').TrimStart('.').ToLowerInvariant()
            if (@($script:IgwtExclusionRiskData.riskyExtensions) -contains $e) { $reasons.Add(".$e files can carry code; excluding the extension skips them everywhere."); $high = $true }
            if ($e -eq '*' -or $e -eq '') { $reasons.Add('Excludes every extension.'); $high = $true }
        }
        'IpAddress' {
            if ($v -match '^(0\.0\.0\.0|::)(/0)?$' -or $v -match '/([0-9]|1[0-5])$') { $reasons.Add('A very broad IP range.'); $high = $true }
            elseif ($v -match '/(1[6-9]|2[0-3])$') { $reasons.Add('A large IP range.') }
        }
    }
    $sev = $(if ($high) { 'High' } elseif ($reasons.Count) { 'Medium' } else { 'Low' })
    return [pscustomobject]@{ Severity = $sev; Reasons = $reasons.ToArray() }
}

function Get-IgwtDefenderExclusionAudit {
    <#
    .SYNOPSIS
        Every Defender exclusion with its source (Local preference, Local GPO, Domain GPO / policy,
        MDM) and risk. Defender hides exclusions from non-administrators; then Readable is $false.
        Read-only.
    #>
    [CmdletBinding()]
    param()
    $pref = $null
    try { $pref = Get-IgwtMpPreferenceSafe } catch { throw "Defender preferences are unavailable: $($_.Exception.Message)" }
    $rows = New-Object System.Collections.Generic.List[object]
    $readable = $true
    $hidden = { param($vals) @($vals | Where-Object { [string]$_ -like 'N/A*' }).Count -gt 0 }
    $local = @{ Machine = @(Get-IgwtLocalPolicyEntries -Class Machine) }
    foreach ($k in $script:IgwtExclusionKinds.Keys) {
        $d = $script:IgwtExclusionKinds[$k]
        $vals = @($pref.($d.Pref) | Where-Object { $_ })
        if (& $hidden $vals) { $readable = $false; $vals = @() }
        $polKey = "SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$($d.PolicyKey)"
        $polNames = @()
        if (Test-IgwtRegistryKey -Path ('HKLM:\' + $polKey)) { $item = Get-Item -LiteralPath (Resolve-IgwtRegistryPath -Path ('HKLM:\' + $polKey)) -ErrorAction SilentlyContinue; if ($item) { $polNames = @($item.GetValueNames() | Where-Object { $_ }) } }
        $mdmVals = @()
        $mdm = Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Name ("Excluded{0}" -f $(switch ($k) { 'Path' { 'Paths' } 'Process' { 'Processes' } 'Extension' { 'Extensions' } default { '' } }))
        if ($mdm.Exists) { $mdmVals = @(([string]$mdm.Value).Split('|') | Where-Object { $_ }) }
        foreach ($v in @(@($vals) + @($polNames) + @($mdmVals) | Sort-Object -Unique)) {
            $src = $(if ($polNames -contains $v) { $(if (@($local.Machine | Where-Object { [string]::Equals([string]$_.Key, $polKey, [System.StringComparison]::OrdinalIgnoreCase) -and $_.ValueName -eq $v }).Count) { 'Local GPO' } else { 'Policy (domain GPO or registry)' }) } elseif ($mdmVals -contains $v) { 'MDM' } else { 'Local preference' })
            $risk = Test-IgwtExclusionRisk -Kind $k -Value $v
            $rows.Add([pscustomobject]@{ Kind = $k; Value = $v; Source = $src; Severity = $risk.Severity; Reasons = $risk.Reasons; Removable = ($src -in 'Local preference', 'Local GPO') })
        }
    }
    # ASR-only exclusions come from the ASR Center (their single source of truth); CFA allowed apps from Defender.
    $asr = Get-IgwtAsrGlobalExclusions
    if (-not $asr.Readable) { $readable = $false }
    foreach ($v in @($asr.Paths)) { $risk = Test-IgwtExclusionRisk -Kind AsrOnly -Value $v; $rows.Add([pscustomobject]@{ Kind = 'AsrOnly'; Value = $v; Source = 'ASR Center'; Severity = $risk.Severity; Reasons = $risk.Reasons; Removable = $false }) }
    $cfa = @($pref.ControlledFolderAccessAllowedApplications | Where-Object { $_ })
    if (& $hidden $cfa) { $readable = $false } else { foreach ($v in $cfa) { $risk = Test-IgwtExclusionRisk -Kind CfaApp -Value $v; $rows.Add([pscustomobject]@{ Kind = 'CfaApp'; Value = $v; Source = 'ASR Center'; Severity = $risk.Severity; Reasons = $risk.Reasons; Removable = $false }) } }
    [pscustomobject]@{
        Readable = $readable
        Note = $(if (-not $readable) { 'Defender shows exclusions to administrators only; run elevated to audit them.' } else { 'ASR-only exclusions and Controlled folder access apps are managed in the ASR Center (-Asr).' })
        Exclusions = $rows.ToArray()
        High = @($rows | Where-Object Severity -EQ 'High').Count
    }
}

function Remove-IgwtDefenderExclusion {
    <#
    .SYNOPSIS
        Removes one antivirus exclusion after confirmation: from Defender's preference
        (Remove-MpPreference) or from the Local GPO. Exclusions from a domain GPO or MDM cannot be
        removed locally. The removed value is logged so it can be re-added by hand in Windows
        Security if it was needed; iG Windows Tuner never adds exclusions.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][ValidateSet('Path', 'Process', 'Extension', 'IpAddress')][string]$Kind, [Parameter(Mandatory = $true)][string]$Value)
    $audit = Get-IgwtDefenderExclusionAudit
    if (-not $audit.Readable) { throw 'Exclusions are hidden from non-administrators; run elevated.' }
    $row = @($audit.Exclusions | Where-Object { $_.Kind -eq $Kind -and [string]::Equals([string]$_.Value, $Value, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $row) { throw "No $Kind exclusion '$Value' found." }
    if (-not $row.Removable) { throw "This exclusion comes from $($row.Source); remove it there (your organization or the domain GPO)." }
    if (-not $PSCmdlet.ShouldProcess("$Kind exclusion $Value", 'Remove')) { return $null }
    $d = $script:IgwtExclusionKinds[$Kind]
    if ($row.Source -eq 'Local GPO') {
        $bt = [pscustomobject]@{ Class = 'Machine'; Key = "SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$($d.PolicyKey)"; ValueName = [string]$row.Value }
        $backup = Backup-IgwtLocalGpo -Reason "before removing the $Kind exclusion $Value"
        $null = Set-IgwtBridgeValue -Target $bt -Exists $false
        Remove-IgwtRegistryValue -Path ('HKLM:\' + $bt.Key) -Name $bt.ValueName
        Write-IgwtLog -Level Warn -Message "Removed $Kind exclusion '$Value' from the Local GPO. Backup: $backup"
        return [pscustomobject]@{ Kind = $Kind; Value = $Value; Source = 'Local GPO'; Backup = $backup }
    }
    $arg = @{ ($d.Remove) = @([string]$row.Value); ErrorAction = 'Stop' }
    Remove-MpPreference @arg
    Clear-IgwtCache -Prefix 'mp:' -WhatIf:$false
    Write-IgwtLog -Level Warn -Message "Removed $Kind exclusion '$Value' from Defender (Remove-MpPreference). Re-add it by hand in Windows Security if it was needed."
    return [pscustomobject]@{ Kind = $Kind; Value = $Value; Source = 'Local preference'; Backup = $null }
}
