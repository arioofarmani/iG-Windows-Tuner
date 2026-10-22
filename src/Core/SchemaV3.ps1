# SchemaV3.ps1
# Schema v3 for tweak files (3.0): scope, editions, managedBy, admxRef, gpoPath, requiresDomain and
# requiresMdm. v2 entries are upgraded in memory (and on disk by tools\Convert-IgwtV1Data.ps1);
# actions are never changed, so every snapshot still matches its item.

$script:IgwtTweakSchemaVersion = 3
$script:IgwtScopes = @('Performance', 'Network', 'Privacy', 'Updates', 'Defender', 'AttackSurface', 'AuditLogging', 'System')
$script:IgwtManagedBySources = @('local', 'gpo', 'mdm')
$script:IgwtGpoPaths = @('machine', 'user')

function Get-IgwtDefaultScope {
    <# .SYNOPSIS The scope a v2 item gets from its category, group and actions (used by the v2 -> v3 migration). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Tweak)
    $cat = [string]$Tweak.category
    $group = [string]$Tweak.group
    $types = @(@($Tweak.actions) | ForEach-Object { [string]$_.type })
    switch ($cat) {
        'Network' { return 'Network' }
        'Background & Privacy' { if ($group -eq 'Windows Update') { return 'Updates' } else { return 'Privacy' } }
        'Security' {
            if ([string]$Tweak.id -match 'logging') { return 'AuditLogging' }
            if ($types -contains 'mpPreference' -or ($group -eq 'Microsoft Defender' -and $types -notcontains 'asrRule')) { return 'Defender' }
            return 'AttackSurface'
        }
        { $_ -in 'Storage', 'System' } { return 'System' }
    }
    return 'Performance'
}

function Get-IgwtPolicyLocation {
    <#
    .SYNOPSIS
        'machine' or 'user' when a registry path is a Group Policy location (SOFTWARE\Policies or
        the documented CurrentVersion\Policies keys), otherwise ''.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Path)
    $p = [string]$Path
    if ($p -match '^(HKLM:|HKEY_LOCAL_MACHINE)\\SOFTWARE\\(Policies\\|Microsoft\\Windows\\CurrentVersion\\Policies\\)') { return 'machine' }
    if ($p -match '^(HKCU:|HKEY_CURRENT_USER)\\Software\\(Policies\\|Microsoft\\Windows\\CurrentVersion\\Policies\\)') { return 'user' }
    return ''
}

function Get-IgwtDefaultGpoPath {
    <# .SYNOPSIS gpoPath for an item: machine/user when all of its policy-location registry actions share one side, '' when it writes no policy. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Tweak)
    $locs = @(@($Tweak.actions) | Where-Object { [string]$_.type -eq 'registry' } | ForEach-Object { Get-IgwtPolicyLocation -Path ([string]$_.path) } | Where-Object { $_ } | Select-Object -Unique)
    if ($locs.Count -eq 1) { return [string]$locs[0] }
    if ($locs.Count -gt 1) { return 'machine' }
    return ''
}

function ConvertTo-IgwtV3Tweak {
    <#
    .SYNOPSIS
        v2 tweak -> v3 tweak (ordered): adds scope, editions (moved up from appliesTo.editions),
        managedBy, admxRef, gpoPath, requiresDomain and requiresMdm. Existing v3 values are kept.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak)
    $o = ConvertTo-IgwtV2Tweak -Tweak $Tweak
    if (-not $o.Contains('scope') -or -not $o['scope']) { $o['scope'] = Get-IgwtDefaultScope -Tweak $Tweak }
    $applies = $o['appliesTo']
    $editions = @()
    if ($o.Contains('editions')) { $editions = @($o['editions'] | Where-Object { $_ }) }
    if ($applies -and $applies.Contains('editions')) {
        $editions = @(@($editions) + @($applies['editions'] | Where-Object { $_ }) | Select-Object -Unique)
        $applies.Remove('editions')
    }
    $o['editions'] = @($editions)
    if (-not $o.Contains('gpoPath')) { $o['gpoPath'] = Get-IgwtDefaultGpoPath -Tweak $Tweak }
    if (-not $o.Contains('managedBy') -or @($o['managedBy']).Count -eq 0) { if ($o['gpoPath']) { $o['managedBy'] = @('local', 'gpo', 'mdm') } else { $o['managedBy'] = @('local') } }
    else { $o['managedBy'] = @($o['managedBy']) }
    if (-not $o.Contains('admxRef')) { $o['admxRef'] = $null }
    if (-not $o.Contains('requiresDomain')) { $o['requiresDomain'] = $false }
    if (-not $o.Contains('requiresMdm')) { $o['requiresMdm'] = $false }
    return (ConvertTo-IgwtOrderedCopy -Object $o -Order $script:IgwtTweakKeyOrder -Last @('actions'))
}

function Test-IgwtV3Fields {
    <# .SYNOPSIS Validates the schema v3 fields of one normalized tweak; adds error strings to Errors. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Errors)
    $tid = [string]$Tweak.id
    if ($script:IgwtScopes -notcontains [string]$Tweak.scope) { $Errors.Add("${tid}: scope must be one of $($script:IgwtScopes -join ', ').") }
    foreach ($e in @($Tweak.editions | Where-Object { $_ })) { if ($script:IgwtEditionFamilies -notcontains [string]$e) { $Errors.Add("${tid}: unknown edition '$e'.") } }
    foreach ($m in @($Tweak.managedBy | Where-Object { $_ })) { if ($script:IgwtManagedBySources -notcontains [string]$m) { $Errors.Add("${tid}: managedBy may contain local, gpo and mdm only.") } }
    if (@($Tweak.managedBy) -notcontains 'local') { $Errors.Add("${tid}: managedBy must include 'local' (iG Windows Tuner applies items locally).") }
    if ([string]$Tweak.gpoPath -and $script:IgwtGpoPaths -notcontains [string]$Tweak.gpoPath) { $Errors.Add("${tid}: gpoPath must be machine, user or empty.") }
    $expected = Get-IgwtDefaultGpoPath -Tweak $Tweak
    if ($expected -and -not [string]$Tweak.gpoPath) { $Errors.Add("${tid}: writes a Group Policy location; set gpoPath to '$expected'.") }
    if ([string]$Tweak.gpoPath -and @($Tweak.managedBy) -notcontains 'gpo') { $Errors.Add("${tid}: a policy item (gpoPath) must list 'gpo' in managedBy.") }
    if ($null -ne $Tweak.admxRef) {
        if (-not ([string]$Tweak.admxRef.file -match '\.admx$') -or -not [string]$Tweak.admxRef.policy) { $Errors.Add("${tid}: admxRef needs file (*.admx) and policy.") }
    }
}
