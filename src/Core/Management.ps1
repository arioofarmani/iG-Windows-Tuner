# Management.ps1
# Platform and management awareness (3.0): edition family, Local Group Policy support, domain and
# Entra ID join, MDM (Intune) enrollment, Microsoft Defender for Endpoint and third-party
# antivirus. On a managed PC, items a higher authority controls are report-only unless the user
# explicitly acknowledges a local change. Everything here is read-only.

function Get-IgwtJoinInfo {
    <# .SYNOPSIS Domain and Entra ID (Azure AD) join state from WMI and the CloudDomainJoin registry key. Read-only. #>
    [CmdletBinding()]
    param()
    $domain = $false; $domainName = ''
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domain = [bool]$cs.PartOfDomain
        if ($domain) { $domainName = [string]$cs.Domain }
    } catch { Write-Verbose "Domain state unavailable: $($_.Exception.Message)" }
    $entra = $false; $tenant = ''
    try {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
        if ((Test-IgwtRegistryKey -Path $key)) {
            $sub = @(Get-ChildItem -LiteralPath (Resolve-IgwtRegistryPath -Path $key) -ErrorAction Stop)
            if ($sub.Count) {
                $entra = $true
                $tenantId = $sub[0].GetValue('TenantId')
                if ($tenantId) { $tenant = [string]$tenantId }
            }
        }
    } catch { Write-Verbose "Entra join state unavailable: $($_.Exception.Message)" }
    [pscustomobject]@{ DomainJoined = $domain; DomainName = $domainName; EntraJoined = $entra; TenantId = $tenant }
}

function Get-IgwtMdmEnrollment {
    <#
    .SYNOPSIS
        MDM enrollments (HKLM\SOFTWARE\Microsoft\Enrollments) that are active (EnrollmentState 1)
        and belong to a management service (ProviderID set, for example "MS DM Server" for Intune). Read-only.
    #>
    [CmdletBinding()]
    param()
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $root = Resolve-IgwtRegistryPath -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments'
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $state = $k.GetValue('EnrollmentState'); $provider = [string]$k.GetValue('ProviderID'); $type = [string]$k.GetValue('EnrollmentType')
            # Real MDM enrollments are type 6 (MDM) or 13 (MDM with Entra ID). Windows itself keeps
            # "Deploy/Cloud/Local Authority" entries (types 28-32) on unmanaged PCs; they are not MDM.
            if ([string]$state -eq '1' -and $provider -and $type -in '6', '13' -and $provider -notmatch '^(Deploy|Cloud|Local) Authority$') { $out.Add([pscustomobject]@{ Provider = $provider; Upn = [string]$k.GetValue('UPN'); Id = $k.PSChildName }) }
        }
    } catch { Write-Verbose "MDM enrollments unavailable: $($_.Exception.Message)" }
    return $out.ToArray()
}

function Get-IgwtSecurityManagement {
    <#
    .SYNOPSIS
        Defender for Endpoint onboarding, Defender running mode (normal, passive, EDR block) and the
        antivirus products registered with Windows Security Center. Read-only.
    #>
    [CmdletBinding()]
    param()
    $mde = $false
    try {
        $v = Get-IgwtRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'
        $mde = ($v.Exists -and [int]$v.Value -eq 1)
    } catch { Write-Verbose 'Defender for Endpoint state unavailable.' }
    $mode = ''
    try { $mode = [string](Get-IgwtCached -Key 'mp:status' -TtlSeconds 10 -ScriptBlock { Get-MpComputerStatus -ErrorAction Stop }).AMRunningMode } catch { $mode = '' }
    $av = @()
    try { $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop | ForEach-Object { [string]$_.displayName } | Where-Object { $_ }) } catch { $av = @() }
    $third = @($av | Where-Object { $_ -notmatch '(?i)Microsoft Defender|Windows Defender' })
    [pscustomobject]@{ DefenderForEndpoint = $mde; DefenderMode = $mode; AntivirusProducts = $av; ThirdPartyAntivirus = $third }
}

function Get-IgwtManagementState {
    <#
    .SYNOPSIS
        Platform and management summary: edition family, Local Group Policy support, domain and
        Entra ID join, MDM enrollment, Defender for Endpoint, third-party antivirus, and whether the
        PC is managed (domain or MDM). Cached for the session; -Force reads again. Read-only.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtManagementCache -and -not $Force -and -not $script:IgwtSettings.TestMode) { return $script:IgwtManagementCache }
    $os = Get-IgwtOsInfo
    $family = Get-IgwtEditionFamily -EditionId ([string]$os.EditionId)
    $join = Get-IgwtJoinInfo
    $mdm = @(Get-IgwtMdmEnrollment)
    $sec = Get-IgwtSecurityManagement
    $authorities = New-Object System.Collections.Generic.List[string]
    if ($join.DomainJoined) { $authorities.Add("Active Directory domain $($join.DomainName)") }
    if ($mdm.Count) { $authorities.Add("MDM ($(@($mdm | ForEach-Object { $_.Provider } | Select-Object -Unique) -join ', '))") }
    if ($sec.DefenderForEndpoint) { $authorities.Add('Microsoft Defender for Endpoint') }
    $state = [pscustomobject]@{
        EditionId = [string]$os.EditionId; EditionFamily = $family; Build = [int]$os.Build
        LocalGroupPolicy = ($family -ne 'Home')
        DomainJoined = [bool]$join.DomainJoined; DomainName = [string]$join.DomainName; EntraJoined = [bool]$join.EntraJoined; TenantId = [string]$join.TenantId
        MdmEnrolled = ($mdm.Count -gt 0); MdmProviders = @($mdm | ForEach-Object { $_.Provider } | Select-Object -Unique)
        DefenderForEndpoint = [bool]$sec.DefenderForEndpoint; DefenderMode = [string]$sec.DefenderMode; ThirdPartyAntivirus = @($sec.ThirdPartyAntivirus)
        Managed = ([bool]$join.DomainJoined -or $mdm.Count -gt 0)
        Authorities = $authorities.ToArray()
    }
    if (-not $script:IgwtSettings.TestMode) { $script:IgwtManagementCache = $state }
    return $state
}

function Get-IgwtItemAuthority {
    <#
    .SYNOPSIS
        Why an item may be controlled by a higher authority on this PC, or $null: a policy item
        (gpoPath) on a domain-joined or MDM-enrolled PC. The engine treats such items as report-only
        unless the caller acknowledges a local change.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, $Management)
    if (-not $Management) { return $null }
    if (-not $Management.Managed) { return $null }
    if (-not [string]$Tweak.gpoPath) { return $null }
    return "This PC is managed ($(@($Management.Authorities) -join ', ')); a domain or MDM policy can override this setting, and local changes need -AcknowledgeManaged."
}

function Format-IgwtManagementState {
    <# .SYNOPSIS Text report of Get-IgwtManagementState. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)
    $yn = { param($b) if ($b) { 'yes' } else { 'no' } }
    @(
        'Platform and management (read-only)'
        ('  Edition:              {0} ({1}), build {2}' -f $State.EditionFamily, $State.EditionId, $State.Build)
        ('  Local Group Policy:   {0}' -f $(if ($State.LocalGroupPolicy) { 'available' } else { 'not available on Home: policy features are report-only' }))
        ('  Domain joined:        {0}{1}' -f (& $yn $State.DomainJoined), $(if ($State.DomainName) { " ($($State.DomainName))" } else { '' }))
        ('  Entra ID joined:      {0}' -f (& $yn $State.EntraJoined))
        ('  MDM enrolled:         {0}{1}' -f (& $yn $State.MdmEnrolled), $(if (@($State.MdmProviders).Count) { " ($(@($State.MdmProviders) -join ', '))" } else { '' }))
        ('  Defender for Endpoint: {0}' -f (& $yn $State.DefenderForEndpoint))
        ('  Defender mode:        {0}' -f $(if ($State.DefenderMode) { $State.DefenderMode } else { 'unknown' }))
        ('  Other antivirus:      {0}' -f $(if (@($State.ThirdPartyAntivirus).Count) { @($State.ThirdPartyAntivirus) -join ', ' } else { 'none' }))
        ('  Managed:              {0}' -f $(if ($State.Managed) { "yes ($(@($State.Authorities) -join '; ')): policy items are report-only unless you pass -AcknowledgeManaged" } else { 'no: every item can be applied locally' }))
    )
}
