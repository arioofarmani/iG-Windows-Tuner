# Platform.ps1
# Windows edition families. Catalog items, Toolkit features and (from 3.0) policies list the
# editions on which Windows honors them; an item for another edition is shown as "not effective
# on this edition" instead of silently writing a setting Windows ignores.

$script:IgwtEditionFamilies = @('Home', 'Professional', 'Enterprise', 'Education', 'Server')

function Get-IgwtEditionFamily {
    <#
    .SYNOPSIS
        Maps an EditionID (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion) to Home,
        Professional, Enterprise, Education or Server ('' when unknown).
    .DESCRIPTION
        Pro Education and Education share the Education family (Microsoft lists both under
        Education SKUs); Pro for Workstations is Professional; LTSC and IoT Enterprise are
        Enterprise.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$EditionId)
    $e = ([string]$EditionId).Trim()
    if (-not $e) { return '' }
    if ($e -match '^(?i)Server') { return 'Server' }
    if ($e -match '^(?i)Core') { return 'Home' }
    if ($e -match '^(?i)(Education|ProfessionalEducation)') { return 'Education' }
    if ($e -match '^(?i)(Enterprise|IoTEnterprise)') { return 'Enterprise' }
    if ($e -match '^(?i)Professional') { return 'Professional' }
    return ''
}

function Test-IgwtEditionSupported {
    <#
    .SYNOPSIS
        True when the edition family of EditionId is one of Editions (or Editions is empty, or the
        edition is unknown, so detection problems never hide an item).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyCollection()][string[]]$Editions, [AllowEmptyString()][string]$EditionId)
    $list = @($Editions | Where-Object { $_ })
    if ($list.Count -eq 0) { return $true }
    $family = Get-IgwtEditionFamily -EditionId $EditionId
    if (-not $family) { return $true }
    return (@($list | Where-Object { [string]$_ -eq $family }).Count -gt 0)
}
