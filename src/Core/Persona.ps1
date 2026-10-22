# Persona.ps1
# Personas (3.0): Gamer, Power User and Sysadmin change the default navigation order and which item
# levels are shown. They never change a safety rule: gates, acknowledgements, protected lists and
# report-only behavior are identical for every persona. The choice is a per-user preference stored
# in %LOCALAPPDATA%\iGWindowsTuner\settings.json.

$script:IgwtPersonas = [ordered]@{
    Gamer     = [pscustomobject]@{
        Name = 'Gamer'; VisibleLevels = @('Standard', 'Advanced'); ShowRiskZone = $true
        Hint = 'Gaming first: presets, performance pages and the network test lead; Expert items are hidden (switch persona to see them).'
        NavOrder = @('Dashboard', 'Presets', 'Power & CPU', 'Graphics & Display', 'Input', 'Network', 'NetTest', 'Background & Privacy', 'Security', 'Asr', 'Defender', 'System', 'Risk Zone', 'Cleaner', 'Toolkit', 'Startup', 'Storage', 'Disk', 'Diagnostics', 'Manage', 'Inspect', 'Backups', 'Rejected', 'About')
    }
    PowerUser = [pscustomobject]@{
        Name = 'PowerUser'; VisibleLevels = @('Standard', 'Advanced', 'Expert', 'Lab'); ShowRiskZone = $true
        Hint = 'Everything visible, including Expert controls and the Risk Zone.'
        NavOrder = @()
    }
    Sysadmin  = [pscustomobject]@{
        Name = 'Sysadmin'; VisibleLevels = @('Standard', 'Advanced', 'Expert'); ShowRiskZone = $false
        Hint = 'Security, Defender, management, network and deployment lead; the Risk Zone is hidden. Policy items are report-only on managed PCs for every persona.'
        NavOrder = @('Dashboard', 'Security', 'Asr', 'Defender', 'Manage', 'Network', 'NetTest', 'Diagnostics', 'Toolkit', 'Background & Privacy', 'Presets', 'Inspect', 'System', 'Power & CPU', 'Graphics & Display', 'Input', 'Cleaner', 'Storage', 'Disk', 'Startup', 'Backups', 'Rejected', 'About')
    }
}

function Get-IgwtUserSettingsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path ([string]$script:IgwtSettings.UserLogRoot) 'settings.json')
}

function Get-IgwtPersona {
    <# .SYNOPSIS The current user's persona (Gamer by default). Read-only. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($script:IgwtSettings.TestMode -and $null -ne $script:IgwtSettings.Persona) { return [string]$script:IgwtSettings.Persona }
    $file = Get-IgwtUserSettingsPath
    if (Test-Path -LiteralPath $file) {
        try { $p = [string](Read-IgwtJsonFile -Path $file).persona; if ($script:IgwtPersonas.Contains($p)) { return $p } } catch { Write-Verbose 'User settings unreadable; using the default persona.' }
    }
    return 'Gamer'
}

function Set-IgwtPersona {
    <# .SYNOPSIS Saves the persona for the current user (a display preference; safety rules are unchanged). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Gamer', 'PowerUser', 'Sysadmin')][string]$Name)
    if ($script:IgwtSettings.TestMode) { $script:IgwtSettings.Persona = $Name; return }
    if (-not $PSCmdlet.ShouldProcess('persona', "Set $Name")) { return }
    $file = Get-IgwtUserSettingsPath
    $dir = Split-Path -Parent $file
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $doc = [ordered]@{}
    if (Test-Path -LiteralPath $file) { try { $old = Read-IgwtJsonFile -Path $file; foreach ($p in $old.PSObject.Properties) { $doc[$p.Name] = $p.Value } } catch { $doc = [ordered]@{} } }
    $doc['persona'] = $Name
    [System.IO.File]::WriteAllText($file, (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-IgwtPersonaProfile {
    <# .SYNOPSIS The visible levels, navigation order and Risk Zone visibility of a persona (default: the current one). #>
    [CmdletBinding()]
    param([ValidateSet('Gamer', 'PowerUser', 'Sysadmin')][string]$Name)
    if (-not $Name) { $Name = Get-IgwtPersona }
    return $script:IgwtPersonas[$Name]
}

function Test-IgwtItemVisible {
    <# .SYNOPSIS True when a persona shows an item (by level; the Risk Zone follows ShowRiskZone). Display only. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)]$Persona)
    if ([string]$Tweak.category -eq 'Risk Zone') { return [bool]$Persona.ShowRiskZone }
    return (@($Persona.VisibleLevels) -contains [string]$Tweak.level)
}
