# Apps.ps1
# App and package actions:
#   appx        remove an inbox app for the current user (optionally its provisioned copy); revert
#               re-registers it from its install folder or reinstalls it from the Store via winget
#   winget      install or uninstall a winget package (user-initiated, fixed arguments only)
#   capability  add or remove a Windows capability (Features on Demand)
# Core apps (Store, App Installer, Windows Security, shell, Xbox identity/Gaming Services, frameworks)
# are never removed.

$script:IgwtProtectedAppx = @(
    'Microsoft.WindowsStore', 'Microsoft.DesktopAppInstaller', 'Microsoft.SecHealthUI', 'Microsoft.Windows.SecHealthUI', 'Microsoft.StorePurchaseApp',
    'Microsoft.Windows.ShellExperienceHost', 'Microsoft.Windows.StartMenuExperienceHost', 'Microsoft.AAD.BrokerPlugin', 'Microsoft.AccountsControl',
    'windows.immersivecontrolpanel', 'Microsoft.Windows.CloudExperienceHost', 'Microsoft.XboxIdentityProvider', 'Microsoft.GamingServices',
    'Microsoft.Winget.Source', 'Microsoft.WindowsAppRuntime*', 'Microsoft.UI.Xaml*', 'Microsoft.VCLibs*', 'Microsoft.NET.*', 'MicrosoftWindows.Client.*',
    'Microsoft.Windows.Search', 'Microsoft.LockApp', 'Microsoft.Windows.OOBENetworkConnectionFlow'
)
$script:IgwtWingetNotFound = -1978335212   # 0x8A150014 APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND

#region appx

function Test-IgwtAppxProtected {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Package)
    foreach ($p in $script:IgwtProtectedAppx) { if ($Package -like $p) { return $true } }
    return $false
}

function Get-IgwtAppxInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Package)
    $pkg = @(Get-AppxPackage -Name $Package -ErrorAction SilentlyContinue) | Select-Object -First 1
    [pscustomobject]@{ Installed = [bool]$pkg; FullName = $(if ($pkg) { [string]$pkg.PackageFullName } else { '' }); InstallLocation = $(if ($pkg) { [string]$pkg.InstallLocation } else { '' }) }
}

function Get-IgwtAppxState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $i = Get-IgwtAppxInfo -Package ([string]$Action.package)
    $cur = $(if ($i.Installed) { 'Installed' } else { 'Removed' })
    [pscustomobject]@{ Target = "App $($Action.package) (current user)"; Current = $cur; Desired = [string]$Action.on; State = $(if ($cur -eq [string]$Action.on) { 'On' } else { 'Off' }); Note = '' }
}

function Get-IgwtAppxSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $i = Get-IgwtAppxInfo -Package ([string]$Action.package)
    return @{ installed = $i.Installed; fullName = $i.FullName; installLocation = $i.InstallLocation }
}

function Install-IgwtAppxPackage {
    <# .SYNOPSIS Re-registers an app from its install folder, or reinstalls it from the Store via winget (storeId). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [string]$InstallLocation)
    $manifest = $null
    if ($InstallLocation) { $manifest = Join-Path $InstallLocation 'AppxManifest.xml' }
    if ($manifest -and (Test-Path -LiteralPath $manifest)) {
        if ($PSCmdlet.ShouldProcess($Action.package, 'Re-register app')) { Add-AppxPackage -Register -Path $manifest -DisableDevelopmentMode -ErrorAction Stop }
        return
    }
    if ($Action.storeId) {
        if ($PSCmdlet.ShouldProcess($Action.package, "Reinstall from Microsoft Store ($($Action.storeId))")) { Install-IgwtWingetPackage -Id ([string]$Action.storeId) -Source 'msstore' }
        return
    }
    throw "Reinstall $($Action.package) from the Microsoft Store; its files are no longer on this PC."
}

function Invoke-IgwtAppxApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $pkg = [string]$Action.package
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    $i = Get-IgwtAppxInfo -Package $pkg
    if ($target -eq 'Removed') {
        if (Test-IgwtAppxProtected -Package $pkg) { throw "App '$pkg' is protected and is never removed by iG Windows Tuner." }
        if ($i.Installed -and $PSCmdlet.ShouldProcess($pkg, 'Remove app for the current user')) { Remove-AppxPackage -Package $i.FullName -ErrorAction Stop }
        if ($Action.provisioned) {
            foreach ($pp in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { [string]$_.DisplayName -eq $pkg })) {
                if ($PSCmdlet.ShouldProcess($pkg, 'Remove provisioned copy (new user profiles)')) { $null = Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop }
            }
        }
        return
    }
    if (-not $i.Installed) { Install-IgwtAppxPackage -Action $Action -InstallLocation '' }
}

function Restore-IgwtAppxSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $i = Get-IgwtAppxInfo -Package ([string]$Action.package)
    if ([bool]$Snapshot.installed -and -not $i.Installed) { Install-IgwtAppxPackage -Action $Action -InstallLocation ([string]$Snapshot.installLocation) }
    elseif (-not [bool]$Snapshot.installed -and $i.Installed -and $PSCmdlet.ShouldProcess($Action.package, 'Remove app installed since the snapshot')) { Remove-AppxPackage -Package $i.FullName -ErrorAction Stop }
}

#endregion

#region winget

function Invoke-IgwtWinget {
    <# .SYNOPSIS Runs winget.exe with fixed arguments; refuses to run in TestMode (tests must mock it). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    if ($script:IgwtSettings.TestMode) { throw 'TestMode safety: winget.exe must be mocked in tests.' }
    # 'export' only writes the inventory file the caller names (a temporary file).
    $readOnly = @('list', 'search', 'show', 'export', '--version')
    if ($readOnly -notcontains $Arguments[0] -and -not $PSCmdlet.ShouldProcess("winget $($Arguments -join ' ')", 'Run')) { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
    $cmd = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { throw 'winget (App Installer) is not available on this PC.' }
    $exe = $cmd.Source
    $out = & $exe @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out }
}

function Test-IgwtWingetInstalled {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Id)
    $r = Invoke-IgwtWinget -Arguments @('list', '--id', $Id, '--exact', '--accept-source-agreements', '--disable-interactivity')
    if ($r.ExitCode -eq 0) { return $true }
    if ($r.ExitCode -eq $script:IgwtWingetNotFound) { return $false }
    throw "winget list failed (exit $($r.ExitCode))."
}

function Install-IgwtWingetPackage {
    <#
    .SYNOPSIS Installs a winget package. The accept flags are passed only after the user accepted the agreements.
    .PARAMETER AcceptAgreements
        The user accepted the winget package and source agreements for this install.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id, [string]$Source = 'winget', [switch]$AcceptAgreements)
    if (-not ([bool]$AcceptAgreements -or (Test-IgwtWingetConsent))) { throw "winget's package and source agreements have not been accepted (Toolkit > Install shows them)." }
    if (-not $PSCmdlet.ShouldProcess($Id, "winget install ($Source)")) { return }
    $r = Invoke-IgwtWinget -Arguments @('install', '--id', $Id, '--exact', '--source', $Source, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    if ($r.ExitCode -ne 0) { throw "winget install $Id failed (exit $($r.ExitCode))." }
}

function Uninstall-IgwtWingetPackage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Id)
    if (-not $PSCmdlet.ShouldProcess($Id, 'winget uninstall')) { return }
    $r = Invoke-IgwtWinget -Arguments @('uninstall', '--id', $Id, '--exact', '--silent', '--disable-interactivity')
    if ($r.ExitCode -ne 0) { throw "winget uninstall $Id failed (exit $($r.ExitCode))." }
}

function Get-IgwtWingetState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $label = "Package $($Action.id) (winget)"
    try { $installed = Test-IgwtWingetInstalled -Id ([string]$Action.id) } catch {
        return [pscustomobject]@{ Target = $label; Current = 'unknown'; Desired = [string]$Action.on; State = 'Unknown'; Note = $_.Exception.Message }
    }
    $cur = $(if ($installed) { 'Installed' } else { 'NotInstalled' })
    [pscustomobject]@{ Target = $label; Current = $cur; Desired = [string]$Action.on; State = $(if ($cur -eq [string]$Action.on) { 'On' } else { 'Off' }); Note = '' }
}

function Get-IgwtWingetSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    return @{ installed = (Test-IgwtWingetInstalled -Id ([string]$Action.id)) }
}

function Invoke-IgwtWingetApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    $installed = Test-IgwtWingetInstalled -Id ([string]$Action.id)
    $source = 'winget'
    if ($Action.source) { $source = [string]$Action.source }
    if ($target -eq 'Installed' -and -not $installed) { Install-IgwtWingetPackage -Id ([string]$Action.id) -Source $source }
    elseif ($target -eq 'NotInstalled' -and $installed) { Uninstall-IgwtWingetPackage -Id ([string]$Action.id) }
}

function Restore-IgwtWingetSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $installed = Test-IgwtWingetInstalled -Id ([string]$Action.id)
    $source = 'winget'
    if ($Action.source) { $source = [string]$Action.source }
    if ([bool]$Snapshot.installed -and -not $installed) { Install-IgwtWingetPackage -Id ([string]$Action.id) -Source $source }
    elseif (-not [bool]$Snapshot.installed -and $installed) { Uninstall-IgwtWingetPackage -Id ([string]$Action.id) }
}

#endregion

#region capability

function Get-IgwtCapabilityValue {
    <# .SYNOPSIS State (Installed, NotPresent, Staged...) of one Windows capability, or $null when unknown on this build. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $c = @(Get-WindowsCapability -Online -Name $Name -ErrorAction Stop)
    if ($c.Count -ne 1) { return $null }
    return [pscustomobject]@{ Name = [string]$c[0].Name; State = [string]$c[0].State }
}

function Get-IgwtCapabilityState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $label = "Windows capability $($Action.name)"
    if ($Context -and $null -ne $Context.IsAdmin -and -not $Context.IsAdmin) { return [pscustomobject]@{ Target = $label; Current = 'requires administrator to read'; Desired = [string]$Action.on; State = 'Unknown'; Note = '' } }
    try { $c = Get-IgwtCapabilityValue -Name ([string]$Action.name) } catch { return [pscustomobject]@{ Target = $label; Current = 'unreadable'; Desired = [string]$Action.on; State = 'Unknown'; Note = $_.Exception.Message } }
    if (-not $c) { return [pscustomobject]@{ Target = $label; Current = 'not offered'; Desired = [string]$Action.on; State = 'NotApplicable'; Note = 'This capability is not offered on this Windows build.' } }
    $isOn = ($c.State -eq [string]$Action.on) -or ([string]$Action.on -eq 'NotPresent' -and $c.State -eq 'Removed')
    [pscustomobject]@{ Target = "Windows capability $($c.Name)"; Current = $c.State; Desired = [string]$Action.on; State = $(if ($isOn) { 'On' } else { 'Off' }); Note = '' }
}

function Get-IgwtCapabilitySnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $c = Get-IgwtCapabilityValue -Name ([string]$Action.name)
    return @{ name = $(if ($c) { $c.Name } else { '' }); state = $(if ($c) { $c.State } else { '' }) }
}

function Set-IgwtCapability {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][ValidateSet('Installed', 'NotPresent')][string]$State)
    if (-not $PSCmdlet.ShouldProcess($Name, "Set capability $State")) { return }
    if ($State -eq 'Installed') { $null = Add-WindowsCapability -Online -Name $Name -ErrorAction Stop }
    else { $null = Remove-WindowsCapability -Online -Name $Name -ErrorAction Stop }
}

function Invoke-IgwtCapabilityApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $c = Get-IgwtCapabilityValue -Name ([string]$Action.name)
    if (-not $c) { return }
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = [string]$Action.default }
    $isInstalled = ($c.State -eq 'Installed')
    if ($isInstalled -ne ($target -eq 'Installed')) { Set-IgwtCapability -Name $c.Name -State $target }
}

function Restore-IgwtCapabilitySnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    if (-not $Snapshot.state) { return }
    $c = Get-IgwtCapabilityValue -Name ([string]$Action.name)
    if (-not $c) { return }
    $wasInstalled = ([string]$Snapshot.state -eq 'Installed')
    if (($c.State -eq 'Installed') -ne $wasInstalled) { Set-IgwtCapability -Name $c.Name -State $(if ($wasInstalled) { 'Installed' } else { 'NotPresent' }) }
}

#endregion
