# ManagedChange.ps1
# One audited path for the changes the management modules offer (service startup type, scheduled
# task enable/disable, inbox app removal, optional features, capabilities, app firewall rules).
# Each change becomes a synthetic action of an existing, tested action type, is snapshotted
# (operation 'Manage') and applied through the normal dispatch. On revert the action is rebuilt from
# the stored kind/target/value and validated again against the protection rules, so an edited
# snapshot cannot target a protected service, task, app or Windows firewall rule.

$script:IgwtManagedKinds = @('service', 'task', 'appx', 'feature', 'capability', 'firewallRule')
$script:IgwtManagedValues = @{
    service      = @('Automatic', 'AutomaticDelayed', 'Manual', 'Disabled')
    task         = @('Enabled', 'Disabled')
    appx         = @('Removed')
    feature      = @('Enabled', 'Disabled')
    capability   = @('Installed', 'NotPresent')
    firewallRule = @('Enabled', 'Disabled')
}
# Features and capabilities the manager never disables or removes (enabling them is allowed).
$script:IgwtProtectedFeatures = @('Windows-Defender*', 'NetFx4*', 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform', 'Printing-PrintToPDFServices-Features', 'SearchEngine-Client-Package')
# Legacy components that lower security when enabled (SMBv1, PowerShell 2.0 bypasses AMSI and
# script block logging, cleartext protocols, the IE engine): never enabled or installed.
$script:IgwtInsecureFeatures = @('SMB1Protocol*', 'MicrosoftWindowsPowerShellV2*', 'TelnetClient', 'TelnetServer', 'TFTP', 'Internet-Explorer-Optional*', 'SimpleTCP')
$script:IgwtInsecureCapabilities = @('Browser.InternetExplorer*')
$script:IgwtProtectedCapabilities = @('Language.*', 'Microsoft.Windows.Notepad*', 'Microsoft.Windows.PowerShell.ISE*', 'Windows.Client.ShellComponents*', 'OpenSSH.Client*')
$script:IgwtAntiCheatTaskPattern = '(?i)(vgc|vanguard|faceit|easyanticheat|battleye|ricochet|javelin)'

function Get-IgwtServiceRules {
    <# .SYNOPSIS Protected service rules from data\manage\services.json (cached). #>
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:IgwtServiceRuleCache -and -not $Force) { return $script:IgwtServiceRuleCache }
    $file = Join-Path (Get-IgwtDataFolder) 'manage\services.json'
    $rules = @()
    if (Test-Path -LiteralPath $file) { $rules = @((Read-IgwtJsonFile -Path $file).protected | Where-Object { $_ }) }
    $script:IgwtServiceRuleCache = $rules
    return $rules
}

function Get-IgwtServiceProtection {
    <# .SYNOPSIS Reason a service is protected from changes, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:IgwtProtectedServices -contains $Name) { return 'Protected by iG Windows Tuner (anti-cheat or core security).' }
    foreach ($r in @(Get-IgwtServiceRules)) {
        if (@($r.names) -contains $Name) { return [string]$r.reason }
        foreach ($p in @($r.patterns | Where-Object { $_ })) { if ($Name -like [string]$p) { return [string]$r.reason } }
    }
    return $null
}

function Test-IgwtManageCatalog {
    <# .SYNOPSIS Validates data\manage\services.json and nic-keywords.json. Returns error strings (empty = valid). #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $errors = New-Object System.Collections.Generic.List[string]
    $root = Join-Path (Get-IgwtDataFolder) 'manage'
    $svcFile = Join-Path $root 'services.json'
    if (-not (Test-Path -LiteralPath $svcFile)) { $errors.Add('manage\services.json: missing.') }
    else {
        $groups = @((Read-IgwtJsonFile -Path $svcFile).protected | Where-Object { $_ })
        if ($groups.Count -eq 0) { $errors.Add('manage\services.json: no protected groups.') }
        $all = @($groups | ForEach-Object { @($_.names) } | Where-Object { $_ })
        foreach ($g in $groups) {
            if (-not [string]$g.reason -or ([string]$g.reason).Length -gt 200) { $errors.Add('manage\services.json: every group needs a reason of 200 characters or fewer.') }
            if (@($g.names).Count + @($g.patterns | Where-Object { $_ }).Count -eq 0) { $errors.Add('manage\services.json: empty group.') }
        }
        foreach ($must in 'RpcSs', 'DcomLaunch', 'BFE', 'mpssvc', 'WinDefend', 'EventLog', 'Winmgmt', 'CryptSvc', 'BITS', 'DoSvc', 'MDCoreSvc', 'webthreatdefsvc', 'AppIDSvc', 'Audiosrv', 'Dhcp', 'Dnscache', 'nsi', 'TrustedInstaller', 'vgc', 'EasyAntiCheat_EOS', 'BEService') {
            if (@($all | Where-Object { [string]$_ -eq $must }).Count -eq 0) { $errors.Add("manage\services.json: required protected service '$must' is missing.") }
        }
    }
    $nicFile = Join-Path $root 'nic-keywords.json'
    if (-not (Test-Path -LiteralPath $nicFile)) { $errors.Add('manage\nic-keywords.json: missing.') }
    else {
        $doc = Read-IgwtJsonFile -Path $nicFile
        if (-not ([string]$doc.source -like 'https://*')) { $errors.Add('manage\nic-keywords.json: source must be an https URL.') }
        $seenKw = @{}
        foreach ($k in @($doc.keywords | Where-Object { $_ })) {
            $kw = [string]$k.keyword
            if (-not $kw.StartsWith('*')) { $errors.Add("manage\nic-keywords.json: '$kw' is not a standardized keyword (must start with *).") }
            if ($seenKw.ContainsKey($kw.ToLowerInvariant())) { $errors.Add("manage\nic-keywords.json: duplicate '$kw'.") }
            $seenKw[$kw.ToLowerInvariant()] = $true
            if (-not [string]$k.description -or ([string]$k.description).Length -gt 240) { $errors.Add("manage\nic-keywords.json: '$kw' needs a description of 240 characters or fewer.") }
        }
    }
    return $errors.ToArray()
}

function Test-IgwtNamePattern {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Name, [string[]]$Patterns)
    foreach ($p in @($Patterns)) { if ($Name -like $p) { return $true } }
    return $false
}

function Test-IgwtWindowsFirewallRule {
    <# .SYNOPSIS True for rules that ship with Windows (resource-string group such as '@FirewallAPI.dll,-...'). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Rule)
    return ([string]$Rule.Group -like '@*' -or [string]$Rule.DisplayGroup -like '@*' -or [string]$Rule.Name -like 'iGWindowsTuner-*')
}

function New-IgwtManagedAction {
    <#
    .SYNOPSIS
        Validates a management change and returns the synthetic action that performs it. Throws
        with the reason when the target is protected or the value is not allowed.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Validates and builds an in-memory action only; Invoke-IgwtManagedChange applies it.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('service', 'task', 'appx', 'feature', 'capability', 'firewallRule')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][string]$Value, [switch]$Provisioned)
    if ($script:IgwtManagedValues[$Kind] -notcontains $Value) { throw "Value '$Value' is not allowed for $Kind (allowed: $($script:IgwtManagedValues[$Kind] -join ', '))." }
    $t = $Target.Trim()
    if (-not $t) { throw 'The target is empty.' }
    switch ($Kind) {
        'service' {
            if ($t -notmatch '^[\w\.\-\$ ]{1,256}$') { throw "'$t' is not a valid service name." }
            $why = Get-IgwtServiceProtection -Name $t
            if ($why) { throw "Service '$t' is protected: $why" }
            $svc = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$($t -replace "'", "''")'" -ErrorAction Stop) | Select-Object -First 1
            if (-not $svc) { throw "Service '$t' does not exist." }
            if ([string]$svc.ServiceType -match '(?i)driver') { throw "'$t' is a driver; iG Windows Tuner only changes Win32 services." }
            return [pscustomobject]@{ type = 'service'; name = [string]$svc.Name; startupType = $Value; default = $Value; stop = $false }
        }
        'task' {
            if ($t -notmatch '^\\') { throw "Give the full task path, for example '\Microsoft\Windows\...\TaskName'." }
            $i = $t.LastIndexOf('\')
            $path = $t.Substring(0, $i + 1); $name = $t.Substring($i + 1)
            if (-not $name) { throw 'The task name is missing.' }
            Assert-IgwtTaskAllowed -Path $path
            if ($t -match $script:IgwtAntiCheatTaskPattern) { throw "Task '$t' belongs to an anti-cheat and is never changed." }
            return [pscustomobject]@{ type = 'scheduledTask'; path = $path; name = $name; on = $Value; default = $(if ($Value -eq 'Disabled') { 'Enabled' } else { 'Disabled' }) }
        }
        'appx' {
            if ($t -notmatch '^[\w\.\-]+$') { throw "'$t' is not a valid package name." }
            if (Test-IgwtAppxProtected -Package $t) { throw "App '$t' is protected (Store, App Installer, Xbox identity, Gaming Services, Windows Security, WebView2, frameworks and shell)." }
            $pkg = @(Get-AppxPackage -Name $t -ErrorAction SilentlyContinue) | Select-Object -First 1
            if ($pkg -and ($pkg.IsFramework -or [string]$pkg.SignatureKind -eq 'System')) { throw "App '$t' is a framework or system component and is never removed." }
            return [pscustomobject]@{ type = 'appx'; package = $t; on = 'Removed'; default = 'Installed'; provisioned = [bool]$Provisioned }
        }
        'feature' {
            if ($t -notmatch '^[\w\.\-]+$') { throw "'$t' is not a valid feature name." }
            if ($Value -eq 'Enabled' -and (Test-IgwtNamePattern -Name $t -Patterns $script:IgwtInsecureFeatures)) { throw "Feature '$t' lowers security (legacy or cleartext component) and is never enabled by iG Windows Tuner." }
            if ($Value -eq 'Disabled' -and (Test-IgwtNamePattern -Name $t -Patterns $script:IgwtProtectedFeatures)) { throw "Feature '$t' is protected (Defender, .NET 4, WSL and virtualization, Print to PDF, search) and is never disabled." }
            return [pscustomobject]@{ type = 'optionalFeature'; feature = $t; on = $Value; default = $(if ($Value -eq 'Enabled') { 'Disabled' } else { 'Enabled' }) }
        }
        'capability' {
            if ($t -notmatch '^[\w\.\-~]+$') { throw "'$t' is not a valid capability name." }
            if ($Value -eq 'Installed' -and (Test-IgwtNamePattern -Name $t -Patterns $script:IgwtInsecureCapabilities)) { throw "Capability '$t' lowers security and is never installed by iG Windows Tuner." }
            if ($Value -eq 'NotPresent' -and (Test-IgwtNamePattern -Name $t -Patterns $script:IgwtProtectedCapabilities)) { throw "Capability '$t' is protected (languages, Notepad, shell components, OpenSSH client) and is never removed." }
            return [pscustomobject]@{ type = 'capability'; name = $t; on = $Value; default = $(if ($Value -eq 'Installed') { 'NotPresent' } else { 'Installed' }) }
        }
        'firewallRule' {
            $rule = @(Get-NetFirewallRule -Name $t -ErrorAction SilentlyContinue) | Select-Object -First 1
            if (-not $rule) { throw "Firewall rule '$t' does not exist." }
            if (Test-IgwtWindowsFirewallRule -Rule $rule) { throw "'$($rule.DisplayName)' is a Windows or iG Windows Tuner rule; the rule browser only changes rules that apps created." }
            return [pscustomobject]@{ type = 'managedFirewallRule'; name = [string]$rule.Name; on = $Value }
        }
    }
}

function Get-IgwtManagedSnapshotData {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action)
    if ([string]$Action.type -eq 'managedFirewallRule') {
        $r = @(Get-NetFirewallRule -Name ([string]$Action.name) -ErrorAction Stop) | Select-Object -First 1
        return @{ enabled = ([string]$r.Enabled -eq 'True') }
    }
    return (Get-IgwtActionSnapshot -Action $Action -Context $null)
}

function Test-IgwtManagedActionOn {
    <# .SYNOPSIS True when the target already has the requested value. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Action)
    if ([string]$Action.type -eq 'managedFirewallRule') {
        $r = @(Get-NetFirewallRule -Name ([string]$Action.name) -ErrorAction Stop) | Select-Object -First 1
        return (([string]$r.Enabled -eq 'True') -eq ([string]$Action.on -eq 'Enabled'))
    }
    $states = @(Get-IgwtActionState -Action $Action -Context $null | ForEach-Object { [string]$_.State })
    return ((Get-IgwtStateRollup -States $states) -eq 'On')
}

function Get-IgwtManagedChangePlan {
    <# .SYNOPSIS Dry run of Invoke-IgwtManagedChange: validates the change (protection rules) and reports whether anything would change. Read-only. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('service', 'task', 'appx', 'feature', 'capability', 'firewallRule')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][string]$Value, [switch]$Provisioned)
    $action = New-IgwtManagedAction -Kind $Kind -Target $Target -Value $Value -Provisioned:$Provisioned
    $already = Test-IgwtManagedActionOn -Action $action
    $current = $null
    if ([string]$action.type -ne 'managedFirewallRule') { $current = @(Get-IgwtActionState -Action $action -Context $null | ForEach-Object { [string]$_.Current }) -join ', ' }
    else { $current = $(if ((Get-IgwtManagedSnapshotData -Action $action).enabled) { 'Enabled' } else { 'Disabled' }) }
    [pscustomobject]@{
        Kind = $Kind; Target = $Target; Value = $Value; Current = $current; HasChange = -not $already
        Change = $(if ($already) { 'Already set; nothing to change.' } else { "$Kind $Target : $current -> $Value" })
        Reversible = $(if ($Kind -eq 'appx') { 'partial (re-registered or reinstalled from the Microsoft Store)' } else { 'full (snapshot)' })
    }
}

function Invoke-IgwtManagedChange {
    <#
    .SYNOPSIS
        Applies one management change after writing a snapshot (operation 'Manage'): service
        startup type, scheduled task enable/disable, inbox app removal (reversible partially:
        re-registered or reinstalled from the Store), optional feature, capability or app firewall
        rule state. Protection rules are checked first.
    .PARAMETER Kind
        service, task, appx, feature, capability or firewallRule.
    .PARAMETER Target
        Service name, full task path, package name, feature, capability or firewall rule name.
    .PARAMETER Value
        Service: Automatic, AutomaticDelayed, Manual, Disabled. Task: Enabled, Disabled. Appx: Removed.
        Feature: Enabled, Disabled. Capability: Installed, NotPresent. Firewall rule: Enabled, Disabled.
    .PARAMETER Provisioned
        Appx: also remove the provisioned copy so new user profiles do not get it.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('service', 'task', 'appx', 'feature', 'capability', 'firewallRule')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][string]$Value, [switch]$Provisioned)
    if (-not $script:IgwtSettings.TestMode) {
        if (-not (Test-IgwtIsAdmin)) { throw 'Management changes need administrator rights.' }
        Initialize-IgwtDataRoot
    }
    $action = New-IgwtManagedAction -Kind $Kind -Target $Target -Value $Value -Provisioned:$Provisioned
    if (Test-IgwtManagedActionOn -Action $action) { return [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @() } }
    $label = "$Kind $Target -> $Value"
    if (-not $PSCmdlet.ShouldProcess($Target, "$Kind -> $Value")) { return [pscustomobject]@{ Snapshot = $null; Changes = 0; Results = @() } }
    $snap = New-IgwtSnapshot -Operation 'Manage' -Detail $label
    Save-IgwtSnapshot -Snapshot $snap
    $tid = "manage:${Kind}:$Target"
    $entryAction = [ordered]@{ index = 0; type = [string]$action.type; fingerprint = "managed|$Kind|$Target"; data = (Get-IgwtManagedSnapshotData -Action $action)
        managed = [ordered]@{ kind = $Kind; target = $Target; value = $Value; provisioned = [bool]$Provisioned } }
    Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions @($entryAction) -Result 'Applied' -Message $label
    try {
        if ([string]$action.type -eq 'managedFirewallRule') { Clear-IgwtCache -Prefix 'fw:' -WhatIf:$false; Set-NetFirewallRule -Name ([string]$action.name) -Enabled $(if ($Value -eq 'Enabled') { 'True' } else { 'False' }) -ErrorAction Stop }
        else { Invoke-IgwtActionApply -Action $action -Context $null -Mode on }
        Write-IgwtLog -Message "Managed change: $label. Snapshot: $($snap.Path)"
        $msg = $(if ($Kind -eq 'service') { 'The new startup type applies from the next start of the service or Windows.' } elseif ($Kind -eq 'appx') { 'Revert re-registers the app or reinstalls it from the Store.' } else { '' })
        return [pscustomobject]@{ Snapshot = $snap.Path; Changes = 1; Results = @([pscustomobject]@{ Target = $Target; Change = $label; Result = 'Applied'; Message = $msg }) }
    } catch {
        Add-IgwtSnapshotEntry -Snapshot $snap -TweakId $tid -Actions @($entryAction) -Result 'Failed' -Message $_.Exception.Message
        Write-IgwtLog -Level Error -Message "Managed change $label failed: $($_.Exception.Message)"
        return [pscustomobject]@{ Snapshot = $snap.Path; Changes = 1; Results = @([pscustomobject]@{ Target = $Target; Change = $label; Result = 'Failed'; Message = $_.Exception.Message }) }
    }
}

function Restore-IgwtManagedSnapshot {
    <#
    .SYNOPSIS
        Reverts a 'Manage' snapshot. Each action is rebuilt from its stored kind, target and value
        and validated again (protected targets are refused); the restore data comes from the file,
        the action definition from code. The current state is captured in a new snapshot first.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $doc = Read-IgwtSnapshot -Path $SnapshotPath
    if ([string]$doc.operation -ne 'Manage') { throw 'This is not a management snapshot.' }
    # A failed change has an Applied and a Failed entry with the same data: restore it once.
    $seen = @{}
    $entries = @($doc.entries | Where-Object { $_ -and [string]$_.result -in 'Applied', 'Failed' } | Where-Object { $k = [string]$_.tweakId; if ($seen.ContainsKey($k)) { $false } else { $seen[$k] = $true; $true } })
    [array]::Reverse($entries)
    $results = New-Object System.Collections.Generic.List[object]
    if ($entries.Count -eq 0 -or -not $PSCmdlet.ShouldProcess("$($entries.Count) change(s) from $(Split-Path $SnapshotPath -Leaf)", 'Revert')) { return [pscustomobject]@{ Snapshot = $null; Results = @() } }
    $undo = New-IgwtSnapshot -Operation 'Manage' -Detail "revert of $(Split-Path $SnapshotPath -Leaf)"
    Save-IgwtSnapshot -Snapshot $undo
    foreach ($e in $entries) {
        $tid = [string]$e.tweakId
        foreach ($a in @($e.actions | Where-Object { $_ })) {
            try {
                $m = $a.managed
                if (-not $m -or $script:IgwtManagedKinds -notcontains [string]$m.kind) { throw 'Snapshot entry has no valid management kind.' }
                $action = New-IgwtManagedAction -Kind ([string]$m.kind) -Target ([string]$m.target) -Value ([string]$m.value) -Provisioned:([bool]$m.provisioned)
                if ([string]$action.type -ne [string]$a.type) { throw 'Snapshot action type does not match its kind.' }
                $current = Get-IgwtManagedSnapshotData -Action $action
                Add-IgwtSnapshotEntry -Snapshot $undo -TweakId $tid -Actions @([ordered]@{ index = 0; type = [string]$action.type; fingerprint = [string]$a.fingerprint; data = $current; managed = $m }) -Result 'Applied' -Message 'before revert'
                if ([string]$action.type -eq 'managedFirewallRule') { Clear-IgwtCache -Prefix 'fw:' -WhatIf:$false; Set-NetFirewallRule -Name ([string]$action.name) -Enabled $(if ([bool]$a.data.enabled) { 'True' } else { 'False' }) -ErrorAction Stop }
                else { Restore-IgwtActionSnapshot -Action $action -Snapshot $a.data -Context $null }
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Reverted'; Message = '' })
            } catch {
                $results.Add([pscustomobject]@{ Id = $tid; Result = 'Failed'; Message = $_.Exception.Message })
                Write-IgwtLog -Level Error -Message "Management revert of ${tid}: $($_.Exception.Message)"
            }
        }
    }
    Write-IgwtLog -Message "Management snapshot $(Split-Path $SnapshotPath -Leaf) reverted. Undo snapshot: $($undo.Path)"
    return [pscustomobject]@{ Snapshot = $undo.Path; Results = $results.ToArray() }
}
