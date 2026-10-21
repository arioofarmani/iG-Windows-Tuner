# StateDetection.ps1
# Reads the real system and rolls each tweak up to On, Off, Partial, NotApplicable,
# ManagedByPolicy or Unknown. Toggles always show actual state, never remembered state.

function New-IgwtContext {
    <#
    .SYNOPSIS
        Collects the runtime facts the engine needs once per operation (hardware, adapters, games).
    .PARAMETER Override
        Hashtable of values to use instead of detection (tests).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([hashtable]$Override)
    Clear-IgwtCache -WhatIf:$false
    $ctx = [ordered]@{
        IsAdmin        = $false
        Build          = 0
        EditionId      = ''
        IsRdp          = $false
        WiredAdapters  = @()
        Games          = @()
        GpuCount       = 0
        HasNvidia      = $false
        HybridCpu      = $false
        DefenderActive = $false
        HardwareTags   = @()
        HardwareProfile = $null
    }
    if ($Override) {
        foreach ($k in $Override.Keys) { $ctx[$k] = $Override[$k] }
        return [pscustomobject]$ctx
    }
    try {
        $hp = Get-IgwtHardwareProfile
        $ctx.HardwareProfile = $hp
        $ctx.HardwareTags = @($hp.Tags)
    } catch { Write-Verbose "Hardware profile unavailable: $($_.Exception.Message)" }
    $ctx.IsAdmin = Test-IgwtIsAdmin
    $os = Get-IgwtOsInfo
    $ctx.Build = $os.Build
    $ctx.EditionId = $os.EditionId
    $ctx.IsRdp = Test-IgwtRdpSession
    try { $ctx.WiredAdapters = @(Get-IgwtActiveWiredAdapter) } catch { $ctx.WiredAdapters = @() }
    try { $ctx.Games = @(Get-IgwtInstalledGames) } catch { $ctx.Games = @() }
    try {
        $gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { $_.PNPDeviceID -like 'PCI\*' })
        $ctx.GpuCount = $gpus.Count
        $ctx.HasNvidia = @($gpus | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_10DE*' }).Count -gt 0
    } catch { Write-Verbose 'GPU detection failed.' }
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $ctx.HybridCpu = ($cpu.Name -match '1[2-9]th Gen Intel|Core\(TM\) Ultra') -and ([int]$cpu.NumberOfLogicalProcessors -lt (2 * [int]$cpu.NumberOfCores))
    } catch { Write-Verbose 'CPU detection failed.' }
    try { $ctx.DefenderActive = Test-IgwtDefenderActive } catch { $ctx.DefenderActive = $false }
    return [pscustomobject]$ctx
}

function Test-IgwtTweakApplicable {
    <# .SYNOPSIS Checks appliesTo (build limits and runtime conditions). Returns Applicable and Reason. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)]$Context)
    if ([string]$Tweak.status -eq 'NotApplicable') { return [pscustomobject]@{ Applicable = $false; Reason = [string]$Tweak.statusReason } }
    $a = $Tweak.appliesTo
    if ($a.minBuild -and $Context.Build -and [int]$Context.Build -lt [int]$a.minBuild) {
        return [pscustomobject]@{ Applicable = $false; Reason = "Requires Windows build $($a.minBuild) or newer." }
    }
    if ($null -ne $a.PSObject.Properties['maxBuild'] -and $a.maxBuild -and [int]$Context.Build -gt [int]$a.maxBuild) {
        return [pscustomobject]@{ Applicable = $false; Reason = "Not honored on builds newer than $($a.maxBuild)." }
    }
    $conds = @($a.conditions | Where-Object { $_ })
    if ($conds -contains 'multipleGpus' -and [int]$Context.GpuCount -lt 2) { return [pscustomobject]@{ Applicable = $false; Reason = 'Only one GPU is active (enable the iGPU in BIOS for this to matter).' } }
    if ($conds -contains 'wiredAdapter' -and @($Context.WiredAdapters).Count -lt 1) { return [pscustomobject]@{ Applicable = $false; Reason = 'No active wired network adapter.' } }
    if ($conds -contains 'nvidiaGpu' -and -not $Context.HasNvidia) { return [pscustomobject]@{ Applicable = $false; Reason = 'No NVIDIA GPU detected.' } }
    if ($conds -contains 'defenderActive' -and -not $Context.DefenderActive) { return [pscustomobject]@{ Applicable = $false; Reason = 'Microsoft Defender Antivirus is not the active antivirus.' } }
    if ($conds -contains 'notRdp' -and $Context.IsRdp) { return [pscustomobject]@{ Applicable = $false; Reason = 'Blocked in a Remote Desktop session (it could cut off this connection).' } }
    # Hardware tags and overlays: blocked items cannot be turned on, but can still be turned off.
    $tags = @()
    if ($null -ne $Context.PSObject.Properties['HardwareTags']) { $tags = @($Context.HardwareTags | Where-Object { $_ }) }
    $block = Get-IgwtHardwareBlock -Tweak $Tweak -Tags $tags
    if ($block) { return [pscustomobject]@{ Applicable = $false; Reason = [string]$block.Reason; Blocked = $true } }
    return [pscustomobject]@{ Applicable = $true; Reason = '' }
}

function Get-IgwtPolicyOverride {
    <# .SYNOPSIS Returns the first Group Policy/MDM value that controls this tweak, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak)
    foreach ($pk in @($Tweak.policyKeys)) {
        if (-not $pk) { continue }
        try {
            $v = Get-IgwtRegistryValue -Path ([string]$pk.path) -Name ([string]$pk.name)
            if ($v.Exists) { return "$($pk.path)\$($pk.name) = $(Format-IgwtRegistryValue -Exists $true -Value $v.Value -Kind $v.Kind)" }
        } catch { Write-Verbose "Policy key check failed: $($_.Exception.Message)" }
    }
    return $null
}

function Get-IgwtStateRollup {
    <# .SYNOPSIS Combines item states into one tweak state. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][string[]]$States)
    $relevant = @($States | Where-Object { $_ -ne 'NotApplicable' })
    if ($relevant.Count -eq 0) { return 'NotApplicable' }
    if ($relevant -contains 'ManagedByPolicy') { return 'ManagedByPolicy' }
    $on = @($relevant | Where-Object { $_ -eq 'On' }).Count
    $off = @($relevant | Where-Object { $_ -eq 'Off' }).Count
    $unknown = @($relevant | Where-Object { $_ -eq 'Unknown' }).Count
    if ($on -eq $relevant.Count) { return 'On' }
    if ($off -eq $relevant.Count) { return 'Off' }
    if ($unknown -eq $relevant.Count) { return 'Unknown' }
    if ($on -gt 0) { return 'Partial' }
    return 'Off'
}

function Get-IgwtActionState {
    <# .SYNOPSIS Dispatches state detection to the action type implementation. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    switch ([string]$Action.type) {
        'registry'           { return @(Get-IgwtRegistryState -Action $Action -Context $Context) }
        'adapterRegistry'    { return @(Get-IgwtRegistryState -Action $Action -Context $Context) }
        'netAdapterPower'    { return @(Get-IgwtRegistryState -Action $Action -Context $Context) }
        'registryListMerge'  { return @(Get-IgwtListMergeState -Action $Action -Context $Context) }
        'powercfgScheme'     { return @(Get-IgwtPowerCfgSchemeState -Action $Action -Context $Context) }
        'powercfgSetting'    { return @(Get-IgwtPowerCfgSettingState -Action $Action -Context $Context) }
        'service'            { return @(Get-IgwtServiceState -Action $Action -Context $Context) }
        'netAdapterAdvanced' { return @(Get-IgwtNetAdapterAdvancedState -Action $Action -Context $Context) }
        'netQosPolicy'       { return @(Get-IgwtNetQosState -Action $Action -Context $Context) }
        'dnsDoh'             { return @(Get-IgwtDnsDohState -Action $Action -Context $Context) }
        'mpPreference'       { return @(Get-IgwtMpPreferenceState -Action $Action -Context $Context) }
        'asrRule'            { return @(Get-IgwtAsrRuleState -Action $Action -Context $Context) }
        'optionalFeature'    { return @(Get-IgwtOptionalFeatureState -Action $Action -Context $Context) }
        'custom'             { $h = Get-IgwtCustomHandler -Name ([string]$Action.handler); return @(& $h.Detect $Action $Context) }
        'check'              { return @(Get-IgwtCheckState -Action $Action -Context $Context) }
        { $_ -in 'storageSense', 'wufbPolicy', 'deviceInterrupt', 'serviceSet' } { return @(Get-IgwtCompositeState -Action $Action -Context $Context) }
        'powercfgAttribute'  { return @(Get-IgwtPowerAttributeState -Action $Action -Context $Context) }
        'powercfgSettingAcDc' { return @(Get-IgwtPowerCfgSettingState -Action $Action -Context $Context) }
        'scheduledTask'      { return @(Get-IgwtScheduledTaskState -Action $Action -Context $Context) }
        'firewallRule'       { return @(Get-IgwtFirewallRuleState -Action $Action -Context $Context) }
        'appx'               { return @(Get-IgwtAppxState -Action $Action -Context $Context) }
        'winget'             { return @(Get-IgwtWingetState -Action $Action -Context $Context) }
        'capability'         { return @(Get-IgwtCapabilityState -Action $Action -Context $Context) }
        { $_ -in 'processMitigation', 'exploitSystem' } { return @(Get-IgwtMitigationState -Action $Action -Context $Context) }
        'cleanerRule'        { return @(Get-IgwtCleanerRuleActionState -Action $Action -Context $Context) }
        default { throw "Unknown action type '$($Action.type)'." }
    }
}

function Get-IgwtTweakState {
    <#
    .SYNOPSIS
        Detects the real state of one tweak. Returns Id, State, Items (per concrete target),
        Applicable, Reason and Policy.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)]$Context)
    $app = Test-IgwtTweakApplicable -Tweak $Tweak -Context $Context
    $blocked = ($null -ne $app.PSObject.Properties['Blocked'] -and $app.Blocked)
    if (-not $app.Applicable -and -not $blocked) {
        return [pscustomobject]@{ Id = $Tweak.id; State = 'NotApplicable'; Items = @(); Applicable = $false; Reason = $app.Reason; Policy = $null; Blocked = $false }
    }
    $items = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($a in @($Tweak.actions)) {
        try {
            foreach ($it in @(Get-IgwtActionState -Action $a -Context $Context)) {
                if ($null -eq $it) { continue }
                $it | Add-Member -NotePropertyName ActionIndex -NotePropertyValue $index -Force
                $it | Add-Member -NotePropertyName ActionType -NotePropertyValue ([string]$a.type) -Force
                $items.Add($it)
            }
        } catch {
            $items.Add([pscustomobject]@{ Target = "$($a.type) action"; Current = 'error'; Desired = ''; State = 'Unknown'; Note = $_.Exception.Message; ActionIndex = $index; ActionType = [string]$a.type })
        }
        $index++
    }
    $policy = Get-IgwtPolicyOverride -Tweak $Tweak
    $state = Get-IgwtStateRollup -States @($items | ForEach-Object { [string]$_.State })
    if ($policy -and $state -ne 'NotApplicable') { $state = 'ManagedByPolicy' }
    $reason = ''
    if ($state -eq 'NotApplicable') { $reason = (@($items | Where-Object { $_.Note } | Select-Object -First 1).Note) }
    if ($state -eq 'ManagedByPolicy') { $reason = "Controlled by Group Policy/MDM: $policy" }
    if ($blocked) {
        # Already applied before the overlay existed: keep the real state so it can be turned off.
        if ($state -in 'On', 'Partial') { return [pscustomobject]@{ Id = $Tweak.id; State = $state; Items = $items.ToArray(); Applicable = $false; Reason = "$($app.Reason) It is currently applied; turning it off is recommended."; Policy = $policy; Blocked = $true } }
        return [pscustomobject]@{ Id = $Tweak.id; State = 'NotApplicable'; Items = @(); Applicable = $false; Reason = $app.Reason; Policy = $null; Blocked = $true }
    }
    return [pscustomobject]@{ Id = $Tweak.id; State = $state; Items = $items.ToArray(); Applicable = $true; Reason = $reason; Policy = $policy; Blocked = $false }
}

function Get-IgwtAllTweakStates {
    <# .SYNOPSIS Detects the state of every tweak (or the given ids). #>
    [CmdletBinding()]
    param([string[]]$Id, $Context)
    if (-not $Context) { $Context = New-IgwtContext }
    $tweaks = Get-IgwtCatalog
    if ($Id) { $tweaks = @($tweaks | Where-Object { $Id -contains $_.id }) }
    foreach ($t in $tweaks) { Get-IgwtTweakState -Tweak $t -Context $Context }
}
