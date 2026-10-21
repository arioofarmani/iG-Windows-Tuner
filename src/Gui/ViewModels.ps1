# ViewModels.ps1
# Data shaping for the WPF GUI. Functions marked "worker" run in the GUI's background runspace
# (they call the engine); the New-IgwtGui*Row functions run on the UI thread and only build
# plain objects for data binding. No tweak logic lives here.

$script:IgwtGlyph = @{
    Pass    = [string][char]0xE73E   # CheckMark
    Fail    = [string][char]0xE711   # Cancel
    Unknown = [string][char]0xE9CE   # Unknown
}
$script:IgwtColor = @{
    Pass = '#FF6CCB5F'; Warn = '#FFFCE100'; Fail = '#FFFF99A4'; Info = '#FF60CDFF'; Unknown = '#FFFCE100'
    Muted = '#FFB9B9B9'; Text = '#FFFFFFFF'; Accent = '#FF60CDFF'
}

#region Worker-side (background runspace)

function Test-IgwtTweakChangedFromDefault {
    <#
    .SYNOPSIS
        Best-effort: does any setting of this tweak currently differ from the documented Windows
        default? Used by the "Changed from default" filter. Read-only.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Tweak, [Parameter(Mandatory = $true)]$State, $Context)
    if ($State.State -eq 'NotApplicable') { return $false }
    foreach ($a in @($Tweak.actions)) {
        try {
            switch ([string]$a.type) {
                { $_ -in 'registry', 'adapterRegistry', 'netAdapterPower' } {
                    $eff = Get-IgwtRegistryActionEffective $a
                    foreach ($t in @(Get-IgwtRegistryTargets -Action $a -Context $Context)) {
                        $cur = Get-IgwtRegistryValue -Path $t.Path -Name $t.Name
                        if ([string]$eff.default -eq $script:IgwtAbsent) {
                            if ($cur.Exists -and -not ($null -ne $eff.absentValue -and (Test-IgwtRegistryValueEqual -Left $cur.Value -Right (ConvertFrom-IgwtSerializableValue -Data $eff.absentValue -Kind $cur.Kind) -Kind $cur.Kind))) { return $true }
                        } elseif ($null -ne $eff.default) {
                            if ($cur.Exists) {
                                if (-not (Test-IgwtRegistryValueEqual -Left $cur.Value -Right (ConvertFrom-IgwtSerializableValue -Data $eff.default -Kind $cur.Kind) -Kind $cur.Kind)) { return $true }
                                if ($eff.valueType -and $cur.Kind -ne [string]$eff.valueType) { return $true }
                            } elseif ($null -ne $eff.absentValue -and [string]$eff.absentValue -ne [string]$eff.default) { return $true }
                        }
                    }
                }
                'registryListMerge' {
                    $cur = Get-IgwtRegistryValue -Path $a.path -Name $a.name
                    $v = $null
                    if ($cur.Exists) { $v = Get-IgwtListItemValue -Text ([string]$cur.Value) -Key $a.item }
                    if ([string]$a.default -eq $script:IgwtRemoveItem) { if ($null -ne $v) { return $true } }
                    elseif ([string]$v -ne [string]$a.default) { return $true }
                }
                'service' {
                    $s = Get-IgwtServiceStartup -Name ([string]$a.name)
                    if ($s -and $s.StartupType -ne [string]$a.default) { return $true }
                }
                'mpPreference' {
                    $v = Get-IgwtMpPreferenceValue -Setting ([string]$a.setting)
                    if ($null -ne $v -and $v -ne (ConvertTo-IgwtMpValue -Setting ([string]$a.setting) -Value $a.default)) { return $true }
                }
                'asrRule' { if ($null -ne (Get-IgwtAsrRuleAction -RuleId ([string]$a.id))) { return $true } }
                'powercfgScheme' { if ((Get-IgwtActivePowerScheme) -ne $script:IgwtSchemeBalanced) { return $true } }
                'netQosPolicy' { if ($State.State -in 'On', 'Partial') { return $true } }
                'dnsDoh' { foreach ($w in @($Context.WiredAdapters)) { if ((Get-IgwtDnsInterfaceConfig -Adapter $w).Static4) { return $true } } }
                'custom' {
                    switch ([string]$a.handler) {
                        { $_ -in 'TcpAutoTuning', 'FirewallProfiles' } { if ($State.State -ne 'On') { return $true } }
                        default { if ($State.State -in 'On', 'Partial') { return $true } }
                    }
                }
                default { }
            }
        } catch { Write-Verbose "Default comparison failed for $($Tweak.id): $($_.Exception.Message)" }
    }
    return $false
}

function Get-IgwtGuiData {
    <#
    .SYNOPSIS
        (worker) Everything the GUI shows, read from the live system in one pass. Read-only.
    .PARAMETER IncludeHealth
        Also run the full health report (slower; used on start and on Refresh).
    #>
    [CmdletBinding()]
    param([switch]$IncludeHealth)
    $ctx = New-IgwtContext
    $states = @{}
    $changed = @{}
    foreach ($t in (Get-IgwtCatalog)) {
        $s = Get-IgwtTweakState -Tweak $t -Context $ctx
        $states[$t.id] = $s
        $changed[$t.id] = (Test-IgwtTweakChangedFromDefault -Tweak $t -State $s -Context $ctx)
    }
    $health = $null
    if ($IncludeHealth) { $health = Get-IgwtHealthReport }
    $ac = $null
    if ($health) { $ac = $health.AntiCheat } else { $ac = Get-IgwtAntiCheatReadiness }
    $startup = @()
    try { $startup = @(Get-IgwtStartupItem) } catch { $startup = @() }
    $hwTags = @($ctx.HardwareTags)
    $hardware = [pscustomobject]@{
        Tags     = @($(if ($ctx.HardwareProfile) { $ctx.HardwareProfile.TagDetails }))
        Overlays = @(Get-IgwtActiveOverlays -Tags $hwTags | ForEach-Object { [pscustomobject]@{ Name = [string]$_.name; Hint = [string]$_.hint; Tags = (@($_.MatchedTags) -join ', '); Guidance = (@($_.guidance | Where-Object { $_ }) -join ' ') } })
    }
    $selections = @{}
    foreach ($p in @(Get-IgwtPreset)) {
        try { $selections[[string]$p.id] = Resolve-IgwtPresetSelection -Preset $p -Tags $hwTags } catch { Write-Verbose "Preset $($p.id) could not be resolved: $($_.Exception.Message)" }
    }
    [pscustomobject]@{
        Hardware   = $hardware
        PresetSelections = $selections
        IsAdmin    = (Test-IgwtIsAdmin)
        Preflight  = (Get-IgwtPreflight)
        Summary    = $(if ($health) { $health.Summary } else { Get-IgwtHardwareSummary })
        Pending    = (Get-IgwtPendingRestartState)
        States     = $states
        Changed    = $changed
        Health     = $health
        AntiCheat  = $ac
        Snapshots  = @(Get-IgwtSnapshotList | Select-Object Path, File, Created, Operation, Detail, Applied, @{ n = 'Count'; e = { @($_.Entries).Count } }, @{ n = 'Failed'; e = { @($_.Entries | Where-Object { $_.result -in 'Failed', 'RolledBack' }).Count } })
        Startup    = $startup
        Games      = @($ctx.Games)
    }
}

function Get-IgwtGuiPreview {
    <#
    .SYNOPSIS
        (worker) Dry-run text for the staged changes. Never changes anything.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]]$ApplyIds = @(), [string[]]$OffIds = @(), [string[]]$ResetIds = @())
    $sb = New-Object System.Text.StringBuilder
    $ctx = New-IgwtContext
    if ($ApplyIds.Count -gt 0) {
        $null = $sb.AppendLine('APPLY')
        foreach ($p in @(Get-IgwtPlan -Id $ApplyIds -Context $ctx)) {
            $null = $sb.AppendLine(("  [{0}] {1} - {2} (Tier {3}, risk {4}{5})" -f $p.Plan, $p.Id, $p.Name, $p.Tier, $p.Risk, $(if ($p.Requires -ne 'none') { ", needs $($p.Requires)" } else { '' })))
            foreach ($i in @($p.Items)) {
                $null = $sb.AppendLine("      $($i.Target)")
                $null = $sb.AppendLine("        $($i.Current)  ->  $($i.Desired)")
                if ($i.Note) { $null = $sb.AppendLine("        note: $($i.Note)") }
            }
            if ($p.Plan -ne 'Change' -and $p.Reason) { $null = $sb.AppendLine("      $($p.Reason)") }
        }
    }
    $resetAll = @($ResetIds)
    if ($OffIds.Count -gt 0) {
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine('TURN OFF')
        foreach ($id in $OffIds) {
            $found = Find-IgwtLatestSnapshotEntry -TweakId $id
            if ($found) { $null = $sb.AppendLine("  [Revert] $id - restores the exact values captured in $(Split-Path $found.Path -Leaf)") }
            else { $null = $sb.AppendLine("  [Reset]  $id - no iG Windows Tuner snapshot exists, so documented Windows defaults are restored"); $resetAll += $id }
        }
    }
    if ($resetAll.Count -gt 0) {
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine('RESET TO WINDOWS DEFAULT')
        foreach ($t in @(Get-IgwtTweak -Id ($resetAll | Select-Object -Unique))) {
            $null = $sb.AppendLine("  $($t.id) - $($t.name)")
            foreach ($a in @($t.actions)) {
                switch ([string]$a.type) {
                    { $_ -in 'registry', 'adapterRegistry' } {
                        foreach ($tg in @(Get-IgwtRegistryTargets -Action $a -Context $ctx)) {
                            $cur = Get-IgwtRegistryValue -Path $tg.Path -Name $tg.Name
                            $null = $sb.AppendLine("      $($tg.Path)\$($tg.Name)")
                            $null = $sb.AppendLine("        $(Format-IgwtRegistryValue -Exists $cur.Exists -Value $cur.Value -Kind $cur.Kind)  ->  default $($a.default)")
                        }
                    }
                    'check' { }
                    default { $null = $sb.AppendLine("      $($a.type): restore the documented default ($(Get-IgwtActionFingerprint $a))") }
                }
            }
        }
    }
    if ($sb.Length -eq 0) { $null = $sb.AppendLine('Nothing staged.') }
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('Before applying, iG Windows Tuner creates a System Restore point and a JSON snapshot of every value listed above.')
    return $sb.ToString()
}

function Invoke-IgwtGuiBatch {
    <#
    .SYNOPSIS
        (worker) Applies the GUI's staged changes: applies, turn-offs (revert from snapshot when one
        exists, otherwise reset to default) and resets. One restore point for the whole batch.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$ApplyIds = @(), [string[]]$OffIds = @(), [string[]]$ResetIds = @(),
        [string]$Operation = 'Apply', [switch]$SkipRestorePoint, [switch]$EnableSystemProtection, [switch]$AcknowledgeRisk
    )
    if (-not $PSCmdlet.ShouldProcess('staged changes', 'Apply')) { return $null }
    $results = New-Object System.Collections.Generic.List[object]
    $snapshots = New-Object System.Collections.Generic.List[string]
    $requires = 'none'
    $rp = $null
    $skip = [bool]$SkipRestorePoint
    $revertIds = @()
    $resetAll = @($ResetIds)
    foreach ($id in $OffIds) {
        if (Find-IgwtLatestSnapshotEntry -TweakId $id) { $revertIds += $id } else { $resetAll += $id }
    }
    $merge = {
        param($r)
        if (-not $r) { return }
        foreach ($x in @($r.Results)) { $results.Add($x) }
        if ($r.Snapshot) { $snapshots.Add([string]$r.Snapshot) }
    }
    try {
        if ($ApplyIds.Count -gt 0) {
            $r = Invoke-IgwtApply -Id $ApplyIds -Operation $Operation -SkipRestorePoint:$skip -EnableSystemProtection:$EnableSystemProtection -AcknowledgeRisk:$AcknowledgeRisk
            $rp = $r.RestorePoint
            & $merge $r
            $skip = $true
        }
        if ($resetAll.Count -gt 0) {
            $r = Invoke-IgwtApply -Id ($resetAll | Select-Object -Unique) -Operation 'ResetDefault' -Mode default -SkipRestorePoint:$skip -EnableSystemProtection:$EnableSystemProtection -AcknowledgeRisk
            if (-not $rp) { $rp = $r.RestorePoint }
            & $merge $r
            $skip = $true
        }
        if ($revertIds.Count -gt 0) {
            $r = Invoke-IgwtRevert -Id $revertIds
            & $merge $r
        }
    } catch {
        $results.Add([pscustomobject]@{ Id = '(batch)'; Result = 'Failed'; Message = $_.Exception.Message })
        Write-IgwtLog -Level Error -Message "GUI batch failed: $($_.Exception.Message)"
    }
    $done = @($results | Where-Object { $_.Result -in 'Applied', 'Reverted' -and $_.PSObject.Properties['Requires'] })
    if (@($done | Where-Object { $_.Requires -eq 'reboot' }).Count -gt 0) { $requires = 'reboot' }
    elseif (@($done | Where-Object { $_.Requires -eq 'logoff' }).Count -gt 0) { $requires = 'logoff' }
    [pscustomobject]@{ Results = $results.ToArray(); Snapshots = $snapshots.ToArray(); Requires = $requires; RestorePoint = $rp }
}

function Export-IgwtGuiReport {
    <# .SYNOPSIS (worker) Writes the HTML health report to the Reports folder and returns its path. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $dir = Get-IgwtDataPath -Kind Reports
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $path = Join-Path $dir ("iGWindowsTuner-report-{0}.html" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    if (-not $PSCmdlet.ShouldProcess($path, 'Write report')) { return $null }
    return (Export-IgwtHealthReport -Report (Get-IgwtHealthReport) -Path $path -Format Html)
}

function Get-IgwtGuiManageData {
    <# .SYNOPSIS (worker) Read-only data for the Manage page: services, tasks, apps, persistence and app firewall rules. Each part reports its own error. #>
    [CmdletBinding()]
    param()
    $part = { param($block) try { & $block } catch { [pscustomobject]@{ Error = $_.Exception.Message } } }
    [pscustomobject]@{
        Services    = & $part { Get-IgwtServiceInventory }
        Tasks       = & $part { Get-IgwtTaskInventory }
        Apps        = & $part { Get-IgwtAppInventory }
        Persistence = & $part { Get-IgwtPersistenceInventory }
        Firewall    = & $part { Get-IgwtFirewallRuleList }
        Hosts       = & $part { Get-IgwtHostsFile }
    }
}

function Get-IgwtGuiDiagnosticsData {
    <# .SYNOPSIS (worker) Read-only data for the Diagnostics page: diagnostics, Windows Update status and adapter properties. #>
    [CmdletBinding()]
    param([int]$Days = 30)
    $part = { param($block) try { & $block } catch { [pscustomobject]@{ Error = $_.Exception.Message } } }
    [pscustomobject]@{
        Diagnostics = & $part { Get-IgwtDiagnostics -Days $Days -Samples 3 }
        Updates     = & $part { Get-IgwtUpdateStatus }
        Adapters    = & $part { Get-IgwtAdapterPropertyInspection }
    }
}

function Export-IgwtGuiSystemReport {
    <# .SYNOPSIS (worker) Writes the full system report (HTML) to the Reports folder and returns its path. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$Quick)
    $dir = Get-IgwtDataPath -Kind Reports
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $path = Join-Path $dir ("iGWindowsTuner-system-report-{0}.html" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    if (-not $PSCmdlet.ShouldProcess($path, 'Write system report')) { return $null }
    return (Export-IgwtSystemReport -Report (Get-IgwtSystemReport -Quick:$Quick) -Path $path -Format Html)
}

#endregion

#region UI-side row builders

function New-IgwtGuiManageRow {
    <# .SYNOPSIS Generic bindable row for the Manage and Diagnostics lists (title, subtitle, state with color, tooltip, source object). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([string]$Title, [string]$Subtitle, [string]$State, [string]$Badge, [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Muted', 'Text')][string]$Tone = 'Text', [string]$Tip, $Source)
    [pscustomobject]@{ Title = $Title; Subtitle = $Subtitle; State = $State; Badge = $Badge; StateBrush = $script:IgwtColor[$Tone]; Tip = $(if ($Tip) { $Tip } else { $Subtitle }); Source = $Source }
}

function New-IgwtGuiTweakRow {
    <# .SYNOPSIS Bindable row for one tweak (state + staging). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, $State, [bool]$Changed, [string]$Staged, [bool]$IsAdmin)
    $stateName = 'Unknown'
    if ($State) { $stateName = [string]$State.State }
    $isOn = ($stateName -eq 'On')
    $desired = $isOn
    if ($Staged -eq 'on') { $desired = $true }
    elseif ($Staged -in 'off', 'reset') { $desired = $false }
    $canToggle = $IsAdmin -and ($stateName -in 'On', 'Off', 'Partial')
    $stateText = switch ($stateName) {
        'On' { 'On' } 'Off' { 'Off' } 'Partial' { 'Partial' } 'NotApplicable' { 'Not applicable' }
        'ManagedByPolicy' { 'Managed by policy' } default { 'Unknown' }
    }
    $stateBrush = switch ($stateName) {
        'On' { $script:IgwtColor.Pass } 'Partial' { $script:IgwtColor.Warn } 'ManagedByPolicy' { $script:IgwtColor.Info }
        'NotApplicable' { $script:IgwtColor.Muted } 'Off' { $script:IgwtColor.Muted } default { $script:IgwtColor.Warn }
    }
    $stateTip = ''
    if ($State -and $State.Reason) { $stateTip = [string]$State.Reason }
    $toggleTip = [string]$Tweak.hint
    if (-not $IsAdmin) { $toggleTip = 'Read-only mode: restart as administrator to stage changes.' }
    elseif (-not $canToggle) { $toggleTip = "Cannot be changed here: $stateText. $stateTip" }
    $pending = ''
    switch ($Staged) { 'on' { $pending = 'Pending: apply' } 'off' { $pending = 'Pending: turn off' } 'reset' { $pending = 'Pending: reset' } }
    $restart = ''
    if ($Tweak.requires -eq 'reboot') { $restart = 'Reboot' } elseif ($Tweak.requires -eq 'logoff') { $restart = 'Sign out' }
    $tier = [string]$Tweak.evidence.tier
    [pscustomobject]@{
        Id                = [string]$Tweak.id
        Name              = $(if ($Tweak.expert) { "$($Tweak.name)" } else { [string]$Tweak.name })
        Category          = [string]$Tweak.category
        Group             = [string]$Tweak.group
        Hint              = [string]$Tweak.hint
        Tier              = $tier
        TierText          = "Tier $tier"
        TierBrush         = $(if ($tier -eq 'A') { $script:IgwtColor.Pass } else { $script:IgwtColor.Warn })
        Risk              = [string]$Tweak.risk
        RiskText          = "Risk $($Tweak.risk)"
        RiskBrush         = $(switch ([string]$Tweak.risk) { 'low' { $script:IgwtColor.Muted } 'medium' { $script:IgwtColor.Warn } default { $script:IgwtColor.Fail } })
        Requires          = [string]$Tweak.requires
        RestartText       = $restart
        RestartVisibility = $(if ($restart) { 'Visible' } else { 'Collapsed' })
        AcText            = $(if ($Tweak.antiCheatText) { [string]$Tweak.antiCheatText } elseif ($Tweak.antiCheatSafe) { 'Anti-cheat safe' } else { 'Breaks anti-cheat' })
        AcBrush           = $(if ($Tweak.antiCheatSafe) { $script:IgwtColor.Pass } else { $script:IgwtColor.Fail })
        Level             = [string]$Tweak.level
        LevelText         = [string]$Tweak.level
        LevelBrush        = $(switch ([string]$Tweak.level) { 'Advanced' { $script:IgwtColor.Info } 'Expert' { $script:IgwtColor.Warn } 'Lab' { $script:IgwtColor.Fail } default { $script:IgwtColor.Muted } })
        LevelVisibility   = $(if ([string]$Tweak.level -and [string]$Tweak.level -ne 'Standard') { 'Visible' } else { 'Collapsed' })
        Expert            = [bool]$Tweak.expert
        State             = $stateName
        StateText         = $stateText
        StateBrush        = $stateBrush
        StateTip          = $(if ($stateTip) { $stateTip } else { $stateText })
        Desired           = $desired
        CanToggle         = $canToggle
        ToggleTip         = $toggleTip
        Staged            = $Staged
        PendingText       = $pending
        PendingVisibility = $(if ($pending) { 'Visible' } else { 'Collapsed' })
        Changed           = $Changed
    }
}

function Test-IgwtGuiRowVisible {
    <# .SYNOPSIS Applies page, search text and filter checkboxes to a row. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Row, [string]$Category, [string]$Search, [hashtable]$Filter)
    if ($Search) {
        $s = $Search.Trim()
        if ($Row.Name -notlike "*$s*" -and $Row.Hint -notlike "*$s*" -and $Row.Id -notlike "*$s*") { return $false }
    } elseif ($Category -and $Row.Category -ne $Category) { return $false }
    if (-not $Filter.TierA -and $Row.Tier -eq 'A') { return $false }
    if (-not $Filter.TierB -and $Row.Tier -eq 'B') { return $false }
    if (-not $Filter.RiskLow -and $Row.Risk -eq 'low') { return $false }
    if (-not $Filter.RiskMedium -and $Row.Risk -eq 'medium') { return $false }
    if (-not $Filter.RiskHigh -and $Row.Risk -eq 'high') { return $false }
    if ($Filter.Restart -and $Row.Requires -eq 'none') { return $false }
    if ($Filter.Changed -and -not $Row.Changed) { return $false }
    return $true
}

function New-IgwtGuiCheckRow {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Check)
    $brush = $script:IgwtColor.Info
    switch ([string]$Check.Status) { 'Pass' { $brush = $script:IgwtColor.Pass } 'Warn' { $brush = $script:IgwtColor.Warn } 'Fail' { $brush = $script:IgwtColor.Fail } 'Unknown' { $brush = $script:IgwtColor.Warn } }
    [pscustomobject]@{
        Status = [string]$Check.Status; Brush = $brush; Section = [string]$Check.Section; Name = [string]$Check.Name; Value = [string]$Check.Value
        Detail = [string]$Check.Detail; Advice = [string]$Check.Advice; AdviceVisibility = $(if ($Check.Advice) { 'Visible' } else { 'Collapsed' })
    }
}

function New-IgwtGuiRequirementRow {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Requirement)
    $kind = 'Fail'
    if ($Requirement.Unknown) { $kind = 'Unknown' } elseif ($Requirement.Pass) { $kind = 'Pass' }
    [pscustomobject]@{ Name = [string]$Requirement.Name; Detail = $(if ($Requirement.Detail) { [string]$Requirement.Detail } else { [string]$Requirement.Name }); Glyph = $script:IgwtGlyph[$kind]; Brush = $script:IgwtColor[$kind] }
}

function New-IgwtGuiMatrixRow {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)
    $kind = [string]$Entry.Status
    $missing = ''
    if (@($Entry.Missing).Count) { $missing = "Missing: $(@($Entry.Missing) -join ', ')" }
    elseif (@($Entry.Unknown).Count) { $missing = "Unverified: $(@($Entry.Unknown) -join ', ')" }
    else { $missing = 'All requirements met' }
    [pscustomobject]@{ Name = [string]$Entry.Name; Missing = $missing; Note = [string]$Entry.Note; Glyph = $script:IgwtGlyph[$kind]; Brush = $script:IgwtColor[$kind] }
}

function New-IgwtGuiCleanerRow {
    <# .SYNOPSIS Bindable row for one cleaner rule scan result. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$RuleScan, $Rule, [bool]$Selected)
    $status = [string]$RuleScan.Status
    $canSelect = $status -in 'Ready', 'RequiresClose'
    $statusText = switch ($status) {
        'Ready' { 'Ready to clean' } 'Empty' { 'Nothing to clean' } 'NotPresent' { 'Not on this PC' } 'Refused' { 'Protected location' }
        'GuidanceOnly' { 'Guidance only' } 'RequiresAdmin' { 'Needs administrator' } 'RequiresClose' { 'Close the app first' }
        'Cancelled' { 'Cancelled' } 'Error' { 'Error' } default { $status }
    }
    $statusBrush = switch ($status) {
        'Ready' { $script:IgwtColor.Accent } 'RequiresClose' { $script:IgwtColor.Warn } 'RequiresAdmin' { $script:IgwtColor.Warn }
        'Error' { $script:IgwtColor.Fail } 'Empty' { $script:IgwtColor.Pass } default { $script:IgwtColor.Muted }
    }
    $levelBrush = switch ([string]$RuleScan.Level) { 'Advanced' { $script:IgwtColor.Warn } 'Expert' { $script:IgwtColor.Fail } default { $script:IgwtColor.Muted } }
    $selectTip = [string]$RuleScan.Hint
    if (-not $canSelect) { $selectTip = "Cannot be cleaned now: $statusText. $($RuleScan.Reason)" }
    $tip = New-Object System.Collections.Generic.List[string]
    if ($Rule) { $tip.Add([string]$Rule.description) }
    if ($RuleScan.SideEffects) { $tip.Add("Side effects: $($RuleScan.SideEffects)") }
    if (@($RuleScan.Samples).Count) { $tip.Add('Largest items: ' + (@($RuleScan.Samples | Select-Object -First 5) -join '; ')) }
    if ($RuleScan.Skipped -and $RuleScan.Skipped.Count) { $tip.Add('Skipped: ' + (@($RuleScan.Skipped.GetEnumerator() | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join '; ')) }
    $count = ''
    if ([int]$RuleScan.Count -gt 0) { $count = "$($RuleScan.Count) item(s)" }
    [pscustomobject]@{
        Id              = [string]$RuleScan.RuleId
        Name            = [string]$RuleScan.Name
        Hint            = [string]$RuleScan.Hint
        Category        = [string]$RuleScan.Category
        Level           = [string]$RuleScan.Level
        LevelBrush      = $levelBrush
        OptInVisibility = $(if ($RuleScan.Default) { 'Collapsed' } else { 'Visible' })
        Reason          = [string]$RuleScan.Reason
        Status          = $status
        StatusText      = $statusText
        StatusBrush     = $statusBrush
        Bytes           = [long]$RuleScan.Bytes
        SizeText        = $(if ([long]$RuleScan.Bytes -gt 0) { Format-IgwtBytes $RuleScan.Bytes } else { '-' })
        CountText       = $count
        Selected        = ($Selected -and $canSelect)
        CanSelect       = $canSelect
        SelectTip       = $selectTip
        Tip             = ($tip -join [Environment]::NewLine)
    }
}

function New-IgwtGuiAsrRow {
    <# .SYNOPSIS Bindable row for one ASR rule (from Get-IgwtAsrStatus). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule)
    $modeText = switch ([string]$Rule.Mode) { 'NotConfigured' { 'Not configured' } 'Off' { 'Off (explicit)' } default { [string]$Rule.Mode } }
    $modeBrush = switch ([string]$Rule.Mode) { 'Block' { $script:IgwtColor.Pass } 'Warn' { $script:IgwtColor.Pass } 'Audit' { $script:IgwtColor.Accent } 'Off' { $script:IgwtColor.Warn } default { $script:IgwtColor.Muted } }
    $impactBrush = switch ([string]$Rule.GamerImpactLevel) { 'medium' { $script:IgwtColor.Warn } 'high' { $script:IgwtColor.Fail } 'low' { $script:IgwtColor.Accent } default { $script:IgwtColor.Pass } }
    $flags = New-Object System.Collections.Generic.List[string]
    if ($Rule.ManagedByPolicy) { $flags.Add("Managed by $($Rule.Source)") }
    if ($Rule.ServerOnly) { $flags.Add('Servers only') }
    if ($Rule.RequiresCloud) { $flags.Add($(if ($Rule.CloudMissing) { 'Needs cloud protection (off)' } else { 'Uses cloud protection' })) }
    if ($Rule.AppliesTo -eq 'office') { $flags.Add('Office') } elseif ($Rule.AppliesTo -eq 'adobe') { $flags.Add('Adobe Reader') }
    $rec = ''
    if ($Rule.ServerOnly) { $rec = 'Not applicable' }
    elseif (-not $Rule.MeetsRecommendation) { $rec = "Recommended: $($Rule.Recommended)" }
    else { $rec = 'Meets recommendation' }
    $excl = @($Rule.Exclusions).Count
    [pscustomobject]@{
        Id                  = [string]$Rule.Id
        Key                 = [string]$Rule.Key
        Name                = [string]$Rule.Name
        Hint                = [string]$Rule.Hint
        CategoryText        = $(if ($Rule.Category -eq 'standard') { 'Standard protection' } else { [string]$Rule.MsCategory })
        ImpactText          = "Gamer impact: $($Rule.GamerImpactLevel)"
        ImpactBrush         = $impactBrush
        FlagText            = ($flags -join ' | ')
        FlagVisibility      = $(if ($flags.Count) { 'Visible' } else { 'Collapsed' })
        ExclusionText       = "$excl exclusion(s)"
        ExclusionVisibility = $(if ($excl) { 'Visible' } else { 'Collapsed' })
        ModeText            = $modeText
        ModeBrush           = $modeBrush
        RecommendText       = $rec
        Rule                = $Rule
    }
}

function New-IgwtGuiAsrAuditRow {
    <# .SYNOPSIS Bindable rows for the ASR audit view: one per program a rule reported, plus rule-level advice. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Audit)
    foreach ($r in @($Audit.Rules)) {
        foreach ($p in @($r.Programs)) {
            [pscustomobject]@{
                Title     = $(if ($p.Path) { [string]$p.Path } else { '(no path)' })
                Subtitle  = "$($r.Name)$(if ($p.Process) { "  |  process: $($p.Process)" })"
                Advice    = "$($p.Suggestion): $($p.Reason)"
                CountText = ("{0}x, last {1}" -f $p.Count, $(if ($p.LastSeen) { ([datetime]$p.LastSeen).ToString('MM-dd HH:mm') } else { '-' }))
                Tip       = "Blocked $($p.Blocked), audited $($p.Audited), warn bypassed $($p.WarnBypassed)."
                RuleId    = [string]$r.Id
                Exclusion = [string]$p.Exclusion
            }
        }
        if ($r.Recommendation -in 'PromoteToBlock', 'PromoteToWarn', 'KeepAuditing', 'ReviewPrograms', 'ReviewBlocks') {
            [pscustomobject]@{
                Title = [string]$r.Name; Subtitle = "Mode: $($r.Mode)"; Advice = "$($r.Recommendation): $($r.RecommendationText)"
                CountText = $(if ($r.Total) { "$($r.Total) event(s)" } else { 'no events' }); Tip = [string]$r.RecommendationText; RuleId = [string]$r.Id; Exclusion = ''
            }
        }
    }
    foreach ($c in @($Audit.ControlledFolderAccess)) {
        [pscustomobject]@{
            Title = [string]$c.Process; Subtitle = "Controlled folder access  |  last file: $($c.LastPath)"; Advice = [string]$c.Advice
            CountText = ("{0}x, last {1}" -f $c.Count, $(if ($c.LastSeen) { ([datetime]$c.LastSeen).ToString('MM-dd HH:mm') } else { '-' })); Tip = "Blocked $($c.Blocked), audited $($c.Audited)."; RuleId = ''; Exclusion = ''
        }
    }
    foreach ($n in @($Audit.NetworkProtection)) {
        [pscustomobject]@{
            Title = [string]$n.Process; Subtitle = "Network protection  |  $($n.LastDetail)"; Advice = 'A connection to a site with a bad reputation was audited or blocked.'
            CountText = ("{0}x" -f $n.Count); Tip = "Blocked $($n.Blocked), audited $($n.Audited)."; RuleId = ''; Exclusion = ''
        }
    }
}

function New-IgwtGuiSecurityCheckRow {
    <# .SYNOPSIS Bindable row for one open security score check, with its fix route. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Check)
    $brush = switch ([string]$Check.Status) { 'Pass' { $script:IgwtColor.Pass } 'Warn' { $script:IgwtColor.Warn } 'Fail' { $script:IgwtColor.Fail } default { $script:IgwtColor.Muted } }
    $route = switch ([string]$Check.Fix) { 'Tweak' { "Fix: $($Check.Target)" } 'AsrCenter' { 'Fix: ASR Center' } 'None' { '' } default { "Fix: $($Check.Target)" } }
    [pscustomobject]@{ Status = [string]$Check.Status; Brush = $brush; Name = [string]$Check.Name; Value = [string]$Check.Value; Route = $route; Hint = [string]$Check.Hint }
}

function New-IgwtGuiPowerRow {
    <# .SYNOPSIS Bindable row for one power setting of the power plan inspector. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Setting)
    $state = New-Object System.Collections.Generic.List[string]
    $brush = $script:IgwtColor.Muted
    if ($Setting.Blocked) { $state.Add('Blocked here'); $brush = $script:IgwtColor.Warn }
    elseif ($Setting.Editable) { $state.Add("Editable ($($Setting.Level))"); $brush = $script:IgwtColor.Accent }
    if ($Setting.ChangedFromDefault) { $state.Add('Differs from default') }
    if ($Setting.Hidden) { $state.Add('Hidden') }
    $tip = New-Object System.Collections.Generic.List[string]
    if ($Setting.Description) { $tip.Add([string]$Setting.Description) }
    if ($null -ne $Setting.DefaultAC) { $tip.Add("Default ($($Setting.DefaultSource)): AC $($Setting.DefaultAC), DC $($Setting.DefaultDC)") }
    if (@($Setting.Options).Count) { $tip.Add('Values: ' + (@($Setting.Options | ForEach-Object { "$($_.Index) $($_.Name)" }) -join ', ')) }
    elseif ($null -ne $Setting.Min) { $tip.Add("Range $($Setting.Min)-$($Setting.Max) $($Setting.Units)") }
    if ($Setting.BlockReason) { $tip.Add([string]$Setting.BlockReason) }
    [pscustomobject]@{
        Alias = $(if ($Setting.Alias) { [string]$Setting.Alias } else { [string]$Setting.Guid }); Name = [string]$Setting.Name
        AcText = "AC $($Setting.AcText)"; DcText = "DC $($Setting.DcText)"; StateText = ($state -join ' | '); StateBrush = $brush
        Tip = ($tip -join [Environment]::NewLine); Setting = $Setting
    }
}

function New-IgwtGuiIrqRow {
    <# .SYNOPSIS Bindable row for one device of the interrupt inspector. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Device)
    $mode = switch ([string]$Device.CurrentMode) { 'Message-signaled' { "MSI, $($Device.Messages) message(s)" } 'Line-based' { "Line-based (IRQ $(@($Device.Irqs) -join ', '))" } default { 'No interrupt assigned' } }
    $brush = switch ([string]$Device.CurrentMode) { 'Message-signaled' { $script:IgwtColor.Pass } 'Line-based' { $script:IgwtColor.Muted } default { $script:IgwtColor.Muted } }
    $policy = "$($Device.PolicyName); priority $($Device.PriorityName)"
    if (@($Device.TargetCpus).Count) { $policy += "; CPUs $(@($Device.TargetCpus) -join ',')" }
    [pscustomobject]@{
        Name = "$($Device.Name)  [$($Device.Class)]"; Note = [string]$Device.Note; ModeText = $mode; ModeBrush = $brush
        SupportsText = "Supports: $(if (@($Device.Supports).Count) { @($Device.Supports) -join ', ' } else { 'not reported' })$(if ($Device.MessageMaximum) { "; up to $($Device.MessageMaximum) messages" })"
        PolicyText = $policy
        Tip = "Instance: $($Device.InstanceId)`nMSISupported: $(if ($null -ne $Device.MsiSupported) { $Device.MsiSupported } else { 'not set' }); MessageNumberLimit: $(if ($null -ne $Device.MessageLimit) { $Device.MessageLimit } else { 'not set' })"
    }
}

function New-IgwtGuiNicRow {
    <# .SYNOPSIS Bindable card for one adapter of the NIC queue inspector. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Adapter)
    $q = { param($v) if ($null -eq $v -or [string]$v -eq '') { '?' } else { [string]$v } }
    [pscustomobject]@{
        Title   = "$($Adapter.Name) - $($Adapter.Description) ($($Adapter.LinkSpeed))"
        Rss     = "RSS $(if ($null -eq $Adapter.RssEnabled) { 'unknown' } elseif ($Adapter.RssEnabled) { 'on' } else { 'off' }); base processor $(& $q $Adapter.BaseProcessor); max processor $(& $q $Adapter.MaxProcessor); receive queues $(& $q $Adapter.ReceiveQueues)$(if ($Adapter.RssProfile) { "; profile $($Adapter.RssProfile)" })"
        Buffers = "Receive buffers $(if ($Adapter.ReceiveBuffers) { "$($Adapter.ReceiveBuffers.Value) (range $($Adapter.ReceiveBuffers.Min)-$($Adapter.ReceiveBuffers.Max))" } else { 'not exposed' }); transmit buffers $(if ($Adapter.TransmitBuffers) { $Adapter.TransmitBuffers.Value } else { 'not exposed' }); discarded received packets $(& $q $Adapter.DiscardedPackets)"
        Advice  = (@($Adapter.Advice) -join [Environment]::NewLine)
    }
}

function New-IgwtGuiKernelRow {
    <# .SYNOPSIS Bindable row for one registry value of the kernel and memory inspector. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Key)
    $brush = switch ([string]$Value.Status) { 'Changed' { $script:IgwtColor.Warn } 'Default' { $script:IgwtColor.Pass } 'Absent' { $script:IgwtColor.Muted } default { $script:IgwtColor.Muted } }
    $link = ''
    if ($Value.Item) { $link = "Change through catalog item $($Value.Item)" } elseif ($Value.Rejected) { $link = "Explained in $($Value.Rejected) (not changed by iG Windows Tuner)" }
    [pscustomobject]@{
        Name = [string]$Value.Name; Key = $Key; Meaning = [string]$Value.Meaning; Link = $link; Current = [string]$Value.Current
        DefaultText = $(if ($Value.Default) { "Windows default: $($Value.Default)" } else { '' }); Status = [string]$Value.Status; StatusBrush = $brush
        Tip = ([string]$Value.Meaning + $(if (@($Value.Sources).Count) { "`n" + (@($Value.Sources) -join "`n") } else { '' }))
    }
}

function New-IgwtGuiDiskRow {
    <# .SYNOPSIS Bindable row for one folder or file of a disk analysis. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [long]$Bytes, [long]$Largest, [string]$Extra, [switch]$IsFolder)
    $leaf = Split-Path -Path $Path -Leaf
    if (-not $leaf) { $leaf = $Path }
    $parent = Split-Path -Path $Path -Parent
    $detail = $parent
    if ($Extra) { $detail = "$Extra  |  $parent" }
    [pscustomobject]@{
        Path     = $Path
        Name     = $leaf
        Detail   = $detail
        Bytes    = $Bytes
        SizeText = (Format-IgwtBytes $Bytes)
        Share    = $(if ($Largest -gt 0) { [Math]::Round(100.0 * $Bytes / $Largest, 1) } else { 0 })
        IsFolder = [bool]$IsFolder
    }
}

function Get-IgwtAboutText {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (@(
            "iG Windows Tuner $script:IgwtVersion tunes Windows 11 Pro for competitive online gaming (lower input and network latency, steadier frametimes) while keeping or raising security and staying compatible with kernel anti-cheat (FACEIT, Riot Vanguard, Easy Anti-Cheat, BattlEye, RICOCHET, Javelin).",
            '',
            'How it works: every change is declared in data\tweaks\*.json with a source, a Windows default and a revert path. The toggles always show the real current state. Applying creates a System Restore point and a JSON snapshot of every value first; each tweak is applied atomically and rolled back on error.',
            '',
            'What it never does: edit BCD (no bcdedit), enable test signing, disable driver signature enforcement, touch Secure Boot, TPM, firmware, voltages or power limits, inject into games, change anti-cheat services, disable Defender/Tamper Protection/AMSI/ETW, add Defender exclusions, create scheduled tasks, services, Run keys or other persistence, download anything, or change your machine or user execution policy.',
            '',
            'Evidence tiers: Tier A = documented by Microsoft or the vendor; Tier B = real but situational (measure before and after). Popular tweaks that are placebo, obsolete or security-reducing are listed on the Rejected Tweaks page with the reason.',
            '',
            'Files: backups in %ProgramData%\iGWindowsTuner\Backups, logs in %ProgramData%\iGWindowsTuner\Logs. See docs\README.md, docs\SECURITY.md and docs\TESTING.md.'
        ) -join [Environment]::NewLine)
}

#endregion
