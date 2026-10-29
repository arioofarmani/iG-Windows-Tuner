# FirewallPage.ps1
# Security > Firewall: the Firewall Manager page (3.4: Overview home, group sidebar and classified rules
# in FirewallHome.ps1). Rules in a SmartGrid (every column and quick
# filter of the spec, risk views), a details pane with the rule actions, the new-rule wizard and the
# edit form, import with preview, exports, and the Profiles and networks tab. Every change goes
# through the engine (Invoke-IgwtFirewallChange and friends): summary first, snapshot, Undo toast;
# in a remote session the change is reverted automatically unless it is kept within 60 seconds.
# After a change only the affected rules are read again.

$script:IgwtFirewallSourceLabel = @{ Windows = 'Windows'; ThirdParty = 'Third-party app'; StoreApp = 'Store app'; Owned = 'iG Windows Tuner'; GroupPolicy = 'Group Policy / MDM' }
#region Rows

function New-IgwtGuiFirewallRow {
    <# .SYNOPSIS SmartGrid row for one firewall rule (engine row in .Rule). Never throws on unexpected values. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rule)
    $r = $Rule
    $profiles = @($r.ProfileList | Where-Object { $_ })
    $match = $(if ($profiles -contains 'Any' -or $profiles.Count -eq 0) { @('Domain', 'Private', 'Public', 'Any') } else { $profiles })
    $open = @($r.Findings | Where-Object { $_ -and -not $_.Ignored })
    $rank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $top = [string]$r.RiskLevel
    $proto = [string]$r.Protocol
    $row = [ordered]@{
        Key = [string]$r.Name; Rule = $r; DisplayName = [string]$r.DisplayName; Name = [string]$r.Name; Group = [string]$r.Group
        Direction = [string]$r.Direction; DirectionText = $(if ($r.PSObject.Properties['DirectionText'] -and $r.DirectionText) { [string]$r.DirectionText } else { Get-IgwtFirewallDirectionText -Direction ([string]$r.Direction) }); Profiles = [string]$r.Profiles; ProfileMatch = $match; Program = [string]$r.Program; Service = [string]$r.Service
        Package = $(if ($r.Package) { [string]$r.Package } elseif ($r.Owner) { [string]$r.Owner } else { '' })
        Protocol = $proto; ProtocolKey = $(if ($proto -like 'ICMP*') { 'ICMP' } elseif ($proto -in '', 'Any') { 'Any' } else { $proto })
        LocalPort = [string]$r.LocalPort; RemotePort = [string]$r.RemotePort; LocalAddress = [string]$r.LocalAddress; RemoteAddress = [string]$r.RemoteAddress
        InterfaceType = [string]$r.InterfaceType; EdgeTraversal = [string]$r.EdgeTraversal; SourceKey = [string]$r.Source; ProgramExists = [string]$r.ProgramExists
        RiskKeys = @($open | ForEach-Object { [string]$_.RiskId }); RiskCount = $(if ($top) { [int]$rank[$top] * 100 + $open.Count } else { 0 }); RiskLevel = $top; Description = [string]$r.Description
        Groups = @($r.Groups); GroupsText = ''; Confidence = [string]$r.Confidence; ConfidenceText = $(if ([string]$r.Confidence -eq 'Low') { 'Low (?)' } else { [string]$r.Confidence })
        ExposedKey = $(if ($r.Exposed) { 'Yes' } else { 'No' }); ConflictKey = $(if ($r.Shadowed -or @($r.Conflicts).Count -or $r.Redundant) { 'Yes' } else { 'No' }); Origin = [string]$r.Origin
    }
    $names = @{ CoreServices = 'Core'; WindowsConnections = 'Windows'; UserInstalled = 'User'; CustomRules = 'Custom'; Inbound = 'In'; Outbound = 'Out'; Blocked = 'Blocked'; Bloated = 'Bloated'; SecurityRisks = 'Risk' }
    $row.GroupsText = (@($r.Groups | Where-Object { $_ } | ForEach-Object { $(if ($names[[string]$_]) { $names[[string]$_] } else { [string]$_ }) }) -join ' | ')
    Add-IgwtGuiStatusField -Row $row -Name 'State' -Text $(if ($r.Enabled) { 'Enabled' } else { 'Disabled' }) -Tone $(if ($r.Enabled) { 'Pass' } else { 'Muted' })
    $row.StateKey = $(if ($r.Enabled) { 'Enabled' } else { 'Disabled' })
    Add-IgwtGuiStatusField -Row $row -Name 'Action' -Text ([string]$r.Action) -Tone $(if ([string]$r.Action -eq 'Block') { 'Warn' } else { 'Info' })
    $srcLabel = $script:IgwtFirewallSourceLabel[[string]$r.Source]
    if (-not $srcLabel) { $srcLabel = [string]$r.Source }
    Add-IgwtGuiStatusField -Row $row -Name 'Source' -Text $srcLabel -Tone $(if ($r.Locked) { 'Muted' } elseif ([string]$r.Source -eq 'Owned') { 'Info' } else { 'Text' }) -Locked:([bool]$r.Locked)
    $riskText = $(if ($open.Count) { "${top}: $(@($open | Sort-Object @{ Expression = { -[int]$rank[[string]$_.Severity] } })[0].Title)$(if ($open.Count -gt 1) { " (+$($open.Count - 1))" })$(if ($r.Exposed) { ', exposed now' })" } else { '' })
    Add-IgwtGuiStatusField -Row $row -Name 'Risk' -Text $riskText -Tone $(switch ($top) { 'Critical' { 'Fail' } 'High' { 'Fail' } 'Medium' { 'Warn' } 'Low' { 'Info' } default { 'Muted' } })
    if (-not $open.Count) { $row.RiskGlyph = '' }
    $originTone = switch ([string]$r.Origin) { 'CoreServices' { 'Muted' } 'WindowsConnections' { 'Info' } 'UserInstalled' { 'Text' } 'CustomRules' { 'Pass' } default { 'Text' } }
    Add-IgwtGuiStatusField -Row $row -Name 'OriginCol' -Text $(if ($r.OriginName) { [string]$r.OriginName } else { '' }) -Tone $originTone -Locked:([bool]$r.Locked)
    return [pscustomobject]$row
}

function Get-IgwtGuiFirewallColumns {
    [CmdletBinding()]
    param()
    @(
        @{ Key = 'DisplayName'; Header = 'Rule'; MinWidth = 200; Tip = 'Description' }
        @{ Key = 'OriginCol'; Header = 'Category'; Width = 170; Template = 'Status'; SortKey = 'Origin' }
        @{ Key = 'State'; Header = 'Enabled'; Width = 110; Template = 'Status'; SortKey = 'StateKey' }
        @{ Key = 'DirectionText'; Header = 'Direction'; Width = 90; SortKey = 'Direction'; Tip = 'Direction' }
        @{ Key = 'Action'; Header = 'Action'; Width = 90; Template = 'Status' }
        @{ Key = 'Profiles'; Header = 'Profiles'; Width = 130 }
        @{ Key = 'Program'; Header = 'Program'; Width = 220; Template = 'Mono' }
        @{ Key = 'Protocol'; Header = 'Protocol'; Width = 90 }
        @{ Key = 'LocalPort'; Header = 'Local port'; Width = 110 }
        @{ Key = 'Source'; Header = 'Source'; Width = 150; Template = 'Status'; Visible = $false }
        @{ Key = 'Risk'; Header = 'Risk'; Width = 240; Template = 'Status'; Kind = 'Number'; SortKey = 'RiskCount' }
        @{ Key = 'GroupsText'; Header = 'Groups'; Width = 190; Visible = $false; Search = $false }
        @{ Key = 'ConfidenceText'; Header = 'Confidence'; Width = 100; Visible = $false }
        @{ Key = 'Groups'; Header = 'Group keys'; Width = 100; Visible = $false; Search = $false }
        @{ Key = 'Group'; Header = 'Group'; Width = 180; Visible = $false }
        @{ Key = 'Service'; Header = 'Service'; Width = 120; Visible = $false }
        @{ Key = 'Package'; Header = 'Package / AppContainer'; Width = 200; Visible = $false; Template = 'Mono' }
        @{ Key = 'RemotePort'; Header = 'Remote port'; Width = 110; Visible = $false }
        @{ Key = 'LocalAddress'; Header = 'Local address'; Width = 140; Visible = $false }
        @{ Key = 'RemoteAddress'; Header = 'Remote address'; Width = 160; Visible = $false }
        @{ Key = 'InterfaceType'; Header = 'Interface type'; Width = 120; Visible = $false }
        @{ Key = 'EdgeTraversal'; Header = 'Edge traversal'; Width = 120; Visible = $false }
        @{ Key = 'ProgramExists'; Header = 'Program exists'; Width = 110; Visible = $false }
        @{ Key = 'Name'; Header = 'Rule name (id)'; Width = 200; Visible = $false; Template = 'Mono' }
        @{ Key = 'Description'; Header = 'Description'; Width = 300; Visible = $false }
    )
}

function Get-IgwtGuiFirewallChips {
    [CmdletBinding()]
    param()
    $riskChips = @(foreach ($k in @((Get-IgwtFirewallKnowledgeBase).Risks)) { @{ Id = "risk-$($k.id)"; Label = [string]$k.title; Group = 'risk'; Field = 'RiskKeys'; Values = @([string]$k.id); Tip = [string]$k.hint; More = $true } })
    @(
        @{ Id = 'sev-high'; Label = 'Critical and High'; Group = 'sev'; Field = 'RiskLevel'; Values = @('Critical', 'High'); Tip = 'Rules with a critical or high-severity finding: review these first' }
        @{ Id = 'sev-medium'; Label = 'Medium'; Group = 'sev'; Field = 'RiskLevel'; Values = @('Medium') }
        @{ Id = 'sev-low'; Label = 'Low'; Group = 'sev'; Field = 'RiskLevel'; Values = @('Low'); More = $true }
        @{ Id = 'exposed'; Label = 'Exposed now'; Group = 'exposed'; Field = 'ExposedKey'; Values = @('Yes'); Tip = 'Allow rules that match a port something is listening on right now' }
        @{ Id = 'conflicts'; Label = 'Conflicts'; Group = 'conflicts'; Field = 'ConflictKey'; Values = @('Yes'); Tip = 'Shadowed, redundant or partly blocked rules'; More = $true }
        @{ Id = 'lowconf'; Label = 'Low confidence'; Group = 'conf'; Field = 'Confidence'; Values = @('Low'); Tip = 'Classifications that are a best guess: check them'; More = $true }
        @{ Id = 'enabled'; Label = 'Enabled'; Group = 'state'; Field = 'StateKey'; Values = @('Enabled') }
        @{ Id = 'disabled'; Label = 'Disabled'; Group = 'state'; Field = 'StateKey'; Values = @('Disabled') }
        @{ Id = 'in'; Label = 'Inbound'; Group = 'dir'; Field = 'Direction'; Values = @('Inbound') }
        @{ Id = 'out'; Label = 'Outbound'; Group = 'dir'; Field = 'Direction'; Values = @('Outbound') }
        @{ Id = 'allow'; Label = 'Allow'; Group = 'action'; Field = 'Action'; Values = @('Allow') }
        @{ Id = 'block'; Label = 'Block'; Group = 'action'; Field = 'Action'; Values = @('Block') }
        @{ Id = 'p-domain'; Label = 'Domain'; Group = 'profile'; Field = 'ProfileMatch'; Values = @('Domain'); Tip = 'Rules that apply on domain networks (also rules for any network)'; More = $true }
        @{ Id = 'p-private'; Label = 'Private'; Group = 'profile'; Field = 'ProfileMatch'; Values = @('Private'); Tip = 'Rules that apply on private networks (also rules for any network)'; More = $true }
        @{ Id = 'p-public'; Label = 'Public'; Group = 'profile'; Field = 'ProfileMatch'; Values = @('Public'); Tip = 'Rules that apply on public networks (also rules for any network)'; More = $true }
        @{ Id = 's-windows'; Label = 'Windows'; Group = 'source'; Field = 'SourceKey'; Values = @('Windows'); More = $true }
        @{ Id = 's-third'; Label = 'Third-party'; Group = 'source'; Field = 'SourceKey'; Values = @('ThirdParty'); More = $true }
        @{ Id = 's-store'; Label = 'Store apps'; Group = 'source'; Field = 'SourceKey'; Values = @('StoreApp'); More = $true }
        @{ Id = 's-owned'; Label = 'iG Windows Tuner'; Group = 'source'; Field = 'SourceKey'; Values = @('Owned'); More = $true }
        @{ Id = 's-gpo'; Label = 'Group Policy / MDM'; Group = 'source'; Field = 'SourceKey'; Values = @('GroupPolicy'); More = $true }
        @{ Id = 'tcp'; Label = 'TCP'; Group = 'proto'; Field = 'ProtocolKey'; Values = @('TCP'); More = $true }
        @{ Id = 'udp'; Label = 'UDP'; Group = 'proto'; Field = 'ProtocolKey'; Values = @('UDP'); More = $true }
        @{ Id = 'icmp'; Label = 'ICMP'; Group = 'proto'; Field = 'ProtocolKey'; Values = @('ICMP'); More = $true }
        @{ Id = 'anyproto'; Label = 'Any protocol'; Group = 'proto'; Field = 'ProtocolKey'; Values = @('Any'); More = $true }
    ) + $riskChips
}

#endregion

#region Page

function Initialize-IgwtGuiFirewallPage {
    <# .SYNOPSIS Builds the rule grid and wires the page (called once at start). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $rows = { param($r) @($r | ForEach-Object { $_.Rule }) }
    $actions = @(
        @{ Id = 'enable'; Label = 'Enable'; Bulk = $true; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallChange -Operation Enable -Rows $r } }
        @{ Id = 'disable'; Label = 'Disable'; Bulk = $true; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallChange -Operation Disable -Rows $r } }
        @{ Id = 'allow'; Label = 'Set to Allow'; Bulk = $true; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallChange -Operation SetAction -Rows $r -Settings @{ Action = 'Allow' } } }
        @{ Id = 'block'; Label = 'Set to Block'; Bulk = $true; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallChange -Operation SetAction -Rows $r -Settings @{ Action = 'Block' } } }
        @{ Id = 'edit'; Label = 'Edit...'; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallEdit -Row @($r)[0] } }
        @{ Id = 'duplicate'; Label = 'Duplicate'; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallChange -Operation Duplicate -Rows $r } }
        @{ Id = 'delete'; Label = 'Delete...'; Bulk = $true; Danger = $true; Changes = $true; Run = { param($r) Invoke-IgwtGuiFirewallChange -Operation Delete -Rows $r } }
    )
    $null = $rows
    $g = New-IgwtSmartGrid -Id 'firewall.rules' -Noun 'rules' -RowKey 'Key' -SearchPlaceholder 'Search name, group, program, port or address' -Columns (Get-IgwtGuiFirewallColumns) -Chips (Get-IgwtGuiFirewallChips) -Actions $actions `
        -EmptyTitle 'No firewall rules were read' -EmptyText 'Press Refresh to read the rules again.' `
        -OnBeforeQuery { param($grid) $grid.Scope = $(if ($script:Gui.FirewallGroup -and $script:Gui.FirewallGroup -ne 'All') { @{ Groups = @([string]$script:Gui.FirewallGroup) } } else { @{} }) } `
        -OnSelectionChanged { param($grid, $sel) $null = $grid; Update-IgwtGuiFirewallDetail -Rows $sel } -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiFirewallRefresh } `
        -OnActivate { param($grid, $row) $null = $grid; if (-not (Test-IgwtReadOnly) -and $script:Gui.IsAdmin) { Invoke-IgwtGuiFirewallEdit -Row $row } }
    $script:Gui.Grids.Firewall = $g
    # Needs attention first by default (risk count, highest first).
    if (-not @($g.Sort).Count) { Set-IgwtGridSort -Grid $g -Key 'Risk' -NoSave; Set-IgwtGridSort -Grid $g -Key 'Risk' -NoSave }
    $c.FwGridHost.Content = $g.Root
    Register-IgwtGuiHandler -Control $c.FwRefreshButton -Event 'Click' -Handler { Start-IgwtGuiFirewallRefresh }
    Register-IgwtGuiHandler -Control $c.FwNewRuleButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallNew }
    Register-IgwtGuiHandler -Control $c.FwImportButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallImport }
    Register-IgwtGuiHandler -Control $c.FwExportButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallExport }
    Register-IgwtGuiHandler -Control $c.FwExportPolicyButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallExport -Policy }
    Register-IgwtGuiHandler -Control $c.FwLogButton -Event 'Click' -Handler { $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwLogTab; Start-IgwtGuiFirewallLogRead }
    foreach ($pair in @(@('FwEnableButton', 'enable'), @('FwDisableButton', 'disable'), @('FwAllowButton', 'allow'), @('FwBlockButton', 'block'), @('FwEditButton', 'edit'), @('FwDuplicateButton', 'duplicate'), @('FwDeleteButton', 'delete'))) {
        $c[$pair[0]].Tag = $pair[1]
        Register-IgwtGuiHandler -Control $c[$pair[0]] -Event 'Click' -Handler { param($s, $e) $null = $e; Invoke-IgwtGridAction -Grid $script:Gui.Grids.Firewall -ActionId ([string]$s.Tag) }
    }
    Register-IgwtGuiHandler -Control $c.FwProfilesPanel -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
        param($s, $e)
        $null = $s
        $src = $e.OriginalSource
        $tag = [string]$src.Tag
        if (-not $tag -or -not ($src -is [System.Windows.Controls.Primitives.ButtonBase])) { return }
        $e.Handled = $true
        Invoke-IgwtGuiFirewallProfileTag -Tag $tag -Source $src
    }
    Initialize-IgwtGuiFirewallHome
    Initialize-IgwtGuiFirewallLogPage
    Update-IgwtGuiFirewallDetail -Rows @()
}

function Start-IgwtGuiFirewallRefresh {
    <# .SYNOPSIS Reads every rule and the profiles in the background (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    Set-IgwtGridState -Grid $script:Gui.Grids.Firewall -State Loading
    $null = Start-IgwtGuiJob -Command 'Get-IgwtFirewallAudit' -Channel 'firewall' -BusyText 'Reading and checking every firewall rule (read-only)...' -OnComplete {
        param($out, $errs)
        $inv = @($out) | Select-Object -Last 1
        if (-not $inv) { Set-IgwtGridState -Grid $script:Gui.Grids.Firewall -State Error -Message $(if (@($errs).Count) { [string]@($errs)[0] } else { 'No data was returned.' }); return }
        Set-IgwtGuiFirewallInventory -Inventory $inv -Chunked
        Set-IgwtGuiStatus ("Firewall: {0} rules read and checked in {1:N1} s." -f $inv.Count, ($inv.LoadMs / 1000))
    }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtFirewallProfileStatus' -Channel 'firewall-profiles' -BusyText 'Reading the firewall profiles (read-only)...' -OnComplete {
        param($out, $errs)
        $p = @($out) | Select-Object -Last 1
        if ($p) { $script:Gui.FirewallProfiles = $p; Set-IgwtGuiFirewallProfiles -Status $p; Update-IgwtGuiFirewallOverview } else { $script:Gui.C.FwProfileNote.Text = "The profiles could not be read: $(@($errs)[0])" }
    }
}

function Set-IgwtGuiFirewallInventory {
    <# .SYNOPSIS Shows an inventory (all rules) on the page. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Inventory, [switch]$Chunked)
    $script:Gui.Firewall = $Inventory
    $script:Gui.FirewallContext = $(if ($Inventory.PSObject.Properties['Context']) { $Inventory.Context } else { $null })
    if ($Chunked) {
        # The window stays responsive: rows are built in slices, then each summary is applied in its own step.
        Invoke-IgwtGuiChunked -Key 'firewall.rows' -Items @($Inventory.Rules) -Build { param($rule) New-IgwtGuiFirewallRow -Rule $rule } -Done {
            param($rows)
            Set-IgwtGridRows -Grid $script:Gui.Grids.Firewall -Rows $rows
            Complete-IgwtGuiFirewallInventory -Step 0
        }
        return
    }
    Set-IgwtGridRows -Grid $script:Gui.Grids.Firewall -Rows @($Inventory.Rules | ForEach-Object { New-IgwtGuiFirewallRow -Rule $_ })
    for ($i = 0; $i -le 4; $i++) { Complete-IgwtGuiFirewallInventory -Step $i -NoSchedule }
}

function Complete-IgwtGuiFirewallInventory {
    <# .SYNOPSIS The parts of an inventory that follow its rows (summary, groups, overview, defaults, notice), each in its own UI step. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([int]$Step, [switch]$NoSchedule)
    $c = $script:Gui.C
    switch ($Step) {
        0 { Update-IgwtGuiFirewallSummary; Update-IgwtGuiFirewallGroups }
        1 { Update-IgwtGuiFirewallOverview }
        2 { Update-IgwtGuiFirewallDefaults }
        3 {
            $notes = @($script:Gui.Firewall.Notes | Where-Object { $_ })
            $c.FwNoticeText.Text = ($notes -join ' ')
            $c.FwNoticeText.Visibility = $(if ($notes.Count) { 'Visible' } else { 'Collapsed' })
        }
    }
    if (-not $NoSchedule -and $Step -lt 3) {
        $script:Gui.FwNextStep = $Step + 1
        $null = $script:Gui.Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [Action] { Complete-IgwtGuiFirewallInventory -Step $script:Gui.FwNextStep })
    }
}

#endregion

#region Changes

function Invoke-IgwtGuiFirewallChange {
    <#
    .SYNOPSIS
        Plans a change, shows its summary (refused rules and warnings included), applies it in the
        background (snapshot first) and offers Undo. Only the affected rules are read again.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable', 'SetAction', 'Edit', 'New', 'Duplicate', 'Delete')][string]$Operation, [object[]]$Rows = @(), [hashtable]$Settings = @{}, [switch]$NoConfirm)
    # A change the user starts (not the next batch of a reviewed run) drops whatever is still queued.
    if (-not $NoConfirm) { $script:Gui.FirewallQueue = $null }
    if ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { $script:Gui.FirewallQueue = $null; Set-IgwtGuiStatus 'Firewall changes need administrator rights and are off in read-only mode.'; return }
    $rules = @($Rows | Where-Object { $_ } | ForEach-Object { if ($_.PSObject.Properties['Rule']) { $_.Rule } else { $_ } })
    $plan = Get-IgwtFirewallChangePlan -Operation $Operation -Rules $rules -Settings $Settings
    if ($plan.Count -eq 0 -and $NoConfirm) {
        # A queued batch with nothing left to change: go on with the run (the preview listed it as skipped).
        if ($script:Gui.FirewallQueue -and $script:Gui.FirewallQueue.Count) { Start-IgwtGuiFirewallQueue -Queue $script:Gui.FirewallQueue }
        return
    }
    if ($plan.Count -eq 0) {
        $reason = @($plan.Items | Where-Object { -not $_.Allowed } | Select-Object -First 1).Reason
        $null = Show-IgwtGuiMessage -Text $(if ($reason) { "Nothing can be changed:`n`n$reason" } else { 'Nothing to change: every selected rule is already set.' }) -Title 'iG Windows Tuner - firewall' -Icon 'Information'
        return
    }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp } | Select-Object -First 12)) { $lines.Add("- $(if ($i.DisplayName) { $i.DisplayName } else { $i.Name }): $($i.Change)") }
    if ($plan.Count -gt 12) { $lines.Add("- ... and $($plan.Count - 12) more") }
    $refused = @($plan.Items | Where-Object { -not $_.Allowed })
    if ($refused.Count) { $lines.Add(''); $lines.Add("Not changed ($($refused.Count)):"); foreach ($i in @($refused | Select-Object -First 5)) { $lines.Add("- $($i.DisplayName): $($i.Reason)") } }
    foreach ($w in $plan.Warnings) { $lines.Add(''); $lines.Add("Note: $w") }
    $lines.Add(''); $lines.Add('A snapshot is written first; Undo restores every rule exactly.')
    if ($plan.RemoteSession) { $lines.Add('A remote session is active: you will be asked to keep the change within 60 seconds, otherwise it is reverted automatically.') }
    $title = @{ Enable = 'Enable rules'; Disable = 'Disable rules'; SetAction = "Set rules to $($Settings.Action)"; Edit = 'Edit rule'; New = 'Create rule'; Duplicate = 'Duplicate rule'; Delete = 'Delete rules' }[$Operation]
    $icon = $(if ($plan.Warnings.Count -or $Operation -eq 'Delete') { 'Warning' } else { 'Question' })
    if (-not $NoConfirm -and (Show-IgwtGuiMessage -Text "$($plan.Summary).`n`n$($lines -join "`n")" -Title "iG Windows Tuner - $title" -Buttons 'YesNo' -Icon $icon) -ne 'Yes') { return }
    $params = @{ Operation = $Operation; Settings = $Settings }
    if ($Operation -ne 'New') { $params.Name = @($plan.Items | Where-Object { $_.Allowed -and -not $_.NoOp } | ForEach-Object { $_.Name }) }
    if ($plan.RemoteSession) { $params.AllowRemoteSession = $true }
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtFirewallChange' -Parameters $params -Blocking -BusyText "$title (snapshot first)..." -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (-not $res) { $script:Gui.FirewallQueue = $null; Show-IgwtGuiError -Message "The firewall change failed: $(@($errs)[0])"; return }
        Complete-IgwtGuiFirewallChange -Result $res
    }
}

function Complete-IgwtGuiFirewallChange {
    <# .SYNOPSIS After a change: result toast with Undo, the remote-session keep timer, and a refresh of the affected rules. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only; Undo runs through the engine.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result)
    $applied = @($Result.Results | Where-Object Result -EQ 'Applied')
    $failed = @($Result.Results | Where-Object Result -EQ 'Failed')
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Result.Plan.Items | Where-Object { $_.Allowed -and $_.Name })) { $names.Add([string]$i.Name) }
    foreach ($a in $applied) { if ([string]$a.Message -match '^New rule (\S+)') { $names.Add($Matches[1]) } }
    $snapshot = [string]$Result.Snapshot
    if ($failed.Count) { $script:Gui.FirewallQueue = $null; Show-IgwtGuiError -Message "$($failed.Count) firewall change(s) failed: $($failed[0].Target): $($failed[0].Message) (the remaining batches were not run)" -Context 'Firewall' }
    if ($applied.Count -and $snapshot) {
        $script:Gui.FirewallLastSnapshot = $snapshot
        Show-IgwtGuiToast -Text "$($applied.Count) firewall rule(s) changed." -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiFirewallUndo -Snapshot $snap } -ActionArgument $snapshot
        if ($Result.RemoteSession) {
            if (-not (Show-IgwtGuiKeepChangesDialog -Seconds 60)) { $script:Gui.FirewallQueue = $null; Invoke-IgwtGuiFirewallUndo -Snapshot $snapshot; return }
        }
    }
    if ($names.Count) { Update-IgwtGuiFirewallRows -Name $names.ToArray() }
    if ($script:Gui.FirewallQueue -and $script:Gui.FirewallQueue.Count) { Start-IgwtGuiFirewallQueue -Queue $script:Gui.FirewallQueue }
}

function Update-IgwtGuiFirewallSummary {
    <# .SYNOPSIS The one-line status at the top: what needs attention first. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $a = $script:Gui.Firewall
    if (-not $a -or -not $a.PSObject.Properties['Summary']) { return }
    $s = $a.Summary
    $n = [int]$s.NeedsAttention
    $text = $(if ($n) { "$n rule$(if ($n -ne 1) { 's' }) need$(if ($n -eq 1) { 's' }) attention ($($s.Severity.Critical) critical, $($s.Severity.High) high)." } else { 'Nothing needs attention.' })
    $c.FwSummaryText.Text = "$text  $($s.Total) rules, $($s.Enabled) enabled, $(@($s.QuickWins).Count) quick win(s)$(if ($s.Locked) { ", $($s.Locked) locked" })$(if ($a.Partial) { '; ports and addresses need administrator rights' })."
    $c.FwSummaryIcon.Text = $(if ($n) { [string][char]0xE7BA } else { [string][char]0xE73E })
    $c.FwSummaryIcon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $(if ($n) { 'BrushWarning' } else { 'BrushSuccess' }))
}
function Update-IgwtGuiFirewallRows {
    <# .SYNOPSIS Reads only these rules again and merges them into the grid (risk flags are recomputed over all rules). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$Name)
    $null = Start-IgwtGuiJob -Command 'Get-IgwtFirewallRuleRows' -Parameters @{ Name = $Name } -Channel 'firewall-rows' -BusyText 'Reading the changed rules...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (-not $res -or -not $script:Gui.Firewall) { Start-IgwtGuiFirewallRefresh; return }
        $gone = @{}; foreach ($m in @($res.Missing)) { $gone[$m] = $true }
        # Changed rows show their new state at once (classified with the last context); the full
        # audit (findings, conflicts, counts) runs again in the background.
        $changed = @($res.Rows)
        if ($script:Gui.FirewallContext) { Invoke-IgwtFirewallClassification -Rows $changed -Context $script:Gui.FirewallContext }
        $all = @(Merge-IgwtGridRows -Existing @($script:Gui.Firewall.Rules | Where-Object { -not $gone.ContainsKey($_.Name) }) -Changed $changed -RowKey 'Name')
        $script:Gui.Firewall.Rules = $all
        $script:Gui.Firewall.Count = $all.Count
        Set-IgwtGridRows -Grid $script:Gui.Grids.Firewall -Rows @($all | ForEach-Object { New-IgwtGuiFirewallRow -Rule $_ })
        Start-IgwtGuiFirewallRefresh
    }
}

function Invoke-IgwtGuiFirewallUndo {
    <# .SYNOPSIS Reverts a firewall snapshot (Undo in the toast, or the remote-session timer). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Snapshot)
    $script:Gui.FirewallQueue = $null   # an undo ends a queued run
    $null = Start-IgwtGuiJob -Command 'Invoke-IgwtRevert' -Parameters @{ SnapshotPath = $Snapshot } -Blocking -BusyText 'Undoing the firewall change...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count -or -not $res) { Show-IgwtGuiError -Message "Undo failed: $(@($errs)[0])" -Context 'Firewall' }
        else {
            $bad = @($res.Results | Where-Object Result -EQ 'Failed')
            if ($bad.Count) { Show-IgwtGuiError -Message "Undo: $($bad.Count) rule(s) could not be restored: $($bad[0].Message)" -Context 'Firewall' }
            else { Show-IgwtGuiToast -Text 'The firewall change was undone.' -Tone Info }
        }
        Start-IgwtGuiFirewallRefresh
    }
}

function Show-IgwtGuiKeepChangesDialog {
    <#
    .SYNOPSIS
        Remote-session safety: "Keep these changes?" with a countdown. Returns $true only when the
        user keeps them in time; otherwise (timeout, Revert, closing the dialog) $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([int]$Seconds = 60)
    $w = New-Object System.Windows.Window
    $w.Title = 'iG Windows Tuner - keep firewall changes?'; $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'
    $w.SizeToContent = 'Height'; $w.Width = 460; $w.ResizeMode = 'NoResize'; $w.ShowInTaskbar = $false; $w.Topmost = $true
    Copy-IgwtGuiResources -Target $w
    $w.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'BrushSurface')
    $panel = New-Object System.Windows.Controls.StackPanel; $panel.Margin = '22,18,22,18'
    $t = New-Object System.Windows.Controls.TextBlock; $t.TextWrapping = 'Wrap'; $t.FontWeight = 'SemiBold'
    $t.Text = 'You are connected remotely. If this firewall change cut your connection, it is reverted automatically.'
    $count = New-Object System.Windows.Controls.TextBlock; $count.Margin = '0,10,0,0'; $count.TextWrapping = 'Wrap'
    $btns = New-Object System.Windows.Controls.StackPanel; $btns.Orientation = 'Horizontal'; $btns.HorizontalAlignment = 'Right'; $btns.Margin = '0,16,0,0'
    $state = @{ Keep = $false; Left = $Seconds }
    $keep = New-Object System.Windows.Controls.Button; $keep.Content = 'Keep changes'; $keep.Style = $w.Resources['AccentButton']
    $revert = New-Object System.Windows.Controls.Button; $revert.Content = 'Revert now'; $revert.Style = $w.Resources[[System.Windows.Controls.Button]]; $revert.Margin = '0'; $revert.IsCancel = $true
    $null = $btns.Children.Add($keep); $null = $btns.Children.Add($revert)
    $null = $panel.Children.Add($t); $null = $panel.Children.Add($count); $null = $panel.Children.Add($btns)
    $w.Content = $panel
    $count.Text = "Reverting in $Seconds seconds."
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    Register-IgwtGuiHandler -Control $timer -Event 'Tick' -Handler { $state.Left--; $count.Text = "Reverting in $($state.Left) seconds."; if ($state.Left -le 0) { $timer.Stop(); $w.Close() } }.GetNewClosure()
    Register-IgwtGuiHandler -Control $keep -Event 'Click' -Handler { $state.Keep = $true; $timer.Stop(); $w.Close() }.GetNewClosure()
    Register-IgwtGuiHandler -Control $revert -Event 'Click' -Handler { $timer.Stop(); $w.Close() }.GetNewClosure()
    $timer.Start()
    $null = $w.ShowDialog()
    $timer.Stop()
    return [bool]$state.Keep
}

function Invoke-IgwtGuiFirewallNew {
    [CmdletBinding()]
    param()
    if ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { Set-IgwtGuiStatus 'Creating rules needs administrator rights and is off in read-only mode.'; return }
    $s = Show-IgwtGuiFirewallRuleDialog -Mode New
    if ($s) { Invoke-IgwtGuiFirewallChange -Operation New -Settings $s }
}

function Invoke-IgwtGuiFirewallEdit {
    [CmdletBinding()]
    param($Row)
    if (-not $Row) { return }
    $rule = $(if ($Row.PSObject.Properties['Rule']) { $Row.Rule } else { $Row })
    $why = Get-IgwtFirewallChangeBlock -Operation Edit -Rule $rule
    if ($why) { $null = Show-IgwtGuiMessage -Text $why -Title 'iG Windows Tuner - edit rule' -Icon 'Information'; return }
    $s = Show-IgwtGuiFirewallRuleDialog -Mode Edit -Rule $rule
    if ($s -and $s.Count) { Invoke-IgwtGuiFirewallChange -Operation Edit -Rows @($rule) -Settings $s }
}

function Get-IgwtGuiFirewallRuleDialogXaml {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Margin="22,18,22,16">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <StackPanel Grid.Row="0">
        <TextBlock x:Name="StepText" Style="{DynamicResource TextOverline}" Margin="0,0,0,2"/>
        <TextBlock x:Name="TitleText" FontSize="{DynamicResource FontSizeTitleSmall}" FontWeight="SemiBold"/>
    </StackPanel>
    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Margin="0,10,0,0">
        <StackPanel>
            <StackPanel x:Name="Step1">
                <TextBlock Style="{DynamicResource TextCaption}" Text="Start from" Margin="0,0,0,4"/>
                <ComboBox x:Name="TemplateBox" Margin="0,0,0,12" AutomationProperties.Name="Start from a template"/>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Rule name" Margin="0,0,0,4"/>
                <TextBox x:Name="NameBox" Tag="For example: My game (UDP)" AutomationProperties.Name="Rule name" Margin="0,0,0,12"/>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Program (leave empty for any program)" Margin="0,0,0,4"/>
                <DockPanel Margin="0,0,0,12">
                    <Button x:Name="BrowseButton" DockPanel.Dock="Right" Content="Browse..." Margin="8,0,0,0"/>
                    <TextBox x:Name="ProgramBox" Tag="C:\Games\Game\game.exe" AutomationProperties.Name="Program path"/>
                </DockPanel>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Description (optional)" Margin="0,0,0,4"/>
                <TextBox x:Name="DescBox" AutomationProperties.Name="Description"/>
            </StackPanel>
            <StackPanel x:Name="Step2">
                <TextBlock Style="{DynamicResource TextCaption}" Text="Direction" Margin="0,8,0,4"/>
                <Border Style="{DynamicResource SegmentHost}" Margin="0,0,0,12">
                    <StackPanel Orientation="Horizontal">
                        <RadioButton x:Name="DirIn" Style="{DynamicResource Segment}" GroupName="dir" Content="Inbound (others connect to this PC)" IsChecked="True"/>
                        <RadioButton x:Name="DirOut" Style="{DynamicResource Segment}" GroupName="dir" Content="Outbound (this PC connects out)"/>
                    </StackPanel>
                </Border>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Action" Margin="0,0,0,4"/>
                <Border Style="{DynamicResource SegmentHost}">
                    <StackPanel Orientation="Horizontal">
                        <RadioButton x:Name="ActAllow" Style="{DynamicResource Segment}" GroupName="act" Content="Allow" IsChecked="True"/>
                        <RadioButton x:Name="ActBlock" Style="{DynamicResource Segment}" GroupName="act" Content="Block"/>
                    </StackPanel>
                </Border>
            </StackPanel>
            <StackPanel x:Name="Step3">
                <TextBlock Style="{DynamicResource TextCaption}" Text="Protocol" Margin="0,8,0,4"/>
                <ComboBox x:Name="ProtoBox" Margin="0,0,0,12" AutomationProperties.Name="Protocol"/>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Local ports (this PC), for example 27015 or 27015-27030; empty = any" Margin="0,0,0,4"/>
                <TextBox x:Name="LocalPortBox" Tag="Any" AutomationProperties.Name="Local ports" Margin="0,0,0,12"/>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Remote ports; empty = any" Margin="0,0,0,4"/>
                <TextBox x:Name="RemotePortBox" Tag="Any" AutomationProperties.Name="Remote ports"/>
            </StackPanel>
            <StackPanel x:Name="Step4">
                <TextBlock Style="{DynamicResource TextCaption}" Text="Networks (profiles)" Margin="0,8,0,4"/>
                <WrapPanel Margin="0,0,0,4">
                    <CheckBox x:Name="ProfPrivate" Content="Private (home)" Margin="0,0,16,0"/>
                    <CheckBox x:Name="ProfPublic" Content="Public (cafes, hotels)" Margin="0,0,16,0"/>
                    <CheckBox x:Name="ProfDomain" Content="Domain (work)"/>
                </WrapPanel>
                <TextBlock x:Name="ProfileHint" Style="{DynamicResource TextCaption}" TextWrapping="Wrap" Margin="0,0,0,12" Text="Allow rules: prefer Private only. Public lets strangers on the same network connect."/>
                <TextBlock Style="{DynamicResource TextCaption}" Text="Remote addresses: IPs, subnets (192.0.2.0/24), ranges or keywords such as LocalSubnet; empty = any" Margin="0,0,0,4"/>
                <TextBox x:Name="RemoteAddrBox" Tag="Any" AutomationProperties.Name="Remote addresses"/>
            </StackPanel>
            <StackPanel x:Name="Step5">
                <TextBlock Style="{DynamicResource TextCaption}" Text="Summary: nothing has changed yet" Margin="0,8,0,4"/>
                <TextBlock x:Name="SummaryText" TextWrapping="Wrap" LineHeight="22"/>
            </StackPanel>
        </StackPanel>
    </ScrollViewer>
    <Border x:Name="ErrorBox" Grid.Row="2" Background="{DynamicResource BrushDangerSoft}" BorderBrush="{DynamicResource BrushDanger}" BorderThickness="1" CornerRadius="6" Padding="10,6" Margin="0,10,0,0" Visibility="Collapsed">
        <TextBlock x:Name="ErrorText" TextWrapping="Wrap"/>
    </Border>
    <DockPanel Grid.Row="3" Margin="0,14,0,0">
        <Button x:Name="CancelButton" DockPanel.Dock="Left" Content="Cancel" IsCancel="True"/>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BackButton" Content="Back"/>
            <Button x:Name="NextButton" Style="{DynamicResource AccentButton}" Content="Next" Margin="0" IsDefault="True"/>
        </StackPanel>
        <Border/>
    </DockPanel>
</Grid>
'@
}

function Show-IgwtGuiFirewallRuleDialog {
    <#
    .SYNOPSIS
        New: a five-step wizard (what, direction and action, protocol and ports, networks and
        addresses, summary) with Back/Next that keeps every value. Edit: one page with the editable
        fields of an existing rule (direction and action are separate actions). Returns the
        settings hashtable, or $null when cancelled. Values are validated before Next/Save.
    #>
    [CmdletBinding()]
    param([ValidateSet('New', 'Edit')][string]$Mode = 'New', $Rule)
    $w = New-Object System.Windows.Window
    $w.Title = $(if ($Mode -eq 'New') { 'iG Windows Tuner - new firewall rule' } else { 'iG Windows Tuner - edit firewall rule' })
    $w.Owner = $script:Gui.Window; $w.WindowStartupLocation = 'CenterOwner'; $w.Width = 620; $w.Height = $(if ($Mode -eq 'New') { 560 } else { 700 }); $w.MinHeight = 420; $w.ShowInTaskbar = $false
    Copy-IgwtGuiResources -Target $w
    $w.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'BrushSurface')
    $w.SetResourceReference([System.Windows.Window]::FontSizeProperty, 'FontSizeBody')
    $w.SetResourceReference([System.Windows.Window]::FontFamilyProperty, 'FontUi')
    $root = [Windows.Markup.XamlReader]::Parse((Get-IgwtGuiFirewallRuleDialogXaml))
    $w.Content = $root
    $f = @{}
    foreach ($n in 'StepText', 'TitleText', 'Step1', 'Step2', 'Step3', 'Step4', 'Step5', 'TemplateBox', 'NameBox', 'BrowseButton', 'ProgramBox', 'DescBox', 'DirIn', 'DirOut', 'ActAllow', 'ActBlock', 'ProtoBox', 'LocalPortBox', 'RemotePortBox',
        'ProfPrivate', 'ProfPublic', 'ProfDomain', 'ProfileHint', 'RemoteAddrBox', 'SummaryText', 'ErrorBox', 'ErrorText', 'CancelButton', 'BackButton', 'NextButton') { $f[$n] = $root.FindName($n) }
    foreach ($b in 'BrowseButton', 'CancelButton', 'BackButton', 'NextButton') { $f[$b].ToolTip = @{ BrowseButton = 'Pick the program file'; CancelButton = 'Close without changing anything'; BackButton = 'Previous step (your entries are kept)'; NextButton = 'Next step' }[$b] }
    $f.ProtoBox.ItemsSource = @('Any', 'TCP', 'UDP', 'ICMPv4', 'ICMPv6')
    $f.ProtoBox.SelectedItem = 'TCP'
    $templates = @(Get-IgwtFirewallRuleTemplates)
    $f.TemplateBox.ItemsSource = @(@('Custom rule') + @($templates | ForEach-Object { $_.Name }))
    $f.TemplateBox.SelectedIndex = 0
    $f.ProfPrivate.IsChecked = $true
    # The dialog is modal: its state lives in one script variable, and the handlers are module
    # functions (closures made with GetNewClosure cannot call the module's private functions).
    $script:IgwtFwDlg = @{ F = $f; Step = 1; Result = $null; Mode = $Mode; W = $w; Templates = $templates; Rule = $Rule }
    if ($Mode -eq 'Edit') {
        $f.NameBox.Text = [string]$Rule.DisplayName
        $f.ProgramBox.Text = $(if ([string]$Rule.Program -in 'Any', '') { '' } else { [string]$Rule.Program })
        $f.DescBox.Text = [string]$Rule.Description
        $f.ProtoBox.SelectedItem = $(if ([string]$Rule.Protocol -in 'Any', 'TCP', 'UDP', 'ICMPv4', 'ICMPv6') { [string]$Rule.Protocol } else { 'Any' })
        $f.LocalPortBox.Text = $(if ([string]$Rule.LocalPort -in 'Any', '') { '' } else { [string]$Rule.LocalPort })
        $f.RemotePortBox.Text = $(if ([string]$Rule.RemotePort -in 'Any', '') { '' } else { [string]$Rule.RemotePort })
        $f.RemoteAddrBox.Text = $(if ([string]$Rule.RemoteAddress -in 'Any', '') { '' } else { [string]$Rule.RemoteAddress })
        $p = @($Rule.ProfileList)
        $any = $p -contains 'Any'
        $f.ProfPrivate.IsChecked = $any -or $p -contains 'Private'; $f.ProfPublic.IsChecked = $any -or $p -contains 'Public'; $f.ProfDomain.IsChecked = $any -or $p -contains 'Domain'
        $f.DirIn.IsChecked = ([string]$Rule.Direction -eq 'Inbound'); $f.DirOut.IsChecked = ([string]$Rule.Direction -eq 'Outbound')
        $f.ActAllow.IsChecked = ([string]$Rule.Action -eq 'Allow'); $f.ActBlock.IsChecked = ([string]$Rule.Action -eq 'Block')
        foreach ($n in 'DirIn', 'DirOut', 'ActAllow', 'ActBlock') { $f[$n].IsEnabled = $false }
        $f.TemplateBox.Visibility = 'Collapsed'
        $f.Step1.Children[0].Visibility = 'Collapsed'
        $f.Step5.Visibility = 'Collapsed'
        $f.StepText.Text = 'EDIT RULE'
        $f.TitleText.Text = [string]$Rule.DisplayName
        $f.BackButton.Visibility = 'Collapsed'
        $f.NextButton.Content = 'Review changes'
        $f.ProfileHint.Text = 'Direction and action are changed with their own buttons.'
    }
    Register-IgwtGuiHandler -Control $f.TemplateBox -Event 'SelectionChanged' -Handler { Use-IgwtGuiFirewallTemplate }
    Register-IgwtGuiHandler -Control $f.BrowseButton -Event 'Click' -Handler {
        $d = $script:IgwtFwDlg
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Programs (*.exe)|*.exe|All files (*.*)|*.*'
        if ($dlg.ShowDialog($d.W)) { $d.F.ProgramBox.Text = $dlg.FileName; if (-not ([string]$d.F.NameBox.Text).Trim()) { $d.F.NameBox.Text = [IO.Path]::GetFileNameWithoutExtension($dlg.FileName) } }
    }
    Register-IgwtGuiHandler -Control $f.BackButton -Event 'Click' -Handler { $d = $script:IgwtFwDlg; if ($d.Step -gt 1) { Show-IgwtGuiFirewallDialogStep -Step ($d.Step - 1) } }
    Register-IgwtGuiHandler -Control $f.CancelButton -Event 'Click' -Handler { $script:IgwtFwDlg.W.Close() }
    Register-IgwtGuiHandler -Control $f.NextButton -Event 'Click' -Handler { Invoke-IgwtGuiFirewallDialogNext }
    Register-IgwtGuiHandler -Control $w -Event 'ContentRendered' -Handler { $null = $script:IgwtFwDlg.F.NameBox.Focus() }
    if ($Mode -eq 'New') { Show-IgwtGuiFirewallDialogStep -Step 1 }
    $null = $w.ShowDialog()
    $result = $script:IgwtFwDlg.Result
    $script:IgwtFwDlg = $null
    return $result
}

function Get-IgwtGuiFirewallDialogSettings {
    <# .SYNOPSIS The values of the rule dialog as engine settings. #>
    [CmdletBinding()]
    param()
    $f = $script:IgwtFwDlg.F
    $profiles = @()
    if ($f.ProfDomain.IsChecked) { $profiles += 'Domain' }
    if ($f.ProfPrivate.IsChecked) { $profiles += 'Private' }
    if ($f.ProfPublic.IsChecked) { $profiles += 'Public' }
    if ($profiles.Count -eq 3) { $profiles = @('Any') }
    $proto = [string]$f.ProtoBox.SelectedItem
    return @{
        DisplayName = ([string]$f.NameBox.Text).Trim(); Description = ([string]$f.DescBox.Text).Trim()
        Direction = $(if ($f.DirOut.IsChecked) { 'Outbound' } else { 'Inbound' }); Action = $(if ($f.ActBlock.IsChecked) { 'Block' } else { 'Allow' })
        Program = $(if (([string]$f.ProgramBox.Text).Trim()) { ([string]$f.ProgramBox.Text).Trim() } else { 'Any' }); Protocol = $proto
        LocalPort = $(if ($proto -in 'TCP', 'UDP') { ([string]$f.LocalPortBox.Text).Trim() } else { '' }); RemotePort = $(if ($proto -in 'TCP', 'UDP') { ([string]$f.RemotePortBox.Text).Trim() } else { '' })
        RemoteAddress = ([string]$f.RemoteAddrBox.Text).Trim(); Profiles = $profiles
    }
}

function Test-IgwtGuiFirewallDialog {
    <# .SYNOPSIS Validates the dialog; shows the problems inline and returns $null, or the settings. #>
    [CmdletBinding()]
    param()
    $d = $script:IgwtFwDlg
    $s = Get-IgwtGuiFirewallDialogSettings
    $check = @{} + $s
    if ($d.Mode -eq 'Edit') { $check.Remove('Direction'); $check.Remove('Action') }
    foreach ($k in 'LocalPort', 'RemotePort', 'RemoteAddress') { if (-not $check[$k]) { $check.Remove($k) } }
    $errs = @(Test-IgwtFirewallRuleSettings -Settings $check -New:($d.Mode -eq 'New'))
    if ($errs.Count) { $d.F.ErrorText.Text = $errs -join ' '; $d.F.ErrorBox.Visibility = 'Visible'; return $null }
    $d.F.ErrorBox.Visibility = 'Collapsed'
    return $s
}

function Show-IgwtGuiFirewallDialogStep {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the dialog only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Step)
    $d = $script:IgwtFwDlg; $f = $d.F
    $d.Step = $Step
    foreach ($i in 1..5) { $f["Step$i"].Visibility = $(if ($i -eq $Step) { 'Visible' } else { 'Collapsed' }) }
    $f.StepText.Text = "STEP $Step OF 5"
    $f.TitleText.Text = @{ 1 = 'What should the rule cover?'; 2 = 'Direction and action'; 3 = 'Protocol and ports'; 4 = 'Networks and remote addresses'; 5 = 'Check and create' }[$Step]
    $f.BackButton.IsEnabled = ($Step -gt 1)
    $f.NextButton.Content = $(if ($Step -eq 5) { 'Create rule' } else { 'Next' })
    $f.ErrorBox.Visibility = 'Collapsed'
    if ($Step -eq 5) {
        $s = Get-IgwtGuiFirewallDialogSettings
        $f.SummaryText.Text = (@("Name: $($s.DisplayName)", "$($s.Direction), $($s.Action)", "Program: $($s.Program)",
                "Protocol: $($s.Protocol)$(if ($s.LocalPort) { ", local ports $($s.LocalPort)" })$(if ($s.RemotePort) { ", remote ports $($s.RemotePort)" })",
                "Networks: $($s.Profiles -join ', ')", "Remote addresses: $(if ($s.RemoteAddress) { $s.RemoteAddress } else { 'any' })", '',
                'Create rule shows the final summary; the rule is created only after you confirm it.') -join [Environment]::NewLine)
    }
}

function Use-IgwtGuiFirewallTemplate {
    <# .SYNOPSIS Fills the wizard from the chosen template (the user can change everything afterwards). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the dialog only.')]
    [CmdletBinding()]
    param()
    $d = $script:IgwtFwDlg; $f = $d.F
    $i = $f.TemplateBox.SelectedIndex - 1
    if ($i -lt 0) { return }
    $t = @($d.Templates)[$i]
    $ts = $t.Settings
    $f.DirIn.IsChecked = ($ts.Direction -eq 'Inbound'); $f.DirOut.IsChecked = ($ts.Direction -eq 'Outbound')
    $f.ActAllow.IsChecked = ($ts.Action -eq 'Allow'); $f.ActBlock.IsChecked = ($ts.Action -eq 'Block')
    $f.ProtoBox.SelectedItem = $ts.Protocol
    $p = @($ts.Profiles)
    $f.ProfPrivate.IsChecked = ($p -contains 'Private' -or $p -contains 'Any'); $f.ProfPublic.IsChecked = ($p -contains 'Public' -or $p -contains 'Any'); $f.ProfDomain.IsChecked = ($p -contains 'Domain' -or $p -contains 'Any')
    $f.RemoteAddrBox.Text = $(if ($ts.RemoteAddress -and $ts.RemoteAddress -ne 'Any') { $ts.RemoteAddress } else { '' })
    if (-not ([string]$f.NameBox.Text).Trim()) { $f.NameBox.Text = $t.Name }
}

function Invoke-IgwtGuiFirewallDialogNext {
    <# .SYNOPSIS Next / Create rule / Review changes. Edit returns only the values that changed. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the dialog only.')]
    [CmdletBinding()]
    param()
    $d = $script:IgwtFwDlg; $f = $d.F
    if ($d.Mode -eq 'Edit') {
        $s = Test-IgwtGuiFirewallDialog
        if (-not $s) { return }
        $rule = $d.Rule
        $old = @{ DisplayName = [string]$rule.DisplayName; Description = [string]$rule.Description; Program = $(if ([string]$rule.Program) { [string]$rule.Program } else { 'Any' }); Protocol = [string]$rule.Protocol
            LocalPort = $(if ([string]$rule.LocalPort -eq 'Any') { '' } else { [string]$rule.LocalPort }); RemotePort = $(if ([string]$rule.RemotePort -eq 'Any') { '' } else { [string]$rule.RemotePort })
            RemoteAddress = $(if ([string]$rule.RemoteAddress -eq 'Any') { '' } else { [string]$rule.RemoteAddress }); Profiles = ([string]$rule.Profiles) }
        $changed = @{}
        foreach ($k in 'DisplayName', 'Description', 'Program', 'Protocol', 'LocalPort', 'RemotePort', 'RemoteAddress') { if ([string]$s[$k] -ne [string]$old[$k]) { $changed[$k] = $s[$k] } }
        if ((@($s.Profiles) -join ', ') -ne $old.Profiles) { $changed.Profiles = $s.Profiles }
        if ($changed.ContainsKey('LocalPort') -or $changed.ContainsKey('RemotePort')) { $changed.Protocol = $s.Protocol }
        if ($changed.Count -eq 0) { $f.ErrorText.Text = 'Nothing was changed.'; $f.ErrorBox.Visibility = 'Visible'; return }
        $d.Result = $changed
        $d.W.Close()
        return
    }
    if ($d.Step -eq 1 -and -not ([string]$f.NameBox.Text).Trim()) { $f.ErrorText.Text = 'Give the rule a name.'; $f.ErrorBox.Visibility = 'Visible'; return }
    if ($d.Step -lt 5) {
        if ($d.Step -ge 3 -and -not (Test-IgwtGuiFirewallDialog)) { return }
        Show-IgwtGuiFirewallDialogStep -Step ($d.Step + 1)
        return
    }
    $s = Test-IgwtGuiFirewallDialog
    if ($s) { $d.Result = $s; $d.W.Close() }
}
#endregion

#region Import, export, log

function Invoke-IgwtGuiFirewallImport {
    [CmdletBinding()]
    param()
    if ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { Set-IgwtGuiStatus 'Importing rules needs administrator rights and is off in read-only mode.'; return }
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'iG Windows Tuner firewall export (*.json)|*.json'
    if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
    $path = $dlg.FileName
    $null = Start-IgwtGuiJob -Command 'Get-IgwtFirewallImportPlan' -Parameters @{ Path = $path } -BusyText 'Comparing the file with the current rules (read-only)...' -OnComplete {
        param($out, $errs)
        $plan = @($out) | Select-Object -Last 1
        if (-not $plan) { Show-IgwtGuiError -Message "The file could not be read: $(@($errs)[0])" -Context 'Firewall'; return }
        $lines = @("$($plan.New) new, $($plan.Changed) changed, $($plan.Same) unchanged, $($plan.Skipped) skipped.", '')
        $lines += @($plan.Items | Where-Object { $_.Status -ne 'Same' } | ForEach-Object { "[$($_.Status)] $($_.DisplayName)$(if ($_.Detail) { ": $($_.Detail)" })" })
        $n = $plan.New + $plan.Changed
        if ($n -eq 0) { $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - import preview' -Text ($lines -join [Environment]::NewLine); return }
        if (-not (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - import preview (nothing changed yet)' -Text ($lines -join [Environment]::NewLine) -AcceptText "Import $n rule(s)" -CancelText 'Cancel')) { return }
        $null = Start-IgwtGuiJob -Command 'Import-IgwtFirewallRules' -Parameters @{ Path = $plan.Path } -Blocking -BusyText 'Importing firewall rules (snapshot first)...' -OnComplete {
            param($o2, $e2)
            $res = @($o2) | Select-Object -Last 1
            if (-not $res) { Show-IgwtGuiError -Message "Import failed: $(@($e2)[0])" -Context 'Firewall'; return }
            if ($res.Snapshot) { Show-IgwtGuiToast -Text "$($res.Changes) rule(s) imported." -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiFirewallUndo -Snapshot $snap } -ActionArgument ([string]$res.Snapshot) }
            Start-IgwtGuiFirewallRefresh
        }
    }
}

function Invoke-IgwtGuiFirewallExport {
    [CmdletBinding()]
    param([switch]$Policy)
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    if ($Policy) { $dlg.Filter = 'Windows Firewall policy (*.wfw)|*.wfw'; $dlg.FileName = "firewall-policy-$(Get-Date -Format 'yyyyMMdd-HHmm').wfw" }
    else { $dlg.Filter = 'JSON, importable (*.json)|*.json|CSV (*.csv)|*.csv'; $dlg.FileName = "firewall-rules-$(Get-Date -Format 'yyyyMMdd-HHmm')" }
    if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
    $path = $dlg.FileName
    if ($Policy) { $cmd = 'Export-IgwtFirewallPolicy'; $params = @{ Path = $path } }
    else { $cmd = 'Export-IgwtFirewallRules'; $params = @{ Path = $path; Format = $(if ($path -like '*.csv') { 'Csv' } else { 'Json' }) } }
    $null = Start-IgwtGuiJob -Command $cmd -Parameters $params -BusyText 'Exporting (the firewall is not changed)...' -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { Show-IgwtGuiError -Message "Export failed: $(@($errs)[0])" -Context 'Firewall' }
        else { Show-IgwtGuiToast -Text "Saved $([IO.Path]::GetFileName([string](@($out) | Select-Object -Last 1)))." -Tone Success }
    }
}


#endregion

#region Profiles and networks

function Set-IgwtGuiFirewallProfiles {
    <# .SYNOPSIS Fills the profile cards and the network list. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Status)
    $c = $script:Gui.C
    $script:Gui.FirewallProfiles = $Status
    $c.FwProfileList.ItemsSource = @(foreach ($p in @($Status.Profiles)) {
            $n = [string]$p.Name
            [pscustomobject]@{
                Name = "$n profile"; StateText = $(if ($p.Enabled) { 'On' } else { 'Off: this network is not protected' }); StateGlyph = Get-IgwtGuiToneGlyph -Tone $(if ($p.Enabled) { 'Pass' } else { 'Fail' })
                StateBrush = Get-IgwtGuiToneBrush -Tone $(if ($p.Enabled) { 'Pass' } else { 'Fail' })
                Detail = "Inbound by default: $($p.DefaultInboundAction). Outbound by default: $($p.DefaultOutboundAction).$(if ($p.LogFile) { "`nLog: $($p.LogFile) ($($p.LogMaxKB) KB)" })"
                Notifications = [bool]$p.Notifications; LogBlocked = [bool]$p.LogBlocked; LogAllowed = [bool]$p.LogAllowed; UnicastResponse = [bool]$p.UnicastResponse
                NotifyTag = "profile|$n|Notifications"; LogBlockedTag = "profile|$n|LogBlocked"; LogAllowedTag = "profile|$n|LogAllowed"; UnicastTag = "profile|$n|UnicastResponse"
                NotifyName = "$n profile: notify when a program is blocked"; LogBlockedName = "$n profile: log blocked connections"; LogAllowedName = "$n profile: log allowed connections"; UnicastName = "$n profile: unicast response to multicast"
                TurnOnTag = "profile|$n|Enabled|True"; TurnOnVisibility = $(if ($p.Enabled) { 'Collapsed' } else { 'Visible' })
                OutboundText = $(if ([string]$p.DefaultOutboundAction -eq 'Block') { 'Allow outbound by default' } else { 'Block outbound by default' })
                OutboundTag = "profile|$n|DefaultOutboundAction|$(if ([string]$p.DefaultOutboundAction -eq 'Block') { 'Allow' } else { 'Block' })"
            }
        })
    $c.FwNetworkList.ItemsSource = @(foreach ($net in @($Status.Networks)) {
            $cat = [string]$net.Category
            [pscustomobject]@{
                Title = "$($net.InterfaceAlias): $($net.Network)"; Detail = "Category: $cat$(if ($cat -eq 'DomainAuthenticated') { ' (set by the domain)' }). Internet: $($net.IPv4)"
                PrivateTag = "net|$($net.InterfaceIndex)|Private"; PublicTag = "net|$($net.InterfaceIndex)|Public"
                CanPrivate = ($cat -eq 'Public'); CanPublic = ($cat -eq 'Private')
            }
        })
    $c.FwProfileNote.Text = $(if (@($Status.Networks).Count) { '' } else { 'No connected network was found.' })
    Update-IgwtGuiFirewallOverview
}

function Invoke-IgwtGuiFirewallProfileTag {
    <# .SYNOPSIS A click on a profile toggle or button ("profile|Public|Setting|value") or a network button ("net|index|Category"). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Tag, $Source)
    $p = $Tag.Split('|')
    $refresh = { Set-IgwtGuiFirewallProfiles -Status $script:Gui.FirewallProfiles }
    if ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { Set-IgwtGuiStatus 'Profile changes need administrator rights and are off in read-only mode.'; & $refresh; return }
    if ($p[0] -eq 'net' -and $p.Count -eq 3) {
        $text = $(if ($p[2] -eq 'Private') { "Set this network to Private?`n`nUse Private only for your own home network: it allows discovery and file-sharing rules that apply to private networks." } else { "Set this network to Public?`n`nPublic is the safer choice for networks you do not control." })
        if ((Show-IgwtGuiMessage -Text "$text`n`nA snapshot is written first." -Title 'iG Windows Tuner - network category' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
        $null = Start-IgwtGuiJob -Command 'Set-IgwtNetworkCategory' -Parameters @{ InterfaceIndex = [int]$p[1]; Category = $p[2] } -Blocking -BusyText "Network category -> $($p[2])..." -OnComplete {
            param($out, $errs)
            Complete-IgwtGuiFirewallProfileChange -Result (@($out) | Select-Object -Last 1) -Errors $errs
        }
        return
    }
    if ($p[0] -ne 'profile' -or $p.Count -lt 3) { return }
    $profileName = $p[1]; $setting = $p[2]
    $value = $(if ($p.Count -ge 4) { $p[3] } elseif ($Source -is [System.Windows.Controls.CheckBox]) { [bool]$Source.IsChecked } else { $null })
    if ($setting -in 'Enabled', 'Notifications', 'LogBlocked', 'LogAllowed', 'UnicastResponse') { $value = $(if ($value -is [bool]) { $value } else { [string]$value -eq 'True' }) }
    $why = Get-IgwtFirewallProfileChangeBlock -Setting $setting -Value $value
    if ($why) { $null = Show-IgwtGuiMessage -Text $why -Title 'iG Windows Tuner - firewall profile' -Icon 'Information'; & $refresh; return }
    $label = @{ Enabled = 'Turn the profile on'; Notifications = 'Notifications'; LogBlocked = 'Log blocked connections'; LogAllowed = 'Log allowed connections'; UnicastResponse = 'Unicast response to multicast'; DefaultOutboundAction = 'Default outbound action' }[$setting]
    $extra = $(if ($setting -eq 'DefaultOutboundAction' -and $value -eq 'Block') { "`n`nEvery program then needs an outbound Allow rule to reach the internet; games, updates and Windows features stop working until you add them." } else { '' })
    if ((Show-IgwtGuiMessage -Text "$profileName profile: $label -> ${value}?$extra`n`nA snapshot is written first." -Title 'iG Windows Tuner - firewall profile' -Buttons 'YesNo' -Icon $(if ($extra) { 'Warning' } else { 'Question' })) -ne 'Yes') { & $refresh; return }
    $null = Start-IgwtGuiJob -Command 'Set-IgwtFirewallProfileSetting' -Parameters @{ Profile = $profileName; Setting = $setting; Value = $value } -Blocking -BusyText "$profileName profile: $label..." -OnComplete {
        param($out, $errs)
        Complete-IgwtGuiFirewallProfileChange -Result (@($out) | Select-Object -Last 1) -Errors $errs
    }
}

function Complete-IgwtGuiFirewallProfileChange {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Result, $Errors)
    if (@($Errors).Count -or -not $Result) { Show-IgwtGuiError -Message "The change was not made: $(@($Errors)[0])" -Context 'Firewall' }
    elseif ($Result.Snapshot) { Show-IgwtGuiToast -Text 'Firewall profile changed.' -Tone Success -ActionText 'Undo' -Action { param($snap) Invoke-IgwtGuiFirewallUndo -Snapshot $snap } -ActionArgument ([string]$Result.Snapshot) }
    $null = Start-IgwtGuiJob -Command 'Get-IgwtFirewallProfileStatus' -Channel 'firewall-profiles' -BusyText 'Reading the firewall profiles (read-only)...' -OnComplete {
        param($out, $errs)
        $p = @($out) | Select-Object -Last 1
        if ($p) { Set-IgwtGuiFirewallProfiles -Status $p }
    }
}

#endregion
