# PolicyPage.ps1
# Group Policy browser: the category tree, every policy in a SmartGrid (name, state, category, class,
# supported on), "configured only" and state chips, and a details pane that reads the policy's
# effective state and choices in the background and sets it through Set-IgwtLocalPolicy (denylist,
# backup first, Undo restores the backup).

function New-IgwtGuiPolicyRow {
    <# .SYNOPSIS SmartGrid row for one policy (from Get-IgwtPolicyBrowserData). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Policy)
    $st = [string]$Policy.State
    $row = [ordered]@{ Key = [string]$Policy.Id; Id = [string]$Policy.Id; Name = [string]$Policy.Name; Category = [string]$Policy.Category; Class = [string]$Policy.Class; SupportedOn = [string]$Policy.SupportedOn
        StateKey = $(if ($st -eq 'NotConfigured') { 'NotConfigured' } else { $st }); Configured = $(if ($st -eq 'NotConfigured') { 'No' } else { 'Yes' }); Settable = $(if ($Policy.Simple) { 'Yes' } else { 'Values' }); File = [string]$Policy.File }
    Add-IgwtGuiStatusField -Row $row -Name 'State' -Text $(switch ($st) { 'NotConfigured' { 'Not configured' } default { $st } }) -Tone $(switch ($st) { 'Enabled' { 'Pass' } 'Disabled' { 'Warn' } 'Configured' { 'Info' } default { 'Muted' } })
    return [pscustomobject]$row
}

function Initialize-IgwtGuiPolicyPage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $g = New-IgwtSmartGrid -Id 'policy.list' -Noun 'policies' -RowKey 'Key' -SearchPlaceholder 'Search policy names, categories and ids' `
        -EmptyTitle 'No policies were read' -EmptyText 'Press Refresh to read the administrative templates again.' `
        -Columns @(
        @{ Key = 'Name'; Header = 'Policy'; MinWidth = 260 }
        @{ Key = 'State'; Header = 'State'; Width = 140; Template = 'Status'; SortKey = 'StateKey' }
        @{ Key = 'Category'; Header = 'Category'; Width = 260 }
        @{ Key = 'Class'; Header = 'Applies to'; Width = 120 }
        @{ Key = 'SupportedOn'; Header = 'Supported on'; Width = 220; Visible = $false }
        @{ Key = 'Id'; Header = 'Id'; Width = 220; Visible = $false; Template = 'Mono' }
    ) -Chips @(
        @{ Id = 'configured'; Label = 'Configured only'; Group = 'cfg'; Field = 'Configured'; Values = @('Yes') }
        @{ Id = 'enabled'; Label = 'Enabled'; Group = 'state'; Field = 'StateKey'; Values = @('Enabled') }
        @{ Id = 'disabled'; Label = 'Disabled'; Group = 'state'; Field = 'StateKey'; Values = @('Disabled') }
        @{ Id = 'machine'; Label = 'Computer'; Group = 'class'; Field = 'Class'; Values = @('Machine', 'Machine and user') }
        @{ Id = 'user'; Label = 'User'; Group = 'class'; Field = 'Class'; Values = @('User', 'Machine and user') }
        @{ Id = 'settable'; Label = 'Can be set here'; Group = 'settable'; Field = 'Settable'; Values = @('Yes'); More = $true; Tip = 'Policies without extra values (others are set with -PolicySet)' }
    ) -OnSelectionChanged { param($grid, $sel) $null = $grid, $sel; Start-IgwtGuiPolicyDetail } -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiPolicyRefresh }
    $script:Gui.Grids.Policy = $g
    $c.PolGridHost.Content = $g.Root
    Register-IgwtGuiHandler -Control $c.PolRefreshButton -Event 'Click' -Handler { Start-IgwtGuiPolicyRefresh }
    Register-IgwtGuiHandler -Control $c.PolTree -Event 'SelectedItemChanged' -Handler { Update-IgwtGuiPolicyScope }
    Register-IgwtGuiHandler -Control $c.PolStateBox -Event 'SelectionChanged' -Handler { Update-IgwtGuiPolicyEdit }
    Register-IgwtGuiHandler -Control $c.PolApplyButton -Event 'Click' -Handler { Invoke-IgwtGuiPolicySet }
}

function Start-IgwtGuiPolicyRefresh {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    Set-IgwtGridState -Grid $script:Gui.Grids.Policy -State Loading
    $null = Start-IgwtGuiJob -Command 'Get-IgwtPolicyBrowserData' -Channel 'policy' -BusyText 'Reading the administrative templates and the Local Group Policy (read-only; the first time can take a minute)...' -OnComplete {
        param($out, $errs)
        $d = @($out) | Select-Object -Last 1
        if (-not $d) { Set-IgwtGridState -Grid $script:Gui.Grids.Policy -State Error -Message $(if (@($errs).Count) { [string]@($errs)[0] } else { 'No data was returned.' }); return }
        Set-IgwtGuiPolicyData -Data $d
    }
}

function Set-IgwtGuiPolicyData {
    <# .SYNOPSIS Shows the policies and builds the category tree. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Data)
    $c = $script:Gui.C
    $script:Gui.Policy = $Data
    $script:Gui.PolicyRows = @($Data.Policies | ForEach-Object { New-IgwtGuiPolicyRow -Policy $_ })
    # Category tree: every path segment once, counts in the headers.
    $c.PolTree.Items.Clear()
    $count = @{}
    foreach ($r in $script:Gui.PolicyRows) {
        $parts = @(([string]$r.Category) -split ' > ' | Where-Object { $_ })
        for ($i = 1; $i -le $parts.Count; $i++) { $k = $parts[0..($i - 1)] -join ' > '; if ($count.ContainsKey($k)) { $count[$k]++ } else { $count[$k] = 1 } }
    }
    $all = New-Object System.Windows.Controls.TreeViewItem
    $all.Header = "All policies ($($script:Gui.PolicyRows.Count))"; $all.Tag = ''; $all.IsExpanded = $true
    $nodes = @{ '' = $all }
    foreach ($k in @($count.Keys | Sort-Object)) {
        $parts = @($k -split ' > ')
        $parent = $(if ($parts.Count -gt 1) { $nodes[($parts[0..($parts.Count - 2)] -join ' > ')] } else { $all })
        if (-not $parent) { $parent = $all }
        $n = New-Object System.Windows.Controls.TreeViewItem
        $n.Header = "$($parts[-1]) ($($count[$k]))"; $n.Tag = $k
        $null = $parent.Items.Add($n)
        $nodes[$k] = $n
    }
    $null = $c.PolTree.Items.Add($all)
    $script:Gui.PolicyScope = ''
    Set-IgwtGridRows -Grid $script:Gui.Grids.Policy -Rows $script:Gui.PolicyRows
    $c.PolSummaryText.Text = "$($Data.Count) policies, $($Data.Configured) configured in the Local Group Policy." + $(if (@($Data.Errors).Count) { " $(@($Data.Errors).Count) template file(s) could not be read." } else { '' })
    $c.PolSummaryIcon.Text = [string][char]0xE946
}

function Update-IgwtGuiPolicyScope {
    <# .SYNOPSIS Shows only the policies of the selected category (and its subcategories). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $node = $script:Gui.C.PolTree.SelectedItem
    if (-not $node -or -not $script:Gui.PolicyRows) { return }
    $scope = [string]$node.Tag
    $script:Gui.PolicyScope = $scope
    $rows = $(if (-not $scope) { $script:Gui.PolicyRows } else { @($script:Gui.PolicyRows | Where-Object { $_.Category -eq $scope -or $_.Category.StartsWith("$scope > ") }) })
    Set-IgwtGridRows -Grid $script:Gui.Grids.Policy -Rows $rows
}

function Start-IgwtGuiPolicyDetail {
    <# .SYNOPSIS Reads the selected policy's explanation, effective state and choices in the background. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $row = Get-IgwtGuiGridItem -Name Policy
    $script:Gui.PolicyDetail = $null
    $c.PolEditPanel.Visibility = 'Collapsed'
    if (-not $row) { $c.PolDetName.Text = 'Select a policy'; $c.PolDetMeta.Text = ''; $c.PolDetState.Text = ''; $c.PolDetExplain.Text = 'Pick a policy to see what it does, its effective state and the states it can be set to.'; return }
    $c.PolDetName.Text = $row.Name
    $c.PolDetMeta.Text = "$($row.Category)  |  $($row.Class)  |  $($row.Id)"
    $c.PolDetState.Text = 'Reading its state...'
    $c.PolDetExplain.Text = ''
    $script:Gui.PolicyDetailWanted = $row.Id
    $null = Start-IgwtGuiJob -Command 'Get-IgwtPolicyBrowserDetail' -Parameters @{ Id = $row.Id } -Channel 'policy-detail' -BusyText 'Reading the policy (read-only)...' -OnComplete {
        param($out, $errs)
        $d = @($out) | Select-Object -Last 1
        if ($script:Gui.PolicyDetailWanted -and $d -and $d.Id -ne $script:Gui.PolicyDetailWanted) { Start-IgwtGuiPolicyDetail; return }
        if (-not $d) { $script:Gui.C.PolDetState.Text = "Not readable: $(@($errs)[0])"; return }
        Set-IgwtGuiPolicyDetail -Detail $d
    }
}

function Set-IgwtGuiPolicyDetail {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Detail)
    $c = $script:Gui.C
    $script:Gui.PolicyDetail = $Detail
    $state = $(switch ([string]$Detail.LocalGpo) { 'NotConfigured' { 'Not configured' } default { [string]$Detail.LocalGpo } })
    $c.PolDetState.Text = "Local Group Policy: $state. Effective source: $($Detail.Source).$(if ($Detail.Tattooed) { ' A value is left in the registry without a policy (tattooed).' })$(if (@($Detail.Conflicts).Count) { ' ' + (@($Detail.Conflicts) -join ' ') })"
    $explain = [string]$Detail.Explain
    if ($explain.Length -gt 2400) { $explain = $explain.Substring(0, 2400) + ' ...' }
    $c.PolDetExplain.Text = $explain.Trim()
    $c.PolStateBox.ItemsSource = @(foreach ($ch in @($Detail.Choices)) {
            [pscustomobject]@{ Value = [string]$ch.State; Values = $ch.Values; Label = $(if ($ch.Allowed) { [string]$ch.Label } elseif ([string]$ch.Label -like '*needs values*') { [string]$ch.Label } else { "$($ch.Label) (not allowed)" }); Allowed = [bool]$ch.Allowed; Reason = [string]$ch.Reason }
        })
    # Preselect the current state when it maps to exactly one entry.
    $cur = @($c.PolStateBox.ItemsSource | Where-Object { $_.Value -eq [string]$Detail.LocalGpo })
    if ($cur.Count -eq 1) { $c.PolStateBox.SelectedItem = $cur[0] }
    $c.PolEditPanel.Visibility = 'Visible'
    Update-IgwtGuiPolicyEdit
}

function Update-IgwtGuiPolicyEdit {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $pick = $c.PolStateBox.SelectedItem
    $d = $script:Gui.PolicyDetail
    $same = ($pick -and $d -and [string]$pick.Value -eq [string]$d.LocalGpo -and -not @($pick.Values.Keys).Count)
    $why = $(if (-not $pick) { 'Pick a state.' } elseif (-not $pick.Allowed) { "Not allowed: $($pick.Reason)" } elseif ($same) { 'Already set.' } elseif ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { 'Changes need administrator rights and are off in read-only mode.' } else { '' })
    $c.PolHelp.Text = $(if ($why -and $why -notin 'Pick a state.', 'Already set.') { $why } else { 'A backup of the Local Group Policy is taken first; Undo restores it.' })
    $c.PolApplyButton.IsEnabled = -not $why -and -not [bool]$script:Gui.Job
}

function Invoke-IgwtGuiPolicySet {
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $d = $script:Gui.PolicyDetail
    $pick = $c.PolStateBox.SelectedItem
    if (-not $d -or -not $pick -or -not $pick.Allowed) { return }
    $params = @{ Id = [string]$d.Id; State = [string]$pick.Value }
    if (@($pick.Values.Keys).Count) { $params.Values = $pick.Values }
    $text = "Set '$($d.Name)' to $($pick.Label)?`n`n$($d.Id)`n`nA backup of the Local Group Policy is taken first; Undo restores it."
    $m = $script:Gui.Management
    if ($m -and $m.Managed) { $text += "`n`nThis PC is managed ($(@($m.Authorities) -join ', ')): a domain or MDM policy can override it."; $params.AcknowledgeManaged = $true }
    if ((Show-IgwtGuiMessage -Text $text -Title 'iG Windows Tuner - Group Policy' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    $null = Start-IgwtGuiJob -Command 'Set-IgwtLocalPolicy' -Parameters $params -Blocking -BusyText 'Setting the policy (backup first)...' -OnComplete {
        param($out, $errs)
        $res = @($out) | Select-Object -Last 1
        if (@($errs).Count -or -not $res) { Show-IgwtGuiError -Message "The policy was not changed: $(@($errs)[0])" -Context 'Policy'; return }
        $note = $(if ($res.Verified -eq $false) { " Not every value was found after the refresh: $(@($res.Mismatch) -join ', ')." } else { '' })
        Show-IgwtGuiToast -Text "$($res.Id) -> $($res.State).$note" -Tone $(if ($res.Verified -eq $false) { 'Warning' } else { 'Success' }) -ActionText 'Undo' -Action { param($b) Invoke-IgwtGuiPolicyUndo -Backup $b } -ActionArgument ([string]$res.Backup)
        Start-IgwtGuiPolicyRefresh
    }
}

function Invoke-IgwtGuiPolicyUndo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Backup)
    $null = Start-IgwtGuiJob -Command 'Restore-IgwtLocalGpo' -Parameters @{ BackupPath = $Backup } -Blocking -BusyText 'Restoring the Local Group Policy backup...' -OnComplete {
        param($out, $errs)
        if (@($errs).Count) { Show-IgwtGuiError -Message "Undo failed: $(@($errs)[0])" -Context 'Policy' } else { Show-IgwtGuiToast -Text 'The Local Group Policy was restored.' -Tone Info }
        Start-IgwtGuiPolicyRefresh
    }
}
