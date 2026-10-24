# ListGrids.ps1
# SmartGrids for the remaining lists (Inspect, Toolkit, Diagnostics, Defender settings, Cleaner,
# Disk Analyzer, Startup Apps, Backups and Rejected tweaks): sortable columns, search, chips,
# saved views and export everywhere. Each grid sits in the "<List>Host" content control of its
# page and is stored under the list's name in $script:Gui.Grids (Get-IgwtGuiGridItem -Name).

function Add-IgwtGuiListGrid {
    <# .SYNOPSIS Stores a page grid under its list name and puts it into the page's host control. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][hashtable]$Grid, [string[]]$SortBy = @(), [switch]$Descending, [switch]$Empty)
    $script:Gui.Grids[$Name] = $Grid
    $script:Gui.C["${Name}Host"].Content = $Grid.Root
    # A default sort when the user has not saved one.
    if (-not @($Grid.Sort).Count -and $SortBy.Count) {
        Set-IgwtGridSort -Grid $Grid -Key $SortBy[0] -NoSave
        if ($Descending) { Set-IgwtGridSort -Grid $Grid -Key $SortBy[0] -NoSave }
        foreach ($k in @($SortBy | Select-Object -Skip 1)) { Set-IgwtGridSort -Grid $Grid -Key $k -Add -NoSave }
    }
    # Lists that fill only after a button press (scan, analyze) start empty, not loading.
    if ($Empty) { Set-IgwtGridRows -Grid $Grid -Rows @() }
}

function Get-IgwtGuiGridItems {
    <# .SYNOPSIS The selected rows of a page SmartGrid (empty when none). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $g = $script:Gui.Grids[$Name]
    if (-not $g) { return @() }
    return @(Get-IgwtGridSelection -Grid $g)
}

function Set-IgwtGuiGridRows {
    <# .SYNOPSIS Loads rows into a page SmartGrid by list name (no-op before the grid exists). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [object[]]$Rows = @(), [string]$ErrorText)
    $g = $script:Gui.Grids[$Name]
    if (-not $g) { return }
    if ($ErrorText) { Set-IgwtGridState -Grid $g -State Error -Message $ErrorText; return }
    Set-IgwtGridRows -Grid $g -Rows @($Rows | Where-Object { $null -ne $_ })
}

function Initialize-IgwtGuiListGrids {
    <# .SYNOPSIS Builds the SmartGrids of the Inspect, Toolkit, Diagnostics, Defender, Cleaner, Disk, Startup, Backups and Rejected pages. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param()
    $inspect = { param($grid) $null = $grid; Start-IgwtGuiInspect }
    $toolkit = { param($grid) $null = $grid; Start-IgwtGuiToolkitRefresh -WithAppState:([bool]($script:Gui.Toolkit -and $script:Gui.Toolkit.AppState)) }
    $toolkitSelect = { param($grid, $rows) $null = $grid, $rows; Update-IgwtGuiToolkitDetail }
    $diag = { param($grid) $null = $grid; Start-IgwtGuiDiagRefresh }
    $refresh = { param($grid) $null = $grid; Start-IgwtGuiRefresh }

    # Inspect > Power plan
    $g = New-IgwtSmartGrid -Id 'inspect.power' -Noun 'settings' -RowKey 'Key' -SearchPlaceholder 'Search power settings' -SelectionMode Single `
        -EmptyTitle 'No power settings shown' -EmptyText 'Tick "Show all settings" to list every processor setting of the active plan.' `
        -OnSelectionChanged { param($grid, $rows) $null = $grid, $rows; Update-IgwtGuiPowerDetail } -OnRefresh $inspect -Columns @(
        @{ Key = 'Alias'; Header = 'Setting'; MinWidth = 160; Width = 200; Tip = 'Tip' }
        @{ Key = 'Name'; Header = 'Name'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'AcText'; Header = 'Plugged in'; Width = 130 }
        @{ Key = 'DcText'; Header = 'Battery'; Width = 130 }
        @{ Key = 'State'; Header = 'Status'; Width = 230; Template = 'Status'; SortKey = 'EditKey' }
        @{ Key = 'Group'; Header = 'Group'; Width = 140; Visible = $false }
        @{ Key = 'LevelText'; Header = 'Level'; Width = 90; Visible = $false }
    ) -Chips @(
        @{ Id = 'editable'; Label = 'Editable here'; Group = 'edit'; Field = 'EditKey'; Values = @('Editable') }
        @{ Id = 'changed'; Label = 'Differs from default'; Group = 'changed'; Field = 'ChangedKey'; Values = @('Yes') }
        @{ Id = 'hidden'; Label = 'Hidden by Windows'; Group = 'hidden'; Field = 'HiddenKey'; Values = @('Yes'); Tip = 'Settings that Power Options does not show' }
        @{ Id = 'blocked'; Label = 'Blocked here'; Group = 'edit'; Field = 'EditKey'; Values = @('Blocked'); Tip = 'Settings a hardware rule blocks on this PC' }
    )
    Add-IgwtGuiListGrid -Name 'InspectPowerList' -Grid $g -SortBy 'State', 'Alias'

    # Inspect > Interrupts
    $g = New-IgwtSmartGrid -Id 'inspect.irq' -Noun 'devices' -RowKey 'Key' -SearchPlaceholder 'Search devices' -OnRefresh $inspect -Columns @(
        @{ Key = 'Device'; Header = 'Device'; MinWidth = 220; Tip = 'Tip' }
        @{ Key = 'Class'; Header = 'Class'; Width = 120 }
        @{ Key = 'Mode'; Header = 'Interrupts'; Width = 200; Template = 'Status' }
        @{ Key = 'SupportsText'; Header = 'Supports'; Width = 220 }
        @{ Key = 'PolicyText'; Header = 'Affinity and priority'; Width = 240 }
        @{ Key = 'Note'; Header = 'Note'; Width = 240; Visible = $false }
    ) -Chips @(
        @{ Id = 'msi'; Label = 'Message-signaled'; Group = 'mode'; Field = 'ModeKey'; Values = @('Message-signaled') }
        @{ Id = 'line'; Label = 'Line-based'; Group = 'mode'; Field = 'ModeKey'; Values = @('Line-based') }
    )
    Add-IgwtGuiListGrid -Name 'InspectIrqList' -Grid $g -SortBy 'Class', 'Device'

    # Inspect > Kernel and memory
    $g = New-IgwtSmartGrid -Id 'inspect.kernel' -Noun 'values' -RowKey 'RowId' -SearchPlaceholder 'Search values, keys and meanings' -OnRefresh $inspect `
        -EmptyTitle 'Every value is at the Windows default' -EmptyText 'Untick "Only values that differ" to see all of them.' -Columns @(
        @{ Key = 'Name'; Header = 'Value'; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'Key'; Header = 'Key'; Width = 260; Template = 'Mono' }
        @{ Key = 'Current'; Header = 'Current'; Width = 130 }
        @{ Key = 'Default'; Header = 'Windows default'; Width = 130 }
        @{ Key = 'Status'; Header = 'Status'; Width = 110; Template = 'Status' }
        @{ Key = 'Link'; Header = 'How to change'; Width = 260 }
        @{ Key = 'Meaning'; Header = 'Meaning'; Width = 320; Visible = $false }
    ) -Chips @(
        @{ Id = 'changed'; Label = 'Differs'; Group = 'status'; Field = 'StatusKey'; Values = @('Changed') }
        @{ Id = 'default'; Label = 'Default'; Group = 'status'; Field = 'StatusKey'; Values = @('Default') }
        @{ Id = 'absent'; Label = 'Not set'; Group = 'status'; Field = 'StatusKey'; Values = @('Absent') }
        @{ Id = 'item'; Label = 'Has a catalog item'; Group = 'item'; Field = 'HasItem'; Values = @('Yes'); Tip = 'Values a catalog item can change (with snapshot and revert)' }
    )
    Add-IgwtGuiListGrid -Name 'InspectKernelList' -Grid $g -SortBy 'Key', 'Name'

    # Toolkit
    $g = New-IgwtSmartGrid -Id 'toolkit.apps' -Noun 'apps' -RowKey 'Key' -SearchPlaceholder 'Search apps' -OnSelectionChanged $toolkitSelect -OnRefresh $toolkit `
        -EmptyTitle 'No apps listed' -EmptyText 'The curated app list could not be read; see the log.' -Columns @(
        @{ Key = 'Title'; Header = 'App'; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'Badge'; Header = 'Category'; Width = 140 }
        @{ Key = 'State'; Header = 'Status'; Width = 170; Template = 'Status' }
        @{ Key = 'PackageId'; Header = 'Package'; Width = 220; Template = 'Mono' }
        @{ Key = 'Hint'; Header = 'What it is'; Width = 300; Visible = $false }
    ) -Chips @(
        @{ Id = 'installed'; Label = 'Installed'; Group = 'inst'; Field = 'InstalledKey'; Values = @('Yes') }
        @{ Id = 'notinstalled'; Label = 'Not installed'; Group = 'inst'; Field = 'InstalledKey'; Values = @('No') }
        @{ Id = 'foss'; Label = 'Open source'; Group = 'foss'; Field = 'FossKey'; Values = @('Yes') }
    )
    Add-IgwtGuiListGrid -Name 'ToolkitAppList' -Grid $g -SortBy 'Badge', 'Title'

    $catalogColumns = @(
        @{ Key = 'Title'; Header = 'Item'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'Category'; Header = 'Category'; Width = 150 }
        @{ Key = 'Level'; Header = 'Level'; Width = 100 }
        @{ Key = 'State'; Header = 'Current'; Width = 140; Template = 'Status' }
        @{ Key = 'Subtitle'; Header = 'What it does'; Width = 300; Visible = $false }
        @{ Key = 'Id'; Header = 'Id'; Width = 220; Template = 'Mono'; Visible = $false }
    )
    $catalogChips = @(
        @{ Id = 'on'; Label = 'On'; Group = 'state'; Field = 'State'; Values = @('On') }
        @{ Id = 'off'; Label = 'Off or partly on'; Group = 'state'; Field = 'State'; Values = @('Off', 'Partial') }
    )
    $g = New-IgwtSmartGrid -Id 'toolkit.tweaks' -Noun 'items' -RowKey 'Key' -SearchPlaceholder 'Search WinUtil-derived items' -SelectionMode Single -OnSelectionChanged $toolkitSelect -Columns $catalogColumns -Chips $catalogChips
    Add-IgwtGuiListGrid -Name 'ToolkitTweakList' -Grid $g -SortBy 'Category', 'Title'
    $g = New-IgwtSmartGrid -Id 'toolkit.updates' -Noun 'items' -RowKey 'Key' -SearchPlaceholder 'Search Windows Update items' -SelectionMode Single -OnSelectionChanged $toolkitSelect -Columns $catalogColumns -Chips $catalogChips
    Add-IgwtGuiListGrid -Name 'ToolkitUpdateList' -Grid $g -SortBy 'Title'

    $g = New-IgwtSmartGrid -Id 'toolkit.features' -Noun 'features' -RowKey 'Key' -SearchPlaceholder 'Search features' -SelectionMode Single -OnSelectionChanged $toolkitSelect -OnRefresh $toolkit -Columns @(
        @{ Key = 'Title'; Header = 'Feature'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'Badge'; Header = 'Kind and editions'; Width = 200 }
        @{ Key = 'State'; Header = 'State'; Width = 170; Template = 'Status' }
        @{ Key = 'Subtitle'; Header = 'What it is'; Width = 300; Visible = $false }
    ) -Chips @(
        @{ Id = 'enabled'; Label = 'Enabled'; Group = 'state'; Field = 'State'; Values = @('Enabled', 'Partly enabled') }
        @{ Id = 'disabled'; Label = 'Disabled'; Group = 'state'; Field = 'State'; Values = @('Disabled') }
    )
    Add-IgwtGuiListGrid -Name 'ToolkitFeatureList' -Grid $g -SortBy 'Title'

    $g = New-IgwtSmartGrid -Id 'toolkit.fixes' -Noun 'fixes' -RowKey 'Key' -SearchPlaceholder 'Search fixes' -SelectionMode Single -OnSelectionChanged $toolkitSelect -Columns @(
        @{ Key = 'Title'; Header = 'Fix'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'Badge'; Header = 'Needs'; Width = 140 }
        @{ Key = 'State'; Header = 'Takes'; Width = 120; Kind = 'Number'; SortKey = 'Minutes' }
        @{ Key = 'Subtitle'; Header = 'What it does'; Width = 320 }
    ) -Chips @(
        @{ Id = 'user'; Label = 'No administrator needed'; Group = 'admin'; Field = 'AdminKey'; Values = @('No') }
        @{ Id = 'restart'; Label = 'Needs a restart'; Group = 'restart'; Field = 'RestartKey'; Values = @('Yes') }
    )
    Add-IgwtGuiListGrid -Name 'ToolkitFixList' -Grid $g -SortBy 'Title'

    $g = New-IgwtSmartGrid -Id 'toolkit.panels' -Noun 'panels' -RowKey 'Key' -SearchPlaceholder 'Search panels' -SelectionMode Single -OnSelectionChanged $toolkitSelect `
        -OnActivate { param($grid, $row) $null = $grid; try { Start-IgwtPanel -Id ([string]$row.Source.Id) } catch { $null = Show-IgwtGuiMessage -Text $_.Exception.Message -Icon 'Warning' } } -Columns @(
        @{ Key = 'Title'; Header = 'Panel'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'Subtitle'; Header = 'What it is'; Width = 320 }
        @{ Key = 'Badge'; Header = 'Opens'; Width = 200; Template = 'Mono' }
    )
    Add-IgwtGuiListGrid -Name 'ToolkitPanelList' -Grid $g -SortBy 'Title'

    # Diagnostics
    $g = New-IgwtSmartGrid -Id 'diag.drivers' -Noun 'drivers' -RowKey 'Key' -SearchPlaceholder 'Search drivers' -OnRefresh $diag -Columns @(
        @{ Key = 'Title'; Header = 'Device'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'Badge'; Header = 'Class'; Width = 120 }
        @{ Key = 'Provider'; Header = 'Provider'; Width = 160 }
        @{ Key = 'Version'; Header = 'Version'; Width = 130 }
        @{ Key = 'DriverDate'; Header = 'Date'; Width = 110; Kind = 'Date' }
        @{ Key = 'State'; Header = 'Status'; Width = 110; Template = 'Status' }
        @{ Key = 'Signer'; Header = 'Signer'; Width = 200; Visible = $false }
    ) -Chips @(
        @{ Id = 'unsigned'; Label = 'Unsigned'; Group = 'flag'; Field = 'State'; Values = @('Unsigned') }
        @{ Id = 'old'; Label = 'Older than three years'; Group = 'flag'; Field = 'State'; Values = @('Old') }
    )
    Add-IgwtGuiListGrid -Name 'DiagDriverList' -Grid $g -SortBy 'State', 'Title'

    $g = New-IgwtSmartGrid -Id 'diag.adapters' -Noun 'properties' -RowKey 'Key' -SearchPlaceholder 'Search adapter properties' -OnRefresh $diag -Columns @(
        @{ Key = 'Property'; Header = 'Property'; MinWidth = 180; Tip = 'Tip' }
        @{ Key = 'Value'; Header = 'Value'; Width = 140 }
        @{ Key = 'DefaultValue'; Header = 'Default'; Width = 110 }
        @{ Key = 'State'; Header = 'Status'; Width = 110; Template = 'Status' }
        @{ Key = 'Badge'; Header = 'Adapter'; Width = 160 }
        @{ Key = 'Keyword'; Header = 'Keyword'; Width = 200; Template = 'Mono'; Visible = $false }
    ) -Chips @(
        @{ Id = 'changed'; Label = 'Changed from default'; Group = 'state'; Field = 'State'; Values = @('Changed') }
    )
    Add-IgwtGuiListGrid -Name 'DiagAdapterList' -Grid $g -SortBy 'Badge', 'Property'

    # Security > Defender settings: preferences and Group Policy (the category box scopes the preferences).
    $defSelect = { param($grid, $rows) $null = $grid, $rows; Update-IgwtGuiDefenderDetails }
    $g = New-IgwtSmartGrid -Id 'defender.prefs' -Noun 'settings' -RowKey 'Key' -SearchPlaceholder 'Search names, descriptions and property names' -SelectionMode Single `
        -OnSelectionChanged $defSelect -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiDefenderRefresh } `
        -EmptyTitle 'Not read yet' -EmptyText 'The Defender settings are read when the page opens.' -Columns @(
        @{ Key = 'Name'; Header = 'Setting'; MinWidth = 180; Tip = 'Hint' }
        @{ Key = 'CategoryText'; Header = 'Category'; Width = 150 }
        @{ Key = 'ValueCol'; Header = 'Current'; Width = 150; Template = 'Status'; SortKey = 'StatusRank' }
        @{ Key = 'RecommendText'; Header = 'Recommended'; Width = 190; Visible = $false }
        @{ Key = 'EditCol'; Header = 'Change'; Width = 140; Template = 'Status' }
        @{ Key = 'SourceName'; Header = 'Set by'; Width = 110; Visible = $false }
        @{ Key = 'Id'; Header = 'Property'; Width = 220; Template = 'Mono'; Visible = $false }
        @{ Key = 'CategoryId'; Header = 'Category id'; Width = 120; Visible = $false; Search = $false }
    ) -Chips @(
        @{ Id = 'attention'; Label = 'Needs attention'; Group = 'status'; Field = 'StatusKey'; Values = @('Off', 'Below', 'Optional'); Tip = 'Settings that are off, below the recommended level, or optional hardening that is off' }
        @{ Id = 'on'; Label = 'Meets recommendation'; Group = 'status'; Field = 'StatusKey'; Values = @('On') }
        @{ Id = 'editable'; Label = 'Changeable here'; Group = 'edit'; Field = 'EditableKey'; Values = @('Yes') }
        @{ Id = 'managed'; Label = 'Set by a policy'; Group = 'source'; Test = { param($row) [string]$row.SourceName -and [string]$row.SourceName -ne 'Local' } }
    )
    Add-IgwtGuiListGrid -Name 'DefList' -Grid $g -SortBy 'ValueCol', 'Name'

    $g = New-IgwtSmartGrid -Id 'defender.policies' -Noun 'policies' -RowKey 'Key' -SearchPlaceholder 'Search policies' -SelectionMode Single `
        -OnSelectionChanged $defSelect -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiDefenderRefresh -Policies } `
        -EmptyTitle 'Not read yet' -EmptyText 'The Defender Group Policy settings are read the first time this view opens.' -Columns @(
        @{ Key = 'Name'; Header = 'Policy'; MinWidth = 200; Tip = 'Id' }
        @{ Key = 'CategoryText'; Header = 'Category'; Width = 200 }
        @{ Key = 'StateCol'; Header = 'State'; Width = 140; Template = 'Status' }
        @{ Key = 'SourceText'; Header = 'Set in'; Width = 150 }
        @{ Key = 'PreferenceName'; Header = 'Preference'; Width = 170; Visible = $false }
        @{ Key = 'RefusedList'; Header = 'Refused states'; Width = 150; Visible = $false }
    ) -Chips @(
        @{ Id = 'configured'; Label = 'Configured'; Group = 'state'; Field = 'StateKey'; Values = @('Enabled', 'Disabled') }
        @{ Id = 'notconfigured'; Label = 'Not configured'; Group = 'state'; Field = 'StateKey'; Values = @('NotConfigured') }
        @{ Id = 'simple'; Label = 'Settable here'; Group = 'simple'; Field = 'SimpleKey'; Values = @('Yes'); Tip = 'Policies this page can set; the others take values on the command line (-PolicySet -PolicyValue)' }
    )
    Add-IgwtGuiListGrid -Name 'DefPolicyList' -Grid $g -SortBy 'CategoryText', 'Name'

    # Cleaner: a tick box per rule (Tag = rule id); the page keeps the selection.
    $g = New-IgwtSmartGrid -Id 'cleaner.rules' -Noun 'rules' -RowKey 'Key' -SearchPlaceholder 'Search rules' -SelectionMode Single -OnRefresh { param($grid) $null = $grid; Start-IgwtGuiCleanerScan } `
        -EmptyTitle 'No scan yet' -EmptyText 'Press Scan to see what each rule would remove. Nothing is deleted by a scan.' -Columns @(
        @{ Key = 'On'; Header = 'Clean'; Width = 64; MinWidth = 56; Template = 'Toggle'; Search = $false }
        @{ Key = 'Name'; Header = 'Rule'; MinWidth = 200; Tip = 'Tip' }
        @{ Key = 'SizeText'; Header = 'Size'; Width = 100; Kind = 'Number'; SortKey = 'Bytes' }
        @{ Key = 'CountText'; Header = 'Items'; Width = 100; Kind = 'Number'; SortKey = 'Count' }
        @{ Key = 'StatusCol'; Header = 'Status'; Width = 170; Template = 'Status' }
        @{ Key = 'Category'; Header = 'Category'; Width = 130 }
        @{ Key = 'LevelCol'; Header = 'Level'; Width = 110; Template = 'Status'; Kind = 'Number'; SortKey = 'LevelRank' }
        @{ Key = 'OptInText'; Header = 'Opt-in'; Width = 80; Visible = $false }
        @{ Key = 'Reason'; Header = 'Note'; Width = 260; Visible = $false }
    ) -Chips @(
        @{ Id = 'ready'; Label = 'Ready to clean'; Group = 'status'; Field = 'Status'; Values = @('Ready') }
        @{ Id = 'blocked'; Label = 'Needs attention'; Group = 'status'; Field = 'Status'; Values = @('RequiresClose', 'RequiresAdmin', 'Error'); Tip = 'Rules that need an app closed or administrator rights' }
        @{ Id = 'ticked'; Label = 'Ticked'; Group = 'ticked'; Test = { param($row) [bool]$script:Gui.CleanSelected[[string]$row.Key] } }
    )
    Add-IgwtGuiListGrid -Name 'CleanerList' -Grid $g -SortBy 'SizeText' -Descending -Empty

    # Disk Analyzer: double-click a folder to look inside it.
    $diskSelect = { param($grid, $rows) $null = $grid; $r = @($rows) | Select-Object -First 1; if ($r) { $script:Gui.DiskSelected = $r.Path } }
    $g = New-IgwtSmartGrid -Id 'disk.folders' -Noun 'folders' -RowKey 'Path' -SearchPlaceholder 'Search folders' -SelectionMode Single -OnSelectionChanged $diskSelect `
        -OnActivate { param($grid, $row) $null = $grid; if ($row -and -not $script:Gui.Job) { Start-IgwtGuiDiskAnalyze -Path $row.Path } } `
        -EmptyTitle 'Nothing analyzed yet' -EmptyText 'Enter a folder or drive and press Analyze (read-only).' -Columns @(
        @{ Key = 'Name'; Header = 'Folder'; MinWidth = 140; Tip = 'Path' }
        @{ Key = 'SizeText'; Header = 'Size'; Width = 90; Kind = 'Number'; SortKey = 'Bytes' }
        @{ Key = 'ShareText'; Header = 'Of largest'; Width = 90; Kind = 'Number'; SortKey = 'Bytes'; Search = $false }
        @{ Key = 'Extra'; Header = 'Files'; Width = 110 }
        @{ Key = 'Parent'; Header = 'In'; Width = 200; Visible = $false }
    )
    Add-IgwtGuiListGrid -Name 'DiskFolderList' -Grid $g -SortBy 'SizeText' -Descending -Empty
    $g = New-IgwtSmartGrid -Id 'disk.files' -Noun 'files' -RowKey 'Path' -SearchPlaceholder 'Search files' -SelectionMode Single -OnSelectionChanged $diskSelect `
        -EmptyTitle 'Nothing analyzed yet' -EmptyText 'Enter a folder or drive and press Analyze (read-only).' -Columns @(
        @{ Key = 'Name'; Header = 'File'; MinWidth = 140; Tip = 'Path' }
        @{ Key = 'SizeText'; Header = 'Size'; Width = 90; Kind = 'Number'; SortKey = 'Bytes' }
        @{ Key = 'Extra'; Header = 'Modified'; Width = 100; Kind = 'Date' }
        @{ Key = 'Parent'; Header = 'In'; Width = 240; Visible = $false }
    )
    Add-IgwtGuiListGrid -Name 'DiskFileList' -Grid $g -SortBy 'SizeText' -Descending -Empty

    # Startup Apps: a switch per entry (StartupApproved; entries are never deleted).
    $g = New-IgwtSmartGrid -Id 'startup.entries' -Noun 'entries' -RowKey 'Key' -SearchPlaceholder 'Search startup entries' -SelectionMode Single -OnRefresh $refresh `
        -EmptyTitle 'No startup entries' -EmptyText 'Nothing starts from the Run keys or the Startup folders.' -Columns @(
        @{ Key = 'On'; Header = 'On'; Width = 64; MinWidth = 56; Template = 'Toggle'; Search = $false }
        @{ Key = 'Name'; Header = 'Entry'; Width = 220; MinWidth = 140; Tip = 'Command' }
        @{ Key = 'ScopeText'; Header = 'Starts for'; Width = 120 }
        @{ Key = 'Command'; Header = 'Command'; MinWidth = 240; Template = 'Mono'; Tip = 'Command' }
        @{ Key = 'Scope'; Header = 'Location'; Width = 120; Visible = $false }
    ) -Chips @(
        @{ Id = 'on'; Label = 'On'; Group = 'state'; Field = 'StateKey'; Values = @('On') }
        @{ Id = 'off'; Label = 'Off'; Group = 'state'; Field = 'StateKey'; Values = @('Off') }
        @{ Id = 'user'; Label = 'This user'; Group = 'scope'; Field = 'ScopeText'; Values = @('This user') }
        @{ Id = 'machine'; Label = 'All users'; Group = 'scope'; Field = 'ScopeText'; Values = @('All users') }
    )
    Add-IgwtGuiListGrid -Name 'StartupList' -Grid $g -SortBy 'Name'

    # Backups: the snapshots, newest first.
    $g = New-IgwtSmartGrid -Id 'backups.snapshots' -Noun 'snapshots' -RowKey 'Key' -SearchPlaceholder 'Search snapshots' -SelectionMode Single -OnRefresh $refresh `
        -OnSelectionChanged { param($grid, $rows) $null = $grid, $rows; Update-IgwtGuiButtons } `
        -EmptyTitle 'No snapshots yet' -EmptyText 'Every apply, revert and change writes a snapshot here before anything changes.' -Columns @(
        @{ Key = 'When'; Header = 'When'; Width = 160; Kind = 'Date' }
        @{ Key = 'Operation'; Header = 'Operation'; Width = 200 }
        @{ Key = 'KindText'; Header = 'Area'; Width = 110 }
        @{ Key = 'Entries'; Header = 'Entries'; Width = 80; Kind = 'Number' }
        @{ Key = 'FailedCol'; Header = 'Failed'; Width = 90; Template = 'Status'; Kind = 'Number'; SortKey = 'Failed' }
        @{ Key = 'Detail'; Header = 'Detail'; MinWidth = 200 }
        @{ Key = 'File'; Header = 'File'; Width = 260; Template = 'Mono'; Visible = $false }
    ) -Chips @(
        @{ Id = 'tweaks'; Label = 'Tweaks and presets'; Group = 'kind'; Field = 'KindText'; Values = @('Tweaks') }
        @{ Id = 'revert'; Label = 'Reverts'; Group = 'kind'; Field = 'KindText'; Values = @('Revert') }
        @{ Id = 'security'; Label = 'Security'; Group = 'kind'; Field = 'KindText'; Values = @('Security') }
        @{ Id = 'system'; Label = 'System'; Group = 'kind'; Field = 'KindText'; Values = @('System') }
        @{ Id = 'failed'; Label = 'With failures'; Group = 'failed'; Test = { param($row) [int]$row.Failed -gt 0 } }
    )
    Add-IgwtGuiListGrid -Name 'SnapshotList' -Grid $g -SortBy 'When' -Descending

    # Rejected tweaks
    $g = New-IgwtSmartGrid -Id 'rejected' -Noun 'tweaks' -RowKey 'Key' -SearchPlaceholder 'Search rejected tweaks' -SelectionMode Single -Columns @(
        @{ Key = 'Name'; Header = 'Tweak'; Width = 280; MinWidth = 180; Tip = 'Reason' }
        @{ Key = 'Category'; Header = 'Why rejected'; Width = 150 }
        @{ Key = 'Claim'; Header = 'Claim'; MinWidth = 200; Tip = 'Claim' }
        @{ Key = 'AvailCol'; Header = 'Availability'; Width = 170; Template = 'Status'; Tip = 'AvailTip' }
        @{ Key = 'RiskItem'; Header = 'Risk Zone item'; Width = 220; Template = 'Mono'; Visible = $false }
        @{ Key = 'Reason'; Header = 'Reason'; Width = 360; Visible = $false }
    ) -Chips @(
        @{ Id = 'risk'; Label = 'In the Risk Zone'; Group = 'avail'; Field = 'RiskKey'; Values = @('Yes'); Tip = 'Reversible items you can apply at your own risk' }
        @{ Id = 'never'; Label = 'Not offered'; Group = 'avail'; Field = 'RiskKey'; Values = @('No') }
    )
    Add-IgwtGuiListGrid -Name 'RejectedList' -Grid $g -SortBy 'Category', 'Name'
}

function New-IgwtGuiStartupRow {
    <# .SYNOPSIS SmartGrid row for one startup entry. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry, [bool]$CanToggle)
    $enabled = [bool]$Entry.Enabled
    [pscustomobject]@{
        Key = "$($Entry.Scope)|$($Entry.Name)"; Scope = [string]$Entry.Scope; Name = [string]$Entry.Name; Command = [string]$Entry.Command; Enabled = $enabled; CanToggle = $CanToggle
        ScopeText = $(if ([string]$Entry.Scope -in 'HKCU-Run', 'User-Folder') { 'This user' } else { 'All users' }); StateKey = $(if ($enabled) { 'On' } else { 'Off' })
        On = $enabled; OnEnabled = $CanToggle; OnName = "Start $($Entry.Name) with Windows"
        OnTip = $(if ($CanToggle) { 'Turn this startup entry on or off (StartupApproved; the entry is never deleted).' } else { 'Restart as administrator to turn startup entries on or off.' })
    }
}

function New-IgwtGuiSnapshotRow {
    <# .SYNOPSIS SmartGrid row for one snapshot (from Get-IgwtSnapshotList). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Snapshot)
    $s = $Snapshot
    $when = [string]$s.Created
    try { $when = ([datetime]::Parse([string]$s.Created, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch { Write-Verbose 'Unparsable snapshot time.' }
    $op = [string]$s.Operation
    $head = ($op -split ':')[0]
    $kind = switch -Regex ($head) {
        '^(Apply|Preset|ResetDefault|Session)$' { 'Tweaks' }
        '^Revert' { 'Revert' }
        '^(ASR|Asr|Defender|Firewall|Policy|SecPolicy|Audit|Baseline|Tattoo)' { 'Security' }
        '^(Manage|Toolkit|Startup|Power|Cleaner|Network)' { 'System' }
        default { 'Other' }
    }
    $failed = 0
    if ($s.PSObject.Properties['Failed'] -and $null -ne $s.Failed) { $failed = [int]$s.Failed }
    $r = [ordered]@{
        Key = [string]$s.Path; Path = [string]$s.Path; File = [string]$s.File; When = $when; Operation = $op; KindText = $kind
        Entries = @($s.Applied).Count; Failed = $failed; Detail = [string]$s.Detail
        Summary = "$(@($s.Applied).Count) applied/reverted entr(ies), $failed failed. $($s.Detail)"
    }
    Add-IgwtGuiStatusField -Row $r -Name 'FailedCol' -Text $(if ($failed) { "$failed failed" } else { 'None' }) -Tone $(if ($failed) { 'Warn' } else { 'Pass' })
    [pscustomobject]$r
}

function New-IgwtGuiRejectedRow {
    <# .SYNOPSIS SmartGrid row for one rejected tweak. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory row only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)
    $e = $Entry
    $risk = [bool]$e.riskItem
    $r = [ordered]@{
        Key = $(if ($e.id) { [string]$e.id } else { [string]$e.name }); Name = [string]$e.name; Category = [string]$e.category; Claim = [string]$e.claim
        Reason = ([string]$e.reason + $(if (@($e.sources).Count) { "`nSources: " + (@($e.sources) -join '  ') } else { '' }))
        RiskKey = $(if ($risk) { 'Yes' } else { 'No' })
    }
    $r.RiskItem = [string]$e.riskItem
    $r.AvailTip = $(if ($risk) { "Available in the Risk Zone at your own risk: $($e.riskItem)" } elseif ($e.unavailable) { [string]$e.unavailable } else { 'Not offered.' })
    Add-IgwtGuiStatusField -Row $r -Name 'AvailCol' -Text $(if ($risk) { 'In the Risk Zone' } else { 'Not offered' }) -Tone $(if ($risk) { 'Warn' } else { 'Muted' }) -Locked:(-not $risk)
    [pscustomobject]$r
}
