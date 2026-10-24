# SmartGrid.ps1
# One reusable list component for every table in the GUI: search (debounced), quick-filter
# chips, per-column filters, single and multi-column sort (Shift+click), column chooser,
# reorder and resize, saved views (remembered per user), multi-select with a bulk-action bar,
# a context menu that mirrors the actions, CSV/JSON export of the current view, virtualization
# and the loading / empty / error / stale states.
#
# The query engine (New-IgwtGridIndex, Invoke-IgwtGridQuery) is plain PowerShell over arrays
# and runs headless in the tests. It precomputes one search string and one sort key per row and
# column when the data is loaded, and sorts with Array.Sort on ranks, so sorting and filtering
# 1,000+ rows stay well under 200 ms on Windows PowerShell 5.1.

#region Query engine (headless)

function ConvertTo-IgwtGridColumn {
    <#
    .SYNOPSIS
        Normalizes a column definition. Keys: Key (row property shown), Header, Kind (Text, Number,
        Date), SortKey (row property to sort by; default Key), Template (Text, Mono, Status, Badge),
        Width, MinWidth, Visible, Search (searched by the text box), Filter (offers a per-column filter),
        Tip (row property for the cell tooltip).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Definition)
    $d = $Definition
    $get = { param($n, $default) if ($d -is [hashtable]) { if ($d.ContainsKey($n) -and $null -ne $d[$n]) { return $d[$n] } } elseif ($d.PSObject.Properties[$n] -and $null -ne $d.$n) { return $d.$n }; return $default }
    $key = [string](& $get 'Key' '')
    if (-not $key) { throw 'A SmartGrid column needs a Key.' }
    $kind = [string](& $get 'Kind' 'Text')
    if ($kind -notin 'Text', 'Number', 'Date') { $kind = 'Text' }
    $template = [string](& $get 'Template' 'Text')
    if ($template -notin 'Text', 'Mono', 'Status', 'Badge', 'Toggle') { $template = 'Text' }
    return [pscustomobject]@{
        Key = $key; Header = [string](& $get 'Header' $key); Kind = $kind; SortKey = [string](& $get 'SortKey' $key); Template = $template
        Width = [double](& $get 'Width' 0); MinWidth = [double](& $get 'MinWidth' 60); Visible = [bool](& $get 'Visible' $true)
        Search = [bool](& $get 'Search' ($kind -ne 'Date')); Filter = [bool](& $get 'Filter' $false); Tip = [string](& $get 'Tip' '')
    }
}

function Get-IgwtGridValue {
    <# .SYNOPSIS A row property as display text; never throws (missing properties are empty). #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Row, [string]$Name)
    if ($null -eq $Row -or -not $Name) { return '' }
    $v = $null
    if ($Row -is [hashtable]) { $v = $Row[$Name] } else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($null -eq $v) { return '' }
    if ($v -is [array]) { return (@($v | ForEach-Object { [string]$_ }) -join ', ') }
    return [string]$v
}

function New-IgwtGridIndex {
    <#
    .SYNOPSIS
        Precomputes the search text and the sort keys of every row. Rebuild it when the rows change.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds in-memory objects only.')]
    [CmdletBinding()]
    param([object[]]$Rows = @(), [Parameter(Mandatory = $true)][object[]]$Columns)
    $cols = @($Columns | ForEach-Object { if ($_.PSObject.Properties['SortKey'] -and $_.PSObject.Properties['Template']) { $_ } else { ConvertTo-IgwtGridColumn -Definition $_ } })
    $rows = @($Rows | Where-Object { $null -ne $_ })
    $n = $rows.Count
    $keys = @{}; $texts = @{}
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $float = [System.Globalization.NumberStyles]::Float
    # One pass per column (inline member access; a function call per cell is 100 times slower).
    foreach ($c in $cols) {
        $name = $c.Key
        $tx = New-Object 'string[]' $n
        $i = 0
        foreach ($row in $rows) {
            $v = $row.$name
            if ($null -eq $v) { $tx[$i] = '' } elseif ($v -is [array]) { $tx[$i] = ($v -join ', ') } else { $tx[$i] = [string]$v }
            $i++
        }
        $texts[$name] = $tx
        $sortName = $c.SortKey
        if ($c.Kind -eq 'Text') {
            if ($sortName -eq $name) { $keys[$name] = $tx }
            else {
                $k = New-Object 'string[]' $n; $i = 0
                foreach ($row in $rows) { $v = $row.$sortName; if ($null -eq $v) { $k[$i] = '' } elseif ($v -is [array]) { $k[$i] = ($v -join ', ') } else { $k[$i] = [string]$v }; $i++ }
                $keys[$name] = $k
            }
        } else {
            $k = New-Object 'double[]' $n; $i = 0
            foreach ($row in $rows) {
                $v = $row.$sortName
                $d = [double]::NegativeInfinity
                if ($v -is [datetime]) { $d = [double]$v.Ticks }
                elseif ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [single] -or $v -is [uint32] -or $v -is [uint64] -or $v -is [int16] -or $v -is [byte]) { $d = [double]$v }
                elseif ($null -ne $v -and "$v") {
                    $p = 0.0; $dt = [datetime]::MinValue
                    if ($c.Kind -eq 'Date' -and [datetime]::TryParse([string]$v, [ref]$dt)) { $d = [double]$dt.Ticks }
                    elseif ([double]::TryParse(([string]$v -replace '[^\d\.\-eE]', ''), $float, $inv, [ref]$p)) { $d = $p }
                }
                $k[$i] = $d; $i++
            }
            $keys[$name] = $k
        }
    }
    $searchCols = New-Object System.Collections.Generic.List[object]
    foreach ($c in $cols) { if ($c.Search) { $searchCols.Add($texts[$c.Key]) } }
    $search = New-Object 'string[]' $n
    $sep = [string][char]0x1F
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $n; $i++) {
        $null = $sb.Clear()
        foreach ($t in $searchCols) { $null = $sb.Append($t[$i]).Append($sep) }
        $search[$i] = $sb.ToString().ToLowerInvariant()
    }
    return @{ Rows = $rows; Count = $n; Columns = $cols; Search = $search; Keys = $keys; Texts = $texts; Ranks = @{}; Chips = @{} }
}

function Get-IgwtGridRank {
    <# .SYNOPSIS Dense rank of every row for one column (ties share a rank); cached in the index. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Index, [Parameter(Mandatory = $true)][string]$Key)
    if ($Index.Ranks.ContainsKey($Key)) { return $Index.Ranks[$Key] }
    $keys = $Index.Keys[$Key]
    $n = $Index.Count
    $rank = New-Object 'int[]' $n
    if ($n -gt 0) {
        $copy = $keys.Clone()
        $idx = New-Object 'int[]' $n
        for ($i = 0; $i -lt $n; $i++) { $idx[$i] = $i }
        $isText = $copy -is [string[]]
        $cmp = [System.StringComparer]::CurrentCultureIgnoreCase
        if ($isText) { [Array]::Sort($copy, $idx, $cmp) } else { [Array]::Sort($copy, $idx) }
        $r = 0
        $rank[$idx[0]] = 0
        for ($i = 1; $i -lt $n; $i++) {
            $same = $(if ($isText) { $cmp.Compare($copy[$i], $copy[$i - 1]) -eq 0 } else { $copy[$i] -eq $copy[$i - 1] })
            if (-not $same) { $r++ }
            $rank[$idx[$i]] = $r
        }
        $Index.Ranks["$Key|max"] = $r
    } else { $Index.Ranks["$Key|max"] = 0 }
    $Index.Ranks[$Key] = $rank
    return $rank
}

function Get-IgwtGridChipMatch {
    <#
    .SYNOPSIS
        Which rows a chip matches (bool[]), computed on first use and cached. A chip matches by
        Field + Values (the row value, or any element of an array value, is one of Values) or by
        a Test scriptblock that receives the row.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Index, [Parameter(Mandatory = $true)]$Chip)
    $id = [string]$Chip.Id
    if ($Index.Chips.ContainsKey($id)) { return $Index.Chips[$id] }
    $n = $Index.Count
    $m = New-Object 'bool[]' $n
    if ($Chip.Test) {
        $test = $Chip.Test
        for ($i = 0; $i -lt $n; $i++) { try { $m[$i] = [bool](& $test $Index.Rows[$i]) } catch { $m[$i] = $false } }
    } elseif ($Chip.Field) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($v in @($Chip.Values)) { $null = $set.Add([string]$v) }
        $field = [string]$Chip.Field
        for ($i = 0; $i -lt $n; $i++) {
            $row = $Index.Rows[$i]
            $v = $row.$field
            if ($null -eq $v) { continue }
            if ($v -is [array] -or $v -is [System.Collections.IList]) { foreach ($e in $v) { if ($set.Contains([string]$e)) { $m[$i] = $true; break } } }
            else { $m[$i] = $set.Contains([string]$v) }
        }
    }
    $Index.Chips[$id] = $m
    return $m
}

function Invoke-IgwtGridQuery {
    <#
    .SYNOPSIS
        Filters and sorts an index. Returns the row positions (int[]) in display order.
    .PARAMETER Search
        Words that must all appear in the searchable columns (case-insensitive).
    .PARAMETER Chips
        Active chips. Chips of the same Group are OR-ed, groups are AND-ed.
    .PARAMETER ColumnFilters
        Column key -> allowed display values.
    .PARAMETER Sort
        Sort levels in priority order: @{ Key = 'Name'; Descending = $false }.
    #>
    [CmdletBinding()]
    [OutputType([int[]])]
    param([Parameter(Mandatory = $true)][hashtable]$Index, [string]$Search, [object[]]$Chips = @(), [hashtable]$ColumnFilters = @{}, [object[]]$Sort = @())
    $n = $Index.Count
    $terms = @(([string]$Search).ToLowerInvariant() -split '\s+' | Where-Object { $_ })
    $groups = [ordered]@{}
    foreach ($ch in @($Chips | Where-Object { $_ })) {
        $g = $(if ($ch.Group) { [string]$ch.Group } else { [string]$ch.Id })
        if (-not $groups.Contains($g)) { $groups[$g] = New-Object System.Collections.Generic.List[object] }
        $groups[$g].Add((Get-IgwtGridChipMatch -Index $Index -Chip $ch))
    }
    $groupMatches = @($groups.Values | ForEach-Object { , $_.ToArray() })
    $colFilters = @()
    foreach ($k in @($ColumnFilters.Keys)) {
        if (-not $Index.Texts.ContainsKey($k)) { continue }
        $allowed = @($ColumnFilters[$k])
        if ($allowed.Count -eq 0) { continue }
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($v in $allowed) { $null = $set.Add([string]$v) }
        $colFilters += , @($Index.Texts[$k], $set)
    }
    $list = New-Object 'System.Collections.Generic.List[int]' $n
    $searchText = $Index.Search
    for ($i = 0; $i -lt $n; $i++) {
        $ok = $true
        foreach ($t in $terms) { if ($searchText[$i].IndexOf($t, [System.StringComparison]::Ordinal) -lt 0) { $ok = $false; break } }
        if (-not $ok) { continue }
        foreach ($gm in $groupMatches) {
            $any = $false
            foreach ($m in $gm) { if ($m[$i]) { $any = $true; break } }
            if (-not $any) { $ok = $false; break }
        }
        if (-not $ok) { continue }
        foreach ($cf in $colFilters) { if (-not $cf[1].Contains($cf[0][$i])) { $ok = $false; break } }
        if ($ok) { $list.Add($i) }
    }
    $result = $list.ToArray()
    $levels = @($Sort | Where-Object { $_ -and $Index.Keys.ContainsKey([string]$_.Key) })
    if ($levels.Count -eq 0 -or $result.Count -lt 2) { return , $result }
    # Composite key: the rank of each level, most significant first, then the original position
    # (keeps the sort stable). Fits a long for 3 levels of up to 30,000 rows (2 levels above that).
    $levels = @($levels | Select-Object -First $(if ($n -gt 30000) { 2 } else { 3 }))
    $ranks = @(); $max = @(); $desc = @()
    foreach ($l in $levels) {
        $ranks += , (Get-IgwtGridRank -Index $Index -Key ([string]$l.Key))
        $max += [long]$Index.Ranks["$([string]$l.Key)|max"]
        $desc += [bool]$l.Descending
    }
    $base = [long]($n + 1)
    $composite = New-Object 'long[]' $result.Count
    for ($j = 0; $j -lt $result.Count; $j++) {
        $i = $result[$j]
        $k = [long]0
        for ($l = 0; $l -lt $ranks.Count; $l++) {
            $r = [long]$ranks[$l][$i]
            if ($desc[$l]) { $r = $max[$l] - $r }
            $k = $k * $base + $r
        }
        $composite[$j] = $k * $base + $i
    }
    [Array]::Sort($composite, $result)
    return , $result
}

#endregion

#region Grid control (WPF)

$script:IgwtGrids = @{}

function Get-IgwtGridShellXaml {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return @'
<DockPanel xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
    <DockPanel DockPanel.Dock="Top" Margin="0,0,0,6" LastChildFill="True">
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
            <TextBlock x:Name="CountText" Style="{DynamicResource TextCaption}" VerticalAlignment="Center" Margin="10,0,10,0"/>
            <TextBlock x:Name="UpdatedText" Style="{DynamicResource TextCaption}" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <Button x:Name="RefreshLink" Style="{DynamicResource LinkButton}" Content="Refresh" VerticalAlignment="Center" Margin="0,0,12,0" ToolTip="Read the list again" Visibility="Collapsed"/>
            <Button x:Name="ClearButton" Style="{DynamicResource GhostButton}" Content="Clear filters" ToolTip="Clear the search, chips and column filters" IsEnabled="False"/>
            <Button x:Name="ViewButton" Style="{DynamicResource GhostButton}" Margin="0" ToolTip="Columns, saved views and export">
                <StackPanel Orientation="Horizontal">
                    <TextBlock Style="{DynamicResource Icon}" Text="&#xE8FD;" FontSize="14" Margin="0,0,6,0"/>
                    <TextBlock Text="View" VerticalAlignment="Center"/>
                </StackPanel>
            </Button>
        </StackPanel>
        <TextBox x:Name="SearchBox" Style="{DynamicResource SearchBox}" Width="280" HorizontalAlignment="Left"/>
    </DockPanel>
    <WrapPanel x:Name="ChipPanel" DockPanel.Dock="Top" Margin="0,2,0,4"/>
    <WrapPanel x:Name="MoreChipPanel" DockPanel.Dock="Top" Margin="0,0,0,4" Visibility="Collapsed"/>
    <Border x:Name="BulkBar" DockPanel.Dock="Top" Visibility="Collapsed" Background="{DynamicResource BrushAccentSoft}" BorderBrush="{DynamicResource BrushAccent}" BorderThickness="1" CornerRadius="6" Padding="12,6" Margin="0,0,0,6">
        <DockPanel>
            <TextBlock x:Name="BulkText" DockPanel.Dock="Left" FontWeight="SemiBold" VerticalAlignment="Center" Margin="0,0,16,0"/>
            <Button x:Name="BulkClearButton" DockPanel.Dock="Right" Style="{DynamicResource LinkButton}" Content="Clear selection" VerticalAlignment="Center" ToolTip="Unselect all rows"/>
            <WrapPanel x:Name="BulkActions" VerticalAlignment="Center"/>
        </DockPanel>
    </Border>
    <Grid>
        <DataGrid x:Name="Grid"/>
        <Border x:Name="StatePanel" Visibility="Collapsed" Background="{DynamicResource BrushBackground}">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" MaxWidth="480" Margin="16">
                <StackPanel x:Name="SkeletonPanel" Width="420" Visibility="Collapsed">
                    <Border Style="{DynamicResource Skeleton}" Width="420"/>
                    <Border Style="{DynamicResource Skeleton}" Width="360" HorizontalAlignment="Left"/>
                    <Border Style="{DynamicResource Skeleton}" Width="400" HorizontalAlignment="Left"/>
                    <Border Style="{DynamicResource Skeleton}" Width="300" HorizontalAlignment="Left"/>
                    <Border Style="{DynamicResource Skeleton}" Width="380" HorizontalAlignment="Left"/>
                </StackPanel>
                <TextBlock x:Name="StateIcon" Style="{DynamicResource Icon}" FontSize="28" HorizontalAlignment="Center" Margin="0,8,0,8"/>
                <TextBlock x:Name="StateTitle" FontSize="{DynamicResource FontSizeSubtitle}" FontWeight="SemiBold" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap"/>
                <TextBlock x:Name="StateText" Style="{DynamicResource TextMuted}" HorizontalAlignment="Center" TextAlignment="Center" Margin="0,4,0,0"/>
                <Button x:Name="StateButton" Style="{DynamicResource AccentButton}" HorizontalAlignment="Center" Margin="0,14,0,0" Visibility="Collapsed"/>
            </StackPanel>
        </Border>
    </Grid>
</DockPanel>
'@
}

function Get-IgwtGridCellTemplateXaml {
    <# .SYNOPSIS The cell template of a column (text truncates with an ellipsis and shows a tooltip). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Column)
    $k = $Column.Key
    $tip = $(if ($Column.Tip) { "ToolTip=`"{Binding $($Column.Tip), Mode=OneWay}`"" } else { '' })
    $ns = 'xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"'
    switch ($Column.Template) {
        'Mono' { return "<DataTemplate $ns><TextBlock Style=`"{DynamicResource GridCellText}`" FontFamily=`"{DynamicResource FontMono}`" Text=`"{Binding $k, Mode=OneWay}`" $tip/></DataTemplate>" }
        'Status' {
            # Status is never colour only: glyph + word, coloured by the row's <Key>Brush.
            return ("<DataTemplate $ns><StackPanel Orientation=`"Horizontal`" $tip>" +
                "<TextBlock Text=`"{Binding ${k}Glyph, Mode=OneWay}`" FontFamily=`"{DynamicResource FontIcons}`" FontSize=`"13`" Foreground=`"{Binding ${k}Brush, Mode=OneWay}`" VerticalAlignment=`"Center`" Margin=`"0,0,6,0`"/>" +
                "<TextBlock Style=`"{DynamicResource GridCellText}`" Text=`"{Binding $k, Mode=OneWay}`" Foreground=`"{Binding ${k}Brush, Mode=OneWay}`" FontWeight=`"SemiBold`"/>" +
                '</StackPanel></DataTemplate>')
        }
        'Toggle' {
            # A switch bound to <Key> (bool), enabled by <Key>Enabled, with the row id in its Tag; the page handles the click.
            return "<DataTemplate $ns><CheckBox Style=`"{DynamicResource ToggleSwitch}`" IsChecked=`"{Binding $k, Mode=OneWay}`" IsEnabled=`"{Binding ${k}Enabled, Mode=OneWay}`" Tag=`"{Binding Key, Mode=OneWay}`" ToolTip=`"{Binding ${k}Tip, Mode=OneWay}`" AutomationProperties.Name=`"{Binding ${k}Name, Mode=OneWay}`" HorizontalAlignment=`"Left`"/></DataTemplate>"
        }
        'Badge' { return "<DataTemplate $ns><Border Style=`"{DynamicResource Badge}`" HorizontalAlignment=`"Left`" $tip><TextBlock Text=`"{Binding $k, Mode=OneWay}`" FontSize=`"{DynamicResource FontSizeCaption}`" TextTrimming=`"CharacterEllipsis`"/></Border></DataTemplate>" }
        default { return "<DataTemplate $ns><TextBlock Style=`"{DynamicResource GridCellText}`" Text=`"{Binding $k, Mode=OneWay}`" $tip/></DataTemplate>" }
    }
}

function New-IgwtSmartGrid {
    <#
    .SYNOPSIS
        Builds a SmartGrid. Returns its state (a hashtable); put .Root into the page.
    .PARAMETER Id
        Unique id; also the key of the saved view (gui-state.json) and the automation id prefix.
    .PARAMETER Columns
        Column definitions (see ConvertTo-IgwtGridColumn).
    .PARAMETER Chips
        Quick filters: @{ Id; Label; Group; Field + Values, or Test = { param($row) ... }; Tip }.
    .PARAMETER Actions
        Row actions: @{ Id; Label; Bulk; Changes; Danger; Run = { param($rows) ... }; CanRun = { param($rows) ... }; Tip }.
        Changes = $true marks actions that change the PC: they are disabled in read-only mode.
    .PARAMETER RowKey
        Row property that identifies a row (keeps the selection across refreshes).
    .PARAMETER OnBeforeQuery
        Runs before every query with the grid: a page can adjust ColumnFilters (for example a
        category that a search lifts).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds window objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][object[]]$Columns, [object[]]$Chips = @(), [object[]]$Actions = @(),
        [string]$RowKey, [string]$SearchPlaceholder = 'Search', [string]$Noun = 'items', [string]$EmptyTitle = 'Nothing to show yet', [string]$EmptyText = '',
        [scriptblock]$OnSelectionChanged, [scriptblock]$OnRefresh, [scriptblock]$OnActivate, [scriptblock]$OnBeforeQuery, [System.Windows.Controls.DataGridSelectionMode]$SelectionMode = 'Extended')
    $root = [Windows.Markup.XamlReader]::Parse((Get-IgwtGridShellXaml))
    $cols = @($Columns | ForEach-Object { ConvertTo-IgwtGridColumn -Definition $_ })
    $g = @{
        Id = $Id; Root = $root; Columns = $cols; Chips = @($Chips); Actions = @($Actions); RowKey = $RowKey; Noun = $Noun; EmptyTitle = $EmptyTitle; EmptyText = $EmptyText
        EmptyActionText = ''; EmptyAction = $null; StateAction = ''
        Index = (New-IgwtGridIndex -Rows @() -Columns $cols); Order = [int[]]@(); Search = ''; ActiveChips = (New-Object 'System.Collections.Generic.HashSet[string]'); ColumnFilters = @{}; Sort = @()
        State = 'Loading'; StateMessage = ''; LastRefreshed = $null; OnSelectionChanged = $OnSelectionChanged; OnRefresh = $OnRefresh; OnActivate = $OnActivate; OnRetry = $OnRefresh; OnBeforeQuery = $OnBeforeQuery; ScrollViewer = $null; Scope = @{}
        C = @{}; ChipButtons = @{}; MoreButton = $null; DataColumns = @{}; Restoring = $false; Updating = $false; SearchTimer = $null; SaveTimer = $null; LastQueryMs = 0; Default = $null
    }
    foreach ($n in 'CountText', 'UpdatedText', 'RefreshLink', 'ClearButton', 'ViewButton', 'SearchBox', 'ChipPanel', 'MoreChipPanel', 'BulkBar', 'BulkText', 'BulkClearButton', 'BulkActions', 'Grid', 'StatePanel', 'SkeletonPanel', 'StateIcon', 'StateTitle', 'StateText', 'StateButton') {
        $g.C[$n] = $root.FindName($n)
    }
    $c = $g.C
    $auto = ($Id -replace '[^A-Za-z0-9]', '')
    # Every element carries the grid id (Tag or DataContext), so the shared handlers below find
    # their grid in $script:IgwtGrids without closures.
    $root.Tag = $Id
    foreach ($b in 'ClearButton', 'ViewButton', 'RefreshLink', 'BulkClearButton', 'StateButton', 'BulkActions', 'Grid') { $c[$b].Tag = $Id }
    $c.ChipPanel.DataContext = $Id
    $c.MoreChipPanel.DataContext = $Id
    $c.SearchBox.DataContext = $Id
    $c.SearchBox.Tag = $SearchPlaceholder
    $c.SearchBox.ToolTip = "$SearchPlaceholder (all words must match; Ctrl+F)"
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($c.SearchBox, "${auto}SearchBox")
    [System.Windows.Automation.AutomationProperties]::SetName($c.SearchBox, $SearchPlaceholder)
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($c.Grid, "${auto}Grid")
    [System.Windows.Automation.AutomationProperties]::SetName($c.Grid, $Noun)
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($c.ClearButton, "${auto}ClearFilters")
    [System.Windows.Automation.AutomationProperties]::SetAutomationId($c.ViewButton, "${auto}ViewMenu")
    [System.Windows.Automation.AutomationProperties]::SetName($c.ViewButton, 'View: columns, saved views and export')
    if ($OnRefresh) { $c.RefreshLink.Visibility = 'Visible' }
    $c.Grid.SelectionMode = $SelectionMode

    foreach ($col in $cols) {
        $dc = New-Object System.Windows.Controls.DataGridTemplateColumn
        $dc.Header = $col.Header
        $dc.SortMemberPath = $col.Key
        $dc.CanUserSort = $true
        $dc.MinWidth = $col.MinWidth
        $dc.Width = $(if ($col.Width -gt 0) { New-Object System.Windows.Controls.DataGridLength($col.Width) } else { New-Object System.Windows.Controls.DataGridLength(1, 'Star') })
        $dc.CellTemplate = [Windows.Markup.XamlReader]::Parse((Get-IgwtGridCellTemplateXaml -Column $col))
        $dc.Visibility = $(if ($col.Visible) { 'Visible' } else { 'Collapsed' })
        $c.Grid.Columns.Add($dc)
        $g.DataColumns[$col.Key] = $dc
    }

    foreach ($ch in $g.Chips) {
        $tb = New-Object System.Windows.Controls.Primitives.ToggleButton
        $tb.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Chip')
        $tb.Content = [string]$ch.Label
        $tb.Tag = [string]$ch.Id
        $tb.ToolTip = $(if ($ch.Tip) { [string]$ch.Tip } else { "Show only: $($ch.Label)" })
        [System.Windows.Automation.AutomationProperties]::SetAutomationId($tb, "Chip_${auto}_$(([string]$ch.Id) -replace '[^A-Za-z0-9]', '')")
        [System.Windows.Automation.AutomationProperties]::SetName($tb, [string]$ch.Label)
        # Primary chips are always shown; chips marked More sit behind a "More filters" toggle (fewer
        # choices at once).
        if ($ch.More) { $null = $c.MoreChipPanel.Children.Add($tb) } else { $null = $c.ChipPanel.Children.Add($tb) }
        $g.ChipButtons[[string]$ch.Id] = $tb
    }
    $moreCount = @($g.Chips | Where-Object { $_.More }).Count
    if ($moreCount) {
        $mb = New-Object System.Windows.Controls.Primitives.ToggleButton
        $mb.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Chip')
        $mb.Content = "More filters ($moreCount)"
        $mb.Tag = ''
        $mb.ToolTip = 'Show or hide the other quick filters'
        [System.Windows.Automation.AutomationProperties]::SetAutomationId($mb, "${auto}MoreFilters")
        [System.Windows.Automation.AutomationProperties]::SetName($mb, 'More filters')
        $null = $c.ChipPanel.Children.Add($mb)
        $g.MoreButton = $mb
    }
    if ($g.Chips.Count -eq 0) { $c.ChipPanel.Visibility = 'Collapsed' }
    Register-IgwtGuiHandler -Control $c.ChipPanel -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($s, $e)
            $tb = $e.OriginalSource
            if (-not ($tb -is [System.Windows.Controls.Primitives.ToggleButton])) { return }
            $grid = $script:IgwtGrids[[string]$s.DataContext]
            if (-not $grid) { return }
            if ([object]::ReferenceEquals($tb, $grid.MoreButton)) { $grid.C.MoreChipPanel.Visibility = $(if ($tb.IsChecked) { 'Visible' } else { 'Collapsed' }); return }
            if ($tb.IsChecked) { $null = $grid.ActiveChips.Add([string]$tb.Tag) } else { $null = $grid.ActiveChips.Remove([string]$tb.Tag) }
            Update-IgwtGridView -Grid $grid
            Request-IgwtGridSave -Grid $grid
        }
    Register-IgwtGuiHandler -Control $c.MoreChipPanel -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($s, $e)
            $tb = $e.OriginalSource
            if (-not ($tb -is [System.Windows.Controls.Primitives.ToggleButton])) { return }
            $grid = $script:IgwtGrids[[string]$s.DataContext]
            if (-not $grid) { return }
            if ([object]::ReferenceEquals($tb, $grid.MoreButton)) { $grid.C.MoreChipPanel.Visibility = $(if ($tb.IsChecked) { 'Visible' } else { 'Collapsed' }); return }
            if ($tb.IsChecked) { $null = $grid.ActiveChips.Add([string]$tb.Tag) } else { $null = $grid.ActiveChips.Remove([string]$tb.Tag) }
            Update-IgwtGridView -Grid $grid
            Request-IgwtGridSave -Grid $grid
        }

    # Search (debounced 150 ms)
    $g.SearchTimer = New-Object System.Windows.Threading.DispatcherTimer
    $g.SearchTimer.Interval = [TimeSpan]::FromMilliseconds(150)
    $g.SearchTimer.Tag = $Id
    Register-IgwtGuiHandler -Control $g.SearchTimer -Event 'Tick' -Handler { param($s, $e) $null = $e; $s.Stop(); $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { $grid.Search = [string]$grid.C.SearchBox.Text; Update-IgwtGridView -Grid $grid; Request-IgwtGridSave -Grid $grid } }
    Register-IgwtGuiHandler -Control $c.SearchBox -Event 'TextChanged' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.DataContext]; if ($grid -and -not $grid.Restoring) { $grid.SearchTimer.Stop(); $grid.SearchTimer.Start() } }

    # Sorting: click = sort by this column (again = reverse); Shift+click = add a sort level.
    Register-IgwtGuiHandler -Control $c.Grid -Event 'Sorting' -Handler {
            param($s, $e)
            $e.Handled = $true
            $grid = $script:IgwtGrids[[string]$s.Tag]
            if (-not $grid) { return }
            $shift = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0
            Set-IgwtGridSort -Grid $grid -Key ([string]$e.Column.SortMemberPath) -Add:$shift
        }
    Register-IgwtGuiHandler -Control $c.Grid -Event 'SelectionChanged' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Update-IgwtGridSelection -Grid $grid } }
    Register-IgwtGuiHandler -Control $c.Grid -Event 'MouseDoubleClick' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid -and $grid.OnActivate -and $s.SelectedItem) { & $grid.OnActivate $grid $s.SelectedItem } }
    Register-IgwtGuiHandler -Control $c.Grid -Event 'ColumnReordered' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Request-IgwtGridSave -Grid $grid } }
    $c.Grid.ContextMenu = New-Object System.Windows.Controls.ContextMenu
    Register-IgwtGuiHandler -Control $c.Grid -Event 'ContextMenuOpening' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { $s.ContextMenu = New-IgwtGridContextMenu -Grid $grid } }
    Register-IgwtGuiHandler -Control $root -Event 'PreviewKeyDown' -Handler {
            param($s, $e)
            if ($e.Key -eq 'F' -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
                $grid = $script:IgwtGrids[[string]$s.Tag]
                if ($grid) { $null = $grid.C.SearchBox.Focus(); $grid.C.SearchBox.SelectAll(); $e.Handled = $true }
            }
        }
    Register-IgwtGuiHandler -Control $c.ClearButton -Event 'Click' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Clear-IgwtGridFilters -Grid $grid } }
    Register-IgwtGuiHandler -Control $c.RefreshLink -Event 'Click' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid -and $grid.OnRefresh) { & $grid.OnRefresh $grid } }
    Register-IgwtGuiHandler -Control $c.BulkClearButton -Event 'Click' -Handler { param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { $grid.C.Grid.UnselectAll() } }
    Register-IgwtGuiHandler -Control $c.ViewButton -Event 'Click' -Handler {
            param($s, $e)
            $null = $e
            $grid = $script:IgwtGrids[[string]$s.Tag]
            if (-not $grid) { return }
            $menu = New-IgwtGridViewMenu -Grid $grid
            $menu.PlacementTarget = $s
            $menu.Placement = 'Bottom'
            $menu.IsOpen = $true
        }
    Register-IgwtGuiHandler -Control $c.StateButton -Event 'Click' -Handler {
            param($s, $e)
            $null = $e
            $grid = $script:IgwtGrids[[string]$s.Tag]
            if (-not $grid) { return }
            switch ([string]$grid.StateAction) {
                'clear' { Clear-IgwtGridFilters -Grid $grid }
                'retry' { if ($grid.OnRetry) { & $grid.OnRetry $grid } }
                default { if ($grid.EmptyAction) { & $grid.EmptyAction $grid } }
            }
        }
    Register-IgwtGuiHandler -Control $c.BulkActions -RoutedEvent ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent) -Handler {
            param($s, $e)
            $btn = $e.OriginalSource
            if (-not ($btn -is [System.Windows.Controls.Button])) { return }
            $grid = $script:IgwtGrids[[string]$s.Tag]
            if ($grid) { Invoke-IgwtGridAction -Grid $grid -ActionId ([string]$btn.Tag) }
        }

    $script:IgwtGrids[$Id] = $g
    Restore-IgwtGridView -Grid $g
    Set-IgwtGridState -Grid $g -State 'Loading'
    return $g
}

function Set-IgwtGridSort {
    <# .SYNOPSIS Click: sort by Key (again: reverse). -Add (Shift+click): add or reverse a sort level (up to 3). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [Parameter(Mandatory = $true)][string]$Key, [switch]$Add, [switch]$NoSave)
    $levels = New-Object System.Collections.Generic.List[object]
    foreach ($l in @($Grid.Sort)) { $levels.Add(@{ Key = [string]$l.Key; Descending = [bool]$l.Descending }) }
    $existing = @($levels | Where-Object { $_.Key -eq $Key }) | Select-Object -First 1
    if ($Add) {
        if ($existing) { $existing.Descending = -not $existing.Descending } else { $levels.Add(@{ Key = $Key; Descending = $false }) }
    } else {
        # Clicking the column that sorts first reverses it (and drops the other levels).
        $desc = $(if ($existing -and $levels[0].Key -eq $Key) { -not $existing.Descending } else { $false })
        $levels.Clear(); $levels.Add(@{ Key = $Key; Descending = $desc })
    }
    $Grid.Sort = @($levels | Select-Object -First 3)
    Update-IgwtGridSortIndicators -Grid $Grid
    Update-IgwtGridView -Grid $Grid
    if (-not $NoSave) { Request-IgwtGridSave -Grid $Grid }
}

function Update-IgwtGridSortIndicators {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $levelOf = @{}
    $i = 0
    foreach ($l in @($Grid.Sort)) { $i++; $levelOf[[string]$l.Key] = @{ N = $i; Desc = [bool]$l.Descending } }
    $multi = @($Grid.Sort).Count -gt 1
    foreach ($col in $Grid.Columns) {
        $dc = $Grid.DataColumns[$col.Key]
        if ($levelOf.ContainsKey($col.Key)) {
            $dc.SortDirection = $(if ($levelOf[$col.Key].Desc) { 'Descending' } else { 'Ascending' })
            # With several sort levels the header shows which one sorts first.
            $dc.Header = $(if ($multi) { "$($col.Header) ($($levelOf[$col.Key].N))" } else { $col.Header })
        } else { $dc.SortDirection = $null; $dc.Header = $col.Header }
    }
}

function Clear-IgwtGridFilters {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $Grid.Restoring = $true
    try {
        $Grid.C.SearchBox.Text = ''
        $Grid.Search = ''
        $Grid.ActiveChips.Clear()
        foreach ($tb in $Grid.ChipButtons.Values) { $tb.IsChecked = $false }
        $Grid.ColumnFilters = @{}
    } finally { $Grid.Restoring = $false }
    Update-IgwtGridView -Grid $Grid
    Request-IgwtGridSave -Grid $Grid
}

function Set-IgwtGridChip {
    <# .SYNOPSIS Turns a chip on or off from code (for example a "needs attention" link). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [Parameter(Mandatory = $true)][string]$ChipId, [bool]$On = $true, [switch]$Exclusive)
    if ($Exclusive) { $Grid.ActiveChips.Clear(); foreach ($tb in $Grid.ChipButtons.Values) { $tb.IsChecked = $false } }
    if ($On) { $null = $Grid.ActiveChips.Add($ChipId) } else { $null = $Grid.ActiveChips.Remove($ChipId) }
    if ($Grid.ChipButtons.ContainsKey($ChipId)) { $Grid.ChipButtons[$ChipId].IsChecked = $On }
    Update-IgwtGridMorePanel -Grid $Grid
    Update-IgwtGridView -Grid $Grid
}

function Set-IgwtGridRows {
    <#
    .SYNOPSIS
        Loads rows: rebuilds the index and keeps search, chips, sort and the selection (by RowKey).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [object[]]$Rows = @())
    $Grid.Index = New-IgwtGridIndex -Rows $Rows -Columns $Grid.Columns
    $Grid.LastRefreshed = Get-Date
    $Grid.State = 'Ready'
    Update-IgwtGridView -Grid $Grid
}

function Update-IgwtGridRows {
    <#
    .SYNOPSIS
        Replaces only the given rows (matched by RowKey) after a change, instead of reloading the
        whole list. Rows whose key is new are added.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [object[]]$Rows = @())
    if (-not $Grid.RowKey) { Set-IgwtGridRows -Grid $Grid -Rows $Rows; return }
    $all = Merge-IgwtGridRows -Existing $Grid.Index.Rows -Changed $Rows -RowKey $Grid.RowKey
    Set-IgwtGridRows -Grid $Grid -Rows $all
}

function Merge-IgwtGridRows {
    <# .SYNOPSIS Existing rows with the changed ones replaced by key (order kept; new keys appended). #>
    [CmdletBinding()]
    param([object[]]$Existing = @(), [object[]]$Changed = @(), [Parameter(Mandatory = $true)][string]$RowKey)
    $map = [ordered]@{}
    foreach ($r in $Changed) { if ($null -ne $r) { $map[[string]$r.$RowKey] = $r } }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Existing) {
        $key = [string]$r.$RowKey
        if ($map.Contains($key)) { $all.Add($map[$key]); $map.Remove($key) } else { $all.Add($r) }
    }
    foreach ($r in $map.Values) { $all.Add($r) }
    return , $all.ToArray()
}

function Get-IgwtGridSelection {
    <# .SYNOPSIS The selected rows. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    return @($Grid.C.Grid.SelectedItems | ForEach-Object { $_ })
}

function Get-IgwtGridViewRows {
    <# .SYNOPSIS The rows of the current view (after search, chips, filters and sort). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $ix = $Grid.Index
    return @(foreach ($i in $Grid.Order) { $ix.Rows[$i] })
}

function Update-IgwtGridView {
    <# .SYNOPSIS Re-runs the query and shows the result; keeps the selection by RowKey. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($Grid.OnBeforeQuery) { & $Grid.OnBeforeQuery $Grid }
    $active = @($Grid.Chips | Where-Object { $Grid.ActiveChips.Contains([string]$_.Id) })
    # Scope (set by the page, for example the category of a tweak page) narrows the rows without
    # counting as a filter the user set: the counter and Clear filters ignore it.
    $filters = @{}
    foreach ($k in @($Grid.ColumnFilters.Keys)) { $filters[$k] = $Grid.ColumnFilters[$k] }
    foreach ($k in @($Grid.Scope.Keys)) { $filters[$k] = $Grid.Scope[$k] }
    $Grid.Order = Invoke-IgwtGridQuery -Index $Grid.Index -Search $Grid.Search -Chips $active -ColumnFilters $filters -Sort $Grid.Sort
    $c = $Grid.C
    $selectedKeys = $null
    if ($Grid.RowKey -and $c.Grid.SelectedItems.Count) {
        $selectedKeys = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($r in $c.Grid.SelectedItems) { $null = $selectedKeys.Add([string]$r.($Grid.RowKey)) }
    }
    $ix = $Grid.Index
    $items = New-Object 'object[]' $Grid.Order.Count
    for ($j = 0; $j -lt $Grid.Order.Count; $j++) { $items[$j] = $ix.Rows[$Grid.Order[$j]] }
    # Keep the scroll position: a refresh after a change must not jump back to the top.
    if (-not $Grid.ScrollViewer -and [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($c.Grid) -gt 0) { $Grid.ScrollViewer = Find-IgwtGridScrollViewer -Node $c.Grid }
    $offset = $(if ($Grid.ScrollViewer) { $Grid.ScrollViewer.VerticalOffset } else { 0 })
    $Grid.Updating = $true
    try {
        $c.Grid.ItemsSource = $items
        # A new ItemsSource clears the sort arrows of the DataGrid; show ours again.
        Update-IgwtGridSortIndicators -Grid $Grid
        if ($selectedKeys -and $selectedKeys.Count) {
            foreach ($r in $items) { if ($selectedKeys.Contains([string]$r.($Grid.RowKey))) { $null = $c.Grid.SelectedItems.Add($r) } }
        }
    } finally { $Grid.Updating = $false }
    if ($Grid.ScrollViewer -and $offset -gt 0) { $sv = $Grid.ScrollViewer; $null = $c.Grid.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Loaded, [Action[double]] { param($o) $sv.ScrollToVerticalOffset($o) }, $offset) }
    $total = $(if (@($Grid.Scope.Keys).Count) { (Invoke-IgwtGridQuery -Index $ix -ColumnFilters $Grid.Scope).Count } else { $ix.Count }); $shown = $items.Count
    $filtered = [bool]($Grid.Search -or $Grid.ActiveChips.Count -or @($Grid.ColumnFilters.Keys).Count)
    $c.CountText.Text = $(if ($filtered) { '{0:N0} of {1:N0} shown' -f $shown, $total } else { '{0:N0} {1}' -f $total, $Grid.Noun })
    $c.ClearButton.IsEnabled = $filtered
    Update-IgwtGridUpdatedText -Grid $Grid
    if ($Grid.State -eq 'Ready') {
        if ($total -eq 0) { Show-IgwtGridStatePanel -Grid $Grid -Kind 'Empty' }
        elseif ($shown -eq 0) { Show-IgwtGridStatePanel -Grid $Grid -Kind 'NoMatch' }
        else { $c.StatePanel.Visibility = 'Collapsed' }
    }
    Update-IgwtGridSelection -Grid $Grid
    $Grid.LastQueryMs = $sw.ElapsedMilliseconds
    if ($script:Gui -and $script:Gui.DiagnosticsPath) { Write-IgwtGuiDiagnostic -Kind 'grid' -Text ("{0}`t{1}`t{2}`t{3}" -f $Grid.Id, $shown, $total, $Grid.LastQueryMs) }
}

function Find-IgwtGridScrollViewer {
    <# .SYNOPSIS The ScrollViewer inside a DataGrid's template. #>
    [CmdletBinding()]
    param($Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Windows.Controls.ScrollViewer]) { return $Node }
    $n = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($Node)
    for ($i = 0; $i -lt $n; $i++) { $r = Find-IgwtGridScrollViewer -Node ([System.Windows.Media.VisualTreeHelper]::GetChild($Node, $i)); if ($r) { return $r } }
    return $null
}

function Update-IgwtGridUpdatedText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $t = $Grid.LastRefreshed
    if (-not $t) { $Grid.C.UpdatedText.Text = ''; return }
    $Grid.C.UpdatedText.Text = Format-IgwtGridAge -Time $t
    $Grid.C.UpdatedText.ToolTip = "Last read at $($t.ToString('T'))"
}

function Format-IgwtGridAge {
    <# .SYNOPSIS "Updated just now", "Updated 3 min ago" or "Updated 14:05". #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][datetime]$Time, [datetime]$Now = (Get-Date))
    $min = [int][math]::Floor(($Now - $Time).TotalMinutes)
    if ($min -lt 1) { return 'Updated just now' }
    if ($min -lt 60) { return "Updated $min min ago" }
    return "Updated $($Time.ToString('t'))"
}

function Update-IgwtGridSelection {
    <# .SYNOPSIS Bulk bar ("N selected") and the page's selection callback. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    if ($Grid.Updating) { return }
    $c = $Grid.C
    $sel = Get-IgwtGridSelection -Grid $Grid
    $bulk = @($Grid.Actions | Where-Object { $_.Bulk })
    if ($sel.Count -gt 1 -and $bulk.Count) {
        $c.BulkText.Text = "$($sel.Count) selected"
        $c.BulkActions.Children.Clear()
        foreach ($a in $bulk) {
            $b = New-Object System.Windows.Controls.Button
            $b.Content = [string]$a.Label
            $b.Tag = [string]$a.Id
            if ($a.Danger) { $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'DangerButton') }
            $why = Get-IgwtGridActionBlock -Action $a -Rows $sel
            $b.IsEnabled = -not $why
            $b.ToolTip = $(if ($why) { $why } elseif ($a.Tip) { [string]$a.Tip } else { "$($a.Label): the selected $($Grid.Noun)" })
            [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($b, $true)
            [System.Windows.Automation.AutomationProperties]::SetName($b, "$($a.Label) ($($sel.Count) selected)")
            $null = $c.BulkActions.Children.Add($b)
        }
        $c.BulkBar.Visibility = 'Visible'
    } else { $c.BulkBar.Visibility = 'Collapsed' }
    if ($Grid.OnSelectionChanged) { & $Grid.OnSelectionChanged $Grid $sel }
}

function Get-IgwtGridActionBlock {
    <# .SYNOPSIS Why an action cannot run on these rows ('' when it can). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Action, [object[]]$Rows = @())
    if ($Rows.Count -eq 0) { return 'Select a row first.' }
    if (-not $Action.Bulk -and $Rows.Count -gt 1) { return 'Select one row for this action.' }
    if ($Action.Changes) {
        if ((Test-IgwtReadOnly) -or ($script:Gui -and $script:Gui.ReadOnly)) { return 'Read-only mode: changes are turned off.' }
        if ($script:Gui -and -not $script:Gui.IsAdmin) { return 'Restart as administrator to make changes.' }
    }
    if ($Action.CanRun) {
        $r = $null
        try { $r = & $Action.CanRun $Rows } catch { $r = $_.Exception.Message }
        if ($r -is [string] -and $r) { return $r }
        if ($r -is [bool] -and -not $r) { return 'Not available for this selection.' }
    }
    return ''
}

function Invoke-IgwtGridAction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs a page action; the action itself confirms changes.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [Parameter(Mandatory = $true)][string]$ActionId)
    $a = @($Grid.Actions | Where-Object { [string]$_.Id -eq $ActionId }) | Select-Object -First 1
    if (-not $a) { return }
    $rows = Get-IgwtGridSelection -Grid $Grid
    $why = Get-IgwtGridActionBlock -Action $a -Rows $rows
    if ($why) { if ($script:Gui) { Set-IgwtGuiStatus $why }; return }
    & $a.Run $rows
}

function New-IgwtGridMenuItem {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds a menu item only.')]
    [CmdletBinding()]
    param([string]$Header, [string]$Tag, [scriptblock]$OnClick, [bool]$Enabled = $true, [string]$Why)
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = $Header
    $mi.Tag = $Tag
    $mi.IsEnabled = $Enabled
    if ($Why) { $mi.ToolTip = $Why; [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($mi, $true) }
    if ($OnClick) { Register-IgwtGuiHandler -Control $mi -Event 'Click' -Handler $OnClick }
    return $mi
}

function New-IgwtGridContextMenu {
    <# .SYNOPSIS Right-click menu: the grid's actions (mirroring the toolbar), copy and export. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds in-memory objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $menu = New-Object System.Windows.Controls.ContextMenu
    $rows = Get-IgwtGridSelection -Grid $Grid
    foreach ($a in $Grid.Actions) {
        $why = Get-IgwtGridActionBlock -Action $a -Rows $rows
        $null = $menu.Items.Add((New-IgwtGridMenuItem -Header ([string]$a.Label) -Tag "$($Grid.Id)|$($a.Id)" -Enabled (-not $why) -Why $why -OnClick {
                    param($s, $e) $null = $e; $p = ([string]$s.Tag).Split('|', 2); $grid = $script:IgwtGrids[$p[0]]; if ($grid) { Invoke-IgwtGridAction -Grid $grid -ActionId $p[1] } }))
    }
    if ($Grid.Actions.Count) { $null = $menu.Items.Add((New-Object System.Windows.Controls.Separator)) }
    $null = $menu.Items.Add((New-IgwtGridMenuItem -Header 'Copy selected rows' -Tag $Grid.Id -Enabled ($rows.Count -gt 0) -OnClick {
                param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Copy-IgwtGridRows -Grid $grid } }))
    $null = $menu.Items.Add((New-IgwtGridMenuItem -Header 'Export selected rows...' -Tag $Grid.Id -Enabled ($rows.Count -gt 0) -OnClick {
                param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Export-IgwtGridView -Grid $grid -Selected } }))
    return $menu
}

function New-IgwtGridViewMenu {
    <# .SYNOPSIS The View menu: columns (show/hide), saved views, reset, export. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds in-memory objects only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $menu = New-Object System.Windows.Controls.ContextMenu
    $colsItem = New-Object System.Windows.Controls.MenuItem
    $colsItem.Header = 'Columns'
    foreach ($col in $Grid.Columns) {
        $mi = New-IgwtGridMenuItem -Header $col.Header -Tag "$($Grid.Id)|$($col.Key)" -OnClick {
            param($s, $e)
            $null = $e
            $p = ([string]$s.Tag).Split('|', 2); $grid = $script:IgwtGrids[$p[0]]
            if (-not $grid) { return }
            $visible = @($grid.DataColumns.Values | Where-Object { $_.Visibility -eq 'Visible' }).Count
            if (-not $s.IsChecked -and $visible -le 1) { $s.IsChecked = $true; return }
            $grid.DataColumns[$p[1]].Visibility = $(if ($s.IsChecked) { 'Visible' } else { 'Collapsed' })
            Request-IgwtGridSave -Grid $grid
        }
        $mi.IsCheckable = $true
        $mi.StaysOpenOnClick = $true
        $mi.IsChecked = ($Grid.DataColumns[$col.Key].Visibility -eq 'Visible')
        $null = $colsItem.Items.Add($mi)
    }
    $null = $menu.Items.Add($colsItem)
    $null = $menu.Items.Add((New-Object System.Windows.Controls.Separator))
    $views = Get-IgwtGridSavedViews -Grid $Grid
    foreach ($name in @($views.Keys | Sort-Object)) {
        $null = $menu.Items.Add((New-IgwtGridMenuItem -Header "Saved view: $name" -Tag "$($Grid.Id)|$name" -OnClick {
                    param($s, $e) $null = $e; $p = ([string]$s.Tag).Split('|', 2); $grid = $script:IgwtGrids[$p[0]]; if ($grid) { Use-IgwtGridSavedView -Grid $grid -Name $p[1] } }))
    }
    $null = $menu.Items.Add((New-IgwtGridMenuItem -Header 'Save this view as...' -Tag $Grid.Id -OnClick {
                param($s, $e)
                $null = $e
                $grid = $script:IgwtGrids[[string]$s.Tag]
                if (-not $grid) { return }
                $name = Read-IgwtGuiText -Title 'Save view' -Prompt 'Name of this view (search, filters, sort and columns):'
                if ($name) { Save-IgwtGridNamedView -Grid $grid -Name $name; Show-IgwtGuiToast -Text "View '$name' saved." -Tone Success }
            }))
    if (@($views.Keys).Count) {
        $del = New-Object System.Windows.Controls.MenuItem
        $del.Header = 'Delete a saved view'
        foreach ($name in @($views.Keys | Sort-Object)) {
            $null = $del.Items.Add((New-IgwtGridMenuItem -Header $name -Tag "$($Grid.Id)|$name" -OnClick {
                        param($s, $e) $null = $e; $p = ([string]$s.Tag).Split('|', 2); $grid = $script:IgwtGrids[$p[0]]; if ($grid) { Remove-IgwtGridNamedView -Grid $grid -Name $p[1] } }))
        }
        $null = $menu.Items.Add($del)
    }
    $null = $menu.Items.Add((New-IgwtGridMenuItem -Header 'Reset to the default view' -Tag $Grid.Id -OnClick {
                param($s, $e) $null = $e; $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Reset-IgwtGridView -Grid $grid } }))
    $null = $menu.Items.Add((New-Object System.Windows.Controls.Separator))
    foreach ($fmt in 'CSV', 'JSON') {
        $null = $menu.Items.Add((New-IgwtGridMenuItem -Header "Export this view to $fmt..." -Tag "$($Grid.Id)|$fmt" -OnClick {
                    param($s, $e) $null = $e; $p = ([string]$s.Tag).Split('|', 2); $grid = $script:IgwtGrids[$p[0]]; if ($grid) { Export-IgwtGridView -Grid $grid -Format $p[1] } }))
    }
    return $menu
}

function Set-IgwtGridState {
    <#
    .SYNOPSIS
        Loading (skeleton; rows already shown stay and "Refreshing..." is shown), Error (message
        and Retry) or Ready.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [ValidateSet('Loading', 'Error', 'Ready')][string]$State, [string]$Message)
    $Grid.State = $State
    $Grid.StateMessage = $Message
    switch ($State) {
        'Loading' { if ($Grid.Index.Count -gt 0) { $Grid.C.UpdatedText.Text = 'Refreshing...' } else { Show-IgwtGridStatePanel -Grid $Grid -Kind 'Loading' } }
        'Error' { Show-IgwtGridStatePanel -Grid $Grid -Kind 'Error' }
        default { Update-IgwtGridView -Grid $Grid }
    }
}

function Show-IgwtGridStatePanel {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [ValidateSet('Loading', 'Empty', 'NoMatch', 'Error')][string]$Kind)
    $c = $Grid.C
    $c.StatePanel.Visibility = 'Visible'
    $c.SkeletonPanel.Visibility = $(if ($Kind -eq 'Loading') { 'Visible' } else { 'Collapsed' })
    $c.StateIcon.Visibility = $(if ($Kind -eq 'Loading') { 'Collapsed' } else { 'Visible' })
    $c.StateButton.Visibility = 'Collapsed'
    $c.StateIcon.ClearValue([System.Windows.Controls.TextBlock]::ForegroundProperty)
    switch ($Kind) {
        'Loading' { $c.StateTitle.Text = "Reading $($Grid.Noun)..."; $c.StateText.Text = 'This runs in the background; you can keep using the app.' }
        'Empty' {
            $c.StateIcon.Text = [string][char]0xE946
            $c.StateTitle.Text = $Grid.EmptyTitle
            $c.StateText.Text = $Grid.EmptyText
            if ($Grid.EmptyActionText -and $Grid.EmptyAction) { $Grid.StateAction = 'empty'; $c.StateButton.Content = $Grid.EmptyActionText; $c.StateButton.Visibility = 'Visible' }
        }
        'NoMatch' {
            $c.StateIcon.Text = [string][char]0xE71C
            $c.StateTitle.Text = "No $($Grid.Noun) match the filters"
            $c.StateText.Text = 'Change the search or the chips, or clear all filters.'
            $Grid.StateAction = 'clear'; $c.StateButton.Content = 'Clear filters'; $c.StateButton.Visibility = 'Visible'
        }
        'Error' {
            $c.StateIcon.Text = [string][char]0xEA39
            $c.StateIcon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BrushDanger')
            $c.StateTitle.Text = "The $($Grid.Noun) could not be read"
            $c.StateText.Text = $(if ($Grid.StateMessage) { $Grid.StateMessage } else { 'See the log for details.' })
            if ($Grid.OnRetry) { $Grid.StateAction = 'retry'; $c.StateButton.Content = 'Retry'; $c.StateButton.Visibility = 'Visible' }
        }
    }
    [System.Windows.Automation.AutomationProperties]::SetName($c.StatePanel, [string]$c.StateTitle.Text)
}

#endregion

#region Views (remembered per user) and export

function Get-IgwtGridViewSnapshot {
    <# .SYNOPSIS The current search, chips, sort and columns as a plain hashtable. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $cols = @(foreach ($col in $Grid.Columns) {
            $dc = $Grid.DataColumns[$col.Key]
            $w = $(if ($dc.Width.IsAbsolute) { [math]::Round($dc.Width.Value) } else { 0 })
            @{ Key = $col.Key; Visible = ($dc.Visibility -eq 'Visible'); Width = $w; Order = $dc.DisplayIndex }
        })
    return @{
        Search  = [string]$Grid.Search
        Chips   = @($Grid.ActiveChips)
        Sort    = @($Grid.Sort | ForEach-Object { @{ Key = [string]$_.Key; Descending = [bool]$_.Descending } })
        Columns = $cols
    }
}

function Set-IgwtGridViewSnapshot {
    <# .SYNOPSIS Applies a saved view (unknown columns and chips are ignored). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, $View)
    if (-not $View) { return }
    $Grid.Restoring = $true
    try {
        $Grid.Search = [string]$View.Search
        $Grid.C.SearchBox.Text = $Grid.Search
        $Grid.ActiveChips.Clear()
        foreach ($id in @($View.Chips)) { if ($id -and $Grid.ChipButtons.ContainsKey([string]$id)) { $null = $Grid.ActiveChips.Add([string]$id) } }
        foreach ($k in @($Grid.ChipButtons.Keys)) { $Grid.ChipButtons[$k].IsChecked = $Grid.ActiveChips.Contains($k) }
        $Grid.Sort = @(@($View.Sort) | Where-Object { $_ -and $Grid.DataColumns.ContainsKey([string]$_.Key) } | ForEach-Object { @{ Key = [string]$_.Key; Descending = [bool]$_.Descending } } | Select-Object -First 3)
        $ordered = @(@($View.Columns) | Where-Object { $_ -and $Grid.DataColumns.ContainsKey([string]$_.Key) } | Sort-Object { [int]$_.Order })
        $n = $Grid.C.Grid.Columns.Count
        foreach ($cv in $ordered) {
            $dc = $Grid.DataColumns[[string]$cv.Key]
            $dc.Visibility = $(if ($null -eq $cv.Visible -or [bool]$cv.Visible) { 'Visible' } else { 'Collapsed' })
            if ([double]$cv.Width -ge $dc.MinWidth) { $dc.Width = New-Object System.Windows.Controls.DataGridLength([double]$cv.Width) }
            $o = [int]$cv.Order
            if ($o -ge 0 -and $o -lt $n) { try { $dc.DisplayIndex = $o } catch { Write-Verbose "Column order not restored: $($_.Exception.Message)" } }
        }
        if (@($Grid.DataColumns.Values | Where-Object { $_.Visibility -eq 'Visible' }).Count -eq 0) { foreach ($dc in $Grid.DataColumns.Values) { $dc.Visibility = 'Visible' } }
    } finally { $Grid.Restoring = $false }
    Update-IgwtGridSortIndicators -Grid $Grid
    Update-IgwtGridMorePanel -Grid $Grid
}

function Update-IgwtGridMorePanel {
    <# .SYNOPSIS Shows the More filters panel when one of its chips is on. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    if (-not $Grid.MoreButton) { return }
    $on = @($Grid.Chips | Where-Object { $_.More -and $Grid.ActiveChips.Contains([string]$_.Id) }).Count -gt 0
    if ($on) { $Grid.MoreButton.IsChecked = $true; $Grid.C.MoreChipPanel.Visibility = 'Visible' }
}

function Restore-IgwtGridView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $Grid.Default = Get-IgwtGridViewSnapshot -Grid $Grid
    if (-not $script:Gui -or -not $script:Gui.ViewState) { return }
    $saved = $script:Gui.ViewState["grid.$($Grid.Id)"]
    if ($saved -and $saved.Current) { Set-IgwtGridViewSnapshot -Grid $Grid -View $saved.Current }
}

function Request-IgwtGridSave {
    <# .SYNOPSIS Saves the grid's view shortly after the last change (debounced). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    if ($Grid.Restoring -or -not $script:Gui -or $script:Gui.NoStateSave) { return }
    if (-not $Grid.SaveTimer) {
        $Grid.SaveTimer = New-Object System.Windows.Threading.DispatcherTimer
        $Grid.SaveTimer.Interval = [TimeSpan]::FromMilliseconds(600)
        $Grid.SaveTimer.Tag = $Grid.Id
        Register-IgwtGuiHandler -Control $Grid.SaveTimer -Event 'Tick' -Handler { param($s, $e) $null = $e; $s.Stop(); $grid = $script:IgwtGrids[[string]$s.Tag]; if ($grid) { Save-IgwtGridView -Grid $grid } }
    }
    $Grid.SaveTimer.Stop(); $Grid.SaveTimer.Start()
}

function Save-IgwtGridView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [switch]$NoWrite)
    if (-not $script:Gui -or $null -eq $script:Gui.ViewState) { return }
    $script:Gui.ViewState["grid.$($Grid.Id)"] = @{ Current = (Get-IgwtGridViewSnapshot -Grid $Grid); Views = (Get-IgwtGridSavedViews -Grid $Grid) }
    if (-not $NoWrite) { Save-IgwtGuiState }
}

function Save-IgwtGridAllViews {
    <# .SYNOPSIS Saves every grid's view (column widths included) when the window closes. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state only.')]
    [CmdletBinding()]
    param()
    if (-not $script:Gui -or $script:Gui.NoStateSave) { return }
    foreach ($g in @($script:IgwtGrids.Values)) { Save-IgwtGridView -Grid $g -NoWrite }
    Save-IgwtGuiState
}

function Get-IgwtGridSavedViews {
    <# .SYNOPSIS Named views of a grid: name -> view. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $out = @{}
    if (-not $script:Gui -or -not $script:Gui.ViewState) { return $out }
    $saved = $script:Gui.ViewState["grid.$($Grid.Id)"]
    if (-not $saved -or -not $saved.Views) { return $out }
    if ($saved.Views -is [hashtable]) { foreach ($k in $saved.Views.Keys) { $out[$k] = $saved.Views[$k] } }
    else { foreach ($p in $saved.Views.PSObject.Properties) { $out[$p.Name] = $p.Value } }
    return $out
}

function Save-IgwtGridNamedView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [Parameter(Mandatory = $true)][string]$Name)
    $views = Get-IgwtGridSavedViews -Grid $Grid
    $views[$Name.Trim()] = Get-IgwtGridViewSnapshot -Grid $Grid
    $script:Gui.ViewState["grid.$($Grid.Id)"] = @{ Current = (Get-IgwtGridViewSnapshot -Grid $Grid); Views = $views }
    Save-IgwtGuiState
}

function Remove-IgwtGridNamedView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the per-user view state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [Parameter(Mandatory = $true)][string]$Name)
    $views = Get-IgwtGridSavedViews -Grid $Grid
    $views.Remove($Name)
    $script:Gui.ViewState["grid.$($Grid.Id)"] = @{ Current = (Get-IgwtGridViewSnapshot -Grid $Grid); Views = $views }
    Save-IgwtGuiState
}

function Use-IgwtGridSavedView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [Parameter(Mandatory = $true)][string]$Name)
    $views = Get-IgwtGridSavedViews -Grid $Grid
    if (-not $views.ContainsKey($Name)) { return }
    Set-IgwtGridViewSnapshot -Grid $Grid -View $views[$Name]
    Update-IgwtGridView -Grid $Grid
    Request-IgwtGridSave -Grid $Grid
}

function Reset-IgwtGridView {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the view only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    Set-IgwtGridViewSnapshot -Grid $Grid -View $Grid.Default
    Update-IgwtGridView -Grid $Grid
    Request-IgwtGridSave -Grid $Grid
}

function ConvertTo-IgwtGridExport {
    <# .SYNOPSIS Rows as plain objects with the visible columns, in display order. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [object[]]$Rows = @())
    $cols = @($Grid.Columns | Where-Object { $Grid.DataColumns[$_.Key].Visibility -eq 'Visible' } | Sort-Object { $Grid.DataColumns[$_.Key].DisplayIndex })
    return @(foreach ($r in $Rows) {
            $o = [ordered]@{}
            foreach ($col in $cols) { $o[$col.Header] = Get-IgwtGridValue -Row $r -Name $col.Key }
            [pscustomobject]$o
        })
}

function Export-IgwtGridView {
    <# .SYNOPSIS Saves the current view (or the selection) to CSV or JSON; writes only the file the user picks. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes the export file the user chose.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid, [ValidateSet('CSV', 'JSON')][string]$Format = 'CSV', [switch]$Selected)
    $rows = $(if ($Selected) { Get-IgwtGridSelection -Grid $Grid } else { Get-IgwtGridViewRows -Grid $Grid })
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV file (*.csv)|*.csv|JSON file (*.json)|*.json'
    $dlg.FilterIndex = $(if ($Format -eq 'JSON') { 2 } else { 1 })
    $dlg.FileName = '{0}-{1}' -f ($Grid.Id -replace '[^A-Za-z0-9\-]', '-'), (Get-Date -Format 'yyyyMMdd-HHmm')
    if (-not $dlg.ShowDialog($script:Gui.Window)) { return }
    $data = ConvertTo-IgwtGridExport -Grid $Grid -Rows $rows
    try {
        if ($dlg.FileName -like '*.json') { ConvertTo-Json -InputObject @($data) -Depth 3 | Set-Content -LiteralPath $dlg.FileName -Encoding UTF8 }
        else { $data | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8 }
        Show-IgwtGuiToast -Text "Exported $($data.Count) row(s) to $([IO.Path]::GetFileName($dlg.FileName))." -Tone Success
    } catch { Show-IgwtGuiError -Message "Export failed: $($_.Exception.Message)" }
}

function Copy-IgwtGridRows {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Grid)
    $data = ConvertTo-IgwtGridExport -Grid $Grid -Rows (Get-IgwtGridSelection -Grid $Grid)
    if (-not $data.Count) { return }
    $text = ($data | ConvertTo-Csv -NoTypeInformation -Delimiter "`t") -join [Environment]::NewLine
    try { [System.Windows.Clipboard]::SetText($text); Set-IgwtGuiStatus "$($data.Count) row(s) copied." } catch { Set-IgwtGuiStatus 'The clipboard is not available.' }
}

#endregion
