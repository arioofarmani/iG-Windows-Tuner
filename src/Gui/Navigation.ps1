# Navigation.ps1
# 4.0 section 3 (D1): the window's sections (Phase 3 design, section 2). The navigation lists seven
# sections plus Advanced tools and Settings; a section with several pages shows them as tabs above the
# page. Every 3.x page id still works (Open-IgwtGuiPage), so deep links, persona orders, saved views and
# the render suite keep their names. Display only: nothing here changes the PC.

$script:IgwtGuiSections = @(
    [pscustomobject]@{ Id = 'Home'; Title = 'Home'; Glyph = [string][char]0xE80F; Pages = @('Home', 'Dashboard'); Bottom = $false; Advanced = $false; Help = 'What to do next, recent changes and health checks' }
    [pscustomobject]@{ Id = 'Play'; Title = 'Play'; Glyph = [string][char]0xE7FC; Pages = @('Presets'); Bottom = $false; Advanced = $false; Help = 'Presets and Session Mode' }
    [pscustomobject]@{ Id = 'Optimize'; Title = 'Optimize'; Glyph = [string][char]0xE945; Pages = @('Power & CPU', 'Graphics & Display', 'Input', 'Background & Privacy', 'System'); Bottom = $false; Advanced = $false; Help = 'Settings that change how Windows runs games' }
    [pscustomobject]@{ Id = 'Security'; Title = 'Security'; Glyph = [string][char]0xE72E; Pages = @('Security', 'Defender', 'Asr', 'Firewall', 'SecSettings'); Bottom = $false; Advanced = $false; Help = 'Security score, Defender, attack surface rules and firewall'
        # 4.0 D6: four tabs (Overview, Protection, Firewall, Policies); Defender and ASR share the Protection tab.
        Groups = @{ 'Defender' = 'Protection'; 'Asr' = 'Protection' } }
    [pscustomobject]@{ Id = 'Network'; Title = 'Network'; Glyph = [string][char]0xE701; Pages = @('NetTest', 'Network', 'Diagnostics'); Bottom = $false; Advanced = $false; Help = 'Network test, network settings and diagnostics' }
    [pscustomobject]@{ Id = 'Clean'; Title = 'Clean'; Glyph = [string][char]0xE74D; Pages = @('Cleaner', 'Storage', 'Startup', 'RegistryCleaner', 'Disk'); Bottom = $false; Advanced = $false; Help = 'Files, registry leftovers, storage and startup apps'
        # 4.0 D7: four tabs (Files, Startup apps, Registry leftovers, Disk); temporary files and Storage Sense share Files.
        Groups = @{ 'Cleaner' = 'Files'; 'Storage' = 'Files' } }
    [pscustomobject]@{ Id = 'History'; Title = 'History'; Glyph = [string][char]0xE81C; Pages = @('History', 'Backups'); Bottom = $false; Advanced = $false; Help = 'Every change with Undo' }
    [pscustomobject]@{ Id = 'Advanced'; Title = 'Advanced tools'; Glyph = [string][char]0xE90F; Pages = @('Advanced', 'Inspect', 'Policy', 'Manage', 'Toolkit', 'Risk Zone', 'Rejected'); Bottom = $true; Advanced = $true; Help = 'Expert inspectors, Group Policy, services and tasks, Toolkit and Risk Zone' }
    [pscustomobject]@{ Id = 'Settings'; Title = 'Settings'; Glyph = [string][char]0xE713; Pages = @('Settings', 'About'); Bottom = $true; Advanced = $false; Help = 'Display, updates and About' }
)

# Short tab names for pages inside a section (plain words, no internal names).
$script:IgwtGuiPageLabels = @{
    'Home' = 'Overview'; 'Dashboard' = 'Health checks'; 'Presets' = 'Presets'
    'Power & CPU' = 'Power & CPU'; 'Graphics & Display' = 'Graphics & Display'; 'Input' = 'Input'; 'Background & Privacy' = 'Background & Privacy'; 'System' = 'System'
    'Security' = 'Overview'; 'Asr' = 'Attack surface rules'; 'Defender' = 'Defender settings'; 'SecSettings' = 'Policies'; 'Firewall' = 'Firewall'
    'NetTest' = 'Network test'; 'Network' = 'Network settings'; 'Diagnostics' = 'Diagnostics'
    'Cleaner' = 'Temporary files'; 'RegistryCleaner' = 'Registry leftovers'; 'Storage' = 'Storage Sense'; 'Disk' = 'Disk'; 'Startup' = 'Startup apps'
    'History' = 'Changes'; 'Backups' = 'Backups and logs'; 'Inspect' = 'Expert inspectors'; 'Policy' = 'Group Policy'; 'Manage' = 'Services and tasks'; 'Toolkit' = 'Toolkit'
    'Risk Zone' = 'Risk Zone'; 'Rejected' = 'Rejected tweaks'; 'About' = 'About'; 'Advanced' = 'Overview'; 'Settings' = 'Settings'
}

function Get-IgwtGuiSectionOf {
    <# .SYNOPSIS The section that holds a page id, or $null. Pure. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Page)
    return (@($script:IgwtGuiSections | Where-Object { $_.Pages -contains $Page }) | Select-Object -First 1)
}

function Get-IgwtGuiPageLabel {
    <# .SYNOPSIS The tab name of a page id (the id itself when none is defined). Pure. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Page)
    if ($script:IgwtGuiPageLabels.ContainsKey($Page)) { return [string]$script:IgwtGuiPageLabels[$Page] }
    return $Page
}

function Get-IgwtGuiSectionOrder {
    <#
    .SYNOPSIS
        The sections in navigation order: the main sections by the persona's page order (a section
        ranks by its best page), then the bottom ones. Advanced tools only when -ShowAdvanced. Pure.
    #>
    [CmdletBinding()]
    param([string[]]$PageOrder = @(), [switch]$ShowAdvanced)
    $rank = @{}
    for ($i = 0; $i -lt $PageOrder.Count; $i++) { if (-not $rank.ContainsKey([string]$PageOrder[$i])) { $rank[[string]$PageOrder[$i]] = $i } }
    $main = @($script:IgwtGuiSections | Where-Object { -not $_.Bottom })
    $sorted = @($main | Sort-Object @{ Expression = {
                $s = $_
                $best = @($s.Pages | ForEach-Object { if ($rank.ContainsKey($_)) { $rank[$_] } }) | Sort-Object | Select-Object -First 1
                if ($null -ne $best) { [int]$best } else { 1000 + [array]::IndexOf(@($main | ForEach-Object { $_.Id }), $s.Id) }
            }
        })
    # Home always comes first: it holds the one next step (Phase 3 principle 1).
    $sorted = @(@($sorted | Where-Object { $_.Id -eq 'Home' }) + @($sorted | Where-Object { $_.Id -ne 'Home' }))
    $bottom = @($script:IgwtGuiSections | Where-Object { $_.Bottom -and ($ShowAdvanced -or -not $_.Advanced) })
    return @($sorted + $bottom)
}

function New-IgwtGuiSectionNavItem {
    <# .SYNOPSIS One navigation entry: 18 px icon and label, named for screen readers. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory element only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Section)
    $it = New-Object System.Windows.Controls.ListBoxItem
    $it.Tag = "section:$($Section.Id)"
    $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
    $ic = New-Object System.Windows.Controls.TextBlock; $ic.Text = $Section.Glyph; $ic.Margin = [System.Windows.Thickness]::new(0, 0, 12, 0)
    $ic.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Icon')
    $tx = New-Object System.Windows.Controls.TextBlock; $tx.Text = $Section.Title
    $null = $sp.Children.Add($ic); $null = $sp.Children.Add($tx)
    $it.Content = $sp
    $it.ToolTip = $Section.Help
    [System.Windows.Automation.AutomationProperties]::SetName($it, $Section.Title)
    [System.Windows.Automation.AutomationProperties]::SetHelpText($it, $Section.Help)
    return $it
}

function Update-IgwtGuiSectionNav {
    <#
    .SYNOPSIS
        Rebuilds the navigation from the sections (persona order, Advanced tools on or off). The
        entries are created once and reused; the list is only touched when the order changed. Keeps
        the current section selected.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $nav = $script:Gui.C.NavList
    if ($null -eq $script:Gui.SectionItems) { $script:Gui.SectionItems = @{} }
    $order = @($(if ($script:Gui.Persona) { $script:Gui.Persona.NavOrder }))
    $sections = Get-IgwtGuiSectionOrder -PageOrder $order -ShowAdvanced:([bool]$script:Gui.ShowAdvanced -and -not [bool]$script:Gui.FocusMode)
    $plan = New-Object System.Collections.Generic.List[object]
    $bottomStarted = $false
    foreach ($s in $sections) {
        if ($s.Bottom -and -not $bottomStarted) { $plan.Add((Get-IgwtGuiNavHeader -Text 'More')); $bottomStarted = $true }
        if (-not $script:Gui.SectionItems.ContainsKey($s.Id)) { $script:Gui.SectionItems[$s.Id] = New-IgwtGuiSectionNavItem -Section $s }
        $plan.Add($script:Gui.SectionItems[$s.Id])
    }
    $same = ($plan.Count -eq $nav.Items.Count)
    for ($n = 0; $same -and $n -lt $plan.Count; $n++) { if (-not [object]::ReferenceEquals($plan[$n], $nav.Items[$n])) { $same = $false } }
    if (-not $same) {
        $script:Gui.NavSuppress = $true
        try { $nav.Items.Clear(); foreach ($x in $plan) { $null = $nav.Items.Add($x) } } finally { $script:Gui.NavSuppress = $false }
    }
    $cur = $(if ($script:Gui.CurrentPage) { Get-IgwtGuiSectionOf -Page $script:Gui.CurrentPage })
    if ($cur -and $script:Gui.SectionItems.ContainsKey($cur.Id) -and $nav.Items.Contains($script:Gui.SectionItems[$cur.Id])) { Select-IgwtGuiSectionItem -Id $cur.Id }
}

function Select-IgwtGuiSectionItem {
    <# .SYNOPSIS Marks a section as selected in the navigation without opening it again. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    if (-not $script:Gui.SectionItems -or -not $script:Gui.SectionItems.ContainsKey($Id)) { return }
    $it = $script:Gui.SectionItems[$Id]
    if ([object]::ReferenceEquals($script:Gui.C.NavList.SelectedItem, $it)) { return }
    $script:Gui.NavSuppress = $true
    try { $script:Gui.C.NavList.SelectedItem = $it } finally { $script:Gui.NavSuppress = $false }
    foreach ($k in @($script:Gui.SectionItems.Keys)) { [System.Windows.Automation.AutomationProperties]::SetItemStatus($script:Gui.SectionItems[$k], $(if ($k -eq $Id) { 'current page' } else { '' })) }
}

function Open-IgwtGuiPage {
    <#
    .SYNOPSIS
        Opens a page by its 3.x id (Dashboard, Power & CPU, Asr, Backups, ...): selects its section,
        its tab, and shows it. An Advanced tools page turns Advanced tools on (and says so).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Page)
    $s = Get-IgwtGuiSectionOf -Page $Page
    if (-not $s) { $Page = 'Home'; $s = Get-IgwtGuiSectionOf -Page 'Home' }
    if ($s.Advanced -and -not $script:Gui.ShowAdvanced) {
        Set-IgwtGuiShowAdvanced -On $true
        Set-IgwtGuiStatus 'Advanced tools are now shown in the navigation (Display menu > Show Advanced tools).'
    }
    if ($null -eq $script:Gui.SectionPage) { $script:Gui.SectionPage = @{} }
    $script:Gui.SectionPage[$s.Id] = $Page
    Select-IgwtGuiSectionItem -Id $s.Id
    Update-IgwtGuiSectionTabs -Section $s -Page $Page
    Show-IgwtGuiPage -Page $Page
}

function Show-IgwtGuiSection {
    <# .SYNOPSIS Opens a section on the page last used in it (its first page the first time). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $s = @($script:IgwtGuiSections | Where-Object { $_.Id -eq $Id })[0]
    if (-not $s) { return }
    $page = $(if ($script:Gui.SectionPage -and $script:Gui.SectionPage[$Id]) { [string]$script:Gui.SectionPage[$Id] } else { [string]$s.Pages[0] })
    Open-IgwtGuiPage -Page $page
}

function Get-IgwtGuiSectionTabList {
    <#
    .SYNOPSIS
        The tabs of a section: one per page, except that pages of one group (Section.Groups, page ->
        group name) share one tab, which opens the group's last page. Returns Label, Key, Pages and
        Target (the page the tab opens). Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Section, [string[]]$Pages = @(), [hashtable]$LastInGroup = @{})
    $groups = $(if ($Section.PSObject.Properties['Groups'] -and $Section.Groups) { $Section.Groups } else { @{} })
    $seen = @{}
    foreach ($p in $Pages) {
        $g = [string]$groups[$p]
        if (-not $g) { [pscustomobject]@{ Label = (Get-IgwtGuiPageLabel -Page $p); Key = $p; Pages = @($p); Target = $p }; continue }
        if ($seen.ContainsKey($g)) { continue }
        $seen[$g] = $true
        $members = @($Pages | Where-Object { [string]$groups[$_] -eq $g })
        $target = $(if ($LastInGroup.ContainsKey($g) -and $members -contains [string]$LastInGroup[$g]) { [string]$LastInGroup[$g] } else { $members[0] })
        [pscustomobject]@{ Label = $g; Key = "group:$g"; Pages = $members; Target = $target }
    }
}

function Update-IgwtGuiSectionTabs {
    <#
    .SYNOPSIS
        The tab row above the page: one tab per page of the section, pages of a group (Protection:
        Defender and ASR) share one tab and get a second, smaller row (single choice, announced as
        toggles). Hidden for one-page sections and for Optimize, whose page has its own category chips.
        The Risk Zone tab follows the persona.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Section, [Parameter(Mandatory = $true)][string]$Page)
    $host2 = $script:Gui.C.SectionTabs
    if (-not $host2) { return }
    $pages = @($Section.Pages | Where-Object { $_ -ne 'Risk Zone' -or -not $script:Gui.Persona -or $script:Gui.Persona.ShowRiskZone })
    if ($pages.Count -lt 2 -or $Section.Id -eq 'Optimize') { $host2.Visibility = 'Collapsed'; return }
    if (-not $script:Gui.TabGroupPage) { $script:Gui.TabGroupPage = @{} }
    $tabs = @(Get-IgwtGuiSectionTabList -Section $Section -Pages $pages -LastInGroup $script:Gui.TabGroupPage)
    $current = @($tabs | Where-Object { $_.Pages -contains $Page }) | Select-Object -First 1
    if ($current -and $current.Key -like 'group:*') { $script:Gui.TabGroupPage[$current.Label] = $Page }
    $host2.Children.Clear()
    foreach ($tb in $tabs) {
        $chip = New-Object System.Windows.Controls.Primitives.ToggleButton
        $chip.Content = $tb.Label; $chip.Tag = $tb.Target
        $chip.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'FilterChip')
        [System.Windows.Automation.AutomationProperties]::SetName($chip, "$($Section.Title): $($tb.Label)")
        $chip.IsChecked = ($current -and $tb.Key -eq $current.Key)
        Register-IgwtGuiHandler -Control $chip -Event 'Click' -Handler { param($s, $e) Open-IgwtGuiPage -Page ([string]$s.Tag) }
        $null = $host2.Children.Add($chip)
    }
    # The pages of the open group, as a second, quieter row after a separator.
    if ($current -and @($current.Pages).Count -gt 1) {
        $sep = New-Object System.Windows.Controls.TextBlock; $sep.Text = [string][char]0x203A; $sep.VerticalAlignment = 'Center'; $sep.Margin = [System.Windows.Thickness]::new(4, 0, 8, 2); $sep.FontSize = 18
        $sep.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BrushTextMuted')
        $null = $host2.Children.Add($sep)
        foreach ($p in $current.Pages) {
            $sub = New-Object System.Windows.Controls.Primitives.ToggleButton
            $sub.Content = Get-IgwtGuiPageLabel -Page $p; $sub.Tag = $p
            $sub.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'FilterChip')
            $sub.Opacity = 0.9; $sub.FontSize = 12
            [System.Windows.Automation.AutomationProperties]::SetName($sub, "$($current.Label): $(Get-IgwtGuiPageLabel -Page $p)")
            $sub.IsChecked = ($p -eq $Page)
            Register-IgwtGuiHandler -Control $sub -Event 'Click' -Handler { param($s, $e) Open-IgwtGuiPage -Page ([string]$s.Tag) }
            $null = $host2.Children.Add($sub)
        }
    }
    $host2.Tag = "$($Section.Id)|$Page"
    $host2.Visibility = 'Visible'
}

function Set-IgwtGuiShowAdvanced {
    <# .SYNOPSIS Shows or hides Advanced tools in the navigation (hidden by default; Phase 3 design). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$On, [switch]$NoSave)
    $script:Gui.ShowAdvanced = $On
    if ($script:Gui.C -and $script:Gui.C.ShowAdvancedBox -and [bool]$script:Gui.C.ShowAdvancedBox.IsChecked -ne $On) { $script:Gui.C.ShowAdvancedBox.IsChecked = $On }
    if (-not $NoSave) { Set-IgwtGuiViewValue -Name 'ShowAdvanced' -Value $On }
    if ($script:Gui.C -and $script:Gui.C.NavList) { Update-IgwtGuiSectionNav }
}
