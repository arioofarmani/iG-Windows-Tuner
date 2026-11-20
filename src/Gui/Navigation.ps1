# Navigation.ps1
# 4.0 section 3 (D1): the window's sections (Phase 3 design, section 2). The navigation lists seven
# sections plus Advanced tools and Settings; a section with several pages shows them as tabs above the
# page. Every 3.x page id still works (Open-IgwtGuiPage), so deep links, persona orders, saved views and
# the render suite keep their names. Display only: nothing here changes the PC.

$script:IgwtGuiSections = @(
    [pscustomobject]@{ Id = 'Home'; Title = 'Home'; Glyph = [string][char]0xE80F; Pages = @('Home', 'Dashboard'); Bottom = $false; Advanced = $false; Help = 'What to do next, recent changes and health checks' }
    [pscustomobject]@{ Id = 'Play'; Title = 'Play'; Glyph = [string][char]0xE7FC; Pages = @('Presets'); Bottom = $false; Advanced = $false; Help = 'Presets and Session Mode' }
    [pscustomobject]@{ Id = 'Optimize'; Title = 'Optimize'; Glyph = [string][char]0xE945; Pages = @('Power & CPU', 'Graphics & Display', 'Input', 'Background & Privacy', 'System'); Bottom = $false; Advanced = $false; Help = 'Settings that change how Windows runs games' }
    [pscustomobject]@{ Id = 'Security'; Title = 'Security'; Glyph = [string][char]0xE72E; Pages = @('Security', 'Asr', 'Defender', 'SecSettings', 'Firewall'); Bottom = $false; Advanced = $false; Help = 'Security score, Defender, attack surface rules and firewall' }
    [pscustomobject]@{ Id = 'Network'; Title = 'Network'; Glyph = [string][char]0xE701; Pages = @('NetTest', 'Network', 'Diagnostics'); Bottom = $false; Advanced = $false; Help = 'Network test, network settings and diagnostics' }
    [pscustomobject]@{ Id = 'Clean'; Title = 'Clean'; Glyph = [string][char]0xE74D; Pages = @('Cleaner', 'RegistryCleaner', 'Storage', 'Disk', 'Startup'); Bottom = $false; Advanced = $false; Help = 'Files, registry leftovers, storage and startup apps' }
    [pscustomobject]@{ Id = 'History'; Title = 'History'; Glyph = [string][char]0xE81C; Pages = @('Backups'); Bottom = $false; Advanced = $false; Help = 'Every change with Undo' }
    [pscustomobject]@{ Id = 'Advanced'; Title = 'Advanced tools'; Glyph = [string][char]0xE90F; Pages = @('Inspect', 'Policy', 'Manage', 'Toolkit', 'Risk Zone', 'Rejected'); Bottom = $true; Advanced = $true; Help = 'Expert inspectors, Group Policy, services and tasks, Toolkit and Risk Zone' }
    [pscustomobject]@{ Id = 'Settings'; Title = 'Settings'; Glyph = [string][char]0xE713; Pages = @('About'); Bottom = $true; Advanced = $false; Help = 'About iG Windows Tuner' }
)

# Short tab names for pages inside a section (plain words, no internal names).
$script:IgwtGuiPageLabels = @{
    'Home' = 'Overview'; 'Dashboard' = 'Health checks'; 'Presets' = 'Presets'
    'Power & CPU' = 'Power & CPU'; 'Graphics & Display' = 'Graphics & Display'; 'Input' = 'Input'; 'Background & Privacy' = 'Background & Privacy'; 'System' = 'System'
    'Security' = 'Overview'; 'Asr' = 'Attack surface rules'; 'Defender' = 'Defender'; 'SecSettings' = 'Security settings'; 'Firewall' = 'Firewall'
    'NetTest' = 'Network test'; 'Network' = 'Network settings'; 'Diagnostics' = 'Diagnostics'
    'Cleaner' = 'Files'; 'RegistryCleaner' = 'Registry leftovers'; 'Storage' = 'Storage Sense'; 'Disk' = 'Disk'; 'Startup' = 'Startup apps'
    'Backups' = 'History'; 'Inspect' = 'Expert inspectors'; 'Policy' = 'Group Policy'; 'Manage' = 'Services and tasks'; 'Toolkit' = 'Toolkit'
    'Risk Zone' = 'Risk Zone'; 'Rejected' = 'Rejected tweaks'; 'About' = 'About'
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

function Update-IgwtGuiSectionTabs {
    <#
    .SYNOPSIS
        The tab row above the page: one tab per page of the section (single choice, announced as
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
    if ([string]$host2.Tag -ne "$($Section.Id)|$($pages -join '|')") {
        $host2.Children.Clear()
        foreach ($p in $pages) {
            $chip = New-Object System.Windows.Controls.Primitives.ToggleButton
            $chip.Content = Get-IgwtGuiPageLabel -Page $p
            $chip.Tag = $p
            $chip.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'FilterChip')
            [System.Windows.Automation.AutomationProperties]::SetName($chip, "$($Section.Title): $(Get-IgwtGuiPageLabel -Page $p)")
            Register-IgwtGuiHandler -Control $chip -Event 'Click' -Handler { param($s, $e) Open-IgwtGuiPage -Page ([string]$s.Tag) }
            $null = $host2.Children.Add($chip)
        }
        $host2.Tag = "$($Section.Id)|$($pages -join '|')"
    }
    foreach ($chip in $host2.Children) { $chip.IsChecked = ([string]$chip.Tag -eq $Page) }
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
