# AdvancedPage.ps1
# 4.0 section 7: Advanced tools open on an overview, one card per tool (what it is for, one button).
# Each tool page then shows the "for experts" info bar (Show-IgwtGuiPage). Handlers use Tags, never
# closures (DECISIONS U9).

$script:IgwtGuiAdvancedCards = @(
    [pscustomobject]@{ Page = 'Inspect'; Title = 'Expert inspectors'; Text = 'Power plan settings, kernel and memory values, and network adapter properties, read from this PC with what each one means.' }
    [pscustomobject]@{ Page = 'Policy'; Title = 'Group Policy'; Text = 'Every administrative template policy on this PC: search, read the explanation, and set one with a backup and undo.' }
    [pscustomobject]@{ Page = 'Manage'; Title = 'Services and tasks'; Text = 'Services, scheduled tasks, apps and startup locations. Windows and security parts are protected and cannot be changed.' }
    [pscustomobject]@{ Page = 'Toolkit'; Title = 'Toolkit'; Text = 'Install and update apps with winget, turn Windows features on or off, run repair steps and open control panels.' }
    [pscustomobject]@{ Page = 'Risk Zone'; Title = 'Risk Zone'; Text = 'Popular tweaks iG does not recommend, each with what it turns off and why. Every one needs a typed confirmation.' }
    [pscustomobject]@{ Page = 'Rejected'; Title = 'Rejected tweaks'; Text = 'Ideas iG checked and left out, with the reason and the sources.' }
)

function Update-IgwtGuiAdvancedPage {
    <# .SYNOPSIS Draws the Advanced tools overview into AdvancedHost: a header, an info bar and one card per tool. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $h = $script:Gui.C.AdvancedHost
    if (-not $h) { return }
    $h.Children.Clear()
    $null = $h.Children.Add((New-IgwtPageHeader -Title 'Advanced tools' -Subtitle 'Deeper Windows settings for experienced users. Everything here is previewed first, journaled and can be undone in History.'))
    $ib = New-IgwtInfoBar -Title 'For experts' -Message 'These tools change settings that most players never need. When unsure, use Optimize and Play instead.' -Tone Info
    $ib.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
    $null = $h.Children.Add($ib)
    $grid = New-Object System.Windows.Controls.Primitives.UniformGrid
    $grid.Columns = 3; $grid.Margin = [System.Windows.Thickness]::new(0, 0, -16, 0)
    $cards = @($script:IgwtGuiAdvancedCards | Where-Object { $_.Page -ne 'Risk Zone' -or -not $script:Gui.Persona -or $script:Gui.Persona.ShowRiskZone })
    foreach ($cd in $cards) {
        $b = New-Object System.Windows.Controls.Border
        $b.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'Card4')
        $b.Margin = [System.Windows.Thickness]::new(0, 0, 16, 16)
        $dp = New-Object System.Windows.Controls.DockPanel
        $open = New-IgwtUiButton -Text 'Open' -Kind Secondary -ObjectName $cd.Title
        $open.Tag = $cd.Page; $open.HorizontalAlignment = 'Left'; $open.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
        Register-IgwtGuiHandler -Control $open -Event 'Click' -Handler { param($s, $e) $null = $e; Open-IgwtGuiPage -Page ([string]$s.Tag) }
        [System.Windows.Controls.DockPanel]::SetDock($open, 'Bottom'); $null = $dp.Children.Add($open)
        $sp = New-Object System.Windows.Controls.StackPanel
        $t = New-IgwtUiText -Text $cd.Title -Style 'TextSubtitle'
        [System.Windows.Automation.AutomationProperties]::SetHeadingLevel($t, [System.Windows.Automation.AutomationHeadingLevel]::Level2)
        $null = $sp.Children.Add($t)
        $d = New-IgwtUiText -Text $cd.Text -Style 'TextBody' -Brush 'BrushTextMuted'; $d.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
        $null = $sp.Children.Add($d)
        $null = $dp.Children.Add($sp)
        $b.Child = $dp
        $null = $grid.Children.Add($b)
    }
    $null = $h.Children.Add($grid)
}
