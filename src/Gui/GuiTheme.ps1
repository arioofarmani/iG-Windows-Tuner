# GuiTheme.ps1
# Design tokens for the WPF GUI: colour palettes (Dark, Light, High Contrast), the type scale
# (14 px body), density and the contrast maths the theme tests use. Every brush in the window is
# one live SolidColorBrush per token (bound to a private source brush, so it is never frozen);
# switching themes changes the colours of those brushes in place, so every element, row and
# tooltip follows without being rebuilt. XAML refers
# to the tokens with DynamicResource. High Contrast takes its colours from the Windows
# high-contrast scheme (SystemColors) and is chosen automatically when Windows uses one.

$script:IgwtThemeTokens = @('Background', 'Sidebar', 'Surface', 'SurfaceAlt', 'SurfaceHover', 'Border', 'BorderStrong', 'Text', 'TextMuted', 'TextDisabled',
    'Accent', 'AccentHover', 'AccentDark', 'AccentSoft', 'OnAccent', 'Focus', 'Success', 'SuccessSoft', 'Warning', 'WarningSoft', 'Danger', 'DangerSoft',
    'DangerStrong', 'OnDanger', 'Info', 'InfoSoft', 'Neutral', 'NeutralSoft', 'Overlay', 'Link')

$script:IgwtThemePalettes = @{
    Dark  = @{
        Background = '#FF15171B'; Sidebar = '#FF111317'; Surface = '#FF1E2127'; SurfaceAlt = '#FF262A31'; SurfaceHover = '#FF2D323A'; Border = '#FF2E333B'; BorderStrong = '#FF6E7681'
        Text = '#FFF2F4F7'; TextMuted = '#FFA7B0BB'; TextDisabled = '#FF6E7681'
        Accent = '#FF4CC2FF'; AccentHover = '#FF7CD3FF'; AccentDark = '#FF0B5FA5'; AccentSoft = '#FF16324A'; OnAccent = '#FF04182A'; Focus = '#FF8AD8FF'
        Success = '#FF5BD08A'; SuccessSoft = '#FF173726'; Warning = '#FFF5C451'; WarningSoft = '#FF3A3016'; Danger = '#FFFF8A93'; DangerSoft = '#FF3D1C21'
        DangerStrong = '#FFC42B1C'; OnDanger = '#FFFFFFFF'; Info = '#FF4CC2FF'; InfoSoft = '#FF16324A'; Neutral = '#FFA7B0BB'; NeutralSoft = '#FF262A31'
        Overlay = '#B3000000'; Link = '#FF6CCBFF'
    }
    Light = @{
        Background = '#FFF4F5F7'; Sidebar = '#FFE9ECF0'; Surface = '#FFFFFFFF'; SurfaceAlt = '#FFF0F2F5'; SurfaceHover = '#FFE3E7EC'; Border = '#FFD3D8DE'; BorderStrong = '#FF7A828C'
        Text = '#FF1A1D21'; TextMuted = '#FF4C5560'; TextDisabled = '#FF8C949E'
        Accent = '#FF0A63BC'; AccentHover = '#FF0B53A0'; AccentDark = '#FFA9CDF2'; AccentSoft = '#FFDCEAF9'; OnAccent = '#FFFFFFFF'; Focus = '#FF0A63BC'
        Success = '#FF136B2D'; SuccessSoft = '#FFE2F3E7'; Warning = '#FF835000'; WarningSoft = '#FFFFF3D1'; Danger = '#FFB42318'; DangerSoft = '#FFFDE8E6'
        DangerStrong = '#FFB42318'; OnDanger = '#FFFFFFFF'; Info = '#FF0A63BC'; InfoSoft = '#FFDCEAF9'; Neutral = '#FF4C5560'; NeutralSoft = '#FFEDEFF2'
        Overlay = '#80000000'; Link = '#FF0A58A8'
    }
}

$script:IgwtTypeScale = [ordered]@{ FontSizeCaption = 12; FontSizeSmall = 13; FontSizeBody = 14; FontSizeBodyLarge = 15; FontSizeSubtitle = 16; FontSizeTitleSmall = 18; FontSizeTitle = 22; FontSizeTitleLarge = 26; FontSizeDisplay = 30 }
$script:IgwtDensity = @{
    Comfortable = @{ GridRowHeight = 38.0; GridCellPadding = '10,7'; RowItemPadding = '14,10'; RowItemMargin = '0,0,0,4'; CardPadding = '16,14' }
    Compact     = @{ GridRowHeight = 28.0; GridCellPadding = '8,3'; RowItemPadding = '10,5'; RowItemMargin = '0,0,0,2'; CardPadding = '12,10' }
}
$script:IgwtThemeBrushes = @{}
$script:IgwtThemeSources = @{}
$script:IgwtThemeName = 'Dark'

function Get-IgwtGuiPalette {
    <#
    .SYNOPSIS
        The colours of a theme as token -> System.Windows.Media.Color. HighContrast reads the
        Windows high-contrast scheme (SystemColors): text, background, highlight, hot-track and
        gray text; status colours are the window text colour (status is always icon plus text).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Dark', 'Light', 'HighContrast')][string]$Name)
    $out = [ordered]@{}
    if ($Name -eq 'HighContrast') {
        $sc = [System.Windows.SystemColors]
        $win = $sc::WindowColor; $text = $sc::WindowTextColor; $hl = $sc::HighlightColor; $hlText = $sc::HighlightTextColor; $gray = $sc::GrayTextColor; $hot = $sc::HotTrackColor
        $map = @{ Background = $win; Sidebar = $win; Surface = $win; SurfaceAlt = $win; SurfaceHover = $win; Border = $text; BorderStrong = $text; Text = $text; TextMuted = $text; TextDisabled = $gray
            Accent = $hl; AccentHover = $hl; AccentDark = $hl; AccentSoft = $win; OnAccent = $hlText; Focus = $hl; Success = $text; SuccessSoft = $win; Warning = $text; WarningSoft = $win
            Danger = $text; DangerSoft = $win; DangerStrong = $hl; OnDanger = $hlText; Info = $text; InfoSoft = $win; Neutral = $text; NeutralSoft = $win; Overlay = $win; Link = $hot }
        foreach ($t in $script:IgwtThemeTokens) { $out[$t] = $map[$t] }
        return $out
    }
    $p = $script:IgwtThemePalettes[$Name]
    foreach ($t in $script:IgwtThemeTokens) { $out[$t] = [System.Windows.Media.ColorConverter]::ConvertFromString([string]$p[$t]) }
    return $out
}

function Resolve-IgwtGuiThemeName {
    <# .SYNOPSIS Resolves System to Dark, Light or HighContrast (Windows high contrast wins, then the app light/dark setting). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Name = 'System')
    if ([System.Windows.SystemParameters]::HighContrast) { return 'HighContrast' }
    if ($Name -in 'Dark', 'Light', 'HighContrast') { return $Name }
    $v = $null
    try { $v = Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' } catch { $v = $null }
    if ($v -and $v.Exists -and [int]$v.Value -eq 1) { return 'Light' }
    return 'Dark'
}

function Set-IgwtGuiTheme {
    <#
    .SYNOPSIS
        Applies a theme to a window (or any element's resources): every Brush<Token> and
        Color<Token> resource. The first call creates one unfrozen brush per token; later calls
        change their colours in place.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window resources only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [string]$Name = 'System')
    $resolved = Resolve-IgwtGuiThemeName -Name $Name
    $pal = Get-IgwtGuiPalette -Name $resolved
    foreach ($t in $script:IgwtThemeTokens) {
        $color = $pal[$t]
        $brush = $script:IgwtThemeBrushes[$t]
        if (-not $brush) {
            # WPF freezes brushes that styles use, so a plain brush could not change colour later.
            # The live brush binds its Color to a private source brush: a bound brush cannot be
            # frozen, and changing the source recolours every element that uses the token.
            $src = [System.Windows.Media.SolidColorBrush]::new($color)
            $brush = [System.Windows.Media.SolidColorBrush]::new()
            $bind = New-Object System.Windows.Data.Binding('Color')
            $bind.Source = $src
            $null = [System.Windows.Data.BindingOperations]::SetBinding($brush, [System.Windows.Media.SolidColorBrush]::ColorProperty, $bind)
            $script:IgwtThemeSources[$t] = $src
            $script:IgwtThemeBrushes[$t] = $brush
        } else { $script:IgwtThemeSources[$t].Color = $color }
        $Target.Resources["Brush$t"] = $brush
        $Target.Resources["Color$t"] = $color
    }
    $script:IgwtThemeName = $resolved
    # Tone -> live brush for the row builders (ViewModels.ps1).
    $script:IgwtColor = @{ Pass = $script:IgwtThemeBrushes.Success; Warn = $script:IgwtThemeBrushes.Warning; Fail = $script:IgwtThemeBrushes.Danger; Info = $script:IgwtThemeBrushes.Info
        Unknown = $script:IgwtThemeBrushes.Warning; Muted = $script:IgwtThemeBrushes.TextMuted; Text = $script:IgwtThemeBrushes.Text; Accent = $script:IgwtThemeBrushes.Accent }
    return $resolved
}

function Set-IgwtGuiTextScale {
    <# .SYNOPSIS Sets every FontSize* token to its base size times the text scale (100-150 %). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window resources only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [ValidateRange(100, 150)][int]$Percent = 100)
    foreach ($k in @($script:IgwtTypeScale.Keys)) { $Target.Resources[$k] = [double]([math]::Round($script:IgwtTypeScale[$k] * $Percent / 100.0, 1)) }
}

function Set-IgwtGuiDensity {
    <# .SYNOPSIS Comfortable or Compact rows, cells and cards. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window resources only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [ValidateSet('Comfortable', 'Compact')][string]$Mode = 'Comfortable')
    $d = $script:IgwtDensity[$Mode]
    $Target.Resources['GridRowHeight'] = [double]$d.GridRowHeight
    foreach ($k in 'GridCellPadding', 'RowItemPadding', 'RowItemMargin', 'CardPadding') { $Target.Resources[$k] = [System.Windows.Thickness]((New-Object System.Windows.ThicknessConverter).ConvertFromString($d[$k])) }
}

function Get-IgwtColorLuminance {
    <# .SYNOPSIS WCAG relative luminance of an opaque colour. #>
    [CmdletBinding()]
    [OutputType([double])]
    param([Parameter(Mandatory = $true)][System.Windows.Media.Color]$Color)
    $lin = { param([double]$c) $c = $c / 255.0; if ($c -le 0.03928) { $c / 12.92 } else { [math]::Pow(($c + 0.055) / 1.055, 2.4) } }
    return (0.2126 * (& $lin $Color.R) + 0.7152 * (& $lin $Color.G) + 0.0722 * (& $lin $Color.B))
}

function Get-IgwtContrastRatio {
    <# .SYNOPSIS WCAG 2.2 contrast ratio between two opaque colours (1 to 21). #>
    [CmdletBinding()]
    [OutputType([double])]
    param([Parameter(Mandatory = $true)][System.Windows.Media.Color]$Foreground, [Parameter(Mandatory = $true)][System.Windows.Media.Color]$Background)
    $a = Get-IgwtColorLuminance -Color $Foreground; $b = Get-IgwtColorLuminance -Color $Background
    $hi = [math]::Max($a, $b); $lo = [math]::Min($a, $b)
    return [math]::Round(($hi + 0.05) / ($lo + 0.05), 2)
}
