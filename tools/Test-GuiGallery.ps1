<#
.SYNOPSIS
    Offscreen component gallery: one sample of every style in src\Gui\Theme.xaml, per theme and
    display scale, rendered to PNG (WPF RenderTargetBitmap). No window is shown, nothing on the PC
    is read or changed. Every Style in Theme.xaml is picked up by its target type, so a new control
    style appears without changing this tool; a style whose target type has no sample fails the run.
.DESCRIPTION
    4.0 section 1.3: the review surface for the design work in sections 2-7. Writes
    <OutDir>\gallery-<theme>-<scale>.png and gallery.json (styles shown, size, seconds).
.PARAMETER OutDir
    Output folder (default artifacts\gui-gallery).
.PARAMETER Theme
    Themes to render (Dark, Light, HighContrast). Default: all.
.PARAMETER Scale
    Display scales to emulate (1 = 100 %). Default: 1, 1.5, 2.
.EXAMPLE
    .\tools\Test-GuiGallery.ps1 -Theme Dark -Scale 1
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [ValidateSet('Dark', 'Light', 'HighContrast')][string[]]$Theme = @('Dark', 'Light', 'HighContrast'),
    [double[]]$Scale = @(1, 1.5, 2)
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# In Windows PowerShell 5.1, $PSScriptRoot is empty in a parameter default under -File.
if (-not $OutDir) { $OutDir = Join-Path $root 'artifacts\gui-gallery' }
if (-not (Test-Path -LiteralPath $OutDir)) { $null = New-Item -ItemType Directory -Path $OutDir -Force }
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$child = Join-Path ([System.IO.Path]::GetTempPath()) ("igwt-gallery-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
@'
param([string]$Root, [string]$Dir, [string]$Theme, [double]$Scale)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $Root 'src\iGWindowsTuner.psd1') -Force
Set-IgwtEnvironment -ReadOnly
$m = Get-Module iGWindowsTuner
& $m {
    param($Dir, $Theme, $Scale)
    Import-IgwtWpf
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $dict = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader(([xml](Get-Content -LiteralPath (Join-Path $script:IgwtModuleRoot 'Gui\Theme.xaml') -Raw)))))
    $host2 = New-Object System.Windows.Controls.Border
    $host2.Resources.MergedDictionaries.Add($dict)
    $null = Set-IgwtGuiTheme -Target $host2 -Name $Theme
    Set-IgwtGuiTextScale -Target $host2 -Percent 100
    Set-IgwtGuiDensity -Target $host2 -Mode Comfortable
    $host2.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'BrushBackground')
    $host2.Padding = [System.Windows.Thickness]::new(24)
    $text = { param($s, $style) $t = New-Object System.Windows.Controls.TextBlock; $t.Text = $s; if ($style) { $t.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, $style) } else { $t.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BrushText') }; $t }
    # One sample per target type. A style whose type is missing here fails the run (see below).
    $sample = @{
        TextBlock    = { param($k) & $text "$k  -  The quick brown fox" $k }
        Button       = { param($k) $b = New-Object System.Windows.Controls.Button; $b.Content = $k; $b }
        CheckBox     = { param($k) $c = New-Object System.Windows.Controls.CheckBox; $c.Content = $k; $c.IsChecked = $true; $c }
        ToggleButton = { param($k) $c = New-Object System.Windows.Controls.Primitives.ToggleButton; $c.Content = "$k (on)"; $c.IsChecked = $true; $c }
        RadioButton  = { param($k) $c = New-Object System.Windows.Controls.RadioButton; $c.Content = "$k (selected)"; $c.IsChecked = $true; $c.GroupName = "g$k"; $c }
        TextBox      = { param($k) $c = New-Object System.Windows.Controls.TextBox; $c.Text = "$k text"; $c.Width = 260; $c }
        Border       = { param($k) $c = New-Object System.Windows.Controls.Border; $c.Child = (& $text $k $null); $c.MinWidth = 160; $c }
        Expander     = { param($k) $c = New-Object System.Windows.Controls.Expander; $c.Header = $k; $c.IsExpanded = $true; $c.Content = (& $text 'Expanded content' $null); $c }
        ListBoxItem  = { param($k) $l = New-Object System.Windows.Controls.ListBox; $i = New-Object System.Windows.Controls.ListBoxItem; $i.Content = $k; $i.IsSelected = $true; $null = $l.Items.Add($i); $l.Width = 240; $l }
        ListViewItem = { param($k) $l = New-Object System.Windows.Controls.ListView; $i = New-Object System.Windows.Controls.ListViewItem; $i.Content = $k; $null = $l.Items.Add($i); $l.Width = 240; $l }
        Thumb        = { param($k) $c = New-Object System.Windows.Controls.Primitives.Thumb; $c.Width = 12; $c.Height = 60; $c }
        ComboBox     = { param($k) $c = New-Object System.Windows.Controls.ComboBox; foreach ($o in 'Option A', 'Option B') { $null = $c.Items.Add($o) }; $c.SelectedIndex = 0; $c.Width = 220; $c }
        ComboBoxItem = { param($k) $c = New-Object System.Windows.Controls.ComboBoxItem; $c.Content = $k; $c.Width = 220; $c }
        ListBox      = { param($k) $c = New-Object System.Windows.Controls.ListBox; foreach ($o in 'First', 'Second (selected)') { $null = $c.Items.Add($o) }; $c.SelectedIndex = 1; $c.Width = 240; $c }
        ListView     = { param($k) $c = New-Object System.Windows.Controls.ListView; foreach ($o in 'First', 'Second (selected)') { $null = $c.Items.Add($o) }; $c.SelectedIndex = 1; $c.Width = 240; $c }
        ProgressBar  = { param($k) $c = New-Object System.Windows.Controls.ProgressBar; $c.Value = 60; $c.Width = 240; $c.Height = 8; $c }
        ScrollBar    = { param($k) $c = New-Object System.Windows.Controls.Primitives.ScrollBar; $c.Orientation = 'Vertical'; $c.Height = 120; $c.Maximum = 100; $c.ViewportSize = 30; $c.Value = 20; $c }
        # A ToolTip cannot have a parent (WPF shows it in its own popup): render it alone, show the picture.
        ToolTip      = {
            param($k)
            $tt = New-Object System.Windows.Controls.ToolTip; $tt.Content = 'A tooltip'
            foreach ($rk in @($host2.Resources.Keys)) { $tt.Resources[$rk] = $host2.Resources[$rk] }
            $tt.Resources.MergedDictionaries.Add($dict)
            $tt.Measure([System.Windows.Size]::new([double]::PositiveInfinity, [double]::PositiveInfinity))
            $tt.Arrange([System.Windows.Rect]::new($tt.DesiredSize)); $tt.UpdateLayout()
            $b = [System.Windows.Media.Imaging.RenderTargetBitmap]::new([int][math]::Ceiling($tt.DesiredSize.Width * $Scale), [int][math]::Ceiling($tt.DesiredSize.Height * $Scale), (96 * $Scale), (96 * $Scale), [System.Windows.Media.PixelFormats]::Pbgra32)
            $b.Render($tt)
            $img = New-Object System.Windows.Controls.Image; $img.Source = $b; $img.Width = $tt.DesiredSize.Width; $img.Height = $tt.DesiredSize.Height; $img.HorizontalAlignment = 'Left'
            $img
        }
        TabControl   = { param($k) $c = New-Object System.Windows.Controls.TabControl; foreach ($o in 'Overview', 'Details') { $i = New-Object System.Windows.Controls.TabItem; $i.Header = $o; $i.Content = (& $text "$o tab" $null); $null = $c.Items.Add($i) }; $c.Width = 320; $c.Height = 110; $c }
        TreeView     = { param($k) $c = New-Object System.Windows.Controls.TreeView; $i = New-Object System.Windows.Controls.TreeViewItem; $i.Header = 'Parent'; $i.IsExpanded = $true; $null = $i.Items.Add('Child'); $null = $c.Items.Add($i); $c.Width = 240; $c }
        # Columns are explicit: a DataGrid generates them on Loaded, which never fires offscreen.
        DataGrid     = {
            param($k)
            $tb = New-Object System.Data.DataTable; $null = $tb.Columns.Add('Setting'); $null = $tb.Columns.Add('Value')
            $null = $tb.Rows.Add('Game Mode', 'On'); $null = $tb.Rows.Add('Search indexing', 'Off')
            $c = New-Object System.Windows.Controls.DataGrid; $c.AutoGenerateColumns = $false; $c.EnableRowVirtualization = $false
            foreach ($n in 'Setting', 'Value') { $col = New-Object System.Windows.Controls.DataGridTextColumn; $col.Header = $n; $col.Binding = New-Object System.Windows.Data.Binding($n); $c.Columns.Add($col) }
            $c.ItemsSource = $tb.DefaultView; $c.Width = 320; $c.SelectedIndex = 0; $c
        }
    }
    # Parts are drawn inside their host control's sample.
    $partOf = @{ DataGridCell = 'DataGrid'; DataGridColumnHeader = 'DataGrid'; DataGridRow = 'DataGrid'; TabItem = 'TabControl'; TreeViewItem = 'TreeView' }
    foreach ($p in @($partOf.Keys)) { $sample[$p] = { param($k) & $text "Shown in the $($partOf[$k.Split(' ')[0]]) sample." 'TextCaption' } }
    $styles = @($dict.Keys | Where-Object { $dict[$_] -is [System.Windows.Style] } | Sort-Object { $dict[$_].TargetType.Name }, { [string]$_ })
    $panel = New-Object System.Windows.Controls.StackPanel
    $null = $panel.Children.Add((& $text "Component gallery - $Theme - $([int]($Scale * 100)) %" 'TextTitle'))
    $missing = New-Object System.Collections.Generic.List[string]
    $shown = New-Object System.Collections.Generic.List[string]
    $group = ''
    $wrap = $null
    foreach ($k in $styles) {
        $type = $dict[$k].TargetType.Name
        if ($type -ne $group) {
            $group = $type
            $h = & $text $type 'TextSection'; $h.Margin = [System.Windows.Thickness]::new(0, 16, 0, 8); $null = $panel.Children.Add($h)
            $wrap = New-Object System.Windows.Controls.WrapPanel; $null = $panel.Children.Add($wrap)
        }
        if (-not $sample.ContainsKey($type)) { $missing.Add("$k ($type)"); continue }
        # A style keyed by its type is the default look: it applies by itself, no style reference.
        $implicit = ($k -is [type])
        $label = $(if ($implicit) { "$type (default)" } else { [string]$k })
        $el = & $sample[$type] $label
        $wrapCell = $false; $cap = $null
        # Icon-font styles get icon glyphs (Segoe Fluent Icons has no letters).
        if (-not $implicit -and [string]$k -match '^(Icon|ToneIcon|CaptionButton|CaptionCloseButton)$') {
            $glyphs = [string][char]0xE713 + ' ' + [char]0xE8BB + ' ' + [char]0xE946
            if ($type -eq 'TextBlock') { $el.Text = $glyphs } else { $el.Content = $glyphs; $el.ToolTip = $label }
            $cap = & $text $label 'TextCaption'; $wrapCell = $true
        }
        # A named style goes on the sample itself, except where the sample wraps the styled item.
        if ($implicit) { }
        elseif ($type -in 'ListBoxItem', 'ListViewItem') { $el.Items[0].SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, [string]$k) }
        elseif ($type -ne 'TextBlock') { $el.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, [string]$k) }
        if ($implicit -and $type -notin 'TextBlock', 'Border', 'Thumb') { $cap = & $text $label 'TextCaption'; $wrapCell = $true }
        $cell = New-Object System.Windows.Controls.StackPanel
        $cell.Margin = [System.Windows.Thickness]::new(0, 0, 16, 12)
        if ($wrapCell) { $null = $cell.Children.Add($cap) }
        $null = $cell.Children.Add($el)
        if ($type -eq 'Button' -and [string]$k -notlike 'Caption*') { $d = & $sample.Button "$label (disabled)"; $d.IsEnabled = $false; if (-not $implicit) { $d.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, [string]$k) }; $d.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0); $null = $cell.Children.Add($d) }
        $null = $wrap.Children.Add($cell)
        $shown.Add($label)
    }
    $host2.Child = $panel
    $host2.LayoutTransform = [System.Windows.Media.ScaleTransform]::new($Scale, $Scale)
    $host2.Measure([System.Windows.Size]::new(1100 * $Scale, [double]::PositiveInfinity))
    $host2.Arrange([System.Windows.Rect]::new(0, 0, 1100 * $Scale, $host2.DesiredSize.Height))
    $host2.UpdateLayout()
    # Grids and lists create their rows on the dispatcher: let it run, then lay out again.
    $host2.Dispatcher.Invoke([action] {}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
    $host2.Measure([System.Windows.Size]::new(1100 * $Scale, [double]::PositiveInfinity))
    $host2.Arrange([System.Windows.Rect]::new(0, 0, 1100 * $Scale, $host2.DesiredSize.Height))
    $host2.UpdateLayout()
    $w = [int][math]::Ceiling($host2.ActualWidth); $h = [int][math]::Ceiling($host2.DesiredSize.Height)
    $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($w, $h, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($host2)
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $file = Join-Path $Dir ("gallery-{0}-{1}.png" -f $Theme.ToLowerInvariant(), [int]($Scale * 100))
    $fs = [System.IO.File]::Create($file)
    try { $enc.Save($fs) } finally { $fs.Dispose() }
    [pscustomobject]@{ Theme = $Theme; Scale = $Scale; File = $file; Styles = $shown.Count; Missing = $missing.ToArray(); Width = $w; Height = $h; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) } | ConvertTo-Json -Compress
} $Dir $Theme $Scale
'@ | Set-Content -LiteralPath $child -Encoding UTF8
$summary = New-Object System.Collections.Generic.List[object]
$failed = $false
try {
    foreach ($t in $Theme) {
        foreach ($s in $Scale) {
            $out = & $psExe -NoProfile -ExecutionPolicy Bypass -STA -File $child -Root $root -Dir $OutDir -Theme $t -Scale $s
            if ($LASTEXITCODE -ne 0) { Write-Warning "Gallery $t $s failed: $($out -join ' ')"; $failed = $true; continue }
            $r = ($out | Select-Object -Last 1) | ConvertFrom-Json
            $summary.Add($r)
            if (@($r.Missing).Count) { Write-Warning "No gallery sample for: $(@($r.Missing) -join ', ')"; $failed = $true }
            '{0,-13} {1,4} %  {2,3} styles  {3,5} s  -> {4}' -f $r.Theme, [int]($r.Scale * 100), $r.Styles, $r.Seconds, $r.File
        }
    }
} finally { Remove-Item -LiteralPath $child -Force -ErrorAction SilentlyContinue }
[System.IO.File]::WriteAllText((Join-Path $OutDir 'gallery.json'), ($summary.ToArray() | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
if ($failed) { exit 1 }
exit 0
