# ChangeProviders.ps1
# 4.0 section 5b (D6): every change goes through the ChangeBar. A page that stages changes registers
# a provider (its count, Preview, Apply and Discard); the bar acts on the provider of the page on
# screen when it has staged changes, otherwise on the tweaks, otherwise on the first provider with
# changes. The tweaks keep their own functions (Invoke-IgwtGuiPreview, Invoke-IgwtGuiApply). Handlers
# use $script:Gui state only, never closures (DECISIONS U9).

function Register-IgwtGuiChangeProvider {
    <# .SYNOPSIS Adds (or replaces) a ChangeBar provider: Id, Noun ("Defender change"), Pages, and scriptblocks Count, Preview, Apply, Discard. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$Noun, [string[]]$Pages = @(),
        [Parameter(Mandatory = $true)][scriptblock]$Count, [Parameter(Mandatory = $true)][scriptblock]$Preview, [Parameter(Mandatory = $true)][scriptblock]$Apply, [Parameter(Mandatory = $true)][scriptblock]$Discard)
    if (-not $script:Gui.ChangeProviders) { $script:Gui.ChangeProviders = [ordered]@{} }
    $script:Gui.ChangeProviders[$Id] = [pscustomobject]@{ Id = $Id; Noun = $Noun; Pages = @($Pages); Count = $Count; Preview = $Preview; Apply = $Apply; Discard = $Discard }
}

function Initialize-IgwtGuiChangeProviders {
    <# .SYNOPSIS Registers the providers of the window: tweaks, Defender settings, ASR rules and Security Settings. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes window state only.')]
    [CmdletBinding()]
    param()
    $script:Gui.ChangeProviders = [ordered]@{}
    if ($null -eq $script:Gui.DefStaged) { $script:Gui.DefStaged = [ordered]@{} }
    if ($null -eq $script:Gui.AsrStaged) { $script:Gui.AsrStaged = [ordered]@{} }
    Register-IgwtGuiChangeProvider -Id 'tweaks' -Noun 'change' -Count { @($script:Gui.Staged.Keys).Count } `
        -Preview { Invoke-IgwtGuiPreview } -Apply { Invoke-IgwtGuiApply } `
        -Discard { $script:Gui.Staged.Clear(); $script:Gui.PresetOperation = $null; Update-IgwtGuiTweakList; Set-IgwtGuiStatus 'All staged changes discarded.' }
    Register-IgwtGuiChangeProvider -Id 'defender' -Noun 'Defender change' -Pages @('Defender') -Count { @($script:Gui.DefStaged.Keys).Count } `
        -Preview { Show-IgwtGuiDefenderStaged } -Apply { Invoke-IgwtGuiDefenderStagedApply } `
        -Discard { $script:Gui.DefStaged.Clear(); Update-IgwtGuiPending; Set-IgwtGuiStatus 'Staged Defender changes discarded.' }
    Register-IgwtGuiChangeProvider -Id 'asr' -Noun 'ASR change' -Pages @('Asr') -Count { @($script:Gui.AsrStaged.Keys).Count } `
        -Preview { Show-IgwtGuiAsrStaged } -Apply { Invoke-IgwtGuiAsrStagedApply } `
        -Discard { $script:Gui.AsrStaged.Clear(); Update-IgwtGuiPending; Update-IgwtGuiAsrRows; Set-IgwtGuiStatus 'Staged ASR changes discarded.' }
    Register-IgwtGuiChangeProvider -Id 'secsettings' -Noun 'security setting change' -Pages @('SecSettings') -Count { Get-IgwtGuiSecStagedCount } `
        -Preview { Invoke-IgwtGuiSecSettingsPreview } -Apply { Invoke-IgwtGuiSecSettingsApply } `
        -Discard { Clear-IgwtGuiSecSettingsStage; Update-IgwtGuiPending }
}

function Get-IgwtGuiChangeProviderState {
    <#
    .SYNOPSIS
        The provider the ChangeBar acts on and the counts (Pure apart from calling each provider's
        Count): the page's own provider when it has changes, else tweaks, else the first provider with
        changes. Returns Active (or $null), Count, Others (changes staged in other providers) and Text.
    #>
    [CmdletBinding()]
    param([string]$Page)
    $list = @($(if ($script:Gui.ChangeProviders) { $script:Gui.ChangeProviders.Values }))
    $counts = @{}
    foreach ($p in $list) { $n = 0; try { $n = [int](& $p.Count) } catch { $n = 0 }; $counts[$p.Id] = $n }
    $active = @($list | Where-Object { $counts[$_.Id] -gt 0 -and @($_.Pages) -contains $Page }) | Select-Object -First 1
    if (-not $active -and $counts['tweaks'] -gt 0) { $active = @($list | Where-Object { $_.Id -eq 'tweaks' })[0] }
    if (-not $active) { $active = @($list | Where-Object { $counts[$_.Id] -gt 0 }) | Select-Object -First 1 }
    $n = $(if ($active) { $counts[$active.Id] } else { 0 })
    $others = 0; foreach ($p in $list) { if (-not $active -or $p.Id -ne $active.Id) { $others += $counts[$p.Id] } }
    $noun = $(if ($active) { [string]$active.Noun } else { 'change' })
    $text = $(if ($n -eq 0) { 'Nothing staged' } elseif ($n -eq 1) { "1 $noun ready" } else { "$n ${noun}s ready" })
    if ($others -gt 0) { $text += " (+$others elsewhere)" }
    return [pscustomobject]@{ Active = $active; Count = $n; Others = $others; Text = $text }
}

function Invoke-IgwtGuiChangeBarAction {
    <# .SYNOPSIS Runs Preview, Apply or Discard of the provider the ChangeBar acts on. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs the provider''s own action, which confirms before any change.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Preview', 'Apply', 'Discard')][string]$Action)
    $st = Get-IgwtGuiChangeProviderState -Page ([string]$script:Gui.CurrentPage)
    if (-not $st.Active -or $st.Count -eq 0) { Set-IgwtGuiStatus 'Nothing is staged.'; return }
    & $st.Active.$Action
}
