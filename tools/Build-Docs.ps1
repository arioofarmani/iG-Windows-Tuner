<#
.SYNOPSIS
    Generates docs\TWEAKS.md, docs\PRESETS.md and docs\REJECTED_TWEAKS.md from the data files.
.DESCRIPTION
    The catalog (data\tweaks\*.json), presets and data\rejected.json are the single source of
    truth; these three documents are regenerated from them and should not be edited by hand.
.EXAMPLE
    .\tools\Build-Docs.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\iGWindowsTuner.psd1') -Force
$docs = Join-Path $root 'docs'
$catalog = @(Get-IgwtCatalog -Force)
$presets = @(Get-IgwtPreset)
$rejected = @(Get-IgwtRejectedTweaks)
$categories = @('Power & CPU', 'Graphics & Display', 'Input', 'Network', 'Background & Privacy', 'Storage', 'Security', 'System')
$nl = "`r`n"

function ConvertTo-MdCell([string]$Text) { return ($Text -replace '\|', '\|' -replace "`r?`n", ' ') }

function Format-Code([string]$Text) { return ([char]96 + $Text + [char]96) }

function Format-DocAction($a) {
    $c = { param($x) Format-Code ([string]$x) }
    switch ($a.type) {
        'registry' {
            $on = [string]$a.on
            if ($null -ne $a.bitClear) { $on = ('clear bit 0x{0:X} (e.g. {1})' -f [int]$a.bitClear, $a.on) }
            $s = 'Registry {0} = {1} ({2}); Windows default {3}' -f (& $c "$($a.path)\$($a.name)"), (& $c $on), $a.valueType, (& $c $a.default)
            if ($null -ne $a.absentValue) { $s += '; absent means ' + (& $c $a.absentValue) }
            if ($a.onlyIfAbsent) { $s += '; only written when missing' }
            return $s
        }
        'adapterRegistry' { return ('Registry (active wired adapter) {0} = {1} ({2}); default {3}' -f (& $c "$($a.path)\$($a.name)"), (& $c $a.on), $a.valueType, (& $c $a.default)) }
        'netAdapterPower' { return ('Active wired adapter driver key {0} = {1} ("allow the computer to turn off this device" cleared); default {2}' -f (& $c 'PnPCapabilities'), (& $c '24'), (& $c '0')) }
        'registryListMerge' { return ('Merge {0} into {1} (other items preserved); default {2}' -f (& $c "$($a.item)=$($a.on)"), (& $c "$($a.path)\$($a.name)"), (& $c $a.default)) }
        'powercfgScheme' { return ('Activate power scheme {0} (revert re-activates the previous scheme)' -f (& $c $a.scheme)) }
        'powercfgSetting' {
            $s = 'Active plan: {0} ({1} / {2}) AC = {3}' -f $a.label, (& $c $a.subgroup), (& $c $a.setting), (& $c $a.ac)
            if ($null -ne $a.dc) { $s += ', DC = ' + (& $c $a.dc) }
            return ($s + "; default from the plan's DefaultPowerSchemeValues")
        }
        'service' {
            $stop = ''
            if ($a.stop) { $stop = ' and stop it' }
            return ('Service {0} startup {1}{2}; Windows default {3}' -f (& $c $a.name), (& $c $a.startupType), $stop, (& $c $a.default))
        }
        'netAdapterAdvanced' {
            $fb = ''
            if (@($a.fallback).Count) { $fb = '; fallback only if the keyword is missing: ' + (@($a.fallback | ForEach-Object { "'{0}' = '{1}'" -f $_.displayName, $_.displayValue }) -join ', ') }
            return ('Adapter advanced property {0} = {1} (no adapter restart){2}; default {3}' -f (& $c $a.keyword), (& $c $a.on), $fb, (& $c $a.default))
        }
        'netQosPolicy' { return ('Policy-based QoS {0}: DSCP {1} for {2} traffic of games marked qos in games.json' -f (& $c "$($a.namePrefix)<game>"), (& $c $a.dscp), (& $c $a.protocol)) }
        'dnsDoh' { return ('DNS servers of the active wired adapter set to {0} with DoH auto-upgrade (fallback to plain DNS: {1}); revert restores DHCP/static servers and DoH entries' -f $a.provider, [bool]$a.allowFallbackToUdp) }
        'mpPreference' { return ('{0}; Windows default {1}' -f (& $c "Set-MpPreference -$($a.setting) $($a.on)"), (& $c $a.default)) }
        'asrRule' { return ('ASR rule {0} ({1}) = {2}; default not configured' -f (& $c $a.id), $a.label, (& $c $a.on)) }
        'optionalFeature' { return ('Optional feature {0} = {1}; default {2}' -f (& $c $a.feature), (& $c $a.on), (& $c $a.default)) }
        'custom' {
            $map = @{
                UltimatePlan      = 'Duplicate {0} (or reuse an existing Ultimate copy) and activate it; revert re-activates the previous plan and deletes only a copy iG Windows Tuner created' -f (& $c 'e9a42b02-d5df-448d-aa00-03f14749eb61')
                Hibernate         = '{0}; revert {1} if it was enabled' -f (& $c 'powercfg /hibernate off'), (& $c '/hibernate on')
                TcpAutoTuning     = '{0} if not Normal; revert restores the previous level' -f (& $c 'Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal')
                FirewallProfiles  = '{0}; revert restores each profile' -f (& $c 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block')
                WifiAdapter       = '{0} for physical Wi-Fi adapters that are not connected; revert re-enables them' -f (& $c 'Disable-NetAdapter')
                GameGpuPreference = 'Merge {0} into {1} for detected games' -f (& $c 'GpuPreference=2'), (& $c 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences\<game exe path>')
                CfaAllowGames     = '{0} for detected games; revert removes only what was added' -f (& $c 'Add-MpPreference -ControlledFolderAccessAllowedApplications <game exe>')
            }
            return $map[[string]$a.handler]
        }
        'check' {
            if ($a.checker -eq 'DefaultApp') { return ('Reads the default app for {0} (expects {1}); change it in Settings > Apps > Default apps' -f (& $c "$($a.extension)$($a.protocol)"), (& $c $a.progId)) }
            return ('Verifies at runtime: {0} (Win32_DeviceGuard)' -f (& $c $a.checker))
        }
        { $_ -in 'storageSense', 'wufbPolicy' } {
            $parts = @(& (Get-Module iGWindowsTuner) { param($x) Get-IgwtCompositeParts -Action $x } $a)
            return (@($parts | ForEach-Object { 'Policy {0} = {1} ({2}); Windows default {3}' -f (& $c "$($_.Action.path)\$($_.Action.name)"), (& $c $_.Action.on), $_.Action.valueType, (& $c $_.Action.default) }) -join '; ')
        }
        'serviceSet' { return ('Services {0} startup type {1}; Windows defaults {2}' -f (@($a.services | ForEach-Object { & $c $_.name }) -join ', '), (@($a.services | ForEach-Object { $_.startupType } | Select-Object -Unique) -join '/'), (@($a.services | ForEach-Object { "$($_.name)=$($_.default)" }) -join ', ')) }
        'deviceInterrupt' {
            $set = @('msiSupported', 'messageNumberLimit', 'devicePolicy', 'devicePriority' | Where-Object { $null -ne $a.$_ } | ForEach-Object { "$_=$($a.$_)" })
            return ('Interrupt settings {0} of present PCI {1} devices (Interrupt Management registry keys); the driver default is restored from the snapshot' -f ($set -join ', '), $a.deviceClass)
        }
        'powercfgAttribute' { return ('Power setting {0} {1} in Power Options (powercfg -attributes); default {2}' -f (& $c "$($a.subgroup)/$($a.setting)"), $(if ($a.visible) { 'shown' } else { 'hidden' }), $a.default) }
        'powercfgSettingAcDc' { return ('Active plan: {0} ({1} / {2}) AC = {3}, DC = {4}' -f $a.label, (& $c $a.subgroup), (& $c $a.setting), (& $c $a.ac), (& $c $a.dc)) }
        'scheduledTask' { return ('Scheduled task {0} {1}; Windows default {2}' -f (& $c "$($a.path)$($a.name)"), $a.on, $a.default) }
        'firewallRule' {
            if ($a.rule) { return ('Windows Firewall block rule {0} ({1}{2}{3}) in group iG Windows Tuner; revert removes it' -f (& $c $a.rule), $a.direction, $(if ($a.protocol) { " $($a.protocol)" }), $(if ($a.localPort) { " port $($a.localPort)" })) }
            return ('Disables the Windows Firewall rule group {0}{1}; revert restores each rule' -f (& $c $a.displayGroup), $(if ($a.direction) { " ($($a.direction))" }))
        }
        'appx' { return ('Removes app {0} for the current user{1}; revert re-registers it or reinstalls it from the Store' -f (& $c $a.package), $(if ($a.provisioned) { ' and its provisioned copy' })) }
        'winget' { return ('winget package {0} {1} (source {2})' -f (& $c $a.id), $a.on, $(if ($a.source) { $a.source } else { 'winget' })) }
        'capability' { return ('Windows capability {0} {1}; default {2}' -f (& $c $a.name), $a.on, $a.default) }
        'processMitigation' { return ('Exploit protection {0} = {1} for {2}; default not set' -f (& $c $a.mitigation), $a.on, (& $c $a.process)) }
        'exploitSystem' { return ('System-wide exploit protection {0} = {1}; default not set' -f (& $c $a.mitigation), $a.on) }
        'cleanerRule' { return ('Runs cleaner rule {0} (scan, then clean only what the scan found); deleted files cannot be restored' -f (& $c $a.rule)) }
    }
}
# ------------------------------------------------------------------ TWEAKS.md
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# iG Windows Tuner tweak catalog$nl$nl")
$null = $sb.Append("> Generated by ``tools\Build-Docs.ps1`` from ``data\tweaks\*.json``. Do not edit by hand.$nl$nl")
$null = $sb.Append("$($catalog.Count) tweaks: $(@($catalog | Where-Object { $_.evidence.tier -eq 'A' }).Count) Tier A (documented by Microsoft or the vendor), $(@($catalog | Where-Object { $_.evidence.tier -eq 'B' }).Count) Tier B (situational; measure before and after). Presets: C = Competitive, B = Balanced, H = Hardened.$nl$nl")
$null = $sb.Append("Levels: $(@('Standard', 'Advanced', 'Expert', 'Lab' | ForEach-Object { $lv = $_; "$(@($catalog | Where-Object { $_.level -eq $lv }).Count) $lv" }) -join ', '). Standard is for everyone; Advanced is for power users; Expert needs an acknowledgement; Lab items knowingly break something (anti-cheat, a security feature) and are never in a preset.$nl$nl")
$null = $sb.Append("| Category | Tier A | Tier B | Total |$nl|---|---|---|---|$nl")
foreach ($c in $categories) {
    $in = @($catalog | Where-Object { $_.category -eq $c })
    $null = $sb.Append("| $c | $(@($in | Where-Object { $_.evidence.tier -eq 'A' }).Count) | $(@($in | Where-Object { $_.evidence.tier -eq 'B' }).Count) | $($in.Count) |$nl")
}
$null = $sb.Append($nl)
foreach ($c in $categories) {
    $null = $sb.Append("## $c$nl$nl| Id | Name | Level | Tier | Risk | Restart | Presets | Anti-cheat |$nl|---|---|---|---|---|---|---|---|$nl")
    foreach ($t in ($catalog | Where-Object { $_.category -eq $c })) {
        $p = (@($presets | Where-Object { $_.tweaks -contains $t.id } | ForEach-Object { $_.name.Substring(0, 1) }) -join '')
        if (-not $p) { $p = '-' }
        $null = $sb.Append("| ``$($t.id)`` | $(ConvertTo-MdCell $t.name) | $($t.level) | $($t.evidence.tier) | $($t.risk) | $($t.requires) | $p | $(if ($t.antiCheatSafe) { 'safe' } else { "**$($t.antiCheatText)**" }) |$nl")
    }
    $null = $sb.Append($nl)
    foreach ($t in ($catalog | Where-Object { $_.category -eq $c })) {
        $null = $sb.Append("### $($t.name)$nl$nl")
        $null = $sb.Append("``$($t.id)`` | $($t.level) | Tier $($t.evidence.tier) | risk $($t.risk) | restart: $($t.requires) | $($t.antiCheatText) | reversible: $($t.reversible) | impact: performance $($t.impact.performance), latency $($t.impact.latency), security $($t.impact.security)$nl$nl")
        if ($t.sideEffects) { $null = $sb.Append("**Side effects:** $($t.sideEffects)$nl$nl") }
        if ($t.warning) { $null = $sb.Append("> **Warning:** $($t.warning)$nl$nl") }
        $null = $sb.Append("*$($t.hint)*$nl$nl$($t.description)$nl$nl**Changes**$nl$nl")
        foreach ($a in $t.actions) { $null = $sb.Append("- $(Format-DocAction $a)$nl") }
        $null = $sb.Append("$nl**Sources**$nl$nl")
        foreach ($s in $t.evidence.sources) { $null = $sb.Append("- <$s>$nl") }
        if ($t.evidence.notes) { $null = $sb.Append("$nl*Evidence notes:* $($t.evidence.notes)$nl") }
        $null = $sb.Append("$nl**Revert:** $(Get-IgwtTweakRevertDescription -Tweak $t)$nl$nl")
    }
}
$tweaksPath = Join-Path $docs 'TWEAKS.md'
if ($PSCmdlet.ShouldProcess($tweaksPath, 'Write')) { [System.IO.File]::WriteAllText($tweaksPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

# ------------------------------------------------------------------ PRESETS.md
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# iG Windows Tuner presets$nl$nl> Generated by ``tools\Build-Docs.ps1`` from ``data\presets\*.json``. Do not edit by hand.$nl$nl")
$null = $sb.Append("Choosing a preset stages only the tweaks whose current state differs; you can untick items before applying. Expert toggles and anything that is not anti-cheat safe are never part of a preset.$nl$nl")
$null = $sb.Append("| Preset | Tweaks | Tier A | Tier B | Needs reboot | Needs sign-out |$nl|---|---|---|---|---|---|$nl")
foreach ($p in $presets) {
    $m = @($catalog | Where-Object { $p.tweaks -contains $_.id })
    $null = $sb.Append("| $($p.name) | $($m.Count) | $(@($m | Where-Object { $_.evidence.tier -eq 'A' }).Count) | $(@($m | Where-Object { $_.evidence.tier -eq 'B' }).Count) | $(@($m | Where-Object { $_.requires -eq 'reboot' }).Count) | $(@($m | Where-Object { $_.requires -eq 'logoff' }).Count) |$nl")
}
foreach ($p in $presets) {
    $null = $sb.Append("$nl## $($p.name): $($p.tagline)$nl$nl*$($p.hint)*$nl$nl$($p.description)$nl$nl")
    $null = $sb.Append("Level ceiling: $($p.levelCeiling) | anti-cheat policy: $($p.antiCheatPolicy) | gaming preset: $(if ($p.gaming) { 'yes' } else { 'no' })$(if (@($p.exclude).Count) { " | excluded: $(@($p.exclude) -join ', ')" })$nl$nl")
    $null = $sb.Append("| Id | Name | Category | Level | Tier | Restart |$nl|---|---|---|---|---|---|$nl")
    foreach ($id in $p.tweaks) {
        $t = $catalog | Where-Object { $_.id -eq $id }
        $null = $sb.Append("| ``$id`` | $(ConvertTo-MdCell $t.name) | $($t.category) | $($t.level) | $($t.evidence.tier) | $($t.requires) |$nl")
    }
}
$c = ($presets | Where-Object id -EQ 'competitive').tweaks; $b = ($presets | Where-Object id -EQ 'balanced').tweaks; $h = ($presets | Where-Object id -EQ 'hardened').tweaks
$null = $sb.Append("$nl## Differences$nl$nl")
$null = $sb.Append("- Only in Competitive: $(@($c | Where-Object { $b -notcontains $_ -and $h -notcontains $_ } | ForEach-Object { Format-Code $_ }) -join ', ')$nl")
$null = $sb.Append("- Only in Hardened: $(@($h | Where-Object { $b -notcontains $_ -and $c -notcontains $_ } | ForEach-Object { Format-Code $_ }) -join ', ')$nl")
$null = $sb.Append("- In Balanced but not Competitive: $(@($b | Where-Object { $c -notcontains $_ } | ForEach-Object { Format-Code $_ }) -join ', ')$nl")
$presetsPath = Join-Path $docs 'PRESETS.md'
if ($PSCmdlet.ShouldProcess($presetsPath, 'Write')) { [System.IO.File]::WriteAllText($presetsPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

# ------------------------------------------------------------------ REJECTED_TWEAKS.md
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# Rejected tweaks$nl$nl> Generated by ``tools\Build-Docs.ps1`` from ``data\rejected.json``. Do not edit by hand.$nl$nl")
$null = $sb.Append("These popular tweaks are deliberately **not implemented**. Each is placebo, obsolete, unstable, security-reducing or hostile to kernel anti-cheat. The only exception is the warned expert toggle ``sec.vbs-hvci-off-expert``, which is never part of a preset.$nl$nl")
$null = $sb.Append("| Tweak | Category | Why not |$nl|---|---|---|$nl")
foreach ($r in $rejected) { $null = $sb.Append("| $(ConvertTo-MdCell $r.name) | $($r.category) | $(ConvertTo-MdCell $r.reason) |$nl") }
$null = $sb.Append($nl)
foreach ($r in $rejected) {
    $null = $sb.Append("## $($r.name)$nl$nl- **Claim:** $($r.claim)$nl- **Category:** $($r.category)$nl- **Reason:** $($r.reason)$nl")
    if (@($r.sources).Count) { $null = $sb.Append("- **Sources:** $(@($r.sources | ForEach-Object { "<$_>" }) -join ' ')$nl") }
    $null = $sb.Append($nl)
}
$rejPath = Join-Path $docs 'REJECTED_TWEAKS.md'
if ($PSCmdlet.ShouldProcess($rejPath, 'Write')) { [System.IO.File]::WriteAllText($rejPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

# ------------------------------------------------------------------ CLEANER.md
$rules = @(Get-IgwtCleanerRules -Force)
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# iG Windows Tuner cleaner rules$nl$nl> Generated by ``tools\Build-Docs.ps1`` from ``data\cleaner\*.json``. Do not edit by hand.$nl$nl")
$null = $sb.Append("$($rules.Count) allow-list rules. Every rule names the folders it may clean; nothing outside them is ever touched. The cleaner always scans first (read-only) and then deletes only the files that scan found, re-checking each file right before it is deleted.$nl$nl")
$null = $sb.Append("## Safety model$nl$nl")
foreach ($line in @(
        'Allow-list only: a file is deleted only if its canonical path lies strictly inside one of the rule''s roots, and the roots are resolved again at clean time.',
        'Paths are canonicalized (`..`, 8.3 short names) before any check; relative, UNC and device paths are refused.',
        'A hard denylist in the deletion primitive protects drive roots, Windows (except Temp, the update download cache, CBS/DISM logs and crash dumps), Program Files (except the Steam shader cache, logs and dumps), ProgramData roots, Defender folders, profile roots, Documents, Desktop, Pictures, Music, Videos, Saved Games, OneDrive and the Downloads folder (opt-in rule only).',
        'Browser profiles: only cache folders (Cache, Code Cache, GPU and shader caches, cache2) are cleaned. Cookies, history, passwords and extensions are never touched.',
        'Junctions, symbolic links and mount points are never followed or deleted; each file''s parent chain is re-checked for reparse points right before deletion.',
        'Cloud placeholders and offline files are skipped, so cleaning never triggers a download.',
        'Files that changed since the scan, are younger than the rule''s minimum age, are in use, or are read-only are skipped.',
        'Only single files and empty folders are deleted; there is no recursive delete. Apps are never closed (rules that need an app closed are skipped while it runs). Services are stopped only for rules that declare them and are always restarted.',
        'Every deleted path is written to `Logs\Cleaner-<time>.jsonl`.'
    )) { $null = $sb.Append("- $line$nl") }
$null = $sb.Append("$nl| Category | Rules | On by default |$nl|---|---|---|$nl")
$cleanerCategories = @('System', 'Gaming', 'Browsers', 'Apps', 'Developer', 'Downloads')
foreach ($cat in $cleanerCategories) {
    $in = @($rules | Where-Object { $_.category -eq $cat })
    $null = $sb.Append("| $cat | $($in.Count) | $(@($in | Where-Object { $_.default }).Count) |$nl")
}
foreach ($cat in $cleanerCategories) {
    $null = $sb.Append("$nl## $cat$nl$nl| Id | Name | Level | Default | Method | Admin | Close first |$nl|---|---|---|---|---|---|---|$nl")
    foreach ($r in ($rules | Where-Object { $_.category -eq $cat })) {
        $null = $sb.Append("| ``$($r.id)`` | $(ConvertTo-MdCell $r.name) | $($r.level) | $(if ($r.default) { 'yes' } else { 'no' }) | $($r.method) | $(if ($r.requiresAdmin) { 'yes' } else { '-' }) | $(if (@($r.requiresClosed).Count) { (@($r.requiresClosed) -join ', ') } else { '-' }) |$nl")
    }
    foreach ($r in ($rules | Where-Object { $_.category -eq $cat })) {
        $null = $sb.Append("$nl### $($r.name)$nl$nl``$($r.id)`` | $($r.level) | Tier $($r.tier) | method $($r.method) | reversible: $($r.reversible)$nl$nl*$($r.hint)*$nl$nl$($r.description)$nl")
        if ($r.sideEffects) { $null = $sb.Append("$nl**Side effects:** $($r.sideEffects)$nl") }
        $where = @()
        if ($r.method -eq 'browserCache') { $where = @($r.userDataRoots | ForEach-Object { "$_ (profiles: $(@($r.profileCacheDirs) -join ', '); root: $(if (@($r.rootCacheDirs).Count) { @($r.rootCacheDirs) -join ', ' } else { '-' }))" }) }
        else { $where = @($r.roots) }
        if ($where.Count) {
            $null = $sb.Append("$nl**Folders:**$nl$nl")
            foreach ($w in $where) { $null = $sb.Append("- ``$w``$nl") }
        }
        $filters = @()
        if ([double]$r.minAgeHours -gt 0) { $filters += "older than $($r.minAgeHours) h" }
        if (@($r.include | Where-Object { $_ -ne '*' }).Count) { $filters += "only $(@($r.include) -join ', ')" }
        if (@($r.exclude).Count) { $filters += "never $(@($r.exclude) -join ', ')" }
        if ([int]$r.keepNewest -gt 0) { $filters += "keeps the newest $($r.keepNewest)" }
        if ($r.recycle) { $filters += 'to the Recycle Bin' }
        if (@($r.services).Count) { $filters += "stops and restarts $(@($r.services) -join ', ')" }
        if ($filters.Count) { $null = $sb.Append("$nl**Filters:** $($filters -join '; ').$nl") }
        if ($r.notes) { $null = $sb.Append("$nl*Note:* $($r.notes)$nl") }
        if (@($r.sources).Count) { $null = $sb.Append("$nl**Sources:** $(@($r.sources | ForEach-Object { "<$_>" }) -join ' ')$nl") }
    }
}
$cleanerPath = Join-Path $docs 'CLEANER.md'
if ($PSCmdlet.ShouldProcess($cleanerPath, 'Write')) { [System.IO.File]::WriteAllText($cleanerPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

# ------------------------------------------------------------------ HARDWARE.md
$tagDefs = @(Get-IgwtHardwareTagDefinitions -Force)
$detection = @(& (Get-Module iGWindowsTuner) { Get-IgwtDetectionRules -Force })
$overlays = @(Get-IgwtHardwareOverlays -Force)
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# iG Windows Tuner hardware profile and overlays$nl$nl> Generated by ``tools\Build-Docs.ps1`` from ``data\hardware\*.json``. Do not edit by hand.$nl$nl")
$null = $sb.Append("iG Windows Tuner detects hardware tags read-only (``.\iGWindowsTuner.ps1 -Hardware``) and applies hardware overlays. Presets are resolved in this order: **intent preset, then hardware overlays, then your own add-ons and removals**. An overlay can block items (they become Not applicable on that hardware; an item that is already applied can still be turned off), add items to presets (only when the preset's level ceiling and anti-cheat policy allow it, and never when the preset excludes them) and show guidance in the report and in preset dry runs.$nl$nl")
$null = $sb.Append("## Hardware tags$nl$nl| Tag | Name | Detected when | Meaning |$nl|---|---|---|---|$nl")
foreach ($t in $tagDefs) {
    $rules = @($detection | Where-Object { $_.tag -eq $t.id })
    $basis = (@($rules | ForEach-Object { $_.basis }) -join ' ')
    $null = $sb.Append("| ``$($t.id)`` | $(ConvertTo-MdCell $t.name) | $(ConvertTo-MdCell $basis) | $(ConvertTo-MdCell $t.hint) |$nl")
}
$null = $sb.Append("$nl## Overlays$nl")
foreach ($o in $overlays) {
    $null = $sb.Append("$nl### $($o.name)$nl$nl``$($o.id)`` | tags: $(@($o.tags | ForEach-Object { Format-Code $_ }) -join ', ') | basis: $($o.basis)$nl$nl*$($o.hint)*$nl$nl$($o.description)$nl$nl")
    $effects = @()
    if (@($o.block | Where-Object { $_ }).Count) { $effects += "Blocks: $(@($o.block | ForEach-Object { Format-Code $_ }) -join ', ')" }
    foreach ($m in @($o.blockMatching | Where-Object { $_ })) {
        $parts = @($m.PSObject.Properties | ForEach-Object { "$($_.Name) = $(@($_.Value) -join ' / ')" })
        $effects += "Blocks any item with an action where $($parts -join '; ')"
    }
    if (@($o.add | Where-Object { $_ }).Count) { $effects += "Adds to presets: $(@($o.add | ForEach-Object { Format-Code $_ }) -join ', ')" }
    foreach ($g in @($o.guidance | Where-Object { $_ })) { $effects += "Guidance: $g" }
    foreach ($e in $effects) { $null = $sb.Append("- $e$nl") }
    $null = $sb.Append("$nl**Sources:** $(@($o.sources | ForEach-Object { "<$_>" }) -join ' ')$nl")
}
$null = $sb.Append("$nl## Basis$nl$nl- **vendor**: documented by the hardware or OS vendor.$nl- **reviewer**: the vendor's guidance as published in reviewer guides and reviews (no public vendor support page found; see ``docs\DECISIONS.md``).$nl- **igwt**: a conservative iG Windows Tuner rule that keeps the Windows default on this hardware.$nl")
$hardwarePath = Join-Path $docs 'HARDWARE.md'
if ($PSCmdlet.ShouldProcess($hardwarePath, 'Write')) { [System.IO.File]::WriteAllText($hardwarePath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

# ------------------------------------------------------------------ ASR_CENTER.md
$asrRules = @(Get-IgwtAsrCatalog -Force)
$checks = @(Get-IgwtSecurityCheckDefinitions)
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# ASR Center and security score$nl$nl> Generated by ``tools\Build-Docs.ps1`` from ``data\asr\rules.json`` and ``src\Security\SecurityScore.ps1``. Do not edit by hand.$nl$nl")
$null = $sb.Append("Microsoft Defender attack surface reduction (ASR) rules block behaviors malware relies on. The ASR Center (GUI page, ``-Asr``, ``-AsrAudit``) shows every rule with its mode, what it means for games, launchers and mods, and the exclusions that apply to it. Modes iG Windows Tuner can set: Not configured (Windows default), Audit, Warn (where supported) and Block. It never writes an explicit Off and never changes server-only rules or rules managed by Group Policy or MDM. Every change writes a snapshot first and can be reverted from Backups & Logs or with ``-RevertAll -Snapshot <file>``.$nl$nl")
$null = $sb.Append("Recommended modes for a gaming PC: the three standard protection rules and the rules without gamer impact in Block; rules that can catch games, launchers or mods in Audit, so you can review the audit view first. ``-AsrRecommended`` only ever raises a rule.$nl$nl")
$null = $sb.Append("| Rule | Key | Category | Gamer impact | Recommended | Warn | Notes |$nl|---|---|---|---|---|---|---|$nl")
foreach ($r in $asrRules) {
    $notes = @()
    if ($r.requiresCloud) { $notes += 'needs cloud protection' }
    if ($r.serverOnly) { $notes += 'Exchange servers only' }
    if ($r.appliesTo -eq 'office') { $notes += 'Office' } elseif ($r.appliesTo -eq 'adobe') { $notes += 'Adobe Reader' }
    $null = $sb.Append("| $(ConvertTo-MdCell $r.name) | $(Format-Code $r.key) | $(if ($r.category -eq 'standard') { 'Standard protection' } else { ConvertTo-MdCell $r.msCategory }) | $($r.gamerImpactLevel) | $($r.recommendedMode) | $(if ($r.supportsWarn) { 'yes' } else { 'no' }) | $(ConvertTo-MdCell ($notes -join ', ')) |$nl")
}
$null = $sb.Append("$nl## Rules$nl")
foreach ($r in $asrRules) {
    $null = $sb.Append("$nl### $($r.name)$nl$nl")
    $null = $sb.Append("$(Format-Code ([string]$r.id)) | key $(Format-Code $r.key)$nl$nl$($r.description)$nl$nl")
    $null = $sb.Append("- **Gamer impact ($($r.gamerImpactLevel)):** $($r.gamerImpact)$nl")
    if ($r.notes) { $null = $sb.Append("- **Notes:** $($r.notes)$nl") }
    $null = $sb.Append("- **Source:** $(@($r.sources | ForEach-Object { "<$_>" }) -join ' ')$nl")
}
$null = $sb.Append("$nl## Exclusions$nl$nl")
$null = $sb.Append("- **Per-rule exclusions** (recommended) are written to the documented Group Policy registry settings: ``HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyPerRuleExclusions`` (value name = rule GUID, data = paths separated by ``>``) plus the policy switch ``ExploitGuard_ASR_ASROnlyPerRuleExclusions = 1``. When iG Windows Tuner runs as administrator it confirms through ``Get-MpPreference`` that Defender picked them up.$nl")
$null = $sb.Append("- **Global ASR exclusions** use ``Add-MpPreference -AttackSurfaceReductionOnlyExclusions`` and apply to every rule.$nl")
$null = $sb.Append("- Refused: drive roots, the Windows folder, the whole Program Files folders, folders or wildcards inside user profiles and ProgramData, Downloads, Desktop, browser cache and temp folders, user environment variables, relative segments, quotes and the ``>`` separator. Folder exclusions must be at least two levels deep. Exclude the program file itself whenever possible.$nl")
$null = $sb.Append("- Defender applies exclusions when a program starts; restart the program after adding one. Antivirus scan exclusions are never added.$nl")
$null = $sb.Append("$nl## Audit view$nl$nl``-AsrAudit [-Days N]`` and the GUI read the Defender Operational log (read-only): ASR 1121 (block), 1122 (audit), 1129 (Warn bypass); controlled folder access 1123/1127 (block), 1124/1128 (audit); network protection 1125 (audit), 1126 (block); 5007 (configuration change). Events are grouped by rule and program, with a next step: promote a quiet Audit rule (after at least 7 days of log coverage), add a per-rule exclusion for a trusted program's exact file, or ignore expected LSASS noise from Windows components.$nl")
$null = $sb.Append("$nl## Security score$nl$nl``-SecurityScore``, ``-Report`` and the dashboard. Pass earns the weight, Warn half, Fail nothing; not applicable, managed and unreadable checks are left out. Grades: Strong 90+, Good 75+, Fair 50+, Weak below.$nl$nl")
$null = $sb.Append("| Check | Weight | Fix | Hint |$nl|---|---|---|---|$nl")
foreach ($c in $checks) {
    $fix = switch ($c.Fix) { 'Tweak' { Format-Code $c.Target } 'AsrCenter' { 'ASR Center' } 'None' { '-' } default { ConvertTo-MdCell $c.Target } }
    $null = $sb.Append("| $(ConvertTo-MdCell $c.Name) | $(if ([int]$c.Weight) { $c.Weight } else { 'info' }) | $fix | $(ConvertTo-MdCell $c.Hint) |$nl")
}
$asrPath = Join-Path $docs 'ASR_CENTER.md'
if ($PSCmdlet.ShouldProcess($asrPath, 'Write')) { [System.IO.File]::WriteAllText($asrPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

# ------------------------------------------------------------------ INSPECTORS.md
$powerSettings = @(Get-IgwtPowerSettingCatalog -Force)
$kernelKeys = @(& (Get-Module iGWindowsTuner) { Get-IgwtKernelInspectorCatalog -Force })
$sb = New-Object System.Text.StringBuilder
$null = $sb.Append("# Expert inspectors and the power plan editor$nl$nl> Generated by ``tools\Build-Docs.ps1`` from ``data\power\processor.json`` and ``data\inspectors\kernel.json``. Do not edit by hand.$nl$nl")
$null = $sb.Append("Read-only inspectors (GUI page *Expert Inspectors*, ``-Inspect All|Power|Interrupts|Network|Kernel|Timer|Crash``) show the settings engineers tune next to the Windows default. Only the processor power settings below can be edited here, with a snapshot first (``-PowerSetting <alias> -Ac <n> [-Dc <n>] -AcknowledgeRisk``, ``-DryRun`` to validate); everything else changes only through catalog items.$nl$nl")
$null = $sb.Append("## Power plan editor$nl$nl- Values are checked against the range ``powercfg /qh`` reports for the active plan.$nl- Hardware overlays apply: on Intel hybrid CPUs core parking and hybrid scheduling settings are blocked; on AMD dual-CCD X3D CPUs core parking is blocked; on laptops battery (DC) values are blocked.$nl- Processor idle disable is never editable (see ``rejected.processor-idle-disable``).$nl- Defaults come from Windows' stored plan defaults; a plan copy is compared with the built-in plan it came from; Ultimate Performance has no stored defaults, so Balanced is shown as a labelled reference.$nl$nl")
$null = $sb.Append("| Alias | Group | Level | Hint | Source |$nl|---|---|---|---|---|$nl")
foreach ($s in $powerSettings) { $null = $sb.Append("| $(Format-Code $s.alias) | $(ConvertTo-MdCell $s.group) | $($s.level) | $(ConvertTo-MdCell $s.hint) | $(@($s.sources | ForEach-Object { "<$_>" }) -join ' ') |$nl") }
$null = $sb.Append("$nl## Kernel and memory inspector$nl$nlEvery value under these keys is listed; documented ones show their meaning and Windows default. Values linked to a catalog item can be changed only through that item; values linked to a rejected entry are explained and never changed.$nl")
foreach ($k in $kernelKeys) {
    $null = $sb.Append("$nl### $($k.name)$nl$nl$(Format-Code ([string]$k.path))$nl$nl$($k.description)$nl$nl| Value | Windows default | Meaning | Link |$nl|---|---|---|---|$nl")
    foreach ($v in @($k.values)) {
        $default = $(if ([string]$v.default -eq '<absent>') { 'not set' } else { @($v.default) -join '; ' })
        $link = $(if ($v.item) { Format-Code $v.item } elseif ($v.rejected) { Format-Code $v.rejected } else { '' })
        $null = $sb.Append("| $(Format-Code $v.name) | $(ConvertTo-MdCell $default) | $(ConvertTo-MdCell $v.meaning) | $link |$nl")
    }
}
$null = $sb.Append("$nl## Other inspectors$nl$nl- **Interrupts:** PCI devices with supported interrupt types (line, MSI, MSI-X), the mode in use (from the allocated interrupt resources), MSISupported / MessageNumberLimit, affinity policy, priority and target CPUs. Changes only through ``gfx.gpu-msi`` (GPU, Expert, reboot); manual affinity pinning is rejected.$nl- **Network queues:** RSS state, base and max processor, queues, receive and transmit buffers with the driver's range, and discarded-packet counters; advice is based on that evidence.$nl- **Timer:** GlobalTimerResolutionRequests behaviour (catalog item ``sched.global-timer-resolution``). The current timer resolution is not shown because reading it needs an undocumented native call; ``powercfg /energy`` (administrator) lists timer requests.$nl- **Crash and page file:** dump type, dump files on disk, stop screen and verbose status settings, page file configuration and usage, with the System catalog items that change them.$nl")
$inspectorsPath = Join-Path $docs 'INSPECTORS.md'
if ($PSCmdlet.ShouldProcess($inspectorsPath, 'Write')) { [System.IO.File]::WriteAllText($inspectorsPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false))) }

Write-Output "Generated: $tweaksPath, $presetsPath, $rejPath, $cleanerPath, $hardwarePath, $asrPath, $inspectorsPath"
