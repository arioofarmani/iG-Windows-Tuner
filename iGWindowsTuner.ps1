<#
.SYNOPSIS
    iG Windows Tuner - auditable Windows 11 gaming performance and security toolbox.

.DESCRIPTION
    Tunes Windows 11 Pro for competitive online gaming while keeping or raising security and
    staying compatible with kernel anti-cheat. Every change is declared in data\tweaks\*.json,
    shown before it is applied, snapshotted to %ProgramData%\iGWindowsTuner\Backups and reversible.

    Without parameters the WPF GUI starts. Read-only modes (-Report, -ListTweaks, -DryRun) never
    change anything and do not need elevation. Modes that change the system relaunch through the
    normal UAC prompt when needed.

.PARAMETER Report
    Read-only health and anti-cheat readiness report.
.PARAMETER ReportPath
    With -Report: also write the report to this .html or .json file.
.PARAMETER ListTweaks
    List every tweak with tier, risk, presets and current state.
.PARAMETER Preset
    Apply a preset by id or name: competitive, balanced, hardened, streamer, engineer, laptop,
    privacy-max, debloat, fortress, or a custom preset (custom-...). -ListPresets lists them. With
    -Drift, the preset to compare against. Session Mode is started with -Session Start instead.
.PARAMETER AddItem
    With -Preset or -SavePreset: items to add to the preset.
.PARAMETER RemoveItem
    With -Preset or -SavePreset: items to leave out.
.PARAMETER ListPresets
    Lists every preset (built-in and custom) with its item count and rules. Read-only.
.PARAMETER SavePreset
    Saves a custom preset with this name: -BasedOn <preset> plus -AddItem and minus -RemoveItem
    (without changes it duplicates the preset). The preset rules are checked first.
.PARAMETER BasedOn
    The preset a custom preset starts from (default balanced).
.PARAMETER ExportPreset
    Writes this preset to -PresetPath as JSON with a SHA256 integrity field.
.PARAMETER ImportPreset
    Imports a preset file (checked against its SHA256 field and the preset rules) as a custom preset.
.PARAMETER RemovePreset
    Deletes a custom preset.
.PARAMETER PresetPath
    File for -ExportPreset.
.PARAMETER Drift
    Drift report: which items of the last applied preset (or -Preset) changed since. Read-only.
.PARAMETER AdoptDrift
    Saves the drifted state as a custom preset with this name (the preset minus the changed items).
.PARAMETER Session
    Session Mode (Tournament/LAN): Start applies the temporary session items with a snapshot,
    Stop restores them, Status shows the session. -DryRun with Start shows the plan.
.PARAMETER Platform
    Read-only platform and management report: edition family, Local Group Policy support, domain
    and Entra ID join, MDM enrollment, Defender for Endpoint, other antivirus and whether policy
    items are report-only on this PC.
.PARAMETER AcknowledgeManaged
    On a domain-joined or MDM-enrolled PC, policy items are report-only. This switch confirms local
    changes that a domain or MDM policy may override (with -Apply or -Preset).
.PARAMETER Persona
    Sets your persona for the GUI (Gamer, PowerUser or Sysadmin): it changes the navigation order and
    which item levels are shown, never a safety rule.
.PARAMETER CloseApps
    With -Session Start: also close the running apps from the Session Mode list.
.PARAMETER Apply
    Apply the given tweak ids.
.PARAMETER Revert
    Revert the given tweak ids from their most recent apply.
.PARAMETER RevertAll
    Revert every tweak of the most recent apply, or of -Snapshot.
.PARAMETER Snapshot
    Snapshot file for -RevertAll.
.PARAMETER ResetDefault
    Reset the given tweak ids to the documented Windows defaults.
.PARAMETER DryRun
    Show exactly what would change and change nothing.
.PARAMETER NoGui
    Never start the GUI (prints help when no mode is given).
.PARAMETER SkipRestorePoint
    Do not create a System Restore point (the JSON snapshot is always written).
.PARAMETER EnableSystemProtection
    Consent to turn on System Protection for the system drive if a restore point cannot be created.
.PARAMETER AcknowledgeRisk
    Required to apply expert toggles (for example turning VBS/HVCI off).
.PARAMETER Json
    Machine-readable output for -Report, -ListTweaks, -DryRun, -Clean and -Analyze.
.PARAMETER Hardware
    Read-only hardware profile: detected hardware tags, the facts behind them and the hardware
    overlays that adjust presets on this PC. With -Json it prints the facts (usable as a test fixture).
.PARAMETER Clean
    Cleaning engine. With -Scan (or -DryRun) it only enumerates and sizes (read-only). Without it,
    it scans, shows the result and deletes only what the scan found after you type YES (or -Yes).
.PARAMETER Scan
    With -Clean: scan only; nothing is deleted.
.PARAMETER CleanRule
    With -Clean: rule ids to use (default: the rules that are on by default up to -CleanLevel).
.PARAMETER CleanLevel
    With -Clean: highest rule level to include (Standard, Advanced, Expert).
.PARAMETER IncludeOptIn
    With -Clean: include rules that are off by default.
.PARAMETER AllUsers
    With -Clean: expand per-user rules to every local profile (requires administrator rights).
.PARAMETER Yes
    With -Clean: skip the YES confirmation (needed with -Json).
.PARAMETER Analyze
    Read-only disk analyzer: largest folders and files under this folder or drive.
.PARAMETER Top
    With -Analyze: number of folders and files to list.
.PARAMETER Asr
    ASR Center. Alone it lists every attack surface reduction rule with its mode, recommendation,
    gamer impact and exclusions (read-only). With -AsrMode, -AsrRecommended, -AsrExclude or
    -AsrUnexclude it changes rules or exclusions after writing a snapshot (-DryRun shows the plan).
.PARAMETER AsrRule
    With -Asr: the rule (key such as 'psexec-wmi' or GUID) to show, set or exclude for.
.PARAMETER AsrMode
    With -Asr -AsrRule: NotConfigured, Audit, Warn or Block.
.PARAMETER AsrRecommended
    With -Asr: raise every rule that is below its recommended mode (never lowers a rule).
.PARAMETER AsrExclude
    With -Asr: paths to exclude. With -AsrRule only from that rule, otherwise from all ASR rules.
    Separate several paths with '|'.
.PARAMETER AsrUnexclude
    With -Asr: paths to remove from the same exclusion list.
.PARAMETER AsrAudit
    Read-only ASR audit view: ASR, controlled folder access and network protection events grouped
    by rule and program, with recommendations.
.PARAMETER Days
    With -AsrAudit: how many days of events to read (1-90, default 14).
.PARAMETER SecurityScore
    Read-only security score with the fix for every failed check, plus the local accounts audit.
.PARAMETER NetworkSurface
    Read-only listening-ports report: programs that accept connections and on which interfaces.
.PARAMETER Inspect
    Read-only expert inspectors: All, Power (processor power settings of the active plan, hidden
    ones included), Interrupts (PCI interrupt modes and affinity), Network (RSS, queues, buffers),
    Kernel (kernel and memory registry values with Windows defaults), Timer, Crash (dumps, page file).
.PARAMETER PowerSetting
    Power plan editor (Expert): the processor setting to change, by alias (for example PERFEPP).
    Use with -Ac, -Dc or -PowerDefault, and -AcknowledgeRisk. -DryRun validates and shows the change.
.PARAMETER Ac
    With -PowerSetting: new plugged-in value.
.PARAMETER Dc
    With -PowerSetting: new battery value.
.PARAMETER PowerDefault
    With -PowerSetting: return the setting to the Windows default of the plan.
.PARAMETER Inventory
    Read-only management views: Services (with the safe-to-change rating), Tasks, Apps, Features
    (administrator), Firewall (rule browser), Hosts (hosts-file viewer), Adapters (every advanced
    property with a description). Filter rows with -Search.
.PARAMETER Search
    With -Inventory: show only rows whose name, display name, path or program contains this text.
.PARAMETER Change
    Snapshot-backed management change: service, task, appx, feature, capability or firewallRule.
    Needs -Target and -Value; protected targets are refused. -DryRun validates and shows the change.
.PARAMETER Target
    With -Change: service name, full task path, package name, feature, capability or firewall rule name.
.PARAMETER Value
    With -Change: service Automatic/AutomaticDelayed/Manual/Disabled; task, feature and firewall rule
    Enabled/Disabled; appx Removed; capability Installed/NotPresent.
.PARAMETER Provisioned
    With -Change appx: also remove the provisioned copy (new user profiles do not get the app).
.PARAMETER Persistence
    Read-only Persistence Inspector (Autoruns-style) with signature status. -ReportPath exports it
    (.html or .json); -IncludeMicrosoft also lists Microsoft-signed services, drivers and tasks.
.PARAMETER IncludeMicrosoft
    With -Persistence: include Microsoft-signed entries (slower).
.PARAMETER Updates
    Read-only Windows Update status: services, pending restart, Windows Update for Business policies, history.
.PARAMETER Diagnostics
    Read-only diagnostics: All, DpcIsr, Reliability, Crashes, Boot, Drivers. -Days sets the history window.
.PARAMETER SystemReport
    Full read-only system report written to -ReportPath (.html or .json). -Quick skips the slow sections.
.PARAMETER Quick
    With -SystemReport: skip persistence signatures and DPC sampling.
.PARAMETER DnsBenchmark
    User-initiated DNS benchmark of the current DNS servers and public resolvers (uses the network, changes nothing).
.PARAMETER Latency
    User-initiated latency, jitter and loss test to the host names or IP addresses you give.
.PARAMETER NetworkTest
    Network quality test: latency, jitter, packet loss and stability to your router, ISP and the
    internet, path trace, path MTU, connection type guess and recommended Windows adjustments.
    Read-only (pings and DNS queries). -ReportPath saves an .html or .json report.
.PARAMETER Duration
    With -NetworkTest: Quick (10 s), Standard (30 s, default) or Extended (2 minutes).
.PARAMETER NetTarget
    With -NetworkTest: up to 4 extra hosts to measure, such as a game server.
.PARAMETER UnderLoad
    With -NetworkTest: after the idle test, measure 20 s of latency while you run a speed test or
    large download, and grade bufferbloat.
.PARAMETER RiskZone
    Lists every rejected tweak: the ones you can apply at your own risk (with warnings and what they
    turn off or on) and the ones that are not offered, with the reason. Read-only.
.PARAMETER Toolkit
    Lists a Toolkit section: Apps (curated winget packages with installed versions; -Quick skips
    the winget inventory), Features, Fixes (with their steps), Panels, Tweaks (WinUtil-derived
    items) or Updates (Windows Update items). -Search filters Apps. Read-only.
.PARAMETER Install
    winget package ids to install (from -Toolkit Apps or any valid id). Needs -AcceptAgreements
    the first time, after you have read the agreements that are printed.
.PARAMETER Uninstall
    winget package ids to uninstall.
.PARAMETER Upgrade
    winget package ids to upgrade.
.PARAMETER UpgradeAll
    Upgrades every package from the winget source (winget upgrade --all).
.PARAMETER AcceptAgreements
    You accept winget's package and source agreements (recorded for later installs).
.PARAMETER AppList
    An app selection file (exported from the GUI or with -ExportAppList) to use with -Install,
    -Uninstall or -Upgrade; its SHA256 field is checked.
.PARAMETER ExportAppList
    Writes the ids given with -AppId to an app selection file.
.PARAMETER AppId
    winget ids for -ExportAppList.
.PARAMETER Fix
    Runs a Toolkit fix (for example fix.sfc). -DryRun only shows its steps.
.PARAMETER OpenPanel
    Opens an inbox Windows tool from -Toolkit Panels (for example panel.device-manager).
.PARAMETER EnableFeature
    Enables a Toolkit feature (for example feature.wsl); snapshot-backed. -DryRun previews.
.PARAMETER DisableFeature
    Disables a Toolkit feature; features other tools depend on (WSL, Virtual Machine Platform and
    the .NET Framework 4) are never disabled. -DryRun previews.
.EXAMPLE
    .\iGWindowsTuner.ps1 -Report
.EXAMPLE
    .\iGWindowsTuner.ps1 -Preset Competitive -DryRun
.EXAMPLE
    .\iGWindowsTuner.ps1 -Apply input.pointer-precision-off,gfx.game-mode
.EXAMPLE
    .\iGWindowsTuner.ps1 -RevertAll
.EXAMPLE
    .\iGWindowsTuner.ps1 -Clean -Scan -CleanLevel Advanced -IncludeOptIn
.EXAMPLE
    .\iGWindowsTuner.ps1 -Clean -CleanRule clean.user.temp,clean.gaming.nvidia-shader
.EXAMPLE
    .\iGWindowsTuner.ps1 -Analyze C:\ -Top 30
.EXAMPLE
    .\iGWindowsTuner.ps1 -Asr -AsrRecommended -DryRun
.EXAMPLE
    .\iGWindowsTuner.ps1 -Asr -AsrRule copied-system-tools -AsrExclude "D:\Games\MyGame\MyGame.exe"
.EXAMPLE
    .\iGWindowsTuner.ps1 -AsrAudit -Days 30
.EXAMPLE
    .\iGWindowsTuner.ps1 -Inspect Power,Interrupts
.EXAMPLE
    .\iGWindowsTuner.ps1 -PowerSetting PERFEPP -Ac 20 -AcknowledgeRisk -DryRun
.EXAMPLE
    .\iGWindowsTuner.ps1 -Inventory Services -Search xbox
.EXAMPLE
    .\iGWindowsTuner.ps1 -Change service -Target XblGameSave -Value Manual -DryRun
.EXAMPLE
    .\iGWindowsTuner.ps1 -Persistence -ReportPath "$env:USERPROFILE\Desktop\persistence.html"
.EXAMPLE
    .\iGWindowsTuner.ps1 -Diagnostics Crashes,Drivers -Days 60
.EXAMPLE
    .\iGWindowsTuner.ps1 -SystemReport -ReportPath "$env:USERPROFILE\Desktop\system-report.html"
.EXAMPLE
    .\iGWindowsTuner.ps1 -Latency 1.1.1.1,valve.net
.EXAMPLE
    .\iGWindowsTuner.ps1 -NetworkTest -Duration Extended -ReportPath "$env:USERPROFILE\Desktop\network.html"
.EXAMPLE
    .\iGWindowsTuner.ps1 -RiskZone
.EXAMPLE
    .\iGWindowsTuner.ps1 -Apply risk.tcp-autotuning-disabled -AcknowledgeRisk -DryRun

.NOTES
    Exit codes: 0 success, 1 error, 2 invalid arguments or unknown tweak/rule id, 3 elevation declined,
    4 preflight refused (unsupported build, System Protection off), 5 one or more tweaks or cleaner
    rules failed, 6 nothing to revert, 3010 success and a reboot is required.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive CLI output with color; data is also available with -Json.')]
[CmdletBinding()]
param(
    [switch]$Report,
    [string]$ReportPath,
    [switch]$ListTweaks,
    [string]$Preset,
    [string[]]$AddItem,
    [string[]]$RemoveItem,
    [switch]$ListPresets,
    [string]$SavePreset,
    [string]$BasedOn,
    [string]$ExportPreset,
    [string]$ImportPreset,
    [string]$RemovePreset,
    [string]$PresetPath,
    [switch]$Drift,
    [string]$AdoptDrift,
    [ValidateSet('Start', 'Stop', 'Status')]
    [string]$Session,
    [switch]$CloseApps,
    [switch]$Platform,
    [switch]$AcknowledgeManaged,
    [ValidateSet('Gamer', 'PowerUser', 'Sysadmin')]
    [string]$Persona,
    [string[]]$Apply,
    [string[]]$Revert,
    [switch]$RevertAll,
    [string]$Snapshot,
    [string[]]$ResetDefault,
    [switch]$DryRun,
    [switch]$NoGui,
    [switch]$SkipRestorePoint,
    [switch]$EnableSystemProtection,
    [switch]$AcknowledgeRisk,
    [switch]$Json,
    [switch]$Hardware,
    [switch]$Clean,
    [switch]$Scan,
    [string[]]$CleanRule,
    [ValidateSet('Standard', 'Advanced', 'Expert')]
    [string]$CleanLevel = 'Standard',
    [switch]$IncludeOptIn,
    [switch]$AllUsers,
    [switch]$Yes,
    [string]$Analyze,
    [ValidateRange(1, 500)]
    [int]$Top = 25,
    [switch]$Asr,
    [string]$AsrRule,
    [ValidateSet('NotConfigured', 'Audit', 'Warn', 'Block')]
    [string]$AsrMode,
    [switch]$AsrRecommended,
    [string[]]$AsrExclude,
    [string[]]$AsrUnexclude,
    [switch]$AsrAudit,
    [ValidateRange(1, 365)]
    [int]$Days = 14,
    [switch]$SecurityScore,
    [switch]$NetworkSurface,
    [ValidateSet('All', 'Power', 'Interrupts', 'Network', 'Kernel', 'Timer', 'Crash')]
    [string[]]$Inspect,
    [string]$PowerSetting,
    [Nullable[long]]$Ac,
    [Nullable[long]]$Dc,
    [switch]$PowerDefault,
    [ValidateSet('Services', 'Tasks', 'Apps', 'Features', 'Firewall', 'Hosts', 'Adapters')]
    [string]$Inventory,
    [string]$Search,
    [ValidateSet('service', 'task', 'appx', 'feature', 'capability', 'firewallRule')]
    [string]$Change,
    [string]$Target,
    [string]$Value,
    [switch]$Provisioned,
    [switch]$Persistence,
    [switch]$IncludeMicrosoft,
    [switch]$Updates,
    [ValidateSet('All', 'DpcIsr', 'Reliability', 'Crashes', 'Boot', 'Drivers')]
    [string[]]$Diagnostics,
    [switch]$SystemReport,
    [switch]$Quick,
    [switch]$DnsBenchmark,
    [string[]]$Latency,
    [switch]$NetworkTest,
    [ValidateSet('Quick', 'Standard', 'Extended')]
    [string]$Duration = 'Standard',
    [string[]]$NetTarget,
    [switch]$UnderLoad,
    [switch]$RiskZone,
    [ValidateSet('Apps', 'Features', 'Fixes', 'Panels', 'Tweaks', 'Updates')]
    [string]$Toolkit,
    [string[]]$Install,
    [string[]]$Uninstall,
    [string[]]$Upgrade,
    [switch]$UpgradeAll,
    [switch]$AcceptAgreements,
    [string]$AppList,
    [string]$ExportAppList,
    [string[]]$AppId,
    [string]$Fix,
    [string]$OpenPanel,
    [string]$EnableFeature,
    [string]$DisableFeature,
    [switch]$ElevatedRelaunch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
Import-Module (Join-Path $PSScriptRoot 'src\iGWindowsTuner.psd1') -Force

function Write-IgwtCliLine {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host $Text -ForegroundColor $Color
}

function Split-IgwtIdList {
    param([string[]]$Value)
    return @($Value | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-IgwtStateColor {
    param([string]$State)
    switch ($State) {
        'On' { [ConsoleColor]::Green } 'Off' { [ConsoleColor]::Gray } 'Partial' { [ConsoleColor]::Yellow }
        'ManagedByPolicy' { [ConsoleColor]::Cyan } 'NotApplicable' { [ConsoleColor]::DarkGray } default { [ConsoleColor]::Yellow }
    }
}

function Write-IgwtPlan {
    param([object[]]$Plan, [string]$Title, $Selection)
    if ($Json) {
        if ($Selection) { [pscustomobject]@{ HardwareTags = $Selection.Tags; Overlays = $Selection.Overlays; Plan = $Plan } | ConvertTo-Json -Depth 8 } else { $Plan | ConvertTo-Json -Depth 6 }
        return
    }
    Write-IgwtCliLine ''
    Write-IgwtCliLine $Title ([ConsoleColor]::White)
    Write-IgwtCliLine ('=' * $Title.Length) ([ConsoleColor]::White)
    if ($Selection) {
        Write-IgwtCliLine ("Hardware tags: {0}" -f $(if (@($Selection.Tags).Count) { @($Selection.Tags) -join ', ' } else { '(none)' })) ([ConsoleColor]::Cyan)
        foreach ($o in $Selection.Overlays) {
            Write-IgwtCliLine ("Overlay: {0} [{1}]" -f $o.Name, (@($o.Tags) -join ', ')) ([ConsoleColor]::Cyan)
            foreach ($g in $o.Guidance) { Write-IgwtCliLine ("         -> {0}" -f $g) ([ConsoleColor]::DarkGray) }
        }
        foreach ($s in @($Selection.Items | Where-Object { -not $_.Included -and -not $_.Blocked })) {
            Write-IgwtCliLine ("[SKIP]   {0,-38} {1}" -f $s.Id, (@($s.Notes) -join ' ')) ([ConsoleColor]::DarkGray)
        }
        Write-IgwtCliLine ''
    }
    foreach ($p in $Plan) {
        $tag = switch ($p.Plan) { 'Change' { '[CHANGE]' } 'Skip' { '[OK]    ' } 'NotApplicable' { '[N/A]   ' } 'Policy' { '[POLICY]' } 'ReportOnly' { '[REPORT]' } default { "[$($p.Plan)]" } }
        $color = switch ($p.Plan) { 'Change' { [ConsoleColor]::Yellow } 'Skip' { [ConsoleColor]::Green } 'Policy' { [ConsoleColor]::Cyan } default { [ConsoleColor]::DarkGray } }
        $origin = ''
        if ($p.PSObject.Properties['Origin'] -and $p.Origin -and $p.Origin -ne 'preset') { $origin = "  [from $($p.Origin)]" }
        Write-IgwtCliLine ("{0} {1,-38} {2}  ({3}, Tier {4}, risk {5}{6}){7}" -f $tag, $p.Id, $p.Name, $p.Level, $p.Tier, $p.Risk, $(if ($p.Requires -ne 'none') { ", needs $($p.Requires)" } else { '' }), $origin) $color
        if ([string]$p.Tier -eq 'R') { Write-IgwtCliLine ("           RISK ZONE (rejected tweak, at your own risk): {0}" -f (Get-IgwtRiskZoneSummary -Tweak (Get-IgwtTweak -Id $p.Id))) ([ConsoleColor]::Red) }
        if ($p.PSObject.Properties['Notes']) {
            foreach ($n in @($p.Notes | Where-Object { $_ -and $_ -ne $p.Reason })) { Write-IgwtCliLine ("           {0}" -f $n) ([ConsoleColor]::Cyan) }
        }
        if ($p.Plan -eq 'Change') {
            foreach ($i in $p.Items) {
                Write-IgwtCliLine ("           {0}" -f $i.Target) ([ConsoleColor]::Gray)
                Write-IgwtCliLine ("             {0}  ->  {1}" -f $i.Current, $i.Desired) ([ConsoleColor]::White)
                if ($i.Note) { Write-IgwtCliLine ("             note: {0}" -f $i.Note) ([ConsoleColor]::DarkGray) }
            }
        } elseif ($p.Reason) {
            Write-IgwtCliLine ("           {0}" -f $p.Reason) ([ConsoleColor]::DarkGray)
        }
    }
    $change = @($Plan | Where-Object { $_.Plan -eq 'Change' })
    $reboot = @($change | Where-Object { $_.Requires -eq 'reboot' }).Count
    $logoff = @($change | Where-Object { $_.Requires -eq 'logoff' }).Count
    Write-IgwtCliLine ''
    Write-IgwtCliLine ("Summary: {0} to change, {1} already set, {2} not applicable, {3} managed by policy. After apply: {4}." -f `
            $change.Count, @($Plan | Where-Object { $_.Plan -eq 'Skip' }).Count, @($Plan | Where-Object { $_.Plan -eq 'NotApplicable' }).Count,
        @($Plan | Where-Object { $_.Plan -eq 'Policy' }).Count, $(if ($reboot) { "reboot ($reboot tweak(s))" } elseif ($logoff) { "sign out ($logoff tweak(s))" } else { 'no restart needed' })) ([ConsoleColor]::White)
}

function Write-IgwtResult {
    param($Result)
    if ($Json) { $Result | ConvertTo-Json -Depth 6; return }
    Write-IgwtCliLine ''
    foreach ($r in $Result.Results) {
        $color = switch ($r.Result) { 'Applied' { [ConsoleColor]::Green } 'Reverted' { [ConsoleColor]::Green } 'Failed' { [ConsoleColor]::Red } default { [ConsoleColor]::DarkGray } }
        Write-IgwtCliLine ("{0,-14} {1}  {2}" -f "[$($r.Result)]", $r.Id, $r.Message) $color
    }
    if ($Result.Snapshot) { Write-IgwtCliLine "Snapshot: $($Result.Snapshot)" ([ConsoleColor]::Gray) }
    if ($Result.PSObject.Properties['RestorePoint'] -and $Result.RestorePoint) {
        Write-IgwtCliLine ("Restore point: {0}" -f $(if ($Result.RestorePoint.Created) { 'created' } else { "not created ($($Result.RestorePoint.Reason))" })) ([ConsoleColor]::Gray)
    }
    if ($Result.Requires -eq 'reboot') { Write-IgwtCliLine 'A REBOOT is required for some changes to take effect.' ([ConsoleColor]::Yellow) }
    elseif ($Result.Requires -eq 'logoff') { Write-IgwtCliLine 'SIGN OUT and back in for some changes to take effect.' ([ConsoleColor]::Yellow) }
}

function Get-IgwtExitCode {
    param($Result)
    if (@($Result.Results | Where-Object { $_.Result -eq 'Failed' }).Count -gt 0) { return 5 }
    if ($Result.Requires -eq 'reboot') { return 3010 }
    return 0
}

function Complete-IgwtCli {
    param([int]$Code)
    if ($ElevatedRelaunch -and -not $Json) {
        Write-IgwtCliLine ''
        $null = Read-Host 'Press Enter to close this window'
    }
    exit $Code
}

function Request-IgwtCliElevation {
    <# Relaunches this script elevated (normal UAC prompt) with the same parameters and exits with its code. #>
    param([System.Collections.IDictionary]$Bound)
    Write-IgwtCliLine 'Administrator rights are required. Requesting elevation (UAC prompt)...' ([ConsoleColor]::Yellow)
    $pass = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Bound.Keys) {
        $v = $Bound[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $pass.Add("-$k") } }
        elseif ($v -is [array] -and $k -in 'AsrExclude', 'AsrUnexclude') { $pass.Add("-$k"); $pass.Add(($v -join '|')) }   # paths may contain commas
        elseif ($v -is [array]) { $pass.Add("-$k"); $pass.Add(($v -join ',')) }
        else { $pass.Add("-$k"); $pass.Add([string]$v) }
    }
    $pass.Add('-ElevatedRelaunch')
    $code = Start-IgwtElevated -ScriptPath $PSCommandPath -ArgumentList $pass.ToArray() -Wait
    if ($null -eq $code) { Write-IgwtCliLine 'Elevation was declined; nothing was changed.' ([ConsoleColor]::Red); exit 3 }
    exit $code
}

function Get-IgwtCleanerStatusColor {
    param([string]$Status)
    switch ($Status) {
        'Ready' { [ConsoleColor]::Yellow } 'Empty' { [ConsoleColor]::Green } 'Cleaned' { [ConsoleColor]::Green } 'Error' { [ConsoleColor]::Red }
        'RequiresClose' { [ConsoleColor]::Cyan } 'RequiresAdmin' { [ConsoleColor]::Cyan } default { [ConsoleColor]::DarkGray }
    }
}

function Write-IgwtCleanerScan {
    param($ScanResult)
    if ($Json) {
        $ScanResult.Rules | Select-Object RuleId, Name, Category, Level, Method, Status, Reason, Bytes, Count, Samples, Skipped, Blockers | ConvertTo-Json -Depth 5
        return
    }
    Write-IgwtCliLine ''
    Write-IgwtCliLine 'iG Windows Tuner cleaner scan (nothing has been deleted)' ([ConsoleColor]::White)
    Write-IgwtCliLine ('=' * 49) ([ConsoleColor]::White)
    foreach ($g in ($ScanResult.Rules | Group-Object Category)) {
        Write-IgwtCliLine ''
        Write-IgwtCliLine $g.Name ([ConsoleColor]::White)
        foreach ($r in $g.Group) {
            Write-IgwtCliLine ("  {0,-16} {1,10} {2,8}  {3,-34} {4}" -f "[$($r.Status)]", (Format-IgwtBytes $r.Bytes), $r.Count, $r.RuleId, $r.Name) (Get-IgwtCleanerStatusColor $r.Status)
            if ($r.Reason) { Write-IgwtCliLine ("                   {0}" -f $r.Reason) ([ConsoleColor]::DarkGray) }
        }
    }
    $ready = @($ScanResult.Rules | Where-Object { $_.Status -eq 'Ready' })
    Write-IgwtCliLine ''
    Write-IgwtCliLine ("Found {0} in {1} item(s); {2} can be cleaned now in {3} rule(s)." -f (Format-IgwtBytes $ScanResult.TotalBytes), $ScanResult.TotalCount,
        (Format-IgwtBytes (($ready | Measure-Object Bytes -Sum).Sum)), $ready.Count) ([ConsoleColor]::White)
}

function Write-IgwtCleanResult {
    param($CleanResult)
    if ($Json) { $CleanResult | Select-Object ScanId, FreedBytes, LogFile, @{ n = 'Rules'; e = { $_.Rules | Select-Object RuleId, Status, Reason, DeletedBytes, DeletedCount, Skipped } } | ConvertTo-Json -Depth 5; return }
    Write-IgwtCliLine ''
    foreach ($r in $CleanResult.Rules) {
        $skipped = [int](($r.Skipped.Values | Measure-Object -Sum).Sum)
        Write-IgwtCliLine ("{0,-11} {1,10} {2,7} file(s), {3} skipped  {4}  {5}" -f "[$($r.Status)]", (Format-IgwtBytes $r.DeletedBytes), $r.DeletedCount, $skipped, $r.RuleId, $r.Reason) (Get-IgwtCleanerStatusColor $r.Status)
    }
    Write-IgwtCliLine ''
    Write-IgwtCliLine ("Freed {0}. Every deleted path is listed in {1}" -f (Format-IgwtBytes $CleanResult.FreedBytes), $CleanResult.LogFile) ([ConsoleColor]::White)
}

function Split-IgwtPathList {
    <# Exclusion paths: separated by '|' (never valid in a path), trailing backslashes trimmed. #>
    param([string[]]$Value)
    return @($Value | ForEach-Object { $_ -split '\|' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { if ($_ -match '^[A-Za-z]:\\$') { $_ } else { $_.TrimEnd('\') } })
}

function Get-IgwtAsrModeColor {
    param([string]$Mode)
    switch ($Mode) { 'Block' { [ConsoleColor]::Green } 'Warn' { [ConsoleColor]::Green } 'Audit' { [ConsoleColor]::Cyan } 'Off' { [ConsoleColor]::Yellow } default { [ConsoleColor]::Gray } }
}

function Write-IgwtAsrStatus {
    param($Status, [string]$Rule)
    $rules = @($Status.Rules)
    if ($Rule) { $rules = @($rules | Where-Object { $_.Key -eq $Rule -or $_.Id -eq $Rule.ToLowerInvariant() }) }
    if ($Json) { [pscustomobject]@{ DefenderActive = $Status.DefenderActive; CloudProtection = $Status.CloudProtection; Summary = $Status.Summary; GlobalExclusions = $Status.GlobalExclusions; Rules = $rules } | ConvertTo-Json -Depth 6; return }
    Write-IgwtCliLine ''
    Write-IgwtCliLine 'ASR Center (read-only view)' ([ConsoleColor]::White)
    Write-IgwtCliLine ("Defender active: {0} | cloud protection: {1} | Tamper Protection: {2}" -f $Status.DefenderActive, $Status.CloudProtection, $Status.TamperProtected) ([ConsoleColor]::Gray)
    if ($Status.Error) { Write-IgwtCliLine $Status.Error ([ConsoleColor]::Yellow) }
    foreach ($r in $rules) {
        $flag = ''
        if (-not $r.MeetsRecommendation -and -not $r.ServerOnly) { $flag = "  -> recommended: $($r.Recommended)" }
        if ($r.ManagedByPolicy) { $flag += "  [managed by $($r.Source)]" }
        Write-IgwtCliLine ("  {0,-14} {1,-26} {2}{3}" -f "[$($r.Mode)]", $r.Key, $r.Name, $flag) (Get-IgwtAsrModeColor $r.Mode)
        Write-IgwtCliLine ("  {0,-14} gamer impact ({1}): {2}" -f '', $r.GamerImpactLevel, $r.GamerImpact) ([ConsoleColor]::DarkGray)
        if ($Rule) {
            Write-IgwtCliLine ("  {0,-14} {1}" -f '', $r.Description) ([ConsoleColor]::Gray)
            Write-IgwtCliLine ("  {0,-14} modes: {1}; GUID {2}" -f '', $(if (@($r.AllowedModes).Count) { @($r.AllowedModes) -join ', ' } else { 'not changed by iG Windows Tuner' }), $r.Id) ([ConsoleColor]::DarkGray)
            foreach ($s in $r.Sources) { Write-IgwtCliLine ("  {0,-14} source: {1}" -f '', $s) ([ConsoleColor]::DarkGray) }
        }
        if (@($r.Exclusions).Count) { Write-IgwtCliLine ("  {0,-14} per-rule exclusions ({1}): {2}" -f '', $(switch ($r.ExclusionsVerified) { 'Yes' { 'confirmed by Defender' } 'No' { 'not picked up yet' } default { 'confirm as administrator' } }), (@($r.Exclusions) -join '; ')) ([ConsoleColor]::Cyan) }
        if ($r.CloudMissing) { Write-IgwtCliLine ("  {0,-14} needs cloud-delivered protection, which is off" -f '') ([ConsoleColor]::Yellow) }
    }
    if (-not $Rule) {
        $g = $Status.GlobalExclusions
        Write-IgwtCliLine ''
        Write-IgwtCliLine ("Global ASR exclusions: {0}" -f $(if (-not $g.Readable) { $g.Note } elseif (@($g.Paths).Count) { @($g.Paths) -join '; ' } else { 'none' })) ([ConsoleColor]::Gray)
        $s = $Status.Summary
        Write-IgwtCliLine ("Summary: {0} Block, {1} Warn, {2} Audit, {3} not configured, {4} below the recommendation. Change with -AsrRule <key> -AsrMode <mode> or -AsrRecommended." -f $s.Block, $s.Warn, $s.Audit, ($s.NotConfigured + $s.Off), $s.BelowRecommendation) ([ConsoleColor]::White)
    }
}

# ---------------------------------------------------------------------------------------------
$modes = @()
if ($Report) { $modes += 'Report' }
if ($ListTweaks) { $modes += 'ListTweaks' }
if ($Preset -and -not ($Drift -or $AdoptDrift)) { $modes += 'Preset' }
if ($ListPresets) { $modes += 'ListPresets' }
if ($SavePreset) { $modes += 'SavePreset' }
if ($ExportPreset) { $modes += 'ExportPreset' }
if ($ImportPreset) { $modes += 'ImportPreset' }
if ($RemovePreset) { $modes += 'RemovePreset' }
if ($Drift) { $modes += 'Drift' }
if ($AdoptDrift) { $modes += 'AdoptDrift' }
if ($Session) { $modes += 'Session' }
if ($Platform) { $modes += 'Platform' }
if ($Persona) { $modes += 'Persona' }
if ($Apply) { $modes += 'Apply' }
if ($Revert) { $modes += 'Revert' }
if ($RevertAll) { $modes += 'RevertAll' }
if ($ResetDefault) { $modes += 'ResetDefault' }
if ($Clean) { $modes += 'Clean' }
if ($Analyze) { $modes += 'Analyze' }
if ($Hardware) { $modes += 'Hardware' }
if ($Asr) { $modes += 'Asr' }
if ($AsrAudit) { $modes += 'AsrAudit' }
if ($SecurityScore) { $modes += 'SecurityScore' }
if ($NetworkSurface) { $modes += 'NetworkSurface' }
if ($Inspect) { $modes += 'Inspect' }
if ($PowerSetting) { $modes += 'PowerSetting' }
if ($Inventory) { $modes += 'Inventory' }
if ($Change) { $modes += 'Change' }
if ($Persistence) { $modes += 'Persistence' }
if ($Updates) { $modes += 'Updates' }
if ($Diagnostics) { $modes += 'Diagnostics' }
if ($SystemReport) { $modes += 'SystemReport' }
if ($DnsBenchmark) { $modes += 'DnsBenchmark' }
if ($Latency) { $modes += 'Latency' }
if ($NetworkTest) { $modes += 'NetworkTest' }
if ($RiskZone) { $modes += 'RiskZone' }
if ($Toolkit) { $modes += 'Toolkit' }
if ($Install -or ($AppList -and -not ($Uninstall -or $Upgrade))) { $modes += 'Install' }
if ($Uninstall) { $modes += 'Uninstall' }
if ($Upgrade) { $modes += 'Upgrade' }
if ($UpgradeAll) { $modes += 'UpgradeAll' }
if ($ExportAppList) { $modes += 'ExportAppList' }
if ($Fix) { $modes += 'Fix' }
if ($OpenPanel) { $modes += 'OpenPanel' }
if ($EnableFeature) { $modes += 'EnableFeature' }
if ($DisableFeature) { $modes += 'DisableFeature' }
if (($AddItem -or $RemoveItem) -and -not ($Preset -or $SavePreset)) { Write-IgwtCliLine '-AddItem and -RemoveItem are only valid with -Preset or -SavePreset.' ([ConsoleColor]::Red); exit 2 }
if ($BasedOn -and -not $SavePreset) { Write-IgwtCliLine '-BasedOn is only valid with -SavePreset.' ([ConsoleColor]::Red); exit 2 }
if ($ExportPreset -and -not $PresetPath) { Write-IgwtCliLine '-ExportPreset needs -PresetPath.' ([ConsoleColor]::Red); exit 2 }
if ($PresetPath -and -not $ExportPreset) { Write-IgwtCliLine '-PresetPath is only valid with -ExportPreset.' ([ConsoleColor]::Red); exit 2 }
if ($CloseApps -and $Session -ne 'Start') { Write-IgwtCliLine '-CloseApps is only valid with -Session Start.' ([ConsoleColor]::Red); exit 2 }
if ($modes.Count -gt 1) { Write-IgwtCliLine "Choose one mode only (got: $($modes -join ', '))." ([ConsoleColor]::Red); exit 2 }
$asrOnly = @('AsrRule', 'AsrMode', 'AsrRecommended', 'AsrExclude', 'AsrUnexclude') | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($asrOnly -and -not $Asr) { Write-IgwtCliLine "-$($asrOnly -join ', -') only valid with -Asr." ([ConsoleColor]::Red); exit 2 }
if ($PSBoundParameters.ContainsKey('Days') -and -not ($AsrAudit -or $Diagnostics -or $SystemReport)) { Write-IgwtCliLine '-Days is only valid with -AsrAudit, -Diagnostics or -SystemReport.' ([ConsoleColor]::Red); exit 2 }
if ($AsrAudit -and $Days -gt 90) { Write-IgwtCliLine '-Days must be 90 or less with -AsrAudit.' ([ConsoleColor]::Red); exit 2 }
if ($Search -and -not ($Inventory -or $Toolkit)) { Write-IgwtCliLine '-Search is only valid with -Inventory or -Toolkit.' ([ConsoleColor]::Red); exit 2 }
if ($AcceptAgreements -and -not ($Install -or $Upgrade -or $UpgradeAll -or $AppList)) { Write-IgwtCliLine '-AcceptAgreements is only valid with -Install, -Upgrade or -UpgradeAll.' ([ConsoleColor]::Red); exit 2 }
if ($AppId -and -not $ExportAppList) { Write-IgwtCliLine '-AppId is only valid with -ExportAppList.' ([ConsoleColor]::Red); exit 2 }
if ($ExportAppList -and -not $AppId) { Write-IgwtCliLine '-ExportAppList needs -AppId.' ([ConsoleColor]::Red); exit 2 }
$changeOnly = @('Target', 'Value', 'Provisioned') | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($changeOnly -and -not $Change) { Write-IgwtCliLine "-$($changeOnly -join ', -') only valid with -Change." ([ConsoleColor]::Red); exit 2 }
if ($Change -and (-not $Target -or -not $Value)) { Write-IgwtCliLine '-Change needs -Target and -Value.' ([ConsoleColor]::Red); exit 2 }
if ($IncludeMicrosoft -and -not $Persistence) { Write-IgwtCliLine '-IncludeMicrosoft is only valid with -Persistence.' ([ConsoleColor]::Red); exit 2 }
if ($Quick -and -not ($SystemReport -or $Toolkit)) { Write-IgwtCliLine '-Quick is only valid with -SystemReport or -Toolkit.' ([ConsoleColor]::Red); exit 2 }
if ($SystemReport -and -not $ReportPath) { Write-IgwtCliLine '-SystemReport needs -ReportPath (.html or .json).' ([ConsoleColor]::Red); exit 2 }
if ($ReportPath -and -not ($Report -or $Persistence -or $SystemReport -or $NetworkTest)) { Write-IgwtCliLine '-ReportPath is only valid with -Report, -Persistence, -SystemReport or -NetworkTest.' ([ConsoleColor]::Red); exit 2 }
$netOnly = @('Duration', 'NetTarget', 'UnderLoad') | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($netOnly -and -not $NetworkTest) { Write-IgwtCliLine "-$($netOnly -join ', -') only valid with -NetworkTest." ([ConsoleColor]::Red); exit 2 }
if ($AsrMode -and -not $AsrRule) { Write-IgwtCliLine '-AsrMode needs -AsrRule.' ([ConsoleColor]::Red); exit 2 }
$powerOnly = @('Ac', 'Dc', 'PowerDefault') | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($powerOnly -and -not $PowerSetting) { Write-IgwtCliLine "-$($powerOnly -join ', -') only valid with -PowerSetting." ([ConsoleColor]::Red); exit 2 }
if ($PowerSetting -and -not $powerOnly) { Write-IgwtCliLine '-PowerSetting needs -Ac, -Dc or -PowerDefault.' ([ConsoleColor]::Red); exit 2 }
if ($Snapshot -and -not $RevertAll) { Write-IgwtCliLine '-Snapshot is only valid with -RevertAll.' ([ConsoleColor]::Red); exit 2 }
$cleanOnly = @('Scan', 'CleanRule', 'CleanLevel', 'IncludeOptIn', 'AllUsers', 'Yes') | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($cleanOnly -and -not $Clean) { Write-IgwtCliLine "-$($cleanOnly -join ', -') only valid with -Clean." ([ConsoleColor]::Red); exit 2 }
if ($PSBoundParameters.ContainsKey('Top') -and -not $Analyze) { Write-IgwtCliLine '-Top is only valid with -Analyze.' ([ConsoleColor]::Red); exit 2 }

try {
    if ($modes -notcontains 'Session' -and -not $Json) {
        try { $staleSession = Get-IgwtSessionState } catch { $staleSession = $null }
        if ($staleSession -and $staleSession.Stale) { Write-IgwtCliLine "A Session Mode session from $($staleSession.Started.ToLocalTime().ToString('g')) was not ended: $($staleSession.Reason) Run -Session Stop to restore your settings." ([ConsoleColor]::Yellow) }
    }
    if ($modes.Count -eq 0) {
        if ($NoGui) { Get-Help $PSCommandPath -Detailed | Out-String | Write-Output; exit 0 }
        Show-IgwtGui -ScriptPath $PSCommandPath
        exit 0
    }

    switch ($modes[0]) {
        'Report' {
            $r = Get-IgwtHealthReport
            if ($Json) { $r | ConvertTo-Json -Depth 10 } else { Format-IgwtHealthReport -Report $r | Write-Output }
            if ($ReportPath) {
                $fmt = 'Html'
                if ($ReportPath -match '\.json$') { $fmt = 'Json' }
                $out = Export-IgwtHealthReport -Report $r -Path $ReportPath -Format $fmt
                if (-not $Json) { Write-IgwtCliLine "Report written to $out" ([ConsoleColor]::Gray) }
            }
            exit 0
        }
        'ListTweaks' {
            $ctx = New-IgwtContext
            $presets = @(Get-IgwtPreset)
            $rows = foreach ($t in Get-IgwtCatalog) {
                $s = Get-IgwtTweakState -Tweak $t -Context $ctx
                $in = @($presets | Where-Object { $_.tweaks -contains $t.id } | ForEach-Object { if ($_.PSObject.Properties['code'] -and $_.code) { $_.code } else { '+' } } | Select-Object -Unique) -join ''
                [pscustomobject]@{ Id = $t.id; Category = $t.category; Name = $t.name; Level = $t.level; Tier = $t.evidence.tier; Risk = $t.risk; Requires = $t.requires
                    Presets = $(if ($in) { $in } else { '-' }); Expert = [bool]$t.expert; AntiCheat = $t.antiCheatText; Reversible = $t.reversible; State = $s.State; Hint = $t.hint }
            }
            if ($Json) { $rows | ConvertTo-Json -Depth 4; exit 0 }
            foreach ($g in ($rows | Group-Object Category)) {
                Write-IgwtCliLine ''
                Write-IgwtCliLine $g.Name ([ConsoleColor]::White)
                foreach ($r in $g.Group) {
                    Write-IgwtCliLine ("  {0,-38} {1,-15} {2,-8} T{3} {4,-6} {5,-6} {6,-10} {7}{8}" -f $r.Id, $r.State, $r.Level, $r.Tier, $r.Risk, $r.Requires, $r.Presets, $r.Name, $(if ($r.AntiCheat -ne 'Anti-cheat safe') { "  [$($r.AntiCheat)]" } else { '' })) (Get-IgwtStateColor $r.State)
                }
            }
            Write-IgwtCliLine ''
            Write-IgwtCliLine ('Presets column: ' + ((@($presets | Where-Object { $_.PSObject.Properties['code'] -and $_.code }) | ForEach-Object { "$($_.code) = $($_.name)" }) -join ', ') + ', + = custom.') ([ConsoleColor]::DarkGray)
            exit 0
        }
        'Hardware' {
            $hp = Get-IgwtHardwareProfile
            $active = @(Get-IgwtHardwareOverlays | Where-Object { @(@($_.tags) | Where-Object { $hp.Tags -contains $_ }).Count -gt 0 })
            if ($Json) { [pscustomobject]@{ Tags = $hp.Tags; TagDetails = $hp.TagDetails; Overlays = @($active | ForEach-Object { $_.id }); Facts = $hp.Facts } | ConvertTo-Json -Depth 6; exit 0 }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Hardware profile (read-only)' ([ConsoleColor]::White)
            Write-IgwtCliLine ("  CPU: {0} | memory {1} GB | system disk: {2} {3} | {4}" -f $hp.Facts.cpu.name, $hp.Facts.memoryGB, $hp.Facts.systemDisk.bus, $hp.Facts.systemDisk.media, $(if ($hp.Derived.Vm) { 'virtual machine' } elseif ($hp.Derived.Laptop) { 'laptop' } else { 'desktop' }))
            Write-IgwtCliLine ("  GPU: {0}" -f (@($hp.Facts.gpus | Where-Object { $_.enabled } | ForEach-Object { $_.name }) -join ' + '))
            Write-IgwtCliLine ("  Network: {0}" -f (@($hp.Facts.nics | ForEach-Object { "$($_.name)$(if (-not $_.enabled) { ' (disabled)' })" }) -join '; '))
            Write-IgwtCliLine ''
            foreach ($t in $hp.TagDetails) { Write-IgwtCliLine ("  {0,-26} {1}" -f $t.Id, $t.Name) ([ConsoleColor]::Cyan); Write-IgwtCliLine ("  {0,-26} {1}" -f '', $t.Basis) ([ConsoleColor]::DarkGray) }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Hardware overlays active on this PC:' ([ConsoleColor]::White)
            foreach ($o in $active) { Write-IgwtCliLine ("  - {0}: {1}" -f $o.name, $o.hint) }
            exit 0
        }
        'Analyze' {
            $target = $Analyze
            if ($target -notmatch '^[A-Za-z]:\\?') {
                try { $target = (Resolve-Path -LiteralPath $Analyze -ErrorAction Stop).ProviderPath } catch { Write-IgwtCliLine "Folder not found: $Analyze" ([ConsoleColor]::Red); exit 2 }
            }
            if ($target -match '^[A-Za-z]:$') { $target += '\' }
            $u = Get-IgwtDiskUsage -Path $target -Top $Top
            if ($Json) { $u | ConvertTo-Json -Depth 4; exit 0 }
            Write-IgwtCliLine ''
            Write-IgwtCliLine ("Disk usage of {0}: {1} in {2} file(s) (read-only; {3} folder(s) not readable, {4} reparse point(s) not followed)" -f $u.Root, (Format-IgwtBytes $u.TotalBytes), $u.Files, $u.AccessDenied, $u.ReparseSkipped) ([ConsoleColor]::White)
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Largest folders' ([ConsoleColor]::White)
            foreach ($f in $u.Folders) { Write-IgwtCliLine ("  {0,10}  {1}" -f (Format-IgwtBytes $f.Bytes), $f.Path) }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Largest files' ([ConsoleColor]::White)
            foreach ($f in $u.LargestFiles) { Write-IgwtCliLine ("  {0,10}  {1}" -f (Format-IgwtBytes $f.Bytes), $f.Path) }
            exit 0
        }
        'AsrAudit' {
            $audit = Get-IgwtAsrAudit -Days $Days
            if ($Json) { $audit | ConvertTo-Json -Depth 7 } else { Format-IgwtAsrAudit -Audit $audit | Write-Output }
            exit 0
        }
        'SecurityScore' {
            $score = Get-IgwtSecurityScore
            $accounts = Get-IgwtLocalAccountAudit
            if ($Json) { [pscustomobject]@{ Score = $score; Accounts = $accounts } | ConvertTo-Json -Depth 6; exit 0 }
            Write-IgwtCliLine ''
            Format-IgwtSecurityScore -Score $score | Write-Output
            Write-IgwtCliLine 'Local accounts (read-only):' ([ConsoleColor]::White)
            if (-not $accounts.Readable) { Write-IgwtCliLine "  $($accounts.Error)" ([ConsoleColor]::Yellow) }
            foreach ($a in @($accounts.Accounts | Where-Object { $_.Enabled })) { Write-IgwtCliLine ("  {0,-22} {1}{2}" -f $a.Name, $a.Source, $(if ($a.IsAdmin) { ', administrator' } else { '' })) }
            foreach ($f in $accounts.Findings) { Write-IgwtCliLine ("  [{0}] {1} {2}" -f $f.Severity.ToUpperInvariant(), $f.Text, $f.Advice) ([ConsoleColor]::Yellow) }
            if (@($accounts.Findings).Count -eq 0 -and $accounts.Readable) { Write-IgwtCliLine '  No findings.' ([ConsoleColor]::Green) }
            exit 0
        }
        'NetworkSurface' {
            $ns = Get-IgwtNetworkSurface
            if ($Json) { $ns | ConvertTo-Json -Depth 5; exit 0 }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Network surface: programs listening for connections (read-only)' ([ConsoleColor]::White)
            if ($ns.Error) { Write-IgwtCliLine $ns.Error ([ConsoleColor]::Yellow) }
            foreach ($e in $ns.Entries) {
                $color = $(if ($e.Scope -eq 'Loopback') { [ConsoleColor]::DarkGray } elseif ($e.Known) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Gray })
                $svc = $(if (@($e.Services).Count) { " [$(@($e.Services | Select-Object -First 3) -join ', ')$(if (@($e.Services).Count -gt 3) { ', ...' })]" } else { '' })
                Write-IgwtCliLine ("  {0} {1,5}  {2,-13} {3}{4}" -f $e.Protocol, $e.Port, $e.Scope, $e.Process, $svc) $color
                if ($e.Known) { Write-IgwtCliLine ("               {0}: {1}{2}" -f $e.Known, $e.Note, $(if ($e.Fix) { " (reduce with $($e.Fix))" } else { '' })) ([ConsoleColor]::DarkGray) }
            }
            Write-IgwtCliLine ''
            Write-IgwtCliLine ("{0} listener(s) on network interfaces, {1} on loopback only. {2}" -f $ns.ExposedCount, $ns.LoopbackCount, $ns.Note) ([ConsoleColor]::White)
            exit 0
        }
        'Inspect' {
            $ins = Get-IgwtInspection -Area $Inspect
            if ($Json) { $ins | ConvertTo-Json -Depth 7 } else { Format-IgwtInspection -Inspection $ins | Write-Output }
            exit 0
        }
        'Inventory' {
            $match = { param($row, [string[]]$fields) if (-not $Search) { return $true }; foreach ($f in $fields) { if ([string]$row.$f -and ([string]$row.$f).IndexOf($Search, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }; return $false }
            switch ($Inventory) {
                'Services' {
                    $inv = Get-IgwtServiceInventory
                    $rows = @($inv.Services | Where-Object { & $match $_ @('Name', 'DisplayName', 'Path') })
                    if ($Json) { $rows | ConvertTo-Json -Depth 4; exit 0 }
                    foreach ($s in $rows) {
                        $color = switch ($s.Rating) { 'Protected' { [ConsoleColor]::DarkGray } 'Catalogued' { [ConsoleColor]::Cyan } 'ThirdParty' { [ConsoleColor]::Yellow } default { [ConsoleColor]::Gray } }
                        Write-IgwtCliLine ("  {0,-11} {1,-8} {2,-17} {3,-30} {4}" -f "[$($s.Rating)]", $s.State, $s.StartupType, $s.Name, $s.DisplayName) $color
                        if ($Search) { Write-IgwtCliLine ("              {0}" -f $s.Advice) ([ConsoleColor]::DarkGray) }
                    }
                    Write-IgwtCliLine ("{0} services, {1} running, {2} protected, {3} third-party. {4}" -f $inv.Counts.Total, $inv.Counts.Running, $inv.Counts.Protected, $inv.Counts.ThirdParty, $inv.Note) ([ConsoleColor]::White)
                }
                'Tasks' {
                    $inv = Get-IgwtTaskInventory
                    $rows = @($inv.Tasks | Where-Object { & $match $_ @('Path', 'Action', 'Author') })
                    if ($Json) { $rows | ConvertTo-Json -Depth 4; exit 0 }
                    foreach ($t in $rows) { Write-IgwtCliLine ("  {0,-9} {1}{2}" -f $t.State, $t.Path, $(if ($t.Protected) { '  [protected]' } else { '' })) $(if ($t.Protected) { [ConsoleColor]::DarkGray } elseif ($t.IsMicrosoft) { [ConsoleColor]::Gray } else { [ConsoleColor]::Yellow }) }
                    Write-IgwtCliLine ("{0} tasks, {1} disabled, {2} third-party. {3}" -f $inv.Counts.Total, $inv.Counts.Disabled, $inv.Counts.ThirdParty, $inv.Note) ([ConsoleColor]::White)
                }
                'Apps' {
                    $inv = Get-IgwtAppInventory
                    $w = @($inv.Win32 | Where-Object { & $match $_ @('Name', 'Publisher') }); $x = @($inv.Appx | Where-Object { & $match $_ @('Name', 'Publisher') })
                    if ($Json) { [pscustomobject]@{ Win32 = $w; Appx = $x } | ConvertTo-Json -Depth 4; exit 0 }
                    Write-IgwtCliLine 'Installed apps (Win32)' ([ConsoleColor]::White)
                    foreach ($a in $w) { Write-IgwtCliLine ("  {0,-50} {1,-18} {2}" -f $a.Name, $a.Version, $a.Publisher) }
                    Write-IgwtCliLine 'Appx packages' ([ConsoleColor]::White)
                    foreach ($a in $x) { Write-IgwtCliLine ("  {0,-11} {1,-55} {2}" -f $(if ($a.Protected) { '[protected]' } else { '[removable]' }), $a.Name, $a.Version) $(if ($a.Protected) { [ConsoleColor]::DarkGray } else { [ConsoleColor]::Gray }) }
                    Write-IgwtCliLine $inv.Note ([ConsoleColor]::White)
                }
                'Features' {
                    $inv = Get-IgwtFeatureInventory
                    $fe = @($inv.Features | Where-Object { & $match $_ @('Name') }); $ca = @($inv.Capabilities | Where-Object { & $match $_ @('Name') })
                    if ($Json) { [pscustomobject]@{ Features = $fe; Capabilities = $ca; Error = $inv.Error } | ConvertTo-Json -Depth 4; exit 0 }
                    if ($inv.Error) { Write-IgwtCliLine $inv.Error ([ConsoleColor]::Yellow) }
                    foreach ($f in $fe) { Write-IgwtCliLine ("  feature    {0,-24} {1}{2}" -f $f.State, $f.Name, $(if ($f.Protected) { '  [protected]' } else { '' })) }
                    foreach ($c in $ca) { Write-IgwtCliLine ("  capability {0,-24} {1}{2}" -f $c.State, $c.Name, $(if ($c.Protected) { '  [protected]' } else { '' })) }
                    Write-IgwtCliLine $inv.Note ([ConsoleColor]::White)
                }
                'Firewall' {
                    $inv = Get-IgwtFirewallRuleList -Search $Search
                    if ($Json) { $inv.Rules | ConvertTo-Json -Depth 3; exit 0 }
                    foreach ($r in $inv.Rules) { Write-IgwtCliLine ("  {0,-8} {1,-8} {2,-5} {3,-50} {4}" -f $(if ($r.IsWindowsRule) { 'Windows' } else { 'App' }), $r.Direction, $(if ($r.Enabled) { 'on' } else { 'off' }), $r.DisplayName, $r.Program) $(if ($r.IsWindowsRule) { [ConsoleColor]::DarkGray } else { [ConsoleColor]::Gray }) }
                    Write-IgwtCliLine ("{0} rule(s), {1} created by apps. {2} Change an app rule with -Change firewallRule -Target <Name> -Value Disabled." -f @($inv.Rules).Count, $inv.AppRules, $inv.Note) ([ConsoleColor]::White)
                }
                'Hosts' {
                    $inv = Get-IgwtHostsFile
                    if ($Json) { $inv | ConvertTo-Json -Depth 4; exit 0 }
                    Write-IgwtCliLine ("Hosts file {0}: {1} entr(ies), {2} flagged. {3}" -f $inv.Path, @($inv.Entries).Count, $inv.Unexpected, $inv.Note) ([ConsoleColor]::White)
                    foreach ($e in $inv.Entries) { Write-IgwtCliLine ("  {0,-16} {1,-15} {2}  {3}" -f "[$($e.Flag)]", $e.Address, $e.HostName, $e.Note) $(if ($e.Flag -eq 'Expected') { [ConsoleColor]::Gray } else { [ConsoleColor]::Yellow }) }
                }
                'Adapters' {
                    $inv = Get-IgwtAdapterPropertyInspection
                    if ($Json) { $inv | ConvertTo-Json -Depth 5; exit 0 }
                    foreach ($a in $inv.Adapters) {
                        Write-IgwtCliLine ''
                        Write-IgwtCliLine ("{0} - {1} ({2}, {3})" -f $a.Name, $a.Description, $a.Status, $a.LinkSpeed) ([ConsoleColor]::White)
                        foreach ($p in @($a.Properties | Where-Object { & $match $_ @('DisplayName', 'Keyword') })) {
                            Write-IgwtCliLine ("  {0,-38} {1,-22} default {2,-8} {3}" -f $p.DisplayName, $p.Value, $p.Default, $(if ($p.ChangedFromDefault) { '[changed]' } else { '' })) $(if ($p.ChangedFromDefault) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Gray })
                            Write-IgwtCliLine ("  {0,-38} {1}" -f '', $p.Description) ([ConsoleColor]::DarkGray)
                        }
                    }
                    Write-IgwtCliLine $inv.Note ([ConsoleColor]::White)
                }
            }
            exit 0
        }
        'Change' {
            try { $plan = Get-IgwtManagedChangePlan -Kind $Change -Target $Target -Value $Value -Provisioned:$Provisioned }
            catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($DryRun -or -not $plan.HasChange) {
                if ($Json) { $plan | ConvertTo-Json; exit 0 }
                Write-IgwtCliLine 'Management change dry run (nothing is changed):' ([ConsoleColor]::White)
                Write-IgwtCliLine ("  {0}" -f $plan.Change) $(if ($plan.HasChange) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green })
                Write-IgwtCliLine ("  Reversible: {0}" -f $plan.Reversible) ([ConsoleColor]::DarkGray)
                exit 0
            }
            if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            $res = Invoke-IgwtManagedChange -Kind $Change -Target $Target -Value $Value -Provisioned:$Provisioned
            if ($Json) { $res | ConvertTo-Json -Depth 5 } else {
                foreach ($r in $res.Results) { Write-IgwtCliLine ("{0,-10} {1} {2}" -f "[$($r.Result)]", $r.Change, $r.Message) $(if ($r.Result -eq 'Failed') { [ConsoleColor]::Red } else { [ConsoleColor]::Green }) }
                if ($res.Snapshot) { Write-IgwtCliLine "Snapshot: $($res.Snapshot) (undo with -RevertAll -Snapshot <file>)" ([ConsoleColor]::Gray) }
            }
            Complete-IgwtCli $(if (@($res.Results | Where-Object { $_.Result -eq 'Failed' }).Count) { 5 } else { 0 })
        }
        'Persistence' {
            $inv = Get-IgwtPersistenceInventory -IncludeMicrosoft:$IncludeMicrosoft
            if ($Json) { $inv | ConvertTo-Json -Depth 5 } else {
                foreach ($g in ($inv.Entries | Group-Object Category)) {
                    Write-IgwtCliLine ''
                    Write-IgwtCliLine $g.Name ([ConsoleColor]::White)
                    foreach ($e in $g.Group) {
                        $color = switch ($e.Severity) { 'Warn' { [ConsoleColor]::Red } 'Review' { [ConsoleColor]::Yellow } default { [ConsoleColor]::Gray } }
                        Write-IgwtCliLine ("  {0,-8} {1,-44} {2,-10} {3}" -f "[$($e.Severity)]", $e.Name, $e.Signature, $e.Signer) $color
                        if ($e.Severity -ne 'Info') { Write-IgwtCliLine ("           {0}  {1}" -f $e.Command, $e.Note) ([ConsoleColor]::DarkGray) }
                    }
                }
                Write-IgwtCliLine ''
                Write-IgwtCliLine ("{0} entries, {1} warning(s), {2} to review. {3}" -f $inv.Counts.Total, $inv.Counts.Warn, $inv.Counts.Review, $inv.Note) ([ConsoleColor]::White)
            }
            if ($ReportPath) {
                $out = Export-IgwtPersistenceReport -Inventory $inv -Path $ReportPath -Format $(if ($ReportPath -match '\.json$') { 'Json' } else { 'Html' })
                if (-not $Json) { Write-IgwtCliLine "Report written to $out" ([ConsoleColor]::Gray) }
            }
            exit 0
        }
        'Updates' {
            $u = Get-IgwtUpdateStatus
            if ($Json) { $u | ConvertTo-Json -Depth 4; exit 0 }
            Write-IgwtCliLine 'Windows Update (read-only)' ([ConsoleColor]::White)
            foreach ($s in $u.Services) { Write-IgwtCliLine ("  {0,-13} {1,-8} {2}" -f $s.Name, $s.Status, $s.StartType) }
            Write-IgwtCliLine ("  Pending restart: {0}" -f $(if (@($u.PendingRestart).Count) { $u.PendingRestart -join ', ' } else { 'no' }))
            Write-IgwtCliLine ("  Policies: {0}" -f $(if (@($u.Policies).Count) { (@($u.Policies | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ') } else { 'none (Windows defaults)' }))
            Write-IgwtCliLine ("  Last successful Windows/driver/app update (not counting Defender definitions): {0}" -f $(if ($u.LastSuccess) { $u.LastSuccess } else { 'unknown' }))
            if ($u.Error) { Write-IgwtCliLine "  $($u.Error)" ([ConsoleColor]::Yellow) }
            foreach ($h in @($u.History | Select-Object -First 15)) { Write-IgwtCliLine ("  {0:yyyy-MM-dd} {1,-22} {2} {3}" -f $h.Date, $h.Result, $h.Title, $h.HResult) $(if ($h.Result -in 'Failed', 'Aborted') { [ConsoleColor]::Red } else { [ConsoleColor]::Gray }) }
            foreach ($a in $u.Advice) { Write-IgwtCliLine "  -> $a" ([ConsoleColor]::Yellow) }
            Write-IgwtCliLine $u.Note ([ConsoleColor]::DarkGray)
            exit 0
        }
        'Diagnostics' {
            $areas = @($Diagnostics); if ($areas -contains 'All') { $areas = @('DpcIsr', 'Reliability', 'Crashes', 'Boot', 'Drivers') }
            $d = Get-IgwtDiagnostics -Area $areas -Days $(if ($PSBoundParameters.ContainsKey('Days')) { $Days } else { 30 })
            if ($Json) { $d | ConvertTo-Json -Depth 6 } else { Format-IgwtDiagnostics -Diagnostics $d | Write-Output }
            exit 0
        }
        'SystemReport' {
            if (-not $Json) { Write-IgwtCliLine 'Collecting the system report (read-only; this takes a minute)...' ([ConsoleColor]::Gray) }
            $r = Get-IgwtSystemReport -Quick:$Quick -Days $(if ($PSBoundParameters.ContainsKey('Days')) { $Days } else { 30 })
            $out = Export-IgwtSystemReport -Report $r -Path $ReportPath -Format $(if ($ReportPath -match '\.json$') { 'Json' } else { 'Html' })
            if ($Json) { [pscustomobject]@{ Path = $out } | ConvertTo-Json } else { Write-IgwtCliLine "System report written to $out. It contains the computer name and installed software; review it before sharing." ([ConsoleColor]::White) }
            exit 0
        }
        'DnsBenchmark' {
            if (-not $Json) { Write-IgwtCliLine 'Running the DNS benchmark (sends DNS queries; changes nothing)...' ([ConsoleColor]::Gray) }
            $b = Invoke-IgwtDnsBenchmark
            if ($Json) { $b | ConvertTo-Json -Depth 4; exit 0 }
            foreach ($r in $b.Results) { Write-IgwtCliLine ("  {0,-10} {1,-16} median {2,7} ms  worst {3,7} ms  failures {4}/{5}" -f $r.Name, $r.Server, $r.MedianMs, $r.WorstMs, $r.Failures, $r.Queries) }
            Write-IgwtCliLine $b.Note ([ConsoleColor]::DarkGray)
            exit 0
        }
        'Latency' {
            $targets = @(Split-IgwtIdList $Latency)
            if (-not $Json) { Write-IgwtCliLine "Measuring latency to $($targets -join ', ') (20 echo requests each; changes nothing)..." ([ConsoleColor]::Gray) }
            $l = Test-IgwtNetworkLatency -Target $targets
            if ($Json) { $l | ConvertTo-Json -Depth 4; exit 0 }
            foreach ($r in $l.Results) {
                if ($r.Error) { Write-IgwtCliLine ("  {0,-24} {1}" -f $r.Target, $r.Error) ([ConsoleColor]::Red); continue }
                Write-IgwtCliLine ("  {0,-24} avg {1,6} ms  min {2,5}  max {3,5}  jitter {4,5} ms  loss {5} %" -f $r.Target, $r.AvgMs, $r.MinMs, $r.MaxMs, $r.JitterMs, $r.LossPercent)
            }
            Write-IgwtCliLine $l.Note ([ConsoleColor]::DarkGray)
            exit 0
        }
        'NetworkTest' {
            if (-not $Json) { Write-IgwtCliLine "Running the $($Duration.ToLowerInvariant()) network test (pings and DNS queries only; changes nothing)..." ([ConsoleColor]::Gray) }
            $res = Invoke-IgwtNetworkQualityTest -Duration $Duration -Target @(Split-IgwtIdList $NetTarget)
            if ($UnderLoad -and -not $res.Error) {
                if (-not $Json) { Write-IgwtCliLine 'Start a speed test or a large download now. Measuring latency under load in 5 seconds, for 20 seconds...' ([ConsoleColor]::Yellow) }
                Start-Sleep -Seconds 5
                $load = Measure-IgwtLoadedLatency -Baseline $res -DurationSec 20
                $res.Bufferbloat = [pscustomobject]@{ Grade = $load.Grade; IncreaseMs = $load.IncreaseMs }
                $res.Recommendations = Get-IgwtNetworkRecommendations -Result $res
            }
            if ($Json) { $res | ConvertTo-Json -Depth 8 } else { Format-IgwtNetworkQuality -Result $res | Write-Output }
            if ($ReportPath -and -not $res.Error) {
                $out = Export-IgwtNetworkReport -Result $res -Path $ReportPath -Format $(if ($ReportPath -match '\.json$') { 'Json' } else { 'Html' })
                if (-not $Json) { Write-IgwtCliLine "Report written to $out" ([ConsoleColor]::Gray) }
            }
            exit $(if ($res.Error) { 1 } else { 0 })
        }
        'RiskZone' {
            $ctx = New-IgwtContext
            $catalog = @(Get-IgwtCatalog)
            $rows = foreach ($r in @(Get-IgwtRejectedTweaks)) {
                $t = $null; $state = ''
                if ($r.riskItem) { $t = $catalog | Where-Object { $_.id -eq [string]$r.riskItem } | Select-Object -First 1; if ($t) { $state = [string](Get-IgwtTweakState -Tweak $t -Context $ctx).State } }
                [pscustomobject]@{ Rejected = [string]$r.id; Name = [string]$r.name; Available = [bool]$t; Item = $(if ($t) { [string]$t.id } else { '' }); State = $state
                    Warning = $(if ($t) { [string]$t.warning } else { '' }); TurnsOff = $(if ($t) { @($t.riskZone.turnsOff) } else { @() }); TurnsOn = $(if ($t) { @($t.riskZone.turnsOn) } else { @() })
                    Risks = $(if ($t) { @($t.riskZone.risks) } else { @() }); NotOffered = [string]$r.unavailable }
            }
            if ($Json) { @($rows) | ConvertTo-Json -Depth 4; exit 0 }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Risk Zone: rejected tweaks you can apply at your own risk' ([ConsoleColor]::Red)
            foreach ($x in @($rows | Where-Object { $_.Available })) {
                Write-IgwtCliLine ("  {0,-34} {1,-14} {2}" -f $x.Item, "[$($x.State)]", $x.Name) (Get-IgwtStateColor $x.State)
                Write-IgwtCliLine ("  {0,-34} {1}" -f '', $x.Warning) ([ConsoleColor]::Yellow)
                if (@($x.TurnsOff).Count) { Write-IgwtCliLine ("  {0,-34} turns off: {1}" -f '', (@($x.TurnsOff) -join '; ')) ([ConsoleColor]::DarkGray) }
                if (@($x.TurnsOn).Count) { Write-IgwtCliLine ("  {0,-34} turns on: {1}" -f '', (@($x.TurnsOn) -join '; ')) ([ConsoleColor]::DarkGray) }
            }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Not offered' ([ConsoleColor]::White)
            foreach ($x in @($rows | Where-Object { -not $_.Available })) { Write-IgwtCliLine ("  {0,-38} {1}" -f $x.Rejected, $x.NotOffered) ([ConsoleColor]::DarkGray) }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Apply one with: .\iGWindowsTuner.ps1 -Apply <risk id> -AcknowledgeRisk (add -DryRun to preview). Every change writes a snapshot and can be reverted.' ([ConsoleColor]::White)
            exit 0
        }
        'PowerSetting' {
            try { $plan = Get-IgwtPowerSettingChangePlan -Setting $PowerSetting -AC $Ac -DC $Dc -Default:$PowerDefault }
            catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            $def = $plan.Definition
            if ($DryRun -or -not $plan.HasChange) {
                if ($Json) { $plan | Select-Object Scheme, Guid, NewAC, NewDC, HasChange, Change | ConvertTo-Json; exit 0 }
                Write-IgwtCliLine ("Power plan editor dry run (nothing is changed): {0} in plan {1}" -f $def.alias, $plan.Scheme) ([ConsoleColor]::White)
                Write-IgwtCliLine ("  {0}" -f $(if ($plan.HasChange) { $plan.Change } else { 'Already set; nothing to change.' })) $(if ($plan.HasChange) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green })
                Write-IgwtCliLine ("  {0}" -f $def.description) ([ConsoleColor]::DarkGray)
                if ([string]$def.level -eq 'Expert' -and -not $AcknowledgeRisk) { Write-IgwtCliLine '  Expert setting: the real change also needs -AcknowledgeRisk.' ([ConsoleColor]::Yellow) }
                exit 0
            }
            if ([string]$def.level -eq 'Expert' -and -not $AcknowledgeRisk) { Write-IgwtCliLine "'$($def.alias)' is an Expert setting. Read its description (-DryRun), then add -AcknowledgeRisk." ([ConsoleColor]::Red); exit 2 }
            if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            $res = Invoke-IgwtPowerSettingChange -Setting $PowerSetting -AC $Ac -DC $Dc -Default:$PowerDefault -AcknowledgeRisk:$AcknowledgeRisk
            if ($Json) { $res | ConvertTo-Json -Depth 5 } else {
                foreach ($r in $res.Results) { Write-IgwtCliLine ("{0,-10} {1}: {2} {3}" -f "[$($r.Result)]", $r.Target, $r.Change, $r.Message) $(if ($r.Result -eq 'Failed') { [ConsoleColor]::Red } else { [ConsoleColor]::Green }) }
                if ($res.Snapshot) { Write-IgwtCliLine "Snapshot: $($res.Snapshot) (undo with -RevertAll -Snapshot <file>)" ([ConsoleColor]::Gray) }
            }
            Complete-IgwtCli $(if (@($res.Results | Where-Object { $_.Result -eq 'Failed' }).Count) { 5 } else { 0 })
        }
        'Asr' {
            $adds = @(Split-IgwtPathList $AsrExclude)
            $removes = @(Split-IgwtPathList $AsrUnexclude)
            $changing = ($AsrMode -or $AsrRecommended -or $adds.Count -or $removes.Count)
            $status = Get-IgwtAsrStatus
            if ($AsrRule -and @($status.Rules | Where-Object { $_.Key -eq $AsrRule -or $_.Id -eq $AsrRule.ToLowerInvariant() }).Count -eq 0) {
                Write-IgwtCliLine "Unknown ASR rule '$AsrRule'. Run -Asr to list the rule keys." ([ConsoleColor]::Red); exit 2
            }
            if (-not $changing) { Write-IgwtAsrStatus -Status $status -Rule $AsrRule; exit 0 }
            foreach ($p in $adds) {
                $check = Test-IgwtAsrExclusion -Path $p
                if (-not $check.Valid) { Write-IgwtCliLine "Exclusion '$p' refused: $($check.Reason)" ([ConsoleColor]::Red); exit 2 }
                foreach ($w in $check.Warnings) { if (-not $Json) { Write-IgwtCliLine "Note for '$p': $w" ([ConsoleColor]::Yellow) } }
            }
            $ruleMode = $null
            if ($AsrMode) { $ruleMode = @{ $AsrRule = $AsrMode } }
            $exclRule = $(if (($adds.Count -or $removes.Count) -and $AsrRule) { $AsrRule } else { '' })
            if ($DryRun) {
                $planRows = New-Object System.Collections.Generic.List[object]
                if ($AsrRecommended) {
                    foreach ($p in @(Get-IgwtAsrRecommendationPlan -Status $status)) {
                        if ($AsrMode -and ($p.Key -eq $AsrRule -or $p.Id -eq $AsrRule.ToLowerInvariant())) { continue }   # the explicit mode wins
                        $planRows.Add([pscustomobject]@{ Target = $p.Key; Change = "$($p.From) -> $($p.To)" })
                    }
                }
                if ($AsrMode) {
                    $r = @($status.Rules | Where-Object { $_.Key -eq $AsrRule -or $_.Id -eq $AsrRule.ToLowerInvariant() })[0]
                    $planRows.Add([pscustomobject]@{ Target = $r.Key; Change = "$($r.Mode) -> $AsrMode$(if ($r.ManagedByPolicy) { " (refused: managed by $($r.Source))" } elseif ($r.AllowedModes -notcontains $AsrMode) { ' (refused: mode not supported)' })" })
                }
                foreach ($p in $adds) { $planRows.Add([pscustomobject]@{ Target = $(if ($exclRule) { "exclusions of $exclRule" } else { 'global ASR exclusions' }); Change = "+ $p" }) }
                foreach ($p in $removes) { $planRows.Add([pscustomobject]@{ Target = $(if ($exclRule) { "exclusions of $exclRule" } else { 'global ASR exclusions' }); Change = "- $p" }) }
                if ($Json) { $planRows | ConvertTo-Json; exit 0 }
                Write-IgwtCliLine 'ASR Center dry run (nothing is changed):' ([ConsoleColor]::White)
                if ($planRows.Count -eq 0) { Write-IgwtCliLine '  Nothing to change.' ([ConsoleColor]::Green) }
                foreach ($row in $planRows) { Write-IgwtCliLine ("  {0,-34} {1}" -f $row.Target, $row.Change) ([ConsoleColor]::Yellow) }
                exit 0
            }
            if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            $res = Invoke-IgwtAsrChange -RuleMode $ruleMode -Recommended:$AsrRecommended -AddExclusion $adds -RemoveExclusion $removes -ExclusionRule $exclRule
            if ($Json) { $res | ConvertTo-Json -Depth 5; Complete-IgwtCli $(if (@($res.Results | Where-Object { $_.Result -eq 'Failed' }).Count) { 5 } else { 0 }) }
            if ($res.Changes -eq 0) { Write-IgwtCliLine 'Nothing to change.' ([ConsoleColor]::Green); Complete-IgwtCli 0 }
            foreach ($r in $res.Results) {
                Write-IgwtCliLine ("{0,-10} {1}: {2}" -f "[$($r.Result)]", $r.Target, $r.Change) $(if ($r.Result -eq 'Failed') { [ConsoleColor]::Red } else { [ConsoleColor]::Green })
                if ($r.Message) { Write-IgwtCliLine ("           {0}" -f $r.Message) ([ConsoleColor]::DarkGray) }
            }
            Write-IgwtCliLine "Snapshot: $($res.Snapshot) (undo with -RevertAll -Snapshot <file>)" ([ConsoleColor]::Gray)
            Complete-IgwtCli $(if (@($res.Results | Where-Object { $_.Result -eq 'Failed' }).Count) { 5 } else { 0 })
        }
        'Clean' {
            $ruleIds = @(Split-IgwtIdList $CleanRule)
            $rules = @(Get-IgwtCleanerRules)
            foreach ($i in $ruleIds) { if (@($rules | Where-Object { $_.id -eq $i }).Count -eq 0) { Write-IgwtCliLine "Unknown cleaner rule '$i'." ([ConsoleColor]::Red); exit 2 } }
            $scanArgs = @{ Level = $CleanLevel; IncludeOptIn = $IncludeOptIn; AllUsers = $AllUsers }
            if ($ruleIds.Count -gt 0) { $scanArgs = @{ RuleId = $ruleIds; AllUsers = $AllUsers } }
            if ($Scan -or $DryRun) {
                if ($AllUsers -and -not (Test-IgwtIsAdmin)) { Write-IgwtCliLine '-AllUsers needs administrator rights (run from an elevated PowerShell).' ([ConsoleColor]::Red); exit 2 }
                Write-IgwtCleanerScan -ScanResult (Invoke-IgwtCleanerScan @scanArgs)
                exit 0
            }
            if ($Json -and -not $Yes) { Write-IgwtCliLine '-Clean with -Json needs -Yes (there is no interactive confirmation).' ([ConsoleColor]::Red); exit 2 }
            $selected = @($rules | Where-Object { $ruleIds -contains $_.id })
            if ($ruleIds.Count -eq 0) {
                $max = [array]::IndexOf(@('Standard', 'Advanced', 'Expert'), $CleanLevel)
                $selected = @($rules | Where-Object { [array]::IndexOf(@('Standard', 'Advanced', 'Expert'), [string]$_.level) -le $max -and ($_.default -or $IncludeOptIn) })
            }
            $needsAdmin = $AllUsers -or @($selected | Where-Object { $_.requiresAdmin -or $_.method -in 'dism', 'driverStore' }).Count -gt 0
            if ($needsAdmin -and -not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            $s = Invoke-IgwtCleanerScan @scanArgs
            if (-not $Json) { Write-IgwtCleanerScan -ScanResult $s }
            $ready = @($s.Rules | Where-Object { $_.Status -eq 'Ready' })
            if ($ready.Count -eq 0) { if (-not $Json) { Write-IgwtCliLine 'Nothing to clean right now.' ([ConsoleColor]::Green) }; Complete-IgwtCli 0 }
            if (-not $Yes) {
                Write-IgwtCliLine ''
                Write-IgwtCliLine 'Deleted files cannot be restored (the Downloads rule uses the Recycle Bin).' ([ConsoleColor]::Yellow)
                $answer = Read-Host ("Type YES to clean {0} rule(s) ({1})" -f $ready.Count, (Format-IgwtBytes (($ready | Measure-Object Bytes -Sum).Sum)))
                if ($answer -cne 'YES') { Write-IgwtCliLine 'Cancelled; nothing was deleted.' ([ConsoleColor]::Yellow); Complete-IgwtCli 0 }
            }
            $c = Invoke-IgwtCleanerClean -Scan $s -RuleId @($ready.RuleId)
            Write-IgwtCleanResult -CleanResult $c
            if (@($c.Rules | Where-Object { $_.Status -eq 'Error' }).Count -gt 0) { Complete-IgwtCli 5 }
            Complete-IgwtCli 0
        }
        'Platform' {
            $st = Get-IgwtManagementState
            if ($Json) { $st | ConvertTo-Json -Depth 4; exit 0 }
            Format-IgwtManagementState -State $st | ForEach-Object { Write-IgwtCliLine $_ ([ConsoleColor]::Gray) }
            $pp = Get-IgwtPersonaProfile
            Write-IgwtCliLine ("  Persona:              {0} ({1})" -f $pp.Name, $pp.Hint) ([ConsoleColor]::Gray)
            exit 0
        }
        'Persona' {
            if ($DryRun) { Write-IgwtCliLine "Would set the persona to $Persona." ([ConsoleColor]::White); exit 0 }
            Set-IgwtPersona -Name $Persona
            Write-IgwtCliLine "Persona set to $Persona. $((Get-IgwtPersonaProfile -Name $Persona).Hint)" ([ConsoleColor]::Green)
            exit 0
        }
        'ListPresets' {
            $rows = @(Get-IgwtPreset | ForEach-Object {
                    $sel = Resolve-IgwtPresetSelection -Preset $_
                    [pscustomobject]@{ Code = $(if ($_.PSObject.Properties['code'] -and $_.code) { $_.code } else { '+' }); Id = $_.id; Name = $_.name; Custom = [bool]($_.PSObject.Properties['custom'] -and $_.custom)
                        Session = [bool]($_.PSObject.Properties['session'] -and $_.session); Gaming = [bool]$_.gaming; LevelCeiling = $_.levelCeiling; Items = @($_.tweaks).Count; OnThisPc = @($sel.Ids).Count; Hint = $_.hint }
                })
            if ($Json) { $rows | ConvertTo-Json -Depth 3; exit 0 }
            foreach ($r in $rows) {
                Write-IgwtCliLine ("  [{0}] {1,-22} {2,-32} {3,3} items ({4} on this PC), ceiling {5}{6}{7}" -f $r.Code, $r.Id, $r.Name, $r.Items, $r.OnThisPc, $r.LevelCeiling, $(if ($r.Gaming) { ', gaming' } else { '' }), $(if ($r.Custom) { ', custom' } elseif ($r.Session) { ', temporary' } else { '' })) $(if ($r.Custom) { [ConsoleColor]::Cyan } else { [ConsoleColor]::White })
                Write-IgwtCliLine ("      {0}" -f $r.Hint) ([ConsoleColor]::DarkGray)
            }
            Write-IgwtCliLine ''
            Write-IgwtCliLine 'Preview with -Preset <id> -DryRun. Session Mode: -Session Start. Custom presets: -SavePreset <name> -BasedOn <id> [-AddItem ...] [-RemoveItem ...].' ([ConsoleColor]::White)
            exit 0
        }
        'Drift' {
            try { $d = Get-IgwtPresetDrift -Preset $Preset } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($Json) { $d | ConvertTo-Json -Depth 4; exit 0 }
            if (-not $d.HasPreset) { Write-IgwtCliLine $d.Message ([ConsoleColor]::Yellow); exit 0 }
            Write-IgwtCliLine ("Drift report for {0}{1}" -f $d.Name, $(if ($d.Applied) { " (applied $(([datetime]$d.Applied).ToString('g')))" } else { ' (compared with the preset as resolved for this PC)' })) ([ConsoleColor]::White)
            foreach ($x in $d.Drifted) { Write-IgwtCliLine ("  [{0}] {1,-38} {2}" -f $x.State, $x.Id, $x.Name) ([ConsoleColor]::Yellow) }
            Write-IgwtCliLine $d.Message $(if (@($d.Drifted).Count) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green })
            if (@($d.Drifted).Count) { Write-IgwtCliLine "Re-apply: -Preset $($d.Preset). Adopt as custom: -AdoptDrift <name>$(if (-not $d.FromRecord) { " -Preset $($d.Preset)" })." ([ConsoleColor]::White) }
            exit 0
        }
        'ExportPreset' {
            try { $out = Export-IgwtPreset -Name $ExportPreset -Path $PresetPath } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($Json) { [pscustomobject]@{ Path = $out } | ConvertTo-Json } else { Write-IgwtCliLine "Preset written to $out (with a SHA256 integrity field)." ([ConsoleColor]::Green) }
            exit 0
        }
        { $_ -in 'SavePreset', 'ImportPreset', 'RemovePreset', 'AdoptDrift' } {
            $op = $modes[0]
            $basedOnId = $(if ($BasedOn) { $BasedOn } else { 'balanced' })
            try {
                switch ($op) {
                    'SavePreset' { $null = Save-IgwtCustomPreset -Name $SavePreset -BasedOn $basedOnId -AddIds (Split-IgwtIdList $AddItem) -RemoveIds (Split-IgwtIdList $RemoveItem) -WhatIf }
                    'ImportPreset' { $null = Import-IgwtPreset -Path $ImportPreset -WhatIf }
                    'RemovePreset' { $null = Remove-IgwtCustomPreset -Name $RemovePreset -WhatIf }
                    'AdoptDrift' { $null = Save-IgwtDriftAsPreset -Name $AdoptDrift -Preset $Preset -WhatIf }
                }
            } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($DryRun) { Write-IgwtCliLine 'Dry run: the preset passed every rule; nothing was written.' ([ConsoleColor]::White); exit 0 }
            if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            $res = $null
            switch ($op) {
                'SavePreset' { $res = Save-IgwtCustomPreset -Name $SavePreset -BasedOn $basedOnId -AddIds (Split-IgwtIdList $AddItem) -RemoveIds (Split-IgwtIdList $RemoveItem) }
                'ImportPreset' { $res = Import-IgwtPreset -Path $ImportPreset }
                'RemovePreset' { Remove-IgwtCustomPreset -Name $RemovePreset }
                'AdoptDrift' { $res = Save-IgwtDriftAsPreset -Name $AdoptDrift -Preset $Preset }
            }
            if ($Json) { $res | ConvertTo-Json -Depth 4 } elseif ($res) { Write-IgwtCliLine ("Saved custom preset {0} ({1} items). Apply it with -Preset {0}." -f $res.id, @($res.tweaks).Count) ([ConsoleColor]::Green) } else { Write-IgwtCliLine 'Done.' ([ConsoleColor]::Green) }
            Complete-IgwtCli 0
        }
        'Session' {
            switch ($Session) {
                'Status' {
                    $st = Get-IgwtSessionState
                    if ($Json) { $st | ConvertTo-Json; exit 0 }
                    if (-not $st.Active) { Write-IgwtCliLine 'No Session Mode session is active.' ([ConsoleColor]::Gray) }
                    else { Write-IgwtCliLine ("Session active since {0} ({1}){2}" -f $st.Started.ToLocalTime().ToString('g'), $st.Owner, $(if ($st.Stale) { ". Stale: $($st.Reason) Run -Session Stop to restore your settings." } else { '' })) $(if ($st.Stale) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }) }
                    exit 0
                }
                'Start' {
                    try { $plan = Get-IgwtSessionPlan } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
                    $st = Get-IgwtSessionState
                    if ($st.Active) { Write-IgwtCliLine "A session is already active (started $($st.Started.ToLocalTime().ToString('g'))). End it with -Session Stop." ([ConsoleColor]::Yellow); exit 2 }
                    if ($DryRun) {
                        Write-IgwtPlan -Plan @(Get-IgwtPlan -Id $plan.Ids) -Title 'Session Mode dry run (nothing is changed)'
                        Write-IgwtCliLine ("Power plan for the session: {0}" -f $(if ($plan.PowerPlan) { $plan.PowerPlan } else { 'unchanged (blocked by the hardware overlays)' })) ([ConsoleColor]::Gray)
                        Write-IgwtCliLine ("Running apps from the close list: {0}" -f $(if (@($plan.Apps).Count) { (@($plan.Apps | ForEach-Object { $_.Name }) -join ', ') + ' (closed only with -CloseApps)' } else { 'none' })) ([ConsoleColor]::Gray)
                        exit 0
                    }
                    if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
                    $close = @(); if ($CloseApps) { $close = @($plan.Apps | ForEach-Object { $_.Name }) }
                    $res = Start-IgwtSession -CloseApps $close -Owner cli
                    if ($Json) { $res | ConvertTo-Json -Depth 5 } else {
                        Write-IgwtResult -Result $res
                        foreach ($c in @($res.Closed)) { Write-IgwtCliLine ("[{0}] {1} {2}" -f $c.Result, $c.Name, $c.Message) ([ConsoleColor]::Gray) }
                        Write-IgwtCliLine 'Session started. End it with -Session Stop; after a restart, the next start of iG Windows Tuner offers to restore it.' ([ConsoleColor]::White)
                    }
                    Complete-IgwtCli (Get-IgwtExitCode -Result $res)
                }
                'Stop' {
                    if ($DryRun) { $st = Get-IgwtSessionState; Write-IgwtCliLine $(if ($st.Active) { "Would restore the settings from $($st.Snapshot)." } else { 'No session is active.' }); exit 0 }
                    if (-not (Get-IgwtSessionState).Active) { Write-IgwtCliLine 'No Session Mode session is active.' ([ConsoleColor]::Gray); exit 6 }
                    if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
                    $res = Stop-IgwtSession
                    Write-IgwtResult -Result $res
                    Complete-IgwtCli (Get-IgwtExitCode -Result $res)
                }
            }
        }
        'Toolkit' {
            switch ($Toolkit) {
                'Apps' {
                    $rows = @(Get-IgwtToolkitApps -Search $Search -WithState:(-not $Quick))
                    if ($Json) { $rows | ConvertTo-Json -Depth 4; exit 0 }
                    if (@($rows | Where-Object { $_.StateNote }).Count) { Write-IgwtCliLine "Installed state unavailable: $(@($rows)[0].StateNote)" ([ConsoleColor]::Yellow) }
                    foreach ($g in @($rows | Group-Object Category)) {
                        Write-IgwtCliLine ''
                        Write-IgwtCliLine $g.Name ([ConsoleColor]::White)
                        foreach ($a in $g.Group) {
                            $st = $(if ($null -eq $a.Installed) { '' } elseif ($a.Installed) { "[installed $($a.Version)]" } else { '' })
                            Write-IgwtCliLine ("  {0,-40} {1,-26} {2}" -f $a.Id, $a.Name, $st) $(if ($a.Installed) { [ConsoleColor]::Green } else { [ConsoleColor]::Gray })
                            Write-IgwtCliLine ("      {0}" -f $a.Hint) ([ConsoleColor]::DarkGray)
                        }
                    }
                    Write-IgwtCliLine ''
                    Write-IgwtCliLine 'Install with -Install <id[,id]> (-DryRun to preview). The first install shows winget''s agreements and needs -AcceptAgreements.' ([ConsoleColor]::White)
                }
                'Features' {
                    $rows = @(Get-IgwtToolkitFeatures -WithState)
                    if ($Json) { $rows | ConvertTo-Json -Depth 5; exit 0 }
                    foreach ($f in $rows) {
                        $st = $(if (-not $f.Supported) { 'not on this edition' } elseif ($f.State -eq 'On') { 'enabled' } elseif ($f.State -eq 'Off') { 'disabled' } elseif ($f.State -eq 'Partial') { 'partly enabled' } else { 'unknown (run elevated to read)' })
                        Write-IgwtCliLine ("  {0,-28} {1,-34} {2}" -f $f.Id, $f.Name, $st) $(if ($f.State -eq 'On') { [ConsoleColor]::Green } else { [ConsoleColor]::Gray })
                        Write-IgwtCliLine ("      {0}" -f $f.Hint) ([ConsoleColor]::DarkGray)
                        if ($f.Warning) { Write-IgwtCliLine ("      Warning: {0}" -f $f.Warning) ([ConsoleColor]::Yellow) }
                    }
                    Write-IgwtCliLine ''
                    Write-IgwtCliLine 'Change with -EnableFeature <id> or -DisableFeature <id> (-DryRun to preview); each change writes a snapshot.' ([ConsoleColor]::White)
                }
                'Fixes' {
                    $rows = @(Get-IgwtToolkitFixes)
                    if ($Json) { $rows | ConvertTo-Json -Depth 4; exit 0 }
                    foreach ($x in $rows) {
                        Write-IgwtCliLine ''
                        Write-IgwtCliLine ("{0,-26} {1}{2}{3}" -f $x.Id, $x.Name, $(if ($x.Admin) { '  [admin]' } else { '' }), $(if ($x.Reboot) { '  [reboot]' } else { '' })) ([ConsoleColor]::White)
                        Write-IgwtCliLine ("  {0}" -f $x.Hint) ([ConsoleColor]::Gray)
                        foreach ($s in $x.Steps) { Write-IgwtCliLine ("    - {0}" -f $s) ([ConsoleColor]::DarkGray) }
                        if ($x.Warning) { Write-IgwtCliLine ("  Warning: {0}" -f $x.Warning) ([ConsoleColor]::Yellow) }
                    }
                    Write-IgwtCliLine ''
                    Write-IgwtCliLine 'Run one with -Fix <id> (-DryRun shows the steps only).' ([ConsoleColor]::White)
                }
                'Panels' {
                    $rows = @(Get-IgwtToolkitPanels)
                    if ($Json) { $rows | ConvertTo-Json -Depth 3; exit 0 }
                    foreach ($p in $rows) { Write-IgwtCliLine ("  {0,-30} {1,-40} {2}" -f $p.Id, $p.Name, $p.Hint) ([ConsoleColor]::Gray) }
                    Write-IgwtCliLine ''
                    Write-IgwtCliLine 'Open one with -OpenPanel <id>.' ([ConsoleColor]::White)
                }
                { $_ -in 'Tweaks', 'Updates' } {
                    $items = $(if ($Toolkit -eq 'Tweaks') { @(Get-IgwtToolkitTweaks) } else { @(Get-IgwtToolkitUpdateItems) })
                    $states = @{}
                    foreach ($s in @(Get-IgwtAllTweakStates -Id @($items | ForEach-Object { $_.id }))) { $states[$s.Id] = $s }
                    $rows = @($items | ForEach-Object { [pscustomobject]@{ Id = $_.id; Name = $_.name; Category = $_.category; Level = $_.level; Tier = $_.tier; State = $states[$_.id].State; Hint = $_.hint; Attribution = $_.attribution } })
                    if ($Json) { $rows | ConvertTo-Json -Depth 3; exit 0 }
                    foreach ($r in $rows) {
                        Write-IgwtCliLine ("  {0,-36} {1,-15} {2,-9} T{3}  {4}" -f $r.Id, $r.State, $r.Level, $r.Tier, $r.Name) (Get-IgwtStateColor $r.State)
                        Write-IgwtCliLine ("      {0}" -f $r.Hint) ([ConsoleColor]::DarkGray)
                    }
                    Write-IgwtCliLine ''
                    if ($Toolkit -eq 'Updates') { Write-IgwtCliLine 'iG Windows Tuner never disables Windows Update. Pause updates natively with -OpenPanel panel.windows-update; -ResetDefault <id> restores Windows defaults.' ([ConsoleColor]::White) }
                    else { Write-IgwtCliLine 'These items are derived from WinUtil (docs\WINUTIL_MAPPING.md) and also appear in their categories. Apply with -Apply <id> (-DryRun to preview).' ([ConsoleColor]::White) }
                }
            }
            exit 0
        }
        'ExportAppList' {
            try { $out = Export-IgwtAppSelection -Path $ExportAppList -Id (Split-IgwtIdList $AppId) }
            catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($Json) { [pscustomobject]@{ Path = $out } | ConvertTo-Json } else { Write-IgwtCliLine "App selection written to $out" ([ConsoleColor]::Green) }
            exit 0
        }
        'OpenPanel' {
            try {
                if ($DryRun) { $p = @(Get-IgwtToolkitPanels | Where-Object { $_.Id -eq $OpenPanel }); if (-not $p) { throw "Unknown panel '$OpenPanel'." }; Write-IgwtCliLine "Would open: $($p[0].Name) ($($p[0].Command))"; exit 0 }
                Start-IgwtPanel -Id $OpenPanel
            } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            exit 0
        }
        { $_ -in 'Install', 'Uninstall', 'Upgrade', 'UpgradeAll' } {
            $op = $modes[0]
            $list = @()
            try {
                if ($AppList) { $list = @(Import-IgwtAppSelection -Path $AppList) }
                switch ($op) { 'Install' { $list += @(Split-IgwtIdList $Install) } 'Uninstall' { $list += @(Split-IgwtIdList $Uninstall) } 'Upgrade' { $list += @(Split-IgwtIdList $Upgrade) } }
                $list = @($list | Select-Object -Unique)
                if ($op -ne 'UpgradeAll' -and $list.Count -eq 0) { throw 'No package ids given.' }
            } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            $known = @{}
            foreach ($a in @(Get-IgwtToolkitApps)) { $known[$a.Id] = $a }
            if ($DryRun) {
                Write-IgwtCliLine "Dry run: winget $($op.ToLowerInvariant()) (nothing is changed):" ([ConsoleColor]::White)
                if ($op -eq 'UpgradeAll') { Write-IgwtCliLine '  every installed package from the winget source' }
                foreach ($i in $list) { Write-IgwtCliLine ("  {0,-40} {1}" -f $i, $(if ($known.ContainsKey($i)) { $known[$i].Name } else { '(not in the curated list)' })) }
                exit 0
            }
            if ($op -ne 'Uninstall' -and -not $AcceptAgreements -and -not (Test-IgwtWingetConsent)) {
                Write-IgwtCliLine 'Before the first install or upgrade, read winget''s agreements:' ([ConsoleColor]::White)
                foreach ($l in (Get-IgwtWingetAgreements).Lines) { Write-IgwtCliLine "  - $l" ([ConsoleColor]::Gray) }
                Write-IgwtCliLine 'Run the command again with -AcceptAgreements if you accept them.' ([ConsoleColor]::Yellow)
                exit 2
            }
            if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            if ($AcceptAgreements -and -not (Test-IgwtWingetConsent)) { Set-IgwtWingetConsent }
            if ($op -eq 'UpgradeAll') {
                $r = Invoke-IgwtWingetUpgradeAll -AcceptAgreements:$AcceptAgreements
                if ($Json) { $r | ConvertTo-Json } else { Write-IgwtCliLine $r.Output; Write-IgwtCliLine "winget upgrade --all: $($r.Result)" $(if ($r.Result -eq 'Failed') { [ConsoleColor]::Red } else { [ConsoleColor]::Green }) }
                Complete-IgwtCli $(if ($r.Result -eq 'Failed') { 5 } else { 0 })
            }
            $res = @(Invoke-IgwtToolkitApp -Operation $op -Id $list -AcceptAgreements:$AcceptAgreements)
            if ($Json) { $res | ConvertTo-Json -Depth 3 } else {
                foreach ($r in $res) { Write-IgwtCliLine ("{0,-18} {1} {2}" -f "[$($r.Result)]", $r.Id, $r.Message) $(if ($r.Result -eq 'Failed') { [ConsoleColor]::Red } else { [ConsoleColor]::Green }) }
            }
            Complete-IgwtCli $(if (@($res | Where-Object { $_.Result -eq 'Failed' }).Count) { 5 } else { 0 })
        }
        'Fix' {
            try { $plan = Get-IgwtToolkitFixPlan -Id $Fix } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($Json -and $DryRun) { $plan | ConvertTo-Json -Depth 3; exit 0 }
            if (-not $Json) {
                Write-IgwtCliLine ("{0}: {1}" -f $plan.Name, $plan.Hint) ([ConsoleColor]::White)
                foreach ($s in $plan.Steps) { Write-IgwtCliLine "  - $s" ([ConsoleColor]::Gray) }
                if ($plan.Warning) { Write-IgwtCliLine "Warning: $($plan.Warning)" ([ConsoleColor]::Yellow) }
                Write-IgwtCliLine "Source: $($plan.Source)" ([ConsoleColor]::DarkGray)
            }
            if ($DryRun) { Write-IgwtCliLine 'Dry run: nothing was run.' ([ConsoleColor]::White); exit 0 }
            if ($plan.Admin -and -not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            $r = Invoke-IgwtToolkitFix -Id $Fix
            if ($Json) { $r | ConvertTo-Json -Depth 4 } else {
                foreach ($s in $r.Steps) {
                    Write-IgwtCliLine ("{0,-14} {1}" -f "[$($s.Result)]", $s.Step) $(if ($s.Result -eq 'Failed') { [ConsoleColor]::Red } elseif ($s.Result -eq 'NotRun') { [ConsoleColor]::DarkGray } else { [ConsoleColor]::Green })
                    if ($s.Output) { Write-IgwtCliLine ($s.Output -replace '(?m)^', '      ') ([ConsoleColor]::DarkGray) }
                }
                Write-IgwtCliLine "Result: $($r.Result)" ([ConsoleColor]::White)
                if ($r.RebootRequired) { Write-IgwtCliLine 'A REBOOT is required to finish this fix.' ([ConsoleColor]::Yellow) }
            }
            if ($r.Result -eq 'Failed') { Complete-IgwtCli 5 }
            Complete-IgwtCli $(if ($r.RebootRequired) { 3010 } else { 0 })
        }
        { $_ -in 'EnableFeature', 'DisableFeature' } {
            $fid = $(if ($EnableFeature) { $EnableFeature } else { $DisableFeature })
            $want = $(if ($EnableFeature) { 'Enabled' } else { 'Disabled' })
            try {
                $f = @(Get-IgwtToolkitFeatures | Where-Object { $_.Id -eq $fid }) | Select-Object -First 1
                if (-not $f) { throw "Unknown Toolkit feature '$fid'. Use -Toolkit Features to list them." }
                $value = $(if ($f.Kind -eq 'capability') { $(if ($want -eq 'Enabled') { 'Installed' } else { 'NotPresent' }) } else { $want })
                $plans = @(foreach ($t in $f.Targets) { Get-IgwtManagedChangePlan -Kind $f.Kind -Target $t -Value $value })
            } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); exit 2 }
            if ($DryRun) {
                if ($Json) { $plans | ConvertTo-Json -Depth 3; exit 0 }
                Write-IgwtCliLine "Dry run: $($f.Name) -> $want (nothing is changed):" ([ConsoleColor]::White)
                foreach ($p in $plans) { Write-IgwtCliLine ("  {0}" -f $p.Change) $(if ($p.HasChange) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }) }
                if ($f.Reboot) { Write-IgwtCliLine '  A restart is needed afterwards.' ([ConsoleColor]::DarkGray) }
                exit 0
            }
            if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }
            try { $r = Invoke-IgwtToolkitFeature -Id $fid -State $want } catch { Write-IgwtCliLine "Refused: $($_.Exception.Message)" ([ConsoleColor]::Red); Complete-IgwtCli 2 }
            if ($Json) { $r | ConvertTo-Json -Depth 4 } else {
                foreach ($x in $r.Results) { Write-IgwtCliLine ("{0,-12} {1} {2}" -f "[$($x.Result)]", $x.Change, $x.Message) $(if ($x.Result -eq 'Failed') { [ConsoleColor]::Red } else { [ConsoleColor]::Green }) }
                if ($r.RebootRequired) { Write-IgwtCliLine 'A REBOOT is required to finish this change.' ([ConsoleColor]::Yellow) }
            }
            if (@($r.Results | Where-Object { $_.Result -eq 'Failed' }).Count) { Complete-IgwtCli 5 }
            Complete-IgwtCli $(if ($r.RebootRequired) { 3010 } else { 0 })
        }
    }

    # Modes below change the system (unless -DryRun).
    $ids = @()
    $operation = 'Apply'
    $mode = 'on'
    switch ($modes[0]) {
        'Preset' {
            try { $presetObj = Get-IgwtPreset -Name $Preset } catch { Write-IgwtCliLine $_.Exception.Message ([ConsoleColor]::Red); exit 2 }
            if ($presetObj.PSObject.Properties['session'] -and $presetObj.session) { Write-IgwtCliLine 'Session Mode is temporary: start it with -Session Start (and end it with -Session Stop).' ([ConsoleColor]::Yellow); exit 2 }
            $presetSelection = Resolve-IgwtPresetSelection -Preset $presetObj -AddIds (Split-IgwtIdList $AddItem) -RemoveIds (Split-IgwtIdList $RemoveItem)
            $ids = @($presetSelection.Ids); $operation = "Preset:$($presetObj.id)"
        }
        'Apply' { $ids = Split-IgwtIdList $Apply }
        'ResetDefault' { $ids = Split-IgwtIdList $ResetDefault; $operation = 'ResetDefault'; $mode = 'default' }
        'Revert' { $ids = Split-IgwtIdList $Revert }
    }
    if ($ids.Count -gt 0) {
        try { $null = Get-IgwtTweak -Id $ids } catch { Write-IgwtCliLine $_.Exception.Message ([ConsoleColor]::Red); exit 2 }
    }

    if ($DryRun) {
        if ($modes[0] -in 'Revert', 'RevertAll') {
            $list = @()
            if ($modes[0] -eq 'Revert') {
                foreach ($i in $ids) {
                    $snaps = @(Get-IgwtSnapshotList | Where-Object { $_.Applied -contains $i } | Select-Object -First 1)
                    $list += [pscustomobject]@{ Id = $i; Snapshot = $(if ($snaps) { $snaps[0].File } else { '(none - nothing to revert)' }) }
                }
            } else {
                $src = $null
                if ($Snapshot) { $src = Get-IgwtSnapshotList | Where-Object { $_.Path -eq (Resolve-Path $Snapshot).Path } | Select-Object -First 1 }
                else { $src = @(Get-IgwtSnapshotList | Where-Object { ($_.Operation -split ':')[0] -in 'Apply', 'Preset', 'ResetDefault' -and $_.Applied.Count -gt 0 }) | Select-Object -First 1 }
                if ($src) { foreach ($i in $src.Applied) { $list += [pscustomobject]@{ Id = $i; Snapshot = $src.File } } }
            }
            if ($Json) { $list | ConvertTo-Json } else {
                Write-IgwtCliLine 'Dry run: these tweaks would be restored from their snapshots (nothing is changed):' ([ConsoleColor]::White)
                if ($list.Count -eq 0) { Write-IgwtCliLine '  (nothing to revert)' }
                foreach ($l in $list) { Write-IgwtCliLine ("  {0,-38} from {1}" -f $l.Id, $l.Snapshot) }
            }
            exit 0
        }
        $title = "iG Windows Tuner dry run - $operation (no changes will be made)"
        if ($modes[0] -eq 'Preset') {
            $ctx = New-IgwtContext
            $plan = @(Get-IgwtPresetPlan -Preset $presetObj.id -Context $ctx -AddIds (Split-IgwtIdList $AddItem) -RemoveIds (Split-IgwtIdList $RemoveItem))
            foreach ($gl in @($presetObj.guidance | Where-Object { $_ })) { Write-IgwtCliLine "Guidance: $gl" ([ConsoleColor]::Cyan) }
            Write-IgwtPlan -Plan $plan -Title $title -Selection $presetSelection
        } else {
            $plan = @(Get-IgwtPlan -Id $ids -Mode $mode)
            Write-IgwtPlan -Plan $plan -Title $title
        }
        exit 0
    }

    if (-not (Test-IgwtIsAdmin)) { Request-IgwtCliElevation -Bound $PSBoundParameters }

    $result = $null
    switch ($modes[0]) {
        'Revert' { $result = Invoke-IgwtRevert -Id $ids }
        'RevertAll' {
            if ($Snapshot) { $result = Invoke-IgwtRevert -SnapshotPath (Resolve-Path $Snapshot).Path }
            else { $result = Invoke-IgwtRevert -Last }
        }
        default {
            $result = Invoke-IgwtApply -Id $ids -Operation $operation -Mode $mode -SkipRestorePoint:$SkipRestorePoint -EnableSystemProtection:$EnableSystemProtection -AcknowledgeRisk:$AcknowledgeRisk -AcknowledgeManaged:$AcknowledgeManaged
        }
    }
    if ($modes[0] -in 'Revert', 'RevertAll' -and @($result.Results).Count -eq 0) {
        Write-IgwtCliLine 'Nothing to revert.' ([ConsoleColor]::Yellow)
        Complete-IgwtCli 6
    }
    Write-IgwtResult -Result $result
    Complete-IgwtCli (Get-IgwtExitCode -Result $result)
} catch {
    $msg = $_.Exception.Message
    Write-IgwtCliLine "Error: $msg" ([ConsoleColor]::Red)
    try { Write-IgwtLog -Level Error -Message "CLI error: $msg" } catch { Write-Verbose 'Logging failed.' }
    if ($msg -match 'System Protection is off|older than') { Complete-IgwtCli 4 }
    if ($msg -match 'Unknown tweak id|conflict|expert toggle') { Complete-IgwtCli 2 }
    Complete-IgwtCli 1
}
