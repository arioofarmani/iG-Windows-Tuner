# Command-line reference

`iGWindowsTuner.ps1` without parameters opens the GUI. Every GUI feature has a command-line equivalent; `-Json` gives machine-readable output for the read-only modes, and `-DryRun` previews every change mode without changing anything. Read-only modes need no elevation; change modes ask for administrator rights through UAC. Choose one mode per call.

This page is generated from the script's comment-based help (`Get-Help .\iGWindowsTuner.ps1 -Full`).

## Read-only reports

| Parameter | Description |
|---|---|
| `-Report` | Read-only health and anti-cheat readiness report. |
| `-ReportPath` | With -Report: also write the report to this .html or .json file. |
| `-ListTweaks` | List every tweak with tier, risk, presets and current state. |
| `-Hardware` | Read-only hardware profile: detected hardware tags, the facts behind them and the hardware overlays that adjust presets on this PC. With -Json it prints the facts (usable as a test fixture). |
| `-Json` | Machine-readable output for -Report, -ListTweaks, -DryRun, -Clean and -Analyze. |
| `-SecurityScore` | Read-only security score with the fix for every failed check, plus the local accounts audit. |
| `-NetworkSurface` | Read-only listening-ports report: programs that accept connections and on which interfaces. |
| `-Inspect` | Read-only expert inspectors: All, Power (processor power settings of the active plan, hidden ones included), Interrupts (PCI interrupt modes and affinity), Network (RSS, queues, buffers), Kernel (kernel and memory registry values with Windows defaults), Timer, Crash (dumps, page file). |
| `-Inventory` | Read-only management views: Services (with the safe-to-change rating), Tasks, Apps, Features (administrator), Firewall (rule browser), Hosts (hosts-file viewer), Adapters (every advanced property with a description). Filter rows with -Search. |
| `-Search` | With -Inventory: show only rows whose name, display name, path or program contains this text. |
| `-Persistence` | Read-only Persistence Inspector (Autoruns-style) with signature status. -ReportPath exports it (.html or .json); -IncludeMicrosoft also lists Microsoft-signed services, drivers and tasks. |
| `-IncludeMicrosoft` | With -Persistence: include Microsoft-signed entries (slower). |
| `-Updates` | Read-only Windows Update status: services, pending restart, Windows Update for Business policies, history. |
| `-Diagnostics` | Read-only diagnostics: All, DpcIsr, Reliability, Crashes, Boot, Drivers. -Days sets the history window. |
| `-Days` | With -AsrAudit: how many days of events to read (1-90, default 14). |
| `-SystemReport` | Full read-only system report written to -ReportPath (.html or .json). -Quick skips the slow sections. |
| `-Quick` | With -SystemReport: skip persistence signatures and DPC sampling. |
| `-RiskZone` | Lists every rejected tweak: the ones you can apply at your own risk (with warnings and what they turn off or on) and the ones that are not offered, with the reason. Read-only. |
| `-NoGui` | Never start the GUI (prints help when no mode is given). |

## Tweaks, presets and revert

| Parameter | Description |
|---|---|
| `-Apply` | Apply the given tweak ids. |
| `-Preset` | Apply a preset by id or name: competitive, balanced, hardened, streamer, engineer, laptop, privacy-max, debloat, fortress, or a custom preset (custom-...). -ListPresets lists them. With -Drift, the preset to compare against. Session Mode is started with -Session Start instead. |
| `-AddItem` | With -Preset or -SavePreset: items to add to the preset. |
| `-RemoveItem` | With -Preset or -SavePreset: items to leave out. |
| `-ListPresets` | Lists every preset (built-in and custom) with its item count and rules. Read-only. |
| `-Revert` | Revert the given tweak ids from their most recent apply. |
| `-RevertAll` | Revert every tweak of the most recent apply, or of -Snapshot. |
| `-Snapshot` | Snapshot file for -RevertAll. |
| `-ResetDefault` | Reset the given tweak ids to the documented Windows defaults. |
| `-DryRun` | Show exactly what would change and change nothing. |
| `-SkipRestorePoint` | Do not create a System Restore point (the JSON snapshot is always written). |
| `-EnableSystemProtection` | Consent to turn on System Protection for the system drive if a restore point cannot be created. |
| `-AcknowledgeRisk` | Required to apply expert toggles (for example turning VBS/HVCI off). |

## Custom presets and drift

| Parameter | Description |
|---|---|
| `-SavePreset` | Saves a custom preset with this name: -BasedOn <preset> plus -AddItem and minus -RemoveItem (without changes it duplicates the preset). The preset rules are checked first. |
| `-BasedOn` | The preset a custom preset starts from (default balanced). |
| `-ExportPreset` | Writes this preset to -PresetPath as JSON with a SHA256 integrity field. |
| `-PresetPath` | File for -ExportPreset. |
| `-ImportPreset` | Imports a preset file (checked against its SHA256 field and the preset rules) as a custom preset. |
| `-RemovePreset` | Deletes a custom preset. |
| `-Drift` | Drift report: which items of the last applied preset (or -Preset) changed since. Read-only. |
| `-AdoptDrift` | Saves the drifted state as a custom preset with this name (the preset minus the changed items). |

## Session Mode

| Parameter | Description |
|---|---|
| `-Session` | Session Mode (Tournament/LAN): Start applies the temporary session items with a snapshot, Stop restores them, Status shows the session. -DryRun with Start shows the plan. |
| `-CloseApps` | With -Session Start: also close the running apps from the Session Mode list. |

## Platform, management and personas

| Parameter | Description |
|---|---|
| `-Platform` | Read-only platform and management report: edition family, Local Group Policy support, domain and Entra ID join, MDM enrollment, Defender for Endpoint, other antivirus and whether policy items are report-only on this PC. |
| `-AcknowledgeManaged` | On a domain-joined or MDM-enrolled PC, policy items are report-only. This switch confirms local changes that a domain or MDM policy may override (with -Apply or -Preset). |
| `-Persona` | Sets your persona for the GUI (Gamer, PowerUser or Sysadmin): it changes the navigation order and which item levels are shown, never a safety rule. |

## Group Policy

| Parameter | Description |
|---|---|
| `-PolicySearch` | Searches every installed ADMX policy by name, explain text or registry path (words are ANDed). -PolicyClass Machine or User filters. Read-only; the first run parses the definitions (cached). |
| `-PolicyClass` | Machine or User, with -PolicySearch, -PolicyShow or -PolicySet. |
| `-PolicyShow` | Shows one policy (id such as WindowsUpdate:DeferFeatureUpdates): explain text, elements, registry mapping and the effective state and source (Local GPO, registry, domain GPO, MDM). |
| `-PolicySet` | Sets a policy in the Local Group Policy Object: backup, Registry.pol, gpt.ini, gpupdate and verification. Needs -PolicyState; -DryRun shows the Registry.pol operations only. Policy values that turn off a security protection are refused. |
| `-PolicyState` | Enabled, Disabled or NotConfigured, with -PolicySet. |
| `-PolicyValue` | Element values for -PolicySet as "elementId=value;elementId2=value" (list values separated by \|). |
| `-PolicyBackup` | Backs up the Local Group Policy folders to the data root. |
| `-PolicyRestore` | Restores the Local Group Policy folders from a backup folder and refreshes policy. |
| `-PolicyReset` | Resets Local Group Policy to default after a backup (-DryRun shows the files and steps). |
| `-PolicyTattoo` | Lists values under the Policies keys that no Registry.pol or domain GPO sets (tattooed values). Read-only. |
| `-PolicyAdopt` | Adds tattooed machine values (from -PolicyTattoo) to the Local GPO, as "Key\ValueName;..." or igwt for every value an iG Windows Tuner item wrote. A GPO backup is taken first; values that would keep a security protection off are refused. Use -DryRun first. |
| `-PolicyRemoveTattoo` | Deletes tattooed machine values from the registry ("Key\ValueName;..." or igwt), after saving them to a restore file. Use -DryRun first. |
| `-TattooRestore` | Writes back values removed by -PolicyRemoveTattoo from its restore file. |
| `-PolicyPreset` | A category policy preset (list shows them): ADMX policies, documented policy values, audit and security settings applied as one batch with backups. Use -DryRun first. |
| `-PolicyPresetRestore` | Reverts a policy preset or baseline apply from the record file it printed. |
| `-PolicyExport` | Exports a policy preset for deployment; needs -ExportFormat (GpoBackup, Reg, Script, Json) and -ExportPath. |
| `-ExportFormat` | GpoBackup (LGPO-style folder), Reg, Script or Json, with -PolicyExport. |
| `-ExportPath` | Folder for -PolicyExport. |
| `-Baseline` | Compares a security baseline or GPO backup folder (registry.pol, GptTmpl.inf, audit.csv) with this PC; -ReportPath writes the comparison as CSV. Read-only. |
| `-BaselineApply` | Applies baseline settings from -Baseline: "differs" for every setting that differs or is not set, or Ref values from the comparison separated by ;. Use -DryRun first. |
| `-AdmxFolder` | Extra ADMX folders (for example Edge, Chrome or Office templates) for the policy catalog. |

## Security policy and auditing

| Parameter | Description |
|---|---|
| `-SecPolicy` | Shows the local security policy: account policies, user rights assignment and security options (secedit /export to a temporary file). Read-only; asks for administrator rights. |
| `-SecPolicySet` | Changes security policy settings, as "Section\Key=Value;..." with the sections SystemAccess, PrivilegeRights (accounts separated by \|, names or *SIDs) and RegistryValues (type,value). Lockout safeguards refuse changes that would lock out you or the administrators. Use -DryRun first. |
| `-SecPolicyRestore` | Restores the settings a -SecPolicySet backup folder changed. |
| `-AuditPolicy` | Shows the advanced audit policy per subcategory (auditpol /get). Read-only; asks for administrator rights. |
| `-AuditSet` | Changes audit subcategories, as "Subcategory name or {GUID}=None\|Success\|Failure\|SuccessAndFailure;...". A backup is taken first. Use -DryRun first. |
| `-AuditImport` | Applies an audit.csv (Group Policy backup or security baseline format); -DryRun shows the differences. |
| `-AuditExport` | Writes the current audit policy as audit.csv to this path. |
| `-AuditRestore` | Restores the audit policy from an -AuditSet or -AuditImport backup folder. |

## Cleaner and disk

| Parameter | Description |
|---|---|
| `-Clean` | Cleaning engine. With -Scan (or -DryRun) it only enumerates and sizes (read-only). Without it, it scans, shows the result and deletes only what the scan found after you type YES (or -Yes). |
| `-Scan` | With -Clean: scan only; nothing is deleted. |
| `-CleanRule` | With -Clean: rule ids to use (default: the rules that are on by default up to -CleanLevel). |
| `-CleanLevel` | With -Clean: highest rule level to include (Standard, Advanced, Expert). |
| `-IncludeOptIn` | With -Clean: include rules that are off by default. |
| `-AllUsers` | With -Clean: expand per-user rules to every local profile (requires administrator rights). |
| `-Yes` | With -Clean: skip the YES confirmation (needed with -Json). |
| `-Analyze` | Read-only disk analyzer: largest folders and files under this folder or drive. |
| `-Top` | With -Analyze: number of folders and files to list. |

## ASR Center

| Parameter | Description |
|---|---|
| `-Asr` | ASR Center. Alone it lists every attack surface reduction rule with its mode, recommendation, gamer impact and exclusions (read-only). With -AsrMode, -AsrRecommended, -AsrExclude or -AsrUnexclude it changes rules or exclusions after writing a snapshot (-DryRun shows the plan). |
| `-AsrRule` | With -Asr: the rule (key such as 'psexec-wmi' or GUID) to show, set or exclude for. |
| `-AsrMode` | With -Asr -AsrRule: NotConfigured, Audit, Warn or Block. |
| `-AsrRecommended` | With -Asr: raise every rule that is below its recommended mode (never lowers a rule). |
| `-AsrExclude` | With -Asr: paths to exclude. With -AsrRule only from that rule, otherwise from all ASR rules. Separate several paths with '\|'. |
| `-AsrUnexclude` | With -Asr: paths to remove from the same exclusion list. |
| `-AsrAudit` | Read-only ASR audit view: ASR, controlled folder access and network protection events grouped by rule and program, with recommendations. |

## Expert controls and management

| Parameter | Description |
|---|---|
| `-PowerSetting` | Power plan editor (Expert): the processor setting to change, by alias (for example PERFEPP). Use with -Ac, -Dc or -PowerDefault, and -AcknowledgeRisk. -DryRun validates and shows the change. |
| `-Ac` | With -PowerSetting: new plugged-in value. |
| `-Dc` | With -PowerSetting: new battery value. |
| `-PowerDefault` | With -PowerSetting: return the setting to the Windows default of the plan. |
| `-Change` | Snapshot-backed management change: service, task, appx, feature, capability or firewallRule. Needs -Target and -Value; protected targets are refused. -DryRun validates and shows the change. |
| `-Target` | With -Change: service name, full task path, package name, feature, capability or firewall rule name. |
| `-Value` | With -Change: service Automatic/AutomaticDelayed/Manual/Disabled; task, feature and firewall rule Enabled/Disabled; appx Removed; capability Installed/NotPresent. |
| `-Provisioned` | With -Change appx: also remove the provisioned copy (new user profiles do not get the app). |

## Network

| Parameter | Description |
|---|---|
| `-DnsBenchmark` | User-initiated DNS benchmark of the current DNS servers and public resolvers (uses the network, changes nothing). |
| `-Latency` | User-initiated latency, jitter and loss test to the host names or IP addresses you give. |
| `-NetworkTest` | Network quality test: latency, jitter, packet loss and stability to your router, ISP and the internet, path trace, path MTU, connection type guess and recommended Windows adjustments. Read-only (pings and DNS queries). -ReportPath saves an .html or .json report. |
| `-Duration` | With -NetworkTest: Quick (10 s), Standard (30 s, default) or Extended (2 minutes). |
| `-NetTarget` | With -NetworkTest: up to 4 extra hosts to measure, such as a game server. |
| `-UnderLoad` | With -NetworkTest: after the idle test, measure 20 s of latency while you run a speed test or large download, and grade bufferbloat. |

## Toolkit

| Parameter | Description |
|---|---|
| `-Toolkit` | Lists a Toolkit section: Apps (curated winget packages with installed versions; -Quick skips the winget inventory), Features, Fixes (with their steps), Panels, Tweaks (WinUtil-derived items) or Updates (Windows Update items). -Search filters Apps. Read-only. |
| `-Install` | winget package ids to install (from -Toolkit Apps or any valid id). Needs -AcceptAgreements the first time, after you have read the agreements that are printed. |
| `-Uninstall` | winget package ids to uninstall. |
| `-Upgrade` | winget package ids to upgrade. |
| `-UpgradeAll` | Upgrades every package from the winget source (winget upgrade --all). |
| `-AcceptAgreements` | You accept winget's package and source agreements (recorded for later installs). |
| `-AppList` | An app selection file (exported from the GUI or with -ExportAppList) to use with -Install, -Uninstall or -Upgrade; its SHA256 field is checked. |
| `-ExportAppList` | Writes the ids given with -AppId to an app selection file. |
| `-AppId` | winget ids for -ExportAppList. |
| `-Fix` | Runs a Toolkit fix (for example fix.sfc). -DryRun only shows its steps. |
| `-OpenPanel` | Opens an inbox Windows tool from -Toolkit Panels (for example panel.device-manager). |
| `-EnableFeature` | Enables a Toolkit feature (for example feature.wsl); snapshot-backed. -DryRun previews. |
| `-DisableFeature` | Disables a Toolkit feature; features other tools depend on (WSL, Virtual Machine Platform and the .NET Framework 4) are never disabled. -DryRun previews. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error |
| 2 | Invalid arguments, unknown id or refused by a rule |
| 3 | Elevation declined |
| 4 | Preflight refused (unsupported build, System Protection off) |
| 5 | One or more items, rules, packages or fix steps failed |
| 6 | Nothing to revert (or no active session) |
| 3010 | Success; a restart is required |

## Examples

```powershell
.\iGWindowsTuner.ps1 -Report
.\iGWindowsTuner.ps1 -Preset Competitive -DryRun
.\iGWindowsTuner.ps1 -Apply input.pointer-precision-off,gfx.game-mode
.\iGWindowsTuner.ps1 -RevertAll
.\iGWindowsTuner.ps1 -Clean -Scan -CleanLevel Advanced -IncludeOptIn
.\iGWindowsTuner.ps1 -Clean -CleanRule clean.user.temp,clean.gaming.nvidia-shader
.\iGWindowsTuner.ps1 -Analyze C:\ -Top 30
.\iGWindowsTuner.ps1 -Asr -AsrRecommended -DryRun
.\iGWindowsTuner.ps1 -Asr -AsrRule copied-system-tools -AsrExclude "D:\Games\MyGame\MyGame.exe"
.\iGWindowsTuner.ps1 -AsrAudit -Days 30
.\iGWindowsTuner.ps1 -Inspect Power,Interrupts
.\iGWindowsTuner.ps1 -PowerSetting PERFEPP -Ac 20 -AcknowledgeRisk -DryRun
.\iGWindowsTuner.ps1 -Inventory Services -Search xbox
.\iGWindowsTuner.ps1 -Change service -Target XblGameSave -Value Manual -DryRun
.\iGWindowsTuner.ps1 -Persistence -ReportPath "$env:USERPROFILE\Desktop\persistence.html"
.\iGWindowsTuner.ps1 -Diagnostics Crashes,Drivers -Days 60
.\iGWindowsTuner.ps1 -SystemReport -ReportPath "$env:USERPROFILE\Desktop\system-report.html"
.\iGWindowsTuner.ps1 -Latency 1.1.1.1,valve.net
.\iGWindowsTuner.ps1 -NetworkTest -Duration Extended -ReportPath "$env:USERPROFILE\Desktop\network.html"
.\iGWindowsTuner.ps1 -RiskZone
.\iGWindowsTuner.ps1 -Apply risk.tcp-autotuning-disabled -AcknowledgeRisk -DryRun
.\iGWindowsTuner.ps1 -ListPresets
.\iGWindowsTuner.ps1 -Preset streamer -DryRun
.\iGWindowsTuner.ps1 -SavePreset "My PC" -BasedOn balanced -AddItem system.long-paths -RemoveItem sec.llmnr-off
.\iGWindowsTuner.ps1 -Drift
.\iGWindowsTuner.ps1 -Session Start -DryRun
.\iGWindowsTuner.ps1 -Toolkit Apps -Search obs
.\iGWindowsTuner.ps1 -Install OBSProject.OBSStudio -DryRun
.\iGWindowsTuner.ps1 -Fix fix.sfc -DryRun
.\iGWindowsTuner.ps1 -EnableFeature feature.wsl -DryRun
.\iGWindowsTuner.ps1 -PolicySearch "defer feature"
.\iGWindowsTuner.ps1 -PolicyShow WindowsUpdate:DeferFeatureUpdates
.\iGWindowsTuner.ps1 -PolicySet WindowsUpdate:DeferFeatureUpdates -PolicyState Enabled -PolicyValue "DeferFeatureUpdatesPeriodId=90" -DryRun
```
