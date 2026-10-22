# Changelog

## Unreleased

### Interface

- New dark theme: calmer palette, softer amber warnings, rounded cards, dark check boxes, combo boxes and thin scroll bars.
- Dashboard redesigned for quick scanning: four status tiles (anti-cheat, security, system health, your changes), one numbered *Do this next* list with at most five items, and every detail section folded into a collapsible panel (problems listed first).
- The ASR Center is part of Security: it sits under Security in the menu for every persona, and both pages have a *Hardening items | ASR Center* switch.
- Manage: every tab has sortable column headers (click to sort, click again to reverse; sizes sort by value).

## 3.0.0 (2026-10-22)

3.0 preview release. The new features are available on the command line (`docs\CLI.md`); the GUI shows the 2.x features. A packet capture and a full network analyzer are not part of 3.0.

### Gaming network optimizer

- `-NetworkOptimize`: measures latency, jitter and loss to the router, the ISP, internet anchors and game servers, applies the Windows network settings and registry values that lower latency and jitter on that connection through the engine (restore point, snapshot), checks connectivity and reverts automatically when the network does not come back, then measures again and compares before and after. Interrupt moderation is turned off only on links up to 2.5 Gbit/s; DSCP marking only with `-RouterHonorsDscp`; refused in Remote Desktop sessions. `docs\NETWORK_GAMING.md`.

### Defender & Security Control Center (phase 7)

- `-DefenderCenter`: status and health (versions, signature age, Tamper Protection read-only, passive mode, Defender for Endpoint, management), every Defender setting with current value, status and source, exclusions audit with risk rating, firewall logging, web and phishing protection, device control and detection logging (Sysmon detected, never installed).
- Defender presets: Gaming-friendly, Microsoft Recommended, Strict and Audit / Evaluation; `-DefenderParsersOn` turns Network Inspection parsers on (never off).
- `-DefenderThreats`, `-DefenderScan` (Quick, Full, Custom, Offline with confirmation), `-QuarantineRestore` (with risk acknowledgement), `-RemoveExclusion` (removal only).
- Firewall as a detection source: `-FirewallLog` analyzer and export, Firewall Logging preset, `-OutboundAllowList` planning aid.
- Docs: `docs\DEFENDER_CENTER.md`, `docs\NETWORK_IDS_IPS.md`.

### Policy presets, baselines and exports (phase 6)

- **14 category policy presets** (`-PolicyPreset`): Privacy & Telemetry, three Windows Update rings (Pilot, Broad, Gaming), Defender Antivirus, Attack Surface, Microsoft Edge Security, Credentials & Authentication Hardening, Remote Access Lockdown, Removable Media, Audit & Logging, Kiosk / Shared Device, Developer Workstation and Secure Gaming PC. Applied as one batch with backups and verification; `-PolicyPresetRestore` reverts.
- **Exports** (`-PolicyExport -ExportFormat GpoBackup|Reg|Script|Json`).
- **Baseline import and compare** (`-Baseline`, `-BaselineApply`): Security Compliance Toolkit baselines and GPO backups, Policy Analyzer-style comparison with CSV export.
- Fix: policies whose element shares the policy value name (such as Join Microsoft MAPS) no longer plan two values.

### Policy items through the Local GPO (phase 5)

- Catalog items that write machine Policies keys now also write the Local GPO (Registry.pol and gpt.ini), so they appear in gpedit and survive policy refresh; snapshots capture the exact Registry.pol entries and v1/v2 snapshots still revert correctly.
- Tattooed values: `-PolicyAdopt` (into the Local GPO, with backup; denylisted values refused), `-PolicyRemoveTattoo` (with a restore file) and `-TattooRestore`. Windows-owned values under CurrentVersion\Policies are no longer reported as tattooed.

### Security policy and auditing (phase 4)

- **Security templates** (`-SecPolicy`, `-SecPolicySet`, `-SecPolicyRestore`): account policies, user rights assignment and security options through secedit, with an export snapshot before and a verification after every change.
- **Lockout safeguards**: logon rights for Administrators and you (Remote Desktop rights while connected remotely), deny rights, password expiry, lockout combinations, the last enabled administrator, and no weakening (Guest, reversible passwords, sensitive privileges for broad groups, denylisted security options).
- **Advanced audit policy** (`-AuditPolicy`, `-AuditSet`, `-AuditImport`, `-AuditExport`, `-AuditRestore`): per-subcategory changes with backup and verification, audit.csv import and export.

### Group Policy engine (phase 3)

- **ADMX catalog**: every installed policy (plus the Central Store and extra template folders) with category path, supported-on text, explain text, registry mapping and elements; cached per user. `-PolicySearch`, `-PolicyShow` (effective state and source: Local GPO, registry, domain GPO, MDM; conflicts; tattoo flag).
- **Registry.pol reader/writer** per [MS-GPREG] (byte-exact round trips, all special value names, corruption refused with the offset) and **gpt.ini** version and client-side extension updates.
- **`-PolicySet`**: backup, Registry.pol, gpt.ini, targeted gpupdate and verification, for every ADMX element type; security-disabling values are refused by `data\policy\denylist.json`. `-PolicyBackup`, `-PolicyRestore`, `-PolicyReset` (with backup), `-PolicyTattoo`.
- Docs: `docs\GROUP_POLICY.md`.
### Platform (phase 2)

- **Schema v3** for tweak files: `scope`, `editions`, `managedBy`, `gpoPath`, `admxRef`, `requiresDomain`, `requiresMdm`, with an in-memory and on-disk migration from v1/v2 (actions unchanged, snapshots stay valid). 26 items are marked as Group Policy items.
- **Management awareness** (`-Platform`): edition family and Local Group Policy support, domain and Entra ID join, MDM enrollment, Defender for Endpoint, Defender mode and other antivirus. On domain-joined or MDM-enrolled PCs, policy items are report-only unless the local change is acknowledged (`-AcknowledgeManaged`, or Yes in the GUI).
- **Personas** (Gamer, Power User, Sysadmin; header selector in the GUI, `-Persona`): navigation order and visible levels change; safety rules never do.
- Hardware detection failures now block overlay-guarded items (review L3).


## 2.3.0 (v2 final)

Completes the 2.x scope before 3.0 (audit: `docs\V3_STARTING_AUDIT.md`).

### Presets 2.0

- Seven new presets: **Streamer & Creator**, **Engineer Workstation**, **Laptop Gamer**, **Privacy Max**, **Clean Install / Debloat**, **Fortress** and **Session Mode** (ten in total, each with a one-letter code and guidance shown in dry runs).
- **Custom presets**: start from any preset, add or remove items (GUI builder, `-SavePreset -BasedOn -AddItem -RemoveItem`), duplicate, export and import as JSON with a SHA256 integrity field, delete. The built-in preset rules apply to them; changed files are skipped.
- **Drift report** (`-Drift`, Presets page banner): which items changed since the last applied preset; re-apply or adopt the current state as a custom preset (`-AdoptDrift`).
- **Session Mode** (`-Session Start|Stop|Status`, Presets page): notifications off, search indexing paused and the highest power plan the hardware allows, with a snapshot; ends with the session or when the app closes, and a stale session after a crash or restart is offered for restore. Listed background apps are closed only after confirmation.

### Toolkit (inspired by WinUtil)

- New **Toolkit** page and CLI (`-Toolkit Apps|Features|Fixes|Panels|Tweaks|Updates`): 92 curated winget packages (install, upgrade, uninstall, upgrade all, import/export of a selection with SHA256; winget's agreements are shown before the first install), Windows features and capabilities (WSL, Hyper-V, Sandbox, .NET 3.5, DirectPlay, NFS client, OpenSSH), 11 previewed fixes (SFC, DISM, chkdsk, Windows Update reset, network reset, winget, Store, Start and search, WMI, icon cache), 25 panel launchers and the Windows Update options.
- `docs\WINUTIL_MAPPING.md` maps every WinUtil item (commit d32efeb) to adopt, adapt, covered or reject; `THIRD_PARTY_NOTICES.md`.
- 23 new catalog items (127 in total), including the WinUtil-derived classic context menu, End task, file extensions, hidden files, Home/Gallery off, dark mode, long paths, Num Lock, activity history, location, consumer experiences, Bing in Start, device metadata, PowerShell telemetry, 365-day feature deferral, Teredo off and prefer IPv4, plus Edge and Microsoft 365 Apps privacy policies, consumer inbox app removal, the Safe Mode ASR rule and the two Session Mode items.

### Engine

- State scan: scheduled tasks and iG Windows Tuner firewall rules are read with one query each per scan (cached, invalidated on every write); warm rescans take about 4 s instead of 10-15 s.
- Edition gating: items honored only on some editions show "not effective on this edition".
- Registry actions: `bitSet`, the key default value (`(default)`) and `HKU:\.DEFAULT` (sign-in screen).
- Protected features can be enabled but never disabled.

### Independent review

- `docs\REVIEW.md`: 3 High, 6 Medium and 8 Low findings; all High and Medium fixed with regression tests (`tests\Review.Tests.ps1`). Recycle Bin rules run first and never purge what another rule just recycled; files that cannot be recycled are skipped instead of deleted; the bin is emptied only when it did not grow since the scan; junctions above a cleaner root are refused; the GUI applies Expert, Lab and Risk Zone items only after their dialog; custom presets are re-validated on load; Session Mode records the session before anything changes; insecure legacy features (SMBv1, PowerShell 2.0, Telnet) are never enabled and more security services are protected.
- **The VBS/HVCI-off expert toggle is retired**: it can no longer be applied and stays only so an earlier change can be reverted.

### Quality

- Sandbox runner: presets on the VM fixture, Session Mode, the cleaner scan/clean/verify cycle and custom presets.
- Docs: `docs\CLI.md` (generated from the help), `docs\EXPERT_LAB.md`, `docs\WINUTIL_MAPPING.md`, `docs\REVIEW.md`.
- Tests: `Toolkit.Tests.ps1`, `Presets.Tests.ps1`; the safety tests allow the Toolkit's fix programs and panel launchers only in its allow-lists and `netsh` resets only in the network-reset fix.


## 2.2.0 (preview)

### Network Test

- New network quality analyzer (GUI page **Network Test**, CLI `-NetworkTest`, `docs\NETWORK_TEST.md`): latency, jitter (sub-millisecond precision), packet loss, percentiles, spikes and loss bursts to the router, the first ISP hop, internet anchors and up to four targets of your own; ICMP traceroute with reverse DNS; path MTU discovery; DNS lookup time.
- Grades per metric and overall (the weakest metric decides), a 0-100 score and an estimated MOS (simplified ITU-T G.107 E-model); optional latency under load with a bufferbloat grade while you run a speed test.
- Connection type guess with confidence and evidence: local link (Ethernet, Wi-Fi 4 to 7 with band, channel and signal, mobile broadband, phone tethering or hotspot, VPN) and internet access (fiber, cable, DSL, cellular, Starlink, geostationary satellite, fixed wireless) from router names, carrier-grade NAT, first-hop latency, idle jitter and MTU.
- Recommendations: the catalog items that lower latency and jitter on this kind of connection and are not applied yet (Ethernet, Wi-Fi and mobile profiles; preview and apply through the normal engine), Risk Zone network items to turn off, and router, Wi-Fi and ISP guidance (SQM against bufferbloat, band and signal, home network versus ISP loss, CGNAT, double NAT, VPN).
- New catalog item `net.wifi-power-max-performance` (Wi-Fi adapter power saving: Maximum Performance on AC, Tier B).
- HTML and JSON reports; `-Duration Quick|Standard|Extended`, `-NetTarget`, `-UnderLoad`, `-ReportPath`.

### Risk Zone

- Rejected tweaks are now available at the user's own risk when they are reversible performance or network settings: 19 items in the new **Risk Zone** category (evidence tier R, level Lab), each with a warning, what it turns off and on, its risks and the reason it was rejected.
- Applying one needs `-AcknowledgeRisk` on the command line or typing "I ACCEPT" in the GUI; Risk Zone items are never part of a preset, conflict with their safe counterparts and are reverted from snapshots like every other item. New handlers for the HPET device, memory compression and disabled TCP auto-tuning.
- Rejected tweaks that turn off security protections (Defender, VBS/HVCI, CPU mitigations, driver signature enforcement, service isolation), edit the boot configuration, cannot be undone or need background software stay unavailable; `data\rejected.json` and the Rejected Tweaks page state the reason for each.
- CLI `-RiskZone` lists every rejected tweak with its availability, warnings and current state; dry runs print the Risk Zone warning.

### Other

- Version 2.2.0 (`$script:IgwtVersion`, module manifest).
- Tests: `tests\Network.Tests.ps1` and `tests\RiskZone.Tests.ps1`; the safety tests allow `netsh` only for the read-only `wlan show interfaces` in the network module.

## 2.0.0 (preview)

### Management and diagnostic modules

- Services: every service with description, status, startup type, dependencies, a rating (Protected, Catalogued, Windows, installed by an app) and the catalog items and presets that touch it; startup type changes with a snapshot. Protected list in `data\manage\services.json`.
- Scheduled tasks: browse all tasks, disable or enable (never create or delete); security, update and anti-cheat tasks are refused. New catalog item `privacy.telemetry-tasks-off` (Advanced, Tier B).
- Persistence Inspector (read-only, Autoruns-style): Run/RunOnce (including WOW6432Node), Startup folders, non-Microsoft services, drivers and tasks, WMI event subscriptions, Winlogon Shell/Userinit, IFEO Debugger, AppInit_DLLs and browser extensions, with Authenticode status and severity. Startup entries, services and tasks can be disabled through their documented mechanisms; HTML/JSON export.
- Apps: installed Win32 and Appx apps; inbox app removal per user or provisioned with a snapshot and reversibility note; protected Store, App Installer, Xbox identity, Gaming Services, Windows Security, WebView2, frameworks and shell. Features and capabilities manager with a protected list.
- Windows Update: read-only status (services, pending restart, policies, history and failures) and new catalog item `privacy.defer-feature-90` (feature updates only).
- Network toolkit: adapter inspector with a description for every advanced property, user-initiated DNS benchmark and latency/jitter/loss test, firewall rule browser (app rules can be enabled or disabled; Windows rules never), read-only hosts-file viewer that flags unexpected entries.
- Diagnostics: DPC and ISR percentages from raw performance counters with top processes, reliability history, crashes (BugCheck, Kernel-Power 41, unexpected shutdowns, app crashes, minidump list), boot performance (event 100), driver inventory with date and signer. Full system report export (HTML and JSON).
- All changes go through `Invoke-IgwtManagedChange` (snapshot operation `Manage`, revert through `Invoke-IgwtRevert`, targets validated again on revert). 84 tweaks in total.
- CLI: `-Inventory Services|Tasks|Apps|Features|Firewall|Hosts|Adapters [-Search]`, `-Change <kind> -Target -Value [-Provisioned] [-DryRun]`, `-Persistence [-IncludeMicrosoft] [-ReportPath]`, `-Updates`, `-Diagnostics <areas> [-Days]`, `-SystemReport -ReportPath [-Quick]`, `-DnsBenchmark`, `-Latency <targets>`. GUI: Manage page (services, tasks, apps, persistence, firewall and hosts) and Diagnostics & Network page (overview, drivers, Windows Update, network tools, system report).
- Tests: `tests\Manage.Tests.ps1` (protection data, managed change round trips and refusals, tampered snapshot, inventories, persistence, update status, network toolkit, diagnostics, system report, catalog items, CLI argument checks).

### Expert controls and inspectors

- Read-only expert inspectors (`docs\INSPECTORS.md`): power plan (every processor setting of the active plan, hidden ones included, with Windows defaults, hidden flag and hardware blocks), interrupts (supported and current interrupt mode, MSI configuration, affinity policy and target CPUs), network queues (RSS, queues, buffers, discarded packets), kernel and memory (registry values with meaning, default and the catalog or rejected entry), timer, and crash dumps and page file.
- Power plan editor (Expert): 16 processor settings, values checked against the range `powercfg` reports, hardware overlays enforced, snapshot first (operation `Power`) and full revert; "Windows default" button and `-PowerDefault`.
- New System category: page file managed by Windows, small memory dumps, verbose status messages, stop code parameters on the blue screen. New items `power.show-processor-settings` and `gfx.gpu-msi` (Expert). 82 tweaks in total.
- Eleven new rejected entries (hypervisor launch type off, processor idle disable, manual interrupt pinning, test signing and kernel debugging, IFEO edits, registry cleaners, hosts-file telemetry blocking, Prefetch cleaning, manual WinSxS/Installer deletion, disabling IPv6).
- CLI: `-Inspect All|Power|Interrupts|Network|Kernel|Timer|Crash [-Json]`, `-PowerSetting <alias> -Ac/-Dc/-PowerDefault [-AcknowledgeRisk] [-DryRun]`. GUI: Expert Inspectors page (tabs, power editor) and a System & Diagnostics category page.
- Tests: `tests\Inspectors.Tests.ps1` (parser including localized labels and UNKNOWN values, editor validation, overlay blocks, snapshot and revert, defaults resolution, interrupt, NIC, kernel, timer and crash inspectors with mocks) and new static checks (inspectors read-only, idle disable never editable).

### ASR Center and security modules

- ASR Center for all 19 Microsoft Defender attack surface reduction rules (`data\asr\rules.json`, `docs\ASR_CENTER.md`): current mode and where it comes from (local, Group Policy, MDM), recommendation, gamer-impact note, Warn and cloud limitations, and exclusions.
- Changes with a snapshot first and full revert: rule modes (Not configured, Audit, Warn where supported, Block; never an explicit Off), "apply recommendations" (never lowers a rule), per-rule exclusions (documented Group Policy registry settings, confirmed through Defender when elevated) and global ASR-only exclusions. Exclusions are validated: no drive roots, Windows folder, whole Program Files, user-writable folders or user variables.
- Read-only audit view: ASR, controlled folder access and network protection events from the Defender log, grouped by rule and program, with next steps (promote a quiet Audit rule, exclude a trusted program's exact file, ignore expected LSASS noise).
- Read-only security score (25 weighted checks, each with its fix: a catalog item, the ASR Center, Windows Security, firmware or Settings), local accounts audit and listening-ports report.
- Eight security items: exploit protection system defaults (repair-only), WDigest caching off, no anonymous enumeration, NTLMv2 only, Windows Script Host off, outbound firewall blocks for mshta/wscript/cscript/regsvr32/certutil, Print Spooler without inbound clients, Print Spooler off.
- `exploitSystem` and `processMitigation` accept `equivalentOn: ["NOTSET"]` for repair-only items.
- CLI: `-Asr` (with `-AsrRule`, `-AsrMode`, `-AsrRecommended`, `-AsrExclude`, `-AsrUnexclude`, `-DryRun`), `-AsrAudit [-Days]`, `-SecurityScore`, `-NetworkSurface`; the security score is part of `-Report` (console and HTML).
- GUI: ASR Center page (rule list, details, mode selector, exclusions, audit view with "use as exclusion") and a Security score card on the dashboard.
- Tests: `tests\Asr.Tests.ps1` (catalog, status, path validation, changes and reverts with stateful Defender mocks in TestRegistry, audit grouping, score, accounts, network surface) and new static checks (no duplicate function names, no `$name?` in strings, ASR code read-only where it should be).

### Action handlers

- 14 new action types, each with detect, snapshot, apply and restore: `storageSense`, `wufbPolicy`, `deviceInterrupt`, `serviceSet` (registry/service composites), `powercfgAttribute`, `powercfgSettingAcDc`, `scheduledTask`, `firewallRule`, `appx`, `winget`, `capability`, `processMitigation`, `exploitSystem`, `cleanerRule`; plus a read-only `DefaultApp` check.
- Safety limits in code and validation: protected services, tasks and apps; firewall Block rules and group disabling only; system exploit protection only ON; device interrupts only on GPU/NIC/USB controllers that declare MSI support, never the boot controller; winget only through fixed arguments; no BCD writes.
- The Storage Sense tweaks use the typed `storageSense` action. `docs\TWEAKS.md` describes every new action type.
- Tests: `tests\Handlers.Tests.ps1` round-trips every handler (detect, snapshot through JSON, apply, detect, restore, detect) in TestRegistry or with stateful mocks, and checks the validation rules.

### Hardware profile engine

- Read-only hardware facts (CPU, active GPUs, network controllers, memory, battery/chassis, Modern Standby, system disk, VM) turned into hardware tags by data-driven rules (`data\hardware\detection.json`). This PC: `intel.hybrid`, `intel.raptorlake.desktop`, `gpu.nvidia`, `nic.marvell`, `storage.nvme`, `ram.32`, `formfactor.desktop`.
- 15 hardware overlays with sources (`data\hardware\overlays.json`, `docs\HARDWARE.md`): Intel hybrid scheduling, Raptor Lake Vmin Shift protection, AMD X3D dual-CCD core steering, AMD chipset driver, Modern Standby and laptop power, SysMain on slow disks or low RAM, virtual machines, Intel Arc Resizable BAR, NVIDIA Reflex, AMD Anti-Lag 2, Intel I225/I226, Killer, Realtek/Marvell drivers.
- Presets resolve as intent preset -> hardware overlays -> your add-ons. Blocked items are Not applicable (already-applied ones can still be turned off); overlay adds respect the preset's level ceiling, anti-cheat policy and exclusions.
- `-Hardware` (read-only profile, `-Json` facts), hardware section in `-Report` (console and HTML), overlay reasons and guidance in `-Preset ... -DryRun`, and a Hardware profile card on the GUI dashboard. Preset cards and staging use the resolved selection.
- Tests: `tests\Hardware.Tests.ps1` with six fixtures (Intel Raptor Lake desktop, AMD X3D dual-CCD desktop, Intel laptop, AMD laptop, Intel Arc desktop, VM).

### Schema v2 and migration

- All data files are schema v2 (`docs\SCHEMA.md`): `level` (Standard/Advanced/Expert/Lab), `antiCheat` ("safe", "unknown" or the anti-cheats it breaks), `reversible`, `sideEffects`, `source` (+ attribution), `hardware` tags and `appliesTo.conditions`. Presets are intent presets (`include`, `exclude`, `levelCeiling`, `antiCheatPolicy`). New hardware tag vocabulary in `data\hardware\tags.json`.
- Automatic migration: v1 catalog files, presets, cleaner rules and snapshots are upgraded in memory when read. `tools\Convert-IgwtV1Data.ps1` rewrites v1 data files (idempotent) and writes schema 2 copies of snapshots to another folder; originals are never changed.
- Snapshots are schema 2 (catalog schema, hardware tags, item level per entry). 1.0 snapshots still revert exactly; a real 1.0 snapshot is a test fixture.
- Validation: every tweak, cleaner rule, preset and hardware tag needs a hint (140 characters or fewer) and a description; valid level, tier, anti-cheat field, reversibility, source and known hardware tags; anti-cheat-breaking items must be Lab; no Lab, rejected or non-safe items in gaming presets.
- GUI shows level badges and the specific anti-cheat impact; every button and input has a tooltip. `-ListTweaks` shows Level, AntiCheat and Reversible, and dry-run plans include Level.

### Cleaning engine

- New allow-list cleaner with 44 rules in six categories (System, Gaming, Browsers, Apps, Developer, Downloads), each with a hint, description and side effects (`docs\CLEANER.md`).
- Two-phase operation: `Invoke-IgwtCleanerScan` sizes everything and deletes nothing; `Invoke-IgwtCleanerClean` deletes only the scanned files after re-validating each one. Deleted paths are logged to `Logs\Cleaner-<time>.jsonl` (10 logs kept, older ones zipped).
- Safety core: path canonicalization (including 8.3 names), hard denylist, no reparse-point following, cloud-placeholder skip, unchanged-since-scan check, no recursive deletes, never closes apps, services always restarted.
- Special methods through supported tools: Recycle Bin, Delivery Optimization cache, DISM component cleanup (with an Expert ResetBase rule), old driver packages (pnputil without /force), and size-only guidance for Windows.old and Docker.
- Read-only disk analyzer (`Get-IgwtDiskUsage`): largest folders and files, junction-safe.
- Storage Sense category with three documented policy tweaks (weekly temp cleanup, Recycle Bin after 30 days, expert Downloads threshold).
- CLI: `-Clean` (`-Scan`/`-DryRun` read-only, `-CleanRule`, `-CleanLevel`, `-IncludeOptIn`, `-AllUsers`, `-Yes`) and `-Analyze <path> -Top N`.
- GUI: Cleaner, Storage Sense and Disk Analyzer pages with cancel support.
- Tests: `tests\Cleaner.Tests.ps1` (fixtures in TestDrive only; traversal, injection, junction swap, locked, offline and changed files, service restore, special methods, analyzer, Storage Sense apply/revert in TestRegistry) plus new static safety checks.

## 1.0.0 (2026-10-16)

First release.

- Data-driven engine with 15 action types: registry, registryListMerge, adapterRegistry, netAdapterPower, powercfgScheme, powercfgSetting, service, netAdapterAdvanced, netQosPolicy, dnsDoh, mpPreference, asrRule, optionalFeature, custom and check.
- 65 catalog tweaks (43 Tier A, 22 Tier B) in 6 categories; 3 presets (Competitive, Balanced, Hardened); 28 documented rejected tweaks.
- Snapshot of exact previous values (type, data, absent, created keys) before every change, plus a System Restore point; atomic per-tweak rollback; idempotent apply; revert by id, last apply or snapshot file; reset to documented Windows defaults.
- Read-only health report (console, HTML, JSON): OS, CPU microcode (Vmin Shift 0x12F check), memory, BIOS, TPM, Secure Boot and the 2023 certificate status, VBS/HVCI/IOMMU, GPU/ReBAR/HAGS/refresh rate, NIC/link speed/EEE, storage/TRIM/free space, Defender/firewall/UAC/LSA/BitLocker, and an anti-cheat readiness matrix.
- WPF GUI with background worker, staged changes, preview, search and filters, Startup Apps, Backups & Logs, and the Rejected Tweaks explainer.
- Pester 5 suite (TestRegistry plus mocks), PSScriptAnalyzer settings, Windows Sandbox end-to-end test, optional Authenticode signing with SHA256 manifest, and generated catalog docs.
