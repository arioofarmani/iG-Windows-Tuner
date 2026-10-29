# AegisTune (iG Windows Tuner) 3.4.0

Released 2026-10-29. Windows 11 (build 26100 or later), Windows PowerShell 5.1.


Firewall Manager 3.4: every rule classified (origin category, direction, blocks, bloat, risks) with the reason and a confidence level, risk findings with plain-language explanations and safe fixes, conflict analysis and an overview dashboard. Includes everything listed under 3.3.0, which was not released separately.

### Firewall Manager 3.4

- Starting audit and sources: `docs\FIREWALL_AUDIT_3.4.md`.
- **Every firewall rule classified**: exactly one origin category (Core Services, Windows Connections, User Installed, Custom Rules) with the reason in one sentence (for example "User Installed: program signed by Valve Corp and located in ..."), a confidence level (High, Medium, Low; Low asks "is this right?"), its direction and block facets and the Bloated assessment for the PC's role. Matching uses stable rule IDs, group resource strings, package publishers and program paths, never translated names. Windows Service Hardening rules are now listed too (read-only). "Move to category", "Not bloated for me" and ignored findings are remembered per user and can be exported.
- **Security-risk findings** for every rule, each with a severity (Critical, High, Medium, Low), a plain explanation, the least invasive recommended fix and alternatives: wide-open inbound rules, remote access and file sharing on Public networks, programs in user-writable folders, unsigned programs, orphaned rules (the program is gone), script hosts, edge traversal on app rules, discovery protocols on Public, any-address where the local subnet would do, disabled Windows security rules, duplicates, wide port ranges and missing descriptions. A rule that matches a port something is listening on right now is marked **Exposed now** and rises one level. Findings can be ignored with a reason and an expiry. Windows rules are never offered Delete, Core Services only Keep, and game, launcher and anti-cheat rules are never recommended for blocking.
- **Conflict analysis**: shadowed allow rules ("this allow rule never applies; block rule X covers the same traffic"), redundant rules and partly blocked rules, from the Windows Firewall order (block over allow over the profile default).
- **Safety rules for changes**: Core Services are read-only, Windows rules are never deleted, Delete is only offered for orphaned, user-installed and custom rules, and blocking a game, launcher or anti-cheat program warns that online play may break.
- **Overview dashboard** (Security > Firewall > Overview): a tile per group with counts and findings, a category chart, findings by severity, *Quick wins* with a preview of what stops working, an exposure map (listening ports and the rules that let them in), recent firewall changes and the profile state.
- **Rules tab with a group sidebar**: pick a group (Core Services, Windows Connections, User Installed, Custom Rules, Inbound, Outbound, Blocked, Bloated, Security Risks) or a saved view; new columns Origin, Groups and Confidence; chips per severity, *Exposed now*, *Conflicts*, *Low confidence* and one per risk rule.
- **Details pane** explains each rule: origin and why, confidence, each finding as a card with the recommended fix and alternatives (turned off with the reason where a rule is locked, a Core Service or a protected game rule), *Move to category*, *Not bloated for me* and *Ignore for 90 days*.
- **Bulk actions per group** and a **smart fix wizard**: one step per kind of finding, your choice per step, a plan preview with the skipped rules and why, then the changes in batches, each with a snapshot and Undo.
- **Audit report**: export the audit as HTML, CSV or JSON.
- **Role picker** on the Overview ("This PC is a Gaming PC / Power user / Sysadmin / Office workstation"): what counts as bloat follows the role; the choice is stored with your firewall choices.
- User guide and audit workflow: `docs\FIREWALL.md`.
- **Rule templates for common scenarios** (game server, LAN file sharing, local web development and more) and **warnings before a rule is created or edited**: the risk rules check the new settings first, for example "Critical: inbound allow for any program, any port, from anywhere". Rules the tuner creates are marked in their description.
- **Compared to Windows defaults**: which default rules of this Windows build were removed or changed, and which rules were added (from the read-only default rule store; a Windows Sandbox baseline is the fallback).
- **Live connections**: current TCP connections and UDP endpoints with the program, its services and the rule that applies (read-only).
- **Firewall scopes**: presets for a Gaming PC, a Workstation, a Public Wi-Fi laptop and a hardened sysadmin PC. Each shows a preview of the bloated rules and risk fixes it would apply, skipping Core Services, locked rules and game, launcher and anti-cheat rules with the reason; applying runs in batches with snapshots and Undo. The built-in presets name a matching scope, but firewall changes are never part of a tweak apply.
- **Export my choices**: save your category changes, "not bloated" marks and ignored findings to a file.
- **Safety hardening from the independent review** (`docs\REVIEW.md`): the change engine classifies rules itself, so Core Services stay read-only and Windows rules are never deleted or edited even when it is called directly or from an import file; "Move to category" can no longer take a rule out of Core Services; queued wizard and scope batches stop when a batch fails, is undone or is reverted by the remote-session timer; Remote Desktop and WinRM rules are recognised on every Windows language and by port range; profile and network-category changes are refused during a remote session; programs on drives that are not connected are no longer treated as orphaned; blocking a game in a secondary Steam library warns too; CSV exports cannot run spreadsheet formulas.
- **Firewall knowledge base** (`data\firewall\*.json`): the nine groups, every built-in Windows rule group of build 26100+ by its stable ID (Core Networking, service hardening, discovery, sharing, remote administration, casting, Xbox and Store apps ...) with what it is for, what stops working without it, risk notes, whether each role needs it (gaming PC, power user, sysadmin, office workstation) and Microsoft sources; 13 risk rules with severities, plain explanations and safe fixes; well-known ports and services; protected game, launcher and anti-cheat programs. Validated by `tools\Test-FirewallKB.ps1`; explained in the generated `docs\FIREWALL_CATEGORIES.md`.

## Also in this release: the 3.3 quality release

3.3 was not released on its own; everything below ships in 3.4.0.


Quality release: a rebuilt, calmer interface, a professional Firewall Manager, sorting and filtering everywhere, and a read-only mode for audits.

#### Added

- **Read-only mode** (`-ReadOnly`, GUI and CLI): every apply, revert, clean, install, delete and change path is turned off in the engine itself (also in the GUI's background worker), and the window shows a "Read-only mode" banner. Commands that would change the PC stop with exit code 7.
- **Error boundary**: an error inside the window now shows an inline message with "Copy details" instead of closing the app.
- **UI test suites**: an offscreen render suite with mocked data (every page, every theme, 100/150/200 %) and a UI Automation suite that drives the real GUI in read-only mode (exceptions, binding errors, UI-thread stalls, memory), plus `tools\Test-All.ps1`.
- **UI audit** of every page: `docs\UI_AUDIT_3.3.md`.
- **Design system and themes**: Dark, Light and High Contrast themes (System follows the Windows app mode and switches to High Contrast when Windows does, while the app runs). One set of colour, type, spacing and density tokens; text contrast is 4.5:1 or more in every theme and checked by tests. Body text is 14 px; text size can be set from 100 to 150 % and density to Comfortable or Compact (header > Display). The choices are remembered per Windows user (`%LOCALAPPDATA%\iGWindowsTuner\gui-state.json`).
- **Title bar in the app theme** with its own minimize, maximize and close buttons (no more white title bar in the dark theme).
- **Themed dialogs and toasts**: confirmations use the app theme instead of the Windows message box; results can appear as a toast with an Undo button.
- **SmartGrid**, one list component for the tables: sort by any column (Shift+click adds a second and third sort level, with arrows and level numbers), search across columns (all words must match, debounced), quick-filter chips, a "N of M shown" counter and Clear filters, column chooser, reorder and resize, saved views per list (restored on the next start), multi-select with an "N selected" bulk bar, a right-click menu that mirrors the actions, copy, CSV/JSON export of the view, virtualization for thousands of rows, and loading, empty, no-match, error (with Retry) and "Updated 3 min ago" states. Manage > Services, Scheduled tasks, Apps and Persistence use it, with new columns (name, status, startup type, runs as, publisher, version, size, signature, command) and chips (running, stopped, startup type, installed by apps, protected, third-party, removable, warnings, not signed).
- **Tweak pages use SmartGrid**: one sortable list per category with a switch per row (it stages the change; nothing changes until Apply), columns for current state, pending change, group, evidence, risk, level, anti-cheat and restart, and chips (off, on, pending, changed from default, tier, risk, restart, anti-cheat safe, level) instead of the old check boxes. A search covers every category; the list keeps its scroll position when it refreshes. Change summaries name the target in words (for example "Registry value HKLM\...\Name") instead of raw action data.
- **Every other list uses SmartGrid too**: Inspect (power plan, interrupts, kernel and memory), Toolkit (apps, WinUtil items, features, fixes, panels, Windows Update items), Diagnostics (drivers, adapter properties), Defender settings (preferences and Group Policy), Cleaner (a switch per rule, sorted by size), Disk Analyzer (folders and files; double-click a folder to look inside), Startup Apps (a switch per entry), Backups (snapshots, newest first, by area and with failures) and Rejected tweaks. Each list has sortable columns, its own search, chips such as *Needs attention*, *Changeable here*, *Differs from default*, *Installed*, *Unsigned* or *With failures*, saved views and CSV/JSON export. The shared Toolkit filter box and the Defender search and filter boxes were replaced by each grid's own search and chips.
- **Diagnostics overview as cards and tables**: interrupt time (DPC/ISR), stability index, crashes and boot time are four summary cards; reliability records, crashes and boots are one sortable, searchable event table (chips per area and *Last 7 days*, export), and the Windows Update history is a table with result and error code (chip *Failed*). Dates show as `yyyy-MM-dd HH:mm` instead of the US format.
- **Background reads run side by side**: the GUI's worker is a pool of three runspaces, so a page that is still loading no longer blocks another page ("Busy - please wait" is gone for reads); background reads show a Cancel link next to the progress bar. Changes still run one at a time.
- New controls for every page: segmented control, filter chips, search boxes with a placeholder, a sortable data grid style with sort arrows, visible keyboard focus everywhere, and buttons that look disabled when they cannot be used.

- **Grouped navigation**: the pages sit in labelled groups (Start, Optimize, Secure, Clean, Manage, Diagnose, History) in your persona's order, and a breadcrumb above each page shows where you are. The app opens on the page you used last.
- **Focus mode** (Display > Focus mode): hides the expert pages, the dashboard details and the Advanced, Expert and Lab items until you turn it off; a "Focus mode" pill in the header shows it is on. Nothing on the PC changes.
- **Dashboard**: your last three changes with an Undo button each, and shortcuts to the pages your persona uses most.
- **Presets**: each card shows how many changes it makes per category, and *Compare...* lists every change (now and after, by category, highest impact first) before anything is staged.
- **Network test**: a clear "Not measured yet" state with the next step, a labelled game-server box, and *Earlier runs*: the last 50 results with the change in ping and jitter against the run before (kept in your own settings folder, no addresses).
- **Group Policy > Compliance**: compare a security baseline or GPO backup folder with this PC, setting by setting (matches, differs, not set), read-only.
- **Backups & Logs > Log**: the log of the last 7 days in the window, with search and chips for warnings and errors.
- **About**: build information with Copy (for bug reports), the changelog and the license and third-party notices.
- Lists and three-pane pages fit the minimum window size (1100 x 720): the search box shrinks and the toolbar moves under it instead of being cut off.

#### Performance

- The window starts about half a second faster: the tweak catalog loads in about 0.15 s instead of 0.6 s, and the cleaner rules are read the first time the Cleaner page needs them.
- The render suite records how long the window takes to build (per startup step) and how long each page takes to switch and lay out.
- **No more freezes while pages load.** The window opened its background workers on the UI thread (a 4 s freeze at start) and a busy worker grew by another runspace on the first page that read several things at once (about 1 s, for example on ASR Center and Group Policy). The workers now open in the background as three ready runspaces, and the first reads wait for them.
- The progress bar no longer freezes the window: the built-in animation forced a layout pass every cycle (a 250 ms freeze every 2 s while a page loaded); it now moves with a render transform.
- Large lists (firewall rules, Group Policy) are built in small slices between frames, and finished background reads are shown one per tick, so the window stays responsive while data arrives.
- Measured with the UI Automation suite on a real PC (read-only): 0 freezes over 200 ms during page loads, navigation, resizing and theme changes; no memory retained after 20 navigation cycles (+0.8 MB managed heap); 0 binding errors and 0 exceptions.

#### Firewall Manager (Security > Firewall)

- **Every rule of the active policy** in one list: loaded with one bulk query per class (rules, programs, ports, addresses, services, interface types) and joined in memory, about 0.7 s for 500 rules on the test PC. Columns: name, group, enabled, direction, action, profiles, program, service, package/AppContainer, protocol, local and remote port, local and remote address, interface type, edge traversal, source, program exists, risk, description (the less used ones in the column chooser).
- **Where each rule comes from**: Windows, third-party app, Store app, iG Windows Tuner or Group Policy / MDM. Group Policy and MDM rules are locked with the managing source shown.
- **Risk views**: inbound allow on Public, any program / any port, program not found, program in a user-writable folder, duplicates (among app and user rules) and disabled Windows defaults, each with an explanation in the details pane. The page opens with what needs attention.
- **Quick filters** for enabled/disabled, direction, action, profile, source and protocol, search over name, group, program, port and address, multi-column sort and saved views.
- **Actions** (single and bulk): enable, disable, Allow/Block (with a warning), edit (name, networks, ports, addresses, program) with validation, duplicate, and delete (not for Windows rules, which can only be disabled). Every action shows a summary first, writes a snapshot, offers Undo in a toast, and refreshes only the rules it changed. Core Networking rules are never disabled.
- **New rule wizard** in five steps with templates (for example "Allow a game inbound (UDP), Private networks only"), Back/Next without losing values and a summary before anything changes.
- **Import and export**: JSON (importable, with a preview of new and changed rules) and CSV, and a full policy backup with netsh advfirewall export (.wfw).
- **Remote-session safety**: rules that keep Remote Desktop or WinRM working are not changed while such a session is active, and other changes are reverted automatically unless you keep them within 60 seconds.
- **Profiles and networks**: per profile on/off, default actions, notifications, unicast response and logging, and Private/Public per connected network. Changes only move toward protection: the firewall is never turned off and inbound traffic stays blocked by default. A firewall log analysis is one click away.
- The Manage page's old firewall tab now points to the Firewall Manager and keeps the hosts-file viewer.

#### ASR Center and Exploit protection

- **ASR rules in a sortable, filterable list**: rule, category, mode, supported modes, gamer impact, events and last event of the last 7 days, managed by and recommendation; quick filters for below recommendation, mode, has events, impact, standard protection and managed rules.
- **Segmented mode control** (Off, Audit, Warn, Block) in the details pane: modes a rule does not support are disabled and say why; rules managed by Group Policy or MDM are locked. **Bulk set mode** for a selection, skipping (and listing) rules that cannot take the mode. After every change the list shows the mode Defender reports, with Undo.
- **Audit to Block** review: every rule in Audit with its events, a suggestion (block when quiet, review the programs first, or keep) and a preview; only the quiet rules move to Block, and only after confirmation.
- The events view and the rules sit on their own tabs: no more empty reserved area under the rules, and "Use as exclusion" no longer overlaps the summary.
- **Exploit protection** tab (read-only): the system-wide settings in a card and every program with its own settings (mitigations turned on and off), sortable and filterable; anti-cheat programs are marked and locked.

#### Fixed

- **Defender Group Policy view: "Configure detection for potentially unwanted applications" no longer lists Enabled as refused.** Each option of a policy is now checked with its own value: Enabled: Block and Enabled: Audit Mode can be set from the page; only the options that turn protection off are refused. Policies with one option or on/off element can be enabled from the page with the chosen option.
- Refusals (a Defender value or policy option that would turn protection off) are shown inline under the control and keep Apply off, instead of opening a dialog.
- Defender settings that a policy sets now look locked: the value box is off, Apply is hidden and the help names the source.
- An unexpected value in a Manage row (for example a new service rating) no longer blanks the whole page; rows fall back to neutral text.
- **Firewall Manager showed raw numbers and false duplicates when started as administrator**: every rule read as Disabled, direction and action as 1/2 and 2/4, every program as Any, the tuner's own rules as third-party, and hundreds of rules as duplicates. The background worker sometimes received the firewall rules without the NetSecurity type data (raw CIM values); the worker now loads the Windows network modules when it starts, and the Firewall Manager also understands the raw values. Store app rules (created by Windows per app package) and rules whose ports could not be read are no longer counted as duplicates.
- Firewall direction is shown as **IN**, **OUT** or **IN/OUT** (the full word is in the tooltip and the details).
- A list that refreshed while scrolled down (for example after a filter chip on Defender settings) showed "Something went wrong (window): Exception has been thrown by the target of an invocation"; the scroll position is now restored without the error.
- Read-only mode is honest everywhere: *Clean selected*, *Run fix* and *Check installed* (it runs winget export) are off with the reason in the tooltip, and refusals say "read-only mode" instead of suggesting a restart as administrator. A persona change in read-only mode says it is not saved.
- Defender settings > Group Policy: *Set policy* could never be enabled; it now follows the selected policy.
- Reduce motion also stops the moving progress bar; navigation and input boxes have accessible names that match their labels; titles use sentence case; Backups & Logs and Rejected tweaks show a status line.
- `-Version` prints the version (with `-Json` as an object).
- The navigation list is only rebuilt when its order changes; rebuilding it twice at start-up could log binding errors at the first render.
- The dashboard no longer shows an empty "Fix:" link for a security check without a fix target.
- Lists that select one row at a time (tweaks, Defender settings, power plan) no longer fail when they refresh while a row is selected; the selection is kept.
- The read-only text views of Diagnostics and Inspect start at the top instead of floating in the middle of the box.
- Event handlers are registered through one guard that refuses a second registration from the same code on the same control, so an action can never fire twice.

#### Every Defender, ASR and security setting

- **Security > Defender settings** (GUI page and `-DefenderSettings`, `-DefenderSet`): all 137 Microsoft Defender Antivirus preferences in 13 categories, including the hidden ones Windows Security does not show (update channels, scheduler randomization, catch-up and grace periods, UDP offloads for network protection, brute-force and remote encryption protection, AI agent protection, Intel TDT, Dev Drive performance mode, reporting and telemetry switches). Each shows its current and recommended value and who sets it; 87 can be changed with a snapshot and revert, protections only move toward on, values that turn a protection off are refused and levels are never lowered. A revert never turns a protection off. Preferences a newer Defender platform adds are listed read-only.
- **Every Defender Group Policy** (`-DefenderPolicies`, Group Policy view of the page): about 140 Defender policies of the installed templates, including the ones without a preference (heuristics, packed executables, archive limits, scan after update, notifications), with their Local GPO state; set them from the page or with `-PolicySet`. The denylist now also refuses the hidden Defender switches that turn a protection off.
- New Security items: **Run Microsoft Defender Antivirus in a sandbox** (`sec.defender-sandbox`) and **Enhanced Phishing Protection** (`sec.enhanced-phishing-protection`).
- Coverage report: `docs\SECURITY_COVERAGE.md` (19 of 19 ASR rules, 137 of 137 Defender preferences, every Windows Security area and what is deliberately left out).
- CLI help: the Policy and Defender parameter descriptions were listed three times; each is now listed once.

#### Interface

- New dark theme: calmer palette, softer amber warnings, rounded cards, dark check boxes, combo boxes and thin scroll bars.
- Dashboard redesigned for quick scanning: four status tiles (anti-cheat, security, system health, your changes), one numbered *Do this next* list with at most five items, and every detail section folded into a collapsible panel (problems listed first).
- The ASR Center and the Defender settings are part of Security: they sit under Security in the menu for every persona, and the pages have a *Hardening items | ASR Center | Defender settings* switch.
- Manage: every tab has sortable column headers (click to sort, click again to reverse; sizes sort by value).

## Download and verify

1. Download `iGWindowsTuner-3.4.0.zip` and `iGWindowsTuner-3.4.0.zip.sha256`.
2. Check the hash: `(Get-FileHash .\iGWindowsTuner-3.4.0.zip -Algorithm SHA256).Hash` must match the value in the .sha256 file. Every file inside the zip is listed with its hash in `SHA256SUMS.txt`.
3. Files from a downloaded zip carry the Mark of the Web; review them, then `Unblock-File` if you trust them.
4. Start with `Start-iGWindowsTuner.cmd` or `.\iGWindowsTuner.ps1`. Run the read-only modes and `-DryRun` first; every change writes a snapshot and can be reverted.

The files are not Authenticode-signed in this release.