# UI audit for 3.3 (phase 0)

Audit of the 3.0.0 + post-release GUI (commit 5fdb489) on 2026-10-23, before any 3.3 change.

**Sources**
- Ario's screenshots and notes in `docs\ui-issues\` (top priority; git-ignored because they contain user names and device details).
- The offscreen render suite (`tools\Test-GuiRender.ps1`, mocked data, 24 pages at 100, 150 and 200 %). The 100 % set is in `docs\screenshots\3.3\before\`.
- The UI Automation suite (`tools\Test-GuiAutomation.ps1`) driving the real GUI in `-ReadOnly` mode on the development PC.
- A code review of `src\Gui` for the common PowerShell/WPF bugs listed in the spec.

**Severity**
- **High**: wrong behaviour, data loss risk, a page that can go blank, or a spec requirement that is missing.
- **Medium**: confusing or slow, or breaks a 3.3 UX rule.
- **Low**: polish.

Status: every High and Medium item is fixed in 3.3 or documented as deferred in `docs\FINAL_REPORT_3.3.md`. The fix phase is noted per item.

## Baseline measurements (automation run, real GUI, read-only)

| Measure | Before | 3.3 budget |
|---|---|---|
| Unhandled exceptions | 0 (but none were caught: there was no error boundary, see X1) | 0 |
| WPF binding errors | 0 | 0 |
| UI-thread stalls over 200 ms | 7 (worst 412 ms at start-up, 399 ms rebuilding the Power & CPU list, 242 ms Diagnostics, 233 ms Manage) | none |
| Page switch to idle | median 14-66 ms, worst 232 ms (ASR Center) | < 300 ms |
| Memory | about 580 MB private at start; +57 MB after 20 navigation cycles | < 50 MB growth |
| Start-up data (`Get-IgwtGuiData -IncludeHealth`) | 20.4 s; Diagnostics 13.8 s; Inspect 9.5 s; Cleaner scan 6.8 s; Manage 4.7 s | first paint < 3 s, data async |
| Sortable column headers exposed to automation | 0 (Manage sort headers have no automation id) | every list |

## Cross-cutting findings (code review)

| # | Severity | Finding | Root cause | Fix |
|---|---|---|---|---|
| X1 | High | An exception in any event handler closed the window. | No `Dispatcher.UnhandledException` or AppDomain handler. | Phase 0: error boundary with an inline error bar ("Copy details") and logging. |
| X2 | High | One unexpected row value blanks a whole page: a service rating outside the tone list made `New-IgwtGuiManageRow` throw and Manage showed "Not read yet"; the render path swallowed it with `Write-Verbose`. | `[ValidateSet]` on a display helper fed raw data; errors swallowed. | Phase 2: SmartGrid row builders never throw on unknown values; load errors show the error state with Retry. |
| X3 | High | No `-ReadOnly` mode; the GUI could only be "read-only" by not being elevated. | Not built. | Phase 0: engine-level read-only mode, inherited by the worker runspace. |
| X4 | High | Only a dark theme; the Windows high-contrast setting is ignored; brushes are `StaticResource`, so a theme cannot change at run time. | Theme.xaml was dark-only. | Phase 1: Dark, Light and High Contrast with `DynamicResource` tokens. |
| X5 | Medium | System queries on the UI thread: `Get-IgwtManagedChangePlan` (services, CIM), `Get-IgwtPowerSettingChangePlan` (powercfg), `Get-IgwtManagementState`, `Test-IgwtSystemProtectionEnabled`, `Get-IgwtWingetAgreements`, `Get-IgwtSessionApps`; whole-list rebuilds of up to 400 ms. | Handlers call engine functions directly. | Phase 2: async layer; Phase 7: incremental list updates. |
| X6 | Medium | One background runspace runs one job at a time; a page opened while another loads stays empty ("Busy - please wait"); most jobs have no progress or cancel. | Single `Start-IgwtGuiJob` slot. | Phase 2: runspace pool with independent read jobs, progress and cancellation. |
| X7 | Medium | After a change, the app reloads everything (`Start-IgwtGuiRefresh` re-reads every tweak and the health report: 20 s) instead of the affected rows. | No cache invalidation per area. | Phase 2/7: per-area cache and row refresh. |
| X8 | Medium | Disabled primary buttons look enabled (Apply with 0 pending, "Apply value" with nothing selected, "Install selected"). | AccentButton has no clear disabled style. | Phase 1: disabled state with lower contrast and no accent fill. |
| X9 | Medium | Body text is 12-13 px; badges 11 px. | Type scale. | Phase 1: 14 px body. |
| X10 | Medium | Unlabeled inputs: the search boxes on Manage, Toolkit and Defender, the Network Test targets box and the ASR exclusion box have no label or placeholder. | No placeholder support in the TextBox style. | Phase 1: placeholder text and AutomationProperties.Name. |
| X11 | Medium | 24 navigation entries in one flat list; the bottom entries need scrolling at 820 px. | Flat navigation. | Phase 5: grouped navigation (Optimize, Secure, Network, Clean, Manage, Expert, Diagnose, Logs). |
| X12 | Medium | Navigation items had no accessible name and the navigation list virtualized, so UI Automation saw 18 of 24 items. | No AutomationProperties.Name. | Phase 0: names and no virtualization for the navigation list. |
| X13 | Low | Event handlers are registered once in Show-IgwtGui (no duplicates found); dialogs create new windows each time. There is no shared guard. | - | Phase 2: one registration helper that refuses duplicates. |
| X14 | Low | White Windows title bar above a dark app. | Default window chrome. | Phase 1 (optional, see DECISIONS). |
| X15 | Low | Lists use ListView (virtualized) but the Dashboard, Rejected, preset cards and Network Test lists are ItemsControls inside a ScrollViewer (not virtualized; small lists). | ItemsControl. | Phase 2: SmartGrid for tables; short card lists stay. |
| X16 | Medium | Memory: about 580 MB private and 57 MB growth after 20 navigation cycles. | Rebuilt row objects and templates on every visit. | Phase 7. |

## Firewall (Manage > Firewall & hosts)

Screenshots: `docs\ui-issues\ario-05-manage-firewall.webp`, `docs\screenshots\3.3\before\19-Manage-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| F1 | High | Not a rule manager: three columns (rule, "Direction, action", state), text search only, no profile, port, address, protocol, service, source or store columns, no quick filters or risk views. | 2.x inventory browser. |
| F2 | High | Single selection; the only action is enable/disable for app rules; no bulk actions, edit, new rule, duplicate, delete, export, import or restore. | Same. |
| F3 | High | Rules come from the persistent store only (`Get-NetFirewallRule` default); Group Policy and MDM rules, AppContainer owners and the effective (active store) state are not shown. | Loader `Get-IgwtFirewallRuleList`. |
| F4 | Medium | Two-line card rows: about 15 of 500 rules visible at once; the detail pane takes a fixed strip at the bottom. | ListView card template. |
| F5 | Medium | No profiles panel (profile state, defaults, logging, network category). | Not built. |

## ASR Center

Screenshots: `docs\ui-issues\ario-02-asr-center.webp`, `docs\screenshots\3.3\before\09-Asr-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| A1 | High | Until "Audit view" is pressed, the lower 40 % of the page is an empty reserved area (rule list cut short, large blank space). | Grid row `2*` reserved for the audit list. |
| A2 | Medium | The details panel shows an empty Mode box, an empty "Gamer impact" heading and an unlabeled exclusion box when no rule is selected. | No empty state. |
| A3 | Medium | "Use as exclusion" overlaps the audit summary text. | Shared DockPanel row. |
| A4 | Medium | Mode is a combo box; unsupported modes are not shown as unavailable with a reason; no bulk mode change; no events column or last event in the list; no audit-to-block wizard. | 2.x design. |
| A5 | Low | "Meets recommendation" wraps into two lines (120 px column); gamer impact text in the accent colour looks like a link. | Column width, colour choice. |

## Security (hardening items) and Defender settings

Screenshots: `docs\ui-issues\ario-01-defender-prefs.webp`, `ario-03-defender-policy-dialog.webp`, `ario-04-defender-devdrive.webp`; `docs\screenshots\3.3\before\08-Security-100.png`, `10-Defender-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| S1 | High | Group Policy view: "Configure detection for potentially unwanted applications" lists **Enabled** as refused. Enabling it is safe (Block or Audit); only the Off choice is refused. | `Get-IgwtDefenderPolicySettings` checks the Enabled state with no element values, so the enum falls back to its first item (Off) and the denylist refuses it. Policies with elements must not be judged by their default element value. |
| S2 | Medium | A refusal opens a modal dialog with a wall of text (the same text is already in the panel). | Dialog per refusal. |
| S3 | Medium | Settings set by Local GPO keep an enabled-looking value box and Apply button (they are disabled but look active), with no lock icon. | No locked state; X8. |
| S4 | Low | Duplicate badges ("Set by Local GPO" and "Source: Local GPO"); "(not reported)" for empty exclusion lists; block time without a unit; long values wrap. | Row builder. |
| S5 | Medium | The hardening items page uses the tweak card list: no sort, no "needs attention first", no status cards. | Shared tweak page. |
| S6 | Low | After "Refresh" the Group Policy list keeps a scroll offset that cuts the first row. | ListView scroll state. |

## Dashboard

Screenshot: `docs\screenshots\3.3\before\00-Dashboard-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| D1 | Medium | No recent changes with undo links and no pending-reboot card; no persona shortcuts. | Not built. |
| D2 | Low | An action can show an empty "Fix:" link when the fix id has no item. | Lookup without fallback. |
| D3 | Medium | Content arrives after the 20 s health report; no skeleton, the tiles say "checking". | X5/X7. |

## Optimize pages (Presets, Power & CPU, Graphics & Display, Input, Network, Background & Privacy, System, Storage Sense, Risk Zone)

Screenshots: `docs\screenshots\3.3\before\01-Presets-100.png` to `07-BackgroundPrivacy-100.png`, `11-System-100.png`, `12-RiskZone-100.png`, `16-Storage-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| O1 | Medium | The filter row wraps onto two lines at 1280 px; at 1100 px it takes three. | WrapPanel of check boxes. |
| O2 | Medium | No sorting (name, impact, state), no grouping by impact, no level chips; 7-8 items visible per screen. | Card list. |
| O3 | Medium | Presets are walls of text; there is no side-by-side compare with the current state or diff counts by category before staging. | 2.x cards. |
| O4 | Low | Tier A/B filters are shown on the Risk Zone page, where every item is tier R. | Shared filter row. |
| O5 | Low | "Exact changes" shows engine fingerprints (`powercfgScheme|scheme=...`). | Plan text. |

## Policy

| # | Severity | Finding | Root cause |
|---|---|---|---|
| P1 | High | No Policy browser in the GUI (CLI only: `-PolicySearch`, `-PolicyShow`, `-PolicySet`). | SPEC-v3 phase 12 was not part of 3.0 (DECISIONS R1/R2). |

## Network (Network Test)

Screenshot: `docs\screenshots\3.3\before\06-NetTest-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| N1 | Medium | Unlabeled targets box; "Measurements", "Recommended" and "Router" are empty headings before a run (no empty state or next step). | No empty states. |
| N2 | Medium | No run history or compare; no Recommended/Custom mode switch; adapter properties (Diagnostics > Network tools) are not sortable. | Not built. |

## Clean (Cleaner, Disk Analyzer)

Screenshots: `docs\screenshots\3.3\before\13-Cleaner-100.png`, `17-Disk-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| C1 | Medium | No sorting by size or rule; the total is in the toolbar and scrolls away with nothing sticky at the bottom; no per-rule expanders with samples. | Card list. |
| C2 | Low | "Ready to clean" status text looks like a link; skip reasons are short single lines. | Style. |
| C3 | Low | Disk Analyzer lists are not sortable. | ListView. |

## Manage (Services, Scheduled tasks, Apps, Persistence, Startup)

Screenshots: `docs\screenshots\3.3\before\19-Manage-100.png`, `15-Startup-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| M1 | High | See X2: one unexpected value blanks the whole page. | ValidateSet in the row helper. |
| M2 | Medium | Sort headers exist but are plain buttons without automation names; no publisher/signature columns; single selection, no bulk actions; protected items not locked with a reason in the list. | 3.0 design. |
| M3 | Medium | Search box without label or placeholder; low density (about 6 services visible). | X10, card rows. |

## Expert (Inspectors)

Screenshot: `docs\screenshots\3.3\before\20-Inspect-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| E1 | Medium | Status text wraps ("Editable (Expert) | Differs from default"); detail strip at the bottom; lists not sortable. | Card list. |
| E2 | High | The power editor's dry run (`Get-IgwtPowerSettingChangePlan`, powercfg) runs on the UI thread. | X5. |

## Toolkit

Screenshot: `docs\screenshots\3.3\before\14-Toolkit-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| T1 | Medium | No column headers or sorting (name, publisher, installed, upgrade available); unlabeled search; no per-package progress. | ListView cards. |
| T2 | Low | Disabled "Install selected" looks enabled (X8). | Style. |

## Diagnose (Diagnostics & network)

Screenshot: `docs\screenshots\3.3\before\18-Diagnostics-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| G1 | Medium | The overview is a monospace text dump, vertically centred in a large box; dates use the US format. | TextBox with formatted text. |
| G2 | Medium | Reliability records, crashes and update history are not tables (no sort, date-range or source filters, no export of the view). | Text output. |

## Profiles, Compliance, Deployment, Timeline

| # | Severity | Finding | Root cause |
|---|---|---|---|
| R1 | Medium | Profiles: personas are a header combo box only. Compliance (baseline compare) and Deployment (policy exports) exist only on the command line; there is no Timeline. | SPEC-v3 phases 10-12 not in 3.0. 3.3 adds read-only GUI views for Compliance (baseline compare) and the Timeline; Deployment stays CLI (DECISIONS). |

## Logs (Backups & Logs)

Screenshot: `docs\screenshots\3.3\before\21-Backups-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| L1 | Medium | Snapshots are tall cards with no search, sort or filter; there is no log viewer or timeline in the window (only "Open logs folder"). | 2.x page. |

## About

Screenshot: `docs\screenshots\3.3\before\23-About-100.png`.

| # | Severity | Finding | Root cause |
|---|---|---|---|
| B1 | Medium | No build information, changelog viewer or third-party notices; the version is 3.0.0. | Static text. |

## Global layout

| # | Severity | Finding | Root cause |
|---|---|---|---|
| Y1 | Low | The header hardware summary is cut off ("32 GB DDR5-60..."). | Fixed header width. |
| Y2 | Medium | The bottom bar's Preview / Apply / Discard apply to staged tweaks but sit on every page, also where nothing can be staged; the label does not say what will be applied. | Global bar. |
| Y3 | Medium | No remembered place (page, filters, sort, scroll), no breadcrumbs, no focus mode, no font scale, density or reduce-motion settings. | Not built. |
