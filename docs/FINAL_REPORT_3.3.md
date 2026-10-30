# Final report: iG Windows Tuner 3.3 (quality release, shipped inside 3.4.0)

3.3 was not released on its own (DECISIONS F5): its phases 0-10 were finished on branch `feature/3.4-firewall` and ship as 3.4.0 together with the Firewall Manager (`docs\FINAL_REPORT_3.4.md`). All checks on the development PC were headless (Pester, PSScriptAnalyzer, offscreen renders, Defender scan); the GUI was not opened after the 2026-10-24 instruction, so the UI Automation suite is under Needs Ario.

## Issues from the UI audit (docs\UI_AUDIT_3.3.md)

61 findings: 12 High, 36 Medium, 13 Low. **All 12 High are fixed.** Of the 36 Medium, 29 are fixed, 3 are partly fixed (N2, C1, T1), 2 are open (D3, Y2) and 2 could not be verified headless (X16 memory growth needs the UI Automation run; E1 was not re-checked); each open part is listed below.

| Section | Fixed | Partly or open |
|---|---|---|
| Cross-cutting | X1 error boundary, X2 neutral fallback rows, X3 `-ReadOnly`, X4 themes and high contrast, X5 queries off the UI thread, X6 runspace pool, X7 partial refresh, X8 visibly disabled buttons, X9 14 px body text, X10 labelled inputs, X11 grouped navigation, X12 accessible navigation | X16 memory growth: needs the UI Automation run (Needs Ario) |
| Firewall | F1-F5 (Firewall Manager, then the 3.4 rebuild) | |
| ASR Center | A1-A4 | |
| Security and Defender | S1-S3, S5 | |
| Dashboard | D1 recent changes with Undo, pending restart tile, persona shortcuts; D2 | D3 open: tiles still say "checking" until the health report arrives (no skeleton) |
| Optimize pages | O1 SmartGrid toolbar, O2 sort/group/chips, O3 preset compare | |
| Policy | P1 Group Policy browser | |
| Network Test | N1 empty state and labelled targets | N2 partly: run history with change vs the run before and sortable adapter properties are built; a Recommended/Custom/Auto mode switch is not (Auto mode was never part of 3.x) |
| Clean | | C1 partly: sortable by size and rule with sizes and skip reasons visible; the total is not sticky and there are no per-rule expanders |
| Manage | M1, M2, M3 (SmartGrid with signature and publisher columns, multi-select) | |
| Expert | E2 power dry run off the UI thread | E1 not re-checked after the move to SmartGrid |
| Toolkit | | T1 partly: sortable, searchable lists with labels; no per-package progress |
| Diagnose | G1 cards and tables, G2 event and update tables with chips and export | |
| Profiles, Compliance, Timeline | R1 Group Policy > Compliance (read-only) and the Backups & Logs snapshot and log views (timeline); Deployment stays command line (decision) | |
| Logs | L1 log viewer, searchable snapshots | |
| About | B1 build info, changelog, notices | |
| Global layout | Y3 remembered page and lists, breadcrumbs, focus mode, text size, density, reduce motion | Y2 open: the Preview/Apply/Discard bar is still shown on every page |

UX checklist (C1-C12, `docs\UX_GUIDELINES.md`): the independent review's per-page table is summarised in `docs\REVIEW.md` (3.3 section). The pages built or rebuilt in 3.3/3.4 (Firewall, Group Policy, Network Test, Disk, Backups & Logs, ASR Center) pass most items; Presets, Diagnostics, Inspect, Toolkit, Manage and Startup still lack a one-line status with a single primary action (C1), some results still use dialogs instead of a toast with Undo (C7), and tab and expander state is not remembered everywhere (C9). These are recorded as known UX gaps; none affects safety.

## Firewall Manager

See `docs\FINAL_REPORT_3.4.md`. Measured in 3.3 (phase 3): 500 rules in 0.7 s warm, 1.7-2.3 s in a fresh background runspace.

## Screenshots

- Before (3.0 interface): `docs\screenshots\3.3\before\`
- After (3.4.0, offscreen from demo data): `docs\screenshots\3.4\` and every page in every theme and scale under `artifacts\gui-render\` (local, git-ignored)

## Performance budgets

| Budget | Result |
|---|---|
| Cold start < 3 s | **Not met: 4.4 s** from launching the process to the first rendered window in the UI Automation run (powershell.exe start, module import 0.6 s, window build 2.6 s, first render 0.3 s). Offscreen proxy: module import 0.62 s + window built 2.31 s when the PC was idle (2.70 s in the final gate run with other programs busy) = about 2.9 to 3.3 s, at the budget edge (was about 3.5 s; catalog loading 576 -> 138 ms, cleaner rules on first use). A real window's first paint needs the UI Automation run. |
| Page switch < 300 ms | Offscreen, mocked data, to first layout (no paint): median 38.5 ms, slowest 198 ms, 0 of 26 pages over 300 ms. |
| Sort/filter < 200 ms | 5,000 rows within budget (test). |
| No UI-thread stall > 200 ms; memory < 50 MB growth after 20 cycles; zero exceptions and binding errors | **Met** in the UI Automation run on 2026-10-29 (real window, read-only, real data): 0 freezes over 200 ms in app work (page loads, navigation of 26 pages x 20 cycles, resize, themes), +0.8 MB retained managed heap after 20 cycles (84 MB raw private growth, garbage not yet collected), 0 exceptions, 0 binding errors. Not counted (DECISIONS U8b): one 325 ms block at the first render (start-up) and 4 freezes while the harness scanned pages with UI Automation. Fixed on the way: the worker pool opened on the UI thread (4.4 s), pool growth on the first multi-read page (about 1 s), the progress bar animation (250 ms every 2 s), applying data in one block (400 ms), 12 binding errors from rebuilding the navigation twice at start-up. |
| Layouts at 100/150/200 % and 1100 x 720 | Rendered in Dark, Light and High Contrast at 100/150/200 % and at 1100 x 720 (100 and 200 %); responsive three-pane layouts and toolbars so nothing clips. |

## Review

`docs\REVIEW.md`, 3.3 section: no High findings; 4 Medium (Check installed, Clean selected and Run fix enabled in read-only mode; Defender "Set policy" never enabled) and 4 Low read-only findings, all fixed; UX findings fixed except the gaps listed above. The 3.4 review (firewall action and remote-session safety) had 2 High and 6 Medium, all fixed.

## GitHub

Merged into `main` and tagged `v3.4.0` locally (`git log main -1`, `git show v3.4.0`). **Not pushed yet**: this machine has no stored HTTPS credentials for github.com and gh is not installed, so the push is left to Ario (GitHub Desktop: open the repository, check that `main` is checked out, Push origin; push the tag with Repository > Push tags, or `git push origin main` and `git push origin v3.4.0`). The secrets and personal-data scan of the working tree and the full history (33 commits) found nothing, and `.gitignore` was extended (captures, policy and firewall exports, app state, snapshots, Sandbox results, keys).

## Needs Ario

- Push `main` and the `v3.4.0` tag (GitHub Desktop) and, if wanted, create the GitHub release from `docs\CHANGELOG.md` with `tools\New-Release.ps1`'s zip and SHA256 manifest.
- Run `tools\Test-GuiAutomation.ps1` (real GUI, read-only) for stalls, memory, exceptions and binding errors, and the Windows Sandbox test.
