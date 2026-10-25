# Final report: iG Windows Tuner 3.4.0 (Firewall Manager)

Built 2026-10-24 on branch `feature/3.4-firewall` from SPEC-v3.4 (phases 0-10), together with the remaining 3.3 phases (DECISIONS F5; see `docs\FINAL_REPORT_3.3.md`). Every measurement on this PC was read-only and not elevated; the GUI was never opened (headless tests and offscreen renders only).

## This PC (counts only)

Read-only audit at the end of the build, role Gaming PC, not elevated (port, address and program filters need administrator rights, so the audit is marked partial and the exposure map is "unknown"):

| Measure | Count |
|---|---|
| Rules (active store plus Windows Service Hardening) | 687 |
| Core Services / Windows Connections / User Installed / Custom Rules | 223 / 436 / 18 / 10 |
| Inbound / Outbound / Blocked | 362 / 325 / 131 |
| Confidence High / Medium / Low | 666 / 21 / 0 |
| Locked (service hardening, Group Policy) | 180 |
| Rules with findings ("Security Risks") | 12 |
| Findings Critical / High / Medium / Low | 0 / 1 / 0 / 11 |
| Needs attention (Critical + High) | 1 |
| Bloated rules enabled for this role | 0 |
| Quick wins | 0 now; 9 when first measured |

**Quick wins:** the first audit on 2026-10-24 found 9 quick wins (enabled rules the Gaming PC role does not need). At the final run there are none: firewall snapshots on this PC from 21:13 to 21:22 record changes made through the app's own change engine (Disable 9 rules, Delete 4, Edit 2, SetAction 1, Delete 1), so those rules were disabled through the app before the final measurement. All 223 rules in groups that are bloat for a gaming PC are now disabled. The 12 rules with findings are user-installed or custom rules (missing descriptions, one program in a user-writable folder; the orphaned-program rules seen earlier are gone).

## Performance

| Measure | Result | Budget |
|---|---|---|
| Classification of 1,000+ synthetic rules | under 5 s cold, under 1 s cached (test) | 5 s / 1 s |
| Classification of this PC's rules | 0.52 s (in the full audit) | |
| Full audit on this PC (inventory, packages, defaults, signatures, listeners, classification, findings, precedence, exposure, history, summary) | 9.4 s cold at the final run (inventory 3.2 s, findings 1.6 s, precedence 1.2 s, listeners 1.1 s); 7.9 s cold / 3.4 s warm earlier | runs in the background worker |
| Audit of 1,030 synthetic rules plus a scope plan | 5.2 s (test, budget 10 s) | DECISIONS F9 |
| Defaults comparison plus matching 500 connections | 1.6 s (test, budget 2 s each) | DECISIONS F9 |
| This PC: defaults comparison / live connections | 277 ms (393 default rules) / 330 ms (159 connections) | |

## What was built

Knowledge base (`data\firewall`: 9 groups, 28 rule groups with Microsoft sources, 13 risk rules, 22 ports, 18 services, protected game/launcher/anti-cheat programs, 4 roles, 7 templates, 4 scopes) with a validator; classification (origin, facets, Bloated per role, confidence, reasons, user overrides); risk findings with plain explanations and safe fixes; exposure correlation with live listeners; precedence and conflict analysis; the Overview dashboard, group sidebar, details pane, bulk actions and smart fix wizard; rule templates with risk warnings before creation; the Windows defaults comparison; live connections; the audit report (HTML/CSV/JSON); firewall-scope presets named by the tweak presets; a role picker; the Sandbox round-trip step (classify, bulk-disable quick wins, revert, default-baseline export). User guide: `docs\FIREWALL.md`; generated reference: `docs\FIREWALL_CATEGORIES.md`.

## Review

Independent review (`docs\REVIEW.md`, 3.4 section): 2 High, 6 Medium, 6 Low. Both High (the engine planned changes without the classification, so Core Services and Windows-rule locks held only in the GUI; leftover queued batches could run later without confirmation) and all Medium findings are fixed with regression tests; L1-L4 fixed, L5 accepted, L6 checked (0 duplicate rule IDs among 687 rules). No open High findings.

## Tests and checks (final gate)

Final gate (headless, 2026-10-25): Pester 924 passed, 0 failed, 1 skipped; PSScriptAnalyzer 0 errors, 0 warnings; Microsoft Defender scan of the project folder clean; offscreen renders of 29 pages in Dark, Light and High Contrast at 100/150/200 % and at 1100 x 720 (100 and 200 %) without warnings. The run before it had one failure: the precedence performance test exceeded its 3 s budget while the PC was busy (renders in that run were 2.5 times slower than usual); the test passed alone twice and in the re-run, and its budget was not changed. UI Automation suite: not run (it opens the GUI; Needs Ario).

## GitHub

Merged into `main` and tagged `v3.4.0` locally (`git log main -1`, `git show v3.4.0`). **Not pushed yet**: this machine has no stored HTTPS credentials for github.com and gh is not installed, so the push is left to Ario (GitHub Desktop: open the repository, check that `main` is checked out, Push origin; push the tag with Repository > Push tags, or `git push origin main` and `git push origin v3.4.0`). The secrets and personal-data scan of the working tree and the full history (33 commits) found nothing, and `.gitignore` was extended (captures, policy and firewall exports, app state, snapshots, Sandbox results, keys).

## Needs Ario

- Push `main` and the tag (GitHub Desktop; HTTPS has no stored credentials and gh is not installed here).
- Run the UI Automation suite (`tools\Test-GuiAutomation.ps1`, opens the GUI in read-only mode) and the Windows Sandbox test (`tools\iGWindowsTuner.wsb`, now with the firewall round-trip and the default-baseline export).
- An elevated read-only audit would fill the exposure map and the port-based findings that the non-elevated runs could not read.
- The firewall changes made through the app on 2026-10-24 between 21:13 and 21:22 (snapshots in `%ProgramData%\iGWindowsTuner\Backups`) were not made by the build session; they can be undone from Backups & Logs if they were not intended.
