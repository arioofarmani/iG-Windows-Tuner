# 3.0 starting audit (Phase 0)

Audit of iG Windows Tuner 2.2.0 before the 3.0 work, taken on 21 Oct 2026 on the development PC (Windows 11 Pro 26H2, build 26300.9711, i7-13700K, RTX 3080, Marvell AQtion 10GbE). All checks below are read-only.

## Sources read

- `PROGRESS.md` (local), `docs/DECISIONS.md`, `docs/CHANGELOG.md`, `docs/TESTING.md`, the catalog, the git log (`52b3a99` 2.0 preview, `c79b405` 2.2).
- `docs/FINAL_REPORT.md` and `docs/REVIEW.md` do not exist yet: the v2 final report and independent review (v2 phases 11 and 12) were never done.
- No "Needs Ario" items were recorded before this audit. Items that waited on the user were all "the user runs the Windows Sandbox test".

## Baseline checks

| Check | Result |
|---|---|
| Catalog (`tools\Test-Catalog.ps1`) | OK: 104 tweaks (57 Tier A, 28 Tier B, 19 Risk Zone), 3 presets, 38 rejected entries (19 offered in the Risk Zone) |
| Pester 5.7.1 | **553 passed, 0 failed, 1 skipped** (the symlink test needs Developer Mode); 147 s |
| PSScriptAnalyzer | 0 errors, 0 warnings, 0 information |
| Defender custom scan of the project | no threats |
| `-Report` | runs read-only in 12.3 s, exit 0; shows the hardware tags |
| `-Preset Competitive -DryRun` | 4.9 s: 1 to change, 41 already set, 2 not applicable |
| `-Preset Balanced -DryRun` | 3.9 s: 2 to change, 33 already set |
| `-Preset Hardened -DryRun` | 4.1 s: 3 to change, 39 already set, 1 not applicable |
| `-Clean -Scan` | 5.9 s: 1.71 GB in 2,570 items, deletes nothing |

## SPEC-v2 phases

| # | Phase | Status | Notes |
|---|---|---|---|
| 1 | Baseline, schema v2, migration | Complete | git was added later (GitHub repo); no `v1-baseline` tag, the v1 tree is archived as a zip |
| 2 | Hardware profile engine and overlays | Complete | |
| 3 | New action handlers | Complete with documented deviations | `bcd` not implemented (DECISIONS A1), `fileAssociation` read-only (A2) |
| 4 | Cleaning engine | Complete | |
| 5 | ASR Center and security modules | Complete | |
| 6 | Expert controls and inspectors | Complete | |
| 7 | Management and diagnostic modules | Complete | |
| 8 | WinUtil investigation, mapping and Toolkit | **Missing** | no `docs/WINUTIL_MAPPING.md`, no Toolkit section (Install, Tweaks, Features, Fixes, Panels, Updates), no `THIRD_PARTY_NOTICES.md` |
| 9 | Presets 2.0, custom presets and drift | **Missing** | 3 of the 10 presets exist (Competitive, Balanced, Hardened); no Streamer & Creator, Engineer Workstation, Laptop Gamer, Privacy Max, Clean Install / Debloat, Fortress, Session Mode; no custom preset builder or drift report |
| 10 | GUI restructure, command palette, timeline, CLI parity | **Partial** | CLI covers every module with `-Json`; missing: grouped navigation, mode switcher, command palette (Ctrl+K), change timeline, pending-reboot center, localization resource files, `docs/CLI.md` |
| 11 | Tests, Sandbox runner, independent review | **Partial** | tests are broad; the Sandbox runner only covers apply/revert of non-expert tweaks (not presets on the VM fixture or the cleaner); no independent review or `docs/REVIEW.md` |
| 12 | Documentation, release build, final report | **Partial** | most docs exist; missing `docs/EXPERT_LAB.md`, `docs/WINUTIL_MAPPING.md`, `docs/CLI.md`, `docs/REVIEW.md`, `THIRD_PARTY_NOTICES.md`, the v2 final report; `tools\New-Release.ps1` exists (the spec called it Build-Release) |

## SPEC-v2 Definition of Done

| Item | Status |
|---|---|
| `-Report` read-only with hardware tags | Complete |
| `-Preset <each of the 10> -DryRun` with overlay reasons | Partial: 3 presets |
| `-Clean -Scan` lists sizes per rule, deletes nothing | Complete |
| GUI opens every section at every mode level; every item shows real state, hint and details | Partial: all pages render with real state and details, but there is no mode switcher |
| Pester green, analyzer clean, Defender clean, review without open high findings | Partial: no review yet |
| v1 snapshots revert after migration | Complete (tests in `Schema.Tests.ps1`) |

## Open issues by severity

### High

- None in shipped behavior: no data-loss, safety-gate or revert defect was found.

### Medium

- **M-1 Slow state scan.** Detecting all 104 items takes 12-15 s (`-ListTweaks` 11.7 s, GUI data 13.2 s), against the 3 s cold-start target. Two items cause 6.4 s: `sec.lolbin-outbound-block` (10 separate `Get-NetFirewallRule` calls, 3.2 s) and `privacy.telemetry-tasks-off` (8 separate `Get-ScheduledTask` calls, 3.2 s). Further: firewall profiles 1.1 s, TCP setting 0.8 s, PnP/MSI 0.8 s, DoH 0.7 s, `New-IgwtContext` 1.2 s.
- **M-2 Missing v2 features**: Toolkit (phase 8), seven presets, custom presets, drift report, Session Mode (phase 9).
- **M-3 Missing v2 UX**: mode switcher, command palette, change timeline, pending-reboot center (phase 10).
- **M-4 No independent review** of the deletion primitive, Lab gates, anti-cheat and preset rules (v2 DoD).
- **M-5 Sandbox runner coverage**: no presets on the VM fixture, no cleaner scan, clean and verify cycle, and none of the 2.x modules (ASR, power editor, management, Risk Zone).
- **M-6 Missing docs**: CLI reference, expert/Lab guide, WinUtil mapping, review, third-party notices, v2 final report.

### Low

- **L-1** `risk.memory-compression-off` reports Unknown when not elevated (`Get-MMAgent` needs administrator rights); correct but uninformative before elevation.
- **L-2** The Rejected Tweaks page and the Risk Zone overlap; the Rejected page links to Risk Zone ids but cannot open them.
- **L-3** Strings are inline in XAML and code, not in resource files (v2 "localization-ready" item).
- **L-4** Per-monitor DPI is system-DPI only (DECISIONS E7, documented).
- **L-5** On the development PC IPv6 is fully disabled by an earlier tool (DisabledComponents 0xFF); environment, not a product defect.

## Code and test metrics

| Metric | Value |
|---|---|
| Source lines (`src\`, .ps1 and .xaml) | 16,903 |
| Test lines (`tests\`) | 4,935 |
| Functions in `src\` | 593 (126 exported) |
| Largest files | `Gui\Gui.ps1` 1,941 lines, `Security\AsrCenter.ps1` 673, `Gui\ViewModels.ps1` 659, `Network\NetworkQuality.ps1` 640, `Actions\Registry.ps1` 614 |
| Slowest test files | Cleaner 37.7 s, Asr 20.6 s, Schema 16.3 s, Manage 13.0 s |

Hotspots: `Gui.ps1` mixes all pages in one file (split by page planned for Phase 12); state detection runs sequentially with per-action queries for firewall rules, tasks and adapters (M-1).

## Performance

| Measure | Value | Target |
|---|---|---|
| Module import (new process) | 0.34-0.52 s | |
| Main window parse | 0.18 s | |
| Window shown (cold, read-only) | about 0.6 s | < 3 s |
| Background state scan until toggles show state | 13.2 s (16.3 s with the health report) | < 3 s with caches warm |
| `-Report` | 12.3 s | |

The window appears quickly and stays responsive (worker runspace), but item states arrive only after the full scan. Phase 1 batches the slow queries; Phase 12 adds progressive loading.

## Plan for Phase 1 (stabilize v2)

1. Fix M-1: one firewall rule query and one scheduled task query per scan (cached, invalidated after every apply), cached firewall profile, TCP and PnP reads; progressive state loading in the GUI.
2. Presets 2.0: the seven missing presets with the items they need, custom presets (builder, save, duplicate, import/export with SHA256), drift report, Session Mode with crash-safe revert.
3. Toolkit: WinUtil investigation and mapping with the commit hash, adopted and adapted items in the catalog, Install (winget), Features, Fixes (preview first), Panels, Updates; `THIRD_PARTY_NOTICES.md`.
4. Sandbox runner: presets on the VM fixture and the cleaner cycle.
5. Independent review of the v2 scope; fix high and medium findings; `docs/REVIEW.md`.
6. Docs: CLI reference, expert/Lab guide, WinUtil mapping; then tag `v2-final`.

The GUI restructure items of v2 phase 10 (grouped navigation, mode switcher, command palette, timeline, pending-reboot center) are done together with the 3.0 persona switch in Phase 12, so the navigation is redesigned once.
