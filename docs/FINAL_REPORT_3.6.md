# Final report: iG Windows Tuner 3.6.0 (transactions)

Built 31 October to 1 November 2026 on `feature/3.6-transactions`, merged into `main` locally with `--no-ff` and tagged `v3.6.0` (annotated, on the merge commit). Nothing was pushed and no GitHub Release was created. The real app window was never opened: every check ran headless (Pester, PSScriptAnalyzer, a Defender scan and the offscreen render suite). Nothing on this PC was changed: every test ran in a scratch test data root and the test registry.

## 1. What 3.6 does

- **Change journal and transaction engine** (DECISIONS T1 to T7, T12, T14): every change is a step of a session: intent with the exact value before, the change, a read-back, then committed or failed; a failed step rolls back its group in reverse. Append-only JSON Lines, a SHA256 chain, crash-torn writes recorded (chainNote), a head record against truncation, compaction into a checkpoint that keeps every baseline, protected folder and files. One change at a time (machine-wide mutex). Unfinished sessions are found and rolled back after a preview. Revert per change, per session or everything, with before / we set / now and Restore / Keep / Skip. The 3.5 snapshots are imported once (originals as baselines; changes still in effect as iG's; values on without a snapshot as adopted, original unknown). Every writer (tweaks, presets, forensic logging and all module writers) goes through the engine; a parser test enforces it.
- **Confidence badges** (T8, T13, T15): Verified, Best effort, Unverified, computed from the sources, this PC's journal and `evidence.testedBuilds`.
- **Declarative presets, schema v3** (T9, T16): item ids with on, default or unchanged; requires, conflicts, notes; strict checks of imported presets; a preview with Already set, Will change, Not applicable, Conflict, Managed by policy and a summary line; one session per preset.
- **Update drift guardian** (T10, T17): read-only check of every value iG set (Still applied, Drifted, Missing, Can't read), Windows updates installed in between (never named as the cause), re-apply through the normal preview or accept (journaled), per item or all.
- **Home card** (T11, T18): the Dashboard is the landing page; one card in the fixed priority order or All clear; Do it opens a preview or a page, Not now for 1 or 7 days (remembered), Why?, All pages; keyboard and automation names; correct in Dark, Light and High Contrast at 100, 150 and 200 % and the minimum size.

## 2. Commits (feature/3.6-transactions, then main)

| Commit | Subject |
|---|---|
| 81ddeed | docs(3.6): transaction engine design (DECISIONS T1-T12) |
| c3b0a30 | feat(engine): change journal and transaction engine (3.6 phase 2, part 1) |
| 5749e40 | feat(forensic): forensic logging on the change engine (3.6 phase 2, part 2) |
| 45657f4 | feat(engine): every writer on the change engine, journal tab, upgrade, compaction (3.6 phase 2) |
| 6cba4f1 | feat(confidence): computed confidence badges per tweak (3.6 phase 3) |
| 19dffc9 | feat(presets): declarative presets, schema v3, with preview (3.6 phase 4) |
| a363ee2 | feat(drift): update drift guardian (3.6 phase 5) |
| 4a452d6 | feat(home): next best action card (3.6 phase 6) |
| 1026811 | fix(3.6): review findings |
| fe6ef69 | chore(release): 3.6.0 |
| 735811f | Merge branch 'feature/3.6-transactions': iG Windows Tuner 3.6.0 (transactions) (tagged v3.6.0) |

## 3. Gates

Every phase was committed only after a green headless gate (`tools\Test-All.ps1 -SkipAutomation`).

| Gate | Pester (passed / failed / skipped, load failures) | Analyzer | Defender | Render |
|---|---|---|---|---|
| Phase 2 (45657f4) | 1016 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |
| Phase 3 (6cba4f1) | 1021 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |
| Phase 4 (19dffc9) | 1035 / 0 / 1 + the schema test fixed for v3 (26/26) | 0 / 0 | clean | 11/11 |
| Phase 5 (a363ee2) | 1044 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |
| Phase 6 (4a452d6) | 1057 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |
| Review fixes (1026811) | 1072 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |
| Release 3.6.0 (fe6ef69) | 1072 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |
| main after the merge (735811f) | 1072 / 0 / 1, 0 | 0 / 0 | clean | 11/11 |

Render = every page in Dark, Light and High Contrast at 100, 150 and 200 %, plus Dark at the minimum size (1100x720) at 100 and 200 %. The one skipped test is the pre-existing elevated-only case.

Two runs before the review-fix commit failed only on the 3.5 firewall precedence budget (3.04 s and 3.06 s against 3 s) while the PC ran about twice as slow as the day before (the committed baseline rendered just as slowly). That test now times the best of two runs after a garbage collection, like the journal budget test; the budget is unchanged.

## 4. Performance against the budgets

Measured in the final release gate and again on main after the merge, on this PC while it ran about half as fast as on 31 October:

| Budget | Target | Measured | Earlier (31 Oct, same code path) |
|---|---|---|---|
| Journal append | < 20 ms | 7.0 ms (main: 6.6 ms) | 3.1 ms |
| Open and verify 10,000 entries | < 1 s | 275 ms (main: 149 ms) | 116 ms |
| Preview of a 100-change preset | < 500 ms | 416 ms (main: 410 ms) | 358 ms |
| Drift check of 500 settings | < 2 s | 633 ms (main: 637 ms) | 157 ms |

The append now also writes the head record (truncation detection, review R13). The journal verification and the value comparison run in a small compiled engine (`src\Core\JournalEngine.cs`, managed code only, checked by tests\Safety.Tests.ps1).

## 5. End-to-end test

`tests\EndToEnd.Tests.ps1` walks the whole story on the real engine in the test registry (only window dialogs mocked): apply a preset (and one more item separately), simulate drift, the drift guardian finds it, the home card shows it, Do it opens the normal preview, re-apply (one session, origin driftFix), chain valid, revert the preset session, reset everything to the baseline, chain still valid, no unfinished session. A second run starts from a 3.5 install (snapshots, no journal), imports them and takes the same steps. It found one real bug before the review: imported 3.x data was reported as a failed restore because `missingDepth` differed (fixed).

## 6. Independent review

A separate read-only agent reviewed the whole 3.6 diff (`main..feature/3.6-transactions`). Findings: 4 High, 9 Medium, 9 Low, 3 questions. Every High and Medium is fixed with a regression test (tests\Review36.Tests.ps1, tests\Journal.Tests.ps1, tests\EndToEnd.Tests.ps1); details in docs\REVIEW.md (3.6 section).

- High: R1 untrusted 3.x snapshots in the import; R2 a real torn write made the journal read-only; R3 undoing a legacy revert did nothing; R4 the journal folder and files were never checked for owner and ACL. All fixed.
- Medium: R5 interrupted steps hidden from recovery; R6 readers could break appends; R7 partial undo of a firewall profile restore; R8 no crash-time undo reference for backup-based writers; R9 stale journal state after the legacy revert; R10 the import overwrote values changed since; R11 T6's adopted pass missing; R12 recovery without a conflict check; R13 truncation not detected. All fixed.
- Low: R14, R15, R16, R18, R20, R21, R22 fixed; R17 documented (T14 limit); R19 accepted (comparing `missingDepth` breaks restores of 3.x data).
- Questions: Q2 was a real bug (`.Contains()` on journal dictionaries fails in Windows PowerShell 5.1; the journal tab could not format real values) and is fixed; Q3 fixed; Q1 partly (readable message; a standard process holding the lock first can delay elevated changes, no escalation).

## 7. UNVERIFIED

- WindowsUpdateClient event 19 is verified on Microsoft Learn ("Troubleshoot unexpected reboots using system event logs"); its Data Names (`updateTitle`, `updateGuid`) and events 20 and 43 are verified on this PC only (DECISIONS T17).
- No catalog item has `evidence.testedBuilds` yet, so no badge is Verified on a fresh PC until a Windows Sandbox run records them (T15).
- Everything that changes Windows was tested with mocks and the test registry only; the real round trips (the journal ACL on a real elevated run, a real power-loss tear, services, firewall, policy, forensic logging) still need the Windows Sandbox run below. From 3.5, still open: whether `wevtutil sl Security /ms:` accepts the smaller size on restore (DECISIONS F12).
- Honest limits (by design, documented): an administrator who rewrites the whole journal consistently is not detected (T4); deleting the whole Journal folder looks like a fresh journal; module undo cannot compare before / we set / now per value (T14).

## 8. Release

- Version 3.6.0 in `src\Core\Environment.ps1` and `src\iGWindowsTuner.psd1`; CHANGELOG 3.6.0 (2026-11-01); `release-notes.md` (what's new, upgrading from 3.5, how to undo); README.
- Package: `dist\iGWindowsTuner-3.6.0.zip`, SHA256 `f8929a89a6c902703642016a6c4ba95efa71fd5cc2607b56376e04ea30e41a00` (also in `dist\iGWindowsTuner-3.6.0.zip.sha256`). Built with `tools\New-Release.ps1 -SkipTests` right after the green release gate (catalog check included). Checked: extracted in the scratch folder, 378 files = 377 tracked project files + SHA256SUMS.txt, every hash matches, no untracked, git-ignored or personal file, the module imports in a fresh process and reports 3.6.0 (319 exported commands).
- Not in the zip by the release script's allow-list (as in 3.5): `.gitattributes`, `.gitignore`, `release-notes.md` (the release description) and `THIRD_PARTY_NOTICES.md` (see Needs Ario).
- `main` = 735811f with the annotated tag `v3.6.0` on it; this report is the one commit after the tag (`docs(3.6): final report`); `git status` clean. The tags v3.4.0 and v3.5.0 are unchanged.

## 9. Scratch files outside the project

Nothing outside the project was deleted. The session scratch folder `%TEMP%\claude\...\scratchpad` holds 279 files and 26 folders (most from earlier releases), including from 3.6: the commit messages (commit-phase2 to 6, commit-review, commit-release), the drafts later moved into the project (Confidence.ps1, Confidence.Tests.ps1, Drift.ps1, Drift.Tests.ps1, forensic-providers.ps1), convert-presets-v3.ps1 (the one-time preset conversion), and the folders render36, render36b, render36c, render36d, render-perf, render-perf-base (offscreen screenshots), jprof (journal profiling data root) and pkg-3.6.0 (the extracted package). The test runs also leave temporary data roots under `%TEMP%` (named by GUID, `IgwtData`), as in earlier releases.

## 10. Needs Ario

- **Windows Sandbox checklist** (`tools\iGWindowsTuner.wsb`; nothing of this may run on this PC):
  1. Apply a preset (Competitive) from the Presets page: the preview, then Apply; check Backups & Logs > Change journal (one session, every step committed).
  2. Revert that session from the journal; then "Reset everything iG changed"; check the values against before.
  3. Simulated drift: change a value iG set (for example turn Game Mode back off), restart the app: the home card shows it; re-apply through the preview; accept another one.
  4. Crash mid-transaction: start a preset and end the process (Task Manager) during Apply; restart: the home card offers the rollback; roll back.
  5. Upgrade from 3.5 to 3.6: install 3.5.0, apply a preset and one tweak, replace with 3.6.0, make a change: the 3.5 snapshots are imported (journal tab), revert the imported session, reset everything.
  6. Forensic logging round trip (still open from 3.5), including the Security log size restore.
  7. Optionally record `evidence.testedBuilds` for the items that read back correctly.
- **Real-window UI Automation run** (`tools\Test-GuiAutomation.ps1`, read-only), if you want one before publishing; it was not run, as agreed.
- **Scheduled drift check**: not built. It conflicts with T13 (no scheduled task, no-persistence rule). Decide whether to change T13 for a later release.
- **THIRD_PARTY_NOTICES.md** is tracked but not in the release zip (the release script's allow-list, unchanged since 3.5). Decide whether it should ship.
- **v3.4.0 tag**: unchanged and local only, as you decided on 30 October (never pushed). Nothing to do unless you want it deleted.
- **Unverified items**: sec.lolbin-outbound-block (MITRE only) and system.bsod-details (WinUtil only) stay Unverified unless a Microsoft source is added.
- **To push and publish** (from a terminal with your GitHub credentials, or GitHub Desktop):
  1. `git -C "C:\IntelGates Tune\iGWindowsTuner" push origin main`
  2. `git -C "C:\IntelGates Tune\iGWindowsTuner" push origin v3.5.0 v3.6.0` (3.5.0 was never published either; push only the tags you want public)
  3. On GitHub: Releases > Draft a new release > choose tag v3.6.0, title "iG Windows Tuner 3.6.0", paste `release-notes.md`, attach `dist\iGWindowsTuner-3.6.0.zip` and `dist\iGWindowsTuner-3.6.0.zip.sha256`, publish.
  4. Optionally delete the merged branch: `git branch -d feature/3.6-transactions`.
