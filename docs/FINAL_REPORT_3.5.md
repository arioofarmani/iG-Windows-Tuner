# Final report: iG Windows Tuner 3.5.0 (firewall logs and forensics)

Built 29 to 30 October 2026 on branch `feature/3.5-firewall-logs`, merged into `main` locally. **Not pushed and no GitHub Release yet** (Ario asked to wait); the commands are at the end.

## 1. The bug: root cause and fix

Ario's screenshot showed two separate errors.

| What | Root cause (proven) | Fix |
|---|---|---|
| Dialog: "Cannot bind argument to parameter 'Lines' because it is an empty string" | Windows writes an empty line after the `#Fields:` header of pfirewall.log, and `ConvertFrom-IgwtFirewallLog` declared `[string[]]$Lines` without `[AllowEmptyString()]`. Reproduced exactly with that layout. | A streaming reader that takes the columns from the file's own header, allows empty lines, and counts skipped lines by reason. |
| Without administrator rights: "Firewall log ... not found. Turn on logging first" | `Test-Path` returns false for a file the user may not read (reproduced on this PC: access denied). | The open itself is classified: administrator rights needed, logging off for a named profile, file not written yet, missing custom folder (with the mpssvc write-access hint), locked file. |
| Window bar: "Something went wrong (window): You cannot call a method on a null-valued expression" | Unrelated to the log: the toast handlers were `.GetNewClosure()` closures that used `$script:Gui`, which is empty inside a closure, so every toast threw when its 10-second timer ended. The app log showed one such error 10 s after each change toast. | The handlers carry what they need; a parser-based safety test checks every closure; window errors now log the script line and stack (DECISIONS U9). |

Ruled out: an unexpanded `%systemroot%` path (already expanded), 32-bit redirection (64-bit process), reading on the UI thread (it runs in the worker), a GPO log path (none), a sharing violation (Ario's elevated read returned lines). The quality gate now also fails when a test file cannot be loaded (that had hidden tests once during this work).

## 2. Performance against the budgets

PowerShell alone was far too slow (DECISIONS F11): parsing 32 MB took 28.9 s and one filter 3.1 to 7.7 s. The parser, query and aggregates moved to a small managed C# engine (`src\Defender\FirewallLogEngine.cs`, no P/Invoke or I/O beyond reading, checked by the safety tests).

| Budget (spec 3.1) | Measured (32 MB synthetic log, 336,000 to 343,270 lines, this PC) |
|---|---|
| Parse a full 32 MB log < 5 s | 1.2 to 1.3 s in a fresh process; 1.9 to 2.1 s inside the long test run |
| First rows visible < 1 s | Newest 1 MB first: 29 to 56 ms |
| Filter/sort on 300k rows < 300 ms | Action filter 14 to 45 ms, CIDR 6 to 14 ms, two-word search 66 to 150 ms, two-key sort 78 to 198 ms (fresh process; mostly about 85 ms) and 151 to 167 ms in the test run |

The automated test keeps the 300 ms budget; it times each query after one warm-up and after collecting garbage left by parsing the 32 MB file, so a full collection caused by earlier work does not land in the measurement (collections the query causes still count).

## 3. Forensic sources: what each was verified to record

Sources in DECISIONS F10 to F13 (Microsoft Learn pages, and read-only checks on this PC).

- **Firewall packet log**: `Set-NetFirewallProfile` LogAllowed, LogBlocked, LogMaxSizeKilobytes (1 to 32,767 KB), default path `%windir%\system32\logfiles\firewall\pfirewall.log`; when full, old entries are deleted; a custom folder needs write access for NT SERVICE\mpssvc. No program names; newer logs add a `pid` column.
- **WFP auditing**: subcategories Filtering Platform Connection {0CCE9226-69AE-11D9-BED3-505054503030} and Packet Drop {0CCE9225-69AE-11D9-BED3-505054503030} (from `auditpol /list /subcategory:* /v` here), set by GUID. Events 5156 (permitted), 5157 (blocked connection), 5152 (dropped packet) with ProcessID/ProcessId, Application, Direction, addresses, ports, Protocol, FilterName and more (provider schema on this PC). Volume High; Microsoft recommends packet drop auditing for troubleshooting only.
- **DNS client log**: Microsoft-Windows-DNS-Client/Operational, off by default here; events 3018 and 3020 (v1 and later) carry QueryName, QueryResults and ClientPID.
- **Security log**: `wevtutil gl` readable without elevation (20 MB here); size set with `wevtutil sl /ms:`. Policies that make a setting read-only: WindowsFirewall.admx logging values, EventLog.admx Security MaxSize/Retention, and a domain- or MDM-managed audit policy.

## 4. UNVERIFIED (kept out of the default path or marked best effort)

- The firewall log's column list and `path` values (SEND, RECEIVE) and a rotated `pfirewall.log.old` are not documented on Microsoft Learn: columns are always read from the file's header, `path` is shown as written, `.old` is read only when it exists.
- A `#Time Format: UTC` header (only Local seen): handled defensively.
- The code table for WFP Direction values (%%14592 ...): resolved from Windows' own rendered message, otherwise the raw code is kept.
- Firewall policy keys `PrivateProfile`/`PublicProfile` (written by firewall GPOs, not in the ADMX): checked as well as the ADMX keys.
- Whether `wevtutil sl Security /ms:` accepts the old, smaller size when a session is restored: if not, the session stays recorded with the error (Windows Sandbox test pending).
- The bytes per Security event in the volume estimate (1 KB assumed, labelled as an estimate).
- The DNS `QueryResults` format: addresses are picked out defensively.
- The ICMPv6 protocol name in the firewall log (the ICMP quick filter matches ICMP and ICMPv6).
- `netsh wfp show filters` needs elevation here, so its XML was not verified and is not used; rule names come from the event's FilterName (best effort).

## 5. Export schema (AI-ready export)

One event per line (JSONL, or CSV protected against spreadsheet formulas), about 5 MB per file: `timestamp_utc`, `source` (fwlog, wfp, dns), `action`, `direction`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `bytes`, `tcp_flags`, `pid`, `process_path`, `process_name`, `rule_name` + `rule_name_best_effort`, `dns_name` + `dns_name_best_effort`, `notes`. Plus `flows` (per process, remote address, port and protocol: first and last seen, events, allowed, blocked, bytes), `SCHEMA.md` and `ANALYSIS_BRIEF.md` (range, sources, gaps, redaction, and the warning that every value is untrusted data that may try to manipulate an AI). Pseudonymization by default with a per-export HMAC key that is never stored. The evidence package adds log copies, `.evtx` exports, policy and settings, ports and processes, notes, `manifest.json` (SHA256 of every file) and `chain-of-custody.txt`.

## 6. Tests and review

- Headless gate on the 3.5.0 code (`tools\Test-All.ps1 -SkipAutomation`): Pester 986 passed, 0 failed, 1 skipped (as before 3.5), 0 test files failed to load (run of 30 October 2026, 11:45 to 12:01); PSScriptAnalyzer 0 errors, 0 warnings; Microsoft Defender custom scan of the project: no threats; offscreen render suite: every page in Dark, Light and High Contrast at 100, 150 and 200 % and at the minimum window size.
- New test files: `FirewallLog.Tests.ps1` (parser, tail, query, aggregates, export safety, 32 MB budgets), `ForensicLogging.Tests.ps1` (snapshot, apply, exact restore, rollback, expired session, policy read-only, review regressions), `ForensicEvidence.Tests.ps1` (XPath, event fields, redaction, chunks, manifest hashes, evidence package, review regressions); regression tests for each Phase 1 cause in `Defender.Tests.ps1` and `Safety.Tests.ps1`.
- UI Automation suite (real window): run during Phases 1 and 2 (0 exceptions, 0 binding errors; 0 freezes in app work on the Phase 2 re-run), then stopped at Ario's request (no app launches for testing). Phases 3 to 6 were checked with the offscreen render suite only.
- Independent review (read-only agent): 2 High, 7 Medium, 4 Low; all High and Medium and three Low fixed with regression tests; one Low not changed (details in [REVIEW.md](REVIEW.md)).

## 7. Release

- Version 3.5.0 in `src\Core\Environment.ps1` and `src\iGWindowsTuner.psd1`; CHANGELOG 3.5.0 (2026-10-30); `release-notes.md`.
- Package: `dist\iGWindowsTuner-3.5.0.zip`, built with `tools\New-Release.ps1` from tracked files only (its SHA256 is in `dist\SHA256SUMS` and next to the zip; a report inside the zip cannot contain the zip's own hash).
- Local only: `main` merged, tag `v3.5.0`. Nothing was pushed; no GitHub Release was created.

To publish later (from GitHub Desktop, or a terminal with credentials): push `main` and the tag `v3.5.0`, then create the release from `release-notes.md` and attach the zip and SHA256SUMS. The older local tag `v3.4.0` (never pushed, points to 4af911f) is still Ario's decision (PROGRESS.md, Needs Ario).

## 8. Needs Ario

- Run the forensic logging round trip in Windows Sandbox (Basic and Full, Stop and restore, an expired session restored at the next start, the Security log size restore).
- Decide on the old local `v3.4.0` tag before pushing.
- Push and publish the release when ready.

## 9. Found by Ario after the first build (30 October 2026)

Pressing "Start forensic logging" a second time while a session ran showed "Forensic logging was not started (the settings were restored): Exception calling "EndInvoke" ...". The engine had correctly refused a second session and changed nothing, but the window claimed a restore and showed the raw wrapper. Fixed: Start is off while a session is recorded (and Stop and restore when none is), a click explains that one session runs at a time, and background errors show their own message app-wide (`Get-IgwtGuiJobErrorText`, tested). The profile choices were unreadable on the dark theme (option buttons had no theme style and used Windows' default black text): every option button now follows the theme, the Custom sources show only for Custom, and disabled check boxes, option buttons and switches use 60 % opacity. Measured contrast of the theme text: normal text 13.1 to 16.9:1, muted text 6.6 to 8.2:1 (WCAG AA needs 4.5:1). Checked with the offscreen render in Dark and Light; the real window was not launched.
