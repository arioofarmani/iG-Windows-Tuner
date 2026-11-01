# Independent review

## v2 scope (3.0 phase 1, 22 October 2026)

An independent reviewer (a separate agent with read-only access) audited the cleaner deletion primitive, the Lab, Expert and Risk Zone gates, the anti-cheat and preset rules with their integrity checks, the new Toolkit, Session Mode, the registry handler additions, the query caches and the management changes against the rules in `CLAUDE.md`. It ran the Cleaner, Presets, Toolkit, Safety and Risk Zone test suites (all passed) and changed nothing.

The reviewer found the core design sound: the cleaner deletes single files from an allow-list and re-validates each one right before deleting it, the engine refuses Expert and Lab items without an acknowledgement, snapshot restores take their paths from the catalog, fix and panel programs come from fixed lists, and winget ids are validated with a fixed source. It reported 3 High, 6 Medium and 8 Low findings. **All High and Medium findings are fixed**, each with a regression test in `tests\Review.Tests.ps1`; most Low findings are fixed too, and the rest are recorded below.

| # | Severity | Finding | Resolution |
|---|---|---|---|
| H1 | High | Downloads files moved to the Recycle Bin could be purged by the Recycle Bin rule in the same clean when the rules were listed in that order. | **Fixed.** Recycle Bin rules always run first in a clean. |
| H2 | High | "Send to Recycle Bin" silently became a permanent delete when Windows could not recycle a file (network or removable drive, bin set to delete immediately, file larger than the bin). | **Fixed.** `Get-IgwtRecycleRefusal` checks the drive type and the bin's settings and size limit; such files are skipped with the reason. |
| H3 | High | The Lab item `sec.vbs-hvci-off-expert` turned VBS/HVCI off, against the stated safety boundary. | **Fixed.** The item is retired (`status: NotApplicable`): it can no longer be applied and stays only so an earlier change can be reverted. `data\rejected.json` and the docs say so. |
| M1 | Medium | The GUI drift "Re-apply" could re-stage Expert, Lab or Risk Zone items and apply them with an automatic acknowledgement. | **Fixed.** The GUI acknowledges only items confirmed in their dialog and refuses others; drift re-apply skips Expert, Lab and Risk Zone items; the drift record holds only the preset's own selection. |
| M2 | Medium | Custom presets were not re-checked against the preset rules when loaded, and a file without `include` passed the SHA256 check. | **Fixed.** Custom presets are validated on every load (files with a legacy `tweaks` list or no `include` are skipped), and a preset's own items never include Lab or Risk Zone items in `Resolve-IgwtPresetSelection`. Custom presets cannot take a built-in name. |
| M3 | Medium | Session Mode was not crash-safe while it was starting. | **Fixed.** The session record is written before anything changes (`state: starting`); an interrupted start is detected as stale and its snapshot is found by time. |
| M4 | Medium | The Recycle Bin rule emptied everything in the bin at clean time, not what the scan showed. | **Fixed.** A drive's bin is emptied only when it did not grow since the scan; otherwise the rule asks for a new scan. |
| M5 | Medium | Junctions above a rule root were not detected (risky in all-users cleaning). | **Fixed.** `Test-IgwtCleanerRootChain` refuses a root when any folder above it is a reparse point, at scan time and before each deletion. |
| M6 | Medium | Management changes could enable SMBv1, PowerShell 2.0 or Telnet, and some security services were not protected. | **Fixed.** Insecure legacy features and capabilities are never enabled; BITS, Delivery Optimization, the Defender core service, Enhanced Phishing Protection and AppID are protected. |
| L1 | Low | A failed service stop during a clean left earlier services stopped. | **Fixed.** Services already stopped are restarted before the error is reported. |
| L2 | Low | Toolkit fix steps were checked against their allow-lists only in the catalog test. | **Fixed.** Every step is checked again when it runs. |
| L3 | Low | The hardware overlay block fails open when hardware detection fails. | Known issue, planned for phase 2 (unknown hardware will block overlay-guarded items). |
| L4 | Low | Resetting a `bitSet` item deleted the whole shared value. | **Fixed.** Only its own bit is cleared; the value is removed only when nothing is left. |
| L5 | Low | Ending a session removed its record even after a failed restore, and a second window could end the first window's session. | **Fixed.** The record is kept when a restore fails; only the window that started a session ends it on close. |
| L6 | Low | The empty-folder delete did not check the folder's root against the rule's roots. | **Fixed.** |
| L7 | Low | The management revert check is weaker since protected features changed from "never changed" to "never disabled". | Known issue (needs a crafted snapshot in the administrator-only data folder); planned for phase 2. |
| L8 | Low | `risk.processor-idle-disable` contradicts the CLAUDE.md wording, and `risk.no-auto-reboot-logged-on` weakens update reboot enforcement. | Documented: both are Risk Zone (rejected, Lab) items behind the typed acknowledgement; processor idle stays blocked on Raptor Lake by the hardware overlay. Custom presets can no longer shadow built-in names (fixed with M2). |

The 3.0 review (phase 13) will audit the Group Policy write path, the lockout safeguards, network rollback, silent mode and edition/management gating.

## 3.4 Firewall Manager (3.4 phase 9, 24 October 2026)

An independent reviewer (a separate agent with read-only file access; it ran nothing and changed nothing) audited the classification, the knowledge base, the risk, precedence and audit engines, the change engine, the GUI actions (details pane, bulk actions, smart fix wizard, change queue, firewall scopes), the HTML report and the Sandbox step against the safety rules of SPEC-v3.4 section 6. It reported 2 High, 6 Medium and 6 Low findings. **Both High and all Medium findings are fixed**, each with a regression test (`tests\FirewallTools.Tests.ps1`, Describe "Firewall review fixes"); the Low findings are fixed except L5 and L6, recorded below.

Confirmed by the reviewer: Group Policy and MDM rules are locked with their source shown; every change writes a snapshot first and can be undone; read-only mode blocks every change path in the engine; the firewall is never turned off and inbound traffic is never allowed by default; every rule gets exactly one origin category with a reason and a confidence; recommendations never disable or block protected game, launcher or anti-cheat rules; firewall scopes run only from the Firewall Manager, never with a tweak apply; the HTML report encodes every value.

| # | Severity | Finding | Resolution |
|---|---|---|---|
| H1 | High | The change engine re-read the rules without the 3.4 classification, so the Core Services lock and "Delete only for app and custom rules" held only in the GUI; a direct `Invoke-IgwtFirewallChange -Operation Delete` on a Core Services Store-app rule, or a crafted import file, was not refused. | **Fixed.** `Invoke-IgwtFirewallChange` and `Get-IgwtFirewallImportPlan` classify the target rules themselves (`Invoke-IgwtFirewallEngineClassification`) before planning; the locks use the engine's own category. |
| H2 | High | Batches left in the GUI change queue (after a refused batch, a failed job or a remote-session revert) ran later, without confirmation, after the next unrelated change. | **Fixed.** The queue continues only straight after a completed batch; a change the user starts, a failed or reverted batch, an undo and read-only mode all drop it, and a queued batch with nothing left to change moves on. |
| M1 | Medium | "Move to category" could move a Core Services rule out of Core Services and so unlock it. | **Fixed.** Moves out of Core Services are ignored; the locks use `EngineOrigin`, which a move never changes. |
| M2 | Medium | Windows-category rules matched by rule ID or package publisher (Source Store app or third party) could be edited or switched to Block. | **Fixed.** Core Services and Windows Connections rules are enable/disable only, whatever their source. |
| M3 | Medium | The scope preview classified without the audit's signatures, so its plan could differ from the screen. | **Fixed.** The preview uses the audit's signatures. |
| M4 | Medium | Remote-session protection matched translated group names and three exact ports: port ranges, the Shadow and WebSocket rules on non-English Windows, enabling an inbound block rule and edits into a block rule were not caught. | **Fixed.** Remote Desktop and WinRM rules are recognised by group resource string, rule ID and parsed port ranges; enabling or editing into an inbound block on every port or a remote port is refused during a remote session. |
| M5 | Medium | Profile and network-category changes had no remote-session guard. | **Fixed.** Turning a profile on or off, default actions and the network category are refused during a remote session (local console only). |
| M6 | Medium | Programs on drives that are not connected (USB, network shares, unexpanded variables) counted as missing, so their rules were offered for deletion as orphaned. | **Fixed.** Such programs are "Unknown", never orphaned. |
| L1 | Low | New, edited or re-enabled block rules on protected game programs did not warn. | **Fixed.** The change plan warns "may break online play". |
| L2 | Low | Protected Steam games in secondary libraries (`D:\SteamLibrary\steamapps\common`) were not matched. | **Fixed.** The pattern is `*\steamapps\common\*`. |
| L3 | Low | The Sandbox firewall step overwrote the tweak results' variables and stopped on the Sandbox's own remote session. | **Fixed.** Own variables, `-AllowRemoteSession` inside the Sandbox, and only rules the engine actually changed are checked. |
| L4 | Low | Test gaps: a fixture typo made every rule "Any profile"; the "works on copies" check compared only the origin. | **Fixed** (typo); the new review tests cover H1, H2, M1, M2, M4, M6 and L1. |
| L5 | Low | The legacy firewall-profile tweak's restore writes back the previous profile values exactly, even "off" (`src\Actions\Custom.ps1`). | **Accepted.** A tweak revert restores the user's own previous state exactly (snapshot rule); the Firewall Manager's own profile restore keeps protection on. |
| L6 | Low (uncertain) | Filters are joined by InstanceID, assuming IDs are unique across policy stores. | **Recorded.** Not seen on this PC (692 rules, no duplicate IDs across stores); revisit if a GPO copy of a built-in ID appears. |
| - | Minor | CSV export did not neutralise spreadsheet formulas in rule names. | **Fixed.** Cells starting with `=`, `+`, `-` or `@` are prefixed with a quote. |

Open High findings: none.

## 3.3 read-only enforcement and UX rules (3.3 phase 8, 24 October 2026)

An independent reviewer (read-only file access; ran nothing, changed nothing) checked that every exported writer is guarded by `Assert-IgwtWritable`, that no GUI path changes the PC directly or in read-only mode, the new 3.3/3.4 features (dashboard Undo, preset Compare, firewall scope, focus mode, log viewer, compliance, network history), and every page against the UX checklist C1-C12 (`docs\UX_GUIDELINES.md`). The firewall change safety was reviewed separately (3.4 section above).

**Engine guard confirmed**: every exported writer checked (apply/revert, cleaner, ASR, power, managed changes, firewall, Defender, Group Policy and security/audit policy, toolkit, presets and session, persona, migration, restore point, startup items) calls `Assert-IgwtWritable` first; the GUI forces `IsAdmin` off in read-only mode and the workers inherit read-only mode. No GUI path changes the PC directly. There are no High findings.

| # | Severity | Finding | Resolution |
|---|---|---|---|
| M1 | Medium | Toolkit "Check installed" stayed enabled in read-only mode and runs `winget export` (writes a temporary file). | **Fixed.** Off in read-only mode, with the reason in the tooltip; the handler checks too. |
| M2 | Medium | "Clean selected" stayed enabled in read-only mode and showed the delete warning before the engine refused. | **Fixed.** Off in read-only mode with the reason; the handler returns early. |
| M3 | Medium | "Run fix" (fixes without admin rights) stayed enabled in read-only mode. | **Fixed.** Same as M2. |
| M4 | Medium | Defender > Group Policy "Set policy" could never be enabled: the button looked at a variable that was never assigned. | **Fixed.** It reads the selected policy row. |
| L1 | Low | Refusals in read-only mode said "Restart as administrator", which does not help (the restart keeps -ReadOnly). | **Fixed.** One reason helper (`Get-IgwtGuiChangeBlockReason`) says read-only mode first, administrator rights second. |
| L2 | Low | Changing the persona in read-only mode silently did not save. | **Fixed.** The status line says it applies to the window only. |
| L3 | Low | App-owned files written in read-only mode (network history, Authenticode cache, ADMX cache) were not listed in the decisions. | **Fixed.** DECISIONS U7b. |
| L4 | Low (uncertain) | An elevated run trusted the Authenticode cache in the per-user folder, which feeds the firewall origin and therefore the locks. | **Fixed.** Elevated runs keep the cache in the admin-only State folder. |
| U1 | UX | Navigation accessible names did not match the labels ("Asr", "NetTest", "Policy"); six combo and text boxes had no accessible name. | **Fixed.** |
| U2 | UX | Reduce motion did not stop the moving busy bar. | **Fixed.** A static bar when Reduce motion is on. |
| U3 | UX | Some titles were in title case ("Disk Analyzer", "Startup Apps", "Rejected Tweaks", "Expert Inspectors", "Network Test"). | **Fixed** (sentence case). The ALL-CAPS overlines stay as a deliberate section style. |
| U4 | UX | Backups & Logs and Rejected tweaks had no status line. | **Fixed.** |
| U5 | UX | Several pages still miss a one-line status and a single primary action at the top (Presets, Diagnostics, Inspect, Toolkit, Manage, Startup), and some pages use more than one accent button. Some results still use dialogs instead of a toast with Undo (startup toggle, Defender setting, toolkit feature). Tab and expander state is not remembered everywhere. Focus mode hides pages, dashboard details and advanced items but does not yet change list columns. | **Open (Low)**, recorded as known UX gaps in `docs\FINAL_REPORT_3.3.md`; none affects safety. |

Open High findings: none.

## 3.5 firewall logs and forensics (29 October 2026)

An independent reviewer (a separate agent with read-only access; it ran nothing that changes the PC) audited parser robustness, the handling of untrusted log and event values, the redaction of exports, and the revert path of forensic logging. It found the parser, the JSON escaping, the keyed pseudonyms and the no-clear/no-persistence rules sound, and reported the issues below. All High and Medium findings were fixed with regression tests (`tests\ForensicLogging.Tests.ps1`, `tests\ForensicEvidence.Tests.ps1`, `tests\FirewallLog.Tests.ps1`).

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | High | A failure in the second `auditpol /set` left the audit policy half-changed: the backup path was only recorded after Set-IgwtAuditPolicy returned. | **Fixed.** The session takes its own `auditpol /backup` before any change and records it in the snapshot first; test "restores the audit policy when the second auditpol /set fails". |
| 6 | High | DNS answer lists ("a;b") were not split, so internal addresses in them stayed visible in a pseudonymized export. | **Fixed.** Each address is redacted; IPv4-mapped IPv6 addresses are recognized. |
| 2 | Medium | A failed rollback after a failed start was reported as "restored". | **Fixed.** An incomplete rollback keeps the session record (rollback-incomplete) and says what was not restored. |
| 3 | Medium | The session record was written after the changes: a crash in between left changed settings without a record. | **Fixed.** The record is written first (status starting) and set active after the changes. |
| 4 | Medium | A damaged session record broke the state view and blocked Start and Stop. | **Fixed.** It is reported as damaged; Stop restores from the newest forensic snapshot (only the tool's own Backups\forensic-* folders are accepted). |
| 5 | Medium | Start used the plan from the preview: a policy that appeared later, or a crafted plan, could change a managed setting or shrink the Security log. | **Fixed.** Start makes the plan again from the current state and only raises sizes. |
| 7 | Medium | Rule names, notes and the brief's messages were not redacted; reverse-lookup names carried internal addresses. | **Fixed.** Free text goes through the same scrub (user folders and names, computer name, internal addresses); *.in-addr.arpa and *.ip6.arpa names are pseudonymized. Public addresses, including this PC's public IPv6 address, are kept by design (documented in ANALYSIS_BRIEF.md). |
| 8 | Medium | Turning Follow live off and on again added entries twice. | **Fixed.** The tail readers keep their position until the next full read; results of an older read are dropped (generation counter). |
| 9 | Medium | A line without a line break could grow in memory without limit; WFP events were all loaded before parsing. | **Fixed.** Lines over 64 KB are skipped and counted (TooLong); events are streamed. |
| 10 | Low | Two log files with the same name were copied only once; the event window moved by the time the copies took. | **Fixed.** Copies are numbered; the XPath is built right before each export (relative timediff is the documented form). |
| 11 | Low | The CSV export of the log analysis and copying grid rows to the clipboard had no formula protection. | **Fixed.** Both use the same protection as every export. |
| 12 | Low | `return $out.ToArray()` unrolls large results through the pipeline in the older reader functions. | **Not changed.** `return , ...` would hand callers that use `@()` one nested array; the GUI and exports use the engine lists directly. |
| 13 | Low | Network-share checks only looked for a `\\` prefix. | **Fixed.** `//server` paths and drive letters mapped to network drives are refused too. |

## 3.6 transactions (31 October to 1 November 2026)

An independent reviewer (a separate agent, read-only: file reads and git only, nothing run) audited the whole 3.6 change set (`main..feature/3.6-transactions` plus the working tree): the journal's permissions, hash chain and tamper handling, restores limited to owned targets, elevation, crash recovery, the lock, imported presets, the drift guardian, the 3.5 import, and UI-thread use and closures (U9). It found the engine well structured (write-ahead intent, read-back, group rollback, the lock released on every path, the drift guardian and home card read-only, the new GUI code within U9 and off the UI thread) but several stated guarantees not yet holding. Every High and Medium finding is fixed with a regression test (tests\Review36.Tests.ps1, tests\Journal.Tests.ps1, tests\EndToEnd.Tests.ps1).

| # | Severity | Finding | Resolution |
|---|---|---|---|
| R1 | High | The 3.x import read snapshot files without the trust check, including the legacy AegisTune folder a standard user can create: a planted snapshot could become a baseline that an elevated "Reset everything" restores. | **Fixed.** Only the tool's own Backups folder, and only files that pass `Test-IgwtTrustedFile` with a known tool and schema. |
| R2 | High | A real power-loss tear keeps the line's correct prefix, so it was reported as an invalid entry: the journal turned read-only and blocked the recovery it exists for. | **Fixed.** An unparseable line is torn whatever its prefix (compiled verifier); a test tears a real entry in the middle. |
| R3 | High | Undoing a journaled `Invoke-IgwtRevert` restored nothing (its own snapshot holds Reverted entries) but was recorded as reverted. | **Fixed.** One-way in the journal (never offered for revert); the targets it restores are journaled as `reverted`. |
| R4 | High | The journal folder and files were never checked for owner and ACL, and a planted checkpoint could hide the real segments. | **Fixed.** Every journal file and the folder must pass `Test-IgwtTrustedFile` (otherwise read-only); the folder is created with the protected ACL; journal writes and change sessions need administrator rights. Honest limit unchanged (T4): an administrator can rewrite everything consistently. |
| R5 | Medium | A step interrupted after its intent (Ctrl+C, an exception) in a session that still ended was invisible to recovery. | **Fixed.** Such sessions end as `interrupted` and their in-doubt steps are offered for recovery. |
| R6 | Medium | Journal readers and the writer used exclusive sharing, so a reader could make an append fail mid-step. | **Fixed.** Read, write and delete sharing on both sides, plus a short retry. |
| R7 | Medium | Undoing `Restore-IgwtFirewallProfileSnapshot` restored only the first setting. | **Fixed.** One-way in the journal. |
| R8 | Medium | Only snapshot-based writers recorded their undo reference before the commit; backup-based writers (Group Policy, audit, security policy, tattoo, policy presets) could not be recovered after a crash. | **Fixed.** `Set-IgwtModuleOperationRef` is called by every backup creator; the tattoo restore picks the right function from the backup on disk. |
| R9 | Medium | Turn-off and revert buttons used the 3.5 revert, which left iG's journal state stale (drift then offered to re-apply the user's own revert). | **Fixed (state).** The 3.5 revert journals every restored target as `reverted`, so drift, the journal tab and "Reset everything" stop tracking it. Turn-off still restores the snapshot value without a conflict question: it is an explicit, previewed choice (documented, not changed). |
| R10 | Medium | The 3.x import recorded every un-reverted apply as iG's current change, even when the value had changed since, so a revert overwrote it silently. | **Fixed.** Committed only when the item is still On; otherwise (and for resets to the default) the original is kept as the baseline only. |
| R11 | Medium | T6's "adopted, original unknown" pass was missing. | **Fixed.** Items on without a snapshot are journaled as `adopted` with the documented Windows default; they are never restored to an unknown value. |
| R12 | Medium | Recovery read its list outside the lock and restored without a conflict check. | **Fixed.** The list is read again under the lock; a value changed since iG set it is left as it is and reported. |
| R13 | Medium | Removing the newest entries or segment went unnoticed, and after a compaction new segments could be numbered into the folded range. | **Fixed.** `Journal\head.json` (sequence and hash) is written after every append and compared on read; numbering continues after the folded segments. Limit: deleting the whole Journal folder looks like a fresh journal (documented). |
| R14 | Low | `Test-IgwtPathUnder` was a string prefix test (`<root>\..\x` passed). | **Fixed.** Paths are resolved first. |
| R15 | Low | A forensic start refused by the engine left a session record behind. | **Fixed.** The record is removed when no change can start. |
| R16 | Low | The double-import check ran outside the lock. | **Fixed.** Checked again under the lock. |
| R17 | Low | "Reset everything" for module targets restores the last snapshot of each key, not the first. | **Documented** (T14 limit: module values live in the writers' own snapshots). |
| R18 | Low | "Reset everything" was disabled after a compaction. | **Fixed.** Enabled from the last-state index. |
| R19 | Low | Ignoring `missingDepth` hides key levels iG created but did not delete. | **Accepted.** The restore still uses it; comparing it breaks restores of 3.x data (the end-to-end test from a 3.5 install). |
| R20 | Low | A non-numeric `schemaVersion` gave a raw cast error. | **Fixed.** Readable message. |
| R21 | Low | Engine entry points had no administrator check. | **Fixed.** `Start-IgwtChangeSession` and journal writes require administrator rights. |
| R22 | Low | A revert plan was not re-checked when it ran. | **Fixed.** Each Ready row is read again under the lock; a value changed since the preview needs a decision. |
| Q1 | Question | Lock squatting and a raw access-denied error. | **Partly.** The access-denied case gives a readable message. A standard process holding the mutex first can delay elevated changes (no escalation); noted as a known limit. |
| Q2 | Question | `.Contains()` on journal dictionaries in Windows PowerShell 5.1. | **Confirmed bug, fixed.** `Test-IgwtMapKey`; a test formats values parsed back from the journal. |
| Q3 | Question | `data['applied']` on object snapshot data. | **Fixed.** Objects get a property instead. |

The end-to-end test (`tests\EndToEnd.Tests.ps1`: preset, drift, home card, preview, re-apply, revert, reset everything, chain checks; once fresh and once from a 3.5 install) also found a real bug before the review: imported 3.x data was reported as a failed restore because `missingDepth` differed. Fixed in `Remove-IgwtVolatileSnapshotKey`.
