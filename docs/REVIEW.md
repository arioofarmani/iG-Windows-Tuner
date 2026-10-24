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
