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
