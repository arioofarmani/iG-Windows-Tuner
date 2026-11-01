# AegisTune (iG Windows Tuner) 3.6.0

Released 2026-11-01. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

Every change is now a recorded, checked and reversible transaction. Design and verification: DECISIONS T1 to T18; independent review: docs\REVIEW.md.

### What's new

- **A change journal for everything iG changes.** Before a setting is changed, iG writes down what it was; after the change, it reads the setting back and records whether it took. If one part of a change fails, the parts already done are put back automatically. The journal is protected against editing: if an entry is changed, removed or reordered, iG notices, says which line, and makes no further changes until it is resolved. It also survives a crash or power loss mid-write.
- **One change at a time.** If a second change is started (in another window, for example), it waits for you with a clear message instead of interfering: "Another change is running since 14:02 (Preset Competitive)".
- **Unfinished changes are found.** If the app or the PC stopped in the middle of a change, iG shows it the next time it starts and offers to roll it back, step by step, after showing you what it will do.
- **Undo anything, precisely.** Backups & Logs > Change journal lists every change by session. Revert one change, one session, or everything iG ever changed back to how it was before iG. Each revert shows the value before, the value iG set and the value now. If something else changed a value since (you, an app, a policy or Windows), you decide: restore anyway, keep the current value, or skip.
- **Confidence badges.** Every tweak shows Verified (documented by Microsoft or the hardware vendor, and confirmed to apply and read back correctly on your Windows build), Best effort (documented, not yet confirmed on your build) or Unverified (no Microsoft or vendor documentation). Verified means "applies correctly", not "makes your PC faster". The tweak lists have a Confidence column and filter.
- **Clearer presets.** Before a preset's changes are staged, a preview shows what will change, what is already set, what does not apply to this PC, any conflicts and anything a policy manages, with a one-line summary. Presets now only name settings and what to do with them (turn on, Windows default, or leave unchanged), never paths or commands, and presets you import are checked strictly with readable messages. The built-in presets do exactly what they did in 3.5.
- **Update drift guardian.** At start, iG checks (read-only) whether every setting it changed is still in place, has been changed back, is missing, or cannot be read. It lists the Windows updates installed in between, without claiming they caused it. Re-apply (with the usual preview) or accept the current value, one setting at a time or all together.
- **Home card.** The Dashboard is now the start page and shows the one thing that most needs your attention: an unfinished change, settings that changed since iG set them, an ended forensic logging session, Unverified items in your preset, or a suggestion; otherwise "All clear". Do it always shows a preview first, Not now hides the card for a day or a week, and Why? explains it.
- Every part of iG that changes Windows (tweaks, presets, firewall, ASR, Defender, Group Policy, audit and security policy, power, startup, services and tasks, toolkit, cleaner, forensic logging) now goes through the same journaled engine. Changes that cannot be undone (removed apps, cleaned files, restore points) are recorded too and marked "cannot be undone".

### Upgrading from 3.5

- Nothing to do. The first time 3.6 changes something, it imports your 3.5 backups once: the original values of the changes you made with 3.5 are kept, so they can still be undone from the change journal, including "reset everything".
- Your 3.5 backups stay where they are (%ProgramData%\iGWindowsTuner\Backups) and Backups & Logs > Snapshots still lists them.
- Custom presets keep working. Presets exported from 3.5 can still be imported.

### How to undo changes

- **One change or one session:** Backups & Logs > Change journal, select it, then "Revert selected change..." or "Revert its session...".
- **Everything iG changed:** Backups & Logs > Change journal > "Reset everything iG changed...": every setting goes back to its value before iG, newest first.
- **A setting Windows changed back:** the home card shows it; choose to re-apply or keep Windows' value.
- Every revert shows a preview first and is recorded in the journal, so a revert can itself be undone.

### Good to know

- The journal is in %ProgramData%\iGWindowsTuner\Journal. It detects edits, but an administrator who rewrites the whole journal consistently cannot be detected (no secret can be hidden from an administrator on the same PC).
- No scheduled task, service or network connection was added. The drift check runs when the app starts and when you refresh.
- Not yet tested end to end on real hardware in Windows Sandbox (see the checklist in the 3.6 final report).

### Install

Download iGWindowsTuner-3.6.0.zip, check it against SHA256SUMS, extract it, and run Start-iGWindowsTuner.cmd. Files from a downloaded zip carry Mark-of-the-Web: review them, then Unblock-File if you trust them.
