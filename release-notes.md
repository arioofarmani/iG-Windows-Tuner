# iG Windows Tuner 3.9.0

Released 2026-11-20. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

One undo system, and the last High findings of the 3.8.1 review.

### Changed

- **Every Revert and Undo now goes through the change journal.** Each value is checked before it is restored and read back afterwards. A value that something else changed since iG set it is no longer overwritten: the revert tells you, and Backups & Logs > Change journal lets you choose.

### Fixed

- ASR rules and Defender exclusions are read back after a change, so a change that Tamper Protection or a policy kept is not shown as done.
- The icon-cache fix never starts the desktop with administrator rights.
- Turning SMB1 off is no longer undone while Windows waits for the restart.
- More services are protected: the administrator prompt, Windows Hello, sign-in, Wi-Fi and gaming services.
- One clean never fills more than half of the Recycle Bin.
- Firewall: smarter duplicate detection, complete rule backups, and a working undo for "block outbound".
- Started with another administrator's account, iG refuses app, winget and per-user cleaning changes instead of touching the wrong profile.

### Good to know

- Tested with the full headless suite (1,554 tests), including a crash test of recovery at every journal step. Real apply-and-restore runs in Windows Sandbox are still to do.
- Full list: docs\CHANGELOG.md. Design notes: docs\DECISIONS.md (W1 to W12).
