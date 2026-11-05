# AegisTune (iG Windows Tuner) 3.6.5

Released 2026-11-05. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

A bug-fix release for 3.6.0. If 3.6.0 refused your changes with "The change journal is read-only ... 'Journal' is not protected", this fixes it. Your journal and backups stay as they are: nothing needs to be repaired.

### Fixed

- **Every change was refused** with "'Journal' is not protected", although the folder was protected correctly. The check took read access for standard users as write access. It now checks only the rights that can really change a file. Reverting from a snapshot used the same check and benefits too.
- **"Cannot index into a null array"** repeated in the log while the journal was refused. The journal tab, the drift check and the home card now keep working and say what is wrong.
- The journal tab could fail on a change without a backup, such as a restore point.

### New

- **Set this journal aside** (Backups & Logs > Change journal): only if a journal really fails its check, for example after someone edited it. It used to block every change with no way out. Now, after you confirm, it is moved aside (nothing is deleted) and the next change starts a new protected journal.

### What 3.6 brought

A change journal with exact undo per change, per session or for everything; confidence badges; presets with a preview; the update drift guardian; and the home card. See docs\CHANGELOG.md.

### Good to know

- Not yet tested end to end in Windows Sandbox: the changes were tested with mocks and against a real journal read-only. Please try one small change first.

### Install

Download iGWindowsTuner-3.6.5.zip, check it against SHA256SUMS, extract it, and run Start-iGWindowsTuner.cmd. Files from a downloaded zip carry Mark-of-the-Web: review them, then Unblock-File if you trust them.