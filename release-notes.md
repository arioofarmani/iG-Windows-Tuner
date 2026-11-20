# iG Windows Tuner 3.8.2

Released 2026-11-20. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

A security and undo release: fixes from an independent review of 3.8.1. No new features.

### Security

- **Planted backups are no longer restored.** A program without admin rights could plant a backup file that iG would then restore with administrator rights, for example turning UAC off. iG now restores only its own backups from its protected Backups folder, and "Revert from file" refuses files from anywhere else.
- **One guard for every policy change.** UEFI-lock values and values that lower a protection are refused everywhere, not only in Security settings.

### Fixed

- Undo now works for a policy change that failed half-way, and a revert no longer says "Reverted" when a network adapter, device or power plan was missing.
- Policy values "false" are written as false.
- The security score fails a protection that a policy turns off.
- Firewall: Recent changes shows its rows again; editing a rule keeps its protocol; the "Share files" template opens only port 445.
- The preview applies exactly what it showed; the Group Policy Undo asks first; forensic Stop keeps working after a busy moment.
- Catalog corrections for Recall, SMB signing on Home, Pro-only policies and laptops.
- Mouse and keyboard changes apply without signing out.

### Good to know

- Real apply-and-restore runs of these fixes in Windows Sandbox are still to do; everything was tested with the full headless suite (1,534 tests).
- Full list: docs\CHANGELOG.md. Design notes: docs\DECISIONS.md (V1 to V13).
