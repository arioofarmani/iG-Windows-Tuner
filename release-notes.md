# iG Windows Tuner 3.8.1

Released 2026-11-13. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

Three new tools, all built on the change journal: every change is previewed, backed up, read back and can be undone with one click.

### Added

- **Registry cleaner** (Clean > Registry cleaner): finds entries left behind by programs that are no longer installed (uninstall entries, App Paths, file associations, Open with, startup entries, Software keys, firewall rules) and shows the evidence for each one. Safe entries are proven leftovers; Review entries are for you to decide. Nothing is selected until you choose it. Windows, security products, drivers, anti-cheats and runtimes are never offered; leftovers of security products point to the vendor's removal tool. Every removal is backed up (a .reg file and the journal) and can be restored per entry or per cleanup. It makes no speed claims.
- **Startup apps: full control**: delete one or several entries with a backup and Undo, turn several on or off at once, open the file location, copy the command, and see the company and the file each entry starts. Windows components and security products can be turned off but not deleted; anti-cheat entries get a warning.
- **Security settings** (Security > Security settings): every security Group Policy from Windows' own definitions, every Defender preference, the ASR rules, the exclusion lists, security options, audit policy and Device Guard state in one list, with the current value and where it comes from. Each setting gets the editor its definition needs. Changes are written like the Group Policy editor, roll back on failure and can be undone. Values set by a domain, MDM or Tamper Protection are read-only; values that would turn a protection off, UEFI locks and lockout-risk settings are refused; VBS, memory integrity, Credential Guard, LSA protection and BitLocker policies need prerequisite checks and a typed confirmation.
- Command line: -RegScan, -RegClean, -RegRestore, -Startup, -StartupRemove, -SecSettings, -SecSetting, -SecSettingSet, -SecSettingRemoveExclusion (every changing verb has -DryRun).

### Fixed

- Defender settings are written through the current Defender module, so newer settings such as AiAgentProtection save; a write that changed nothing no longer offers Undo, and a write that could not be read back keeps it.

### Good to know

- Real apply-and-restore runs of these tools in Windows Sandbox are still to do; everything was tested with the full headless suite (1,460 tests).
- Microsoft security baseline values are not bundled yet.
- Guides: docs\REGISTRY_CLEANER.md, docs\SECURITY_SETTINGS.md. Full list: docs\CHANGELOG.md.
