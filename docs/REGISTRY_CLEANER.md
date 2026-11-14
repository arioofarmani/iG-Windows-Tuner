# Registry cleaner

Clean > Registry cleaner finds registry entries left behind by programs that are no longer installed and removes the ones you select, with a preview, a backup and a one-click restore. It is not a "registry optimizer": removing leftovers does not make Windows faster, and iG does not say so. Design decisions are RG1 to RG34 in [DECISIONS.md](DECISIONS.md) (section "3.8 Registry Analyzer & Cleaner"); the command-line verbs are in [CLI.md](CLI.md).

## What it never does

- **Nothing is selected for you.** After a scan or a rescan no entry is ticked; *Select all Safe* ticks only the Safe entries, including entries hidden by a search or a chip, and the status line then says how many are selected.
- **It shows only what it can prove.** An entry is shown only when every check gave a clear answer. Access denied, an unreadable or skipped drive, a variable it cannot expand, another user's profile or a failed lookup means the entry is not shown at all, never "Safe because nothing was found".
- **Security software is never removed.** Leftovers of antivirus and endpoint products are shown as *Protected*, cannot be ticked, and point to the vendor's own removal tool.
- **Windows, drivers, runtimes, anti-cheat and game launchers are never offered** (see [Protected entries](#protected-entries)).
- **Services and scheduled tasks are only reported.** iG does not remove them; *Open in Manage* takes you to the existing, journaled way to disable them.
- **Every removal is backed up twice** (the change journal and a private backup folder) and can be restored from the page, from Backups & Logs > Change journal, or with `-RegRestore`.
- **A restore never deletes or overwrites anything.** It only puts back what is missing (see [Restore](#restore)).
- In **read-only mode** (`-ReadOnly`) every change path is off in the engine itself; the scan and the previews still work. Removing needs administrator rights; scanning does not.

## What is scanned

| Category | Where | Removed as | Best confidence |
|---|---|---|---|
| Uninstall entry (`uninstall`) | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` in HKLM (64-bit and 32-bit view) and HKCU | key tree | Safe |
| App Paths (`appPath`) | `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths` in HKLM and HKCU | key tree | Safe |
| ProgID (`progId`) | `SOFTWARE\Classes\<ProgID>` in HKLM and HKCU | key tree | Review |
| Applications verbs (`application`) | `SOFTWARE\Classes\Applications\<exe>` in HKLM and HKCU | key tree | Review |
| Open with (`openWith`) | `OpenWithProgids` values of file extensions in HKLM and HKCU Classes | value | Review |
| Run and RunOnce (`run`) | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` in HKLM (both views) and HKCU | value | Safe |
| Software key (`softwareKey`) | `SOFTWARE\<Vendor>\<Product>` in HKLM (both views) and HKCU | key tree | Review |
| Firewall rule (`firewallRule`) | Allow and Block rules of the persistent firewall store whose program is missing | firewall rule | Safe (Allow), Review (Block) |
| Service (`service`) | `SYSTEM\CurrentControlSet\Services\<name>` of a removed program | report only | Review |
| Scheduled task (`task`) | tasks outside `\Microsoft\` whose programs are all missing | report only | Review |

HKCU means one user: the signed-in (interactive) user, or the user running iG when it is not elevated. When iG runs elevated without a signed-in user (for example over SSH), the per-user categories are skipped with the note "Per-user entries were not checked". Other users' hives are never loaded.

**Not scanned in 3.8** (shown in the page help): COM classes, type libraries and interfaces, SharedDLLs, MUICache, ShellBags, Explorer FileExts and OpenWithList, StartupApproved, Active Setup, shell extensions, Startup folder shortcuts, everything under `Classes\Installer`, drivers, and other users' hives. These either have no documented meaning or removing them can break software that is still installed.

## How an entry is judged

Every entry carries its evidence (each check with its result and detail, for example "C:\Program Files\X\x.exe missing on C:, D:"). The detail pane shows the full list.

- **Safe**: every rule of the category's Safe column holds. Safe is reserved for entries whose only job is to point to a file that is gone, proven by more than one pointer where the category has more than one.
- **Review**: the entry looks like a leftover, but it may also carry settings or shared meaning. You decide.
- **Protected**: shown only for security-product leftovers; never selectable.

What every entry needs, whatever its category:

1. **Not protected** (the protected groups, the live checks and your exclusions).
2. **Not owned by an installed program.** Ownership is decided by identifiers and folders, never by display names: an Uninstall key name, an MSI product code (its state read from Windows Installer; only "unknown product" counts as not installed), a service name, a Store package name or family name, or a path under a folder that an installed program, service, package, game or launcher uses. A folder with the product's name under the vendor folder, Program Files, Program Files (x86), ProgramData or the user's AppData also counts as installed. Display names, publishers and value names never make anything removable, but they can always add protection.
3. **Every path it holds is missing.** Paths are parsed by the documented command-line rules (quotes, the CreateProcess try-in-order rule for unquoted paths, `%1`-style placeholders, `@` resource strings and `,index` suffixes). For a host program (rundll32, msiexec, script hosts) the evidence is the payload, not the host. Variables are expanded for the owner of the entry (the machine for HKLM, the scanned user for HKCU), never for the elevated administrator. A 32-bit entry is looked up in both Program Files folders and in System32 and SysWOW64. A path is missing only when it is missing on every online fixed drive and the nearest existing parent folder could be listed.
4. **No unclear step.** Bare names, relative paths, network paths, URLs, `shell:` targets, 8.3 short names, unexpanded variables, reparse points on the path and drives on USB, SD, virtual disks, Storage Spaces or unknown buses are not reported.

The category rules:

| Category | Safe when | Review when |
|---|---|---|
| Uninstall entry | the key is not GUID-shaped, is not a Windows Installer, system-component, child or bundle entry, the uninstaller is missing **and** a second pointer (InstallLocation, or a DisplayIcon outside the uninstaller's folder) is missing, and no App Paths, Run or service entry points to an existing file in the program's folders | only the uninstaller pointer is missing (installers often cache it in ProgramData or Package Cache), the uninstall command uses a host program, or it is an MSI entry that Windows Installer does not know and that has no Installer\Products entry. An entry with a vendor-folder hit, an existing quiet uninstaller or a known MSI product is not shown. |
| App Paths | the program path is absolute and missing, and every folder of its `Path` value is missing | - |
| ProgID | - | every verb command and the DefaultIcon are missing, and no file extension names it together with another registered ProgID |
| Applications verbs | - | every verb command is missing |
| Open with | - | the value names a ProgID that exists in neither Classes root |
| Run and RunOnce | a plain program path is missing | the evidence is the payload of a host program |
| Software key | - | the key holds at least one absolute path value, every such path is missing and no product folder exists. A key without any path value is not shown. A vendor key is offered only when every product key below it is a finding and the vendor name is not on the deny list. |
| Firewall rule | an Allow rule from a user or app source (not Windows, Group Policy, MDM or Store) whose program is missing, that the Firewall Manager would allow to delete, and whose program is not a protected game, launcher or anti-cheat program | a Block rule: "removing it lets this path use the network if the program comes back" |
| Service (report only) | - | an own-process or shared-process service, start type automatic, manual or disabled, stopped, not Microsoft-signed, image path missing |
| Scheduled task (report only) | - | not under `\Microsoft\`, every program action missing, no COM handler action |

A key tree is offered only when it can be backed up and restored exactly: no value of a kind .NET cannot write back, at most 2,000 keys, 2,000 values and 512 KB of data, every subkey readable, no subkey on the deny list (shared or linked keys such as `Wow6432Node`, `Classes`, `Policies`, `Microsoft`, `CLSID`, `TypeLib`, `Interface`), and only inherited permissions with an owner of SYSTEM, Administrators or the scanned user. Otherwise the row says why it cannot be ticked.

## Protected entries

The protected set is data, not code: `data\registry\protected.json`, validated by `Test-IgwtRegCleanProtectedCatalog` (part of `tools\Test-Catalog.ps1`). Its groups:

| Group | What it protects |
|---|---|
| `microsoft` | Windows, Microsoft components and Windows Installer data: `SOFTWARE\Microsoft\*` (except the scanned category roots, whose entries are checked one by one), `Classes\Installer`, the Installer keys, every `Policies` key, `SYSTEM\*`, COM class, interface, type library and AppID keys, entries with Publisher Microsoft Corporation, paths under the Windows folder, Microsoft Store publisher IDs and Microsoft-signed files. |
| `securityVendors` | Antivirus and endpoint products (one entry per vendor, with the removal tool or the text to show). Shown as *Protected*, never removable. |
| `hardware` | Driver and device software (chipset, graphics, audio, network, input and OEM utilities). |
| `antiCheat` | Anti-cheat services, drivers, folders and keys. |
| `runtimes` | Shared runtimes (Visual C++, .NET, DirectX, Java and similar) that other programs still use. |
| `launchers` | Game launchers and their games (see also `data\firewall\apps.json`). |

The existing lists of other features are read too: protected services (`data\manage\services.json`), protected tasks and the anti-cheat task pattern, protected Store apps, and the protected programs of the Firewall Manager (`data\firewall\apps.json`), which are a hard block for the cleaner.

Live checks add protection for products the lists do not know: a key owned by TrustedInstaller or writable only by SYSTEM and TrustedInstaller; a referenced file that still exists and is Microsoft-signed (catalog signatures included); a service that is launch-protected, early-launch, a driver or file system, boot or system start, or a Windows service; a product registered with Windows Security Center; the INF provider of a present device. When a live check cannot run (not elevated, a WMI error, a signature error), the affected entries are treated as protected.

The same protection function runs three times: in the scan, in the preview (after a fresh re-read) and in the engine immediately before each delete.

### Security software

A leftover of a security product (matched by key, path, signer, publisher or display name, a Windows Security Center product, or a launch-protected or early-launch service) is shown under the *Security software* chip as *Protected* with the reason "Use <vendor>'s removal tool". *Open removal tool* opens the vendor's page (https only). Where iG could not confirm a tool page, the row says "<vendor> publishes no removal tool that iG could confirm; contact <vendor> support"; enterprise endpoint products say "Ask your administrator". iG never links a vendor home page as if it were a removal tool.

## Your exclusions

*Never show this again* (right-click a row) and *Exclusions...* keep entries out of every scan. The list is machine-wide, because the cleaner runs elevated and another administrator account must see the same list:

`%ProgramData%\iGWindowsTuner\State\regclean-exclusions.json`

```json
{
  "schemaVersion": 1,
  "entries": [
    { "pattern": "HKCU\\Software\\Contoso\\Old App", "scope": "key", "reason": "kept on purpose", "addedUtc": "2026-11-10T09:00:00Z" }
  ]
}
```

- `scope` is `key` (the key and every key below it), `value` (`HIVE\path\name`) or `path` (a folder or program path; variables are expanded for the scanned user).
- Patterns are PowerShell `-like` wildcards (`*`, `?`, `[ ]`), case-insensitive; *Never show this again* writes an exact pattern with wildcard characters escaped. A key's default value, a scheduled task and a firewall rule without a program path cannot be excluded on their own, and the action says why.
- At most 1,000 entries; every entry needs a reason. An unreadable or invalid file stops the scan with a message instead of silently showing everything.
- An exclusion changes only what iG shows and removes, never the PC, so it is not journaled. It never blocks a restore.
- On the command line: `-RegExclusions`, `-RegExclude <pattern> -Reason <text>`, `-RegUnexclude <pattern>`.

## Removing entries

*Remove selected...* (or `-RegClean`):

1. **Preview.** A fresh plan re-reads every selected entry and runs the protection and evidence checks again. It lists each entry with its key, program and evidence, entries included in a selected parent key ("included in ..."), the backup folder, refused entries with the reason, and the note that firewall rules are saved as rule definitions, not in the .reg file. Nothing changes until you confirm.
2. **Restore point.** iG offers a System Restore point (or to turn System Protection on); *No* keeps the journal and the backup folder only. On the command line, `-SkipRestorePoint` and `-EnableSystemProtection` work as for tweaks.
3. **Backup folder.** A private folder is created before the first change (see below). If it cannot be created or its permissions cannot be set, nothing changes.
4. **One change session.** Each entry is one journaled step: the engine checks again that the cleanup belongs to this session, runs the protection check, re-reads the entry and refuses when it changed since the preview, refuses explicit permissions or a foreign owner, and only then deletes it, values first and keys leaf-first (never a whole-tree delete, so nothing that was not backed up is deleted). It then reads back that the entry is gone.
5. **Result.** Each entry ends *Removed*, *Refused* (nothing was deleted; the session continues), *Failed* (the entry was rolled back and the session stops) or *Not started*. The toast offers *Undo*.

A selected key that lies inside another selected key is absorbed by it; restoring that entry restores the parent with its children.

## Backup folder

`%ProgramData%\iGWindowsTuner\Backups\regclean-<yyyyMMdd-HHmmss>-<6 hex>`

The folder is private from the moment it is created: SYSTEM and Administrators have full control; when the cleanup includes per-user entries, that user can read the folder but not change it (an administrator may later import the .reg file).

| File | Contents |
|---|---|
| `selected.reg` | Every selected key and value in regedit's import format (UTF-16LE with BOM, "Windows Registry Editor Version 5.00"), written by iG's own writer: strings, `dword:`, `hex:`, `hex(2):` (expandable strings), `hex(7):` (multi-strings), `hex(b):` (QWORD), `hex(0):` (REG_NONE). 32-bit entries use their physical `WOW6432Node` path. Per-user keys are written as `[HKEY_USERS\<SID>\...]`, so a double-click import cannot land in another user's hive. |
| `firewall-rules.json` | The full definition of every selected firewall rule (always written; the list is empty when no rule was selected). Firewall rules live under `SYSTEM`, which the cleaner never exports, so they are not in `selected.reg`. |
| `manifest.json` | Scan id, every target (finding id, category, hive, SID, view, path, value or rule name, included entries), the SHA256 of each file, the firewall snapshot path per rule, and the owner and SDDL of every key (for information). |

The change journal (Backups & Logs > Change journal) holds the authoritative snapshot of every removed entry; the backup folder is the second, human-readable copy.

## Restore

- **Restore last cleanup...**, the *Removed* view (right-click > Restore) and the toast's *Undo* show the restore plan first (the value before, the value iG set and the value now), then restore through the change engine. The Change journal tab works as for every other change.
- **Command line:** `-RegRestore <session id | entry id | Last>`; `-DryRun` prints the plan only; `-RegConflict Keep|Skip` (default Skip) decides entries that changed since the cleanup.

**The additive rule:** a restore only creates keys and values that are missing. If anything present differs from the backup, or a key or value is present that the backup does not hold (typically because the program was installed again and wrote its own entries), the restore stops for that entry with "Refused: the key exists again with other data; nothing changed". A restore of an entry that is already back is a no-op. So "Restore anyway" for a conflict ends with nothing changed; Keep and Skip work as usual. A firewall rule is restored from its saved definition and is refused when a rule with the same name exists again with other settings.

## Honest limits

- Only the scanned user's per-user entries are read; other users' leftovers are not found. HKLM entries of another user's per-user install are protected only when a folder or identifier is visible (paths under another user's profile cannot be checked, so they are not shown).
- Key class names, last-write times and the volatile flag cannot be read or restored with .NET, so they are not captured.
- After a restore, a key's owner and inherited permissions can differ from the original (the restoring administrator becomes the owner); the data and the inheritance are exact.
- The change journal's snapshots under the data root stay readable as for every other feature; only the backup folder is private.
- Services and scheduled tasks are reported, not removed.
- Firewall rules are backed up as rule definitions, not in the .reg file.
- Drives on USB, SD, virtual disks, Storage Spaces or unknown buses are skipped, and leftovers on removable or offline drives are never reported.
- The cleaner cannot prove that no program reads a key. That is what Review is for; Safe is limited to entries that only point to missing files.
- A program installed again blocks the restore of its old entry (the additive rule).
- Removing leftovers does not make Windows faster.
- A scan reads every Uninstall, App Paths, Run, Classes and Software key and checks each candidate; on a PC with thousands of entries it can take several minutes. It runs in the background with progress and *Cancel* (a cancelled scan shows a partial result).

## Not verified on Microsoft Learn

These behaviours are not documented on Microsoft Learn. Each is used only in the safe direction: it protects, lowers an entry to Review, or makes it not shown.

1. The rundll32 `DLL,entry` syntax (only an archived KB): rundll32 entries are Review, never Safe.
2. User variables in `HKEY_USERS\<SID>\Environment`, and the User Shell Folders value names `AppData` and `Local AppData`: a variable that is not found leaves the path unchecked, so the entry is not shown.
3. The Uninstall values QuietUninstallString, DisplayIcon, WindowsInstaller, ParentKeyName and BundleProviderKey: they only lower confidence or protect; DisplayIcon counts as a second pointer only together with a missing uninstaller and the folder tests.
4. `root\SecurityCenter2`: used only to add protection; a failed read protects every entry.
5. The .reg file format (only support KB 310516) and the hex line wrapping: the .reg file is the secondary backup; restore uses the journal snapshot.
6. The certificate names "Microsoft Windows Hardware Compatibility Publisher" and "Microsoft Windows Early Launch Anti-malware Publisher" (observed only): used only to protect.
7. Security, anti-cheat and hardware vendor names, signers, publishers and service names: used only to protect.
8. LaunchProtected values 1 and 2 (only 3 is documented): any value of 1 or more protects.
9. No page forbids editing `Classes\Installer` or `Installer\UserData`: they are protected anyway. The packed product code form and the per-user `Software\Microsoft\Installer\Products` location only hide entries.
10. The System Protection check through `SPP\Clients` (existing code): if it is wrong, you are asked and the journal and backup folder still exist.
11. Removal tool pages found only through search results (McAfee, Avast, Sophos Home, Malwarebytes, WithSecure, G DATA, Panda, WatchGuard): re-checked before a release; an unconfirmed tool shows the "no removal tool iG could confirm" text.
12. Whether opening or deleting a registry key follows a registry symbolic link: the deny list keeps every documented link name out of every offered tree.
13. Key class names and the volatile flag cannot be read with .NET: such keys are almost always under SYSTEM, SAM or SECURITY, which are protected or never scanned.
14. The numeric MSFT_Disk bus type values: an allowlist, so an unknown number skips the drive; the system drive does not depend on it.
15. TrustedInstaller identified by translating `NT SERVICE\TrustedInstaller`: a translation failure protects.
16. Windows Sandbox detected by the WDAGUtilityAccount user (Sandbox test script only): the script refuses when unsure.
17. Windows Sandbox has no System Restore (observed): the Sandbox script always skips the restore point.
18. `Get-AppxPackage` without `-PackageTypeFilter` returning main and framework packages.

## Command line

| Verb | What it does |
|---|---|
| `-RegScan [-Category <list>] [-Json] [-ReportPath <file.json>]` | Scan (read-only). |
| `-RegClean <ids or Safe> [-DryRun]` | Prints the preview; without `-DryRun` removes after a confirmation (administrator). `Safe` selects exactly the Safe entries of a fresh scan. |
| `-RegRestore <session id, entry id or Last> [-DryRun] [-RegConflict Keep\|Skip]` | Prints the restore plan; without `-DryRun` restores. |
| `-RegExclusions` | Lists the exclusions (read-only). |
| `-RegExclude <pattern> -Reason <text> [-DryRun]`, `-RegUnexclude <pattern> [-DryRun]` | Adds or removes an exclusion. |

Exit codes: 0 success (also a cancelled confirmation), 1 an entry failed and was rolled back or another error, 2 invalid arguments, 7 read-only mode. Scripts that remove without a prompt call the script from PowerShell with `-Confirm:$false` (Windows PowerShell 5.1 cannot pass `-Confirm:$false` through `powershell.exe -File`). Details: [CLI.md](CLI.md#registry-cleaner).

## Adding a protected vendor

1. Add the vendor to the `vendors` list of the `securityVendors` group in `data\registry\protected.json` (ASCII, 2-space indent): `id`, `name`, `type` (`consumer`, `edr` or `windows`), `publisherPatterns` and/or `displayNamePatterns` (at least one; never starting with a wildcard), `pathPatterns` (a drive, `%Variable%\` or `*\` followed by a folder of at least 4 characters), `keyPatterns` (starting with `HKLM\`, `HKCU\` or `HK*\`; a pattern must not cover a scanned category root), optional `signerPatterns` (`CN=` or `O=`) and `servicePatterns`.
2. `removalTool {name, url, text}`: a consumer vendor needs the https URL of the vendor's removal tool page (fetched and confirmed; never the home page) with a name and a text, or no URL and the text "<vendor> publishes no removal tool that iG could confirm; contact <vendor> support." An EDR vendor's text starts with "Ask your administrator". Record the source in the group's https `sources` and, when it could not be confirmed on the page itself, mark it UNVERIFIED in DECISIONS RG11.
3. Vendor names live only in this file, never in `.ps1` files (`tests\Safety.Tests.ps1` checks the provider and plan files).
4. Run `tools\Test-Catalog.ps1`, then `tests\RegistryCleanerScan.Tests.ps1` and `tests\Safety.Tests.ps1`.

## Testing

Everything is tested headless and non-elevated with Pester's `TestRegistry:` and mocks (`tests\RegistryCleaner*.Tests.ps1`, fixtures in `tests\fixtures\registry` with invented vendors only). Real removal and restore round trips, real WOW64 redirection, a manual import of `selected.reg` and the firewall delete and recreate run only in Windows Sandbox with `tools\RegistryCleaner.Sandbox.ps1` (it refuses to run anywhere else and writes its results to `C:\SandboxResults\registry-cleaner-sandbox.json`).
