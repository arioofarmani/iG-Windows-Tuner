# Group Policy engine (3.0)

iG Windows Tuner reads the Administrative Templates (ADMX/ADML) installed on the PC and writes the
**Local Group Policy Object** the same way the Group Policy editor (gpedit.msc) does: the policy
lands in `Registry.pol`, `gpt.ini` is updated, policy is refreshed, and the result is checked.
Microsoft's definition files are read at run time and never copied into the project.

## Where things live

| What | Location |
|---|---|
| Definitions | `%SystemRoot%\PolicyDefinitions` (plus the domain Central Store on domain-joined PCs, plus folders from `-AdmxFolder`) |
| Parsed catalog cache | `%LOCALAPPDATA%\iGWindowsTuner\Cache\admx-<hash>.xml`, keyed by a hash of every definition file's name, size and write time |
| Local GPO | `%SystemRoot%\System32\GroupPolicy` (`Machine\Registry.pol`, `User\Registry.pol`, `gpt.ini`) and `GroupPolicyUsers` |
| Backups | `%ProgramData%\iGWindowsTuner\Backups\gpo-<timestamp>` with a `manifest.json` of SHA256 hashes |
| Never-write list | `data\policy\denylist.json` |

## Commands

```powershell
.\iGWindowsTuner.ps1 -PolicySearch "defer feature"            # search names, explain text, registry paths
.\iGWindowsTuner.ps1 -PolicyShow WindowsUpdate:DeferFeatureUpdates   # details plus effective state and source
.\iGWindowsTuner.ps1 -PolicySet WindowsUpdate:DeferFeatureUpdates -PolicyState Enabled -PolicyValue "DeferFeatureUpdatesPeriodId=90" -DryRun
.\iGWindowsTuner.ps1 -PolicyBackup | -PolicyRestore <folder> | -PolicyReset -DryRun
.\iGWindowsTuner.ps1 -PolicyTattoo                            # values under Policies keys that no GPO sets
```

Policy ids are `<admx file name>:<policy name>`. `-PolicyValue` takes `elementId=value` pairs separated
by `;`; list values are separated by `|`.

## How a change is written

1. **Plan** (`Get-IgwtPolicyChangePlan`): the policy state becomes Registry.pol operations exactly as
   the ADMX describes them: `enabledValue`/`disabledValue` (or 1/0), `enabledList`/`disabledList`,
   and per element type: `decimal`/`longDecimal` (range-checked, `storeAsText`), `text` (length-checked,
   `expandable`), `multiText`, `boolean` (`trueValue`/`falseValue` and lists), `enum` (by name or
   index, with `valueList`), and `list` (`valuePrefix`, `explicitValue`, `additive`; a non-additive
   list gets a `**delvals.` marker). *Disabled* writes `**del.` markers for element values;
   *Not configured* removes the policy's entries.
2. **Refusals**: any operation on the denylist (Defender, firewall, SmartScreen, Windows Update,
   VBS/HVCI/Credential Guard, UAC, DEP, ASR rules or network protection turned off, antivirus
   exclusions, Tamper Protection) stops the change. Windows Home has no Local Group Policy, so policy
   writes are refused there. On a managed PC (domain or MDM) a local change needs `-AcknowledgeManaged`.
3. **Backup** of both Local GPO folders.
4. **Registry.pol**: read, update only the policy's entries (every other entry keeps its exact bytes),
   write atomically.
5. **gpt.ini**: increment the machine (low 16 bits) or user (high 16 bits) version and register the
   registry client-side extension in `gPCMachineExtensionNames`/`gPCUserExtensionNames`.
6. **Refresh**: `gpupdate /target:computer|user /force`.
7. **Verify**: the resulting registry values are compared with the plan. A mismatch is reported (exit
   code 5); undo with `-PolicyRestore <backup>`.

## Effective state and source

`-PolicyShow` reports, per class, the Local GPO state (Enabled, Disabled, Configured, Not configured),
the actual registry values, domain GPO values (from `gpresult /x`, domain-joined PCs only), the MDM
value (PolicyManager), which one wins, and conflicts.

A **tattooed** value is in the registry under a Policies key but in no Registry.pol or domain GPO.
It was left behind by an earlier policy or tool, or written directly by an iG Windows Tuner 2.x item;
`-PolicyTattoo` lists them and marks the ones that belong to catalog items. Phase 5 moves those items
to the Group Policy engine.

## Reset

`-PolicyReset` backs up and then empties both Local GPO folders and refreshes policy. Domain and MDM
policies are not affected, and tattooed values stay. No Microsoft article documents this reset (see
DECISIONS G4); it is reversible with `-PolicyRestore`.

## Formats

- **Registry.pol** ([MS-GPREG] 2.1): header `PReg` + version 1, then `[key;valuename;type;size;data]`
  entries in UTF-16LE. Special value names `**del.`, `**delvals.`, `**DeleteValues`, `**DeleteKeys`,
  `**SecureKey`, `**soft.` are understood and preserved. Corrupted files are refused with the offset.
- **gpt.ini**: `Version=(user << 16) | machine`; extension lists are `[{CSE}{tool}...]` sorted by CSE.

Sources: [MS-GPREG] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/ ,
ADMX schema https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/admx-schema .

# Security policy and auditing (3.0 phase 4)

## Security templates (secedit)

`-SecPolicy` shows account policies, user rights assignment and security options from
`secedit /export /areas SECURITYPOLICY USER_RIGHTS` (to a temporary file). `-SecPolicySet` changes them:

```powershell
.\iGWindowsTuner.ps1 -SecPolicySet "SystemAccess\MinimumPasswordLength=14;SystemAccess\LockoutBadCount=10" -DryRun
.\iGWindowsTuner.ps1 -SecPolicySet "PrivilegeRights\SeShutdownPrivilege=Administrators" -DryRun
```

Write path: export snapshot (`Backups\secpol-<timestamp>\before.inf` with a SHA256 manifest), a
template with only the changed settings, `secedit /configure /areas SECURITYPOLICY USER_RIGHTS`,
then a fresh export to verify. `-SecPolicyRestore <folder>` puts the changed settings back. secedit
cannot "undefine" a setting that was not defined before; those are listed after a restore.

## Lockout safeguards

Every change is checked before anything is written (`Test-IgwtSecurityPolicySafeguards`):

1. **Logon rights**: Administrators and you keep *Allow log on locally*; in a Remote Desktop session
   you also keep *Allow log on through Remote Desktop Services* and *Access this computer from the
   network* (needed for Network Level Authentication). Deny rights never match you (directly or
   through a group such as Users or Everyone), and *Deny log on locally* never contains Administrators.
2. **Password and lockout**: a maximum password age at or below your password's age is refused (it
   would expire now), as are a minimum age at or above the maximum, a lockout threshold of 1 or 2, a
   lockout duration shorter than the reset counter (Windows requires duration >= reset), and lockout
   until an administrator unlocks (duration 0) when only one administrator is enabled.
3. **Last administrator**: the built-in Administrator is never disabled while it is the last enabled
   administrator, while you are signed in with it, or when the Administrators group cannot be read.
4. **No weakening**: reversible password encryption, the Guest account, anonymous SID/name lookup,
   sensitive privileges (debug, drivers, take ownership, backup/restore, impersonate, ...) for broad
   groups (Everyone, Users, Authenticated Users, Guests, Anonymous), and Registry Values on the policy
   denylist (for example EnableLUA=0) are refused.

## Advanced audit policy (auditpol)

```powershell
.\iGWindowsTuner.ps1 -AuditPolicy
.\iGWindowsTuner.ps1 -AuditSet "Process Creation=SuccessAndFailure;Logon=SuccessAndFailure" -DryRun
.\iGWindowsTuner.ps1 -AuditImport .\baseline\audit.csv -DryRun
.\iGWindowsTuner.ps1 -AuditExport .\audit.csv
```

Changes take an `auditpol /backup` first, use `auditpol /set /subcategory:{GUID}`, and are verified
with `auditpol /get`; `-AuditRestore <folder>` runs `auditpol /restore`. The dry run warns when a
change stops auditing success or failure events, and notes when SCENoApplyLegacyAuditPolicy is not set
(legacy category settings can then override subcategories). The CSV format is the `audit.csv` of
Group Policy backups and security baselines (with "Setting Value" 0-3).

Reading needs administrator rights (secedit exits with 740, auditpol with 0x522 otherwise), so the
read-only views ask for elevation. Sources: secedit export/configure and auditpol get/set/backup/restore
on Microsoft Learn (windows-commands), and the Windows security policy settings reference.