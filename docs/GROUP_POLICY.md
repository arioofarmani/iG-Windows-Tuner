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
# Catalog policy items through the Local GPO (3.0 phase 5)

Catalog items that write a machine Policies key (`HKLM\SOFTWARE\Policies\...` and
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\...`), including the parts of composite
items such as Windows Update for Business deferrals, now also write the value to the Local GPO
(`Machine\Registry.pol`, gpt.ini version bump). They show in gpedit and survive a policy refresh. The
registry gets the same value immediately, so no gpupdate runs. Turning an item off (Windows default)
makes its values "not configured" in the Local GPO.

- **Snapshots** keep each value's exact Registry.pol entries; a revert restores them byte for byte. A
  snapshot entry for any other key or value is refused.
- **v1/v2 snapshots** have no Registry.pol data. Their revert restores the registry as before, and if the
  Local GPO holds an entry for the value, that entry follows the restored value (or is removed), so the
  next refresh does not undo the revert.
- **HKCU items stay per-user registry writes**: the user part of the Local GPO applies to every account
  on the PC.
- The bridge is off on Windows Home (no Local Group Policy), and managed PCs keep policy items
  report-only.

## Tattooed values

`-PolicyTattoo` lists them; under `CurrentVersion\Policies` only values written by catalog items count,
because Windows itself keeps UAC and other security options there.

```powershell
.\iGWindowsTuner.ps1 -PolicyAdopt igwt -DryRun                 # every value an iG Windows Tuner item wrote
.\iGWindowsTuner.ps1 -PolicyAdopt "SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" -DryRun
.\iGWindowsTuner.ps1 -PolicyRemoveTattoo "SOFTWARE\Policies\Vendor\Old\Value" -DryRun
```

Adopting takes a GPO backup (undo with `-PolicyRestore`). Values on the denylist (for example
Defender turned off by an old tool) cannot be adopted, only removed. Removing saves the values to a
restore file (undo with `-TattooRestore`), which can only write back under the machine Policies keys.
# Policy presets, baselines and exports (3.0 phase 6)

`-PolicyPreset list` shows the category presets (data\policy\presets.json). Each one is applied as a single batch: one Local GPO backup, one Registry.pol write per class, gpt.ini, audit and security settings through their engines (with the lockout safeguards), one targeted gpupdate and a verification. A record file lists every backup; `-PolicyPresetRestore <record>` reverts all of it.

```powershell
.\iGWindowsTuner.ps1 -PolicyPreset secure-gaming -DryRun
.\iGWindowsTuner.ps1 -PolicyExport audit-logging -ExportFormat GpoBackup -ExportPath .\export
.\iGWindowsTuner.ps1 -Baseline .\Windows-11-v24H2-Security-Baseline -ReportPath .\compare.csv
.\iGWindowsTuner.ps1 -Baseline .\Windows-11-v24H2-Security-Baseline -BaselineApply differs -DryRun
```

| Preset | Scope | What it does |
|---|---|---|
| `policy.privacy-telemetry` Privacy & Telemetry | Privacy | Required diagnostic data only, no consumer content, ads, activity publishing, web search or Recall. (10 settings) |
| `policy.wufb-pilot` Windows Update ring: Pilot | Updates | Feature updates as soon as they are offered, quality updates installed within 2 days. (2 settings) |
| `policy.wufb-broad` Windows Update ring: Broad | Updates | Feature updates 60 days after release, quality updates installed within 5 days. (2 settings) |
| `policy.wufb-gaming` Windows Update ring: Gaming | Updates | Feature updates after 90 days, no restarts 10 AM-4 AM, 7-day quality deadline, drivers stay yours. (4 settings) |
| `policy.defender-antivirus` Defender Antivirus | Defender | Advanced cloud protection, Block at First Sight, high cloud block level, PUA blocking and network protection. (10 settings) |
| `policy.attack-surface` Attack Surface | AttackSurface | No AutoRun, no multicast name resolution, no insecure guest SMB logons, no WinRM Basic authentication. (6 settings) |
| `policy.edge-security` Microsoft Edge Security | AttackSurface | SmartScreen and PUA blocking without bypass, typo protection, site isolation, no Basic auth over HTTP. (8 settings) |
| `policy.credentials-hardening` Credentials & Authentication Hardening | AttackSurface | LSA protection, NTLMv2 only, no LM hashes, no anonymous enumeration, lockout 10/10/10. (9 settings) |
| `policy.remote-access-lockdown` Remote Access Lockdown | AttackSurface | Remote Desktop only with NLA and high encryption, no drive redirection, no Remote Assistance or WinRS. (5 settings) |
| `policy.removable-media` Removable Media & Device Installation | AttackSurface | No access to USB storage and other removable storage, no AutoRun, removable drives scanned. (3 settings) |
| `policy.audit-logging` Audit & Logging (SOC visibility) | AuditLogging | Process creation with command lines, PowerShell logging, sign-in and account auditing, larger event logs. (21 settings) |
| `policy.kiosk-shared` Kiosk / Shared Device | System | No lock-screen camera or notifications, no clipboard history, no consumer content; Store off on Enterprise/Education. (7 settings) |
| `policy.developer-workstation` Developer Workstation | System | Long paths, Developer Mode sideloading and PowerShell script block logging. (4 settings) |
| `policy.secure-gaming` Secure Gaming PC | AttackSurface | Defender cloud protection and PUA blocking, no AutoRun or LLMNR, Edge SmartScreen PUA, no evening restarts. (8 settings) |

Setting kinds: `admx` (an installed ADMX policy; a missing template shows the setting as unavailable,
add it with `-AdmxFolder`), `registry` (a documented policy value written to Registry.pol, used for
Microsoft Edge so its templates need not be installed), `audit` (subcategory by GUID, from the Win32
auditing constants) and `secpol` (a security template setting). Settings that an edition does not
enforce are applied and marked "Not effective on <edition>". Quality updates are never deferred: the
update rings use feature-update deferrals and deadlines.

## Exports

- **GpoBackup**: `{GUID}\DomainSysvol\GPO\Machine|User\registry.pol`, `...\SecEdit\GptTmpl.inf` and
  `...\Audit\audit.csv`, plus a README with the `LGPO.exe /m`, `/u`, `/s` and `/a` commands. It has no
  Backup.xml or bkupInfo.xml, so it is not a GPMC backup (DECISIONS B3).
- **Reg**: a `.reg` file with the registry policy values (non-additive list clearing is noted as a comment).
- **Script**: a standalone PowerShell script (`-WhatIf` supported) with an INF for security settings.
  Its registry writes do not appear in gpedit; the GPO backup export is preferred.
- **Json**: the preset with its resolved Registry.pol operations.

## Baselines

`-Baseline <folder>` reads a downloaded Security Compliance Toolkit baseline or any GPO backup:
registry.pol (Machine and User), GptTmpl.inf and audit.csv per GPO, named from bkupInfo.xml. The
comparison lists baseline, Local GPO and effective values with a status (Match, Differs, NotSet,
Blocked for values on the denylist, Unsupported for template sections iG Windows Tuner does not apply,
Unknown when reading needs administrator rights) and exports to CSV. `-BaselineApply differs` (or
Ref values) applies through the same batch engine; Blocked values are never selected. Baselines are
never bundled or downloaded.