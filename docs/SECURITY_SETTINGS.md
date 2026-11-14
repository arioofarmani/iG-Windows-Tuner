# Security Settings Manager

Security > Security settings lists every security setting an administrator can configure on this PC, shows its current value and where that value comes from, and changes it with the kind of value the setting needs. Every change is previewed, journaled and can be undone. Design: docs\DECISIONS.md SM1 to SM43.

## What is listed

| Source | Where it comes from | How iG changes it |
|---|---|---|
| Group Policy | The Windows policy definitions in %SystemRoot%\PolicyDefinitions, security categories only (data\security\categories.json): Defender, Device Guard and VBS, BitLocker, Firewall, Credentials Delegation and Credential UI, Kernel DMA, TPM, SmartScreen, LSA, SAM, Kerberos, Exploit protection, Remote Desktop security and connections, SMB client and server, PowerShell, AutoPlay, logon options, Windows Installer | Local Group Policy, written like the Group Policy editor: Machine or User Registry.pol, gpt.ini version and extension list, then one Group Policy refresh |
| Defender preferences | Get-MpPreference, with the names, ranges and units of data\defender\settings.json; documented preferences without a catalog entry are shown read-only | The existing Defender settings writer |
| ASR rules | The ASR Center | Block, Audit or Warn. Off and Not configured are refused; use Audit to watch a rule |
| Exclusions | The exclusion audit | Removing only. iG never adds exclusions, and a removal cannot be undone by iG |
| Security options | secedit export and sceregvl.inf (run iG as administrator) | One secedit step per apply |
| Audit policy | auditpol (run iG as administrator) | Add-only: iG never stops auditing success or failure |
| Device Guard state | Win32_DeviceGuard | Read-only: configured versus running |

Rows show the policy's own name, explanation, supported versions and value definitions.

## Where a value comes from

| Origin | Meaning | Can iG change it? |
|---|---|---|
| Local policy | Local Group Policy (Registry.pol) | Yes |
| Domain GPO | A domain Group Policy (only read on domain-joined PCs) | No: change it in the domain |
| MDM | A management service such as Intune | No |
| Defender | A local Defender preference | Yes |
| Tamper Protection | Tamper Protection blocks the change | No: turn Tamper Protection off in Windows Security first if you really need to |
| Registry only | A Policies value without local policy | No: use Adopt on the Group Policy page |
| Unknown | Domain policy could not be read | No |

On Home (no Group Policy) and on editions iG does not recognise, Group Policy rows are read-only. On a managed PC (MDM or Defender for Endpoint), Group Policy, Defender and ASR rows are read-only until you confirm the change.

## What iG never sets

- Values that turn a protection off, also by setting a policy to Disabled or Not configured while it is on (data\policy\denylist.json and data\security\weakening.json, for example AlwaysInstallElevated, switching PowerShell logging off, insecure guest logons, LSA protection off).
- Any choice with a UEFI lock (memory integrity, Credential Guard, LSA protection). A UEFI lock cannot be removed by software; Microsoft documents removal steps that need firmware access at boot.
- New exclusions, Tamper Protection, and the PowerShell execution policy (it stays as it is, docs\SECURITY.md).
- Lockout settings that cannot be proven safe: requiring a smart card, blocking Microsoft accounts, standard users without elevation when you are not an administrator, shutting down when the audit log is full, and Remote Desktop or firewall changes while you are connected over Remote Desktop.

Refused choices are shown, disabled, with the reason.

## High-risk settings

Virtualization-based security, memory integrity, Credential Guard, LSA protection, App Control and BitLocker policies need:

1. Prerequisite checks: virtualization support, DMA protection, Secure Boot, TPM, and whether the system drive has a BitLocker recovery password (the protector type only, never the key). Driver compatibility is never checked by iG, because Windows has no documented pre-check: open Windows Security > Device security > Core isolation to see incompatible drivers before restarting.
2. The documented side effects, a restart notice and the link to Microsoft's steps for turning memory integrity off from the Windows Recovery Environment.
3. A typed confirmation word (CLI: -AcknowledgeRisk).

Have your BitLocker recovery key ready (aka.ms/myrecoverykey) before restarting after such a change.

## Applying and undoing

Changes are staged, previewed (read-only), then applied as one change session: local policy steps, Defender, ASR, exclusions, one security option step and one audit step. If a step fails, the steps before it are rolled back. The result offers Undo; Backups & Logs > Change journal lists the session as "Security settings". Local policy changes undo value by value; security options and audit policy undo as whole steps. Exclusion removal and a security option that was not defined before cannot be undone by iG and are applied on their own.

## Command line

```
.\iGWindowsTuner.ps1 -SecSettings [-Category <text>] [-Search <text>] [-ConfiguredOnly] [-SourceKind admx,defender,...] [-Json] [-NoCache]
.\iGWindowsTuner.ps1 -SecSetting <id> [-Json]
.\iGWindowsTuner.ps1 -SecSettingSet '<id>=<value>'[,...] [-DryRun] [-AcknowledgeRisk] [-AcknowledgeManaged]
.\iGWindowsTuner.ps1 -SecSettingRemoveExclusion 'Path:<value>'[,...] [-DryRun]
```

Group Policy values are `Enabled`, `Disabled` or `NotConfigured`, then element values as `;element=value`; list items are separated by `|`.

## Baseline

The Baseline column shows a Microsoft security baseline value only where iG can cite it. iG downloads nothing; no baseline values are bundled yet. The Windows 11 security baseline ships as Group Policy backups in Microsoft's Security Compliance Toolkit.

## Honest limits and UNVERIFIED items

- Not verified in Windows Sandbox yet: real local policy writes and gpupdate, secedit and auditpol steps, Device Guard changes and restarts (DECISIONS SM38).
- UNVERIFIED (SM39): the local GPO extension list and client extension pairing; the MDM readout location; whether a configured but not running Device Guard service always means a pending restart; Home edition detection; the sceregvl.inf format; the restart needs of System Guard and kernel stack protection; the timing of BitLocker deny-write policies.
- The policy definitions take about 7 s to read the first time; a refresh takes about 3 s (SM35).
