# Security design

iG Windows Tuner runs with administrator rights and edits system settings, so it is written to be as easy to audit as possible, and to look to Microsoft Defender and SmartScreen like what it is: an ordinary, transparent admin script. That is achieved through transparency, never through evasion.

## Engineering rules (all enforced or tested)

| Rule | How |
|---|---|
| Plain, readable source with comment-based help | Every function has help. There is no obfuscation, no Base64 or `-EncodedCommand`, no `Invoke-Expression`, and no command names built from strings. The GUI worker uses `AddCommand` with fixed command names, never `AddScript`. `tests\Safety.Tests.ps1` scans for all of these. |
| Fully offline | Nothing is downloaded at runtime: no `Invoke-WebRequest`, `WebClient` or BITS. |
| No security tampering | No AMSI, ETW, real-time protection, Tamper Protection or exclusion changes. Defender preferences are limited to an allow-list (PUA, MAPS, sample submission, network protection, Controlled Folder Access, scan idle/CPU) and none of them lowers protection. Tamper Protection is read, never changed. |
| No hidden windows and no persistence | No `-WindowStyle Hidden`, scheduled tasks, services, Run keys or WMI subscriptions. The "pending restart" banner is a JSON file that iG Windows Tuner reads when it starts; nothing runs at logon. |
| Visible elevation only | `Start-Process -Verb RunAs` with the normal UAC prompt (`src\Core\Elevation.ps1`). No UAC bypass. The GUI and read-only modes run without elevation. |
| Execution policy | The machine and user policies are never changed. `Start-iGWindowsTuner.cmd` and the elevation relaunch pass `-ExecutionPolicy Bypass` to that one process only. |
| Native APIs first | The .NET `Microsoft.Win32.RegistryKey` API is used for all registry work (exact types; `REG_EXPAND_SZ` stays unexpanded), plus inbox cmdlets for Defender, NetAdapter, NetQos, DnsClient, services and firewall. No `reg.exe`, `sc.exe` or `netsh`. |
| Allowed external executables | `powercfg.exe` (power plans), `nvidia-smi.exe` (read-only `-q` / `--query-gpu` only, checked in code), and `MpCmdRun.exe` (build-time scan in `tools\` only). |
| One P/Invoke | A single `Add-Type` with C# source in `src\Actions\Custom.ps1` declares `SystemParametersInfo`. It applies the mouse, key-repeat and accessibility-hotkey settings to the running session and broadcasts `WM_SETTINGCHANGE`. `Add-Type -AssemblyName` is used only to load the inbox WPF assemblies. |
| Packaging | Shipped as `.ps1/.psm1/.psd1/.json/.xaml` plus a `.cmd` launcher. Never an EXE (ps2exe output is frequently flagged). |
| Honest names | Nothing is called "bypass", "stealth" or "kill". |

## Integrity of backups (snapshot trust)

A revert writes values back with administrator rights, so the snapshot files are part of the trusted computing base:

- When elevated, `%ProgramData%\iGWindowsTuner` gets a protected ACL: SYSTEM and Administrators have full control, Users have read access, and inheritance is disabled (`Protect-IgwtDataRoot`).
- Before restoring, `Read-IgwtSnapshot` refuses any file that is not owned by SYSTEM, Administrators, TrustedInstaller or the current elevated user, or that grants write access to Everyone, Authenticated Users, Users, Interactive or Guests.
- **Paths always come from the catalog, never from the snapshot file.** A snapshot only supplies previous values, and each entry is matched to the current catalog action by a fingerprint (type + path + name + ...). If the catalog changed since the snapshot, that entry is not restored and is reported instead.
- Restores for dynamic targets are validated as well: QoS policy names must match the `iGWindowsTuner-<game>` targets, startup entries must belong to the five StartupApproved keys, per-game GPU entries must be `X:\...\*.exe` values under `UserGpuPreferences`, and firewall and TCP values must belong to fixed enumerations.

## Change safety

- **Preflight**: refuses builds older than 26100 and requires admin to apply. It warns when the edition is not Pro, a reboot is pending, a battery is present, or the session is a Remote Desktop session.
- **Remote Desktop**: tweaks that could cut off the connection (Remote Desktop/Assistance off, Wi-Fi disable, DNS changes) report NotApplicable in an RDP session. Adapter property changes use `-NoRestart`, so the link never drops mid-apply.
- **Atomic per tweak**: the snapshot entry is written before the first change. If any action fails, that tweak's already-applied actions are restored, the failure is logged, and the run continues.
- **Idempotent**: tweaks already in the target state are skipped, and actions skip values already in place. A second apply writes nothing.
- **Verification**: after apply, the real state is read again. If Tamper Protection, Group Policy or Windows refused a change, it is reported as "not verified" instead of being worked around.
- **Group Policy and MDM**: tweaks controlled by a policy value show "Managed by policy" and are not applied.
- **Restore point**: one is created before every apply through the WMI `SystemRestore` class. The 24-hour limit is lifted only during that call (`SystemRestorePointCreationFrequency = 0`, then the exact previous value is restored). System Protection is enabled only with explicit consent (GUI dialog or `-EnableSystemProtection`).
- **Over-the-shoulder elevation**: if UAC credentials of a different admin are used, per-user (HKCU) settings are redirected to the signed-in user's hive (`HKEY_USERS\<SID>`), so they apply to the gamer and not to the admin account.
- **Logs**: human-readable text plus JSON lines, in an admin-only folder.

## Code signing (optional)

`tools\Sign-Toolbox.ps1` signs the PowerShell files with **your** code-signing certificate. With `-CreateSelfSignedCertificate` and an explicit confirmation, it creates one in `Cert:\CurrentUser\My`; it never adds it to the trusted stores. The script always writes `SHA256SUMS.txt`, and `-Verify` checks the files against it.

## Reporting a problem

If iG Windows Tuner changed something it should not have, open **Backups & Logs**: every change is in a JSON snapshot and in `%ProgramData%\iGWindowsTuner\Logs`. `-RevertAll -Snapshot <file>` restores any snapshot. The System Restore point created before each apply is a second line of defense.
