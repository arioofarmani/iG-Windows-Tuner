# Defender & Security Control Center (3.0)

`-DefenderCenter All` (or one section: Status, Settings, Exclusions, Firewall, Web, DeviceControl,
Logging) shows Microsoft Defender and the related Windows protections in one place. It reads with
`Get-MpComputerStatus`, `Get-MpPreference`, `Get-NetFirewallProfile`, the registry and event log
metadata; it changes nothing. Exclusions and some logs are only visible to administrators.

## What each section shows

| Section | Content |
|---|---|
| Status & health | Engine, platform and security intelligence versions and age, running mode (normal or passive), real-time protection, Tamper Protection (read-only: iG Windows Tuner never changes it), Smart App Control, last scans, Defender for Endpoint onboarding, management |
| Settings | Every Microsoft Defender Antivirus preference this platform reports (all 137 `Get-MpPreference` properties: 123 in `data\defender\settings.json`, the rest in the ASR Center and the exclusions audit; a property a newer platform adds is listed read-only). Current value, recommended value, status (On, Off, Below, Optional, Info), who sets it (Local, Local GPO, Domain GPO, policy, MDM), the ADMX policy and how it can be changed |
| Exclusions | Every path, process, extension and IP exclusion, ASR-only exclusions and Controlled folder access apps, with the source and a risk rating (whole drives, user-writable and temp folders, script hosts, code-carrying extensions, wildcards, broad IP ranges) |
| Firewall | Logging per profile (dropped and allowed packets, file, size) |
| Web & phishing | SmartScreen for apps and files, Edge and Store apps, Edge PUA blocking, Enhanced Phishing Protection policies |
| Device control | Device installation restrictions and removable storage policies, Defender device control state |
| Logging | Defender operational log, Security log size, command lines in event 4688, PowerShell script block, module and transcription logging, advanced audit enforcement, Sysmon (detected and used, never installed) |

Controlled folder access, attack surface reduction rules and exploit protection are managed only in
the ASR Center (`-Asr`); the Control Center links there instead of duplicating controls.

## Changing Defender settings

### Settings editor (`-DefenderSettings`, `-DefenderSet`, GUI: Security > Defender settings)

`-DefenderSettings [-DefenderCategory <id>] [-Json]` lists every preference in 13 categories (real-time
protection, cloud protection, scans and schedules, security intelligence and updates, threat actions,
PUA, network protection and inspection, brute-force and remote encryption protection, AI agent
protection, performance and Dev Drive, reporting and interface, Windows Server, advanced and
undocumented), including the ones Windows Security does not show: update channels, scheduler
randomization, catch-up intervals, grace periods, UDP offloads for network protection, brute-force
and remote encryption protection, AI agent protection, Intel TDT, cache maintenance and more.

`-DefenderSet "CloudBlockLevel=High;ScanScheduleTime=03:30;ScanAvgCPULoadFactor=30" -DryRun` shows
the plan; without `-DryRun` it writes a snapshot (operation `Defender`), sets each value with
`Set-MpPreference` and reads it back (Tamper Protection or a policy can keep the old value; the
result then says `NotApplied`). Values are numbers, the labels `-DefenderSettings` shows,
true/false, on/off (for protections) or HH:mm. The GUI page has the same editor: pick a value (values
that are not allowed are marked) and press Apply value.

The rules (every forward change and every revert):

| Kind | What can be set |
|---|---|
| Protection (real-time, behavior, IOAV, script, archive and network file scanning, Block at First Sight, scan direction) | Only the protective value. iG Windows Tuner never turns a protection off. |
| Hardening (off by default: e-mail and removable drive scanning, catch-up scans, update before scans, OOBE protection, warn-to-block, AI agent protection, Intel TDT, quick scans of exclusions) | Only on (Block or Audit where offered). |
| Level (cloud protection, cloud block level, extended cloud check, sample submission, PUA, network protection, brute-force and remote encryption protection) | Any value except the ones that turn it off (Off, Never send); a level at the recommended value is never lowered. |
| Option (schedules, CPU limits, retention, update channels and intervals, reporting timeouts, telemetry, offloads) | Any listed value, within the documented range. |
| Parser (Network Inspection) | Only on, through `Set-IgwtDefenderParsersOn`, without revert. |
| Group Policy only (proxy and update share sources, threat default actions, per-threat actions, headless UI mode, hiding exclusions) | Through the ADMX policy (`-PolicySet`); the denylist refuses Allow and No action. |
| Shown only | Tamper Protection, exclusion lists (brute-force and remote encryption exclusions), the unknown-threat action, legacy and undocumented settings. |

A setting that a policy or MDM sets is refused locally (the policy wins): change the policy instead.
A revert restores options exactly; an earlier value that would turn a protection off or lower a
level is not written back (result `Kept`), the same rule as the policy presets (DECISIONS D1, D8).

### Every Defender Group Policy (`-DefenderPolicies`, GUI: Group Policy view)

`-DefenderPolicies ''` (or a search text) lists every Defender policy of the installed ADMX files
(about 140 on Windows 11 26H2), also the ones with no preference: heuristics, packed executables,
reparse points, archive depth and size, quick scan interval, aggressive catch-up, scan after update,
update on startup, real-time signature delivery, notification suppression, local setting overrides,
device control and more. Each row shows the Local Group Policy state, the winning source, the
preference it sets and the states the denylist refuses (for example Disabled for heuristics).
Change one with `-PolicySet <id> -PolicyState Enabled|Disabled|NotConfigured [-PolicyValue ...]`
(Local GPO backup first); the GUI sets policies without extra values. Exclusions, ASR and
controlled folder access policies are left to their own areas.

### Policy presets

Changes can also go through policy presets (Local GPO, with backup and revert):

| Preset | Purpose |
|---|---|
| `policy.defender-gaming` | Full protection; scheduled scans at 5 AM, only when idle, low priority, 30% CPU cap |
| `policy.defender-recommended` | Microsoft's recommended cloud, PUA and network protection settings |
| `policy.defender-strict` | High+ cloud block level, network protection Block with warn-to-block, every scan type and every Network Inspection parser on |
| `policy.defender-audit` | PUA, network, brute-force and remote encryption protection in Audit mode, to measure impact first |

On a managed PC (domain or MDM) presets are report-only unless the local change is acknowledged.

**Network Inspection parsers** (DNS, DNS over TCP, HTTP, TLS, SSH, RDP, FTP, SMTP, QUIC), inbound
connection filtering, datagram processing and the DNS sinkhole have no Administrative Template.
`-DefenderParsersOn` (and the Strict preset) turns the ones that are off **on** with
`Set-MpPreference`; they are never turned off, so reverting a preset leaves them on. This is
signature- and reputation-based inspection on the endpoint, not a full IDS/IPS (see
`docs\NETWORK_IDS_IPS.md`).

## Threats, quarantine and scans

- `-DefenderThreats [-Days n]`: threat history (`Get-MpThreatDetection` with `Get-MpThreat`).
- `-QuarantineRestore <name> -IUnderstandTheRisk`: restores a quarantined item (`MpCmdRun -Restore -Name`). The file can run again.
- `-DefenderScan Quick|Full|Custom -ScanPath <path>`; `-DefenderScan Offline -ConfirmRestart` restarts into Microsoft Defender Offline.

## Exclusions

`-RemoveExclusion Path:C:\Temp` removes one antivirus exclusion after confirmation, from Defender's
preference (`Remove-MpPreference`) or from the Local GPO. Exclusions set by a domain GPO or MDM are
shown but cannot be removed locally. iG Windows Tuner never adds antivirus exclusions; add one by
hand in Windows Security if you must, and expect the audit to flag it if it is risky.

## Firewall as a detection source

- The `policy.firewall-logging` preset logs dropped packets for the Domain and Private profiles (32 MB log). The Public profile's logging is set in wf.msc (it has no Administrative Template).
- `-FirewallLog [-FirewallLogPath <file>] [-ReportPath out.json|out.csv]`: top blocked sources, ports and processes, an hourly timeline, export.
- `-OutboundAllowList`: an expert planning aid for default-block outbound (programs seen with allowed outbound connections, Windows components that always need access, warnings). It changes nothing: iG Windows Tuner creates only Block rules and never switches outbound traffic to default-block (DECISIONS D3).
- The v2 firewall rule browser stays under `-Inventory Firewall`.

Sources: Set-MpPreference reference, Defender CSP, Defender Administrative Templates (explain text),
network protection, cloud protection, Tamper Protection,
Defender exclusions and common exclusion mistakes, Microsoft Defender Offline, Windows Firewall
logging (Microsoft Learn).
