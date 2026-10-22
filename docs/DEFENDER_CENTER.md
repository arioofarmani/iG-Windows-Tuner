# Defender & Security Control Center (3.0)

`-DefenderCenter All` (or one section: Status, Settings, Exclusions, Firewall, Web, DeviceControl,
Logging) shows Microsoft Defender and the related Windows protections in one place. It reads with
`Get-MpComputerStatus`, `Get-MpPreference`, `Get-NetFirewallProfile`, the registry and event log
metadata; it changes nothing. Exclusions and some logs are only visible to administrators.

## What each section shows

| Section | Content |
|---|---|
| Status & health | Engine, platform and security intelligence versions and age, running mode (normal or passive), real-time protection, Tamper Protection (read-only: iG Windows Tuner never changes it), Smart App Control, last scans, Defender for Endpoint onboarding, management |
| Settings | Every setting in `data\defender\settings.json` that this platform reports: real-time and behavior, cloud protection, scans and updates, threat actions and retention, PUA, network protection and Network Inspection. Current value, status (On, Off, Below, Info), who sets it (Local, Local GPO, Domain GPO, policy, MDM) and the ADMX policy that changes it |
| Exclusions | Every path, process, extension and IP exclusion, ASR-only exclusions and Controlled folder access apps, with the source and a risk rating (whole drives, user-writable and temp folders, script hosts, code-carrying extensions, wildcards, broad IP ranges) |
| Firewall | Logging per profile (dropped and allowed packets, file, size) |
| Web & phishing | SmartScreen for apps and files, Edge and Store apps, Edge PUA blocking, Enhanced Phishing Protection policies |
| Device control | Device installation restrictions and removable storage policies, Defender device control state |
| Logging | Defender operational log, Security log size, command lines in event 4688, PowerShell script block, module and transcription logging, advanced audit enforcement, Sysmon (detected and used, never installed) |

Controlled folder access, attack surface reduction rules and exploit protection are managed only in
the ASR Center (`-Asr`); the Control Center links there instead of duplicating controls.

## Changing Defender settings

Changes go through policy presets (Local GPO, with backup and revert):

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

Sources: Set-MpPreference reference, network protection, cloud protection, Tamper Protection,
Defender exclusions and common exclusion mistakes, Microsoft Defender Offline, Windows Firewall
logging (Microsoft Learn).
