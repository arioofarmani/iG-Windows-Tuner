# Security coverage report

Audit of 2026-10-22 (Windows 11 Pro 26H2 build 26300, Defender platform 4.18.26090.9): which
attack surface reduction rules, Microsoft Defender Antivirus settings and Windows Security features
iG Windows Tuner covers, where each one lives in the application, and what is deliberately left
out. Sources: the Microsoft Learn ASR rules reference, the Set-MpPreference reference, the Defender
CSP, the Defender Administrative Templates on this PC, and the Windows Security documentation.

## Attack surface reduction: 19 of 19 rules

Every rule of Microsoft's ASR reference is in `data\asr\rules.json` with the same GUID, including
Block Webshell creation for Servers (server only) and Block rebooting machine in Safe Mode. Each rule
can be set to Not configured, Audit, Warn (where supported) or Block in the ASR Center, with per-rule
and ASR-only exclusions and the audit view (GUI: Security > ASR Center, CLI: `-Asr`).

## Microsoft Defender Antivirus: 137 of 137 preferences

`Get-MpPreference` reports 137 properties on this platform. All of them are covered:

| Where | Count | How they can be changed |
|---|---|---|
| Security > Defender settings, editable (`-DefenderSet`) | 87 | Snapshot first, revert in Backups & Logs; protections only move toward on |
| Security > Defender settings, Network Inspection parsers | 12 | Only ever turned on |
| Security > Defender settings, Group Policy only | 13 | `-PolicySet` (proxy, update shares, threat default actions, per-threat actions, headless UI, hide exclusions) |
| Security > Defender settings, shown only | 11 | Tamper Protection, exclusion lists, unknown-threat action, legacy and undocumented settings |
| ASR Center | 9 | ASR rules and their exclusions, controlled folder access and its allowed apps and folders |
| Exclusions audit | 4 | Path, process, extension and IP exclusions: shown with a risk rating, removal only |
| Device identifier | 1 | `ComputerID` (not a setting) |

The catalog has the Microsoft description, the allowed values and the recommended value of every
setting (`data\defender\settings.json`). A property that a newer Defender platform adds is listed
read-only as "not in the catalog yet" until it is documented and reviewed, so nothing stays hidden;
the test `tests\DefenderSettings.Tests.ps1` fails if the catalog misses a property of the recorded
platform (`tests\fixtures\defender\mppreference-properties.json`).

Hidden settings that Windows Security does not show and that are now configurable: update channels
(security intelligence, engine, platform, safe deployment), gradual rollout, scheduler
randomization, catch-up and grace periods, scan schedule offset and remediation schedule, CPU
throttling for idle and custom scans, cache maintenance, full scans on battery, mapped network
drives, quick scans of contextual exclusions, UDP receive and segmentation offload and asynchronous
inspection for network protection, network protection reputation engine, brute-force and remote
encryption protection (mode, aggressiveness, block time, local network blocking, learning period),
AI agent protection and network inspection, Dev Drive performance mode, file hash computation,
Intel Threat Detection Technology, reporting timeouts, service health reports and the core service
telemetry and ECS switches.

### Defender Group Policy: every Defender policy

`-DefenderPolicies` and the Group Policy view of the Defender page list every Defender policy of the
installed Administrative Templates (142 on this PC, without exclusions, ASR and controlled folder
access), including the ones with no preference: heuristics, packed executables, reparse points,
archive depth and size, quick scan interval, aggressive catch-up, scan after update, update on
startup, real-time signature delivery, notifications, local setting overrides and device control.
The policy denylist (`data\policy\denylist.json`) refuses every state that turns a protection off.

## Windows Security areas

| Windows Security area | Feature | In iG Windows Tuner |
|---|---|---|
| Virus & threat protection | Real-time, cloud, sample submission, PUA, scans, updates | Security > Defender settings; catalog items `sec.defender-hardening`, `sec.gaming-friendly-scans`; Defender policy presets |
| | Tamper Protection | Shown only (status); never changed |
| | Exclusions | Exclusions audit with risk rating, removal only; never added |
| | Controlled folder access (ransomware protection) | ASR Center; `sec.cfa-audit`, `sec.cfa-allow-games` |
| | Protection history, quarantine, scans | `-DefenderThreats`, `-QuarantineRestore`, `-DefenderScan` |
| | Defender in a sandbox (hidden) | `sec.defender-sandbox` (new) |
| Firewall & network protection | Firewall profiles, notifications, logging | `sec.firewall-on`, firewall logging preset, `-FirewallLog`, firewall rule browser (Manage) |
| | Network protection, Network Inspection | Security > Defender settings; `sec.network-protection`; `-DefenderParsersOn` |
| App & browser control | Smart App Control | Shown only (turning it on needs a clean install; turning it off cannot be undone) |
| | SmartScreen for apps and files, Edge and Store apps | `sec.smartscreen-on`, Edge Security policy preset |
| | Potentially unwanted app blocking (Defender and Edge) | Defender settings (PUAProtection), Edge Security preset |
| | Phishing protection (Enhanced Phishing Protection) | `sec.enhanced-phishing-protection` (new) |
| | Exploit protection (system and per-program) | ASR Center exploit protection, `sec.exploit-protection-defaults` |
| Device security | Memory integrity, VBS | `sec.hvci-on`, `sec.vbs-hvci-off-expert` (Expert, anti-cheat aware) |
| | Local Security Authority protection | `sec.lsa-protection` |
| | Microsoft Vulnerable Driver Blocklist | `sec.vulnerable-driver-blocklist` |
| | Kernel-mode hardware-enforced stack protection | `sec.kernel-shadow-stacks` |
| | Memory access protection (Kernel DMA), Secure Boot, TPM | Shown only (dashboard and anti-cheat readiness); firmware settings |
| Account protection | Windows Hello, dynamic lock | Not covered (account features, not system settings) |
| Family options, device performance | | Not applicable |

Other hardening outside the Windows Security app: UAC, LLMNR, NetBIOS, remote access, anonymous
access, AutoRun, SMB, Print Spooler, NTLMv2, WDigest, script hosts, PowerShell logging and LOLBin
outbound blocks (Security items), security policy and audit policy (`-SecPolicy`, `-AuditPolicy`),
and every installed Administrative Template (`-PolicySearch`, `-PolicySet`).

## Deliberately not covered

| Feature | Why |
|---|---|
| Turning off real-time protection, Tamper Protection, cloud protection, SmartScreen, the firewall, UAC, VBS/HVCI or CPU mitigations | Project safety rule; the editor and the policy denylist refuse it |
| Adding antivirus exclusions or per-threat Allow actions | Project safety rule; exclusions are only removed |
| Credential Guard | Enterprise and Education only (not available on Pro); enabled by default on eligible Enterprise PCs since 22H2 |
| System Guard Secure Launch (firmware protection) | Needs specific firmware support and an edition check that could not be verified on this PC |
| Microsoft Defender Application Guard | Deprecated by Microsoft |
| Smart App Control on/off | On needs a clean install, off cannot be undone; shown only |
| Undocumented preferences (package inspection, trust label protection, thread pool cap, network scanning for IOAV) | Never write undocumented values; shown only |
