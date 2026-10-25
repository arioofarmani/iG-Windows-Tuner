# Firewall Manager 3.4: starting audit (phase 0)

Date: 2026-10-24. Scope: SPEC-v3.4-firewall phase 0 (review the 3.3 Firewall Manager, read this PC's
rules read-only, record the sources the 3.4 classification and risk engine rely on).

Counts only: no rule export of this PC is stored anywhere in the repository (it reveals installed
software). Tests use synthetic fixtures.

## 1. What 3.3 has, and what happens to it

| Part (3.3) | Where | 3.4 |
|---|---|---|
| Bulk inventory: one query per class (rules, application, port, address, service, interface filters), joined in memory on InstanceID | `Get-IgwtFirewallInventory`, `Join-IgwtFirewallData` | **Keep.** Already reads raw CIM values (fix 57ba748). Extend with the Windows Service Hardening stores (read-only, Core Services). |
| Source (Windows, ThirdParty, StoreApp, Owned, GroupPolicy) from the display group `@...` and the owner | `Get-IgwtFirewallRuleSource` | **Replace** with the origin category engine (Core Services, Windows Connections, User Installed, Custom Rules) driven by data files; the managing store (GPO/MDM lock) stays a separate property. |
| Risk flags hard-coded in code (inbound Public, broad, program missing, user-writable, duplicate, disabled Windows default) | `Add-IgwtFirewallRisk` | **Refactor** into data (`data\firewall\risks.json`) with severities, explanations, recommended and alternative actions; add the spec 2.3 patterns, signature and exposure checks. |
| Duplicate detection (key of direction, action, program, service, package, protocol, ports, remote address, profiles) | `Add-IgwtFirewallRisk` | **Fix**: Store-app rules and rules whose ports could not be read are excluded (57ba748). Move under the precedence engine (redundant = fully covered by another rule). |
| Snapshot-backed changes (enable, disable, Allow/Block, edit, duplicate, delete), validation, remote-session dead-man switch (60 s), Core Networking protection, GPO/MDM lock | `Get-IgwtFirewallChangePlan`, `Invoke-IgwtFirewallChange`, `Restore-IgwtFirewallSnapshot`, `Get-IgwtFirewallChangeBlock` | **Keep.** Extend the change blocks with the new rules: Core Services locked, Windows rules never deleted, delete only for orphaned or Custom/User Installed rules, anti-cheat and launcher rules never blocked by a recommendation. |
| Import/export (JSON, CSV, .wfw), profiles and network category, firewall log analysis | same file | **Keep.** The audit report (phase 7) builds on the export code. |
| GUI: SmartGrid with columns and chips, details pane, wizard, edit form, Undo toasts, profiles tab | `src\Gui\FirewallPage.ps1` | **Refactor**: add the Overview (home), the group sidebar with counts, membership chips on rows, the plain-language summary at the top of the details pane, group bulk actions with preview, the smart fix wizard. |
| Tests: engine 18, page 12 (mocks) | `tests\FirewallManager.Tests.ps1`, `tests\FirewallPage.Tests.ps1` | **Keep** and add the synthetic 1,000+ rule fixture set, classification, precedence, exposure, safety and performance tests. |

3.3 UI audit items F1-F5 (not a rule manager, single selection, persistent store only, card rows, no
profiles panel) were closed in 3.3 phase 3.

## 2. This PC, read-only (2026-10-24, not elevated)

| Measure | Value |
|---|---|
| Rules in the active store | 512 (read in 0.8 s) |
| Policy store source | PersistentStore 512 (no Group Policy or MDM rules on this PC) |
| Direction / action | inbound allow 282, outbound allow 220, outbound block 10 |
| Enabled | 246 enabled, 266 disabled |
| Group is a resource string (`@FirewallAPI.dll,-NNNNN` and similar) | 450; plain-text group 50; no group 12 |
| AppContainer (Store app) rules with an owner SID | 66 |
| Rules with a GUID name (app installers and firewall prompts) | 43, 32 of them with a description |
| Largest built-in groups by stable ID | Network Discovery (`@FirewallAPI.dll,-32752`) 52, Core Networking (`-25000`) 40, File and Printer Sharing (`-28502`) 32, Windows Media Player Network Sharing (`-31252`) 31, Media Center Extenders (`-30752`) 19, Cast to Device (`-36001`) 18, Remote Assistance (`-33002`) 15 |
| Windows Service Hardening, StaticServiceStore (read-only store) | 177 rules (inbound block 61, outbound block 57, outbound allow 36, inbound allow 23) |
| ConfigurableServiceStore (third-party service restrictions) | 3 rules |
| SystemDefaults store (the Windows default rule set of this build) | 393 rules (inbound allow 231, outbound allow 162) |

Notes for the design:

- **Stable identifiers are available for almost every Windows rule**: the rule `Name` (for example
  `CoreNet-DHCP-In`, `NETDIS-...`, `FPS-...`) and the raw group resource string. Display names are
  localized; the engine never matches on them.
- **Without administrator rights** the port, address and interface-type filters are not readable
  (access denied). Classification must work without them (lower confidence for port-based risk
  rules, shown as "needs administrator rights to check").
- **The SystemDefaults store gives a baseline of the Windows default rules for this exact build**
  without the sandbox (decision F2). The sandbox export stays as the fallback and for older builds.
- Windows Service Hardening rules are not part of the persistent store; they are read separately
  and always classified as Core Services (locked).

## 3. Sources

| Topic | Source | What it says (used for) |
|---|---|---|
| Rule precedence (current) | [Windows Firewall rules, Microsoft Learn (updated 2026-10-08)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules) | Explicit allow beats the default block; explicit block beats a conflicting allow; a more specific rule beats a less specific one except where a block applies; no administrator-assigned ordering. Also: keep the defaults, restrict remote address to Local Subnet for home/small-network services, document rules, allow outbound by default, never allow all inbound by default; a dismissed or non-admin firewall prompt creates block rules (TCP and UDP). |
| Rule precedence (with authenticated bypass) | [Firewall Rules, Windows Server 2008 R2 (archived)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc730951(v=ws.10)) | Authenticated bypass, then block, then allow, then the profile default. Program rules open ports only while the program listens; port rules are open whenever the firewall runs (used to rate port-only allow rules as broader). Service containers (svchost) without a service restriction are a risk. |
| Policy stores, Windows Service Hardening | [Set-NetFirewallServiceFilter (NetSecurity)](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallservicefilter) and [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule) | StaticServiceStore is read-only and holds the service restrictions that ship with Windows; ConfigurableServiceStore holds third-party service restrictions; ActiveStore is the resultant policy. |
| Core Networking group | [Configuring predefined rules by using Group Policy](https://technet.microsoft.com/en-us/library/cc753295) | Microsoft's deployment guide keeps every Core Networking rule enabled; review the other predefined groups and deploy only those that fit. |
| AppContainer / Store app rules | [App capability declarations](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations), [Implementing an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer), [Troubleshooting UWP app connectivity](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall) | An AppContainer has no network access without a capability (internetClient, internetClientServer, privateNetworkClientServer); Windows creates per-package rules (owner = user SID, package in the rule ID). |
| Admin and file protocols on untrusted networks | [CISA: misconfigurations used in ransomware campaigns](https://www.cisa.gov/stopransomware/misconfigurations-and-weaknesses-known-be-used-ransomware-campaigns), [CISA countermeasure CM0025 (RDP)](https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0025) | Exposed RDP and SMB are common ransomware entry points; restrict RDP to approved users and networks. |
| Script hosts and LOLBins | [LOLBAS project](https://lolbas-project.github.io/) | Signed Windows binaries (mshta, regsvr32, rundll32, certutil, wscript, cscript, powershell, cmd) that attackers use to download and run code; allow rules for them widen what malware can do. |
| NetBIOS, LLMNR, mDNS | "Aligning on mDNS: ramping down NetBIOS name resolution and LLMNR" (Microsoft Networking Blog, April 2022; [mirror](https://thewindowsupdate.com/?p=176993)), [SANS ISC: passwords off the wire using LLMNR](https://isc.sans.edu/diary/Passwords+Part+2+Passwords+off+the+Wire+using+LLMNR/23369) | Microsoft is phasing out NetBIOS and LLMNR in favour of mDNS; LLMNR/NBT-NS answers on untrusted networks enable credential capture. |
| Teredo and Xbox networking | [Implementing firewall filters for Teredo](https://learn.microsoft.com/en-us/windows/win32/teredo/implementing-firewall-filters-for-teredo) | Teredo is used by Xbox Live party chat and peer multiplayer; disabling it breaks those (note on Xbox rules, never a default recommendation for gamers). |

Open points (verified during phase 1, recorded per knowledge-base entry): the exact rule IDs of each
built-in group on build 26100+ are taken from the SystemDefaults store of this PC (IDs only) and
from Microsoft's group names; entries Microsoft does not document get `basis: igwt` and a Medium
confidence.
