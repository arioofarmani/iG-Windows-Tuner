# WinUtil mapping

iG Windows Tuner's Toolkit section borrows ideas from [Chris Titus Tech's WinUtil](https://github.com/ChrisTitusTech/winutil) (MIT License). This document maps every item in WinUtil's configuration to one decision.

- **Source:** `github.com/ChrisTitusTech/winutil`, commit `d32efebac6d50ce1a4e9734fb9400b884f76e7e6` (21 Oct 2026), files `config/tweaks.json`, `config/feature.json`, `config/applications.json`, `config/appx.json`, `config/dns.json`, `config/preset.json` and `functions/public/Invoke-WPFUpdates*.ps1`, read on 21 Oct 2026.
- **Method:** each item was re-implemented in iG Windows Tuner's own schema with its own texts, Microsoft sources, a Windows default and a revert path. No WinUtil code or text is copied, so nothing is vendored under `third_party/`; derived items carry `source: "winutil"` and an `attribution` (see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)).
- **Never:** WinUtil is not fetched at runtime and its `irm | iex` launch method is not used.

Decisions:

| Decision | Meaning |
|---|---|
| **Adopt** | Added with the same effect. |
| **Adapt** | Added, but changed for safety or to use the documented mechanism; the reason is given. |
| **Covered** | iG Windows Tuner already has an equivalent item or module. |
| **Reject** | Not added; the reason is given. |

## Tweaks: essential

| WinUtil item | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| Activity History - Disable | Adopt | `privacy.activity-history-off` | Uses the two documented policies (PublishUserActivities, UploadUserActivities). |
| Hibernation - Disable | Covered | `power.hibernation-off` | |
| Widgets - Remove | Adapt | `privacy.widgets-off` | The documented policy turns Widgets off. Removing the Web Experience package is rejected: it also hosts other shell features and returns with updates. |
| Start Menu Previous Layout - Enable | Reject | | Flips an undocumented feature-management override that Windows updates can reverse or break. |
| Microsoft Store Recommended Search Results - Disable | Reject | | Denies all access to the Store's database file with `icacls`; that breaks Store search and is an ACL hack on app data. |
| Location Tracking - Disable | Adapt | `privacy.location-off` | The documented "Turn off location" policy instead of consent-store edits and disabling the geolocation service. Advanced, because Find my device and automatic time zone stop working. |
| Services - Set to Manual | Adapt | Manage > Services, `privacy.diagtrack-disabled` | Service changes go through the curated, rated services list. DiagTrack is covered. Disabling SharedAccess is rejected (Mobile Hotspot and Hyper-V/WSL NAT need it); SvcHostSplitThresholdInKB is rejected (groups services into fewer processes, which reduces isolation and reliability for no measurable gain). |
| ConsumerFeatures - Disable | Adopt | `privacy.consumer-features-off` | Marked Enterprise and Education only, as Microsoft documents. |
| Telemetry - Disable | Adapt | `privacy.diagnostic-data-required`, `privacy.ads-suggestions-off`, `privacy.telemetry-tasks-off`, `privacy.powershell-telemetry-off` | The documented policies are covered. Rejected parts: `Set-MpPreference -SubmitSamplesConsent 2` (weakens Defender cloud protection and Block at First Sight) and disabling WerSvc (no crash reports, worse reliability data). |
| Delivery Optimization - Disable | Covered | `net.delivery-optimization-p2p-off` | HTTP-only download keeps Windows Update working without peer uploads. |
| BitLocker - Disable | Reject | | Removes disk encryption. Security never goes down. |
| Restore Point - Create | Covered | Engine | Every apply creates a restore point first. |
| End Task With Right Click - Enable | Adopt | `system.end-task-taskbar` | |
| Windows Platform Binary Table (WPBT) - Disable | Reject | | `DisableWpbtExecution` is undocumented; Microsoft's documented control for firmware-delivered binaries is an App Control (WDAC) policy, and OEM anti-theft agents depend on WPBT. Listed for a future App Control item. |
| Prevent Device Companion Apps | Adopt | `privacy.device-metadata-off` | |
| Disk Cleanup - Run | Covered | Cleaner | Allow-list rules with a scan that deletes nothing. |
| Temporary Files - Remove | Covered | Cleaner | |
| File Explorer Automatic Folder Discovery - Disable | Reject | | Deletes all saved folder views (Bags, BagMRU) to fix a slowdown that is not reproducible on current builds. |

## Tweaks: advanced (WinUtil "CAUTION")

| WinUtil item | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| Brave Browser - Debloat | Reject | | Third-party browser settings; Brave's own settings cover them. |
| RDP Unsigned File Warnings - Disable | Reject | | Removes the warning Microsoft added against malicious `.rdp` files used in phishing. |
| Microsoft Edge - Debloat | Adapt | `privacy.edge-background-off`, Privacy Max preset | Only documented Edge privacy policies; nothing that removes security features. |
| Microsoft Edge - Remove | Reject | | WebView2 apps depend on Edge components, Windows Update reinstalls it, and removal is unsupported. |
| Date & Time - Set Time to UTC | Reject | | `RealTimeIsUniversal` is not supported by Microsoft; configure the Linux side to local time instead. |
| Microsoft OneDrive - Remove | Adapt | Toolkit > Install (uninstall `Microsoft.OneDrive` with winget) | The official uninstaller through winget, with a file warning; reversible by installing it again. WinUtil's permission changes on the OneDrive folder are not used. |
| File Explorer Home and Gallery - Disable | Adopt | `system.explorer-home-gallery-off` | Tier B: the unpin values are undocumented. |
| Visual Effects - Set to Best Performance | Covered | `privacy.reduce-visual-effects` | |
| Disable Reserved Storage | Reject | | Microsoft keeps reserved storage so updates install reliably; disabling it causes failed feature updates on full disks. |
| Storage Sense - Disable | Covered | `storage.storage-sense-weekly` | iG Windows Tuner configures Storage Sense instead of turning it off. |
| Windows AI - Disable And Remove | Adapt | `privacy.ai-features-off` | The documented policies turn Recall, Click to Do and Copilot features off. Removing the CoreAI package by writing an EndOfLife entry is rejected (unsupported servicing hack). |
| Razer Software Auto-Install - Disable | Adapt | `privacy.device-metadata-off` | The documented device-metadata policy instead of deny ACLs on `C:\Windows\Installer\Razer` and driver-search changes. |
| Logitech Download Assistant Auto-Install - Disable | Adapt | `privacy.device-metadata-off`, Manage > Startup | Same policy; startup entries are handled by the persistence inspector. |
| System Tray Notifications & Calendar - Disable | Reject | | Also hides Windows Security and Defender alerts. Session Mode uses Do Not Disturb instead. |
| Adobe URL Block List - Enable | Reject | | Edits the hosts file (project rule: no hosts-file blocking). |
| Right-Click Menu Previous Layout - Enable | Adopt | `system.classic-context-menu` | Tier B: undocumented COM override. |
| IPv6 - Set IPv4 as Preferred | Adopt | `net.prefer-ipv4` | Sets only bit 0x20 and keeps other bits. |
| Teredo - Disable | Adapt | `net.teredo-off` | The documented "Set Teredo State" policy instead of `DisabledComponents`, with the Xbox networking warning. |
| IPv6 - Disable | Reject | Risk Zone `risk.ipv6-disable` | Unsupported by Microsoft; `net.prefer-ipv4` is the alternative. |
| Background Apps - Disable | Covered | `privacy.background-apps-off` | |
| O&O ShutUp10++ - Run | Reject | | Downloads and runs a third-party binary. |
| DNS - Set to | Covered | `net.doh-cloudflare`, `net.doh-quad9`, DNS benchmark | iG Windows Tuner adds DNS over HTTPS and measures resolvers first. WinUtil's list (Google, Cloudflare, Cloudflare malware and family, OpenDNS, Quad9, AdGuard) is not copied; the benchmark accepts any resolver. |

## Tweaks: preferences (WinUtil toggles)

| WinUtil item | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| BSoD Verbose Mode | Covered | `system.bsod-details` | Already derived from WinUtil. |
| System Tray Battery Percentage | Reject | | A direct Settings preference with no tuning value. |
| Dark Theme for Windows | Adopt | `system.dark-mode` | |
| File Explorer File Extensions | Adopt | `system.show-file-extensions` | Security benefit: disguised executables become visible. |
| File Explorer Hidden Files | Adopt | `system.show-hidden-files` | |
| Logon Verbose Mode | Covered | `system.verbose-status` | |
| Microsoft Outlook New Version | Reject | | Office preference, out of scope. |
| Scrollbars Always Visible | Reject | | Accessibility preference in Settings. |
| Multiplane Overlay | Reject | | A driver-specific workaround for flicker on some GPUs (Microsoft does not document `OverlayTestMode` as a setting); it is not a performance tweak. |
| Mouse Acceleration | Covered | `input.pointer-precision-off` | |
| Num Lock on Startup | Adopt | `system.numlock-on-boot` | Tier B: documented only in Microsoft support answers. |
| Window Snapping | Reject | | Settings preference. |
| S0 Sleep Network Connectivity | Reject | | Modern Standby behavior is a laptop policy decision; the Laptop Gamer preset keeps Windows defaults. |
| S3 Sleep | Reject | | `PlatformAoAcOverride` forces S3 on Modern Standby hardware whose firmware may not support it (failed resume). |
| Settings Home Page | Reject | | Settings preference. |
| Start Menu Bing Search | Adopt | `privacy.bing-search-off` | Tier B: undocumented per-user value. |
| Logon Screen Acrylic Blur | Reject | | Cosmetic, no tuning value. |
| Lock Screen - Disable | Reject | | `NoLockScreen` is honored only on Enterprise and Education, and the lock screen hides sign-in prompts. |
| Start Menu Recommendations | Reject | | Relies on setting `IsEducationEnvironment`, which spoofs an education environment. |
| Sticky Keys | Covered | `input.accessibility-hotkeys-off` | |
| Taskbar Centered Icons, Taskbar Search Icon, Taskbar Task View Icon | Reject | | Taskbar preferences in Settings. |
| Game Mode | Covered | `gfx.game-mode` | |
| Enable Long Paths | Adopt | `system.long-paths` | |

## Performance plans

| WinUtil item | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| Ultimate Performance Profile - Enable / Disable | Covered | `power.ultimate-plan` | Hardware-guarded: blocked on laptops and handhelds by the overlays. |

## Features

| WinUtil item | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| .NET Framework (2, 3, 4) | Adopt | Toolkit > Features `feature.netfx3` | .NET 4 is already part of Windows and stays protected. |
| Hyper-V | Adopt | `feature.hyperv` | Pro, Enterprise and Education only. |
| Legacy Media Components (WMP, DirectPlay) | Adapt | `feature.directplay` | Only DirectPlay (older games need it); Windows Media Player legacy is not needed for games. |
| Windows Subsystem for Linux | Adopt | `feature.wsl` | Enables WSL and Virtual Machine Platform. |
| Network File System | Adapt | `feature.nfs-client` | The NFS client only; WinUtil's anonymous UID/GID registry changes are not made. |
| Registry Backup (Daily Task) | Reject | | Creates a scheduled task (project rule: no persistence); iG Windows Tuner snapshots every change instead. |
| Legacy F8 Boot Recovery - Enable / Disable | Reject | | Uses `bcdedit` (project rule: never edit BCD). Advanced startup is reachable with Shift+Restart. |
| Windows Sandbox | Adopt | `feature.sandbox` | Pro, Enterprise and Education only. |
| OpenSSH Server - Enable | Adopt | `capability.openssh-server` | With an attack-surface warning (opens port 22). The OpenSSH client is also listed. |
| CTT PowerShell Profile - Install / Remove | Reject | | Downloads a third-party profile script. |

## Fixes

| WinUtil item | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| NTP Server - Enable | Reject | | Replaces Microsoft's time service with pool.ntp.org; Windows time sync works as shipped. |
| AutoLogon - Run | Reject | | Downloads Sysinternals Autologon and stores a reusable password; `netplwiz` is listed in Panels for users who choose it. |
| Windows Update - Reset | Adapt | `fix.windows-update-reset` | Microsoft's documented component reset (stop services, rename SoftwareDistribution and catroot2, start services), previewed first. No ACL or DLL re-registration steps. |
| Network - Reset | Adopt | `fix.network-reset` | Winsock and TCP/IP reset with a warning about VPN adapters and static IP settings, and a reboot. |
| System Corruption Scan - Run | Adopt | `fix.dism-restorehealth`, `fix.sfc`, `fix.chkdsk-scan` | Three separate fixes, each previewed. |
| WinGet - Reinstall | Adapt | `fix.winget-reregister` | Re-registers the inbox App Installer package; nothing is downloaded. |
| (spec) Store reset, Start/Search reset, WMI verify, icon cache | Added | `fix.store-reset`, `fix.start-reregister`, `fix.wmi-verify`, `fix.wmi-salvage`, `fix.icon-cache-rebuild` | From SPEC-v2, not in WinUtil. |

## Legacy Windows panels

| WinUtil item | Decision | iG Windows Tuner |
|---|---|---|
| Computer Management, Control Panel, Mouse, Network Connections, Power, Printers, Programs and Features, Region, Security and Maintenance, Sound, System Properties, Time and Date, Windows Defender Firewall, System Restore | Adopt | Toolkit > Panels (fixed launchers for inbox tools only) |
| (spec) netplwiz, Device Manager, Services, Event Viewer, Disk Management, Local Group Policy Editor, Firewall with Advanced Security, Task Scheduler, Resource Monitor, Reliability Monitor, System Information, Windows Update settings | Added | Toolkit > Panels |

## Applications (`config/applications.json`, 236 entries)

| Decision | iG Windows Tuner | Reason |
|---|---|---|
| Adapt | Toolkit > Install, `data/toolkit/apps.json` | iG Windows Tuner keeps its own curated list (gaming, streaming, development, utilities, security and sysadmin tools) with its own descriptions, each package id checked with `winget search` on 21 Oct 2026. WinUtil's descriptions are not copied. Installs use winget only (no Chocolatey: its bootstrap is download-and-execute), and winget's source and package agreements are shown before the first install. |

## Inbox apps (`config/appx.json`, 33 entries) and preset `AppxDefault`

| Decision | iG Windows Tuner | Reason |
|---|---|---|
| Adapt | Manage > Apps, Clean Install / Debloat preset | Removal goes through the managed-change path with the protected list: Store, App Installer, Xbox identity, Gaming Services, Xbox TCUI (WinUtil also warns about these), Windows Security, WebView2 and frameworks are never removed. Removal is reversible partially (re-registered or reinstalled from the Store). |

## Presets (`config/preset.json`)

| WinUtil preset | Decision | iG Windows Tuner |
|---|---|---|
| Minimal, Standard | Adapt | Clean Install / Debloat preset (`debloat`): the safe-mapped equivalents of the Standard items. |
| Advanced | Adapt | Not a preset: its extra items are covered, adapted or rejected above. |

## Updates

| WinUtil option | Decision | iG Windows Tuner | Reason |
|---|---|---|---|
| Default Settings | Adopt | Toolkit > Updates "Windows defaults" | Resets the Windows Update items to default (removes the policies). |
| Security Settings | Adapt | `privacy.defer-feature-365`, `privacy.keep-drivers` | The 365-day feature deferral and the driver exclusion as separate, reversible items. The 4-day quality-update deferral is not a catalog item, because catalog items never lower security (it delays security fixes; the 3.0 Windows Update for Business ring presets cover it for administrators). WinUtil's `AUOptions 3` (notify before install) is not set: automatic install keeps security updates on time, and `privacy.update-active-hours` prevents restarts during play. |
| Disable All Updates | Reject | | Security never goes down. Pause updates in Settings (linked from the Updates tab) or defer feature updates instead. |

## Out of scope

- MicroWin (custom ISO building): listed in the README roadmap.
