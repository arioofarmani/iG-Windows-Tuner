# Anti-cheat compatibility

iG Windows Tuner must never break kernel-level anti-cheat. This page records the current platform requirements (verified during development on 16 Oct 2026), how iG Windows Tuner detects them, and the rules that follow from them.

## Requirements by anti-cheat

| Anti-cheat | TPM 2.0 | Secure Boot | VBS | HVCI | IOMMU / DMA protection | Windows | Notes |
|---|---|---|---|---|---|---|---|
| **FACEIT AC** (CS2) | Required | Required | Required (waves) | - | Required (waves) | Windows 11 from 14 Oct 2026 | TPM 2.0 and Secure Boot have been mandatory for all players since 25 Nov 2025. IOMMU and VBS were rolled out in waves (limited rollout from April 2025; required above 3,000 Elo from August 2025). FACEIT says VBS is required for IOMMU to work reliably. |
| **Riot Vanguard** (VALORANT, LoL), classic | Required on Windows 11 | Required on Windows 11 | - | - | - | - | Vanguard's own error codes (VAN 9001/9003) enforce TPM 2.0 and Secure Boot on Windows 11. |
| **Riot Vanguard On-Demand mode** (optional) | Required | Required | Required | Required | Required | Windows 11 **25H2+** | Uses the Runtime Driver Attestation Report that ships with 25H2. VGTray's Pre-Check lists anything still missing. |
| **Call of Duty** (RICOCHET) | Required | Required | - | - | - | - | Mandatory since Black Ops 7. |
| **Battlefield 6** (Javelin) | Required | Required | - | - | - | - | Kernel-level anti-cheat. |
| **Easy Anti-Cheat / BattlEye** | - | Per game | - | - | - | - | No platform-wide requirement. Test signing and kernel debugging are refused. |
| **VAC** (Dota 2, CS2) | - | - | - | - | - | - | User-mode anti-cheat with no platform requirement. |

Sources:

- FACEIT: <https://support.faceit.com/hc/en-us/articles/23117181142556> (Windows security requirements FAQ), <https://support.faceit.com/hc/en-us/articles/22851956652956-Known-issues-with-Anti-Cheat-Requirements>. Both blocked automated download (HTTP 403), so their content was verified through search results and news coverage. The Windows 10 cut-off date (14 Oct 2026) comes from secondary coverage, for example <https://www.dust2.us/news/66964/faceit-announces-major-anti-cheat-update>.
- Riot Vanguard On-Demand: <https://support.riotgames.com/en-us/riot/support-tools/vanguard-pre-check> (fetched; lists Windows 11 25H2 or newer, Secure Boot, TPM 2.0, IOMMU, VBS, HVCI), plus <https://www.tomshardware.com/video-games/pc-gaming/riot-vanguard-adds-an-on-demand-mode-that-stops-anti-cheat-loading-at-boot-on-secured-windows-11-pcs>.
- Call of Duty and Battlefield 6: <https://www.guru3d.com/story/call-of-duty-black-ops-7-system-requirements-tpm-20-and-secure-boot>, <https://www.thesixthaxis.com/?p=462600>.
- VBS, HVCI and DMA properties: <https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity>.

## How iG Windows Tuner detects readiness (read-only)

| Requirement | Detection |
|---|---|
| TPM 2.0 ready | Elevated: `Get-Tpm` (present/ready) plus the `Win32_Tpm` spec version. Not elevated: the "Trusted Platform Module 2.0" PnP device and its status (labelled "presence only"). |
| Secure Boot on | `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`; `Confirm-SecureBootUEFI` when elevated. |
| Secure Boot 2023 certificates | `...\SecureBoot\Servicing\UEFICA2023Status` (`Updated`), `WindowsUEFICA2023Capable` (2 = booting the 2023-signed boot manager), `UEFICA2023Error`. Elevated runs also check that `db` contains "Windows UEFI CA 2023" and `KEK` contains "KEK 2K CA 2023". Microsoft Windows Production PCA 2011 expires on **19 Oct 2026**, and the report flags this prominently. iG Windows Tuner never triggers certificate deployment (`AvailableUpdates`); it points to Windows Security > Device security > Secure Boot. |
| VBS running | `Win32_DeviceGuard.VirtualizationBasedSecurityStatus = 2` |
| HVCI running | `Win32_DeviceGuard.SecurityServicesRunning` contains 2 |
| IOMMU / Kernel DMA protection | `Win32_DeviceGuard.AvailableSecurityProperties` contains 3 ("DMA protection is available"). msinfo32's "Kernel DMA Protection" line gives a second confirmation. |
| Windows 11 / 25H2+ | Build >= 22000 / >= 26200 |
| No test signing / kernel debugging | `HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions` (read only; BCD is never read or written) |

The **Dashboard** shows each requirement plus a per-anti-cheat pass/fail matrix. The header pill is:

- **Green**: everything passes, including Vanguard On-Demand prerequisites and the 2023 certificates.
- **Amber**: the kernel anti-cheats work, but an optional mode or the 2023 certificates are missing.
- **Red**: a hard requirement fails (TPM, Secure Boot, or test signing active).

A typical current gaming PC (Intel 13th gen on Z690, Windows 11 Pro 26H2) shows **Green**: TPM 2.0 present, Secure Boot on, 2023 certificates applied (`Updated`, capable = 2), VBS and HVCI running, DMA protection available.

## Rules enforced in code

- The classic "disable VBS / Memory Integrity for FPS" tweak is **excluded from every preset** (enforced by `Test-IgwtCatalog` and the Pester suite). It exists only as the expert toggle `sec.vbs-hvci-off-expert`. That toggle needs `-AcknowledgeRisk` on the CLI or a confirmation dialog in the GUI, and shows a red warning that names FACEIT and Vanguard.
- Every catalog entry declares `antiCheatSafe`. A tweak that is not anti-cheat safe must be an expert toggle with a warning, and may not appear in a preset.
- Services `vgc`, `vgk`, `FACEIT*`, `EasyAntiCheat*`, `BEService`, `BEDaisy` and the core security services are on a hard deny-list in the service action, so the engine throws even if a catalog entry tried to change them.
- No BCD access, test signing, driver signature changes, kernel debugging, DEP/ASLR/CFG changes, Secure Boot or TPM changes, driver installs, or game process/file access. Static tests in `tests\Safety.Tests.ps1` scan the shipped source for these.
- `sec.hvci-on` (Tier A, in every preset) keeps memory integrity on; its "reset to Windows default" is also on.
- Kernel-mode hardware-enforced stack protection (`sec.kernel-shadow-stacks`) is a manual Tier B toggle, because some older anti-cheat drivers were incompatible with it.
