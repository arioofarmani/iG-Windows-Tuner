# iG Windows Tuner

**An auditable, reversible Windows 11 tuner for competitive gaming that keeps your PC secure and your anti-cheat happy.**

![Version](https://img.shields.io/badge/version-3.0-0078D4)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.4-5391FE)
![Tests](https://img.shields.io/badge/Pester-762%20passing-2EA44F)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-preview-orange)

## Why this exists

Most "gaming optimizer" scripts make the same trade: paste a few hundred registry edits from a forum, disable Defender, Windows Update and virtualization-based security, and hope the frame rate goes up. The result is often placebo, sometimes slower, frequently less secure, and increasingly incompatible with kernel anti-cheat (Riot Vanguard, FACEIT, Easy Anti-Cheat, BattlEye, RICOCHET, Javelin), which now *requires* TPM 2.0, Secure Boot, VBS and HVCI.

iG Windows Tuner takes the opposite approach:

- **Evidence first.** Every change is documented by Microsoft or the hardware vendor (Tier A), or is real but situational and clearly marked "measure before and after" (Tier B). Popular tweaks that are placebo, obsolete or harmful are not hidden. They are listed with the reason they were rejected, and the reversible ones can be applied at your own risk from the **Risk Zone**, with a clear warning of what each one turns off or on.
- **Everything is reversible.** Before anything changes, the exact previous value (including its type, or the fact that it did not exist) is written to a JSON snapshot, and a System Restore point is created. Any change can be reverted individually or all at once.
- **Security goes up, not down.** Defender, the firewall, UAC, SmartScreen, Windows Update, VBS/HVCI and Secure Boot are never weakened. The tool includes hardening such as attack surface reduction rules, LSA protection and encrypted DNS.
- **Anti-cheat compatible by design.** Nothing that anti-cheat depends on is touched, and readiness for each major anti-cheat is checked and shown.
- **Transparent.** Every registry path, service, power setting and policy is shown as "current -> target" before you apply anything. Nothing is downloaded, obfuscated or hidden.

## What it does

| Area | Highlights |
|---|---|
| **Presets** | Ten presets (Competitive, Balanced, Hardened, Streamer & Creator, Engineer Workstation, Laptop Gamer, Privacy Max, Clean Install / Debloat, Fortress and a temporary Session Mode for match days), adjusted automatically to your hardware. Build your own custom presets, export and import them with an integrity check, and see what drifted since you applied one. |
| **Tweak catalog** | 127 verified items across Power & CPU, Graphics & Display, Input, Network, Background & Privacy, Security, Storage and System, each with a hint, a description, sources and a revert path. |
| **Health report** | Read-only checks of firmware, microcode, Secure Boot, VBS/HVCI, GPU (Resizable BAR, refresh rate), network adapter, storage and an anti-cheat readiness score. HTML export. |
| **ASR Center** | All 19 Microsoft Defender attack surface reduction rules with modes, gamer-impact notes, per-rule exclusions and an audit view of what each rule blocked. |
| **Security score** | 25 weighted checks, each with the exact fix, plus a local accounts audit and a listening-ports report. |
| **Expert inspectors** | Power plan (hidden processor settings included), interrupts and MSI mode, network queues, kernel and memory values, timer, crash dumps, all next to their Windows defaults. |
| **Cleaner** | Allow-list rules for temp files, caches and logs with a scan that deletes nothing, plus a disk analyzer and Storage Sense policies. |
| **Manage** | Services with a safe-to-change rating, scheduled tasks, apps, an Autoruns-style persistence inspector with signature checks, and a firewall rule browser. |
| **Toolkit** | Inspired by WinUtil and re-implemented with documented sources: a curated winget app installer, Windows features (WSL, Hyper-V, Sandbox, .NET 3.5), previewed repair fixes (SFC, DISM, Windows Update and network reset), classic panels and Windows Update deferrals. |
| **Diagnostics** | DPC/ISR time, reliability history, crashes and minidumps, boot performance, driver inventory, Windows Update status, DNS benchmark, latency and jitter test, and a full system report. |
| **Gaming network optimizer** | Measures latency, jitter and loss to your router, your ISP, internet anchors and your game server, applies the Windows network settings and registry values that lower latency and jitter on that connection (with a snapshot), checks that the network still works and reverts automatically if not, then measures again and shows before and after. |
| **Group Policy engine** | Every installed Administrative Template policy with search, effective state and source (Local GPO, domain, MDM) and tattoo detection. Writes the Local GPO like gpedit (Registry.pol, gpt.ini, gpupdate, verification) with backup, restore and reset. Policy items of the catalog now also land in the Local GPO. |
| **Security policy & auditing** | Account policies, user rights and security options (secedit) and advanced audit policy (auditpol) with backups and lockout safeguards that refuse anything that would lock you or the administrators out. |
| **Policy presets & baselines** | 18 category presets (privacy, Windows Update rings, Defender, attack surface, Edge, credentials, remote access, removable media, audit and logging, firewall logging, kiosk, developer, secure gaming), import and compare of Security Compliance Toolkit baselines, and export as LGPO-style GPO folder, .reg, script or JSON. |
| **Defender & Security Control Center** | Defender status and every setting with who manages it, an exclusions audit that flags risky exclusions (removal only), threat history, scans, Network Inspection parsers (only ever turned on), web and phishing protection, detection logging and a firewall log analyzer. |

The WPF interface follows the Windows 11 design language and starts **read-only**. It asks for administrator rights through the normal UAC prompt only when you choose to apply something.

## Quick start

Requirements: Windows 11 Pro 24H2 or newer (build 26100+), and Windows PowerShell 5.1, which is built in. PowerShell 7.4 also works. No installation and no dependencies.

1. Download or clone this repository.
2. Double-click **`Start-iGWindowsTuner.cmd`** to open the GUI. It starts in read-only mode.

Or use the command line (read-only commands need no elevation):

```powershell
.\iGWindowsTuner.ps1 -Report                      # health and anti-cheat readiness
.\iGWindowsTuner.ps1 -ListTweaks                  # every item with its tier, risk and current state
.\iGWindowsTuner.ps1 -Preset Competitive -DryRun  # exactly what a preset would change; changes nothing
.\iGWindowsTuner.ps1 -SecurityScore               # security score with the fix for each finding
.\iGWindowsTuner.ps1 -NetworkOptimize -DryRun     # measure the connection and show the gaming network plan
.\iGWindowsTuner.ps1 -DefenderCenter All          # Defender & Security Control Center
```

Optimize the network for gaming (measures, applies, verifies, measures again; add your game server with `-NetTarget`):

```powershell
.\iGWindowsTuner.ps1 -NetworkOptimize -Duration Standard -NetTarget eu.example-game-server.net
```

Changes are applied and undone like this (each one writes a snapshot first):

```powershell
.\iGWindowsTuner.ps1 -Preset Balanced
.\iGWindowsTuner.ps1 -Revert input.pointer-precision-off
.\iGWindowsTuner.ps1 -RevertAll                   # undo the most recent apply
```

If you downloaded a zip, Windows marks the files as coming from the internet. Review them, check them against `SHA256SUMS.txt`, and then unblock them (`Get-ChildItem -Recurse | Unblock-File`).

## What it never does

Not even from the Risk Zone:

- Edit BCD, enable test signing, disable driver signature enforcement, or turn off DEP, ASLR or CFG.
- Touch Secure Boot, TPM, firmware, voltages, power limits or anti-cheat services, or install drivers.
- Disable Defender, Tamper Protection, AMSI, ETW, the firewall, UAC, SmartScreen or Windows Update, or add antivirus exclusions.
- Create persistence (scheduled tasks, services, Run keys, WMI subscriptions), hide windows, download anything, or change your execution policy.

These rules are enforced by a static safety test suite that runs against the source code.

## How it is built

- **Data-driven.** The catalog lives in `data\*.json` (tweak files use schema v3). The engine dispatches typed actions (registry, service, power plan, firewall, QoS, scheduled task, and more), and each action type implements detect, snapshot, apply and restore.
- **Plain PowerShell.** It is readable, modular and has comment-based help on every function. It uses one documented P/Invoke (`SystemParametersInfo`) and no compiled binaries.
- **Tested.** 762 Pester tests run against Pester's `TestRegistry:` drive and mocks only, so the suite never touches the real system. PSScriptAnalyzer reports zero findings, and a Microsoft Defender scan runs as part of the quality checks (`tools\Invoke-QualityChecks.ps1`).
- **Safe end-to-end testing.** `tools\New-SandboxConfig.ps1` generates a Windows Sandbox configuration that runs a full apply and revert cycle in a disposable VM.

## Documentation

| Document | Content |
|---|---|
| [docs/README.md](docs/README.md) | Full user guide: CLI options, exit codes, GUI, files and troubleshooting |
| [docs/TWEAKS.md](docs/TWEAKS.md) | Every item with its exact changes, evidence and sources |
| [docs/PRESETS.md](docs/PRESETS.md) | Preset contents and rules |
| [docs/REJECTED_TWEAKS.md](docs/REJECTED_TWEAKS.md) | Popular tweaks that were rejected, why, and which ones the Risk Zone offers |
| [docs/ANTICHEAT.md](docs/ANTICHEAT.md) | Anti-cheat requirements and compatibility |
| [docs/SECURITY.md](docs/SECURITY.md) | Engineering and safety rules |
| [docs/ASR_CENTER.md](docs/ASR_CENTER.md), [docs/INSPECTORS.md](docs/INSPECTORS.md), [docs/HARDWARE.md](docs/HARDWARE.md), [docs/CLEANER.md](docs/CLEANER.md) | Module references |
| [docs/CLI.md](docs/CLI.md), [docs/EXPERT_LAB.md](docs/EXPERT_LAB.md) | Command-line reference; levels, gates and expert controls |
| [docs/GROUP_POLICY.md](docs/GROUP_POLICY.md) | Group Policy engine, security policy and auditing, policy presets, baselines and exports |
| [docs/DEFENDER_CENTER.md](docs/DEFENDER_CENTER.md), [docs/NETWORK_IDS_IPS.md](docs/NETWORK_IDS_IPS.md) | Defender & Security Control Center; what the endpoint adds to a network IDS/IPS |
| [docs/NETWORK_GAMING.md](docs/NETWORK_GAMING.md) | Gaming network optimizer: what it measures, the rules it follows, and how to undo it |
| [docs/WINUTIL_MAPPING.md](docs/WINUTIL_MAPPING.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | How each WinUtil item was adopted, adapted or rejected; credits |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Design decisions and their reasons |
| [docs/TESTING.md](docs/TESTING.md) | Test suite, Sandbox test and measurement plan |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Release notes |

## Project status

This is version **3.0** (preview). It adds the Group Policy engine, security policy and auditing, category policy presets with baselines and exports, the Defender & Security Control Center and the gaming network optimizer, all covered by tests. The new 3.0 features are available on the command line; the GUI shows the 2.x features.

Run the read-only commands and `-DryRun` first, and review what a change does before you apply it.

## Contributing

Contributions are welcome, provided they follow the evidence rule: a new item needs a current Microsoft or vendor source (or a Tier B "measure" label), a hint, a description, a revert path and tests. Read [CONTRIBUTING.md](CONTRIBUTING.md), then run `tools\Invoke-QualityChecks.ps1` before opening a pull request.

## License

[MIT](LICENSE). iG Windows Tuner is provided as is, without warranty. You are responsible for the changes you apply to your system; every change can be reverted with the built-in snapshots.
