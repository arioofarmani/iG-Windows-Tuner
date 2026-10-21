# iG Windows Tuner

iG Windows Tuner is an auditable PowerShell + WPF toolbox that tunes **Windows 11 Pro (24H2 / 25H2 / 26H2, builds 26100 / 26200 / 26300)** for competitive online gaming (lower input and network latency, steadier frametimes) while keeping or **raising** security, and without breaking kernel anti-cheat (FACEIT, Riot Vanguard, Easy Anti-Cheat, BattlEye, RICOCHET, Javelin).

Every change is:

1. **Proven**: documented by Microsoft or the vendor (Tier A), or real but situational and marked "measure before/after" (Tier B). Popular placebo tweaks are listed with the reason on the *Rejected Tweaks* page ([REJECTED_TWEAKS.md](REJECTED_TWEAKS.md)).
2. **Reversible**: a JSON snapshot of the exact previous value, including its type and "the value did not exist", is written before anything changes. A System Restore point is created too.
3. **Compatible**: detected at runtime. Nothing that anti-cheat needs (TPM, Secure Boot, VBS, HVCI, IOMMU) is ever touched.
4. **Transparent**: the GUI and `-DryRun` show every registry path and value (current -> target) before applying.

## Requirements

- Windows 11 Pro, build 26100 or newer (older builds are refused).
- Windows PowerShell 5.1 (inbox). PowerShell 7.4+ also works.
- No downloads and no dependencies. Pester and PSScriptAnalyzer are needed only for development.

## Quick start

All read-only commands work without elevation:

```powershell
# Health and anti-cheat readiness report (read-only); optionally save it as HTML
.\iGWindowsTuner.ps1 -Report
.\iGWindowsTuner.ps1 -Report -ReportPath .\report.html

# Every tweak with its tier, risk, presets and current state
.\iGWindowsTuner.ps1 -ListTweaks

# What a preset would change (prints the full diff, changes nothing)
.\iGWindowsTuner.ps1 -Preset Competitive -DryRun

# GUI (double-click Start-iGWindowsTuner.cmd, or:)
.\Start-iGWindowsTuner.cmd
```

The commands that change the system request elevation through the normal UAC prompt:

```powershell
.\iGWindowsTuner.ps1 -Preset Balanced                 # restore point + snapshot, then apply
.\iGWindowsTuner.ps1 -Apply gfx.windowed-optimizations,input.pointer-precision-off
.\iGWindowsTuner.ps1 -Revert input.pointer-precision-off
.\iGWindowsTuner.ps1 -RevertAll                       # revert the most recent apply
.\iGWindowsTuner.ps1 -RevertAll -Snapshot "C:\ProgramData\iGWindowsTuner\Backups\snapshot-....json"
.\iGWindowsTuner.ps1 -ResetDefault gfx.hags           # documented Windows default
```

Options: `-DryRun`, `-SkipRestorePoint` (the JSON snapshot is still written), `-EnableSystemProtection` (consent to turn on System Protection for C: when it is off), `-AcknowledgeRisk` (required for expert toggles), `-Json` (machine-readable output), `-NoGui`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error |
| 2 | Invalid arguments, unknown tweak id, conflicting selection, or an expert toggle without `-AcknowledgeRisk` |
| 3 | Elevation declined |
| 4 | Preflight refused (build older than 26100, or System Protection off without consent) |
| 5 | One or more tweaks failed and were rolled back |
| 6 | Nothing to revert |
| 3010 | Success; a reboot is required |

## Presets

| Preset | Purpose |
|---|---|
| **Competitive** | Every Tier A performance, input and network item, plus the Tier B latency items. The security baseline (Defender, VBS/HVCI, ASR baseline, LSA protection, firewall) stays fully on. |
| **Balanced** | Recommended daily driver: Tier A performance plus Tier A security and privacy. No Tier B. |
| **Hardened** | Balanced plus encrypted DNS (Quad9), AI features off, Office/Adobe ASR rules in Block mode, Controlled Folder Access audit, UAC always-notify, NetBIOS/RDP/Remote Assistance off, PowerShell script block logging, unused Wi-Fi off. Still compatible with competitive anti-cheat. |

The full lists are in [PRESETS.md](PRESETS.md), and every tweak with its exact changes and sources is in [TWEAKS.md](TWEAKS.md). Both are generated from the catalog by `tools\Build-Docs.ps1`.

## GUI

- A dark Windows 11-style window (minimum 1100x720) with icons from the inbox Segoe Fluent Icons font.
- **Header**: hardware summary, OS build, admin badge, and an anti-cheat readiness pill (green, amber or red).
- **Pages**: Dashboard (health), Presets, Power & CPU, Graphics & Display, Input, Network, Background & Privacy, Security, Startup Apps, Backups & Logs, Rejected Tweaks, About.
- **Toggles** always show the real current state. Toggling only stages a change. The bottom bar shows `N pending - Preview - Apply - Discard`, and Preview is a dry-run diff.
- **Details pane**: description, exact changes (current -> target), clickable sources, how to revert, and "reset to Windows default".
- **Search and filters**: text, tier, risk, needs restart, changed from default. Shortcuts: Ctrl+F to search, F5 to refresh.
- **Background work**: all long operations run in a background runspace, so the window never freezes. A collapsible log console shows progress.
- **Read-only start**: the GUI starts read-only. Applying requires "Restart as administrator", which uses the normal UAC prompt.

## What iG Windows Tuner never does

- Edit BCD (there is no `bcdedit` anywhere), enable test signing, disable driver signature enforcement, enable kernel debugging, or disable DEP/ASLR/CFG.
- Touch Secure Boot, TPM, firmware, voltages, power limits or CPU C-states, or install drivers.
- Touch game processes or files, or anti-cheat services (vgc/vgk, FACEIT, EasyAntiCheat, BEService).
- Disable Defender, Tamper Protection, AMSI, ETW, the firewall, UAC, SmartScreen or Windows Update, or add Defender exclusions.
- Create persistence (scheduled tasks, services, Run keys, WMI subscriptions), hide windows, download anything, or change the machine or user execution policy.

See [SECURITY.md](SECURITY.md) for the full engineering rules and [ANTICHEAT.md](ANTICHEAT.md) for anti-cheat requirements.

## Files and folders

| Path | Content |
|---|---|
| `%ProgramData%\iGWindowsTuner\Backups` | JSON snapshots (one per apply, revert, reset or startup change) |
| `%ProgramData%\iGWindowsTuner\Logs` | `iGWindowsTuner-yyyyMMdd.log` (text) and `.jsonl` (JSON lines). Read-only runs log to `%LOCALAPPDATA%\iGWindowsTuner\Logs` |
| `%ProgramData%\iGWindowsTuner\State` | `pending-restart.json` (drives the restart banner) |
| `%ProgramData%\iGWindowsTuner\Reports` | HTML reports exported from the GUI |

The data folder gets an ACL that grants write access to SYSTEM and Administrators only, so a standard user cannot plant snapshots that an elevated revert would trust.

## Project layout

```
iGWindowsTuner.ps1              entry point (CLI + GUI), elevation relaunch
Start-iGWindowsTuner.cmd        double-click launcher (process-scope execution policy only)
src/                       module: Core (engine, snapshot, restore point, preflight, logging),
                           Actions (one file per action type), Health (read-only checks), Gui (XAML + code)
data/tweaks/*.json         the catalog (single source of truth)
data/presets/*.json        Competitive, Balanced, Hardened
data/games.json            game executables and discovery hints (Dota 2 first)
data/rejected.json         documented but not implemented
data/schema/               JSON schema for tweak files
tests/                     Pester 5 suite (TestRegistry + mocks only)
tools/                     Build-Docs, Test-Catalog, Invoke-QualityChecks, Sign-Toolbox, New-Release,
                           New-SandboxConfig + Invoke-SandboxTest (Windows Sandbox end-to-end test)
docs/                      this documentation
```

## Troubleshooting

- **"running scripts is disabled"**: use `Start-iGWindowsTuner.cmd`. It passes `-ExecutionPolicy Bypass` to that one PowerShell process only.
- **Files downloaded as a zip**: Windows marks them as coming from the internet. Review the files, verify `SHA256SUMS.txt`, then run `Get-ChildItem -Recurse | Unblock-File` if you trust them.
- **A tweak shows "Managed by policy"**: Group Policy or MDM controls that setting, so iG Windows Tuner will not fight it.
- **"Not verified" after apply**: Windows or Tamper Protection refused or rewrote the value. iG Windows Tuner reports it instead of working around it.
- **Undo everything**: Backups & Logs > Revert last apply, or `.\iGWindowsTuner.ps1 -RevertAll`. The System Restore point created before each apply is a second safety net.
