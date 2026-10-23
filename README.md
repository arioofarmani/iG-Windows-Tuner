# iG Windows Tuner

**An auditable, reversible Windows 11 tuner for competitive gaming that keeps your PC secure and your anti-cheat happy.**

![Version](https://img.shields.io/badge/version-3.0-0078D4)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.4-5391FE)
![Tests](https://img.shields.io/badge/Pester-782%20passing-2EA44F)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-preview-orange)

iG Windows Tuner

Evidence-based Windows 11 tuning. Transparent changes. Reversible by design.

iG Windows Tuner is an open-source Windows 11 utility for managing system performance, security, privacy, gaming settings, and advanced Windows configuration.

Built with PowerShell and WPF, it combines curated presets with detailed system controls, security auditing, diagnostics, and configuration management.

Unlike one-click optimization tools, iG Windows Tuner shows what a change does, why it exists, and how to undo it.

Why iG Windows Tuner?
Evidence-based tuning — Settings are documented with Microsoft or hardware-vendor sources, or clearly identified as requiring measurement.
Reversible changes — Previous configuration values are captured before supported changes are applied, with individual and bulk rollback options.
Security-focused — Security controls are designed to strengthen or preserve protection rather than sacrifice it for speculative performance gains.
Gaming-aware — Includes competitive gaming presets and checks for important kernel anti-cheat prerequisites.
Full transparency — Review current and proposed values before applying changes.
Built-in diagnostics — Inspect system health, security configuration, network performance, and Windows reliability.
No forced changes on launch — The graphical interface starts in read-only mode.
What can you do?
Performance and gaming

Explore CPU, power, graphics, input, and network settings. Compare measured results instead of assuming every tweak improves performance.

Security and privacy

Audit Windows security settings, review Microsoft Defender configuration, manage privacy policies, and inspect potential security weaknesses.

Presets and configuration

Choose from curated profiles for different workloads, create custom presets, and review configuration changes before applying them.

Diagnostics and system management

Generate system health reports, inspect services and scheduled tasks, review firewall rules, troubleshoot Windows, and examine network latency and reliability.

Advanced Windows administration

Explore Group Policy, security policies, Defender controls, compliance baselines, and configuration exports.

Quick start

Requirements

Windows 11 Pro 24H2 or newer (build 26100+).
Windows PowerShell 5.1, included with Windows. PowerShell 7.4 is also supported.
No additional dependencies are required.

Run the application

Download or clone this repository.
Run Start-iGWindowsTuner.cmd.
Review the interface and inspect your current settings.
Choose a preset or individual setting.
Review the proposed changes before applying them.

The graphical interface starts in read-only mode. Administrator privileges are requested through Windows UAC when needed to apply changes.

Before applying changes

System tuning can affect stability, security, and application compatibility.

Review each proposed change before approving it.
Start with read-only reports and -DryRun commands.
Create a backup and a Windows restore point before significant changes.
Measure performance before and after tuning.
Verify that your games, applications, and security requirements still work as expected.

The built-in snapshots and rollback features help restore supported configuration changes, but they are not a substitute for a complete backup.

Project status

Version 3.0 — Preview

The command-line interface includes newer Group Policy, security auditing, Defender management, and gaming network optimization features. The graphical interface currently exposes the 2.x feature set.

Some features and workflows are still evolving. Review the documentation before relying on the tool for production or security-critical systems.

Documentation
User guide
Tweak catalog and evidence
Preset guide
Anti-cheat compatibility
Security and design principles
Rejected tweaks and their rationale
Testing methodology
Changelog
Contributing

Contributions are welcome. New tweaks should include supporting evidence, a clear explanation, risk information, a rollback path, and appropriate tests.

See CONTRIBUTING.md to get started.

License

Released under the MIT License.

Provided as-is, without warranty. Review changes carefully and use the tool at your own risk.
