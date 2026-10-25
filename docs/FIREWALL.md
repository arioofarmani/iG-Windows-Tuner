# Firewall Manager

Security > Firewall shows every rule of the Windows Defender Firewall, explains where each one comes from and what looks risky, and changes rules only after a preview, with a snapshot and Undo. This guide covers the pages and the audit workflow. How rules are classified is in [FIREWALL_CATEGORIES.md](FIREWALL_CATEGORIES.md) (generated from the knowledge base); design decisions are F1 to F9 in [DECISIONS.md](DECISIONS.md).

## What it never does

- It never turns the firewall off and never sets inbound traffic to Allow by default.
- **Core Services** rules (Core Networking, Windows Service Hardening and other rules Windows needs to stay connected, secure and updated) are read-only.
- **Windows rules** are never deleted or edited: they can only be enabled or disabled (Windows turns them back on when a feature needs them).
- **Delete** is offered only for orphaned rules (the program is gone), user-installed and custom rules, always with a confirmation and a snapshot.
- **Group Policy and MDM rules** are read-only and show the managing source.
- **Game, launcher and anti-cheat rules** (Steam/Valve, FACEIT, Vanguard, Easy Anti-Cheat, BattlEye and others in `data\firewall\apps.json`) are never recommended for blocking or disabling; blocking one warns that online play may break.
- **Remote sessions:** while Remote Desktop or WinRM is in use, rules that carry the session cannot be changed, inbound blocks on every port or the remote ports are refused, profile and network-category changes are refused, and any other change is reverted after 60 seconds unless you keep it.
- In **read-only mode** (`-ReadOnly`) every change path is off in the engine itself; the audit, previews and reports still work.

## The pages

| Tab | What it shows |
|---|---|
| **Overview** | Firewall status per profile; how many rules need attention (Critical and High findings) with one *Review* button; *Quick wins* (bloated rules that can be disabled safely for your role) with a preview; a tile per rule group; rules by origin and by direction; the exposure map (ports something is listening on right now and the rules that let traffic in); recent firewall changes with Undo. |
| **Rules** | Every rule in a sortable, filterable list with a group sidebar (Core Services, Windows Connections, User Installed, Custom Rules, Inbound, Outbound, Blocked, Bloated, Security Risks) and saved views. Chips filter by severity, *Exposed now*, conflicts, low confidence and each risk rule. The details pane explains the rule in plain words: where it comes from and why, the confidence, each finding with the recommended fix and alternatives, conflicts with other rules and its change history. |
| **Live connections** | Current TCP connections and UDP endpoints with the program, its services and the rule that applies (read-only, on request). |
| **Compared to Windows defaults** | Default rules of this Windows build that were removed or changed, and rules that were added. The default set comes from the read-only SystemDefaults store; a baseline exported in Windows Sandbox is the fallback. |
| **Profiles and networks** | Per profile: on/off, default actions, notifications, logging; Private or Public per connected network. Changes only move toward protection. |

## Audit workflow

1. **Open the Overview.** The status line and the *needs attention* card say what matters first. Nothing is changed by looking.
2. **Check the role.** Bloat depends on what the PC is for (Gaming PC, Power user, Sysadmin, Workstation); the role is set in the Firewall Manager and stored per user.
3. **Review the findings.** *Review N findings* opens the Rules tab filtered to Critical and High. For each rule the details pane gives the plain-language risk, the least invasive fix and alternatives. *Ignore for 90 days* (with a reason) hides a finding you accept; *Move to category* and *Not bloated for me* correct the classification. These choices are your own file and can be exported (*Export my choices...*).
4. **Fix in one go with the smart fix wizard** (or the quick wins preview): one step per kind of finding, your choice per step, then a preview that lists every rule that will change and every rule that is skipped and why. Changes run in batches; each batch writes a snapshot first and can be undone. If a batch fails, is undone or is reverted by the remote-session timer, the remaining batches do not run.
5. **Or apply a firewall scope.** *Firewall scope...* offers presets for a Gaming PC, a Workstation, a Public Wi-Fi laptop and a hardened sysadmin PC (`data\firewall\scopes.json`). Each shows its preview first; the built-in tweak presets name a matching scope but never apply it with the tweaks.
6. **Keep a record.** *Audit report* exports the audit as HTML, CSV or JSON (counts, findings, recommendations). A report from this PC lists its installed programs, so keep it private.
7. **Undo anything** from the toast, the Overview's recent changes or Backups & Logs.

## New rules

*New rule...* starts a wizard with scenario templates (game server, LAN file sharing, local web development, block a program and more; `data\firewall\templates.json`). Before anything is created, the risk rules check the new settings, for example "Critical: inbound allow for any program, any port, from anywhere". Rules the tuner creates carry the group "iG Windows Tuner" and a marker in their description.

## Command line and engine

Everything the page shows comes from read-only engine functions, for example:

```powershell
Import-Module .\src\iGWindowsTuner.psd1
$a = Get-IgwtFirewallAudit -Role Gamer          # classification, findings, conflicts, exposure, summary
$a.Summary.QuickWins
Get-IgwtFirewallScopePlan -Scope gaming-pc -Rows $a.Rules   # preview only
Export-IgwtFirewallAuditReport -Path .\firewall-audit.html
```

Changes go through `Invoke-IgwtFirewallChange` only (snapshot operation `Firewall`, revert with `Invoke-IgwtRevert`), which classifies the rules itself and applies every lock above.

## Performance

Measured on the 1,030-rule synthetic fixture (tests): classification under 1 s once cached, the full audit plus a scope plan about 5 s, the defaults comparison and matching 500 connections under 2 s. On the test PC (692 rules, read-only, not elevated) the audit took 7.9 s cold and 3.4 s warm in the background worker.
