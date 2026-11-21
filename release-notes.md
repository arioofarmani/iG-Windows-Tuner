# iG Windows Tuner 4.0.0

Released 2026-11-21. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

The redesign release. The window is rebuilt around seven sections, and every change, from any page, is applied from one bar at the bottom.

### New

- **Seven sections instead of 24 pages:** Home, Play, Optimize, Network, Security, Clean and History, plus Advanced tools and Settings. Old page links still open the right place.
- **Home** shows the one thing that needs you, three status tiles, and your recent changes with Undo.
- **Optimize** is one list with category chips and a details panel. Each setting shows its evidence, anti-cheat status and whether it can be undone.
- **History** shows what iG changed as session cards. Undo checks every value first and asks when something else changed it since. "Reset everything iG changed" is one click away.
- **Security** has four tabs: Overview, Protection (Defender and attack surface rules), Firewall and Policies. Changes are staged and applied like tweaks.
- **Network** shows your DNS servers (encrypted or not, with a benchmark), the network profile with a switch, and the programs your firewall blocks.
- **Clean** has four tabs: Files, Startup apps, Registry leftovers and Disk.
- **Settings** is a page now. **Advanced tools** open on an overview that explains each tool.
- A new look: design tokens checked for contrast, dark, light and High Contrast themes, and a focus ring on every control.

### Fixed

- Every Medium finding of the 3.8.1 review is fixed, except one kept by design with its reason (resetting to the Windows default does not ask the risk question). Among them:
  - security policy values with line breaks are refused, and the evidence export no longer keeps your public IP address;
  - Defender changes that Tamper Protection or a policy blocks are no longer shown as done;
  - undoing removes no longer tries to reinstall apps, and SMB1 comes back with its client and server parts;
  - the registry cleaner no longer offers settings keys of installed programs;
  - a PC onboarded to Microsoft Defender for Endpoint is treated as managed.
- Changing the theme could freeze the window.
- Staging a preset no longer replaces the changes you staged by hand without asking.

### Good to know

- Tested with the full headless suite, the offscreen render suite in every theme at 100, 150 and 200 %, the UI Automation suite on the real window, and ten real change-and-undo round trips on a Windows 11 PC (tweak, policy, firewall, ASR, Defender, audit, Session Mode, startup, registry leftover, conflict handling).
- Settings, backups and the change journal from 3.x are kept and read by 4.0.
- Full list: docs\CHANGELOG.md. Design notes: docs\DECISIONS.md.
