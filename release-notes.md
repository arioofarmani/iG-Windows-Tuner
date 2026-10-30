# AegisTune (iG Windows Tuner) 3.5.0

Released 2026-10-30. Windows 11 (build 26100 or later), Windows PowerShell 5.1.

Firewall logs and forensics: the firewall log analysis works again (two bugs fixed), a fast log reader with filters and an overview, time-boxed forensic connection logging that restores every setting exactly, and evidence collection with an AI-ready export. Verification sources: DECISIONS F10 to F13; independent review: docs\REVIEW.md.

### Fixed

- **"Analyze the firewall log" failed on every real log** with "Cannot bind argument to parameter 'Lines' because it is an empty string": Windows writes an empty line after the `#Fields:` header, and the parser refused empty lines. The log is now read with a streaming reader that opens it shared with the firewall service (read, write and delete sharing), takes the columns from the file's own `#Fields:` header, reads the rotated `.old` file when there is one, skips a last line that is still being written, and reports skipped lines by reason.
- **Clear messages instead of "not found":** without administrator rights the log was reported as missing ("turn on logging first"), because the existence check returns false for a file you may not read. The analysis now says what is wrong and what to do: administrator rights needed, logging off for a named profile, the log not written yet, a missing custom log folder (with the service account that needs write access), or the file locked by another program.
- **"Something went wrong (window): You cannot call a method on a null-valued expression"** appeared about 10 seconds after any change that showed a message at the bottom right (for example a firewall or profile change): the message's close timer could not reach the window. Fixed, a test now checks every handler of that kind, and errors of this kind now record the script line in the log.
- **Forensic logging, Start while a session runs** (found by Ario on 2026-10-30): the error said the settings were restored and showed a raw "Exception calling EndInvoke" text. Start is now off while a session is recorded (Stop and restore is off when none is), a click explains that only one session runs at a time, and errors from background work show their own message everywhere in the app.
- **Easier to read:** the profile choices on the Forensic logging tab used Windows' default black text on the dark theme; option buttons now follow the theme everywhere. The Custom sources show only when Custom is chosen, and disabled check boxes, option buttons and switches are drawn at 60 % instead of 45 % opacity.
- The quality gate now also fails when a test file cannot be loaded (its tests would otherwise be silently missing from the count).

### Firewall log reader

- **Security > Firewall > Log**: the firewall log in a sortable, filterable list. The newest entries show at once while the whole log (and the older `.old` file) is read in the background. Columns: time (local; UTC in the tooltip), action, direction (as the log writes it: SEND or RECEIVE), protocol, source and destination with ports, size, TCP flags, process and note.
- Quick filters (blocked, allowed, inbound, outbound, TCP, UDP, ICMP, last 15 minutes, hour or 24 hours, with a note), full-text search, and a filter row for an address or network (CIDR, IPv4 and IPv6), ports, a process and a time range. Saved views keep these filters.
- An overview of the current view: counts, events over time, and the top blocked sources, blocked ports (with what the port is used for), processes and remote addresses; click one to filter on it. "Rules for the selected port" opens the Rules tab searching for that port.
- **Follow live** reads only what the firewall appended since the last read (every 2 seconds) and notices when Windows starts a new log file. **Notes** bookmark entries with your own text; they stay on this PC and are included in exports.
- Fast on big logs: a full 32 MB log (about 340,000 entries) is read in about 1.2 s, the newest entries show in under 0.1 s, and filters, search and sorting take 6 to 180 ms. A small compiled reader does this work (plain C# source in the project, no downloads; see DECISIONS F11).
- Exports of any list are protected against spreadsheet formula injection (a cell starting with = + - @ gets a leading apostrophe). Log values come from the network and are only ever shown as plain text.
- Process names are best effort: the log has only a process id, and the name shown is the process that has that id now.

### Forensic logging

- **Security > Firewall > Forensic logging**: make Windows record connections for a limited time and put everything back afterwards. Three sources, each with what it records, its volume, its current state and whether a policy manages it: the firewall packet log, WFP connection auditing (every connection with the program path, Security events 5156 and 5157, and 5152 for dropped packets) and the DNS client log (names with the process id).
- Profiles: **Basic** (blocked packets), **Full forensic** (all three sources, allowed and blocked) and **Custom**; every change is previewed (from what to what) before it starts.
- Time-boxed sessions (30 minutes, 2 hours, 8 hours or until stopped) with a banner "Forensic logging active since ...". The previous settings come back automatically when the session ends while the app is open; if it ended while the app was closed, the next start shows it and offers to restore. No scheduled task or service is created.
- Before anything changes, every touched setting is saved (firewall profile logging, the audit subcategories with `auditpol /backup`, the Security log size, the DNS client log) and restored exactly. If a step fails, everything applied so far is restored. The Security log is enlarged first (256 MB, 512 MB or 1 GB; never made smaller). Event logs are never cleared, settings set by a policy are not changed, and logs are never written to a network share.
- **Estimate the volume**: watches new connections for 10 seconds (read-only) and shows the expected events per hour and how long each Security log size lasts.

### Evidence and AI export

- **Collect evidence package** (Forensic logging tab, or `Export-IgwtEvidencePackage`): a new timestamped folder (and optionally a zip with its SHA256) with copies of the firewall logs (originals are read with a shared open and never changed), `.evtx` exports of the WFP and DNS client events of the chosen time range, the firewall policy (.wfw) and profile and logging settings, listening ports and running processes, your notes, `manifest.json` (tool version, UTC and local time, range, sources, counts and the SHA256 of every file) and `chain-of-custody.txt`.
- **Export for AI analysis** (`Export-IgwtForensicDataset`): the firewall log, WFP and DNS events in one normalized schema (JSONL, or CSV protected against spreadsheet formulas), files of about 5 MB, a flow summary per program, remote address, port and protocol, `SCHEMA.md`, and `ANALYSIS_BRIEF.md` with the range, sources, known gaps, the redaction used and a clear warning that every value is untrusted network data that may try to manipulate an AI.
- Pseudonymization by default: internal addresses, local host names, user names and user folders in paths get consistent pseudonyms (keyed hash with a key that is never stored). A raw export for local use only is available with a warning. Rule names and DNS names are best effort and flagged as such. Nothing is ever uploaded.

### Install

Download iGWindowsTuner-3.5.0.zip, check it against SHA256SUMS, extract it, and run Start-iGWindowsTuner.cmd. Files from a downloaded zip carry Mark-of-the-Web: review them, then Unblock-File if you trust them.

Forensic logging changes Windows logging settings: every setting is saved first and restored when the session ends. The enable and restore round trip was tested with mocks; the Windows Sandbox run is pending.
