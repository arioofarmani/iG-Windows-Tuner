# Roadmap: ideas not in the current spec

Ideas that came up while building a release but were outside its scope. They are not planned or promised; each needs its own spec and verification first.

## From 3.5 (firewall logs and forensics)

- **Rule names from the WFP filter list.** Resolve a WFP event's filter run-time id through `netsh wfp show filters` (needs elevation; its XML was not verified for 3.5, so 3.5 uses the event's own FilterName field).
- **Direction codes without the rendered message.** Map `%%14592`-style codes through the provider's parameter message file instead of the rendered event text (no documented table was found).
- **Live WFP and DNS view.** Show WFP and DNS events in the Log tab next to the firewall log, with the same filters.
- **Measured volume estimate.** Replace the 1 KB-per-event assumption with the average record size of the Security log after a session (`wevtutil gli` on the user's PC).
- **Saved forensic profiles.** Let the user save a Custom source selection by name.
- **Evidence verification.** A command that re-checks an evidence folder against its manifest.json and reports changed or missing files.
- **Port knowledge in the export.** Add the port meaning from the firewall knowledge base to the flow summary.
