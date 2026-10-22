# Network IDS/IPS: what the endpoint can and cannot do

iG Windows Tuner runs on one Windows PC. A full network intrusion detection and prevention system
(IDS/IPS) belongs on the edge of the network, where it sees every device's traffic.

## On the edge firewall

Run an IDS/IPS such as **Suricata** on the router or firewall, for example **OPNsense** or
**pfSense**:

- It inspects traffic of every device: PCs, consoles, phones, TVs and IoT devices that cannot run
  security software.
- It uses rule sets (for example Emerging Threats) that match exploit and command-and-control
  traffic patterns, not only known-bad addresses.
- In IPS (inline) mode it drops matching traffic before it reaches the device.
- It logs alerts centrally, so a SOC or a home lab can correlate them.

Costs: a router with enough CPU for the line speed, rule tuning to avoid false positives, and
encrypted traffic (TLS) limits what it can see beyond names and certificates.

## On this PC

What iG Windows Tuner adds on the endpoint:

- **Microsoft Defender network protection** blocks connections to domains and IPs with a bad
  reputation, in every app, with Block or Audit mode (Defender presets).
- **Network Inspection** (the Network Inspection System) parses DNS, DNS over TCP, HTTP, TLS
  handshakes, SSH, RDP, FTP, SMTP and QUIC and matches them against Microsoft's signatures, with
  inbound connection filtering and a DNS sinkhole. This is signature- and reputation-based
  inspection for this PC only; it is not a full IDS/IPS (`-DefenderParsersOn` turns it on).
- **Windows Firewall logging** with an analyzer for blocked sources, ports and processes
  (`-FirewallLog`), so blocked scans and connection attempts become visible.
- **Detection logging**: process creation with command lines, PowerShell logging, sign-in auditing
  and Sysmon (when installed) for a SIEM or an incident responder (`-PolicyPreset audit-logging`).

Use both: the edge IDS/IPS for the network, Defender and the firewall log for the endpoint.
