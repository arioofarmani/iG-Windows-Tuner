# Network test

The network test (GUI page **Network Test**, CLI `-NetworkTest`) measures the quality and stability of your connection, guesses what kind of connection you have and recommends the Windows networking adjustments that lower latency and jitter for online games, calls and streaming.

It is **read-only**: it sends ICMP echo requests (pings) and a few DNS queries and changes nothing. Recommended adjustments are applied only through the normal engine (preview, snapshot, apply, revert).

```powershell
.\iGWindowsTuner.ps1 -NetworkTest                                   # 30-second standard test
.\iGWindowsTuner.ps1 -NetworkTest -Duration Extended                # 2 minutes, best for spikes and loss bursts
.\iGWindowsTuner.ps1 -NetworkTest -NetTarget 155.133.248.34        # also measure a game server
.\iGWindowsTuner.ps1 -NetworkTest -UnderLoad                        # then measure while you run a speed test
.\iGWindowsTuner.ps1 -NetworkTest -ReportPath .\network.html        # save an HTML (or .json) report
```

## What it measures

| Step | Details |
|---|---|
| Active connection | The adapter that carries the default route: Ethernet, Wi-Fi, mobile broadband, phone tethering, VPN or a virtual switch; link speed, gateway, local address (private or carrier-grade NAT), IPv6, DNS servers, MTU. On Wi-Fi also the standard (Wi-Fi 4 to 7), band, channel, signal and link rates from `netsh wlan show interfaces` (read-only). |
| Path | An ICMP traceroute to 1.1.1.1 with reverse DNS for each hop, marking private, carrier-grade NAT (100.64.0.0/10) and public hops. |
| Path MTU | The largest packet that passes without fragmentation (Don't Fragment probes): 1500 is a native Ethernet path, 1492 means PPPoE, lower values mean a tunnel. |
| Latency series | Round-robin pings at 4 per second to your router, the first ISP hop, two internet anchors (1.1.1.1 and 8.8.8.8) and up to four targets of your own, for 10 s, 30 s or 2 minutes. Round-trip times are timed with a high-resolution stopwatch, so jitter has sub-millisecond precision. |
| DNS | Lookup time of three common names against your current DNS server. |
| Under load (optional) | 20 s of pings while you run a speed test or large download; the increase over the idle median is graded as bufferbloat. iG Windows Tuner does not generate the load itself. |

## Metrics and grades

| Metric | Meaning | A+ | A | B | C | D | F |
|---|---|---|---|---|---|---|---|
| Latency (average) | Round-trip time | <= 20 ms | <= 40 | <= 60 | <= 100 | <= 150 | more |
| Jitter | Mean difference between consecutive replies | <= 2 ms | <= 5 | <= 10 | <= 20 | <= 40 | more |
| Packet loss | Pings without a reply | 0 % | <= 0.5 | <= 1 | <= 2.5 | <= 5 | more |
| Stability | Spikes per minute plus twice the longest loss burst | 0 | <= 1 | <= 3 | <= 6 | <= 12 | more |
| Bufferbloat | Median latency increase under load | < 5 ms | < 30 | < 60 | < 200 | < 400 | more |

- The **overall grade** is the weakest of latency, jitter, loss and stability, so one bad metric is never hidden by good ones. The page also names the limiting metric.
- A **spike** is a reply slower than 1.5 times the median and more than max(10 ms, 3 x median absolute deviation) above it. The rate uses at least a one-minute window, so one spike in a short test does not look like a trend.
- The **score** (0-100) subtracts penalties for latency above 20 ms, jitter above 2 ms, loss and spikes.
- **MOS** (1 to 4.5) is the estimated call quality from the simplified ITU-T G.107 E-model used by VoIP monitoring tools.
- Routers answer pings *to themselves* with low priority, so occasional spikes or loss to the router alone are normal when the internet targets are clean; the test only reports a home-network problem when both show it.

## Connection type guess

The test guesses the **local link** (for example "Wi-Fi 6 (5 GHz)" or "Ethernet (2.5 Gbps)") and the **internet access technology**, with a confidence and the evidence it used:

| Evidence | Points to |
|---|---|
| Mobile broadband adapter, phone tethering over USB, phone hotspot gateway (192.168.43.1, 172.20.10.1) | Cellular |
| ISP router names containing gpon, ftth, fiber; dsl, bras; cable, cmts, docsis; lte, mobile; starlink; vsat | The matching technology |
| Carrier-grade NAT on the path | Cellular, Starlink, some fiber ISPs |
| First ISP hop latency (minus the router): <= 3 ms fiber, 3-8 ms cable or VDSL, 8-20 ms DSL, 20-60 ms radio links, > 450 ms geostationary satellite | Fiber, cable, DSL, cellular/Starlink/fixed wireless, satellite |
| 100.64.0.1 as the first ISP hop at 15-60 ms | Starlink |
| Path MTU 1492 (PPPoE) | DSL or fiber |
| Idle jitter above 8 ms on a wired link | Radio access network |

Behind a VPN the line cannot be identified, and the guess says so. With little evidence the result is "Unknown" with low confidence rather than a made-up answer.

## Recommendations

Recommended **Windows adjustments** are catalog items that help latency or jitter on your kind of connection and are not applied yet:

| Profile | Items |
|---|---|
| Ethernet | `net.adapter-power-saving-off`, `net.eee-off`, `net.interrupt-moderation-off`, `net.rss-on`, `net.qos-dscp-games`, `sched.network-throttling-off`, `sched.system-responsiveness`, `net.tcp-autotuning-normal`, `net.delivery-optimization-p2p-off`, `power.pcie-aspm-off` |
| Wi-Fi | `net.wifi-power-max-performance`, `net.qos-dscp-games`, `sched.network-throttling-off`, `sched.system-responsiveness`, `net.tcp-autotuning-normal`, `net.delivery-optimization-p2p-off`, `power.pcie-aspm-off` |
| Mobile data, satellite, other | `sched.network-throttling-off`, `sched.system-responsiveness`, `net.tcp-autotuning-normal`, `net.delivery-optimization-p2p-off` |

Risk Zone items are never recommended. If a Risk Zone network item is on (for example IPv6 disabled or TCP auto-tuning disabled), the test suggests turning it off. In the GUI, **Preview recommended adjustments** stages the items and shows the dry-run preview; nothing changes until you press Apply.

**Router, Wi-Fi and ISP guidance** covers what Windows settings cannot fix: using a cable, weak signal, the 2.4 GHz band, old Wi-Fi standards, loss or jitter inside the home network versus beyond the router, bufferbloat (enable SQM such as CAKE or fq_codel on the router), carrier-grade NAT, double NAT, VPNs, slow DNS, and the physical limits of satellite and mobile links.

## Limits

- Ping measures ICMP; some servers ignore or deprioritize it, so 100 % loss to a host does not prove that game traffic fails.
- The connection type guess is a heuristic. Router names and latency patterns differ between ISPs; the evidence list shows why the test decided as it did.
- The test does not measure throughput (speed). Use any speed test for that, and run **Measure under load** at the same time.
