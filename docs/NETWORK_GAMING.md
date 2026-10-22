# Gaming network optimizer (3.0)

`-NetworkOptimize` tunes the network settings of the PC it runs on for online gaming: low latency
and, above all, low jitter. It works in four steps:

1. **Measure** (read-only, pings and DNS queries): latency, jitter, loss and stability to your
   router, the first ISP hop, two internet anchors and up to four targets you add with `-NetTarget`
   (for example your game server), plus the path, the path MTU and the connection type.
2. **Plan**: the catalog items that lower latency and jitter on this kind of connection and are
   not applied yet, with the reason for each and the measurement behind it.
3. **Apply** through the normal engine: System Restore point, JSON snapshot, per-item rollback.
   Then the router, the internet and DNS must answer within 60 seconds; otherwise every change is
   **reverted automatically**.
4. **Measure again** and show before and after per target (median, jitter, loss, grade). Small
   differences are measurement noise and count as "Same".

```powershell
.\iGWindowsTuner.ps1 -NetworkOptimize -DryRun                    # measure and show the plan only
.\iGWindowsTuner.ps1 -NetworkOptimize -Duration Extended -NetTarget my.game.server
.\iGWindowsTuner.ps1 -RevertAll -Snapshot <the snapshot it printed>   # undo
```

## What it can change

| Connection | Items (each only when not applied yet) |
|---|---|
| Ethernet | Adapter power saving off, Energy Efficient Ethernet off, interrupt moderation off (links up to 2.5 Gbit/s only), RSS on, network throttling off, system responsiveness for games, TCP auto-tuning normal, Delivery Optimization peer upload off, PCI Express link power saving off |
| Wi-Fi | Wi-Fi adapter maximum performance, network throttling off, system responsiveness, TCP auto-tuning normal, Delivery Optimization peer upload off, PCI Express link power saving off |
| Other (cellular, VPN) | Network throttling off, system responsiveness, TCP auto-tuning normal, Delivery Optimization peer upload off |

DSCP marking of game traffic is added only with `-RouterHonorsDscp`, because it helps only when the
router prioritizes by DSCP. Each item's exact registry values, adapter properties and sources are in
`docs\TWEAKS.md`.

## Rules it follows

- Windows defaults are already good for most networks; an item is applied only for the connection
  type it helps, and the before/after measurement shows the effect.
- Interrupt moderation stays at the driver default above 2.5 Gbit/s (off costs a lot of CPU there).
- MTU, DNS servers, static IP and gateway are never changed, and IPv6 is never turned off.
  Popular tweaks without evidence are not used; they are listed with the reason in
  `docs\REJECTED_TWEAKS.md`. The delayed-ACK item (TcpAckFrequency) stays out of the plan because games
  mostly use UDP; apply it yourself only if you measure a benefit.
- It refuses to run in a Remote Desktop session (adapter changes restart the link).
- Router-side fixes are shown as guidance: SQM (CAKE or fq_codel) for bufferbloat, 5/6 GHz Wi-Fi,
  bridge mode against double NAT, a cable instead of Wi-Fi for competitive play.