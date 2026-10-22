# Expert and Lab guide

iG Windows Tuner sorts every item into four levels. The level decides who should use it, which gate it passes and whether a preset may contain it.

| Level | For | Gate | In presets |
|---|---|---|---|
| Standard | Everyone | None beyond the normal preview and apply | Yes |
| Advanced | Users who read the description | None; situational items say "measure" | Yes, up to each preset's level ceiling |
| Expert | Engineers who measure before and after | `-AcknowledgeRisk` on the command line, a confirmation in the GUI, a restore point before the first Expert apply | Only inside hardware overlays where documented |
| Lab | Experiments that knowingly break something (anti-cheat, a Windows default Microsoft recommends) | Same as Expert, plus the item's warning | Never |

The **Risk Zone** (`-RiskZone`, GUI page Risk Zone) holds the rejected tweaks that are reversible: tier R, level Lab. Applying one needs `-AcknowledgeRisk` or typing "I ACCEPT" in the GUI, and every one lists what it turns off and on and why it was rejected. Rejected tweaks that turn off security protections, edit the boot configuration or cannot be undone are never offered.

## Before you apply an Expert or Lab item

1. Read the item's description, warning and sources (`-Apply <id> -DryRun` prints all of them).
2. Measure first: frame times with a capture tool, DPC/ISR latency (`-Diagnostics DpcIsr`), network latency (`-NetworkTest`). Situational (Tier B) items only help when a measurement shows it.
3. Apply one item at a time and measure again. If it does not help, revert it.

## Expert controls

- **Power plan editor** (`-Inspect Power`, `-PowerSetting <alias> -Ac <n> -Dc <n>`): hidden processor settings next to their Windows defaults; hardware overlays block settings that are unsafe on a CPU family (for example processor idle on Raptor Lake desktops). Processor idle disable is never offered.
- **Interrupts and MSI** (`-Inspect Interrupts`), **network queues** (`-Inspect Network`), **kernel and memory values** (`-Inspect Kernel`), **timer** (`-Inspect Timer`) and **crash dumps** (`-Inspect Crash`): read-only; a value becomes changeable only through a catalog item.
- **Management** (`-Inventory`, `-Change`): services, tasks, inbox apps, features and app firewall rules with protection rules and a snapshot per change.

## Undo

Every change writes a JSON snapshot first (`%ProgramData%\iGWindowsTuner\Backups`), and a restore point is created before applies when System Protection is on.

```powershell
.\iGWindowsTuner.ps1 -Revert <id>          # one item, from its latest snapshot
.\iGWindowsTuner.ps1 -RevertAll            # the most recent apply or preset
.\iGWindowsTuner.ps1 -ResetDefault <id>    # the documented Windows default
```

## What stays off limits

Not even Lab items edit BCD, enable test signing, disable driver signature enforcement, DEP, ASLR or CFG, touch Secure Boot, TPM, firmware, voltages or anti-cheat services, disable Defender, the firewall, UAC, SmartScreen or Windows Update, add antivirus exclusions, create persistence or download anything. `tests\Safety.Tests.ps1` enforces these rules against the source code.
