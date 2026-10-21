# Contributing to iG Windows Tuner

Thank you for helping. iG Windows Tuner changes real systems, so every contribution follows three rules: **evidence first** (a current Microsoft or vendor source, or a Tier B "measure" label), **everything reversible** (snapshot, apply, restore) and **security never goes down**.

## Develop safely

Develop on your everyday PC with read-only commands only:

- `.\iGWindowsTuner.ps1 -Report`, `-ListTweaks`, `-Hardware`, `-Inspect`, `-SecurityScore`, `-Inventory`, `-Diagnostics`, and any command with `-DryRun`.
- `.\iGWindowsTuner.ps1 -Clean -Scan` (enumerates and sizes, deletes nothing) and `-Analyze <path>`.
- `Show-IgwtGui -RenderTo <folder>` to render every GUI page offscreen.
- The Pester suite, PSScriptAnalyzer, `tools\Test-Catalog.ps1` and `tools\Build-Docs.ps1`.

Run real apply and revert cycles (`-Apply`, `-Preset`, `-Revert`, `-Clean` without `-Scan`, ASR, power plan and management changes) only in Windows Sandbox: run `tools\New-SandboxConfig.ps1`, then open the generated `tools\iGWindowsTuner.wsb` (see `docs\TESTING.md`).

Before opening a pull request, run `tools\Invoke-QualityChecks.ps1` (catalog validation, Pester, PSScriptAnalyzer and a Microsoft Defender scan) and regenerate the docs with `tools\Build-Docs.ps1`.
## Architecture in one paragraph

`data\tweaks\*.json` (schema v2, `docs\SCHEMA.md`) declares every tweak (id, texts, `level`, evidence, impact, risk, `antiCheat`, `reversible`, `sideEffects`, `requires`, `appliesTo`, `hardware`, `source`, typed `actions`). The loaders also accept v1 entries and upgrade them in memory (`src\Core\Migration.ps1`); `tools\Convert-IgwtV1Data.ps1` rewrites v1 files. The computed properties `expert`, `antiCheatSafe` and `tier` exist only in memory. The engine (`src\Core\Engine.ps1`) dispatches each action type through explicit `switch` statements to `src\Actions\<Type>.ps1`. Each action type implements: **State** (detect), **Snapshot** (capture exact previous data), **Apply** (`on` or Windows `default`) and **Restore** (from snapshot). `src\Core\StateDetection.ps1` rolls item states up to On / Off / Partial / NotApplicable / ManagedByPolicy / Unknown. The CLI (`iGWindowsTuner.ps1`) and the GUI (`src\Gui`) only call engine functions; the GUI worker runspace calls exported commands with `AddCommand`.

## How to add a tweak

1. Verify the setting against current Microsoft or vendor documentation for build 26100+ (path, value, type, Windows default). Popularity is not evidence. Record deviations in `docs\DECISIONS.md`.
2. Add an entry to the right `data\tweaks\<category>.json`:
   - `id` as `category.name` in lower case; `hint` of 140 characters or less; a 2-4 sentence `description` (what, why, trade-off, how to revert).
   - `evidence.tier` `A` (documented) or `B` (situational: the hint or description must say "measure"), with at least one https source.
   - Schema v2 fields: `level` (Standard, Advanced, Expert, Lab), `antiCheat` (`"safe"`, `"unknown"` or `{ "breaks": [...] }`), `reversible` (full, partial, none), `sideEffects` (text, required unless fully reversible), `source` (igwt, winutil + `attribution`, microsoft), `hardware` (`tags`/`excludeTags` from `data\hardware\tags.json`), and `appliesTo` (`minBuild`, optional `maxBuild`, `editions`, `conditions`). Write the file with `ConvertTo-IgwtJson` style (2-space indent, ASCII) or run `tools\Convert-IgwtV1Data.ps1`, which also normalizes formatting.
   - Registry actions need `valueType`, `on` and `default` (`"<absent>"` when the value does not exist by default). Use `absentValue` when Windows treats a missing value as a specific value, `equivalentOn` for other values that count as on, `bitClear` to clear flag bits, and `onlyIfAbsent` for create-only values.
   - Prefer existing action types (1.0 types plus 2.0: storageSense, wufbPolicy, deviceInterrupt, serviceSet, powercfgAttribute, powercfgSettingAcDc, scheduledTask, firewallRule, appx, winget, capability, processMitigation, exploitSystem, cleanerRule; `check` with checker DefaultApp). A new type needs State/Snapshot/Apply/Restore, entries in the four dispatch switches (`StateDetection.ps1`, `Engine.ps1`), identifying fields in `Get-IgwtActionFingerprint`, rules in `Test-IgwtV2Action`, a description in `tools\Build-Docs.ps1` and a round trip in `tests\Handlers.Tests.ps1`. For a one-off handler, add Detect/Snapshot/Apply/Restore to `$script:IgwtCustomHandlers` in `src\Actions\Custom.ps1`.
   - An item that breaks anti-cheat is level `Lab` with `antiCheat: { "breaks": [...] }`; unknown impact needs Expert or Lab. Expert and Lab items need a `warning`. Never change an existing action's identifying fields (type, path, name, item, ...): snapshots match actions by fingerprint.
3. Add the id to a preset's `include` only when it fits the preset rules (level at or below `levelCeiling`, never Lab; gaming presets only `antiCheat: "safe"`; Balanced = Tier A only; no conflicting pairs).
4. Run `tools\Test-Catalog.ps1`, then the Pester suite, then `tools\Build-Docs.ps1` (regenerates `docs\TWEAKS.md`, `docs\PRESETS.md`, `docs\REJECTED_TWEAKS.md` and `docs\CLEANER.md`).
5. Rejected ideas go to `data\rejected.json` with a reason, never into the catalog.
6. Renaming an id: add `"old": "new"` to `data\migration\id-map.json` so old snapshots and presets still resolve.

## How to add a hardware tag or overlay

1. New tag: add it to `data\hardware\tags.json` (id, name, group, hint, description) and a detection rule to `data\hardware\detection.json` (`when` keys are ANDed, `anyOf` is OR; keys: cpuVendor, cpuName, cpuNameNot, cpuFamily, cpuModels, hybrid, gpuName, gpuPnp, nicName, nicPnp, laptop, vm, modernStandby, systemDiskBus, systemDiskMedia, memoryGBMin, memoryGBBelow). Never use HypervisorPresent for VM detection.
2. New overlay: add it to `data\hardware\overlays.json` with `id` `overlay.*`, `tags` (any of), `hint`, `description`, `basis` (vendor, reviewer, igwt), https `sources`, and at least one of `block` (item ids), `blockMatching` (action fields such as type/setting/handler/name, or `fieldPresent`), `add` (item ids) and `guidance`.
3. Add or update a fixture in `tests\fixtures\hardware` (capture real facts with `.\iGWindowsTuner.ps1 -Hardware -Json`; no serial numbers) and assert the tags and preset effects in `tests\Hardware.Tests.ps1`. Then run `tools\Build-Docs.ps1` (regenerates `docs\HARDWARE.md`).

## How to add or change an ASR rule

1. Check the rule against the Microsoft Learn ASR reference and overview (GUID, Warn support, cloud dependency, server-only, standard vs other).
2. Edit `data\asr\rules.json`: `id` (GUID), `key` (lower-case-hyphenated), `name`, `category` (standard, other), `msCategory`, `order`, `hint` (140 characters or fewer), `description`, `gamerImpact` and `gamerImpactLevel` (none, low, medium, high), `supportsWarn`, `requiresCloud`, `appliesTo` (office, adobe, exchange or empty), `serverOnly`, `recommendedMode` (standard rules Block; medium/high gamer impact never Block; server-only NotConfigured), `notes`, https `sources`. Never change a GUID: ASR snapshots refer to it.
3. Run the Pester suite (`Test-IgwtAsrCatalog` runs inside `Test-IgwtCatalog`) and `tools\Build-Docs.ps1` (regenerates `docs\ASR_CENTER.md`).
4. ASR changes go through `Invoke-IgwtAsrChange` only (snapshot operation `ASR`, revert through `Invoke-IgwtRevert`). Exclusions are ASR-only and must pass `Test-IgwtAsrExclusion`; antivirus exclusions are never added.

## How to extend the expert inspectors

- **Power plan editor:** add a processor setting to `data\power\processor.json` (`alias`, `guid`, `group`, `level` Advanced/Expert, `hint` of 140 characters or fewer, `description`, https `sources`). Ranges come from `powercfg /qh` at runtime; hardware overlays (`data\hardware\overlays.json`, `blockMatching` with `type: powercfgSetting`) decide where it is blocked. Processor idle disable must never be added.
- **Kernel and memory inspector:** add keys or values to `data\inspectors\kernel.json` (`name`, `default` or `<absent>`, optional `absentMeans`, `meaning`, optional `item` (catalog id) or `rejected` (rejected id), `sources`). The inspector stays read-only: a value becomes changeable only through a catalog item.
- Run the Pester suite (`Test-IgwtPowerSettingCatalog` and `Test-IgwtKernelInspectorCatalog` run inside `Test-IgwtCatalog`) and `tools\Build-Docs.ps1` (regenerates `docs\INSPECTORS.md`).

## How to extend the management modules

- **Protected services:** add names or wildcard patterns with a reason to `data\manage\services.json`; `Test-IgwtManageCatalog` (inside `Test-IgwtCatalog`) also requires the core protected list. Protected tasks come from `$script:IgwtProtectedTaskPaths` (`src\Actions\ScheduledTask.ps1`) plus the anti-cheat pattern in `src\Manage\ManagedChange.ps1`; protected apps from `Test-IgwtAppxProtected`; protected features and capabilities from `src\Manage\ManagedChange.ps1`.
- **New change kind:** extend `New-IgwtManagedAction` so it validates the target and returns an action of an existing, tested type; never add a write path outside `Invoke-IgwtManagedChange` (snapshot operation `Manage`, revert rebuilds and re-validates the action).
- **Curated sets** (such as telemetry tasks) are catalog items, not hard-coded lists in the module.
- **NIC keyword descriptions:** `data\manage\nic-keywords.json` (standardized `*` keywords only, with the Microsoft source).
- Everything else in `src\Manage` (inventories, persistence, update status, network toolkit, diagnostics, system report) stays read-only; tests mock every system call (`tests\Manage.Tests.ps1`).

## How to add a Risk Zone item

The Risk Zone offers rejected tweaks at the user's own risk. Only reversible performance, input, system or network settings qualify; never add items that turn off security protections, edit the boot configuration, delete files irreversibly or need background software.

1. The tweak must already be an entry in `data\rejected.json` (with the reason it is rejected).
2. Add the item to `data\tweaks\riskzone.json`: id `risk.*`, `category: "Risk Zone"`, `level: "Lab"`, `evidence.tier: "R"` with at least one https source and the rejection reason in `evidence.notes`, a `warning`, `sideEffects` describing what it switches off or on, and a `riskZone` block (`rejected`, `turnsOff`, `turnsOn`, `risks`). Declare `conflictsWith` for the safe counterpart if one exists. Defaults must be the real Windows defaults.
3. Set `riskItem` on the rejected entry (and remove `unavailable`).
4. Add an apply/revert test to `tests\RiskZone.Tests.ps1`, then run the quality checks and `tools\Build-Docs.ps1`.

## Network test

`src\Network\NetworkQuality.ps1` is read-only: ICMP probes go through `Send-IgwtPingProbe`, reverse DNS through `Resolve-IgwtHostName` and Wi-Fi details through `Invoke-IgwtNetshWlanInterfaces` (fixed `wlan show interfaces` arguments). All three refuse to run in TestMode, so tests mock them (`tests\Network.Tests.ps1`). Recommendations may only reference existing catalog items; new adjustments go through the normal "How to add a tweak" process first.
## How to add a cleaner rule

1. Find the vendor's documented cache location (or mark the rule Tier B). Never point a rule at user documents, profile roots or program folders: the denylist in `src\Cleaner\CleanerSafety.ps1` refuses them anyway.
2. Add it to `data\cleaner\<category>.json` with `id` `clean.*`, `level`, `tier`, `method`, `hint`, `description`, `sideEffects`, `antiCheat: "safe"`, `reversible` (none, or partial for Recycle Bin rules), `source`, `hardware`, and `roots` (or `userDataRoots` + cache folder names for browsers). List apps that must be closed in `requiresClosed`; only Standard rules may be `default: true`.
3. Run the Pester suite (`tests\Cleaner.Tests.ps1` validates the catalog) and `tools\Build-Docs.ps1`.

## Tests

```powershell
# non-elevated Windows PowerShell
Import-Module Pester -RequiredVersion 5.7.1
Invoke-Pester -Path .\tests -Output Detailed
Invoke-ScriptAnalyzer -Path . -Recurse        # uses PSScriptAnalyzerSettings.psd1 (documented exclusions)
.\tools\Invoke-QualityChecks.ps1              # all of the above plus the Defender scan
```

- Tests call `Initialize-IgwtTestEnvironment` (`tests\TestHelpers.ps1`), which redirects `HKLM:\` and `HKCU:\` into `TestRegistry:` and turns on TestMode. In TestMode, any registry path that escapes the redirect throws, and `powercfg`/`nvidia-smi` throw unless mocked.
- Mock system cmdlets with `Mock <Cmdlet> -ModuleName iGWindowsTuner`. Note that many NetAdapter/NetQos/DnsClient parameters are `string[]`, so index `[0]` in mocks.
- The suite refuses to run elevated on a real machine (`IGWT_ALLOW_ELEVATED_TESTS=1` is meant for Windows Sandbox only).

## Conventions

- PowerShell 5.1 syntax: no ternary, `??`, `?.` or `-AsHashtable`. Keep source files ASCII.
- `[Math]::Min`/`Max` with an integer literal and a double picks the integer overload and truncates (`[Math]::Max(0, 0.5)` is 0): cast both arguments to `[double]`. `@($genericList)` throws in Windows PowerShell 5.1: use `.ToArray()`. A single `[pscustomobject]` has no `.Count` in 5.1: wrap results in `@()`.
- Inside double-quoted strings, write `${var}?` (PowerShell would otherwise parse `$var?` as a variable named `var?`). Avoid nested double quotes with backtick escapes inside `$()`.
- Functions use the `Igwt` noun prefix; state-changing ones support `-WhatIf`. Keep comment-based help on every function.
- Never add `Invoke-Expression`, Base64, downloads, hidden windows, persistence, `bcdedit`, Defender antivirus exclusions or AMSI/ETW changes (ASR-only exclusions exist only in the ASR Center). `tests\Safety.Tests.ps1` will fail.
- Every function name must be unique across `src\` (a later file silently replaces an earlier definition); `tests\Safety.Tests.ps1` checks it. Reuse existing helpers such as `Test-IgwtPathUnder -Path -Parent`.
- No tweak logic in the GUI.
