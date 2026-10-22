# Data schema v2

iG Windows Tuner 2.0 data files declare `"schemaVersion": 2`. JSON Schema documents for editors are in
`data\schema\` (`tweak.schema.json`, `preset.schema.json`, `cleaner-rule.schema.json`); the
authoritative checks are `Test-IgwtCatalog` and `Test-IgwtCleanerCatalog`, which the Pester
suite runs.

## Fields shared by every item

Every user-facing item (tweak, cleaner rule, preset, hardware tag) has:

| Field | Rule |
|---|---|
| `hint` | Tooltip, 140 characters or fewer. |
| `description` | What it does, why, the trade-off and how to revert (at least 40 characters). |

Tweaks and cleaner rules also have:

| Field | Values | Meaning |
|---|---|---|
| `level` | `Standard`, `Advanced`, `Expert`, `Lab` | Who should use the item and how it is gated. Separate from the evidence tier. |
| tier | `A`, `B`, `R` | Evidence tier: `evidence.tier` for tweaks, top-level `tier` for cleaner rules. `R` (rejected) is only for Risk Zone items. |
| `antiCheat` | `"safe"`, `"unknown"`, `{ "breaks": ["FACEIT", ...] }` | Anything other than `safe` is shown as a badge and kept out of gaming presets. `breaks` requires level `Lab`; `unknown` requires `Expert` or `Lab`. |
| `reversible` | `full`, `partial`, `none` | `full`: the snapshot restores everything. Anything else must be explained in `sideEffects`. Cleaner deletions are `none` (Recycle Bin rules `partial`). |
| `sideEffects` | text | Empty when there are none. |
| `source` | `igwt`, `winutil`, `microsoft` | `winutil` items need an `attribution`. |
| `hardware` | `{ "tags": [], "excludeTags": [] }` | Tags from `data\hardware\tags.json`. Empty means the item applies to all hardware. |

### Levels

| Level | Audience | Gate today | In presets |
|---|---|---|---|
| Standard | Everyone | none | yes |
| Advanced | Power users | none (mode switch arrives with the GUI restructure) | yes |
| Expert | Engineers | `-AcknowledgeRisk` / GUI confirmation | only inside hardware overlays and the Engineer preset |
| Lab | Benchmarking and research | `-AcknowledgeRisk` / GUI confirmation (typed confirmation and red banner arrive with the GUI restructure) | never |

## Tweak-only fields

`requires` (`none`, `logoff`, `reboot`), `appliesTo` (`minBuild`, optional `maxBuild`,
`editions`, and `conditions`: runtime checks `wiredAdapter`, `multipleGpus`, `nvidiaGpu`,
`defenderActive`, `notRdp`), `warning` (required for Expert and Lab), `impact`, `risk`,
`evidence`, `conflictsWith`, `policyKeys`, `postApply`, `revertNote`, `actions`.

Action definitions did not change from v1. Snapshots match actions by fingerprint (type plus
identifying fields such as path, name and item), so never change those fields on an existing
action; add a new action or a new tweak instead.

### 2.0 action types

| Type | Key fields |
|---|---|
| `storageSense` | `setting` (enabled, cadence, temporaryFiles, recycleBinDays, downloadsDays), `value` |
| `wufbPolicy` | `setting` (featureDeferralDays 0-365, qualityDeferralDays 0-30, targetRelease `{ product, version }`), `value` |
| `deviceInterrupt` | `deviceClass` (Display, Net, USB), any of `msiSupported`, `messageNumberLimit`, `devicePolicy`, `devicePriority`; Expert/Lab, `requires: reboot` |
| `serviceSet` | `services: [{ name, startupType, default }]`, optional `stop` |
| `powercfgAttribute` | `subgroup`, `setting`, `visible`, `default` (hidden or visible), `label` |
| `powercfgSettingAcDc` | `subgroup`, `setting`, `ac`, `dc`, `defaultAc`/`defaultDc` or `defaultFromScheme`, `label` |
| `scheduledTask` | `path` (`\...\`), `name`, `on`/`default` (Enabled, Disabled) |
| `firewallRule` | owned: `rule` (`iGWindowsTuner-*`), `displayName`, `direction`, `action: Block`, optional `protocol`, `localPort`, `remotePort`, `program`, `profile`; or group: `displayGroup`, optional `direction`, `on: Disabled`, `default` |
| `appx` | `package`, `on: Removed`, `default: Installed`, optional `provisioned`, `storeId`; reversible partial |
| `winget` | `id`, optional `source` (winget, msstore), `on`/`default` (Installed, NotInstalled) |
| `capability` | `name`, `on`/`default` (Installed, NotPresent) |
| `processMitigation` | `process` (`name.exe`), `mitigation`, `on` (ON, OFF; OFF needs Expert/Lab) |
| `exploitSystem` | `mitigation`, `on: ON` |
| `cleanerRule` | `rule` (cleaner rule id); reversible none |
| `check` + `checker: DefaultApp` | `extension` or `protocol`, `progId` (read-only) |

## Schema v3 fields (3.0)

Tweak files are schema v3. The loaders still accept v1 and v2 entries and upgrade them in memory; `tools\Convert-IgwtV1Data.ps1` rewrites old files. Actions never change, so every snapshot keeps matching its item.

| Field | Values | Meaning |
|---|---|---|
| `scope` | `Performance`, `Network`, `Privacy`, `Updates`, `Defender`, `AttackSurface`, `AuditLogging`, `System` | Which scoped (category) preset an item belongs to. The migration derives it from the category, group and action types. |
| `editions` | `Home`, `Professional`, `Enterprise`, `Education`, `Server` | Edition families on which Windows honors the item; empty means all. On other editions the item is "not effective on this edition" (an existing value can still be removed). Replaces `appliesTo.editions`. |
| `managedBy` | `local`, `gpo`, `mdm` | Where the setting can be controlled from. Items that write a Group Policy location list all three. |
| `gpoPath` | `machine`, `user`, empty | Group Policy side of a policy item (registry actions under `SOFTWARE\Policies` or `CurrentVersion\Policies`). Required for such items; on domain-joined or MDM-enrolled PCs these items are report-only unless the user acknowledges local changes. |
| `admxRef` | `{ file, policy, class }` or `null` | The ADMX policy behind the item (filled in by the Group Policy engine work). |
| `requiresDomain`, `requiresMdm` | boolean | The item only makes sense on a domain-joined or MDM-enrolled PC. |

## Presets (intent presets)

| Field | Meaning |
|---|---|
| `include` | Tweak ids in the preset. |
| `exclude` | Ids explicitly kept out, even when a hardware overlay would add them. |
| `levelCeiling` | Highest item level allowed (`Standard`, `Advanced`, `Expert`); Lab is never allowed. |
| `antiCheatPolicy` | `safeOnly` (required for gaming presets) or `any`. |
| `gaming` | Gaming presets may only contain `antiCheat: "safe"` items. |
| `hint`, `description`, `tagline`, `order` | Texts and sort order. |

In memory, every preset also has `tweaks` = `include` minus `exclude`. Preset selection resolves it
further through the hardware overlays.

## Other data files

| File | Content | Validated by |
|---|---|---|
| `data\asr\rules.json` | The 19 ASR rules: GUID, key, texts, gamer impact, Warn/cloud/server-only flags, recommended mode, sources (`docs\ASR_CENTER.md`). | `Test-IgwtAsrCatalog` |
| `data\power\processor.json` | Processor settings the power plan editor may change: alias, GUID, group, level, texts, sources (`docs\INSPECTORS.md`). | `Test-IgwtPowerSettingCatalog` |
| `data\inspectors\kernel.json` | Registry keys and documented values for the kernel and memory inspector: default, meaning, catalog item or rejected entry. | `Test-IgwtKernelInspectorCatalog` |
| `data\manage\services.json` | Services the management module never changes: groups of `names` and/or wildcard `patterns`, each with a `reason` (200 characters or fewer). | `Test-IgwtManageCatalog` (also requires the spec section 12 core list) |
| `data\manage\nic-keywords.json` | Descriptions of standardized NDIS adapter keywords (`keyword` starting with `*`, `description` of 240 characters or fewer) and the https `source`. | `Test-IgwtManageCatalog` |
| `data\hardware\*.json` | Hardware tags, detection rules and overlays (`docs\HARDWARE.md`). | `Test-IgwtHardwareCatalog` |

All of them run inside `Test-IgwtCatalog`.

## Risk Zone items and the rejected list

Risk Zone items (`data\tweaks\riskzone.json`) are tweaks with `category: "Risk Zone"`, an id starting with `risk.`, `evidence.tier: "R"`, `level: "Lab"`, a `warning`, non-empty `sideEffects` and a `riskZone` block:

| Field | Content |
|---|---|
| `riskZone.rejected` | Id of the entry in `data\rejected.json` |
| `riskZone.turnsOff` | What the item switches off (list) |
| `riskZone.turnsOn` | What the item switches on (list; at least one of the two lists is non-empty) |
| `riskZone.risks` | The risks the user accepts (list, at least one) |

Every entry in `data\rejected.json` has exactly one of `riskItem` (the Risk Zone item id) or `unavailable` (why it is not offered). `Test-IgwtRiskZoneItem` and `Test-IgwtCatalog` check both directions.

## Snapshots

New snapshots are schema 2: `catalogSchema`, `hardwareTags` and a `level` on every entry (so a Lab
item that is still applied can be found). Schema 1 snapshots (iG Windows Tuner 1.x) are read directly and
upgraded in memory; the file is never rewritten. Unknown schemas are refused.

Special operations have their own restore code in `Invoke-IgwtRevert`: `Startup` (StartupApproved),
`ASR` (ASR Center), `Power` (power plan editor) and `Manage` (management modules). A `Manage` entry's
action carries `managed: { kind, target, value, provisioned }`; on revert the action is rebuilt from
those fields and validated again against the protection rules, and only the restore `data` comes
from the file.

## Migration

- **Automatic:** the loaders upgrade v1 tweaks, presets, cleaner rules and snapshots in memory, so
  an old data folder or backup keeps working. `Test-IgwtCatalog` still reports v1 files so they get
  converted.
- **Tool:** `tools\Convert-IgwtV1Data.ps1 [-DataFolder <path>] [-WhatIf]` rewrites v1 files in place
  (idempotent). `-SnapshotFolder <dir> -SnapshotDestination <other dir>` writes schema 2 copies of
  snapshots; originals are never modified.
- **Mapping:** level = Lab for v1 expert items that were not anti-cheat safe, Expert for other v1
  expert items, Advanced for Tier B or medium/high risk, otherwise Standard. `antiCheatSafe: true`
  becomes `"safe"`; `false` becomes `{ "breaks": [...] }` with the anti-cheats named in the warning
  (or `"unknown"`). `appliesTo.hardware` checks move to `appliesTo.conditions`. v1 presets become
  intent presets with `levelCeiling: Advanced` and `antiCheatPolicy: safeOnly`.
- **Renamed ids:** `data\migration\id-map.json` maps old ids to new ones for snapshots and presets.
