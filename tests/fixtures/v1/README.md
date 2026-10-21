# 1.0 data fixtures

Frozen copies of the 1.0 data (released under the working name AegisTune), used by `tests\Schema.Tests.ps1` to prove that schema v2
migration and v1 snapshot revert keep working. Do not edit or migrate these files.

- `data\tweaks`, `data\presets`, `data\rejected.json`, `data\games.json`: the 1.0.0 data files.
- `snapshot-*-v1fix.json`: a real schema 1 snapshot written by the 1.0.0 engine inside Pester's
  TestRegistry (tweaks `gfx.game-mode`, `gfx.windowed-optimizations`, `input.pointer-precision-off`,
  `sec.autorun-off`). The computer name and user SID were replaced with placeholders; nothing else
  was changed. Values captured before the apply:
  - `HKCU:\Control Panel\Mouse`: MouseSpeed "1", MouseThreshold1 "6", MouseThreshold2 "10" (REG_SZ)
  - `HKCU:\Software\Microsoft\DirectX\UserGpuPreferences\DirectXUserGlobalSettings`: "VRROptimizeEnable=1;"
  - `HKCU:\Software\Microsoft\GameBar\AutoGameModeEnabled`: 0 (REG_DWORD)
  - `HKLM:\...\Policies\Explorer`: NoDriveTypeAutoRun and NoAutorun absent (key missing)
