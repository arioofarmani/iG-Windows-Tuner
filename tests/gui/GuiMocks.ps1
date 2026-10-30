# GuiMocks.ps1
# Mocked data providers for the offscreen GUI render suite (tools\Test-GuiRender.ps1). Dot-sourced
# into the module scope, these functions replace the GUI's data functions with deterministic,
# synthetic data: a demo gaming PC with generic names, the real catalogs (tweaks, ASR rules,
# Defender settings, toolkit) and nothing read from the PC that runs the suite. Nothing here
# changes anything. Every mock keeps the shape of the real function's output.

$script:MockNow = [datetime]'2026-10-22T19:30:00'

function script:Get-IgwtMockRandom {
    param([string]$Seed)
    $h = 17
    foreach ($ch in $Seed.ToCharArray()) { $h = ($h * 31 + [int]$ch) % 2147483647 }
    return (New-Object System.Random $h)
}

function script:New-IgwtMockStateItems {
    param($Tweak, [string]$State)
    $i = 0
    foreach ($a in @($Tweak.actions)) {
        $target = ''
        try { $target = Get-IgwtActionFingerprint $a } catch { $target = [string]$a.type }
        $on = [string]$a.on
        $cur = $(if ($State -eq 'On') { $on } elseif ($a.default) { [string]$a.default } else { '(default)' })
        [pscustomobject]@{ Target = $target; Current = $cur; Desired = $on; State = $(if ($State -eq 'Partial' -and $i -gt 0) { 'Off' } elseif ($State -eq 'Partial') { 'On' } else { $State }); Note = ''; ActionIndex = $i; ActionType = [string]$a.type }
        $i++
    }
}

function script:Get-IgwtGuiData {
    [CmdletBinding()]
    param([switch]$IncludeHealth)
    $states = @{}; $changed = @{}
    foreach ($t in (Get-IgwtCatalog)) {
        $r = Get-IgwtMockRandom -Seed ([string]$t.id)
        $roll = $r.Next(100)
        $state = $(if ([string]$t.evidence.tier -eq 'R') { 'Off' } elseif ($roll -lt 46) { 'On' } elseif ($roll -lt 78) { 'Off' } elseif ($roll -lt 86) { 'Partial' } elseif ($roll -lt 94) { 'NotApplicable' } else { 'Off' })
        $states[[string]$t.id] = [pscustomobject]@{
            Id = [string]$t.id; State = $state; Items = @(New-IgwtMockStateItems -Tweak $t -State $state); Applicable = ($state -ne 'NotApplicable')
            Reason = $(if ($state -eq 'NotApplicable') { 'Not applicable on this hardware or edition.' } else { '' }); Policy = $null; Blocked = $false; Authority = $null
        }
        $changed[[string]$t.id] = ($state -in 'On', 'Partial')
    }
    $tagIds = @('cpu-amd', 'cpu-x3d', 'gpu-nvidia', 'nic-realtek', 'desktop', 'nvme')
    $allTags = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'hardware\tags.json')).tags)
    $tags = @($allTags | Select-Object -First 6 | ForEach-Object { [pscustomobject]@{ Id = [string]$_.id; Name = [string]$_.name; Group = [string]$_.group; Hint = [string]$_.hint; Basis = 'detected' } })
    $tagIds = @($tags | ForEach-Object { $_.Id })
    $overlays = @(Get-IgwtActiveOverlays -Tags $tagIds | ForEach-Object { [pscustomobject]@{ Name = [string]$_.name; Hint = [string]$_.hint; Tags = (@($_.MatchedTags) -join ', '); Guidance = (@($_.guidance | Where-Object { $_ }) -join ' ') } })
    $selections = @{}
    foreach ($p in @(Get-IgwtPreset)) { try { $selections[[string]$p.id] = Resolve-IgwtPresetSelection -Preset $p -Tags $tagIds } catch { Write-Verbose "mock preset $($p.id): $($_.Exception.Message)" } }
    $summary = [pscustomobject]@{ Cpu = 'AMD Ryzen 7 7800X3D 8-Core'; Gpu = 'NVIDIA GeForce RTX 4070 SUPER'; Memory = '32 GB DDR5-6000'; Os = 'Windows 11 Pro 25H2 (26200.6584)'; Text = 'AMD Ryzen 7 7800X3D | NVIDIA GeForce RTX 4070 SUPER | 32 GB DDR5-6000 | Windows 11 Pro 25H2' }
    $req = [ordered]@{}
    foreach ($k in 'tpm', 'secureBoot', 'secureBoot2023', 'vbs', 'hvci', 'iommu', 'win11', 'win1125h2', 'noTestSign') {
        $names = @{ tpm = 'TPM 2.0 ready'; secureBoot = 'Secure Boot on'; secureBoot2023 = 'Secure Boot 2023 certificates'; vbs = 'Virtualization-based security running'; hvci = 'Memory integrity (HVCI) running'; iommu = 'IOMMU / Kernel DMA protection'; win11 = 'Windows 11'; win1125h2 = 'Windows 11 25H2 or later'; noTestSign = 'Test signing off' }
        $req[$k] = [pscustomobject]@{ Name = $names[$k]; Pass = ($k -ne 'secureBoot2023'); Unknown = $false; Detail = '' }
    }
    $matrix = @(
        @('faceit', 'FACEIT Anti-Cheat (CS2)', 'Ready'), @('vanguard', 'Riot Vanguard (VALORANT, LoL)', 'Ready'), @('vanguardOnDemand', 'Riot Vanguard On-Demand mode', 'Ready'),
        @('ricochet', 'Call of Duty (RICOCHET)', 'Ready'), @('javelin', 'Battlefield 6 (Javelin)', 'Ready'), @('eac', 'Easy Anti-Cheat', 'Ready'), @('battleye', 'BattlEye', 'Ready')
    ) | ForEach-Object { [pscustomobject]@{ Id = $_[0]; Name = $_[1]; Status = $_[2]; Missing = @(); Unknown = @(); Note = '' } }
    $ac = [pscustomobject]@{ Overall = 'Ready'; Requirements = [pscustomobject]$req; Matrix = $matrix }
    $health = $null
    if ($IncludeHealth) {
        $checks = New-Object System.Collections.Generic.List[object]
        $defs = @(
            @('System', 'os', 'Windows build', 'Pass', '26200.6584 (25H2)'), @('System', 'uptime', 'Uptime', 'Pass', '2 days'), @('System', 'pending', 'Pending restart', 'Pass', 'None'),
            @('System', 'restore', 'System Protection', 'Pass', 'On (C:)'), @('Security', 'defender', 'Microsoft Defender Antivirus', 'Pass', 'Active, up to date'), @('Security', 'firewall', 'Windows Firewall', 'Pass', 'On for all profiles'),
            @('Security', 'tpm', 'TPM 2.0', 'Pass', 'Ready'), @('Security', 'secureboot', 'Secure Boot', 'Pass', 'On'), @('Security', 'sb2023', 'Secure Boot 2023 certificates', 'Warn', 'Not installed yet'),
            @('Security', 'hvci', 'Memory integrity', 'Pass', 'Running'), @('Performance', 'power', 'Power plan', 'Pass', 'Balanced'), @('Performance', 'gamemode', 'Game Mode', 'Pass', 'On'),
            @('Performance', 'hags', 'Hardware-accelerated GPU scheduling', 'Pass', 'On'), @('Performance', 'vrr', 'Variable refresh rate', 'Info', 'Monitor dependent'), @('Drivers', 'gpu', 'GPU driver', 'Pass', '581.42 (2 weeks old)'),
            @('Drivers', 'chipset', 'Chipset driver', 'Warn', '14 months old'), @('Network', 'nic', 'Network adapter', 'Pass', '2.5 Gbps wired'), @('Network', 'dns', 'DNS resolver', 'Pass', 'Router')
        )
        foreach ($d in $defs) { $checks.Add([pscustomobject]@{ Section = $d[0]; Id = $d[1]; Name = $d[2]; Status = $d[3]; Value = $d[4]; Detail = ''; Advice = $(if ($d[3] -eq 'Warn') { 'See the item details.' } else { '' }); Source = '' }) }
        $secChecks = @(
            @('defender', 'Defender real-time protection', 'Pass', 10), @('cloud', 'Cloud-delivered protection', 'Pass', 6), @('pua', 'Potentially unwanted app blocking', 'Pass', 4), @('asr', 'Attack surface reduction baseline', 'Pass', 8),
            @('np', 'Network protection', 'Fail', 5), @('hvci', 'Memory integrity', 'Pass', 10), @('lsa', 'LSA protection', 'Pass', 6), @('smb1', 'SMBv1 off', 'Pass', 5),
            @('uac', 'UAC on', 'Pass', 8), @('fw', 'Firewall on', 'Pass', 8), @('ss', 'SmartScreen', 'Pass', 5), @('drv', 'Vulnerable driver blocklist', 'Fail', 5)
        ) | ForEach-Object { [pscustomobject]@{ Id = $_[0]; Name = $_[1]; Status = $_[2]; Value = $(if ($_[2] -eq 'Pass') { 'On' } else { 'Off' }); Weight = $_[3]; Earned = $(if ($_[2] -eq 'Pass') { [double]$_[3] } else { 0.0 }); Counted = $true; Fix = $(if ($_[2] -eq 'Fail') { 'sec.' + $_[0] } else { '' }); Target = ''; Hint = ''; Description = '' } }
        $sec = [pscustomobject]@{ Generated = $script:MockNow.ToString('o'); Score = 88; Grade = 'B+'; Earned = 70.0; Possible = 80.0; Checks = $secChecks; ToFix = @($secChecks | Where-Object Status -EQ 'Fail') }
        $health = [pscustomobject]@{
            Generated = $script:MockNow.ToString('o'); Tool = 'iG Windows Tuner'; Computer = 'DEMO-PC'; Elevated = $true; Summary = $summary
            Hardware = [pscustomobject]@{ Tags = $tags; Overlays = $overlays }; Checks = $checks.ToArray(); AntiCheat = $ac; Security = $sec
            Games = @([pscustomobject]@{ Id = 'cs2'; Name = 'Counter-Strike 2'; ExePath = 'D:\Games\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe'; AntiCheat = 'VAC' })
            NvidiaGuidance = @([pscustomobject]@{ Item = 'Low Latency Mode'; Advice = 'Use Reflex in games that support it; otherwise On.' }, [pscustomobject]@{ Item = 'Power management mode'; Advice = 'Normal; Prefer maximum performance only per game.' })
            Recommendations = @([pscustomobject]@{ Title = 'Turn on network protection'; Text = 'Blocks connections to known-bad sites in every app.'; Source = 'Security' }, [pscustomobject]@{ Title = 'Install the Secure Boot 2023 certificates'; Text = 'Windows Update delivers them; needed before 2026 certificate expiry.'; Source = 'Health' })
        }
    }
    $snaps = @(for ($i = 0; $i -lt 12; $i++) {
            $t = $script:MockNow.AddHours(-7 * $i - 1)
            $ops = @('Apply', 'Preset:competitive', 'ASR', 'Manage', 'Defender', 'Power', 'Revert')
            $op = $ops[$i % $ops.Count]
            [pscustomobject]@{ Path = "C:\ProgramData\iGWindowsTuner\Backups\snapshot-$($t.ToString('yyyyMMdd-HHmmss'))-$op.json"; File = "snapshot-$($t.ToString('yyyyMMdd-HHmmss'))-$op.json"; Created = $t.ToUniversalTime().ToString('o'); Operation = $op; Detail = ''; Applied = @('net.example'); Count = 1 + ($i % 4); Failed = 0 }
        })
    $startup = @(
        @('HKCU', 'Steam', '"C:\Program Files (x86)\Steam\steam.exe" -silent', $true), @('HKCU', 'Discord', '"C:\Users\Player\AppData\Local\Discord\Update.exe" --processStart Discord.exe', $true),
        @('HKLM', 'SecurityHealth', '%windir%\system32\SecurityHealthSystray.exe', $true), @('HKCU', 'OneDrive', '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', $false),
        @('HKLM', 'NVIDIA App', '"C:\Program Files\NVIDIA Corporation\NVIDIA App\CEF\NVIDIA App.exe" --minimized', $true), @('HKCU', 'Spotify', '"C:\Users\Player\AppData\Roaming\Spotify\Spotify.exe" --autostart', $false)
    ) | ForEach-Object { [pscustomobject]@{ Scope = $_[0]; Name = $_[1]; Command = $_[2]; Enabled = $_[3]; Machine = ($_[0] -eq 'HKLM'); Location = "$($_[0])\Software\Microsoft\Windows\CurrentVersion\Run" } }
    $os = [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; EditionId = 'Professional'; DisplayVersion = '25H2'; Build = 26200; Ubr = 6584; FullBuild = '26200.6584'; LastBootUpTime = $script:MockNow.AddDays(-2); Uptime = [timespan]::FromDays(2) }
    [pscustomobject]@{
        Hardware = [pscustomobject]@{ Tags = $tags; Overlays = $overlays }; PresetSelections = $selections; IsAdmin = $true
        Preflight = [pscustomobject]@{ IsAdmin = $true; Os = $os; Build = 26200; EditionId = 'Professional'; IsPro = $true; SupportedBuild = $true; PendingReboot = @(); Power = [pscustomobject]@{ IsPortable = $false; HasBattery = $false; OnBattery = $false }; IsRdpSession = $false; Warnings = @(); Errors = @(); CanApply = $true }
        Summary = $summary; Pending = $null; States = $states; Changed = $changed; Health = $health; AntiCheat = $ac; Snapshots = $snaps; Startup = $startup
        Games = @([pscustomobject]@{ Id = 'cs2'; Name = 'Counter-Strike 2'; ExePath = 'D:\Games\cs2.exe'; AntiCheat = 'VAC' })
    }
}

function script:Invoke-IgwtCleanerScan {
    [CmdletBinding()]
    param([string]$Level = 'Standard', [switch]$IncludeOptIn, [switch]$AllUsers, [string[]]$RuleId, $CancellationToken, [scriptblock]$OnProgress)
    $rules = @(Get-IgwtCleanerRules)
    $rows = foreach ($r in $rules) {
        $rnd = Get-IgwtMockRandom -Seed ([string]$r.id)
        $bytes = [long]($rnd.Next(1, 4000)) * 1MB / 10
        $skip = ($rnd.Next(10) -eq 0)
        [pscustomobject]@{ RuleId = [string]$r.id; Name = [string]$r.name; Category = [string]$r.category; Level = [string]$r.level; Method = [string]$r.method; Default = [bool]$r.default; Hint = [string]$r.hint; SideEffects = [string]$r.sideEffects
            Status = $(if ($skip) { 'Skipped' } else { 'Ready' }); Reason = $(if ($skip) { 'The app is running; close it to clean this cache.' } else { '' }); Bytes = $(if ($skip) { 0 } else { $bytes }); Count = $rnd.Next(5, 3000)
            Roots = @(); Items = $null; Directories = $null; Skipped = @{}; SkippedSamples = @{}; Samples = @(); Truncated = $false; Cancelled = $false; Extra = $null; Blockers = @(); ResolvedRoots = @() }
    }
    $rows = @($rows)
    [pscustomobject]@{ Id = 'mock'; Created = $script:MockNow.ToString('o'); AllUsers = $false; Rules = $rows; TotalBytes = [long](($rows | Measure-Object Bytes -Sum).Sum); TotalCount = [int](($rows | Measure-Object Count -Sum).Sum) }
}

function script:Get-IgwtDiskUsage {
    [CmdletBinding()]
    param([string]$Path, [int]$Top = 12, $CancellationToken, [scriptblock]$OnProgress)
    $folders = @('Steam\steamapps\common\Cyberpunk 2077', 'Steam\steamapps\common\Call of Duty', 'Battle.net\Diablo IV', 'Riot Games\VALORANT', 'Epic Games\Fortnite', 'Steam\steamapps\common\Baldurs Gate 3', 'Steam\steamapps\shadercache', 'Captures', 'Steam\steamapps\downloading', 'Mods', 'Ubisoft\Assassins Creed Shadows', 'EA Games\Battlefield 6')
    $i = 0
    $f = foreach ($n in $folders) { $i++; [pscustomobject]@{ Path = "D:\Games\$n"; Bytes = [long](120 - 9 * $i) * 1GB; Files = 4000 + 700 * $i; Depth = 1 } }
    $files = foreach ($n in 1..$Top) { [pscustomobject]@{ Path = "D:\Games\Steam\steamapps\common\Cyberpunk 2077\archive\pc\content\basegame_$n.archive"; Bytes = [long](40 - 2 * $n) * 1GB / 4; LastWrite = $script:MockNow.AddDays(-$n) } }
    [pscustomobject]@{ Root = 'D:\Games'; TotalBytes = 980GB; Files = 412000; Folders = @($f | Select-Object -First $Top); LargestFiles = @($files); AccessDenied = 0; ReparseSkipped = 2; Cancelled = $false }
}

function script:Get-IgwtInspection {
    [CmdletBinding()]
    param([string[]]$Area)
    $proc = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'power\processor.json')).settings)
    $settings = foreach ($p in $proc) {
        $rnd = Get-IgwtMockRandom -Seed ([string]$p.alias)
        $ac = $rnd.Next(0, 100)
        [pscustomobject]@{ Guid = [string]$p.guid; Alias = [string]$p.alias; Name = "Processor $(([string]$p.group).ToLowerInvariant()) setting ($($p.alias))"; Group = [string]$p.group; AC = [long]$ac; DC = [long]$ac; AcText = "$ac"; DcText = "$ac"; DefaultAC = $ac; DefaultDC = $ac; DefaultSource = 'Balanced'
            ChangedFromDefault = ($rnd.Next(4) -eq 0); Min = [long]0; Max = [long]100; Increment = [long]1; Units = '%'; Options = @(); Hidden = $false; Editable = $true; Level = [string]$p.level; Hint = [string]$p.hint; Description = [string]$p.description
            Blocked = $false; BlockReason = ''; DcBlocked = $false; DcBlockReason = ''; Sources = $p.sources }
    }
    $devs = @('NVIDIA GeForce RTX 4070 SUPER', 'Realtek Gaming 2.5GbE Family Controller', 'AMD USB 3.20 eXtensible Host Controller', 'High Definition Audio Controller', 'Standard NVM Express Controller', 'AMD PCI Express GPP Bridge') | ForEach-Object {
        [pscustomobject]@{ Name = $_; Class = 'System'; InstanceId = 'PCI\VEN_0000&DEV_0000\0'; Status = 'OK'; Supports = @('LineBased', 'MSI'); MessageMaximum = [uint32]8; CurrentMode = 'MSI'; Messages = 1; Irqs = @(); MsiSupported = [uint32]1; MessageLimit = [uint32]0; DevicePolicy = $null; PolicyName = 'Default'; DevicePriority = $null; PriorityName = 'Undefined'; TargetCpus = @(); CatalogClass = ''; Note = '' }
    }
    $kernelKeys = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'inspectors\kernel.json')).keys) | ForEach-Object {
        $k = $_
        [pscustomobject]@{ Id = [string]$k.id; Name = [string]$k.name; Path = [string]$k.path; Hint = [string]$k.hint; Description = [string]$k.description; Readable = $true; Changed = 0
            Values = @($k.values | ForEach-Object { [pscustomobject]@{ Name = [string]$_.name; Kind = 'DWord'; Current = [string]$_.default; Default = [string]$_.default; Status = 'Default'; Meaning = [string]$_.meaning; Item = [string]$_.item; Rejected = [string]$_.rejected; Sources = $_.sources } }) }
    }
    $q = [pscustomobject]@{ Keyword = '*NumRssQueues'; DisplayName = 'Maximum Number of RSS Queues'; Value = '4'; DisplayValue = '4 Queues'; Default = '4'; Min = $null; Max = $null; Allowed = @('1', '2', '4') }
    $rb = [pscustomobject]@{ Keyword = '*ReceiveBuffers'; DisplayName = 'Receive Buffers'; Value = '512'; DisplayValue = '512'; Default = '512'; Min = '80'; Max = '1024'; Allowed = @() }
    [pscustomobject]@{
        Generated = $script:MockNow.ToString('o'); Elevated = $true
        Power = [pscustomobject]@{ Scheme = '381b4222-f694-41f0-9685-ff5bb260df2e'; SchemeName = 'Balanced'; Subgroup = 'Processor power management'; Tags = @('cpu-amd', 'cpu-x3d'); Settings = @($settings); Editable = @($settings).Count; Changed = 2; DefaultsFrom = 'Balanced'; Note = '' }
        Interrupts = [pscustomobject]@{ Devices = @($devs); MessageSignaled = 6; LineBased = 0; Note = '' }
        Network = [pscustomobject]@{ Adapters = @([pscustomobject]@{ Name = 'Ethernet'; Description = 'Realtek Gaming 2.5GbE Family Controller'; Status = 'Up'; LinkSpeed = '2.5 Gbps'; RssEnabled = $true; RssProfile = 'NUMAStatic'; BaseProcessor = $null; MaxProcessor = $null; ReceiveQueues = 4; Queues = $q; BaseProcessorProp = $null; ReceiveBuffers = $rb; TransmitBuffers = $rb; DiscardedPackets = [long]0; ReceiveErrors = [long]0; Advice = @('RSS is on with 4 queues.') }); Note = '' }
        Kernel = [pscustomobject]@{ Keys = @($kernelKeys); Changed = 0; Note = '' }
        Timer = [pscustomobject]@{ GlobalTimerResolutionRequests = $null; Behaviour = 'Default (per-process timer resolution)'; Item = ''; CurrentResolution = $null; Note = ''; Sources = @('https://learn.microsoft.com/') }
        Crash = [pscustomobject]@{ DumpType = [uint32]3; DumpTypeName = 'Small memory dump'; AutoReboot = [uint32]1; DisplayParameters = $null; DumpFile = '%SystemRoot%\MEMORY.DMP'; DumpFileBytes = $null; MinidumpFolder = '%SystemRoot%\Minidump'; Minidumps = 0; MinidumpBytes = [long]0; LatestMinidump = $null; VerboseStatus = [uint32]0; PageFileMode = 'System managed'; PagingFiles = @('?:\pagefile.sys'); PageFiles = @([pscustomobject]@{ Path = 'C:\pagefile.sys'; AllocatedMB = 4864; CurrentMB = 412; PeakMB = 1290 }); Advice = @(); Items = @('system.small-dumps') }
    }
}

function script:New-IgwtMockFirewallRules {
    param([int]$Count = 1200)
    $apps = @('C:\Program Files (x86)\Steam\steam.exe', 'D:\Games\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe', 'C:\Program Files\Discord\Discord.exe', 'C:\Users\Player\AppData\Local\Programs\Tool\tool.exe', 'C:\Program Files\NVIDIA Corporation\NVIDIA App\NVIDIA App.exe', 'Any')
    $groups = @('Core Networking', 'Remote Desktop', 'File and Printer Sharing', 'Network Discovery', 'Windows Defender Firewall Remote Management', 'Delivery Optimization', 'mDNS', 'Cast to Device functionality', '')
    for ($i = 0; $i -lt $Count; $i++) {
        $rnd = Get-IgwtMockRandom -Seed "fw$i"
        $win = ($rnd.Next(10) -lt 7)
        $dir = $(if ($rnd.Next(2) -eq 0) { 'Inbound' } else { 'Outbound' })
        $grp = $(if ($win) { $groups[$rnd.Next($groups.Count - 1)] } else { '' })
        $app = $(if ($win) { '%SystemRoot%\system32\svchost.exe' } else { $apps[$rnd.Next($apps.Count)] })
        $name = $(if ($win) { "$grp ($(@('TCP-In', 'UDP-In', 'TCP-Out', 'UDP-Out', 'ICMPv4-In', 'ICMPv6-In')[$rnd.Next(6)]))" } else { "$([System.IO.Path]::GetFileNameWithoutExtension($app)) rule $i" })
        [pscustomobject]@{ Name = "{mock-$i}"; DisplayName = $name; Direction = $dir; Action = $(if ($rnd.Next(12) -eq 0) { 'Block' } else { 'Allow' }); Enabled = ($rnd.Next(10) -lt 6)
            Profile = @('Any', 'Domain, Private', 'Private', 'Public', 'Domain')[$rnd.Next(5)]; Group = $grp; Program = $app; IsWindowsRule = $win; CanChange = (-not $win) }
    }
}

function script:Get-IgwtGuiManageData {
    [CmdletBinding()]
    param()
    $svcNames = @('AudioSrv', 'BITS', 'Dnscache', 'EventLog', 'gpsvc', 'LanmanServer', 'mpssvc', 'Spooler', 'SysMain', 'Themes', 'W32Time', 'WinDefend', 'WSearch', 'wuauserv', 'XblAuthManager', 'XboxGipSvc', 'DiagTrack', 'dmwappushservice', 'MapsBroker', 'Fax', 'RemoteRegistry', 'TabletInputService', 'SteamClientService', 'NVDisplay.ContainerLocalSystem', 'GameInputSvc', 'EasyAntiCheat_EOS', 'vgc', 'BEService', 'TrustedInstaller', 'CryptSvc')
    $services = for ($i = 0; $i -lt 260; $i++) {
        $rnd = Get-IgwtMockRandom -Seed "svc$i"
        $n = $(if ($i -lt $svcNames.Count) { $svcNames[$i] } else { "DemoService$i" })
        $prot = ($n -in 'WinDefend', 'mpssvc', 'EventLog', 'gpsvc', 'TrustedInstaller', 'CryptSvc', 'wuauserv', 'Dnscache', 'EasyAntiCheat_EOS', 'vgc', 'BEService')
        [pscustomobject]@{ Name = $n; DisplayName = "$n service"; Description = 'Demo service description.'; State = @('Running', 'Stopped')[$rnd.Next(2)]; StartupType = @('Automatic', 'Manual', 'Disabled', 'AutomaticDelayed')[$rnd.Next(4)]; Account = 'LocalSystem'; Path = 'C:\Windows\system32\svchost.exe -k demo'
            Rating = $(if ($prot) { 'Protected' } elseif ($n -in 'DiagTrack', 'dmwappushservice', 'MapsBroker', 'Fax') { 'Catalogued' } elseif ($n -like 'Demo*' -or $n -like 'Steam*' -or $n -like 'NV*') { 'ThirdParty' } else { 'Windows' }); Advice = ''; CatalogItems = @(); DependsOn = ''; Dependents = $null; CanChange = (-not $prot) }
    }
    $tasks = for ($i = 0; $i -lt 180; $i++) {
        $rnd = Get-IgwtMockRandom -Seed "task$i"
        $folder = @('\Microsoft\Windows\Application Experience\', '\Microsoft\Windows\Customer Experience Improvement Program\', '\Microsoft\Windows\Defrag\', '\Microsoft\Windows\WindowsUpdate\', '\', '\Microsoft\Windows\Windows Defender\')[$rnd.Next(6)]
        $ms = ($folder -ne '\'); $prot = ($folder -match 'WindowsUpdate|Defender')
        [pscustomobject]@{ Path = "${folder}Task$i"; TaskPath = $folder; Name = "Task$i"; State = @('Ready', 'Disabled', 'Running')[$rnd.Next(3)]; Author = $(if ($ms) { 'Microsoft Corporation' } else { 'Demo Vendor' }); Description = 'Demo task.'; Action = 'C:\Windows\system32\demo.exe'; IsMicrosoft = $ms; Protected = $prot; CanDisable = (-not $prot) }
    }
    $win32 = @('Steam', 'Discord', '7-Zip 24.08', 'NVIDIA App', 'Mozilla Firefox', 'OBS Studio', 'Notepad++', 'VLC media player', 'Logitech G HUB', 'Battle.net', 'Epic Games Launcher', 'Riot Vanguard') | ForEach-Object { [pscustomobject]@{ Name = $_; Version = '1.0'; Publisher = 'Demo Publisher'; InstallDate = '20260901'; SizeMB = $null; Scope = 'Machine' } }
    $appx = @('Microsoft.WindowsCalculator', 'Microsoft.XboxGamingOverlay', 'Microsoft.GamingApp', 'Microsoft.BingNews', 'Microsoft.WindowsStore', 'Microsoft.ZuneMusic', 'Microsoft.Todos', 'Clipchamp.Clipchamp', 'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.Windows.Photos') | ForEach-Object { $prot = ($_ -in 'Microsoft.WindowsStore', 'Microsoft.GamingApp'); [pscustomobject]@{ Name = $_; Version = '1.0.0.0'; Publisher = 'CN=Microsoft Corporation'; Inbox = $true; Protected = $prot; CanRemove = (-not $prot); Note = '' } }
    $persist = for ($i = 0; $i -lt 50; $i++) {
        $rnd = Get-IgwtMockRandom -Seed "pe$i"
        $sev = @('OK', 'OK', 'OK', 'Review', 'Warn')[$rnd.Next(5)]
        [pscustomobject]@{ Category = @('Run keys', 'Services', 'Scheduled tasks', 'Startup folder', 'WMI', 'Winlogon')[$rnd.Next(6)]; Location = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'; Name = "Entry $i"; Command = 'C:\Program Files\Demo\demo.exe /background'; File = 'C:\Program Files\Demo\demo.exe'
            Signature = $(if ($sev -eq 'Warn') { 'NotSigned' } else { 'Valid' }); Signer = 'Demo Publisher'; IsMicrosoft = $false; Enabled = $true; Severity = $sev; Note = ''; ActionKind = 'StartupApproved'; ActionTarget = "Entry $i" }
    }
    $rules = @(New-IgwtMockFirewallRules -Count 1200)
    [pscustomobject]@{
        Services = [pscustomobject]@{ Services = @($services); Counts = [pscustomobject]@{ Total = 260; Running = 120; Protected = 40; ThirdParty = 18 }; Note = '' }
        Tasks = [pscustomobject]@{ Tasks = @($tasks); Counts = [pscustomobject]@{ Total = 180; Disabled = 30; ThirdParty = 12 }; Note = '' }
        Apps = [pscustomobject]@{ Win32 = @($win32); Appx = @($appx); Note = '' }
        Persistence = [pscustomobject]@{ Generated = $script:MockNow.ToString('o'); Entries = @($persist); Counts = [pscustomobject]@{ Total = 50; Warn = 6; Review = 9 }; Note = '' }
        Firewall = [pscustomobject]@{ Rules = $rules; AppRules = @($rules | Where-Object { -not $_.IsWindowsRule }).Count; Note = '' }
        Hosts = [pscustomobject]@{ Path = 'C:\Windows\System32\drivers\etc\hosts'; Exists = $true; Entries = @(); Unexpected = 0; Note = '' }
    }
}

function script:Get-IgwtGuiDiagnosticsData {
    [CmdletBinding()]
    param([int]$Days = 30)
    $samples = @(1..3 | ForEach-Object { [pscustomobject]@{ Dpc = 0.4; Isr = 0.1; Cpu = 6.0; InterruptsPerSec = 9000.0; DpcRate = 1200.0 } })
    $stat = { param($a, $m) [pscustomobject]@{ Average = [double]$a; Max = [double]$m } }
    $dpc = [pscustomobject]@{ Samples = $samples; Dpc = (& $stat 0.4 0.6); Isr = (& $stat 0.1 0.2); DpcRate = (& $stat 1200 1500); Interrupts = (& $stat 9000 11000); Cpu = (& $stat 6 9)
        TopProcesses = @(@('cs2', 41.2), @('steamwebhelper', 3.1), @('Discord', 2.4), @('dwm', 1.8)) | ForEach-Object { [pscustomobject]@{ Name = $_[0]; ProcessId = 4000; CpuPercent = [double]$_[1]; WorkingSetMB = 900.0 } }; Advice = @(); Note = '' }
    $rel = [pscustomobject]@{ Days = $Days; Index = @(0..29 | ForEach-Object { [pscustomobject]@{ Time = $script:MockNow.AddDays(-$_); Index = [double](9 - ($_ % 4) * 0.5) } }); Current = 8.6
        Records = @(0..9 | ForEach-Object { [pscustomobject]@{ Time = $script:MockNow.AddDays(-2 * $_); Source = 'Application Error'; Product = 'Demo.exe'; EventId = 1000; Message = 'Faulting application demo.exe' } }); Error = ''; Note = '' }
    $crash = [pscustomobject]@{ Days = $Days; Events = @([pscustomobject]@{ Time = $script:MockNow.AddDays(-9); Kind = 'AppCrash'; EventId = 1000; Detail = 'demo.exe' }); Counts = [pscustomobject]@{ BugCheck = 0; KernelPower41 = 0; UnexpectedShutdown = 0; AppCrash = 1 }; Minidumps = @(); MinidumpFolder = 'C:\Windows\Minidump'; DumpType = 'Small memory dump'; Advice = @(); Note = '' }
    $drivers = for ($i = 0; $i -lt 60; $i++) { $rnd = Get-IgwtMockRandom -Seed "drv$i"; [pscustomobject]@{ Device = "Demo device $i"; Class = @('System', 'Display', 'Net', 'MEDIA', 'USB', 'HIDClass')[$rnd.Next(6)]; Version = "1.0.$i"; Date = $script:MockNow.AddDays(-30 * $rnd.Next(1, 50)).ToString('yyyy-MM-dd'); Provider = 'Demo Vendor'; Signer = 'Microsoft Windows Hardware Compatibility Publisher'; Inf = "oem$i.inf"; Signed = $true; Flag = $(if ($rnd.Next(8) -eq 0) { 'Old' } else { '' }) } }
    $updates = [pscustomobject]@{ Services = @(@('wuauserv', 'Running', 'Manual'), @('BITS', 'Running', 'AutomaticDelayed'), @('UsoSvc', 'Running', 'Automatic'), @('WaaSMedicSvc', 'Stopped', 'Manual')) | ForEach-Object { [pscustomobject]@{ Name = $_[0]; Status = $_[1]; StartType = $_[2] } }
        PendingRestart = @(); Policies = @(); LastSuccess = $script:MockNow.AddDays(-1); History = @(0..39 | ForEach-Object { [pscustomobject]@{ Date = $script:MockNow.AddDays(-3 * $_); Title = "2026-$('{0:D2}' -f (10 - [int]($_ / 4))) Cumulative Update for Windows 11 Version 25H2 (KB50$('{0:D5}' -f (99000 - $_)))"; Result = $(if ($_ -eq 5) { 'Failed' } else { 'Succeeded' }); HResult = '0x0' } }); Failed = 1; Error = ''; Advice = @(); Note = '' }
    $props = @(@('*EEE', 'Energy Efficient Ethernet', 'Disabled', 'Enabled'), @('*FlowControl', 'Flow Control', 'Rx & Tx Enabled', 'Rx & Tx Enabled'), @('*InterruptModeration', 'Interrupt Moderation', 'Enabled', 'Enabled'), @('*JumboPacket', 'Jumbo Frame', 'Disabled', 'Disabled'), @('*RSS', 'Receive Side Scaling', 'Enabled', 'Enabled'), @('*SpeedDuplex', 'Speed & Duplex', 'Auto Negotiation', 'Auto Negotiation')) | ForEach-Object { [pscustomobject]@{ Keyword = $_[0]; DisplayName = $_[1]; Value = $_[2]; RegistryValue = '1'; Default = $_[3]; Allowed = ''; Range = ''; Standardized = $true; Description = 'Standardized NDIS keyword.'; ChangedFromDefault = ($_[2] -ne $_[3]) } }
    [pscustomobject]@{
        Diagnostics = [pscustomobject]@{ Generated = $script:MockNow.ToString('o'); DpcIsr = $dpc; Reliability = $rel; Crashes = $crash; Boot = [pscustomobject]@{ Boots = @(); AverageBootSeconds = $null; Error = 'Needs administrator rights.'; Note = '' }; Drivers = [pscustomobject]@{ Drivers = @($drivers); Counts = [pscustomobject]@{ Total = 60; Unsigned = 0; Old = 7 }; Note = '' } }
        Updates = $updates
        Adapters = [pscustomobject]@{ Adapters = @([pscustomobject]@{ Name = 'Ethernet'; Description = 'Realtek Gaming 2.5GbE Family Controller'; Status = 'Up'; LinkSpeed = '2.5 Gbps'; Properties = @($props) }); Note = '' }
    }
}

function script:Get-IgwtGuiToolkitData {
    [CmdletBinding()]
    param([switch]$WithAppState)
    $features = @(Get-IgwtToolkitFeatures | ForEach-Object { $_ | Add-Member -NotePropertyName Supported -NotePropertyValue $true -Force -PassThru | Add-Member -NotePropertyName State -NotePropertyValue $(if ((Get-IgwtMockRandom -Seed ([string]$_.Id)).Next(2)) { 'On' } else { 'Off' }) -Force -PassThru | Add-Member -NotePropertyName TargetStates -NotePropertyValue @() -Force -PassThru })
    [pscustomobject]@{ Apps = @(Get-IgwtToolkitApps); AppState = [bool]$WithAppState; Consent = $true; Features = $features; Fixes = @(Get-IgwtToolkitFixes); Panels = @(Get-IgwtToolkitPanels) }
}

function script:Get-IgwtAsrStatus {
    [CmdletBinding()]
    param()
    $cat = @((Read-IgwtJsonFile -Path (Join-Path (Get-IgwtDataFolder) 'asr\rules.json')).rules)
    $rules = foreach ($r in $cat) {
        $mode = $(if ([string]$r.recommendedMode -eq 'Block') { 'Block' } elseif ([string]$r.gamerImpactLevel -in 'medium', 'high') { 'Audit' } elseif ($r.serverOnly) { 'NotConfigured' } else { 'Warn' })
        $code = @{ Block = 1; Audit = 2; Warn = 6; NotConfigured = 0 }[$mode]
        [pscustomobject]@{ Id = [string]$r.id; Key = [string]$r.key; Name = [string]$r.name; Category = [string]$r.category; MsCategory = [string]$r.msCategory; Mode = $mode; Code = $code; Source = $(if ($mode -eq 'NotConfigured') { 'NotSet' } else { 'Local' }); ManagedByPolicy = $false
            Recommended = [string]$r.recommendedMode; MeetsRecommendation = $true; AllowedModes = @(@('NotConfigured', 'Audit') + $(if ($r.supportsWarn) { @('Warn') } else { @() }) + @('Block')); SupportsWarn = [bool]$r.supportsWarn; RequiresCloud = [bool]$r.requiresCloud; CloudMissing = $false
            ServerOnly = [bool]$r.serverOnly; AppliesTo = [string]$r.appliesTo; Hint = [string]$r.hint; Description = [string]$r.description; GamerImpact = [string]$r.gamerImpact; GamerImpactLevel = [string]$r.gamerImpactLevel; Notes = [string]$r.notes; Exclusions = @(); ExclusionsVerified = 'yes'; Sources = @($r.sources) }
    }
    $rules = @($rules)
    $count = { param($m) @($rules | Where-Object Mode -EQ $m).Count }
    [pscustomobject]@{ DefenderActive = $true; CloudProtection = $true; TamperProtected = $true; Elevated = $true; Error = ''; Rules = $rules; UnknownRules = @()
        GlobalExclusions = [pscustomobject]@{ Readable = $true; Paths = @(); Note = '' }
        Summary = [pscustomobject]@{ Block = (& $count 'Block'); Warn = (& $count 'Warn'); Audit = (& $count 'Audit'); Off = 0; NotConfigured = (& $count 'NotConfigured'); BelowRecommendation = 0; StandardInBlock = 3; StandardTotal = 3; PolicyManaged = 0; RulesWithExclusions = 0 } }
}

function script:Get-IgwtAsrAudit {
    [CmdletBinding()]
    param([int]$Days = 14)
    $st = Get-IgwtAsrStatus
    $rows = foreach ($r in $st.Rules) {
        $rnd = Get-IgwtMockRandom -Seed ([string]$r.Key)
        $n = $(if ($r.Mode -eq 'Audit') { $rnd.Next(0, 9) } else { $rnd.Next(0, 2) })
        $progs = @(); if ($n) { $progs = @([pscustomobject]@{ Path = 'C:\Program Files\Demo\updater.exe'; Process = 'updater.exe'; Count = $n; Blocked = 0; Audited = $n; WarnBypassed = 0; LastSeen = $script:MockNow.AddHours(-$n); Suggestion = 'Exclude'; Exclusion = 'C:\Program Files\Demo\updater.exe'; Reason = 'Signed updater' }) }
        [pscustomobject]@{ Id = $r.Id; Key = $r.Key; Name = $r.Name; Mode = $r.Mode; Blocked = 0; Audited = $n; WarnBypassed = 0; Total = $n; LastSeen = $(if ($n) { $script:MockNow.AddHours(-$n) } else { $null }); Programs = $progs; Recommendation = $(if ($r.Mode -eq 'Audit' -and -not $n) { 'Promote' } elseif ($n) { 'Review' } else { '' }); RecommendationText = '' }
    }
    $rows = @($rows)
    [pscustomobject]@{ Generated = $script:MockNow.ToString('o'); Readable = $true; Error = ''; Days = $Days; CoverageDays = [double]$Days; Truncated = $false; Rules = $rows; UnknownRules = @()
        ControlledFolderAccess = @([pscustomobject]@{ Process = 'C:\Program Files\Demo\game.exe'; Count = 3; Blocked = 3; Audited = 0; LastPath = 'C:\Users\Player\Documents\My Games\save.dat'; LastSeen = $script:MockNow.AddDays(-1); Advice = 'If you trust this game, allow it in Windows Security.' })
        NetworkProtection = @(); ConfigChanges = @(); Totals = [pscustomobject]@{ AsrBlocked = 0; AsrAudited = (($rows | Measure-Object Audited -Sum).Sum); WarnBypassed = 0; Cfa = 3; Network = 0; ToReview = @($rows | Where-Object Recommendation -EQ 'Review').Count; ToPromote = @($rows | Where-Object Recommendation -EQ 'Promote').Count } }
}

# Defender: the real settings functions run against a synthetic Get-MpPreference with every
# catalog setting at its protective (or a typical) value; sources are Local and policies not configured.
function script:Get-MpPreference {
    $h = [ordered]@{}
    foreach ($s in @((Get-IgwtDefenderSettingCatalog).settings)) {
        $v = $null
        switch ([string]$s.type) {
            'bool' { $v = $(if ($null -ne $s.on) { [bool]$s.on } else { $false }) }
            'enum' { $v = $(if ($null -ne $s.on) { [byte]$s.on } else { [byte]@(Get-IgwtDefenderEnumValues -Definition $s)[0].v }) }
            'uint' { $v = $(if ($null -ne $s.on) { [uint32]$s.on } elseif ($null -ne $s.min) { [uint32]$s.min } else { [uint32]0 }) }
            'time' { $v = [timespan]'02:00:00' }
            'list' { $v = $null }
            default { $v = $(if ([string]$s.mp -eq 'SignatureFallbackOrder') { 'MicrosoftUpdateServer|MMPC' } else { '' }) }
        }
        $h[[string]$s.mp] = $v
    }
    $h['CloudBlockLevel'] = [byte]0; $h['CloudExtendedTimeout'] = [uint32]0; $h['DisableEmailScanning'] = $true; $h['DisableQuicParsing'] = $true
    return [pscustomobject]$h
}
function script:Get-MpComputerStatus { [pscustomobject]@{ AMServiceEnabled = $true; AntivirusEnabled = $true; AMRunningMode = 'Normal'; RealTimeProtectionEnabled = $true; IsTamperProtected = $true; AntivirusSignatureAge = 0; QuickScanAge = 1; FullScanAge = 12; AMEngineVersion = '1.1.25090.3'; AMProductVersion = '4.18.25090.3'; AntivirusSignatureVersion = '1.439.120.0'; SmartAppControlState = 'Off'; DeviceControlState = 'Disabled' } }
function script:Get-IgwtDefenderSettingSource { param($Setting, $PolicyDefinition) return 'Local' }
function script:Get-IgwtPolicyState { param($Policy, [string]$Class) [pscustomobject]@{ Id = $Policy.Id; Class = 'Machine'; LocalGpo = 'NotConfigured'; Registry = @(); Domain = @(); Mdm = $null; Source = 'Not configured'; Tattooed = $false; Conflicts = @() } }
function script:Get-IgwtManagementState { param([switch]$Force) [pscustomobject]@{ Managed = $false; DomainJoined = $false; DomainName = ''; Authorities = @(); LocalGroupPolicy = $true; EditionFamily = 'Pro' } }
function script:Get-IgwtSessionState { [pscustomobject]@{ Active = $false; Stale = $false; Started = $null; Owner = ''; Snapshot = ''; Reason = '' } }
function script:Get-IgwtPersona { return 'Gamer' }
function script:Test-IgwtIsAdmin { return $true }

function script:Invoke-IgwtNetworkQualityTest {
    [CmdletBinding()]
    param([string]$Duration = 'Standard', [string[]]$Target, [switch]$UnderLoad, [scriptblock]$OnProgress)
    $st = { param($m, $j, $l) [pscustomobject]@{ MedianMs = [double]$m; P95Ms = [double]($m + 3); MaxMs = [double]($m + 9); JitterMs = [double]$j; LossPercent = [double]$l; Spikes = 0 } }
    $score = { param($g) [pscustomobject]@{ Grade = $g; Score = 92; Mos = 4.4; Latency = 'A'; Jitter = 'A'; Loss = 'A+'; Stability = 'A'; Verdict = 'Great for competitive online games.' } }
    $targets = @(@('Router', '192.0.2.1', 'Router', 0.4, 0.1), @('ISP gateway', '198.51.100.1', 'ISP', 3.2, 0.4), @('Cloudflare DNS', '1.1.1.1', 'Internet', 6.8, 0.6), @('Game server (EU West)', '203.0.113.20', 'Game', 18.4, 1.1)) | ForEach-Object { [pscustomobject]@{ Name = $_[0]; Address = $_[1]; Role = $_[2]; Stats = (& $st $_[3] $_[4] 0); Score = (& $score 'A') } }
    [pscustomobject]@{ Error = ''; Duration = $Duration; DurationSec = 30; Generated = $script:MockNow.ToString('o'); Score = (& $score 'A'); Internet = [pscustomobject]@{ Stats = (& $st 6.8 0.6 0) }
        Bufferbloat = [pscustomobject]@{ Grade = 'A' }; TypeGuess = [pscustomobject]@{ Local = 'Wired Ethernet'; Access = 'Fiber'; Confidence = 'medium'; Evidence = @('Round trip to the ISP under 5 ms', 'No Wi-Fi in use') }
        Connection = [pscustomobject]@{ Description = 'Realtek Gaming 2.5GbE Family Controller'; Gateway = '192.0.2.1'; IPv6 = $true; Wifi = $null }; Mtu = 1500; Targets = $targets
        Recommendations = [pscustomobject]@{ Profile = 'Wired, low latency'; Tweaks = @([pscustomobject]@{ Id = 'net.nagle-off'; Name = 'Turn off Nagle for games'; Why = 'Sends small game packets right away.'; Level = 'Advanced'; Tier = 'B' }); Reverts = @(); Guidance = @([pscustomobject]@{ Title = 'Use wired Ethernet'; Text = 'Already wired.'; Severity = 'Info' }); TweakIds = @('net.nagle-off') }
        Trace = @(@(1, '192.0.2.1', 0.4, 'Router', ''), @(2, '198.51.100.1', 3.2, 'ISP', ''), @(3, '1.1.1.1', 6.8, 'Internet', 'one.one.one.one')) | ForEach-Object { [pscustomobject]@{ Hop = $_[0]; Address = $_[1]; RttMs = $_[2]; Class = $_[3]; Name = $_[4] } } }
}

function script:Get-IgwtFirewallInventory {
    # 1,200 synthetic rules (Windows, third-party, Store apps, iG Windows Tuner, Group Policy) with
    # the risk cases the page shows; programs under C:\Games\Demo exist, the others do not.
    param([string]$PolicyStore = 'ActiveStore')
    $null = $PolicyStore
    $rnd = Get-IgwtMockRandom -Seed 'firewall-manager'
    $groups = @('Core Networking', 'Remote Desktop', 'File and Printer Sharing', 'Network Discovery', 'Delivery Optimization', 'mDNS', 'Cast to Device functionality', 'Wi-Fi Direct Network Discovery')
    $apps = @('C:\Games\Demo\DemoShooter\shooter.exe', 'C:\Games\Demo\Launcher\launcher.exe', 'C:\Program Files\Demo Voice\voice.exe', 'C:\Users\Player\AppData\Local\DemoUpdater\update.exe', 'C:\Program Files\Old Tool\tool.exe', 'C:\Games\Demo\Racer\racer.exe')
    $rules = New-Object System.Collections.Generic.List[object]; $app = New-Object System.Collections.Generic.List[object]; $port = New-Object System.Collections.Generic.List[object]; $addr = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt 1200; $i++) {
        $kind = $(if ($i % 10 -lt 6) { 'win' } elseif ($i % 10 -lt 8) { 'third' } elseif ($i % 10 -eq 8) { 'store' } elseif ($i % 40 -eq 9) { 'gpo' } elseif ($i % 20 -eq 19) { 'owned' } else { 'third' })
        $name = "DEMO-RULE-$i"; $display = ''; $group = ''; $owner = ''; $storeType = 'Local'; $program = 'Any'; $package = ''
        switch ($kind) {
            'win' { $g = $groups[$i % $groups.Count]; $display = "$g ($(if ($i % 2) { 'In' } else { 'Out' })-$i)"; $group = "@FirewallAPI.dll,-$(30000 + $i % 50)"; $program = $(if ($i % 3) { 'System' } else { '%SystemRoot%\system32\svchost.exe' }) }
            'third' { $p = $apps[$i % $apps.Count]; $display = "$([IO.Path]::GetFileNameWithoutExtension($p)) $(if ($i % 2) { 'TCP' } else { 'UDP' }) $i"; $program = $p }
            'store' { $display = "Demo Store App $($i % 25)"; $owner = "S-1-5-21-0-0-0-$($i % 25)"; $package = "S-1-15-2-$($i % 25)" }
            'gpo' { $display = "Corporate policy $i"; $storeType = 'GroupPolicy' }
            'owned' { $name = "iGWindowsTuner-User-demo$i"; $display = "My rule $i"; $group = 'iG Windows Tuner'; $program = $apps[0] }
        }
        $dir = $(if ($i % 2) { 'Inbound' } else { 'Outbound' })
        $prof = @('Any', 'Private', 'Public', 'Domain', 'Private, Public', 'Domain, Private')[$i % 6]
        $rules.Add([pscustomobject]@{ InstanceID = $name; Name = $name; DisplayName = $display; DisplayGroup = $(if ($group -like '@*') { $groups[$i % $groups.Count] } else { $group }); Group = $group
                Enabled = $(if ($i % 7 -eq 0) { 'False' } else { 'True' }); Direction = $dir; Action = $(if ($i % 9 -eq 0) { 'Block' } else { 'Allow' }); Profile = $prof
                PolicyStoreSourceType = $storeType; PolicyStoreSource = $(if ($storeType -eq 'GroupPolicy') { 'demo.test policy' } else { 'PersistentStore' }); Owner = $owner; EdgeTraversalPolicy = 'Block'; Description = "Demo rule $i for the screenshots." })
        $app.Add([pscustomobject]@{ InstanceID = $name; Program = $program; Package = $package })
        $proto = @('TCP', 'UDP', 'Any', 'ICMPv4', 'TCP', 'UDP')[$i % 6]
        $lp = $(if ($proto -in 'TCP', 'UDP') { @('27015', '3074', '443', '5353', '80', '27015-27030')[$rnd.Next(6)] } else { 'Any' })
        if ($i -eq 13) { $proto = 'Any'; $lp = 'Any'; $app[$app.Count - 1].Program = 'Any' }
        $port.Add([pscustomobject]@{ InstanceID = $name; Protocol = $proto; LocalPort = $lp; RemotePort = 'Any' })
        $addr.Add([pscustomobject]@{ InstanceID = $name; LocalAddress = 'Any'; RemoteAddress = $(if ($i % 11 -eq 0) { 'LocalSubnet' } elseif ($i % 13 -eq 0) { '192.0.2.0/24' } else { 'Any' }) })
    }
    $rows = Join-IgwtFirewallData -Rules $rules.ToArray() -ApplicationFilters $app.ToArray() -PortFilters $port.ToArray() -AddressFilters $addr.ToArray() -PathExists { param($p) $p -like 'C:\Games\Demo\*' -or $p -like '*svchost.exe' -or $p -like 'C:\Program Files\Demo Voice\*' }
    [pscustomobject]@{ Rules = $rows; Count = @($rows).Count; PolicyStore = 'ActiveStore'; Partial = $false; Notes = @(); Timing = [pscustomobject]@{ Rules = 412; Join = 96 }; LoadMs = 640
        Counts = [pscustomobject]@{ Enabled = @($rows | Where-Object Enabled).Count; Risky = 0; Locked = @($rows | Where-Object Locked).Count }; Read = $script:MockNow }
}

function script:Get-IgwtFirewallAudit {
    # The 1,200 demo rules through the real classification, findings, conflict and summary steps,
    # with synthetic listeners, packages and signatures (no system reads).
    param([string]$Role, $Inventory, [switch]$NoListeners, [switch]$NoSignatures)
    $null = $NoListeners, $NoSignatures
    $inv = $(if ($Inventory) { $Inventory } else { Get-IgwtFirewallInventory })
    $rows = @($inv.Rules)
    $listeners = @(
        [pscustomobject]@{ Protocol = 'UDP'; LocalAddress = '0.0.0.0'; LocalPort = 27015; ProcessId = 4100; ProcessName = 'shooter'; Path = 'C:\Games\Demo\DemoShooter\shooter.exe'; Services = @(); Local = $false }
        [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 3074; ProcessId = 4200; ProcessName = 'launcher'; Path = 'C:\Games\Demo\Launcher\launcher.exe'; Services = @(); Local = $false }
        [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 135; ProcessId = 1000; ProcessName = 'svchost'; Path = 'C:\WINDOWS\system32\svchost.exe'; Services = @('RpcSs'); Local = $false }
        [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '127.0.0.1'; LocalPort = 5939; ProcessId = 5100; ProcessName = 'voice'; Path = 'C:\Program Files\Demo Voice\voice.exe'; Services = @(); Local = $true }
        [pscustomobject]@{ Protocol = 'UDP'; LocalAddress = '0.0.0.0'; LocalPort = 5353; ProcessId = 1200; ProcessName = 'svchost'; Path = 'C:\WINDOWS\system32\svchost.exe'; Services = @('Dnscache'); Local = $false }
    )
    $signatures = @{ 'c:\program files\old tool\tool.exe' = [pscustomobject]@{ Status = 'NotSigned'; Signer = '' } }
    $none = [pscustomobject]@{ Role = ''; Categories = [pscustomobject]@{}; NotBloated = @(); Ignored = [pscustomobject]@{} }
    $ctx = Get-IgwtFirewallClassificationContext -Role $(if ($Role) { $Role } else { 'Gamer' }) -InstalledPackages @('Microsoft.WindowsStore') -Signatures $signatures -Overrides $none
    Invoke-IgwtFirewallClassification -Rows $rows -Context $ctx
    $findings = @(Get-IgwtFirewallFindings -Rows $rows -Context $ctx -Listeners $listeners -Now $script:MockNow)
    $relations = @(Get-IgwtFirewallConflicts -Rows $rows)
    $recent = @(
        [pscustomobject]@{ Path = 'C:\ProgramData\iGWindowsTuner\Backups\snapshot-demo-1.json'; Created = $script:MockNow.AddHours(-2); Operation = 'Firewall:Disable'; Detail = 'Disabled 4 Media Center Extenders rules'; Rules = @('DEMO-RULE-12') }
        [pscustomobject]@{ Path = 'C:\ProgramData\iGWindowsTuner\Backups\snapshot-demo-2.json'; Created = $script:MockNow.AddDays(-1); Operation = 'Firewall:Edit'; Detail = 'Restricted "voice TCP 7" to Private networks'; Rules = @('DEMO-RULE-7') }
    )
    # Default rules of the demo build: the Windows rules as shipped, one of them changed since, one removed.
    $defaults = @{}
    foreach ($r in @($rows | Where-Object { $_.IsWindows -and [string]$_.Store -notin 'StaticServiceStore', 'ConfigurableServiceStore' })) { $defaults[[string]$r.Name] = [pscustomobject]@{ Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; Enabled = [bool]$r.Enabled; Direction = [string]$r.Direction; Action = [string]$r.Action; Profile = [string]$r.Profiles; Source = 'SystemDefaults' } }
    $first = @($defaults.Keys | Sort-Object | Select-Object -First 1)
    if ($first.Count) { $defaults[$first[0]].Enabled = -not $defaults[$first[0]].Enabled }
    $defaults['DEMO-REMOVED-In'] = [pscustomobject]@{ Name = 'DEMO-REMOVED-In'; DisplayName = 'Demo default rule (removed)'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; Source = 'SystemDefaults' }
    [pscustomobject]@{
        Rules = $rows; Count = $rows.Count; Summary = (Get-IgwtFirewallAuditSummary -Rows $rows); Findings = $findings; Relations = $relations; Listeners = $listeners
        Exposure = @(Get-IgwtFirewallExposureMap -Rows $rows -Listeners $listeners); RecentChanges = $recent
        Role = $ctx.Role; Partial = $false; Notes = @(); HasDefaults = $true; DefaultRules = $defaults
        Timing = [pscustomobject]@{ Inventory = 640; Classify = 310; Findings = 520 }; LoadMs = 2140; InventoryMs = 640; Read = $script:MockNow
    }
}

function script:Get-IgwtFirewallProfileStatus {
    [pscustomobject]@{
        Profiles = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; Notifications = $false; UnicastResponse = $true; LogAllowed = $false; LogBlocked = $false; LogFile = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxKB = 4096 }
            [pscustomobject]@{ Name = 'Private'; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; Notifications = $true; UnicastResponse = $true; LogAllowed = $false; LogBlocked = $true; LogFile = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxKB = 32767 }
            [pscustomobject]@{ Name = 'Public'; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; Notifications = $true; UnicastResponse = $false; LogAllowed = $false; LogBlocked = $true; LogFile = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxKB = 32767 }
        )
        Networks = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 12; Network = 'Demo Network'; Category = 'Private'; IPv4 = 'Internet' })
    }
}

function script:Get-IgwtExploitProtectionInventory {
    [pscustomobject]@{
        System = @([pscustomobject]@{ Name = 'Data Execution Prevention (DEP)'; Value = 'Default (on)' }, [pscustomobject]@{ Name = 'Mandatory ASLR'; Value = 'Default (on)' }, [pscustomobject]@{ Name = 'Control flow guard (CFG)'; Value = 'Default (on)' }, [pscustomobject]@{ Name = 'SEH overwrite protection (SEHOP)'; Value = 'Default (on)' })
        Programs = @(
            [pscustomobject]@{ Program = 'DemoShooter.exe'; Source = 'Registry'; AntiCheat = $false; Locked = $false; On = 'Data Execution Prevention (DEP), Control flow guard (CFG)'; Off = ''; OnCount = 2; OffCount = 0; Note = '' }
            [pscustomobject]@{ Program = 'EasyAntiCheat_EOS.exe'; Source = 'Registry'; AntiCheat = $true; Locked = $true; On = 'Data Execution Prevention (DEP), Mandatory ASLR'; Off = ''; OnCount = 2; OffCount = 0; Note = 'Anti-cheat: its mitigations are set by the anti-cheat; never change them.' }
            [pscustomobject]@{ Program = 'OldTool.exe'; Source = 'Registry'; AntiCheat = $false; Locked = $false; On = ''; Off = 'Control flow guard (CFG)'; OnCount = 0; OffCount = 1; Note = 'Some mitigations are turned off for this program; that weakens it unless the program needs it.' }
        )
        Notes = @(); WeakSystem = 0
    }
}

function script:Get-IgwtPolicyBrowserData {
    # 600 synthetic policies in a small category tree; a few configured.
    $cats = @('Windows Components > Microsoft Defender Antivirus', 'Windows Components > Microsoft Defender Antivirus > Real-time Protection', 'Windows Components > Windows Update > Manage end user experience', 'Windows Components > Windows Update > Legacy Policies', 'System > Power Management > Sleep Settings', 'Network > DNS Client', 'Windows Components > Game DVR', 'Control Panel > Personalization')
    $rows = for ($i = 0; $i -lt 600; $i++) {
        [pscustomobject]@{ Id = "Demo:Policy$i"; Name = "Demo policy ${i}: $(@('Turn on behavior monitoring', 'Configure automatic updates', 'Allow standby states', 'Turn off multicast name resolution', 'Enables or disables Game DVR', 'Prevent changing lock screen image')[$i % 6])"
            Category = $cats[$i % $cats.Count]; Class = @('Machine', 'User', 'Machine and user')[$i % 3]; SupportedOn = 'At least Windows 10'
            State = $(if ($i % 97 -eq 0) { 'Enabled' } elseif ($i % 113 -eq 0) { 'Disabled' } else { 'NotConfigured' }); Simple = ($i % 4 -ne 0); File = 'Demo.admx' }
    }
    [pscustomobject]@{ Policies = @($rows); Count = 600; Configured = @($rows | Where-Object { $_.State -ne 'NotConfigured' }).Count; CatalogMs = 820; TotalMs = 1240; Errors = @() }
}

function script:Get-IgwtPolicyBrowserDetail {
    param([string]$Id)
    [pscustomobject]@{ Id = $Id; Name = 'Demo policy'; Explain = 'This demo policy setting shows how the explanation of a policy appears in the details pane.'; Category = 'Windows Components'; SupportedOn = 'At least Windows 10'; Class = 'Machine'
        LocalGpo = 'Enabled'; Source = 'Local GPO'; Tattooed = $false; Conflicts = @()
        Choices = @([pscustomobject]@{ State = 'NotConfigured'; Label = 'Not configured'; Values = @{}; Allowed = $true; Reason = '' }, [pscustomobject]@{ State = 'Disabled'; Label = 'Disabled'; Values = @{}; Allowed = $true; Reason = '' }, [pscustomobject]@{ State = 'Enabled'; Label = 'Enabled'; Values = @{}; Allowed = $true; Reason = '' }) }
}

function script:Read-IgwtFirewallLogSession {
    # Synthetic firewall log (documentation address ranges, generic process names) parsed by the real engine.
    param([switch]$Quick, [long]$TailBytes = 1MB, [hashtable]$Notes = @{})
    Initialize-IgwtFirewallLogEngine
    $rnd = Get-IgwtMockRandom 'fwlog'
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("#Version: 1.5`n#Software: Microsoft Windows Firewall`n#Time Format: Local`n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid`n`n")
    $start = $script:MockNow.AddHours(-6)
    for ($i = 0; $i -lt 1500; $i++) {
        $t = $start.AddSeconds($i * 14 + $rnd.Next(0, 10))
        $out = ($rnd.Next(0, 4) -eq 0)
        $port = @(3389, 445, 22, 23, 135, 5353, 1900, 443, 80)[$rnd.Next(0, 9)]
        $src = $(if ($out) { '192.168.1.20' } else { "203.0.113.$($rnd.Next(1, 40))" })
        $dst = $(if ($out) { "198.51.100.$($rnd.Next(1, 60))" } else { '192.168.1.20' })
        $proto = $(if ($port -in 5353, 1900) { 'UDP' } else { 'TCP' })
        $null = $sb.AppendFormat('{0:yyyy-MM-dd HH:mm:ss} {1} {2} {3} {4} {5} {6} {7} {8} - - - - - - {9} {10}', $t, $(if ($out) { 'ALLOW' } else { 'DROP' }), $proto, $src, $dst, $rnd.Next(1024, 65535), $(if ($out) { 443 } else { $port }), $rnd.Next(40, 1400), $(if ($proto -eq 'TCP') { 'S' } else { '-' }), $(if ($out) { 'SEND' } else { 'RECEIVE' }), $(if ($out) { @(4120, 5230, 6644)[$rnd.Next(0, 3)] } else { 4 })).Append("`n")
    }
    $r = ConvertFrom-IgwtFirewallLogText -Text $sb.ToString() -File 'C:\WINDOWS\system32\LogFiles\Firewall\pfirewall.log'
    $names = New-Object 'System.Collections.Generic.Dictionary[int,string]'
    $names[4] = 'System'; $names[4120] = 'GameLauncher'; $names[5230] = 'Browser'; $names[6644] = 'VoiceChat'
    $null = [IgwtFirewallLog.Engine]::SetProcessNames($r.Entries, $names, 'pid {0} (ended)')
    [pscustomobject]@{ Entries = $r.Entries; Files = @([pscustomobject]@{ Path = 'C:\WINDOWS\system32\LogFiles\Firewall\pfirewall.log'; Profiles = @('Domain', 'Private', 'Public'); Entries = $r.Entries.Count; Bytes = [long]$sb.Length; EndOffset = $r.EndOffset; Fields = $r.Fields; TimeIsUtc = $false; Skipped = $r.Skipped; ReadMs = 40; Current = $true })
        ProfilesOff = @(); Messages = @(); Quick = [bool]$Quick; ReadMs = 40; ReadAt = $script:MockNow }
}

function script:Get-IgwtForensicSession {
    # The render suite never reads a real session record.
    param([datetime]$Now = (Get-Date))
    $null = $Now
    return $null
}

function script:Get-IgwtForensicLoggingState {
    # Demo PC: blocked packets logged everywhere, no WFP auditing, DNS client log off.
    [pscustomobject]@{
        Firewall = @(foreach ($n in 'Domain', 'Private', 'Public') { [pscustomobject]@{ Profile = $n; LogBlocked = $true; LogAllowed = ($n -eq 'Public'); LogMaxKB = 32767; LogFile = 'C:\WINDOWS\system32\LogFiles\Firewall\pfirewall.log'; ManagedBy = 'Local'; PolicyValues = @(); OnNetworkShare = $false } })
        Wfp = [pscustomobject]@{ Connection = 'None'; PacketDrop = 'None'; Readable = $true; ManagedBy = 'Local'; Authorities = @() }
        SecurityLog = [pscustomobject]@{ MaxSizeBytes = 20971520; Retention = $false; AutoBackup = $false; ManagedBy = 'Local' }
        Dns = [pscustomobject]@{ Enabled = $false; MaxSizeBytes = 1052672; ManagedBy = 'Local' }
        Session = $null; Notes = @()
    }
}
