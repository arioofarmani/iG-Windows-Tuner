# Static checks that the shipped code stays transparent and never contains the techniques the
# project rules forbid (BCD edits, obfuscation, download-and-execute, persistence, security
# tampering). These scan the source text; they do not execute anything.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Shipped = @(Get-ChildItem -Path (Join-Path $script:IgwtProjectRoot 'src'), (Join-Path $script:IgwtProjectRoot 'data') -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.json, *.xaml) +
        @(Get-Item (Join-Path $script:IgwtProjectRoot 'iGWindowsTuner.ps1'), (Join-Path $script:IgwtProjectRoot 'Start-iGWindowsTuner.cmd'))
    $script:Code = @($script:Shipped | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1', '.cmd' })
    function Get-Matches([string]$Pattern, [object[]]$Files = $script:Code) {
        foreach ($f in $Files) {
            $i = 0
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                $i++
                if ($line -match $Pattern -and $line -notmatch '^\s*#') { "$($f.Name):${i}: $($line.Trim())" }
            }
        }
    }
}

Describe 'Forbidden techniques are absent from shipped code' {
    It 'never runs bcdedit' { Get-Matches '(?i)bcdedit(\.exe)?\s' | Should -BeNullOrEmpty }
    It 'never uses Invoke-Expression or iex' { Get-Matches '(?i)\b(Invoke-Expression|iex)\b' | Should -BeNullOrEmpty }
    It 'never uses -EncodedCommand or Base64 decoding' { Get-Matches '(?i)(EncodedCommand|FromBase64String|ToBase64String)' | Should -BeNullOrEmpty }
    It 'never downloads anything' { Get-Matches '(?i)(Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|Net\.WebClient|Start-BitsTransfer|\biwr\b|\bcurl\b|\bwget\b)' | Should -BeNullOrEmpty }
    It 'never creates persistence (tasks, services, Run keys, WMI subscriptions)' {
        Get-Matches '(?i)(Register-ScheduledTask|New-ScheduledTask|schtasks|New-Service|sc\.exe\s+create|__EventFilter|Register-WmiEvent|Register-CimIndicationEvent)' | Should -BeNullOrEmpty
        Get-Matches '(?i)Set-ItemProperty.*CurrentVersion\\Run' | Should -BeNullOrEmpty
    }
    It 'never hides windows' { Get-Matches '(?i)WindowStyle\s+Hidden|-w\s+hidden|CreateNoWindow' | Should -BeNullOrEmpty }
    It 'never changes machine or user execution policy' { Get-Matches '(?i)Set-ExecutionPolicy' | Should -BeNullOrEmpty }
    It 'never touches AMSI, ETW, real-time protection, Tamper Protection or Defender exclusions' {
        Get-Matches '(?i)(AmsiUtils|amsiInitFailed|EtwEventWrite|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|TamperProtection\s*=|ExclusionPath|ExclusionProcess|ExclusionExtension)' | Should -BeNullOrEmpty
    }
    It 'never disables driver signature enforcement or enables test signing' { Get-Matches '(?i)(testsigning\s+on|nointegritychecks|DISABLE_INTEGRITY_CHECKS\s*=)' | Should -BeNullOrEmpty }
    It 'uses no UAC bypass (only Start-Process -Verb RunAs)' {
        Get-Matches '(?i)(fodhelper|eventvwr|ms-settings\\shell|computerdefaults|sdclt|ConsentPromptBehaviorAdmin\s*=\s*0)' | Should -BeNullOrEmpty
        foreach ($h in @(Get-Matches '(?i)-Verb\s+RunAs')) { $h | Should -Match '^Elevation\.ps1:' }
    }
    It 'contains exactly one Add-Type with C# source (the SystemParametersInfo P/Invoke)' {
        $typeDefs = @(Get-Matches '(?i)Add-Type\s+-TypeDefinition')
        $typeDefs.Count | Should -Be 1
        $typeDefs[0] | Should -Match 'Custom\.ps1'
        @(Get-Matches '(?i)DllImport').Count | Should -Be 1
    }
    It 'runs only the allowed external executables' {
        foreach ($i in @(Get-Matches '&\s*\$exe\b')) { $i | Should -Match '^(PowerCfg|Gpu|CleanerEngine|Apps|NetworkQuality)\.ps1:' }
        $literals = foreach ($m in @(Get-Matches "(?i)'[^']*\.exe'")) { foreach ($x in [regex]::Matches($m, "(?i)'([^']*\.exe)'")) { Split-Path $x.Groups[1].Value -Leaf } }
        foreach ($e in @($literals)) { $e | Should -BeIn @('powercfg.exe', 'nvidia-smi.exe', 'powershell.exe', 'pwsh.exe', 'explorer.exe', 'dism.exe', 'pnputil.exe', 'winget.exe', 'netsh.exe') }
    }
    It 'runs netsh only to read Wi-Fi details (wlan show interfaces) in the network module' {
        foreach ($h in @(Get-Matches '(?i)netsh')) { $h | Should -Match '^NetworkQuality\.ps1:' }
        @(Get-Matches '(?i)& \$exe ''wlan'' ''show'' ''interfaces''').Count | Should -Be 1
        Get-Matches "(?i)netsh.*\b(set|add|delete|reset|int(erface)?\s+ip)\b" | Should -BeNullOrEmpty
    }
    It 'builds no command names from strings at runtime' {
        Get-Matches '(?i)&\s*\(\s*["''].*\$' | Should -BeNullOrEmpty
        Get-Matches '(?i)\[scriptblock\]::Create' | Should -BeNullOrEmpty
        Get-Matches '(?i)\.AddScript\(' | Should -BeNullOrEmpty
    }
    It 'never names things bypass, stealth or kill' {
        Get-Matches '(?i)function\s+\S*(bypass|stealth|kill)' | Should -BeNullOrEmpty
    }
    It 'only uses -ExecutionPolicy Bypass for the process (launcher and UAC relaunch)' {
        foreach ($h in @(Get-Matches '(?i)ExecutionPolicy')) { $h | Should -Match '(?i)-ExecutionPolicy[''"]?,?\s*[''"]?Bypass' }
    }
}

Describe '2.0 action handlers stay within their limits' {
    It 'never creates, imports or deletes scheduled tasks (enable/disable only)' {
        Get-Matches '(?i)(Register-ScheduledTask|Unregister-ScheduledTask|New-ScheduledTask|Set-ScheduledTask|schtasks)' | Should -BeNullOrEmpty
    }
    It 'creates firewall rules only in the iG Windows Tuner group and only as Block rules' {
        foreach ($h in @(Get-Matches '(?i)New-NetFirewallRule')) { $h | Should -Match '^Firewall\.ps1:' }
        Get-Matches "(?i)Action\s*=\s*'Allow'" | Should -BeNullOrEmpty
    }
    It 'runs winget only through Invoke-IgwtWinget and never with --force' {
        foreach ($h in @(Get-Matches '(?i)winget\.exe')) { $h | Should -Match '^Apps\.ps1:' }
        Get-Matches "(?i)'--force'" | Should -BeNullOrEmpty
    }
    It 'never writes BCD (there is no bcd action handler)' {
        Get-Matches "(?i)'bcd'\s*\{" | Should -BeNullOrEmpty
    }
}

Describe 'Module structure' {
    It 'defines every function only once (a later file would silently replace the earlier one)' {
        $names = foreach ($f in @($script:Code | Where-Object { $_.Extension -eq '.ps1' -and $_.FullName -like '*\src\*' })) {
            foreach ($m in (Select-String -LiteralPath $f.FullName -Pattern '^\s*function\s+([A-Za-z0-9\-]+)')) { $m.Matches[0].Groups[1].Value }
        }
        @($names | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
    }
    It 'never writes $name? in a string (PowerShell reads it as a variable named "name?"; use ${name}?)' {
        Get-Matches '\$[A-Za-z_][A-Za-z0-9_]*\?' | Should -BeNullOrEmpty
    }
}

Describe 'Expert inspectors stay read-only (except the power plan editor)' {
    BeforeAll { $script:InspectorCode = @($script:Code | Where-Object { $_.DirectoryName -like '*\src\Inspectors' }) }
    It 'has inspector source files to check' { $script:InspectorCode.Count | Should -BeGreaterOrEqual 4 }
    It 'changes power settings only in the power plan editor and nothing else anywhere' {
        foreach ($h in @(Get-Matches '(?i)Set-IgwtPowerSettingIndex' $script:InspectorCode)) { $h | Should -Match '^PowerInspector\.ps1:' }
        Get-Matches '(?i)\b(Set-IgwtRegistryValue|Remove-IgwtRegistryValue|Set-ItemProperty|New-ItemProperty|Remove-Item|Set-NetAdapter\w*|Set-PnpDevice\w*|Enable-PnpDevice|Disable-PnpDevice|Set-Service|Restart-Service)\b' $script:InspectorCode | Should -BeNullOrEmpty
    }
    It 'never offers processor idle disable for editing' {
        $json = Get-Content -LiteralPath (Join-Path $script:IgwtProjectRoot 'data\power\processor.json') -Raw
        $json | Should -Not -Match '5d76a2ca-e8c0-402f-a133-2158492d58ad'
        $json | Should -Not -Match 'IDLEDISABLE'
    }
}

Describe 'ASR Center and security modules stay within their limits' {
    BeforeAll { $script:SecurityCode = @($script:Code | Where-Object { $_.DirectoryName -like '*\src\Security' }) }
    It 'has security source files to check' { $script:SecurityCode.Count | Should -BeGreaterOrEqual 3 }
    It 'changes ASR-only exclusions in the ASR Center only (never antivirus exclusions)' {
        foreach ($h in @(Get-Matches '(?i)AttackSurfaceReductionOnlyExclusions')) { $h | Should -Match '^AsrCenter\.ps1:' }
    }
    It 'writes the registry only under the ASR policy key' {
        foreach ($h in @(Get-Matches '(?i)Set-IgwtRegistryValue' $script:SecurityCode)) { $h | Should -Match '^AsrCenter\.ps1:.*\$script:IgwtAsr(PolicyKey|PerRuleKey)' }
    }
    It 'keeps the audit view, security score, accounts audit and network surface read-only' {
        $readOnly = @($script:SecurityCode | Where-Object { $_.Name -in 'AsrAudit.ps1', 'SecurityScore.ps1' })
        $readOnly.Count | Should -Be 2
        Get-Matches '(?i)\b(Set|Add|Remove|Enable|Disable|Stop|Start|Restart|Clear|Rename|Move|Copy|New)-(?!Object\b|IgwtContext\b)[A-Za-z]' $readOnly | Should -BeNullOrEmpty
    }
    It 'never maps an ASR change to an explicit Off (code 0)' {
        $def = @(Get-Matches '(?i)\$script:IgwtAsrSettableCodes\s*=' $script:SecurityCode)
        $def.Count | Should -Be 1
        $def[0] | Should -Not -Match '=\s*0\b'
        Get-Matches '(?i)-Code\s+0\b' $script:SecurityCode | Should -BeNullOrEmpty
    }
}

Describe 'Cleaning engine stays non-recursive and never closes apps' {
    BeforeAll {
        $script:CleanerCode = @($script:Code | Where-Object { $_.DirectoryName -like '*\src\Cleaner' })
    }
    It 'has cleaner source files to check' { $script:CleanerCode.Count | Should -BeGreaterThan 0 }
    It 'never deletes recursively' {
        Get-Matches '(?i)Remove-Item[^\r\n]*-Recurse' $script:CleanerCode | Should -BeNullOrEmpty
        Get-Matches '(?i)Directory\]::Delete\([^)]*\$true' $script:CleanerCode | Should -BeNullOrEmpty
        Get-Matches '(?i)\.Delete\(\s*\$true\s*\)' $script:CleanerCode | Should -BeNullOrEmpty
        Get-Matches '(?i)\b(rd|rmdir)\s+/s' $script:CleanerCode | Should -BeNullOrEmpty
    }
    It 'deletes files only inside the safety primitive' {
        foreach ($h in @(Get-Matches '(?i)\[System\.IO\.File\]::Delete|\[IO\.File\]::Delete' $script:CleanerCode)) { $h | Should -Match '^CleanerSafety\.ps1:' }
        foreach ($h in @(Get-Matches '(?i)Directory\]::Delete' $script:CleanerCode)) { $h | Should -Match '^CleanerSafety\.ps1:' }
    }
    It 'never kills processes' { Get-Matches '(?i)(Stop-Process|taskkill|\.Kill\()' $script:CleanerCode | Should -BeNullOrEmpty }
    It 'never forces driver package removal' {
        Get-Matches '(?i)&\s*\$exe[^\r\n]*/force' $script:CleanerCode | Should -BeNullOrEmpty
        @(Get-Matches '(?i)&\s*\$exe\s+/delete-driver\s+\$Inf\s+2>&1\s*$' $script:CleanerCode).Count | Should -Be 1
    }
    It 'never takes ownership or rewrites ACLs' { Get-Matches '(?i)(takeown|icacls|Set-Acl)' $script:CleanerCode | Should -BeNullOrEmpty }
}
