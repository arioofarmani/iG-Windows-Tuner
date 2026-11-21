# The engine boundary (4.0, section 1.2): the GUI shows and asks; only the engine changes the PC.
# One module stays one module (about 1,500 tests mock against the name iGWindowsTuner), and these
# tests hold the boundary instead: they read src\Gui with the PowerShell parser.

BeforeDiscovery {
    $script:GuiFiles = @(Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Gui') -Filter '*.ps1' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    $script:Exported = @((Import-PowerShellDataFile (Join-Path $root 'src\iGWindowsTuner.psd1')).FunctionsToExport)
    # Discovery data is not visible at run time in Pester 5: list the GUI files again.
    $script:GuiPaths = @(Get-ChildItem -LiteralPath (Join-Path $root 'src\Gui') -Filter '*.ps1' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
    $script:Area = @{}
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $root 'src') -Recurse -Filter '*.ps1') {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
        foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $script:Area[$fn.Name] = $f.Directory.Name }
    }
    function Get-GuiAst([string]$Path) { [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null) }
    # Commands and .NET members that change the PC. The GUI reaches them only through engine functions.
    $script:WriterCommand = '^(Set|New|Remove|Rename|Clear)-ItemProperty$|^(Set|Stop|Start|Restart|Suspend)-Service$|^(Set|Add|Remove)-MpPreference$|^(Set|New|Remove|Enable|Disable|Copy)-NetFirewall|^(Enable|Disable|Unregister|Register|Set)-ScheduledTask$|^Set-Acl$|^Set-ProcessMitigation$|^(Set|Enable|Disable|Restart|Rename)-NetAdapter|^(Set|Add|Remove)-DnsClient|^(Enable|Disable)-WindowsOptionalFeature$|^(Add|Remove)-AppxPackage$|^(powercfg|reg|regedit|secedit|auditpol|gpupdate|bcdedit|sc|netsh|wevtutil|dism)(\.exe)?$'
    $script:WriterMember = @('SetValue', 'DeleteValue', 'CreateSubKey', 'DeleteSubKey', 'DeleteSubKeyTree', 'SetAccessControl')
    # Engine functions that are not exported but that the 3.9 GUI calls: read-only helpers (formatting,
    # comparison, reads) and one guard. This list may only shrink: the 4.0 screens (sections 2-7) move
    # these calls behind exported functions. A new entry fails the test below.
    $script:InternalAllowed = @(
        'Assert-IgwtWritable', 'ConvertFrom-IgwtSerializableValue', 'ConvertTo-IgwtDefenderSettingValue', 'ConvertTo-IgwtFirewallChangeRequest',
        'ConvertTo-IgwtMpValue', 'ConvertTo-IgwtSafeCsv', 'Format-IgwtDefenderSettingValue', 'Format-IgwtJournalValue', 'Format-IgwtRegistryValue',
        'Get-IgwtActionFingerprint', 'Get-IgwtActiveOverlays', 'Get-IgwtActivePowerScheme', 'Get-IgwtAsrRuleAction', 'Get-IgwtDefenderSettingCatalog',
        'Get-IgwtDefenderSettingDefinition', 'Get-IgwtDnsInterfaceConfig', 'Get-IgwtFirewallChangeBlock', 'Get-IgwtFirewallDirectionText',
        'Get-IgwtFirewallProfileChangeBlock', 'Get-IgwtHostExecutable', 'Get-IgwtLevelRank', 'Get-IgwtListItemValue', 'Get-IgwtMpPreferenceValue',
        'Get-IgwtRegistryActionEffective', 'Get-IgwtRegistryTargets', 'Get-IgwtRegistryValue', 'Get-IgwtServiceStartup', 'Initialize-IgwtFirewallLogEngine',
        'Protect-IgwtCsvValue', 'Test-IgwtDefenderValueEqual', 'Test-IgwtFirewallRuleSettings', 'Test-IgwtItemVisible', 'Test-IgwtRegistryValueEqual',
        'Test-IgwtSnapshotHasChange'
    )
}

Describe 'Engine boundary: <Name>' -ForEach $script:GuiFiles {
    It 'changes nothing on the PC directly (no registry, service, firewall, Defender, policy or task writers)' {
        $ast = Get-GuiAst $Path
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $n = $c.GetCommandName()
            if ($n -and $n -match $script:WriterCommand) { $hits.Add("line $($c.Extent.StartLineNumber): $n") }
        }
        foreach ($m in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
            if ($script:WriterMember -contains [string]$m.Member.Value) { $hits.Add("line $($m.Extent.StartLineNumber): .$($m.Member.Value)()") }
        }
        $hits | Should -BeNullOrEmpty -Because 'the GUI asks the engine (Invoke-Igwt*, Set-Igwt*), which snapshots, journals and reads back'
    }
    It 'runs only exported engine commands in the background worker' {
        $ast = Get-GuiAst $Path
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($j in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Start-IgwtGuiJob' }, $true)) {
            $els = @($j.CommandElements)
            $i = -1
            for ($k = 0; $k -lt $els.Count; $k++) { if ($els[$k] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$k].ParameterName -eq 'Command') { $i = $k } }
            if ($i -lt 0) { continue }
            $arg = $els[$i + 1]
            $names = @()
            if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $names = @($arg.Value) }
            elseif ($arg -is [System.Management.Automation.Language.VariableExpressionAst]) {
                # A variable: every string it is set to in the same function counts.
                $fn = $j.Parent; while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                $var = $arg.VariablePath.UserPath
                $names = @($fn.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $args[0].Left.VariablePath.UserPath -eq $var }, $true) | ForEach-Object {
                        $v = $_.Right.Expression
                        if ($v -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $v.Value } else { "<not a fixed name at line $($_.Extent.StartLineNumber)>" }
                    })
                if (-not $names.Count) { $names = @("<unresolved `$$var at line $($j.Extent.StartLineNumber)>") }
            } else { $names = @("<not a fixed name at line $($j.Extent.StartLineNumber)>") }
            foreach ($n in $names) { if ($script:Exported -notcontains $n) { $bad.Add($n) } }
        }
        $bad | Should -BeNullOrEmpty -Because 'the worker runspace sees exported commands only, and the exports are the engine API'
    }
}

Describe 'Engine boundary: internal engine helpers used by the GUI' {
    It 'adds no new internal engine function to the GUI (the allowed list only shrinks)' {
        $used = @{}
        $script:GuiPaths.Count | Should -BeGreaterThan 10
        foreach ($f in $script:GuiPaths) {
            foreach ($c in (Get-GuiAst $f.Path).FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $n = $c.GetCommandName()
                if ($n -and $script:Area.ContainsKey($n) -and $script:Area[$n] -ne 'Gui' -and $script:Exported -notcontains $n) { $used[$n] = $f.Name }
            }
        }
        $new = @($used.Keys | Where-Object { $script:InternalAllowed -notcontains $_ } | ForEach-Object { "$_ (in $($used[$_]))" })
        $new | Should -BeNullOrEmpty -Because 'call an exported engine function instead, or export a read-only one on purpose'
        # Keep the list honest: a helper the GUI no longer calls is removed from it.
        $stale = @($script:InternalAllowed | Where-Object { -not $used.ContainsKey($_) })
        $stale | Should -BeNullOrEmpty -Because 'remove it from $InternalAllowed so the list keeps shrinking'
    }
    It 'allows only read-only helpers and the read-only guard' {
        foreach ($n in $script:InternalAllowed) {
            ($n -split '-')[0] | Should -BeIn @('Assert', 'ConvertFrom', 'ConvertTo', 'Format', 'Get', 'Initialize', 'Protect', 'Test') -Because $n
        }
    }
}
