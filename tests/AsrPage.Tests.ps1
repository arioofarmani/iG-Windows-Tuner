BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Rule = { param($id, $mode, $impact = 'none', $allowed = @('NotConfigured', 'Audit', 'Warn', 'Block'), $managed = $false)
        [pscustomobject]@{ Id = $id; Key = $id; Name = "Rule $id"; Hint = 'hint'; Description = 'desc'; Notes = ''; Category = 'other'; MsCategory = 'Other'; GamerImpactLevel = $impact; GamerImpact = 'impact text'
            Mode = $mode; Source = $(if ($managed) { 'GroupPolicy' } else { 'Local' }); ManagedByPolicy = $managed; AllowedModes = $allowed; Recommended = 'Block'; MeetsRecommendation = ($mode -eq 'Block'); ServerOnly = $false
            RequiresCloud = $false; CloudMissing = $false; AppliesTo = ''; Exclusions = @(); Sources = @() } }
}

Describe 'ASR Center rows and Audit-to-Block plan' {
    It 'shows mode, impact, events and last event, and locks rules managed by policy' {
        InModuleScope iGWindowsTuner -Parameters @{ Rule = $script:Rule } {
            param($Rule)
            $audit = [pscustomobject]@{ Id = 'a1'; Total = 5; Programs = @([pscustomobject]@{ LastSeen = [datetime]'2026-10-20 10:00' }, [pscustomobject]@{ LastSeen = [datetime]'2026-10-22 08:00' }) }
            $row = New-IgwtGuiAsrGridRow -Rule (& $Rule 'a1' 'Audit' 'medium') -AuditRule $audit
            $row.Mode | Should -Be 'Audit'
            $row.Impact | Should -Be 'Medium'
            $row.ImpactRank | Should -Be 2
            $row.Events | Should -Be 5
            $row.LastEvent | Should -Be ([datetime]'2026-10-22 08:00')
            $row.BelowRecommendation | Should -Be 'Yes'
            $row.Supported | Should -Be 'Off, Audit, Warn, Block'
            $locked = New-IgwtGuiAsrGridRow -Rule (& $Rule 'a2' 'Block' 'none' @('Block') $true)
            $locked.ManagedBy | Should -Be 'GroupPolicy'
            $locked.ModeGlyph | Should -Be ([string][char]0xE72E)
            (New-IgwtGuiAsrGridRow -Rule (& $Rule 'a3' 'Weird' 'odd')).Mode | Should -Be 'Weird'
        }
    }

    It 'suggests Block only for quiet rules in Audit that support Block, and never touches managed rules' {
        InModuleScope iGWindowsTuner -Parameters @{ Rule = $script:Rule } {
            param($Rule)
            $status = [pscustomobject]@{ Rules = @((& $Rule 'q' 'Audit'), (& $Rule 'n' 'Audit' 'high'), (& $Rule 'x' 'Audit' 'none' @('NotConfigured', 'Audit')), (& $Rule 'm' 'Audit' 'none' @('Block') $true), (& $Rule 'b' 'Block')) }
            $audit = [pscustomobject]@{ Readable = $true; Rules = @([pscustomobject]@{ Id = 'n'; Total = 3; Programs = @([pscustomobject]@{ Path = 'C:\Games\g.exe'; Count = 3; Suggestion = 'Exclude' }) }) }
            $plan = @(Get-IgwtAsrPromotionPlan -Status $status -Audit $audit)
            @($plan | ForEach-Object Id) | Should -Be @('q', 'n', 'x')
            ($plan | Where-Object Id -EQ 'q').Suggestion | Should -Be 'Block'
            ($plan | Where-Object Id -EQ 'n').Suggestion | Should -Be 'Review'
            ($plan | Where-Object Id -EQ 'n').Programs[0] | Should -Match 'g\.exe'
            ($plan | Where-Object Id -EQ 'x').Suggestion | Should -Be 'Keep'
            @($plan | Where-Object Recommended).Count | Should -Be 1
        }
    }

    It 'builds event rows for rules, controlled folder access and network protection' {
        InModuleScope iGWindowsTuner {
            $audit = [pscustomobject]@{ Rules = @([pscustomobject]@{ Id = 'r'; Name = 'Rule r'; Programs = @([pscustomobject]@{ Path = 'C:\x.exe'; Count = 2; LastSeen = [datetime]'2026-10-21'; Suggestion = 'Exclude'; Reason = 'trusted'; Blocked = 2; Audited = 0; WarnBypassed = 0; Exclusion = 'C:\x.exe' }) })
                ControlledFolderAccess = @([pscustomobject]@{ Process = 'y.exe'; Count = 1; LastSeen = $null; Advice = 'a'; LastPath = 'p'; Blocked = 1; Audited = 0 })
                NetworkProtection = @([pscustomobject]@{ Process = ''; Destination = 'example.test'; Count = 4; LastSeen = [datetime]'2026-10-22'; Advice = 'b' }) }
            $rows = @(New-IgwtGuiAsrEventRow -Audit $audit)
            $rows.Count | Should -Be 3
            $rows[0].Exclusion | Should -Be 'C:\x.exe'
            $rows[2].Program | Should -Be 'example.test'
            @($rows | ForEach-Object Key | Select-Object -Unique).Count | Should -Be 3
        }
    }
}

Describe 'Exploit protection (read-only)' {
    It 'lists the mitigations a program turns on or off and locks anti-cheat programs' {
        InModuleScope iGWindowsTuner {
            $mk = { param($name, $dep, $cfg) [pscustomobject]@{ ProcessName = $name; Source = 'Registry'; Dep = [pscustomobject]@{ Enable = $dep }; Cfg = [pscustomobject]@{ Enable = $cfg }; Aslr = [pscustomobject]@{ BottomUp = 'NOTSET'; ForceRelocateImages = 'NOTSET'; HighEntropy = 'NOTSET' } } }
            $rows = @(ConvertTo-IgwtExploitProtectionRows -Programs @((& $mk 'game.exe' 'ON' 'OFF'), (& $mk 'EasyAntiCheat_EOS.exe' 'ON' 'ON'), (& $mk 'vgc.exe' 'NOTSET' 'NOTSET')))
            $g = $rows | Where-Object Program -EQ 'game.exe'
            $g.On | Should -Match 'DEP'
            $g.Off | Should -Match 'CFG'
            $g.OffCount | Should -Be 1
            $g.Locked | Should -BeFalse
            ($rows | Where-Object Program -EQ 'EasyAntiCheat_EOS.exe').Locked | Should -BeTrue
            ($rows | Where-Object Program -EQ 'vgc.exe').AntiCheat | Should -BeTrue
        }
    }

    It 'never writes exploit protection settings' {
        $src = Get-Content (Join-Path $script:IgwtProjectRoot 'src\Security\ExploitProtection.ps1') -Raw
        $src | Should -Not -Match 'Set-ProcessMitigation'
    }
}
