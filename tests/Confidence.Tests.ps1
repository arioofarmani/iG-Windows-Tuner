BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Decisions = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\docs\DECISIONS.md') -Raw
}

# Confidence badges (3.6, DECISIONS T8, T13): computed from sources, the journal and testedBuilds.
Describe 'Confidence badges' {
    It 'has no empty source and no DECISIONS ID that does not exist' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($t in @(Get-IgwtCatalog)) {
            foreach ($s in @($t.evidence.sources)) {
                if ([string]::IsNullOrWhiteSpace([string]$s)) { $bad.Add("$($t.id): empty source") ; continue }
                if ([string]$s -match '^DECISIONS ([A-Z]{1,3}\d{1,3}[a-z]?)$' -and $script:Decisions -notmatch ('(?m)^\| ' + [regex]::Escape($Matches[1]) + ' \|')) { $bad.Add("$($t.id): $s does not exist") }
            }
        }
        $bad -join "`n" | Should -BeNullOrEmpty
    }
    It 'counts Microsoft, Intel and DECISIONS sources only (DECISIONS T13)' {
        InModuleScope iGWindowsTuner {
            Test-IgwtQualifyingSource -Source 'https://learn.microsoft.com/en-us/windows/x' | Should -BeTrue
            Test-IgwtQualifyingSource -Source 'https://support.microsoft.com/kb/1' | Should -BeTrue
            Test-IgwtQualifyingSource -Source 'https://www.intel.com/content/x' | Should -BeTrue
            Test-IgwtQualifyingSource -Source 'DECISIONS T8' | Should -BeTrue
            Test-IgwtQualifyingSource -Source 'https://attack.mitre.org/techniques/T1218/' | Should -BeFalse
            Test-IgwtQualifyingSource -Source 'https://winutil.christitus.com/x' | Should -BeFalse
            Test-IgwtQualifyingSource -Source 'https://learn.microsoft.com.evil.example/x' | Should -BeFalse
        }
    }
    It 'lists exactly the items Ario approved as Unverified' {
        $map = Get-IgwtConfidenceMap
        @($map.Values | Where-Object Level -EQ 'Unverified' | ForEach-Object Id | Sort-Object) | Should -Be @('sec.lolbin-outbound-block', 'system.bsod-details')
    }
    It 'is Best effort without a read-back on this build, Verified with one, and says what was tested where' {
        InModuleScope iGWindowsTuner {
            $t = Get-IgwtTweak -Id 'gfx.game-mode'
            $none = [pscustomobject]@{ Build = '26300'; Passed = (New-Object 'System.Collections.Generic.HashSet[string]'); Failed = (New-Object 'System.Collections.Generic.HashSet[string]') }
            $c = Get-IgwtConfidence -Tweak $t -Context $none
            $c.Level | Should -Be 'BestEffort'
            $c.Tip | Should -BeLike '*not that it makes the PC faster*'
            $here = [pscustomobject]@{ Build = '26300'; Passed = (New-Object 'System.Collections.Generic.HashSet[string]'); Failed = (New-Object 'System.Collections.Generic.HashSet[string]') }
            $null = $here.Passed.Add('gfx.game-mode')
            (Get-IgwtConfidence -Tweak $t -Context $here).Level | Should -Be 'Verified'
            $copy = $t | Select-Object *; $copy.evidence = [pscustomobject]@{ tier = 'A'; sources = @($t.evidence.sources); testedBuilds = @(26100) }
            $tip = (Get-IgwtConfidence -Tweak $copy -Context $none).Tip
            $tip | Should -BeLike '*Tested on build 26100; this PC runs 26300*'
            $copy.evidence = [pscustomobject]@{ tier = 'A'; sources = @($t.evidence.sources); testedBuilds = @(26300) }
            (Get-IgwtConfidence -Tweak $copy -Context $none).Level | Should -Be 'Verified'
            $copy.evidence = [pscustomobject]@{ tier = 'A'; sources = @($t.evidence.sources); testedBuilds = @(26300); partialSource = $true }
            (Get-IgwtConfidence -Tweak $copy -Context $none).Level | Should -Be 'BestEffort'
        }
    }
    It 'takes Verified from this PC''s journal (a passed read-back on this build), never from a failed one' {
        InModuleScope iGWindowsTuner {
            $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            $ctx = Get-IgwtConfidenceContext
            $ctx.Passed.Contains('gfx.game-mode') | Should -BeTrue
            (Get-IgwtConfidence -Tweak (Get-IgwtTweak -Id 'gfx.game-mode') -Context $ctx).Level | Should -Be 'Verified'
            $null = $ctx.Failed.Add('gfx.game-mode')
            (Get-IgwtConfidence -Tweak (Get-IgwtTweak -Id 'gfx.game-mode') -Context $ctx).Level | Should -Be 'BestEffort'
        }
    }
}
