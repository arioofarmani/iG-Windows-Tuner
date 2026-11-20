# 3.9 stage B: every revert goes through the change journal (B1).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe '3.9 B1: Invoke-IgwtRevert runs through the change journal' {
    BeforeEach {
        InModuleScope iGWindowsTuner {
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 0
            foreach ($d in @((Get-IgwtJournalFolder), (Get-IgwtDataPath -Kind Backups))) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force } }
            $script:IgwtJournal = $null
        }
    }
    It 'reverts by id through a journal revert session and records the revert for staging' {
        InModuleScope iGWindowsTuner {
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 1
            $r = Invoke-IgwtRevert -Id 'gfx.game-mode'
            @($r.Results)[0].Result | Should -Be 'Reverted'
            $r.Session | Should -Not -BeNullOrEmpty -Because 'it ran as a journal session'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
            Find-IgwtLatestSnapshotEntry -TweakId 'gfx.game-mode' | Should -BeNullOrEmpty -Because 'the revert record makes it no longer revertable'
        }
    }
    It 'does not overwrite a value changed since iG set it, and says where to decide' {
        InModuleScope iGWindowsTuner {
            $null = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            Set-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Kind 'DWord' -Value 7
            $r = Invoke-IgwtRevert -Id 'gfx.game-mode'
            @($r.Results)[0].Result | Should -Be 'Failed'
            @($r.Results)[0].Message | Should -BeLike '*Change journal*'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 7 -Because 'nothing is overwritten'
        }
    }
    It 'reverts by the apply snapshot path (the GUI Revert buttons) through the journal' {
        InModuleScope iGWindowsTuner {
            $a = Invoke-IgwtApply -Id 'gfx.game-mode' -Context (New-IgwtContext)
            $r = Invoke-IgwtRevert -SnapshotPath $a.Snapshot
            $r.Session | Should -Not -BeNullOrEmpty
            @($r.Results)[0].Result | Should -Be 'Reverted'
            (Get-IgwtRegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled').Value | Should -Be 0
        }
    }
}
