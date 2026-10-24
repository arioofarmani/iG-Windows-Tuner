BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

# Diagnostics page (audit G1/G2): cards and tables instead of a monospace text dump.
Describe 'Diagnostics page rows' {
    It 'formats dates as yyyy-MM-dd HH:mm and leaves other text alone' {
        InModuleScope iGWindowsTuner {
            Format-IgwtGuiTime -Value ([datetime]::new(2026, 10, 2, 7, 5, 0)) | Should -Be '2026-10-02 07:05'
            Format-IgwtGuiTime -Value '2026-10-02T07:05:00' | Should -Be '2026-10-02 07:05'
            Format-IgwtGuiTime -Value 'n/a' | Should -Be 'n/a'
            Format-IgwtGuiTime -Value $null | Should -Be ''
        }
    }

    It 'turns reliability records, crashes and boots into event rows (missing parts are skipped)' {
        InModuleScope iGWindowsTuner {
            $t = [datetime]::new(2026, 10, 20, 9, 0, 0)
            $d = [pscustomobject]@{
                Reliability = [pscustomobject]@{ Records = @([pscustomobject]@{ Time = $t; Source = 'Application Error'; Product = 'game.exe'; Message = 'Faulting module x' }) }
                Crashes     = [pscustomobject]@{ Events = @([pscustomobject]@{ Time = $t; Kind = 'BugCheck'; Detail = '0x139' }, [pscustomobject]@{ Time = $t; Kind = 'AppCrash'; Detail = 'a.exe' }) }
                Boot        = [pscustomobject]@{ Boots = @([pscustomobject]@{ Time = $t; BootMs = 21000; MainPathMs = 9000; PostBootMs = 12000; Degraded = $true }) }
                DpcIsr      = [pscustomobject]@{ Error = 'Needs administrator rights.' }
            }
            $rows = @(Get-IgwtGuiDiagEventRows -Diagnostics $d)
            $rows.Count | Should -Be 4
            ($rows | Where-Object { $_.Area -eq 'Crashes' -and $_.KindCol -eq 'BugCheck' }).KindColGlyph | Should -Be $script:IgwtToneGlyph['Fail']
            ($rows | Where-Object Area -eq 'Boot').Detail | Should -Match 'Total 21[.,]0 s'
            ($rows | Where-Object Area -eq 'Reliability').Detail | Should -Be 'game.exe: Faulting module x'
            $rows[0].When | Should -Be '2026-10-20 09:00'
            @(Get-IgwtGuiDiagEventRows -Diagnostics ([pscustomobject]@{ Crashes = [pscustomobject]@{ Error = 'x' } })).Count | Should -Be 0
            @(Get-IgwtGuiDiagEventRows -Diagnostics $null).Count | Should -Be 0
        }
    }

    It 'builds update history rows with a result status and a hex error code' {
        InModuleScope iGWindowsTuner {
            $r = New-IgwtGuiUpdateHistoryRow -Entry ([pscustomobject]@{ Date = [datetime]::new(2026, 10, 1); Title = 'KB1'; Result = 'Failed'; HResult = -2145124329 })
            $r.ResultCol | Should -Be 'Failed'; $r.ResultColGlyph | Should -Be $script:IgwtToneGlyph['Fail']; $r.HResultText | Should -Be '0x80240017'
            (New-IgwtGuiUpdateHistoryRow -Entry ([pscustomobject]@{ Date = $null; Title = 'KB2'; Result = 'Succeeded'; HResult = 0 })).HResultText | Should -Be ''
        }
    }
}
