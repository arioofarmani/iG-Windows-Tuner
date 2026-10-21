BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Health parsers (pure functions)' {
    It 'parses the 4-byte microcode revision format (current builds)' {
        InModuleScope iGWindowsTuner { ConvertFrom-IgwtMicrocodeRevision -Bytes ([byte[]](0x2F, 0x01, 0x00, 0x00)) | Should -Be 0x12F }
    }
    It 'parses the 8-byte microcode revision format (revision in the high DWORD)' {
        InModuleScope iGWindowsTuner { ConvertFrom-IgwtMicrocodeRevision -Bytes ([byte[]](0, 0, 0, 0, 0x2B, 0x01, 0, 0)) | Should -Be 0x12B }
    }
    It 'falls back to the low DWORD when the high DWORD is zero' {
        InModuleScope iGWindowsTuner { ConvertFrom-IgwtMicrocodeRevision -Bytes ([byte[]](0x2F, 0x01, 0, 0, 0, 0, 0, 0)) | Should -Be 0x12F }
    }
    It 'returns -1 for missing data' {
        InModuleScope iGWindowsTuner { ConvertFrom-IgwtMicrocodeRevision -Bytes ([byte[]]@()) | Should -Be -1 }
    }

    It 'detects test signing and kernel debugging from SystemStartOptions' -ForEach @(
        @{ Opt = ' NOEXECUTE=OPTIN  FVEBOOT=2666496  NOVGA'; Test = $false; Debug = $false }
        @{ Opt = ' TESTSIGNING NOEXECUTE=OPTIN'; Test = $true; Debug = $false }
        @{ Opt = ' DEBUG DEBUGPORT=NET NOEXECUTE=OPTIN'; Test = $false; Debug = $true }
        @{ Opt = ' NODEBUG NOEXECUTE=OPTIN'; Test = $false; Debug = $false }
    ) {
        $o = $Opt
        $flags = InModuleScope iGWindowsTuner -Parameters @{ O = $o } { param($O) Get-IgwtBootFlags -StartOptions $O }
        $flags.TestSigning | Should -Be $Test
        $flags.KernelDebug | Should -Be $Debug
    }

    It 'accepts 239 Hz on a 240 Hz display but flags 60 Hz' {
        InModuleScope iGWindowsTuner {
            Test-IgwtRefreshRateOk -Current 239 -Maximum 240 | Should -BeTrue
            Test-IgwtRefreshRateOk -Current 60 -Maximum 240 | Should -BeFalse
        }
    }

    It 'reads the BAR1 size from nvidia-smi output (Resizable BAR)' {
        $sample = "    FB Memory Usage`r`n        Total                             : 10240 MiB`r`n    BAR1 Memory Usage`r`n        Total                             : 16384 MiB`r`n        Used                              : 1 MiB"
        InModuleScope iGWindowsTuner -Parameters @{ S = $sample } { param($S) ConvertFrom-IgwtNvidiaBar1 -Text $S } | Should -Be 16384
    }

    It 'extracts Steam library paths from libraryfolders.vdf' {
        $vdf = '"libraryfolders" { "0" { "path" "C:\\Program Files (x86)\\Steam" } "1" { "path" "D:\\SteamLibrary" } }'
        $paths = InModuleScope iGWindowsTuner -Parameters @{ V = $vdf } { param($V) ConvertFrom-IgwtSteamLibraryVdf -Text $V }
        $paths | Should -Be @('C:\Program Files (x86)\Steam', 'D:\SteamLibrary')
    }
}

Describe 'Anti-cheat readiness roll-up' {
    BeforeAll {
        function Get-Req([bool]$Pass, [bool]$Unknown = $false) { [pscustomobject]@{ Name = 'r'; Pass = $Pass; Unknown = $Unknown; Detail = '' } }
        function Get-ReqSet([hashtable]$Override = @{}) {
            $o = [ordered]@{ tpm = (Get-Req $true); secureBoot = (Get-Req $true); secureBoot2023 = (Get-Req $true); vbs = (Get-Req $true); hvci = (Get-Req $true)
                iommu = (Get-Req $true); win11 = (Get-Req $true); win1125h2 = (Get-Req $true); noTestSign = (Get-Req $true) }
            foreach ($k in $Override.Keys) { $o[$k] = $Override[$k] }
            return [pscustomobject]$o
        }
    }

    It 'is Green when every requirement passes' {
        (Get-IgwtAntiCheatReadiness -Requirements (Get-ReqSet)).Overall | Should -Be 'Green'
    }

    It 'is Amber when only Vanguard On-Demand prerequisites are missing (HVCI off)' {
        $r = Get-IgwtAntiCheatReadiness -Requirements (Get-ReqSet @{ hvci = (Get-Req $false) })
        $r.Overall | Should -Be 'Amber'
        ($r.Matrix | Where-Object Id -EQ 'vanguardOnDemand').Status | Should -Be 'Fail'
        ($r.Matrix | Where-Object Id -EQ 'faceit').Status | Should -Be 'Pass'
    }

    It 'is Red when Secure Boot is off (FACEIT, Vanguard, CoD and BF6 fail)' {
        $r = Get-IgwtAntiCheatReadiness -Requirements (Get-ReqSet @{ secureBoot = (Get-Req $false) })
        $r.Overall | Should -Be 'Red'
        foreach ($id in 'faceit', 'vanguard', 'ricochet', 'javelin') { ($r.Matrix | Where-Object Id -EQ $id).Status | Should -Be 'Fail' }
        ($r.Matrix | Where-Object Id -EQ 'vac').Status | Should -Be 'Pass'
    }

    It 'is Red when test signing is active' {
        (Get-IgwtAntiCheatReadiness -Requirements (Get-ReqSet @{ noTestSign = (Get-Req $false) })).Overall | Should -Be 'Red'
    }

    It 'marks FACEIT as failing without IOMMU' {
        $r = Get-IgwtAntiCheatReadiness -Requirements (Get-ReqSet @{ iommu = (Get-Req $false) })
        ($r.Matrix | Where-Object Id -EQ 'faceit').Status | Should -Be 'Fail'
    }
}
