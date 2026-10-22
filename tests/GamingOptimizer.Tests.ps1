# Gaming network optimization: plan rules from measurements, apply through the engine, automatic
# revert when the network does not come back, before/after comparison. Measurements, the engine
# and probes are mocked; nothing real runs.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    function Get-TestTarget([string]$Name, [string]$Address, [string]$Role, [double]$Median, [double]$Jitter, [double]$Loss) {
        [pscustomobject]@{ Name = $Name; Address = $Address; Role = $Role; Stats = [pscustomobject]@{ Received = 100; MedianMs = $Median; JitterMs = $Jitter; LossPercent = $Loss }; Score = [pscustomobject]@{ Grade = 'B' } }
    }
    function Get-TestResult([string]$Kind = 'Ethernet', [string]$Speed = '1 Gbps', [double]$Jitter = 4, [double]$Median = 20) {
        $t = @((Get-TestTarget 'Your router' '192.168.1.1' 'Gateway' 0.5 0.4 0), (Get-TestTarget 'Cloudflare DNS' '1.1.1.1' 'Internet' $Median $Jitter 0))
        [pscustomobject]@{ Error = ''; Connection = [pscustomobject]@{ Kind = $Kind; LinkSpeed = $Speed; Gateway = '192.168.1.1'; DnsServers = @('192.168.1.1') }; Targets = $t; Internet = $t[1] }
    }
    $script:Recs = [pscustomobject]@{ Profile = 'Ethernet gaming profile'; Reverts = @(); Guidance = @(); Tweaks = @(
            [pscustomobject]@{ Id = 'net.eee-off'; Name = 'EEE off'; Level = 'Standard'; Tier = 'A'; Why = 'w' },
            [pscustomobject]@{ Id = 'net.interrupt-moderation-off'; Name = 'IM off'; Level = 'Advanced'; Tier = 'B'; Why = 'w' },
            [pscustomobject]@{ Id = 'net.qos-dscp-games'; Name = 'DSCP'; Level = 'Advanced'; Tier = 'B'; Why = 'w' }) }
}

Describe 'Gaming network optimization' {
    BeforeEach {
        Mock -ModuleName iGWindowsTuner Get-IgwtNetworkRecommendations { $script:Recs }
        $script:Ctx = New-IgwtTestContext
    }
    Context 'Plan rules' {
        It 'parses link speeds' {
            InModuleScope iGWindowsTuner {
                ConvertTo-IgwtLinkSpeedMbps -LinkSpeed '2.5 Gbps' | Should -Be 2500
                ConvertTo-IgwtLinkSpeedMbps -LinkSpeed '866,7 Mbps' | Should -Be 866.7
                ConvertTo-IgwtLinkSpeedMbps -LinkSpeed '' | Should -BeNullOrEmpty
            }
        }
        It 'keeps interrupt moderation off at 1 Gbit/s and leaves out DSCP without router confirmation' {
            $p = InModuleScope iGWindowsTuner -Parameters @{ R = (Get-TestResult); C = $script:Ctx } { param($R, $C) Get-IgwtGamingNetworkPlan -Result $R -Context $C }
            @($p.Ids) | Should -Be @('net.eee-off', 'net.interrupt-moderation-off')
            ($p.Skipped | Where-Object Id -EQ 'net.qos-dscp-games').Reason | Should -Match 'RouterHonorsDscp'
            $p.Evidence[0] | Should -Match 'jitter 4 ms'
        }
        It 'leaves interrupt moderation at the default above 2.5 Gbit/s and includes DSCP when confirmed' {
            $p = InModuleScope iGWindowsTuner -Parameters @{ R = (Get-TestResult -Speed '10 Gbps'); C = $script:Ctx } { param($R, $C) Get-IgwtGamingNetworkPlan -Result $R -Context $C -RouterHonorsDscp }
            @($p.Ids) | Should -Be @('net.eee-off', 'net.qos-dscp-games')
            ($p.Skipped | Where-Object Id -EQ 'net.interrupt-moderation-off').Reason | Should -Match 'CPU'
        }
    }
    Context 'Apply, check and compare' {
        BeforeEach {
            $script:Tests = 0
            Mock -ModuleName iGWindowsTuner Invoke-IgwtNetworkQualityTest { $script:Tests++; if ($script:Tests -eq 1) { Get-TestResult -Jitter 4 -Median 20 } else { Get-TestResult -Jitter 1 -Median 18 } }
            Mock -ModuleName iGWindowsTuner Invoke-IgwtApply { [pscustomobject]@{ Snapshot = 'C:\snap.json'; Results = @([pscustomobject]@{ Id = 'net.eee-off'; Result = 'Applied'; Message = '' }); Requires = 'none' } }
            Mock -ModuleName iGWindowsTuner Invoke-IgwtRevert { }
            Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe { [pscustomobject]@{ Status = 'Success'; Address = $Target; RttMs = 1 } }
            Mock -ModuleName iGWindowsTuner Measure-IgwtDnsQuery { 5 }
            Mock -ModuleName iGWindowsTuner Start-Sleep { }
        }
        It 'plans only with -PlanOnly' {
            $r = InModuleScope iGWindowsTuner -Parameters @{ C = $script:Ctx } { param($C) Invoke-IgwtGamingNetworkOptimization -Duration Quick -PlanOnly -Context $C }
            @($r.Plan.Ids).Count | Should -Be 2
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtApply -Times 0
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtNetworkQualityTest -Times 1 -Exactly
        }
        It 'applies through the engine, checks connectivity and compares before and after' {
            $r = InModuleScope iGWindowsTuner -Parameters @{ C = $script:Ctx } { param($C) Invoke-IgwtGamingNetworkOptimization -Duration Quick -Context $C }
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtApply -Times 1 -Exactly -ParameterFilter { $Operation -eq 'Preset:NetworkGaming' -and @($Id) -contains 'net.eee-off' }
            $r.Connectivity.Ok | Should -BeTrue
            $r.RevertedAutomatically | Should -BeFalse
            ($r.Comparison | Where-Object Role -EQ 'Internet').Verdict | Should -Be 'Better'
            ($r.Comparison | Where-Object Role -EQ 'Internet').JitterChange | Should -Be -3
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtRevert -Times 0
        }
        It 'reverts automatically when the network does not come back' {
            Mock -ModuleName iGWindowsTuner Send-IgwtPingProbe { [pscustomobject]@{ Status = 'TimedOut'; Address = ''; RttMs = $null } }
            $r = InModuleScope iGWindowsTuner -Parameters @{ C = $script:Ctx } { param($C) Invoke-IgwtGamingNetworkOptimization -Duration Quick -ConnectivityTimeoutSec 5 -Context $C }
            $r.RevertedAutomatically | Should -BeTrue
            $r.Error | Should -Match 'reverted automatically'
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtRevert -Times 1 -Exactly -ParameterFilter { $SnapshotPath -eq 'C:\snap.json' }
        }
        It 'refuses in a Remote Desktop session' {
            $ctx = New-IgwtTestContext -Extra @{ IsRdp = $true }
            $r = InModuleScope iGWindowsTuner -Parameters @{ C = $ctx } { param($C) Invoke-IgwtGamingNetworkOptimization -Duration Quick -Context $C }
            $r.Error | Should -Match 'Remote Desktop'
            Should -Invoke -ModuleName iGWindowsTuner Invoke-IgwtApply -Times 0
        }
        It 'treats small differences as noise' {
            $b = Get-TestResult -Jitter 2 -Median 20; $a = Get-TestResult -Jitter 1.8 -Median 20.5
            $c = @(InModuleScope iGWindowsTuner -Parameters @{ B = $b; A = $a } { param($B, $A) Compare-IgwtNetworkQuality -Before $B -After $A })
            ($c | Where-Object Role -EQ 'Internet').Verdict | Should -Be 'Same'
            $w = Get-TestResult -Jitter 6 -Median 25
            (@(InModuleScope iGWindowsTuner -Parameters @{ B = $b; A = $w } { param($B, $A) Compare-IgwtNetworkQuality -Before $B -After $A }) | Where-Object Role -EQ 'Internet').Verdict | Should -Be 'Worse'
        }
    }
}
