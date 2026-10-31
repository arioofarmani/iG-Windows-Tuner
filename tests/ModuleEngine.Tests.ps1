# Module writers on the change engine (3.6, DECISIONS T14): each exported writer runs as one
# journaled step whose exact previous data is the writer's own snapshot or backup. Service access
# is mocked; registry access stays in TestRegistry.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment

    function Initialize-FaxMock {
        Mock -ModuleName iGWindowsTuner Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            $all = @([pscustomobject]@{ Name = 'Fax'; DisplayName = 'Fax'; Description = ''; State = 'Stopped'; StartMode = 'Manual'; DelayedAutoStart = $false; StartName = 'NetworkService'; PathName = "$env:SystemRoot\system32\fxssvc.exe"; ServiceType = 'Own Process' })
            if ($Filter -match "Name='([^']+)'") { $n = $Matches[1]; return @($all | Where-Object { $_.Name -eq $n }) }
            return $all
        }
        Mock -ModuleName iGWindowsTuner Get-Service { if ($Name) { [pscustomobject]@{ Name = $Name[0]; Status = 'Stopped'; StartType = 'Manual'; ServicesDependedOn = @(); DependentServices = @() } } else { @() } }
        Mock -ModuleName iGWindowsTuner Set-Service {
            $v = switch ([string]$StartupType) { 'Automatic' { 2 } 'Manual' { 3 } 'Disabled' { 4 } }
            Set-ItemProperty -LiteralPath "TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value $v
        }
        $p = 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\Fax'
        if (-not (Test-Path -LiteralPath $p)) { $null = New-Item -Path $p -Force }
        $null = New-ItemProperty -LiteralPath $p -Name Start -Value 3 -PropertyType DWord -Force
    }
    function Get-FaxStart { (Get-ItemProperty -LiteralPath 'TestRegistry:\HKLM\SYSTEM\CurrentControlSet\Services\Fax' -Name Start).Start }
}

Describe 'Module writers on the change engine' {
    BeforeEach {
        Initialize-FaxMock
        InModuleScope iGWindowsTuner { $d = Get-IgwtJournalFolder; if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; $script:IgwtJournal = $null }
    }

    It 'journals a management change as one session with its snapshot as the undo reference' {
        $r = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Disabled'
        @($r.Results)[0].Result | Should -Be 'Applied' -Because 'the writer returns its own result unchanged'
        Get-FaxStart | Should -Be 4
        InModuleScope iGWindowsTuner -Parameters @{ Snap = $r.Snapshot } {
            param($Snap)
            $script:IgwtJournal = $null
            $j = Read-IgwtJournal
            $j.Status | Should -Be 'Ok'
            $start = @($j.Entries | Where-Object { $_['kind'] -eq 'sessionStart' })
            $start.Count | Should -Be 1
            $start[0]['origin']['type'] | Should -Be 'module'
            $start[0]['origin']['ref'] | Should -Be 'Invoke-IgwtManagedChange'
            @($j.Entries | Where-Object { $_['kind'] -eq 'moduleRef' })[0]['ref'] | Should -Be $Snap -Because 'the snapshot is recorded before the change'
            $c = @($j.Entries | Where-Object { $_['kind'] -eq 'committed' })
            $c.Count | Should -Be 1
            $c[0]['target']['provider'] | Should -Be 'module'
            $c[0]['desired']['Target'] | Should -Be 'Fax'
            $c[0]['applied']['ref'] | Should -Be $Snap
            @($j.Entries | Where-Object { $_['kind'] -eq 'sessionEnd' })[0]['outcome'] | Should -Be 'ok'
        }
    }
    It 'reverts a module change from the journal and then reports it as already reverted' {
        $r = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Disabled'
        $sid = InModuleScope iGWindowsTuner { $script:IgwtJournal = $null; @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' })[0]['session'] }
        $plan = @(Get-IgwtRevertPlan -SessionId $sid)
        $plan.Count | Should -Be 1
        $plan[0].Status | Should -Be 'Ready'
        $res = Invoke-IgwtJournalRevert -Plan $plan -Title 'Revert test' -Confirm:$false
        @($res.Results)[0].Result | Should -Be 'Reverted'
        Get-FaxStart | Should -Be 3
        @(Get-IgwtRevertPlan -SessionId $sid)[0].Status | Should -Be 'Already'
        $null = $r
    }
    It 'journals a refused change as failed and passes the error to the caller' {
        { Invoke-IgwtManagedChange -Kind service -Target 'NoSuchSvc' -Value 'Disabled' } | Should -Throw '*does not exist*'
        InModuleScope iGWindowsTuner {
            $script:IgwtJournal = $null
            $j = Read-IgwtJournal
            @($j.Entries | Where-Object { $_['kind'] -eq 'failed' }).Count | Should -Be 1
            @(Get-IgwtIncompleteChangeSession).Count | Should -Be 0
        }
    }
    It 'runs a nested writer directly inside the outer step (one session)' {
        $r = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Disabled'
        $null = Invoke-IgwtRevert -SnapshotPath $r.Snapshot
        Get-FaxStart | Should -Be 3
        InModuleScope iGWindowsTuner {
            $script:IgwtJournal = $null
            $s = @((Read-IgwtJournal).Entries | Where-Object { $_['kind'] -eq 'sessionStart' })
            $s.Count | Should -Be 2 -Because 'the change and the legacy revert are one session each; the revert''s restore is not a third'
            $s[1]['origin']['ref'] | Should -Be 'Invoke-IgwtRevert'
        }
    }
    It 'previews with -WhatIf without a session' {
        $null = Invoke-IgwtManagedChange -Kind service -Target 'Fax' -Value 'Disabled' -WhatIf
        Get-FaxStart | Should -Be 3
        InModuleScope iGWindowsTuner { $script:IgwtJournal = $null; (Read-IgwtJournal).Status | Should -Be 'Empty' }
    }
    It 'refuses a module target that is not a registered writer' {
        InModuleScope iGWindowsTuner {
            { Resolve-IgwtChangeTarget -Target ([ordered]@{ provider = 'module'; key = 'module|Remove-Item|x'; op = 'Remove-Item' }) } | Should -Throw '*not a module writer*'
            { Invoke-IgwtModuleOperation -Command 'Remove-Item' -Parameters @{} } | Should -Throw '*not a registered module writer*'
        }
    }
}
