# Startup Apps full management (DECISIONS SA1-SA10): delete with backup, additive restore,
# rollback, refusals and warnings, folder files, read-only details and the CLI dry run.
# TestRegistry, TestDrive and mocks only; the real Run keys and Startup folders are never touched.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:RunKey = 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
    $script:ApprovedKey = 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    $script:ApprovedFolderKey = 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    function Write-TestRunValue([string]$Name, [string]$Data, [string]$Kind = 'String') {
        if (-not (Test-Path -LiteralPath $script:RunKey)) { New-Item -Path $script:RunKey -Force | Out-Null }
        New-ItemProperty -Path $script:RunKey -Name $Name -Value $Data -PropertyType $Kind -Force | Out-Null
    }
    function Write-TestApprovedValue([string]$Key, [string]$Name, [byte[]]$Bytes) {
        if (-not (Test-Path -LiteralPath $Key)) { New-Item -Path $Key -Force | Out-Null }
        New-ItemProperty -Path $Key -Name $Name -Value $Bytes -PropertyType Binary -Force | Out-Null
    }
    function Get-RawRun([string]$Name) {
        $k = Get-Item -LiteralPath $script:RunKey
        if (@($k.GetValueNames()) -notcontains $Name) { return $null }
        [pscustomobject]@{ Kind = $k.GetValueKind($Name).ToString(); Data = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    }
}

AfterAll { InModuleScope iGWindowsTuner { $script:IgwtStartupFolderOverride = @{} } }

Describe 'Deleting a Run value (SA2) and restoring it (SA4)' {
    BeforeEach {
        Remove-Item -Path $script:RunKey -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $script:ApprovedKey -Recurse -Force -ErrorAction SilentlyContinue
        Mock -ModuleName iGWindowsTuner New-IgwtPrivateBackupFolder { throw 'no folder backup for a Run value' }
    }
    It 'deletes the value and its on/off state, and the revert restores both exactly (REG_EXPAND_SZ not expanded)' {
        Write-TestRunValue -Name 'Contoso Agent' -Data '"%LOCALAPPDATA%\Contoso\agent.app" --tray' -Kind ExpandString
        Write-TestApprovedValue -Key $script:ApprovedKey -Name 'Contoso Agent' -Bytes ([byte[]](3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8))
        $snap = Remove-IgwtStartupItem -Item 'HKCU-Run|Contoso Agent' -Confirm:$false
        $snap | Should -Exist
        Get-RawRun 'Contoso Agent' | Should -BeNullOrEmpty
        (Get-ItemProperty -Path $script:ApprovedKey).PSObject.Properties['Contoso Agent'] | Should -BeNullOrEmpty
        $r = Invoke-IgwtRevert -SnapshotPath $snap -Context (New-IgwtTestContext)
        @($r.Results | Where-Object { $_.Result -ne 'Reverted' }) | Should -BeNullOrEmpty
        $raw = Get-RawRun 'Contoso Agent'
        $raw.Kind | Should -Be 'ExpandString'
        $raw.Data | Should -Be '"%LOCALAPPDATA%\Contoso\agent.app" --tray'
        [byte[]](Get-ItemProperty -Path $script:ApprovedKey).'Contoso Agent' | Should -Be ([byte[]](3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8))
    }
    It 'restores additively: an equal value is already present, a different value refuses with nothing changed' {
        Write-TestRunValue -Name 'Fabrikam Sync' -Data 'C:\Fabrikam\sync.app'
        $snap = Remove-IgwtStartupItem -Item 'HKCU-Run|Fabrikam Sync' -Confirm:$false
        $data = (Get-Content -LiteralPath $snap -Raw | ConvertFrom-Json).entries[0].actions[0].data
        Write-TestRunValue -Name 'Fabrikam Sync' -Data 'C:\Fabrikam\sync.app'
        InModuleScope iGWindowsTuner -Parameters @{ D = $data } { param($D) Restore-IgwtStartupEntry -Data $D -Confirm:$false } | Should -Be 'AlreadyPresent'
        Write-TestRunValue -Name 'Fabrikam Sync' -Data 'C:\Fabrikam\other.app'
        { InModuleScope iGWindowsTuner -Parameters @{ D = $data } { param($D) Restore-IgwtStartupEntry -Data $D -Confirm:$false } } | Should -Throw '*exists again with other data*'
        (Get-RawRun 'Fabrikam Sync').Data | Should -Be 'C:\Fabrikam\other.app'
    }
    It 'rolls back the entries already deleted when a later one fails' {
        Write-TestRunValue -Name 'Alpha' -Data 'C:\Contoso\alpha.app'
        Write-TestRunValue -Name 'Beta' -Data 'C:\Contoso\beta.app'
        Mock -ModuleName iGWindowsTuner Remove-IgwtStartupEntry {
            if ([string]$Data['name'] -eq 'Beta') { throw 'simulated failure' }
            Remove-ItemProperty -Path 'TestRegistry:\HKCU\Software\Microsoft\Windows\CurrentVersion\Run' -Name ([string]$Data['name'])
        }
        { Remove-IgwtStartupItem -Item 'HKCU-Run|Alpha', 'HKCU-Run|Beta' -Confirm:$false } | Should -Throw '*Beta*nothing changed*'
        (Get-RawRun 'Alpha').Data | Should -Be 'C:\Contoso\alpha.app'
        (Get-RawRun 'Beta').Data | Should -Be 'C:\Contoso\beta.app'
    }
    It 'refuses an id outside the allow-listed scopes and a missing entry, with nothing changed' {
        Write-TestRunValue -Name 'Keep' -Data 'C:\Contoso\keep.app'
        { Remove-IgwtStartupItem -Item 'HKCU-RunOnce|Keep' -Confirm:$false } | Should -Throw '*Unknown startup scope*'
        { Remove-IgwtStartupItem -Item 'HKCU-Run|Keep', 'HKCU-Run|Gone' -Confirm:$false } | Should -Throw '*Gone*no longer exists*'
        (Get-RawRun 'Keep').Data | Should -Be 'C:\Contoso\keep.app'
    }
}

Describe 'Refusals and warnings (SA5)' {
    BeforeEach { Remove-Item -Path $script:RunKey -Recurse -Force -ErrorAction SilentlyContinue }
    It 'refuses a Windows component and a security product, warns for an anti-cheat, allows the rest' {
        Write-TestRunValue -Name 'SecurityHealth' -Data "$env:SystemRoot\system32\SecurityHealthSystray.exe"
        Write-TestRunValue -Name 'Bitdefender Agent' -Data 'C:\Program Files\Bitdefender\Bitdefender Agent\agent.app'
        Write-TestRunValue -Name 'FACEIT' -Data '"C:\Users\Player\AppData\Local\FACEIT\update.app" --processStart "FACEIT.app"'
        Write-TestRunValue -Name 'Steam' -Data '"C:\Program Files (x86)\Steam\steam.app" -silent'
        $plan = @(Get-IgwtStartupRemovePlan -Item 'HKCU-Run|SecurityHealth', 'HKCU-Run|Bitdefender Agent', 'HKCU-Run|FACEIT', 'HKCU-Run|Steam')
        ($plan | Where-Object Name -EQ 'SecurityHealth').Refused | Should -Match 'part of Windows'
        ($plan | Where-Object Name -EQ 'Bitdefender Agent').Refused | Should -Match 'security product'
        $face = $plan | Where-Object Name -EQ 'FACEIT'
        $face.Refused | Should -BeNullOrEmpty
        $face.Warning | Should -Match 'anti-cheat'
        ($plan | Where-Object Name -EQ 'Steam').Refused | Should -BeNullOrEmpty
        $text = @(Format-IgwtStartupRemovePlan -Plan $plan) -join "`n"
        $text | Should -Match 'Not deleted:'
        $text | Should -Match 'Warning: This belongs to an anti-cheat'
        { Remove-IgwtStartupItem -Item 'HKCU-Run|SecurityHealth', 'HKCU-Run|Steam' -Confirm:$false } | Should -Throw 'Refused, nothing changed*'
        (Get-RawRun 'Steam') | Should -Not -BeNullOrEmpty
    }
    It 'turning a protected entry off stays possible' {
        Write-TestRunValue -Name 'SecurityHealth' -Data "$env:SystemRoot\system32\SecurityHealthSystray.exe"
        { Set-IgwtStartupItemEnabled -Scope 'HKCU-Run' -Name 'SecurityHealth' -Enabled $false -Confirm:$false } | Should -Not -Throw
    }
}

Describe 'Deleting a Startup folder file (SA3)' {
    BeforeAll {
        $script:Folder = Join-Path $TestDrive 'Startup'
        $null = New-Item -ItemType Directory -Path $script:Folder -Force
        InModuleScope iGWindowsTuner -Parameters @{ F = $script:Folder } { param($F) $script:IgwtStartupFolderOverride = @{ 'User-Folder' = $F } }
    }
    BeforeEach {
        Get-ChildItem -LiteralPath $script:Folder -Force | Remove-Item -Force -Recurse
        Remove-Item -Path $script:ApprovedFolderKey -Recurse -Force -ErrorAction SilentlyContinue
        Mock -ModuleName iGWindowsTuner New-IgwtPrivateBackupFolder { (New-Item -ItemType Directory -Path $Path -Force).FullName }
    }
    It 'copies the file into a backup folder first, deletes it, and the revert copies it back byte for byte' {
        $file = Join-Path $script:Folder 'Contoso Tool.lnk'
        [IO.File]::WriteAllBytes($file, [byte[]](1..200 | ForEach-Object { [byte]($_ % 256) }))
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        Write-TestApprovedValue -Key $script:ApprovedFolderKey -Name 'Contoso Tool.lnk' -Bytes ([byte[]](2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        $item = @(Get-IgwtStartupItem | Where-Object { $_.Name -eq 'Contoso Tool.lnk' })
        $item.Count | Should -Be 1
        $item[0].Scope | Should -Be 'User-Folder'
        $snap = Remove-IgwtStartupItem -Item 'User-Folder|Contoso Tool.lnk' -Confirm:$false
        $file | Should -Not -Exist
        $data = (Get-Content -LiteralPath $snap -Raw | ConvertFrom-Json).entries[0].actions[0].data
        $data.sha256 | Should -Be $hash
        $data.backupFolder | Should -Match '^startup-[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$'
        $r = Invoke-IgwtRevert -SnapshotPath $snap -Context (New-IgwtTestContext)
        @($r.Results | Where-Object { $_.Result -ne 'Reverted' }) | Should -BeNullOrEmpty
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash | Should -Be $hash
        [byte[]](Get-ItemProperty -Path $script:ApprovedFolderKey).'Contoso Tool.lnk' | Should -Be ([byte[]](2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    }
    It 'refuses a restore when the backup copy does not match its hash' {
        $file = Join-Path $script:Folder 'Fabrikam.lnk'
        [IO.File]::WriteAllBytes($file, [byte[]](5, 6, 7))
        $snap = Remove-IgwtStartupItem -Item 'User-Folder|Fabrikam.lnk' -Confirm:$false
        $data = (Get-Content -LiteralPath $snap -Raw | ConvertFrom-Json).entries[0].actions[0].data
        $copy = Join-Path (Join-Path (Split-Path -Parent $snap) $data.backupFolder) 'Fabrikam.lnk'
        [IO.File]::WriteAllBytes($copy, [byte[]](9, 9, 9))
        { InModuleScope iGWindowsTuner -Parameters @{ D = $data } { param($D) Restore-IgwtStartupEntry -Data $D -Confirm:$false } } | Should -Throw '*does not match its recorded hash*'
        $file | Should -Not -Exist
    }
    It 'refuses names with path parts, desktop.ini and files over 10 MB' {
        { InModuleScope iGWindowsTuner { ConvertFrom-IgwtStartupItemId -Id 'User-Folder|..\evil.lnk' } } | Should -Throw '*not a file name*'
        { InModuleScope iGWindowsTuner { ConvertFrom-IgwtStartupItemId -Id 'User-Folder|desktop.ini' } } | Should -Throw '*not a file name*'
        $big = Join-Path $script:Folder 'Big.lnk'
        $fs = [IO.File]::Create($big); $fs.SetLength(11MB); $fs.Dispose()
        { Remove-IgwtStartupItem -Item 'User-Folder|Big.lnk' -Confirm:$false } | Should -Throw '*larger than 10 MB*'
        $big | Should -Exist
    }
    It 'never reads the real Startup folders in test mode' {
        InModuleScope iGWindowsTuner { Get-IgwtStartupFolderPath -Scope 'Common-Folder' } | Should -BeNullOrEmpty
    }
}

Describe 'Details (SA6)' {
    It 'reports the target, whether it exists, the source and a missing file' {
        Remove-Item -Path $script:RunKey -Recurse -Force -ErrorAction SilentlyContinue
        Write-TestRunValue -Name 'Gone Tool' -Data '"C:\NoSuchFolder-igwt\gone.exe" /min'
        $e = @(Get-IgwtStartupItem | Where-Object { $_.Name -eq 'Gone Tool' })[0]
        $e.Target | Should -Be 'C:\NoSuchFolder-igwt\gone.exe'
        $e.TargetExists | Should -BeFalse
        $e.FileMissing | Should -BeTrue
        $e.Source | Should -Match 'CurrentVersion\\Run$'
        $e.Protection | Should -Be ''
    }
}

Describe 'Read-only mode' {
    It 'refuses the delete before anything else' {
        InModuleScope iGWindowsTuner { $script:IgwtSettings.ReadOnly = $true }
        try { { Remove-IgwtStartupItem -Item 'HKCU-Run|Anything' -Confirm:$false } | Should -Throw '*read-only*' }
        finally { InModuleScope iGWindowsTuner { $script:IgwtSettings.ReadOnly = $false } }
    }
}
