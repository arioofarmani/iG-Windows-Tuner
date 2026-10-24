# GUI layout rules that do not need a window: Manage list sorting, the ASR Center as part of
# Security in the navigation, and the dashboard and Manage controls in the XAML.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
    $script:Xaml = [xml](Get-Content (Join-Path $script:IgwtProjectRoot 'src\Gui\MainWindow.xaml') -Raw)
    $script:Ns = New-Object System.Xml.XmlNamespaceManager($script:Xaml.NameTable)
    $script:Ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
}

Describe 'GUI layout' {
    It 'hosts a SmartGrid on every Manage tab and on the Firewall page' {
        foreach ($h in 'ManageServiceGridHost', 'ManageTaskGridHost', 'ManageAppGridHost', 'ManagePersistGridHost', 'FwGridHost') { @($script:Xaml.SelectNodes("//w:ContentControl[@*[local-name()='Name']='$h']", $script:Ns)).Count | Should -Be 1 -Because $h }
        @($script:Xaml.SelectNodes("//w:Button[starts-with(@Tag,'sort:')]", $script:Ns)).Count | Should -Be 0 -Because 'SmartGrid replaced the old sort header buttons'
    }
    It 'lists the Firewall Manager under Security, after the ASR Center and the Defender settings' {
        $nav = @($script:Xaml.SelectNodes("//w:ListBox[@*[local-name()='Name']='NavList']/w:ListBoxItem", $script:Ns) | ForEach-Object { $_.Tag })
        $nav[[array]::IndexOf($nav, 'Security') + 3] | Should -Be 'Firewall'
        InModuleScope iGWindowsTuner { foreach ($p in 'Gamer', 'Sysadmin') { $o = @((Get-IgwtPersonaProfile -Name $p).NavOrder); if ($o.Count) { $o[[array]::IndexOf($o, 'Defender') + 1] | Should -Be 'Firewall' -Because $p } } }
    }
    It 'builds Firewall rows with status, source, lock and risk fields and offers every quick filter of the spec' {
        InModuleScope iGWindowsTuner {
            $rule = [pscustomobject]@{ Name = 'r1'; DisplayName = 'Game'; Group = ''; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profiles = 'Any'; ProfileList = @('Any'); Program = 'C:\G\g.exe'; Service = 'Any'; Package = ''; Owner = ''
                Protocol = 'ICMPv4'; LocalPort = 'Any'; RemotePort = 'Any'; LocalAddress = 'Any'; RemoteAddress = 'Any'; InterfaceType = 'Any'; EdgeTraversal = 'Block'; Source = 'GroupPolicy'; StoreSource = 'x'; Locked = $true; LockReason = 'Set by Group Policy'
                ProgramExists = 'No'; Description = ''; Risks = @('InboundPublic', 'ProgramMissing'); RiskText = 'Inbound allow on Public; Program not found' }
            $row = New-IgwtGuiFirewallRow -Rule $rule
            $row.State | Should -Be 'Enabled'
            $row.ProfileMatch | Should -Contain 'Public'
            $row.ProtocolKey | Should -Be 'ICMP'
            $row.Source | Should -Be 'Group Policy / MDM'
            $row.SourceGlyph | Should -Be ([string][char]0xE72E)
            $row.RiskCount | Should -Be 20
            $row.Risk | Should -Match 'Inbound allow on Public'
            (New-IgwtGuiFirewallRow -Rule ([pscustomobject]@{ Name = 'x' })).State | Should -Be 'Disabled'
            $chips = @(Get-IgwtGuiFirewallChips)
            foreach ($v in 'InboundPublic', 'Broad', 'ProgramMissing', 'UserWritable', 'Duplicate', 'DisabledWindows') { @($chips | Where-Object { @($_.Values) -contains $v }).Count | Should -Be 1 -Because $v }
            foreach ($id in 'enabled', 'disabled', 'in', 'out', 'allow', 'block', 'p-domain', 'p-private', 'p-public', 's-windows', 's-third', 's-owned', 's-gpo', 's-store', 'tcp', 'udp', 'icmp', 'anyproto') { @($chips | Where-Object Id -EQ $id).Count | Should -Be 1 -Because $id }
            $cols = @(Get-IgwtGuiFirewallColumns | ForEach-Object { $_.Key })
            foreach ($k in 'DisplayName', 'Group', 'State', 'Direction', 'Action', 'Profiles', 'Program', 'Service', 'Package', 'Protocol', 'LocalPort', 'RemotePort', 'LocalAddress', 'RemoteAddress', 'InterfaceType', 'EdgeTraversal', 'Source', 'ProgramExists', 'Risk', 'Description') { $cols | Should -Contain $k }
        }
    }
    It 'builds Manage rows that never throw on unexpected values' {
        InModuleScope iGWindowsTuner {
            $svc = New-IgwtGuiServiceRow -Service ([pscustomobject]@{ Name = 'X'; DisplayName = 'X svc'; Rating = 'SomethingNew' })
            $svc.Rating | Should -Be 'SomethingNew'
            $svc.RatingGlyph | Should -Not -BeNullOrEmpty
            (New-IgwtGuiServiceRow -Service $null).Rating | Should -Be 'Unknown'
            (New-IgwtGuiTaskRow -Task ([pscustomobject]@{ Name = 't'; Protected = $true })).State | Should -Be 'Protected'
            (New-IgwtGuiAppRow -App ([pscustomobject]@{ Name = 'a'; SizeMB = 12 }) -Kind Win32).Size | Should -Be '12 MB'
            $p = New-IgwtGuiPersistenceRow -Entry ([pscustomobject]@{ Name = 'p'; Severity = 'Warn' })
            $p.Severity | Should -Be 'Warning'
            $p.SeverityKey | Should -Be 0
            (New-IgwtGuiManageRow -Title 't' -Tone 'Bogus').StateBrush | Should -Be $script:IgwtColor.Text
        }
    }
    It 'shows the ASR Center and the Defender settings directly under Security in the navigation and in every persona' {
        $nav = @($script:Xaml.SelectNodes("//w:ListBox[@*[local-name()='Name']='NavList']/w:ListBoxItem", $script:Ns) | ForEach-Object { $_.Tag })
        $nav[[array]::IndexOf($nav, 'Security') + 1] | Should -Be 'Asr'
        $nav[[array]::IndexOf($nav, 'Security') + 2] | Should -Be 'Defender'
        foreach ($p in 'Gamer', 'PowerUser', 'Sysadmin') {
            $order = @((InModuleScope iGWindowsTuner -Parameters @{ P = $p } { param($P) Get-IgwtPersonaProfile -Name $P }).NavOrder)
            if ($order.Count) { $order[[array]::IndexOf($order, 'Security') + 1] | Should -Be 'Asr' -Because $p; $order[[array]::IndexOf($order, 'Security') + 2] | Should -Be 'Defender' -Because $p }
        }
    }
    It 'defines every Defender page control the GUI code uses and builds its rows' {
        $names = @($script:Xaml.SelectNodes("//*[@*[local-name()='Name']]") | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') })
        $list = InModuleScope iGWindowsTuner { $script:IgwtGuiControlNames }
        foreach ($n in @($list | Where-Object { $_ -like 'Def*' -or $_ -in 'PageDefender', 'SecDefenderButton', 'AsrDefenderButton' })) { $names | Should -Contain $n }
        InModuleScope iGWindowsTuner {
            $row = New-IgwtGuiDefenderRow -Setting ([pscustomobject]@{ Property = 'CloudBlockLevel'; Name = 'Cloud block level'; Hint = 'h'; CategoryName = 'Cloud protection'; Edit = 'set'; Editable = $true; Source = 'Local'; Display = 'Default'; Status = 'Below'; ProtectiveDisplay = 'High' })
            $row.EditText | Should -Be 'Changeable'; $row.RecommendText | Should -Be 'Recommended: High'; $row.SourceVisibility | Should -Be 'Collapsed'
            $row = New-IgwtGuiDefenderRow -Setting ([pscustomobject]@{ Property = 'PUAProtection'; Name = 'PUA'; Hint = 'h'; CategoryName = 'PUA'; Edit = 'set'; Editable = $false; Source = 'MDM'; Display = 'Block'; Status = 'On'; ProtectiveDisplay = 'Block' })
            $row.EditText | Should -Be 'Set by MDM'; $row.RecommendText | Should -Be 'Meets recommendation'; $row.SourceVisibility | Should -Be 'Visible'
            $p = New-IgwtGuiDefenderPolicyRow -Policy ([pscustomobject]@{ Id = 'WindowsDefender:Scan_DisableHeuristics'; Name = 'Turn on heuristics'; Category = 'Windows Components > Microsoft Defender Antivirus > Scan'; State = 'NotConfigured'; Source = 'Not configured'; Preference = ''; Simple = $true; Refused = @('Disabled: Turns off a Defender scanning component.') })
            $p.StateText | Should -Be 'Not configured'; $p.RefusedText | Should -Be 'Refused: Disabled'; $p.CategoryText | Should -Be 'Microsoft Defender Antivirus > Scan'; $p.PreferenceVisibility | Should -Be 'Collapsed'
        }
    }
    It 'defines every named dashboard control the GUI code uses' {
        $names = @($script:Xaml.SelectNodes("//*[@*[local-name()='Name']]") | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') })
        $list = InModuleScope iGWindowsTuner { $script:IgwtGuiControlNames }
        foreach ($n in @($list | Where-Object { $_ -like 'Dash*' -or $_ -in 'SecuritySwitch', 'SecAsrButton', 'AsrHardeningButton' })) { $names | Should -Contain $n }
    }
}
