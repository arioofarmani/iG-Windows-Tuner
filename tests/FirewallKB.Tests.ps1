BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

# Firewall Manager 3.4 knowledge base (data\firewall\*.json) and its validator.
Describe 'Firewall knowledge base' {
    It 'is valid: categories, groups, risk rules, ports, services, programs and roles' {
        InModuleScope iGWindowsTuner {
            @(Test-IgwtFirewallKnowledgeBase) | Should -BeNullOrEmpty
            $kb = Get-IgwtFirewallKnowledgeBase -Force
            @($kb.Categories).Count | Should -Be 9
            @($kb.Categories | Where-Object layer -EQ 'origin').Count | Should -Be 4
            @($kb.Groups | Where-Object id -EQ 'core-networking').category | Should -Be 'CoreServices'
            @($kb.Risks | Where-Object severity -EQ 'Critical').Count | Should -BeGreaterThan 0
        }
    }

    It 'is part of the catalog check' {
        InModuleScope iGWindowsTuner { (Get-Command Test-IgwtCatalog).Definition | Should -Match 'Test-IgwtFirewallKnowledgeBase' }
    }

    It 'reports missing fields, bad values, unknown checks, duplicates and non-https sources' {
        $src = Join-Path $script:IgwtProjectRoot 'data'
        $copy = Join-Path $TestDrive 'data'
        $null = New-Item -ItemType Directory -Path (Join-Path $copy 'firewall') -Force
        Copy-Item (Join-Path $src 'firewall\*.json') (Join-Path $copy 'firewall')
        $g = Get-Content (Join-Path $copy 'firewall\groups.json') -Raw | ConvertFrom-Json
        $dup = $g.groups[1] | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $dup.hint = 'x' * 141
        $dup.roles.Gamer = 'maybe'
        $dup.sources = @('http://example.com/plain')
        $g.groups += $dup
        $g | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $copy 'firewall\groups.json') -Encoding UTF8
        $r = Get-Content (Join-Path $copy 'firewall\risks.json') -Raw | ConvertFrom-Json
        $r.risks[0].when = @('enabled', 'madeUpCheck', 'ports:nope')
        $r.risks[1].recommended = 'Delete'
        $r.risks[2].severity = 'Severe'
        $r | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $copy 'firewall\risks.json') -Encoding UTF8
        InModuleScope iGWindowsTuner -Parameters @{ Copy = $copy } {
            param($Copy)
            $old = $script:IgwtSettings.DataFolder
            try {
                $script:IgwtSettings.DataFolder = $Copy
                $errors = @(Test-IgwtFirewallKnowledgeBase)
                ($errors -join "`n") | Should -Match 'duplicate id'
                ($errors -join "`n") | Should -Match 'longer than 140'
                ($errors -join "`n") | Should -Match "role 'Gamer' must be"
                ($errors -join "`n") | Should -Match 'not an https URL'
                ($errors -join "`n") | Should -Match "unknown check 'madeUpCheck'"
                ($errors -join "`n") | Should -Match "unknown port set 'nope'"
                ($errors -join "`n") | Should -Match 'Delete may only be recommended'
                ($errors -join "`n") | Should -Match 'severity must be'
                ($errors -join "`n") | Should -Match 'is also in'
            } finally { $script:IgwtSettings.DataFolder = $old; $null = Get-IgwtFirewallKnowledgeBase -Force }
        }
    }
}
