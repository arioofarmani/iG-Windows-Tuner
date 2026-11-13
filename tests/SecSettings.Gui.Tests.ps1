# Security Settings Manager, B10 (DECISIONS SM33): the grid rows of the Security settings page.
# The page itself (editor, detail pane, confirmation) is checked by the offscreen render.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-IgwtTestEnvironment
}

Describe 'Security settings grid rows' {
    It 'shows the state, a lock for read-only rows, staged changes and the filter keys' {
        InModuleScope iGWindowsTuner {
            Mock Get-IgwtGuiToneBrush { $null }
            $editable = New-IgwtSecSettingRow -Fields @{ Id = 'admx:F:P:Machine'; SourceKind = 'admx'; Name = 'Contoso policy'; State = 'Enabled'; Origin = 'LocalPolicy'; CurrentText = 'Enabled'; Category = @('Contoso', 'Child') }
            $locked = New-IgwtSecSettingRow -Fields @{ Id = 'defender:X'; SourceKind = 'defender'; Name = 'Contoso preference'; ReadOnly = $true; ReadOnlyReason = 'Set by MDM; change it there.'; Origin = 'Mdm' }
            $high = New-IgwtSecSettingRow -Fields @{ Id = 'admx:F:V:Machine'; SourceKind = 'admx'; Name = 'VBS'; State = 'NotConfigured'; Risk = 'high' }
            $r = New-IgwtGuiSecSettingRow -Setting $editable
            $r.StateCol | Should -Be 'Configured'; $r.ConfiguredKey | Should -Be 'Yes'; $r.AccessKey | Should -Be 'Editable'; $r.SourceText | Should -Be 'Group Policy'; $r.CategoryText | Should -Be 'Contoso > Child'
            $r = New-IgwtGuiSecSettingRow -Setting $locked
            $r.StateCol | Should -Be 'Read-only'; $r.AccessKey | Should -Be 'ReadOnly'; $r.Tip | Should -Match 'MDM'; $r.StateColGlyph | Should -Be $script:IgwtToneGlyph['Lock']
            (New-IgwtGuiSecSettingRow -Setting $high).StateCol | Should -Be 'High risk'
            (New-IgwtGuiSecSettingRow -Setting $editable -Staged @{ 'admx:F:P:Machine' = $true }).StateCol | Should -Be 'Staged'
        }
    }
}
