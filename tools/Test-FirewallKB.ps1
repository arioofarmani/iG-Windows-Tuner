<#
.SYNOPSIS
    Validates the Firewall Manager knowledge base (data\firewall\*.json). Read-only.
.DESCRIPTION
    Checks required fields, valid categories, roles, severities, actions and risk checks, https
    sources, hint length, and that no id, group resource string, rule ID pattern or port appears
    twice. Exit code 0 = valid, 1 = errors found.
.EXAMPLE
    .\tools\Test-FirewallKB.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\iGWindowsTuner.psd1') -Force
$errors = @(Test-IgwtFirewallKnowledgeBase)
if ($errors.Count -eq 0) {
    $kb = Get-IgwtFirewallKnowledgeBase
    Write-Output ("Firewall knowledge base OK: {0} categories, {1} groups, {2} risk rules, {3} ports, {4} services, {5} protected programs, {6} roles." -f
        @($kb.Categories).Count, @($kb.Groups).Count, @($kb.Risks).Count, @($kb.Ports).Count, @($kb.Services).Count, @($kb.Apps.protected).Count, @($kb.Roles).Count)
    exit 0
}
Write-Output "Firewall knowledge base has $($errors.Count) error(s):"
$errors | ForEach-Object { Write-Output "  - $_" }
exit 1
