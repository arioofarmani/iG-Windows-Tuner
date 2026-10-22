# TestHelpers.ps1
# Shared setup for the iG Windows Tuner Pester 5 suite.
# Safety: tests never touch the real HKLM/HKCU. Every registry path is redirected into Pester's
# TestRegistry: drive, and the engine's TestMode throws if any path escapes the redirect.
# External executables (powercfg, nvidia-smi) throw in TestMode unless mocked, and all
# system-changing cmdlets (Defender, NetAdapter, NetQos, DNS, services) are mocked per test.
# The suite refuses to run elevated on a real machine so an unmocked call cannot change anything.

$script:IgwtProjectRoot = Split-Path -Parent $PSScriptRoot

function Assert-IgwtTestNotElevated {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $env:IGWT_ALLOW_ELEVATED_TESTS) {
        throw 'Run the iG Windows Tuner tests from a NON-elevated PowerShell (set IGWT_ALLOW_ELEVATED_TESTS=1 only inside Windows Sandbox).'
    }
}

function Initialize-IgwtTestEnvironment {
    <# .SYNOPSIS Imports the module and redirects all registry access into TestRegistry:. Call from BeforeAll. #>
    Assert-IgwtTestNotElevated
    Import-Module (Join-Path $script:IgwtProjectRoot 'src\iGWindowsTuner.psd1') -Force
    $null = New-Item -Path 'TestRegistry:\HKLM' -Force
    $null = New-Item -Path 'TestRegistry:\HKCU' -Force
    $null = New-Item -Path 'TestRegistry:\HKU' -Force
    $redirect = [ordered]@{ 'HKLM:\' = 'TestRegistry:\HKLM\'; 'HKCU:\' = 'TestRegistry:\HKCU\'; 'HKU:\' = 'TestRegistry:\HKU\' }
    Set-IgwtEnvironment -TestMode -DataRoot (Join-Path $TestDrive 'IgwtData') -RegistryRedirect $redirect
}

function New-IgwtTestContext {
    <# .SYNOPSIS Engine context with no real adapters or games (tests add what they need). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([hashtable]$Extra = @{})
    $o = @{ IsAdmin = $true; Build = 26300; EditionId = 'Professional'; IsRdp = $false; WiredAdapters = @(); Games = @(); GpuCount = 1; HasNvidia = $true; HybridCpu = $true; DefenderActive = $true }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    return (New-IgwtContext -Override $o)
}

function New-IgwtTestTweak {
    <# .SYNOPSIS Minimal normalized (schema v2) tweak object for engine tests, including the computed expert/antiCheatSafe/tier properties. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds or refreshes in-memory objects only; changes no system state.')]
    [CmdletBinding()]
    param([string]$Id, [object[]]$Actions, [string]$Requires = 'none', [int]$Order = 50, [switch]$Expert, [string[]]$ConflictsWith = @())
    $level = 'Standard'
    if ($Expert) { $level = 'Expert' }
    $t = [pscustomobject]@{
        id = $Id; name = "Test $Id"; category = 'Security'; level = $level; hint = 'test'; description = 'test (measure)'
        evidence = [pscustomobject]@{ tier = 'A'; sources = @('https://learn.microsoft.com/'); notes = '' }
        impact = [pscustomobject]@{ performance = 'none'; latency = 'none'; security = '0' }
        risk = 'low'; antiCheat = 'safe'; reversible = 'full'; sideEffects = ''; requires = $Requires; order = $Order; warning = 'w'
        source = 'igwt'; attribution = ''; hardware = [pscustomobject]@{ tags = @(); excludeTags = @() }
        conflictsWith = $ConflictsWith; status = 'Active'; statusReason = ''; policyKeys = @(); postApply = $null; group = ''; revertNote = ''
        appliesTo = [pscustomobject]@{ minBuild = 26100; conditions = @() }
        actions = @($Actions | ForEach-Object { [pscustomobject]$_ })
        expert = [bool]$Expert; antiCheatSafe = $true; antiCheatText = 'Anti-cheat safe'; tier = 'A'
    }
    return $t
}
