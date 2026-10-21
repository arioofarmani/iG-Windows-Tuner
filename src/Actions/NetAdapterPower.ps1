# NetAdapterPower.ps1
# 'netAdapterPower' action: the Device Manager option "Allow the computer to turn off this
# device to save power" for the active wired adapter.
#
# Set-NetAdapterPowerManagement does not expose this option, so it is written as the
# documented PnPCapabilities value in the adapter's driver key (24 = do not allow, 0 = allow,
# the default). The action is implemented by the registry engine (see Get-IgwtRegistryTargets
# and Get-IgwtRegistryActionEffective in Registry.ps1) so it gets the same exact snapshot and
# revert behavior as every other registry value. A reboot is required for it to take effect.

function Get-IgwtAdapterPowerInfo {
    <# .SYNOPSIS Read-only: PnPCapabilities for each active wired adapter (used by the health report). #>
    [CmdletBinding()]
    param()
    foreach ($a in @(Get-IgwtActiveWiredAdapter)) {
        $classKey = Get-IgwtAdapterClassKey -InterfaceGuid $a.InterfaceGuid
        $value = $null
        if ($classKey) {
            try { $value = (Get-ItemProperty -LiteralPath $classKey -Name PnPCapabilities -ErrorAction Stop).PnPCapabilities } catch { $value = $null }
        }
        [pscustomobject]@{
            Adapter        = $a.Name
            PnPCapabilities = $value
            AllowTurnOff   = $(if ($null -eq $value) { 'Allowed (default)' } elseif (([int]$value -band 0x10) -ne 0 -or ([int]$value -band 0x08) -ne 0) { 'Not allowed' } else { 'Allowed' })
        }
    }
}
