# Cache.ps1
# Short-lived read cache for slow, read-only queries (Get-MpPreference, powercfg /list, adapter
# properties) so one state scan does not repeat them dozens of times. Every write path clears
# the related entries, and the cache is disabled in TestMode so mocks are always honored.

$script:IgwtCache = @{}

function Get-IgwtCached {
    <# .SYNOPSIS Returns a cached value or runs the scriptblock and caches its result for TtlSeconds. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Key, [int]$TtlSeconds = 5, [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock)
    if ($script:IgwtSettings.TestMode) { return (& $ScriptBlock) }
    $hit = $script:IgwtCache[$Key]
    if ($hit -and $hit.Expires -gt [DateTime]::UtcNow) { return $hit.Value }
    $value = & $ScriptBlock
    $script:IgwtCache[$Key] = @{ Value = $value; Expires = [DateTime]::UtcNow.AddSeconds($TtlSeconds) }
    return $value
}

function Clear-IgwtCache {
    <# .SYNOPSIS Drops cached entries whose key starts with Prefix (all entries without Prefix). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Prefix)
    if (-not $PSCmdlet.ShouldProcess('read cache', 'Clear')) { return }
    if (-not $Prefix) { $script:IgwtCache.Clear(); return }
    foreach ($k in @($script:IgwtCache.Keys)) { if ($k.StartsWith($Prefix)) { $script:IgwtCache.Remove($k) } }
}
