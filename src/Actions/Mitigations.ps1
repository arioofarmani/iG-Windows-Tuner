# Mitigations.ps1
# Exploit protection actions (ProcessMitigations module):
#   processMitigation  one mitigation for one program (Set-ProcessMitigation -Name)
#   exploitSystem      one system-wide mitigation (Set-ProcessMitigation -System); catalog items may
#                      only turn system mitigations ON
# Each mitigation is captured as ON, OFF or NOTSET and restored exactly: NOTSET is restored with
# '-Remove -Disable <mitigation>', which Microsoft documents as returning it to the default.
# 'equivalentOn': ['NOTSET'] makes an item repair-only: "use default" counts as on (for mitigations
# that Windows enables by default), so only an explicit OFF is changed.

# Mitigation name (as used by -Enable/-Disable) -> property path in Get-ProcessMitigation output.
$script:IgwtMitigationMap = [ordered]@{
    DEP = 'DEP.Enable'; EmulateAtlThunks = 'DEP.EmulateAtlThunks'; SEHOP = 'SEHOP.Enable'
    ForceRelocateImages = 'ASLR.ForceRelocateImages'; RequireInfo = 'ASLR.RequireInfo'; BottomUp = 'ASLR.BottomUp'; HighEntropy = 'ASLR.HighEntropy'
    CFG = 'CFG.Enable'; SuppressExports = 'CFG.SuppressExports'; StrictCFG = 'CFG.StrictControlFlowGuard'
    StrictHandle = 'StrictHandle.Enable'; DisableExtensionPoints = 'ExtensionPoints.DisableExtensionPoints'
    BlockDynamicCode = 'DynamicCode.BlockDynamicCode'; DisableNonSystemFonts = 'FontDisable.DisableNonSystemFonts'
    BlockRemoteImageLoads = 'ImageLoad.BlockRemoteImageLoads'; BlockLowLabelImageLoads = 'ImageLoad.BlockLowLabelImageLoads'; PreferSystem32 = 'ImageLoad.PreferSystem32'
    DisallowChildProcessCreation = 'ChildProcess.DisallowChildProcessCreation'; MicrosoftSignedOnly = 'BinarySignature.MicrosoftSignedOnly'
    DisableWin32kSystemCalls = 'SystemCalls.DisableWin32kSystemCalls'
}

function Get-IgwtMitigationValue {
    <# .SYNOPSIS ON, OFF or NOTSET for one mitigation, system-wide (no -Process) or for one program. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Mitigation, [string]$Process)
    $path = $script:IgwtMitigationMap[$Mitigation]
    if (-not $path) { throw "Unsupported mitigation '$Mitigation'." }
    $obj = $null
    try {
        if ($Process) { $obj = Get-ProcessMitigation -Name $Process -ErrorAction Stop } else { $obj = Get-ProcessMitigation -System -ErrorAction Stop }
    } catch {
        if ($Process) { return 'NOTSET' }
        throw
    }
    $obj = @($obj) | Select-Object -First 1
    if (-not $obj) { return 'NOTSET' }
    $v = $obj
    foreach ($part in $path.Split('.')) {
        if ($null -eq $v) { break }
        $v = $v.$part
    }
    $s = ([string]$v).ToUpperInvariant()
    if ($s -in 'ON', 'OFF') { return $s }
    return 'NOTSET'
}

function Set-IgwtMitigationValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Mitigation, [Parameter(Mandatory = $true)][ValidateSet('ON', 'OFF', 'NOTSET')][string]$Value, [string]$Process)
    $target = $(if ($Process) { $Process } else { 'system' })
    if (-not $PSCmdlet.ShouldProcess($target, "Set exploit protection $Mitigation = $Value")) { return }
    $p = @{ ErrorAction = 'Stop' }
    if ($Process) { $p.Name = $Process } else { $p.System = $true }
    switch ($Value) {
        'ON' { $p.Enable = $Mitigation }
        'OFF' { $p.Disable = $Mitigation }
        'NOTSET' { $p.Remove = $true; $p.Disable = $Mitigation }
    }
    $null = Set-ProcessMitigation @p
}

function Get-IgwtMitigationTarget {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Action)
    if ([string]$Action.type -eq 'processMitigation') { return [string]$Action.process }
    return ''
}

function Test-IgwtMitigationOn {
    <# .SYNOPSIS True when the value is the action's 'on' value or one of its equivalentOn values. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)][string]$Value)
    if ($Value -eq [string]$Action.on) { return $true }
    return (@($Action.equivalentOn | Where-Object { $_ } | ForEach-Object { ([string]$_).ToUpperInvariant() }) -contains $Value)
}

function Get-IgwtMitigationState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $proc = Get-IgwtMitigationTarget -Action $Action
    $label = "Exploit protection $($Action.mitigation) ($(if ($proc) { $proc } else { 'system-wide' }))"
    try { $cur = Get-IgwtMitigationValue -Mitigation ([string]$Action.mitigation) -Process $proc } catch {
        return [pscustomobject]@{ Target = $label; Current = 'unreadable'; Desired = [string]$Action.on; State = 'Unknown'; Note = $_.Exception.Message }
    }
    $note = $(if ($cur -eq 'NOTSET' -and (Test-IgwtMitigationOn -Action $Action -Value $cur)) { 'Use default (Windows turns it on).' } else { '' })
    [pscustomobject]@{ Target = $label; Current = $cur; Desired = [string]$Action.on; State = $(if (Test-IgwtMitigationOn -Action $Action -Value $cur) { 'On' } else { 'Off' }); Note = $note }
}

function Get-IgwtMitigationSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    return @{ value = (Get-IgwtMitigationValue -Mitigation ([string]$Action.mitigation) -Process (Get-IgwtMitigationTarget -Action $Action)) }
}

function Invoke-IgwtMitigationApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'default')][string]$Mode = 'on')
    $proc = Get-IgwtMitigationTarget -Action $Action
    $target = [string]$Action.on
    if ($Mode -eq 'default') { $target = 'NOTSET' }
    if ([string]$Action.type -eq 'exploitSystem' -and $target -eq 'OFF') { throw 'iG Windows Tuner never turns system-wide exploit protection off.' }
    $cur = Get-IgwtMitigationValue -Mitigation ([string]$Action.mitigation) -Process $proc
    if ($Mode -eq 'on' -and (Test-IgwtMitigationOn -Action $Action -Value $cur)) { return }
    if ($cur -ne $target) { Set-IgwtMitigationValue -Mitigation ([string]$Action.mitigation) -Value $target -Process $proc }
}

function Restore-IgwtMitigationSnapshot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, [Parameter(Mandatory = $true)]$Snapshot, $Context)
    $prev = ([string]$Snapshot.value).ToUpperInvariant()
    if ($prev -notin 'ON', 'OFF', 'NOTSET') { throw "Snapshot value '$prev' is not ON, OFF or NOTSET." }
    $proc = Get-IgwtMitigationTarget -Action $Action
    $cur = Get-IgwtMitigationValue -Mitigation ([string]$Action.mitigation) -Process $proc
    if ($cur -ne $prev) { Set-IgwtMitigationValue -Mitigation ([string]$Action.mitigation) -Value $prev -Process $proc }
}
