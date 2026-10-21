# RegistryListMerge.ps1
# 'registryListMerge' action: edits one key=value item inside a semicolon-separated REG_SZ
# (for example DirectXUserGlobalSettings = "SwapEffectUpgradeEnable=1;VRROptimizeEnable=1;").
# Unrelated items are always preserved; the value is never overwritten wholesale.

$script:IgwtRemoveItem = '<remove>'

function ConvertFrom-IgwtListString {
    <# .SYNOPSIS Parses "A=1;B=2;" into ordered items (Key, Value, Raw). #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $list = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrEmpty($Text)) { return , $list }
    foreach ($part in $Text.Split([char[]]@(';'))) {
        if ($part.Trim().Length -eq 0) { continue }
        $idx = $part.IndexOf('=')
        if ($idx -gt 0) {
            $list.Add([pscustomobject]@{ Key = $part.Substring(0, $idx).Trim(); Value = $part.Substring($idx + 1); Raw = $part })
        } else {
            $list.Add([pscustomobject]@{ Key = $null; Value = $null; Raw = $part })
        }
    }
    return , $list
}

function ConvertTo-IgwtListString {
    <# .SYNOPSIS Serializes items back to "A=1;B=2;" (Windows writes a trailing semicolon). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Items)
    $sb = New-Object System.Text.StringBuilder
    foreach ($i in $Items) {
        if ($null -ne $i.Key) { $null = $sb.Append("$($i.Key)=$($i.Value);") } else { $null = $sb.Append("$($i.Raw);") }
    }
    return $sb.ToString()
}

function Get-IgwtListItemValue {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory = $true)][string]$Key)
    foreach ($i in (ConvertFrom-IgwtListString $Text)) {
        if ($null -ne $i.Key -and [string]::Equals($i.Key, $Key, [System.StringComparison]::OrdinalIgnoreCase)) { return $i.Value }
    }
    return $null
}

function Set-IgwtListItem {
    <# .SYNOPSIS Returns Text with Key set to Value (replaced in place or appended). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][string]$Value)
    $items = ConvertFrom-IgwtListString $Text
    $found = $false
    foreach ($i in $items) {
        if ($null -ne $i.Key -and [string]::Equals($i.Key, $Key, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($PSCmdlet.ShouldProcess($Key, "Set list item to $Value")) { $i.Value = $Value }
            $found = $true
        }
    }
    if (-not $found) { $items.Add([pscustomobject]@{ Key = $Key; Value = $Value; Raw = "$Key=$Value" }) }
    return (ConvertTo-IgwtListString $items)
}

function Remove-IgwtListItem {
    <# .SYNOPSIS Returns Text without Key. Other items are untouched. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory = $true)][string]$Key)
    $items = ConvertFrom-IgwtListString $Text
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($i in $items) {
        if ($null -ne $i.Key -and [string]::Equals($i.Key, $Key, [System.StringComparison]::OrdinalIgnoreCase)) {
            if (-not $PSCmdlet.ShouldProcess($Key, 'Remove list item')) { $kept.Add($i) }
            continue
        }
        $kept.Add($i)
    }
    return (ConvertTo-IgwtListString $kept)
}

function Get-IgwtListMergeState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Action, $Context)
    $cur = Get-IgwtRegistryValue -Path $Action.path -Name $Action.name
    $text = $null
    if ($cur.Exists) { $text = [string]$cur.Value }
    $itemValue = Get-IgwtListItemValue -Text $text -Key $Action.item
    $isOn = ($null -ne $itemValue -and [string]$itemValue -eq [string]$Action.on)
    $desiredText = Set-IgwtListItem -Text $text -Key $Action.item -Value ([string]$Action.on) -WhatIf:$false
    [pscustomobject]@{
        Target  = "$($Action.path)\$($Action.name) [$($Action.item)]"
        Current = $(if ($cur.Exists) { '"{0}"' -f $text } else { $script:IgwtAbsent })
        Desired = ('"{0}"' -f $desiredText)
        State   = $(if ($isOn) { 'On' } else { 'Off' })
        Note    = 'Only this item is changed; other items in the string are preserved.'
    }
}

function Invoke-IgwtListMergeApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Action, $Context, [ValidateSet('on', 'off', 'default')][string]$Mode = 'on')
    $cur = Get-IgwtRegistryValue -Path $Action.path -Name $Action.name
    $text = $null
    $kind = 'String'
    if ($cur.Exists) {
        $text = [string]$cur.Value
        if ($cur.Kind -eq 'ExpandString') { $kind = 'ExpandString' }
    }
    $target = $Action.on
    if ($Mode -eq 'off') { $target = $Action.off }
    if ($Mode -eq 'default') { $target = $Action.default }
    if ($null -eq $target) { $target = $script:IgwtRemoveItem }
    if ([string]$target -eq $script:IgwtRemoveItem) {
        $new = Remove-IgwtListItem -Text $text -Key $Action.item -WhatIf:$false
    } else {
        $new = Set-IgwtListItem -Text $text -Key $Action.item -Value ([string]$target) -WhatIf:$false
    }
    if ($cur.Exists -and $new -eq $text) { return }
    if ([string]::IsNullOrEmpty($new)) {
        if ($cur.Exists -and $PSCmdlet.ShouldProcess("$($Action.path)\$($Action.name)", 'Delete empty list value')) {
            Remove-IgwtRegistryValue -Path $Action.path -Name $Action.name
        }
        return
    }
    if ($PSCmdlet.ShouldProcess("$($Action.path)\$($Action.name)", "Set list item $($Action.item)")) {
        Set-IgwtRegistryValue -Path $Action.path -Name $Action.name -Kind $kind -Value $new
    }
}
