# PolicyBridge.ps1
# Routes catalog registry items that write a machine Policies key (HKLM\SOFTWARE\Policies and
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies) through the Local GPO: the value is
# written to the registry as before and also to Machine\Registry.pol (with a gpt.ini version
# bump), so it shows in gpedit and survives a policy refresh. Snapshots capture the exact
# Registry.pol entry bytes; older snapshots without them keep the file in step with the restored
# value. HKCU items stay direct per-user writes: the user part of the Local GPO applies to every
# account on the PC (docs\DECISIONS.md M1). Tattooed values can be adopted into the Local GPO or
# removed.

function Get-IgwtPolicyBridgeTarget {
    <# .SYNOPSIS The Registry.pol key and value name for a machine Policies registry path, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)
    if ($Path -notmatch '^(?i)HKLM:\\((SOFTWARE\\Policies|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies)(\\.*)?)$') { return $null }
    if (-not $Name) { return $null }
    return [pscustomobject]@{ Class = 'Machine'; Key = $Matches[1].TrimEnd('\'); ValueName = $Name }
}

function Test-IgwtPolicyBridgeEnabled {
    <#
    .SYNOPSIS
        True when Policies items go through the Local GPO: the edition has Local Group Policy and
        the bridge is not turned off. In TestMode only with a temporary GPO folder.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($script:IgwtSettings.PolicyBridge -eq $false) { return $false }
    if ($script:IgwtSettings.TestMode -and -not $script:IgwtSettings.GpoRoot) { return $false }
    try { return [bool](Get-IgwtManagementState).LocalGroupPolicy } catch { return $false }
}

function ConvertTo-IgwtPolTypeFromKind {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Kind)
    switch ($Kind) { 'String' { 1 } 'ExpandString' { 2 } 'Binary' { 3 } 'DWord' { 4 } 'MultiString' { 7 } 'QWord' { 11 } default { throw "Registry kind $Kind cannot be written to Registry.pol." } }
}

function Get-IgwtBridgePolEntries {
    <# .SYNOPSIS The Registry.pol entries of one value (the value itself and a **del. marker). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target, [AllowEmptyCollection()][object[]]$Entries)
    if ($null -eq $Entries) { $Entries = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $Target.Class)).Entries) }
    @($Entries | Where-Object {
            [string]::Equals([string]$_.Key, $Target.Key, [System.StringComparison]::OrdinalIgnoreCase) -and
            ([string]::Equals([string]$_.ValueName, $Target.ValueName, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals([string]$_.ValueName, "**del.$($Target.ValueName)", [System.StringComparison]::OrdinalIgnoreCase))
        })
}

function Save-IgwtBridgePol {
    <# .SYNOPSIS Writes Machine/User Registry.pol entries and bumps gpt.ini when the bytes changed. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class, [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Before, [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$After)
    $old = [BitConverter]::ToString((ConvertTo-IgwtRegistryPolBytes -Entries $Before))
    $new = [BitConverter]::ToString((ConvertTo-IgwtRegistryPolBytes -Entries $After))
    if ($old -eq $new) { return $false }
    if (-not $PSCmdlet.ShouldProcess("Local GPO $Class Registry.pol", 'Update')) { return $false }
    Write-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $Class) -Entries $After
    $gpt = Join-Path (Get-IgwtGpoRoot) 'gpt.ini'
    Assert-IgwtGpoPathAllowed -Path $gpt
    $text = $(if (Test-Path -LiteralPath $gpt) { [System.IO.File]::ReadAllText($gpt) } else { '' })
    [System.IO.File]::WriteAllText($gpt, (Update-IgwtGptIniText -Text $text -Class $Class), [System.Text.Encoding]::ASCII)
    Clear-IgwtCache -Prefix 'pol:' -WhatIf:$false
    return $true
}

function Set-IgwtBridgeValue {
    <#
    .SYNOPSIS
        Puts one value into the Local GPO Registry.pol (Exists) or removes it, making the policy
        "not configured" for that value. Other entries keep their exact bytes.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)][bool]$Exists, [string]$Kind, $Value)
    $before = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $Target.Class)).Entries)
    if ($Exists) {
        $type = ConvertTo-IgwtPolTypeFromKind -Kind $Kind
        $after = @(Set-IgwtPolEntry -Entries $before -Key $Target.Key -ValueName $Target.ValueName -Type $type -Value $Value)
    } else { $after = @(Remove-IgwtPolEntry -Entries $before -Key $Target.Key -ValueName $Target.ValueName) }
    return (Save-IgwtBridgePol -Class $Target.Class -Before $before -After $after)
}

function Test-IgwtBridgeInSync {
    <# .SYNOPSIS True when Registry.pol holds exactly the given value (or nothing, for an absent value). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)][bool]$Exists, [string]$Kind, $Value)
    $mine = @(Get-IgwtBridgePolEntries -Target $Target)
    if (-not $Exists) { return ($mine.Count -eq 0) }
    $val = @($mine | Where-Object { [string]::Equals([string]$_.ValueName, $Target.ValueName, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $val -or $mine.Count -ne 1) { return $false }
    if ([int]$val.Type -ne (ConvertTo-IgwtPolTypeFromKind -Kind $Kind)) { return $false }
    return ([BitConverter]::ToString([byte[]]$val.Data) -eq [BitConverter]::ToString((ConvertTo-IgwtPolData -Type $val.Type -Value $Value)))
}

function Get-IgwtBridgeSnapshot {
    <# .SYNOPSIS The exact Registry.pol entries of one value, for a snapshot ({ entries = [hex of the raw entry bytes] }). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target)
    return [ordered]@{ class = $Target.Class; entries = @(Get-IgwtBridgePolEntries -Target $Target | ForEach-Object { ConvertTo-IgwtHexString -Value (ConvertTo-IgwtPolEntryBytes -Entry $_) }) }
}

function Restore-IgwtBridgeSnapshot {
    <#
    .SYNOPSIS
        Restores the Registry.pol entries of one value from a snapshot. The key and value name come
        from the catalog action; snapshot entries for any other key or value are refused.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Target, [Parameter(Mandatory = $true)]$Pol)
    # Each snapshot entry is one raw [key;value;type;size;data] record; parse it behind a PReg header.
    $header = ConvertTo-IgwtRegistryPolBytes -Entries @()
    $restore = @(foreach ($b in @($Pol.entries)) { (Read-IgwtRegistryPol -Bytes ([byte[]]($header + (ConvertTo-IgwtByteArray -Value ([string]$b))))).Entries })
    foreach ($e in $restore) {
        $okName = [string]::Equals([string]$e.ValueName, $Target.ValueName, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals([string]$e.ValueName, "**del.$($Target.ValueName)", [System.StringComparison]::OrdinalIgnoreCase)
        if (-not [string]::Equals([string]$e.Key, $Target.Key, [System.StringComparison]::OrdinalIgnoreCase) -or -not $okName) { throw "The snapshot's Registry.pol entry $($e.Key)\$($e.ValueName) does not belong to $($Target.Key)\$($Target.ValueName); nothing was restored." }
    }
    $before = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class $Target.Class)).Entries)
    $after = @(Remove-IgwtPolEntry -Entries $before -Key $Target.Key -ValueName $Target.ValueName) + $restore
    return (Save-IgwtBridgePol -Class $Target.Class -Before $before -After @($after))
}

#region Tattooed values

function Get-IgwtTattooAdoptionPlan {
    <#
    .SYNOPSIS
        Plan for tattooed machine values: Adopt (add the current value to the Local GPO, so it is
        managed and visible in gpedit) or Remove (delete it from the registry). Values on the
        policy denylist cannot be adopted (they would cement a disabled protection); they can be
        removed. Read-only.
    .PARAMETER Select
        "Key\ValueName" entries, or 'igwt' for every value written by an iG Windows Tuner item.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Adopt', 'Remove')][string]$Action, [Parameter(Mandatory = $true)][string[]]$Select)
    $rows = @(Get-IgwtTattooedPolicyValues | Where-Object { $_.Class -eq 'Machine' })
    $wanted = @($Select | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $picked = @($rows | Where-Object { $r = $_; ($wanted -contains 'igwt' -and $r.WrittenBy -like 'iG*') -or @($wanted | Where-Object { [string]::Equals($_, "$($r.Key)\$($r.ValueName)", [System.StringComparison]::OrdinalIgnoreCase) }).Count })
    $missing = @($wanted | Where-Object { $w = $_; $w -ne 'igwt' -and -not @($picked | Where-Object { [string]::Equals("$($_.Key)\$($_.ValueName)", $w, [System.StringComparison]::OrdinalIgnoreCase) }).Count })
    $ops = foreach ($r in $picked) {
        $cur = Get-IgwtRegistryValue -Path ('HKLM:\' + $r.Key) -Name $r.ValueName
        $refusal = ''
        if ($Action -eq 'Adopt') {
            $why = Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = $r.Key; ValueName = $r.ValueName; Type = $cur.Kind; Value = $cur.Value })
            if ($why) { $refusal = "cannot be adopted: $why Remove it instead." }
            elseif ($cur.Kind -notin 'String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord') { $refusal = "type $($cur.Kind) cannot be written to Registry.pol." }
        }
        [pscustomobject]@{ Key = $r.Key; ValueName = $r.ValueName; Kind = $cur.Kind; Value = $cur.Value; WrittenBy = $r.WrittenBy; Refusal = $refusal }
    }
    [pscustomobject]@{ Action = $Action; Ops = @($ops); NotFound = $missing; Enabled = (Test-IgwtPolicyBridgeEnabled) }
}

function Invoke-IgwtTattooAdoption {
    <#
    .SYNOPSIS
        Adopts tattooed values into the Local GPO (after a GPO backup) or removes them from the
        registry (after saving them to a restore file). Returns the backup folder or restore file.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][ValidateSet('Adopt', 'Remove')][string]$Action, [Parameter(Mandatory = $true)][string[]]$Select)
    $plan = Get-IgwtTattooAdoptionPlan -Action $Action -Select $Select
    $ok = @($plan.Ops | Where-Object { -not $_.Refusal })
    if (-not $ok.Count) { throw 'Nothing to do: no selected tattooed value can be changed.' }
    if ($Action -eq 'Adopt' -and -not $plan.Enabled) { throw 'This edition has no Local Group Policy (or the bridge is off); values cannot be adopted.' }
    if (-not $script:IgwtSettings.TestMode -and -not (Test-IgwtIsAdmin)) { throw 'This needs administrator rights.' }
    if (-not $PSCmdlet.ShouldProcess("$($ok.Count) tattooed value(s)", $Action)) { return $null }
    if ($Action -eq 'Adopt') {
        $backup = Backup-IgwtLocalGpo -Reason 'before adopting tattooed values'
        $before = @((Read-IgwtRegistryPol -Path (Get-IgwtLocalPolPath -Class Machine)).Entries)
        $after = $before
        foreach ($o in $ok) { $after = @(Set-IgwtPolEntry -Entries $after -Key $o.Key -ValueName $o.ValueName -Type (ConvertTo-IgwtPolTypeFromKind -Kind $o.Kind) -Value $o.Value) }
        $null = Save-IgwtBridgePol -Class Machine -Before $before -After $after
        Write-IgwtLog -Message "Adopted $($ok.Count) tattooed value(s) into the Local GPO. Backup: $backup"
        return [pscustomobject]@{ Action = 'Adopt'; Count = $ok.Count; Backup = $backup; Skipped = @($plan.Ops | Where-Object { $_.Refusal }) }
    }
    if (-not $script:IgwtSettings.TestMode) { Initialize-IgwtDataRoot }
    $dir = Get-IgwtDataPath -Kind Backups
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $file = Join-Path $dir ("tattoo-{0}.json" -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
    $doc = [ordered]@{ kind = 'igwt-tattoo-removal'; created = (Get-Date).ToString('o'); values = @($ok | ForEach-Object { [ordered]@{ key = $_.Key; name = $_.ValueName; kind = $_.Kind; value = (ConvertTo-IgwtSerializableValue -Value $_.Value -Kind $_.Kind) } }) }
    [System.IO.File]::WriteAllText($file, (ConvertTo-IgwtJson -InputObject $doc), (New-Object System.Text.UTF8Encoding($false)))
    foreach ($o in $ok) { Remove-IgwtRegistryValue -Path ('HKLM:\' + $o.Key) -Name $o.ValueName }
    Write-IgwtLog -Message "Removed $($ok.Count) tattooed value(s). Restore file: $file"
    return [pscustomobject]@{ Action = 'Remove'; Count = $ok.Count; Backup = $file; Skipped = @($plan.Ops | Where-Object { $_.Refusal }) }
}

function Restore-IgwtTattooRemoval {
    <# .SYNOPSIS Writes back values removed by Invoke-IgwtTattooAdoption -Action Remove (only under the machine Policies keys). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    $doc = Read-IgwtJsonFile -Path $Path
    if ([string]$doc.kind -ne 'igwt-tattoo-removal') { throw "'$Path' is not a tattoo removal file." }
    $n = 0
    foreach ($v in @($doc.values)) {
        if (-not (Get-IgwtPolicyBridgeTarget -Path ('HKLM:\' + [string]$v.key) -Name ([string]$v.name))) { throw "'$($v.key)' is not under a machine Policies key; nothing more was restored." }
        if ($PSCmdlet.ShouldProcess("HKLM:\$($v.key)\$($v.name)", 'Restore')) {
            Set-IgwtRegistryValue -Path ('HKLM:\' + [string]$v.key) -Name ([string]$v.name) -Kind ([string]$v.kind) -Value (ConvertFrom-IgwtSerializableValue -Data $v.value -Kind ([string]$v.kind))
            $n++
        }
    }
    return [pscustomobject]@{ Restored = $n }
}

#endregion
