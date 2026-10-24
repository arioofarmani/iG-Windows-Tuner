# PolicyBrowser.ps1
# Data for the GUI Policy browser: every ADMX policy with its category, class, supported-on text and
# its Local Group Policy state, read in bulk (one Registry.pol read per class and an in-memory index;
# the exact state is worked out only for the policies that have entries). Read-only. Changes go
# through Set-IgwtLocalPolicy (denylist, backup first).

function Get-IgwtPolicyEntryIndex {
    <# .SYNOPSIS The Local GPO Registry.pol entries of a class as a set of "key|valuename" (lower case, del. markers included). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Machine', 'User')][string]$Class, [object[]]$Entries)
    if ($null -eq $Entries) { $Entries = @(Get-IgwtLocalPolicyEntries -Class $Class) }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $keys = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in @($Entries)) {
        $k = ([string]$e.Key).ToLowerInvariant()
        $null = $keys.Add($k)
        $null = $set.Add("$k|$(([string]$e.ValueName -replace '^\*\*del(vals)?\.', '').ToLowerInvariant())")
    }
    return @{ Names = $set; Keys = $keys }
}

function Test-IgwtPolicyHasEntries {
    <# .SYNOPSIS Quick check: does any Registry.pol entry belong to this policy (main value, lists, elements)? Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Policy, [Parameter(Mandatory = $true)][hashtable]$Index)
    $key = ([string]$Policy.Key).ToLowerInvariant()
    if (-not $Index.Keys.Contains($key) -and -not @($Policy.Elements | Where-Object { $_ -and $Index.Keys.Contains(([string]$_.Key).ToLowerInvariant()) }).Count -and -not @(@($Policy.EnabledList) + @($Policy.DisabledList) | Where-Object { $_ -and $Index.Keys.Contains(([string]$_.Key).ToLowerInvariant()) }).Count) { return $false }
    if ($Policy.ValueName -and $Index.Names.Contains("$key|$(([string]$Policy.ValueName).ToLowerInvariant())")) { return $true }
    foreach ($e in @($Policy.Elements | Where-Object { $_ })) {
        $ek = ([string]$e.Key).ToLowerInvariant()
        if ($e.Type -eq 'list') { if ($Index.Keys.Contains($ek)) { return $true } }
        elseif ($e.ValueName -and $Index.Names.Contains("$ek|$(([string]$e.ValueName).ToLowerInvariant())")) { return $true }
    }
    foreach ($i in @(@($Policy.EnabledList) + @($Policy.DisabledList) | Where-Object { $_ -and $_.ValueName })) { if ($Index.Names.Contains("$(([string]$i.Key).ToLowerInvariant())|$(([string]$i.ValueName).ToLowerInvariant())")) { return $true } }
    return $false
}

function Get-IgwtPolicyBrowserData {
    <#
    .SYNOPSIS
        Every ADMX policy for the GUI browser with its Local GPO state (Not configured, Enabled,
        Disabled or Configured) and the category tree. Read-only.
    #>
    [CmdletBinding()]
    param()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $cat = Get-IgwtAdmxCatalog
    $loadMs = $sw.ElapsedMilliseconds
    $idx = @{ Machine = (Get-IgwtPolicyEntryIndex -Class Machine); User = (Get-IgwtPolicyEntryIndex -Class User) }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($cat.Policies)) {
        $classes = $(switch ([string]$p.Class) { 'Machine' { @('Machine') } 'User' { @('User') } default { @('Machine', 'User') } })
        $state = 'NotConfigured'
        foreach ($cl in $classes) {
            if (Test-IgwtPolicyHasEntries -Policy $p -Index $idx[$cl]) {
                try { $state = [string](Get-IgwtPolicyLocalState -Policy $p -Class $cl) } catch { $state = 'Configured' }
                if ($state -ne 'NotConfigured') { break }
            }
        }
        $rows.Add([pscustomobject]@{
                Id = [string]$p.Id; Name = [string]$p.DisplayName; Category = [string]$p.CategoryPath; Class = $(if ([string]$p.Class -eq 'Both') { 'Machine and user' } else { [string]$p.Class })
                SupportedOn = [string]$p.SupportedOn; State = $state; Simple = (@($p.Elements).Count -eq 0); File = [string]$p.File
            })
    }
    [pscustomobject]@{ Policies = $rows.ToArray(); Count = $rows.Count; Configured = @($rows | Where-Object { $_.State -ne 'NotConfigured' }).Count; CatalogMs = $loadMs; TotalMs = $sw.ElapsedMilliseconds; Errors = @($cat.Errors) }
}

function Get-IgwtPolicyBrowserDetail {
    <#
    .SYNOPSIS
        One policy for the GUI details pane: explanation, effective state (Local GPO, registry,
        domain, MDM) and the states it can be set to from the GUI. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $p = Get-IgwtPolicyDefinition -Id $Id
    $st = $null
    try { $st = Get-IgwtPolicyState -Policy $p } catch { Write-Verbose "State of ${Id}: $($_.Exception.Message)" }
    [pscustomobject]@{
        Id = [string]$p.Id; Name = [string]$p.DisplayName; Explain = [string]$p.Explain; Category = [string]$p.CategoryPath; SupportedOn = [string]$p.SupportedOn; Class = [string]$p.Class
        LocalGpo = $(if ($st) { [string]$st.LocalGpo } else { 'Unknown' }); Source = $(if ($st) { [string]$st.Source } else { 'unknown' }); Tattooed = [bool]($st -and $st.Tattooed); Conflicts = @($(if ($st) { $st.Conflicts }))
        Choices = @(Get-IgwtPolicyChoices -Policy $p)
    }
}
