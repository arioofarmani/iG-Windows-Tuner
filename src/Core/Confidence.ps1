# Confidence.ps1
# Confidence badges (3.6, DECISIONS T8 and T13): computed per catalog item, never stored.
#   Verified     a qualifying source, and the item applied and read back correctly on this Windows
#                build (this PC's change journal, or evidence.testedBuilds from Sandbox runs).
#   Best effort  a qualifying source, but no passed read-back on this build (or evidence.partialSource).
#   Unverified   no qualifying source.
# A qualifying source is Microsoft documentation, hardware-vendor documentation (intel.com) or a
# DECISIONS ID ("DECISIONS T8"). Verified means "applies and reads back correctly", not "faster".

$script:IgwtQualifyingSourcePattern = '^https://(learn|support|msrc|devblogs|technet)\.microsoft\.com/|^https://blogs\.windows\.com/|^https://(www\.)?intel\.com/|^DECISIONS [A-Z]{1,3}\d{1,3}[a-z]?$'

function Test-IgwtQualifyingSource {
    <# .SYNOPSIS True when a source counts for a confidence badge (DECISIONS T13). Pure. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Source)
    return ($Source -match $script:IgwtQualifyingSourcePattern)
}

function Get-IgwtConfidenceContext {
    <#
    .SYNOPSIS
        What the badges need once per screen: this Windows build and the catalog items whose every
        changed action read back correctly on this build in this PC's journal. Read-only.
    #>
    [CmdletBinding()]
    param($Journal)
    $build = [string](Get-IgwtWindowsBuildInfo).Build
    $passed = New-Object 'System.Collections.Generic.HashSet[string]'
    $failed = New-Object 'System.Collections.Generic.HashSet[string]'
    if (-not $Journal) { try { $Journal = Read-IgwtJournal } catch { $Journal = $null } }
    if ($Journal -and $Journal.Status -eq 'Ok') {
        foreach ($e in $Journal.Entries) {
            $kind = [string]$e['kind']
            if ($kind -notin 'committed', 'failed') { continue }
            $t = $e['target']
            if (-not ($t -is [System.Collections.IDictionary]) -or [string]$t['provider'] -ne 'action' -or [string]$e['op'] -eq 'restore') { continue }
            if ([string]$e['build'] -ne $build) { continue }
            $id = [string]$e['item']
            if ($kind -eq 'committed' -and $e['readBack'] -and [bool]$e['readBack']['ok'] -and [string]$e['readBack']['state'] -ne 'imported') { $null = $passed.Add($id) }
            elseif ($kind -eq 'failed') { $null = $failed.Add($id) }
        }
    }
    return [pscustomobject]@{ Build = $build; Passed = $passed; Failed = $failed }
}

function Get-IgwtConfidence {
    <#
    .SYNOPSIS
        The confidence badge of one catalog item: Level (Verified, BestEffort, Unverified), Label,
        Tip (what was tested where), the qualifying sources and the tested builds. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Tweak, $Context)
    if (-not $Context) { $Context = Get-IgwtConfidenceContext }
    $ev = $Tweak.evidence
    $sources = @($ev.sources | Where-Object { $_ })
    $good = @($sources | Where-Object { Test-IgwtQualifyingSource -Source ([string]$_) })
    $tested = @($ev.testedBuilds | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $partial = [bool]$ev.partialSource
    $id = [string]$Tweak.id
    $here = $Context.Passed.Contains($id) -and -not $Context.Failed.Contains($id)
    $testedHere = $tested -contains $Context.Build
    $where = $(if ($here) { "Applied and read back correctly on this PC (build $($Context.Build))." }
        elseif ($testedHere) { "Tested in Windows Sandbox on build $($Context.Build), the build this PC runs." }
        elseif ($tested.Count) { "Tested on build $($tested -join ', '); this PC runs $($Context.Build)." }
        else { "Not yet tested on build $($Context.Build), the build this PC runs." })
    if ($Context.Failed.Contains($id)) { $where = "A read-back failed on this PC (build $($Context.Build)): see Backups & Logs > Change journal." }
    $meaning = 'Verified means it applies and reads back correctly, not that it makes the PC faster.'
    if (-not $good.Count) {
        $why = $(if ($sources.Count) { 'Its sources are not Microsoft or hardware-vendor documentation.' } else { 'It has no source.' })
        return [pscustomobject]@{ Id = $id; Level = 'Unverified'; Label = 'Unverified'; Tip = "Unverified. $why $where"; Sources = $good; TestedBuilds = $tested }
    }
    if (($here -or $testedHere) -and -not $partial) {
        return [pscustomobject]@{ Id = $id; Level = 'Verified'; Label = 'Verified'; Tip = "Verified. Documented ($($good.Count) source(s)). $where $meaning"; Sources = $good; TestedBuilds = $tested }
    }
    $part = $(if ($partial) { ' The documentation covers only part of what it changes.' } else { '' })
    return [pscustomobject]@{ Id = $id; Level = 'BestEffort'; Label = 'Best effort'; Tip = "Best effort. Documented ($($good.Count) source(s)).$part $where $meaning"; Sources = $good; TestedBuilds = $tested }
}

function Get-IgwtConfidenceMap {
    <# .SYNOPSIS Confidence badges of the whole catalog, by item id (one journal read). Read-only. #>
    [CmdletBinding()]
    param([object[]]$Catalog, $Context)
    if (-not $Catalog) { $Catalog = @(Get-IgwtCatalog) }
    if (-not $Context) { $Context = Get-IgwtConfidenceContext }
    $map = @{}
    foreach ($t in $Catalog) { $map[[string]$t.id] = Get-IgwtConfidence -Tweak $t -Context $Context }
    return $map
}
