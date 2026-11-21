# Words.ps1
# Plain counts for visible texts: "1 setting", "3 settings" instead of "3 setting(s)" (4.0 section 8, D9).

function Format-IgwtCount {
    <#
    .SYNOPSIS
        A count with its noun in the right number: 1 setting, 2 settings, 1 entry, 2 entries. Pure.
    .PARAMETER Count
        The number (any numeric value; only exactly 1 is singular).
    .PARAMETER Noun
        The singular noun.
    .PARAMETER Plural
        The plural when it is not the noun plus "s" (entries, crashes).
    .PARAMETER Verb
        A plural verb to add in the matching form: are, were, have, or a verb that takes -s (differ, use, match, wait).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowNull()]$Count, [Parameter(Mandatory = $true)][string]$Noun, [string]$Plural, [string]$Verb)
    $n = $(if ($null -eq $Count) { 0 } else { $Count })
    if (-not $Plural) { $Plural = "${Noun}s" }
    $one = $false
    try { $one = ([double]$n -eq 1) } catch { $one = $false }
    $text = '{0} {1}' -f $n, $(if ($one) { $Noun } else { $Plural })
    if ($Verb) {
        $v = $(if (-not $one) { $Verb } else { switch ($Verb) { 'are' { 'is' } 'were' { 'was' } 'have' { 'has' } default { if ($Verb -match '(ch|sh|s|x)$') { "${Verb}es" } else { "${Verb}s" } } } })
        $text = "$text $v"
    }
    return $text
}