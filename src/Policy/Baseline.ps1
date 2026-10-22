# Baseline.ps1
# Import and compare security baselines and GPO backups (SPEC-v3 3.7): a folder the user
# downloaded, such as a Microsoft Security Compliance Toolkit baseline or a GPMC backup, is read for
# registry.pol (Machine and User), GptTmpl.inf (security template) and audit.csv files, with the GPO
# names from bkupInfo.xml. The comparison shows baseline, Local GPO and effective values side by
# side (Policy Analyzer style) and exports to CSV; selected settings are applied through the policy
# batch engine (denylist, lockout safeguards, backups). Nothing is bundled or downloaded.

function Get-IgwtBaselineGpoName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Folder)
    foreach ($f in @('bkupInfo.xml', 'Backup.xml')) {
        $p = Join-Path $Folder $f
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $x = New-Object System.Xml.XmlDocument; $x.XmlResolver = $null; $x.Load($p)
            $n = $x.SelectSingleNode("//*[local-name()='GPODisplayName' or local-name()='DisplayName']")
            if ($n -and $n.InnerText.Trim()) { return $n.InnerText.Trim() }
        } catch { Write-Verbose "Unreadable ${p}: $($_.Exception.Message)" }
    }
    return (Split-Path -Leaf $Folder)
}

function Import-IgwtPolicyBaseline {
    <#
    .SYNOPSIS
        Reads a baseline or GPO backup folder: every GPO with its Machine and User registry.pol
        entries, GptTmpl.inf sections and audit.csv rows. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Baseline folder '$Path' not found." }
    $gpos = New-Object System.Collections.Generic.List[object]
    $roots = @(Get-ChildItem -LiteralPath $Path -Recurse -Directory -Filter 'DomainSysvol' -ErrorAction SilentlyContinue | ForEach-Object { $_.Parent.FullName })
    # LGPO-style or hand-made folders without DomainSysvol: treat the folder itself as one GPO.
    if (-not $roots.Count) { $roots = @($Path) }
    foreach ($r in $roots) {
        $gpo = [pscustomobject]@{ Name = (Get-IgwtBaselineGpoName -Folder $r); Folder = $r; Machine = @(); User = @(); Security = $null; Audit = @(); Errors = New-Object System.Collections.Generic.List[string] }
        foreach ($pol in @(Get-ChildItem -LiteralPath $r -Recurse -File -Filter 'registry.pol' -ErrorAction SilentlyContinue)) {
            $cls = Split-Path -Leaf (Split-Path -Parent $pol.FullName)
            try {
                $e = @((Read-IgwtRegistryPol -Path $pol.FullName).Entries)
                if ($cls -eq 'Machine') { $gpo.Machine = @($gpo.Machine) + $e } elseif ($cls -eq 'User') { $gpo.User = @($gpo.User) + $e } else { $gpo.Errors.Add("$($pol.FullName): not in a Machine or User folder; skipped.") }
            } catch { $gpo.Errors.Add("$($pol.FullName): $($_.Exception.Message)") }
        }
        $inf = @(Get-ChildItem -LiteralPath $r -Recurse -File -Filter 'GptTmpl.inf' -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($inf) { try { $gpo.Security = Read-IgwtSecurityInfFile -Path $inf.FullName } catch { $gpo.Errors.Add("$($inf.FullName): $($_.Exception.Message)") } }
        $csv = @(Get-ChildItem -LiteralPath $r -Recurse -File -Filter 'audit.csv' -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($csv) { try { $gpo.Audit = @(ConvertFrom-IgwtAuditCsv -Text ([System.IO.File]::ReadAllText($csv.FullName)) | Where-Object { -not $_.Option }) } catch { $gpo.Errors.Add("$($csv.FullName): $($_.Exception.Message)") } }
        if (@($gpo.Machine).Count -or @($gpo.User).Count -or $gpo.Security -or @($gpo.Audit).Count) { $gpos.Add($gpo) }
    }
    if (-not $gpos.Count) { throw "No registry.pol, GptTmpl.inf or audit.csv found under '$Path'." }
    return [pscustomobject]@{ Path = $Path; Gpos = $gpos.ToArray() }
}

function Format-IgwtPolEntryValue {
    [CmdletBinding()]
    [OutputType([string])]
    param($Entry)
    if ($null -eq $Entry) { return '' }
    if ($Entry.Special -eq 'del') { return '<deleted>' }
    return [string](@($Entry.Value) -join ',')
}

function Compare-IgwtPolicyBaseline {
    <#
    .SYNOPSIS
        Compares a baseline with this PC: per setting the baseline value, the Local GPO value,
        the effective value (registry, security policy, audit policy) and a status (Match,
        Differs, NotSet, Blocked for values on the denylist, Unsupported, Unknown when a value
        needs administrator rights to read). Rows carry a Ref used to select them for apply. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Baseline)
    $sec = $null; $secErr = ''; $audit = $null; $auditErr = ''
    if (@($Baseline.Gpos | Where-Object { $_.Security }).Count) { try { $sec = Export-IgwtSecurityPolicy } catch { $secErr = $_.Exception.Message } }
    if (@($Baseline.Gpos | Where-Object { @($_.Audit).Count }).Count) { try { $audit = Get-IgwtAuditPolicy } catch { $auditErr = $_.Exception.Message } }
    $local = @{ Machine = @(Get-IgwtLocalPolicyEntries -Class Machine); User = @(Get-IgwtLocalPolicyEntries -Class User) }
    foreach ($g in $Baseline.Gpos) {
        foreach ($cls in 'Machine', 'User') {
            foreach ($e in @($g.$cls)) {
                if (-not $e.ValueName -or ($e.Special -and $e.Special -ne 'del')) { continue }
                $name = $(if ($e.Special -eq 'del') { $e.ValueName.Substring(6) } else { $e.ValueName })
                $lg = @($local[$cls] | Where-Object { [string]::Equals([string]$_.Key, $e.Key, [System.StringComparison]::OrdinalIgnoreCase) -and ([string]::Equals([string]$_.ValueName, $name, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals([string]$_.ValueName, "**del.$name", [System.StringComparison]::OrdinalIgnoreCase)) }) | Select-Object -First 1
                $eff = Get-IgwtRegistryValue -Path ((Get-IgwtPolicyRoot -Class $cls) + $e.Key) -Name $name
                $base = Format-IgwtPolEntryValue -Entry $e
                $effText = $(if ($eff.Exists) { [string](@($eff.Value) -join ',') } else { '' })
                $status = $(if ($e.Special -eq 'del') { $(if ($eff.Exists) { 'Differs' } else { 'Match' }) } elseif (-not $eff.Exists) { 'NotSet' } elseif ($effText -eq $base) { 'Match' } else { 'Differs' })
                if ($e.Special -ne 'del') {
                    $why = Test-IgwtPolicyOpAllowed -Op ([pscustomobject]@{ Op = 'Set'; Key = $e.Key; ValueName = $name; Type = $e.TypeName; Value = $e.Value })
                    if ($why) { $status = 'Blocked' }
                }
                [pscustomobject]@{ Gpo = $g.Name; Area = "Registry ($cls)"; Setting = "$($e.Key)\$name"; Baseline = $base; LocalGpo = (Format-IgwtPolEntryValue -Entry $lg); Effective = $effText; Status = $status; Ref = "Registry|$cls|$($e.Key)|$name"; Entry = $e; Class = $cls }
            }
        }
        if ($g.Security) {
            foreach ($s in @($g.Security.Keys)) {
                if ($s -in 'Unicode', 'Version') { continue }
                foreach ($k in @($g.Security[$s].Keys)) {
                    $bv = [string]$g.Security[$s][$k]
                    $supported = $s -in 'System Access', 'Privilege Rights', 'Registry Values'
                    $cur = $(if ($sec -and $sec.Contains($s) -and $sec[$s].Contains($k)) { [string]$sec[$s][$k] } else { '' })
                    $status = $(if (-not $supported) { 'Unsupported' } elseif (-not $sec) { 'Unknown' } elseif (-not $cur) { 'NotSet' } else { $same = $(if ($s -eq 'Privilege Rights') { ((@(ConvertTo-IgwtSidList -Value $cur) | Sort-Object) -join ',') -eq ((@(ConvertTo-IgwtSidList -Value $bv) | Sort-Object) -join ',') } else { $cur -eq $bv }); $(if ($same) { 'Match' } else { 'Differs' }) })
                    [pscustomobject]@{ Gpo = $g.Name; Area = "Security ($s)"; Setting = $k; Baseline = $bv; LocalGpo = ''; Effective = $(if ($sec) { $cur } else { $secErr }); Status = $status; Ref = "Security|$s|$k"; Entry = $null; Class = 'Machine' }
                }
            }
        }
        foreach ($a in @($g.Audit)) {
            $cur = $(if ($audit) { @($audit.Subcategories | Where-Object { ([string]$_.Guid).Trim('{}') -eq ([string]$a.Guid).Trim('{}') }) | Select-Object -First 1 } else { $null })
            $status = $(if (-not $audit) { 'Unknown' } elseif (-not $cur) { 'Unsupported' } elseif ($cur.Setting -eq $a.Setting) { 'Match' } else { 'Differs' })
            [pscustomobject]@{ Gpo = $g.Name; Area = 'Audit'; Setting = $a.Subcategory; Baseline = $a.Setting; LocalGpo = ''; Effective = $(if ($cur) { $cur.Setting } elseif ($audit) { '' } else { $auditErr }); Status = $status; Ref = "Audit|$(([string]$a.Guid).Trim('{}'))"; Entry = $null; Class = 'Machine' }
        }
    }
}

function Export-IgwtPolicyComparison {
    <# .SYNOPSIS Writes a baseline comparison to CSV (UTF-8). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory = $true)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Export comparison')) { return }
    $csv = @($Rows | Select-Object Gpo, Area, Setting, Baseline, LocalGpo, Effective, Status | ConvertTo-Csv -NoTypeInformation)
    [System.IO.File]::WriteAllText($Path, (($csv -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-IgwtPolicyBaselinePlan {
    <#
    .SYNOPSIS
        A policy batch plan for selected comparison rows (by Ref, or 'differs' for every row that is
        Differs or NotSet). Blocked, Unsupported and Match rows are never selected. Read-only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Baseline, [Parameter(Mandatory = $true)][string[]]$Select, [object[]]$Comparison)
    if (-not $Comparison) { $Comparison = @(Compare-IgwtPolicyBaseline -Baseline $Baseline) }
    $want = @($Select | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $picked = @($Comparison | Where-Object { ($want -contains 'differs' -and $_.Status -in 'Differs', 'NotSet') -or $want -contains $_.Ref })
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $picked) {
        $row = [ordered]@{ Kind = ''; Name = "$($c.Area): $($c.Setting) = $($c.Baseline)"; Class = $c.Class; Ops = @(); Status = 'Change'; Reason = ''; Note = "From $($c.Gpo)"; Setting = $null }
        if ($c.Status -in 'Blocked', 'Unsupported', 'Match') { $row.Status = $(if ($c.Status -eq 'Match') { 'InPlace' } elseif ($c.Status -eq 'Blocked') { 'Refused' } else { 'Unavailable' }); $row.Reason = $(if ($c.Status -eq 'Blocked') { 'The value turns off a security protection (policy denylist).' } elseif ($c.Status -eq 'Unsupported') { 'iG Windows Tuner does not apply this kind of setting.' } else { '' }) }
        switch -Wildcard ($c.Ref) {
            'Registry|*' {
                $row.Kind = 'registry'
                $e = $c.Entry
                $name = $(if ($e.Special -eq 'del') { $e.ValueName.Substring(6) } else { $e.ValueName })
                $row.Ops = @($(if ($e.Special -eq 'del') { [pscustomobject]@{ Op = 'Delete'; Key = $e.Key; ValueName = $name; Type = ''; Value = $null } } else { [pscustomobject]@{ Op = 'Set'; Key = $e.Key; ValueName = $name; Type = $e.TypeName; Value = $e.Value } }))
                if ($row.Status -eq 'Change' -and $e.TypeName -notin 'String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord' -and $e.Special -ne 'del') { $row.Status = 'Unavailable'; $row.Reason = "Type $($e.TypeName) is not supported." }
            }
            'Security|*' { $parts = $c.Ref.Split('|'); $row.Kind = 'secpol'; $row.Setting = [pscustomobject]@{ key = "$($parts[1])\$($parts[2])"; value = $c.Baseline } }
            'Audit|*' { $row.Kind = 'audit'; $row.Setting = [pscustomobject]@{ guid = $c.Ref.Split('|')[1]; name = $c.Setting; setting = $c.Baseline }; if ($c.Status -eq 'Unknown') { $row.Status = 'Unknown'; $row.Reason = $c.Effective } }
        }
        if ($row.Kind -eq 'secpol' -and $c.Status -eq 'Unknown') { $row.Status = 'Unknown'; $row.Reason = $c.Effective }
        $rows.Add([pscustomobject]$row)
    }
    $refusals = @()
    $secRows = @($rows | Where-Object { $_.Kind -eq 'secpol' -and $_.Status -eq 'Change' })
    if ($secRows.Count) {
        try { $sp = Get-IgwtSecurityChangePlan -Changes @($secRows | ForEach-Object { ConvertFrom-IgwtSecurityChangeText -Text ("{0}={1}" -f $_.Setting.key, $_.Setting.value) }); $refusals += @($sp.Refusals) } catch { $refusals += $_.Exception.Message }
    }
    $m = Get-IgwtManagementState
    if (-not $m.LocalGroupPolicy) { $refusals += 'Windows Home has no Local Group Policy: baselines are report-only on this edition.' }
    $missing = @($want | Where-Object { $_ -ne 'differs' -and -not @($Comparison | Where-Object Ref -EQ $_).Count })
    [pscustomobject]@{ Preset = [pscustomobject]@{ id = "baseline:$(Split-Path -Leaf $Baseline.Path)"; name = "Baseline $(Split-Path -Leaf $Baseline.Path)" }
        Rows = $rows.ToArray(); Refusals = $refusals; Managed = [bool]$m.Managed; Authorities = @($m.Authorities); NotFound = $missing
        Changes = @($rows | Where-Object { $_.Status -eq 'Change' }).Count; Unavailable = @($rows | Where-Object { $_.Status -in 'Unavailable', 'Refused' }).Count }
}
