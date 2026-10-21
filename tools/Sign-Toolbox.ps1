<#
.SYNOPSIS
    Optional: Authenticode-sign iG Windows Tuner's PowerShell files with YOUR certificate and write a
    SHA256 manifest of every shipped file.
.DESCRIPTION
    - Signs *.ps1, *.psm1 and *.psd1 with a code-signing certificate from Cert:\CurrentUser\My
      (selected by thumbprint, or the only code-signing certificate present).
    - -CreateSelfSignedCertificate creates "CN=iG Windows Tuner Local Code Signing" in
      Cert:\CurrentUser\My, but only after you confirm. It never adds the certificate to the
      Trusted Root or Trusted Publishers stores; the script prints how to do that yourself if
      you want signatures to show as Valid.
    - Always writes SHA256SUMS.txt (after signing, so the hashes match the signed files).
    - -Verify checks the current files against SHA256SUMS.txt and reports differences.
    .cmd, .json and .xaml files cannot carry Authenticode signatures; the manifest covers them.
.PARAMETER CertificateThumbprint
    Thumbprint of an existing code-signing certificate in Cert:\CurrentUser\My.
.PARAMETER CreateSelfSignedCertificate
    Create a self-signed code-signing certificate (asks for confirmation).
.PARAMETER TimestampServer
    Optional RFC 3161 timestamp URL (signing then needs network access).
.PARAMETER ManifestOnly
    Only (re)write SHA256SUMS.txt.
.PARAMETER Verify
    Verify files against SHA256SUMS.txt.
.EXAMPLE
    .\tools\Sign-Toolbox.ps1 -ManifestOnly
.EXAMPLE
    .\tools\Sign-Toolbox.ps1 -CreateSelfSignedCertificate
.EXAMPLE
    .\tools\Sign-Toolbox.ps1 -Verify
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$CertificateThumbprint,
    [switch]$CreateSelfSignedCertificate,
    [string]$TimestampServer,
    [switch]$ManifestOnly,
    [switch]$Verify
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'SHA256SUMS.txt'

function Get-ShippedFile {
    $include = @('iGWindowsTuner.ps1', 'Start-iGWindowsTuner.cmd', 'CONTRIBUTING.md', 'LICENSE', 'README.md', 'PSScriptAnalyzerSettings.psd1')
    $files = foreach ($n in $include) { $p = Join-Path $root $n; if (Test-Path -LiteralPath $p) { Get-Item -LiteralPath $p } }
    $files = @($files) + @(Get-ChildItem -LiteralPath (Join-Path $root 'src'), (Join-Path $root 'data'), (Join-Path $root 'docs'), (Join-Path $root 'tools'), (Join-Path $root 'tests') -Recurse -File | Where-Object { $_.Extension -ne '.wsb' })   # the .wsb is generated per machine
    return @($files | Sort-Object FullName)
}

function Get-RelativePath([string]$Full) { return $Full.Substring($root.Length + 1).Replace('\', '/') }

if ($Verify) {
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw "No manifest at $manifestPath." }
    $expected = @{}
    foreach ($line in (Get-Content -LiteralPath $manifestPath)) { if ($line -match '^([0-9a-f]{64})\s+(.+)$') { $expected[$Matches[2]] = $Matches[1] } }
    $bad = 0
    foreach ($f in (Get-ShippedFile)) {
        $rel = Get-RelativePath $f.FullName
        $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $expected.ContainsKey($rel)) { Write-Output "NEW      $rel"; $bad++ }
        elseif ($expected[$rel] -ne $h) { Write-Output "CHANGED  $rel"; $bad++ }
        $expected.Remove($rel)
    }
    foreach ($k in $expected.Keys) { Write-Output "MISSING  $k"; $bad++ }
    if ($bad -eq 0) { Write-Output 'All files match SHA256SUMS.txt.'; exit 0 }
    exit 1
}

if (-not $ManifestOnly) {
    $cert = $null
    if ($CreateSelfSignedCertificate) {
        $question = 'Create a self-signed code-signing certificate "CN=iG Windows Tuner Local Code Signing" in Cert:\CurrentUser\My? It is only trusted after you add it to Trusted Publishers yourself.'
        if (-not $PSCmdlet.ShouldContinue($question, 'iG Windows Tuner signing')) { Write-Output 'Cancelled; no certificate created.'; exit 2 }
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=iG Windows Tuner Local Code Signing' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3)
        Write-Output "Created certificate $($cert.Thumbprint) in Cert:\CurrentUser\My."
        Write-Output 'To make the signatures Valid on this PC, export the public certificate and import it into "Trusted Publishers"'
        Write-Output '(and "Trusted Root Certification Authorities" for a self-signed certificate) for the current user. iG Windows Tuner does not do this for you.'
    } elseif ($CertificateThumbprint) {
        $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert | Where-Object { $_.Thumbprint -eq $CertificateThumbprint } | Select-Object -First 1
    } else {
        $all = @(Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert)
        if ($all.Count -eq 1) { $cert = $all[0] }
        elseif ($all.Count -gt 1) { throw 'Several code-signing certificates found; pass -CertificateThumbprint.' }
    }
    if (-not $cert) { throw 'No code-signing certificate found. Pass -CertificateThumbprint, use -CreateSelfSignedCertificate, or run with -ManifestOnly.' }
    $toSign = @(Get-ShippedFile | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' })
    foreach ($f in $toSign) {
        if (-not $PSCmdlet.ShouldProcess($f.FullName, 'Authenticode sign')) { continue }
        $params = @{ FilePath = $f.FullName; Certificate = $cert; HashAlgorithm = 'SHA256' }
        if ($TimestampServer) { $params.TimestampServer = $TimestampServer }
        $sig = Set-AuthenticodeSignature @params
        Write-Output ("{0,-14} {1}" -f $sig.Status, (Get-RelativePath $f.FullName))
    }
}

if ($PSCmdlet.ShouldProcess($manifestPath, 'Write SHA256 manifest')) {
    $lines = foreach ($f in (Get-ShippedFile)) {
        if ($f.FullName -eq $manifestPath) { continue }
        '{0}  {1}' -f (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), (Get-RelativePath $f.FullName)
    }
    [System.IO.File]::WriteAllLines($manifestPath, [string[]]@($lines), (New-Object System.Text.UTF8Encoding($false)))
    Write-Output "Wrote $manifestPath ($(@($lines).Count) files)."
}
