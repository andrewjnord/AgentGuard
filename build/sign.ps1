<#
.SYNOPSIS
  Authenticode-signs files with a PFX certificate (SHA-256, RFC 3161 timestamp).
  The certificate comes from the environment so it never lands on disk in the repo:
    SIGNING_CERT_PFX       base64 of the .pfx
    SIGNING_CERT_PASSWORD  its password
#>
param(
    [Parameter(Mandatory)] [string[]]$Files,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
if (-not $env:SIGNING_CERT_PFX) { throw "SIGNING_CERT_PFX is not set." }

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)." }

$pfx = Join-Path ([IO.Path]::GetTempPath()) ("agentguard-" + [guid]::NewGuid() + ".pfx")
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGNING_CERT_PFX))
    # signtool takes many files per call; batch to stay under the command-line limit.
    $batch = @()
    foreach ($f in $Files) {
        $batch += $f
        if ($batch.Count -ge 50) {
            & $signtool.FullName sign /fd sha256 /tr $TimestampUrl /td sha256 /f $pfx /p $env:SIGNING_CERT_PASSWORD /d "AgentGuard" $batch
            if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
            $batch = @()
        }
    }
    if ($batch.Count -gt 0) {
        & $signtool.FullName sign /fd sha256 /tr $TimestampUrl /td sha256 /f $pfx /p $env:SIGNING_CERT_PASSWORD /d "AgentGuard" $batch
        if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
    }
    & $signtool.FullName verify /pa /q $Files
    if ($LASTEXITCODE -ne 0) { throw "signature verification failed" }
}
finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}
