# One invocation for existing AWS/OPNsense LAB evidence. No resource mutations.
[CmdletBinding()]
param(
    [string]$AwsScopePath,
    [string]$CaBundlePath,
    [string]$ApiKeyFile,
    [string]$ApiAccount = 'opnsense_auditor'
)
$ErrorActionPreference = 'Stop'
$repoKisa = Split-Path -Parent $PSScriptRoot
$pythonKisa = Join-Path $repoKisa '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonKisa)) { throw 'EXISTING_PROJECT_PYTHON_REQUIRED' }
if (-not $CaBundlePath) { $CaBundlePath = Join-Path $env:USERPROFILE 'Downloads\SJ-Lab-CA_crt.pem' }
if (-not $ApiKeyFile) {
    $keyDirKisa = Join-Path $repoKisa 'key'
    if (Test-Path -LiteralPath $keyDirKisa) {
        $keysKisa = @(Get-ChildItem -LiteralPath $keyDirKisa -File -Filter 'OPNsense*.txt')
        if ($keysKisa.Count -eq 1) { $ApiKeyFile = $keysKisa[0].FullName }
    }
}
if (-not $AwsScopePath) {
    $exportsKisa = Join-Path $repoKisa 'reports\phase2-aws-audit-lab'
    if (Test-Path -LiteralPath $exportsKisa) {
        foreach ($candidateKisa in @(Get-ChildItem -LiteralPath $exportsKisa -Filter scope.json -File -Recurse | Sort-Object LastWriteTimeUtc -Descending)) {
            $scopeKisa = Get-Content -LiteralPath $candidateKisa.FullName -Raw | ConvertFrom-Json
            if ($scopeKisa.schema_version -eq 2 -and @($scopeKisa.policy.internal_subnet_ids).Count -gt 0) {
                $AwsScopePath = $candidateKisa.FullName
                break
            }
        }
    }
}
$stampKisa = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$outKisa = Join-Path $repoKisa ("logs\kisa-remaining-" + $stampKisa)
if (Test-Path -LiteralPath $outKisa) { throw 'NEW_OUTPUT_DIRECTORY_REQUIRED' }
New-Item -ItemType Directory -Path $outKisa | Out-Null
$failedKisa = $false
Push-Location -LiteralPath $repoKisa
try {
    if ($AwsScopePath) {
        & $pythonKisa -m scripts.collect_kisa_aws_live --scope-json $AwsScopePath --output-dir (Join-Path $outKisa 'aws') *> (Join-Path $outKisa 'aws-execution.log')
        if ($LASTEXITCODE -ne 0) { $failedKisa = $true; Write-Output 'AWS_COLLECTION_ERROR_SEE_PRIVATE_LOG' }
        else { Write-Output 'AWS_LIVE_EVIDENCE_SAVED_NO_AWS_CHANGES' }
    }
    else { $failedKisa = $true; Write-Output 'EXPLICIT_EXISTING_PRIVATE_AWS_LAB_SCOPE_MISSING' }
    if (Test-Path -LiteralPath $CaBundlePath) {
        $opnArgsKisa = @('-m','scripts.collect_kisa_opnsense_live','--ca-bundle',$CaBundlePath,'--output-dir',(Join-Path $outKisa 'opnsense'))
        if ($ApiKeyFile) { $opnArgsKisa += @('--api-credentials-file',$ApiKeyFile,'--api-account',$ApiAccount) }
        & $pythonKisa @opnArgsKisa *> (Join-Path $outKisa 'opnsense-execution.log')
        if ($LASTEXITCODE -ne 0) { $failedKisa = $true; Write-Output 'OPNSENSE_COLLECTION_ERROR_SEE_PRIVATE_LOG' }
        else { Write-Output 'OPNSENSE_LIVE_PARTIAL_EVIDENCE_SAVED_FULL_ITEM_VERDICT_MAY_NEED_REVIEW' }
    }
    else { $failedKisa = $true; Write-Output 'EXISTING_TRUSTED_OPNSENSE_CA_REQUIRED' }
}
finally { Pop-Location }
Write-Output ('Private evidence: ' + $outKisa)
if ($failedKisa) { exit 1 }
