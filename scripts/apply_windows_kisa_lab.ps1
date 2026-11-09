# Requires PowerShell 5.1+, isolated Windows Server 2022 standalone VM only.
# -Apply mutates ONLY the current VM's local lockout policy after explicit guards.
# Read-only mode (without -Apply) performs a local policy export and records actual values.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpectedComputerName,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [switch]$Apply,
    [switch]$AcknowledgeIsolatedLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
if ($env:COMPUTERNAME -ine $ExpectedComputerName -or $computer.Name -ine $ExpectedComputerName) {
    throw 'KISA_LAB_COMPUTER_NAME_MISMATCH'
}
if ($computer.PartOfDomain -or [int]$computer.DomainRole -ne 2) {
    throw 'KISA_LAB_STANDALONE_SERVER_REQUIRED'
}
if ([int]$operatingSystem.ProductType -ne 3) {
    throw 'KISA_LAB_WINDOWS_SERVER_REQUIRED'
}
if ($Apply) {
    if (-not $AcknowledgeIsolatedLab) {
        throw 'KISA_LAB_EXPLICIT_ACKNOWLEDGEMENT_REQUIRED'
    }
    if ($computer.Model -notmatch '(?i)virtual|vmware|kvm|hyper-v|virtualbox|qemu') {
        throw 'KISA_LAB_VIRTUAL_MACHINE_REQUIRED'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'KISA_LAB_ELEVATED_ADMIN_REQUIRED'
    }
}
if (Test-Path -LiteralPath $OutputPath) {
    throw 'KISA_LAB_OUTPUT_ALREADY_EXISTS'
}

function Read-LockoutPolicy {
    $export = Join-Path $env:TEMP ("kisa-local-lockout-" + [Guid]::NewGuid().ToString("N") + ".inf")
    try {
        & secedit.exe /export /cfg $export /areas SECURITYPOLICY 1>$null 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $export)) {
            throw 'KISA_LAB_SECEDIT_EXPORT_FAILED'
        }
        $data = @{}
        foreach ($line in (Get-Content -LiteralPath $export -Encoding Unicode)) {
            if ($line -match '^\s*(LockoutBadCount|LockoutDuration|ResetLockoutCount)\s*=\s*([0-9]+)\s*$') {
                $data[$Matches[1]] = [int]$Matches[2]
            }
        }
        foreach ($name in @('LockoutBadCount','LockoutDuration','ResetLockoutCount')) {
            if (-not $data.ContainsKey($name)) {
                throw 'KISA_LAB_LOCKOUT_POLICY_INCOMPLETE'
            }
        }
        return @{
            lockout_threshold = $data['LockoutBadCount']
            lockout_duration = $data['LockoutDuration']
            reset_minutes = $data['ResetLockoutCount']
        }
    }
    finally {
        if (Test-Path -LiteralPath $export) {
            Remove-Item -LiteralPath $export -Force -ErrorAction SilentlyContinue
        }
    }
}

$before = Read-LockoutPolicy
if ($Apply) {
    # Explicit local policy update only, no domain/GPO or remote targets.
    & net.exe accounts /lockoutthreshold:5 /lockoutduration:60 /lockoutwindow:60 1>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'KISA_LAB_LOCKOUT_SETTING_FAILED_INSPECT_VM_BEFORE_RETRY'
    }
}
$after = Read-LockoutPolicy
$thresholdOK = $after.lockout_threshold -ge 1 -and $after.lockout_threshold -le 5
$durationOK = $after.lockout_duration -ge 60 -and $after.reset_minutes -ge 60

$record = [ordered]@{
    mode = 'LAB'
    schema_version = 1
    profile = 'KISA-CIIP-2025-12-24-SELECTED-0.1'
    collected_at = [DateTimeOffset]::UtcNow.ToString('o')
    source = 'current_standalone_windows_vm_secedit_export'
    source_kind = 'local_powershell_policy_export'
    apply_requested = [bool]$Apply
    observed_guideline_status = [ordered]@{
        'W-04' = $(if ($thresholdOK) { 'PASS' } else { 'FAIL' })
        'W-08' = $(if ($durationOK) { 'PASS' } else { 'FAIL' })
    }
    results = @(
        [ordered]@{
            check_id = 'WIN-LAB-004'
            status = 'NEEDS_REVIEW'
            assessment_basis = 'current_standalone_vm_secedit_export'
            before_values = $before
            after_values = $after
        }
    )
    limitations = @(
        'local_policy_only_not_domain_GPO',
        'only_W04_W08_not_entire_KISA_guide',
        'actual_operational_access_and_account_lockout_not_tested',
        'VM_output_is_local_evidence_do_not_commit'
    )
}
$json = $record | ConvertTo-Json -Depth 8
$full = [IO.Path]::GetFullPath($OutputPath)
$parent = [IO.Path]::GetDirectoryName($full)
if (-not [IO.Directory]::Exists($parent)) {
    throw 'KISA_LAB_OUTPUT_DIRECTORY_NOT_FOUND'
}
$bytes = New-Object System.Text.UTF8Encoding($false)
$stream = New-Object System.IO.FileStream($full, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try {
    $writer = New-Object System.IO.StreamWriter($stream, $bytes)
    try { $writer.Write($json) ; $writer.Flush() }
    finally { $writer.Dispose() }
}
finally { $stream.Dispose() }

Write-Output ('KISA W-04 local policy: ' + $record.observed_guideline_status['W-04'])
Write-Output ('KISA W-08 local policy: ' + $record.observed_guideline_status['W-08'])
Write-Output ('Evidence saved to ' + $full)
