# Run manually INSIDE an approved Windows Server lab VM. Never changes policy.
# Normalized output only: no user names, full SIDs, raw policy/audit text or keys.
[CmdletBinding()]
param(
    [switch]$Execute,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$')]
    [string]$AssetId = 'WIN-LAB-SERVER',
    [string]$OutputPath,
    [ValidateSet('Unknown', 'Required', 'NotRequired')]
    [string]$SpoolerRequirement = 'Unknown',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$')]
    [string]$RoleApproval = 'UNCONFIRMED'
)
$ErrorActionPreference = 'Stop'
if (-not $Execute) {
    Write-Output 'PREPARATION_ONLY: run inside an approved Server VM with -Execute -OutputPath <new-json>'
    return
}
function FailureSection($Failure) {
    $code = 'query_failed'
    if ($Failure.Exception -is [System.UnauthorizedAccessException] -or
        $Failure.CategoryInfo.Category -eq 'PermissionDenied') { $code = 'permission_denied' }
    if ($Failure.Exception -is [System.Management.Automation.CommandNotFoundException]) { $code = 'command_unavailable' }
    $exception = $Failure.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.FormatException]) { $code = 'parse_failed' }
        if ($exception -is [System.ComponentModel.Win32Exception] -and $exception.NativeErrorCode -eq 5) { $code = 'permission_denied' }
        $exception = $exception.InnerException
    }
    return @{ state = 'ERROR'; error_code = $code; values = @{} }
}
function Collected($Values) { return @{ state = 'COLLECTED'; values = $Values } }
function ExactBoolean($Value) {
    if ($null -eq $Value) { return $null }
    # NotConfigured is not True; do not cast enumeration values to Boolean.
    if ($Value.ToString() -eq 'True') { return $true }
    if ($Value.ToString() -eq 'False') { return $false }
    return $null
}
function ConvertFrom-WindowsSecurityPolicy([string[]]$Lines) {
    $numbers = @{}
    $inSystemAccess = $false
    foreach ($line in $Lines) {
        $clean = $line.TrimStart([char]0xFEFF)
        $header = [regex]::Match($clean, '^\s*\[\s*([^\]]+?)\s*\]\s*(?:;.*)?$')
        if ($header.Success) { $inSystemAccess = $header.Groups[1].Value -eq 'System Access'; continue }
        if (-not $inSystemAccess) { continue }
        $field = [regex]::Match($clean, '^\s*(MinimumPasswordLength|PasswordComplexity|LockoutBadCount|LockoutDuration|ResetLockoutCount)\s*=\s*(-?\d+)\s*(?:;.*)?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($field.Success) {
            $key = $field.Groups[1].Value
            if ($numbers.ContainsKey($key)) { throw [FormatException]::new('duplicate_policy_field') }
            $numbers[$key] = [int]$field.Groups[2].Value
        } elseif ($clean -match '^\s*(MinimumPasswordLength|PasswordComplexity|LockoutBadCount|LockoutDuration|ResetLockoutCount)\s*=') {
            throw [FormatException]::new('invalid_policy_field')
        }
    }
    if ($numbers.Count -eq 0) { throw [FormatException]::new('no_policy_values_parsed') }
    $values = @{ merged_policy = $true }
    $mapping = @{ MinimumPasswordLength = 'minimum_length'; LockoutBadCount = 'lockout_threshold'; LockoutDuration = 'lockout_duration'; ResetLockoutCount = 'reset_minutes' }
    foreach ($key in $mapping.Keys) {
        if ($numbers.ContainsKey($key) -and $numbers[$key] -ge 0) { $values[$mapping[$key]] = $numbers[$key] }
    }
    if ($numbers.ContainsKey('PasswordComplexity')) {
        if ($numbers.PasswordComplexity -notin @(0, 1)) { throw [FormatException]::new('invalid_complexity') }
        $values.complexity = $numbers.PasswordComplexity -eq 1
    }
    return $values
}
try {
    if (-not $OutputPath -or $AssetId -match '(?i)secret|token|authorization|password|private.?key|api.?key' -or
        $RoleApproval -match '(?i)secret|token|authorization|password|private.?key|api.?key') {
        throw 'invalid_arguments'
    }
    if (-not [Environment]::Is64BitProcess) { throw 'requires_64bit_powershell' }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$os.ProductType -notin @(2, 3)) { throw 'not_windows_server' }
    $release = $null
    if ($os.Caption -match 'Windows Server (2019|2022|2025)\b') { $release = $Matches[1] }
    if ($null -eq $release) { throw 'candidate_version_not_identified' }
    $role = [int]$computer.DomainRole
    $sections = @{}
    if ($role -in @(4, 5)) {
        $sections.guest = @{ state = 'NOT_APPLICABLE'; values = @{} }
    } else {
        try {
            $guest = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' })
            $enabled = $null
            if ($guest.Count -eq 1) { $enabled = ExactBoolean $guest[0].Enabled }
            $sections.guest = Collected @{ matching_accounts = $guest.Count; enabled = $enabled }
        } catch { $sections.guest = FailureSection $_ }
    }
    # Export ONLY SECURITYPOLICY, parse a numeric allowlist and remove temporary
    # files. /export does not apply policy; /configure and /import are never used.
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('windows-audit-' + [guid]::NewGuid().ToString('N'))
    $configPath = Join-Path $temporary 'policy.inf'
    $logPath = Join-Path $temporary 'export.log'
    try {
        [void][IO.Directory]::CreateDirectory($temporary)
        $null = & "$env:SystemRoot\System32\secedit.exe" /export /mergedpolicy /cfg $configPath /areas SECURITYPOLICY /log $logPath /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'export_failed' }
        $values = ConvertFrom-WindowsSecurityPolicy ([IO.File]::ReadAllLines($configPath))
        $sections.security_policy = Collected $values
    } catch { $sections.security_policy = FailureSection $_ }
    finally {
        # Only these exact files and the newly-created empty directory; no recursive deletion.
        foreach ($ownedPath in @($configPath, $logPath)) {
            if ([IO.File]::Exists($ownedPath)) { [IO.File]::Delete($ownedPath) }
        }
        if ([IO.Directory]::Exists($temporary)) { [IO.Directory]::Delete($temporary, $false) }
    }
    try {
        # A successful empty CIM result alone does not stand in for SCM error
        # 1060. Corroborate absence with a read-only local SCM query. Command
        # failures, permission errors and contradictory results remain ERROR.
        $serviceConfigs = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop)
        $required = $null
        $approval = $null
        if ($SpoolerRequirement -ne 'Unknown' -and $RoleApproval -ne 'UNCONFIRMED') {
            $required = $SpoolerRequirement -eq 'Required'
            $approval = $RoleApproval
        }
        $values = @{ required = $required; role_approval = $approval; running = $null; disabled = $null }
        if ($serviceConfigs.Count -eq 0) {
            $null = & "$env:SystemRoot\System32\sc.exe" query Spooler 2>&1
            $scmExit = $LASTEXITCODE
            if ($scmExit -eq 5) { throw [System.UnauthorizedAccessException]::new('scm_query_denied') }
            if ($scmExit -ne 1060) { throw 'service_absence_not_corroborated' }
            $values.present = $false
            $values.native_error_code = 1060
            # Feature lookup is independent of service lookup. Its failure
            # cannot erase confirmed absence or authorize an N/A verdict.
            try {
                $features = @(Get-WindowsFeature -Name Print-Services,Print-Server -ErrorAction Stop)
                $values.feature_query_state = 'COLLECTED'
                foreach ($item in @(@('Print-Services', 'print_services_installed'), @('Print-Server', 'print_server_installed'))) {
                    $feature = @($features | Where-Object { $_.Name -eq $item[0] })
                    if ($feature.Count -ne 1 -or $feature[0].InstallState.ToString() -notin @('Installed', 'Available', 'Removed')) { throw 'feature_not_identified' }
                    $values[$item[1]] = $feature[0].InstallState.ToString() -eq 'Installed'
                }
            } catch {
                $values.feature_query_state = 'ERROR'
                $values.feature_error_code = (FailureSection $_).error_code
                $values.Remove('print_services_installed')
                $values.Remove('print_server_installed')
            }
        } elseif ($serviceConfigs.Count -eq 1) {
            $service = Get-Service -Name Spooler -ErrorAction Stop
            $serviceConfig = $serviceConfigs[0]
            $values.present = $true
            if ($service.Status.ToString() -in @('Running', 'Stopped')) { $values.running = $service.Status.ToString() -eq 'Running' }
            if ($serviceConfig.StartMode -in @('Auto', 'Manual', 'Disabled')) { $values.disabled = $serviceConfig.StartMode -eq 'Disabled' }
        } else { throw 'ambiguous_service_result' }
        $sections.spooler = Collected $values
    } catch { $sections.spooler = FailureSection $_ }
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $values = @{ policy_store = 'ActiveStore'; service_running = $null }
        $firewallService = Get-Service -Name MpsSvc -ErrorAction Stop
        if ($firewallService.Status.ToString() -in @('Running', 'Stopped')) { $values.service_running = $firewallService.Status.ToString() -eq 'Running' }
        foreach ($name in @('Domain', 'Private', 'Public')) {
            $matchesProfile = @($profiles | Where-Object { $_.Name -eq $name })
            $values[$name.ToLowerInvariant()] = $null
            if ($matchesProfile.Count -eq 1) { $values[$name.ToLowerInvariant()] = ExactBoolean $matchesProfile[0].Enabled }
        }
        $sections.firewall = Collected $values
    } catch { $sections.firewall = FailureSection $_ }
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $sections.smb = Collected @{ smb1_enabled = (ExactBoolean $smb.EnableSMB1Protocol); require_signing = (ExactBoolean $smb.RequireSecuritySignature) }
    } catch { $sections.smb = FailureSection $_ }
    try {
        # Read system subcategory flags by stable GUID, without localized CSV,
        # event records, process command lines, or per-user identities.
        if (-not ('WindowsAuditReadOnly' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WindowsAuditReadOnly {
    [StructLayout(LayoutKind.Sequential)]
    private struct PolicyInfo { public Guid Subcategory; public uint Flags; public Guid Category; }
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subcategories, uint count, out IntPtr policy);
    [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr buffer);
    public static uint Read(Guid subcategory) {
        IntPtr buffer;
        if (!AuditQuerySystemPolicy(new Guid[] { subcategory }, 1, out buffer))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            PolicyInfo info = (PolicyInfo)Marshal.PtrToStructure(buffer, typeof(PolicyInfo));
            if (info.Subcategory != subcategory || info.Flags > 4)
                throw new FormatException("audit_response_invalid");
            return info.Flags;
        } finally { AuditFree(buffer); }
    }
}
'@
        }
        $guids = @('0cce9215-69ae-11d9-bed3-505054503030', '0cce923f-69ae-11d9-bed3-505054503030',
            '0cce9235-69ae-11d9-bed3-505054503030', '0cce922f-69ae-11d9-bed3-505054503030',
            '0cce922b-69ae-11d9-bed3-505054503030')
        $auditRows = @()
        foreach ($guid in $guids) { $auditRows += @{ guid = $guid; mask = [int][WindowsAuditReadOnly]::Read([guid]$guid) } }
        $sections.audit = Collected @{ parser_verified = $true; method = 'AuditQuerySystemPolicy'; subcategories = $auditRows }
    } catch { $sections.audit = FailureSection $_ }
    $bundle = @{
        schema_version = 1; origin = 'local_server_readonly'; asset_id = $AssetId
        collected_at = [DateTimeOffset]::UtcNow.ToString('o')
        system = @{ server_release = $release; os_version = [string]$os.Version; build_number = [string]$os.BuildNumber; product_type = [int]$os.ProductType; domain_role = $role; part_of_domain = (ExactBoolean $computer.PartOfDomain); is_64bit = [Environment]::Is64BitProcess }
        sections = $sections
    }
    $json = $bundle | ConvertTo-Json -Depth 8
    # CreateNew prevents overwriting existing evidence. No raw collector output printed.
    $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    Write-Output 'COLLECTED: normalized JSON saved; no policy changes performed'
} catch {
    # No exception text, path, raw native output or credentials in stdout/stderr.
    Write-Output 'ERROR: collection_not_completed; check Server/64-bit/permissions/new_output_path locally'
    exit 2
}
