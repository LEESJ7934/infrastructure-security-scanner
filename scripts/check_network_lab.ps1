# Read-only host readiness. No daemon start, VM changes, install or networking writes.
$ErrorActionPreference = 'Continue'
Write-Output 'Network LAB readiness (read only). UNKNOWN does not mean ready.'
Get-Command docker -ErrorAction SilentlyContinue | Select-Object Name,Source
docker compose version --short
$context = docker context show
if ($LASTEXITCODE -eq 0 -and $context -in @('default','desktop-linux')) {
    $contextInfo = docker context inspect $context | ConvertFrom-Json
    $endpoint = $contextInfo[0].Endpoints.docker.Host
    if ($endpoint -in @('npipe:////./pipe/docker_engine','npipe:////./pipe/dockerDesktopLinuxEngine','unix:///var/run/docker.sock')) {
        docker --context $context info --format 'Engine={{.OSType}} DockerMemoryBytes={{.MemTotal}}'
        if ($LASTEXITCODE -ne 0) { Write-Output 'Docker Linux engine: NOT CONFIRMED. Open existing Docker Desktop manually.' }
        else {
            # Read existing subnet allocations before choosing 10.203.* LAB ranges.
            $networkIds = docker --context $context network ls --format '{{.ID}}'
            foreach ($id in $networkIds) {
                docker --context $context network inspect $id --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'
            }
        }
    } else { Write-Output 'Remote Docker endpoint refused; choose a local Desktop Linux context.' }
} else { Write-Output 'Docker context: UNKNOWN or outside allowed local contexts.' }
& "$env:SystemRoot\System32\wsl.exe" --list --verbose
if ($LASTEXITCODE -ne 0) { Write-Output 'WSL distributions/status: UNKNOWN (query failed); do not reinstall automatically.' }
try {
    Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
        Select-Object @{Name='TotalMemoryGiB';Expression={[math]::Round($_.TotalVisibleMemorySize/1MB,2)}},
                      @{Name='FreeMemoryGiB';Expression={[math]::Round($_.FreePhysicalMemory/1MB,2)}}
} catch { Write-Output 'Host free memory: UNKNOWN. Check Task Manager locally.' }
try {
    Get-VM -ErrorAction Stop | Where-Object { $_.Name -match 'OPNsense|Alpine|TestLinux|Windows|WS2022' } |
        Select-Object Name,State,MemoryAssigned
} catch { Write-Output 'Existing lab VM states: UNKNOWN. Inspect Hyper-V Manager locally; no VM state changes required.' }
try {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias,IPAddress,PrefixLength
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $_.LocalPort -in @(22,23,80,443,179,2601,8080) } | Select-Object LocalAddress,LocalPort
} catch { Write-Output 'Host subnet/port inventory: incomplete. LAB publishes no host ports; subnet overlap still needs review.' }
Write-Output 'Before building: review 10.203.0/24, 10.203.10/24, 10.203.20/24 overlap; recommend >=4 GiB free host RAM.'
