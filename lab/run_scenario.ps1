# PowerShell helper to run a scenario on Windows host
param (
    [string]$Scenario = "S01"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigsDir = Join-Path $ScriptDir "configs"

# Locate config file
$ConfigFile = ""
if (Test-Path $Scenario) {
    $ConfigFile = $Scenario
} elseif (Test-Path (Join-Path $ConfigsDir $Scenario)) {
    $ConfigFile = Join-Path $ConfigsDir $Scenario
} elseif (Test-Path (Join-Path $ConfigsDir "$Scenario.conf")) {
    $ConfigFile = Join-Path $ConfigsDir "$Scenario.conf"
} else {
    $Matches = Get-ChildItem -Path $ConfigsDir -Filter "$Scenario*.conf"
    if ($Matches.Count -gt 0) {
        $ConfigFile = $Matches[0].FullName
    } else {
        Write-Error "Config '$Scenario' not found in $ConfigsDir"
    }
}

$ScenarioName = [System.IO.Path]::GetFileNameWithoutExtension($ConfigFile)
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "[+] Target Scenario: $ScenarioName" -ForegroundColor Cyan
Write-Host "[+] Config Template: $ConfigFile" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# Check containers
$runningA = docker ps --format '{{.Names}}' | Select-String "^node-a$"
$runningB = docker ps --format '{{.Names}}' | Select-String "^node-b$"

if (-not $runningA -or -not $runningB) {
    Write-Error "Containers node-a and node-b must be running. Run: docker compose -f lab/docker-compose.yml up -d"
}

# Read and substitute template for Node-A
$TemplateContent = Get-Content $ConfigFile -Raw
$NodeAConf = $TemplateContent `
    -replace '%LOCAL_IP%', '172.28.0.10' `
    -replace '%REMOTE_IP%', '172.28.0.20' `
    -replace '%LOCAL_IPV6%', 'fd00:abcd:1234::10' `
    -replace '%REMOTE_IPV6%', 'fd00:abcd:1234::20' `
    -replace '%LOCAL_ID%', 'node-a' `
    -replace '%REMOTE_ID%', 'node-b' `
    -replace '%LOCAL_TS%', '172.28.0.10/32' `
    -replace '%REMOTE_TS%', '172.28.0.20/32' `
    -replace '%LOCAL_TS_V6%', 'fd00:abcd:1234::10/128' `
    -replace '%REMOTE_TS_V6%', 'fd00:abcd:1234::20/128'

# Read and substitute template for Node-B
$NodeBConf = $TemplateContent `
    -replace '%LOCAL_IP%', '172.28.0.20' `
    -replace '%REMOTE_IP%', '172.28.0.10' `
    -replace '%LOCAL_IPV6%', 'fd00:abcd:1234::20' `
    -replace '%REMOTE_IPV6%', 'fd00:abcd:1234::10' `
    -replace '%LOCAL_ID%', 'node-b' `
    -replace '%REMOTE_ID%', 'node-a' `
    -replace '%LOCAL_TS%', '172.28.0.20/32' `
    -replace '%REMOTE_TS%', '172.28.0.10/32' `
    -replace '%LOCAL_TS_V6%', 'fd00:abcd:1234::20/128' `
    -replace '%REMOTE_TS_V6%', 'fd00:abcd:1234::10/128'

# Write to temporary files and copy into containers
$TempA = [System.IO.Path]::GetTempFileName()
$TempB = [System.IO.Path]::GetTempFileName()
Set-Content -Path $TempA -Value $NodeAConf
Set-Content -Path $TempB -Value $NodeBConf

docker cp $TempA "node-a:/etc/swanctl/conf.d/active.conf"
docker cp $TempB "node-b:/etc/swanctl/conf.d/active.conf"
Remove-Item $TempA, $TempB

Write-Host "[+] Config deployed to node-a and node-b." -ForegroundColor Green

# Terminate existing SAs (gracefully ignore if no existing SA is present)
try {
    & docker exec node-a sh -c "swanctl --terminate --ike vpn-scenario 2>/dev/null || true" 2>&1 | Out-Null
} catch { }
try {
    & docker exec node-b sh -c "swanctl --terminate --ike vpn-scenario 2>/dev/null || true" 2>&1 | Out-Null
} catch { }
Start-Sleep -Seconds 1

# Reload configs
Write-Host "[+] Reloading strongSwan configuration..." -ForegroundColor Green
docker exec node-b swanctl --load-all 2>&1 | Out-Null
docker exec node-a swanctl --load-all 2>&1 | Out-Null

# Initiate tunnel
Write-Host "[+] Initiating tunnel from node-a -> node-b..." -ForegroundColor Yellow
$InitRes = docker exec node-a swanctl --initiate --child vpn-child 2>&1
Write-Host $InitRes

# Verify
Write-Host "[+] Verifying SA establishment..." -ForegroundColor Green
$Established = $false
for ($i = 0; $i -lt 10; $i++) {
    $Sas = docker exec node-a swanctl --list-sas 2>&1
    if ($Sas -match "ESTABLISHED" -or $Sas -match "INSTALLED") {
        $Established = $true
        break
    }
    Start-Sleep -Seconds 1
}

if ($Established) {
    Write-Host "==================================================================" -ForegroundColor Green
    Write-Host "[*] SUCCESS: Scenario $ScenarioName Negotiated & ESTABLISHED!" -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green
    docker exec node-a swanctl --list-sas
} else {
    Write-Host "==================================================================" -ForegroundColor Red
    Write-Host "[-] FAILED: Scenario $ScenarioName could not establish SA." -ForegroundColor Red
    Write-Host "==================================================================" -ForegroundColor Red
    docker exec node-a swanctl --list-sas
    exit 1
}
