# PowerShell Environment & Lab Health Verification
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "=== 1. Checking Docker & Container Status ===" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "=== 2. Checking Lab Network & StrongSwan ===" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$runningA = docker ps --format '{{.Names}}' | Select-String "^node-a$"
$runningB = docker ps --format '{{.Names}}' | Select-String "^node-b$"

if ($runningA -and $runningB) {
    Write-Host "[+] Node-A -> Node-B Ping Test (IPv4):" -ForegroundColor Green
    docker exec node-a ping -c 2 172.28.0.20

    Write-Host "`n[+] Node-A strongSwan Version & SAs:" -ForegroundColor Green
    docker exec node-a swanctl --version
    docker exec node-a swanctl --list-sas

    Write-Host "`n[+] Node-B strongSwan Version:" -ForegroundColor Green
    docker exec node-b swanctl --version
} else {
    Write-Host "[!] Containers node-a and node-b are not running." -ForegroundColor Yellow
    Write-Host "    Start them with: docker compose -f lab/docker-compose.yml up -d" -ForegroundColor Yellow
}
Write-Host "`n=== Health Check Complete ===" -ForegroundColor Cyan
