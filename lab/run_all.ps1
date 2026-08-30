# PowerShell helper to run the complete scenario matrix on Windows
$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceDir = Split-Path -Parent $ScriptDir
$DataDir = Join-Path $WorkspaceDir "data"
$PcapsDir = Join-Path $DataDir "pcaps"
$LabelsFile = Join-Path $DataDir "labels.csv"

if (-not (Test-Path $PcapsDir)) {
    New-Item -ItemType Directory -Path $PcapsDir -Force | Out-Null
}

if (-not (Test-Path $LabelsFile)) {
    "scenario_id,mode,encryption,integrity,dh_group,pfs,ike_version,ip_version,traffic_type,pcap_path" | Out-File -FilePath $LabelsFile -Encoding utf8
}

$Scenarios = @(
    "S01:S01_tunnel_aes256gcm_dh14_pfson_v4:tunnel:AES-256-GCM:AEAD:14:true:IKEv2:IPv4:web",
    "S02:S02_transport_aes128cbc_sha256_dh2_pfsoff_v4:transport:AES-128-CBC:HMAC-SHA256:2:false:IKEv2:IPv4:email",
    "S03:S03_tunnel_aes128gcm_dh19_pfson_v4:tunnel:AES-128-GCM:AEAD:19:true:IKEv2:IPv4:voip",
    "S04:S04_tunnel_aes256cbc_sha512_dh14_pfson_v4:tunnel:AES-256-CBC:HMAC-SHA512:14:true:IKEv2:IPv4:video",
    "S05:S05_transport_aes256gcm_dh19_pfson_v4:transport:AES-256-GCM:AEAD:19:true:IKEv2:IPv4:chat",
    "S06:S06_tunnel_3des_sha1_dh2_pfsoff_v4:tunnel:3DES-CBC:HMAC-SHA1:2:false:IKEv2:IPv4:icmp",
    "S07:S07_tunnel_aes128cbc_md5_dh1_pfsoff_v4:tunnel:AES-128-CBC:HMAC-MD5:1:false:IKEv1:IPv4:web",
    "S08:S08_tunnel_aes256gcm_dh20_pfson_v4:tunnel:AES-256-GCM:AEAD:20:true:IKEv2:IPv4:video",
    "S09:S09_transport_aes128gcm_dh14_pfsoff_v4:transport:AES-128-GCM:AEAD:14:false:IKEv2:IPv4:email",
    "S10:S10_tunnel_aes256cbc_sha256_dh5_pfsoff_v4:tunnel:AES-256-CBC:HMAC-SHA256:5:false:IKEv2:IPv4:voip",
    "S11:S11_tunnel_aes256gcm_dh14_pfson_v6:tunnel:AES-256-GCM:AEAD:14:true:IKEv2:IPv6:chat",
    "S12:S12_transport_aes256gcm_dh19_pfson_v6:transport:AES-256-GCM:AEAD:19:true:IKEv2:IPv6:icmp",
    "S13:S13_tunnel_ikev1_aes256cbc_sha1_dh14_pfson_v4:tunnel:AES-256-CBC:HMAC-SHA1:14:true:IKEv1:IPv4:web",
    "S14:S14_tunnel_chacha20poly1305_curve25519_pfson_v4:tunnel:CHACHA20-POLY1305:AEAD:31:true:IKEv2:IPv4:voip"
)

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "[+] Starting Automated IPsec Lab Run across $($Scenarios.Count) Scenarios" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

foreach ($Entry in $Scenarios) {
    $Parts = $Entry.Split(":")
    $S_Id = $Parts[0]
    $S_Conf = $Parts[1]
    $S_Mode = $Parts[2]
    $S_Enc = $Parts[3]
    $S_Int = $Parts[4]
    $S_DH = $Parts[5]
    $S_PFS = $Parts[6]
    $S_IKE = $Parts[7]
    $S_IP = $Parts[8]
    $S_Traffic = $Parts[9]

    $PfsTag = if ($S_PFS -eq "true") { "pfson" } else { "pfsoff" }
    $EncTag = $S_Enc.ToLower().Replace("-", "").Replace("_", "")
    $PcapName = "${S_Id}_${S_Mode}_${EncTag}_dh${S_DH}_${PfsTag}_$($S_IP.ToLower())_${S_Traffic}.pcap"
    $RelPcapPath = "data/pcaps/$PcapName"

    Write-Host "`n------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "[*] Scenario: $S_Id | Mode: $S_Mode | Enc: $S_Enc | DH: $S_DH | Traffic: $S_Traffic" -ForegroundColor Yellow
    Write-Host "[*] PCAP Output: $RelPcapPath" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------" -ForegroundColor Yellow

    # Start tcpdump in background on node-a
    docker exec -d node-a tcpdump -i any -s 0 -w "/workspace/$RelPcapPath" "(udp port 500 or udp port 4500 or proto 50 or proto 51 or icmp or icmp6 or tcp or udp)"
    Start-Sleep -Seconds 1

    # Run scenario
    & "$ScriptDir\run_scenario.ps1" -Scenario $S_Conf
    if ($LASTEXITCODE -eq 0) {
        $Passed++
        $TargetIp = if ($S_IP -eq "IPv6") { "fd00:abcd:1234::20" } else { "172.28.0.20" }
        Write-Host "[+] Injecting $S_Traffic traffic..." -ForegroundColor Green

        switch ($S_Traffic) {
            "web"   { docker exec node-a /workspace/lab/traffic/gen_web.sh $TargetIp 12 8000 }
            "email" { docker exec node-a python3 /workspace/lab/traffic/gen_email.py $TargetIp 12 2525 }
            "icmp"  { docker exec node-a /workspace/lab/traffic/gen_icmp.sh $TargetIp 12 }
            "voip"  { docker exec node-a python3 /workspace/lab/traffic/gen_voip.py $TargetIp 12 5004 }
            "video" { docker exec node-a python3 /workspace/lab/traffic/gen_video.py $TargetIp 12 5006 }
            "chat"  { docker exec node-a python3 /workspace/lab/traffic/gen_chat.py $TargetIp 12 5222 }
        }
    } else {
        $Failed++
        Write-Warning "Scenario $S_Id failed negotiation."
    }

    # Stop tcpdump
    docker exec node-a pkill -2 tcpdump 2>$null
    docker exec node-a pkill -f tcpdump 2>$null
    Start-Sleep -Seconds 1

    # Terminate tunnel (gracefully ignore if not present)
    try {
        & docker exec node-a sh -c "swanctl --terminate --ike vpn-scenario 2>/dev/null || true" 2>&1 | Out-Null
        & docker exec node-b sh -c "swanctl --terminate --ike vpn-scenario 2>/dev/null || true" 2>&1 | Out-Null
    } catch { }

    # Add label
    $Existing = Get-Content $LabelsFile | Select-String "^$S_Id,"
    if (-not $Existing) {
        "$S_Id,$S_Mode,$S_Enc,$S_Int,$S_DH,$S_PFS,$S_IKE,$S_IP,$S_Traffic,$RelPcapPath" | Out-File -FilePath $LabelsFile -Append -Encoding utf8
    }
}

Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "[*] Matrix Complete! Summary: $Passed Passed / $Failed Failed / $($Scenarios.Count) Total" -ForegroundColor Cyan
Write-Host "[*] PCAPs in: $PcapsDir" -ForegroundColor Cyan
Write-Host "[*] Labels CSV: $LabelsFile" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
