param (
    [string]$Scenario = "S01a"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

$EnvFile = Join-Path $ScriptDir "scenarios\$Scenario.env"
if (-not (Test-Path $EnvFile)) {
    Write-Error "Scenario config file not found: $EnvFile"
}

Write-Host "================================================================================"
Write-Host "          SECUREMAILSCOPE LAB RUNNER: SCENARIO $Scenario                     "
Write-Host "================================================================================"

$CapturesDir = Join-Path $ScriptDir "captures"
if (-not (Test-Path $CapturesDir)) {
    New-Item -ItemType Directory -Path $CapturesDir | Out-Null
}

$CertFile = Join-Path $ScriptDir "ca\out\valid-2048-sha256.crt"
if (-not (Test-Path $CertFile)) {
    Write-Host "[*] Generating lab certificates via make_ca.sh in WSL..."
    wsl -d Ubuntu -e bash -c "cd /mnt/c/Users/gaura/OneDrive/Desktop/projects/blockchain-project && bash lab/ca/make_ca.sh"
}

Set-Location $ScriptDir

$env:SCENARIO = $Scenario
$PcapFile = Join-Path $CapturesDir "$Scenario.pcap"
if (Test-Path $PcapFile) {
    Remove-Item $PcapFile -Force
}

Write-Host "[*] Bringing up mailserver and capture services for $Scenario..."
docker compose up -d mailserver capture

Write-Host "[*] Waiting for mailserver to initialize..."
Start-Sleep -Seconds 3

Write-Host "[*] Executing client for scenario $Scenario..."
switch ($Scenario) {
    "S01a" {
        docker compose run --rm client --scenario S01a --mode starttls --auth no --max-tls 1.2 --server-name 172.28.0.10
    }
    "S01b" {
        docker compose run --rm client --scenario S01b --mode starttls --auth no --max-tls 1.3 --server-name 172.28.0.10
    }
    "S02" {
        docker compose run --rm client --scenario S02 --mode starttls --auth no --max-tls 1.0 --server-name 172.28.0.10
    }
    "S05" {
        docker compose run --rm client --scenario S05 --mode plain --auth yes --server-name 172.28.0.10
    }
    "S06" {
        docker compose run --rm client --scenario S06 --mode plain --auth no --server-name 172.28.0.10
    }
    "S13" {
        docker compose run --rm client --scenario S13 --mode implicit --auth no --max-tls 1.2 --port 465 --server-name 172.28.0.10
    }
    Default {
        docker compose run --rm client --scenario $Scenario --mode starttls --auth no --max-tls 1.2 --server-name 172.28.0.10
    }
}

Start-Sleep -Seconds 2

Write-Host "[*] Tearing down capture and services..."
docker compose stop capture mailserver
docker compose down

if (Test-Path $PcapFile) {
    $bytes = (Get-Item $PcapFile).Length
    Write-Host "[+] Capture written: $PcapFile ($bytes bytes)"
} else {
    Write-Error "Error: PCAP capture file not created!"
}

Write-Host "================================================================================"
Write-Host "                  TSHARK VERIFICATION FOR $Scenario                           "
Write-Host "================================================================================"

Write-Host "[*] Inspecting $Scenario.pcap with containerized tshark..."
docker run --rm -v "${CapturesDir}:/captures:ro" alpine:3.20 sh -c "apk add --no-cache tshark >/dev/null 2>&1 && tshark -r /captures/$Scenario.pcap -Y 'smtp || tls' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info"

Write-Host "================================================================================"
Write-Host "[SUCCESS] Scenario $Scenario completed successfully!"
