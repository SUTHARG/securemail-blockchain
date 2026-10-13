#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SCENARIO="${1:-S01a}"
ENV_FILE="${SCRIPT_DIR}/scenarios/${SCENARIO}.env"

if [ ! -f "${ENV_FILE}" ]; then
  echo "[-] Error: Scenario config file not found: ${ENV_FILE}"
  exit 1
fi

echo "================================================================================"
echo "          SECUREMAILSCOPE LAB RUNNER: SCENARIO ${SCENARIO}                     "
echo "================================================================================"

mkdir -p "${SCRIPT_DIR}/captures"

# Ensure certificates exist
if [ ! -f "${SCRIPT_DIR}/ca/out/valid-2048-sha256.crt" ]; then
  echo "[*] Generating lab certificates first..."
  bash "${SCRIPT_DIR}/ca/make_ca.sh"
fi

cd "${SCRIPT_DIR}"

export SCENARIO
PCAP_FILE="${SCRIPT_DIR}/captures/${SCENARIO}.pcap"
rm -f "${PCAP_FILE}"

echo "[*] Bringing up mailserver and capture services for ${SCENARIO}..."
docker compose up -d mailserver capture

# Wait for mailserver to be healthy and listening on port 25
echo "[*] Waiting for mailserver to initialize..."
for i in {1..30}; do
  if docker exec lab-mailserver nc -z 127.0.0.1 25 &>/dev/null || docker exec lab-mailserver netstat -tuln 2>/dev/null | grep -q ":25 "; then
    echo "[+] Mailserver listening on port 25."
    break
  fi
  sleep 1
done

# Run client according to scenario parameters
echo "[*] Executing client for scenario ${SCENARIO}..."
case "${SCENARIO}" in
  S01a)
    docker compose run --rm client --scenario S01a --mode starttls --auth no --max-tls 1.2 --server-name 172.28.0.10
    ;;
  S01b)
    docker compose run --rm client --scenario S01b --mode starttls --auth no --max-tls 1.3 --server-name 172.28.0.10
    ;;
  S02)
    docker compose run --rm client --scenario S02 --mode starttls --auth no --max-tls 1.0 --server-name 172.28.0.10
    ;;
  S05)
    docker compose run --rm client --scenario S05 --mode plain --auth yes --server-name 172.28.0.10
    ;;
  S06)
    docker compose run --rm client --scenario S06 --mode plain --auth no --server-name 172.28.0.10
    ;;
  S13)
    docker compose run --rm client --scenario S13 --mode implicit --auth no --max-tls 1.2 --port 465 --server-name 172.28.0.10
    ;;
  *)
    # Default to STARTTLS TLS 1.2
    docker compose run --rm client --scenario "${SCENARIO}" --mode starttls --auth no --max-tls 1.2 --server-name 172.28.0.10
    ;;
esac

# Allow tcpdump buffer flush
sleep 2

echo "[*] Tearing down capture and services..."
docker compose stop capture mailserver
docker compose down

if [ -f "${PCAP_FILE}" ]; then
  FILE_SIZE=$(wc -c < "${PCAP_FILE}" | tr -d ' ')
  echo "[+] Capture written: ${PCAP_FILE} (${FILE_SIZE} bytes)"
else
  echo "[-] Error: PCAP capture file not created!"
  exit 1
fi

echo "================================================================================"
echo "                  TSHARK VERIFICATION FOR ${SCENARIO}                           "
echo "================================================================================"

if command -v tshark &>/dev/null; then
  tshark -r "${PCAP_FILE}" -Y "smtp || tls" -T fields \
    -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info
else
  echo "[*] Using containerized tshark to inspect ${SCENARIO}.pcap..."
  docker run --rm -v "${SCRIPT_DIR}/captures:/captures:ro" \
    alpine:3.20 sh -c "apk add --no-cache tshark >/dev/null 2>&1 && tshark -r /captures/${SCENARIO}.pcap -Y 'smtp || tls' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info" || true
fi

echo "================================================================================"
echo "[SUCCESS] Scenario ${SCENARIO} completed successfully!"
