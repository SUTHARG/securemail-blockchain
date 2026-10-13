#!/usr/bin/env bash
set -euo pipefail

# Determine script directory
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR="$(pwd)/lab/ca"
fi
OUT_DIR="${SCRIPT_DIR}/out"
CA_DIR="${SCRIPT_DIR}/demoCA"
CONF="${SCRIPT_DIR}/openssl.cnf"

echo "[*] Initializing Lab CA directory structure..."
rm -rf "${OUT_DIR}" "${CA_DIR}"
mkdir -p "${OUT_DIR}" "${CA_DIR}/newcerts"

touch "${CA_DIR}/index.txt"
echo "01" > "${CA_DIR}/serial"

# 1. Generate Primary Root CA
echo "[*] Generating Primary Root CA..."
openssl req -x509 -new -nodes -sha256 -days 3650 \
  -keyout "${CA_DIR}/ca.key" \
  -out "${CA_DIR}/ca.crt" \
  -subj "/C=US/O=SecureMailScope Lab/CN=SecureMailScope Root CA" \
  -config "${CONF}" -extensions v3_ca

cp "${CA_DIR}/ca.crt" "${OUT_DIR}/ca.crt"
cp "${CA_DIR}/ca.crt" "${OUT_DIR}/client_trust.crt"

# 2. Profile: valid-2048-sha256
echo "[*] Issuing profile: valid-2048-sha256..."
openssl req -new -nodes -newkey rsa:2048 -sha256 \
  -keyout "${OUT_DIR}/valid-2048-sha256.key" \
  -out "${OUT_DIR}/valid-2048-sha256.csr" \
  -subj "/CN=172.28.0.10/O=SecureMailScope Lab" \
  -config "${CONF}"

openssl ca -batch -config "${CONF}" -extensions v3_server -days 365 \
  -in "${OUT_DIR}/valid-2048-sha256.csr" \
  -out "${OUT_DIR}/valid-2048-sha256.crt"

# 3. Profile: expired (using openssl ca with past startdate and enddate)
echo "[*] Issuing profile: expired (validity 2020-01-01 to 2021-01-01)..."
openssl req -new -nodes -newkey rsa:2048 -sha256 \
  -keyout "${OUT_DIR}/expired.key" \
  -out "${OUT_DIR}/expired.csr" \
  -subj "/CN=172.28.0.10/O=Expired Lab" \
  -config "${CONF}"

openssl ca -batch -config "${CONF}" -extensions v3_server \
  -startdate 200101000000Z -enddate 210101000000Z \
  -in "${OUT_DIR}/expired.csr" \
  -out "${OUT_DIR}/expired.crt"

# 4. Profile: rsa1024 (weak key length)
echo "[*] Issuing profile: rsa1024..."
openssl req -new -nodes -newkey rsa:1024 -sha256 \
  -keyout "${OUT_DIR}/rsa1024.key" \
  -out "${OUT_DIR}/rsa1024.csr" \
  -subj "/CN=172.28.0.10/O=RSA1024 Lab" \
  -config "${CONF}"

openssl ca -batch -config "${CONF}" -extensions v3_server -days 365 \
  -in "${OUT_DIR}/rsa1024.csr" \
  -out "${OUT_DIR}/rsa1024.crt"

# 5. Profile: sha1 (weak signature algorithm)
echo "[*] Issuing profile: sha1..."
openssl req -new -nodes -newkey rsa:2048 -sha1 \
  -keyout "${OUT_DIR}/sha1.key" \
  -out "${OUT_DIR}/sha1.csr" \
  -subj "/CN=172.28.0.10/O=SHA1 Lab" \
  -config "${CONF}"

openssl ca -batch -config "${CONF}" -extensions v3_server -md sha1 -days 365 \
  -in "${OUT_DIR}/sha1.csr" \
  -out "${OUT_DIR}/sha1.crt" || {
    echo "[!] Fallback for strict OpenSSL 3 default provider on SHA-1..."
    openssl ca -batch -config "${CONF}" -extensions v3_server -md sha1 -days 365 \
      -provider default -provider legacy \
      -in "${OUT_DIR}/sha1.csr" \
      -out "${OUT_DIR}/sha1.crt"
}

# 6. Profile: self-signed (leaf certificate signed by its own private key)
echo "[*] Issuing profile: self-signed..."
openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 365 \
  -keyout "${OUT_DIR}/self-signed.key" \
  -out "${OUT_DIR}/self-signed.crt" \
  -subj "/CN=172.28.0.10/O=Self-Signed Server" \
  -config "${CONF}" -extensions v3_server

# 7. Profile: untrusted-ca (signed by a secondary Rogue CA not in client_trust.crt)
echo "[*] Generating Secondary Rogue CA and issuing untrusted-ca..."
mkdir -p "${SCRIPT_DIR}/rogueCA/newcerts"
touch "${SCRIPT_DIR}/rogueCA/index.txt"
echo "01" > "${SCRIPT_DIR}/rogueCA/serial"

openssl req -x509 -new -nodes -sha256 -days 3650 \
  -keyout "${SCRIPT_DIR}/rogueCA/ca.key" \
  -out "${SCRIPT_DIR}/rogueCA/ca.crt" \
  -subj "/C=US/O=Rogue Untrusted Organization/CN=Rogue Root CA" \
  -config "${CONF}" -extensions v3_ca

openssl req -new -nodes -newkey rsa:2048 -sha256 \
  -keyout "${OUT_DIR}/untrusted-ca.key" \
  -out "${OUT_DIR}/untrusted-ca.csr" \
  -subj "/CN=172.28.0.10/O=Untrusted CA Server" \
  -config "${CONF}"

openssl x509 -req -days 365 \
  -in "${OUT_DIR}/untrusted-ca.csr" \
  -CA "${SCRIPT_DIR}/rogueCA/ca.crt" \
  -CAkey "${SCRIPT_DIR}/rogueCA/ca.key" \
  -CAcreateserial \
  -extfile "${CONF}" -extensions v3_server \
  -out "${OUT_DIR}/untrusted-ca.crt"

# Clean up temporary CSRs and internal CA build dirs
rm -f "${OUT_DIR}"/*.csr
rm -rf "${SCRIPT_DIR}/rogueCA"

echo "[+] Lab certificates generated successfully in: ${OUT_DIR}"
ls -la "${OUT_DIR}"
