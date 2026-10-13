#!/usr/bin/env bash
set -euo pipefail

# SecureMailScope Container Determinism Check (Prompt 5.8)
# Runs the engine container twice on every lab capture with --network none
# and compares sha256sum of all generated canonical outputs.

IMAGE_NAME="smscope:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CAPTURES_DIR="${REPO_ROOT}/lab/captures"
ORG_SECRET_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

echo "=== SecureMailScope Container Determinism Check ==="

# 1. Build image if not present
echo "[*] Building engine container image ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
IMAGE_ID=$(docker inspect --format='{{index .Id}}' "${IMAGE_NAME}")
echo "[+] Built ${IMAGE_NAME} (Image ID: ${IMAGE_ID})"

TMP_BASE=$(mktemp -d /tmp/smscope_determinism_XXXXXX)
trap 'rm -rf "${TMP_BASE}"' EXIT

FAILED=0
TOTAL=0

for pcap in "${CAPTURES_DIR}"/*.pcap; do
    [ -f "${pcap}" ] || continue
    SCENARIO=$(basename "${pcap}" .pcap)
    TOTAL=$((TOTAL + 1))
    echo "--- Testing scenario: ${SCENARIO} ---"

    OUT1="${TMP_BASE}/${SCENARIO}_run1"
    OUT2="${TMP_BASE}/${SCENARIO}_run2"
    mkdir -p "${OUT1}" "${OUT2}"
    chmod 777 "${OUT1}" "${OUT2}"

    # Run 1
    docker run --rm --network none \
        -v "${pcap}:/data/input.pcap:ro" \
        -v "${OUT1}:/data/out" \
        "${IMAGE_NAME}" \
        analyze /data/input.pcap \
        --org-secret-hex "${ORG_SECRET_HEX}" \
        --out /data/out \
        --case-id "det-${SCENARIO}" > /dev/null

    # Run 2
    docker run --rm --network none \
        -v "${pcap}:/data/input.pcap:ro" \
        -v "${OUT2}:/data/out" \
        "${IMAGE_NAME}" \
        analyze /data/input.pcap \
        --org-secret-hex "${ORG_SECRET_HEX}" \
        --out /data/out \
        --case-id "det-${SCENARIO}" > /dev/null

    # Compare hashes of all generated files
    (cd "${OUT1}" && sha256sum *.json > "${TMP_BASE}/${SCENARIO}_hash1.txt")
    (cd "${OUT2}" && sha256sum *.json > "${TMP_BASE}/${SCENARIO}_hash2.txt")

    if diff -u "${TMP_BASE}/${SCENARIO}_hash1.txt" "${TMP_BASE}/${SCENARIO}_hash2.txt"; then
        echo "[PASS] ${SCENARIO}: Run 1 and Run 2 produced bit-for-bit identical outputs."
    else
        echo "[FAIL] ${SCENARIO}: Divergence detected between Run 1 and Run 2!"
        FAILED=$((FAILED + 1))
    fi
done

echo "===================================================="
if [ "${FAILED}" -eq 0 ]; then
    echo "SUCCESS: Zero differences detected across all ${TOTAL} scenarios."
    exit 0
else
    echo "FAILURE: ${FAILED}/${TOTAL} scenarios had non-deterministic output differences."
    exit 1
fi
