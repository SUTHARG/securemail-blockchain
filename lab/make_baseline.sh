#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[*] Generating baseline capture and training advisory Isolation Forest model..."
python "${REPO_ROOT}/lab/make_baseline.py"
echo "[+] Baseline generation complete."
