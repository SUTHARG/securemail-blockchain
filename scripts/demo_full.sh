#!/usr/bin/env bash
set -e

# SecureMailScope: Full End-to-End Live Demonstration Script
# Phase 9 / Prompt 9.1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "================================================================================"
echo "          SECUREMAILSCOPE INTERACTIVE FORENSIC DEMONSTRATION                   "
echo "================================================================================"

python scripts/demo_full.py "$@"
