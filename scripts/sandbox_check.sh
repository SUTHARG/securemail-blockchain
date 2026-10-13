#!/usr/bin/env bash
# Runs the sandbox verification script inside a hardened Docker container
set -euo pipefail

IMAGE_NAME="smscope-engine:latest"

echo "Building engine image ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" -f Dockerfile .

echo "Running sandbox verification inside read-only container with zero network..."
docker run --rm \
    --network none \
    --read-only \
    --user 1000:1000 \
    --tmpfs /tmp/out:rw,size=64m \
    --entrypoint python \
    "${IMAGE_NAME}" \
    /app/scripts/sandbox_check.py --out-dir /tmp/out

echo "Sandbox check completed successfully."
