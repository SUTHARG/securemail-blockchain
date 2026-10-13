# Decision Record: 020 - Docker Python Baseline and Multi-Version Compatibility

## Context
SecureMailScope requires bitwise deterministic consensus execution across all participating validator nodes. Variations in Python runtime versions, C extensions (such as OpenSSL bindings in `cryptography` and `dpkt`), or container base layers could introduce divergence in cryptographic hashing or rule evaluation.

Additionally, the development host environment uses Python 3.13 (`3.13.5`), while containerized validator nodes execute within minimal containers.

## Decision
1. **Container Engine Base Image:**
   - Standardized on `python:3.11-slim-bookworm@sha256:7f4d22197ae71221f7db19eb0b1f4806a143b879c5dc2ab440056e4c76b1f237`.
   - **Rationale:** Debian 12 (Bookworm) with Python 3.11 represents the current enterprise Long-Term Support baseline with stable GLibc and OpenSSL interfaces. The cryptographic digest is immutable and guarantees byte-for-byte reproducibility across validator nodes.

2. **Host & Virtual Environment Support:**
   - Supported local Python versions: `>= 3.11` (verified on Python 3.11 and Python 3.13).
   - All code avoids version-specific features or deprecated APIs, ensuring identical behaviour across 3.11 and 3.13.

3. **Continuous Integration Matrix:**
   - GitHub Actions CI workflow (`.github/workflows/ci.yml`) executes all unit, integration, and contract tests across both Python 3.11 and Python 3.13 to prevent drift.

## Consequences
- Engine Docker container builds require context from the repository root (`docker build -t smscope-engine:latest .`) to copy `engine`, `ruleset`, and `lab/ca/out/client_trust.crt`.
- Strict `.dockerignore` prevents any environment files (`.env*`), private keys, or build caches from leaking into the engine image.
