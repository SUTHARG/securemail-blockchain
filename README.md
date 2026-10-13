# SecureMailScope

**SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Network Forensic Traffic**

SecureMailScope couples a passive, deterministic network forensic analysis engine with an EVM-anchored multi-validator commit-reveal consensus scheme and an append-only cryptographic host posture ledger.

---

## Architecture Overview

1. **Forensic Analysis Engine (`engine/smscope/`)**:
   - Parses passive email PCAP traffic across SMTP (ports 25, 465, 587), IMAP (ports 143, 993), and POP3 (ports 110, 995).
   - Evaluates a 19-rule security ruleset (core R01–R12 and extended R13–R19) using strictly deterministic integer arithmetic (no floats, wall-clock time, or random seeds in consensus hashes).
   - Generates pseudonymous per-host finding digests and posture scores $[0, 100]$.
   - Packages results into an RFC 8785-canonicalized (JSON Canonicalization Scheme) Merkle tree root with per-host inclusion proofs.

2. **Smart Contracts (`contracts/contracts/`)**:
   - `Roles.sol`: Access control (Admin, Analyst, Validator).
   - `CaseRegistry.sol`: Case lifecycle tracking, pinning of container image digests and ruleset hashes.
   - `ValidationQuorum.sol`: $k$-of-$N$ commit-reveal consensus over engine execution result roots with dispute/expiry handling.
   - `PostureLedger.sol`: Cryptographic, per-host hash-chained posture history verified by Merkle inclusion proofs.
   - `MerkleVerifier.sol`: On-chain inclusion proof verification library.

3. **Validator Service & Consensus (`validator/service.py`, `validator/node.py`)**:
   - Long-running validator service processes that poll the blockchain for cases where they participate in the validator snapshot.
   - Executes engine analysis in network-less sandboxes (`--network none --read-only`), verifies strict engine and ruleset pinning, saves cryptographic salts atomically, and conducts two-phase commit-reveal consensus.
   - Asymmetric sealed envelope delivery (`validator/crypto.py`): Supports Curve25519 sealed box encryption for PCAP and organization secret distribution to validator inboxes (`POST /cases/{id}/distribute`).

4. **Web Presentation & Dashboard (`backend/`)**:
   - REST API and server-rendered HTML dashboard (Jinja2) with zero third-party CDN or external assets.
   - Dedicated views: Case overview, host rankings, prioritized findings, email sessions, TLS cipher distribution charts (pure Python inline SVG), X.509 certificate tables, advisory anomaly detection, and on-chain verification.

5. **Independent Verifier (`verifier/verify.py`)**:
   - Five-step mathematical verification suite independent of validator nodes:
     - Step 1: PCAP SHA-256 == on-chain `pcapHash`.
     - Step 2: Findings & host scores regenerate Merkle root matching `result_root.json`.
     - Step 3: Local Merkle root == on-chain `finalRoot`.
     - Step 4: Posture ledger hash-chain integrity & Merkle inclusion proof.
     - Step 5: Canonical report SHA-256 == on-chain `reportHash`.

---

## Tier Scope & Implementation Truth Table

| Capability | Scope / Milestone | Status | Implementation File Path(s) |
|---|---|---|---|
| **T1: SMTP Protocol Ingestion & Parsing** | Tier 1 (Baseline) | Implemented | `engine/smscope/protocols/smtp.py`, `engine/tests/test_smtp.py` |
| **T1: Core Security Ruleset (R01–R12)** | Tier 1 (Baseline) | Implemented | `engine/smscope/rules/evaluator.py`, `ruleset/ruleset.yaml` |
| **T1: Deterministic Merkle Result Roots** | Tier 1 (Baseline) | Implemented | `engine/smscope/results/merkle.py`, `engine/tests/test_merkle.py` |
| **T1: EVM Commit-Reveal & PostureLedger** | Tier 1 (Baseline) | Implemented | `contracts/contracts/`, `contracts/test/` |
| **T2.1: IMAP Protocol Parsing** | Tier 2 Extension | Implemented | `engine/smscope/protocols/imap.py`, `engine/tests/test_imap.py` |
| **T2.2: POP3 Protocol Parsing** | Tier 2 Extension | Implemented | `engine/smscope/protocols/pop3.py`, `engine/tests/test_pop3.py` |
| **T2.3: Extended Ruleset (R13–R19)** | Tier 2 Extension | Implemented | `engine/smscope/rules/evaluator.py`, `ruleset/ruleset.yaml`, `engine/tests/test_rules.py` |
| **T2.4: Advisory Anomaly Detection** | Tier 2 Extension | Implemented | `advisory/anomaly/detector.py`, `eval/e8_anomaly.py`, `engine/tests/test_anomaly.py` |
| **T2.5: Deterministic PDF Export** | Tier 2 Extension | Implemented | `backend/reports/pdf.py`, `backend/tests/test_reports.py` |
| **T2.6: Evidence Capping & Limits** | Tier 2 Extension | Implemented | `engine/smscope/limits.py`, `engine/tests/test_limits.py` |
| **T2.7: Inline SVG Visualizations** | Tier 2 Extension | Implemented | `backend/charts.py`, `backend/templates/tls.html`, `backend/tests/test_dashboard.py` |
| **T3.1: Asymmetric Key Distribution** | Tier 3 Extension | Implemented | `validator/keygen.py`, `backend/app.py` (`/validators/{id}/key`) |
| **T3.2: Asymmetric Sealed Envelopes** | Tier 3 Extension | Implemented | `validator/crypto.py`, `backend/app.py` (`/cases/{id}/distribute`) |
| **T3.3: Authenticated Decryptor Service**| Tier 3 Extension | Implemented | `validator/crypto.py`, `validator/service.py`, `validator/tests/test_encrypted_delivery.py` |

---

## Prerequisites & Installation

### Required Software & Versions
- **Python:** `>= 3.11`
- **Node.js:** `>= 18.0.0` with `npm`
- **Docker:** (Optional, for containerized engine execution and mail server lab)
- **Wireshark / TShark:** `>= 4.0.0` (Optional, for ground truth comparison)

### Step 1: Clone & Install Dependencies
```bash
# Clone the repository
git clone <your-repo-url>
cd blockchain-project

# Install smart contract dependencies
cd contracts
npm install
cd ..

# Install Python package and dependencies in editable mode
pip install -e .[backend,dev]
```

### PDF Report Export (Tier 2 / Prompt T2.5)
PDF report generation (`GET /cases/{id}/report?format=pdf`) uses WeasyPrint when system C libraries (Pango/Cairo) are present. When running in environments without native GTK libraries (such as clean Windows hosts), SecureMailScope provides a pure-Python fallback renderer using `pydyf`, explicitly labeling the document as `fallback rendering`.

---

## How to Build the Engine Container

The engine can run directly as a Python module or within a sealed, network-less Docker container built from the repository root:
```bash
docker build -t smscope-engine:latest .
```

To run an analysis inside the sealed sandbox container:
```bash
docker run --rm --network none --read-only \
  -v "$(pwd)/lab/captures/S05.pcap:/input/pcap.bin:ro" \
  -v "$(pwd)/out:/out" \
  smscope-engine:latest \
  analyze /input/pcap.bin \
  --org-secret-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --out /out
```

---

## How to Run the Mail Lab & Generate Captures

The lab environment uses Postfix and Dovecot with synthetic client traffic:
```bash
# Start containerized mail server
docker compose -f lab/docker-compose.yaml up -d

# Execute test scenarios and generate traffic
python lab/client/run_client.py --scenario S05 --mode starttls --auth yes

# Stop lab environment
docker compose -f lab/docker-compose.yaml down
```
Pre-captured PCAPs for all scenarios `S01a` through `S13`, `S20`–`S25`, `S30`–`S35`, and adversarial vectors `X01`–`X03` are bundled in `lab/captures/`.

---

## Starting the Blockchain Node & Contracts

### 1. Start Local Hardhat EVM Node
In Terminal 1:
```bash
cd contracts
npx hardhat node
```

### 2. Deploy Contracts & Grant Roles
In Terminal 2:
```bash
cd contracts
npx hardhat run scripts/deploy.ts --network localhost
cd ..
```
This produces `contracts/deployments/local.json` containing deployed contract addresses and ABIs.

---

## Starting Backend API & Validator Services

### 1. Start the FastAPI Backend & Dashboard
In Terminal 2:
```bash
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```
Access the server-rendered dashboard in your browser at `http://127.0.0.1:8000`.

### 2. Start Three Independent Validator Services
In separate terminals (or background jobs), configure keys from `local.json` and start the validator daemons:

```bash
# Validator 1 (Hardhat Public Default Test Account #1 - for local development only)
export VALIDATOR_1_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
python validator/service.py --id 1 --key-env VALIDATOR_1_KEY

# Validator 2 (Hardhat Public Default Test Account #2 - for local development only)
export VALIDATOR_2_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
python validator/service.py --id 2 --key-env VALIDATOR_2_KEY

# Validator 3 (Hardhat Public Default Test Account #3 - for local development only)
export VALIDATOR_3_KEY=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
python validator/service.py --id 3 --key-env VALIDATOR_3_KEY
```

---

## Running the Interactive Demonstration

Run the automated live demonstration:
```bash
make demo
```
*(Direct script: `bash scripts/demo_full.sh`)*

---

## Running the Test Suites

Execute all automated unit and integration tests across engine, backend, validator, and smart contracts:
```bash
# Run all test suites
make test

# Or run individual test directories directly:
python -m pytest engine/tests       # Engine, TLS, X.509, protocols, rules (245 passed)
python -m pytest backend/tests      # Backend REST API, reports, and dashboard (41 passed)
python -m pytest validator/tests    # Validator cryptography & encrypted delivery (9 passed)
cd contracts && npm test && cd ..   # Smart contract consensus & ledger suite (90 passing)
```

---

## Regenerating the Evaluation Suite (Milestone M5)

Run the single-command evaluation orchestrator:
```bash
make eval
# Or directly:
python eval/run_all.py
```

Generated evaluation tables and reports:
- `eval/results/e1_parsing_agreement.{csv,md}`: Protocol and TLS parsing accuracy vs tshark ground truth (98.63% agreement).
- `eval/results/e2_detection_accuracy.{csv,md}`: Precision and recall across evaluated rules.
- `eval/results/e3_baseline_comparison.{csv,md}`: Comparative audit vs Zeek SSL notices.
- `eval/results/e4_determinism.{csv,md}`: Byte-identical engine reproducibility across 5 runs (0 byte variance).
- `eval/results/e5_chain_tests.{csv,md}`: On-chain Byzantine consensus, tamper detection, and RBAC matrix.
- `eval/results/e6_gas.{csv,md}`: Gas consumption across operations for $N=3$ and $N=5$.
- `eval/results/e7_leak_test.{csv,md}`: Scan for credential/secret leaks.
- `eval/results/e8_anomaly.{csv,md}`: Isolation forest anomaly detection benchmarks.
- `eval/THREATS.md`: Threats to validity documentation.

---

## Project Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Formal architectural design specification.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md): Traceability matrix covering course deliverables.
- [docs/VIVA.md](docs/VIVA.md): Technical defense and viva voce Q&A (~150 words per question).
- [docs/decisions/](docs/decisions/): Architectural decision records (Decisions 004 through 020).
- [docs/audits/](docs/audits/): Acceptance audit records.
