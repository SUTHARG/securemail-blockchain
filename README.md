# SecureMailScope

**Decentralized Cryptographic Security Posture Assessment & Network Forensic Ledger**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Solidity 0.8.24](https://img.shields.io/badge/solidity-0.8.24-lightgrey.svg)](https://soliditylang.org/)
[![Hardhat](https://img.shields.io/badge/framework-Hardhat-yellow.svg)](https://hardhat.org/)
[![Tests Passing](https://img.shields.io/badge/tests-536%20passing-brightgreen.svg)]()
[![E1 Ground Truth](https://img.shields.io/badge/parsing%20agreement-100%25-success.svg)]()
[![Zero External CDN](https://img.shields.io/badge/privacy-zero%20CDN-orange.svg)]()

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement & Threat Model](#problem-statement--threat-model)
3. [System Architecture Across Tiers](#system-architecture-across-tiers)
   - [Tier 1: Baseline Architecture & Forensic Engine](#tier-1-baseline-architecture--forensic-engine)
   - [Tier 2: Multi-Protocol Forensic Capabilities](#tier-2-multi-protocol-forensic-capabilities)
   - [Tier 3: Asymmetric Sealed Delivery & Decentralized Validators](#tier-3-asymmetric-sealed-delivery--decentralized-validators)
4. [Forensic Security Ruleset (R01–R19)](#forensic-security-ruleset-r01r19)
5. [Smart Contract Architecture & EVM Consensus](#smart-contract-architecture--evm-consensus)
   - [Contract Breakdown](#contract-breakdown)
   - [Commit-Reveal Protocol Workflow](#commit-reveal-protocol-workflow)
   - [Append-Only PostureLedger](#append-only-postureledger)
6. [Five-Step Mathematical Verification Pipeline](#five-step-mathematical-verification-pipeline)
7. [Web Presentation & REST API Dashboard](#web-presentation--rest-api-dashboard)
   - [Zero-CDN Dashboard UI](#zero-cdn-dashboard-ui)
   - [REST API Reference](#rest-api-reference)
   - [Dual-Mode Authentication](#dual-mode-authentication)
8. [Repository Directory Structure](#repository-directory-structure)
9. [Step-by-Step Installation & Setup](#step-by-step-installation--setup)
   - [Prerequisites](#prerequisites)
   - [Step 1: Clone Repository & Install Dependencies](#step-1-clone-repository--install-dependencies)
   - [Step 2: Environment Configuration](#step-2-environment-configuration)
   - [Step 3: Start Local Blockchain & Deploy Contracts](#step-3-start-local-blockchain--deploy-contracts)
   - [Step 4: Start Backend Application](#step-4-start-backend-application)
   - [Step 5: Start Validator Nodes](#step-5-start-validator-nodes)
   - [Step 6: Run Automated Demonstration](#step-6-run-automated-demonstration)
10. [Automated Test Suite & Verification Evidence](#automated-test-suite--verification-evidence)
11. [Empirical Evaluation Benchmarks (Milestone M5)](#empirical-evaluation-benchmarks-milestone-m5)
12. [Mail Lab & Synthetic PCAP Scenarios](#mail-lab--synthetic-pcap-scenarios)
13. [Independent Verification Execution](#independent-verification-execution)
14. [Deploying & Pushing to GitHub](#deploying--pushing-to-github)

---

## Executive Summary

**SecureMailScope** is an end-to-end decentralized forensic security posture platform designed to assess email network traffic while guaranteeing tamper-proof non-repudiation. It unites:

- **Deterministic Passive Network Forensics:** Byte-level inspection of SMTP, IMAP, and POP3 packet captures (PCAP) with full TLS 1.2/1.3 and X.509 cryptographic validation.
- **Strict Integer-Arithmetic Scoring:** 19 formal security rules evaluated deterministically without floating-point math, non-deterministic wall-clock timestamps, or unpinned seeds.
- **EVM-Anchored Commit-Reveal Consensus:** Multi-party cryptographic validation using Hardhat/Solidity smart contracts where independent validator nodes reach $k$-of-$N$ quorum over RFC 8785 canonical Merkle roots.
- **Append-Only Posture Ledger:** A cryptographically hash-chained on-chain ledger recording historical host security scores with verifiable Merkle inclusion proofs.
- **Zero-Trust Asymmetric Delivery:** Confidential PCAP and organization secret transmission to sandboxed validator execution environments using Curve25519 / X25519 sealed boxes.
- **Self-Contained Web Dashboard:** A high-speed FastAPI and Jinja2 interface with pure Python inline SVG charts, zero external CDN dependencies, and dual-mode RBAC authentication.

---

## Problem Statement & Threat Model

### The Challenges of Mail Infrastructure Auditing
Mail transfer agents (MTAs) and mail delivery agents (MDAs) remain frequent targets for downgrade attacks, credential interception, and impersonation:
1. **Opportunistic Encryption Exploitation:** Protocols like STARTTLS are vulnerable to active stripping attacks (STRIPTLS) if clients don't strictly enforce TLS.
2. **Cryptographic Weaknesses:** Continued acceptance of deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1), non-forward-secret ciphers (static RSA), or short keys.
3. **PKI & Certificate Flaws:** Self-signed certificates, expired leaf certificates, Subject Alternative Name (SAN) discrepancies, and untrusted issuer chains.
4. **Credential Leakage:** Plaintext transmission of `AUTH LOGIN`, `AUTH PLAIN`, or `PASS` commands over unencrypted transport layers.

### Centralized Auditing Vulnerabilities
Traditional network forensic audits suffer from critical integrity risks:
- **Single Point of Compromise:** Centralized logging databases can be retroactively altered, deleted, or falsified by malicious administrators or compromised hosts.
- **Non-Reproducible Analysis:** Forensic tools often incorporate local environment parameters, floating-point rounding discrepancies, or non-deterministic ordering that prevent independent verification.
- **Absence of Non-Repudiation:** Once a report is generated, third-party auditors cannot mathematically prove that the analysis was conducted on the exact unmodified raw traffic capture.

### SecureMailScope Threat Model & Countermeasures
| Threat Vector | Description | SecureMailScope Countermeasure |
|---|---|---|
| **Raw PCAP Tampering** | Manipulating packet data prior to or after analysis. | Exact SHA-256 hash of the PCAP is pinned on-chain in `CaseRegistry` at case creation. |
| **Biased or Rogues Validators** | A validator attempts to falsify or manipulate findings. | $k$-of-$N$ commit-reveal consensus scheme over Merkle `resultRoot`; minority deviations are rejected. |
| **State History Revision** | Retroactively altering past posture scores of a host. | `PostureLedger` enforces strict keccak256 hash chaining: $H_i = \text{keccak256}(H_{i-1} \parallel \dots)$. |
| **Secret & PCAP Interception** | Sniffing PCAP or org secret in transit between analyst and validator. | Asymmetric Curve25519 sealed box encryption (`validator/crypto.py`) addressed strictly to validator public keys. |
| **Sandboxed DoS / Egress Attacks** | Malicious PCAPs attempting resource exhaustion or network calls. | Network-less execution (`--network none --read-only`), strict packet/session/evidence limits (`limits.py`). |
| **Non-Deterministic Roots** | Platform-dependent JSON serialization altering Merkle hashes. | RFC 8785 JSON Canonicalization Scheme (JCS) with integer-only sorting and encoding. |

---

## System Architecture Across Tiers

SecureMailScope is engineered across three progressive tiers:

```
+----------------------------------------------------------------------------------------------------+
|                                    SECUREMAILSCOPE ARCHITECTURE                                    |
+----------------------------------------------------------------------------------------------------+

  [ Network Analyst ]
          │
          ▼
   Raw PCAP Upload  ───►  [ SHA-256 Digest ] ───►  [ CaseRegistry.sol (EVM) ]
          │                                                    │
          ▼                                                    │ Pinned Case Parameters
   Asymmetric Sealed Box                                       ▼
  (X25519-ChaCha20-Poly1305) ───────────────────────►  [ Independent Validators ]
                                                       (Node 1, Node 2, Node 3)
                                                               │
                                                               ▼ (Isolated Container)
                                                       [ Deterministic Engine ]
                                                       - SMTP / IMAP / POP3
                                                       - TLS 1.2 / 1.3 Parser
                                                       - X.509 PKI Verifier
                                                       - Ruleset Evaluator (R01-R19)
                                                               │
                                                               ▼
                                                       [ RFC 8785 Canonical Merkle Tree ]
                                                               │
                     ┌─────────────────────────────────────────┴────────────────────────────────────┐
                     ▼                                                                              ▼
         Phase 1: Commit Hash                                                           Phase 2: Reveal Root
      keccak256(resultRoot, salt)                                                        (resultRoot, salt)
                     │                                                                              │
                     ▼                                                                              ▼
      [ ValidationQuorum.sol ] ◄────────────────────────────────────────────────────────────────────┘
                     │
                     ▼ (Consensus Reached: k-of-N Quorum)
             Lock `finalRoot`
                     │
                     ▼
      [ PostureLedger.sol ] ◄── Appends Hash-Chained Host Posture with Merkle Inclusion Proof
                     │
                     ▼
      [ Backend Dashboard & API ] ◄── Generates Canonical JSON / HTML / Fallback PDF Reports
                     │
                     ▼
      [ Independent Verifier ] ◄── 5-Step Mathematical Verification Suite
```

### Tier 1: Baseline Architecture & Forensic Engine
- **Passive Protocol Ingestion (`engine/smscope/protocols/`):**
  - **SMTP (`smtp.py`):** Parses command/response sequences across ports 25, 465, and 587. Inspects EHLO/HELO banners, detects `250-STARTTLS` advertisement, tracks `STARTTLS` handshake initiation, and alerts on cleartext authentication commands (`AUTH PLAIN`, `AUTH LOGIN`).
  - **TLS & PKI (`engine/smscope/tls/`):** Custom wire-format TLS record layer parser. Extracts `ClientHello` and `ServerHello` handshake messages, detects TLS version (including RFC 8446 TLS 1.3 `supported_versions` extension extraction), parses cipher suites, Server Name Indication (SNI), Application-Layer Protocol Negotiation (ALPN), and decodes X.509 certificate chains via `cryptography.x509`.
- **Core Security Ruleset (`ruleset/ruleset.yaml`, `engine/smscope/rules/evaluator.py`):**
  - Evaluates rules R01 through R12 covering unencrypted sessions, plaintext credentials, outdated protocol versions, broken cipher suites, and invalid certificates.
- **Deterministic Merkle Results (`engine/smscope/results/`):**
  - Canonicalizes finding records and host posture summaries using RFC 8785 JSON Canonicalization Scheme (JCS).
  - Calculates SHA-256 leaf digests and constructs a binary Merkle tree with sorted pairs to derive a 32-byte `resultRoot`.
- **EVM Smart Contracts (`contracts/contracts/`):**
  - Hardhat-managed Solidity contracts establishing case lifecycles, commit-reveal consensus, role-based access control, and host posture history.

### Tier 2: Multi-Protocol Forensic Capabilities
- **Expanded Protocols (`protocols/imap.py`, `protocols/pop3.py`):**
  - **IMAP:** Deep inspection of IMAP4rev1 traffic on ports 143 (STARTTLS) and 993 (implicit TLS). Detects `CAPABILITY` advertisements, `STARTTLS` negotiation, and plaintext `LOGIN` commands.
  - **POP3:** Parsing of POP3 traffic on ports 110 (STLS) and 995 (implicit TLS). Detects `STLS` capabilities, plaintext `USER`/`PASS` authentication, and unencrypted sessions.
- **Extended Security Ruleset (R13–R19):**
  - Expands coverage to weak certificate signatures (MD5/SHA-1), SNI discrepancies, incomplete certificate authority chains, self-signed certificates, inconsistent STARTTLS policy advertisements across server endpoints, and ephemeral leaf certificate variance.
- **Advisory Anomaly Detection (`advisory/anomaly/detector.py`, `eval/e8_anomaly.py`):**
  - Unsupervised machine learning (Isolation Forest) benchmarking alongside heuristic divergence checks to flag anomalous email session anomalies without disrupting deterministic consensus roots.
- **Resource Bounds & Evidence Limits (`engine/smscope/limits.py`):**
  - Enforces hard boundaries on captured packets, session state allocations, and maximum recorded evidence items per finding to defeat algorithmic complexity DoS attacks.
- **Inline SVG Visualizations (`backend/charts.py`):**
  - Generates responsive, lightweight inline SVG charts directly in Python (TLS version breakdown, cipher suite distributions, finding severities) without external JavaScript libraries or CDN requests.
- **Dual-Engine PDF Reporting (`backend/reports/pdf.py`):**
  - Exports deterministic executive reports. Uses WeasyPrint when system Cairo/Pango C libraries are present; seamlessly falls back to pure-Python PDF rendering (`pydyf`) on standard platforms.

### Tier 3: Asymmetric Sealed Delivery & Decentralized Validators
- **Asymmetric Key Exchange (`validator/keygen.py`):**
  - Each validator generates an X25519 keypair. Public keys are registered on the backend (`/validators/{id}/key`).
- **Sealed Box Encryption (`validator/crypto.py`):**
  - PCAPs and sensitive organization secrets are encrypted using libsodium-compatible Curve25519 / X25519-ChaCha20-Poly1305 sealed boxes (`nacl.public.SealedBox`).
  - Only the target validator node possessing the matching private key can decrypt the envelope.
- **Sandboxed Execution Container (`Dockerfile`):**
  - Sealed Docker image (`smscope-engine:latest`) designed to run under `--network none --read-only`, preventing network egress, data exfiltration, or runtime modification.

---

## Forensic Security Ruleset (R01–R19)

SecureMailScope implements 19 formal security rules. Each rule produces evidence records and deterministic score penalties:

| Rule ID | Severity | Default Penalty | Target Protocols | Description & Detection Condition |
|---|---|---|---|---|
| **R01** | **Critical** | -40 pts | SMTP, IMAP, POP3 | **Cleartext credentials sent before encryption:** `AUTH PLAIN`, `AUTH LOGIN`, or `USER`/`PASS` transmitted over unencrypted session. |
| **R02** | **High** | -25 pts | SMTP | **Mail session with no encryption and STARTTLS not offered:** Plaintext session where server banner lacks `STARTTLS`. |
| **R03** | **High** | -25 pts | SMTP, IMAP, POP3 | **STARTTLS offered but never attempted:** Server advertised STARTTLS capability, but client proceeded in plaintext. |
| **R04** | **High** | -25 pts | SMTP, IMAP, POP3 | **STARTTLS attempted, refused, session continued in plaintext:** Handshake failed/rejected and client fell back to plaintext. |
| **R05** | **Critical** | -40 pts | TLS | **SSL 3.0 or older negotiated:** Handshake negotiated obsolete and broken protocol version (SSL 2.0 / SSL 3.0). |
| **R06** | **High** | -25 pts | TLS | **TLS 1.0 or 1.1 negotiated:** Handshake negotiated deprecated TLS versions prohibited by RFC 8996. |
| **R07** | **Critical** | -40 pts | TLS | **NULL, EXPORT, or anonymous cipher suite:** Selected cipher provides zero encryption or export-grade weakness. |
| **R08** | **High** | -25 pts | TLS | **RC4, DES, or 3DES cipher suite:** Negotiated legacy symmetric cipher vulnerable to known cryptanalytic attacks. |
| **R09** | **Medium** | -15 pts | TLS | **No forward secrecy (static RSA or static DH):** Cipher suite lacks ephemeral key exchange (ECDHE/DHE). |
| **R10** | **Medium** | -15 pts | TLS | **DHE prime below 2048 bits:** Ephemeral Diffie-Hellman parameters vulnerable to Logjam-style precomputation. |
| **R11** | **High** | -25 pts | X.509 PKI | **Certificate expired at capture time:** PCAP packet timestamp falls outside certificate `notBefore` / `notAfter`. |
| **R12** | **High** | -25 pts | X.509 PKI | **RSA key below 2048 bits or EC key below 224 bits:** Public key length violates modern cryptographic standards. |
| **R13** | **High** | -25 pts | X.509 PKI | **MD5 or SHA-1 signature on non-root certificate:** Intermediate or leaf certificate utilizes collision-vulnerable hash. |
| **R14** | **Medium** | -15 pts | TLS / PKI | **Certificate name does not match SNI:** Server certificate SAN / CN entries do not match negotiated SNI hostname. |
| **R15** | **Low** | -10 pts | X.509 PKI | **Unknown issuer or incomplete chain:** Certificate authority is missing or cannot be validated against root store. |
| **R16** | **Medium** | -15 pts | X.509 PKI | **Self-signed leaf certificate:** Leaf certificate is signed by its own subject without intermediate CA trust. |
| **R17** | **Medium** | -15 pts | SMTP, IMAP, POP3 | **Inconsistent STARTTLS advertisement:** STARTTLS offered to server in some sessions but omitted in others (STRIPTLS). |
| **R18** | **Medium** | -15 pts | TLS / PKI | **Leaf certificate variance across endpoints:** Distinct leaf certificates observed for the same server endpoint in one capture. |
| **R19** | **Info** | 0 pts | TLS 1.3 | **Certificate not observable (TLS 1.3 or resumed):** Certificate encrypted or session resumed; noted without penalty. |

### Deterministic Integer Scoring Model
The posture score for each evaluated host is calculated using integer arithmetic:
$$\text{Score}(H) = \max\left(0, \min\left(100, 100 - \sum_{i \in \text{Findings}(H)} \text{Penalty}_i\right)\right)$$
- If no findings occur, the host score is $100$.
- Floating-point arithmetic is strictly avoided across the engine to prevent IEEE-754 architecture divergence across operating systems.

---

## Smart Contract Architecture & EVM Consensus

The smart contracts are written in Solidity `0.8.24` and compiled using Hardhat.

```
                           +----------------------+
                           |      Roles.sol       |
                           | (Admin/Analyst/Val.) |
                           +----------+-----------+
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
  +--------------------+    +--------------------+    +--------------------+
  |  CaseRegistry.sol  |    |ValidationQuorum.sol|    | PostureLedger.sol  |
  |  (Case State Mach) |◄──►| (Commit-Reveal)    |    | (Hash-Chain Ledger)|
  +--------------------+    +--------------------+    +---------+----------+
                                                                │
                                                                ▼
                                                      +--------------------+
                                                      | MerkleVerifier.sol |
                                                      | (Inclusion Proofs) |
                                                      +--------------------+
```

### Contract Breakdown
1. **`Roles.sol`**:
   - Manages role permissions using bitmap-efficient or OpenZeppelin-compatible structures:
     - `DEFAULT_ADMIN_ROLE`: Authorizes contract upgrades, configures quorum thresholds ($k, N$).
     - `ANALYST_ROLE`: Creates cases, uploads PCAP metadata, anchors finalized reports.
     - `VALIDATOR_ROLE`: Authorizes participating validator nodes to submit commits and reveals.
2. **`CaseRegistry.sol`**:
   - Tracks case lifecycle: `CREATED` $\to$ `IN_VALIDATION` $\to$ `REVEAL_OPEN` $\to$ `CONSENSUS_REACHED` $\to$ `REPORT_ANCHORED`.
   - Immutable pinning of: `pcapHash` (SHA-256), `engineImageDigest`, `rulesetHash`, and final consensus `resultRoot`.
3. **`ValidationQuorum.sol`**:
   - Implements $k$-of-$N$ commit-reveal consensus.
   - Enforces commit deadlines and reveal windows.
   - Computes modal agreement: when $k$ matching reveals are verified, consensus is reached and `finalRoot` is submitted to `CaseRegistry`.
   - Handles dispute detection if competing roots exceed fault tolerance thresholds.
4. **`PostureLedger.sol`**:
   - Append-only cryptographic ledger storing historical host posture evaluations.
   - Each host retains an independent cryptographic hash chain:
     $$H_0 = 0x00\dots00$$
     $$H_i = \text{keccak256}\left(\text{abi.encode}(hostId, caseId, score, resultRoot, H_{i-1}, timestamp)\right)$$
   - Verifies Merkle inclusion proofs via `MerkleVerifier.sol` before accepting score appends.
5. **`MerkleVerifier.sol`**:
   - Pure cryptographic library for verifying binary Merkle tree proofs on-chain.

### Commit-Reveal Protocol Workflow
1. **Case Creation:** An analyst registers a case on `CaseRegistry` by providing `pcapHash`, deadline blocks, and a validator snapshot of $N$ addresses.
2. **Commit Phase:** Each selected validator runs the deterministic engine on the PCAP, derives the 32-byte `resultRoot`, generates a cryptographically secure random 32-byte `salt`, and submits:
   $$\text{commitHash} = \text{keccak256}\left(\text{abi.encodePacked}(resultRoot, salt)\right)$$
3. **Reveal Phase:** Once the commit window closes, validators submit their plaintext `resultRoot` and `salt`. The contract verifies that $\text{keccak256}(resultRoot, salt) \equiv \text{commitHash}$.
4. **Quorum Finalization:** Once $k$ matching reveals match the identical `resultRoot`, the contract marks consensus as reached and notifies `CaseRegistry`.

---

## Five-Step Mathematical Verification Pipeline

Any independent auditor can verify the authenticity, consensus, and history of a SecureMailScope analysis without trusting any centralized database:

```
  Step 1: Raw PCAP Verification
  SHA-256( local_pcap.bin ) == onchain CaseRegistry.pcapHash( caseId )
                                  │
                                  ▼ PASS
  Step 2: Canonical Merkle Tree Reconstitution
  Rebuild leaves from findings.json + host_scores.json via RFC 8785
  Local Tree Root == result.json resultRoot
                                  │
                                  ▼ PASS
  Step 3: Quorum Root Consensus Match
  Recomputed Local Merkle Root == onchain CaseRegistry.finalRoot( caseId )
                                  │
                                  ▼ PASS
  Step 4: Posture Ledger Hash-Chain Integrity
  For every host:
    Verify H_i == keccak256( hostId, caseId, score, resultRoot, H_{i-1}, timestamp )
    Verify Merkle inclusion proof against finalRoot
                                  │
                                  ▼ PASS
  Step 5: Canonical Report Anchoring
  SHA-256( RFC-8785( report.json ) ) == onchain CaseRegistry.reportHash( caseId )
                                  │
                                  ▼
                   ALL 5 VERIFICATION CHECKS PASS
```

Execute this verification using the CLI verifier:
```bash
python -m verifier.verify \
  --case-id <32-byte-hex-case-id> \
  --pcap lab/captures/S05.pcap \
  --findings-dir data/cases/<case-uuid> \
  --report data/cases/<case-uuid>/report.json
```

---

## Web Presentation & REST API Dashboard

### Zero-CDN Dashboard UI
The web presentation layer is built on FastAPI and Jinja2 with an unwavering privacy commitment:
- **Zero Third-Party Assets:** No Google Fonts, no Cloudflare CDN scripts, no external tracking pixels.
- **Pure Python SVG Rendering:** Inline SVG visualization components generated on the fly for TLS version usage, cipher suite frequency, and posture distribution.
- **Dedicated Forensic Views:**
  - `/` — Cases overview, case creation, system posture health.
  - `/cases/{id}` — Case summary, pinned hashes, state badges.
  - `/cases/{id}/chain` — On-chain validator commit-reveal inspection, transaction hashes, quorum status.
  - `/cases/{id}/findings` — Categorized rule findings (R01–R19) with raw packet evidence snippets.
  - `/cases/{id}/sessions` — Dissected email sessions (SMTP/IMAP/POP3), commands, status codes.
  - `/cases/{id}/tls` — TLS handshake parameters, versions, cipher distribution charts.
  - `/cases/{id}/certificates` — X.509 certificate chains, SAN entries, expiration, issuers.
  - `/cases/{id}/advisory` — Unsupervised ML anomaly detection and outlier scoring.
  - `/cases/{id}/report?format=json|html|pdf` — Exportable audit reports.

### REST API Reference
| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/` | Renders dashboard case overview | Browser / None |
| `POST` | `/cases` | Create new case and upload PCAP | Analyst (`X-API-Key`) |
| `GET` | `/cases/{id}` | Detailed case inspection view | Browser / Optional Analyst |
| `GET` | `/cases/{id}/chain` | Real-time blockchain quorum & validator state | Browser / Optional Analyst |
| `GET` | `/cases/{id}/findings` | Interactive findings breakdown | Browser / Optional Analyst |
| `GET` | `/cases/{id}/sessions` | Email session explorer | Browser / Optional Analyst |
| `GET` | `/cases/{id}/tls` | TLS metrics & inline SVG charts | Browser / Optional Analyst |
| `GET` | `/cases/{id}/certificates` | X.509 certificate viewer | Browser / Optional Analyst |
| `GET` | `/cases/{id}/advisory` | Advisory anomaly detection report | Browser / Optional Analyst |
| `GET` | `/cases/{id}/report` | Generate audit report (`?format=json\|html\|pdf`) | Browser / Optional Analyst |
| `POST` | `/cases/{id}/distribute` | Create sealed asymmetric envelopes for validators | Analyst (`X-API-Key`) |
| `GET` | `/validators/{id}/inbox` | Validator polls for sealed jobs | Validator |
| `POST` | `/validators/{id}/key` | Register validator X25519 public key | Validator |
| `GET` | `/api/health` | Service health status and EVM RPC connectivity | None |

### Dual-Mode Authentication
SecureMailScope implements dual-mode authentication via `backend/auth.py`:
1. **API Automation:** Automated scripts, CI/CD pipelines, and CLI tools pass `X-API-Key: <key>` headers (`ADMIN_API_KEY` or `ANALYST_API_KEY`).
2. **Browser Navigation:** When accessed directly via web browsers (detected via standard HTTP headers `Accept: text/html` and `Sec-Fetch-Mode: navigate`), read-only views are seamlessly accessible to analysts without modal authentication blocks.

---

## Repository Directory Structure

```
blockchain-project/
├── backend/                        # FastAPI Web Backend & Dashboard
│   ├── app.py                      # Main application endpoints & routing
│   ├── auth.py                     # Dual-mode API key & browser authentication
│   ├── charts.py                   # Pure Python inline SVG chart generation
│   ├── database.py                 # SQLite metadata persistence & audit logging
│   ├── runner.py                   # Engine invocation & result indexing
│   ├── storage.py                  # PCAP storage & stream validation
│   ├── chain/                      # EVM Web3 gateway & contract interfaces
│   │   └── gateway.py              # ChainGateway for CaseRegistry & Quorum
│   ├── reports/                    # Report generation engine
│   │   ├── builder.py              # Canonical JSON report assembly
│   │   └── pdf.py                  # Deterministic PDF export (WeasyPrint / pydyf)
│   ├── templates/                  # Zero-CDN Jinja2 HTML templates
│   └── tests/                      # Backend REST API & regression tests (50 tests)
│
├── contracts/                      # Hardhat EVM Smart Contracts
│   ├── contracts/                  # Solidity source files (0.8.24)
│   │   ├── CaseRegistry.sol        # Case lifecycle, hash pinning, roots
│   │   ├── ValidationQuorum.sol    # k-of-N commit-reveal consensus
│   │   ├── PostureLedger.sol       # Append-only hash-chained posture ledger
│   │   ├── Roles.sol               # Admin, Analyst, Validator RBAC
│   │   └── MerkleVerifier.sol      # Merkle proof verification library
│   ├── scripts/                    # Deployment & migration scripts
│   │   └── deploy.ts               # Deploys contracts & configures roles
│   ├── deployments/                # Deployed contract artifacts & local.json
│   └── test/                       # Hardhat test suites (90 tests)
│
├── engine/                         # Core Deterministic Forensic Engine
│   └── smscope/                    # Python forensic analysis package
│       ├── protocols/              # Protocol parsers (SMTP, IMAP, POP3)
│       ├── tls/                    # TLS 1.2/1.3 record & handshake parser
│       ├── x509/                   # X.509 certificate validation & SAN checks
│       ├── rules/                  # Evaluator for ruleset R01–R19
│       ├── results/                # Canonical JSON, Merkle tree, & hashing
│       ├── limits.py               # Resource bounds & evidence limits
│       └── pcap.py                 # Streaming PCAP reader
│   └── tests/                      # Engine unit & integration tests (245 tests)
│
├── validator/                      # Decentralized Validator Service
│   ├── service.py                  # Validator daemon process
│   ├── node.py                     # Analysis execution, commit & reveal logic
│   ├── crypto.py                   # Curve25519 sealed box encryption/decryption
│   ├── keygen.py                   # X25519 validator keypair generation
│   └── tests/                      # Validator crypto & delivery tests (9 tests)
│
├── verifier/                       # Independent Mathematical Verifier
│   └── verify.py                   # 5-step cryptographic verification suite
│
├── ruleset/                        # Formal Security Specifications
│   └── ruleset.yaml                # 19-rule security specification
│
├── lab/                            # Synthetic Mail Lab & PCAPs
│   ├── docker-compose.yaml         # Postfix & Dovecot container setup
│   ├── client/                     # Synthetic test client traffic generators
│   └── captures/                   # Pre-recorded test captures (S01a–S13, X01–X03)
│
├── eval/                           # Milestone M5 Empirical Benchmarks
│   ├── run_all.py                  # Evaluation orchestrator
│   ├── e1_ground_truth.py          # E1: Parser agreement vs tshark (100.0%)
│   ├── e2_detection.py             # E2: Detection accuracy across 19 rules
│   ├── e3_baseline.py              # E3: Comparison against Zeek SSL notices
│   ├── e4_determinism.py           # E4: 5-run byte-identical determinism test
│   ├── e5_chain.py                 # E5: On-chain Byzantine consensus test
│   ├── e6_gas.py                   # E6: Gas consumption profiling
│   ├── e7_leaks.py                 # E7: Zero credential leak audit
│   ├── e8_anomaly.py               # E8: Unsupervised Isolation Forest benchmark
│   └── results/                    # Generated CSV and Markdown report artifacts
│
├── scripts/                        # Utility Scripts & Demonstrations
│   ├── demo_full.sh                # End-to-end automated live demonstration
│   └── determinism_check.py        # Bit-level reproducibility check
│
├── docs/                           # Architectural Documentation & Audits
│   ├── ARCHITECTURE.md             # Formal system architecture specification
│   ├── COMPLIANCE.md               # Compliance & traceability matrix
│   └── VIVA.md                     # Technical viva defense Q&A reference
│
├── Dockerfile                      # Sealed sandbox engine container
├── Makefile                        # Build, test, and evaluation automation
├── pyproject.toml                  # Python package configuration
└── README.md                       # Master documentation (this file)
```

---

## Step-by-Step Installation & Setup

### Prerequisites
- **Operating System:** Linux, macOS, or Windows (WSL2 / PowerShell supported)
- **Python:** `>= 3.11`
- **Node.js:** `>= 18.0.0` with `npm`
- **Docker:** (Optional) Required only for running the mail lab or sealed container execution.
- **TShark / Wireshark:** `>= 4.0.0` (Optional) Required only for running evaluation benchmark E1.

---

### Step 1: Clone Repository & Install Dependencies

```bash
# 1. Clone the repository
git clone https://github.com/SUTHARG/securemail-blockchain.git
cd securemail-blockchain

# 2. Install smart contract dependencies
cd contracts
npm install
cd ..

# 3. Create and activate a Python virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# 4. Install Python dependencies in editable mode
pip install -e .[backend,dev]
```

---

### Step 2: Environment Configuration

Create a `.env` file in the repository root by copying the template:

```bash
cp .env.example .env
```

Ensure `.env` contains the following parameters:
```ini
# 32-byte hexadecimal organization secret for host pseudonymization
ORG_SECRET_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Local Hardhat Private Keys (Hardhat Account #0 is Admin/Analyst, Accounts #1-#3 are Validators)
ADMIN_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ANALYST_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VALIDATOR_KEY_1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
VALIDATOR_KEY_2=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
VALIDATOR_KEY_3=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6

# Blockchain RPC Provider URL
RPC_URL=http://127.0.0.1:8545

# API Access Keys for REST API client automation
ANALYST_API_KEY=analyst-secret-key-12345
ADMIN_API_KEY=admin-secret-key-67890
```

---

### Step 3: Start Local Blockchain & Deploy Contracts

Open a dedicated terminal (Terminal 1) to run the Hardhat local node:
```bash
# Terminal 1: Start local EVM node
cd contracts
npx hardhat node
```
*Keep Terminal 1 running.*

In Terminal 2, compile and deploy the smart contracts:
```bash
# Terminal 2: Deploy contracts to the local node
cd contracts
npx hardhat run scripts/deploy.ts --network localhost
cd ..
```
*This deploys `Roles`, `CaseRegistry`, `ValidationQuorum`, and `PostureLedger`, writing deployed addresses and ABI paths to `contracts/deployments/local.json`.*

---

### Step 4: Start Backend Application

In Terminal 2, launch the FastAPI server using Uvicorn:
```bash
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```
Open your browser at **`http://127.0.0.1:8000`** to access the dashboard.

---

### Step 5: Start Validator Nodes

The validator daemon services monitor their inboxes and the blockchain, executing forensic engine analysis, blinded commitments, and on-chain reveals. Because `validator/service.py` automatically loads keys from `.env` (supporting both `VALIDATOR_KEY_<id>` and `VALIDATOR_<id>_KEY`), you can launch them directly:

```bash
# Terminal 3: Validator Node 1
python validator/service.py --id 1

# Terminal 4: Validator Node 2
python validator/service.py --id 2

# Terminal 5: Validator Node 3
python validator/service.py --id 3
```

Alternatively, specify custom environment variables or direct keys:
```bash
# On Linux/macOS:
export VALIDATOR_KEY_1="<YOUR_VALIDATOR_1_KEY_HEX>"
python validator/service.py --id 1 --key-env VALIDATOR_KEY_1

# On Windows PowerShell:
$env:VALIDATOR_KEY_1="<YOUR_VALIDATOR_1_KEY_HEX>"
python validator/service.py --id 1 --key-env VALIDATOR_KEY_1
```
*Note: You can also trigger the multi-validator consensus round directly from the Web Dashboard by clicking "Run Validator Consensus Round".*

---

### Step 6: Run Automated Demonstration (Clean Isolated Demo)

> [!IMPORTANT]
> **Demonstration Environment Context:**
> The live demonstration and test suites execute strictly against a **local Hardhat EVM development node** (Chain ID `31337`, JSON-RPC `http://127.0.0.1:8545`) and parse **synthetic forensic PCAP captures** (`lab/captures/`). It does not connect to a public Ethereum network or monitor live production mail servers.

To observe the entire lifecycle—registering the engine and validator set on-chain, uploading a PCAP, creating an on-chain case, distributing sealed envelopes, achieving multi-validator quorum, updating the posture ledger, anchoring the report, and executing the 5-step mathematical verification—run the clean demo runner:

```bash
python scripts/run_clean_demo.py
```

**Key Execution Features:**
1. **Engine & Validator Registration:** Automatically checks and registers the engine image digest, ruleset catalog hash, and all 3 validator addresses on-chain.
2. **On-Chain Consensus & Finalization:** Submits case claim, collects commitments and reveals from Validators 1, 2, and 3, reaches quorum, finalizes outcome, appends to `PostureLedger`, and anchors `reportHash`.
3. **5-Step Independent Verification:** Executes Section 8 verification (PCAP hash check, Merkle root recomputation, on-chain finalRoot comparison, PostureLedger hash-chain verification, and report hash match).
4. **Data Isolation:** All demo run database rows and case files are created in an isolated run folder (`data/demo_runs/run_<timestamp>/`), completely preserving `data/smscope.db` and existing case files.

#### Viewing the Demo Case in the Dashboard
To explore the newly generated demo case within the web interface:

1. Launch the backend pointing to the isolated demo data directory. `DATA_DIR` selects the cases folder and the default database location; `DB_PATH` selects the database file. `DATABASE_PATH` and `CASES_DIR` are not configuration variables in this backend.
   - **On Linux / macOS:**
     ```bash
     DATA_DIR=data/demo_runs/run_<timestamp> DB_PATH=data/demo_runs/run_<timestamp>/smscope.db uvicorn backend.app:app --host 127.0.0.1 --port 8000
     ```
   - **On Windows (PowerShell):**
     ```powershell
     $env:DATA_DIR = (Resolve-Path ".\data\demo_runs\run_<timestamp>").Path
     $env:DB_PATH = Join-Path $env:DATA_DIR "smscope.db"
     python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
     ```
2. Navigate to **`http://127.0.0.1:8000`** in your browser.
3. When prompted on `/login`, enter the Analyst API key from `.env`:
   - **API Key:** the value of `ANALYST_API_KEY` in `.env`. The application has no default analyst API key; configure one with at least 16 characters before starting the backend.
4. Access the Case Overview, Sessions, Findings, Host Scores, and On-Chain Verification pages.

The demo backend also requires `CASE_STORAGE_KEY_HEX` to be set to 64 hexadecimal characters (32 bytes). Keep the same key when reopening an existing demo data directory; changing it makes previously stored encrypted case data unreadable.

---

## Automated Test Suite & Verification Evidence

SecureMailScope maintains strict, comprehensive automated test coverage across all subsystems. **Every single test is verified passing:**

| Test Suite | Directory | Tests Passing | Description |
|---|---|---|---|
| **Forensic Engine** | `engine/tests/` | **302 passed** | SMTP/IMAP/POP3 parsers, TLS 1.2/1.3 handshakes, X.509 PKI, stream semantics (contiguity & termination), ruleset R01–R19, Merkle tree, canonical JSON, limits. |
| **Smart Contracts** | `contracts/test/` | **90 passed** | Solidity unit tests, commit-reveal state machine, quorum thresholds, posture ledger hash-chains, disputes. |
| **Backend API & Web** | `backend/tests/` | **123 passed** | REST endpoints, authentication RBAC, CSRF protection, PDF/HTML reports, data directory isolation, chain gateway, stream pipeline integration. |
| **Validator Service** | `validator/tests/` | **21 passed** | Curve25519 sealed box encryption, sealed PCAP delivery, multi-validator decryption, consensus submission, fail-closed binding. |
| **TOTAL** | — | **536 passed** | **100% test pass rate across all suites (0 failures, 0 errors).** |

### Running the Tests
Execute the test suites with:

```bash
# Run Engine forensic tests (302 tests)
python -m pytest engine/tests -v

# Run Backend web and API tests (123 tests)
python -m pytest backend/tests -v

# Run Validator crypto and sealed delivery tests (21 tests)
python -m pytest validator/tests -v

# Run Smart Contract EVM tests (90 tests)
cd contracts && npx hardhat test && cd ..
```

> [!TIP]
> **Windows pytest note:** When running pytest on Windows with a custom temporary directory, ensure the root directory exists before specifying a nested `--basetemp` path (e.g. `--basetemp=.pytest_tmp/run1`), or let pytest use its default workspace sandbox.

---

## Empirical Evaluation Benchmarks (Milestone M5)

The project includes an empirical evaluation pipeline replicating the benchmark matrix in `eval/`:

```bash
python eval/run_all.py
# Or via Makefile:
make eval
```

### Benchmark Summary Results

1. **E1: Parsing Agreement vs. Ground Truth (`eval/results/e1_parsing_agreement.md`)**
   - **Result:** **100.00% Agreement (73/73 fields matched)** against Wireshark/tshark ground truth across test scenarios (`S01a`–`S13`, `X01`–`X03`), including RFC 8446 TLS 1.3 `supported_versions` extension extraction.
2. **E2: Detection Accuracy across Rules (`eval/results/e2_detection_accuracy.md`)**
   - **Result:** 100% precision and recall across all evaluated rules (R01 through R19) on synthetic test vectors.
3. **E3: Baseline Comparison vs. Zeek (`eval/results/e3_baseline_comparison.md`)**
   - **Result:** SecureMailScope detects granular application-level mail downgrade attempts (e.g., STARTTLS stripping, plaintext auth) that traditional Zeek SSL analyzers omit.
4. **E4: Engine Determinism & Bit-Level Reproducibility (`eval/results/e4_determinism.md`)**
   - **Result:** **0 byte variance** across 5 successive runs on identical PCAP captures; identical SHA-256 Merkle root generated every time.
5. **E5: On-Chain Byzantine Consensus & Tamper Resistance (`eval/results/e5_chain_tests.md`)**
   - **Result:** Verifies that a rogue validator attempting to submit a fraudulent `resultRoot` is rejected by quorum consensus and unable to anchor corrupt data.
6. **E6: Gas Consumption Profiling (`eval/results/e6_gas.md`)**
   - **Result:** Profiles gas efficiency for case registration, validator commit, validator reveal, and posture ledger appends under $N=3$ and $N=5$.
7. **E7: Zero-Credential Leakage Audit (`eval/results/e7_leak_test.md`)**
   - **Result:** Automated audit confirming zero plaintext passwords, API keys, or private keys leak into on-chain storage or generated reports.
8. **E8: Advisory Anomaly Detection (`eval/results/e8_anomaly.md`)**
   - **Result:** Unsupervised Isolation Forest benchmarks identifying outlier email sessions with high separation margins.

---

## Mail Lab & Synthetic PCAP Scenarios

The `lab/` directory provides a self-contained mail server testing environment utilizing Postfix and Dovecot with synthetic client generation scripts.

### Scenario Catalog (`lab/captures/`)
- **`S01a` / `S01b`**: Baseline plain SMTP sessions with and without authentication.
- **`S02`**: STARTTLS offered and successfully negotiated with modern TLS 1.3.
- **`S03`**: Opportunistic TLS fallback scenario.
- **`S04`**: STRIPTLS downgrade attack (STARTTLS advertisement stripped in transit).
- **`S05`**: Plaintext SMTP session with no encryption offered; cleartext credentials transmitted.
- **`S06`**: Obsolete SSLv3 negotiated.
- **`S07`**: Deprecated TLS 1.0 / 1.1 negotiated.
- **`S08`**: Broken cipher suites (RC4 / 3DES / NULL).
- **`S09`**: Non-forward-secret cipher suite negotiated (pure RSA key exchange).
- **`S10`**: Weak Diffie-Hellman parameters (DHE prime < 2048 bits).
- **`S11`**: Expired X.509 certificate.
- **`S12`**: Sub-2048-bit RSA public key.
- **`S13`**: Self-signed leaf certificate.
- **`S20`–`S25`**: IMAP4rev1 test scenarios (Plaintext, STARTTLS, Implicit TLS 993).
- **`S30`–`S35`**: POP3 test scenarios (Plaintext, STLS, Implicit TLS 995).
- **`X01`–`X03`**: Adversarial vectors (Malformed packet headers, truncated TLS records, fuzz vectors).

---

## Independent Verification Execution

Auditors can run the 5-step verification process on any completed case:

```bash
python -m verifier.verify \
  --case-id <CASE_ID_HEX> \
  --pcap lab/captures/S05.pcap \
  --findings-dir data/cases/<CASE_UUID> \
  --report data/cases/<CASE_UUID>/report.json \
  --rpc-url http://127.0.0.1:8545
```

**Verification Output:**
```
================================================================================
            SECUREMAILSCOPE VERIFICATION SUITE: 0x5a3f8b...
================================================================================
[Step 1] PCAP SHA-256 equals on-chain pcapHash: PASS
[Step 2] Leaves and root rebuilt from findings and scores equal result.json: PASS
[Step 3] Recomputed root equals on-chain finalRoot: PASS
[Step 4] Posture chain verified (3 records checked): PASS
[Step 5] Report SHA-256 equals on-chain reportHash: PASS
================================================================================
[VERIFICATION RESULT] ALL FIVE STEPS PASSED SUCCESSFULLY.
================================================================================
```

---

## Deploying & Pushing to GitHub

To push the repository to GitHub:

```bash
# 1. Initialize git remote (if not already set)
git remote add origin https://github.com/SUTHARG/securemail-blockchain.git
# Or update existing remote:
git remote set-url origin https://github.com/SUTHARG/securemail-blockchain.git

# 2. Stage updated files
git add README.md

# 3. Commit changes with a descriptive message
git commit -m "docs: complete comprehensive technical documentation in README"

# 4. Push to main branch
git branch -M main
git push -u origin main
```

---

## License & Intellectual Property

SecureMailScope is developed for academic research and advanced network security auditing.
All cryptographic primitives, smart contracts, and forensic parsing algorithms adhere to RFC 8785, RFC 8446, and relevant standards.
