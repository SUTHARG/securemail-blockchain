# Decision 015: API Service Architecture and Data Management

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` Section 3 and Prompt 6.1 (Phase 6: Backend Services and Validators) require an API service that exposes case management, PCAP ingestion, analysis dispatching, forensic artifact inspection, cryptographic verification, and audit logging. The service must enforce role separation between security analysts and system administrators, maintain file system permissions (0700 for case directories), prevent database duplication of engine results, protect credentials, and provide clean resumption semantics.

## Decisions

1. **Framework and Persistence Strategy**:
   - **FastAPI**: Selected for native asynchronous request handling, OpenAPI generation, and dependency injection for security credentials.
   - **SQLite (`backend/database.py`)**: Utilized via standard library `sqlite3` with row factory for operational state tracking across four core tables:
     - `cases`: `(id TEXT PRIMARY KEY, status TEXT, pcap_sha256 TEXT, created_at INTEGER, engine_version TEXT)`
     - `analysis_runs`: `(case_id TEXT PRIMARY KEY, status TEXT, started_at INTEGER, finished_at INTEGER, error TEXT)`
     - `chain_txs`: `(case_id TEXT, step TEXT, nonce INTEGER, tx_hash TEXT, status TEXT, retries INTEGER, PRIMARY KEY (case_id, step))`
     - `audit_log`: `(id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, actor TEXT, action TEXT, case_id TEXT, detail TEXT)`
   - **Canonical Artifact Storage (`data/cases/<caseId>/`)**:
     - Case directories are provisioned with mode `0700` (`rwx------`) containing `pcap.bin` (`0600`) and canonical JSON outputs (`sessions.json`, `findings.json`, `host_scores.json`, `result.json`, `manifest.json`, `host_proofs.json`).
     - **Decoupling Rule**: Analysis findings, sessions, and host scores are read directly from canonical JSON files on disk during API queries (`/sessions`, `/findings`, `/hosts`) with pagination support (`limit`, `offset`), and are **never** stored as database rows or JSON blobs in SQLite.

2. **Role-Based Access Control (RBAC)**:
   - Configurable static API keys: `ANALYST_API_KEY` and `ADMIN_API_KEY`.
   - Injected via `X-API-Key` or `Authorization: Bearer <key>`.
   - **Analyst Endpoints** (`require_analyst`): Accept analyst key; strictly reject unauthenticated calls (401) and administrative keys (403 Forbidden).
   - **Administrative Endpoints** (`require_admin`): Accept admin key; strictly reject unauthenticated calls (401) and analyst keys (403 Forbidden).

3. **PCAP Ingestion & Stream Validation**:
   - Ingestion streams uploaded chunks while computing the SHA-256 digest on the fly.
   - Header magic verification supports standard microsecond (`0xa1b2c3d4`, `0xd4c3b2a1`), nanosecond (`0xa1b23c4d`, `0x4d3cb2a1`), and PCAP-NG (`0x0a0d0d0a`). Invalid magic numbers immediately abort with HTTP 400.
   - Enforces configurable maximum upload limit (`MAX_UPLOAD_SIZE`, default 100 MB). Over-limit streams abort with HTTP 413 without retaining partial files on disk.

4. **Engine Runner Abstraction**:
   - `backend/runner.py` executes forensic analysis synchronously or as an asynchronous FastAPI `BackgroundTask`.
   - Supports execution via isolated Docker container (`docker run --network none --read-only ...`) when the daemon is available, seamlessly falling back to local Python module execution (`python -m smscope analyze ...`).
   - Supports resumption from `failed` state if a process terminates prematurely.
   - Strict secret sanitization ensures `ORG_SECRET_HEX` and extracted cleartext passwords (e.g. `LabPass-123!`) never leak into audit records, error traces, or API responses (AGENT_RULES Rules 4 and 6).

5. **Cryptographic Verification & Prompt 6.2 Stubs**:
   - `POST /cases/{id}/verify` recomputes the SHA-256 hash of `pcap.bin` and verifies the computed Merkle root against `result.json`.
   - Chain-altering endpoints (`open`, `claim`, `finalize`, `record`, `anchor`, `resolve`) return HTTP 501 Not Implemented until the blockchain orchestration worker is integrated in Prompt 6.2.

## Consequences
- Clean separation of operational metadata in SQLite from immutable forensic evidence on disk.
- Complete isolation between administrative roles and analyst workflows.
- Fully compatible with both local testing environments and containerized cloud deployments.
