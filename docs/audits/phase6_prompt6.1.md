# Specification Compliance Audit: Phase 6, Prompt 6.1 (API Service)

## Scope
Audit of the SecureMailScope API Service implementation across:
- `backend/app.py`
- `backend/config.py`
- `backend/database.py`
- `backend/auth.py`
- `backend/storage.py`
- `backend/runner.py`
- `backend/tests/test_api.py`
against:
- `AGENT_RULES.md`
- `docs/ARCHITECTURE.md` Section 3
- `docs/PROMPT_LIBRARY.md` Phase 6, Prompt 6.1
- `docs/decisions/015-api-service-architecture.md`

---

### 1. Specification Discrepancies
None identified.
- **Case Ingestion (`POST /cases`)**:
  - Validates PCAP magic number bytes across microsecond, nanosecond, and PCAP-NG formats. Rejects non-PCAP uploads with HTTP 400.
  - Enforces configurable maximum size limit (`MAX_UPLOAD_SIZE`, default 100 MB). Rejects oversize uploads with HTTP 413 and safely unlinks incomplete files.
  - Computes streaming SHA-256 digest on the fly without loading entire captures into memory.
  - Provisions case directories (`data/cases/<caseId>/`) with mode `0700` (`rwx------`).
  - Records initial case status as `uploaded` in SQLite `cases` table and logs a `case_uploaded` audit entry.
- **Analysis Execution (`POST /cases/{id}/analyze`)**:
  - Supports synchronous and background execution modes.
  - Invokes containerized engine via Docker when available, seamlessly falling back to local Python CLI execution (`python -m smscope analyze`).
  - Updates `analysis_runs` with start/finish timestamps and errors.
  - Transitions case to `analyzed` upon success, or `failed` upon error.
  - Supports resumption from `failed` state if a process terminates prematurely.
- **Forensic Inspection Endpoints (`GET /cases/{id}/sessions`, `/findings`, `/hosts`)**:
  - Strictly reads and paginates (`limit`, `offset`) canonical JSON files on disk (`sessions.json`, `findings.json`, `host_scores.json`).
  - Adheres strictly to the architectural constraint that forensic outputs are never duplicated as database rows or JSON blobs in SQLite.
- **Cryptographic Verification (`POST /cases/{id}/verify`)**:
  - Re-reads `pcap.bin` to recompute and verify SHA-256 against stored database metadata.
  - Verifies stored Merkle root in `result.json` against canonical forensic findings and host scores.
- **Role-Based Access Control**:
  - Static API keys (`ANALYST_API_KEY`, `ADMIN_API_KEY`) enforced via FastAPI security dependencies.
  - Analysts are forbidden (HTTP 403) from administrative endpoints.
  - Administrators are forbidden (HTTP 403) from analyst endpoints.
  - Missing credentials return HTTP 401 Unauthorized.
- **Chain-Altering Stubs**:
  - Chain-changing endpoints (`open`, `claim`, `finalize`, `record`, `anchor`, `resolve`) return HTTP 501 Not Implemented until the worker is integrated in Prompt 6.2.

---

### 2. Missing Decisions
None. Architectural decisions for backend data persistence, role separation, runner abstraction, and storage isolation are documented in:
- [015-api-service-architecture.md](file:///c:/Users/gaura/OneDrive/Desktop/projects/blockchain-project/docs/decisions/015-api-service-architecture.md)

---

### 3. AGENT_RULES.md Violations
- **Rule 1 (Floating point arithmetic)**: None. Host scores and severity weights remain pure integers.
- **Rule 2 (Wall-clock time)**: None. Forensic analysis remains tied strictly to packet timestamps. API database tracking uses integer UNIX epochs.
- **Rule 3 (Unordered iteration in output)**: None. Canonical JSON readers and API response models retain strict deterministic ordering.
- **Rule 4 (Credential logging)**: None. Planted credentials (e.g., `labuser` and `LabPass-123!` in `S05.pcap`) are never logged in audit tables, error messages, or API responses. Verified by `test_planted_credentials_and_secrets_never_leaked`.
- **Rule 5 (Passive engine)**: None. Analysis engine runs fully offline without network egress (`--network none`).
- **Rule 6 (Organization secret)**: None. `ORG_SECRET_HEX` is explicitly redacted from all error messages, audit logs, and API payloads.
- **Rule 7 (Verification before claim)**: Respected. Verification endpoint validates canonical artifacts prior to on-chain claim submission.

---

### 4. Verification Summary
| Verification Suite | Target / Command | Result |
| :--- | :--- | :--- |
| Backend API Test Suite | `python -m pytest backend/tests` | **PASS** (13/13 tests pass in 3.40s) |
| Combined Engine & Backend Tests | `python -m pytest engine/tests backend/tests` | **PASS** (218/218 tests pass in 10.07s) |
| Forensic Precision & Recall | `python eval/compare_labels.py` | **PASS** (17/17 lab scenarios, 100% P & R) |
| Hardhat Smart Contracts | `npm test` in `contracts/` | **PASS** (90/90 tests pass in 4s) |
