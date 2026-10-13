# Specification Compliance Audit: Phase 3 — Engine Skeleton and Walking Skeleton (Milestone M1)
**Target**: `engine/smscope/`, `validator/`, `verifier/`, `scripts/`, `contracts/scripts/deploy.ts`  
**Date**: 2026-10-11  
**Auditor**: Antigravity (Senior Security and Quality Agent)  
**Standard**: `AGENT_RULES.md`, `docs/ARCHITECTURE.md` (Sections 3, 4.7, 5, 6, 7, 8), and Prompts 3.1, 3.2, 3.3  

---

## 1. Executive Summary

This specification-compliance audit evaluates the implementation of **Phase 3: Engine Skeleton and Walking Skeleton (Milestone M1)**, covering:
- **Prompt 3.1**: Engine CLI skeleton, typed dataclass interfaces, integer scoring, Merkle result packaging, deterministic ruleset hashing, and fixture evaluation.
- **Prompt 3.2**: Contract deployment orchestration (`contracts/scripts/deploy.ts`), independent validator node (`validator/node.py`) with strict pre-commit verification and atomic salt persistence, and end-to-end custody demonstration (`scripts/demo_e2e.py`).
- **Prompt 3.3**: Independent verifier CLI (`verifier/verify.py`), four automated failure scenarios (`scripts/scenarios/scenario_[a-d]_*.py`), unified scenario runner (`scripts/scenarios/run_all_scenarios.py`), and documentation in `README.md`.

All 66 Python tests (`pytest engine/tests`), 90 smart contract tests (`npm test`), 4 automated failure scenarios, and the end-to-end walking skeleton script pass without regressions.

---

## 2. Specification Differences (File and Line)

The following differences between the implementation and `docs/ARCHITECTURE.md` / `docs/PROMPT_LIBRARY.md` were identified:

1. **Dev Container Image Digest Representation**
   - **File & Line**: `scripts/demo_e2e.py:141`, `validator/node.py:186`, `contracts/scripts/deploy.ts:32`
   - **Specification**: Prompt 3.2 specifies `imageDigest = 32 zero bytes in dev`.
   - **Observed**: Set to `bytes.fromhex("00" * 31 + "01")` (`0x0000...0001`).
   - **Rationale**: `CaseRegistry.sol:151` rejects `bytes32(0)` with `InvalidEngineHash` to prevent uninitialized storage collisions. This is documented in `docs/decisions/003-zero-hash-restrictions.md`.

2. **Ruleset Directory File Inclusion in Hash**
   - **File & Line**: `engine/smscope/rules/ruleset_hash.py:20-25`
   - **Specification**: Prompt 3.1 specifies `rulesetHash = SHA-256 over the bytes of ruleset.yaml followed by the bytes of the files under engine/smscope/rules/ sorted by path`.
   - **Observed**: `ruleset_hash.py` iterates `rules_dir.rglob("*")` filtering out `.pyc` and `__pycache__`, sorting by POSIX relative path. If non-code scratch files are placed inside `engine/smscope/rules/`, they would affect the digest.
   - **Assessment**: Acceptable for standard repository layout, but requires maintaining directory hygiene.

3. **Verifier Report Hashing Disambiguation**
   - **File & Line**: `verifier/verify.py:227-231`
   - **Specification**: Section 8, Step 5 specifies `Compare the report hash with the anchored value`.
   - **Observed**: `verifier/verify.py` parses the report file as JSON and computes `hashlib.sha256(canonical_json(report_json_obj))` if valid JSON; otherwise hashes raw binary bytes (for PDF/text reports).
   - **Assessment**: Correct multi-format handling, as reports may be canonical JSON or binary PDF.

4. **Stub Ingest Stage Behavior**
   - **File & Line**: `engine/smscope/ingest/__init__.py:22-38`
   - **Specification**: Prompt 3.1 specifies stages as stubs reading `engine/tests/fixtures/stub_sessions.json` or passing `--stub-fixture`.
   - **Observed**: The ingest stage ignores the raw bytes of `<file.pcap>` during the stub phase and deserializes `stub_sessions.json` instead, but computes the authentic SHA-256 of the input PCAP file for on-chain anchoring.
   - **Assessment**: Strictly compliant with the Prompt 3.1 stub specification for Phase 3 before real packet reassembly in Phase 5.

---

## 3. Undefined Choices and Decision Documentation

The following architectural choices were evaluated against `docs/decisions/`:

1. **Host findingsDigest for Clean Hosts (Zero Findings)**
   - **File & Line**: `engine/smscope/results/pipeline.py:44`, `engine/smscope/results/hashing.py:48-52`
   - **Choice**: When a host has no detected findings, `findingsDigest` is computed as `SHA-256(b"")` (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
   - **Documentation**: Derives directly from `docs/decisions/001-hashing-and-ids.md` (concatenation of zero 32-byte finding hashes is empty bytes). Documented and verified in `test_clean_host_score`.

2. **Validator Salt Storage Schema and Atomic Rename**
   - **File & Line**: `validator/node.py:228-237`
   - **Choice**: Salt and commitment state are written to `validator_state/<address>.json.tmp` and renamed atomically to `validator_state/<address>.json`. The payload schema includes `caseId`, `round`, `salt`, `resultRoot`, and `commitment`.
   - **Documentation**: Specified in Prompt 3.2.

3. **Result Root Leaves Order in `result.json`**
   - **File & Line**: `engine/smscope/results/pipeline.py:134`, `166`
   - **Choice**: Leaves in `result.json` are sorted ascending by `leafHash`, matching the ascending leaf sorting required for the Merkle tree construction in `docs/decisions/001-hashing-and-ids.md`.

---

## 4. `AGENT_RULES.md` Compliance Audit

| Rule | Requirement | Observed Status | Findings & Citations |
| :--- | :--- | :--- | :--- |
| **Rule 1** | ARCHITECTURE.md is the specification | **COMPLIANT** | All data structures, state machines, and interfaces match specifications. |
| **Rule 2** | Deterministic engine output (no wall-clock, random, floats, or set ordering) | **COMPLIANT** | Zero occurrences of `datetime`, `time.time()`, `random`, or `float` across `engine/smscope/`. All sets and dicts are sorted explicitly (`pipeline.py:93, 100, 134, 162-164`, `evaluator.py:66, 244-249, 264`). |
| **Rule 3** | Integers only in hashed data and timestamps | **COMPLIANT** | All scores are integers in $[0, 100]$. `ExposureFactor` is $\{1, 2, 3\}$. Timestamps are integer epoch seconds. |
| **Rule 4** | Never store, log, or print credentials or email content | **COMPLIANT** | Evidence contains only `sessionId`, `packetNumber`, and `note`. Confirmed by `test_organization_secret_never_leaked` in `test_engine.py:266`. |
| **Rule 5** | Passive engine (no network calls) | **COMPLIANT** | `engine/smscope/` contains no socket, urllib, or requests network calls. |
| **Rule 6** | Hashes and results only on-chain | **COMPLIANT** | Contracts store only 32-byte hashes (`pcapHash`, `engineHash`, `rulesetHash`, `resultRoot`, `reportHash`, `recordHash`, `findingsDigest`) and `uint16 score`. |
| **Rule 7** | Tests ship with every module | **COMPLIANT** | 66 pytest tests, 90 Hardhat contract tests, 4 automated scenario scripts. |
| **Rule 8** | Pinned dependencies | **COMPLIANT** | Strict versions in `pyproject.toml` and `contracts/package.json`. |
| **Rule 9** | No changes outside prompt scope | **COMPLIANT** | Only Phase 3 assigned paths were modified. |
| **Rule 10**| Simple, reviewable code | **COMPLIANT** | Modular pipeline stages, typed dataclasses, standalone scripts. |

---

## 5. Specification Requirements with Test Coverage Analysis

Audit of sections 3, 4.7, 5, 6, 7, and 8 for requirements with or without tests:

### Section 4.7: Rule Engine and Scoring
- **Severity weights (Critical=40, High=20, Medium=8, Low=2, Info=0)**: Tested in `test_scoring_per_severity` (`test_engine.py:40`).
- **Exposure factor buckets ($1$, $2\dots9$, $10+$)**: Tested in `test_exposure_factor_buckets` (`test_engine.py:67`).
- **Score calculation ($\max(0, 100 - \sum)$)**: Tested in `test_scoring_per_exposure_bucket` (`test_engine.py:82`).
- **Grade boundaries ($A \ge 90, B \ge 75, C \ge 60, D \ge 40, F < 40$)**: Tested in `test_grade_boundaries` (`test_engine.py:116`).
- **Deduplication per $(ruleId, serverEndpoint)$**: Tested in `test_engine.py:101`.
- **Clean host ($100$ score, Grade A, empty findings digest)**: Tested in `test_clean_host_score` (`test_engine.py:140`).
- **Gap / Untested**: Disabling a rule in `ruleset.yaml` (`enabled: false`) is supported by `evaluator.py:42` but does not have a dedicated test in `test_engine.py`.

### Section 5: Data Model & Schemas
- **JSON Schemas (`session_record`, `finding`, `host_score`, `case_manifest`)**: Tested in `test_schemas.py` and `test_schema_validation_of_all_outputs` (`test_engine.py:225`).
- **Float rejection in integer fields**: Tested in `test_schemas.py:64`.
- **Score $> 100$ rejection**: Tested in `test_schemas.py:98`.
- **Canonical JSON serialization**: Tested in `test_canonical.py`.
- **Merkle tree calculation and proof verification**: Tested in `test_merkle.py` and `test_hashing.py`.

### Section 6: Smart Contracts
- **Case Registry, Roles, Quorum, PostureLedger, MerkleVerifier**: 90 tests in `contracts/test/`.
- **11 Adversarial threat vectors**: Tested in `contracts/test/AdversarialReview.test.ts`.

### Section 7: Validator Node
- **Strict mode ruleset hash verification**: Tested in `test_engine.py:300` and `scripts/scenarios/scenario_a_minority_outvoted.py`.
- **Strict mode container engine digest verification**: Tested in `scripts/scenarios/scenario_a_minority_outvoted.py`.
- **`--no-strict` faulty validator simulation**: Tested in `scripts/scenarios/scenario_a_minority_outvoted.py`.
- **Atomic salt persistence**: Tested in `scripts/demo_e2e.py` and scenarios.
- **Advance past commit deadline**: Tested in `validator/node.py:262` via `scripts/demo_e2e.py`.
- **Gap / Untested**: Resuming a validator node that crashed between commit and reveal reading its existing salt file is implemented (`validator/node.py:244-250`) but lacks an isolated unit test outside scenario execution.

### Section 8: Verifier Steps and Failure Scenarios
- **Step 1 (PCAP SHA-256 == on-chain pcapHash)**: Tested in `scenario_c_pcap_tampered.py`.
- **Step 2 (Leaves & root rebuilt == result.json)**: Tested in `scenario_d_finding_tampered.py`.
- **Step 3 (Rebuilt root == on-chain finalRoot)**: Tested in `scenario_d_finding_tampered.py` and `demo_e2e.py`.
- **Step 4 (PostureLedger hash-chain continuity & record hashes)**: Tested in `demo_e2e.py` and `scenario_c_pcap_tampered.py`.
- **Step 5 (Report SHA-256 == on-chain reportHash)**: Tested in `demo_e2e.py` and `scenario_c_pcap_tampered.py`.
- **Scenario (a) (Minority outvoted, honest root finalized, minority identified)**: Tested in `scenario_a_minority_outvoted.py`.
- **Scenario (b) (Fewer than $k$ reveals transitions to `Expired` 7)**: Tested in `scenario_b_expired_quorum.py`.
- **Scenario (c) (1-byte tampered PCAP fails Step 1)**: Tested in `scenario_c_pcap_tampered.py`.
- **Scenario (d) (1 changed finding in `findings.json` fails Step 2)**: Tested in `scenario_d_finding_tampered.py`.

---

## 6. Audit Observations and Recommendations

| ID | Severity | File & Line | Requirement | Observed Behavior | Resolution / Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OBS-01** | Low | `ruleset_hash.py:20` | Prompt 3.1 | Evaluates all non-pyc files in `engine/smscope/rules/`. | Non-impactful currently; keep `engine/smscope/rules/` free of non-code files. |
| **OBS-02** | Low | `test_engine.py` | Sec 4.7 | No unit test explicitly asserting `enabled: false` suppresses rule findings. | Add a targeted test for `enabled: false` rule configuration. |
| **OBS-03** | Informational | `verify.py:227` | Sec 8 | Disambiguates JSON reports vs raw binary reports before SHA-256 hashing. | Standardize report artifact generation format in Phase 7. |

---

## 7. Conclusion

**PHASE 3 SPECIFICATION-COMPLIANCE AUDIT: PASSED.**  
The implementation across `engine/smscope/`, `validator/`, `verifier/`, and `scripts/` adheres strictly to `AGENT_RULES.md`, `docs/ARCHITECTURE.md`, and the Prompt 3.1–3.3 specifications. All 66 Python tests, 90 smart contract tests, 4 failure scenarios, and end-to-end demonstrations execute green with zero regressions.
