# Audit: Phase 6 — Prompt 6.2 (Chain Gateway and API Service)

**Status: PASSED — 5/5 tests green**
**Date:** 2026-10-11

---

## Acceptance Checklist

| Requirement | Status | Evidence |
|---|---|---|
| ChainGateway owns all signing keys and nonce locks | PASS | _analyst_lock, _admin_lock per account |
| open_case / claim / advance / finalize / record_posture / anchor_report / resolve implemented | PASS | All ops in gateway.py |
| Idempotency: no duplicate txs on double-call | PASS | test_gateway_idempotence PASSED |
| Crash recovery: status=sent txs recovered without re-send | PASS | test_crash_recovery_before_receipt_stored PASSED |
| Revert detection: surfaces reason, never retried | PASS | test_revert_reported_and_not_retried PASSED |
| Event polling corrects DB from chain source of truth | PASS | test_event_listener_sync PASSED |
| Full flow: upload -> analyze -> open -> claim -> commit/reveal -> finalize -> record -> anchor | PASS | test_gateway_full_flow PASSED |
| chain_txs stored BEFORE waiting for receipt | PASS | _send_tx lines 291-292 |
| No wall-clock time, no floats, no credentials in logs | PASS | Code audit |
| REST endpoints wired | PASS | app.py |

---

## Bugs Fixed During Implementation

| Bug | Root Cause | Fix |
|---|---|---|
| isPostureRecorded ABIFunctionNotFound | PostureLedger exposes hasRecorded(caseId, hostId) | Renamed in gateway.py and test_gateway.py |
| contradicted ABIFunctionNotFound | CaseRegistry exposes isContradicted(caseId) | Renamed in gateway.py |
| getRecords ABIFunctionNotFound | PostureLedger has no bulk getter; use recordCount + recordAt(i) | Replaced in app.py |
| getRoundSnapshot ABIFunctionNotFound | ValidationQuorum exposes getValidatorSnapshot(caseId, round) | Renamed in gateway.py |
| getRevealedRoot ABIFunctionNotFound | ValidationQuorum exposes getValidatorRoot(caseId, round, addr) | Renamed in gateway.py |
| txHash prefix inconsistency | receipt.transactionHash.hex() lacks 0x; DB stored with 0x | Added 0x+ to all 8 receipt return sites |
| Revert test got 500 not 400 | InvalidStateError escaped to generic 500 handler | Open case first in test; add InvalidStateError to finalize 400 handler |

---

## Test Results

5 passed in 14.49s
- test_gateway_full_flow                    PASSED
- test_gateway_idempotence                  PASSED
- test_crash_recovery_before_receipt_stored PASSED
- test_revert_reported_and_not_retried      PASSED
- test_event_listener_sync                  PASSED
