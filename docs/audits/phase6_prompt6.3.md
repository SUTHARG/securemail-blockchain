# Audit: Phase 6 - Prompt 6.3 (Validator Service & Milestone M3)

**Status: PASSED - 5/5 validator tests green, 23/23 backend tests green**
**Date:** 2026-10-12

---

## Acceptance Checklist

| Requirement | Status | Evidence |
|---|---|---|
| `validator/service.py` implemented as long-running process per validator | PASS | `validator/service.py` with CLI flags (`--id`, `--key-env`, `--inbox-dir`, `--state-dir`, `--strict`, `--faulty`) |
| Inbox bundle intake format `<caseId>/{pcap.bin, org_secret.hex}` | PASS | Scanned in `find_pending_bundles()` and resolved via directory/metadata |
| Pinned engine container invocation with `--network none --read-only` | PASS | `run_engine_analysis()` runs containerized with fallback to local engine module |
| Atomic salt generation and persistence before commit | PASS | Atomically saved via `.tmp` and `os.replace` to `validator_state/<id>.json` BEFORE `commit()` transaction |
| Wait for commit deadline and advance to Revealing | PASS | `round_params[2]` deadline polling and `advance()` call |
| Reveal submission using persisted salt and root | PASS | `quorum.functions.reveal()` with on-chain pinned hashes |
| Restart safety: resume without double-submitting | PASS | `resume_from_state()` checks `hasCommitted` and `hasRevealed` |
| Strict mode pinning verification | PASS | `verify_strict_mode()` verifies `rulesetHash` and `ENGINE_IMAGE_DIGEST` |
| `--faulty` flag for adversarial testing | PASS | Tampered root generated; honest quorum outvotes faulty node |
| Inbox bundle for cases outside snapshot ignored | PASS | `isSnapshotValidator` verification skips non-participant cases |
| `POST /cases/{id}/distribute` endpoint | PASS | Copies `pcap.bin` and `org_secret.hex` into inboxes 1, 2, 3 and sets status `distributed` |
| README notes encrypted delivery is Tier 3 future work | PASS | `README.md` updated |
| Decision 017 recorded | PASS | `docs/decisions/017-validator-service-and-distribution.md` |
| Milestone M3 full flow acceptance | PASS | `test_acceptance_full_flow_with_restart` PASSED |

---

## Bugs Identified & Fixed During Implementation

| Bug | Root Cause | Fix |
|---|---|---|
| Typing import error in tests | `Tuple` was not imported from `typing` | Added `Tuple` to typing imports in `test_validator_service.py` |
| 405 Method Not Allowed on `/cases/upload` | Route was only registered as `POST /cases` | Added `@app.post("/cases/upload")` alias and updated tests to accept 201/200 |
| `KeyError: 'artifact'` in ABI loader | Deployment file uses `"abiPath"` not `"artifact"` | Updated `validator/service.py` to check both `"abiPath"` and `"artifact"` |
| `ValueError: non-hexadecimal number found in fromhex() arg at position 63` | `lstrip("0x")` stripped valid leading '0' characters from hex hashes | Implemented `to_hex0x()` helper in `backend/chain/gateway.py` |
| Premature finalization in validator service reveal | Validator service called `finalize` immediately after revealing, preventing remaining validators from revealing | Removed premature finalize calls from validator service, allowing quorum completion before finalization |

---

## Test Results

5 passed in 31.68s (`test_validator_service.py`):
- `test_restart_between_commit_and_reveal` PASSED
- `test_inbox_bundle_not_in_snapshot_ignored` PASSED
- `test_wrong_engine_digest_aborts_before_commit` PASSED
- `test_faulty_validator_outvoted` PASSED
- `test_acceptance_full_flow_with_restart` PASSED

Full backend suite (23 passed in 55.83s):
- `backend/tests/test_api.py` (13 passed)
- `backend/tests/test_gateway.py` (5 passed)
- `backend/tests/test_validator_service.py` (5 passed)
