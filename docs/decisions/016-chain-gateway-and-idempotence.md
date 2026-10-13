# Decision 016: Blockchain Gateway, Idempotence, and Event Synchronization

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` Sections 3.3 and 6, and Prompt 6.2 require a unified blockchain gateway (`backend/chain/gateway.py`) that acts as the sole custodian of private keys (`ANALYST_KEY` and `ADMIN_KEY`) and nonce sequences. The gateway must manage the complete on-chain lifecycle for forensic cases while strictly enforcing idempotency, crash resilience, transient retry with backoff, immediate halt on contract reverts, and event-driven log synchronization.

## Decisions

1. **Custody of Signing Keys and Nonces**:
   - `ANALYST_KEY` and `ADMIN_KEY` are read exclusively from environment configuration.
   - Dedicated `threading.Lock` per account (`_analyst_lock` and `_admin_lock`) protects against concurrent nonce desynchronization.
   - Nonces are retrieved with `pending` block tag under lock.

2. **Pre-Send Idempotency & Crash Recovery**:
   - **Pre-check**: Before constructing or broadcasting a transaction, the gateway checks both local `chain_txs` records and on-chain contract state (`caseState`, `reportHash`, `isPostureRecorded`). If the desired state transition or transaction has already occurred, the existing receipt or state is returned without broadcasting a duplicate transaction.
   - **Crash Recovery**: Transactions are persisted to `chain_txs` with `status="sent"`, `nonce`, and `tx_hash` **BEFORE** awaiting the transaction receipt. If a process crash or network partition occurs after broadcast, subsequent invocations first query `eth_getTransactionReceipt` for the recorded hash. Once mined, the record transitions to `confirmed` without issuing a second transaction.

3. **RPC Error Handling & Revert Isolation**:
   - **Transient Failures**: Transient network drops, timeouts, or rate limits are retried with exponential backoff up to `max_retries` (default 3).
   - **Contract Reverts**: Contract logic errors (e.g. `InvalidCaseState`, `NotCaseAnalyst`, `AccessControlUnauthorizedAccount`) are simulated during gas estimation or detected via status 0 receipts. Reverts are **never** retried; they are marked `status="reverted"` in `chain_txs` and surfaced as `TransactionRevertedError` with the extracted revert reason.

4. **Chain as Canonical Source of Truth**:
   - `poll_events` queries contract logs from `last_processed_block + 1` up to the current block header for `CaseRegistry`, `ValidationQuorum`, and `PostureLedger`.
   - Any divergence between database case status and verified on-chain state is automatically reconciled in favor of the blockchain, with audit trail entries recorded.

5. **API Wiring & Verification**:
   - Replaced Phase 6.1 HTTP 501 stubs with live endpoints:
     - `POST /cases/{id}/open` (Analyst)
     - `POST /cases/{id}/claim` (Analyst)
     - `POST /cases/{id}/finalize` (Analyst)
     - `POST /cases/{id}/record` (Analyst)
     - `POST /cases/{id}/anchor` (Analyst)
     - `POST /cases/{id}/resolve` (Admin only)
   - `GET /cases/{id}/chain` returns active on-chain lifecycle state, analyst address, claimed and finalized roots, validator commitment and reveal details, and custody transaction hashes.

## Consequences
- Guaranteed zero duplicate transactions even under crash and re-execution scenarios.
- Strict protection against infinite loops on transaction reverts.
- Seamless decoupling between analyst REST workflows and EVM state machines.
