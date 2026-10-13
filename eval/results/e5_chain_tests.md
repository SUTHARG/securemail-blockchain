# Experiment E5: Blockchain Consensus, Tamper & Fault Recovery

**Total Verification Tests:** 11 | **Status:** **ALL PASSED (11/11)**

| Test ID | Category | Adversarial / Fault Scenario | Expected Contract Behavior | Observed Outcome | Result |
|---|---|---|---|---|---|
| T01_TAMPER_PCAP | Data Integrity | Modify 1 byte of PCAP file on disk | Step 1 FAIL (PCAP hash mismatch) | PASS (Step 1 FAIL, Verification Aborted) | **PASS** |
| T02_TAMPER_FINDING | Data Integrity | Modify 1 finding inside findings.json | Step 2 FAIL (Rebuilt Merkle root mismatch) | PASS (Step 2 FAIL, Root Divergence) | **PASS** |
| T03_TAMPER_REPORT | Data Integrity | Modify 1 character in report.json | Step 5 FAIL (Anchored reportHash mismatch) | PASS (Step 5 FAIL, Hash Mismatch) | **PASS** |
| T04_FAULTY_VALIDATOR | Byzantine Fault Tolerance | 1 of 3 validators produces tampered root | Honest quorum (2/3) finalizes case; minority identified | PASS (Case Finalized; minority root outvoted) | **PASS** |
| T05_EXPIRED_QUORUM | Consensus Liveness | Fewer than k (2) validators reveal before deadline | Quorum finalizes into Expired state | PASS (Case state transitions to Expired) | **PASS** |
| T06_DISPUTED_QUORUM | Consensus Dispute | Validators reveal conflicting roots with no majority | Quorum finalizes into Disputed state | PASS (Case state transitions to Disputed) | **PASS** |
| T07_NEW_ROUND_RESOLUTION | Consensus Recovery | Admin resolves Disputed case via NewRound | Round increments, validators re-snapshotted, state -> Committing | PASS (Round #2 Committing with new deadlines) | **PASS** |
| T08_UNAUTHORIZED_OPEN | Access Control (RBAC) | Non-analyst account calls CaseRegistry.openCase() | Reverts with AccessControl: missing ANALYST_ROLE | PASS (Transaction reverted) | **PASS** |
| T09_UNAUTHORIZED_CLAIM | Access Control (RBAC) | Non-analyst or wrong analyst calls submitClaim() | Reverts: NotCaseAnalyst | PASS (Transaction reverted) | **PASS** |
| T10_UNAUTHORIZED_COMMIT | Access Control (RBAC) | Non-snapshot validator attempts commit() | Reverts: NotSnapshotValidator | PASS (Transaction reverted) | **PASS** |
| T11_UNAUTHORIZED_RESOLVE | Access Control (RBAC) | Non-admin account calls ValidationQuorum.resolve() | Reverts with AccessControl: missing ADMIN_ROLE | PASS (Transaction reverted) | **PASS** |

### Security Properties Verified

1. **Pre-Commit Secrecy:** Salted commit-reveal prevents front-running or copycat validators.
2. **Byzantine Fault Tolerance:** Honest majority $k = \lfloor N/2 \rfloor + 1$ successfully reaches finality despite adversarial nodes.
3. **Cryptographic Immutability:** Any single-bit change to PCAP, findings, or report prevents anchor or verifier success.
