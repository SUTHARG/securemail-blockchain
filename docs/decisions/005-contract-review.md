# Decision 005: Adversarial Smart Contract Review and Attack Vector Verification

## Status
Accepted

## Context
Prompt 2.4 mandates an independent adversarial review of the complete smart contract suite (`Roles.sol`, `CaseRegistry.sol`, `ValidationQuorum.sol`, `MerkleVerifier.sol`, `PostureLedger.sol`) against 11 primary attacker vectors before proceeding to Phase 3 engine development.

---

## Adversarial Findings and Conclusions

### Vector (1): Finalize without $k$ matching reveals
- **Attacker Objective**: Force case finalization with fewer than $k = \lfloor N/2 \rfloor + 1$ matching reveals on a root.
- **Contract Defense**:
  - `ValidationQuorum.sol:288-307`: `finalize()` checks `revealCounts[claimedRoot] >= quorum`. If below quorum, early finalization reverts with `OutcomeNotReady` while the reveal window is active.
  - After the reveal deadline, cases with insufficient agreement transition to `Expired` (if `totalReveals < quorum`) or `Disputed` (if `totalReveals >= quorum`).
  - `ValidationQuorum.sol:333-336`: Administrative `resolve(AttestMajority, root)` strictly verifies `revealCounts[root] >= quorum`, preventing admin bypass. `AttestMajority` is prohibited from `Expired`.
- **Test Proof**: `AdversarialReview.test.ts:74-100`, `ValidationQuorum.test.ts:209-233, 742-747`.
- **Conclusion**: **PREVENTED**.

---

### Vector (2): Reveal on behalf of a validator you do not control
- **Attacker Objective**: Submit a reveal on behalf of another validator without possessing their private key.
- **Contract Defense**:
  - `ValidationQuorum.sol:247-266`: `reveal()` does not accept a validator address parameter. Validator identity is derived strictly from `msg.sender`.
  - The contract looks up `r.commitments[msg.sender]` and checks `keccak256(abi.encode(caseId, msg.sender, resultRoot, salt))`.
  - Callers not in the snapshot revert with `NotSnapshotValidator`.
- **Test Proof**: `AdversarialReview.test.ts:102-120`, `ValidationQuorum.test.ts:360-377`.
- **Conclusion**: **PREVENTED**.

---

### Vector (3): Copy another validator's root
- **Attacker Objective**: Observe an honest validator's root during the commit phase and submit the same root.
- **Contract Defense**:
  - `ValidationQuorum.sol:183-206`: Commitments are blinded with an unrevealed 256-bit salt: `keccak256(abi.encode(caseId, validator, resultRoot, salt))`.
  - Copying the raw commitment hash $C$ from the mempool and submitting it under a different validator address fails at reveal time, because `abi.encode` binds `msg.sender`.
- **Test Proof**: `AdversarialReview.test.ts:122-143`, `ValidationQuorum.test.ts:453-467`.
- **Conclusion**: **PREVENTED**.

---

### Vector (4): Change state out of order
- **Attacker Objective**: Bypass the state machine (e.g., skip commit window, advance without waiting, reopen finalized cases).
- **Contract Defense**:
  - Mutators in `CaseRegistry.sol` require `onlyRole(QUORUM_ROLE)`.
  - Every external mutator in `ValidationQuorum.sol` asserts the exact requisite state:
    - `submitClaim`: requires `State.Opened`.
    - `commit`: requires `State.Committing`.
    - `advance`: requires `State.Committing` and `block.timestamp >= commitDeadline`.
    - `reveal`: requires `State.Revealing` and `block.timestamp < revealDeadline`.
    - `finalize`: requires `State.Revealing`.
    - `resolve`: requires `State.Disputed` or `State.Expired`.
- **Test Proof**: `AdversarialReview.test.ts:145-181`, `ValidationQuorum.test.ts:631-645, 856-915`.
- **Conclusion**: **PREVENTED**.

---

### Vector (5): Record a posture for a case that is not Finalized
- **Attacker Objective**: Submit host risk posture records for cases in `Opened`, `Committing`, `Revealing`, `Disputed`, `Expired`, or `Rejected` states.
- **Contract Defense**:
  - `PostureLedger.sol:121-124`: `_validateCase()` checks `caseRegistry.caseState(caseId) == CaseRegistry.State.Finalized`.
  - Any attempt to record for a non-finalized case reverts with `CaseNotFinalized(caseId, state)`.
- **Test Proof**: `AdversarialReview.test.ts:183-205`, `PostureLedger.test.ts:258-269`.
- **Conclusion**: **PREVENTED**.

---

### Vector (6): Record the same host twice for one case
- **Attacker Objective**: Submit duplicate posture records for a single `(caseId, hostId)` pair.
- **Contract Defense**:
  - `PostureLedger.sol:80, 107`: Tracks `_recorded[caseId][hostId]`.
  - Re-submitting for an already-recorded `(caseId, hostId)` pair immediately reverts with `PostureAlreadyRecorded(caseId, hostId)`.
- **Test Proof**: `AdversarialReview.test.ts:207-236`, `PostureLedger.test.ts:249-256`.
- **Conclusion**: **PREVENTED**.

---

### Vector (7): Replay a commit from another case or another round
- **Attacker Objective**: Replay a commitment across different cases or consensus rounds.
- **Contract Defense**:
  - **Cross-case replay**: `caseId` is hashed inside `abi.encode(...)`. Attempting to reveal against a different `caseId` reverts with `CommitmentMismatch`.
  - **Cross-round replay**: Round storage is partitioned per `(caseId, round)`. A commitment from Round 1 cannot be revealed in Round 2 without an explicit Round 2 `commit()` call (`NoPriorCommitment`).
  - **Operational Guarantee**: Off-chain validator nodes sample fresh random 32-byte salts for every round (Prompt 3.2), ensuring cryptographic distinctness.
- **Test Proof**: `AdversarialReview.test.ts:238-261`, `ValidationQuorum.test.ts:469-487, 502-530`.
- **Conclusion**: **PREVENTED**.

---

### Vector (8): Change the pinned engine after a claim to change what is accepted
- **Attacker Objective**: Register a new engine image globally after claim submission to alter the accepted consensus verification pair.
- **Contract Defense**:
  - `ValidationQuorum.sol:170`, `CaseRegistry.sol:247-248`: The engine image digest and ruleset hash are pinned directly to the case at claim time.
  - `ValidationQuorum.sol:260-261`: `reveal()` strictly checks against `caseRegistry.engineHash(caseId)` and `caseRegistry.rulesetHash(caseId)`. Global updates to `activeEngine` do not modify existing cases.
- **Test Proof**: `AdversarialReview.test.ts:263-288`, `ValidationQuorum.test.ts:650-709`.
- **Conclusion**: **PREVENTED**.

---

### Vector (9): Leave a case permanently stuck
- **Attacker Objective**: Lock a case permanently in `Committing` or `Revealing` state.
- **Contract Defense**:
  - `advance()` is permissionless: anyone can advance to `Revealing` once `block.timestamp >= commitDeadline`.
  - `finalize()` is permissionless: anyone can trigger early finalization upon quorum agreement or transition to `Expired`/`Disputed` once `block.timestamp > revealDeadline`.
  - `resolve()` allows the administrator to restart validation via `NewRound` or close via `Reject`.
- **Test Proof**: `AdversarialReview.test.ts:290-311`, `ValidationQuorum.test.ts:80-117, 209-265`.
- **Conclusion**: **PREVENTED**.

---

### Vector (10): Overflow or truncation of score or counters
- **Attacker Objective**: Overflow counters or submit unconstrained scores to corrupt on-chain state.
- **Contract Defense**:
  - Solidity 0.8.24 has built-in checked arithmetic for all increments and math.
  - `score` in `PostureLedger.sol:78` is restricted: `if (score > 100) revert InvalidScore(score);`.
  - Quorum threshold calculation `n / 2 + 1` is safe integer arithmetic for $N \ge 3$.
- **Test Proof**: `AdversarialReview.test.ts:313-339`, `PostureLedger.test.ts:219-224`.
- **Conclusion**: **PREVENTED**.

---

### Vector (11): Reentrancy through any external call
- **Attacker Objective**: Reenter contract functions during external calls to hijack control flow.
- **Contract Defense**:
  - Contracts do not transfer ETH or tokens.
  - External calls from `ValidationQuorum` and `PostureLedger` are strictly bounded to the trusted immutable `CaseRegistry`.
  - `CaseRegistry` contains no untrusted call paths or external fallbacks.
- **Test Proof**: `AdversarialReview.test.ts:341-346`.
- **Conclusion**: **PREVENTED**.

---

## Summary of Audit Proofs

| Attack Vector | Vulnerability Exists? | Primary Defense | Verification Test |
| :--- | :--- | :--- | :--- |
| (1) Finalize without $k$ reveals | No | Quorum threshold checks | `AdversarialReview.test.ts:74` |
| (2) Reveal on behalf of others | No | Derived `msg.sender` validation | `AdversarialReview.test.ts:102` |
| (3) Copy another validator's root | No | Blinded salt + sender binding | `AdversarialReview.test.ts:122` |
| (4) Out-of-order state transitions | No | Rigorous state checks + `QUORUM_ROLE` | `AdversarialReview.test.ts:145` |
| (5) Record posture on unfinalized case | No | `_validateCase()` status check | `AdversarialReview.test.ts:183` |
| (6) Record same host twice | No | Double-record mapping guard | `AdversarialReview.test.ts:207` |
| (7) Commit replay | No | `caseId` binding + round storage | `AdversarialReview.test.ts:238` |
| (8) Pinned engine tampering | No | Case-pinned hashes immutable | `AdversarialReview.test.ts:263` |
| (9) Permanently stuck cases | No | Permissionless `advance()`/`finalize()` | `AdversarialReview.test.ts:290` |
| (10) Integer overflow / score manipulation | No | Checked arithmetic + `score <= 100` | `AdversarialReview.test.ts:313` |
| (11) Reentrancy hijacking | No | No untrusted external calls | `AdversarialReview.test.ts:341` |

## Acceptance Criteria
- Every item has an explicit conclusion and implementation proof.
- All 90 smart contract tests and 21 Python engine tests pass.
- No existing tests were weakened.
