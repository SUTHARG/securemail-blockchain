# Decision 004: Validation Quorum Precedence, Lifecycle Boundaries, and Event Specifications

## Status
Accepted

## Context
When coordinating validator consensus in `ValidationQuorum.sol` using a commit-reveal scheme, several operational rules must be unambiguously defined:
1. Precedence between `Expired` and `Disputed` when the reveal window elapses without consensus.
2. Exact deadline boundary condition semantics (`<`, `<=`, `>=`, `>`).
3. Consensus isolation across rounds and immutability across global engine upgrades.
4. Administrative dispute and expiration resolution paths.
5. Exact event parameters and event log design for off-chain auditors.

## Decision

### 1. Quorum Calculation
- Quorum is calculated using integer arithmetic: $k = \lfloor N / 2 \rfloor + 1$.
- At least 3 registered validators ($N \ge 3$) are required to submit a claim or initiate a new validation round.

### 2. Early Finalization vs. Window Expiration Precedence
- **Condition A (Claim Agreement)**: As soon as $k$ reveals match `claimedRoot`, the case transitions to `Finalized` immediately without requiring the reveal window to elapse.
- **Condition B (Window Elapsed Boundary)**: If Condition A is not met, finalization requires that the reveal window has strictly closed: `block.timestamp > revealDeadline`. Calls to `finalize()` while `block.timestamp <= revealDeadline` revert with `OutcomeNotReady`.
- **Condition C (Participation Evaluation & Expired Precedence)**:
  - If `totalReveals < k`, the case transitions to `Expired`.
  - If `totalReveals >= k`, the case transitions to `Disputed`.
  - `Expired` strictly takes precedence over `Disputed`. A case cannot be disputed unless a qualifying quorum of validators ($k$) participated. Failure of liveness is treated as an expiration, not a forensic divergence.

### 3. Exact Deadline Boundary Conditions
- **Commit Phase**: Valid commitments require `block.timestamp < commitDeadline`. Submissions at or after `commitDeadline` (`block.timestamp >= commitDeadline`) revert with `CommitDeadlinePassed`.
- **Advance Transition**: Transition from `Committing` to `Revealing` requires `block.timestamp >= commitDeadline`. Calling `advance()` earlier reverts with `CommitWindowActive`.
- **Reveal Phase**: Valid reveals require `block.timestamp < revealDeadline`. Submissions at or after `revealDeadline` (`block.timestamp >= revealDeadline`) revert with `RevealDeadlinePassed`.
- **Evaluation Phase**: Outcome evaluation (Expired vs. Disputed) requires `block.timestamp > revealDeadline`.

### 4. Resolution Actions and Administrative Boundaries
- Defined resolution actions:
  - `AttestMajority`: Attests an alternative or consensus root that attained $\ge k$ matching reveals in the disputed round. Sets `contradicted = (root != claimedRoot)`. Prohibited from `Expired` state.
  - `NewRound`: Increments case round in `CaseRegistry`, takes a fresh validator snapshot, resets round state, recalculates $N$ and $k$, sets fresh deadlines, and transitions case to `Committing`. Allowed from both `Disputed` and `Expired`.
  - `Reject`: Transitions case state to `Rejected`. Allowed from both `Disputed` and `Expired`.
- Resolutions cannot be applied to `Finalized` or `Rejected` cases.

### 5. Engine and Ruleset Pinning
- Pinned container image digest and ruleset hash are captured in `CaseRegistry` at claim time.
- Validator reveals are validated strictly against the pinned hashes stored in the case (`caseRegistry.engineHash(caseId)` and `caseRegistry.rulesetHash(caseId)`), ensuring active engine upgrades do not affect in-flight verification rounds.

### 6. Event Specifications
The custody event log for validation quorum consists of:
- `ClaimSubmitted(bytes32 indexed caseId, address indexed analyst, bytes32 claimedRoot, bytes32 engineHash, bytes32 rulesetHash)`
- `CommitSubmitted(bytes32 indexed caseId, address indexed validator, bytes32 commitment, uint32 round)`
- `RevealSubmitted(bytes32 indexed caseId, address indexed validator, bytes32 resultRoot, uint32 round)`
- `CaseFinalized(bytes32 indexed caseId, bytes32 finalRoot, bool contradicted)`
- `CaseDisputed(bytes32 indexed caseId, uint32 round)`
- `CaseExpired(bytes32 indexed caseId, uint32 round)`
- `CaseResolved(bytes32 indexed caseId, ResolutionAction action, bytes32 root)`
- `WindowsUpdated(uint64 commitWindow, uint64 revealWindow)`

## Consequences
- Guarantees deterministic, game-theoretically sound validator coordination.
- Eliminates ambiguity at window boundaries.
- Prevents rogue validator sets or engine modifications from invalidating active consensus cases.

## References
- `docs/ARCHITECTURE.md` sections 6.3, 6.4, 6.7, 6.8, 14.1, 14.2
- `AGENT_RULES.md`
