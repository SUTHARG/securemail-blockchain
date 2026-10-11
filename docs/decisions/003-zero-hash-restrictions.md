# Decision 003: Defensive Zero-Hash Validation in Smart Contracts

## Status
Accepted

## Context
In `contracts/contracts/CaseRegistry.sol`, several state-changing operations accept 32-byte cryptographic hashes (`bytes32`):
1. `openCase(bytes32 _pcapHash)`
2. `anchorReport(bytes32 caseId, bytes32 _reportHash)`
3. `registerEngine(bytes32 imageDigest, bytes32 _rulesetHash)`

`docs/ARCHITECTURE.md` (Sections 6.1 and 6.2) assumes valid SHA-256 cryptographic digests without explicitly stating whether `bytes32(0)` (`0x0000...0000`) should be rejected by contract guards.

## Decision
`CaseRegistry.sol` strictly rejects `bytes32(0)` for PCAP hashes, report custody digests, engine image digests, and ruleset hashes:
1. **PCAP Hash Guard (`_pcapHash != bytes32(0)`)**:
   - Reverts with `InvalidPcapHash()` if `_pcapHash == bytes32(0)`.
   - *Rationale*: A captured PCAP file always contains data whose SHA-256 digest is non-zero. A zero hash represents an uninitialized or corrupted input.
2. **Report Custody Hash Guard (`_reportHash != bytes32(0)`)**:
   - Reverts with `InvalidReportHash()` if `_reportHash == bytes32(0)`.
   - *Rationale*: A forensic analysis report has non-empty document content. Furthermore, `c.reportHash == bytes32(0)` is the internal sentinel value indicating that a report has not yet been anchored. Allowing `bytes32(0)` as a valid report hash would break the one-time anchoring invariant.
3. **Engine and Ruleset Hashes Guard (`imageDigest != bytes32(0)` and `_rulesetHash != bytes32(0)`)**:
   - Reverts with `InvalidEngineHash()` if either hash is `bytes32(0)`.
   - *Rationale*: Pinned releases must represent real, verifiable container image digests and ruleset files. Allowing a zero hash could permit an administrator to pin an uninitialized pair, undermining validator consensus.

## Implications for Valid Inputs
- **No valid input is excluded**: The pre-image resistance and distribution of SHA-256 ensure that the probability of a genuine file hashing to `bytes32(0)` is $2^{-256}$, which is cryptographically negligible.
- **Fail-fast behavior**: Reverting immediately on `bytes32(0)` prevents client configuration errors, uninitialized variables in script calls, and corrupt state records from reaching contract storage.

## References
- `docs/ARCHITECTURE.md` sections 5.4, 6.1, 6.2
- `contracts/contracts/CaseRegistry.sol`
- `AGENT_RULES.md`
