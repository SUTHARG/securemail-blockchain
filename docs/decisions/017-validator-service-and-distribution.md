# Decision 017: Validator Service Architecture, Bundle Distribution, and Consensus Resilience

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` Sections 6.4 and 7, and Prompt 6.3 define the validator service architecture for multi-party commit-reveal consensus. Each validator operates as an independent service process holding its own signing key and inbox. It monitors the blockchain for cases where it is designated in the validator snapshot, executes the pinned engine container in an isolated network-less sandbox, generates and persists a cryptographic salt, and drives the commit-reveal cycle to finalization.

## Decisions

1. **Service Configuration and Inbox Layout**:
   - Each validator service instance is configured via `--id <id>` (e.g. 1, 2, 3), `--key-env <ENV_VAR>` (e.g. `VALIDATOR_1_KEY`), `--inbox-dir` (default `validator_inbox/<id>/`), and `--state-dir` (default `validator_state/`).
   - Bundle intake format: `validator_inbox/<id>/<caseId>/pcap.bin` and `validator_inbox/<id>/<caseId>/org_secret.hex`.
   - Before taking any action on a case, the service validates `quorum.isSnapshotValidator(caseId, round, validator_address)`. Bundles for cases where the validator is not an authorized snapshot participant are strictly ignored.

2. **Atomic State Persistence and Restart Safety**:
   - Prior to broadcasting a commit transaction, the service generates a cryptographically secure 32-byte salt (`os.urandom(32)`).
   - The salt, case ID, round, result root, and computed commitment are atomically written to `validator_state/<id>.json` using a temporary file (`.tmp`) and an atomic file system replace operation (`os.replace`).
   - On service startup or recovery, the service checks `validator_state/<id>.json`. If a commitment is already recorded on-chain (`hasCommitted == true`) but not revealed (`hasRevealed == false`), the service immediately resumes the workflow: it waits for the reveal window to open (triggering `advance()` if the commit window has elapsed) and broadcasts the reveal transaction with the persisted salt.
   - If already revealed, the service avoids duplicate transactions.

3. **Strict Mode and Pinning Verification**:
   - Consistent with `validator/node.py`, strict mode verifies that:
     1. Local `manifest.json["rulesetHash"]` matches `caseRegistry.rulesetHash(caseId)`.
     2. Environment `ENGINE_IMAGE_DIGEST` matches `caseRegistry.engineHash(caseId)`.
   - Any divergence aborts processing before any commit transaction is submitted.

4. **Containerized Execution with Fallback**:
   - The primary execution model invokes `docker run --rm --network none --read-only -v <bundle>:/inbox:ro -v <out>:/out <engine_image> analyze ...`.
   - If Docker daemon is unavailable in the environment, the runner safely invokes the direct local engine CLI (`python -m smscope analyze ...`), honoring the passive engine requirements.

5. **Faulty Validator Emulation (`--faulty`)**:
   - A `--faulty` command-line switch enables adversarial evaluation testing: the validator computes an invalid result root, commits and reveals it, and demonstrates that the honest validator quorum outvotes the faulty participant.

6. **Tier 1 Bundle Distribution Endpoint**:
   - `POST /cases/{case_id}/distribute` copies `pcap.bin` and `org_secret.hex` from the case data repository into `validator_inbox/1/<case_id>/`, `validator_inbox/2/<case_id>/`, and `validator_inbox/3/<case_id>/`.
   - It marks case status as `distributed` and logs an audit trail event.
   - Encrypted off-chain delivery (asymmetric key envelope encryption) is explicitly documented as Tier 3 future work.

## Consequences
- Reliable crash recovery between commit and reveal stages without data loss or stuck cases.
- Complete isolation of signing keys between validators and API services.
- Clean outvoting of malicious or corrupted validator outputs.
