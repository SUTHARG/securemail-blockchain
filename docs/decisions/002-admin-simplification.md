# Decision 002: Single Administrator Role Simplification

## Status
Accepted

## Context
Section 6.1 and 6.7 of `docs/ARCHITECTURE.md` specify that the Administrator should ideally be governed by a multisig contract for production deployments. For course development, automated testing, and milestone demonstrations, configuring a live multisig adds substantial out-of-band operational overhead without adding security posture value to the forensic verification pipeline.

## Decision
The deploying address is directly granted `ADMIN_ROLE` (and `DEFAULT_ADMIN_ROLE`) upon contract construction. This single administrator account holds exclusive permissions to:
1. Register approved engine releases and ruleset hashes (`registerEngine`).
2. Add and remove validator addresses (`addValidator`, `removeValidator`).
3. Resolve disputed rounds and manage quorum exceptions.

## Consequences
- Simplifies local deployment scripts, unit tests, and CI/demo execution.
- Retains complete role separation between Admin, Analyst, Validator, and Quorum roles.
- Must be documented as a demonstration simplification in the final course report, with production upgrade path to Gnosis Safe / multisig noted.

## References
- `docs/ARCHITECTURE.md` sections 3.2, 6.1, 6.7
- `AGENT_RULES.md`
