# Decision 000: Technology Platform Selection

## Status
Accepted

## Context
SecureMailScope requires an on-chain verification and state-tracking layer along with an off-chain passive network analysis engine and backend services. The architectural specification (docs/ARCHITECTURE.md Section 1 and Section 3.4) considers EVM and Hyperledger Fabric as options, establishing EVM terms as the working baseline. A definitive platform choice is required for implementation.

## Decision
1. **Smart Contracts**: EVM-compatible chain using Solidity and the Hardhat development environment (TypeScript configuration and tests).
2. **Analysis Engine**: Python (>= 3.11 / 3.13) utilizing standard cryptographic and parsing libraries (`cryptography`, `dpkt`, `jsonschema`, `pytest`, `hypothesis`).
3. **Backend & Validator Services**: Python for operational consistency and direct reuse of the engine results library.

## Consequences
- Contracts will be authored in Solidity (0.8.x), compiled, tested, and deployed via Hardhat with TypeScript.
- The engine remains deterministic and portable across POSIX and container environments.
- Python facilitates deterministic canonical JSON construction, Merkle tree operations, and integration across CLI and backend components.

## References
- `docs/ARCHITECTURE.md` sections 1, 3.4, 6
- `AGENT_RULES.md`
