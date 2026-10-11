# Decision 001: Hashing, Identifiers, and Merkle Tree Construction

## Status
Accepted

## Context
SecureMailScope requires cryptographic identifiers for endpoints, findings, hosts, and result trees to enable deterministic agreement between independent validator instances and verifiable on-chain posture proofs. The encoding, canonical serialization, and Merkle tree generation rules must be completely unambiguous and reproducible across Python and Solidity.

## Decision
1. **Endpoint String Representation**:
   - IPv4 endpoints are formatted as `'a.b.c.d:port'` (e.g., `'192.168.1.10:25'`).
   - IPv6 endpoints are formatted as `'[address]:port'` with the IP address in compressed lowercase form (e.g., `'[2001:db8::1]:25'`).
2. **Finding Identifier (`findingId`)**:
   - Computed as SHA-256 over the ASCII bytes of `'<ruleId>|<serverEndpoint>'` (e.g., `'R01|192.168.1.10:25'`).
   - Encoded as a 64-character lowercase hex string.
3. **Findings Digest per Host (`findingsDigest`)**:
   - Computed as SHA-256 over the concatenation of that host's `findingId`s converted to their raw 32-byte values, sorted in ascending lexicographical byte order.
   - If a host has zero findings, `findingsDigest` is SHA-256 over the empty byte string (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
4. **Host Identifier (`hostId`)**:
   - Computed as HMAC-SHA-256 with `key = organization secret bytes` and `message = the ASCII endpoint string`.
   - Output is raw 32 bytes (or 64-character lowercase hex string representation).
5. **Merkle Tree Construction & Proofs**:
   - **Leaf Ordering**: Input leaves are sorted ascending by raw hash bytes.
   - **Duplicate Leaves**: Duplicate leaf hashes are strictly rejected with an exception.
   - **Empty Trees**: An empty leaf list is strictly rejected with an exception.
   - **Single Leaf**: The root of a tree containing exactly one leaf is that leaf itself.
   - **Odd Nodes**: An odd node at any level that cannot be paired is carried up to the next level unchanged.
   - **Node Hashing**: Interior nodes are computed as `SHA-256(0x01 + min(a, b) + max(a, b))` where `a` and `b` are compared as raw byte sequences (or unsigned 256-bit integers). Proofs require no left/right positional flags because node hashing sorts its inputs.
   - **Leaf Domain Separation**:
     - Finding leaf: `SHA-256(0x00 + canonical_json(finding))`
     - Host score leaf: `SHA-256(0x02 + hostId[32] + findingsDigest[32] + score as 2-byte big-endian uint16)`

## Consequences
- Guarantees byte-identical result roots across independent engines regardless of platform.
- Eliminates positional overhead in Merkle inclusion proofs for `PostureLedger.sol`.
- Protects internal network topologies by pseudonymizing IP addresses on-chain via HMAC.

## References
- `docs/ARCHITECTURE.md` sections 5.1, 5.2, 5.3, 5.4, 6.5
- `AGENT_RULES.md`
