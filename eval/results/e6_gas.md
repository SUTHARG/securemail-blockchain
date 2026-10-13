# E6: Gas Consumption Evaluation

Gas consumption measured across all seven primary on-chain operations in EVM units (gas) for quorum sizes **N = 3** (fault tolerance $k = 2$) and **N = 5** ($k = 3$).

## Gas Consumption Matrix

| Operation | Contract | Caller Role | Gas (N=3, k=2) | Gas (N=5, k=3) | Delta (N=5 vs N=3) | Operation Description |
|:---|:---|:---|:---:|:---:|:---:|:---|
| `openCase` | `CaseRegistry` | Analyst | 137,596 | 137,596 | 0 | Initializes case with pcapHash and analyst tracking |
| `submitClaim` | `ValidationQuorum` | Analyst | 315,711 | 409,795 | +94,084 | Submits claim and snapshots active validator set (scales with N) |
| `commit` | `ValidationQuorum` | Validator | 82,240 | 82,240 | 0 | Records keccak256 commitment of result root and secret salt |
| `reveal` | `ValidationQuorum` | Validator | 139,195 | 139,195 | 0 | Reveals root, salt, and verified pinned engine/ruleset hashes |
| `finalize` | `ValidationQuorum` | Permissionless | 74,007 | 74,007 | 0 | Evaluates revealed quorum threshold and marks Finalized |
| `recordPosture` | `PostureLedger` | Analyst | 224,268 | 224,268 | 0 | Verifies inclusion Merkle proof against finalized root and appends record |
| `anchorReport` | `CaseRegistry` | Analyst | 51,293 | 51,293 | 0 | Anchors canonical report.json SHA-256 digest on-chain |
| **Lifecycle Total (Per Case)** | *All Contracts* | *Combined* | **1,024,310** | **1,118,394** | **+94,084** | *Sum of single-execution of each operation* |

## Scalability & Complexity Analysis

1. **Snapshotting Scalability:** `submitClaim` is the only operation whose gas cost scales with the validator quorum size $N$. For $N=3$, gas is 315,711; for $N=5$, gas is 409,795 ($+94,084$ gas, or ~47,042 gas per additional validator stored into the active round storage snapshot).
2. **Constant-Time Verification:** Operations `commit`, `reveal`, and `finalize` exhibit $O(1)$ gas complexity per validator call, as commitments and reveals index direct mapping slots.
3. **Merkle Inclusion Proof Cost:** `recordPosture` costs ~224,268 gas, which incorporates on-chain keccak256 leaf reconstruction, sibling proof path verification (`MerkleVerifier.verify`), and persistent state insertion in `PostureLedger`.
4. **Economic Feasibility:** At typical enterprise consortium gas costs (e.g. Polygon PoS / Arbitrum / local permissioned Geth @ < 20 Gwei), a full case lifecycle costs less than $0.05 USD, making on-chain forensic integrity highly practical.
