# Decision 013: Rule Evaluation, Finding Deduplication, and Host Posture Scoring

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` Section 4.7 and Prompt 5.7 specify the detection engine's Tier 1 ruleset, finding deduplication rules, evidence capping semantics, and integer host posture scoring formula. The system must evaluate passive forensic observations across network sessions into deterministic cryptographic findings and compute an integer posture score (0–100) and letter grade (A, B, C, D, F) without floating-point arithmetic.

## Decisions

1. **Tier 1 Detection Rules Trigger Conditions**:
   The engine implements exactly the 12 Tier 1 rules defined in `ruleset/ruleset.yaml`:
   - **R01 (Critical, 40)**: The session has at least one cleartext authentication entry (`len(session.cleartextAuth) > 0`).
   - **R02 (High, 20)**: `session.transportMode == "plaintext"` and `session.starttls.offered is False`.
   - **R03 (High, 20)**: `session.starttls.offered is True`, `session.starttls.attempted is False`, and `session.transportMode == "plaintext"`.
   - **R06 (High, 20)**: `session.tls is not None` and `session.tls.version in ["TLS 1.0", "TLS 1.1"]`.
   - **R08 (High, 20)**: `session.tls is not None` and `session.tls.cipherSuiteName` contains RC4, DES, or 3DES.
   - **R09 (Medium, 8)**: `session.tls is not None` and `session.tls.forwardSecrecy is False` with key exchange type in `["RSA", "DH", "ECDH"]` (static RSA or static DH without ephemeral key exchange).
   - **R11 (High, 20)**: Any observed certificate in `session.certificates` has `"expired" in cert.verdicts` or `session.firstPacketTs > cert.notAfter`.
   - **R12 (High, 20)**: Any observed certificate has `"weakKey" in cert.verdicts` (RSA $< 2048$ bits or EC $< 224$ bits).
   - **R13 (High, 20)**: Any observed certificate that is not self-signed has `"weakSignature" in cert.verdicts` (MD5 or SHA-1 signature hash).
   - **R15 (Low, 2)**: Any observed certificate has `"unknownIssuer"` (or `"incompleteChain"`) in its verdicts and the leaf certificate is not self-signed.
   - **R16 (Medium, 8)**: The leaf certificate is self-signed (`"selfSigned"` in verdicts or `subject == issuer`).
   - **R19 (Info, 0)**: `session.tls is not None` and `session.tls.certObservable is False` (TLS 1.3 or session resumption).

2. **Finding Deduplication and Identification**:
   - Findings are deduplicated per `(ruleId, serverEndpoint)`.
   - `findingId`: Deterministic SHA-256 digest computed as `SHA-256(ruleId + ":" + serverEndpoint)`.
   - `sessionCount`: Total count of unique sessions affected by this finding.
   - `sortedSessionIds`: Sorted list of unique integer `sessionId`s in ascending numerical order.

3. **Evidence Ordering and Capping**:
   - Evidence records (`{sessionId, packetNumber, note}`) are collected across all affected sessions.
   - Evidence is deduplicated by `(sessionId, packetNumber, note)` and sorted in ascending numerical order by `sessionId`, then `packetNumber`, then `note`.
   - Exactly at most 5 evidence entries (`evidence[:5]`) are retained per finding to guarantee bounded on-chain and off-chain payload sizes.

4. **Pure Integer Host Posture Scoring**:
   - Adhering strictly to Rule 1 (`AGENT_RULES.md`), all scoring math is performed exclusively with integer arithmetic.
   - **Severity Weights**:
     - Critical: 40
     - High: 20
     - Medium: 8
     - Low: 2
     - Info: 0
   - **Integer Exposure Factor**:
     - 1 session affected: exposure factor = 1
     - 2 to 9 sessions affected: exposure factor = 2
     - 10 or more sessions affected: exposure factor = 3
   - **Score Deduction Formula**:
     $$\text{totalDeductions} = \sum_{f \in \text{hostFindings}} \text{weight}(f.\text{severity}) \times \text{exposureFactor}(f.\text{sessionCount})$$
     $$\text{score} = \max(0, 100 - \text{totalDeductions})$$
   - **Grade Boundaries**:
     - A: $\text{score} \ge 90$
     - B: $75 \le \text{score} \le 89$
     - C: $60 \le \text{score} \le 74$
     - D: $40 \le \text{score} \le 59$
     - F: $\text{score} < 40$

5. **Discrepancy Label Policy**:
   - Lab scenario labels in `lab/labels/<ID>.json` are derived from ground-truth observed fields (tshark).
   - If a scenario exhibits multiple vulnerabilities on the wire (such as S02 negotiating both deprecated TLS 1.0 and static RSA cipher suite 0x002F), all matching rule hits are included in the label with explanatory comments, adhering to Prompt 4.2 guidelines.

## Consequences
- Guarantees deterministic, reproducible findings across different platforms and runs.
- Prevents unbounded growth of evidence arrays in findings while preserving the earliest session evidence.
- Ensures zero floating-point divergence between off-chain Python analysis and on-chain EVM contract verification.
