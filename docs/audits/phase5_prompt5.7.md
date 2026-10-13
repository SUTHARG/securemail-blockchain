# Specification Compliance Audit: Phase 5, Prompt 5.7

## Scope
Audit of `engine/smscope/rules/evaluator.py`, `eval/compare_labels.py`, `engine/tests/test_rules.py`, and related configurations against:
- `AGENT_RULES.md`
- `docs/ARCHITECTURE.md`, Sections 4.7 and 5
- `docs/PROMPT_LIBRARY.md`, Prompt 5.7
- `docs/decisions/013-rule-evaluation-and-scoring.md`

---

### 1. Specification Discrepancies
None identified.
- **Rule Implementation**:
  - Implements all 12 Tier 1 detection rules strictly using real forensic session records:
    - R01 (Critical, weight 40): Triggered when `len(session.cleartextAuth) > 0`.
    - R02 (High, weight 20): Triggered when `transportMode == "plaintext"` and `not session.starttls.offered`.
    - R03 (High, weight 20): Triggered when `session.starttls.offered and not session.starttls.attempted and transportMode == "plaintext"`.
    - R06 (High, weight 20): Triggered when `session.tls.version in ["TLS 1.0", "TLS 1.1"]`.
    - R08 (High, weight 20): Triggered when cipher suite name contains RC4, DES, or 3DES.
    - R09 (Medium, weight 8): Triggered when `session.tls.forwardSecrecy is False` and `kxType in ["RSA", "DH", "ECDH"]` (or static).
    - R11 (High, weight 20): Triggered when any observed certificate has `"expired" in cert.verdicts` or `session.firstPacketTs > cert.notAfter`.
    - R12 (High, weight 20): Triggered when any observed certificate has `"weakKey" in cert.verdicts` (RSA $< 2048$ or EC $< 224$ bits).
    - R13 (High, weight 20): Triggered when any non-self-signed certificate has `"weakSignature" in cert.verdicts` (MD5 or SHA-1 signature algorithm).
    - R15 (Low, weight 2): Triggered when any observed certificate has `"unknownIssuer"` (or `"incompleteChain"`) and the leaf is not self-signed.
    - R16 (Medium, weight 8): Triggered when the leaf certificate is self-signed (`"selfSigned"` in leaf verdicts or `subject == issuer`).
    - R19 (Info, weight 0): Triggered when `session.tls.certObservable is False` (TLS 1.3 or session resumption).
- **Deduplication**:
  - Exactly one finding emitted per `(ruleId, serverEndpoint)`.
  - Deterministic `findingId` derived via SHA-256 digest of `ruleId + ":" + serverEndpoint`.
  - `sessionCount` accurately tallies the number of unique affected sessions; `sortedSessionIds` contains ascending sorted session IDs.
- **Evidence Capping**:
  - Evidence list is deduplicated and sorted by `(sessionId, packetNumber, note)`.
  - Bounded at $\le 5$ entries (`unique_evidence[:5]`) in ascending `sessionId` order.
- **Pure Integer Host Posture Scoring**:
  - Exposure factor: 1 for 1 session, 2 for 2–9 sessions, 3 for $\ge 10$ sessions.
  - Severity weights: Critical=40, High=20, Medium=8, Low=2, Info=0.
  - Formula: $\text{score} = \max(0, 100 - \sum \text{weight} \times \text{exposureFactor})$.
  - Grade bands: A $\ge 90$, B 75–89, C 60–74, D 40–59, F $< 40$.
  - 100% integer arithmetic; zero float conversions.
- **Ground Truth Comparison**:
  - `eval/compare_labels.py` evaluates all 17 captures in `lab/captures/` and compares findings against `lab/labels/`.
  - Achieves 100% precision and 100% recall across all 17 scenarios, exiting with code 0.

---

### 2. Missing Decisions
None. Rule triggers, evidence capping, deduplication rules, and integer scoring math are fully documented in [docs/decisions/013-rule-evaluation-and-scoring.md](file:///c:/Users/gaura/OneDrive/Desktop/projects/blockchain-project/docs/decisions/013-rule-evaluation-and-scoring.md).

---

### 3. AGENT_RULES.md Violations
- **Floating point arithmetic**: None. All scoring deductions, exposure factors, weights, and grade boundaries utilize integer arithmetic.
- **Wall-clock time**: None. Certificate expiration checks rely strictly on packet capture timestamps (`firstPacketTs`).
- **Unordered iteration in written output**: None. Findings are sorted by `findingId`, evidence by `(sessionId, packetNumber, note)`, and details deterministically sorted.
- **Credential / payload logging**: None. Cleartext authentication records only mechanism names (`PLAIN`, `LOGIN`) and packet numbers; never raw passwords or tokens.
- **Passive engine**: None. Engine runs 100% offline with zero network lookups.

---

### 4. Specification Requirements Coverage
| Requirement | Implementation | Test Coverage |
| :--- | :--- | :--- |
| Real session evaluation for Tier 1 rules | `evaluator.py:evaluate` | `test_rules.py:TestTier1Rules` |
| R01 (Cleartext credentials) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r01_cleartext_auth` |
| R02 (Plaintext without STARTTLS) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r02_plaintext_no_starttls` |
| R03 (STARTTLS offered but ignored) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r03_starttls_offered_not_attempted` |
| R06 (Deprecated TLS 1.0/1.1) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r06_deprecated_tls_version` |
| R08 (Insecure ciphers RC4/DES/3DES) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r08_insecure_ciphers` |
| R09 (No forward secrecy) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r09_no_forward_secrecy` |
| R11 (Certificate expired at capture time) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r11_expired_certificate` |
| R12 (Weak RSA < 2048 or EC < 224 key) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r12_weak_key` |
| R13 (Weak MD5/SHA-1 signature) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r13_weak_signature` |
| R15 (Unknown issuer / untrusted CA) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r15_unknown_issuer` |
| R16 (Self-signed leaf certificate) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r16_self_signed_leaf` |
| R19 (Certificate not observable) | `evaluator.py:evaluate` | `test_rules.py:test_rule_r19_cert_not_observable` |
| Finding deduplication by (rule, endpoint) | `evaluator.py:evaluate` | `test_rules.py:test_deduplication_by_rule_and_endpoint` |
| Evidence capping at $\le 5$ in ascending order | `evaluator.py:evaluate` | `test_rules.py:test_evidence_capped_at_five` |
| RSA key boundary (2048 vs 1024 / 2047) | `evaluator.py:evaluate` | `test_rules.py:test_rsa_key_size_boundary` |
| TLS version boundary (1.1 vs 1.2) | `evaluator.py:evaluate` | `test_rules.py:test_tls_version_boundary` |
| Exposure factor boundary (1, 2-9, 10+) | `evaluator.py:compute_exposure_factor` | `test_rules.py:test_session_count_exposure_boundary` |
| Scoring boundary (9 vs 10 sessions) | `evaluator.py:calculate_host_score` | `test_rules.py:test_scoring_boundary_9_vs_10_sessions` |
| Grade boundaries (A, B, C, D, F) | `evaluator.py:compute_grade` | `test_rules.py:test_grade_boundaries` |
| Evaluation determinism across runs | `evaluator.py:evaluate` | `test_rules.py:test_determinism_across_runs_and_shuffles` |
| Label comparison tool & 100% acceptance | `eval/compare_labels.py` | `eval/compare_labels.py` (exits 0 on S01a–S13, X01–X03) |
