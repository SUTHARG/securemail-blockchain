# Audit: Tier 2 - Prompt T2.4 (Advisory Anomaly Detection)

**Status: PASSED - All deliverables complete and verified**
**Date:** 2026-10-13

---

## Acceptance Checklist

| Requirement | Status | Evidence |
|---|---|---|
| Create `advisory/anomaly/` strictly outside consensus & result root | PASS | Implemented `advisory/anomaly/features.py`, `detector.py`, `__init__.py`. Anomaly scores are never hashed into Merkle result root and never sent on-chain. |
| Deterministic integer feature extraction per session | PASS | Extracting 8 integer features: `tls_version`, `cipher_suite_code`, `ja3_rarity_bucket`, `cert_differs_from_baseline`, `handshake_size_bucket`, `resumed_flag`, `starttls_offered`, `starttls_used`. No floating-point values or timestamp floats. |
| Baseline generation & model training | PASS | `lab/make_baseline.sh` and `lab/make_baseline.py` generated 250 clean sessions across 5 client profiles in `lab/captures/baseline.pcap`. Model saved as `advisory/anomaly/model.joblib` and metadata saved in `baseline_summary.json` recording scikit-learn version. |
| Deterministic Isolation Forest scoring & heuristic explanation | PASS | Fixed `random_state=42`. Calibration threshold set. Separate empirical heuristic (<5% baseline frequency) for top deviating features with explicit disclaimers in code and reports. |
| Injected anomalies A1, A2, A3 | PASS | PCAPs generated in `scripts/build_test_pcap.py`: `A1.pcap` (certificate replacement), `A2.pcap` (TLS 1.0 negotiation), `A3.pcap` (unseen client JA3 profile). |
| Evaluation script `eval/e8_anomaly.py` | PASS | Evaluates detection rate & false positive rate on A1–A3 vs clean captures (S01a, S13, baseline held-out). Generates `eval/results/e8_anomaly.csv` and `eval/results/e8_anomaly.md`. Added to `eval/run_all.py`. |
| Reports & Dashboard integration | PASS | Dedicated "Advisory Anomaly Detection (Non-Consensus / Off-Chain)" section added to `backend/reports/builder.py` and `backend/reports/templates/report.html`, with strict zero-float canonical JSON serialization and clear non-consensus badges. |
| Unit tests & Determinism | PASS | 6 tests in `engine/tests/test_anomaly.py` passing. Two runs produce identical scores. Full engine test suite: 230 passing; backend suite: 32 passing. |

---

## Key Experimental Findings (E8)

1. **Where ML Adds Value**:
   - **Scenario A3 (Unseen Client JA3 Profile)**: The mail client connects using an unusual cipher suite list and unseen JA3 signature. The deterministic rule engine produces 0 findings because the connection is compliant with RFCs. The advisory Isolation Forest detector flags the session with top deviating features `cipher_suite_code=156` and `ja3_rarity_bucket=0`.
2. **Where ML Adds Noise / Rule Engine Dominates**:
   - **Scenarios A1 & A2 (Protocol Violations)**: The deterministic rule engine detects certificate replacements (**R18**) and deprecated TLS 1.0 negotiations (**R06**) with 100% precision and zero false alarms.
   - In small synthetic baseline datasets, unsupervised tree isolation does not inherently shorten tree depths for binary protocol flags without extensive feature cardinality, and can produce false positives on rare ciphers.
3. **Architectural Separation**:
   - ML detection is kept strictly outside the Merkle result root and quorum verification. It provides an advisory triage signal without compromising cryptographic determinism.

---

## Deliverables Generated
1. `advisory/anomaly/features.py`: Discrete integer feature extraction.
2. `advisory/anomaly/detector.py`: Scikit-learn Isolation Forest wrapper with deterministic scoring and empirical explanation heuristic.
3. `advisory/anomaly/__init__.py`: Package export.
4. `lab/make_baseline.py` & `lab/make_baseline.sh`: Baseline PCAP generator (250 clean sessions) and model training.
5. `advisory/anomaly/model.joblib`: Trained model artifact.
6. `advisory/anomaly/baseline_summary.json`: Model hyperparameters, threshold, feature distributions, and scikit-learn version.
7. `scripts/build_test_pcap.py`: Builders for injected anomalies A1, A2, A3.
8. `eval/e8_anomaly.py`: Evaluation experiment script.
9. `eval/results/e8_anomaly.csv` & `eval/results/e8_anomaly.md`: Experiment results and comparative analysis.
10. `eval/run_all.py`: Orchestrator updated to run E8 alongside E1–E7.
11. `backend/reports/builder.py`: Advisory section generation adhering to zero-float canonical JSON.
12. `backend/reports/templates/report.html`: Non-consensus advisory anomaly report section.
13. `engine/tests/test_anomaly.py`: Determinism and isolation unit tests.
