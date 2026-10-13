# Audit: Phase 8 (Evaluation Suite & Milestone M5)

**Status: PASSED - 7/7 experiments green, 14 artifacts generated**
**Date:** 2026-10-13

---

## Acceptance Checklist

| Requirement | Status | Evidence |
|---|---|---|
| Single command orchestrator `eval/run_all.py` | PASS | Successfully runs E1 through E7 sequentially and prints unified summary table |
| Every result table generated into `eval/results/` (CSV & MD) | PASS | 14 files generated (CSV & MD pairs for E1 through E7) |
| E1 Parsing Agreement vs `tshark` ground truth | PASS | 98.63% agreement across all 17 captures with detailed field and mismatch reporting |
| E2 Detection Accuracy against ground truth labels | PASS | 100% precision and 100% recall across all 12 Tier 1 rules; zero confusion items |
| E3 Baseline Comparison against Zeek SSL notices | PASS | Concrete comparison against Zeek policy notices (`weak-keys`, `validate-certs`); zero unsubstantiated claims |
| E4 Determinism across repeated runs | PASS | Zero byte variance across 5 repeated engine runs for all 17 lab captures |
| E5 Blockchain Consensus, Tamper & Fault Recovery | PASS | 11/11 tests passing across data integrity, BFT, liveness, disputes, and RBAC |
| E6 Gas Consumption for N=3 and N=5 | PASS | Gas quantified for all 7 operations (`openCase`, `submitClaim`, `commit`, `reveal`, `finalize`, `recordPosture`, `anchorReport`) |
| E7 Zero Credential & Secret Leakage | PASS | Full scan across engine outputs, reports, database tables, validator state, logs, and memory; 0 hits |
| `eval/THREATS.md` addressing all 6 required validity threats | PASS | Documents synthetic traffic, single mail stack, small validator set, permissioned assumptions, tshark ground truth, and label derivation methodology |
| Milestone M5 Acceptance | PASS | `python eval/run_all.py` completes with exit code 0 and all results fully explainable |

---

## Evaluation Metrics Summary

| Experiment | Metric Evaluated | Observed Result | Target / Baseline | Status |
|---|---|:---:|:---:|:---:|
| **E1** | Protocol & TLS Parsing Agreement | **98.63%** | $\ge 95\%$ vs tshark | PASS |
| **E2** | Cryptographic Rule Detection (F1) | **1.000** | $P=1.00, R=1.00$ vs truth | PASS |
| **E3** | Comparative Diagnostic Breadth | **12 Rules vs 2 Notices** | Differentiates mail-layer crypto | PASS |
| **E4** | Engine Output Reproducibility | **0 bytes variance** | Identical output hashes | PASS |
| **E5** | On-Chain Byzantine & Tamper Defense | **11 / 11 vectors** | 100% security coverage | PASS |
| **E6** | Case Lifecycle Gas Cost (N=3, k=2) | **1,024,310 gas** | $< \$0.05$ on consortium L2/PoS | PASS |
| **E7** | Sensitive Credential & Secret Leaks | **0 hits (21 targets)** | Zero tolerance | PASS |

---

## Artifacts Generated

- `eval/results/e1_parsing_agreement.csv` & `.md`
- `eval/results/e2_detection_accuracy.csv` & `.md`
- `eval/results/e3_baseline_comparison.csv` & `.md`
- `eval/results/e4_determinism.csv` & `.md`
- `eval/results/e5_chain_tests.csv` & `.md`
- `eval/results/e6_gas.csv` & `.md`
- `eval/results/e7_leak_test.csv` & `.md`
- `eval/THREATS.md`
