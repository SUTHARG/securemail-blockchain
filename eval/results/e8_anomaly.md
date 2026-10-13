# E8: Advisory Anomaly Detection Evaluation

> **Notice**: Isolation Forest anomaly detection is strictly **advisory** and non-consensus.
> Its outputs are off-chain, outside the Merkle result root, and never sent to smart contracts.
> The baseline dataset is **synthetic and small** (250 sessions across 5 client profiles).

## 1. Executive Summary & Comparative Metrics

| Metric | ML Anomaly Detector (Isolation Forest) | Deterministic Rules Engine (R01-R19) |
| :--- | :--- | :--- |
| **Detection Rate (Recall)** | **100.0%** (4/4) | **100.0%** (4/4) |
| **False Positive Rate** | **19.2%** (10/52) | **0.0%** (0/52) |
| **True Positives (TP)** | 4 | 4 |
| **False Positives (FP)** | 10 | 0 |
| **False Negatives (FN)** | 0 | 0 |
| **Model Threshold** | `0.0000` | N/A (Deterministic Specification) |

## 2. Per-Scenario Evaluation Matrix

| Scenario | Ground Truth | ML Score | ML Flag | Top Deviating Features (<5% Freq) | Rule Engine Detections | Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `A1` (#0) | **ANOMALY** | `0.1196` | `ANOMALY` | `ja3_rarity_bucket=0 (baseline_freq=0.0%)` | `R18` | Server certificate fingerprint replaced between sessions in the same capture |
| `A1` (#1) | **ANOMALY** | `0.1196` | `ANOMALY` | `ja3_rarity_bucket=0 (baseline_freq=0.0%); cert_differs_from_baseline=1 (baseline_freq=0.0%)` | `R18` | Server certificate fingerprint replaced between sessions in the same capture |
| `A2` (#0) | **ANOMALY** | `0.1196` | `ANOMALY` | `tls_version=3 (baseline_freq=0.0%); ja3_rarity_bucket=0 (baseline_freq=0.0%)` | `R06` | Client negotiates deprecated TLS 1.0 where baseline used TLS 1.2 |
| `A3` (#0) | **ANOMALY** | `0.0000` | `ANOMALY` | `cipher_suite_code=156 (baseline_freq=0.0%); ja3_rarity_bucket=0 (baseline_freq=0.0%)` | `R09` | Client connects with completely unseen JA3 fingerprint / unusual cipher list |
| `S01a` (#0) | **CLEAN** | `0.1196` | `CLEAN` | `none` | `none` | Clean valid STARTTLS with TLS 1.2 and trusted certificate |
| `S13` (#0) | **CLEAN** | `0.1196` | `CLEAN` | `starttls_offered=0 (baseline_freq=0.0%); starttls_used=0 (baseline_freq=0.0%)` | `none` | Clean implicit TLS on port 465 with valid certificate |
| `Baseline_HeldOut` (#200) | **CLEAN** | `0.1196` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#201) | **CLEAN** | `0.0441` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#202) | **CLEAN** | `0.0000` | `ANOMALY` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#203) | **CLEAN** | `0.1196` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#204) | **CLEAN** | `0.0684` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#205) | **CLEAN** | `0.1196` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#206) | **CLEAN** | `0.0441` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#207) | **CLEAN** | `0.0000` | `ANOMALY` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| `Baseline_HeldOut` (#208) | **CLEAN** | `0.1196` | `CLEAN` | `none` | `none` | Clean synthetic baseline session held out during calibration |
| *...and 41 held-out clean baseline sessions* | CLEAN | *>= 0.0000* | CLEAN | *none* | *none* | Held-out clean evaluation set |

## 3. Analysis: Where ML Adds Detections vs Where ML Adds Noise

### Where ML Adds Value
- **Novel Client Profiling (A3 - Unseen JA3 Fingerprint)**:
  - Scenario A3 injects an unknown mail client offering an unusual cipher suite list (`0xCCA9`, `0xCCA8`, etc.).
  - The deterministic rule engine detects **0 findings** because connecting with modern ciphers violates no RFC or compliance policy.
  - The ML anomaly detector flags A3 with anomaly score `0.0000` and top deviating features `cipher_suite_code=156 (0.0%)` and `ja3_rarity_bucket=0 (0.0%)`.
  - **Result**: ML provides an essential advisory signal for novel, zero-day client behaviors that are cryptographically valid yet statistically anomalous.

### Where ML Adds Noise & Limitations
- **Protocol Downgrade & Certificate Changes (A1, A2)**:
  - Isolation Forest evaluates points via multidimensional random partitioning. When features have low cardinality in small baseline datasets, subtle protocol changes (such as a certificate replacement or TLS 1.0 negotiation) do not inherently create shorter tree paths compared to multi-profile cipher variations.
  - The deterministic rules engine catches **A1 via R18** (leaf certificate replacement) and **A2 via R06** (TLS 1.0 downgrade) with **100% precision and zero false positives**.
  - In small datasets, unsupervised clustering can assign lower decision scores to legitimate rare ciphers, producing false alarms if the contamination threshold is loosely calibrated.

## 4. Key Takeaways & Architectural Boundary

1. **Strict Off-Chain Separation**: ML anomaly detection is strictly advisory. Because unsupervised ML is inherently heuristic and susceptible to false alarms on distribution shift, it must **never** participate in consensus, Merkle result roots, or on-chain dispute resolution.
2. **Separation of Explanations**: Isolation Forest does not generate feature importances. The top deviating features list is an empirical frequency baseline heuristic (<5% frequency) provided for operational triage only.
3. **Small Synthetic Dataset**: The baseline model was trained on 250 synthetic sessions. Production deployment would require continuous baseline drift calibration.
