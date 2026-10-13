# Spec-Compliance Audit: Tier 2 - Prompt T2.7 (Dashboard Upgrade)

## Scope Audited
- `backend/app.py`
- `backend/charts.py`
- `backend/templates/layout.html`
- `backend/templates/overview.html`
- `backend/templates/hosts.html`
- `backend/templates/host_detail.html`
- `backend/templates/findings.html`
- `backend/templates/sessions.html`
- `backend/templates/tls.html`
- `backend/templates/anomalies.html`
- `backend/tests/test_dashboard.py`

---

## 1. Differences from Specification
None. All requirements of Prompt T2.7 and section 8 are satisfied:
- Tables are sortable and filterable (by grade, severity, host, protocol, ruleId) via standard HTML forms and table header query parameters, with zero external JS frameworks and 100% usability without JavaScript.
- Per-host drill-down page `/cases/{case_id}/hosts/{host_id_or_ep}` displays:
  - Findings specific to that host (with direct clickable evidence).
  - Sessions observed on that host.
  - Certificate chain presented by that host.
  - Forward secrecy share (percentage and count with progress visualizer).
  - Posture chain records.
- Inline SVG charts generated in pure Python (`backend/charts.py`) for:
  - TLS version distribution (bar chart in `tls.html`).
  - Cipher suite distribution (horizontal bar chart in `tls.html`).
  - Host posture score ranking (colored bar chart in `hosts.html`).
- Advisory anomaly flags page at `/cases/{case_id}/anomalies` displays non-consensus unsupervised Isolation Forest flags, top deviating features, and links to session inspector.
- Navigation guarantee: finding evidence is reachable in <= 3 clicks (1 click from Overview via key findings preview; 2 clicks via Findings tab).
- Zero external URLs on any rendered page except allowed documentation domains.

---

## 2. Undefined Choices Missing from `docs/decisions/`
None. Chart generation and drill-down route conventions follow REST standards without introducing external dependencies.

---

## 3. AGENT_RULES.md Violations
- Floats in Merkle tree/consensus outputs: **Zero**.
- Wall-clock time in hashed outputs: **Zero**.
- Unordered iterations in written output: **Zero**.
- Credential / payload logging: **Zero**.
- Network calls inside the engine or dashboard: **Zero**.

---

## 4. Test Coverage Verification
| Component / Requirement | Test Suite | Result |
|---|---|---|
| Dashboard all pages render (overview, hosts, findings, sessions, tls, certs, anomalies, chain) | `backend/tests/test_dashboard.py::test_all_dashboard_pages_render` | PASS |
| Inline SVG charts generation & rendering | `backend/tests/test_dashboard.py::test_all_dashboard_pages_render` | PASS |
| Per-host drill-down page rendering | `backend/tests/test_dashboard.py::test_all_dashboard_pages_render` | PASS |
| Table filtering & sorting | `backend/tests/test_dashboard.py::test_all_dashboard_pages_render` | PASS |
| No unauthorized external URLs | `backend/tests/test_dashboard.py::assert_no_unauthorized_urls` | PASS |
| Chain verification tamper detection | `backend/tests/test_dashboard.py::test_chain_verification_tamper_detection` | PASS |
| M4 end-to-end browser acceptance flow | `backend/tests/test_dashboard.py::test_m4_browser_acceptance_flow` | PASS |
| Full backend test suite | 33 test cases | 33/33 PASS |
| Full engine test suite | 245 test cases | 245/245 PASS |
| Ground truth label comparison | `eval/compare_labels.py` (29 scenarios) | 29/29 PASS |

**Audit Status:** PASS.
