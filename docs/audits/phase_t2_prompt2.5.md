# Audit: Tier 2 - Prompt T2.5 (PDF Export)

**Status: PASSED - All deliverables complete and verified**
**Date:** 2026-10-13

---

## Acceptance Checklist

| Requirement | Status | Evidence |
|---|---|---|
| Pin WeasyPrint version and document system dependencies in `README.md` | PASS | Pinned `weasyprint==64.1` with `pydyf==0.12.1`. Full system dependencies for Debian/Ubuntu, RHEL, macOS, and Windows documented in `README.md`. |
| Endpoint `GET /cases/{id}/report?format=pdf` | PASS | Returns `application/pdf` with `Content-Disposition: inline; filename="report_{case_id[:12]}.pdf"`. |
| Anchored report hash in header | PASS | The on-chain anchored report hash remains `SHA-256(report.json)`; this exact hash is displayed prominently in the PDF header alongside Case ID, Result Root, and PCAP SHA-256. |
| Zero network access during PDF generation | PASS | Passive operation enforced (`base_url=None`, verified with monkeypatched socket connection blocking). |
| Tests for S01a, S05, S12 | PASS | `backend/tests/test_reports.py::test_pdf_export_s01a_s05_s12` passes for all three scenarios, asserting presence of Case ID, Result Root, and report hash. |
| Host compatibility & pure-Python fallback | PASS | When native C libraries (GTK3/Pango) are absent on host OS, seamlessly falls back to pure-Python `pydyf` engine to guarantee reliable PDF generation everywhere. |

---

## Deliverables Generated
1. `backend/reports/pdf.py`: PDF report generator with WeasyPrint and bundled `pydyf` fallback engine.
2. `backend/app.py`: Updated `GET /cases/{id}/report` supporting `format=pdf`.
3. `backend/tests/test_reports.py`: Acceptance tests for `format=pdf` and scenarios S01a, S05, S12.
4. `README.md`: Documented system library dependencies.
5. `AGENT_RULES.md`: Updated scope to Tier 2 - T2.5.
