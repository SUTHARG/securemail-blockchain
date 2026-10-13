# Phase T3 Prompt 3.2 Audit: Advisory LLM Recommendations

**Date:** 2026-10-13  
**Status:** PASS  
**Scope:** Tier 3 - Prompt T3.2 (LLM Recommendations - Advisory)

---

## 1. Specification Compliance

| Requirement | Status | Verification & Code Locations |
| :--- | :---: | :--- |
| **Strict Input Isolation (findings.json only)** | **PASS** | `backend/reports/llm_advisor.py` (`generate_advisory_recommendations`). Extracts only sanitized finding metadata (`findingId`, `ruleId`, `title`, `severity`, `serverEndpoint`). Never ingests or exposes PCAP bytes, sessions, or evidence payloads. |
| **Output JSON Format (`{findingId, summary, steps}`)** | **PASS** | `backend/reports/llm_advisor.py` (`validate_and_filter_recommendations`). Enforces structured output format with explicit typing. |
| **Hallucinated findingId Rejection** | **PASS** | Validates `findingId` strictly against the set of finding IDs present in `findings.json`. Hallucinated IDs are dropped completely. |
| **Missing Field Rejection & Static Fallback** | **PASS** | Items missing required fields (`summary`, `steps`) are rejected and replaced by the rule's static template from `recommendations.yaml`. |
| **Allow-List Parameter Verification** | **PASS** | Builds an allow-list of configuration parameters directly from `recommendations.yaml` (`build_allowed_parameters_set`). Any recommendation containing an unvetted parameter name is rejected and replaced by the static template. |
| **Provider Interface with Fake Implementation** | **PASS** | `LLMProvider` abstract base class with `FakeLLMProvider` implementation supporting normal and failure-injected modes. Runs 100% offline without external network or API keys. |
| **Consensus Result Root Invariant** | **PASS** | Merkle result root is computed solely over `finding_leaf` and `host_score_leaf`. Advisory recommendations are strictly off-chain and leave `resultRoot` unchanged. |
| **Advisory Labeling in Report** | **PASS** | `backend/reports/templates/report.html` renders generated recommendations with distinct gold badge `[ADVISORY (NON-CONSENSUS)]`. |

---

## 2. Test Verification

| Test Suite / Objective | Status | Result |
| :--- | :---: | :--- |
| `backend/tests/test_llm_recommendations.py` | **PASS** | 7/7 tests passed in 2.35s. |
| - `test_allowed_parameters_set_built_correctly` | **PASS** | Validates allow-list extraction from `recommendations.yaml`. |
| - `test_hallucinated_finding_id_rejected` | **PASS** | Invented finding ID rejected. |
| - `test_snippet_with_unknown_parameter_replaced_by_static_template` | **PASS** | Unvetted parameter replaced by static fallback. |
| - `test_missing_required_fields_replaced` | **PASS** | Incomplete items replaced by static template. |
| - `test_fake_provider_path_works` | **PASS** | Fake provider cleanly generates validated recommendations. |
| - `test_result_root_unchanged_when_generator_runs` | **PASS** | Consensus result root remains identical before and after. |
| - `test_acceptance_report_shows_labeled_recommendations_and_verifier_passes` | **PASS** | Report HTML contains labeled advisory recommendations and verifier Step 2 passes. |
| `backend/tests/test_reports.py` | **PASS** | 4/4 tests passed in 6.46s (including PDF export). |

---

## 3. Files Created or Modified
- `backend/reports/llm_advisor.py` (Advisory recommendation generator, allow-list extraction, validation, fake provider)
- `backend/reports/builder.py` (Integrated advisory recommendations into findings and report JSON)
- `backend/reports/templates/report.html` (Added labeled `[ADVISORY (NON-CONSENSUS)]` remediation card)
- `backend/tests/test_llm_recommendations.py` (7 tests for Prompt T3.2)
- `docs/audits/phase_t3_prompt3.2.md`
