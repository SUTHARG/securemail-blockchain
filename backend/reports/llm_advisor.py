"""Advisory LLM Recommendation Generator (Tier 3 / Prompt T3.2).

Strict Constraints:
1. Input: findings.json ONLY (never PCAP data, sessions, or evidence payloads).
2. Output JSON: List of {findingId, summary, steps}.
3. Validation:
   - Rejects items whose findingId is not in findings.json (hallucination rejection).
   - Rejects items with missing required fields (findingId, summary, steps).
   - Rejects configuration snippets containing parameter names not in allow-list from recommendations.yaml.
   - Any rejected item is replaced by the rule's static template from recommendations.yaml.
4. Interface with fake provider for testing and offline execution.
5. All generated text is marked 'Advisory'.
6. Consensus Result root is NEVER changed by this advisory generator.
"""
from abc import ABC, abstractmethod
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set
import yaml

import backend.config as config
from backend.reports.builder import load_recommendations

RECOMMENDATIONS_FILE = Path(__file__).resolve().parent / "recommendations.yaml"


def build_allowed_parameters_set(recs_file: Optional[Path] = None) -> Set[str]:
    """Builds allow-list of valid configuration parameter names from recommendations.yaml."""
    target_file = recs_file or RECOMMENDATIONS_FILE
    if not target_file.exists():
        return set()

    with open(target_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    allowed: Set[str] = set()
    for rule_data in data.get("rules", {}).values():
        for param in rule_data.get("parameters", []):
            allowed.add(param.strip().lower())
    return allowed


def extract_potential_parameters(text: str) -> Set[str]:
    """
    Extracts potential configuration parameter names from text or code snippets.
    Matches identifiers on the left side of '=' or directive-like words (e.g. smtpd_tls_security_level).
    """
    params: Set[str] = set()
    # Match key = value configurations
    for match in re.finditer(r"([a-zA-Z0-9_-]{3,})\s*=", text):
        params.add(match.group(1).lower())
    # Match -o key=value (Postfix master.cf style)
    for match in re.finditer(r"-o\s+([a-zA-Z0-9_-]{3,})\s*=", text):
        params.add(match.group(1).lower())
    return params


class LLMProvider(ABC):
    """Abstract interface for LLM recommendation generation."""

    @abstractmethod
    def generate(self, sanitized_findings_summary: List[Dict[str, Any]]) -> str:
        """Takes sanitized findings summary and returns JSON string."""
        pass


class FakeLLMProvider(LLMProvider):
    """
    Deterministic fake provider used for offline testing and evaluation.
    Can be configured with simulated hallucinations or disallowed parameters.
    """

    def __init__(
        self,
        hallucinate_finding_id: bool = False,
        inject_unknown_parameter: bool = False,
        omit_required_field: bool = False,
    ):
        self.hallucinate_finding_id = hallucinate_finding_id
        self.inject_unknown_parameter = inject_unknown_parameter
        self.omit_required_field = omit_required_field

    def generate(self, sanitized_findings_summary: List[Dict[str, Any]]) -> str:
        recommendations = []

        if self.hallucinate_finding_id:
            # Produce an item with a completely hallucinated finding ID
            recommendations.append({
                "findingId": "hallucinated_finding_id_00000000000000000000000000000000",
                "summary": "Fake summary for hallucinated finding.",
                "steps": ["Step 1: Check mail server.", "Step 2: Restart service."],
            })

        for item in sanitized_findings_summary:
            fid = item.get("findingId")
            rule_id = item.get("ruleId")

            if self.omit_required_field:
                # Omit 'steps' field to trigger missing-field rejection
                recommendations.append({
                    "findingId": fid,
                    "summary": f"Incomplete advisory recommendation for {rule_id}.",
                })
                continue

            if self.inject_unknown_parameter:
                # Inject a forbidden configuration parameter not in allow-list
                steps = [
                    "Open /etc/postfix/main.cf",
                    "Configure malicious_unvetted_param = disable_all_security",
                    "Reload postfix",
                ]
            else:
                # Use vetted parameter from rule if available
                steps = [
                    f"Review service configuration for endpoint {item.get('serverEndpoint')}.",
                    "Apply hardening directives specified in security baseline.",
                    "Verify with a new passive capture.",
                ]

            recommendations.append({
                "findingId": fid,
                "summary": f"Advisory remediation guidance for {rule_id} ({item.get('title')}).",
                "steps": steps,
            })

        return json.dumps(recommendations)


def get_static_fallback(
    rule_id: str,
    finding_id: str,
    static_rules: Dict[str, Any],
) -> Dict[str, Any]:
    """Generates fallback recommendation from static recommendations.yaml."""
    rule_info = static_rules.get(rule_id, {})
    title = rule_info.get("title", rule_id)
    explanation = rule_info.get("explanation", "Review configuration according to RFC guidelines.")
    config_fix = rule_info.get("configuration_fix", "")

    steps = [explanation]
    if config_fix:
        steps.append("Recommended configuration update:\n" + config_fix.strip())
    for url in rule_info.get("documentation_urls", []):
        steps.append(f"Reference: {url}")

    return {
        "findingId": finding_id,
        "summary": f"Static template recommendation for {rule_id}: {title}",
        "steps": steps,
        "isAdvisory": True,
        "source": "static_template_fallback",
    }


def validate_and_filter_recommendations(
    raw_output_text: str,
    findings: List[Dict[str, Any]],
    allowed_parameters: Optional[Set[str]] = None,
    static_rules: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Validates LLM output against specification rules:
    1. Rejects any item whose findingId is not in findings.json (hallucination rejection).
    2. Rejects any item with a missing required field (findingId, summary, steps).
    3. Rejects any item containing a parameter name not in allow-list from recommendations.yaml.
    4. Replaces any rejected or missing item with static template from recommendations.yaml.
    """
    allowed_params = (
        allowed_parameters if allowed_parameters is not None
        else build_allowed_parameters_set()
    )
    rules_dict = static_rules if static_rules is not None else load_recommendations()

    # Map findingId -> finding object
    valid_findings_map = {f.get("findingId"): f for f in findings if f.get("findingId")}

    # Parse JSON from LLM output
    parsed_items: List[Dict[str, Any]] = []
    try:
        data = json.loads(raw_output_text)
        if isinstance(data, list):
            parsed_items = data
        elif isinstance(data, dict) and "recommendations" in data and isinstance(data["recommendations"], list):
            parsed_items = data["recommendations"]
    except Exception:
        parsed_items = []

    validated_results: Dict[str, Dict[str, Any]] = {}

    for item in parsed_items:
        if not isinstance(item, dict):
            continue

        fid = item.get("findingId")
        summary = item.get("summary")
        steps = item.get("steps")

        # 1. Reject hallucinated findingId (must be in findings.json)
        if not fid or fid not in valid_findings_map:
            # Hallucinated item: completely rejected
            continue

        finding_obj = valid_findings_map[fid]
        rule_id = finding_obj.get("ruleId", "")

        # 2. Reject missing required fields
        if not summary or not steps or not isinstance(steps, list):
            validated_results[fid] = get_static_fallback(rule_id, fid, rules_dict)
            continue

        # 3. Check for disallowed parameter names in summary and steps
        all_text = str(summary) + "\n" + "\n".join(str(s) for s in steps)
        extracted_params = extract_potential_parameters(all_text)

        disallowed_found = False
        for param in extracted_params:
            if param not in allowed_params:
                disallowed_found = True
                break

        if disallowed_found:
            # Disallowed parameter: replace with static template
            validated_results[fid] = get_static_fallback(rule_id, fid, rules_dict)
            continue

        # Validated advisory recommendation
        validated_results[fid] = {
            "findingId": fid,
            "summary": str(summary),
            "steps": [str(s) for s in steps],
            "isAdvisory": True,
            "source": "advisory_llm",
        }

    # 4. Fill in static template for any findings that were missing or rejected
    final_output: List[Dict[str, Any]] = []
    for fid, finding_obj in valid_findings_map.items():
        if fid in validated_results:
            final_output.append(validated_results[fid])
        else:
            final_output.append(get_static_fallback(finding_obj.get("ruleId", ""), fid, rules_dict))

    return final_output


def generate_advisory_recommendations(
    findings: List[Dict[str, Any]],
    provider: Optional[LLMProvider] = None,
) -> List[Dict[str, Any]]:
    """
    Main entry point for advisory recommendation generation.
    Takes findings ONLY (never PCAP, sessions, or evidence payloads).
    Returns list of validated {findingId, summary, steps, isAdvisory: True}.
    """
    if not findings:
        return []

    # Sanitize input: extract findingId, ruleId, title, severity, serverEndpoint ONLY
    sanitized_input: List[Dict[str, Any]] = []
    static_rules = load_recommendations()
    for f in findings:
        rule_id = str(f.get("ruleId", ""))
        rule_info = static_rules.get(rule_id, {})
        sanitized_input.append({
            "findingId": str(f.get("findingId", "")),
            "ruleId": rule_id,
            "title": rule_info.get("title", rule_id),
            "severity": str(f.get("severity", "Info")),
            "serverEndpoint": str(f.get("serverEndpoint", "")),
        })

    active_provider = provider or FakeLLMProvider()
    raw_output = active_provider.generate(sanitized_input)

    return validate_and_filter_recommendations(
        raw_output_text=raw_output,
        findings=findings,
        static_rules=static_rules,
    )
