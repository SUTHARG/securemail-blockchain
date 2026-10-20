"""Report builder constructing canonical JSON and Jinja2 HTML reports (Prompt 7.1)."""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

import backend.config as config
from backend.database import get_case, get_chain_txs
from backend.storage import get_case_dir, read_case_json
from engine.smscope.results.canonical import canonical_json
from engine.smscope.results.hashing import finding_leaf, host_score_leaf
from engine.smscope.results.merkle import MerkleTree

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
RECOMMENDATIONS_FILE = Path(__file__).resolve().parent / "recommendations.yaml"

SEVERITY_WEIGHTS: Dict[str, int] = {
    "Critical": 40,
    "High": 20,
    "Medium": 8,
    "Low": 2,
    "Info": 0,
}


def load_recommendations() -> Dict[str, Dict[str, Any]]:
    """Load static remediation templates from recommendations.yaml."""
    if not RECOMMENDATIONS_FILE.exists():
        return {}
    with open(RECOMMENDATIONS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("rules", {})


def compute_exposure_factor(session_count: int) -> int:
    """Integer exposure factor based on affected session count."""
    if session_count >= 10:
        return 3
    elif session_count >= 2:
        return 2
    return 1


def build_case_report(
    case_id: str,
    save: bool = True,
    gateway_override: Optional[Any] = None,
) -> Tuple[Dict[str, Any], bytes, str, str]:
    """
    Builds deterministic report.json and self-contained report.html.

    Returns:
        (report_dict, canonical_bytes, report_sha256_hex, html_content)
    """
    case_dir = get_case_dir(case_id)
    case_record = get_case(case_id) or {}
    manifest = read_case_json(case_id, "manifest.json") or {}
    raw_findings = read_case_json(case_id, "findings.json") or []
    host_scores = read_case_json(case_id, "host_scores.json") or []
    raw_sessions = read_case_json(case_id, "sessions.json") or []
    from engine.smscope.models import SessionRecord
    sessions = [
        SessionRecord.from_dict(s).to_dict(include_extended=True) if isinstance(s, dict) else s
        for s in raw_sessions
    ]
    result = read_case_json(case_id, "result.json") or {}
    tx_rows = get_chain_txs(case_id)

    # 1. Base Identifiers
    pcap_path = case_dir / "pcap.bin"
    actual_pcap_sha = ""
    pcap_read_error = ""
    if not pcap_path.exists():
        pcap_read_error = "Stored PCAP file missing on disk"
    else:
        try:
            from validator.crypto import decrypt_at_rest
            raw_pcap_bytes = pcap_path.read_bytes()
            decrypted_bytes = decrypt_at_rest(raw_pcap_bytes)
            actual_pcap_sha = hashlib.sha256(decrypted_bytes).hexdigest().lower()
        except Exception as exc:
            actual_pcap_sha = ""
            pcap_read_error = f"PCAP decryption failed: {exc}"

    db_pcap_hash = (case_record.get("pcap_sha256") or manifest.get("pcapSha256") or "").lower()
    pcap_hash = actual_pcap_sha or db_pcap_hash

    engine_version = str(manifest.get("engineVersion") or "0.1.0")
    ruleset_hash = str(manifest.get("rulesetHash") or "")
    result_root = str(result.get("resultRoot") or manifest.get("resultRoot") or "")

    # Tx hashes mapping
    tx_hashes: Dict[str, str] = {}
    for tx in tx_rows:
        tx_hashes[tx["step"]] = tx["tx_hash"]
    if "txHashes" in manifest and isinstance(manifest["txHashes"], dict):
        for k, v in manifest["txHashes"].items():
            if k not in tx_hashes and v:
                tx_hashes[k] = str(v)

    # 2. Recommendations & Findings Prioritization (Static + Advisory Prompt T3.2)
    recommendations = load_recommendations()
    try:
        from backend.reports.llm_advisor import generate_advisory_recommendations
        advisory_recs = generate_advisory_recommendations(raw_findings)
        advisory_by_fid = {r["findingId"]: r for r in advisory_recs}
    except Exception:
        advisory_recs = []
        advisory_by_fid = {}

    prioritized_findings: List[Dict[str, Any]] = []

    for f in raw_findings:
        fid = str(f.get("findingId", ""))
        rule_id = str(f.get("ruleId", ""))
        severity = str(f.get("severity", "Info"))
        session_count = int(f.get("sessionCount", 1))
        exposure = compute_exposure_factor(session_count)
        f_rec = recommendations.get(rule_id)
        adv_rec = advisory_by_fid.get(fid)

        evidence_list: List[Dict[str, Any]] = []
        for ev in f.get("evidence", []):
            evidence_list.append({
                "sessionId": int(ev.get("sessionId", 0)),
                "packetNumber": int(ev.get("packetNumber", 0)),
                "note": str(ev.get("note", "")),
            })

        # Ensure no credential content in details
        clean_details = {k: v for k, v in f.get("details", {}).items() if "auth" not in k.lower() and "pass" not in k.lower()}

        finding_obj: Dict[str, Any] = {
            "findingId": fid,
            "ruleId": rule_id,
            "title": f_rec.get("title", rule_id) if f_rec else rule_id,
            "severity": severity,
            "serverEndpoint": str(f.get("serverEndpoint", "")),
            "sessionCount": session_count,
            "exposureFactor": exposure,
            "sortedSessionIds": [int(s) for s in f.get("sortedSessionIds", [])],
            "evidence": evidence_list,
            "details": clean_details,
            "recommendation": f_rec,
            "advisoryRecommendation": adv_rec,
        }
        prioritized_findings.append(finding_obj)

    # Sort strictly: severity desc, exposure desc, ruleId asc, serverEndpoint asc
    prioritized_findings.sort(
        key=lambda item: (
            -SEVERITY_WEIGHTS.get(item["severity"], 0),
            -item["exposureFactor"],
            item["ruleId"],
            item["serverEndpoint"],
        )
    )

    # 3. Host Scores (sorted by hostId ascending)
    sorted_host_scores: List[Dict[str, Any]] = []
    for h in host_scores:
        sorted_host_scores.append({
            "hostId": str(h.get("hostId", "")),
            "serverEndpoint": str(h.get("serverEndpoint", "")),
            "score": int(h.get("score", 0)),
            "grade": str(h.get("grade", "F")),
            "findingsDigest": str(h.get("findingsDigest", "")),
        })
    sorted_host_scores.sort(key=lambda item: item["hostId"])

    # 4. Session & TLS Summary
    protocol_counts: Dict[str, int] = {}
    tls_version_counts: Dict[str, int] = {}
    cipher_counts: Dict[str, int] = {}
    server_tls_stats: Dict[str, Dict[str, int]] = {}

    for s in sessions:
        proto = str(s.get("protocol", "UNKNOWN"))
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        endpoint = str(s.get("serverEndpoint", ""))
        if endpoint not in server_tls_stats:
            server_tls_stats[endpoint] = {"forwardSecrecyCount": 0, "totalTls": 0}

        tls_info = s.get("tls")
        if tls_info:
            server_tls_stats[endpoint]["totalTls"] += 1
            ver = str(tls_info.get("version") or "Unknown")
            tls_version_counts[ver] = tls_version_counts.get(ver, 0) + 1

            cipher = str(tls_info.get("cipherSuiteName") or "Unknown")
            cipher_counts[cipher] = cipher_counts.get(cipher, 0) + 1

            if tls_info.get("forwardSecrecy"):
                server_tls_stats[endpoint]["forwardSecrecyCount"] += 1
        else:
            tls_version_counts["None"] = tls_version_counts.get("None", 0) + 1

    forward_secrecy_share: Dict[str, Dict[str, int]] = {}
    for ep, stats in sorted(server_tls_stats.items()):
        total = stats["totalTls"]
        fs_count = stats["forwardSecrecyCount"]
        share = int(round(100 * fs_count / total)) if total > 0 else 0
        forward_secrecy_share[ep] = {
            "forwardSecrecyCount": fs_count,
            "totalTls": total,
            "sharePercent": share,
        }

    session_summary: Dict[str, Any] = {
        "totalSessions": len(sessions),
        "protocols": dict(sorted(protocol_counts.items())),
        "tlsVersions": dict(sorted(tls_version_counts.items())),
        "cipherSuites": dict(sorted(cipher_counts.items())),
        "forwardSecrecyShare": forward_secrecy_share,
    }

    # 5. Certificates Table (unique by sha256 fingerprint, sorted)
    cert_map: Dict[str, Dict[str, Any]] = {}
    for s in sessions:
        ep = str(s.get("serverEndpoint", ""))
        for cert in s.get("certificates", []):
            fp = str(cert.get("sha256", ""))
            if fp and fp not in cert_map:
                cert_map[fp] = {
                    "fingerprintSha256": fp,
                    "subject": str(cert.get("subject", "")),
                    "issuer": str(cert.get("issuer", "")),
                    "notBefore": int(cert.get("notBefore", 0)),
                    "notAfter": int(cert.get("notAfter", 0)),
                    "keyAlgorithm": str(cert.get("keyAlgorithm", "")),
                    "keySize": int(cert.get("keySize", 0)),
                    "signatureAlgorithm": str(cert.get("signatureAlgorithm", "")),
                    "san": sorted([str(x) for x in cert.get("san", [])]),
                    "isCa": bool(cert.get("isCa", False)),
                    "verdicts": sorted([str(x) for x in cert.get("verdicts", [])]),
                    "serverEndpoint": ep,
                }
    certificates_table = [cert_map[k] for k in sorted(cert_map.keys())]

    # 6. Visibility Limits
    tls13_count = 0
    resumed_count = 0
    no_sni_count = 0
    incomplete_count = 0
    contiguous_count = 0
    terminated_count = 0
    confirmed_complete_count = 0
    parse_errors_count = 0

    for s in sessions:
        tls_info = s.get("tls")
        if tls_info:
            if tls_info.get("version") == "TLS 1.3":
                tls13_count += 1
            if tls_info.get("resumed"):
                resumed_count += 1
            if not tls_info.get("sni"):
                no_sni_count += 1
        if not s.get("streamComplete", True):
            incomplete_count += 1
        if s.get("streamContiguous", s.get("streamComplete", True)):
            contiguous_count += 1
        if s.get("streamTerminated", False):
            terminated_count += 1
        if s.get("confirmedComplete", False):
            confirmed_complete_count += 1
        if s.get("protocol") == "UNKNOWN":
            parse_errors_count += 1

    visibility_limits: Dict[str, Any] = {
        "tls13Count": tls13_count,
        "resumedCount": resumed_count,
        "noSniCount": no_sni_count,
        "incompleteStreamsCount": incomplete_count,
        "contiguousStreamsCount": contiguous_count,
        "terminatedStreamsCount": terminated_count,
        "confirmedCompleteStreamsCount": confirmed_complete_count,
        "parseErrorsCount": parse_errors_count,
        "summary": "Passive network capture cannot observe X.509 certificates in TLS 1.3 encrypted handshakes or resumed sessions, and unobserved payload is never evaluated.",
    }

    # 7. On-Chain State & Verifier Steps
    onchain_state: Dict[str, Any] = {
        "status": case_record.get("status") or "Finalized",
        "onchainId": case_record.get("onchain_case_id") or case_record.get("onchain_id") or "",
        "reportHash": None,
        "finalRoot": result_root,
    }

    # Calculate five verifier steps
    step1_pass = False
    if pcap_read_error:
        step1_status = "FAIL"
        step1_details = pcap_read_error
    else:
        step1_status = "PENDING"
        step1_details = "Case not yet opened on-chain"
    step2_pass = False
    step3_pass = False
    step4_pass = False
    step4_details = "Posture not yet recorded on-chain"
    step5_pass = False

    # Step 2: Merkle rebuild check
    try:
        leaf_bytes_list: List[bytes] = []
        for f in raw_findings:
            leaf_bytes_list.append(finding_leaf(canonical_json(f)))
        for h in host_scores:
            leaf_bytes_list.append(host_score_leaf(h["hostId"], h["findingsDigest"], int(h["score"])))
        if leaf_bytes_list:
            recomputed_tree = MerkleTree(leaf_bytes_list)
            step2_pass = (recomputed_tree.root_hex.lower().replace("0x", "") == result_root.lower().replace("0x", ""))
    except Exception:
        step2_pass = False

    # Check on-chain contracts if gateway available
    onchain_info = None
    try:
        from backend.app import get_gateway
        gateway = gateway_override or get_gateway()
        onchain_info = gateway.get_chain_status(case_id)
        if onchain_info:
            onchain_state["status"] = onchain_info.get("stateName", onchain_state["status"])
            onchain_id_val = onchain_info.get("onchainCaseId") or case_record.get("onchain_case_id")
            raw_onchain_pcap = onchain_info.get("pcapHash")
            onchain_pcap = (raw_onchain_pcap or "").replace("0x", "").lower()
            if pcap_read_error:
                step1_pass = False
                step1_status = "FAIL"
                step1_details = pcap_read_error
            elif not onchain_id_val:
                step1_pass = False
                step1_status = "PENDING"
                step1_details = "Case not yet opened on-chain"
            elif not onchain_pcap or onchain_pcap == "0" * 64:
                step1_pass = False
                step1_status = "FAIL"
                step1_details = "On-chain pcapHash is missing or zero for opened case"
            elif not actual_pcap_sha:
                step1_pass = False
                step1_status = "FAIL"
                step1_details = pcap_read_error or "Stored PCAP file missing or unreadable on disk"
            elif db_pcap_hash and actual_pcap_sha != db_pcap_hash:
                step1_pass = False
                step1_status = "FAIL"
                step1_details = "Decrypted PCAP hash does not match stored case record"
            elif actual_pcap_sha == onchain_pcap:
                step1_pass = True
                step1_status = "PASS"
                step1_details = f"PCAP SHA-256 matches on-chain pcapHash: {actual_pcap_sha[:16]}..."
            else:
                step1_pass = False
                step1_status = "FAIL"
                step1_details = "PCAP SHA-256 does not match on-chain pcapHash"

            onchain_root = (onchain_info.get("finalRoot") or "").replace("0x", "").lower()
            if onchain_root and onchain_root != "0" * 64:
                step3_pass = (result_root.lower().replace("0x", "") == onchain_root)
            else:
                step3_pass = False

            onchain_report = (onchain_info.get("reportHash") or "").replace("0x", "").lower()
            if onchain_report and onchain_report != "0" * 64:
                onchain_state["reportHash"] = "0x" + onchain_report

            # Step 4 check: Walk and verify PostureLedger records
            if onchain_info.get("stateName") == "Finalized" and len(host_scores) > 0 and gateway.posture_ledger:
                try:
                    from backend.chain.verifier import verify_posture_ledger_hash_chain
                    case_hex = case_record.get("onchain_case_id") or case_id
                    case_bytes = bytes.fromhex(case_hex.replace("0x", ""))
                    result_root_bytes = bytes.fromhex(result_root.replace("0x", "")) if result_root else bytes(32)
                    step4_pass, step4_details = verify_posture_ledger_hash_chain(
                        posture_ledger_contract=gateway.posture_ledger,
                        onchain_case_bytes=case_bytes,
                        result_root_bytes=result_root_bytes,
                        expected_host_scores=host_scores,
                        w3_instance=getattr(gateway, "w3", None),
                    )
                    if step4_pass:
                        step4_status = "PASS"
                    else:
                        details_lower = step4_details.lower()
                        if "no posture records on-chain" in details_lower or "not yet recorded" in details_lower:
                            step4_status = "PENDING"
                        else:
                            step4_status = "FAIL"
                except Exception as exc:
                    step4_pass = False
                    step4_status = "FAIL"
                    step4_details = f"PostureLedger verification error: {exc}"
            else:
                step4_pass = False
                step4_status = "PENDING"
                step4_details = "Posture not yet recorded on-chain"
    except Exception:
        step1_pass = False
        step3_pass = False
        step4_pass = False
        step4_status = "PENDING"

    # 7.5 Advisory Anomaly Detection (Prompt T2.4: strictly non-consensus, outside result root)
    advisory_flagged: List[Dict[str, Any]] = []
    advisory_model_path = Path(__file__).resolve().parents[2] / "advisory" / "anomaly" / "model.joblib"
    advisory_summary_path = Path(__file__).resolve().parents[2] / "advisory" / "anomaly" / "baseline_summary.json"
    if advisory_model_path.exists() and advisory_summary_path.exists() and sessions:
        try:
            from advisory.anomaly.detector import AnomalyDetector
            detector = AnomalyDetector(advisory_model_path, advisory_summary_path)
            for s in sessions:
                scored = detector.score_session(s)
                if scored.get("isAnomaly"):
                    clean_scored = {
                        "sessionId": int(scored["sessionId"]),
                        "serverEndpoint": str(scored["serverEndpoint"]),
                        "anomalyScore": f"{float(scored['anomalyScore']):.4f}",
                        "isAnomaly": bool(scored["isAnomaly"]),
                        "topDeviatingFeatures": list(scored["topDeviatingFeatures"]),
                        "explanationNote": str(scored["explanationNote"]),
                    }
                    advisory_flagged.append(clean_scored)
        except Exception:
            pass

    advisory_section: Dict[str, Any] = {
        "isConsensus": False,
        "onChain": False,
        "disclaimer": "Advisory Anomaly Detection is off-chain, strictly outside consensus quorum, and not part of the Merkle result root.",
        "flaggedCount": len(advisory_flagged),
        "totalSessions": len(sessions),
        "flaggedSessions": advisory_flagged,
    }

    # 8. Assemble Stable, Immutable Report Payload
    # Exclude mutable live chain state and later transactions so anchored report cannot drift.
    canonical_report_payload: Dict[str, Any] = {
        "caseId": case_id,
        "pcapHash": pcap_hash,
        "engineVersion": engine_version,
        "rulesetHash": ruleset_hash,
        "resultRoot": result_root,
        "hostScores": sorted_host_scores,
        "findings": prioritized_findings,
        "sessionSummary": session_summary,
        "certificates": certificates_table,
        "visibilityLimits": visibility_limits,
        "recommendations": {f["ruleId"]: f["recommendation"] for f in prioritized_findings if f.get("recommendation")},
        "advisoryRecommendations": advisory_recs,
        "advisory": advisory_section,
    }

    # Deterministic serialization & hashing of the stable core payload
    canonical_bytes = canonical_json(canonical_report_payload)
    report_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    # Step 5: Report SHA-256 vs Anchored reportHash
    anchored_hex = (onchain_state.get("reportHash") or "").lower().replace("0x", "")
    if anchored_hex and anchored_hex != "0" * 64:
        step5_pass = (report_sha256.lower() == anchored_hex)
        step5_status = "PASS" if step5_pass else "FAIL"
        step5_details = "Report hash matches anchored reportHash" if step5_pass else f"Report SHA-256 ({report_sha256[:16]}...) does not match anchored reportHash ({anchored_hex[:16]}...)"
    else:
        step5_pass = False
        step5_status = "PENDING"
        step5_details = "Report not yet anchored on-chain"

    verifier_steps: List[Dict[str, Any]] = [
        {
            "step": 1,
            "name": "PCAP SHA-256 vs On-Chain pcapHash",
            "status": step1_status,
            "details": step1_details,
        },
        {
            "step": 2,
            "name": "Off-Chain Leaves & Root Rebuild",
            "status": "PASS" if step2_pass else ("PENDING" if not result_root else "FAIL"),
            "details": (f"Rebuilt Root matches resultRoot: {result_root[:16]}..." if step2_pass else ("Local analysis pending: result.json not yet generated" if not result_root else "Tree rebuild mismatch: computed root does not match stored resultRoot")),
        },
        {
            "step": 3,
            "name": "Result Root vs On-Chain finalRoot",
            "status": "PASS" if step3_pass else ("PENDING" if not onchain_info or not onchain_info.get("finalRoot") else "FAIL"),
            "details": "Verified against CaseRegistry" if step3_pass else "Not yet finalized on-chain or root mismatch",
        },
        {
            "step": 4,
            "name": "PostureLedger Hash Chain Walk",
            "status": step4_status,
            "details": step4_details,
        },
        {
            "step": 5,
            "name": "Report SHA-256 vs Anchored reportHash",
            "status": step5_status,
            "details": step5_details,
        },
    ]

    # Assemble report dict with status envelope for HTML rendering & API clients
    report_dict: Dict[str, Any] = dict(canonical_report_payload)
    report_dict["reportHash"] = report_sha256
    report_dict["txHashes"] = tx_hashes
    report_dict["onChainState"] = onchain_state
    report_dict["verifierSteps"] = verifier_steps
    report_dict["statusEnvelope"] = {
        "txHashes": tx_hashes,
        "onChainState": onchain_state,
        "verifierSteps": verifier_steps,
    }

    # 9. Render Jinja2 HTML
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    html_content = template.render(report=report_dict)

    # 10. Persistence
    if save:
        report_json_path = case_dir / "report.json"
        with open(report_json_path, "wb") as f:
            f.write(canonical_bytes)

        report_status_path = case_dir / "report_status.json"
        with open(report_status_path, "wb") as f:
            f.write(canonical_json(report_dict["statusEnvelope"]))

        report_html_path = case_dir / "report.html"
        with open(report_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Update manifest.json with reportHash
        manifest["reportHash"] = report_sha256
        with open(case_dir / "manifest.json", "wb") as f:
            f.write(canonical_json(manifest))

    return report_dict, canonical_bytes, report_sha256, html_content
