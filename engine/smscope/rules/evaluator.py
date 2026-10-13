"""Rule evaluator, evidence capping, and integer scoring for SecureMailScope."""
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import yaml

from engine.smscope.models import SessionRecord, Finding, Evidence
from engine.smscope.results.hashing import finding_id
from engine.smscope.rules.ruleset_hash import compute_ruleset_hash
from engine.smscope.tls.ciphers_generated import CIPHER_SUITES

SEVERITY_WEIGHTS: Dict[str, int] = {
    "Critical": 40,
    "High": 20,
    "Medium": 8,
    "Low": 2,
    "Info": 0,
}


def compute_exposure_factor(session_count: int) -> int:
    """Integer exposure factor from affected session count (Section 4.7)."""
    if session_count <= 1:
        return 1
    elif session_count <= 9:
        return 2
    else:
        return 3


def compute_grade(score: int) -> str:
    """Grade boundaries according to Section 4.7."""
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def calculate_host_score(findings: List[Finding]) -> Tuple[int, str]:
    """Calculate integer score (0-100) and grade for a host's findings."""
    total_deductions = 0
    for f in findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 0)
        exposure = compute_exposure_factor(f.sessionCount)
        total_deductions += weight * exposure

    score = max(0, 100 - total_deductions)
    grade = compute_grade(score)
    return score, grade


def load_ruleset(ruleset_path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Load ruleset configuration from YAML file."""
    if ruleset_path is None:
        ruleset_path = Path(__file__).resolve().parents[3] / "ruleset" / "ruleset.yaml"
    if not ruleset_path.exists():
        raise FileNotFoundError(f"Ruleset file not found: {ruleset_path}")

    with open(ruleset_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = {}
    for r in data.get("rules", []):
        rules[r["id"]] = r
    return rules


class RuleEvaluator:
    """Evaluates detection rules against session records."""

    def __init__(self, ruleset_path: Optional[Path] = None):
        self.ruleset = load_ruleset(ruleset_path)

    def evaluate(self, sessions: List[SessionRecord]) -> List[Finding]:
        """Evaluate all enabled rules and return deduplicated findings."""
        # Key: (rule_id, server_endpoint) -> { "sessions": set(), "evidence": list(), "details": dict(), "severity": Optional[str] }
        detections: Dict[Tuple[str, str], Dict[str, Any]] = {}

        def record(
            rule_id: str,
            session: SessionRecord,
            evidence_items: List[Evidence],
            details: Dict[str, Any],
            severity: Optional[str] = None,
        ):
            if rule_id not in self.ruleset:
                return
            if not self.ruleset[rule_id].get("enabled", True):
                return
            key = (rule_id, session.serverEndpoint)
            if key not in detections:
                detections[key] = {
                    "sessions": set(),
                    "evidence": [],
                    "details": {},
                    "severity": severity,
                }
            detections[key]["sessions"].add(session.sessionId)
            detections[key]["evidence"].extend(evidence_items)
            detections[key]["details"].update(details)
            if severity and not detections[key].get("severity"):
                detections[key]["severity"] = severity

        def record_multi(
            rule_id: str,
            server_endpoint: str,
            session_ids: Any,
            evidence_items: List[Evidence],
            details: Dict[str, Any],
            severity: Optional[str] = None,
        ):
            if rule_id not in self.ruleset:
                return
            if not self.ruleset[rule_id].get("enabled", True):
                return
            key = (rule_id, server_endpoint)
            if key not in detections:
                detections[key] = {
                    "sessions": set(),
                    "evidence": [],
                    "details": {},
                    "severity": severity,
                }
            detections[key]["sessions"].update(session_ids)
            detections[key]["evidence"].extend(evidence_items)
            detections[key]["details"].update(details)
            if severity and not detections[key].get("severity"):
                detections[key]["severity"] = severity

        for session in sessions:
            # R01 Critical: the session has any cleartextAuth entry
            if len(session.cleartextAuth) > 0:
                evs = [
                    Evidence(
                        sessionId=session.sessionId,
                        packetNumber=auth.packetNumber,
                        note=f"Cleartext {auth.mechanism} authentication",
                    )
                    for auth in session.cleartextAuth
                ]
                mechs = sorted(list({a.mechanism for a in session.cleartextAuth}))
                record("R01", session, evs, {"mechanisms": mechs})

            # R02 High: transportMode is plaintext and starttls.offered is false
            if session.transportMode == "plaintext" and not session.starttls.offered:
                evs = [
                    Evidence(
                        sessionId=session.sessionId,
                        packetNumber=1,
                        note="Plaintext mail session with STARTTLS not offered",
                    )
                ]
                record("R02", session, evs, {"protocol": session.protocol})

            # R03 High: starttls.offered is true, starttls.attempted is false, and transportMode is plaintext
            if (
                session.starttls.offered
                and not session.starttls.attempted
                and session.transportMode == "plaintext"
            ):
                evs = [
                    Evidence(
                        sessionId=session.sessionId,
                        packetNumber=1,
                        note="STARTTLS offered but client did not attempt it",
                    )
                ]
                record("R03", session, evs, {"outcome": session.starttls.outcome})

            # R04 High: starttls.outcome is refused and the session continued in plaintext
            if (
                session.starttls.attempted
                and session.starttls.outcome == "refused"
                and session.transportMode == "plaintext"
            ):
                evs = [
                    Evidence(
                        sessionId=session.sessionId,
                        packetNumber=1,
                        note="STARTTLS was refused and session continued in plaintext",
                    )
                ]
                record("R04", session, evs, {"outcome": session.starttls.outcome})

            # TLS-specific checks
            if session.tls is not None:
                # R05 Critical: negotiated version below TLS 1.0 (SSL 3.0 or earlier)
                if session.tls.version:
                    v_str = str(session.tls.version).upper()
                    if v_str in ["SSL 3.0", "SSL 2.0", "0X0300", "0X0002"] or v_str.startswith("SSL"):
                        evs = [
                            Evidence(
                                sessionId=session.sessionId,
                                packetNumber=1,
                                note=f"Negotiated insecure SSL version below TLS 1.0: {session.tls.version}",
                            )
                        ]
                        record("R05", session, evs, {"version": session.tls.version})

                # R06 High: the negotiated version is TLS 1.0 or TLS 1.1
                if session.tls.version in ["TLS 1.0", "TLS 1.1"]:
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Deprecated TLS version negotiated: {session.tls.version}",
                        )
                    ]
                    record("R06", session, evs, {"version": session.tls.version})

                # R07 Critical: cipher weakClass is NULL, EXPORT or anon
                if session.tls.cipherSuiteCode is not None:
                    c_entry = CIPHER_SUITES.get(session.tls.cipherSuiteCode, {})
                    weak_class = c_entry.get("weakClass")
                    if not weak_class and session.tls.cipherSuiteName:
                        c_name = session.tls.cipherSuiteName.upper()
                        if "NULL" in c_name:
                            weak_class = "NULL"
                        elif "EXPORT" in c_name:
                            weak_class = "EXPORT"
                        elif "ANON" in c_name or "A_NULL" in c_name or "_ANON" in c_name:
                            weak_class = "anon"
                    if weak_class in ["NULL", "EXPORT", "anon"]:
                        evs = [
                            Evidence(
                                sessionId=session.sessionId,
                                packetNumber=1,
                                note=f"Insecure cipher suite class: {weak_class} ({session.tls.cipherSuiteName})",
                            )
                        ]
                        record(
                            "R07",
                            session,
                            evs,
                            {
                                "cipherSuiteName": session.tls.cipherSuiteName,
                                "cipherSuiteCode": session.tls.cipherSuiteCode,
                                "weakClass": weak_class,
                            },
                        )

                # R08 High: cipher weakClass is RC4, DES or 3DES
                if session.tls.cipherSuiteName:
                    c_upper = session.tls.cipherSuiteName.upper()
                    if any(bad in c_upper for bad in ["RC4", "DES", "3DES"]):
                        evs = [
                            Evidence(
                                sessionId=session.sessionId,
                                packetNumber=1,
                                note=f"Insecure cipher suite negotiated: {session.tls.cipherSuiteName}",
                            )
                        ]
                        record(
                            "R08",
                            session,
                            evs,
                            {
                                "cipherSuiteName": session.tls.cipherSuiteName,
                                "cipherSuiteCode": session.tls.cipherSuiteCode,
                            },
                        )

                # R09 Medium: forwardSecrecy is false and kxType is RSA, DH or ECDH
                if session.tls.forwardSecrecy is False:
                    kx = (session.tls.kxType or "").upper()
                    if kx in ["RSA", "DH", "ECDH"] or not kx:
                        evs = [
                            Evidence(
                                sessionId=session.sessionId,
                                packetNumber=1,
                                note=f"Non-forward-secret key exchange: {session.tls.kxType or 'static'}",
                            )
                        ]
                        record("R09", session, evs, {"kxType": session.tls.kxType})

                # R10 Medium (High if below 1024 bits): DHE with kxGroupOrDhBits below 2048
                kx = (session.tls.kxType or "").upper()
                if "DHE" in kx:
                    bits = session.tls.kxGroupOrDhBits
                    if isinstance(bits, int) and 0 < bits < 2048:
                        sev = "High" if bits < 1024 else "Medium"
                        evs = [
                            Evidence(
                                sessionId=session.sessionId,
                                packetNumber=1,
                                note=f"DHE key exchange prime below 2048 bits: {bits} bits",
                            )
                        ]
                        record(
                            "R10",
                            session,
                            evs,
                            {"kxGroupOrDhBits": bits, "kxType": session.tls.kxType},
                            severity=sev,
                        )

                # R14 Medium: SNI present and no SAN matches it (not evaluable without SNI)
                if session.tls.sni and session.certificates:
                    leaf = session.certificates[0]
                    if "hostnameMismatch" in leaf.verdicts:
                        evs = [
                            Evidence(
                                sessionId=session.sessionId,
                                packetNumber=1,
                                note=f"Certificate SAN does not match requested SNI '{session.tls.sni}'",
                            )
                        ]
                        record(
                            "R14",
                            session,
                            evs,
                            {
                                "sni": session.tls.sni,
                                "san": leaf.san,
                                "certificateSha256": leaf.sha256,
                            },
                        )

                # R19 Info: certObservable is false
                if session.tls.certObservable is False:
                    reason = session.tls.certNotObservableReason or session.tls.version or "resumed"
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Certificate not observable: {reason}",
                        )
                    ]
                    record("R19", session, evs, {"reason": reason})

            # Certificate checks
            for cert in session.certificates:
                # R11 High: any observed certificate has notAfter earlier than capture time
                if "expired" in cert.verdicts or (
                    cert.notAfter is not None and session.firstPacketTs > cert.notAfter
                ):
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Certificate expired at capture time (notAfter={cert.notAfter}, captureTs={session.firstPacketTs})",
                        )
                    ]
                    record("R11", session, evs, {"certificateSha256": cert.sha256, "notAfter": cert.notAfter})

                # R12 High: any non-anchor observed certificate has an RSA key below 2048 bits or EC below 224 bits
                is_weak_rsa = cert.keyAlgorithm == "RSA" and cert.keySize < 2048
                is_weak_ec = cert.keyAlgorithm == "EC" and cert.keySize < 224
                if "weakKey" in cert.verdicts or is_weak_rsa or is_weak_ec:
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Weak key size: {cert.keyAlgorithm} {cert.keySize} bits",
                        )
                    ]
                    record(
                        "R12",
                        session,
                        evs,
                        {"certificateSha256": cert.sha256, "keyAlgorithm": cert.keyAlgorithm, "keySize": cert.keySize},
                    )

                # R13 High: any observed certificate that is not self-signed has an MD5 or SHA-1 signature hash
                is_self_signed = "selfSigned" in cert.verdicts or (cert.subject == cert.issuer)
                sig_lower = cert.signatureAlgorithm.lower()
                is_weak_sig = any(bad in sig_lower for bad in ["md5", "sha1", "sha-1"])
                if not is_self_signed and ("weakSignature" in cert.verdicts or is_weak_sig):
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Weak signature on certificate: {cert.signatureAlgorithm}",
                        )
                    ]
                    record(
                        "R13",
                        session,
                        evs,
                        {"certificateSha256": cert.sha256, "signatureAlgorithm": cert.signatureAlgorithm},
                    )

                # R15 Low: the chain verdict is unknownIssuer and the leaf is not self-signed
                if ("unknownIssuer" in cert.verdicts or "incompleteChain" in cert.verdicts) and not is_self_signed:
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Untrusted issuer: {cert.issuer}",
                        )
                    ]
                    record(
                        "R15",
                        session,
                        evs,
                        {"certificateSha256": cert.sha256, "issuer": cert.issuer},
                    )

            # R16 Medium: the leaf certificate is self-signed
            if session.certificates:
                leaf = session.certificates[0]
                if "selfSigned" in leaf.verdicts or leaf.subject == leaf.issuer:
                    evs = [
                        Evidence(
                            sessionId=session.sessionId,
                            packetNumber=1,
                            note=f"Self-signed leaf certificate: {leaf.subject}",
                        )
                    ]
                    record(
                        "R16",
                        session,
                        evs,
                        {"certificateSha256": leaf.sha256, "subject": leaf.subject},
                    )

        # Multi-session checks per server endpoint
        by_server: Dict[str, List[SessionRecord]] = {}
        for s in sessions:
            by_server.setdefault(s.serverEndpoint, []).append(s)

        for server_ep, s_list in by_server.items():
            # R17 Medium: STARTTLS advertised in some sessions and not in others for same serverEndpoint
            plain_sessions = [s for s in s_list if s.transportMode in ("plaintext", "starttls")]
            advertised = sorted([s.sessionId for s in plain_sessions if s.starttls.offered])
            not_advertised = sorted([s.sessionId for s in plain_sessions if not s.starttls.offered])

            if advertised and not_advertised:
                evs = []
                for s in plain_sessions:
                    if not s.starttls.offered and len(evs) < 5:
                        evs.append(
                            Evidence(
                                sessionId=s.sessionId,
                                packetNumber=1,
                                note="STARTTLS not advertised in this session",
                            )
                        )
                for s in plain_sessions:
                    if s.starttls.offered and len(evs) < 5:
                        evs.append(
                            Evidence(
                                sessionId=s.sessionId,
                                packetNumber=1,
                                note="STARTTLS advertised in this session",
                            )
                        )
                record_multi(
                    "R17",
                    server_ep,
                    set(advertised + not_advertised),
                    evs,
                    {
                        "advertisedSessionIds": advertised,
                        "notAdvertisedSessionIds": not_advertised,
                        "note": "indicator, not proof of stripping",
                    },
                )

            # R18 Medium: two or more distinct leaf certificate fingerprints for same server endpoint
            leaf_fps: Dict[str, List[int]] = {}
            for s in s_list:
                if s.certificates:
                    leaf_fp = s.certificates[0].sha256
                    leaf_fps.setdefault(leaf_fp, []).append(s.sessionId)

            if len(leaf_fps) >= 2:
                all_cert_sessions = set()
                evs = []
                for fp, s_ids in sorted(leaf_fps.items()):
                    all_cert_sessions.update(s_ids)
                    if len(evs) < 5:
                        evs.append(
                            Evidence(
                                sessionId=s_ids[0],
                                packetNumber=1,
                                note=f"Leaf certificate fingerprint: {fp[:16]}... ({len(s_ids)} sessions)",
                            )
                        )
                record_multi(
                    "R18",
                    server_ep,
                    all_cert_sessions,
                    evs,
                    {
                        "fingerprints": sorted(list(leaf_fps.keys())),
                        "sessionCountPerFingerprint": {k: len(v) for k, v in sorted(leaf_fps.items())},
                    },
                )

        # Assemble deduplicated findings
        findings: List[Finding] = []
        for (rule_id, server_endpoint), data in sorted(detections.items()):
            rule_meta = self.ruleset[rule_id]
            f_id = finding_id(rule_id, server_endpoint)
            sorted_session_ids = sorted(list(data["sessions"]))

            # Deterministic sorting and deduplication of evidence items
            # Ascending sessionId, packetNumber, note
            seen_evidence = set()
            unique_evidence = []
            for e in sorted(
                data["evidence"],
                key=lambda ev: (ev.sessionId, ev.packetNumber, ev.note),
            ):
                ev_key = (e.sessionId, e.packetNumber, e.note)
                if ev_key not in seen_evidence:
                    seen_evidence.add(ev_key)
                    unique_evidence.append(e)

            # Cap evidence at <= 5 entries
            capped_evidence = unique_evidence[:5]
            finding_severity = data.get("severity") or rule_meta["severity"]

            findings.append(
                Finding(
                    findingId=f_id,
                    ruleId=rule_id,
                    severity=finding_severity,
                    serverEndpoint=server_endpoint,
                    sortedSessionIds=sorted_session_ids,
                    sessionCount=len(sorted_session_ids),
                    evidence=capped_evidence,
                    details=data["details"],
                )
            )

        # Sort findings by findingId for determinism
        findings.sort(key=lambda f: f.findingId)
        return findings


def evaluate_rules(sessions: List[SessionRecord], ruleset_path: Optional[Path] = None) -> List[Finding]:
    """Convenience function to evaluate rules."""
    evaluator = RuleEvaluator(ruleset_path)
    return evaluator.evaluate(sessions)
