"""Unit, boundary, and determinism tests for Tier 1 detection rules and integer scoring."""
import random
from typing import List, Optional
import pytest

from engine.smscope.models import (
    CertificateInfo,
    CleartextAuth,
    Evidence,
    Finding,
    SessionRecord,
    StarttlsInfo,
    TlsInfo,
)
from engine.smscope.rules.evaluator import (
    RuleEvaluator,
    evaluate_rules,
    calculate_host_score,
    compute_exposure_factor,
    compute_grade,
    SEVERITY_WEIGHTS,
)


def make_synthetic_session(
    session_id: int = 1,
    server_endpoint: str = "172.28.0.10:25",
    transport_mode: str = "starttls",
    starttls_offered: bool = True,
    starttls_attempted: bool = True,
    starttls_outcome: str = "succeeded",
    cleartext_auth: Optional[List[CleartextAuth]] = None,
    tls_info: Optional[TlsInfo] = None,
    certificates: Optional[List[CertificateInfo]] = None,
    first_packet_ts: int = 1700000000,
) -> SessionRecord:
    """Helper to synthesize SessionRecord instances for rule unit tests."""
    return SessionRecord(
        sessionId=session_id,
        clientEndpoint="172.28.0.20:45000",
        serverEndpoint=server_endpoint,
        protocol="smtp",
        protocolSource="port",
        transportMode=transport_mode,
        streamComplete=True,
        firstPacketTs=first_packet_ts,
        starttls=StarttlsInfo(
            offered=starttls_offered,
            attempted=starttls_attempted,
            outcome=starttls_outcome,
        ),
        cleartextAuth=cleartext_auth or [],
        tls=tls_info,
        certificates=certificates or [],
    )


# ---------------------------------------------------------------------------
# Individual Tier 1 Rule Unit Tests (Synthetic Sessions)
# ---------------------------------------------------------------------------


class TestTier1Rules:
    """Test every Tier 1 rule in isolation using synthetic session records."""

    def test_rule_r01_cleartext_auth(self):
        """R01 (Critical): Cleartext credentials sent before encryption."""
        sess = make_synthetic_session(
            transport_mode="plaintext",
            starttls_offered=False,
            cleartext_auth=[
                CleartextAuth(mechanism="PLAIN", packetNumber=4),
                CleartextAuth(mechanism="LOGIN", packetNumber=8),
            ],
        )
        findings = evaluate_rules([sess])
        r01_findings = [f for f in findings if f.ruleId == "R01"]
        assert len(r01_findings) == 1
        f = r01_findings[0]
        assert f.severity == "Critical"
        assert f.sessionCount == 1
        assert len(f.evidence) == 2
        assert f.evidence[0].packetNumber == 4
        assert f.evidence[1].packetNumber == 8
        assert f.details["mechanisms"] == ["LOGIN", "PLAIN"]

    def test_rule_r02_plaintext_no_starttls(self):
        """R02 (High): Mail session with no encryption and STARTTLS not offered."""
        sess = make_synthetic_session(
            transport_mode="plaintext",
            starttls_offered=False,
            starttls_attempted=False,
            starttls_outcome="notOffered",
        )
        findings = evaluate_rules([sess])
        r02_findings = [f for f in findings if f.ruleId == "R02"]
        assert len(r02_findings) == 1
        assert r02_findings[0].severity == "High"

    def test_rule_r03_starttls_offered_not_attempted(self):
        """R03 (High): STARTTLS offered but never attempted."""
        sess = make_synthetic_session(
            transport_mode="plaintext",
            starttls_offered=True,
            starttls_attempted=False,
            starttls_outcome="ignored",
        )
        findings = evaluate_rules([sess])
        r03_findings = [f for f in findings if f.ruleId == "R03"]
        assert len(r03_findings) == 1
        assert r03_findings[0].severity == "High"
        assert r03_findings[0].details["outcome"] == "ignored"

    def test_rule_r06_deprecated_tls_version(self):
        """R06 (High): TLS 1.0 or 1.1 negotiated."""
        sess_tls10 = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="TLS 1.0",
                forwardSecrecy=True,
                kxType="ECDHE",
            )
        )
        findings = evaluate_rules([sess_tls10])
        r06_findings = [f for f in findings if f.ruleId == "R06"]
        assert len(r06_findings) == 1
        assert r06_findings[0].severity == "High"
        assert r06_findings[0].details["version"] == "TLS 1.0"

    def test_rule_r08_insecure_ciphers(self):
        """R08 (High): RC4, DES, or 3DES cipher suite."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="TLS 1.2",
                cipherSuiteName="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                cipherSuiteCode=0x000A,
                forwardSecrecy=True,
                kxType="ECDHE",
            )
        )
        findings = evaluate_rules([sess])
        r08_findings = [f for f in findings if f.ruleId == "R08"]
        assert len(r08_findings) == 1
        assert r08_findings[0].severity == "High"
        assert r08_findings[0].details["cipherSuiteName"] == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

    def test_rule_r09_no_forward_secrecy(self):
        """R09 (Medium): No forward secrecy (static RSA or static DH)."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="TLS 1.2",
                cipherSuiteName="TLS_RSA_WITH_AES_256_GCM_SHA384",
                cipherSuiteCode=0x009D,
                forwardSecrecy=False,
                kxType="RSA",
            )
        )
        findings = evaluate_rules([sess])
        r09_findings = [f for f in findings if f.ruleId == "R09"]
        assert len(r09_findings) == 1
        assert r09_findings[0].severity == "Medium"
        assert r09_findings[0].details["kxType"] == "RSA"

    def test_rule_r11_expired_certificate(self):
        """R11 (High): Certificate expired at capture time."""
        cert = CertificateInfo(
            sha256="aa" * 32,
            subject="CN=mail.lab.local",
            issuer="CN=Root CA",
            notBefore=1500000000,
            notAfter=1600000000,  # Expired relative to capture_ts=1700000000
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["mail.lab.local"],
            isCa=False,
            verdicts=["expired"],
        )
        sess = make_synthetic_session(
            first_packet_ts=1700000000,
            certificates=[cert],
        )
        findings = evaluate_rules([sess])
        r11_findings = [f for f in findings if f.ruleId == "R11"]
        assert len(r11_findings) == 1
        assert r11_findings[0].severity == "High"

    def test_rule_r12_weak_key(self):
        """R12 (High): RSA key below 2048 bits or EC key below 224 bits."""
        cert = CertificateInfo(
            sha256="bb" * 32,
            subject="CN=mail.lab.local",
            issuer="CN=Root CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=1024,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["mail.lab.local"],
            isCa=False,
            verdicts=["weakKey"],
        )
        sess = make_synthetic_session(certificates=[cert])
        findings = evaluate_rules([sess])
        r12_findings = [f for f in findings if f.ruleId == "R12"]
        assert len(r12_findings) == 1
        assert r12_findings[0].severity == "High"
        assert r12_findings[0].details["keySize"] == 1024

    def test_rule_r13_weak_signature(self):
        """R13 (High): MD5 or SHA-1 signature on non-self-signed certificate."""
        cert = CertificateInfo(
            sha256="cc" * 32,
            subject="CN=mail.lab.local",
            issuer="CN=Intermediate CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha1WithRSAEncryption",
            san=["mail.lab.local"],
            isCa=False,
            verdicts=["weakSignature"],
        )
        sess = make_synthetic_session(certificates=[cert])
        findings = evaluate_rules([sess])
        r13_findings = [f for f in findings if f.ruleId == "R13"]
        assert len(r13_findings) == 1
        assert r13_findings[0].severity == "High"

    def test_rule_r15_unknown_issuer(self):
        """R15 (Low): Unknown issuer / incomplete chain and leaf is not self-signed."""
        cert = CertificateInfo(
            sha256="dd" * 32,
            subject="CN=mail.lab.local",
            issuer="CN=Untrusted Rogue CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["mail.lab.local"],
            isCa=False,
            verdicts=["unknownIssuer"],
        )
        sess = make_synthetic_session(certificates=[cert])
        findings = evaluate_rules([sess])
        r15_findings = [f for f in findings if f.ruleId == "R15"]
        assert len(r15_findings) == 1
        assert r15_findings[0].severity == "Low"

    def test_rule_r16_self_signed_leaf(self):
        """R16 (Medium): Self-signed leaf certificate."""
        cert = CertificateInfo(
            sha256="ee" * 32,
            subject="CN=mail.lab.local",
            issuer="CN=mail.lab.local",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["mail.lab.local"],
            isCa=False,
            verdicts=["selfSigned", "unknownIssuer"],
        )
        sess = make_synthetic_session(certificates=[cert])
        findings = evaluate_rules([sess])
        r16_findings = [f for f in findings if f.ruleId == "R16"]
        r15_findings = [f for f in findings if f.ruleId == "R15"]
        assert len(r16_findings) == 1
        assert r16_findings[0].severity == "Medium"
        # R15 should NOT fire when leaf is self-signed
        assert len(r15_findings) == 0

    def test_rule_r19_cert_not_observable(self):
        """R19 (Info): Certificate not observable (TLS 1.3 or session resumption)."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=False,
                version="TLS 1.3",
                forwardSecrecy=True,
                kxType="ECDHE",
                certNotObservableReason="tls13",
            )
        )
        findings = evaluate_rules([sess])
        r19_findings = [f for f in findings if f.ruleId == "R19"]
        assert len(r19_findings) == 1
        assert r19_findings[0].severity == "Info"
        assert r19_findings[0].details["reason"] == "tls13"

    def test_rule_r04_refused_starttls(self):
        """R04 (High): STARTTLS refused and session continued in plaintext."""
        sess = make_synthetic_session(
            transport_mode="plaintext",
            starttls_offered=True,
            starttls_attempted=True,
            starttls_outcome="refused",
        )
        findings = evaluate_rules([sess])
        r04 = [f for f in findings if f.ruleId == "R04"]
        assert len(r04) == 1
        assert r04[0].severity == "High"

    def test_rule_r05_ssl_3_0(self):
        """R05 (Critical): Negotiated version below TLS 1.0 (SSL 3.0)."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="SSL 3.0",
                cipherSuiteCode=0x002F,
                cipherSuiteName="TLS_RSA_WITH_AES_128_CBC_SHA",
            )
        )
        findings = evaluate_rules([sess])
        r05 = [f for f in findings if f.ruleId == "R05"]
        assert len(r05) == 1
        assert r05[0].severity == "Critical"

    def test_rule_r07_weak_cipher_class(self):
        """R07 (Critical): Cipher weakClass is NULL, EXPORT or anon."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=False,
                version="TLS 1.2",
                cipherSuiteCode=0x0034,  # TLS_DH_anon_WITH_AES_128_CBC_SHA
                cipherSuiteName="TLS_DH_anon_WITH_AES_128_CBC_SHA",
            )
        )
        findings = evaluate_rules([sess])
        r07 = [f for f in findings if f.ruleId == "R07"]
        assert len(r07) == 1
        assert r07[0].severity == "Critical"
        assert r07[0].details["weakClass"] == "anon"

    def test_rule_r10_dhe_weak_prime(self):
        """R10 (Medium / High < 1024): DHE prime below 2048 bits."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="TLS 1.2",
                kxType="DHE",
                kxGroupOrDhBits=1024,
            )
        )
        findings = evaluate_rules([sess])
        r10 = [f for f in findings if f.ruleId == "R10"]
        assert len(r10) == 1
        assert r10[0].severity == "Medium"
        assert r10[0].details["kxGroupOrDhBits"] == 1024

        # Below 1024 bits -> High
        sess_weak = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="TLS 1.2",
                kxType="DHE",
                kxGroupOrDhBits=768,
            )
        )
        findings_weak = evaluate_rules([sess_weak])
        r10_weak = [f for f in findings_weak if f.ruleId == "R10"]
        assert len(r10_weak) == 1
        assert r10_weak[0].severity == "High"

    def test_rule_r14_hostname_mismatch(self):
        """R14 (Medium): SNI present and no SAN matches it."""
        cert = CertificateInfo(
            sha256="dd" * 32,
            subject="CN=mail.lab.local",
            issuer="CN=Root CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["mail.example.com"],
            isCa=False,
            verdicts=["hostnameMismatch"],
        )
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version="TLS 1.2",
                sni="other.example.com",
            ),
            certificates=[cert],
        )
        findings = evaluate_rules([sess])
        r14 = [f for f in findings if f.ruleId == "R14"]
        assert len(r14) == 1
        assert r14[0].severity == "Medium"
        assert r14[0].details["sni"] == "other.example.com"

    def test_rule_r17_starttls_stripping_indicator(self):
        """R17 (Medium): STARTTLS advertised in some sessions and not in others."""
        s1 = make_synthetic_session(
            session_id=1,
            server_endpoint="10.0.0.1:25",
            transport_mode="starttls",
            starttls_offered=True,
            starttls_attempted=True,
            starttls_outcome="succeeded",
        )
        s2 = make_synthetic_session(
            session_id=2,
            server_endpoint="10.0.0.1:25",
            transport_mode="plaintext",
            starttls_offered=False,
            starttls_attempted=False,
            starttls_outcome="notOffered",
        )
        findings = evaluate_rules([s1, s2])
        r17 = [f for f in findings if f.ruleId == "R17"]
        assert len(r17) == 1
        assert r17[0].severity == "Medium"
        assert r17[0].details["advertisedSessionIds"] == [1]
        assert r17[0].details["notAdvertisedSessionIds"] == [2]

    def test_rule_r18_distinct_leaf_certificates(self):
        """R18 (Medium): Distinct leaf certificate fingerprints for same server endpoint."""
        c1 = CertificateInfo(
            sha256="aa" * 32,
            subject="CN=node1.lab.local",
            issuer="CN=Root CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["node1.lab.local"],
            isCa=False,
            verdicts=[],
        )
        c2 = CertificateInfo(
            sha256="bb" * 32,
            subject="CN=node2.lab.local",
            issuer="CN=Root CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=2048,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["node2.lab.local"],
            isCa=False,
            verdicts=[],
        )
        s1 = make_synthetic_session(session_id=1, server_endpoint="10.0.0.1:25", certificates=[c1])
        s2 = make_synthetic_session(session_id=2, server_endpoint="10.0.0.1:25", certificates=[c2])
        findings = evaluate_rules([s1, s2])
        r18 = [f for f in findings if f.ruleId == "R18"]
        assert len(r18) == 1
        assert r18[0].severity == "Medium"
        assert len(r18[0].details["fingerprints"]) == 2


# ---------------------------------------------------------------------------
# Boundary Tests
# ---------------------------------------------------------------------------


class TestBoundaryConditions:
    """Test boundary conditions for key sizes, TLS versions, and session counts."""

    @pytest.mark.parametrize(
        "key_size,should_trigger",
        [
            (1024, True),
            (2047, True),
            (2048, False),
            (4096, False),
        ],
    )
    def test_rsa_key_size_boundary(self, key_size: int, should_trigger: bool):
        """RSA key boundary: < 2048 triggers R12, >= 2048 passes."""
        verdicts = ["weakKey"] if key_size < 2048 else ["valid"]
        cert = CertificateInfo(
            sha256="11" * 32,
            subject="CN=test",
            issuer="CN=Root CA",
            notBefore=1600000000,
            notAfter=1800000000,
            keyAlgorithm="RSA",
            keySize=key_size,
            signatureAlgorithm="sha256WithRSAEncryption",
            san=["test"],
            isCa=False,
            verdicts=verdicts,
        )
        sess = make_synthetic_session(certificates=[cert])
        findings = evaluate_rules([sess])
        has_r12 = any(f.ruleId == "R12" for f in findings)
        assert has_r12 == should_trigger

    @pytest.mark.parametrize(
        "tls_version,should_trigger",
        [
            ("TLS 1.0", True),
            ("TLS 1.1", True),
            ("TLS 1.2", False),
            ("TLS 1.3", False),
        ],
    )
    def test_tls_version_boundary(self, tls_version: str, should_trigger: bool):
        """TLS version boundary: TLS 1.0 and 1.1 trigger R06, TLS 1.2+ passes."""
        sess = make_synthetic_session(
            tls_info=TlsInfo(
                certObservable=True,
                version=tls_version,
                forwardSecrecy=True,
                kxType="ECDHE",
            )
        )
        findings = evaluate_rules([sess])
        has_r06 = any(f.ruleId == "R06" for f in findings)
        assert has_r06 == should_trigger

    @pytest.mark.parametrize(
        "session_count,expected_exposure",
        [
            (1, 1),
            (2, 2),
            (5, 2),
            (9, 2),
            (10, 3),
            (11, 3),
        ],
    )
    def test_session_count_exposure_boundary(self, session_count: int, expected_exposure: int):
        """Exposure factor boundary: 1 for 1, 2 for 2-9, 3 for 10+."""
        assert compute_exposure_factor(session_count) == expected_exposure

    def test_scoring_boundary_9_vs_10_sessions(self):
        """Verify score calculation difference between 9 and 10 affected sessions."""
        endpoint = "10.0.0.1:25"

        # 9 sessions with High finding (weight 20, exposure 2 -> deduction 40, score 60, grade C)
        sessions_9 = [
            make_synthetic_session(
                session_id=i,
                server_endpoint=endpoint,
                tls_info=TlsInfo(certObservable=True, version="TLS 1.0", forwardSecrecy=True, kxType="ECDHE"),
            )
            for i in range(1, 10)
        ]
        findings_9 = evaluate_rules(sessions_9)
        assert len(findings_9) == 1
        assert findings_9[0].sessionCount == 9
        score_9, grade_9 = calculate_host_score(findings_9)
        assert score_9 == 100 - (20 * 2)  # 60
        assert grade_9 == "C"

        # 10 sessions with High finding (weight 20, exposure 3 -> deduction 60, score 40, grade D)
        sessions_10 = [
            make_synthetic_session(
                session_id=i,
                server_endpoint=endpoint,
                tls_info=TlsInfo(certObservable=True, version="TLS 1.0", forwardSecrecy=True, kxType="ECDHE"),
            )
            for i in range(1, 11)
        ]
        findings_10 = evaluate_rules(sessions_10)
        assert len(findings_10) == 1
        assert findings_10[0].sessionCount == 10
        score_10, grade_10 = calculate_host_score(findings_10)
        assert score_10 == 100 - (20 * 3)  # 40
        assert grade_10 == "D"

    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (100, "A"),
            (90, "A"),
            (89, "B"),
            (75, "B"),
            (74, "C"),
            (60, "C"),
            (59, "D"),
            (40, "D"),
            (39, "F"),
            (0, "F"),
        ],
    )
    def test_grade_boundaries(self, score: int, expected_grade: str):
        """Test exact grade boundary transitions."""
        assert compute_grade(score) == expected_grade


# ---------------------------------------------------------------------------
# Deduplication and Evidence Capping Tests
# ---------------------------------------------------------------------------


class TestDeduplicationAndEvidence:
    """Test finding deduplication and evidence capping at <= 5 items."""

    def test_evidence_capped_at_five(self):
        """Verify that a finding affecting >= 5 sessions caps evidence at exactly 5 entries in ascending sessionId order."""
        endpoint = "10.0.0.1:25"
        # 12 sessions
        sessions = [
            make_synthetic_session(
                session_id=i,
                server_endpoint=endpoint,
                tls_info=TlsInfo(certObservable=True, version="TLS 1.1", forwardSecrecy=True, kxType="ECDHE"),
            )
            for i in range(12)
        ]
        findings = evaluate_rules(sessions)
        assert len(findings) == 1
        f = findings[0]
        assert f.sessionCount == 12
        assert len(f.evidence) == 5
        # Verify ascending order of session IDs in evidence
        session_ids_in_evidence = [e.sessionId for e in f.evidence]
        assert session_ids_in_evidence == [0, 1, 2, 3, 4]

    def test_deduplication_by_rule_and_endpoint(self):
        """Verify that multiple sessions hitting the same rule on the same host collapse into 1 finding."""
        endpoint1 = "10.0.0.1:25"
        endpoint2 = "10.0.0.2:25"
        sessions = [
            make_synthetic_session(session_id=1, server_endpoint=endpoint1, transport_mode="plaintext", starttls_offered=False),
            make_synthetic_session(session_id=2, server_endpoint=endpoint1, transport_mode="plaintext", starttls_offered=False),
            make_synthetic_session(session_id=3, server_endpoint=endpoint2, transport_mode="plaintext", starttls_offered=False),
        ]
        findings = evaluate_rules(sessions)
        # Should produce 2 findings: one for endpoint1, one for endpoint2
        assert len(findings) == 2
        f1 = next(f for f in findings if f.serverEndpoint == endpoint1)
        f2 = next(f for f in findings if f.serverEndpoint == endpoint2)
        assert f1.sessionCount == 2
        assert f1.sortedSessionIds == [1, 2]
        assert f2.sessionCount == 1
        assert f2.sortedSessionIds == [3]


# ---------------------------------------------------------------------------
# Determinism Tests Across Multiple Runs
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Verify that evaluate_rules produces bit-identical outputs regardless of input order."""

    def test_determinism_across_runs_and_shuffles(self):
        sessions = [
            make_synthetic_session(session_id=1, server_endpoint="10.0.0.1:25", transport_mode="plaintext", starttls_offered=False),
            make_synthetic_session(session_id=2, server_endpoint="10.0.0.1:25", cleartext_auth=[CleartextAuth("PLAIN", 10)]),
            make_synthetic_session(session_id=3, server_endpoint="10.0.0.2:25", tls_info=TlsInfo(certObservable=True, version="TLS 1.0", forwardSecrecy=True, kxType="ECDHE")),
            make_synthetic_session(session_id=4, server_endpoint="10.0.0.2:25", tls_info=TlsInfo(certObservable=False, version="TLS 1.3", forwardSecrecy=True, kxType="ECDHE", certNotObservableReason="tls13")),
        ]

        # Run 1: Original order
        res1 = evaluate_rules(sessions)
        dict1 = [f.to_dict() for f in res1]

        # Run 2: Shuffled order
        shuffled = list(sessions)
        random.seed(42)
        random.shuffle(shuffled)
        res2 = evaluate_rules(shuffled)
        dict2 = [f.to_dict() for f in res2]

        # Run 3: Reversed order
        res3 = evaluate_rules(list(reversed(sessions)))
        dict3 = [f.to_dict() for f in res3]

        assert dict1 == dict2
        assert dict1 == dict3
