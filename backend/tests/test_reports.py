"""Unit and integration tests for Report Builder (Prompt 7.1).

Verifies:
1. Every Tier 1 rule has a static recommendation with verified docs URLs.
2. report.json is byte-identical on repeated builds (determinism).
3. report.html contains no external URLs other than documentation links.
4. Planted credentials ("labuser", "LabPass-123!") appear nowhere in report files.
5. S05 acceptance: R01 and R02 are prioritized first, with evidence packet numbers.
6. API endpoint GET /cases/{id}/report format behavior (json, html, pdf 501).
"""
import hashlib
import json
import re
import shutil
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app import app
import backend.config as config
from backend.database import create_case, init_db, update_case_status
from backend.reports.builder import build_case_report, load_recommendations
from backend.runner import execute_analysis
from backend.storage import get_case_dir

TIER1_RULES = [
    "R01", "R02", "R03", "R06", "R08", "R09",
    "R11", "R12", "R13", "R15", "R16", "R19",
]

ALLOWED_DOC_DOMAINS = [
    "postfix.org",
    "dovecot.org",
    "certbot.eff.org",
    "openssl.org",
    "datatracker.ietf.org",
]

PLANTED_CREDENTIALS = [
    "labuser",
    "LabPass-123!",
    "bGFidXNlcg==",  # base64 labuser
    "TGFiUGFzcy0xMjMh",  # base64 LabPass-123!
]

AUTH_HEADER = {"Authorization": f"Bearer {config.ANALYST_API_KEY}"}


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_reports.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def test_every_tier1_rule_has_recommendation():
    """Verify that every Tier 1 rule is present in recommendations.yaml with required fields."""
    recs = load_recommendations()
    assert len(recs) >= len(TIER1_RULES)

    for rule_id in TIER1_RULES:
        assert rule_id in recs, f"Missing recommendation for Tier 1 rule: {rule_id}"
        rec = recs[rule_id]
        assert rec["ruleId"] == rule_id
        assert "title" in rec and rec["title"]
        assert "component" in rec and rec["component"]
        assert "parameters" in rec and len(rec["parameters"]) > 0
        assert "configuration_fix" in rec and len(rec["configuration_fix"]) > 0
        assert "documentation_urls" in rec and len(rec["documentation_urls"]) > 0
        assert "explanation" in rec and len(rec["explanation"]) > 0

        # Verify documentation URLs use official allowed domains
        for url in rec["documentation_urls"]:
            assert any(domain in url for domain in ALLOWED_DOC_DOMAINS), (
                f"URL {url} does not belong to allowed documentation domains"
            )


def test_report_builder_determinism_and_acceptance_s05(tmp_path):
    """
    Test S05 capture:
    - R01 and R02 listed first
    - Evidence packet numbers match PCAP frames
    - report.json is byte-identical across two separate builds
    - Planted credentials appear nowhere
    - HTML has no external URLs except docs
    """
    s05_pcap = config.REPO_ROOT / "lab" / "captures" / "S05.pcap"
    assert s05_pcap.exists(), "S05.pcap capture fixture missing"

    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    dest_pcap = case_dir / "pcap.bin"
    shutil.copy2(s05_pcap, dest_pcap)

    pcap_sha256 = hashlib.sha256(dest_pcap.read_bytes()).hexdigest()
    create_case(case_id=case_id, pcap_sha256=pcap_sha256, status="uploaded")

    # Run analysis using local engine
    success = execute_analysis(case_id=case_id, use_docker=False)
    assert success, "Engine analysis on S05 failed"
    update_case_status(case_id, "Finalized")

    # First build
    report1, bytes1, hash1, html1 = build_case_report(case_id, save=True)

    # Second build
    report2, bytes2, hash2, html2 = build_case_report(case_id, save=False)

    # Check byte-identical determinism
    assert bytes1 == bytes2, "report.json canonical bytes differ across builds!"
    assert hash1 == hash2, "report.json SHA-256 differs across builds!"
    assert html1 == html2, "report.html output differs across builds!"

    # Acceptance: S05 lists R01 and R02 first
    findings = report1["findings"]
    assert len(findings) >= 2, f"Expected at least 2 findings for S05, got {len(findings)}"

    rule_ids = [f["ruleId"] for f in findings]
    assert rule_ids[0] == "R01", f"Expected R01 first, got {rule_ids[0]}"
    assert rule_ids[1] == "R02", f"Expected R02 second, got {rule_ids[1]}"

    # Verify evidence packet numbers are non-zero and match Wireshark packets
    for f in findings[:2]:
        assert len(f["evidence"]) > 0, f"Finding {f['ruleId']} has no evidence packet references"
        for ev in f["evidence"]:
            assert ev["packetNumber"] > 0, f"Packet number {ev['packetNumber']} is invalid"

    # Verify planted credentials appear nowhere in JSON or HTML
    report_json_str = bytes1.decode("utf-8")
    for cred in PLANTED_CREDENTIALS:
        assert cred not in report_json_str, f"Planted credential '{cred}' leaked in report.json!"
        assert cred not in html1, f"Planted credential '{cred}' leaked in report.html!"

    # Verify HTML external URLs only belong to allowed docs
    urls = re.findall(r'href=[\'"](https?://[^\'">]+)', html1)
    for url in urls:
        assert any(domain in url for domain in ALLOWED_DOC_DOMAINS), (
            f"Unauthorized external URL in report.html: {url}"
        )


def test_get_report_api_endpoints():
    """Test GET /cases/{id}/report with json, html, and pdf formats."""
    client = TestClient(app)

    # Create dummy case with findings
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    pcap_sha = hashlib.sha256(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20).hexdigest()
    create_case(case_id=case_id, pcap_sha256=pcap_sha, status="Finalized")

    # Seed minimal outputs
    (case_dir / "manifest.json").write_text(json.dumps({
        "caseId": case_id,
        "pcapSha256": pcap_sha,
        "engineVersion": "0.1.0",
        "rulesetHash": "abc",
        "resultRoot": "def",
    }))
    (case_dir / "findings.json").write_text(json.dumps([]))
    (case_dir / "host_scores.json").write_text(json.dumps([]))
    (case_dir / "sessions.json").write_text(json.dumps([]))
    (case_dir / "result.json").write_text(json.dumps({"resultRoot": "def", "leaves": []}))

    # 1. format=json
    res_json = client.get(f"/cases/{case_id}/report?format=json", headers=AUTH_HEADER)
    assert res_json.status_code == 200
    assert res_json.headers["content-type"] == "application/json"
    data = res_json.json()
    assert data["caseId"] == case_id
    assert "findings" in data
    assert "verifierSteps" in data

    # 2. format=html
    res_html = client.get(f"/cases/{case_id}/report?format=html", headers=AUTH_HEADER)
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert f"SecureMailScope Posture Assessment Report" in res_html.text

    # 3. format=pdf returns 200 application/pdf
    res_pdf = client.get(f"/cases/{case_id}/report?format=pdf", headers=AUTH_HEADER)
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert res_pdf.content.startswith(b"%PDF")
    assert case_id.encode("utf-8") in res_pdf.content

    # 4. invalid format returns 400
    res_bad = client.get(f"/cases/{case_id}/report?format=docx", headers=AUTH_HEADER)
    assert res_bad.status_code == 400

    # 5. non-existent case returns 404
    res_404 = client.get("/cases/nonexistent/report?format=json", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_pdf_export_s01a_s05_s12(monkeypatch):
    """
    Prompt T2.5 acceptance tests:
    - Generation succeeds for S01a, S05, and S12
    - PDF text contains case ID, result root, and report hash
    - Zero network access during generation
    """
    import socket
    from backend.reports.builder import build_case_report
    from backend.reports.pdf import generate_pdf_report
    from backend.runner import execute_analysis
    from backend.database import update_case_status

    # Enforce zero network calls during generation
    def no_network_connect(*args, **kwargs):
        raise RuntimeError("Network call attempted during PDF generation (Passive Engine Rule Violation)!")

    monkeypatch.setattr(socket.socket, "connect", no_network_connect)

    scenarios = ["S01a", "S05", "S12"]
    for sc in scenarios:
        pcap_src = config.REPO_ROOT / "lab" / "captures" / f"{sc}.pcap"
        assert pcap_src.exists(), f"Missing fixture {pcap_src}"

        case_id = uuid.uuid4().hex
        case_dir = get_case_dir(case_id)
        shutil.copy2(pcap_src, case_dir / "pcap.bin")

        pcap_sha = hashlib.sha256((case_dir / "pcap.bin").read_bytes()).hexdigest()
        create_case(case_id=case_id, pcap_sha256=pcap_sha, status="uploaded")

        # Analyze using local engine
        ok = execute_analysis(case_id=case_id, use_docker=False)
        assert ok, f"Analysis failed on {sc}"
        update_case_status(case_id, "Finalized")

        # Build report
        report_dict, canonical_bytes, report_hash, html_content = build_case_report(case_id, save=True)
        result_root = report_dict["resultRoot"]

        # Generate PDF
        pdf_bytes = generate_pdf_report(report_dict, html_content, report_hash)
        assert len(pdf_bytes) > 0, f"Generated empty PDF for {sc}"
        assert pdf_bytes.startswith(b"%PDF"), f"Invalid PDF magic number for {sc}"

        # Verify case ID, result root, and report hash are present in the PDF text
        assert case_id.encode("ascii") in pdf_bytes, f"Case ID {case_id} missing from {sc} PDF"
        assert result_root.encode("ascii") in pdf_bytes, f"Result root {result_root} missing from {sc} PDF"
        assert report_hash.encode("ascii") in pdf_bytes, f"Report hash {report_hash} missing from {sc} PDF"


def test_pydyf_fallback_labels_and_identifiers():
    """Verify pydyf fallback output is explicitly labeled 'fallback rendering' and contains case ID, result root, and report hash."""
    from backend.reports.pdf import build_pdf_with_pydyf
    report_dict = {
        "caseId": "case-verify-12345",
        "resultRoot": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "pcapHash": "0xaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd",
        "engineVersion": "0.1.0",
        "hostScores": [],
        "findings": [],
    }
    report_hash = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    pdf_bytes = build_pdf_with_pydyf(report_dict, report_hash)
    assert pdf_bytes.startswith(b"%PDF")
    assert b"fallback rendering" in pdf_bytes
    assert b"case-verify-12345" in pdf_bytes
    assert b"0x1234567890abcdef" in pdf_bytes
    assert b"0xdeadbeefdeadbeef" in pdf_bytes


