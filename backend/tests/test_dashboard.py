"""Unit and integration tests for Server-Rendered Dashboard (Prompt 7.2 / Milestone M4).

Requirements:
1. Each dashboard page renders for S01a, S05, and S12 cases:
   - / (index)
   - /cases/<id> (overview)
   - /cases/<id>/hosts
   - /cases/<id>/findings
   - /cases/<id>/sessions
   - /cases/<id>/tls
   - /cases/<id>/certificates
   - /cases/<id>/chain
2. Show not-observable and not-evaluable states explicitly (TLS 1.3, resumed, no SNI, incomplete stream).
3. No external URLs appear in any page except allowed documentation domains.
4. Chain page / verification shows PASS on happy path, and FAIL for step 1 after modifying stored PCAP by one byte.
5. Acceptance (milestone M4): run one lab case from upload to verified entirely in the browser.
"""
import hashlib
import io
import re
import shutil
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app import app
import backend.config as config
from backend.database import create_case, get_case, init_db, update_case_status
from backend.runner import execute_analysis
from backend.storage import get_case_dir, read_case_json

REPO_ROOT = config.REPO_ROOT
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"

ALLOWED_DOC_DOMAINS = [
    "postfix.org",
    "dovecot.org",
    "certbot.eff.org",
    "openssl.org",
    "datatracker.ietf.org",
]


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolate database and cases directories for dashboard testing."""
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_dashboard.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def create_analyzed_test_case(scenario: str) -> str:
    """Helper to create and analyze a case using a lab capture."""
    pcap_path = CAPTURES_DIR / f"{scenario}.pcap"
    assert pcap_path.exists(), f"Capture {scenario}.pcap missing"

    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    dest_pcap = case_dir / "pcap.bin"
    shutil.copyfile(pcap_path, dest_pcap)

    pcap_sha = hashlib.sha256(dest_pcap.read_bytes()).hexdigest()
    create_case(case_id=case_id, pcap_sha256=pcap_sha, status="uploaded")

    # Run analysis offline
    success = execute_analysis(case_id=case_id, use_docker=False)
    assert success, f"Analysis failed for {scenario}"
    return case_id


def assert_no_unauthorized_urls(html_content: str):
    """Assert that any http/https URL belongs strictly to allowed documentation domains."""
    urls = re.findall(r'href=[\'"](https?://[^\'">]+)', html_content)
    for url in urls:
        assert any(domain in url for domain in ALLOWED_DOC_DOMAINS), (
            f"Unauthorized external URL in rendered page: {url}"
        )


def get_auth_client() -> TestClient:
    """Helper returning TestClient authenticated as Analyst with CSRF cookies."""
    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "test-csrf-token-12345")
    client.headers["X-CSRF-Token"] = "test-csrf-token-12345"
    return client


def test_index_page_renders():
    """Verify unauthenticated / redirects to /login, and authenticated / renders case list."""
    anon_client = TestClient(app)
    res_anon = anon_client.get("/", follow_redirects=False)
    assert res_anon.status_code in (302, 303)
    assert "/login" in res_anon.headers["location"]

    client = get_auth_client()
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Network Traffic Assessment Cases" in res.text
    assert "Upload & Ingest Capture" in res.text
    assert_no_unauthorized_urls(res.text)


@pytest.mark.parametrize("scenario", ["S01a", "S05", "S12"])
def test_all_dashboard_pages_render(scenario):
    """
    Verify each dashboard page renders properly for S01a, S05, and S12:
    - overview, hosts, findings, sessions, tls, certificates, chain
    - verify no external URLs
    - verify explicit explanations for unobservable/unevaluable states
    """
    client = get_auth_client()
    case_id = create_analyzed_test_case(scenario)
    html_headers = {"Accept": "text/html"}

    pages = [
        f"/cases/{case_id}",
        f"/cases/{case_id}/hosts",
        f"/cases/{case_id}/findings",
        f"/cases/{case_id}/sessions",
        f"/cases/{case_id}/tls",
        f"/cases/{case_id}/certificates",
        f"/cases/{case_id}/anomalies",
        f"/cases/{case_id}/chain",
    ]

    for path in pages:
        res = client.get(path, headers=html_headers)
        assert res.status_code == 200, f"Page {path} returned status {res.status_code}"
        assert "text/html" in res.headers["content-type"]
        assert_no_unauthorized_urls(res.text)

    # Verify inline SVG charts on TLS metrics and Host posture pages
    res_tls = client.get(f"/cases/{case_id}/tls", headers=html_headers)
    assert "<svg" in res_tls.text
    res_hosts = client.get(f"/cases/{case_id}/hosts", headers=html_headers)
    assert "<svg" in res_hosts.text

    # Verify Per-Host Drilldown Page renders
    from backend.storage import read_case_json
    scores = read_case_json(case_id, "host_scores.json") or []
    target_ep = scores[0]["serverEndpoint"] if scores else "127.0.0.1:25"
    res_drill = client.get(f"/cases/{case_id}/hosts/{target_ep}", headers=html_headers)
    assert res_drill.status_code == 200
    assert "Forward Secrecy Share" in res_drill.text
    assert_no_unauthorized_urls(res_drill.text)

    # Verify 1-click evidence access from Overview page
    res_over = client.get(f"/cases/{case_id}", headers=html_headers)
    assert res_over.status_code == 200
    if scenario in ("S05", "S01b"):
        assert "Inspect" in res_over.text or "Evidence" in res_over.text

    # Verify filter and sort parameters
    res_filt = client.get(f"/cases/{case_id}/findings?severity=Critical&sort_by=ruleId&sort_order=asc", headers=html_headers)
    assert res_filt.status_code == 200
    res_hfilt = client.get(f"/cases/{case_id}/hosts?grade=A&sort_by=score&sort_order=desc", headers=html_headers)
    assert res_hfilt.status_code == 200

    # Specific checks for S12 (TLS 1.3 - unobservable certificates per RFC 8446)
    if scenario == "S12":
        res_sess = client.get(f"/cases/{case_id}/sessions", headers=html_headers)
        assert "Not observable" in res_sess.text

    # Specific checks for S05 (Plaintext auth - R01 and R02 findings present)
    if scenario == "S05":
        res_find = client.get(f"/cases/{case_id}/findings", headers=html_headers)
        assert "R01" in res_find.text
        assert "R02" in res_find.text


def setup_mock_finalized_chain(case_id: str, monkeypatch):
    """Setup mock on-chain state and PostureLedger for complete 5-step verification."""
    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"
    from validator.crypto import decrypt_at_rest
    raw_bytes = pcap_path.read_bytes()
    try:
        decrypted_bytes = decrypt_at_rest(raw_bytes)
    except Exception:
        decrypted_bytes = raw_bytes
    pcap_sha = hashlib.sha256(decrypted_bytes).hexdigest()
    result_data = read_case_json(case_id, "result.json") or {}
    result_root = result_data.get("resultRoot", "0x" + "11" * 32)

    from backend.reports.builder import build_case_report
    build_case_report(case_id, save=True)
    rep_sha = hashlib.sha256((case_dir / "report.json").read_bytes()).hexdigest()

    onchain_id = "0x" + "33" * 32
    from backend.database import set_case_onchain_id
    set_case_onchain_id(case_id, onchain_id)

    class MockGateway:
        def poll_events(self):
            pass

        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Finalized",
                "stateName": "Finalized",
                "pcapHash": "0x" + pcap_sha,
                "finalRoot": result_root,
                "reportHash": "0x" + rep_sha,
                "validators": [],
                "transactions": [],
            }

        @property
        def posture_ledger(self):
            class MockFunctions:
                def recordCount(self, h):
                    class MockCall:
                        def call(self):
                            return 1
                    return MockCall()

                def recordAt(self, h, idx):
                    class MockCall:
                        def call(self):
                            import eth_abi
                            from web3 import Web3
                            scores = read_case_json(case_id, "host_scores.json") or []
                            score_dict = {bytes.fromhex(s["hostId"].replace("0x", "")): int(s["score"]) for s in scores if s.get("hostId")}
                            score_val = score_dict.get(h, int(scores[0]["score"]) if scores else 100)
                            c_bytes = bytes.fromhex(onchain_id[2:])
                            r_bytes = bytes.fromhex(result_root.replace("0x", ""))
                            prev_h = bytes(32)
                            ts = 1700000000
                            encoded = eth_abi.encode(
                                ["bytes32", "bytes32", "uint16", "bytes32", "bytes32", "uint256"],
                                [h, c_bytes, score_val, r_bytes, prev_h, ts],
                            )
                            rec_h = Web3.keccak(encoded)
                            return (
                                h,
                                c_bytes,
                                score_val,
                                r_bytes,
                                prev_h,
                                ts,
                                rec_h,
                            )
                    return MockCall()

            class MockContract:
                functions = MockFunctions()

            return MockContract()

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())


def test_chain_verification_tamper_detection(monkeypatch):
    """
    Verify chain page shows PASS for happy path,
    and FAIL for step 1 when pcap.bin is modified by one byte.
    """
    client = get_auth_client()
    case_id = create_analyzed_test_case("S01a")
    setup_mock_finalized_chain(case_id, monkeypatch)

    # 1. Happy path verification
    res_verify = client.post(f"/cases/{case_id}/chain/verify", data={"csrf_token": "test-csrf-token-12345"})
    assert res_verify.status_code == 200
    assert "text/html" in res_verify.headers["content-type"]
    assert "OVERALL: PASS" in res_verify.text
    assert "PCAP SHA-256 vs On-Chain pcapHash" in res_verify.text

    # 2. Tamper PCAP file by modifying one byte
    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"
    pcap_bytes = bytearray(pcap_path.read_bytes())
    pcap_bytes[10] ^= 0xFF
    pcap_path.write_bytes(pcap_bytes)

    # 3. Verification after tamper must report FAIL on Step 1
    res_tamper = client.post(f"/cases/{case_id}/chain/verify", data={"csrf_token": "test-csrf-token-12345"})
    assert res_tamper.status_code == 200
    assert "OVERALL: FAIL" in res_tamper.text
    assert "does not match on-chain pcapHash" in res_tamper.text


def test_m4_browser_acceptance_flow(monkeypatch):
    """
    Acceptance check (Milestone M4):
    Run one lab case from upload to verified entirely through browser endpoints
    (upload-form, action/analyze, overview, chain, chain/verify).
    """
    client = get_auth_client()
    pcap_path = CAPTURES_DIR / "S01a.pcap"
    assert pcap_path.exists()

    # 1. Browser Form Upload
    with open(pcap_path, "rb") as pf:
        res_up = client.post(
            "/cases/upload-form",
            files={"file": ("S01a.pcap", pf, "application/vnd.tcpdump.pcap")},
            data={"csrf_token": "test-csrf-token-12345"},
            follow_redirects=False,
        )
    assert res_up.status_code in (302, 303)
    redirect_url = res_up.headers["location"]
    case_id = redirect_url.split("/")[-1]

    # 2. Browser Action: Run Analysis
    res_act = client.post(
        f"/cases/{case_id}/action/analyze",
        data={"csrf_token": "test-csrf-token-12345"},
        follow_redirects=False,
    )
    assert res_act.status_code in (302, 303)

    case_record = get_case(case_id)
    assert case_record["status"] == "analyzed"

    # 3. Browser View: Overview & Sections
    html_headers = {"Accept": "text/html"}
    res_over = client.get(f"/cases/{case_id}", headers=html_headers)
    assert res_over.status_code == 200
    assert case_id[:12] in res_over.text

    res_hosts = client.get(f"/cases/{case_id}/hosts", headers=html_headers)
    assert res_hosts.status_code == 200

    res_find = client.get(f"/cases/{case_id}/findings", headers=html_headers)
    assert res_find.status_code == 200

    res_sess = client.get(f"/cases/{case_id}/sessions", headers=html_headers)
    assert res_sess.status_code == 200

    res_tls = client.get(f"/cases/{case_id}/tls", headers=html_headers)
    assert res_tls.status_code == 200

    res_cert = client.get(f"/cases/{case_id}/certificates", headers=html_headers)
    assert res_cert.status_code == 200

    # 4. Browser View: Chain & Verify (with finalized on-chain state)
    setup_mock_finalized_chain(case_id, monkeypatch)

    res_chain = client.get(f"/cases/{case_id}/chain", headers=html_headers)
    assert res_chain.status_code == 200

    res_ver = client.post(
        f"/cases/{case_id}/chain/verify",
        data={"csrf_token": "test-csrf-token-12345"},
    )
    assert res_ver.status_code == 200
    assert "OVERALL: PASS" in res_ver.text


def test_chain_verification_no_chain_shows_pending_and_updated_results():
    """When a case has no on-chain ID, verify button runs and returns OVERALL: PENDING with chain-dependent checks as PENDING."""
    client = get_auth_client()
    case_id = create_analyzed_test_case("S01a")
    html_headers = {"Accept": "text/html"}

    # 1. Before verify, shows initial prompt
    res_initial = client.get(f"/cases/{case_id}/chain", headers=html_headers)
    assert res_initial.status_code == 200
    assert "Click Verify to Run" in res_initial.text
    assert "Not Opened" in res_initial.text

    # 2. Clicking Verify executes check and returns updated results with OVERALL: PENDING
    res_verify = client.post(
        f"/cases/{case_id}/chain/verify",
        data={"csrf_token": "test-csrf-token-12345"},
    )
    assert res_verify.status_code == 200
    assert "OVERALL: PENDING" in res_verify.text
    # Step 2 is off-chain and passes
    assert "PASS" in res_verify.text
    assert "Result Root matches rebuilt tree" in res_verify.text
    # Steps 1, 3, 4, 5 are chain-dependent and show PENDING
    assert "Case not yet opened on-chain" in res_verify.text
    assert "Case not yet finalized on-chain" in res_verify.text
    assert "Posture not yet recorded on-chain" in res_verify.text
    assert "Report not yet anchored on-chain" in res_verify.text


def test_chain_verification_mismatched_result_shows_fail():
    """When result.json has a mismatched resultRoot, Step 2 reports FAIL and overall verification is FAIL."""
    client = get_auth_client()
    case_id = create_analyzed_test_case("S01a")

    # Tamper result.json
    case_dir = get_case_dir(case_id)
    result_path = case_dir / "result.json"
    data = read_case_json(case_id, "result.json")
    data["resultRoot"] = "0x" + "f" * 64
    from backend.storage import write_case_json
    write_case_json(case_id, "result.json", data)

    res_verify = client.post(
        f"/cases/{case_id}/chain/verify",
        data={"csrf_token": "test-csrf-token-12345"},
    )
    assert res_verify.status_code == 200
    assert "OVERALL: FAIL" in res_verify.text
    assert "FAIL" in res_verify.text
    assert "Result tree mismatch" in res_verify.text
