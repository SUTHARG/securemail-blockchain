"""Regression tests for Authentication, RBAC, and CSRF protection (Issue 1 & 2).

Verifies:
1. Anonymous browser request to protected HTML view redirects to /login?next=<path>.
2. Anonymous programmatic request to protected endpoint receives HTTP 401 Unauthorized.
3. Valid analyst API key / cookie grants access to analyst endpoints.
4. Invalid API key receives HTTP 401 Unauthorized.
5. Admin key cannot access analyst-only endpoints (HTTP 403 Forbidden).
6. Missing CSRF token on browser POST requests is rejected with HTTP 403 Forbidden.
7. Mismatched CSRF token on browser POST requests is rejected with HTTP 403 Forbidden.
8. Valid CSRF token on browser POST requests succeeds.
"""
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app import app
import backend.config as config
from backend.database import create_case, init_db


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolate database and cases directories."""
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_auth_csrf.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def test_anonymous_browser_redirects_to_login():
    """Unauthenticated browser request must redirect to /login?next=..."""
    client = TestClient(app)
    res = client.get("/cases/some-case-123", headers={"Accept": "text/html"}, follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/login" in res.headers["location"]
    assert "next=" in res.headers["location"]


def test_anonymous_api_returns_401():
    """Unauthenticated programmatic API request must return HTTP 401 Unauthorized."""
    client = TestClient(app)
    res = client.get("/cases/some-case-123", headers={"Accept": "application/json"})
    assert res.status_code == 401
    assert "Missing API key" in res.json().get("detail", "")


def test_invalid_api_key_returns_401():
    """Invalid API key must return HTTP 401 Unauthorized."""
    client = TestClient(app)
    res = client.get(
        "/cases/some-case-123",
        headers={"X-API-Key": "wrong-key-value", "Accept": "application/json"},
    )
    assert res.status_code == 401
    assert "Invalid analyst API key" in res.json().get("detail", "")


def test_admin_key_to_analyst_endpoint_returns_403():
    """Admin key attempting to access analyst endpoint must return HTTP 403 Forbidden."""
    client = TestClient(app)
    res = client.get(
        "/cases/some-case-123",
        headers={"X-API-Key": config.ADMIN_API_KEY, "Accept": "application/json"},
    )
    assert res.status_code == 403
    assert "Admin key cannot access analyst endpoints" in res.json().get("detail", "")


def test_valid_analyst_key_accesses_endpoint():
    """Valid analyst key can access analyst endpoint."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="b" * 64, status="uploaded")

    client = TestClient(app)
    res = client.get(
        f"/cases/{case_id}",
        headers={"X-API-Key": config.ANALYST_API_KEY, "Accept": "application/json"},
    )
    assert res.status_code == 200
    assert res.json()["id"] == case_id


def test_csrf_protection_missing_cookie_rejected():
    """Browser request with api_key cookie but missing csrf_token cookie must be rejected with 403."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="c" * 64, status="uploaded")

    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)

    res = client.post(
        f"/cases/{case_id}/action/analyze",
        data={"csrf_token": "some-token"},
        follow_redirects=False,
    )
    assert res.status_code == 403
    assert "CSRF" in res.json().get("detail", "")


def test_csrf_protection_mismatched_token_rejected():
    """Browser request with mismatched CSRF token must be rejected with 403."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="d" * 64, status="uploaded")

    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "correct-cookie-token")

    res = client.post(
        f"/cases/{case_id}/action/analyze",
        data={"csrf_token": "wrong-submitted-token"},
        follow_redirects=False,
    )
    assert res.status_code == 403
    assert "CSRF" in res.json().get("detail", "")


def test_csrf_protection_valid_token_accepted():
    """Browser request with matching CSRF token is accepted."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="e" * 64, status="uploaded")

    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "valid-matching-token")

    res = client.post(
        f"/cases/{case_id}/action/analyze",
        data={"csrf_token": "valid-matching-token"},
        follow_redirects=False,
    )
    # Action proceeds (redirects to case view or returns 303)
    assert res.status_code in (302, 303)


def test_api_key_in_query_parameter_rejected():
    """Secrets in URLs (?api_key=...) must be rejected with 401 Unauthorized."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="f" * 64, status="uploaded")

    client = TestClient(app)
    res = client.get(
        f"/cases/{case_id}?api_key={config.ANALYST_API_KEY}",
        headers={"Accept": "application/json"},
    )
    assert res.status_code == 401


def test_api_header_auth_exempt_from_csrf():
    """Pure API-key header requests must not require browser CSRF token."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="1" * 64, status="uploaded")

    client = TestClient(app)
    # Header authenticated, no cookies
    res = client.post(
        f"/cases/{case_id}/analyze",
        headers={"X-API-Key": config.ANALYST_API_KEY, "Accept": "application/json"},
    )
    # Should proceed past auth/csrf (e.g. 200 or business logic status), never 403 CSRF
    assert res.status_code != 403


def test_cookie_auth_post_without_csrf_rejected_on_all_mutations():
    """Cookie authenticated POST without CSRF must fail on mutation routes."""
    case_id = uuid.uuid4().hex
    create_case(case_id=case_id, pcap_sha256="2" * 64, status="uploaded")

    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    # No csrf_token cookie or header

    for path in [
        f"/cases/{case_id}/analyze",
        f"/cases/{case_id}/open",
        f"/cases/{case_id}/claim",
        f"/cases/{case_id}/finalize",
        f"/cases/{case_id}/record",
        f"/cases/{case_id}/anchor",
    ]:
        res = client.post(path, headers={"Accept": "application/json"})
        assert res.status_code == 403
        assert "CSRF" in res.json().get("detail", "")


def test_login_malicious_next_redirect_sanitized():
    """Login with external, scheme-relative, or malformed next destinations redirects safely to '/'."""
    client = TestClient(app)
    # Get login page to receive csrf_token
    res_page = client.get("/login")
    assert res_page.status_code == 200
    csrf_tok = client.cookies.get("csrf_token")

    malicious_targets = [
        "https://evil.com/phish",
        "//evil.com",
        "javascript:alert(1)",
        "ftp://attacker.com",
        "\\\\evil.com\\share",
    ]

    for evil in malicious_targets:
        csrf_tok = client.cookies.get("csrf_token")
        res = client.post(
            "/login",
            data={"api_key": config.ANALYST_API_KEY, "next": evil, "csrf_token": csrf_tok},
            follow_redirects=False,
        )
        assert res.status_code in (302, 303)
        loc = res.headers["location"]
        assert not loc.startswith("//")
        assert not loc.startswith("http")
        assert loc == "/"


def test_logout_post_only_with_csrf():
    """GET /logout must be rejected (405 Method Not Allowed); POST /logout requires CSRF."""
    client = TestClient(app)
    # GET /logout
    res_get = client.get("/logout")
    assert res_get.status_code == 405

    # POST /logout without auth/csrf
    res_post_nocsrf = client.post("/logout")
    # Missing CSRF
    assert res_post_nocsrf.status_code in (401, 403)

    # POST /logout with auth and CSRF
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "logout-token")
    res_post_valid = client.post("/logout", data={"csrf_token": "logout-token"}, follow_redirects=False)
    assert res_post_valid.status_code in (302, 303)
    assert res_post_valid.headers["location"] == "/login"
