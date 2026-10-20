"""Authentication, RBAC, and CSRF dependencies for SecureMailScope API."""
import hmac
import secrets
from typing import Optional, Tuple
from fastapi import Header, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

import backend.config as config

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class BrowserAuthRedirect(Exception):
    """Raised when an unauthenticated browser request needs redirection to /login."""
    def __init__(self, next_url: str = "/"):
        self.next_url = next_url


def generate_csrf_token() -> str:
    """Generate cryptographically secure CSRF token."""
    return secrets.token_hex(32)


def get_api_key(
    request: Request,
    x_api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(None),
) -> str:
    """Extract API key strictly from X-API-Key header, Authorization Bearer, or cookie."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    cookie = request.cookies.get("api_key")
    if cookie:
        return cookie
    return ""


def validate_analyst_key(api_key: str) -> Optional[Tuple[int, str]]:
    """Validates analyst key, returning (status_code, error_detail) on failure, or None on success."""
    if not api_key:
        return status.HTTP_401_UNAUTHORIZED, "Missing API key"
    if not config.ANALYST_API_KEY:
        return status.HTTP_500_INTERNAL_SERVER_ERROR, "ANALYST_API_KEY is not configured on the server"
    if api_key == config.ADMIN_API_KEY:
        return status.HTTP_403_FORBIDDEN, "Admin key cannot access analyst endpoints"
    if api_key != config.ANALYST_API_KEY:
        return status.HTTP_401_UNAUTHORIZED, "Invalid analyst API key"
    return None


def require_analyst(api_key: str = Security(get_api_key)) -> str:
    """Enforce analyst role: accepts ANALYST_API_KEY, rejects ADMIN_API_KEY with 403, missing/invalid with 401."""
    err = validate_analyst_key(api_key)
    if err:
        code, msg = err
        raise HTTPException(status_code=code, detail=msg)
    return "analyst"


def require_analyst_html(
    request: Request,
    api_key: str = Security(get_api_key),
) -> str:
    """
    Enforces analyst authentication for browser views.
    Unauthenticated browser requests (Accept: text/html) are redirected to /login?next=<path>.
    Programmatic API callers without text/html are rejected with 401/403.
    """
    err = validate_analyst_key(api_key)
    if err:
        code, msg = err
        accept = request.headers.get("accept", "")
        if code == status.HTTP_401_UNAUTHORIZED:
            is_html_request = ("text/html" in accept or request.url.path == "/") and request.query_params.get("format") != "json"
            if is_html_request:
                next_url = request.url.path
                if request.url.query:
                    next_url = f"{next_url}?{request.url.query}"
                raise BrowserAuthRedirect(next_url=next_url)
            raise HTTPException(status_code=code, detail=msg)
        raise HTTPException(status_code=code, detail=msg)
    return "analyst"


def require_admin(api_key: str = Security(get_api_key)) -> str:
    """Enforce admin role: accepts ADMIN_API_KEY, rejects ANALYST_API_KEY with 403."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )
    if not config.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ADMIN_API_KEY is not configured on the server",
        )
    if api_key == config.ANALYST_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst key cannot access admin endpoints",
        )
    if api_key != config.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key",
        )
    return "admin"


async def verify_csrf(request: Request) -> None:
    """
    Validates CSRF token for state-changing browser requests.
    Checks token from form field 'csrf_token' or header 'X-CSRF-Token' against cookie 'csrf_token'.
    Pure API callers with X-API-Key or Authorization headers are exempt, but cookie-authenticated
    browser requests must provide a valid matching CSRF token.
    """
    has_header_auth = bool(
        request.headers.get("X-API-Key")
        or request.headers.get("Authorization")
    )
    if has_header_auth and not request.cookies.get("api_key"):
        return

    cookie_token = request.cookies.get("csrf_token")
    if not cookie_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing from cookie",
        )

    submitted_token = request.headers.get("X-CSRF-Token")
    if not submitted_token:
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            try:
                form = await request.form()
                submitted_token = form.get("csrf_token")
            except Exception:
                submitted_token = None

    if not submitted_token or not hmac.compare_digest(str(submitted_token), str(cookie_token)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid",
        )
