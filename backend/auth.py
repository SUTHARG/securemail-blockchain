"""Authentication and RBAC dependencies for SecureMailScope API."""
from typing import Optional
from fastapi import Header, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

import backend.config as config

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key(
    request: Request,
    x_api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(None),
) -> str:
    """Extract API key from X-API-Key header, Authorization Bearer, query param, or cookie."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    qp = request.query_params.get("api_key") or request.query_params.get("key")
    if qp:
        return qp
    cookie = request.cookies.get("api_key")
    if cookie:
        return cookie
    return ""


def require_analyst(api_key: str = Security(get_api_key)) -> str:
    """Enforce analyst role: accepts ANALYST_API_KEY, rejects ADMIN_API_KEY with 403."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )
    if api_key == config.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin key cannot access analyst endpoints",
        )
    if api_key != config.ANALYST_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid analyst API key",
        )
    return "analyst"


def optional_analyst(
    request: Request,
    api_key: str = Security(get_api_key),
) -> str:
    """Allow HTML requests to view dashboard without API key; enforce analyst key for API requests."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return "browser_analyst"
    return require_analyst(api_key)


def require_admin(api_key: str = Security(get_api_key)) -> str:
    """Enforce admin role: accepts ADMIN_API_KEY, rejects ANALYST_API_KEY with 403."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
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
