"""FastAPI backend application for SecureMailScope (Prompt 6.1)."""
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import logging
from pathlib import Path
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import uuid

logger = logging.getLogger("securemailscope.backend.app")

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Body,
    Query,
    Request,
    UploadFile,
    File,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from backend.auth import (
    BrowserAuthRedirect,
    generate_csrf_token,
    require_admin,
    require_analyst,
    require_analyst_html,
    verify_csrf,
)
from backend.chain.deployment import get_client_deployment_config
from backend.chain.gateway import (
    ChainGateway,
    CaseNotFoundError,
    GatewayError,
    InvalidStateError,
    TransactionRevertedError,
)
import backend.config as config
from backend.database import (
    add_audit_entry,
    create_case,
    get_case,
    get_case_by_onchain_id,
    get_chain_txs,
    get_validator_key,
    init_db,
    list_all_cases,
    list_validator_keys,
    register_validator_key,
    update_case_status,
)
from backend.reports.builder import load_recommendations
from backend.runner import execute_analysis
from backend.storage import (
    get_case_dir,
    read_case_json,
    read_case_pcap,
    stream_and_validate_pcap,
)


_gateway_instance: Optional[ChainGateway] = None


def get_gateway() -> ChainGateway:
    """Get or create singleton ChainGateway instance."""
    global _gateway_instance
    if _gateway_instance is None:
        _gateway_instance = ChainGateway()
    return _gateway_instance


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database, storage, and validate configuration on startup."""
    config.validate_environment()
    config.CASES_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    yield


app = FastAPI(
    title="SecureMailScope API",
    version="0.1.0",
    description="Cryptographic Security Posture Assessment API Service",
    lifespan=lifespan,
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

STATUS_STAGE_MAP = {
    "uploaded": 0,
    "analyzed": 1,
    "opened": 2,
    "opened_on_chain": 2,
    "claimed": 3,
    "distributed": 4,
    "committing": 5,
    "revealing": 6,
    "Finalized": 7,
    "finalized": 7,
    "recorded": 8,
    "report_anchored": 9,
}


@app.exception_handler(BrowserAuthRedirect)
async def browser_auth_redirect_handler(request: Request, exc: BrowserAuthRedirect):
    return RedirectResponse(
        url=f"/login?next={exc.next_url}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def is_safe_relative_url(url: Optional[str]) -> bool:
    """Ensure redirect URL is a safe, same-origin relative path."""
    if not url:
        return False
    # Reject scheme-relative URLs like "//example.com" or backslash bypasses like "/\evil.com"
    if url.startswith("//") or url.startswith("/\\") or url.startswith("\\"):
        return False
    if not url.startswith("/"):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme or parsed.netloc:
            return False
        return True
    except Exception:
        return False


def _get_csrf_token(request: Request) -> str:
    return request.cookies.get("csrf_token") or generate_csrf_token()


def _is_secure_request(request: Request) -> bool:
    """Return True if connection is HTTPS or environment is production."""
    return (
        request.url.scheme == "https"
        or getattr(config, "APP_ENV", "").lower() == "production"
        or request.headers.get("x-forwarded-proto") == "https"
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: Optional[str] = "/"):
    api_key = request.cookies.get("api_key") or ""
    safe_next = next if is_safe_relative_url(next) else "/"
    if api_key == config.ANALYST_API_KEY and config.ANALYST_API_KEY:
        return RedirectResponse(url=safe_next, status_code=status.HTTP_303_SEE_OTHER)
    csrf_token = _get_csrf_token(request)
    response = templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None, "next_url": safe_next, "csrf_token": csrf_token},
    )
    if "csrf_token" not in request.cookies:
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,
            secure=_is_secure_request(request),
            samesite="lax",
            path="/",
        )
    return response


@app.post("/login")
async def login_submit(
    request: Request,
    api_key: str = Form(...),
    next: Optional[str] = Form("/"),
    csrf_token: Optional[str] = Form(None),
):
    target = next if is_safe_relative_url(next) else "/"
    cookie_csrf = request.cookies.get("csrf_token")
    if not cookie_csrf or not csrf_token or not hmac.compare_digest(str(csrf_token), str(cookie_csrf)):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid or missing CSRF token",
                "next_url": target,
                "csrf_token": cookie_csrf or generate_csrf_token(),
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )

    if not config.ANALYST_API_KEY:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "ANALYST_API_KEY is not configured on the server", "next_url": target, "csrf_token": cookie_csrf or generate_csrf_token()},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if api_key == config.ADMIN_API_KEY:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Admin key cannot access analyst dashboard", "next_url": target, "csrf_token": cookie_csrf or generate_csrf_token()},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    if api_key != config.ANALYST_API_KEY:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid analyst API key", "next_url": target, "csrf_token": cookie_csrf or generate_csrf_token()},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    new_csrf_token = generate_csrf_token()
    is_secure = _is_secure_request(request)
    response = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="api_key",
        value=api_key,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="csrf_token",
        value=new_csrf_token,
        httponly=False,
        secure=is_secure,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/logout")
async def logout(
    request: Request,
    _csrf: None = Depends(verify_csrf),
):
    is_secure = _is_secure_request(request)
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="api_key", path="/", secure=is_secure)
    response.delete_cookie(key="csrf_token", path="/", secure=is_secure)
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard_index(
    request: Request,
    actor: str = Depends(require_analyst_html),
):
    """Case list and PCAP upload form."""
    csrf_token = _get_csrf_token(request)
    raw_cases = list_all_cases()
    formatted_cases = []
    for c in raw_cases:
        created_str = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(c["created_at"]))
            if c.get("created_at")
            else ""
        )
        formatted_cases.append({
            "case_id": c["id"],
            "pcap_sha256": c["pcap_sha256"],
            "status": c["status"],
            "created_at": created_str,
        })
    response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "cases": formatted_cases,
            "csrf_token": csrf_token,
            "is_authenticated": True,
        },
    )
    if "csrf_token" not in request.cookies:
        response.set_cookie(key="csrf_token", value=csrf_token, httponly=False, samesite="lax", path="/")
    return response


@app.post("/cases/upload-form")
async def upload_case_form(
    request: Request,
    file: UploadFile = File(...),
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
):
    """Browser upload form handler redirecting to case overview."""
    case_id = uuid.uuid4().hex
    pcap_sha256, pcap_path, total_size = await stream_and_validate_pcap(file, case_id)
    create_case(case_id=case_id, pcap_sha256=pcap_sha256, status="uploaded")
    add_audit_entry(
        actor="analyst",
        action="case_uploaded",
        case_id=case_id,
        detail=f"bytes={total_size}",
    )
    return RedirectResponse(url=f"/cases/{case_id}", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# 1. Case Ingestion & Analysis
# ---------------------------------------------------------------------------


@app.post("/cases", status_code=status.HTTP_201_CREATED)
@app.post("/cases/upload", status_code=status.HTTP_201_CREATED)
async def upload_case(
    file: UploadFile = File(...),
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Upload PCAP capture and register a new case."""
    case_id = uuid.uuid4().hex

    # Stream PCAP while validating magic number, size limit, and computing SHA-256
    pcap_sha256, pcap_path, total_size = await stream_and_validate_pcap(file, case_id)

    case_record = create_case(case_id=case_id, pcap_sha256=pcap_sha256, status="uploaded")
    add_audit_entry(
        actor="analyst",
        action="case_uploaded",
        case_id=case_id,
        detail=f"bytes={total_size}",
    )

    return {
        "caseId": case_id,
        "status": "uploaded",
        "pcapSha256": pcap_sha256,
        "createdAt": case_record["created_at"],
    }


@app.post("/cases/{case_id}/analyze")
async def analyze_case(
    case_id: str,
    background_tasks: BackgroundTasks,
    sync: bool = Query(True, description="Run synchronously if True, or as background task if False"),
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Execute offline analysis on case PCAP."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    if case["status"] not in ("uploaded", "failed"):
        return {"caseId": case_id, "status": case["status"], "message": "Case already analyzed"}

    if sync:
        success = execute_analysis(case_id)
        updated_case = get_case(case_id)
        return {
            "caseId": case_id,
            "status": updated_case["status"] if updated_case else "unknown",
            "success": success,
        }
    else:
        background_tasks.add_task(execute_analysis, case_id)
        return {"caseId": case_id, "status": "running"}


@app.post("/cases/{case_id}/distribute")
async def distribute_case(
    case_id: str,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Distribute case PCAP and organization secret to validator inboxes (Tier 1: file copy)."""
    case = get_case(case_id)
    if not case:
        case = get_case_by_onchain_id(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    case_dir = get_case_dir(case["id"])
    pcap_path = case_dir / "pcap.bin"
    if not pcap_path.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Case PCAP (pcap.bin) not found",
        )

    # Read plaintext pcap bytes (transparently decrypting from storage at rest, fails closed)
    raw_pcap_bytes = read_case_pcap(case["id"])

    # Determine organization secret
    secret_hex = config.ORG_SECRET_HEX.strip()
    secret_file = case_dir / "org_secret.hex"
    if secret_file.exists():
        secret_hex = secret_file.read_text(encoding="utf-8").strip()

    repo_root = config.REPO_ROOT
    inboxes_copied: List[str] = []
    validator_ids = ["1", "2", "3"]
    onchain_id_str = case.get("onchain_case_id")

    for vid in validator_ids:
        inbox_dir = repo_root / "validator_inbox" / vid
        case_bundle = inbox_dir / case["id"]
        case_bundle.mkdir(parents=True, exist_ok=True)

        pubkey_hex = get_validator_key(vid)
        if not pubkey_hex:
            local_pub = repo_root / "validator_state" / f"validator_{vid}.pub"
            if local_pub.exists():
                pubkey_hex = local_pub.read_text(encoding="ascii").strip()

        if pubkey_hex:
            import nacl.public
            from validator.crypto import encrypt_validator_bundle

            val_pub = nacl.public.PublicKey(bytes.fromhex(pubkey_hex))
            bundle_enc = encrypt_validator_bundle(
                pcap_bytes=raw_pcap_bytes,
                org_secret_hex=secret_hex,
                validator_public_key=val_pub,
                onchain_case_id=onchain_id_str,
            )
            (case_bundle / "bundle.enc").write_bytes(bundle_enc)
            # Remove any unencrypted artifacts
            (case_bundle / "pcap.bin").unlink(missing_ok=True)
            (case_bundle / "org_secret.hex").unlink(missing_ok=True)

            if onchain_id_str:
                (case_bundle / "onchain_case_id.txt").write_text(
                    onchain_id_str.strip(), encoding="utf-8"
                )
                clean_onchain = onchain_id_str.lower().replace("0x", "")
                onchain_bundle = inbox_dir / clean_onchain
                if onchain_bundle != case_bundle:
                    onchain_bundle.mkdir(parents=True, exist_ok=True)
                    (onchain_bundle / "bundle.enc").write_bytes(bundle_enc)
                    (onchain_bundle / "onchain_case_id.txt").write_text(
                        onchain_id_str.strip(), encoding="utf-8"
                    )
                    (onchain_bundle / "pcap.bin").unlink(missing_ok=True)
                    (onchain_bundle / "org_secret.hex").unlink(missing_ok=True)
        else:
            # Fallback to plaintext delivery (Tier 1 behavior)
            (case_bundle / "pcap.bin").write_bytes(raw_pcap_bytes)
            (case_bundle / "org_secret.hex").write_text(secret_hex, encoding="utf-8")

            if onchain_id_str:
                (case_bundle / "onchain_case_id.txt").write_text(
                    onchain_id_str.strip(), encoding="utf-8"
                )
                clean_onchain = onchain_id_str.lower().replace("0x", "")
                onchain_bundle = inbox_dir / clean_onchain
                if onchain_bundle != case_bundle:
                    onchain_bundle.mkdir(parents=True, exist_ok=True)
                    (onchain_bundle / "pcap.bin").write_bytes(raw_pcap_bytes)
                    (onchain_bundle / "org_secret.hex").write_text(secret_hex, encoding="utf-8")
                    (onchain_bundle / "onchain_case_id.txt").write_text(
                        onchain_id_str.strip(), encoding="utf-8"
                    )

        inboxes_copied.append(f"validator_inbox/{vid}/{case['id']}")

    update_case_status(case["id"], "distributed")
    add_audit_entry(
        actor=actor,
        action="case_distributed",
        case_id=case["id"],
        detail=f"Distributed to {len(validator_ids)} validator inboxes",
    )

    return {
        "caseId": case["id"],
        "onchainCaseId": case.get("onchain_case_id"),
        "status": "distributed",
        "inboxes": inboxes_copied,
    }


# ---------------------------------------------------------------------------
# Validator Public Key Registration (Prompt T3.1)
# ---------------------------------------------------------------------------


@app.post("/validators/{validator_id}/key", status_code=status.HTTP_200_OK)
async def register_validator_public_key(
    validator_id: str,
    payload: Dict[str, Any] = Body(...),
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Register validator Curve25519 public key with the backend."""
    pub_hex = payload.get("publicKeyHex") or payload.get("publicKey") or payload.get("key")
    if not pub_hex or not isinstance(pub_hex, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or invalid 'publicKeyHex' in payload",
        )
    clean_hex = pub_hex.strip().lower().replace("0x", "")
    try:
        raw_key = bytes.fromhex(clean_hex)
        if len(raw_key) != 32:
            raise ValueError("Curve25519 public key must be exactly 32 bytes")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Curve25519 public key hex: {exc}",
        )

    register_validator_key(validator_id, clean_hex)
    add_audit_entry(
        actor=actor,
        action="validator_key_registered",
        detail=f"validator_id={validator_id}",
    )
    return {
        "validatorId": validator_id,
        "publicKeyHex": clean_hex,
        "status": "registered",
    }


@app.get("/validators/{validator_id}/key")
async def get_validator_public_key_route(
    validator_id: str,
    actor: str = Depends(require_analyst),
) -> Dict[str, Any]:
    """Retrieve registered validator public key."""
    key_hex = get_validator_key(validator_id)
    if not key_hex:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Validator {validator_id} public key not registered",
        )
    return {
        "validatorId": validator_id,
        "publicKeyHex": key_hex,
    }


# ---------------------------------------------------------------------------
# 2. Case Metadata & Inspection
# ---------------------------------------------------------------------------


@app.get("/cases/{case_id}")
async def get_case_details(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
) -> Any:
    """Get case status and metadata (JSON or HTML overview)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    if "text/html" in request.headers.get("accept", ""):
        manifest = read_case_json(case_id, "manifest.json") or {}
        result = read_case_json(case_id, "result.json") or {}
        cur_status = case["status"]
        stage_idx = STATUS_STAGE_MAP.get(cur_status, 0)
        timeline_status = cur_status
        timeline_stage_idx = stage_idx

        # Direct 1-click evidence preview on overview
        findings = read_case_json(case_id, "findings.json") or []
        recs = load_recommendations()
        top_findings = []
        for f in findings[:5]:
            r_id = f.get("ruleId", "")
            rec = recs.get(r_id)
            ev_list = []
            for ev in f.get("evidence", []):
                ev_list.append({
                    "sessionId": ev.get("sessionId", 0),
                    "packetNumber": ev.get("packetNumber", 0),
                    "note": ev.get("note", ""),
                })
            top_findings.append({
                "findingId": f.get("findingId", ""),
                "ruleId": r_id,
                "title": rec.get("title", r_id) if rec else r_id,
                "severity": f.get("severity", "Info"),
                "serverEndpoint": f.get("serverEndpoint", ""),
                "evidence": ev_list,
            })

        host_scores = read_case_json(case_id, "host_scores.json") or []

        onchain_id = case.get("onchain_case_id") or ""
        onchain_status = "Not Opened"
        chain_info = {}
        if onchain_id:
            try:
                gateway = get_gateway()
                chain_info = gateway.get_chain_status(case_id)
                onchain_status = chain_info.get("stateName") or chain_info.get("state") or "Opened"
                # The report anchor is authoritative on-chain state. A previous
                # idempotent anchor call may have succeeded before the local case
                # status was synchronized, so derive the final timeline step from
                # the actual contract value as well as the local workflow status.
                report_hash = chain_info.get("reportHash")
                if isinstance(report_hash, str):
                    normalized_report_hash = report_hash.strip().lower()
                    if normalized_report_hash.startswith("0x"):
                        normalized_report_hash = normalized_report_hash[2:]
                    if (
                        len(normalized_report_hash) == 64
                        and any(char != "0" for char in normalized_report_hash)
                        and all(char in "0123456789abcdef" for char in normalized_report_hash)
                    ):
                        timeline_status = "report_anchored"
                        timeline_stage_idx = STATUS_STAGE_MAP["report_anchored"]
            except Exception:
                onchain_status = "Unavailable"

        engine_configured = False
        commit_deadline_passed = False
        try:
            gw_inst = get_gateway()
            active_img, active_rule = gw_inst.case_registry.functions.activeEngine().call()
            engine_configured = bool(active_img != bytes(32) and active_rule != bytes(32))
            if chain_info and chain_info.get("commitDeadline"):
                now_ts = gw_inst.w3.eth.get_block("latest").timestamp
                commit_deadline_passed = bool(now_ts >= chain_info["commitDeadline"])
        except Exception:
            engine_configured = False
            commit_deadline_passed = False

        return templates.TemplateResponse(
            "overview.html",
            {
                "request": request,
                "case_id": case["id"],
                "active_tab": "overview",
                "current_status": cur_status,
                "timeline_status": timeline_status,
                "onchain_status": onchain_status,
                "chain_info": chain_info,
                "engine_configured": engine_configured,
                "commit_deadline_passed": commit_deadline_passed,
                "can_finalize": chain_info.get("canFinalize", False),
                "quorum_reached": chain_info.get("quorumReached", False),
                "matching_reveals": chain_info.get("matchingReveals", 0),
                "quorum_k": chain_info.get("k", 2),
                "validators": chain_info.get("validators", []),
                "stage_index": timeline_stage_idx,
                "pcap_sha256": case["pcap_sha256"],
                "result_root": result.get("resultRoot") or manifest.get("resultRoot") or "",
                "ruleset_hash": manifest.get("rulesetHash") or "",
                "onchain_id": onchain_id,
                "top_findings": top_findings,
                "top_hosts": host_scores[:5],
                "csrf_token": _get_csrf_token(request),
                "error": request.query_params.get("error"),
                "success": request.query_params.get("success"),
            },
        )
    return case


@app.get("/cases/{case_id}/sessions")
async def get_case_sessions(
    case_id: str,
    request: Request,
    host: Optional[str] = Query(None),
    finding: Optional[str] = Query(None),
    proto: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("sessionId"),
    sort_order: Optional[str] = Query("asc"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    actor: str = Depends(require_analyst_html),
) -> Any:
    """Get paginated session records from disk (JSON or HTML)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    raw_sessions = read_case_json(case_id, "sessions.json")
    if raw_sessions is None:
        if "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(
                "sessions.html",
                {
                    "request": request,
                    "case_id": case_id,
                    "active_tab": "sessions",
                    "sessions": [],
                    "all_hosts": [],
                    "selected_host": "",
                    "all_rules": [],
                    "selected_finding": "",
                    "selected_proto": "",
                    "sort_by": sort_by,
                    "sort_order": sort_order,
                },
            )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sessions not found (analysis pending)")

    from engine.smscope.models import SessionRecord
    sessions = [
        SessionRecord.from_dict(s).to_dict(include_extended=True) if isinstance(s, dict) else s
        for s in raw_sessions
    ]

    if "text/html" in request.headers.get("accept", ""):
        all_hosts = sorted(list({s.get("serverEndpoint") for s in sessions if s.get("serverEndpoint")}))
        findings = read_case_json(case_id, "findings.json") or []
        all_rules = sorted(list({f.get("ruleId") for f in findings if f.get("ruleId")}))

        filtered = list(sessions)
        if host:
            filtered = [s for s in filtered if s.get("serverEndpoint") == host]
        if proto:
            filtered = [s for s in filtered if str(s.get("protocol", "")).upper() == proto.upper()]
        if finding:
            matched_sids = set()
            for f in findings:
                if f.get("ruleId") == finding:
                    matched_sids.update(f.get("sortedSessionIds", []))
            filtered = [s for s in filtered if s.get("sessionId") in matched_sids]

        # Sort sessions
        rev = (sort_order == "desc")
        if sort_by == "clientEndpoint":
            filtered.sort(key=lambda s: str(s.get("clientEndpoint", "")), reverse=rev)
        elif sort_by == "serverEndpoint":
            filtered.sort(key=lambda s: str(s.get("serverEndpoint", "")), reverse=rev)
        elif sort_by == "protocol":
            filtered.sort(key=lambda s: str(s.get("protocol", "")), reverse=rev)
        else:
            filtered.sort(key=lambda s: int(s.get("sessionId", 0)), reverse=rev)

        return templates.TemplateResponse(
            "sessions.html",
            {
                "request": request,
                "case_id": case_id,
                "active_tab": "sessions",
                "sessions": filtered,
                "all_hosts": all_hosts,
                "selected_host": host or "",
                "all_rules": all_rules,
                "selected_finding": finding or "",
                "selected_proto": proto or "",
                "sort_by": sort_by or "sessionId",
                "sort_order": sort_order or "asc",
            },
        )

    total = len(sessions)
    page = sessions[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": page}


@app.get("/cases/{case_id}/findings")
async def get_case_findings(
    case_id: str,
    request: Request,
    severity: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("severity"),
    sort_order: Optional[str] = Query("desc"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    actor: str = Depends(require_analyst_html),
) -> Any:
    """Get paginated cryptographic findings from disk (JSON or HTML)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    findings = read_case_json(case_id, "findings.json")
    if findings is None:
        if "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(
                "findings.html",
                {
                    "request": request,
                    "case_id": case_id,
                    "active_tab": "findings",
                    "findings": [],
                    "all_hosts": [],
                    "selected_severity": "",
                    "selected_host": "",
                    "sort_by": sort_by,
                    "sort_order": sort_order,
                },
            )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Findings not found (analysis pending)")

    if "text/html" in request.headers.get("accept", ""):
        recs = load_recommendations()
        all_hosts = sorted(list({f.get("serverEndpoint") for f in findings if f.get("serverEndpoint")}))
        enriched_findings = []
        for f in findings:
            r_id = f.get("ruleId", "")
            rec = recs.get(r_id)
            ev_list = []
            for ev in f.get("evidence", []):
                ev_list.append({
                    "sessionId": ev.get("sessionId", 0),
                    "packetNumber": ev.get("packetNumber", 0),
                    "note": ev.get("note", ""),
                })
            enriched_findings.append({
                "findingId": f.get("findingId", ""),
                "ruleId": r_id,
                "title": rec.get("title", r_id) if rec else r_id,
                "severity": f.get("severity", "Info"),
                "serverEndpoint": f.get("serverEndpoint", ""),
                "sessionCount": f.get("sessionCount", 1),
                "evidence": ev_list,
                "recommendation": rec,
                "details": f.get("details", {}),
            })

        # Filter
        if severity:
            enriched_findings = [f for f in enriched_findings if f["severity"].lower() == severity.lower()]
        if host:
            enriched_findings = [f for f in enriched_findings if f["serverEndpoint"] == host]

        # Sort
        sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        rev = (sort_order == "desc")
        if sort_by == "ruleId":
            enriched_findings.sort(key=lambda f: f["ruleId"], reverse=rev)
        elif sort_by == "sessionCount":
            enriched_findings.sort(key=lambda f: f["sessionCount"], reverse=rev)
        else:
            enriched_findings.sort(key=lambda f: (sev_rank.get(f["severity"], 0), f["ruleId"]), reverse=rev)

        return templates.TemplateResponse(
            "findings.html",
            {
                "request": request,
                "case_id": case_id,
                "active_tab": "findings",
                "findings": enriched_findings,
                "all_hosts": all_hosts,
                "selected_severity": severity or "",
                "selected_host": host or "",
                "sort_by": sort_by or "severity",
                "sort_order": sort_order or "desc",
            },
        )

    total = len(findings)
    page = findings[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": page}


@app.get("/cases/{case_id}/hosts")
async def get_case_hosts(
    case_id: str,
    request: Request,
    grade: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("score"),
    sort_order: Optional[str] = Query("desc"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    actor: str = Depends(require_analyst_html),
) -> Any:
    """Get paginated host scores and posture summaries (JSON or HTML)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    hosts = read_case_json(case_id, "host_scores.json")
    if hosts is None:
        if "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(
                "hosts.html",
                {
                    "request": request,
                    "case_id": case_id,
                    "active_tab": "hosts",
                    "host_scores": [],
                    "host_scores_svg": "",
                    "selected_grade": "",
                    "sort_by": sort_by,
                    "sort_order": sort_order,
                },
            )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host scores not found (analysis pending)")

    if "text/html" in request.headers.get("accept", ""):
        findings = read_case_json(case_id, "findings.json") or []
        enriched_hosts = []
        for h in hosts:
            ep = h.get("serverEndpoint", "")
            f_count = sum(1 for f in findings if f.get("serverEndpoint") == ep)
            enriched_hosts.append({
                "hostId": h.get("hostId", ""),
                "serverEndpoint": ep,
                "score": h.get("score", 0),
                "grade": h.get("grade", "F"),
                "findingsDigest": h.get("findingsDigest", ""),
                "finding_count": f_count,
            })

        from backend.charts import generate_host_scores_svg
        host_scores_svg = generate_host_scores_svg(enriched_hosts)

        # Filter
        if grade:
            enriched_hosts = [h for h in enriched_hosts if h["grade"].upper() == grade.upper()]

        # Sort
        rev = (sort_order == "desc")
        if sort_by == "serverEndpoint":
            enriched_hosts.sort(key=lambda h: h["serverEndpoint"], reverse=rev)
        elif sort_by == "grade":
            enriched_hosts.sort(key=lambda h: h["grade"], reverse=rev)
        else:
            enriched_hosts.sort(key=lambda h: int(h["score"]), reverse=rev)

        return templates.TemplateResponse(
            "hosts.html",
            {
                "request": request,
                "case_id": case_id,
                "active_tab": "hosts",
                "host_scores": enriched_hosts,
                "host_scores_svg": host_scores_svg,
                "selected_grade": grade or "",
                "sort_by": sort_by or "score",
                "sort_order": sort_order or "desc",
            },
        )

    total = len(hosts)
    page = hosts[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": page}


@app.get("/cases/{case_id}/hosts/{host_id_or_ep}", response_class=HTMLResponse)
async def get_case_host_detail(
    case_id: str,
    host_id_or_ep: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
):
    """Render drill-down page for a specific host (findings, sessions, certs, FS share, posture chain)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    host_scores = read_case_json(case_id, "host_scores.json") or []
    import urllib.parse
    decoded = urllib.parse.unquote(host_id_or_ep)

    target_host = None
    for h in host_scores:
        if (
            h.get("hostId") == host_id_or_ep
            or h.get("serverEndpoint") == decoded
            or h.get("serverEndpoint") == host_id_or_ep
        ):
            target_host = dict(h)
            break

    if not target_host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Host not found: {host_id_or_ep}")

    ep = target_host.get("serverEndpoint", "")
    findings = read_case_json(case_id, "findings.json") or []
    sessions = read_case_json(case_id, "sessions.json") or []

    # 1. Findings on this host
    recs = load_recommendations()
    host_findings = []
    for f in findings:
        if f.get("serverEndpoint") == ep:
            r_id = f.get("ruleId", "")
            rec = recs.get(r_id)
            ev_list = []
            for ev in f.get("evidence", []):
                ev_list.append({
                    "sessionId": ev.get("sessionId", 0),
                    "packetNumber": ev.get("packetNumber", 0),
                    "note": ev.get("note", ""),
                })
            host_findings.append({
                "ruleId": r_id,
                "title": rec.get("title", r_id) if rec else r_id,
                "severity": f.get("severity", "Info"),
                "sessionCount": f.get("sessionCount", 1),
                "evidence": ev_list,
            })

    # 2. Sessions on this host
    host_sessions = [s for s in sessions if s.get("serverEndpoint") == ep]

    # 3. Certificates on this host
    cert_map: Dict[str, Dict[str, Any]] = {}
    total_tls = 0
    fs_count = 0
    for s in host_sessions:
        tls_info = s.get("tls")
        if tls_info:
            total_tls += 1
            if tls_info.get("forwardSecrecy"):
                fs_count += 1
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
                    "verdicts": list(cert.get("verdicts", [])),
                }

    host_certs = list(cert_map.values())

    # 4. Forward Secrecy Share
    share_pct = int(round(100 * fs_count / total_tls)) if total_tls > 0 else 0
    fs_share = {
        "forwardSecrecyCount": fs_count,
        "totalTls": total_tls,
        "sharePercent": share_pct,
    }

    # 5. Merkle Leaf and Posture Chain
    from engine.smscope.results.hashing import host_score_leaf
    try:
        leaf_hash = host_score_leaf(
            target_host["hostId"],
            target_host["findingsDigest"],
            int(target_host["score"]),
        ).hex()
    except Exception:
        leaf_hash = "0" * 64
    target_host["leafHash"] = leaf_hash

    posture_records = []
    txs = get_chain_txs(case_id)
    for tx in txs:
        if tx.get("op") == "record":
            posture_records.append({
                "recordHash": str(tx.get("tx_hash", ""))[:32] + "...",
                "leafHash": leaf_hash,
                "score": target_host["score"],
            })

    return templates.TemplateResponse(
        "host_detail.html",
        {
            "request": request,
            "case_id": case_id,
            "active_tab": "hosts",
            "host": target_host,
            "findings": host_findings,
            "sessions": host_sessions,
            "certificates": host_certs,
            "fs_share": fs_share,
            "posture_records": posture_records,
        },
    )


@app.get("/cases/{case_id}/anomalies", response_class=HTMLResponse)
@app.get("/cases/{case_id}/anomaly", response_class=HTMLResponse)
async def get_case_anomalies_page(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
):
    """Render advisory anomaly flags page from offline unsupervised model."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    sessions = read_case_json(case_id, "sessions.json") or []
    anomalies: List[Dict[str, Any]] = []

    advisory_model_path = Path(__file__).resolve().parent.parent / "advisory" / "anomaly" / "model.joblib"
    advisory_summary_path = Path(__file__).resolve().parent.parent / "advisory" / "anomaly" / "baseline_summary.json"

    if advisory_model_path.exists() and advisory_summary_path.exists() and sessions:
        try:
            from advisory.anomaly.detector import AnomalyDetector
            detector = AnomalyDetector(advisory_model_path, advisory_summary_path)
            for s in sessions:
                scored = detector.score_session(s)
                anomalies.append({
                    "sessionId": int(scored.get("sessionId", 0)),
                    "serverEndpoint": str(scored.get("serverEndpoint", "")),
                    "anomalyScore": f"{float(scored.get('anomalyScore', 0.0)):.4f}",
                    "flagged": bool(scored.get("isAnomaly", False)),
                    "topDeviatingFeatures": list(scored.get("topDeviatingFeatures", [])),
                    "explanation": str(scored.get("explanationNote", "")),
                })
        except Exception:
            pass

    # Sort anomalous sessions first, then by score descending
    anomalies.sort(key=lambda x: (not x["flagged"], x["anomalyScore"]), reverse=False)

    return templates.TemplateResponse(
        "anomalies.html",
        {
            "request": request,
            "case_id": case_id,
            "active_tab": "anomalies",
            "anomalies": anomalies,
        },
    )


@app.get("/cases/{case_id}/tls", response_class=HTMLResponse)
async def get_case_tls_page(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
):
    """Render TLS protocol version and cipher suite distribution metrics page."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    sessions = read_case_json(case_id, "sessions.json") or []
    tls_version_counts: Dict[str, int] = {}
    cipher_counts: Dict[str, int] = {}
    server_tls_stats: Dict[str, Dict[str, int]] = {}

    for s in sessions:
        endpoint = str(s.get("serverEndpoint", ""))
        if endpoint and endpoint not in server_tls_stats:
            server_tls_stats[endpoint] = {"forwardSecrecyCount": 0, "totalTls": 0}

        tls_info = s.get("tls")
        if tls_info:
            if endpoint:
                server_tls_stats[endpoint]["totalTls"] += 1
            ver = str(tls_info.get("version") or "Unknown")
            tls_version_counts[ver] = tls_version_counts.get(ver, 0) + 1

            cipher = str(tls_info.get("cipherSuiteName") or "Unknown")
            cipher_counts[cipher] = cipher_counts.get(cipher, 0) + 1

            if tls_info.get("forwardSecrecy") and endpoint:
                server_tls_stats[endpoint]["forwardSecrecyCount"] += 1
        else:
            tls_version_counts["None"] = tls_version_counts.get("None", 0) + 1

    fs_share: Dict[str, Dict[str, int]] = {}
    for ep, stats in sorted(server_tls_stats.items()):
        total = stats["totalTls"]
        fs_count = stats["forwardSecrecyCount"]
        share = int(round(100 * fs_count / total)) if total > 0 else 0
        fs_share[ep] = {
            "forwardSecrecyCount": fs_count,
            "totalTls": total,
            "sharePercent": share,
        }

    total_tls = sum(v for k, v in tls_version_counts.items() if k != "None")

    from backend.charts import generate_version_distribution_svg, generate_cipher_distribution_svg
    version_svg = generate_version_distribution_svg(tls_version_counts)
    cipher_svg = generate_cipher_distribution_svg(cipher_counts)

    return templates.TemplateResponse(
        "tls.html",
        {
            "request": request,
            "case_id": case_id,
            "active_tab": "tls",
            "tls_versions": dict(sorted(tls_version_counts.items())),
            "total_sessions": len(sessions),
            "total_tls": total_tls,
            "fs_share": fs_share,
            "cipher_suites": dict(sorted(cipher_counts.items(), key=lambda x: -x[1])),
            "version_svg": version_svg,
            "cipher_svg": cipher_svg,
        },
    )


@app.get("/cases/{case_id}/certificates", response_class=HTMLResponse)
async def get_case_certificates_page(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
):
    """Render observed X.509 certificates table."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    sessions = read_case_json(case_id, "sessions.json") or []
    cert_map: Dict[str, Dict[str, Any]] = {}
    for s in sessions:
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
                }
    certificates_table = [cert_map[k] for k in sorted(cert_map.keys())]

    return templates.TemplateResponse(
        "certificates.html",
        {
            "request": request,
            "case_id": case_id,
            "active_tab": "certificates",
            "certificates": certificates_table,
        },
    )


def _compute_verifier_steps_and_state(case_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    """Helper to assemble chain state, validators, transactions, and 5-step verifier results."""
    case = get_case(case_id) or {}
    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"
    manifest = read_case_json(case_id, "manifest.json") or {}
    result = read_case_json(case_id, "result.json") or {}
    findings_data = read_case_json(case_id, "findings.json") or []
    scores_data = read_case_json(case_id, "host_scores.json") or []

    # Step 1: Recompute PCAP SHA-256
    actual_pcap_sha = ""
    pcap_read_error = ""
    if not pcap_path.exists():
        pcap_read_error = "Stored PCAP file missing on disk"
    else:
        from validator.crypto import decrypt_at_rest
        try:
            actual_pcap_sha = hashlib.sha256(decrypt_at_rest(pcap_path.read_bytes())).hexdigest().lower()
        except Exception as exc:
            actual_pcap_sha = ""
            pcap_read_error = f"PCAP decryption failed: {exc}"

    # Step 2: Leaves & Root Rebuild
    step2_match = False
    step2_status = "PENDING"
    step2_details = "Local analysis pending: result.json not yet generated"
    result_root = (result.get("resultRoot") or "").lower().replace("0x", "") if result else ""

    if result is not None:
        if not result_root:
            step2_status = "FAIL"
            step2_details = "result.json missing resultRoot"
        elif findings_data is None or scores_data is None:
            step2_status = "FAIL"
            step2_details = "findings.json or host_scores.json missing for result validation"
        else:
            try:
                from engine.smscope.results.canonical import canonical_json
                from engine.smscope.results.hashing import finding_leaf, host_score_leaf
                from engine.smscope.results.merkle import MerkleTree

                leaves = []
                for f in findings_data:
                    leaves.append(finding_leaf(canonical_json(f)))
                for s in scores_data:
                    leaves.append(host_score_leaf(s["hostId"], s["findingsDigest"], int(s["score"])))
                if leaves:
                    computed_tree = MerkleTree(leaves)
                    step2_match = (computed_tree.root.hex().lower() == result_root)
                    if step2_match:
                        step2_status = "PASS"
                        step2_details = f"Result Root matches rebuilt tree: {result_root[:16]}..."
                    else:
                        step2_status = "FAIL"
                        step2_details = "Result tree mismatch: computed root does not match stored resultRoot"
                else:
                    step2_status = "FAIL"
                    step2_details = "No leaves found to rebuild Merkle tree"
            except Exception as exc:
                step2_match = False
                step2_status = "FAIL"
                step2_details = f"Tree rebuild error: {exc}"

    # On-Chain State from Gateway
    chain_info: Dict[str, Any] = {}
    validators: List[Dict[str, Any]] = []
    txs = get_chain_txs(case_id)

    step1_match = False
    if pcap_read_error:
        step1_status = "FAIL"
        step1_details = pcap_read_error
    else:
        step1_status = "PENDING"
        step1_details = "Case not yet opened on-chain"

    step3_match = False
    step3_status = "PENDING"
    step3_details = "Case not yet finalized on-chain"

    step4_match = False
    step4_status = "PENDING"
    step4_details = "Posture not yet recorded on-chain"

    step5_match = False
    step5_status = "PENDING"
    step5_details = "Report not yet anchored on-chain"

    onchain_case_id = case.get("onchain_case_id")
    if onchain_case_id:
        try:
            gw = get_gateway()
            try:
                gw.poll_events()
            except Exception:
                pass
            chain_info = gw.get_chain_status(case_id)
            validators = chain_info.get("validators", [])

            # Step 1 check vs on-chain pcapHash
            db_pcap_hash = (case.get("pcap_sha256") or manifest.get("pcapSha256") or "").lower()
            onchain_pcap = (chain_info.get("pcapHash") or "").lower().replace("0x", "")
            if pcap_read_error:
                step1_match = False
                step1_status = "FAIL"
                step1_details = pcap_read_error
            elif not onchain_pcap or onchain_pcap == "0" * 64:
                step1_match = False
                step1_status = "FAIL"
                step1_details = "On-chain pcapHash is missing or zero for opened case"
            elif db_pcap_hash and actual_pcap_sha != db_pcap_hash:
                step1_match = False
                step1_status = "FAIL"
                step1_details = "Decrypted PCAP hash does not match stored case record and does not match on-chain pcapHash"
            elif actual_pcap_sha and actual_pcap_sha == onchain_pcap:
                step1_match = True
                step1_status = "PASS"
                step1_details = f"Stored PCAP matches on-chain pcapHash: {actual_pcap_sha[:16]}..."
            else:
                step1_match = False
                step1_status = "FAIL"
                step1_details = "Stored PCAP SHA-256 does not match on-chain pcapHash"

            # Step 3 check vs on-chain finalRoot
            final_root = (chain_info.get("finalRoot") or "").lower().replace("0x", "")
            if final_root and final_root != "0" * 64:
                step3_match = (result_root == final_root and bool(result_root))
                step3_status = "PASS" if step3_match else "FAIL"
                step3_details = "Result root matches on-chain finalRoot" if step3_match else "Result root mismatch with on-chain finalRoot"
            else:
                step3_status = "PENDING"
                step3_details = "Case not yet finalized on-chain"

            # Step 4: Walk and verify PostureLedger records
            if chain_info.get("state") == "Finalized" and len(scores_data) > 0 and gw.posture_ledger:
                try:
                    from backend.chain.verifier import verify_posture_ledger_hash_chain
                    case_bytes = bytes.fromhex(onchain_case_id.replace("0x", ""))
                    result_root_bytes = bytes.fromhex(result_root) if result_root else bytes(32)
                    step4_match, step4_details = verify_posture_ledger_hash_chain(
                        posture_ledger_contract=gw.posture_ledger,
                        onchain_case_bytes=case_bytes,
                        result_root_bytes=result_root_bytes,
                        expected_host_scores=scores_data,
                        w3_instance=getattr(gw, "w3", None),
                    )
                    step4_status = "PASS" if step4_match else "FAIL"
                except Exception as exc:
                    step4_match = False
                    step4_status = "FAIL"
                    step4_details = f"PostureLedger verification error: {exc}"
            else:
                step4_match = False
                step4_status = "PENDING"
                step4_details = "Posture not yet recorded on-chain"

            # Step 5: ReportHash check
            rep_file = case_dir / "report.json"
            anchored_report = (chain_info.get("reportHash") or "").lower().replace("0x", "")
            if anchored_report and anchored_report != "0" * 64:
                if rep_file.exists():
                    actual_rep_hash = hashlib.sha256(rep_file.read_bytes()).hexdigest().lower()
                    step5_match = (actual_rep_hash == anchored_report)
                    step5_status = "PASS" if step5_match else "FAIL"
                    step5_details = "Report hash matches on-chain anchored reportHash" if step5_match else "Report hash mismatch with on-chain reportHash"
                else:
                    step5_status = "FAIL"
                    step5_details = "report.json missing locally"
        except CaseNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"On-chain case record not found for case {case_id}",
            )
        except HTTPException:
            raise
        except Exception as exc:
            err_str = str(exc).lower()
            if "connection" in err_str or "max retries" in err_str or "actively refused" in err_str or "failed to establish" in err_str:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Blockchain RPC endpoint is unavailable",
                )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Blockchain service error: {exc}",
            )
    else:
        # Case has not been opened on-chain yet
        chain_info = {
            "caseId": case_id,
            "status": case.get("status", "uploaded"),
            "onchainCaseId": None,
            "state": "None",
            "stateName": "Not Opened",
            "finalRoot": None,
            "reportHash": None,
            "round": 0,
            "k": 2,
            "n": 3,
            "validators": [],
            "transactions": txs,
        }

    verifier_steps = [
        {
            "step": 1,
            "name": "PCAP SHA-256 vs On-Chain pcapHash",
            "status": step1_status,
            "details": step1_details,
        },
        {
            "step": 2,
            "name": "Off-Chain Leaves & Root Rebuild",
            "status": step2_status,
            "details": step2_details,
        },
        {
            "step": 3,
            "name": "Result Root vs On-Chain finalRoot",
            "status": step3_status,
            "details": step3_details,
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

    has_fail = any(s["status"] == "FAIL" for s in verifier_steps)
    has_pending = any(s["status"] == "PENDING" for s in verifier_steps)
    if has_fail:
        overall_status = "FAIL"
    elif has_pending:
        overall_status = "PENDING"
    else:
        overall_status = "PASS"
    chain_info["overall_status"] = overall_status

    all_passed = bool(
        step1_match
        and step1_status == "PASS"
        and step2_match
        and step2_status == "PASS"
        and step3_match
        and step3_status == "PASS"
        and step4_match
        and step4_status == "PASS"
        and step5_match
        and step5_status == "PASS"
    )
    return verifier_steps, chain_info, validators, txs, all_passed


@app.get("/cases/{case_id}/chain")
async def get_case_chain_state(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
) -> Any:
    """Get on-chain custody and transaction state (JSON or HTML)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    verifier_steps, chain_info, validators, txs, all_passed = _compute_verifier_steps_and_state(case_id)
    deployment_info = get_client_deployment_config()
    deployment_info["case"] = {
        "caseId": case_id,
        "onchainCaseId": chain_info.get("onchainCaseId") or case.get("onchain_case_id"),
        "pcapHash": chain_info.get("pcapHash") or case.get("pcap_sha256"),
        "finalRoot": chain_info.get("finalRoot"),
        "reportHash": chain_info.get("reportHash"),
        "status": chain_info.get("stateName") or case.get("status"),
        "transactions": txs,
    }

    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(
            "chain.html",
            {
                "request": request,
                "case_id": case_id,
                "active_tab": "chain",
                "chain_state": chain_info,
                "verifier_steps": verifier_steps,
                "verification_result": None,
                "validator_submissions": validators,
                "transactions": txs,
                "deployment_info": deployment_info,
                "csrf_token": _get_csrf_token(request),
            },
        )

    if not case.get("onchain_case_id"):
        result_json = read_case_json(case_id, "result.json")
        result_root = result_json.get("resultRoot") if result_json else None
        return {
            "caseId": case_id,
            "status": case["status"],
            "onchainCaseId": None,
            "state": "None",
            "resultRoot": result_root,
            "transactions": txs,
        }

    return chain_info


@app.get("/cases/{case_id}/chain/config")
async def get_case_chain_config(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst_html),
) -> Dict[str, Any]:
    """Return JSON deployment configuration, ABIs, and case details for client-side inspection."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    dep_cfg = get_client_deployment_config()
    txs = get_chain_txs(case_id)
    onchain_case_id = case.get("onchain_case_id")
    pcap_sha = case.get("pcap_sha256") or ""

    return {
        **dep_cfg,
        "case": {
            "caseId": case_id,
            "onchainCaseId": onchain_case_id,
            "pcapHash": pcap_sha,
            "status": case.get("status", "uploaded"),
            "transactions": txs,
        },
    }


@app.post("/cases/{case_id}/chain/verify")
async def verify_case_browser(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
):
    """Run Section 8 independent verification suite and render HTML results."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    verifier_steps, chain_info, validators, txs, all_passed = _compute_verifier_steps_and_state(case_id)
    deployment_info = get_client_deployment_config()
    deployment_info["case"] = {
        "caseId": case_id,
        "onchainCaseId": chain_info.get("onchainCaseId") or case.get("onchain_case_id"),
        "pcapHash": chain_info.get("pcapHash") or case.get("pcap_sha256"),
        "finalRoot": chain_info.get("finalRoot"),
        "reportHash": chain_info.get("reportHash"),
        "status": chain_info.get("stateName") or case.get("status"),
        "transactions": txs,
    }
    return templates.TemplateResponse(
        "chain.html",
        {
            "request": request,
            "case_id": case_id,
            "active_tab": "chain",
            "chain_state": chain_info,
            "verifier_steps": verifier_steps,
            "verification_result": {
                "verified": all_passed,
                "overall_status": chain_info.get("overall_status", "PASS" if all_passed else "FAIL"),
                "has_pending": any(s["status"] == "PENDING" for s in verifier_steps),
                "has_fail": any(s["status"] == "FAIL" for s in verifier_steps),
            },
            "validator_submissions": validators,
            "transactions": txs,
            "deployment_info": deployment_info,
            "csrf_token": _get_csrf_token(request),
        },
    )


@app.post("/cases/{case_id}/action/{action}")
async def execute_case_browser_action(
    case_id: str,
    action: str,
    request: Request,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
):
    """Execute lifecycle action from browser overview and redirect to case with clear error messages."""
    import urllib.parse
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    act = action.lower()
    error_msg = None
    def _get_active_gateway():
        try:
            return get_gateway()
        except Exception as exc:
            raise GatewayError(f"Blockchain gateway is unavailable: {exc}")

    try:
        if act == "analyze":
            execute_analysis(case_id)
        elif act == "open":
            gateway = _get_active_gateway()
            gateway.open_case(case_id)
        elif act in ("register_engine", "register-engine"):
            gateway = _get_active_gateway()
            res = gateway.register_engine_for_case(case_id=case_id)
            if res.get("idempotent"):
                msg = "Engine and ruleset hash are already registered on-chain. Ready to submit claim."
            else:
                msg = f"Engine and ruleset successfully registered on CaseRegistry! Ready to submit claim."
            encoded_msg = urllib.parse.quote(msg)
            return RedirectResponse(url=f"/cases/{case_id}?success={encoded_msg}", status_code=status.HTTP_303_SEE_OTHER)
        elif act == "claim":
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Claim action requires an on-chain case.")
            gateway = _get_active_gateway()
            gateway.submit_claim(case_id)
        elif act == "distribute":
            await distribute_case(case_id, actor="browser_analyst")
            encoded_msg = urllib.parse.quote(
                "Action 'distribute' completed: Bundles placed in validator inboxes. Next: Run Validator Consensus."
            )
            return RedirectResponse(url=f"/cases/{case_id}?success={encoded_msg}", status_code=status.HTTP_303_SEE_OTHER)
        elif act in ("validate", "validators", "consensus"):
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Validator consensus requires an on-chain case.")
            gateway = _get_active_gateway()
            val_res = gateway.run_validator_round(case_id)
            if not val_res.get("quorumReached"):
                msg = val_res.get("message") or f"Validator consensus did not reach quorum ({val_res.get('reveals', 0)}/{val_res.get('quorum', 2)} matching reveals)."
                encoded_err = urllib.parse.quote(msg)
                return RedirectResponse(url=f"/cases/{case_id}?error={encoded_err}", status_code=status.HTTP_303_SEE_OTHER)
            encoded_msg = urllib.parse.quote(
                f"Validator consensus achieved: {val_res.get('reveals', 0)}/{val_res.get('quorum', 2)} matching reveals on-chain (Quorum: Reached)"
            )
            return RedirectResponse(url=f"/cases/{case_id}?success={encoded_msg}", status_code=status.HTTP_303_SEE_OTHER)
        elif act in ("resolve_new_round", "new_round"):
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet.")
            gateway = _get_active_gateway()
            res = gateway.resolve(case_id, action="NewRound")
            new_status = res.get("status", "committing")
            encoded_msg = urllib.parse.quote(
                f"Admin resolution completed: New round started on-chain! Case state is now '{new_status}'. Validators can now commit."
            )
            return RedirectResponse(url=f"/cases/{case_id}?success={encoded_msg}", status_code=status.HTTP_303_SEE_OTHER)
        elif act == "advance":
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Advance action requires an on-chain case.")
            gateway = _get_active_gateway()
            gateway.advance(case_id)
        elif act == "finalize":
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Finalize action requires an on-chain case.")
            gateway = _get_active_gateway()
            gateway.finalize(case_id)
        elif act == "record":
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Record action requires an on-chain case.")
            gateway = _get_active_gateway()
            gateway.record_posture(case_id)
        elif act == "anchor":
            if not case.get("onchain_case_id"):
                raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Anchor action requires an on-chain case.")
            gateway = _get_active_gateway()
            gateway.anchor_report(case_id)
        else:
            raise InvalidStateError(f"Unknown browser action: {action}")
    except (CaseNotFoundError, InvalidStateError, GatewayError, TransactionRevertedError) as exc:
        error_msg = str(exc)
    except Exception as exc:
        logger.exception("Unexpected error executing browser action '%s' for case %s", act, case_id)
        error_msg = f"An unexpected error occurred while executing {act}. Please check server logs."

    if error_msg:
        encoded_err = urllib.parse.quote(error_msg)
        return RedirectResponse(url=f"/cases/{case_id}?error={encoded_err}", status_code=status.HTTP_303_SEE_OTHER)

    encoded_msg = urllib.parse.quote(f"Action '{act}' completed successfully")
    return RedirectResponse(url=f"/cases/{case_id}?success={encoded_msg}", status_code=status.HTTP_303_SEE_OTHER)



@app.post("/cases/{case_id}/verify")
async def verify_case_endpoint(
    case_id: str,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Run verification checks on case outputs."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"
    if not pcap_path.exists():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="pcap.bin missing")

    # Step 1: Recompute PCAP SHA-256
    from validator.crypto import decrypt_at_rest
    actual_sha = hashlib.sha256(decrypt_at_rest(pcap_path.read_bytes())).hexdigest()
    pcap_match = (actual_sha == case["pcap_sha256"])

    # Step 2: Rebuild leaves and result root from canonical findings and host scores
    result_data = read_case_json(case_id, "result.json")
    findings_data = read_case_json(case_id, "findings.json")
    scores_data = read_case_json(case_id, "host_scores.json")

    merkle_valid = False
    if result_data and findings_data is not None and scores_data is not None:
        try:
            from engine.smscope.results.canonical import canonical_json
            from engine.smscope.results.hashing import finding_leaf, host_score_leaf
            from engine.smscope.results.merkle import MerkleTree

            leaves = []
            for f in findings_data:
                leaves.append(finding_leaf(canonical_json(f)))
            for s in scores_data:
                leaves.append(host_score_leaf(s["hostId"], s["findingsDigest"], s["score"]))

            computed_tree = MerkleTree(leaves)
            merkle_valid = (computed_tree.root.hex() == result_data.get("resultRoot"))
        except Exception:
            merkle_valid = False

    passed = pcap_match and merkle_valid
    return {
        "caseId": case_id,
        "pcapVerified": pcap_match,
        "merkleRootVerified": merkle_valid,
        "verified": passed,
    }


@app.get("/hosts/{host_id}/posture-chain")
async def get_host_posture_chain(
    host_id: str,
    actor: str = Depends(require_analyst),
) -> Dict[str, Any]:
    """Retrieve hash-linked posture chain for host."""
    clean_host = host_id.replace("0x", "")
    try:
        gateway = get_gateway()
        host_id_bytes = bytes.fromhex(clean_host)
        count = gateway.posture_ledger.functions.recordCount(host_id_bytes).call()
        records = []
        for i in range(count):
            r = gateway.posture_ledger.functions.recordAt(host_id_bytes, i).call()
            records.append({
                "hostId": "0x" + r[0].hex(),
                "caseId": "0x" + r[1].hex(),
                "score": r[2],
                "resultRoot": "0x" + r[3].hex(),
                "prevHash": "0x" + r[4].hex(),
                "timestamp": r[5],
                "recordHash": "0x" + r[6].hex(),
            })
        return {
            "hostId": host_id,
            "records": records,
            "length": len(records),
        }
    except Exception:
        return {
            "hostId": host_id,
            "records": [],
            "length": 0,
        }


# ---------------------------------------------------------------------------
# 4. Chain-Changing Endpoints (Prompt 6.2)
# ---------------------------------------------------------------------------


@app.post("/cases/{case_id}/open")
async def open_case_on_chain(
    case_id: str,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Open forensic case in CaseRegistry."""
    try:
        gateway = get_gateway()
        return gateway.open_case(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except TransactionRevertedError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@app.post("/cases/{case_id}/claim")
async def claim_case_on_chain(
    case_id: str,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Submit claimed forensic result root to ValidationQuorum."""
    try:
        gateway = get_gateway()
        return gateway.submit_claim(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (InvalidStateError, GatewayError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except TransactionRevertedError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@app.post("/cases/{case_id}/finalize")
async def finalize_case_on_chain(
    case_id: str,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Trigger quorum finalization."""
    try:
        gateway = get_gateway()
        return gateway.finalize(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (InvalidStateError, GatewayError, TransactionRevertedError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@app.post("/cases/{case_id}/record")
async def record_case_on_chain(
    case_id: str,
    request: Request,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Any:
    """Record verified host posture scores on PostureLedger."""
    is_html = "text/html" in request.headers.get("accept", "")
    try:
        case = get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case {case_id} not found")
        if not case.get("onchain_case_id"):
            raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet. Record action requires an on-chain case.")

        try:
            gateway = get_gateway()
        except Exception as exc:
            raise GatewayError(f"Blockchain gateway is unavailable: {exc}")
        result = gateway.record_posture(case_id)
        if is_html:
            encoded_msg = urllib.parse.quote("Posture successfully recorded on PostureLedger")
            return RedirectResponse(url=f"/cases/{case_id}?success={encoded_msg}", status_code=status.HTTP_303_SEE_OTHER)
        return result
    except CaseNotFoundError as exc:
        if is_html:
            encoded_err = urllib.parse.quote(str(exc))
            return RedirectResponse(url=f"/cases/{case_id}?error={encoded_err}", status_code=status.HTTP_303_SEE_OTHER)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (InvalidStateError, GatewayError, TransactionRevertedError) as exc:
        if is_html:
            encoded_err = urllib.parse.quote(str(exc))
            return RedirectResponse(url=f"/cases/{case_id}?error={encoded_err}", status_code=status.HTTP_303_SEE_OTHER)
        err_msg = str(exc).lower()
        if "connection" in err_msg or "refused" in err_msg or "deployment file" in err_msg or "unavailable" in err_msg:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Blockchain service unavailable: {exc}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in record_case_on_chain for case %s", case_id)
        if is_html:
            encoded_err = urllib.parse.quote("An unexpected error occurred while recording posture.")
            return RedirectResponse(url=f"/cases/{case_id}?error={encoded_err}", status_code=status.HTTP_303_SEE_OTHER)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.post("/cases/{case_id}/anchor")
async def anchor_case_on_chain(
    case_id: str,
    actor: str = Depends(require_analyst),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Anchor custody report hash in CaseRegistry."""
    try:
        gateway = get_gateway()
        return gateway.anchor_report(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (InvalidStateError, GatewayError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except TransactionRevertedError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        err_msg = str(exc).lower()
        if "connection" in err_msg or "refused" in err_msg or "deployment file" in err_msg or "unavailable" in err_msg:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Blockchain service unavailable: {exc}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


class ResolveRequest(BaseModel):
    action: str = "AttestMajority"
    root: Optional[str] = None


@app.post("/cases/{case_id}/resolve")
async def resolve_case_on_chain(
    case_id: str,
    payload: ResolveRequest = Body(default_factory=ResolveRequest),
    actor: str = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Dict[str, Any]:
    """Administrator resolution for Disputed or Expired cases."""
    try:
        gateway = get_gateway()
        return gateway.resolve(case_id, action=payload.action, root_hex=payload.root)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (InvalidStateError, GatewayError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except TransactionRevertedError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


class RegisterEngineRequest(BaseModel):
    caseId: Optional[str] = None
    imageDigest: Optional[str] = None
    rulesetHash: Optional[str] = None
    ensureValidators: bool = True


@app.post("/api/admin/register-engine")
async def admin_register_engine_api(
    payload: RegisterEngineRequest = Body(default_factory=RegisterEngineRequest),
    actor: str = Depends(require_admin),
) -> Dict[str, Any]:
    """Administrator endpoint to register approved engine release and ruleset hash on CaseRegistry."""
    try:
        gateway = get_gateway()
        return gateway.register_engine_for_case(
            case_id=payload.caseId,
            image_digest_hex=payload.imageDigest,
            ruleset_hash_hex=payload.rulesetHash,
            ensure_validators=payload.ensureValidators,
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@app.get("/cases/{case_id}/report")
async def get_case_report(
    case_id: str,
    request: Request,
    format: str = Query("json", description="Report format: json or html (pdf returns 501)"),
    actor: str = Depends(require_analyst_html),
):
    """Generate or retrieve deterministic posture report (JSON or HTML)."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")

    fmt = format.lower()
    if fmt not in ("json", "html", "pdf"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported format: {format}. Supported: json, html, pdf")

    from backend.reports.builder import build_case_report
    try:
        report_dict, canonical_bytes, report_hash, html_content = build_case_report(case_id, save=True)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to build report: {exc}")

    if fmt == "json":
        from engine.smscope.results.canonical import canonical_json
        return Response(content=canonical_json(report_dict), media_type="application/json")
    elif fmt == "html":
        return HTMLResponse(content=html_content)
    elif fmt == "pdf":
        from backend.reports.pdf import generate_pdf_report
        try:
            pdf_bytes = generate_pdf_report(report_dict, html_content, report_hash)
            # Save pdf report in case directory
            case_dir = get_case_dir(case_id)
            (case_dir / "report.pdf").write_bytes(pdf_bytes)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'inline; filename="report_{case_id[:12]}.pdf"'},
            )
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to generate PDF: {exc}")

