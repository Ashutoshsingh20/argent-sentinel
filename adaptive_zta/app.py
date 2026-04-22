import os
import json
import time
import sys
import logging
import hashlib
import hmac
from types import SimpleNamespace
from datetime import datetime
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager
from uuid import uuid4
from urllib.parse import quote

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator
import asyncio
import re
import numpy as np
import httpx

import database as db
from sqlalchemy.orm import Session
from sqlalchemy import func

import vanguard_brain as vb
from enforcement_engine import get_live_enforcement_engine
from policy_engine import get_policy_engine
from policy_overrides import get_override_store, OverrideType
from tenant_registry import get_tenant_registry, TenantConfig, TrustThresholds
from safety_controller import get_safety_controller
from fail_safe_manager import get_fail_safe_manager
from intelligence_layer import get_intelligence_layer
from alerting_engine import get_alert_manager
import config
from infrastructure import sentinel
import evaluator as ev
from collections import deque
import threading

from phase5.gateway import AdaptiveGateway
from phase5.identity import build_entity_id
from phase5.types import IncomingRequest
from cloud_actions import engine as cloud_action_engine
from cloud_features import registry as cloud_feature_registry
from decision_observability import DecisionRecordOut, observability
from runtime_logging import configure_logging
from runtime_metrics import inc_decision, inc_http, observe_sentinel_latency, render_metrics
from runtime_security import authorizer, rate_limiter
from runtime_settings import settings
from zero_trust_auth import (
    create_access_token,
    create_bound_session,
    decode_access_token,
    elevate_session_with_totp,
    enforce_zero_trust,
    revoke_session,
)

configure_logging()
logger = logging.getLogger(__name__)

# [PHASE 8 NUCLEAR UPGRADE] - High-Throughput Memory Ingestion
ingestion_queue = deque(maxlen=100000)
queue_lock = threading.Lock()
shutdown_event = threading.Event()
feature_cache_lock = threading.Lock()
feature_cache: Dict[str, tuple[int, np.ndarray, float]] = {}
FEATURE_CACHE_TTL_SECONDS = 5.0
MAX_PROCESSING_MS = 1000.0

# Phase 7 UI: bounded in-memory stream for latest decisions.
recent_events_lock = threading.Lock()
recent_events: deque[dict[str, Any]] = deque(maxlen=1000)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    db.init_db()
    # Phase A — initialize policy engine + live enforcement
    try:
        _policy_engine = get_policy_engine()
        _live_enforcement = get_live_enforcement_engine()
        _override_store = get_override_store()
        _fail_safe = get_fail_safe_manager()
        logger.info("Policy engine initialized", extra={"version": _policy_engine.version})
    except Exception as exc:
        logger.error("Policy engine init failed", extra={"error": str(exc)})
    # Phase B — initialize tenant registry
    try:
        _tenant_reg = get_tenant_registry()
        logger.info("Tenant registry initialized", extra={"count": len(_tenant_reg.list_all())})
    except Exception as exc:
        logger.error("Tenant registry init failed", extra={"error": str(exc)})
    # Phase D — initialize intelligence layer
    try:
        _intel = get_intelligence_layer()
        logger.info("Intelligence Layer initialized (D1-D4 active)")
    except Exception as exc:
        logger.error("Intelligence Layer init failed", extra={"error": str(exc)})
    # Phase E — initialize alerting engine
    try:
        _alert_mgr = get_alert_manager()
        _alert_mgr.start()
        logger.info("AlertManager started (Phase E)")
    except Exception as exc:
        logger.error("AlertManager init failed", extra={"error": str(exc)})
    if phase5_gateway is not None:
        try:
            phase5_gateway.sentinel.state_store.startup_health_check()
        except Exception as exc:
            logger.warning("State store health check failed", extra={"error": str(exc)})
    engine.start_shadow_learning()
    
    # Start periodic pruning in background
    import threading
    def auto_prune():
        while True:
            try:
                with db.engine.begin() as conn:
                    # Prune telemetry older than 5 minutes
                    conn.execute(db.text("DELETE FROM telemetry WHERE timestamp < :limit"), 
                                {"limit": time.time() - 300})
                    # Also prune old enforcement actions to keep UI snappy
                    conn.execute(db.text("DELETE FROM enforcements WHERE timestamp < DATETIME('now', '-10 minutes')"))
            except Exception as e:
                logger.warning("Auto-prune failed", extra={"error": str(e)})
            time.sleep(60)

    prune_thread = threading.Thread(target=auto_prune, daemon=True)
    prune_thread.start()
            
    # [PHASE 8] Start Autonomous Telemetry Worker
    drain_thread = threading.Thread(target=telemetry_drain_worker, daemon=True)
    drain_thread.start()
    
    yield
    # Shutdown logic
    shutdown_event.set()
    try:
        engine.stop_shadow_learning()
    except:
        pass
    try:
        engine.save_brain()
    except: pass

# Initialize FastAPI with lifespan
app = FastAPI(title="Zentra Command Center", version="8.0.0", lifespan=lifespan)

TARGET_API = settings.target_api
GATEWAY_ALLOW_THRESHOLD = settings.gateway_allow_threshold
GATEWAY_ISOLATE_THRESHOLD = settings.gateway_isolate_threshold
ENABLE_PHASE5_GATEWAY = settings.enable_phase5_gateway
TARGET_API_MAP = {
    "default": TARGET_API,
}

phase5_gateway: Optional[AdaptiveGateway] = AdaptiveGateway() if ENABLE_PHASE5_GATEWAY else None

# Static mode only: no autonomous simulator injection.

# Setup Templates and Static Files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
templates = Jinja2Templates(directory=TEMPLATES_DIR)


def _safe_template_response(request: Request, template_name: str) -> HTMLResponse:
    try:
        return templates.TemplateResponse(request, template_name, {})
    except Exception as exc:
        logger.exception("Template render failed", extra={"template": template_name, "error": str(exc)})
        return HTMLResponse(
            content=(
                "<html><head><title>Zentra</title></head><body>"
                "<h2>Zentra UI is recovering</h2>"
                "<p>The requested page could not be rendered.</p>"
                "<p><a href='/healthz'>Check health</a> | <a href='/register'>Request IAM access</a></p>"
                "</body></html>"
            ),
            status_code=200,
        )


@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return _safe_template_response(request, "landing.html")

@app.get("/login", response_class=HTMLResponse)
def login_route(request: Request):
    return _safe_template_response(request, "login.html")

@app.get("/register", response_class=HTMLResponse)
def register_route(request: Request):
    return _safe_template_response(request, "register.html")


@app.get("/request-iam")
def request_iam_alias():
    return RedirectResponse(url="/register", status_code=307)


@app.get("/request-an-iam")
def request_an_iam_alias():
    return RedirectResponse(url="/register", status_code=307)


@app.get("/signup")
def signup_alias():
    return RedirectResponse(url="/register", status_code=307)


@app.get("/sign-up")
def sign_up_alias():
    return RedirectResponse(url="/register", status_code=307)


@app.get("/ui/login")
def ui_login_alias():
    return RedirectResponse(url="/login", status_code=307)


@app.get("/ui/register")
def ui_register_alias():
    return RedirectResponse(url="/register", status_code=307)

@app.get("/ui")
def redirect_to_ui():
    return RedirectResponse(url="/ui/dashboard")

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Enable CORS for Web GUI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000", "https://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if settings.force_https:
    app.add_middleware(HTTPSRedirectMiddleware)


# ─ Phase B: X-Tenant-ID middleware ──────────────────────────────────────────
TENANT_HEADER = "X-Tenant-ID"
TENANT_EXEMPT_PATHS = {"/", "/healthz", "/metrics", "/docs", "/openapi.json",
                       "/dashboard/summary", "/dashboard/entities", "/model-info",
                       "/intelligence/status", "/intelligence/suggestions", "/safety/status",
                       "/soc/dashboard", "/soc/overview", "/soc/alerts", "/soc/timeline",
                       "/soc/policy/audit", "/soc/tenants/comparison", "/soc/decisions/distribution"}


@app.middleware("http")
async def tenant_isolation_middleware(request: Request, call_next):
    """Resolve tenant from X-Tenant-ID header; inject into request.state."""
    path = request.url.path
    tenant_id = request.headers.get(TENANT_HEADER, "default").strip() or "default"

    if path not in TENANT_EXEMPT_PATHS:
        registry = get_tenant_registry()
        if not registry.exists(tenant_id) and tenant_id != "default":
            return JSONResponse(
                status_code=400,
                content={"detail": f"Unknown tenant: {tenant_id}"},
            )

    request.state.tenant_id = tenant_id
    response = await call_next(request)
    response.headers["X-Tenant-ID"] = tenant_id
    return response
# ─────────────────────────────────────────────────────────────────────


@app.middleware("http")
async def security_and_metrics_middleware(request: Request, call_next):
    try:
        authorizer.validate(request)
    except HTTPException as exc:
        return db_fastapi_error_response(exc)

    retry_after = rate_limiter.allow(request)
    if retry_after is not None:
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded"},
            headers={"Retry-After": str(retry_after)},
        )

    response = await call_next(request)
    inc_http(request.method, request.url.path, response.status_code)
    return response


def db_fastapi_error_response(exc: HTTPException):
    headers = exc.headers if exc.headers is not None else None
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=headers)


VALID_PLATFORM_ROLES = {"Administrator", "Analyst", "ReadOnly"}


def _hash_passphrase(passphrase: str, salt: Optional[str] = None) -> str:
    return db.hash_passphrase(passphrase, salt)


def _verify_passphrase(passphrase: str, stored_hash: Optional[str]) -> bool:
    if not stored_hash:
        return False
    try:
        scheme, salt, expected = stored_hash.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    candidate = _hash_passphrase(passphrase, salt).split("$", 2)[2]
    return hmac.compare_digest(candidate, expected)


def _ensure_dev_admin(session: Session) -> db.PlatformUser:
    user = session.query(db.PlatformUser).filter(db.PlatformUser.email == "alex@argent.local").first()
    now = datetime.utcnow()
    if user is None:
        user = db.PlatformUser(
            id="dev-alex-001",
            email="alex@argent.local",
            full_name="Alex Mercer",
            role="Administrator",
            department="Threat Operations",
            role_updated_at=now,
            role_updated_by="system_seed",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    elif user.role != "Administrator":
        user.role = "Administrator"
        user.role_updated_at = now
        user.role_updated_by = "system_seed"
        session.commit()
        session.refresh(user)
    return user


def _current_platform_user(request: Request, session: Session) -> Optional[db.PlatformUser]:
    user_id = request.headers.get("X-Argent-User") or request.cookies.get("argent_user_id")
    if not user_id:
        if os.getenv("AUTH_ALLOW_INSECURE_DEV", "1") == "1":
            return _ensure_dev_admin(session)
        return None
    user_id = user_id.strip()
    user = (
        session.query(db.PlatformUser)
        .filter((db.PlatformUser.email == user_id) | (db.PlatformUser.id == user_id))
        .first()
    )
    if user is None and user_id == "alex@argent.local":
        return _ensure_dev_admin(session)
    return user


def require_platform_role(request: Request, *allowed_roles: str) -> db.PlatformUser:
    user = getattr(request.state, "platform_user", None)
    if user is None and os.getenv("AUTH_ALLOW_INSECURE_DEV", "1") == "1":
        # Keep local/dev UI usable even if DB-backed identity lookup fails.
        user = SimpleNamespace(
            id="dev-fallback-admin",
            email="alex@argent.local",
            role="Administrator",
        )
        request.state.platform_user = user
    if user is None:
        raise HTTPException(status_code=401, detail="platform identity unavailable")
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"{user.role} cannot access this control plane surface")
    return user


def require_admin(request: Request) -> db.PlatformUser:
    return require_platform_role(request, "Administrator")


def require_feedback_operator(request: Request) -> db.PlatformUser:
    return require_platform_role(request, "Administrator", "Analyst")


def require_platform_role_ui(request: Request, *allowed_roles: str) -> Optional[RedirectResponse]:
    """UI routes should redirect anonymous users to login instead of returning raw JSON 401."""
    user = getattr(request.state, "platform_user", None)
    if user is None:
        next_path = request.url.path
        if request.url.query:
            next_path = f"{next_path}?{request.url.query}"
        encoded_next = quote(next_path, safe="")
        return RedirectResponse(url=f"/login?next={encoded_next}", status_code=307)
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"{user.role} cannot access this control plane surface")
    return None


@app.middleware("http")
async def platform_user_middleware(request: Request, call_next):
    session = db.SessionLocal()
    try:
        request.state.platform_user = _current_platform_user(request, session)
    except Exception as exc:
        logger.warning("Platform user resolution failed", extra={"error": str(exc)})
        request.state.platform_user = None
    finally:
        session.close()
    return await call_next(request)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# Dependency
def get_db():
    session = db.SessionLocal()
    try:
        yield session
    finally:
        session.close()


def zero_trust_guard(request: Request, s: Session = Depends(get_db)) -> Dict[str, Any]:
    return enforce_zero_trust(request=request, session=s, evaluator=engine.evaluate_ui_request)


def _format_model_reason(reason: Optional[str]) -> dict:
    text = (reason or "").strip()
    pattern = (
        r"^TABNET_STATIC_(ATTACK|NORMAL)\s+"
        r"p=([0-9.]+)\s+thr=([0-9.]+)\s+margin=([0-9.]+)\s+"
        r"top=([a-z_]+):([0-9.]+),([a-z_]+):([0-9.]+)$"
    )
    m = re.match(pattern, text)
    if not m:
        return {
            "reason_raw": text,
            "reason_explain": text if text else "No reason available",
            "top_factors": [],
        }

    decision = m.group(1)
    p = float(m.group(2))
    thr = float(m.group(3))
    margin = float(m.group(4))
    f1 = m.group(5)
    w1 = float(m.group(6))
    f2 = m.group(7)
    w2 = float(m.group(8))

    comparator = ">" if decision == "ATTACK" else "<="
    explain = (
        f"{decision}: p={p:.3f} {comparator} thr={thr:.3f} "
        f"(margin={margin:.3f}); top factors {f1} ({w1:.3f}) and {f2} ({w2:.3f})"
    )

    return {
        "reason_raw": text,
        "reason_explain": explain,
        "top_factors": [
            {"name": f1, "weight": round(w1, 3)},
            {"name": f2, "weight": round(w2, 3)},
        ],
    }


def _clip01(value: float) -> float:
    return float(np.clip(value, 0.0, 1.0))


def _to_float(data: Dict[str, Any], key: str, default: float) -> float:
    raw = data.get(key, default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


def _to_int(data: Dict[str, Any], key: str, default: int) -> int:
    raw = data.get(key, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return int(default)


def build_features(data: Dict[str, Any]) -> np.ndarray:
    api_rate = max(0.0, _to_float(data, "api_rate", 120.0))
    payload_size = max(0.0, _to_float(data, "payload_size", 256.0))
    traversal_depth = max(0.0, float(_to_int(data, "traversal_depth", 2)))
    session_duration = max(0.0, _to_float(data, "session_duration", 180.0))
    failed_auth_count = max(0.0, float(_to_int(data, "failed_auth_count", 0)))
    geo_anomaly_flag = _clip01(float(_to_int(data, "geo_anomaly_flag", 0)))

    api_norm = _clip01(api_rate / 500.0)
    payload_norm = _clip01(payload_size / 5000.0)
    traversal_norm = _clip01(traversal_depth / 20.0)
    session_norm = _clip01(session_duration / 3600.0)
    auth_norm = _clip01(failed_auth_count / 10.0)

    behavior_risk = (
        0.35 * auth_norm
        + 0.25 * traversal_norm
        + 0.20 * api_norm
        + 0.10 * payload_norm
        + 0.10 * session_norm
    )
    default_behavior = _clip01(1.0 - behavior_risk)

    protocol = str(data.get("protocol_type", "HTTPS")).strip().upper()
    protocol_risk = {"HTTPS": 0.1, "HTTP": 0.35, "SSH": 0.45}.get(protocol, 0.30)
    context_risk = 0.50 * geo_anomaly_flag + 0.30 * protocol_risk + 0.20 * 0.20
    default_context = _clip01(1.0 - context_risk)

    default_history = _clip01(_to_float(data, "history", 0.75))
    default_anomaly = _clip01(0.40 * auth_norm + 0.25 * traversal_norm + 0.20 * geo_anomaly_flag + 0.15 * payload_norm)

    behavior = _clip01(_to_float(data, "behavior", default_behavior))
    context = _clip01(_to_float(data, "context", default_context))
    history = _clip01(_to_float(data, "history", default_history))
    anomaly = _clip01(_to_float(data, "anomaly", default_anomaly))

    api_x_payload = _clip01(api_norm * payload_norm)
    trav_x_auth = _clip01(traversal_norm * auth_norm)
    api_x_trav = _clip01(api_norm * traversal_norm)
    payload_x_auth = _clip01(payload_norm * auth_norm)
    log_payload = _clip01(np.log1p(payload_size) / np.log1p(5000.0))

    return np.array(
        [
            behavior,
            context,
            history,
            anomaly,
            api_norm,
            payload_norm,
            traversal_norm,
            session_norm,
            auth_norm,
            geo_anomaly_flag,
            api_x_payload,
            trav_x_auth,
            api_x_trav,
            payload_x_auth,
            log_payload,
        ],
        dtype=np.float32,
    )


def _feature_signature(data: Dict[str, Any]) -> int:
    # Signature intentionally focuses on fields that influence feature construction.
    payload = (
        str(data.get("entity_id", "")),
        round(_to_float(data, "api_rate", 120.0), 4),
        round(_to_float(data, "payload_size", 256.0), 4),
        _to_int(data, "traversal_depth", 2),
        round(_to_float(data, "session_duration", 180.0), 4),
        _to_int(data, "failed_auth_count", 0),
        _to_int(data, "geo_anomaly_flag", 0),
        str(data.get("protocol_type", "HTTPS")).upper(),
        round(_to_float(data, "behavior", -1.0), 4),
        round(_to_float(data, "context", -1.0), 4),
        round(_to_float(data, "history", -1.0), 4),
        round(_to_float(data, "anomaly", -1.0), 4),
    )
    return hash(payload)


def get_features(entity_id: str, data: Dict[str, Any]) -> np.ndarray:
    now = time.time()
    sig = _feature_signature(data)
    with feature_cache_lock:
        row = feature_cache.get(entity_id)
        if row is not None:
            cached_sig, cached_features, cached_ts = row
            if cached_sig == sig and (now - cached_ts) <= FEATURE_CACHE_TTL_SECONDS:
                return cached_features

    features = build_features(data)
    with feature_cache_lock:
        feature_cache[entity_id] = (sig, features, now)
    return features


async def batch_features(requests_batch: List[Dict[str, Any]]) -> List[np.ndarray]:
    return [get_features(str(item.get("entity_id", "")), item) for item in requests_batch]


def build_features_batch(records: List['TelemetryIn']) -> Dict[str, np.ndarray]:
    features_by_entity: Dict[str, np.ndarray] = {}
    for rec in records:
        payload = rec.model_dump()
        features_by_entity[rec.entity_id] = get_features(rec.entity_id, payload)
    return features_by_entity


def _build_gateway_penalty(data: Dict[str, Any], features: np.ndarray) -> float:
    protocol = str(data.get("protocol_type", "HTTPS")).strip().upper()
    protocol_penalty = {"HTTPS": 0.0, "HTTP": 6.0, "SSH": 8.0}.get(protocol, 4.0)

    anomaly_penalty = float(features[3]) * 25.0
    auth_penalty = _clip01(_to_int(data, "failed_auth_count", 0) / 10.0) * 15.0
    geo_penalty = _clip01(_to_int(data, "geo_anomaly_flag", 0)) * 10.0
    rate_penalty = _clip01(_to_float(data, "api_rate", 0.0) / 500.0) * 7.0
    depth_penalty = _clip01(_to_int(data, "traversal_depth", 0) / 20.0) * 5.0
    payload_penalty = _clip01(_to_float(data, "payload_size", 0.0) / 5000.0) * 5.0

    return float(
        protocol_penalty
        + anomaly_penalty
        + auth_penalty
        + geo_penalty
        + rate_penalty
        + depth_penalty
        + payload_penalty
    )


def _apply_gateway_decision_policy(auth: Dict[str, Any], data: Dict[str, Any], features: np.ndarray) -> Dict[str, Any]:
    base_trust = float(auth["trust"])
    penalty = _build_gateway_penalty(data, features)
    adjusted_trust = round(max(0.0, min(100.0, base_trust - penalty)), 2)

    # Keep decision boundaries authoritative from the model policy path.
    decision = str(auth.get("decision", "ALLOW"))

    auth["trust_raw"] = base_trust
    auth["policy_penalty"] = round(penalty, 2)
    auth["trust"] = adjusted_trust
    auth["decision"] = decision
    auth["reason"] = (
        f"{auth['reason']} | gateway_policy trust_raw={base_trust:.2f} "
        f"penalty={penalty:.2f} trust_adj={adjusted_trust:.2f}"
    )
    return auth


def _append_recent_event(
    entity_id: str,
    decision: str,
    prob: Optional[float],
    trust: Optional[float],
    reason: Optional[str],
) -> None:
    event = {
        "entity": entity_id,
        "decision": decision,
        "prob": prob,
        "trust": trust,
        "reason": reason,
        "time": time.time(),
    }
    with recent_events_lock:
        recent_events.append(event)


def _resolve_target_api(data: Dict[str, Any]) -> str:
    service_key = str(data.get("target_service", "default")).strip().lower() or "default"
    return TARGET_API_MAP.get(service_key, TARGET_API_MAP["default"])


def _request_id_from_request(request: Request) -> str:
    rid = (request.headers.get("x-request-id") or "").strip()
    return rid if rid else str(uuid4())


def _decision_feature_snapshot(data: Dict[str, Any]) -> Dict[str, Any]:
    keys = [
        "entity_id",
        "entity_type",
        "cloud_env",
        "api_rate",
        "payload_size",
        "traversal_depth",
        "session_duration",
        "failed_auth_count",
        "geo_anomaly_flag",
        "protocol_type",
        "timestamp",
    ]
    return {k: data.get(k) for k in keys if k in data}


def _normalize_cloud(cloud: str) -> str:
    cloud_norm = cloud.strip().upper()
    if cloud_norm in {"AZURE", "AWS", "GCP"}:
        return cloud_norm
    if cloud_norm == "AZ":
        return "AZURE"
    return "AWS"


def _build_phase5_request(data: Dict[str, Any]) -> IncomingRequest:
    raw_entity = str(data.get("entity_id", "")).strip()
    if not raw_entity:
        raise HTTPException(status_code=400, detail="entity_id is required")

    cloud = _normalize_cloud(str(data.get("cloud_env", "AWS")))
    service = str(data.get("target_service") or data.get("entity_type") or "gateway").strip().lower() or "gateway"

    if raw_entity.count(":") >= 2:
        entity_id = raw_entity
    else:
        entity_id = build_entity_id(raw_entity, cloud, service)

    return IncomingRequest(
        entity_id=entity_id,
        cloud=cloud,
        service=service,
        timestamp=float(data.get("timestamp", time.time())),
        anomaly_score=float(data.get("geo_anomaly_flag", 0.0)),
        payload_size=float(data.get("payload_size", 0.0)),
        endpoint_risk_score=min(1.0, float(data.get("failed_auth_count", 0.0)) / 10.0),
        http_method=str(data.get("http_method", "GET")).upper(),
        source_ip=str(data.get("source_ip", "0.0.0.0")),
        auth_failure=int(data.get("failed_auth_count", 0)) > 0,
    )


def _persist_gateway_event(
    entity_id: str,
    payload: Dict[str, Any],
    trust: float,
    decision: str,
    reason: str,
    confidence: float,
    components: Dict[str, Any],
) -> None:
    s = db.SessionLocal()
    try:
        entity = s.query(db.Entity).filter(db.Entity.id == entity_id).first()
        if not entity:
            entity = db.Entity(
                id=entity_id,
                entity_type=str(payload.get("entity_type", "unknown")),
                cloud_env=str(payload.get("cloud_env", "AWS")),
                current_trust_score=75.0,
                status="ALLOW",
            )
            s.add(entity)
            s.flush()

        telemetry = db.Telemetry(
            entity_id=entity_id,
            timestamp=_to_float(payload, "timestamp", time.time()),
            timestep=payload.get("timestep"),
            api_rate=_to_float(payload, "api_rate", 120.0),
            payload_size=_to_float(payload, "payload_size", 256.0),
            traversal_depth=_to_int(payload, "traversal_depth", 2),
            session_duration=_to_float(payload, "session_duration", 180.0),
            failed_auth_count=_to_int(payload, "failed_auth_count", 0),
            geo_anomaly_flag=_to_int(payload, "geo_anomaly_flag", 0),
            protocol_type=str(payload.get("protocol_type", "HTTPS")).upper(),
            is_attack=_to_int(payload, "is_attack", 0),
        )
        s.add(telemetry)

        entity.current_trust_score = trust
        entity.status = decision
        entity.last_updated = datetime.utcnow()

        enforcement = db.EnforcementAction(
            entity_id=entity_id,
            decision=decision,
            reason=reason,
            trust_score_at_action=trust,
            confidence_score=confidence,
            b_score=components.get("b_score"),
            c_score=components.get("c_score"),
            h_score=components.get("h_score"),
            a_score=components.get("a_score"),
            a_prime_score=components.get("a_prime_score"),
            api_rate=_to_float(payload, "api_rate", 120.0),
            payload_size=_to_float(payload, "payload_size", 256.0),
        )
        s.add(enforcement)
        s.commit()

        sentinel.deploy_block(entity_id, decision, reason)
        db.hot_state.set(f"trust:{entity_id}", trust)
        db.hot_state.set(f"status:{entity_id}", decision)
    except Exception as exc:
        s.rollback()
        logger.warning("Gateway persistence failed", extra={"entity_id": entity_id, "error": str(exc)})
    finally:
        s.close()


def authorize_logic(
    data: Dict[str, Any],
    s: Session,
    background_tasks: Optional[BackgroundTasks] = None,
    source: str = "authorize",
    request_id: Optional[str] = None,
    tenant_id: str = "default",
    simulation: bool = False,
) -> Dict[str, Any]:
    entity_id = str(data.get("entity_id", "")).strip()
    if not entity_id:
        raise HTTPException(status_code=400, detail="entity_id is required")

    t0 = time.perf_counter()
    features = get_features(entity_id, data)

    # ── Phase D: Context Intelligence enrichment ───────────────────────────
    ctx_score = None
    try:
        intel = get_intelligence_layer()
        ctx_score = intel.enrich_context(entity_id, data)
        # Boost geo_anomaly_flag if context flags rate spike
        if "RATE_SPIKE" in " ".join(ctx_score.flags) and not data.get("geo_anomaly_flag"):
            data = dict(data)   # don't mutate caller's dict
            if ctx_score.behavioral_velocity > 0.7:
                data["geo_anomaly_flag"] = 1  # elevate signal for policy evaluation
    except Exception as ctx_exc:
        logger.debug("Context enrichment failed", extra={"error": str(ctx_exc)})
    # ───────────────────────────────────────────────────────────────────────────

    trust, model_decision, reason, confidence, components = engine.calculate_trust(
        entity_id,
        s,
        features=features,
    )

    processing_ms = (time.perf_counter() - t0) * 1000.0
    if processing_ms > MAX_PROCESSING_MS:
        fallback_decision = str(db.hot_state.get(f"status:{entity_id}", model_decision))
        fallback_trust = float(db.hot_state.get(f"trust:{entity_id}", trust) or trust)
        model_decision = fallback_decision
        trust = fallback_trust
        reason = f"TIMEOUT_FALLBACK processing_ms={processing_ms:.2f} prev_state_decision={fallback_decision}"
        confidence = min(confidence, 60.0)
        logger.warning(
            "Timeout fallback applied",
            extra={"entity_id": entity_id, "processing_ms": processing_ms, "fallback_decision": fallback_decision},
        )

    # ── Phase A: Policy Engine evaluation ────────────────────────────────
    try:
        enforcement = get_live_enforcement_engine().decide(
            entity_id=entity_id,
            trust_score=trust,
            telemetry=data,
            tenant_id=tenant_id,
            source=source,
            simulation=simulation,
        )
        decision = enforcement.action
        policy_meta = enforcement.to_dict()
    except Exception as policy_exc:
        logger.warning("Policy engine error — using model decision",
                       extra={"entity_id": entity_id, "error": str(policy_exc)})
        get_fail_safe_manager().record_model_error()
        decision = model_decision
        policy_meta = {
            "action": model_decision,
            "rule_id": "POLICY_ERROR_FALLBACK",
            "policy_version": "unknown",
            "reason": reason,
            "confidence": confidence / 100.0,
            "matched_rules": [],
        }
    # ─────────────────────────────────────────────────────────────────────

    # ── Fail-Safe Layer (Policy -> Fail-Safe -> Enforcement) ─────────────
    try:
        fail_safe = get_fail_safe_manager().evaluate(
            entity_id=entity_id,
            proposed_action=decision,
            confidence=float(policy_meta.get("confidence", 0.5) or 0.5),
            matched_rules=list(policy_meta.get("matched_rules", [])),
            simulation=simulation,
        )
        decision = fail_safe.final_action
        policy_meta["system_mode"] = fail_safe.system_mode
        policy_meta["fail_safe_applied"] = fail_safe.fail_safe_applied
        policy_meta["fail_safe_reason"] = fail_safe.fail_safe_reason
        policy_meta["fallback_action"] = fail_safe.fallback_action
        if fail_safe.fail_safe_applied:
            existing_reason = policy_meta.get("reason", reason)
            policy_meta["reason"] = f"{existing_reason} | FAIL_SAFE: {fail_safe.fail_safe_reason}"
            policy_meta["matched_rules"] = policy_meta.get("matched_rules", []) + ["FAIL_SAFE_OVERRIDE"]
    except Exception as fail_safe_exc:
        logger.warning("Fail-safe manager error — using policy decision",
                       extra={"entity_id": entity_id, "error": str(fail_safe_exc)})
    # ─────────────────────────────────────────────────────────────────────

    # ── Phase C: Safety Controller ────────────────────────────────────────
    try:
        safety = get_safety_controller()
        safe_action, was_overridden, safety_reason = safety.enforce(
            tenant_id=tenant_id,
            proposed_action=decision,
            simulation=simulation,
        )
        if was_overridden:
            logger.warning(
                "Safety controller overrode decision",
                extra={
                    "entity_id": entity_id,
                    "original": decision,
                    "final": safe_action,
                    "reason": safety_reason,
                },
            )
            policy_meta["reason"] = f"{policy_meta.get('reason', reason)} | SAFETY: {safety_reason}"
            policy_meta["matched_rules"] = policy_meta.get("matched_rules", []) + ["SAFETY_OVERRIDE"]
        decision = safe_action
    except Exception as safety_exc:
        logger.warning("Safety controller error — using policy decision",
                       extra={"entity_id": entity_id, "error": str(safety_exc)})
    # ─────────────────────────────────────────────────────────────────────

    logger.info(
        "Decision issued",
        extra={
            "entity_id": entity_id,
            "decision": decision,
            "rule_id": policy_meta.get("rule_id"),
            "policy_version": policy_meta.get("policy_version"),
            "trust": trust,
            "confidence": confidence,
            "probability": components.get("prob_score"),
        },
    )
    inc_decision(decision)
    _append_recent_event(
        entity_id=entity_id,
        decision=decision,
        prob=components.get("prob_score"),
        trust=trust,
        reason=policy_meta.get("reason", reason),
    )

    if background_tasks is not None:
        background_tasks.add_task(
            _persist_gateway_event,
            entity_id,
            data,
            trust,
            decision,
            policy_meta.get("reason", reason),
            confidence,
            components,
        )

    auth = {
        "entity_id": entity_id,
        "decision": decision,
        "trust": trust,
        "reason": policy_meta.get("reason", reason),
        "confidence": confidence,
        "components": components,
        # Phase A policy fields
        "rule_id": policy_meta.get("rule_id"),
        "policy_version": policy_meta.get("policy_version"),
        "policy_confidence": policy_meta.get("confidence"),
        "matched_rules": policy_meta.get("matched_rules", []),
        "override_id": policy_meta.get("override_id"),
        "system_mode": policy_meta.get("system_mode", "NORMAL"),
        "fail_safe_applied": bool(policy_meta.get("fail_safe_applied", False)),
        "fail_safe_reason": policy_meta.get("fail_safe_reason", ""),
        "fallback_action": policy_meta.get("fallback_action"),
        # Phase D context
        "context": (ctx_score.to_dict() if ctx_score else {}),
    }
    resolved = _apply_gateway_decision_policy(auth, data, features)


    record = observability.build_record(
        request_id=request_id,
        source=source,
        entity_id=entity_id,
        input_features=_decision_feature_snapshot(data),
        risk_score=float(components.get("prob_score")) if components.get("prob_score") is not None else None,
        trust_score=float(resolved.get("trust")) if resolved.get("trust") is not None else None,
        policy_decision=str(model_decision),
        final_action=str(resolved.get("decision", decision)),
        latency_ms=float(processing_ms),
        status="success",
    )
    observability.emit(record, background_tasks=background_tasks)

    return resolved


class GatewayFeedbackIn(BaseModel):
    entity_id: str
    true_label: int

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:@\-]{1,128}", v):
            raise ValueError("entity_id contains invalid characters")
        return v

    @field_validator("true_label")
    @classmethod
    def validate_true_label(cls, v: int) -> int:
        if int(v) not in (0, 1):
            raise ValueError("true_label must be 0 or 1")
        return int(v)


# ─────────────────────────────────────────────────────────────────────────────
# Phase A — Policy Management Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class OverrideCreateIn(BaseModel):
    entity_id: str
    override_type: str         # FORCE_ISOLATE | FORCE_ALLOW | FORCE_RATE_LIMIT | SKIP_RULES | CUSTOM_THRESHOLD
    duration_seconds: float = 300.0
    operator_id: str = "api"
    reason: str = ""
    skip_rule_ids: List[str] = []
    threshold_overrides: Dict[str, float] = {}
    tenant_id: str = "default"


@app.get("/policy/status")
def policy_status():
    """Current policy engine version, rule count, hot-reload status."""
    pe = get_policy_engine()
    return {
        "version": pe.version,
        "rules": len(pe.get_rules_summary()),
        "hot_reload": True,
    }


@app.get("/policy/rules")
def policy_rules(tenant_id: str = "default"):
    """List all active rules with match counts."""
    pe = get_policy_engine()
    return {
        "policy_version": pe.version,
        "tenant_id": tenant_id,
        "rules": pe.get_rules_summary(tenant_id=tenant_id if tenant_id != "default" else None),
    }


from pydantic import BaseModel
class PolicyConditionIn(BaseModel):
    field: str
    op: str
    value: str


class KillSwitchToggleIn(BaseModel):
    enable: bool = Field(..., description="Enable or disable kill switch")

class PolicyRuleIn(BaseModel):
    id: str
    priority: int
    action: str
    reason: str
    conditions: list[PolicyConditionIn]

@app.post("/policy/rules/add")
def policy_add_rule(request: Request, payload: PolicyRuleIn, tenant_id: str = "default"):
    require_admin(request)
    from pathlib import Path
    import yaml
    import json
    
    # Simple append logic to the rules file
    pe = get_policy_engine()
    rules_path = pe._rules_path if tenant_id == "default" else Path("policies") / tenant_id / "rules.yaml"
    
    try:
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
    except:
        data = {"version": "1.0.0", "rules": []}
        
    # Convert typed payload to dict manually to handle pydantic v1 vs v2
    new_rule = {
        "id": payload.id,
        "priority": payload.priority,
        "conflict_weight": 0.5,
        "action": payload.action,
        "reason": payload.reason,
        "conditions": [{"field": c.field, "op": c.op, "value": c.value} for c in payload.conditions]
    }
    
    data.setdefault("rules", []).append(new_rule)
    
    with open(rules_path, "w") as f:
        yaml.dump(data, f, sort_keys=False)
        
    pe.reload()
    return {"status": "success", "new_version": pe.version}

@app.post("/policy/rules/reload")
def policy_reload(tenant_id: Optional[str] = None):
    """Hot-reload policy rules from YAML file. Returns new version."""
    pe = get_policy_engine()
    if tenant_id:
        new_version = pe.reload_tenant(tenant_id)
        return {"tenant_id": tenant_id, "version": new_version, "reloaded": new_version is not None}
    new_version = pe.reload()
    return {"version": new_version, "reloaded": True}


@app.get("/policy/audit")
def policy_audit(
    entity_id: Optional[str] = None,
    tenant_id: str = "default",
    since: Optional[float] = None,
    limit: int = 100,
    s: Session = Depends(get_db),
):
    """Query policy audit log. Filter by entity, tenant, and/or start timestamp."""
    from sqlalchemy import text as sqla_text
    limit = max(1, min(int(limit), 500))
    since = float(since) if since else (time.time() - 3600.0)
    query = s.query(db.PolicyAuditLog).filter(
        db.PolicyAuditLog.tenant_id == tenant_id,
        db.PolicyAuditLog.timestamp >= since,
    )
    if entity_id:
        query = query.filter(db.PolicyAuditLog.entity_id == entity_id)
    rows = query.order_by(db.PolicyAuditLog.timestamp.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "audit": [
            {
                "id": r.id,
                "entity_id": r.entity_id,
                "tenant_id": r.tenant_id,
                "timestamp": r.timestamp,
                "rule_id": r.rule_id,
                "policy_version": r.policy_version,
                "action": r.action,
                "reason": r.reason,
                "confidence": r.confidence,
                "override_id": r.override_id,
                "override_type": r.override_type,
                "trust_score": r.trust_score,
                "source": r.source,
                "matched_rules": r.matched_rules,
            }
            for r in rows
        ],
    }


@app.post("/policy/overrides")
def create_override(body: OverrideCreateIn):
    """Create a time-bounded policy override for an entity."""
    valid_types = {"FORCE_ISOLATE", "FORCE_ALLOW", "FORCE_RATE_LIMIT", "SKIP_RULES", "CUSTOM_THRESHOLD"}
    if body.override_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"override_type must be one of {valid_types}")
    if body.duration_seconds <= 0 or body.duration_seconds > 86400:
        raise HTTPException(status_code=400, detail="duration_seconds must be in (0, 86400]")

    store = get_override_store()
    ov = store.create(
        tenant_id=body.tenant_id,
        entity_id=body.entity_id,
        override_type=body.override_type,  # type: ignore[arg-type]
        duration_seconds=body.duration_seconds,
        operator_id=body.operator_id,
        reason=body.reason,
        skip_rule_ids=body.skip_rule_ids,
        threshold_overrides=body.threshold_overrides,
    )
    return ov.to_dict()


@app.get("/policy/overrides")
def list_overrides(tenant_id: str = "default"):
    """List all active overrides for a tenant."""
    store = get_override_store()
    return {"overrides": store.list_all(tenant_id=tenant_id)}


@app.delete("/policy/overrides/{override_id}")
def cancel_override(override_id: str, tenant_id: str = "default"):
    """Cancel an active override by ID."""
    store = get_override_store()
    removed = store.cancel(override_id, tenant_id=tenant_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Override not found or already expired")
    return {"cancelled": True, "override_id": override_id}


# ─────────────────────────────────────────────────────────────────────────────

@app.get("/dashboard/summary")

def get_summary(s: Session = Depends(get_db)):
    total_entities = s.query(db.Entity).count()
    allow_count = s.query(db.Entity).filter(db.Entity.status == "ALLOW").count()
    rate_limit_count = s.query(db.Entity).filter(db.Entity.status == "RATE_LIMIT").count()
    isolate_count = s.query(db.Entity).filter(db.Entity.status == "ISOLATE").count()
    
    # Infrastructure Integration
    infra = sentinel.get_status()
    
    # Combined Unsafe Count as requested
    unsafe_count = rate_limit_count + isolate_count
    
    # Ensure totals match Managed Entities exactly (Account for pending/unknown)
    pending_count = total_entities - (allow_count + unsafe_count)
    
    avg_trust = s.query(func.avg(db.Entity.current_trust_score)).scalar() or 0.0
    
    # 2. Get Threat Intelligence (Excluding 'ALLOW' decisions)
    threats = s.query(db.EnforcementAction).filter(db.EnforcementAction.decision != 'ALLOW').order_by(db.EnforcementAction.timestamp.desc()).limit(15).all()
    threats_out = []
    for t in threats:
        reason_view = _format_model_reason(t.reason)
        threats_out.append(
            {
                "id": t.id,
                "entity_id": t.entity_id,
                "decision": t.decision,
                "reason": reason_view["reason_raw"],
                "reason_explain": reason_view["reason_explain"],
                "top_factors": reason_view["top_factors"],
                "time": t.timestamp.isoformat() if t.timestamp else None,
                "confidence": t.confidence_score if t.confidence_score else 85.0,
                "is_correct": bool(t.is_correct) if t.is_correct is not None else True,
            }
        )

    # [SINGLE SOURCE OF TRUTH]
    # Metrics are now sourced exclusively from the latest evaluation cycle
    brain_metrics = engine.last_cycle_metrics
    shadow_metrics = engine.get_shadow_status()
    fail_safe_status = get_fail_safe_manager().status()
    fail_safe_metrics = get_fail_safe_manager().safety_metrics()
    return {
        "total_entities": total_entities,
        "allow_count": allow_count,
        "rate_limit_count": rate_limit_count,
        "isolate_count": isolate_count,
        "unsafe_count": unsafe_count,
        "pending_count": max(0, pending_count),
        "avg_trust": round(avg_trust, 2),
        "latest_threats": threats_out,
        "brain_stats": {
            "cycles": brain_metrics.get("cycle", 0),
            "loss": float(brain_metrics.get("loss", 0.0)),
            "coverage": float(brain_metrics.get("coverage", 0.0)),
            "accuracy": float(brain_metrics.get("accuracy", 0.0)),
            "f1": float(brain_metrics.get("f1", 0.0)),
            "precision": float(brain_metrics.get("precision", 0.0)),
            "recall": float(brain_metrics.get("recall", 0.0)),
            "adversarial_gain": float(brain_metrics.get("gain", 0.0)),
            "tp": int(brain_metrics.get("tp", 0)),
            "fp": int(brain_metrics.get("fp", 0)),
            "fn": int(brain_metrics.get("fn", 0)),
            "tn": int(brain_metrics.get("tn", 0)),
            "status": brain_metrics.get("status", "STATIC_MODEL_ACTIVE")
        },
        "shadow_stats": shadow_metrics,
        "infrastructure": infra,
        "system_mode": fail_safe_status.get("system_mode", "NORMAL"),
        "fail_safe_alerts": int(fail_safe_metrics.get("fallback_count", 0)),
    }


@app.get("/dashboard/entities")
def get_entities(status: Optional[str] = None, search: Optional[str] = None, s: Session = Depends(get_db)):
    query = s.query(db.Entity)
    if search:
        query = query.filter(db.Entity.id.like(f"%{search}%"))
    if status and status != 'ALL':
        if status == 'UNSAFE':
            query = query.filter(db.Entity.status.in_(['RATE_LIMIT', 'ISOLATE']))
        else:
            query = query.filter(db.Entity.status == status)
    entities = query.order_by(db.Entity.last_updated.desc()).limit(50).all()
    # For each entity, get latest confidence from enforcement action
    out = []
    for e in entities:
        last_action = s.query(db.EnforcementAction).filter(db.EnforcementAction.entity_id == e.id).order_by(db.EnforcementAction.timestamp.desc()).first()
        out.append({
            "id": e.id,
            "cloud_env": e.cloud_env,
            "status": e.status,
            "trust": round(e.current_trust_score, 2),
            "confidence": last_action.confidence_score if last_action else 90.0,
            "is_correct": bool(last_action.is_correct) if last_action and last_action.is_correct is not None else True
        })
    return out


@app.get("/ui", response_class=HTMLResponse)
def ui_index(request: Request):
    redirect = require_platform_role_ui(request, "Administrator", "Analyst", "ReadOnly")
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "dashboard.html", {"active_page": "dashboard"})


@app.get("/ui/dashboard", response_class=HTMLResponse)
def ui_dashboard(request: Request):
    redirect = require_platform_role_ui(request, "Administrator", "Analyst", "ReadOnly")
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "dashboard.html", {"active_page": "dashboard"})




@app.get("/ui/rules", response_class=HTMLResponse)
def ui_rules(request: Request):
    redirect = require_platform_role_ui(request, "Administrator", "Analyst")
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "policy_rules.html", {"active_page": "rules"})


@app.get("/ui/shadow", response_class=HTMLResponse)
def ui_shadow(request: Request):
    redirect = require_platform_role_ui(request, "Administrator")
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "shadow_model.html", {"active_page": "shadow"})

@app.get("/ui/developer", response_class=HTMLResponse)
def ui_developer(request: Request):
    redirect = require_platform_role_ui(request, "Administrator")
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "developer_console.html", {"active_page": "developer"})


@app.get("/ui/iam", response_class=HTMLResponse)
def ui_iam(request: Request, s: Session = Depends(get_db)):
    redirect = require_platform_role_ui(request, "Administrator")
    if redirect is not None:
        return redirect
    users = s.query(db.PlatformUser).order_by(db.PlatformUser.email.asc()).all()
    promotions = (
        s.query(db.ShadowPromotionEvent)
        .order_by(db.ShadowPromotionEvent.promoted_at.desc())
        .limit(10)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "iam_management.html",
        {"active_page": "iam", "users": users, "promotions": promotions, "roles": sorted(VALID_PLATFORM_ROLES)},
    )


class IAMRoleUpdateIn(BaseModel):
    user_id: str
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        role = value.strip()
        if role not in VALID_PLATFORM_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_PLATFORM_ROLES)}")
        return role


@app.post("/api/iam/update_role")
def iam_update_role(request: Request, payload: IAMRoleUpdateIn, s: Session = Depends(get_db)):
    actor = require_admin(request)
    target = (
        s.query(db.PlatformUser)
        .filter((db.PlatformUser.id == payload.user_id) | (db.PlatformUser.email == payload.user_id))
        .first()
    )
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    target.role = payload.role
    target.role_updated_at = datetime.utcnow()
    target.role_updated_by = actor.email or actor.id
    s.commit()
    return {
        "status": "success",
        "user_id": target.id,
        "email": target.email,
        "role": target.role,
        "role_updated_at": target.role_updated_at.isoformat() if target.role_updated_at else None,
        "role_updated_by": target.role_updated_by,
    }

@app.get("/ui/status")
def ui_status(_: Dict[str, Any] = Depends(zero_trust_guard), s: Session = Depends(get_db)):
    active_entities = s.query(db.Entity).count()
    with recent_events_lock:
        latest = recent_events[-1] if recent_events else None
    return {
        "active_entities": int(active_entities),
        "mode": "RUNNING",
        "event_buffer_size": len(recent_events),
        "latest_event": latest,
        "auth": {
            "jwt_enabled": bool(settings.jwt_enabled),
            "jwt_algorithm": settings.jwt_algorithm,
            "jwks_enabled": bool(settings.jwt_jwks_url),
            "https_required": bool(settings.jwt_require_https_for_auth),
        },
    }


@app.get("/ui/events")
def ui_events(limit: int = 50, _: Dict[str, Any] = Depends(zero_trust_guard)):
    lim = max(1, min(int(limit), 200))
    with recent_events_lock:
        return list(recent_events)[-lim:]


@app.get("/decisions/recent", response_model=List[DecisionRecordOut])
def decisions_recent(
    limit: int = 50,
    final_action: Optional[str] = None,
    status: Optional[str] = None,
    _: Dict[str, Any] = Depends(zero_trust_guard),
):
    return observability.recent_from_db(limit=limit, final_action=final_action, status=status)


@app.get("/ui/decisions/recent", response_model=List[DecisionRecordOut])
def ui_decisions_recent(
    limit: int = 50,
    final_action: Optional[str] = None,
    status: Optional[str] = None,
    _: Dict[str, Any] = Depends(zero_trust_guard),
):
    return observability.recent_from_db(limit=limit, final_action=final_action, status=status)


@app.get("/ui/entity/{entity_id}")
def ui_entity(entity_id: str, _: Dict[str, Any] = Depends(zero_trust_guard), s: Session = Depends(get_db)):
    trust = db.hot_state.get(f"trust:{entity_id}")
    status = db.hot_state.get(f"status:{entity_id}")

    entity = s.query(db.Entity).filter(db.Entity.id == entity_id).first()
    if entity is None and (trust is None or status is None):
        raise HTTPException(status_code=404, detail="Entity not found")

    recent_history = (
        s.query(db.EnforcementAction)
        .filter(db.EnforcementAction.entity_id == entity_id)
        .order_by(db.EnforcementAction.timestamp.desc())
        .limit(20)
        .all()
    )

    history = [
        {
            "time": row.timestamp.isoformat() if row.timestamp else None,
            "decision": row.decision,
            "trust": row.trust_score_at_action,
            "confidence": row.confidence_score,
            "reason": row.reason,
        }
        for row in recent_history
    ]

    return {
        "entity": entity_id,
        "trust": float(trust) if trust is not None else float(entity.current_trust_score),
        "state": str(status) if status is not None else str(entity.status),
        "history": history,
    }


@app.get("/ui/cloud/features")
def ui_cloud_features(force_refresh: int = 0, _: Dict[str, Any] = Depends(zero_trust_guard)):
    force = bool(int(force_refresh))
    return cloud_feature_registry.get(force=force)


@app.get("/ui/cloud/providers")
def ui_cloud_providers(force_refresh: int = 0, _: Dict[str, Any] = Depends(zero_trust_guard)):
    payload = cloud_feature_registry.get(force=bool(int(force_refresh)))
    providers = payload.get("providers", {})
    return {
        "updated_at": payload.get("updated_at"),
        "providers": [
            {"name": name, "count": int(data.get("count", 0))}
            for name, data in providers.items()
        ],
    }


class CloudActionInvokeIn(BaseModel):
    provider: str
    action: str = "invoke"
    decision: Optional[Dict[str, Any]] = None
    intent: Optional[Dict[str, Any]] = None
    intent_name: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    risk_level: Optional[str] = None
    reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    service: Optional[str] = None
    operation: Optional[str] = None
    region: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)
    method: Optional[str] = None
    path: Optional[str] = None
    url: Optional[str] = None
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    api_version: Optional[str] = None

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        provider = v.strip().lower()
        if provider not in {"aws", "azure", "gcp"}:
            raise ValueError("provider must be one of aws, azure, gcp")
        return provider


@app.get("/cloud/actions/catalog")
def cloud_actions_catalog(force_refresh: int = 0, _: Dict[str, Any] = Depends(zero_trust_guard)):
    force = bool(int(force_refresh))
    return cloud_action_engine.catalog(force_refresh=force)


@app.post("/cloud/invoke")
@app.post("/cloud/actions/invoke")
def cloud_actions_invoke(
    req: CloudActionInvokeIn,
    request: Request,
    background_tasks: BackgroundTasks,
    _: Dict[str, Any] = Depends(zero_trust_guard),
):
    request_id = _request_id_from_request(request)
    t0 = time.perf_counter()
    result = cloud_action_engine.invoke(provider=req.provider, request=req.model_dump())

    record_status = "success" if result.get("ok", False) else "error"
    entity_id = str(req.target_id or "").strip() or None
    execution_status = str(result.get("execution_status", "failed"))

    record = observability.build_record(
        request_id=request_id,
        source="cloud_actions.invoke",
        entity_id=entity_id,
        input_features={"provider": req.provider, "action": req.action},
        policy_decision=str(req.action or "invoke"),
        final_action="EXECUTED" if record_status == "success" else "FAILED",
        latency_ms=(time.perf_counter() - t0) * 1000.0,
        status=record_status,
        error_message=None if record_status == "success" else str(result.get("error", "cloud action failed")),
        extra={
            "intent": result.get("intent"),
            "compiled_actions": result.get("compiled_actions", []),
            "execution_status": execution_status,
            "operation_results": result.get("operation_results", []),
        },
    )
    observability.emit(record, background_tasks=background_tasks)

    if not result.get("ok", False):
        # Keep structured details for UI while returning a meaningful status code.
        message = str(result.get("error", "cloud action failed"))
        status_code = 403 if "blocked" in message or "disabled" in message else 400
        if execution_status == "degraded":
            status_code = 207
        raise HTTPException(status_code=status_code, detail=result)
    return result


class AuthSessionStartIn(BaseModel):
    user_id: str

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        val = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@\-]{1,128}", val):
            raise ValueError("invalid user_id")
        return val


class AuthStepUpIn(BaseModel):
    otp_code: str

    @field_validator("otp_code")
    @classmethod
    def validate_otp(cls, v: str) -> str:
        code = v.strip()
        if not re.fullmatch(r"\d{6}", code):
            raise ValueError("otp_code must be 6 digits")
        return code


class IAMLoginIn(BaseModel):
    email: str
    passphrase: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("valid email is required")
        return email


class IAMRegisterIn(IAMLoginIn):
    full_name: str
    department: str = "SOC Analyst"

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        name = value.strip()
        if len(name) < 2 or len(name) > 80:
            raise ValueError("full_name must be 2-80 characters")
        return name


class IAMProvisionIn(IAMRegisterIn):
    role: str
    org_id: str = "default"
    org_name: str = ""
    allowed_clouds: List[str] = ["AWS"]

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        role = value.strip()
        if role not in VALID_PLATFORM_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_PLATFORM_ROLES)}")
        return role

    @field_validator("org_id")
    @classmethod
    def validate_org_id(cls, v: str) -> str:
        val = v.strip().lower()
        if not re.fullmatch(r"[a-z0-9\-]{2,64}", val):
            raise ValueError("org_id must be 2-64 lowercase alphanumeric+hyphen characters")
        return val


@app.post("/api/iam/provision")
def iam_provision(request: Request, payload: IAMProvisionIn, s: Session = Depends(get_db)):
    actor = require_admin(request)
    existing = s.query(db.PlatformUser).filter(db.PlatformUser.email == payload.email).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="User identity already exists")

    # Ensure Organization (Tenant) exists
    reg = get_tenant_registry()
    if not reg.exists(payload.org_id):
        try:
            reg.create(TenantConfig(
                tenant_id=payload.org_id,
                display_name=payload.org_name or payload.org_id.upper(),
                thresholds=TrustThresholds(allow=65.0, rate_limit=48.0, isolate=48.0),
                rate_limit_rpm=12000,
                allowed_cloud_envs=payload.allowed_clouds,
                policy_file="default",
                shadow_learning_enabled=True,
                max_entities=50000,
                created_at=time.time(),
            ))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to provision organization: {str(exc)}")

    now = datetime.utcnow()
    user = db.PlatformUser(
        id=f"user-{uuid4().hex}",
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        department=payload.department.strip()[:80] or "SOC Analyst",
        created_at=now,
        role_updated_at=now,
        role_updated_by=actor.email or actor.id,
        password_hash=_hash_passphrase(payload.passphrase),
        last_login_at=None,
        tenant_id=payload.org_id,
    )
    s.add(user)
    s.commit()
    return {
        "status": "success",
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
    }


@app.post("/api/iam/login")
def iam_login(payload: IAMLoginIn, s: Session = Depends(get_db)):
    user = s.query(db.PlatformUser).filter(db.PlatformUser.email == payload.email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Unknown IAM user")

    if not user.password_hash:
        user.password_hash = _hash_passphrase(payload.passphrase)
    elif not _verify_passphrase(payload.passphrase, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid passphrase")

    user.last_login_at = datetime.utcnow()
    s.commit()
    return {
        "status": "success",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "department": user.department,
    }


@app.post("/api/iam/register")
def iam_register(payload: IAMRegisterIn, s: Session = Depends(get_db)):
    existing = s.query(db.PlatformUser).filter(db.PlatformUser.email == payload.email).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="IAM user already exists")

    now = datetime.utcnow()
    user = db.PlatformUser(
        id=f"user-{uuid4().hex}",
        email=payload.email,
        full_name=payload.full_name,
        role="Administrator",
        department=payload.department.strip()[:80] or "SOC Analyst",
        created_at=now,
        role_updated_at=now,
        role_updated_by="self_register",
        password_hash=_hash_passphrase(payload.passphrase),
        last_login_at=now,
    )
    s.add(user)
    s.commit()
    return {
        "status": "success",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "department": user.department,
    }


@app.post("/api/register")
def api_register_alias(payload: IAMRegisterIn, s: Session = Depends(get_db)):
    return iam_register(payload, s)


@app.post("/api/login")
def api_login_alias(payload: IAMLoginIn, s: Session = Depends(get_db)):
    return iam_login(payload, s)


@app.post("/auth/session/start")
def auth_session_start(data: AuthSessionStartIn, request: Request, s: Session = Depends(get_db)):
    row = create_bound_session(s, data.user_id, request)
    token = create_access_token(data.user_id, row.session_id)
    return {
        "access_token": token,
        "token_type": "bearer",
        "session_id": row.session_id,
        "expires_in_seconds": int(settings.jwt_access_token_minutes) * 60,
        "mfa_required": True,
    }


@app.get("/auth/session/me")
def auth_session_me(zt: Dict[str, Any] = Depends(zero_trust_guard), s: Session = Depends(get_db)):
    row = (
        s.query(db.UISession)
        .filter(db.UISession.session_id == zt["session_id"], db.UISession.user_id == zt["user_id"])
        .first()
    )
    return {
        "user_id": zt["user_id"],
        "session_id": zt["session_id"],
        "trust_score": zt["trust_score"],
        "action": zt["action"],
        "risk_level": float(row.risk_level) if row else None,
        "last_seen": row.last_seen.isoformat() if row and row.last_seen else None,
        "is_active": bool(int(row.is_active)) if row else False,
        "elevated": bool(row.elevated_until and datetime.utcnow() <= row.elevated_until) if row else False,
    }


@app.post("/auth/step-up")
def auth_step_up(payload: AuthStepUpIn, request: Request, s: Session = Depends(get_db)):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    claims = decode_access_token(header.removeprefix("Bearer ").strip())
    user_id = str(claims.get("sub", ""))
    session_id = str(claims.get("session_id", ""))
    ok = elevate_session_with_totp(session=s, user_id=user_id, session_id=session_id, otp_code=payload.otp_code)
    if not ok:
        raise HTTPException(status_code=401, detail="invalid MFA code")
    return {"session_id": session_id, "status": "elevated"}


@app.post("/auth/session/revoke")
def auth_session_revoke(zt: Dict[str, Any] = Depends(zero_trust_guard), s: Session = Depends(get_db)):
    ok = revoke_session(session=s, user_id=zt["user_id"], session_id=zt["session_id"])
    if not ok:
        raise HTTPException(status_code=404, detail="session not found")
    return {"session_id": zt["session_id"], "revoked": True}

# Pydantic Schemas
class TelemetryIn(BaseModel):
    entity_id: str
    entity_type: Optional[str] = None
    cloud_env: Optional[str] = None
    timestamp: float
    timestep: Optional[int] = None
    api_rate: float
    payload_size: float
    traversal_depth: int
    session_duration: float
    failed_auth_count: int
    geo_anomaly_flag: int
    protocol_type: str
    is_attack: Optional[int] = None

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:@\-]{1,128}", v):
            raise ValueError("entity_id contains invalid characters")
        return v

    @field_validator("protocol_type")
    @classmethod
    def validate_protocol_type(cls, v: str) -> str:
        p = v.strip().upper()
        if p not in {"HTTPS", "HTTP", "SSH"}:
            raise ValueError("protocol_type must be one of HTTPS, HTTP, SSH")
        return p

class TelemetryBatch(BaseModel):
    records: List[TelemetryIn]

class EntityStatus(BaseModel):
    entity_id: str
    trust_score: float
    status: str

# Initialize Advanced Analytics
experiment_evaluator = ev.ArgentEvaluator()

# --- INITIALIZATION ---
engine = vb.get_engine()
engine.evaluator = experiment_evaluator # Inject for cyclic logging

@app.get("/model-info")
def get_model_info():
    return {
        "decision_engine": "TabNetClassifier",
        "input_features": ["behavior_score", "context_score", "history_score", "anomaly_score"],
        "threshold": float(getattr(engine, "threshold", 0.5)),
        "mode": "static_inference",
        "model_source": getattr(engine, "model_source", "unknown"),
    }

@app.get("/trust/{entity_id}", response_model=EntityStatus)
def get_trust_score(entity_id: str, s: Session = Depends(get_db)):
    cached_trust = db.hot_state.get(f"trust:{entity_id}")
    cached_status = db.hot_state.get(f"status:{entity_id}")
    if cached_trust is not None and cached_status is not None:
        return EntityStatus(entity_id=entity_id, trust_score=float(cached_trust), status=str(cached_status))

    entity = s.query(db.Entity).filter(db.Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    return EntityStatus(
        entity_id=entity.id,
        trust_score=entity.current_trust_score,
        status=entity.status
    )



# ─────────────────────────────────────────────────────────────────────────────
# Phase B — Tenant Management Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TenantCreateIn(BaseModel):
    tenant_id: str
    display_name: str = ""
    allow_threshold: float = 65.0
    rate_limit_threshold: float = 48.0
    isolate_threshold: float = 48.0
    rate_limit_rpm: int = 12000
    allowed_cloud_envs: List[str] = ["AWS", "Azure", "GCP"]
    shadow_learning_enabled: bool = True
    max_entities: int = 50000
    max_isolations_per_minute: int = 50
    max_cloud_mutations_per_hour: int = 5


@app.get("/tenants")
def list_tenants(_: Dict[str, Any] = Depends(zero_trust_guard)):
    """List all active tenants."""
    reg = get_tenant_registry()
    return {"tenants": reg.list_all()}


@app.post("/tenants")
def create_tenant(body: TenantCreateIn, _: Dict[str, Any] = Depends(zero_trust_guard)):
    """Create a new tenant."""
    import re as re_mod
    if not re_mod.fullmatch(r"[a-z0-9\-]{2,64}", body.tenant_id):
        raise HTTPException(status_code=400, detail="tenant_id must be lowercase alphanumeric+hyphen, 2-64 chars")
    reg = get_tenant_registry()
    if reg.exists(body.tenant_id):
        raise HTTPException(status_code=409, detail=f"Tenant '{body.tenant_id}' already exists")
    import time as _time
    cfg = TenantConfig(
        tenant_id=body.tenant_id,
        display_name=body.display_name or body.tenant_id,
        thresholds=TrustThresholds(
            allow=body.allow_threshold,
            rate_limit=body.rate_limit_threshold,
            isolate=body.isolate_threshold,
        ),
        rate_limit_rpm=body.rate_limit_rpm,
        allowed_cloud_envs=body.allowed_cloud_envs,
        policy_file="default",
        shadow_learning_enabled=body.shadow_learning_enabled,
        max_entities=body.max_entities,
        created_at=_time.time(),
        active=True,
        max_isolations_per_minute=body.max_isolations_per_minute,
        max_cloud_mutations_per_hour=body.max_cloud_mutations_per_hour,
    )
    reg.create(cfg)
    return cfg.to_dict()


@app.get("/tenants/{tenant_id}/config")
def get_tenant_config(tenant_id: str, _: Dict[str, Any] = Depends(zero_trust_guard)):
    """Get configuration for a specific tenant."""
    reg = get_tenant_registry()
    cfg = reg.get_or_none(tenant_id)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return cfg.to_dict()


@app.put("/tenants/{tenant_id}/config")
def update_tenant_config(
    tenant_id: str,
    updates: Dict[str, Any],
    _: Dict[str, Any] = Depends(zero_trust_guard),
):
    """Update tenant configuration fields."""
    reg = get_tenant_registry()
    if not reg.exists(tenant_id):
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    try:
        updated = reg.update(tenant_id, updates)
        return updated.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/tenants/{tenant_id}/metrics")
def get_tenant_metrics(tenant_id: str, s: Session = Depends(get_db)):
    """Per-tenant decision distribution and entity count."""
    total = s.query(db.Entity).filter(db.Entity.tenant_id == tenant_id).count()
    allow = s.query(db.Entity).filter(
        db.Entity.tenant_id == tenant_id, db.Entity.status == "ALLOW"
    ).count()
    rate_limit = s.query(db.Entity).filter(
        db.Entity.tenant_id == tenant_id, db.Entity.status == "RATE_LIMIT"
    ).count()
    isolate = s.query(db.Entity).filter(
        db.Entity.tenant_id == tenant_id, db.Entity.status == "ISOLATE"
    ).count()
    audit_count = s.query(db.PolicyAuditLog).filter(
        db.PolicyAuditLog.tenant_id == tenant_id
    ).count()
    return {
        "tenant_id": tenant_id,
        "entity_count": total,
        "decisions": {
            "ALLOW": allow,
            "RATE_LIMIT": rate_limit,
            "ISOLATE": isolate,
        },
        "policy_audit_events": audit_count,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Phase C — Safety Control Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/system/status")
def system_status():
    fsm = get_fail_safe_manager()
    return fsm.status()


@app.post("/system/kill-switch")
def system_kill_switch(
    body: KillSwitchToggleIn,
    _: Dict[str, Any] = Depends(zero_trust_guard),
):
    fsm = get_fail_safe_manager()
    state = fsm.set_kill_switch(body.enable)
    return {"kill_switch_status": state, "system_mode": fsm.status().get("system_mode")}


@app.get("/system/safety-metrics")
def system_safety_metrics():
    fsm = get_fail_safe_manager()
    return fsm.safety_metrics()

@app.get("/safety/status")
def safety_status(tenant_id: str = "default"):
    """Current circuit breaker state and per-tenant limit utilization."""
    sc = get_safety_controller()
    return sc.get_status(tenant_id=tenant_id)


@app.post("/safety/circuit/reset")
def safety_circuit_reset(
    operator_id: str = "api",
    _: Dict[str, Any] = Depends(zero_trust_guard),
):
    """
    Manually reset circuit breaker from OPEN → HALF_OPEN.
    Requires N successful probes before fully closing.
    """
    sc = get_safety_controller()
    was_open = sc.circuit.reset(operator_id=operator_id)
    status = sc.circuit.get_status()
    return {
        "reset": was_open,
        "new_state": status.state,
        "probe_limit": sc.circuit._probe_limit,
        "operator_id": operator_id,
    }


@app.get("/safety/limits")
def safety_limits(tenant_id: str = "default"):
    """Current execution limit stats for a tenant."""
    sc = get_safety_controller()
    return sc.limits.get_stats(tenant_id=tenant_id)

# ─────────────────────────────────────────────────────────────────────────────
# Phase D — Intelligence Layer Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/intelligence/status")
def intelligence_status():
    """Current health and stats of the Intelligence Layer."""
    intel = get_intelligence_layer()
    return intel.health()


@app.get("/intelligence/suggestions")
def intelligence_suggestions(
    tenant_id: Optional[str] = None,
    since_hours: float = 24.0,
    min_samples: int = 10,
):
    """Get rule adjustment suggestions based on recent feedback."""
    intel = get_intelligence_layer()
    suggestions = intel.get_adjustment_suggestions(
        tenant_id=tenant_id,
        since_hours=since_hours,
        min_samples=min_samples
    )
    return {"suggestions": [s.to_dict() for s in suggestions]}


@app.post("/intelligence/adjustments/apply")
def apply_intelligence_adjustments(
    dry_run: bool = True,
):
    """
    Beta: Apply rule priority/weight adjustments automatically.
    Returns the count of rules updated and the new policy version.
    """
    intel = get_intelligence_layer()
    result = intel.apply_adjustments(dry_run=dry_run)
    return result

# ─────────────────────────────────────────────────────────────────────────────
# Phase E — SOC Visibility Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/soc/dashboard", response_class=HTMLResponse)
def soc_dashboard(request: Request):
    """Serve the SOC Command Center dashboard."""
    require_platform_role(request, "Administrator", "Analyst", "ReadOnly")
    return templates.TemplateResponse(request, "soc_dashboard.html", {"active_page": "soc"})


@app.post("/soc/decision/{decision_id}/feedback")
def submit_decision_feedback(request: Request, decision_id: int, feedback: Dict[str, Any], s: Session = Depends(get_db)):
    """Accept continuous feedback from human operators on a specific enforcement decision."""
    require_feedback_operator(request)
    enf = s.query(db.EnforcementAction).filter(db.EnforcementAction.id == decision_id).first()
    if not enf:
        raise HTTPException(status_code=404, detail="Decision not found")
        
    is_correct = feedback.get("is_correct", True)
    enf.is_correct = 1 if is_correct else 0
    s.commit()
    
    # Notify Intelligence Layer if initialized
    try:
        from intelligence_layer import get_intelligence_layer
        intel = get_intelligence_layer()
        intel.record_feedback(
            tenant_id="default",
            entity_id=enf.entity_id,
            decision=enf.decision,
            is_correct=is_correct,
            source="human_operator"
        )
    except Exception as e:
        import logging
        logging.error(f"Failed to route feedback to intelligence layer: {e}")
        
    return {"status": "success", "decision_id": decision_id, "is_correct": is_correct}

@app.get("/soc/decision/{decision_id}", response_class=HTMLResponse)
def decision_explorer_ui(request: Request, decision_id: int):
    """Serve the Decision Explorer UI for forensic tracing."""
    require_platform_role(request, "Administrator", "Analyst", "ReadOnly")
    return templates.TemplateResponse(request, "decision_explorer.html", {"decision_id": decision_id, "active_page": "soc"})

@app.get("/api/decision/{decision_id}/trace")
def get_decision_trace(decision_id: int, s: Session = Depends(get_db)):
    """Provides full forensic trace for a single enforcement action."""
    enf = s.query(db.EnforcementAction).filter(db.EnforcementAction.id == decision_id).first()
    if not enf:
        raise HTTPException(status_code=404, detail="Decision not found")
        
    # Get telemetry at action if possible
    tel = s.query(db.Telemetry).filter(db.Telemetry.entity_id == enf.entity_id).order_by(db.Telemetry.timestamp.desc()).first()
    
    # Try to find corresponding Policy Audit Log
    audit = s.query(db.PolicyAuditLog).filter(
        db.PolicyAuditLog.entity_id == enf.entity_id,
        db.PolicyAuditLog.action == enf.decision
    ).order_by(db.PolicyAuditLog.timestamp.desc()).first()
    
    return {
        "id": enf.id,
        "entity_id": enf.entity_id,
        "timestamp": enf.timestamp.isoformat(),
        "action": enf.decision,
        "reason": enf.reason,
        "trust_score": enf.trust_score_at_action,
        "b_score": enf.b_score,
        "c_score": enf.c_score,
        "h_score": enf.h_score,
        "a_score": enf.a_score,
        "a_prime_score": enf.a_prime_score,
        "telemetry": {
            "api_rate": tel.api_rate if tel else enf.api_rate,
            "payload_size": tel.payload_size if tel else enf.payload_size,
            "geo_anomaly": tel.geo_anomaly_flag if tel else 0,
            "protocol": tel.protocol_type if tel else "HTTPS",
        },
        "policy": {
            "rule_id": audit.rule_id if audit else "UNKNOWN",
            "matched_rules": json.loads(audit.matched_rules) if audit and audit.matched_rules else [],
            "override_applied": audit.override_id if audit else None,
        }
        ,
        "fail_safe": {
            "applied": "FAIL_SAFE:" in (enf.reason or "") or "FAIL_SAFE_OVERRIDE" in (json.loads(audit.matched_rules) if audit and audit.matched_rules else []),
            "reason": ((enf.reason or "").split("FAIL_SAFE:", 1)[1].strip() if "FAIL_SAFE:" in (enf.reason or "") else ""),
            "fallback_action": enf.decision if "FAIL_SAFE:" in (enf.reason or "") else None,
            "system_mode": "SAFE_MODE" if "monitor-only mode" in (enf.reason or "") else ("DEGRADED" if "DEGRADED mode" in (enf.reason or "") else "NORMAL"),
        },
    }


@app.get("/soc/overview")
def soc_overview(tenant_id: Optional[str] = None, s: Session = Depends(get_db)):
    """
    Aggregated system health: all subsystem statuses, alert counts,
    decision distribution, and intelligence metrics.
    """
    # Decision distribution
    allow_count = s.query(db.Entity).filter(db.Entity.status == "ALLOW").count()
    rate_limit_count = s.query(db.Entity).filter(db.Entity.status == "RATE_LIMIT").count()
    isolate_count = s.query(db.Entity).filter(db.Entity.status == "ISOLATE").count()
    total_entities = allow_count + rate_limit_count + isolate_count
    avg_trust = s.query(func.avg(db.Entity.current_trust_score)).scalar() or 0.0

    # Safety status
    try:
        sc = get_safety_controller()
        safety_status = sc.get_status(tenant_id=tenant_id)
    except Exception:
        safety_status = {"circuit_breaker": {"state": "UNKNOWN"}, "execution_limits": {}}

    # Alert counts
    try:
        am = get_alert_manager()
        alert_counts = am.store.get_counts()
        alert_stats = am.get_stats()
    except Exception:
        alert_counts = {"FIRING": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0, "by_severity": {}}
        alert_stats = {}

    # Intelligence status
    try:
        intel = get_intelligence_layer()
        intel_health = intel.health()
    except Exception:
        intel_health = {}

    # Policy info
    try:
        pe = get_policy_engine()
        policy_version = pe.version
        rules_count = len(pe.get_rules_summary())
    except Exception:
        policy_version = "unknown"
        rules_count = 0

    # Tenant count
    try:
        tr = get_tenant_registry()
        tenant_count = len(tr.list_all())
    except Exception:
        tenant_count = 0

    return {
        "total_entities": total_entities,
        "avg_trust": round(avg_trust, 2),
        "decision_distribution": {
            "ALLOW": allow_count,
            "RATE_LIMIT": rate_limit_count,
            "ISOLATE": isolate_count,
        },
        "safety": safety_status,
        "alert_counts": alert_counts,
        "alert_scanner": alert_stats,
        "intelligence": intel_health,
        "policy_version": policy_version,
        "rules_count": rules_count,
        "tenant_count": tenant_count,
    }


@app.get("/soc/alerts")
def soc_alerts(
    severity: Optional[str] = None,
    tenant_id: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 50,
):
    """Active and historical alerts with filtering."""
    am = get_alert_manager()
    all_alerts = am.store.get_all(limit=limit)

    if severity:
        all_alerts = [a for a in all_alerts if a.severity == severity.upper()]
    if tenant_id:
        all_alerts = [a for a in all_alerts if a.tenant_id == tenant_id or a.tenant_id is None]
    if state:
        all_alerts = [a for a in all_alerts if a.state == state.upper()]

    return {
        "alerts": [a.to_dict() for a in all_alerts[:limit]],
        "total": len(all_alerts),
        "counts": am.store.get_counts(),
    }


@app.post("/soc/alerts/{alert_id}/acknowledge")
def soc_alert_acknowledge(alert_id: str, operator_id: str = "soc"):
    """Acknowledge a firing alert."""
    am = get_alert_manager()
    success = am.store.acknowledge(alert_id, operator_id=operator_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found or not in FIRING state")
    return {"alert_id": alert_id, "state": "ACKNOWLEDGED", "operator_id": operator_id}


@app.post("/soc/alerts/{alert_id}/resolve")
def soc_alert_resolve(alert_id: str, operator_id: str = "soc"):
    """Resolve an alert (FIRING or ACKNOWLEDGED → RESOLVED)."""
    am = get_alert_manager()
    success = am.store.resolve(alert_id, operator_id=operator_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "state": "RESOLVED", "operator_id": operator_id}


@app.get("/soc/timeline")
def soc_timeline(limit: int = 50, s: Session = Depends(get_db)):
    """
    Chronological event stream: recent decisions, safety overrides,
    circuit trips, and alerts.
    """
    events: List[Dict[str, Any]] = []

    # Recent enforcement actions
    try:
        actions = (
            s.query(db.EnforcementAction)
            .order_by(db.EnforcementAction.timestamp.desc())
            .limit(limit)
            .all()
        )
        for a in actions:
            ts = a.timestamp.timestamp() if a.timestamp else time.time()
            events.append({
                "id": a.id,
                "timestamp": ts,
                "type": a.decision or "UNKNOWN",
                "decision": a.decision,
                "entity_id": a.entity_id,
                "description": f"{a.decision} · trust={a.trust_score_at_action:.1f}" if a.trust_score_at_action else a.decision,
                "source": "enforcement",
            })
    except Exception:
        pass

    # Recent alerts
    try:
        am = get_alert_manager()
        for alert in am.store.get_all(limit=20):
            events.append({
                "timestamp": alert.fired_at,
                "type": "ALERT",
                "decision": None,
                "entity_id": None,
                "description": f"[{alert.severity}] {alert.title}",
                "source": "alerting",
            })
    except Exception:
        pass

    # Sort by timestamp descending
    events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    return {"events": events[:limit]}


@app.get("/soc/policy/audit")
def soc_policy_audit(tenant_id: Optional[str] = None):
    """Policy rule match frequency and summary."""
    try:
        pe = get_policy_engine()
        rules = pe.get_rules_summary(tenant_id=tenant_id)
        return {"rules": rules, "version": pe.version}
    except Exception as exc:
        return {"rules": [], "version": "unknown", "error": str(exc)}


@app.get("/soc/tenants/comparison")
def soc_tenants_comparison():
    """Side-by-side tenant health metrics."""
    try:
        tr = get_tenant_registry()
        tenants = tr.list_all()
        return {"tenants": tenants}
    except Exception as exc:
        return {"tenants": [], "error": str(exc)}


@app.get("/soc/decisions/distribution")
def soc_decisions_distribution(s: Session = Depends(get_db)):
    """Decision distribution over time."""
    allow = s.query(db.Entity).filter(db.Entity.status == "ALLOW").count()
    rate_limit = s.query(db.Entity).filter(db.Entity.status == "RATE_LIMIT").count()
    isolate = s.query(db.Entity).filter(db.Entity.status == "ISOLATE").count()
    return {
        "distribution": {"ALLOW": allow, "RATE_LIMIT": rate_limit, "ISOLATE": isolate},
        "total": allow + rate_limit + isolate,
    }


# ─────────────────────────────────────────────────────────────────────────────

@app.post("/authorize")



async def authorize(request: Request, background_tasks: BackgroundTasks, s: Session = Depends(get_db)):
    request_id = _request_id_from_request(request)
    tenant_id = getattr(request.state, "tenant_id", "default")
    t0 = time.perf_counter()
    data: Dict[str, Any] = {}
    try:
        data = await request.json()
        auth = authorize_logic(
            data, s, background_tasks,
            source="authorize",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        return {
            "decision": auth["decision"],
            "trust": auth["trust"],
            "reason": auth["reason"],
            "rule_id": auth.get("rule_id"),
            "policy_version": auth.get("policy_version"),
            "matched_rules": auth.get("matched_rules", []),
            "tenant_id": tenant_id,
            "request_id": request_id,
            "context": auth.get("context", {}),
        }
    except Exception as exc:
        record = observability.build_record(
            request_id=request_id,
            source="authorize",
            entity_id=str(data.get("entity_id", "")).strip() or None,
            input_features=_decision_feature_snapshot(data),
            status="error",
            final_action="ERROR",
            policy_decision="ERROR",
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            error_message=str(exc),
        )
        observability.emit(record, background_tasks=background_tasks)
        raise


@app.post("/gateway")
async def gateway(request: Request, background_tasks: BackgroundTasks, s: Session = Depends(get_db)):
    request_id = _request_id_from_request(request)
    t0 = time.perf_counter()
    data: Dict[str, Any] = {}
    try:
        data = await request.json()

        if phase5_gateway is not None:
            phase5_req = _build_phase5_request(data)

            async def _forward(req: IncomingRequest) -> Dict[str, Any]:
                target_api = _resolve_target_api(data)
                async with httpx.AsyncClient(timeout=5.0) as client:
                    try:
                        target_response = await client.post(target_api, json=data)
                    except httpx.HTTPError as exc:
                        raise HTTPException(status_code=502, detail=f"target API unavailable: {exc}") from exc

                try:
                    forwarded_body = target_response.json()
                except ValueError:
                    forwarded_body = {"raw": target_response.text}

                return {
                    "status": "forwarded",
                    "decision": "ALLOW",
                    "entity_id": req.entity_id,
                    "target_api": target_api,
                    "target_status_code": target_response.status_code,
                    "target_response": forwarded_body,
                }

            async def _throttle(req: IncomingRequest) -> Dict[str, Any]:
                return {
                    "status": "limited",
                    "decision": "RATE_LIMIT",
                    "entity_id": req.entity_id,
                    "scope": "READ_ONLY_SCOPED",
                }

            async def _block(req: IncomingRequest) -> Dict[str, Any]:
                return {
                    "status": "blocked",
                    "decision": "ISOLATE",
                    "entity_id": req.entity_id,
                    "reason": "Sentinel enforcement",
                }

            response = await phase5_gateway.handle_request_async(
                phase5_req,
                _forward,
                _throttle,
                _block,
                50,
            )
            policy_decision = "ALLOW"
            final_action = str(response.get("decision", "ALLOW")) if isinstance(response, dict) else "ALLOW"
            trust_score = float(db.hot_state.get(f"trust:{phase5_req.entity_id}", 0.0) or 0.0)
            risk_score = max(0.0, min(1.0, 1.0 - (trust_score / 100.0)))

            if phase5_gateway.metrics.events:
                last_event = phase5_gateway.metrics.events[-1]
                observe_sentinel_latency(last_event.get("sentinel_latency_ms", 0.0))
                inc_decision(last_event.get("decision", "ALLOW"))
                logger.info("Gateway decision", extra=last_event)
                policy_decision = str(last_event.get("decision", final_action))
                final_action = str(last_event.get("decision", final_action))
                _append_recent_event(
                    entity_id=str(last_event.get("entity_id", phase5_req.entity_id)),
                    decision=final_action,
                    prob=None,
                    trust=trust_score,
                    reason="Sentinel gateway path",
                )

            record = observability.build_record(
                request_id=request_id,
                source="gateway",
                entity_id=phase5_req.entity_id,
                input_features=_decision_feature_snapshot(data),
                risk_score=risk_score,
                trust_score=trust_score,
                policy_decision=policy_decision,
                final_action=final_action,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                status="success",
            )
            observability.emit(record, background_tasks=background_tasks)
            return response

        auth = authorize_logic(data, s, background_tasks, source="gateway", request_id=request_id)

        if auth["decision"] == "ISOLATE":
            return {
                "status": "blocked",
                "decision": auth["decision"],
                "trust": auth["trust"],
                "reason": auth["reason"],
                "request_id": request_id,
            }

        if auth["decision"] == "RATE_LIMIT":
            return {
                "status": "limited",
                "decision": auth["decision"],
                "trust": auth["trust"],
                "reason": auth["reason"],
                "scope": "READ_ONLY_SCOPED",
                "request_id": request_id,
            }

        target_api = _resolve_target_api(data)
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                target_response = await client.post(target_api, json=data)
            except httpx.HTTPError as exc:
                raise HTTPException(status_code=502, detail=f"target API unavailable: {exc}") from exc

        try:
            forwarded_body = target_response.json()
        except ValueError:
            forwarded_body = {"raw": target_response.text}

        return {
            "status": "forwarded",
            "decision": auth["decision"],
            "trust": auth["trust"],
            "reason": auth["reason"],
            "target_api": target_api,
            "target_status_code": target_response.status_code,
            "target_response": forwarded_body,
            "request_id": request_id,
        }
    except Exception as exc:
        record = observability.build_record(
            request_id=request_id,
            source="gateway",
            entity_id=str(data.get("entity_id", "")).strip() or None,
            input_features=_decision_feature_snapshot(data),
            status="error",
            final_action="ERROR",
            policy_decision="ERROR",
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            error_message=str(exc),
        )
        observability.emit(record, background_tasks=background_tasks)
        raise


@app.post("/gateway/feedback")
def gateway_feedback(data: GatewayFeedbackIn, s: Session = Depends(get_db)):
    """
    Records ground-truth label for an entity and triggers:
      1. Intelligence feedback collector (D2)
      2. Neural hard-buffer routing for retraining (D4)
    """
    # 1. Update legacy brain state
    accepted = engine.record_enforcement_feedback(data.entity_id, s, data.true_label)
    if not accepted:
        raise HTTPException(status_code=404, detail="No telemetry found for entity")

    # 2. Phase D: Intelligence Feed
    try:
        intel = get_intelligence_layer()
        # Find the latest audit record for this entity to get rule_id and trust_score
        audit = (
            s.query(db.PolicyAuditLog)
            .filter(db.PolicyAuditLog.entity_id == data.entity_id)
            .order_by(db.PolicyAuditLog.timestamp.desc())
            .first()
        )
        
        # Pull telemetry for feature reconstruction
        latest_telem = (
            s.query(db.Telemetry)
            .filter(db.Telemetry.entity_id == data.entity_id)
            .order_by(db.Telemetry.timestamp.desc())
            .first()
        )
        
        if audit and latest_telem:
            # We reconstruct features to send to model feedback buffer
            entity = s.query(db.Entity).filter(db.Entity.id == data.entity_id).first()
            features = engine._build_feature_vector(latest_telem, entity)
            
            intel.record_feedback(
                tenant_id=audit.tenant_id,
                entity_id=data.entity_id,
                decision=audit.action,
                true_label=data.true_label,
                rule_id=audit.rule_id,
                trust_score=audit.trust_score,
                features=features.tolist() if hasattr(features, "tolist") else list(features),
                context_composite=0.5, # Default since we don't store ctx in audit yet
                source="gateway_feedback"
            )
            logger.info("Intelligence feedback recorded", extra={"entity_id": data.entity_id, "correct": (data.true_label == 0 and audit.action == "ALLOW")})
    except Exception as intel_exc:
        logger.warning("Failed to record intelligence feedback", extra={"error": str(intel_exc)})

    return {"entity_id": data.entity_id, "accepted": True, "true_label": data.true_label}


@app.post("/ingest", status_code=202)
def ingest_telemetry(data: TelemetryIn, background_tasks: BackgroundTasks, s: Session = Depends(get_db)):
    # 1. Ensure Entity Exists
    entity = s.query(db.Entity).filter(db.Entity.id == data.entity_id).first()
    if not entity:
        # Default metadata for new entities
        entity = db.Entity(
            id=data.entity_id, 
            entity_type="unknown", 
            cloud_env="AWS", 
            current_trust_score=75.0, 
            status="ALLOW"
        )
        s.add(entity)
        s.commit()
    
    # 2. Record Telemetry
    payload = data.model_dump()
    # Remove fields that belong to Entity metadata or simulation ground truth
    for field in ["entity_type", "cloud_env", "is_attack"]:
        payload.pop(field, None)
    
    telemetry = db.Telemetry(**payload)
    s.add(telemetry)
    s.commit()
    
    # 3. Trigger Analytics Worker
    infer_t0 = time.perf_counter()
    try:
        score, decision, reason, conf, comps = engine.calculate_trust(
            data.entity_id,
            s,
            true_label=data.is_attack,
            features=get_features(data.entity_id, data.model_dump()),
        )
    except Exception as exc:
        record = observability.build_record(
            source="ingest",
            entity_id=data.entity_id,
            input_features=_decision_feature_snapshot(data.model_dump()),
            status="error",
            policy_decision="ERROR",
            final_action="ERROR",
            latency_ms=(time.perf_counter() - infer_t0) * 1000.0,
            error_message=str(exc),
        )
        observability.emit(record, background_tasks=background_tasks)
        raise

    infer_ms = (time.perf_counter() - infer_t0) * 1000.0
    
    # 4. Update Entity State
    entity.current_trust_score = score
    entity.status = decision
    entity.last_updated = datetime.utcnow()
    
    # 5. Record Enforcement Action
    enforcement = db.EnforcementAction(
        entity_id=data.entity_id,
        decision=decision,
        reason=reason,
        trust_score_at_action=score,
        confidence_score=conf,
        b_score=comps.get("b_score"),
        c_score=comps.get("c_score"),
        h_score=comps.get("h_score"),
        a_score=comps.get("a_score"),
        a_prime_score=comps.get("a_prime_score"),
        api_rate=data.api_rate,
        payload_size=data.payload_size
    )
    s.add(enforcement)
    s.commit()

    # 6. Deploy to Infrastructure Sentinel (Closed Loop)
    background_tasks.add_task(sentinel.deploy_block, data.entity_id, decision, reason)
    
    # 7. Hot State Persistence (Mock Redis)
    db.hot_state.set(f"trust:{data.entity_id}", score)
    db.hot_state.set(f"status:{data.entity_id}", decision)
    db.hot_state.set(f"history:{data.entity_id}", _clip01(score / 100.0))

    record = observability.build_record(
        source="ingest",
        entity_id=data.entity_id,
        input_features=_decision_feature_snapshot(data.model_dump()),
        risk_score=float(comps.get("prob_score")) if comps.get("prob_score") is not None else None,
        trust_score=float(score),
        policy_decision=str(decision),
        final_action=str(decision),
        latency_ms=infer_ms,
        status="success",
    )
    observability.emit(record, background_tasks=background_tasks)

    # [PHASE 8 PERFORMANCE] static inference only: no live learning path.

    return {
        "entity": data.entity_id,
        "trust_score": score,
        "decision": decision,
        "reason": reason,
        "reason_details": comps.get("decision_reason_details", {}),
        "prediction": comps.get("prediction"),
        "probability": comps.get("prob_score"),
        "feature_contributions": comps.get("feature_contributions", {}),
    }

@app.post("/ingest-batch", status_code=202)
def ingest_batch(batch: TelemetryBatch):
    """
    Nuclear High-Throughput Ingest (Phase 8 Performance Tier)
    Zero-blocking memory push. Lowest possible latency.
    """
    with queue_lock:
        ingestion_queue.extend(batch.records)
    return {"status": "enqueued", "count": len(batch.records)}

def telemetry_drain_worker():
    """Autonomous Background Worker: Drains memory queue to DB & Analytics."""
    global engine
    logger.info("Autonomous ingestion worker engaged")
    
    while not shutdown_event.is_set():
        batch_to_process = []
        with queue_lock:
            # Drain up to 1000 records at a time for bulk efficiency
            size = min(len(ingestion_queue), 1000)
            for _ in range(size):
                batch_to_process.append(ingestion_queue.popleft())
        
        if not batch_to_process:
            time.sleep(0.1) # Cool down if queue is empty
            continue
            
        # Process the micro-batch in one DB context
        s = db.SessionLocal()
        try:
            # 1. Bulk Upsert Entities (Registry)
            entity_ids = list(set([d.entity_id for d in batch_to_process]))
            existing_map = {e.id: e for e in s.query(db.Entity).filter(db.Entity.id.in_(entity_ids)).all()}
            
            missing_entities = []
            for d in batch_to_process:
                if d.entity_id not in existing_map:
                    new_ent = db.Entity(
                        id=d.entity_id, 
                        entity_type=d.entity_type or "unknown", 
                        cloud_env=d.cloud_env or "AWS", 
                        current_trust_score=75.0, 
                        status="ALLOW"
                    )
                    existing_map[d.entity_id] = new_ent
                    missing_entities.append(new_ent)
            
            if missing_entities:
                s.add_all(missing_entities)
                s.flush()
            
            # 2. Bulk Save Raw Telemetry (100% Persistence)
            telemetry_objs = []
            for data in batch_to_process:
                payload = data.model_dump()
                for field in ["entity_type", "cloud_env", "is_attack"]:
                    payload.pop(field, None)
                telemetry_objs.append(db.Telemetry(**payload))
            s.add_all(telemetry_objs)
            s.flush()

            # 3. Sampled Analytics for Metrics Visibility (10% Sampling for 200/s stability)
            tp = fp = fn = tn = 0
            coverage_count = 0
            labeled_count = 0
            
            # Take every 10th record or a random subset for analytics
            sample_size = max(1, len(batch_to_process) // 10)
            analytics_batch = batch_to_process[:sample_size]
            features_by_entity = build_features_batch(analytics_batch)
            
            for data in analytics_batch:
                entity = existing_map.get(data.entity_id)
                if not entity: continue
                
                # 1. Base Neural Inference
                score, base_decision, base_reason, conf, comps = engine.calculate_trust(
                    data.entity_id,
                    s,
                    true_label=data.is_attack,
                    features=features_by_entity.get(data.entity_id),
                )
                
                # 2. Policy Enforcement & Zero Trust Overrides
                policy_verdict = get_live_enforcement_engine().decide(
                    entity_id=data.entity_id,
                    trust_score=score,
                    telemetry=data.model_dump(),
                    tenant_id="default",
                    source="autonomous_sim",
                    simulation=False # Allow metrics to populate the dashboard and API
                )
                decision = policy_verdict.action
                reason = policy_verdict.reason
                try:
                    fail_safe = get_fail_safe_manager().evaluate(
                        entity_id=data.entity_id,
                        proposed_action=decision,
                        confidence=float(policy_verdict.confidence),
                        matched_rules=list(policy_verdict.matched_rules),
                        simulation=False,
                    )
                    if fail_safe.fail_safe_applied:
                        decision = fail_safe.final_action
                        reason = f"{reason} | FAIL_SAFE: {fail_safe.fail_safe_reason}"
                except Exception as fail_safe_exc:
                    logger.warning("Fail-safe manager error in worker", extra={"error": str(fail_safe_exc)})
                
                # Real-time Stats Accumulation
                prob = float(comps.get('prob_score', 0.5))
                pred_attack = bool(prob > float(getattr(engine, 'threshold', 0.5)))

                # Update online quality metrics only for explicitly labeled events.
                if data.is_attack is not None:
                    labeled_count += 1
                    actual_attack = bool(int(data.is_attack))
                    if pred_attack and actual_attack:
                        tp += 1
                    elif pred_attack and not actual_attack:
                        fp += 1
                    elif not pred_attack and actual_attack:
                        fn += 1
                    else:
                        tn += 1
                    if abs(prob - float(getattr(engine, 'threshold', 0.5))) <= 0.15:
                        coverage_count += 1
                else:
                    actual_attack = False
                
                # Update State & Enforcement
                entity.current_trust_score = score
                entity.status = decision
                
                enforcement = db.EnforcementAction(
                    entity_id=data.entity_id,
                    decision=decision, reason=reason,
                    trust_score_at_action=score, confidence_score=conf,
                    b_score=comps.get("b_score"), c_score=comps.get("c_score"),
                    h_score=comps.get("h_score"), a_score=comps.get("a_score"),
                    a_prime_score=comps.get("a_prime_score"),
                    api_rate=data.api_rate, payload_size=data.payload_size,
                    is_correct=1 if (actual_attack == (decision in ['RATE_LIMIT', 'ISOLATE'])) else 0
                )
                s.add(enforcement)
                sentinel.deploy_block(data.entity_id, decision, reason)
                db.hot_state.set(f"trust:{data.entity_id}", score)
                db.hot_state.set(f"status:{data.entity_id}", decision)
                db.hot_state.set(f"history:{data.entity_id}", _clip01(score / 100.0))
            
            s.commit()
            
            # 4. Instant Intelligence Visibility
            if labeled_count > 0:
                engine.track_batch_performance(tp, fp, fn, tn, coverage_count, labeled_count)
            
        except Exception as e:
            logger.warning("Worker error", extra={"error": str(e)})
        finally:
            s.close()

@app.get("/enforcement/status")
def get_enforcement_status():
    return sentinel.get_status()

@app.get("/enforcement/check/{entity_id}")
def check_block(entity_id: str):
    return {"blocked": sentinel.is_blocked(entity_id)}

# Stress Testing Endpoints REMOVED for Research Upgrade
@app.get("/metrics/snapshot")
def get_metrics_snapshot(s: Session = Depends(get_db)):
    avg_trust = s.query(func.avg(db.Entity.current_trust_score)).scalar() or 0.0
    allow_count = s.query(func.count(db.Entity.id)).filter(db.Entity.status == "ALLOW").scalar()
    rate_limit_count = s.query(func.count(db.Entity.id)).filter(db.Entity.status == "RATE_LIMIT").scalar()
    isolate_count = s.query(func.count(db.Entity.id)).filter(db.Entity.status == "ISOLATE").scalar()
    unsafe_count = s.query(func.count(db.Telemetry.id)).filter(db.Telemetry.geo_anomaly_flag == 1).scalar()
    
    # Brain Stats (CYCLIC RESEARCH METRICS - Single Source of Truth)
    brain_snapshot = engine.last_cycle_metrics
    brain_stats = {
        "cycles": brain_snapshot.get("cycle", 0),
        "loss": float(brain_snapshot.get("loss", 0.0)),
        "coverage": float(brain_snapshot.get("coverage", 0.0)),
        "accuracy": float(brain_snapshot.get("accuracy", 0.0)),
        "f1": float(brain_snapshot.get("f1", 0.0)),
        "precision": float(brain_snapshot.get("precision", 0.0)),
        "recall": float(brain_snapshot.get("recall", 0.0)),
        "adversarial_gain": float(brain_snapshot.get("gain", 0.0)),
        "tp": int(brain_snapshot.get("tp", 0)),
        "fp": int(brain_snapshot.get("fp", 0)),
        "fn": int(brain_snapshot.get("fn", 0)),
        "tn": int(brain_snapshot.get("tn", 0)),
        "status": brain_snapshot.get("status", "STATIC_MODEL_ACTIVE")
    }
    
    return {
        "avg_trust": round(avg_trust, 2),
        "allow_count": allow_count,
        "rate_limit_count": rate_limit_count,
        "isolate_count": isolate_count,
        "unsafe_count": unsafe_count,
        "brain_stats": brain_stats
    }


@app.get("/metrics")
def get_prometheus_metrics():
    return render_metrics()

@app.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # We need a fresh DB session for each snapshot in the loop
            session = db.SessionLocal()
            try:
                avg_trust = session.query(func.avg(db.Entity.current_trust_score)).scalar() or 0.0
                pass_cnt = session.query(db.Entity).filter(db.Entity.status == "ALLOW").count()
                limit_cnt = session.query(db.Entity).filter(db.Entity.status == "RATE_LIMIT").count()
                block_cnt = session.query(db.Entity).filter(db.Entity.status == "ISOLATE").count()
                brain_snapshot = engine.last_cycle_metrics
                
                snapshot = {
                    "mode": "static_inference",
                    "kind": "tabnet",
                    "elapsed": 0,
                    "intensity": 0,
                    "avg_trust": round(avg_trust, 2),
                    "counts": {"PASS": pass_cnt, "LIMIT": limit_cnt, "BLOCK": block_cnt},
                    "detected": int(block_cnt + limit_cnt),
                    "detection_delay": 0,
                    "transitions": 0,
                    "brain_status": brain_snapshot.get("status", "STATIC_MODEL_ACTIVE"),
                }
                await websocket.send_json(snapshot)
            finally:
                session.close()
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")

import signal

# Cleanup on shutdown
def graceful_shutdown(sig, frame):
    logger.warning("Shutdown signal received")
    try:
        engine.save_brain()
    except Exception as e:
        logger.error("Failed to save intelligence", extra={"error": str(e)})
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)

if __name__ == "__main__":
    import uvicorn
    import sys
    uvicorn.run(app, host=settings.app_host, port=settings.app_port)
