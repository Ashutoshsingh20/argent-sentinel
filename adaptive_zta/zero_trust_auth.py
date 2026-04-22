from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

import jwt
from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

import database as db
from runtime_settings import settings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _device_hash(request: Request) -> str:
    ua = request.headers.get("user-agent", "")
    fingerprint = request.headers.get("x-device-fingerprint", "")
    return _sha256_hex(f"{ua}|{fingerprint}")


def _ip_hash(request: Request) -> str:
    return _sha256_hex(_client_ip(request))


def _jwt_signing_key() -> str:
    key = settings.jwt_private_key_pem.strip()
    if not key:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="missing RS256 private key")
    return key


def _jwt_verification_key() -> str:
    key = settings.jwt_public_key_pem.strip()
    if not key and not settings.jwt_jwks_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="missing RS256 public key or JWKS URL")
    return key


def create_access_token(user_id: str, session_id: str) -> str:
    now = int(time.time())
    exp = now + int(settings.jwt_access_token_minutes) * 60
    payload = {
        "sub": user_id,
        "session_id": session_id,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, _jwt_signing_key(), algorithm="RS256")


def decode_access_token(token: str) -> Dict[str, Any]:
    algo = settings.jwt_algorithm.upper().strip()
    if algo != "RS256":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="JWT_ALGORITHM must be RS256")

    try:
        if settings.jwt_jwks_url:
            jwk_client = jwt.PyJWKClient(settings.jwt_jwks_url)
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "session_id"]},
            )
        else:
            claims = jwt.decode(
                token,
                _jwt_verification_key(),
                algorithms=["RS256"],
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "session_id"]},
            )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"invalid token: {exc}") from exc

    if not claims.get("sub") or not claims.get("session_id"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token claims")
    return claims


def _totp_secret_bytes(secret: str) -> bytes:
    normalized = secret.strip().replace(" ", "")
    padding = "=" * ((8 - (len(normalized) % 8)) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def generate_totp_secret() -> str:
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("utf-8").rstrip("=")


def _totp_code(secret: str, at_counter: int) -> str:
    key = _totp_secret_bytes(secret)
    msg = struct.pack(">Q", at_counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    otp = binary % 1_000_000
    return f"{otp:06d}"


def verify_totp(secret: str, code: str, for_time: Optional[int] = None) -> bool:
    now = int(for_time if for_time is not None else time.time())
    step = int(settings.zt_totp_step_seconds)
    drift = int(settings.zt_totp_allowed_drift)
    counter = now // step
    candidate = (code or "").strip()
    if len(candidate) != 6 or not candidate.isdigit():
        return False

    for off in range(-drift, drift + 1):
        if hmac.compare_digest(_totp_code(secret, counter + off), candidate):
            return True
    return False


def _ensure_user_auth(session: Session, user_id: str) -> db.UIUserAuth:
    row = session.query(db.UIUserAuth).filter(db.UIUserAuth.user_id == user_id).first()
    if row is None:
        row = db.UIUserAuth(user_id=user_id, totp_secret=generate_totp_secret(), mfa_enabled=1)
        session.add(row)
        session.commit()
        session.refresh(row)
    return row


def create_bound_session(session: Session, user_id: str, request: Request) -> db.UISession:
    user_auth = _ensure_user_auth(session, user_id)
    session_id = str(uuid4())
    row = db.UISession(
        session_id=session_id,
        user_id=user_id,
        device_hash=_device_hash(request),
        ip_hash=_ip_hash(request),
        created_at=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        risk_level=0.0,
        is_active=1,
        elevated_until=None,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    _audit_event(
        session=session,
        user_id=user_id,
        session_id=session_id,
        event_type="session_created",
        status="success",
        detail="session bound to device and ip hash",
    )
    if user_auth.mfa_enabled:
        _audit_event(
            session=session,
            user_id=user_id,
            session_id=session_id,
            event_type="mfa_enabled",
            status="success",
            detail="mfa required for step-up paths",
        )
    return row


def _audit_event(
    *,
    session: Session,
    user_id: Optional[str],
    session_id: Optional[str],
    event_type: str,
    status: str,
    detail: str,
) -> None:
    try:
        event = db.AuthAuditEvent(
            timestamp=datetime.utcnow(),
            user_id=user_id,
            session_id=session_id,
            event_type=event_type,
            status=status,
            detail=detail,
        )
        session.add(event)
        session.commit()
    except Exception:
        session.rollback()


def _required_threshold(path: str) -> float:
    if path.startswith("/cloud/actions/"):
        return float(settings.zt_high_trust_threshold)
    if path.startswith("/ui/decisions"):
        return float(settings.zt_medium_trust_threshold)
    if path.startswith("/ui/dashboard") or path == "/ui" or path.startswith("/ui/"):
        return float(settings.zt_low_trust_threshold)
    return float(settings.zt_medium_trust_threshold)


def _is_high_risk_route(path: str) -> bool:
    return path.startswith("/cloud/actions/")


def _load_session(session: Session, session_id: str, user_id: str) -> db.UISession:
    row = (
        session.query(db.UISession)
        .filter(db.UISession.session_id == session_id, db.UISession.user_id == user_id)
        .first()
    )
    if row is None or int(row.is_active or 0) != 1:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session")
    return row


def build_request_context(request: Request, claims: Dict[str, Any], ui_session: db.UISession) -> Dict[str, Any]:
    current_device = _device_hash(request)
    current_ip = _ip_hash(request)
    now = _utc_now()
    last_seen = ui_session.last_seen.replace(tzinfo=timezone.utc) if ui_session.last_seen else now
    inactive_seconds = max(0, int((now - last_seen).total_seconds()))

    return {
        "user_id": str(claims.get("sub", "")),
        "session_id": str(claims.get("session_id", "")),
        "device_hash": current_device,
        "ip_hash": current_ip,
        "route": request.url.path,
        "method": request.method,
        "timestamp": now.isoformat(),
        "device_mismatch": current_device != str(ui_session.device_hash or ""),
        "ip_mismatch": current_ip != str(ui_session.ip_hash or ""),
        "inactive_seconds": inactive_seconds,
        "high_risk_route": _is_high_risk_route(request.url.path),
        "required_threshold": _required_threshold(request.url.path),
        "session_risk_level": float(ui_session.risk_level or 0.0),
    }


def _session_is_elevated(ui_session: db.UISession) -> bool:
    if not ui_session.elevated_until:
        return False
    elevated_until = ui_session.elevated_until.replace(tzinfo=timezone.utc)
    return _utc_now() <= elevated_until


def enforce_zero_trust(
    *,
    request: Request,
    session: Session,
    evaluator: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")

    token = header.removeprefix("Bearer ").strip()
    claims = decode_access_token(token)
    user_id = str(claims.get("sub"))
    session_id = str(claims.get("session_id"))

    ui_session = _load_session(session, session_id, user_id)
    ctx = build_request_context(request, claims, ui_session)

    if ctx["inactive_seconds"] > int(settings.zt_session_idle_timeout_seconds):
        ui_session.is_active = 0
        session.add(ui_session)
        session.commit()
        _audit_event(
            session=session,
            user_id=user_id,
            session_id=session_id,
            event_type="session_timeout",
            status="denied",
            detail="session timed out on inactivity",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session expired")

    decision = evaluator(ctx)
    trust_score = float(decision.get("trust_score", 0.0))
    action = str(decision.get("action", "deny")).lower()
    required = float(ctx["required_threshold"])

    if trust_score < required:
        action = "step_up"
    if trust_score < float(settings.zt_deny_trust_threshold):
        action = "deny"

    # Device mismatch is hard signal for step-up.
    if bool(ctx.get("device_mismatch")):
        action = "step_up"

    # IP mismatch is soft signal: force step-up on high-risk routes.
    if bool(ctx.get("ip_mismatch")) and bool(ctx.get("high_risk_route")):
        action = "step_up"

    if action == "deny":
        _audit_event(
            session=session,
            user_id=user_id,
            session_id=session_id,
            event_type="zero_trust_guard",
            status="denied",
            detail=f"trust_score={trust_score:.2f}",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="access denied")

    if action == "step_up":
        if _session_is_elevated(ui_session):
            action = "allow"
        else:
            code = request.headers.get("x-step-up-code", "").strip()
            user_auth = _ensure_user_auth(session, user_id)
            if not verify_totp(str(user_auth.totp_secret), code):
                _audit_event(
                    session=session,
                    user_id=user_id,
                    session_id=session_id,
                    event_type="mfa_challenge",
                    status="required",
                    detail="mfa required or invalid code",
                )
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA required")

            ui_session.elevated_until = datetime.utcnow() + timedelta(seconds=int(settings.zt_step_up_ttl_seconds))
            _audit_event(
                session=session,
                user_id=user_id,
                session_id=session_id,
                event_type="mfa_verified",
                status="success",
                detail="session elevated",
            )

    ui_session.last_seen = datetime.utcnow()
    ui_session.risk_level = max(0.0, 100.0 - trust_score)
    session.add(ui_session)
    session.commit()

    return {
        "user_id": user_id,
        "session_id": session_id,
        "trust_score": trust_score,
        "action": action,
        "context": {
            "route": ctx["route"],
            "method": ctx["method"],
            "high_risk_route": bool(ctx["high_risk_route"]),
        },
    }


def revoke_session(*, session: Session, user_id: str, session_id: str) -> bool:
    row = (
        session.query(db.UISession)
        .filter(db.UISession.user_id == user_id, db.UISession.session_id == session_id)
        .first()
    )
    if row is None:
        return False
    row.is_active = 0
    row.elevated_until = None
    row.last_seen = datetime.utcnow()
    session.add(row)
    session.commit()
    _audit_event(
        session=session,
        user_id=user_id,
        session_id=session_id,
        event_type="session_revoked",
        status="success",
        detail="session manually revoked",
    )
    return True


def elevate_session_with_totp(*, session: Session, user_id: str, session_id: str, otp_code: str) -> bool:
    ui_session = (
        session.query(db.UISession)
        .filter(db.UISession.user_id == user_id, db.UISession.session_id == session_id)
        .first()
    )
    if ui_session is None or int(ui_session.is_active or 0) != 1:
        return False

    user_auth = _ensure_user_auth(session, user_id)
    if not verify_totp(str(user_auth.totp_secret), otp_code):
        _audit_event(
            session=session,
            user_id=user_id,
            session_id=session_id,
            event_type="mfa_verify",
            status="failed",
            detail="invalid otp",
        )
        return False

    ui_session.elevated_until = datetime.utcnow() + timedelta(seconds=int(settings.zt_step_up_ttl_seconds))
    ui_session.last_seen = datetime.utcnow()
    session.add(ui_session)
    session.commit()
    _audit_event(
        session=session,
        user_id=user_id,
        session_id=session_id,
        event_type="mfa_verify",
        status="success",
        detail="session elevated by otp",
    )
    return True
