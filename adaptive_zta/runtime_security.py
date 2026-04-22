from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from fastapi import HTTPException, Request, status

from runtime_settings import settings
from zero_trust_auth import decode_access_token


class JWTAuthorizer:
    def __init__(self) -> None:
        self._exempt = settings.jwt_exempt_paths()

    def should_skip(self, path: str) -> bool:
        if path in self._exempt:
            return True
        return (
            path.startswith("/static/")
            or path.startswith("/ws/")
            or path.startswith("/ui")
            or path in {"/", "/login", "/register", "/soc/dashboard"}
            or path in {
                "/dashboard/summary",
                "/dashboard/entities",
                "/policy/status",
                "/policy/rules",
                "/policy/rules/add",
                "/soc/timeline",
                "/soc/alerts",
                "/soc/tenants/comparison",
                "/soc/decisions/distribution",
                "/api/iam/update_role",
            }
            or path.startswith("/soc/decision/")
            or path.startswith("/api/decision/")
            or path in {"/api/iam/login", "/api/iam/register"}
            or path == "/auth/session/start"
            or path == "/favicon.ico"
        )

    def validate(self, request: Request) -> None:
        if not settings.jwt_enabled or self.should_skip(request.url.path):
            return

        if settings.jwt_require_https_for_auth and not settings.auth_allow_insecure_dev:
            scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
            if scheme != "https":
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="https required for authenticated routes")

        if settings.jwt_algorithm.upper().strip() != "RS256":
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="JWT_ALGORITHM must be RS256")

        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")

        token = header.removeprefix("Bearer ").strip()
        decode_access_token(token)


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._exempt_paths = {
            "/",
            "/login",
            "/register",
            "/request-iam",
            "/request-an-iam",
            "/signup",
            "/sign-up",
            "/healthz",
            "/favicon.ico",
            "/dashboard/summary",
            "/dashboard/entities",
            "/soc/tenants/comparison",
            "/soc/decisions/distribution",
            "/soc/timeline",
            "/soc/alerts",
            "/ingest",
            "/ingest-batch",
        }

    def _client_key(self, request: Request) -> str:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",", 1)[0].strip()
        return request.client.host if request.client else "unknown"

    def allow(self, request: Request) -> Optional[int]:
        if not settings.rate_limit_enabled:
            return None

        path = request.url.path
        if path in self._exempt_paths or path.startswith(("/static/", "/ui")):
            return None

        now = time.time()
        window = float(settings.rate_limit_window_seconds)
        max_requests = settings.rate_limit_requests
        key = self._client_key(request)
        buf = self._hits[key]

        while buf and (now - buf[0]) > window:
            buf.popleft()

        if len(buf) >= max_requests:
            retry_after = int(window - (now - buf[0])) if buf else int(window)
            return max(1, retry_after)

        buf.append(now)
        return None


authorizer = JWTAuthorizer()
rate_limiter = InMemoryRateLimiter()
