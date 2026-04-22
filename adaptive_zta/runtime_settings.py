import os
from dataclasses import dataclass
from typing import Set

from dotenv import load_dotenv


load_dotenv()


def _as_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _as_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _as_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_host: str = os.getenv("APP_HOST", "0.0.0.0")
    app_port: int = _as_int("APP_PORT", 8000)

    target_api: str = os.getenv("TARGET_API", "http://localhost:9000")
    enable_phase5_gateway: bool = _as_bool("ENABLE_PHASE5_GATEWAY", True)

    jwt_enabled: bool = _as_bool("JWT_ENABLED", True)
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "RS256")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "argent-sentinel")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "argent-clients")
    jwt_access_token_minutes: int = _as_int("JWT_ACCESS_TOKEN_MINUTES", 10)
    jwt_private_key_pem: str = os.getenv("JWT_PRIVATE_KEY_PEM", "").strip()
    jwt_public_key_pem: str = os.getenv("JWT_PUBLIC_KEY_PEM", "").strip()
    jwt_exempt_paths_raw: str = os.getenv("JWT_EXEMPT_PATHS", "/,/healthz,/metrics,/docs,/openapi.json")
    jwt_jwks_url: str = os.getenv("JWT_JWKS_URL", "").strip()
    jwt_require_https_for_auth: bool = _as_bool("JWT_REQUIRE_HTTPS_FOR_AUTH", True)
    auth_allow_insecure_dev: bool = _as_bool("AUTH_ALLOW_INSECURE_DEV", False)

    zt_low_trust_threshold: float = _as_float("ZT_LOW_TRUST_THRESHOLD", 45.0)
    zt_medium_trust_threshold: float = _as_float("ZT_MEDIUM_TRUST_THRESHOLD", 65.0)
    zt_high_trust_threshold: float = _as_float("ZT_HIGH_TRUST_THRESHOLD", 85.0)
    zt_deny_trust_threshold: float = _as_float("ZT_DENY_TRUST_THRESHOLD", 25.0)
    zt_session_idle_timeout_seconds: int = _as_int("ZT_SESSION_IDLE_TIMEOUT_SECONDS", 1800)
    zt_step_up_ttl_seconds: int = _as_int("ZT_STEP_UP_TTL_SECONDS", 600)
    zt_totp_step_seconds: int = _as_int("ZT_TOTP_STEP_SECONDS", 30)
    zt_totp_allowed_drift: int = _as_int("ZT_TOTP_ALLOWED_DRIFT", 1)

    rate_limit_enabled: bool = _as_bool("RATE_LIMIT_ENABLED", True)
    rate_limit_requests: int = _as_int("RATE_LIMIT_REQUESTS", 120)
    rate_limit_window_seconds: int = _as_int("RATE_LIMIT_WINDOW_SECONDS", 60)

    redis_enabled: bool = _as_bool("REDIS_ENABLED", False)
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    state_key_scope: str = os.getenv("STATE_KEY_SCOPE", "entity").strip().lower()
    state_ttl_normal_seconds: int = _as_int("STATE_TTL_NORMAL_SECONDS", 86400)
    state_ttl_high_risk_seconds: int = _as_int("STATE_TTL_HIGH_RISK_SECONDS", 604800)

    prom_metrics_enabled: bool = _as_bool("PROM_METRICS_ENABLED", True)
    force_https: bool = _as_bool("FORCE_HTTPS", False)

    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format: str = os.getenv("LOG_FORMAT", "json").lower()

    cloud_actions_enabled: bool = _as_bool("CLOUD_ACTIONS_ENABLED", False)
    aws_cloud_actions_enabled: bool = _as_bool("AWS_CLOUD_ACTIONS_ENABLED", False)
    aws_lambda_target: str = os.getenv("AWS_LAMBDA_TARGET", "").strip()
    azure_cloud_actions_enabled: bool = _as_bool("AZURE_CLOUD_ACTIONS_ENABLED", False)
    azure_tag_scope: str = os.getenv("AZURE_TAG_SCOPE", "").strip()
    gcp_cloud_actions_enabled: bool = _as_bool("GCP_CLOUD_ACTIONS_ENABLED", False)
    gcp_project_id: str = os.getenv("GCP_PROJECT_ID", "").strip()
    cloud_actions_allow_mutations: bool = _as_bool("CLOUD_ACTIONS_ALLOW_MUTATIONS", False)
    cloud_actions_timeout_seconds: int = _as_int("CLOUD_ACTIONS_TIMEOUT_SECONDS", 20)
    cloud_feature_manifest_urls_raw: str = os.getenv("CLOUD_FEATURE_MANIFEST_URLS", "").strip()
    cloud_feature_refresh_seconds: int = _as_int("CLOUD_FEATURE_REFRESH_SECONDS", 30)

    gateway_allow_threshold: float = _as_float("GATEWAY_ALLOW_THRESHOLD", 55.0)
    gateway_isolate_threshold: float = _as_float("GATEWAY_ISOLATE_THRESHOLD", 40.0)

    def jwt_exempt_paths(self) -> Set[str]:
        return {path.strip() for path in self.jwt_exempt_paths_raw.split(",") if path.strip()}

    def cloud_feature_manifest_urls(self) -> list[str]:
        if not self.cloud_feature_manifest_urls_raw:
            return []
        return [u.strip() for u in self.cloud_feature_manifest_urls_raw.split(",") if u.strip()]


settings = Settings()
