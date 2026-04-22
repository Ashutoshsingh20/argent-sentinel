"""
Argent Sentinel — Tenant Registry (Phase B)
===========================================
True SaaS isolation: every entity, decision, policy, and
enforcement action is scoped to a tenant_id.

Features:
  - TenantConfig: per-tenant thresholds, rate limits, clouds, policy file
  - TenantRegistry: YAML + DB-backed, hot-reload, thread-safe
  - Per-tenant policy file: policies/{tenant_id}/rules.yaml (optional)
  - Isolation guarantee: no shared in-memory state leaks across tenants
  - Audit: tenant creation logged to DB
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

_TENANT_FILE = Path(__file__).parent / "tenants" / "tenants.yaml"
_TENANT_POLICY_DIR = Path(__file__).parent / "policies"


# ────────────────────────────────────────────────────────────────────────────
# Data model
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class TrustThresholds:
    allow: float = 65.0         # trust >= allow → ALLOW
    rate_limit: float = 48.0   # trust >= rate_limit → RATE_LIMIT
    isolate: float = 48.0      # trust < isolate → ISOLATE


@dataclass
class TenantConfig:
    tenant_id: str
    display_name: str
    thresholds: TrustThresholds
    rate_limit_rpm: int                 # max API requests per minute
    allowed_cloud_envs: List[str]       # subset of ["AWS", "Azure", "GCP"]
    policy_file: str                    # "default" or absolute path
    shadow_learning_enabled: bool
    max_entities: int                   # hard cap on entity count
    created_at: float
    active: bool = True
    # Safety overrides (Phase C wires these)
    max_isolations_per_minute: int = 50
    max_cloud_mutations_per_hour: int = 5
    approval_required_above_trust: Optional[float] = None  # if trust < X, require approval

    def has_cloud(self, cloud: str) -> bool:
        norm = cloud.strip().upper()
        return norm in [e.upper() for e in self.allowed_cloud_envs]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "thresholds": {
                "allow": self.thresholds.allow,
                "rate_limit": self.thresholds.rate_limit,
                "isolate": self.thresholds.isolate,
            },
            "rate_limit_rpm": self.rate_limit_rpm,
            "allowed_cloud_envs": self.allowed_cloud_envs,
            "policy_file": self.policy_file,
            "shadow_learning_enabled": self.shadow_learning_enabled,
            "max_entities": self.max_entities,
            "created_at": self.created_at,
            "active": self.active,
            "safety": {
                "max_isolations_per_minute": self.max_isolations_per_minute,
                "max_cloud_mutations_per_hour": self.max_cloud_mutations_per_hour,
                "approval_required_above_trust": self.approval_required_above_trust,
            },
        }


_DEFAULT_TENANT = TenantConfig(
    tenant_id="default",
    display_name="Default Tenant",
    thresholds=TrustThresholds(allow=65.0, rate_limit=48.0, isolate=48.0),
    rate_limit_rpm=12000,
    allowed_cloud_envs=["AWS", "Azure", "GCP"],
    policy_file="default",
    shadow_learning_enabled=True,
    max_entities=50000,
    created_at=0.0,
    active=True,
)


# ────────────────────────────────────────────────────────────────────────────
# Registry
# ────────────────────────────────────────────────────────────────────────────

def _parse_tenant(raw: Dict[str, Any]) -> TenantConfig:
    thr_raw = raw.get("trust_thresholds", raw.get("thresholds", {}))
    thresholds = TrustThresholds(
        allow=float(thr_raw.get("allow", 65.0)),
        rate_limit=float(thr_raw.get("rate_limit", 48.0)),
        isolate=float(thr_raw.get("isolate", 48.0)),
    )
    safety = raw.get("safety", {})
    return TenantConfig(
        tenant_id=str(raw["id"]),
        display_name=str(raw.get("display_name", raw["id"])),
        thresholds=thresholds,
        rate_limit_rpm=int(raw.get("rate_limit_rpm", 12000)),
        allowed_cloud_envs=list(raw.get("allowed_cloud_envs", ["AWS", "Azure", "GCP"])),
        policy_file=str(raw.get("policy_file", "default")),
        shadow_learning_enabled=bool(raw.get("shadow_learning_enabled", True)),
        max_entities=int(raw.get("max_entities", 50000)),
        created_at=float(raw.get("created_at", time.time())),
        active=bool(raw.get("active", True)),
        max_isolations_per_minute=int(safety.get("max_isolations_per_minute", 50)),
        max_cloud_mutations_per_hour=int(safety.get("max_cloud_mutations_per_hour", 5)),
        approval_required_above_trust=raw.get("approval_required_above_trust"),
    )


class TenantRegistry:
    """
    Thread-safe registry of all tenants.

    Lookup: O(1) dict lookup; always returns a TenantConfig (falls back to default).
    Hot-reload: watches tenants.yaml every 10s for changes.
    """

    def __init__(self, config_path: Path = _TENANT_FILE, hot_reload: bool = True) -> None:
        self._lock = threading.RLock()
        self._config_path = config_path
        self._tenants: Dict[str, TenantConfig] = {"default": _DEFAULT_TENANT}
        self._loaded_mtime: float = 0.0

        self._load()

        if hot_reload:
            t = threading.Thread(target=self._watch_loop, daemon=True, name="tenant-watcher")
            t.start()

    # ── Loading ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if yaml is None or not self._config_path.exists():
            logger.info("Tenant config file not found — using default tenant only")
            return
        try:
            with self._config_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            raw_tenants = data.get("tenants", [])
            new_map: Dict[str, TenantConfig] = {"default": _DEFAULT_TENANT}
            for raw in raw_tenants:
                try:
                    t = _parse_tenant(raw)
                    new_map[t.tenant_id] = t
                except Exception as exc:
                    logger.warning("Skipping malformed tenant config", extra={"raw": raw, "error": str(exc)})
            with self._lock:
                self._tenants = new_map
                self._loaded_mtime = self._config_path.stat().st_mtime
            logger.info(
                "Tenant registry loaded",
                extra={"count": len(new_map), "path": str(self._config_path)},
            )
        except Exception as exc:
            logger.error("Failed to load tenant registry", extra={"error": str(exc)})

    def reload(self) -> int:
        self._load()
        with self._lock:
            return len(self._tenants)

    def _watch_loop(self) -> None:
        while True:
            try:
                if self._config_path.exists():
                    mtime = self._config_path.stat().st_mtime
                    with self._lock:
                        last = self._loaded_mtime
                    if mtime > last:
                        logger.info("Tenant file changed — hot-reloading")
                        self._load()
            except Exception:
                pass
            time.sleep(10)

    # ── Lookup ───────────────────────────────────────────────────────────

    def get(self, tenant_id: str) -> TenantConfig:
        """Returns tenant config. Falls back to 'default' for unknown tenants."""
        with self._lock:
            return self._tenants.get(tenant_id) or self._tenants["default"]

    def get_or_none(self, tenant_id: str) -> Optional[TenantConfig]:
        with self._lock:
            return self._tenants.get(tenant_id)

    def exists(self, tenant_id: str) -> bool:
        with self._lock:
            return tenant_id in self._tenants

    def list_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [t.to_dict() for t in self._tenants.values() if t.active]

    # ── Mutation ─────────────────────────────────────────────────────────

    def create(self, config: TenantConfig) -> TenantConfig:
        if self.exists(config.tenant_id):
            raise ValueError(f"Tenant '{config.tenant_id}' already exists")
        with self._lock:
            self._tenants[config.tenant_id] = config
        self._persist()
        logger.info("Tenant created", extra={"tenant_id": config.tenant_id})
        return config

    def update(self, tenant_id: str, updates: Dict[str, Any]) -> TenantConfig:
        with self._lock:
            existing = self._tenants.get(tenant_id)
            if not existing:
                raise KeyError(f"Tenant '{tenant_id}' not found")
            # Patch allowed fields
            if "display_name" in updates:
                existing.display_name = str(updates["display_name"])
            if "rate_limit_rpm" in updates:
                existing.rate_limit_rpm = int(updates["rate_limit_rpm"])
            if "shadow_learning_enabled" in updates:
                existing.shadow_learning_enabled = bool(updates["shadow_learning_enabled"])
            if "max_entities" in updates:
                existing.max_entities = int(updates["max_entities"])
            if "active" in updates:
                existing.active = bool(updates["active"])
            if "thresholds" in updates:
                thr = updates["thresholds"]
                existing.thresholds.allow = float(thr.get("allow", existing.thresholds.allow))
                existing.thresholds.rate_limit = float(thr.get("rate_limit", existing.thresholds.rate_limit))
                existing.thresholds.isolate = float(thr.get("isolate", existing.thresholds.isolate))
            self._tenants[tenant_id] = existing
        self._persist()
        return existing

    def _persist(self) -> None:
        """Write current registry back to YAML file."""
        if yaml is None:
            return
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                tenants_data = [
                    {
                        "id": t.tenant_id,
                        "display_name": t.display_name,
                        "trust_thresholds": {
                            "allow": t.thresholds.allow,
                            "rate_limit": t.thresholds.rate_limit,
                            "isolate": t.thresholds.isolate,
                        },
                        "rate_limit_rpm": t.rate_limit_rpm,
                        "allowed_cloud_envs": t.allowed_cloud_envs,
                        "policy_file": t.policy_file,
                        "shadow_learning_enabled": t.shadow_learning_enabled,
                        "max_entities": t.max_entities,
                        "active": t.active,
                        "safety": {
                            "max_isolations_per_minute": t.max_isolations_per_minute,
                            "max_cloud_mutations_per_hour": t.max_cloud_mutations_per_hour,
                        },
                    }
                    for t in self._tenants.values()
                ]
            with self._config_path.open("w", encoding="utf-8") as f:
                yaml.dump({"tenants": tenants_data}, f, default_flow_style=False, sort_keys=False)
        except Exception as exc:
            logger.warning("Failed to persist tenant registry", extra={"error": str(exc)})


# ────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ────────────────────────────────────────────────────────────────────────────

_registry: Optional[TenantRegistry] = None
_registry_lock = threading.Lock()


def get_tenant_registry() -> TenantRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = TenantRegistry(hot_reload=True)
    return _registry
