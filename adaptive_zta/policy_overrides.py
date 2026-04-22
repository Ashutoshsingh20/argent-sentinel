"""
Argent Sentinel — Policy Override Store (Phase A)
=================================================
Time-bounded, persisted overrides that sit above the rule engine.

Override types:
  FORCE_ISOLATE    — entity always ISOLATEs until expiry
  FORCE_ALLOW      — entity is whitelisted until expiry
  FORCE_RATE_LIMIT — entity is capped at RATE_LIMIT until expiry
  SKIP_RULES       — named rule IDs skipped for this entity
  CUSTOM_THRESHOLD — per-entity trust threshold override

Overrides are:
  - Persisted to SQLite (survive restarts)
  - Held in memory for zero-latency lookup on hot path
  - Auto-expired in the background
  - Audited (every override application emits an audit record)
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

OverrideType = Literal[
    "FORCE_ISOLATE",
    "FORCE_ALLOW",
    "FORCE_RATE_LIMIT",
    "SKIP_RULES",
    "CUSTOM_THRESHOLD",
]


@dataclass
class PolicyOverride:
    override_id: str
    tenant_id: str
    entity_id: str
    override_type: OverrideType
    created_at: float
    expires_at: float
    operator_id: str
    reason: str
    # For SKIP_RULES: which rule IDs to skip
    skip_rule_ids: List[str] = field(default_factory=list)
    # For CUSTOM_THRESHOLD: {"allow": float, "rate_limit": float, "isolate": float}
    threshold_overrides: Dict[str, float] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return time.time() < self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "override_id": self.override_id,
            "tenant_id": self.tenant_id,
            "entity_id": self.entity_id,
            "override_type": self.override_type,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "operator_id": self.operator_id,
            "reason": self.reason,
            "skip_rule_ids": self.skip_rule_ids,
            "threshold_overrides": self.threshold_overrides,
            "active": self.is_active,
            "ttl_remaining_seconds": max(0.0, self.expires_at - time.time()),
        }


@dataclass
class OverrideResult:
    """Returned when an override applies to a policy decision."""
    override_id: str
    override_type: OverrideType
    forced_action: Optional[str]   # None if type is SKIP_RULES or CUSTOM_THRESHOLD
    skip_rule_ids: List[str]
    threshold_overrides: Dict[str, float]
    expires_at: float


class PolicyOverrideStore:
    """
    In-memory override store backed by SQLite persistence.

    Hot path: single dict lookup, O(1).
    Background: expiry sweeper every 60s.
    """

    def __init__(self, db_path: str = "outputs/policy_overrides.db") -> None:
        self._lock = threading.RLock()
        # Structure: {(tenant_id, entity_id): [PolicyOverride, ...]}
        self._store: Dict[tuple, List[PolicyOverride]] = {}
        self._db_path = db_path
        self._init_db()
        self._load_from_db()

        self._sweeper = threading.Thread(target=self._expiry_sweep, daemon=True, name="override-sweeper")
        self._sweeper.start()

    # ── DB Layer ─────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        import sqlite3
        import os
        os.makedirs(os.path.dirname(self._db_path) if os.path.dirname(self._db_path) else ".", exist_ok=True)
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS policy_overrides (
                        override_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        override_type TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        operator_id TEXT,
                        reason TEXT,
                        skip_rule_ids TEXT DEFAULT '[]',
                        threshold_overrides TEXT DEFAULT '{}'
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ov_entity ON policy_overrides(tenant_id, entity_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ov_expires ON policy_overrides(expires_at)")
                conn.commit()
        except Exception as exc:
            logger.warning("Override DB init failed (will use in-memory only)", extra={"error": str(exc)})

    def _load_from_db(self) -> None:
        import sqlite3, json
        try:
            with sqlite3.connect(self._db_path) as conn:
                rows = conn.execute(
                    "SELECT * FROM policy_overrides WHERE expires_at > ?",
                    (time.time(),)
                ).fetchall()
            for row in rows:
                ov = PolicyOverride(
                    override_id=row[0],
                    tenant_id=row[1],
                    entity_id=row[2],
                    override_type=row[3],
                    created_at=row[4],
                    expires_at=row[5],
                    operator_id=row[6] or "",
                    reason=row[7] or "",
                    skip_rule_ids=json.loads(row[8] or "[]"),
                    threshold_overrides=json.loads(row[9] or "{}"),
                )
                key = (ov.tenant_id, ov.entity_id)
                with self._lock:
                    self._store.setdefault(key, []).append(ov)
            logger.info("Policy overrides restored from DB", extra={"count": len(rows)})
        except Exception as exc:
            logger.warning("Could not restore overrides from DB", extra={"error": str(exc)})

    def _persist(self, ov: PolicyOverride) -> None:
        import sqlite3, json
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO policy_overrides
                       (override_id, tenant_id, entity_id, override_type,
                        created_at, expires_at, operator_id, reason,
                        skip_rule_ids, threshold_overrides)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        ov.override_id, ov.tenant_id, ov.entity_id,
                        ov.override_type, ov.created_at, ov.expires_at,
                        ov.operator_id, ov.reason,
                        json.dumps(ov.skip_rule_ids),
                        json.dumps(ov.threshold_overrides),
                    )
                )
                conn.commit()
        except Exception as exc:
            logger.warning("Override persistence failed", extra={"error": str(exc)})

    def _delete_from_db(self, override_id: str) -> None:
        import sqlite3
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("DELETE FROM policy_overrides WHERE override_id = ?", (override_id,))
                conn.commit()
        except Exception:
            pass

    # ── CRUD ─────────────────────────────────────────────────────────────

    def create(
        self,
        tenant_id: str,
        entity_id: str,
        override_type: OverrideType,
        duration_seconds: float,
        operator_id: str = "system",
        reason: str = "",
        skip_rule_ids: Optional[List[str]] = None,
        threshold_overrides: Optional[Dict[str, float]] = None,
    ) -> PolicyOverride:
        now = time.time()
        ov = PolicyOverride(
            override_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            entity_id=entity_id,
            override_type=override_type,
            created_at=now,
            expires_at=now + duration_seconds,
            operator_id=operator_id,
            reason=reason,
            skip_rule_ids=skip_rule_ids or [],
            threshold_overrides=threshold_overrides or {},
        )
        key = (tenant_id, entity_id)
        with self._lock:
            self._store.setdefault(key, []).append(ov)
        self._persist(ov)
        logger.info(
            "Policy override created",
            extra={
                "override_id": ov.override_id,
                "entity_id": entity_id,
                "tenant_id": tenant_id,
                "type": override_type,
                "expires_in_s": duration_seconds,
            },
        )
        return ov

    def cancel(self, override_id: str, tenant_id: str) -> bool:
        """Cancel an active override by ID. Returns True if found and removed."""
        with self._lock:
            for key, overrides in self._store.items():
                for ov in overrides:
                    if ov.override_id == override_id and ov.tenant_id == tenant_id:
                        overrides.remove(ov)
                        self._delete_from_db(override_id)
                        logger.info("Override cancelled", extra={"override_id": override_id})
                        return True
        return False

    def get_active_for_entity(
        self, tenant_id: str, entity_id: str
    ) -> List[PolicyOverride]:
        key = (tenant_id, entity_id)
        with self._lock:
            overrides = self._store.get(key, [])
            return [o for o in overrides if o.is_active]

    def list_all(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            result = []
            for overrides in self._store.values():
                for ov in overrides:
                    if ov.is_active:
                        if tenant_id is None or ov.tenant_id == tenant_id:
                            result.append(ov.to_dict())
            return sorted(result, key=lambda x: x["expires_at"])

    # ── Hot-path resolution ──────────────────────────────────────────────

    def resolve(
        self, tenant_id: str, entity_id: str
    ) -> Optional[OverrideResult]:
        """
        Called on every request. Returns the highest-priority applicable override,
        or None if no override is active.

        Priority: FORCE_ISOLATE > FORCE_RATE_LIMIT > FORCE_ALLOW > SKIP_RULES > CUSTOM_THRESHOLD
        """
        active = self.get_active_for_entity(tenant_id, entity_id)
        if not active:
            return None

        _OVERRIDE_PRIORITY = {
            "FORCE_ISOLATE": 5,
            "FORCE_RATE_LIMIT": 4,
            "FORCE_ALLOW": 3,
            "SKIP_RULES": 2,
            "CUSTOM_THRESHOLD": 1,
        }
        best = max(active, key=lambda o: _OVERRIDE_PRIORITY.get(o.override_type, 0))

        forced_action_map = {
            "FORCE_ISOLATE": "ISOLATE",
            "FORCE_RATE_LIMIT": "RATE_LIMIT",
            "FORCE_ALLOW": "ALLOW",
        }
        return OverrideResult(
            override_id=best.override_id,
            override_type=best.override_type,
            forced_action=forced_action_map.get(best.override_type),
            skip_rule_ids=best.skip_rule_ids,
            threshold_overrides=best.threshold_overrides,
            expires_at=best.expires_at,
        )

    # ── Background expiry ────────────────────────────────────────────────

    def _expiry_sweep(self) -> None:
        while True:
            try:
                expired_ids: List[str] = []
                now = time.time()
                with self._lock:
                    for key in list(self._store.keys()):
                        before = self._store[key]
                        active = [o for o in before if o.is_active]
                        expired = [o for o in before if not o.is_active]
                        self._store[key] = active
                        if not active:
                            del self._store[key]
                        for o in expired:
                            expired_ids.append(o.override_id)
                if expired_ids:
                    import sqlite3
                    with sqlite3.connect(self._db_path) as conn:
                        conn.execute(
                            f"DELETE FROM policy_overrides WHERE override_id IN ({','.join('?' * len(expired_ids))})",
                            expired_ids,
                        )
                        conn.commit()
                    logger.info("Expired overrides purged", extra={"count": len(expired_ids)})
            except Exception as exc:
                logger.warning("Override expiry sweep failed", extra={"error": str(exc)})
            time.sleep(60)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_override_store: Optional[PolicyOverrideStore] = None
_override_lock = threading.Lock()


def get_override_store() -> PolicyOverrideStore:
    global _override_store
    if _override_store is None:
        with _override_lock:
            if _override_store is None:
                _override_store = PolicyOverrideStore()
    return _override_store
