from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict
from typing import Callable

from .identity import principal_id
from .types import EntityState

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None


class RedisUnavailableError(RuntimeError):
    pass


class RedisEntityStateStore:
    """Redis-backed entity state with optimistic locking and in-memory fallback."""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        redis_enabled: bool = False,
        normal_ttl_seconds: int = 86400,
        high_risk_ttl_seconds: int = 604800,
        key_scope: str = "entity",
    ) -> None:
        self.redis_enabled = bool(redis_enabled and redis is not None)
        self.normal_ttl_seconds = normal_ttl_seconds
        self.high_risk_ttl_seconds = high_risk_ttl_seconds
        self.key_scope = key_scope.strip().lower()
        self.redis_error_count = 0
        self.redis_ops_count = 0

        self._mem_lock = threading.Lock()
        self._mem_state: dict[str, tuple[EntityState, float]] = {}

        self._redis = None
        if self.redis_enabled:
            self._redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def state_key(self, entity_id: str) -> str:
        if self.key_scope == "principal":
            return f"sentinel:state:principal:{principal_id(entity_id)}"
        return f"sentinel:state:entity:{entity_id}"

    @classmethod
    def from_env(cls) -> "RedisEntityStateStore":
        redis_enabled = os.getenv("REDIS_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        key_scope = os.getenv("STATE_KEY_SCOPE", "entity")
        try:
            normal_ttl = int(os.getenv("STATE_TTL_NORMAL_SECONDS", "86400"))
        except ValueError:
            normal_ttl = 86400
        try:
            high_risk_ttl = int(os.getenv("STATE_TTL_HIGH_RISK_SECONDS", "604800"))
        except ValueError:
            high_risk_ttl = 604800
        return cls(
            redis_url=redis_url,
            redis_enabled=redis_enabled,
            normal_ttl_seconds=normal_ttl,
            high_risk_ttl_seconds=high_risk_ttl,
            key_scope=key_scope,
        )

    def startup_health_check(self) -> None:
        if not self.redis_enabled:
            return
        try:
            self.redis_ops_count += 1
            if self._redis is None or not self._redis.ping():
                raise RedisUnavailableError("redis health check failed")
        except Exception as exc:
            self.redis_error_count += 1
            raise RedisUnavailableError(str(exc)) from exc

    def migrate_from_memory(self, previous: dict[str, EntityState]) -> None:
        now = time.time()
        for entity_id, state in previous.items():
            self.set_entity_state(entity_id, state, now_ts=now)

    def _effective_ttl(self, state: EntityState) -> int:
        return self.high_risk_ttl_seconds if state.escalation_level >= 2 else self.normal_ttl_seconds

    def get_entity_state(self, entity_id: str, now_ts: float = None) -> EntityState:
        now = now_ts if now_ts is not None else time.time()
        key = self.state_key(entity_id)

        if self.redis_enabled:
            try:
                self.redis_ops_count += 1
                assert self._redis is not None
                raw = self._redis.get(key)
                if not raw:
                    return EntityState.default(ts=now)
                return EntityState(**json.loads(raw))
            except Exception:
                self.redis_error_count += 1

        with self._mem_lock:
            row = self._mem_state.get(key)
            if row is None:
                return EntityState.default(ts=now)
            state, expires_at = row
            if now > expires_at:
                del self._mem_state[key]
                return EntityState.default(ts=now)
            return state

    def update_entity_state(
        self,
        entity_id: str,
        updater: Callable[[EntityState], EntityState],
        now_ts: float = None,
    ) -> EntityState:
        now = now_ts if now_ts is not None else time.time()
        key = self.state_key(entity_id)

        if self.redis_enabled:
            try:
                assert self._redis is not None
                with self._redis.pipeline() as pipe:
                    while True:
                        try:
                            self.redis_ops_count += 1
                            pipe.watch(key)
                            raw = pipe.get(key)
                            current = EntityState.default(ts=now) if not raw else EntityState(**json.loads(raw))
                            updated = updater(current)
                            ttl = self._effective_ttl(updated)
                            pipe.multi()
                            pipe.setex(key, ttl, json.dumps(asdict(updated)))
                            pipe.execute()
                            return updated
                        except redis.WatchError:  # type: ignore[attr-defined]
                            continue
                        finally:
                            pipe.reset()
            except Exception:
                self.redis_error_count += 1

        with self._mem_lock:
            row = self._mem_state.get(key)
            if row is None:
                old_state = EntityState.default(ts=now)
            else:
                state, expires_at = row
                old_state = EntityState.default(ts=now) if now > expires_at else state
            new_state = updater(old_state)
            self._mem_state[key] = (new_state, now + self._effective_ttl(new_state))
            return new_state

    def set_entity_state(self, entity_id: str, state: EntityState, now_ts: float = None) -> None:
        now = now_ts if now_ts is not None else time.time()

        def apply(_: EntityState) -> EntityState:
            return state

        self.update_entity_state(entity_id, apply, now_ts=now)

    def redis_error_rate(self) -> float:
        if self.redis_ops_count == 0:
            return 0.0
        return self.redis_error_count / self.redis_ops_count
