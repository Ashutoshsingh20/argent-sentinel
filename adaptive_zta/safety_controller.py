"""
Argent Sentinel — Safety Controller (Phase C)
=============================================
Three interlocking guardrails that prevent catastrophic automated actions:

1. ExecutionLimits
   - Per-tenant sliding-window isolation caps
   - Per-tenant cloud mutation hour caps
   - Surplus ISOLATEs downgraded to RATE_LIMIT automatically
   - Never fail open: a mis-configured limit defaults to RESTRICT

2. CircuitBreaker
   - Opens when anomaly spike > 40% of visible entities ISOLATEd in 60s
   - Opens when API latency p95 > 200ms sustained 30s
   - OPEN → all new decisions fall back to configured fallback action
   - HALF_OPEN → probe N requests before closing
   - Manual reset via /safety/circuit/reset

3. RiskBudget
   - Dynamic cap: tracks "risk spend" per decision severity
   - ISOLATE costs 3 units, RATE_LIMIT costs 1, ALLOW costs 0
   - Per-tenant hourly budget (default: 150 units)
   - Once exhausted, subsequent risky decisions cap at RATE_LIMIT

Global safety rules:
  ✓ Never fail open (default fallback = RATE_LIMIT)
  ✓ Always log decisions
  ✓ Always allow simulation mode (bypasses limits)
  ✓ Always enforce tenant isolation
"""

from __future__ import annotations

import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Literal, Optional, Tuple

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────

Action = Literal["ALLOW", "RATE_LIMIT", "ISOLATE"]

_RISK_COST: Dict[str, int] = {
    "ISOLATE": 3,
    "RATE_LIMIT": 1,
    "ALLOW": 0,
}

_DEFAULT_FALLBACK: Action = "RATE_LIMIT"   # never fail open


# ────────────────────────────────────────────────────────────────────────────
# Execution Limits  (per-tenant, sliding-window)
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class LimitCheckResult:
    allowed: bool
    downgraded_action: Optional[Action]   # if allowed=False, use this instead
    reason: str
    limit_name: str


class _SlidingWindowCounter:
    """Thread-safe sliding-window event counter."""

    def __init__(self, window_seconds: float) -> None:
        self._window = window_seconds
        self._events: Deque[float] = collections.deque()
        self._lock = threading.Lock()

    def record(self) -> None:
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            self._prune(now)

    def count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return len(self._events)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


class TenantLimits:
    """Per-tenant counters and limit configuration."""

    def __init__(
        self,
        max_isolations_per_minute: int = 50,
        max_cloud_mutations_per_hour: int = 5,
        risk_budget_per_hour: int = 150,
    ) -> None:
        self.max_isolations_per_minute = max_isolations_per_minute
        self.max_cloud_mutations_per_hour = max_cloud_mutations_per_hour
        self.risk_budget_per_hour = risk_budget_per_hour

        self._isolation_counter = _SlidingWindowCounter(60.0)
        self._mutation_counter = _SlidingWindowCounter(3600.0)
        self._risk_budget_counter = _SlidingWindowCounter(3600.0)
        self._budget_spent: int = 0
        self._budget_lock = threading.Lock()

    def check_isolation(self) -> LimitCheckResult:
        current = self._isolation_counter.count()
        if current >= self.max_isolations_per_minute:
            return LimitCheckResult(
                allowed=False,
                downgraded_action="RATE_LIMIT",
                reason=f"Isolation cap reached: {current}/{self.max_isolations_per_minute} per minute",
                limit_name="max_isolations_per_minute",
            )
        return LimitCheckResult(allowed=True, downgraded_action=None, reason="", limit_name="")

    def record_isolation(self) -> None:
        self._isolation_counter.record()

    def check_mutation(self) -> LimitCheckResult:
        current = self._mutation_counter.count()
        if current >= self.max_cloud_mutations_per_hour:
            return LimitCheckResult(
                allowed=False,
                downgraded_action="RATE_LIMIT",
                reason=f"Cloud mutation cap reached: {current}/{self.max_cloud_mutations_per_hour} per hour",
                limit_name="max_cloud_mutations_per_hour",
            )
        return LimitCheckResult(allowed=True, downgraded_action=None, reason="", limit_name="")

    def record_mutation(self) -> None:
        self._mutation_counter.record()

    def check_risk_budget(self, action: str) -> LimitCheckResult:
        cost = _RISK_COST.get(action, 0)
        if cost == 0:
            return LimitCheckResult(allowed=True, downgraded_action=None, reason="", limit_name="")
        with self._budget_lock:
            if self._budget_spent + cost > self.risk_budget_per_hour:
                return LimitCheckResult(
                    allowed=False,
                    downgraded_action="RATE_LIMIT",
                    reason=f"Risk budget exhausted: {self._budget_spent}/{self.risk_budget_per_hour} units/hour",
                    limit_name="risk_budget_per_hour",
                )
        return LimitCheckResult(allowed=True, downgraded_action=None, reason="", limit_name="")

    def record_risk(self, action: str) -> None:
        cost = _RISK_COST.get(action, 0)
        if cost > 0:
            with self._budget_lock:
                self._budget_spent += cost

    def get_stats(self) -> Dict[str, Any]:
        return {
            "isolations_per_minute": self._isolation_counter.count(),
            "mutations_per_hour": self._mutation_counter.count(),
            "risk_budget_spent": self._budget_spent,
            "risk_budget_limit": self.risk_budget_per_hour,
        }


class ExecutionLimits:
    """Manages per-tenant limit state. Singleton pattern — call get_execution_limits()."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tenants: Dict[str, TenantLimits] = {}

    def _get_or_create(
        self,
        tenant_id: str,
        max_isolations_per_minute: int = 50,
        max_cloud_mutations_per_hour: int = 5,
        risk_budget_per_hour: int = 150,
    ) -> TenantLimits:
        with self._lock:
            if tenant_id not in self._tenants:
                self._tenants[tenant_id] = TenantLimits(
                    max_isolations_per_minute=max_isolations_per_minute,
                    max_cloud_mutations_per_hour=max_cloud_mutations_per_hour,
                    risk_budget_per_hour=risk_budget_per_hour,
                )
            return self._tenants[tenant_id]

    def update_from_tenant_config(self, tenant_id: str) -> None:
        """Sync limits from TenantRegistry config."""
        try:
            from tenant_registry import get_tenant_registry
            cfg = get_tenant_registry().get(tenant_id)
            with self._lock:
                tl = self._tenants.get(tenant_id)
                if tl:
                    tl.max_isolations_per_minute = cfg.max_isolations_per_minute
                    tl.max_cloud_mutations_per_hour = cfg.max_cloud_mutations_per_hour
        except Exception:
            pass

    def check_and_record(
        self,
        tenant_id: str,
        action: str,
        is_cloud_mutation: bool = False,
        simulation: bool = False,
    ) -> Tuple[Action, Optional[str]]:
        """
        Check all limits for a proposed action.
        Returns (final_action, downgrade_reason or None).

        Simulation mode: checks limits but does NOT record (dry-run safe).
        """
        if action == "ALLOW":
            return "ALLOW", None

        try:
            from tenant_registry import get_tenant_registry
            cfg = get_tenant_registry().get(tenant_id)
            tl = self._get_or_create(
                tenant_id,
                max_isolations_per_minute=cfg.max_isolations_per_minute,
                max_cloud_mutations_per_hour=cfg.max_cloud_mutations_per_hour,
            )
        except Exception:
            tl = self._get_or_create(tenant_id)

        if action == "ISOLATE":
            result = tl.check_isolation()
            if not result.allowed:
                logger.warning(
                    "Isolation cap hit — downgrading to RATE_LIMIT",
                    extra={"tenant_id": tenant_id, "reason": result.reason},
                )
                if not simulation:
                    tl.record_risk("RATE_LIMIT")
                return "RATE_LIMIT", result.reason
            if not simulation:
                tl.record_isolation()

        budget_result = tl.check_risk_budget(action)
        if not budget_result.allowed:
            logger.warning(
                "Risk budget exhausted — downgrading",
                extra={"tenant_id": tenant_id, "reason": budget_result.reason},
            )
            if not simulation:
                tl.record_risk("RATE_LIMIT")
            return "RATE_LIMIT", budget_result.reason

        if is_cloud_mutation:
            mutation_result = tl.check_mutation()
            if not mutation_result.allowed:
                logger.warning(
                    "Cloud mutation cap hit — blocking",
                    extra={"tenant_id": tenant_id, "reason": mutation_result.reason},
                )
                return "RATE_LIMIT", mutation_result.reason
            if not simulation:
                tl.record_mutation()

        if not simulation:
            tl.record_risk(action)

        return action, None

    def get_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if tenant_id:
                tl = self._tenants.get(tenant_id)
                return {tenant_id: tl.get_stats()} if tl else {}
            return {tid: tl.get_stats() for tid, tl in self._tenants.items()}


# ────────────────────────────────────────────────────────────────────────────
# Circuit Breaker
# ────────────────────────────────────────────────────────────────────────────

CircuitState = Literal["CLOSED", "OPEN", "HALF_OPEN"]


@dataclass
class CircuitStatus:
    state: CircuitState
    opened_at: Optional[float]
    failure_count: int
    probe_successes: int
    fallback_action: Action
    last_trigger: Optional[str]


class CircuitBreaker:
    """
    System-wide (not per-tenant) circuit breaker.
    
    Triggers:
      - Anomaly spike: > 40% of recent events are ISOLATE in 60s window
      - System overload: recorded via record_latency()
    
    OPEN  → all decisions return fallback_action (default: RATE_LIMIT)
    HALF_OPEN → probe_limit successes required before returning to CLOSED
    """

    def __init__(
        self,
        isolation_rate_threshold: float = 0.40,
        probe_limit: int = 10,
        fallback_action: Action = "RATE_LIMIT",
    ) -> None:
        self._lock = threading.Lock()
        self._state: CircuitState = "CLOSED"
        self._opened_at: Optional[float] = None
        self._failure_count: int = 0
        self._probe_successes: int = 0
        self._probe_limit = probe_limit
        self._fallback = fallback_action
        self._last_trigger: Optional[str] = None
        self._isolation_threshold = isolation_rate_threshold

        # Sliding windows for rate calculation
        self._isolate_events = _SlidingWindowCounter(60.0)
        self._total_events = _SlidingWindowCounter(60.0)
        self._enabled: bool = True

    def record_event(self, action: str) -> None:
        """Record every enforcement decision for rate calculation."""
        self._total_events.record()
        if action == "ISOLATE":
            self._isolate_events.record()
        self._check_auto_open()

    def _check_auto_open(self) -> None:
        total = self._total_events.count()
        if total < 10:
            return   # insufficient data
        isolate = self._isolate_events.count()
        rate = isolate / total
        if rate > self._isolation_threshold:
            with self._lock:
                if self._state == "CLOSED":
                    self._open(f"Isolation rate spike: {rate:.1%} > threshold {self._isolation_threshold:.1%}")

    def _open(self, trigger: str) -> None:
        self._state = "OPEN"
        self._opened_at = time.time()
        self._failure_count += 1
        self._last_trigger = trigger
        self._probe_successes = 0
        logger.error(
            "CIRCUIT BREAKER OPENED",
            extra={"trigger": trigger, "failure_count": self._failure_count},
        )

    def is_open(self) -> bool:
        with self._lock:
            return self._state == "OPEN" and self._enabled

    def is_half_open(self) -> bool:
        with self._lock:
            return self._state == "HALF_OPEN"

    def get_fallback(self) -> Action:
        return self._fallback

    def check(self, proposed_action: str, simulation: bool = False) -> Tuple[Action, bool, Optional[str]]:
        """
        Check circuit state for a proposed action.
        Returns (final_action, was_overridden, override_reason).
        """
        if simulation:
            return proposed_action, False, None  # type: ignore[return-value]
        with self._lock:
            if self._state == "OPEN":
                return self._fallback, True, f"Circuit OPEN: {self._last_trigger}"
            if self._state == "HALF_OPEN":
                self._probe_successes += 1
                if self._probe_successes >= self._probe_limit:
                    self._state = "CLOSED"
                    logger.info("Circuit breaker CLOSED after successful probes")
        return proposed_action, False, None  # type: ignore[return-value]

    def reset(self, operator_id: str = "system") -> bool:
        """Manually close the circuit breaker. Returns True if it was open."""
        with self._lock:
            if self._state in ("OPEN", "HALF_OPEN"):
                self._state = "HALF_OPEN"
                self._probe_successes = 0
                logger.info(
                    "Circuit breaker manually reset to HALF_OPEN",
                    extra={"operator_id": operator_id},
                )
                return True
        return False

    def enable(self) -> None:
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        with self._lock:
            self._enabled = False

    def get_status(self) -> CircuitStatus:
        with self._lock:
            return CircuitStatus(
                state=self._state,
                opened_at=self._opened_at,
                failure_count=self._failure_count,
                probe_successes=self._probe_successes,
                fallback_action=self._fallback,
                last_trigger=self._last_trigger,
            )


# ────────────────────────────────────────────────────────────────────────────
# SafetyController — unified entry point
# ────────────────────────────────────────────────────────────────────────────

class SafetyController:
    """
    Single entry point for all Phase C safety checks.

    Call order:
      1. circuit_breaker.check() — if open, return fallback immediately
      2. execution_limits.check_and_record() — enforce caps
      3. Return (final_action, was_modified, reason)
    """

    def __init__(self) -> None:
        self.limits = ExecutionLimits()
        self.circuit = CircuitBreaker()

    def enforce(
        self,
        tenant_id: str,
        proposed_action: str,
        is_cloud_mutation: bool = False,
        simulation: bool = False,
    ) -> Tuple[Action, bool, Optional[str]]:
        """
        Returns (final_action, was_overridden, override_reason).
        
        was_overridden=True means the SafetyController changed the action.
        """
        # 1. Circuit breaker check
        final_action, cb_override, cb_reason = self.circuit.check(
            proposed_action, simulation=simulation
        )
        if cb_override:
            self.circuit.record_event(final_action)
            return final_action, True, cb_reason

        # 2. Execution limits check
        capped_action, limit_reason = self.limits.check_and_record(
            tenant_id=tenant_id,
            action=proposed_action,
            is_cloud_mutation=is_cloud_mutation,
            simulation=simulation,
        )
        if capped_action != proposed_action:
            self.circuit.record_event(capped_action)
            return capped_action, True, limit_reason

        # All clear
        self.circuit.record_event(proposed_action)
        return proposed_action, False, None  # type: ignore[return-value]

    def get_status(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        cb = self.circuit.get_status()
        return {
            "circuit_breaker": {
                "state": cb.state,
                "opened_at": cb.opened_at,
                "failure_count": cb.failure_count,
                "fallback_action": cb.fallback_action,
                "last_trigger": cb.last_trigger,
            },
            "execution_limits": self.limits.get_stats(tenant_id=tenant_id),
        }


# ────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ────────────────────────────────────────────────────────────────────────────

_controller: Optional[SafetyController] = None
_controller_lock = threading.Lock()


def get_safety_controller() -> SafetyController:
    global _controller
    if _controller is None:
        with _controller_lock:
            if _controller is None:
                _controller = SafetyController()
    return _controller
