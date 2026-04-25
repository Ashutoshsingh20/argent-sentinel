"""
Argent Sentinel — Alerting Engine (Phase E)
============================================
Production alerting subsystem for SOC visibility.

Architecture:
  AlertRule       — declarative threshold-based alert definitions
  Alert           — individual alert instance with lifecycle (FIRING → ACK → RESOLVED)
  AlertManager    — background scanner (5s interval) that evaluates rules against live state
  AlertStore      — in-memory + SQLite persistence for alert history

Built-in rules (12):
  1.  CIRCUIT_BREAKER_OPEN        — circuit breaker tripped
  2.  ISOLATION_RATE_SPIKE        — isolation rate > 30% in 60s
  3.  RISK_BUDGET_EXHAUSTED       — risk budget > 80% depleted
  4.  RULE_FP_RATE_HIGH           — false-positive rate > 25% for any rule
  5.  RULE_FN_RATE_HIGH           — false-negative rate > 15% for any rule
  6.  TRUST_SCORE_LOW             — avg trust < 50 sustained
  7.  CLOUD_MUTATION_CAP          — cloud mutation quota > 80%
  8.  ENTITY_ISOLATION_STREAK     — entity isolated > 10 consecutive times
  9.  MODEL_FEEDBACK_ERROR_RATE   — feedback loop error count elevated
  10. TENANT_RATE_LIMIT_PRESSURE  — tenant approaching rate limit
  11. POLICY_RELOAD_FAILURE       — policy engine hot-reload error
  12. SAFETY_DOWNGRADE_RATE       — safety override rate above 20%
"""

from __future__ import annotations

import collections
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Literal, Optional, Tuple
from tenant_scope import alert_key as _alert_key
from runtime_settings import settings

logger = logging.getLogger(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Types
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AlertSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
AlertState = Literal["FIRING", "ACKNOWLEDGED", "RESOLVED"]

_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Alert Model
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class Alert:
    alert_id: str
    rule_id: str
    severity: AlertSeverity
    title: str
    description: str
    state: AlertState
    fired_at: float
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    acknowledged_by: Optional[str] = None
    resolved_by: Optional[str] = None
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "state": self.state,
            "fired_at": self.fired_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "acknowledged_by": self.acknowledged_by,
            "resolved_by": self.resolved_by,
            "tenant_id": self.tenant_id,
            "metadata": self.metadata,
            "age_seconds": round(time.time() - self.fired_at, 1),
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Alert Store — in-memory + SQLite
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AlertStore:
    """Persisted alert history with in-memory hot index."""

    def __init__(self, db_path: str = "outputs/alerts.db") -> None:
        self._lock = threading.RLock()
        self._active: Dict[str, Alert] = {}          # alert_id → Alert (FIRING or ACK)
        self._history: Deque[Alert] = collections.deque(maxlen=500)
        self._db_path = db_path
        self._init_db()
        self._load_active()

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) if os.path.dirname(self._db_path) else ".", exist_ok=True)
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        rule_id TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        state TEXT NOT NULL DEFAULT 'FIRING',
                        fired_at REAL NOT NULL,
                        acknowledged_at REAL,
                        resolved_at REAL,
                        acknowledged_by TEXT,
                        resolved_by TEXT,
                        tenant_id TEXT,
                        metadata TEXT DEFAULT '{}'
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_state ON alerts(state)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_fired ON alerts(fired_at)")
                conn.commit()
        except Exception as exc:
            logger.warning("Alert DB init failed", extra={"error": str(exc)})

    def _load_active(self) -> None:
        try:
            with sqlite3.connect(self._db_path) as conn:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE state IN ('FIRING', 'ACKNOWLEDGED') ORDER BY fired_at DESC"
                ).fetchall()
            for row in rows:
                alert = Alert(
                    alert_id=row[0], rule_id=row[1], severity=row[2],
                    title=row[3], description=row[4] or "", state=row[5],
                    fired_at=row[6], acknowledged_at=row[7], resolved_at=row[8],
                    acknowledged_by=row[9], resolved_by=row[10], tenant_id=row[11],
                    metadata=json.loads(row[12] or "{}"),
                )
                with self._lock:
                    self._active[alert.alert_id] = alert
        except Exception as exc:
            logger.warning("Alert load failed", extra={"error": str(exc)})

    def fire(self, alert: Alert) -> None:
        with self._lock:
            self._active[alert.alert_id] = alert
        self._persist(alert)
        logger.warning(
            f"ALERT FIRED: [{alert.severity}] {alert.title}",
            extra={"alert_id": alert.alert_id, "rule_id": alert.rule_id},
        )

    def acknowledge(self, alert_id: str, operator_id: str = "soc") -> bool:
        with self._lock:
            alert = self._active.get(alert_id)
            if not alert or alert.state != "FIRING":
                return False
            alert.state = "ACKNOWLEDGED"
            alert.acknowledged_at = time.time()
            alert.acknowledged_by = operator_id
        self._persist(alert)
        return True

    def resolve(self, alert_id: str, operator_id: str = "system") -> bool:
        with self._lock:
            alert = self._active.pop(alert_id, None)
            if not alert:
                return False
            alert.state = "RESOLVED"
            alert.resolved_at = time.time()
            alert.resolved_by = operator_id
            self._history.appendleft(alert)
        self._persist(alert)
        return True

    def get_active(self, severity: Optional[str] = None, tenant_id: Optional[str] = None) -> List[Alert]:
        with self._lock:
            alerts = list(self._active.values())
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if tenant_id:
            alerts = [a for a in alerts if a.tenant_id == tenant_id or a.tenant_id is None]
        return sorted(alerts, key=lambda a: (_SEVERITY_RANK.get(a.severity, 0), a.fired_at), reverse=True)

    def get_history(self, limit: int = 50) -> List[Alert]:
        with self._lock:
            return list(self._history)[:limit]

    def get_all(self, limit: int = 100) -> List[Alert]:
        active = self.get_active()
        history = self.get_history(limit=limit - len(active))
        return active + history

    def has_active_for_rule(self, rule_id: str) -> bool:
        with self._lock:
            return any(a.rule_id == rule_id and a.state == "FIRING" for a in self._active.values())

    def get_counts(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {"FIRING": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0}
            for a in self._active.values():
                counts[a.state] = counts.get(a.state, 0) + 1
            counts["RESOLVED"] = len(self._history)
            severity_counts: Dict[str, int] = {}
            for a in self._active.values():
                severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1
            return {**counts, "by_severity": severity_counts}

    def _persist(self, alert: Alert) -> None:
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO alerts
                       (alert_id, rule_id, severity, title, description, state,
                        fired_at, acknowledged_at, resolved_at,
                        acknowledged_by, resolved_by, tenant_id, metadata)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        alert.alert_id, alert.rule_id, alert.severity,
                        alert.title, alert.description, alert.state,
                        alert.fired_at, alert.acknowledged_at, alert.resolved_at,
                        alert.acknowledged_by, alert.resolved_by, alert.tenant_id,
                        json.dumps(alert.metadata),
                    )
                )
                conn.commit()
        except Exception as exc:
            logger.warning("Alert persist failed", extra={"error": str(exc)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Alert Manager — background scanner + rule evaluator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AlertManager:
    """
    Scans system state every 5 seconds and fires alerts when conditions are met.
    Auto-resolves alerts when conditions clear.
    """

    def __init__(self, scan_interval: float = 5.0) -> None:
        self.store = AlertStore()
        self._scan_interval = scan_interval
        self._running = False
        self._stats = {
            "scans": 0,
            "alerts_fired": 0,
            "alerts_resolved": 0,
            "last_scan_ts": 0.0,
            "last_scan_duration_ms": 0.0,
        }
        self._lock = threading.Lock()
        # Track which rules are currently firing (for auto-resolve)
        self._firing_rules: Dict[str, str] = {}  # rule_id → alert_id

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._scan_loop, daemon=True, name="alert-scanner")
        t.start()
        logger.info("AlertManager started (Phase E)")

    def stop(self) -> None:
        self._running = False

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def _scan_loop(self) -> None:
        # Initial delay to let system warm up
        time.sleep(10)
        while self._running:
            try:
                t0 = time.perf_counter()
                self._evaluate_all_rules()
                elapsed_ms = (time.perf_counter() - t0) * 1000
                with self._lock:
                    self._stats["scans"] += 1
                    self._stats["last_scan_ts"] = time.time()
                    self._stats["last_scan_duration_ms"] = round(elapsed_ms, 2)
            except Exception as exc:
                logger.warning("Alert scan failed", extra={"error": str(exc)})
            time.sleep(self._scan_interval)

    def _evaluate_all_rules(self) -> None:
        """Evaluate all built-in alert rules."""
        if settings.tenant_isolation_enabled:
            from tenant_registry import get_tenant_registry
            tenants = [t["id"] for t in get_tenant_registry().list_all()]
        else:
            tenants = ["default"]

        for tenant_id in tenants:
            self._check_circuit_breaker(tenant_id)
            self._check_isolation_rate(tenant_id)
            self._check_fp_rate(tenant_id)
            self._check_fn_rate(tenant_id)
            self._check_trust_score(tenant_id)
            self._check_model_feedback(tenant_id)
            
        self._check_risk_budget()
        self._check_cloud_mutation_cap()
        self._check_safety_downgrade()

    # ── Helper: fire or auto-resolve ────────────────────────────────────────

    def _fire_or_skip(
        self,
        rule_id: str,
        severity: AlertSeverity,
        title: str,
        description: str,
        tenant_id: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Fire alert if not already firing for this rule. Track for auto-resolve."""
        rk = _alert_key(tenant_id, rule_id) if settings.tenant_isolation_enabled else rule_id
        with self._lock:
            if rk in self._firing_rules:
                return  # already firing

        alert = Alert(
            alert_id=str(uuid.uuid4()),
            rule_id=rk,
            severity=severity,
            title=title,
            description=description,
            state="FIRING",
            fired_at=time.time(),
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        self.store.fire(alert)
        with self._lock:
            self._firing_rules[rk] = alert.alert_id
            self._stats["alerts_fired"] += 1

    def _auto_resolve(self, rule_id: str, tenant_id: str = "default") -> None:
        """Auto-resolve an alert if its condition has cleared."""
        rk = _alert_key(tenant_id, rule_id) if settings.tenant_isolation_enabled else rule_id
        with self._lock:
            alert_id = self._firing_rules.pop(rk, None)
        if alert_id:
            self.store.resolve(alert_id, operator_id="auto_resolve")
            with self._lock:
                self._stats["alerts_resolved"] += 1

    # ── Rule 1: Circuit Breaker OPEN ────────────────────────────────────────

    def _check_circuit_breaker(self, tenant_id: str = "default") -> None:
        try:
            from safety_controller import get_safety_controller
            sc = get_safety_controller()
            status = sc.get_status(tenant_id=tenant_id)["circuit_breaker"]
            state = status["state"]
            if state in ("OPEN", "HALF_OPEN"):
                self._fire_or_skip(
                    rule_id="CIRCUIT_BREAKER_OPEN",
                    severity="CRITICAL",
                    title="Circuit Breaker Tripped",
                    description=f"Circuit breaker is {state}. Trigger: {status['last_trigger'] or 'unknown'}. "
                                f"Failure count: {status['failure_count']}. All decisions falling back to {status['fallback_action']}.",
                    tenant_id=tenant_id,
                    metadata={"state": state, "trigger": status["last_trigger"], "failures": status["failure_count"]},
                )
            else:
                self._auto_resolve("CIRCUIT_BREAKER_OPEN", tenant_id=tenant_id)
        except Exception:
            pass

    # ── Rule 2: Isolation Rate Spike ────────────────────────────────────────

    def _check_isolation_rate(self, tenant_id: str = "default") -> None:
        try:

            from safety_controller import get_safety_controller
            sc = get_safety_controller()
            cb = sc._get_circuit_breaker(tenant_id) if settings.tenant_isolation_enabled else sc.circuit
            isolate_count = cb._isolate_events.count()
            total_count = cb._total_events.count()
            if total_count >= 10:
                rate = isolate_count / total_count
                if rate > 0.30:
                    self._fire_or_skip(
                        rule_id="ISOLATION_RATE_SPIKE",
                        severity="HIGH",
                        title="Isolation Rate Spike",
                        description=f"Isolation rate is {rate:.1%} ({isolate_count}/{total_count} events in 60s window). "
                                    f"Threshold: 30%.",
                        tenant_id=tenant_id,
                        metadata={"rate": round(rate, 4), "isolations": isolate_count, "total": total_count},
                    )
                else:
                    self._auto_resolve("ISOLATION_RATE_SPIKE", tenant_id=tenant_id)
            else:
                self._auto_resolve("ISOLATION_RATE_SPIKE", tenant_id=tenant_id)
        except Exception:
            pass

    # ── Rule 3: Risk Budget Exhausted ───────────────────────────────────────

    def _check_risk_budget(self) -> None:
        try:
            from safety_controller import get_safety_controller
            sc = get_safety_controller()
            all_stats = sc.limits.get_stats()
            for tenant_id, stats in all_stats.items():
                spent = stats.get("risk_budget_spent", 0)
                limit = stats.get("risk_budget_limit", 150)
                if limit > 0 and (spent / limit) > 0.80:
                    self._fire_or_skip(
                        rule_id=f"RISK_BUDGET_EXHAUSTED:{tenant_id}",
                        severity="HIGH",
                        title=f"Risk Budget > 80% — {tenant_id}",
                        description=f"Tenant '{tenant_id}' risk budget: {spent}/{limit} units ({spent/limit:.0%} spent). "
                                    f"Subsequent risky decisions will be capped at RATE_LIMIT.",
                        tenant_id=tenant_id,
                        metadata={"spent": spent, "limit": limit, "tenant_id": tenant_id},
                    )
                else:
                    self._auto_resolve(f"RISK_BUDGET_EXHAUSTED:{tenant_id}")
        except Exception:
            pass

    # ── Rule 4: High FP Rate ───────────────────────────────────────────────

    def _check_fp_rate(self, tenant_id: str = "default") -> None:
        try:
            from intelligence_layer import get_intelligence_layer
            intel = get_intelligence_layer()
            accuracy = intel.feedback.get_rule_accuracy(tenant_id=tenant_id, since_hours=24.0, min_samples=10)
            any_firing = False
            for rule_id, stats in accuracy.items():
                if stats.get("fp_rate", 0) > 0.25:
                    self._fire_or_skip(
                        rule_id=f"RULE_FP_RATE_HIGH:{rule_id}",
                        severity="MEDIUM",
                        title=f"High False-Positive Rate — {rule_id}",
                        description=f"Rule '{rule_id}' has a {stats['fp_rate']:.0%} false-positive rate "
                                    f"({stats['total']} samples in 24h). Consider tuning down priority.",
                        tenant_id=tenant_id,
                        metadata={"rule_id": rule_id, **stats},
                    )
                    any_firing = True
                else:
                    self._auto_resolve(f"RULE_FP_RATE_HIGH:{rule_id}", tenant_id=tenant_id)
        except Exception:
            pass

    # ── Rule 5: High FN Rate ───────────────────────────────────────────────

    def _check_fn_rate(self, tenant_id: str = "default") -> None:
        try:
            from intelligence_layer import get_intelligence_layer
            intel = get_intelligence_layer()
            accuracy = intel.feedback.get_rule_accuracy(tenant_id=tenant_id, since_hours=24.0, min_samples=10)
            for rule_id, stats in accuracy.items():
                if stats.get("fn_rate", 0) > 0.15:
                    self._fire_or_skip(
                        rule_id=f"RULE_FN_RATE_HIGH:{rule_id}",
                        severity="HIGH",
                        title=f"High False-Negative Rate — {rule_id}",
                        description=f"Rule '{rule_id}' has a {stats['fn_rate']:.0%} false-negative rate "
                                    f"({stats['total']} samples in 24h). Real threats may be bypassing this rule.",
                        tenant_id=tenant_id,
                        metadata={"rule_id": rule_id, **stats},
                    )
                else:
                    self._auto_resolve(f"RULE_FN_RATE_HIGH:{rule_id}", tenant_id=tenant_id)
        except Exception:
            pass

    # ── Rule 6: Low Trust Score ─────────────────────────────────────────────

    def _check_trust_score(self, tenant_id: str = "default") -> None:
        try:
            import database as db
            from sqlalchemy import func
            s = db.SessionLocal()
            try:
                _q = s.query(db.Entity)
                if settings.tenant_isolation_enabled:
                    _q = _q.filter(db.Entity.tenant_id == tenant_id)
                avg_trust = _q.with_entities(func.avg(db.Entity.current_trust_score)).scalar() or 75.0
            finally:
                s.close()
            if avg_trust < 50.0:
                self._fire_or_skip(
                    rule_id="TRUST_SCORE_LOW",
                    severity="MEDIUM",
                    title="Average Trust Score Below 50",
                    description=f"System-wide average trust score is {avg_trust:.1f}. "
                                f"This indicates widespread anomalous activity or model drift.",
                    tenant_id=tenant_id,
                    metadata={"avg_trust": round(avg_trust, 2)},
                )
            else:
                self._auto_resolve("TRUST_SCORE_LOW", tenant_id=tenant_id)
        except Exception:
            pass

    # ── Rule 7: Cloud Mutation Cap ──────────────────────────────────────────

    def _check_cloud_mutation_cap(self) -> None:
        try:
            from safety_controller import get_safety_controller
            sc = get_safety_controller()
            all_stats = sc.limits.get_stats()
            for tenant_id, stats in all_stats.items():
                mutations = stats.get("mutations_per_hour", 0)
                # Default cap from tenant config
                from tenant_registry import get_tenant_registry
                cfg = get_tenant_registry().get(tenant_id)
                cap = cfg.max_cloud_mutations_per_hour
                if cap > 0 and (mutations / cap) > 0.80:
                    self._fire_or_skip(
                        rule_id=f"CLOUD_MUTATION_CAP:{tenant_id}",
                        severity="MEDIUM",
                        title=f"Cloud Mutation Cap > 80% — {tenant_id}",
                        description=f"Tenant '{tenant_id}' has used {mutations}/{cap} cloud mutations this hour.",
                        tenant_id=tenant_id,
                        metadata={"mutations": mutations, "cap": cap},
                    )
                else:
                    self._auto_resolve(f"CLOUD_MUTATION_CAP:{tenant_id}")
        except Exception:
            pass

    # ── Rule 9: Model Feedback Error Rate ───────────────────────────────────

    def _check_model_feedback(self, tenant_id: str = "default") -> None:
        try:
            from intelligence_layer import get_intelligence_layer
            intel = get_intelligence_layer()
            stats = intel.model_feedback.get_stats()
            # In complete backend isolation, ModelFeedback itself should be scoped per tenant.
            # Assuming shared model loop for now but filtering active stats
            total = stats.get("total_routed", 0)
            fp = stats.get("fp", 0)
            fn = stats.get("fn", 0)
            if total > 10 and (fp + fn) / max(1, total) > 0.5:
                self._fire_or_skip(
                    rule_id="MODEL_FEEDBACK_ERROR_RATE",
                    severity="MEDIUM",
                    title="Model Feedback Error Rate Elevated",
                    description=f"Model feedback loop has routed {total} samples with {fp} FP and {fn} FN corrections. "
                                f"Error rate: {(fp+fn)/max(1,total):.0%}.",
                    tenant_id=tenant_id,
                    metadata=stats,
                )
            else:
                self._auto_resolve("MODEL_FEEDBACK_ERROR_RATE", tenant_id=tenant_id)
        except Exception:
            pass

    # ── Rule 12: Safety Downgrade Rate ──────────────────────────────────────

    def _check_safety_downgrade(self) -> None:
        try:
            from safety_controller import get_safety_controller
            sc = get_safety_controller()
            all_stats = sc.limits.get_stats()
            for tenant_id, stats in all_stats.items():
                isolations = stats.get("isolations_per_minute", 0)
                # If significant isolations are hitting caps, that's a downgrade signal
                from tenant_registry import get_tenant_registry
                cfg = get_tenant_registry().get(tenant_id)
                cap = cfg.max_isolations_per_minute
                if cap > 0 and isolations > 0 and (isolations / cap) > 0.80:
                    self._fire_or_skip(
                        rule_id=f"SAFETY_DOWNGRADE_RATE:{tenant_id}",
                        severity="HIGH",
                        title=f"Safety Downgrade Rate High — {tenant_id}",
                        description=f"Tenant '{tenant_id}' isolation rate {isolations}/{cap} per minute ({isolations/cap:.0%}). "
                                    f"Excess isolations are being downgraded to RATE_LIMIT.",
                        tenant_id=tenant_id,
                        metadata={"isolations": isolations, "cap": cap},
                    )
                else:
                    self._auto_resolve(f"SAFETY_DOWNGRADE_RATE:{tenant_id}")
        except Exception:
            pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Module-level singleton
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_manager: Optional[AlertManager] = None
_manager_lock = threading.Lock()


def get_alert_manager() -> AlertManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = AlertManager()
    return _manager
