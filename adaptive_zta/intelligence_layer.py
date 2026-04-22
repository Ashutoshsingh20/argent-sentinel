"""
Argent Sentinel — Intelligence Layer · Phase D
===============================================
Four interlocking subsystems:

  D1. ContextIntelligence   — real-time entity criticality & environment scoring
  D2. FeedbackCollector     — track action effectiveness, record ground-truth outcomes
  D3. PolicyAdjuster        — analyze feedback patterns, propose rule weight changes
  D4. ModelFeedback         — route failed decisions back as shadow learning signals

Global flow after Phase D:
  Request → Auth → Context Score → TabNet + context boost → Policy
          → Safety → Execution → Audit → [background] Feedback loop
"""

from __future__ import annotations

import collections
import json
import logging
import math
import statistics
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# D1 — Context Intelligence
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ContextScore:
    """Per-request context enrichment."""
    entity_criticality: float       # 0.0–1.0; higher = more critical / higher blast radius
    environment_risk: float         # 0.0–1.0; cloud env risk level
    behavioral_velocity: float      # api_rate change vs 5-min moving average
    time_risk: float                # off-hours / weekend flag (0.0=business hours, 1.0=high-risk time)
    composite: float                # weighted aggregate used to boost trust-floor decisions
    flags: List[str]                # human-readable risk flags

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_criticality": round(self.entity_criticality, 4),
            "environment_risk": round(self.environment_risk, 4),
            "behavioral_velocity": round(self.behavioral_velocity, 4),
            "time_risk": round(self.time_risk, 4),
            "composite": round(self.composite, 4),
            "flags": self.flags,
        }


_ENTITY_TYPE_CRITICALITY: Dict[str, float] = {
    "service_account": 0.85,   # high blast-radius if compromised
    "api_gateway": 0.80,
    "microservice": 0.60,
    "human_user": 0.45,
}

_CLOUD_ENV_RISK: Dict[str, float] = {
    "aws": 0.55,
    "azure": 0.50,
    "gcp": 0.45,
}


class ContextIntelligence:
    """
    Enriches each authorization request with context signals that the
    raw TabNet model cannot see (entity criticality, time-of-day, velocity).

    Thread-safe — keeps a per-entity rate-window for velocity calculation.
    """

    def __init__(self, velocity_window_seconds: float = 300.0) -> None:
        self._lock = threading.Lock()
        # entity_id → deque of (timestamp, api_rate) for velocity tracking
        self._rate_history: Dict[str, Deque[Tuple[float, float]]] = {}
        self._velocity_window = velocity_window_seconds

    def score(self, entity_id: str, telemetry: Dict[str, Any]) -> ContextScore:
        """Compute a ContextScore for a request."""
        flags: List[str] = []

        # ── Entity criticality ──────────────────────────────────────────
        entity_type = str(telemetry.get("entity_type", "human_user")).lower()
        criticality = _ENTITY_TYPE_CRITICALITY.get(entity_type, 0.5)

        # ── Environment risk ────────────────────────────────────────────
        cloud = str(telemetry.get("cloud_env", "aws")).lower()
        env_risk = _CLOUD_ENV_RISK.get(cloud, 0.5)
        if telemetry.get("geo_anomaly_flag", 0):
            env_risk = min(1.0, env_risk + 0.20)
            flags.append("GEO_ANOMALY")

        # ── Behavioral velocity ─────────────────────────────────────────
        api_rate = float(telemetry.get("api_rate", 0.0))
        ts = float(telemetry.get("timestamp", time.time()))
        velocity = self._compute_velocity(entity_id, ts, api_rate)
        if velocity > 0.5:
            flags.append(f"RATE_SPIKE:{velocity:.2f}")

        # ── Time-of-day risk ────────────────────────────────────────────
        time_risk = self._compute_time_risk(ts)
        if time_risk > 0.7:
            flags.append("OFF_HOURS")

        # ── Protocol risk boost ─────────────────────────────────────────
        protocol = str(telemetry.get("protocol_type", "HTTPS")).upper()
        proto_risk = {"HTTPS": 0.0, "HTTP": 0.25, "SSH": 0.40}.get(protocol, 0.20)
        if proto_risk > 0.2:
            flags.append(f"RISKY_PROTO:{protocol}")

        # ── Composite score ─────────────────────────────────────────────
        composite = (
            0.35 * criticality
            + 0.25 * env_risk
            + 0.20 * velocity
            + 0.15 * time_risk
            + 0.05 * proto_risk
        )
        composite = max(0.0, min(1.0, composite))

        return ContextScore(
            entity_criticality=criticality,
            environment_risk=env_risk,
            behavioral_velocity=velocity,
            time_risk=time_risk,
            composite=composite,
            flags=flags,
        )

    def _compute_velocity(self, entity_id: str, ts: float, api_rate: float) -> float:
        """Returns normalized rate-of-change (0=stable, 1=extreme spike)."""
        with self._lock:
            hist = self._rate_history.setdefault(entity_id, collections.deque())
            cutoff = ts - self._velocity_window
            while hist and hist[0][0] < cutoff:
                hist.popleft()
            hist.append((ts, api_rate))
            if len(hist) < 3:
                return 0.0
            rates = [r for _, r in hist]
            avg = statistics.mean(rates[:-1])
            if avg == 0.0:
                return 0.0
            change = (api_rate - avg) / max(1.0, avg)
            return max(0.0, min(1.0, change))

    @staticmethod
    def _compute_time_risk(ts: float) -> float:
        """
        0.0 = business hours (Mon-Fri 09:00–18:00 local)
        1.0 = deep off-hours (00:00–05:00) or weekend
        """
        import datetime as dt
        utc = dt.datetime.utcfromtimestamp(ts)
        weekday = utc.weekday()   # 0=Mon, 6=Sun
        hour = utc.hour

        if weekday >= 5:          # weekend
            return 0.8
        if 9 <= hour < 18:
            return 0.1            # business hours — low risk
        if 18 <= hour < 22:
            return 0.4            # after hours — moderate
        return 0.85               # late night / early morning — high


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# D2 — Feedback Collector
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class FeedbackRecord:
    feedback_id: str
    tenant_id: str
    entity_id: str
    timestamp: float
    decision: str                # what the system decided
    true_label: int              # 0=benign, 1=malicious
    rule_id: str                 # which rule triggered
    trust_score: float
    context_composite: float
    correct: bool                # decision aligned with true_label
    source: str                  # "gateway_feedback" | "operator" | "automated"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feedback_id": self.feedback_id,
            "tenant_id": self.tenant_id,
            "entity_id": self.entity_id,
            "timestamp": self.timestamp,
            "decision": self.decision,
            "true_label": self.true_label,
            "rule_id": self.rule_id,
            "trust_score": round(self.trust_score, 3),
            "context_composite": round(self.context_composite, 3),
            "correct": self.correct,
            "source": self.source,
        }


class FeedbackCollector:
    """
    Collects ground-truth labels for past decisions.
    Stores in SQLite and provides per-rule accuracy stats for PolicyAdjuster.
    """

    def __init__(self, db_path: str = "outputs/feedback.db") -> None:
        self._lock = threading.Lock()
        self._db_path = db_path
        self._buffer: List[FeedbackRecord] = []
        self._init_db()

        # Background writer
        t = threading.Thread(target=self._writer_loop, daemon=True, name="feedback-writer")
        t.start()

    def _init_db(self) -> None:
        import sqlite3, os
        os.makedirs(os.path.dirname(self._db_path) if os.path.dirname(self._db_path) else ".", exist_ok=True)
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS feedback (
                        feedback_id TEXT PRIMARY KEY,
                        tenant_id TEXT,
                        entity_id TEXT,
                        timestamp REAL,
                        decision TEXT,
                        true_label INTEGER,
                        rule_id TEXT,
                        trust_score REAL,
                        context_composite REAL,
                        correct INTEGER,
                        source TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_rule ON feedback(rule_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_tenant ON feedback(tenant_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_ts ON feedback(timestamp)")
                conn.commit()
        except Exception as exc:
            logger.warning("Feedback DB init failed", extra={"error": str(exc)})

    def record(
        self,
        tenant_id: str,
        entity_id: str,
        decision: str,
        true_label: int,
        rule_id: str,
        trust_score: float,
        context_composite: float = 0.5,
        source: str = "gateway_feedback",
    ) -> FeedbackRecord:
        """
        True label semantics:
          0 = entity was benign (ALLOW was correct)
          1 = entity was malicious (ISOLATE/RATE_LIMIT was correct)
        """
        benign_actions = {"ALLOW"}
        malicious_actions = {"ISOLATE", "RATE_LIMIT"}

        if true_label == 0:
            correct = decision in benign_actions
        else:
            correct = decision in malicious_actions

        rec = FeedbackRecord(
            feedback_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            entity_id=entity_id,
            timestamp=time.time(),
            decision=decision,
            true_label=true_label,
            rule_id=rule_id,
            trust_score=trust_score,
            context_composite=context_composite,
            correct=correct,
            source=source,
        )
        with self._lock:
            self._buffer.append(rec)
        return rec

    def get_rule_accuracy(
        self,
        tenant_id: Optional[str] = None,
        since_hours: float = 24.0,
        min_samples: int = 10,
    ) -> Dict[str, Dict[str, Any]]:
        """Returns accuracy stats per rule_id for PolicyAdjuster."""
        import sqlite3
        since = time.time() - since_hours * 3600
        try:
            with sqlite3.connect(self._db_path) as conn:
                if tenant_id:
                    rows = conn.execute(
                        "SELECT rule_id, correct, decision FROM feedback WHERE timestamp > ? AND tenant_id = ?",
                        (since, tenant_id)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT rule_id, correct, decision FROM feedback WHERE timestamp > ?",
                        (since,)
                    ).fetchall()
        except Exception:
            return {}

        from collections import defaultdict
        stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"total": 0, "correct": 0, "fp": 0, "fn": 0})
        for rule_id, correct, decision in rows:
            s = stats[rule_id]
            s["total"] += 1
            if correct:
                s["correct"] += 1
            elif decision in ("ISOLATE", "RATE_LIMIT"):
                s["fp"] += 1   # decided threat but was benign
            else:
                s["fn"] += 1   # allowed but was malicious

        out = {}
        for rule_id, s in stats.items():
            if s["total"] < min_samples:
                continue
            accuracy = s["correct"] / s["total"]
            fp_rate = s["fp"] / s["total"]
            fn_rate = s["fn"] / s["total"]
            out[rule_id] = {
                "total": s["total"],
                "accuracy": round(accuracy, 4),
                "fp_rate": round(fp_rate, 4),
                "fn_rate": round(fn_rate, 4),
            }
        return out

    def _writer_loop(self) -> None:
        while True:
            time.sleep(5)
            with self._lock:
                batch = list(self._buffer)
                self._buffer.clear()
            if batch:
                self._write(batch)

    def _write(self, batch: List[FeedbackRecord]) -> None:
        import sqlite3
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.executemany(
                    """INSERT OR IGNORE INTO feedback
                       (feedback_id, tenant_id, entity_id, timestamp, decision,
                        true_label, rule_id, trust_score, context_composite, correct, source)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (r.feedback_id, r.tenant_id, r.entity_id, r.timestamp,
                         r.decision, r.true_label, r.rule_id, r.trust_score,
                         r.context_composite, int(r.correct), r.source)
                        for r in batch
                    ]
                )
                conn.commit()
        except Exception as exc:
            logger.warning("Feedback write failed", extra={"error": str(exc)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# D3 — Policy Adjuster
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class AdjustmentSuggestion:
    rule_id: str
    current_priority: int
    suggested_priority: int
    current_weight: float
    suggested_weight: float
    reason: str
    severity: str              # "TUNE_DOWN" | "TUNE_UP" | "REVIEW" | "OK"
    fp_rate: float
    fn_rate: float
    accuracy: float
    sample_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "current_priority": self.current_priority,
            "suggested_priority": self.suggested_priority,
            "current_weight": round(self.current_weight, 4),
            "suggested_weight": round(self.suggested_weight, 4),
            "reason": self.reason,
            "severity": self.severity,
            "fp_rate": round(self.fp_rate, 4),
            "fn_rate": round(self.fn_rate, 4),
            "accuracy": round(self.accuracy, 4),
            "sample_count": self.sample_count,
        }


class PolicyAdjuster:
    """
    Analyzes FeedbackCollector data and generates AdjustmentSuggestions.

    Phase D design: suggestions are ADVISORY — operators review them.
    Auto-application is opt-in via apply_suggestions().

    Thresholds:
      fp_rate > 0.30  → rule fires too aggressively → TUNE_DOWN
      fn_rate > 0.20  → rule misses too many threats → TUNE_UP
      accuracy > 0.85 → rule is healthy → OK
    """

    FP_THRESHOLD = 0.30   # rule fires on too many benign entities
    FN_THRESHOLD = 0.20   # rule misses too many real threats
    OK_THRESHOLD = 0.85

    def analyze(
        self,
        feedback: FeedbackCollector,
        tenant_id: Optional[str] = None,
        since_hours: float = 24.0,
        min_samples: int = 10,
    ) -> List[AdjustmentSuggestion]:
        """Produce per-rule adjustment suggestions based on recent feedback."""
        from policy_engine import get_policy_engine
        pe = get_policy_engine()
        rules_summary = {r["id"]: r for r in pe.get_rules_summary()}
        accuracy_by_rule = feedback.get_rule_accuracy(
            tenant_id=tenant_id, since_hours=since_hours, min_samples=min_samples
        )

        suggestions: List[AdjustmentSuggestion] = []
        for rule_id, stats in accuracy_by_rule.items():
            rule_meta = rules_summary.get(rule_id, {})
            curr_priority = int(rule_meta.get("priority", 50))
            curr_weight = float(rule_meta.get("conflict_weight", 0.5))
            fp = stats["fp_rate"]
            fn = stats["fn_rate"]
            acc = stats["accuracy"]
            n = stats["total"]

            if fp > self.FP_THRESHOLD:
                # Rule fires on too many benign entities → lower priority/weight
                delta_p = max(-15, -int(fp * 30))
                delta_w = max(-0.25, -fp * 0.5)
                suggestions.append(AdjustmentSuggestion(
                    rule_id=rule_id,
                    current_priority=curr_priority,
                    suggested_priority=max(1, curr_priority + delta_p),
                    current_weight=curr_weight,
                    suggested_weight=max(0.05, curr_weight + delta_w),
                    reason=f"High false-positive rate ({fp:.1%}) — rule fires on too many benign entities",
                    severity="TUNE_DOWN",
                    fp_rate=fp, fn_rate=fn, accuracy=acc, sample_count=n,
                ))
            elif fn > self.FN_THRESHOLD:
                # Rule misses real threats → raise priority/weight
                delta_p = min(+15, int(fn * 30))
                delta_w = min(+0.25, fn * 0.5)
                suggestions.append(AdjustmentSuggestion(
                    rule_id=rule_id,
                    current_priority=curr_priority,
                    suggested_priority=min(100, curr_priority + delta_p),
                    current_weight=curr_weight,
                    suggested_weight=min(1.0, curr_weight + delta_w),
                    reason=f"High false-negative rate ({fn:.1%}) — rule misses real threats",
                    severity="TUNE_UP",
                    fp_rate=fp, fn_rate=fn, accuracy=acc, sample_count=n,
                ))
            elif acc < 0.60:
                suggestions.append(AdjustmentSuggestion(
                    rule_id=rule_id,
                    current_priority=curr_priority,
                    suggested_priority=curr_priority,
                    current_weight=curr_weight,
                    suggested_weight=curr_weight,
                    reason=f"Low overall accuracy ({acc:.1%}) — rule may need condition revision",
                    severity="REVIEW",
                    fp_rate=fp, fn_rate=fn, accuracy=acc, sample_count=n,
                ))
            else:
                suggestions.append(AdjustmentSuggestion(
                    rule_id=rule_id,
                    current_priority=curr_priority,
                    suggested_priority=curr_priority,
                    current_weight=curr_weight,
                    suggested_weight=curr_weight,
                    reason=f"Rule performing well (accuracy={acc:.1%})",
                    severity="OK",
                    fp_rate=fp, fn_rate=fn, accuracy=acc, sample_count=n,
                ))

        return sorted(suggestions, key=lambda s: {"TUNE_DOWN": 0, "TUNE_UP": 1, "REVIEW": 2, "OK": 3}.get(s.severity, 4))

    def apply_suggestions(
        self,
        suggestions: List[AdjustmentSuggestion],
        auto_apply_severity: List[str] = ("TUNE_DOWN", "TUNE_UP"),
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Apply approved suggestions to the live policy YAML and trigger hot-reload.
        dry_run=True: return what would change without writing.
        """
        from policy_engine import get_policy_engine
        import yaml

        pe = get_policy_engine()
        rules_path = pe._rules_path

        if yaml is None or not rules_path.exists():
            return {"applied": 0, "error": "yaml not available or rules file missing"}

        with rules_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        rules_list = data.get("rules", [])
        applied: List[str] = []
        rule_map = {r["id"]: r for r in rules_list}

        for sug in suggestions:
            if sug.severity not in auto_apply_severity:
                continue
            if sug.rule_id not in rule_map:
                continue
            if not dry_run:
                rule_map[sug.rule_id]["priority"] = sug.suggested_priority
                rule_map[sug.rule_id]["conflict_weight"] = round(sug.suggested_weight, 4)
            applied.append(sug.rule_id)

        if not dry_run and applied:
            data["rules"] = list(rule_map.values())
            with rules_path.open("w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            new_version = pe.reload()
            return {"applied": len(applied), "rules": applied, "new_version": new_version}

        return {"applied": len(applied) if not dry_run else 0, "would_apply": applied, "dry_run": dry_run}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# D4 — Model Feedback: Failed decisions → shadow training signals
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ModelFeedbackSignal:
    entity_id: str
    features: List[float]
    true_label: int            # 0=benign, 1=malicious
    decision: str              # what the model decided
    was_correct: bool
    trust_score: float
    source: str = "feedback_loop"


class ModelFeedback:
    """
    Routes incorrect decisions to vanguard_brain's shadow learning buffers.

    When a decision is confirmed wrong:
      - false_positive (ISOLATE/RATE_LIMIT on benign) → add to hard_buffer with label=0
      - false_negative (ALLOW on malicious)           → add to hard_buffer with label=1

    Hard buffer samples are prioritised in shadow retraining (70/30 hard/recent mix).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: List[ModelFeedbackSignal] = []
        self._stats = {"fp": 0, "fn": 0, "total_routed": 0}

        t = threading.Thread(target=self._route_loop, daemon=True, name="model-feedback")
        t.start()

    def submit(
        self,
        entity_id: str,
        features: List[float],
        decision: str,
        true_label: int,
        trust_score: float,
        source: str = "feedback_loop",
    ) -> None:
        benign_actions = {"ALLOW"}
        correct = (true_label == 0 and decision in benign_actions) or \
                  (true_label == 1 and decision not in benign_actions)

        signal = ModelFeedbackSignal(
            entity_id=entity_id,
            features=features,
            true_label=true_label,
            decision=decision,
            was_correct=correct,
            trust_score=trust_score,
            source=source,
        )
        with self._lock:
            self._pending.append(signal)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def _route_loop(self) -> None:
        while True:
            time.sleep(10)
            with self._lock:
                batch = list(self._pending)
                self._pending.clear()
            if batch:
                self._route_to_brain(batch)

    def _route_to_brain(self, batch: List[ModelFeedbackSignal]) -> None:
        try:
            import vanguard_brain as vb
            brain = vb.get_engine()
            if brain is None or not hasattr(brain, "hard_buffer"):
                return

            import numpy as np
            import torch

            routed = 0
            for sig in batch:
                if sig.was_correct:
                    continue   # only route mistakes
                try:
                    feat = np.array(sig.features, dtype=np.float32)
                    label = sig.true_label
                    with brain._buffer_lock:
                        brain.hard_buffer.append((feat, label))
                    if sig.true_label == 0:
                        with self._lock:
                            self._stats["fp"] += 1
                    else:
                        with self._lock:
                            self._stats["fn"] += 1
                    routed += 1
                except Exception:
                    pass

            with self._lock:
                self._stats["total_routed"] += routed

            if routed:
                logger.info(
                    "ModelFeedback: routed incorrect decisions to shadow buffer",
                    extra={"routed": routed, "batch_size": len(batch)},
                )
        except Exception as exc:
            logger.warning("ModelFeedback routing failed", extra={"error": str(exc)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Intelligence Layer — unified entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class IntelligenceLayer:
    """
    Aggregates all four D-phase subsystems.
    Initialized once at app startup; accessed via get_intelligence_layer().
    """

    def __init__(self) -> None:
        self.context = ContextIntelligence()
        self.feedback = FeedbackCollector()
        self.adjuster = PolicyAdjuster()
        self.model_feedback = ModelFeedback()
        logger.info("Intelligence Layer initialized (Phase D)")

    def enrich_context(self, entity_id: str, telemetry: Dict[str, Any]) -> ContextScore:
        return self.context.score(entity_id, telemetry)

    def record_feedback(
        self,
        tenant_id: str,
        entity_id: str,
        decision: str,
        true_label: int,
        rule_id: str,
        trust_score: float,
        features: Optional[List[float]] = None,
        context_composite: float = 0.5,
        source: str = "gateway_feedback",
    ) -> FeedbackRecord:
        rec = self.feedback.record(
            tenant_id=tenant_id,
            entity_id=entity_id,
            decision=decision,
            true_label=true_label,
            rule_id=rule_id,
            trust_score=trust_score,
            context_composite=context_composite,
            source=source,
        )
        # Route incorrect decisions to shadow buffer
        if features:
            self.model_feedback.submit(
                entity_id=entity_id,
                features=features,
                decision=decision,
                true_label=true_label,
                trust_score=trust_score,
                source=source,
            )
        return rec

    def get_adjustment_suggestions(
        self,
        tenant_id: Optional[str] = None,
        since_hours: float = 24.0,
        min_samples: int = 10,
    ) -> List[AdjustmentSuggestion]:
        return self.adjuster.analyze(
            self.feedback,
            tenant_id=tenant_id,
            since_hours=since_hours,
            min_samples=min_samples,
        )

    def apply_adjustments(self, dry_run: bool = True) -> Dict[str, Any]:
        suggestions = self.get_adjustment_suggestions(since_hours=48.0, min_samples=20)
        return self.adjuster.apply_suggestions(
            [s for s in suggestions if s.severity in ("TUNE_DOWN", "TUNE_UP")],
            dry_run=dry_run,
        )

    def health(self) -> Dict[str, Any]:
        fb_stats = self.feedback.get_rule_accuracy(since_hours=1.0, min_samples=1)
        return {
            "context_intelligence": "active",
            "feedback_rules_tracked": len(fb_stats),
            "model_feedback": self.model_feedback.get_stats(),
        }


# ────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ────────────────────────────────────────────────────────────────────────────

_intel: Optional[IntelligenceLayer] = None
_intel_lock = threading.Lock()


def get_intelligence_layer() -> IntelligenceLayer:
    global _intel
    if _intel is None:
        with _intel_lock:
            if _intel is None:
                _intel = IntelligenceLayer()
    return _intel
