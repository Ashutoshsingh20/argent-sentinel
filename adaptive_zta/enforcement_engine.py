"""
Argent Sentinel — Enforcement Engine (Phase A enhanced)
=======================================================
Two distinct operation modes:

1. EnforcementEngine (legacy batch)
   — reads CSV trust scores, applies decisions offline.
   — kept for research/evaluation pipeline.

2. LiveEnforcementEngine (Phase A online)
   — called on the hot request path (authorize / gateway).
   — combines PolicyEngine + PolicyOverrideStore with model trust score.
   — produces a single, auditable EnforcementDecision per event.
   — writes to PolicyAuditLog asynchronously.
"""

from __future__ import annotations

import json
import logging
import time
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional



logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Online decision dataclass
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class EnforcementDecision:
    """Single authoritative outcome for a request."""
    action: str                    # ALLOW | RATE_LIMIT | ISOLATE
    rule_id: str
    policy_version: str
    reason: str
    confidence: float
    trust_score: float
    override_id: Optional[str]
    override_type: Optional[str]
    matched_rules: List[str]       # rule_ids
    simulation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "rule_id": self.rule_id,
            "policy_version": self.policy_version,
            "reason": self.reason,
            "confidence": round(self.confidence, 4),
            "trust_score": round(self.trust_score, 2),
            "override_id": self.override_id,
            "override_type": self.override_type,
            "matched_rules": self.matched_rules,
            "simulation": self.simulation,
        }


# ────────────────────────────────────────────────────────────────────────────
# LiveEnforcementEngine
# ────────────────────────────────────────────────────────────────────────────

class LiveEnforcementEngine:
    """
    Online enforcement engine — replaces inline threshold checks in app.py.

    Flow per request:
      1. Check override store → if forced action, return immediately.
      2. Build context dict from telemetry + model output.
      3. Evaluate PolicyEngine rules (with conflict resolution).
      4. Return EnforcementDecision.
      5. Async: write PolicyAuditLog row.

    Thread-safe: uses internal audit queue with background writer.
    """

    def __init__(self, audit_async: bool = True) -> None:
        from policy_engine import get_policy_engine
        from policy_overrides import get_override_store

        self._policy = get_policy_engine()
        self._overrides = get_override_store()
        self._audit_async = audit_async

        if audit_async:
            self._audit_queue: List[Dict[str, Any]] = []
            self._audit_lock = threading.Lock()
            self._audit_thread = threading.Thread(
                target=self._audit_writer, daemon=True, name="enforcement-audit"
            )
            self._audit_thread.start()

    # ── Hot path ──────────────────────────────────────────────────────────

    def decide(
        self,
        entity_id: str,
        trust_score: float,
        telemetry: Dict[str, Any],
        tenant_id: str = "default",
        source: str = "authorize",
        simulation: bool = False,
    ) -> EnforcementDecision:
        """
        Main entry point. Called once per request.

        telemetry dict should contain raw fields:
          geo_anomaly_flag, failed_auth_count, protocol_type,
          entity_type, traversal_depth, api_rate, payload_size,
          session_duration, cloud_env — plus computed trust_score.
        """
        # 1. Override check (O(1))
        override = self._overrides.resolve(tenant_id, entity_id)
        if override and override.forced_action is not None:
            decision = EnforcementDecision(
                action=override.forced_action,
                rule_id=f"OVERRIDE:{override.override_type}",
                policy_version=self._policy.version,
                reason=f"Policy override active [{override.override_type}]",
                confidence=1.0,
                trust_score=trust_score,
                override_id=override.override_id,
                override_type=override.override_type,
                matched_rules=[],
                simulation=simulation,
            )
            self._enqueue_audit(decision, entity_id, tenant_id, source)
            return decision

        # 2. Build eval context
        ctx = self._build_context(trust_score, telemetry)

        # 3. Mask skipped rules (SKIP_RULES override)
        skip_ids: List[str] = []
        if override and override.skip_rule_ids:
            skip_ids = override.skip_rule_ids

        # 4. Policy evaluation
        pd_result = self._policy.evaluate(ctx, tenant_id=tenant_id, simulation=simulation)

        # Filter out skipped rules from matched list
        effective_action = pd_result.action
        effective_rule_id = pd_result.rule_id
        effective_reason = pd_result.reason
        if skip_ids and pd_result.rule_id in skip_ids:
            # Re-evaluate excluding skipped rules — simplification: use fallback
            non_skipped = [m for m in pd_result.matched_rules if m.rule_id not in skip_ids]
            if non_skipped:
                from policy_engine import _ACTION_SEVERITY
                best = max(non_skipped, key=lambda m: (_ACTION_SEVERITY.get(m.action, 0), m.conflict_weight))
                effective_action = best.action
                effective_rule_id = best.rule_id
                effective_reason = best.reason
            else:
                effective_action = "ALLOW"
                effective_rule_id = "FALLBACK_SKIP"
                effective_reason = "All matched rules were skipped by override"

        # 5. Apply CUSTOM_THRESHOLD override if present
        if override and override.threshold_overrides:
            thr = override.threshold_overrides
            effective_action = self._apply_custom_thresholds(
                trust_score, thr, effective_action
            )

        matched_ids = [m.rule_id for m in pd_result.matched_rules]
        decision = EnforcementDecision(
            action=effective_action,
            rule_id=effective_rule_id,
            policy_version=pd_result.policy_version,
            reason=effective_reason,
            confidence=pd_result.confidence,
            trust_score=trust_score,
            override_id=override.override_id if override else None,
            override_type=override.override_type if override else None,
            matched_rules=matched_ids,
            simulation=simulation,
        )
        self._enqueue_audit(decision, entity_id, tenant_id, source)
        return decision

    @staticmethod
    def _build_context(trust_score: float, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        ctx = dict(telemetry)
        ctx["trust_score"] = float(trust_score)
        # Normalise protocol to uppercase
        proto = str(ctx.get("protocol_type", "HTTPS")).upper()
        if proto not in ("HTTPS", "HTTP", "SSH"):
            proto = "HTTPS"
        ctx["protocol_type"] = proto
        return ctx

    @staticmethod
    def _apply_custom_thresholds(
        trust_score: float, thr: Dict[str, float], current_action: str
    ) -> str:
        isolate_thr = thr.get("isolate", 48.0)
        rate_limit_thr = thr.get("rate_limit", 65.0)
        if trust_score < isolate_thr:
            return "ISOLATE"
        if trust_score < rate_limit_thr:
            return "RATE_LIMIT"
        return "ALLOW"

    # ── Audit trail ───────────────────────────────────────────────────────

    def _enqueue_audit(
        self,
        decision: EnforcementDecision,
        entity_id: str,
        tenant_id: str,
        source: str,
    ) -> None:
        record = {
            "tenant_id": tenant_id,
            "entity_id": entity_id,
            "timestamp": time.time(),
            "rule_id": decision.rule_id,
            "policy_version": decision.policy_version,
            "action": decision.action,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "override_id": decision.override_id,
            "override_type": decision.override_type,
            "trust_score": decision.trust_score,
            "source": source,
            "matched_rules": json.dumps(decision.matched_rules),
            "simulation": 1 if decision.simulation else 0,
        }
        if self._audit_async:
            with self._audit_lock:
                self._audit_queue.append(record)
        else:
            self._write_audit([record])

    def _audit_writer(self) -> None:
        while True:
            time.sleep(2)
            with self._audit_lock:
                batch = list(self._audit_queue)
                self._audit_queue.clear()
            if batch:
                try:
                    self._write_audit(batch)
                except Exception as exc:
                    logger.warning("Audit write failed", extra={"error": str(exc), "dropped": len(batch)})

    @staticmethod
    def _write_audit(records: List[Dict[str, Any]]) -> None:
        import database as db
        s = db.SessionLocal()
        try:
            for rec in records:
                s.add(db.PolicyAuditLog(**rec))
            s.commit()
        except Exception as exc:
            s.rollback()
            logger.warning("Audit DB write failed", extra={"error": str(exc)})
        finally:
            s.close()


# ────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ────────────────────────────────────────────────────────────────────────────

_live_engine: Optional[LiveEnforcementEngine] = None
_live_lock = threading.Lock()


def get_live_enforcement_engine() -> LiveEnforcementEngine:
    global _live_engine
    if _live_engine is None:
        with _live_lock:
            if _live_engine is None:
                _live_engine = LiveEnforcementEngine(audit_async=True)
    return _live_engine




    def __init__(self, data_path='outputs/trust_scores.csv'):
        import pandas as pd
        self.df = pd.read_csv(data_path)
        self.telemetry = pd.read_csv('outputs/behavioral_scores.csv')
        self.df = pd.merge(self.df, self.telemetry[['entity_id', 'timestep', 'timestamp']], on=['entity_id', 'timestep'])
        self.df = self.df.sort_values(['entity_id', 'timestep']).reset_index(drop=True)
        
    def _apply_decisions(self):
        conditions = [
            (self.df['trust_score'] > 70),
            (self.df['trust_score'] >= 40) & (self.df['trust_score'] <= 70),
            (self.df['trust_score'] < 40)
        ]
        choices = ['ALLOW', 'RATE_LIMIT', 'ISOLATE']
        import numpy as np
        self.df['decision'] = np.select(conditions, choices, default='ALLOW')
        
    def _apply_special_rules(self):
        # 1. RAPID-DECAY: Trust diff < -30 in < 5 timesteps
        # We can implement this by comparing T(t) with max(T(t-4) .. T(t-1))
        # If T(t) - max_past_5 < -30, then rapid decay.
        
        # 2. ESCALATION: ISOLATE for > 10 consecutive steps
        grouped = self.df.groupby('entity_id')
        
        # Calculate Rolling Max of past 4 timesteps properly (window=5 because it includes current)
        rolling_max = grouped['trust_score'].transform(lambda x: x.rolling(5, min_periods=1).max())
        
        self.df['rapid_decay'] = (self.df['trust_score'] - rolling_max) < -30
        
        # Consecutive ISOLATE count
        isolate_mask = self.df['decision'] == 'ISOLATE'
        
        # A trick to group consecutive True blocks
        consec_blocks = isolate_mask != isolate_mask.shift()
        idx_groups = consec_blocks.groupby(self.df['entity_id']).cumsum()
        
        # Count consecutive run length
        run_lengths = self.df.groupby(['entity_id', idx_groups]).cumcount() + 1
        
        # But we only want run length where isolate is True
        import numpy as np
        isolate_runs = np.where(isolate_mask, run_lengths, 0)
        self.df['escalated_flag'] = isolate_runs > 10

        import numpy as np
        self.df['reason'] = np.where(
            self.df['rapid_decay'], 'SOC_ALERT_RAPID_DECAY',
            np.where(self.df['escalated_flag'], 'PERM_BLOCK_ESCALATION', 'NORMAL_POLICY')
        )
        # Even if T > 40, if rapid decay triggers, it might be allowed but flag reason SOC_ALERT.
        # But wait, does rapid-decay ENFORCE an action? The prompt says: "immediate SOC alert", it doesn't say it changes the ALLOW/RATE_LIMIT/ISOLATE decision block. It just logs it.
        # Permanent block flag does mean manual review required. So that sets 'escalated_flag'=1.

    def format_log(self):
        self._apply_decisions()
        self._apply_special_rules()
        
        log_cols = ['entity_id', 'timestamp', 'trust_score', 'decision', 'reason', 'escalated_flag']
        self.log_df = self.df[log_cols]
        self.log_df.to_csv('outputs/enforcement_log.csv', index=False)
        return self.log_df

if __name__ == '__main__':
    engine = EnforcementEngine()
    log_df = engine.format_log()
    
    print("\n■ STEP 6 COMPLETE: Trust Engine + Enforcement Engine")
    
    print("\n› T(t) Stats at t=600:")
    t600 = log_df.loc[engine.df['timestep'] == 599]
    print(t600['trust_score'].describe())
    
    print("\n› Enforcement Action Breakdown:")
    print(log_df['decision'].value_counts())
    
    # Rapid Decay alerts count (how many true)
    rapid_alerts = engine.df['rapid_decay'].sum()
    print(f"\n› Rapid-Decay Alerts Fired: {rapid_alerts}")
    
    # Escalations (unique entities and count)
    escalations = log_df[log_df['escalated_flag']]
    print(f"› Escalation Flags Fired: {len(escalations)} (affecting {escalations['entity_id'].nunique()} distinct entities)")
    
    print("\n→ HALT. Await: 'proceed to Step 7'")
