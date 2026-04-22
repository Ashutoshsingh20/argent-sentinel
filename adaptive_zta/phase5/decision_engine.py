from __future__ import annotations

import time
from dataclasses import dataclass

from .identity import GlobalIdentityRegistry, IdentityRecord, principal_id
from .policy import PolicyAbstractionLayer
from .shadow import ShadowLearnerClient
from .state_store import RedisEntityStateStore
from .types import Decision, IncomingRequest, ShadowSample


MAX_PAYLOAD = 5000.0
MAX_FAILURES = 20.0
MAX_ANOMALY = 2.0
FEATURE_SCHEMA_VERSION = 1


def _clip01(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass
class DecisionResult:
    decision: Decision
    confidence: float
    latency_ms: float
    features: list[float]
    escalation_level: int
    trust_score: float


class FrozenSentinelDecisionEngine:
    """Inference-time architecture only; frozen model policy and deterministic thresholds."""

    def __init__(self, state_store: RedisEntityStateStore = None) -> None:
        self.state_store = state_store or RedisEntityStateStore.from_env()
        self.policy = PolicyAbstractionLayer()
        self.shadow = ShadowLearnerClient()
        self.registry = GlobalIdentityRegistry()

        self.decision_budget_ms = 50.0
        self.feature_budget_ms = 10.0
        self.schema_version = FEATURE_SCHEMA_VERSION
        self._last_auth_failure_by_principal: dict[str, float] = {}

    def register_entity(self, request: IncomingRequest) -> None:
        parts = request.entity_id.split(":")
        if len(parts) < 3:
            raise ValueError("entity_id must be canonical: uid:cloud:service[:region]")
        self.registry.register(
            request.entity_id,
            IdentityRecord(uid=parts[0], cloud=request.cloud, service=request.service, region=parts[3] if len(parts) > 3 else None),
        )

    def build_feature_vector(self, request: IncomingRequest) -> tuple[list[float], float]:
        t0 = time.perf_counter()
        state = self.state_store.get_entity_state(request.entity_id, now_ts=request.timestamp)

        req_features = [
            _clip01(request.payload_size / MAX_PAYLOAD),
            _clip01(request.endpoint_risk_score),
            0.0 if request.http_method == "GET" else 0.5 if request.http_method == "POST" else 1.0,
            _clip01(((request.timestamp % 86400.0) / 86400.0)),
            _clip01(request.anomaly_score),
        ]

        recent_services = [svc for ts, svc in state.services_5m if request.timestamp - ts <= 300.0]
        if request.service not in recent_services:
            recent_services.append(request.service)

        total = max(1, state.request_count)
        cross_features = [
            _clip01(state.trust_score),
            _clip01(state.anomaly_accumulator / MAX_ANOMALY),
            _clip01(state.failure_count / MAX_FAILURES),
            _clip01(len(state.active_clouds) / 3.0),
            _clip01((state.request_count / max(1.0, (request.timestamp - state.last_seen_ts + 1.0))) / 10.0),
            _clip01((state.anomaly_accumulator + state.failure_count * 0.1) / 3.0),
            _clip01(len(set(recent_services)) / 10.0),
            _clip01(state.failure_count / total),
        ]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return req_features + cross_features, elapsed_ms

    def _decide(self, risk: float, current_level: int) -> tuple[Decision, int]:
        # Hysteresis: escalation can only move up in the same session.
        if risk >= 0.75:
            return "ISOLATE", max(current_level, 3)
        if risk >= 0.50:
            return "RATE_LIMIT", max(current_level, 2)
        if current_level >= 2:
            return "RATE_LIMIT", current_level
        return "ALLOW", current_level

    def _estimate_confidence(self, request: IncomingRequest, trust_score: float) -> float:
        # Lower confidence for novel/high-entropy combinations that often indicate unseen attack patterns.
        payload_norm = _clip01(request.payload_size / MAX_PAYLOAD)
        novelty = abs(request.endpoint_risk_score - request.anomaly_score) + abs(payload_norm - request.anomaly_score)
        base = 1.0 - abs(0.5 - trust_score)
        return _clip01(base - 0.45 * novelty)

    def authorize(self, request: IncomingRequest, timeout_ms: int = 50, dry_run: bool = False) -> DecisionResult:
        start = time.perf_counter()
        self.register_entity(request)

        features, feature_ms = self.build_feature_vector(request)
        degraded_mode = feature_ms > self.feature_budget_ms

        def updater(state):
            state.request_count += 1
            state.last_seen_ts = request.timestamp
            if request.cloud not in state.active_clouds:
                state.active_clouds.append(request.cloud)
            state.services_5m = [item for item in state.services_5m if request.timestamp - item[0] <= 300.0]
            state.services_5m.append((request.timestamp, request.service))
            state.anomaly_accumulator = _clip01(state.anomaly_accumulator * 0.985 + request.anomaly_score * 0.25)
            if request.auth_failure:
                state.failure_count += 1
                self._last_auth_failure_by_principal[principal_id(request.entity_id)] = request.timestamp
            derived_risk = _clip01(
                request.anomaly_score * 0.65
                + state.anomaly_accumulator * 0.35
                + _clip01(state.failure_count / MAX_FAILURES) * 0.15
            )
            decision, level = self._decide(derived_risk, state.escalation_level)
            state.escalation_level = level
            state.last_decision = decision
            state.trust_score = _clip01(1.0 - derived_risk)
            return state

        state = self.state_store.update_entity_state(request.entity_id, updater, now_ts=request.timestamp)
        decision = state.last_decision
        confidence = self._estimate_confidence(request, state.trust_score)

        if degraded_mode:
            # Under burst pressure, remain fail-safe and deterministic without throwing.
            if state.escalation_level >= 3:
                decision = "ISOLATE"
            elif state.escalation_level >= 2:
                decision = "RATE_LIMIT"
            confidence = min(confidence, 0.6)

        # Synchronous audited policy enforcement.
        self.policy.enforce(decision, request.cloud, request.entity_id, dry_run=dry_run)

        latency_ms = (time.perf_counter() - start) * 1000.0
        if latency_ms > timeout_ms or latency_ms > self.decision_budget_ms:
            # SLA breach fallback: keep prior deterministic decision and continue.
            if state.escalation_level >= 3:
                decision = "ISOLATE"
            elif state.escalation_level >= 2:
                decision = "RATE_LIMIT"
            confidence = min(confidence, 0.55)

        # Shadow sample criteria.
        prev_fail_ts = self._last_auth_failure_by_principal.get(principal_id(request.entity_id), 0.0)
        submit_shadow = (
            confidence < 0.65
            or (decision == "ISOLATE" and state.trust_score > 0.8)
            or (decision == "ALLOW" and (request.timestamp - prev_fail_ts) <= 30.0)
            or state.escalation_level > 0
        )
        if submit_shadow:
            self.shadow.submit(
                ShadowSample(
                    entity_id=request.entity_id,
                    features=features,
                    decision=decision,
                    ground_truth=None,
                    confidence=confidence,
                    cloud=request.cloud,
                    service=request.service,
                    timestamp=request.timestamp,
                )
            )

        return DecisionResult(
            decision=decision,
            confidence=confidence,
            latency_ms=latency_ms,
            features=features,
            escalation_level=state.escalation_level,
            trust_score=state.trust_score,
        )

    def get_state(self, entity_id: str):
        return self.state_store.get_entity_state(entity_id)
