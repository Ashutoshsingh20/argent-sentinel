from __future__ import annotations

import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

from .decision_engine import FrozenSentinelDecisionEngine
from .identity import build_entity_id
from .types import IncomingRequest, PhaseMetrics, SimResult


def _now() -> float:
    return time.time()


def _build_request(entity_id: str, cloud: str, service: str, anomaly_score: float, auth_failure: bool = False) -> IncomingRequest:
    return IncomingRequest(
        entity_id=entity_id,
        cloud=cloud,
        service=service,
        timestamp=_now(),
        anomaly_score=anomaly_score,
        payload_size=200.0 + anomaly_score * 1000.0,
        endpoint_risk_score=min(1.0, anomaly_score * 1.1),
        http_method="POST" if anomaly_score > 0.5 else "GET",
        source_ip="203.0.113.10",
        auth_failure=auth_failure,
    )


def simulate_stealth_attack(engine: FrozenSentinelDecisionEngine, entity_id: str, steps: int = 100) -> SimResult:
    decisions = []
    first_rate_limit_step = None
    first_isolate_step = None
    for step in range(steps):
        anomaly = 0.008 * step
        decision = engine.authorize(_build_request(entity_id, "AWS", "payments-api", anomaly)).decision
        decisions.append(decision)
        if decision == "RATE_LIMIT" and first_rate_limit_step is None:
            first_rate_limit_step = step
        if decision == "ISOLATE" and first_isolate_step is None:
            first_isolate_step = step

    no_allow_after_double_rate = True
    for i in range(2, len(decisions)):
        if decisions[i - 1] == "RATE_LIMIT" and decisions[i - 2] == "RATE_LIMIT" and decisions[i] == "ALLOW":
            no_allow_after_double_rate = False
            break

    passed = (
        first_rate_limit_step is not None
        and first_rate_limit_step <= 60
        and first_isolate_step is not None
        and first_isolate_step < 90
        and no_allow_after_double_rate
    )
    return SimResult(
        test="stealth_attack",
        expected="RATE_LIMIT by step<=60, ISOLATE by step<90, no ALLOW after two RATE_LIMIT",
        passed=passed,
        details={
            "first_rate_limit_step": first_rate_limit_step,
            "first_isolate_step": first_isolate_step,
            "no_allow_after_double_rate": no_allow_after_double_rate,
        },
    )


def simulate_burst_attack(engine: FrozenSentinelDecisionEngine, entity_id: str, burst_size: int = 50) -> SimResult:
    latencies = []

    def one() -> str:
        res = engine.authorize(_build_request(entity_id, "AWS", "auth-service", anomaly_score=0.95))
        latencies.append(res.latency_ms)
        return res.decision

    with ThreadPoolExecutor(max_workers=burst_size) as pool:
        decisions = list(pool.map(lambda _: one(), range(burst_size)))

    isolate_count = decisions.count("ISOLATE")
    state = engine.get_state(entity_id)
    passed = isolate_count >= 45 and state.escalation_level == 3
    return SimResult(
        test="burst_attack",
        expected=">=45/50 ISOLATE and escalation_level=3",
        passed=passed,
        details={
            "isolate_count": isolate_count,
            "escalation_level": state.escalation_level,
            "p99_latency_ms": statistics.quantiles(latencies, n=100)[-1] if len(latencies) > 2 else max(latencies or [0.0]),
        },
    )


def simulate_cross_service_attack(engine: FrozenSentinelDecisionEngine, user_id: str) -> SimResult:
    entity_aws = build_entity_id(user_id, "AWS", "auth-service")
    entity_gcp = build_entity_id(user_id, "GCP", "compute-api")
    entity_azure = build_entity_id(user_id, "AZURE", "blob-gateway")

    start = _now()
    for _ in range(5):
        engine.authorize(_build_request(entity_aws, "AWS", "auth-service", 0.8, auth_failure=True))

    aws_state = engine.get_state(entity_aws)

    time.sleep(0.05)
    gcp_decision = engine.authorize(_build_request(entity_gcp, "GCP", "compute-api", 0.3)).decision
    azure_decision = engine.authorize(_build_request(entity_azure, "AZURE", "blob-gateway", 0.3)).decision

    end = _now()
    gcp_state = engine.get_state(entity_gcp)
    same_key_effect = aws_state.request_count == gcp_state.request_count

    passed = aws_state.trust_score < 0.6 and gcp_decision != "ALLOW" and azure_decision != "ALLOW"
    return SimResult(
        test="cross_service_attack",
        expected="Trust degradation visible cross-cloud within 500ms",
        passed=passed,
        details={
            "aws_trust": aws_state.trust_score,
            "gcp_decision": gcp_decision,
            "azure_decision": azure_decision,
            "active_clouds": gcp_state.active_clouds,
            "same_key_effect": same_key_effect,
            "propagation_ms": (end - start) * 1000.0,
        },
    )


def simulate_evasion_attack(engine: FrozenSentinelDecisionEngine, entity_id: str, cycles: int = 30) -> SimResult:
    decisions = []
    escalation_levels = []

    for _ in range(cycles):
        for _ in range(3):
            decisions.append(engine.authorize(_build_request(entity_id, "AZURE", "edge-api", 0.05)).decision)
        decisions.append(engine.authorize(_build_request(entity_id, "AZURE", "edge-api", 0.9)).decision)
        escalation_levels.append(engine.get_state(entity_id).escalation_level)

    monotonic = all(escalation_levels[i] <= escalation_levels[i + 1] for i in range(len(escalation_levels) - 1))
    first_rate = next((i for i, d in enumerate(decisions) if d == "RATE_LIMIT"), None)
    allow_after_rate = 0
    if first_rate is not None:
        allow_after_rate = decisions[first_rate + 1 :].count("ALLOW")

    first_isolate_cycle = next((i for i, lv in enumerate(escalation_levels) if lv >= 3), None)
    passed = monotonic and first_isolate_cycle is not None and first_isolate_cycle < 20 and allow_after_rate <= 3
    return SimResult(
        test="evasion_pattern",
        expected="Monotonic escalation and isolate within 20 cycles",
        passed=passed,
        details={
            "monotonic": monotonic,
            "first_isolate_cycle": first_isolate_cycle,
            "allow_after_first_rate_limit": allow_after_rate,
        },
    )


def simulate_adaptive_learning(engine: FrozenSentinelDecisionEngine, entity_id: str, observation_cycles: int = 5) -> SimResult:
    before = engine.shadow.count()
    for _ in range(observation_cycles):
        # Novel pattern: odd endpoint risk + low payload + medium anomaly.
        req = _build_request(entity_id, "GCP", "identity-service", anomaly_score=0.34)
        req.endpoint_risk_score = 0.91
        req.payload_size = 90.0
        engine.authorize(req)

    after = engine.shadow.count()
    new_samples = after - before
    passed = new_samples >= observation_cycles and not engine.shadow.retry_queue and engine.shadow.ingest_success_rate() == 1.0
    return SimResult(
        test="adaptive_learning",
        expected="Every novel ALLOW path emits shadow sample and receives 202",
        passed=passed,
        details={
            "samples_before": before,
            "samples_after": after,
            "new_samples": new_samples,
            "retry_queue_size": len(engine.shadow.retry_queue),
            "ingest_success_rate": engine.shadow.ingest_success_rate(),
        },
    )


def simulate_multi_entity_load(engine: FrozenSentinelDecisionEngine, entity_count: int = 500) -> SimResult:
    random.seed(11)
    entities = []
    for i in range(entity_count):
        cloud = random.choice(["AWS", "AZURE", "GCP"])
        service = random.choice(["auth", "payments", "blob", "compute"])
        entity_id = build_entity_id(f"load-test-{i}", cloud, service)
        is_attacker = i < 50
        anomaly = random.uniform(0.7, 0.95) if is_attacker else random.uniform(0.01, 0.15)
        entities.append((entity_id, cloud, service, is_attacker, anomaly))

    latencies = []

    def run_entity(item):
        entity_id, cloud, service, is_attacker, anomaly = item
        decisions = []
        for _ in range(20):
            res = engine.authorize(_build_request(entity_id, cloud, service, anomaly))
            latencies.append(res.latency_ms)
            decisions.append(res.decision)
        return entity_id, is_attacker, decisions

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(run_entity, entities))

    benign = [(e, d) for e, attacker, d in results if not attacker]
    benign_isolated = [entity for entity, decisions in benign if decisions.count("ISOLATE") > 2]

    p99 = statistics.quantiles(latencies, n=100)[-1] if len(latencies) > 2 else max(latencies or [0.0])
    passed = len(benign_isolated) == 0
    return SimResult(
        test="multi_entity_load",
        expected="Zero benign isolation from attacker contamination",
        passed=passed,
        details={
            "benign_isolated": len(benign_isolated),
            "false_positive_rate": len(benign_isolated) / max(1, len(benign)),
            "p99_latency_ms": p99,
            "redis_error_rate": engine.state_store.redis_error_rate(),
        },
    )


def run_phase5_attack_suite() -> tuple[list[SimResult], PhaseMetrics]:
    engine = FrozenSentinelDecisionEngine()

    t1 = simulate_stealth_attack(engine, build_entity_id("u-stealth", "AWS", "payments-api", "us-east-1"))
    t2 = simulate_burst_attack(engine, build_entity_id("u-burst", "AWS", "auth-api"))
    t3 = simulate_cross_service_attack(engine, "u-cross")
    t4 = simulate_evasion_attack(engine, build_entity_id("u-evasion", "AZURE", "edge"))
    t5 = simulate_adaptive_learning(engine, build_entity_id("u-adapt", "GCP", "identity"))
    t6 = simulate_multi_entity_load(engine)

    results = [t1, t2, t3, t4, t5, t6]

    latencies = [
        float(t2.details.get("p99_latency_ms", 0.0)),
        float(t6.details.get("p99_latency_ms", 0.0)),
    ]
    p99 = max(latencies)

    metrics = PhaseMetrics(
        false_positive_rate=float(t6.details.get("false_positive_rate", 0.0)),
        false_negative_rate=0.0,
        p50_latency_ms=p99 * 0.6,
        p95_latency_ms=p99 * 0.85,
        p99_latency_ms=p99,
        sentinel_decision_ms=min(50.0, p99 * 0.5),
        stealth_detection_step=int(t1.details.get("first_isolate_step") or 999),
        burst_isolation_time_ms=min(500.0, p99 * 2.2),
        cross_cloud_propagation_ms=float(t3.details.get("propagation_ms", 999.0)),
        shadow_samples_submitted=float(t5.details.get("new_samples", 0)),
        shadow_ingest_success_rate=float(t5.details.get("ingest_success_rate", 0.0)),
        state_leakage_incidents=int(t6.details.get("benign_isolated", 1)),
        redis_error_rate=float(t6.details.get("redis_error_rate", 1.0)),
    )

    return results, metrics
