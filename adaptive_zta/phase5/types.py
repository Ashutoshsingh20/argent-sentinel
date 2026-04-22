from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Decision = Literal["ALLOW", "RATE_LIMIT", "ISOLATE"]
Cloud = Literal["AWS", "AZURE", "GCP"]


@dataclass
class IncomingRequest:
    entity_id: str
    cloud: Cloud
    service: str
    timestamp: float
    anomaly_score: float
    payload_size: float = 0.0
    endpoint_risk_score: float = 0.0
    http_method: str = "GET"
    source_ip: str = "0.0.0.0"
    auth_failure: bool = False


@dataclass
class EntityState:
    trust_score: float
    anomaly_accumulator: float
    request_count: int
    failure_count: int
    last_decision: Decision
    last_seen_ts: float
    active_clouds: list[str]
    escalation_level: int
    services_5m: list[tuple[float, str]] = field(default_factory=list)

    @classmethod
    def default(cls, ts: float) -> "EntityState":
        return cls(
            trust_score=1.0,
            anomaly_accumulator=0.0,
            request_count=0,
            failure_count=0,
            last_decision="ALLOW",
            last_seen_ts=ts,
            active_clouds=[],
            escalation_level=0,
            services_5m=[],
        )


@dataclass
class ShadowSample:
    entity_id: str
    features: list[float]
    decision: Decision
    ground_truth: str
    confidence: float
    cloud: str
    service: str
    timestamp: float


@dataclass
class SimResult:
    test: str
    expected: str
    passed: bool
    details: dict[str, Any]


@dataclass
class PhaseMetrics:
    false_positive_rate: float
    false_negative_rate: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    sentinel_decision_ms: float
    stealth_detection_step: int
    burst_isolation_time_ms: float
    cross_cloud_propagation_ms: float
    shadow_samples_submitted: int
    shadow_ingest_success_rate: float
    state_leakage_incidents: int
    redis_error_rate: float

    TARGETS = {
        "false_positive_rate": 0.02,
        "false_negative_rate": 0.05,
        "p99_latency_ms": 150.0,
        "stealth_detection_step": 70,
        "burst_isolation_time_ms": 500.0,
        "cross_cloud_propagation_ms": 500.0,
        "state_leakage_incidents": 0,
        "redis_error_rate": 0.0001,
    }
