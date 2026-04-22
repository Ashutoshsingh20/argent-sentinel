from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass
from typing import Awaitable, Callable

from .decision_engine import FrozenSentinelDecisionEngine
from .types import Decision, IncomingRequest


@dataclass
class GatewayTelemetryEvent:
    entity_id: str
    decision: Decision
    cloud: str
    service: str
    sentinel_latency_ms: float
    gateway_latency_ms: float
    timestamp: float


class MetricsBus:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: GatewayTelemetryEvent) -> None:
        self.events.append(asdict(event))


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_after_seconds: float = 10.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_after_seconds = reset_after_seconds
        self.failures = 0
        self.opened_at = 0.0

    def can_call(self) -> bool:
        if self.failures < self.failure_threshold:
            return True
        if (time.time() - self.opened_at) >= self.reset_after_seconds:
            self.failures = 0
            self.opened_at = 0.0
            return True
        return False

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = 0.0

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold and self.opened_at == 0.0:
            self.opened_at = time.time()


class AdaptiveGateway:
    """Fail-closed gateway wrapper with circuit breaker and structured telemetry."""

    def __init__(self, sentinel: FrozenSentinelDecisionEngine = None) -> None:
        self.sentinel = sentinel or FrozenSentinelDecisionEngine()
        self.breaker = CircuitBreaker()
        self.metrics = MetricsBus()

    def handle_request(
        self,
        request: IncomingRequest,
        forward: Callable[[IncomingRequest], dict],
        throttle: Callable[[IncomingRequest], dict],
        block: Callable[[IncomingRequest], dict],
        timeout_ms: int = 50,
    ) -> dict:
        t0 = time.perf_counter()

        if not self.breaker.can_call():
            decision: Decision = "ISOLATE"
            sentinel_ms = float(timeout_ms)
        else:
            try:
                result = self.sentinel.authorize(request, timeout_ms=timeout_ms)
                decision = result.decision
                sentinel_ms = result.latency_ms
                self.breaker.record_success()
            except Exception:
                self.breaker.record_failure()
                decision = "ISOLATE"
                sentinel_ms = float(timeout_ms)

        if decision == "ALLOW":
            response = forward(request)
        elif decision == "RATE_LIMIT":
            response = throttle(request)
        else:
            response = block(request)

        gateway_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.emit(
            GatewayTelemetryEvent(
                entity_id=request.entity_id,
                decision=decision,
                cloud=request.cloud,
                service=request.service,
                sentinel_latency_ms=sentinel_ms,
                gateway_latency_ms=gateway_ms,
                timestamp=time.time(),
            )
        )
        return response

    async def handle_request_async(
        self,
        request: IncomingRequest,
        forward: Callable[[IncomingRequest], Awaitable[dict]],
        throttle: Callable[[IncomingRequest], Awaitable[dict]],
        block: Callable[[IncomingRequest], Awaitable[dict]],
        timeout_ms: int = 50,
    ) -> dict:
        t0 = time.perf_counter()

        if not self.breaker.can_call():
            decision: Decision = "ISOLATE"
            sentinel_ms = float(timeout_ms)
        else:
            try:
                result = await asyncio.to_thread(self.sentinel.authorize, request, timeout_ms)
                decision = result.decision
                sentinel_ms = result.latency_ms
                self.breaker.record_success()
            except Exception:
                self.breaker.record_failure()
                decision = "ISOLATE"
                sentinel_ms = float(timeout_ms)

        if decision == "ALLOW":
            response = await forward(request)
        elif decision == "RATE_LIMIT":
            response = await throttle(request)
        else:
            response = await block(request)

        gateway_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.emit(
            GatewayTelemetryEvent(
                entity_id=request.entity_id,
                decision=decision,
                cloud=request.cloud,
                service=request.service,
                sentinel_latency_ms=sentinel_ms,
                gateway_latency_ms=gateway_ms,
                timestamp=time.time(),
            )
        )
        return response
