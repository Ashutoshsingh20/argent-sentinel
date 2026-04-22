from __future__ import annotations

import time
from contextlib import contextmanager

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

REQUEST_COUNT = Counter("argent_requests_total", "Total HTTP requests", ["method", "path", "status"])
ATTACK_DECISIONS = Counter("argent_attack_decisions_total", "Decision counts", ["decision"])
GATEWAY_LATENCY = Histogram("argent_gateway_latency_ms", "Gateway end-to-end latency in ms", buckets=(5, 10, 20, 30, 40, 50, 75, 100, 250))
SENTINEL_LATENCY = Histogram("argent_sentinel_latency_ms", "Sentinel decision latency in ms", buckets=(1, 2, 5, 10, 20, 30, 40, 50, 75, 100))


@contextmanager
def observe_gateway_latency() -> float:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        GATEWAY_LATENCY.observe((time.perf_counter() - t0) * 1000.0)


def observe_sentinel_latency(value_ms: float) -> None:
    SENTINEL_LATENCY.observe(max(0.0, float(value_ms)))


def inc_decision(decision: str) -> None:
    ATTACK_DECISIONS.labels(decision=decision).inc()


def inc_http(method: str, path: str, status: int) -> None:
    REQUEST_COUNT.labels(method=method, path=path, status=str(status)).inc()


def render_metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
