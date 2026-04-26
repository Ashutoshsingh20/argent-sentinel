from __future__ import annotations

import time
from contextlib import contextmanager

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

REQUEST_COUNT = Counter("argent_requests_total", "Total HTTP requests", ["tenant_id", "method", "path", "status"])
ATTACK_DECISIONS = Counter("argent_attack_decisions_total", "Decision counts", ["tenant_id", "decision"])
GATEWAY_LATENCY = Histogram("argent_gateway_latency_ms", "Gateway end-to-end latency in ms", ["tenant_id"], buckets=(5, 10, 20, 30, 40, 50, 75, 100, 250))
SENTINEL_LATENCY = Histogram("argent_sentinel_latency_ms", "Sentinel decision latency in ms", ["tenant_id"], buckets=(1, 2, 5, 10, 20, 30, 40, 50, 75, 100))


@contextmanager
def observe_gateway_latency(tenant_id: str = "default") -> float:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        GATEWAY_LATENCY.labels(tenant_id=tenant_id).observe((time.perf_counter() - t0) * 1000.0)


def observe_sentinel_latency(value_ms: float, tenant_id: str = "default") -> None:
    SENTINEL_LATENCY.labels(tenant_id=tenant_id).observe(max(0.0, float(value_ms)))


def inc_decision(decision: str, tenant_id: str = "default") -> None:
    ATTACK_DECISIONS.labels(tenant_id=tenant_id, decision=decision).inc()


def inc_http(method: str, path: str, status: int, tenant_id: str = "default") -> None:
    REQUEST_COUNT.labels(tenant_id=tenant_id, method=method, path=path, status=str(status)).inc()


def render_metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
