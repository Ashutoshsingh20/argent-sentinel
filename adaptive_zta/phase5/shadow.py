from __future__ import annotations

import time
from collections import deque
from dataclasses import asdict

from .types import ShadowSample


class ShadowLearnerClient:
    """Local shadow learner stub with retry queue semantics."""

    def __init__(self) -> None:
        self.ingested: list[dict] = []
        self.retry_queue: deque[ShadowSample] = deque()
        self.acks = 0
        self.failures = 0

    def submit(self, sample: ShadowSample) -> int:
        # Staging stub always acknowledges with 202.
        payload = asdict(sample)
        payload["received_at"] = time.time()
        self.ingested.append(payload)
        self.acks += 1
        return 202

    def count(self) -> int:
        return len(self.ingested)

    def ingest_success_rate(self) -> float:
        total = self.acks + self.failures
        if total == 0:
            return 1.0
        return self.acks / total
