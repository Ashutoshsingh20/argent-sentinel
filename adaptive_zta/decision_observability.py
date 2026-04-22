from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from fastapi import BackgroundTasks
from pydantic import BaseModel, Field

import database as db


class DecisionRecordIn(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str
    input_features: Dict[str, Any] = Field(default_factory=dict)
    risk_score: Optional[float] = None
    trust_score: Optional[float] = None
    policy_decision: Optional[str] = None
    final_action: Optional[str] = None
    latency_ms: Optional[float] = None
    status: Literal["success", "error"]
    error_message: Optional[str] = None
    entity_id: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class DecisionRecordOut(DecisionRecordIn):
    pass


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _normalize_extra(extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    payload = dict(extra or {})
    payload.setdefault("intent", None)
    payload.setdefault("compiled_actions", [])
    payload.setdefault("execution_status", None)
    return _json_safe(payload)


class DecisionObservability:
    def __init__(self, buffer_size: int = 100):
        self._buffer: deque[Dict[str, Any]] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()

    def build_record(
        self,
        *,
        source: str,
        status: Literal["success", "error"],
        request_id: Optional[str] = None,
        entity_id: Optional[str] = None,
        input_features: Optional[Dict[str, Any]] = None,
        risk_score: Optional[float] = None,
        trust_score: Optional[float] = None,
        policy_decision: Optional[str] = None,
        final_action: Optional[str] = None,
        latency_ms: Optional[float] = None,
        error_message: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> DecisionRecordIn:
        return DecisionRecordIn(
            request_id=request_id or str(uuid4()),
            source=source,
            entity_id=entity_id,
            input_features=_json_safe(input_features or {}),
            risk_score=risk_score,
            trust_score=trust_score,
            policy_decision=policy_decision,
            final_action=final_action,
            latency_ms=latency_ms,
            status=status,
            error_message=error_message,
            extra=_normalize_extra(extra),
        )

    def emit(self, record: DecisionRecordIn, background_tasks: Optional[BackgroundTasks] = None) -> None:
        payload = record.model_dump()
        with self._lock:
            self._buffer.append(payload)

        if background_tasks is not None:
            background_tasks.add_task(self._persist_safe, payload)
            return

        thread = threading.Thread(target=self._persist_safe, args=(payload,), daemon=True)
        thread.start()

    def _persist_safe(self, payload: Dict[str, Any]) -> None:
        session = db.SessionLocal()
        try:
            row = db.DecisionRecord(
                request_id=str(payload.get("request_id", "")),
                timestamp=str(payload.get("timestamp", "")),
                source=str(payload.get("source", "unknown")),
                entity_id=payload.get("entity_id"),
                input_features=payload.get("input_features") or {},
                risk_score=payload.get("risk_score"),
                trust_score=payload.get("trust_score"),
                policy_decision=payload.get("policy_decision"),
                final_action=payload.get("final_action"),
                latency_ms=payload.get("latency_ms"),
                status=str(payload.get("status", "error")),
                error_message=payload.get("error_message"),
                extra=payload.get("extra") or {},
            )
            session.add(row)
            session.commit()
        except Exception:
            # Observability must never break request execution.
            session.rollback()
        finally:
            session.close()

    def recent_from_db(
        self,
        *,
        limit: int = 50,
        final_action: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[DecisionRecordOut]:
        lim = max(1, min(int(limit), 200))
        session = db.SessionLocal()
        try:
            query = session.query(db.DecisionRecord)
            if final_action:
                query = query.filter(db.DecisionRecord.final_action == final_action)
            if status:
                query = query.filter(db.DecisionRecord.status == status)

            rows = query.order_by(db.DecisionRecord.id.desc()).limit(lim).all()
            return [
                DecisionRecordOut(
                    request_id=row.request_id,
                    timestamp=row.timestamp,
                    source=row.source,
                    entity_id=row.entity_id,
                    input_features=row.input_features or {},
                    risk_score=row.risk_score,
                    trust_score=row.trust_score,
                    policy_decision=row.policy_decision,
                    final_action=row.final_action,
                    latency_ms=row.latency_ms,
                    status=row.status,
                    error_message=row.error_message,
                    extra=row.extra or {},
                )
                for row in rows
            ]
        except Exception:
            # Safe degradation: fallback to ring buffer.
            with self._lock:
                items = list(self._buffer)[-lim:]
            items.reverse()
            result: List[DecisionRecordOut] = []
            for item in items:
                if final_action and item.get("final_action") != final_action:
                    continue
                if status and item.get("status") != status:
                    continue
                result.append(DecisionRecordOut(**item))
            return result[:lim]
        finally:
            session.close()


observability = DecisionObservability(buffer_size=100)
