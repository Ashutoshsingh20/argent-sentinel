from __future__ import annotations

from typing import Any, Mapping, Optional

from pydantic import BaseModel, Field


class Intent(BaseModel):
    name: str
    target_type: str
    target_id: str
    risk_level: str
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


DEFAULT_DECISION_INTENT_MAP: dict[str, str] = {
    "deny": "block_request",
    "step_up": "monitor_entity",
    "allow": "monitor_entity",
    "rate_limit": "restrict_identity",
    "isolate": "isolate_compute",
    "revoke": "revoke_access",
}


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _get_value(decision: Any, key: str, default: Any = None) -> Any:
    if isinstance(decision, Mapping):
        return decision.get(key, default)
    return getattr(decision, key, default)


def _normalize_risk_level(trust_score: float) -> str:
    if trust_score < 0.3:
        return "high"
    if trust_score < 0.7:
        return "medium"
    return "low"


def _normalize_trust_score(raw_score: Any) -> float:
    try:
        value = float(raw_score)
    except (TypeError, ValueError):
        return 0.5
    if value > 1.0:
        value = value / 100.0
    return max(0.0, min(1.0, value))


def decision_to_intent(
    decision: Any,
    decision_map: Optional[Mapping[str, str]] = None,
) -> Intent:
    mapping = dict(DEFAULT_DECISION_INTENT_MAP)
    if decision_map:
        mapping.update({str(k).strip().lower(): str(v).strip() for k, v in decision_map.items()})

    action = _as_str(_get_value(decision, "action") or _get_value(decision, "decision"), "allow").strip().lower()
    trust_score = _normalize_trust_score(_get_value(decision, "trust_score"))
    reason = _as_str(
        _get_value(decision, "reason")
        or _get_value(decision, "decision_reason")
        or _get_value(decision, "policy_decision"),
        "decision-engine output",
    )

    target_id = _as_str(_get_value(decision, "target_id") or _get_value(decision, "entity_id") or _get_value(decision, "principal_id"), "unknown-target")
    target_type = _as_str(_get_value(decision, "target_type"), "user").strip().lower()

    # Explicit escalation path: low-trust allow converts to isolate intent.
    if action == "allow" and trust_score < 0.3:
        intent_name = "isolate_compute"
    else:
        intent_name = mapping.get(action, "monitor_entity")

    risk_level = _as_str(_get_value(decision, "risk_level"), _normalize_risk_level(trust_score)).strip().lower()
    if risk_level not in {"low", "medium", "high"}:
        risk_level = _normalize_risk_level(trust_score)

    metadata = {
        "decision_action": action,
        "decision_trust_score": trust_score,
    }

    source_metadata = _get_value(decision, "metadata")
    if isinstance(source_metadata, Mapping):
        metadata.update(dict(source_metadata))

    return Intent(
        name=intent_name,
        target_type=target_type,
        target_id=target_id,
        risk_level=risk_level,
        reason=reason,
        metadata=metadata,
    )
