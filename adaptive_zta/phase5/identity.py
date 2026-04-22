from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Cloud = Literal["AWS", "AZURE", "GCP"]


class EntityIdCollisionError(ValueError):
    pass


@dataclass
class IdentityRecord:
    uid: str
    cloud: Cloud
    service: str
    region: str


class GlobalIdentityRegistry:
    """Detects impossible-by-construction collisions and raises loudly."""

    def __init__(self) -> None:
        self._seen: dict[str, IdentityRecord] = {}

    def register(self, entity_id: str, record: IdentityRecord) -> None:
        existing = self._seen.get(entity_id)
        if existing and existing != record:
            raise EntityIdCollisionError(
                f"entity_id collision detected: {entity_id} maps to two principals"
            )
        self._seen[entity_id] = record


def _safe_component(value: str, name: str) -> str:
    comp = value.strip()
    if not comp:
        raise ValueError(f"{name} must be non-empty")
    if ":" in comp:
        raise ValueError(f"{name} cannot contain ':'")
    return comp


def build_entity_id(
    user_id: str,
    cloud: Cloud,
    service: str,
    region: str = None,
) -> str:
    uid = _safe_component(user_id, "user_id")
    svc = _safe_component(service, "service")
    parts = [uid, cloud, svc]
    if region is not None:
        parts.append(_safe_component(region, "region"))
    return ":".join(parts)


def principal_id(entity_id: str) -> str:
    """Returns canonical user principal segment for global shared state."""
    return entity_id.split(":", 1)[0]
