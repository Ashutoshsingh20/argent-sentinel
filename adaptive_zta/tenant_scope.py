"""
tenant_scope.py — Namespace utilities for per-tenant state isolation.

All shared state (hot state, feature cache, in-memory dicts) MUST use
these helpers to construct keys. Never build tenant-scoped keys inline.

Key format:
    entity_key("acme", "ENT-001")       → "acme:ENT-001"
    hot_key("trust", "acme", "ENT-001") → "trust:acme:ENT-001"
    cache_key("acme", "ENT-001")        → "feat:acme:ENT-001"
    alert_key("acme", "CB_OPEN")        → "acme:CB_OPEN"
"""
from __future__ import annotations


def entity_key(tenant_id: str, entity_id: str) -> str:
    """Canonical scoped entity key."""
    return f"{tenant_id}:{entity_id}"


def hot_key(prefix: str, tenant_id: str, entity_id: str) -> str:
    """Hot state key with prefix (trust, status, history)."""
    return f"{prefix}:{tenant_id}:{entity_id}"


def cache_key(tenant_id: str, entity_id: str) -> str:
    """Feature cache key."""
    return f"feat:{tenant_id}:{entity_id}"


def alert_key(tenant_id: str, rule_id: str) -> str:
    """Alert firing-rule key."""
    return f"{tenant_id}:{rule_id}"
