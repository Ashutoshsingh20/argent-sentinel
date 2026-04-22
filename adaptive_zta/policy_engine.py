"""
Argent Sentinel — Policy Engine (Phase A)
=========================================
Multi-rule declarative policy evaluation with:
  - YAML rule DSL loading (per-tenant support)
  - Priority ordering + conflict resolution (most-severe wins)
  - Policy versioning (every decision tagged with version hash)
  - Hot-reload without restart (file mtime polling)
  - Simulation / dry-run mode
  - Full match audit trail per evaluation
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

try:
    import yaml  # PyYAML
except ImportError:
    yaml = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

Action = Literal["ALLOW", "RATE_LIMIT", "ISOLATE"]

_ACTION_SEVERITY: Dict[str, int] = {
    "ALLOW": 0,
    "RATE_LIMIT": 1,
    "ISOLATE": 2,
}

_OPS = {
    "eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "regex"
}


@dataclass
class PolicyCondition:
    field: str
    op: str
    value: Any

    def evaluate(self, ctx: Dict[str, Any]) -> bool:
        if ctx is None:
            return False
        raw = ctx.get(self.field)
        if raw is None:
            return False
        try:
            return self._apply(raw)
        except Exception:
            return False

    def _apply(self, raw: Any) -> bool:
        v = self.value
        op = self.op
        # numeric coercion for scalar comparisons
        if op in ("gt", "gte", "lt", "lte"):
            raw = float(raw)
            v = float(v)
        if op == "eq":
            return str(raw).upper() == str(v).upper() if isinstance(v, str) else raw == v
        if op == "neq":
            return str(raw).upper() != str(v).upper() if isinstance(v, str) else raw != v
        if op == "gt":
            return raw > v
        if op == "gte":
            return raw >= v
        if op == "lt":
            return raw < v
        if op == "lte":
            return raw <= v
        if op == "in":
            norm_v = [str(x).upper() for x in v] if isinstance(v, list) else [str(v).upper()]
            return str(raw).upper() in norm_v
        if op == "not_in":
            norm_v = [str(x).upper() for x in v] if isinstance(v, list) else [str(v).upper()]
            return str(raw).upper() not in norm_v
        if op == "contains":
            return str(v).lower() in str(raw).lower()
        if op == "regex":
            return bool(re.search(str(v), str(raw), re.IGNORECASE))
        return False


@dataclass
class PolicyRule:
    id: str
    priority: int
    conflict_weight: float
    action: Action
    reason: str
    conditions: List[PolicyCondition]
    tags: List[str] = field(default_factory=list)

    def matches(self, ctx: Dict[str, Any]) -> bool:
        """All conditions must match (AND logic)."""
        return all(c.evaluate(ctx) for c in self.conditions)


@dataclass
class MatchedRule:
    rule_id: str
    action: Action
    reason: str
    priority: int
    conflict_weight: float
    tags: List[str]


@dataclass
class PolicyDecision:
    action: Action
    rule_id: str
    policy_version: str
    reason: str
    confidence: float          # 0.0–1.0; derived from conflict_weight
    matched_rules: List[MatchedRule]
    evaluated_rules: int
    simulation: bool = False   # True if dry-run / no side effects


# ---------------------------------------------------------------------------
# Rule Loading
# ---------------------------------------------------------------------------

def _parse_conditions(raw: List[Dict]) -> List[PolicyCondition]:
    out = []
    for c in raw:
        op = str(c.get("op", "eq")).lower()
        if op not in _OPS:
            raise ValueError(f"Unknown operator: {op}")
        out.append(PolicyCondition(
            field=str(c["field"]),
            op=op,
            value=c["value"],
        ))
    return out


def _parse_rules(data: Dict) -> Tuple[List[PolicyRule], str]:
    """Parse YAML dict → rules list + version string."""
    version = str(data.get("version", "0.0.0"))
    raw_rules = data.get("rules", [])
    rules: List[PolicyRule] = []
    for r in raw_rules:
        try:
            rules.append(PolicyRule(
                id=str(r["id"]),
                priority=int(r.get("priority", 50)),
                conflict_weight=float(r.get("conflict_weight", 0.5)),
                action=r["action"],
                reason=str(r.get("reason", "")),
                conditions=_parse_conditions(r.get("conditions", [])),
                tags=list(r.get("tags", [])),
            ))
        except Exception as exc:
            logger.warning("Skipping malformed rule", extra={"rule": r, "error": str(exc)})
    # sort descending priority
    rules.sort(key=lambda x: x.priority, reverse=True)
    return rules, version


def _file_version_hash(path: Path) -> str:
    """Stable content-hash used as policy version fingerprint."""
    try:
        content = path.read_bytes()
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

_DEFAULT_RULES_PATH = Path(__file__).parent / "policies" / "rules.yaml"
_TENANT_RULES_DIR = Path(__file__).parent / "policies"


class PolicyEngine:
    """
    Thread-safe declarative policy engine.

    Conflict resolution:
      When multiple rules match, the engine selects the most severe action
      (ISOLATE > RATE_LIMIT > ALLOW). Ties within the same severity level
      are broken by conflict_weight (higher = preferred).
    """

    def __init__(self, rules_path: Optional[Path] = None, hot_reload: bool = True) -> None:
        self._lock = threading.RLock()
        self._rules_path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH
        self._hot_reload = hot_reload
        self._rules: List[PolicyRule] = []
        self._version: str = "0.0.0"
        self._loaded_mtime: float = 0.0
        self._match_counts: Dict[str, int] = {}

        # Per-tenant cache: tenant_id → (rules, version, mtime)
        self._tenant_cache: Dict[str, Tuple[List[PolicyRule], str, float]] = {}

        self._load(self._rules_path)

        if hot_reload:
            self._watcher = threading.Thread(target=self._watch_loop, daemon=True, name="policy-watcher")
            self._watcher.start()

    # ── Loading ──────────────────────────────────────────────────────────

    def _load(self, path: Path) -> None:
        if yaml is None:
            logger.error("PyYAML not installed — policy engine disabled. Run: pip install pyyaml")
            return
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rules, version = _parse_rules(data or {})
            version_hash = _file_version_hash(path)
            with self._lock:
                self._rules = rules
                self._version = f"{version}+{version_hash}"
                self._loaded_mtime = path.stat().st_mtime if path.exists() else 0.0
                self._match_counts = {r.id: 0 for r in rules}
            logger.info(
                "Policy rules loaded",
                extra={"path": str(path), "count": len(rules), "version": self._version},
            )
        except Exception as exc:
            logger.error("Failed to load policy rules", extra={"path": str(path), "error": str(exc)})

    def reload(self) -> str:
        """Hot-reload base rules. Returns new version string."""
        self._load(self._rules_path)
        with self._lock:
            self._tenant_cache.clear()
        return self._version

    def reload_tenant(self, tenant_id: str) -> Optional[str]:
        """Hot-reload per-tenant rules if present."""
        path = _TENANT_RULES_DIR / tenant_id / "rules.yaml"
        if not path.exists():
            with self._lock:
                self._tenant_cache.pop(tenant_id, None)
            return None
        if yaml is None:
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rules, version = _parse_rules(data or {})
            version_hash = _file_version_hash(path)
            versioned = f"{version}+{version_hash}"
            mtime = path.stat().st_mtime
            with self._lock:
                self._tenant_cache[tenant_id] = (rules, versioned, mtime)
            logger.info("Per-tenant policy reloaded", extra={"tenant_id": tenant_id, "version": versioned})
            return versioned
        except Exception as exc:
            logger.warning("Failed to load tenant rules", extra={"tenant_id": tenant_id, "error": str(exc)})
            return None

    def _get_rules_for_tenant(self, tenant_id: Optional[str]) -> Tuple[List[PolicyRule], str]:
        if not tenant_id:
            with self._lock:
                return list(self._rules), self._version

        path = _TENANT_RULES_DIR / tenant_id / "rules.yaml"
        with self._lock:
            cached = self._tenant_cache.get(tenant_id)
        if path.exists():
            mtime = path.stat().st_mtime
            if cached and cached[2] >= mtime:
                return cached[0], cached[1]
            self.reload_tenant(tenant_id)
            with self._lock:
                cached = self._tenant_cache.get(tenant_id)
            if cached:
                return cached[0], cached[1]

        with self._lock:
            return list(self._rules), self._version

    def _watch_loop(self) -> None:
        while True:
            try:
                if self._rules_path.exists():
                    mtime = self._rules_path.stat().st_mtime
                    with self._lock:
                        last = self._loaded_mtime
                    if mtime > last:
                        logger.info("Policy file changed — hot-reloading")
                        self._load(self._rules_path)
            except Exception:
                pass
            time.sleep(5)

    # ── Evaluation ───────────────────────────────────────────────────────

    def evaluate(
        self,
        ctx: Dict[str, Any],
        tenant_id: Optional[str] = None,
        simulation: bool = False,
    ) -> PolicyDecision:
        """
        Evaluate all rules against context dict.

        ctx must contain fields matching rule conditions
        (e.g. geo_anomaly_flag, failed_auth_count, protocol_type,
              trust_score, entity_type, traversal_depth, …).

        Returns a PolicyDecision with the resolved action and full audit trail.
        """
        rules, version = self._get_rules_for_tenant(tenant_id)

        matched: List[MatchedRule] = []
        for rule in rules:
            if rule.matches(ctx):
                matched.append(MatchedRule(
                    rule_id=rule.id,
                    action=rule.action,
                    reason=rule.reason,
                    priority=rule.priority,
                    conflict_weight=rule.conflict_weight,
                    tags=rule.tags,
                ))
                if not simulation:
                    with self._lock:
                        self._match_counts[rule.id] = self._match_counts.get(rule.id, 0) + 1

        action, winner = self._resolve_conflicts(matched)
        confidence = winner.conflict_weight if winner else 0.5

        return PolicyDecision(
            action=action,
            rule_id=winner.rule_id if winner else "FALLBACK_MODEL",
            policy_version=version,
            reason=winner.reason if winner else "No policy rule matched — model decision",
            confidence=confidence,
            matched_rules=matched,
            evaluated_rules=len(rules),
            simulation=simulation,
        )

    def _resolve_conflicts(
        self, matched: List[MatchedRule]
    ) -> Tuple[Action, Optional[MatchedRule]]:
        """Most-severe action wins; ties broken by conflict_weight."""
        if not matched:
            return "ALLOW", None

        # Group by severity
        best_severity = max(_ACTION_SEVERITY.get(m.action, 0) for m in matched)
        candidates = [m for m in matched if _ACTION_SEVERITY.get(m.action, 0) == best_severity]

        # Within same severity, highest conflict_weight wins
        winner = max(candidates, key=lambda m: m.conflict_weight)
        return winner.action, winner

    # ── Introspection ────────────────────────────────────────────────────

    @property
    def version(self) -> str:
        with self._lock:
            return self._version

    def get_rules_summary(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        rules, version = self._get_rules_for_tenant(tenant_id)
        with self._lock:
            counts = dict(self._match_counts)
        return [
            {
                "id": r.id,
                "priority": r.priority,
                "action": r.action,
                "reason": r.reason,
                "tags": r.tags,
                "conditions": len(r.conditions),
                "match_count": counts.get(r.id, 0),
            }
            for r in rules
        ]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[PolicyEngine] = None
_engine_lock = threading.Lock()


def get_policy_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = PolicyEngine(hot_reload=True)
    return _engine
