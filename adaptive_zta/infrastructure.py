import threading
import time
from typing import Dict, Set, List

class InfrastructureSentinel:
    """
    Simulates a Cloud Infrastructure Enforcement Layer.
    Manages Firewall Rules (Layer 4/7) and IAM Quarantines.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.firewall_blocked_entities: Set[str] = set()
        self.iam_quarantined_entities: Dict[str, str] = {} # entity_id -> restricted_permissions
        self.enforcement_log: List[dict] = []
        
        # Stats for UI
        self.total_blocks_applied = 0
        self.active_firewall_rules = 0

    def deploy_block(self, entity_id: str, decision: str, reason: str, tenant_id: str = "default"):
        """Mock 'Deploy' a decision to the infrastructure."""
        key = f"{tenant_id}:{entity_id}"
        with self._lock:
            if decision == "ISOLATE":
                if key not in self.firewall_blocked_entities:
                    self.firewall_blocked_entities.add(key)
                    self.active_firewall_rules += 1
                    self.total_blocks_applied += 1
                    self._log_event(entity_id, "FIREWALL_DROP", reason, tenant_id)
            
            elif decision == "RATE_LIMIT":
                if key not in self.iam_quarantined_entities:
                    self.iam_quarantined_entities[key] = "READ_ONLY_SCOPED"
                    self.total_blocks_applied += 1
                    self._log_event(entity_id, "IAM_QUARANTINE", reason, tenant_id)
            
            elif decision == "ALLOW":
                # Lift blocks if behavior improves
                if key in self.firewall_blocked_entities:
                    self.firewall_blocked_entities.remove(key)
                    self.active_firewall_rules -= 1
                    self._log_event(entity_id, "FIREWALL_RESTORE", "TRUST_REGAINED", tenant_id)
                
                self.iam_quarantined_entities.pop(key, None)

    def is_blocked(self, entity_id: str, tenant_id: str = "default") -> bool:
        """Check if an entity is currently unreachable due to firewall."""
        with self._lock:
            return f"{tenant_id}:{entity_id}" in self.firewall_blocked_entities

    def get_status(self, tenant_id: str = "default"):
        with self._lock:
            return {
                "firewall_rules": sum(1 for k in self.firewall_blocked_entities if k.startswith(f"{tenant_id}:")),
                "iam_quarantines": sum(1 for k in self.iam_quarantined_entities.keys() if k.startswith(f"{tenant_id}:")),
                "total_actions": sum(1 for log in self.enforcement_log if log.get("tenant_id") == tenant_id),
                "latest_infrastructure_logs": [log for log in self.enforcement_log if log.get("tenant_id") == tenant_id][-10:][::-1]
            }

    def _log_event(self, entity: str, action: str, reason: str, tenant_id: str):
        self.enforcement_log.append({
            "timestamp": time.time(),
            "entity_id": entity,
            "tenant_id": tenant_id,
            "action": action,
            "reason": reason
        })

# Global instance for the simulation
sentinel = InfrastructureSentinel()
