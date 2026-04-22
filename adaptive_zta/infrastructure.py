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

    def deploy_block(self, entity_id: str, decision: str, reason: str):
        """Mock 'Deploy' a decision to the infrastructure."""
        with self._lock:
            if decision == "ISOLATE":
                if entity_id not in self.firewall_blocked_entities:
                    self.firewall_blocked_entities.add(entity_id)
                    self.active_firewall_rules += 1
                    self.total_blocks_applied += 1
                    self._log_event(entity_id, "FIREWALL_DROP", reason)
            
            elif decision == "RATE_LIMIT":
                if entity_id not in self.iam_quarantined_entities:
                    self.iam_quarantined_entities[entity_id] = "READ_ONLY_SCOPED"
                    self.total_blocks_applied += 1
                    self._log_event(entity_id, "IAM_QUARANTINE", reason)
            
            elif decision == "ALLOW":
                # Lift blocks if behavior improves
                if entity_id in self.firewall_blocked_entities:
                    self.firewall_blocked_entities.remove(entity_id)
                    self.active_firewall_rules -= 1
                    self._log_event(entity_id, "FIREWALL_RESTORE", "TRUST_REGAINED")
                
                self.iam_quarantined_entities.pop(entity_id, None)

    def is_blocked(self, entity_id: str) -> bool:
        """Check if an entity is currently unreachable due to firewall."""
        with self._lock:
            return entity_id in self.firewall_blocked_entities

    def get_status(self):
        with self._lock:
            return {
                "firewall_rules": self.active_firewall_rules,
                "iam_quarantines": len(self.iam_quarantined_entities),
                "total_actions": self.total_blocks_applied,
                "latest_infrastructure_logs": self.enforcement_log[-10:][::-1]
            }

    def _log_event(self, entity: str, action: str, reason: str):
        self.enforcement_log.append({
            "timestamp": time.time(),
            "entity_id": entity,
            "action": action,
            "reason": reason
        })

# Global instance for the simulation
sentinel = InfrastructureSentinel()
