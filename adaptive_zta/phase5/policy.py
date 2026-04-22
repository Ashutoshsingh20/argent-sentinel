from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Protocol, TypedDict

from runtime_settings import settings

from .types import Decision

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None

try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.mgmt.resource import ResourceManagementClient  # type: ignore
except Exception:  # pragma: no cover
    DefaultAzureCredential = None
    ResourceManagementClient = None

try:
    from google.cloud import resourcemanager_v3  # type: ignore
except Exception:  # pragma: no cover
    resourcemanager_v3 = None


class CloudPolicy(TypedDict):
    ALLOW: str
    RATE_LIMIT: str
    ISOLATE: str


POLICY_MAP: dict[str, CloudPolicy] = {
    "AWS": {
        "ALLOW": "IAM_ALLOW",
        "RATE_LIMIT": "API_GATEWAY_THROTTLE",
        "ISOLATE": "IAM_DENY_INLINE",
    },
    "AZURE": {
        "ALLOW": "RBAC_PERMIT",
        "RATE_LIMIT": "APIM_THROTTLE_POLICY",
        "ISOLATE": "CONDITIONAL_ACCESS_BLOCK",
    },
    "GCP": {
        "ALLOW": "IAM_BINDING_ALLOW",
        "RATE_LIMIT": "CLOUD_ARMOR_RATE_LIMIT",
        "ISOLATE": "VPC_FIREWALL_DENY",
    },
}


class PolicyEnforcementError(RuntimeError):
    pass


logger = logging.getLogger(__name__)


class CloudClient(Protocol):
    def apply(self, policy_action: str, entity_id: str, dry_run: bool = False) -> None:
        ...


@dataclass
class AuditRecord:
    timestamp: float
    decision: str
    cloud: str
    action: str
    entity_id: str
    dry_run: bool


class InMemoryAuditLog:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def record(self, decision: str, cloud: str, action: str, entity_id: str, dry_run: bool) -> None:
        self.records.append(
            AuditRecord(
                timestamp=time.time(),
                decision=decision,
                cloud=cloud,
                action=action,
                entity_id=entity_id,
                dry_run=dry_run,
            )
        )


class MockCloudClient:
    """Idempotent policy application for local/staging simulation."""

    def __init__(self) -> None:
        self.last_action_by_entity: dict[str, str] = {}

    def apply(self, policy_action: str, entity_id: str, dry_run: bool = False) -> None:
        if dry_run:
            return
        # Idempotent: setting same action repeatedly is no-op.
        self.last_action_by_entity[entity_id] = policy_action


class AWSCloudClient(MockCloudClient):
    def __init__(self) -> None:
        super().__init__()
        self._lambda_target = settings.aws_lambda_target
        self._lambda = boto3.client("lambda") if boto3 is not None and self._lambda_target else None

    def apply(self, policy_action: str, entity_id: str, dry_run: bool = False) -> None:
        super().apply(policy_action, entity_id, dry_run=dry_run)
        if dry_run or self._lambda is None:
            return

        if policy_action == "IAM_DENY_INLINE":
            # Real cloud enforcement: hard throttle Lambda to zero concurrency.
            self._lambda.put_function_concurrency(FunctionName=self._lambda_target, ReservedConcurrentExecutions=0)
        elif policy_action == "API_GATEWAY_THROTTLE":
            self._lambda.put_function_concurrency(FunctionName=self._lambda_target, ReservedConcurrentExecutions=1)
        elif policy_action == "IAM_ALLOW":
            self._lambda.delete_function_concurrency(FunctionName=self._lambda_target)


class AzureCloudClient(MockCloudClient):
    def __init__(self) -> None:
        super().__init__()
        self._scope = settings.azure_tag_scope
        self._resource_client = None
        if DefaultAzureCredential is not None and ResourceManagementClient is not None and self._scope:
            subscription_id = self._scope.split("/")[2] if self._scope.startswith("/subscriptions/") else ""
            if subscription_id:
                credential = DefaultAzureCredential()
                self._resource_client = ResourceManagementClient(credential, subscription_id)

    def apply(self, policy_action: str, entity_id: str, dry_run: bool = False) -> None:
        super().apply(policy_action, entity_id, dry_run=dry_run)
        if dry_run or self._resource_client is None or not self._scope:
            return

        tags = {
            "sentinel_entity": entity_id,
            "sentinel_action": policy_action,
            "sentinel_updated": str(int(time.time())),
        }
        self._resource_client.tags.begin_update_at_scope(self._scope, {"operation": "Merge", "properties": {"tags": tags}})


class GCPCloudClient(MockCloudClient):
    def __init__(self) -> None:
        super().__init__()
        self._project_id = settings.gcp_project_id
        self._client = resourcemanager_v3.ProjectsClient() if resourcemanager_v3 is not None and self._project_id else None

    def apply(self, policy_action: str, entity_id: str, dry_run: bool = False) -> None:
        super().apply(policy_action, entity_id, dry_run=dry_run)
        if dry_run or self._client is None or not self._project_id:
            return

        project_name = f"projects/{self._project_id}"
        project = self._client.get_project(name=project_name)
        labels = dict(project.labels)
        labels["sentinel-action"] = policy_action.lower().replace("_", "-")[:63]
        labels["sentinel-entity"] = entity_id.lower().replace(":", "-")[:63]
        project.labels = labels
        self._client.update_project(project=project)


class PolicyAbstractionLayer:
    def __init__(self) -> None:
        self.audit_log = InMemoryAuditLog()
        self._clients: dict[str, CloudClient] = {
            "AWS": MockCloudClient(),
            "AZURE": MockCloudClient(),
            "GCP": MockCloudClient(),
        }
        self._configure_cloud_clients()

    def _configure_cloud_clients(self) -> None:
        if not settings.cloud_actions_enabled:
            return
        if settings.aws_cloud_actions_enabled:
            self._clients["AWS"] = AWSCloudClient()
        if settings.azure_cloud_actions_enabled:
            self._clients["AZURE"] = AzureCloudClient()
        if settings.gcp_cloud_actions_enabled:
            self._clients["GCP"] = GCPCloudClient()
        logger.info("Cloud policy clients configured", extra={"aws": settings.aws_cloud_actions_enabled, "azure": settings.azure_cloud_actions_enabled, "gcp": settings.gcp_cloud_actions_enabled})

    def get_cloud_client(self, cloud: str) -> CloudClient:
        if cloud not in self._clients:
            raise PolicyEnforcementError(f"unsupported cloud: {cloud}")
        return self._clients[cloud]

    def enforce(self, decision: Decision, cloud: str, entity_id: str, dry_run: bool = False) -> str:
        try:
            action = POLICY_MAP[cloud][decision]
            client = self.get_cloud_client(cloud)
            client.apply(action, entity_id, dry_run=dry_run)
            self.audit_log.record(
                decision=decision,
                cloud=cloud,
                action=action,
                entity_id=entity_id,
                dry_run=dry_run,
            )
            return action
        except Exception as exc:  # pragma: no cover
            raise PolicyEnforcementError(str(exc)) from exc
