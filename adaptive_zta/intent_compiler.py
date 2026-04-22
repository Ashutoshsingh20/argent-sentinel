from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from intent_model import Intent


class CompiledOperation(BaseModel):
    service: str
    operation: str
    params: dict[str, Any] = Field(default_factory=dict)
    destructive: bool = False
    timeout_seconds: int = 20


class CompiledAction(BaseModel):
    provider: str
    intent: Intent
    operations: list[CompiledOperation] = Field(default_factory=list)
    allow_destructive: bool = False


class CompilationError(Exception):
    pass


def _timeout(intent: Intent) -> int:
    raw = intent.metadata.get("timeout_seconds")
    try:
        value = int(raw)
        if value > 0:
            return value
    except (TypeError, ValueError):
        pass
    return 20


def _allow_destructive(intent: Intent) -> bool:
    return bool(intent.metadata.get("allow_destructive", False))


def _compile_isolate_compute(intent: Intent, provider: str) -> list[CompiledOperation]:
    t = _timeout(intent)
    if provider == "aws":
        region = str(intent.metadata.get("region") or "")
        return [
            CompiledOperation(
                service="ec2",
                operation="modify_instance_attribute",
                params={
                    "InstanceId": intent.target_id,
                    "Groups": [],
                    "region": region,
                },
                destructive=True,
                timeout_seconds=t,
            ),
            CompiledOperation(
                service="iam",
                operation="remove_role_from_instance_profile",
                params={
                    "InstanceProfileName": str(intent.metadata.get("instance_profile_name", "")),
                    "RoleName": str(intent.metadata.get("role_name", "")),
                    "region": region,
                },
                destructive=True,
                timeout_seconds=t,
            ),
        ]

    if provider == "azure":
        return [
            CompiledOperation(
                service="network",
                operation="patch_nsg",
                params={
                    "method": "PATCH",
                    "path": str(intent.metadata.get("nsg_path", "")),
                    "api_version": str(intent.metadata.get("network_api_version", "2023-11-01")),
                    "body": intent.metadata.get("nsg_patch_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            ),
            CompiledOperation(
                service="authorization",
                operation="delete_role_assignment",
                params={
                    "method": "DELETE",
                    "path": str(intent.metadata.get("role_assignment_path", "")),
                    "api_version": str(intent.metadata.get("auth_api_version", "2022-04-01")),
                },
                destructive=True,
                timeout_seconds=t,
            ),
        ]

    if provider == "gcp":
        return [
            CompiledOperation(
                service="compute",
                operation="insert_firewall_rule",
                params={
                    "method": "POST",
                    "url": str(intent.metadata.get("firewall_url", "")),
                    "body": intent.metadata.get("firewall_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            ),
            CompiledOperation(
                service="iam",
                operation="remove_iam_binding",
                params={
                    "method": "POST",
                    "url": str(intent.metadata.get("iam_url", "")),
                    "body": intent.metadata.get("iam_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            ),
        ]

    raise CompilationError(f"unsupported provider for isolate_compute: {provider}")


def _compile_restrict_identity(intent: Intent, provider: str) -> list[CompiledOperation]:
    t = _timeout(intent)
    if provider == "aws":
        return [
            CompiledOperation(
                service="iam",
                operation="put_user_policy",
                params={
                    "UserName": intent.target_id,
                    "PolicyName": str(intent.metadata.get("policy_name", "argent-restrict-access")),
                    "PolicyDocument": str(intent.metadata.get("policy_document", "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}")),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    if provider == "azure":
        return [
            CompiledOperation(
                service="authorization",
                operation="create_deny_assignment",
                params={
                    "method": "PUT",
                    "path": str(intent.metadata.get("deny_assignment_path", "")),
                    "api_version": str(intent.metadata.get("auth_api_version", "2022-04-01")),
                    "body": intent.metadata.get("deny_assignment_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    if provider == "gcp":
        return [
            CompiledOperation(
                service="iam",
                operation="set_deny_policy",
                params={
                    "method": "POST",
                    "url": str(intent.metadata.get("deny_policy_url", "")),
                    "body": intent.metadata.get("deny_policy_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    raise CompilationError(f"unsupported provider for restrict_identity: {provider}")


def _compile_revoke_access(intent: Intent, provider: str) -> list[CompiledOperation]:
    t = _timeout(intent)
    if provider == "aws":
        return [
            CompiledOperation(
                service="iam",
                operation="delete_access_key",
                params={
                    "UserName": str(intent.metadata.get("username", intent.target_id)),
                    "AccessKeyId": str(intent.metadata.get("access_key_id", "")),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    if provider == "azure":
        return [
            CompiledOperation(
                service="graph",
                operation="revoke_sign_in_sessions",
                params={
                    "method": "POST",
                    "path": str(intent.metadata.get("graph_path", "")),
                    "api_version": str(intent.metadata.get("graph_api_version", "1.0")),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    if provider == "gcp":
        return [
            CompiledOperation(
                service="oauth2",
                operation="revoke_token",
                params={
                    "method": "POST",
                    "url": str(intent.metadata.get("revoke_url", "")),
                    "body": intent.metadata.get("revoke_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    raise CompilationError(f"unsupported provider for revoke_access: {provider}")


def _compile_monitor_entity(intent: Intent, provider: str) -> list[CompiledOperation]:
    t = _timeout(intent)
    if provider == "aws":
        return [
            CompiledOperation(
                service="cloudwatch",
                operation="put_metric_alarm",
                params={
                    "AlarmName": f"argent-monitor-{intent.target_id}",
                    "MetricName": str(intent.metadata.get("metric_name", "SuspiciousActivity")),
                    "Namespace": str(intent.metadata.get("namespace", "ArgentSentinel")),
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "Threshold": float(intent.metadata.get("threshold", 1.0)),
                    "EvaluationPeriods": int(intent.metadata.get("evaluation_periods", 1)),
                    "Period": int(intent.metadata.get("period", 60)),
                    "Statistic": "Sum",
                },
                destructive=False,
                timeout_seconds=t,
            )
        ]
    if provider == "azure":
        return [
            CompiledOperation(
                service="insights",
                operation="create_metric_alert",
                params={
                    "method": "PUT",
                    "path": str(intent.metadata.get("alert_path", "")),
                    "api_version": str(intent.metadata.get("insights_api_version", "2018-03-01")),
                    "body": intent.metadata.get("alert_body", {}),
                },
                destructive=False,
                timeout_seconds=t,
            )
        ]
    if provider == "gcp":
        return [
            CompiledOperation(
                service="monitoring",
                operation="create_alert_policy",
                params={
                    "method": "POST",
                    "url": str(intent.metadata.get("alert_policy_url", "")),
                    "body": intent.metadata.get("alert_policy_body", {}),
                },
                destructive=False,
                timeout_seconds=t,
            )
        ]
    raise CompilationError(f"unsupported provider for monitor_entity: {provider}")


def _compile_block_request(intent: Intent, provider: str) -> list[CompiledOperation]:
    t = _timeout(intent)
    if provider == "aws":
        return [
            CompiledOperation(
                service="wafv2",
                operation="update_ip_set",
                params={
                    "Name": str(intent.metadata.get("ip_set_name", "argent-blocklist")),
                    "Scope": str(intent.metadata.get("scope", "REGIONAL")),
                    "Id": str(intent.metadata.get("ip_set_id", "")),
                    "LockToken": str(intent.metadata.get("lock_token", "")),
                    "Addresses": list(intent.metadata.get("addresses", [])),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    if provider == "azure":
        return [
            CompiledOperation(
                service="network",
                operation="upsert_waf_custom_rule",
                params={
                    "method": "PATCH",
                    "path": str(intent.metadata.get("waf_policy_path", "")),
                    "api_version": str(intent.metadata.get("network_api_version", "2023-09-01")),
                    "body": intent.metadata.get("waf_patch_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    if provider == "gcp":
        return [
            CompiledOperation(
                service="security",
                operation="add_cloud_armor_rule",
                params={
                    "method": "POST",
                    "url": str(intent.metadata.get("armor_url", "")),
                    "body": intent.metadata.get("armor_body", {}),
                },
                destructive=True,
                timeout_seconds=t,
            )
        ]
    raise CompilationError(f"unsupported provider for block_request: {provider}")


INTENT_COMPILERS = {
    "isolate_compute": _compile_isolate_compute,
    "restrict_identity": _compile_restrict_identity,
    "revoke_access": _compile_revoke_access,
    "monitor_entity": _compile_monitor_entity,
    "block_request": _compile_block_request,
}


def compile_intent(intent: Intent, provider: str) -> CompiledAction:
    provider_norm = provider.strip().lower()
    if provider_norm not in {"aws", "azure", "gcp"}:
        raise CompilationError(f"unsupported provider: {provider}")

    compiler = INTENT_COMPILERS.get(intent.name)
    if compiler is None:
        raise CompilationError(f"unsupported intent: {intent.name}")

    operations = compiler(intent, provider_norm)
    if not operations:
        raise CompilationError(f"intent produced no operations: {intent.name}")

    return CompiledAction(
        provider=provider_norm,
        intent=intent,
        operations=operations,
        allow_destructive=_allow_destructive(intent),
    )
