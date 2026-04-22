from __future__ import annotations

import json
import logging
from typing import Any, Dict

from adapters import AWSAdapter, AzureAdapter, GCPAdapter
from intent_compiler import CompiledAction, CompilationError, compile_intent
from intent_model import Intent, decision_to_intent
from cloud_features import registry as cloud_feature_registry
from runtime_settings import settings


logger = logging.getLogger(__name__)


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _provider_enabled(provider: str) -> bool:
    p = provider.lower()
    if not settings.cloud_actions_enabled:
        return False
    if p == "aws":
        return settings.aws_cloud_actions_enabled
    if p == "azure":
        return settings.azure_cloud_actions_enabled
    if p == "gcp":
        return settings.gcp_cloud_actions_enabled
    return False


def get_adapter(provider: str):
    p = provider.strip().lower()
    if p == "aws":
        return AWSAdapter()
    if p == "azure":
        return AzureAdapter()
    if p == "gcp":
        return GCPAdapter()
    raise ValueError(f"unsupported provider: {provider}")


def _build_intent_from_request(request: Dict[str, Any]) -> Intent:
    if isinstance(request.get("intent"), dict):
        return Intent(**request["intent"])

    intent_name = str(request.get("intent_name") or "").strip()
    if intent_name:
        return Intent(
            name=intent_name,
            target_type=str(request.get("target_type") or "user").strip().lower(),
            target_id=str(request.get("target_id") or request.get("entity_id") or "unknown-target"),
            risk_level=str(request.get("risk_level") or "medium").strip().lower(),
            reason=str(request.get("reason") or "cloud action request"),
            metadata=dict(request.get("metadata") or {}),
        )

    if isinstance(request.get("decision"), dict):
        return decision_to_intent(request["decision"])

    action = str(request.get("action") or request.get("decision") or "").strip().lower()
    if action in {"deny", "step_up", "allow", "rate_limit", "isolate", "revoke"}:
        return decision_to_intent(request)

    raise ValueError(
        "unable to derive intent from request. Provide intent, intent_name, or decision payload"
    )


class CloudActionEngine:
    def catalog(self, force_refresh: bool = False) -> Dict[str, Any]:
        payload = cloud_feature_registry.get(force=force_refresh)
        providers = payload.get("providers", {})

        aws_services = [x.get("name") for x in providers.get("aws", {}).get("features", []) if x.get("name")]
        azure_services = [x.get("name") for x in providers.get("azure", {}).get("features", []) if x.get("name")]
        gcp_services = [x.get("name") for x in providers.get("gcp", {}).get("features", []) if x.get("name")]

        return {
            "updated_at": payload.get("updated_at"),
            "providers": {
                "aws": {
                    "enabled": bool(_provider_enabled("aws")),
                    "service_count": len(aws_services),
                    "services": aws_services,
                    "actions": [
                        {
                            "name": "invoke",
                            "description": "Invoke any boto3 client operation for the selected AWS service",
                            "required": ["service", "operation"],
                            "optional": ["region", "params"],
                        }
                    ],
                },
                "azure": {
                    "enabled": bool(_provider_enabled("azure")),
                    "service_count": len(azure_services),
                    "services": azure_services,
                    "actions": [
                        {
                            "name": "invoke",
                            "description": "Invoke Azure Resource Manager REST operations",
                            "required": ["method", "path"],
                            "optional": ["api_version", "query", "body"],
                        }
                    ],
                },
                "gcp": {
                    "enabled": bool(_provider_enabled("gcp")),
                    "service_count": len(gcp_services),
                    "services": gcp_services,
                    "actions": [
                        {
                            "name": "invoke",
                            "description": "Invoke any Google Cloud REST API endpoint with ADC credentials",
                            "required": ["method", "url"],
                            "optional": ["query", "body"],
                        }
                    ],
                },
            },
            "controls": {
                "allow_mutations": bool(settings.cloud_actions_allow_mutations),
                "timeout_seconds": int(settings.cloud_actions_timeout_seconds),
            },
            "intent_model": {
                "supported_intents": [
                    "isolate_compute",
                    "restrict_identity",
                    "revoke_access",
                    "monitor_entity",
                    "block_request",
                ],
                "pipeline": ["intent", "compiler", "provider_adapter", "execution"],
                "request_formats": ["intent", "intent_name", "decision"],
            },
        }

    def execute_intent(self, intent: Intent, provider: str) -> Dict[str, Any]:
        p = provider.strip().lower()
        if p not in {"aws", "azure", "gcp"}:
            return {"ok": False, "error": f"unsupported provider: {provider}", "execution_status": "failed"}

        if not _provider_enabled(p):
            return {
                "ok": False,
                "error": f"provider disabled: {p}",
                "hint": f"Enable CLOUD_ACTIONS_ENABLED=1 and {p.upper()}_CLOUD_ACTIONS_ENABLED=1",
                "execution_status": "failed",
            }

        compiled: CompiledAction
        try:
            compiled = compile_intent(intent, p)
        except CompilationError as exc:
            fallback = {
                "ok": False,
                "provider": p,
                "intent": intent.model_dump(),
                "execution_status": "failed",
                "fallback_action": "no_execution",
                "error": f"intent compilation failed: {exc}",
            }
            logger.error(
                "Intent compilation failed",
                extra={"provider": p, "intent": intent.model_dump(), "error": str(exc)},
            )
            return fallback

        try:
            adapter = get_adapter(p)
            adapter.validate(compiled)
            adapter_result = adapter.execute(compiled)
            result = {
                "ok": bool(adapter_result.ok),
                "provider": p,
                "intent": intent.model_dump(),
                "compiled_actions": [op.model_dump() for op in compiled.operations],
                "execution_status": adapter_result.execution_status,
                "operation_results": adapter_result.operation_results,
                "error": adapter_result.error,
            }
            logger.info(
                "Intent execution completed",
                extra={
                    "provider": p,
                    "intent": intent.model_dump(),
                    "compiled_actions": [op.model_dump() for op in compiled.operations],
                    "execution_status": adapter_result.execution_status,
                    "ok": bool(adapter_result.ok),
                },
            )
            return result
        except Exception as exc:
            logger.error(
                "Adapter execution failed",
                extra={
                    "provider": p,
                    "intent": intent.model_dump(),
                    "compiled_actions": [op.model_dump() for op in compiled.operations],
                    "error": str(exc),
                },
            )
            return {
                "ok": False,
                "provider": p,
                "intent": intent.model_dump(),
                "compiled_actions": [op.model_dump() for op in compiled.operations],
                "execution_status": "failed",
                "error": str(exc),
            }

    def execute_decision(self, provider: str, decision: Dict[str, Any]) -> Dict[str, Any]:
        intent = decision_to_intent(decision)
        return self.execute_intent(intent=intent, provider=provider)

    def invoke(self, provider: str, request: Dict[str, Any]) -> Dict[str, Any]:
        try:
            intent = _build_intent_from_request(request)
        except Exception as exc:
            return {
                "ok": False,
                "error": str(exc),
                "execution_status": "failed",
                "fallback_action": "no_execution",
            }

        try:
            return self.execute_intent(intent=intent, provider=provider)
        except Exception as exc:
            return {
                "ok": False,
                "provider": provider,
                "intent": intent.model_dump(),
                "execution_status": "failed",
                "error": str(exc),
            }


engine = CloudActionEngine()
