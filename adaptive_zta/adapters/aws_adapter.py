from __future__ import annotations

from typing import Any

from adapters.base import AdapterExecutionResult, CloudAdapter, json_safe
from intent_compiler import CompiledAction

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None


class AWSAdapter(CloudAdapter):
    provider = "aws"

    def validate(self, compiled_action: CompiledAction) -> None:
        super().validate(compiled_action)
        if boto3 is None:
            raise RuntimeError("boto3 is not installed")
        for op in compiled_action.operations:
            region = str(op.params.get("region") or "")
            if not region and op.service in {"ec2", "iam", "wafv2", "cloudwatch"}:
                # Region can be configured globally in AWS SDK chain; this is only a soft check.
                continue

    def execute(self, compiled_action: CompiledAction) -> AdapterExecutionResult:
        self.validate(compiled_action)

        operation_results: list[dict[str, Any]] = []
        executed_count = 0

        for op in compiled_action.operations:
            service = op.service
            operation = op.operation
            params = dict(op.params)
            region = str(params.pop("region", "") or "") or None

            def _call_aws() -> Any:
                client = boto3.client(service, region_name=region)
                fn = getattr(client, operation, None)
                if fn is None:
                    raise ValueError(f"unsupported AWS operation for {service}: {operation}")
                return fn(**params)

            try:
                result = self._run_with_timeout(op.timeout_seconds, _call_aws)
                executed_count += 1
                operation_results.append(
                    {
                        "service": service,
                        "operation": operation,
                        "ok": True,
                        "result": json_safe(result),
                    }
                )
            except Exception as exc:
                operation_results.append(
                    {
                        "service": service,
                        "operation": operation,
                        "ok": False,
                        "error": str(exc),
                    }
                )
                status = "degraded" if executed_count > 0 else "failed"
                return AdapterExecutionResult(
                    ok=False,
                    provider=self.provider,
                    intent=compiled_action.intent.name,
                    execution_status=status,
                    operation_results=operation_results,
                    error=str(exc),
                )

        return AdapterExecutionResult(
            ok=True,
            provider=self.provider,
            intent=compiled_action.intent.name,
            execution_status="success",
            operation_results=operation_results,
        )
