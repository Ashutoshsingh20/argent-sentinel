from __future__ import annotations

from typing import Any

import httpx

from adapters.base import AdapterExecutionResult, CloudAdapter, json_safe
from intent_compiler import CompiledAction
from runtime_settings import settings

try:
    from azure.identity import DefaultAzureCredential  # type: ignore
except Exception:  # pragma: no cover
    DefaultAzureCredential = None


class AzureAdapter(CloudAdapter):
    provider = "azure"

    def validate(self, compiled_action: CompiledAction) -> None:
        super().validate(compiled_action)
        if DefaultAzureCredential is None:
            raise RuntimeError("azure identity SDK is not installed")
        for op in compiled_action.operations:
            method = str(op.params.get("method", "GET")).upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                raise ValueError(f"unsupported Azure method: {method}")
            if not op.params.get("path") and not op.params.get("url"):
                raise ValueError("Azure operation requires params.path or params.url")

    def execute(self, compiled_action: CompiledAction) -> AdapterExecutionResult:
        self.validate(compiled_action)

        operation_results: list[dict[str, Any]] = []
        executed_count = 0

        credential = DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}"}

        with httpx.Client(timeout=float(settings.cloud_actions_timeout_seconds)) as client:
            for op in compiled_action.operations:
                method = str(op.params.get("method", "GET")).upper()
                url = str(op.params.get("url") or "").strip()
                path = str(op.params.get("path") or "").strip()
                if not url:
                    url = (
                        path
                        if path.startswith("http")
                        else f"https://management.azure.com{path if path.startswith('/') else '/' + path}"
                    )

                query = dict(op.params.get("query") or {})
                api_version = str(op.params.get("api_version") or "").strip()
                if "api-version=" not in url and api_version:
                    query["api-version"] = api_version

                body = op.params.get("body")

                try:
                    res = self._run_with_timeout(
                        op.timeout_seconds,
                        lambda: client.request(method, url, params=query, json=body, headers=headers),
                    )
                    executed_count += 1
                    try:
                        parsed: Any = res.json()
                    except Exception:
                        parsed = res.text

                    ok = 200 <= res.status_code < 300
                    operation_results.append(
                        {
                            "service": op.service,
                            "operation": op.operation,
                            "ok": ok,
                            "status_code": res.status_code,
                            "result": json_safe(parsed),
                        }
                    )
                    if not ok:
                        status = "degraded" if executed_count > 1 else "failed"
                        return AdapterExecutionResult(
                            ok=False,
                            provider=self.provider,
                            intent=compiled_action.intent.name,
                            execution_status=status,
                            operation_results=operation_results,
                            error=f"Azure operation failed with status {res.status_code}",
                        )
                except Exception as exc:
                    operation_results.append(
                        {
                            "service": op.service,
                            "operation": op.operation,
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
