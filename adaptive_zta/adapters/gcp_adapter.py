from __future__ import annotations

from typing import Any

import httpx

from adapters.base import AdapterExecutionResult, CloudAdapter, json_safe
from intent_compiler import CompiledAction
from runtime_settings import settings

try:
    import google.auth  # type: ignore
    from google.auth.transport.requests import Request as GoogleAuthRequest  # type: ignore
except Exception:  # pragma: no cover
    google = None
    GoogleAuthRequest = None


class GCPAdapter(CloudAdapter):
    provider = "gcp"

    def validate(self, compiled_action: CompiledAction) -> None:
        super().validate(compiled_action)
        if google is None or GoogleAuthRequest is None:
            raise RuntimeError("google-auth is not installed")
        for op in compiled_action.operations:
            method = str(op.params.get("method", "GET")).upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                raise ValueError(f"unsupported GCP method: {method}")
            if not op.params.get("url"):
                raise ValueError("GCP operation requires params.url")

    def execute(self, compiled_action: CompiledAction) -> AdapterExecutionResult:
        self.validate(compiled_action)

        operation_results: list[dict[str, Any]] = []
        executed_count = 0

        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(GoogleAuthRequest())
        headers = {"Authorization": f"Bearer {credentials.token}"}

        with httpx.Client(timeout=float(settings.cloud_actions_timeout_seconds)) as client:
            for op in compiled_action.operations:
                method = str(op.params.get("method", "GET")).upper()
                url = str(op.params.get("url") or "").strip()
                query = dict(op.params.get("query") or {})
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
                            error=f"GCP operation failed with status {res.status_code}",
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
