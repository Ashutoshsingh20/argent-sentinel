from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Callable

from pydantic import BaseModel, Field

from intent_compiler import CompiledAction, CompiledOperation
from runtime_settings import settings


class AdapterExecutionResult(BaseModel):
    ok: bool
    provider: str
    intent: str
    execution_status: str
    operation_results: list[dict[str, Any]] = Field(default_factory=list)
    error: str = None


class CloudAdapter:
    provider: str = "unknown"

    def validate(self, compiled_action: CompiledAction) -> None:
        if compiled_action.provider != self.provider:
            raise ValueError(
                f"compiled provider {compiled_action.provider} does not match adapter {self.provider}"
            )
        self._enforce_operation_guardrails(compiled_action)

    def execute(self, compiled_action: CompiledAction) -> AdapterExecutionResult:
        raise NotImplementedError

    def rollback(self, compiled_action: CompiledAction) -> dict[str, Any]:
        return {
            "ok": False,
            "provider": self.provider,
            "rolled_back": False,
            "message": "rollback not implemented",
        }

    def _enforce_operation_guardrails(self, compiled_action: CompiledAction) -> None:
        if not compiled_action.operations:
            raise ValueError("compiled action has no operations")

        for op in compiled_action.operations:
            self._validate_operation(op)
            if op.destructive:
                self._enforce_destructive_policy(compiled_action, op)

    def _validate_operation(self, op: CompiledOperation) -> None:
        if not op.service:
            raise ValueError("operation.service is required")
        if not op.operation:
            raise ValueError("operation.operation is required")
        if not isinstance(op.params, dict):
            raise ValueError("operation.params must be a dict")

    def _enforce_destructive_policy(self, compiled_action: CompiledAction, op: CompiledOperation) -> None:
        explicitly_allowed = bool(compiled_action.allow_destructive)
        if not settings.cloud_actions_allow_mutations or not explicitly_allowed:
            raise PermissionError(
                "destructive operation blocked by policy. "
                "Enable CLOUD_ACTIONS_ALLOW_MUTATIONS=1 and set intent metadata allow_destructive=true"
            )

    def _run_with_timeout(self, timeout_seconds: int, fn: Callable[[], Any]) -> Any:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(fn)
            try:
                return future.result(timeout=max(1, int(timeout_seconds)))
            except FutureTimeoutError as exc:
                raise TimeoutError(
                    f"operation timed out after {timeout_seconds} seconds"
                ) from exc


def json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)
