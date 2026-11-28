"""Windows Computer Control runtime over the existing Device Control gateway channel."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from .contracts import (
    ComputerAction,
    ComputerActionError,
    ComputerResult,
    redact_value,
)
from .ledger import ComputerRunLedger, LedgerEntry
from .manifest import CAPABILITY_IDS, EXTERNAL_SIDE_EFFECT_CAPABILITIES, SHELL_CAPABILITIES
from .providers.base import ComputerProvider
from .session import SessionInfo, detect_session, local_takeover_requested
from .session_mutex import DesktopMutex

HIGH_RISK_CAPABILITIES = frozenset(EXTERNAL_SIDE_EFFECT_CAPABILITIES | {
    "computer.clipboard.read", "computer.clipboard.write",
})


class ControlClient(Protocol):
    def pull(self, limit: int = 10) -> list[dict[str, Any]]:
        ...

    def progress(self, command_id: str, status: str) -> dict[str, Any]:
        ...

    def result(self, command_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        ...

    def upload_evidence(self, command_id: str, data: bytes, **kwargs: Any) -> dict[str, Any]:
        ...


@dataclass
class ComputerRuntime:
    client: ControlClient
    desktop_provider: ComputerProvider
    tenant_ref: str
    endpoint_id: str
    device_id: str
    gateway_id: str
    browser_provider: ComputerProvider | None = None
    allowed_capabilities: set[str] = field(default_factory=lambda: set(CAPABILITY_IDS))
    ledger: ComputerRunLedger = field(default_factory=ComputerRunLedger)
    pause_path: str | None = None
    session_probe: Callable[[], SessionInfo] = detect_session
    mutex_name: str = "MindOS.ComputerControl.Desktop"

    def run_once(self, limit: int = 10) -> dict[str, int]:
        commands = self.client.pull(limit)
        executed = 0
        for command in commands:
            self._execute(command)
            executed += 1
        return {"pulled": len(commands), "executed": executed}

    def health(self) -> dict[str, Any]:
        session = self.session_probe()
        return {
            "runtime": "computer-control",
            "status": "ready" if session.allows_ui() else "degraded",
            "session": session.state,
            "desktop_provider": self.desktop_provider.health().status,
            "browser_provider": self.browser_provider.health().status
            if self.browser_provider else "unavailable",
            "paused": self.paused(),
        }

    def paused(self) -> bool:
        return local_takeover_requested(self.pause_path)

    def _provider(self, capability_id: str) -> ComputerProvider | None:
        if capability_id.startswith("browser."):
            return self.browser_provider
        return self.desktop_provider

    def _execute(self, envelope: dict[str, Any]) -> None:
        command_id = str(envelope.get("command_id") or "")
        if not command_id:
            return
        try:
            action = ComputerAction.from_envelope(envelope)
        except ComputerActionError as exc:
            self._result(command_id, ComputerResult(
                status="rejected", provider_status=exc.code,
                error_code=exc.code, error_message=str(exc),
            ), [])
            return
        if (action.tenant_ref != self.tenant_ref
                or action.endpoint_id != self.endpoint_id
                or action.device_id != self.device_id
                or str(envelope.get("gateway_id") or "") != self.gateway_id):
            self._reject(command_id, "binding_mismatch")
            return
        if not action.task_ref or not action.run_ref:
            self._reject(command_id, "task_run_required")
            return
        if action.capability_id in SHELL_CAPABILITIES or action.capability_id not in self.allowed_capabilities:
            self._reject(command_id, "capability_not_allowlisted")
            return
        if action.capability_id in HIGH_RISK_CAPABILITIES and not action.approval_ref:
            self._reject(command_id, "approval_required")
            return
        if self.paused():
            self._reject(command_id, "local_takeover")
            return

        key = action.ledger_key()
        previous = self.ledger.get(key)
        if previous is not None:
            if previous.fingerprint != action.fingerprint():
                self._reject(command_id, "idempotency_fingerprint_conflict")
                return
            if previous.phase == "executing":
                # Crash after dispatch: outcome is unknown; never repeat.
                result = ComputerResult(
                    status="uncertain", provider_status="crash_recovery",
                    error_code="unknown_after_dispatch",
                    error_message="runtime restarted after dispatch; reconcile same action",
                    reconcile_required=True,
                )
                self._record(key, action, "unknown", result.to_dict())
                self._result(command_id, result, [])
                return
            if previous.result is not None:
                # Same command redelivery: report recorded result, no action.
                self._report_recorded(command_id, previous.result)
                return

        session = self.session_probe()
        if not session.allows_ui():
            self._reject(command_id, f"session_{session.state}")
            return
        provider = self._provider(action.capability_id)
        if provider is None:
            self._reject(command_id, "provider_unavailable")
            return

        with DesktopMutex(session.session_id, name=self.mutex_name).hold(2.0) as acquired:
            if not acquired:
                self._reject(command_id, "desktop_busy")
                return
            try:
                self._record(key, action, "executing", None)
            except RuntimeError as exc:
                self._reject(command_id, str(exc))
                return
            self.client.progress(command_id, "accepted")
            self.client.progress(command_id, "executing")
            try:
                execution = provider.execute(action)
                result = execution.result
                evidence_refs = self._upload_evidence(command_id, execution.evidence)
                result.evidence_refs = evidence_refs
                if action.capability_id in EXTERNAL_SIDE_EFFECT_CAPABILITIES:
                    result.output = {**result.output, "approval_ref": action.approval_ref}
            except Exception as exc:  # noqa: BLE001 - provider isolation
                result = ComputerResult(
                    status="uncertain", provider_status="provider_exception",
                    error_code=type(exc).__name__,
                    error_message="provider failed after dispatch; reconcile",
                    reconcile_required=True,
                )
            self._record(key, action, "unknown" if result.reconcile_required else "completed",
                         result.to_dict())
            self._result(command_id, result, result.evidence_refs)

    def _upload_evidence(self, command_id: str, evidence: list[Any]) -> list[str]:
        refs: list[str] = []
        for item in evidence:
            reference = self._upload_one(command_id, item)
            if reference:
                refs.append(reference)
        return refs

    def _upload_one(self, command_id: str, item: Any) -> str | None:
        try:
            metadata = self.client.upload_evidence(
                command_id, item.content,
                evidence_type=item.evidence_type,
                mime_type=item.mime_type,
                redaction_status=item.redaction_status,
                captured_at=item.captured_at,
            )
        except Exception:  # noqa: BLE001 - evidence failure must not replay action
            return None
        evidence_id = metadata.get("evidence_id") if isinstance(metadata, dict) else None
        return str(evidence_id) if evidence_id else None

    def _record(self, key: str, action: ComputerAction, phase: str,
                result: dict[str, Any] | None) -> None:
        self.ledger.record(LedgerEntry(
            schema="dc.computer-ledger/v2",
            tenant_ref=action.tenant_ref,
            endpoint_id=action.endpoint_id,
            task_ref=str(action.task_ref or ""),
            run_ref=str(action.run_ref or ""),
            idempotency_key=action.idempotency_key,
            fingerprint=action.fingerprint(),
            phase=phase,
            command_id=action.command_id,
            result=redact_value(result) if result is not None else None,
        ))

    def _reject(self, command_id: str, reason: str) -> None:
        self._result(command_id, ComputerResult(
            status="rejected", provider_status=reason, error_code=reason,
            error_message=reason,
        ), [])

    def _result(self, command_id: str, result: ComputerResult,
                evidence_refs: list[str]) -> None:
        status = result.status
        if result.reconcile_required:
            status = "uncertain"
        payload = {
            "status": status,
            "reason": result.error_code or result.provider_status,
            "error_class": "policy" if status == "rejected" else "adapter",
            "retryable": False,
            "executed": status in {"succeeded", "executed_unverified", "uncertain", "failed"},
            "output": redact_value(result.output),
            "verification": result.verification,
            "evidence_refs": evidence_refs[:20],
            "adapter_version": "computer-control/1.0.0",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }
        self.client.result(command_id, payload)

    def _report_recorded(self, command_id: str, result: dict[str, Any]) -> None:
        recorded = ComputerResult(**result)
        recorded.evidence_refs = list(recorded.evidence_refs or [])
        self._result(command_id, recorded, recorded.evidence_refs)

    def reconcile_unknown(self, action: ComputerAction) -> dict[str, Any]:
        """Observation-only reconciliation; never dispatches an action."""

        if action.task_ref is None or action.run_ref is None:
            raise RuntimeError("task_run_required")
        if self.paused():
            raise RuntimeError("local_takeover")
        session = self.session_probe()
        if not session.allows_ui():
            raise RuntimeError(f"session_{session.state}")
        provider = self._provider(action.capability_id)
        if provider is None:
            raise RuntimeError("provider_unavailable")
        observation = provider.observe(action)
        entry = self.ledger.get(action.ledger_key())
        if entry is not None:
            entry.phase = "unknown"
            entry.result = {"status": "uncertain", "observation": redact_value(observation.to_dict())}
            self.ledger.record(entry)
        return redact_value(observation.to_dict())


__all__ = ["ComputerRuntime", "ControlClient"]
