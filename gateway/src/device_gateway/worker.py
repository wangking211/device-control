"""Gateway worker: pull, revalidate, execute, verify, report.

Failure policy:

* preflight rejection → ``rejected``, no device call;
* adapter timeout/crash/disconnect → ``uncertain`` (never retried blindly);
* duplicate non-idempotent command whose outcome is unknown → ``uncertain``;
* control-plane transport failure while reporting → result is persisted in the
  local ledger as ``result_pending`` and re-sent idempotently, never re-executed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from . import manifest
from .adapters.base import ActionResult, AdapterError, AdapterTimeout, DeviceAdapter
from .control_client import ControlPlaneClient, ControlPlaneError
from .ledger import CONFLICT, DUPLICATE, DedupeLedger
from .preflight import Context, Rejected, revalidate
from .queue import BackpressureError, BoundedQueue


@dataclass
class WorkerConfig:
    heartbeat_interval_seconds: float = 30.0
    poll_interval_seconds: float = 2.0
    batch_size: int = 5
    agent_version: str = "0.1.0"
    max_result_retries: int = 3


@dataclass
class WorkerState:
    paused: bool = False
    paused_reason: str | None = None
    last_heartbeat: float = 0.0
    reported: list[str] = field(default_factory=list)


class GatewayWorker:
    def __init__(
        self,
        *,
        client: ControlPlaneClient,
        adapter: DeviceAdapter,
        ledger: DedupeLedger,
        queue: BoundedQueue,
        tenant_ref: str,
        config: WorkerConfig | None = None,
        clock: Callable[[], float] = time.monotonic,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.client = client
        self.adapter = adapter
        self.ledger = ledger
        self.queue = queue
        self.tenant_ref = tenant_ref
        self.config = config or WorkerConfig()
        self.clock = clock
        self.on_event = on_event
        self.state = WorkerState()

    # -- local control --------------------------------------------------

    def pause(self, reason: str = "operator_pause") -> None:
        """Pause locally; no cloud round-trip is required."""

        self.state.paused = True
        self.state.paused_reason = reason
        self._emit("gateway.paused", {"reason": reason})

    def resume(self) -> None:
        self.state.paused = False
        self.state.paused_reason = None
        self._emit("gateway.resumed", {})

    # -- lifecycle ------------------------------------------------------

    def run_once(self) -> dict[str, Any]:
        summary = {"heartbeat": False, "pulled": 0, "executed": 0, "pending_flushed": 0}
        if self._heartbeat_due():
            self.heartbeat()
            summary["heartbeat"] = True
        if self.state.paused:
            return summary
        summary["pending_flushed"] = self.flush_pending_results()
        if len(self.queue) < self.queue.capacity:
            summary["pulled"] = self.poll_once()
        for _ in range(max(0, self.config.batch_size)):
            if not self.execute_next():
                break
            summary["executed"] += 1
        return summary

    def run_forever(self, stop: Callable[[], bool] | None = None) -> None:
        while not (stop and stop()):
            try:
                self.run_once()
            except ControlPlaneError as exc:
                self._emit("gateway.control_plane_error", {"code": exc.code, "status": exc.status})
            time.sleep(self.config.poll_interval_seconds)

    # -- heartbeat ------------------------------------------------------

    def heartbeat(self) -> dict[str, Any]:
        health = self._safe_health()
        status = "online"
        if self.state.paused or health.get("takeover"):
            status = "degraded"
        elif health.get("status") in {"unavailable", "error"}:
            status = "degraded"
        response = self.client.heartbeat(
            status=status,
            adapter_inventory=manifest.inventory(
                getattr(self.adapter, "adapter_id", "unknown"),
                getattr(self.adapter, "version", "0.0.0"),
                health,
            ),
            agent_version=self.config.agent_version,
            health=health,
        )
        tenant = response.get("tenant_ref")
        if isinstance(tenant, str) and tenant:
            self.tenant_ref = tenant
        self.state.last_heartbeat = self.clock()
        return response

    # -- pull / admit ---------------------------------------------------

    def poll_once(self) -> int:
        if not self.tenant_ref:
            # Fail closed: a gateway that has not learned its tenant from the
            # control plane must not admit commands.
            return 0
        commands = self.client.pull(limit=self.config.batch_size)
        admitted = 0
        for command in commands:
            claim = self.ledger.claim(command)
            if claim.outcome == CONFLICT:
                self._report_local_rejection(
                    command, "idempotency_conflict",
                    "same idempotency key with a different payload",
                )
                continue
            if claim.outcome == DUPLICATE:
                if claim.status in {"claimed", "executing"}:
                    capability = manifest.capability(
                        str(command.get("capability_id")), str(command.get("capability_version"))
                    )
                    if not (capability or {}).get("supports_idempotency"):
                        self._report(
                            command,
                            status="uncertain",
                            reason="duplicate_after_uncertain_execution",
                            error_class="transport",
                        )
                        self.ledger.complete(str(command["command_id"]), status="uncertain")
                        continue
                else:
                    continue
            try:
                self.queue.put(command)
                admitted += 1
            except BackpressureError:
                self._report_local_rejection(command, "backpressure", "gateway queue is full")
        return admitted

    # -- execute --------------------------------------------------------

    def execute_next(self) -> bool:
        command = self.queue.get_nowait()
        if command is None:
            return False
        command_id = str(command["command_id"])
        health = self._safe_health()
        if health.get("takeover"):
            self.pause("user_takeover")
            self._report(command, status="rejected", reason="user_takeover",
                         error_class="user_takeover")
            self.ledger.complete(command_id, status="rejected")
            return True
        if self.state.paused:
            # Re-admit later without executing; the queue is local and cheap.
            try:
                self.queue.put(command)
            except BackpressureError:
                self._report_local_rejection(command, "paused", "gateway paused locally")
            return False

        try:
            observed = self.adapter.observe_state()
            revalidate(command, Context(
                tenant_ref=self.tenant_ref,
                gateway_id=self.client.gateway_id,
                now=datetime.now(timezone.utc),
                observed_state_hash=observed.get("state_hash"),
                allowed_apps=frozenset(getattr(self.adapter, "allowed_apps", frozenset())),
            ))
        except Rejected as exc:
            self._report(command, status="rejected", reason=f"{exc.code}: {exc.reason}",
                         error_class=exc.error_class)
            self.ledger.complete(command_id, status="rejected")
            return True
        except AdapterError as exc:
            self._report(command, status="failed", reason=str(exc),
                         error_class=exc.error_class, retryable=exc.retryable)
            self.ledger.complete(command_id, status="failed")
            return True

        self._safe_progress(command_id, "accepted")
        self._safe_progress(command_id, "executing")
        self._emit("gateway.executing", {"command_id": command_id,
                                         "capability_id": command.get("capability_id")})
        result = self._execute(command)
        posted = self._report(command, **result)
        status = result["status"]
        if posted:
            self.ledger.complete(command_id, status=status)
        else:
            self.ledger.complete(command_id, status="result_pending",
                                 result=self._result_payload(command, **result))
        return True

    def _execute(self, command: dict[str, Any]) -> dict[str, Any]:
        capability = manifest.capability(
            str(command["capability_id"]), str(command["capability_version"])
        )
        timeout_ms = int((capability or {}).get("max_timeout_ms") or 15000)
        started = time.monotonic()
        try:
            outcome: ActionResult = self.adapter.execute(
                str(command["capability_id"]), dict(command.get("parameters") or {})
            )
        except AdapterTimeout as exc:
            return {"status": "uncertain", "reason": str(exc), "error_class": "timeout"}
        except AdapterError as exc:
            return {"status": "uncertain" if exc.uncertain else "failed",
                    "reason": str(exc), "error_class": exc.error_class,
                    "retryable": exc.retryable}
        except Exception as exc:  # noqa: BLE001 - adapter crash isolation
            return {"status": "uncertain", "reason": f"adapter_crash:{type(exc).__name__}",
                    "error_class": "adapter"}
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if elapsed_ms > timeout_ms:
            return {"status": "uncertain", "reason": "adapter_overran_timeout",
                    "error_class": "timeout"}
        status = outcome.status
        verification = outcome.verification
        if status == "succeeded" and not self._verification_ok(verification):
            # Never claim success without evidence.
            status = "uncertain"
            outcome.reason = outcome.reason or "verification_insufficient"
        return {
            "status": status,
            "reason": outcome.reason,
            "error_class": outcome.error_class,
            "retryable": outcome.retryable,
            "output": outcome.output,
            "verification": verification,
            "evidence_refs": outcome.evidence_refs,
        }

    # -- reporting ------------------------------------------------------

    def flush_pending_results(self) -> int:
        flushed = 0
        for command_id, payload in self.ledger.pending_results():
            try:
                self.client.result(command_id, payload)
            except ControlPlaneError:
                continue
            self.ledger.complete(command_id, status=str(payload.get("status") or "uncertain"))
            flushed += 1
        return flushed

    def _report(self, command: dict[str, Any], **result: Any) -> bool:
        payload = self._result_payload(command, **result)
        for attempt in range(self.config.max_result_retries):
            try:
                self.client.result(str(command["command_id"]), payload)
                self.state.reported.append(str(command["command_id"]))
                return True
            except ControlPlaneError as exc:
                # 409 means the control plane already holds a terminal answer;
                # another post will not change it.
                if exc.status == 409:
                    return True
                if attempt == self.config.max_result_retries - 1:
                    self._emit("gateway.result_pending", {"command_id": command["command_id"]})
                    return False
                time.sleep(0.2 * (attempt + 1))
        return False

    def _report_local_rejection(self, command: dict[str, Any], reason: str,
                                detail: str) -> None:
        self._report(command, status="rejected", reason=f"{reason}:{detail}",
                     error_class="validation" if reason != "backpressure" else "unavailable")
        self.ledger.complete(str(command["command_id"]), status="rejected")

    def _safe_progress(self, command_id: str, status: str) -> None:
        try:
            self.client.progress(command_id, status)
        except ControlPlaneError:
            # Execution continues; the final result carries the authoritative
            # outcome and the control plane reconciles missing progress.
            pass

    def _safe_health(self) -> dict[str, Any]:
        try:
            return dict(self.adapter.health())
        except Exception as exc:  # noqa: BLE001 - health must not crash the loop
            return {"status": "error", "reason": type(exc).__name__}

    def _heartbeat_due(self) -> bool:
        return (self.clock() - self.state.last_heartbeat) >= self.config.heartbeat_interval_seconds

    @staticmethod
    def _verification_ok(verification: Any) -> bool:
        return bool(
            isinstance(verification, dict)
            and verification.get("verified") is True
            and verification.get("method")
            and verification.get("observed_at")
        )

    @staticmethod
    def _result_payload(command: dict[str, Any], *, status: str, reason: str | None = None,
                        error_class: str | None = None, retryable: bool = False,
                        output: dict[str, Any] | None = None,
                        verification: dict[str, Any] | None = None,
                        evidence_refs: list[str] | None = None) -> dict[str, Any]:
        return {
            "status": status,
            "reason": reason,
            "error_class": error_class,
            "retryable": bool(retryable),
            "output": output or {},
            "verification": verification,
            "evidence_refs": (evidence_refs or [])[:20],
            "adapter_version": str(command.get("_adapter_version") or "gateway"),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self.on_event is not None:
            try:
                self.on_event(event, payload)
            except Exception:  # noqa: BLE001 - observers must not break the worker
                pass
