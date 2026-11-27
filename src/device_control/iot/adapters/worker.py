"""Home Assistant pilot worker over the existing Device Control command channel.

The worker only translates already-authorized command envelopes to the HA
adapter. It does not decide policy, leases or approvals; the control plane does.
It enforces a local entity/capability allowlist, compares the observed state hash
before a write, and posts explicit verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .. import ha_pilot
from .home_assistant_adapter import HomeAssistantAdapter


class ControlClient(Protocol):
    def pull(self, limit: int = 10) -> list[dict[str, Any]]:
        ...

    def progress(self, command_id: str, status: str) -> dict[str, Any]:
        ...

    def result(self, command_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        ...


@dataclass
class HomeAssistantPilotWorker:
    client: ControlClient
    adapter: HomeAssistantAdapter
    allowed_entities: set[str]

    def run_once(self, limit: int = 10) -> dict[str, int]:
        commands = self.client.pull(limit)
        executed = 0
        for command in commands:
            self._execute(command)
            executed += 1
        return {"pulled": len(commands), "executed": executed}

    def _execute(self, command: dict[str, Any]) -> None:
        command_id = str(command["command_id"])
        capability_id = str(command["capability_id"])
        parameters = command.get("parameters") or {}
        entity_id = str(parameters.get("entity_id") or "")
        if capability_id not in ha_pilot.CAPABILITY_IDS:
            self._reject(command_id, "capability_not_allowlisted")
            return
        if entity_id not in self.allowed_entities:
            self._reject(command_id, "entity_not_allowlisted")
            return
        if command.get("gateway_id") != self.client.gateway_id:  # type: ignore[attr-defined]
            self._reject(command_id, "gateway_mismatch")
            return
        try:
            before = self.adapter.observe(entity_id)
        except Exception as exc:  # noqa: BLE001 - adapter/transport failure
            self._result(command_id, status="failed", reason=type(exc).__name__,
                         error_class="unavailable")
            return
        if command.get("state_hash") and before.state_hash != command["state_hash"]:
            self._result(command_id, status="rejected", reason="state_changed",
                         error_class="state_changed")
            return
        if capability_id in ha_pilot.READ_CAPABILITIES:
            self._result(
                command_id, status="succeeded",
                verification=self._verification(before, "read_after_write"),
                output={"state": before.properties.get("state")},
            )
            return
        self.client.progress(command_id, "accepted")
        self.client.progress(command_id, "executing")
        mapped = ha_pilot.native_command(capability_id, parameters)
        try:
            outcome = self.adapter.execute(mapped)
        except Exception as exc:  # noqa: BLE001 - adapter crash isolation
            self._result(command_id, status="uncertain", reason=type(exc).__name__,
                         error_class="adapter")
            return
        if not outcome.accepted:
            self._result(command_id, status="rejected", reason=outcome.error or "rejected",
                         error_class="policy" if outcome.status == "rejected" else "adapter")
            return
        observed = outcome.observed
        if not outcome.verified:
            self._result(command_id, status="executed_unverified",
                         reason="state_not_verified", output={
                             "state": observed.properties.get("state") if observed else None,
                         })
            return
        self._result(
            command_id, status="succeeded",
            verification=self._verification(observed, "read_after_write"),
            output={"state": observed.properties.get("state") if observed else None},
        )

    def _reject(self, command_id: str, reason: str) -> None:
        self._result(command_id, status="rejected", reason=reason, error_class="policy")

    def _result(self, command_id: str, *, status: str, reason: str | None = None,
                error_class: str | None = None, output: dict[str, Any] | None = None,
                verification: dict[str, Any] | None = None) -> None:
        self.client.result(command_id, {
            "status": status,
            "reason": reason,
            "error_class": error_class,
            "retryable": False,
            "executed": status in {"succeeded", "executed_unverified", "uncertain", "failed"},
            "output": output or {},
            "verification": verification,
            "evidence_refs": [],
            "adapter_version": self.adapter.adapter_id,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        })

    @staticmethod
    def _verification(observation: Any, method: str) -> dict[str, Any]:
        return {
            "method": method,
            "verified": True,
            "observed_at": observation.observed_at if observation else
            datetime.now(timezone.utc).isoformat(),
            "quality": "medium",
            "observed_state": observation.properties if observation else None,
        }
