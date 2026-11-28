"""Home Assistant pilot worker over the existing Device Control command channel.

The worker only translates already-authorized command envelopes to the HA
adapter. It does not decide policy, leases or approvals; the control plane does.
Before any read or write it resolves a trusted, versioned device binding and
compares tenant, gateway, platform instance, endpoint, device, native entity and
capability grant. Every field is mandatory: a partial envelope is rejected, not
silently skipped. Writes additionally require an active lease, an approval
nonce and the upstream ``ask`` decision, and are only executed when the observed
state still matches the approved state hash/version.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .. import ha_pilot
from .binding import BindingRegistry, BindingRejected
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
    bindings: BindingRegistry
    max_state_age_seconds: float = 15.0

    def run_once(self, limit: int = 10) -> dict[str, int]:
        commands = self.client.pull(limit)
        executed = 0
        for command in commands:
            self._execute(command)
            executed += 1
        return {"pulled": len(commands), "executed": executed}

    def _execute(self, command: dict[str, Any]) -> None:
        command_id = str(command.get("command_id") or "")
        if not command_id:
            return
        capability_id = str(command.get("capability_id") or "")
        parameters = command.get("parameters") or {}
        if not isinstance(parameters, dict):
            self._reject(command_id, "parameters_invalid")
            return
        entity_id = str(parameters.get("entity_id") or "")
        if not entity_id:
            self._reject(command_id, "entity_missing")
            return
        if capability_id not in ha_pilot.CAPABILITY_IDS:
            self._reject(command_id, "capability_not_allowlisted")
            return
        try:
            binding = self.bindings.resolve(entity_id)
            binding.assert_claims(command)
            binding.assert_capability(capability_id)
        except BindingRejected as exc:
            self._reject(command_id, exc.reason)
            return

        is_read = capability_id in ha_pilot.READ_CAPABILITIES
        if not self._check_authorization(command, is_read=is_read):
            return

        try:
            before = self.adapter.observe(entity_id)
        except Exception as exc:  # noqa: BLE001 - adapter/transport failure
            self._result(command_id, status="failed", reason=type(exc).__name__,
                         error_class="unavailable")
            return
        if is_read:
            self._result(
                command_id, status="succeeded",
                verification=self._verification(before, "sensor_observation"),
                output={"state": before.properties.get("state")},
            )
            return
        if not self._check_write_state(command, before):
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

    def _check_authorization(self, command: dict[str, Any], *, is_read: bool) -> bool:
        """Require control-plane authority; an envelope cannot self-authorize."""

        command_id = str(command["command_id"])
        decision = command.get("policy_decision")
        if is_read:
            if decision != "allow":
                self._reject(command_id, "policy_decision_mismatch")
                return False
            return True
        if decision != "ask":
            self._reject(command_id, "policy_decision_mismatch")
            return False
        if not str(command.get("lease_id") or "").strip():
            self._reject(command_id, "lease_missing")
            return False
        if not str(command.get("approval_id") or "").strip():
            self._reject(command_id, "approval_missing")
            return False
        if not str(command.get("approval_nonce") or "").strip():
            self._reject(command_id, "approval_nonce_missing")
            return False
        return True

    def _check_write_state(self, command: dict[str, Any], before: Any) -> bool:
        state_hash = command.get("state_hash")
        state_version = command.get("state_version")
        if not state_hash or not state_version:
            self._reject(str(command["command_id"]), "state_prerequisite_missing")
            return False
        if before.state_hash != state_hash or before.state_version != state_version:
            self._reject(str(command["command_id"]), "state_changed")
            return False
        if before.quality != "good" or before.connectivity != "online":
            self._reject(str(command["command_id"]), "state_unavailable")
            return False
        try:
            observed = datetime.fromisoformat(str(before.observed_at).replace("Z", "+00:00"))
        except ValueError:
            self._reject(str(command["command_id"]), "state_observed_at_invalid")
            return False
        if observed.tzinfo is None:
            self._reject(str(command["command_id"]), "state_observed_at_invalid")
            return False
        now = datetime.now(timezone.utc)
        age = (now - observed).total_seconds()
        if age < -60 or age > self.max_state_age_seconds:
            self._reject(str(command["command_id"]), "state_stale")
            return False
        return True

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
