"""Trusted, versioned device bindings for edge adapters.

A command envelope is a *claim*. It says which tenant, gateway, platform,
endpoint, device and native entity the sender believes it addresses. The edge
never executes on claims alone: it resolves the claim against a binding issued
by the control plane, carrying a revision and a validity window, then compares
every identity field. Missing, empty, stale, expired, revoked or conflicting
values fail closed, so a partial envelope cannot simply skip a check.

The registry is keyed by native entity because that is the only value the HA
adapter can address. The binding is the single source for scope and capability
grants; a local entity allowlist is never sufficient on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

CLAIM_FIELDS = (
    "tenant_ref",
    "gateway_id",
    "platform_instance_id",
    "endpoint_id",
    "device_id",
)


class BindingRejected(Exception):
    """A command cannot be bound to a trusted device identity."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class DeviceBinding:
    """An operator/control-plane issued binding for one native entity."""

    tenant_ref: str
    gateway_id: str
    platform_instance_id: str
    endpoint_id: str
    device_id: str
    entity_id: str
    capabilities: frozenset[str]
    revision: int
    issued_at: datetime
    valid_until: datetime
    revoked_at: datetime | None = None
    source: str = "control-plane"

    def assert_active(self, now: datetime) -> None:
        if self.revoked_at is not None:
            raise BindingRejected("binding_revoked")
        if now < self.issued_at:
            raise BindingRejected("binding_not_yet_valid")
        if now >= self.valid_until:
            raise BindingRejected("binding_expired")
        if self.revision < 1:
            raise BindingRejected("binding_revision_invalid")
        for field in ("tenant_ref", "gateway_id", "platform_instance_id",
                      "endpoint_id", "device_id", "entity_id"):
            if not str(getattr(self, field) or "").strip():
                raise BindingRejected("binding_incomplete")
        if not self.capabilities:
            raise BindingRejected("binding_capabilities_empty")

    def assert_claims(self, command: Mapping[str, Any]) -> None:
        """Compare every envelope identity field; absence is a rejection."""

        for field in CLAIM_FIELDS:
            claimed = command.get(field)
            if not isinstance(claimed, str) or not claimed.strip():
                raise BindingRejected("claim_field_missing")
            if claimed != getattr(self, field):
                raise BindingRejected(f"{_reason_for(field)}_mismatch")
        claimed_revision = command.get("binding_revision")
        if claimed_revision is not None:
            try:
                revision = int(claimed_revision)
            except (TypeError, ValueError) as exc:
                raise BindingRejected("binding_revision_invalid") from exc
            # A lower revision means the edge cached a pre-revocation binding;
            # a higher one means the command references a binding we do not
            # have. Both are stale and must be re-resolved.
            if revision != self.revision:
                raise BindingRejected("binding_revision_mismatch")

    def assert_capability(self, capability_id: str) -> None:
        if capability_id not in self.capabilities:
            raise BindingRejected("capability_not_granted")


def _reason_for(field: str) -> str:
    return {
        "tenant_ref": "tenant",
        "gateway_id": "gateway",
        "platform_instance_id": "platform_instance",
        "endpoint_id": "endpoint_mapping",
        "device_id": "device_mapping",
    }.get(field, field)


class BindingRegistry:
    """In-memory view of control-plane bindings for one edge scope."""

    def __init__(self, *, tenant_ref: str, gateway_id: str, platform_instance_id: str,
                 clock=None) -> None:
        for value in (tenant_ref, gateway_id, platform_instance_id):
            if not str(value or "").strip():
                raise ValueError("binding registry scope is incomplete")
        self.tenant_ref = tenant_ref
        self.gateway_id = gateway_id
        self.platform_instance_id = platform_instance_id
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._bindings: dict[str, DeviceBinding] = {}

    def bind(self, *, entity_id: str, endpoint_id: str, device_id: str,
             capabilities: Iterable[str], revision: int | None = None,
             ttl_seconds: float = 300.0) -> DeviceBinding:
        now = self._clock()
        previous = self._bindings.get(entity_id)
        next_revision = revision if revision is not None else (
            (previous.revision + 1) if previous else 1
        )
        binding = DeviceBinding(
            tenant_ref=self.tenant_ref,
            gateway_id=self.gateway_id,
            platform_instance_id=self.platform_instance_id,
            endpoint_id=endpoint_id,
            device_id=device_id,
            entity_id=entity_id,
            capabilities=frozenset(capabilities),
            revision=next_revision,
            issued_at=now,
            valid_until=now + timedelta(seconds=ttl_seconds),
        )
        self._bindings[entity_id] = binding
        return binding

    def revoke(self, entity_id: str) -> DeviceBinding | None:
        binding = self._bindings.get(entity_id)
        if binding is None:
            return None
        revoked = replace(binding, revoked_at=self._clock(), revision=binding.revision + 1)
        self._bindings[entity_id] = revoked
        return revoked

    def resolve(self, entity_id: str) -> DeviceBinding:
        binding = self._bindings.get(entity_id)
        if binding is None:
            raise BindingRejected("entity_binding_missing")
        binding.assert_active(self._clock())
        return binding

    def load_document(self, document: Mapping[str, Any], *,
                      document_valid_until: str | None = None) -> list[DeviceBinding]:
        """Load a control-plane binding document.

        The document scope must match this edge exactly. Any malformed binding
        aborts the whole load so a partial document cannot widen access.
        """

        if str(document.get("tenant_ref") or "") != self.tenant_ref:
            raise BindingRejected("binding_document_scope_mismatch")
        if str(document.get("gateway_id") or "") != self.gateway_id:
            raise BindingRejected("binding_document_scope_mismatch")
        if str(document.get("platform_instance_id") or "") != self.platform_instance_id:
            raise BindingRejected("binding_document_scope_mismatch")
        valid_until = _parse_timestamp(
            document_valid_until or str(document.get("valid_until") or "")
        )
        if valid_until is None:
            raise BindingRejected("binding_document_expiry_missing")
        items = document.get("bindings")
        if not isinstance(items, list) or not items:
            raise BindingRejected("binding_document_empty")
        loaded: list[DeviceBinding] = []
        for item in items:
            if not isinstance(item, Mapping):
                raise BindingRejected("binding_document_invalid")
            entity_id = str(item.get("entity_id") or "")
            capabilities = item.get("capabilities")
            if not entity_id or not isinstance(capabilities, list) or not capabilities:
                raise BindingRejected("binding_document_invalid")
            raw_revision = item.get("revision")
            if not isinstance(raw_revision, (int, str)) or isinstance(raw_revision, bool):
                raise BindingRejected("binding_revision_invalid")
            try:
                revision = int(raw_revision)
            except (TypeError, ValueError) as exc:
                raise BindingRejected("binding_revision_invalid") from exc
            issued_at = _parse_timestamp(item.get("issued_at")) or self._clock()
            binding = DeviceBinding(
                tenant_ref=self.tenant_ref,
                gateway_id=self.gateway_id,
                platform_instance_id=self.platform_instance_id,
                endpoint_id=str(item.get("endpoint_id") or ""),
                device_id=str(item.get("device_id") or ""),
                entity_id=entity_id,
                capabilities=frozenset(str(value) for value in capabilities),
                revision=revision,
                issued_at=issued_at,
                valid_until=valid_until,
                source=str(document.get("source") or "control-plane"),
            )
            binding.assert_active(self._clock())
            self._bindings[entity_id] = binding
            loaded.append(binding)
        return loaded

    def snapshot(self) -> list[dict[str, Any]]:
        return [
            {
                "entity_id": binding.entity_id,
                "tenant_ref": binding.tenant_ref,
                "gateway_id": binding.gateway_id,
                "platform_instance_id": binding.platform_instance_id,
                "endpoint_id": binding.endpoint_id,
                "device_id": binding.device_id,
                "capabilities": sorted(binding.capabilities),
                "revision": binding.revision,
                "issued_at": binding.issued_at.isoformat(),
                "valid_until": binding.valid_until.isoformat(),
                "revoked": binding.revoked_at is not None,
            }
            for binding in self._bindings.values()
        ]


__all__ = [
    "BindingRegistry",
    "BindingRejected",
    "CLAIM_FIELDS",
    "DeviceBinding",
]
