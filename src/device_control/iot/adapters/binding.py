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

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from ...canonical import canonical_json

CLAIM_FIELDS = (
    "tenant_ref",
    "gateway_id",
    "platform_instance_id",
    "endpoint_id",
    "device_id",
)

BINDING_DOCUMENT_SCHEMA = "dc-binding-document/v1"


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
        raw_revision = command.get("binding_revision")
        if raw_revision is None or raw_revision == "":
            raise BindingRejected("binding_revision_missing")
        if isinstance(raw_revision, bool) or not isinstance(raw_revision, (int, str)):
            raise BindingRejected("binding_revision_invalid")
        try:
            revision = int(raw_revision)
        except (TypeError, ValueError) as exc:
            raise BindingRejected("binding_revision_invalid") from exc
        # Binding revision is an exact match, never a minimum: an older edge
        # cache and a newer command are both untrustworthy.
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
                 verification_key: str | None = None, key_id: str | None = None,
                 clock=None, state_path: str | Path | None = None) -> None:
        for value in (tenant_ref, gateway_id, platform_instance_id):
            if not str(value or "").strip():
                raise ValueError("binding registry scope is incomplete")
        self.tenant_ref = tenant_ref
        self.gateway_id = gateway_id
        self.platform_instance_id = platform_instance_id
        self._verification_key = verification_key or ""
        self._key_id = key_id or ""
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._bindings: dict[str, DeviceBinding] = {}
        self._tombstones: dict[str, tuple[int, int, str]] = {}
        self._seen_nonces: dict[str, str] = {}
        self._document_revision = 0
        self._document_digest: str | None = None
        self._state_path = Path(state_path) if state_path else None
        self._load_state()

    def bind(self, *, entity_id: str, endpoint_id: str, device_id: str,
             capabilities: Iterable[str], revision: int | None = None,
             ttl_seconds: float = 300.0) -> DeviceBinding:
        now = self._clock()
        previous = self._bindings.get(entity_id)
        tombstone = self._tombstones.get(entity_id)
        floor = max(
            previous.revision if previous else 0,
            tombstone[0] if tombstone else 0,
        )
        next_revision = revision if revision is not None else floor + 1
        if next_revision <= floor:
            raise BindingRejected("binding_revision_regression")
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
        self._tombstones.pop(entity_id, None)
        self._persist_state()
        return binding

    def revoke(self, entity_id: str) -> DeviceBinding | None:
        binding = self._bindings.get(entity_id)
        if binding is None:
            return None
        revoked = replace(binding, revoked_at=self._clock(), revision=binding.revision + 1)
        self._bindings[entity_id] = revoked
        self._persist_state()
        return revoked

    def resolve(self, entity_id: str) -> DeviceBinding:
        binding = self._bindings.get(entity_id)
        if binding is None:
            if entity_id in self._tombstones:
                raise BindingRejected("binding_revoked")
            raise BindingRejected("entity_binding_missing")
        binding.assert_active(self._clock())
        return binding

    def load_document(self, document: Mapping[str, Any], *,
                      document_valid_until: str | None = None) -> list[DeviceBinding]:
        """Verify and atomically load a signed control-plane binding document.

        Any invalid signature, scope, validity, revision, nonce or binding
        aborts the entire load, so a partially-valid document can never widen
        edge access.
        """

        key = self._verification_key
        if len(key.encode("utf-8")) < 32:
            raise BindingRejected("binding_document_unsigned")
        if str(document.get("signature_algorithm") or "") != "hmac-sha256":
            raise BindingRejected("binding_document_unsigned")
        signature = str(document.get("signature") or "")
        if not signature:
            raise BindingRejected("binding_document_unsigned")
        if self._key_id and str(document.get("key_id") or "") != self._key_id:
            raise BindingRejected("binding_document_key_mismatch")
        payload = {name: value for name, value in document.items()
                   if name not in {"signature", "signature_algorithm"}}
        expected = hmac.new(
            key.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise BindingRejected("binding_document_signature_invalid")
        if str(document.get("schema") or "") != BINDING_DOCUMENT_SCHEMA:
            raise BindingRejected("binding_document_invalid")

        if str(document.get("tenant_ref") or "") != self.tenant_ref:
            raise BindingRejected("binding_document_scope_mismatch")
        if str(document.get("gateway_id") or "") != self.gateway_id:
            raise BindingRejected("binding_document_scope_mismatch")
        if str(document.get("platform_instance_id") or "") != self.platform_instance_id:
            raise BindingRejected("binding_document_scope_mismatch")

        now = self._clock()
        issued_at = _parse_timestamp(document.get("issued_at"))
        valid_until = _parse_timestamp(
            document_valid_until or str(document.get("valid_until") or "")
        )
        if issued_at is None or valid_until is None:
            raise BindingRejected("binding_document_expiry_missing")
        if issued_at > now + timedelta(seconds=60):
            raise BindingRejected("binding_document_not_yet_valid")
        if now >= valid_until or valid_until <= issued_at:
            raise BindingRejected("binding_document_expired")
        nonce = str(document.get("nonce") or "")
        if not nonce:
            raise BindingRejected("binding_document_invalid")
        raw_document_revision = document.get("revision")
        if isinstance(raw_document_revision, bool) or not isinstance(raw_document_revision, int):
            raise BindingRejected("binding_revision_invalid")
        if raw_document_revision < 1:
            raise BindingRejected("binding_revision_invalid")

        payload_digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        previous_nonce = self._seen_nonces.get(nonce)
        if previous_nonce is not None:
            if previous_nonce == payload_digest:
                return list(self._bindings.values())
            raise BindingRejected("binding_document_replay")
        if raw_document_revision < self._document_revision:
            raise BindingRejected("binding_document_stale")

        items = document.get("bindings")
        if not isinstance(items, list):
            raise BindingRejected("binding_document_empty")
        pending: dict[str, DeviceBinding] = {}
        for item in items:
            if not isinstance(item, Mapping):
                raise BindingRejected("binding_document_invalid")
            entity_id = str(item.get("entity_id") or "")
            capabilities = item.get("capabilities")
            if not entity_id or not isinstance(capabilities, list) or not capabilities:
                raise BindingRejected("binding_document_invalid")
            if entity_id in pending:
                raise BindingRejected("binding_document_invalid")
            raw_revision = item.get("revision")
            if isinstance(raw_revision, bool) or not isinstance(raw_revision, int):
                raise BindingRejected("binding_revision_invalid")
            if raw_revision < 1:
                raise BindingRejected("binding_revision_invalid")
            capability_set = frozenset(str(value) for value in capabilities)
            endpoint_id = str(item.get("endpoint_id") or "")
            device_id = str(item.get("device_id") or "")
            existing = self._bindings.get(entity_id)
            if existing is not None:
                if raw_revision < existing.revision:
                    raise BindingRejected("binding_revision_regression")
                if raw_revision == existing.revision and (
                    existing.endpoint_id != endpoint_id
                    or existing.device_id != device_id
                    or existing.capabilities != capability_set
                ):
                    raise BindingRejected("binding_document_conflict")
            tombstone = self._tombstones.get(entity_id)
            if tombstone is not None:
                # A re-added entity must come from a newer snapshot and use a
                # strictly newer per-device revision than the revocation.
                if raw_document_revision <= tombstone[1]:
                    raise BindingRejected("binding_revision_regression")
                if raw_revision <= tombstone[0]:
                    raise BindingRejected("binding_revision_regression")
            binding = DeviceBinding(
                tenant_ref=self.tenant_ref,
                gateway_id=self.gateway_id,
                platform_instance_id=self.platform_instance_id,
                endpoint_id=endpoint_id,
                device_id=device_id,
                entity_id=entity_id,
                capabilities=capability_set,
                revision=raw_revision,
                issued_at=_parse_timestamp(item.get("issued_at")) or now,
                valid_until=valid_until,
                source=str(document.get("source") or "control-plane"),
            )
            binding.assert_active(now)
            pending[entity_id] = binding

        binding_set_digest = hashlib.sha256(canonical_json({
            "tenant_ref": self.tenant_ref,
            "gateway_id": self.gateway_id,
            "platform_instance_id": self.platform_instance_id,
            "revision": raw_document_revision,
            "bindings": sorted(
                [
                    {
                        "entity_id": str(item.get("entity_id") or ""),
                        "device_id": str(item.get("device_id") or ""),
                        "endpoint_id": str(item.get("endpoint_id") or ""),
                        "capabilities": sorted(str(value) for value in item.get("capabilities") or []),
                        "revision": item.get("revision"),
                    }
                    for item in items
                ],
                key=lambda item: item["entity_id"],
            ),
        }).encode("utf-8")).hexdigest()
        if (raw_document_revision == self._document_revision
                and self._document_digest not in {None, binding_set_digest}):
            raise BindingRejected("binding_document_conflict")

        # Snapshot semantics: the document is the complete active set. Any
        # entity omitted from a newer snapshot becomes a durable tombstone.
        omitted = set(self._bindings) - set(pending)
        for entity_id in omitted:
            old = self._bindings[entity_id]
            self._tombstones[entity_id] = (
                max(old.revision, (self._tombstones.get(entity_id) or (0,))[0]),
                raw_document_revision,
                now.isoformat(),
            )
        for entity_id in pending:
            self._tombstones.pop(entity_id, None)
        self._bindings = pending
        self._seen_nonces[nonce] = payload_digest
        self._document_revision = raw_document_revision
        self._document_digest = binding_set_digest
        self._persist_state()
        return list(pending.values())

    # -- durable edge cache --------------------------------------------

    @staticmethod
    def _binding_state(binding: DeviceBinding) -> dict[str, Any]:
        return {
            "tenant_ref": binding.tenant_ref,
            "gateway_id": binding.gateway_id,
            "platform_instance_id": binding.platform_instance_id,
            "endpoint_id": binding.endpoint_id,
            "device_id": binding.device_id,
            "entity_id": binding.entity_id,
            "capabilities": sorted(binding.capabilities),
            "revision": binding.revision,
            "issued_at": binding.issued_at.isoformat(),
            "valid_until": binding.valid_until.isoformat(),
            "revoked_at": binding.revoked_at.isoformat() if binding.revoked_at else None,
            "source": binding.source,
        }

    def _load_state(self) -> None:
        if self._state_path is None or not self._state_path.is_file():
            return
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if (data.get("tenant_ref") != self.tenant_ref
                or data.get("gateway_id") != self.gateway_id
                or data.get("platform_instance_id") != self.platform_instance_id):
            return
        self._document_revision = int(data.get("document_revision") or 0)
        self._document_digest = data.get("document_digest")
        for item in data.get("bindings") or []:
            issued_at = _parse_timestamp(item.get("issued_at"))
            valid_until = _parse_timestamp(item.get("valid_until"))
            if issued_at is None or valid_until is None:
                continue
            binding = DeviceBinding(
                tenant_ref=self.tenant_ref,
                gateway_id=self.gateway_id,
                platform_instance_id=self.platform_instance_id,
                endpoint_id=str(item.get("endpoint_id") or ""),
                device_id=str(item.get("device_id") or ""),
                entity_id=str(item.get("entity_id") or ""),
                capabilities=frozenset(str(value) for value in item.get("capabilities") or []),
                revision=int(item.get("revision") or 0),
                issued_at=issued_at,
                valid_until=valid_until,
                revoked_at=_parse_timestamp(item.get("revoked_at")),
                source=str(item.get("source") or "control-plane"),
            )
            self._bindings[binding.entity_id] = binding
        for entity_id, value in (data.get("tombstones") or {}).items():
            try:
                self._tombstones[str(entity_id)] = (
                    int(value[0]), int(value[1]), str(value[2]),
                )
            except (TypeError, ValueError, IndexError):
                continue

    def _persist_state(self) -> None:
        if self._state_path is None:
            return
        data = {
            "tenant_ref": self.tenant_ref,
            "gateway_id": self.gateway_id,
            "platform_instance_id": self.platform_instance_id,
            "document_revision": self._document_revision,
            "document_digest": self._document_digest,
            "bindings": [self._binding_state(binding)
                         for binding in self._bindings.values()],
            "tombstones": {entity_id: list(value)
                           for entity_id, value in self._tombstones.items()},
        }
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        os.replace(temporary, self._state_path)

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
