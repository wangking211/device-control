"""Canonical JSON and digest helpers shared by the control plane.

Every digest that binds an approval, a command or an idempotency record is
computed here so two call sites cannot drift. ``json.dumps`` with sorted keys
and no whitespace is the canonical form for objects that only contain JSON
values. Unknown objects fail closed instead of being silently stringified.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically represented."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise CanonicalizationError("value is not canonicalizable JSON") from exc


def sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def digest_object(value: Any) -> str:
    return sha256_hex(canonical_json(value))


APPROVAL_BINDING_FIELDS = (
    "tenant_ref",
    "endpoint_id",
    "gateway_id",
    "capability_id",
    "capability_version",
    "parameters",
    "intent",
    "requester_ref",
    "lease_id",
    "policy_version",
    "state_hash",
)


def approval_binding_digest(
    *,
    tenant_ref: str,
    endpoint_id: str,
    gateway_id: str,
    capability_id: str,
    capability_version: str,
    parameters: Mapping[str, Any],
    intent: str,
    requester_ref: str,
    lease_id: str,
    policy_version: str,
    state_hash: str | None,
) -> str:
    """Bind an approval to the exact action it authorizes.

    ``state_hash`` is the gateway's last observed screen/state digest. It is
    allowed to be ``None`` only for capabilities that do not observe state;
    callers must not substitute a fresh hash after the user decided.
    """

    return digest_object(
        {
            "tenant_ref": tenant_ref,
            "endpoint_id": endpoint_id,
            "gateway_id": gateway_id,
            "capability_id": capability_id,
            "capability_version": capability_version,
            "parameters": parameters,
            "intent": intent,
            "requester_ref": requester_ref,
            "lease_id": lease_id,
            "policy_version": policy_version,
            "state_hash": state_hash,
        }
    )


def command_payload_hash(
    *,
    capability_id: str,
    capability_version: str,
    parameters: Mapping[str, Any],
    intent: str,
    deadline: str,
    state_hash: str | None,
) -> str:
    return digest_object(
        {
            "capability_id": capability_id,
            "capability_version": capability_version,
            "parameters": parameters,
            "intent": intent,
            "deadline": deadline,
            "state_hash": state_hash,
        }
    )
