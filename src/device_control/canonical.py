"""Canonical JSON, digest and manifest-signature helpers.

Every digest that binds a manifest, approval or command is computed here so
two call sites cannot drift. ``json.dumps`` with sorted keys and no whitespace
is the canonical form for objects that only contain JSON values.
"""

from __future__ import annotations

import hashlib
import hmac
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


MANIFEST_DIGEST_FIELDS = (
    "manifest_id",
    "manifest_version",
    "protocol_version",
    "endpoint_id",
    "device_id",
    "device_fingerprint",
    "capabilities",
)


def manifest_payload(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {field: manifest[field] for field in MANIFEST_DIGEST_FIELDS if field in manifest}


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return digest_object(manifest_payload(manifest))


def sign_manifest(digest: str, key: str) -> str:
    if len(key.encode("utf-8")) < 32:
        raise ValueError("manifest signing key must be at least 32 bytes")
    return hmac.new(key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256).hexdigest()


def verify_manifest_signature(digest: str, signature: str, key: str) -> bool:
    if not signature or len(key.encode("utf-8")) < 32:
        return False
    return hmac.compare_digest(sign_manifest(digest, key), signature)


APPROVAL_BINDING_FIELDS = (
    "tenant_ref",
    "endpoint_id",
    "device_id",
    "device_fingerprint",
    "gateway_id",
    "capability_id",
    "capability_version",
    "operation",
    "parameters",
    "intent",
    "requester_ref",
    "lease_id",
    "policy_version",
    "manifest_digest",
    "state_hash",
    "state_version",
    "approval_nonce",
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
    operation: str = "",
    device_id: str | None = None,
    device_fingerprint: str | None = None,
    manifest_digest_value: str = "",
    state_version: str | None = None,
    approval_nonce: str = "",
) -> str:
    """Bind an approval to the exact action it authorizes.

    ``state_hash``/``state_version`` are required for capabilities whose
    manifest declares a state precondition; callers must not substitute a
    fresh state after the user decided.
    """

    return digest_object(
        {
            "tenant_ref": tenant_ref,
            "endpoint_id": endpoint_id,
            "device_id": device_id,
            "device_fingerprint": device_fingerprint,
            "gateway_id": gateway_id,
            "capability_id": capability_id,
            "capability_version": capability_version,
            "operation": operation,
            "parameters": parameters,
            "intent": intent,
            "requester_ref": requester_ref,
            "lease_id": lease_id,
            "policy_version": policy_version,
            "manifest_digest": manifest_digest_value,
            "state_hash": state_hash,
            "state_version": state_version,
            "approval_nonce": approval_nonce,
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
    operation: str = "",
    state_version: str | None = None,
    manifest_digest_value: str = "",
) -> str:
    return digest_object(
        {
            "capability_id": capability_id,
            "capability_version": capability_version,
            "operation": operation,
            "parameters": parameters,
            "intent": intent,
            "deadline": deadline,
            "state_hash": state_hash,
            "state_version": state_version,
            "manifest_digest": manifest_digest_value,
        }
    )
