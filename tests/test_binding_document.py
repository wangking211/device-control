"""Signed, atomic binding document trust-edge tests."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pytest
from support import BINDING_KEY

from device_control.canonical import canonical_json
from device_control.iot.adapters.binding import BindingRegistry, BindingRejected


def signed(document, key=BINDING_KEY, *, key_id="test-binding-key-1"):
    document = {
        **document,
        "schema": "dc-binding-document/v1",
        "signature_algorithm": "hmac-sha256",
        "key_id": key_id,
    }
    payload = {k: v for k, v in document.items()
               if k not in {"signature", "signature_algorithm"}}
    document["signature"] = hmac.new(
        key.encode(), canonical_json(payload).encode(), hashlib.sha256
    ).hexdigest()
    return document


def document(**overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "tenant_ref": "tenant-a",
        "gateway_id": "ha-ha-1",
        "platform_instance_id": "ha-1",
        "revision": 10,
        "nonce": "nonce-10",
        "issued_at": now.isoformat(),
        "valid_until": (now + timedelta(minutes=5)).isoformat(),
        "source": "control-plane",
        "bindings": [{
            "entity_id": "light.kitchen",
            "device_id": "ha:tenant-a:light:kitchen",
            "endpoint_id": "ep-ha",
            "capabilities": ["device.observe", "light.turn_on"],
            "revision": 7,
            "issued_at": now.isoformat(),
        }],
    }
    payload.update(overrides)
    return payload


def registry(**overrides):
    return BindingRegistry(
        tenant_ref="tenant-a", gateway_id="ha-ha-1", platform_instance_id="ha-1",
        verification_key=BINDING_KEY, key_id="test-binding-key-1", **overrides,
    )


def reject(bindings, document, reason):
    with pytest.raises(BindingRejected) as exc:
        bindings.load_document(document)
    assert exc.value.reason == reason


def test_valid_signed_document_loads():
    loaded = registry().load_document(signed(document()))
    assert loaded[0].entity_id == "light.kitchen"
    assert loaded[0].revision == 7


def test_unsigned_or_wrong_key_document_is_rejected():
    reject(registry(), document(), "binding_document_unsigned")
    reject(registry(), signed(document(), key="x" * 40),
           "binding_document_signature_invalid")
    reject(registry(), signed(document(), key_id="other-key"),
           "binding_document_key_mismatch")


def test_tampered_document_is_rejected():
    tampered = signed(document())
    tampered["bindings"][0]["capabilities"].append("ui.tap")
    reject(registry(), tampered, "binding_document_signature_invalid")


def test_expired_and_not_yet_valid_documents_are_rejected():
    now = datetime.now(timezone.utc)
    reject(registry(), signed(document(
        issued_at=(now - timedelta(minutes=10)).isoformat(),
        valid_until=(now - timedelta(minutes=1)).isoformat(),
    )), "binding_document_expired")
    reject(registry(), signed(document(
        issued_at=(now + timedelta(minutes=10)).isoformat(),
        valid_until=(now + timedelta(minutes=20)).isoformat(),
    )), "binding_document_not_yet_valid")


def test_cross_scope_document_is_rejected():
    reject(registry(), signed(document(tenant_ref="tenant-b")),
           "binding_document_scope_mismatch")
    reject(registry(), signed(document(gateway_id="ha-other")),
           "binding_document_scope_mismatch")


def test_nonce_replay_with_different_content_is_rejected():
    bindings = registry()
    first = signed(document())
    bindings.load_document(first)
    # Same nonce, same content: idempotent refresh.
    bindings.load_document(first)
    altered = signed(document())
    altered["bindings"][0]["capabilities"] = ["device.observe"]
    # Re-sign is not possible for an attacker, but even a key holder must not
    # reuse a nonce for different content.
    payload = {k: v for k, v in altered.items()
               if k not in {"signature", "signature_algorithm"}}
    altered["signature"] = hmac.new(
        BINDING_KEY.encode(), canonical_json(payload).encode(), hashlib.sha256
    ).hexdigest()
    reject(bindings, altered, "binding_document_replay")


def test_stale_revision_is_rejected():
    bindings = registry()
    newer = signed(document(revision=11, nonce="nonce-11"))
    bindings.load_document(newer)
    stale = signed(document(revision=10, nonce="nonce-12"))
    reject(bindings, stale, "binding_document_stale")


def test_refresh_with_same_revision_and_new_nonce_is_accepted():
    bindings = registry()
    bindings.load_document(signed(document()))
    refreshed = signed(document(nonce="nonce-refresh"))
    bindings.load_document(refreshed)
    assert bindings.resolve("light.kitchen").revision == 7


def test_conflicting_same_revision_is_rejected():
    bindings = registry()
    bindings.load_document(signed(document()))
    conflicting = document(nonce="nonce-other")
    conflicting["bindings"][0]["capabilities"] = ["device.observe"]
    reject(bindings, signed(conflicting), "binding_document_conflict")


def test_load_is_atomic_when_a_later_binding_is_invalid():
    bindings = registry()
    invalid = document()
    invalid["bindings"].append({
        "entity_id": "", "device_id": "d2", "endpoint_id": "ep-2",
        "capabilities": ["device.observe"], "revision": 1,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    })
    reject(bindings, signed(invalid), "binding_document_invalid")
    # The first, otherwise-valid binding must not have been applied.
    with pytest.raises(BindingRejected) as exc:
        bindings.resolve("light.kitchen")
    assert exc.value.reason == "entity_binding_missing"
