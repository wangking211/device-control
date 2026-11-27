# Manifest Key Management (DC-010-04)

Production uses Ed25519: the control plane/operator signs, the gateway verifies
with a public key only. HMAC remains a controlled compatibility mode and must be
explicitly enabled (`DEVICE_CONTROL_MANIFEST_ALLOW_HMAC=true`); it is not the
production default.

## Manifest signing fields

The canonical digest covers: manifest id/version, protocol, tenant, gateway,
endpoint, device id/fingerprint, revision, issued/expires, key id, algorithm and
capabilities. `signature` is excluded. This prevents replay across
tenant/gateway/device and rejects tampering.

## Generate and sign

```bash
openssl genpkey -algorithm ed25519 -out release-private.pem
openssl pkey -in release-private.pem -pubout -out release-public.pem

python scripts/sign_manifest.py \
  --manifest manifest.json --out manifest.signed.json \
  --private-key release-private.pem --key-id release-key-1 \
  --tenant tenant-a --gateway gateway-a --endpoint phone-1 \
  --device device-phone-1 --fingerprint <sha256> --revision 1 --valid-days 30
```

Control plane:

```bash
DEVICE_CONTROL_MANIFEST_PUBLIC_KEY_PATH=/etc/device-control/release-public.pem
DEVICE_CONTROL_MANIFEST_KEY_IDS=release-key-1
DEVICE_CONTROL_MANIFEST_REQUIRE_SIGNATURE=true
```

Gateway:

```bash
DEVICE_GATEWAY_MANIFEST_PUBLIC_KEY_PATH=/etc/device-control/release-public.pem
DEVICE_GATEWAY_MANIFEST_KEY_IDS=release-key-1
DEVICE_GATEWAY_MANIFEST_REQUIRE_SIGNATURE=true
DEVICE_GATEWAY_ENV=production
```

The gateway fails to start when a production key is missing, the algorithm is
not Ed25519, the key id is unknown, the window is invalid, or verification fails.

## Rotation / revocation

1. Publish the new public key and add its `key_id` to the allowed set on both
   control plane and gateways.
2. Sign a new manifest revision with the new key, register it, and let gateways
   heartbeat the new digest.
3. Remove the old `key_id` from allowed sets and revoke old approvals/commands
   by manifest-change invalidation.
4. For emergency rotation, revoke gateway credentials, deploy the new public
   key, and re-enroll. Never ship the private key to an edge device.

## Compatibility

HMAC signing remains for local/controlled migration only. It is rejected when
`DEVICE_CONTROL_MANIFEST_ALLOW_HMAC` is false. Plan removal once all gateways
hold Ed25519 public keys.

## Tests

`tests/test_gateway_protocol.py::test_ed25519_manifest_signature_and_key_id`
covers accepted signature, unknown key id and tampered payload. Gateway startup
verification is exercised by `build_components` validation and preflight.
